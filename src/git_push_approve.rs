//! Pure orchestrator for promoting an approved staged push.
//!
//! The B1e.2c handler is responsible for the audit/mint ceremony around an
//! `ApproveStagedPush` RPC: validate the operator, look up the staged entry,
//! mint a credential under the grant-log discipline, write the resolution
//! row, and delete the staging directory. This module does the part in
//! between — given an already-minted GitHub installation token and the
//! payload from the staged entry, it stands up an isolated bare staging
//! repo, fetches the prerequisite commit, ingests the bundle, plans the
//! per-commit walk, and runs [`prepare_fast_forward_plan`] against the
//! GitHub Git Data API.
//!
//! It is deliberately in two halves, split at the only step that can
//! move a branch on GitHub. [`prepare_approve`] does everything up to
//! the `PATCH` and hands back a [`PreparedApprove`];
//! [`PreparedApprove::commit`] re-verifies the lease one final time
//! and issues the `PATCH`, and demands an [`UncertainAttempt`] to do
//! it. The handler mints that witness from the audit log in between,
//! so the durable "a PATCH may exist" record brackets the PATCH as
//! tightly as it can — a crash during the fetch, plan or upload leaves
//! an attempt that boot reconcile resolves on its own instead of one
//! an operator has to reconcile by hand, and the time spent minting
//! the witness sits outside the publish race because the lease is
//! rechecked after it.
//!
//! All side effects happen against the `work_root` carried by the caller's
//! [`PromoteRuntimeConfig`] plus the GitHub API base; nothing here touches
//! the audit log, the secret store, or the staging store. Failures bubble
//! up as [`RunApproveError`] so the handler can decide how to record them
//! in the audit log — see B1e.2c.
//!
//! The slice that wires this into the broker's `approve_staged_push`
//! handler is B1e.2c; until that lands the broker stub still returns the
//! slice-B1e.1 placeholder error.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::audit::UncertainAttempt;
use crate::clean_git::{
    self, CleanGitEnv, CleanGitInvocation, SMALL_STDOUT_CAP, clean_git_config_env,
};
use crate::core::{ApproveAttemptId, RepoRef};
use crate::git_push_objects_cat_file::{CatFileObjectSource, OpenError};
use crate::git_push_promote::{
    CommitError, ExecuteError, ExecuteOutcome, PreparedPromotion, PromoteRuntimeConfig,
    commit_prepared_promotion, prepare_fast_forward_plan,
};
use crate::git_push_trailers::TrailerSource;
use crate::git_push_walker::{
    FastForwardPlanError, REV_LIST_STDOUT_BYTE_CAP, plan_fast_forward_via_rev_list,
};
use crate::github_git_db::{GitDataClient, GitDataTimeouts};
use crate::signing::WritSigningKey;
use crate::vm_git::{GitBranchName, GitCloneRepo, GitObjectId};
use crate::vm_git_bundle::GitSecretValue;

/// Per-object size ceiling fed to [`CatFileObjectSource`] when reading
/// staging-repo objects during the walker upload. 256 MiB matches every
/// existing call site (walker integration tests, vm-push staging max
/// object size); kept as a module-private constant for B1e.2b rather
/// than threaded through [`PromoteRuntimeConfig`] because making it
/// configurable is its own (small) future slice and the current 256 MiB
/// ceiling is already what production code carries.
const STAGING_REPO_MAX_OBJECT_BYTES: u64 = 256 << 20;

/// Outcome of a successful approve walk.
///
/// Mirrors [`ExecuteOutcome`] but collapses the `Noop`/`Advanced` split:
/// the operator-facing "new app tip" is the same SHA either way — the
/// bundle's already-on-GitHub tip for the noop case, the walker's
/// freshly-uploaded tip for the advanced case. The handler records the
/// audit resolution against this single SHA without re-disambiguating.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunApproveOutcome {
    new_app_tip: GitObjectId,
}

impl RunApproveOutcome {
    pub fn new_app_tip(&self) -> &GitObjectId {
        &self.new_app_tip
    }
}

/// Errors surfaced from [`prepare_approve`].
///
/// Each variant maps onto a specific stage of the orchestrator so the
/// handler in B1e.2c can record a structured failure reason in the
/// audit log without re-parsing the wrapped error string.
///
/// Every one of them is provably pre-PATCH: the branch on GitHub is
/// untouched, so the attempt is retryable. The failure that is *not*
/// retryable has its own type, [`CommitError::UpdateRef`], and can
/// only come out of [`PreparedApprove::commit`].
#[derive(Debug, thiserror::Error)]
pub enum RunApproveError {
    #[error("staging repo preparation failed: {0}")]
    Prepare(#[from] PrepareStagingError),
    #[error("`git cat-file -t` against the staged bundle tip failed: {0}")]
    ResolveBundleTip(String),
    /// The bundle's advertised tip is in the staging repo but is not a
    /// `commit` — typically an annotated tag, tree, or blob. A hostile
    /// VM that stages a tag-SHA tip would have its tag peeled by
    /// `rev-list` and the wrong commit would be replayed; this gate
    /// (a post-unbundle `cat-file -t == commit` invariant) prevents that.
    #[error("bundle tip {sha} is not a commit object (actual type: {actual_type})")]
    BundleTipNotACommit { sha: String, actual_type: String },
    #[error("fast-forward planning against the staging repo failed: {0}")]
    Plan(#[from] FastForwardPlanError),
    #[error("could not open `git cat-file --batch` against the staging repo: {0}")]
    OpenObjectSource(#[from] OpenError),
    #[error("prepare_fast_forward_plan failed: {0}")]
    Execute(#[from] ExecuteError),
}

/// Errors that can fall out of [`prepare_staging_repo`].
///
/// Each `Git*` variant pins down which of the three subprocess steps
/// failed (init, fetch, unbundle); the prepare layer's job is purely
/// to assemble a staging repo whose state the planner can read, so
/// these are reported separately even though they share a single
/// `CleanGitError` cause type (kept out of the rustdoc-resolved link
/// surface because the `clean_git` module is `pub(crate)`).
#[derive(Debug, thiserror::Error)]
pub enum PrepareStagingError {
    #[error("approve staging dir already exists: {0}")]
    StagingDirExists(PathBuf),
    #[error("could not create approve staging dir {path}: {source}")]
    AllocateStagingDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not write bundle to staging dir at {path}: {source}")]
    WriteBundleFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Stringified rather than carrying the underlying `CleanGitError`:
    /// the clean-git module is `pub(crate)` and publishing one of its
    /// variants here would force the entire hardening helper into the
    /// public surface for no caller benefit — handlers log the cause,
    /// they don't pattern-match on it. Same precedent as
    /// [`FastForwardPlanError::Git`].
    #[error("`git init --bare` against staging dir failed: {0}")]
    GitInit(String),
    #[error("`git fetch` of prerequisite commit into staging dir failed: {0}")]
    GitFetch(String),
    #[error("`git bundle unbundle` of staged push bundle failed: {0}")]
    GitUnbundle(String),
}

/// An approve pipeline that has run every step that provably cannot
/// have moved the branch on GitHub, and is one `PATCH` away from
/// publishing. Produced by [`prepare_approve`], consumed by
/// [`PreparedApprove::commit`].
///
/// Holding this value means: the staging repo has been built, fetched,
/// unbundled, planned and torn down again; the lease was checked before
/// and after the walk; every object the push needs is uploaded to
/// GitHub's object database, unreferenced. None of that is observable
/// to anyone else and none of it can be a partial publish, so the
/// caller's attempt row can still be in the cheap, auto-recoverable
/// `Started` state.
///
/// The PATCH is the step past which the broker cannot prove whether
/// GitHub moved — hence [`PreparedApprove::commit`] demands an
/// [`UncertainAttempt`], which only the audit log can mint.
#[derive(Debug)]
pub struct PreparedApprove {
    client: GitDataClient,
    repo: RepoRef,
    branch: GitBranchName,
    attempt_id: ApproveAttemptId,
    prepared: PreparedPromotion,
}

impl PreparedApprove {
    /// Publish: re-verify the lease one last time, then issue the
    /// single branch-moving call of the whole pipeline
    /// (`PATCH /git/refs/heads/<branch>`) — or, on the noop path, no
    /// branch-moving call at all, once the lease `GET` has confirmed
    /// the branch still points at the staged tip. Either way the lease
    /// re-verification runs: recording a noop as approved asserts the
    /// branch is at that tip just as a PATCH asserts it moved there.
    ///
    /// `authority` is the audit log's proof that this attempt is
    /// durably recorded as `Uncertain`, i.e. that a crash from here on
    /// will be recognised as "a PATCH may have landed" rather than
    /// silently retried. It is not decoration: without it there is no
    /// way to call this function.
    ///
    /// The failure type splits by proof — see [`CommitError`]. The
    /// `FinalLease*` variants fire before any PATCH is sent (the
    /// caller resolves them like a prepare failure: retryable, no
    /// quarantine); only [`CommitError::UpdateRef`] proves a PATCH
    /// reached GitHub without a confirmed response. Every *other* way
    /// an approve can fail already happened, and failed, in
    /// [`prepare_approve`].
    pub async fn commit(
        self,
        authority: &UncertainAttempt,
    ) -> Result<RunApproveOutcome, CommitError> {
        assert_eq!(
            authority.attempt_id(),
            self.attempt_id,
            "PATCH authorised by the wrong attempt's Uncertain row",
        );
        let outcome =
            commit_prepared_promotion(&self.client, &self.repo, &self.branch, self.prepared)
                .await?;
        let new_app_tip = match outcome {
            ExecuteOutcome::Noop { tip } => tip,
            ExecuteOutcome::Advanced { new_app_tip } => new_app_tip,
        };
        Ok(RunApproveOutcome { new_app_tip })
    }
}

/// Drive the approve pipeline up to (but not including) the publish.
///
/// Inputs come from the audit/staging layer (the staged push receipt
/// plus the bundle bytes) and from the handler's mint step (the
/// `api_base` and `token` for the GitHub installation). The output is a
/// [`PreparedApprove`]; call [`PreparedApprove::commit`] — with the
/// attempt recorded `Uncertain` first — to actually move the branch.
///
/// On error the partially-populated staging dir is removed before
/// returning; on success its removal is *spawned* rather than awaited.
/// The final lease check lives inside the prepare, so on the success
/// path every awaited millisecond between here and the caller's PATCH
/// widens the window in which another actor can move the branch under
/// a still-passing lease — and a 256 MiB staging repo can take real
/// time to delete. The PATCH needs nothing from disk, so the deletion
/// runs concurrently. Removal failures are logged via `tracing::warn`
/// but never bubble up — a stale staging dir sits harmlessly at its
/// per-attempt path (it can never collide with a retry) until swept,
/// but a successful promote that returns Err to the operator would
/// force the bailiff to retry against a branch that already moved.
///
/// `signing_key` is required (B-track pins app-identity signing) and
/// is forwarded as `Some(...)` to [`prepare_fast_forward_plan`]. The
/// `Option` arm in the layer below is reserved for the
/// `AlreadyAtExpected` short-circuit, where no commits are signed
/// anyway, plus pre-B1d call sites that no longer exist in main.
// Each argument is a distinct concern (runtime config / GitHub
// access / repo identity / branch / lease anchor / bundle payload /
// signing identity / trailer set / attempt id).
// Bundling them adds a struct layer without simplifying the call site,
// so the flat shape matches `prepare_fast_forward_plan` precedent.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_approve(
    runtime: &PromoteRuntimeConfig,
    api_base: &str,
    token: &GitSecretValue,
    repo: &GitCloneRepo,
    branch: &GitBranchName,
    expected_remote_head: &GitObjectId,
    bundle_tip: &GitObjectId,
    bundle_bytes: &[u8],
    signing_key: &WritSigningKey,
    trailers: &[TrailerSource],
    attempt_id: ApproveAttemptId,
) -> Result<PreparedApprove, RunApproveError> {
    let staging = prepare_staging_repo(
        runtime,
        attempt_id,
        expected_remote_head,
        repo,
        token,
        bundle_bytes,
    )
    .await?;

    let result = prepare_approve_with_staging_repo(
        &staging,
        runtime,
        api_base,
        token,
        repo.as_repo_ref(),
        branch,
        expected_remote_head,
        bundle_tip,
        signing_key,
        trailers,
        attempt_id,
    )
    .await;

    let staging_path = staging.path().to_path_buf();
    match &result {
        Ok(_) => {
            // Success means the post-walk lease check has already run
            // and the caller's next move is the PATCH. Nothing past
            // this point may add latency to that window, so the
            // deletion is fire-and-forget; the dir is per-attempt so
            // a failure to delete strands only disk, never a retry.
            tokio::spawn(async move {
                if let Err(err) = tokio::fs::remove_dir_all(&staging_path).await {
                    tracing::warn!(
                        error = %err,
                        staging_dir = %staging_path.display(),
                        "approve staging dir cleanup failed; leaving for manual sweep",
                    );
                }
            });
        }
        Err(_) => {
            // No PATCH is coming, so there is no window to protect;
            // clean up before returning.
            if let Err(err) = tokio::fs::remove_dir_all(&staging_path).await {
                tracing::warn!(
                    error = %err,
                    staging_dir = %staging_path.display(),
                    "approve staging dir cleanup failed; leaving for manual sweep",
                );
            }
        }
    }

    result
}

/// HTTP-side half of the orchestrator. Public so wiremock tests can
/// drive it against a pre-populated staging repo without paying the
/// full prepare cost (real `git fetch` against a real origin is out
/// of scope for fast unit tests).
#[allow(clippy::too_many_arguments)]
pub async fn prepare_approve_with_staging_repo(
    staging: &StagingRepo,
    runtime: &PromoteRuntimeConfig,
    api_base: &str,
    token: &GitSecretValue,
    repo: &RepoRef,
    branch: &GitBranchName,
    expected_remote_head: &GitObjectId,
    bundle_tip: &GitObjectId,
    signing_key: &WritSigningKey,
    trailers: &[TrailerSource],
    attempt_id: ApproveAttemptId,
) -> Result<PreparedApprove, RunApproveError> {
    // Enforce the commit-type gate: the bundle has been unbundled into
    // the staging repo by this point;
    // `cat-file -t <bundle_tip>` reports the object's *literal* type
    // (`commit` / `tag` / `tree` / `blob`) without peeling, so a
    // hostile VM that stages an annotated tag SHA as the bundle tip
    // would be caught here instead of being silently peeled to its
    // target commit by the later `rev-list` walk.
    verify_bundle_tip_is_commit(runtime, staging.path(), bundle_tip).await?;

    let plan = plan_fast_forward_via_rev_list(
        bundle_tip,
        expected_remote_head,
        staging.path(),
        runtime.git_program(),
        runtime.step_timeout(),
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await?;

    // `cat_file_timeout` — *not* `step_timeout` — becomes the source's
    // per-object read deadline: the traversal reads a *local* object DB
    // over a pipe to an already-running child, so it wants a tight wedge
    // detector, whereas a step timeout has to cover a whole subprocess
    // including a network `fetch`. This is where the fix for the
    // unbounded `read_object_raw` pipe awaits lives — per object, so the
    // walker's GitHub uploads (bounded separately by `GitDataTimeouts`,
    // and deliberately allowed to run slower) are never folded into it.
    let source = CatFileObjectSource::open(
        staging.path(),
        runtime.git_program(),
        STAGING_REPO_MAX_OBJECT_BYTES,
        runtime.cat_file_timeout(),
    )
    .await?;

    // Bounded on every phase: an approve runs with the attempt row in
    // flight, so a GitHub endpoint that black-holes or withholds must
    // fail the attempt rather than park it forever.
    let client = GitDataClient::new(
        GitDataTimeouts::production(),
        api_base.to_string(),
        token.as_str().to_string(),
    );

    // The cat-file traversal below is bounded from *inside* the object
    // source: each `read_object_raw` runs under the per-object
    // `read_timeout` wired above, and a wedged read fails as
    // `ExecuteError::Replay` — through this normal error return, so it
    // still crosses the `prepare::objects_uploaded` crash boundary. The
    // GitHub calls keep their own `GitDataTimeouts` budgets. Nothing
    // here needs a whole-traversal deadline, which would wrongly fail a
    // legitimate multi-object replay whose serial uploads outlast one
    // step.
    let prepared = prepare_fast_forward_plan(
        &client,
        repo,
        branch,
        expected_remote_head,
        &source,
        plan,
        trailers,
        Some(signing_key),
    )
    .await;
    // Unconditional: on the error paths the walker may still have
    // uploaded objects before failing, and GitHub-side durable state
    // is exactly what a crash boundary marks.
    crate::crash_point::point("prepare::objects_uploaded").await;

    // `close()` reaps the `git cat-file --batch` child even on error
    // paths above; ignore its result because it only signals stderr
    // chatter at this point, and the orchestrator's success/failure is
    // fully captured by `prepared`. Unlike the per-object reads, `close`
    // polls `waitid` for the leader's exit in a loop that never returns
    // for a wedged child, so it needs its own external deadline. On
    // elapse the dropped `close()` future runs its internal
    // `PgidCleanupGuard`, which SIGKILLs the process group (see
    // `cat_file_source_close_cancellation_kills_process_group`).
    // `cat_file_timeout` again: reaping a child that has been told to
    // finish is the same class of local interaction as reading one
    // object from it, and a step-sized ceiling here would leave a
    // wedged child unreaped for minutes.
    if tokio::time::timeout(runtime.cat_file_timeout(), source.close())
        .await
        .is_err()
    {
        tracing::warn!(
            cat_file_timeout = ?runtime.cat_file_timeout(),
            "`git cat-file --batch` did not exit within the cat-file timeout; \
             SIGKILLed its process group via the cancellation guard",
        );
    }

    Ok(PreparedApprove {
        client,
        repo: repo.clone(),
        branch: branch.clone(),
        attempt_id,
        prepared: prepared?,
    })
}

/// Owns the on-disk staging repo path for a single approve cycle.
///
/// The `Drop` impl deliberately does *not* `rm -rf` the path: the
/// orchestrator runs cleanup explicitly on its own (success or error)
/// so failures can be logged. Tests construct this directly via the
/// `#[cfg(test)]`-only `from_path_for_test` constructor against a
/// pre-populated repo so they can drive `run_approve_with_staging_repo`
/// without the fetch.
#[derive(Debug)]
pub struct StagingRepo {
    path: PathBuf,
}

impl StagingRepo {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Wrap a caller-prepared bare repo path. Only used by tests of
    /// `run_approve_with_staging_repo`; production code goes through
    /// [`prepare_staging_repo`].
    #[cfg(test)]
    pub(crate) fn from_path_for_test(path: PathBuf) -> Self {
        Self { path }
    }
}

/// Build a fresh bare staging repo at `<work_root>/approve/<attempt_id>`
/// containing both the staged push's prerequisite (fetched from
/// `clone_base_url`/`<owner>/<name>.git`) and the bundle's contents
/// (unbundled from a temp file inside the same dir).
///
/// The dir is keyed by *attempt* id, not push-request id, and that
/// choice is load-bearing for crash recovery: a broker that dies
/// mid-prepare never runs its cleanup, and boot reconcile is
/// deliberately filesystem-blind (the audit log is the system of
/// record). Since every retry mints a fresh attempt id, the residue
/// of a dead attempt can never collide with a new one — it just sits
/// at the dead attempt's path until an operator sweeps it. Keying by
/// request id would make the same residue block every retry of that
/// push with `StagingDirExists`.
///
/// Refuses to proceed if the per-attempt dir already exists — the
/// attempt_id is a fresh UUID per approve and the audit DAO refuses
/// concurrent attempts, so the only ways to hit this are UUID
/// collision or two brokers sharing a `work_root`. Refusing is the
/// safest outcome for both.
pub async fn prepare_staging_repo(
    runtime: &PromoteRuntimeConfig,
    attempt_id: ApproveAttemptId,
    expected_remote_head: &GitObjectId,
    repo: &GitCloneRepo,
    token: &GitSecretValue,
    bundle_bytes: &[u8],
) -> Result<StagingRepo, PrepareStagingError> {
    let staging_dir = staging_dir_for(runtime, attempt_id);
    if let Some(parent) = staging_dir.parent() {
        // Parent is *shared* across approve requests so we must
        // tolerate AlreadyExists (it persists once any first approve
        // has run). `<work_root>` itself is owned by the broker's
        // config layer (config.rs creates it at 0700) so we only need
        // to materialise the single `<work_root>/approve` level here;
        // a missing `<work_root>` is a config error and surfaces as
        // NotFound rather than being silently filled in at the
        // default umask.
        ensure_private_dir(parent).await.map_err(|source| {
            PrepareStagingError::AllocateStagingDir {
                path: parent.to_path_buf(),
                source,
            }
        })?;
    }
    // The per-attempt staging dir, in contrast, MUST be allocated
    // exclusively by this call. `create_exclusive_private_dir` does
    // a single atomic `mkdir(path, 0700)` and returns AlreadyExists
    // as a hard error; this collapses the prior `try_exists` +
    // `create_private_dir` pair (which had a TOCTOU window between
    // the existence check and the mkdir, and was vulnerable to two
    // concurrent approves both winning the existence check and then
    // racing on `staged.bundle` / `remove_dir_all`). The dedicated
    // `StagingDirExists` variant lets the handler surface "duplicate
    // concurrent approve" distinctly from generic mkdir failures.
    create_exclusive_private_dir(&staging_dir)
        .await
        .map_err(|source| match source.kind() {
            std::io::ErrorKind::AlreadyExists => {
                PrepareStagingError::StagingDirExists(staging_dir.clone())
            }
            _ => PrepareStagingError::AllocateStagingDir {
                path: staging_dir.clone(),
                source,
            },
        })?;
    crate::crash_point::point("prepare::staging_dir_created").await;

    // Past this point we own `staging_dir` on disk; any failure must
    // clean it up so the next retry can re-mkdir without tripping the
    // refuse-if-exists guard at the top. `run_approve`'s own cleanup
    // only fires when prepare *succeeds* and produces a `StagingRepo`.
    match run_prepare_steps(
        runtime,
        &staging_dir,
        expected_remote_head,
        repo,
        token,
        bundle_bytes,
    )
    .await
    {
        Ok(()) => Ok(StagingRepo { path: staging_dir }),
        Err(err) => {
            if let Err(cleanup) = tokio::fs::remove_dir_all(&staging_dir).await {
                tracing::warn!(
                    error = %cleanup,
                    staging_dir = %staging_dir.display(),
                    "approve staging dir cleanup after prepare failure failed; leaving for manual sweep",
                );
            }
            Err(err)
        }
    }
}

async fn run_prepare_steps(
    runtime: &PromoteRuntimeConfig,
    staging_dir: &std::path::Path,
    expected_remote_head: &GitObjectId,
    repo: &GitCloneRepo,
    token: &GitSecretValue,
    bundle_bytes: &[u8],
) -> Result<(), PrepareStagingError> {
    let bundle_path = staging_dir.join("staged.bundle");
    write_private_file(&bundle_path, bundle_bytes)
        .await
        .map_err(|source| PrepareStagingError::WriteBundleFile {
            path: bundle_path.clone(),
            source,
        })?;
    crate::crash_point::point("prepare::bundle_written").await;

    let init = build_init_bare_invocation(runtime, staging_dir);
    clean_git::run_clean_git(&init, runtime.step_timeout(), None)
        .await
        .map_err(|e| PrepareStagingError::GitInit(e.to_string()))?;
    crate::crash_point::point("prepare::repo_initialised").await;

    let fetch = build_fetch_prereq_invocation(runtime, staging_dir, repo, expected_remote_head);
    clean_git::run_clean_git(&fetch, runtime.step_timeout(), Some(token.as_str()))
        .await
        .map_err(|e| PrepareStagingError::GitFetch(e.to_string()))?;
    crate::crash_point::point("prepare::prereq_fetched").await;

    let unbundle = build_unbundle_invocation(runtime, staging_dir, &bundle_path);
    clean_git::run_clean_git(&unbundle, runtime.step_timeout(), None)
        .await
        .map_err(|e| PrepareStagingError::GitUnbundle(e.to_string()))?;
    crate::crash_point::point("prepare::unbundled").await;

    Ok(())
}

pub(crate) fn staging_dir_for(
    runtime: &PromoteRuntimeConfig,
    attempt_id: ApproveAttemptId,
) -> PathBuf {
    runtime
        .work_root()
        .join("approve")
        .join(attempt_id.to_string())
}

/// Atomic-mode `mkdir(path, 0700)` that fails if `path` already
/// exists, then unconditionally chmods to *exactly* 0o700. Use this
/// for any directory the caller must own *exclusively* — a duplicate
/// concurrent caller should be rejected, not silently joined onto
/// the same path.
///
/// Why both an atomic-mode create *and* a follow-up chmod:
///
/// - `DirBuilder::mode(0o700)` resolves to a single `mkdir(path,
///   0700)` syscall. The kernel ANDs `0700` with the inverse of the
///   process umask, so the *creation* mode is always `≤ 0o700`. That
///   closes a TOCTOU race a plain `create_dir` + separate
///   `set_permissions` would open: under a permissive umask (e.g.
///   `0o000`) the directory would briefly exist at `0o777 & ~umask =
///   0o777` and a local user holding an `O_PATH` fd to the parent
///   could `openat` into it during that window and keep the fd
///   across the chmod (POSIX permission checks fire at `open` time,
///   not at use time), reading the staged bundle and loose objects
///   even after the mode tightened.
/// - The follow-up `set_permissions(0o700)` is *not* a security
///   measure; it widens the mode back from the umask-clamped result.
///   Under a restrictive umask (e.g. `0o077`, or a paranoid
///   `0o777`), `mkdir(path, 0700)` would land the directory at
///   `0o600` or even `0o000`, at which point the daemon couldn't
///   create `staged.bundle` inside it and the approve would
///   self-DoS. The chmod restores exact 0o700 so the owner-writable
///   bits the daemon needs are present regardless of inherited
///   umask.
///
/// Matches `git_push_staging::create_private_dir`.
async fn create_exclusive_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    let mut builder = tokio::fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        builder.mode(0o700);
    }
    builder.create(path).await?;
    // If the chmod step fails after the mkdir succeeded, unwind:
    // remove the now-partially-initialized dir so a retry can mkdir
    // again. Without this, a transient chmod failure would turn into
    // `StagingDirExists` on every retry, because the helper's
    // contract is "this call mints the dir" and the on-disk artifact
    // from a failed call would otherwise collide with the next one.
    if let Err(chmod_err) = set_private_dir_permissions(path).await {
        // Best-effort cleanup: if the rmdir itself fails (e.g. we
        // lost the ability to remove what we just created), surface
        // the *original* chmod error rather than the cleanup error —
        // the chmod failure is what the caller actually needs to
        // react to.
        let _ = tokio::fs::remove_dir(path).await;
        return Err(chmod_err);
    }
    Ok(())
}

/// Ensure `path` exists as a 0700 directory, tolerating the case
/// where it already exists (and tightening its mode if so). Use this
/// for *shared* directories like `<work_root>/approve` that any
/// approve request can lazily materialise — the first caller mints
/// the directory, later callers just validate the mode is right.
///
/// Wraps [`create_exclusive_private_dir`] and absorbs AlreadyExists,
/// then unconditionally chmods to 0700 to tighten the perms in case
/// the directory pre-existed at a looser mode (e.g. an operator who
/// hand-created `work_root` with default umask before pointing the
/// daemon at it). Matches `git_push_staging::create_private_dir`.
async fn ensure_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    match create_exclusive_private_dir(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            set_private_dir_permissions(path).await
        }
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
async fn set_private_dir_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await
}

#[cfg(not(unix))]
async fn set_private_dir_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Write `body` to `path` with mode 0600 on Unix, refusing to clobber
/// an existing file. Matches `git_push_staging::write_private_file`.
///
/// The `mode(0o600)` request on `OpenOptions` resolves to a single
/// `open(O_CREAT|O_EXCL, 0600)` syscall, which the kernel ANDs with
/// the inverse of the process umask — so the *creation* mode is `≤
/// 0o600`. That closes the same TOCTOU race the dir helper closes:
/// no transient window at owner-`0o644` / group-readable. The
/// follow-up chmod on Unix then *widens* the mode back to exactly
/// 0o600, because under a restrictive umask (e.g. `0o077` or a
/// paranoid `0o777`) the initial mode would have been `0o000`, and
/// `git bundle unbundle` reopens the file *by path* after we drop the
/// fd — losing owner-read would make approve self-DoS even though
/// the through-fd `write_all` succeeded.
async fn write_private_file(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    // tokio's `OpenOptions::mode` is an inherent method on Unix
    // builds (not a trait), so no `OpenOptionsExt` import is needed
    // — on non-Unix builds the call simply isn't compiled.
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    use tokio::io::AsyncWriteExt;
    let mut file = options.open(path).await?;
    file.write_all(body).await?;
    file.sync_all().await?;
    drop(file);
    set_private_file_permissions(path).await
}

#[cfg(unix)]
async fn set_private_file_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await
}

#[cfg(not(unix))]
async fn set_private_file_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// `git -C <staging_dir> init --bare --quiet`.
///
/// No secret needed; the hardened env keeps `core.fsmonitor`, custom
/// templates, and credential helpers from running.
pub(crate) fn build_init_bare_invocation(
    runtime: &PromoteRuntimeConfig,
    staging_dir: &std::path::Path,
) -> CleanGitInvocation {
    CleanGitInvocation::new(
        runtime.git_program().to_path_buf(),
        [
            OsString::from("-C"),
            staging_dir.as_os_str().to_os_string(),
            OsString::from("init"),
            OsString::from("--bare"),
            OsString::from("--quiet"),
        ],
        clean_git_config_env(),
        Vec::new(),
    )
}

/// `git -C <staging_dir> -c credential.helper= -c credential.useHttpPath=true \
///       fetch --no-tags --quiet <url> <expected_remote_head>`.
///
/// Credential injection mirrors
/// [`crate::vm_git_bundle::GitCloneBundlePlan::clone_mirror_command`]:
/// `credential.helper=` is forced empty so git falls back to
/// `GIT_ASKPASS`, the askpass program reads the token from the env
/// var named by [`crate::vm_git_bundle::GitCredentialBoundary::token_env`],
/// and `GIT_TERMINAL_PROMPT=0` suppresses the interactive fallback.
/// `--no-tags` keeps the fetch from inflating the staging repo with
/// upstream tag refs we never look at, and `--quiet` keeps stderr off
/// the failure path when the fetch succeeds.
pub(crate) fn build_fetch_prereq_invocation(
    runtime: &PromoteRuntimeConfig,
    staging_dir: &std::path::Path,
    repo: &GitCloneRepo,
    expected_remote_head: &GitObjectId,
) -> CleanGitInvocation {
    let url = runtime.clone_base_url().repo_url(repo);
    let credential = runtime.credential();
    let args = [
        OsString::from("-C"),
        staging_dir.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from("credential.helper="),
        OsString::from("-c"),
        OsString::from("credential.useHttpPath=true"),
        OsString::from("fetch"),
        OsString::from("--no-tags"),
        OsString::from("--quiet"),
        OsString::from("--"),
        OsString::from(url),
        OsString::from(expected_remote_head.as_str()),
    ];
    let mut env = clean_git_config_env();
    env.push(CleanGitEnv::new("GIT_TERMINAL_PROMPT", "0"));
    env.push(CleanGitEnv::new(
        "GIT_ASKPASS",
        credential.askpass_program().display().to_string(),
    ));
    CleanGitInvocation::new(
        runtime.git_program().to_path_buf(),
        args,
        env,
        vec![credential.token_env().as_str().to_string()],
    )
}

/// `git -C <staging_dir> cat-file -t <bundle_tip>`.
///
/// Asserts that `bundle_tip` resolves to a commit object — `cat-file
/// -t` returns the object's literal type (no peeling), so an
/// annotated-tag SHA shows up as `"tag"` rather than passing through
/// as `"commit"` like `rev-parse --verify <sha>^{commit}` would.
/// Enforces the post-unbundle commit-type invariant on the bundle tip.
pub(crate) fn build_resolve_bundle_tip_invocation(
    runtime: &PromoteRuntimeConfig,
    staging_dir: &std::path::Path,
    bundle_tip: &GitObjectId,
) -> CleanGitInvocation {
    CleanGitInvocation::new(
        runtime.git_program().to_path_buf(),
        [
            OsString::from("-C"),
            staging_dir.as_os_str().to_os_string(),
            OsString::from("cat-file"),
            OsString::from("-t"),
            OsString::from(bundle_tip.as_str()),
        ],
        clean_git_config_env(),
        Vec::new(),
    )
}

/// Run `cat-file -t <bundle_tip>` against the staging repo and reject
/// anything other than a `commit` object. See
/// [`build_resolve_bundle_tip_invocation`] for the motivation.
async fn verify_bundle_tip_is_commit(
    runtime: &PromoteRuntimeConfig,
    staging_dir: &std::path::Path,
    bundle_tip: &GitObjectId,
) -> Result<(), RunApproveError> {
    let invocation = build_resolve_bundle_tip_invocation(runtime, staging_dir, bundle_tip);
    let stdout = clean_git::run_clean_git_capture_stdout(
        &invocation,
        runtime.step_timeout(),
        SMALL_STDOUT_CAP,
        None,
    )
    .await
    .map_err(|e| RunApproveError::ResolveBundleTip(e.to_string()))?;
    let text = std::str::from_utf8(&stdout).unwrap_or("<non-utf8>");
    let actual = text.trim_end();
    if actual == "commit" {
        Ok(())
    } else {
        Err(RunApproveError::BundleTipNotACommit {
            sha: bundle_tip.as_str().to_string(),
            actual_type: actual.to_string(),
        })
    }
}

/// `git -C <staging_dir> bundle unbundle <bundle_path>`.
///
/// `unbundle` writes loose objects (or a pack, depending on version)
/// into the bare repo's object database. No ref is created; the
/// planner runs `rev-list` directly against the SHA the bundle named,
/// which is reachable via the unpacked objects.
///
/// `git bundle unbundle` does not accept `--quiet` — its sole option
/// is `--progress`, which we leave off so progress chatter stays off
/// stderr by default and we still see real errors when they fire.
pub(crate) fn build_unbundle_invocation(
    runtime: &PromoteRuntimeConfig,
    staging_dir: &std::path::Path,
    bundle_path: &std::path::Path,
) -> CleanGitInvocation {
    CleanGitInvocation::new(
        runtime.git_program().to_path_buf(),
        [
            OsString::from("-C"),
            staging_dir.as_os_str().to_os_string(),
            OsString::from("bundle"),
            OsString::from("unbundle"),
            bundle_path.as_os_str().to_os_string(),
        ],
        clean_git_config_env(),
        Vec::new(),
    )
}

#[cfg(test)]
mod tests;
