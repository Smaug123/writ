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
//! [`PreparedApprove::commit`] issues the `PATCH`, and demands an
//! [`UncertainAttempt`] to do it. The handler mints that witness from
//! the audit log in between, so the durable "a PATCH may exist" record
//! brackets the PATCH as tightly as it can — a crash during the fetch,
//! plan or upload leaves an attempt that boot reconcile resolves on its
//! own instead of one an operator has to reconcile by hand.
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
use crate::clean_git::{self, CleanGitEnv, CleanGitInvocation, clean_git_config_env};
use crate::core::{ApproveAttemptId, RepoRef, RequestId};
use crate::git_push_promote::{
    ExecuteError, ExecuteOutcome, PreparedPromotion, PromoteRuntimeConfig, UpdateRefError,
    commit_prepared_promotion, prepare_fast_forward_plan,
};
use crate::git_push_replay::TrailerSource;
use crate::git_push_replay_object_source::{CatFileObjectSource, OpenError};
use crate::git_push_replay_walker::{FastForwardPlanError, plan_fast_forward_via_rev_list};
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
/// retryable has its own type, [`UpdateRefError`], and can only come
/// out of [`PreparedApprove::commit`].
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
    /// (mirroring `git_push_replay::ingest_bundle`'s post-unbundle
    /// `cat-file -t == commit` invariant) prevents that.
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
    /// Publish: issue the single branch-moving call of the whole
    /// pipeline (`PATCH /git/refs/heads/<branch>`), or nothing at all
    /// if the branch already points at the staged tip.
    ///
    /// `authority` is the audit log's proof that this attempt is
    /// durably recorded as `Uncertain`, i.e. that a crash from here on
    /// will be recognised as "a PATCH may have landed" rather than
    /// silently retried. It is not decoration: without it there is no
    /// way to call this function.
    ///
    /// The single failure type is deliberate — see [`UpdateRefError`].
    /// Every *other* way an approve can fail already happened, and
    /// failed, in [`prepare_approve`].
    pub async fn commit(
        self,
        authority: &UncertainAttempt,
    ) -> Result<RunApproveOutcome, UpdateRefError> {
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
/// On error the partially-populated staging dir is still removed; on
/// success the staging dir is removed before returning. Removal
/// failures are logged via `tracing::warn` but never bubble up — a
/// stale staging dir is recoverable on the next boot reconcile, but a
/// successful promote that returns Err to the operator is much worse
/// (it would force the bailiff to retry against a branch that already
/// moved).
///
/// `signing_key` is required (B-track pins app-identity signing) and
/// is forwarded as `Some(...)` to [`prepare_fast_forward_plan`]. The
/// `Option` arm in the layer below is reserved for the
/// `AlreadyAtExpected` short-circuit, where no commits are signed
/// anyway, plus pre-B1d call sites that no longer exist in main.
// Each argument is a distinct concern (runtime config / GitHub
// access / repo identity / branch / lease anchor / bundle payload /
// signing identity / trailer set / per-request and attempt ids).
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
    request_id: RequestId,
    attempt_id: ApproveAttemptId,
) -> Result<PreparedApprove, RunApproveError> {
    let staging = prepare_staging_repo(
        runtime,
        request_id,
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

    if let Err(err) = tokio::fs::remove_dir_all(staging.path()).await {
        tracing::warn!(
            error = %err,
            staging_dir = %staging.path().display(),
            "approve staging dir cleanup failed; leaving for boot-time reconciliation",
        );
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
    // Mirror `git_push_replay::ingest_bundle`'s commit-type gate. The
    // bundle has been unbundled into the staging repo by this point;
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
    )
    .await?;

    let source = CatFileObjectSource::open(
        staging.path(),
        runtime.git_program(),
        STAGING_REPO_MAX_OBJECT_BYTES,
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

    // `close()` reaps the `git cat-file --batch` child even on error
    // paths above; ignore its result because it only signals stderr
    // chatter at this point, and the orchestrator's success/failure
    // is fully captured by `prepared`.
    let _ = source.close().await;

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

/// Build a fresh bare staging repo at `<work_root>/approve/<request_id>`
/// containing both the staged push's prerequisite (fetched from
/// `clone_base_url`/`<owner>/<name>.git`) and the bundle's contents
/// (unbundled from a temp file inside the same dir).
///
/// Refuses to proceed if the per-request staging dir already exists —
/// the request_id is a fresh UUID per RPC so the only way to hit this
/// is a duplicate concurrent approve, which would be the broker
/// shipping two parallel mints for the same staged push. Refusing
/// here is the safest outcome.
pub async fn prepare_staging_repo(
    runtime: &PromoteRuntimeConfig,
    request_id: RequestId,
    expected_remote_head: &GitObjectId,
    repo: &GitCloneRepo,
    token: &GitSecretValue,
    bundle_bytes: &[u8],
) -> Result<StagingRepo, PrepareStagingError> {
    let staging_dir = staging_dir_for(runtime, request_id);
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
    // The per-request staging dir, in contrast, MUST be allocated
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
                    "approve staging dir cleanup after prepare failure failed; leaving for boot-time reconciliation",
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

    let init = build_init_bare_invocation(runtime, staging_dir);
    clean_git::run_clean_git(&init, runtime.step_timeout(), None)
        .await
        .map_err(|e| PrepareStagingError::GitInit(e.to_string()))?;

    let fetch = build_fetch_prereq_invocation(runtime, staging_dir, repo, expected_remote_head);
    clean_git::run_clean_git(&fetch, runtime.step_timeout(), Some(token.as_str()))
        .await
        .map_err(|e| PrepareStagingError::GitFetch(e.to_string()))?;

    let unbundle = build_unbundle_invocation(runtime, staging_dir, &bundle_path);
    clean_git::run_clean_git(&unbundle, runtime.step_timeout(), None)
        .await
        .map_err(|e| PrepareStagingError::GitUnbundle(e.to_string()))?;

    Ok(())
}

pub(crate) fn staging_dir_for(runtime: &PromoteRuntimeConfig, request_id: RequestId) -> PathBuf {
    runtime
        .work_root()
        .join("approve")
        .join(request_id.to_string())
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
/// Mirrors the invariant
/// [`crate::git_push_replay::ingest_bundle`] enforces post-unbundle.
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
    let stdout = clean_git::run_clean_git_capture_stdout(&invocation, runtime.step_timeout(), None)
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
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::str::FromStr;
    use std::time::Duration;

    use serde_json::json;
    use time::macros::datetime;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::github_git_db::{CommitIdentity, GitDataError};
    use crate::vm_git::GitBranchName;
    use crate::vm_git_bundle::{GitCloneBaseUrl, GitCredentialBoundary, GitSecretEnvVar};

    // ---------- shared fixtures ----------

    fn sample_request_id() -> RequestId {
        // Deterministic so test failure messages stay reproducible.
        RequestId::from_uuid(uuid::Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap())
    }

    fn sample_object_id(nibble: char) -> GitObjectId {
        GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
    }

    fn sample_repo() -> GitCloneRepo {
        GitCloneRepo::new(RepoRef::from_str("owner/name").unwrap()).unwrap()
    }

    fn sample_token() -> GitSecretValue {
        GitSecretValue::new("ghs_test_token_value").unwrap()
    }

    const PRIVATE_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");

    fn sample_signing_key() -> WritSigningKey {
        // Re-uses the same test fixture the promote/walker tests use so
        // signed commit bodies stay byte-identical across the B-track
        // test suite — useful when a regression somewhere downstream
        // changes the canonicalisation.
        WritSigningKey::from_openssh_pem(PRIVATE_PEM).expect("fixture private key parses")
    }

    fn sample_runtime(work_root: PathBuf) -> PromoteRuntimeConfig {
        PromoteRuntimeConfig::new(
            PathBuf::from("/usr/bin/git"),
            GitCloneBaseUrl::github(),
            GitCredentialBoundary::new(
                PathBuf::from("/usr/local/bin/fake-askpass"),
                GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap(),
            )
            .unwrap(),
            work_root,
            Duration::from_secs(30),
        )
        .unwrap()
    }

    // ---------- pure invocation-shape tests ----------

    #[test]
    fn init_bare_invocation_pins_argv_and_clean_env() {
        let runtime = sample_runtime(PathBuf::from("/tmp/promote"));
        let staging = PathBuf::from("/tmp/promote/approve/abc");
        let inv = build_init_bare_invocation(&runtime, &staging);
        assert_eq!(inv.program(), Path::new("/usr/bin/git"));
        assert_eq!(
            inv.display_args_lossy(),
            vec![
                "-C".to_string(),
                staging.display().to_string(),
                "init".to_string(),
                "--bare".to_string(),
                "--quiet".to_string(),
            ],
        );
        assert!(inv.required_secret_env().is_empty());
        let names: Vec<&str> = inv.env().iter().map(|e| e.name()).collect();
        assert!(names.contains(&"GIT_CONFIG_NOSYSTEM"));
        assert!(names.contains(&"HOME"));
        assert!(!names.contains(&"GIT_ASKPASS"));
    }

    #[test]
    fn fetch_prereq_invocation_pins_credential_wiring() {
        let runtime = sample_runtime(PathBuf::from("/tmp/promote"));
        let staging = PathBuf::from("/tmp/promote/approve/abc");
        let repo = sample_repo();
        let head = sample_object_id('a');
        let inv = build_fetch_prereq_invocation(&runtime, &staging, &repo, &head);
        assert_eq!(inv.program(), Path::new("/usr/bin/git"));
        assert_eq!(
            inv.display_args_lossy(),
            vec![
                "-C".to_string(),
                staging.display().to_string(),
                "-c".to_string(),
                "credential.helper=".to_string(),
                "-c".to_string(),
                "credential.useHttpPath=true".to_string(),
                "fetch".to_string(),
                "--no-tags".to_string(),
                "--quiet".to_string(),
                "--".to_string(),
                "https://github.com/owner/name.git".to_string(),
                head.as_str().to_string(),
            ],
        );
        assert_eq!(inv.required_secret_env(), &["WRIT_GIT_TOKEN".to_string()]);
        let env: std::collections::BTreeMap<&str, &str> =
            inv.env().iter().map(|e| (e.name(), e.value())).collect();
        assert_eq!(env.get("GIT_TERMINAL_PROMPT"), Some(&"0"));
        assert_eq!(env.get("GIT_ASKPASS"), Some(&"/usr/local/bin/fake-askpass"),);
        // Hardened env must still be present alongside the fetch-specific bits.
        assert_eq!(env.get("GIT_CONFIG_NOSYSTEM"), Some(&"1"));
        assert_eq!(env.get("GIT_CONFIG_GLOBAL"), Some(&"/dev/null"));
        assert_eq!(env.get("HOME"), Some(&"/dev/null"));
    }

    #[test]
    fn unbundle_invocation_pins_argv_and_takes_no_secret() {
        let runtime = sample_runtime(PathBuf::from("/tmp/promote"));
        let staging = PathBuf::from("/tmp/promote/approve/abc");
        let bundle = staging.join("staged.bundle");
        let inv = build_unbundle_invocation(&runtime, &staging, &bundle);
        assert_eq!(
            inv.display_args_lossy(),
            vec![
                "-C".to_string(),
                staging.display().to_string(),
                "bundle".to_string(),
                "unbundle".to_string(),
                bundle.display().to_string(),
            ],
        );
        // `--quiet` must not appear: `git bundle unbundle` rejects it as
        // an unknown flag and the subprocess would exit with usage
        // status, which would mask the real approve outcome.
        assert!(
            !inv.display_args_lossy().iter().any(|a| a == "--quiet"),
            "`git bundle unbundle` does not accept --quiet",
        );
        assert!(inv.required_secret_env().is_empty());
    }

    #[test]
    fn staging_dir_for_isolates_each_request_under_approve() {
        let runtime = sample_runtime(PathBuf::from("/tmp/promote"));
        let id_a = sample_request_id();
        let id_b = RequestId::new();
        let a = staging_dir_for(&runtime, id_a);
        let b = staging_dir_for(&runtime, id_b);
        assert_ne!(a, b);
        assert!(a.starts_with("/tmp/promote/approve/"));
        assert!(b.starts_with("/tmp/promote/approve/"));
    }

    // ---------- prepare_staging_repo guard test (does not run git) ----------

    #[tokio::test]
    async fn prepare_refuses_pre_existing_staging_dir() {
        let work = tempfile::tempdir().unwrap();
        let runtime = sample_runtime(work.path().to_path_buf());
        let request_id = sample_request_id();
        let staging = staging_dir_for(&runtime, request_id);
        // Plant a colliding dir.
        std::fs::create_dir_all(&staging).unwrap();

        let err = prepare_staging_repo(
            &runtime,
            request_id,
            &sample_object_id('a'),
            &sample_repo(),
            &sample_token(),
            b"unused-bundle",
        )
        .await
        .expect_err("must refuse pre-existing staging dir");

        assert!(matches!(
            err,
            PrepareStagingError::StagingDirExists(ref p) if p == &staging
        ));
    }

    // ---------- real-git integration: build_real_staging_repo helper ----------

    /// Locate the system `git` for integration tests. Skips when absent
    /// rather than panicking so the suite stays runnable on hermetic
    /// builders that don't expose a system git.
    fn maybe_git() -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("git");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }

    /// Run `git -C <repo> <args>` under the hardened env plus pinned
    /// committer identity so commit SHAs are deterministic across runs.
    fn run_git(git: &Path, repo: &Path, args: &[&str]) -> std::process::Output {
        let output = Command::new(git)
            .arg("-C")
            .arg(repo)
            .args(args)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_COUNT", "0")
            .env("HOME", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_AUTHOR_DATE", "2024-01-15T10:30:45Z")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_DATE", "2024-01-15T10:30:45Z")
            .output()
            .unwrap_or_else(|err| panic!("spawning git {args:?} failed: {err}"));
        assert!(
            output.status.success(),
            "git -C {} {args:?} failed: stdout={:?} stderr={}",
            repo.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        output
    }

    fn rev_parse(git: &Path, repo: &Path, rev: &str) -> GitObjectId {
        let out = run_git(git, repo, &["rev-parse", rev]);
        let sha = String::from_utf8(out.stdout).unwrap().trim().to_string();
        GitObjectId::new(sha).expect("rev-parse output must be a valid 40-hex SHA")
    }

    /// Spin up a non-bare workspace, two empty commits (parent -> child),
    /// then push both into a fresh bare repo to act as the staging repo
    /// the orchestrator's planner reads from. Returns the staging dir
    /// plus the two SHAs.
    fn build_real_staging_repo() -> (tempfile::TempDir, PathBuf, GitObjectId, GitObjectId) {
        let git = maybe_git().expect("real-git integration tests need `git` on PATH");
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        let staging = tmp.path().join("staging.git");
        std::fs::create_dir(&work).unwrap();
        run_git(&git, &work, &["init", "--quiet", "--initial-branch=main"]);
        run_git(
            &git,
            &work,
            &["commit", "--allow-empty", "--quiet", "-m", "parent"],
        );
        let parent = rev_parse(&git, &work, "HEAD");
        run_git(
            &git,
            &work,
            &["commit", "--allow-empty", "--quiet", "-m", "child"],
        );
        let child = rev_parse(&git, &work, "HEAD");

        run_git(
            &git,
            tmp.path(),
            &["init", "--bare", "--quiet", "staging.git"],
        );
        run_git(
            &git,
            &staging,
            &[
                "fetch",
                "--no-tags",
                "--quiet",
                &work.display().to_string(),
                "refs/heads/main:refs/heads/main",
            ],
        );

        (tmp, staging, parent, child)
    }

    fn sample_identity() -> CommitIdentity {
        CommitIdentity::new(
            "Test",
            "test@example.invalid",
            datetime!(2024-01-15 10:30:45 UTC),
        )
        .expect("sample identity must be valid")
    }

    /// Drive both production halves back to back, standing in for the
    /// `mark_attempt_uncertain` the broker does in between. Tests that
    /// care about *which* half a failure comes from call the halves
    /// directly instead.
    #[allow(clippy::too_many_arguments)]
    async fn prepare_and_commit(
        staging: &StagingRepo,
        runtime: &PromoteRuntimeConfig,
        api_base: &str,
        repo: &RepoRef,
        branch: &GitBranchName,
        expected_remote_head: &GitObjectId,
        bundle_tip: &GitObjectId,
    ) -> Result<Result<RunApproveOutcome, UpdateRefError>, RunApproveError> {
        let attempt_id = ApproveAttemptId::new();
        let prepared = prepare_approve_with_staging_repo(
            staging,
            runtime,
            api_base,
            &sample_token(),
            repo,
            branch,
            expected_remote_head,
            bundle_tip,
            &sample_signing_key(),
            &[],
            attempt_id,
        )
        .await?;
        Ok(prepared
            .commit(&UncertainAttempt::for_test(attempt_id))
            .await)
    }

    fn ref_response_body(branch: &str, sha: &GitObjectId) -> serde_json::Value {
        json!({
            "ref": format!("refs/heads/{branch}"),
            "object": { "sha": sha.as_str(), "type": "commit" },
        })
    }

    fn runtime_pointed_at(staging_parent: &Path) -> PromoteRuntimeConfig {
        // Use the *real* `git` binary so the planner and CatFileObjectSource
        // can run against the staging repo.
        let git = maybe_git().expect("real-git integration tests need `git` on PATH");
        PromoteRuntimeConfig::new(
            git,
            GitCloneBaseUrl::github(),
            GitCredentialBoundary::new(
                PathBuf::from("/usr/local/bin/fake-askpass"),
                GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap(),
            )
            .unwrap(),
            staging_parent.to_path_buf(),
            Duration::from_secs(30),
        )
        .unwrap()
    }

    // ---------- run_approve_with_staging_repo: wiremock-backed ----------

    /// Replay arm happy path: pre-walk lease matches, walker uploads
    /// the single commit (its empty tree + the commit), post-walk
    /// lease still matches, PATCH advances the branch. Asserted by
    /// counts on each mock plus the returned `new_app_tip`.
    #[tokio::test]
    async fn run_approve_advances_branch_when_bundle_is_fast_forward() {
        if maybe_git().is_none() {
            eprintln!("skipping: `git` not on PATH");
            return;
        }
        let (tmp, staging_path, parent, child) = build_real_staging_repo();
        let staging = StagingRepo::from_path_for_test(staging_path);
        let runtime = runtime_pointed_at(tmp.path());

        let server = MockServer::start().await;
        let new_app_tree = sample_object_id('e');
        let new_app_tip = sample_object_id('f');

        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ref_response_body("main", &parent)),
            )
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": new_app_tree.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": new_app_tip.as_str(),
                "author": {
                    "name": sample_identity().name(),
                    "email": sample_identity().email(),
                    "date": "2024-01-15T10:30:45Z",
                },
                // The approve path signs, so GitHub's affirmative
                // verification verdict is part of a faithful response —
                // without it `create_commit` refuses the SHA.
                "verification": { "verified": true, "reason": "valid" },
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/refs/heads/main"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ref_response_body("main", &new_app_tip)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let branch = GitBranchName::new("main").unwrap();
        let outcome = prepare_and_commit(
            &staging,
            &runtime,
            &server.uri(),
            &sample_repo().as_repo_ref().clone(),
            &branch,
            &parent,
            &child,
        )
        .await
        .expect("happy-path approve must prepare")
        .expect("happy-path approve must commit");

        assert_eq!(outcome.new_app_tip(), &new_app_tip);
    }

    /// Pre-walk lease miss: the GitHub-side branch tip is not the
    /// `expected_remote_head` the staged push was authorised against.
    /// `execute_fast_forward_plan` reports `ExpectedHeadMoved` and
    /// does not issue any upload or PATCH.
    #[tokio::test]
    async fn run_approve_refuses_when_branch_moved_before_walk() {
        if maybe_git().is_none() {
            eprintln!("skipping: `git` not on PATH");
            return;
        }
        let (tmp, staging_path, parent, child) = build_real_staging_repo();
        let staging = StagingRepo::from_path_for_test(staging_path);
        let runtime = runtime_pointed_at(tmp.path());

        let server = MockServer::start().await;
        let elsewhere = sample_object_id('9');
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ref_response_body("main", &elsewhere)),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let branch = GitBranchName::new("main").unwrap();
        let err = prepare_and_commit(
            &staging,
            &runtime,
            &server.uri(),
            &sample_repo().as_repo_ref().clone(),
            &branch,
            &parent,
            &child,
        )
        .await
        .expect_err("pre-walk lease miss must surface as ExpectedHeadMoved");

        assert!(matches!(
            err,
            RunApproveError::Execute(ExecuteError::ExpectedHeadMoved { .. })
        ));
    }

    /// Noop path: bundle's tip equals the lease anchor, so the
    /// planner returns `AlreadyAtExpected`. The orchestrator must not
    /// hit *any* GitHub endpoint (no lease GET, no upload, no PATCH);
    /// the returned `new_app_tip` is the lease anchor itself.
    #[tokio::test]
    async fn run_approve_returns_noop_without_http_when_bundle_tip_equals_lease() {
        if maybe_git().is_none() {
            eprintln!("skipping: `git` not on PATH");
            return;
        }
        let (tmp, staging_path, _parent, child) = build_real_staging_repo();
        let staging = StagingRepo::from_path_for_test(staging_path);
        let runtime = runtime_pointed_at(tmp.path());

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let branch = GitBranchName::new("main").unwrap();
        let outcome = prepare_and_commit(
            &staging,
            &runtime,
            &server.uri(),
            &sample_repo().as_repo_ref().clone(),
            &branch,
            &child,
            &child,
        )
        .await
        .expect("noop approve must prepare")
        .expect("noop approve must commit");

        assert_eq!(outcome.new_app_tip(), &child);
    }

    /// `PATCH /git/refs/heads/<branch>` returns non-2xx after a
    /// successful walk. The walker's commits *did* land on GitHub but
    /// the ref was not advanced. The failure must come out of the
    /// *commit* half — `prepare` has to have succeeded, because that is
    /// what tells the broker to record `Uncertain` before the PATCH and
    /// `PostPatchFailure` after it.
    #[tokio::test]
    async fn run_approve_surfaces_update_ref_failure_after_walk() {
        if maybe_git().is_none() {
            eprintln!("skipping: `git` not on PATH");
            return;
        }
        let (tmp, staging_path, parent, child) = build_real_staging_repo();
        let staging = StagingRepo::from_path_for_test(staging_path);
        let runtime = runtime_pointed_at(tmp.path());

        let server = MockServer::start().await;
        let new_app_tree = sample_object_id('e');
        let new_app_tip = sample_object_id('f');
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ref_response_body("main", &parent)),
            )
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": new_app_tree.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": new_app_tip.as_str(),
                "verification": { "verified": true, "reason": "valid" },
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/refs/heads/main"))
            .respond_with(
                ResponseTemplate::new(422).set_body_string(
                    r#"{"message":"not a fast forward","documentation_url":"..."}"#,
                ),
            )
            .expect(1)
            .mount(&server)
            .await;

        let branch = GitBranchName::new("main").unwrap();
        let err = prepare_and_commit(
            &staging,
            &runtime,
            &server.uri(),
            &sample_repo().as_repo_ref().clone(),
            &branch,
            &parent,
            &child,
        )
        .await
        .expect("the walk and both lease checks succeed: this failure is the PATCH's")
        .expect_err("update_ref failure must surface");

        let UpdateRefError(GitDataError::ApiError { status, .. }) = err else {
            panic!("expected an update_ref API error, got: {err:?}");
        };
        assert_eq!(status.as_u16(), 422);
    }

    /// The load-bearing property of the split: `prepare_approve` must
    /// carry the pipeline all the way to the PATCH's doorstep — both
    /// lease checks and every object upload — *without* issuing the
    /// PATCH. That is what lets the broker leave the attempt row in the
    /// auto-recoverable `Started` state across the whole expensive,
    /// network-bound part of an approve, and only enter the
    /// manually-reconciled `Uncertain` state for the one round-trip
    /// that can actually move the branch.
    ///
    /// `expect(0)` on the PATCH mock is the assertion; dropping the
    /// `PreparedApprove` un-committed must leave GitHub's branch where
    /// it was.
    #[tokio::test]
    async fn prepare_approve_uploads_every_object_but_never_patches() {
        if maybe_git().is_none() {
            eprintln!("skipping: `git` not on PATH");
            return;
        }
        let (tmp, staging_path, parent, child) = build_real_staging_repo();
        let staging = StagingRepo::from_path_for_test(staging_path);
        let runtime = runtime_pointed_at(tmp.path());

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ref_response_body("main", &parent)),
            )
            // Both lease checks — the pre-walk one and the post-walk
            // recheck — belong to the prepare half.
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": sample_object_id('e').as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": sample_object_id('f').as_str(),
                // The approve path signs, so GitHub's affirmative
                // verification verdict is part of a faithful response —
                // without it `create_commit` refuses the SHA.
                "verification": { "verified": true, "reason": "valid" },
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let prepared = prepare_approve_with_staging_repo(
            &staging,
            &runtime,
            &server.uri(),
            &sample_token(),
            &sample_repo().as_repo_ref().clone(),
            &GitBranchName::new("main").unwrap(),
            &parent,
            &child,
            &sample_signing_key(),
            &[],
            ApproveAttemptId::new(),
        )
        .await
        .expect("prepare must run the walk to completion");

        drop(prepared);
        // `MockServer`'s `expect` bounds are verified on drop; make the
        // failure legible if the PATCH did fire.
        server.verify().await;
    }

    /// The witness is per-attempt: committing a prepared approve under
    /// some *other* attempt's `Uncertain` row would publish to GitHub
    /// with the wrong row holding the "a PATCH may exist" record — the
    /// exact confusion the witness exists to prevent. Fail loudly.
    #[tokio::test]
    #[should_panic(expected = "PATCH authorised by the wrong attempt")]
    async fn commit_under_another_attempts_witness_panics() {
        if maybe_git().is_none() {
            // `should_panic` cannot be skipped conditionally, so panic
            // with the expected message to keep a git-less box green.
            panic!("PATCH authorised by the wrong attempt (skipped: `git` not on PATH)");
        }
        let (tmp, staging_path, parent, child) = build_real_staging_repo();
        let staging = StagingRepo::from_path_for_test(staging_path);
        let runtime = runtime_pointed_at(tmp.path());

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ref_response_body("main", &parent)),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": sample_object_id('e').as_str(),
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": sample_object_id('f').as_str(),
                // The approve path signs, so GitHub's affirmative
                // verification verdict is part of a faithful response —
                // without it `create_commit` refuses the SHA.
                "verification": { "verified": true, "reason": "valid" },
            })))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let prepared = prepare_approve_with_staging_repo(
            &staging,
            &runtime,
            &server.uri(),
            &sample_token(),
            &sample_repo().as_repo_ref().clone(),
            &GitBranchName::new("main").unwrap(),
            &parent,
            &child,
            &sample_signing_key(),
            &[],
            ApproveAttemptId::new(),
        )
        .await
        .expect("prepare must succeed");

        let someone_elses = UncertainAttempt::for_test(ApproveAttemptId::new());
        let _ = prepared.commit(&someone_elses).await;
    }

    // ---------- prepare-side real-git regression tests ----------

    /// Regression test for the `git bundle unbundle --quiet` mistake:
    /// drive `build_unbundle_invocation` through `clean_git::run_clean_git`
    /// against a real bundle and a real bare staging repo, and verify
    /// the bundle's commit lands as an object in the staging repo. The
    /// pure invocation-shape test only pins argv; this one would have
    /// caught the bad flag because real git rejects `--quiet` for
    /// `bundle unbundle` with usage status.
    #[tokio::test]
    async fn unbundle_invocation_runs_against_real_git() {
        let Some(git) = maybe_git() else {
            eprintln!("skipping: `git` not on PATH");
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        let staging = tmp.path().join("staging.git");
        let bundle_path = tmp.path().join("staged.bundle");

        std::fs::create_dir(&work).unwrap();
        run_git(&git, &work, &["init", "--quiet", "--initial-branch=main"]);
        run_git(
            &git,
            &work,
            &["commit", "--allow-empty", "--quiet", "-m", "one"],
        );
        let head = rev_parse(&git, &work, "HEAD");

        run_git(
            &git,
            &work,
            &[
                "bundle",
                "create",
                bundle_path.to_str().unwrap(),
                "refs/heads/main",
            ],
        );
        run_git(
            &git,
            tmp.path(),
            &["init", "--bare", "--quiet", "staging.git"],
        );

        let runtime = runtime_pointed_at(tmp.path());
        let inv = build_unbundle_invocation(&runtime, &staging, &bundle_path);
        clean_git::run_clean_git(&inv, runtime.step_timeout(), None)
            .await
            .expect("`git bundle unbundle` must succeed against a real staging repo");

        // The bundled commit must now be present in the staging repo's
        // object database (no ref is created — that's the planner's
        // job — but `cat-file -e` confirms reachability).
        let exists = Command::new(&git)
            .arg("-C")
            .arg(&staging)
            .args(["cat-file", "-e", head.as_str()])
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("HOME", "/dev/null")
            .status()
            .expect("spawning git cat-file failed");
        assert!(
            exists.success(),
            "bundled commit {head} not present in staging repo after unbundle",
            head = head.as_str(),
        );
    }

    /// Regression test for the annotated-tag bundle-tip bypass:
    /// `cat-file -t` reports the literal object type, so when the
    /// bundle's advertised tip is a tag SHA we must reject it
    /// instead of letting `rev-list` peel it to its target commit.
    /// Stand up a real staging repo containing both a commit and an
    /// annotated tag, pass the tag SHA as `bundle_tip`, and assert
    /// `RunApproveError::BundleTipNotACommit`.
    #[tokio::test]
    async fn run_approve_rejects_non_commit_bundle_tip() {
        let Some(git) = maybe_git() else {
            eprintln!("skipping: `git` not on PATH");
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        let staging_path = tmp.path().join("staging.git");
        std::fs::create_dir(&work).unwrap();
        run_git(&git, &work, &["init", "--quiet", "--initial-branch=main"]);
        run_git(
            &git,
            &work,
            &["commit", "--allow-empty", "--quiet", "-m", "one"],
        );
        let commit = rev_parse(&git, &work, "HEAD");
        run_git(&git, &work, &["tag", "-a", "v1", "-m", "tagmsg"]);
        // `git rev-parse v1` returns the tag-object SHA (not the
        // commit it points at), which is exactly what a hostile VM
        // would stage if it tried to launder a tag through approve.
        let tag_sha = rev_parse(&git, &work, "v1");
        assert_ne!(
            tag_sha, commit,
            "annotated tag must be a distinct object from its target",
        );

        run_git(
            &git,
            tmp.path(),
            &["init", "--bare", "--quiet", "staging.git"],
        );
        // Fetch the tag explicitly so the tag object lands in staging.
        run_git(
            &git,
            &staging_path,
            &[
                "fetch",
                "--no-tags",
                "--quiet",
                &work.display().to_string(),
                "refs/tags/v1:refs/tags/v1",
            ],
        );

        let runtime = runtime_pointed_at(tmp.path());
        let staging = StagingRepo::from_path_for_test(staging_path);
        let server = MockServer::start().await;
        // Reject before any HTTP traffic is issued: no mocks needed,
        // but assert the staging-repo type check fires first.
        let branch = GitBranchName::new("main").unwrap();
        let err = prepare_and_commit(
            &staging,
            &runtime,
            &server.uri(),
            &sample_repo().as_repo_ref().clone(),
            &branch,
            &commit,
            &tag_sha,
        )
        .await
        .expect_err("tag-SHA bundle tip must be rejected before planning");

        assert!(
            matches!(
                err,
                RunApproveError::BundleTipNotACommit { ref sha, ref actual_type }
                    if sha == tag_sha.as_str() && actual_type == "tag"
            ),
            "expected BundleTipNotACommit{{tag}}, got: {err:?}",
        );
    }

    /// `set_private_dir_permissions` is the post-`mkdir` chmod step
    /// that codex round 5 caught us missing. The atomic
    /// `mkdir(path, 0700)` issued by `create_exclusive_private_dir`
    /// is ANDed with the inverse of the process umask, so under a
    /// restrictive umask (e.g. `0o777` — paranoid services, locked
    /// systemd units) the dir lands at `0o000` and `run_prepare_steps`
    /// can't create `staged.bundle` inside it. This unit test runs
    /// the chmod step against a pre-existing 0o000 directory — the
    /// exact post-mkdir state under that umask — and asserts the
    /// helper raises the mode to exact 0o700. It avoids mutating the
    /// process umask itself, which would race with parallel tests in
    /// the same binary that depend on a sane umask for git/init/etc.
    #[cfg(unix)]
    #[tokio::test]
    async fn set_private_dir_permissions_forces_exact_0700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("dir-from-restrictive-umask");
        std::fs::create_dir(&p).unwrap();
        // Simulate the state `mkdir(path, 0700)` would leave under
        // umask 0o777: every permission bit cleared.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        set_private_dir_permissions(&p).await.unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "helper must raise dir to exact 0o700 from 0o000; got 0o{mode:o}",
        );

        // And from a *loose* starting state (the codex round-3
        // scenario), the same helper must *tighten* to 0o700.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        set_private_dir_permissions(&p).await.unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "helper must tighten dir from 0o755 to 0o700; got 0o{mode:o}",
        );
    }

    /// Companion to the dir test: codex round 5 also flagged
    /// `write_private_file`. Under a restrictive umask the through-fd
    /// `write_all` succeeds (the fd was opened with write perms), but
    /// the on-disk mode is `0o000`, so `git bundle unbundle` (which
    /// reopens the file *by path*) gets EACCES. The chmod-back step
    /// must raise the mode to exact 0o600 from whatever the umask
    /// left behind. Tested directly against the post-create chmod
    /// helper for the same anti-flake reason as the dir test.
    #[cfg(unix)]
    #[tokio::test]
    async fn set_private_file_permissions_forces_exact_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("file-from-restrictive-umask");
        std::fs::write(&p, b"bundle-bytes").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        set_private_file_permissions(&p).await.unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "helper must raise file to exact 0o600 from 0o000; got 0o{mode:o}",
        );

        // From a loose starting state, tighten.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        set_private_file_permissions(&p).await.unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "helper must tighten file from 0o644 to 0o600; got 0o{mode:o}",
        );

        // And the post-helper file must be reopenable by path for
        // read. This is the path `git bundle unbundle` takes after
        // `write_private_file` drops its write fd.
        let body = std::fs::read(&p).expect("must be able to reopen file by path");
        assert_eq!(body, b"bundle-bytes");
    }

    /// Regression test that prepare creates the staging dir and the
    /// bundle file with private (0700 / 0600) permissions on Unix.
    /// Other local users must not be able to read the staged bundle
    /// or the loose objects in the bare repo.
    #[cfg(unix)]
    #[tokio::test]
    async fn prepare_creates_staging_artifacts_with_private_permissions() {
        // We don't need fetch to succeed for this test — just the
        // chmod-after-create path. Run prepare against a nonexistent
        // git binary so init fails *after* the staging dir + bundle
        // file have been created, then inspect their modes on the
        // returned-but-cleaned-up... wait — cleanup removes them.
        // Instead, run prepare just up to the bundle write by
        // exercising the helpers directly. They're the targets of
        // the codex finding so a direct test is the right granularity.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("private-dir");
        create_exclusive_private_dir(&dir).await.unwrap();
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "private staging dir must be 0700, got 0o{dir_mode:o}",
        );

        let file = dir.join("staged.bundle");
        write_private_file(&file, b"bundle-bytes").await.unwrap();
        let file_mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            file_mode, 0o600,
            "private bundle file must be 0600, got 0o{file_mode:o}",
        );
    }

    /// Regression test for the prepare-side cleanup hole: if any of
    /// the git-subprocess steps fail after the staging dir has been
    /// created, `prepare_staging_repo` must remove the staging dir
    /// before returning the error. Trigger by pointing the runtime at
    /// a nonexistent git binary so `git init --bare` fails to spawn.
    #[tokio::test]
    async fn prepare_cleans_staging_dir_when_step_fails() {
        let work_root = tempfile::tempdir().unwrap();
        // Nonexistent git binary forces the init step to fail at spawn.
        let runtime = PromoteRuntimeConfig::new(
            PathBuf::from("/nonexistent/bin/git-does-not-exist"),
            GitCloneBaseUrl::github(),
            GitCredentialBoundary::new(
                PathBuf::from("/usr/local/bin/fake-askpass"),
                GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap(),
            )
            .unwrap(),
            work_root.path().to_path_buf(),
            Duration::from_secs(30),
        )
        .unwrap();
        let request_id = sample_request_id();
        let staging_dir = staging_dir_for(&runtime, request_id);

        let err = prepare_staging_repo(
            &runtime,
            request_id,
            &sample_object_id('a'),
            &sample_repo(),
            &sample_token(),
            b"bundle-bytes-irrelevant",
        )
        .await
        .expect_err("nonexistent git binary must fail prepare");

        assert!(
            matches!(err, PrepareStagingError::GitInit(_)),
            "expected GitInit error, got: {err:?}",
        );
        assert!(
            !tokio::fs::try_exists(&staging_dir).await.unwrap_or(true),
            "staging dir {} must be cleaned up after prepare failure",
            staging_dir.display(),
        );
    }

    /// Regression test for the round-3→round-4 race. Two concurrent
    /// approves for the *same* `request_id` both passed the
    /// (now-removed) `try_exists` check, then both called the
    /// AlreadyExists-tolerant `create_private_dir`, so both could
    /// share the same staging directory; the loser would later
    /// `remove_dir_all` it out from under the winner. The fix is
    /// `create_exclusive_private_dir`: a single atomic
    /// `mkdir(path, 0700)` whose AlreadyExists surfaces as
    /// `StagingDirExists`. This test pounds the helper directly with
    /// many concurrent tasks on the same path and asserts exactly one
    /// wins; everyone else gets AlreadyExists. That is the property
    /// `prepare_staging_repo`'s per-request-dir call site relies on.
    #[tokio::test]
    async fn create_exclusive_private_dir_serialises_concurrent_callers() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("contested");
        let mut handles = Vec::new();
        for _ in 0..16 {
            let p = path.clone();
            handles.push(tokio::spawn(async move {
                create_exclusive_private_dir(&p).await
            }));
        }
        let mut wins = 0usize;
        let mut already_exists = 0usize;
        for h in handles {
            match h.await.unwrap() {
                Ok(()) => wins += 1,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    already_exists += 1;
                }
                Err(err) => panic!("unexpected error: {err:?}"),
            }
        }
        assert_eq!(wins, 1, "exactly one caller must win the mkdir race");
        assert_eq!(
            already_exists, 15,
            "all losers must report AlreadyExists, got {already_exists}",
        );
    }

    /// Companion to the race test: `ensure_private_dir` is the
    /// shared-parent variant that *absorbs* AlreadyExists and just
    /// (re-)tightens the mode. Calling it repeatedly must succeed
    /// every time and must always leave the dir at 0700 even if a
    /// prior caller had left it loose.
    #[cfg(unix)]
    #[tokio::test]
    async fn ensure_private_dir_is_idempotent_and_tightens_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("shared");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        ensure_private_dir(&path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "first ensure must tighten to 0700, got 0o{mode:o}"
        );

        // A second call on a dir already at 0700 must remain a no-op.
        ensure_private_dir(&path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "second ensure must keep 0700, got 0o{mode:o}");
    }
}
