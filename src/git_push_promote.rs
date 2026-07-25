//! Compose a planned fast-forward push into the GitHub publish step.
//!
//! Takes the output of the slice-B1b planner ([`FastForwardPlan`]) and
//! runs the two remaining steps of the staged-push pipeline against
//! GitHub — as two functions, not one, split exactly where the
//! consequences change:
//!
//! 1. [`prepare_fast_forward_plan`] walks the plan's topo-sorted
//!    commits through [`replay_commits`], which uploads each commit's
//!    full tree-and-blob closure via the GitHub Git Data REST API and
//!    returns the final App-identity commit SHA. Nothing it does is
//!    observable: uploaded objects sit unreferenced in GitHub's object
//!    database until a ref points at one. Every failure is retryable.
//! 2. [`commit_prepared_promotion`] issues `PATCH
//!    /repos/.../git/refs/heads/<branch>` via
//!    [`GitDataClient::update_ref`] so the branch on GitHub points at
//!    the App-side SHA. This is the publish, and the one call in the
//!    pipeline whose failure leaves the outcome genuinely unknown.
//!
//! Keeping them apart lets the broker record "a PATCH may exist" in its
//! audit log in between — tightly bracketing the one step that can
//! actually move a branch, rather than the whole pipeline. See
//! [`crate::git_push_approve`].
//!
//! The [`FastForwardPlan::AlreadyAtExpected`] arm short-circuits the
//! upload and the re-point: nothing new was pushed, so there is
//! nothing to upload and no ref to move. It does *not* short-circuit
//! the lease check — recording a noop as approved is still a claim
//! that the branch is at the staged tip, so [`commit_prepared_promotion`]
//! confirms that with one `GET` before the caller records it.
//!
//! App-identity commit signing is plumbed straight through to the
//! walker: when `signing_key` is `Some(&key)`, every commit
//! [`replay_commits`] uploads is signed (the `signature` field of
//! GitHub's `create_commit` carries the resulting SSHSIG); when it is
//! `None`, commits go out unsigned. The orchestrator does not look at
//! the key — it only owns the question of whether the post-walk lease
//! still holds.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::core::RepoRef;
use crate::git_push_trailers::TrailerSource;
use crate::git_push_walker::{FastForwardPlan, GitObjectSource, ReplayError, replay_commits};
use crate::github_git_db::{GitDataClient, GitDataError};
use crate::signing::WritSigningKey;
use crate::vm_git::{GitBranchName, GitObjectId};
use crate::vm_git_bundle::{GitCloneBaseUrl, GitCredentialBoundary};

/// Default for [`PromoteRuntimeConfig::cat_file_timeout`].
///
/// Deliberately a constant rather than a deployment knob: it does not
/// bound how much *work* the broker will tolerate, it asserts a
/// property of a healthy machine. Every interaction it covers is a
/// single exchange with an already-running local child over a pipe —
/// hand it a SHA, read the object back; or close stdin and reap. On a
/// working host these are milliseconds, and no legitimate repository
/// makes them slow, because size is bounded separately by
/// `STAGING_REPO_MAX_OBJECT_BYTES`. Thirty seconds is therefore not a
/// budget but a wedge detector, and the same value
/// [`crate::git_push_objects_cat_file`]'s own tests treat as "plenty".
pub const DEFAULT_CAT_FILE_TIMEOUT: Duration = Duration::from_secs(30);

/// Static configuration the broker needs to drive an approved staged
/// push end-to-end: spin up a fresh bare staging repo, fetch the
/// prerequisite commit from origin, ingest the bundle, then plan +
/// walk onto GitHub and update the branch ref.
///
/// The values mirror the subset of
/// [`crate::vm_http::VmHttpGitCloneConfig`] that promote also needs:
/// `git_program` to run `git init --bare`/`git fetch`/`git bundle
/// unbundle`; `clone_base_url` and `credential` to authenticate the
/// prereq fetch against `https://github.com/<owner>/<name>.git`;
/// `work_root` as the parent directory under which each promote
/// allocates a fresh per-request staging repo; and `step_timeout` as
/// the per-step ceiling each *one-shot* `git` invocation runs under.
///
/// `cat_file_timeout` is deliberately *not* `step_timeout`: see its
/// accessor for why one duration cannot serve both roles.
///
/// Carried as `Option<Arc<Self>>` on
/// [`crate::server::BrokerState`]. `None` means writd was booted
/// without VM-HTTP support, so `approve_staged_push` returns a clean
/// configuration error rather than a generic "broker confused"
/// failure — same pattern the `RunAgent` triple already follows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromoteRuntimeConfig {
    git_program: PathBuf,
    clone_base_url: GitCloneBaseUrl,
    credential: GitCredentialBoundary,
    work_root: PathBuf,
    step_timeout: Duration,
    cat_file_timeout: Duration,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum PromoteRuntimeConfigError {
    #[error("git_program path must not be empty")]
    EmptyGitProgram,
    #[error("work_root path must not be empty")]
    EmptyWorkRoot,
    #[error("work_root must be absolute: {0}")]
    RelativeWorkRoot(PathBuf),
    #[error("step_timeout must be nonzero")]
    ZeroStepTimeout,
    #[error("cat_file_timeout must be nonzero")]
    ZeroCatFileTimeout,
}

impl PromoteRuntimeConfig {
    pub fn new(
        git_program: impl Into<PathBuf>,
        clone_base_url: GitCloneBaseUrl,
        credential: GitCredentialBoundary,
        work_root: impl Into<PathBuf>,
        step_timeout: Duration,
    ) -> Result<Self, PromoteRuntimeConfigError> {
        let git_program = git_program.into();
        let work_root = work_root.into();
        if git_program.as_os_str().is_empty() {
            return Err(PromoteRuntimeConfigError::EmptyGitProgram);
        }
        if work_root.as_os_str().is_empty() {
            return Err(PromoteRuntimeConfigError::EmptyWorkRoot);
        }
        if !work_root.is_absolute() {
            return Err(PromoteRuntimeConfigError::RelativeWorkRoot(work_root));
        }
        if step_timeout.is_zero() {
            return Err(PromoteRuntimeConfigError::ZeroStepTimeout);
        }
        Ok(Self {
            git_program,
            clone_base_url,
            credential,
            work_root,
            step_timeout,
            cat_file_timeout: DEFAULT_CAT_FILE_TIMEOUT,
        })
    }

    /// Override [`Self::cat_file_timeout`], which otherwise defaults to
    /// [`DEFAULT_CAT_FILE_TIMEOUT`].
    ///
    /// Exists so a test can shrink the wedge detector to milliseconds
    /// without also shrinking `step_timeout` — which would put the
    /// deadline under test in a race with the real `git` subprocesses
    /// the same pipeline runs. Production does not call it: the default
    /// is the intended value, and there is nothing an operator could
    /// usefully tune (see the constant's doc).
    pub fn with_cat_file_timeout(
        mut self,
        cat_file_timeout: Duration,
    ) -> Result<Self, PromoteRuntimeConfigError> {
        if cat_file_timeout.is_zero() {
            return Err(PromoteRuntimeConfigError::ZeroCatFileTimeout);
        }
        self.cat_file_timeout = cat_file_timeout;
        Ok(self)
    }

    pub fn git_program(&self) -> &Path {
        &self.git_program
    }

    pub fn clone_base_url(&self) -> &GitCloneBaseUrl {
        &self.clone_base_url
    }

    pub fn credential(&self) -> &GitCredentialBoundary {
        &self.credential
    }

    pub fn work_root(&self) -> &Path {
        &self.work_root
    }

    /// Ceiling on one *one-shot* `git` subprocess: `init --bare`,
    /// `fetch`, `bundle unbundle`, `cat-file -t`, `rev-list`. Each
    /// spawns a process that does real work — a `fetch` pulls the
    /// prerequisite commit over the network — so this is sized for the
    /// slowest legitimate one, and in production comes from
    /// `clone_timeout_secs` (default 300 s).
    pub fn step_timeout(&self) -> Duration {
        self.step_timeout
    }

    /// Ceiling on one exchange with the long-lived `git cat-file
    /// --batch` child: a single object read, and the final reap in
    /// `close()`.
    ///
    /// Separate from [`Self::step_timeout`] because the two bound
    /// different things and want opposite sizes. A step timeout covers
    /// a whole subprocess including a network fetch, so it must be
    /// generous; these are pipe round-trips to a child that is already
    /// running against a *local* object DB, so a generous value is not
    /// caution but a hole — under `step_timeout`'s production default a
    /// wedged read would park an approve, holding the attempt row and
    /// the operator's live approval, for five minutes per object.
    ///
    /// Reusing one duration also made the wedged-traversal test
    /// unreliable: it had to set the shared value low enough to finish
    /// quickly, which put the real `cat-file -t` subprocess in a race
    /// with the deadline under test, and under parallel-test load the
    /// subprocess sometimes lost.
    pub fn cat_file_timeout(&self) -> Duration {
        self.cat_file_timeout
    }
}

/// Outcome of running [`commit_prepared_promotion`].
///
/// Mirrors the two arms of [`FastForwardPlan`], reporting which path
/// was taken so the caller can audit the promotion without re-parsing
/// the plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecuteOutcome {
    /// The plan was [`FastForwardPlan::AlreadyAtExpected`]: nothing
    /// was uploaded and no ref update was issued. The branch on GitHub
    /// was confirmed (by [`commit_prepared_promotion`]'s lease `GET`)
    /// to still point at `tip`, so recording this outcome as approved
    /// is a claim the broker verified rather than assumed.
    Noop { tip: GitObjectId },
    /// The plan was [`FastForwardPlan::Replay`]: the walker uploaded
    /// every commit in the plan (plus its tree and blob closure) and
    /// the branch was updated to point at `new_app_tip` — the
    /// App-identity SHA GitHub returned for the *last* commit in the
    /// topo-sorted walk.
    Advanced { new_app_tip: GitObjectId },
}

/// A promotion that has run every step that provably *cannot* have
/// moved the branch on GitHub, and is now one `PATCH` away from
/// publishing.
///
/// This is the seam the audit layer needs. Everything upstream of a
/// `PreparedPromotion` — the lease checks and the walker's blob / tree
/// / commit uploads — leaves the branch ref untouched: the uploads
/// land in GitHub's object database as unreferenced objects that GC
/// eventually reclaims, and nothing observes them until a ref points
/// at one. So a broker that dies anywhere before this value exists
/// dies in a state that is provably retryable, and the attempt row can
/// stay in a cheaply-recoverable state until here.
///
/// Committing one (see [`commit_prepared_promotion`]) is the step past
/// which the broker can no longer prove whether GitHub moved the
/// branch, so the caller must record its intent to PATCH *before*
/// calling it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedPromotion {
    /// The plan was [`FastForwardPlan::AlreadyAtExpected`]: the staged
    /// tip equals the lease anchor, so no objects were uploaded and no
    /// ref update is owed. Committing this issues a single
    /// lease-verifying `GET` — and no mutation — because recording the
    /// noop as approved asserts the branch is at `tip`, an assertion
    /// that must be checked, not assumed. See [`commit_prepared_promotion`].
    Noop { tip: GitObjectId },
    /// Objects are uploaded and the lease was still intact as of the
    /// post-walk recheck. The remaining steps are a final lease
    /// re-verification against `expected_remote_head` and then `PATCH
    /// /git/refs/heads/<branch>` to `new_app_tip` — both performed by
    /// [`commit_prepared_promotion`], back to back, so the caller can
    /// take as long as it needs between prepare and commit without
    /// widening the publish race window.
    RefUpdate {
        new_app_tip: GitObjectId,
        expected_remote_head: GitObjectId,
    },
}

/// The PATCH was issued and did not confirm.
///
/// A distinct type rather than an [`ExecuteError`] variant because it
/// carries a *proof obligation*, not just a cause: a value of this type
/// exists only where a `PATCH /git/refs/...` was issued and did not
/// confirm, which means the branch on GitHub may or may not have moved.
/// The caller owes the audit log a "the PATCH may have landed"
/// resolution. Encoding that in its own type means the caller cannot
/// get the classification wrong: [`CommitError`]'s other variants are
/// all provably pre-PATCH, and only this one wraps a sent PATCH.
#[derive(Debug, thiserror::Error)]
#[error("ref update against GitHub failed: {0}")]
pub struct UpdateRefError(#[source] pub GitDataError);

/// How [`commit_prepared_promotion`] can fail.
///
/// The two `FinalLease*` variants fire *before* any ref-moving call —
/// GitHub's branch is provably untouched by this attempt, so the
/// caller resolves them exactly like a prepare-phase failure
/// (retryable, no quarantine). They arise on both committed shapes:
/// the RefUpdate arm checks the lease before its PATCH, and the Noop
/// arm checks it before returning success (a noop records no mutation
/// but still asserts the branch is at the staged tip). Only
/// [`CommitError::UpdateRef`] wraps a sent PATCH; it is the sole
/// variant that owes the audit log a "the PATCH may have landed"
/// resolution, and it can only come from the RefUpdate arm.
#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    /// The last-second `GET /git/ref/heads/<branch>` failed. No ref
    /// update was issued.
    #[error("final branch head lookup before publish failed: {0}")]
    FinalLeaseLookup(GitDataError),
    /// The last-second lease check found the branch no longer at the
    /// anchor the receipt was authorised against — another actor moved
    /// (or rewound) it since. No ref update was issued. For the
    /// RefUpdate arm, publishing would have been a `force=false`
    /// fast-forward onto a baseline the approval never covered; for the
    /// Noop arm, recording the push as approved would have asserted a
    /// branch state (`expected`) that no longer holds.
    #[error(
        "branch head on GitHub is {actual}, but the staged push was authorised against \
         expected_remote_head {expected} — branch moved after prepare; publish refused"
    )]
    FinalLeaseMoved {
        expected: GitObjectId,
        actual: GitObjectId,
    },
    /// The PATCH was issued and did not confirm. See [`UpdateRefError`].
    #[error(transparent)]
    UpdateRef(#[from] UpdateRefError),
}

#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    /// `GET /git/ref/heads/<branch>` (the pre-walk lease check)
    /// returned non-2xx. No upload was attempted, no ref was
    /// updated — the staged push remains in place and can be
    /// retried once the GitHub-side cause is resolved.
    #[error("branch head lookup against GitHub failed: {0}")]
    LeaseLookup(GitDataError),
    /// The branch's current tip on GitHub does not equal the
    /// `expected_remote_head` the staged receipt was authorised
    /// against. Another actor rewound or otherwise moved the branch
    /// between when the planner read it and when promotion ran.
    /// Refused without uploading anything: re-planning is required
    /// because the bundle's history is no longer guaranteed to
    /// fast-forward whatever the branch now points at.
    #[error(
        "branch head on GitHub is {actual}, but the staged push was authorised against \
         expected_remote_head {expected} — branch moved between staging and promotion"
    )]
    ExpectedHeadMoved {
        expected: GitObjectId,
        actual: GitObjectId,
    },
    /// One of the per-commit walker steps failed (object source
    /// missing the requested SHA, GitHub Git Data create-blob/tree/
    /// commit returned non-2xx, or the walker found an unmapped
    /// parent — a structural bug in the planner output, never
    /// expected with a plan produced by
    /// [`crate::git_push_walker::plan_fast_forward_via_rev_list`]).
    #[error("replay walk failed: {0}")]
    Replay(#[from] ReplayError),
    /// The post-replay `GET /git/ref/heads/<branch>` (the second lease
    /// check, immediately before the PATCH) failed. The walker did
    /// upload commits — `uploaded_tip` is the App-identity SHA the
    /// walker produced — but the ref was *not* updated, because we
    /// could not re-verify that the branch still points at
    /// `expected_remote_head`. The uploaded objects are unreferenced
    /// on GitHub until either GC reclaims them or a retry re-points
    /// the branch at them.
    #[error("post-replay branch head lookup against GitHub failed: {source}")]
    LeaseRecheckFailed {
        uploaded_tip: GitObjectId,
        #[source]
        source: GitDataError,
    },
    /// The post-replay lease check succeeded but the branch on GitHub
    /// has moved away from `expected_remote_head` *during* the walker
    /// upload window. The walker uploaded `uploaded_tip` (it is
    /// present on GitHub as an unreferenced object) but the ref was
    /// not updated, because publishing `uploaded_tip` would now be
    /// a fast-forward from a tip the bailiff never approved. The
    /// staged push must be re-planned against the new branch tip.
    #[error(
        "branch head on GitHub moved during replay: now {actual}, expected {expected} — \
         walker uploaded {uploaded_tip} but the ref was not advanced"
    )]
    ExpectedHeadMovedAfterReplay {
        expected: GitObjectId,
        actual: GitObjectId,
        uploaded_tip: GitObjectId,
    },
}

/// Walk the planner's commits onto GitHub, stopping one step short of
/// re-pointing the branch.
///
/// Every failure this can return is provably pre-PATCH: the branch ref
/// on GitHub is untouched, whatever went wrong. That is what the type
/// asserts — there is no PATCH-failure variant, because the PATCH is
/// [`commit_prepared_promotion`]'s job and [`UpdateRefError`]'s to
/// report. A caller can therefore run this whole phase *before*
/// durably committing to "a PATCH may exist on GitHub".
///
/// Two return shapes, parallel to the two arms of [`FastForwardPlan`]:
///
/// * `AlreadyAtExpected { tip }` → returns [`PreparedPromotion::Noop`]
///   immediately. No HTTP call is issued *here* — but the lease is
///   still enforced later, by [`commit_prepared_promotion`], before
///   the noop is recorded as approved (see below). The audit record
///   should note the noop and the staged push's resolution.
/// * `Replay { commits, seed }` → drives [`replay_commits`] with
///   `commits`, `seed`, and `trailers`, and returns
///   [`PreparedPromotion::RefUpdate`] carrying the final App-side SHA
///   for [`commit_prepared_promotion`] to publish.
///
/// ## Lease enforcement
///
/// `expected_remote_head` is the App-side branch tip the staged
/// receipt was authorised against — the planner's baseline. GitHub
/// has no native compare-and-swap on refs: `update_ref(force=false)`
/// only checks that the new tip is a fast-forward of the *current*
/// branch tip, not that the current tip equals an expected previous
/// tip. Without an explicit lease check, an actor that rewinds the
/// branch (to *any* commit `expected_remote_head` is descended from,
/// including ancestors of expected_remote_head itself) could
/// silently turn an approved fast-forward into a publish onto a
/// baseline the bailiff never saw.
///
/// The orchestrator therefore checks twice, and
/// [`commit_prepared_promotion`] a third time:
///
/// 1. **Pre-walk** — `GET /git/ref/heads/<branch>` before any
///    upload. If the head ≠ `expected_remote_head`, refuse with
///    [`ExecuteError::ExpectedHeadMoved`]. Failing here costs no
///    upload bandwidth.
/// 2. **Post-walk** — a second `GET /git/ref/heads/<branch>` after
///    the uploads. If the head ≠ `expected_remote_head` (someone
///    raced us during the upload window), refuse with
///    [`ExecuteError::ExpectedHeadMovedAfterReplay`]. The walker's
///    uploaded objects remain on GitHub unreferenced — they don't
///    publish anything because the ref never moves.
/// 3. **Pre-PATCH** — [`commit_prepared_promotion`] re-verifies the
///    lease immediately before the `PATCH`, refusing with
///    [`CommitError::FinalLeaseMoved`] without sending it. The caller
///    may take arbitrarily long between prepare and commit (reaping
///    subprocesses, writing the `Uncertain` audit row); this check is
///    what keeps that interval out of the publish race.
///
/// The residual race window is therefore a single GET→PATCH
/// round-trip inside `commit_prepared_promotion`, regardless of caller
/// behaviour. Closing even that requires server-side CAS, which the
/// REST refs API does not offer; a race landing inside it surfaces as
/// a 422 from `update_ref` (no longer a fast-forward) or, in the worst
/// case where the branch has rewound to an ancestor of
/// `expected_remote_head`, as a silent stale-baseline publish — the
/// smallest TOCTOU window the GitHub REST API admits.
///
/// The `AlreadyAtExpected` arm skips the pre-walk and post-walk checks
/// because it uploads nothing — there is no bandwidth to save and no
/// upload window to bracket. It does **not** skip the third check:
/// [`commit_prepared_promotion`]'s `Noop` arm still issues the
/// lease-verifying `GET` before the caller records the resolution.
/// The noop makes no *mutating* call, but recording it as approved
/// asserts `new_app_tip = tip` is the branch's state — an assertion
/// that is false if a rival moved the branch away from `tip` after the
/// receipt was staged, so it must be verified against GitHub, not
/// assumed from the plan. Skipping it would let a noop record a branch
/// state that never held.
///
/// `trailers` is forwarded to the walker untouched.
///
/// `signing_key` is also forwarded to the walker untouched. When
/// `Some(&key)`, every commit the walker creates is published with
/// an App-identity SSHSIG signature; when `None`, commits go out
/// unsigned. The orchestrator does not inspect the key — it is the
/// walker that builds the canonical bytes and signs them. The
/// AlreadyAtExpected arm uploads no commits, so the key is unused
/// in that path.
///
/// ## Failure modes
///
/// * [`ExecuteError::LeaseLookup`] — the pre-walk `GET` failed. No
///   upload attempted, no ref update issued.
/// * [`ExecuteError::ExpectedHeadMoved`] — branch on GitHub no
///   longer matches `expected_remote_head` at pre-walk check.
///   No upload attempted.
/// * [`ExecuteError::Replay`] — walker failure inside the upload
///   loop. No ref update has been issued so the branch on GitHub
///   is unchanged; the partial upload becomes unreferenced loose
///   objects that GitHub eventually GC's.
/// * [`ExecuteError::LeaseRecheckFailed`] — the post-walk `GET`
///   failed. The walker uploaded `uploaded_tip` but the ref was
///   not advanced because we could not re-verify the lease.
/// * [`ExecuteError::ExpectedHeadMovedAfterReplay`] — the branch
///   moved during the walker upload window. The walker uploaded
///   `uploaded_tip` (now unreferenced on GitHub) but the ref was
///   not advanced.
// One past clippy's argument-count threshold: each arg is a distinct
// concern (transport, repo, branch, lease tip, object source, plan,
// trailers, signing key) and the natural caller has them as separate
// values, so bundling them into a struct adds boilerplate without
// adding meaning. Revisit if a future slice (e.g. B1e wiring this
// into the broker's HTTP handler) ends up packing them in a single
// place anyway.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_fast_forward_plan<S: GitObjectSource>(
    client: &GitDataClient,
    repo: &RepoRef,
    branch: &GitBranchName,
    expected_remote_head: &GitObjectId,
    source: &S,
    plan: FastForwardPlan,
    trailers: &[TrailerSource],
    signing_key: Option<&WritSigningKey>,
) -> Result<PreparedPromotion, ExecuteError> {
    match plan {
        FastForwardPlan::AlreadyAtExpected { tip } => Ok(PreparedPromotion::Noop { tip }),
        FastForwardPlan::Replay { commits, seed } => {
            let actual_head = client
                .get_branch_head(repo, branch)
                .await
                .map_err(ExecuteError::LeaseLookup)?;
            if &actual_head != expected_remote_head {
                return Err(ExecuteError::ExpectedHeadMoved {
                    expected: expected_remote_head.clone(),
                    actual: actual_head,
                });
            }
            let (new_app_tip, _final_map) =
                replay_commits(client, repo, source, &commits, seed, trailers, signing_key).await?;
            let actual_head_after =
                client
                    .get_branch_head(repo, branch)
                    .await
                    .map_err(|source| ExecuteError::LeaseRecheckFailed {
                        uploaded_tip: new_app_tip.clone(),
                        source,
                    })?;
            if &actual_head_after != expected_remote_head {
                return Err(ExecuteError::ExpectedHeadMovedAfterReplay {
                    expected: expected_remote_head.clone(),
                    actual: actual_head_after,
                    uploaded_tip: new_app_tip,
                });
            }
            Ok(PreparedPromotion::RefUpdate {
                new_app_tip,
                expected_remote_head: expected_remote_head.clone(),
            })
        }
    }
}

/// The publish half of the pipeline, following
/// [`prepare_fast_forward_plan`]: point the branch at the
/// [`PreparedPromotion`].
///
/// Both arms re-verify the lease with one last
/// `GET /git/ref/heads/<branch>` before doing anything else.
/// [`PreparedPromotion::RefUpdate`] then issues exactly one
/// `PATCH /git/refs/heads/<branch>`, the only GitHub call in the whole
/// promote pipeline that can move the branch.
/// [`PreparedPromotion::Noop`] issues no mutation — but it is *not*
/// free of the lease check: the branch already "should" point at the
/// staged tip, and recording the noop as approved asserts exactly
/// that, so committing it confirms the branch is still at `tip` and
/// refuses (`FinalLeaseMoved`) if a rival moved it. Both arms can
/// therefore fail with the same `FinalLease*` variants; only the
/// RefUpdate arm can additionally fail past the PATCH.
///
/// The final GET is load-bearing, not paranoia. `update_ref` runs with
/// `force=false`, but GitHub's fast-forward check only demands that the
/// new tip *descend from the current head* — it is not a compare-and-
/// swap against `expected_remote_head`. If another actor rewinds the
/// branch to an ancestor after the post-walk check (the caller may
/// spend arbitrary time between prepare and commit: reaping the object
/// source, writing the `Uncertain` row), the PATCH would still succeed
/// and silently publish against a baseline the approval never covered.
/// (The noop arm has no PATCH, but the symmetric hazard is recording an
/// approval whose asserted branch tip a rival has since replaced.)
/// Rechecking *inside* commit pins the race window to a single
/// GET→PATCH round-trip regardless of what the caller does in between;
/// closing even that residue needs server-side CAS, which the REST API
/// does not offer (GraphQL's `updateRefs` with `expectedHeadOid` is
/// the eventual candidate).
///
/// Failures split by proof: the `FinalLease*` variants of
/// [`CommitError`] fire before any PATCH is sent (branch provably
/// untouched — resolve like a prepare failure), and
/// [`CommitError::UpdateRef`] wraps a sent PATCH whose outcome is
/// unknown.
pub async fn commit_prepared_promotion(
    client: &GitDataClient,
    repo: &RepoRef,
    branch: &GitBranchName,
    prepared: PreparedPromotion,
) -> Result<ExecuteOutcome, CommitError> {
    match prepared {
        PreparedPromotion::Noop { tip } => {
            // A noop issues no ref update, but recording it as approved
            // is still a *claim* that the branch is at `tip` (== the
            // `expected_remote_head` the receipt was staged against —
            // the planner guarantees that equality for the
            // `AlreadyAtExpected` arm). Verify the lease before the
            // caller writes that claim: if a rival moved the branch
            // after staging, refuse rather than record a branch state
            // that never held. Provably no-mutation — the same
            // pre-PATCH refusal shape the RefUpdate arm gives, so the
            // caller resolves it identically (retryable, no quarantine).
            let actual = client
                .get_branch_head(repo, branch)
                .await
                .map_err(CommitError::FinalLeaseLookup)?;
            if actual != tip {
                return Err(CommitError::FinalLeaseMoved {
                    expected: tip,
                    actual,
                });
            }
            Ok(ExecuteOutcome::Noop { tip })
        }
        PreparedPromotion::RefUpdate {
            new_app_tip,
            expected_remote_head,
        } => {
            let actual = client
                .get_branch_head(repo, branch)
                .await
                .map_err(CommitError::FinalLeaseLookup)?;
            if actual != expected_remote_head {
                return Err(CommitError::FinalLeaseMoved {
                    expected: expected_remote_head,
                    actual,
                });
            }
            client
                .update_ref(repo, branch, &new_app_tip)
                .await
                .map_err(UpdateRefError)?;
            Ok(ExecuteOutcome::Advanced { new_app_tip })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde_json::json;
    use time::macros::datetime;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::git_push_walker::test_fixture::InMemoryGitObjectSource;
    use crate::git_push_walker::{ShaMap, StagingCommit, StagingTree};
    use crate::github_git_db::{CommitIdentity, GitDataTimeouts};

    fn sample_repo() -> RepoRef {
        RepoRef::from_str("owner/name").unwrap()
    }

    fn sample_object_id(nibble: char) -> GitObjectId {
        GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
    }

    fn sample_identity(name: &str) -> CommitIdentity {
        CommitIdentity::new(
            name,
            format!("{name}@example.invalid"),
            datetime!(2024-01-15 10:30:45 UTC),
        )
        .expect("sample date formats")
    }

    fn client_against(server: &MockServer, token: &str) -> GitDataClient {
        GitDataClient::new(
            GitDataTimeouts::production(),
            server.uri(),
            token.to_string(),
        )
    }

    /// Either half of the pipeline can fail, and the tests below care
    /// which. Production never needs this union: the broker handles the
    /// two halves at different points in its audit ceremony, so each
    /// call site sees exactly one of these error types.
    #[derive(Debug, thiserror::Error)]
    enum PromoteError {
        #[error(transparent)]
        Prepare(#[from] ExecuteError),
        #[error(transparent)]
        Commit(#[from] CommitError),
    }

    /// Run both halves back to back. Production drives them separately
    /// (recording the attempt `Uncertain` in between); for tests of the
    /// GitHub-facing behaviour the seam is irrelevant, so they exercise
    /// the pipeline end to end through this.
    #[allow(clippy::too_many_arguments)]
    async fn execute_fast_forward_plan<S: GitObjectSource>(
        client: &GitDataClient,
        repo: &RepoRef,
        branch: &GitBranchName,
        expected_remote_head: &GitObjectId,
        source: &S,
        plan: FastForwardPlan,
        trailers: &[TrailerSource],
        signing_key: Option<&WritSigningKey>,
    ) -> Result<ExecuteOutcome, PromoteError> {
        let prepared = prepare_fast_forward_plan(
            client,
            repo,
            branch,
            expected_remote_head,
            source,
            plan,
            trailers,
            signing_key,
        )
        .await?;
        Ok(commit_prepared_promotion(client, repo, branch, prepared).await?)
    }

    fn ref_response_body(sha: &GitObjectId) -> serde_json::Value {
        json!({
            "ref": "refs/heads/main",
            "object": { "sha": sha.as_str(), "type": "commit" },
        })
    }

    fn sample_credential() -> GitCredentialBoundary {
        use crate::vm_git_bundle::GitSecretEnvVar;
        GitCredentialBoundary::new(
            PathBuf::from("/usr/local/bin/fake-askpass"),
            GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn promote_runtime_config_rejects_empty_git_program() {
        let err = PromoteRuntimeConfig::new(
            PathBuf::new(),
            GitCloneBaseUrl::github(),
            sample_credential(),
            PathBuf::from("/tmp/promote"),
            Duration::from_secs(30),
        )
        .expect_err("empty git program must be rejected");
        assert_eq!(err, PromoteRuntimeConfigError::EmptyGitProgram);
    }

    #[test]
    fn promote_runtime_config_rejects_empty_work_root() {
        let err = PromoteRuntimeConfig::new(
            PathBuf::from("/usr/bin/git"),
            GitCloneBaseUrl::github(),
            sample_credential(),
            PathBuf::new(),
            Duration::from_secs(30),
        )
        .expect_err("empty work root must be rejected");
        assert_eq!(err, PromoteRuntimeConfigError::EmptyWorkRoot);
    }

    #[test]
    fn promote_runtime_config_rejects_relative_work_root() {
        let err = PromoteRuntimeConfig::new(
            PathBuf::from("/usr/bin/git"),
            GitCloneBaseUrl::github(),
            sample_credential(),
            PathBuf::from("relative/promote"),
            Duration::from_secs(30),
        )
        .expect_err("relative work root must be rejected");
        assert_eq!(
            err,
            PromoteRuntimeConfigError::RelativeWorkRoot(PathBuf::from("relative/promote")),
        );
    }

    #[test]
    fn promote_runtime_config_rejects_zero_step_timeout() {
        let err = PromoteRuntimeConfig::new(
            PathBuf::from("/usr/bin/git"),
            GitCloneBaseUrl::github(),
            sample_credential(),
            PathBuf::from("/tmp/promote"),
            Duration::ZERO,
        )
        .expect_err("zero timeout must be rejected");
        assert_eq!(err, PromoteRuntimeConfigError::ZeroStepTimeout);
    }

    #[test]
    fn promote_runtime_config_rejects_zero_cat_file_timeout() {
        let err = PromoteRuntimeConfig::new(
            PathBuf::from("/usr/bin/git"),
            GitCloneBaseUrl::github(),
            sample_credential(),
            PathBuf::from("/tmp/promote"),
            Duration::from_secs(30),
        )
        .expect("valid promote runtime config")
        .with_cat_file_timeout(Duration::ZERO)
        .expect_err("zero cat-file timeout must be rejected");
        assert_eq!(err, PromoteRuntimeConfigError::ZeroCatFileTimeout);
    }

    /// The two durations are independent by construction: overriding one
    /// must not disturb the other, in either direction. This is the
    /// property the wedged-traversal test relies on to set a tight read
    /// deadline without putting the real `git` subprocesses it also runs
    /// into a race.
    #[test]
    fn the_cat_file_timeout_defaults_and_overrides_independently_of_the_step_timeout() {
        let base = PromoteRuntimeConfig::new(
            PathBuf::from("/usr/bin/git"),
            GitCloneBaseUrl::github(),
            sample_credential(),
            PathBuf::from("/tmp/promote"),
            Duration::from_secs(300),
        )
        .expect("valid promote runtime config");
        assert_eq!(base.step_timeout(), Duration::from_secs(300));
        assert_eq!(base.cat_file_timeout(), DEFAULT_CAT_FILE_TIMEOUT);

        let tightened = base
            .clone()
            .with_cat_file_timeout(Duration::from_millis(500))
            .expect("nonzero cat-file timeout");
        assert_eq!(tightened.cat_file_timeout(), Duration::from_millis(500));
        assert_eq!(
            tightened.step_timeout(),
            base.step_timeout(),
            "shrinking the cat-file deadline must not shrink the step ceiling",
        );
    }

    #[test]
    fn promote_runtime_config_round_trips_valid_inputs() {
        let cfg = PromoteRuntimeConfig::new(
            PathBuf::from("/usr/bin/git"),
            GitCloneBaseUrl::github(),
            sample_credential(),
            PathBuf::from("/tmp/promote"),
            Duration::from_secs(60),
        )
        .expect("valid promote runtime config");
        assert_eq!(cfg.git_program(), Path::new("/usr/bin/git"));
        assert_eq!(cfg.work_root(), Path::new("/tmp/promote"));
        assert_eq!(cfg.step_timeout(), Duration::from_secs(60));
        assert_eq!(cfg.cat_file_timeout(), DEFAULT_CAT_FILE_TIMEOUT);
        assert_eq!(cfg.clone_base_url(), &GitCloneBaseUrl::github());
        let _credential: &GitCredentialBoundary = cfg.credential();
    }

    /// The `AlreadyAtExpected` arm uploads nothing and re-points
    /// nothing — but it is *not* HTTP-free: committing a noop records
    /// `new_app_tip = tip` as the branch's state, so it must confirm
    /// the branch is still at `tip` (the planner guarantees `tip ==
    /// expected_remote_head` here) before that record lands. The one
    /// lease-check `GET` returns `tip`, so the noop succeeds; the
    /// `expect(0)` on POST/PATCH pins that no upload or ref-update is
    /// issued.
    #[tokio::test]
    async fn execute_noop_verifies_lease_then_returns_noop() {
        let server = MockServer::start().await;
        let tip = sample_object_id('a');
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&tip)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let source = InMemoryGitObjectSource::new();

        let outcome = execute_fast_forward_plan(
            &client,
            &sample_repo(),
            &branch,
            // AlreadyAtExpected implies bundle_tip == expected_remote_head.
            &tip,
            &source,
            FastForwardPlan::AlreadyAtExpected { tip: tip.clone() },
            &[],
            None,
        )
        .await
        .expect("noop must succeed when the branch is still at tip");

        assert_eq!(outcome, ExecuteOutcome::Noop { tip });
    }

    /// The commit half's final lease recheck: the prepare half saw the
    /// expected head, but by the time `commit_prepared_promotion` runs
    /// the branch has moved (rewound). The PATCH must not be sent —
    /// `expect(0)` on the PATCH mock is the assertion — and the error
    /// must be the provably-pre-PATCH `FinalLeaseMoved` variant.
    #[tokio::test]
    async fn commit_refuses_when_branch_moved_between_prepare_and_publish() {
        let server = MockServer::start().await;
        let expected = sample_object_id('a');
        let rewound = sample_object_id('9');
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&rewound)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = commit_prepared_promotion(
            &client,
            &sample_repo(),
            &branch,
            PreparedPromotion::RefUpdate {
                new_app_tip: sample_object_id('e'),
                expected_remote_head: expected.clone(),
            },
        )
        .await
        .expect_err("a moved branch must refuse to publish");

        match err {
            CommitError::FinalLeaseMoved {
                expected: e,
                actual,
            } => {
                assert_eq!(e, expected);
                assert_eq!(actual, rewound);
            }
            other => panic!("expected FinalLeaseMoved, got {other:?}"),
        }
    }

    /// A failing final lease lookup is equally pre-PATCH: no ref
    /// update may be issued when the branch position cannot be
    /// re-verified.
    #[tokio::test]
    async fn commit_refuses_when_final_lease_lookup_fails() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(500).set_body_string("wobble"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = commit_prepared_promotion(
            &client,
            &sample_repo(),
            &branch,
            PreparedPromotion::RefUpdate {
                new_app_tip: sample_object_id('e'),
                expected_remote_head: sample_object_id('a'),
            },
        )
        .await
        .expect_err("an unverifiable branch position must refuse to publish");

        assert!(
            matches!(err, CommitError::FinalLeaseLookup(_)),
            "expected FinalLeaseLookup, got {err:?}",
        );
    }

    /// The noop is still a *claim*: committing it records
    /// `new_app_tip = tip` as the branch's state, so it too must verify
    /// the lease immediately before that record lands. If a rival moved
    /// the branch away from `tip` (== the `expected_remote_head` the
    /// noop was staged against) after the receipt was staged, recording
    /// "approved at `tip`" would be a false branch-state claim. The
    /// `GET` reveals the move and `commit` must refuse with
    /// `FinalLeaseMoved` — the same provably-no-mutation refusal the
    /// RefUpdate arm gives. `expect(0)` on PATCH is decorative here (a
    /// noop never patches); the load-bearing assertion is the refusal.
    #[tokio::test]
    async fn commit_noop_refuses_when_branch_moved_away_from_tip() {
        let server = MockServer::start().await;
        let tip = sample_object_id('a');
        let moved = sample_object_id('9');
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&moved)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = commit_prepared_promotion(
            &client,
            &sample_repo(),
            &branch,
            PreparedPromotion::Noop { tip: tip.clone() },
        )
        .await
        .expect_err("a moved branch must refuse to record the noop as approved");

        match err {
            CommitError::FinalLeaseMoved { expected, actual } => {
                assert_eq!(expected, tip);
                assert_eq!(actual, moved);
            }
            other => panic!("expected FinalLeaseMoved, got {other:?}"),
        }
    }

    /// The noop's lease GET can itself fail; like the RefUpdate arm's
    /// final lookup, an unverifiable branch position must refuse to
    /// record the approval rather than assume the branch is at `tip`.
    #[tokio::test]
    async fn commit_noop_refuses_when_lease_lookup_fails() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(503).set_body_string("wobble"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = commit_prepared_promotion(
            &client,
            &sample_repo(),
            &branch,
            PreparedPromotion::Noop {
                tip: sample_object_id('a'),
            },
        )
        .await
        .expect_err("an unverifiable branch position must refuse the noop resolution");

        assert!(
            matches!(err, CommitError::FinalLeaseLookup(_)),
            "expected FinalLeaseLookup, got {err:?}",
        );
    }

    /// Replay arm happy path: lease-GET returns expected_remote_head
    /// three times (pre-walk, post-walk, and commit's final pre-PATCH
    /// recheck), walker uploads the commit chain, update_ref PATCHes
    /// the branch to the final App-side tip. Asserts the full HTTP
    /// shape: the lease GETs, the upload count (so a regression that
    /// drops a commit shows up), and the PATCH body which is the only
    /// signal that distinguishes "branch updated to the right SHA"
    /// from "branch update silently sent the wrong SHA".
    #[tokio::test]
    async fn execute_walks_replay_plan_then_calls_update_ref() {
        let server = MockServer::start().await;
        let expected = sample_object_id('a');
        let empty_tree_app = sample_object_id('d');
        let c1_app = sample_object_id('e');
        let c2_app = sample_object_id('f');

        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&expected)))
            .expect(3)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .and(body_json(json!({ "tree": [] })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": empty_tree_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": c1_app.as_str(),
            })))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": c2_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/refs/heads/main"))
            .and(body_json(json!({
                "sha": c2_app.as_str(),
                "force": false,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&c2_app)))
            .expect(1)
            .mount(&server)
            .await;

        let c1 = sample_object_id('b');
        let c2 = sample_object_id('c');
        let empty_tree_bundle = sample_object_id('1');
        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(empty_tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            c1.clone(),
            StagingCommit {
                tree: empty_tree_bundle.clone(),
                parents: vec![expected.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "new c1\n".to_string(),
            },
        );
        source.insert_commit(
            c2.clone(),
            StagingCommit {
                tree: empty_tree_bundle,
                parents: vec![c1.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "new c2\n".to_string(),
            },
        );
        let mut seed = ShaMap::new();
        seed.seed_commit_identity(expected.clone());

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let outcome = execute_fast_forward_plan(
            &client,
            &sample_repo(),
            &branch,
            &expected,
            &source,
            FastForwardPlan::Replay {
                commits: vec![c1, c2],
                seed,
            },
            &[],
            None,
        )
        .await
        .expect("replay path ok");

        assert_eq!(
            outcome,
            ExecuteOutcome::Advanced {
                new_app_tip: c2_app
            }
        );
    }

    /// Lease miss: GET returns a SHA other than `expected_remote_head`.
    /// The orchestrator must refuse before uploading anything, because
    /// the branch tip has moved away from the planner's baseline and
    /// the bundle's history is no longer guaranteed to fast-forward
    /// the new tip. Asserted by mounting strict-zero counters on the
    /// upload (POST) and ref-update (PATCH) endpoints.
    #[tokio::test]
    async fn execute_surfaces_lease_mismatch_without_walking_or_calling_update_ref() {
        let server = MockServer::start().await;
        let expected = sample_object_id('a');
        let actual = sample_object_id('2');

        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&actual)))
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

        let c1 = sample_object_id('b');
        let empty_tree_bundle = sample_object_id('1');
        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(empty_tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            c1.clone(),
            StagingCommit {
                tree: empty_tree_bundle,
                parents: vec![expected.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "new c1\n".to_string(),
            },
        );
        let mut seed = ShaMap::new();
        seed.seed_commit_identity(expected.clone());

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = execute_fast_forward_plan(
            &client,
            &sample_repo(),
            &branch,
            &expected,
            &source,
            FastForwardPlan::Replay {
                commits: vec![c1],
                seed,
            },
            &[],
            None,
        )
        .await
        .expect_err("stale lease must be rejected");
        match err {
            PromoteError::Prepare(ExecuteError::ExpectedHeadMoved {
                expected: e,
                actual: a,
            }) => {
                assert_eq!(e, expected);
                assert_eq!(a, actual);
            }
            other => panic!("expected ExpectedHeadMoved, got {other:?}"),
        }
    }

    /// Lease lookup itself fails (GitHub returns 5xx on the GET). No
    /// upload attempted, no ref update issued — the caller can retry
    /// once GitHub recovers. Failure must surface as `LeaseLookup`,
    /// not `Replay`, so retry logic can distinguish "couldn't even
    /// check the lease" from "walker failed mid-stream".
    #[tokio::test]
    async fn execute_surfaces_lease_lookup_failure_without_walking() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(503))
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

        let expected = sample_object_id('a');
        let c1 = sample_object_id('b');
        let empty_tree_bundle = sample_object_id('1');
        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(empty_tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            c1.clone(),
            StagingCommit {
                tree: empty_tree_bundle,
                parents: vec![expected.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "new c1\n".to_string(),
            },
        );
        let mut seed = ShaMap::new();
        seed.seed_commit_identity(expected.clone());

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = execute_fast_forward_plan(
            &client,
            &sample_repo(),
            &branch,
            &expected,
            &source,
            FastForwardPlan::Replay {
                commits: vec![c1],
                seed,
            },
            &[],
            None,
        )
        .await
        .expect_err("lease lookup failure must surface");
        assert!(
            matches!(err, PromoteError::Prepare(ExecuteError::LeaseLookup(_))),
            "expected LeaseLookup, got {err:?}"
        );
    }

    /// Race during the upload window: the pre-walk GET returns
    /// `expected_remote_head`, the walker uploads the commit chain
    /// successfully, but the post-walk GET reveals the branch has
    /// been moved out from under us. The orchestrator must refuse to
    /// `PATCH` — without this second check, `update_ref(force=false)`
    /// would still succeed if the new branch tip is an ancestor of
    /// `expected_remote_head` (because `new_app_tip` would still
    /// fast-forward from it), turning an approved push into a
    /// publish onto a baseline the bailiff never saw.
    ///
    /// Asserted by sequencing two GET responses (first returns
    /// `expected`, second returns a different SHA) and mounting a
    /// strict-zero PATCH counter.
    #[tokio::test]
    async fn execute_rechecks_lease_after_replay_and_refuses_if_branch_moved() {
        let server = MockServer::start().await;
        let expected = sample_object_id('a');
        let moved = sample_object_id('2');
        let empty_tree_app = sample_object_id('d');
        let c1_app = sample_object_id('e');

        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&expected)))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&moved)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": empty_tree_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": c1_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let c1 = sample_object_id('b');
        let empty_tree_bundle = sample_object_id('1');
        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(empty_tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            c1.clone(),
            StagingCommit {
                tree: empty_tree_bundle,
                parents: vec![expected.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "new c1\n".to_string(),
            },
        );
        let mut seed = ShaMap::new();
        seed.seed_commit_identity(expected.clone());

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = execute_fast_forward_plan(
            &client,
            &sample_repo(),
            &branch,
            &expected,
            &source,
            FastForwardPlan::Replay {
                commits: vec![c1],
                seed,
            },
            &[],
            None,
        )
        .await
        .expect_err("post-replay lease miss must be rejected");
        match err {
            PromoteError::Prepare(ExecuteError::ExpectedHeadMovedAfterReplay {
                expected: e,
                actual: a,
                uploaded_tip,
            }) => {
                assert_eq!(e, expected);
                assert_eq!(a, moved);
                assert_eq!(uploaded_tip, c1_app);
            }
            other => panic!("expected ExpectedHeadMovedAfterReplay, got {other:?}"),
        }
    }

    /// Post-replay GET returns 5xx. The walker has already uploaded
    /// the commits — they're on GitHub as unreferenced objects — but
    /// we can't verify the lease, so the PATCH must not fire. Failure
    /// surfaces as `LeaseRecheckFailed` carrying the `uploaded_tip`,
    /// so the caller (or a follow-up retry) knows which commits are
    /// already on GitHub.
    #[tokio::test]
    async fn execute_surfaces_post_replay_lease_failure_without_calling_update_ref() {
        let server = MockServer::start().await;
        let expected = sample_object_id('a');
        let empty_tree_app = sample_object_id('d');
        let c1_app = sample_object_id('e');

        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&expected)))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": empty_tree_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": c1_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let c1 = sample_object_id('b');
        let empty_tree_bundle = sample_object_id('1');
        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(empty_tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            c1.clone(),
            StagingCommit {
                tree: empty_tree_bundle,
                parents: vec![expected.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "new c1\n".to_string(),
            },
        );
        let mut seed = ShaMap::new();
        seed.seed_commit_identity(expected.clone());

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = execute_fast_forward_plan(
            &client,
            &sample_repo(),
            &branch,
            &expected,
            &source,
            FastForwardPlan::Replay {
                commits: vec![c1],
                seed,
            },
            &[],
            None,
        )
        .await
        .expect_err("post-replay lookup failure must surface");
        match err {
            PromoteError::Prepare(ExecuteError::LeaseRecheckFailed {
                uploaded_tip,
                source: _,
            }) => {
                assert_eq!(uploaded_tip, c1_app);
            }
            other => panic!("expected LeaseRecheckFailed, got {other:?}"),
        }
    }

    /// The walker's first GitHub call is a tree create. If it fails,
    /// the replay error must surface and no update_ref must be
    /// attempted: at that point no commits exist on the App side, so
    /// pointing the branch anywhere would either no-op (sha unchanged)
    /// or worse, point at a partial chain. The mock fails the tree
    /// POST and asserts the PATCH never fires. The lease GET succeeds
    /// — the failure is downstream of the lease check.
    #[tokio::test]
    async fn execute_surfaces_replay_failure_without_calling_update_ref() {
        let server = MockServer::start().await;
        let expected = sample_object_id('a');
        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&expected)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let c1 = sample_object_id('b');
        let empty_tree_bundle = sample_object_id('1');
        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(empty_tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            c1.clone(),
            StagingCommit {
                tree: empty_tree_bundle,
                parents: vec![expected.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "new c1\n".to_string(),
            },
        );
        let mut seed = ShaMap::new();
        seed.seed_commit_identity(expected.clone());

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = execute_fast_forward_plan(
            &client,
            &sample_repo(),
            &branch,
            &expected,
            &source,
            FastForwardPlan::Replay {
                commits: vec![c1],
                seed,
            },
            &[],
            None,
        )
        .await
        .expect_err("replay must surface walker error");
        assert!(
            matches!(err, PromoteError::Prepare(ExecuteError::Replay(_))),
            "expected Replay, got {err:?}"
        );
    }

    /// Symmetric failure: the walker succeeds (all uploads return
    /// 201) but the final ref update returns 422. This is GitHub's
    /// documented "not a fast forward" reply — it can happen if the
    /// branch on GitHub raced and advanced underneath us between
    /// when the planner read it and when we patched it. The error
    /// must surface as `UpdateRef`, not `Replay`, so a caller that
    /// wants to retry knows the commits are already on GitHub.
    #[tokio::test]
    async fn execute_surfaces_update_ref_failure_after_successful_replay() {
        let server = MockServer::start().await;
        let expected = sample_object_id('a');
        let empty_tree_app = sample_object_id('d');
        let c1_app = sample_object_id('e');

        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&expected)))
            .expect(3)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": empty_tree_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": c1_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/refs/heads/main"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_json(json!({"message": "Update is not a fast forward"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let c1 = sample_object_id('b');
        let empty_tree_bundle = sample_object_id('1');
        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(empty_tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            c1.clone(),
            StagingCommit {
                tree: empty_tree_bundle,
                parents: vec![expected.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "new c1\n".to_string(),
            },
        );
        let mut seed = ShaMap::new();
        seed.seed_commit_identity(expected.clone());

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = execute_fast_forward_plan(
            &client,
            &sample_repo(),
            &branch,
            &expected,
            &source,
            FastForwardPlan::Replay {
                commits: vec![c1],
                seed,
            },
            &[],
            None,
        )
        .await
        .expect_err("update_ref failure must surface");
        match err {
            PromoteError::Commit(CommitError::UpdateRef(UpdateRefError(
                GitDataError::ApiError { status, .. },
            ))) => {
                assert_eq!(status.as_u16(), 422);
            }
            other => panic!("expected a commit-half UpdateRef ApiError 422, got {other:?}"),
        }
    }

    /// `signing_key: Some(&key)` reaches the walker: the recorded
    /// create_commit body carries an SSHSIG signature that verifies
    /// under the `"git"` namespace against canonical bytes assembled
    /// from the same wire fields. The walker's own tests already
    /// cover the canonical-bytes ↔ signature relationship; this test
    /// pins the *plumbing* — that `execute_fast_forward_plan`
    /// forwards the key through without dropping or substituting it.
    #[tokio::test]
    async fn execute_threads_signing_key_to_walker_and_published_commit_is_signed() {
        use crate::git_commit_sign::{CommitSigningInput, canonical_commit_bytes};
        use crate::signing::{GIT_SSHSIG_NAMESPACE, WritSigningKey};
        use ssh_key::SshSig;

        const PRIVATE_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
        const PUBLIC_OPENSSH: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");

        let server = MockServer::start().await;
        let expected = sample_object_id('a');
        let empty_tree_app = sample_object_id('d');
        let c1_app = sample_object_id('e');

        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&expected)))
            .expect(3)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": empty_tree_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": c1_app.as_str(),
                // This test drives the signing path, so a faithful
                // GitHub response carries the affirmative verification
                // verdict `create_commit` now requires before it will
                // hand the SHA on to publication.
                "verification": { "verified": true, "reason": "valid" },
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/refs/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&c1_app)))
            .expect(1)
            .mount(&server)
            .await;

        let c1 = sample_object_id('b');
        let empty_tree_bundle = sample_object_id('1');
        let author = sample_identity("Alice");
        let committer = sample_identity("Bot");
        let message = "signed commit\n";

        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(empty_tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            c1.clone(),
            StagingCommit {
                tree: empty_tree_bundle,
                parents: vec![expected.clone()],
                author: author.clone(),
                committer: committer.clone(),
                message: message.to_string(),
            },
        );
        let mut seed = ShaMap::new();
        seed.seed_commit_identity(expected.clone());

        let key =
            WritSigningKey::from_openssh_pem(PRIVATE_PEM).expect("fixture private key parses");
        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        execute_fast_forward_plan(
            &client,
            &sample_repo(),
            &branch,
            &expected,
            &source,
            FastForwardPlan::Replay {
                commits: vec![c1.clone()],
                seed,
            },
            &[],
            Some(&key),
        )
        .await
        .expect("replay path ok");

        // Pull the commit POST out of the captured requests and pin
        // the signature.
        let received = server.received_requests().await.expect("recording enabled");
        let commit_post = received
            .iter()
            .find(|r| {
                r.method == reqwest::Method::POST && r.url.path() == "/repos/owner/name/git/commits"
            })
            .expect("create_commit was issued");
        let body: serde_json::Value =
            serde_json::from_slice(&commit_post.body).expect("commit body is JSON");
        let armored = body["signature"]
            .as_str()
            .expect("signing key was threaded so body has a string signature field");
        let parsed: SshSig = armored.parse().expect("SSHSIG armor parses");

        let canonical = canonical_commit_bytes(&CommitSigningInput {
            tree: &empty_tree_app,
            parents: std::slice::from_ref(&expected),
            author: &author,
            committer: &committer,
            message,
        })
        .expect("canonicalise");
        let pubk =
            ssh_key::PublicKey::from_openssh(PUBLIC_OPENSSH).expect("fixture public key parses");
        pubk.verify(GIT_SSHSIG_NAMESPACE, &canonical, &parsed)
            .expect("execute forwarded the signing key — signature verifies");
    }

    /// The end-to-end guarantee: when GitHub declines to verify a
    /// signature we sent, the branch is **not** published. The `.expect(0)`
    /// on the PATCH mock is the load-bearing assertion — before the fix
    /// this path swallowed the verdict, fast-forwarded `refs/heads/main`
    /// onto an unverified commit, and recorded the push as a success.
    #[tokio::test]
    async fn execute_refuses_to_publish_branch_when_github_reports_commit_unverified() {
        use crate::signing::WritSigningKey;

        const PRIVATE_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");

        let server = MockServer::start().await;
        let expected = sample_object_id('a');
        let empty_tree_app = sample_object_id('d');
        let c1_app = sample_object_id('e');

        Mock::given(method("GET"))
            .and(path("/repos/owner/name/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&expected)))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": empty_tree_app.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        // GitHub created the commit — 201 — but refused the signature.
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": c1_app.as_str(),
                "verification": { "verified": false, "reason": "unknown_key" },
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/name/git/refs/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body(&c1_app)))
            .expect(0)
            .mount(&server)
            .await;

        let c1 = sample_object_id('b');
        let empty_tree_bundle = sample_object_id('1');
        let mut source = InMemoryGitObjectSource::new();
        source.insert_tree(empty_tree_bundle.clone(), StagingTree { entries: vec![] });
        source.insert_commit(
            c1.clone(),
            StagingCommit {
                tree: empty_tree_bundle,
                parents: vec![expected.clone()],
                author: sample_identity("Alice"),
                committer: sample_identity("Bot"),
                message: "signed commit\n".to_string(),
            },
        );
        let mut seed = ShaMap::new();
        seed.seed_commit_identity(expected.clone());

        let key =
            WritSigningKey::from_openssh_pem(PRIVATE_PEM).expect("fixture private key parses");
        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let err = execute_fast_forward_plan(
            &client,
            &sample_repo(),
            &branch,
            &expected,
            &source,
            FastForwardPlan::Replay {
                commits: vec![c1.clone()],
                seed,
            },
            &[],
            Some(&key),
        )
        .await
        .expect_err("an unverified commit must abort the promote, not publish");
        assert!(
            format!("{err:?}").contains("UnverifiedSignedCommit"),
            "the failure must name the unverified commit so an operator can act on it: {err:?}",
        );
    }
}
