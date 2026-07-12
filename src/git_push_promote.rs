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
//! The [`FastForwardPlan::AlreadyAtExpected`] arm short-circuits both
//! steps: nothing new was pushed, so there is nothing to upload and
//! nothing to re-point.
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
use crate::git_push_replay::TrailerSource;
use crate::git_push_replay_walker::{
    FastForwardPlan, GitObjectSource, ReplayError, replay_commits,
};
use crate::github_git_db::{GitDataClient, GitDataError};
use crate::signing::WritSigningKey;
use crate::vm_git::{GitBranchName, GitObjectId};
use crate::vm_git_bundle::{GitCloneBaseUrl, GitCredentialBoundary};

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
/// the per-step ceiling each `git` invocation runs under.
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
        })
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

    pub fn step_timeout(&self) -> Duration {
        self.step_timeout
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
    /// was uploaded and no ref update was issued because the branch
    /// on GitHub already points at `tip`.
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
    /// The plan was [`FastForwardPlan::AlreadyAtExpected`]: the branch
    /// already points at `tip`. Committing this issues no HTTP at all.
    Noop { tip: GitObjectId },
    /// Objects are uploaded and the lease was still intact as of the
    /// post-walk recheck. The one remaining step is `PATCH
    /// /git/refs/heads/<branch>` to `new_app_tip`.
    RefUpdate { new_app_tip: GitObjectId },
}

/// The one and only way [`commit_prepared_promotion`] can fail.
///
/// A distinct type rather than an [`ExecuteError`] variant because it
/// carries a *proof obligation*, not just a cause: a value of this type
/// exists only where a `PATCH /git/refs/...` was issued and did not
/// confirm, which means the branch on GitHub may or may not have moved.
/// The caller owes the audit log a "the PATCH may have landed"
/// resolution. Encoding that in the type means the caller cannot get
/// the classification wrong by matching the wrong variant — there is no
/// other variant.
#[derive(Debug, thiserror::Error)]
#[error("ref update against GitHub failed: {0}")]
pub struct UpdateRefError(#[source] pub GitDataError);

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
    /// [`crate::git_push_replay_walker::plan_fast_forward_via_rev_list`]).
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
///   immediately. No HTTP call is issued. The audit record should
///   note the noop and the staged push's resolution.
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
/// The orchestrator therefore checks twice:
///
/// 1. **Pre-walk** — `GET /git/ref/heads/<branch>` before any
///    upload. If the head ≠ `expected_remote_head`, refuse with
///    [`ExecuteError::ExpectedHeadMoved`]. Failing here costs no
///    upload bandwidth.
/// 2. **Post-walk** — a second `GET /git/ref/heads/<branch>`
///    immediately before the `PATCH`. If the head ≠
///    `expected_remote_head` (someone raced us during the upload
///    window), refuse with
///    [`ExecuteError::ExpectedHeadMovedAfterReplay`]. The walker's
///    uploaded objects remain on GitHub unreferenced — they don't
///    publish anything because the ref never moves.
///
/// The residual race window between the second GET and the PATCH
/// itself (i.e. between this function returning and
/// [`commit_prepared_promotion`] being called) is unavoidable without
/// server-side CAS, but is bounded to a single HTTP round-trip plus
/// whatever the caller does in between — which is why the caller is
/// expected to do only one thing there: record its intent to PATCH. A
/// race that lands inside that window surfaces as a 422 from
/// `update_ref` (it would no longer be a fast-forward) or, in the worst
/// case where the branch has rewound to an ancestor of
/// `expected_remote_head`, as a silent stale-baseline publish — the
/// smallest TOCTOU window we can achieve with the GitHub API as given.
///
/// The `AlreadyAtExpected` arm skips both checks because it issues
/// no GitHub-mutating call; the audit record speaks for what the
/// orchestrator did (nothing), which remains correct regardless
/// of how the branch has since moved.
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
            Ok(PreparedPromotion::RefUpdate { new_app_tip })
        }
    }
}

/// The publish half of the pipeline, following
/// [`prepare_fast_forward_plan`]: point the branch at the
/// [`PreparedPromotion`].
///
/// [`PreparedPromotion::Noop`] issues no HTTP — the branch already
/// points at the tip — so it cannot fail. [`PreparedPromotion::RefUpdate`]
/// issues exactly one `PATCH /git/refs/heads/<branch>`, which is the
/// only GitHub call in the whole promote pipeline that can move the
/// branch. Any error it returns is therefore an [`UpdateRefError`]:
/// the PATCH was sent and its result is unknown.
pub async fn commit_prepared_promotion(
    client: &GitDataClient,
    repo: &RepoRef,
    branch: &GitBranchName,
    prepared: PreparedPromotion,
) -> Result<ExecuteOutcome, UpdateRefError> {
    match prepared {
        PreparedPromotion::Noop { tip } => Ok(ExecuteOutcome::Noop { tip }),
        PreparedPromotion::RefUpdate { new_app_tip } => {
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
    use crate::git_push_replay_walker::test_fixture::InMemoryGitObjectSource;
    use crate::git_push_replay_walker::{ShaMap, StagingCommit, StagingTree};
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
        Commit(#[from] UpdateRefError),
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
        assert_eq!(cfg.clone_base_url(), &GitCloneBaseUrl::github());
        let _credential: &GitCredentialBoundary = cfg.credential();
    }

    /// The `AlreadyAtExpected` arm must short-circuit before any
    /// network call: nothing was pushed at staging time (bundle_tip
    /// == expected_remote_head), so the orchestrator has nothing to
    /// upload and no ref to re-point. The lease check is also
    /// skipped — there is no GitHub-mutating action to lease against.
    ///
    /// Asserted by mounting catch-all wiremocks that fail any HTTP
    /// request of each method. If the function attempts any HTTP,
    /// the matching catch-all's `.expect(0)` triggers a test failure.
    #[tokio::test]
    async fn execute_returns_noop_without_http_when_plan_is_already_at_expected() {
        let server = MockServer::start().await;
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
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let branch = GitBranchName::new("main").unwrap();
        let source = InMemoryGitObjectSource::new();
        let tip = sample_object_id('a');
        let expected = sample_object_id('9');

        let outcome = execute_fast_forward_plan(
            &client,
            &sample_repo(),
            &branch,
            &expected,
            &source,
            FastForwardPlan::AlreadyAtExpected { tip: tip.clone() },
            &[],
            None,
        )
        .await
        .expect("noop must succeed");

        assert_eq!(outcome, ExecuteOutcome::Noop { tip });
    }

    /// Replay arm happy path: lease-GET returns expected_remote_head
    /// twice (pre-walk and post-walk), walker uploads the commit
    /// chain, update_ref PATCHes the branch to the final App-side
    /// tip. Asserts the full HTTP shape: both lease GETs, the upload
    /// count (so a regression that drops a commit shows up), and the
    /// PATCH body which is the only signal that distinguishes "branch
    /// updated to the right SHA" from "branch update silently sent
    /// the wrong SHA".
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
            .expect(2)
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
            .expect(2)
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
            PromoteError::Commit(UpdateRefError(GitDataError::ApiError { status, .. })) => {
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
            .expect(2)
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
