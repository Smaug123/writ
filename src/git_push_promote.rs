//! Compose a planned fast-forward push into the GitHub publish step.
//!
//! [`execute_fast_forward_plan`] takes the output of the slice-B1b
//! planner ([`FastForwardPlan`]) and runs the two remaining steps of
//! the staged-push pipeline against GitHub:
//!
//! 1. Walk the plan's topo-sorted commits through [`replay_commits`],
//!    which uploads each commit's full tree-and-blob closure via the
//!    GitHub Git Data REST API and returns the final App-identity
//!    commit SHA.
//! 2. Issue `PATCH /repos/.../git/refs/heads/<branch>` via
//!    [`GitDataClient::update_ref`] so the branch on GitHub points at
//!    the App-side SHA.
//!
//! The [`FastForwardPlan::AlreadyAtExpected`] arm short-circuits both
//! steps: nothing new was pushed, so there is nothing to upload and
//! nothing to re-point.
//!
//! This module is the seam slice B1d will use to inject an
//! App-identity commit signature: signing is a property of the
//! per-commit upload step (the GitHub Git Data API accepts a
//! detached PGP/SSH signature in the `signature` field of the
//! `create_commit` request), which the walker already carries via
//! [`TrailerSource`]. B1d will add a signing-trailer variant; this
//! orchestrator forwards `trailers` through unchanged so the
//! wire-up is a single-call-site change once the variant lands.

use crate::core::RepoRef;
use crate::git_push_replay::TrailerSource;
use crate::git_push_replay_walker::{
    FastForwardPlan, GitObjectSource, ReplayError, replay_commits,
};
use crate::github_git_db::{GitDataClient, GitDataError};
use crate::vm_git::{GitBranchName, GitObjectId};

/// Outcome of running [`execute_fast_forward_plan`].
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
    /// `PATCH /git/refs/heads/<branch>` returned non-2xx. The commits
    /// already landed in GitHub's object database (replay completed
    /// before this point), so a retry after fixing the cause is
    /// idempotent — the prior uploads are reused.
    #[error("ref update against GitHub failed: {0}")]
    UpdateRef(GitDataError),
}

/// Walk the planner's commits onto GitHub and re-point the branch.
///
/// Two return shapes, parallel to the two arms of [`FastForwardPlan`]:
///
/// * `AlreadyAtExpected { tip }` → returns [`ExecuteOutcome::Noop`]
///   immediately. No HTTP call is issued. The audit record should
///   note the noop and the staged push's resolution.
/// * `Replay { commits, seed }` → drives [`replay_commits`] with
///   `commits`, `seed`, and `trailers`, then calls
///   [`GitDataClient::update_ref`] on the branch with the final
///   App-side SHA. Returns [`ExecuteOutcome::Advanced`] on success.
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
/// itself is unavoidable without server-side CAS, but is bounded
/// to a single HTTP round-trip. A race that lands inside that
/// window surfaces as a 422 from `update_ref` (it would no longer
/// be a fast-forward) or, in the worst case where the branch has
/// rewound to an ancestor of `expected_remote_head`, as a silent
/// stale-baseline publish — the smallest TOCTOU window we can
/// achieve with the GitHub API as given.
///
/// The `AlreadyAtExpected` arm skips both checks because it issues
/// no GitHub-mutating call; the audit record speaks for what the
/// orchestrator did (nothing), which remains correct regardless
/// of how the branch has since moved.
///
/// `trailers` is forwarded to the walker untouched. Slice B1c uses
/// `&[]` at every call site; slice B1d will introduce a
/// signing-related trailer variant that mints the App-identity
/// signature on every uploaded commit.
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
/// * [`ExecuteError::UpdateRef`] — successful walk and post-walk
///   lease check, but the `PATCH` itself returned non-2xx (e.g.
///   the branch raced in the tiny window between the recheck and
///   the PATCH). The commits *are* on GitHub but no ref points
///   at them yet. Re-running the orchestrator with the same plan
///   is idempotent: the walker short-circuits every already-mapped
///   commit, and `update_ref` retries against the same target.
pub async fn execute_fast_forward_plan<S: GitObjectSource>(
    client: &GitDataClient,
    repo: &RepoRef,
    branch: &GitBranchName,
    expected_remote_head: &GitObjectId,
    source: &S,
    plan: FastForwardPlan,
    trailers: &[TrailerSource],
) -> Result<ExecuteOutcome, ExecuteError> {
    match plan {
        FastForwardPlan::AlreadyAtExpected { tip } => Ok(ExecuteOutcome::Noop { tip }),
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
                replay_commits(client, repo, source, &commits, seed, trailers).await?;
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
            client
                .update_ref(repo, branch, &new_app_tip)
                .await
                .map_err(ExecuteError::UpdateRef)?;
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
    use crate::github_git_db::CommitIdentity;

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
        GitDataClient::new(reqwest::Client::new(), server.uri(), token.to_string())
    }

    fn ref_response_body(sha: &GitObjectId) -> serde_json::Value {
        json!({
            "ref": "refs/heads/main",
            "object": { "sha": sha.as_str(), "type": "commit" },
        })
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
        )
        .await
        .expect_err("stale lease must be rejected");
        match err {
            ExecuteError::ExpectedHeadMoved {
                expected: e,
                actual: a,
            } => {
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
        )
        .await
        .expect_err("lease lookup failure must surface");
        assert!(
            matches!(err, ExecuteError::LeaseLookup(_)),
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
        )
        .await
        .expect_err("post-replay lease miss must be rejected");
        match err {
            ExecuteError::ExpectedHeadMovedAfterReplay {
                expected: e,
                actual: a,
                uploaded_tip,
            } => {
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
        )
        .await
        .expect_err("post-replay lookup failure must surface");
        match err {
            ExecuteError::LeaseRecheckFailed {
                uploaded_tip,
                source: _,
            } => {
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
        )
        .await
        .expect_err("replay must surface walker error");
        assert!(
            matches!(err, ExecuteError::Replay(_)),
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
        )
        .await
        .expect_err("update_ref failure must surface");
        match err {
            ExecuteError::UpdateRef(GitDataError::ApiError { status, .. }) => {
                assert_eq!(status.as_u16(), 422);
            }
            other => panic!("expected UpdateRef ApiError 422, got {other:?}"),
        }
    }
}
