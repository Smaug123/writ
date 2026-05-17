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
/// receipt was authorised against — the planner's baseline. Before
/// uploading anything in the `Replay` arm the orchestrator issues
/// `GET /git/ref/heads/<branch>` and refuses (via
/// [`ExecuteError::ExpectedHeadMoved`]) if the branch on GitHub no
/// longer points at that SHA. GitHub's `update_ref` natively only
/// checks fast-forward against the *current* tip, not against an
/// expected previous tip; without this explicit check, another
/// actor that rewound the branch between staging and promotion
/// could silently turn an approved fast-forward into a publish
/// onto a different baseline.
///
/// The check is TOCTOU-vulnerable — the branch can still race
/// between this `GET` and the eventual `PATCH` — but failing fast
/// before the walk is the best we can do without a GitHub-side
/// CAS, and the residual race window is bounded to the walker
/// runtime. A race that lands inside that window surfaces as a
/// 422 from `update_ref` instead of a stale-baseline publish.
///
/// The `AlreadyAtExpected` arm skips this check because it issues
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
///   longer matches `expected_remote_head`. No upload attempted.
/// * [`ExecuteError::Replay`] — walker failure inside the upload
///   loop. No ref update has been issued so the branch on GitHub
///   is unchanged; the partial upload becomes unreferenced loose
///   objects that GitHub eventually GC's.
/// * [`ExecuteError::UpdateRef`] — successful walk, failed
///   `update_ref`. The commits *are* on GitHub but no ref points
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

    /// Replay arm happy path: lease-GET returns expected_remote_head,
    /// walker uploads the commit chain, update_ref PATCHes the branch
    /// to the final App-side tip. Asserts the full HTTP shape: the
    /// lease GET, the upload count (so a regression that drops a
    /// commit shows up), and the PATCH body which is the only signal
    /// that distinguishes "branch updated to the right SHA" from
    /// "branch update silently sent the wrong SHA".
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
            .expect(1)
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
