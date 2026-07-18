//! Example-based tests for `plan_fast_forward_via_rev_list` and the
//! totality of the branch-creation-to-fast-forward error mapping.

use super::test_fixture::InMemoryGitObjectSource;
use super::test_support::*;
use super::*;
use serde_json::json;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Same `Replay`-extraction helper as `expect_replay`, but for
/// the fast-forward result enum. Keeps the per-test asserts focussed
/// on shape rather than match scaffolding.
fn expect_replay_ff(plan: FastForwardPlan) -> (Vec<GitObjectId>, ShaMap) {
    match plan {
        FastForwardPlan::Replay { commits, seed } => (commits, seed),
        FastForwardPlan::AlreadyAtExpected { tip } => {
            panic!("expected Replay, got AlreadyAtExpected {{ tip: {tip:?} }}")
        }
    }
}

#[tokio::test]
async fn fast_forward_plan_returns_single_commit_when_tip_is_child_of_expected_remote_head() {
    let (_dir, repo, git) = init_test_repo();
    let expected = commit_empty(&git, &repo, "expected remote head");
    let new1 = commit_empty(&git, &repo, "one new commit");

    let plan = plan_fast_forward_via_rev_list(
        &new1,
        &expected,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect("plan ok");
    let (commits, seed) = expect_replay_ff(plan);
    assert_eq!(commits, vec![new1]);
    // The boundary is `expected_remote_head` itself — strictly the
    // parent of the only new commit.
    assert_eq!(seed.commit(&expected), Some(&expected));
    assert_eq!(seed.commit_count(), 1);
}

#[tokio::test]
async fn fast_forward_plan_rejects_when_rev_list_output_exceeds_cap() {
    // A single new commit already makes `rev-list --boundary` emit far more
    // than a handful of bytes (the new commit's id plus the boundary id), so a
    // tiny cap trips the guard. This exercises the real reviewed path: the
    // planner must refuse the walk (killing the git process group) rather than
    // buffer and parse guest-controlled `rev-list` output unbounded.
    let (_dir, repo, git) = init_test_repo();
    let expected = commit_empty(&git, &repo, "expected remote head");
    let new1 = commit_empty(&git, &repo, "one new commit");

    let err = plan_fast_forward_via_rev_list(&new1, &expected, &repo, &git, TEST_GIT_TIMEOUT, 8)
        .await
        .expect_err("over-cap rev-list output must be refused");
    match err {
        FastForwardPlanError::RevListOutputTooLarge { cap } => assert_eq!(cap, 8),
        other => panic!("expected RevListOutputTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn fast_forward_plan_topologically_sorts_linear_chain() {
    let (_dir, repo, git) = init_test_repo();
    let expected = commit_empty(&git, &repo, "expected");
    let c1 = commit_empty(&git, &repo, "c1");
    let c2 = commit_empty(&git, &repo, "c2");
    let c3 = commit_empty(&git, &repo, "c3");

    let plan = plan_fast_forward_via_rev_list(
        &c3,
        &expected,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect("plan ok");
    let (commits, seed) = expect_replay_ff(plan);
    assert_eq!(commits, vec![c1.clone(), c2, c3]);
    // Boundary is `expected` (the parent of the first new commit
    // on the chain); the new chain's own intermediate commits are
    // not boundaries.
    assert_eq!(seed.commit(&expected), Some(&expected));
    assert!(seed.commit(&c1).is_none());
}

#[tokio::test]
async fn fast_forward_plan_handles_merge_with_mixed_age_parents() {
    // Topology:
    //
    //   c0 ─ expected ─────────╮
    //    │                     ├─ merge  (bundle tip)
    //    └─ side1 ──────────── ╯
    //
    // expected_remote_head = expected.  side1 forks at c0 (older
    // than expected). merge's parents are (expected, side1). The
    // walker must emit [side1, merge], with c0 and/or expected as
    // boundaries so the merge's parent slot resolves.
    let (_dir, repo, git) = init_test_repo();
    let c0 = commit_empty(&git, &repo, "c0");
    let expected = commit_empty(&git, &repo, "expected on default");
    run_git(
        &git,
        &repo,
        &["checkout", "--quiet", "-b", "side", c0.as_str()],
    );
    let side1 = commit_empty(&git, &repo, "side1");
    let merge = commit_merge(&git, &repo, "merge", &[&expected, &side1]);

    let plan = plan_fast_forward_via_rev_list(
        &merge,
        &expected,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect("plan ok");
    let (commits, seed) = expect_replay_ff(plan);
    assert_eq!(commits.len(), 2, "got {commits:?}");
    assert!(
        !commits.contains(&c0),
        "c0 must not be uploaded — reachable from expected_remote_head"
    );
    assert!(
        !commits.contains(&expected),
        "expected_remote_head must not appear in the upload set"
    );
    let side1_idx = commits
        .iter()
        .position(|s| s == &side1)
        .expect("side1 emitted");
    let merge_idx = commits
        .iter()
        .position(|s| s == &merge)
        .expect("merge emitted");
    assert!(side1_idx < merge_idx, "side1 must precede merge");
    // At least one of {c0, expected} must seed the walker so the
    // merge's parent slot can be resolved.
    assert!(
        seed.commit(&c0).is_some() || seed.commit(&expected).is_some(),
        "expected some ancestor in the seed map, got {seed:?}",
    );
}

#[tokio::test]
async fn fast_forward_plan_returns_already_at_expected_when_bundle_tip_equals_expected_remote_head()
{
    // Agent pushes an unchanged ref (e.g. `git push origin main`
    // with no local commits ahead). The bundle would be empty;
    // the planner must surface this as AlreadyAtExpected so the
    // orchestrator skips both walker and ref-update.
    let (_dir, repo, git) = init_test_repo();
    let head = commit_empty(&git, &repo, "only commit");
    let plan = plan_fast_forward_via_rev_list(
        &head,
        &head,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect("bundle_tip == expected_remote_head must succeed as AlreadyAtExpected");
    match plan {
        FastForwardPlan::AlreadyAtExpected { tip } => {
            assert_eq!(tip, head);
        }
        other => panic!("expected AlreadyAtExpected, got {other:?}"),
    }
}

#[tokio::test]
async fn fast_forward_plan_rejects_diverged_history() {
    // Build an orphan branch as the bundle tip — its history
    // shares nothing with `expected_remote_head`, so `rev-list`
    // emits all of orphan_tip's ancestry as interesting and no
    // boundary commits. That's the "not a fast forward" shape
    // the broker must refuse to publish.
    let (_dir, repo, git) = init_test_repo();
    let expected = commit_empty(&git, &repo, "expected");
    run_git(&git, &repo, &["checkout", "--quiet", "--orphan", "orphan"]);
    let orphan_tip = commit_empty(&git, &repo, "orphan tip");

    let err = plan_fast_forward_via_rev_list(
        &orphan_tip,
        &expected,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect_err("diverged history must be rejected");
    match err {
        FastForwardPlanError::DivergedHistory {
            expected_remote_head: erh,
            bundle_tip: bt,
        } => {
            assert_eq!(erh, expected.as_str());
            assert_eq!(bt, orphan_tip.as_str());
        }
        other => panic!("expected DivergedHistory, got {other:?}"),
    }
}

#[tokio::test]
async fn fast_forward_plan_rejects_fork_from_older_ancestor() {
    // Topology:
    //
    //   c0 ─ expected         (expected_remote_head)
    //    └─ side_tip          (bundle_tip)
    //
    // bundle_tip and expected_remote_head share an older common
    // ancestor `c0`, but neither is an ancestor of the other —
    // this is *diverged*, not a fast-forward. `git rev-list
    // --boundary ^expected side_tip` emits `side_tip` as
    // interesting and `c0` as the boundary, so the naive
    // "boundaries non-empty → Replay" rule wrongly accepts this.
    // The planner must recognise that `expected_remote_head`
    // itself is not the boundary and reject it.
    let (_dir, repo, git) = init_test_repo();
    let c0 = commit_empty(&git, &repo, "c0 shared ancestor");
    let expected = commit_empty(&git, &repo, "expected on default");
    run_git(
        &git,
        &repo,
        &["checkout", "--quiet", "-b", "side", c0.as_str()],
    );
    let side_tip = commit_empty(&git, &repo, "side tip");

    let err = plan_fast_forward_via_rev_list(
        &side_tip,
        &expected,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect_err("fork from older ancestor must be rejected");
    match err {
        FastForwardPlanError::DivergedHistory {
            expected_remote_head: erh,
            bundle_tip: bt,
        } => {
            assert_eq!(erh, expected.as_str());
            assert_eq!(bt, side_tip.as_str());
        }
        other => panic!("expected DivergedHistory, got {other:?}"),
    }
}

#[tokio::test]
async fn fast_forward_plan_rejects_rewind() {
    // Topology: linear chain c1 ─ c2. Caller asks the planner to
    // treat bundle_tip = c1 against expected_remote_head = c2.
    // That's a rewind: bundle_tip is a strict ancestor of
    // expected_remote_head, not a fast-forward. `git rev-list
    // --boundary ^c2 c1` emits nothing (c1 is reachable from c2),
    // so the naive "empty output → AlreadyAtExpected" rule
    // wrongly accepts it as a noop. The planner must check
    // SHA-equality before declaring noop and reject this as
    // DivergedHistory.
    let (_dir, repo, git) = init_test_repo();
    let c1 = commit_empty(&git, &repo, "c1");
    let c2 = commit_empty(&git, &repo, "c2");

    let err = plan_fast_forward_via_rev_list(
        &c1,
        &c2,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect_err("rewind must be rejected");
    match err {
        FastForwardPlanError::DivergedHistory {
            expected_remote_head: erh,
            bundle_tip: bt,
        } => {
            assert_eq!(erh, c2.as_str());
            assert_eq!(bt, c1.as_str());
        }
        other => panic!("expected DivergedHistory, got {other:?}"),
    }
}

#[tokio::test]
async fn fast_forward_plan_rejects_shallow_staging_repo() {
    let (_dir, repo, git) = init_test_repo();
    let expected = commit_empty(&git, &repo, "expected");
    let c1 = commit_empty(&git, &repo, "new");

    let shallow_marker = repo.join(".git").join("shallow");
    std::fs::write(&shallow_marker, format!("{}\n", expected.as_str())).unwrap();
    assert!(shallow_marker.exists(), "marker write must succeed");

    let err = plan_fast_forward_via_rev_list(
        &c1,
        &expected,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect_err("shallow staging repo must be rejected");
    match err {
        FastForwardPlanError::ShallowStagingRepo { staging_repo } => {
            assert_eq!(staging_repo, repo.display().to_string());
        }
        other => panic!("expected ShallowStagingRepo, got {other:?}"),
    }
}

#[tokio::test]
async fn fast_forward_plan_surfaces_git_error_on_unknown_sha() {
    let (_dir, repo, git) = init_test_repo();
    let head = commit_empty(&git, &repo, "only commit");
    let bogus = GitObjectId::new("0".repeat(40)).unwrap();
    let err = plan_fast_forward_via_rev_list(
        &bogus,
        &head,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect_err("unknown SHA must surface as Git error");
    assert!(
        matches!(err, FastForwardPlanError::Git(_)),
        "expected Git, got {err:?}",
    );
}

/// End-to-end integration: feed a real-git fast-forward plan
/// straight into `replay_commits` against a wiremock-backed
/// GitHub Git Data client. Proves the boundary
/// (= expected_remote_head) lands in the seed map in a shape that
/// satisfies the walker's `UnmappedParent` guard, identical in
/// structure to the branch-creation end-to-end test but with the
/// fast-forward planner.
#[tokio::test]
async fn fast_forward_plan_seeds_replay_commits_end_to_end() {
    let (_dir, repo, git) = init_test_repo();
    let expected = commit_empty(&git, &repo, "expected remote head");
    let c1 = commit_empty(&git, &repo, "new c1");
    let c2 = commit_empty(&git, &repo, "new c2");

    let plan = plan_fast_forward_via_rev_list(
        &c2,
        &expected,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect("plan ok");
    let (plan_commits, plan_seed) = expect_replay_ff(plan);
    assert_eq!(plan_commits, vec![c1.clone(), c2.clone()]);
    assert_eq!(plan_seed.commit(&expected), Some(&expected));

    let server = MockServer::start().await;
    let empty_tree_app = sample_object_id('d');
    let c1_app = sample_object_id('e');
    let c2_app = sample_object_id('f');
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

    let mut source = InMemoryGitObjectSource::new();
    let empty_tree_bundle = rev_parse(&git, &repo, &format!("{}^{{tree}}", c1.as_str()));
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

    let client = client_against(&server, "ghs_fake_token");
    let (final_sha, map) = replay_commits(
        &client,
        &sample_repo(),
        &source,
        &plan_commits,
        plan_seed,
        &[],
        None,
    )
    .await
    .expect("replay ok");

    assert_eq!(final_sha, c2_app);
    assert_eq!(map.commit(&c1), Some(&c1_app));
    assert_eq!(map.commit(&c2), Some(&c2_app));
    assert_eq!(map.commit(&expected), Some(&expected));
}

/// `branch_creation_to_fast_forward` is total: every variant of
/// the source enum maps to a sensible variant of the destination.
/// Pin the mapping so a future refactor can't silently re-route
/// (e.g. by changing a variant's name) without updating the
/// adapter.
#[test]
fn branch_creation_to_fast_forward_is_total() {
    assert_eq!(
        branch_creation_to_fast_forward(BranchCreationPlanError::Git("boom".to_string())),
        FastForwardPlanError::Git("boom".to_string()),
    );
    assert_eq!(
        branch_creation_to_fast_forward(BranchCreationPlanError::InvalidRevListOutput {
            line: "bad".to_string(),
            reason: "reason".to_string(),
        }),
        FastForwardPlanError::InvalidRevListOutput {
            line: "bad".to_string(),
            reason: "reason".to_string(),
        },
    );
    assert_eq!(
        branch_creation_to_fast_forward(BranchCreationPlanError::ShallowStagingRepo {
            staging_repo: "/tmp/staging".to_string(),
        }),
        FastForwardPlanError::ShallowStagingRepo {
            staging_repo: "/tmp/staging".to_string(),
        },
    );
    assert_eq!(
        branch_creation_to_fast_forward(BranchCreationPlanError::DisjointHistory {
            default_head: "aaaa".to_string(),
            bundle_tip: "bbbb".to_string(),
        }),
        FastForwardPlanError::DivergedHistory {
            expected_remote_head: "aaaa".to_string(),
            bundle_tip: "bbbb".to_string(),
        },
    );
}
