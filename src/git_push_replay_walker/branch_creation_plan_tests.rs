//! Example-based tests for `plan_branch_creation_via_rev_list`: its
//! argv/parse primitives, the real-git end-to-end topology cases, and
//! the subprocess-timeout guard.

use super::test_fixture::InMemoryGitObjectSource;
use super::test_support::*;
use super::*;
use std::path::PathBuf;

use serde_json::json;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Assert a planner result is `Replay` and return the inner
/// `(commits, seed)`. Keeps real-git tests legible without
/// repeating the `match` boilerplate at every call site.
fn expect_replay(plan: BranchCreationPlan) -> (Vec<GitObjectId>, ShaMap) {
    match plan {
        BranchCreationPlan::Replay { commits, seed } => (commits, seed),
        BranchCreationPlan::AlreadyOnDefault { tip } => {
            panic!("expected Replay, got AlreadyOnDefault {{ tip: {tip:?} }}")
        }
    }
}

// ----- pure helpers -----

#[test]
fn build_is_shallow_invocation_pins_argv_shape() {
    let staging = PathBuf::from("/tmp/staging");
    let git = PathBuf::from("/usr/bin/git");
    let invocation = build_is_shallow_invocation(&staging, &git);
    assert_eq!(invocation.program(), git.as_path());
    assert_eq!(
        invocation.display_args_lossy(),
        vec![
            "-C".to_string(),
            "/tmp/staging".to_string(),
            "rev-parse".to_string(),
            "--is-shallow-repository".to_string(),
        ],
    );
    assert!(invocation.required_secret_env().is_empty());
    // Hardened env stays attached to the pre-flight check too —
    // otherwise a malicious `core.fsmonitor` in a parent `.git`
    // dir could fire.
    let names: Vec<&str> = invocation.env().iter().map(|e| e.name()).collect();
    assert!(names.contains(&"GIT_CONFIG_NOSYSTEM"));
    assert!(names.contains(&"HOME"));
}

#[test]
fn parse_is_shallow_output_recognises_true_and_false() {
    assert!(parse_is_shallow_output(b"true\n").unwrap());
    assert!(!parse_is_shallow_output(b"false\n").unwrap());
    // Whitespace tolerance: git always emits a trailing newline,
    // but defensive trim covers windows-CRLF too.
    assert!(parse_is_shallow_output(b"  true  ").unwrap());
    assert!(!parse_is_shallow_output(b"false\r\n").unwrap());
}

#[test]
fn parse_is_shallow_output_rejects_unexpected_value() {
    let err = parse_is_shallow_output(b"maybe\n").unwrap_err();
    match err {
        BranchCreationPlanError::InvalidRevListOutput { line, .. } => {
            assert_eq!(line, "maybe");
        }
        other => panic!("expected InvalidRevListOutput, got {other:?}"),
    }
}

#[test]
fn build_rev_list_boundary_invocation_pins_argv_shape() {
    let staging = PathBuf::from("/tmp/staging");
    let git = PathBuf::from("/usr/bin/git");
    let bundle_tip = sample_object_id('a');
    let default_head = sample_object_id('b');
    let invocation = build_rev_list_boundary_invocation(&staging, &git, &bundle_tip, &default_head);
    assert_eq!(invocation.program(), git.as_path());
    assert_eq!(
        invocation.display_args_lossy(),
        vec![
            "-C".to_string(),
            "/tmp/staging".to_string(),
            "rev-list".to_string(),
            "--topo-order".to_string(),
            "--reverse".to_string(),
            "--boundary".to_string(),
            format!("^{}", default_head.as_str()),
            bundle_tip.as_str().to_string(),
        ],
    );
    // Reading the staging repo never needs a credential — the
    // App token is a GitHub-side thing, not a local-git thing.
    assert!(invocation.required_secret_env().is_empty());
    // Sanity-check the hardened-env wiring: the production
    // helper must supply at least the `GIT_CONFIG_NOSYSTEM` and
    // `HOME` entries. Spelling them out here catches regressions
    // where someone swaps out `clean_git_config_env`.
    let names: Vec<&str> = invocation.env().iter().map(|e| e.name()).collect();
    assert!(names.contains(&"GIT_CONFIG_NOSYSTEM"));
    assert!(names.contains(&"HOME"));
}

#[test]
fn parse_rev_list_boundary_output_splits_interesting_and_boundary() {
    let a = "a".repeat(40);
    let b = "b".repeat(40);
    let c = "c".repeat(40);
    let stdout = format!("{a}\n{b}\n-{c}\n");
    let (commits, boundaries) = parse_rev_list_boundary_output(stdout.as_bytes()).unwrap();
    let commit_strs: Vec<&str> = commits.iter().map(GitObjectId::as_str).collect();
    let boundary_strs: Vec<&str> = boundaries.iter().map(GitObjectId::as_str).collect();
    assert_eq!(commit_strs, vec![a.as_str(), b.as_str()]);
    assert_eq!(boundary_strs, vec![c.as_str()]);
}

#[test]
fn parse_rev_list_boundary_output_accepts_empty_input() {
    let (commits, boundaries) = parse_rev_list_boundary_output(b"").unwrap();
    assert!(commits.is_empty());
    assert!(boundaries.is_empty());
}

#[test]
fn parse_rev_list_boundary_output_ignores_blank_lines() {
    let sha = "a".repeat(40);
    let stdout = format!("\n{sha}\n\n");
    let (commits, _) = parse_rev_list_boundary_output(stdout.as_bytes()).unwrap();
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].as_str(), sha);
}

#[test]
fn parse_rev_list_boundary_output_rejects_short_sha() {
    let err = parse_rev_list_boundary_output(b"abc\n").unwrap_err();
    match err {
        BranchCreationPlanError::InvalidRevListOutput { line, .. } => {
            assert_eq!(line, "abc");
        }
        other => panic!("expected InvalidRevListOutput, got {other:?}"),
    }
}

#[test]
fn parse_rev_list_boundary_output_rejects_non_hex_sha() {
    let bad = "z".repeat(40);
    let err = parse_rev_list_boundary_output(bad.as_bytes()).unwrap_err();
    assert!(
        matches!(err, BranchCreationPlanError::InvalidRevListOutput { .. }),
        "got {err:?}",
    );
}

#[test]
fn parse_rev_list_boundary_output_preserves_dash_prefix_in_error_line() {
    // The reported `line` includes the leading `-`, so a future
    // debugger sees exactly what git emitted (boundary or not)
    // rather than an unprefixed snippet that could be mistaken
    // for an interesting commit.
    let err = parse_rev_list_boundary_output(b"-abc\n").unwrap_err();
    match err {
        BranchCreationPlanError::InvalidRevListOutput { line, .. } => {
            assert_eq!(line, "-abc");
        }
        other => panic!("expected InvalidRevListOutput, got {other:?}"),
    }
}

#[test]
fn parse_rev_list_boundary_output_rejects_non_utf8() {
    let mut bytes = vec![b'a'; 40];
    bytes.push(b'\n');
    bytes.push(0xff);
    let err = parse_rev_list_boundary_output(&bytes).unwrap_err();
    match err {
        BranchCreationPlanError::InvalidRevListOutput { line, .. } => {
            assert!(line.contains("non-utf8"), "got {line}");
        }
        other => panic!("expected InvalidRevListOutput, got {other:?}"),
    }
}

// ----- real-git end-to-end -----

#[tokio::test]
async fn rev_list_plan_rejects_when_rev_list_output_exceeds_cap() {
    // A single new commit makes `rev-list --boundary` emit well over a handful
    // of bytes, so a tiny cap trips the guard: the planner must refuse the walk
    // (killing the git process group) rather than buffer and parse
    // guest-controlled output unbounded.
    let (_dir, repo, git) = init_test_repo();
    let c0 = commit_empty(&git, &repo, "default head");
    let c1 = commit_empty(&git, &repo, "one new commit");

    let err = plan_branch_creation_via_rev_list(&c1, &c0, &repo, &git, TEST_GIT_TIMEOUT, 8)
        .await
        .expect_err("over-cap rev-list output must be refused");
    match err {
        BranchCreationPlanError::RevListOutputTooLarge { cap } => assert_eq!(cap, 8),
        other => panic!("expected RevListOutputTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn rev_list_plan_returns_single_commit_when_tip_is_child_of_default_head() {
    let (_dir, repo, git) = init_test_repo();
    let c0 = commit_empty(&git, &repo, "default head");
    let c1 = commit_empty(&git, &repo, "one new commit");

    let plan = plan_branch_creation_via_rev_list(
        &c1,
        &c0,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect("plan ok");
    let (commits, seed) = expect_replay(plan);
    assert_eq!(commits, vec![c1]);
    assert_eq!(seed.commit(&c0), Some(&c0));
    assert_eq!(seed.commit_count(), 1);
}

#[tokio::test]
async fn rev_list_plan_topologically_sorts_linear_chain() {
    let (_dir, repo, git) = init_test_repo();
    let c0 = commit_empty(&git, &repo, "c0");
    let c1 = commit_empty(&git, &repo, "c1");
    let c2 = commit_empty(&git, &repo, "c2");
    let c3 = commit_empty(&git, &repo, "c3");

    let plan = plan_branch_creation_via_rev_list(
        &c3,
        &c0,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect("plan ok");
    let (commits, seed) = expect_replay(plan);
    assert_eq!(commits, vec![c1.clone(), c2, c3]);
    // `--boundary` reports the merge-base; for a linear chain
    // that's the commit we passed as default_head. The boundary
    // is not c1.
    assert_eq!(seed.commit(&c0), Some(&c0));
    assert!(seed.commit(&c1).is_none());
}

#[tokio::test]
async fn rev_list_plan_handles_merge_with_mixed_age_parents() {
    // Build the topology the in-walker DFS got wrong:
    //
    //   c0 ─ c_old ────────╮
    //    │                 ├─ merge  (bundle tip)
    //    └─ new1 ──────────╯
    //
    // default_head = c_old.  c_old's only ancestor is c0, which
    // is already on default. new1's only ancestor is c0 too, but
    // new1 itself is new. The walker must emit [new1, merge] —
    // never c0 (which is reachable from default_head via c_old).
    let (_dir, repo, git) = init_test_repo();
    let c0 = commit_empty(&git, &repo, "c0");
    let c_old = commit_empty(&git, &repo, "c_old on default");
    // Branch off c0 (older than default head) for the new side.
    run_git(
        &git,
        &repo,
        &["checkout", "--quiet", "-b", "side", c0.as_str()],
    );
    let new1 = commit_empty(&git, &repo, "new1");
    let merge = commit_merge(&git, &repo, "merge", &[&c_old, &new1]);

    let plan = plan_branch_creation_via_rev_list(
        &merge,
        &c_old,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect("plan ok");
    let (commits, seed) = expect_replay(plan);
    assert_eq!(commits.len(), 2, "got {commits:?}");
    assert!(
        !commits.contains(&c0),
        "c0 must not be uploaded — already on default"
    );
    assert!(
        !commits.contains(&c_old),
        "c_old is default head — must not appear"
    );
    let new1_idx = commits
        .iter()
        .position(|s| s == &new1)
        .expect("new1 emitted");
    let merge_idx = commits
        .iter()
        .position(|s| s == &merge)
        .expect("merge emitted");
    assert!(new1_idx < merge_idx, "new1 must precede merge");
    // The merge-base of merge and c_old is c0; c_old is on the
    // default branch and is also a direct parent of merge, so
    // rev-list reports both as boundaries.
    assert!(
        seed.commit(&c0).is_some() || seed.commit(&c_old).is_some(),
        "expected some default-side ancestor in the seed map, got {seed:?}",
    );
}

#[tokio::test]
async fn rev_list_plan_handles_fork_from_older_default_commit() {
    // c0 ─ c1 ─ c2  (default branch, head = c2)
    //       └─ new   (bundle tip, forked at c1)
    //
    // The DFS approach would walk new → c1 and stop only at c2
    // (never reached); the rev-list approach excludes everything
    // reachable from c2, so c1 (and c0) are out.
    let (_dir, repo, git) = init_test_repo();
    let _c0 = commit_empty(&git, &repo, "c0");
    let c1 = commit_empty(&git, &repo, "c1");
    let c2 = commit_empty(&git, &repo, "c2 (default head)");

    run_git(
        &git,
        &repo,
        &["checkout", "--quiet", "-b", "side", c1.as_str()],
    );
    let new = commit_empty(&git, &repo, "new on side");

    let plan = plan_branch_creation_via_rev_list(
        &new,
        &c2,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect("plan ok");
    let (commits, seed) = expect_replay(plan);
    assert_eq!(commits, vec![new]);
    // Merge-base is c1, which is the boundary rev-list reports.
    assert_eq!(seed.commit(&c1), Some(&c1));
}

#[tokio::test]
async fn rev_list_plan_rejects_shallow_staging_repo() {
    // Simulate a shallow clone by creating `.git/shallow`. We
    // don't need an actually-truncated history here — the
    // planner's check is "does `.git/shallow` exist", per `git
    // rev-parse --is-shallow-repository`. The variant exists to
    // prevent a real shallow clone from silently masquerading
    // as `DisjointHistory`, so the test pins the detection
    // path, not the underlying truncation behaviour.
    let (_dir, repo, git) = init_test_repo();
    let default_head = commit_empty(&git, &repo, "default");
    let c1 = commit_empty(&git, &repo, "new");

    let shallow_marker = repo.join(".git").join("shallow");
    std::fs::write(&shallow_marker, format!("{}\n", default_head.as_str())).unwrap();
    assert!(shallow_marker.exists(), "marker write must succeed");

    let err = plan_branch_creation_via_rev_list(
        &c1,
        &default_head,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect_err("shallow staging repo must be rejected");
    match err {
        BranchCreationPlanError::ShallowStagingRepo { staging_repo } => {
            assert_eq!(staging_repo, repo.display().to_string());
        }
        other => panic!("expected ShallowStagingRepo, got {other:?}"),
    }
}

#[tokio::test]
async fn rev_list_plan_rejects_disjoint_history() {
    let (_dir, repo, git) = init_test_repo();
    let default_head = commit_empty(&git, &repo, "default");
    // Orphan branch: --orphan makes the next commit parentless,
    // so its history shares nothing with `default_head`.
    run_git(&git, &repo, &["checkout", "--quiet", "--orphan", "orphan"]);
    // After --orphan from an empty-tree commit the index is also
    // empty, so an --allow-empty commit produces a parentless
    // empty-tree root.
    let orphan_tip = commit_empty(&git, &repo, "orphan tip");

    let err = plan_branch_creation_via_rev_list(
        &orphan_tip,
        &default_head,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect_err("disjoint history must be rejected");
    match err {
        BranchCreationPlanError::DisjointHistory {
            default_head: dh,
            bundle_tip: bt,
        } => {
            assert_eq!(dh, default_head.as_str());
            assert_eq!(bt, orphan_tip.as_str());
        }
        other => panic!("expected DisjointHistory, got {other:?}"),
    }
}

#[tokio::test]
async fn rev_list_plan_returns_already_on_default_when_bundle_tip_equals_default_head() {
    // Agent creates a new branch pointing at the current default
    // head (e.g. `git branch feature/foo main && git push origin
    // feature/foo`). No commits to upload — the orchestrator just
    // needs to publish the ref at the existing SHA.
    let (_dir, repo, git) = init_test_repo();
    let head = commit_empty(&git, &repo, "only commit");
    let plan = plan_branch_creation_via_rev_list(
        &head,
        &head,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect("bundle_tip == default_head must succeed as AlreadyOnDefault");
    match plan {
        BranchCreationPlan::AlreadyOnDefault { tip } => {
            assert_eq!(tip, head);
        }
        other => panic!("expected AlreadyOnDefault, got {other:?}"),
    }
}

#[tokio::test]
async fn rev_list_plan_returns_already_on_default_when_bundle_tip_is_ancestor_of_default_head() {
    // Agent creates a new branch pointing at an older commit on
    // the default branch (e.g. tagging a past release). No upload
    // needed; the ref publication is still valid.
    let (_dir, repo, git) = init_test_repo();
    let c0 = commit_empty(&git, &repo, "c0");
    let c1 = commit_empty(&git, &repo, "c1 (default head)");

    let plan = plan_branch_creation_via_rev_list(
        &c0,
        &c1,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect("ancestor bundle_tip must succeed as AlreadyOnDefault");
    match plan {
        BranchCreationPlan::AlreadyOnDefault { tip } => {
            assert_eq!(tip, c0);
        }
        other => panic!("expected AlreadyOnDefault, got {other:?}"),
    }
}

#[tokio::test]
async fn rev_list_plan_surfaces_git_error_on_unknown_sha() {
    let (_dir, repo, git) = init_test_repo();
    let head = commit_empty(&git, &repo, "only commit");
    let bogus = GitObjectId::new("0".repeat(40)).unwrap();
    let err = plan_branch_creation_via_rev_list(
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
        matches!(err, BranchCreationPlanError::Git(_)),
        "expected Git, got {err:?}",
    );
}

/// End-to-end integration: feed a real-git plan straight into
/// `replay_commits` against a wiremock-backed GitHub Git Data
/// client. Proves the boundary commits land in the seed map in
/// a shape that satisfies the walker's `UnmappedParent` guard,
/// without needing an in-memory `GitObjectSource` to mimic
/// staging-repo topology.
#[tokio::test]
async fn rev_list_plan_seeds_replay_commits_end_to_end() {
    let (_dir, repo, git) = init_test_repo();
    let default_head = commit_empty(&git, &repo, "default head");
    let c1 = commit_empty(&git, &repo, "new c1");
    let c2 = commit_empty(&git, &repo, "new c2");

    let plan = plan_branch_creation_via_rev_list(
        &c2,
        &default_head,
        &repo,
        &git,
        TEST_GIT_TIMEOUT,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect("plan ok");
    let (plan_commits, plan_seed) = expect_replay(plan);
    assert_eq!(plan_commits, vec![c1.clone(), c2.clone()]);
    assert_eq!(plan_seed.commit(&default_head), Some(&default_head));

    // Stub out blob/tree/commit creation so the replay walker
    // can run without a real GitHub. The bundle commits all
    // share the same empty tree (because both are
    // `commit --allow-empty` on an empty initial repo), so
    // exactly one tree create is expected.
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

    // In-memory source pre-populated with the two new commits
    // (and the empty tree they share). We don't insert
    // default_head because the seed map identity-maps it; the
    // walker never reads its commit object.
    let mut source = InMemoryGitObjectSource::new();
    let empty_tree_bundle = rev_parse(&git, &repo, &format!("{}^{{tree}}", c1.as_str()));
    source.insert_tree(empty_tree_bundle.clone(), StagingTree { entries: vec![] });
    source.insert_commit(
        c1.clone(),
        StagingCommit {
            tree: empty_tree_bundle.clone(),
            parents: vec![default_head.clone()],
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
    assert_eq!(map.commit(&default_head), Some(&default_head));
}

// ----- subprocess-timeout probe -----

/// Create an executable file at `dir/name` containing `body`,
/// chmod 0o755. Returns the absolute path. Used to inject a
/// shell-script stand-in for `git` into the planner so we can
/// exercise failure paths (timeout) without a real git
/// subprocess.
fn write_executable_probe(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).expect("probe file create");
    file.write_all(body.as_bytes()).expect("probe body write");
    drop(file);
    let mut perms = std::fs::metadata(&path).expect("probe stat").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("probe chmod");
    path
}

/// Locate an executable on the test runner's `PATH` without
/// resolving symlinks. Mirrors `resolve_program_for_clean_env` but
/// returns the caller-visible path so the basename survives into
/// `argv[0]` after `execve` — required on Nix where coreutils is
/// a multi-call binary dispatched by `basename(argv[0])`.
fn locate_on_path(name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH").expect("PATH must be set in tests");
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        match std::fs::metadata(&candidate) {
            Ok(meta) if meta.is_file() && (meta.permissions().mode() & 0o111) != 0 => {
                return candidate;
            }
            _ => {}
        }
    }
    panic!("required test tool {name} not found on PATH");
}

/// Shell-quote a path so it embeds safely inside a script body.
fn shell_quote(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let mut quoted = String::with_capacity(raw.len() + 2);
    quoted.push('\'');
    for ch in raw.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

/// When the rev-list subprocess does not exit before the
/// configured timeout, the planner surfaces it as
/// `Git("...timed out...")` rather than blocking the orchestrator
/// thread. The probe is a shell script standing in for `git` that
/// answers the `rev-parse --is-shallow-repository` preflight
/// cleanly (so the planner reaches `rev-list`) and then stalls.
///
/// `clean_git` strips `PATH` from the child, so the script cannot
/// resolve `sleep` at exec time. We resolve it from the test
/// runner's `PATH` (without canonicalising — coreutils is a
/// multi-call binary on Nix) and embed the path directly so the
/// stall survives in the cleared environment.
#[tokio::test]
async fn plan_branch_creation_surfaces_timeout_when_subprocess_stalls() {
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().to_path_buf();
    let sleep_bin = locate_on_path("sleep");
    // argv layout under the planner: `-C <staging> <subcommand> ...`.
    // After `shift 2`, `$1` is the git subcommand.
    let script = format!(
        "#!/bin/sh\nshift 2\nif [ \"$1\" = rev-parse ]; then\n  echo false\n  exit 0\nfi\nexec {sleep} 5\n",
        sleep = shell_quote(&sleep_bin),
    );
    let probe = write_executable_probe(dir.path(), "git-sleep", &script);
    let bundle_tip = sample_object_id('a');
    let default_head = sample_object_id('b');
    let short_timeout = Duration::from_millis(150);
    let err = plan_branch_creation_via_rev_list(
        &bundle_tip,
        &default_head,
        &staging,
        &probe,
        short_timeout,
        REV_LIST_STDOUT_BYTE_CAP,
    )
    .await
    .expect_err("sleeping probe must time out");
    match err {
        BranchCreationPlanError::Git(msg) => {
            assert!(
                msg.contains("timed out"),
                "expected timeout indication in error, got: {msg}",
            );
        }
        other => panic!("expected Git, got {other:?}"),
    }
}
