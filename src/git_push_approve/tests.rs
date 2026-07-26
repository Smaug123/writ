//! Tests for the staged-push approve-preparation logic (`PreparedApprove`,
//! `StagingRepo`, and the bring-up/verify helpers). Split out of
//! `git_push_approve.rs` (an inline `#[cfg(test)]` module) to keep the
//! production file readable; the tests are unchanged.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use serde_json::json;
use time::macros::datetime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::git_push_promote::UpdateRefError;
use crate::github_git_db::{CommitIdentity, GitDataError};
use crate::vm_git::GitBranchName;
use crate::vm_git_bundle::{GitCloneBaseUrl, GitCredentialBoundary, GitSecretEnvVar};

// ---------- shared fixtures ----------

fn sample_object_id(nibble: char) -> GitObjectId {
    GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
}

fn sample_repo() -> GitCloneRepo {
    GitCloneRepo::new(RepoRef::from_str("owner/name").unwrap()).unwrap()
}

fn sample_token() -> GitSecretValue {
    GitSecretValue::new("ghs_test_token_value").unwrap()
}

const PRIVATE_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");

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
fn staging_dir_for_isolates_each_attempt_under_approve() {
    let runtime = sample_runtime(PathBuf::from("/tmp/promote"));
    let id_a = ApproveAttemptId::new();
    let id_b = ApproveAttemptId::new();
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
    let attempt_id = ApproveAttemptId::new();
    let staging = staging_dir_for(&runtime, attempt_id);
    // Plant a colliding dir.
    std::fs::create_dir_all(&staging).unwrap();

    let err = prepare_staging_repo(
        &runtime,
        attempt_id,
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
) -> Result<Result<RunApproveOutcome, CommitError>, RunApproveError> {
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
        .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body("main", &parent)))
        // Pre-walk, post-walk, and commit's final pre-PATCH recheck.
        .expect(3)
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
/// planner returns `AlreadyAtExpected`. No upload and no PATCH are
/// issued (`expect(0)` on POST/PATCH), but the commit half still
/// issues the single lease-check `GET` before recording the noop
/// as approved — the branch is confirmed still at the anchor, so
/// the returned `new_app_tip` is the lease anchor itself.
#[tokio::test]
async fn run_approve_returns_noop_after_lease_check_when_bundle_tip_equals_lease() {
    if maybe_git().is_none() {
        eprintln!("skipping: `git` not on PATH");
        return;
    }
    let (tmp, staging_path, _parent, child) = build_real_staging_repo();
    let staging = StagingRepo::from_path_for_test(staging_path);
    let runtime = runtime_pointed_at(tmp.path());

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/ref/heads/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body("main", &child)))
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

/// The noop's lease check is load-bearing: bundle tip equals the
/// lease anchor, so the planner returns `AlreadyAtExpected`, but a
/// rival has moved the branch away from the anchor since the
/// receipt was staged. Recording "approved at <anchor>" would then
/// be a false branch-state claim, so the commit half must refuse
/// with `FinalLeaseMoved` (provably no mutation — `expect(0)` on
/// PATCH) rather than resolve the push as approved.
#[tokio::test]
async fn run_approve_noop_refuses_when_branch_moved_away_from_lease() {
    if maybe_git().is_none() {
        eprintln!("skipping: `git` not on PATH");
        return;
    }
    let (tmp, staging_path, _parent, child) = build_real_staging_repo();
    let staging = StagingRepo::from_path_for_test(staging_path);
    let runtime = runtime_pointed_at(tmp.path());

    let server = MockServer::start().await;
    let moved = sample_object_id('9');
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/ref/heads/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body("main", &moved)))
        .expect(1)
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
        &child,
        &child,
    )
    .await
    .expect("noop approve must prepare")
    .expect_err("a moved branch must refuse the noop resolution");

    match err {
        CommitError::FinalLeaseMoved { expected, actual } => {
            assert_eq!(expected, child);
            assert_eq!(actual, moved);
        }
        other => panic!("expected FinalLeaseMoved, got {other:?}"),
    }
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
        .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body("main", &parent)))
        // Pre-walk, post-walk, and commit's final pre-PATCH recheck.
        .expect(3)
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
            ResponseTemplate::new(422)
                .set_body_string(r#"{"message":"not a fast forward","documentation_url":"..."}"#),
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

    let CommitError::UpdateRef(UpdateRefError(GitDataError::ApiError { status, .. })) = err else {
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
        .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body("main", &parent)))
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

/// Locate an absolute `sleep`. The stall wrapper below runs under
/// `env_clear()` (both `CatFileObjectSource::open` and the
/// clean-git helpers wipe the environment), so it inherits no
/// `PATH` and cannot resolve `sleep` by name — embed the absolute
/// path. Mirrors the object-source module's own helper.
fn maybe_sleep() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("sleep");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Write a `git` wrapper that behaves like the real binary for every
/// invocation the approve pipeline makes (`cat-file -t`, `rev-list`)
/// *except* `cat-file --batch`, which it replaces with an unbounded
/// sleep. That is exactly the shape of a wedged object-traversal
/// child: it accepts the request SHA on stdin (the pipe buffers it)
/// but never writes a response, so `read_object_raw`'s `read_line`
/// would block forever. Returns the wrapper path.
fn write_stalling_cat_file_wrapper(dir: &Path, git: &Path, sleep: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let wrapper = dir.join("git-stall-batch.sh");
    let script = format!(
        "#!/bin/sh\n\
         for arg in \"$@\"; do\n\
         \tif [ \"$arg\" = \"--batch\" ]; then\n\
         \t\texec {sleep} 600\n\
         \tfi\n\
         done\n\
         exec {git} \"$@\"\n",
        sleep = sleep.display(),
        git = git.display(),
    );
    std::fs::write(&wrapper, script).expect("write cat-file stall wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))
        .expect("chmod wrapper");
    wrapper
}

/// End-to-end wiring check for the cat-file read deadline: the
/// configured step timeout covered `rev-list` and the other one-shot
/// Git commands, but not the long-lived `git cat-file --batch`
/// traversal, whose `read_object_raw` pipe reads are unbounded. A
/// child that stalls mid-response parked the whole approve — attempt
/// row and operator approval still active — long after the CLI
/// disconnected. `open` now carries `cat_file_timeout` as a per-object
/// read deadline, so a wedged read surfaces as a retryable
/// `ExecuteError::Replay` (a `ReadTimedOut` under the hood) instead
/// of hanging. (The per-object placement — verified directly in
/// `git_push_objects_cat_file` — is what keeps a legitimate
/// multi-object upload from being folded into one step's budget.)
///
/// The step timeout is set *generously* here, and that is the second
/// thing this test pins: the read deadline must be independent of it.
/// While the two shared one field the test had to drive the shared
/// value down to 500 ms to stay quick, which put the real `cat-file
/// -t` subprocess in a race with the deadline under test — a race it
/// lost under parallel-test load, so the test flaked with
/// `ResolveBundleTip("Git command timed out")` instead of the read
/// timeout. Now a generous step timeout costs nothing, and if the read
/// deadline is ever re-derived from it this test fails on the outer
/// guard rather than flaking.
///
/// That outer `tokio::time::timeout` is the anti-hang guard: with the
/// fix the inner per-read deadline (500 ms) fires first and the call
/// returns; without it the traversal blocks for the step timeout (or
/// forever) and the guard elapses, failing the test instead of wedging
/// CI.
#[tokio::test]
async fn prepare_approve_bounds_a_stalled_cat_file_traversal() {
    let Some(git) = maybe_git() else {
        eprintln!("skipping: `git` not on PATH");
        return;
    };
    let Some(sleep) = maybe_sleep() else {
        eprintln!("skipping: `sleep` not on PATH");
        return;
    };
    let (tmp, staging_path, parent, child) = build_real_staging_repo();
    let staging = StagingRepo::from_path_for_test(staging_path);
    let wrapper = write_stalling_cat_file_wrapper(tmp.path(), &git, &sleep);

    // The step timeout is generous — the wrapper really does exec
    // `git` for `cat-file -t` and `rev-list`, and those must not be
    // racing anything. The cat-file read below stalls forever, so the
    // short per-object deadline is what has to fire.
    let deadline = Duration::from_millis(500);
    let runtime = PromoteRuntimeConfig::new(
        wrapper,
        GitCloneBaseUrl::github(),
        GitCredentialBoundary::new(
            PathBuf::from("/usr/local/bin/fake-askpass"),
            GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap(),
        )
        .unwrap(),
        tmp.path().to_path_buf(),
        Duration::from_secs(30),
    )
    .unwrap()
    .with_cat_file_timeout(deadline)
    .unwrap();

    let server = MockServer::start().await;
    // The Replay arm's pre-walk lease check must succeed so the walk
    // reaches the (stalling) object read; the stall precedes any
    // upload, so no object is ever POSTed and no ref is PATCHed.
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/ref/heads/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body("main", &parent)))
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

    // 60 s, and not tight: this guard exists to convert a hang into a
    // failure, so its only job is to sit well clear of every legitimate
    // cost in the call. One of those costs is large and has nothing to
    // do with the deadline under test — `prepare_approve_with_staging_repo`
    // constructs a `reqwest::Client`, which on macOS loads the system
    // trust store and has been measured here at ~10 s. Sizing the guard
    // against the 500 ms deadline instead would just re-introduce a
    // race, with the client build as the thing that loses.
    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        prepare_approve_with_staging_repo(
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
        ),
    )
    .await
    .expect("the per-object read deadline must return; a hang means the fix regressed");

    // A wedged read surfaces as a retryable replay failure carrying
    // the timeout diagnostic — not a hang, and not a whole-traversal
    // timeout that would also have failed a slow-but-legitimate push.
    match outcome {
        Err(RunApproveError::Execute(ExecuteError::Replay(ref replay))) => assert!(
            replay.to_string().contains("timed out"),
            "expected a read-timeout replay error, got: {replay}"
        ),
        other => panic!("expected Execute(Replay(read timeout)), got {other:?}"),
    }

    // The stall is upstream of any upload; verify no POST/PATCH fired.
    server.verify().await;
}

/// The reviewer scenario for the last-second lease recheck: both
/// prepare-side lease checks pass, then — during the interval the
/// broker spends closing the object source and writing the
/// `Uncertain` row — another actor rewinds the branch. A
/// `force=false` PATCH would still *succeed* (the prepared tip
/// descends from the rewound head), publishing against a baseline
/// the approval never covered. `commit` must therefore re-verify
/// the lease immediately before the PATCH and refuse without
/// issuing it: the `expect(0)` on the PATCH mock is the assertion.
#[tokio::test]
async fn commit_rechecks_lease_and_refuses_when_branch_moved_after_prepare() {
    if maybe_git().is_none() {
        eprintln!("skipping: `git` not on PATH");
        return;
    }
    let (tmp, staging_path, parent, child) = build_real_staging_repo();
    let staging = StagingRepo::from_path_for_test(staging_path);
    let runtime = runtime_pointed_at(tmp.path());

    let server = MockServer::start().await;
    // Both prepare-side lease checks see the expected head…
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/ref/heads/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body("main", &parent)))
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;
    // …and any later lease check sees the rewound branch.
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/ref/heads/main"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(ref_response_body("main", &sample_object_id('9'))),
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
            "verification": { "verified": true, "reason": "valid" },
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let branch = GitBranchName::new("main").unwrap();
    let attempt_id = ApproveAttemptId::new();
    let prepared = prepare_approve_with_staging_repo(
        &staging,
        &runtime,
        &server.uri(),
        &sample_token(),
        &sample_repo().as_repo_ref().clone(),
        &branch,
        &parent,
        &child,
        &sample_signing_key(),
        &[],
        attempt_id,
    )
    .await
    .expect("prepare must succeed while the lease still holds");

    let err = prepared
        .commit(&UncertainAttempt::for_test(attempt_id))
        .await
        .expect_err("a branch rewound after prepare must refuse to publish");
    assert!(
        matches!(err, CommitError::FinalLeaseMoved { .. }),
        "expected FinalLeaseMoved, got {err:?}",
    );
    // The PATCH `expect(0)` is enforced here.
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
        .respond_with(ResponseTemplate::new(200).set_body_json(ref_response_body("main", &parent)))
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

/// Stage-3 oracle for the crash harness's fake origin: the *real*
/// `prepare_staging_repo` — mkdir, bundle write, `git init`, an
/// actual `git fetch` over the origin's dumb-HTTP server, and
/// `git bundle unbundle` — succeeds end to end, leaving both the
/// prerequisite (via the network fetch) and the bundle tip (via
/// the unbundle) in the staging repo. This is also the first test
/// to exercise a *successful* prepare fetch at all; everything
/// prior stubbed git or stopped short of the network.
#[tokio::test]
async fn prepare_staging_repo_fetches_prereq_from_fake_origin() {
    use crate::fake_origin::FakeOrigin;
    let Some(origin) = FakeOrigin::start().await else {
        eprintln!("skipping: `git` not on PATH");
        return;
    };
    let git = maybe_git().expect("FakeOrigin::start returned Some, so git exists");
    let work_root = tempfile::tempdir().unwrap();
    let runtime = PromoteRuntimeConfig::new(
        git.clone(),
        origin.clone_base_url(),
        GitCredentialBoundary::new(
            PathBuf::from("/usr/local/bin/fake-askpass"),
            GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap(),
        )
        .unwrap(),
        work_root.path().to_path_buf(),
        Duration::from_secs(30),
    )
    .unwrap();

    let staging = prepare_staging_repo(
        &runtime,
        ApproveAttemptId::new(),
        origin.prereq(),
        &sample_repo(),
        &sample_token(),
        origin.bundle_bytes(),
    )
    .await
    .expect("prepare must fetch the prereq over dumb HTTP and unbundle the tip");

    for (what, sha) in [("prereq", origin.prereq()), ("bundle tip", origin.tip())] {
        let exists = Command::new(&git)
            .arg("-C")
            .arg(staging.path())
            .args(["cat-file", "-e", sha.as_str()])
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("HOME", "/dev/null")
            .status()
            .expect("spawning git cat-file failed");
        assert!(
            exists.success(),
            "{what} {sha} must be present in the staging repo",
            sha = sha.as_str(),
        );
    }
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
    let attempt_id = ApproveAttemptId::new();
    let staging_dir = staging_dir_for(&runtime, attempt_id);

    let err = prepare_staging_repo(
        &runtime,
        attempt_id,
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
/// `prepare_staging_repo`'s per-attempt-dir call site relies on.
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
