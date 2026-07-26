//! Shared fixtures and real-git helpers for the walker test modules.
//!
//! `super::*` re-exports the production items and the parent module's
//! private `use` aliases (`GitObjectId`, `RepoRef`, `Duration`, …); the
//! explicit imports add what the parent does not pull in.

use super::*;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

use crate::github_git_db::GitDataHttp;

use serde_json::json;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub(super) fn sample_repo() -> RepoRef {
    RepoRef::from_str("owner/name").unwrap()
}

pub(super) fn sample_object_id(nibble: char) -> GitObjectId {
    GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
}

pub(super) fn sample_identity(name: &str) -> CommitIdentity {
    use time::macros::datetime;
    CommitIdentity::new(
        name,
        format!("{name}@example.invalid"),
        datetime!(2024-01-15 10:30:45 UTC),
    )
    .expect("sample date formats")
}

pub(super) fn client_against(server: &MockServer, token: &str) -> GitDataClient {
    GitDataClient::new(&GitDataHttp::production(), server.uri(), token.to_string())
}

/// Mount a blob create that strictly matches the given content
/// and responds with the given SHA. Returns nothing — failing
/// the strict body match shows up as the test's commit-create
/// matcher never firing (or wiremock surfaces an unmatched
/// request).
pub(super) async fn mount_blob_create(server: &MockServer, content: &[u8], returned: &GitObjectId) {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(content);
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/blobs"))
        .and(body_json(json!({
            "content": encoded,
            "encoding": "base64",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": returned.as_str(),
        })))
        .expect(1)
        .mount(server)
        .await;
}

pub(super) async fn mount_tree_create(
    server: &MockServer,
    expected_body: serde_json::Value,
    returned: &GitObjectId,
) {
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/trees"))
        .and(body_json(expected_body))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": returned.as_str(),
        })))
        .expect(1)
        .mount(server)
        .await;
}

pub(super) async fn mount_commit_create(
    server: &MockServer,
    expected_body: serde_json::Value,
    returned: &GitObjectId,
) {
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/commits"))
        .and(body_json(expected_body))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": returned.as_str(),
        })))
        .expect(1)
        .mount(server)
        .await;
}

/// The planner shell-outs are sub-second under a normal load.
/// 10s gives plenty of room on a saturated CI host without
/// letting a wedged child hang the suite indefinitely.
pub(super) const TEST_GIT_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn required_git() -> PathBuf {
    let path = std::env::var_os("PATH")
        .unwrap_or_else(|| panic!("PATH must contain `git` for walker tests"));
    for dir in std::env::split_paths(&path) {
        let candidate = if dir.is_absolute() {
            dir.join("git")
        } else {
            std::env::current_dir().unwrap().join(dir).join("git")
        };
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!("`git` not found on PATH for walker tests");
}

/// Spawn `git -C <repo> <args>` under the same hardened env the
/// production planner uses, plus pinned author/committer
/// identity and date so commit SHAs are deterministic across
/// runs and machines. Asserts success; returns the full output
/// for callers that need stdout (e.g. `rev-parse`).
pub(super) fn run_git(git: &Path, repo: &Path, args: &[&str]) -> std::process::Output {
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
        "git -C {} {args:?} failed with {}: stdout={:?} stderr={}",
        repo.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

pub(super) fn rev_parse(git: &Path, repo: &Path, rev: &str) -> GitObjectId {
    let out = run_git(git, repo, &["rev-parse", rev]);
    let sha = String::from_utf8(out.stdout).unwrap().trim().to_string();
    GitObjectId::new(sha).expect("rev-parse output must be a valid 40-hex SHA")
}

/// Fresh tempdir, `git init` inside it, no global config. Returns
/// `(TempDir, repo_path)` — the caller must keep the TempDir
/// alive for the test's duration (drop deletes the directory).
pub(super) fn init_test_repo() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().to_path_buf();
    let git = required_git();
    let init = Command::new(&git)
        .args(["init", "--quiet"])
        .arg(&repo)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_COUNT", "0")
        .env("HOME", "/dev/null")
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&init.stderr),
    );
    (dir, repo, git)
}

/// Create an empty commit on HEAD with the given message; return
/// its SHA. With the pinned env in [`run_git`] the resulting SHA
/// is deterministic across runs as long as parents are too.
pub(super) fn commit_empty(git: &Path, repo: &Path, message: &str) -> GitObjectId {
    run_git(
        git,
        repo,
        &["commit", "--allow-empty", "--quiet", "-m", message],
    );
    rev_parse(git, repo, "HEAD")
}

/// Create a merge commit via `commit-tree` with explicit parents.
/// Uses the tree of the first parent. Returns the merge SHA.
pub(super) fn commit_merge(
    git: &Path,
    repo: &Path,
    message: &str,
    parents: &[&GitObjectId],
) -> GitObjectId {
    let tree_out = run_git(
        git,
        repo,
        &["rev-parse", &format!("{}^{{tree}}", parents[0].as_str())],
    );
    let tree = String::from_utf8(tree_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    let mut args: Vec<String> = vec![
        "commit-tree".to_string(),
        tree,
        "-m".to_string(),
        message.to_string(),
    ];
    for parent in parents {
        args.push("-p".to_string());
        args.push(parent.as_str().to_string());
    }
    let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = run_git(git, repo, &args_refs);
    let sha = String::from_utf8(out.stdout).unwrap().trim().to_string();
    GitObjectId::new(sha).unwrap()
}
