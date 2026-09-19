//! Real-git helpers for tests that build repositories on disk.
//!
//! Every command runs under the same hardened environment production uses
//! (`writ_core::git_env::apply_clean_git_config`, so an operator's
//! `/etc/gitconfig` cannot change what a test observes) plus a pinned
//! author/committer identity and date, so commit SHAs are deterministic
//! across runs and machines as long as their parents are.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use writ_core::git_env::apply_clean_git_config;

use crate::vm_git::GitObjectId;

use super::required_tool;

/// `git -C <repo> <args>`, asserting success. Returns the full output for
/// callers that need stdout.
pub fn run_git(git: &Path, repo: &Path, args: &[&str]) -> std::process::Output {
    let output = writ_core::process_spawn::output(
        apply_clean_git_config(Command::new(git).arg("-C").arg(repo).args(args).env_clear())
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_AUTHOR_DATE", "2024-01-15T10:30:45Z")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_DATE", "2024-01-15T10:30:45Z")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
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

/// [`run_git`]'s stdout with the trailing newline removed.
pub fn git_stdout(git: &Path, repo: &Path, args: &[&str]) -> String {
    String::from_utf8(run_git(git, repo, args).stdout)
        .expect("git stdout is UTF-8")
        .trim_end_matches('\n')
        .to_string()
}

/// `git rev-parse <rev>` as an object id.
pub fn rev_parse(git: &Path, repo: &Path, rev: &str) -> GitObjectId {
    GitObjectId::new(
        git_stdout(git, repo, &["rev-parse", rev])
            .trim()
            .to_string(),
    )
    .expect("rev-parse output must be a valid 40-hex SHA")
}

/// A fresh tempdir with `git init` run inside it and no global config.
/// Returns `(tempdir, repo path, git path)`; the caller keeps the tempdir
/// alive for the test's duration, since dropping it deletes the repository.
pub fn init_test_repo() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().to_path_buf();
    let git = required_tool("git");
    let init = writ_core::process_spawn::output(
        apply_clean_git_config(
            Command::new(&git)
                .args(["init", "--quiet"])
                .arg(&repo)
                .env_clear(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()),
    )
    .unwrap();
    assert!(
        init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&init.stderr),
    );
    (dir, repo, git)
}

/// An empty commit on `HEAD` with `message`; returns its SHA.
pub fn commit_empty(git: &Path, repo: &Path, message: &str) -> GitObjectId {
    run_git(
        git,
        repo,
        &["commit", "--allow-empty", "--quiet", "-m", message],
    );
    rev_parse(git, repo, "HEAD")
}

/// A merge commit over `parents` (first parent's tree) via `commit-tree`;
/// returns its SHA.
pub fn commit_merge(
    git: &Path,
    repo: &Path,
    message: &str,
    parents: &[&GitObjectId],
) -> GitObjectId {
    let tree = git_stdout(
        git,
        repo,
        &["rev-parse", &format!("{}^{{tree}}", parents[0].as_str())],
    );
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
    GitObjectId::new(git_stdout(git, repo, &args_refs)).unwrap()
}
