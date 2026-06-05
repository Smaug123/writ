//! Materialise a working tree of a flake from a retained bare mirror.
//!
//! Flake-input provisioning runs `nix flake archive` against a *directory*
//! containing the repo's `flake.nix` and committed `flake.lock`. The broker
//! retains each clone as a bare mirror (see [`crate::vm_git_mirror_cache`]), so
//! to provision we first check the relevant commit out of that mirror into a
//! throwaway working tree.
//!
//! A `git worktree` linked to the mirror gives that tree without re-cloning and
//! without copying the object store. The materialised tree is independent of
//! the mirror's lifetime once checked out, so a later eviction of the mirror
//! cannot pull the floor out from under an in-flight provision (the
//! eviction-vs-reader hazard a bare path handout would have).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use crate::clean_git::{CleanGitInvocation, clean_git_config_env, run_clean_git};
use crate::vm_git_mirror_cache::GitCommitSha;

#[derive(Debug, thiserror::Error)]
pub enum MaterializeError {
    #[error("could not create flake worktree scratch dir {path:?}: {source}")]
    Scratch {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("git worktree add failed: {0}")]
    WorktreeAdd(String),
}

/// A checked-out working tree of a flake, linked to the bare mirror it came
/// from. Dropping it detaches the worktree from the mirror and removes the
/// checked-out files (best-effort), so a provision that returns early or panics
/// still cleans up.
#[derive(Debug)]
pub struct MaterializedFlake {
    git_program: PathBuf,
    mirror_dir: PathBuf,
    path: PathBuf,
}

impl MaterializedFlake {
    /// The directory holding the checked-out flake (its `flake.nix` /
    /// `flake.lock`), ready to hand to `nix flake archive`.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for MaterializedFlake {
    fn drop(&mut self) {
        // Best-effort teardown, synchronous because Drop cannot await. Detach
        // the worktree from the mirror (which also removes its files), then make
        // sure the directory is gone. A leftover worktree registration is
        // reclaimed by a later `git worktree prune`; the files live under the
        // broker's scratch root. Errors are deliberately ignored — cleanup must
        // not panic during unwinding, and the inputs (our own paths) are
        // trusted, so the hardened `clean_git` path is unnecessary here.
        let mut git_dir_arg = OsString::from("--git-dir=");
        git_dir_arg.push(self.mirror_dir.as_os_str());
        let _ = std::process::Command::new(&self.git_program)
            .arg(&git_dir_arg)
            .args(["worktree", "remove", "--force"])
            .arg(&self.path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Check `rev` out of the bare mirror at `mirror_dir` into a fresh worktree
/// under `scratch_root`, returning a guard that cleans the worktree up when
/// dropped. `scratch_root` must already exist; the worktree directory itself is
/// created by `git` and must not pre-exist (a unique name guarantees that).
pub async fn materialize_flake_tree(
    git_program: &Path,
    mirror_dir: &Path,
    rev: &GitCommitSha,
    scratch_root: &Path,
    worktree_name: &str,
    timeout: Duration,
) -> Result<MaterializedFlake, MaterializeError> {
    if let Err(source) = std::fs::create_dir_all(scratch_root) {
        return Err(MaterializeError::Scratch {
            path: scratch_root.to_path_buf(),
            source,
        });
    }
    let worktree = scratch_root.join(worktree_name);

    let mut git_dir_arg = OsString::from("--git-dir=");
    git_dir_arg.push(mirror_dir.as_os_str());
    let invocation = CleanGitInvocation::new(
        git_program.to_path_buf(),
        vec![
            git_dir_arg,
            OsString::from("worktree"),
            OsString::from("add"),
            OsString::from("--detach"),
            worktree.as_os_str().to_os_string(),
            OsString::from(rev.as_str()),
        ],
        clean_git_config_env(),
        Vec::new(),
    );
    run_clean_git(&invocation, timeout, None)
        .await
        .map_err(|err| MaterializeError::WorktreeAdd(err.to_string()))?;

    Ok(MaterializedFlake {
        git_program: git_program.to_path_buf(),
        mirror_dir: mirror_dir.to_path_buf(),
        path: worktree,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_on_path() -> PathBuf {
        let path = std::env::var_os("PATH").expect("PATH must be set for git tests");
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("git");
            if candidate.is_file() {
                return candidate;
            }
        }
        panic!("git must be on PATH for flake_materialize tests");
    }

    /// Run a git command to completion, asserting success, for test fixtures.
    fn git(program: &Path, args: &[&str], cwd: &Path) {
        let status = std::process::Command::new(program)
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn git_stdout(program: &Path, args: &[&str], cwd: &Path) -> String {
        let out = std::process::Command::new(program)
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?} failed");
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    /// Build a bare mirror of a repo carrying a flake at a known commit, and
    /// return `(mirror_dir, rev)`.
    fn fixture_mirror(git_program: &Path, root: &Path) -> (PathBuf, GitCommitSha) {
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(git_program, &["init", "-q", "-b", "main"], &repo);
        std::fs::write(repo.join("flake.nix"), b"{ outputs = _: {}; }").unwrap();
        std::fs::write(repo.join("flake.lock"), b"{\"version\":7}").unwrap();
        git(git_program, &["add", "."], &repo);
        git(git_program, &["commit", "-qm", "flake"], &repo);
        let rev = GitCommitSha::parse(&git_stdout(git_program, &["rev-parse", "HEAD"], &repo))
            .expect("rev-parse must yield a commit hash");

        let mirror = root.join("mirror.git");
        git(
            git_program,
            &[
                "clone",
                "-q",
                "--mirror",
                repo.to_str().unwrap(),
                mirror.to_str().unwrap(),
            ],
            root,
        );
        (mirror, rev)
    }

    #[tokio::test]
    async fn materialize_checks_out_the_flake_then_cleans_up_on_drop() {
        let git_program = git_on_path();
        let tmp = tempfile::tempdir().unwrap();
        let (mirror, rev) = fixture_mirror(&git_program, tmp.path());
        let scratch = tmp.path().join("scratch");

        let worktree_path = {
            let materialized = materialize_flake_tree(
                &git_program,
                &mirror,
                &rev,
                &scratch,
                "flake-wt",
                Duration::from_secs(30),
            )
            .await
            .unwrap();

            // The committed flake is present and readable as a plain directory.
            assert_eq!(
                std::fs::read(materialized.path().join("flake.nix")).unwrap(),
                b"{ outputs = _: {}; }"
            );
            assert_eq!(
                std::fs::read(materialized.path().join("flake.lock")).unwrap(),
                b"{\"version\":7}"
            );
            materialized.path().to_path_buf()
        };

        // Dropping the guard removed the checked-out tree.
        assert!(
            !worktree_path.exists(),
            "the worktree should be cleaned up on drop"
        );
    }

    #[tokio::test]
    async fn materialize_fails_for_an_unknown_rev() {
        let git_program = git_on_path();
        let tmp = tempfile::tempdir().unwrap();
        let (mirror, _rev) = fixture_mirror(&git_program, tmp.path());
        let scratch = tmp.path().join("scratch");
        let missing = GitCommitSha::parse(&"a".repeat(40)).unwrap();

        let result = materialize_flake_tree(
            &git_program,
            &mirror,
            &missing,
            &scratch,
            "flake-wt",
            Duration::from_secs(30),
        )
        .await;

        assert!(matches!(result, Err(MaterializeError::WorktreeAdd(_))));
    }
}
