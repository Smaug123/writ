//! Materialise a standalone working tree of a flake from a retained bare mirror.
//!
//! Flake-input provisioning runs `nix flake archive` against a *directory*
//! containing the repo's `flake.nix` and committed `flake.lock`. The broker
//! retains each clone as a bare mirror (see [`crate::vm_git_mirror_cache`]), so
//! to provision we check the relevant commit out of that mirror into a
//! throwaway working tree.
//!
//! The tree is produced with a **local clone** (`git clone --local`), not a
//! linked `git worktree`. A linked worktree's `.git` points back into the
//! mirror's object store, so `nix flake archive` (which opens the directory as
//! a Git repo) would break if the mirror were evicted mid-provision. A local
//! clone instead hardlinks the object store (or copies it, cross-filesystem)
//! into a self-contained repository, so the materialised tree is independent of
//! the mirror's lifetime — dissolving the eviction-vs-reader hazard a bare path
//! handout (or a linked worktree) would have had, without needing a pin.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::clean_git::{CleanGitInvocation, clean_git_config_env, run_clean_git};
use crate::vm_git_mirror_cache::GitCommitSha;

#[derive(Debug, thiserror::Error)]
pub enum MaterializeError {
    #[error("{which} path must be absolute: {path:?}")]
    RelativePath { which: &'static str, path: PathBuf },
    #[error("could not create flake materialisation scratch dir {path:?}: {source}")]
    Scratch {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("git clone --local of the mirror failed: {0}")]
    Clone(String),
    #[error("git checkout of {rev} failed: {message}")]
    Checkout { rev: String, message: String },
}

/// A standalone checkout of a flake, cloned from the bare mirror it came from.
/// Dropping it removes the checked-out repository (best-effort), so a provision
/// that returns early or panics still cleans up. Because it is a full local
/// clone, it has no back-reference into the mirror and stays usable even if the
/// mirror is removed.
#[derive(Debug)]
pub struct MaterializedFlake {
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
        // Best-effort: a local clone registers nothing in the mirror, so
        // removing the directory is the whole teardown. Errors are ignored so
        // cleanup never panics during unwinding.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Clone `rev` out of the bare mirror at `mirror_dir` into a fresh standalone
/// repository under `scratch_root`, returning a guard that removes it when
/// dropped. The destination directory is allocated internally (so it always
/// lives under `scratch_root`); `scratch_root` is created owner-only because
/// the checkout holds possibly-private repository content.
pub async fn materialize_flake_tree(
    git_program: &Path,
    mirror_dir: &Path,
    rev: &GitCommitSha,
    scratch_root: &Path,
    timeout: Duration,
) -> Result<MaterializedFlake, MaterializeError> {
    // `run_clean_git` runs git from a fixed root cwd, so every path in the argv
    // must be absolute or it would resolve differently from the Rust-side
    // create/chmod/remove (leaking a private checkout, or removing the wrong
    // directory on drop). The broker always passes absolute paths; fail loud
    // otherwise.
    for (which, path) in [("mirror_dir", mirror_dir), ("scratch_root", scratch_root)] {
        if !path.is_absolute() {
            return Err(MaterializeError::RelativePath {
                which,
                path: path.to_path_buf(),
            });
        }
    }
    create_private_dir_all(scratch_root).map_err(|source| MaterializeError::Scratch {
        path: scratch_root.to_path_buf(),
        source,
    })?;
    // Allocate the destination ourselves so it cannot escape `scratch_root`.
    let dest = scratch_root.join(format!("flake-{}", uuid::Uuid::new_v4().simple()));

    // A `--local` clone hardlinks (or, cross-filesystem, copies) the mirror's
    // object store into a self-contained repo. `--no-checkout` skips the
    // default-branch checkout; the explicit detached checkout below puts the
    // requested commit's tree on disk.
    let clone = CleanGitInvocation::new(
        git_program.to_path_buf(),
        vec![
            OsString::from("clone"),
            OsString::from("--local"),
            OsString::from("--no-checkout"),
            OsString::from("--quiet"),
            OsString::from("--"),
            mirror_dir.as_os_str().to_os_string(),
            dest.as_os_str().to_os_string(),
        ],
        clean_git_config_env(),
        Vec::new(),
    );
    if let Err(err) = run_clean_git(&clone, timeout, None).await {
        let _ = std::fs::remove_dir_all(&dest);
        return Err(MaterializeError::Clone(err.to_string()));
    }

    let checkout = CleanGitInvocation::new(
        git_program.to_path_buf(),
        vec![
            OsString::from("-C"),
            dest.as_os_str().to_os_string(),
            OsString::from("checkout"),
            OsString::from("--detach"),
            OsString::from(rev.as_str()),
        ],
        clean_git_config_env(),
        Vec::new(),
    );
    if let Err(err) = run_clean_git(&checkout, timeout, None).await {
        let _ = std::fs::remove_dir_all(&dest);
        return Err(MaterializeError::Checkout {
            rev: rev.as_str().to_string(),
            message: err.to_string(),
        });
    }

    Ok(MaterializedFlake { path: dest })
}

/// Create a directory tree restricted to the owner; the checkout holds
/// possibly-private repository content, so other local users must not be able
/// to traverse into the scratch root. The explicit `set_permissions` defeats
/// the process umask.
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(test)]
mod tests {
    use std::process::Stdio;

    use super::*;
    use writ_core::git_env::apply_clean_git_config;

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

    use crate::flake_fixtures::git_failure;

    fn git(program: &Path, args: &[&str], cwd: &Path) {
        let out = apply_clean_git_config(&mut std::process::Command::new(program))
            .args(args)
            .current_dir(cwd)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", git_failure(args, cwd, &out));
    }

    fn git_stdout(program: &Path, args: &[&str], cwd: &Path) -> String {
        let out = apply_clean_git_config(&mut std::process::Command::new(program))
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", git_failure(args, cwd, &out));
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
                Duration::from_secs(30),
            )
            .await
            .unwrap();

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

        assert!(
            !worktree_path.exists(),
            "the checkout should be cleaned up on drop"
        );
    }

    #[tokio::test]
    async fn materialized_tree_survives_mirror_deletion() {
        let git_program = git_on_path();
        let tmp = tempfile::tempdir().unwrap();
        let (mirror, rev) = fixture_mirror(&git_program, tmp.path());
        let scratch = tmp.path().join("scratch");
        let materialized = materialize_flake_tree(
            &git_program,
            &mirror,
            &rev,
            &scratch,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        // Remove the source mirror entirely: a self-contained clone must keep
        // working, which is what nix flake archive needs.
        std::fs::remove_dir_all(&mirror).unwrap();

        assert_eq!(
            std::fs::read(materialized.path().join("flake.nix")).unwrap(),
            b"{ outputs = _: {}; }"
        );
        let head = git_stdout(
            &git_program,
            &[
                "-C",
                materialized.path().to_str().unwrap(),
                "rev-parse",
                "HEAD",
            ],
            tmp.path(),
        );
        assert_eq!(
            head,
            rev.as_str(),
            "the clone resolves the commit on its own"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn materialize_creates_an_owner_only_scratch_root() {
        use std::os::unix::fs::PermissionsExt;
        let git_program = git_on_path();
        let tmp = tempfile::tempdir().unwrap();
        let (mirror, rev) = fixture_mirror(&git_program, tmp.path());
        let scratch = tmp.path().join("nested/scratch");

        let _materialized = materialize_flake_tree(
            &git_program,
            &mirror,
            &rev,
            &scratch,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        let mode = std::fs::metadata(&scratch).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "scratch root must be owner-only");
    }

    #[tokio::test]
    async fn materialize_rejects_a_relative_scratch_root() {
        let git_program = git_on_path();
        let tmp = tempfile::tempdir().unwrap();
        let (mirror, rev) = fixture_mirror(&git_program, tmp.path());

        let result = materialize_flake_tree(
            &git_program,
            &mirror,
            &rev,
            Path::new("relative/scratch"),
            Duration::from_secs(30),
        )
        .await;

        assert!(matches!(
            result,
            Err(MaterializeError::RelativePath {
                which: "scratch_root",
                ..
            })
        ));
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
            Duration::from_secs(30),
        )
        .await;

        assert!(matches!(result, Err(MaterializeError::Checkout { .. })));
    }
}
