//! Shared test fixtures for flake provisioning.
//!
//! Two things every provisioning test needs and neither layer owns: a real bare
//! git mirror of a repository with a committed flake (the `(repo, rev)` entry a
//! clone would have retained), and a *fake* `nix` whose behaviour the test
//! chooses. The fake is what makes the audited paths testable without nix on
//! PATH: the endpoint's success and failure outcomes are then exercised in
//! every CI run rather than only where a nix daemon exists. The real-`nix`
//! tests still exist alongside them (skipped when nix is absent).
//!
//! Used by the host core ([`crate::flake_provision`]), the mirror orchestrator
//! ([`crate::flake_provision_from_mirror`]), and the VM-HTTP endpoint tests.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::vm_git_mirror_cache::GitCommitSha;
use writ_core::git_env::apply_clean_git_config;

/// A `flake.lock` declaring no inputs — the only network-free provisionable
/// fixture, since the classifier (correctly) refuses local `path`/`file://`
/// inputs. `nix flake archive` still copies the flake's own source path.
pub(crate) const NO_INPUT_LOCK: &str = r#"{"nodes":{"root":{}},"root":"root","version":7}"#;

/// A `flake.lock` the classifier refuses: an `ssh` input requires credentials.
pub(crate) const SSH_INPUT_LOCK: &str = r#"{
    "version": 7,
    "root": "root",
    "nodes": {
        "root": { "inputs": { "dep": "dep" } },
        "dep": {
            "locked": {
                "type": "git",
                "url": "git+ssh://git@example.com/acme/secret",
                "rev": "1111111111111111111111111111111111111111",
                "narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            }
        }
    }
}"#;

/// Locate `name` on PATH. Returns `None` so a test can skip on a machine
/// without the tool; CI has both `git` and `nix`.
pub(crate) fn tool_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Render a failed fixture `git` invocation with everything needed to
/// diagnose it from a CI log alone.
///
/// This exists because it once wasn't there. A nix-sandbox CI run failed
/// with `git ["clone", "-q", "--mirror", ...] failed` and nothing else:
/// the helpers ran git with `stderr(Stdio::null())`, so the one place
/// git explains itself was discarded before anyone could read it. An
/// intermittent failure that cannot be diagnosed after the fact is one
/// that has to be reproduced to be understood, and a rare one may never
/// be. Exit status, stderr, and the working directory are cheap to keep
/// and are the whole diagnosis.
///
/// `stdout` is included too: `git` writes some errors there, and a
/// fixture command that succeeds prints nothing, so this costs no noise
/// on the happy path.
pub(crate) fn git_failure(args: &[&str], cwd: &Path, out: &std::process::Output) -> String {
    format!(
        "git {args:?} in {} failed: {}\n--- stderr ---\n{}\n--- stdout ---\n{}",
        cwd.display(),
        out.status,
        String::from_utf8_lossy(&out.stderr).trim(),
        String::from_utf8_lossy(&out.stdout).trim(),
    )
}

/// `-c` flags that stop git spawning a *detached background process* over
/// the fixture repository.
///
/// This is not tidiness. `git commit` runs
/// `git maintenance run --auto --quiet --detach`, which keeps writing to
/// `objects/` after `git commit` has exited and returned to the caller.
/// A fixture that commits and then immediately clones is therefore
/// racing a writer it never asked for, and lost that race in CI:
///
/// ```text
/// fatal: failed to copy file to '…/mirror.git/objects/pack/
///        .tmp-23252-pack-ca4771….idx': No such file or directory
/// ```
///
/// `clone_local` copies the source object store by walking it, so it
/// enumerated `objects/pack/`, saw maintenance's transient
/// `.tmp-<pid>-pack-*` file, and by the time it opened that file
/// maintenance had renamed it away. (git reports the errno against the
/// *destination* path, which is why the message reads as though the
/// destination directory were missing.) The pid in the name belongs to
/// neither the test nor its clone: it is the detached child.
///
/// So the fix is to remove the second writer rather than to retry around
/// it. Verified directly: with `maintenance.auto=false`, `GIT_TRACE`
/// shows zero `maintenance run --auto` spawns where an unconfigured
/// commit shows three. `gc.auto=0` covers the older direct-gc path.
///
/// Deliberately *not* added to `apply_clean_git_config`: that recipe is
/// production code's, and whether writd wants background maintenance
/// suppressed on the repositories it manages is a real operational
/// decision (repacking has to happen sometime) rather than a test-harness
/// one. Tracked separately.
const NO_AUTO_MAINTENANCE: [&str; 4] = ["-c", "maintenance.auto=false", "-c", "gc.auto=0"];

/// A fixture `git` command: the hardened config recipe, plus no detached
/// background maintenance.
fn fixture_git_command(program: &Path, args: &[&str], cwd: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    apply_clean_git_config(&mut command)
        .args(NO_AUTO_MAINTENANCE)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null());
    command
}

pub(crate) fn git(program: &Path, args: &[&str], cwd: &Path) {
    let out = fixture_git_command(program, args, cwd)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@e")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@e")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", git_failure(args, cwd, &out));
}

pub(crate) fn git_stdout(program: &Path, args: &[&str], cwd: &Path) -> String {
    let out = fixture_git_command(program, args, cwd).output().unwrap();
    assert!(out.status.success(), "{}", git_failure(args, cwd, &out));
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// Build a bare mirror of a repository whose committed `flake.lock` is `lock`.
/// Returns `(bare_mirror_dir, rev)` — exactly what the clone handler retains
/// under a [`MirrorCacheKey`](crate::vm_git_mirror_cache::MirrorCacheKey).
pub(crate) fn flake_mirror_with_lock(
    git_program: &Path,
    root: &Path,
    lock: &str,
) -> (PathBuf, GitCommitSha) {
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(git_program, &["init", "-q", "-b", "main"], &repo);
    std::fs::write(
        repo.join("flake.nix"),
        "{\n  description = \"fixture\";\n  outputs = { self }: { ok = true; };\n}\n",
    )
    .unwrap();
    std::fs::write(repo.join("flake.lock"), lock).unwrap();
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

/// [`flake_mirror_with_lock`] with the no-input lock.
pub(crate) fn no_input_flake_mirror(git_program: &Path, root: &Path) -> (PathBuf, GitCommitSha) {
    flake_mirror_with_lock(git_program, root, NO_INPUT_LOCK)
}

/// Write an executable `nix` shim under `root` and return its absolute path.
fn write_fake_nix(root: &Path, script: &str) -> PathBuf {
    let bin = root.join("fake-nix-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let program = bin.join("nix");
    std::fs::write(&program, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    program
}

/// A fake `nix` that "archives": it finds the `--to file://…` staging URL the
/// plan passes and writes one narinfo plus its NAR there, then exits 0. Enough
/// for the real scan, budget check, and cache merge to run — so the success
/// path, and the audit outcome it produces, are exercised without nix.
pub(crate) fn fake_nix_archiving(root: &Path) -> PathBuf {
    write_fake_nix(
        root,
        r#"#!/bin/sh
to=
prev=
for arg in "$@"; do
    if [ "$prev" = "--to" ]; then to=$arg; fi
    prev=$arg
done
[ -n "$to" ] || exit 64
dir=${to#file://}
mkdir -p "$dir/nar" || exit 65
printf 'fixture-nar-bytes\n' > "$dir/nar/fixture.nar" || exit 66
printf 'StorePath: /nix/store/00000000000000000000000000000000-fixture\nURL: nar/fixture.nar\nNarHash: sha256-0000\n' \
    > "$dir/00000000000000000000000000000000.narinfo" || exit 67
"#,
    )
}

/// A fake `nix` that exits with `code` without writing anything — the audited
/// failure path (`nix flake archive exited with …`).
pub(crate) fn fake_nix_failing(root: &Path, code: u8) -> PathBuf {
    write_fake_nix(root, &format!("#!/bin/sh\nexit {code}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture commit spawns no detached background maintenance.
    ///
    /// This is the flake's cause, pinned. `git commit` normally runs
    /// `git maintenance run --auto --quiet --detach`, which outlives the
    /// commit and keeps writing to `objects/`; the very next fixture step
    /// clones that repository, and `clone_local` walks the object store
    /// while it is being written. In CI that walk reached maintenance's
    /// transient `.tmp-<pid>-pack-*.idx` after it had been renamed away,
    /// and died with ENOENT.
    ///
    /// Asserted through `GIT_TRACE`, because what has to be proved is a
    /// *negative about process spawning* — that nothing was launched.
    /// The absence of a background writer cannot be observed by
    /// inspecting the repository afterwards: not losing the race is
    /// exactly what already happened almost every time.
    #[test]
    fn a_fixture_commit_leaves_no_background_writer_behind() {
        let Some(git_program) = tool_on_path("git") else {
            eprintln!("skipping: git must be on PATH");
            return;
        };
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&git_program, &["init", "-q", "-b", "main"], &repo);
        std::fs::write(repo.join("f"), "x").unwrap();
        git(&git_program, &["add", "."], &repo);

        let out = fixture_git_command(&git_program, &["commit", "-qm", "m"], &repo)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e")
            .env("GIT_TRACE", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            git_failure(&["commit"], &repo, &out),
        );

        // GIT_TRACE goes to stderr. An unconfigured commit shows several
        // `maintenance run --auto` lines here.
        let trace = String::from_utf8_lossy(&out.stderr);
        assert!(
            !trace.contains("maintenance run --auto"),
            "fixture commit spawned background maintenance:\n{trace}",
        );
        assert!(
            !trace.contains("gc --auto"),
            "fixture commit spawned background gc:\n{trace}",
        );
    }

    /// A failing fixture `git` reports git's own explanation.
    ///
    /// The regression this pins is a silent one: the helpers used to run
    /// git with `stderr(Stdio::null())` and assert `"git {args:?}
    /// failed"`, so a CI failure carried the command and nothing about
    /// why it failed. Asserting on a *real* failing invocation rather
    /// than a synthesised `Output` is the point — it is the plumbing
    /// (that stderr is captured at all) that broke, not the formatting.
    #[test]
    fn a_failed_fixture_git_reports_gits_own_stderr() {
        let Some(git_program) = tool_on_path("git") else {
            eprintln!("skipping: git must be on PATH");
            return;
        };
        let temp = tempfile::tempdir().unwrap();
        let args = ["clone", "-q", "--mirror", "definitely-not-a-repo", "dest"];

        // Drive the helper itself, not a hand-built `Output`: what broke
        // was the plumbing (stderr was routed to `Stdio::null()` before
        // anything could read it), so a test that formats its own
        // `Output` would still pass with the bug present. The panic
        // message printed by the default hook during this is expected.
        let panic = std::panic::catch_unwind(|| git(&git_program, &args, temp.path()))
            .expect_err("cloning a nonexistent repository must fail");
        let rendered = panic
            .downcast_ref::<String>()
            .expect("assert! panics with a formatted String")
            .clone();
        assert!(
            rendered.contains("definitely-not-a-repo"),
            "must name the command: {rendered}",
        );
        assert!(
            rendered.contains(temp.path().to_str().unwrap()),
            "must name the working directory: {rendered}",
        );
        // git's own words. Without this the message is a tautology: the
        // command failed, which we already knew from the assertion.
        assert!(
            rendered.to_lowercase().contains("repository")
                || rendered.to_lowercase().contains("does not exist"),
            "must carry git's stderr: {rendered}",
        );
    }
}
