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

pub(crate) fn git(program: &Path, args: &[&str], cwd: &Path) {
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
