//! Test scaffolding every crate's tests may need and none should re-type:
//! finding a tool on `PATH`, quoting for a shell script, and writing the
//! executable stand-ins tests put on `PATH` in place of `git`, `container`
//! and friends. Compiled only under `cfg(test)` or the `test-support`
//! feature, which downstream crates enable as a dev-dependency; nothing here
//! reaches a production build. The root crate's `test_support` re-exports it.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The first executable regular file named `name` on the test runner's `PATH`,
/// or `None` so a test can skip when the tool is absent (CI has every tool the
/// suite uses; a developer machine may not).
///
/// The returned path is the caller-visible spelling, never canonicalised: the
/// basename must survive into `argv[0]` after `execve`, because on Nix
/// coreutils is a multi-call binary dispatched by `basename(argv[0])` and bash
/// changes behaviour when invoked through its `sh` symlink. Relative `PATH`
/// entries are resolved against the current directory so the result is usable
/// from any working directory the test later switches to.
pub fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = if dir.is_absolute() {
            dir.join(name)
        } else {
            std::env::current_dir().ok()?.join(dir).join(name)
        };
        let meta = std::fs::metadata(&candidate).ok()?;
        (meta.is_file() && meta.permissions().mode() & 0o111 != 0).then_some(candidate)
    })
}

/// [`find_in_path`] for a tool the test cannot do without.
pub fn required_tool(name: &str) -> PathBuf {
    find_in_path(name).unwrap_or_else(|| {
        panic!(
            "required test tool `{name}` not found on PATH ({:?})",
            std::env::var_os("PATH").unwrap_or_default()
        )
    })
}

/// The first of `names` that [`find_in_path`] resolves. For tools with more
/// than one spelling, such as a shell that is `bash` on a Nix stdenv and `sh`
/// elsewhere.
pub fn required_tool_any(names: &[&str]) -> PathBuf {
    names
        .iter()
        .find_map(|name| find_in_path(name))
        .unwrap_or_else(|| {
            panic!(
                "none of {names:?} found on PATH ({:?})",
                std::env::var_os("PATH").unwrap_or_default()
            )
        })
}

/// `value` as a single-quoted POSIX shell word: safe to splice into a script
/// body whatever it contains.
pub fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// [`shell_single_quote`] over a path's display form.
pub fn shell_quote_path(path: &Path) -> String {
    shell_single_quote(&path.display().to_string())
}

/// Write `body` to `dir/name` and make it executable (mode `0o755`). The
/// usual way a test stands in a shell script for `git`, `container`, `pfctl`
/// or another tool the code under test would otherwise spawn.
pub fn write_executable_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write test script");
    let mut perms = std::fs::metadata(&path)
        .expect("stat test script")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod test script");
    path
}
