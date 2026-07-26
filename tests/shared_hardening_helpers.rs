//! Source-scanning guards that keep safety-critical helpers from being
//! re-implemented alongside their canonical definition.
//!
//! These tests do something unusual — they read the workspace's own `.rs` files
//! — because the defect they prevent is not expressible against the code's
//! runtime behaviour. Two correct-looking implementations of the same discipline
//! is not a wrong answer any unit test can catch; it is a *structural* property,
//! and it only becomes a bug later, when one copy is updated and the other is
//! not.
//!
//! That is not hypothetical here. The hardened Git environment recipe was
//! written out longhand at ~8 sites; one used `GIT_CONFIG_SYSTEM=/dev/null`
//! instead of `GIT_CONFIG_NOSYSTEM=1` and omitted `GIT_CONFIG_COUNT=0`, and two
//! others omitted `GIT_CONFIG_COUNT=0` as well — each looking perfectly careful
//! in isolation. Separately, two spawn-retry loops recognised disjoint sets of
//! transient errno, so each caller was flaky under exactly the pressure the
//! other had been hardened against.
//!
//! Each test names the one file allowed to define the thing, so adding a
//! legitimate new definition is a deliberate edit here rather than an accident.

use std::path::{Path, PathBuf};

/// Every `.rs` file in the workspace, excluding build output.
fn workspace_rust_sources() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    let mut stack = vec![root.join("src"), root.join("crates"), root.join("tests")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    assert!(
        out.len() > 50,
        "source scan found only {} files; the walk is broken, so this guard \
         would pass vacuously",
        out.len()
    );
    out
}

fn relative(path: &Path) -> String {
    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// This file, which necessarily spells out every needle it searches for.
const THIS_FILE: &str = "tests/shared_hardening_helpers.rs";

/// Report every file (other than `allowed`) containing any of `needles`.
fn offenders(needles: &[&str], allowed: &[&str]) -> Vec<String> {
    let mut hits = Vec::new();
    for path in workspace_rust_sources() {
        let rel = relative(&path);
        if rel == THIS_FILE || allowed.contains(&rel.as_str()) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for needle in needles {
            if text.contains(needle) {
                hits.push(format!("{rel}: contains {needle:?}"));
            }
        }
    }
    hits.sort();
    hits
}

/// The hardened Git environment must be *applied* from
/// `writ_core::git_env`, never re-typed.
///
/// The needles match the act of setting one of the variables on a `Command`
/// (`.env("GIT_CONFIG_…"`), not merely mentioning its name — so doc comments and
/// tests that *assert* a child saw the recipe are unaffected. That distinction is
/// what keeps the guard specific enough to stay useful.
#[test]
fn only_git_env_defines_the_hardened_git_recipe() {
    let hits = offenders(
        &[
            r#".env("GIT_CONFIG_NOSYSTEM""#,
            r#".env("GIT_CONFIG_GLOBAL""#,
            r#".env("GIT_CONFIG_SYSTEM""#,
            r#".env("GIT_CONFIG_COUNT""#,
            r#"env("GIT_CONFIG_NOSYSTEM""#,
            r#"env("GIT_CONFIG_GLOBAL""#,
            r#"env("GIT_CONFIG_SYSTEM""#,
            r#"env("GIT_CONFIG_COUNT""#,
        ],
        &["crates/writ-core/src/git_env.rs"],
    );
    assert!(
        hits.is_empty(),
        "the hardened Git environment must come from `writ_core::git_env` \
         (`CLEAN_GIT_CONFIG_ENV`, `GIT_CONFIG_DENY_ENV`, or \
         `apply_clean_git_config`), not be written out again. A partial copy is \
         how `GIT_CONFIG_COUNT=0` went missing at three call sites.\n  {}",
        hits.join("\n  ")
    );
}

/// A transient spawn refusal must be classified in exactly one place.
///
/// Two loops previously split the errno set between them: `process_spawn`
/// recognised `ETXTBSY` only, and a `notes_repo`-local loop recognised the
/// resource errnos only. Both looked complete; each was blind to half the
/// problem. Any new mention of these errno outside the classifier is a third
/// copy waiting to diverge.
#[test]
fn only_process_spawn_classifies_transient_spawn_failures() {
    let hits = offenders(
        &[
            "libc::ETXTBSY",
            "libc::EAGAIN",
            "libc::EMFILE",
            "libc::ENFILE",
        ],
        &["crates/writ-core/src/process_spawn.rs"],
    );
    assert!(
        hits.is_empty(),
        "transient spawn-refusal errno belong only to \
         `writ_core::process_spawn`; spawn children through `spawn`, \
         `spawn_async`, or `output` rather than adding another retry loop.\n  {}",
        hits.join("\n  ")
    );
}

/// Running a child with a timeout and a process-group kill must go through
/// `process_supervisor`.
///
/// The needle is the syscall (`libc::killpg`), not the word, so prose that
/// *explains* the group-kill ordering is unaffected — only a second
/// implementation of it trips this.
///
/// A `killpg` outside the supervisor means a second, parallel supervision
/// discipline. `git_push_objects_cat_file` had exactly that: its own cleanup
/// guard, its own `ESRCH`/`EPERM` tolerance, and its own `waitid(WNOWAIT)` probe,
/// ~75 lines duplicating the supervisor's. It legitimately cannot use
/// `run_supervised` (its `cat-file --batch` child is a long-lived session, not a
/// spawn-and-wait), but it can and now does share the primitives.
#[test]
fn only_process_supervisor_kills_process_groups() {
    let hits = offenders(&["libc::killpg"], &["src/process_supervisor.rs"]);
    assert!(
        hits.is_empty(),
        "process-group signalling belongs to `process_supervisor`; use \
         `run_supervised` or `run_supervised_blocking`.\n  {}",
        hits.join("\n  ")
    );
}
