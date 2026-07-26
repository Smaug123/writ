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

/// The hardened Git environment must be *applied* from `writ_core::git_env`,
/// never re-typed.
///
/// The needles are the bare variable names, deliberately **not** tied to a
/// particular setter spelling. An earlier version of this guard matched only
/// `.env("GIT_CONFIG_…"`, which missed `.envs([("GIT_CONFIG_NOSYSTEM", "1"), …])`
/// — i.e. exactly the style the migrated call sites were rewritten into. A guard
/// blind to the codebase's own idiom is worse than none, because it reads as
/// coverage.
///
/// The cost of matching bare names is that files legitimately *asserting* a child
/// saw the recipe also match, so they are allowlisted individually below. That is
/// the intended trade: adding a name to this list is a deliberate, reviewable act,
/// whereas a new file quietly constructing the recipe is not.
#[test]
fn only_git_env_defines_the_hardened_git_recipe() {
    let hits = offenders(
        // Every entry of the recipe, plus `GIT_CONFIG_SYSTEM` (the divergent
        // spelling that started this) and `GIT_CONFIG` (the `--file` override).
        &[
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
            // Quoted, so this matches only the standalone `GIT_CONFIG` name and
            // not the five suffixed ones above (every one of which starts with
            // it). The comment above used to claim this was covered when it was
            // not — an unquoted needle would have matched everything and been
            // silently useless.
            "\"GIT_CONFIG\"",
        ],
        &[
            "crates/writ-core/src/git_env.rs",
            // Assert on the recipe rather than defining it: they check that a
            // spawned child actually saw the hardened values.
            "src/clean_git.rs",
            "src/notes_repo/tests.rs",
            "src/git_push_approve/tests.rs",
            "src/git_push_walker/branch_creation_plan_tests.rs",
            "src/vm_git_bundle.rs",
        ],
    );
    assert!(
        hits.is_empty(),
        "the hardened Git environment must come from `writ_core::git_env` — call \
         `apply_clean_git_config` (or `apply_git_config_denials`), not the raw \
         constants and not a hand-written copy. Note the recipe includes a \
         *removal* (`GIT_CONFIG`) that a name/value list cannot express, so \
         `.envs(CLEAN_GIT_CONFIG_ENV)` is itself incomplete.\n  {}",
        hits.join("\n  ")
    );
}

/// The recipe constants must not be applied directly outside `git_env`.
///
/// Separate from the test above because it catches a *correct-looking* misuse
/// rather than a re-typing: `.envs(CLEAN_GIT_CONFIG_ENV)` sets every value in the
/// recipe and still leaves `GIT_CONFIG` inherited, because a removal cannot be a
/// `(name, value)` pair. The constants remain public for assertions and for
/// callers composing their own env; applying them is what must go through the
/// helper.
#[test]
fn the_recipe_constants_are_not_applied_outside_git_env() {
    let hits = offenders(
        &[
            ".envs(writ_core::git_env::CLEAN_GIT_CONFIG_ENV)",
            ".envs(CLEAN_GIT_CONFIG_ENV)",
            ".envs(writ_core::git_env::GIT_CONFIG_DENY_ENV)",
            ".envs(GIT_CONFIG_DENY_ENV)",
        ],
        &["crates/writ-core/src/git_env.rs"],
    );
    assert!(
        hits.is_empty(),
        "apply the recipe with `apply_clean_git_config` / \
         `apply_git_config_denials`; `.envs(...)` alone silently omits the \
         `GIT_CONFIG` removal.\n  {}",
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
            "libc::ENOMEM",
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

/// `env_clear` must not follow the recipe in the same statement.
///
/// `Command::env_clear` wipes entries already set, so
/// `apply_clean_git_config(cmd).env_clear()` silently discards the whole recipe
/// and leaves the child running against the host's Git configuration. The call
/// site reads as hardened; it is not.
///
/// This is not hypothetical: mechanically wrapping six builder chains with the
/// applier put `env_clear()` after it at every one of them, and no behavioural
/// test noticed — the fixtures still passed, just unhardened. Ordering is
/// invisible to a needle scan, so it gets its own check.
#[test]
fn env_clear_never_follows_the_hardening_recipe() {
    const APPLIERS: &[&str] = &[
        "apply_clean_git_config(",
        "apply_clean_git_config_async(",
        "apply_git_config_denials(",
        "apply_git_config_denials_async(",
    ];
    let mut hits = Vec::new();
    for path in workspace_rust_sources() {
        let rel = relative(&path);
        if rel == THIS_FILE {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for applier in APPLIERS {
            let mut from = 0;
            while let Some(found) = text[from..].find(applier) {
                let at = from + found;
                from = at + applier.len();
                // The statement this call sits in.
                let stmt_end = text[at..].find(';').map_or(text.len(), |e| at + e);
                let stmt = &text[at..stmt_end];
                // Walk to the matching close paren of the applier call; anything
                // after it is chained onto the *result*, so an `env_clear` there
                // erases what the applier just set. An `env_clear` *inside* the
                // parens runs first and is correct.
                let mut depth = 0usize;
                let mut close = None;
                for (offset, ch) in stmt.char_indices() {
                    match ch {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                close = Some(offset);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let Some(close) = close else { continue };
                if stmt[close..].contains("env_clear") {
                    hits.push(format!(
                        "{rel}: `env_clear` is chained after {applier}…), which wipes the recipe"
                    ));
                }
            }
        }
    }
    hits.sort();
    hits.dedup();
    assert!(
        hits.is_empty(),
        "clear the environment *first*, then apply the recipe — \
         `apply_clean_git_config(Command::new(git).env_clear())`, not \
         `apply_clean_git_config(&mut Command::new(git)).env_clear()`.\n  {}",
        hits.join("\n  ")
    );
}
