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

/// The source with whole-line comments removed, so a needle scan sees code.
///
/// Every guard here forbids *doing* something, never *describing* it, and the
/// two are indistinguishable to a substring scan. Left unfiltered, the recipe
/// guard forbids documentation from naming `gc.auto` at all — which is a bad
/// trade, because the fix an author reaches for is either vaguer prose or a
/// whole-file allowlist entry, and the second silently exempts that file's real
/// code forever after.
///
/// The `killpg` guard already gets this right by keying on the syscall rather
/// than the word; this is the same idea for needles that have no such spelling.
/// Only lines whose first non-whitespace is `//` are dropped, which covers
/// `//`, `///`, and `//!`. A trailing comment after code on the same line is
/// kept: preferring a rare false positive to a class of false negative.
fn code_only(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

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
        let text = code_only(&text);
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
            // The numbered channel is part of the recipe now — it is how the
            // clean recipe imposes `maintenance.auto=false` / `gc.auto=0`. A
            // second definition of it is worse than a second copy of a denial:
            // whoever writes it must also get `GIT_CONFIG_COUNT` right, and a
            // count that disagrees with the pairs either drops a setting
            // silently or brings an inherited slot into range.
            "GIT_CONFIG_KEY_",
            "GIT_CONFIG_VALUE_",
            // And the settings themselves, in either spelling, so a caller
            // cannot re-impose them per-command with `-c`. That is where they
            // started life (the flake fixtures), and it is how they would drift
            // back out of the shared recipe.
            "maintenance.auto",
            "gc.auto",
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
/// The needles are the syscalls, not the words, so prose that *explains* the
/// group-kill ordering is unaffected — only a second implementation of it trips
/// this.
///
/// A group kill outside the shared primitive means a second, parallel
/// supervision discipline. `git_push_objects_cat_file` had exactly that: its own
/// cleanup guard, its own `ESRCH`/`EPERM` tolerance, and its own
/// `waitid(WNOWAIT)` probe, ~75 lines duplicating the supervisor's. It
/// legitimately cannot use `run_supervised` (its `cat-file --batch` child is a
/// long-lived session, not a spawn-and-wait), but it can and now does share the
/// primitives.
///
/// **`libc::kill(-` is a needle because the first version of this guard missed
/// it.** `kill` with a negated pid is `killpg` spelled differently — same
/// syscall, same semantics — and the agent-run deadline was written that way and
/// sailed past a guard that only knew one spelling. A guard blind to an
/// equivalent spelling reads as coverage while providing none.
///
/// The allowlist is `writ-core`'s module rather than `process_supervisor`
/// because the primitive moved there: `writ-agent-run` needs it too, and it
/// cannot depend on the root crate.
#[test]
fn only_process_supervisor_kills_process_groups() {
    let hits = offenders(
        &["libc::killpg", "libc::kill(-"],
        &["crates/writ-core/src/process_group.rs"],
    );
    assert!(
        hits.is_empty(),
        "process-group signalling belongs to `writ_core::process_group`; use \
         `kill_process_group`, or `run_supervised`/`run_supervised_blocking`.\n  {}",
        hits.join("\n  ")
    );
}

/// Does this source text construct a *process* `Command`?
///
/// The naive needle `"Command::new("` also matches this workspace's own wire
/// types — `VmGitCloneCommand::new`, `VmGitPushCommand::new`,
/// `VmWorkspaceInitCommand::new` — which are inert request structs that spawn
/// nothing. Left unfixed it reported eleven such call sites, and a guard whose
/// output is mostly noise gets an allowlist entry rather than a fix. So the
/// identifier is resolved and only the real thing counts, under any of the
/// spellings in use here (`Command`, `std::process::Command`, and the
/// `StdCommand` alias used where tokio's `Command` is also in scope).
fn builds_a_process_command(body: &str) -> bool {
    process_command_sites(body).next().is_some()
}

/// Byte offsets of every `Command::new(` in `body` that names a *process*
/// command, with the wire types resolved away as described above.
fn process_command_sites(body: &str) -> impl Iterator<Item = usize> + '_ {
    body.match_indices("Command::new(").filter_map(|(at, _)| {
        let path_start = body[..at]
            .rfind(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
            .map_or(0, |i| i + 1);
        let path = &body[path_start..at + "Command".len()];
        matches!(
            path.rsplit("::").next(),
            Some("Command") | Some("StdCommand")
        )
        .then_some(at)
    })
}

/// Does this source text actually *run* the command it built?
///
/// A body that constructs a `Command` only to inspect its argv or environment
/// (several guest tests do exactly that) hardens nothing and needs nothing, so
/// flagging it would only teach the reader to add allowlist entries.
fn spawns_it(body: &str) -> bool {
    [
        ".output()",
        ".status()",
        ".spawn()",
        "process_spawn::",
        "run_supervised",
    ]
    .iter()
    .any(|marker| body.contains(marker))
}

/// A helper named after `git` that builds its own process `Command` must apply
/// the recipe.
///
/// The two guards above ask "is the recipe re-typed anywhere?" and "are the raw
/// constants applied anywhere?". Neither asks the question that actually matters
/// — *does every git invocation get hardened?* — so both pass cleanly over a
/// helper that simply never mentions the recipe at all. Several did: two
/// `git_stdout` test fixtures, a pair of `cat-file` test helpers, and, worse,
/// four **production** guest-side runners in `writ-vm-client`, which
/// `git_env`'s own module doc named as a consumer.
///
/// Keying on the function name is a heuristic, and a deliberately stated one: it
/// catches a helper written to run git, which is how every bypass so far was
/// introduced, and it cannot catch a git spawn inside a differently-named
/// function. The durable version of this invariant is a construction boundary —
/// a `CleanGitInvocation` that is the only way to obtain a runnable git
/// `Command`, so the recipe is applied by the type rather than remembered by the
/// author. Until that exists, treat this as a backstop, not a proof.
#[test]
fn a_git_named_helper_must_apply_the_recipe_to_its_own_command() {
    const APPLIERS: &[&str] = &["apply_clean_git_config", "apply_git_config_denials"];
    /// `file::function` pairs that build and run git without calling an applier,
    /// for a reason recorded here.
    const EXEMPT: &[&str] = &[
        // The broker's hardened path, and the closest thing the workspace has to
        // the construction boundary this guard approximates: the recipe arrives
        // as already-validated `CleanGitEnv` values carried by the
        // `CleanGitInvocation` (from `clean_git_config_env`, built from
        // `CLEAN_GIT_CONFIG_ENV`), with `GIT_CONFIG_REMOVE_ENV` applied
        // alongside. Hardened by construction rather than by remembering to
        // call a function — which is why it is the exception and not the gap.
        "src/clean_git.rs::run_clean_git_inner",
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
        for (offset, _) in text.match_indices("fn ") {
            let after = &text[offset + 3..];
            let name_len = after
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(0);
            let name = &after[..name_len];
            if !name.contains("git") {
                continue;
            }
            // Only the *body* matters: a caller that hardens the command before
            // passing it in is fine, and so is a test asserting on argv.
            let Some(body_start) = text[offset..].find('{').map(|at| offset + at) else {
                continue;
            };
            let mut depth = 0usize;
            let mut body_end = None;
            for (at, ch) in text[body_start..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            body_end = Some(body_start + at);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(body_end) = body_end else { continue };
            let body = &text[body_start..body_end];
            if !builds_a_process_command(body) || !spawns_it(body) {
                continue;
            }
            if APPLIERS.iter().any(|applier| body.contains(applier)) {
                continue;
            }
            if EXEMPT.contains(&format!("{rel}::{name}").as_str()) {
                continue;
            }
            hits.push(format!(
                "{rel}: fn {name} builds and runs git without the recipe"
            ));
        }
    }
    hits.sort();
    hits.dedup();
    assert!(
        hits.is_empty(),
        "a helper that runs `git` must apply the hardened recipe to the Command \
         it builds (`writ_core::git_env::apply_clean_git_config`, or \
         `apply_git_config_denials` where HOME must be left alone). If a helper \
         genuinely must not be hardened, that is a decision worth writing down \
         here rather than leaving to the reader.\n  {}",
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

/// The source with whole-line comments blanked rather than removed, so byte
/// offsets still map to the original line numbers.
///
/// [`code_only`] is the right tool when only "does this text contain X?"
/// matters; a guard that reports a *location* needs the numbering intact.
fn blank_comment_lines(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.trim_start().starts_with("//") {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The statement containing the expression that starts at `from`: everything up
/// to the first `;` that is not nested inside brackets opened after `from`.
///
/// Builder chains here run to a dozen lines and freely contain `;` inside
/// closures and nested calls, so "to the end of the line" and "to the next `;`"
/// are both wrong.
fn statement_at(text: &str, from: usize) -> &str {
    let rest = &text[from..];
    let mut depth = 0i32;
    for (at, ch) in rest.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ';' if depth <= 0 => return &rest[..at],
            _ => {}
        }
    }
    rest
}

/// Every child process is spawned through `writ_core::process_spawn`.
///
/// That module's whole purpose is to hold, in one place, the judgement about
/// *which* spawn failures mean "the child never ran, so retrying re-runs
/// nothing" — `ETXTBSY`, `EAGAIN`, `ENOMEM`, `EMFILE`, `ENFILE` — and how long
/// each is worth waiting out. A call site that spells `.spawn()`, `.status()`
/// or `.output()` directly on a `Command` has silently opted out of that
/// judgement, and does so invisibly: the code looks identical to the hardened
/// form, and the difference only shows up as a flake on a loaded machine.
///
/// It has already cost real time. `broker_vm_runner`'s spawn-latency
/// calibration ran its freshly-written fake `container` script through a bare
/// `Command::status()`, and a sibling thread's `fork` holding a writable fd to
/// that script failed CI with `ExecutableFileBusy` — the one errno the
/// primitive was written for, at the one call site in the file that bypassed
/// it. Nothing but a reader's attention connected the two.
///
/// The check is per *statement*, not per function: a body that correctly uses
/// the primitive once and then hand-rolls a second spawn is exactly the case a
/// body-scoped scan would wave through.
///
/// **Indirect spawns count.** An earlier version of this guard only looked at
/// terminators chained onto the `Command::new(…)` expression, and recorded the
/// gap — a `Command` stashed in a local and spawned ten lines later — as a
/// documented blind spot. The gap was *already occupied*: `command.spawn()` in
/// `git_env`'s fixtures, `fixture_git_command(…).output()` in `flake_fixtures`,
/// and `command.output()` in `notes_repo`'s tests all sat in it. Documenting a
/// hole that real code is standing in is not a caveat, it is a miss, so the
/// scan now covers any terminator in a file that builds a process `Command` at
/// all — and those sites were migrated.
///
/// **What this still does not catch.** A file that never *constructs* a
/// `Command` but receives one as a parameter and spawns it. Nothing in the
/// workspace does that today; if something does later, this guard will not say
/// so. The durable answer remains a type that is the only way to obtain a
/// runnable command, applying the retry by construction rather than by the
/// author remembering; until that exists, treat this as a backstop.
#[test]
fn every_child_spawn_goes_through_the_retrying_primitive() {
    /// Terminators that run a built `Command`, as chained method calls.
    const TERMINATORS: &[&str] = &[".spawn()", ".status()", ".output()"];
    /// Ways of reaching the primitive, any of which makes a statement fine.
    /// `run_supervised` spawns through `process_spawn` internally.
    const HARDENED: &[&str] = &["process_spawn", "run_supervised"];
    /// The module that *defines* the retry: its own `command.spawn()` calls are
    /// the thing every other site is required to route through.
    const DEFINES_THE_PRIMITIVE: &str = "crates/writ-core/src/process_spawn.rs";
    /// Receiver names that are known not to be process `Command`s, in files
    /// that do build `Command`s elsewhere. Listed by name rather than by file so
    /// that adding one is a deliberate, reviewable act — the same trade the
    /// git-recipe guard makes.
    ///
    /// `self` is here on a *structural* ground rather than a naming convention:
    /// `Command` is a foreign type, so the orphan rule means no `impl` in this
    /// workspace can ever have `self: Command`. `ProcessInvocation::output` is
    /// the receiver in practice, and it spawns through the primitive.
    ///
    /// The rest are conventional: `response`/`resp` are `reqwest::Response`,
    /// `prepared` is a `PreparedVmHttpSession` (whose `spawn` starts a tokio
    /// task, not a process), and `running`/`starting` are `AgentVmSessionState`.
    const NON_COMMAND_RECEIVERS: &[&str] = &[
        "self", "response", "resp", "prepared", "running", "starting",
    ];
    /// `file::function` pairs whose terminator has a receiver this scan cannot
    /// name — a call rather than a binding — and which is not a `Command`.
    const EXEMPT: &[&str] = &[
        // `reqwest::Client::new().get(…).send().await.unwrap().status()` — the
        // HTTP status of a path-traversal probe, not a child process. The file
        // builds git `Command`s elsewhere, which is why it is in scope at all.
        "src/fake_origin.rs::origin_serves_info_refs_for_the_prereq",
    ];

    let mut hits = Vec::new();
    for path in workspace_rust_sources() {
        let rel = relative(&path);
        if rel == THIS_FILE || rel == DEFINES_THE_PRIMITIVE {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let text = blank_comment_lines(&raw);
        // Direct: a terminator chained onto `Command::new(…)` itself.
        for at in process_command_sites(&text) {
            let stmt = statement_at(&text, at);
            let Some(terminator) = TERMINATORS.iter().find(|t| stmt.contains(**t)) else {
                continue;
            };
            if HARDENED.iter().any(|marker| stmt.contains(marker)) {
                continue;
            }
            let line = text[..at].matches('\n').count() + 1;
            hits.push(format!("{rel}:{line}: `{terminator}` on a bare Command"));
        }
        // Indirect: any terminator at all, in a file that builds `Command`s.
        // Scoping to such files is what keeps the ~40 `response.status()` calls
        // on HTTP responses out of the report.
        if !builds_a_process_command(&text) {
            continue;
        }
        for terminator in TERMINATORS {
            for (at, _) in text.match_indices(terminator) {
                if statement_containing(&text, at)
                    .is_some_and(|stmt| HARDENED.iter().any(|m| stmt.contains(m)))
                {
                    continue;
                }
                match receiver_before(&text, at) {
                    // A named binding we have already accounted for.
                    Some(name) if NON_COMMAND_RECEIVERS.contains(&name) => continue,
                    Some(_) => {}
                    // The receiver is a call or other expression, so the name
                    // allowlist cannot speak to it; fall through to `EXEMPT`.
                    None => {}
                }
                let line = text[..at].matches('\n').count() + 1;
                if let Some(function) = enclosing_fn(&text, at)
                    && EXEMPT.contains(&format!("{rel}::{function}").as_str())
                {
                    continue;
                }
                hits.push(format!("{rel}:{line}: `{terminator}` on a Command"));
            }
        }
    }
    hits.sort();
    hits.dedup();
    assert!(
        hits.is_empty(),
        "spawn through `writ_core::process_spawn` — `spawn` for a `Child`, \
         `output` to run and collect (note it inherits stdio by default, unlike \
         `Command::output`), `spawn_async` for tokio — so that a spawn the OS \
         refused outright is retried rather than reported as a failure. \
         {} site(s):\n  {}",
        hits.len(),
        hits.join("\n  ")
    );
}

/// The identifier a method call at `at` is invoked on, if the receiver is a
/// plain binding rather than a call or a longer expression.
///
/// `None` where the receiver is `…)` — a call, an `unwrap`, an `await` — since
/// a name allowlist can say nothing useful about those.
fn receiver_before(text: &str, at: usize) -> Option<&str> {
    let before = &text[..at];
    let start = before.rfind(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    let name = &before[start + 1..];
    // A `.` immediately before the name means it is itself a field or method
    // result (`self.command.spawn()`), not a binding this list can vouch for.
    (!name.is_empty() && before[..=start].ends_with(|c: char| c != '.')).then_some(name)
}

/// The statement containing byte offset `at`, scanning back to the previous
/// `;` or block boundary.
fn statement_containing(text: &str, at: usize) -> Option<&str> {
    let start = text[..at]
        .rfind([';', '{', '}'])
        .map_or(0, |found| found + 1);
    Some(&text[start..at])
}

/// The name of the `fn` whose body contains `at`, by taking the nearest
/// preceding `fn` declaration. A heuristic, and only used to key `EXEMPT`
/// entries, where being wrong means a stale allowlist line rather than a
/// missed spawn.
fn enclosing_fn(text: &str, at: usize) -> Option<&str> {
    let before = &text[..at];
    let start = before.rfind("fn ")? + 3;
    let name_len = text[start..].find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    Some(&text[start..start + name_len])
}
