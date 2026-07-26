//! CLI-parsing and command-dispatch tests for the `bailiff` binary. Split out
//! of `bailiff.rs` (an inline `#[cfg(test)]` module) to keep the binary's
//! command surface readable; the tests are unchanged.

use super::*;
use clap::Parser;

/// `bailiff plan submit` parses the minimal required flag set
/// and threads each argument into the corresponding field of
/// `PlanCmd::Submit`. A regression in the clap attribute set
/// (a renamed flag, a misspelled default, a long/short
/// collision) surfaces here as a parse failure or a wrong
/// field assignment.
#[test]
fn plan_submit_parses_minimum_required_flags() {
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "submit",
        "--prompt-file",
        "/tmp/p.txt",
        "--repo",
        "smaug123/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
    ])
    .unwrap();
    let Cmd::Plan {
        action:
            PlanCmd::Submit {
                prompt_file,
                repo,
                bailiff_repo,
                writ_repo,
                writ_allowed_signers,
                plan_id,
                purpose,
                label,
                agent,
                model,
            },
    } = args.cmd
    else {
        panic!("expected PlanCmd::Submit");
    };
    assert_eq!(prompt_file, PathBuf::from("/tmp/p.txt"));
    assert_eq!(repo, "smaug123/writ");
    assert!(bailiff_repo.is_none());
    assert!(writ_repo.is_none());
    assert_eq!(
        writ_allowed_signers,
        PathBuf::from("/etc/bailiff/allowed_signers")
    );
    assert!(plan_id.is_none());
    assert_eq!(purpose, "plan-submit");
    assert!(label.is_none());
    assert_eq!(agent, AgentKind::Claude);
    assert!(model.is_none());
}

/// Every optional flag round-trips. Pins the contract that the
/// CLI surface is what later scripting depends on.
#[test]
fn plan_submit_accepts_every_optional_flag() {
    let plan_id_str = "1d1d1d1d-2d2d-3d3d-4d4d-5d5d5d5d5d5d";
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "submit",
        "--prompt-file",
        "/tmp/p.txt",
        "--repo",
        "smaug123/writ",
        "--bailiff-repo",
        "/var/bailiff",
        "--writ-repo",
        "/var/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
        "--plan-id",
        plan_id_str,
        "--purpose",
        "plan-submit:rev-2",
        "--label",
        "feature 42",
        "--agent",
        "codex",
        "--model",
        "gpt-test",
    ])
    .unwrap();
    let Cmd::Plan {
        action:
            PlanCmd::Submit {
                bailiff_repo,
                writ_repo,
                plan_id,
                purpose,
                label,
                agent,
                model,
                ..
            },
    } = args.cmd
    else {
        panic!("expected PlanCmd::Submit");
    };
    assert_eq!(
        bailiff_repo.as_deref(),
        Some(std::path::Path::new("/var/bailiff"))
    );
    assert_eq!(
        writ_repo.as_deref(),
        Some(std::path::Path::new("/var/writ"))
    );
    assert_eq!(plan_id.unwrap().to_string(), plan_id_str);
    assert_eq!(purpose, "plan-submit:rev-2");
    assert_eq!(label.as_deref(), Some("feature 42"));
    assert_eq!(agent, AgentKind::Codex);
    assert_eq!(model.as_deref(), Some("gpt-test"));
}

/// `bailiff plan decide` parses the minimum required flag set
/// (`--plan-id` plus exactly one of `--accept` / `--reject`) and
/// threads each argument into the corresponding field of
/// `PlanCmd::Decide`. A regression in the clap attribute set
/// (a renamed flag, a missing `ArgGroup`, a misspelled default)
/// surfaces here as a parse failure or a wrong field assignment.
#[test]
fn plan_decide_parses_minimum_required_flags() {
    let plan_id_str = "1d1d1d1d-2d2d-3d3d-4d4d-5d5d5d5d5d5d";
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "decide",
        "--plan-id",
        plan_id_str,
        "--accept",
    ])
    .unwrap();
    let Cmd::Plan {
        action:
            PlanCmd::Decide {
                plan_id,
                accept,
                reject,
                decider,
                bailiff_repo,
            },
    } = args.cmd
    else {
        panic!("expected PlanCmd::Decide");
    };
    assert_eq!(plan_id.to_string(), plan_id_str);
    assert!(accept);
    assert!(!reject);
    assert!(
        decider.is_none(),
        "default decider derivation belongs to plan_decide, not the parser"
    );
    assert!(bailiff_repo.is_none());
}

/// Every optional flag round-trips, and `--reject` flips the
/// outcome from accept to reject. Together with the
/// minimum-required test this pins both halves of the
/// accept/reject group plus the optional flag surface.
#[test]
fn plan_decide_accepts_every_optional_flag_with_reject() {
    let plan_id_str = "2d2d2d2d-3d3d-4d4d-5d5d-6d6d6d6d6d6d";
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "decide",
        "--plan-id",
        plan_id_str,
        "--reject",
        "--decider",
        "cli:alice",
        "--bailiff-repo",
        "/var/bailiff",
    ])
    .unwrap();
    let Cmd::Plan {
        action:
            PlanCmd::Decide {
                plan_id,
                accept,
                reject,
                decider,
                bailiff_repo,
            },
    } = args.cmd
    else {
        panic!("expected PlanCmd::Decide");
    };
    assert_eq!(plan_id.to_string(), plan_id_str);
    assert!(!accept);
    assert!(reject);
    assert_eq!(decider.as_deref(), Some("cli:alice"));
    assert_eq!(
        bailiff_repo.as_deref(),
        Some(std::path::Path::new("/var/bailiff")),
    );
}

/// Clap's `ArgGroup` on the outcome flags must reject both
/// `--accept` and `--reject`. A regression that drops the group
/// (or that uses `multiple = true`) would silently accept this
/// and make `resolve_decision_outcome`'s `(true, true)` branch
/// reachable from the CLI.
#[test]
fn plan_decide_rejects_both_accept_and_reject() {
    let plan_id_str = "3d3d3d3d-4d4d-5d5d-6d6d-7d7d7d7d7d7d";
    let err = Args::try_parse_from([
        "bailiff",
        "plan",
        "decide",
        "--plan-id",
        plan_id_str,
        "--accept",
        "--reject",
    ])
    .err()
    .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--accept") || msg.contains("--reject") || msg.contains("decide_outcome"),
        "expected ArgGroup conflict, got: {msg}",
    );
}

/// `ArgGroup::required(true)` must reject the no-outcome case.
/// A regression that drops `required(true)` would silently pass
/// `(accept=false, reject=false)` through and trip
/// `resolve_decision_outcome`'s `unreachable!`.
#[test]
fn plan_decide_rejects_neither_accept_nor_reject() {
    let plan_id_str = "4d4d4d4d-5d5d-6d6d-7d7d-8d8d8d8d8d8d";
    let err = Args::try_parse_from(["bailiff", "plan", "decide", "--plan-id", plan_id_str])
        .err()
        .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--accept") || msg.contains("--reject") || msg.contains("required"),
        "expected required-arg-group failure, got: {msg}",
    );
}

/// `--plan-id` is required; without it the parse fails. Pins the
/// clap surface — a regression to `Option<PlanId>` (a copy-paste
/// of `plan submit`'s opt-in shape) would silently accept this.
#[test]
fn plan_decide_rejects_missing_plan_id() {
    let err = Args::try_parse_from(["bailiff", "plan", "decide", "--accept"])
        .err()
        .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--plan-id") || msg.contains("required"),
        "expected missing-plan-id failure, got: {msg}",
    );
}

/// `PlanId::from_str` runs at parse, so a malformed UUID is a
/// parse error rather than a runtime failure inside
/// `plan_decide`. Pins that the value_parser stays wired to the
/// validating constructor.
#[test]
fn plan_decide_rejects_malformed_plan_id() {
    let err = Args::try_parse_from([
        "bailiff",
        "plan",
        "decide",
        "--plan-id",
        "not-a-uuid",
        "--accept",
    ])
    .err()
    .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--plan-id") || msg.contains("uuid") || msg.contains("UUID"),
        "expected malformed-plan-id failure, got: {msg}",
    );
}

/// `resolve_decision_outcome` is the load-bearing
/// flag-to-`Decision` mapping. Pin both reachable branches —
/// a swap (`accept` → `Rejected`) would be catastrophically wrong
/// but invisible to the parser-only tests above.
#[test]
fn resolve_decision_outcome_maps_accept_and_reject() {
    assert_eq!(resolve_decision_outcome(true, false), Decision::Accepted);
    assert_eq!(resolve_decision_outcome(false, true), Decision::Rejected);
}

/// `resolve_decider` honours an explicit `--decider` flag
/// verbatim, ignoring the supplied `user_env`. The flag is the
/// override path scripted callers use; it must not be silently
/// overridden by the env-var fallback even when one is present.
#[test]
fn resolve_decider_honours_explicit_flag() {
    let d = resolve_decider(Some("agent:run-xyz".into()), Some("alice".into())).unwrap();
    assert_eq!(d.as_str(), "agent:run-xyz");
}

/// Without `--decider`, `resolve_decider` falls back to
/// `cli:<user_env>`. The env value is injected (not read from the
/// live process), so this is a pure function and doesn't race
/// with other tests in the same binary.
#[test]
fn resolve_decider_defaults_to_cli_user() {
    let d = resolve_decider(None, Some("alice".into())).unwrap();
    assert_eq!(d.as_str(), "cli:alice");
}

/// Without `--decider` and with `user_env = None`,
/// `resolve_decider` fails with a user-actionable message
/// mentioning both fallback sources. Stricter than writ's removed
/// `plan decide` verb (which fell back to `cli:unknown`); the
/// `PlanCmd::Decide` docstring explains why. Pin the failure
/// shape so the divergence is intentional rather than a silent
/// regression.
#[test]
fn resolve_decider_fails_when_no_flag_and_no_user_env() {
    let err = resolve_decider(None, None).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("--decider") && msg.contains("USER"),
        "expected actionable error mentioning both --decider and USER, got: {msg}",
    );
}

/// `default_bailiff_repo_path` honours `XDG_DATA_HOME` when
/// set and falls back to the documented `~/.local/share`
/// location otherwise. The env-var manipulation is process-
/// scoped; running other tests concurrently in the same
/// process could see the temporary unset, so the test serialises
/// the env access by snapshotting and restoring.
#[test]
fn default_paths_track_xdg_data_home() {
    // Snapshot to restore; SAFETY-WISE we never share env access with
    // other parallel tests in this binary that mutate the same vars.
    // The `tests` module in this binary doesn't touch XDG_DATA_HOME
    // anywhere else, so the only risk is concurrent integration
    // tests — none exist for this binary today.
    let snapshot = std::env::var_os("XDG_DATA_HOME");
    unsafe {
        std::env::set_var("XDG_DATA_HOME", "/data");
    }
    assert_eq!(
        default_bailiff_repo_path(),
        PathBuf::from("/data/bailiff/repo")
    );
    assert_eq!(default_writ_repo_path(), PathBuf::from("/data/writ/repo"));
    // Pin the invariant: bailiff's writ-repo default must agree
    // with the daemon's notes-repo default, because writd writes
    // and bailiff fetches from the same disk location when both
    // run with stock config.
    assert_eq!(
        default_writ_repo_path(),
        writ::config::default_notes_repo_path(),
        "bailiff and writd default writ-repo path diverged — one was renamed without the other",
    );

    unsafe {
        std::env::remove_var("XDG_DATA_HOME");
        std::env::set_var("HOME", "/home/test");
    }
    assert_eq!(
        default_bailiff_repo_path(),
        PathBuf::from("/home/test/.local/share/bailiff/repo")
    );
    assert_eq!(
        default_writ_repo_path(),
        PathBuf::from("/home/test/.local/share/writ/repo")
    );

    unsafe {
        match snapshot {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
    }
}

/// `bailiff plan review` parses the minimum required flag set
/// (`--plan-id`, `--prompt-file`, `--repo`, `--writ-allowed-signers`)
/// and threads each argument into the corresponding field of
/// `PlanCmd::Review`. A regression in the clap attribute set
/// (a renamed flag, a misspelled default, a long/short collision)
/// surfaces here as a parse failure or a wrong field assignment.
#[test]
fn plan_review_parses_minimum_required_flags() {
    let plan_id_str = "1d1d1d1d-2d2d-3d3d-4d4d-5d5d5d5d5d5d";
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "review",
        "--plan-id",
        plan_id_str,
        "--prompt-file",
        "/tmp/r.txt",
        "--repo",
        "smaug123/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
    ])
    .unwrap();
    let Cmd::Plan {
        action:
            PlanCmd::Review {
                plan_id,
                prompt_file,
                repo,
                bailiff_repo,
                writ_repo,
                writ_allowed_signers,
                purpose,
                label,
                agent,
                model,
            },
    } = args.cmd
    else {
        panic!("expected PlanCmd::Review");
    };
    assert_eq!(plan_id.to_string(), plan_id_str);
    assert_eq!(prompt_file, PathBuf::from("/tmp/r.txt"));
    assert_eq!(repo, "smaug123/writ");
    assert!(bailiff_repo.is_none());
    assert!(writ_repo.is_none());
    assert_eq!(
        writ_allowed_signers,
        PathBuf::from("/etc/bailiff/allowed_signers")
    );
    assert_eq!(purpose, "plan-review");
    assert!(label.is_none());
    assert_eq!(agent, AgentKind::Claude);
    assert!(model.is_none());
}

/// Every optional flag round-trips. Pins the full review CLI
/// surface so scripted callers see a stable contract.
#[test]
fn plan_review_accepts_every_optional_flag() {
    let plan_id_str = "2d2d2d2d-3d3d-4d4d-5d5d-6d6d6d6d6d6d";
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "review",
        "--plan-id",
        plan_id_str,
        "--prompt-file",
        "/tmp/r.txt",
        "--repo",
        "smaug123/writ",
        "--bailiff-repo",
        "/var/bailiff",
        "--writ-repo",
        "/var/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
        "--purpose",
        "plan-review:rev-2",
        "--label",
        "feature 42 review",
        "--agent",
        "codex",
        "--model",
        "gpt-test",
    ])
    .unwrap();
    let Cmd::Plan {
        action:
            PlanCmd::Review {
                plan_id,
                bailiff_repo,
                writ_repo,
                purpose,
                label,
                agent,
                model,
                ..
            },
    } = args.cmd
    else {
        panic!("expected PlanCmd::Review");
    };
    assert_eq!(plan_id.to_string(), plan_id_str);
    assert_eq!(
        bailiff_repo.as_deref(),
        Some(std::path::Path::new("/var/bailiff"))
    );
    assert_eq!(
        writ_repo.as_deref(),
        Some(std::path::Path::new("/var/writ"))
    );
    assert_eq!(purpose, "plan-review:rev-2");
    assert_eq!(label.as_deref(), Some("feature 42 review"));
    assert_eq!(agent, AgentKind::Codex);
    assert_eq!(model.as_deref(), Some("gpt-test"));
}

/// `--plan-id` is required; without it the parse fails. Pins the
/// divergence from `plan submit` (which auto-allocates): reviewing
/// presupposes an existing plan, so the id is mandatory.
#[test]
fn plan_review_rejects_missing_plan_id() {
    let err = Args::try_parse_from([
        "bailiff",
        "plan",
        "review",
        "--prompt-file",
        "/tmp/r.txt",
        "--repo",
        "smaug123/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
    ])
    .err()
    .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--plan-id") || msg.contains("required"),
        "expected missing-plan-id failure, got: {msg}",
    );
}

/// `PlanId::from_str` runs at parse, so a malformed UUID is a
/// parse error rather than a runtime failure inside `plan_review`.
/// Pins that the value_parser stays wired to the validating
/// constructor.
#[test]
fn plan_review_rejects_malformed_plan_id() {
    let err = Args::try_parse_from([
        "bailiff",
        "plan",
        "review",
        "--plan-id",
        "not-a-uuid",
        "--prompt-file",
        "/tmp/r.txt",
        "--repo",
        "smaug123/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
    ])
    .err()
    .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--plan-id") || msg.contains("uuid") || msg.contains("UUID"),
        "expected malformed-plan-id failure, got: {msg}",
    );
}

/// `bailiff plan list` parses with no required flags and accepts
/// the single optional `--bailiff-repo` override. The body of
/// `plan_list` (path resolution, repo init, ref enumeration,
/// formatter) is exercised by the library-side helper tests in
/// `bailiff_plan_read::list_tests` and `cli::output::tests` — the
/// parser test pins the clap surface so a renamed flag surfaces
/// here rather than as a confused operator running into an unknown
/// argument message.
#[test]
fn plan_list_parses_with_no_flags() {
    let args = Args::try_parse_from(["bailiff", "plan", "list"]).unwrap();
    let Cmd::Plan {
        action: PlanCmd::List { bailiff_repo },
    } = args.cmd
    else {
        panic!("expected PlanCmd::List");
    };
    assert!(bailiff_repo.is_none());
}

/// `--bailiff-repo` round-trips. Pins the optional-flag contract;
/// scripted callers that override the default path depend on this.
#[test]
fn plan_list_accepts_bailiff_repo_override() {
    let args = Args::try_parse_from(["bailiff", "plan", "list", "--bailiff-repo", "/var/bailiff"])
        .unwrap();
    let Cmd::Plan {
        action: PlanCmd::List { bailiff_repo },
    } = args.cmd
    else {
        panic!("expected PlanCmd::List");
    };
    assert_eq!(
        bailiff_repo.as_deref(),
        Some(std::path::Path::new("/var/bailiff"))
    );
}

/// `bailiff plan show` parses the minimum required flag set
/// (`--plan-id`, `--writ-allowed-signers`) and threads each
/// argument into the corresponding field. Pins the clap surface
/// so a renamed flag surfaces here rather than as a confused
/// operator running into an unknown-argument message.
#[test]
fn plan_show_parses_minimum_required_flags() {
    let plan_id_str = "5d5d5d5d-6d6d-7d7d-8d8d-9d9d9d9d9d9d";
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "show",
        "--plan-id",
        plan_id_str,
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
    ])
    .unwrap();
    let Cmd::Plan {
        action:
            PlanCmd::Show {
                plan_id,
                writ_allowed_signers,
                bailiff_repo,
            },
    } = args.cmd
    else {
        panic!("expected PlanCmd::Show");
    };
    assert_eq!(plan_id.to_string(), plan_id_str);
    assert_eq!(
        writ_allowed_signers,
        PathBuf::from("/etc/bailiff/allowed_signers")
    );
    assert!(bailiff_repo.is_none());
}

/// `--bailiff-repo` round-trips for `show`. Pins the optional-flag
/// contract; scripted callers that override the default path
/// depend on this.
#[test]
fn plan_show_accepts_bailiff_repo_override() {
    let plan_id_str = "6d6d6d6d-7d7d-8d8d-9d9d-1e1e1e1e1e1e";
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "show",
        "--plan-id",
        plan_id_str,
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
        "--bailiff-repo",
        "/var/bailiff",
    ])
    .unwrap();
    let Cmd::Plan {
        action: PlanCmd::Show { bailiff_repo, .. },
    } = args.cmd
    else {
        panic!("expected PlanCmd::Show");
    };
    assert_eq!(
        bailiff_repo.as_deref(),
        Some(std::path::Path::new("/var/bailiff"))
    );
}

/// `--plan-id` is required. A regression that made it optional
/// (a copy-paste of `plan submit`'s opt-in shape) would silently
/// accept this and reach `plan_show` with a `None` id.
#[test]
fn plan_show_rejects_missing_plan_id() {
    let err = Args::try_parse_from([
        "bailiff",
        "plan",
        "show",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
    ])
    .err()
    .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--plan-id") || msg.contains("required"),
        "expected missing-plan-id failure, got: {msg}",
    );
}

/// `--writ-allowed-signers` is required. A regression that made
/// it optional would let `plan_show` reach the on-disk read with
/// a `None` path; pin the contract here at the parser tier.
#[test]
fn plan_show_rejects_missing_writ_allowed_signers() {
    let plan_id_str = "7d7d7d7d-8d8d-9d9d-1e1e-2e2e2e2e2e2e";
    let err = Args::try_parse_from(["bailiff", "plan", "show", "--plan-id", plan_id_str])
        .err()
        .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--writ-allowed-signers") || msg.contains("required"),
        "expected missing-writ-allowed-signers failure, got: {msg}",
    );
}

/// `PlanId::from_str` runs at parse, so a malformed UUID is a
/// parse error rather than a runtime failure inside `plan_show`.
/// Pins that the value_parser stays wired to the validating
/// constructor.
#[test]
fn plan_show_rejects_malformed_plan_id() {
    let err = Args::try_parse_from([
        "bailiff",
        "plan",
        "show",
        "--plan-id",
        "not-a-uuid",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
    ])
    .err()
    .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--plan-id") || msg.contains("uuid") || msg.contains("UUID"),
        "expected malformed-plan-id failure, got: {msg}",
    );
}

/// `--prompt-file` is required. A regression that made it optional
/// would let `plan_review` reach the on-disk read with a `None`
/// path; pin the contract here at the parser tier.
#[test]
fn plan_review_rejects_missing_prompt_file() {
    let plan_id_str = "3d3d3d3d-4d4d-5d5d-6d6d-7d7d7d7d7d7d";
    let err = Args::try_parse_from([
        "bailiff",
        "plan",
        "review",
        "--plan-id",
        plan_id_str,
        "--repo",
        "smaug123/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
    ])
    .err()
    .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--prompt-file") || msg.contains("required"),
        "expected missing-prompt-file failure, got: {msg}",
    );
}

/// `bailiff plan implement` parses the minimum required flag set
/// (`--plan-id`, `--prompt-file`, `--repo`, `--writ-allowed-signers`)
/// and threads each argument into the corresponding field of
/// `PlanCmd::Implement`. The defaults pin the operator-facing
/// contract: `--purpose` is `"plan-implement"` (parallels
/// `plan-submit` / `plan-review`); `--agent` is `claude` to match
/// the GitHub-App selection writ uses when no explicit identity is
/// passed. A regression in the clap attribute set surfaces here
/// rather than at runtime.
#[test]
fn plan_implement_parses_minimum_required_flags() {
    let plan_id_str = "1e1e1e1e-2e2e-3e3e-4e4e-5e5e5e5e5e5e";
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "implement",
        "--plan-id",
        plan_id_str,
        "--prompt-file",
        "/tmp/i.txt",
        "--repo",
        "smaug123/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
        "--model",
        "claude-opus-4-7",
    ])
    .unwrap();
    let Cmd::Plan {
        action:
            PlanCmd::Implement {
                plan_id,
                prompt_file,
                repo,
                bailiff_repo,
                writ_repo,
                writ_allowed_signers,
                purpose,
                agent,
                model,
                ..
            },
    } = args.cmd
    else {
        panic!("expected PlanCmd::Implement");
    };
    assert_eq!(plan_id.to_string(), plan_id_str);
    assert_eq!(prompt_file, PathBuf::from("/tmp/i.txt"));
    assert_eq!(repo, "smaug123/writ");
    assert!(bailiff_repo.is_none());
    assert!(writ_repo.is_none());
    assert_eq!(
        writ_allowed_signers,
        PathBuf::from("/etc/bailiff/allowed_signers")
    );
    assert_eq!(purpose, "plan-implement");
    assert_eq!(agent, AgentKind::Claude);
    assert_eq!(model, "claude-opus-4-7");
}

/// Every optional flag round-trips. Pins the full implement CLI
/// surface so scripted callers see a stable contract.
#[test]
fn plan_implement_accepts_every_optional_flag() {
    let plan_id_str = "2e2e2e2e-3e3e-4e4e-5e5e-6e6e6e6e6e6e";
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "implement",
        "--plan-id",
        plan_id_str,
        "--prompt-file",
        "/tmp/i.txt",
        "--repo",
        "smaug123/writ",
        "--bailiff-repo",
        "/var/bailiff",
        "--writ-repo",
        "/var/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
        "--purpose",
        "plan-implement:rev-2",
        "--agent",
        "codex",
        "--model",
        "gpt-test",
    ])
    .unwrap();
    let Cmd::Plan {
        action:
            PlanCmd::Implement {
                plan_id,
                bailiff_repo,
                writ_repo,
                purpose,
                agent,
                model,
                ..
            },
    } = args.cmd
    else {
        panic!("expected PlanCmd::Implement");
    };
    assert_eq!(plan_id.to_string(), plan_id_str);
    assert_eq!(
        bailiff_repo.as_deref(),
        Some(std::path::Path::new("/var/bailiff"))
    );
    assert_eq!(
        writ_repo.as_deref(),
        Some(std::path::Path::new("/var/writ"))
    );
    assert_eq!(purpose, "plan-implement:rev-2");
    assert_eq!(agent, AgentKind::Codex);
    assert_eq!(model, "gpt-test");
}

/// `--plan-id` is required. Implementing presupposes a submitted +
/// decided plan, so there is no auto-allocation — the id is
/// mandatory. A regression to `Option<PlanId>` (a copy-paste of
/// `plan submit`'s opt-in shape) would silently accept this and
/// reach `plan_implement` with a `None` id.
#[test]
fn plan_implement_rejects_missing_plan_id() {
    let err = Args::try_parse_from([
        "bailiff",
        "plan",
        "implement",
        "--prompt-file",
        "/tmp/i.txt",
        "--repo",
        "smaug123/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
        "--model",
        "claude-opus-4-7",
    ])
    .err()
    .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--plan-id") || msg.contains("required"),
        "expected missing-plan-id failure, got: {msg}",
    );
}

/// `--prompt-file` is required. Pins the surface — a regression
/// that made it optional would let `plan_implement` reach the
/// on-disk read with a `None` path. The clap-side doc on this flag
/// must continue to read "the operator's original feature prompt"
/// because `submit_implement` composes the implementer's effective
/// prompt internally from this plus the verified plan body.
#[test]
fn plan_implement_rejects_missing_prompt_file() {
    let plan_id_str = "3e3e3e3e-4e4e-5e5e-6e6e-7e7e7e7e7e7e";
    let err = Args::try_parse_from([
        "bailiff",
        "plan",
        "implement",
        "--plan-id",
        plan_id_str,
        "--repo",
        "smaug123/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
        "--model",
        "claude-opus-4-7",
    ])
    .err()
    .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--prompt-file") || msg.contains("required"),
        "expected missing-prompt-file failure, got: {msg}",
    );
}

/// `--model` is required for `plan implement`. Writd's VM dispatch
/// arm rejects a `RunAgent` carrying a workspace bootstrap but no
/// `agent_model` with "VM mode requires agent_model", so accepting
/// the flag as optional would mean the default `bailiff plan
/// implement …` invocation fails at the broker rather than at parse
/// time. Codex review on slice VM3 flagged this — pin the surface
/// so a regression to `Option<String>` (the shape inherited from
/// the read-side `plan submit` / `plan review` verbs) fails here.
#[test]
fn plan_implement_rejects_missing_model() {
    let plan_id_str = "6e6e6e6e-7e7e-8e8e-9e9e-aeaeaeaeaeae";
    let err = Args::try_parse_from([
        "bailiff",
        "plan",
        "implement",
        "--plan-id",
        plan_id_str,
        "--prompt-file",
        "/tmp/i.txt",
        "--repo",
        "smaug123/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
    ])
    .err()
    .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--model") || msg.contains("required"),
        "expected missing-model failure, got: {msg}",
    );
}

/// `PlanId::from_str` runs at parse, so a malformed UUID is a
/// parse error rather than a runtime failure inside `plan_implement`.
/// Pins that the value_parser stays wired to the validating
/// constructor.
#[test]
fn plan_implement_rejects_malformed_plan_id() {
    let err = Args::try_parse_from([
        "bailiff",
        "plan",
        "implement",
        "--plan-id",
        "not-a-uuid",
        "--prompt-file",
        "/tmp/i.txt",
        "--repo",
        "smaug123/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
        "--model",
        "claude-opus-4-7",
    ])
    .err()
    .expect("expected parse error");
    let msg = err.to_string();
    assert!(
        msg.contains("--plan-id") || msg.contains("uuid") || msg.contains("UUID"),
        "expected malformed-plan-id failure, got: {msg}",
    );
}

/// `bailiff plan implement` parses the workspace bootstrap flags
/// (`--workspace-warm`, `--workspace-destination`) and threads them
/// into `PlanCmd::Implement` so the CLI binding can build an
/// `AgentVmWorkspaceBootstrap` for `SubmitImplementInputs`. Slice
/// VM3 introduces the flags so `submit_implement` can request a
/// per-run VM checkout; the workspace repo is taken from the
/// existing `--repo` flag (`WorkspaceWrite` capability and the
/// bootstrap target are the same `owner/name`). A regression that
/// dropped either flag from the surface would surface here as a
/// clap parse error or as a `None` on the parsed variant.
#[test]
fn plan_implement_parses_workspace_flags() {
    let plan_id_str = "4e4e4e4e-5e5e-6e6e-7e7e-8e8e8e8e8e8e";
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "implement",
        "--plan-id",
        plan_id_str,
        "--prompt-file",
        "/tmp/i.txt",
        "--repo",
        "smaug123/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
        "--model",
        "claude-opus-4-7",
        "--workspace-warm",
        "sources",
        "--workspace-destination",
        "/repo",
    ])
    .unwrap();
    let Cmd::Plan {
        action:
            PlanCmd::Implement {
                workspace_warm,
                workspace_destination,
                ..
            },
    } = args.cmd
    else {
        panic!("expected PlanCmd::Implement");
    };
    assert_eq!(workspace_warm, WorkspaceWarmMode::Sources);
    assert_eq!(
        workspace_destination.as_deref(),
        Some(std::path::Path::new("/repo"))
    );
}

/// The workspace flags are optional with sensible defaults: omitted
/// `--workspace-warm` defaults to `devshell` (the
/// `WorkspaceWarmMode::Default` impl), and omitted
/// `--workspace-destination` lands as `None` (so writd picks
/// `default_workspace_destination` for the repo). A regression that
/// made either flag required would force every operator invocation
/// to spell out the default, which is contrary to the slice's
/// "operator supplies repo, broker picks the rest" ergonomics.
#[test]
fn plan_implement_defaults_workspace_warm_to_devshell() {
    let plan_id_str = "5e5e5e5e-6e6e-7e7e-8e8e-9e9e9e9e9e9e";
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "implement",
        "--plan-id",
        plan_id_str,
        "--prompt-file",
        "/tmp/i.txt",
        "--repo",
        "smaug123/writ",
        "--writ-allowed-signers",
        "/etc/bailiff/allowed_signers",
        "--model",
        "claude-opus-4-7",
    ])
    .unwrap();
    let Cmd::Plan {
        action:
            PlanCmd::Implement {
                workspace_warm,
                workspace_destination,
                ..
            },
    } = args.cmd
    else {
        panic!("expected PlanCmd::Implement");
    };
    assert_eq!(workspace_warm, WorkspaceWarmMode::DevShell);
    assert!(workspace_destination.is_none());
}

/// Happy path for `build_implement_workspace_bootstrap`: a UTF-8
/// `--workspace-destination` round-trips verbatim onto the
/// bootstrap, the warm mode passes through unchanged, and the
/// bootstrap's `repo` agrees with the `RepoRef` the helper was
/// handed (the workflow's "capability and bootstrap target must
/// be the same owner/name" invariant).
#[test]
fn build_implement_workspace_bootstrap_threads_utf8_destination_and_warm() {
    let repo: RepoRef = "smaug123/writ".parse().unwrap();
    let dest = PathBuf::from("/workspace/writ");
    let workspace =
        build_implement_workspace_bootstrap(&repo, Some(dest.clone()), WorkspaceWarmMode::Sources)
            .expect("UTF-8 destination must be accepted");
    assert_eq!(workspace.destination, Some(dest));
    assert_eq!(workspace.warm, WorkspaceWarmMode::Sources);
    assert_eq!(workspace.repo.to_string(), "smaug123/writ");
}

/// `build_implement_workspace_bootstrap` rejects a non-UTF-8
/// `--workspace-destination` *at the CLI boundary*. Codex review
/// on slice VM3 flagged that without this check, a non-UTF-8 path
/// (entirely legal at the OS level on Unix) flows onto the wire,
/// where `writ_client::roundtrip` does
/// `serde_json::to_string(&msg).expect("ClientMessage always
/// serializes")` — `serde_json`'s `PathBuf` serializer returns an
/// error for non-UTF-8 paths, so the `expect` would panic the
/// client instead of returning a `WritClientError`. The
/// validation belongs here (and not on
/// `AgentVmWorkspaceBootstrap` itself) because the invariant is
/// outbound-only: the bootstrap type is shared with deserialise
/// paths where a non-UTF-8 path would already have failed at
/// `serde_json`.
#[test]
#[cfg(unix)]
fn build_implement_workspace_bootstrap_rejects_non_utf8_destination() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let repo: RepoRef = "smaug123/writ".parse().unwrap();
    let bad = PathBuf::from(OsString::from_vec(vec![0xff, 0xfe, 0xfd]));
    let err = build_implement_workspace_bootstrap(&repo, Some(bad), WorkspaceWarmMode::DevShell)
        .expect_err(
            "non-UTF-8 --workspace-destination must surface at the CLI boundary, \
         not as a serialize-time panic in writ_client::roundtrip",
        );
    assert!(
        err.contains("UTF-8") || err.contains("--workspace-destination"),
        "expected UTF-8 validation failure naming the flag, got: {err}",
    );
}

// The `implement_lock_blocks_concurrent_acquire_and_releases_on_drop`
// test lived here until slice 2. It pinned the CLI-layer
// `acquire_implement_lock` helper, which no longer exists: locking is
// a library concern now, keyed per plan rather than per repo, and
// taken by all four mutating verbs rather than by `implement` alone.
//
// Its own docstring predicted its removal — it listed "swapping
// `try_lock` for `lock`" as a regression it would catch, and that is
// precisely the deliberate change: `PlanGuard::acquire` waits instead
// of failing fast, because the holder is typically mid-LLM-run and
// "retry later" is not something a caller can act on. The equivalent
// coverage is `bailiff_repo_guard::tests`, which asserts exclusion,
// per-plan granularity, and release-then-reacquire against the real
// guard.

/// The dossier verb parses its flags, and `--allow-terminal` defaults
/// off.
///
/// The default is the load-bearing half: the guard exists because
/// implementer stdout is agent-controlled and a terminal interprets
/// rather than counts, so a flag that defaulted *on* would be the
/// guarantee silently absent.
#[test]
fn plan_dossier_parses_and_defaults_to_refusing_a_terminal() {
    let args = Args::try_parse_from([
        "bailiff",
        "plan",
        "dossier",
        "--plan-id",
        "11111111-2222-4333-8444-555555555555",
        "--writ-allowed-signers",
        "/tmp/signers",
    ])
    .expect("minimum required flags must parse");
    match args.cmd {
        Cmd::Plan {
            action:
                PlanCmd::Dossier {
                    plan_id,
                    bailiff_repo,
                    writ_repo,
                    writ_allowed_signers,
                    allow_terminal,
                },
        } => {
            assert_eq!(plan_id.to_string(), "11111111-2222-4333-8444-555555555555");
            assert_eq!(bailiff_repo, None);
            assert_eq!(writ_repo, None);
            assert_eq!(writ_allowed_signers, PathBuf::from("/tmp/signers"));
            assert!(
                !allow_terminal,
                "the terminal guard must be on unless the operator opts out",
            );
        }
        _ => panic!("expected PlanCmd::Dossier, got a different command"),
    }
}
