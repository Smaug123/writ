//! Operator identity capture and CLI-flag → outcome mapping helpers.
//!
//! Kept pure so the test suite can exercise the mappings without
//! mutating process env (`std::env::set_var` is unsafe under Rust 2024
//! and would race with Clap's env-aware parsers in parallel tests).

use crate::agent_plan::DecisionOutcome;
use crate::protocol::ReconcileOutcome;
use crate::vm_git::GitObjectId;

/// Read the operator identity the CLI will assert to the broker.
///
/// The local socket is the trust boundary, so this only needs to be a
/// stable, human-readable label. The pure mapping lives in
/// [`classify_operator_identity`] so it can be exercised in tests
/// without mutating the process environment — `std::env::set_var` is
/// unsafe under Rust 2024 and would race with Clap's env-aware
/// argument parsing in other unit tests.
pub fn capture_operator_identity() -> String {
    classify_operator_identity(std::env::var("USER").ok())
}

/// `$USER` is what every interactive shell sets; if it is missing or
/// empty (some CI containers drop it), record `"unknown"` rather than
/// failing the reject — the audit row should always land.
pub fn classify_operator_identity(user: Option<String>) -> String {
    match user {
        Some(value) if !value.is_empty() => value,
        _ => "unknown".to_string(),
    }
}

/// Map the parsed `--accept` / `--reject-restart` flags to a
/// [`DecisionOutcome`]. Clap's `ArgGroup` enforces exactly-one before
/// we get here, so the `(false, false)` and `(true, true)` cases are
/// unreachable in practice — they panic loudly rather than guess.
pub fn resolve_decision_outcome(accept: bool, reject_restart: bool) -> DecisionOutcome {
    match (accept, reject_restart) {
        (true, false) => DecisionOutcome::Accepted,
        (false, true) => DecisionOutcome::RejectedRestart,
        (false, false) | (true, true) => {
            unreachable!("clap ArgGroup enforces exactly one of --accept / --reject-restart")
        }
    }
}

/// Map the parsed reconcile flag set to a [`ReconcileOutcome`]. Clap's
/// `ArgGroup` enforces exactly-one of `--confirmed-applied` /
/// `--confirmed-not-applied`, and `required_if_eq` enforces that the
/// dependent text/SHA flags are present, so the `None` arms here are
/// unreachable in practice and panic rather than guess.
///
/// `new_app_tip` is parsed via [`GitObjectId`]'s `FromStr` impl so a
/// malformed SHA fails fast at the CLI instead of after the daemon
/// round-trip.
pub fn resolve_reconcile_outcome(
    confirmed_applied: bool,
    confirmed_not_applied: bool,
    new_app_tip: Option<String>,
    reason: Option<String>,
    detail: Option<String>,
) -> Result<ReconcileOutcome, Box<dyn std::error::Error>> {
    match (confirmed_applied, confirmed_not_applied) {
        (true, false) => {
            let new_app_tip = new_app_tip.unwrap_or_else(|| {
                unreachable!("clap required_if_eq enforces --new-app-tip with --confirmed-applied")
            });
            let reason = reason.unwrap_or_else(|| {
                unreachable!("clap required_if_eq enforces --reason with --confirmed-applied")
            });
            let new_app_tip: GitObjectId = new_app_tip
                .parse()
                .map_err(|e| format!("invalid --new-app-tip: {e}"))?;
            Ok(ReconcileOutcome::Applied {
                new_app_tip,
                reason,
            })
        }
        (false, true) => {
            let detail = detail.unwrap_or_else(|| {
                unreachable!("clap required_if_eq enforces --detail with --confirmed-not-applied")
            });
            Ok(ReconcileOutcome::NotApplied { detail })
        }
        (false, false) | (true, true) => {
            unreachable!(
                "clap ArgGroup enforces exactly one of --confirmed-applied / --confirmed-not-applied"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the operator-identity mapping: a set value flows through
    /// verbatim; missing or empty falls back to `"unknown"` so the
    /// audit row always lands. Tested on the pure helper so the suite
    /// never mutates `USER` at runtime — `set_var` would race with
    /// Clap's env-aware parsers in other parallel tests.
    #[test]
    fn classify_operator_identity_maps_user_env_with_unknown_fallback() {
        assert_eq!(classify_operator_identity(Some("alice".into())), "alice");
        assert_eq!(classify_operator_identity(Some(String::new())), "unknown");
        assert_eq!(classify_operator_identity(None), "unknown");
    }

    #[test]
    fn resolve_decision_outcome_maps_each_flag() {
        assert_eq!(
            resolve_decision_outcome(true, false),
            DecisionOutcome::Accepted,
        );
        assert_eq!(
            resolve_decision_outcome(false, true),
            DecisionOutcome::RejectedRestart,
        );
    }

    /// `--confirmed-applied` is set and the dependent flags are present.
    /// This pins the field mapping so a future refactor that swaps
    /// argument order at the call site can't silently mis-route values.
    #[test]
    fn resolve_reconcile_outcome_applied_returns_applied_variant() {
        let outcome = resolve_reconcile_outcome(
            true,
            false,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            Some("manual confirmation".into()),
            None,
        )
        .expect("applied resolution should succeed");
        match outcome {
            ReconcileOutcome::Applied {
                new_app_tip,
                reason,
            } => {
                assert_eq!(
                    new_app_tip.as_str(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                );
                assert_eq!(reason, "manual confirmation");
            }
            ReconcileOutcome::NotApplied { .. } => panic!("expected Applied variant"),
        }
    }

    /// Symmetric coverage for the not-applied verdict; `detail` flows
    /// through unchanged.
    #[test]
    fn resolve_reconcile_outcome_not_applied_returns_not_applied_variant() {
        let outcome =
            resolve_reconcile_outcome(false, true, None, None, Some("no remote movement".into()))
                .expect("not-applied resolution should succeed");
        match outcome {
            ReconcileOutcome::NotApplied { detail } => {
                assert_eq!(detail, "no remote movement");
            }
            ReconcileOutcome::Applied { .. } => panic!("expected NotApplied variant"),
        }
    }

    /// A malformed SHA on `--new-app-tip` should fail at the CLI rather
    /// than after the daemon round-trip; the resolver parses it via
    /// `GitObjectId::from_str` and surfaces the parse error verbatim.
    #[test]
    fn resolve_reconcile_outcome_rejects_invalid_new_app_tip() {
        let err = resolve_reconcile_outcome(
            true,
            false,
            Some("not-a-sha".into()),
            Some("manual confirmation".into()),
            None,
        )
        .expect_err("invalid SHA should fail");
        assert!(
            err.to_string().contains("--new-app-tip"),
            "unexpected error: {err}",
        );
    }
}
