//! Cross-cutting validation and SQL conversion helpers used by every
//! domain submodule when parsing rows back from SQLite or projecting
//! audit records into bind parameters.

use rusqlite::{Connection, OptionalExtension, params};

use super::AuditError;
use writ_agent_run::AgentRunStreamSummary;
use writ_core::core::SessionId;

/// Fail if `session_id` is absent or already closed. Runs inside the caller's
/// transaction so the check and the request-row insert commit atomically — the
/// SQL `*_requires_open_session` triggers are belt-and-braces to this.
///
/// This is the single home for the open-session guard every two-phase
/// request-row writer needs: the proxy tables (via `proxy_table`) and the
/// hand-rolled `agent_run` / `flake_provision` / `grant` / `git_push` DAOs, which
/// each previously inlined a byte-identical copy of this `SELECT`-and-`match`.
pub(super) fn check_session_open(
    conn: &Connection,
    session_id: SessionId,
) -> Result<(), AuditError> {
    let session_closed_at: Option<Option<i64>> = conn
        .query_row(
            "SELECT closed_at FROM session WHERE session_id = ?1",
            params![session_id.as_uuid().to_string()],
            |row| row.get(0),
        )
        .optional()?;
    match session_closed_at {
        None => Err(AuditError::Invariant("session does not exist")),
        Some(Some(_)) => Err(AuditError::Invariant("session is closed")),
        Some(None) => Ok(()),
    }
}

pub(super) fn u16_from_sql_status(value: i64) -> Result<u16, AuditError> {
    let status = u16::try_from(value)
        .map_err(|_| AuditError::Invariant("Nix cache audit status is out of range"))?;
    if !(100..=599).contains(&status) {
        return Err(AuditError::Invariant(
            "Nix cache audit status is out of HTTP range",
        ));
    }
    Ok(status)
}

pub(super) fn validate_stream_summary(
    summary: &AgentRunStreamSummary,
    label: &'static str,
) -> Result<(), AuditError> {
    agent_run_stream_path_to_text(&summary.path, label)?;
    validate_sha256_hex(&summary.sha256_hex, label)?;
    Ok(())
}

pub(super) fn validate_sha256_hex(value: &str, label: &'static str) -> Result<(), AuditError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(labeled_invariant(label, "sha256 hex digest is invalid"));
    }
    Ok(())
}

pub(super) fn u64_to_sql_i64(value: u64, label: &'static str) -> Result<i64, AuditError> {
    i64::try_from(value)
        .map_err(|_| labeled_invariant(label, "audit byte count does not fit in SQLite integer"))
}

pub(super) fn path_to_sql_text(
    path: &std::path::Path,
    label: &'static str,
) -> Result<String, AuditError> {
    Ok(agent_run_stream_path_to_text(path, label)?.to_string())
}

pub(super) fn agent_run_stream_path_to_text<'a>(
    path: &'a std::path::Path,
    label: &'static str,
) -> Result<&'a str, AuditError> {
    let Some(path) = path.to_str() else {
        return Err(labeled_invariant(label, "audit path must be valid UTF-8"));
    };
    validate_agent_run_stream_path_text(path, label)?;
    Ok(path)
}

pub(super) fn validate_agent_run_stream_path_text(
    path: &str,
    label: &'static str,
) -> Result<(), AuditError> {
    if path.is_empty() {
        return Err(labeled_invariant(
            label,
            "agent run stream path must not be empty",
        ));
    }
    if !std::path::Path::new(path).is_absolute() {
        return Err(labeled_invariant(
            label,
            "agent run stream path must be absolute",
        ));
    }
    Ok(())
}

pub(super) fn labeled_invariant(label: &'static str, message: &'static str) -> AuditError {
    AuditError::LabeledInvariant { label, message }
}

pub(super) fn bool_to_sql_i64(value: bool) -> i64 {
    i64::from(value)
}

#[cfg(test)]
mod tests {
    use super::check_session_open;
    use crate::test_support::sample_session;
    use crate::{AuditError, AuditLog};
    use proptest::prelude::*;
    use writ_core::core::{SessionId, UnixMillis};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// The single shared guard must classify the three session states exactly
        /// as the five now-removed per-DAO copies did: an open session is `Ok`, a
        /// closed one is `Invariant("session is closed")`, and an id that was never
        /// opened is `Invariant("session does not exist")`. Every hand-rolled
        /// two-phase writer relied on precisely this trichotomy, so a divergence
        /// here is a behaviour change in all of them at once.
        #[test]
        fn check_session_open_classifies_open_closed_and_missing(
            close: bool,
            closed_at_ms in 1_700_000_000i64..1_800_000_000,
        ) {
            let log = AuditLog::open_in_memory().unwrap();
            let s = sample_session();
            log.open_session(&s).unwrap();

            // An id that was never opened: "does not exist" (a fresh random id
            // cannot collide with the sample session).
            let missing = log.with_conn(|c| check_session_open(c, SessionId::new()));
            prop_assert!(
                matches!(missing, Err(AuditError::Invariant("session does not exist"))),
                "got: {missing:?}"
            );

            if close {
                log.close_session(s.session_id, UnixMillis::from_millis(closed_at_ms))
                    .unwrap();
                let closed = log.with_conn(|c| check_session_open(c, s.session_id));
                prop_assert!(
                    matches!(closed, Err(AuditError::Invariant("session is closed"))),
                    "got: {closed:?}"
                );
            } else {
                let open = log.with_conn(|c| check_session_open(c, s.session_id));
                prop_assert!(open.is_ok(), "got: {open:?}");
            }
        }
    }
}
