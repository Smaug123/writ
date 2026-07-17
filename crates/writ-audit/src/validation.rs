//! Cross-cutting validation and SQL conversion helpers used by every
//! domain submodule when parsing rows back from SQLite or projecting
//! audit records into bind parameters.

use super::AuditError;
use writ_agent_run::AgentRunStreamSummary;

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
