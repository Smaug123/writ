//! Read-side primitive for observing an agent run's recorded outcome.
//!
//! [`wait_for_agent_run_outcome`] polls the audit log for the outcome row
//! the guest POSTs to `/v1/agent-runs/<id>/outcome`; it drives no VM
//! lifecycle. The parent daemon's synchronous `RunAgent` dispatch wires it
//! between starting the run and reading the result.

use crate::agent_run::AgentRunId;

/// Errors returned by [`wait_for_agent_run_outcome`].
///
/// `Timeout` carries the elapsed deadline rather than a free-form
/// message so the synchronous `RunAgent` dispatch arm (slice VM2b) can
/// format a stable operator-facing message and verifiers can assert on
/// the structured fields. `Audit` propagates the underlying audit
/// failure verbatim — a poll that surfaces an audit error is almost
/// always a sign the broker is wedged (the in-memory SQLite handle is
/// poisoned, the disk is gone), not a transient miss.
#[derive(Debug, thiserror::Error)]
pub enum WaitForAgentRunOutcomeError {
    #[error("agent run {run_id} did not complete within {timeout:?}")]
    Timeout {
        run_id: AgentRunId,
        timeout: std::time::Duration,
    },
    #[error("audit lookup failed: {0}")]
    Audit(#[from] crate::audit::AuditError),
}

/// Poll the audit log for `run_id`'s outcome row until it appears, the
/// audit lookup fails, or `timeout` elapses. The wait helper does not
/// drive the VM's lifecycle — it is a one-shot read-side primitive for
/// the synchronous-wait shape that slice VM2b's `RunAgent` dispatch
/// arm needs (the guest POSTs `/v1/agent-runs/<id>/outcome`, which
/// writes the row from `route_agent_run_outcome_request`; this helper
/// observes that write).
///
/// `poll_interval` bounds how often the audit table is queried; the
/// final sleep is clamped to the remaining deadline so an oversized
/// `poll_interval` cannot stretch the call past `timeout`. `Duration::ZERO`
/// for either parameter is legal: with zero timeout the helper checks
/// once and returns Timeout if the row is absent; with zero interval
/// the helper spins (only sensible when the row is expected to be
/// already present).
pub async fn wait_for_agent_run_outcome(
    audit: &crate::audit::AuditLog,
    run_id: AgentRunId,
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
) -> Result<crate::audit::AgentRunOutcomeAuditRecord, WaitForAgentRunOutcomeError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(record) = audit.get_agent_run_outcome(run_id)? {
            return Ok(record);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(WaitForAgentRunOutcomeError::Timeout { run_id, timeout });
        }
        let remaining = deadline.saturating_duration_since(now);
        tokio::time::sleep(poll_interval.min(remaining)).await;
    }
}
