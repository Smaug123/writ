//! `/v1/agent-runs/{run_id}` — the operator's read view of one agent run.
//!
//! `/v1/agent-vms` has always exposed `current_run_id` and said the run
//! itself was "exposed through its own resource". This is that resource.
//! Until it existed, the columns an operator most wants after a run —
//! `purpose`, `correlation_id`, the exit code, the stream paths — were
//! reachable only by opening the audit database with `sqlite3`.
//!
//! **This is a projection of the audit log, not a second source of
//! truth.** Every field is read from the `agent_run` and
//! `agent_run_outcome` rows and nothing is recomputed, so the resource
//! cannot disagree with what `writ agent verify` checks. In particular
//! it does *not* re-hash the stream files to confirm they still match
//! `sha256_hex`: this endpoint reports what was recorded, and
//! corroborating that against the bytes on disk is
//! [`crate::run_provenance`]'s job. An operator reading `sha256_hex`
//! here is reading a claim made at completion time, which is the only
//! thing the audit row can honestly offer.
//!
//! Keyed by run id rather than nested under the session, because a run
//! outlives its VM — the audit rows survive `close_agent_vm_session`,
//! so nesting would make the reachable set shrink as sessions end.

use crate::agent_run::{
    AgentPromptSummary, AgentRunId, AgentRunStreamSummary, AgentRunTerminalStatus, CorrelationId,
    RunPurpose,
};
use crate::core::{AgentKind, SessionId, UnixMillis};
use serde::Serialize;

use super::{UiHttpErrorTag, UiHttpResponse, UiHttpService};

/// One agent run: the request row, plus the outcome row if the run has
/// finished.
///
/// Every key is always present, including `null`s. A UI polling a
/// running agent should see `"outcome": null` become an object rather
/// than a key appear from nowhere, and "the field is absent" and "the
/// field is not yet known" are the same state here — so there is
/// nothing for `skip_serializing_if` to express.
#[derive(Serialize)]
pub struct AgentRunDetailResponse {
    pub run_id: AgentRunId,
    pub session_id: SessionId,
    pub requested_at: UnixMillis,
    pub agent_kind: AgentKind,
    /// `None` has two truthful readings — the run predates migration 8,
    /// or it came through `StartAgentRun`, which has no purpose field —
    /// and the resource deliberately does not guess between them.
    pub purpose: Option<RunPurpose>,
    pub correlation_id: Option<CorrelationId>,
    pub prompt: AgentPromptSummary,
    /// `None` while the run is in flight, and also for a run whose
    /// outcome row was never written (the daemon died mid-run). The
    /// audit log cannot distinguish those, so neither does this.
    pub outcome: Option<AgentRunOutcomeView>,
}

/// The outcome row, minus the `run_id` it repeats from its parent.
///
/// [`crate::agent_run::AgentRunOutcome`] carries `run_id` because it
/// travels alone over the guest upload path; here it is already the
/// key of the enclosing resource, and emitting it twice invites a
/// reader to wonder when the two could differ. They cannot: the
/// lookup is by that id.
#[derive(Serialize)]
pub struct AgentRunOutcomeView {
    pub completed_at: UnixMillis,
    pub status: AgentRunTerminalStatus,
    pub exit_code: i32,
    pub stdout: AgentRunStreamSummary,
    pub stderr: AgentRunStreamSummary,
}

pub(super) fn detail(service: &UiHttpService, run_id_str: &str) -> UiHttpResponse {
    let Ok(run_id) = run_id_str.parse::<AgentRunId>() else {
        return UiHttpResponse::error_with_run_id(
            UiHttpErrorTag::MalformedRunId,
            run_id_str.to_string(),
        );
    };

    let request = match service.audit().get_agent_run(run_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return UiHttpResponse::error_with_run_id(
                UiHttpErrorTag::UnknownRun,
                run_id.to_string(),
            );
        }
        Err(err) => return UiHttpResponse::error_internal(err.to_string()),
    };

    // Read the outcome *after* the request row, so the pair can only
    // ever be stale in the direction that reads as "still running".
    // The other order could observe an outcome written between the two
    // reads while missing the request row entirely, and report a
    // finished run as unknown.
    let outcome = match service.audit().get_agent_run_outcome(run_id) {
        Ok(o) => o,
        Err(err) => return UiHttpResponse::error_internal(err.to_string()),
    };

    UiHttpResponse::json(
        200,
        &AgentRunDetailResponse {
            run_id: request.run_id,
            session_id: request.session_id,
            requested_at: request.requested_at,
            agent_kind: request.agent_kind,
            purpose: request.purpose,
            correlation_id: request.correlation_id,
            prompt: request.prompt,
            outcome: outcome.map(|o| AgentRunOutcomeView {
                completed_at: o.completed_at,
                status: o.outcome.status,
                exit_code: o.outcome.exit_code,
                stdout: o.outcome.stdout,
                stderr: o.outcome.stderr,
            }),
        },
    )
}

#[cfg(test)]
mod tests;
