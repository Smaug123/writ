//! `/v1/agent-vms` list and detail handlers.
//!
//! Both routes join the agent VM daemon's runtime view with the audit
//! `session` row and the `current_run_id` derived from the most recent
//! `agent_run`. The daemon is optional at broker boot, so when it is
//! absent the list endpoint returns an empty array and the detail
//! endpoint returns `unknown_session` — neither leaks the missing
//! sub-system to the client.

use crate::agent_run::AgentRunId;
use crate::agent_vm_lifecycle::AgentVmSessionStateStatus;
use crate::audit::SessionRunSummary;
use crate::core::{AgentKind, SessionId, UnixMillis};
use crate::protocol::AgentVmSessionInfo;
use serde::Serialize;

use super::{UiHttpErrorTag, UiHttpResponse, UiHttpService};

#[derive(Serialize)]
pub struct AgentVmListResponse {
    pub agent_vms: Vec<AgentVmRow>,
}

#[derive(Serialize)]
pub struct AgentVmDetailResponse {
    #[serde(flatten)]
    pub row: AgentVmRow,
}

/// One row of `/v1/agent-vms`: the VM daemon's session info joined with
/// the audit session row (label, agent kind/model, open/close times) and
/// the latest agent-run identifier on that session, if any.
#[derive(Serialize)]
pub struct AgentVmRow {
    pub session_id: SessionId,
    pub status: AgentVmSessionStateStatus,
    pub vm_name: String,
    pub network_name: String,
    pub subnet_index: u16,
    pub broker_urls: Vec<String>,
    pub runtime_attached: bool,
    pub label: Option<String>,
    pub agent_kind: Option<AgentKind>,
    pub agent_model: Option<String>,
    pub opened_at: Option<UnixMillis>,
    pub closed_at: Option<UnixMillis>,
    pub current_run_id: Option<AgentRunId>,
}

pub(super) async fn list(service: &UiHttpService) -> UiHttpResponse {
    let Some(daemon) = service.agent_vm() else {
        return UiHttpResponse::json(200, &AgentVmListResponse { agent_vms: vec![] });
    };

    let infos = match daemon.list_sessions().await {
        Ok(infos) => infos,
        Err(err) => return UiHttpResponse::error_internal(err.to_string()),
    };

    // One batched join for the whole listing. Per-VM lookups meant two
    // SQLite round trips *and two mutex acquisitions* per VM per
    // request, which is the one place in this endpoint that grows with
    // the fleet.
    let ids: Vec<SessionId> = infos.iter().map(|info| info.session_id).collect();
    let joined = match service.audit().sessions_with_latest_run(&ids) {
        Ok(joined) => joined,
        Err(err) => return UiHttpResponse::error_internal(err.to_string()),
    };

    let mut rows: Vec<AgentVmRow> = Vec::with_capacity(infos.len());
    for info in infos {
        let summary = joined.get(&info.session_id).cloned().unwrap_or_default();
        rows.push(build_row(info, summary));
    }
    // Newest session first by opened_at; sessions with no audit row sink
    // to the bottom so the active set stays at the top of the listing.
    rows.sort_by(|a, b| match (a.opened_at, b.opened_at) {
        (Some(x), Some(y)) => y.cmp(&x),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    UiHttpResponse::json(200, &AgentVmListResponse { agent_vms: rows })
}

pub(super) async fn detail(service: &UiHttpService, session_id_str: &str) -> UiHttpResponse {
    let session_id = match session_id_str.parse::<SessionId>() {
        Ok(id) => id,
        Err(_) => {
            return UiHttpResponse::error_with_session_id(
                UiHttpErrorTag::MalformedSessionId,
                session_id_str.to_string(),
            );
        }
    };

    let Some(daemon) = service.agent_vm() else {
        return UiHttpResponse::error_with_session_id(
            UiHttpErrorTag::UnknownSession,
            session_id.to_string(),
        );
    };

    let infos = match daemon.list_sessions().await {
        Ok(infos) => infos,
        Err(err) => return UiHttpResponse::error_internal(err.to_string()),
    };

    let Some(info) = infos.into_iter().find(|s| s.session_id == session_id) else {
        return UiHttpResponse::error_with_session_id(
            UiHttpErrorTag::UnknownSession,
            session_id.to_string(),
        );
    };

    // The same batched call with one id, so detail and list cannot
    // drift into answering differently about the same session.
    let joined = match service.audit().sessions_with_latest_run(&[session_id]) {
        Ok(joined) => joined,
        Err(err) => return UiHttpResponse::error_internal(err.to_string()),
    };
    let summary = joined.get(&session_id).cloned().unwrap_or_default();

    UiHttpResponse::json(
        200,
        &AgentVmDetailResponse {
            row: build_row(info, summary),
        },
    )
}

/// Pure projection of the daemon's runtime view plus the audit join.
/// Takes the looked-up summary rather than the service, so the query
/// count is the caller's business and this cannot smuggle in a
/// per-row read.
fn build_row(info: AgentVmSessionInfo, summary: SessionRunSummary) -> AgentVmRow {
    let SessionRunSummary {
        session,
        latest_run_id,
    } = summary;
    let (label, agent_kind, agent_model, opened_at, closed_at) = match session {
        Some(s) => (
            s.label,
            s.agent_kind,
            s.agent_model,
            Some(s.opened_at),
            s.closed_at,
        ),
        None => (None, None, None, None, None),
    };
    AgentVmRow {
        session_id: info.session_id,
        status: info.status,
        vm_name: info.vm_name,
        network_name: info.network_name,
        subnet_index: info.subnet_index,
        broker_urls: info.broker_urls,
        runtime_attached: info.runtime_attached,
        label,
        agent_kind,
        agent_model,
        opened_at,
        closed_at,
        current_run_id: latest_run_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_vm_lifecycle::NetworkHealth;
    use crate::core::SessionRecord;

    fn info(session_id: SessionId) -> AgentVmSessionInfo {
        AgentVmSessionInfo {
            session_id,
            status: AgentVmSessionStateStatus::Running,
            subnet_index: 7,
            vm_name: "writ-vm-7".into(),
            network_name: "writ-net-7".into(),
            broker_urls: vec!["http://192.168.7.1:8080".into()],
            runtime_attached: true,
            network_health: NetworkHealth::unknown(),
        }
    }

    /// The join projects the audit half onto the runtime half without
    /// crossing the two over.
    ///
    /// Testable at all only because `build_row` now takes the
    /// looked-up summary rather than the service: it previously needed
    /// a live `AgentVmDaemon` to reach, so nothing exercised it.
    #[test]
    fn a_row_carries_both_halves_of_the_join() {
        let session_id = SessionId::new();
        let run_id = crate::agent_run::AgentRunId::new();
        let row = build_row(
            info(session_id),
            SessionRunSummary {
                session: Some(SessionRecord {
                    session_id,
                    label: Some("nightly".into()),
                    agent_kind: Some(AgentKind::Codex),
                    agent_model: Some("gpt-5".into()),
                    opened_at: UnixMillis::from_millis(1_700_000_000),
                    closed_at: Some(UnixMillis::from_millis(1_700_000_900)),
                }),
                latest_run_id: Some(run_id),
            },
        );

        assert_eq!(row.session_id, session_id);
        assert_eq!(row.vm_name, "writ-vm-7");
        assert_eq!(row.subnet_index, 7);
        assert_eq!(row.label.as_deref(), Some("nightly"));
        assert_eq!(row.agent_kind, Some(AgentKind::Codex));
        assert_eq!(row.agent_model.as_deref(), Some("gpt-5"));
        assert_eq!(row.opened_at, Some(UnixMillis::from_millis(1_700_000_000)));
        assert_eq!(row.closed_at, Some(UnixMillis::from_millis(1_700_000_900)));
        assert_eq!(row.current_run_id, Some(run_id));
    }

    /// A VM the audit log has never seen still produces a row: the
    /// daemon's runtime view survives and only the audit half is
    /// `None`. Dropping such a VM from the listing would hide exactly
    /// the session an operator is most likely to be hunting.
    #[test]
    fn a_session_with_no_audit_row_keeps_its_runtime_half() {
        let session_id = SessionId::new();
        let row = build_row(info(session_id), SessionRunSummary::default());

        assert_eq!(row.session_id, session_id);
        assert_eq!(row.vm_name, "writ-vm-7");
        assert!(row.runtime_attached);
        assert_eq!(row.label, None);
        assert_eq!(row.agent_kind, None);
        assert_eq!(row.agent_model, None);
        assert_eq!(row.opened_at, None);
        assert_eq!(row.closed_at, None);
        assert_eq!(row.current_run_id, None);
    }
}
