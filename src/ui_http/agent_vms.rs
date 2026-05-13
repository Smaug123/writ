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

    let mut rows: Vec<AgentVmRow> = Vec::with_capacity(infos.len());
    for info in infos {
        match build_row(service, info) {
            Ok(row) => rows.push(row),
            Err(err) => return err,
        }
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

    match build_row(service, info) {
        Ok(row) => UiHttpResponse::json(200, &AgentVmDetailResponse { row }),
        Err(err) => err,
    }
}

fn build_row(
    service: &UiHttpService,
    info: AgentVmSessionInfo,
) -> Result<AgentVmRow, UiHttpResponse> {
    let session = service
        .audit()
        .get_session(info.session_id)
        .map_err(|err| UiHttpResponse::error_internal(err.to_string()))?;
    let current_run_id = service
        .audit()
        .latest_agent_run_id_for_session(info.session_id)
        .map_err(|err| UiHttpResponse::error_internal(err.to_string()))?;
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
    Ok(AgentVmRow {
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
        current_run_id,
    })
}
