//! Shared test fixtures used by the audit submodules' inline tests.

use super::{AuditError, AuditLog, HostMintAuditTable, HostMintOutcome, PreMintRecord};
use writ_core::core::CredentialGrant;
use writ_core::core::{
    AgentKind, CapabilityRequest, GitHubAccess, GitHubGrantedScope, GitHubPermissions,
    GitHubRequest, GrantedScope, MetadataAccess, PolicyDecision, RepoRef, RequestId, SessionId,
    SessionRecord, UnixMillis,
};

pub(super) fn sample_session() -> SessionRecord {
    SessionRecord {
        session_id: SessionId::new(),
        label: Some("test".into()),
        agent_kind: Some(AgentKind::Claude),
        agent_model: Some("claude-opus-4-7".into()),
        opened_at: UnixMillis::from_millis(1_700_000_000),
        closed_at: None,
    }
}

pub(super) fn sample_repo() -> RepoRef {
    RepoRef {
        owner: "o".into(),
        name: "n".into(),
    }
}

pub(super) fn sample_request() -> CapabilityRequest {
    CapabilityRequest::GitHub(GitHubRequest::Contents {
        access: GitHubAccess::Write,
        repo: sample_repo(),
    })
}

pub(super) fn sample_scope() -> GrantedScope {
    GrantedScope::GitHub(GitHubGrantedScope {
        repository: sample_repo(),
        permissions: GitHubPermissions {
            contents: Some(GitHubAccess::Write),
            metadata: Some(MetadataAccess::Read),
            ..Default::default()
        },
    })
}

/// Write the mint's request row on its own, so a later [`record_grant`] or
/// [`record_mint_failure`] has something to attach to.
pub(super) fn pre_mint(
    log: &AuditLog,
    request_id: RequestId,
    session_id: SessionId,
    request: &CapabilityRequest,
    decision: &PolicyDecision,
    received_at: UnixMillis,
) -> Result<(), AuditError> {
    log.seed_effect_request::<HostMintAuditTable>(&PreMintRecord {
        request_id,
        session_id,
        received_at,
        request,
        decision,
    })
}

/// Write the `Granted` ending of a mint on its own.
pub(super) fn record_grant(log: &AuditLog, grant: &CredentialGrant) -> Result<(), AuditError> {
    log.seed_effect_outcome::<HostMintAuditTable>(&HostMintOutcome::Granted(grant))
}

/// Write the `Failed` ending of a mint on its own.
pub(super) fn record_mint_failure(
    log: &AuditLog,
    request_id: RequestId,
    failed_at: UnixMillis,
    error: &str,
) -> Result<(), AuditError> {
    log.seed_effect_outcome::<HostMintAuditTable>(&HostMintOutcome::Failed {
        request_id,
        failed_at,
        error,
    })
}
