//! Shared test fixtures used by the audit submodules' inline tests.

use super::{AuditError, AuditLog, PreMintRecord};
use crate::core::{
    AgentKind, CapabilityRequest, CredentialGrant, GitHubAccess, GitHubGrantedScope,
    GitHubPermissions, GitHubRequest, GrantedScope, Jti, MetadataAccess, PolicyDecision, RepoRef,
    RequestId, SessionId, SessionRecord, TtlSeconds, UnixMillis,
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

/// Stash the request+decision row so subsequent `record_grant` or
/// `record_mint_failure` calls have something to attach to.
pub(super) fn pre_mint(
    log: &AuditLog,
    request_id: RequestId,
    session_id: SessionId,
    request: &CapabilityRequest,
    decision: &PolicyDecision,
    received_at: UnixMillis,
) -> Result<(), AuditError> {
    log.record_pre_mint(&PreMintRecord {
        request_id,
        session_id,
        received_at,
        request,
        decision,
    })
}

pub(super) fn record_sample_write_grant(
    log: &AuditLog,
    session_id: SessionId,
    capability_request_id: RequestId,
) -> CredentialGrant {
    let req = sample_request();
    let scope = sample_scope();
    pre_mint(
        log,
        capability_request_id,
        session_id,
        &req,
        &PolicyDecision::Grant {
            scope: scope.clone(),
            ttl: TtlSeconds::new(300).unwrap(),
        },
        UnixMillis::from_millis(1_700_000_110),
    )
    .unwrap();
    let grant = CredentialGrant {
        jti: Jti::new(),
        request_id: capability_request_id,
        session_id,
        github_app_id: Some(42),
        scope,
        issued_at: UnixMillis::from_millis(1_700_000_110),
        expires_at: UnixMillis::from_millis(1_700_000_410),
    };
    log.record_grant(&grant).unwrap();
    grant
}
