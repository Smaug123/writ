//! Git push: serves the per-session VM-facing `POST /v1/git/push` endpoint
//! by persisting the agent's git bundle and metadata to a host-local
//! staging area for human review. The broker does *not* contact GitHub
//! during a VM push; promotion to the remote happens later, out of band.

use std::sync::Arc;

use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, GitPushOutcomeRecord, GitPushOutcomeResult,
    GitPushRequestRecord,
};
use crate::core::{RequestId, UnixMillis};
use crate::git_push_staging::{GitPushStagingStore, StagingError};
use crate::secret::SecretStore;
use crate::server::BrokerState;
use crate::vm_git::{
    VM_GIT_PUSH_PATH, VmGitPushBodyError, VmGitPushBodyLimits, VmGitPushErrorCode,
    VmGitPushErrorResponse, parse_vm_git_push_request_body,
};

use super::{VmHttpRequest, VmHttpResponse, VmHttpSession, VmHttpStatus};

pub struct VmHttpGitPushService<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    staging_store: Arc<GitPushStagingStore>,
    body_limits: VmGitPushBodyLimits,
}

impl<S: SecretStore> VmHttpGitPushService<S> {
    pub fn new(
        broker_state: Arc<BrokerState<S>>,
        staging_store: Arc<GitPushStagingStore>,
        body_limits: VmGitPushBodyLimits,
    ) -> Self {
        Self {
            broker_state,
            staging_store,
            body_limits,
        }
    }

    pub(super) fn body_limits(&self) -> VmGitPushBodyLimits {
        self.body_limits
    }
}

impl<S: SecretStore> Clone for VmHttpGitPushService<S> {
    fn clone(&self) -> Self {
        Self {
            broker_state: Arc::clone(&self.broker_state),
            staging_store: Arc::clone(&self.staging_store),
            body_limits: self.body_limits,
        }
    }
}

impl<S: SecretStore> std::fmt::Debug for VmHttpGitPushService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmHttpGitPushService")
            .field("staging_root", &self.staging_store.root())
            .field("body_limits", &self.body_limits)
            .finish_non_exhaustive()
    }
}

pub(super) fn is_git_push_target(target: &str) -> bool {
    target == VM_GIT_PUSH_PATH
}

pub(super) async fn route_git_push_request<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    body: Vec<u8>,
    service: VmHttpGitPushService<S>,
) -> VmHttpResponse {
    if request.method != "POST" {
        return VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
    }
    handle_git_push_request(session, body, service).await
}

async fn handle_git_push_request<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    body: Vec<u8>,
    service: VmHttpGitPushService<S>,
) -> VmHttpResponse {
    let parsed = match parse_vm_git_push_request_body(&body, service.body_limits) {
        Ok(parsed) => parsed,
        Err(err) => {
            return git_push_error_response(
                VmHttpStatus::BadRequest,
                VmGitPushErrorCode::InvalidRequest,
                body_error_message(&err),
            );
        }
    };
    drop(body);

    let push_request_id = RequestId::new();
    let received_at = UnixMillis::now();
    let (metadata, bundle) = parsed.into_parts();

    // Inherit the run's correlation id (if any) so a push staged by a
    // `--correlation-id`'d agent run carries the same join key. The
    // correlation belongs to the run; the push merely participates.
    // Untagged sessions and non-run sessions return `None` and the
    // column stays NULL.
    let correlation_id = match service
        .broker_state
        .audit
        .correlation_id_for_session(session.session_id())
    {
        Ok(value) => value,
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_request_correlation_lookup",
                push_request_id = %push_request_id,
                error = %err,
                "audit read failed",
            );
            return git_push_error_response(
                VmHttpStatus::InternalServerError,
                VmGitPushErrorCode::PushFailed,
                "audit read failed",
            );
        }
    };

    let record = GitPushRequestRecord {
        push_request_id,
        session_id: session.session_id(),
        received_at,
        repo: metadata.repo().clone(),
        branch: metadata.branch().clone(),
        expected_remote_head: metadata.expected_remote_head().cloned(),
        new_head: metadata.new_head().clone(),
        correlation_id,
    };
    match service.broker_state.audit.record_git_push_request(&record) {
        Ok(()) => {}
        Err(AuditError::Invariant("session does not exist")) => {
            return git_push_error_response(
                VmHttpStatus::Unauthorized,
                VmGitPushErrorCode::Denied,
                "session is not active",
            );
        }
        Err(AuditError::Invariant("session is closed")) => {
            return git_push_error_response(
                VmHttpStatus::Gone,
                VmGitPushErrorCode::Denied,
                "session is closed",
            );
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_request",
                push_request_id = %push_request_id,
                error = %err,
                "audit write failed",
            );
            return git_push_error_response(
                VmHttpStatus::InternalServerError,
                VmGitPushErrorCode::PushFailed,
                "audit write failed",
            );
        }
    }

    let staged_at = UnixMillis::now();
    let staging_result = {
        let staging_store = Arc::clone(&service.staging_store);
        let metadata_for_staging = metadata.clone();
        tokio::task::spawn_blocking(move || {
            staging_store.stage(push_request_id, staged_at, metadata_for_staging, bundle)
        })
        .await
    };

    let staging_result = match staging_result {
        Ok(result) => result,
        Err(join_err) => {
            tracing::error!(
                push_request_id = %push_request_id,
                error = %join_err,
                "git push staging task panicked",
            );
            return git_push_error_response(
                VmHttpStatus::InternalServerError,
                VmGitPushErrorCode::PushFailed,
                "staging task failed",
            );
        }
    };

    match staging_result {
        Ok(receipt) => {
            if let Err(err) = record_unattempted_outcome(
                &service,
                push_request_id,
                GitPushOutcomeResult::Staged,
                "staged for review",
            ) {
                tracing::error!(
                    target: AUDIT_WRITE_FAILURE_TARGET,
                    kind = "git_push_outcome",
                    push_request_id = %push_request_id,
                    error = %err,
                    "audit write failed",
                );
                return git_push_error_response(
                    VmHttpStatus::InternalServerError,
                    VmGitPushErrorCode::PushFailed,
                    "audit write failed",
                );
            }
            VmHttpResponse::json(VmHttpStatus::Ok, &receipt)
        }
        Err(StagingError::Conflict { .. }) => {
            if let Err(err) = record_unattempted_outcome(
                &service,
                push_request_id,
                GitPushOutcomeResult::Denied,
                "staged content conflict",
            ) {
                tracing::error!(
                    target: AUDIT_WRITE_FAILURE_TARGET,
                    kind = "git_push_outcome",
                    push_request_id = %push_request_id,
                    error = %err,
                    "audit write failed",
                );
                return git_push_error_response(
                    VmHttpStatus::InternalServerError,
                    VmGitPushErrorCode::PushFailed,
                    "audit write failed",
                );
            }
            git_push_error_response(
                VmHttpStatus::Conflict,
                VmGitPushErrorCode::Denied,
                "different content already staged for this request id",
            )
        }
        Err(err) => {
            // Deliberately leave the request row without an outcome: a
            // staging IO failure is the failure mode that needs human
            // triage rather than silent reclassification.
            tracing::error!(
                push_request_id = %push_request_id,
                error = %err,
                "git push staging failed",
            );
            git_push_error_response(
                VmHttpStatus::InternalServerError,
                VmGitPushErrorCode::PushFailed,
                "staging failed",
            )
        }
    }
}

fn record_unattempted_outcome<S: SecretStore>(
    service: &VmHttpGitPushService<S>,
    push_request_id: RequestId,
    result: GitPushOutcomeResult,
    message: &str,
) -> Result<(), AuditError> {
    service
        .broker_state
        .audit
        .record_git_push_outcome(&GitPushOutcomeRecord {
            push_request_id,
            push_attempt_id: None,
            completed_at: UnixMillis::now(),
            result,
            github_status: None,
            message,
        })
}

fn git_push_error_response(
    status: VmHttpStatus,
    error: VmGitPushErrorCode,
    message: impl Into<String>,
) -> VmHttpResponse {
    VmHttpResponse::json(status, &VmGitPushErrorResponse::new(error, message))
}

fn body_error_message(err: &VmGitPushBodyError) -> String {
    format!("invalid Git push request: {err}")
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::super::tests::{
        bearer, make_broker_state, no_services, open_audit_session, session_for_subnet, token,
    };
    use super::super::{
        VM_HTTP_READ_TIMEOUT, VmHttpRequest, VmHttpServices, VmHttpStatus,
        dispatch_vm_http_head_and_body, route_authenticated_vm_http_request,
    };
    use super::*;
    use crate::audit::GitPushOutcomeResult;
    use crate::core::{Ipv4Cidr, UnixMillis};
    use crate::secret::SecretStore;
    use crate::server::BrokerState;
    use crate::vm_git::{
        GitBranchName, GitCloneRepo, GitObjectId, VmGitPushMetadata, VmGitPushRequest,
        VmGitPushStagedReceipt, encode_vm_git_push_request_body,
    };

    fn test_body_limits() -> VmGitPushBodyLimits {
        VmGitPushBodyLimits::new(64 * 1024, 8 * 1024, 64 * 1024).unwrap()
    }

    fn open_test_staging_store() -> (Arc<GitPushStagingStore>, TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = GitPushStagingStore::open(tmp.path().join("staging")).unwrap();
        (Arc::new(store), tmp)
    }

    pub(super) fn git_push_service_for_test(
        state: &Arc<BrokerState<Box<dyn SecretStore>>>,
        staging: Arc<GitPushStagingStore>,
    ) -> VmHttpGitPushService<Box<dyn SecretStore>> {
        VmHttpGitPushService::new(Arc::clone(state), staging, test_body_limits())
    }

    fn sample_repo() -> GitCloneRepo {
        "owner/repo".parse().unwrap()
    }

    fn sample_branch() -> GitBranchName {
        "feature/x".parse().unwrap()
    }

    fn oid(nibble: char) -> GitObjectId {
        std::iter::repeat_n(nibble, 40)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    fn sample_metadata() -> VmGitPushMetadata {
        VmGitPushMetadata::new(sample_repo(), sample_branch(), Some(oid('a')), oid('b'))
    }

    fn encoded_body(metadata: VmGitPushMetadata, bundle: Vec<u8>) -> Vec<u8> {
        let request = VmGitPushRequest::new(metadata, bundle).unwrap();
        encode_vm_git_push_request_body(&request).unwrap()
    }

    fn services_with_git_push(
        git_push: VmHttpGitPushService<Box<dyn SecretStore>>,
    ) -> VmHttpServices<Box<dyn SecretStore>> {
        VmHttpServices {
            git_clone: None,
            nix_cache: None,
            claude_proxy: None,
            openai_proxy: None,
            agent_runs: None,
            git_push: Some(git_push),
        }
    }

    #[tokio::test]
    async fn disabled_git_push_route_is_not_found_for_all_methods() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345));

        for method in ["GET", "POST"] {
            let request = VmHttpRequest::new(
                method,
                VM_GIT_PUSH_PATH,
                Some(bearer(token().as_str())),
                peer,
            );
            let response =
                route_authenticated_vm_http_request(&session, &request, Vec::new(), no_services())
                    .await
                    .into_buffered();

            assert_eq!(response.status, VmHttpStatus::NotFound);
        }
    }

    #[tokio::test]
    async fn enabled_git_push_route_is_not_found_for_non_post_methods() {
        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let (staging, _tmp) = open_test_staging_store();
        let service = git_push_service_for_test(&state, staging);
        let request = VmHttpRequest::new(
            "GET",
            VM_GIT_PUSH_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
        );

        let response = route_authenticated_vm_http_request(
            &session,
            &request,
            Vec::new(),
            services_with_git_push(service),
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn disabled_git_push_route_does_not_read_declared_body() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let bearer_auth = bearer(token().as_str());
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dispatch_vm_http_head_and_body(
                &session,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
                "POST",
                VM_GIT_PUSH_PATH,
                &[
                    ("authorization", bearer_auth.as_str()),
                    ("content-length", "1"),
                ],
                Vec::new(),
                no_services(),
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("disabled Git push route must not wait for a declared body");

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn git_push_rejects_malformed_body_without_audit() {
        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let (staging, _tmp) = open_test_staging_store();
        let service = git_push_service_for_test(&state, staging);

        let response = handle_git_push_request(&session, b"too short".to_vec(), service).await;

        assert_eq!(response.status, VmHttpStatus::BadRequest);
        let body: VmGitPushErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmGitPushErrorCode::InvalidRequest);
        assert!(
            state
                .audit
                .list_git_pushes_for_session(session.session_id())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn git_push_unknown_session_returns_unauthorized_without_audit_row() {
        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        // No `open_audit_session` — the session is unknown to the audit log.
        let (staging, _tmp) = open_test_staging_store();
        let service = git_push_service_for_test(&state, staging);

        let body = encoded_body(sample_metadata(), b"bundle bytes".to_vec());
        let response = handle_git_push_request(&session, body, service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        let parsed: VmGitPushErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(parsed.error(), VmGitPushErrorCode::Denied);
        assert_eq!(parsed.message(), "session is not active");
        assert!(
            state
                .audit
                .list_git_pushes_for_session(session.session_id())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn git_push_closed_session_returns_gone_without_audit_row() {
        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        state
            .audit
            .close_session(session.session_id(), UnixMillis::now())
            .unwrap();
        let (staging, _tmp) = open_test_staging_store();
        let service = git_push_service_for_test(&state, staging);

        let body = encoded_body(sample_metadata(), b"bundle".to_vec());
        let response = handle_git_push_request(&session, body, service).await;

        assert_eq!(response.status, VmHttpStatus::Gone);
        let parsed: VmGitPushErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(parsed.error(), VmGitPushErrorCode::Denied);
        assert_eq!(parsed.message(), "session is closed");
        assert!(
            state
                .audit
                .list_git_pushes_for_session(session.session_id())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn git_push_stages_bundle_and_returns_receipt() {
        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let (staging, _tmp) = open_test_staging_store();
        let service = git_push_service_for_test(&state, Arc::clone(&staging));

        let metadata = sample_metadata();
        let bundle = b"PACK bundle bytes".to_vec();
        let body = encoded_body(metadata.clone(), bundle.clone());
        let response = handle_git_push_request(&session, body, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let receipt: VmGitPushStagedReceipt = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(receipt.repo(), metadata.repo());
        assert_eq!(receipt.branch(), metadata.branch());
        assert_eq!(
            receipt.expected_remote_head(),
            metadata.expected_remote_head()
        );
        assert_eq!(receipt.new_head(), metadata.new_head());

        let loaded = staging.load(receipt.push_request_id()).unwrap();
        assert_eq!(loaded.bundle(), bundle.as_slice());

        let audit_entries = state
            .audit
            .list_git_pushes_for_session(session.session_id())
            .unwrap();
        assert_eq!(audit_entries.len(), 1);
        let entry = &audit_entries[0];
        assert_eq!(entry.push_request_id, receipt.push_request_id());
        assert_eq!(entry.result, Some(GitPushOutcomeResult::Staged));
        assert_eq!(entry.message.as_deref(), Some("staged for review"));
        assert!(entry.push_attempt_id.is_none());
    }

    /// A push from a `--correlation-id`'d agent run inherits the run's
    /// correlation id onto the `git_push_request` audit row, so a
    /// downstream join on `correlation_id` stitches the run and its
    /// pushes together.
    #[tokio::test]
    async fn git_push_inherits_correlation_id_from_tagged_agent_run() {
        use crate::agent_plan::CorrelationId;
        use crate::agent_run::{AgentPrompt, AgentRunId};
        use crate::audit::AgentRunAuditRecord;
        use crate::core::AgentKind;

        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let correlation = CorrelationId::try_new("feat-42_xyz").unwrap();
        state
            .audit
            .record_agent_run(&AgentRunAuditRecord {
                run_id: AgentRunId::new(),
                session_id: session.session_id(),
                requested_at: UnixMillis::now(),
                agent_kind: AgentKind::Claude,
                prompt: AgentPrompt::new("prompt").summary(),
                correlation_id: Some(correlation.clone()),
            })
            .unwrap();
        let (staging, _tmp) = open_test_staging_store();

        let body = encoded_body(sample_metadata(), b"tagged bundle".to_vec());
        let response = handle_git_push_request(
            &session,
            body,
            git_push_service_for_test(&state, Arc::clone(&staging)),
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let receipt: VmGitPushStagedReceipt = serde_json::from_slice(&response.body).unwrap();
        let entry = state
            .audit
            .get_git_push(receipt.push_request_id())
            .unwrap()
            .expect("push row exists");
        assert_eq!(entry.correlation_id, Some(correlation));
    }

    /// A session with no `agent_run` row — the raw-VM-session path —
    /// has nothing to inherit from, so the push's `correlation_id`
    /// stays NULL.
    #[tokio::test]
    async fn git_push_without_agent_run_leaves_correlation_id_null() {
        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let (staging, _tmp) = open_test_staging_store();

        let body = encoded_body(sample_metadata(), b"untagged bundle".to_vec());
        let response = handle_git_push_request(
            &session,
            body,
            git_push_service_for_test(&state, Arc::clone(&staging)),
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let receipt: VmGitPushStagedReceipt = serde_json::from_slice(&response.body).unwrap();
        let entry = state
            .audit
            .get_git_push(receipt.push_request_id())
            .unwrap()
            .expect("push row exists");
        assert!(entry.correlation_id.is_none());
    }

    /// An agent run with no correlation id (the un-`--correlation-id`'d
    /// case) gives the push nothing to inherit, so the column stays
    /// NULL even though the run exists.
    #[tokio::test]
    async fn git_push_with_untagged_agent_run_leaves_correlation_id_null() {
        use crate::agent_run::{AgentPrompt, AgentRunId};
        use crate::audit::AgentRunAuditRecord;
        use crate::core::AgentKind;

        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        state
            .audit
            .record_agent_run(&AgentRunAuditRecord {
                run_id: AgentRunId::new(),
                session_id: session.session_id(),
                requested_at: UnixMillis::now(),
                agent_kind: AgentKind::Claude,
                prompt: AgentPrompt::new("prompt").summary(),
                correlation_id: None,
            })
            .unwrap();
        let (staging, _tmp) = open_test_staging_store();

        let body = encoded_body(sample_metadata(), b"untagged-run bundle".to_vec());
        let response = handle_git_push_request(
            &session,
            body,
            git_push_service_for_test(&state, Arc::clone(&staging)),
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let receipt: VmGitPushStagedReceipt = serde_json::from_slice(&response.body).unwrap();
        let entry = state
            .audit
            .get_git_push(receipt.push_request_id())
            .unwrap()
            .expect("push row exists");
        assert!(entry.correlation_id.is_none());
    }

    #[tokio::test]
    async fn git_push_idempotent_replay_with_same_payload_succeeds_for_new_request_id() {
        // Each fresh HTTP request mints a new `push_request_id`, so identical
        // payloads from a retry are independent staged entries from the
        // staging store's perspective. The staging store's own idempotency
        // path is exercised in its unit tests.
        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let (staging, _tmp) = open_test_staging_store();

        let metadata = sample_metadata();
        let bundle = b"bundle".to_vec();
        let body_one = encoded_body(metadata.clone(), bundle.clone());
        let body_two = encoded_body(metadata, bundle);

        let r1 = handle_git_push_request(
            &session,
            body_one,
            git_push_service_for_test(&state, Arc::clone(&staging)),
        )
        .await;
        let r2 = handle_git_push_request(
            &session,
            body_two,
            git_push_service_for_test(&state, Arc::clone(&staging)),
        )
        .await;

        assert_eq!(r1.status, VmHttpStatus::Ok);
        assert_eq!(r2.status, VmHttpStatus::Ok);
        let p1: VmGitPushStagedReceipt = serde_json::from_slice(&r1.body).unwrap();
        let p2: VmGitPushStagedReceipt = serde_json::from_slice(&r2.body).unwrap();
        assert_ne!(p1.push_request_id(), p2.push_request_id());
        assert_eq!(staging.list().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn git_push_branch_creation_round_trips_with_null_expected_head() {
        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let (staging, _tmp) = open_test_staging_store();
        let service = git_push_service_for_test(&state, Arc::clone(&staging));

        let metadata = VmGitPushMetadata::new(sample_repo(), sample_branch(), None, oid('c'));
        let body = encoded_body(metadata.clone(), b"create-bundle".to_vec());
        let response = handle_git_push_request(&session, body, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let receipt: VmGitPushStagedReceipt = serde_json::from_slice(&response.body).unwrap();
        assert!(receipt.expected_remote_head().is_none());
        let loaded = staging.load(receipt.push_request_id()).unwrap();
        assert!(loaded.receipt().expected_remote_head().is_none());
    }

    #[tokio::test]
    async fn git_push_full_dispatch_stages_and_audits() {
        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let (staging, _tmp) = open_test_staging_store();
        let service = git_push_service_for_test(&state, Arc::clone(&staging));

        let bearer_auth = bearer(token().as_str());
        let metadata = sample_metadata();
        let body = encoded_body(metadata.clone(), b"PACK from dispatch".to_vec());
        let content_length = body.len().to_string();
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "POST",
            VM_GIT_PUSH_PATH,
            &[
                ("authorization", bearer_auth.as_str()),
                ("content-length", content_length.as_str()),
            ],
            body,
            services_with_git_push(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let receipt: VmGitPushStagedReceipt = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(receipt.repo(), metadata.repo());
        assert_eq!(staging.list().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn git_push_dispatch_rejects_body_exceeding_limit() {
        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let (staging, _tmp) = open_test_staging_store();
        // Tight body cap so an oversized request is cheap to construct.
        let tight = VmGitPushBodyLimits::new(128, 64, 64).unwrap();
        let service = VmHttpGitPushService::new(Arc::clone(&state), Arc::clone(&staging), tight);

        let bearer_auth = bearer(token().as_str());
        let oversized = vec![0u8; 1024];
        let content_length = oversized.len().to_string();
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "POST",
            VM_GIT_PUSH_PATH,
            &[
                ("authorization", bearer_auth.as_str()),
                ("content-length", content_length.as_str()),
            ],
            oversized,
            services_with_git_push(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::BadRequest);
        assert!(staging.list().unwrap().is_empty());
        assert!(
            state
                .audit
                .list_git_pushes_for_session(session.session_id())
                .unwrap()
                .is_empty()
        );
    }
}
