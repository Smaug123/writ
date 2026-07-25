//! Git push: serves the per-session VM-facing `POST /v1/git/push` endpoint
//! by persisting the agent's git bundle and metadata to a host-local
//! staging area for human review. The broker does *not* contact GitHub
//! during a VM push; promotion to the remote happens later, out of band.

use std::sync::Arc;

use crate::agent_run::CorrelationId;
use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, AuditLog, GitPushAuditTable, GitPushOutcomeRecord,
    GitPushOutcomeResult, GitPushRequestRecord, RecordedRequest,
};
use crate::core::{RequestId, SessionId, UnixMillis};
use crate::git_push_staging::{GitPushStagingStore, StagingError};
use crate::secret::SecretStore;
use crate::server::BrokerState;
use crate::vm_git::{
    VM_GIT_PUSH_PATH, VmGitPushBodyError, VmGitPushBodyLimits, VmGitPushErrorCode,
    VmGitPushErrorResponse, VmGitPushMetadata, parse_vm_git_push_request_body,
};

use super::broker_effect::{BrokeredEffect, EffectCompletion, broker_effect};
use super::{VmHttpDispatch, VmHttpRequest, VmHttpResponse, VmHttpSession, VmHttpStatus};

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

    /// The audit log this service records into — the `broker_effect` driver's
    /// `begin_effect`/`complete` receiver.
    pub(super) fn audit(&self) -> &Arc<AuditLog> {
        &self.broker_state.audit
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
) -> VmHttpDispatch {
    if request.method != "POST" {
        return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
    }
    handle_git_push_dispatch(session, body, service).await
}

/// Drive a git-push VM-stage request through the `broker_effect` guard: the
/// driver begins the request row, [`GitPushEffect::perform`] stages the bundle,
/// and the driver completes the `Staged`/`Denied` outcome — or, on a staging-IO
/// failure that has no truthful outcome, the effect *abandons* the guard, leaving
/// the request row dangling for boot recovery (`reconcile_orphaned_staged_carriers`
/// recovers an on-disk carrier; `reconcile_unpaired_effect_rows` flags a
/// genuinely-stuck row).
async fn handle_git_push_dispatch<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    body: Vec<u8>,
    service: VmHttpGitPushService<S>,
) -> VmHttpDispatch {
    // Reject-before-begin: a malformed body or a failed correlation read returns
    // a client response and records *no* audit row (the driver begins the request
    // row only for a well-formed request).
    let effect = match GitPushEffect::new(session, body, &service) {
        Ok(effect) => effect,
        Err(response) => return response.into(),
    };
    broker_effect(service.audit(), effect).await
}

/// Test-only wrapper returning the buffered response directly — a git-push
/// response never streams — so the example-based and crash-injection tests read
/// the `VmHttpResponse` unchanged.
#[cfg(test)]
async fn handle_git_push_request<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    body: Vec<u8>,
    service: VmHttpGitPushService<S>,
) -> VmHttpResponse {
    handle_git_push_dispatch(session, body, service)
        .await
        .into_buffered()
}

/// A git-push VM-stage request modelled as a [`BrokeredEffect`]. The
/// `broker_effect` driver owns the audit sequencing (begin the request row, run
/// `perform`, complete or abandon the outcome), so the staging effect cannot
/// reach the guest without recording — or deliberately abandoning — its pair.
struct GitPushEffect<'a, S: SecretStore + Send + Sync + 'static> {
    service: &'a VmHttpGitPushService<S>,
    push_request_id: RequestId,
    session_id: SessionId,
    received_at: UnixMillis,
    metadata: VmGitPushMetadata,
    correlation_id: Option<CorrelationId>,
    bundle: Vec<u8>,
}

/// Owned outcome payload for a git-push effect; [`BrokeredEffect::outcome_row`]
/// borrows a `GitPushOutcomeRecord` out of it. Only the *resolvable* outcomes are
/// here (`Staged` / `Denied`); a staging-IO failure has no truthful outcome and is
/// abandoned instead.
struct GitPushOutcomeData {
    push_request_id: RequestId,
    result: GitPushOutcomeResult,
    message: &'static str,
}

impl GitPushOutcomeData {
    fn staged(push_request_id: RequestId) -> Self {
        Self {
            push_request_id,
            result: GitPushOutcomeResult::Staged,
            message: "staged for review",
        }
    }

    fn denied(push_request_id: RequestId, message: &'static str) -> Self {
        Self {
            push_request_id,
            result: GitPushOutcomeResult::Denied,
            message,
        }
    }
}

impl<'a, S: SecretStore + Send + Sync + 'static> GitPushEffect<'a, S> {
    /// Parse and preflight *before* any audit row is begun (reject-before-begin):
    /// a malformed body (`400`) or a failed correlation-id read (`500`) returns a
    /// client response and records nothing. The request row is begun only by the
    /// driver, after this succeeds.
    fn new(
        session: &VmHttpSession,
        body: Vec<u8>,
        service: &'a VmHttpGitPushService<S>,
    ) -> Result<Self, VmHttpResponse> {
        let parsed =
            parse_vm_git_push_request_body(&body, service.body_limits()).map_err(|err| {
                git_push_error_response(
                    VmHttpStatus::BadRequest,
                    VmGitPushErrorCode::InvalidRequest,
                    body_error_message(&err),
                )
            })?;
        // Release the ~max_body_bytes encoded body as soon as `parsed` owns its
        // copy — before the correlation lookup below, which can block on the audit
        // mutex behind a slow SQLite write; holding both the encoded body and the
        // bundle per blocked worker doubles peak memory under concurrent pushes.
        drop(body);
        let push_request_id = RequestId::new();
        // Stamp arrival *before* the (mutex-blocking) audit lookup, so
        // `received_at` orders pushes by when the broker received them, not by
        // audit-write contention (`list_git_pushes_for_session` sorts by it).
        let received_at = UnixMillis::now();
        let (metadata, bundle) = parsed.into_parts();

        // Inherit the run's correlation id (if any) so a push staged by a
        // `--correlation-id`'d agent run carries the same join key. The
        // correlation belongs to the run; the push merely participates. Untagged
        // sessions and non-run sessions return `None` and the column stays NULL.
        let correlation_id = service
            .audit()
            .correlation_id_for_session(session.session_id())
            .map_err(|err| {
                tracing::error!(
                    target: AUDIT_WRITE_FAILURE_TARGET,
                    kind = "git_push_request_correlation_lookup",
                    push_request_id = %push_request_id,
                    error = %err,
                    "audit read failed",
                );
                git_push_error_response(
                    VmHttpStatus::InternalServerError,
                    VmGitPushErrorCode::PushFailed,
                    "audit read failed",
                )
            })?;

        Ok(Self {
            service,
            push_request_id,
            session_id: session.session_id(),
            received_at,
            metadata,
            correlation_id,
            bundle,
        })
    }
}

impl<'a, S: SecretStore + Send + Sync + 'static> BrokeredEffect for GitPushEffect<'a, S> {
    type Table = GitPushAuditTable;
    type Outcome = GitPushOutcomeData;
    const REQUEST_AUDIT_KIND: &'static str = "git_push_request";
    const OUTCOME_AUDIT_KIND: &'static str = "git_push_outcome";

    fn audit_key(&self) -> impl std::fmt::Display + '_ {
        self.push_request_id
    }

    fn request_row(&self) -> GitPushRequestRecord {
        // `GitPushRequestRecord` owns its fields and is not `Clone`, so rebuild it
        // from the stored metadata (cheap: a repo/branch and two object ids).
        GitPushRequestRecord {
            push_request_id: self.push_request_id,
            session_id: self.session_id,
            received_at: self.received_at,
            repo: self.metadata.repo().clone(),
            branch: self.metadata.branch().clone(),
            expected_remote_head: self.metadata.expected_remote_head().cloned(),
            new_head: self.metadata.new_head().clone(),
            correlation_id: self.correlation_id.clone(),
        }
    }

    async fn perform(self) -> EffectCompletion<Self> {
        let GitPushEffect {
            service,
            push_request_id,
            metadata,
            bundle,
            ..
        } = self;
        let staged_at = UnixMillis::now();
        let staging_result = {
            let staging_store = Arc::clone(&service.staging_store);
            tokio::task::spawn_blocking(move || {
                staging_store.stage(push_request_id, staged_at, metadata, bundle)
            })
            .await
        };

        let staging_result = match staging_result {
            Ok(result) => result,
            Err(join_err) => {
                // The blocking task panicked: no truthful outcome exists, so
                // abandon (dangling row for boot recovery) rather than fabricate.
                tracing::error!(
                    push_request_id = %push_request_id,
                    error = %join_err,
                    "git push staging task panicked",
                );
                return abandoned_git_push(git_push_error_response(
                    VmHttpStatus::InternalServerError,
                    VmGitPushErrorCode::PushFailed,
                    "staging task failed",
                ));
            }
        };

        match staging_result {
            Ok(receipt) => {
                // Durable effect: the carrier is fsynced and atomically renamed
                // into `staged/`, so any carrier visible there is complete. The
                // driver next commits the `Staged` outcome; if *that* write fails,
                // the carrier is left on disk (the driver touches no filesystem)
                // for `reconcile_orphaned_staged_carriers` to recover on the next
                // boot — never torn by a non-atomic delete here.
                crate::crash_point::point("git_push::carrier_staged").await;
                EffectCompletion::Buffered {
                    outcome: GitPushOutcomeData::staged(push_request_id),
                    response: VmHttpResponse::json(VmHttpStatus::Ok, &receipt),
                }
            }
            Err(StagingError::Conflict { .. }) => EffectCompletion::Buffered {
                outcome: GitPushOutcomeData::denied(push_request_id, "staged content conflict"),
                response: git_push_error_response(
                    VmHttpStatus::Conflict,
                    VmGitPushErrorCode::Denied,
                    "different content already staged for this request id",
                ),
            },
            Err(err) => {
                // A staging IO failure needs human triage, not silent
                // reclassification: abandon so the request row is left dangling.
                tracing::error!(
                    push_request_id = %push_request_id,
                    error = %err,
                    "git push staging failed",
                );
                abandoned_git_push(git_push_error_response(
                    VmHttpStatus::InternalServerError,
                    VmGitPushErrorCode::PushFailed,
                    "staging failed",
                ))
            }
        }
    }

    fn outcome_row(outcome: &GitPushOutcomeData) -> GitPushOutcomeRecord<'_> {
        GitPushOutcomeRecord {
            push_request_id: outcome.push_request_id,
            completed_at: UnixMillis::now(),
            result: outcome.result,
            github_status: None,
            message: outcome.message,
        }
    }

    fn begin_error_response(err: &AuditError) -> Option<VmHttpResponse> {
        // A closed/unknown session is a clean client error, not an audit-write
        // failure — return the domain response and skip the 500 + tracing event.
        match err {
            AuditError::Invariant("session does not exist") => Some(git_push_error_response(
                VmHttpStatus::Unauthorized,
                VmGitPushErrorCode::Denied,
                "session is not active",
            )),
            AuditError::Invariant("session is closed") => Some(git_push_error_response(
                VmHttpStatus::Gone,
                VmGitPushErrorCode::Denied,
                "session is closed",
            )),
            _ => None,
        }
    }

    fn audit_write_failure_response() -> VmHttpResponse {
        // Preserve the typed envelope in the audit-fault mode: the endpoint always
        // answered a JSON `VmGitPushErrorResponse`, so a `begin`/`complete` audit
        // failure keeps that contract rather than the driver's plain-text 500.
        git_push_error_response(
            VmHttpStatus::InternalServerError,
            VmGitPushErrorCode::PushFailed,
            "audit write failed",
        )
    }
}

/// Build an [`EffectCompletion::Abandoned`] for git-push: given the live guard,
/// [`abandon`](RecordedRequest::abandon) it (no outcome — the deliberate dangling
/// row) and return `response`. The `abandon` call is available because
/// `GitPushAuditTable: AbandonableEffect`.
fn abandoned_git_push<'a, S: SecretStore + Send + Sync + 'static>(
    response: VmHttpResponse,
) -> EffectCompletion<GitPushEffect<'a, S>> {
    EffectCompletion::Abandoned(Box::new(
        move |guard: RecordedRequest<GitPushAuditTable>| {
            guard.abandon();
            response.into()
        },
    ))
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
        dispatch_vm_http_head_and_body, resolve_and_route_authenticated_vm_http_request,
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
            flake_provision: None,
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
            let response = resolve_and_route_authenticated_vm_http_request(
                &session,
                &request,
                Vec::new(),
                no_services(),
            )
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

        let response = resolve_and_route_authenticated_vm_http_request(
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
    }

    /// Stage-0 audit-pair oracle applied to a *real current handler*: driving
    /// `handle_git_push_request` on its happy path must leave the
    /// `(git_push_request, git_push_outcome)` pair complete — the two-phase
    /// request-row-before-effect, outcome-row-after discipline this handler wires
    /// by hand. See `docs/plans/2026-07-18-brokered-effect-audit-enforcement.md`
    /// §4; the oracle primitive lives in `writ-audit::effect_audit_oracle`.
    #[tokio::test]
    async fn git_push_handler_satisfies_audit_pair_oracle() {
        let github = wiremock::MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let (staging, _tmp) = open_test_staging_store();
        let service = git_push_service_for_test(&state, staging);

        let before = state.audit.table_row_count_for_test("git_push_outcome");
        let body = encoded_body(sample_metadata(), b"PACK bundle bytes".to_vec());
        let response = handle_git_push_request(&session, body, service).await;
        assert_eq!(response.status, VmHttpStatus::Ok);

        // Non-vacuity: the drive actually reached a recorded terminal state...
        assert_eq!(
            state.audit.table_row_count_for_test("git_push_outcome"),
            before + 1,
            "the staged push must record exactly one outcome row",
        );
        // ...and the invariant holds: no staged request lacks its outcome row.
        state.audit.assert_effect_audit_pairs_complete(
            "git_push_request",
            "git_push_outcome",
            "push_request_id",
        );
    }

    /// A push from a `--correlation-id`'d agent run inherits the run's
    /// correlation id onto the `git_push_request` audit row, so a
    /// downstream join on `correlation_id` stitches the run and its
    /// pushes together.
    #[tokio::test]
    async fn git_push_inherits_correlation_id_from_tagged_agent_run() {
        use crate::agent_run::{AgentPrompt, AgentRunId, CorrelationId};
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

    /// The invariant this whole fix protects: for a crash at *every*
    /// durable-effect boundary in the push handler, running the boot
    /// carrier sweep afterwards leaves the world in a resolvable state —
    /// any carrier still on disk has a `staged` outcome row (so it is
    /// both approvable and rejectable), and there is never a carrier
    /// stuck without one. Uses the crash-injection harness's count-then-
    /// sweep pattern so a newly-added point widens coverage automatically.
    #[tokio::test]
    async fn crash_between_effects_leaves_every_carrier_resolvable_after_sweep() {
        use crate::boot_reconcile::reconcile_orphaned_staged_carriers;
        use crate::crash_point::{CrashPlan, run_until_crash};

        let github = wiremock::MockServer::start().await;

        // One counting run to learn how many crash points the handler has.
        let n = {
            let state = make_broker_state(&github);
            let session =
                session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
            open_audit_session(&state, session.session_id());
            let (staging, _tmp) = open_test_staging_store();
            let plan = CrashPlan::count();
            run_until_crash(
                &plan,
                handle_git_push_request(
                    &session,
                    encoded_body(sample_metadata(), b"bundle".to_vec()),
                    git_push_service_for_test(&state, staging),
                ),
            )
            .await
            .expect_completed("counting run must not crash");
            plan.points_passed()
        };
        assert!(
            n >= 3,
            "handler must instrument its three durable effects (got {n})",
        );

        // A crash before the driver commits the outcome drops a *live* audit
        // guard; modeled as an interruption (not the guard's bug backstop), it is
        // observable on the crash outcome. Assert the modeling actually engages —
        // otherwise a regression that silently paniced (or never held a guard)
        // would slip past.
        let mut saw_git_push_interruption = false;
        for k in 0..n {
            let state = make_broker_state(&github);
            let session =
                session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
            open_audit_session(&state, session.session_id());
            let (staging, _tmp) = open_test_staging_store();
            let plan = CrashPlan::crash_at(k);
            let outcome = run_until_crash(
                &plan,
                handle_git_push_request(
                    &session,
                    encoded_body(sample_metadata(), b"bundle".to_vec()),
                    git_push_service_for_test(&state, Arc::clone(&staging)),
                ),
            )
            .await;
            saw_git_push_interruption |= outcome.interrupted_guards().contains(&"Git push");

            // Boot recovery: the sweep the daemon runs at startup.
            reconcile_orphaned_staged_carriers(
                &state.audit,
                &staging,
                crate::git_push_staging::recovery_receipt_bound(64 * 1024),
                UnixMillis::now(),
            )
            .unwrap();

            // Oracle: any carrier still on disk is resolvable.
            for receipt in staging.list().unwrap() {
                let entry = state
                    .audit
                    .get_git_push(receipt.push_request_id())
                    .unwrap()
                    .expect("a carrier on disk must have an audit request row");
                assert_eq!(
                    entry.result,
                    Some(GitPushOutcomeResult::Staged),
                    "crash at point {k}: carrier {} left unresolvable",
                    receipt.push_request_id(),
                );
            }
        }
        assert!(
            saw_git_push_interruption,
            "a crash before the outcome commit must abort a live git-push guard, \
             modeled as an interruption",
        );
    }

    /// Part 1 (online repair): when the `Staged` outcome write fails while
    /// the process is alive, the handler deletes the carrier before
    /// returning failure, so no stuck carrier is left behind. The failure
    /// is forced deterministically by pre-empting the outcome row (with a
    /// terminal `Denied`) at the post-staging crash point, tripping the
    /// primary key on the handler's own write.
    /// Part 1: when the `Staged` outcome write fails while the process
    /// is alive, the handler must leave the intact carrier on disk — it
    /// must not delete it, because `delete` is a non-atomic
    /// `remove_dir_all` whose interruption would tear the carrier and
    /// make it unrecoverable. Leaving the complete carrier lets the boot
    /// sweep recover it (that handoff — intact carrier, no outcome row →
    /// `Staged` — is exercised by the crash oracle above and by
    /// `boot_reconcile`'s `orphaned_carrier_is_recovered_to_staged`).
    ///
    /// The failure is forced deterministically by pre-empting the outcome
    /// row at the post-staging crash point, tripping the primary key on
    /// the handler's own write.
    #[tokio::test]
    async fn outcome_write_failure_leaves_the_carrier_intact_for_recovery() {
        use crate::audit::GitPushOutcomeRecord;
        use crate::crash_point::{CrashPlan, run_until_crash};

        let github = wiremock::MockServer::start().await;

        let idx = {
            let state = make_broker_state(&github);
            let session =
                session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
            open_audit_session(&state, session.session_id());
            let (staging, _tmp) = open_test_staging_store();
            let plan = CrashPlan::count();
            run_until_crash(
                &plan,
                handle_git_push_request(
                    &session,
                    encoded_body(sample_metadata(), b"x".to_vec()),
                    git_push_service_for_test(&state, staging),
                ),
            )
            .await
            .expect_completed("counting run must not crash");
            plan.names()
                .iter()
                .position(|name| *name == "git_push::carrier_staged")
                .expect("handler must have a carrier_staged crash point")
        };

        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let (staging, _tmp) = open_test_staging_store();

        let audit_for_action = Arc::clone(&state.audit);
        let staging_for_action = Arc::clone(&staging);
        let plan = CrashPlan::act_at(idx, move || {
            let id = staging_for_action.list().unwrap()[0].push_request_id();
            audit_for_action
                .record_git_push_outcome(&GitPushOutcomeRecord {
                    push_request_id: id,
                    completed_at: UnixMillis::from_millis(1),
                    result: GitPushOutcomeResult::Denied,
                    github_status: None,
                    message: "pre-empted to force outcome-write failure",
                })
                .unwrap();
        });

        let response = run_until_crash(
            &plan,
            handle_git_push_request(
                &session,
                encoded_body(sample_metadata(), b"x".to_vec()),
                git_push_service_for_test(&state, Arc::clone(&staging)),
            ),
        )
        .await
        .expect_completed("act mode must not park");

        assert!(plan.acted(), "the pre-empting action must have fired");
        assert_eq!(response.status, VmHttpStatus::InternalServerError);
        // The audit-fault mode keeps the typed Git-push envelope, not the
        // driver's plain-text 500.
        let parsed: VmGitPushErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(parsed.error(), VmGitPushErrorCode::PushFailed);
        assert_eq!(parsed.message(), "audit write failed");

        // The carrier must be preserved *and complete* — both the
        // receipt and the bundle — so the boot sweep can recover it.
        let carriers = staging.list().unwrap();
        assert_eq!(
            carriers.len(),
            1,
            "the carrier must be left intact, not deleted, on an outcome-write failure",
        );
        let loaded = staging.load(carriers[0].push_request_id()).unwrap();
        assert_eq!(loaded.bundle(), b"x");
    }
}
