//! Plan submission: serves the per-session VM-facing
//! `POST /v1/plans` endpoint by parsing one [`PlanSubmission`], binding
//! it to the requesting agent run, and writing it to the audit log.
//!
//! The route does not yet enforce `agent_run.stage = 'plan'`; that
//! check lands in slice 3 once the `agent_run.stage` column exists.
//! What this slice *does* enforce is cross-session authorisation: the
//! `agent_run_id` named in the request body must belong to the bearer
//! session calling the route, so one VM cannot attach a plan to a run
//! it does not own.

use std::sync::Arc;

use crate::agent_plan::{PlanCreated, PlanId, PlanSubmission, VM_PLANS_PATH_PREFIX};
use crate::audit::{AUDIT_WRITE_FAILURE_TARGET, AuditError, PlanSubmissionRecord};
use crate::core::UnixMillis;
use crate::secret::SecretStore;
use crate::server::BrokerState;

use super::{VmHttpRequest, VmHttpResponse, VmHttpSession, VmHttpStatus};

pub struct VmHttpPlanService<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
}

impl<S: SecretStore> VmHttpPlanService<S> {
    pub fn new(broker_state: Arc<BrokerState<S>>) -> Self {
        Self { broker_state }
    }
}

impl<S: SecretStore> Clone for VmHttpPlanService<S> {
    fn clone(&self) -> Self {
        Self {
            broker_state: Arc::clone(&self.broker_state),
        }
    }
}

impl<S: SecretStore> std::fmt::Debug for VmHttpPlanService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmHttpPlanService").finish_non_exhaustive()
    }
}

pub(super) fn is_plans_collection_target(target: &str) -> bool {
    target == VM_PLANS_PATH_PREFIX
}

pub(super) async fn route_plans_collection_request<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    body: Vec<u8>,
    service: VmHttpPlanService<S>,
) -> VmHttpResponse {
    if request.method != "POST" {
        return VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed");
    }
    handle_plan_submission(session, body, service).await
}

async fn handle_plan_submission<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    body: Vec<u8>,
    service: VmHttpPlanService<S>,
) -> VmHttpResponse {
    let submission = match serde_json::from_slice::<PlanSubmission>(&body) {
        Ok(submission) => submission,
        Err(err) => {
            return VmHttpResponse::text(
                VmHttpStatus::BadRequest,
                format!("invalid plan submission: {err}"),
            );
        }
    };
    drop(body);

    let audit = &service.broker_state.audit;
    let calling_session = session.session_id();
    match audit.get_agent_run(submission.agent_run_id) {
        Ok(Some(run)) if run.session_id == calling_session => {}
        Ok(Some(_)) => {
            // The run exists but belongs to a different session. Treat
            // this as unauthorised rather than not-found: the caller
            // knows enough to name a real run id, but isn't the owner.
            return VmHttpResponse::text(
                VmHttpStatus::Unauthorized,
                "agent run does not belong to this session",
            );
        }
        Ok(None) => {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "agent run does not exist");
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_submission_run_lookup",
                run_id = %submission.agent_run_id,
                error = %err,
                "audit read failed",
            );
            return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit read failed");
        }
    }

    let plan_id = PlanId::new();
    let record = PlanSubmissionRecord {
        plan_id,
        agent_run_id: submission.agent_run_id,
        submitted_at: UnixMillis::now(),
        body: submission.body,
    };
    match audit.record_plan_submission(&record) {
        Ok(()) => VmHttpResponse::json(VmHttpStatus::Ok, &PlanCreated { plan_id }),
        Err(AuditError::Invariant("agent run does not exist")) => {
            // The run existed at the lookup above and now doesn't — a
            // session race or audit corruption. Surface as 410 Gone so
            // the caller can distinguish "you never had this run" from
            // "your run vanished mid-request".
            VmHttpResponse::text(VmHttpStatus::Gone, "agent run no longer exists")
        }
        Err(AuditError::Invariant("session is closed")) => {
            VmHttpResponse::text(VmHttpStatus::Gone, "session is closed")
        }
        Err(AuditError::Sqlite(err))
            if err.to_string().to_uppercase().contains("UNIQUE") =>
        {
            // The `UNIQUE(agent_run_id)` invariant in the plan table:
            // one plan per planner run.
            VmHttpResponse::text(
                VmHttpStatus::Conflict,
                "plan already submitted for this run",
            )
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_submission",
                run_id = %submission.agent_run_id,
                plan_id = %plan_id,
                error = %err,
                "audit write failed",
            );
            VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use wiremock::MockServer;

    use super::super::tests::{
        bearer, make_broker_state, no_services, open_audit_session, session_for_subnet, token,
    };
    use super::super::{
        VM_HTTP_READ_TIMEOUT, VmHttpRequest, VmHttpServices, VmHttpStatus,
        dispatch_vm_http_head_and_body, route_authenticated_vm_http_request,
    };
    use super::*;
    use crate::agent_plan::PlanBody;
    use crate::agent_run::{AgentPrompt, AgentRunId};
    use crate::audit::AgentRunAuditRecord;
    use crate::core::{AgentKind, Ipv4Cidr, SessionId, SessionRecord, UnixMillis};
    use crate::secret::SecretStore;
    use crate::server::BrokerState;

    pub(super) fn plan_service_for_test(
        state: &Arc<BrokerState<Box<dyn SecretStore>>>,
    ) -> VmHttpPlanService<Box<dyn SecretStore>> {
        VmHttpPlanService::new(Arc::clone(state))
    }

    fn services_with_plans(
        plans: VmHttpPlanService<Box<dyn SecretStore>>,
    ) -> VmHttpServices<Box<dyn SecretStore>> {
        VmHttpServices {
            git_clone: None,
            nix_cache: None,
            claude_proxy: None,
            openai_proxy: None,
            agent_runs: None,
            git_push: None,
            plans: Some(plans),
        }
    }

    fn record_planner_run(
        state: &BrokerState<Box<dyn SecretStore>>,
        session_id: SessionId,
    ) -> AgentRunId {
        let run_id = AgentRunId::new();
        state
            .audit
            .record_agent_run(&AgentRunAuditRecord {
                run_id,
                session_id,
                requested_at: UnixMillis::now(),
                agent_kind: AgentKind::Claude,
                prompt: AgentPrompt::new("plan this").summary(),
                correlation_id: None,
            })
            .unwrap();
        run_id
    }

    fn open_session_for(state: &BrokerState<Box<dyn SecretStore>>, session_id: SessionId) {
        state
            .audit
            .open_session(&SessionRecord {
                session_id,
                label: Some("plan-test".into()),
                agent_kind: Some(AgentKind::Claude),
                agent_model: None,
                opened_at: UnixMillis::now(),
                closed_at: None,
            })
            .unwrap();
    }

    fn submission_body(run_id: AgentRunId, body: &str) -> Vec<u8> {
        serde_json::to_vec(&PlanSubmission {
            agent_run_id: run_id,
            body: PlanBody::try_new(body).unwrap(),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn disabled_plans_route_is_not_found_for_all_methods() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345));

        for method in ["GET", "POST", "PUT", "DELETE"] {
            let request = VmHttpRequest::new(
                method,
                VM_PLANS_PATH_PREFIX,
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
    async fn enabled_plans_route_rejects_non_post_methods() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let service = plan_service_for_test(&state);
        let request = VmHttpRequest::new(
            "GET",
            VM_PLANS_PATH_PREFIX,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
        );

        let response = route_authenticated_vm_http_request(
            &session,
            &request,
            Vec::new(),
            services_with_plans(service),
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::MethodNotAllowed);
    }

    #[tokio::test]
    async fn plan_submission_rejects_malformed_body_without_audit() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let service = plan_service_for_test(&state);

        let response = handle_plan_submission(&session, b"not json".to_vec(), service).await;

        assert_eq!(response.status, VmHttpStatus::BadRequest);
        assert!(
            state
                .audit
                .list_plans_for_session(session.session_id())
                .unwrap()
                .is_empty(),
        );
    }

    #[tokio::test]
    async fn plan_submission_rejects_unknown_run() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let service = plan_service_for_test(&state);
        // A run id the audit log has never seen.
        let body = submission_body(AgentRunId::new(), "# Plan");

        let response = handle_plan_submission(&session, body, service).await;

        assert_eq!(response.status, VmHttpStatus::NotFound);
        assert!(
            state
                .audit
                .list_plans_for_session(session.session_id())
                .unwrap()
                .is_empty(),
        );
    }

    #[tokio::test]
    async fn plan_submission_rejects_run_owned_by_other_session() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        // A second session that owns the run; the calling session does not.
        let other_session_id: SessionId =
            "82ab0bb1-7c12-4a4e-9f51-6d3d77011111".parse().unwrap();
        open_session_for(&state, other_session_id);
        let stranger_run = record_planner_run(&state, other_session_id);
        let service = plan_service_for_test(&state);

        let body = submission_body(stranger_run, "# Plan");
        let response = handle_plan_submission(&session, body, service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        assert!(
            state
                .audit
                .list_plans_for_session(session.session_id())
                .unwrap()
                .is_empty(),
        );
        // The plan also did not land under the other session.
        assert!(
            state
                .audit
                .list_plans_for_session(other_session_id)
                .unwrap()
                .is_empty(),
        );
    }

    #[tokio::test]
    async fn plan_submission_records_audit_row_and_returns_plan_id() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id = record_planner_run(&state, session.session_id());
        let service = plan_service_for_test(&state);

        let response =
            handle_plan_submission(&session, submission_body(run_id, "# Plan body"), service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let created: PlanCreated = serde_json::from_slice(&response.body).unwrap();

        let stored = state.audit.get_plan(created.plan_id).unwrap().unwrap();
        assert_eq!(stored.plan_id, created.plan_id);
        assert_eq!(stored.agent_run_id, run_id);
        assert_eq!(stored.body.as_str(), "# Plan body");

        // Roundtrip via list_plans_for_session.
        let list = state
            .audit
            .list_plans_for_session(session.session_id())
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].plan_id, created.plan_id);
    }

    #[tokio::test]
    async fn plan_submission_rejects_second_plan_for_same_run() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id = record_planner_run(&state, session.session_id());

        let first =
            handle_plan_submission(&session, submission_body(run_id, "# First"), plan_service_for_test(&state))
                .await;
        assert_eq!(first.status, VmHttpStatus::Ok);

        let second = handle_plan_submission(
            &session,
            submission_body(run_id, "# Second"),
            plan_service_for_test(&state),
        )
        .await;
        assert_eq!(second.status, VmHttpStatus::Conflict);

        let list = state
            .audit
            .list_plans_for_session(session.session_id())
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].body.as_str(), "# First");
    }

    #[tokio::test]
    async fn plan_submission_closed_session_returns_gone() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id = record_planner_run(&state, session.session_id());
        state
            .audit
            .close_session(session.session_id(), UnixMillis::now())
            .unwrap();
        let service = plan_service_for_test(&state);

        let response =
            handle_plan_submission(&session, submission_body(run_id, "# Plan"), service).await;

        assert_eq!(response.status, VmHttpStatus::Gone);
        assert!(
            state
                .audit
                .list_plans_for_session(session.session_id())
                .unwrap()
                .is_empty(),
        );
    }

    /// Regression for the body-limit budget: a maximum-size body packed
    /// with bytes that JSON expands maximally (`\0` → `\u0000`, 6× per
    /// byte) must still be admitted. The route's `Limited::collect` cap
    /// gates on *encoded* bytes, so a tight `MAX_PLAN_BODY_BYTES + small
    /// envelope` budget would reject this even though `PlanBody::try_new`
    /// is happy to accept the decoded value.
    #[tokio::test]
    async fn plan_submission_admits_max_body_with_worst_case_json_expansion() {
        use crate::agent_plan::MAX_PLAN_BODY_BYTES;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id = record_planner_run(&state, session.session_id());
        let service = plan_service_for_test(&state);

        let raw_body = "\0".repeat(MAX_PLAN_BODY_BYTES);
        let body = submission_body(run_id, &raw_body);
        assert!(
            body.len() > MAX_PLAN_BODY_BYTES,
            "test premise: encoded body must exceed the decoded length",
        );
        let bearer_auth = bearer(token().as_str());
        let content_length = body.len().to_string();
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "POST",
            VM_PLANS_PATH_PREFIX,
            &[
                ("authorization", bearer_auth.as_str()),
                ("content-length", content_length.as_str()),
            ],
            body,
            services_with_plans(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let created: PlanCreated = serde_json::from_slice(&response.body).unwrap();
        let stored = state.audit.get_plan(created.plan_id).unwrap().unwrap();
        assert_eq!(stored.body.byte_len() as usize, MAX_PLAN_BODY_BYTES);
    }

    #[tokio::test]
    async fn plan_submission_full_dispatch_records_audit() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id = record_planner_run(&state, session.session_id());
        let service = plan_service_for_test(&state);

        let bearer_auth = bearer(token().as_str());
        let body = submission_body(run_id, "# Plan via dispatch");
        let content_length = body.len().to_string();
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "POST",
            VM_PLANS_PATH_PREFIX,
            &[
                ("authorization", bearer_auth.as_str()),
                ("content-length", content_length.as_str()),
            ],
            body,
            services_with_plans(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let created: PlanCreated = serde_json::from_slice(&response.body).unwrap();
        let stored = state.audit.get_plan(created.plan_id).unwrap().unwrap();
        assert_eq!(stored.body.as_str(), "# Plan via dispatch");
    }

}
