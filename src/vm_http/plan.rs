//! Plan VM HTTP routes. Two endpoints today, both served from this
//! module:
//!
//! - `POST /v1/plans` — a planner submits a plan body.
//! - `GET  /v1/plans/<plan_id>` — a reviewer or implementer reads the
//!   plan body, decision (when set), and originating-run id.
//!
//! Submission runs two gates before the audit write:
//!
//! 1. **Cross-session:** the `agent_run_id` named in the request body
//!    must belong to the bearer session calling the route, so one VM
//!    cannot attach a plan to a run it does not own.
//! 2. **Per-stage:** the named run must be at `stage = 'plan'`. The
//!    pure stage→action gate is
//!    [`route_permitted_by_stage_and_decision`]; this route invokes it
//!    with [`PlanRouteAction::SubmitPlan`] so a review- or execute-
//!    stage run cannot smuggle a plan submission past the audit log.
//!
//! The read route gates on the bearer session's run, not a body-named
//! run (the URL has no body):
//!
//! 1. **Session→run:** the bearer's session must own an `agent_run` row
//!    (else 401 — no run on this session to authorise as).
//! 2. **Binding:** that run's `read_plan_id` must equal the requested
//!    `<plan_id>` (else 401 — the run is not the one bound to this
//!    plan).
//! 3. **Per-stage:** the run's stage must permit `ReadPlan`. Slice 4
//!    short-circuits the decision-gate branch to "always-accepted";
//!    slice 6 will land the real `plan_decision.outcome = 'accepted'`
//!    check.

use std::sync::Arc;

use crate::agent_plan::{
    DecisionOutcome, DecisionView, PlanCreated, PlanId, PlanRouteAction, PlanRouteAuthError,
    PlanSubmission, PlanView, VM_PLANS_PATH_PREFIX, route_permitted_by_stage_and_decision,
};
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

/// Recognises a per-plan target shaped exactly `/v1/plans/<plan_id>`
/// (no trailing slash, no further path components, no query string).
/// Sub-routes like `/v1/plans/<plan_id>/reviews` belong to later
/// slices and are deliberately *not* matched here; this keeps the
/// dispatcher's match ordering simple.
pub(super) fn parse_plan_id_target(target: &str) -> Option<PlanId> {
    let suffix = target
        .strip_prefix(VM_PLANS_PATH_PREFIX)?
        .strip_prefix('/')?;
    if suffix.contains('/') {
        return None;
    }
    suffix.parse().ok()
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

pub(super) async fn route_plan_id_request<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    plan_id: PlanId,
    service: VmHttpPlanService<S>,
) -> VmHttpResponse {
    if request.method != "GET" {
        return VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed");
    }
    handle_plan_read(session, plan_id, service).await
}

async fn handle_plan_read<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    plan_id: PlanId,
    service: VmHttpPlanService<S>,
) -> VmHttpResponse {
    let audit = &service.broker_state.audit;
    let calling_session = session.session_id();

    let run = match audit.agent_run_for_session(calling_session) {
        Ok(Some(run)) => run,
        Ok(None) => {
            // The bearer authenticated this session, but no agent_run
            // exists on it. Today this means a raw-VM session (no
            // `start_agent_run_session` was issued); such a session
            // has no role in the plan pipeline and therefore no
            // authority to read any plan.
            return VmHttpResponse::text(
                VmHttpStatus::Unauthorized,
                "no agent run on this session",
            );
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_read_run_lookup",
                plan_id = %plan_id,
                session_id = %calling_session,
                error = %err,
                "audit read failed",
            );
            return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit read failed");
        }
    };

    // Binding gate runs *before* the stage gate so we don't leak
    // which stages can read plans to a caller who isn't bound to
    // this plan. The 401 (not 403) mirrors the submission route's
    // session-ownership distinction: "authenticated but not the
    // run bound to this plan."
    if run.read_plan_id != Some(plan_id) {
        return VmHttpResponse::text(
            VmHttpStatus::Unauthorized,
            "agent run is not bound to this plan",
        );
    }

    // Per-stage gate. Slice 4 short-circuits the decision branch by
    // claiming "always accepted" so an execute-stage implementer can
    // pull the plan body before slice 6 lands the real
    // `plan_decision.outcome = 'accepted'` check. Review-stage runs
    // already pass the gate regardless of decision, so the
    // short-circuit only affects the execute path.
    let decision_for_gate = Some(DecisionOutcome::Accepted);
    if let Err(err) = route_permitted_by_stage_and_decision(
        PlanRouteAction::ReadPlan,
        run.stage,
        decision_for_gate,
    ) {
        match err {
            PlanRouteAuthError::StageNotPermitted { .. } => {
                return VmHttpResponse::text(VmHttpStatus::Forbidden, err.to_string());
            }
            // Unreachable under the slice-4 short-circuit, but kept
            // for forward-compatibility with slice 6. A defensive 500
            // here makes the mismatch loud rather than silent.
            PlanRouteAuthError::DecisionNotAccepted { .. } => {
                tracing::error!(
                    target: AUDIT_WRITE_FAILURE_TARGET,
                    kind = "plan_read_gate_decision_branch_taken",
                    plan_id = %plan_id,
                    error = %err,
                    "stage gate returned unexpected decision branch",
                );
                return VmHttpResponse::text(
                    VmHttpStatus::InternalServerError,
                    "stage gate returned unexpected decision branch",
                );
            }
        }
    }

    let plan = match audit.get_plan(plan_id) {
        Ok(Some(plan)) => plan,
        Ok(None) => {
            // The binding check above passed, so `agent_run.read_plan_id`
            // points at this plan_id — and the schema has a FOREIGN KEY
            // from `agent_run.read_plan_id` to `plan.plan_id`. Reaching
            // `None` here therefore implies the audit DB is missing a
            // row a FK guarantees exists, which we surface loudly.
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_read_fk_violation",
                plan_id = %plan_id,
                run_id = %run.run_id,
                "agent_run.read_plan_id points at a non-existent plan",
            );
            return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit invariant");
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_read_plan_lookup",
                plan_id = %plan_id,
                error = %err,
                "audit read failed",
            );
            return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit read failed");
        }
    };

    // The decision is looked up for the *response body*; the stage
    // gate above used the slice-4 short-circuit, not this value.
    // Slice 6 will replace `decision_for_gate` with `decision_from_db`
    // and these become a single lookup.
    let decision = match audit.get_plan_decision(plan_id) {
        Ok(opt) => opt.map(|r| DecisionView {
            outcome: r.outcome,
            decided_at: r.decided_at,
        }),
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_read_decision_lookup",
                plan_id = %plan_id,
                error = %err,
                "audit read failed",
            );
            return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit read failed");
        }
    };

    let view = PlanView {
        plan_id: plan.plan_id,
        body: plan.body,
        originating_run_id: plan.agent_run_id,
        decision,
    };
    VmHttpResponse::json(VmHttpStatus::Ok, &view)
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
    let run = match audit.get_agent_run(submission.agent_run_id) {
        Ok(Some(run)) if run.session_id == calling_session => run,
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
    };

    // Per-stage gate. `SubmitPlan` does not consult any plan-level
    // decision (planners submit before any decision exists), so the
    // decision argument is `None`.
    if let Err(err) =
        route_permitted_by_stage_and_decision(PlanRouteAction::SubmitPlan, run.stage, None)
    {
        match err {
            PlanRouteAuthError::StageNotPermitted { .. } => {
                return VmHttpResponse::text(VmHttpStatus::Forbidden, err.to_string());
            }
            // SubmitPlan never consults the decision gate, so the
            // pure function cannot return DecisionNotAccepted here.
            // Surface as 500 rather than crash so a future change to
            // the gate cannot silently smuggle a plan in via the
            // wrong branch.
            PlanRouteAuthError::DecisionNotAccepted { .. } => {
                tracing::error!(
                    target: AUDIT_WRITE_FAILURE_TARGET,
                    kind = "plan_submission_gate_decision_branch_taken",
                    run_id = %submission.agent_run_id,
                    error = %err,
                    "stage gate returned unexpected decision branch",
                );
                return VmHttpResponse::text(
                    VmHttpStatus::InternalServerError,
                    "stage gate returned unexpected decision branch",
                );
            }
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
        Err(AuditError::Sqlite(err)) if err.to_string().to_uppercase().contains("UNIQUE") => {
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
        record_run_at_stage(state, session_id, crate::agent_plan::Stage::Plan)
    }

    fn record_run_at_stage(
        state: &BrokerState<Box<dyn SecretStore>>,
        session_id: SessionId,
        stage: crate::agent_plan::Stage,
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
                stage,
                read_plan_id: None,
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
        let other_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d77011111".parse().unwrap();
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

    /// The cross-session gate runs *before* the stage gate, so a
    /// stranger session that names a run owned by another session sees
    /// `Unauthorized` regardless of that run's stage. We pin this
    /// ordering so a future change can't accidentally leak the
    /// presence-of-a-non-plan-run via 403 vs 401.
    #[tokio::test]
    async fn plan_submission_session_gate_runs_before_stage_gate() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let other_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d77011222".parse().unwrap();
        open_session_for(&state, other_session_id);
        // The stranger's run is at the *correct* stage; only the
        // session ownership should make us reject.
        let stranger_run = record_planner_run(&state, other_session_id);
        let service = plan_service_for_test(&state);

        let response =
            handle_plan_submission(&session, submission_body(stranger_run, "# Plan"), service)
                .await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
    }

    /// Submission from a `review`-stage run is forbidden: a reviewer
    /// cannot smuggle in a plan via this route. The 403 (not 401)
    /// distinguishes "authenticated but role doesn't permit" from
    /// "not the run owner."
    #[tokio::test]
    async fn plan_submission_rejects_review_stage_run() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id = record_run_at_stage(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Review,
        );
        let service = plan_service_for_test(&state);

        let response =
            handle_plan_submission(&session, submission_body(run_id, "# Plan body"), service).await;

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let message = std::str::from_utf8(&response.body).unwrap();
        assert!(
            message.contains("review") && message.contains("submit_plan"),
            "unexpected body: {message}",
        );
        // Nothing landed in the audit log.
        assert!(
            state
                .audit
                .list_plans_for_session(session.session_id())
                .unwrap()
                .is_empty(),
        );
    }

    /// Same gate applies to the default `execute` stage — the
    /// historical pre-pipeline shape. A run that does not opt into
    /// `--stage plan` cannot submit a plan.
    #[tokio::test]
    async fn plan_submission_rejects_execute_stage_run() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id = record_run_at_stage(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
        );
        let service = plan_service_for_test(&state);

        let response =
            handle_plan_submission(&session, submission_body(run_id, "# Plan body"), service).await;

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let message = std::str::from_utf8(&response.body).unwrap();
        assert!(
            message.contains("execute") && message.contains("submit_plan"),
            "unexpected body: {message}",
        );
        assert!(
            state
                .audit
                .list_plans_for_session(session.session_id())
                .unwrap()
                .is_empty(),
        );
    }

    #[tokio::test]
    async fn plan_submission_rejects_second_plan_for_same_run() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id = record_planner_run(&state, session.session_id());

        let first = handle_plan_submission(
            &session,
            submission_body(run_id, "# First"),
            plan_service_for_test(&state),
        )
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
    /// with bytes that JSON expands maximally (any control byte
    /// 0x01..=0x1f to `\u00XX`, 6x per byte) must still be admitted.
    /// The route's `Limited::collect` cap gates on *encoded* bytes,
    /// so a tight `MAX_PLAN_BODY_BYTES + small envelope` budget would
    /// reject this even though `PlanBody::try_new` is happy to accept
    /// the decoded value. NUL (0x00) would expand identically but is
    /// rejected by `PlanBody::try_new` at the parse boundary, so the
    /// next worst-case byte (SOH, 0x01) carries the same property.
    #[tokio::test]
    async fn plan_submission_admits_max_body_with_worst_case_json_expansion() {
        use crate::agent_plan::MAX_PLAN_BODY_BYTES;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id = record_planner_run(&state, session.session_id());
        let service = plan_service_for_test(&state);

        let raw_body = "\u{0001}".repeat(MAX_PLAN_BODY_BYTES);
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

    // ---------- GET /v1/plans/<plan_id> ----------

    fn record_plan(
        state: &BrokerState<Box<dyn SecretStore>>,
        planner_run_id: AgentRunId,
        body: &str,
    ) -> PlanId {
        let plan_id = PlanId::new();
        state
            .audit
            .record_plan_submission(&PlanSubmissionRecord {
                plan_id,
                agent_run_id: planner_run_id,
                submitted_at: UnixMillis::now(),
                body: PlanBody::try_new(body).unwrap(),
            })
            .unwrap();
        plan_id
    }

    fn record_run_bound(
        state: &BrokerState<Box<dyn SecretStore>>,
        session_id: SessionId,
        stage: crate::agent_plan::Stage,
        plan_id: PlanId,
    ) -> AgentRunId {
        let run_id = AgentRunId::new();
        state
            .audit
            .record_agent_run(&AgentRunAuditRecord {
                run_id,
                session_id,
                requested_at: UnixMillis::now(),
                agent_kind: AgentKind::Claude,
                prompt: AgentPrompt::new("read the plan").summary(),
                correlation_id: None,
                stage,
                read_plan_id: Some(plan_id),
            })
            .unwrap();
        run_id
    }

    fn plan_target(plan_id: PlanId) -> String {
        format!("{VM_PLANS_PATH_PREFIX}/{plan_id}")
    }

    /// Sets up a planner run on a *separate* session, lands a plan, and
    /// returns the new `plan_id`. The calling-session bearer test cases
    /// use this to build a real plan they can then bind their reader
    /// run to (the FK requires the plan to exist before
    /// `read_plan_id = Some(plan_id)` can be inserted).
    fn record_plan_via_separate_planner(
        state: &BrokerState<Box<dyn SecretStore>>,
        planner_session_id: SessionId,
    ) -> PlanId {
        open_session_for(state, planner_session_id);
        let planner_run = record_planner_run(state, planner_session_id);
        record_plan(state, planner_run, "# Plan body")
    }

    #[test]
    fn parse_plan_id_target_matches_only_exact_per_id_shape() {
        let plan_id = PlanId::new();
        let exact = format!("/v1/plans/{plan_id}");
        assert_eq!(parse_plan_id_target(&exact), Some(plan_id));

        // Collection target itself is not a per-id target.
        assert_eq!(parse_plan_id_target(VM_PLANS_PATH_PREFIX), None);
        // Trailing slash is not a valid id.
        assert_eq!(parse_plan_id_target(&format!("/v1/plans/{plan_id}/")), None);
        // Suffix paths belong to later slices, not this matcher.
        assert_eq!(
            parse_plan_id_target(&format!("/v1/plans/{plan_id}/reviews")),
            None
        );
        // Non-uuid id is rejected.
        assert_eq!(parse_plan_id_target("/v1/plans/not-a-uuid"), None);
        // Wrong prefix.
        assert_eq!(parse_plan_id_target("/v1/widgets/foo"), None);
    }

    #[tokio::test]
    async fn plan_read_unknown_target_with_disabled_service_is_not_found() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345));
        let request = VmHttpRequest::new(
            "GET",
            plan_target(PlanId::new()),
            Some(bearer(token().as_str())),
            peer,
        );
        let response =
            route_authenticated_vm_http_request(&session, &request, Vec::new(), no_services())
                .await
                .into_buffered();
        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn plan_read_rejects_non_get_methods() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let service = plan_service_for_test(&state);
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345));

        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            let request = VmHttpRequest::new(
                method,
                plan_target(PlanId::new()),
                Some(bearer(token().as_str())),
                peer,
            );
            let response = route_authenticated_vm_http_request(
                &session,
                &request,
                Vec::new(),
                services_with_plans(service.clone()),
            )
            .await
            .into_buffered();
            assert_eq!(
                response.status,
                VmHttpStatus::MethodNotAllowed,
                "{method} should be MethodNotAllowed",
            );
        }
    }

    /// A session that authenticated but has no `agent_run` (the raw
    /// `start_agent_vm_session` flow) cannot read any plan. The error
    /// is 401 rather than 404 so a caller without a run can't probe
    /// whether arbitrary plan ids exist.
    #[tokio::test]
    async fn plan_read_session_with_no_run_is_unauthorized() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let service = plan_service_for_test(&state);

        let response = handle_plan_read(&session, PlanId::new(), service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        let msg = std::str::from_utf8(&response.body).unwrap();
        assert!(
            msg.contains("no agent run on this session"),
            "unexpected body: {msg}",
        );
    }

    /// The bearer session does have a run, but its `read_plan_id` does
    /// not match the requested plan. Returns 401 (binding mismatch).
    /// This must fire *before* the stage gate so a stage=review run
    /// asking for the wrong plan doesn't leak whether that plan is
    /// readable by reviewers.
    #[tokio::test]
    async fn plan_read_run_not_bound_to_plan_is_unauthorized() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());

        // Two plans exist; the reader is bound to plan A but asks
        // for plan B.
        let planner_session: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d77013333".parse().unwrap();
        let plan_a = record_plan_via_separate_planner(&state, planner_session);
        let other_planner: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d77014444".parse().unwrap();
        let plan_b = record_plan_via_separate_planner(&state, other_planner);
        let _reader_bound_to_a = record_run_bound(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Review,
            plan_a,
        );

        let service = plan_service_for_test(&state);
        let response = handle_plan_read(&session, plan_b, service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        let msg = std::str::from_utf8(&response.body).unwrap();
        assert!(
            msg.contains("not bound to this plan"),
            "unexpected body: {msg}",
        );
    }

    /// A `stage = 'plan'` run cannot have `read_plan_id` set (the
    /// startup-time `check_start_agent_run_binding` rejects this), so
    /// in practice the binding gate fires first and returns 401. Belt-
    /// and-braces: if a future audit-row state were ever to put a
    /// stage=plan run with a matching `read_plan_id` in the DB (it
    /// shouldn't), the stage gate would still reject it as 403.
    #[tokio::test]
    async fn plan_read_planner_stage_is_rejected_by_binding_gate() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());

        let planner_session: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d77015555".parse().unwrap();
        let plan_id = record_plan_via_separate_planner(&state, planner_session);
        // The calling session's run is a planner — `read_plan_id =
        // None`. Asking for the plan therefore fails the binding gate
        // before the stage gate ever runs.
        let _planner_on_session = record_planner_run(&state, session.session_id());

        let service = plan_service_for_test(&state);
        let response = handle_plan_read(&session, plan_id, service).await;
        assert_eq!(response.status, VmHttpStatus::Unauthorized);
    }

    /// Successful read by a `stage = 'review'` run. The response
    /// `originating_run_id` matches the planner who submitted the plan
    /// (not the reader on the calling session), and `decision` is
    /// `None` because no decision row has been recorded.
    #[tokio::test]
    async fn plan_read_review_stage_returns_plan_view() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());

        let planner_session: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d77016666".parse().unwrap();
        open_session_for(&state, planner_session);
        let planner_run = record_planner_run(&state, planner_session);
        let plan_id = record_plan(&state, planner_run, "# The plan body");

        let _reviewer_run = record_run_bound(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Review,
            plan_id,
        );

        let service = plan_service_for_test(&state);
        let response = handle_plan_read(&session, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let view: PlanView = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(view.plan_id, plan_id);
        assert_eq!(view.body.as_str(), "# The plan body");
        assert_eq!(view.originating_run_id, planner_run);
        assert!(view.decision.is_none());
    }

    /// Slice 4 short-circuits the decision branch: an `execute`-stage
    /// run can fetch a plan even if no `plan_decision` row exists.
    /// Slice 6 will tighten this to "must be accepted." Pin the current
    /// behaviour so the slice-6 patch fails this test (its replacement
    /// makes the absent-decision case 403) — that failure is the
    /// signal that the short-circuit has been removed.
    #[tokio::test]
    async fn plan_read_execute_stage_succeeds_without_decision_in_slice_4() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());

        let planner_session: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d77017777".parse().unwrap();
        open_session_for(&state, planner_session);
        let planner_run = record_planner_run(&state, planner_session);
        let plan_id = record_plan(&state, planner_run, "# Execute body");

        let _implementer_run = record_run_bound(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
            plan_id,
        );

        let service = plan_service_for_test(&state);
        let response = handle_plan_read(&session, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let view: PlanView = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(view.body.as_str(), "# Execute body");
        assert!(view.decision.is_none());
    }

    /// When a `plan_decision` row exists, the read returns it verbatim
    /// in `decision`. Belt-and-braces against the slice-4 short-circuit
    /// silently dropping the field: the gate uses `Some(Accepted)`, but
    /// the response must reflect what's actually in the DB.
    #[tokio::test]
    async fn plan_read_returns_real_decision_when_recorded() {
        use crate::agent_plan::{Decider, DecisionOutcome};
        use crate::audit::PlanDecisionRecord;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());

        let planner_session: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d77018888".parse().unwrap();
        open_session_for(&state, planner_session);
        let planner_run = record_planner_run(&state, planner_session);
        let plan_id = record_plan(&state, planner_run, "# Decided");

        let decided_at = UnixMillis::from_millis(1_700_000_500_000);
        state
            .audit
            .record_plan_decision(&PlanDecisionRecord {
                plan_id,
                decided_at,
                outcome: DecisionOutcome::Accepted,
                decider: Decider::try_new("operator-1").unwrap(),
            })
            .unwrap();

        let _implementer_run = record_run_bound(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
            plan_id,
        );

        let service = plan_service_for_test(&state);
        let response = handle_plan_read(&session, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let view: PlanView = serde_json::from_slice(&response.body).unwrap();
        let decision = view.decision.expect("decision should be present");
        assert_eq!(decision.outcome, DecisionOutcome::Accepted);
        assert_eq!(decision.decided_at, decided_at);
    }

    /// End-to-end through the full HTTP dispatcher: bearer auth,
    /// route matching, JSON encoding all the way to a buffered
    /// response. Regression for the slice-4c wire-up at the
    /// `/v1/plans/<id>` matcher in `vm_http/mod.rs` — a wire-shape
    /// regression elsewhere fails this test, not just the unit cases.
    #[tokio::test]
    async fn plan_read_full_dispatch_returns_plan_view() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());

        let planner_session: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d77019999".parse().unwrap();
        open_session_for(&state, planner_session);
        let planner_run = record_planner_run(&state, planner_session);
        let plan_id = record_plan(&state, planner_run, "# Dispatch body");
        let _reviewer = record_run_bound(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Review,
            plan_id,
        );
        let service = plan_service_for_test(&state);

        let bearer_auth = bearer(token().as_str());
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "GET",
            &plan_target(plan_id),
            &[("authorization", bearer_auth.as_str())],
            Vec::new(),
            services_with_plans(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let view: PlanView = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(view.plan_id, plan_id);
        assert_eq!(view.body.as_str(), "# Dispatch body");
        assert_eq!(view.originating_run_id, planner_run);
    }
}
