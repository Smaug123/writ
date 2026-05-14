//! Plan VM HTTP routes. Four endpoints today, all served from this
//! module:
//!
//! - `POST /v1/plans` — a planner submits a plan body.
//! - `GET  /v1/plans/<plan_id>` — a reviewer or implementer reads the
//!   plan body, decision (when set), and originating-run id.
//! - `POST /v1/plans/<plan_id>/addenda` — an executor posts a
//!   follow-up addendum body against an already-accepted plan.
//! - `POST /v1/plans/<plan_id>/abort` — an executor posts a hard-abort
//!   against a plan it has decided is fundamentally unworkable
//!   mid-execution.
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
//! 3. **Per-stage:** the run's stage must permit `ReadPlan`. The pure
//!    stage→action gate is [`route_permitted_by_stage_and_decision`].
//!    A review-stage read passes regardless of decision (reviewers
//!    must be able to re-read the plan they're voting on, even after
//!    rejection). An execute-stage read requires a recorded
//!    `Accepted` row: a missing decision is no longer treated as
//!    implicit acceptance, so an implementer cannot pull the plan
//!    body until an operator has signed off via `writ plan decide
//!    --accept`.
//!
//! The addendum route mirrors the read route's session-based shape —
//! the request body carries no `agent_run_id`, so the run is looked
//! up via `agent_run_for_session(calling_session)`. After that the
//! gates are the same set as `ReadPlan` (session→run, binding,
//! stage+decision via [`route_permitted_by_stage_and_decision`] with
//! [`PlanRouteAction::SubmitAddendum`]), and unlike `SubmitReview`
//! both `StageNotPermitted` *and* `DecisionNotAccepted` are
//! meaningful 403 outcomes from the pure gate: addenda are
//! execute-stage only and only against an Accepted plan.
//!
//! The abort route shares the addendum route's shape (session→run,
//! binding, then stage gate) but deliberately *omits* the
//! plan-decision check. Per spec §"Decisions taken" item 9, an
//! execute-stage run is only running at all because acceptance has
//! already been enforced upstream (read-plan gates that on
//! execute-stage reads), so re-checking here would only fire on a
//! corrupted state; it would also forbid the very case the abort
//! signal exists for ("the accepted plan turned out to be wrong").
//! Concretely the route passes [`PlanRouteAction::SubmitAbort`] to the
//! pure gate, which matches only `Stage::Execute` and never returns
//! `DecisionNotAccepted` for this action — that arm is a defensive
//! 500 so a future change to the gate cannot silently smuggle a hard-
//! abort through the wrong branch.

use std::sync::Arc;

use crate::agent_plan::{
    AbortRecorded, AbortSubmission, AddendumCreated, AddendumId, AddendumSubmission, DecisionView,
    PlanCreated, PlanId, PlanRouteAction, PlanRouteAuthError, PlanSubmission, PlanView,
    ReviewCreated, ReviewId, ReviewSubmission, VM_PLANS_PATH_PREFIX,
    route_permitted_by_stage_and_decision,
};
use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, PlanAbortRecord, PlanAddendumRecord, PlanReviewRecord,
    PlanSubmissionRecord,
};
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
/// Sub-routes like `/v1/plans/<plan_id>/reviews` have their own
/// parser ([`parse_plan_reviews_target`]) and are not matched here.
pub(super) fn parse_plan_id_target(target: &str) -> Option<PlanId> {
    let suffix = target
        .strip_prefix(VM_PLANS_PATH_PREFIX)?
        .strip_prefix('/')?;
    if suffix.contains('/') {
        return None;
    }
    suffix.parse().ok()
}

/// `/v1/plans/<plan_id>/reviews`. Returns the parsed `plan_id` when
/// the target names the reviews sub-collection of exactly one plan.
/// Rejects extra trailing path segments so a reviewer cannot reach
/// past the route (e.g. `.../reviews/../foo`).
pub(super) fn parse_plan_reviews_target(target: &str) -> Option<PlanId> {
    let suffix = target
        .strip_prefix(VM_PLANS_PATH_PREFIX)?
        .strip_prefix('/')?;
    let raw_id = suffix.strip_suffix("/reviews")?;
    if raw_id.contains('/') {
        return None;
    }
    raw_id.parse().ok()
}

/// `/v1/plans/<plan_id>/addenda`. Returns the parsed `plan_id` when
/// the target names the addenda sub-collection of exactly one plan.
/// Same shape as [`parse_plan_reviews_target`]: trailing path segments
/// are rejected so callers cannot walk past the route.
pub(super) fn parse_plan_addenda_target(target: &str) -> Option<PlanId> {
    let suffix = target
        .strip_prefix(VM_PLANS_PATH_PREFIX)?
        .strip_prefix('/')?;
    let raw_id = suffix.strip_suffix("/addenda")?;
    if raw_id.contains('/') {
        return None;
    }
    raw_id.parse().ok()
}

/// `/v1/plans/<plan_id>/abort`. Returns the parsed `plan_id` when the
/// target names the per-plan abort endpoint. Same shape as the reviews
/// and addenda parsers; the `abort` suffix names a single hard-abort
/// signal (PK on `plan_abort.plan_id`), not a sub-collection.
pub(super) fn parse_plan_abort_target(target: &str) -> Option<PlanId> {
    let suffix = target
        .strip_prefix(VM_PLANS_PATH_PREFIX)?
        .strip_prefix('/')?;
    let raw_id = suffix.strip_suffix("/abort")?;
    if raw_id.contains('/') {
        return None;
    }
    raw_id.parse().ok()
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

    // Fetch the decision before the stage gate so an execute-stage
    // read can be denied unless an `Accepted` row exists. The pure
    // gate consults the decision only for stages that require
    // acceptance (Execute today; SubmitAddendum tomorrow), so a
    // review-stage read with no decision still passes through.
    let decision_record = match audit.get_plan_decision(plan_id) {
        Ok(opt) => opt,
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
    let decision_for_gate = decision_record.as_ref().map(|r| r.outcome);
    if let Err(err) = route_permitted_by_stage_and_decision(
        PlanRouteAction::ReadPlan,
        run.stage,
        decision_for_gate,
    ) {
        match err {
            PlanRouteAuthError::StageNotPermitted { .. }
            | PlanRouteAuthError::DecisionNotAccepted { .. } => {
                return VmHttpResponse::text(VmHttpStatus::Forbidden, err.to_string());
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

    let decision = decision_record.map(|r| DecisionView {
        outcome: r.outcome,
        decided_at: r.decided_at,
    });

    let view = PlanView {
        plan_id: plan.plan_id,
        body: plan.body,
        originating_run_id: plan.agent_run_id,
        decision,
    };
    VmHttpResponse::json(VmHttpStatus::Ok, &view)
}

pub(super) async fn route_plan_reviews_request<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    body: Vec<u8>,
    plan_id: PlanId,
    service: VmHttpPlanService<S>,
) -> VmHttpResponse {
    if request.method != "POST" {
        return VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed");
    }
    handle_plan_review_submission(session, body, plan_id, service).await
}

pub(super) async fn route_plan_addenda_request<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    body: Vec<u8>,
    plan_id: PlanId,
    service: VmHttpPlanService<S>,
) -> VmHttpResponse {
    if request.method != "POST" {
        return VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed");
    }
    handle_plan_addendum_submission(session, body, plan_id, service).await
}

pub(super) async fn route_plan_abort_request<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    body: Vec<u8>,
    plan_id: PlanId,
    service: VmHttpPlanService<S>,
) -> VmHttpResponse {
    if request.method != "POST" {
        return VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed");
    }
    handle_plan_abort_submission(session, body, plan_id, service).await
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

async fn handle_plan_review_submission<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    body: Vec<u8>,
    plan_id: PlanId,
    service: VmHttpPlanService<S>,
) -> VmHttpResponse {
    let submission = match serde_json::from_slice::<ReviewSubmission>(&body) {
        Ok(submission) => submission,
        Err(err) => {
            return VmHttpResponse::text(
                VmHttpStatus::BadRequest,
                format!("invalid review submission: {err}"),
            );
        }
    };
    drop(body);

    let audit = &service.broker_state.audit;
    let calling_session = session.session_id();
    let run = match audit.get_agent_run(submission.agent_run_id) {
        Ok(Some(run)) if run.session_id == calling_session => run,
        Ok(Some(_)) => {
            // Same ordering as `handle_plan_submission`: the
            // cross-session gate runs first so a stranger naming a real
            // run sees 401 rather than leaking presence-of-run via 403.
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
                kind = "plan_review_run_lookup",
                run_id = %submission.agent_run_id,
                plan_id = %plan_id,
                error = %err,
                "audit read failed",
            );
            return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit read failed");
        }
    };

    // Per-stage gate. `SubmitReview` is admitted only when
    // `run.stage = 'review'`; no decision consultation.
    if let Err(err) =
        route_permitted_by_stage_and_decision(PlanRouteAction::SubmitReview, run.stage, None)
    {
        match err {
            PlanRouteAuthError::StageNotPermitted { .. } => {
                return VmHttpResponse::text(VmHttpStatus::Forbidden, err.to_string());
            }
            // `SubmitReview` never consults the decision branch; if the
            // pure gate ever returns it for this action, surface as 500
            // so a future refactor cannot silently re-route a verdict
            // through the wrong branch.
            PlanRouteAuthError::DecisionNotAccepted { .. } => {
                tracing::error!(
                    target: AUDIT_WRITE_FAILURE_TARGET,
                    kind = "plan_review_gate_decision_branch_taken",
                    run_id = %submission.agent_run_id,
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

    // Cross-binding gate: a reviewer can only post a verdict against
    // the plan it was started against. The matching DAO check and the
    // `plan_review_requires_reviewer_run` trigger are the audit-side
    // defences; this pre-check turns the wire-side failure into a
    // typed 403 rather than a 500 from the audit invariant.
    if run.read_plan_id != Some(plan_id) {
        return VmHttpResponse::text(
            VmHttpStatus::Forbidden,
            "agent run is not bound to this plan",
        );
    }

    let review_id = ReviewId::new();
    let record = PlanReviewRecord {
        review_id,
        plan_id,
        agent_run_id: submission.agent_run_id,
        submitted_at: UnixMillis::now(),
        verdict: submission.verdict,
        feedback: submission.feedback,
    };
    match audit.record_plan_review(&record) {
        Ok(()) => VmHttpResponse::json(VmHttpStatus::Ok, &ReviewCreated { review_id }),
        Err(AuditError::Invariant("agent run does not exist")) => {
            // Run vanished between our lookup and the write — a race
            // with session close or audit-side deletion. 410 Gone
            // mirrors `handle_plan_submission`.
            VmHttpResponse::text(VmHttpStatus::Gone, "agent run no longer exists")
        }
        Err(AuditError::Invariant("session is closed")) => {
            VmHttpResponse::text(VmHttpStatus::Gone, "session is closed")
        }
        Err(AuditError::Invariant("plan does not exist")) => {
            // The plan named in the URL is gone (or never existed).
            // The cross-binding gate above requires
            // `run.read_plan_id = Some(plan_id)` which is FK-checked
            // against `plan`, so reaching here means the plan was
            // deleted in the race window. 410 Gone matches the
            // disappearing-run case above: this URL was valid once and
            // no longer is.
            VmHttpResponse::text(VmHttpStatus::Gone, "plan no longer exists")
        }
        Err(AuditError::Sqlite(err)) if err.to_string().to_uppercase().contains("UNIQUE") => {
            // `UNIQUE(agent_run_id)` on `plan_review`: one verdict per
            // reviewer run, no overwrites.
            VmHttpResponse::text(
                VmHttpStatus::Conflict,
                "review already recorded for this run",
            )
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_review",
                run_id = %submission.agent_run_id,
                plan_id = %plan_id,
                review_id = %review_id,
                error = %err,
                "audit write failed",
            );
            VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed")
        }
    }
}

async fn handle_plan_addendum_submission<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    body: Vec<u8>,
    plan_id: PlanId,
    service: VmHttpPlanService<S>,
) -> VmHttpResponse {
    let submission = match serde_json::from_slice::<AddendumSubmission>(&body) {
        Ok(submission) => submission,
        Err(err) => {
            return VmHttpResponse::text(
                VmHttpStatus::BadRequest,
                format!("invalid addendum submission: {err}"),
            );
        }
    };
    drop(body);

    let audit = &service.broker_state.audit;
    let calling_session = session.session_id();

    // The request body carries no `agent_run_id`, so the run is
    // looked up from the bearer's session. This matches the read
    // route's shape.
    let run = match audit.agent_run_for_session(calling_session) {
        Ok(Some(run)) => run,
        Ok(None) => {
            return VmHttpResponse::text(
                VmHttpStatus::Unauthorized,
                "no agent run on this session",
            );
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_addendum_run_lookup",
                plan_id = %plan_id,
                session_id = %calling_session,
                error = %err,
                "audit read failed",
            );
            return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit read failed");
        }
    };

    // Binding gate before the stage gate, mirroring the read route:
    // do not leak which stages may post addenda to a caller whose run
    // is not bound to this plan. The 401 (not 403) matches the read
    // route's "authenticated but not the run bound to this plan."
    if run.read_plan_id != Some(plan_id) {
        return VmHttpResponse::text(
            VmHttpStatus::Unauthorized,
            "agent run is not bound to this plan",
        );
    }

    // Fetch the decision so the pure stage+decision gate can return
    // `DecisionNotAccepted` cleanly for an execute-stage run whose
    // plan has not been accepted.
    let decision_record = match audit.get_plan_decision(plan_id) {
        Ok(opt) => opt,
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_addendum_decision_lookup",
                plan_id = %plan_id,
                error = %err,
                "audit read failed",
            );
            return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit read failed");
        }
    };
    let decision_for_gate = decision_record.as_ref().map(|r| r.outcome);

    // Unlike `SubmitPlan`/`SubmitReview`, `SubmitAddendum` legitimately
    // consults both gate branches: `Execute` is the only admitted
    // stage, and a non-Accepted decision is a real 403 outcome.
    if let Err(err) = route_permitted_by_stage_and_decision(
        PlanRouteAction::SubmitAddendum,
        run.stage,
        decision_for_gate,
    ) {
        match err {
            PlanRouteAuthError::StageNotPermitted { .. }
            | PlanRouteAuthError::DecisionNotAccepted { .. } => {
                return VmHttpResponse::text(VmHttpStatus::Forbidden, err.to_string());
            }
        }
    }

    let addendum_id = AddendumId::new();
    let record = PlanAddendumRecord {
        addendum_id,
        plan_id,
        agent_run_id: run.run_id,
        submitted_at: UnixMillis::now(),
        body: submission.body,
    };
    match audit.record_plan_addendum(&record) {
        Ok(()) => VmHttpResponse::json(VmHttpStatus::Ok, &AddendumCreated { addendum_id }),
        Err(AuditError::Invariant("agent run does not exist")) => {
            // Run vanished between session→run lookup and the write.
            VmHttpResponse::text(VmHttpStatus::Gone, "agent run no longer exists")
        }
        Err(AuditError::Invariant("session is closed")) => {
            VmHttpResponse::text(VmHttpStatus::Gone, "session is closed")
        }
        Err(AuditError::Invariant("plan does not exist")) => {
            // The binding gate above requires
            // `run.read_plan_id = Some(plan_id)` which is FK-checked
            // against `plan`, so reaching here means the plan row
            // was deleted in the race window.
            VmHttpResponse::text(VmHttpStatus::Gone, "plan no longer exists")
        }
        Err(AuditError::Sqlite(err)) if err.to_string().to_uppercase().contains("UNIQUE") => {
            // `UNIQUE(agent_run_id)` on `plan_addendum`: one addendum
            // per executor run.
            VmHttpResponse::text(
                VmHttpStatus::Conflict,
                "addendum already recorded for this run",
            )
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_addendum",
                run_id = %run.run_id,
                plan_id = %plan_id,
                addendum_id = %addendum_id,
                error = %err,
                "audit write failed",
            );
            VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed")
        }
    }
}

async fn handle_plan_abort_submission<S: SecretStore + Send + Sync + 'static>(
    session: &VmHttpSession,
    body: Vec<u8>,
    plan_id: PlanId,
    service: VmHttpPlanService<S>,
) -> VmHttpResponse {
    let submission = match serde_json::from_slice::<AbortSubmission>(&body) {
        Ok(submission) => submission,
        Err(err) => {
            return VmHttpResponse::text(
                VmHttpStatus::BadRequest,
                format!("invalid abort submission: {err}"),
            );
        }
    };
    drop(body);

    let audit = &service.broker_state.audit;
    let calling_session = session.session_id();

    // Session-based shape, like the addendum route: the URL names the
    // plan and the request body is reason-only, so the run is looked
    // up from the bearer's session.
    let run = match audit.agent_run_for_session(calling_session) {
        Ok(Some(run)) => run,
        Ok(None) => {
            return VmHttpResponse::text(
                VmHttpStatus::Unauthorized,
                "no agent run on this session",
            );
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_abort_run_lookup",
                plan_id = %plan_id,
                session_id = %calling_session,
                error = %err,
                "audit read failed",
            );
            return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit read failed");
        }
    };

    // Binding gate before the stage gate (same ordering as the read
    // and addendum routes): do not leak which stages may abort to a
    // caller whose run is not bound to this plan. 401 (not 403)
    // matches the addendum route's "authenticated but not the run
    // bound to this plan."
    if run.read_plan_id != Some(plan_id) {
        return VmHttpResponse::text(
            VmHttpStatus::Unauthorized,
            "agent run is not bound to this plan",
        );
    }

    // The abort route deliberately does *not* consult the plan
    // decision: an execute-stage run is only running because
    // acceptance has already been enforced upstream, and the spec
    // (§"Decisions taken" item 9) explicitly omits the check here so
    // the implementer can still post an abort against a plan whose
    // decision the operator might later flip. Pass `None` for the
    // decision and treat any `DecisionNotAccepted` from the pure gate
    // as a defensive 500: `SubmitAbort` never consults that branch,
    // and a hit means the gate has been reshaped without updating
    // this handler.
    if let Err(err) =
        route_permitted_by_stage_and_decision(PlanRouteAction::SubmitAbort, run.stage, None)
    {
        match err {
            PlanRouteAuthError::StageNotPermitted { .. } => {
                return VmHttpResponse::text(VmHttpStatus::Forbidden, err.to_string());
            }
            PlanRouteAuthError::DecisionNotAccepted { .. } => {
                tracing::error!(
                    target: AUDIT_WRITE_FAILURE_TARGET,
                    kind = "plan_abort_gate_decision_branch_taken",
                    run_id = %run.run_id,
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

    let aborted_at = UnixMillis::now();
    let record = PlanAbortRecord {
        plan_id,
        agent_run_id: run.run_id,
        aborted_at,
        reason: submission.reason,
    };
    match audit.record_plan_abort(&record) {
        Ok(()) => VmHttpResponse::json(VmHttpStatus::Ok, &AbortRecorded { aborted_at }),
        Err(AuditError::Invariant("agent run does not exist")) => {
            // Run vanished between the session→run lookup and the
            // write — same race shape as the addendum route.
            VmHttpResponse::text(VmHttpStatus::Gone, "agent run no longer exists")
        }
        Err(AuditError::Invariant("session is closed")) => {
            VmHttpResponse::text(VmHttpStatus::Gone, "session is closed")
        }
        Err(AuditError::Invariant("plan does not exist")) => {
            // The binding gate above requires
            // `run.read_plan_id = Some(plan_id)` which is FK-checked
            // against `plan`, so reaching here means the plan row was
            // deleted in the race window.
            VmHttpResponse::text(VmHttpStatus::Gone, "plan no longer exists")
        }
        Err(AuditError::Sqlite(err)) if err.to_string().to_uppercase().contains("UNIQUE") => {
            // `plan_abort.plan_id` is a PRIMARY KEY, so a second abort
            // for the same plan surfaces as a UNIQUE/PK violation.
            // Unlike `plan_addendum` (UNIQUE on `agent_run_id`), this
            // is one-per-plan: a different executor on a retry session
            // would also hit this branch.
            VmHttpResponse::text(VmHttpStatus::Conflict, "plan already aborted")
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_abort",
                run_id = %run.run_id,
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
        record_run_at_stage_with_read_plan(state, session_id, stage, None)
    }

    fn record_run_at_stage_with_read_plan(
        state: &BrokerState<Box<dyn SecretStore>>,
        session_id: SessionId,
        stage: crate::agent_plan::Stage,
        read_plan_id: Option<PlanId>,
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
                read_plan_id,
            })
            .unwrap();
        run_id
    }

    /// Fixture: submit a plan owned by `planner_run`, then return its
    /// `PlanId`. Tests of the review route need a real plan in the DB
    /// (FK target for `read_plan_id` and the URL path segment).
    fn submit_plan_for_run(
        state: &BrokerState<Box<dyn SecretStore>>,
        planner_run: AgentRunId,
        body: &str,
    ) -> PlanId {
        let plan_id = PlanId::new();
        state
            .audit
            .record_plan_submission(&PlanSubmissionRecord {
                plan_id,
                agent_run_id: planner_run,
                submitted_at: UnixMillis::now(),
                body: PlanBody::try_new(body).unwrap(),
            })
            .unwrap();
        plan_id
    }

    /// Fixture: create a reviewer run on `session_id` bound to
    /// `plan_id` via `read_plan_id`. Mirrors the start-time binding
    /// the route enforces.
    fn record_reviewer_run(
        state: &BrokerState<Box<dyn SecretStore>>,
        session_id: SessionId,
        plan_id: PlanId,
    ) -> AgentRunId {
        record_run_at_stage_with_read_plan(
            state,
            session_id,
            crate::agent_plan::Stage::Review,
            Some(plan_id),
        )
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

    fn review_submission_body(
        run_id: AgentRunId,
        verdict: crate::agent_plan::Verdict,
        feedback: Option<&str>,
    ) -> Vec<u8> {
        serde_json::to_vec(&ReviewSubmission {
            agent_run_id: run_id,
            verdict,
            feedback: feedback.map(|f| crate::agent_plan::PlanFeedback::try_new(f).unwrap()),
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
        // Suffix paths are matched by a sibling parser
        // (`parse_plan_reviews_target`), not this one.
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

    /// An execute-stage run cannot fetch the plan body until an
    /// operator has recorded an `Accepted` decision. With no
    /// `plan_decision` row the read is 403 — the slice-6 acceptance
    /// gate has replaced the slice-4 short-circuit that defaulted a
    /// missing row to accepted.
    #[tokio::test]
    async fn plan_read_execute_stage_without_decision_is_forbidden() {
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

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let msg = std::str::from_utf8(&response.body).unwrap();
        assert!(
            msg.contains("decision") && msg.contains("no decision recorded"),
            "unexpected body: {msg}",
        );
    }

    /// An execute-stage read with a recorded `Accepted` decision is
    /// the happy path the slice-6 gate is built to admit, and the
    /// response surfaces the decision verbatim (outcome + timestamp).
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

    /// A recorded `RejectedRestart` decision denies an execute-stage
    /// read. The 403 distinguishes this from the 401 binding-mismatch
    /// path: the run *is* bound to this plan, but the operator has
    /// closed it.
    #[tokio::test]
    async fn plan_read_execute_stage_rejected_decision_is_forbidden() {
        use crate::agent_plan::{Decider, DecisionOutcome};
        use crate::audit::PlanDecisionRecord;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());

        let planner_session: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7701aaaa".parse().unwrap();
        open_session_for(&state, planner_session);
        let planner_run = record_planner_run(&state, planner_session);
        let plan_id = record_plan(&state, planner_run, "# Rejected body");

        state
            .audit
            .record_plan_decision(&PlanDecisionRecord {
                plan_id,
                decided_at: UnixMillis::from_millis(1_700_000_600_000),
                outcome: DecisionOutcome::RejectedRestart,
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

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let msg = std::str::from_utf8(&response.body).unwrap();
        assert!(
            msg.contains("decision") && msg.contains("rejected_restart"),
            "unexpected body: {msg}",
        );
    }

    /// A reviewer's read is not gated on the decision (the spec
    /// admits review-stage reads regardless of decision so reviewers
    /// can re-read the plan they're deciding on). Pin this so a
    /// future tightening of the gate doesn't accidentally lock
    /// reviewers out of plans an operator has rejected.
    #[tokio::test]
    async fn plan_read_review_stage_is_allowed_even_with_rejected_decision() {
        use crate::agent_plan::{Decider, DecisionOutcome};
        use crate::audit::PlanDecisionRecord;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());

        let planner_session: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7701bbbb".parse().unwrap();
        open_session_for(&state, planner_session);
        let planner_run = record_planner_run(&state, planner_session);
        let plan_id = record_plan(&state, planner_run, "# Reviewer body");

        state
            .audit
            .record_plan_decision(&PlanDecisionRecord {
                plan_id,
                decided_at: UnixMillis::from_millis(1_700_000_700_000),
                outcome: DecisionOutcome::RejectedRestart,
                decider: Decider::try_new("operator-1").unwrap(),
            })
            .unwrap();

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
        let decision = view.decision.expect("decision should be present");
        assert_eq!(decision.outcome, DecisionOutcome::RejectedRestart);
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

    // --- POST /v1/plans/<plan_id>/reviews ---------------------------

    /// Reference: `parse_plan_reviews_target` is the URL-shape gate. A
    /// well-formed `/v1/plans/<uuid>/reviews` resolves; anything that
    /// would let a caller reach past the route (extra segments,
    /// missing `/reviews` suffix, malformed UUID) returns `None`.
    #[test]
    fn parse_plan_reviews_target_accepts_well_formed_and_rejects_others() {
        let plan_id = PlanId::new();
        let ok = format!("/v1/plans/{plan_id}/reviews");
        assert_eq!(parse_plan_reviews_target(&ok), Some(plan_id));

        // Missing `/reviews` suffix.
        let bare = format!("/v1/plans/{plan_id}");
        assert_eq!(parse_plan_reviews_target(&bare), None);

        // Extra segment after `/reviews`.
        let deeper = format!("/v1/plans/{plan_id}/reviews/extra");
        assert_eq!(parse_plan_reviews_target(&deeper), None);

        // Slash inside the id segment.
        let with_slash = format!("/v1/plans/a/{plan_id}/reviews");
        assert_eq!(parse_plan_reviews_target(&with_slash), None);

        // Not a UUID.
        assert_eq!(
            parse_plan_reviews_target("/v1/plans/not-a-uuid/reviews"),
            None
        );

        // Wrong prefix.
        assert_eq!(parse_plan_reviews_target("/plans/x/reviews"), None);

        // Just the collection — must not match the reviews parser.
        assert_eq!(parse_plan_reviews_target("/v1/plans"), None);
    }

    /// With `services.plans = None`, the reviews route is dark: all
    /// methods return 404 (and we never reach the per-method 405
    /// branch). Mirrors `disabled_plans_route_is_not_found_for_all_methods`.
    #[tokio::test]
    async fn disabled_plan_reviews_route_is_not_found_for_all_methods() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345));
        let target = crate::agent_plan::vm_plan_reviews_path(PlanId::new());

        for method in ["GET", "POST", "PUT", "DELETE"] {
            let request = VmHttpRequest::new(method, &target, Some(bearer(token().as_str())), peer);
            let response =
                route_authenticated_vm_http_request(&session, &request, Vec::new(), no_services())
                    .await
                    .into_buffered();

            assert_eq!(response.status, VmHttpStatus::NotFound);
        }
    }

    #[tokio::test]
    async fn enabled_plan_reviews_route_rejects_non_post_methods() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let service = plan_service_for_test(&state);
        let target = crate::agent_plan::vm_plan_reviews_path(PlanId::new());
        let request = VmHttpRequest::new(
            "GET",
            &target,
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
    async fn plan_review_rejects_malformed_body_without_audit() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_run = record_planner_run(&state, session.session_id());
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        let service = plan_service_for_test(&state);

        let response =
            handle_plan_review_submission(&session, b"not json".to_vec(), plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::BadRequest);
        assert!(
            state
                .audit
                .list_plan_reviews_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    #[tokio::test]
    async fn plan_review_rejects_unknown_run() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_run = record_planner_run(&state, session.session_id());
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        let service = plan_service_for_test(&state);

        let body =
            review_submission_body(AgentRunId::new(), crate::agent_plan::Verdict::Approve, None);
        let response = handle_plan_review_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::NotFound);
        assert!(
            state
                .audit
                .list_plan_reviews_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    /// A second session that owns the reviewer run; the calling
    /// session does not. Same shape as
    /// `plan_submission_rejects_run_owned_by_other_session`: 401, no
    /// audit row.
    #[tokio::test]
    async fn plan_review_rejects_run_owned_by_other_session() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let other_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d77011333".parse().unwrap();
        open_session_for(&state, other_session_id);
        let planner_run = record_planner_run(&state, other_session_id);
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        let stranger_reviewer = record_reviewer_run(&state, other_session_id, plan_id);
        let service = plan_service_for_test(&state);

        let body =
            review_submission_body(stranger_reviewer, crate::agent_plan::Verdict::Approve, None);
        let response = handle_plan_review_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        assert!(
            state
                .audit
                .list_plan_reviews_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    /// A planner-stage run cannot post a review verdict, even one
    /// bound (via a hypothetical future flow) to a plan. 403, not 401.
    #[tokio::test]
    async fn plan_review_rejects_non_review_stage_run() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_run = record_planner_run(&state, session.session_id());
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        let service = plan_service_for_test(&state);

        // Use the planner run (`stage = 'plan'`) as the reviewer; the
        // stage gate must reject before the cross-binding gate.
        let body = review_submission_body(planner_run, crate::agent_plan::Verdict::Approve, None);
        let response = handle_plan_review_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let message = std::str::from_utf8(&response.body).unwrap();
        assert!(
            message.contains("plan") && message.contains("submit_review"),
            "unexpected body: {message}",
        );
        assert!(
            state
                .audit
                .list_plan_reviews_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    /// A reviewer run bound to plan A cannot post a verdict against
    /// plan B. The pre-check turns the audit invariant into a typed
    /// 403; the DAO and trigger remain as defences but the route must
    /// not let the request reach them.
    #[tokio::test]
    async fn plan_review_rejects_reviewer_bound_to_different_plan() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_run = record_planner_run(&state, session.session_id());
        let plan_a = submit_plan_for_run(&state, planner_run, "# Plan A");
        // A second planner run for plan B (plan submission requires a
        // distinct `agent_run_id` per the `UNIQUE(agent_run_id)` clause
        // on `plan`).
        let other_planner = record_planner_run(&state, session.session_id());
        let plan_b = submit_plan_for_run(&state, other_planner, "# Plan B");
        let reviewer_of_a = record_reviewer_run(&state, session.session_id(), plan_a);
        let service = plan_service_for_test(&state);

        let body = review_submission_body(reviewer_of_a, crate::agent_plan::Verdict::Approve, None);
        let response = handle_plan_review_submission(&session, body, plan_b, service).await;

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let message = std::str::from_utf8(&response.body).unwrap();
        assert!(message.contains("not bound"), "unexpected body: {message}",);
        // Nothing landed against either plan.
        assert!(
            state
                .audit
                .list_plan_reviews_for_plan(plan_a)
                .unwrap()
                .is_empty(),
        );
        assert!(
            state
                .audit
                .list_plan_reviews_for_plan(plan_b)
                .unwrap()
                .is_empty(),
        );
    }

    /// A reviewer run with `read_plan_id = NULL` cannot smuggle a
    /// verdict in — the cross-binding gate requires
    /// `read_plan_id = Some(<url-plan>)`. The migration enforces the
    /// invariant at start-time, but the route must not assume it.
    #[tokio::test]
    async fn plan_review_rejects_reviewer_without_read_plan_id() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_run = record_planner_run(&state, session.session_id());
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        // Reviewer stage but no `read_plan_id`.
        let unbound_reviewer = record_run_at_stage(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Review,
        );
        let service = plan_service_for_test(&state);

        let body =
            review_submission_body(unbound_reviewer, crate::agent_plan::Verdict::Approve, None);
        let response = handle_plan_review_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        assert!(
            state
                .audit
                .list_plan_reviews_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    /// Cross-session gate runs before stage gate (mirrors
    /// `plan_submission_session_gate_runs_before_stage_gate`). The
    /// stranger run is at the *correct* stage and bound to the
    /// *correct* plan; only session ownership rejects.
    #[tokio::test]
    async fn plan_review_session_gate_runs_before_stage_gate() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let other_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d77011444".parse().unwrap();
        open_session_for(&state, other_session_id);
        let planner_run = record_planner_run(&state, other_session_id);
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        let stranger_reviewer = record_reviewer_run(&state, other_session_id, plan_id);
        let service = plan_service_for_test(&state);

        let body =
            review_submission_body(stranger_reviewer, crate::agent_plan::Verdict::Approve, None);
        let response = handle_plan_review_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
    }

    /// Happy path: a reviewer bound to the URL plan posts an approval
    /// with feedback. Response is 200 with `ReviewCreated`; the audit
    /// row reflects the verdict, the feedback body, and the same
    /// `review_id`.
    #[tokio::test]
    async fn plan_review_records_audit_row_and_returns_review_id() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_run = record_planner_run(&state, session.session_id());
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        let reviewer = record_reviewer_run(&state, session.session_id(), plan_id);
        let service = plan_service_for_test(&state);

        let body = review_submission_body(
            reviewer,
            crate::agent_plan::Verdict::RequestChanges,
            Some("re-scope step 3"),
        );
        let response = handle_plan_review_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let created: ReviewCreated = serde_json::from_slice(&response.body).unwrap();
        let stored = state
            .audit
            .get_plan_review(created.review_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.review_id, created.review_id);
        assert_eq!(stored.plan_id, plan_id);
        assert_eq!(stored.agent_run_id, reviewer);
        assert_eq!(stored.verdict, crate::agent_plan::Verdict::RequestChanges);
        assert_eq!(
            stored.feedback.as_ref().map(|f| f.as_str()),
            Some("re-scope step 3"),
        );
    }

    /// A reviewer that opts to skip feedback (approve-without-comment)
    /// is admitted; the audit row carries `feedback = None`.
    #[tokio::test]
    async fn plan_review_admits_approval_without_feedback() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_run = record_planner_run(&state, session.session_id());
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        let reviewer = record_reviewer_run(&state, session.session_id(), plan_id);
        let service = plan_service_for_test(&state);

        let body = review_submission_body(reviewer, crate::agent_plan::Verdict::Approve, None);
        let response = handle_plan_review_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let created: ReviewCreated = serde_json::from_slice(&response.body).unwrap();
        let stored = state
            .audit
            .get_plan_review(created.review_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.verdict, crate::agent_plan::Verdict::Approve);
        assert!(stored.feedback.is_none());
    }

    #[tokio::test]
    async fn plan_review_rejects_second_review_for_same_run() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_run = record_planner_run(&state, session.session_id());
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        let reviewer = record_reviewer_run(&state, session.session_id(), plan_id);

        let first = handle_plan_review_submission(
            &session,
            review_submission_body(reviewer, crate::agent_plan::Verdict::Approve, None),
            plan_id,
            plan_service_for_test(&state),
        )
        .await;
        assert_eq!(first.status, VmHttpStatus::Ok);

        let second = handle_plan_review_submission(
            &session,
            review_submission_body(
                reviewer,
                crate::agent_plan::Verdict::RequestChanges,
                Some("changed my mind"),
            ),
            plan_id,
            plan_service_for_test(&state),
        )
        .await;
        assert_eq!(second.status, VmHttpStatus::Conflict);

        // Only the first verdict landed.
        let rows = state.audit.list_plan_reviews_for_plan(plan_id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].verdict, crate::agent_plan::Verdict::Approve);
    }

    #[tokio::test]
    async fn plan_review_closed_session_returns_gone() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_run = record_planner_run(&state, session.session_id());
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        let reviewer = record_reviewer_run(&state, session.session_id(), plan_id);
        state
            .audit
            .close_session(session.session_id(), UnixMillis::now())
            .unwrap();
        let service = plan_service_for_test(&state);

        let body = review_submission_body(reviewer, crate::agent_plan::Verdict::Approve, None);
        let response = handle_plan_review_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Gone);
        assert!(
            state
                .audit
                .list_plan_reviews_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    /// End-to-end through `dispatch_vm_http_head_and_body`: the
    /// `parse_plan_reviews_target` wire-up in `mod.rs` is exercised
    /// (URL → handler → audit row), and the per-route body cap admits
    /// a normally-sized request.
    #[tokio::test]
    async fn plan_review_full_dispatch_records_audit() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_run = record_planner_run(&state, session.session_id());
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan via dispatch");
        let reviewer = record_reviewer_run(&state, session.session_id(), plan_id);
        let service = plan_service_for_test(&state);

        let bearer_auth = bearer(token().as_str());
        let body =
            review_submission_body(reviewer, crate::agent_plan::Verdict::Approve, Some("LGTM"));
        let content_length = body.len().to_string();
        let target = crate::agent_plan::vm_plan_reviews_path(plan_id);
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "POST",
            &target,
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
        let created: ReviewCreated = serde_json::from_slice(&response.body).unwrap();
        let stored = state
            .audit
            .get_plan_review(created.review_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.plan_id, plan_id);
        assert_eq!(stored.agent_run_id, reviewer);
        assert_eq!(stored.verdict, crate::agent_plan::Verdict::Approve);
        assert_eq!(stored.feedback.as_ref().map(|f| f.as_str()), Some("LGTM"));
    }

    // --- POST /v1/plans/<plan_id>/addenda ---------------------------

    /// Fixture: land an `Accepted` decision on `plan_id` from `decider`.
    /// Addendum tests need this because the route's stage+decision gate
    /// only admits execute-stage runs against accepted plans.
    fn record_accepted_decision(
        state: &BrokerState<Box<dyn SecretStore>>,
        plan_id: PlanId,
        decider: &str,
    ) {
        use crate::agent_plan::{Decider, DecisionOutcome};
        use crate::audit::PlanDecisionRecord;
        state
            .audit
            .record_plan_decision(&PlanDecisionRecord {
                plan_id,
                decided_at: UnixMillis::now(),
                outcome: DecisionOutcome::Accepted,
                decider: Decider::try_new(decider).unwrap(),
            })
            .unwrap();
    }

    /// Fixture: create an executor (execute-stage) run on `session_id`
    /// bound to `plan_id` via `read_plan_id`.
    fn record_executor_run(
        state: &BrokerState<Box<dyn SecretStore>>,
        session_id: SessionId,
        plan_id: PlanId,
    ) -> AgentRunId {
        record_run_at_stage_with_read_plan(
            state,
            session_id,
            crate::agent_plan::Stage::Execute,
            Some(plan_id),
        )
    }

    fn addendum_submission_body(body: &str) -> Vec<u8> {
        serde_json::to_vec(&crate::agent_plan::AddendumSubmission {
            body: PlanBody::try_new(body).unwrap(),
        })
        .unwrap()
    }

    /// Fixture: set up an Accepted plan on a *separate* planner
    /// session, so the calling session can be reserved for the run
    /// under test. `agent_run_for_session` returns the most-recent
    /// run on a session, so addendum tests that put the planner and
    /// the executor on the same session can race when the two
    /// `requested_at` timestamps land in the same millisecond. The
    /// separate-session pattern is the same one used by the read-route
    /// tests via `record_plan_via_separate_planner`.
    fn setup_accepted_plan_on_separate_session(
        state: &BrokerState<Box<dyn SecretStore>>,
        planner_session_id: SessionId,
        plan_body: &str,
    ) -> PlanId {
        open_session_for(state, planner_session_id);
        let planner_run = record_planner_run(state, planner_session_id);
        let plan_id = submit_plan_for_run(state, planner_run, plan_body);
        record_accepted_decision(state, plan_id, "operator-1");
        plan_id
    }

    /// `parse_plan_addenda_target` is the URL-shape gate for the
    /// addenda route. Mirrors `parse_plan_reviews_target_*`.
    #[test]
    fn parse_plan_addenda_target_accepts_well_formed_and_rejects_others() {
        let plan_id = PlanId::new();
        let ok = format!("/v1/plans/{plan_id}/addenda");
        assert_eq!(parse_plan_addenda_target(&ok), Some(plan_id));

        // Missing `/addenda` suffix.
        let bare = format!("/v1/plans/{plan_id}");
        assert_eq!(parse_plan_addenda_target(&bare), None);

        // Extra segment after `/addenda`.
        let deeper = format!("/v1/plans/{plan_id}/addenda/extra");
        assert_eq!(parse_plan_addenda_target(&deeper), None);

        // Slash inside the id segment.
        let with_slash = format!("/v1/plans/a/{plan_id}/addenda");
        assert_eq!(parse_plan_addenda_target(&with_slash), None);

        // Not a UUID.
        assert_eq!(
            parse_plan_addenda_target("/v1/plans/not-a-uuid/addenda"),
            None
        );

        // Wrong prefix.
        assert_eq!(parse_plan_addenda_target("/plans/x/addenda"), None);

        // Just the collection — must not match the addenda parser.
        assert_eq!(parse_plan_addenda_target("/v1/plans"), None);

        // The reviews sub-route is not the addenda sub-route.
        let reviews = format!("/v1/plans/{plan_id}/reviews");
        assert_eq!(parse_plan_addenda_target(&reviews), None);
    }

    /// With `services.plans = None`, the addenda route is dark: all
    /// methods return 404. Mirrors
    /// `disabled_plan_reviews_route_is_not_found_for_all_methods`.
    #[tokio::test]
    async fn disabled_plan_addenda_route_is_not_found_for_all_methods() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345));
        let target = crate::agent_plan::vm_plan_addenda_path(PlanId::new());

        for method in ["GET", "POST", "PUT", "DELETE"] {
            let request = VmHttpRequest::new(method, &target, Some(bearer(token().as_str())), peer);
            let response =
                route_authenticated_vm_http_request(&session, &request, Vec::new(), no_services())
                    .await
                    .into_buffered();

            assert_eq!(response.status, VmHttpStatus::NotFound);
        }
    }

    #[tokio::test]
    async fn enabled_plan_addenda_route_rejects_non_post_methods() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let service = plan_service_for_test(&state);
        let target = crate::agent_plan::vm_plan_addenda_path(PlanId::new());
        let request = VmHttpRequest::new(
            "GET",
            &target,
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
    async fn plan_addendum_rejects_malformed_body_without_audit() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702bbb1".parse().unwrap();
        let plan_id = setup_accepted_plan_on_separate_session(&state, planner_session_id, "# Plan");
        let _executor = record_executor_run(&state, session.session_id(), plan_id);
        let service = plan_service_for_test(&state);

        let response =
            handle_plan_addendum_submission(&session, b"not json".to_vec(), plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::BadRequest);
        assert!(
            state
                .audit
                .list_plan_addenda_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    /// A bearer session with no `agent_run` row cannot post an
    /// addendum. 401 mirrors the read-route shape (no body-named run
    /// to disambiguate against).
    #[tokio::test]
    async fn plan_addendum_session_with_no_run_is_unauthorized() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        // Set up a plan on a separate planner session so the URL is
        // shaped correctly but the calling session has no run.
        let other_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702aaaa".parse().unwrap();
        open_session_for(&state, other_session_id);
        let planner_run = record_planner_run(&state, other_session_id);
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        record_accepted_decision(&state, plan_id, "operator-1");
        let service = plan_service_for_test(&state);

        let body = addendum_submission_body("# Addendum");
        let response = handle_plan_addendum_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        assert!(
            state
                .audit
                .list_plan_addenda_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    /// An execute-stage run bound to plan A cannot post an addendum
    /// against plan B. Binding gate returns 401 (matching the read
    /// route's choice for the same gate).
    #[tokio::test]
    async fn plan_addendum_rejects_run_bound_to_different_plan() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_a: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702bbb2".parse().unwrap();
        let planner_session_b: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702bbb3".parse().unwrap();
        let plan_a = setup_accepted_plan_on_separate_session(&state, planner_session_a, "# Plan A");
        let plan_b = setup_accepted_plan_on_separate_session(&state, planner_session_b, "# Plan B");
        let _executor_of_a = record_executor_run(&state, session.session_id(), plan_a);
        let service = plan_service_for_test(&state);

        let body = addendum_submission_body("# Addendum");
        let response = handle_plan_addendum_submission(&session, body, plan_b, service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        let message = std::str::from_utf8(&response.body).unwrap();
        assert!(message.contains("not bound"), "unexpected body: {message}",);
        assert!(
            state
                .audit
                .list_plan_addenda_for_plan(plan_a)
                .unwrap()
                .is_empty(),
        );
        assert!(
            state
                .audit
                .list_plan_addenda_for_plan(plan_b)
                .unwrap()
                .is_empty(),
        );
    }

    /// A run at the right stage but with `read_plan_id = NULL` cannot
    /// post an addendum — the binding gate requires a Some match.
    #[tokio::test]
    async fn plan_addendum_rejects_executor_without_read_plan_id() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702bbb4".parse().unwrap();
        let plan_id = setup_accepted_plan_on_separate_session(&state, planner_session_id, "# Plan");
        let _unbound_executor = record_run_at_stage(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
        );
        let service = plan_service_for_test(&state);

        let body = addendum_submission_body("# Addendum");
        let response = handle_plan_addendum_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        assert!(
            state
                .audit
                .list_plan_addenda_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    /// A reviewer-stage run bound to the right plan is rejected by the
    /// stage gate with 403. Distinguishes the "wrong stage" outcome
    /// from the 401 binding-mismatch path.
    #[tokio::test]
    async fn plan_addendum_rejects_non_execute_stage_run() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702bbb5".parse().unwrap();
        let plan_id = setup_accepted_plan_on_separate_session(&state, planner_session_id, "# Plan");
        // A reviewer bound to the plan — stage gate must reject before
        // the audit write.
        let _reviewer = record_reviewer_run(&state, session.session_id(), plan_id);
        let service = plan_service_for_test(&state);

        let body = addendum_submission_body("# Addendum");
        let response = handle_plan_addendum_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let message = std::str::from_utf8(&response.body).unwrap();
        assert!(
            message.contains("submit_addendum"),
            "unexpected body: {message}",
        );
        assert!(
            state
                .audit
                .list_plan_addenda_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    /// An execute-stage run bound to the right plan but with no
    /// `plan_decision` row is rejected by the stage+decision gate. 403
    /// `DecisionNotAccepted`, not 401.
    #[tokio::test]
    async fn plan_addendum_rejects_when_decision_missing() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        // Plan submitted on a separate session, but deliberately no
        // Accepted decision recorded — gate must reject.
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702bbb6".parse().unwrap();
        open_session_for(&state, planner_session_id);
        let planner_run = record_planner_run(&state, planner_session_id);
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        let _executor = record_executor_run(&state, session.session_id(), plan_id);
        let service = plan_service_for_test(&state);

        let body = addendum_submission_body("# Addendum");
        let response = handle_plan_addendum_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let message = std::str::from_utf8(&response.body).unwrap();
        assert!(
            message.contains("decision") && message.contains("no decision recorded"),
            "unexpected body: {message}",
        );
        assert!(
            state
                .audit
                .list_plan_addenda_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    /// An execute-stage run against a plan with a `RejectedRestart`
    /// decision is rejected by the stage+decision gate. 403 with the
    /// decision name in the message — same shape as the read route.
    #[tokio::test]
    async fn plan_addendum_rejects_when_decision_not_accepted() {
        use crate::agent_plan::{Decider, DecisionOutcome};
        use crate::audit::PlanDecisionRecord;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702bbb7".parse().unwrap();
        open_session_for(&state, planner_session_id);
        let planner_run = record_planner_run(&state, planner_session_id);
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        state
            .audit
            .record_plan_decision(&PlanDecisionRecord {
                plan_id,
                decided_at: UnixMillis::now(),
                outcome: DecisionOutcome::RejectedRestart,
                decider: Decider::try_new("operator-1").unwrap(),
            })
            .unwrap();
        let _executor = record_executor_run(&state, session.session_id(), plan_id);
        let service = plan_service_for_test(&state);

        let body = addendum_submission_body("# Addendum");
        let response = handle_plan_addendum_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let message = std::str::from_utf8(&response.body).unwrap();
        assert!(
            message.contains("decision") && message.contains("rejected_restart"),
            "unexpected body: {message}",
        );
        assert!(
            state
                .audit
                .list_plan_addenda_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    /// Happy path: an execute-stage run bound to an accepted plan
    /// posts an addendum. 200 with `AddendumCreated`; the audit row
    /// reflects the run/plan binding and the same `addendum_id`.
    #[tokio::test]
    async fn plan_addendum_records_audit_row_and_returns_addendum_id() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702bbb8".parse().unwrap();
        let plan_id = setup_accepted_plan_on_separate_session(&state, planner_session_id, "# Plan");
        let executor = record_executor_run(&state, session.session_id(), plan_id);
        let service = plan_service_for_test(&state);

        let body = addendum_submission_body("# First addendum body");
        let response = handle_plan_addendum_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let created: AddendumCreated = serde_json::from_slice(&response.body).unwrap();
        let stored = state
            .audit
            .get_plan_addendum(created.addendum_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.addendum_id, created.addendum_id);
        assert_eq!(stored.plan_id, plan_id);
        assert_eq!(stored.agent_run_id, executor);
        assert_eq!(stored.body.as_str(), "# First addendum body");
    }

    /// Two addenda from the same executor run are forbidden by
    /// `UNIQUE(agent_run_id)` on `plan_addendum`. The second attempt
    /// returns 409 and leaves only the first row in place.
    #[tokio::test]
    async fn plan_addendum_rejects_second_addendum_for_same_run() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702bbb9".parse().unwrap();
        let plan_id = setup_accepted_plan_on_separate_session(&state, planner_session_id, "# Plan");
        let _executor = record_executor_run(&state, session.session_id(), plan_id);

        let first = handle_plan_addendum_submission(
            &session,
            addendum_submission_body("# First"),
            plan_id,
            plan_service_for_test(&state),
        )
        .await;
        assert_eq!(first.status, VmHttpStatus::Ok);

        let second = handle_plan_addendum_submission(
            &session,
            addendum_submission_body("# Second"),
            plan_id,
            plan_service_for_test(&state),
        )
        .await;
        assert_eq!(second.status, VmHttpStatus::Conflict);

        let rows = state.audit.list_plan_addenda_for_plan(plan_id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].body.as_str(), "# First");
    }

    /// Closing the session between setup and the addendum write
    /// surfaces as 410 Gone (matching the review/submission shape for
    /// the same audit invariant).
    #[tokio::test]
    async fn plan_addendum_closed_session_returns_gone() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702bbba".parse().unwrap();
        let plan_id = setup_accepted_plan_on_separate_session(&state, planner_session_id, "# Plan");
        let _executor = record_executor_run(&state, session.session_id(), plan_id);
        state
            .audit
            .close_session(session.session_id(), UnixMillis::now())
            .unwrap();
        let service = plan_service_for_test(&state);

        let body = addendum_submission_body("# Addendum");
        let response = handle_plan_addendum_submission(&session, body, plan_id, service).await;

        // The route's session→run lookup happens before the write,
        // and `agent_run_for_session` returns the run regardless of
        // the session's closed state — the DAO's "session is closed"
        // invariant is what we expect to surface here.
        assert_eq!(response.status, VmHttpStatus::Gone);
        assert!(
            state
                .audit
                .list_plan_addenda_for_plan(plan_id)
                .unwrap()
                .is_empty(),
        );
    }

    /// End-to-end through `dispatch_vm_http_head_and_body`: exercises
    /// the `parse_plan_addenda_target` wire-up and the per-route body
    /// cap from `mod.rs`. Regression for the URL → handler →
    /// audit-row path.
    #[tokio::test]
    async fn plan_addendum_full_dispatch_records_audit() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702bbbb".parse().unwrap();
        let plan_id = setup_accepted_plan_on_separate_session(
            &state,
            planner_session_id,
            "# Plan via dispatch",
        );
        let executor = record_executor_run(&state, session.session_id(), plan_id);
        let service = plan_service_for_test(&state);

        let bearer_auth = bearer(token().as_str());
        let body = addendum_submission_body("# Dispatch addendum");
        let content_length = body.len().to_string();
        let target = crate::agent_plan::vm_plan_addenda_path(plan_id);
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "POST",
            &target,
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
        let created: AddendumCreated = serde_json::from_slice(&response.body).unwrap();
        let stored = state
            .audit
            .get_plan_addendum(created.addendum_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.plan_id, plan_id);
        assert_eq!(stored.agent_run_id, executor);
        assert_eq!(stored.body.as_str(), "# Dispatch addendum");
    }

    /// Body-limit budget regression for the addenda route: a
    /// maximum-size addendum body packed with worst-case
    /// JSON-expanding bytes (any control byte 0x01..=0x1f expands 6:1
    /// as `\u00XX`) must still be admitted.
    #[tokio::test]
    async fn plan_addendum_admits_max_body_with_worst_case_json_expansion() {
        use crate::agent_plan::MAX_PLAN_BODY_BYTES;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702bbbc".parse().unwrap();
        let plan_id = setup_accepted_plan_on_separate_session(&state, planner_session_id, "# Plan");
        let _executor = record_executor_run(&state, session.session_id(), plan_id);
        let service = plan_service_for_test(&state);

        let raw_body = "\u{0001}".repeat(MAX_PLAN_BODY_BYTES);
        let body = addendum_submission_body(&raw_body);
        assert!(
            body.len() > MAX_PLAN_BODY_BYTES,
            "test premise: encoded body must exceed the decoded length",
        );
        let bearer_auth = bearer(token().as_str());
        let content_length = body.len().to_string();
        let target = crate::agent_plan::vm_plan_addenda_path(plan_id);
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "POST",
            &target,
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
        let created: AddendumCreated = serde_json::from_slice(&response.body).unwrap();
        let stored = state
            .audit
            .get_plan_addendum(created.addendum_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.body.as_str().len(), MAX_PLAN_BODY_BYTES);
    }

    /// Regression for the body-limit budget: a maximum-size feedback
    /// body packed with worst-case JSON-expanding bytes (any control
    /// byte 0x01..=0x1f expands 6:1 as `\u00XX`) must still be
    /// admitted. NUL (0x00) is rejected by `PlanFeedback::try_new` at
    /// the parse boundary, so SOH (0x01) carries the same property.
    #[tokio::test]
    async fn plan_review_admits_max_feedback_with_worst_case_json_expansion() {
        use crate::agent_plan::MAX_PLAN_FEEDBACK_BYTES;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_run = record_planner_run(&state, session.session_id());
        let plan_id = submit_plan_for_run(&state, planner_run, "# Plan");
        let reviewer = record_reviewer_run(&state, session.session_id(), plan_id);
        let service = plan_service_for_test(&state);

        let raw_feedback = "\u{0001}".repeat(MAX_PLAN_FEEDBACK_BYTES);
        let body = review_submission_body(
            reviewer,
            crate::agent_plan::Verdict::RequestChanges,
            Some(&raw_feedback),
        );
        assert!(
            body.len() > MAX_PLAN_FEEDBACK_BYTES,
            "test premise: encoded body must exceed the decoded length",
        );
        let bearer_auth = bearer(token().as_str());
        let content_length = body.len().to_string();
        let target = crate::agent_plan::vm_plan_reviews_path(plan_id);
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "POST",
            &target,
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
        let created: ReviewCreated = serde_json::from_slice(&response.body).unwrap();
        let stored = state
            .audit
            .get_plan_review(created.review_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.feedback.as_ref().map(|f| f.as_str().len()),
            Some(MAX_PLAN_FEEDBACK_BYTES),
        );
    }

    // --- POST /v1/plans/<plan_id>/abort ------------------------------

    fn abort_submission_body(reason: &str) -> Vec<u8> {
        use crate::agent_plan::{AbortSubmission, PlanAbortReason};
        serde_json::to_vec(&AbortSubmission {
            reason: PlanAbortReason::try_new(reason).unwrap(),
        })
        .unwrap()
    }

    /// Fixture: set up an accepted plan on a separate planner session.
    /// Mirrors `setup_accepted_plan_on_separate_session` — the abort
    /// route is execute-stage only and `agent_run_for_session` returns
    /// the latest run, so the planner and executor share a session
    /// only when test timestamps differ.
    fn setup_plan_on_separate_session_with_decision(
        state: &BrokerState<Box<dyn SecretStore>>,
        planner_session_id: SessionId,
        plan_body: &str,
        decision: Option<crate::agent_plan::DecisionOutcome>,
    ) -> PlanId {
        open_session_for(state, planner_session_id);
        let planner_run = record_planner_run(state, planner_session_id);
        let plan_id = submit_plan_for_run(state, planner_run, plan_body);
        if let Some(outcome) = decision {
            use crate::agent_plan::Decider;
            use crate::audit::PlanDecisionRecord;
            state
                .audit
                .record_plan_decision(&PlanDecisionRecord {
                    plan_id,
                    decided_at: UnixMillis::now(),
                    outcome,
                    decider: Decider::try_new("operator-1").unwrap(),
                })
                .unwrap();
        }
        plan_id
    }

    /// `parse_plan_abort_target` is the URL-shape gate for the abort
    /// route. Same shape as the reviews and addenda parsers.
    #[test]
    fn parse_plan_abort_target_accepts_well_formed_and_rejects_others() {
        let plan_id = PlanId::new();
        let ok = format!("/v1/plans/{plan_id}/abort");
        assert_eq!(parse_plan_abort_target(&ok), Some(plan_id));

        // Missing `/abort` suffix.
        let bare = format!("/v1/plans/{plan_id}");
        assert_eq!(parse_plan_abort_target(&bare), None);

        // Extra segment after `/abort`.
        let deeper = format!("/v1/plans/{plan_id}/abort/extra");
        assert_eq!(parse_plan_abort_target(&deeper), None);

        // Slash inside the id segment.
        let with_slash = format!("/v1/plans/a/{plan_id}/abort");
        assert_eq!(parse_plan_abort_target(&with_slash), None);

        // Not a UUID.
        assert_eq!(parse_plan_abort_target("/v1/plans/not-a-uuid/abort"), None,);

        // Wrong prefix.
        assert_eq!(parse_plan_abort_target("/plans/x/abort"), None);

        // Just the collection — must not match the abort parser.
        assert_eq!(parse_plan_abort_target("/v1/plans"), None);

        // The other sub-routes are not the abort sub-route.
        let reviews = format!("/v1/plans/{plan_id}/reviews");
        assert_eq!(parse_plan_abort_target(&reviews), None);
        let addenda = format!("/v1/plans/{plan_id}/addenda");
        assert_eq!(parse_plan_abort_target(&addenda), None);
    }

    /// With `services.plans = None`, the abort route is dark: all
    /// methods return 404. Mirrors the addenda-route dark test.
    #[tokio::test]
    async fn disabled_plan_abort_route_is_not_found_for_all_methods() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345));
        let target = crate::agent_plan::vm_plan_abort_path(PlanId::new());

        for method in ["GET", "POST", "PUT", "DELETE"] {
            let request = VmHttpRequest::new(method, &target, Some(bearer(token().as_str())), peer);
            let response =
                route_authenticated_vm_http_request(&session, &request, Vec::new(), no_services())
                    .await
                    .into_buffered();

            assert_eq!(response.status, VmHttpStatus::NotFound);
        }
    }

    #[tokio::test]
    async fn enabled_plan_abort_route_rejects_non_post_methods() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let service = plan_service_for_test(&state);
        let target = crate::agent_plan::vm_plan_abort_path(PlanId::new());
        let request = VmHttpRequest::new(
            "GET",
            &target,
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
    async fn plan_abort_rejects_malformed_body_without_audit() {
        use crate::agent_plan::DecisionOutcome;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c001".parse().unwrap();
        let plan_id = setup_plan_on_separate_session_with_decision(
            &state,
            planner_session_id,
            "# Plan",
            Some(DecisionOutcome::Accepted),
        );
        let _executor = record_run_at_stage_with_read_plan(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
            Some(plan_id),
        );
        let service = plan_service_for_test(&state);

        let response =
            handle_plan_abort_submission(&session, b"not json".to_vec(), plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::BadRequest);
        assert!(state.audit.get_plan_abort(plan_id).unwrap().is_none());
    }

    /// A bearer session with no `agent_run` row cannot post an abort.
    /// 401 mirrors the addendum-route shape.
    #[tokio::test]
    async fn plan_abort_session_with_no_run_is_unauthorized() {
        use crate::agent_plan::DecisionOutcome;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let other_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c002".parse().unwrap();
        let plan_id = setup_plan_on_separate_session_with_decision(
            &state,
            other_session_id,
            "# Plan",
            Some(DecisionOutcome::Accepted),
        );
        let service = plan_service_for_test(&state);

        let body = abort_submission_body("plan turned out to be unworkable");
        let response = handle_plan_abort_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        assert!(state.audit.get_plan_abort(plan_id).unwrap().is_none());
    }

    /// An execute-stage run bound to plan A cannot post an abort
    /// against plan B. Binding gate returns 401, matching the addenda
    /// route's choice for the same gate.
    #[tokio::test]
    async fn plan_abort_rejects_run_bound_to_different_plan() {
        use crate::agent_plan::DecisionOutcome;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_a: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c003".parse().unwrap();
        let planner_session_b: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c004".parse().unwrap();
        let plan_a = setup_plan_on_separate_session_with_decision(
            &state,
            planner_session_a,
            "# Plan A",
            Some(DecisionOutcome::Accepted),
        );
        let plan_b = setup_plan_on_separate_session_with_decision(
            &state,
            planner_session_b,
            "# Plan B",
            Some(DecisionOutcome::Accepted),
        );
        let _executor_of_a = record_run_at_stage_with_read_plan(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
            Some(plan_a),
        );
        let service = plan_service_for_test(&state);

        let body = abort_submission_body("unworkable");
        let response = handle_plan_abort_submission(&session, body, plan_b, service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        let message = std::str::from_utf8(&response.body).unwrap();
        assert!(message.contains("not bound"), "unexpected body: {message}",);
        assert!(state.audit.get_plan_abort(plan_a).unwrap().is_none());
        assert!(state.audit.get_plan_abort(plan_b).unwrap().is_none());
    }

    /// A run at the right stage but with `read_plan_id = NULL` cannot
    /// post an abort — the binding gate requires a Some match.
    #[tokio::test]
    async fn plan_abort_rejects_executor_without_read_plan_id() {
        use crate::agent_plan::DecisionOutcome;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c005".parse().unwrap();
        let plan_id = setup_plan_on_separate_session_with_decision(
            &state,
            planner_session_id,
            "# Plan",
            Some(DecisionOutcome::Accepted),
        );
        let _unbound_executor = record_run_at_stage(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
        );
        let service = plan_service_for_test(&state);

        let body = abort_submission_body("unworkable");
        let response = handle_plan_abort_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        assert!(state.audit.get_plan_abort(plan_id).unwrap().is_none());
    }

    /// A reviewer-stage run bound to the right plan is rejected by the
    /// stage gate with 403. Distinguishes the wrong-stage outcome from
    /// the 401 binding-mismatch path.
    #[tokio::test]
    async fn plan_abort_rejects_non_execute_stage_run() {
        use crate::agent_plan::DecisionOutcome;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c006".parse().unwrap();
        let plan_id = setup_plan_on_separate_session_with_decision(
            &state,
            planner_session_id,
            "# Plan",
            Some(DecisionOutcome::Accepted),
        );
        let _reviewer = record_reviewer_run(&state, session.session_id(), plan_id);
        let service = plan_service_for_test(&state);

        let body = abort_submission_body("unworkable");
        let response = handle_plan_abort_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let message = std::str::from_utf8(&response.body).unwrap();
        assert!(
            message.contains("submit_abort"),
            "unexpected body: {message}",
        );
        assert!(state.audit.get_plan_abort(plan_id).unwrap().is_none());
    }

    /// Spec-significant difference from the addendum route: a hard-
    /// abort against a plan with **no** decision row is admitted, not
    /// 403'd. `SubmitAbort` deliberately omits the acceptance gate.
    #[tokio::test]
    async fn plan_abort_admits_undecided_plan() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c007".parse().unwrap();
        let plan_id = setup_plan_on_separate_session_with_decision(
            &state,
            planner_session_id,
            "# Plan",
            None,
        );
        let executor = record_run_at_stage_with_read_plan(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
            Some(plan_id),
        );
        let service = plan_service_for_test(&state);

        let body = abort_submission_body("plan turned out to be unworkable");
        let response = handle_plan_abort_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let stored = state.audit.get_plan_abort(plan_id).unwrap().unwrap();
        assert_eq!(stored.plan_id, plan_id);
        assert_eq!(stored.agent_run_id, executor);
        assert_eq!(stored.reason.as_str(), "plan turned out to be unworkable");
    }

    /// Spec-significant: a hard-abort against a `RejectedRestart`
    /// plan is also admitted. The operator may flip the decision
    /// later; in the meantime the executor's abort signal still lands.
    #[tokio::test]
    async fn plan_abort_admits_rejected_plan() {
        use crate::agent_plan::DecisionOutcome;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c008".parse().unwrap();
        let plan_id = setup_plan_on_separate_session_with_decision(
            &state,
            planner_session_id,
            "# Plan",
            Some(DecisionOutcome::RejectedRestart),
        );
        let executor = record_run_at_stage_with_read_plan(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
            Some(plan_id),
        );
        let service = plan_service_for_test(&state);

        let body = abort_submission_body("nope");
        let response = handle_plan_abort_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let stored = state.audit.get_plan_abort(plan_id).unwrap().unwrap();
        assert_eq!(stored.agent_run_id, executor);
    }

    /// Happy path: an execute-stage run bound to an accepted plan
    /// posts an abort. 200 with `AbortRecorded`; the audit row
    /// matches the request.
    #[tokio::test]
    async fn plan_abort_records_audit_row_and_returns_aborted_at() {
        use crate::agent_plan::DecisionOutcome;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c009".parse().unwrap();
        let plan_id = setup_plan_on_separate_session_with_decision(
            &state,
            planner_session_id,
            "# Plan",
            Some(DecisionOutcome::Accepted),
        );
        let executor = record_run_at_stage_with_read_plan(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
            Some(plan_id),
        );
        let service = plan_service_for_test(&state);

        let body = abort_submission_body("unworkable for these reasons");
        let response = handle_plan_abort_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        let recorded: AbortRecorded = serde_json::from_slice(&response.body).unwrap();
        let stored = state.audit.get_plan_abort(plan_id).unwrap().unwrap();
        assert_eq!(stored.plan_id, plan_id);
        assert_eq!(stored.agent_run_id, executor);
        assert_eq!(stored.reason.as_str(), "unworkable for these reasons");
        // The wire-side `aborted_at` is the value the audit row was
        // stamped with; the handler reads `UnixMillis::now()` once and
        // hands the same value to both sides.
        assert_eq!(stored.aborted_at, recorded.aborted_at);
    }

    /// A second abort against the same plan is forbidden by the
    /// PRIMARY KEY on `plan_abort.plan_id` (one abort per plan, not
    /// per run). Surfaces as 409 with the first row left in place.
    #[tokio::test]
    async fn plan_abort_rejects_second_abort_for_same_plan() {
        use crate::agent_plan::DecisionOutcome;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c00a".parse().unwrap();
        let plan_id = setup_plan_on_separate_session_with_decision(
            &state,
            planner_session_id,
            "# Plan",
            Some(DecisionOutcome::Accepted),
        );
        let _executor = record_run_at_stage_with_read_plan(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
            Some(plan_id),
        );

        let first = handle_plan_abort_submission(
            &session,
            abort_submission_body("first"),
            plan_id,
            plan_service_for_test(&state),
        )
        .await;
        assert_eq!(first.status, VmHttpStatus::Ok);

        let second = handle_plan_abort_submission(
            &session,
            abort_submission_body("second"),
            plan_id,
            plan_service_for_test(&state),
        )
        .await;
        assert_eq!(second.status, VmHttpStatus::Conflict);
        let message = std::str::from_utf8(&second.body).unwrap();
        assert!(
            message.contains("already aborted"),
            "unexpected body: {message}",
        );

        let stored = state.audit.get_plan_abort(plan_id).unwrap().unwrap();
        assert_eq!(stored.reason.as_str(), "first");
    }

    /// Closing the session between setup and the abort write surfaces
    /// as 410 Gone (same as the addendum/review routes for the same
    /// audit invariant).
    #[tokio::test]
    async fn plan_abort_closed_session_returns_gone() {
        use crate::agent_plan::DecisionOutcome;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c00b".parse().unwrap();
        let plan_id = setup_plan_on_separate_session_with_decision(
            &state,
            planner_session_id,
            "# Plan",
            Some(DecisionOutcome::Accepted),
        );
        let _executor = record_run_at_stage_with_read_plan(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
            Some(plan_id),
        );
        state
            .audit
            .close_session(session.session_id(), UnixMillis::now())
            .unwrap();
        let service = plan_service_for_test(&state);

        let body = abort_submission_body("late");
        let response = handle_plan_abort_submission(&session, body, plan_id, service).await;

        assert_eq!(response.status, VmHttpStatus::Gone);
        assert!(state.audit.get_plan_abort(plan_id).unwrap().is_none());
    }

    /// End-to-end through `dispatch_vm_http_head_and_body`: exercises
    /// the `parse_plan_abort_target` wire-up and the per-route body
    /// cap from `mod.rs`. Regression for URL → handler → audit-row.
    #[tokio::test]
    async fn plan_abort_full_dispatch_records_audit() {
        use crate::agent_plan::DecisionOutcome;

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c00c".parse().unwrap();
        let plan_id = setup_plan_on_separate_session_with_decision(
            &state,
            planner_session_id,
            "# Plan via dispatch",
            Some(DecisionOutcome::Accepted),
        );
        let executor = record_run_at_stage_with_read_plan(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
            Some(plan_id),
        );
        let service = plan_service_for_test(&state);

        let bearer_auth = bearer(token().as_str());
        let body = abort_submission_body("dispatched abort");
        let content_length = body.len().to_string();
        let target = crate::agent_plan::vm_plan_abort_path(plan_id);
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "POST",
            &target,
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
        let recorded: AbortRecorded = serde_json::from_slice(&response.body).unwrap();
        let stored = state.audit.get_plan_abort(plan_id).unwrap().unwrap();
        assert_eq!(stored.plan_id, plan_id);
        assert_eq!(stored.agent_run_id, executor);
        assert_eq!(stored.reason.as_str(), "dispatched abort");
        assert_eq!(stored.aborted_at, recorded.aborted_at);
    }

    /// Body-limit budget regression for the abort route: a maximum-
    /// size reason packed with worst-case JSON-expanding bytes (any
    /// ASCII control byte 0x01..=0x1f expands 6:1 as `\u00XX`) must
    /// still be admitted. NUL (0x00) is rejected by
    /// `PlanAbortReason::try_new` at the parse boundary, so SOH (0x01)
    /// carries the property.
    #[tokio::test]
    async fn plan_abort_admits_max_reason_with_worst_case_json_expansion() {
        use crate::agent_plan::{DecisionOutcome, MAX_PLAN_ABORT_REASON_BYTES};

        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let planner_session_id: SessionId = "82ab0bb1-7c12-4a4e-9f51-6d3d7702c00d".parse().unwrap();
        let plan_id = setup_plan_on_separate_session_with_decision(
            &state,
            planner_session_id,
            "# Plan",
            Some(DecisionOutcome::Accepted),
        );
        let _executor = record_run_at_stage_with_read_plan(
            &state,
            session.session_id(),
            crate::agent_plan::Stage::Execute,
            Some(plan_id),
        );
        let service = plan_service_for_test(&state);

        let raw_reason = "\u{0001}".repeat(MAX_PLAN_ABORT_REASON_BYTES);
        let body = abort_submission_body(&raw_reason);
        assert!(
            body.len() > MAX_PLAN_ABORT_REASON_BYTES,
            "test premise: encoded body must exceed the decoded length",
        );
        let bearer_auth = bearer(token().as_str());
        let content_length = body.len().to_string();
        let target = crate::agent_plan::vm_plan_abort_path(plan_id);
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "POST",
            &target,
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
        let stored = state.audit.get_plan_abort(plan_id).unwrap().unwrap();
        assert_eq!(stored.reason.as_str().len(), MAX_PLAN_ABORT_REASON_BYTES);
    }
}
