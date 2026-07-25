//! The generic VM-HTTP effect driver.
//!
//! [`broker_effect`] owns the audit sequencing for a brokered VM-HTTP effect:
//! acquire the guard (begin a session-open-checked request row, durable *before*
//! the effect — or, for an outcome-only effect, resume the row an earlier
//! lifecycle event minted), run the effect, then complete the matching outcome row — or, for a streaming
//! response, thread the audit guard into the response body so the outcome is
//! recorded when the body drains. Because the *driver*, not the effect impl,
//! holds and discharges the [`RecordedRequest`] guard, no effect can perform its
//! IO without recording the `(request, outcome)` pair: the guard is
//! `#[must_use]`, and it never leaves this function except into a streaming body
//! that completes it on drop. Acquisition is likewise the driver's: an effect
//! supplies only the *description* of how to acquire (a request row, or a key to
//! resume).
//!
//! Effects declare their per-effect variation through [`BrokeredEffect`] (which
//! audit table, how to build the request row or resume an earlier one, how to run
//! the effect); the driver owns the sequence. This is the Stage-4 shape from
//! `docs/plans/2026-07-18-brokered-effect-audit-enforcement.md`: it drives both
//! model proxies, git-push staging, flake provisioning, and agent-run outcomes.

use std::sync::Arc;

use super::{VmHttpDispatch, VmHttpResponse, VmHttpStatus};
use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, AuditLog, EffectAuditTable, RecordedRequest,
};

/// A brokered VM-HTTP effect whose `(request, outcome)` audit pair is written by
/// the [`broker_effect`] driver, not by the effect itself.
///
/// The trait carries only what the driver needs to sequence the audit pair; the
/// heterogeneous IO stays in the impl's [`perform`](BrokeredEffect::perform).
#[allow(async_fn_in_trait)]
pub(in crate::vm_http) trait BrokeredEffect: Sized {
    /// The audit `(request, outcome)` table pair this effect records into.
    type Table: EffectAuditTable;
    /// Owned outcome payload produced by [`perform`](BrokeredEffect::perform).
    /// [`outcome_row`](BrokeredEffect::outcome_row) borrows an outcome row out of
    /// it just before the guard is completed — so the row can borrow owned data
    /// (`upstream_url`, `error`) that outlives `perform`'s stack frame.
    type Outcome;

    /// `kind = …` on the [`AUDIT_WRITE_FAILURE_TARGET`] event when the
    /// request-row write fails.
    const REQUEST_AUDIT_KIND: &'static str;
    /// `kind = …` on the [`AUDIT_WRITE_FAILURE_TARGET`] event when the
    /// outcome-row write fails.
    const OUTCOME_AUDIT_KIND: &'static str;

    /// The identifier logged on an audit fault: this effect's audit key, as it
    /// appears in the `(request, outcome)` rows. Returned as a `Display` rather
    /// than a `RequestId` because the key type is per table — a `RequestId` for
    /// the proxies and flake provisioning, a push request id for git-push, an
    /// `AgentRunId` for agent runs — and labelling a run id as a request id in
    /// the log would be a small lie in exactly the place an operator is trying to
    /// correlate rows.
    fn audit_key(&self) -> impl std::fmt::Display + '_;

    /// The request row to begin the guard with — its Allow/Deny decision baked in
    /// by the impl.
    fn request_row(&self) -> <Self::Table as EffectAuditTable>::RequestRow<'_>;

    /// Run the effect (or short-circuit a denial), consuming the effect. Returns
    /// either a buffered outcome+response the driver completes immediately, or a
    /// streaming completion that takes ownership of the guard.
    async fn perform(self) -> EffectCompletion<Self>;

    /// Borrow an outcome row out of an owned outcome payload.
    fn outcome_row(outcome: &Self::Outcome) -> <Self::Table as EffectAuditTable>::OutcomeRow<'_>;

    /// Map a `begin_effect` failure to a domain client response, or `None` to
    /// fall back to the generic audit-write 500. An *expected* begin failure — a
    /// closed or unknown session — is a clean client error, not an audit-write
    /// failure, so an effect can return its own status/body (git-push maps these
    /// to `410 Gone` / `401 Unauthorized`) and suppress the spurious
    /// `AUDIT_WRITE_FAILURE`. Defaulted to `None`: the proxies keep the generic
    /// 500 for every begin failure.
    fn begin_error_response(_err: &AuditError) -> Option<VmHttpResponse> {
        None
    }

    /// Acquire the audit guard the driver holds across the effect.
    ///
    /// Defaulted to the **two-phase** shape: begin a request row from
    /// [`request_row`](BrokeredEffect::request_row), mapping an expected failure
    /// through [`begin_error_response`](BrokeredEffect::begin_error_response).
    /// An **outcome-only** effect — one whose request row was minted by an
    /// earlier lifecycle event, i.e. agent runs — overrides this to call
    /// [`resume_effect`](crate::audit::AuditLog::resume_effect) instead.
    ///
    /// It is an override rather than a `Durability` flag the driver branches on
    /// because `resume_effect` is bounded on `OutcomeOnlyEffect`, which the
    /// generic driver cannot carry: resolving the bound *where the override is
    /// written* is the same technique [`EffectCompletion::Abandoned`] uses for
    /// `abandon`. The driver still owns the guard from here on, and still owns
    /// the `AUDIT_WRITE_FAILURE` logging — hence [`AcquireFailure`] distinguishes
    /// "answer the guest this" from "an audit write genuinely failed".
    fn acquire(
        &self,
        audit: &Arc<AuditLog>,
    ) -> Result<RecordedRequest<Self::Table>, AcquireFailure> {
        audit
            .begin_effect::<Self::Table>(&self.request_row())
            .map_err(|err| match Self::begin_error_response(&err) {
                Some(response) => AcquireFailure::Answered(response),
                None => AcquireFailure::Audit(err),
            })
    }

    /// The 500 body returned when an audit write genuinely fails (a `begin_effect`
    /// error the effect did not map, or a `complete` failure). Defaulted to a
    /// plain-text body; an effect whose endpoint promises a typed error envelope
    /// overrides this so the contract holds even in the audit-fault mode (git-push
    /// returns its JSON `VmGitPushErrorResponse`). Logging stays centralized in
    /// [`audit_write_500`].
    fn audit_write_failure_response() -> VmHttpResponse {
        VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed")
    }
}

/// Why [`BrokeredEffect::acquire`] produced no guard.
///
/// The split is what keeps the `AUDIT_WRITE_FAILURE` signal meaningful: a
/// refusal the guest simply gets told about (a closed session, an effect that was
/// never begun, a concurrent attempt to record the same outcome) is not an audit
/// *fault*, and must not be logged as one.
pub(in crate::vm_http) enum AcquireFailure {
    /// Answer the guest this, verbatim. Nothing failed to write, so nothing is
    /// logged and no audit row exists.
    Answered(VmHttpResponse),
    /// An audit write or read genuinely failed: the driver logs
    /// [`AUDIT_WRITE_FAILURE_TARGET`] and answers
    /// [`BrokeredEffect::audit_write_failure_response`].
    Audit(AuditError),
}

/// What [`BrokeredEffect::perform`] returns.
pub(in crate::vm_http) enum EffectCompletion<E: BrokeredEffect> {
    /// The outcome is known now: the driver completes the guard with
    /// `E::outcome_row(&outcome)` and returns `response`.
    Buffered {
        outcome: E::Outcome,
        response: VmHttpResponse,
    },
    /// The outcome is known only when the response body drains. The closure takes
    /// ownership of the guard and threads it into the streaming body, which
    /// completes the pair on drop. It is the ONLY consumer of the guard on this
    /// path, so the guard cannot escape unrecorded.
    Streaming(GuardDischarge<E::Table>),
    /// The effect performed IO but has *no truthful outcome* to record — git-push's
    /// staging-IO failure, where no `GitPushOutcomeResult` honestly describes "the
    /// host errored mid-stage". The closure [`abandons`](crate::audit::RecordedRequest::abandon)
    /// the guard (discharging it *without* an outcome, so the Drop backstop stays
    /// silent) and returns `response`, deliberately leaving the request row
    /// dangling for the boot sweep. The `abandon` call inside the closure requires
    /// `E::Table: AbandonableEffect`, so only opted-in effects can build this.
    Abandoned(GuardDischarge<E::Table>),
}

/// A guard-consuming completion: given the live guard, it discharges the guard
/// (by threading it into a streaming body, or by abandoning it) and returns the
/// guest-facing dispatch. Erasing this as a closure is what lets an effect encode
/// a discharge whose type bound (`AbandonableEffect` for abandon) the generic
/// driver need not carry — the bound is resolved where the closure is built.
pub(in crate::vm_http) type GuardDischarge<T> =
    Box<dyn FnOnce(RecordedRequest<T>) -> VmHttpDispatch + Send>;

/// Drive a brokered effect: begin the request row, run the effect, complete the
/// outcome row (or hand the guard to the streaming body). The guard never leaves
/// this function except into a streaming body, so every path records both halves
/// of the audit pair or fails closed with a 500 + `AUDIT_WRITE_FAILURE`.
pub(in crate::vm_http) async fn broker_effect<E: BrokeredEffect>(
    audit: &Arc<AuditLog>,
    effect: E,
) -> VmHttpDispatch {
    let recorded = match effect.acquire(audit) {
        Ok(recorded) => recorded,
        // An *expected* acquisition failure (a closed session, an unbegun or
        // already-claimed effect) is a domain client error the effect maps
        // itself; anything else is an audit-write 500 with the failure logged.
        Err(AcquireFailure::Answered(response)) => return response.into(),
        Err(AcquireFailure::Audit(err)) => {
            return audit_write_500(
                E::REQUEST_AUDIT_KIND,
                &effect.audit_key(),
                err,
                E::audit_write_failure_response(),
            );
        }
    };
    // Durable boundary: the request row is committed. A crash from here — through
    // the effect and its outcome write — leaves a dangling request row the boot
    // sweep reconciles. (Inert in production; only a test `CrashPlan` acts on it.)
    crate::crash_point::point("broker_effect::request_recorded").await;
    // Rendered before `perform` consumes the effect; only the outcome-write
    // failure path below reads it.
    let audit_key = effect.audit_key().to_string();
    match effect.perform().await {
        EffectCompletion::Buffered { outcome, response } => {
            if let Err(err) = recorded.complete(&E::outcome_row(&outcome)) {
                return audit_write_500(
                    E::OUTCOME_AUDIT_KIND,
                    &audit_key,
                    err,
                    E::audit_write_failure_response(),
                );
            }
            // Durable boundary: the outcome row is committed; the pair is complete.
            crate::crash_point::point("broker_effect::outcome_recorded").await;
            response.into()
        }
        // Both discharge the guard (into the stream body, or by abandoning it) and
        // return the dispatch — the guard never escapes the driver un-discharged.
        EffectCompletion::Streaming(discharge) | EffectCompletion::Abandoned(discharge) => {
            discharge(recorded)
        }
    }
}

/// Emit the [`AUDIT_WRITE_FAILURE_TARGET`] event (centralized) and return the
/// effect's audit-failure `response`. Fail-closed: an audit-write failure never
/// lets the guest-facing effect succeed silently.
fn audit_write_500(
    kind: &'static str,
    audit_key: &dyn std::fmt::Display,
    err: AuditError,
    response: VmHttpResponse,
) -> VmHttpDispatch {
    tracing::error!(
        target: AUDIT_WRITE_FAILURE_TARGET,
        kind,
        audit_key = %audit_key,
        error = %err,
        "audit write failed",
    );
    response.into()
}
