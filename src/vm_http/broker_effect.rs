//! The generic VM-HTTP effect driver.
//!
//! [`broker_effect`] owns the audit sequencing for a brokered VM-HTTP effect:
//! begin the request row (session-open-checked, durable *before* the effect),
//! run the effect, then complete the matching outcome row — or, for a streaming
//! response, thread the audit guard into the response body so the outcome is
//! recorded when the body drains. Because the *driver*, not the effect impl,
//! holds and discharges the [`RecordedRequest`] guard, no effect can perform its
//! IO without recording the `(request, outcome)` pair: the guard is
//! `#[must_use]`, and it never leaves this function except into a streaming body
//! that completes it on drop.
//!
//! Effects declare their per-effect variation through [`BrokeredEffect`] (which
//! audit table, how to build the request row, how to run the effect); the driver
//! owns the sequence. This is the Stage-4 shape from
//! `docs/plans/2026-07-18-brokered-effect-audit-enforcement.md`: it drives the
//! two proxies today, and later stages extend the trait for the remaining
//! effects.

use std::sync::Arc;

use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, AuditLog, EffectAuditTable, RecordedRequest,
};
use crate::core::RequestId;

use super::{VmHttpDispatch, VmHttpResponse, VmHttpStatus};

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

    /// The correlation id logged on an audit-write failure. (For the proxies this
    /// is the request row's key.)
    fn request_id(&self) -> RequestId;

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
    let request_id = effect.request_id();
    let recorded = match audit.begin_effect::<E::Table>(&effect.request_row()) {
        Ok(recorded) => recorded,
        // An *expected* begin failure (a closed or unknown session) is a domain
        // client error the effect maps itself; anything else is an audit-write
        // 500 with the failure logged.
        Err(err) => {
            return match E::begin_error_response(&err) {
                Some(response) => response.into(),
                None => audit_write_500(
                    E::REQUEST_AUDIT_KIND,
                    request_id,
                    err,
                    E::audit_write_failure_response(),
                ),
            };
        }
    };
    // Durable boundary: the request row is committed. A crash from here — through
    // the effect and its outcome write — leaves a dangling request row the boot
    // sweep reconciles. (Inert in production; only a test `CrashPlan` acts on it.)
    crate::crash_point::point("broker_effect::request_recorded").await;
    match effect.perform().await {
        EffectCompletion::Buffered { outcome, response } => {
            if let Err(err) = recorded.complete(&E::outcome_row(&outcome)) {
                return audit_write_500(
                    E::OUTCOME_AUDIT_KIND,
                    request_id,
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
    request_id: RequestId,
    err: AuditError,
    response: VmHttpResponse,
) -> VmHttpDispatch {
    tracing::error!(
        target: AUDIT_WRITE_FAILURE_TARGET,
        kind,
        request_id = %request_id,
        error = %err,
        "audit write failed",
    );
    response.into()
}
