//! Tests for [`read_decision_note`] — the slice D1.4 read counterpart
//! to [`crate::bailiff_plan_write::write_decision_note`]. The
//! load-bearing round-trip test drives the actual writer so a future
//! refactor that drifts the writer's seed-OID derivation from the
//! reader's surfaces here; the remaining tests plant bodies directly
//! via the low-level [`NotesRepo::write_note`].
use super::test_support::bailiff_repo;
use super::*;
use crate::bailiff_decision::{Decider, Decision};
use crate::bailiff_plan_note::{
    DecisionNote, PlanId, plan_decision_seed_blob_bytes, plan_notes_ref,
    plan_submission_seed_blob_bytes,
};
use crate::bailiff_plan_write::write_decision_note;
use crate::core::UnixMillis;
use tempfile::TempDir;

fn sample_decision_note(plan_id: PlanId, outcome: Decision) -> DecisionNote {
    DecisionNote {
        plan_id,
        outcome,
        decider: Decider::try_new("cli:alice").unwrap(),
        decided_at: UnixMillis::from_millis(1_700_000_000_456),
    }
}

/// A plan with no decision note attached returns `Ok(None)`.
/// Covers the fresh-repo case where the plan's notes ref does
/// not exist at all — the most common state during normal
/// operation (operator hasn't ruled on this plan yet).
#[test]
fn read_decision_note_returns_none_when_no_decision_recorded() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    let result = read_decision_note(&bailiff, plan_id).unwrap();
    assert!(
        result.is_none(),
        "expected None for an undecided plan, got: {result:?}"
    );
}

/// Load-bearing round-trip: writing a decision and reading it
/// back recovers a byte-for-byte equal [`DecisionNote`]. Pins
/// that the writer's seed-OID derivation matches the reader's
/// — a divergence here would make every decision unrecoverable.
#[test]
fn read_decision_note_round_trips_through_write_decision_note() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    let written = sample_decision_note(plan_id, Decision::Accepted);
    write_decision_note(&bailiff, &written).unwrap();

    let read_back = read_decision_note(&bailiff, plan_id).unwrap();
    assert_eq!(read_back.as_ref(), Some(&written));
}

/// Both outcomes round-trip — pin that the `Decision` enum's
/// serde tagging stays compatible between writer and reader.
/// A regression that flipped to a wrapped tagging
/// (`{"outcome":{"Accepted":null}}`) would break readers writing
/// the new shape against repos written by the old shape.
#[test]
fn read_decision_note_round_trips_both_outcomes() {
    for outcome in [Decision::Accepted, Decision::Rejected] {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let written = sample_decision_note(plan_id, outcome);
        write_decision_note(&bailiff, &written).unwrap();
        let read_back = read_decision_note(&bailiff, plan_id).unwrap();
        assert_eq!(read_back.as_ref(), Some(&written), "outcome {outcome:?}");
    }
}

/// A submission note alone is not a decision: `read_decision_note`
/// must return `None` even when the plan's notes ref exists with
/// a submission attached. Exercises the "ref present, no
/// annotation at the decision seed's target" branch — the
/// load-bearing read-side property the two-seeds-per-plan design
/// exists to provide.
#[test]
fn read_decision_note_returns_none_when_only_submission_is_present() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    let plan_ref = plan_notes_ref(plan_id);

    // Plant a submission-shaped note directly via `write_note`
    // — the body shape doesn't matter; we only care that the
    // submission's presence under the same ref doesn't fool the
    // decision reader into returning `Some(corrupt)`.
    let submission_seed = plan_submission_seed_blob_bytes(plan_id);
    bailiff
        .write_note(&plan_ref, &submission_seed, b"submission-body")
        .unwrap();

    let result = read_decision_note(&bailiff, plan_id).unwrap();
    assert!(
        result.is_none(),
        "expected None with only submission present, got: {result:?}",
    );
}

/// Distinct plans don't cross-read: reading plan A's decision
/// must not return plan B's. A regression that dropped `plan_id`
/// from the ref derivation would silently make every plan share
/// one decision; this test catches that by writing different
/// outcomes to two plans and verifying each reader gets its own.
#[test]
fn read_decision_note_does_not_cross_read_between_plans() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let p1 = PlanId::new();
    let p2 = PlanId::new();
    write_decision_note(&bailiff, &sample_decision_note(p1, Decision::Accepted)).unwrap();
    write_decision_note(&bailiff, &sample_decision_note(p2, Decision::Rejected)).unwrap();

    let r1 = read_decision_note(&bailiff, p1).unwrap().unwrap();
    let r2 = read_decision_note(&bailiff, p2).unwrap().unwrap();
    assert_eq!(r1.plan_id, p1);
    assert_eq!(r1.outcome, Decision::Accepted);
    assert_eq!(r2.plan_id, p2);
    assert_eq!(r2.outcome, Decision::Rejected);
}

/// A semantically-corrupt body — one that parses cleanly as a
/// `DecisionNote` but whose embedded `plan_id` belongs to a
/// different plan — surfaces as `ReadDecisionError::PlanIdMismatch`
/// rather than `Ok(Some(other_plans_decision))`. A future
/// acceptance gate must never be fooled into ruling on plan A by
/// reading plan B's verdict; the threat model has manual repo
/// repair or a buggy low-level writer producing this state, and
/// the read path is the right place to catch it because that's
/// where the requested `plan_id` is in scope.
#[test]
fn read_decision_note_returns_plan_id_mismatch_when_body_carries_other_plan_id() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let queried = PlanId::new();
    let other = PlanId::new();
    assert_ne!(queried, other, "PlanId::new must not collide");

    // Plant a well-formed DecisionNote for `other` under `queried`'s
    // decision seed. The only way to reach this state is by
    // bypassing `write_decision_note` (which derives the seed from
    // `decision_note.plan_id`), so go through the low-level
    // `write_note` API directly.
    let queried_ref = plan_notes_ref(queried);
    let queried_seed = plan_decision_seed_blob_bytes(queried);
    let foreign_note = sample_decision_note(other, Decision::Accepted);
    bailiff
        .write_note(&queried_ref, &queried_seed, &foreign_note.canonical_bytes())
        .unwrap();

    let err = read_decision_note(&bailiff, queried).unwrap_err();
    match err {
        ReadDecisionError::PlanIdMismatch { requested, found } => {
            assert_eq!(requested, queried);
            assert_eq!(found, other);
        }
        other_err => panic!("expected PlanIdMismatch, got: {other_err:?}"),
    }
}

/// A corrupt body at the decision seed's target surfaces as
/// `ReadDecisionError::Decode`, not as `Ok(None)` or as a
/// generic `ReadNote` error. Construct the case by planting
/// non-JSON bytes directly via `NotesRepo::write_note` at the
/// decision seed — bypassing `write_decision_note` is the only
/// way to produce this state in practice (the writer always
/// produces canonical bytes), but the read-side must still
/// classify it correctly.
#[test]
fn read_decision_note_returns_decode_error_on_corrupt_body() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    let plan_ref = plan_notes_ref(plan_id);
    let decision_seed = plan_decision_seed_blob_bytes(plan_id);
    bailiff
        .write_note(&plan_ref, &decision_seed, b"not json at all")
        .unwrap();

    let err = read_decision_note(&bailiff, plan_id).unwrap_err();
    assert!(
        matches!(err, ReadDecisionError::Decode(_)),
        "expected Decode error, got: {err:?}",
    );
}
