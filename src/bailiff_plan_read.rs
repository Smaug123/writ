//! Bailiff-side read helpers for per-plan notes. Sibling to
//! [`crate::bailiff_plan_write`]: where the write helpers attach the
//! bailiff-owned notes a plan accumulates, the read helpers project
//! them back into typed Rust values.
//!
//! Slice D1.4 of `docs/plans/2026-05-16-slice-d1-decide.md`. D1.3
//! pinned the write side ([`crate::bailiff_plan_write::write_decision_note`]);
//! this module pins the read side at the same seed-OID convention so
//! D2 (review) and slice E (implementer) can both consult a plan's
//! decision without re-deriving the storage layout.
//!
//! Today this module only exposes [`read_decision_note`]. A
//! corresponding `read_plan_note` arrives whenever a consumer first
//! needs it (slice F's `bailiff plan show` is the likely landing
//! point); D1.4 deliberately defers it because nothing in the
//! upcoming slices reads the submission note programmatically yet.

use thiserror::Error;

use crate::bailiff_plan_note::{
    DecisionNote, DecisionNoteParseError, PlanId, plan_decision_seed_blob_bytes, plan_notes_ref,
};
use crate::notes_repo::{NotesRepo, NotesRepoError};

/// Read the decision note for `plan_id`, if one has been recorded.
/// Returns `Ok(None)` when no decision exists yet — both the
/// no-such-plan-id case (no notes ref for that plan) and the
/// plan-exists-but-undecided case (ref present, no annotation at the
/// decision seed's target OID) fold into the same `None` because both
/// mean "operator has not yet ruled on this plan."
///
/// Sibling to [`crate::bailiff_plan_write::write_decision_note`]: the
/// writer hashes [`plan_decision_seed_blob_bytes`] to pick the attach
/// OID, the reader hashes the same seed bytes to recover it, and
/// content-addressed storage makes the round-trip work without any
/// separate registry. The submission note ([`crate::bailiff_plan_note::PlanNote`])
/// is **not** consulted: D1 keeps decisions independently readable so
/// a future caller can ask "has this plan been decided?" without
/// gating on the submission being present.
pub fn read_decision_note(
    bailiff_repo: &NotesRepo,
    plan_id: PlanId,
) -> Result<Option<DecisionNote>, ReadDecisionError> {
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_decision_seed_blob_bytes(plan_id);
    let Some(body) = bailiff_repo
        .read_note_at_seed(&plan_ref, &seed)
        .map_err(ReadDecisionError::ReadNote)?
    else {
        return Ok(None);
    };
    let note = DecisionNote::from_canonical_bytes(&body).map_err(ReadDecisionError::Decode)?;
    Ok(Some(note))
}

/// Tagged failure modes of [`read_decision_note`]. The two variants
/// distinguish "reading the bytes failed" from "bytes came back but
/// did not parse as a [`DecisionNote`]" so a caller can react
/// appropriately: the former is a filesystem or git problem
/// (operator-misconfigured repo path), the latter is on-disk
/// corruption or a schema regression.
#[derive(Debug, Error)]
pub enum ReadDecisionError {
    /// Reading the underlying note body from bailiff's repo failed
    /// for any reason other than absence. Absence (no decision yet)
    /// is folded into `Ok(None)` by [`read_decision_note`] and never
    /// surfaces here.
    #[error("reading the decision note from bailiff's repo failed: {0}")]
    ReadNote(#[source] NotesRepoError),
    /// The note body existed but did not parse as a
    /// [`DecisionNote`]. Indicates wire-level corruption — the
    /// canonical JSON shape is fixed and `deny_unknown_fields` plus
    /// the field-type validators make this near-impossible for any
    /// body [`crate::bailiff_plan_write::write_decision_note`] itself
    /// produced.
    #[error("decoding the decision note body failed: {0}")]
    Decode(#[source] DecisionNoteParseError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bailiff_decision::{Decider, Decision};
    use crate::bailiff_plan_note::{
        DecisionNote, PlanId, plan_decision_seed_blob_bytes, plan_notes_ref,
        plan_submission_seed_blob_bytes,
    };
    use crate::bailiff_plan_write::write_decision_note;
    use crate::core::UnixMillis;
    use tempfile::TempDir;

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

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
}
