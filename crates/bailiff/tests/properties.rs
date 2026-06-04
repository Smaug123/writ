//! Property-based tests for bailiff's plan/decision data model. The
//! invariants mirror the writ-side core round-trip properties: every
//! bailiff value round-trips cleanly through its wire form (JSON or
//! canonical bytes), and the per-plan seed bytes never collide.

use bailiff::bailiff_decision::{Decider, Decision, MAX_DECIDER_BYTES};
use bailiff::bailiff_plan_note::{
    DecisionNote, PlanId as BailiffPlanId, plan_decision_seed_blob_bytes,
    plan_submission_seed_blob_bytes,
};
use proptest::prelude::*;
use writ::core::UnixMillis;

fn arb_bailiff_decision() -> impl Strategy<Value = Decision> {
    prop_oneof![Just(Decision::Accepted), Just(Decision::Rejected)]
}

/// Strategy over `Decider` values that span the whole acceptable
/// input space: any printable ASCII string of 1..=MAX bytes.
/// Printable ASCII suffices to cover the invariants (non-empty,
/// bounded length, no embedded NUL); UTF-8 multi-byte characters
/// would only stress the byte-length bound, which the deterministic
/// unit test for `TooLong` already pins.
fn arb_decider() -> impl Strategy<Value = Decider> {
    let max_bytes = MAX_DECIDER_BYTES;
    (1usize..=max_bytes)
        .prop_flat_map(move |len| {
            proptest::collection::vec(0x20u8..=0x7eu8, len)
                .prop_map(|bytes| String::from_utf8(bytes).expect("ASCII bytes are valid UTF-8"))
        })
        .prop_map(|s| Decider::try_new(s).expect("strategy produces only valid Decider strings"))
}

fn arb_bailiff_plan_id() -> impl Strategy<Value = BailiffPlanId> {
    any::<u128>().prop_map(|n| BailiffPlanId::from_uuid(uuid::Uuid::from_u128(n)))
}

fn arb_unix_millis() -> impl Strategy<Value = UnixMillis> {
    any::<i64>().prop_map(UnixMillis::from_millis)
}

fn arb_decision_note() -> impl Strategy<Value = DecisionNote> {
    (
        arb_bailiff_plan_id(),
        arb_bailiff_decision(),
        arb_decider(),
        arb_unix_millis(),
    )
        .prop_map(|(plan_id, outcome, decider, decided_at)| DecisionNote {
            plan_id,
            outcome,
            decider,
            decided_at,
        })
}

proptest! {
    /// Bailiff-side `Decision` enum: every variant's text projections
    /// agree. The same shape as `decision_outcome_all_text_projections_agree`
    /// but pinned against the renamed, two-variant enum that bailiff
    /// owns.
    #[test]
    fn bailiff_decision_all_text_projections_agree(d in arb_bailiff_decision()) {
        prop_assert_eq!(d.as_str().parse::<Decision>().unwrap(), d);
        prop_assert_eq!(d.to_string(), d.as_str());
        let j = serde_json::to_string(&d).unwrap();
        prop_assert_eq!(&j, &format!("\"{}\"", d.as_str()));
        let back: Decision = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, d);
    }

    /// Any valid `Decider` round-trips through JSON and its on-wire
    /// form is its bare string content (no escaping for the
    /// printable-ASCII subset the strategy explores, which is what
    /// real `cli:<user>` / `agent:<uuid>` strings live in).
    #[test]
    fn bailiff_decider_roundtrips_through_json(d in arb_decider()) {
        let j = serde_json::to_string(&d).unwrap();
        let back: Decider = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, d);
    }

    /// `Decider::try_new(d.as_str())` is idempotent: parsing the
    /// already-validated string yields an equal value. Together with
    /// the JSON round-trip property this proves the type's identity
    /// is its byte content, not anything stored alongside it.
    #[test]
    fn bailiff_decider_try_new_is_idempotent_on_valid_input(d in arb_decider()) {
        let again = Decider::try_new(d.as_str()).unwrap();
        prop_assert_eq!(again, d);
    }

    /// `DecisionNote` round-trips through its canonical-bytes wire
    /// form. The body of the git note bailiff writes is
    /// `note.canonical_bytes()`; a reader hashing the seed OID and
    /// reading the body must recover the same struct. This covers
    /// the same invariant the unit-test sample-instance pins, but
    /// across the full space of valid field values.
    #[test]
    fn bailiff_decision_note_roundtrips_through_canonical_bytes(note in arb_decision_note()) {
        let bytes = note.canonical_bytes();
        let back = DecisionNote::from_canonical_bytes(&bytes).unwrap();
        prop_assert_eq!(back, note);
    }

    /// Submission and decision seed bytes never collide for the same
    /// plan id, for any plan id we can construct. Unit test pins one
    /// case; this confirms the invariant across the full PlanId
    /// space, so a future suffix change can't accidentally make the
    /// two seeds equal for some specific UUID shape.
    #[test]
    fn bailiff_submission_and_decision_seeds_differ_for_every_plan_id(
        plan_id in arb_bailiff_plan_id(),
    ) {
        let submission = plan_submission_seed_blob_bytes(plan_id);
        let decision = plan_decision_seed_blob_bytes(plan_id);
        prop_assert_ne!(submission, decision);
    }
}
