//! Tests for [`write_decision_note`] — the slice D1.3 idempotent
//! write helper. Each test drives the helper directly against a
//! tempdir-backed bare repo (no broker, no writ side).
use super::test_support::*;
use super::*;
use crate::bailiff_decision::{Decider, Decision};
use crate::bailiff_plan_note::{
    DecisionNote, PlanId, plan_decision_seed_blob_bytes, plan_notes_ref,
};
use tempfile::TempDir;
use writ::core::UnixMillis;

fn sample_decider() -> Decider {
    Decider::try_new("cli:alice").unwrap()
}

fn sample_decision_note(plan_id: PlanId, outcome: Decision) -> DecisionNote {
    DecisionNote {
        plan_id,
        outcome,
        decider: sample_decider(),
        decided_at: UnixMillis::from_millis(1_700_000_000_456),
    }
}

/// A note write leaves bailiff's repo compacted-if-needed, not merely written.
///
/// Writ suppresses git's background auto-maintenance in every repo it owns, so
/// nothing else will ever pack this one; before this, nothing called
/// `compact_if_needed` for bailiff at all. What is asserted is the *wiring* —
/// that the repo was measured — rather than a repack, because a fixture repo
/// holds a handful of objects and git's own `gc.auto` threshold is 6700, so the
/// honest outcome here is `Skipped`.
///
/// The count must be non-zero: a `Skipped { loose_objects: 0 }` would be what a
/// measurement of the *wrong repo* looks like, and would pass a bare
/// `matches!(.., Skipped { .. })`.
#[test]
fn writing_a_decision_note_compacts_the_repo_if_needed() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let note = sample_decision_note(PlanId::new(), Decision::Accepted);

    let written = write_decision_note(&bailiff, &note).expect("the decision must be recorded");

    match written
        .compaction
        .expect("compaction must have been attempted")
    {
        CompactionOutcome::Skipped { loose_objects } => assert!(
            loose_objects.get() > 0,
            "the note write leaves loose objects behind, so a zero count means \
             the measurement did not see this repo"
        ),
        other => panic!("a fixture repo is far under git's threshold, got {other:?}"),
    }
}

/// Happy path: first decision for a plan writes a note whose body
/// decodes back to the same `DecisionNote` the caller submitted,
/// attached at the deterministic decision-seed OID.
#[test]
fn write_decision_note_writes_then_reads_back() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    let note = sample_decision_note(plan_id, Decision::Accepted);

    let returned_oid = write_decision_note(&bailiff, &note)
        .expect("first decision must succeed")
        .target_oid;

    // The returned OID must be the deterministic decision-seed
    // OID for this plan id — readers recompute it from the plan
    // id alone, so any drift between writer and reader here is
    // a silent break of the read path.
    let body = bailiff
        .read_note(&plan_notes_ref(plan_id), &returned_oid)
        .expect("decision body must be readable at the returned OID");
    let parsed =
        DecisionNote::from_canonical_bytes(&body).expect("body must decode as DecisionNote");
    assert_eq!(parsed, note);

    // Sanity: the seed bytes are non-empty and have the expected
    // `<plan_id>::decision` shape (already pinned in
    // `bailiff_plan_note` tests, but pinning here too means a
    // future writer-side change can't silently diverge).
    let seed = plan_decision_seed_blob_bytes(plan_id);
    assert_eq!(
        std::str::from_utf8(&seed).unwrap(),
        format!("{plan_id}::decision"),
    );
}

/// Idempotent-by-error: a second decide call for the same plan
/// returns `DecisionAlreadyRecorded` rather than overwriting. The
/// second call's note carries different content (Rejected vs
/// Accepted, different decider) so any silent overwrite would
/// surface as a body mismatch on the read-back.
#[test]
fn write_decision_note_returns_already_recorded_on_second_call() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    let first = sample_decision_note(plan_id, Decision::Accepted);
    let returned_oid = write_decision_note(&bailiff, &first).unwrap().target_oid;

    let mut second = sample_decision_note(plan_id, Decision::Rejected);
    second.decider = Decider::try_new("cli:bob").unwrap();
    let err = write_decision_note(&bailiff, &second).unwrap_err();
    match err {
        WriteDecisionNoteError::DecisionAlreadyRecorded {
            plan_id: pid,
            target_oid,
        } => {
            assert_eq!(pid, plan_id);
            assert_eq!(target_oid, returned_oid);
        }
        other => panic!("expected DecisionAlreadyRecorded, got: {other:?}"),
    }

    // The original Accepted body must still be the one attached.
    let body = bailiff
        .read_note(&plan_notes_ref(plan_id), &returned_oid)
        .unwrap();
    let parsed = DecisionNote::from_canonical_bytes(&body).unwrap();
    assert_eq!(parsed, first);
}

/// Distinct plan ids each get their own decision note under the
/// same notes-ref *prefix* but at different per-plan refs. A
/// regression that drops the plan id from the ref derivation would
/// silently collapse both into one ref.
#[test]
fn write_decision_note_supports_distinct_plans_independently() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let p1 = PlanId::new();
    let p2 = PlanId::new();
    let note1 = sample_decision_note(p1, Decision::Accepted);
    let note2 = sample_decision_note(p2, Decision::Rejected);

    let oid1 = write_decision_note(&bailiff, &note1).unwrap().target_oid;
    let oid2 = write_decision_note(&bailiff, &note2).unwrap().target_oid;
    assert_ne!(oid1, oid2, "distinct plans must seed distinct targets");

    let body1 = bailiff.read_note(&plan_notes_ref(p1), &oid1).unwrap();
    let body2 = bailiff.read_note(&plan_notes_ref(p2), &oid2).unwrap();
    let parsed1 = DecisionNote::from_canonical_bytes(&body1).unwrap();
    let parsed2 = DecisionNote::from_canonical_bytes(&body2).unwrap();
    assert_eq!(parsed1, note1);
    assert_eq!(parsed2, note2);
}

/// Load-bearing coexistence pin: a submission note and a decision
/// note for the same plan live under the same per-plan ref at
/// distinct seed OIDs. The decision write must not collide with a
/// pre-existing submission, and the submission must remain
/// readable after the decision is attached. This is the property
/// the two-seeds-per-plan design exists to provide.
#[test]
fn write_decision_note_coexists_with_existing_submission_under_same_ref() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    let plan_ref = plan_notes_ref(plan_id);

    // Plant a submission-shaped note directly via `write_note` so
    // we don't need to drive the full slice-C broker round-trip
    // for a coexistence pin. The exact body shape doesn't matter
    // here; we only care that the decision write doesn't trip
    // over an existing note under the same ref.
    let submission_seed = crate::bailiff_plan_note::plan_submission_seed_blob_bytes(plan_id);
    let submission_target = bailiff
        .write_note(&plan_ref, &submission_seed, b"submission-body")
        .expect("submission write must succeed");

    let decision = sample_decision_note(plan_id, Decision::Accepted);
    let decision_target = write_decision_note(&bailiff, &decision)
        .expect("decision write must succeed")
        .target_oid;

    assert_ne!(
        submission_target, decision_target,
        "submission and decision must attach at distinct OIDs",
    );
    assert_eq!(
        bailiff.read_note(&plan_ref, &submission_target).unwrap(),
        b"submission-body",
        "submission body must survive the decision write",
    );
    let decision_body = bailiff.read_note(&plan_ref, &decision_target).unwrap();
    assert_eq!(
        DecisionNote::from_canonical_bytes(&decision_body).unwrap(),
        decision,
    );
}

/// Decision can be written even when no submission note exists
/// yet. D1 chose not to gate the decide verb on submission
/// presence — the only invariant the write helper enforces is
/// "one decision per plan." Pin that choice so a future change
/// that adds a precondition has to update this test.
#[test]
fn write_decision_note_does_not_require_pre_existing_submission() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    let note = sample_decision_note(plan_id, Decision::Rejected);

    let oid = write_decision_note(&bailiff, &note)
        .expect("decision write must succeed without a prior submission note")
        .target_oid;
    let body = bailiff.read_note(&plan_notes_ref(plan_id), &oid).unwrap();
    assert_eq!(DecisionNote::from_canonical_bytes(&body).unwrap(), note);
}

/// Every note writer must take the repo-wide mutation lock.
///
/// Asserted by making the lock *unobtainable* — `bailiff-locks` is
/// planted as a regular file, so `create_dir_all` inside
/// `lock_repo_mutations` fails — and requiring the write to surface
/// `RepoLock`. A writer that skipped the lock would sail past and
/// succeed.
///
/// This is deliberately structural rather than a concurrency race: a
/// timing test can pass merely because the other party was slow, which
/// is how two earlier attempts in this PR proved nothing. Here the
/// only way to return `RepoLock` is to have asked for the lock.
///
/// It exists because `write_decision_note` shipped for one round with
/// a `RepoLock` variant it could never produce: the error was added,
/// the call was not, and nothing failed. Note-loss for a run whose
/// agent had already pushed was the exposure.
#[test]
fn write_decision_note_takes_the_repo_mutation_lock() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();

    // Occupy the lock directory's path with a regular file.
    std::fs::write(bailiff.path().join("bailiff-locks"), b"not a directory").unwrap();

    let note = sample_decision_note(plan_id, Decision::Accepted);
    match write_decision_note(&bailiff, &note) {
        Err(WriteDecisionNoteError::RepoLock(_)) => {}
        Ok(written) => panic!(
            "write_decision_note wrote at {oid} without taking the repo mutation lock",
            oid = written.target_oid
        ),
        Err(other) => panic!("expected RepoLock, got: {other:?}"),
    }

    // ... and nothing was written: this would have been the plan's
    // first note, so its ref must not exist.
    let refs = bailiff
        .list_refs_under_prefix(plan_notes_ref(plan_id).as_str())
        .unwrap();
    assert!(
        refs.is_empty(),
        "a locked-out write must not persist: {refs:?}"
    );
}
