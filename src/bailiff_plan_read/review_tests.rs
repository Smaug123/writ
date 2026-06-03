//! Tests for [`read_review_note`] — the slice D2.3 read counterpart
//! to [`crate::bailiff_plan_write::write_review_note`]. The
//! load-bearing round-trip test drives the actual writer so a
//! future refactor that drifts the writer's seed-OID derivation
//! from the reader's surfaces here; the remaining tests plant
//! bodies directly via the low-level [`NotesRepo::write_note`] to
//! avoid the broker setup the writer would otherwise require.
use super::test_support::*;
use super::*;
use crate::bailiff_plan_note::{
    PlanId, ReviewNote, plan_notes_ref, plan_review_seed_blob_bytes,
    plan_submission_seed_blob_bytes,
};
use crate::bailiff_plan_write::write_review_note;
use crate::core::{CapabilitySet, RepoRef};
use crate::run_envelope::SignedRunEnvelope;
use crate::run_verify::AllowedSigners;
use crate::signing::WritSigningKey;
use crate::vm_git::GitObjectId;
use crate::writ_client::RunAgentCompleted;
use tempfile::TempDir;

/// Build a freshly-signed envelope under `signing_key`. Mirrors
/// the same-named helper in `bailiff_plan_write::review_tests` so
/// the envelope shape matches what writ produces today.
fn freshly_signed(signing_key: &WritSigningKey) -> SignedRunEnvelope {
    signed_envelope(
        signing_key,
        b"reviewer prose",
        b"reviewer-prompt",
        vec![CapabilitySet::WorkspaceRead {
            repo: RepoRef {
                owner: "smaug123".into(),
                name: "writ".into(),
            },
        }],
    )
}

/// Stand up a writ repo containing one signed envelope and return
/// the `RunAgentCompleted` reply bailiff would have seen, so the
/// round-trip test can drive `write_review_note` end-to-end.
fn writ_repo_with_envelope(
    tmp: &TempDir,
    signing_key: &WritSigningKey,
) -> (NotesRepo, RunAgentCompleted) {
    let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let envelope = freshly_signed(signing_key);
    let body = envelope.to_bytes();
    let target = writ_repo
        .write_note(
            &writ_notes_ref(),
            envelope.metadata.run_id.to_string().as_bytes(),
            &body,
        )
        .unwrap();
    let completed = RunAgentCompleted {
        output_oid: target,
        signed_metadata: envelope.metadata,
        signature: envelope.signature,
    };
    (writ_repo, completed)
}

/// Plant a ready-made [`ReviewNote`] directly at its review seed
/// via the low-level [`NotesRepo::write_note`] API. Used by tests
/// that don't need to exercise the full fetch-verify-attach path
/// of [`write_review_note`] — e.g. cross-plan reads, decode
/// failures.
fn plant_review_note(bailiff: &NotesRepo, plan_id: PlanId, note: &ReviewNote) -> GitObjectId {
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_review_seed_blob_bytes(plan_id);
    bailiff
        .write_note(&plan_ref, &seed, &note.canonical_bytes())
        .unwrap()
}

fn sample_review_note(plan_id: PlanId) -> ReviewNote {
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let envelope = freshly_signed(&signing_key);
    ReviewNote {
        plan_id,
        purpose: "plan-review".into(),
        writ_output_oid: GitObjectId::new("c".repeat(40)).unwrap(),
        signed_metadata: envelope.metadata,
        signature: envelope.signature,
    }
}

/// A plan with no review note attached returns `Ok(None)`. Covers
/// the fresh-repo case where the plan's notes ref does not exist
/// at all — the most common state during normal operation (writ
/// has not produced a reviewer envelope yet).
#[test]
fn read_review_note_returns_none_when_no_review_recorded() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    let result = read_review_note(&bailiff, plan_id).unwrap();
    assert!(
        result.is_none(),
        "expected None for an unreviewed plan, got: {result:?}",
    );
}

/// Load-bearing round-trip: driving the real
/// [`write_review_note`] then reading back via
/// [`read_review_note`] recovers a byte-for-byte equal
/// [`ReviewNote`]. Pins that the writer's seed-OID derivation
/// matches the reader's — a divergence here would make every
/// review unrecoverable.
#[test]
fn read_review_note_round_trips_through_write_review_note() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
    let plan_id = PlanId::new();
    let purpose = "plan-review".to_string();
    write_review_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        plan_id,
        purpose.clone(),
        &completed,
        &allowed,
    )
    .expect("write_review_note must succeed");

    let read_back = read_review_note(&bailiff, plan_id)
        .expect("read_review_note must succeed")
        .expect("read_review_note must return Some after a successful write");
    assert_eq!(read_back.plan_id, plan_id);
    assert_eq!(read_back.purpose, purpose);
    assert_eq!(read_back.writ_output_oid, completed.output_oid);
    assert_eq!(read_back.signed_metadata, completed.signed_metadata);
    assert_eq!(read_back.signature, completed.signature);
}

/// A submission note alone is not a review: `read_review_note`
/// must return `None` even when the plan's notes ref exists with
/// a submission attached. Exercises the "ref present, no
/// annotation at the review seed's target" branch — the
/// load-bearing read-side property the three-seeds-per-plan
/// design exists to provide.
#[test]
fn read_review_note_returns_none_when_only_submission_is_present() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    let plan_ref = plan_notes_ref(plan_id);

    let submission_seed = plan_submission_seed_blob_bytes(plan_id);
    bailiff
        .write_note(&plan_ref, &submission_seed, b"submission-body")
        .unwrap();

    let result = read_review_note(&bailiff, plan_id).unwrap();
    assert!(
        result.is_none(),
        "expected None with only submission present, got: {result:?}",
    );
}

/// A decision note alone is not a review either. Same coexistence
/// property as the submission case but for the third seed pair.
/// Without this, a future suffix collision between `::decision`
/// and `::review` would silently make every decision read as a
/// review.
#[test]
fn read_review_note_returns_none_when_only_decision_is_present() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    let plan_ref = plan_notes_ref(plan_id);

    let decision_seed = plan_decision_seed_blob_bytes(plan_id);
    bailiff
        .write_note(&plan_ref, &decision_seed, b"decision-body")
        .unwrap();

    let result = read_review_note(&bailiff, plan_id).unwrap();
    assert!(
        result.is_none(),
        "expected None with only decision present, got: {result:?}",
    );
}

/// Distinct plans don't cross-read: reading plan A's review must
/// not return plan B's. A regression that dropped `plan_id` from
/// the ref derivation would silently make every plan share one
/// review; this test catches that by planting different purposes
/// for two plans and verifying each reader gets its own.
#[test]
fn read_review_note_does_not_cross_read_between_plans() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let p1 = PlanId::new();
    let p2 = PlanId::new();
    let mut note1 = sample_review_note(p1);
    note1.purpose = "first".into();
    let mut note2 = sample_review_note(p2);
    note2.purpose = "second".into();
    plant_review_note(&bailiff, p1, &note1);
    plant_review_note(&bailiff, p2, &note2);

    let r1 = read_review_note(&bailiff, p1).unwrap().unwrap();
    let r2 = read_review_note(&bailiff, p2).unwrap().unwrap();
    assert_eq!(r1.plan_id, p1);
    assert_eq!(r1.purpose, "first");
    assert_eq!(r2.plan_id, p2);
    assert_eq!(r2.purpose, "second");
}

/// A semantically-corrupt body — one that parses cleanly as a
/// [`ReviewNote`] but whose embedded `plan_id` belongs to a
/// different plan — surfaces as `ReadReviewError::PlanIdMismatch`
/// rather than `Ok(Some(other_plans_review))`. A future caller
/// rendering reviewer prose must never display plan B's review
/// when asked about plan A; the threat model has manual repo
/// repair or a buggy low-level writer producing this state, and
/// the read path is the right place to catch it because that's
/// where the requested `plan_id` is in scope.
#[test]
fn read_review_note_returns_plan_id_mismatch_when_body_carries_other_plan_id() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let queried = PlanId::new();
    let other = PlanId::new();
    assert_ne!(queried, other, "PlanId::new must not collide");

    // Plant a well-formed ReviewNote for `other` under `queried`'s
    // review seed. The only way to reach this state is by
    // bypassing `write_review_note` (which derives the seed from
    // the `plan_id` it embeds in the note), so go through the
    // low-level `write_note` API.
    let queried_ref = plan_notes_ref(queried);
    let queried_seed = plan_review_seed_blob_bytes(queried);
    let foreign_note = sample_review_note(other);
    bailiff
        .write_note(&queried_ref, &queried_seed, &foreign_note.canonical_bytes())
        .unwrap();

    let err = read_review_note(&bailiff, queried).unwrap_err();
    match err {
        ReadReviewError::PlanIdMismatch { requested, found } => {
            assert_eq!(requested, queried);
            assert_eq!(found, other);
        }
        other_err => panic!("expected PlanIdMismatch, got: {other_err:?}"),
    }
}

/// A corrupt body at the review seed's target surfaces as
/// `ReadReviewError::Decode`, not as `Ok(None)` or as a generic
/// `ReadNote` error. Construct the case by planting non-JSON
/// bytes directly via `NotesRepo::write_note` at the review
/// seed — bypassing `write_review_note` is the only way to
/// produce this state in practice (the writer always produces
/// canonical bytes), but the read-side must still classify it
/// correctly.
#[test]
fn read_review_note_returns_decode_error_on_corrupt_body() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    let plan_ref = plan_notes_ref(plan_id);
    let review_seed = plan_review_seed_blob_bytes(plan_id);
    bailiff
        .write_note(&plan_ref, &review_seed, b"not json at all")
        .unwrap();

    let err = read_review_note(&bailiff, plan_id).unwrap_err();
    assert!(
        matches!(err, ReadReviewError::Decode(_)),
        "expected Decode error, got: {err:?}",
    );
}
