//! Tests for [`write_review_note`] — the slice D2.2 fetch-verify-
//! attach helper. Same harness shape as `tests` (a tempdir-backed
//! writ repo holding one signed envelope, a sibling bailiff repo,
//! and an `AllowedSigners` keyring); the round-trip is exercised
//! directly without standing up the broker. The full broker
//! handshake is covered by `end_to_end_tests` below.
use super::test_support::*;
use super::*;
use crate::bailiff_plan_note::{PlanId, ReviewNote, plan_notes_ref, plan_review_seed_blob_bytes};
use tempfile::TempDir;
use writ::signing::{WritSigningKey, WritVerifyingKey};

/// Happy path: with writ's envelope in place and an allowed-signers
/// list that contains writ's key, `write_review_note` attaches a
/// review note that decodes back to a `ReviewNote` whose envelope
/// fields match what writ produced. Load-bearing contract D2.4's
/// `submit_review` relies on.
#[test]
fn write_review_note_happy_path_round_trips_through_bailiff_repo() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed, envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let plan_id = PlanId::new();
    let purpose = "plan-review".to_string();
    let returned_oid = write_review_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        plan_id,
        purpose.clone(),
        &completed,
        &allowed,
    )
    .expect("happy path must succeed");

    let body = bailiff
        .read_note(&plan_notes_ref(plan_id), &returned_oid)
        .expect("bailiff-side review note must be readable at the returned OID");
    let note = ReviewNote::from_canonical_bytes(&body).expect("body must decode");
    assert_eq!(note.plan_id, plan_id);
    assert_eq!(note.purpose, purpose);
    assert_eq!(note.writ_output_oid, completed.output_oid);
    assert_eq!(note.signed_metadata, envelope.metadata);
    assert_eq!(note.signature, envelope.signature);

    // The seed bytes are the load-bearing input to `git hash-object`;
    // pin them here so a future writer-side change can't silently
    // diverge the seed from the slice-D2 plan doc.
    let seed = plan_review_seed_blob_bytes(plan_id);
    assert_eq!(
        std::str::from_utf8(&seed).unwrap(),
        format!("{plan_id}::review"),
    );
}

/// Idempotent-by-error: a second review for the same plan returns
/// `ReviewAlreadyRecorded` rather than overwriting. The second call
/// carries a different `purpose` so any silent overwrite would
/// surface as a body mismatch on the read-back.
#[test]
fn write_review_note_returns_already_recorded_on_second_call() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let plan_id = PlanId::new();
    let first_oid = write_review_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        plan_id,
        "first".into(),
        &completed,
        &allowed,
    )
    .expect("first review must succeed");

    let err = write_review_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        plan_id,
        "second".into(),
        &completed,
        &allowed,
    )
    .unwrap_err();
    match err {
        WriteReviewNoteError::ReviewAlreadyRecorded {
            plan_id: pid,
            target_oid,
        } => {
            assert_eq!(pid, plan_id);
            assert_eq!(target_oid, first_oid);
        }
        other => panic!("expected ReviewAlreadyRecorded, got: {other:?}"),
    }

    // First body must survive.
    let body = bailiff
        .read_note(&plan_notes_ref(plan_id), &first_oid)
        .unwrap();
    let note = ReviewNote::from_canonical_bytes(&body).unwrap();
    assert_eq!(note.purpose, "first");
}

/// Coexistence pin: a submission note and a review note for the
/// same plan live under the same per-plan ref at distinct seed
/// OIDs. The review write must not collide with a pre-existing
/// submission, and the submission must remain readable after the
/// review is attached. Property the three-seeds-per-plan design
/// exists to provide.
#[test]
fn write_review_note_coexists_with_existing_submission_under_same_ref() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let plan_id = PlanId::new();
    let plan_ref = plan_notes_ref(plan_id);

    // Plant a submission-shaped note directly via `write_note` so
    // we don't drag the full slice-C broker round-trip in here.
    let submission_seed = crate::bailiff_plan_note::plan_submission_seed_blob_bytes(plan_id);
    let submission_target = bailiff
        .write_note(&plan_ref, &submission_seed, b"submission-body")
        .expect("submission write must succeed");

    let review_target = write_review_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        plan_id,
        "plan-review".into(),
        &completed,
        &allowed,
    )
    .expect("review write must succeed alongside a submission");

    assert_ne!(
        submission_target, review_target,
        "submission and review must attach at distinct OIDs",
    );
    assert_eq!(
        bailiff.read_note(&plan_ref, &submission_target).unwrap(),
        b"submission-body",
        "submission body must survive the review write",
    );
    let review_body = bailiff.read_note(&plan_ref, &review_target).unwrap();
    assert_eq!(
        ReviewNote::from_canonical_bytes(&review_body)
            .unwrap()
            .plan_id,
        plan_id,
    );
}

/// Coexistence pin: a decision note and a review note for the same
/// plan live under the same per-plan ref at distinct seed OIDs.
/// Mirrors the submission-coexistence test for the third pairwise
/// combination; without this, a future suffix collision between
/// `::decision` and `::review` would only surface in slice F's
/// read paths.
#[test]
fn write_review_note_coexists_with_existing_decision_under_same_ref() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let plan_id = PlanId::new();
    let plan_ref = plan_notes_ref(plan_id);

    // Plant a decision-shaped note directly via `write_note`.
    let decision_seed = crate::bailiff_plan_note::plan_decision_seed_blob_bytes(plan_id);
    let decision_target = bailiff
        .write_note(&plan_ref, &decision_seed, b"decision-body")
        .expect("decision write must succeed");

    let review_target = write_review_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        plan_id,
        "plan-review".into(),
        &completed,
        &allowed,
    )
    .expect("review write must succeed alongside a decision");

    assert_ne!(
        decision_target, review_target,
        "decision and review must attach at distinct OIDs",
    );
    assert_eq!(
        bailiff.read_note(&plan_ref, &decision_target).unwrap(),
        b"decision-body",
        "decision body must survive the review write",
    );
}

/// Two distinct plan ids produce two distinct bailiff-side reviews
/// from the *same* writ envelope. The plan id is the only thing
/// that varies between the two writes; the writ-side OID stays the
/// same in both notes.
#[test]
fn write_review_note_supports_distinct_plans_independently() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let p1 = PlanId::new();
    let p2 = PlanId::new();
    let oid1 = write_review_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        p1,
        "first".into(),
        &completed,
        &allowed,
    )
    .unwrap();
    let oid2 = write_review_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        p2,
        "second".into(),
        &completed,
        &allowed,
    )
    .unwrap();
    assert_ne!(oid1, oid2, "distinct plan ids must seed distinct OIDs");

    let body1 = bailiff.read_note(&plan_notes_ref(p1), &oid1).unwrap();
    let body2 = bailiff.read_note(&plan_notes_ref(p2), &oid2).unwrap();
    let note1 = ReviewNote::from_canonical_bytes(&body1).unwrap();
    let note2 = ReviewNote::from_canonical_bytes(&body2).unwrap();
    assert_eq!(note1.plan_id, p1);
    assert_eq!(note2.plan_id, p2);
    assert_eq!(
        note1.writ_output_oid, note2.writ_output_oid,
        "both reviews reference the same writ envelope",
    );
    assert_ne!(note1.purpose, note2.purpose);
}

/// Defence in depth: if the envelope writ stored in its repo
/// disagrees with the metadata writ returned over the wire,
/// bailiff refuses to attach the review.
#[test]
fn write_review_note_rejects_metadata_mismatch_between_envelope_and_reply() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, mut completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    completed.signed_metadata.exit_code = completed.signed_metadata.exit_code.wrapping_add(1);

    let err = write_review_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        PlanId::new(),
        "p".into(),
        &completed,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            WriteReviewNoteError::FetchVerify(FetchVerifyError::EnvelopeMetadataMismatch)
        ),
        "expected EnvelopeMetadataMismatch, got: {err:?}",
    );
}

/// Defence in depth: same as the metadata case but for the
/// signature field.
#[test]
fn write_review_note_rejects_signature_mismatch_between_envelope_and_reply() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, mut completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    completed.signature = writ::core::SshSignature::try_new(
        "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH-other-bytes\n-----END SSH SIGNATURE-----",
    )
    .unwrap();

    let err = write_review_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        PlanId::new(),
        "p".into(),
        &completed,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            WriteReviewNoteError::FetchVerify(FetchVerifyError::EnvelopeSignatureMismatch)
        ),
        "expected EnvelopeSignatureMismatch, got: {err:?}",
    );
}

/// If bailiff's keyring doesn't contain writ's signing key, the
/// envelope verification step fails with `UnknownSigner`, which
/// surfaces as `WriteReviewNoteError::FetchVerify(FetchVerifyError::Verify(..))`. Operator-
/// misconfigured-trust case.
#[test]
fn write_review_note_rejects_envelope_when_signer_not_trusted() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);

    let other = WritVerifyingKey::from_openssh(OTHER_PUB.trim()).unwrap();
    let allowed = AllowedSigners::from_keys([other]);

    let err = write_review_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        PlanId::new(),
        "p".into(),
        &completed,
        &allowed,
    )
    .unwrap_err();
    match err {
        WriteReviewNoteError::FetchVerify(FetchVerifyError::Verify(
            VerifyError::UnknownSigner { .. },
        )) => {}
        other => panic!("expected Verify(UnknownSigner), got: {other:?}"),
    }
}

/// A bad writ-repo path surfaces as `Fetch`, distinct from the
/// later `ReadEnvelope` variant. Operators see "your writ repo
/// path is wrong" instead of "no such note."
#[test]
fn write_review_note_reports_fetch_failure_for_missing_writ_repo() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (_writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let bogus = tmp.path().join("does-not-exist");
    let err = write_review_note(
        &bailiff,
        &bogus,
        &writ_notes_ref(),
        PlanId::new(),
        "p".into(),
        &completed,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            WriteReviewNoteError::FetchVerify(FetchVerifyError::Fetch(_))
        ),
        "expected Fetch error, got: {err:?}",
    );
}

/// Review can be written even when no submission note exists yet.
/// D2 chose not to gate the write helper on submission presence
/// (mirrors D1.3's decoupling); the submission-presence gate lives
/// in slice D2.4's `submit_review` workflow, where the body is
/// consumed for prompt composition. Pin that choice so a future
/// change that adds a precondition has to update this test.
#[test]
fn write_review_note_does_not_require_pre_existing_submission() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let plan_id = PlanId::new();
    let returned_oid = write_review_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        plan_id,
        "plan-review".into(),
        &completed,
        &allowed,
    )
    .expect("review write must succeed without a prior submission note");
    let body = bailiff
        .read_note(&plan_notes_ref(plan_id), &returned_oid)
        .unwrap();
    let note = ReviewNote::from_canonical_bytes(&body).unwrap();
    assert_eq!(note.plan_id, plan_id);
}
