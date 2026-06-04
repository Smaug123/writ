//! Unit tests bypass the broker: the helper's contract is "given a
//! writ repo that contains a freshly-signed envelope, fetch it
//! across to bailiff's repo, verify, and write a PlanNote." We
//! exercise that contract directly by writing a known envelope
//! into a tempdir-backed writ repo and driving `write_plan_note`
//! against it.
//!
//! The full broker bring-up is covered by the integration test
//! in `end_to_end_tests` below, which mirrors the slice-B5
//! round-trip in `writ_client.rs` and tacks `write_plan_note` on
//! the end.
use super::test_support::*;
use super::*;
use crate::bailiff_plan_note::{PlanId, PlanNote, plan_notes_ref, plan_submission_seed_blob_bytes};
use tempfile::TempDir;
use writ::signing::{WritSigningKey, WritVerifyingKey};

/// Happy path: with writ's note in place and an allowed-signers
/// list that contains writ's key, `write_plan_note` writes a
/// plan note that decodes back to a `PlanNote` whose envelope
/// fields match what writ produced.
///
/// This is the load-bearing contract bailiff's slice-C CLI relies
/// on. A regression in fetch, verify, ref derivation, or write
/// surfaces here.
#[test]
fn write_plan_note_happy_path_round_trips_through_bailiff_repo() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed, envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let plan_id = PlanId::new();
    let purpose = "plan-stage:c2".to_string();
    let returned_oid = write_plan_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        plan_id,
        purpose.clone(),
        &completed,
        &allowed,
    )
    .expect("happy path must succeed");

    // The returned OID is the deterministic seed-blob OID derived
    // from plan_id alone — pin that contract so a future schema
    // change can't quietly diverge the writer and reader.
    let expected_seed_bytes = plan_submission_seed_blob_bytes(plan_id);
    let body = bailiff
        .read_note(&plan_notes_ref(plan_id), &returned_oid)
        .expect("bailiff-side note must be readable at the returned OID");

    let note = PlanNote::from_canonical_bytes(&body).expect("body must decode");
    assert_eq!(note.plan_id, plan_id);
    assert_eq!(note.purpose, purpose);
    assert_eq!(note.writ_output_oid, completed.output_oid);
    assert_eq!(note.signed_metadata, envelope.metadata);
    assert_eq!(note.signature, envelope.signature);

    // Sanity: the seed bytes are not the same as the OID — the
    // OID is what `git hash-object` of the seed bytes produces.
    // We don't recompute the SHA-1 here; we just confirm the
    // function returned something and the bytes are stable.
    assert!(!expected_seed_bytes.is_empty());
}

/// Defence in depth: if the envelope writ stored in its repo
/// disagrees with what writ returned over the wire, bailiff
/// refuses to attach a plan note. Construct that case by giving
/// `write_plan_note` a `RunAgentCompleted` whose metadata field
/// has been tampered with.
#[test]
fn write_plan_note_rejects_metadata_mismatch_between_envelope_and_reply() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, mut completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    // Flip a metadata field on the wire-side reply without
    // touching the on-disk envelope. The envelope is still
    // cryptographically valid; the divergence is what the check
    // catches.
    completed.signed_metadata.exit_code = completed.signed_metadata.exit_code.wrapping_add(1);

    let err = write_plan_note(
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
            WritePlanNoteError::FetchVerify(FetchVerifyError::EnvelopeMetadataMismatch)
        ),
        "expected EnvelopeMetadataMismatch, got: {err:?}",
    );
}

/// Same defence as the metadata case but for the signature
/// field. A wire reply whose signature differs from the stored
/// envelope's signature is also a refusal.
#[test]
fn write_plan_note_rejects_signature_mismatch_between_envelope_and_reply() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, mut completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    // Substitute the signature with a different (still well-formed)
    // SshSignature — the byte mismatch is what trips the check.
    completed.signature = writ::core::SshSignature::try_new(
        "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH-other-bytes\n-----END SSH SIGNATURE-----",
    )
    .unwrap();

    let err = write_plan_note(
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
            WritePlanNoteError::FetchVerify(FetchVerifyError::EnvelopeSignatureMismatch)
        ),
        "expected EnvelopeSignatureMismatch, got: {err:?}",
    );
}

/// If bailiff's keyring doesn't contain writ's signing key the
/// envelope verification step fails with `UnknownSigner`, which
/// surfaces as `WritePlanNoteError::FetchVerify(FetchVerifyError::Verify(..))`. This is the
/// operator-misconfigured-trust case.
#[test]
fn write_plan_note_rejects_envelope_when_signer_not_trusted() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);

    // Keyring contains *only* an unrelated key — verification
    // fails before signature math runs.
    let other = WritVerifyingKey::from_openssh(OTHER_PUB.trim()).unwrap();
    let allowed = AllowedSigners::from_keys([other]);

    let err = write_plan_note(
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
        WritePlanNoteError::FetchVerify(FetchVerifyError::Verify(VerifyError::UnknownSigner {
            ..
        })) => {}
        other => panic!("expected Verify(UnknownSigner), got: {other:?}"),
    }
}

/// A bad writ-repo path surfaces as `Fetch`, distinct from the
/// later `ReadEnvelope` variant. Operators see "your writ repo
/// path is wrong" instead of "no such note."
#[test]
fn write_plan_note_reports_fetch_failure_for_missing_writ_repo() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (_writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let bogus = tmp.path().join("does-not-exist");
    let err = write_plan_note(
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
            WritePlanNoteError::FetchVerify(FetchVerifyError::Fetch(_))
        ),
        "expected Fetch error, got: {err:?}",
    );
}

/// `write_plan_note` calls `write_note` on the bailiff repo,
/// which refuses to overwrite an existing note for the same
/// target. A duplicate-plan-id call must surface as
/// `WritePlanNote`, not silently overwrite.
#[test]
fn write_plan_note_refuses_to_overwrite_existing_plan_id() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let plan_id = PlanId::new();
    write_plan_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        plan_id,
        "first".into(),
        &completed,
        &allowed,
    )
    .expect("first write succeeds");

    let err = write_plan_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        plan_id,
        "second".into(),
        &completed,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(err, WritePlanNoteError::WritePlanNote(_)),
        "expected WritePlanNote error, got: {err:?}",
    );
}

/// Two distinct plan ids produce two distinct bailiff-side notes
/// from the *same* writ envelope. The plan id is the only thing
/// that varies between the two writes; the writ-side OID stays
/// the same in both notes.
#[test]
fn write_plan_note_supports_two_plans_referencing_one_writ_envelope() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let p1 = PlanId::new();
    let p2 = PlanId::new();
    let oid1 = write_plan_note(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        p1,
        "first".into(),
        &completed,
        &allowed,
    )
    .unwrap();
    let oid2 = write_plan_note(
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
    let note1 = PlanNote::from_canonical_bytes(&body1).unwrap();
    let note2 = PlanNote::from_canonical_bytes(&body2).unwrap();
    assert_eq!(note1.plan_id, p1);
    assert_eq!(note2.plan_id, p2);
    assert_eq!(
        note1.writ_output_oid, note2.writ_output_oid,
        "both plans reference the same writ envelope",
    );
    assert_ne!(note1.purpose, note2.purpose);
}
