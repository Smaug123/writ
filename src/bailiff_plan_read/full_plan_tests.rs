//! Tests for [`read_writ_envelope_at_oid`] and [`read_full_plan`] —
//! slice F3's read-and-verify composition.
//!
//! Fixtures plant coherent writ runs (envelope + paired bailiff
//! signed note pointing at the envelope's target OID) directly
//! through [`NotesRepo::write_note`]. This bypasses the writ broker
//! and the writ→bailiff fetch hop on purpose — those are the
//! concern of the end-to-end round-trip in
//! `run_verify::tests::round_trip_writ_writes_bailiff_fetches_and_verifies`.
//! Here we exercise the pure read-side composition under the same
//! crypto primitives.
//!
//! The four [`VerifiedSection`] variants are each driven by a
//! distinct fault injection: missing envelope (no writ note at the
//! OID), malformed envelope (non-JSON bytes), output tamper
//! (envelope output bytes don't hash to the metadata's digest), and
//! metadata tamper (canonical bytes diverge from what was signed,
//! plus the signer-not-in-allowed-signers variant).
use super::test_support::*;
use super::*;
use crate::agent_run::{AgentRunId, sha256_hex};
use crate::bailiff_decision::{Decider, Decision};
use crate::bailiff_plan_note::{
    DecisionNote, ImplementNote, PlanId, PlanNote, ReviewNote, plan_decision_seed_blob_bytes,
    plan_implement_seed_blob_bytes, plan_notes_ref, plan_review_seed_blob_bytes,
    plan_submission_seed_blob_bytes,
};
use crate::core::{CapabilitySet, RepoRef, SessionId, Sha256Hex, SshSignature, UnixMillis};
use crate::protocol::SignedRunMetadata;
use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use crate::run_verify::VerifyError;
use crate::signing::WritSigningKey;
use crate::vm_git::GitObjectId;
use tempfile::TempDir;

/// Build a `SignedRunMetadata` whose `output_envelope_sha256` binds
/// to the canonical bytes of an empty [`OutputEnvelope`]. Used by
/// every helper here so a paired envelope plants without any
/// additional bookkeeping; the `seed_str` differentiates prompt
/// digests across plants so the metadatas don't compare equal.
fn build_metadata(
    signing_key: &WritSigningKey,
    completed_at_millis: i64,
    seed_str: &str,
) -> (SignedRunMetadata, Vec<u8>) {
    let output = OutputEnvelope {
        stdout: format!("{seed_str}-stdout").into_bytes(),
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let output_bytes = output.to_bytes();
    let output_sha = Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap();
    let prompt_sha = Sha256Hex::try_new(sha256_hex(seed_str.as_bytes())).unwrap();
    let metadata = SignedRunMetadata {
        run_id: AgentRunId::new(),
        session_id: SessionId::new(),
        prompt_sha256: prompt_sha,
        output_envelope_sha256: output_sha,
        capabilities: vec![CapabilitySet::WorkspaceRead {
            repo: RepoRef {
                owner: "smaug123".into(),
                name: "writ".into(),
            },
        }],
        exit_code: 0,
        completed_at: UnixMillis::from_millis(completed_at_millis),
        signing_key_fingerprint: signing_key.fingerprint(),
    };
    (metadata, output_bytes)
}

/// Bundle of (writ envelope target OID, signed metadata, signature)
/// returned by [`plant_run`]: enough for a paired bailiff signed
/// note to reference and re-sign over the same metadata. Each
/// `plant_run` call seeds a fresh [`AgentRunId`] so multiple runs
/// in one test plant at distinct target OIDs.
struct PlantedRun {
    writ_output_oid: GitObjectId,
    metadata: SignedRunMetadata,
    signature: SshSignature,
}

/// Build a fresh writ envelope under `signing_key`, plant it on
/// bailiff's writ notes ref keyed by the run id, and return the
/// projection a paired bailiff note will reuse. The envelope's
/// output bytes are seeded by `seed_str` so the planted body is
/// distinct across calls within one test.
fn plant_run(
    bailiff: &NotesRepo,
    signing_key: &WritSigningKey,
    completed_at_millis: i64,
    seed_str: &str,
) -> PlantedRun {
    let (metadata, output_bytes) = build_metadata(signing_key, completed_at_millis, seed_str);
    let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
    let envelope = SignedRunEnvelope {
        metadata: metadata.clone(),
        signature: signature.clone(),
        output: output_bytes,
    };
    let writ_output_oid = bailiff
        .write_note(
            &writ_notes_ref(),
            metadata.run_id.to_string().as_bytes(),
            &envelope.to_bytes(),
        )
        .unwrap();
    PlantedRun {
        writ_output_oid,
        metadata,
        signature,
    }
}

fn plant_plan_note_for(bailiff: &NotesRepo, plan_id: PlanId, run: &PlantedRun) {
    let note = PlanNote {
        plan_id,
        purpose: "plan-submission".into(),
        writ_output_oid: run.writ_output_oid.clone(),
        signed_metadata: run.metadata.clone(),
        signature: run.signature.clone(),
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_submission_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();
}

fn plant_review_note_for(bailiff: &NotesRepo, plan_id: PlanId, run: &PlantedRun) {
    let note = ReviewNote {
        plan_id,
        purpose: "plan-review".into(),
        writ_output_oid: run.writ_output_oid.clone(),
        signed_metadata: run.metadata.clone(),
        signature: run.signature.clone(),
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_review_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();
}

fn plant_implement_note_for(bailiff: &NotesRepo, plan_id: PlanId, run: &PlantedRun) {
    let note = ImplementNote {
        plan_id,
        purpose: "plan-implement".into(),
        writ_output_oid: run.writ_output_oid.clone(),
        signed_metadata: run.metadata.clone(),
        signature: run.signature.clone(),
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_implement_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();
}

fn plant_decision_note_for(bailiff: &NotesRepo, plan_id: PlanId, outcome: Decision) {
    let note = DecisionNote {
        plan_id,
        outcome,
        decider: Decider::try_new("cli:alice").unwrap(),
        decided_at: UnixMillis::from_millis(1_700_000_500_000),
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_decision_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();
}

fn allowed_signers_for(signing_key: &WritSigningKey) -> AllowedSigners {
    AllowedSigners::from_keys([signing_key.verifying_key()])
}

/// Absent: bailiff has not fetched a writ envelope at this OID, so
/// the read returns `Ok(None)`. Pins the "not fetched yet" case the
/// `WritEnvelopeMissing` variant rests on.
#[test]
fn read_writ_envelope_at_oid_returns_none_when_absent() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let oid = GitObjectId::new("a".repeat(40)).unwrap();
    let result = read_writ_envelope_at_oid(&bailiff, &oid).unwrap();
    assert!(result.is_none());
}

/// Present: plant a real envelope, read by the returned OID, and
/// the decoded envelope round-trips byte-equal in metadata and
/// signature.
#[test]
fn read_writ_envelope_at_oid_round_trips_planted_envelope() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let run = plant_run(&bailiff, &signing_key, 1, "roundtrip");
    let envelope = read_writ_envelope_at_oid(&bailiff, &run.writ_output_oid)
        .unwrap()
        .expect("envelope was just planted");
    assert_eq!(envelope.metadata, run.metadata);
    assert_eq!(envelope.signature, run.signature);
}

/// Garbage body at a real OID: the read returns `Decode`, not
/// `Ok(None)` and not `Read`. Pins the "envelope present but
/// corrupted on disk" diagnostic.
#[test]
fn read_writ_envelope_at_oid_surfaces_decode_failure_on_garbage_body() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let oid = bailiff
        .write_note(&writ_notes_ref(), b"garbage-seed", b"not-json-at-all")
        .unwrap();
    match read_writ_envelope_at_oid(&bailiff, &oid) {
        Err(ReadWritEnvelopeError::Decode(_)) => {}
        other => panic!("expected Decode error, got {other:?}"),
    }
}

/// Happy path: plant + decision + review + implement, all signed
/// by the same writ key listed in allowed-signers. Every section
/// surfaces as [`VerifiedSection::Verified`] and the decision
/// projects through unchanged.
#[test]
fn read_full_plan_returns_verified_view_when_all_four_sections_present() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let plan_id = PlanId::new();

    let plan_run = plant_run(&bailiff, &signing_key, 1, "plan");
    let review_run = plant_run(&bailiff, &signing_key, 2, "review");
    let implement_run = plant_run(&bailiff, &signing_key, 3, "implement");

    plant_plan_note_for(&bailiff, plan_id, &plan_run);
    plant_decision_note_for(&bailiff, plan_id, Decision::Accepted);
    plant_review_note_for(&bailiff, plan_id, &review_run);
    plant_implement_note_for(&bailiff, plan_id, &implement_run);

    let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
    assert_eq!(view.plan_id, plan_id);
    match view.plan.as_ref().expect("plan section must be present") {
        VerifiedSection::Verified { note, envelope } => {
            assert_eq!(note.plan_id, plan_id);
            assert_eq!(envelope.metadata, plan_run.metadata);
        }
        other => panic!("expected Verified plan section, got {other:?}"),
    }
    assert!(view.decision.is_some(), "decision must be present");
    match view
        .review
        .as_ref()
        .expect("review section must be present")
    {
        VerifiedSection::Verified { note, envelope } => {
            assert_eq!(note.plan_id, plan_id);
            assert_eq!(envelope.metadata, review_run.metadata);
        }
        other => panic!("expected Verified review section, got {other:?}"),
    }
    match view
        .implement
        .as_ref()
        .expect("implement section must be present")
    {
        VerifiedSection::Verified { note, envelope } => {
            assert_eq!(note.plan_id, plan_id);
            assert_eq!(envelope.metadata, implement_run.metadata);
        }
        other => panic!("expected Verified implement section, got {other:?}"),
    }
}

/// Plan-only: just the plan submission is planted. The other three
/// fields surface as `None` (structural absence), not as failure
/// variants — `None` and "failure to verify" are different
/// states.
#[test]
fn read_full_plan_returns_only_plan_section_when_other_notes_missing() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let plan_id = PlanId::new();
    let plan_run = plant_run(&bailiff, &signing_key, 1, "plan-only");
    plant_plan_note_for(&bailiff, plan_id, &plan_run);
    let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
    assert!(matches!(view.plan, Some(VerifiedSection::Verified { .. })));
    assert!(view.decision.is_none());
    assert!(view.review.is_none());
    assert!(view.implement.is_none());
}

/// Corrupt anomaly: downstream notes (decision + review) present
/// but plan submission absent. `view.plan = None` is representable
/// because `plan` is `Option<VerifiedSection<_>>`, and the other
/// available sections still render — exactly the property
/// [`PlanFullView`]'s doc string promises.
#[test]
fn read_full_plan_returns_none_plan_when_only_downstream_notes_present() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let plan_id = PlanId::new();
    plant_decision_note_for(&bailiff, plan_id, Decision::Accepted);
    let review_run = plant_run(&bailiff, &signing_key, 2, "orphan-review");
    plant_review_note_for(&bailiff, plan_id, &review_run);
    let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
    assert!(view.plan.is_none(), "plan missing in corrupt state");
    assert!(view.decision.is_some());
    assert!(matches!(
        view.review,
        Some(VerifiedSection::Verified { .. })
    ));
    assert!(view.implement.is_none());
}

/// Writ envelope missing: a plan note references a synthetic OID
/// where bailiff has no writ note. The section surfaces as
/// [`VerifiedSection::WritEnvelopeMissing`] — the
/// "operator forgot to fetch" recoverable state.
#[test]
fn read_full_plan_marks_section_when_writ_envelope_missing() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let plan_id = PlanId::new();

    let synthetic_oid = GitObjectId::new("d".repeat(40)).unwrap();
    let (metadata, _output_bytes) = build_metadata(&signing_key, 1, "no-envelope");
    let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
    let note = PlanNote {
        plan_id,
        purpose: "plan".into(),
        writ_output_oid: synthetic_oid.clone(),
        signed_metadata: metadata,
        signature,
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_submission_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();

    let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
    match view.plan.as_ref().unwrap() {
        VerifiedSection::WritEnvelopeMissing { note } => {
            assert_eq!(note.writ_output_oid, synthetic_oid);
        }
        other => panic!("expected WritEnvelopeMissing, got {other:?}"),
    }
}

/// Envelope body malformed: plant non-JSON bytes on the writ ref,
/// capture the resulting OID, and point a plan note at it. The
/// section surfaces as [`VerifiedSection::EnvelopeMalformed`] —
/// distinct from missing (so an operator can tell "not fetched"
/// from "fetched but corrupt").
#[test]
fn read_full_plan_marks_section_when_envelope_body_malformed() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let plan_id = PlanId::new();

    let malformed_oid = bailiff
        .write_note(&writ_notes_ref(), b"malformed-seed", b"<<not json>>")
        .unwrap();
    let (metadata, _output_bytes) = build_metadata(&signing_key, 1, "malformed-envelope");
    let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
    let note = PlanNote {
        plan_id,
        purpose: "plan".into(),
        writ_output_oid: malformed_oid.clone(),
        signed_metadata: metadata,
        signature,
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_submission_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();

    let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
    match view.plan.as_ref().unwrap() {
        VerifiedSection::EnvelopeMalformed { note, .. } => {
            assert_eq!(note.writ_output_oid, malformed_oid);
        }
        other => panic!("expected EnvelopeMalformed, got {other:?}"),
    }
}

/// Output digest mismatch: plant an envelope whose `output` bytes
/// don't hash to the metadata's `output_envelope_sha256` claim,
/// then verify under the legitimate signer. The verifier rejects
/// at the digest step before consulting the signature.
#[test]
fn read_full_plan_marks_section_when_output_digest_mismatches() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let plan_id = PlanId::new();

    let (metadata, output_bytes) = build_metadata(&signing_key, 1, "digest-mismatch");
    let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
    // Swap the bound output bytes for an unrelated payload after
    // the metadata digest is fixed — re-hashing on the verifier
    // side will surface the divergence.
    let mut tampered_output = output_bytes.clone();
    tampered_output.push(0xFF);
    let envelope = SignedRunEnvelope {
        metadata: metadata.clone(),
        signature: signature.clone(),
        output: tampered_output,
    };
    let oid = bailiff
        .write_note(
            &writ_notes_ref(),
            metadata.run_id.to_string().as_bytes(),
            &envelope.to_bytes(),
        )
        .unwrap();
    let note = PlanNote {
        plan_id,
        purpose: "plan".into(),
        writ_output_oid: oid,
        signed_metadata: metadata,
        signature,
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_submission_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();

    let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
    match view.plan.as_ref().unwrap() {
        VerifiedSection::SignatureFailure {
            error: VerifyError::OutputDigestMismatch { .. },
            ..
        } => {}
        other => panic!("expected SignatureFailure(OutputDigestMismatch), got {other:?}"),
    }
}

/// Unknown signer: envelope is built and signed by writ key A, but
/// allowed-signers contains only key B. The verifier rejects at
/// the fingerprint-lookup step (before consulting the signature),
/// surfacing as `SignatureFailure(UnknownSigner)`.
#[test]
fn read_full_plan_marks_section_when_signer_not_in_allowed_signers() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let other_key = WritSigningKey::from_openssh_pem(OTHER_PEM).unwrap();
    let primary_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let plan_id = PlanId::new();

    // Envelope and bailiff plan note are both signed by the
    // *other* key; the AllowedSigners passed to read_full_plan
    // contains only the *primary* key.
    let plan_run = plant_run(&bailiff, &other_key, 1, "signed-by-other");
    plant_plan_note_for(&bailiff, plan_id, &plan_run);

    let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&primary_key)).unwrap();
    match view.plan.as_ref().unwrap() {
        VerifiedSection::SignatureFailure {
            error: VerifyError::UnknownSigner { fingerprint },
            ..
        } => {
            assert_eq!(fingerprint, &other_key.fingerprint());
        }
        other => panic!("expected SignatureFailure(UnknownSigner), got {other:?}"),
    }
}

/// Metadata tamper: build and sign an envelope, then mutate one
/// non-digest metadata field (`exit_code`) before encoding. The
/// output digest still binds (we didn't touch the output bytes or
/// `output_envelope_sha256`), the signer is known, but the
/// signature no longer matches `canonical_bytes` — surfaces as
/// `SignatureFailure(SignatureInvalid)`.
#[test]
fn read_full_plan_marks_section_when_metadata_tampered_post_sign() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let plan_id = PlanId::new();

    let (mut metadata, output_bytes) = build_metadata(&signing_key, 1, "metadata-tamper");
    let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
    // Mutate after signing. The output digest still binds because
    // `output_envelope_sha256` is unchanged; only the exit code
    // diverges from what the signature covered.
    metadata.exit_code = metadata.exit_code.wrapping_add(1);
    let envelope = SignedRunEnvelope {
        metadata: metadata.clone(),
        signature: signature.clone(),
        output: output_bytes,
    };
    let oid = bailiff
        .write_note(
            &writ_notes_ref(),
            metadata.run_id.to_string().as_bytes(),
            &envelope.to_bytes(),
        )
        .unwrap();
    let note = PlanNote {
        plan_id,
        purpose: "plan".into(),
        writ_output_oid: oid,
        signed_metadata: metadata,
        signature,
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_submission_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();

    let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
    match view.plan.as_ref().unwrap() {
        VerifiedSection::SignatureFailure {
            error: VerifyError::SignatureInvalid(_),
            ..
        } => {}
        other => panic!("expected SignatureFailure(SignatureInvalid), got {other:?}"),
    }
}

/// Note/envelope binding: plant a legitimate envelope under one
/// signed metadata, then plant a bailiff plan note that points at
/// the same OID but carries a *different* signed metadata (also
/// validly signed in isolation). The envelope verifies, but the
/// note's copied `(signed_metadata, signature)` pair doesn't
/// match the envelope's — so the section must surface as
/// `NoteEnvelopeMismatch`, never as `Verified`.
///
/// This is the attack vector codex P1 surfaced: without the
/// binding check, an operator who edits the bailiff plan note
/// (mutating `purpose`, or replacing `signed_metadata` with the
/// metadata of a different run) could be shown the forged note
/// next to a legitimate envelope's `Verified` status.
#[test]
fn read_full_plan_rejects_note_when_metadata_does_not_match_envelope() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let plan_id = PlanId::new();

    // Envelope: signed run A, planted on bailiff's writ ref.
    let envelope_run = plant_run(&bailiff, &signing_key, 1, "envelope-run");

    // Note: built from a *different* signed run B, but pointing
    // at run A's envelope OID. Both metadatas are independently
    // valid; the binding from note → envelope is what's broken.
    let (note_metadata, _) = build_metadata(&signing_key, 2, "note-run");
    let note_signature = signing_key.sign(&note_metadata.canonical_bytes()).unwrap();
    let note = PlanNote {
        plan_id,
        purpose: "plan".into(),
        writ_output_oid: envelope_run.writ_output_oid.clone(),
        signed_metadata: note_metadata,
        signature: note_signature,
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_submission_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();

    let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
    match view.plan.as_ref().unwrap() {
        VerifiedSection::NoteEnvelopeMismatch { note, envelope } => {
            assert_eq!(note.writ_output_oid, envelope_run.writ_output_oid);
            assert_eq!(envelope.metadata, envelope_run.metadata);
            assert_ne!(note.signed_metadata, envelope.metadata);
        }
        other => panic!("expected NoteEnvelopeMismatch, got {other:?}"),
    }
}

/// Mutating only the bailiff note's `signature` (but leaving its
/// `signed_metadata` byte-for-byte equal to the envelope's) must
/// still trip the binding check. The note claims a different
/// signature than the envelope carries; rendering it as
/// `Verified` would let a stale or attacker-supplied signature
/// ride alongside a legitimate envelope.
#[test]
fn read_full_plan_rejects_note_when_only_signature_diverges() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let plan_id = PlanId::new();

    let envelope_run = plant_run(&bailiff, &signing_key, 1, "binding-signature");
    // Re-sign the same metadata under a different key (the
    // ssh-sig signing process incorporates a random nonce, so
    // even signing under the same key would give different bytes;
    // a different key just makes the divergence more obvious).
    let other_key = WritSigningKey::from_openssh_pem(OTHER_PEM).unwrap();
    let foreign_signature = other_key
        .sign(&envelope_run.metadata.canonical_bytes())
        .unwrap();
    assert_ne!(foreign_signature, envelope_run.signature);
    let note = PlanNote {
        plan_id,
        purpose: "plan".into(),
        writ_output_oid: envelope_run.writ_output_oid.clone(),
        signed_metadata: envelope_run.metadata.clone(),
        signature: foreign_signature,
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_submission_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();

    let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
    assert!(matches!(
        view.plan,
        Some(VerifiedSection::NoteEnvelopeMismatch { .. }),
    ));
}
