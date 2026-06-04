//! Unit tests for [`read_plan_body_bytes`]. Each test plants a
//! known envelope in a writ repo via the same `NotesRepo`
//! primitives the production writer uses, then probes a single
//! failure mode. The helper is the new defence-in-depth surface
//! for "bailiff reads its own signed envelopes back" so every
//! variant of [`ReadPlanBodyError`] gets a pinned test.
use super::test_support::*;
use super::*;
use crate::bailiff_plan_note::PlanId;
use tempfile::TempDir;
use writ::agent_run::{AgentRunId, sha256_hex};
use writ::core::{CapabilitySet, RepoRef, SessionId, Sha256Hex, UnixMillis};
use writ::protocol::SignedRunMetadata;
use writ::signing::WritSigningKey;
use writ::vm_git::GitObjectId;

/// Build an envelope around an arbitrary stdout payload. Used
/// for tests that need to exercise the post-verify decode steps
/// (truncation, UTF-8) — the envelope must sign whatever payload
/// the test plants or `Verify` would fail first.
fn signed_envelope_with_output(
    signing_key: &WritSigningKey,
    output: OutputEnvelope,
) -> SignedRunEnvelope {
    let output_bytes = output.to_bytes();
    let output_sha = Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap();
    let prompt_sha = Sha256Hex::try_new(sha256_hex(b"planner-prompt")).unwrap();
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
        completed_at: UnixMillis::from_millis(1_700_000_000_000),
        signing_key_fingerprint: signing_key.fingerprint(),
    };
    let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
    SignedRunEnvelope {
        metadata,
        signature,
        output: output_bytes,
    }
}

/// Plant a known envelope in a writ repo, return the writ repo +
/// the `PlanNote` bailiff would have recorded if it had run
/// `write_plan_note` against this envelope.
///
/// The `PlanNote` is the second input to `read_plan_body_bytes`;
/// building it here (rather than via the real writer) keeps the
/// test focused on the read-side behaviour and lets the negative
/// tests poke at individual fields.
fn writ_repo_and_plan_note(tmp: &TempDir, envelope: &SignedRunEnvelope) -> (NotesRepo, PlanNote) {
    let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let body = envelope.to_bytes();
    let oid = writ_repo
        .write_note(
            &writ_notes_ref(),
            envelope.metadata.run_id.to_string().as_bytes(),
            &body,
        )
        .unwrap();
    let plan_note = PlanNote {
        plan_id: PlanId::new(),
        purpose: "plan-submission".into(),
        writ_output_oid: oid,
        signed_metadata: envelope.metadata.clone(),
        signature: envelope.signature.clone(),
    };
    (writ_repo, plan_note)
}

/// Happy path: a freshly-signed envelope under a trusted key,
/// stdout containing UTF-8 prose, no truncation. Returns the
/// stdout bytes exactly.
#[test]
fn happy_path_returns_stdout_as_string() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let plan_body = "# Plan\n\nReplace bar with baz.\n";
    let output = OutputEnvelope {
        stdout: plan_body.as_bytes().to_vec(),
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let envelope = signed_envelope_with_output(&signing_key, output);
    let (writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let body = read_plan_body_bytes(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        &plan_note,
        &allowed,
    )
    .expect("happy path must extract the plan body");
    assert_eq!(body, plan_body);
}

/// `Fetch` failure when the writ repo path doesn't point to a
/// usable repo. Construct the case by passing a temp directory
/// that exists but contains no git repo.
#[test]
fn fetch_failure_when_writ_repo_path_is_not_a_repo() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let output = OutputEnvelope {
        stdout: b"body".to_vec(),
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let envelope = signed_envelope_with_output(&signing_key, output);
    let (_writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let bogus_path = tmp.path().join("nonexistent");
    let err = read_plan_body_bytes(
        &bailiff,
        &bogus_path,
        &writ_notes_ref(),
        &plan_note,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(err, ReadPlanBodyError::Fetch(_)),
        "expected Fetch, got: {err:?}",
    );
}

/// `ReadEnvelope` failure when the OID recorded on the plan
/// note isn't present in writ's repo. Build a plan note that
/// references an OID nothing writes to.
#[test]
fn read_envelope_failure_when_oid_is_absent() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let output = OutputEnvelope {
        stdout: b"body".to_vec(),
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let envelope = signed_envelope_with_output(&signing_key, output);
    let (writ_repo, mut plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
    // Replace the legitimate OID with one nothing was written
    // for. The OID is 40 hex chars; pick one no SHA-1 would
    // accidentally produce.
    plan_note.writ_output_oid = GitObjectId::new("e".repeat(40)).unwrap();
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let err = read_plan_body_bytes(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        &plan_note,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(err, ReadPlanBodyError::ReadEnvelope(_)),
        "expected ReadEnvelope, got: {err:?}",
    );
}

/// `DecodeEnvelope` failure when the bytes at the recorded OID
/// aren't a valid `SignedRunEnvelope`. Plant non-JSON bytes
/// directly at the OID and reference them from the plan note.
#[test]
fn decode_envelope_failure_when_body_is_not_envelope_json() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let oid = writ_repo
        .write_note(&writ_notes_ref(), b"corrupt-seed", b"not json at all")
        .unwrap();
    let dummy_envelope = signed_envelope_with_output(
        &signing_key,
        OutputEnvelope {
            stdout: b"x".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        },
    );
    let plan_note = PlanNote {
        plan_id: PlanId::new(),
        purpose: "plan-submission".into(),
        writ_output_oid: oid,
        signed_metadata: dummy_envelope.metadata,
        signature: dummy_envelope.signature,
    };
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let err = read_plan_body_bytes(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        &plan_note,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(err, ReadPlanBodyError::DecodeEnvelope(_)),
        "expected DecodeEnvelope, got: {err:?}",
    );
}

/// `EnvelopeMetadataMismatch` when the recorded plan-note
/// metadata differs from the metadata on disk. Construct a
/// plan note that records *different* metadata than what writ's
/// repo carries — the helper must refuse rather than accept
/// whichever copy is more recent.
#[test]
fn envelope_metadata_mismatch_when_plan_note_records_other_metadata() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let output = OutputEnvelope {
        stdout: b"body".to_vec(),
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let envelope = signed_envelope_with_output(&signing_key, output);
    let (writ_repo, mut plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
    // Tweak the recorded metadata so it differs from what writ
    // signed — bump `exit_code` because it's covered by the
    // signature but doesn't change the digest of any other field.
    plan_note.signed_metadata.exit_code = 99;
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let err = read_plan_body_bytes(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        &plan_note,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(err, ReadPlanBodyError::EnvelopeMetadataMismatch),
        "expected EnvelopeMetadataMismatch, got: {err:?}",
    );
}

/// `EnvelopeSignatureMismatch` when the recorded plan-note
/// signature differs from the signature on disk but the metadata
/// matches. Sign a second envelope (different run id ⇒ different
/// signed bytes ⇒ different signature) and splice its signature
/// onto the plan note while keeping the on-disk envelope.
#[test]
fn envelope_signature_mismatch_when_plan_note_records_other_signature() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let output = OutputEnvelope {
        stdout: b"body".to_vec(),
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let envelope = signed_envelope_with_output(&signing_key, output);
    let (writ_repo, mut plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
    // Sign a different envelope, take its signature, put it on
    // the plan note. The on-disk envelope's signature is still
    // the legitimate one; the plan note records a foreign one.
    let other_envelope = signed_envelope_with_output(
        &signing_key,
        OutputEnvelope {
            stdout: b"different body".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        },
    );
    plan_note.signature = other_envelope.signature;
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let err = read_plan_body_bytes(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        &plan_note,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(err, ReadPlanBodyError::EnvelopeSignatureMismatch),
        "expected EnvelopeSignatureMismatch, got: {err:?}",
    );
}

/// `Verify` failure when the signing key isn't in the allowed
/// signers set. Verifies the helper's defence-in-depth re-check
/// catches an envelope whose signing key is no longer trusted —
/// even though the plan note's recorded metadata and signature
/// match the on-disk envelope.
#[test]
fn verify_failure_under_untrusted_signer() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let output = OutputEnvelope {
        stdout: b"body".to_vec(),
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let envelope = signed_envelope_with_output(&signing_key, output);
    let (writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
    let bailiff = bailiff_repo(&tmp);
    // Allowed-signers set contains the *other* key, not writ's.
    let allowed = AllowedSigners::from_openssh_lines(OTHER_PUB).unwrap();

    let err = read_plan_body_bytes(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        &plan_note,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(err, ReadPlanBodyError::Verify(_)),
        "expected Verify, got: {err:?}",
    );
}

/// `DecodeOutput` failure when the `output` field decodes as
/// envelope JSON but not as an `OutputEnvelope`. Built by
/// signing a non-OutputEnvelope payload as the `output` bytes —
/// the signature covers the digest of these bytes so the verify
/// step passes, but the post-verify decode fails.
#[test]
fn decode_output_failure_when_output_is_not_output_envelope_json() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let output_bytes = b"not an output envelope".to_vec();
    let output_sha = Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap();
    let prompt_sha = Sha256Hex::try_new(sha256_hex(b"prompt")).unwrap();
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
        completed_at: UnixMillis::from_millis(1_700_000_000_000),
        signing_key_fingerprint: signing_key.fingerprint(),
    };
    let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
    let envelope = SignedRunEnvelope {
        metadata,
        signature,
        output: output_bytes,
    };
    let (writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let err = read_plan_body_bytes(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        &plan_note,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(err, ReadPlanBodyError::DecodeOutput(_)),
        "expected DecodeOutput, got: {err:?}",
    );
}

/// `OutputTruncated` when the planner's stdout was truncated by
/// writ. The signature covers the truncation marker, so the
/// envelope verifies — but using only a prefix as the plan body
/// could mislead the reviewer, so the helper refuses.
#[test]
fn output_truncated_when_stdout_was_capped_by_writ() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let output = OutputEnvelope {
        stdout: b"prefix only".to_vec(),
        stderr: Vec::new(),
        stdout_truncated_at: Some(11),
        stderr_truncated_at: None,
    };
    let envelope = signed_envelope_with_output(&signing_key, output);
    let (writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let err = read_plan_body_bytes(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        &plan_note,
        &allowed,
    )
    .unwrap_err();
    match err {
        ReadPlanBodyError::OutputTruncated {
            stdout_truncated_at,
        } => assert_eq!(stdout_truncated_at, 11),
        other => panic!("expected OutputTruncated, got: {other:?}"),
    }
}

/// `OutputEmpty` when the planner's stdout is zero bytes. The
/// design contract treats planner stdout as the plan body, so
/// an empty plan body is a protocol violation that must bail
/// before any reviewer session opens.
#[test]
fn output_empty_when_stdout_is_zero_bytes() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let output = OutputEnvelope {
        stdout: Vec::new(),
        stderr: b"informational".to_vec(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let envelope = signed_envelope_with_output(&signing_key, output);
    let (writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let err = read_plan_body_bytes(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        &plan_note,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(err, ReadPlanBodyError::OutputEmpty),
        "expected OutputEmpty, got: {err:?}",
    );
}

/// `OutputNotUtf8` when the planner's stdout bytes aren't valid
/// UTF-8. Plant a known-invalid sequence (lone 0xFF) and verify
/// the helper rejects rather than lossily decoding.
#[test]
fn output_not_utf8_when_stdout_contains_invalid_bytes() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let output = OutputEnvelope {
        stdout: vec![0xFF, 0xFE, 0xFD],
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let envelope = signed_envelope_with_output(&signing_key, output);
    let (writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let err = read_plan_body_bytes(
        &bailiff,
        writ_repo.path(),
        &writ_notes_ref(),
        &plan_note,
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(err, ReadPlanBodyError::OutputNotUtf8(_)),
        "expected OutputNotUtf8, got: {err:?}",
    );
}
