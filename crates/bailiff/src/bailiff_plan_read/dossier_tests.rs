//! Tests for [`read_dossier`] — the read half of the end goal, where
//! N implementer variants become comparable.
//!
//! Real notes against a real writ repo, so the fetch → re-verify →
//! decode chain runs for every attempt exactly as it does in
//! production. That matters more here than usual: the dossier's whole
//! job is to say which outputs are trustworthy, and a stubbed verifier
//! would make that claim untestable.

use super::test_support::*;
use super::*;
use crate::bailiff_decision::{Decider, Decision};
use crate::bailiff_plan_note::{DecisionNote, ImplementAttempt, plan_notes_ref};
use crate::bailiff_plan_write::{StageNoteTarget, write_stage_note};
use crate::bailiff_stage::StageNoteSlot;
use tempfile::TempDir;
use writ::agent_run::{AgentRunId, sha256_hex};
use writ::core::{CapabilitySet, RepoRef, SessionId, Sha256Hex, UnixMillis};
use writ::run_envelope::OutputEnvelope;
use writ::run_verify::AllowedSigners;
use writ::signing::WritSigningKey;
use writ::writ_client::RunAgentCompleted;

/// Plant one writ envelope whose stdout is exactly `stdout`, and
/// return the `RunAgentCompleted` bailiff would have seen for it.
///
/// Takes the bytes rather than deriving them from a seed string,
/// because every assertion in this file is about *which* bytes came
/// back for *which* attempt.
fn plant_run(
    repo: &NotesRepo,
    signing_key: &WritSigningKey,
    completed_at_millis: i64,
    stdout: &[u8],
) -> RunAgentCompleted {
    let output = OutputEnvelope {
        stdout: stdout.to_vec(),
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let output_bytes = output.to_bytes();
    let metadata = SignedRunMetadata {
        run_id: AgentRunId::new(),
        session_id: SessionId::new(),
        prompt_sha256: Sha256Hex::try_new(sha256_hex(b"prompt")).unwrap(),
        output_envelope_sha256: Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap(),
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
    let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
    let envelope = SignedRunEnvelope {
        metadata: metadata.clone(),
        signature: signature.clone(),
        output: output_bytes,
    };
    let writ_output_oid = repo
        .write_note(
            &writ_notes_ref(),
            metadata.run_id.to_string().as_bytes(),
            &envelope.to_bytes(),
        )
        .unwrap();
    RunAgentCompleted {
        output_oid: writ_output_oid,
        signed_metadata: metadata,
        signature,
    }
}

/// A plan in `Accepted` with `outputs.len()` implementer attempts,
/// each carrying the given stdout.
///
/// Bailiff's own repo doubles as the writ remote here: `read_dossier`
/// fetches writ's notes ref into bailiff's repo, and fetching a repo
/// from itself is a no-op that leaves the planted envelopes exactly
/// where the reader looks for them.
fn plan_with_attempts(
    tmp: &TempDir,
    signing_key: &WritSigningKey,
    plan_body: &[u8],
    outputs: &[&[u8]],
) -> (NotesRepo, PlanId, std::path::PathBuf) {
    let bailiff = bailiff_repo(tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
    let plan_id = PlanId::new();
    let writ_path = bailiff.path().to_path_buf();

    let write = |slot: StageNoteSlot, purpose: &str, run: &RunAgentCompleted| {
        write_stage_note(
            &bailiff,
            &StageNoteTarget {
                slot,
                plan_id,
                writ_repo_path: writ_path.clone(),
                allowed_signers: allowed.clone(),
            },
            &writ_notes_ref(),
            purpose.to_string(),
            run,
        )
        .unwrap_or_else(|e| panic!("planting {purpose}: {e}"));
    };

    let plan_run = plant_run(&bailiff, signing_key, 1, plan_body);
    write(StageNoteSlot::Submission, "plan-submit", &plan_run);
    let review_run = plant_run(&bailiff, signing_key, 2, b"review-stdout");
    write(StageNoteSlot::Review, "plan-review", &review_run);

    let decision = DecisionNote {
        plan_id,
        outcome: Decision::Accepted,
        decider: Decider::try_new("cli:test").unwrap(),
        decided_at: UnixMillis::from_millis(3),
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &crate::bailiff_plan_note::plan_decision_seed_blob_bytes(plan_id),
            &decision.canonical_bytes(),
        )
        .unwrap();

    for (index, stdout) in outputs.iter().enumerate() {
        let attempt = ImplementAttempt::first_n(index as u32 + 1).last().unwrap();
        let run = plant_run(&bailiff, signing_key, 10 + index as i64, stdout);
        write(
            StageNoteSlot::Implement(attempt),
            &format!("attempt-{index}"),
            &run,
        );
    }
    (bailiff, plan_id, writ_path)
}

fn trusted() -> AllowedSigners {
    AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap()
}

/// Three attempts render as three entries, in order, each with **its
/// own** bytes.
///
/// The outputs are distinct and checked individually. A dossier that
/// rendered one attempt's output three times would satisfy any
/// assertion about counts, and that is precisely the failure that
/// would make variant comparison worthless.
#[test]
fn every_attempt_contributes_its_own_output() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let outputs: [&[u8]; 3] = [b"first variant\n", b"second variant\n", b"third\n"];
    let (bailiff, plan_id, writ_path) =
        plan_with_attempts(&tmp, &signing_key, b"# Plan\n\nDo it.\n", &outputs);

    let dossier = read_dossier(&bailiff, plan_id, &writ_path, &writ_notes_ref(), &trusted())
        .expect("dossier must assemble");

    assert_eq!(dossier.plan_id, plan_id);
    assert_eq!(
        dossier.plan_body.as_ref().unwrap().as_ref().unwrap(),
        b"# Plan\n\nDo it.\n",
        "the approved plan body appears once, as the context every attempt shared",
    );
    assert_eq!(dossier.attempts.len(), 3);
    for (index, entry) in dossier.attempts.iter().enumerate() {
        assert_eq!(
            entry.attempt.index(),
            index as u32,
            "attempts must be in order",
        );
        assert_eq!(entry.purpose, format!("attempt-{index}"));
        let output = entry
            .output
            .as_ref()
            .unwrap_or_else(|e| panic!("attempt {index} must verify: {e}"));
        assert_eq!(
            output.stdout, outputs[index],
            "attempt {index} must carry its own bytes",
        );
    }
}

/// An attempt whose envelope does not verify contributes **no bytes**,
/// and says why.
///
/// The load-bearing property of the whole verb. A dossier exists to be
/// read and acted on, so unverified agent output sitting beside
/// verified output with nothing to distinguish them is the worst thing
/// it could do. The failure is recorded per attempt rather than
/// failing the whole read, so one bad attempt does not hide the good
/// ones either.
#[test]
fn an_unverifiable_attempt_contributes_no_bytes() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let outputs: [&[u8]; 2] = [b"trustworthy\n", b"also trustworthy\n"];
    let (bailiff, plan_id, writ_path) =
        plan_with_attempts(&tmp, &signing_key, b"# Plan\n\nDo it.\n", &outputs);

    // A keyring that cannot verify writ's key — the same observable
    // state as an envelope swapped on disk after it was recorded.
    let untrusted = AllowedSigners::from_openssh_lines(OTHER_PUB).unwrap();
    let dossier = read_dossier(&bailiff, plan_id, &writ_path, &writ_notes_ref(), &untrusted)
        .expect("the dossier must still assemble; per-attempt failures stay per-attempt");

    assert_eq!(
        dossier.attempts.len(),
        2,
        "the attempts are still enumerated — only their bytes are withheld",
    );
    for entry in &dossier.attempts {
        assert!(
            entry.output.is_err(),
            "attempt {} verified under a keyring that cannot verify it",
            entry.attempt,
        );
    }
    assert!(dossier.plan_body.as_ref().unwrap().is_err());
}

/// A plan with no implementer attempts yields an empty attempt list
/// and still renders its plan body — the pre-fan-out shape, which must
/// keep working.
#[test]
fn a_plan_with_no_attempts_still_yields_its_plan_body() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (bailiff, plan_id, writ_path) =
        plan_with_attempts(&tmp, &signing_key, b"# Plan\n\nNothing yet.\n", &[]);

    let dossier = read_dossier(&bailiff, plan_id, &writ_path, &writ_notes_ref(), &trusted())
        .expect("dossier must assemble");
    assert!(dossier.attempts.is_empty());
    assert_eq!(
        dossier.plan_body.unwrap().unwrap(),
        b"# Plan\n\nNothing yet.\n",
    );
}

/// An attempt that produced **no output at all** renders as an attempt
/// with zero bytes, not as a failure.
///
/// `read_plan_body_bytes` refuses empty stdout, because the planner's
/// stdout *is* the plan body. An implementer that pushes and says
/// nothing is ordinary, and the dossier must not conflate "said
/// nothing" with "could not be verified". The split between the shared
/// parse (`read_verified_output`) and the per-caller policy exists for
/// exactly this, so this test is what keeps the split honest.
#[test]
fn an_attempt_with_empty_output_is_not_a_failure() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let outputs: [&[u8]; 1] = [b""];
    let (bailiff, plan_id, writ_path) =
        plan_with_attempts(&tmp, &signing_key, b"# Plan\n\nDo it.\n", &outputs);

    let dossier = read_dossier(&bailiff, plan_id, &writ_path, &writ_notes_ref(), &trusted())
        .expect("dossier must assemble");
    let output = dossier.attempts[0]
        .output
        .as_ref()
        .expect("an empty output verifies like any other");
    assert!(output.stdout.is_empty());
}

/// Non-UTF-8 output survives the round trip verbatim.
///
/// `read_plan_body_bytes` requires UTF-8 because its bytes become an
/// LLM prompt. An implementer's stdout has no such requirement — it
/// may contain any bytes at all — which is why `DossierOutput.stdout`
/// is a `Vec<u8>` and the renderer length-prefixes it rather than
/// escaping it.
#[test]
fn non_utf8_output_survives_verbatim() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let raw: &[u8] = &[0xff, 0xfe, 0x00, b'\n', 0x80];
    let (bailiff, plan_id, writ_path) =
        plan_with_attempts(&tmp, &signing_key, b"# Plan\n\nDo it.\n", &[raw]);

    let dossier = read_dossier(&bailiff, plan_id, &writ_path, &writ_notes_ref(), &trusted())
        .expect("dossier must assemble");
    assert_eq!(dossier.attempts[0].output.as_ref().unwrap().stdout, raw);
}
