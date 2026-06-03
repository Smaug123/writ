//! Tests for [`list_plan_ids`] and [`summarize_plan`] — slice F2's
//! aggregate read primitives. The helpers compose over the existing
//! `read_*_note` siblings (already covered by their own modules) so
//! these tests focus on:
//!
//! - ref enumeration: empty repo, multiple plans, lexicographic
//!   ordering, parse failure on a non-UUID tail.
//! - summary aggregation: each subset of the four notes maps to
//!   the expected `BailiffPlanSummary` field set.
//! - workflow-state derivation: every variant of [`WorkflowState`]
//!   is reachable from a corresponding fixture.
//!
//! Notes are planted directly via [`NotesRepo::write_note`] rather
//! than through the real write workflow because the summary helper
//! is a pure read-side composition; exercising the write workflow
//! end-to-end would require a writ broker per test, which is the
//! existing round-trip tests' concern in the sibling modules.
use super::test_support::*;
use super::*;
use crate::agent_run::{AgentRunId, sha256_hex};
use crate::bailiff_decision::{Decider, Decision};
use crate::bailiff_plan_note::{
    DecisionNote, ImplementNote, PlanId, PlanNote, ReviewNote, plan_decision_seed_blob_bytes,
    plan_implement_seed_blob_bytes, plan_notes_ref, plan_review_seed_blob_bytes,
    plan_submission_seed_blob_bytes,
};
use crate::core::{
    CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, SshSignature, UnixMillis,
};
use crate::protocol::SignedRunMetadata;
use crate::run_envelope::OutputEnvelope;
use crate::signing::WritSigningKey;
use crate::vm_git::GitObjectId;
use tempfile::TempDir;

/// Build a `SignedRunMetadata` + matching signature with a given
/// `completed_at`. Reused across the three signed note types
/// (`PlanNote`, `ReviewNote`, `ImplementNote`) because the read
/// helpers only consult `completed_at` and the typed signature
/// must round-trip through `from_canonical_bytes`. The signature
/// is computed under the test signing key so the bytes are
/// structurally valid even though no verifier runs in this test
/// module.
fn sample_metadata_and_signature(completed_at_millis: i64) -> (SignedRunMetadata, SshSignature) {
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let output = OutputEnvelope {
        stdout: b"agent stdout".to_vec(),
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let output_sha = Sha256Hex::try_new(sha256_hex(&output.to_bytes())).unwrap();
    let prompt_sha = Sha256Hex::try_new(sha256_hex(b"agent-prompt")).unwrap();
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
    let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
    (metadata, signature)
}

fn plant_plan_note(bailiff: &NotesRepo, plan_id: PlanId, purpose: &str, submitted_at_millis: i64) {
    let (metadata, signature) = sample_metadata_and_signature(submitted_at_millis);
    let note = PlanNote {
        plan_id,
        purpose: purpose.to_string(),
        writ_output_oid: GitObjectId::new("a".repeat(40)).unwrap(),
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
}

fn plant_decision_note(
    bailiff: &NotesRepo,
    plan_id: PlanId,
    outcome: Decision,
    decider: &str,
    decided_at_millis: i64,
) {
    let note = DecisionNote {
        plan_id,
        outcome,
        decider: Decider::try_new(decider).unwrap(),
        decided_at: UnixMillis::from_millis(decided_at_millis),
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_decision_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();
}

fn plant_review_note(bailiff: &NotesRepo, plan_id: PlanId, reviewed_at_millis: i64) {
    let (metadata, signature) = sample_metadata_and_signature(reviewed_at_millis);
    let note = ReviewNote {
        plan_id,
        purpose: "plan-review".into(),
        writ_output_oid: GitObjectId::new("b".repeat(40)).unwrap(),
        signed_metadata: metadata,
        signature,
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_review_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();
}

fn plant_implement_note(bailiff: &NotesRepo, plan_id: PlanId, implemented_at_millis: i64) {
    let (metadata, signature) = sample_metadata_and_signature(implemented_at_millis);
    let note = ImplementNote {
        plan_id,
        purpose: "plan-implement".into(),
        writ_output_oid: GitObjectId::new("c".repeat(40)).unwrap(),
        signed_metadata: metadata,
        signature,
    };
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &plan_implement_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();
}

/// Empty repo has no plan refs → empty vec, exit success. Common
/// state on a fresh bailiff install.
#[test]
fn list_plan_ids_returns_empty_vec_on_empty_repo() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    assert_eq!(list_plan_ids(&bailiff).unwrap(), Vec::<PlanId>::new());
}

/// Three plans with attached submission notes — listing returns
/// the three ids in `for-each-ref` (lexicographic-by-ref-name)
/// order. Pins the contract operators rely on when piping list
/// output through `head -n` or similar.
#[test]
fn list_plan_ids_returns_plans_in_lexicographic_order() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let id_a = PlanId::from_uuid("0a000000-0000-4000-8000-000000000001".parse().unwrap());
    let id_b = PlanId::from_uuid("0b000000-0000-4000-8000-000000000002".parse().unwrap());
    let id_c = PlanId::from_uuid("0c000000-0000-4000-8000-000000000003".parse().unwrap());
    // Plant out of order to confirm the helper does not preserve
    // insertion order — only the ref-name lex order matters.
    plant_plan_note(&bailiff, id_c, "third", 3);
    plant_plan_note(&bailiff, id_a, "first", 1);
    plant_plan_note(&bailiff, id_b, "second", 2);
    let ids = list_plan_ids(&bailiff).unwrap();
    assert_eq!(ids, vec![id_a, id_b, id_c]);
}

/// A ref under the plan prefix whose tail is not a parseable UUID
/// surfaces as `ListPlanIdsError::ParseRef` with the offending tail
/// in the error payload. Constructed by planting a note under a
/// manually-constructed ref name that bypasses
/// `plan_notes_ref(plan_id)`. This is the corruption-detection
/// signal: bailiff is the sole writer to the plan namespace, so
/// the only way to reach this state is manual `git update-ref` or
/// an external writer.
#[test]
fn list_plan_ids_returns_parse_error_on_non_uuid_tail() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    // The bad ref name still has to satisfy `NotesRef::try_new`'s
    // validators (no whitespace, no `..`, etc.) — using `garbage`
    // as the tail keeps the ref well-formed while the tail fails
    // UUID parsing.
    let bad_ref = NotesRef::try_new("refs/notes/bailiff/v1/plans/not-a-uuid").unwrap();
    bailiff
        .write_note(&bad_ref, b"seed-bytes", b"body")
        .unwrap();
    let err = list_plan_ids(&bailiff).unwrap_err();
    match err {
        ListPlanIdsError::ParseRef {
            raw_ref,
            tail,
            source: _,
        } => {
            assert_eq!(raw_ref, "refs/notes/bailiff/v1/plans/not-a-uuid");
            assert_eq!(tail, "not-a-uuid");
        }
        other => panic!("expected ParseRef, got: {other:?}"),
    }
}

/// `Uuid::parse_str` accepts non-canonical spellings (uppercase
/// hex, 32 unhyphenated hex characters) that `plan_notes_ref`
/// never emits. If `list_plan_ids` let those through, the
/// downstream `summarize_plan` would re-derive the ref name in
/// canonical lowercase-hyphenated form and look there — finding
/// nothing and silently hiding the corrupted ref that actually
/// carries the notes. Surface them as `NonCanonicalRef` so the
/// operator sees which on-disk ref is the offender.
#[test]
fn list_plan_ids_rejects_uppercase_hex_uuid_tail() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let bad_ref =
        NotesRef::try_new("refs/notes/bailiff/v1/plans/AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")
            .unwrap();
    bailiff
        .write_note(&bad_ref, b"seed-bytes", b"body")
        .unwrap();
    let err = list_plan_ids(&bailiff).unwrap_err();
    match err {
        ListPlanIdsError::NonCanonicalRef {
            raw_ref,
            tail,
            canonical,
        } => {
            assert_eq!(
                raw_ref,
                "refs/notes/bailiff/v1/plans/AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"
            );
            assert_eq!(tail, "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE");
            assert_eq!(canonical, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        }
        other => panic!("expected NonCanonicalRef, got: {other:?}"),
    }
}

/// The other non-canonical spelling `uuid` accepts: 32 hex
/// characters without hyphens. Same risk and same fix as the
/// uppercase case, separately pinned because the two code paths
/// inside `Uuid::parse_str` are independent.
#[test]
fn list_plan_ids_rejects_unhyphenated_uuid_tail() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let bad_ref =
        NotesRef::try_new("refs/notes/bailiff/v1/plans/aaaaaaaabbbb4ccc8dddeeeeeeeeeeee").unwrap();
    bailiff
        .write_note(&bad_ref, b"seed-bytes", b"body")
        .unwrap();
    let err = list_plan_ids(&bailiff).unwrap_err();
    match err {
        ListPlanIdsError::NonCanonicalRef {
            tail, canonical, ..
        } => {
            assert_eq!(tail, "aaaaaaaabbbb4ccc8dddeeeeeeeeeeee");
            assert_eq!(canonical, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        }
        other => panic!("expected NonCanonicalRef, got: {other:?}"),
    }
}

/// A plan-id whose ref exists but carries no submission note
/// (decision attached first, manual repo state) folds into
/// `submission: None` rather than an error. Pin the surface so
/// `bailiff plan list` keeps rendering the row instead of failing
/// the whole command — the [`WorkflowState::Corrupt`] derivation
/// is how the operator sees the anomaly.
#[test]
fn summarize_plan_returns_corrupt_state_when_only_decision_present() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    plant_decision_note(&bailiff, plan_id, Decision::Accepted, "cli:tester", 100);
    let summary = summarize_plan(&bailiff, plan_id).unwrap();
    assert_eq!(summary.plan_id, plan_id);
    assert!(summary.submission.is_none());
    assert!(summary.decision.is_some());
    assert!(summary.reviewed_at.is_none());
    assert!(summary.implemented_at.is_none());
    assert_eq!(summary.state(), WorkflowState::Corrupt);
}

/// Submission only: the four optionals are submission=Some,
/// decision=None, reviewed_at=None, implemented_at=None.
/// `purpose` and `submitted_at` come from the plan note's body and
/// metadata; pin both.
#[test]
fn summarize_plan_returns_submission_only_when_just_submitted() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    plant_plan_note(&bailiff, plan_id, "fix-oauth-drift", 1_700_000_000_000);
    let summary = summarize_plan(&bailiff, plan_id).unwrap();
    let submission = summary
        .submission
        .as_ref()
        .expect("submission must be Some");
    assert_eq!(submission.purpose, "fix-oauth-drift");
    assert_eq!(submission.submitted_at.as_millis(), 1_700_000_000_000);
    assert!(summary.decision.is_none());
    assert!(summary.reviewed_at.is_none());
    assert!(summary.implemented_at.is_none());
    assert_eq!(summary.state(), WorkflowState::Submitted);
}

/// Submission + accept decision → state=accepted, decision fields
/// projected from the note. A regression that swapped accept and
/// reject would be catastrophically wrong but invisible to the
/// `submitted` test above.
#[test]
fn summarize_plan_projects_accepted_decision() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    plant_plan_note(&bailiff, plan_id, "p", 1);
    plant_decision_note(&bailiff, plan_id, Decision::Accepted, "cli:alice", 2);
    let summary = summarize_plan(&bailiff, plan_id).unwrap();
    let decision = summary.decision.as_ref().expect("decision must be Some");
    assert_eq!(decision.outcome, Decision::Accepted);
    assert_eq!(decision.decider.as_str(), "cli:alice");
    assert_eq!(decision.decided_at.as_millis(), 2);
    assert_eq!(summary.state(), WorkflowState::Accepted);
}

/// Submission + reject decision → state=rejected.
#[test]
fn summarize_plan_projects_rejected_decision() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    plant_plan_note(&bailiff, plan_id, "p", 1);
    plant_decision_note(&bailiff, plan_id, Decision::Rejected, "cli:bob", 2);
    let summary = summarize_plan(&bailiff, plan_id).unwrap();
    assert_eq!(
        summary.decision.as_ref().map(|d| d.outcome),
        Some(Decision::Rejected),
    );
    assert_eq!(summary.state(), WorkflowState::Rejected);
}

/// Submission + accept + review → state=reviewed; `reviewed_at`
/// lifted from the review note's signed metadata.
#[test]
fn summarize_plan_projects_reviewed_at_when_reviewed() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    plant_plan_note(&bailiff, plan_id, "p", 1);
    plant_decision_note(&bailiff, plan_id, Decision::Accepted, "cli:alice", 2);
    plant_review_note(&bailiff, plan_id, 1_700_000_001_000);
    let summary = summarize_plan(&bailiff, plan_id).unwrap();
    assert_eq!(
        summary.reviewed_at.map(|t| t.as_millis()),
        Some(1_700_000_001_000),
    );
    assert!(summary.implemented_at.is_none());
    assert_eq!(summary.state(), WorkflowState::Reviewed);
}

/// All four notes present → state=implemented; every projection
/// populated. The "highest stage" rule means `Implemented` wins
/// over `Reviewed` even though both notes are attached.
#[test]
fn summarize_plan_projects_implemented_at_when_implemented() {
    let tmp = TempDir::new().unwrap();
    let bailiff = bailiff_repo(&tmp);
    let plan_id = PlanId::new();
    plant_plan_note(&bailiff, plan_id, "p", 1);
    plant_decision_note(&bailiff, plan_id, Decision::Accepted, "cli:alice", 2);
    plant_review_note(&bailiff, plan_id, 3);
    plant_implement_note(&bailiff, plan_id, 1_700_000_002_000);
    let summary = summarize_plan(&bailiff, plan_id).unwrap();
    assert_eq!(
        summary.implemented_at.map(|t| t.as_millis()),
        Some(1_700_000_002_000),
    );
    assert_eq!(
        summary.reviewed_at.map(|t| t.as_millis()),
        Some(3),
        "reviewed_at must still surface even though state overrides to implemented",
    );
    assert_eq!(summary.state(), WorkflowState::Implemented);
}

/// `WorkflowState::as_str` pins the lowercase string the formatter
/// writes; a rename would surface here rather than as a test-snapshot
/// drift somewhere far from the source.
#[test]
fn workflow_state_as_str_is_stable_lowercase() {
    assert_eq!(WorkflowState::Corrupt.as_str(), "corrupt");
    assert_eq!(WorkflowState::Submitted.as_str(), "submitted");
    assert_eq!(WorkflowState::Accepted.as_str(), "accepted");
    assert_eq!(WorkflowState::Rejected.as_str(), "rejected");
    assert_eq!(WorkflowState::Reviewed.as_str(), "reviewed");
    assert_eq!(WorkflowState::Implemented.as_str(), "implemented");
    // Display must agree with as_str.
    assert_eq!(WorkflowState::Submitted.to_string(), "submitted");
}
