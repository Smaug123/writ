//! Tests for the three stage-note readers, parameterised over
//! [`AgentStage`] the way `bailiff_plan_write::stage_tests` is for the
//! writer. Every case runs for every stage, so a property pinned for one
//! reader is pinned for all of them.
//!
//! The round-trip case drives the real writer so a drift between the
//! writer's seed and the reader's surfaces here; the rest plant bodies
//! directly through the low-level [`NotesRepo::write_note`], which is
//! the only way the corrupt states they cover can arise.

use super::test_support::*;
use super::*;
use crate::bailiff_plan_note::{
    ImplementAttempt, ImplementNote, PlanId, PlanNote, ReviewNote, plan_decision_seed_blob_bytes,
    plan_notes_ref,
};
use crate::bailiff_plan_write::{StageNoteTarget, write_stage_note};
use crate::bailiff_stage::AgentStage;
use tempfile::TempDir;
use writ::core::SshSignature;
use writ::protocol::SignedRunMetadata;
use writ::run_verify::AllowedSigners;
use writ::signing::WritSigningKey;
use writ::vm_git::GitObjectId;

/// What a reader answered, projected out of the stage's own note type
/// so one assertion serves all three.
#[derive(Debug)]
enum Read {
    Absent,
    Note {
        plan_id: PlanId,
        purpose: String,
        writ_output_oid: GitObjectId,
        signed_metadata: SignedRunMetadata,
        signature: SshSignature,
    },
    Decode,
    PlanIdMismatch {
        requested: PlanId,
        found: PlanId,
    },
    Failed,
}

fn read(stage: AgentStage, bailiff: &NotesRepo, plan_id: PlanId) -> Read {
    macro_rules! via {
        ($result:expr) => {
            match $result {
                Ok(None) => Read::Absent,
                Ok(Some(n)) => Read::Note {
                    plan_id: n.plan_id,
                    purpose: n.purpose,
                    writ_output_oid: n.writ_output_oid,
                    signed_metadata: n.signed_metadata,
                    signature: n.signature,
                },
                Err(ReadNoteError::Decode(_)) => Read::Decode,
                Err(ReadNoteError::PlanIdMismatch { requested, found }) => {
                    Read::PlanIdMismatch { requested, found }
                }
                Err(ReadNoteError::ReadNote(_)) => Read::Failed,
            }
        };
    }
    match stage {
        AgentStage::Submit => via!(read_plan_note(bailiff, plan_id)),
        AgentStage::Review => via!(read_review_note(bailiff, plan_id)),
        AgentStage::Implement => {
            via!(read_implement_note(
                bailiff,
                plan_id,
                ImplementAttempt::FIRST
            ))
        }
    }
}

/// The canonical bytes of a well-formed note of `stage`'s type, for
/// planting directly.
fn sample_body(stage: AgentStage, plan_id: PlanId, purpose: &str) -> Vec<u8> {
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let envelope = freshly_signed(&signing_key);
    let purpose = purpose.to_string();
    let writ_output_oid = GitObjectId::new("d".repeat(40)).unwrap();
    let signed_metadata = envelope.metadata;
    let signature = envelope.signature;
    match stage {
        AgentStage::Submit => PlanNote {
            plan_id,
            purpose,
            writ_output_oid,
            signed_metadata,
            signature,
        }
        .canonical_bytes(),
        AgentStage::Review => ReviewNote {
            plan_id,
            purpose,
            writ_output_oid,
            signed_metadata,
            signature,
        }
        .canonical_bytes(),
        AgentStage::Implement => ImplementNote {
            plan_id,
            purpose,
            writ_output_oid,
            signed_metadata,
            signature,
        }
        .canonical_bytes(),
    }
}

/// Plant `body` at `stage`'s first slot for `plan_id`.
fn plant(bailiff: &NotesRepo, stage: AgentStage, plan_id: PlanId, body: &[u8]) {
    bailiff
        .write_note(
            &plan_notes_ref(plan_id),
            &stage.first_slot().seed(plan_id),
            body,
        )
        .unwrap();
}

/// Every seed a plan's ref can carry a note at, so a reader can be shown
/// ignoring all the slots that are not its own.
fn every_seed(plan_id: PlanId) -> Vec<(String, Vec<u8>)> {
    let mut seeds: Vec<(String, Vec<u8>)> = AgentStage::ALL
        .iter()
        .map(|stage| (stage.to_string(), stage.first_slot().seed(plan_id)))
        .collect();
    seeds.push((
        "decision".to_string(),
        plan_decision_seed_blob_bytes(plan_id),
    ));
    seeds
}

/// A plan with no note of the stage's kind reads as `None`, both when the
/// plan's ref does not exist at all and when it exists carrying notes at
/// every *other* seed. The latter is the load-bearing property of the
/// seeds-per-plan scheme: a collision between two seed derivations would
/// make one kind of note read as another.
#[test]
fn absent_note_reads_as_none_whatever_else_is_present() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        assert!(
            matches!(read(stage, &bailiff, plan_id), Read::Absent),
            "{stage}: fresh repo"
        );

        let own = stage.first_slot().seed(plan_id);
        for (name, seed) in every_seed(plan_id) {
            if seed == own {
                continue;
            }
            bailiff
                .write_note(&plan_notes_ref(plan_id), &seed, b"some other note")
                .unwrap();
            let got = read(stage, &bailiff, plan_id);
            assert!(
                matches!(got, Read::Absent),
                "{stage}: with a {name} note present, got {got:?}"
            );
        }
    }
}

/// Load-bearing round-trip: what the real writer attaches, the reader
/// finds, field for field. A drift between the writer's seed derivation
/// and the reader's would make every note of that stage unrecoverable.
#[test]
fn round_trips_through_write_stage_note() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed) = writ_repo_with_envelope(&tmp, &freshly_signed(&signing_key));
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let plan_id = PlanId::new();
        let purpose = format!("plan-{stage}");
        write_stage_note(
            &bailiff,
            &StageNoteTarget {
                slot: stage.first_slot(),
                plan_id,
                writ_repo_path: writ_repo.path().to_path_buf(),
                allowed_signers: allowed,
            },
            &writ_notes_ref(),
            purpose.clone(),
            &completed,
        )
        .unwrap_or_else(|e| panic!("{stage}: write must succeed: {e}"));

        match read(stage, &bailiff, plan_id) {
            Read::Note {
                plan_id: got_plan,
                purpose: got_purpose,
                writ_output_oid,
                signed_metadata,
                signature,
            } => {
                assert_eq!(got_plan, plan_id, "{stage}");
                assert_eq!(got_purpose, purpose, "{stage}");
                assert_eq!(writ_output_oid, completed.output_oid, "{stage}");
                assert_eq!(signed_metadata, completed.signed_metadata, "{stage}");
                assert_eq!(signature, completed.signature, "{stage}");
            }
            other => panic!("{stage}: expected the written note back, got {other:?}"),
        }
    }
}

/// Distinct plans do not cross-read: a regression that dropped
/// `plan_id` from the ref derivation would make every plan share one
/// note.
#[test]
fn distinct_plans_read_their_own_notes() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let p1 = PlanId::new();
        let p2 = PlanId::new();
        plant(&bailiff, stage, p1, &sample_body(stage, p1, "first"));
        plant(&bailiff, stage, p2, &sample_body(stage, p2, "second"));
        for (plan, expected) in [(p1, "first"), (p2, "second")] {
            match read(stage, &bailiff, plan) {
                Read::Note {
                    plan_id, purpose, ..
                } => {
                    assert_eq!(plan_id, plan, "{stage}");
                    assert_eq!(purpose, expected, "{stage}");
                }
                other => panic!("{stage}: expected plan {plan}'s note, got {other:?}"),
            }
        }
    }
}

/// A well-formed body carrying another plan's id, planted under this
/// plan's seed, is refused as `PlanIdMismatch` rather than surfaced: a
/// gate must never act on plan A from plan B's note. Only manual repo
/// surgery or a buggy low-level writer can produce the state, and the
/// reader is where the requested id is in scope to catch it.
#[test]
fn a_foreign_plan_id_is_refused() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let queried = PlanId::new();
        let other = PlanId::new();
        plant(
            &bailiff,
            stage,
            queried,
            &sample_body(stage, other, "foreign"),
        );
        match read(stage, &bailiff, queried) {
            Read::PlanIdMismatch { requested, found } => {
                assert_eq!(requested, queried, "{stage}");
                assert_eq!(found, other, "{stage}");
            }
            other_read => panic!("{stage}: expected PlanIdMismatch, got {other_read:?}"),
        }
    }
}

/// Bytes at the seed that are not a note of the stage's type are a
/// `Decode` error, not `None` and not a read failure.
#[test]
fn a_corrupt_body_is_a_decode_error() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        plant(&bailiff, stage, plan_id, b"not json at all");
        let got = read(stage, &bailiff, plan_id);
        assert!(matches!(got, Read::Decode), "{stage}: got {got:?}");
    }
}
