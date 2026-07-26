//! Tests for [`write_stage_note`], parameterised over the three
//! envelope-bearing stages.
//!
//! Replaces `plan_tests`, `review_tests`, and `implement_tests`, which
//! between them were 1,168 lines carrying the same test names modulo
//! the noun — the test-layer half of the triplication slice 3b removes.
//! Every case here runs for all three stages, so the coverage is
//! strictly larger than the three modules it replaces: several
//! properties were previously pinned for only one or two of them.
//!
//! Harness shape is unchanged: a tempdir-backed writ repo holding one
//! signed envelope, a sibling bailiff repo, and an `AllowedSigners`
//! keyring. The full broker handshake stays in `end_to_end_tests`.

use super::test_support::*;
use super::*;
use crate::bailiff_plan_note::{
    ImplementNote, PlanId, PlanNote, ReviewNote, plan_decision_seed_blob_bytes, plan_notes_ref,
};
use tempfile::TempDir;
use writ::core::{SshSignature, UnixMillis};
use writ::protocol::SignedRunMetadata;
use writ::signing::WritSigningKey;

/// The write target for a stage in this harness. Bundling it here
/// keeps each case's call site about the property it is testing rather
/// than about argument order.
fn target(
    stage: AgentStage,
    plan_id: PlanId,
    writ_repo_path: &std::path::Path,
    allowed: &AllowedSigners,
) -> StageNoteTarget {
    StageNoteTarget {
        stage,
        plan_id,
        writ_repo_path: writ_repo_path.to_path_buf(),
        allowed_signers: allowed.clone(),
    }
}

/// The fields every stage note carries, decoded through the *right*
/// type for `stage`.
///
/// The three note types are field-identical and generated from one
/// macro, but they stay distinct so that `read_plan_body_bytes` can
/// demand the submission specifically. This match is how a
/// stage-parameterised test reads one back without picking a type at
/// random — decoding an implement note as a `PlanNote` would succeed
/// and prove nothing.
struct DecodedNote {
    plan_id: PlanId,
    purpose: String,
    writ_output_oid: GitObjectId,
    signed_metadata: SignedRunMetadata,
    signature: SshSignature,
}

fn decode(stage: AgentStage, body: &[u8]) -> DecodedNote {
    macro_rules! via {
        ($ty:ty) => {{
            let n = <$ty>::from_canonical_bytes(body).expect("body must decode");
            DecodedNote {
                plan_id: n.plan_id,
                purpose: n.purpose,
                writ_output_oid: n.writ_output_oid,
                signed_metadata: n.signed_metadata,
                signature: n.signature,
            }
        }};
    }
    match stage {
        AgentStage::Submit => via!(PlanNote),
        AgentStage::Review => via!(ReviewNote),
        AgentStage::Implement => via!(ImplementNote),
    }
}

/// The seed bytes each stage attaches at, written out rather than
/// taken from `AgentStage::note_seed`.
///
/// A test that asked `note_seed` what the seed is could not catch
/// `note_seed` returning the wrong one. These literals are the
/// contract: they are what every note already in an operator's repo
/// was attached at, so changing one orphans those notes.
fn expected_seed_text(stage: AgentStage, plan_id: PlanId) -> String {
    match stage {
        AgentStage::Submit => format!("{plan_id}"),
        AgentStage::Review => format!("{plan_id}::review"),
        AgentStage::Implement => format!("{plan_id}::implement"),
    }
}

/// Happy path, per stage: the note attaches, decodes back through its
/// own type, carries the envelope fields writ produced, and lands at
/// the seed the scheme documents.
#[test]
fn happy_path_round_trips_for_every_stage() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let plan_id = PlanId::new();
        let purpose = format!("plan-{stage}");
        let returned_oid = write_stage_note(
            &bailiff,
            &target(stage, plan_id, writ_repo.path(), &allowed),
            &writ_notes_ref(),
            purpose.clone(),
            &completed,
        )
        .unwrap_or_else(|e| panic!("{stage} happy path must succeed: {e}"));

        let body = bailiff
            .read_note(&plan_notes_ref(plan_id), &returned_oid)
            .unwrap_or_else(|e| panic!("{stage} note must be readable at the returned OID: {e}"));
        let note = decode(stage, &body);
        assert_eq!(note.plan_id, plan_id, "{stage}");
        assert_eq!(note.purpose, purpose, "{stage}");
        assert_eq!(note.writ_output_oid, completed.output_oid, "{stage}");
        assert_eq!(note.signed_metadata, envelope.metadata, "{stage}");
        assert_eq!(note.signature, envelope.signature, "{stage}");

        // The seed bytes are the load-bearing input to `git
        // hash-object`; pin them so a writer-side change cannot
        // silently move where a stage's note lives.
        assert_eq!(
            std::str::from_utf8(&stage.note_seed(plan_id)).unwrap(),
            expected_seed_text(stage, plan_id),
            "{stage} seed",
        );
    }
}

/// Idempotent by error, for **every** stage.
///
/// Before slice 3b the submission was the odd one out: `write_note`
/// refused a duplicate with a generic git failure where its siblings
/// returned the typed conflict. Both refused; only one said why. This
/// test running for `Submit` is the record of that delta — under the
/// old code it would have failed for that stage alone.
#[test]
fn a_second_write_is_refused_and_the_first_body_survives() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let plan_id = PlanId::new();

        let write = |purpose: &str| {
            write_stage_note(
                &bailiff,
                &target(stage, plan_id, writ_repo.path(), &allowed),
                &writ_notes_ref(),
                purpose.to_string(),
                &completed,
            )
        };

        let first_oid = write("first").unwrap_or_else(|e| panic!("{stage} first write: {e}"));
        // A different `purpose` on the second call, so a silent
        // overwrite would surface as a body mismatch below rather than
        // passing as a no-op.
        let err = write("second").expect_err("a second write must be refused");
        match err {
            WriteStageNoteError::AlreadyRecorded {
                stage: got_stage,
                plan_id: got_plan,
                target_oid,
            } => {
                assert_eq!(got_stage, stage);
                assert_eq!(got_plan, plan_id);
                assert_eq!(target_oid, first_oid);
            }
            other => panic!("expected AlreadyRecorded for {stage}, got: {other:?}"),
        }

        let body = bailiff
            .read_note(&plan_notes_ref(plan_id), &first_oid)
            .unwrap();
        assert_eq!(decode(stage, &body).purpose, "first", "{stage}");
    }
}

/// Defence in depth: if writ's reply and the envelope it stored
/// disagree about the metadata, no note is written.
#[test]
fn metadata_mismatch_between_envelope_and_reply_is_rejected() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, mut completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        completed.signed_metadata.completed_at = UnixMillis::from_millis(1);
        let err = write_stage_note(
            &bailiff,
            &target(stage, PlanId::new(), writ_repo.path(), &allowed),
            &writ_notes_ref(),
            "p".into(),
            &completed,
        )
        .expect_err("a metadata mismatch must be refused");
        assert!(
            matches!(
                err,
                WriteStageNoteError::FetchVerify(FetchVerifyError::EnvelopeMetadataMismatch)
            ),
            "{stage}: expected EnvelopeMetadataMismatch, got {err:?}",
        );
    }
}

/// The signature half of the same defence.
#[test]
fn signature_mismatch_between_envelope_and_reply_is_rejected() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, mut completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        completed.signature = freshly_signed(&signing_key).signature;
        let err = write_stage_note(
            &bailiff,
            &target(stage, PlanId::new(), writ_repo.path(), &allowed),
            &writ_notes_ref(),
            "p".into(),
            &completed,
        )
        .expect_err("a signature mismatch must be refused");
        assert!(
            matches!(
                err,
                WriteStageNoteError::FetchVerify(FetchVerifyError::EnvelopeSignatureMismatch)
            ),
            "{stage}: expected EnvelopeSignatureMismatch, got {err:?}",
        );
    }
}

/// An envelope signed by a key bailiff's keyring does not carry is
/// refused at `verify_run_envelope`, whichever stage asked.
#[test]
fn an_untrusted_signer_is_rejected() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(OTHER_PUB).unwrap();

        let err = write_stage_note(
            &bailiff,
            &target(stage, PlanId::new(), writ_repo.path(), &allowed),
            &writ_notes_ref(),
            "p".into(),
            &completed,
        )
        .expect_err("an untrusted signer must be refused");
        assert!(
            matches!(
                err,
                WriteStageNoteError::FetchVerify(FetchVerifyError::Verify(_))
            ),
            "{stage}: expected Verify, got {err:?}",
        );
    }
}

/// A writ repo that is not there surfaces as `Fetch`, not as a
/// verification failure — the operator's problem is a path, not a key.
#[test]
fn a_missing_writ_repo_surfaces_as_a_fetch_failure() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (_writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let err = write_stage_note(
            &bailiff,
            &target(
                stage,
                PlanId::new(),
                &tmp.path().join("no-such-writ-repo"),
                &allowed,
            ),
            &writ_notes_ref(),
            "p".into(),
            &completed,
        )
        .expect_err("a missing writ repo must be refused");
        assert!(
            matches!(
                err,
                WriteStageNoteError::FetchVerify(FetchVerifyError::Fetch(_))
            ),
            "{stage}: expected Fetch, got {err:?}",
        );
    }
}

/// Two plans are independent: the same envelope backs a note under
/// each, and neither write disturbs the other.
///
/// Previously pinned for the submission alone
/// (`supports_two_plans_referencing_one_writ_envelope`) and, in a
/// different form, for review and implement.
#[test]
fn distinct_plans_are_independent_for_every_stage() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let (a, b) = (PlanId::new(), PlanId::new());
        let write = |plan_id, purpose: &str| {
            write_stage_note(
                &bailiff,
                &target(stage, plan_id, writ_repo.path(), &allowed),
                &writ_notes_ref(),
                purpose.to_string(),
                &completed,
            )
            .unwrap_or_else(|e| panic!("{stage} write for {plan_id}: {e}"))
        };
        let oid_a = write(a, "first-plan");
        let oid_b = write(b, "second-plan");

        assert_ne!(
            oid_a, oid_b,
            "{stage}: distinct plans must attach at distinct OIDs"
        );
        assert_eq!(
            decode(
                stage,
                &bailiff.read_note(&plan_notes_ref(a), &oid_a).unwrap()
            )
            .purpose,
            "first-plan",
            "{stage}",
        );
        assert_eq!(
            decode(
                stage,
                &bailiff.read_note(&plan_notes_ref(b), &oid_b).unwrap()
            )
            .purpose,
            "second-plan",
            "{stage}",
        );
    }
}

/// **All four** of a plan's notes coexist under one ref at four
/// distinct targets, and all four read back.
///
/// The three old modules each pinned two or three *pairwise*
/// combinations of this, which is both more code and less coverage:
/// pairwise tests cannot catch a three-way collision. The whole
/// one-ref-per-plan design rests on the four seed families being
/// disjoint, so assert that directly.
#[test]
fn all_four_notes_coexist_under_one_ref() {
    let tmp = TempDir::new().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
    let bailiff = bailiff_repo(&tmp);
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

    let plan_id = PlanId::new();
    let plan_ref = plan_notes_ref(plan_id);

    // The decision note carries no envelope, so plant it directly
    // rather than dragging `write_decision_note`'s own contract in.
    let decision_target = bailiff
        .write_note(
            &plan_ref,
            &plan_decision_seed_blob_bytes(plan_id),
            b"decision-body",
        )
        .expect("decision plant must succeed");

    let staged: Vec<(AgentStage, GitObjectId)> = AgentStage::ALL
        .into_iter()
        .map(|stage| {
            let oid = write_stage_note(
                &bailiff,
                &target(stage, plan_id, writ_repo.path(), &allowed),
                &writ_notes_ref(),
                format!("plan-{stage}"),
                &completed,
            )
            .unwrap_or_else(|e| panic!("{stage} must write alongside the other notes: {e}"));
            (stage, oid)
        })
        .collect();

    let mut oids: Vec<GitObjectId> = staged.iter().map(|(_, o)| o.clone()).collect();
    oids.push(decision_target.clone());
    let mut deduped: Vec<String> = oids.iter().map(|o| o.to_string()).collect();
    deduped.sort();
    deduped.dedup();
    assert_eq!(
        deduped.len(),
        4,
        "the four seed families must be disjoint; got {oids:?}",
    );

    // Every one of the four is still readable, and still says what it
    // said. A collision that silently overwrote would show up here as
    // a wrong `purpose`, not merely as a missing note.
    assert_eq!(
        bailiff.read_note(&plan_ref, &decision_target).unwrap(),
        b"decision-body",
        "the decision body must survive three stage writes",
    );
    for (stage, oid) in staged {
        let body = bailiff
            .read_note(&plan_ref, &oid)
            .unwrap_or_else(|e| panic!("{stage} note must still be readable: {e}"));
        assert_eq!(
            decode(stage, &body).purpose,
            format!("plan-{stage}"),
            "{stage}"
        );
    }
}

/// A stage's note writes with **no other note present**: the write
/// helper enforces one invariant only (one note per plan-and-stage),
/// and ordering is the state machine's job under the plan lock.
///
/// Previously pinned as `does_not_require_pre_existing_submission` for
/// review and implement; it holds for all three, and stating it for
/// all three is what keeps a precondition from creeping back into the
/// write layer where the gate could not see it.
#[test]
fn any_stage_writes_with_no_other_note_present() {
    for stage in AgentStage::ALL {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let plan_id = PlanId::new();
        write_stage_note(
            &bailiff,
            &target(stage, plan_id, writ_repo.path(), &allowed),
            &writ_notes_ref(),
            "p".into(),
            &completed,
        )
        .unwrap_or_else(|e| panic!("{stage} must write with no other note present: {e}"));
    }
}
