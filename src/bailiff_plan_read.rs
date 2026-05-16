//! Bailiff-side read helpers for per-plan notes. Sibling to
//! [`crate::bailiff_plan_write`]: where the write helpers attach the
//! bailiff-owned notes a plan accumulates, the read helpers project
//! them back into typed Rust values.
//!
//! Slice D1.4 of `docs/plans/2026-05-16-slice-d1-decide.md` introduced
//! the decision read; slice D2.3 of
//! `docs/plans/2026-05-16-slice-d2-review.md` added the review read at
//! the third seed-OID; slice D2.4a of the same review plan adds the
//! submission read so the upcoming `submit_review` workflow (D2.4b,
//! the first real consumer) can fetch the planner's `writ_output_oid`
//! and resolve it back to a plan body. All three read helpers pin the
//! same seed-OID convention the matching writers use, so a round-trip
//! through the per-plan ref doesn't depend on any registry beyond the
//! deterministic seed bytes.

use thiserror::Error;

use crate::bailiff_plan_note::{
    DecisionNote, DecisionNoteParseError, PlanId, PlanNote, PlanNoteParseError, ReviewNote,
    ReviewNoteParseError, plan_decision_seed_blob_bytes, plan_notes_ref,
    plan_review_seed_blob_bytes, plan_submission_seed_blob_bytes,
};
use crate::notes_repo::{NotesRepo, NotesRepoError};

/// Read the decision note for `plan_id`, if one has been recorded.
/// Returns `Ok(None)` when no decision exists yet — both the
/// no-such-plan-id case (no notes ref for that plan) and the
/// plan-exists-but-undecided case (ref present, no annotation at the
/// decision seed's target OID) fold into the same `None` because both
/// mean "operator has not yet ruled on this plan."
///
/// Sibling to [`crate::bailiff_plan_write::write_decision_note`]: the
/// writer hashes [`plan_decision_seed_blob_bytes`] to pick the attach
/// OID, the reader hashes the same seed bytes to recover it, and
/// content-addressed storage makes the round-trip work without any
/// separate registry. The submission note ([`crate::bailiff_plan_note::PlanNote`])
/// is **not** consulted: D1 keeps decisions independently readable so
/// a future caller can ask "has this plan been decided?" without
/// gating on the submission being present.
pub fn read_decision_note(
    bailiff_repo: &NotesRepo,
    plan_id: PlanId,
) -> Result<Option<DecisionNote>, ReadDecisionError> {
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_decision_seed_blob_bytes(plan_id);
    let Some(body) = bailiff_repo
        .read_note_at_seed(&plan_ref, &seed)
        .map_err(ReadDecisionError::ReadNote)?
    else {
        return Ok(None);
    };
    let note = DecisionNote::from_canonical_bytes(&body).map_err(ReadDecisionError::Decode)?;
    if note.plan_id != plan_id {
        return Err(ReadDecisionError::PlanIdMismatch {
            requested: plan_id,
            found: note.plan_id,
        });
    }
    Ok(Some(note))
}

/// Tagged failure modes of [`read_decision_note`]. The two variants
/// distinguish "reading the bytes failed" from "bytes came back but
/// did not parse as a [`DecisionNote`]" so a caller can react
/// appropriately: the former is a filesystem or git problem
/// (operator-misconfigured repo path), the latter is on-disk
/// corruption or a schema regression.
#[derive(Debug, Error)]
pub enum ReadDecisionError {
    /// Reading the underlying note body from bailiff's repo failed
    /// for any reason other than absence. Absence (no decision yet)
    /// is folded into `Ok(None)` by [`read_decision_note`] and never
    /// surfaces here.
    #[error("reading the decision note from bailiff's repo failed: {0}")]
    ReadNote(#[source] NotesRepoError),
    /// The note body existed but did not parse as a
    /// [`DecisionNote`]. Indicates wire-level corruption — the
    /// canonical JSON shape is fixed and `deny_unknown_fields` plus
    /// the field-type validators make this near-impossible for any
    /// body [`crate::bailiff_plan_write::write_decision_note`] itself
    /// produced.
    #[error("decoding the decision note body failed: {0}")]
    Decode(#[source] DecisionNoteParseError),
    /// The note parsed cleanly but its embedded `plan_id` does not
    /// match the plan we were asked to read. Unreachable through
    /// [`crate::bailiff_plan_write::write_decision_note`] (which always
    /// derives the attach seed from `decision_note.plan_id`), so this
    /// surfaces only when bytes were planted via the low-level
    /// [`crate::notes_repo::NotesRepo::write_note`] path or pasted by
    /// hand after manual repo repair. Treat it as semantic corruption:
    /// a future acceptance gate must not be fooled into ruling on
    /// plan A by reading plan B's verdict.
    #[error(
        "decision note at plan {requested} carries embedded plan_id {found}; refusing to surface a cross-plan verdict"
    )]
    PlanIdMismatch { requested: PlanId, found: PlanId },
}

/// Read the review note for `plan_id`, if one has been recorded.
/// Returns `Ok(None)` when no review exists yet — both the
/// no-such-plan-id case (no notes ref for that plan) and the
/// plan-exists-but-unreviewed case (ref present, no annotation at the
/// review seed's target OID) fold into the same `None` because both
/// mean "writ has not produced a reviewer envelope for this plan."
///
/// Sibling to [`crate::bailiff_plan_write::write_review_note`]: the
/// writer hashes [`plan_review_seed_blob_bytes`] to pick the attach
/// OID, the reader hashes the same seed bytes to recover it, and
/// content-addressed storage makes the round-trip work without any
/// separate registry. Neither the submission nor the decision note is
/// consulted: D2 keeps reviews independently readable so a future
/// caller can ask "has this plan been reviewed?" without gating on
/// either of the other notes being present.
pub fn read_review_note(
    bailiff_repo: &NotesRepo,
    plan_id: PlanId,
) -> Result<Option<ReviewNote>, ReadReviewError> {
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_review_seed_blob_bytes(plan_id);
    let Some(body) = bailiff_repo
        .read_note_at_seed(&plan_ref, &seed)
        .map_err(ReadReviewError::ReadNote)?
    else {
        return Ok(None);
    };
    let note = ReviewNote::from_canonical_bytes(&body).map_err(ReadReviewError::Decode)?;
    if note.plan_id != plan_id {
        return Err(ReadReviewError::PlanIdMismatch {
            requested: plan_id,
            found: note.plan_id,
        });
    }
    Ok(Some(note))
}

/// Tagged failure modes of [`read_review_note`]. Same three-variant
/// shape as [`ReadDecisionError`]: filesystem/git read failure vs.
/// bytes-came-back-but-did-not-parse vs. semantic corruption
/// (cross-plan body planted under another plan's seed).
#[derive(Debug, Error)]
pub enum ReadReviewError {
    /// Reading the underlying note body from bailiff's repo failed
    /// for any reason other than absence. Absence (no review yet) is
    /// folded into `Ok(None)` by [`read_review_note`] and never
    /// surfaces here.
    #[error("reading the review note from bailiff's repo failed: {0}")]
    ReadNote(#[source] NotesRepoError),
    /// The note body existed but did not parse as a [`ReviewNote`].
    /// Indicates wire-level corruption — the canonical JSON shape is
    /// fixed and `deny_unknown_fields` plus the field-type validators
    /// make this near-impossible for any body
    /// [`crate::bailiff_plan_write::write_review_note`] itself produced.
    #[error("decoding the review note body failed: {0}")]
    Decode(#[source] ReviewNoteParseError),
    /// The note parsed cleanly but its embedded `plan_id` does not
    /// match the plan we were asked to read. Unreachable through
    /// [`crate::bailiff_plan_write::write_review_note`] (which always
    /// derives the attach seed from the `plan_id` argument it
    /// embeds in the note), so this surfaces only when bytes were
    /// planted via the low-level
    /// [`crate::notes_repo::NotesRepo::write_note`] path or pasted by
    /// hand after manual repo repair. Treat it as semantic corruption:
    /// a future reader rendering reviewer prose must not be fooled
    /// into displaying plan B's review when asked about plan A.
    #[error(
        "review note at plan {requested} carries embedded plan_id {found}; refusing to surface a cross-plan review"
    )]
    PlanIdMismatch { requested: PlanId, found: PlanId },
}

/// Read the submission note for `plan_id`, if one has been recorded.
/// Returns `Ok(None)` when no submission exists yet — both the
/// no-such-plan-id case (no notes ref for that plan) and the
/// plan-exists-but-not-submitted case (ref present, no annotation at
/// the submission seed's target OID) fold into the same `None`
/// because both mean "writ has not produced a planner envelope for
/// this plan yet."
///
/// Sibling to [`crate::bailiff_plan_write::write_plan_note`]: the
/// writer hashes [`plan_submission_seed_blob_bytes`] to pick the
/// attach OID, the reader hashes the same seed bytes to recover it,
/// and content-addressed storage makes the round-trip work without
/// any separate registry. Neither the decision nor the review note
/// is consulted: the submission stays independently readable so a
/// caller can ask "what planner envelope was submitted for this
/// plan?" without gating on the other two notes being present.
pub fn read_plan_note(
    bailiff_repo: &NotesRepo,
    plan_id: PlanId,
) -> Result<Option<PlanNote>, ReadPlanError> {
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_submission_seed_blob_bytes(plan_id);
    let Some(body) = bailiff_repo
        .read_note_at_seed(&plan_ref, &seed)
        .map_err(ReadPlanError::ReadNote)?
    else {
        return Ok(None);
    };
    let note = PlanNote::from_canonical_bytes(&body).map_err(ReadPlanError::Decode)?;
    if note.plan_id != plan_id {
        return Err(ReadPlanError::PlanIdMismatch {
            requested: plan_id,
            found: note.plan_id,
        });
    }
    Ok(Some(note))
}

/// Tagged failure modes of [`read_plan_note`]. Same three-variant
/// shape as [`ReadDecisionError`] / [`ReadReviewError`]:
/// filesystem/git read failure vs. bytes-came-back-but-did-not-parse
/// vs. semantic corruption (cross-plan body planted under another
/// plan's seed).
#[derive(Debug, Error)]
pub enum ReadPlanError {
    /// Reading the underlying note body from bailiff's repo failed
    /// for any reason other than absence. Absence (no submission
    /// yet) is folded into `Ok(None)` by [`read_plan_note`] and
    /// never surfaces here.
    #[error("reading the plan submission note from bailiff's repo failed: {0}")]
    ReadNote(#[source] NotesRepoError),
    /// The note body existed but did not parse as a [`PlanNote`].
    /// Indicates wire-level corruption — the canonical JSON shape is
    /// fixed and `deny_unknown_fields` plus the field-type validators
    /// make this near-impossible for any body
    /// [`crate::bailiff_plan_write::write_plan_note`] itself produced.
    #[error("decoding the plan submission note body failed: {0}")]
    Decode(#[source] PlanNoteParseError),
    /// The note parsed cleanly but its embedded `plan_id` does not
    /// match the plan we were asked to read. Unreachable through
    /// [`crate::bailiff_plan_write::write_plan_note`] (which always
    /// derives the attach seed from the `plan_id` argument it embeds
    /// in the note), so this surfaces only when bytes were planted
    /// via the low-level [`crate::notes_repo::NotesRepo::write_note`]
    /// path or pasted by hand after manual repo repair. Treat it as
    /// semantic corruption: the upcoming `submit_review` workflow
    /// must not be fooled into composing a reviewer prompt from
    /// plan B's body when asked about plan A.
    #[error(
        "plan submission note at plan {requested} carries embedded plan_id {found}; refusing to surface a cross-plan submission"
    )]
    PlanIdMismatch { requested: PlanId, found: PlanId },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bailiff_decision::{Decider, Decision};
    use crate::bailiff_plan_note::{
        DecisionNote, PlanId, plan_decision_seed_blob_bytes, plan_notes_ref,
        plan_submission_seed_blob_bytes,
    };
    use crate::bailiff_plan_write::write_decision_note;
    use crate::core::UnixMillis;
    use tempfile::TempDir;

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    fn sample_decision_note(plan_id: PlanId, outcome: Decision) -> DecisionNote {
        DecisionNote {
            plan_id,
            outcome,
            decider: Decider::try_new("cli:alice").unwrap(),
            decided_at: UnixMillis::from_millis(1_700_000_000_456),
        }
    }

    /// A plan with no decision note attached returns `Ok(None)`.
    /// Covers the fresh-repo case where the plan's notes ref does
    /// not exist at all — the most common state during normal
    /// operation (operator hasn't ruled on this plan yet).
    #[test]
    fn read_decision_note_returns_none_when_no_decision_recorded() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let result = read_decision_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None for an undecided plan, got: {result:?}"
        );
    }

    /// Load-bearing round-trip: writing a decision and reading it
    /// back recovers a byte-for-byte equal [`DecisionNote`]. Pins
    /// that the writer's seed-OID derivation matches the reader's
    /// — a divergence here would make every decision unrecoverable.
    #[test]
    fn read_decision_note_round_trips_through_write_decision_note() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let written = sample_decision_note(plan_id, Decision::Accepted);
        write_decision_note(&bailiff, &written).unwrap();

        let read_back = read_decision_note(&bailiff, plan_id).unwrap();
        assert_eq!(read_back.as_ref(), Some(&written));
    }

    /// Both outcomes round-trip — pin that the `Decision` enum's
    /// serde tagging stays compatible between writer and reader.
    /// A regression that flipped to a wrapped tagging
    /// (`{"outcome":{"Accepted":null}}`) would break readers writing
    /// the new shape against repos written by the old shape.
    #[test]
    fn read_decision_note_round_trips_both_outcomes() {
        for outcome in [Decision::Accepted, Decision::Rejected] {
            let tmp = TempDir::new().unwrap();
            let bailiff = bailiff_repo(&tmp);
            let plan_id = PlanId::new();
            let written = sample_decision_note(plan_id, outcome);
            write_decision_note(&bailiff, &written).unwrap();
            let read_back = read_decision_note(&bailiff, plan_id).unwrap();
            assert_eq!(read_back.as_ref(), Some(&written), "outcome {outcome:?}");
        }
    }

    /// A submission note alone is not a decision: `read_decision_note`
    /// must return `None` even when the plan's notes ref exists with
    /// a submission attached. Exercises the "ref present, no
    /// annotation at the decision seed's target" branch — the
    /// load-bearing read-side property the two-seeds-per-plan design
    /// exists to provide.
    #[test]
    fn read_decision_note_returns_none_when_only_submission_is_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        // Plant a submission-shaped note directly via `write_note`
        // — the body shape doesn't matter; we only care that the
        // submission's presence under the same ref doesn't fool the
        // decision reader into returning `Some(corrupt)`.
        let submission_seed = plan_submission_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &submission_seed, b"submission-body")
            .unwrap();

        let result = read_decision_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None with only submission present, got: {result:?}",
        );
    }

    /// Distinct plans don't cross-read: reading plan A's decision
    /// must not return plan B's. A regression that dropped `plan_id`
    /// from the ref derivation would silently make every plan share
    /// one decision; this test catches that by writing different
    /// outcomes to two plans and verifying each reader gets its own.
    #[test]
    fn read_decision_note_does_not_cross_read_between_plans() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let p1 = PlanId::new();
        let p2 = PlanId::new();
        write_decision_note(&bailiff, &sample_decision_note(p1, Decision::Accepted)).unwrap();
        write_decision_note(&bailiff, &sample_decision_note(p2, Decision::Rejected)).unwrap();

        let r1 = read_decision_note(&bailiff, p1).unwrap().unwrap();
        let r2 = read_decision_note(&bailiff, p2).unwrap().unwrap();
        assert_eq!(r1.plan_id, p1);
        assert_eq!(r1.outcome, Decision::Accepted);
        assert_eq!(r2.plan_id, p2);
        assert_eq!(r2.outcome, Decision::Rejected);
    }

    /// A semantically-corrupt body — one that parses cleanly as a
    /// `DecisionNote` but whose embedded `plan_id` belongs to a
    /// different plan — surfaces as `ReadDecisionError::PlanIdMismatch`
    /// rather than `Ok(Some(other_plans_decision))`. A future
    /// acceptance gate must never be fooled into ruling on plan A by
    /// reading plan B's verdict; the threat model has manual repo
    /// repair or a buggy low-level writer producing this state, and
    /// the read path is the right place to catch it because that's
    /// where the requested `plan_id` is in scope.
    #[test]
    fn read_decision_note_returns_plan_id_mismatch_when_body_carries_other_plan_id() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let queried = PlanId::new();
        let other = PlanId::new();
        assert_ne!(queried, other, "PlanId::new must not collide");

        // Plant a well-formed DecisionNote for `other` under `queried`'s
        // decision seed. The only way to reach this state is by
        // bypassing `write_decision_note` (which derives the seed from
        // `decision_note.plan_id`), so go through the low-level
        // `write_note` API directly.
        let queried_ref = plan_notes_ref(queried);
        let queried_seed = plan_decision_seed_blob_bytes(queried);
        let foreign_note = sample_decision_note(other, Decision::Accepted);
        bailiff
            .write_note(&queried_ref, &queried_seed, &foreign_note.canonical_bytes())
            .unwrap();

        let err = read_decision_note(&bailiff, queried).unwrap_err();
        match err {
            ReadDecisionError::PlanIdMismatch { requested, found } => {
                assert_eq!(requested, queried);
                assert_eq!(found, other);
            }
            other_err => panic!("expected PlanIdMismatch, got: {other_err:?}"),
        }
    }

    /// A corrupt body at the decision seed's target surfaces as
    /// `ReadDecisionError::Decode`, not as `Ok(None)` or as a
    /// generic `ReadNote` error. Construct the case by planting
    /// non-JSON bytes directly via `NotesRepo::write_note` at the
    /// decision seed — bypassing `write_decision_note` is the only
    /// way to produce this state in practice (the writer always
    /// produces canonical bytes), but the read-side must still
    /// classify it correctly.
    #[test]
    fn read_decision_note_returns_decode_error_on_corrupt_body() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);
        let decision_seed = plan_decision_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &decision_seed, b"not json at all")
            .unwrap();

        let err = read_decision_note(&bailiff, plan_id).unwrap_err();
        assert!(
            matches!(err, ReadDecisionError::Decode(_)),
            "expected Decode error, got: {err:?}",
        );
    }
}

#[cfg(test)]
mod review_tests {
    //! Tests for [`read_review_note`] — the slice D2.3 read counterpart
    //! to [`crate::bailiff_plan_write::write_review_note`]. The
    //! load-bearing round-trip test drives the actual writer so a
    //! future refactor that drifts the writer's seed-OID derivation
    //! from the reader's surfaces here; the remaining tests plant
    //! bodies directly via the low-level [`NotesRepo::write_note`] to
    //! avoid the broker setup the writer would otherwise require.
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_plan_note::{
        PlanId, ReviewNote, plan_notes_ref, plan_review_seed_blob_bytes,
        plan_submission_seed_blob_bytes,
    };
    use crate::bailiff_plan_write::write_review_note;
    use crate::core::{CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::run_verify::AllowedSigners;
    use crate::signing::WritSigningKey;
    use crate::vm_git::GitObjectId;
    use crate::writ_client::RunAgentCompleted;
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    fn writ_notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    /// Build a freshly-signed envelope under `signing_key`. Mirrors
    /// the same-named helper in `bailiff_plan_write::review_tests` so
    /// the envelope shape matches what writ produces today.
    fn freshly_signed(signing_key: &WritSigningKey) -> SignedRunEnvelope {
        let output = OutputEnvelope {
            stdout: b"reviewer prose".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let output_bytes = output.to_bytes();
        let output_sha = Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap();
        let prompt_sha = Sha256Hex::try_new(sha256_hex(b"reviewer-prompt")).unwrap();
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
}

#[cfg(test)]
mod plan_tests {
    //! Tests for [`read_plan_note`] — the slice D2.4a read counterpart
    //! to [`crate::bailiff_plan_write::write_plan_note`]. The
    //! load-bearing round-trip test drives the actual writer so a
    //! future refactor that drifts the writer's seed-OID derivation
    //! from the reader's surfaces here; the remaining tests plant
    //! bodies directly via the low-level [`NotesRepo::write_note`] to
    //! avoid the broker setup the writer would otherwise require.
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_plan_note::{
        PlanId, PlanNote, plan_decision_seed_blob_bytes, plan_notes_ref,
        plan_review_seed_blob_bytes, plan_submission_seed_blob_bytes,
    };
    use crate::bailiff_plan_write::write_plan_note;
    use crate::core::{CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::run_verify::AllowedSigners;
    use crate::signing::WritSigningKey;
    use crate::vm_git::GitObjectId;
    use crate::writ_client::RunAgentCompleted;
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    fn writ_notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    /// Build a freshly-signed envelope under `signing_key`. Mirrors
    /// the same-named helper in `bailiff_plan_write::tests` so the
    /// envelope shape matches what writ produces today.
    fn freshly_signed(signing_key: &WritSigningKey) -> SignedRunEnvelope {
        let output = OutputEnvelope {
            stdout: b"planner prose".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
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

    /// Stand up a writ repo containing one signed envelope and return
    /// the `RunAgentCompleted` reply bailiff would have seen, so the
    /// round-trip test can drive `write_plan_note` end-to-end.
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

    /// Plant a ready-made [`PlanNote`] directly at its submission seed
    /// via the low-level [`NotesRepo::write_note`] API. Used by tests
    /// that don't need to exercise the full fetch-verify-attach path
    /// of [`write_plan_note`] — e.g. cross-plan reads, decode failures.
    fn plant_plan_note(bailiff: &NotesRepo, plan_id: PlanId, note: &PlanNote) -> GitObjectId {
        let plan_ref = plan_notes_ref(plan_id);
        let seed = plan_submission_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &seed, &note.canonical_bytes())
            .unwrap()
    }

    fn sample_plan_note(plan_id: PlanId) -> PlanNote {
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let envelope = freshly_signed(&signing_key);
        PlanNote {
            plan_id,
            purpose: "plan-submission".into(),
            writ_output_oid: GitObjectId::new("d".repeat(40)).unwrap(),
            signed_metadata: envelope.metadata,
            signature: envelope.signature,
        }
    }

    /// A plan with no submission note attached returns `Ok(None)`.
    /// Covers the fresh-repo case where the plan's notes ref does
    /// not exist at all — the most common state during normal
    /// operation (writ has not produced a planner envelope yet).
    #[test]
    fn read_plan_note_returns_none_when_no_submission_recorded() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let result = read_plan_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None for an unsubmitted plan, got: {result:?}",
        );
    }

    /// Load-bearing round-trip: driving the real
    /// [`write_plan_note`] then reading back via [`read_plan_note`]
    /// recovers a byte-for-byte equal [`PlanNote`]. Pins that the
    /// writer's seed-OID derivation matches the reader's — a
    /// divergence here would make every submission unrecoverable.
    #[test]
    fn read_plan_note_round_trips_through_write_plan_note() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let plan_id = PlanId::new();
        let purpose = "plan-submission".to_string();
        write_plan_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            plan_id,
            purpose.clone(),
            &completed,
            &allowed,
        )
        .expect("write_plan_note must succeed");

        let read_back = read_plan_note(&bailiff, plan_id)
            .expect("read_plan_note must succeed")
            .expect("read_plan_note must return Some after a successful write");
        assert_eq!(read_back.plan_id, plan_id);
        assert_eq!(read_back.purpose, purpose);
        assert_eq!(read_back.writ_output_oid, completed.output_oid);
        assert_eq!(read_back.signed_metadata, completed.signed_metadata);
        assert_eq!(read_back.signature, completed.signature);
    }

    /// A decision note alone is not a submission: `read_plan_note`
    /// must return `None` even when the plan's notes ref exists with
    /// a decision attached. Exercises the "ref present, no
    /// annotation at the submission seed's target" branch — the
    /// load-bearing read-side property the three-seeds-per-plan
    /// design exists to provide. Without this, a future suffix
    /// collision between `::decision` and the bare-`plan_id`
    /// submission seed would silently make every decision read as a
    /// submission.
    #[test]
    fn read_plan_note_returns_none_when_only_decision_is_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        let decision_seed = plan_decision_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &decision_seed, b"decision-body")
            .unwrap();

        let result = read_plan_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None with only decision present, got: {result:?}",
        );
    }

    /// A review note alone is not a submission either. Same
    /// coexistence property as the decision case but for the third
    /// seed pair: a future suffix collision between `::review` and
    /// the bare-`plan_id` submission seed would silently make every
    /// review read as a submission.
    #[test]
    fn read_plan_note_returns_none_when_only_review_is_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        let review_seed = plan_review_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &review_seed, b"review-body")
            .unwrap();

        let result = read_plan_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None with only review present, got: {result:?}",
        );
    }

    /// Distinct plans don't cross-read: reading plan A's submission
    /// must not return plan B's. A regression that dropped `plan_id`
    /// from the ref derivation would silently make every plan share
    /// one submission; this test catches that by planting different
    /// purposes for two plans and verifying each reader gets its own.
    #[test]
    fn read_plan_note_does_not_cross_read_between_plans() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let p1 = PlanId::new();
        let p2 = PlanId::new();
        let mut note1 = sample_plan_note(p1);
        note1.purpose = "first".into();
        let mut note2 = sample_plan_note(p2);
        note2.purpose = "second".into();
        plant_plan_note(&bailiff, p1, &note1);
        plant_plan_note(&bailiff, p2, &note2);

        let r1 = read_plan_note(&bailiff, p1).unwrap().unwrap();
        let r2 = read_plan_note(&bailiff, p2).unwrap().unwrap();
        assert_eq!(r1.plan_id, p1);
        assert_eq!(r1.purpose, "first");
        assert_eq!(r2.plan_id, p2);
        assert_eq!(r2.purpose, "second");
    }

    /// A semantically-corrupt body — one that parses cleanly as a
    /// [`PlanNote`] but whose embedded `plan_id` belongs to a
    /// different plan — surfaces as `ReadPlanError::PlanIdMismatch`
    /// rather than `Ok(Some(other_plans_submission))`. The upcoming
    /// `submit_review` workflow (D2.4b) resolves the submission's
    /// `writ_output_oid` to fetch the planner envelope; if a foreign
    /// plan's submission slipped past this check, the reviewer
    /// prompt for plan A would carry plan B's body. The threat model
    /// has manual repo repair or a buggy low-level writer producing
    /// this state, and the read path is the right place to catch it
    /// because that's where the requested `plan_id` is in scope.
    #[test]
    fn read_plan_note_returns_plan_id_mismatch_when_body_carries_other_plan_id() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let queried = PlanId::new();
        let other = PlanId::new();
        assert_ne!(queried, other, "PlanId::new must not collide");

        // Plant a well-formed PlanNote for `other` under `queried`'s
        // submission seed. The only way to reach this state is by
        // bypassing `write_plan_note` (which derives the seed from
        // the `plan_id` it embeds in the note), so go through the
        // low-level `write_note` API.
        let queried_ref = plan_notes_ref(queried);
        let queried_seed = plan_submission_seed_blob_bytes(queried);
        let foreign_note = sample_plan_note(other);
        bailiff
            .write_note(&queried_ref, &queried_seed, &foreign_note.canonical_bytes())
            .unwrap();

        let err = read_plan_note(&bailiff, queried).unwrap_err();
        match err {
            ReadPlanError::PlanIdMismatch { requested, found } => {
                assert_eq!(requested, queried);
                assert_eq!(found, other);
            }
            other_err => panic!("expected PlanIdMismatch, got: {other_err:?}"),
        }
    }

    /// A corrupt body at the submission seed's target surfaces as
    /// `ReadPlanError::Decode`, not as `Ok(None)` or as a generic
    /// `ReadNote` error. Construct the case by planting non-JSON
    /// bytes directly via `NotesRepo::write_note` at the submission
    /// seed — bypassing `write_plan_note` is the only way to produce
    /// this state in practice (the writer always produces canonical
    /// bytes), but the read-side must still classify it correctly.
    #[test]
    fn read_plan_note_returns_decode_error_on_corrupt_body() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);
        let submission_seed = plan_submission_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &submission_seed, b"not json at all")
            .unwrap();

        let err = read_plan_note(&bailiff, plan_id).unwrap_err();
        assert!(
            matches!(err, ReadPlanError::Decode(_)),
            "expected Decode error, got: {err:?}",
        );
    }
}
