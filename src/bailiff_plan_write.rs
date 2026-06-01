//! Bailiff-side write helper that completes the slice-C handshake:
//! fetch writ's signed envelope, verify it, and persist a [`PlanNote`]
//! at the plan's notes ref in bailiff's own bare repo.
//!
//! This is slice C2 of `docs/plans/2026-05-14-bailiff-split.md`. The
//! data layer ([`crate::bailiff_plan_note`]) is slice C1; the CLI
//! verb that drives this helper is slice C3.
//!
//! # Flow
//!
//! Given a [`RunAgentCompleted`] (what writ returned over the
//! Unix-socket RPC) and a path to writ's bare repo:
//!
//! 1. `git fetch` writ's `refs/notes/writ/v1/*` namespace into
//!    bailiff's own repo via [`NotesRepo::fetch_from_remote`].
//! 2. Read the note body at `completed.output_oid` under
//!    `writ_notes_ref` — the same ref bailiff named in the
//!    `RunAgent` request — and decode it as a
//!    [`SignedRunEnvelope`].
//! 3. **Defence in depth:** check the envelope's metadata and
//!    signature match `completed`'s. If writ replies one thing on
//!    the wire and stores another in its notes ref, that's writ
//!    equivocating (or one of the two sources is corrupt) — both
//!    are operator-actionable, not silently recoverable.
//! 4. Run [`verify_run_envelope`] under `allowed_signers`. This
//!    rebinds the output bytes to the metadata digest and verifies
//!    the SSHSIG under bailiff's keyring — the same end-to-end
//!    check the slice-B5 round-trip pinned.
//! 5. Build a [`PlanNote`] referencing `completed.output_oid` (the
//!    writ-side seed OID — *not* the envelope blob; see the
//!    `writ_output_oid` docstring in [`crate::bailiff_plan_note`])
//!    and write it to [`plan_notes_ref`]`(plan_id)` in
//!    bailiff's repo with seed [`plan_submission_seed_blob_bytes`]`(plan_id)`.
//!    Returns the bailiff-side target OID.
//!
//! Every failure mode is a tagged variant of [`WritePlanNoteError`]
//! so the slice-C3 CLI verb can react without parsing prose.

use std::path::Path;

use thiserror::Error;

use crate::bailiff_plan_note::{
    DecisionNote, ImplementNote, PlanId, PlanNote, ReviewNote, plan_decision_seed_blob_bytes,
    plan_implement_seed_blob_bytes, plan_notes_ref, plan_review_seed_blob_bytes,
    plan_submission_seed_blob_bytes,
};
use crate::core::NotesRef;
use crate::notes_repo::{NotesRepo, NotesRepoError, WriteOutcome};
use crate::run_envelope::SignedRunEnvelope;
use crate::run_verify::{AllowedSigners, VerifyError, verify_run_envelope};
use crate::vm_git::GitObjectId;
use crate::writ_client::RunAgentCompleted;

/// Refspec bailiff uses to mirror writ's `v1` notes namespace into
/// its own repo. The leading `+` is load-bearing: writ may rewrite
/// history under its own ref (e.g. when slice G strips the legacy
/// `agent_plan` namespace), and bailiff is the local read mirror —
/// accepting forced updates is correct because writ is the source of
/// truth for its own namespace.
pub(crate) const WRIT_V1_NOTES_REFSPEC: &str = "+refs/notes/writ/v1/*:refs/notes/writ/v1/*";

/// Fetch writ's `v1` notes namespace into bailiff's repo, read the
/// signed envelope writ stored at `completed.output_oid` under
/// `writ_notes_ref`, and verify it end-to-end. Returns the verified
/// [`SignedRunEnvelope`].
///
/// This is the fetch→verify phase shared byte-for-byte by
/// [`write_plan_note`], [`write_review_note`], and
/// [`write_implement_note`]; only the subsequent attach — note type,
/// seed, and storage policy — differs between the three verbs. See the
/// module docstring for the step-by-step flow and [`FetchVerifyError`]
/// for the failure shape.
fn fetch_and_verify(
    bailiff_repo: &NotesRepo,
    writ_repo_path: &Path,
    writ_notes_ref: &NotesRef,
    completed: &RunAgentCompleted,
    allowed_signers: &AllowedSigners,
) -> Result<SignedRunEnvelope, FetchVerifyError> {
    bailiff_repo
        .fetch_from_remote(writ_repo_path, &[WRIT_V1_NOTES_REFSPEC])
        .map_err(FetchVerifyError::Fetch)?;
    let body = bailiff_repo
        .read_note(writ_notes_ref, &completed.output_oid)
        .map_err(FetchVerifyError::ReadEnvelope)?;
    let envelope =
        SignedRunEnvelope::from_bytes(&body).map_err(FetchVerifyError::DecodeEnvelope)?;

    if envelope.metadata != completed.signed_metadata {
        return Err(FetchVerifyError::EnvelopeMetadataMismatch);
    }
    if envelope.signature != completed.signature {
        return Err(FetchVerifyError::EnvelopeSignatureMismatch);
    }

    verify_run_envelope(&envelope, allowed_signers).map_err(FetchVerifyError::Verify)?;
    Ok(envelope)
}

/// Tagged failure modes of [`fetch_and_verify`] — the fetch→read→
/// decode→parity-check→verify phase that precedes the attach in
/// [`write_plan_note`], [`write_review_note`], and
/// [`write_implement_note`]. Each verb's error type embeds this via a
/// transparent `FetchVerify` variant, so the six pre-storage failure
/// modes are named once rather than copied per verb. Each maps to one
/// specific step so a caller can surface the right operator action:
/// "writ repo path wrong" vs "fetched but no such note" vs "envelope
/// and reply disagree" vs "signature doesn't verify" are all different
/// problems.
#[derive(Debug, Error)]
pub enum FetchVerifyError {
    /// `git fetch` against writ's repo failed. Usually a wrong
    /// `writ_repo_path` or filesystem permission problem.
    #[error("fetching writ's notes ref failed: {0}")]
    Fetch(#[source] NotesRepoError),
    /// The fetch succeeded but no note exists at
    /// `completed.output_oid` under `writ_notes_ref`. Either the
    /// fetch refspec didn't cover the ref writ used, or writ's note
    /// hasn't propagated yet (a race the synchronous-reply RPC
    /// contract forecloses, but the variant exists so the failure is
    /// named rather than swallowed).
    #[error("reading the writ envelope note failed: {0}")]
    ReadEnvelope(#[source] NotesRepoError),
    /// The note body exists but isn't a valid [`SignedRunEnvelope`].
    /// Indicates wire-level corruption — `deny_unknown_fields` and
    /// the strict newtype validators on the envelope make this
    /// near-impossible for any envelope writ itself produced.
    #[error("decoding the writ envelope failed: {0}")]
    DecodeEnvelope(#[source] serde_json::Error),
    /// The envelope's `metadata` in writ's repo differs from the
    /// `signed_metadata` writ returned in [`RunAgentCompleted`].
    /// Writ is either equivocating or one of the two sources is
    /// corrupt; bailiff refuses to attach a note in either case.
    #[error(
        "envelope metadata fetched from writ's repo does not match the metadata writ \
         returned in RunAgentCompleted"
    )]
    EnvelopeMetadataMismatch,
    /// Same defence-in-depth check as [`Self::EnvelopeMetadataMismatch`]
    /// but for the signature field.
    #[error(
        "envelope signature fetched from writ's repo does not match the signature writ \
         returned in RunAgentCompleted"
    )]
    EnvelopeSignatureMismatch,
    /// [`verify_run_envelope`] rejected the envelope. The wrapped
    /// [`VerifyError`] names whether the failure was an output
    /// digest mismatch, an unknown signer, or a bad signature.
    #[error("verifying the fetched envelope failed: {0}")]
    Verify(#[source] VerifyError),
}

/// Fetch writ's signed envelope, verify it end-to-end, and attach a
/// [`PlanNote`] for `plan_id` to bailiff's per-plan notes ref.
///
/// Returns the bailiff-side target OID — the deterministic seed-blob
/// OID that [`plan_submission_seed_blob_bytes`] hashes to, which a caller can
/// hold onto for diagnostics or to read the freshly-written note back
/// without recomputing it.
///
/// See the module docstring for the step-by-step flow and the
/// [`WritePlanNoteError`] variants for the failure shape.
pub fn write_plan_note(
    bailiff_repo: &NotesRepo,
    writ_repo_path: &Path,
    writ_notes_ref: &NotesRef,
    plan_id: PlanId,
    purpose: String,
    completed: &RunAgentCompleted,
    allowed_signers: &AllowedSigners,
) -> Result<GitObjectId, WritePlanNoteError> {
    let envelope = fetch_and_verify(
        bailiff_repo,
        writ_repo_path,
        writ_notes_ref,
        completed,
        allowed_signers,
    )?;

    let note = PlanNote {
        plan_id,
        purpose,
        writ_output_oid: completed.output_oid.clone(),
        signed_metadata: envelope.metadata,
        signature: envelope.signature,
    };
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_submission_seed_blob_bytes(plan_id);
    let bytes = note.canonical_bytes();
    bailiff_repo
        .write_note(&plan_ref, &seed, &bytes)
        .map_err(WritePlanNoteError::WritePlanNote)
}

/// Tagged failure modes of [`write_plan_note`]. The shared
/// fetch→verify phase's failures arrive via the transparent
/// [`FetchVerifyError`] embedded in [`Self::FetchVerify`]; only the
/// plan-note write itself is specific to this verb.
#[derive(Debug, Error)]
pub enum WritePlanNoteError {
    /// The shared fetch→verify phase failed before any plan note was
    /// written. See [`FetchVerifyError`] for the step-by-step matrix.
    #[error(transparent)]
    FetchVerify(#[from] FetchVerifyError),
    /// Writing the bailiff-side plan note failed. Usually a
    /// duplicate-write (a plan id reused against an existing ref) or
    /// a filesystem problem.
    #[error("writing the plan note to bailiff's repo failed: {0}")]
    WritePlanNote(#[source] NotesRepoError),
}

/// Write `decision_note` as the **decision** note for its plan under
/// [`plan_notes_ref`]`(plan_id)` in bailiff's repo. Slice D1.3 of
/// `docs/plans/2026-05-16-slice-d1-decide.md`.
///
/// Idempotent-by-error: if a decision note already exists for the
/// plan, returns [`WriteDecisionNoteError::DecisionAlreadyRecorded`]
/// rather than overwriting. The operator workflow for "I want to
/// change my mind" is "the plan is dead, submit a new one," so
/// silently overwriting an existing verdict would destroy audit
/// state without surfacing the conflict.
///
/// Sibling to [`write_plan_note`] under the same per-plan notes
/// ref: the decision attaches at the seed OID derived from
/// [`plan_decision_seed_blob_bytes`] so the submission and decision
/// notes coexist without colliding. The submission's presence is
/// **not** a precondition — D1 keeps the decide verb usable against
/// any plan id whose write helper hasn't reached the submission step
/// yet, on the grounds that a typed `DecisionAlreadyRecorded` is the
/// only invariant worth enforcing at this layer.
///
/// Returns the bailiff-side target OID — the deterministic seed-blob
/// OID [`plan_decision_seed_blob_bytes`] hashes to — so a caller can
/// hand it to [`NotesRepo::read_note`] without recomputing it.
pub fn write_decision_note(
    bailiff_repo: &NotesRepo,
    decision_note: &DecisionNote,
) -> Result<GitObjectId, WriteDecisionNoteError> {
    let plan_id = decision_note.plan_id;
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_decision_seed_blob_bytes(plan_id);
    let body = decision_note.canonical_bytes();
    match bailiff_repo
        .write_note_if_absent(&plan_ref, &seed, &body)
        .map_err(WriteDecisionNoteError::WriteDecisionNote)?
    {
        WriteOutcome::Written(oid) => Ok(oid),
        WriteOutcome::AlreadyPresent(target_oid) => {
            Err(WriteDecisionNoteError::DecisionAlreadyRecorded {
                plan_id,
                target_oid,
            })
        }
    }
}

/// Tagged failure modes of [`write_decision_note`]. The
/// `DecisionAlreadyRecorded` variant is the load-bearing one:
/// idempotent-by-error storage means a duplicate decide call must be
/// distinguishable from a generic git failure so the CLI verb can
/// emit a stable exit code for "this plan already has a verdict."
#[derive(Debug, Error)]
pub enum WriteDecisionNoteError {
    /// A decision note for this plan already exists under
    /// [`plan_notes_ref`]`(plan_id)` at `target_oid`. D1 does not
    /// overwrite; the operator's recourse is to submit a fresh plan.
    #[error("decision already recorded for plan {plan_id} at target {target_oid}")]
    DecisionAlreadyRecorded {
        plan_id: PlanId,
        target_oid: GitObjectId,
    },
    /// Writing the decision note to bailiff's repo failed for any
    /// reason other than the idempotency conflict. Usually a
    /// filesystem problem or a cross-process race that slipped past
    /// the per-repo mutex (see [`NotesRepo::write_note_if_absent`]'s
    /// docstring for the residual race surface).
    #[error("writing the decision note to bailiff's repo failed: {0}")]
    WriteDecisionNote(#[source] NotesRepoError),
}

/// Fetch writ's signed envelope for a reviewer run, verify it
/// end-to-end, and attach a [`ReviewNote`] for `plan_id` to bailiff's
/// per-plan notes ref. Slice D2.2 of
/// `docs/plans/2026-05-16-slice-d2-review.md`.
///
/// Same fetch-verify-attach shape as [`write_plan_note`] — the
/// envelope-vs-reply metadata/signature parity check and the
/// `verify_run_envelope` pass are byte-for-byte identical. The
/// load-bearing difference is the storage primitive: review notes are
/// **idempotent by error**. A second review for the same `plan_id`
/// returns [`WriteReviewNoteError::ReviewAlreadyRecorded`] rather than
/// overwriting, mirroring [`write_decision_note`]'s
/// `DecisionAlreadyRecorded` contract. D2 ships single-review-per-plan;
/// multi-review history is the documented `v1` → `v2` ref-prefix bump
/// (see the slice-D2 plan doc).
///
/// The review note attaches under
/// [`plan_notes_ref`]`(plan_id)` at the seed OID derived from
/// [`plan_review_seed_blob_bytes`], distinct from the submission seed
/// (bare plan id) and the decision seed (`::decision` suffix), so the
/// three notes coexist under one per-plan ref.
///
/// **No precondition on submission presence.** Mirrors D1.3's decoupling
/// of decide from submission: the only invariant the write helper
/// enforces is "one review per plan." The submission-presence gate
/// lives in the slice-D2.4 `submit_review` workflow, where the plan
/// body is consumed for prompt composition.
///
/// Returns the bailiff-side target OID — the deterministic seed-blob
/// OID [`plan_review_seed_blob_bytes`] hashes to — so a caller can
/// hand it to [`NotesRepo::read_note`] without recomputing it.
pub fn write_review_note(
    bailiff_repo: &NotesRepo,
    writ_repo_path: &Path,
    writ_notes_ref: &NotesRef,
    plan_id: PlanId,
    purpose: String,
    completed: &RunAgentCompleted,
    allowed_signers: &AllowedSigners,
) -> Result<GitObjectId, WriteReviewNoteError> {
    let envelope = fetch_and_verify(
        bailiff_repo,
        writ_repo_path,
        writ_notes_ref,
        completed,
        allowed_signers,
    )?;

    let note = ReviewNote {
        plan_id,
        purpose,
        writ_output_oid: completed.output_oid.clone(),
        signed_metadata: envelope.metadata,
        signature: envelope.signature,
    };
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_review_seed_blob_bytes(plan_id);
    let bytes = note.canonical_bytes();
    match bailiff_repo
        .write_note_if_absent(&plan_ref, &seed, &bytes)
        .map_err(WriteReviewNoteError::WriteReviewNote)?
    {
        WriteOutcome::Written(oid) => Ok(oid),
        WriteOutcome::AlreadyPresent(target_oid) => {
            Err(WriteReviewNoteError::ReviewAlreadyRecorded {
                plan_id,
                target_oid,
            })
        }
    }
}

/// Tagged failure modes of [`write_review_note`]. The shared
/// fetch→verify phase's failures arrive via the transparent
/// [`FetchVerifyError`] in [`Self::FetchVerify`]; the two storage
/// variants are specific to this verb's idempotent-by-error write
/// (`ReviewAlreadyRecorded` distinct from a generic `WriteReviewNote`).
#[derive(Debug, Error)]
pub enum WriteReviewNoteError {
    /// The shared fetch→verify phase failed before any review note was
    /// written. See [`FetchVerifyError`] for the step-by-step matrix.
    #[error(transparent)]
    FetchVerify(#[from] FetchVerifyError),
    /// A review note for this plan already exists under
    /// [`plan_notes_ref`]`(plan_id)` at `target_oid`. D2 does not
    /// overwrite; the operator's recourse is to submit a fresh plan
    /// (multi-review history is a future `v1` → `v2` migration).
    #[error("review already recorded for plan {plan_id} at target {target_oid}")]
    ReviewAlreadyRecorded {
        plan_id: PlanId,
        target_oid: GitObjectId,
    },
    /// Writing the review note to bailiff's repo failed for any
    /// reason other than the idempotency conflict. Usually a
    /// filesystem problem or a cross-process race that slipped past
    /// the per-repo mutex (see [`NotesRepo::write_note_if_absent`]'s
    /// docstring for the residual race surface).
    #[error("writing the review note to bailiff's repo failed: {0}")]
    WriteReviewNote(#[source] NotesRepoError),
}

/// Fetch writ's signed envelope for an implementer run, verify it
/// end-to-end, and attach an [`ImplementNote`] for `plan_id` to
/// bailiff's per-plan notes ref. Slice E2 of
/// `docs/plans/2026-05-14-bailiff-split.md`.
///
/// Same fetch-verify-attach shape as [`write_plan_note`] and
/// [`write_review_note`] — the envelope-vs-reply metadata/signature
/// parity check and the `verify_run_envelope` pass are byte-for-byte
/// identical. The load-bearing difference is the seed: implement
/// notes attach under [`plan_notes_ref`]`(plan_id)` at the seed OID
/// derived from [`plan_implement_seed_blob_bytes`], disjoint from the
/// submission, decision, and review seeds so all four notes coexist
/// under one per-plan ref.
///
/// **Idempotent by error.** A second implement-note write for the
/// same `plan_id` returns
/// [`WriteImplementNoteError::ImplementAlreadyRecorded`] rather than
/// overwriting, mirroring the [`WriteReviewNoteError::ReviewAlreadyRecorded`]
/// and [`WriteDecisionNoteError::DecisionAlreadyRecorded`] contracts.
/// Slice E ships single-implement-per-plan; multi-attempt history is
/// the documented `v1` → `v2` ref-prefix bump.
///
/// **No precondition on submission, decision, or review presence.**
/// Mirrors the decoupling baked into [`write_review_note`] and
/// [`write_decision_note`]: the only invariant the write helper
/// enforces is "one implement per plan." The acceptance gate (a
/// plan note must exist and have an `Accepted` decision note) lives
/// in the slice-E4 `submit_implement` workflow, where the plan body
/// is consumed for implementer prompt composition.
///
/// Returns the bailiff-side target OID — the deterministic seed-blob
/// OID [`plan_implement_seed_blob_bytes`] hashes to — so a caller can
/// hand it to [`NotesRepo::read_note`] without recomputing it.
pub fn write_implement_note(
    bailiff_repo: &NotesRepo,
    writ_repo_path: &Path,
    writ_notes_ref: &NotesRef,
    plan_id: PlanId,
    purpose: String,
    completed: &RunAgentCompleted,
    allowed_signers: &AllowedSigners,
) -> Result<GitObjectId, WriteImplementNoteError> {
    let envelope = fetch_and_verify(
        bailiff_repo,
        writ_repo_path,
        writ_notes_ref,
        completed,
        allowed_signers,
    )?;

    let note = ImplementNote {
        plan_id,
        purpose,
        writ_output_oid: completed.output_oid.clone(),
        signed_metadata: envelope.metadata,
        signature: envelope.signature,
    };
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_implement_seed_blob_bytes(plan_id);
    let bytes = note.canonical_bytes();
    match bailiff_repo
        .write_note_if_absent(&plan_ref, &seed, &bytes)
        .map_err(WriteImplementNoteError::WriteImplementNote)?
    {
        WriteOutcome::Written(oid) => Ok(oid),
        WriteOutcome::AlreadyPresent(target_oid) => {
            Err(WriteImplementNoteError::ImplementAlreadyRecorded {
                plan_id,
                target_oid,
            })
        }
    }
}

/// Tagged failure modes of [`write_implement_note`]. Shape parallels
/// [`WriteReviewNoteError`]: the shared fetch→verify phase's failures
/// arrive via the transparent [`FetchVerifyError`] in
/// [`Self::FetchVerify`], and the idempotent-by-error storage primitive
/// (`ImplementAlreadyRecorded` distinct from a generic
/// `WriteImplementNote`) mirrors [`WriteReviewNoteError`] and
/// [`WriteDecisionNoteError`].
#[derive(Debug, Error)]
pub enum WriteImplementNoteError {
    /// The shared fetch→verify phase failed before any implement note
    /// was written. See [`FetchVerifyError`] for the step-by-step matrix.
    #[error(transparent)]
    FetchVerify(#[from] FetchVerifyError),
    /// An implement note for this plan already exists under
    /// [`plan_notes_ref`]`(plan_id)` at `target_oid`. Slice E does not
    /// overwrite; the operator's recourse is to submit a fresh plan
    /// (multi-attempt implement history is a future `v1` → `v2`
    /// migration).
    #[error("implement already recorded for plan {plan_id} at target {target_oid}")]
    ImplementAlreadyRecorded {
        plan_id: PlanId,
        target_oid: GitObjectId,
    },
    /// Writing the implement note to bailiff's repo failed for any
    /// reason other than the idempotency conflict. Usually a
    /// filesystem problem or a cross-process race that slipped past
    /// the per-repo mutex (see [`NotesRepo::write_note_if_absent`]'s
    /// docstring for the residual race surface).
    #[error("writing the implement note to bailiff's repo failed: {0}")]
    WriteImplementNote(#[source] NotesRepoError),
}

#[cfg(test)]
mod tests {
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
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_plan_note::{
        PlanId, PlanNote, plan_notes_ref, plan_submission_seed_blob_bytes,
    };
    use crate::core::{CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::signing::{WritSigningKey, WritVerifyingKey};
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");
    const OTHER_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing_other.key.pub");

    fn writ_notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    /// Build a freshly-signed envelope under `signing_key`. Mirrors
    /// the `freshly_signed` helper in `run_verify.rs` tests so the
    /// envelope shape is the realistic one writ produces.
    fn freshly_signed(signing_key: &WritSigningKey) -> SignedRunEnvelope {
        let output = OutputEnvelope {
            stdout: b"hello".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let output_bytes = output.to_bytes();
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
        SignedRunEnvelope {
            metadata,
            signature,
            output: output_bytes,
        }
    }

    /// Prepare a writ repo containing one signed envelope keyed on the
    /// run id, exactly the shape writ's `RunAgent` handler produces.
    /// Returns the writ repo, the `RunAgentCompleted` reply bailiff
    /// would have seen, and the envelope itself for tampering tests.
    fn writ_repo_with_envelope(
        tmp: &TempDir,
        signing_key: &WritSigningKey,
    ) -> (NotesRepo, RunAgentCompleted, SignedRunEnvelope) {
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let nref = writ_notes_ref();
        let envelope = freshly_signed(signing_key);
        let body = envelope.to_bytes();
        let target = writ_repo
            .write_note(
                &nref,
                envelope.metadata.run_id.to_string().as_bytes(),
                &body,
            )
            .unwrap();
        let completed = RunAgentCompleted {
            output_oid: target,
            signed_metadata: envelope.metadata.clone(),
            signature: envelope.signature.clone(),
        };
        (writ_repo, completed, envelope)
    }

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

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
        completed.signature = crate::core::SshSignature::try_new(
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
            WritePlanNoteError::FetchVerify(FetchVerifyError::Verify(
                VerifyError::UnknownSigner { .. },
            )) => {}
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
}

#[cfg(test)]
mod decision_tests {
    //! Tests for [`write_decision_note`] — the slice D1.3 idempotent
    //! write helper. Each test drives the helper directly against a
    //! tempdir-backed bare repo (no broker, no writ side).
    use super::*;
    use crate::bailiff_decision::{Decider, Decision};
    use crate::bailiff_plan_note::{
        DecisionNote, PlanId, plan_decision_seed_blob_bytes, plan_notes_ref,
    };
    use crate::core::UnixMillis;
    use tempfile::TempDir;

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    fn sample_decider() -> Decider {
        Decider::try_new("cli:alice").unwrap()
    }

    fn sample_decision_note(plan_id: PlanId, outcome: Decision) -> DecisionNote {
        DecisionNote {
            plan_id,
            outcome,
            decider: sample_decider(),
            decided_at: UnixMillis::from_millis(1_700_000_000_456),
        }
    }

    /// Happy path: first decision for a plan writes a note whose body
    /// decodes back to the same `DecisionNote` the caller submitted,
    /// attached at the deterministic decision-seed OID.
    #[test]
    fn write_decision_note_writes_then_reads_back() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let note = sample_decision_note(plan_id, Decision::Accepted);

        let returned_oid =
            write_decision_note(&bailiff, &note).expect("first decision must succeed");

        // The returned OID must be the deterministic decision-seed
        // OID for this plan id — readers recompute it from the plan
        // id alone, so any drift between writer and reader here is
        // a silent break of the read path.
        let body = bailiff
            .read_note(&plan_notes_ref(plan_id), &returned_oid)
            .expect("decision body must be readable at the returned OID");
        let parsed =
            DecisionNote::from_canonical_bytes(&body).expect("body must decode as DecisionNote");
        assert_eq!(parsed, note);

        // Sanity: the seed bytes are non-empty and have the expected
        // `<plan_id>::decision` shape (already pinned in
        // `bailiff_plan_note` tests, but pinning here too means a
        // future writer-side change can't silently diverge).
        let seed = plan_decision_seed_blob_bytes(plan_id);
        assert_eq!(
            std::str::from_utf8(&seed).unwrap(),
            format!("{plan_id}::decision"),
        );
    }

    /// Idempotent-by-error: a second decide call for the same plan
    /// returns `DecisionAlreadyRecorded` rather than overwriting. The
    /// second call's note carries different content (Rejected vs
    /// Accepted, different decider) so any silent overwrite would
    /// surface as a body mismatch on the read-back.
    #[test]
    fn write_decision_note_returns_already_recorded_on_second_call() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let first = sample_decision_note(plan_id, Decision::Accepted);
        let returned_oid = write_decision_note(&bailiff, &first).unwrap();

        let mut second = sample_decision_note(plan_id, Decision::Rejected);
        second.decider = Decider::try_new("cli:bob").unwrap();
        let err = write_decision_note(&bailiff, &second).unwrap_err();
        match err {
            WriteDecisionNoteError::DecisionAlreadyRecorded {
                plan_id: pid,
                target_oid,
            } => {
                assert_eq!(pid, plan_id);
                assert_eq!(target_oid, returned_oid);
            }
            other => panic!("expected DecisionAlreadyRecorded, got: {other:?}"),
        }

        // The original Accepted body must still be the one attached.
        let body = bailiff
            .read_note(&plan_notes_ref(plan_id), &returned_oid)
            .unwrap();
        let parsed = DecisionNote::from_canonical_bytes(&body).unwrap();
        assert_eq!(parsed, first);
    }

    /// Distinct plan ids each get their own decision note under the
    /// same notes-ref *prefix* but at different per-plan refs. A
    /// regression that drops the plan id from the ref derivation would
    /// silently collapse both into one ref.
    #[test]
    fn write_decision_note_supports_distinct_plans_independently() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let p1 = PlanId::new();
        let p2 = PlanId::new();
        let note1 = sample_decision_note(p1, Decision::Accepted);
        let note2 = sample_decision_note(p2, Decision::Rejected);

        let oid1 = write_decision_note(&bailiff, &note1).unwrap();
        let oid2 = write_decision_note(&bailiff, &note2).unwrap();
        assert_ne!(oid1, oid2, "distinct plans must seed distinct targets");

        let body1 = bailiff.read_note(&plan_notes_ref(p1), &oid1).unwrap();
        let body2 = bailiff.read_note(&plan_notes_ref(p2), &oid2).unwrap();
        let parsed1 = DecisionNote::from_canonical_bytes(&body1).unwrap();
        let parsed2 = DecisionNote::from_canonical_bytes(&body2).unwrap();
        assert_eq!(parsed1, note1);
        assert_eq!(parsed2, note2);
    }

    /// Load-bearing coexistence pin: a submission note and a decision
    /// note for the same plan live under the same per-plan ref at
    /// distinct seed OIDs. The decision write must not collide with a
    /// pre-existing submission, and the submission must remain
    /// readable after the decision is attached. This is the property
    /// the two-seeds-per-plan design exists to provide.
    #[test]
    fn write_decision_note_coexists_with_existing_submission_under_same_ref() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        // Plant a submission-shaped note directly via `write_note` so
        // we don't need to drive the full slice-C broker round-trip
        // for a coexistence pin. The exact body shape doesn't matter
        // here; we only care that the decision write doesn't trip
        // over an existing note under the same ref.
        let submission_seed = crate::bailiff_plan_note::plan_submission_seed_blob_bytes(plan_id);
        let submission_target = bailiff
            .write_note(&plan_ref, &submission_seed, b"submission-body")
            .expect("submission write must succeed");

        let decision = sample_decision_note(plan_id, Decision::Accepted);
        let decision_target =
            write_decision_note(&bailiff, &decision).expect("decision write must succeed");

        assert_ne!(
            submission_target, decision_target,
            "submission and decision must attach at distinct OIDs",
        );
        assert_eq!(
            bailiff.read_note(&plan_ref, &submission_target).unwrap(),
            b"submission-body",
            "submission body must survive the decision write",
        );
        let decision_body = bailiff.read_note(&plan_ref, &decision_target).unwrap();
        assert_eq!(
            DecisionNote::from_canonical_bytes(&decision_body).unwrap(),
            decision,
        );
    }

    /// Decision can be written even when no submission note exists
    /// yet. D1 chose not to gate the decide verb on submission
    /// presence — the only invariant the write helper enforces is
    /// "one decision per plan." Pin that choice so a future change
    /// that adds a precondition has to update this test.
    #[test]
    fn write_decision_note_does_not_require_pre_existing_submission() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let note = sample_decision_note(plan_id, Decision::Rejected);

        let oid = write_decision_note(&bailiff, &note)
            .expect("decision write must succeed without a prior submission note");
        let body = bailiff.read_note(&plan_notes_ref(plan_id), &oid).unwrap();
        assert_eq!(DecisionNote::from_canonical_bytes(&body).unwrap(), note);
    }
}

#[cfg(test)]
mod review_tests {
    //! Tests for [`write_review_note`] — the slice D2.2 fetch-verify-
    //! attach helper. Same harness shape as `tests` (a tempdir-backed
    //! writ repo holding one signed envelope, a sibling bailiff repo,
    //! and an `AllowedSigners` keyring); the round-trip is exercised
    //! directly without standing up the broker. The full broker
    //! handshake is covered by `end_to_end_tests` below.
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_plan_note::{
        PlanId, ReviewNote, plan_notes_ref, plan_review_seed_blob_bytes,
    };
    use crate::core::{CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::signing::{WritSigningKey, WritVerifyingKey};
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");
    const OTHER_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing_other.key.pub");

    fn writ_notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    /// Build a freshly-signed envelope under `signing_key`. Mirrors
    /// the same-named helper in `tests` so the envelope shape matches
    /// what writ produces today.
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

    /// Prepare a writ repo containing one signed envelope keyed on the
    /// run id, the same shape writ's `RunAgent` handler produces.
    fn writ_repo_with_envelope(
        tmp: &TempDir,
        signing_key: &WritSigningKey,
    ) -> (NotesRepo, RunAgentCompleted, SignedRunEnvelope) {
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let nref = writ_notes_ref();
        let envelope = freshly_signed(signing_key);
        let body = envelope.to_bytes();
        let target = writ_repo
            .write_note(
                &nref,
                envelope.metadata.run_id.to_string().as_bytes(),
                &body,
            )
            .unwrap();
        let completed = RunAgentCompleted {
            output_oid: target,
            signed_metadata: envelope.metadata.clone(),
            signature: envelope.signature.clone(),
        };
        (writ_repo, completed, envelope)
    }

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

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

        completed.signature = crate::core::SshSignature::try_new(
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
}

#[cfg(test)]
mod implement_tests {
    //! Tests for [`write_implement_note`] — the slice E2 fetch-verify-
    //! attach helper. Same harness shape as `review_tests` (a
    //! tempdir-backed writ repo holding one signed envelope, a sibling
    //! bailiff repo, and an `AllowedSigners` keyring); the round-trip
    //! is exercised directly without standing up the broker. The full
    //! broker handshake is covered by `end_to_end_tests` below.
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_plan_note::{
        ImplementNote, PlanId, plan_implement_seed_blob_bytes, plan_notes_ref,
    };
    use crate::core::{CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::signing::{WritSigningKey, WritVerifyingKey};
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");
    const OTHER_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing_other.key.pub");

    fn writ_notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    /// Build a freshly-signed envelope under `signing_key`. Mirrors
    /// the same-named helper in `tests` and `review_tests` so the
    /// envelope shape matches what writ produces today. The stdout
    /// payload is the only thing that differs (implementer prose
    /// rather than reviewer prose), and it's not load-bearing — it
    /// just makes the round-trip self-documenting.
    fn freshly_signed(signing_key: &WritSigningKey) -> SignedRunEnvelope {
        let output = OutputEnvelope {
            stdout: b"implementer prose".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let output_bytes = output.to_bytes();
        let output_sha = Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap();
        let prompt_sha = Sha256Hex::try_new(sha256_hex(b"implementer-prompt")).unwrap();
        let metadata = SignedRunMetadata {
            run_id: AgentRunId::new(),
            session_id: SessionId::new(),
            prompt_sha256: prompt_sha,
            output_envelope_sha256: output_sha,
            capabilities: vec![CapabilitySet::WorkspaceWrite {
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

    /// Prepare a writ repo containing one signed envelope keyed on the
    /// run id, the same shape writ's `RunAgent` handler produces.
    fn writ_repo_with_envelope(
        tmp: &TempDir,
        signing_key: &WritSigningKey,
    ) -> (NotesRepo, RunAgentCompleted, SignedRunEnvelope) {
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let nref = writ_notes_ref();
        let envelope = freshly_signed(signing_key);
        let body = envelope.to_bytes();
        let target = writ_repo
            .write_note(
                &nref,
                envelope.metadata.run_id.to_string().as_bytes(),
                &body,
            )
            .unwrap();
        let completed = RunAgentCompleted {
            output_oid: target,
            signed_metadata: envelope.metadata.clone(),
            signature: envelope.signature.clone(),
        };
        (writ_repo, completed, envelope)
    }

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    /// Happy path: with writ's envelope in place and an allowed-signers
    /// list that contains writ's key, `write_implement_note` attaches
    /// an implement note that decodes back to an `ImplementNote` whose
    /// envelope fields match what writ produced. Load-bearing contract
    /// slice E4's `submit_implement` relies on.
    #[test]
    fn write_implement_note_happy_path_round_trips_through_bailiff_repo() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let plan_id = PlanId::new();
        let purpose = "plan-implement".to_string();
        let returned_oid = write_implement_note(
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
            .expect("bailiff-side implement note must be readable at the returned OID");
        let note = ImplementNote::from_canonical_bytes(&body).expect("body must decode");
        assert_eq!(note.plan_id, plan_id);
        assert_eq!(note.purpose, purpose);
        assert_eq!(note.writ_output_oid, completed.output_oid);
        assert_eq!(note.signed_metadata, envelope.metadata);
        assert_eq!(note.signature, envelope.signature);

        // The seed bytes are the load-bearing input to `git hash-object`;
        // pin them here so a future writer-side change can't silently
        // diverge the seed from the slice-E plan doc.
        let seed = plan_implement_seed_blob_bytes(plan_id);
        assert_eq!(
            std::str::from_utf8(&seed).unwrap(),
            format!("{plan_id}::implement"),
        );
    }

    /// Idempotent-by-error: a second implement-note write for the same
    /// plan returns `ImplementAlreadyRecorded` rather than overwriting.
    /// The second call carries a different `purpose` so any silent
    /// overwrite would surface as a body mismatch on the read-back.
    #[test]
    fn write_implement_note_returns_already_recorded_on_second_call() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let plan_id = PlanId::new();
        let first_oid = write_implement_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            plan_id,
            "first".into(),
            &completed,
            &allowed,
        )
        .expect("first implement must succeed");

        let err = write_implement_note(
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
            WriteImplementNoteError::ImplementAlreadyRecorded {
                plan_id: pid,
                target_oid,
            } => {
                assert_eq!(pid, plan_id);
                assert_eq!(target_oid, first_oid);
            }
            other => panic!("expected ImplementAlreadyRecorded, got: {other:?}"),
        }

        // First body must survive.
        let body = bailiff
            .read_note(&plan_notes_ref(plan_id), &first_oid)
            .unwrap();
        let note = ImplementNote::from_canonical_bytes(&body).unwrap();
        assert_eq!(note.purpose, "first");
    }

    /// Coexistence pin: a submission note and an implement note for
    /// the same plan live under the same per-plan ref at distinct seed
    /// OIDs. Property the four-seeds-per-plan design exists to provide.
    #[test]
    fn write_implement_note_coexists_with_existing_submission_under_same_ref() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        let submission_seed = crate::bailiff_plan_note::plan_submission_seed_blob_bytes(plan_id);
        let submission_target = bailiff
            .write_note(&plan_ref, &submission_seed, b"submission-body")
            .expect("submission write must succeed");

        let implement_target = write_implement_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            plan_id,
            "plan-implement".into(),
            &completed,
            &allowed,
        )
        .expect("implement write must succeed alongside a submission");

        assert_ne!(
            submission_target, implement_target,
            "submission and implement must attach at distinct OIDs",
        );
        assert_eq!(
            bailiff.read_note(&plan_ref, &submission_target).unwrap(),
            b"submission-body",
            "submission body must survive the implement write",
        );
        let implement_body = bailiff.read_note(&plan_ref, &implement_target).unwrap();
        assert_eq!(
            ImplementNote::from_canonical_bytes(&implement_body)
                .unwrap()
                .plan_id,
            plan_id,
        );
    }

    /// Coexistence pin: a decision note and an implement note for the
    /// same plan live under the same per-plan ref at distinct seed OIDs.
    /// Without this, a future suffix collision between `::decision` and
    /// `::implement` would only surface in slice F's read paths.
    #[test]
    fn write_implement_note_coexists_with_existing_decision_under_same_ref() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        let decision_seed = crate::bailiff_plan_note::plan_decision_seed_blob_bytes(plan_id);
        let decision_target = bailiff
            .write_note(&plan_ref, &decision_seed, b"decision-body")
            .expect("decision write must succeed");

        let implement_target = write_implement_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            plan_id,
            "plan-implement".into(),
            &completed,
            &allowed,
        )
        .expect("implement write must succeed alongside a decision");

        assert_ne!(
            decision_target, implement_target,
            "decision and implement must attach at distinct OIDs",
        );
        assert_eq!(
            bailiff.read_note(&plan_ref, &decision_target).unwrap(),
            b"decision-body",
            "decision body must survive the implement write",
        );
    }

    /// Coexistence pin: a review note and an implement note for the
    /// same plan live under the same per-plan ref at distinct seed OIDs.
    /// Closes the all-pairs coexistence matrix against the existing
    /// three seed kinds.
    #[test]
    fn write_implement_note_coexists_with_existing_review_under_same_ref() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        let review_seed = crate::bailiff_plan_note::plan_review_seed_blob_bytes(plan_id);
        let review_target = bailiff
            .write_note(&plan_ref, &review_seed, b"review-body")
            .expect("review write must succeed");

        let implement_target = write_implement_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            plan_id,
            "plan-implement".into(),
            &completed,
            &allowed,
        )
        .expect("implement write must succeed alongside a review");

        assert_ne!(
            review_target, implement_target,
            "review and implement must attach at distinct OIDs",
        );
        assert_eq!(
            bailiff.read_note(&plan_ref, &review_target).unwrap(),
            b"review-body",
            "review body must survive the implement write",
        );
    }

    /// Two distinct plan ids produce two distinct bailiff-side implement
    /// notes from the *same* writ envelope. The plan id is the only
    /// thing that varies between the two writes; the writ-side OID
    /// stays the same in both notes.
    #[test]
    fn write_implement_note_supports_distinct_plans_independently() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let p1 = PlanId::new();
        let p2 = PlanId::new();
        let oid1 = write_implement_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            p1,
            "first".into(),
            &completed,
            &allowed,
        )
        .unwrap();
        let oid2 = write_implement_note(
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
        let note1 = ImplementNote::from_canonical_bytes(&body1).unwrap();
        let note2 = ImplementNote::from_canonical_bytes(&body2).unwrap();
        assert_eq!(note1.plan_id, p1);
        assert_eq!(note2.plan_id, p2);
        assert_eq!(
            note1.writ_output_oid, note2.writ_output_oid,
            "both implements reference the same writ envelope",
        );
        assert_ne!(note1.purpose, note2.purpose);
    }

    /// Defence in depth: if the envelope writ stored in its repo
    /// disagrees with the metadata writ returned over the wire,
    /// bailiff refuses to attach the implement.
    #[test]
    fn write_implement_note_rejects_metadata_mismatch_between_envelope_and_reply() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, mut completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        completed.signed_metadata.exit_code = completed.signed_metadata.exit_code.wrapping_add(1);

        let err = write_implement_note(
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
                WriteImplementNoteError::FetchVerify(FetchVerifyError::EnvelopeMetadataMismatch)
            ),
            "expected EnvelopeMetadataMismatch, got: {err:?}",
        );
    }

    /// Defence in depth: same as the metadata case but for the
    /// signature field.
    #[test]
    fn write_implement_note_rejects_signature_mismatch_between_envelope_and_reply() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, mut completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        completed.signature = crate::core::SshSignature::try_new(
            "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH-other-bytes\n-----END SSH SIGNATURE-----",
        )
        .unwrap();

        let err = write_implement_note(
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
                WriteImplementNoteError::FetchVerify(FetchVerifyError::EnvelopeSignatureMismatch)
            ),
            "expected EnvelopeSignatureMismatch, got: {err:?}",
        );
    }

    /// If bailiff's keyring doesn't contain writ's signing key, the
    /// envelope verification step fails with `UnknownSigner`, which
    /// surfaces as `WriteImplementNoteError::FetchVerify(FetchVerifyError::Verify(..))`. Operator-
    /// misconfigured-trust case.
    #[test]
    fn write_implement_note_rejects_envelope_when_signer_not_trusted() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);

        let other = WritVerifyingKey::from_openssh(OTHER_PUB.trim()).unwrap();
        let allowed = AllowedSigners::from_keys([other]);

        let err = write_implement_note(
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
            WriteImplementNoteError::FetchVerify(FetchVerifyError::Verify(
                VerifyError::UnknownSigner { .. },
            )) => {}
            other => panic!("expected Verify(UnknownSigner), got: {other:?}"),
        }
    }

    /// A bad writ-repo path surfaces as `Fetch`, distinct from the
    /// later `ReadEnvelope` variant. Operators see "your writ repo
    /// path is wrong" instead of "no such note."
    #[test]
    fn write_implement_note_reports_fetch_failure_for_missing_writ_repo() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (_writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let bogus = tmp.path().join("does-not-exist");
        let err = write_implement_note(
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
                WriteImplementNoteError::FetchVerify(FetchVerifyError::Fetch(_))
            ),
            "expected Fetch error, got: {err:?}",
        );
    }

    /// Implement can be written even when no submission, decision, or
    /// review note exists yet. Slice E chose not to gate the write
    /// helper on any of those preconditions (mirrors D1.3 and D2.2's
    /// decoupling); the acceptance gate lives in slice E4's
    /// `submit_implement` workflow. Pin that choice so a future change
    /// that adds a precondition has to update this test.
    #[test]
    fn write_implement_note_does_not_require_pre_existing_submission() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let plan_id = PlanId::new();
        let returned_oid = write_implement_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            plan_id,
            "plan-implement".into(),
            &completed,
            &allowed,
        )
        .expect("implement write must succeed without a prior submission note");
        let body = bailiff
            .read_note(&plan_notes_ref(plan_id), &returned_oid)
            .unwrap();
        let note = ImplementNote::from_canonical_bytes(&body).unwrap();
        assert_eq!(note.plan_id, plan_id);
    }
}

#[cfg(test)]
mod end_to_end_tests {
    //! Full slice-C handshake against a real writ broker. Mirrors the
    //! slice-B5 round-trip in `writ_client.rs` and tacks
    //! `write_plan_note` on the end: bailiff sends `RunAgent`, writ
    //! signs and persists the envelope, then bailiff drives
    //! `write_plan_note` to fetch the envelope, verify it, and store
    //! a `PlanNote` keyed on the plan id.
    //!
    //! A regression anywhere in the chain — protocol framing, signing
    //! namespace, notes write, fetch refspec, envelope/reply
    //! agreement, plan-note serialisation — fails this test rather
    //! than getting caught by a downstream consumer.
    use std::collections::{BTreeMap, HashMap};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::sync::Mutex as AsyncMutex;
    use wiremock::MockServer;

    use super::*;
    use crate::agent_run::AgentPrompt;
    use crate::audit::AuditLog;
    use crate::bailiff_plan_note::{ImplementNote, PlanId, PlanNote, ReviewNote, plan_notes_ref};
    use crate::core::{AgentKind, CapabilitySet, NotesRef, RepoRef, TtlSeconds};
    use crate::github::{GitHubAppConfig, GitHubAppRegistryConfig, GitHubMinter};
    use crate::notes_repo::NotesRepo;
    use crate::policy::PolicyConfig;
    use crate::run_verify::AllowedSigners;
    use crate::secret::{SecretError, SecretKey, SecretStore};
    use crate::server::{
        BrokerState, RunAgentSpawnConfig, prepare_broker_listener, serve_broker_with_agent_vm,
    };
    use crate::signing::WritSigningKey;
    use crate::writ_client::{RunAgentRequest, WritClient};

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");
    const TEST_PRIV: &str = include_str!("../tests/fixtures/rsa_test_1.pem");

    /// In-memory `SecretStore`. Same minimal shim as the writ_client
    /// end-to-end test uses — production runs against
    /// `FileSecretStore`, but for a test that only stores the
    /// GitHub-app PEM to satisfy `BrokerState`'s non-empty registry
    /// invariant, an in-memory map is enough.
    #[derive(Default)]
    struct InMemStore(Mutex<HashMap<String, String>>);

    impl SecretStore for InMemStore {
        fn get(&self, key: &SecretKey) -> Result<Option<String>, SecretError> {
            Ok(self.0.lock().unwrap().get(key.as_str()).cloned())
        }
        fn put(&self, key: &SecretKey, value: &str) -> Result<(), SecretError> {
            self.0
                .lock()
                .unwrap()
                .insert(key.as_str().to_string(), value.to_string());
            Ok(())
        }
        fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
            self.0.lock().unwrap().remove(key.as_str());
            Ok(())
        }
    }

    fn find_in_path(name: &str) -> Option<std::path::PathBuf> {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|p| p.join(name))
                .find(|p| p.is_file())
        })
    }

    #[tokio::test]
    async fn write_plan_note_completes_after_real_broker_round_trip() {
        // --- Broker bring-up (writ side) ----------------------------
        let tmp = tempfile::tempdir().unwrap();
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let bailiff_repo_handle = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");

        let github_server = MockServer::start().await;
        let pk = SecretKey::new("gh-app-pk").unwrap();
        let store = InMemStore::default();
        store.put(&pk, TEST_PRIV).unwrap();
        let mut apps = BTreeMap::new();
        apps.insert(
            AgentKind::Claude,
            GitHubAppConfig {
                app_id: 42,
                installation_id: 999,
                installation_owner: "o".into(),
                private_key_secret: pk,
                api_base: github_server.uri(),
            },
        );
        let minter = GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap());

        let state = Arc::new(BrokerState {
            audit: Arc::new(AuditLog::open_in_memory().unwrap()),
            minter,
            secrets: store,
            policy: PolicyConfig {
                writable_repos: vec![],
                default_ttl: TtlSeconds::new(3600).unwrap(),
            },
            staging_store: None,
            notes_repo: Some(Arc::new(writ_repo)),
            signing_key: Some(signing_key.clone()),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: cat,
                args: Vec::new(),
            }),
            promote_runtime: None,
        });

        let socket_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let socket_path = socket_dir.path().join("writ.sock");
        let listener = prepare_broker_listener(&socket_path).await.unwrap();
        let broker_state = Arc::clone(&state);
        let broker_task = tokio::spawn(async move {
            let _ = serve_broker_with_agent_vm(listener, broker_state, None).await;
        });

        // --- Client request (bailiff side) --------------------------
        let prompt_text = "noop\n";
        let writ_notes_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
        let purpose = "plan-submit".to_string();
        let client = WritClient::new(&socket_path);
        let completed = tokio::time::timeout(
            Duration::from_secs(15),
            client.run_agent(RunAgentRequest {
                prompt: AgentPrompt::new(prompt_text),
                capabilities: vec![CapabilitySet::WorkspaceRead {
                    repo: RepoRef {
                        owner: "smaug123".into(),
                        name: "writ".into(),
                    },
                }],
                purpose: purpose.clone(),
                output_ref: writ_notes_ref.clone(),
                session_id: None,
                workspace: None,
                agent_kind: None,
                agent_model: None,
            }),
        )
        .await
        .expect("RunAgent must complete within 15s")
        .expect("RunAgent must succeed");

        // --- Plan-note write (bailiff side) -------------------------
        // `write_plan_note` is blocking (shells out to git); wrap it
        // in `spawn_blocking` so we don't stall the runtime. A short
        // async lock on the bailiff repo keeps the single-writer
        // invariant visible at the call site.
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let plan_id = PlanId::new();
        let completed_clone = completed.clone();
        let writ_notes_ref_clone = writ_notes_ref.clone();
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo_handle));
        let bailiff_for_block = Arc::clone(&bailiff);
        let returned_oid = tokio::task::spawn_blocking(move || {
            let bailiff = bailiff_for_block.blocking_lock();
            write_plan_note(
                &bailiff,
                &writ_repo_path,
                &writ_notes_ref_clone,
                plan_id,
                purpose.clone(),
                &completed_clone,
                &allowed,
            )
        })
        .await
        .unwrap()
        .expect("write_plan_note must succeed under the trusted-signer keyring");

        // --- Read back the plan note from bailiff's repo ------------
        let bailiff_for_read = Arc::clone(&bailiff);
        let plan_ref = plan_notes_ref(plan_id);
        let body = tokio::task::spawn_blocking(move || {
            let bailiff = bailiff_for_read.blocking_lock();
            bailiff.read_note(&plan_ref, &returned_oid)
        })
        .await
        .unwrap()
        .expect("bailiff-side plan note must be readable at the returned OID");
        let note = PlanNote::from_canonical_bytes(&body)
            .expect("bailiff-side body must decode as PlanNote");

        // The note carries the plan-id bailiff allocated, the purpose
        // bailiff sent on the wire, the writ-side OID writ returned,
        // and the signed metadata + signature the broker produced.
        assert_eq!(note.plan_id, plan_id);
        assert_eq!(note.purpose, "plan-submit");
        assert_eq!(note.writ_output_oid, completed.output_oid);
        assert_eq!(note.signed_metadata, completed.signed_metadata);
        assert_eq!(note.signature, completed.signature);

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Full slice-D2 handshake against a real writ broker: bailiff
    /// sends `RunAgent` for a reviewer run, writ signs and persists
    /// the envelope, then bailiff drives `write_review_note` to fetch
    /// the envelope, verify it, and store a `ReviewNote` keyed on the
    /// plan id. Parallel to
    /// [`write_plan_note_completes_after_real_broker_round_trip`];
    /// the only material differences are the helper under test, the
    /// purpose string, and the read-back type.
    #[tokio::test]
    async fn write_review_note_completes_after_real_broker_round_trip() {
        // --- Broker bring-up (writ side) ----------------------------
        let tmp = tempfile::tempdir().unwrap();
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let bailiff_repo_handle = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");

        let github_server = MockServer::start().await;
        let pk = SecretKey::new("gh-app-pk").unwrap();
        let store = InMemStore::default();
        store.put(&pk, TEST_PRIV).unwrap();
        let mut apps = BTreeMap::new();
        apps.insert(
            AgentKind::Claude,
            GitHubAppConfig {
                app_id: 42,
                installation_id: 999,
                installation_owner: "o".into(),
                private_key_secret: pk,
                api_base: github_server.uri(),
            },
        );
        let minter = GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap());

        let state = Arc::new(BrokerState {
            audit: Arc::new(AuditLog::open_in_memory().unwrap()),
            minter,
            secrets: store,
            policy: PolicyConfig {
                writable_repos: vec![],
                default_ttl: TtlSeconds::new(3600).unwrap(),
            },
            staging_store: None,
            notes_repo: Some(Arc::new(writ_repo)),
            signing_key: Some(signing_key.clone()),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: cat,
                args: Vec::new(),
            }),
            promote_runtime: None,
        });

        let socket_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let socket_path = socket_dir.path().join("writ.sock");
        let listener = prepare_broker_listener(&socket_path).await.unwrap();
        let broker_state = Arc::clone(&state);
        let broker_task = tokio::spawn(async move {
            let _ = serve_broker_with_agent_vm(listener, broker_state, None).await;
        });

        // --- Client request (bailiff side) --------------------------
        let prompt_text = "reviewer-prompt + plan body\n";
        let writ_notes_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
        let purpose = "plan-review".to_string();
        let client = WritClient::new(&socket_path);
        let completed = tokio::time::timeout(
            Duration::from_secs(15),
            client.run_agent(RunAgentRequest {
                prompt: AgentPrompt::new(prompt_text),
                capabilities: vec![CapabilitySet::WorkspaceRead {
                    repo: RepoRef {
                        owner: "smaug123".into(),
                        name: "writ".into(),
                    },
                }],
                purpose: purpose.clone(),
                output_ref: writ_notes_ref.clone(),
                session_id: None,
                workspace: None,
                agent_kind: None,
                agent_model: None,
            }),
        )
        .await
        .expect("RunAgent must complete within 15s")
        .expect("RunAgent must succeed");

        // --- Review-note write (bailiff side) -----------------------
        // `write_review_note` is blocking (shells out to git); wrap
        // it in `spawn_blocking` so we don't stall the runtime. Same
        // `AsyncMutex<NotesRepo>` shape the plan-note round-trip uses.
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let plan_id = PlanId::new();
        let completed_clone = completed.clone();
        let writ_notes_ref_clone = writ_notes_ref.clone();
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo_handle));
        let bailiff_for_block = Arc::clone(&bailiff);
        let returned_oid = tokio::task::spawn_blocking(move || {
            let bailiff = bailiff_for_block.blocking_lock();
            write_review_note(
                &bailiff,
                &writ_repo_path,
                &writ_notes_ref_clone,
                plan_id,
                purpose.clone(),
                &completed_clone,
                &allowed,
            )
        })
        .await
        .unwrap()
        .expect("write_review_note must succeed under the trusted-signer keyring");

        // --- Read back the review note from bailiff's repo ----------
        let bailiff_for_read = Arc::clone(&bailiff);
        let plan_ref = plan_notes_ref(plan_id);
        let body = tokio::task::spawn_blocking(move || {
            let bailiff = bailiff_for_read.blocking_lock();
            bailiff.read_note(&plan_ref, &returned_oid)
        })
        .await
        .unwrap()
        .expect("bailiff-side review note must be readable at the returned OID");
        let note = ReviewNote::from_canonical_bytes(&body)
            .expect("bailiff-side body must decode as ReviewNote");

        assert_eq!(note.plan_id, plan_id);
        assert_eq!(note.purpose, "plan-review");
        assert_eq!(note.writ_output_oid, completed.output_oid);
        assert_eq!(note.signed_metadata, completed.signed_metadata);
        assert_eq!(note.signature, completed.signature);

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Full slice-E handshake against a real writ broker: bailiff
    /// sends `RunAgent` for an implementer run, writ signs and persists
    /// the envelope, then bailiff drives `write_implement_note` to
    /// fetch the envelope, verify it, and store an `ImplementNote`
    /// keyed on the plan id. Parallel to
    /// [`write_plan_note_completes_after_real_broker_round_trip`] and
    /// [`write_review_note_completes_after_real_broker_round_trip`];
    /// the only material differences are the helper under test, the
    /// purpose string, and the read-back type.
    #[tokio::test]
    async fn write_implement_note_completes_after_real_broker_round_trip() {
        // --- Broker bring-up (writ side) ----------------------------
        let tmp = tempfile::tempdir().unwrap();
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let bailiff_repo_handle = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");

        let github_server = MockServer::start().await;
        let pk = SecretKey::new("gh-app-pk").unwrap();
        let store = InMemStore::default();
        store.put(&pk, TEST_PRIV).unwrap();
        let mut apps = BTreeMap::new();
        apps.insert(
            AgentKind::Claude,
            GitHubAppConfig {
                app_id: 42,
                installation_id: 999,
                installation_owner: "o".into(),
                private_key_secret: pk,
                api_base: github_server.uri(),
            },
        );
        let minter = GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap());

        let state = Arc::new(BrokerState {
            audit: Arc::new(AuditLog::open_in_memory().unwrap()),
            minter,
            secrets: store,
            policy: PolicyConfig {
                writable_repos: vec![],
                default_ttl: TtlSeconds::new(3600).unwrap(),
            },
            staging_store: None,
            notes_repo: Some(Arc::new(writ_repo)),
            signing_key: Some(signing_key.clone()),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: cat,
                args: Vec::new(),
            }),
            promote_runtime: None,
        });

        let socket_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let socket_path = socket_dir.path().join("writ.sock");
        let listener = prepare_broker_listener(&socket_path).await.unwrap();
        let broker_state = Arc::clone(&state);
        let broker_task = tokio::spawn(async move {
            let _ = serve_broker_with_agent_vm(listener, broker_state, None).await;
        });

        // --- Client request (bailiff side) --------------------------
        let prompt_text = "implementer-prompt + plan body\n";
        let writ_notes_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
        let purpose = "plan-implement".to_string();
        let client = WritClient::new(&socket_path);
        let completed = tokio::time::timeout(
            Duration::from_secs(15),
            client.run_agent(RunAgentRequest {
                prompt: AgentPrompt::new(prompt_text),
                capabilities: vec![CapabilitySet::WorkspaceRead {
                    repo: RepoRef {
                        owner: "smaug123".into(),
                        name: "writ".into(),
                    },
                }],
                purpose: purpose.clone(),
                output_ref: writ_notes_ref.clone(),
                session_id: None,
                workspace: None,
                agent_kind: None,
                agent_model: None,
            }),
        )
        .await
        .expect("RunAgent must complete within 15s")
        .expect("RunAgent must succeed");

        // --- Implement-note write (bailiff side) --------------------
        // `write_implement_note` is blocking (shells out to git); wrap
        // it in `spawn_blocking` so we don't stall the runtime. Same
        // `AsyncMutex<NotesRepo>` shape the plan-note and review-note
        // round-trips use.
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let plan_id = PlanId::new();
        let completed_clone = completed.clone();
        let writ_notes_ref_clone = writ_notes_ref.clone();
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo_handle));
        let bailiff_for_block = Arc::clone(&bailiff);
        let returned_oid = tokio::task::spawn_blocking(move || {
            let bailiff = bailiff_for_block.blocking_lock();
            write_implement_note(
                &bailiff,
                &writ_repo_path,
                &writ_notes_ref_clone,
                plan_id,
                purpose.clone(),
                &completed_clone,
                &allowed,
            )
        })
        .await
        .unwrap()
        .expect("write_implement_note must succeed under the trusted-signer keyring");

        // --- Read back the implement note from bailiff's repo -------
        let bailiff_for_read = Arc::clone(&bailiff);
        let plan_ref = plan_notes_ref(plan_id);
        let body = tokio::task::spawn_blocking(move || {
            let bailiff = bailiff_for_read.blocking_lock();
            bailiff.read_note(&plan_ref, &returned_oid)
        })
        .await
        .unwrap()
        .expect("bailiff-side implement note must be readable at the returned OID");
        let note = ImplementNote::from_canonical_bytes(&body)
            .expect("bailiff-side body must decode as ImplementNote");

        assert_eq!(note.plan_id, plan_id);
        assert_eq!(note.purpose, "plan-implement");
        assert_eq!(note.writ_output_oid, completed.output_oid);
        assert_eq!(note.signed_metadata, completed.signed_metadata);
        assert_eq!(note.signature, completed.signature);

        broker_task.abort();
        let _ = broker_task.await;
    }
}
