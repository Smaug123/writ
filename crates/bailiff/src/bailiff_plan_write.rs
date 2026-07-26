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
use crate::bailiff_repo_guard::lock_repo_mutations;
use writ::core::NotesRef;
use writ::notes_repo::{NotesRepo, NotesRepoError, WriteOutcome};
use writ::run_envelope::SignedRunEnvelope;
use writ::run_verify::{AllowedSigners, VerifyError, verify_run_envelope};
use writ::vm_git::GitObjectId;
use writ::writ_client::RunAgentCompleted;

/// Refspec bailiff uses to mirror writ's `v1` notes namespace into
/// its own repo. The leading `+` is load-bearing: writ may rewrite
/// history under its own ref, and bailiff is the local read mirror —
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

/// Tagged failure modes of `fetch_and_verify` — the fetch→read→
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
    // Repo-wide, and held across the note write as well as the fetch:
    // git refuses to make concurrent fetch+notes-add safe, and the
    // per-plan lock does not span two processes on different plans.
    // See `lock_repo_mutations`.
    let _repo_lock = lock_repo_mutations(bailiff_repo).map_err(WritePlanNoteError::RepoLock)?;
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
    /// The repo-wide mutation lock could not be taken. A filesystem
    /// problem, not contention — the lock waits.
    #[error("locking bailiff's repo for mutation failed: {0}")]
    RepoLock(#[source] crate::bailiff_repo_guard::PlanGuardError),
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
    /// The repo-wide mutation lock could not be taken. A filesystem
    /// problem, not contention — the lock waits.
    #[error("locking bailiff's repo for mutation failed: {0}")]
    RepoLock(#[source] crate::bailiff_repo_guard::PlanGuardError),
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
    // Repo-wide, and held across the note write as well as the fetch:
    // git refuses to make concurrent fetch+notes-add safe, and the
    // per-plan lock does not span two processes on different plans.
    // See `lock_repo_mutations`.
    let _repo_lock = lock_repo_mutations(bailiff_repo).map_err(WriteReviewNoteError::RepoLock)?;
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
    /// The repo-wide mutation lock could not be taken. A filesystem
    /// problem, not contention — the lock waits.
    #[error("locking bailiff's repo for mutation failed: {0}")]
    RepoLock(#[source] crate::bailiff_repo_guard::PlanGuardError),
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
    // Repo-wide, and held across the note write as well as the fetch:
    // git refuses to make concurrent fetch+notes-add safe, and the
    // per-plan lock does not span two processes on different plans.
    // See `lock_repo_mutations`.
    let _repo_lock =
        lock_repo_mutations(bailiff_repo).map_err(WriteImplementNoteError::RepoLock)?;
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
    /// The repo-wide mutation lock could not be taken. A filesystem
    /// problem, not contention — the lock waits.
    #[error("locking bailiff's repo for mutation failed: {0}")]
    RepoLock(#[source] crate::bailiff_repo_guard::PlanGuardError),
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
mod decision_tests;
#[cfg(test)]
mod end_to_end_tests;
#[cfg(test)]
mod implement_tests;
#[cfg(test)]
mod plan_tests;
#[cfg(test)]
mod review_tests;
#[cfg(test)]
mod test_support;

/// Property-based spec for the fetch→verify→attach contract that the
/// three envelope-bearing write helpers share via `fetch_and_verify`.
/// The example/edge-case tests in the sibling `*_tests` modules pin
/// specific scenarios; this module asserts the same contract holds for
/// *arbitrary* envelope payloads. Each case drives real git repos in
/// tempdirs, so the proptest case counts are deliberately low — git
/// fork/exec dominates the wall-clock.
#[cfg(test)]
mod spec {
    use super::test_support::{
        OTHER_PUB, SIGNING_PEM, SIGNING_PUB, bailiff_repo, signed_envelope, writ_notes_ref,
    };
    use super::*;
    use crate::bailiff_plan_note::{
        ImplementNote, PlanId, PlanNote, ReviewNote, plan_implement_seed_blob_bytes,
        plan_notes_ref, plan_review_seed_blob_bytes, plan_submission_seed_blob_bytes,
    };
    use proptest::prelude::*;
    use tempfile::TempDir;
    use writ::core::{CapabilitySet, RepoRef, SshSignature};
    use writ::signing::{WritSigningKey, WritVerifyingKey};

    /// The three verbs that share `fetch_and_verify`. Round-trip (and,
    /// for review/implement, idempotency) differs per verb; the
    /// fetch-verify failure matrix does not, so the rejection property
    /// drives one representative verb.
    #[derive(Debug, Clone, Copy)]
    enum Verb {
        Plan,
        Review,
        Implement,
    }

    fn arb_verb() -> impl Strategy<Value = Verb> {
        prop_oneof![Just(Verb::Plan), Just(Verb::Review), Just(Verb::Implement)]
    }

    fn arb_capabilities() -> impl Strategy<Value = Vec<CapabilitySet>> {
        let cap = ("[a-z0-9_-]{1,16}", "[a-z0-9_.-]{1,16}", any::<bool>()).prop_map(
            |(owner, name, writable)| {
                let repo = RepoRef { owner, name };
                if writable {
                    CapabilitySet::WorkspaceWrite { repo }
                } else {
                    CapabilitySet::WorkspaceRead { repo }
                }
            },
        );
        prop::collection::vec(cap, 0..3)
    }

    /// The *inputs* to an envelope; signing happens in the test body so
    /// the signature binds the generated metadata.
    #[derive(Debug, Clone)]
    struct Payload {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        prompt: Vec<u8>,
        capabilities: Vec<CapabilitySet>,
        exit_code: i32,
        completed_at_millis: i64,
    }

    fn arb_payload() -> impl Strategy<Value = Payload> {
        (
            prop::collection::vec(any::<u8>(), 0..64),
            prop::collection::vec(any::<u8>(), 0..64),
            prop::collection::vec(any::<u8>(), 0..64),
            arb_capabilities(),
            any::<i32>(),
            any::<i64>(),
        )
            .prop_map(
                |(stdout, stderr, prompt, capabilities, exit_code, completed_at_millis)| Payload {
                    stdout,
                    stderr,
                    prompt,
                    capabilities,
                    exit_code,
                    completed_at_millis,
                },
            )
    }

    fn envelope_for(signing_key: &WritSigningKey, p: &Payload) -> SignedRunEnvelope {
        signed_envelope(
            signing_key,
            p.stdout.clone(),
            p.stderr.clone(),
            &p.prompt,
            p.capabilities.clone(),
            p.exit_code,
            p.completed_at_millis,
        )
    }

    /// Write `envelope` into a fresh tempdir writ repo and return the
    /// repo plus the `RunAgentCompleted` reply bailiff would have seen.
    /// Mirrors `test_support::writ_repo_with_envelope` for a
    /// caller-supplied envelope.
    fn writ_repo_for(
        tmp: &TempDir,
        envelope: &SignedRunEnvelope,
    ) -> (NotesRepo, RunAgentCompleted) {
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let target = writ_repo
            .write_note(
                &writ_notes_ref(),
                envelope.metadata.run_id.to_string().as_bytes(),
                &envelope.to_bytes(),
            )
            .unwrap();
        let completed = RunAgentCompleted {
            output_oid: target,
            signed_metadata: envelope.metadata.clone(),
            signature: envelope.signature.clone(),
        };
        (writ_repo, completed)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// For any valid payload and any verb, a trusted-signer write
        /// succeeds and the bailiff-side note reads back with exactly
        /// the envelope fields writ signed.
        #[test]
        fn every_verb_round_trips_a_trusted_envelope(verb in arb_verb(), payload in arb_payload()) {
            let tmp = TempDir::new().unwrap();
            let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
            let envelope = envelope_for(&signing_key, &payload);
            let (writ_repo, completed) = writ_repo_for(&tmp, &envelope);
            let bailiff = bailiff_repo(&tmp);
            let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
            let plan_id = PlanId::new();
            let purpose = "spec".to_string();

            let (returned_oid, seed) = match verb {
                Verb::Plan => (
                    write_plan_note(&bailiff, writ_repo.path(), &writ_notes_ref(), plan_id, purpose.clone(), &completed, &allowed)
                        .expect("plan write must succeed"),
                    plan_submission_seed_blob_bytes(plan_id),
                ),
                Verb::Review => (
                    write_review_note(&bailiff, writ_repo.path(), &writ_notes_ref(), plan_id, purpose.clone(), &completed, &allowed)
                        .expect("review write must succeed"),
                    plan_review_seed_blob_bytes(plan_id),
                ),
                Verb::Implement => (
                    write_implement_note(&bailiff, writ_repo.path(), &writ_notes_ref(), plan_id, purpose.clone(), &completed, &allowed)
                        .expect("implement write must succeed"),
                    plan_implement_seed_blob_bytes(plan_id),
                ),
            };

            prop_assert!(!seed.is_empty());
            let body = bailiff
                .read_note(&plan_notes_ref(plan_id), &returned_oid)
                .expect("bailiff-side note must be readable at the returned OID");

            // Every note type carries the same envelope fields; assert
            // the round-trip preserved them regardless of which verb wrote.
            let (got_plan_id, got_purpose, got_oid, got_meta, got_sig) = match verb {
                Verb::Plan => {
                    let n = PlanNote::from_canonical_bytes(&body).expect("body must decode");
                    (n.plan_id, n.purpose, n.writ_output_oid, n.signed_metadata, n.signature)
                }
                Verb::Review => {
                    let n = ReviewNote::from_canonical_bytes(&body).expect("body must decode");
                    (n.plan_id, n.purpose, n.writ_output_oid, n.signed_metadata, n.signature)
                }
                Verb::Implement => {
                    let n = ImplementNote::from_canonical_bytes(&body).expect("body must decode");
                    (n.plan_id, n.purpose, n.writ_output_oid, n.signed_metadata, n.signature)
                }
            };
            prop_assert_eq!(got_plan_id, plan_id);
            prop_assert_eq!(got_purpose, purpose);
            prop_assert_eq!(got_oid, completed.output_oid.clone());
            prop_assert_eq!(got_meta, envelope.metadata.clone());
            prop_assert_eq!(got_sig, envelope.signature.clone());
        }

        /// The shared fetch-verify phase rejects a tampered or
        /// untrusted envelope with the matching variant: metadata
        /// divergence, signature divergence, or an unknown signer.
        /// Driven through `write_plan_note` as a representative verb.
        #[test]
        fn fetch_verify_rejects_tampered_or_untrusted_envelopes(payload in arb_payload(), fault in 0u8..3) {
            let tmp = TempDir::new().unwrap();
            let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
            let envelope = envelope_for(&signing_key, &payload);
            let (writ_repo, mut completed) = writ_repo_for(&tmp, &envelope);
            let bailiff = bailiff_repo(&tmp);

            // fault 0: metadata tamper; 1: signature tamper; 2: untrusted signer.
            let allowed = if fault == 2 {
                let other = WritVerifyingKey::from_openssh(OTHER_PUB.trim()).unwrap();
                AllowedSigners::from_keys([other])
            } else {
                AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap()
            };
            if fault == 0 {
                completed.signed_metadata.exit_code = completed.signed_metadata.exit_code.wrapping_add(1);
            } else if fault == 1 {
                completed.signature = SshSignature::try_new(
                    "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH-other-bytes\n-----END SSH SIGNATURE-----",
                )
                .unwrap();
            }

            let err = write_plan_note(&bailiff, writ_repo.path(), &writ_notes_ref(), PlanId::new(), "spec".into(), &completed, &allowed)
                .unwrap_err();
            match (fault, &err) {
                (0, WritePlanNoteError::FetchVerify(FetchVerifyError::EnvelopeMetadataMismatch)) => {}
                (1, WritePlanNoteError::FetchVerify(FetchVerifyError::EnvelopeSignatureMismatch)) => {}
                (2, WritePlanNoteError::FetchVerify(FetchVerifyError::Verify(VerifyError::UnknownSigner { .. }))) => {}
                _ => prop_assert!(false, "fault {fault} produced unexpected error: {err:?}"),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Review and implement writes are idempotent by error: the
        /// second write for a plan id is refused rather than silently
        /// overwriting the first.
        #[test]
        fn review_and_implement_writes_are_idempotent(payload in arb_payload(), use_implement in any::<bool>()) {
            let tmp = TempDir::new().unwrap();
            let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
            let envelope = envelope_for(&signing_key, &payload);
            let (writ_repo, completed) = writ_repo_for(&tmp, &envelope);
            let bailiff = bailiff_repo(&tmp);
            let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
            let plan_id = PlanId::new();

            if use_implement {
                write_implement_note(&bailiff, writ_repo.path(), &writ_notes_ref(), plan_id, "spec".into(), &completed, &allowed)
                    .expect("first implement write succeeds");
                let err = write_implement_note(&bailiff, writ_repo.path(), &writ_notes_ref(), plan_id, "spec".into(), &completed, &allowed)
                    .unwrap_err();
                prop_assert!(
                    matches!(err, WriteImplementNoteError::ImplementAlreadyRecorded { .. }),
                    "second implement must be refused, got: {err:?}",
                );
            } else {
                write_review_note(&bailiff, writ_repo.path(), &writ_notes_ref(), plan_id, "spec".into(), &completed, &allowed)
                    .expect("first review write succeeds");
                let err = write_review_note(&bailiff, writ_repo.path(), &writ_notes_ref(), plan_id, "spec".into(), &completed, &allowed)
                    .unwrap_err();
                prop_assert!(
                    matches!(err, WriteReviewNoteError::ReviewAlreadyRecorded { .. }),
                    "second review must be refused, got: {err:?}",
                );
            }
        }
    }
}
