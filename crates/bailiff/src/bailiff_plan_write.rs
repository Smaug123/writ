//! Bailiff-side write helper that completes the slice-C handshake:
//! fetch writ's signed envelope, verify it, and persist the stage's
//! note at the plan's notes ref in bailiff's own bare repo.
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
//!    bailiff's repo with seed [`crate::bailiff_stage::AgentStage::note_seed`]`(plan_id)`.
//!    Returns the bailiff-side target OID.
//!
//! Every failure mode is a tagged variant of [`WriteStageNoteError`]
//! so the CLI verbs can react without parsing prose. Since slice 3b
//! one function serves all three envelope-bearing stages; only the
//! decision note, which carries no envelope, has its own writer.

use std::path::Path;

use thiserror::Error;

use crate::bailiff_plan_note::{
    DecisionNote, ImplementNote, PlanId, PlanNote, ReviewNote, plan_decision_seed_blob_bytes,
    plan_notes_ref,
};
use crate::bailiff_repo_guard::lock_repo_mutations;
use crate::bailiff_stage::AgentStage;
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
/// [`crate::bailiff_plan_write::write_stage_note`], [`crate::bailiff_plan_write::write_stage_note`], and
/// [`crate::bailiff_plan_write::write_stage_note`]; only the subsequent attach — note type,
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
/// [`crate::bailiff_plan_write::write_stage_note`], [`crate::bailiff_plan_write::write_stage_note`], and
/// [`crate::bailiff_plan_write::write_stage_note`]. Each verb's error type embeds this via a
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
/// Sibling to [`crate::bailiff_plan_write::write_stage_note`] under the same per-plan notes
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
    // Decision notes do not fetch, but a `git notes add` still races
    // another *process*'s fetch or note write for a different plan;
    // per-plan flocks do not cover that. See `lock_repo_mutations`.
    let _repo_lock = lock_repo_mutations(bailiff_repo).map_err(WriteDecisionNoteError::RepoLock)?;
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

/// Fetch writ's signed envelope for `stage`'s run, verify it
/// end-to-end, and attach the stage's note to bailiff's per-plan ref.
///
/// One function for all three envelope-bearing stages. Before slice 3b
/// this was `write_plan_note` / `write_review_note` /
/// `write_implement_note` — three bodies that were byte-identical
/// modulo the note type, the seed, and the noun in their error enums.
///
/// The stage varies exactly three things, and each is a projection of
/// [`AgentStage`] rather than a parameter a caller could get wrong:
/// which note body is built, which seed it attaches at
/// ([`AgentStage::note_seed`]), and which noun the error names.
///
/// Returns the bailiff-side target OID — the deterministic seed-blob
/// OID the stage's seed hashes to — so a caller can hand it to
/// [`NotesRepo::read_note`] without recomputing it.
///
/// **Idempotent by error.** A second write for the same
/// `(plan_id, stage)` returns
/// [`WriteStageNoteError::AlreadyRecorded`] rather than overwriting.
/// Before slice 3b the submission was the odd one out here: it called
/// `write_note`, so its duplicate surfaced as a generic git failure
/// where its siblings' surfaced as the typed conflict. Both refused;
/// only one said why. Unreachable through the workflow either way,
/// since slice 1 gates `Submit` to `Absent`.
///
/// **No precondition on any other note's presence.** The write helper
/// enforces one invariant — one note per `(plan, stage)`. Ordering is
/// [`crate::bailiff_plan_state::allows`]'s job, checked under the plan
/// lock by [`crate::bailiff_stage::open_plan_stage`].
pub fn write_stage_note(
    bailiff_repo: &NotesRepo,
    target: &StageNoteTarget,
    writ_notes_ref: &NotesRef,
    purpose: String,
    completed: &RunAgentCompleted,
) -> Result<GitObjectId, WriteStageNoteError> {
    let StageNoteTarget {
        stage,
        plan_id,
        writ_repo_path,
        allowed_signers,
    } = target;
    let (stage, plan_id) = (*stage, *plan_id);
    // Repo-wide, and held across the note write as well as the fetch:
    // git refuses to make concurrent fetch+notes-add safe, and the
    // per-plan lock does not span two processes on different plans.
    // See `lock_repo_mutations`.
    let _repo_lock = lock_repo_mutations(bailiff_repo).map_err(WriteStageNoteError::RepoLock)?;
    let envelope = fetch_and_verify(
        bailiff_repo,
        writ_repo_path,
        writ_notes_ref,
        completed,
        allowed_signers,
    )?;

    let body = stage_note_body(stage, plan_id, purpose, completed, envelope);
    match bailiff_repo
        .write_note_if_absent(&plan_notes_ref(plan_id), &stage.note_seed(plan_id), &body)
        .map_err(|source| WriteStageNoteError::Write { stage, source })?
    {
        WriteOutcome::Written(oid) => Ok(oid),
        WriteOutcome::AlreadyPresent(target_oid) => Err(WriteStageNoteError::AlreadyRecorded {
            stage,
            plan_id,
            target_oid,
        }),
    }
}

/// Where a stage's note lands, and what its envelope is checked
/// against.
///
/// Bundled rather than passed as loose arguments because the four
/// travel together from the CLI through the runner to the write, and
/// because [`write_stage_note`] would otherwise take eight parameters
/// — four of which a caller could permute without the compiler
/// noticing, since two are paths and two are ids.
///
/// `purpose` and the writ output ref are deliberately **not** here.
/// They go to writ *and* onto the note, so they live in
/// [`crate::bailiff_stage::StageRunInputs`] alone and the runner
/// passes the same values to both; a copy here would be a second
/// place for them to disagree.
#[derive(Clone, Debug)]
pub struct StageNoteTarget {
    /// Which note to write. Also selects the seed it attaches at and
    /// the noun its errors name.
    pub stage: AgentStage,
    /// Plan the note belongs to.
    pub plan_id: PlanId,
    /// Path to writ's bare repo, fetched from to re-read and verify
    /// the envelope the RPC reply names.
    pub writ_repo_path: std::path::PathBuf,
    /// Keyring the envelope's signature must verify under.
    pub allowed_signers: AllowedSigners,
}

/// The canonical bytes of `stage`'s note.
///
/// The three note types are field-identical and generated from one
/// macro, but they stay *distinct types* so that
/// [`crate::bailiff_plan_read::read_plan_body_bytes`] can demand the
/// submission specifically. This match is the one place that has to
/// name all three, and it produces bytes rather than a value, so the
/// distinction costs nothing downstream.
fn stage_note_body(
    stage: AgentStage,
    plan_id: PlanId,
    purpose: String,
    completed: &RunAgentCompleted,
    envelope: SignedRunEnvelope,
) -> Vec<u8> {
    let writ_output_oid = completed.output_oid.clone();
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

/// Tagged failure modes of [`write_stage_note`].
///
/// One enum where slice 3a had three, each with the same four
/// failures under a different noun. The stage travels *in* the
/// variants that need it, so an operator-facing message can still name
/// the right artefact without a per-stage enum to hang it on.
#[derive(Debug, Error)]
pub enum WriteStageNoteError {
    /// The repo-wide mutation lock could not be taken. A filesystem
    /// problem, not contention — the lock waits.
    #[error("locking bailiff's repo for mutation failed: {0}")]
    RepoLock(#[source] crate::bailiff_repo_guard::PlanGuardError),
    /// The shared fetch→verify phase failed before any note was
    /// written. See [`FetchVerifyError`] for the step-by-step matrix.
    #[error(transparent)]
    FetchVerify(#[from] FetchVerifyError),
    /// A note for this `(plan, stage)` already exists under
    /// [`plan_notes_ref`]`(plan_id)` at `target_oid`. Bailiff does not
    /// overwrite; the operator's recourse is to submit a fresh plan
    /// (repeat attempts are the documented `v1` → `v2` migration).
    #[error("{stage} already recorded for plan {plan_id} at target {target_oid}")]
    AlreadyRecorded {
        stage: AgentStage,
        plan_id: PlanId,
        target_oid: GitObjectId,
    },
    /// Writing the note to bailiff's repo failed for any reason other
    /// than the idempotency conflict. Usually a filesystem problem or
    /// a cross-process race that slipped past the per-repo mutex (see
    /// [`NotesRepo::write_note_if_absent`]'s docstring for the
    /// residual race surface).
    #[error("writing the {stage} note to bailiff's repo failed: {source}")]
    Write {
        stage: AgentStage,
        #[source]
        source: NotesRepoError,
    },
}

#[cfg(test)]
mod decision_tests;
#[cfg(test)]
mod end_to_end_tests;
// `plan_tests` / `review_tests` / `implement_tests` collapsed into
// `stage_tests` in slice 3b, along with the three write helpers they
// covered. Every case there runs for all three stages, so the coverage
// is strictly larger than the three modules it replaces.
#[cfg(test)]
mod stage_tests;
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
    use crate::bailiff_plan_note::{ImplementNote, PlanId, PlanNote, ReviewNote, plan_notes_ref};
    use proptest::prelude::*;
    use tempfile::TempDir;
    use writ::core::{CapabilitySet, RepoRef, SshSignature};
    use writ::signing::{WritSigningKey, WritVerifyingKey};

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

        /// For any valid payload and any stage, a trusted-signer
        /// write succeeds and the bailiff-side note reads back with
        /// exactly the envelope fields writ signed.
        ///
        /// Ranges over `AgentStage::ALL` rather than a local `Verb`
        /// enum. That enum was a *fourth* encoding of the three-stage
        /// distinction, alongside the three note types, the three
        /// writers, and the three error enums slice 3b collapsed —
        /// found only because deleting the writers broke it.
        #[test]
        fn every_stage_round_trips_a_trusted_envelope(
            stage_index in 0usize..AgentStage::ALL.len(),
            payload in arb_payload(),
        ) {
            let stage = AgentStage::ALL[stage_index];
            let tmp = TempDir::new().unwrap();
            let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
            let envelope = envelope_for(&signing_key, &payload);
            let (writ_repo, completed) = writ_repo_for(&tmp, &envelope);
            let bailiff = bailiff_repo(&tmp);
            let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
            let plan_id = PlanId::new();
            let purpose = "spec".to_string();

            let target = StageNoteTarget {
                stage,
                plan_id,
                writ_repo_path: writ_repo.path().to_path_buf(),
                allowed_signers: allowed.clone(),
            };
            let returned_oid = write_stage_note(
                &bailiff, &target, &writ_notes_ref(), purpose.clone(), &completed,
            ).expect("a trusted-signer write must succeed");

            prop_assert!(!stage.note_seed(plan_id).is_empty());
            let body = bailiff
                .read_note(&plan_notes_ref(plan_id), &returned_oid)
                .expect("bailiff-side note must be readable at the returned OID");

            // Decoded through the stage's own type: the three are
            // distinct on purpose, so decoding an implement note as a
            // `PlanNote` would succeed and prove nothing.
            let (got_plan_id, got_purpose, got_oid, got_meta, got_sig) = match stage {
                AgentStage::Submit => {
                    let n = PlanNote::from_canonical_bytes(&body).expect("body must decode");
                    (n.plan_id, n.purpose, n.writ_output_oid, n.signed_metadata, n.signature)
                }
                AgentStage::Review => {
                    let n = ReviewNote::from_canonical_bytes(&body).expect("body must decode");
                    (n.plan_id, n.purpose, n.writ_output_oid, n.signed_metadata, n.signature)
                }
                AgentStage::Implement => {
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
        /// Driven through the submission stage as representative;
        /// the phase is shared, so the stage is not the variable here.
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

            let target = StageNoteTarget {
                stage: AgentStage::Submit,
                plan_id: PlanId::new(),
                writ_repo_path: writ_repo.path().to_path_buf(),
                allowed_signers: allowed.clone(),
            };
            let err = write_stage_note(&bailiff, &target, &writ_notes_ref(), "spec".into(), &completed)
                .unwrap_err();
            match (fault, &err) {
                (0, WriteStageNoteError::FetchVerify(FetchVerifyError::EnvelopeMetadataMismatch)) => {}
                (1, WriteStageNoteError::FetchVerify(FetchVerifyError::EnvelopeSignatureMismatch)) => {}
                (2, WriteStageNoteError::FetchVerify(FetchVerifyError::Verify(VerifyError::UnknownSigner { .. }))) => {}
                _ => prop_assert!(false, "fault {fault} produced unexpected error: {err:?}"),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// **Every** stage's write is idempotent by error: the second
        /// write for a plan id is refused rather than silently
        /// overwriting the first.
        ///
        /// Was `review_and_implement_writes_are_idempotent`, over two
        /// stages. The submission was excluded because it alone called
        /// `write_note`, whose duplicate surfaced as a generic git
        /// failure rather than the typed conflict. Slice 3b made all
        /// three typed, so the property now holds for all three — and
        /// its scope is the record of that delta.
        #[test]
        fn every_stage_write_is_idempotent_by_error(
            stage_index in 0usize..AgentStage::ALL.len(),
            payload in arb_payload(),
        ) {
            let stage = AgentStage::ALL[stage_index];
            let tmp = TempDir::new().unwrap();
            let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
            let envelope = envelope_for(&signing_key, &payload);
            let (writ_repo, completed) = writ_repo_for(&tmp, &envelope);
            let bailiff = bailiff_repo(&tmp);
            let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
            let plan_id = PlanId::new();

            let target = StageNoteTarget {
                stage,
                plan_id,
                writ_repo_path: writ_repo.path().to_path_buf(),
                allowed_signers: allowed.clone(),
            };
            let write = || write_stage_note(
                &bailiff, &target, &writ_notes_ref(), "spec".into(), &completed,
            );
            let first = write().expect("first write succeeds");
            let err = write().unwrap_err();
            match err {
                WriteStageNoteError::AlreadyRecorded { stage: got, plan_id: pid, target_oid } => {
                    prop_assert_eq!(got, stage);
                    prop_assert_eq!(pid, plan_id);
                    prop_assert_eq!(target_oid, first);
                }
                other => prop_assert!(false, "{stage}: expected AlreadyRecorded, got {other:?}"),
            }
        }
    }
}
