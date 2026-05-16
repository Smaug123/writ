//! Slice-D2.4 workflow function that drives `bailiff plan review`:
//! read the planner's submission note, fetch + verify the signed
//! envelope it points to, decode the planner's stdout as the plan
//! body, compose the reviewer's effective prompt, open a writ
//! session, run the reviewer agent, persist a
//! [`crate::bailiff_plan_note::ReviewNote`] in bailiff's repo, close
//! the session.
//!
//! Sibling to [`crate::bailiff_plan_submit`]: the post-`OpenSession`
//! contract is identical (close-on-error on every later failure). The
//! novelty is the pre-RPC chain — bailiff is for the first time
//! reading back one of its own writ-signed envelopes to compose a
//! follow-up agent's prompt, and the byte-for-byte trip from
//! `SignedRunEnvelope` → `OutputEnvelope` → UTF-8 stdout is new
//! ground that every variant of [`ReadPlanBodyError`] guards.
//!
//! # Composition
//!
//! The reviewer prompt is `reviewer_instructions` + the
//! [`crate::bailiff::REVIEWER_PROMPT_SEPARATOR`] string + the plan
//! body bytes, joined inline (rather than via
//! [`crate::bailiff::compose_reviewer_prompt`]) so this slice does
//! not grow a fresh dependency on `agent_plan::PlanBody` — slice G
//! deletes that type, and re-wrapping bytes in `PlanBody` just to
//! unwrap them again would be churn. Sharing only the `&'static str`
//! separator keeps the two compositions phrase-identical until the
//! constant moves to its post-slice-G home.
//!
//! # Error handling
//!
//! Pre-RPC failures (read-side and prompt composition) return
//! without ever opening a writ session, so writ's audit log stays
//! clean. After the session opens, every failure path attempts to
//! close the session before returning. A close-during-cleanup
//! failure is suppressed in favour of the original error — the
//! original is always the more actionable one. Returning a
//! close-only failure is still surfaced when the workflow itself
//! succeeded.

use std::path::Path;
use std::string::FromUtf8Error;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinError;

use crate::agent_run::{AgentPrompt, AgentPromptError};
use crate::bailiff::REVIEWER_PROMPT_SEPARATOR;
use crate::bailiff_plan_note::{PlanId, PlanNote};
use crate::bailiff_plan_read::{ReadPlanError, read_plan_note};
use crate::bailiff_plan_write::{WRIT_V1_NOTES_REFSPEC, WriteReviewNoteError, write_review_note};
use crate::core::{AgentKind, CapabilitySet, NotesRef, SessionId};
use crate::notes_repo::{NotesRepo, NotesRepoError};
use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use crate::run_verify::{AllowedSigners, VerifyError, verify_run_envelope};
use crate::vm_git::GitObjectId;
use crate::writ_client::{RunAgentCompleted, RunAgentRequest, WritClient, WritClientError};

/// Inputs to [`submit_review`]. Mirror of [`crate::bailiff_plan_submit::SubmitPlanInputs`]
/// with `plan_id` non-optional (the plan must already exist) and
/// `reviewer_instructions` carrying the operator's prompt — the
/// composed prompt is built inside [`submit_review`] and never appears
/// on the input struct.
#[derive(Debug)]
pub struct SubmitReviewInputs {
    /// Plan to review. The submission note must already exist under
    /// [`crate::bailiff_plan_note::plan_notes_ref`]`(plan_id)` or
    /// [`submit_review`] surfaces [`SubmitReviewError::PlanSubmissionMissing`].
    pub plan_id: PlanId,
    /// Reviewer instructions the operator authored. The composed
    /// prompt is `reviewer_instructions` + separator + plan body;
    /// the boundary byte-cap check fires on the *composed* prompt,
    /// so a near-cap reviewer prompt can still overflow even though
    /// it parsed cleanly here.
    pub reviewer_instructions: AgentPrompt,
    /// Capabilities granted to the reviewer run. Today the CLI
    /// builds a single-element `Vec` with `WorkspaceRead` on the
    /// reviewer's target repo; the field is a `Vec` because the wire
    /// shape is and a future stage may grant several.
    pub capabilities: Vec<CapabilitySet>,
    /// Opaque tag bailiff sends on `RunAgent`. Writ stores it
    /// verbatim in its audit row and on the review note in bailiff's
    /// repo; useful for cross-correlation, never policy-interpreted.
    pub purpose: String,
    /// Notes ref bailiff asks writ to write the reviewer envelope
    /// to. Today this is always `refs/notes/writ/v1/agent-outputs`;
    /// surfacing it as a parameter (rather than a constant) keeps
    /// the function honest about the same ref bailiff later passes
    /// to [`write_review_note`].
    pub writ_output_ref: NotesRef,
    /// Optional human-readable session label. Stored on writ's audit
    /// session row; informational only.
    pub session_label: Option<String>,
    /// Optional coarse agent identity. Writ uses it for GitHub-App
    /// selection on credential mints; with a `WorkspaceRead`-only
    /// capability set the field is unused, but is plumbed so a
    /// future review run that mints GitHub credentials can pass it
    /// without a downstream refactor.
    pub session_agent_kind: Option<AgentKind>,
    /// Optional model identifier (e.g. `"claude-opus-4-7"`). Stored
    /// on writ's audit session row alongside `agent_kind`.
    pub session_agent_model: Option<String>,
}

/// Outcome of a successful [`submit_review`] call. Carries the
/// inputs a caller needs to refer back to the persisted artefacts
/// without re-deriving them.
#[derive(Clone, Debug)]
pub struct SubmitReviewOutcome {
    /// The plan id reviewed (passed through from
    /// [`SubmitReviewInputs::plan_id`]; surfaced again so the CLI
    /// can print it without juggling the input back to the call
    /// site).
    pub plan_id: PlanId,
    /// Bailiff-side OID where the review note is attached. The
    /// deterministic seed-blob OID
    /// [`crate::bailiff_plan_note::plan_review_seed_blob_bytes`]
    /// hashes to; callable readers can recompute it but having it
    /// on the result avoids the recomputation.
    pub review_note_oid: GitObjectId,
    /// Writ's session id for the *reviewer run only* — the
    /// authority/audit window writ minted for this `RunAgent` call,
    /// closed on the happy path before this outcome is returned.
    /// Surfaced so callers can correlate the run with writ's audit
    /// row; not a handle later workflow stages reuse.
    pub reviewer_session_id: SessionId,
    /// What writ returned for the reviewer run — the OID of the
    /// signed envelope note in writ's repo, plus the signed metadata
    /// and signature. Lets a caller verify or display the run
    /// without a second round-trip.
    pub run: RunAgentCompleted,
}

/// Drive the full plan-review workflow against a live writ broker.
///
/// `bailiff_repo` is taken as an [`Arc`]`<`[`AsyncMutex`]`<_>>` so
/// the single-writer invariant on bailiff's bare repo is visible at
/// the call site and the workflow can compose with other in-flight
/// bailiff operations sharing the same handle (today there are none,
/// but the lock makes the contract explicit).
pub async fn submit_review(
    client: &WritClient,
    bailiff_repo: Arc<AsyncMutex<NotesRepo>>,
    writ_repo_path: &Path,
    allowed_signers: AllowedSigners,
    inputs: SubmitReviewInputs,
) -> Result<SubmitReviewOutcome, SubmitReviewError> {
    // Pre-RPC: read the submission note, fetch+verify+decode the
    // planner envelope, extract the plan body. Done before opening
    // a session so a missing or unverifiable submission never burns
    // a writ audit row.
    let plan_id = inputs.plan_id;
    let writ_repo_path_owned = writ_repo_path.to_path_buf();
    let writ_output_ref_for_read = inputs.writ_output_ref.clone();
    let allowed_for_read = allowed_signers.clone();
    let bailiff_for_read = Arc::clone(&bailiff_repo);
    let read_outcome =
        tokio::task::spawn_blocking(move || -> Result<(PlanNote, String), SubmitReviewError> {
            let bailiff = bailiff_for_read.blocking_lock();
            let plan_note =
                match read_plan_note(&bailiff, plan_id).map_err(SubmitReviewError::ReadPlanNote)? {
                    Some(note) => note,
                    None => return Err(SubmitReviewError::PlanSubmissionMissing { plan_id }),
                };
            let body = read_plan_body_bytes(
                &bailiff,
                &writ_repo_path_owned,
                &writ_output_ref_for_read,
                &plan_note,
                &allowed_for_read,
            )
            .map_err(SubmitReviewError::ReadPlanEnvelope)?;
            Ok((plan_note, body))
        })
        .await
        .map_err(SubmitReviewError::ReadTaskFailed)?;
    let (_plan_note, plan_body) = read_outcome?;

    let reviewer_prompt =
        compose_reviewer_prompt_bytes(inputs.reviewer_instructions.as_str(), plan_body.as_str())
            .map_err(SubmitReviewError::ComposeReviewerPrompt)?;

    let session_id = client
        .open_session(
            inputs.session_label.clone(),
            inputs.session_agent_kind,
            inputs.session_agent_model.clone(),
        )
        .await
        .map_err(SubmitReviewError::OpenSession)?;

    // From here on, every early return must close the session.
    let run_result = client
        .run_agent(RunAgentRequest {
            prompt: reviewer_prompt,
            capabilities: inputs.capabilities,
            purpose: inputs.purpose.clone(),
            output_ref: inputs.writ_output_ref.clone(),
            session_id: Some(session_id),
        })
        .await;
    let completed = match run_result {
        Ok(c) => c,
        Err(source) => {
            let _ = client.close_session(session_id).await;
            return Err(SubmitReviewError::RunAgent { session_id, source });
        }
    };

    // Cross-check the broker honoured the session binding we asked
    // for: the signed metadata must stamp the same session id we
    // opened. A mismatch means the broker minted its own id and the
    // envelope can't be correlated with our audit row — refuse to
    // persist the review note.
    if completed.signed_metadata.session_id != session_id {
        let returned_session_id = completed.signed_metadata.session_id;
        let _ = client.close_session(session_id).await;
        return Err(SubmitReviewError::SessionIdMismatch {
            session_id,
            returned_session_id,
        });
    }

    // `write_review_note` shells out to git; wrap in `spawn_blocking`
    // and hold the bailiff-repo lock for the blocking section only.
    let writ_repo_path_owned = writ_repo_path.to_path_buf();
    let writ_output_ref_clone = inputs.writ_output_ref.clone();
    let purpose_clone = inputs.purpose.clone();
    let completed_clone = completed.clone();
    let bailiff_for_write = Arc::clone(&bailiff_repo);
    let write_outcome = tokio::task::spawn_blocking(move || {
        let bailiff = bailiff_for_write.blocking_lock();
        write_review_note(
            &bailiff,
            &writ_repo_path_owned,
            &writ_output_ref_clone,
            plan_id,
            purpose_clone,
            &completed_clone,
            &allowed_signers,
        )
    })
    .await;
    let review_note_oid = match write_outcome {
        Ok(Ok(oid)) => oid,
        Ok(Err(source)) => {
            let _ = client.close_session(session_id).await;
            return Err(SubmitReviewError::WriteReviewNote { session_id, source });
        }
        Err(source) => {
            let _ = client.close_session(session_id).await;
            return Err(SubmitReviewError::WriteTaskFailed { session_id, source });
        }
    };

    if let Err(source) = client.close_session(session_id).await {
        return Err(SubmitReviewError::CloseSession { session_id, source });
    }

    Ok(SubmitReviewOutcome {
        plan_id,
        review_note_oid,
        reviewer_session_id: session_id,
        run: completed,
    })
}

/// Compose the reviewer's effective prompt from operator instructions
/// and the planner's plan body. Inline counterpart to
/// [`crate::bailiff::compose_reviewer_prompt`] that takes raw `&str`
/// rather than `agent_plan::PlanBody` — slice G deletes that type
/// and re-wrapping bytes in it just to unwrap them is churn. The
/// separator string is the same `&'static str` the existing
/// composer uses so both renderings stay phrase-identical.
fn compose_reviewer_prompt_bytes(
    reviewer_instructions: &str,
    plan_body: &str,
) -> Result<AgentPrompt, AgentPromptError> {
    let mut combined = String::with_capacity(
        reviewer_instructions.len() + REVIEWER_PROMPT_SEPARATOR.len() + plan_body.len(),
    );
    combined.push_str(reviewer_instructions);
    combined.push_str(REVIEWER_PROMPT_SEPARATOR);
    combined.push_str(plan_body);
    AgentPrompt::try_new(combined)
}

/// Resolve the planner envelope referenced by `plan_note` and
/// return its stdout bytes (the plan body) as a UTF-8 [`String`].
///
/// Steps, each guarded by a distinct [`ReadPlanBodyError`] variant:
///
/// 1. Fetch writ's notes refspec into bailiff's repo (`Fetch`).
/// 2. Read the envelope note from writ's notes ref at
///    `plan_note.writ_output_oid` (`ReadEnvelope`).
/// 3. Decode the body as a [`SignedRunEnvelope`] (`DecodeEnvelope`).
/// 4. Defence-in-depth parity checks: the envelope on disk must
///    carry the same `metadata` and `signature` the plan note
///    recorded at submission time (`EnvelopeMetadataMismatch`,
///    `EnvelopeSignatureMismatch`). A divergence means either
///    bailiff's plan note or writ's repo was tampered with after
///    submission.
/// 5. Re-verify the envelope under `allowed_signers` so a tampered
///    `output` field (the signed payload) is caught before its
///    bytes are spliced into the reviewer prompt (`Verify`).
/// 6. Decode the envelope's `output` field as an [`OutputEnvelope`]
///    (`DecodeOutput`).
/// 7. Refuse to use truncated stdout (`OutputTruncated`) — a partial
///    plan body could mislead the reviewer into approving an
///    incomplete spec.
/// 8. UTF-8-decode the stdout bytes (`OutputNotUtf8`); the planner's
///    stdout *is* the plan body and a non-text body is a protocol
///    violation per `docs/plans/2026-05-16-slice-d2-review.md`.
///
/// Why re-verify? `write_plan_note` already ran
/// `verify_run_envelope` at submission time, so a fresh signature
/// check looks redundant. It is not: between submission and review
/// the envelope on disk could be replaced (manual repo repair, a
/// faulty mirror, etc.), and the plan body becomes part of the
/// reviewer prompt — the LLM acts on it. A second verify costs
/// microseconds and forecloses an entire class of "I tampered with
/// the planner's stdout between submission and review" attacks.
///
/// Empty stdout is *not* rejected: an LLM planner that produced no
/// output is a downstream concern the reviewer can flag, and an
/// empty `plan_body` slot in the composed prompt is observable
/// rather than spoof-able.
fn read_plan_body_bytes(
    bailiff_repo: &NotesRepo,
    writ_repo_path: &Path,
    writ_notes_ref: &NotesRef,
    plan_note: &PlanNote,
    allowed_signers: &AllowedSigners,
) -> Result<String, ReadPlanBodyError> {
    bailiff_repo
        .fetch_from_remote(writ_repo_path, &[WRIT_V1_NOTES_REFSPEC])
        .map_err(ReadPlanBodyError::Fetch)?;
    let body = bailiff_repo
        .read_note(writ_notes_ref, &plan_note.writ_output_oid)
        .map_err(ReadPlanBodyError::ReadEnvelope)?;
    let envelope =
        SignedRunEnvelope::from_bytes(&body).map_err(ReadPlanBodyError::DecodeEnvelope)?;
    if envelope.metadata != plan_note.signed_metadata {
        return Err(ReadPlanBodyError::EnvelopeMetadataMismatch);
    }
    if envelope.signature != plan_note.signature {
        return Err(ReadPlanBodyError::EnvelopeSignatureMismatch);
    }
    verify_run_envelope(&envelope, allowed_signers).map_err(ReadPlanBodyError::Verify)?;
    let output =
        OutputEnvelope::from_bytes(&envelope.output).map_err(ReadPlanBodyError::DecodeOutput)?;
    if let Some(stdout_truncated_at) = output.stdout_truncated_at {
        return Err(ReadPlanBodyError::OutputTruncated {
            stdout_truncated_at,
        });
    }
    String::from_utf8(output.stdout).map_err(ReadPlanBodyError::OutputNotUtf8)
}

/// Tagged failure modes of the planner-envelope read step that
/// `submit_review` performs before composing the reviewer prompt.
/// Each variant pins one concrete step of the planner-envelope →
/// plan-body extraction so the workflow caller can map it to the
/// right operator message: "writ repo path wrong" vs "envelope on
/// disk diverges from the recorded plan note" vs "planner output
/// isn't text" are all distinct problems.
#[derive(Debug, Error)]
pub enum ReadPlanBodyError {
    /// `git fetch` against writ's repo failed. Usually a wrong
    /// `writ_repo_path` or a filesystem permission problem.
    #[error("fetching writ's notes ref failed: {0}")]
    Fetch(#[source] NotesRepoError),
    /// The fetch succeeded but no note exists at the plan note's
    /// `writ_output_oid` under `writ_notes_ref`. Either the fetch
    /// refspec didn't cover the ref writ used for the planner run,
    /// or writ's repo was pruned since submission.
    #[error("reading the planner envelope note failed: {0}")]
    ReadEnvelope(#[source] NotesRepoError),
    /// The note body exists but isn't a valid [`SignedRunEnvelope`].
    /// Indicates wire-level corruption — `deny_unknown_fields` and
    /// the strict newtype validators make this near-impossible for
    /// any envelope writ itself produced.
    #[error("decoding the planner envelope failed: {0}")]
    DecodeEnvelope(#[source] serde_json::Error),
    /// The envelope's `metadata` on disk differs from the
    /// `signed_metadata` the plan note recorded at submission time.
    /// Defence-in-depth: between submission and review, either
    /// bailiff's plan note or writ's repo was tampered with.
    /// Bailiff refuses to use the on-disk bytes for prompt
    /// composition in either case.
    #[error(
        "planner envelope metadata on disk does not match the metadata recorded in the plan \
         submission note"
    )]
    EnvelopeMetadataMismatch,
    /// Same defence-in-depth check as [`Self::EnvelopeMetadataMismatch`]
    /// but for the signature field. Pinned distinct from the metadata
    /// mismatch because the two have different operator
    /// implications: a metadata mismatch with a valid signature
    /// suggests bailiff's note was edited; a signature mismatch
    /// with matching metadata suggests writ's repo was replaced.
    #[error(
        "planner envelope signature on disk does not match the signature recorded in the plan \
         submission note"
    )]
    EnvelopeSignatureMismatch,
    /// [`verify_run_envelope`] rejected the envelope. The wrapped
    /// [`VerifyError`] names whether the failure was an output
    /// digest mismatch, an unknown signer, or a bad signature.
    /// Caught here so a tampered `output` field (the bytes the
    /// reviewer will see) never reaches the prompt composer.
    #[error("re-verifying the planner envelope failed: {0}")]
    Verify(#[source] VerifyError),
    /// The envelope verified but its `output` field doesn't decode
    /// as an [`OutputEnvelope`]. Indicates wire-level corruption
    /// inside the signed payload — would require the signing key
    /// to be compromised, since the digest covers these bytes.
    #[error("decoding the planner output envelope failed: {0}")]
    DecodeOutput(#[source] serde_json::Error),
    /// The planner's stdout was truncated by writ at byte offset
    /// `stdout_truncated_at`. The captured prefix is genuinely
    /// signed, but using only a prefix as the plan body could
    /// mislead the reviewer into approving an incomplete spec —
    /// the operator's recourse is to re-run the planner with a
    /// narrower scope so the body fits writ's per-stream cap.
    #[error("planner stdout was truncated at byte offset {stdout_truncated_at}")]
    OutputTruncated { stdout_truncated_at: u64 },
    /// The planner's stdout bytes are not valid UTF-8. The planner
    /// is contracted to emit a human-readable plan body; non-text
    /// output is a protocol violation. Surfacing the
    /// [`FromUtf8Error`] preserves the byte offset where the
    /// invalid sequence began.
    #[error("planner stdout is not valid UTF-8: {0}")]
    OutputNotUtf8(#[source] FromUtf8Error),
}

/// Tagged failure modes of [`submit_review`]. Pre-RPC variants
/// return before any writ session is opened; post-RPC variants
/// carry the [`SessionId`] [`submit_review`] minted, and by the
/// time the variant is returned, [`submit_review`] has *attempted*
/// to close that session. `CloseSession` is the one variant where
/// the close itself failed — the session may still be open.
#[derive(Debug, Error)]
pub enum SubmitReviewError {
    /// The `spawn_blocking` task that owns the pre-RPC read chain
    /// panicked or was cancelled. Surfaces separately from
    /// `ReadPlanNote` / `ReadPlanEnvelope` because the cause is a
    /// tokio-runtime condition, not a bailiff/writ contract
    /// violation. Pre-RPC: no session was opened.
    #[error("plan-body read task failed: {0}")]
    ReadTaskFailed(#[source] JoinError),
    /// [`read_plan_note`] returned an error. Distinct from
    /// [`Self::PlanSubmissionMissing`] (which is the `Ok(None)`
    /// case) so the operator can tell "bailiff's repo is broken"
    /// from "this plan has no submission yet." Pre-RPC.
    #[error("reading the plan submission note failed: {0}")]
    ReadPlanNote(#[source] ReadPlanError),
    /// Bailiff was asked to review a plan with no submission note
    /// recorded. The plan id may be wrong, or the operator may
    /// have asked for a review before `bailiff plan submit` ran.
    /// Pre-RPC.
    #[error("no plan submission note recorded for plan {plan_id}")]
    PlanSubmissionMissing { plan_id: PlanId },
    /// The fetch / verify / decode chain that extracts the plan
    /// body from the planner envelope failed. The wrapped
    /// [`ReadPlanBodyError`] names the specific step. Pre-RPC.
    #[error("reading the planner envelope failed: {0}")]
    ReadPlanEnvelope(#[source] ReadPlanBodyError),
    /// The composed reviewer prompt (`reviewer_instructions` +
    /// separator + `plan_body`) exceeded
    /// [`crate::agent_run::MAX_AGENT_PROMPT_BYTES`]. Either the
    /// reviewer instructions are large, the plan body is large, or
    /// both — the operator's recourse is to narrow one side.
    /// Pre-RPC.
    #[error("composing the reviewer prompt failed: {0}")]
    ComposeReviewerPrompt(#[source] AgentPromptError),
    /// The initial `OpenSession` RPC failed. Workflow never
    /// started; no cleanup needed.
    #[error("opening writ session failed: {0}")]
    OpenSession(#[source] WritClientError),
    /// The `RunAgent` RPC failed. The session was closed before
    /// returning this error so writ's audit log shows the workflow
    /// ended cleanly.
    #[error("RunAgent RPC failed (session {session_id}): {source}")]
    RunAgent {
        session_id: SessionId,
        #[source]
        source: WritClientError,
    },
    /// The broker stamped a different session id into the signed
    /// metadata than the one we asked it to bind. Indicates the
    /// broker is at a wire version that ignores the `session_id`
    /// field — the envelope is unusable because it can't be
    /// correlated to our audit row. The session bailiff opened was
    /// closed before this error returned; no bailiff-side review
    /// note is written.
    #[error(
        "broker returned signed metadata bound to session {returned_session_id}, \
         expected {session_id}"
    )]
    SessionIdMismatch {
        /// The session id bailiff opened and passed in `RunAgent`.
        session_id: SessionId,
        /// The session id the broker actually stamped into the
        /// signed metadata.
        returned_session_id: SessionId,
    },
    /// Fetch/verify/write of the bailiff-side review note failed.
    /// Writ already ran the reviewer agent and signed the envelope,
    /// so an operator can re-attempt the review-note write against
    /// the same envelope without re-running the agent. Includes the
    /// idempotency-conflict case
    /// ([`WriteReviewNoteError::ReviewAlreadyRecorded`]).
    #[error("writing the bailiff-side review note failed (session {session_id}): {source}")]
    WriteReviewNote {
        session_id: SessionId,
        #[source]
        source: WriteReviewNoteError,
    },
    /// The `spawn_blocking` task that owns the `write_review_note`
    /// call panicked or was cancelled. Surfaces separately from
    /// `WriteReviewNote` because the cause is a tokio-runtime
    /// condition, not a bailiff/writ contract violation.
    #[error("review-note write task failed (session {session_id}): {source}")]
    WriteTaskFailed {
        session_id: SessionId,
        #[source]
        source: JoinError,
    },
    /// The review note was written but the closing `CloseSession`
    /// failed. The workflow's persistent state (the review note in
    /// bailiff's repo) is already in place; this is a session-row
    /// cleanup failure that an operator can ignore in most cases,
    /// but the variant surfaces it so scripts can react if needed.
    #[error("closing writ session {session_id} after review submit failed: {source}")]
    CloseSession {
        session_id: SessionId,
        #[source]
        source: WritClientError,
    },
}

#[cfg(test)]
mod read_plan_body_tests {
    //! Unit tests for [`read_plan_body_bytes`]. Each test plants a
    //! known envelope in a writ repo via the same `NotesRepo`
    //! primitives the production writer uses, then probes a single
    //! failure mode. The helper is the new defence-in-depth surface
    //! for "bailiff reads its own signed envelopes back" so every
    //! variant of [`ReadPlanBodyError`] gets a pinned test.
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_plan_note::PlanId;
    use crate::core::{CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
    use crate::protocol::SignedRunMetadata;
    use crate::signing::WritSigningKey;
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");
    const OTHER_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing_other.key.pub");

    fn writ_notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

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
    fn writ_repo_and_plan_note(
        tmp: &TempDir,
        envelope: &SignedRunEnvelope,
    ) -> (NotesRepo, PlanNote) {
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
}

#[cfg(test)]
mod compose_tests {
    //! Tests for [`compose_reviewer_prompt_bytes`]. The composer
    //! is intentionally tiny — same shape as the existing
    //! [`crate::bailiff::compose_reviewer_prompt`] but taking
    //! `&str` — and the two tests pin the load-bearing properties:
    //! the separator appears verbatim, and the byte cap fires on
    //! the combined length.
    use super::*;

    #[test]
    fn separator_appears_verbatim_between_instructions_and_body() {
        let composed =
            compose_reviewer_prompt_bytes("Evaluate the plan.", "# Plan\n\nDo a thing.\n").unwrap();
        let expected =
            format!("Evaluate the plan.{REVIEWER_PROMPT_SEPARATOR}# Plan\n\nDo a thing.\n");
        assert_eq!(composed.as_str(), expected);
    }

    #[test]
    fn errors_when_combined_exceeds_agent_prompt_limit() {
        // Instructions at the cap, non-empty plan body, plus the
        // separator must overflow `AgentPrompt::try_new`.
        let instructions = "x".repeat(crate::agent_run::MAX_AGENT_PROMPT_BYTES);
        let err = compose_reviewer_prompt_bytes(&instructions, "p").unwrap_err();
        assert!(err.to_string().contains("exceeding"), "{err}");
    }
}

#[cfg(test)]
mod end_to_end_tests {
    //! End-to-end against a real writ broker. Pattern mirrors
    //! [`crate::bailiff_plan_submit::end_to_end_tests`]: bring up
    //! the broker, plant a planner envelope so a submission note
    //! can be recorded, drive `submit_review`, assert the review
    //! note lands in bailiff's repo and the session row in writ's
    //! audit log transitions open → closed.
    use std::collections::{BTreeMap, HashMap};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use wiremock::MockServer;

    use super::*;
    use crate::audit::AuditLog;
    use crate::bailiff_plan_note::{ReviewNote, plan_notes_ref};
    use crate::bailiff_plan_submit::{SubmitPlanInputs, submit_plan};
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
    use crate::writ_client::WritClient;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");
    const TEST_PRIV: &str = include_str!("../tests/fixtures/rsa_test_1.pem");

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

    /// Build a broker, return (state, socket path, broker join
    /// handle). Reused across the three end-to-end tests.
    async fn spawn_broker(
        tmp: &tempfile::TempDir,
        signing_key: WritSigningKey,
    ) -> (
        Arc<BrokerState<InMemStore>>,
        std::path::PathBuf,
        tokio::task::JoinHandle<()>,
    ) {
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
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
            signing_key: Some(signing_key),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: cat,
                args: Vec::new(),
            }),
        });
        let socket_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let socket_path = socket_dir.path().join("writ.sock");
        std::mem::forget(socket_dir);
        let listener = prepare_broker_listener(&socket_path).await.unwrap();
        let broker_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let _ = serve_broker_with_agent_vm(listener, broker_state, None).await;
        });
        (state, socket_path, task)
    }

    /// Run `submit_plan` against the broker so a submission note is
    /// recorded in bailiff's repo. Returns the plan id and bailiff
    /// repo handle so the caller can drive a `submit_review` against
    /// the same plan.
    async fn record_submission(
        bailiff: &Arc<AsyncMutex<NotesRepo>>,
        client: &WritClient,
        writ_repo_path: &Path,
        allowed: &AllowedSigners,
        plan_body: &str,
    ) -> PlanId {
        let plan_id = PlanId::new();
        let inputs = SubmitPlanInputs {
            prompt: AgentPrompt::try_new(plan_body).unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            purpose: "plan-submit".into(),
            writ_output_ref: NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_label: Some("plan-submit:test".into()),
            session_agent_kind: Some(AgentKind::Claude),
            session_agent_model: Some("claude-test".into()),
            plan_id,
        };
        submit_plan(
            client,
            Arc::clone(bailiff),
            writ_repo_path,
            allowed.clone(),
            inputs,
        )
        .await
        .expect("submit_plan must succeed for the submission fixture");
        plan_id
    }

    /// Happy path: submit a plan first (so bailiff has a submission
    /// note to read), then drive `submit_review`. The review note
    /// must decode from bailiff's repo and reference the reviewer's
    /// writ-side OID; the reviewer's session must close.
    #[tokio::test]
    async fn submit_review_round_trips_through_open_run_write_close() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo));
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let client = WritClient::new(&socket_path);

        // `cat` echoes its stdin to stdout — submitting "the plan
        // body" produces an envelope whose stdout *is* "the plan
        // body". This is the round-trip property D2 hangs on.
        let plan_body = "# Plan\n\nReplace bar with baz.\n";
        let plan_id =
            record_submission(&bailiff, &client, &writ_repo_path, &allowed, plan_body).await;

        let inputs = SubmitReviewInputs {
            plan_id,
            reviewer_instructions: AgentPrompt::try_new("Evaluate the plan.").unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            purpose: "plan-review".into(),
            writ_output_ref: NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_label: Some("plan-review:test".into()),
            session_agent_kind: Some(AgentKind::Claude),
            session_agent_model: Some("claude-test".into()),
        };

        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            submit_review(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed.clone(),
                inputs,
            ),
        )
        .await
        .expect("submit_review must complete within 15s")
        .expect("submit_review must succeed under the trusted-signer keyring");

        assert_eq!(outcome.plan_id, plan_id);
        assert_eq!(
            outcome.run.signed_metadata.session_id, outcome.reviewer_session_id,
            "signed metadata must bind the session id bailiff opened",
        );

        // Review note decodes from bailiff's repo and references the
        // writ-side OID writ returned for the reviewer run.
        let bailiff_for_read = Arc::clone(&bailiff);
        let plan_ref = plan_notes_ref(plan_id);
        let oid = outcome.review_note_oid.clone();
        let body = tokio::task::spawn_blocking(move || {
            let bailiff = bailiff_for_read.blocking_lock();
            bailiff.read_note(&plan_ref, &oid)
        })
        .await
        .unwrap()
        .expect("bailiff-side review note must be readable at the returned OID");
        let note = ReviewNote::from_canonical_bytes(&body).unwrap();
        assert_eq!(note.plan_id, plan_id);
        assert_eq!(note.purpose, "plan-review");
        assert_eq!(note.writ_output_oid, outcome.run.output_oid);
        assert_eq!(note.signed_metadata, outcome.run.signed_metadata);
        assert_eq!(note.signature, outcome.run.signature);

        // Writ's audit log records the reviewer session as closed.
        let audit = Arc::clone(&state.audit);
        let session_id = outcome.reviewer_session_id;
        let session_row = tokio::task::spawn_blocking(move || audit.get_session(session_id))
            .await
            .unwrap()
            .expect("session row read must succeed")
            .expect("reviewer session must exist in audit log");
        assert!(
            session_row.closed_at.is_some(),
            "reviewer session must be closed after submit_review returns"
        );

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Pre-RPC: `submit_review` against a plan id that has no
    /// submission note returns `PlanSubmissionMissing` *without
    /// opening a session*. Verified by inspecting writ's audit log:
    /// no session row should exist for an id that was never opened.
    #[tokio::test]
    async fn submit_review_returns_plan_submission_missing_without_opening_session() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo));
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let client = WritClient::new(&socket_path);
        let plan_id = PlanId::new();

        let inputs = SubmitReviewInputs {
            plan_id,
            reviewer_instructions: AgentPrompt::try_new("Evaluate.").unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            purpose: "plan-review".into(),
            writ_output_ref: NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_label: None,
            session_agent_kind: Some(AgentKind::Claude),
            session_agent_model: None,
        };
        let err = tokio::time::timeout(
            Duration::from_secs(15),
            submit_review(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed,
                inputs,
            ),
        )
        .await
        .expect("submit_review must return within 15s")
        .expect_err("missing submission must surface as PlanSubmissionMissing");

        match err {
            SubmitReviewError::PlanSubmissionMissing { plan_id: found } => {
                assert_eq!(found, plan_id);
            }
            other => panic!("expected PlanSubmissionMissing, got: {other:?}"),
        }
        // The variant alone witnesses that `open_session` was never
        // reached: `submit_review` returns `PlanSubmissionMissing`
        // strictly before the `client.open_session` call.

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Second `submit_review` against an already-reviewed plan
    /// propagates `WriteReviewNote { source: ReviewAlreadyRecorded }`
    /// and still closes the second reviewer's session. The first
    /// review note remains intact (the idempotency guard rejects
    /// the write rather than overwriting).
    #[tokio::test]
    async fn submit_review_propagates_review_already_recorded_and_closes_session() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo));
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let client = WritClient::new(&socket_path);

        let plan_body = "# Plan\n\nReplace bar with baz.\n";
        let plan_id =
            record_submission(&bailiff, &client, &writ_repo_path, &allowed, plan_body).await;

        let inputs = || SubmitReviewInputs {
            plan_id,
            reviewer_instructions: AgentPrompt::try_new("Evaluate.").unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            purpose: "plan-review".into(),
            writ_output_ref: NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_label: None,
            session_agent_kind: Some(AgentKind::Claude),
            session_agent_model: None,
        };

        let first = tokio::time::timeout(
            Duration::from_secs(15),
            submit_review(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed.clone(),
                inputs(),
            ),
        )
        .await
        .expect("first submit_review must return within 15s")
        .expect("first submit_review must succeed");

        let err = tokio::time::timeout(
            Duration::from_secs(15),
            submit_review(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed.clone(),
                inputs(),
            ),
        )
        .await
        .expect("second submit_review must return within 15s")
        .expect_err("second submit_review must reject the duplicate");

        let session_id = match &err {
            SubmitReviewError::WriteReviewNote {
                session_id,
                source: WriteReviewNoteError::ReviewAlreadyRecorded { plan_id: rec, .. },
            } => {
                assert_eq!(*rec, plan_id);
                *session_id
            }
            other => panic!("expected WriteReviewNote{{ReviewAlreadyRecorded}}, got: {other:?}"),
        };
        assert_ne!(
            session_id, first.reviewer_session_id,
            "second submit_review must open a fresh session",
        );

        // The second reviewer's session must still close even
        // though `write_review_note` rejected the duplicate.
        let audit = Arc::clone(&state.audit);
        let session_row = tokio::task::spawn_blocking(move || audit.get_session(session_id))
            .await
            .unwrap()
            .expect("session row read must succeed")
            .expect("second reviewer session must exist in audit log");
        assert!(
            session_row.closed_at.is_some(),
            "second submit_review must close its session on ReviewAlreadyRecorded",
        );

        broker_task.abort();
        let _ = broker_task.await;
    }
}
