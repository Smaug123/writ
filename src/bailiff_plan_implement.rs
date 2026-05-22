//! Slice-E4b workflow function that drives `bailiff plan implement`:
//! read the planner's submission note, gate on bailiff's decision note
//! recording an *accepted* verdict, fetch + verify the signed planner
//! envelope, decode the planner's stdout as the plan body, compose the
//! implementer's effective prompt from the operator's feature prompt
//! and the approved plan body, open a writ session, run the implementer
//! agent, persist a [`crate::bailiff_plan_note::ImplementNote`] in
//! bailiff's repo, close the session.
//!
//! Sibling to [`crate::bailiff_plan_review::submit_review`]: the
//! post-`OpenSession` contract is identical (close-on-error on every
//! later failure) and the pre-RPC fetch-verify-decode chain is the
//! same lifted `read_plan_body_bytes` helper. The two novelties of
//! the implement workflow are:
//!
//! 1. The decision-note gate. Per slice E of
//!    `docs/plans/2026-05-14-bailiff-split.md`: "the *is the plan
//!    accepted?* gate lives in bailiff's read-side: refuse to compose
//!    unless bailiff's own decision note says accepted." Bailiff
//!    surfaces three pre-RPC error variants — `PlanSubmissionMissing`,
//!    `PlanNotDecided`, `PlanRejected` — so an operator can tell which
//!    precondition tripped.
//! 2. The composed prompt uses [`PLAN_PROMPT_SEPARATOR`]
//!    (`# Approved plan`), not the reviewer's `# Proposed plan`. The
//!    implementer is acting on an accepted artefact and the prompt
//!    framing makes that explicit so an LLM reading the combined
//!    prompt cannot mistake the plan's status.
//!
//! # Composition
//!
//! The implementer prompt is `feature_prompt` + the
//! [`PLAN_PROMPT_SEPARATOR`] string + the plan body bytes, joined
//! inline (rather than wrapping into `agent_plan::PlanBody` first)
//! to avoid re-wrapping bytes just to unwrap them again for signing.
//!
//! Reviewer feedback stays *out* of the composed prompt: per
//! `docs/plans/2026-05-11-agent-plans.md` §"Implementer prompt
//! construction" reviewer feedback drives the *decision*, not the
//! execution. The review note is therefore not consulted here.
//!
//! # Error handling
//!
//! Pre-RPC failures (read-side, decision gate, prompt composition)
//! return without ever opening a writ session, so writ's audit log
//! stays clean. After the session opens, every failure path attempts
//! to close the session before returning. A close-during-cleanup
//! failure is suppressed in favour of the original error — the
//! original is always the more actionable one. Returning a
//! close-only failure is still surfaced when the workflow itself
//! succeeded.

use std::path::Path;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinError;

use crate::agent_run::{AgentPrompt, AgentPromptError};
use crate::bailiff_decision::Decision;
use crate::bailiff_plan_note::{PlanId, PlanNote};
use crate::bailiff_plan_read::{
    ReadDecisionError, ReadImplementError, ReadPlanBodyError, ReadPlanError, read_decision_note,
    read_implement_note, read_plan_body_bytes, read_plan_note,
};
use crate::bailiff_plan_write::{WriteImplementNoteError, write_implement_note};
use crate::bailiff_repo_guard::BailiffRepoGuard;
use crate::core::{AgentKind, CapabilitySet, NotesRef, SessionId};
use crate::notes_repo::NotesRepo;
use crate::run_verify::AllowedSigners;
use crate::vm_git::GitObjectId;
use crate::writ_client::{RunAgentCompleted, RunAgentRequest, WritClient, WritClientError};

/// Inputs to [`submit_implement`]. Mirror of
/// [`crate::bailiff_plan_review::SubmitReviewInputs`] with
/// `feature_prompt` carrying the operator's original feature request
/// — the composed implementer prompt is built inside
/// [`submit_implement`] and never appears on the input struct.
#[derive(Debug)]
pub struct SubmitImplementInputs {
    /// Plan to implement. Both the submission note and an *accepted*
    /// decision note must already exist under
    /// [`crate::bailiff_plan_note::plan_notes_ref`]`(plan_id)` or
    /// [`submit_implement`] surfaces [`SubmitImplementError::PlanSubmissionMissing`]
    /// / [`SubmitImplementError::PlanNotDecided`] /
    /// [`SubmitImplementError::PlanRejected`] respectively.
    pub plan_id: PlanId,
    /// The operator's original feature prompt — the request that
    /// triggered the plan. The composed prompt is `feature_prompt` +
    /// separator + plan body; the boundary byte-cap check fires on
    /// the *composed* prompt, so a near-cap feature prompt can still
    /// overflow even though it parsed cleanly here.
    pub feature_prompt: AgentPrompt,
    /// Capabilities granted to the implementer run. The CLI builds a
    /// single-element `Vec` with `WorkspaceWrite` on the
    /// implementer's target repo; the field is a `Vec` because the
    /// wire shape is and a future stage may grant several.
    pub capabilities: Vec<CapabilitySet>,
    /// Opaque tag bailiff sends on `RunAgent`. Writ stores it
    /// verbatim in its audit row and on the implement note in
    /// bailiff's repo; useful for cross-correlation, never
    /// policy-interpreted.
    pub purpose: String,
    /// Notes ref bailiff asks writ to write the implementer envelope
    /// to. Today this is always `refs/notes/writ/v1/agent-outputs`;
    /// surfacing it as a parameter (rather than a constant) keeps
    /// the function honest about the same ref bailiff later passes
    /// to [`write_implement_note`].
    pub writ_output_ref: NotesRef,
    /// Optional human-readable session label. Stored on writ's audit
    /// session row; informational only.
    pub session_label: Option<String>,
    /// Optional coarse agent identity. Writ uses it for GitHub-App
    /// selection on credential mints; with a `WorkspaceWrite`
    /// capability set the field selects which GitHub App to use for
    /// the implementer's push credentials.
    pub session_agent_kind: Option<AgentKind>,
    /// Optional model identifier (e.g. `"claude-opus-4-7"`). Stored
    /// on writ's audit session row alongside `agent_kind`.
    pub session_agent_model: Option<String>,
}

/// Outcome of a successful [`submit_implement`] call. Carries the
/// inputs a caller needs to refer back to the persisted artefacts
/// without re-deriving them.
#[derive(Clone, Debug)]
pub struct SubmitImplementOutcome {
    /// The plan id implemented (passed through from
    /// [`SubmitImplementInputs::plan_id`]; surfaced again so the CLI
    /// can print it without juggling the input back to the call
    /// site).
    pub plan_id: PlanId,
    /// Bailiff-side OID where the implement note is attached. The
    /// deterministic seed-blob OID
    /// [`crate::bailiff_plan_note::plan_implement_seed_blob_bytes`]
    /// hashes to; callable readers can recompute it but having it
    /// on the result avoids the recomputation.
    pub implement_note_oid: GitObjectId,
    /// Writ's session id for the *implementer run only* — the
    /// authority/audit window writ minted for this `RunAgent` call,
    /// closed on the happy path before this outcome is returned.
    /// Surfaced so callers can correlate the run with writ's audit
    /// row; not a handle later workflow stages reuse.
    pub implementer_session_id: SessionId,
    /// What writ returned for the implementer run — the OID of the
    /// signed envelope note in writ's repo, plus the signed metadata
    /// and signature. Lets a caller verify or display the run
    /// without a second round-trip.
    pub run: RunAgentCompleted,
}

/// Drive the full plan-implement workflow against a live writ broker.
///
/// `bailiff_repo` is taken as an [`Arc`]`<`[`AsyncMutex`]`<_>>` so the
/// single-writer invariant on bailiff's bare repo can be enforced for
/// the whole workflow: [`submit_implement`] acquires the lock via
/// [`BailiffRepoGuard`] before reading the decision and duplicate
/// gates and releases it only on return. Holding the guard across the
/// gate-then-write sequence is what makes the duplicate gate
/// load-bearing for in-process callers — without it two concurrent
/// `submit_implement` calls could both pass `read_implement_note` and
/// then both open `WorkspaceWrite` sessions whose side effects no
/// later `write_implement_note` rejection can undo.
pub async fn submit_implement(
    client: &WritClient,
    bailiff_repo: Arc<AsyncMutex<NotesRepo>>,
    writ_repo_path: &Path,
    allowed_signers: AllowedSigners,
    inputs: SubmitImplementInputs,
) -> Result<SubmitImplementOutcome, SubmitImplementError> {
    // Hold the bailiff-repo lock across the entire workflow — pre-RPC
    // gates, opens, run, write, close — so concurrent submit_*/bailiff
    // workflows serialise instead of racing the gate-then-write
    // sequence. Released on function return.
    let mut bailiff = BailiffRepoGuard::acquire(bailiff_repo).await;

    // Pre-RPC: read the submission note, read the decision note (and
    // gate on it being an `accepted` verdict), gate on the absence of
    // an existing implement note, fetch+verify+decode the planner
    // envelope. Done before opening a session so any missing or
    // unverifiable precondition never burns a writ audit row.
    let plan_id = inputs.plan_id;
    let writ_repo_path_owned = writ_repo_path.to_path_buf();
    let writ_output_ref_for_read = inputs.writ_output_ref.clone();
    let allowed_for_read = allowed_signers.clone();
    let read_outcome = bailiff
        .run_blocking(
            move |repo| -> Result<(PlanNote, String), SubmitImplementError> {
                let plan_note = match read_plan_note(repo, plan_id)
                    .map_err(SubmitImplementError::ReadPlanNote)?
                {
                    Some(note) => note,
                    None => return Err(SubmitImplementError::PlanSubmissionMissing { plan_id }),
                };
                let decision = match read_decision_note(repo, plan_id)
                    .map_err(SubmitImplementError::ReadDecisionNote)?
                {
                    Some(note) => note,
                    None => return Err(SubmitImplementError::PlanNotDecided { plan_id }),
                };
                if decision.outcome != Decision::Accepted {
                    return Err(SubmitImplementError::PlanRejected { plan_id });
                }
                // Duplicate gate: if an implement note already exists,
                // refuse before opening a session. The implementer
                // holds `WorkspaceWrite`, so a re-run can push a
                // second set of changes even though
                // `write_implement_note` would reject the bailiff-side
                // write. The workflow-held guard makes the gate
                // atomic against concurrent in-process callers: the
                // second caller blocks on `acquire` until the first
                // either writes the implement note (so this read
                // returns `Some`) or fails and releases.
                if read_implement_note(repo, plan_id)
                    .map_err(SubmitImplementError::ReadImplementNote)?
                    .is_some()
                {
                    return Err(SubmitImplementError::AlreadyImplemented { plan_id });
                }
                let body = read_plan_body_bytes(
                    repo,
                    &writ_repo_path_owned,
                    &writ_output_ref_for_read,
                    &plan_note,
                    &allowed_for_read,
                )
                .map_err(SubmitImplementError::ReadPlanEnvelope)?;
                Ok((plan_note, body))
            },
        )
        .await
        .map_err(SubmitImplementError::ReadTaskFailed)?;
    let (_plan_note, plan_body) = read_outcome?;

    let implementer_prompt =
        compose_implementer_prompt_bytes(inputs.feature_prompt.as_str(), plan_body.as_str())
            .map_err(SubmitImplementError::ComposeImplementerPrompt)?;

    let session_id = client
        .open_session(
            inputs.session_label.clone(),
            inputs.session_agent_kind,
            inputs.session_agent_model.clone(),
        )
        .await
        .map_err(SubmitImplementError::OpenSession)?;

    // From here on, every early return must close the session.
    let run_result = client
        .run_agent(RunAgentRequest {
            prompt: implementer_prompt,
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
            return Err(SubmitImplementError::RunAgent { session_id, source });
        }
    };

    // Cross-check the broker honoured the session binding we asked
    // for: the signed metadata must stamp the same session id we
    // opened. A mismatch means the broker minted its own id and the
    // envelope can't be correlated with our audit row — refuse to
    // persist the implement note.
    if completed.signed_metadata.session_id != session_id {
        let returned_session_id = completed.signed_metadata.session_id;
        let _ = client.close_session(session_id).await;
        return Err(SubmitImplementError::SessionIdMismatch {
            session_id,
            returned_session_id,
        });
    }

    // `write_implement_note` is blocking (shells out to git). Run
    // under the workflow-held guard so the lock spans this section
    // and the surrounding awaits without being re-acquired here.
    let writ_repo_path_owned = writ_repo_path.to_path_buf();
    let writ_output_ref_clone = inputs.writ_output_ref.clone();
    let purpose_clone = inputs.purpose.clone();
    let completed_clone = completed.clone();
    let write_outcome = bailiff
        .run_blocking(move |repo| {
            write_implement_note(
                repo,
                &writ_repo_path_owned,
                &writ_output_ref_clone,
                plan_id,
                purpose_clone,
                &completed_clone,
                &allowed_signers,
            )
        })
        .await;
    let implement_note_oid = match write_outcome {
        Ok(Ok(oid)) => oid,
        Ok(Err(source)) => {
            let _ = client.close_session(session_id).await;
            return Err(SubmitImplementError::WriteImplementNote { session_id, source });
        }
        Err(source) => {
            let _ = client.close_session(session_id).await;
            return Err(SubmitImplementError::WriteTaskFailed { session_id, source });
        }
    };

    if let Err(source) = client.close_session(session_id).await {
        return Err(SubmitImplementError::CloseSession { session_id, source });
    }

    Ok(SubmitImplementOutcome {
        plan_id,
        implement_note_oid,
        implementer_session_id: session_id,
        run: completed,
    })
}

/// Separator the implementer's effective prompt uses between the
/// feature-request prompt and the approved plan body. `# Approved
/// plan` makes the artefact's status explicit so an LLM reading the
/// combined prompt cannot mistake an accepted plan for a proposed
/// one (the reviewer-side composer in `bailiff_plan_review.rs` uses
/// a different heading for the same reason).
const PLAN_PROMPT_SEPARATOR: &str = "\n\n---\n\n# Approved plan\n\n";

/// Compose the implementer's effective prompt from the operator's
/// feature prompt and the approved plan body. Takes raw `&str` rather
/// than `agent_plan::PlanBody` because the plan body has already been
/// extracted from the signed planner envelope as bytes — re-wrapping
/// it just to unwrap it again for signing would be churn.
fn compose_implementer_prompt_bytes(
    feature_prompt: &str,
    plan_body: &str,
) -> Result<AgentPrompt, AgentPromptError> {
    let mut combined =
        String::with_capacity(feature_prompt.len() + PLAN_PROMPT_SEPARATOR.len() + plan_body.len());
    combined.push_str(feature_prompt);
    combined.push_str(PLAN_PROMPT_SEPARATOR);
    combined.push_str(plan_body);
    AgentPrompt::try_new(combined)
}

/// Tagged failure modes of [`submit_implement`]. Pre-RPC variants
/// return before any writ session is opened; post-RPC variants
/// carry the [`SessionId`] [`submit_implement`] minted, and by the
/// time the variant is returned, [`submit_implement`] has *attempted*
/// to close that session. `CloseSession` is the one variant where
/// the close itself failed — the session may still be open.
#[derive(Debug, Error)]
pub enum SubmitImplementError {
    /// The `spawn_blocking` task that owns the pre-RPC read chain
    /// panicked or was cancelled. Surfaces separately from
    /// `ReadPlanNote` / `ReadDecisionNote` / `ReadPlanEnvelope`
    /// because the cause is a tokio-runtime condition, not a
    /// bailiff/writ contract violation. Pre-RPC: no session was
    /// opened.
    #[error("plan-body read task failed: {0}")]
    ReadTaskFailed(#[source] JoinError),
    /// [`read_plan_note`] returned an error. Distinct from
    /// [`Self::PlanSubmissionMissing`] (which is the `Ok(None)`
    /// case) so the operator can tell "bailiff's repo is broken"
    /// from "this plan has no submission yet." Pre-RPC.
    #[error("reading the plan submission note failed: {0}")]
    ReadPlanNote(#[source] ReadPlanError),
    /// Bailiff was asked to implement a plan with no submission note
    /// recorded. The plan id may be wrong, or the operator may
    /// have asked for an implementation before `bailiff plan submit`
    /// ran. Pre-RPC.
    #[error("no plan submission note recorded for plan {plan_id}")]
    PlanSubmissionMissing { plan_id: PlanId },
    /// [`read_decision_note`] returned an error. Distinct from
    /// [`Self::PlanNotDecided`] (which is the `Ok(None)` case) so the
    /// operator can tell "bailiff's repo is broken" from "this plan
    /// has no decision yet." Pre-RPC.
    #[error("reading the plan decision note failed: {0}")]
    ReadDecisionNote(#[source] ReadDecisionError),
    /// Bailiff was asked to implement a plan whose decision note has
    /// not been recorded yet. The operator's recourse is to run
    /// `bailiff plan decide accept|reject` first; this variant fires
    /// before any session is opened. Pre-RPC.
    #[error("no decision recorded for plan {plan_id}; run `bailiff plan decide` first")]
    PlanNotDecided { plan_id: PlanId },
    /// Bailiff was asked to implement a plan whose decision note
    /// records `rejected`. The implementer gate is "decision says
    /// accepted"; a rejected plan is dead and bailiff refuses to
    /// compose an implementer prompt against it. Pre-RPC.
    #[error("plan {plan_id} was rejected; refusing to compose an implementer prompt")]
    PlanRejected { plan_id: PlanId },
    /// [`read_implement_note`] returned an error. Distinct from
    /// [`Self::AlreadyImplemented`] (which is the `Ok(Some(_))` case)
    /// so the operator can tell "bailiff's repo is broken" from "this
    /// plan has already been implemented." Pre-RPC.
    #[error("reading the plan implement note failed: {0}")]
    ReadImplementNote(#[source] ReadImplementError),
    /// Bailiff was asked to implement a plan that already has an
    /// implement note recorded. The implementer holds
    /// `WorkspaceWrite`, so a duplicate run could push a second set
    /// of changes; the gate fires before any session is opened.
    /// Pre-RPC.
    #[error("plan {plan_id} has already been implemented; refusing to re-run the implementer")]
    AlreadyImplemented { plan_id: PlanId },
    /// The fetch / verify / decode chain that extracts the plan
    /// body from the planner envelope failed. The wrapped
    /// [`ReadPlanBodyError`] names the specific step. Pre-RPC.
    #[error("reading the planner envelope failed: {0}")]
    ReadPlanEnvelope(#[source] ReadPlanBodyError),
    /// The composed implementer prompt (`feature_prompt` +
    /// separator + `plan_body`) exceeded
    /// [`crate::agent_run::MAX_AGENT_PROMPT_BYTES`]. Either the
    /// feature prompt is large, the plan body is large, or both —
    /// the operator's recourse is to narrow one side. Pre-RPC.
    #[error("composing the implementer prompt failed: {0}")]
    ComposeImplementerPrompt(#[source] AgentPromptError),
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
    /// closed before this error returned; no bailiff-side implement
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
    /// Fetch/verify/write of the bailiff-side implement note failed.
    /// Writ already ran the implementer agent and signed the envelope,
    /// so an operator can re-attempt the implement-note write against
    /// the same envelope without re-running the agent. Includes the
    /// idempotency-conflict case
    /// ([`WriteImplementNoteError::ImplementAlreadyRecorded`]).
    #[error("writing the bailiff-side implement note failed (session {session_id}): {source}")]
    WriteImplementNote {
        session_id: SessionId,
        #[source]
        source: WriteImplementNoteError,
    },
    /// The `spawn_blocking` task that owns the `write_implement_note`
    /// call panicked or was cancelled. Surfaces separately from
    /// `WriteImplementNote` because the cause is a tokio-runtime
    /// condition, not a bailiff/writ contract violation.
    #[error("implement-note write task failed (session {session_id}): {source}")]
    WriteTaskFailed {
        session_id: SessionId,
        #[source]
        source: JoinError,
    },
    /// The implement note was written but the closing `CloseSession`
    /// failed. The workflow's persistent state (the implement note in
    /// bailiff's repo) is already in place; this is a session-row
    /// cleanup failure that an operator can ignore in most cases,
    /// but the variant surfaces it so scripts can react if needed.
    #[error("closing writ session {session_id} after implement submit failed: {source}")]
    CloseSession {
        session_id: SessionId,
        #[source]
        source: WritClientError,
    },
}

#[cfg(test)]
mod compose_tests {
    //! Tests for [`compose_implementer_prompt_bytes`]. The composer
    //! is intentionally tiny; the unit tests pin the load-bearing
    //! properties: the separator appears verbatim, and the byte cap
    //! fires on the combined length. The proptest below additionally
    //! checks that, for any feature/plan within range, the output is
    //! exactly `feature || SEPARATOR || plan`.
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn separator_appears_verbatim_between_feature_prompt_and_body() {
        let composed =
            compose_implementer_prompt_bytes("Rename foo to bar.", "# Plan\n\nDo a thing.\n")
                .unwrap();
        let expected = format!("Rename foo to bar.{PLAN_PROMPT_SEPARATOR}# Plan\n\nDo a thing.\n");
        assert_eq!(composed.as_str(), expected);
    }

    #[test]
    fn errors_when_combined_exceeds_agent_prompt_limit() {
        // Feature prompt at the cap, non-empty plan body, plus the
        // separator must overflow `AgentPrompt::try_new`.
        let feature_prompt = "x".repeat(crate::agent_run::MAX_AGENT_PROMPT_BYTES);
        let err = compose_implementer_prompt_bytes(&feature_prompt, "p").unwrap_err();
        assert!(err.to_string().contains("exceeding"), "{err}");
    }

    proptest! {
        /// `compose_implementer_prompt_bytes` is a structural
        /// concatenation: the result starts with the feature prompt,
        /// ends with the plan body, contains the separator between
        /// them, and has byte length equal to the sum of the three
        /// parts.
        #[test]
        fn compose_implementer_prompt_three_segments(
            feature_text in "[ -~]{1,1024}",
            plan_text in "[ -~]{1,1024}",
        ) {
            let combined = compose_implementer_prompt_bytes(&feature_text, &plan_text).unwrap();
            let s = combined.as_str();
            prop_assert!(s.starts_with(&feature_text), "missing prefix");
            prop_assert!(s.ends_with(&plan_text), "missing suffix");
            prop_assert!(s.contains(PLAN_PROMPT_SEPARATOR), "missing separator");
            prop_assert_eq!(
                s.len(),
                feature_text.len() + PLAN_PROMPT_SEPARATOR.len() + plan_text.len(),
            );
        }
    }
}

#[cfg(test)]
mod end_to_end_tests {
    //! End-to-end against a real writ broker. Pattern mirrors
    //! [`crate::bailiff_plan_review::end_to_end_tests`]: bring up
    //! the broker, plant a planner envelope so a submission note
    //! can be recorded, plant a decision note (the implementer
    //! gate), drive `submit_implement`, assert the implement note
    //! lands in bailiff's repo and the session row in writ's audit
    //! log transitions open → closed.
    use std::collections::{BTreeMap, HashMap};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use wiremock::MockServer;

    use super::*;
    use crate::audit::AuditLog;
    use crate::bailiff_decision::{Decider, Decision};
    use crate::bailiff_plan_note::{DecisionNote, ImplementNote, plan_notes_ref};
    use crate::bailiff_plan_submit::{SubmitPlanInputs, submit_plan};
    use crate::bailiff_plan_write::write_decision_note;
    use crate::core::{AgentKind, CapabilitySet, NotesRef, RepoRef, TtlSeconds, UnixMillis};
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

    fn writ_repo_ref() -> RepoRef {
        RepoRef {
            owner: "smaug123".into(),
            name: "writ".into(),
        }
    }

    /// Build a broker, return (state, socket path, broker join
    /// handle). Reused across the end-to-end tests.
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
            promote_runtime: None,
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
    /// recorded in bailiff's repo. Returns the plan id so the caller
    /// can plant a decision and drive `submit_implement`.
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
                repo: writ_repo_ref(),
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

    /// Plant a decision note on `plan_id` with the supplied outcome,
    /// using `write_decision_note` so the on-disk shape matches what
    /// the production `bailiff plan decide` verb produces.
    async fn record_decision(
        bailiff: &Arc<AsyncMutex<NotesRepo>>,
        plan_id: PlanId,
        outcome: Decision,
    ) {
        let bailiff = Arc::clone(bailiff);
        let note = DecisionNote {
            plan_id,
            outcome,
            decider: Decider::try_new("cli:test").unwrap(),
            decided_at: UnixMillis::from_millis(1_700_000_000_000),
        };
        tokio::task::spawn_blocking(move || {
            let bailiff = bailiff.blocking_lock();
            write_decision_note(&bailiff, &note)
                .expect("write_decision_note must succeed for the fixture");
        })
        .await
        .unwrap();
    }

    fn implement_inputs(plan_id: PlanId) -> SubmitImplementInputs {
        SubmitImplementInputs {
            plan_id,
            feature_prompt: AgentPrompt::try_new("Rename foo to bar.").unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceWrite {
                repo: writ_repo_ref(),
            }],
            purpose: "plan-implement".into(),
            writ_output_ref: NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_label: Some("plan-implement:test".into()),
            session_agent_kind: Some(AgentKind::Claude),
            session_agent_model: Some("claude-test".into()),
        }
    }

    /// Happy path: submit a plan, plant an `accepted` decision, then
    /// drive `submit_implement`. The implement note must decode from
    /// bailiff's repo and reference the implementer's writ-side OID;
    /// the implementer's session must close.
    #[tokio::test]
    async fn submit_implement_round_trips_through_open_run_write_close() {
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
        // body". This is the round-trip property the implement
        // workflow hangs on for prompt composition.
        let plan_body = "# Plan\n\nReplace bar with baz.\n";
        let plan_id =
            record_submission(&bailiff, &client, &writ_repo_path, &allowed, plan_body).await;
        record_decision(&bailiff, plan_id, Decision::Accepted).await;

        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            submit_implement(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed.clone(),
                implement_inputs(plan_id),
            ),
        )
        .await
        .expect("submit_implement must complete within 15s")
        .expect("submit_implement must succeed under the trusted-signer keyring");

        assert_eq!(outcome.plan_id, plan_id);
        assert_eq!(
            outcome.run.signed_metadata.session_id, outcome.implementer_session_id,
            "signed metadata must bind the session id bailiff opened",
        );

        // Implement note decodes from bailiff's repo and references
        // the writ-side OID writ returned for the implementer run.
        let bailiff_for_read = Arc::clone(&bailiff);
        let plan_ref = plan_notes_ref(plan_id);
        let oid = outcome.implement_note_oid.clone();
        let body = tokio::task::spawn_blocking(move || {
            let bailiff = bailiff_for_read.blocking_lock();
            bailiff.read_note(&plan_ref, &oid)
        })
        .await
        .unwrap()
        .expect("bailiff-side implement note must be readable at the returned OID");
        let note = ImplementNote::from_canonical_bytes(&body).unwrap();
        assert_eq!(note.plan_id, plan_id);
        assert_eq!(note.purpose, "plan-implement");
        assert_eq!(note.writ_output_oid, outcome.run.output_oid);
        assert_eq!(note.signed_metadata, outcome.run.signed_metadata);
        assert_eq!(note.signature, outcome.run.signature);

        // Writ's audit log records the implementer session as closed.
        let audit = Arc::clone(&state.audit);
        let session_id = outcome.implementer_session_id;
        let session_row = tokio::task::spawn_blocking(move || audit.get_session(session_id))
            .await
            .unwrap()
            .expect("session row read must succeed")
            .expect("implementer session must exist in audit log");
        assert!(
            session_row.closed_at.is_some(),
            "implementer session must be closed after submit_implement returns"
        );

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Pre-RPC: `submit_implement` against a plan id that has no
    /// submission note returns `PlanSubmissionMissing` *without
    /// opening a session*. The variant alone witnesses that
    /// `open_session` was never reached — `submit_implement` returns
    /// `PlanSubmissionMissing` strictly before the
    /// `client.open_session` call.
    #[tokio::test]
    async fn submit_implement_returns_plan_submission_missing_without_opening_session() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (_state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo));
        let writ_repo_path = tmp.path().join("writ-bare");
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let client = WritClient::new(&socket_path);
        let plan_id = PlanId::new();

        let err = tokio::time::timeout(
            Duration::from_secs(15),
            submit_implement(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed,
                implement_inputs(plan_id),
            ),
        )
        .await
        .expect("submit_implement must return within 15s")
        .expect_err("missing submission must surface as PlanSubmissionMissing");

        match err {
            SubmitImplementError::PlanSubmissionMissing { plan_id: found } => {
                assert_eq!(found, plan_id);
            }
            other => panic!("expected PlanSubmissionMissing, got: {other:?}"),
        }

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Pre-RPC: a plan with a submission note but *no decision note*
    /// surfaces `PlanNotDecided` without opening a session. Verifies
    /// that the decision gate fires distinctly from the submission
    /// gate so an operator can tell which precondition tripped.
    #[tokio::test]
    async fn submit_implement_returns_plan_not_decided_when_no_decision_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (_state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo));
        let writ_repo_path = tmp.path().join("writ-bare");
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let client = WritClient::new(&socket_path);

        // Submit a plan but plant *no* decision.
        let plan_body = "# Plan\n\nDo a thing.\n";
        let plan_id =
            record_submission(&bailiff, &client, &writ_repo_path, &allowed, plan_body).await;

        let err = tokio::time::timeout(
            Duration::from_secs(15),
            submit_implement(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed,
                implement_inputs(plan_id),
            ),
        )
        .await
        .expect("submit_implement must return within 15s")
        .expect_err("undecided plan must surface as PlanNotDecided");

        match err {
            SubmitImplementError::PlanNotDecided { plan_id: found } => {
                assert_eq!(found, plan_id);
            }
            other => panic!("expected PlanNotDecided, got: {other:?}"),
        }

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Pre-RPC: a plan with a *rejected* decision note surfaces
    /// `PlanRejected` without opening a session. Verifies the gate's
    /// negative-acceptance branch fires distinctly from the
    /// no-decision branch.
    #[tokio::test]
    async fn submit_implement_returns_plan_rejected_when_decision_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (_state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo));
        let writ_repo_path = tmp.path().join("writ-bare");
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let client = WritClient::new(&socket_path);

        let plan_body = "# Plan\n\nDo a thing.\n";
        let plan_id =
            record_submission(&bailiff, &client, &writ_repo_path, &allowed, plan_body).await;
        record_decision(&bailiff, plan_id, Decision::Rejected).await;

        let err = tokio::time::timeout(
            Duration::from_secs(15),
            submit_implement(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed,
                implement_inputs(plan_id),
            ),
        )
        .await
        .expect("submit_implement must return within 15s")
        .expect_err("rejected plan must surface as PlanRejected");

        match err {
            SubmitImplementError::PlanRejected { plan_id: found } => {
                assert_eq!(found, plan_id);
            }
            other => panic!("expected PlanRejected, got: {other:?}"),
        }

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Pre-RPC: a plan that has already been implemented surfaces
    /// `AlreadyImplemented` on a repeat call, without opening a new
    /// session or running the implementer agent a second time. Guards
    /// the codex-flagged footgun: the implementer holds
    /// `WorkspaceWrite`, so an accidental double-click on
    /// `bailiff plan implement` must not let it push twice. The
    /// bailiff-side implement note's OID is unchanged across the
    /// repeat — proof the duplicate path did not even reach
    /// `write_implement_note`, which would mint a fresh signature
    /// stamp.
    #[tokio::test]
    async fn submit_implement_returns_already_implemented_on_repeat_call() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo));
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let client = WritClient::new(&socket_path);

        let plan_body = "# Plan\n\nDo a thing.\n";
        let plan_id =
            record_submission(&bailiff, &client, &writ_repo_path, &allowed, plan_body).await;
        record_decision(&bailiff, plan_id, Decision::Accepted).await;

        // First call must succeed and stamp an implement note.
        let first = tokio::time::timeout(
            Duration::from_secs(15),
            submit_implement(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed.clone(),
                implement_inputs(plan_id),
            ),
        )
        .await
        .expect("first submit_implement must complete within 15s")
        .expect("first submit_implement must succeed");
        let first_session = first.implementer_session_id;
        let first_run_output_oid = first.run.output_oid.clone();

        let err = tokio::time::timeout(
            Duration::from_secs(15),
            submit_implement(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed,
                implement_inputs(plan_id),
            ),
        )
        .await
        .expect("duplicate submit_implement must return within 15s")
        .expect_err("duplicate implement must surface as AlreadyImplemented");

        match err {
            SubmitImplementError::AlreadyImplemented { plan_id: found } => {
                assert_eq!(found, plan_id);
            }
            other => panic!("expected AlreadyImplemented, got: {other:?}"),
        }

        // Witness 1: the first session is still closed and untouched.
        // If the duplicate path had opened a new session bound to the
        // same id (impossible — session ids are fresh per
        // `open_session`) or run any cleanup against `first_session`
        // it would show here.
        let audit_for_get = Arc::clone(&state.audit);
        let row = tokio::task::spawn_blocking(move || audit_for_get.get_session(first_session))
            .await
            .unwrap()
            .expect("audit read")
            .expect("first implementer session must exist");
        assert!(
            row.closed_at.is_some(),
            "first implementer session must remain closed",
        );

        // Witness 2: the bailiff-side implement note's signed envelope
        // is exactly the first run's envelope. The duplicate path did
        // not reach `write_implement_note`, so the recorded run is
        // unchanged.
        let bailiff_for_read = Arc::clone(&bailiff);
        let plan_ref = plan_notes_ref(plan_id);
        let oid = first.implement_note_oid.clone();
        let body = tokio::task::spawn_blocking(move || {
            let bailiff = bailiff_for_read.blocking_lock();
            bailiff.read_note(&plan_ref, &oid)
        })
        .await
        .unwrap()
        .expect("implement note must be readable");
        let note = ImplementNote::from_canonical_bytes(&body).unwrap();
        assert_eq!(note.writ_output_oid, first_run_output_oid);

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Concurrent `submit_implement` against the same plan: exactly
    /// one call must succeed and every other must surface
    /// `AlreadyImplemented` — the *pre-RPC* duplicate-gate variant,
    /// never the post-RPC
    /// [`WriteImplementNoteError::ImplementAlreadyRecorded`] that
    /// `write_implement_note` would surface if two callers both
    /// reached the write step.
    ///
    /// Witnesses the in-process atomicity invariant
    /// [`BailiffRepoGuard`] is the primitive of: the
    /// `read_implement_note` gate and the `write_implement_note` call
    /// happen under one held lock, so a second caller blocks on
    /// `acquire` until the first has either landed the implement note
    /// (so the gate fires) or failed and released (so the next caller
    /// is free to proceed). Without the workflow-spanning guard a
    /// concurrent duplicate could pass the gate, open a
    /// `WorkspaceWrite` session, run the agent, and only fail at the
    /// terminal `write_implement_note` step — by which time the
    /// implementer's side effects are already loose.
    #[tokio::test]
    async fn concurrent_submit_implement_serialises_on_the_duplicate_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo));
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let client = WritClient::new(&socket_path);

        let plan_body = "# Plan\n\nDo a thing.\n";
        let plan_id =
            record_submission(&bailiff, &client, &writ_repo_path, &allowed, plan_body).await;
        record_decision(&bailiff, plan_id, Decision::Accepted).await;

        // Three concurrent calls is enough to exercise the
        // queue-on-`acquire` path while keeping the test runtime
        // modest. `tokio::join!` polls the three futures on a single
        // task, which is exactly the in-process-concurrency case the
        // guard exists to make atomic.
        let call = |label: &str| {
            let label = label.to_string();
            let client_ref = &client;
            let bailiff = Arc::clone(&bailiff);
            let writ_repo_path = writ_repo_path.clone();
            let allowed = allowed.clone();
            async move {
                tokio::time::timeout(
                    Duration::from_secs(30),
                    submit_implement(
                        client_ref,
                        bailiff,
                        &writ_repo_path,
                        allowed,
                        implement_inputs(plan_id),
                    ),
                )
                .await
                .unwrap_or_else(|_| panic!("submit_implement ({label}) must complete within 30s"))
            }
        };
        let (a, b, c) = tokio::join!(call("a"), call("b"), call("c"));
        let outcomes = [a, b, c];

        let successes: Vec<_> = outcomes.iter().filter_map(|r| r.as_ref().ok()).collect();
        let failures: Vec<_> = outcomes.iter().filter_map(|r| r.as_ref().err()).collect();
        assert_eq!(
            successes.len(),
            1,
            "exactly one concurrent submit_implement must succeed; outcomes = {outcomes:?}",
        );
        assert_eq!(
            failures.len(),
            2,
            "the other two concurrent calls must fail; outcomes = {outcomes:?}",
        );
        for err in &failures {
            match err {
                SubmitImplementError::AlreadyImplemented { plan_id: found } => {
                    assert_eq!(*found, plan_id);
                }
                SubmitImplementError::WriteImplementNote { .. } => panic!(
                    "duplicate must trip the pre-RPC gate, not the write-side idempotency \
                     check; got: {err:?}",
                ),
                other => panic!("expected AlreadyImplemented, got: {other:?}"),
            }
        }

        // All three sessions writ recorded must be closed — both the
        // succeeding caller and the two callers that surfaced
        // `AlreadyImplemented` before opening any session leave a
        // tidy audit trail. The losers never opened sessions, so
        // only the winner's session id should appear in the log.
        let winner_session = successes[0].implementer_session_id;
        let audit = Arc::clone(&state.audit);
        let row = tokio::task::spawn_blocking(move || audit.get_session(winner_session))
            .await
            .unwrap()
            .expect("audit read must succeed")
            .expect("winner session must exist in audit log");
        assert!(
            row.closed_at.is_some(),
            "winner session must close after submit_implement returns",
        );

        broker_task.abort();
        let _ = broker_task.await;
    }
}
