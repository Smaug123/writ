//! Slice-E4b workflow function that drives `bailiff plan implement`:
//! read the planner's submission note, gate on bailiff's decision note
//! recording an *accepted* verdict, fetch + verify the signed planner
//! envelope, decode the planner's stdout as the plan body, compose the
//! implementer's effective prompt from the operator's feature prompt
//! and the approved plan body, request the implementer run via writ's
//! `RunAgent` RPC (which dispatches to writd's VM arm: the broker
//! mints its own audit session, runs the agent inside a per-run VM,
//! and closes the session before returning), persist a
//! [`crate::bailiff_plan_note::ImplementNote`] in bailiff's repo.
//!
//! Sibling to [`crate::bailiff_plan_review::submit_review`], with the
//! same pre-RPC fetch-verify-decode chain via the lifted
//! `read_plan_body_bytes` helper. The two novelties of the implement
//! workflow are:
//!
//! 1. The workflow gate. Per slice E of
//!    `docs/plans/2026-05-14-bailiff-split.md`: "the *is the plan
//!    accepted?* gate lives in bailiff's read-side: refuse to compose
//!    unless bailiff's own decision note says accepted." Since slice 1
//!    (`docs/plans/2026-07-26-bailiff-workflow-as-data.md`) that gate
//!    is one call to [`crate::bailiff_plan_state::allows`] rather than
//!    a hand-rolled chain, and it additionally requires a review — the
//!    single `IllegalTransition` variant names the observed state, so
//!    an operator still sees exactly which precondition tripped.
//! 2. The composed prompt uses `PLAN_PROMPT_SEPARATOR`
//!    (`# Approved plan`), not the reviewer's `# Proposed plan`. The
//!    implementer is acting on an accepted artefact and the prompt
//!    framing makes that explicit so an LLM reading the combined
//!    prompt cannot mistake the plan's status.
//!
//! # Composition
//!
//! The implementer prompt is `feature_prompt` + the
//! `PLAN_PROMPT_SEPARATOR` string + the plan body bytes, joined
//! inline (rather than re-wrapping the bytes in a structured
//! plan-body type first) to avoid unwrapping them again for signing.
//!
//! Reviewer feedback stays *out* of the composed prompt: per
//! `docs/plans/2026-05-11-agent-plans.md` §"Implementer prompt
//! construction" reviewer feedback drives the *decision*, not the
//! execution. The review note is therefore not consulted here.
//!
//! # Error handling
//!
//! Pre-RPC failures (read-side, decision gate, prompt composition)
//! return without ever invoking writ, so writ's audit log stays
//! clean. VM mode mints its own audit session and closes it on the
//! broker side before `RunAgent` returns, so bailiff has no session
//! to clean up on a post-RPC failure: the audit window is entirely
//! broker-managed.

use std::path::Path;
use std::sync::Arc;

use thiserror::Error;
use tokio::task::JoinError;

use crate::bailiff_plan_note::{PlanId, PlanNote};
use crate::bailiff_plan_read::{
    ReadPlanBodyError, ReadPlanError, SummarizePlanError, read_plan_body_bytes, read_plan_note,
    summarize_plan,
};
use crate::bailiff_plan_state::{IllegalTransition, PlanStage, allows};
use crate::bailiff_plan_write::{WriteImplementNoteError, write_implement_note};
use crate::bailiff_repo_guard::{PlanGuard, PlanGuardError};
use writ::agent_run::{AgentPrompt, AgentPromptError};
use writ::core::{AgentKind, CapabilitySet, NotesRef, SessionId};
use writ::notes_repo::NotesRepo;
use writ::run_verify::AllowedSigners;
use writ::vm_git::{AgentVmWorkspaceBootstrap, GitObjectId};
use writ::writ_client::{RunAgentCompleted, RunAgentRequest, WritClient, WritClientError};

/// Inputs to [`submit_implement`]. Mirror of
/// [`crate::bailiff_plan_review::SubmitReviewInputs`] with
/// `feature_prompt` carrying the operator's original feature request
/// — the composed implementer prompt is built inside
/// [`submit_implement`] and never appears on the input struct.
#[derive(Debug)]
pub struct SubmitImplementInputs {
    /// Plan to implement. It must be in
    /// [`crate::bailiff_plan_state::PlanState::Reviewed`] — submission,
    /// an *accepted* decision, and a review note all attached under
    /// [`crate::bailiff_plan_note::plan_notes_ref`]`(plan_id)` — or
    /// [`submit_implement`] surfaces
    /// [`SubmitImplementError::IllegalTransition`] naming the state it
    /// actually found.
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
    /// Coarse agent identity. Writ uses it for GitHub-App selection
    /// on credential mints; with a `WorkspaceWrite` capability set
    /// the field selects which GitHub App to use for the
    /// implementer's push credentials. Required (not optional) here
    /// because writd's VM dispatch arm rejects a `RunAgent` carrying
    /// a workspace bootstrap but no `agent_kind`.
    pub session_agent_kind: AgentKind,
    /// Model identifier (e.g. `"claude-opus-4-7"`). Stored on writ's
    /// audit session row alongside `agent_kind`. Required (not
    /// optional) here because writd's VM dispatch arm rejects a
    /// `RunAgent` carrying a workspace bootstrap but no
    /// `agent_model`.
    pub session_agent_model: String,
    /// Workspace bootstrap describing the per-run VM checkout the
    /// implementer agent runs in. The implementer always carries a
    /// `WorkspaceWrite` capability, so the broker rejects the
    /// request unless a workspace is supplied; the bootstrap is what
    /// routes the run into writd's VM dispatch arm.
    ///
    /// The bootstrap's `repo` should match the `repo` referenced by
    /// the `WorkspaceWrite` element of [`Self::capabilities`] (the
    /// agent's cwd inside the VM is the checkout, and the
    /// capability tells writd which credential to mint for the push
    /// — the two must agree or the push will be denied at policy
    /// time). The CLI binding takes both from the same `--repo`
    /// flag.
    pub workspace: AgentVmWorkspaceBootstrap,
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
/// `bailiff_repo` is an `Arc<NotesRepo>`; the workflow takes
/// this plan's lock via [`PlanGuard`] before its first read and holds
/// it until return, so the gate and the eventual note write cannot be
/// interleaved by another workflow — in this process or another.
pub async fn submit_implement(
    client: &WritClient,
    bailiff_repo: Arc<NotesRepo>,
    writ_repo_path: &Path,
    allowed_signers: AllowedSigners,
    inputs: SubmitImplementInputs,
) -> Result<SubmitImplementOutcome, SubmitImplementError> {
    // Hold the bailiff-repo lock across the entire workflow — pre-RPC
    // gates, opens, run, write, close — so concurrent submit_*/bailiff
    // workflows serialise instead of racing the gate-then-write
    // sequence. Released on function return.
    let plan_id = inputs.plan_id;
    let mut bailiff = PlanGuard::acquire(bailiff_repo, plan_id)
        .await
        .map_err(SubmitImplementError::PlanLock)?;

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
                // One gate, one definition. This replaces a 25-line
                // hand-rolled sequence (submission? decision? is it
                // Accepted? no implement note yet?) that was one of
                // four disagreeing encodings of the workflow's
                // transition relation — see
                // `docs/plans/2026-07-26-bailiff-workflow-as-data.md`.
                // The old duplicate-implement check is subsumed:
                // `Implement` is illegal from `Implemented`.
                //
                // The workflow-held guard is what makes the gate
                // load-bearing rather than advisory: a second caller
                // blocks on `acquire` until the first either writes
                // the implement note (so this read observes it) or
                // fails and releases. Without it, both callers could
                // pass here and both open `WorkspaceWrite` sessions
                // whose side effects no later note-write rejection can
                // undo.
                let state = summarize_plan(repo, plan_id)
                    .map_err(SubmitImplementError::ReadPlanState)?
                    .state();
                allows(state, PlanStage::Implement).map_err(|source| {
                    SubmitImplementError::IllegalTransition { plan_id, source }
                })?;

                let plan_note = read_plan_note(repo, plan_id)
                    .map_err(SubmitImplementError::ReadPlanNote)?
                    .expect("gate passed, so a submission note exists");
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

    // VM mode mints its own audit session (the broker rejects a
    // caller-supplied `session_id` alongside a workspace bootstrap),
    // and `agent_vm.stop_session` closes that session on the broker
    // side before `RunAgent` returns. Bailiff therefore neither
    // opens nor closes a session here: the run's audit window is
    // entirely broker-managed. The session id surfaces back via the
    // signed envelope's metadata, which is where the workflow's
    // `implementer_session_id` field comes from.
    let run_agent_request = build_implementer_run_agent_request(implementer_prompt, &inputs);
    let completed = client
        .run_agent(run_agent_request)
        .await
        .map_err(SubmitImplementError::RunAgent)?;
    let session_id = completed.signed_metadata.session_id;

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
            return Err(SubmitImplementError::WriteImplementNote { session_id, source });
        }
        Err(source) => {
            return Err(SubmitImplementError::WriteTaskFailed { session_id, source });
        }
    };

    Ok(SubmitImplementOutcome {
        plan_id,
        implement_note_oid,
        implementer_session_id: session_id,
        run: completed,
    })
}

/// Pure binding from [`SubmitImplementInputs`] to the wire-level
/// [`RunAgentRequest`] writd receives. Lifted out so the field-level
/// invariants — the workspace bootstrap routes the run into writd's
/// VM dispatch arm, `agent_kind` / `agent_model` carry the
/// VM-required identity, and `session_id` stays `None` so writd's
/// VM dispatch arm mints its own audit session — are testable
/// without standing up a broker.
fn build_implementer_run_agent_request(
    composed_prompt: AgentPrompt,
    inputs: &SubmitImplementInputs,
) -> RunAgentRequest {
    RunAgentRequest {
        prompt: composed_prompt,
        capabilities: inputs.capabilities.clone(),
        purpose: inputs.purpose.clone(),
        output_ref: inputs.writ_output_ref.clone(),
        session_id: None,
        workspace: Some(inputs.workspace.clone()),
        agent_kind: Some(inputs.session_agent_kind),
        agent_model: Some(inputs.session_agent_model.clone()),
    }
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
/// than a structured plan-body type because the plan body has already
/// been extracted from the signed planner envelope as bytes —
/// re-wrapping it just to unwrap it again for signing would be churn.
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
/// return before writ is invoked; post-RPC variants surface either
/// the `RunAgent` failure itself (no session id is available — the
/// VM dispatch arm mints its own and closes it before returning)
/// or a failure that happens after `RunAgent` succeeded, in which
/// case the variant carries the [`SessionId`] writ stamped into the
/// signed metadata. The broker-side session is already closed by
/// the time any post-RPC variant returns.
#[derive(Debug, Error)]
pub enum SubmitImplementError {
    /// This plan's lock could not be taken — another bailiff process
    /// is working on it, or the lockfile is unusable. Pre-RPC: no
    /// session was opened and no note was read.
    #[error("locking plan: {0}")]
    PlanLock(#[source] PlanGuardError),
    /// The `spawn_blocking` task that owns the pre-RPC read chain
    /// panicked or was cancelled. Surfaces separately from
    /// `ReadPlanNote` / `ReadDecisionNote` / `ReadPlanEnvelope`
    /// because the cause is a tokio-runtime condition, not a
    /// bailiff/writ contract violation. Pre-RPC: no session was
    /// opened.
    #[error("plan-body read task failed: {0}")]
    ReadTaskFailed(#[source] JoinError),
    /// [`read_plan_note`] returned an error. The gate has already
    /// passed by the time this read runs, so this is "bailiff's repo
    /// broke between two reads", not "the plan is in the wrong
    /// state" — that is [`Self::IllegalTransition`]. Pre-RPC.
    #[error("reading the plan submission note failed: {0}")]
    ReadPlanNote(#[source] ReadPlanError),
    /// Reading the four notes to determine the plan's state failed.
    /// Distinct from [`Self::IllegalTransition`] (the state was read
    /// fine and forbids the stage) so the operator can tell
    /// "bailiff's repo is broken" from "this plan is not ready".
    /// Pre-RPC.
    #[error("reading the plan's state failed: {0}")]
    ReadPlanState(#[source] SummarizePlanError),
    /// The plan is not in a state from which `implement` may run.
    ///
    /// Replaces the five separate variants this gate used to raise
    /// (`PlanSubmissionMissing`, `PlanNotDecided`, `PlanRejected`,
    /// `AlreadyImplemented`, and their read-error siblings): the
    /// wrapped [`IllegalTransition`] names the observed state, the
    /// blocked stage, and the operator's next command, all derived
    /// from the one transition relation rather than hand-written per
    /// failure mode. Pre-RPC: no session was opened.
    #[error("plan {plan_id}: {source}")]
    IllegalTransition {
        plan_id: PlanId,
        #[source]
        source: IllegalTransition,
    },
    /// The fetch / verify / decode chain that extracts the plan
    /// body from the planner envelope failed. The wrapped
    /// [`ReadPlanBodyError`] names the specific step. Pre-RPC.
    #[error("reading the planner envelope failed: {0}")]
    ReadPlanEnvelope(#[source] ReadPlanBodyError),
    /// The composed implementer prompt (`feature_prompt` +
    /// separator + `plan_body`) exceeded
    /// [`writ::agent_run::MAX_AGENT_PROMPT_BYTES`]. Either the
    /// feature prompt is large, the plan body is large, or both —
    /// the operator's recourse is to narrow one side. Pre-RPC.
    #[error("composing the implementer prompt failed: {0}")]
    ComposeImplementerPrompt(#[source] AgentPromptError),
    /// The `RunAgent` RPC failed. The VM dispatch arm mints its
    /// own audit session and closes it on the broker side before
    /// returning, so no caller-side cleanup is needed; there is
    /// also no session id to surface (one was never returned).
    #[error("RunAgent RPC failed: {0}")]
    RunAgent(#[source] WritClientError),
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
        let feature_prompt = "x".repeat(writ::agent_run::MAX_AGENT_PROMPT_BYTES);
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
mod build_request_tests {
    //! Unit tests for the pure `build_implementer_run_agent_request`
    //! helper. The helper is the binding between `SubmitImplementInputs`
    //! and the wire-level `RunAgentRequest` writd receives: every field
    //! the implementer cares about (workspace bootstrap, agent kind,
    //! agent model) must flow through verbatim, and the VM-mints-its-
    //! own-session invariant (`session_id: None`) must hold.
    use super::*;
    use std::path::PathBuf;
    use writ::core::{AgentKind, RepoRef};
    use writ::vm_git::{AgentVmWorkspaceBootstrap, GitCloneRepo, WorkspaceWarmMode};

    fn sample_workspace() -> AgentVmWorkspaceBootstrap {
        AgentVmWorkspaceBootstrap {
            repo: GitCloneRepo::new(RepoRef {
                owner: "smaug123".into(),
                name: "writ".into(),
            })
            .unwrap(),
            destination: Some(PathBuf::from("/workspace/writ")),
            warm: WorkspaceWarmMode::DevShell,
        }
    }

    fn sample_inputs() -> SubmitImplementInputs {
        SubmitImplementInputs {
            plan_id: PlanId::new(),
            feature_prompt: AgentPrompt::try_new("Implement feature X.").unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceWrite {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            purpose: "plan-implement".into(),
            writ_output_ref: NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_agent_kind: AgentKind::Claude,
            session_agent_model: "claude-opus-4-7".into(),
            workspace: sample_workspace(),
        }
    }

    /// `build_implementer_run_agent_request` carries every VM-relevant
    /// field of `SubmitImplementInputs` onto the `RunAgentRequest` writd
    /// will see: the workspace bootstrap (so dispatch routes into the
    /// VM arm), the agent kind and agent model (required by the VM arm
    /// since the broker doesn't pick a default), and `session_id: None`
    /// (VM mode mints its own audit session; passing a caller-supplied
    /// id alongside a workspace bootstrap is what `run_agent_in_vm`
    /// rejects with "VM mode mints its own audit session").
    #[test]
    fn build_implementer_run_agent_request_threads_workspace_and_agent_identity() {
        let inputs = sample_inputs();
        let prompt = AgentPrompt::try_new("composed-prompt").unwrap();
        let req = build_implementer_run_agent_request(prompt.clone(), &inputs);

        assert_eq!(req.prompt.as_str(), prompt.as_str());
        assert_eq!(req.capabilities, inputs.capabilities);
        assert_eq!(req.purpose, inputs.purpose);
        assert_eq!(req.output_ref, inputs.writ_output_ref);
        assert_eq!(
            req.session_id, None,
            "VM mode mints its own audit session; bailiff must not pre-open one",
        );
        assert_eq!(
            req.workspace.as_ref(),
            Some(&inputs.workspace),
            "workspace bootstrap must thread through verbatim",
        );
        assert_eq!(req.agent_kind, Some(inputs.session_agent_kind));
        assert_eq!(
            req.agent_model.as_deref(),
            Some(inputs.session_agent_model.as_str())
        );
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
    use crate::bailiff_decision::{Decider, Decision};
    use crate::bailiff_plan_note::{DecisionNote, ImplementNote, plan_notes_ref};
    use crate::bailiff_plan_note::{ReviewNote, plan_review_seed_blob_bytes};
    use crate::bailiff_plan_read::read_plan_note;
    use crate::bailiff_plan_state::PlanState;
    use crate::bailiff_plan_submit::{SubmitPlanInputs, submit_plan};
    use crate::bailiff_plan_write::write_decision_note;
    use writ::audit::AuditLog;
    use writ::core::{AgentKind, CapabilitySet, NotesRef, RepoRef, TtlSeconds, UnixMillis};
    use writ::github::{GitHubAppConfig, GitHubAppRegistryConfig, GitHubMinter};
    use writ::notes_repo::NotesRepo;
    use writ::policy::PolicyConfig;
    use writ::run_verify::AllowedSigners;
    use writ::secret::{SecretError, SecretKey, SecretStore};
    use writ::server::{
        BrokerState, RunAgentSpawnConfig, prepare_broker_listener, serve_broker_with_agent_vm,
    };
    use writ::signing::WritSigningKey;
    use writ::writ_client::WritClient;

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
            git_data_http: std::sync::OnceLock::new(),
            mirror_pins: writ::vm_git_mirror_cache::MirrorPins::new(),
            chatgpt_oauth_authority: Default::default(),
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
        bailiff: &Arc<NotesRepo>,
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
    async fn record_decision(bailiff: &Arc<NotesRepo>, plan_id: PlanId, outcome: Decision) {
        let bailiff = Arc::clone(bailiff);
        let note = DecisionNote {
            plan_id,
            outcome,
            decider: Decider::try_new("cli:test").unwrap(),
            decided_at: UnixMillis::from_millis(1_700_000_000_000),
        };
        tokio::task::spawn_blocking(move || {
            write_decision_note(&bailiff, &note)
                .expect("write_decision_note must succeed for the fixture");
        })
        .await
        .unwrap();
    }

    /// Plant a review note on `plan_id` so the plan reaches
    /// `PlanState::Reviewed`, the only state `implement` is legal
    /// from.
    ///
    /// Written directly rather than through `submit_review` because
    /// the implement gate reads note *presence*, never the review
    /// note's envelope — running a second real agent to produce a
    /// verifiable one would slow every implement test for no extra
    /// coverage. The signed metadata and signature are copied off the
    /// plan note so the planted note is still structurally
    /// well-formed.
    async fn record_review(bailiff: &Arc<NotesRepo>, plan_id: PlanId) {
        let bailiff = Arc::clone(bailiff);
        tokio::task::spawn_blocking(move || {
            let plan_note = read_plan_note(&bailiff, plan_id)
                .expect("reading the plan note must succeed for the fixture")
                .expect("record_review requires a submission note");
            let note = ReviewNote {
                plan_id,
                purpose: "plan-review".into(),
                writ_output_oid: plan_note.writ_output_oid.clone(),
                signed_metadata: plan_note.signed_metadata.clone(),
                signature: plan_note.signature.clone(),
            };
            bailiff
                .write_note(
                    &plan_notes_ref(plan_id),
                    &plan_review_seed_blob_bytes(plan_id),
                    &note.canonical_bytes(),
                )
                .expect("write_note must succeed for the review fixture");
        })
        .await
        .unwrap();
    }

    fn implement_inputs(plan_id: PlanId) -> SubmitImplementInputs {
        use writ::vm_git::{GitCloneRepo, WorkspaceWarmMode};
        SubmitImplementInputs {
            plan_id,
            feature_prompt: AgentPrompt::try_new("Rename foo to bar.").unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceWrite {
                repo: writ_repo_ref(),
            }],
            purpose: "plan-implement".into(),
            writ_output_ref: NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_agent_kind: AgentKind::Claude,
            session_agent_model: "claude-test".into(),
            workspace: AgentVmWorkspaceBootstrap {
                repo: GitCloneRepo::new(writ_repo_ref()).unwrap(),
                destination: None,
                warm: WorkspaceWarmMode::DevShell,
            },
        }
    }

    /// Happy path: submit a plan, plant an `accepted` decision, then
    /// drive `submit_implement`. The implement note must decode from
    /// bailiff's repo and reference the implementer's writ-side OID;
    /// the implementer's session must close.
    #[tokio::test]
    #[ignore = "re-enabled by slice VM3 once bailiff passes workspace: Some(...) for WorkspaceWrite runs"]
    async fn submit_implement_round_trips_through_open_run_write_close() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(bailiff_repo);
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
        // Slice 1: `implement` is legal only from `reviewed`.
        record_review(&bailiff, plan_id).await;

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
            let bailiff = &*bailiff_for_read;
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
    /// submission note returns `IllegalTransition` *without
    /// opening a session*. The variant alone witnesses that
    /// `open_session` was never reached — `submit_implement` returns
    /// `IllegalTransition` strictly before the
    /// `client.open_session` call.
    #[tokio::test]
    async fn submit_implement_returns_plan_submission_missing_without_opening_session() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (_state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(bailiff_repo);
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
        .expect_err("missing submission must surface as IllegalTransition");

        match err {
            SubmitImplementError::IllegalTransition {
                plan_id: found,
                source,
            } => {
                assert_eq!(found, plan_id);
                // Strictly more informative than the old
                // `PlanSubmissionMissing`: the error now names the
                // state observed, not just the note that was missing.
                assert_eq!(source.state, PlanState::Absent);
                assert_eq!(source.stage, PlanStage::Implement);
            }
            other => panic!("expected IllegalTransition, got: {other:?}"),
        }

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Pre-RPC: a plan with a submission note but *no decision note*
    /// surfaces `IllegalTransition` without opening a session. Verifies
    /// that the decision gate fires distinctly from the submission
    /// gate so an operator can tell which precondition tripped.
    #[tokio::test]
    async fn submit_implement_returns_plan_not_decided_when_no_decision_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (_state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(bailiff_repo);
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
        .expect_err("undecided plan must surface as IllegalTransition");

        match err {
            SubmitImplementError::IllegalTransition {
                plan_id: found,
                source,
            } => {
                assert_eq!(found, plan_id);
                assert_eq!(source.state, PlanState::Submitted);
                assert_eq!(source.stage, PlanStage::Implement);
            }
            other => panic!("expected IllegalTransition, got: {other:?}"),
        }

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Pre-RPC: a plan with a *rejected* decision note surfaces
    /// `IllegalTransition` without opening a session. Verifies the gate's
    /// negative-acceptance branch fires distinctly from the
    /// no-decision branch.
    #[tokio::test]
    async fn submit_implement_returns_plan_rejected_when_decision_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (_state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(bailiff_repo);
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
        .expect_err("rejected plan must surface as IllegalTransition");

        match err {
            SubmitImplementError::IllegalTransition {
                plan_id: found,
                source,
            } => {
                assert_eq!(found, plan_id);
                assert_eq!(source.state, PlanState::Rejected);
                assert_eq!(source.stage, PlanStage::Implement);
            }
            other => panic!("expected IllegalTransition, got: {other:?}"),
        }

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Pre-RPC: a plan that has already been implemented surfaces
    /// `IllegalTransition` on a repeat call, without opening a new
    /// session or running the implementer agent a second time. Guards
    /// the codex-flagged footgun: the implementer holds
    /// Behaviour delta (slice 1): implementing an accepted plan that
    /// has **not been reviewed** is refused, pre-RPC.
    ///
    /// The pre-slice gate checked submission -> decision ->
    /// `Accepted` -> no prior implement, and never read the review
    /// note, so an accepted-but-unreviewed plan went straight to a
    /// `WorkspaceWrite`-capable agent run. This is the tightening
    /// that makes review-before-implement policy rather than
    /// convention.
    ///
    /// Unlike its siblings this test needs no VM: the gate fires
    /// before any RPC, so it does not depend on the workspace
    /// plumbing that has the round-trip tests ignored.
    #[tokio::test]
    async fn submit_implement_refuses_an_unreviewed_plan_before_any_rpc() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(bailiff_repo);
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let client = WritClient::new(&socket_path);

        let plan_body = "# Plan\n\nDo a thing.\n";
        let plan_id =
            record_submission(&bailiff, &client, &writ_repo_path, &allowed, plan_body).await;
        record_decision(&bailiff, plan_id, Decision::Accepted).await;
        // Deliberately no `record_review`.

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
        .expect_err("an unreviewed plan must not be implementable");

        match &err {
            SubmitImplementError::IllegalTransition {
                plan_id: found,
                source,
            } => {
                assert_eq!(*found, plan_id);
                assert_eq!(source.state, PlanState::Accepted);
                assert_eq!(source.stage, PlanStage::Implement);
                assert!(
                    source
                        .to_string()
                        .contains("run `bailiff plan review` first"),
                    "{source}",
                );
            }
            other => panic!("expected IllegalTransition, got: {other:?}"),
        }

        // No implement note was written, so the plan stays
        // implementable once it has actually been reviewed.
        let bailiff_for_read = Arc::clone(&bailiff);
        let implement_note = tokio::task::spawn_blocking(move || {
            let repo = &*bailiff_for_read;
            crate::bailiff_plan_read::read_implement_note(repo, plan_id)
        })
        .await
        .unwrap()
        .expect("reading the implement note must succeed");
        assert!(implement_note.is_none());

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// `WorkspaceWrite`, so an accidental double-click on
    /// `bailiff plan implement` must not let it push twice. The
    /// bailiff-side implement note's OID is unchanged across the
    /// repeat — proof the duplicate path did not even reach
    /// `write_implement_note`, which would mint a fresh signature
    /// stamp.
    #[tokio::test]
    #[ignore = "re-enabled by slice VM3 once bailiff passes workspace: Some(...) for WorkspaceWrite runs"]
    async fn submit_implement_returns_already_implemented_on_repeat_call() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(bailiff_repo);
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let client = WritClient::new(&socket_path);

        let plan_body = "# Plan\n\nDo a thing.\n";
        let plan_id =
            record_submission(&bailiff, &client, &writ_repo_path, &allowed, plan_body).await;
        record_decision(&bailiff, plan_id, Decision::Accepted).await;
        // Slice 1: `implement` is legal only from `reviewed`.
        record_review(&bailiff, plan_id).await;

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
        .expect_err("duplicate implement must surface as IllegalTransition");

        match err {
            // The duplicate-implement gate is no longer a bespoke
            // check: `Implement` is simply illegal from `Implemented`.
            SubmitImplementError::IllegalTransition {
                plan_id: found,
                source,
            } => {
                assert_eq!(found, plan_id);
                assert_eq!(source.state, PlanState::Implemented);
                assert_eq!(source.stage, PlanStage::Implement);
            }
            other => panic!("expected IllegalTransition, got: {other:?}"),
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
            let bailiff = &*bailiff_for_read;
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
    /// `IllegalTransition` — the *pre-RPC* duplicate-gate variant,
    /// never the post-RPC
    /// [`WriteImplementNoteError::ImplementAlreadyRecorded`] that
    /// `write_implement_note` would surface if two callers both
    /// reached the write step.
    ///
    /// Witnesses the in-process atomicity invariant
    /// [`PlanGuard`] is the primitive of: the
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
    #[ignore = "re-enabled by slice VM3 once bailiff passes workspace: Some(...) for WorkspaceWrite runs"]
    async fn concurrent_submit_implement_serialises_on_the_duplicate_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(bailiff_repo);
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let client = WritClient::new(&socket_path);

        let plan_body = "# Plan\n\nDo a thing.\n";
        let plan_id =
            record_submission(&bailiff, &client, &writ_repo_path, &allowed, plan_body).await;
        record_decision(&bailiff, plan_id, Decision::Accepted).await;
        // Slice 1: `implement` is legal only from `reviewed`.
        record_review(&bailiff, plan_id).await;

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
                SubmitImplementError::IllegalTransition {
                    plan_id: found,
                    source,
                } => {
                    assert_eq!(*found, plan_id);
                    assert_eq!(source.state, PlanState::Implemented);
                    assert_eq!(source.stage, PlanStage::Implement);
                }
                SubmitImplementError::WriteImplementNote { .. } => panic!(
                    "duplicate must trip the pre-RPC gate, not the write-side idempotency \
                     check; got: {err:?}",
                ),
                other => panic!("expected IllegalTransition, got: {other:?}"),
            }
        }

        // All three sessions writ recorded must be closed — both the
        // succeeding caller and the two callers that surfaced
        // `IllegalTransition` before opening any session leave a
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
