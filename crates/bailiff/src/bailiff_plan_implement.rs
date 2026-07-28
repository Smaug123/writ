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
//! 2. The composed prompt uses the separator
//!    [`crate::bailiff_stage::PlanBodyStage::Implement`] names
//!    (`# Approved plan`), not the reviewer's `# Proposed plan`. The
//!    implementer is acting on an accepted artefact and the prompt
//!    framing makes that explicit so an LLM reading the combined
//!    prompt cannot mistake the plan's status.
//!
//! # Composition
//!
//! The implementer prompt is `feature_prompt` + that separator + the
//! plan body bytes, joined inline (rather than re-wrapping the bytes
//! in a structured plan-body type first) to avoid unwrapping them
//! again for signing.
//!
//! Reviewer feedback stays *out* of the composed prompt: per
//! `docs/plans/2026-05-11-agent-plans.md` §"Implementer prompt
//! construction" reviewer feedback drives the *decision*, not the
//! execution. The review note is therefore not read for prompt
//! composition — though since slice 1 the workflow does require one
//! to exist, because `implement` runs only from `accepted` and a
//! verdict is only reachable through `review`.
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

use crate::bailiff_plan_note::PlanId;
use crate::bailiff_plan_read::{
    ReadImplementError, ReadPlanBodyError, ReadPlanError, SummarizePlanError,
    read_implement_attempts,
};
use crate::bailiff_plan_state::IllegalTransition;
use crate::bailiff_plan_write::WriteStageNoteError;
use crate::bailiff_repo_guard::PlanGuardError;
use crate::bailiff_stage::{
    BrokerSession, BrokerSessionRunError, ComposePlanPromptError, OpenPlanStageError,
    PlanBodyStage, StageNoteSlot, StageNoteTarget, StageRunInputs, compose_with_plan_body,
    open_plan_stage, run_under_broker_session,
};
use writ::agent_run::{AgentPrompt, AgentPromptError};
use writ::core::{AgentKind, CapabilitySet, NotesRef, SessionId};
use writ::notes_repo::NotesRepo;
use writ::run_verify::AllowedSigners;
use writ::vm_git::{AgentVmWorkspaceBootstrap, GitObjectId};
use writ::writ_client::{RunAgentCompleted, WritClient, WritClientError};

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
    /// to [`crate::bailiff_plan_write::write_stage_note`].
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
/// Three phases from [`crate::bailiff_stage`], composed: gate, compose
/// the prompt from the verified plan body, then run under a session
/// **the broker** owns. The plan lock
/// [`crate::bailiff_stage::open_plan_stage`] returns is held until this
/// function returns, so the gate and the eventual note write cannot be
/// interleaved by another workflow — in this process or another.
///
/// The third phase is [`run_under_broker_session`], not its
/// owned-session sibling, and that is a type-level distinction rather
/// than a runtime flag: there is no code path from here that could
/// open or close a writ session, because the VM dispatch arm owns
/// both ends.
pub async fn submit_implement(
    client: &WritClient,
    bailiff_repo: Arc<NotesRepo>,
    writ_repo_path: &Path,
    allowed_signers: AllowedSigners,
    inputs: SubmitImplementInputs,
) -> Result<SubmitImplementOutcome, SubmitImplementError> {
    // One gate, one definition. This replaces a 25-line hand-rolled
    // sequence (submission? decision? is it Accepted? no implement
    // note yet?) that was one of four disagreeing encodings of the
    // workflow's transition relation — see
    // `docs/plans/2026-07-26-bailiff-workflow-as-data.md`. The old
    // duplicate-implement check is subsumed: `Implement` is illegal
    // from `Implemented`.
    //
    // The guard `open_plan_stage` returns is what makes the gate
    // load-bearing rather than advisory: a second caller blocks on
    // acquisition until the first either writes the implement note (so
    // its read observes it) or fails and releases. Without it, both
    // callers could pass the gate and both open `WorkspaceWrite`
    // sessions whose side effects no later note-write rejection can
    // undo.
    let plan_id = inputs.plan_id;
    let mut guard = open_plan_stage(
        bailiff_repo,
        plan_id,
        PlanBodyStage::Implement.stage().precondition(),
    )
    .await?;

    // Pre-RPC: read the submission note, fetch+verify+decode the
    // planner envelope, splice the plan body under `# Approved plan`.
    // Done before invoking writ so any missing or unverifiable
    // precondition never burns a writ audit row.
    let implementer_prompt = compose_with_plan_body(
        &mut guard,
        writ_repo_path,
        &inputs.writ_output_ref,
        &allowed_signers,
        plan_id,
        inputs.feature_prompt,
        PlanBodyStage::Implement,
    )
    .await?;

    // Which attempt this run is. Chosen here, under the same guard the
    // gate ran under, so "read the attempts, then write the next one"
    // is atomic against another process — the same reason the gate and
    // the note write share a lock. An operator never names an index:
    // tracking them by hand is exactly the bookkeeping the plan lock
    // already does correctly.
    let attempts = guard
        .run_blocking(move |repo| read_implement_attempts(repo, plan_id))
        .await
        .map_err(SubmitImplementError::ReadTaskFailed)?
        .map_err(SubmitImplementError::ReadImplementAttempts)?;
    let attempt = attempts
        .next_free
        .ok_or(SubmitImplementError::AttemptsExhausted { plan_id })?;

    // VM mode mints its own audit session (the broker rejects a
    // caller-supplied `session_id` alongside a workspace bootstrap),
    // and `agent_vm.stop_session` closes that session on the broker
    // side before `RunAgent` returns. Bailiff therefore neither opens
    // nor closes a session here: the run's audit window is entirely
    // broker-managed. The session id surfaces back via the signed
    // envelope's metadata, which is where the workflow's
    // `implementer_session_id` field comes from.
    let stage = run_under_broker_session(
        client,
        &mut guard,
        BrokerSession {
            workspace: inputs.workspace,
            agent_kind: inputs.session_agent_kind,
            agent_model: inputs.session_agent_model,
        },
        StageNoteTarget {
            slot: StageNoteSlot::Implement(attempt),
            plan_id,
            writ_repo_path: writ_repo_path.to_path_buf(),
            allowed_signers,
        },
        StageRunInputs {
            prompt: implementer_prompt,
            capabilities: inputs.capabilities,
            purpose: inputs.purpose,
            writ_output_ref: inputs.writ_output_ref,
        },
    )
    .await?;

    Ok(SubmitImplementOutcome {
        plan_id,
        implement_note_oid: stage.note_oid,
        implementer_session_id: stage.session_id,
        run: stage.run,
    })
}

/// Total map from the gate phase's failures onto this workflow's. All
/// four variants are produced by [`open_plan_stage`] for every caller,
/// so the match is exhaustive with no unreachable arm.
impl From<OpenPlanStageError> for SubmitImplementError {
    fn from(source: OpenPlanStageError) -> Self {
        match source {
            OpenPlanStageError::PlanLock(source) => Self::PlanLock(source),
            OpenPlanStageError::ReadTaskFailed(source) => Self::ReadTaskFailed(source),
            OpenPlanStageError::ReadPlanState(source) => Self::ReadPlanState(source),
            OpenPlanStageError::IllegalTransition { plan_id, source } => {
                Self::IllegalTransition { plan_id, source }
            }
        }
    }
}

/// Total map from the prompt-composition phase's failures onto this
/// workflow's.
impl From<ComposePlanPromptError> for SubmitImplementError {
    fn from(source: ComposePlanPromptError) -> Self {
        match source {
            ComposePlanPromptError::ReadTaskFailed(source) => Self::ReadTaskFailed(source),
            ComposePlanPromptError::ReadPlanNote(source) => Self::ReadPlanNote(source),
            ComposePlanPromptError::ReadPlanEnvelope(source) => Self::ReadPlanEnvelope(source),
            ComposePlanPromptError::ComposePrompt(source) => Self::ComposeImplementerPrompt(source),
        }
    }
}

/// Total map from the broker-session run phase's failures onto this
/// workflow's.
///
/// Three variants, not six: [`BrokerSessionRunError`] has no
/// `OpenSession`, `SessionIdMismatch`, or `CloseSession`, because the
/// path that would produce them does not exist on this side. A single
/// shared run-phase error would have forced this workflow to name
/// three failures it cannot have.
impl From<BrokerSessionRunError> for SubmitImplementError {
    fn from(source: BrokerSessionRunError) -> Self {
        match source {
            BrokerSessionRunError::RunAgent(source) => Self::RunAgent(source),
            BrokerSessionRunError::WriteNote { session_id, source } => {
                Self::WriteImplementNote { session_id, source }
            }
            BrokerSessionRunError::WriteTaskFailed { session_id, source } => {
                Self::WriteTaskFailed { session_id, source }
            }
        }
    }
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
    /// [`crate::bailiff_plan_read::read_plan_note`] returned an error.
    /// The gate has already
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
    /// Scanning the plan's existing implementer attempts failed, so
    /// which attempt this run would be is unknown. Includes the
    /// not-dense anomaly, where a gap in the sequence makes the count
    /// untrustworthy. Pre-RPC.
    #[error("reading the plan's implementer attempts failed: {0}")]
    ReadImplementAttempts(#[source] ReadImplementError),
    /// The plan already carries [`crate::bailiff_plan_note::ImplementAttempt::MAX`]
    /// attempts. The bound exists so the upward probe for a free
    /// attempt is finite; hitting it means fan-out on this plan is
    /// over, and the recourse is a fresh plan. Pre-RPC.
    #[error("plan {plan_id} has no free implementer attempt left")]
    AttemptsExhausted { plan_id: PlanId },
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
    /// ([`crate::bailiff_plan_write::WriteStageNoteError::AlreadyRecorded`]).
    #[error("writing the bailiff-side implement note failed (session {session_id}): {source}")]
    WriteImplementNote {
        session_id: SessionId,
        #[source]
        source: WriteStageNoteError,
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

// `compose_tests` moved to `crate::bailiff_stage::tests` in slice 3,
// along with the composer it covered. The implementer's framing is now
// `PlanBodyStage::Implement`, and its exact-concatenation, byte-cap,
// and three-segment property tests live beside the single definition.

// `build_request_tests` moved to `crate::bailiff_stage::tests` in
// slice 3, along with the binding it covered. The invariants it
// asserted — workspace bootstrap threaded verbatim, agent kind and
// model present, `session_id: None` — are now properties of
// `broker_run_agent_request`, which is the only way a VM-dispatched
// request gets built.

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
    use crate::bailiff_plan_note::ImplementAttempt;
    use crate::bailiff_plan_note::{DecisionNote, ImplementNote, plan_notes_ref};
    use crate::bailiff_plan_note::{ReviewNote, plan_review_seed_blob_bytes};
    use crate::bailiff_plan_read::read_plan_note;
    use crate::bailiff_plan_state::{PlanStage, PlanState};
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
                log_root: writ::config::AgentRunLogRoot::check(tmp.path().join("agent-runs"))
                    .unwrap(),
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
        // `implement` is legal only from `accepted`, which under the
        // shipped order means both a review and a verdict.
        record_review(&bailiff, plan_id).await;
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
        // A verdict presupposes a review under the shipped order.
        record_review(&bailiff, plan_id).await;
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
    /// Behaviour delta (slice 1): implementing a reviewed plan that
    /// has **no verdict yet** is refused, pre-RPC.
    ///
    /// The pre-slice gate never read the review note at all, so it
    /// could not distinguish these states; and because the operator's
    /// verdict is the last gate before a `WorkspaceWrite`-capable
    /// agent run, "reviewed but nobody has decided" must not reach
    /// it.
    ///
    /// Unlike its siblings this test needs no VM: the gate fires
    /// before any RPC, so it does not depend on the workspace
    /// plumbing that has the round-trip tests ignored.
    #[tokio::test]
    async fn submit_implement_refuses_an_undecided_plan_before_any_rpc() {
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
        record_review(&bailiff, plan_id).await;
        // Deliberately no `record_decision`.

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
        .expect_err("an undecided plan must not be implementable");

        match &err {
            SubmitImplementError::IllegalTransition {
                plan_id: found,
                source,
            } => {
                assert_eq!(*found, plan_id);
                assert_eq!(source.state, PlanState::Reviewed);
                assert_eq!(source.stage, PlanStage::Implement);
                assert!(
                    source
                        .to_string()
                        .contains("run `bailiff plan decide` first"),
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
            crate::bailiff_plan_read::read_implement_note(repo, plan_id, ImplementAttempt::FIRST)
        })
        .await
        .unwrap()
        .expect("reading the implement note must succeed");
        assert!(implement_note.is_none());

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// A repeat call starts a **new attempt** rather than being
    /// refused.
    ///
    /// Was `submit_implement_returns_already_implemented_on_repeat_call`,
    /// which asserted the opposite: the pre-slice-4 duplicate gate
    /// existed so an accidental double-click could not push twice.
    /// Slice 4 made repeating this stage the point — fan-out is N
    /// implementer runs on one accepted plan — so the guarantee moves
    /// rather than disappearing: the *earlier attempt's note is
    /// untouched*, which is what stops a repeat from rewriting a
    /// completed run's audit record.
    ///
    /// Still `#[ignore]`d pending slice VM3, so this encodes the
    /// intended contract without having been observed to hold. The
    /// runnable half of the same claim is
    /// `several_implementer_attempts_coexist_on_one_plan` in
    /// `bailiff_plan_write::stage_tests`, which drives the note writes
    /// directly.
    #[tokio::test]
    #[ignore = "re-enabled by slice VM3 once bailiff passes workspace: Some(...) for WorkspaceWrite runs"]
    async fn submit_implement_repeat_call_starts_a_new_attempt() {
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
        // `implement` is legal only from `accepted`, which under the
        // shipped order means both a review and a verdict.
        record_review(&bailiff, plan_id).await;
        record_decision(&bailiff, plan_id, Decision::Accepted).await;

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

        let second = tokio::time::timeout(
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
        .expect("second submit_implement must return within 15s")
        .expect("a repeat implement must start a new attempt, not be refused");

        assert_ne!(
            second.implement_note_oid, first.implement_note_oid,
            "the second attempt must attach at its own target",
        );

        // Witness 1: the first session is still closed and untouched.
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

        // Witness 2: attempt zero's note still records the *first*
        // run's envelope. This is the guarantee the old duplicate gate
        // provided and the one that must survive repeatability — a
        // second attempt may not rewrite a completed run's audit
        // record.
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

        // Witness 3: the reader sees exactly two dense attempts.
        let bailiff_for_scan = Arc::clone(&bailiff);
        let attempts = tokio::task::spawn_blocking(move || {
            crate::bailiff_plan_read::read_implement_attempts(&bailiff_for_scan, plan_id)
        })
        .await
        .unwrap()
        .expect("the attempt scan must succeed");
        assert_eq!(
            attempts
                .notes
                .iter()
                .map(|(a, _)| a.index())
                .collect::<Vec<_>>(),
            vec![0, 1],
        );
        assert_eq!(attempts.next_free.map(|a| a.index()), Some(2));

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Concurrent `submit_implement` against the same plan:
    /// **every** call succeeds, and they land on distinct, dense
    /// attempts.
    ///
    /// Was `concurrent_submit_implement_serialises_on_the_duplicate_gate`,
    /// which required one success and two `IllegalTransition`s. Slice
    /// 4 made the stage repeatable, so the thing being witnessed
    /// changes but does not weaken: the guard still serialises the
    /// callers, and what serialisation buys is now *distinct attempt
    /// indices* rather than *one winner*.
    ///
    /// That is still the in-process atomicity invariant [`PlanGuard`]
    /// is the primitive of. Each caller reads the attempt set and
    /// writes its note under one held lock, so a second caller blocks
    /// until the first has either landed its note (making the next
    /// index free) or failed and released. Without the
    /// workflow-spanning guard two callers could read the same
    /// `next_free`, both open `WorkspaceWrite` sessions, both run
    /// agents, and only one survive the write — by which time the
    /// loser's side effects are already loose. So the load-bearing
    /// assertion is that **no call fails with `AlreadyRecorded`**:
    /// that variant means two callers picked the same index, which is
    /// exactly the race the lock exists to prevent.
    ///
    /// Still `#[ignore]`d pending slice VM3, so this encodes the
    /// intended contract without having been observed to hold.
    #[tokio::test]
    #[ignore = "re-enabled by slice VM3 once bailiff passes workspace: Some(...) for WorkspaceWrite runs"]
    async fn concurrent_submit_implement_serialises_into_distinct_attempts() {
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
        // `implement` is legal only from `accepted`, which under the
        // shipped order means both a review and a verdict.
        record_review(&bailiff, plan_id).await;
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
        // Any failure is a bug now, but `AlreadyRecorded` is the
        // specific one that means the lock did not hold: two callers
        // read the same `next_free` and raced for the same seed.
        for err in &failures {
            assert!(
                !matches!(err, SubmitImplementError::WriteImplementNote { .. }),
                "two callers picked the same attempt index, so the plan lock did not \
                 serialise them; got: {err:?}",
            );
        }
        assert_eq!(
            successes.len(),
            3,
            "every concurrent submit_implement must land its own attempt; outcomes = \
             {outcomes:?}",
        );

        // Three distinct notes, and the attempt sequence is dense —
        // serialisation is what makes both true at once.
        let mut oids: Vec<String> = successes
            .iter()
            .map(|o| o.implement_note_oid.to_string())
            .collect();
        oids.sort();
        oids.dedup();
        assert_eq!(oids.len(), 3, "each attempt must attach at its own target");

        let bailiff_for_scan = Arc::clone(&bailiff);
        let attempts = tokio::task::spawn_blocking(move || {
            crate::bailiff_plan_read::read_implement_attempts(&bailiff_for_scan, plan_id)
        })
        .await
        .unwrap()
        .expect("the attempt scan must succeed; a gap would mean a lost write");
        assert_eq!(
            attempts
                .notes
                .iter()
                .map(|(a, _)| a.index())
                .collect::<Vec<_>>(),
            vec![0, 1, 2],
        );

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
