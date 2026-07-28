//! The phase vocabulary the three agent-run workflows are composed
//! from: gate, compose, run.
//!
//! Slice 3 of `docs/plans/2026-07-26-bailiff-workflow-as-data.md`.
//! `submit_plan`, `submit_review`, and `submit_implement` were three
//! near-identical 120-line bodies — read inputs, take the guard, gate,
//! read and verify the prior envelope, compose a prompt, run the
//! agent, write a signed note — with three near-identical
//! `Inputs`/`Outcome`/`Error` triples. The rule of three was met; this
//! module is the extraction.
//!
//! # Why phases rather than one interpreter
//!
//! The plan's original sketch was a single `StageSpec` value driven by
//! a single `run_stage` returning a single `StageError`. Written out
//! against the real failure surface, only one of the four failure
//! groups is universal:
//!
//! | Failure group | Submit | Review | Implement |
//! |---|---|---|---|
//! | lock / read state / illegal transition | ✓ | ✓ | ✓ |
//! | read submission note, verify envelope, compose | — | ✓ | ✓ |
//! | open session, session-id cross-check, close | ✓ | ✓ | — |
//! | run agent, write note, write-task join | ✓ | ✓ | ✓ |
//!
//! A single union error therefore makes three illegal states
//! representable at once: a submit failure naming a planner envelope
//! it never read, an implement failure naming a session bailiff never
//! opened, and — since the implement path has no session id until
//! `RunAgent` returns — a `RunAgent` variant whose `session_id` widens
//! to `Option<SessionId>` for one arm's benefit. That is the same
//! defect this plan exists to remove (one encoding, wrong for every
//! specific case), reintroduced at the error layer.
//!
//! So the data is a *phase vocabulary*, and each stage is the
//! composition of its phases. Every error type here is total for its
//! callers: each caller produces every variant, so each caller's map
//! into its own enum is a total match with no unreachable arm.
//!
//! # Session ownership is a DU promoted to the type level
//!
//! Submit and review open their own writ session, bind `RunAgent` to
//! it, and close it on every exit path after the open. Implement is
//! VM-dispatched: writd's VM arm mints its own audit session and
//! closes it before `RunAgent` returns, so bailiff must send no
//! `session_id` and must not close.
//!
//! That is two functions ([`run_under_owned_session`] and
//! [`run_under_broker_session`]), not one function over a
//! `SessionOwnership` tag. The close-session path is then not
//! *reachable* from the broker-managed stage rather than merely
//! unreached, and the caller is routed by the data it holds: only the
//! implement stage has an [`AgentVmWorkspaceBootstrap`] to put in a
//! [`BrokerSession`], which is the same field writd's dispatch keys
//! on.

use std::path::Path;
use std::sync::Arc;

use thiserror::Error;
use tokio::task::JoinError;

use crate::bailiff_plan_note::{
    ImplementAttempt, PlanId, plan_implement_seed_blob_bytes, plan_review_seed_blob_bytes,
    plan_submission_seed_blob_bytes,
};
use crate::bailiff_plan_read::{
    ReadPlanBodyError, ReadPlanError, SummarizePlanError, read_plan_body_bytes, read_plan_note,
    summarize_plan,
};
use crate::bailiff_plan_state::{IllegalTransition, PlanStage, allows};
pub use crate::bailiff_plan_write::StageNoteTarget;
use crate::bailiff_plan_write::{WriteStageNoteError, write_stage_note};
use crate::bailiff_repo_guard::{PlanGuard, PlanGuardError};
use writ::agent_run::{AgentPrompt, AgentPromptError, RunPurpose};
use writ::core::{AgentKind, CapabilitySet, NotesRef, SessionId};
use writ::notes_repo::NotesRepo;
use writ::run_verify::AllowedSigners;
use writ::vm_git::{AgentVmWorkspaceBootstrap, GitObjectId};
use writ::writ_client::{RunAgentCompleted, RunAgentRequest, WritClient, WritClientError};

/// The stages of the plan workflow that run an agent.
///
/// Deliberately not [`PlanStage`], which has a fourth variant:
/// `Decide` records a human verdict and runs no agent, so "compose a
/// prompt for the decide stage" and "write the decide stage's agent
/// envelope" are states this type makes unrepresentable.
///
/// Both static axes — the precondition slice 1's relation gates on,
/// and the framing the plan body is spliced under — are *derived from*
/// this one value rather than stored beside it, so they cannot
/// disagree with the stage or with each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AgentStage {
    /// The planner run. Produces the plan body every later stage reads.
    Submit,
    /// The reviewer run. Reads the plan body as a *proposal*.
    Review,
    /// The implementer run. Reads the plan body as an *approved*
    /// artefact, and is the only stage whose session the broker owns.
    Implement,
}

impl AgentStage {
    /// Every agent-run stage, for exhaustive tests. Kept adjacent to
    /// the variants so the two cannot drift.
    pub const ALL: [AgentStage; 3] = [
        AgentStage::Submit,
        AgentStage::Review,
        AgentStage::Implement,
    ];

    /// The transition [`allows`] must permit before this stage runs.
    ///
    /// The mapping is the identity on the three shared names; it
    /// exists so a caller of this module never writes a `PlanStage`
    /// literal next to an `AgentStage` and gets the pair wrong.
    pub const fn precondition(self) -> PlanStage {
        match self {
            AgentStage::Submit => PlanStage::Submit,
            AgentStage::Review => PlanStage::Review,
            AgentStage::Implement => PlanStage::Implement,
        }
    }

    /// The slot this stage writes to on a plan with no prior notes.
    ///
    /// Total, unlike the general stage⇒slot direction: `Implement`
    /// owns a family of slots, and this names its first. Callers that
    /// may be extending an existing plan must ask
    /// [`crate::bailiff_plan_read::read_implement_attempts`] instead —
    /// this is for the first run and for tests that sweep the stages.
    pub const fn first_slot(self) -> StageNoteSlot {
        match self {
            AgentStage::Submit => StageNoteSlot::Submission,
            AgentStage::Review => StageNoteSlot::Review,
            AgentStage::Implement => StageNoteSlot::Implement(ImplementAttempt::FIRST),
        }
    }

    /// `Some` iff this stage's prompt splices in a plan body.
    ///
    /// `None` for [`AgentStage::Submit`], which *produces* the plan
    /// body rather than consuming one: its prompt is the operator's
    /// bytes verbatim.
    pub const fn plan_body_stage(self) -> Option<PlanBodyStage> {
        match self {
            AgentStage::Submit => None,
            AgentStage::Review => Some(PlanBodyStage::Review),
            AgentStage::Implement => Some(PlanBodyStage::Implement),
        }
    }
}

/// The agent-run stages that *consume* the plan body a submit
/// produced, and the framing each puts on it.
///
/// `Submit` is absent by construction, which is the point: it produces
/// the body, so "splice the plan body into the planner's own prompt"
/// is not expressible, and [`compose_with_plan_body`] can take this
/// type instead of an [`AgentStage`] plus an `expect`.
///
/// The framing is *derived* here rather than living in a second enum
/// beside this one. The two would be bijective, and a bijective pair
/// of enums is a pair that can disagree — the defect this whole plan
/// removes. The distinction they encode is load-bearing and was got
/// wrong once: slice 1 shipped the stage order inverted, which turned
/// the reviewer's `# Proposed plan` heading into a lie about an
/// already-decided plan (see the plan doc, "The stage order was
/// wrong").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlanBodyStage {
    /// The reviewer. Its feedback is an input to the verdict, so the
    /// plan it reads is still a *proposal*.
    Review,
    /// The implementer. It acts on a plan that carries an accepted
    /// verdict.
    Implement,
}

/// Which note slot a run writes to.
///
/// A refinement of [`AgentStage`], not a duplicate of it: submit and
/// review each own exactly one slot on a plan, while implement owns
/// one *per attempt* since slice 4 made fan-out N implementer runs
/// under one plan. Carrying the attempt here rather than on
/// [`AgentStage`] is what keeps "the third submission" unrepresentable
/// — `AgentStage` still answers the gate and the prompt, which have no
/// attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StageNoteSlot {
    /// The plan's one submission note.
    Submission,
    /// The plan's one review note.
    Review,
    /// One implementer attempt's note.
    Implement(ImplementAttempt),
}

impl StageNoteSlot {
    /// Which agent produced the run this slot records. The projection
    /// back to [`AgentStage`]; the inverse is not a function, because
    /// `Implement` maps to a family.
    pub const fn stage(self) -> AgentStage {
        match self {
            StageNoteSlot::Submission => AgentStage::Submit,
            StageNoteSlot::Review => AgentStage::Review,
            StageNoteSlot::Implement(_) => AgentStage::Implement,
        }
    }

    /// The deterministic seed blob this slot's note attaches at, under
    /// [`crate::bailiff_plan_note::plan_notes_ref`]`(plan_id)`.
    ///
    /// The seed families are disjoint by construction, which is what
    /// lets all of a plan's notes coexist under one ref. Routing every
    /// slot through this projection is what lets `write_stage_note` be
    /// one function: before slice 3b each write helper named its own
    /// seed, so the seed and the note body were chosen in two places
    /// that could disagree.
    pub fn seed(self, plan_id: PlanId) -> Vec<u8> {
        match self {
            StageNoteSlot::Submission => plan_submission_seed_blob_bytes(plan_id),
            StageNoteSlot::Review => plan_review_seed_blob_bytes(plan_id),
            StageNoteSlot::Implement(attempt) => plan_implement_seed_blob_bytes(plan_id, attempt),
        }
    }
}

/// Names the stage in operator-facing text — the noun
/// `WriteStageNoteError` puts in "already recorded for plan …".
/// Matches the wire words `PlanState` / `PlanStage` use.
impl std::fmt::Display for AgentStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let word = match self {
            AgentStage::Submit => "submission",
            AgentStage::Review => "review",
            AgentStage::Implement => "implement",
        };
        f.write_str(word)
    }
}

impl PlanBodyStage {
    /// Both body-consuming stages, for exhaustive tests.
    pub const ALL: [PlanBodyStage; 2] = [PlanBodyStage::Review, PlanBodyStage::Implement];

    /// The separator spliced between the operator's instructions and
    /// the plan body. Byte-identical to the private constants the
    /// review and implement modules held before slice 3 — the RPC
    /// trace fixtures record composed prompts verbatim, so any drift
    /// here fails `review_happy` / `implement_happy` with a diff.
    pub const fn separator(self) -> &'static str {
        match self {
            PlanBodyStage::Review => "\n\n---\n\n# Proposed plan\n\n",
            PlanBodyStage::Implement => "\n\n---\n\n# Approved plan\n\n",
        }
    }

    /// The [`AgentStage`] this refines. The inverse of
    /// [`AgentStage::plan_body_stage`] on its `Some` cases.
    pub const fn stage(self) -> AgentStage {
        match self {
            PlanBodyStage::Review => AgentStage::Review,
            PlanBodyStage::Implement => AgentStage::Implement,
        }
    }
}

/// Splice `body` after `head` under `stage`'s framing.
///
/// Takes raw `&str` rather than a structured plan-body type because
/// the body has already been extracted from the signed planner
/// envelope as bytes — re-wrapping it just to unwrap it again for
/// signing would be churn.
pub fn splice_plan_body(
    head: &str,
    stage: PlanBodyStage,
    body: &str,
) -> Result<AgentPrompt, AgentPromptError> {
    let separator = stage.separator();
    let mut combined = String::with_capacity(head.len() + separator.len() + body.len());
    combined.push_str(head);
    combined.push_str(separator);
    combined.push_str(body);
    AgentPrompt::try_new(combined)
}

// ---------------------------------------------------------------
// Phase 1 — take the plan's lock, then gate.
// ---------------------------------------------------------------

/// Take `plan_id`'s lock and refuse unless the relation allows `stage`
/// from the plan's current state.
///
/// The returned [`PlanGuard`] must be held for the rest of the
/// workflow: the read here is a *gate* only because the lock spans it
/// and the eventual note write. Two workflows on one plan would
/// otherwise both pass this and both proceed, and no later note-write
/// rejection can undo a `WorkspaceWrite` agent run.
///
/// Takes a [`PlanStage`], not an [`AgentStage`], because `decide` runs
/// this phase too — it is the one mutating verb with no agent run, and
/// slice 2's whole point was that it stops being the exception.
pub async fn open_plan_stage(
    bailiff_repo: Arc<NotesRepo>,
    plan_id: PlanId,
    stage: PlanStage,
) -> Result<PlanGuard, OpenPlanStageError> {
    let mut guard = PlanGuard::acquire(bailiff_repo, plan_id)
        .await
        .map_err(OpenPlanStageError::PlanLock)?;
    let state = guard
        .run_blocking(move |repo| summarize_plan(repo, plan_id).map(|s| s.state()))
        .await
        .map_err(OpenPlanStageError::ReadTaskFailed)?
        .map_err(OpenPlanStageError::ReadPlanState)?;
    allows(state, stage)
        .map_err(|source| OpenPlanStageError::IllegalTransition { plan_id, source })?;
    Ok(guard)
}

/// Why a stage could not be opened. All four variants are reachable
/// from every caller, so each caller's map into its own error enum is
/// a total match.
#[derive(Debug, Error)]
pub enum OpenPlanStageError {
    /// The plan's lock could not be taken — a filesystem problem, not
    /// contention; [`PlanGuard::acquire`] waits out contention.
    #[error("locking plan: {0}")]
    PlanLock(#[source] PlanGuardError),
    /// The `spawn_blocking` task owning the state read panicked or was
    /// cancelled. A tokio-runtime condition, not a contract violation.
    #[error("plan-state read task failed: {0}")]
    ReadTaskFailed(#[source] JoinError),
    /// Reading the notes that determine the plan's state failed.
    /// Distinct from [`Self::IllegalTransition`], where the state read
    /// fine and forbids the stage.
    #[error("reading the plan's state failed: {0}")]
    ReadPlanState(#[source] SummarizePlanError),
    /// The state was read and the relation forbids this stage. The
    /// wrapped [`IllegalTransition`] renders the operator's next step
    /// from the relation itself.
    #[error("plan {plan_id}: {source}")]
    IllegalTransition {
        plan_id: PlanId,
        #[source]
        source: IllegalTransition,
    },
}

// ---------------------------------------------------------------
// Phase 2 — read the plan body out of the signed planner envelope
// and splice it into the stage's prompt.
// ---------------------------------------------------------------

/// Read the submission note, fetch and verify the planner envelope it
/// points at, decode the planner's stdout as the plan body, and splice
/// it after `head` under `stage`'s framing.
///
/// Runs under the caller's held `guard`, so it observes the same plan
/// state [`open_plan_stage`] gated on. Pre-RPC by construction: no
/// writ session exists yet, so a missing or unverifiable submission
/// never burns an audit row.
///
/// The `expect` on the submission note is discharged by the gate:
/// every state from which `Review` or `Implement` is legal has a
/// submission, and the lock is what makes that still true here.
pub async fn compose_with_plan_body(
    guard: &mut PlanGuard,
    writ_repo_path: &Path,
    writ_output_ref: &NotesRef,
    allowed_signers: &AllowedSigners,
    plan_id: PlanId,
    head: AgentPrompt,
    stage: PlanBodyStage,
) -> Result<AgentPrompt, ComposePlanPromptError> {
    let writ_repo_path = writ_repo_path.to_path_buf();
    let writ_output_ref = writ_output_ref.clone();
    let allowed_signers = allowed_signers.clone();
    let body = guard
        .run_blocking(move |repo| -> Result<String, ComposePlanPromptError> {
            let plan_note = read_plan_note(repo, plan_id)
                .map_err(ComposePlanPromptError::ReadPlanNote)?
                .expect("gate passed, so a submission note exists");
            read_plan_body_bytes(
                repo,
                &writ_repo_path,
                &writ_output_ref,
                &plan_note,
                &allowed_signers,
            )
            .map_err(ComposePlanPromptError::ReadPlanEnvelope)
        })
        .await
        .map_err(ComposePlanPromptError::ReadTaskFailed)??;

    splice_plan_body(head.as_str(), stage, &body).map_err(ComposePlanPromptError::ComposePrompt)
}

/// Why a plan-body prompt could not be composed. All four variants are
/// reachable from both callers (review and implement).
#[derive(Debug, Error)]
pub enum ComposePlanPromptError {
    /// The `spawn_blocking` task owning the read chain panicked or was
    /// cancelled. A tokio-runtime condition, not a contract violation.
    #[error("plan-body read task failed: {0}")]
    ReadTaskFailed(#[source] JoinError),
    /// Reading the submission note failed. The gate has already passed
    /// by the time this runs, so this is "bailiff's repo broke between
    /// two reads", not "the plan is in the wrong state".
    #[error("reading the plan submission note failed: {0}")]
    ReadPlanNote(#[source] ReadPlanError),
    /// The fetch / verify / decode chain that extracts the plan body
    /// from the planner envelope failed.
    #[error("reading the planner envelope failed: {0}")]
    ReadPlanEnvelope(#[source] ReadPlanBodyError),
    /// The composed prompt exceeded
    /// [`writ::agent_run::MAX_AGENT_PROMPT_BYTES`]. Either the
    /// operator's instructions are large, the plan body is large, or
    /// both; the recourse is to narrow one side.
    #[error("composing the prompt failed: {0}")]
    ComposePrompt(#[source] AgentPromptError),
}

// ---------------------------------------------------------------
// Phase 3 — run the agent and attach the stage's note.
// ---------------------------------------------------------------

/// What a stage sends writ on `RunAgent`, minus the session binding —
/// which is what the two runner functions differ on.
#[derive(Debug)]
pub struct StageRunInputs {
    /// The fully composed prompt. [`AgentPrompt`] already carries the
    /// byte-cap proof, so the runner never sees an oversize prompt.
    pub prompt: AgentPrompt,
    /// Capabilities granted to the run. A `Vec` because the wire shape
    /// is; today each stage sends exactly one.
    pub capabilities: Vec<CapabilitySet>,
    /// Opaque tag writ stores verbatim in its audit row and bailiff
    /// stores on the note. Never policy-interpreted.
    ///
    /// Held as a parsed [`RunPurpose`] so a purpose writ would refuse is
    /// rejected at bailiff's own CLI boundary, before a session is opened
    /// and an audit row spent. The note takes the same value as a
    /// `String`: a note's `purpose` is a historical record that may
    /// predate the type, so the note reader must stay able to read
    /// whatever an older bailiff wrote.
    pub purpose: RunPurpose,
    /// Notes ref writ writes the signed envelope to, and the same ref
    /// the note write later fetches from.
    pub writ_output_ref: NotesRef,
}

/// A writ session bailiff opens, binds, and closes itself.
#[derive(Clone, Debug)]
pub struct OwnedSession {
    /// Human-readable label on writ's audit session row.
    /// Informational only.
    pub label: Option<String>,
    /// Coarse agent identity, used by writ for GitHub-App selection on
    /// credential mints. Optional because a `WorkspaceRead`-only
    /// capability set does not need one.
    pub agent_kind: Option<AgentKind>,
    /// Model identifier stored alongside `agent_kind`.
    pub agent_model: Option<String>,
}

/// A writ session **the broker** mints and closes, on the VM dispatch
/// path.
///
/// The presence of a workspace bootstrap is what routes the run into
/// writd's VM arm, and that arm rejects a request that carries a
/// bootstrap without an agent kind or model — so both are required
/// here rather than optional, and the illegal combination is not
/// constructible.
#[derive(Clone, Debug)]
pub struct BrokerSession {
    /// The per-run VM checkout the agent runs in. Its `repo` must
    /// match the repo of the run's `WorkspaceWrite` capability, or the
    /// push is denied at policy time.
    pub workspace: AgentVmWorkspaceBootstrap,
    /// Coarse agent identity. Required: see the type docs.
    pub agent_kind: AgentKind,
    /// Model identifier. Required: see the type docs.
    pub agent_model: String,
}

/// What a completed stage produced.
#[derive(Clone, Debug)]
pub struct StageRun {
    /// Bailiff-side OID the stage's note is attached at.
    pub note_oid: GitObjectId,
    /// Writ's session id for this run. For an owned session it is the
    /// id bailiff opened; for a broker session it is the id writ
    /// stamped into the signed metadata.
    pub session_id: SessionId,
    /// What writ returned: the envelope OID, signed metadata, and
    /// signature.
    pub run: RunAgentCompleted,
}

/// The wire request for a run bound to a session bailiff owns.
///
/// Separate from the runner so the field-level binding is testable
/// without a broker. `workspace` / `agent_kind` / `agent_model` are
/// `None`: identity was fixed at `OpenSession`, and a workspace
/// bootstrap here would route the run into the VM arm, which rejects a
/// caller-supplied session id.
pub fn owned_run_agent_request(inputs: StageRunInputs, session_id: SessionId) -> RunAgentRequest {
    RunAgentRequest {
        prompt: inputs.prompt,
        capabilities: inputs.capabilities,
        purpose: inputs.purpose,
        output_ref: inputs.writ_output_ref,
        session_id: Some(session_id),
        workspace: None,
        agent_kind: None,
        agent_model: None,
    }
}

/// The wire request for a VM-dispatched run whose session the broker
/// mints.
///
/// `session_id` is `None`: `run_agent_in_vm` rejects a caller-supplied
/// id alongside a workspace bootstrap with "VM mode mints its own
/// audit session". Because that field is hard-coded rather than
/// threaded from an input, the illegal pairing is unreachable rather
/// than merely unused.
pub fn broker_run_agent_request(inputs: StageRunInputs, session: BrokerSession) -> RunAgentRequest {
    RunAgentRequest {
        prompt: inputs.prompt,
        capabilities: inputs.capabilities,
        purpose: inputs.purpose,
        output_ref: inputs.writ_output_ref,
        session_id: None,
        workspace: Some(session.workspace),
        agent_kind: Some(session.agent_kind),
        agent_model: Some(session.agent_model),
    }
}

/// Run the agent under a session bailiff owns, then attach the stage's
/// note — closing the session on every exit path after the open.
///
/// `write_note` is the stage's note writer, applied under the held
/// guard. It is a closure rather than a DU over the three
/// `write_*_note` helpers because those return three distinct error
/// types: a DU would force a three-arm union of which each caller can
/// reach exactly one, which is the unreachable-variant shape this
/// module exists to avoid. Leaving it generic in `N` also keeps
/// `bailiff_plan_write.rs` out of slice 3's diff entirely. Every call
/// site builds the closure on the line above the call, so control flow
/// stays local.
///
/// All six [`OwnedSessionRunError`] variants are reachable from both
/// callers.
pub async fn run_under_owned_session(
    client: &WritClient,
    guard: &mut PlanGuard,
    session: OwnedSession,
    note: StageNoteTarget,
    inputs: StageRunInputs,
) -> Result<StageRun, OwnedSessionRunError> {
    // The same `purpose` and output ref go to writ and onto the note.
    let purpose = inputs.purpose.to_string();
    let writ_output_ref = inputs.writ_output_ref.clone();

    let session_id = client
        .open_session(session.label, session.agent_kind, session.agent_model)
        .await
        .map_err(OwnedSessionRunError::OpenSession)?;

    // From here on, every early return must close the session.
    let completed = match client
        .run_agent(owned_run_agent_request(inputs, session_id))
        .await
    {
        Ok(completed) => completed,
        Err(source) => {
            let _ = client.close_session(session_id).await;
            return Err(OwnedSessionRunError::RunAgent { session_id, source });
        }
    };

    // Cross-check the broker honoured the session binding we asked
    // for: the signed metadata must stamp the same session id we
    // opened. A mismatch means the broker minted its own and the
    // envelope cannot be correlated with our audit row — refuse to
    // persist the note.
    if completed.signed_metadata.session_id != session_id {
        let returned_session_id = completed.signed_metadata.session_id;
        let _ = client.close_session(session_id).await;
        return Err(OwnedSessionRunError::SessionIdMismatch {
            session_id,
            returned_session_id,
        });
    }

    let completed_for_write = completed.clone();
    let write_outcome = guard
        .run_blocking(move |repo| {
            write_stage_note(repo, &note, &writ_output_ref, purpose, &completed_for_write)
        })
        .await;
    let note_oid = match write_outcome {
        Ok(Ok(note_oid)) => note_oid,
        Ok(Err(source)) => {
            let _ = client.close_session(session_id).await;
            return Err(OwnedSessionRunError::WriteNote { session_id, source });
        }
        Err(source) => {
            let _ = client.close_session(session_id).await;
            return Err(OwnedSessionRunError::WriteTaskFailed { session_id, source });
        }
    };

    if let Err(source) = client.close_session(session_id).await {
        return Err(OwnedSessionRunError::CloseSession { session_id, source });
    }

    Ok(StageRun {
        note_oid,
        session_id,
        run: completed,
    })
}

/// Why a run under a bailiff-owned session failed.
///
/// Every variant after [`Self::OpenSession`] carries the [`SessionId`]
/// bailiff minted, and by the time it is returned the close has been
/// *attempted*. [`Self::CloseSession`] is the one variant where the
/// close itself failed, so the session may still be open.
#[derive(Debug, Error)]
pub enum OwnedSessionRunError {
    /// The initial `OpenSession` RPC failed. Nothing to clean up.
    #[error("opening writ session failed: {0}")]
    OpenSession(#[source] WritClientError),
    /// The `RunAgent` RPC failed; the session was closed first so
    /// writ's audit log shows the workflow ending cleanly.
    #[error("RunAgent RPC failed (session {session_id}): {source}")]
    RunAgent {
        session_id: SessionId,
        #[source]
        source: WritClientError,
    },
    /// The broker stamped a different session id into the signed
    /// metadata than the one bailiff bound. The envelope cannot be
    /// correlated to our audit row, so no note is written.
    #[error(
        "broker returned signed metadata bound to session {returned_session_id}, \
         expected {session_id}"
    )]
    SessionIdMismatch {
        /// The id bailiff opened and passed in `RunAgent`.
        session_id: SessionId,
        /// The id the broker actually stamped.
        returned_session_id: SessionId,
    },
    /// The stage's note write failed. Writ already ran the agent and
    /// signed the envelope, so an operator can re-attempt the note
    /// write against the same envelope without re-running the agent.
    #[error("writing the bailiff-side note failed (session {session_id}): {source}")]
    WriteNote {
        session_id: SessionId,
        #[source]
        source: WriteStageNoteError,
    },
    /// The `spawn_blocking` task owning the note write panicked or was
    /// cancelled. A tokio-runtime condition, not a contract violation.
    #[error("note write task failed (session {session_id}): {source}")]
    WriteTaskFailed {
        session_id: SessionId,
        #[source]
        source: JoinError,
    },
    /// The note was written but the closing `CloseSession` failed. The
    /// workflow's persistent state is already in place; this is a
    /// session-row cleanup failure.
    #[error("closing writ session {session_id} failed: {source}")]
    CloseSession {
        session_id: SessionId,
        #[source]
        source: WritClientError,
    },
}

/// Run the agent under a session the **broker** owns, then attach the
/// stage's note.
///
/// No open, no close, and no caller-supplied session id: writd's VM
/// dispatch arm mints its own audit session and `agent_vm.stop_session`
/// closes it before `RunAgent` returns. The session id therefore
/// arrives *in* the signed metadata rather than being chosen by
/// bailiff, which is why there is no cross-check to make here — there
/// is nothing to compare against.
///
/// All three [`BrokerSessionRunError`] variants are reachable from its
/// one caller.
pub async fn run_under_broker_session(
    client: &WritClient,
    guard: &mut PlanGuard,
    session: BrokerSession,
    note: StageNoteTarget,
    inputs: StageRunInputs,
) -> Result<StageRun, BrokerSessionRunError> {
    let purpose = inputs.purpose.to_string();
    let writ_output_ref = inputs.writ_output_ref.clone();

    let completed = client
        .run_agent(broker_run_agent_request(inputs, session))
        .await
        .map_err(BrokerSessionRunError::RunAgent)?;
    let session_id = completed.signed_metadata.session_id;

    let completed_for_write = completed.clone();
    let note_oid = guard
        .run_blocking(move |repo| {
            write_stage_note(repo, &note, &writ_output_ref, purpose, &completed_for_write)
        })
        .await
        .map_err(|source| BrokerSessionRunError::WriteTaskFailed { session_id, source })?
        .map_err(|source| BrokerSessionRunError::WriteNote { session_id, source })?;

    Ok(StageRun {
        note_oid,
        session_id,
        run: completed,
    })
}

/// Why a run under a broker-owned session failed.
///
/// There is no `OpenSession`, `SessionIdMismatch`, or `CloseSession`
/// variant, because there is no code path here that could produce one.
/// The broker-side session is already closed by the time any variant
/// returns.
#[derive(Debug, Error)]
pub enum BrokerSessionRunError {
    /// The `RunAgent` RPC failed. No session id is available — the VM
    /// arm mints its own and closes it before returning — and no
    /// caller-side cleanup is needed.
    #[error("RunAgent RPC failed: {0}")]
    RunAgent(#[source] WritClientError),
    /// The stage's note write failed. Writ already ran the agent and
    /// signed the envelope, so an operator can re-attempt the note
    /// write against the same envelope without re-running the agent.
    #[error("writing the bailiff-side note failed (session {session_id}): {source}")]
    WriteNote {
        session_id: SessionId,
        #[source]
        source: WriteStageNoteError,
    },
    /// The `spawn_blocking` task owning the note write panicked or was
    /// cancelled. A tokio-runtime condition, not a contract violation.
    #[error("note write task failed (session {session_id}): {source}")]
    WriteTaskFailed {
        session_id: SessionId,
        #[source]
        source: JoinError,
    },
}

#[cfg(test)]
mod tests;
