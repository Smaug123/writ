//! Slice-C3 workflow function that drives `bailiff plan submit`:
//! open a writ session, run the planner agent, persist a
//! [`crate::bailiff_plan_note::PlanNote`] in bailiff's repo, close
//! the session.
//!
//! The CLI parsing lives in `src/bin/bailiff.rs`; this module is the
//! pure async function the binary calls once it has validated its
//! inputs, so the workflow is unit/integration-testable without
//! spawning a subprocess.
//!
//! # Session model
//!
//! Pinned 2026-05-16 (open question 1 in
//! `docs/plans/2026-05-14-bailiff-split.md`): a writ session is the
//! authority/audit window for a *single agent run*, not the bailiff
//! workflow. `submit_plan` opens a session for the planner run, issues
//! `RunAgent` under it, and closes it on the happy path — the
//! `planner_session_id` returned in [`SubmitPlanOutcome`] is an audit
//! reference, not a handle later workflow stages reuse.
//!
//! Workflow identity is the bailiff-owned [`PlanId`], threaded across
//! stages and invisible to writ. Slices D/E (review, implement) each
//! open their own writ session per run; all stages attach their notes
//! under the same plan-scoped ref. This supersedes the earlier
//! "one session per plan workflow" pin: writ's
//! [`writ::core::SessionRecord`] carries a single `agent_kind` /
//! `agent_model` chosen at `OpenSession`, so a workflow that uses
//! different agents per stage cannot share one session by
//! construction.
//!
//! # Error handling
//!
//! After the session opens, every failure path attempts to close the
//! session before returning. A close-during-cleanup failure is
//! suppressed in favour of the original error — the original is
//! always the more actionable one. Returning a close-only failure is
//! still surfaced when the workflow itself succeeded.

use std::path::Path;

use thiserror::Error;
use tokio::task::JoinError;

use crate::bailiff_plan_note::PlanId;
use crate::bailiff_plan_read::SummarizePlanError;
use crate::bailiff_plan_state::IllegalTransition;

use crate::bailiff_plan_write::WriteStageNoteError;
use crate::bailiff_repo_guard::PlanGuardError;
use crate::bailiff_stage::{
    AgentStage, OpenPlanStageError, OwnedSession, OwnedSessionRunError, StageNoteSlot,
    StageNoteTarget, StageRunInputs, open_plan_stage, run_under_owned_session,
};
use writ::agent_run::{AgentPrompt, RunPurpose};
use writ::core::{AgentKind, CapabilitySet, NotesRef, SessionId};
use writ::notes_repo::NotesRepo;
use writ::run_verify::AllowedSigners;
use writ::vm_git::GitObjectId;
use writ::writ_client::{RunAgentCompleted, WritClient, WritClientError};

/// Inputs to [`submit_plan`]. An explicit struct keeps the call site
/// readable when more fields land in slices D/E (review-plan id,
/// implementer prompt composition, etc.).
#[derive(Debug)]
pub struct SubmitPlanInputs {
    /// Prompt to forward to the planner agent. The CLI reads bytes
    /// from `--prompt-file` and passes them through
    /// [`AgentPrompt::try_new`] so size validation happens at the
    /// boundary; interior code never sees an oversize prompt.
    pub prompt: AgentPrompt,
    /// Capabilities granted to the planner run. `bailiff plan submit`
    /// builds a single-element `Vec` containing `WorkspaceRead` on
    /// the planner's target repo today; the field is a `Vec` because
    /// the wire shape is and a future stage may grant several.
    pub capabilities: Vec<CapabilitySet>,
    /// Opaque tag bailiff sends on `RunAgent`. Writ stores it
    /// verbatim in its audit row and on the plan note in bailiff's
    /// repo; useful for cross-correlation, never policy-interpreted.
    ///
    /// Parsed at bailiff's CLI boundary, so a purpose writ would refuse
    /// fails before any session is opened or audit row spent.
    pub purpose: RunPurpose,
    /// Notes ref bailiff asks writ to write the envelope to. Today
    /// this is always `refs/notes/writ/v1/agent-outputs`; surfacing
    /// it as a parameter (rather than a constant) keeps the function
    /// honest about the same ref bailiff later passes to
    /// [`crate::bailiff_plan_write::write_stage_note`].
    pub writ_output_ref: NotesRef,
    /// Optional human-readable session label. Stored on writ's audit
    /// session row; informational only.
    pub session_label: Option<String>,
    /// Optional coarse agent identity. Writ uses it for GitHub-App
    /// selection on credential mints; with a `WorkspaceRead`-only
    /// capability set today the field is unused, but is plumbed so
    /// slice D/E reviewer/implementer runs (which mint GitHub
    /// credentials) can pass it without a downstream refactor.
    pub session_agent_kind: Option<AgentKind>,
    /// Optional model identifier (e.g. `"claude-opus-4-7"`). Stored
    /// on writ's audit session row alongside `agent_kind`.
    pub session_agent_model: Option<String>,
    /// Bailiff's plan id. The CLI allocates one with [`PlanId::new`]
    /// when `--plan-id` is absent so the workflow always sees a
    /// concrete id; surfacing the type here lets the CLI generate it
    /// at the boundary rather than mid-workflow.
    pub plan_id: PlanId,
}

/// Outcome of a successful [`submit_plan`] call. Carries the inputs
/// a caller needs to refer back to the persisted artefacts without
/// re-deriving them.
#[derive(Clone, Debug)]
pub struct SubmitPlanOutcome {
    /// The plan id used (passed through from
    /// [`SubmitPlanInputs::plan_id`]; surfaced again so the CLI can
    /// print it without juggling the input back to the call site).
    pub plan_id: PlanId,
    /// Bailiff-side OID where the plan note is attached. The
    /// deterministic seed-blob OID `plan_submission_seed_blob_bytes(plan_id)`
    /// hashes to; callable readers can recompute it but having it on
    /// the result avoids the recomputation.
    pub plan_note_oid: GitObjectId,
    /// Writ's session id for the *planner run only* — the
    /// authority/audit window writ minted for this `RunAgent` call,
    /// closed on the happy path before this outcome is returned.
    /// Surfaced so callers can correlate the run with writ's audit
    /// row; it is not a handle later workflow stages reuse (each
    /// stage opens its own session per the pinned 2026-05-16 model).
    pub planner_session_id: SessionId,
    /// What writ returned for the planner run — the OID of the
    /// signed envelope note in writ's repo, plus the signed metadata
    /// and signature. Lets a caller verify or display the run
    /// without a second round-trip.
    pub run: RunAgentCompleted,
}

/// Drive the full plan-submit workflow against a live writ broker.
///
/// Two phases from [`crate::bailiff_stage`], composed: gate, then run
/// under a session bailiff owns. The plan lock
/// [`crate::bailiff_stage::open_plan_stage`] returns is held until this
/// function returns, so the gate and the eventual note write cannot be
/// interleaved by another workflow — in this process or another.
///
/// `submit` is the stage with no prompt composition phase: it
/// *produces* the plan body every later stage reads, so the operator's
/// prompt goes to the planner verbatim. That is why
/// [`AgentStage::Submit`] has no
/// [`crate::bailiff_stage::PlanBodyStage`].
pub async fn submit_plan(
    client: &WritClient,
    bailiff_repo: std::sync::Arc<NotesRepo>,
    writ_repo_path: &Path,
    allowed_signers: AllowedSigners,
    inputs: SubmitPlanInputs,
) -> Result<SubmitPlanOutcome, SubmitPlanError> {
    // Pre-RPC gate. `submit` had none before slice 1: it opened a
    // session and ran the planner immediately, so submitting against
    // an id that already had a plan note burned a full agent run
    // before `write_plan_note` refused the duplicate. `Submit` is
    // legal only from `Absent`, so that now costs nothing.
    let plan_id = inputs.plan_id;
    let mut guard =
        open_plan_stage(bailiff_repo, plan_id, AgentStage::Submit.precondition()).await?;

    let stage = run_under_owned_session(
        client,
        &mut guard,
        OwnedSession {
            label: inputs.session_label,
            agent_kind: inputs.session_agent_kind,
            agent_model: inputs.session_agent_model,
        },
        StageNoteTarget {
            slot: StageNoteSlot::Submission,
            plan_id,
            writ_repo_path: writ_repo_path.to_path_buf(),
            allowed_signers,
        },
        StageRunInputs {
            prompt: inputs.prompt,
            capabilities: inputs.capabilities,
            purpose: inputs.purpose,
            writ_output_ref: inputs.writ_output_ref,
        },
    )
    .await?;

    Ok(SubmitPlanOutcome {
        plan_id,
        plan_note_oid: stage.note_oid,
        planner_session_id: stage.session_id,
        run: stage.run,
    })
}

/// Total map from the gate phase's failures onto this workflow's. All
/// four variants are produced by [`open_plan_stage`] for every caller,
/// so the match is exhaustive with no unreachable arm — which is the
/// property that made a phase vocabulary preferable to one union
/// `StageError`.
impl From<OpenPlanStageError> for SubmitPlanError {
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

/// Total map from the owned-session run phase's failures onto this
/// workflow's. See [`From<OpenPlanStageError>`](SubmitPlanError).
impl From<OwnedSessionRunError> for SubmitPlanError {
    fn from(source: OwnedSessionRunError) -> Self {
        match source {
            OwnedSessionRunError::OpenSession(source) => Self::OpenSession(source),
            OwnedSessionRunError::RunAgent { session_id, source } => {
                Self::RunAgent { session_id, source }
            }
            OwnedSessionRunError::SessionIdMismatch {
                session_id,
                returned_session_id,
            } => Self::SessionIdMismatch {
                session_id,
                returned_session_id,
            },
            OwnedSessionRunError::WriteNote { session_id, source } => {
                Self::WritePlanNote { session_id, source }
            }
            OwnedSessionRunError::WriteTaskFailed { session_id, source } => {
                Self::WriteTaskFailed { session_id, source }
            }
            OwnedSessionRunError::CloseSession { session_id, source } => {
                Self::CloseSession { session_id, source }
            }
        }
    }
}

/// Tagged failure modes of [`submit_plan`]. Each variant pins one
/// concrete failure step so the CLI can map it to the right operator
/// message: "couldn't reach writ" vs "writ refused the run" vs
/// "envelope didn't verify" are distinct problems.
///
/// Every variant after the initial `OpenSession` failure carries
/// the [`SessionId`] [`submit_plan`] minted. By the time the variant
/// is returned, [`submit_plan`] has *attempted* to close that
/// session — the id is for operator-visible diagnostics
/// (cross-reference against writ's audit log) and for tests pinning
/// the close-on-error contract. `CloseSession` is the one variant
/// where the close itself failed; the session may still be open in
/// that case.
#[derive(Debug, Error)]
pub enum SubmitPlanError {
    /// This plan's lock could not be taken — another bailiff process
    /// is working on it, or the lockfile is unusable. Pre-RPC: no
    /// session was opened and no note was read.
    #[error("locking plan: {0}")]
    PlanLock(#[source] PlanGuardError),
    /// The `spawn_blocking` task that owns the pre-RPC state read
    /// panicked or was cancelled. Pre-RPC: no session was opened.
    #[error("plan-state read task failed: {0}")]
    ReadTaskFailed(#[source] JoinError),
    /// Reading the four notes to determine the plan's state failed.
    /// Distinct from [`Self::IllegalTransition`] (the state was read
    /// fine and forbids the stage). Pre-RPC.
    #[error("reading the plan's state failed: {0}")]
    ReadPlanState(#[source] SummarizePlanError),
    /// The plan id already has notes attached, so `submit` may not
    /// run against it. Pre-RPC — the point of the gate is that this
    /// costs no agent run, which the pre-slice-1 code could not say.
    #[error("plan {plan_id}: {source}")]
    IllegalTransition {
        plan_id: PlanId,
        #[source]
        source: IllegalTransition,
    },
    /// The initial `OpenSession` RPC failed. Workflow never started;
    /// no cleanup needed.
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
    /// Fetch/verify/write of the bailiff-side plan note failed. Writ
    /// already ran the agent and signed the envelope, so an operator
    /// can re-attempt the plan-note write against the same envelope
    /// without re-running the agent.
    #[error("writing the bailiff-side plan note failed (session {session_id}): {source}")]
    WritePlanNote {
        session_id: SessionId,
        #[source]
        source: WriteStageNoteError,
    },
    /// The `spawn_blocking` task that owns the `write_plan_note`
    /// call panicked or was cancelled. Surfaces separately from
    /// `WritePlanNote` because the cause is a tokio-runtime
    /// condition, not a bailiff/writ contract violation.
    #[error("plan-note write task failed (session {session_id}): {source}")]
    WriteTaskFailed {
        session_id: SessionId,
        #[source]
        source: JoinError,
    },
    /// The plan-note was written but the closing `CloseSession`
    /// failed. The workflow's persistent state (the plan note in
    /// bailiff's repo) is already in place; this is a session-row
    /// cleanup failure that an operator can ignore in most cases,
    /// but the variant surfaces it so scripts can react if needed.
    #[error("closing writ session {session_id} after plan submit failed: {source}")]
    CloseSession {
        session_id: SessionId,
        #[source]
        source: WritClientError,
    },
    /// The broker stamped a different session id into the signed
    /// metadata than the one we asked it to bind. Indicates the broker
    /// is at a wire version that ignores the `session_id` field — the
    /// envelope is unusable because it can't be correlated to our
    /// audit row. The session bailiff opened was closed before this
    /// error returned; no bailiff-side plan note is written.
    #[error(
        "broker returned signed metadata bound to session {returned_session_id}, \
         expected {session_id}"
    )]
    SessionIdMismatch {
        /// The session id bailiff opened and passed in `RunAgent`.
        session_id: SessionId,
        /// The session id the broker actually stamped into the signed
        /// metadata.
        returned_session_id: SessionId,
    },
}

#[cfg(test)]
mod end_to_end_tests {
    //! End-to-end against a real writ broker. Mirrors
    //! `bailiff_plan_write::end_to_end_tests`: bring up the broker,
    //! drive `submit_plan`, assert the plan note ended up in
    //! bailiff's repo and the session row in writ's audit log
    //! transitions open → closed.
    //!
    //! What this exercises beyond the slice-C2 end-to-end:
    //! - The full session lifecycle (open before submit, close
    //!   after). A regression that drops `OpenSession` or
    //!   `CloseSession` fails this test rather than getting caught
    //!   downstream.
    //! - The error-path session close: with a deliberately-broken
    //!   `allowed_signers`, the plan-note write fails *and* the
    //!   session still closes — confirming the cleanup behaviour the
    //!   error docstrings promise.
    use std::collections::{BTreeMap, HashMap};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use wiremock::MockServer;

    use super::*;
    use crate::bailiff_plan_note::{PlanNote, plan_notes_ref};
    use crate::bailiff_plan_state::{PlanStage, PlanState};
    use crate::bailiff_plan_write::{FetchVerifyError, WriteStageNoteError};
    use writ::audit::AuditLog;
    use writ::core::{AgentKind, CapabilitySet, NotesRef, RepoRef, TtlSeconds};
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
    const OTHER_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing_other.key.pub");
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
    /// handle, tempdir, writ repo path). Reused by the happy-path
    /// and error-path tests.
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
                agent_kind: writ::core::AgentKind::Claude,
                log_root: writ::config::AgentRunLogRoot::check(tmp.path().join("agent-runs"))
                    .unwrap(),
            }),
            agent_run_slots: Default::default(),
            promote_runtime: None,
            git_data_http: std::sync::OnceLock::new(),
            mirror_pins: writ::vm_git_mirror_cache::MirrorPins::new(),
            chatgpt_oauth_authority: Default::default(),
        });
        let socket_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        // Leak the socket dir for the lifetime of the test — the broker
        // task holds the listener; we keep the tempdir alive by leaking
        // the handle into the returned tuple. Simpler than threading a
        // guard.
        let socket_path = socket_dir.path().join("writ.sock");
        std::mem::forget(socket_dir);
        let listener = prepare_broker_listener(&socket_path).await.unwrap();
        let broker_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let _ = serve_broker_with_agent_vm(listener, broker_state, None).await;
        });
        (state, socket_path, task)
    }

    /// Happy path: open a session, run a noop agent through `cat`,
    /// write the plan note into bailiff's repo, close the session.
    /// All four steps observed externally — the plan note decodes,
    /// and writ's audit log records the session as closed.
    #[tokio::test]
    async fn submit_plan_round_trips_through_open_run_write_close() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(bailiff_repo);
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let plan_id = PlanId::new();
        let inputs = SubmitPlanInputs {
            prompt: AgentPrompt::try_new("noop\n").unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            purpose: "plan-submit".parse().unwrap(),
            writ_output_ref: NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_label: Some("plan-submit:test".into()),
            session_agent_kind: Some(AgentKind::Claude),
            session_agent_model: Some("claude-test".into()),
            plan_id,
        };

        let client = WritClient::new(&socket_path);
        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            submit_plan(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed,
                inputs,
            ),
        )
        .await
        .expect("submit_plan must complete within 15s")
        .expect("submit_plan must succeed under the trusted-signer keyring");

        assert_eq!(outcome.plan_id, plan_id);

        // The signed metadata writ produced stamps the same session id
        // bailiff opened. This is the P2 invariant: a verifier can
        // correlate the envelope back to writ's audit session row.
        assert_eq!(
            outcome.run.signed_metadata.session_id, outcome.planner_session_id,
            "signed metadata must bind the session id bailiff opened",
        );

        // Plan note decodes from bailiff's repo and references the
        // writ-side OID writ returned.
        let bailiff_for_read = Arc::clone(&bailiff);
        let plan_ref = plan_notes_ref(plan_id);
        let oid = outcome.plan_note_oid.clone();
        let body = tokio::task::spawn_blocking(move || {
            let bailiff = &*bailiff_for_read;
            bailiff.read_note(&plan_ref, &oid)
        })
        .await
        .unwrap()
        .expect("bailiff-side plan note must be readable at the returned OID");
        let note = PlanNote::from_canonical_bytes(&body).unwrap();
        assert_eq!(note.plan_id, plan_id);
        assert_eq!(note.purpose, "plan-submit");
        assert_eq!(note.writ_output_oid, outcome.run.output_oid);
        assert_eq!(note.signed_metadata, outcome.run.signed_metadata);
        assert_eq!(note.signature, outcome.run.signature);

        // Writ's audit log recorded the session bailiff opened and
        // shows it as closed — confirms `CloseSession` ran.
        let audit = Arc::clone(&state.audit);
        let session_id = outcome.planner_session_id;
        let session_row = tokio::task::spawn_blocking(move || audit.get_session(session_id))
            .await
            .unwrap()
            .expect("session row read must succeed")
            .expect("session must exist in audit log");
        assert!(
            session_row.closed_at.is_some(),
            "session must be closed after submit_plan returns"
        );

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Behaviour delta (slice 1): re-submitting against a plan id
    /// that already has notes is refused *before* the planner runs.
    ///
    /// `submit_plan` previously had no pre-RPC gate at all — it
    /// opened a session and ran the planner immediately, so a
    /// repeated `--plan-id` burned a full agent run before
    /// `write_plan_note`'s idempotency check refused the duplicate.
    /// `Submit` is legal only from `Absent`, so the same mistake is
    /// now free. Witnessed against writ's audit log: the second call
    /// leaves no new session row.
    #[tokio::test]
    async fn submit_plan_refuses_a_duplicate_plan_id_before_running_the_planner() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(bailiff_repo);
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let plan_id = PlanId::new();
        let inputs = || SubmitPlanInputs {
            prompt: AgentPrompt::try_new("noop\n").unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            purpose: "plan-submit".parse().unwrap(),
            writ_output_ref: NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_label: None,
            session_agent_kind: Some(AgentKind::Claude),
            session_agent_model: None,
            plan_id,
        };

        let client = WritClient::new(&socket_path);
        let first = tokio::time::timeout(
            Duration::from_secs(15),
            submit_plan(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed.clone(),
                inputs(),
            ),
        )
        .await
        .expect("first submit_plan must return within 15s")
        .expect("first submit_plan must succeed");

        let err = tokio::time::timeout(
            Duration::from_secs(15),
            submit_plan(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed,
                inputs(),
            ),
        )
        .await
        .expect("second submit_plan must return within 15s")
        .expect_err("a duplicate plan id must be refused");

        match &err {
            SubmitPlanError::IllegalTransition {
                plan_id: found,
                source,
            } => {
                assert_eq!(*found, plan_id);
                assert_eq!(source.state, PlanState::Submitted);
                assert_eq!(source.stage, PlanStage::Submit);
            }
            other => panic!("expected IllegalTransition, got: {other:?}"),
        }

        // The first planner session is the only one, and it closed
        // cleanly. A pre-slice-1 binary would have opened a second.
        let first_session = first.planner_session_id;
        let audit = Arc::clone(&state.audit);
        let row = tokio::task::spawn_blocking(move || audit.get_session(first_session))
            .await
            .unwrap()
            .expect("session row read must succeed")
            .expect("first planner session must exist");
        assert!(row.closed_at.is_some());

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// Error path: an `allowed_signers` set that doesn't contain
    /// writ's key makes `write_plan_note` fail with `Verify` — and
    /// the session must still close, so a follow-up `CloseSession`
    /// from somewhere else doesn't double-close.
    #[tokio::test]
    async fn submit_plan_closes_session_on_write_plan_note_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (state, socket_path, broker_task) = spawn_broker(&tmp, signing_key.clone()).await;

        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(bailiff_repo);
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        // The other key is on the keyring — writ signs with the
        // primary key — so verification fails with `UnknownSigner`.
        let allowed = AllowedSigners::from_openssh_lines(OTHER_PUB).unwrap();
        let plan_id = PlanId::new();
        let inputs = SubmitPlanInputs {
            prompt: AgentPrompt::try_new("noop\n").unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            purpose: "plan-submit".parse().unwrap(),
            writ_output_ref: NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_label: None,
            // Broker rejects `OpenSession` without an agent kind when
            // a GitHub-app registry is configured (the path
            // `submit_plan` exercises). Pass `Claude` so the failure
            // we're pinning lands in `write_plan_note`, not in
            // `open_session`.
            session_agent_kind: Some(AgentKind::Claude),
            session_agent_model: None,
            plan_id,
        };

        let client = WritClient::new(&socket_path);
        let err = tokio::time::timeout(
            Duration::from_secs(15),
            submit_plan(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed,
                inputs,
            ),
        )
        .await
        .expect("submit_plan must return within 15s")
        .expect_err("untrusted signer must surface as WritePlanNote(Verify(_))");

        // The error carries the session id `submit_plan` minted —
        // use it to verify the cleanup `CloseSession` ran against
        // writ's audit log.
        let session_id = match &err {
            SubmitPlanError::WritePlanNote {
                session_id,
                source: WriteStageNoteError::FetchVerify(FetchVerifyError::Verify(_)),
            } => *session_id,
            other => panic!("expected WritePlanNote{{Verify}}, got {other:?}"),
        };

        let audit = Arc::clone(&state.audit);
        let session_row = tokio::task::spawn_blocking(move || audit.get_session(session_id))
            .await
            .unwrap()
            .expect("session row read must succeed")
            .expect("session must exist in audit log");
        assert!(
            session_row.closed_at.is_some(),
            "submit_plan must close its session even when write_plan_note fails",
        );

        broker_task.abort();
        let _ = broker_task.await;
    }
}

#[cfg(test)]
mod session_mismatch_tests {
    //! Stub-broker unit test for [`SubmitPlanError::SessionIdMismatch`].
    //!
    //! The real broker honours the caller-supplied session id, so the
    //! mismatch path can't be exercised against `serve_broker_with_agent_vm`.
    //! Instead, drive a minimal Unix-socket stub that returns canned
    //! replies in lockstep: `SessionOpened { X }`, `RunAgentCompleted`
    //! with signed metadata stamping a *different* session id `Y`,
    //! then `SessionClosed`. The assertion is that `submit_plan` bails
    //! at the cross-check with both ids surfaced in the error variant,
    //! and that the cleanup `CloseSession` still ran (the stub records
    //! the third request it saw).
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tokio::sync::Mutex as AsyncMutex;
    use tokio::task::JoinHandle;

    use super::*;
    use writ::agent_run::AgentPrompt;
    use writ::core::{
        AgentKind, CapabilitySet, NotesRef, RepoRef, Sha256Hex, SshKeyFingerprint, SshSignature,
        UnixMillis,
    };
    use writ::notes_repo::NotesRepo;
    use writ::protocol::{ClientMessage, ServerMessage, SignedRunMetadata};
    use writ::run_verify::AllowedSigners;
    use writ::vm_git::GitObjectId;

    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");

    /// One-shot stub: each accepted connection reads one
    /// [`ClientMessage`], records it, then writes the next queued
    /// [`ServerMessage`]. Modelled on the broker stub in
    /// `writ_client::tests` but lives here so the test can read the
    /// recorded sequence after `submit_plan` returns.
    struct StubBroker {
        socket_path: PathBuf,
        requests: Arc<AsyncMutex<Vec<ClientMessage>>>,
        _task: JoinHandle<()>,
        _dir: tempfile::TempDir,
    }

    impl StubBroker {
        async fn start(replies: Vec<ServerMessage>) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let socket_path = dir.path().join("writ.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let requests = Arc::new(AsyncMutex::new(Vec::new()));
            let req_clone = Arc::clone(&requests);
            let mut replies = replies.into_iter();
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let Some(reply) = replies.next() else {
                        return;
                    };
                    let (reader, mut writer) = stream.into_split();
                    let mut lines = BufReader::new(reader).lines();
                    if let Ok(Some(line)) = lines.next_line().await
                        && let Ok(msg) = serde_json::from_str::<ClientMessage>(&line)
                    {
                        req_clone.lock().await.push(msg);
                    }
                    let mut json = serde_json::to_string(&reply).unwrap();
                    json.push('\n');
                    let _ = writer.write_all(json.as_bytes()).await;
                    let _ = writer.shutdown().await;
                }
            });
            Self {
                socket_path,
                requests,
                _task: task,
                _dir: dir,
            }
        }

        async fn observed(&self) -> Vec<ClientMessage> {
            self.requests.lock().await.clone()
        }
    }

    fn sample_oid() -> GitObjectId {
        std::iter::repeat_n('a', 40)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    fn sample_signed_metadata(session_id: SessionId) -> SignedRunMetadata {
        SignedRunMetadata {
            run_id: "f2f2f2f2-0000-0000-0000-000000000001".parse().unwrap(),
            session_id,
            prompt_sha256: Sha256Hex::try_new(std::iter::repeat_n('a', 64).collect::<String>())
                .unwrap(),
            output_envelope_sha256: Sha256Hex::try_new(
                std::iter::repeat_n('b', 64).collect::<String>(),
            )
            .unwrap(),
            capabilities: Vec::new(),
            exit_code: 0,
            completed_at: UnixMillis::from_millis(1_700_000_000_000),
            signing_key_fingerprint: SshKeyFingerprint::try_new(
                "SHA256:Wn0p0WC9F8bJ35rwTRsLP6w8b9ZsZh4HX0FYpC0Zg",
            )
            .unwrap(),
        }
    }

    fn sample_signature() -> SshSignature {
        SshSignature::try_new(
            "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ...\n-----END SSH SIGNATURE-----",
        )
        .unwrap()
    }

    /// When the broker stamps a different session id into the signed
    /// metadata than the one bailiff opened, `submit_plan` bails with
    /// [`SubmitPlanError::SessionIdMismatch`] carrying both ids, and
    /// the cleanup `CloseSession` still runs against the original id
    /// — the third frame the stub saw must be `CloseSession { X }`.
    #[tokio::test]
    async fn submit_plan_rejects_mismatched_session_id_and_still_closes_session() {
        let opened_id = SessionId::new();
        let mismatched_id = SessionId::new();
        assert_ne!(opened_id, mismatched_id);

        let broker = StubBroker::start(vec![
            ServerMessage::SessionOpened {
                session_id: opened_id,
            },
            ServerMessage::RunAgentCompleted {
                output_oid: sample_oid(),
                signed_metadata: sample_signed_metadata(mismatched_id),
                signature: sample_signature(),
            },
            ServerMessage::SessionClosed,
        ])
        .await;

        // bailiff repo / allowed_signers are not touched on the
        // mismatch path (the bail-out is before `write_plan_note`), so
        // an inert temp repo and a real-but-unused signer set are
        // fine.
        let tmp = tempfile::tempdir().unwrap();
        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let bailiff = Arc::new(bailiff_repo);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let writ_repo_path = tmp.path().join("writ-bare-never-read");

        let inputs = SubmitPlanInputs {
            prompt: AgentPrompt::try_new("noop\n").unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            purpose: "plan-submit".parse().unwrap(),
            writ_output_ref: NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_label: None,
            session_agent_kind: Some(AgentKind::Claude),
            session_agent_model: None,
            plan_id: PlanId::new(),
        };

        let client = WritClient::new(&broker.socket_path);
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            submit_plan(
                &client,
                Arc::clone(&bailiff),
                &writ_repo_path,
                allowed,
                inputs,
            ),
        )
        .await
        .expect("submit_plan must complete within 5s")
        .expect_err("mismatched session id must surface as SessionIdMismatch");

        match err {
            SubmitPlanError::SessionIdMismatch {
                session_id,
                returned_session_id,
            } => {
                assert_eq!(session_id, opened_id);
                assert_eq!(returned_session_id, mismatched_id);
            }
            other => panic!("expected SessionIdMismatch, got {other:?}"),
        }

        // The stub records each ClientMessage it served. Sequence
        // pinned: OpenSession, RunAgent (with the opened id), then
        // CloseSession on the cleanup path — the workflow does not
        // skip cleanup when bailing on the mismatch.
        let seen = broker.observed().await;
        assert_eq!(seen.len(), 3, "expected three RPCs, got {seen:?}");
        assert!(
            matches!(seen[0], ClientMessage::OpenSession { .. }),
            "first RPC was not OpenSession: {:?}",
            seen[0],
        );
        match &seen[1] {
            ClientMessage::RunAgent { session_id, .. } => assert_eq!(
                *session_id,
                Some(opened_id),
                "RunAgent must thread the opened session id",
            ),
            other => panic!("expected RunAgent, got {other:?}"),
        }
        match &seen[2] {
            ClientMessage::CloseSession { session_id } => assert_eq!(*session_id, opened_id),
            other => panic!("expected CloseSession, got {other:?}"),
        }
    }
}
