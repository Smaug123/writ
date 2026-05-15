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
//! Pinned 2026-05-15 (open question 1 in
//! `docs/plans/2026-05-14-bailiff-split.md`): one writ session per
//! bailiff plan workflow. `submit_plan` opens the session up front,
//! and any later agent runs for the same plan (review, implement in
//! slices D/E) will reuse the same id rather than mint a new one.
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
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinError;

use crate::agent_run::AgentPrompt;
use crate::bailiff_plan_note::PlanId;
use crate::bailiff_plan_write::{WritePlanNoteError, write_plan_note};
use crate::core::{AgentKind, CapabilitySet, NotesRef, SessionId};
use crate::notes_repo::NotesRepo;
use crate::run_verify::AllowedSigners;
use crate::vm_git::GitObjectId;
use crate::writ_client::{RunAgentCompleted, RunAgentRequest, WritClient, WritClientError};

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
    pub purpose: String,
    /// Notes ref bailiff asks writ to write the envelope to. Today
    /// this is always `refs/notes/writ/v1/agent-outputs`; surfacing
    /// it as a parameter (rather than a constant) keeps the function
    /// honest about the same ref bailiff later passes to
    /// [`write_plan_note`].
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
    /// deterministic seed-blob OID `plan_seed_blob_bytes(plan_id)`
    /// hashes to; callable readers can recompute it but having it on
    /// the result avoids the recomputation.
    pub plan_note_oid: GitObjectId,
    /// Writ's session id for this workflow. Future
    /// review/implementer runs reuse the same id (slice-C session
    /// model).
    pub session_id: SessionId,
    /// What writ returned for the planner run — the OID of the
    /// signed envelope note in writ's repo, plus the signed metadata
    /// and signature. Lets a caller verify or display the run
    /// without a second round-trip.
    pub run: RunAgentCompleted,
}

/// Drive the full plan-submit workflow against a live writ broker.
///
/// `bailiff_repo` is taken as an `Arc<AsyncMutex<_>>` so the
/// single-writer invariant on bailiff's bare repo is visible at the
/// call site and the workflow can compose with other in-flight
/// bailiff operations that share the same handle (today there are
/// none, but the lock makes the contract explicit).
pub async fn submit_plan(
    client: &WritClient,
    bailiff_repo: std::sync::Arc<AsyncMutex<NotesRepo>>,
    writ_repo_path: &Path,
    allowed_signers: AllowedSigners,
    inputs: SubmitPlanInputs,
) -> Result<SubmitPlanOutcome, SubmitPlanError> {
    let session_id = client
        .open_session(
            inputs.session_label.clone(),
            inputs.session_agent_kind,
            inputs.session_agent_model.clone(),
        )
        .await
        .map_err(SubmitPlanError::OpenSession)?;

    // From here on, every early return must close the session.
    let run_result = client
        .run_agent(RunAgentRequest {
            prompt: inputs.prompt,
            capabilities: inputs.capabilities,
            purpose: inputs.purpose.clone(),
            output_ref: inputs.writ_output_ref.clone(),
        })
        .await;
    let completed = match run_result {
        Ok(c) => c,
        Err(source) => {
            let _ = client.close_session(session_id).await;
            return Err(SubmitPlanError::RunAgent { session_id, source });
        }
    };

    // `write_plan_note` is blocking (shells out to git). Wrap in
    // `spawn_blocking` so we don't stall the tokio runtime, and lock
    // the bailiff repo for the duration of the blocking section.
    let writ_repo_path_owned = writ_repo_path.to_path_buf();
    let writ_output_ref_clone = inputs.writ_output_ref.clone();
    let purpose_clone = inputs.purpose.clone();
    let plan_id = inputs.plan_id;
    let completed_clone = completed.clone();
    let bailiff_for_block = std::sync::Arc::clone(&bailiff_repo);
    let write_outcome = tokio::task::spawn_blocking(move || {
        let bailiff = bailiff_for_block.blocking_lock();
        write_plan_note(
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
    let plan_note_oid = match write_outcome {
        Ok(Ok(oid)) => oid,
        Ok(Err(source)) => {
            let _ = client.close_session(session_id).await;
            return Err(SubmitPlanError::WritePlanNote { session_id, source });
        }
        Err(source) => {
            let _ = client.close_session(session_id).await;
            return Err(SubmitPlanError::WriteTaskFailed { session_id, source });
        }
    };

    if let Err(source) = client.close_session(session_id).await {
        return Err(SubmitPlanError::CloseSession { session_id, source });
    }

    Ok(SubmitPlanOutcome {
        plan_id,
        plan_note_oid,
        session_id,
        run: completed,
    })
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
        source: WritePlanNoteError,
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
    use crate::audit::AuditLog;
    use crate::bailiff_plan_note::{PlanNote, plan_submission_ref};
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
            }),
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
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo));
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
            purpose: "plan-submit".into(),
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

        // Plan note decodes from bailiff's repo and references the
        // writ-side OID writ returned.
        let bailiff_for_read = Arc::clone(&bailiff);
        let plan_ref = plan_submission_ref(plan_id);
        let oid = outcome.plan_note_oid.clone();
        let body = tokio::task::spawn_blocking(move || {
            let bailiff = bailiff_for_read.blocking_lock();
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
        let session_id = outcome.session_id;
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
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo));
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
            purpose: "plan-submit".into(),
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
                source: WritePlanNoteError::Verify(_),
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
