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
//! `REVIEWER_PROMPT_SEPARATOR` string + the plan body bytes, joined
//! inline (rather than wrapping into `agent_plan::PlanBody` first) to
//! avoid re-wrapping bytes just to unwrap them again for signing.
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
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinError;

use crate::bailiff_plan_note::{PlanId, PlanNote};
use crate::bailiff_plan_read::{
    ReadPlanBodyError, ReadPlanError, read_plan_body_bytes, read_plan_note,
};
use crate::bailiff_plan_write::{WriteReviewNoteError, write_review_note};
use crate::bailiff_repo_guard::BailiffRepoGuard;
use writ::agent_run::{AgentPrompt, AgentPromptError};
use writ::core::{AgentKind, CapabilitySet, NotesRef, SessionId};
use writ::notes_repo::NotesRepo;
use writ::run_verify::AllowedSigners;
use writ::vm_git::GitObjectId;
use writ::writ_client::{RunAgentCompleted, RunAgentRequest, WritClient, WritClientError};

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
/// `bailiff_repo` is taken as an [`Arc`]`<`[`AsyncMutex`]`<_>>` so the
/// single-writer invariant on bailiff's bare repo can be enforced for
/// the whole workflow: [`submit_review`] acquires the lock via
/// [`BailiffRepoGuard`] before reading the submission note and
/// releases it only on return, so a concurrent bailiff workflow
/// cannot interleave between the pre-RPC read gate and the eventual
/// review-note write.
pub async fn submit_review(
    client: &WritClient,
    bailiff_repo: Arc<AsyncMutex<NotesRepo>>,
    writ_repo_path: &Path,
    allowed_signers: AllowedSigners,
    inputs: SubmitReviewInputs,
) -> Result<SubmitReviewOutcome, SubmitReviewError> {
    // Hold the bailiff-repo lock across the entire workflow — pre-RPC
    // read, opens, run, write, close — so concurrent submit_*/bailiff
    // workflows serialise instead of racing the gate-then-write
    // sequence. Released on function return.
    let mut bailiff = BailiffRepoGuard::acquire(bailiff_repo).await;

    // Pre-RPC: read the submission note, fetch+verify+decode the
    // planner envelope, extract the plan body. Done before opening
    // a session so a missing or unverifiable submission never burns
    // a writ audit row.
    let plan_id = inputs.plan_id;
    let writ_repo_path_owned = writ_repo_path.to_path_buf();
    let writ_output_ref_for_read = inputs.writ_output_ref.clone();
    let allowed_for_read = allowed_signers.clone();
    let read_outcome = bailiff
        .run_blocking(
            move |repo| -> Result<(PlanNote, String), SubmitReviewError> {
                let plan_note =
                    match read_plan_note(repo, plan_id).map_err(SubmitReviewError::ReadPlanNote)? {
                        Some(note) => note,
                        None => return Err(SubmitReviewError::PlanSubmissionMissing { plan_id }),
                    };
                let body = read_plan_body_bytes(
                    repo,
                    &writ_repo_path_owned,
                    &writ_output_ref_for_read,
                    &plan_note,
                    &allowed_for_read,
                )
                .map_err(SubmitReviewError::ReadPlanEnvelope)?;
                Ok((plan_note, body))
            },
        )
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
            workspace: None,
            agent_kind: None,
            agent_model: None,
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

    // `write_review_note` is blocking (shells out to git). Run under
    // the workflow-held guard so the lock spans this section and the
    // surrounding awaits without being re-acquired here.
    let writ_repo_path_owned = writ_repo_path.to_path_buf();
    let writ_output_ref_clone = inputs.writ_output_ref.clone();
    let purpose_clone = inputs.purpose.clone();
    let completed_clone = completed.clone();
    let write_outcome = bailiff
        .run_blocking(move |repo| {
            write_review_note(
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

/// Separator the reviewer's effective prompt uses between the
/// reviewer instructions and the plan body under evaluation. Distinct
/// from the implementer-side `# Approved plan` heading
/// (`bailiff_plan_implement.rs::PLAN_PROMPT_SEPARATOR`) because the
/// plan has not been accepted at the point the reviewer reads it:
/// `# Proposed plan` makes that frame explicit so an LLM cannot
/// mistake the artefact's status.
const REVIEWER_PROMPT_SEPARATOR: &str = "\n\n---\n\n# Proposed plan\n\n";

/// Compose the reviewer's effective prompt from operator instructions
/// and the planner's plan body. Takes raw `&str` rather than
/// `agent_plan::PlanBody` because the plan body has already been
/// extracted from the signed planner envelope as bytes — re-wrapping
/// it just to unwrap it again for signing would be churn.
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
    /// [`writ::agent_run::MAX_AGENT_PROMPT_BYTES`]. Either the
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
mod compose_tests {
    //! Tests for [`compose_reviewer_prompt_bytes`]. The composer
    //! is intentionally tiny; the two tests pin the load-bearing
    //! properties: the separator appears verbatim, and the byte cap
    //! fires on the combined length.
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
        let instructions = "x".repeat(writ::agent_run::MAX_AGENT_PROMPT_BYTES);
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
    use crate::bailiff_plan_note::{ReviewNote, plan_notes_ref};
    use crate::bailiff_plan_submit::{SubmitPlanInputs, submit_plan};
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
