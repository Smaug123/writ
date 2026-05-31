//! Unix socket listener and request dispatcher.
//!
//! The broker serves one connection at a time within each tokio task.
//! Requests from different panes arrive on different connections and are
//! multiplexed by the tokio scheduler; per-connection processing is
//! strictly sequential (one line in → one line out).
//!
//! The testable core is [`dispatch_message`]: it takes a [`ClientMessage`]
//! and shared broker state, and returns a [`ServerMessage`]. Socket I/O
//! lives in `handle_connection` and only calls [`dispatch_message`].
//! All tests exercise [`dispatch_message`] directly.

use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::agent_run::{AgentPrompt, AgentRunId, sha256_hex};
use crate::agent_vm_daemon::AgentVmDaemon;
use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, AuditLog, GitPushOutcomeResult, GitPushResolution,
    GitPushResolutionRecord, PreMintRecord, PromoteMintAudit, ReconciliationTarget, RejectBlocker,
};
use crate::core::{
    ApproveAttemptId, CapabilityRequest, GITHUB_INSTALLATION_TOKEN_MAX_SECONDS, GitHubAccess,
    GitHubGrantedScope, GitHubPermissions, GrantedScope, MetadataAccess, PolicyDecision, RequestId,
    SessionId, SessionRecord, TtlSeconds, UnixMillis,
};
use crate::core::{NotesRef, Sha256Hex};
use crate::git_push_approve::{RunApproveError, run_approve};
use crate::git_push_promote::{ExecuteError, PromoteRuntimeConfig};
use crate::git_push_staging::{GitPushStagingStore, StagedEntry, StagingError};
use crate::github::GitHubMinter;
use crate::notes_repo::NotesRepo;
use crate::policy::{self, PolicyConfig};
use crate::protocol::{
    ClientMessage, ReconcileOutcome, RejectionReason, ServerMessage, SignedRunMetadata,
    StagedPushAuditView, StagedPushDetail, StagedPushSummary,
};
use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use crate::secret::SecretStore;
use crate::signing::WritSigningKey;
use crate::vm_git_bundle::GitSecretValue;

/// Boot-time description of the child process that produces an agent
/// run's stdout. Pure data — dispatch reads `command` and `args`,
/// hands them to `tokio::process::Command`, writes the prompt bytes
/// to the child's stdin, and captures stdout. The shell — *which*
/// binary writ launches — is set at boot; the wire `RunAgent` request
/// does not choose it, so a `RunAgent` caller cannot smuggle in an
/// arbitrary command.
///
/// Slice B accepts a single fixed command for the whole daemon; the
/// agent-kind selection that bailiff will eventually drive arrives in
/// slice C alongside the session-per-workflow refinement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunAgentSpawnConfig {
    pub command: std::path::PathBuf,
    pub args: Vec<String>,
}

/// Shared state for the broker. Wrapped in `Arc` so connections spawned
/// onto different tokio tasks can all reference the same audit log,
/// minter config, and secret store.
///
/// `staging_store` is `Some` exactly when the daemon was configured with
/// agent-VM HTTP support (the staging root lives under `vm_http`).
/// Promote operations fail with a configuration error when it is `None`.
///
/// `notes_repo`, `signing_key`, and `run_agent_spawn` form the
/// `RunAgent` triple: each must be `Some` for [`ClientMessage::RunAgent`]
/// to dispatch. They are independent because writd boots in
/// configurations that don't need agent-run signing (e.g. agent-VM-only
/// tests) and a missing one should be reported as an explicit
/// configuration error, not a generic "broker confused" failure.
///
/// `promote_runtime` is `Some` exactly when writd was booted with agent-VM
/// HTTP support; it carries the git/credential/work-root/step-timeout
/// values needed to execute an approved staged push. The handler for
/// [`ClientMessage::ApproveStagedPush`] returns a clean configuration
/// error when this is `None`, same as the `RunAgent` triple does.
pub struct BrokerState<S: SecretStore> {
    pub audit: Arc<AuditLog>,
    pub minter: GitHubMinter,
    pub secrets: S,
    pub policy: PolicyConfig,
    pub staging_store: Option<Arc<GitPushStagingStore>>,
    pub notes_repo: Option<Arc<NotesRepo>>,
    pub signing_key: Option<WritSigningKey>,
    pub run_agent_spawn: Option<RunAgentSpawnConfig>,
    pub promote_runtime: Option<Arc<PromoteRuntimeConfig>>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum CapabilityOutcome {
    Granted {
        token: String,
        expires_at: UnixMillis,
    },
    Denied {
        reason: String,
    },
    UnknownSession {
        session_id: SessionId,
    },
    ClosedSession {
        session_id: SessionId,
    },
    Error {
        message: String,
    },
}

impl std::fmt::Debug for CapabilityOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Granted { expires_at, .. } => f
                .debug_struct("Granted")
                .field("token", &"<redacted>")
                .field("expires_at", expires_at)
                .finish(),
            Self::Denied { reason } => f.debug_struct("Denied").field("reason", reason).finish(),
            Self::UnknownSession { session_id } => f
                .debug_struct("UnknownSession")
                .field("session_id", session_id)
                .finish(),
            Self::ClosedSession { session_id } => f
                .debug_struct("ClosedSession")
                .field("session_id", session_id)
                .finish(),
            Self::Error { message } => f.debug_struct("Error").field("message", message).finish(),
        }
    }
}

/// Return the default Unix socket path. Uses `$XDG_RUNTIME_DIR/writ/writd.sock`
/// when set, falling back to `$HOME/.local/run/writ/writd.sock`.
pub fn default_socket_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        PathBuf::from(dir).join("writ/writd.sock")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
        PathBuf::from(home).join(".local/run/writ/writd.sock")
    }
}

/// Evaluate one [`ClientMessage`] and produce a [`ServerMessage`].
/// This is the only function that touches business logic; the socket
/// loop calls it once per line without knowing what it does.
pub async fn dispatch_message<S: SecretStore + Send + Sync + 'static>(
    msg: ClientMessage,
    state: &Arc<BrokerState<S>>,
) -> ServerMessage {
    dispatch_message_with_agent_vm(msg, state, None).await
}

/// Evaluate one message with an optional daemon-managed agent VM controller.
/// Use this entry point when `writd` was configured with agent-VM support; the
/// simpler [`dispatch_message`] wrapper delegates here with no controller.
pub async fn dispatch_message_with_agent_vm<S: SecretStore + Send + Sync + 'static>(
    msg: ClientMessage,
    state: &Arc<BrokerState<S>>,
    agent_vm: Option<&Arc<AgentVmDaemon>>,
) -> ServerMessage {
    match msg {
        ClientMessage::OpenSession {
            label,
            agent_kind,
            agent_model,
        } => {
            if agent_kind.is_none() {
                return missing_agent_kind_for_registry_response();
            }
            let session_id = SessionId::new();
            let record = SessionRecord {
                session_id,
                label,
                agent_kind,
                agent_model,
                opened_at: UnixMillis::now(),
                closed_at: None,
            };
            match state.audit.open_session(&record) {
                Ok(()) => ServerMessage::SessionOpened { session_id },
                Err(e) => ServerMessage::Error {
                    message: e.to_string(),
                },
            }
        }

        ClientMessage::CloseSession { session_id } => {
            // An UPDATE that matches 0 rows (unknown session) is a no-op,
            // not an error. Idempotent close is fine for retry safety.
            match state.audit.close_session(session_id, UnixMillis::now()) {
                Ok(()) => ServerMessage::SessionClosed,
                Err(e) => ServerMessage::Error {
                    message: e.to_string(),
                },
            }
        }

        ClientMessage::Request {
            session_id,
            capability,
        } => dispatch_capability(session_id, capability, state).await,
        ClientMessage::StartAgentVm {
            label,
            agent_kind,
            agent_model,
            workspace,
            guest_command,
        } => {
            if agent_kind.is_none() {
                return missing_agent_kind_for_registry_response();
            }
            match agent_vm {
                Some(agent_vm) => match agent_vm
                    .start_session(
                        Arc::clone(state),
                        label,
                        agent_kind,
                        agent_model,
                        workspace,
                        guest_command,
                    )
                    .await
                {
                    Ok(started) => ServerMessage::AgentVmStarted {
                        session_id: started.session_id(),
                        broker_url: started.broker_url().to_string(),
                    },
                    Err(err) => ServerMessage::Error {
                        message: err.to_string(),
                    },
                },
                None => ServerMessage::Error {
                    message: "agent VM runtime is not configured".into(),
                },
            }
        }
        ClientMessage::StartAgentRun {
            label,
            agent_kind,
            agent_model,
            workspace,
            prompt,
            correlation_id,
        } => match agent_vm {
            Some(agent_vm) => {
                debug_assert!(
                    prompt.byte_len()
                        <= u64::try_from(crate::agent_run::MAX_AGENT_PROMPT_BYTES)
                            .expect("agent prompt byte limit fits in u64"),
                    "AgentPrompt validates prompt size before dispatch"
                );
                match agent_vm
                    .start_agent_run_session(
                        Arc::clone(state),
                        label,
                        agent_kind,
                        agent_model,
                        workspace,
                        prompt,
                        correlation_id,
                    )
                    .await
                {
                    Ok(started) => ServerMessage::AgentRunStarted {
                        session_id: started.session_id(),
                        run_id: started.run_id(),
                        broker_url: started.broker_url().to_string(),
                    },
                    Err(err) => ServerMessage::Error {
                        message: err.to_string(),
                    },
                }
            }
            None => ServerMessage::Error {
                message: "agent VM runtime is not configured".into(),
            },
        },
        ClientMessage::StopAgentVm { session_id } => match agent_vm {
            Some(agent_vm) => match agent_vm.stop_session(state, session_id).await {
                Ok(()) => ServerMessage::AgentVmStopped,
                Err(err) => ServerMessage::Error {
                    message: err.to_string(),
                },
            },
            None => ServerMessage::Error {
                message: "agent VM runtime is not configured".into(),
            },
        },
        ClientMessage::ListAgentVms {} => match agent_vm {
            Some(agent_vm) => match agent_vm.list_sessions().await {
                Ok(sessions) => ServerMessage::AgentVmSessions { sessions },
                Err(err) => ServerMessage::Error {
                    message: err.to_string(),
                },
            },
            None => ServerMessage::Error {
                message: "agent VM runtime is not configured".into(),
            },
        },
        ClientMessage::ListStagedPushes { session_id } => {
            list_staged_pushes(state, session_id).await
        }
        ClientMessage::ShowStagedPush { request_id } => show_staged_push(state, request_id).await,
        ClientMessage::RejectStagedPush {
            request_id,
            operator,
            reason,
        } => reject_staged_push(state, request_id, operator, reason).await,
        ClientMessage::ApproveStagedPush {
            request_id,
            operator,
        } => approve_staged_push(state, request_id, operator).await,
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator,
            outcome,
        } => reconcile_staged_push(state, request_id, operator, outcome).await,
        ClientMessage::RunAgent {
            prompt,
            capabilities,
            purpose,
            output_ref,
            session_id,
            workspace,
            agent_kind,
            agent_model,
        } => {
            run_agent(
                state,
                prompt,
                capabilities,
                purpose,
                output_ref,
                session_id,
                workspace,
                agent_kind,
                agent_model,
                agent_vm,
            )
            .await
        }
    }
}

async fn list_staged_pushes<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    session_id: Option<SessionId>,
) -> ServerMessage {
    let Some(staging_store) = state.staging_store.clone() else {
        return staging_not_configured();
    };

    let receipts = match session_id {
        // No filter: scan the whole staging directory. Sync work hops
        // off the async runtime so a directory-walk on a slow
        // filesystem doesn't block other connections.
        None => match tokio::task::spawn_blocking(move || staging_store.list()).await {
            Ok(Ok(receipts)) => receipts,
            Ok(Err(err)) => {
                return ServerMessage::Error {
                    message: err.to_string(),
                };
            }
            Err(err) => {
                return ServerMessage::Error {
                    message: format!("staging list task failed: {err}"),
                };
            }
        },
        // Session filter: drive the lookup off the audit log, which is
        // the source of truth for which request ids belong to a given
        // session. Loading by id (rather than scanning every staging
        // dir and then filtering) keeps the filtered path's blast
        // radius scoped to the entries the audit log actually names:
        // an unrelated malformed sibling directory (e.g. left by
        // external tampering) won't surface as an error from a
        // session-filtered call it has nothing to do with.
        //
        // Audit rows whose staging directory is gone (the natural state
        // for a previously approved/rejected push) are silently skipped:
        // the request id is part of the session's history but the
        // staged entry is no longer waiting for review. A staging entry
        // that is *present but corrupt* for an audit-named id is still
        // a real broker invariant violation and surfaces as Error — the
        // audit log promised this entry; if it doesn't parse, the
        // operator should see that, not get an empty list.
        Some(session_id) => {
            let audit = Arc::clone(&state.audit);
            let request_ids: Vec<RequestId> = match tokio::task::spawn_blocking(move || {
                audit.list_git_pushes_for_session(session_id)
            })
            .await
            {
                Ok(Ok(rows)) => rows.into_iter().map(|row| row.push_request_id).collect(),
                Ok(Err(err)) => {
                    return ServerMessage::Error {
                        message: err.to_string(),
                    };
                }
                Err(err) => {
                    return ServerMessage::Error {
                        message: format!("audit list task failed: {err}"),
                    };
                }
            };

            // Per-id staging reads on one blocking task (rather than
            // spawn_blocking per id) keeps the task-spawn overhead
            // bounded on sessions with many pushes.
            let load = tokio::task::spawn_blocking(move || {
                let mut receipts = Vec::with_capacity(request_ids.len());
                for id in request_ids {
                    if let Some(receipt) = staging_store.try_load_receipt(id)? {
                        receipts.push(receipt);
                    }
                }
                Ok::<_, StagingError>(receipts)
            })
            .await;
            match load {
                Ok(Ok(receipts)) => receipts,
                Ok(Err(err)) => {
                    return ServerMessage::Error {
                        message: err.to_string(),
                    };
                }
                Err(err) => {
                    return ServerMessage::Error {
                        message: format!("staging load task failed: {err}"),
                    };
                }
            }
        }
    };

    let pushes = receipts
        .iter()
        .map(StagedPushSummary::from_receipt)
        .collect();
    ServerMessage::StagedPushes { pushes }
}

async fn show_staged_push<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
) -> ServerMessage {
    let Some(staging_store) = state.staging_store.clone() else {
        return staging_not_configured();
    };
    let entry: StagedEntry = match tokio::task::spawn_blocking({
        let staging_store = Arc::clone(&staging_store);
        move || staging_store.load(request_id)
    })
    .await
    {
        Ok(Ok(entry)) => entry,
        Ok(Err(StagingError::NotFound { request_id })) => {
            return ServerMessage::UnknownStagedPush { request_id };
        }
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: err.to_string(),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("staging load task failed: {err}"),
            };
        }
    };

    let audit_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.get_git_push(request_id)).await
    };
    let audit_entry = match audit_lookup {
        Ok(Ok(Some(entry))) => entry,
        Ok(Ok(None)) => {
            // Staged on disk but no audit row — broker invariant violation.
            // Surface explicitly rather than fabricating a `received_at`.
            return ServerMessage::Error {
                message: format!(
                    "staged push {request_id} has no audit record; \
                     promotion cannot proceed until the broker state is repaired",
                ),
            };
        }
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: err.to_string(),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("audit lookup task failed: {err}"),
            };
        }
    };

    let (receipt, bundle) = entry.into_parts();
    let bundle_bytes = bundle.len() as u64;
    let summary = StagedPushSummary::from_receipt(&receipt);
    let audit = StagedPushAuditView {
        session_id: audit_entry.session_id,
        received_at: audit_entry.received_at,
        result: audit_entry.result,
    };
    ServerMessage::StagedPush {
        push: StagedPushDetail {
            summary,
            bundle_bytes,
            audit,
        },
    }
}

/// Cap on the operator string the broker will accept. The audit row's
/// `operator` column is unbounded text, so the broker enforces a sane
/// upper bound at the wire boundary to keep a malformed CLI from
/// bloating the audit DB. The local socket is the trust boundary; the
/// operator field is informational only.
pub(crate) const MAX_OPERATOR_BYTES: usize = 256;

async fn reject_staged_push<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
    operator: String,
    reason: RejectionReason,
) -> ServerMessage {
    let Some(staging_store) = state.staging_store.clone() else {
        return staging_not_configured();
    };

    if operator.is_empty() {
        return ServerMessage::Error {
            message: "operator identity must not be empty".into(),
        };
    }
    if operator.len() > MAX_OPERATOR_BYTES {
        return ServerMessage::Error {
            message: format!(
                "operator identity is {} bytes, exceeding the {MAX_OPERATOR_BYTES}-byte limit",
                operator.len(),
            ),
        };
    }

    // Verify the staging directory exists before touching the audit
    // log. Matching `show_staged_push`'s ordering lets the two endpoints
    // agree on what "the staging is gone" means and gives the operator
    // a clean `UnknownStagedPush` instead of a trigger-violation error
    // when the dir was already deleted by a prior reject.
    let load_check = {
        let staging_store = Arc::clone(&staging_store);
        tokio::task::spawn_blocking(move || staging_store.load(request_id)).await
    };
    match load_check {
        Ok(Ok(_)) => {}
        Ok(Err(StagingError::NotFound { request_id })) => {
            return ServerMessage::UnknownStagedPush { request_id };
        }
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: err.to_string(),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("staging load task failed: {err}"),
            };
        }
    }

    // Consult the approve-attempt state machine before attempting the
    // INSERT. The `git_push_resolution_refuses_active_approve` trigger
    // is the load-bearing correctness piece (it refuses contradictory
    // commits at the SQL boundary), but its raw `RAISE(ABORT, ...)`
    // text is opaque to the operator. Calling `reject_blocker_for_push`
    // first lets the handler surface a typed diagnostic that names the
    // attempt and points at the operator action. The trigger-mapping
    // below covers the SELECT-vs-INSERT race where a fresh `Started`
    // row lands in the gap.
    match preflight_reject_blocker(state, request_id).await {
        Ok(None) => {}
        Ok(Some(blocker)) => {
            return reject_blocker_response(&staging_store, request_id, blocker).await;
        }
        Err(message) => return ServerMessage::Error { message },
    }

    let decided_at = UnixMillis::now();
    let reason_owned = reason.as_str().to_string();
    let operator_owned = operator.clone();
    let audit = Arc::clone(&state.audit);
    let resolution_result = tokio::task::spawn_blocking(move || {
        audit.record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id: request_id,
            decided_at,
            decision: GitPushResolution::Rejected,
            operator: &operator_owned,
            reason: &reason_owned,
        })
    })
    .await;
    match resolution_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            // The PK on `git_push_resolution.push_request_id` surfaces
            // as a SQLite "UNIQUE constraint" error when a previous
            // decision is already recorded. The trigger that requires a
            // `staged` outcome row surfaces with the literal message
            // pinned in the migration. Other SQL errors are broker
            // invariant violations.
            if is_unique_constraint_violation(&err) {
                // A prior `Rejected` decision means the staging dir
                // should already be gone. If we still saw it on disk
                // above, the previous reject's cleanup failed mid-way:
                // retry the delete here so the operator has a recovery
                // path instead of the dir staying stuck in
                // `promote list`. `Approved` is left alone because Stage
                // D's promotion flow owns that directory's lifecycle.
                retry_cleanup_for_rejected(state, &staging_store, request_id).await;
                return ServerMessage::StagedPushAlreadyResolved { request_id };
            }
            if is_active_approve_refusal(&err) {
                // The defence-in-depth path: an attempt row landed
                // between our preflight blocker check and this INSERT,
                // and the trigger refused the commit. Re-query so the
                // operator gets the same typed diagnostic the preflight
                // path would have produced.
                match preflight_reject_blocker(state, request_id).await {
                    Ok(Some(blocker)) => {
                        return reject_blocker_response(&staging_store, request_id, blocker).await;
                    }
                    // The blocker disappeared between the trigger
                    // firing and the re-query (e.g. the racing approve
                    // resolved to PrePatchFailure). This is a stale
                    // refusal — the row is now insertable. Rather than
                    // retry here and risk an infinite-loop interaction
                    // with whatever wrote the row, surface a concrete
                    // diagnostic so the operator retries explicitly.
                    Ok(None) => {
                        return ServerMessage::Error {
                            message: format!(
                                "staged push {request_id} reject was refused by an in-flight \
                                 approve attempt that has since resolved; retry the reject"
                            ),
                        };
                    }
                    Err(message) => return ServerMessage::Error { message },
                }
            }
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_resolution",
                request_id = %request_id,
                error = %err,
                "audit write failed: staged push reject not recorded",
            );
            return ServerMessage::Error {
                message: err.to_string(),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("audit write task failed: {err}"),
            };
        }
    }

    // Audit row committed. Delete the staging dir last so that if the
    // delete fails, the next call sees both the audit row and the dir
    // and returns `StagedPushAlreadyResolved` rather than silently
    // reporting success without removing the on-disk artifact.
    let delete_result = {
        let staging_store = Arc::clone(&staging_store);
        tokio::task::spawn_blocking(move || staging_store.delete(request_id)).await
    };
    match delete_result {
        Ok(Ok(())) => ServerMessage::StagedPushRejected { request_id },
        Ok(Err(err)) => ServerMessage::Error {
            message: format!(
                "staged push {request_id} was recorded as rejected but the staging \
                 directory could not be removed: {err}"
            ),
        },
        Err(err) => ServerMessage::Error {
            message: format!("staging delete task failed: {err}"),
        },
    }
}

/// TTL for the GitHub installation token minted by an approve decision.
///
/// GitHub returns ~1h installation tokens regardless of what we request
/// and the minter rejects responses where `expires_at` exceeds
/// `issued_at + ttl + TTL_SKEW_TOLERANCE_SECONDS`. Setting the ceiling
/// any lower than [`GITHUB_INSTALLATION_TOKEN_MAX_SECONDS`] makes every
/// real mint fail with `TtlExceeded`. The minter's TTL is an
/// *accept-back* bound on the GitHub-returned expiry, not a request the
/// server honours — pinning it at the GitHub-imposed maximum is the
/// only correct setting. The credential's actual lifetime is bounded by
/// the duration of this single `run_approve` invocation; the broker
/// drops the token (and the only reference to it) once the call
/// returns.
const APPROVE_MINT_TTL_SECONDS: i64 = GITHUB_INSTALLATION_TOKEN_MAX_SECONDS;

/// Handler for [`ClientMessage::ApproveStagedPush`].
///
/// Drives the approve-attempt state machine defined in
/// `docs/design/approve_state_machine.md`. Each invocation creates one
/// `git_push_approve_attempt` row; the row transitions
/// `Started → Uncertain → Resolved` (or `Started → Resolved` on a
/// pre-mint failure) with the schema's forward-only trigger enforcing
/// the order. The state machine — not a filesystem marker, not an
/// in-memory mutex — is the load-bearing piece that gates reject and
/// the only durable state approve mutates outside of GitHub.
///
/// Flow:
///
///   1. Validate `operator` (non-empty, bounded) before any IO so a
///      caller cannot probe broker state via a malformed identity field.
///   2. Check the three configured-state slots (`staging_store`,
///      `promote_runtime`, `signing_key`) so a not-configured broker
///      returns a precise diagnosis rather than dead-ending later.
///   3. Load the staging entry atomically (receipt + bundle bytes); a
///      missing entry surfaces as `UnknownStagedPush`.
///   4. Read the joined audit view via [`AuditLog::get_git_push`]:
///        * **Early short-circuit** on a prior resolution row — no
///          attempt is started and no credential is wasted.
///        * Refuse if no `Staged` outcome row exists (the staging dir
///          and the audit log have drifted apart — operator must
///          investigate).
///        * Refuse a branch-creation push (no `expected_remote_head`):
///          the walker needs a lease anchor a fresh branch does not
///          have. Documented gap; failing closed is the right shape.
///   5. Look up the originating session for `agent_kind`. The session
///      is by definition closed by now; `get_session` reads it just the
///      same.
///   6. `start_approve_attempt`: insert `Started` row. The DAO refuses
///      if any attempt is `Started`/`Uncertain` or
///      `Resolved(PostPatchFailure)` — those are the
///      reject-blocking states and would also block a fresh approve.
///   7. Mint a one-shot installation token. On failure: transition the
///      attempt to `Resolved(PrePatchFailure)` (no mint to capture).
///   8. `mark_attempt_uncertain`: capture the mint context inline on
///      the attempt row. **This is the TX that commits the broker to
///      "the PATCH may exist on GitHub"** — reject is refused from this
///      point until the attempt resolves.
///   9. Run [`run_approve`] against the staging entry. The current
///      slice writes `Uncertain` *before* `run_approve` rather than
///      between the walker and `update_ref`; the cost is that
///      `prepare`/`plan`/`walker` failures resolve from `Uncertain`
///      instead of `Started`, blocking reject during the brief window
///      they run. A follow-up slice can refactor `run_approve` to
///      expose a post-walker hook if the over-conservative window
///      proves costly. The schema's forward-only trigger admits
///      `Uncertain → Resolved(PrePatchFailure)` so the path is valid.
///  10. On success: `complete_attempt_succeeded` atomically transitions
///      the attempt to `Resolved(Succeeded)` *and* writes the
///      `git_push_resolution(decision='approved')` row in a single
///      SQLite transaction (the resolution-INSERT trigger sees the
///      attempt already at `succeeded` and lets the row through).
///  11. On `RunApproveError::Execute(ExecuteError::UpdateRef(_))`:
///      `update_ref` was issued and GitHub's state is uncertain →
///      `complete_attempt_post_patch_failure` (quarantines the push).
///  12. On any other `RunApproveError`: no PATCH was issued →
///      `complete_attempt_pre_patch_failure`. The mint context is
///      preserved on the row.
///  13. Staging-dir delete is best-effort after the joint TX; failures
///      are logged. A stale dir surfaces in `promote list` for manual
///      cleanup.
///
/// The token's `api_base` is plumbed straight through from
/// [`crate::github::MintedToken::into_promote_pieces`] — using a
/// different base would mint against one GitHub instance and call the
/// Git Data REST API against another, which the consume-and-pair shape
/// rules out at compile time.
async fn approve_staged_push<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
    operator: String,
) -> ServerMessage {
    if operator.is_empty() {
        return ServerMessage::Error {
            message: "operator identity must not be empty".into(),
        };
    }
    if operator.len() > MAX_OPERATOR_BYTES {
        return ServerMessage::Error {
            message: format!(
                "operator identity is {} bytes, exceeding the {MAX_OPERATOR_BYTES}-byte limit",
                operator.len(),
            ),
        };
    }

    let Some(staging_store) = state.staging_store.clone() else {
        return staging_not_configured();
    };
    let Some(promote_runtime) = state.promote_runtime.clone() else {
        return approve_staged_push_not_configured("promote_runtime");
    };
    let Some(signing_key) = state.signing_key.clone() else {
        return approve_staged_push_not_configured("signing_key");
    };

    let load_result = {
        let staging_store = Arc::clone(&staging_store);
        tokio::task::spawn_blocking(move || staging_store.load(request_id)).await
    };
    let entry = match load_result {
        Ok(Ok(entry)) => entry,
        Ok(Err(StagingError::NotFound { request_id })) => {
            return ServerMessage::UnknownStagedPush { request_id };
        }
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: err.to_string(),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("staging load task failed: {err}"),
            };
        }
    };

    // Joined audit view: the source of truth for the prior-resolution
    // short-circuit (so a duplicate approve never starts an attempt or
    // wastes a mint), the outcome-row precondition, and the session-id
    // we need to select the GitHub App.
    let audit_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.get_git_push(request_id)).await
    };
    let audit_entry = match audit_lookup {
        Ok(Ok(Some(entry))) => entry,
        Ok(Ok(None)) => {
            return ServerMessage::Error {
                message: format!(
                    "staged push {request_id} has a staging directory but no audit row; \
                     broker audit log and staging store have drifted apart"
                ),
            };
        }
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: format!("audit lookup failed: {err}"),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("audit lookup task failed: {err}"),
            };
        }
    };

    if audit_entry.resolution.is_some() {
        return ServerMessage::StagedPushAlreadyResolved { request_id };
    }

    if audit_entry.result != Some(GitPushOutcomeResult::Staged) {
        return ServerMessage::Error {
            message: format!(
                "staged push {request_id} has no `staged` outcome row \
                 (audit result: {:?}); refusing to approve a push that is not staged",
                audit_entry.result,
            ),
        };
    }

    if audit_entry.expected_remote_head.is_none() {
        return ServerMessage::Error {
            message: format!(
                "staged push {request_id} is a branch-creation push \
                 (no expected_remote_head); approve does not yet support branch creation"
            ),
        };
    }

    let session_id = audit_entry.session_id;
    let session_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.get_session(session_id)).await
    };
    let session = match session_lookup {
        Ok(Ok(Some(s))) => s,
        Ok(Ok(None)) => {
            return ServerMessage::Error {
                message: format!(
                    "staged push {request_id} references session {session_id} \
                     but that session is not in the audit log"
                ),
            };
        }
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: format!("session lookup failed: {err}"),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("session lookup task failed: {err}"),
            };
        }
    };

    // A `Started` row written here is durable. If writd crashes
    // between this INSERT and the next `complete_attempt_*` call, the
    // attempt row stays `Started` and blocks both a follow-up approve
    // (the DAO refuses to start a second non-`pre_patch_failure`
    // attempt) and a follow-up reject (the
    // `git_push_resolution_refuses_active_approve` trigger treats
    // `started` as in-flight). Boot reconcile is the load-bearing
    // recovery story for that window — slice B1e.3d adds the daemon
    // startup pass that drives every stale `Started` attempt (and the
    // `Uncertain` ones whose mint is past `expires_at`) to
    // `Resolved(PrePatchFailure)` so the staged push becomes
    // reject-eligible again without manual DB repair.
    let attempt_id = ApproveAttemptId::new();
    let started_at = UnixMillis::now();
    let start_result = {
        let audit = Arc::clone(&state.audit);
        let operator = operator.clone();
        tokio::task::spawn_blocking(move || {
            audit.start_approve_attempt(attempt_id, request_id, &operator, started_at)
        })
        .await
    };
    match start_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            // `start_approve_attempt` refuses in three shapes: a prior
            // resolution row exists (the early short-circuit above
            // would normally catch this, but a race between two
            // concurrent approves can land both past the
            // `audit_entry.resolution.is_some()` check before either
            // has inserted), a non-`pre_patch_failure` attempt is
            // active for the same push, or the staged-outcome
            // precondition has gone away under us. All are surfaced as
            // a generic error: the operator (or a future reviewer)
            // reads the audit row to disambiguate.
            return ServerMessage::Error {
                message: format!("approve attempt could not be started: {err}"),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("approve attempt start task failed: {err}"),
            };
        }
    }

    // Static promote scope: `contents:write` is what the Git Data REST
    // API needs to upload blobs/trees/commits and update the branch
    // ref; `metadata:read` is implicit but listed explicitly because
    // the minter's permissions-echo check refuses any drift between
    // what we asked for and what GitHub returned. The single repo on
    // the scope is the one the staged push targets.
    let github_scope = GitHubGrantedScope {
        repository: entry.receipt().repo().as_repo_ref().clone(),
        permissions: GitHubPermissions {
            contents: Some(GitHubAccess::Write),
            metadata: Some(MetadataAccess::Read),
            ..Default::default()
        },
    };
    let ttl = TtlSeconds::new(APPROVE_MINT_TTL_SECONDS)
        .expect("APPROVE_MINT_TTL_SECONDS is in TtlSeconds range");

    let mint_result = state
        .minter
        .mint_for_agent(&state.secrets, session.agent_kind, github_scope, ttl)
        .await;
    let minted = match mint_result {
        Ok(m) => m,
        Err(err) => {
            let detail = format!("mint failed: {}", err.agent_message());
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, None).await;
            return ServerMessage::Error {
                message: format!("approve-time mint failed: {}", err.agent_message()),
            };
        }
    };

    let (api_base, raw_token, mint_audit) = minted.into_promote_pieces();
    let token = match GitSecretValue::new(raw_token) {
        Ok(t) => t,
        Err(err) => {
            let detail = format!("mint produced unusable token: {err}");
            // Mint succeeded by the time we have a `MintedToken`, so
            // capture the mint context on the attempt row even though
            // the token cannot be used. The audit log can still answer
            // "what mint was issued for this attempt."
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, Some(mint_audit))
                .await;
            return ServerMessage::Error {
                message: format!("approve-time mint produced an unusable token: {err}"),
            };
        }
    };

    // Commit to "the PATCH may exist on GitHub": from here until
    // `Resolved` lands the attempt is `Uncertain` and the new
    // `git_push_resolution_refuses_active_approve` trigger blocks any
    // concurrent reject. Failures from `run_approve` after this point
    // resolve through the `complete_attempt_*` DAO methods, never via
    // a direct `record_git_push_resolution` call.
    let uncertain_result = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.mark_attempt_uncertain(attempt_id, mint_audit))
            .await
    };
    match uncertain_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            // The attempt row is still `Started` (the UPDATE was
            // refused) so a `pre_patch_failure` capturing the mint is
            // the correct shape: no PATCH was issued, but the mint was.
            let detail = format!("mark_attempt_uncertain failed: {err}");
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, Some(mint_audit))
                .await;
            return ServerMessage::Error {
                message: format!("approve attempt could not enter Uncertain: {err}"),
            };
        }
        Err(err) => {
            let detail = format!("mark_attempt_uncertain task failed: {err}");
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, Some(mint_audit))
                .await;
            return ServerMessage::Error {
                message: format!("approve attempt Uncertain task failed: {err}"),
            };
        }
    }

    let receipt = entry.receipt();
    let repo = receipt.repo().clone();
    let branch = receipt.branch().clone();
    let expected_remote_head = receipt
        .expected_remote_head()
        .cloned()
        .expect("expected_remote_head presence was checked above");
    let bundle_tip = receipt.new_head().clone();
    let (_, bundle_bytes) = entry.into_parts();

    let run_result = run_approve(
        &promote_runtime,
        &api_base,
        &token,
        &repo,
        &branch,
        &expected_remote_head,
        &bundle_tip,
        &bundle_bytes,
        &signing_key,
        // Trailers are an open follow-up: the design pins a per-approve
        // trailer set (operator id, original commit sha) but the policy
        // hasn't been ratified yet, so the slice ships with no trailers
        // and the bundle's commits are replayed verbatim. The empty
        // slice is identical in shape to what the run_approve unit
        // tests pass.
        &[],
        request_id,
    )
    .await;

    let outcome = match run_result {
        Ok(outcome) => outcome,
        Err(err) => {
            // `Execute(UpdateRef(_))` is the only variant that proves a
            // PATCH was sent to GitHub; every other variant fires
            // before `execute_fast_forward_plan` issues
            // `PATCH /git/refs/...`. Map the variant onto the
            // attempt's terminal state accordingly.
            //
            // `err` can wrap `GitDataError::ApiError { body, .. }`
            // whose `body` is unbounded GitHub/GHES bytes; cap both
            // the audit `detail` and the wire `message` at
            // `MAX_WIRE_ERROR_BYTES` so a hostile or misbehaving
            // server can't bloat the audit DB column or blow up the
            // `ServerMessage::Error` envelope.
            let detail =
                truncate_for_wire(format!("run_approve failed: {err}"), MAX_WIRE_ERROR_BYTES);
            match &err {
                RunApproveError::Execute(ExecuteError::UpdateRef(_)) => {
                    resolve_post_patch_failure(state, attempt_id, request_id, &detail).await;
                    return ServerMessage::Error {
                        message: truncate_for_wire(
                            format!(
                                "approve pipeline issued update_ref against GitHub but the \
                                 response could not be confirmed; staged push {request_id} is \
                                 quarantined and must be reconciled manually: {err}"
                            ),
                            MAX_WIRE_ERROR_BYTES,
                        ),
                    };
                }
                _ => {
                    resolve_pre_patch_failure(state, attempt_id, request_id, &detail, None).await;
                    let message = match &err {
                        RunApproveError::Prepare(_) => format!("staging preparation failed: {err}"),
                        _ => format!("approve pipeline failed: {err}"),
                    };
                    return ServerMessage::Error {
                        message: truncate_for_wire(message, MAX_WIRE_ERROR_BYTES),
                    };
                }
            }
        }
    };

    // Joint TX: attempt → Resolved(Succeeded) *and* the
    // `git_push_resolution(decision='approved')` row land in one
    // SQLite transaction. The resolution-INSERT trigger sees the
    // attempt at `succeeded` (the UPDATE runs first) and admits the
    // row; an in-flight reject would have been refused at its own
    // INSERT by the same trigger.
    let new_app_tip = outcome.new_app_tip().clone();
    let completed_at = UnixMillis::now();
    let reason = format!("approved by {operator}");
    let success_result = {
        let audit = Arc::clone(&state.audit);
        let new_app_tip = new_app_tip.clone();
        let operator = operator.clone();
        let reason = reason.clone();
        tokio::task::spawn_blocking(move || {
            audit.complete_attempt_succeeded(
                attempt_id,
                &new_app_tip,
                &operator,
                &reason,
                completed_at,
            )
        })
        .await
    };
    match success_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            // The branch on GitHub now points at `new_app_tip` but the
            // audit log could not commit the joint TX. The attempt is
            // still `Uncertain`. Try to record `PostPatchFailure` so
            // reject is refused going forward; if that also fails the
            // attempt stays `Uncertain` and boot reconcile surfaces it.
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_succeeded",
                request_id = %request_id,
                attempt_id = %attempt_id,
                jti = %mint_audit.jti,
                error = %err,
                "audit write failed: approve succeeded on GitHub but joint TX did not commit; \
                 falling back to PostPatchFailure",
            );
            let detail = format!("complete_attempt_succeeded failed: {err}");
            resolve_post_patch_failure(state, attempt_id, request_id, &detail).await;
            return ServerMessage::Error {
                message: format!(
                    "branch was advanced on GitHub (new_app_tip = {new_app_tip}) but the audit \
                     resolution row could not be committed: {err}"
                ),
            };
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_succeeded",
                request_id = %request_id,
                attempt_id = %attempt_id,
                jti = %mint_audit.jti,
                error = %err,
                "audit write task failed: approve succeeded on GitHub but joint TX did not commit; \
                 falling back to PostPatchFailure",
            );
            let detail = format!("complete_attempt_succeeded task failed: {err}");
            resolve_post_patch_failure(state, attempt_id, request_id, &detail).await;
            return ServerMessage::Error {
                message: format!("approve resolution task failed: {err}"),
            };
        }
    }

    // Best-effort staging-dir delete after the joint TX. A stale dir
    // surfaces in `promote list` and cannot cause a contradictory
    // reject because the resolution row is already in place.
    let delete_result = {
        let staging_store = Arc::clone(&staging_store);
        tokio::task::spawn_blocking(move || staging_store.delete(request_id)).await
    };
    match delete_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(
                request_id = %request_id,
                error = %err,
                "approved staged push: staging dir delete failed; \
                 audit row is committed, dir will appear in `promote list`",
            );
        }
        Err(err) => {
            tracing::warn!(
                request_id = %request_id,
                error = %err,
                "approved staged push: staging dir delete task failed; \
                 leaving for boot-time reconciliation",
            );
        }
    }

    ServerMessage::StagedPushApproved {
        request_id,
        new_app_tip,
    }
}

/// Drive an attempt to `Resolved(PrePatchFailure)`. Chooses between the
/// mint-capturing and non-capturing DAO variants based on whether the
/// caller has a mint to record: the column-immutability trigger refuses
/// to write a mint different from one that's already there, so we must
/// not pass `Some(mint)` to the capturing variant when the attempt is
/// already `Uncertain` (it carries the mint inline already).
async fn resolve_pre_patch_failure<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    attempt_id: ApproveAttemptId,
    request_id: RequestId,
    detail: &str,
    mint_to_capture: Option<PromoteMintAudit>,
) {
    let completed_at = UnixMillis::now();
    let audit = Arc::clone(&state.audit);
    let detail_owned = detail.to_string();
    let result = tokio::task::spawn_blocking(move || match mint_to_capture {
        Some(mint) => audit.complete_attempt_pre_patch_failure_capturing_mint(
            attempt_id,
            mint,
            &detail_owned,
            completed_at,
        ),
        None => audit.complete_attempt_pre_patch_failure(attempt_id, &detail_owned, completed_at),
    })
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_pre_patch_failure",
                request_id = %request_id,
                attempt_id = %attempt_id,
                error = %err,
                "audit write failed: approve attempt could not be resolved as PrePatchFailure; \
                 attempt remains Started/Uncertain — boot reconcile will surface it",
            );
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_pre_patch_failure",
                request_id = %request_id,
                attempt_id = %attempt_id,
                error = %err,
                "audit write task failed: approve attempt could not be resolved as PrePatchFailure; \
                 attempt remains Started/Uncertain — boot reconcile will surface it",
            );
        }
    }
}

/// Drive an `Uncertain` attempt to `Resolved(PostPatchFailure)`. Used
/// by the two paths that prove the PATCH was sent: a direct
/// `Execute(UpdateRef(_))` error from `run_approve` (non-2xx /
/// transport drop on the PATCH itself) and the post-success
/// joint-TX-failed path (the PATCH succeeded but the audit log could
/// not commit it).
async fn resolve_post_patch_failure<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    attempt_id: ApproveAttemptId,
    request_id: RequestId,
    detail: &str,
) {
    let completed_at = UnixMillis::now();
    let audit = Arc::clone(&state.audit);
    let detail_owned = detail.to_string();
    let result = tokio::task::spawn_blocking(move || {
        audit.complete_attempt_post_patch_failure(attempt_id, &detail_owned, completed_at)
    })
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_post_patch_failure",
                request_id = %request_id,
                attempt_id = %attempt_id,
                error = %err,
                "audit write failed: approve attempt could not be resolved as PostPatchFailure; \
                 attempt remains Uncertain — boot reconcile will surface it",
            );
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_post_patch_failure",
                request_id = %request_id,
                attempt_id = %attempt_id,
                error = %err,
                "audit write task failed: approve attempt could not be resolved as PostPatchFailure; \
                 attempt remains Uncertain — boot reconcile will surface it",
            );
        }
    }
}

fn approve_staged_push_not_configured(component: &str) -> ServerMessage {
    ServerMessage::Error {
        message: format!(
            "ApproveStagedPush dispatch is not configured: {component} is unset; \
             writd needs staging_store + promote_runtime + signing_key to serve ApproveStagedPush"
        ),
    }
}

/// Handler for [`ClientMessage::ReconcileStagedPush`].
///
/// Drives a manual reconciliation of a quarantined approve attempt by
/// inserting a born-terminal `git_push_approve_attempt` row whose
/// `supersedes_attempt_id` points back at the predecessor. The
/// predecessor is the oldest non-superseded attempt in either
/// `Uncertain` (boot-observed only) or `Resolved(PostPatchFailure)` —
/// the two states that wedge a staged push between reject and approve
/// after the broker observes (or may have observed) the PATCH go out.
///
/// Flow:
///   1. Wire-side validation of `operator` and the outcome's free-form
///      text (`reason` on `Applied`, `detail` on `NotApplied`): non-empty
///      and bounded so a malformed CLI cannot bloat the audit DB. The
///      DAO repeats the non-empty check as defence-in-depth; the upper
///      bound is enforced at the wire only.
///   2. Require `staging_store` configured. Reconciliation requires a
///      staging dir to act against (operators inspect it to decide
///      Applied vs NotApplied); a daemon without staging cannot honour
///      the request.
///   3. Load the staging entry. Missing dir surfaces as
///      `UnknownStagedPush` — symmetrical with reject/approve.
///   4. Joined audit view: a prior resolution row short-circuits to
///      `StagedPushAlreadyResolved`. This guards against the operator
///      racing themselves (e.g. running `promote reconcile` against a
///      push that just landed a duplicate approve).
///   5. Classify the push via [`AuditLog::classify_reconciliation_target`]:
///        * `Eligible { attempt_id }` → fall through to the DAO write.
///        * Anything else → `StagedPushNotReconcilable` with a typed
///          reason naming the classification.
///   6. Mint a fresh `ApproveAttemptId` for the reconciliation row and
///      branch on `outcome`:
///        * `Applied` → joint TX writes the reconciliation attempt row
///          *and* the `git_push_resolution(decision='approved')` row,
///          carrying the predecessor's captured mint context verbatim.
///        * `NotApplied` → born-terminal `Resolved(PrePatchFailure)`
///          reconciliation row. No resolution row is written; the push
///          is once again rejectable.
///   7. On `Applied` success: best-effort `staging_store.delete`. On
///      `NotApplied`: leave the staging dir on disk so the operator can
///      drive a follow-up reject/retry.
///   8. Map any `AuditError::Invariant` returned by the DAO into
///      `StagedPushNotReconcilable` — the predecessor's eligibility
///      slipped between classify and the write (concurrent
///      reconciliation, race with a state change). Other errors land
///      as `ServerMessage::Error` and are logged at
///      [`AUDIT_WRITE_FAILURE_TARGET`].
async fn reconcile_staged_push<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
    operator: String,
    outcome: ReconcileOutcome,
) -> ServerMessage {
    if operator.is_empty() {
        return ServerMessage::Error {
            message: "operator identity must not be empty".into(),
        };
    }
    if operator.len() > MAX_OPERATOR_BYTES {
        return ServerMessage::Error {
            message: format!(
                "operator identity is {} bytes, exceeding the {MAX_OPERATOR_BYTES}-byte limit",
                operator.len(),
            ),
        };
    }

    // The free-form outcome text gets recorded verbatim on the audit
    // row (`reason` on the resolution row for Applied, `failure_detail`
    // on the reconciliation attempt for NotApplied). Cap at the same
    // 4 KiB upper bound the `RejectionReason` parser enforces so the
    // audit DB cannot be bloated by a malformed CLI.
    let outcome_text = match &outcome {
        ReconcileOutcome::Applied { reason, .. } => ("reason", reason.as_str()),
        ReconcileOutcome::NotApplied { detail } => ("detail", detail.as_str()),
    };
    if outcome_text.1.is_empty() {
        return ServerMessage::Error {
            message: format!(
                "reconciliation {label} must not be empty",
                label = outcome_text.0,
            ),
        };
    }
    if outcome_text.1.len() > crate::protocol::MAX_REJECTION_REASON_BYTES {
        return ServerMessage::Error {
            message: format!(
                "reconciliation {label} is {len} bytes, exceeding the {cap}-byte limit",
                label = outcome_text.0,
                len = outcome_text.1.len(),
                cap = crate::protocol::MAX_REJECTION_REASON_BYTES,
            ),
        };
    }

    let Some(staging_store) = state.staging_store.clone() else {
        return staging_not_configured();
    };

    // Probe staging before any audit work. Missing-dir is the same
    // surface as reject/approve; if the operator passes a stale request
    // id we want to say so explicitly rather than write an audit row
    // referencing a push the broker can no longer see.
    let load_check = {
        let staging_store = Arc::clone(&staging_store);
        tokio::task::spawn_blocking(move || staging_store.load(request_id)).await
    };
    match load_check {
        Ok(Ok(_)) => {}
        Ok(Err(StagingError::NotFound { request_id })) => {
            return ServerMessage::UnknownStagedPush { request_id };
        }
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: err.to_string(),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("staging load task failed: {err}"),
            };
        }
    }

    // Short-circuit on a prior resolution row before classifying. A
    // resolved push has nothing to reconcile (the operator decision
    // is already in place), and saying so explicitly avoids spending
    // a classify SELECT on a no-op.
    let audit_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.get_git_push(request_id)).await
    };
    match audit_lookup {
        Ok(Ok(Some(entry))) => {
            if entry.resolution.is_some() {
                return ServerMessage::StagedPushAlreadyResolved { request_id };
            }
        }
        Ok(Ok(None)) => {
            return ServerMessage::Error {
                message: format!(
                    "staged push {request_id} has a staging directory but no audit row; \
                     broker audit log and staging store have drifted apart"
                ),
            };
        }
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: format!("audit lookup failed: {err}"),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("audit lookup task failed: {err}"),
            };
        }
    }

    // Classify the push. The variants surface to the operator as four
    // distinct "nothing to reconcile" reasons so the CLI can guide the
    // next action (wait for boot reconcile vs. there was never an
    // attempt vs. every blocker is already cleared).
    let target_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.classify_reconciliation_target(request_id)).await
    };
    let predecessor = match target_lookup {
        Ok(Ok(ReconciliationTarget::Eligible { attempt_id })) => attempt_id,
        Ok(Ok(ReconciliationTarget::NoAttempts)) => {
            return ServerMessage::StagedPushNotReconcilable {
                request_id,
                reason: format!(
                    "no approve attempt has been recorded against staged push {request_id}; \
                     nothing to reconcile"
                ),
            };
        }
        Ok(Ok(ReconciliationTarget::AttemptInFlight)) => {
            return ServerMessage::StagedPushNotReconcilable {
                request_id,
                reason: format!(
                    "staged push {request_id} has an in-flight approve attempt; \
                     reconciliation must wait for the live attempt to resolve \
                     (or for boot reconcile to drive a daemon-survivor row)"
                ),
            };
        }
        Ok(Ok(ReconciliationTarget::NothingToReconcile)) => {
            return ServerMessage::StagedPushNotReconcilable {
                request_id,
                reason: format!(
                    "staged push {request_id} has no quarantined approve attempt to clear; \
                     every attempt is already cleanly terminated"
                ),
            };
        }
        Ok(Err(err)) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "classify_reconciliation_target",
                request_id = %request_id,
                error = %err,
                "audit read failed: reconciliation classification errored",
            );
            return ServerMessage::Error {
                message: format!("reconciliation classification failed: {err}"),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("reconciliation classification task failed: {err}"),
            };
        }
    };

    let attempt_id = ApproveAttemptId::new();
    let completed_at = UnixMillis::now();
    let is_applied = matches!(outcome, ReconcileOutcome::Applied { .. });
    let write_result = match outcome {
        ReconcileOutcome::Applied {
            new_app_tip,
            reason,
        } => {
            let audit = Arc::clone(&state.audit);
            let operator = operator.clone();
            tokio::task::spawn_blocking(move || {
                audit.record_reconciliation_attempt_applied(
                    attempt_id,
                    predecessor,
                    &new_app_tip,
                    &operator,
                    &reason,
                    completed_at,
                )
            })
            .await
        }
        ReconcileOutcome::NotApplied { detail } => {
            let audit = Arc::clone(&state.audit);
            let operator = operator.clone();
            tokio::task::spawn_blocking(move || {
                audit.record_reconciliation_attempt_not_applied(
                    attempt_id,
                    predecessor,
                    &operator,
                    &detail,
                    completed_at,
                )
            })
            .await
        }
    };

    // The DAO refuses on Invariant shapes that all reduce to "the
    // predecessor isn't actually clearable any more" — most likely a
    // concurrent reconciliation landed first. Surface the typed
    // `NotReconcilable` so the operator re-runs `promote list` and
    // picks the next blocker.
    match write_result {
        Ok(Ok(())) => {}
        Ok(Err(AuditError::Invariant(detail))) => {
            return ServerMessage::StagedPushNotReconcilable {
                request_id,
                reason: format!(
                    "staged push {request_id} reconciliation refused by audit invariant: \
                     {detail}; re-run promote list and retry"
                ),
            };
        }
        Ok(Err(AuditError::LabeledInvariant { label, message })) => {
            return ServerMessage::StagedPushNotReconcilable {
                request_id,
                reason: format!(
                    "staged push {request_id} reconciliation refused by audit invariant \
                     ({label}): {message}; re-run promote list and retry"
                ),
            };
        }
        Ok(Err(err)) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_reconciliation",
                request_id = %request_id,
                attempt_id = %attempt_id,
                predecessor = %predecessor,
                error = %err,
                "audit write failed: reconciliation attempt not recorded",
            );
            return ServerMessage::Error {
                message: err.to_string(),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("reconciliation audit write task failed: {err}"),
            };
        }
    }

    // Applied: the joint TX committed the resolution row. The push is
    // now terminally approved, so the staging dir is finished — try to
    // delete it the same way `approve_staged_push` does. NotApplied
    // leaves the staging dir alone so a follow-up reject sees it on
    // disk.
    if is_applied {
        let delete_result = {
            let staging_store = Arc::clone(&staging_store);
            tokio::task::spawn_blocking(move || staging_store.delete(request_id)).await
        };
        match delete_result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %err,
                    "reconciled (applied) staged push: staging dir delete failed; \
                     audit row is committed, dir will appear in `promote list`",
                );
            }
            Err(err) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %err,
                    "reconciled (applied) staged push: staging dir delete task failed; \
                     leaving for boot-time reconciliation",
                );
            }
        }
    }

    ServerMessage::StagedPushReconciled { request_id }
}

/// Maximum byte length of an error string echoed back on the wire in a
/// [`ServerMessage::Error`] or written into the
/// `git_push_approve_attempt.failure_detail` audit column. The approve
/// pipeline can wrap a [`crate::github_git_db::GitDataError::ApiError`]
/// whose `body` is the raw bytes a GitHub Enterprise instance (or a
/// proxy in front of it) returns; that body is otherwise unbounded and
/// would expand both the broker's per-error wire footprint *and* the
/// audit DB without limit. 4 KiB is large enough to preserve the
/// diagnostic shape (status line, JSON error object, the first few
/// stack-trace-ish lines) while keeping a worst-case error envelope
/// comfortably under the broker's per-message processing budget.
const MAX_WIRE_ERROR_BYTES: usize = 4 * 1024;

/// Truncate `s` to at most `cap` bytes, with a sentinel marker so the
/// reader can tell the message is a prefix. The marker is appended
/// after the cap (the returned string is `cap + marker.len()` bytes
/// long when truncation happens), because the goal is to bound the
/// *body* the broker reflects from GitHub, not to bound the total
/// envelope to the byte. Splits on a `char` boundary so the result is
/// valid UTF-8 even when the cap lands inside a multi-byte sequence.
fn truncate_for_wire(s: String, cap: usize) -> String {
    if s.len() <= cap {
        return s;
    }
    let mut boundary = cap;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let mut out = s;
    out.truncate(boundary);
    out.push_str("... [truncated]");
    out
}

/// Best-effort retry of the staging-dir delete on a duplicate-resolution
/// path: a prior `Rejected` row commits the decision, but if its
/// follow-up `delete` failed (transient filesystem error, perm flip,
/// crash) the dir lingers and the operator has no way to clear it.
/// Try again here and swallow any error — the caller still returns
/// `StagedPushAlreadyResolved`, and if the dir remains it will surface
/// in the next `promote list` for the operator to act on.
async fn retry_cleanup_for_rejected<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    staging_store: &Arc<GitPushStagingStore>,
    request_id: RequestId,
) {
    let audit = Arc::clone(&state.audit);
    let lookup = tokio::task::spawn_blocking(move || audit.get_git_push(request_id)).await;
    let prior_decision = match lookup {
        Ok(Ok(Some(entry))) => entry.resolution.map(|r| r.decision),
        _ => None,
    };
    if !matches!(prior_decision, Some(GitPushResolution::Rejected)) {
        return;
    }
    retry_staging_delete(staging_store, request_id, "duplicate-reject").await;
}

/// Best-effort staging-dir delete used by the duplicate-resolution
/// recovery paths. Logs a `warn` if the delete itself errors;
/// task-join failures are surfaced the same way. Centralised here so
/// the duplicate-reject and the
/// `RejectBlocker::AlreadyApproved` branches share the same
/// observable behaviour — both are "a prior resolution committed, the
/// staging dir may have leaked, retry the cleanup."
async fn retry_staging_delete(
    staging_store: &Arc<GitPushStagingStore>,
    request_id: RequestId,
    context: &'static str,
) {
    let staging_store = Arc::clone(staging_store);
    let delete_outcome =
        tokio::task::spawn_blocking(move || staging_store.delete(request_id)).await;
    match delete_outcome {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(
                request_id = %request_id,
                context,
                error = %err,
                "staging cleanup retry failed; staging dir may still be present",
            );
        }
        Err(err) => {
            tracing::warn!(
                request_id = %request_id,
                context,
                error = %err,
                "staging cleanup retry task failed; staging dir may still be present",
            );
        }
    }
}

/// Recognise the "row already exists" failure shape for the
/// `git_push_resolution` PK insert. Rusqlite surfaces both
/// `SQLITE_CONSTRAINT_PRIMARYKEY` (1555) and `SQLITE_CONSTRAINT_UNIQUE`
/// (2067) via `ConstraintViolation`; the message text disambiguates.
fn is_unique_constraint_violation(err: &crate::audit::AuditError) -> bool {
    let crate::audit::AuditError::Sqlite(sql_err) = err else {
        return false;
    };
    let rusqlite::Error::SqliteFailure(code, _) = sql_err else {
        return false;
    };
    if !matches!(code.code, rusqlite::ErrorCode::ConstraintViolation) {
        return false;
    }
    let message = sql_err.to_string().to_lowercase();
    message.contains("unique") || message.contains("primary key")
}

/// Detect the `git_push_resolution_refuses_active_approve` trigger
/// firing. The trigger is the schema-level defence-in-depth for the
/// approve-attempt state machine: any attempted `INSERT` into
/// `git_push_resolution` while a same-push attempt is `Started`,
/// `Uncertain`, or `Resolved(PostPatchFailure)` is refused with the
/// literal message below. The reject handler calls
/// [`AuditLog::reject_blocker_for_push`] *first* to give the operator a
/// typed diagnostic, but the SELECT-vs-INSERT window admits a racing
/// approve that lands a fresh `Started` row in between; matching the
/// trigger's text lets the handler translate that race back into the
/// same typed surface instead of leaking the raw SQL refusal.
///
/// The matched literal is mirrored from
/// `src/audit/migrations/0005_approve_attempt_state_machine.sql`.
fn is_active_approve_refusal(err: &crate::audit::AuditError) -> bool {
    const TRIGGER_MESSAGE: &str =
        "git push resolution refused: approve attempt is in-flight or quarantined";
    let crate::audit::AuditError::Sqlite(sql_err) = err else {
        return false;
    };
    let rusqlite::Error::SqliteFailure(code, _) = sql_err else {
        return false;
    };
    if !matches!(code.code, rusqlite::ErrorCode::ConstraintViolation) {
        return false;
    }
    sql_err.to_string().contains(TRIGGER_MESSAGE)
}

/// Query [`AuditLog::reject_blocker_for_push`] from the broker's tokio
/// runtime, returning the typed `Option<RejectBlocker>` plus a wire
/// error message if the spawn-blocking call itself fails. Centralising
/// this lets the handler call the same machinery twice (preflight and
/// the trigger-race recovery path) without duplicating the join /
/// error-mapping boilerplate.
async fn preflight_reject_blocker<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
) -> Result<Option<RejectBlocker>, String> {
    let audit = Arc::clone(&state.audit);
    match tokio::task::spawn_blocking(move || audit.reject_blocker_for_push(request_id)).await {
        Ok(Ok(blocker)) => Ok(blocker),
        Ok(Err(err)) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "reject_blocker_for_push",
                request_id = %request_id,
                error = %err,
                "audit read failed: reject blocker query errored",
            );
            Err(err.to_string())
        }
        Err(err) => Err(format!("audit read task failed: {err}")),
    }
}

/// Map a non-`None` [`RejectBlocker`] into the reject handler's
/// response. `AlreadyApproved` reuses the existing
/// `StagedPushAlreadyResolved` surface — when the joint TX in
/// `complete_attempt_succeeded` commits, the resolution row is present
/// alongside the attempt row, so the operator-facing behaviour matches
/// a duplicate-reject hit. The other variants surface as `Error` with
/// a diagnostic that names the attempt and points the operator at the
/// next action.
async fn reject_blocker_response(
    staging_store: &Arc<GitPushStagingStore>,
    request_id: RequestId,
    blocker: RejectBlocker,
) -> ServerMessage {
    match blocker {
        RejectBlocker::AttemptInFlight { attempt_id } => ServerMessage::Error {
            message: format!(
                "staged push {request_id} cannot be rejected: approve attempt {attempt_id} \
                 is in flight; retry once it resolves or wait for boot reconcile to drive \
                 the attempt to a terminal state"
            ),
        },
        RejectBlocker::AlreadyApproved { .. } => {
            // The approve handler best-effort deletes the staging dir
            // post-joint-TX (`approve_staged_push` line ~1449); if that
            // delete failed the dir is still on disk and the operator's
            // late reject is the second chance to remove it. The
            // existing `retry_cleanup_for_rejected` path only fires for
            // a prior `Rejected` decision, so the shared
            // `retry_staging_delete` helper covers the
            // duplicate-approve branch with the same observable
            // behaviour.
            retry_staging_delete(staging_store, request_id, "duplicate-approve").await;
            ServerMessage::StagedPushAlreadyResolved { request_id }
        }
        RejectBlocker::PostPatchUncertain { attempt_id } => ServerMessage::Error {
            message: format!(
                "staged push {request_id} cannot be rejected: approve attempt {attempt_id} \
                 may have advanced the branch on GitHub; inspect the remote ref and \
                 reconcile manually before retrying"
            ),
        },
    }
}

fn staging_not_configured() -> ServerMessage {
    ServerMessage::Error {
        message: "git push staging is not configured; \
                  the broker config needs an agent_vm.vm_http section"
            .into(),
    }
}

/// Per-stream byte cap for stdout/stderr capture in [`run_agent`].
///
/// A signed envelope embeds the captured bytes, so an agent that
/// emits unbounded output would otherwise let one `RunAgent` call
/// exhaust writd's memory (the JSON+base64 wrapper makes a second
/// in-memory copy on top of the captured buffer). Capping at 4 MiB
/// keeps the per-call footprint bounded; the `truncated_at` marker on
/// `OutputEnvelope` records the cap so verifiers know the capture is
/// a prefix rather than the whole stream.
pub(crate) const MAX_RUN_AGENT_STREAM_BYTES: usize = 4 * 1024 * 1024;

/// Total wall-clock budget the VM dispatch arm gives a per-run VM
/// agent to complete and POST its outcome to writd. Implementer runs
/// can be long — the bailiff CLI's flock acceptance message already
/// pins "30-minute hold per implement" — so the writd-side wait must
/// be at least as generous as the operator's mental model. A run that
/// blows past this is almost always a stuck guest, not a slow agent;
/// the wait helper returns a structured `Timeout` so the caller
/// surface names both the run id and the elapsed duration.
const RUN_AGENT_VM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);
/// How often the wait helper polls the audit table for the outcome
/// row. 500ms keeps the audit handle warm without spinning; the row
/// arrives within one POST round-trip after the guest finishes, so
/// the observed latency from "outcome lands" to "wait returns" is
/// bounded by this interval rather than the full timeout.
const RUN_AGENT_VM_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Read `reader` to EOF, retaining at most `cap` bytes. After the cap
/// is hit, further bytes are drained and discarded so the child does
/// not block writing to a full pipe. The returned `truncated_at` is
/// `Some(cap)` iff any bytes were dropped — `None` means the entire
/// stream fit. The cap is byte-aligned to whatever the underlying read
/// returned; we do not bisect a single read across the boundary.
pub(crate) async fn capture_stream_capped<R>(
    mut reader: R,
    cap: usize,
) -> std::io::Result<(Vec<u8>, Option<u64>)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = vec![0u8; 16 * 1024];
    let mut truncated_at: Option<u64> = None;
    loop {
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            return Ok((buf, truncated_at));
        }
        if truncated_at.is_some() {
            // Past the cap: drain to keep the child unblocked.
            continue;
        }
        let room = cap.saturating_sub(buf.len());
        if room == 0 {
            // We previously filled exactly to the cap. Receiving more
            // bytes proves the stream extended past it.
            truncated_at = Some(cap as u64);
        } else if n <= room {
            buf.extend_from_slice(&tmp[..n]);
        } else {
            buf.extend_from_slice(&tmp[..room]);
            truncated_at = Some(cap as u64);
        }
    }
}

fn run_agent_not_configured(component: &str) -> ServerMessage {
    ServerMessage::Error {
        message: format!(
            "RunAgent dispatch is not configured: {component} is unset; \
             writd needs notes_repo + signing_key + run_agent_spawn to serve RunAgent"
        ),
    }
}

/// Handle a [`ClientMessage::RunAgent`] request end-to-end.
///
/// Spawn the configured child with the prompt on stdin, capture stdout
/// to completion, sign the resulting [`SignedRunMetadata`], wrap
/// everything in a [`SignedRunEnvelope`], and store the envelope in
/// writ's own bare repo under `output_ref` keyed on the fresh run id.
/// The on-the-wire `output_ref` is a ref name inside writ's repo
/// (bailiff fetches `refs/notes/writ/v1/*` over Git remote, per the
/// cross-daemon ownership decision pinned in
/// `docs/plans/2026-05-14-bailiff-split.md`); the request does **not**
/// name a filesystem path.
///
/// `capabilities` is recorded verbatim into the signed metadata so a
/// verifier sees the full set the run was authorised under.
/// Capability-set policy enforcement (refusing to spawn if a granted
/// variant is denied by `policy::*`) is deferred to a follow-up slice
/// alongside the audit row — see the plan doc.
#[allow(clippy::too_many_arguments)]
async fn run_agent<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    prompt: AgentPrompt,
    capabilities: Vec<crate::core::CapabilitySet>,
    purpose: String,
    output_ref: NotesRef,
    request_session_id: Option<SessionId>,
    workspace: Option<crate::vm_git::AgentVmWorkspaceBootstrap>,
    agent_kind: Option<crate::core::AgentKind>,
    agent_model: Option<String>,
    agent_vm: Option<&Arc<crate::agent_vm_daemon::AgentVmDaemon>>,
) -> ServerMessage {
    // `purpose` is part of the wire contract and will land on the
    // audit row in the follow-up slice. Holding the name in scope (not
    // discarding via `_`) keeps the future plumbing self-evident.
    let _purpose = purpose;

    // VM1 invariant: a `WorkspaceWrite` capability is only meaningful
    // when the request also carries a workspace bootstrap, because the
    // host-spawn path has no cwd for the agent to mutate. Reject the
    // lie before any state work happens — an unconfigured broker still
    // fails here rather than masking the gate with a not-configured
    // message. When `workspace` is `Some`, route to the per-run VM
    // dispatch; the host-spawn path below is for read-only or
    // prompt-only runs that have no checkout to operate on.
    let needs_workspace = capabilities
        .iter()
        .any(|c| matches!(c, crate::core::CapabilitySet::WorkspaceWrite { .. }));
    match (needs_workspace, workspace) {
        (true, None) => {
            return ServerMessage::Error {
                message: "RunAgent: WorkspaceWrite capability requires a workspace bootstrap"
                    .into(),
            };
        }
        (_, Some(ws)) => {
            return run_agent_in_vm(
                state,
                agent_vm,
                prompt,
                capabilities,
                output_ref,
                request_session_id,
                ws,
                agent_kind,
                agent_model,
            )
            .await;
        }
        (false, None) => {}
    }

    let Some(notes_repo) = state.notes_repo.clone() else {
        return run_agent_not_configured("notes_repo");
    };
    let Some(signing_key) = state.signing_key.clone() else {
        return run_agent_not_configured("signing_key");
    };
    let Some(spawn_config) = state.run_agent_spawn.clone() else {
        return run_agent_not_configured("run_agent_spawn");
    };

    // Bind the run to the caller's audit session when supplied: the
    // signed metadata stamps the same id, so a verifier can correlate
    // the envelope back to a session row. Reject unknown / already-
    // closed sessions before we spawn — running an agent against a
    // session that doesn't exist (or has ended) would silently produce
    // a signed envelope claiming an unreachable session.
    let resolved_session_id = match request_session_id {
        Some(claimed) => match state.audit.get_session(claimed) {
            Ok(Some(session)) if session.closed_at.is_none() => claimed,
            Ok(Some(_)) => {
                return ServerMessage::ClosedSession {
                    session_id: claimed,
                };
            }
            Ok(None) => {
                return ServerMessage::UnknownSession {
                    session_id: claimed,
                };
            }
            Err(err) => {
                return ServerMessage::Error {
                    message: format!("RunAgent: read session {claimed}: {err}"),
                };
            }
        },
        None => SessionId::new(),
    };

    let mut command = tokio::process::Command::new(&spawn_config.command);
    command
        .args(&spawn_config.args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = match crate::process_spawn::spawn_async(&mut command).await {
        Ok(c) => c,
        Err(err) => {
            return ServerMessage::Error {
                message: format!(
                    "RunAgent: spawn {:?} failed: {err}",
                    spawn_config.command.display()
                ),
            };
        }
    };

    // Feed the prompt to the child on a background task so the
    // reader tasks below aren't deadlocked when the child reads more
    // than the pipe buffer holds. Drop the writer half on EOF so the
    // child sees stdin close.
    let mut stdin = child
        .stdin
        .take()
        .expect("child stdin was requested via Stdio::piped");
    let prompt_bytes = prompt.as_bytes().to_vec();
    let prompt_sha256_str = sha256_hex(&prompt_bytes);
    let writer = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let res = stdin.write_all(&prompt_bytes).await;
        // Explicit shutdown so the child sees EOF on stdin even if the
        // tokio runtime decides to delay the drop.
        let _ = stdin.shutdown().await;
        res
    });

    // Read stdout and stderr concurrently on their own tasks: a child
    // that fills either pipe buffer would otherwise block on write,
    // and `child.wait()` would never return. Each reader caps its
    // retained buffer at MAX_RUN_AGENT_STREAM_BYTES and drains past
    // that — bounding writd's memory footprint per call.
    let stdout_pipe = child
        .stdout
        .take()
        .expect("child stdout was requested via Stdio::piped");
    let stderr_pipe = child
        .stderr
        .take()
        .expect("child stderr was requested via Stdio::piped");
    let stdout_task = tokio::spawn(async move {
        capture_stream_capped(stdout_pipe, MAX_RUN_AGENT_STREAM_BYTES).await
    });
    let stderr_task = tokio::spawn(async move {
        capture_stream_capped(stderr_pipe, MAX_RUN_AGENT_STREAM_BYTES).await
    });

    let status = match child.wait().await {
        Ok(s) => s,
        Err(err) => {
            // The reader/writer tasks are still alive; await them so
            // the captured buffers don't outlive the borrow. Their
            // results are uninteresting once wait failed.
            let _ = writer.await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            return ServerMessage::Error {
                message: format!("RunAgent: wait for child failed: {err}"),
            };
        }
    };
    // The writer task may have failed (broken pipe is normal when a
    // child exits without reading the whole prompt — e.g. `head -c 0`).
    // Drain it so the task doesn't leak; treat any error as informational.
    let _ = writer.await;

    let (stdout_bytes, stdout_truncated_at) = match stdout_task.await {
        Ok(Ok(v)) => v,
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: format!("RunAgent: read stdout: {err}"),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: stdout reader task failed: {err}"),
            };
        }
    };
    let (stderr_bytes, stderr_truncated_at) = match stderr_task.await {
        Ok(Ok(v)) => v,
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: format!("RunAgent: read stderr: {err}"),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: stderr reader task failed: {err}"),
            };
        }
    };

    // Signal termination: surface as a typed negative so the audit
    // row (when it lands) records "killed by signal" distinguishably
    // from an explicit non-zero exit. -1 is the placeholder pending
    // the audit-row slice that will refine this.
    let exit_code = status.code().unwrap_or(-1);

    let output_envelope = OutputEnvelope {
        stdout: stdout_bytes,
        stderr: stderr_bytes,
        stdout_truncated_at,
        stderr_truncated_at,
    };
    // The hash binds the canonical envelope bytes — not raw stdout —
    // so a verifier that re-encodes the envelope from its parsed form
    // can re-derive `output_envelope_sha256` deterministically.
    let output_envelope_bytes = output_envelope.to_bytes();
    let output_envelope_sha256_str = sha256_hex(&output_envelope_bytes);

    let prompt_sha256 = Sha256Hex::try_new(prompt_sha256_str)
        .expect("sha256_hex returns canonical 64-lowercase-hex output");
    let output_envelope_sha256 = Sha256Hex::try_new(output_envelope_sha256_str)
        .expect("sha256_hex returns canonical 64-lowercase-hex output");

    let metadata = SignedRunMetadata {
        run_id: AgentRunId::new(),
        // Resolved above: caller-supplied id when bound to an audit
        // session, freshly-minted otherwise. A verifier sees the same
        // id the caller asked for, so an envelope's session_id can be
        // cross-referenced with writ's audit log.
        session_id: resolved_session_id,
        prompt_sha256,
        output_envelope_sha256,
        capabilities,
        exit_code,
        completed_at: UnixMillis::now(),
        signing_key_fingerprint: signing_key.fingerprint(),
    };

    let canonical = metadata.canonical_bytes();
    let signature = match signing_key.sign(&canonical) {
        Ok(s) => s,
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: sign canonical metadata: {err}"),
            };
        }
    };

    let envelope = SignedRunEnvelope {
        metadata: metadata.clone(),
        signature: signature.clone(),
        output: output_envelope_bytes,
    };
    let envelope_bytes = envelope.to_bytes();
    // Seed the note's target OID with the run id bytes so each run gets
    // a distinct attachment object. The seed carries no payload — the
    // signed envelope itself lives in the note body, per the slice-B
    // durability decision (envelope in body, not a separate blob).
    let run_id_seed = metadata.run_id.to_string().into_bytes();

    let write_result = {
        let notes_repo = Arc::clone(&notes_repo);
        let output_ref = output_ref.clone();
        tokio::task::spawn_blocking(move || {
            notes_repo.write_note(&output_ref, &run_id_seed, &envelope_bytes)
        })
        .await
    };
    let output_oid = match write_result {
        Ok(Ok(oid)) => oid,
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: format!("RunAgent: write signed-run note: {err}"),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: notes-write task failed: {err}"),
            };
        }
    };

    ServerMessage::RunAgentCompleted {
        output_oid,
        signed_metadata: metadata,
        signature,
    }
}

/// VM dispatch arm for [`ClientMessage::RunAgent`]: open a per-run agent
/// VM via [`AgentVmDaemon::start_agent_run_session`], wait for the
/// guest's outcome row to land, materialise the signed envelope from
/// the on-disk streams, and persist it to writ's notes repo.
///
/// The arm is structurally distinct from the host-spawn path:
/// * `session_id` is *minted by the VM lifecycle* (the agent VM opens
///   its own audit session). A caller that passes `session_id: Some(_)`
///   alongside a `workspace` bootstrap is asking for two contradictory
///   session bindings; reject up front rather than silently ignoring
///   one.
/// * `agent_kind` and `agent_model` must both be present — the VM
///   lifecycle needs them to record the agent_run row and to build the
///   guest command. The host path tolerates them being absent because
///   it doesn't open an audit session; the VM path cannot.
/// * The 30-minute timeout matches bailiff's flock "30-minute hold per
///   implement" message so the operator's mental model matches reality
///   on both sides.
///
/// The envelope materialiser is pure-with-IO: no audit writes, no
/// network. This arm assembles the surrounding context (configuration
/// checks, prompt hashing, lifecycle start, wait, notes-repo write)
/// and returns the same `RunAgentCompleted` wire variant the host path
/// returns, so a verifier consumes both shapes uniformly.
#[allow(clippy::too_many_arguments)]
async fn run_agent_in_vm<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    agent_vm: Option<&Arc<crate::agent_vm_daemon::AgentVmDaemon>>,
    prompt: AgentPrompt,
    capabilities: Vec<crate::core::CapabilitySet>,
    output_ref: NotesRef,
    request_session_id: Option<SessionId>,
    workspace: crate::vm_git::AgentVmWorkspaceBootstrap,
    agent_kind: Option<crate::core::AgentKind>,
    agent_model: Option<String>,
) -> ServerMessage {
    if request_session_id.is_some() {
        return ServerMessage::Error {
            message: "RunAgent: VM mode mints its own audit session; \
                      caller must not supply session_id alongside a workspace bootstrap"
                .into(),
        };
    }

    let Some(agent_vm) = agent_vm else {
        return ServerMessage::Error {
            message: "RunAgent: agent VM runtime is not configured; \
                      the broker config needs an agent_vm.vm_http section"
                .into(),
        };
    };
    let Some(agent_kind) = agent_kind else {
        return ServerMessage::Error {
            message: "RunAgent: VM mode requires agent_kind".into(),
        };
    };
    let Some(agent_model) = agent_model else {
        return ServerMessage::Error {
            message: "RunAgent: VM mode requires agent_model".into(),
        };
    };

    let Some(notes_repo) = state.notes_repo.clone() else {
        return run_agent_not_configured("notes_repo");
    };
    let Some(signing_key) = state.signing_key.clone() else {
        return run_agent_not_configured("signing_key");
    };

    let prompt_bytes = prompt.as_bytes().to_vec();
    let prompt_sha256_str = sha256_hex(&prompt_bytes);
    let prompt_sha256 = Sha256Hex::try_new(prompt_sha256_str)
        .expect("sha256_hex returns canonical 64-lowercase-hex output");

    let started = match agent_vm
        .start_agent_run_session(
            Arc::clone(state),
            None,
            agent_kind,
            agent_model,
            workspace,
            prompt,
            None,
        )
        .await
    {
        Ok(s) => s,
        Err(err) => {
            // Start failed: the lifecycle never registered a managed
            // VM (the `Err` arm of `start_agent_run_session` already
            // closes the audit session on failure), so there's
            // nothing to tear down here.
            return ServerMessage::Error {
                message: format!("RunAgent: start agent VM run: {err}"),
            };
        }
    };

    let session_id = started.session_id();
    let run_id = started.run_id();

    // After `start_agent_run_session` returns Ok, the VM is live with
    // an open audit session and broker token. Every return path below
    // must funnel through `stop_session` so a completed (or
    // timed-out) run can't leave a guest holding broker authority
    // until daemon restart. This is the trust-boundary invariant the
    // VM design rests on: a finished run is no longer authorised.
    let response = run_agent_in_vm_after_start(
        &state.audit,
        &notes_repo,
        &signing_key,
        session_id,
        run_id,
        prompt_sha256,
        capabilities,
        output_ref,
    )
    .await;

    if let Err(err) = agent_vm.stop_session(state, session_id).await {
        tracing::error!(
            session_id = %session_id,
            run_id = %run_id,
            error = %err,
            "stop agent VM session after RunAgent dispatch failed",
        );
        // A successful envelope is moot if the guest is still
        // authorised: the trust boundary says "a finished RunAgent
        // returns a guest with no live broker authority." Surface the
        // cleanup failure as an Error so the caller can't read
        // `RunAgentCompleted` as a clean shutdown — the signed note
        // is still on disk for the operator to retrieve via audit,
        // but the wire response no longer asserts a fully-torn-down
        // run. Operator action is required: daemon reconcile (or
        // restart) will clean up the dangling session/state.
        return ServerMessage::Error {
            message: format!(
                "RunAgent: stop agent VM session {session_id} (run {run_id}) failed: {err}; \
                 the managed VM may still hold broker authority — operator action required",
            ),
        };
    }

    response
}

/// Post-start half of the VM dispatch arm: wait for the guest's
/// outcome row, materialise the signed envelope, write the note.
///
/// Split out so the caller can wrap every return path with a single
/// `stop_session` cleanup — the trust-boundary invariant is that a
/// finished `RunAgent` returns a guest with no live broker authority
/// regardless of which step inside the dispatch arm produced the
/// error.
#[allow(clippy::too_many_arguments)]
async fn run_agent_in_vm_after_start(
    audit: &crate::audit::AuditLog,
    notes_repo: &Arc<crate::notes_repo::NotesRepo>,
    signing_key: &crate::signing::WritSigningKey,
    session_id: SessionId,
    run_id: AgentRunId,
    prompt_sha256: Sha256Hex,
    capabilities: Vec<crate::core::CapabilitySet>,
    output_ref: NotesRef,
) -> ServerMessage {
    let outcome = match crate::agent_vm_daemon::wait_for_agent_run_outcome(
        audit,
        run_id,
        RUN_AGENT_VM_TIMEOUT,
        RUN_AGENT_VM_POLL_INTERVAL,
    )
    .await
    {
        Ok(o) => o,
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: wait for agent VM outcome: {err}"),
            };
        }
    };

    let materialised = match crate::agent_vm_daemon::materialize_vm_signed_envelope(
        &outcome,
        session_id,
        prompt_sha256,
        capabilities,
        signing_key,
    )
    .await
    {
        Ok(m) => m,
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: materialise signed envelope: {err}"),
            };
        }
    };

    let run_id_seed = run_id.to_string().into_bytes();
    let envelope_bytes = materialised.envelope_bytes;
    let metadata = materialised.envelope.metadata;
    let signature = materialised.envelope.signature;

    let write_result = {
        let notes_repo = Arc::clone(notes_repo);
        tokio::task::spawn_blocking(move || {
            notes_repo.write_note(&output_ref, &run_id_seed, &envelope_bytes)
        })
        .await
    };
    let output_oid = match write_result {
        Ok(Ok(oid)) => oid,
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: format!("RunAgent: write signed-run note: {err}"),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("RunAgent: notes-write task failed: {err}"),
            };
        }
    };

    ServerMessage::RunAgentCompleted {
        output_oid,
        signed_metadata: metadata,
        signature,
    }
}

fn missing_agent_kind_for_registry_response() -> ServerMessage {
    ServerMessage::Error {
        message: "agent kind is required; open the session with --agent claude or --agent codex"
            .into(),
    }
}

async fn dispatch_capability<S: SecretStore + Send + Sync>(
    session_id: SessionId,
    capability: CapabilityRequest,
    state: &Arc<BrokerState<S>>,
) -> ServerMessage {
    // The five `CapabilityOutcome` variants map 1:1 to wire variants;
    // we deliberately do *not* collapse `UnknownSession`/`ClosedSession`
    // into `Error` so clients can distinguish them by type tag rather
    // than by string-matching a free-form message.
    match request_capability(session_id, capability, state).await {
        CapabilityOutcome::Granted { token, expires_at } => {
            ServerMessage::TokenGranted { token, expires_at }
        }
        CapabilityOutcome::Denied { reason } => ServerMessage::Denied { reason },
        CapabilityOutcome::UnknownSession { session_id } => {
            ServerMessage::UnknownSession { session_id }
        }
        CapabilityOutcome::ClosedSession { session_id } => {
            ServerMessage::ClosedSession { session_id }
        }
        CapabilityOutcome::Error { message } => ServerMessage::Error { message },
    }
}

pub(crate) async fn request_capability<S: SecretStore + Send + Sync>(
    session_id: SessionId,
    capability: CapabilityRequest,
    state: &Arc<BrokerState<S>>,
) -> CapabilityOutcome {
    // Preflight the session for a readable client error. The
    // authoritative check runs inside `record_pre_mint`'s transaction
    // (and the `request_requires_open_session` trigger behind it) —
    // without that, a CloseSession racing this check would land before
    // the insert and we'd write against a closed session. This preflight
    // only exists so the common "session is gone" case returns a clean
    // message instead of leaking the generic audit-invariant string.
    let session = match state.audit.get_session(session_id) {
        Ok(None) => {
            return CapabilityOutcome::UnknownSession { session_id };
        }
        Ok(Some(s)) if s.closed_at.is_some() => {
            return CapabilityOutcome::ClosedSession { session_id };
        }
        Err(e) => {
            return CapabilityOutcome::Error {
                message: e.to_string(),
            };
        }
        Ok(Some(session)) => session,
    };

    let request_id = RequestId::new();
    let received_at = UnixMillis::now();
    let decision = policy::decide(&capability, &state.policy);

    // Pre-record the request + decision *before* we await the backend
    // mint. If we recorded only on the way back out, a crash (or a
    // CloseSession that lands during the await and trips the
    // session-closed check) would leave the broker having minted a
    // credential with no audit trail — a direct violation of the
    // "every request/decision is append-only audited" invariant in
    // docs/design/broker.md. With pre-recording, the request row
    // commits before any network I/O; the grant or mint-failure is
    // appended once the mint completes.
    if let Err(e) = state.audit.record_pre_mint(&PreMintRecord {
        request_id,
        session_id,
        received_at,
        request: &capability,
        decision: &decision,
    }) {
        return CapabilityOutcome::Error {
            message: format!("request could not be recorded: {e}"),
        };
    }

    // Early-return on Deny: no await point follows, so the &decision
    // borrow is trivially scoped.
    if let PolicyDecision::Deny { reason } = &decision {
        return CapabilityOutcome::Denied {
            reason: reason.clone(),
        };
    }

    // Decision is Grant. Extract scope/ttl (cloning) before the await
    // so the short-lived &decision borrows don't cross the async boundary.
    let (github_scope, ttl): (_, TtlSeconds) = match &decision {
        PolicyDecision::Grant { scope, ttl } => {
            let s = match scope {
                GrantedScope::GitHub(s) => s.clone(),
            };
            (s, *ttl)
        }
        PolicyDecision::Deny { .. } => unreachable!("handled above"),
    };

    let mint_result = state
        .minter
        .mint_for_agent(&state.secrets, session.agent_kind, github_scope, ttl)
        .await;

    match mint_result {
        Ok(minted) => {
            let expires_at = minted.expires_at();
            let (token, grant) = minted.into_grant_and_token(request_id, session_id);
            if let Err(e) = state.audit.record_grant(&grant) {
                // The audit log is the system of record. Delivering a token
                // that isn't recorded would violate the broker's core
                // invariant ("no unaudited grant"). The minted token is
                // wasted; it expires on its own without ever being used.
                // A transient disk issue will resolve on retry; a permanent
                // one (full disk, corrupt DB) must be fixed by the operator.
                tracing::error!(
                    target: AUDIT_WRITE_FAILURE_TARGET,
                    kind = "broker_grant",
                    jti = %grant.jti,
                    error = %e,
                    "audit write failed: minted credential not delivered",
                );
                return CapabilityOutcome::Error {
                    message: format!(
                        "credential was minted but could not be recorded; not delivering: {e}"
                    ),
                };
            }
            CapabilityOutcome::Granted { token, expires_at }
        }

        Err(e) => {
            // The audit row is the system of record and keeps the full
            // `Display` (which itself caps `ApiError.body` to 256 chars in
            // `MintError`'s impl). The agent only ever sees the bounded
            // label form so the protocol surface can't carry unbounded or
            // sensitive backend payloads — see `MintError::agent_message`.
            let audit_message = e.to_string();
            let agent_message = e.agent_message();
            if let Err(ae) =
                state
                    .audit
                    .record_mint_failure(request_id, UnixMillis::now(), &audit_message)
            {
                return CapabilityOutcome::Error {
                    message: format!(
                        "mint failed and the failure could not be recorded: {ae} \
                         (original mint error: {agent_message})"
                    ),
                };
            }
            CapabilityOutcome::Error {
                message: agent_message,
            }
        }
    }
}

/// Maximum bytes we will buffer for a single newline-terminated request.
/// The largest honest [`ClientMessage`] is a `RunAgent` carrying a
/// 1 MiB [`AgentPrompt`] (the cap pinned by
/// [`crate::agent_run::MAX_AGENT_PROMPT_BYTES`]); other variants are at
/// most a few KiB. `serde_json` escapes ASCII control bytes as
/// `\u00XX`, expanding worst-case input 6:1, so the wire frame for a
/// 1 MiB control-character prompt is up to 6 MiB before envelope
/// overhead. Matches the `6 * MAX_X_BYTES + small` convention used by
/// `vm_http` for the same reason. A peer that writes
/// non-newline-terminated data still can't make the broker allocate
/// without bound — without this cap, `read_until(b'\n')` grows the
/// buffer until the process OOMs.
const MAX_LINE_BYTES: usize = 6 * crate::agent_run::MAX_AGENT_PROMPT_BYTES + 64 * 1024;

/// Maximum idle time between reads on a connection. The CLI sends one
/// message and reads one reply, so a healthy peer never approaches
/// this. A stalled peer that connects and then goes quiet would
/// otherwise pin a tokio task and an fd forever.
const IDLE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Read one newline-terminated line from `reader`, failing with
/// `InvalidData` if the line would exceed `max` bytes (exclusive of the
/// terminator). Returns `Ok(None)` on clean EOF before any bytes are
/// seen, mirroring `AsyncBufReadExt::read_line`'s convention.
async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(if buf.is_empty() { None } else { Some(buf) });
        }
        if let Some(i) = available.iter().position(|&b| b == b'\n') {
            if buf.len() + i > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("request line exceeds {max}-byte limit"),
                ));
            }
            buf.extend_from_slice(&available[..i]);
            reader.consume(i + 1);
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return Ok(Some(buf));
        }
        let len = available.len();
        if buf.len() + len > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("request line exceeds {max}-byte limit"),
            ));
        }
        buf.extend_from_slice(available);
        reader.consume(len);
    }
}

async fn handle_connection<S: SecretStore + Send + Sync + 'static>(
    stream: UnixStream,
    state: Arc<BrokerState<S>>,
    agent_vm: Option<Arc<AgentVmDaemon>>,
) -> io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    loop {
        let read = tokio::time::timeout(
            IDLE_READ_TIMEOUT,
            read_line_bounded(&mut reader, MAX_LINE_BYTES),
        )
        .await;
        let bytes = match read {
            // Idle peer: close rather than hold the task open indefinitely.
            Err(_elapsed) => return Ok(()),
            Ok(Ok(Some(b))) => b,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(e)) if e.kind() == io::ErrorKind::InvalidData => {
                // Oversize line: send a structured error back so the CLI
                // surfaces something actionable, then close.
                let resp = ServerMessage::Error {
                    message: e.to_string(),
                };
                let mut json =
                    serde_json::to_string(&resp).expect("ServerMessage always serializes");
                json.push('\n');
                let _ = writer.write_all(json.as_bytes()).await;
                return Ok(());
            }
            Ok(Err(e)) => return Err(e),
        };
        let response = match serde_json::from_slice::<ClientMessage>(&bytes) {
            Err(e) => ServerMessage::Error {
                message: format!("invalid request: {e}"),
            },
            Ok(msg) => dispatch_message_with_agent_vm(msg, &state, agent_vm.as_ref()).await,
        };
        let mut json = serde_json::to_string(&response).expect("ServerMessage always serializes");
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
    }
}

/// Bind the listener, handling the stale-socket case safely.
///
/// Order matters: we attempt the bind first. If it fails with
/// `AddrInUse`, only then do we probe for liveness. This is deliberate
/// — probing first and then removing the file has a TOCTOU window where
/// another `writd` could bind between our liveness check and our
/// `remove_file`, and we'd delete the live daemon's socket. By
/// attempting the bind first, the kernel adjudicates: if someone else
/// is already bound, our `bind` fails, and we only rewrite the
/// filesystem if the existing socket is confirmed stale.
///
/// A residual race remains: between confirming staleness (connect
/// fails) and removing the file, a new `writd` could start and bind.
/// Our `remove_file` would then delete its socket. The retry bind
/// immediately after would fail with `AddrInUse` (the other daemon is
/// still listening on the inode, even after the dentry was unlinked),
/// and we return the error. The other daemon's socket *file* is gone
/// but its listening socket is still serving — operator intervention
/// (restart the surviving daemon) is needed. This is strictly better
/// than the probe-first ordering, which could delete a live socket
/// *and* then succeed in rebinding, stealing the identity. A proper
/// fix requires an flock-protected lock file; that's a larger change.
async fn bind_socket(socket_path: &Path) -> io::Result<UnixListener> {
    match UnixListener::bind(socket_path) {
        Ok(l) => return Ok(l),
        Err(e) if e.kind() != io::ErrorKind::AddrInUse => return Err(e),
        Err(_) => {}
    }

    // AddrInUse: either a live daemon or a stale socket file. Probe.
    if UnixStream::connect(socket_path).await.is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "another writd is already running at {}; \
                 stop it before starting a new one",
                socket_path.display()
            ),
        ));
    }

    // Only remove the path if it's actually a socket. A regular file at
    // the configured socket path almost certainly means operator error;
    // silently clobbering it would be surprising and destructive.
    match std::fs::metadata(socket_path) {
        Ok(m) if !m.file_type().is_socket() => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} exists but is not a socket; refusing to remove it",
                    socket_path.display()
                ),
            ));
        }
        Ok(_) => std::fs::remove_file(socket_path)?,
        // Someone else cleaned up between probe and metadata — fine,
        // just proceed to rebind.
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    UnixListener::bind(socket_path)
}

/// Listen on `socket_path`, spawning a task per connection. Returns only
/// on a fatal listener error.
///
/// The parent directory is created with mode 0700 before binding. If
/// the parent already exists with group or world access bits set the
/// function returns `ErrorKind::PermissionDenied` without binding —
/// any looser permission means a local attacker can connect to the
/// credential socket. A stale socket file is removed only after
/// confirming nothing is listening on it; if a live daemon is already
/// serving the path this function returns `ErrorKind::AddrInUse`.
pub async fn run<S: SecretStore + Send + Sync + 'static>(
    socket_path: &Path,
    state: Arc<BrokerState<S>>,
) -> io::Result<()> {
    run_with_agent_vm(socket_path, state, None).await
}

/// Listen on `socket_path` with an optional daemon-managed agent VM controller.
/// Use this when `writd` was configured with agent-VM support; [`run`] delegates
/// here with no controller for the ordinary broker-only daemon.
pub async fn run_with_agent_vm<S: SecretStore + Send + Sync + 'static>(
    socket_path: &Path,
    state: Arc<BrokerState<S>>,
    agent_vm: Option<Arc<AgentVmDaemon>>,
) -> io::Result<()> {
    let listener = prepare_broker_listener(socket_path).await?;
    serve_broker_with_agent_vm(listener, state, agent_vm).await
}

/// Validate the socket parent and bind the Unix socket, returning the
/// bound listener. Use this when the caller needs to prove singleton
/// daemon ownership *before* doing other side-effecting setup (e.g.
/// rotating the UI HTTP bearer). [`serve_broker_with_agent_vm`] is the
/// matching consumer.
///
/// The parent directory is created with mode 0700 if missing. If the
/// parent already exists with group or world access bits set the
/// function returns `ErrorKind::PermissionDenied` without binding. A
/// stale socket file is removed only after confirming nothing is
/// listening on it; if a live daemon is already serving the path this
/// returns `ErrorKind::AddrInUse`.
pub async fn prepare_broker_listener(socket_path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        // The socket is the auth boundary: any process that can reach the
        // parent directory can connect and request credentials. Refuse if
        // the parent has group or world access bits, even if we didn't
        // create it — we don't silently chmod a directory we don't own.
        // Operators can fix with: chmod 700 <parent>.
        let mode = std::fs::metadata(parent)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "socket parent {} has group/world access bits (mode {:04o}); \
                     refusing to bind: any local user could connect to the credential \
                     socket. Fix with: chmod 700 {}",
                    parent.display(),
                    mode & 0o777,
                    parent.display()
                ),
            ));
        }
    }

    bind_socket(socket_path).await
}

/// Accept connections on `listener` until a fatal listener error.
/// Pair with [`prepare_broker_listener`].
pub async fn serve_broker_with_agent_vm<S: SecretStore + Send + Sync + 'static>(
    listener: UnixListener,
    state: Arc<BrokerState<S>>,
    agent_vm: Option<Arc<AgentVmDaemon>>,
) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        let agent_vm = agent_vm.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, state, agent_vm).await {
                tracing::warn!(error = %e, "broker connection handler error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{GitPushApproveAttemptOutcome, GitPushApproveAttemptState};
    use crate::core::{AgentKind, GitHubAccess, RepoRef};
    use crate::github::{GitHubAppConfig, GitHubAppRegistryConfig, GitHubMinter};
    use crate::policy::PolicyConfig;
    use crate::secret::{SecretError, SecretKey, SecretStore};
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // --- Test secret store -----------------------------------------------

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

    // Fixture key — same material used in github.rs tests; kept in a
    // file so the test binary doesn't embed the PEM inline and so we
    // can share it across modules without duplicating the bytes.
    const TEST_PRIV: &str = include_str!("../tests/fixtures/rsa_test_1.pem");

    /// Walk `PATH` looking for `name`. Returns the first match.
    /// The `run_agent` tests need real tools (`cat`, `false`,
    /// `sh`/`bash`) and the production `RunAgentSpawnConfig` carries
    /// an absolute path, so tests resolve one at setup. Hardcoding
    /// `/bin/...` or `/usr/bin/...` works on macOS dev hosts but not
    /// in Nix CI sandboxes where coreutils live under `/nix/store/`.
    fn find_in_path(name: &str) -> Option<std::path::PathBuf> {
        let path_var = std::env::var_os("PATH")?;
        std::env::split_paths(&path_var)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    }

    /// Like [`find_in_path`] but tries several names in order. Used
    /// for the shell — Nix stdenv reliably provides `bash` on PATH
    /// but `sh` may be a symlink that isn't always in scope.
    fn find_in_path_any(names: &[&str]) -> std::path::PathBuf {
        for name in names {
            if let Some(path) = find_in_path(name) {
                return path;
            }
        }
        let path_var = std::env::var_os("PATH").unwrap_or_default();
        panic!("could not locate any of {names:?} in PATH ({path_var:?})");
    }

    fn make_state(
        server: &MockServer,
        writable: Vec<RepoRef>,
        owner: &str,
    ) -> Arc<BrokerState<InMemStore>> {
        let pk = SecretKey::new("gh-app-pk").unwrap();
        let store = InMemStore::default();
        store.put(&pk, TEST_PRIV).unwrap();
        let mut apps = BTreeMap::new();
        apps.insert(
            AgentKind::Claude,
            GitHubAppConfig {
                app_id: 42,
                installation_id: 999,
                installation_owner: owner.into(),
                private_key_secret: pk,
                api_base: server.uri(),
            },
        );
        let minter = GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap());
        Arc::new(BrokerState {
            audit: Arc::new(AuditLog::open_in_memory().unwrap()),
            minter,
            secrets: store,
            policy: PolicyConfig {
                writable_repos: writable,
                default_ttl: crate::core::TtlSeconds::new(3600).unwrap(),
            },
            staging_store: None,
            notes_repo: None,
            signing_key: None,
            run_agent_spawn: None,
            promote_runtime: None,
        })
    }

    fn make_agent_registry_state(server: &MockServer) -> Arc<BrokerState<InMemStore>> {
        make_agent_registry_state_for_agents(server, &[AgentKind::Claude, AgentKind::Codex])
    }

    fn make_agent_registry_state_for_agents(
        server: &MockServer,
        agents: &[AgentKind],
    ) -> Arc<BrokerState<InMemStore>> {
        let claude_pk = SecretKey::new("claude-pk").unwrap();
        let codex_pk = SecretKey::new("codex-pk").unwrap();
        let store = InMemStore::default();
        store.put(&claude_pk, TEST_PRIV).unwrap();
        store.put(&codex_pk, TEST_PRIV).unwrap();
        let mut apps = BTreeMap::new();
        for agent in agents {
            let config = match agent {
                AgentKind::Claude => GitHubAppConfig {
                    app_id: 101,
                    installation_id: 111,
                    installation_owner: "o".into(),
                    private_key_secret: claude_pk.clone(),
                    api_base: server.uri(),
                },
                AgentKind::Codex => GitHubAppConfig {
                    app_id: 202,
                    installation_id: 222,
                    installation_owner: "o".into(),
                    private_key_secret: codex_pk.clone(),
                    api_base: server.uri(),
                },
            };
            apps.insert(*agent, config);
        }
        let minter = GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap());
        Arc::new(BrokerState {
            audit: Arc::new(AuditLog::open_in_memory().unwrap()),
            minter,
            secrets: store,
            policy: PolicyConfig {
                writable_repos: Vec::new(),
                default_ttl: crate::core::TtlSeconds::new(3600).unwrap(),
            },
            staging_store: None,
            notes_repo: None,
            signing_key: None,
            run_agent_spawn: None,
            promote_runtime: None,
        })
    }

    fn repo(owner: &str, name: &str) -> RepoRef {
        RepoRef {
            owner: owner.into(),
            name: name.into(),
        }
    }

    fn expiry_str_from_now(secs: i64) -> String {
        let t = time::OffsetDateTime::now_utc() + time::Duration::seconds(secs);
        t.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    }

    // --- Session lifecycle -----------------------------------------------

    #[tokio::test]
    async fn open_session_returns_session_opened_and_records_in_db() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");

        let resp = dispatch_message(
            ClientMessage::OpenSession {
                label: Some("test".into()),
                agent_kind: Some(AgentKind::Claude),
                agent_model: None,
            },
            &state,
        )
        .await;

        let session_id = match resp {
            ServerMessage::SessionOpened { session_id } => session_id,
            other => panic!("expected SessionOpened, got {other:?}"),
        };

        // DB must contain the record
        let record = state.audit.get_session(session_id).unwrap().unwrap();
        assert_eq!(record.label.as_deref(), Some("test"));
        assert!(record.closed_at.is_none());
    }

    #[tokio::test]
    async fn close_session_after_open_returns_session_closed_and_sets_timestamp() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");

        let session_id = match dispatch_message(
            ClientMessage::OpenSession {
                label: None,
                agent_kind: Some(AgentKind::Claude),
                agent_model: None,
            },
            &state,
        )
        .await
        {
            ServerMessage::SessionOpened { session_id } => session_id,
            other => panic!("{other:?}"),
        };

        let resp = dispatch_message(ClientMessage::CloseSession { session_id }, &state).await;
        assert_eq!(resp, ServerMessage::SessionClosed);

        let record = state.audit.get_session(session_id).unwrap().unwrap();
        assert!(record.closed_at.is_some());
    }

    #[tokio::test]
    async fn close_unknown_session_is_silently_accepted() {
        // The UPDATE simply matches 0 rows; no error is returned.
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let unknown: SessionId = "00000000-0000-0000-0000-deadbeef0001".parse().unwrap();
        let resp = dispatch_message(
            ClientMessage::CloseSession {
                session_id: unknown,
            },
            &state,
        )
        .await;
        assert_eq!(resp, ServerMessage::SessionClosed);
    }

    /// Dispatch refuses `RunAgent` when any of the three configuration
    /// fields (`notes_repo`, `signing_key`, `run_agent_spawn`) is
    /// `None`. Returning an explicit, component-named `Error` rather
    /// than panicking or silently accepting the request lets an
    /// operator see exactly which boot wiring is missing. Until the
    /// writd boot slice lands, every BrokerState used in tests (and
    /// the production daemon) leaves these unset and `RunAgent`
    /// surfaces that fact verbatim.
    #[tokio::test]
    async fn run_agent_dispatch_errors_when_not_configured() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");

        let resp = dispatch_message(
            ClientMessage::RunAgent {
                prompt: crate::agent_run::AgentPrompt::new("hello"),
                capabilities: vec![crate::core::CapabilitySet::WorkspaceRead {
                    repo: RepoRef {
                        owner: "smaug123".into(),
                        name: "writ".into(),
                    },
                }],
                purpose: "test".into(),
                output_ref: crate::core::NotesRef::try_new("refs/notes/writ/agent-outputs")
                    .unwrap(),
                session_id: None,
                workspace: None,
                agent_kind: None,
                agent_model: None,
            },
            &state,
        )
        .await;

        let ServerMessage::Error { message } = resp else {
            panic!("expected ServerMessage::Error, got {resp:?}");
        };
        assert!(
            message.contains("not configured") && message.contains("notes_repo"),
            "expected 'not configured' message naming the missing component, got: {message}",
        );
    }

    /// `WorkspaceWrite` is only meaningful inside a VM workspace: the
    /// host spawn path has no cwd, so granting write authority over a
    /// nonexistent checkout would be a wire-level lie. The broker
    /// must refuse a `RunAgent` carrying any `WorkspaceWrite`
    /// capability whose `workspace` bootstrap is `None`, *before*
    /// touching broker state — so an unconfigured broker still
    /// rejects with this gate rather than the not-configured message.
    /// Slice VM1's load-bearing invariant.
    #[tokio::test]
    async fn run_agent_rejects_workspace_write_without_workspace_bootstrap() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");

        let resp = dispatch_message(
            ClientMessage::RunAgent {
                prompt: crate::agent_run::AgentPrompt::new("implement"),
                capabilities: vec![crate::core::CapabilitySet::WorkspaceWrite {
                    repo: RepoRef {
                        owner: "smaug123".into(),
                        name: "writ".into(),
                    },
                }],
                purpose: "implement-stage".into(),
                output_ref: crate::core::NotesRef::try_new("refs/notes/writ/agent-outputs")
                    .unwrap(),
                session_id: None,
                workspace: None,
                agent_kind: None,
                agent_model: None,
            },
            &state,
        )
        .await;

        let ServerMessage::Error { message } = resp else {
            panic!("expected ServerMessage::Error, got {resp:?}");
        };
        assert!(
            message.contains("WorkspaceWrite") && message.contains("workspace"),
            "expected gate error naming WorkspaceWrite and the workspace bootstrap requirement, got: {message}",
        );
    }

    /// When `workspace` is `Some`, the broker routes through the
    /// agent-VM lifecycle. `dispatch_message` forwards `agent_vm: None`
    /// — the runtime is not configured on this code path — so the VM
    /// dispatch arm must surface a clear "agent VM runtime is not
    /// configured" error rather than a panic or silent fall-through to
    /// the host spawn (which would defeat the point of the field).
    /// Slice VM2b wires the dispatch arm; this test pins the
    /// unconfigured-runtime gate that protects callers from a silent
    /// host-spawn fallback.
    #[tokio::test]
    async fn run_agent_with_workspace_reports_unconfigured_vm_runtime() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");

        let resp = dispatch_message(
            ClientMessage::RunAgent {
                prompt: crate::agent_run::AgentPrompt::new("implement"),
                capabilities: vec![crate::core::CapabilitySet::WorkspaceWrite {
                    repo: RepoRef {
                        owner: "smaug123".into(),
                        name: "writ".into(),
                    },
                }],
                purpose: "implement-stage".into(),
                output_ref: crate::core::NotesRef::try_new("refs/notes/writ/agent-outputs")
                    .unwrap(),
                session_id: None,
                workspace: Some(crate::vm_git::AgentVmWorkspaceBootstrap {
                    repo: "owner/repo".parse().unwrap(),
                    destination: None,
                    warm: crate::vm_git::WorkspaceWarmMode::None,
                }),
                agent_kind: Some(crate::core::AgentKind::Claude),
                agent_model: Some("claude-opus".into()),
            },
            &state,
        )
        .await;

        let ServerMessage::Error { message } = resp else {
            panic!("expected ServerMessage::Error, got {resp:?}");
        };
        assert!(
            message.contains("agent VM runtime is not configured"),
            "expected unconfigured-runtime error, got: {message}",
        );
    }

    /// Round-trip a `RunAgent` request end-to-end through a fully
    /// configured `BrokerState`: spawn a `cat`-style child that copies
    /// stdin to stdout, sign the resulting metadata, write the
    /// envelope into a fresh on-disk notes repo, then read the note
    /// back and verify the signature and content hashes.
    ///
    /// This is the slice-B contract test the plan calls out: bailiff
    /// sends `RunAgent { prompt: "noop", … }`, writ runs a no-op
    /// child, writes a signed note to writ's repo, and a verifier
    /// (this test, standing in for bailiff's read side in slice B5)
    /// re-derives every signed quantity from the envelope.
    #[tokio::test]
    async fn run_agent_round_trip_signs_and_writes_note() {
        use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
        use crate::signing::WritSigningKey;

        const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");

        let tmp = tempfile::tempdir().unwrap();
        let repo_path = tmp.path().join("writ-repo");
        let notes_repo = NotesRepo::init_or_open(&repo_path).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let verifying_key = signing_key.verifying_key();
        let fingerprint = signing_key.fingerprint();

        // `cat` is the canonical "noop" agent: it copies stdin to
        // stdout, so the captured stdout is byte-equal to the prompt
        // bytes writ writes in. That gives us a deterministic capture
        // we can check from the verifier side without baking spawner
        // internals into the test.
        let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");
        // `RunAgent` does not mint GitHub tokens, but `BrokerState`
        // requires a non-empty registry. Reuse the existing test
        // helper so the registry shape stays in lockstep with other
        // dispatch tests; the wiremock server is harmless overhead.
        let server = MockServer::start().await;
        let base = make_state(&server, vec![], "o");
        // Tear the Arc apart so we can extend the state with the
        // run-agent triple. `Arc::try_unwrap` succeeds because nothing
        // else holds the Arc yet.
        let base = Arc::try_unwrap(base)
            .unwrap_or_else(|_| panic!("make_state Arc must be uniquely held"));
        let state = Arc::new(BrokerState {
            audit: base.audit,
            minter: base.minter,
            secrets: base.secrets,
            policy: base.policy,
            staging_store: base.staging_store,
            notes_repo: Some(Arc::new(notes_repo)),
            signing_key: Some(signing_key),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: cat,
                args: Vec::new(),
            }),
            promote_runtime: base.promote_runtime,
        });

        let prompt_text = "hello world from cat\n";
        let output_ref =
            crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
        let resp = dispatch_message(
            ClientMessage::RunAgent {
                prompt: crate::agent_run::AgentPrompt::new(prompt_text),
                capabilities: vec![crate::core::CapabilitySet::WorkspaceRead {
                    repo: RepoRef {
                        owner: "smaug123".into(),
                        name: "writ".into(),
                    },
                }],
                purpose: "round-trip-test".into(),
                output_ref: output_ref.clone(),
                session_id: None,
                workspace: None,
                agent_kind: None,
                agent_model: None,
            },
            &state,
        )
        .await;

        let (output_oid, signed_metadata, signature) = match resp {
            ServerMessage::RunAgentCompleted {
                output_oid,
                signed_metadata,
                signature,
            } => (output_oid, signed_metadata, signature),
            other => panic!("expected RunAgentCompleted, got {other:?}"),
        };

        // 1. Signed metadata uses the keyring we configured.
        assert_eq!(signed_metadata.signing_key_fingerprint, fingerprint);
        assert_eq!(signed_metadata.exit_code, 0);
        let expected_prompt_hash = crate::agent_run::sha256_hex(prompt_text.as_bytes());
        assert_eq!(signed_metadata.prompt_sha256.as_str(), expected_prompt_hash);

        // 2. Detached signature verifies against the canonical bytes.
        verifying_key
            .verify(&signed_metadata.canonical_bytes(), &signature)
            .expect("signature must verify against canonical metadata");

        // 3. Note body decodes to a `SignedRunEnvelope` whose pieces
        // match the response. The note's target OID is the seed-blob
        // OID dispatch returned; reading the note back proves both
        // that the envelope round-trips byte-exact and that the
        // verifier can find the artefact from just the OID + ref name.
        let notes_repo_handle = state.notes_repo.as_ref().unwrap().clone();
        let body = tokio::task::spawn_blocking({
            let output_ref = output_ref.clone();
            let oid = output_oid.clone();
            move || notes_repo_handle.read_note(&output_ref, &oid)
        })
        .await
        .unwrap()
        .unwrap();
        let envelope = SignedRunEnvelope::from_bytes(&body).unwrap();
        assert_eq!(envelope.metadata, signed_metadata);
        assert_eq!(envelope.signature, signature);
        // 4. The envelope's output bytes hash to the value the metadata
        // committed to — i.e. nothing in the storage path silently
        // mangled the binary payload.
        assert_eq!(
            crate::agent_run::sha256_hex(&envelope.output),
            signed_metadata.output_envelope_sha256.as_str(),
        );
        // 5. Decode the inner `OutputEnvelope` and assert the captured
        // streams match what the child actually wrote: `cat` echoes
        // stdin to stdout verbatim and writes nothing to stderr, with
        // neither stream hitting the 4 MiB cap.
        let output_envelope = OutputEnvelope::from_bytes(&envelope.output).unwrap();
        assert_eq!(output_envelope.stdout, prompt_text.as_bytes());
        assert!(output_envelope.stderr.is_empty());
        assert_eq!(output_envelope.stdout_truncated_at, None);
        assert_eq!(output_envelope.stderr_truncated_at, None);
    }

    /// A non-zero terminal exit must reach the signed metadata
    /// verbatim and the note must still be written: the plan calls
    /// out crash semantics explicitly ("writ still writes whatever was
    /// captured and signs the partial; the audit row records the
    /// non-zero exit code"). Using `/bin/false` is the smallest
    /// exercise of that path — no stdout, no stderr, exit code 1.
    #[tokio::test]
    async fn run_agent_signs_non_zero_exit() {
        use crate::run_envelope::OutputEnvelope;
        use crate::signing::WritSigningKey;

        const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");

        let tmp = tempfile::tempdir().unwrap();
        let notes_repo = NotesRepo::init_or_open(tmp.path().join("repo")).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let false_bin = find_in_path("false").expect("false must be on PATH for the test");

        let server = MockServer::start().await;
        let base = Arc::try_unwrap(make_state(&server, vec![], "o"))
            .unwrap_or_else(|_| panic!("make_state Arc must be uniquely held"));
        let state = Arc::new(BrokerState {
            audit: base.audit,
            minter: base.minter,
            secrets: base.secrets,
            policy: base.policy,
            staging_store: base.staging_store,
            notes_repo: Some(Arc::new(notes_repo)),
            signing_key: Some(signing_key),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: false_bin,
                args: Vec::new(),
            }),
            promote_runtime: base.promote_runtime,
        });

        let resp = dispatch_message(
            ClientMessage::RunAgent {
                prompt: crate::agent_run::AgentPrompt::new("ignored"),
                capabilities: Vec::new(),
                purpose: "non-zero-exit".into(),
                output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs")
                    .unwrap(),
                session_id: None,
                workspace: None,
                agent_kind: None,
                agent_model: None,
            },
            &state,
        )
        .await;

        let signed_metadata = match resp {
            ServerMessage::RunAgentCompleted {
                signed_metadata, ..
            } => signed_metadata,
            other => panic!("expected RunAgentCompleted, got {other:?}"),
        };
        assert_eq!(signed_metadata.exit_code, 1);
        // `/bin/false` writes nothing on either stream. The hash binds
        // the canonical bytes of the *envelope wrapping* those empty
        // streams, not the empty string — re-derive that here.
        let empty_envelope = OutputEnvelope {
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        assert_eq!(
            signed_metadata.output_envelope_sha256.as_str(),
            crate::agent_run::sha256_hex(&empty_envelope.to_bytes()),
        );
    }

    /// Stderr from the agent must reach the signed envelope verbatim.
    /// A child whose diagnostics land on stderr (the common case for
    /// non-zero exits) would otherwise produce a signed note that
    /// silently elides them — exactly the issue Codex flagged in the
    /// stderr-discard P2. We drive the path here with a one-liner
    /// shell that writes a known string to each stream, then decode
    /// the on-disk envelope and assert both came through.
    #[tokio::test]
    async fn run_agent_captures_stderr_in_envelope() {
        use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
        use crate::signing::WritSigningKey;

        const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");

        let tmp = tempfile::tempdir().unwrap();
        let notes_repo = NotesRepo::init_or_open(tmp.path().join("repo")).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let sh = find_in_path_any(&["sh", "bash"]);

        let server = MockServer::start().await;
        let base = Arc::try_unwrap(make_state(&server, vec![], "o"))
            .unwrap_or_else(|_| panic!("make_state Arc must be uniquely held"));
        let state = Arc::new(BrokerState {
            audit: base.audit,
            minter: base.minter,
            secrets: base.secrets,
            policy: base.policy,
            staging_store: base.staging_store,
            notes_repo: Some(Arc::new(notes_repo)),
            signing_key: Some(signing_key),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: sh,
                args: vec!["-c".into(), "printf out; printf err 1>&2; exit 0".into()],
            }),
            promote_runtime: base.promote_runtime,
        });

        let output_ref =
            crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
        let resp = dispatch_message(
            ClientMessage::RunAgent {
                prompt: crate::agent_run::AgentPrompt::new("ignored"),
                capabilities: Vec::new(),
                purpose: "stderr-capture".into(),
                output_ref: output_ref.clone(),
                session_id: None,
                workspace: None,
                agent_kind: None,
                agent_model: None,
            },
            &state,
        )
        .await;

        let (output_oid, signed_metadata) = match resp {
            ServerMessage::RunAgentCompleted {
                output_oid,
                signed_metadata,
                ..
            } => (output_oid, signed_metadata),
            other => panic!("expected RunAgentCompleted, got {other:?}"),
        };

        let notes_repo_handle = state.notes_repo.as_ref().unwrap().clone();
        let body = tokio::task::spawn_blocking({
            let output_ref = output_ref.clone();
            let oid = output_oid.clone();
            move || notes_repo_handle.read_note(&output_ref, &oid)
        })
        .await
        .unwrap()
        .unwrap();
        let envelope = SignedRunEnvelope::from_bytes(&body).unwrap();
        let output_envelope = OutputEnvelope::from_bytes(&envelope.output).unwrap();
        assert_eq!(output_envelope.stdout, b"out");
        assert_eq!(output_envelope.stderr, b"err");
        assert_eq!(output_envelope.stdout_truncated_at, None);
        assert_eq!(output_envelope.stderr_truncated_at, None);
        // The metadata hash must bind the actual envelope bytes — if
        // stderr were silently dropped before hashing, this assertion
        // would survive but a verifier re-deriving the digest would
        // see a mismatch. Re-derive it from the encoded envelope here.
        assert_eq!(
            signed_metadata.output_envelope_sha256.as_str(),
            crate::agent_run::sha256_hex(&envelope.output),
        );
    }

    /// Capture beyond the per-stream cap must be silently dropped and
    /// the `truncated_at` marker must record the cap offset.
    /// Verifies the bounded-buffer fix end-to-end: a child that emits
    /// more than the cap allows does not balloon writd's memory, and
    /// the signed envelope honestly reports the partial capture.
    #[tokio::test]
    async fn run_agent_caps_stream_capture_records_truncation() {
        use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
        use crate::signing::WritSigningKey;

        const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");

        let tmp = tempfile::tempdir().unwrap();
        let notes_repo = NotesRepo::init_or_open(tmp.path().join("repo")).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let sh = find_in_path_any(&["sh", "bash"]);

        let server = MockServer::start().await;
        let base = Arc::try_unwrap(make_state(&server, vec![], "o"))
            .unwrap_or_else(|_| panic!("make_state Arc must be uniquely held"));
        let state = Arc::new(BrokerState {
            audit: base.audit,
            minter: base.minter,
            secrets: base.secrets,
            policy: base.policy,
            staging_store: base.staging_store,
            notes_repo: Some(Arc::new(notes_repo)),
            signing_key: Some(signing_key),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: sh,
                // Emit MAX_RUN_AGENT_STREAM_BYTES + 1 KiB of stdout so
                // the cap path runs without depending on shell-builtin
                // performance for many megabytes of output. dd with a
                // 1 MiB block size and (cap_mib + 1 / 1024) reps would
                // be tidier, but `head -c` from /dev/zero is portable
                // across BSD and GNU userland.
                args: vec![
                    "-c".into(),
                    format!("head -c {} /dev/zero", MAX_RUN_AGENT_STREAM_BYTES + 1024),
                ],
            }),
            promote_runtime: base.promote_runtime,
        });

        let output_ref =
            crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
        let resp = dispatch_message(
            ClientMessage::RunAgent {
                prompt: crate::agent_run::AgentPrompt::new("ignored"),
                capabilities: Vec::new(),
                purpose: "truncation".into(),
                output_ref: output_ref.clone(),
                session_id: None,
                workspace: None,
                agent_kind: None,
                agent_model: None,
            },
            &state,
        )
        .await;

        let output_oid = match resp {
            ServerMessage::RunAgentCompleted { output_oid, .. } => output_oid,
            other => panic!("expected RunAgentCompleted, got {other:?}"),
        };

        let notes_repo_handle = state.notes_repo.as_ref().unwrap().clone();
        let body = tokio::task::spawn_blocking({
            let output_ref = output_ref.clone();
            let oid = output_oid.clone();
            move || notes_repo_handle.read_note(&output_ref, &oid)
        })
        .await
        .unwrap()
        .unwrap();
        let envelope = SignedRunEnvelope::from_bytes(&body).unwrap();
        let output_envelope = OutputEnvelope::from_bytes(&envelope.output).unwrap();
        assert_eq!(output_envelope.stdout.len(), MAX_RUN_AGENT_STREAM_BYTES);
        assert_eq!(
            output_envelope.stdout_truncated_at,
            Some(MAX_RUN_AGENT_STREAM_BYTES as u64),
        );
        assert!(output_envelope.stderr.is_empty());
        assert_eq!(output_envelope.stderr_truncated_at, None);
    }

    /// When `RunAgent` carries a `session_id` bound to an open audit
    /// session, the signed metadata stamps the same id. This is the
    /// producer-side half of the slice-C session model (2026-05-16):
    /// bailiff opens a per-run session, threads the id into
    /// `RunAgent`, and the signed envelope correlates with the audit
    /// row so verifiers can recover the run-level authority window.
    #[tokio::test]
    async fn run_agent_stamps_caller_supplied_session_id_into_signed_metadata() {
        use crate::core::SessionRecord;
        use crate::signing::WritSigningKey;

        const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");

        let tmp = tempfile::tempdir().unwrap();
        let notes_repo = NotesRepo::init_or_open(tmp.path().join("repo")).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");
        let server = MockServer::start().await;
        let base = Arc::try_unwrap(make_state(&server, vec![], "o"))
            .unwrap_or_else(|_| panic!("make_state Arc must be uniquely held"));
        let state = Arc::new(BrokerState {
            audit: base.audit,
            minter: base.minter,
            secrets: base.secrets,
            policy: base.policy,
            staging_store: base.staging_store,
            notes_repo: Some(Arc::new(notes_repo)),
            signing_key: Some(signing_key),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: cat,
                args: Vec::new(),
            }),
            promote_runtime: base.promote_runtime,
        });

        let session_id = SessionId::new();
        state
            .audit
            .open_session(&SessionRecord {
                session_id,
                label: Some("plan-submit".into()),
                agent_kind: Some(AgentKind::Claude),
                agent_model: None,
                opened_at: UnixMillis::now(),
                closed_at: None,
            })
            .expect("open audit session");

        let resp = dispatch_message(
            ClientMessage::RunAgent {
                prompt: crate::agent_run::AgentPrompt::new("hi"),
                capabilities: Vec::new(),
                purpose: "bound-session".into(),
                output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs")
                    .unwrap(),
                session_id: Some(session_id),
                workspace: None,
                agent_kind: None,
                agent_model: None,
            },
            &state,
        )
        .await;
        let signed_metadata = match resp {
            ServerMessage::RunAgentCompleted {
                signed_metadata, ..
            } => signed_metadata,
            other => panic!("expected RunAgentCompleted, got {other:?}"),
        };
        assert_eq!(
            signed_metadata.session_id, session_id,
            "signed metadata must stamp the caller-supplied session id",
        );
    }

    /// `RunAgent` against an unknown `session_id` (one that's never
    /// been opened) is rejected with `UnknownSession` before the agent
    /// is spawned. A signed envelope claiming an unreachable session
    /// would be worse than a clear refusal.
    #[tokio::test]
    async fn run_agent_rejects_unknown_session_id() {
        use crate::signing::WritSigningKey;

        const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");

        let tmp = tempfile::tempdir().unwrap();
        let notes_repo = NotesRepo::init_or_open(tmp.path().join("repo")).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");
        let server = MockServer::start().await;
        let base = Arc::try_unwrap(make_state(&server, vec![], "o"))
            .unwrap_or_else(|_| panic!("make_state Arc must be uniquely held"));
        let state = Arc::new(BrokerState {
            audit: base.audit,
            minter: base.minter,
            secrets: base.secrets,
            policy: base.policy,
            staging_store: base.staging_store,
            notes_repo: Some(Arc::new(notes_repo)),
            signing_key: Some(signing_key),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: cat,
                args: Vec::new(),
            }),
            promote_runtime: base.promote_runtime,
        });

        let bogus = SessionId::new();
        let resp = dispatch_message(
            ClientMessage::RunAgent {
                prompt: crate::agent_run::AgentPrompt::new("hi"),
                capabilities: Vec::new(),
                purpose: "unknown-session".into(),
                output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs")
                    .unwrap(),
                session_id: Some(bogus),
                workspace: None,
                agent_kind: None,
                agent_model: None,
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::UnknownSession { session_id } => assert_eq!(session_id, bogus),
            other => panic!("expected UnknownSession, got {other:?}"),
        }
    }

    /// `RunAgent` against a session that's already been closed is
    /// rejected with `ClosedSession`. Reusing a workflow's session id
    /// after the workflow ended would otherwise produce envelopes
    /// stamped with a session the audit log says is dead.
    #[tokio::test]
    async fn run_agent_rejects_closed_session_id() {
        use crate::core::SessionRecord;
        use crate::signing::WritSigningKey;

        const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");

        let tmp = tempfile::tempdir().unwrap();
        let notes_repo = NotesRepo::init_or_open(tmp.path().join("repo")).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");
        let server = MockServer::start().await;
        let base = Arc::try_unwrap(make_state(&server, vec![], "o"))
            .unwrap_or_else(|_| panic!("make_state Arc must be uniquely held"));
        let state = Arc::new(BrokerState {
            audit: base.audit,
            minter: base.minter,
            secrets: base.secrets,
            policy: base.policy,
            staging_store: base.staging_store,
            notes_repo: Some(Arc::new(notes_repo)),
            signing_key: Some(signing_key),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: cat,
                args: Vec::new(),
            }),
            promote_runtime: base.promote_runtime,
        });

        let session_id = SessionId::new();
        state
            .audit
            .open_session(&SessionRecord {
                session_id,
                label: None,
                agent_kind: Some(AgentKind::Claude),
                agent_model: None,
                opened_at: UnixMillis::now(),
                closed_at: None,
            })
            .unwrap();
        state
            .audit
            .close_session(session_id, UnixMillis::now())
            .unwrap();

        let resp = dispatch_message(
            ClientMessage::RunAgent {
                prompt: crate::agent_run::AgentPrompt::new("hi"),
                capabilities: Vec::new(),
                purpose: "closed-session".into(),
                output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs")
                    .unwrap(),
                session_id: Some(session_id),
                workspace: None,
                agent_kind: None,
                agent_model: None,
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::ClosedSession { session_id: seen } => assert_eq!(seen, session_id),
            other => panic!("expected ClosedSession, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn agent_vm_messages_fail_when_runtime_is_not_configured() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");

        let start = dispatch_message(
            ClientMessage::StartAgentVm {
                label: None,
                agent_kind: Some(AgentKind::Claude),
                agent_model: None,
                workspace: None,
                guest_command: vec!["true".into()],
            },
            &state,
        )
        .await;
        assert_eq!(
            start,
            ServerMessage::Error {
                message: "agent VM runtime is not configured".into()
            }
        );

        let stop = dispatch_message(
            ClientMessage::StopAgentVm {
                session_id: "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
            },
            &state,
        )
        .await;
        assert_eq!(
            stop,
            ServerMessage::Error {
                message: "agent VM runtime is not configured".into()
            }
        );

        let list = dispatch_message(ClientMessage::ListAgentVms {}, &state).await;
        assert_eq!(
            list,
            ServerMessage::Error {
                message: "agent VM runtime is not configured".into()
            }
        );
    }

    // --- Staged-push listing / show -------------------------------------

    /// Build a `BrokerState` whose `staging_store` points at a fresh temp
    /// directory. Returned alongside the `TempDir` so the caller keeps the
    /// staging root alive for the duration of the test.
    fn make_state_with_staging(
        server: &MockServer,
    ) -> (Arc<BrokerState<InMemStore>>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = GitPushStagingStore::open(tmp.path().join("staging")).unwrap();
        // Installation owner matches `sample_clone_repo()`'s "owner/repo"
        // so the minter's repository-belongs-to-installation check
        // passes when an approve test reaches the mint step. Tests that
        // don't mint are unaffected by the owner string.
        let mut state = make_state(server, vec![], "owner");
        let inner = Arc::get_mut(&mut state).expect("fresh Arc has no other handles");
        inner.staging_store = Some(Arc::new(store));
        (state, tmp)
    }

    /// `make_state_with_staging` extended with the two extra pieces an
    /// approve handler needs to reach its load step: a
    /// [`PromoteRuntimeConfig`] (built against a fake git binary path
    /// and a per-test work_root under the same tempdir as staging) and
    /// a [`WritSigningKey`] (from the shared fixture). The fake git
    /// path is deliberately unused in slice B1e.2c — this slice never
    /// spawns git, it only proves the configured-state guards admit a
    /// well-formed request through to the load. B1e.2d/2e will swap in
    /// the system git for the integration tests that actually fetch
    /// and unbundle.
    fn make_state_with_approve_ready(
        server: &MockServer,
    ) -> (Arc<BrokerState<InMemStore>>, tempfile::TempDir) {
        use crate::git_push_promote::PromoteRuntimeConfig;
        use crate::signing::WritSigningKey;
        use crate::vm_git_bundle::{GitCloneBaseUrl, GitCredentialBoundary, GitSecretEnvVar};
        const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");

        let (mut state, tmp) = make_state_with_staging(server);
        let work_root = tmp.path().join("promote");
        std::fs::create_dir_all(&work_root).unwrap();
        let runtime = PromoteRuntimeConfig::new(
            // Slice B1e.2c never spawns git; the fake path is fine
            // and is replaced by `which git` in the follow-up slices.
            PathBuf::from("/nonexistent/bin/git"),
            GitCloneBaseUrl::github(),
            GitCredentialBoundary::new(
                PathBuf::from("/nonexistent/bin/askpass"),
                GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap(),
            )
            .unwrap(),
            work_root,
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();

        let inner = Arc::get_mut(&mut state).expect("fresh Arc has no other handles");
        inner.promote_runtime = Some(Arc::new(runtime));
        inner.signing_key = Some(signing_key);
        (state, tmp)
    }

    fn sample_clone_repo() -> crate::vm_git::GitCloneRepo {
        "owner/repo".parse().unwrap()
    }

    fn sample_branch() -> crate::vm_git::GitBranchName {
        "feature/x".parse().unwrap()
    }

    fn sample_object_id(nibble: char) -> crate::vm_git::GitObjectId {
        std::iter::repeat_n(nibble, 40)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    /// Mirror of the same-named helper in `audit::git_push::tests`; the
    /// values aren't significant — the tests that consume this just
    /// need a `PromoteMintAudit` whose shape passes the DAO's column
    /// checks when transitioning an attempt to `Uncertain`.
    fn sample_promote_mint_audit() -> PromoteMintAudit {
        PromoteMintAudit {
            jti: crate::core::Jti::new(),
            github_app_id: 42,
            issued_at: UnixMillis::from_millis(1_700_000_190),
            expires_at: UnixMillis::from_millis(1_700_000_490),
        }
    }

    /// Stage a push on disk *and* record the matching audit row plus a
    /// `Staged` outcome row so the resolution trigger admits operator
    /// decisions against the resulting request id. Returns the request id.
    async fn stage_with_staged_outcome(
        state: &Arc<BrokerState<InMemStore>>,
        session_id: SessionId,
        bundle: Vec<u8>,
        staged_at: UnixMillis,
        received_at: UnixMillis,
    ) -> RequestId {
        let request_id = stage_with_audit(state, session_id, bundle, staged_at, received_at).await;
        state
            .audit
            .record_git_push_outcome(&crate::audit::GitPushOutcomeRecord {
                push_request_id: request_id,
                completed_at: received_at,
                result: crate::audit::GitPushOutcomeResult::Staged,
                github_status: None,
                message: "staged for operator review",
            })
            .unwrap();
        request_id
    }

    /// Stage a push on disk *and* record the matching audit row so the
    /// joined Show view has both halves available. Returns the request id.
    async fn stage_with_audit(
        state: &Arc<BrokerState<InMemStore>>,
        session_id: SessionId,
        bundle: Vec<u8>,
        staged_at: UnixMillis,
        received_at: UnixMillis,
    ) -> RequestId {
        let request_id = RequestId::new();
        let metadata = crate::vm_git::VmGitPushMetadata::new(
            sample_clone_repo(),
            sample_branch(),
            Some(sample_object_id('a')),
            sample_object_id('b'),
        );
        let staging = state
            .staging_store
            .as_ref()
            .expect("staging configured")
            .clone();
        let bundle_for_stage = bundle.clone();
        tokio::task::spawn_blocking(move || {
            staging
                .stage(request_id, staged_at, metadata, bundle_for_stage)
                .unwrap();
        })
        .await
        .unwrap();
        state
            .audit
            .record_git_push_request(&crate::audit::GitPushRequestRecord {
                push_request_id: request_id,
                session_id,
                received_at,
                repo: sample_clone_repo(),
                branch: sample_branch(),
                expected_remote_head: Some(sample_object_id('a')),
                new_head: sample_object_id('b'),
                correlation_id: None,
            })
            .unwrap();
        request_id
    }

    #[tokio::test]
    async fn list_staged_pushes_without_staging_configured_returns_error() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let resp =
            dispatch_message(ClientMessage::ListStagedPushes { session_id: None }, &state).await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("staging"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Same staging-absent error path on the filtered request: the
    /// session_id filter must not change *which* errors the broker
    /// returns, only which entries it keeps on the success path.
    #[tokio::test]
    async fn list_staged_pushes_with_session_filter_without_staging_configured_returns_error() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let resp = dispatch_message(
            ClientMessage::ListStagedPushes {
                session_id: Some(SessionId::new()),
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("staging"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_staged_pushes_with_empty_store_returns_empty_list() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let resp =
            dispatch_message(ClientMessage::ListStagedPushes { session_id: None }, &state).await;
        assert_eq!(resp, ServerMessage::StagedPushes { pushes: vec![] });
    }

    #[tokio::test]
    async fn list_staged_pushes_returns_summary_for_each_staged_entry() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;

        let id_a = stage_with_audit(
            &state,
            session_id,
            b"bundle-a".to_vec(),
            UnixMillis::from_millis(1_700_000_001_000),
            UnixMillis::from_millis(1_700_000_001_500),
        )
        .await;
        let id_b = stage_with_audit(
            &state,
            session_id,
            b"bundle-b".to_vec(),
            UnixMillis::from_millis(1_700_000_002_000),
            UnixMillis::from_millis(1_700_000_002_500),
        )
        .await;

        let resp =
            dispatch_message(ClientMessage::ListStagedPushes { session_id: None }, &state).await;
        let mut pushes = match resp {
            ServerMessage::StagedPushes { pushes } => pushes,
            other => panic!("expected StagedPushes, got {other:?}"),
        };
        pushes.sort_by_key(|p| p.staged_at);
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0].push_request_id, id_a);
        assert_eq!(pushes[0].staged_at.as_millis(), 1_700_000_001_000);
        assert_eq!(pushes[1].push_request_id, id_b);
        assert_eq!(pushes[1].staged_at.as_millis(), 1_700_000_002_000);
    }

    /// Filtering by `session_id` returns only the staged pushes recorded
    /// under that session in the audit log. Witnesses the core join:
    /// pushes from a sibling session never appear in the result.
    #[tokio::test]
    async fn list_staged_pushes_with_session_filter_returns_only_matching_pushes() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_a = open_session(&state).await;
        let session_b = open_session(&state).await;

        let id_a1 = stage_with_audit(
            &state,
            session_a,
            b"a1".to_vec(),
            UnixMillis::from_millis(1_700_000_001_000),
            UnixMillis::from_millis(1_700_000_001_500),
        )
        .await;
        let id_a2 = stage_with_audit(
            &state,
            session_a,
            b"a2".to_vec(),
            UnixMillis::from_millis(1_700_000_002_000),
            UnixMillis::from_millis(1_700_000_002_500),
        )
        .await;
        let id_b1 = stage_with_audit(
            &state,
            session_b,
            b"b1".to_vec(),
            UnixMillis::from_millis(1_700_000_003_000),
            UnixMillis::from_millis(1_700_000_003_500),
        )
        .await;

        let resp = dispatch_message(
            ClientMessage::ListStagedPushes {
                session_id: Some(session_a),
            },
            &state,
        )
        .await;
        let mut pushes = match resp {
            ServerMessage::StagedPushes { pushes } => pushes,
            other => panic!("expected StagedPushes, got {other:?}"),
        };
        pushes.sort_by_key(|p| p.staged_at);
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0].push_request_id, id_a1);
        assert_eq!(pushes[1].push_request_id, id_a2);

        // Sibling session sees only its own push, not session_a's two.
        let resp = dispatch_message(
            ClientMessage::ListStagedPushes {
                session_id: Some(session_b),
            },
            &state,
        )
        .await;
        let pushes = match resp {
            ServerMessage::StagedPushes { pushes } => pushes,
            other => panic!("expected StagedPushes, got {other:?}"),
        };
        assert_eq!(pushes.len(), 1);
        assert_eq!(pushes[0].push_request_id, id_b1);

        // And the unfiltered listing still returns all three: filtering
        // is an opt-in narrowing, not a hidden default.
        let resp =
            dispatch_message(ClientMessage::ListStagedPushes { session_id: None }, &state).await;
        let pushes = match resp {
            ServerMessage::StagedPushes { pushes } => pushes,
            other => panic!("expected StagedPushes, got {other:?}"),
        };
        assert_eq!(pushes.len(), 3);
    }

    /// Filter by a session that has no push rows in the audit log
    /// (e.g. a session that was opened but never staged a push, or an
    /// id that does not exist at all). The broker returns an empty
    /// list rather than an error: "no rows matched the filter" is a
    /// successful empty listing.
    #[tokio::test]
    async fn list_staged_pushes_with_session_filter_for_unknown_session_returns_empty() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);

        // Seed the staging store with one push under a different
        // session so we can witness it is excluded by the unknown-
        // session filter.
        let other = open_session(&state).await;
        stage_with_audit(
            &state,
            other,
            b"other".to_vec(),
            UnixMillis::from_millis(1_700_000_001_000),
            UnixMillis::from_millis(1_700_000_001_500),
        )
        .await;

        let resp = dispatch_message(
            ClientMessage::ListStagedPushes {
                session_id: Some(SessionId::new()),
            },
            &state,
        )
        .await;
        assert_eq!(resp, ServerMessage::StagedPushes { pushes: vec![] });
    }

    /// Staging entries that lack a matching audit row (e.g. an orphan
    /// directory left over from a crash between `staging_store.stage`
    /// and `record_git_push_request`) must be excluded by the session
    /// filter even when the operator filters by a "real" session id.
    /// The audit log is the source of truth for the
    /// staged-push ↔ session mapping; an orphan staging directory has no
    /// session.
    #[tokio::test]
    async fn list_staged_pushes_with_session_filter_excludes_orphan_staging() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;

        // One legitimate staged push under `session_id`.
        let real = stage_with_audit(
            &state,
            session_id,
            b"real".to_vec(),
            UnixMillis::from_millis(1_700_000_001_000),
            UnixMillis::from_millis(1_700_000_001_500),
        )
        .await;

        // One staging-only entry with no audit row.
        let orphan_request_id = RequestId::new();
        let metadata = crate::vm_git::VmGitPushMetadata::new(
            sample_clone_repo(),
            sample_branch(),
            None,
            sample_object_id('c'),
        );
        let staging = state.staging_store.as_ref().unwrap().clone();
        tokio::task::spawn_blocking(move || {
            staging
                .stage(
                    orphan_request_id,
                    UnixMillis::from_millis(1_700_000_002_000),
                    metadata,
                    b"orphan".to_vec(),
                )
                .unwrap();
        })
        .await
        .unwrap();

        let resp = dispatch_message(
            ClientMessage::ListStagedPushes {
                session_id: Some(session_id),
            },
            &state,
        )
        .await;
        let pushes = match resp {
            ServerMessage::StagedPushes { pushes } => pushes,
            other => panic!("expected StagedPushes, got {other:?}"),
        };
        assert_eq!(pushes.len(), 1);
        assert_eq!(pushes[0].push_request_id, real);
        // Sanity: the unfiltered listing still surfaces the orphan,
        // since unfiltered listing reflects on-disk staging only and
        // not the audit DB. Today the `show` endpoint will surface the
        // orphan as an error; that contract is unchanged.
        let resp =
            dispatch_message(ClientMessage::ListStagedPushes { session_id: None }, &state).await;
        let pushes = match resp {
            ServerMessage::StagedPushes { pushes } => pushes,
            other => panic!("expected StagedPushes, got {other:?}"),
        };
        assert_eq!(pushes.len(), 2);
    }

    /// Codex R4 P2: a session-filtered listing must not be broken by an
    /// unrelated malformed staging dir. The audit log names the request
    /// ids that belong to the session, and we load only those — so a
    /// corrupt sibling dir (e.g. left by external tampering or an
    /// interrupted write) is invisible to the filtered call.
    #[tokio::test]
    async fn list_staged_pushes_with_session_filter_ignores_unrelated_malformed_dir() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;

        let real = stage_with_audit(
            &state,
            session_id,
            b"real".to_vec(),
            UnixMillis::from_millis(1_700_000_010_000),
            UnixMillis::from_millis(1_700_000_010_500),
        )
        .await;

        // Drop a malformed directory into the staging root that has no
        // audit row and a name we never look up. Pre-fix this would
        // make `staging_store.list()` fail and surface as an error from
        // the filtered call.
        let staging_root = state.staging_store.as_ref().unwrap().root().to_path_buf();
        tokio::task::spawn_blocking(move || {
            let bogus = staging_root.join("staged").join("not-a-uuid");
            std::fs::create_dir_all(&bogus).unwrap();
        })
        .await
        .unwrap();

        let resp = dispatch_message(
            ClientMessage::ListStagedPushes {
                session_id: Some(session_id),
            },
            &state,
        )
        .await;
        let pushes = match resp {
            ServerMessage::StagedPushes { pushes } => pushes,
            other => panic!("expected StagedPushes, got {other:?}"),
        };
        assert_eq!(pushes.len(), 1);
        assert_eq!(pushes[0].push_request_id, real);
    }

    #[tokio::test]
    async fn show_staged_push_without_staging_configured_returns_error() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let resp = dispatch_message(
            ClientMessage::ShowStagedPush {
                request_id: RequestId::new(),
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("staging"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn show_staged_push_for_unknown_request_id_returns_unknown_staged_push() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let request_id = RequestId::new();
        let resp = dispatch_message(ClientMessage::ShowStagedPush { request_id }, &state).await;
        assert_eq!(resp, ServerMessage::UnknownStagedPush { request_id });
    }

    #[tokio::test]
    async fn show_staged_push_returns_detail_joining_staging_and_audit() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;

        let staged_at = UnixMillis::from_millis(1_700_000_500_000);
        let received_at = UnixMillis::from_millis(1_700_000_500_250);
        let bundle = b"PACK bundle payload".to_vec();
        let request_id =
            stage_with_audit(&state, session_id, bundle.clone(), staged_at, received_at).await;

        let resp = dispatch_message(ClientMessage::ShowStagedPush { request_id }, &state).await;
        let push = match resp {
            ServerMessage::StagedPush { push } => push,
            other => panic!("expected StagedPush, got {other:?}"),
        };
        assert_eq!(push.summary.push_request_id, request_id);
        assert_eq!(push.summary.staged_at, staged_at);
        assert_eq!(push.bundle_bytes, bundle.len() as u64);
        assert_eq!(push.audit.session_id, session_id);
        assert_eq!(push.audit.received_at, received_at);
        // No outcome row recorded → audit.result stays None.
        assert_eq!(push.audit.result, None);
    }

    /// If the on-disk staging entry has no matching audit row, the
    /// broker must surface that as an Error rather than fabricating a
    /// `received_at`. This protects the audit-chain invariant that
    /// every staged push has a request row.
    #[tokio::test]
    async fn show_staged_push_with_orphan_staging_returns_error() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);

        let request_id = RequestId::new();
        let metadata = crate::vm_git::VmGitPushMetadata::new(
            sample_clone_repo(),
            sample_branch(),
            None,
            sample_object_id('c'),
        );
        let staging = state.staging_store.as_ref().unwrap().clone();
        tokio::task::spawn_blocking(move || {
            staging
                .stage(
                    request_id,
                    UnixMillis::from_millis(1),
                    metadata,
                    b"orphan".to_vec(),
                )
                .unwrap();
        })
        .await
        .unwrap();

        let resp = dispatch_message(ClientMessage::ShowStagedPush { request_id }, &state).await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("no audit record"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // --- Staged-push reject ---------------------------------------------

    fn reason(text: &str) -> RejectionReason {
        RejectionReason::try_new(text).expect("test reason fits the bound")
    }

    #[tokio::test]
    async fn reject_staged_push_without_staging_configured_returns_error() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let resp = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id: RequestId::new(),
                operator: "alice".into(),
                reason: reason("nope"),
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("staging"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reject_staged_push_with_unknown_request_returns_unknown_staged_push() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let request_id = RequestId::new();
        let resp = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id,
                operator: "alice".into(),
                reason: reason("not staged"),
            },
            &state,
        )
        .await;
        assert_eq!(resp, ServerMessage::UnknownStagedPush { request_id });
    }

    #[tokio::test]
    async fn reject_staged_push_happy_path_records_audit_and_deletes_staging() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_000_010_000),
            UnixMillis::from_millis(1_700_000_010_500),
        )
        .await;

        let resp = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id,
                operator: "alice".into(),
                reason: reason("contains a secret"),
            },
            &state,
        )
        .await;

        assert_eq!(resp, ServerMessage::StagedPushRejected { request_id });

        // Audit row is present with the right shape.
        let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
        let resolution = audit_entry
            .resolution
            .expect("resolution row recorded after reject");
        assert_eq!(resolution.decision, GitPushResolution::Rejected);
        assert_eq!(resolution.operator, "alice");
        assert_eq!(resolution.reason, "contains a secret");

        // Staging directory is gone; a follow-up reject sees UnknownStagedPush.
        let follow_up = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id,
                operator: "alice".into(),
                reason: reason("retry"),
            },
            &state,
        )
        .await;
        assert_eq!(follow_up, ServerMessage::UnknownStagedPush { request_id });
    }

    /// A second reject after an existing `Rejected` row returns
    /// `AlreadyResolved` (the audit row was not authored by this call),
    /// and — critically — opportunistically cleans up the staging dir
    /// so a failed first-cleanup doesn't leave the entry stuck. The
    /// original audit row is not overwritten.
    #[tokio::test]
    async fn reject_staged_push_already_resolved_path_retries_cleanup() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_000_020_000),
            UnixMillis::from_millis(1_700_000_020_500),
        )
        .await;

        // Record the operator decision out-of-band so the staging dir is
        // still on disk when dispatch sees the PK violation — the exact
        // shape of "first reject's cleanup failed".
        state
            .audit
            .record_git_push_resolution(&GitPushResolutionRecord {
                push_request_id: request_id,
                decided_at: UnixMillis::from_millis(1_700_000_021_000),
                decision: GitPushResolution::Rejected,
                operator: "alice",
                reason: "first decision",
            })
            .unwrap();
        assert!(
            state
                .staging_store
                .as_ref()
                .unwrap()
                .load(request_id)
                .is_ok()
        );

        let resp = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id,
                operator: "bob".into(),
                reason: reason("second decision"),
            },
            &state,
        )
        .await;

        assert_eq!(
            resp,
            ServerMessage::StagedPushAlreadyResolved { request_id }
        );

        // Original audit row must be untouched.
        let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
        let resolution = audit_entry.resolution.expect("first decision still there");
        assert_eq!(resolution.operator, "alice");
        assert_eq!(resolution.reason, "first decision");

        // Staging dir was cleaned up on the retry path so the entry no
        // longer shows in `promote list`.
        match state.staging_store.as_ref().unwrap().load(request_id) {
            Err(StagingError::NotFound { .. }) => {}
            other => panic!("expected staging cleanup, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reject_staged_push_with_empty_operator_returns_error() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let resp = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id: RequestId::new(),
                operator: String::new(),
                reason: reason("nope"),
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("operator"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reject_staged_push_with_oversize_operator_returns_error() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let oversized = "a".repeat(MAX_OPERATOR_BYTES + 1);
        let resp = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id: RequestId::new(),
                operator: oversized,
                reason: reason("nope"),
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("operator"), "got: {message}");
                assert!(message.contains("byte"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// If somehow the audit log has a request row but no `Staged` outcome
    /// (e.g. broker crashed mid-stage and resumed without re-recording),
    /// the v13 trigger keeps the resolution table consistent by refusing
    /// the insert. The broker surfaces this as a plain Error rather than
    /// `StagedPushAlreadyResolved`, since no prior decision exists.
    #[tokio::test]
    async fn reject_staged_push_without_staged_outcome_returns_error() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        // Note: stage_with_audit records the request row but no outcome row.
        let request_id = stage_with_audit(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_000_030_000),
            UnixMillis::from_millis(1_700_000_030_500),
        )
        .await;

        let resp = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id,
                operator: "alice".into(),
                reason: reason("trigger should refuse"),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { .. } => {}
            other => panic!("expected Error, got {other:?}"),
        }

        // Staging directory must still be present: the audit insert failed
        // before commit-then-delete could touch the filesystem.
        assert!(
            state
                .staging_store
                .as_ref()
                .unwrap()
                .load(request_id)
                .is_ok()
        );
    }

    /// A `Started` attempt blocks reject: the broker has committed to an
    /// approve in flight but hasn't yet reached the PATCH boundary.
    /// Surfacing the typed diagnostic (with the attempt_id and an
    /// actionable hint) is the point of this slice — the raw trigger
    /// ABORT text is opaque to the operator.
    #[tokio::test]
    async fn reject_staged_push_with_started_attempt_refuses_with_in_flight_diagnostic() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_001_010_000),
            UnixMillis::from_millis(1_700_001_010_500),
        )
        .await;
        let attempt_id = ApproveAttemptId::new();
        state
            .audit
            .start_approve_attempt(
                attempt_id,
                request_id,
                "alice",
                UnixMillis::from_millis(1_700_001_011_000),
            )
            .unwrap();

        let resp = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id,
                operator: "bob".into(),
                reason: reason("racing reject"),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains(&attempt_id.to_string()),
                    "expected attempt id in diagnostic, got: {message}",
                );
                assert!(
                    message.contains("in flight"),
                    "expected 'in flight' phrasing, got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // No resolution row should have been written; the attempt
        // remains `Started` and the staging dir is still on disk.
        let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
        assert!(audit_entry.resolution.is_none());
        assert!(
            state
                .staging_store
                .as_ref()
                .unwrap()
                .load(request_id)
                .is_ok()
        );
    }

    /// Same shape as the `Started` case but the attempt has advanced to
    /// `Uncertain` — the broker may have issued the PATCH but not yet
    /// confirmed it. Reject is still refused with the in-flight
    /// diagnostic; the operator waits for the attempt to resolve.
    #[tokio::test]
    async fn reject_staged_push_with_uncertain_attempt_refuses_with_in_flight_diagnostic() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_001_020_000),
            UnixMillis::from_millis(1_700_001_020_500),
        )
        .await;
        let attempt_id = ApproveAttemptId::new();
        state
            .audit
            .start_approve_attempt(
                attempt_id,
                request_id,
                "alice",
                UnixMillis::from_millis(1_700_001_021_000),
            )
            .unwrap();
        state
            .audit
            .mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
            .unwrap();

        let resp = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id,
                operator: "bob".into(),
                reason: reason("racing reject"),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains(&attempt_id.to_string()),
                    "expected attempt id in diagnostic, got: {message}",
                );
                assert!(
                    message.contains("in flight"),
                    "expected 'in flight' phrasing, got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }

        let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
        assert!(audit_entry.resolution.is_none());
    }

    /// A `Resolved(Succeeded)` attempt is the joint-TX outcome: the
    /// resolution row is already present alongside the attempt row.
    /// Reject must reuse the existing already-resolved path so the
    /// operator gets the same surface that a duplicate reject produces,
    /// and so the staging dir cleanup retries on this call.
    #[tokio::test]
    async fn reject_staged_push_with_succeeded_attempt_returns_already_resolved() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_001_030_000),
            UnixMillis::from_millis(1_700_001_030_500),
        )
        .await;
        let attempt_id = ApproveAttemptId::new();
        state
            .audit
            .start_approve_attempt(
                attempt_id,
                request_id,
                "alice",
                UnixMillis::from_millis(1_700_001_031_000),
            )
            .unwrap();
        state
            .audit
            .mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
            .unwrap();
        state
            .audit
            .complete_attempt_succeeded(
                attempt_id,
                &sample_object_id('a'),
                "alice",
                "promoted by test",
                UnixMillis::from_millis(1_700_001_032_000),
            )
            .unwrap();
        // The joint TX wrote the resolution row alongside the attempt.
        let before = state.audit.get_git_push(request_id).unwrap().unwrap();
        assert!(before.resolution.is_some());

        let resp = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id,
                operator: "bob".into(),
                reason: reason("late reject"),
            },
            &state,
        )
        .await;

        assert_eq!(
            resp,
            ServerMessage::StagedPushAlreadyResolved { request_id }
        );

        // Original (approved) resolution row is untouched.
        let after = state.audit.get_git_push(request_id).unwrap().unwrap();
        let resolution = after.resolution.expect("resolution row remains");
        assert!(
            matches!(resolution.decision, GitPushResolution::Approved(_)),
            "expected approved decision, got {:?}",
            resolution.decision,
        );
        assert_eq!(resolution.operator, "alice");

        // The retry-cleanup path ran: staging dir is gone.
        match state.staging_store.as_ref().unwrap().load(request_id) {
            Err(StagingError::NotFound { .. }) => {}
            other => panic!("expected staging cleanup, got {other:?}"),
        }
    }

    /// A `Resolved(PostPatchFailure)` attempt quarantines the push: the
    /// broker called `update_ref` but cannot confirm GitHub's terminal
    /// state. Reject is refused until manual reconciliation; the
    /// diagnostic must point at that operator action.
    #[tokio::test]
    async fn reject_staged_push_with_post_patch_failure_refuses_with_uncertain_diagnostic() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_001_040_000),
            UnixMillis::from_millis(1_700_001_040_500),
        )
        .await;
        let attempt_id = ApproveAttemptId::new();
        state
            .audit
            .start_approve_attempt(
                attempt_id,
                request_id,
                "alice",
                UnixMillis::from_millis(1_700_001_041_000),
            )
            .unwrap();
        state
            .audit
            .mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
            .unwrap();
        state
            .audit
            .complete_attempt_post_patch_failure(
                attempt_id,
                "github 502 on update_ref",
                UnixMillis::from_millis(1_700_001_042_000),
            )
            .unwrap();

        let resp = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id,
                operator: "bob".into(),
                reason: reason("late reject"),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains(&attempt_id.to_string()),
                    "expected attempt id in diagnostic, got: {message}",
                );
                assert!(
                    message.contains("reconcile") && message.contains("manually"),
                    "expected manual-reconciliation hint, got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // No resolution row got written; the attempt remains in
        // `Resolved(PostPatchFailure)` quarantine.
        let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
        assert!(audit_entry.resolution.is_none());
    }

    /// Pre-patch failure is *not* a blocker — `reject_blocker_for_push`
    /// returns `None` for an attempt that proved no PATCH was issued
    /// (mint failure, plan failure, etc.), so reject proceeds normally.
    /// This is the retry-after-transient-approve-failure path.
    #[tokio::test]
    async fn reject_staged_push_with_pre_patch_failure_attempt_proceeds_normally() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_001_050_000),
            UnixMillis::from_millis(1_700_001_050_500),
        )
        .await;
        let attempt_id = ApproveAttemptId::new();
        state
            .audit
            .start_approve_attempt(
                attempt_id,
                request_id,
                "alice",
                UnixMillis::from_millis(1_700_001_051_000),
            )
            .unwrap();
        state
            .audit
            .complete_attempt_pre_patch_failure(
                attempt_id,
                "mint failed",
                UnixMillis::from_millis(1_700_001_052_000),
            )
            .unwrap();

        let resp = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id,
                operator: "bob".into(),
                reason: reason("operator decision"),
            },
            &state,
        )
        .await;

        assert_eq!(resp, ServerMessage::StagedPushRejected { request_id });

        // Resolution row was written, staging dir removed.
        let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
        let resolution = audit_entry.resolution.expect("rejected resolution row");
        assert_eq!(resolution.decision, GitPushResolution::Rejected);
        assert_eq!(resolution.operator, "bob");
    }

    /// `is_active_approve_refusal` detects the
    /// `git_push_resolution_refuses_active_approve` trigger's raised
    /// message verbatim. This is the contract the handler depends on
    /// when it re-queries the blocker on INSERT failure. Verifies the
    /// match string is wired up correctly without standing up a full
    /// dispatch — the literal lives in the migration SQL.
    /// `is_active_approve_refusal` detects the
    /// `git_push_resolution_refuses_active_approve` trigger firing.
    /// This is the defence-in-depth path the handler relies on when an
    /// attempt row lands between the preflight blocker check and the
    /// resolution INSERT. Asserts both that a real trigger ABORT
    /// matches the predicate and that a sibling PK violation does
    /// *not* — keeping the existing
    /// `is_unique_constraint_violation` branch distinct.
    #[tokio::test]
    async fn is_active_approve_refusal_matches_the_trigger_message() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_002_000_000),
            UnixMillis::from_millis(1_700_002_000_500),
        )
        .await;
        let attempt_id = ApproveAttemptId::new();
        state
            .audit
            .start_approve_attempt(
                attempt_id,
                request_id,
                "alice",
                UnixMillis::from_millis(1_700_002_001_000),
            )
            .unwrap();

        let err = state
            .audit
            .record_git_push_resolution(&GitPushResolutionRecord {
                push_request_id: request_id,
                decided_at: UnixMillis::from_millis(1_700_002_002_000),
                decision: GitPushResolution::Rejected,
                operator: "bob",
                reason: "racing",
            })
            .expect_err("trigger refuses the INSERT");
        assert!(
            is_active_approve_refusal(&err),
            "predicate must classify trigger ABORT, got: {err:?}",
        );
        // A PK violation must *not* match this predicate so the
        // existing `is_unique_constraint_violation` branch keeps its
        // distinct behaviour.
        let fake_pk_err = crate::audit::AuditError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::ConstraintViolation,
                extended_code: 0,
            },
            Some("UNIQUE constraint failed: git_push_resolution.push_request_id".into()),
        ));
        assert!(
            !is_active_approve_refusal(&fake_pk_err),
            "PK violation must not match the trigger predicate",
        );
        assert!(is_unique_constraint_violation(&fake_pk_err));
    }

    // --- Staged-push approve (state machine) ----------------------------

    /// Mint failure (no GitHub mock for the access_tokens endpoint) must
    /// drive the attempt to `Resolved(PrePatchFailure)` with no mint
    /// captured — mint never produced a `MintedToken`, so there is no
    /// `PromoteMintAudit` to record. The handler surfaces a generic
    /// Error to the caller; no resolution row is written (the schema
    /// trigger insists approved/rejected resolutions are operator
    /// decisions, not failure side effects), and the staging dir
    /// remains so the operator can retry once the GitHub App config is
    /// healed.
    #[tokio::test]
    async fn approve_staged_push_mint_failure_resolves_attempt_as_pre_patch_failure() {
        let server = MockServer::start().await;
        // No `/app/installations/.../access_tokens` mock: the mint
        // request falls through wiremock's default 404 handler and
        // surfaces as a mint failure inside the handler.
        let (state, _tmp) = make_state_with_approve_ready(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_000_040_000),
            UnixMillis::from_millis(1_700_000_040_500),
        )
        .await;

        let resp = dispatch_message(
            ClientMessage::ApproveStagedPush {
                request_id,
                operator: "alice".into(),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("mint failed"),
                    "expected mint-failure error, got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // Attempt row reached `Resolved(PrePatchFailure)` without a
        // mint context: the mint never succeeded, so the row carries
        // `mint: None`.
        let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
        assert_eq!(attempts.len(), 1);
        match &attempts[0].state {
            GitPushApproveAttemptState::Resolved {
                outcome: GitPushApproveAttemptOutcome::PrePatchFailure { detail },
                mint,
                ..
            } => {
                assert!(mint.is_none(), "mint must not be captured on pre-mint fail");
                assert!(
                    detail.contains("mint failed"),
                    "failure detail must name the mint step: {detail}",
                );
            }
            other => panic!("expected Resolved(PrePatchFailure), got {other:?}"),
        }

        // No resolution row: PrePatchFailure leaves the push rejectable.
        let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
        assert!(audit_entry.resolution.is_none());

        // Staging dir is still there so reject (or a follow-up
        // approve) can act on the same staged push.
        assert!(
            state
                .staging_store
                .as_ref()
                .unwrap()
                .load(request_id)
                .is_ok()
        );
    }

    /// A prior `Rejected` resolution row makes the push immutable: any
    /// follow-up approve must short-circuit with
    /// `StagedPushAlreadyResolved` before starting an attempt or
    /// minting a token. The check sits on the joined audit view so a
    /// rejected-then-deleted-staging-dir push (the normal reject
    /// outcome) still races correctly with a concurrent approve.
    #[tokio::test]
    async fn approve_staged_push_with_prior_resolution_short_circuits() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_approve_ready(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_000_040_000),
            UnixMillis::from_millis(1_700_000_040_500),
        )
        .await;

        state
            .audit
            .record_git_push_resolution(&crate::audit::GitPushResolutionRecord {
                push_request_id: request_id,
                decided_at: UnixMillis::from_millis(1_700_000_041_000),
                decision: crate::audit::GitPushResolution::Rejected,
                operator: "bob",
                reason: "not ready",
            })
            .unwrap();

        // Belt-and-braces: a mock with `expect(0)` on the mint endpoint
        // would panic if the handler reached the mint step. The short-
        // circuit must fire before that.
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let resp = dispatch_message(
            ClientMessage::ApproveStagedPush {
                request_id,
                operator: "alice".into(),
            },
            &state,
        )
        .await;

        assert_eq!(
            resp,
            ServerMessage::StagedPushAlreadyResolved { request_id }
        );

        // No attempt row created: the short-circuit fires before
        // `start_approve_attempt`.
        let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
        assert!(attempts.is_empty());
    }

    /// Branch-creation pushes (no `expected_remote_head`) are refused
    /// by the handler before any attempt or mint: the fast-forward
    /// planner needs a lease anchor, and approve does not yet have a
    /// safe story for creating a brand-new branch via PUT. Refusing
    /// here gives the operator a clear diagnostic instead of letting
    /// the request fail deeper in the pipeline.
    #[tokio::test]
    async fn approve_staged_push_for_branch_creation_returns_error() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_approve_ready(&server);
        let session_id = open_session(&state).await;

        // Build a staged push whose audit row has
        // `expected_remote_head = None`. Mirrors `stage_with_audit`
        // but with a hand-rolled metadata that carries no parent.
        let request_id = RequestId::new();
        let metadata = crate::vm_git::VmGitPushMetadata::new(
            sample_clone_repo(),
            sample_branch(),
            None,
            sample_object_id('b'),
        );
        let staging = state.staging_store.as_ref().unwrap().clone();
        let bundle = b"bundle".to_vec();
        tokio::task::spawn_blocking(move || {
            staging
                .stage(
                    request_id,
                    UnixMillis::from_millis(1_700_000_040_000),
                    metadata,
                    bundle,
                )
                .unwrap();
        })
        .await
        .unwrap();
        state
            .audit
            .record_git_push_request(&crate::audit::GitPushRequestRecord {
                push_request_id: request_id,
                session_id,
                received_at: UnixMillis::from_millis(1_700_000_040_500),
                repo: sample_clone_repo(),
                branch: sample_branch(),
                expected_remote_head: None,
                new_head: sample_object_id('b'),
                correlation_id: None,
            })
            .unwrap();
        state
            .audit
            .record_git_push_outcome(&crate::audit::GitPushOutcomeRecord {
                push_request_id: request_id,
                completed_at: UnixMillis::from_millis(1_700_000_040_500),
                result: crate::audit::GitPushOutcomeResult::Staged,
                github_status: None,
                message: "staged for operator review",
            })
            .unwrap();

        let resp = dispatch_message(
            ClientMessage::ApproveStagedPush {
                request_id,
                operator: "alice".into(),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("branch-creation"),
                    "expected branch-creation refusal, got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // No attempt row: refusal happens before
        // `start_approve_attempt`.
        let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
        assert!(attempts.is_empty());
    }

    /// `run_approve` failure that fires before `update_ref` (e.g. the
    /// `git init --bare` in `prepare_staging_repo` because the
    /// configured `git_program` is bogus) must drive the attempt from
    /// `Uncertain` to `Resolved(PrePatchFailure)`. The mint context
    /// recorded by `mark_attempt_uncertain` survives on the resolved
    /// row, and reject becomes legal again because the trigger admits
    /// reject when every attempt is `PrePatchFailure`.
    #[tokio::test]
    async fn approve_staged_push_run_approve_failure_resolves_as_pre_patch_failure() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_approve_ready(&server);
        // `make_state_with_approve_ready` wires git_program to
        // `/nonexistent/bin/git`, so `prepare_staging_repo`'s
        // `git init --bare` fails — exactly the pre-PATCH failure
        // mode this test wants to exercise.
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_000_040_000),
            UnixMillis::from_millis(1_700_000_040_500),
        )
        .await;

        let expiry = expiry_str_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_test_token",
                "expires_at": expiry,
                "permissions": {"contents": "write", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"full_name": "owner/repo"}],
            })))
            .expect(1)
            .mount(&server)
            .await;

        let resp = dispatch_message(
            ClientMessage::ApproveStagedPush {
                request_id,
                operator: "alice".into(),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("staging preparation failed")
                        || message.contains("approve pipeline failed"),
                    "expected pre-PATCH pipeline failure, got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // Attempt row reached `Resolved(PrePatchFailure)` with the
        // mint context the `Uncertain` step recorded (the column-
        // immutability trigger preserves it across the resolve).
        let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
        assert_eq!(attempts.len(), 1);
        match &attempts[0].state {
            GitPushApproveAttemptState::Resolved {
                outcome: GitPushApproveAttemptOutcome::PrePatchFailure { detail },
                mint,
                ..
            } => {
                assert!(
                    mint.is_some(),
                    "mint context must persist from Uncertain across the resolve",
                );
                assert!(
                    detail.contains("run_approve failed"),
                    "failure detail must name the pipeline step: {detail}",
                );
            }
            other => panic!("expected Resolved(PrePatchFailure), got {other:?}"),
        }

        // PrePatchFailure leaves the push rejectable: no resolution
        // row, staging dir still on disk.
        let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
        assert!(audit_entry.resolution.is_none());
        assert!(
            state
                .staging_store
                .as_ref()
                .unwrap()
                .load(request_id)
                .is_ok()
        );
    }

    #[test]
    fn truncate_for_wire_passes_short_input_through() {
        let s = "hello".to_string();
        assert_eq!(truncate_for_wire(s.clone(), 16), s);
    }

    #[test]
    fn truncate_for_wire_passes_exact_cap_through() {
        // At exactly `cap` bytes there is nothing to truncate; the
        // sentinel marker must not be appended.
        let s = "x".repeat(8);
        assert_eq!(truncate_for_wire(s.clone(), 8), s);
    }

    #[test]
    fn truncate_for_wire_caps_oversize_input_and_appends_marker() {
        let s = "x".repeat(10);
        let out = truncate_for_wire(s, 4);
        assert_eq!(out, "xxxx... [truncated]");
    }

    #[test]
    fn truncate_for_wire_respects_utf8_boundary_when_cap_lands_mid_codepoint() {
        // "é" is a two-byte UTF-8 sequence (0xC3 0xA9). With cap=1 the
        // naive split would land between the two bytes; the helper must
        // back up to the previous char boundary so the result is valid
        // UTF-8.
        let s = "é".to_string();
        let out = truncate_for_wire(s.clone(), 1);
        // s is 2 bytes so cap=1 triggers truncation; the prefix before
        // the marker must be empty (the only char boundary at-or-below
        // 1 is 0).
        assert_eq!(out, "... [truncated]");
    }

    /// Operator validation runs before the configured-state checks so a
    /// caller can never use a malformed operator field to probe the
    /// broker's internal config shape. An empty operator is rejected
    /// with the same message the reject path uses.
    #[tokio::test]
    async fn approve_staged_push_with_empty_operator_returns_error() {
        let server = MockServer::start().await;
        // Use the plain (un-staging) state to prove the validation
        // short-circuits before the staging check fires.
        let state = make_state(&server, vec![], "o");
        let resp = dispatch_message(
            ClientMessage::ApproveStagedPush {
                request_id: RequestId::new(),
                operator: String::new(),
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("operator identity must not be empty"),
                    "expected empty-operator error, got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Same shape as the empty-operator test: oversize operators (over
    /// `MAX_OPERATOR_BYTES`) are rejected before any disk IO so a
    /// caller can't pad the audit log via the operator field. The cap
    /// is shared with the reject path.
    #[tokio::test]
    async fn approve_staged_push_with_oversize_operator_returns_error() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let oversize = "x".repeat(MAX_OPERATOR_BYTES + 1);
        let resp = dispatch_message(
            ClientMessage::ApproveStagedPush {
                request_id: RequestId::new(),
                operator: oversize,
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("exceeding the"),
                    "expected oversize-operator error, got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// If `staging_store` is unset the broker can never have produced
    /// a staged push receipt for this `request_id` in the first place,
    /// so the right surface is "not configured" rather than
    /// `UnknownStagedPush`. Same shape as the reject path's
    /// `staging_not_configured` response.
    #[tokio::test]
    async fn approve_staged_push_without_staging_store_returns_not_configured() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let resp = dispatch_message(
            ClientMessage::ApproveStagedPush {
                request_id: RequestId::new(),
                operator: "alice".into(),
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("git push staging is not configured"),
                    "expected staging-not-configured error, got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// `staging_store` is wired but `promote_runtime` is not: the load
    /// step would technically be runnable, but kicking it off without
    /// `promote_runtime` would just succeed and then dead-end at the
    /// mint slice. Returning a "not configured" error here gives the
    /// operator a precise diagnosis instead.
    #[tokio::test]
    async fn approve_staged_push_without_promote_runtime_returns_not_configured() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_000_040_000),
            UnixMillis::from_millis(1_700_000_040_500),
        )
        .await;
        let resp = dispatch_message(
            ClientMessage::ApproveStagedPush {
                request_id,
                operator: "alice".into(),
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("promote_runtime is unset"),
                    "expected promote_runtime-not-configured error, got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
        // The configured-state check must not have written an audit
        // row or removed the staging dir.
        let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
        assert!(audit_entry.resolution.is_none());
        assert!(
            state
                .staging_store
                .as_ref()
                .unwrap()
                .load(request_id)
                .is_ok()
        );
    }

    /// `staging_store` and `promote_runtime` are both wired but
    /// `signing_key` is not. Without the signing key, the eventual
    /// `run_approve` call would have no app-identity to sign the
    /// replayed commits with — same diagnosis pattern as
    /// `promote_runtime`.
    #[tokio::test]
    async fn approve_staged_push_without_signing_key_returns_not_configured() {
        use crate::git_push_promote::PromoteRuntimeConfig;
        use crate::vm_git_bundle::{GitCloneBaseUrl, GitCredentialBoundary, GitSecretEnvVar};
        let server = MockServer::start().await;
        let (mut state, tmp) = make_state_with_staging(&server);
        let runtime = PromoteRuntimeConfig::new(
            PathBuf::from("/nonexistent/bin/git"),
            GitCloneBaseUrl::github(),
            GitCredentialBoundary::new(
                PathBuf::from("/nonexistent/bin/askpass"),
                GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap(),
            )
            .unwrap(),
            tmp.path().join("promote"),
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let inner = Arc::get_mut(&mut state).expect("fresh Arc has no other handles");
        inner.promote_runtime = Some(Arc::new(runtime));
        // signing_key intentionally left None.

        let resp = dispatch_message(
            ClientMessage::ApproveStagedPush {
                request_id: RequestId::new(),
                operator: "alice".into(),
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("signing_key is unset"),
                    "expected signing_key-not-configured error, got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// A request_id with no corresponding staging dir on disk must
    /// surface as `UnknownStagedPush`, not a generic Error — the
    /// reject path uses the same convention. This lets the CLI render
    /// "no such staged push" cleanly instead of leaking IO error text.
    #[tokio::test]
    async fn approve_staged_push_with_unknown_request_returns_unknown_staged_push() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_approve_ready(&server);
        let unknown = RequestId::new();
        let resp = dispatch_message(
            ClientMessage::ApproveStagedPush {
                request_id: unknown,
                operator: "alice".into(),
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::UnknownStagedPush { request_id } => {
                assert_eq!(request_id, unknown);
            }
            other => panic!("expected UnknownStagedPush, got {other:?}"),
        }
    }

    // --- Reconcile staged push -----------------------------------------

    /// Stage a push, start an approve attempt, drive it to `Uncertain`,
    /// then mark it boot-observed so the row is eligible for manual
    /// reconciliation. Returns `(request_id, predecessor_attempt_id)`.
    /// Mirrors the `Uncertain` survivor case boot reconcile leaves on
    /// disk after a daemon restart.
    async fn stage_with_boot_observed_uncertain_attempt(
        state: &Arc<BrokerState<InMemStore>>,
        timeline_base_ms: i64,
    ) -> (RequestId, ApproveAttemptId) {
        let session_id = open_session(state).await;
        let request_id = stage_with_staged_outcome(
            state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(timeline_base_ms),
            UnixMillis::from_millis(timeline_base_ms + 500),
        )
        .await;
        let attempt_id = ApproveAttemptId::new();
        state
            .audit
            .start_approve_attempt(
                attempt_id,
                request_id,
                "alice",
                UnixMillis::from_millis(timeline_base_ms + 1_000),
            )
            .unwrap();
        state
            .audit
            .mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
            .unwrap();
        state
            .audit
            .mark_attempt_boot_observed(
                attempt_id,
                UnixMillis::from_millis(timeline_base_ms + 2_000),
            )
            .unwrap();
        (request_id, attempt_id)
    }

    /// Stage a push, start an approve attempt, drive it through
    /// `Uncertain` to `Resolved(PostPatchFailure)`. The predecessor is
    /// terminal and does not require a boot-observed marker —
    /// reconciliation is admitted directly.
    async fn stage_with_post_patch_failure_attempt(
        state: &Arc<BrokerState<InMemStore>>,
        timeline_base_ms: i64,
    ) -> (RequestId, ApproveAttemptId) {
        let session_id = open_session(state).await;
        let request_id = stage_with_staged_outcome(
            state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(timeline_base_ms),
            UnixMillis::from_millis(timeline_base_ms + 500),
        )
        .await;
        let attempt_id = ApproveAttemptId::new();
        state
            .audit
            .start_approve_attempt(
                attempt_id,
                request_id,
                "alice",
                UnixMillis::from_millis(timeline_base_ms + 1_000),
            )
            .unwrap();
        state
            .audit
            .mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
            .unwrap();
        state
            .audit
            .complete_attempt_post_patch_failure(
                attempt_id,
                "github 502 on update_ref",
                UnixMillis::from_millis(timeline_base_ms + 2_000),
            )
            .unwrap();
        (request_id, attempt_id)
    }

    #[tokio::test]
    async fn reconcile_staged_push_without_staging_configured_returns_error() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id: RequestId::new(),
                operator: "alice".into(),
                outcome: ReconcileOutcome::NotApplied {
                    detail: "operator confirmed no PATCH landed".into(),
                },
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("staging"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reconcile_staged_push_with_empty_operator_returns_error() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id: RequestId::new(),
                operator: String::new(),
                outcome: ReconcileOutcome::NotApplied { detail: "x".into() },
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("operator"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reconcile_staged_push_with_oversize_operator_returns_error() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let oversize = "a".repeat(MAX_OPERATOR_BYTES + 1);
        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id: RequestId::new(),
                operator: oversize,
                outcome: ReconcileOutcome::NotApplied { detail: "x".into() },
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("operator"), "got: {message}");
                assert!(message.contains("byte"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reconcile_staged_push_with_empty_detail_returns_error() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id: RequestId::new(),
                operator: "alice".into(),
                outcome: ReconcileOutcome::NotApplied {
                    detail: String::new(),
                },
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("detail") && message.contains("empty"),
                    "got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reconcile_staged_push_with_empty_reason_returns_error() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id: RequestId::new(),
                operator: "alice".into(),
                outcome: ReconcileOutcome::Applied {
                    new_app_tip: sample_object_id('c'),
                    reason: String::new(),
                },
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("reason") && message.contains("empty"),
                    "got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reconcile_staged_push_with_oversize_detail_returns_error() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let oversize = "z".repeat(crate::protocol::MAX_REJECTION_REASON_BYTES + 1);
        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id: RequestId::new(),
                operator: "alice".into(),
                outcome: ReconcileOutcome::NotApplied { detail: oversize },
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("detail"), "got: {message}");
                assert!(message.contains("byte"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reconcile_staged_push_with_unknown_request_returns_unknown_staged_push() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let request_id = RequestId::new();
        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id,
                operator: "alice".into(),
                outcome: ReconcileOutcome::NotApplied {
                    detail: "operator confirmed nothing landed".into(),
                },
            },
            &state,
        )
        .await;
        assert_eq!(resp, ServerMessage::UnknownStagedPush { request_id });
    }

    #[tokio::test]
    async fn reconcile_staged_push_with_no_attempts_returns_not_reconcilable() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_010_000_000),
            UnixMillis::from_millis(1_700_010_000_500),
        )
        .await;
        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id,
                operator: "alice".into(),
                outcome: ReconcileOutcome::NotApplied {
                    detail: "no attempts to reconcile".into(),
                },
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::StagedPushNotReconcilable {
                request_id: got_id,
                reason,
            } => {
                assert_eq!(got_id, request_id);
                assert!(
                    reason.contains("no approve attempt"),
                    "got reason: {reason}",
                );
            }
            other => panic!("expected StagedPushNotReconcilable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reconcile_staged_push_with_in_flight_started_attempt_returns_not_reconcilable() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_011_000_000),
            UnixMillis::from_millis(1_700_011_000_500),
        )
        .await;
        let attempt_id = ApproveAttemptId::new();
        state
            .audit
            .start_approve_attempt(
                attempt_id,
                request_id,
                "alice",
                UnixMillis::from_millis(1_700_011_001_000),
            )
            .unwrap();

        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id,
                operator: "alice".into(),
                outcome: ReconcileOutcome::NotApplied {
                    detail: "racing reconciliation".into(),
                },
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::StagedPushNotReconcilable {
                request_id: got_id,
                reason,
            } => {
                assert_eq!(got_id, request_id);
                assert!(reason.contains("in-flight"), "got reason: {reason}");
            }
            other => panic!("expected StagedPushNotReconcilable, got {other:?}"),
        }

        // No reconciliation row was written.
        let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
        assert_eq!(attempts.len(), 1);
    }

    #[tokio::test]
    async fn reconcile_staged_push_with_uncertain_not_boot_observed_returns_not_reconcilable() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_011_200_000),
            UnixMillis::from_millis(1_700_011_200_500),
        )
        .await;
        let attempt_id = ApproveAttemptId::new();
        state
            .audit
            .start_approve_attempt(
                attempt_id,
                request_id,
                "alice",
                UnixMillis::from_millis(1_700_011_201_000),
            )
            .unwrap();
        state
            .audit
            .mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
            .unwrap();
        // Note: no mark_attempt_boot_observed — the row may belong to a
        // live worker and reconciliation must wait.

        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id,
                operator: "alice".into(),
                outcome: ReconcileOutcome::NotApplied {
                    detail: "racing reconciliation".into(),
                },
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::StagedPushNotReconcilable {
                request_id: got_id,
                reason,
            } => {
                assert_eq!(got_id, request_id);
                assert!(reason.contains("in-flight"), "got reason: {reason}");
            }
            other => panic!("expected StagedPushNotReconcilable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reconcile_staged_push_with_only_pre_patch_failure_returns_not_reconcilable() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_012_000_000),
            UnixMillis::from_millis(1_700_012_000_500),
        )
        .await;
        let attempt_id = ApproveAttemptId::new();
        state
            .audit
            .start_approve_attempt(
                attempt_id,
                request_id,
                "alice",
                UnixMillis::from_millis(1_700_012_001_000),
            )
            .unwrap();
        state
            .audit
            .complete_attempt_pre_patch_failure(
                attempt_id,
                "mint failed",
                UnixMillis::from_millis(1_700_012_002_000),
            )
            .unwrap();

        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id,
                operator: "alice".into(),
                outcome: ReconcileOutcome::NotApplied {
                    detail: "nothing to clear".into(),
                },
            },
            &state,
        )
        .await;
        match resp {
            ServerMessage::StagedPushNotReconcilable {
                request_id: got_id,
                reason,
            } => {
                assert_eq!(got_id, request_id);
                assert!(
                    reason.contains("no quarantined approve attempt"),
                    "got reason: {reason}",
                );
            }
            other => panic!("expected StagedPushNotReconcilable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reconcile_staged_push_with_prior_resolution_returns_already_resolved() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let session_id = open_session(&state).await;
        let request_id = stage_with_staged_outcome(
            &state,
            session_id,
            b"bundle".to_vec(),
            UnixMillis::from_millis(1_700_013_000_000),
            UnixMillis::from_millis(1_700_013_000_500),
        )
        .await;
        state
            .audit
            .record_git_push_resolution(&GitPushResolutionRecord {
                push_request_id: request_id,
                decided_at: UnixMillis::from_millis(1_700_013_001_000),
                decision: GitPushResolution::Rejected,
                operator: "alice",
                reason: "prior decision",
            })
            .unwrap();

        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id,
                operator: "bob".into(),
                outcome: ReconcileOutcome::NotApplied {
                    detail: "racing reconciliation".into(),
                },
            },
            &state,
        )
        .await;
        assert_eq!(
            resp,
            ServerMessage::StagedPushAlreadyResolved { request_id }
        );
    }

    /// Happy-path: a `Resolved(PostPatchFailure)` attempt is the
    /// canonical reconciliation target — terminal, no boot-observed
    /// marker required. `Applied` writes the reconciliation row and
    /// the joint-TX `git_push_resolution(decision='approved')` row,
    /// then deletes the staging dir.
    #[tokio::test]
    async fn reconcile_staged_push_applied_against_post_patch_failure_records_resolution() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let (request_id, predecessor) =
            stage_with_post_patch_failure_attempt(&state, 1_700_020_000_000).await;
        let new_app_tip = sample_object_id('c');

        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id,
                operator: "bob".into(),
                outcome: ReconcileOutcome::Applied {
                    new_app_tip: new_app_tip.clone(),
                    reason: "operator confirmed branch advanced".into(),
                },
            },
            &state,
        )
        .await;
        assert_eq!(resp, ServerMessage::StagedPushReconciled { request_id });

        // The resolution row is now `Approved` with the predecessor's
        // mint context copied through.
        let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
        let resolution = audit_entry.resolution.expect("resolution row recorded");
        assert!(
            matches!(resolution.decision, GitPushResolution::Approved(_)),
            "expected Approved decision, got {:?}",
            resolution.decision,
        );
        assert_eq!(resolution.operator, "bob");

        // The reconciliation row supersedes the predecessor and carries
        // the new_app_tip via its `Succeeded` outcome. Two attempt
        // rows, both committed.
        let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
        assert_eq!(attempts.len(), 2);
        assert!(
            attempts.iter().any(|a| a.attempt_id == predecessor),
            "predecessor row must remain",
        );
        let reconciliation = attempts
            .iter()
            .find(|a| a.attempt_id != predecessor)
            .expect("reconciliation row recorded");
        match &reconciliation.state {
            GitPushApproveAttemptState::Resolved {
                outcome: GitPushApproveAttemptOutcome::Succeeded { new_app_tip: tip },
                ..
            } => {
                assert_eq!(tip, &new_app_tip);
            }
            other => {
                panic!("expected reconciliation row to be Resolved(Succeeded), got {other:?}",)
            }
        }

        // Staging dir was deleted after the joint TX committed.
        match state.staging_store.as_ref().unwrap().load(request_id) {
            Err(StagingError::NotFound { .. }) => {}
            other => panic!("expected staging cleanup, got {other:?}"),
        }
    }

    /// `NotApplied` against a `Resolved(PostPatchFailure)` predecessor
    /// writes a born-terminal `Resolved(PrePatchFailure)` reconciliation
    /// row but no resolution row. The staging dir survives so a
    /// follow-up reject can decide the operator action.
    #[tokio::test]
    async fn reconcile_staged_push_not_applied_against_post_patch_failure_leaves_push_rejectable() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let (request_id, _predecessor) =
            stage_with_post_patch_failure_attempt(&state, 1_700_021_000_000).await;

        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id,
                operator: "bob".into(),
                outcome: ReconcileOutcome::NotApplied {
                    detail: "operator confirmed branch did not advance".into(),
                },
            },
            &state,
        )
        .await;
        assert_eq!(resp, ServerMessage::StagedPushReconciled { request_id });

        // No resolution row — push is again rejectable.
        let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
        assert!(audit_entry.resolution.is_none());

        // Staging dir is still on disk so a follow-up reject finds it.
        assert!(
            state
                .staging_store
                .as_ref()
                .unwrap()
                .load(request_id)
                .is_ok(),
        );

        // Follow-up reject now proceeds (PrePatchFailure is not a
        // blocker after the predecessor was superseded).
        let follow_up = dispatch_message(
            ClientMessage::RejectStagedPush {
                request_id,
                operator: "bob".into(),
                reason: reason("after not-applied reconciliation"),
            },
            &state,
        )
        .await;
        assert_eq!(follow_up, ServerMessage::StagedPushRejected { request_id });
    }

    /// A boot-observed `Uncertain` row is the survivor case: the
    /// daemon crashed mid-approve, boot reconcile marked the row
    /// observable, and the operator manually decides the GitHub side.
    /// Reconciliation `Applied` lands the resolution row and clears
    /// the quarantine.
    #[tokio::test]
    async fn reconcile_staged_push_applied_against_boot_observed_uncertain_records_resolution() {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let (request_id, _predecessor) =
            stage_with_boot_observed_uncertain_attempt(&state, 1_700_022_000_000).await;
        let new_app_tip = sample_object_id('d');

        let resp = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id,
                operator: "bob".into(),
                outcome: ReconcileOutcome::Applied {
                    new_app_tip: new_app_tip.clone(),
                    reason: "branch advanced under restart".into(),
                },
            },
            &state,
        )
        .await;
        assert_eq!(resp, ServerMessage::StagedPushReconciled { request_id });

        let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
        let resolution = audit_entry.resolution.expect("resolution row recorded");
        assert!(matches!(
            resolution.decision,
            GitPushResolution::Approved(_)
        ));
    }

    /// Two reconciliations in a row against the same push: the second
    /// fails because the predecessor is already superseded. The handler
    /// surfaces the DAO Invariant as `StagedPushNotReconcilable` rather
    /// than a generic Error so the CLI can guide the operator to
    /// re-list and pick the new state.
    #[tokio::test]
    async fn reconcile_staged_push_against_already_superseded_predecessor_returns_not_reconcilable()
    {
        let server = MockServer::start().await;
        let (state, _tmp) = make_state_with_staging(&server);
        let (request_id, _predecessor) =
            stage_with_post_patch_failure_attempt(&state, 1_700_023_000_000).await;

        // First reconciliation clears the predecessor.
        let first = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id,
                operator: "bob".into(),
                outcome: ReconcileOutcome::NotApplied {
                    detail: "no patch landed".into(),
                },
            },
            &state,
        )
        .await;
        assert_eq!(first, ServerMessage::StagedPushReconciled { request_id });

        // Second call sees the predecessor has been superseded; the
        // classifier now reports NothingToReconcile (every blocker is
        // cleared) rather than Eligible.
        let second = dispatch_message(
            ClientMessage::ReconcileStagedPush {
                request_id,
                operator: "bob".into(),
                outcome: ReconcileOutcome::NotApplied {
                    detail: "racing second call".into(),
                },
            },
            &state,
        )
        .await;
        match second {
            ServerMessage::StagedPushNotReconcilable {
                request_id: got_id,
                reason,
            } => {
                assert_eq!(got_id, request_id);
                assert!(
                    reason.contains("no quarantined approve attempt"),
                    "got reason: {reason}",
                );
            }
            other => panic!("expected StagedPushNotReconcilable, got {other:?}"),
        }
    }

    // --- Policy decisions ------------------------------------------------

    #[test]
    fn capability_outcome_debug_redacts_granted_token() {
        let outcome = CapabilityOutcome::Granted {
            token: "ghs_should_not_print".into(),
            expires_at: UnixMillis::from_millis(1_700_000_000_000),
        };

        let debug = format!("{outcome:?}");

        assert!(!debug.contains("ghs_should_not_print"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(debug.contains("expires_at"), "{debug}");
    }

    #[tokio::test]
    async fn request_not_on_allowlist_is_denied() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o"); // empty allowlist

        let session_id = open_session(&state).await;

        let resp = dispatch_message(
            ClientMessage::Request {
                session_id,
                capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                    access: GitHubAccess::Write,
                    repo: repo("o", "n"),
                }),
            },
            &state,
        )
        .await;

        assert!(
            matches!(resp, ServerMessage::Denied { .. }),
            "expected Denied, got {resp:?}"
        );
    }

    #[tokio::test]
    async fn request_on_closed_session_returns_closed_session_variant_without_minting() {
        // If a client closes the session and then tries to mint, the
        // broker must reject rather than issue a credential and audit
        // it against a session that is already "quiet" on paper. This
        // covers the happy-path (non-racy) case where the close lands
        // before dispatch_capability starts; the audit-layer check is
        // what catches the rare race where close lands during the
        // minter's await, exercised in audit.rs.
        let server = MockServer::start().await;
        let state = make_state(&server, vec![repo("o", "n")], "o");
        // If dispatch_capability failed to reject a closed session and
        // the minter was still hit, the lack of a mount would cause the
        // request to fall through to a 404 and mask the bug we're
        // checking. Belt-and-braces: mount a handler that panics so a
        // minting attempt becomes loud.
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let session_id = open_session(&state).await;
        let close_resp = dispatch_message(ClientMessage::CloseSession { session_id }, &state).await;
        assert_eq!(close_resp, ServerMessage::SessionClosed);

        let resp = dispatch_message(
            ClientMessage::Request {
                session_id,
                capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                    access: GitHubAccess::Read,
                    repo: repo("o", "n"),
                }),
            },
            &state,
        )
        .await;

        assert_eq!(resp, ServerMessage::ClosedSession { session_id });

        // No audit row should have been recorded for the post-close
        // request attempt.
        assert!(
            state
                .audit
                .list_grants_for_session(session_id)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn request_for_unknown_session_returns_unknown_session_variant() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![repo("o", "n")], "o");
        let unknown: SessionId = "00000000-0000-0000-0000-deadbeef0002".parse().unwrap();

        let resp = dispatch_message(
            ClientMessage::Request {
                session_id: unknown,
                capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                    access: GitHubAccess::Read,
                    repo: repo("o", "n"),
                }),
            },
            &state,
        )
        .await;

        assert_eq!(
            resp,
            ServerMessage::UnknownSession {
                session_id: unknown,
            },
        );
    }

    #[tokio::test]
    async fn request_on_allowlisted_repo_returns_token() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![repo("o", "n")], "o");
        let session_id = open_session(&state).await;

        let expiry = expiry_str_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_test_token",
                "expires_at": expiry,
                "permissions": {"contents": "read", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"full_name": "o/n"}]
            })))
            .mount(&server)
            .await;

        let resp = dispatch_message(
            ClientMessage::Request {
                session_id,
                capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                    access: GitHubAccess::Read,
                    repo: repo("o", "n"),
                }),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::TokenGranted { token, expires_at } => {
                assert_eq!(token, "ghs_test_token");
                assert!(expires_at.as_millis() > 0);
            }
            other => panic!("expected TokenGranted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_uses_github_app_for_session_agent_kind() {
        let server = MockServer::start().await;
        let state = make_agent_registry_state(&server);
        let session_id = match dispatch_message(
            ClientMessage::OpenSession {
                label: None,
                agent_kind: Some(AgentKind::Codex),
                agent_model: Some("claude-opus-misleading".into()),
            },
            &state,
        )
        .await
        {
            ServerMessage::SessionOpened { session_id } => session_id,
            other => panic!("open_session failed: {other:?}"),
        };

        Mock::given(method("POST"))
            .and(path("/app/installations/111/access_tokens"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/app/installations/222/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_codex_token",
                "expires_at": expiry_str_from_now(3600),
                "permissions": {"contents": "read", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"full_name": "o/n"}]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let resp = dispatch_message(
            ClientMessage::Request {
                session_id,
                capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                    access: GitHubAccess::Read,
                    repo: repo("o", "n"),
                }),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::TokenGranted { token, .. } => {
                assert_eq!(token, "ghs_codex_token");
            }
            other => panic!("expected TokenGranted, got {other:?}"),
        }

        let grants = state.audit.list_grants_for_session(session_id).unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].github_app_id, Some(202));
    }

    #[tokio::test]
    async fn agent_registry_rejects_session_open_without_agent_kind() {
        let server = MockServer::start().await;
        let state = make_agent_registry_state(&server);

        Mock::given(method("POST"))
            .and(path("/app/installations/111/access_tokens"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/app/installations/222/access_tokens"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let resp = dispatch_message(
            ClientMessage::OpenSession {
                label: None,
                agent_kind: None,
                agent_model: Some("claude-opus-misleading".into()),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("--agent claude"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn agent_registry_rejects_agent_vm_start_without_agent_kind() {
        let server = MockServer::start().await;
        let state = make_agent_registry_state(&server);

        let resp = dispatch_message(
            ClientMessage::StartAgentVm {
                label: None,
                agent_kind: None,
                agent_model: None,
                workspace: None,
                guest_command: vec!["true".into()],
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("--agent claude"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn agent_registry_reports_missing_app_for_session_agent_kind() {
        let server = MockServer::start().await;
        let state = make_agent_registry_state_for_agents(&server, &[AgentKind::Claude]);
        let session_id = open_session_with_agent_kind(&state, Some(AgentKind::Codex)).await;

        Mock::given(method("POST"))
            .and(path("/app/installations/111/access_tokens"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let resp = dispatch_message(
            ClientMessage::Request {
                session_id,
                capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                    access: GitHubAccess::Read,
                    repo: repo("o", "n"),
                }),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("no GitHub App is configured for agent kind codex"),
                    "got: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mint_failure_returns_bounded_label_to_agent_without_echoing_body() {
        // GitHub returns a 401 with a body the broker must not forward
        // verbatim to the agent: it could be very long, and might echo a
        // sensitive fragment (e.g. an internal identifier in an error
        // message). The protocol surface must carry only the bounded
        // label produced by `MintError::agent_message`.
        let server = MockServer::start().await;
        let state = make_state(&server, vec![repo("o", "n")], "o");
        let session_id = open_session(&state).await;

        let body_marker = "do-not-leak-this-fragment-XYZ";
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "message": format!("bad credentials: {body_marker}"),
            })))
            .mount(&server)
            .await;

        let resp = dispatch_message(
            ClientMessage::Request {
                session_id,
                capability: CapabilityRequest::GitHub(crate::core::GitHubRequest::Contents {
                    access: GitHubAccess::Read,
                    repo: repo("o", "n"),
                }),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    !message.contains(body_marker),
                    "agent surface must not echo API body: {message}"
                );
                assert!(
                    message.contains("401"),
                    "agent surface should carry the status discriminant: {message}"
                );
                // Sanity-cap on the protocol message itself, mirroring
                // the in-module assertion in `agent_message_…_bounded`.
                assert!(message.len() <= 256, "message too long: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // --- Integration: full socket round-trip -----------------------------

    #[tokio::test]
    async fn socket_roundtrip_open_and_close_session() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");

        let dir = tempfile::tempdir().unwrap();
        // The permission check in run() requires the parent to be 0700;
        // tempfile creates 0755, so fix it before spawning.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let sock_path = dir.path().join("test.sock");

        // Spawn the listener
        let state_clone = Arc::clone(&state);
        let path_clone = sock_path.clone();
        tokio::spawn(async move {
            let _ = run(&path_clone, state_clone).await;
        });

        let stream = connect_with_retries(&sock_path).await;
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        // Open session
        let open_msg = serde_json::to_string(&ClientMessage::OpenSession {
            label: Some("integration".into()),
            agent_kind: Some(AgentKind::Claude),
            agent_model: None,
        })
        .unwrap()
            + "\n";
        writer.write_all(open_msg.as_bytes()).await.unwrap();
        let reply = lines.next_line().await.unwrap().unwrap();
        let server_msg: ServerMessage = serde_json::from_str(&reply).unwrap();
        let session_id = match server_msg {
            ServerMessage::SessionOpened { session_id } => session_id,
            other => panic!("expected SessionOpened, got {other:?}"),
        };

        // Close session
        let close_msg =
            serde_json::to_string(&ClientMessage::CloseSession { session_id }).unwrap() + "\n";
        writer.write_all(close_msg.as_bytes()).await.unwrap();
        let reply = lines.next_line().await.unwrap().unwrap();
        let server_msg: ServerMessage = serde_json::from_str(&reply).unwrap();
        assert_eq!(server_msg, ServerMessage::SessionClosed);

        // Verify the DB was updated by the server
        let record = state.audit.get_session(session_id).unwrap().unwrap();
        assert!(record.closed_at.is_some());
    }

    // --- Helper ----------------------------------------------------------

    async fn open_session<S: SecretStore + Send + Sync + 'static>(
        state: &Arc<BrokerState<S>>,
    ) -> SessionId {
        open_session_with_agent_kind(state, Some(AgentKind::Claude)).await
    }

    async fn open_session_with_agent_kind<S: SecretStore + Send + Sync + 'static>(
        state: &Arc<BrokerState<S>>,
        agent_kind: Option<AgentKind>,
    ) -> SessionId {
        match dispatch_message(
            ClientMessage::OpenSession {
                label: None,
                agent_kind,
                agent_model: None,
            },
            state,
        )
        .await
        {
            ServerMessage::SessionOpened { session_id } => session_id,
            other => panic!("open_session failed: {other:?}"),
        }
    }

    // --- Bounded read_line -----------------------------------------------

    /// Normal line within the cap: reads cleanly, strips trailing `\r`.
    #[tokio::test]
    async fn read_line_bounded_reads_up_to_newline() {
        let mut input = &b"hello\r\n"[..];
        let line = read_line_bounded(&mut input, 64).await.unwrap().unwrap();
        assert_eq!(&line, b"hello");
    }

    /// EOF before any bytes is `Ok(None)`, matching AsyncBufReadExt::read_line.
    #[tokio::test]
    async fn read_line_bounded_returns_none_on_clean_eof() {
        let mut input: &[u8] = b"";
        assert!(read_line_bounded(&mut input, 64).await.unwrap().is_none());
    }

    /// EOF after bytes but without a newline yields whatever was read —
    /// lets the caller decide whether a final unterminated frame is an
    /// error (our caller treats the JSON parse failure as the error).
    #[tokio::test]
    async fn read_line_bounded_returns_partial_on_eof_without_newline() {
        let mut input = &b"abc"[..];
        let line = read_line_bounded(&mut input, 64).await.unwrap().unwrap();
        assert_eq!(&line, b"abc");
    }

    /// A line exceeding the cap (even without a newline) is rejected
    /// rather than buffered to completion — that's the whole point of
    /// the cap.
    #[tokio::test]
    async fn read_line_bounded_rejects_oversize_without_newline() {
        let big = vec![b'x'; 128];
        let mut input = big.as_slice();
        let err = read_line_bounded(&mut input, 64).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Oversize with a newline also rejects, and does so without having
    /// grown the internal buffer past the cap.
    #[tokio::test]
    async fn read_line_bounded_rejects_oversize_with_newline() {
        let mut big = vec![b'x'; 128];
        big.push(b'\n');
        let mut input = big.as_slice();
        let err = read_line_bounded(&mut input, 64).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// After the cap is hit, the connection-level handler reports a
    /// structured error to the peer so a CLI surfaces something
    /// actionable rather than a mystery-close.
    #[tokio::test]
    async fn oversize_request_over_socket_returns_structured_error() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let sock_path = dir.path().join("test.sock");

        let state_clone = Arc::clone(&state);
        let path_clone = sock_path.clone();
        tokio::spawn(async move {
            let _ = run(&path_clone, state_clone).await;
        });

        let stream = connect_with_retries(&sock_path).await;
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        // Write > MAX_LINE_BYTES non-newline bytes, then a newline. The
        // writes may fail with BrokenPipe/ConnectionReset: the server
        // trips the cap mid-read, sends its Error reply, and closes,
        // which can race ahead of our later writes on Linux. Tolerating
        // a write failure here is correct — the invariant under test is
        // that the *read* side sees a structured Error reply, not that
        // every byte we tried to send was acknowledged.
        let oversize = vec![b'x'; MAX_LINE_BYTES + 1];
        let _ = writer.write_all(&oversize).await;
        let _ = writer.write_all(b"\n").await;

        let reply = lines.next_line().await.unwrap().unwrap();
        let msg: ServerMessage = serde_json::from_str(&reply).unwrap();
        match msg {
            ServerMessage::Error { message } => {
                assert!(message.contains("exceeds"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // --- Socket bind handling -------------------------------------------

    /// Fresh parent directory with no pre-existing socket file: bind succeeds.
    #[tokio::test]
    async fn bind_socket_succeeds_on_empty_path() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("w.sock");
        let l = bind_socket(&sock).await.unwrap();
        assert!(sock.exists());
        drop(l);
    }

    /// A leftover socket file with no live listener (stale) is detected
    /// (connect fails), cleaned up, and the rebind succeeds.
    ///
    /// The reclaim is retried on a bounded deadline. In the parallel test
    /// harness a sibling `fork()` in another test can transiently inherit
    /// this just-dropped listener's fd — `O_CLOEXEC` closes it only at the
    /// child's `exec`, not at `fork` — keeping the AF_UNIX socket
    /// momentarily connectable (into the listen backlog) so `bind_socket`'s
    /// liveness probe reports `AddrInUse`. The window is sub-millisecond:
    /// once the forked child `exec`s, the socket is truly gone and the
    /// reclaim succeeds. Production `writd` startup binds the socket once
    /// with no concurrent listener being dropped, so it never sees this
    /// transient; only the test harness manufactures it, so only the test
    /// tolerates it. A genuine reclaim failure still surfaces: any other
    /// error fails immediately, and exhausting the deadline panics rather
    /// than hanging.
    #[tokio::test]
    async fn bind_socket_reclaims_stale_socket_file() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("w.sock");
        {
            // Bind, then drop the listener. The socket *file* lingers
            // (Rust doesn't rm on drop) but nothing is listening.
            let _listener = UnixListener::bind(&sock).unwrap();
        }
        assert!(sock.exists(), "precondition: stale socket file present");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let l = loop {
            match bind_socket(&sock).await {
                Ok(l) => break l,
                Err(e)
                    if e.kind() == io::ErrorKind::AddrInUse
                        && std::time::Instant::now() < deadline =>
                {
                    // Transient fork-inherited connectability; retry once
                    // the holding child has had a chance to exec.
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(e) => panic!("bind_socket failed to reclaim stale socket: {e}"),
            }
        };
        assert!(sock.exists());
        drop(l);
    }

    /// A live listener at the path must be refused — we don't want two
    /// daemons fighting over the same credential socket.
    #[tokio::test]
    async fn bind_socket_refuses_to_displace_live_listener() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("w.sock");
        let _live = UnixListener::bind(&sock).unwrap();
        let err = bind_socket(&sock).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        assert!(err.to_string().contains("already running"), "got: {err}");
    }

    /// A regular file (not a socket) at the configured path is operator
    /// error; refuse rather than silently deleting arbitrary files.
    #[tokio::test]
    async fn bind_socket_refuses_to_delete_non_socket_file() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("w.sock");
        std::fs::write(&sock, b"not a socket").unwrap();
        let err = bind_socket(&sock).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    /// Wait for the spawned listener to finish binding. A short retry
    /// loop beats `sleep(N)` because it succeeds the moment the bind
    /// completes (fast path on unloaded CI) and still bounds the total
    /// wait so a bug in `run()` surfaces as a test failure rather than
    /// a hang.
    async fn connect_with_retries(sock_path: &Path) -> UnixStream {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match UnixStream::connect(sock_path).await {
                Ok(s) => return s,
                Err(_) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Err(e) => panic!("listener never came up at {}: {e}", sock_path.display()),
            }
        }
    }
}
