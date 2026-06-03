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
    let entry = match load_staged_entry(&staging_store, request_id).await {
        Ok(entry) => entry,
        Err(resp) => return resp,
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

/// Reject an empty or oversize operator identity before any IO, so a
/// caller cannot probe broker state via a malformed identity field.
/// Shared verbatim by reject/approve/reconcile; the limit and the
/// wording live in one place. Returns `Some(error_response)` when the
/// operator is invalid, `None` when it passes.
fn validate_operator(operator: &str) -> Option<ServerMessage> {
    if operator.is_empty() {
        return Some(ServerMessage::Error {
            message: "operator identity must not be empty".into(),
        });
    }
    if operator.len() > MAX_OPERATOR_BYTES {
        return Some(ServerMessage::Error {
            message: format!(
                "operator identity is {} bytes, exceeding the {MAX_OPERATOR_BYTES}-byte limit",
                operator.len(),
            ),
        });
    }
    None
}

/// Load a staging entry off the blocking pool, mapping the absence of a
/// staging directory to a clean `UnknownStagedPush`. Every staged-push
/// handler probes staging through here so they agree on what "the
/// staging is gone" means: a missing dir is `UnknownStagedPush`, a
/// failed `spawn_blocking` join is a generic `Error`. Callers that only
/// need an existence check discard the returned [`StagedEntry`].
async fn load_staged_entry(
    staging_store: &Arc<GitPushStagingStore>,
    request_id: RequestId,
) -> Result<StagedEntry, ServerMessage> {
    let staging_store = Arc::clone(staging_store);
    match tokio::task::spawn_blocking(move || staging_store.load(request_id)).await {
        Ok(Ok(entry)) => Ok(entry),
        Ok(Err(StagingError::NotFound { request_id })) => {
            Err(ServerMessage::UnknownStagedPush { request_id })
        }
        Ok(Err(err)) => Err(ServerMessage::Error {
            message: err.to_string(),
        }),
        Err(err) => Err(ServerMessage::Error {
            message: format!("staging load task failed: {err}"),
        }),
    }
}

async fn reject_staged_push<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
    operator: String,
    reason: RejectionReason,
) -> ServerMessage {
    let Some(staging_store) = state.staging_store.clone() else {
        return staging_not_configured();
    };

    if let Some(resp) = validate_operator(&operator) {
        return resp;
    }

    // Verify the staging directory exists before touching the audit
    // log. Matching `show_staged_push`'s ordering lets the two endpoints
    // agree on what "the staging is gone" means and gives the operator
    // a clean `UnknownStagedPush` instead of a trigger-violation error
    // when the dir was already deleted by a prior reject.
    if let Err(resp) = load_staged_entry(&staging_store, request_id).await {
        return resp;
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
    if let Some(resp) = validate_operator(&operator) {
        return resp;
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

    let entry = match load_staged_entry(&staging_store, request_id).await {
        Ok(entry) => entry,
        Err(resp) => return resp,
    };

    let agent_kind = match check_approvable_push(state, request_id).await {
        Ok(agent_kind) => agent_kind,
        Err(resp) => return resp,
    };

    let attempt_id = match start_approve_attempt_row(state, request_id, &operator).await {
        Ok(attempt_id) => attempt_id,
        Err(resp) => return resp,
    };

    let new_app_tip = match execute_started_attempt(
        state,
        attempt_id,
        request_id,
        &operator,
        agent_kind,
        entry,
        &promote_runtime,
        &signing_key,
    )
    .await
    {
        Ok(new_app_tip) => new_app_tip,
        Err(resp) => return resp,
    };

    delete_staging_after_approve(&staging_store, request_id).await;

    ServerMessage::StagedPushApproved {
        request_id,
        new_app_tip,
    }
}

/// Read the joined audit view and confirm the push is approvable,
/// returning the originating session's `agent_kind` (the GitHub App to
/// mint against). Refuses — without starting an attempt — on a prior
/// resolution, a missing `Staged` outcome row, or a branch-creation push
/// (no `expected_remote_head`, which the walker's lease anchor requires).
async fn check_approvable_push<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
) -> Result<Option<crate::core::AgentKind>, ServerMessage> {
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
            return Err(ServerMessage::Error {
                message: format!(
                    "staged push {request_id} has a staging directory but no audit row; \
                     broker audit log and staging store have drifted apart"
                ),
            });
        }
        Ok(Err(err)) => {
            return Err(ServerMessage::Error {
                message: format!("audit lookup failed: {err}"),
            });
        }
        Err(err) => {
            return Err(ServerMessage::Error {
                message: format!("audit lookup task failed: {err}"),
            });
        }
    };

    if audit_entry.resolution.is_some() {
        return Err(ServerMessage::StagedPushAlreadyResolved { request_id });
    }

    if audit_entry.result != Some(GitPushOutcomeResult::Staged) {
        return Err(ServerMessage::Error {
            message: format!(
                "staged push {request_id} has no `staged` outcome row \
                 (audit result: {:?}); refusing to approve a push that is not staged",
                audit_entry.result,
            ),
        });
    }

    if audit_entry.expected_remote_head.is_none() {
        return Err(ServerMessage::Error {
            message: format!(
                "staged push {request_id} is a branch-creation push \
                 (no expected_remote_head); approve does not yet support branch creation"
            ),
        });
    }

    let session_id = audit_entry.session_id;
    let session_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.get_session(session_id)).await
    };
    let session = match session_lookup {
        Ok(Ok(Some(s))) => s,
        Ok(Ok(None)) => {
            return Err(ServerMessage::Error {
                message: format!(
                    "staged push {request_id} references session {session_id} \
                     but that session is not in the audit log"
                ),
            });
        }
        Ok(Err(err)) => {
            return Err(ServerMessage::Error {
                message: format!("session lookup failed: {err}"),
            });
        }
        Err(err) => {
            return Err(ServerMessage::Error {
                message: format!("session lookup task failed: {err}"),
            });
        }
    };

    Ok(session.agent_kind)
}

/// Insert the durable `Started` attempt row that gates concurrent
/// approve/reject. A `Started` row written here survives a crash: the
/// DAO refuses to start a second non-`pre_patch_failure` attempt and the
/// `git_push_resolution_refuses_active_approve` trigger treats `started`
/// as in-flight, so a wedged `Started` row is recovered by boot reconcile
/// (which drives stale `Started` attempts — and `Uncertain` ones past
/// their mint `expires_at` — to `Resolved(PrePatchFailure)`) rather than
/// by manual DB repair.
async fn start_approve_attempt_row<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
    operator: &str,
) -> Result<ApproveAttemptId, ServerMessage> {
    let attempt_id = ApproveAttemptId::new();
    let started_at = UnixMillis::now();
    let start_result = {
        let audit = Arc::clone(&state.audit);
        let operator = operator.to_string();
        tokio::task::spawn_blocking(move || {
            audit.start_approve_attempt(attempt_id, request_id, &operator, started_at)
        })
        .await
    };
    match start_result {
        Ok(Ok(())) => Ok(attempt_id),
        Ok(Err(err)) => {
            // `start_approve_attempt` refuses in three shapes: a prior
            // resolution row exists (the short-circuit in
            // `check_approvable_push` normally catches this, but a race
            // between two concurrent approves can land both past that
            // check before either has inserted), a non-`pre_patch_failure`
            // attempt is active for the same push, or the staged-outcome
            // precondition has gone away under us. All are surfaced as a
            // generic error: the operator (or a future reviewer) reads the
            // audit row to disambiguate.
            Err(ServerMessage::Error {
                message: format!("approve attempt could not be started: {err}"),
            })
        }
        Err(err) => Err(ServerMessage::Error {
            message: format!("approve attempt start task failed: {err}"),
        }),
    }
}

/// Drive a freshly-`Started` attempt to a terminal state and return the
/// new app tip on success. Mints a one-shot installation token, marks the
/// attempt `Uncertain` (the commit point past which a concurrent reject is
/// refused), runs the approve pipeline, and commits the joint
/// success/resolution TX. Every failure path first resolves the attempt
/// through the appropriate `resolve_*_failure` DAO (so the row never stays
/// `Started`/`Uncertain` on a returned error) and then yields the wire
/// `Error` for the caller to return; this is the one place the
/// `attempt_id`/`mint_audit` threading lives.
// `result_large_err`: `ServerMessage` is the wire reply type; this transient
// local Result early-returns it unchanged, so boxing would only add indirection
// at every construction site. `too_many_arguments`: the flat shape matches the
// `run_approve` / run_agent precedent in this crate.
#[allow(clippy::result_large_err, clippy::too_many_arguments)]
async fn execute_started_attempt<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    attempt_id: ApproveAttemptId,
    request_id: RequestId,
    operator: &str,
    agent_kind: Option<crate::core::AgentKind>,
    entry: StagedEntry,
    promote_runtime: &PromoteRuntimeConfig,
    signing_key: &WritSigningKey,
) -> Result<crate::vm_git::GitObjectId, ServerMessage> {
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
        .mint_for_agent(&state.secrets, agent_kind, github_scope, ttl)
        .await;
    let minted = match mint_result {
        Ok(m) => m,
        Err(err) => {
            let detail = format!("mint failed: {}", err.agent_message());
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, None).await;
            return Err(ServerMessage::Error {
                message: format!("approve-time mint failed: {}", err.agent_message()),
            });
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
            return Err(ServerMessage::Error {
                message: format!("approve-time mint produced an unusable token: {err}"),
            });
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
            return Err(ServerMessage::Error {
                message: format!("approve attempt could not enter Uncertain: {err}"),
            });
        }
        Err(err) => {
            let detail = format!("mark_attempt_uncertain task failed: {err}");
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, Some(mint_audit))
                .await;
            return Err(ServerMessage::Error {
                message: format!("approve attempt Uncertain task failed: {err}"),
            });
        }
    }

    let receipt = entry.receipt();
    let repo = receipt.repo().clone();
    let branch = receipt.branch().clone();
    let expected_remote_head = receipt
        .expected_remote_head()
        .cloned()
        .expect("expected_remote_head presence was checked by check_approvable_push");
    let bundle_tip = receipt.new_head().clone();
    let (_, bundle_bytes) = entry.into_parts();

    let run_result = run_approve(
        promote_runtime,
        &api_base,
        &token,
        &repo,
        &branch,
        &expected_remote_head,
        &bundle_tip,
        &bundle_bytes,
        signing_key,
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
                    return Err(ServerMessage::Error {
                        message: truncate_for_wire(
                            format!(
                                "approve pipeline issued update_ref against GitHub but the \
                                 response could not be confirmed; staged push {request_id} is \
                                 quarantined and must be reconciled manually: {err}"
                            ),
                            MAX_WIRE_ERROR_BYTES,
                        ),
                    });
                }
                _ => {
                    resolve_pre_patch_failure(state, attempt_id, request_id, &detail, None).await;
                    let message = match &err {
                        RunApproveError::Prepare(_) => format!("staging preparation failed: {err}"),
                        _ => format!("approve pipeline failed: {err}"),
                    };
                    return Err(ServerMessage::Error {
                        message: truncate_for_wire(message, MAX_WIRE_ERROR_BYTES),
                    });
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
        let operator = operator.to_string();
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
            return Err(ServerMessage::Error {
                message: format!(
                    "branch was advanced on GitHub (new_app_tip = {new_app_tip}) but the audit \
                     resolution row could not be committed: {err}"
                ),
            });
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
            return Err(ServerMessage::Error {
                message: format!("approve resolution task failed: {err}"),
            });
        }
    }

    Ok(new_app_tip)
}

/// Best-effort staging-dir delete after the approve resolution row is
/// committed. A stale dir surfaces in `promote list` for manual cleanup
/// and cannot cause a contradictory reject because the resolution row is
/// already in place, so failures are logged, not surfaced.
async fn delete_staging_after_approve(
    staging_store: &Arc<GitPushStagingStore>,
    request_id: RequestId,
) {
    let delete_result = {
        let staging_store = Arc::clone(staging_store);
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
    if let Some(resp) = validate_operator(&operator) {
        return resp;
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
    if let Err(resp) = load_staged_entry(&staging_store, request_id).await {
        return resp;
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
mod capability_tests;
#[cfg(test)]
mod reconcile_tests;
#[cfg(test)]
mod run_agent_tests;
#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod staged_push_approve_tests;
#[cfg(test)]
mod staged_push_list_tests;
#[cfg(test)]
mod staged_push_reject_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod transport_tests;
