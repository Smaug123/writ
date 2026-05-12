//! Unix socket listener and request dispatcher.
//!
//! The broker serves one connection at a time within each tokio task.
//! Requests from different panes arrive on different connections and are
//! multiplexed by the tokio scheduler; per-connection processing is
//! strictly sequential (one line in → one line out).
//!
//! The testable core is [`dispatch_message`]: it takes a [`ClientMessage`]
//! and shared broker state, and returns a [`ServerMessage`]. Socket I/O
//! lives in [`handle_connection`] and only calls [`dispatch_message`].
//! All tests exercise [`dispatch_message`] directly.

use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::agent_plan::{CorrelationId, Decider, DecisionOutcome, PlanId};
use crate::agent_vm_daemon::AgentVmDaemon;
use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditLog, GitPushResolution, GitPushResolutionRecord,
    PlanDecisionRecord, PreMintRecord,
};
use crate::core::{
    CapabilityRequest, GrantedScope, PolicyDecision, RequestId, SessionId, SessionRecord,
    TtlSeconds, UnixMillis,
};
use crate::git_push_staging::{GitPushStagingStore, StagedEntry, StagingError};
use crate::github::GitHubMinter;
use crate::policy::{self, PolicyConfig};
use crate::protocol::{
    ClientMessage, PlanDetail, PlanSummary, RejectionReason, ServerMessage, StagedPushAuditView,
    StagedPushDetail, StagedPushSummary,
};
use crate::secret::SecretStore;

/// Shared state for the broker. Wrapped in `Arc` so connections spawned
/// onto different tokio tasks can all reference the same audit log,
/// minter config, and secret store.
///
/// `staging_store` is `Some` exactly when the daemon was configured with
/// agent-VM HTTP support (the staging root lives under `vm_http`).
/// Promote operations fail with a configuration error when it is `None`.
pub struct BrokerState<S: SecretStore> {
    pub audit: Arc<AuditLog>,
    pub minter: GitHubMinter,
    pub secrets: S,
    pub policy: PolicyConfig,
    pub staging_store: Option<Arc<GitPushStagingStore>>,
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
            stage,
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
                        stage,
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
        ClientMessage::ListStagedPushes {} => list_staged_pushes(state).await,
        ClientMessage::ShowStagedPush { request_id } => show_staged_push(state, request_id).await,
        ClientMessage::RejectStagedPush {
            request_id,
            operator,
            reason,
        } => reject_staged_push(state, request_id, operator, reason).await,
        ClientMessage::ListPlans { correlation_id } => list_plans(state, correlation_id).await,
        ClientMessage::ShowPlan { plan_id } => show_plan(state, plan_id).await,
        ClientMessage::DecidePlan {
            plan_id,
            outcome,
            decider,
        } => decide_plan(state, plan_id, outcome, decider).await,
    }
}

async fn list_staged_pushes<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
) -> ServerMessage {
    let Some(staging_store) = state.staging_store.clone() else {
        return staging_not_configured();
    };
    // The staging store is sync; hop it off the async runtime so a
    // directory-walk on a slow filesystem doesn't block other connections.
    let result = tokio::task::spawn_blocking(move || staging_store.list()).await;
    match result {
        Ok(Ok(receipts)) => {
            let pushes = receipts
                .iter()
                .map(StagedPushSummary::from_receipt)
                .collect();
            ServerMessage::StagedPushes { pushes }
        }
        Ok(Err(err)) => ServerMessage::Error {
            message: err.to_string(),
        },
        Err(err) => ServerMessage::Error {
            message: format!("staging list task failed: {err}"),
        },
    }
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

async fn list_plans<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    correlation_id: Option<CorrelationId>,
) -> ServerMessage {
    let audit = Arc::clone(&state.audit);
    let result =
        tokio::task::spawn_blocking(move || audit.list_plans(correlation_id.as_ref())).await;
    match result {
        Ok(Ok(entries)) => {
            let plans = entries
                .into_iter()
                .map(|e| PlanSummary {
                    plan_id: e.plan_id,
                    agent_run_id: e.agent_run_id,
                    correlation_id: e.correlation_id,
                    submitted_at: e.submitted_at,
                    body_sha256: e.body_sha256,
                    body_bytes: e.body_bytes,
                })
                .collect();
            ServerMessage::Plans { plans }
        }
        Ok(Err(err)) => ServerMessage::Error {
            message: err.to_string(),
        },
        Err(err) => ServerMessage::Error {
            message: format!("plan list task failed: {err}"),
        },
    }
}

async fn show_plan<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    plan_id: PlanId,
) -> ServerMessage {
    let audit = Arc::clone(&state.audit);
    let plan_lookup = tokio::task::spawn_blocking(move || audit.get_plan(plan_id)).await;
    let plan = match plan_lookup {
        Ok(Ok(Some(plan))) => plan,
        Ok(Ok(None)) => return ServerMessage::UnknownPlan { plan_id },
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: err.to_string(),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("plan lookup task failed: {err}"),
            };
        }
    };

    // Join correlation_id from the planner's agent_run. The plan row has
    // a foreign-key onto agent_run so `Ok(None)` would be an invariant
    // violation; surface it explicitly rather than fabricating a value.
    let run_id = plan.agent_run_id;
    let correlation_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.correlation_id_for_run(run_id)).await
    };
    let correlation_id = match correlation_lookup {
        Ok(Ok(Some(value))) => value,
        Ok(Ok(None)) => {
            return ServerMessage::Error {
                message: format!(
                    "plan {plan_id} references agent_run {run_id} which has no audit row; \
                     broker state is corrupt",
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
                message: format!("correlation_id lookup task failed: {err}"),
            };
        }
    };

    let body_sha256 = plan.body.sha256_hex();
    let body_bytes = plan.body.byte_len();
    let summary = PlanSummary {
        plan_id: plan.plan_id,
        agent_run_id: plan.agent_run_id,
        correlation_id,
        submitted_at: plan.submitted_at,
        body_sha256,
        body_bytes,
    };
    ServerMessage::Plan {
        plan: PlanDetail {
            summary,
            body: plan.body,
        },
    }
}

/// Record an operator decision against a plan.
///
/// Look up the plan first so the "no such plan" case surfaces as a
/// dedicated [`ServerMessage::UnknownPlan`] reply rather than collapsing
/// into a generic error. The lookup is race-free against the second
/// write: plans are append-only in the schema (no `DELETE` path), so a
/// plan that exists now will still exist when the decision insert runs.
///
/// A second decision against the same plan trips the PRIMARY KEY on
/// `plan_decision.plan_id`; that surfaces as
/// [`ServerMessage::PlanAlreadyDecided`] via the same
/// [`is_unique_constraint_violation`] helper the staged-push reject path
/// uses, so a replay is a clean wire-level outcome instead of a prose
/// error string.
async fn decide_plan<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    plan_id: PlanId,
    outcome: DecisionOutcome,
    decider: Decider,
) -> ServerMessage {
    let plan_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.get_plan(plan_id)).await
    };
    match plan_lookup {
        Ok(Ok(Some(_))) => {}
        Ok(Ok(None)) => return ServerMessage::UnknownPlan { plan_id },
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: err.to_string(),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("plan lookup task failed: {err}"),
            };
        }
    }

    let decided_at = UnixMillis::now();
    let audit = Arc::clone(&state.audit);
    let result = tokio::task::spawn_blocking(move || {
        audit.record_plan_decision(&PlanDecisionRecord {
            plan_id,
            decided_at,
            outcome,
            decider,
        })
    })
    .await;
    match result {
        Ok(Ok(())) => ServerMessage::PlanDecided { plan_id },
        Ok(Err(err)) => {
            if is_unique_constraint_violation(&err) {
                return ServerMessage::PlanAlreadyDecided { plan_id };
            }
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "plan_decision",
                plan_id = %plan_id,
                error = %err,
                "audit write failed: plan decision not recorded",
            );
            ServerMessage::Error {
                message: err.to_string(),
            }
        }
        Err(err) => ServerMessage::Error {
            message: format!("audit write task failed: {err}"),
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
    if prior_decision != Some(GitPushResolution::Rejected) {
        return;
    }
    let staging_store = Arc::clone(staging_store);
    let delete_outcome =
        tokio::task::spawn_blocking(move || staging_store.delete(request_id)).await;
    if let Ok(Err(err)) = delete_outcome {
        tracing::warn!(
            request_id = %request_id,
            error = %err,
            "duplicate-reject cleanup retry failed; staging dir may still be present",
        );
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

fn staging_not_configured() -> ServerMessage {
    ServerMessage::Error {
        message: "git push staging is not configured; \
                  the broker config needs an agent_vm.vm_http section"
            .into(),
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
/// An honest ClientMessage is a few hundred bytes (a long label plus a
/// GitHubRequest); 64 KiB is three orders of magnitude above that. The
/// cap exists so a peer that opens a connection and writes
/// non-newline-terminated data can't make the broker allocate without
/// bound — without it, `read_until(b'\n')` grows the buffer until the
/// process OOMs.
const MAX_LINE_BYTES: usize = 64 * 1024;

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

    let listener = bind_socket(socket_path).await?;
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
        let mut state = make_state(server, vec![], "o");
        let inner = Arc::get_mut(&mut state).expect("fresh Arc has no other handles");
        inner.staging_store = Some(Arc::new(store));
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
                push_attempt_id: None,
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
        let resp = dispatch_message(ClientMessage::ListStagedPushes {}, &state).await;
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
        let resp = dispatch_message(ClientMessage::ListStagedPushes {}, &state).await;
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

        let resp = dispatch_message(ClientMessage::ListStagedPushes {}, &state).await;
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

    // --- Plan listing / show -------------------------------------------

    /// Record a planner `agent_run` + a plan submission against the
    /// given session, returning `(run_id, plan_id, body)`. Mirrors the
    /// vm_http flow without going through the HTTP layer.
    async fn record_planner_run_and_plan(
        state: &Arc<BrokerState<InMemStore>>,
        session_id: SessionId,
        correlation_id: Option<crate::agent_plan::CorrelationId>,
        body_text: &str,
        submitted_at: UnixMillis,
    ) -> (crate::agent_run::AgentRunId, crate::agent_plan::PlanId) {
        let run_id = crate::agent_run::AgentRunId::new();
        let plan_id = crate::agent_plan::PlanId::new();
        let body = crate::agent_plan::PlanBody::try_new(body_text).unwrap();
        let prompt = crate::agent_run::AgentPrompt::new("plan this").summary();
        state
            .audit
            .record_agent_run(&crate::audit::AgentRunAuditRecord {
                run_id,
                session_id,
                requested_at: UnixMillis::from_millis(1_700_000_000),
                agent_kind: AgentKind::Claude,
                prompt,
                correlation_id,
                stage: crate::agent_plan::Stage::Plan,
                read_plan_id: None,
            })
            .unwrap();
        state
            .audit
            .record_plan_submission(&crate::audit::PlanSubmissionRecord {
                plan_id,
                agent_run_id: run_id,
                submitted_at,
                body,
            })
            .unwrap();
        (run_id, plan_id)
    }

    #[tokio::test]
    async fn list_plans_with_no_plans_returns_empty_listing() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let resp = dispatch_message(
            ClientMessage::ListPlans {
                correlation_id: None,
            },
            &state,
        )
        .await;
        assert_eq!(resp, ServerMessage::Plans { plans: vec![] });
    }

    #[tokio::test]
    async fn list_plans_returns_summaries_ordered_by_submitted_at() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let session_id = open_session(&state).await;
        let (_, plan_old) = record_planner_run_and_plan(
            &state,
            session_id,
            None,
            "# old",
            UnixMillis::from_millis(1_700_000_300),
        )
        .await;
        let (_, plan_new) = record_planner_run_and_plan(
            &state,
            session_id,
            None,
            "# even newer plan",
            UnixMillis::from_millis(1_700_000_400),
        )
        .await;
        let resp = dispatch_message(
            ClientMessage::ListPlans {
                correlation_id: None,
            },
            &state,
        )
        .await;
        let plans = match resp {
            ServerMessage::Plans { plans } => plans,
            other => panic!("expected Plans, got {other:?}"),
        };
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].plan_id, plan_old);
        assert_eq!(plans[0].submitted_at.as_millis(), 1_700_000_300);
        assert_eq!(plans[1].plan_id, plan_new);
        assert_eq!(plans[1].submitted_at.as_millis(), 1_700_000_400);
        // Body bytes is the verbatim source length.
        assert_eq!(plans[0].body_bytes, "# old".len() as u64);
        assert_eq!(plans[1].body_bytes, "# even newer plan".len() as u64);
    }

    #[tokio::test]
    async fn list_plans_filters_by_correlation_id() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let session_id = open_session(&state).await;
        let target = crate::agent_plan::CorrelationId::try_new("feat-42_xyz").unwrap();
        let (_, plan_target) = record_planner_run_and_plan(
            &state,
            session_id,
            Some(target.clone()),
            "# target",
            UnixMillis::from_millis(1_700_000_200),
        )
        .await;
        record_planner_run_and_plan(
            &state,
            session_id,
            None,
            "# unrelated",
            UnixMillis::from_millis(1_700_000_300),
        )
        .await;

        let resp = dispatch_message(
            ClientMessage::ListPlans {
                correlation_id: Some(target.clone()),
            },
            &state,
        )
        .await;
        let plans = match resp {
            ServerMessage::Plans { plans } => plans,
            other => panic!("expected Plans, got {other:?}"),
        };
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].plan_id, plan_target);
        assert_eq!(plans[0].correlation_id.as_ref(), Some(&target));
    }

    #[tokio::test]
    async fn show_plan_for_unknown_plan_id_returns_unknown_plan() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let plan_id = crate::agent_plan::PlanId::new();
        let resp = dispatch_message(ClientMessage::ShowPlan { plan_id }, &state).await;
        assert_eq!(resp, ServerMessage::UnknownPlan { plan_id });
    }

    #[tokio::test]
    async fn show_plan_returns_detail_with_body_and_joined_correlation_id() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let session_id = open_session(&state).await;
        let target = crate::agent_plan::CorrelationId::try_new("feat-7_abc").unwrap();
        let body_text = "# Plan\n\nDo the thing.";
        let (run_id, plan_id) = record_planner_run_and_plan(
            &state,
            session_id,
            Some(target.clone()),
            body_text,
            UnixMillis::from_millis(1_700_000_200),
        )
        .await;

        let resp = dispatch_message(ClientMessage::ShowPlan { plan_id }, &state).await;
        let detail = match resp {
            ServerMessage::Plan { plan } => plan,
            other => panic!("expected Plan, got {other:?}"),
        };
        assert_eq!(detail.summary.plan_id, plan_id);
        assert_eq!(detail.summary.agent_run_id, run_id);
        assert_eq!(detail.summary.correlation_id.as_ref(), Some(&target));
        assert_eq!(detail.summary.body_bytes, body_text.len() as u64);
        assert_eq!(detail.body.as_str(), body_text);
    }

    /// A plan submitted under a run with no correlation id surfaces
    /// `Some(None)` from `correlation_id_for_run`, which the handler
    /// flattens to `None` on the wire.
    #[tokio::test]
    async fn show_plan_for_untagged_run_returns_none_correlation_id() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let session_id = open_session(&state).await;
        let (_, plan_id) = record_planner_run_and_plan(
            &state,
            session_id,
            None,
            "# untagged",
            UnixMillis::from_millis(1_700_000_200),
        )
        .await;

        let resp = dispatch_message(ClientMessage::ShowPlan { plan_id }, &state).await;
        let detail = match resp {
            ServerMessage::Plan { plan } => plan,
            other => panic!("expected Plan, got {other:?}"),
        };
        assert!(detail.summary.correlation_id.is_none());
    }

    #[tokio::test]
    async fn decide_plan_for_unknown_plan_id_returns_unknown_plan() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let plan_id = crate::agent_plan::PlanId::new();
        let resp = dispatch_message(
            ClientMessage::DecidePlan {
                plan_id,
                outcome: DecisionOutcome::Accepted,
                decider: Decider::try_new("cli:alice").unwrap(),
            },
            &state,
        )
        .await;
        assert_eq!(resp, ServerMessage::UnknownPlan { plan_id });
        // The audit log gained no row from the rejected call.
        let stored = state.audit.get_plan_decision(plan_id).unwrap();
        assert!(
            stored.is_none(),
            "unknown-plan dispatch must not persist a row, got {stored:?}",
        );
    }

    #[tokio::test]
    async fn decide_plan_records_audit_row_for_every_outcome() {
        for outcome in [DecisionOutcome::Accepted, DecisionOutcome::RejectedRestart] {
            let server = MockServer::start().await;
            let state = make_state(&server, vec![], "o");
            let session_id = open_session(&state).await;
            let (_, plan_id) = record_planner_run_and_plan(
                &state,
                session_id,
                None,
                "# plan",
                UnixMillis::from_millis(1_700_000_200),
            )
            .await;

            let resp = dispatch_message(
                ClientMessage::DecidePlan {
                    plan_id,
                    outcome,
                    decider: Decider::try_new("cli:alice").unwrap(),
                },
                &state,
            )
            .await;
            assert_eq!(resp, ServerMessage::PlanDecided { plan_id });

            // The audit row landed with exactly the wire-supplied outcome
            // and decider.
            let stored = state
                .audit
                .get_plan_decision(plan_id)
                .unwrap()
                .expect("decision row should exist");
            assert_eq!(stored.plan_id, plan_id);
            assert_eq!(stored.outcome, outcome);
            assert_eq!(stored.decider.as_str(), "cli:alice");
        }
    }

    /// A second `DecidePlan` for the same plan must surface as
    /// `PlanAlreadyDecided` — the PK collision on `plan_decision.plan_id`
    /// is what makes the broker idempotent for replays. The audit row's
    /// original outcome and decider stay unchanged.
    #[tokio::test]
    async fn decide_plan_second_call_for_same_plan_returns_plan_already_decided() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let session_id = open_session(&state).await;
        let (_, plan_id) = record_planner_run_and_plan(
            &state,
            session_id,
            None,
            "# plan",
            UnixMillis::from_millis(1_700_000_200),
        )
        .await;

        let first = dispatch_message(
            ClientMessage::DecidePlan {
                plan_id,
                outcome: DecisionOutcome::Accepted,
                decider: Decider::try_new("cli:alice").unwrap(),
            },
            &state,
        )
        .await;
        assert_eq!(first, ServerMessage::PlanDecided { plan_id });

        let second = dispatch_message(
            ClientMessage::DecidePlan {
                plan_id,
                outcome: DecisionOutcome::RejectedRestart,
                decider: Decider::try_new("cli:bob").unwrap(),
            },
            &state,
        )
        .await;
        assert_eq!(second, ServerMessage::PlanAlreadyDecided { plan_id });

        // The original decision stands; the replay did not overwrite it.
        let stored = state
            .audit
            .get_plan_decision(plan_id)
            .unwrap()
            .expect("decision row should exist");
        assert_eq!(stored.outcome, DecisionOutcome::Accepted);
        assert_eq!(stored.decider.as_str(), "cli:alice");
    }

    /// Operator decisions are deliberately cross-session: an operator
    /// may decide on a plan whose planner session is long since closed.
    /// The dispatch handler must accept the call without resurrecting
    /// the session.
    #[tokio::test]
    async fn decide_plan_succeeds_after_planner_session_closes() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let session_id = open_session(&state).await;
        let (_, plan_id) = record_planner_run_and_plan(
            &state,
            session_id,
            None,
            "# plan",
            UnixMillis::from_millis(1_700_000_200),
        )
        .await;
        state
            .audit
            .close_session(session_id, UnixMillis::from_millis(1_700_000_300))
            .unwrap();

        let resp = dispatch_message(
            ClientMessage::DecidePlan {
                plan_id,
                outcome: DecisionOutcome::Accepted,
                decider: Decider::try_new("cli:alice").unwrap(),
            },
            &state,
        )
        .await;
        assert_eq!(resp, ServerMessage::PlanDecided { plan_id });
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

        // Write > MAX_LINE_BYTES non-newline bytes, then a newline.
        let oversize = vec![b'x'; MAX_LINE_BYTES + 1];
        writer.write_all(&oversize).await.unwrap();
        writer.write_all(b"\n").await.unwrap();

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
        let l = bind_socket(&sock).await.unwrap();
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
