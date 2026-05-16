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

use crate::agent_plan::{
    CorrelationId, Decider, DecisionOutcome, DecisionView, PlanId, check_start_agent_run_binding,
};
use crate::agent_run::{AgentPrompt, AgentRunId, sha256_hex};
use crate::agent_vm_daemon::AgentVmDaemon;
use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, AuditLog, GitPushResolution, GitPushResolutionRecord,
    PlanDecisionRecord, PreMintRecord,
};
use crate::core::{
    CapabilityRequest, GrantedScope, PolicyDecision, RequestId, SessionId, SessionRecord,
    TtlSeconds, UnixMillis,
};
use crate::core::{NotesRef, Sha256Hex};
use crate::git_push_staging::{GitPushStagingStore, StagedEntry, StagingError};
use crate::github::GitHubMinter;
use crate::notes_repo::NotesRepo;
use crate::policy::{self, PolicyConfig};
use crate::protocol::{
    ClientMessage, PlanAbortView, PlanAddendumView, PlanDetail, PlanReviewView, PlanSummary,
    RejectionReason, ServerMessage, SignedRunMetadata, StagedPushAuditView, StagedPushDetail,
    StagedPushSummary,
};
use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use crate::secret::SecretStore;
use crate::signing::WritSigningKey;

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
pub struct BrokerState<S: SecretStore> {
    pub audit: Arc<AuditLog>,
    pub minter: GitHubMinter,
    pub secrets: S,
    pub policy: PolicyConfig,
    pub staging_store: Option<Arc<GitPushStagingStore>>,
    pub notes_repo: Option<Arc<NotesRepo>>,
    pub signing_key: Option<WritSigningKey>,
    pub run_agent_spawn: Option<RunAgentSpawnConfig>,
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
            read_plan_id,
        } => {
            if let Err(err) = check_start_agent_run_binding(stage, read_plan_id.is_some()) {
                return ServerMessage::Error {
                    message: err.to_string(),
                };
            }
            match agent_vm {
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
                            read_plan_id,
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
            }
        }
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
        ClientMessage::RunAgent {
            prompt,
            capabilities,
            purpose,
            output_ref,
            session_id,
        } => run_agent(state, prompt, capabilities, purpose, output_ref, session_id).await,
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
    // All five audit lookups land in one blocking task. SQLite serialises
    // on the connection anyway, so fanning them out would not parallelise;
    // a single task is simpler (one error ladder, one `JoinError`).
    let audit = Arc::clone(&state.audit);
    let joined = tokio::task::spawn_blocking(move || -> Result<ShowPlanLookup, AuditError> {
        let Some(plan) = audit.get_plan(plan_id)? else {
            return Ok(ShowPlanLookup::Unknown);
        };
        let run_id = plan.agent_run_id;
        // The plan row has a FOREIGN KEY onto agent_run, so the *outer*
        // `Option::None` here would be an invariant violation (no such
        // agent_run row). The *inner* `Option::None` means the planner
        // run exists but is untagged, which is a normal "no
        // correlation" outcome and passes through to the summary.
        let Some(correlation_id) = audit.correlation_id_for_run(run_id)? else {
            return Ok(ShowPlanLookup::MissingCorrelation { run_id });
        };
        let reviews = audit.list_plan_reviews_for_plan(plan_id)?;
        let decision = audit.get_plan_decision(plan_id)?;
        let addenda = audit.list_plan_addenda_for_plan(plan_id)?;
        let abort = audit.get_plan_abort(plan_id)?;
        Ok(ShowPlanLookup::Found {
            plan,
            correlation_id,
            reviews,
            decision,
            addenda,
            abort,
        })
    })
    .await;
    let (plan, correlation_id, reviews, decision, addenda, abort) = match joined {
        Ok(Ok(ShowPlanLookup::Found {
            plan,
            correlation_id,
            reviews,
            decision,
            addenda,
            abort,
        })) => (plan, correlation_id, reviews, decision, addenda, abort),
        Ok(Ok(ShowPlanLookup::Unknown)) => return ServerMessage::UnknownPlan { plan_id },
        Ok(Ok(ShowPlanLookup::MissingCorrelation { run_id })) => {
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
                message: format!("plan lookup task failed: {err}"),
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
    let reviews: Vec<PlanReviewView> = reviews
        .into_iter()
        .map(|r| PlanReviewView {
            review_id: r.review_id,
            reviewer_run_id: r.agent_run_id,
            submitted_at: r.submitted_at,
            verdict: r.verdict,
            feedback: r.feedback,
        })
        .collect();
    let addenda: Vec<PlanAddendumView> = addenda
        .into_iter()
        .map(|r| PlanAddendumView {
            addendum_id: r.addendum_id,
            executor_run_id: r.agent_run_id,
            submitted_at: r.submitted_at,
            body: r.body,
        })
        .collect();
    let decision = decision.map(|r| DecisionView {
        outcome: r.outcome,
        decided_at: r.decided_at,
    });
    let abort = abort.map(|r| PlanAbortView {
        executor_run_id: r.agent_run_id,
        aborted_at: r.aborted_at,
        reason: r.reason,
    });
    ServerMessage::Plan {
        plan: PlanDetail {
            summary,
            body: plan.body,
            reviews,
            decision,
            addenda,
            abort,
        },
    }
}

/// Outcome of the combined `show_plan` audit task. Separating the three
/// "look-up succeeded" shapes from the `AuditError`/`JoinError` paths
/// keeps the outer match small and lets the blocking closure use
/// `?` for IO failures.
///
/// The `Found` variant carries the full joined audit state for one
/// plan; it is several hundred bytes wide while the other variants
/// are near-empty. The asymmetry is fine here because the value is
/// constructed and matched once in `show_plan` and immediately
/// destructured into named locals — there is no storage of this enum
/// in any collection where the per-variant slack would matter.
#[allow(clippy::large_enum_variant)]
enum ShowPlanLookup {
    Unknown,
    MissingCorrelation {
        run_id: crate::agent_run::AgentRunId,
    },
    Found {
        plan: crate::audit::PlanSubmissionRecord,
        correlation_id: Option<CorrelationId>,
        reviews: Vec<crate::audit::PlanReviewRecord>,
        decision: Option<PlanDecisionRecord>,
        addenda: Vec<crate::audit::PlanAddendumRecord>,
        abort: Option<crate::audit::PlanAbortRecord>,
    },
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

/// Per-stream byte cap for stdout/stderr capture in [`run_agent`].
///
/// A signed envelope embeds the captured bytes, so an agent that
/// emits unbounded output would otherwise let one `RunAgent` call
/// exhaust writd's memory (the JSON+base64 wrapper makes a second
/// in-memory copy on top of the captured buffer). Capping at 4 MiB
/// keeps the per-call footprint bounded; the `truncated_at` marker on
/// `OutputEnvelope` records the cap so verifiers know the capture is
/// a prefix rather than the whole stream.
const MAX_RUN_AGENT_STREAM_BYTES: usize = 4 * 1024 * 1024;

/// Read `reader` to EOF, retaining at most `cap` bytes. After the cap
/// is hit, further bytes are drained and discarded so the child does
/// not block writing to a full pipe. The returned `truncated_at` is
/// `Some(cap)` iff any bytes were dropped — `None` means the entire
/// stream fit. The cap is byte-aligned to whatever the underlying read
/// returned; we do not bisect a single read across the boundary.
async fn capture_stream_capped<R>(
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
async fn run_agent<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    prompt: AgentPrompt,
    capabilities: Vec<crate::core::CapabilitySet>,
    purpose: String,
    output_ref: NotesRef,
    request_session_id: Option<SessionId>,
) -> ServerMessage {
    // `purpose` is part of the wire contract and will land on the
    // audit row in the follow-up slice. Holding the name in scope (not
    // discarding via `_`) keeps the future plumbing self-evident.
    let _purpose = purpose;

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
        });

        let resp = dispatch_message(
            ClientMessage::RunAgent {
                prompt: crate::agent_run::AgentPrompt::new("ignored"),
                capabilities: Vec::new(),
                purpose: "non-zero-exit".into(),
                output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs")
                    .unwrap(),
                session_id: None,
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

    /// A `review`-stage `StartAgentRun` with no `read_plan_id` is
    /// incoherent: every plan route a reviewer needs gates on
    /// `agent_run.read_plan_id = <plan_id>`, so binding to NULL
    /// produces a VM that can never satisfy authorisation. The
    /// broker must refuse before opening any session or audit row.
    /// The check sits in front of the agent-VM-runtime branch so
    /// the error surfaces even when no daemon is configured —
    /// callers learn what is wrong with the request, not what is
    /// wrong with the broker.
    #[tokio::test]
    async fn start_agent_run_review_without_read_plan_id_is_rejected() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");

        let resp = dispatch_message(
            ClientMessage::StartAgentRun {
                label: None,
                agent_kind: AgentKind::Claude,
                agent_model: "claude-test".into(),
                workspace: crate::vm_git::AgentVmWorkspaceBootstrap {
                    repo: sample_clone_repo(),
                    destination: None,
                    warm: crate::vm_git::WorkspaceWarmMode::None,
                },
                prompt: crate::agent_run::AgentPrompt::new("p"),
                stage: crate::agent_plan::Stage::Review,
                correlation_id: None,
                read_plan_id: None,
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("review") && message.contains("read_plan_id"),
                    "got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Symmetric to the review case: a `plan`-stage run that
    /// carries `read_plan_id` is incoherent (planner runs create
    /// plans, they do not read one), and is rejected for the same
    /// reason — the broker has no route that honours such a row,
    /// so persisting it would be silent rot.
    #[tokio::test]
    async fn start_agent_run_plan_with_read_plan_id_is_rejected() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");

        let resp = dispatch_message(
            ClientMessage::StartAgentRun {
                label: None,
                agent_kind: AgentKind::Claude,
                agent_model: "claude-test".into(),
                workspace: crate::vm_git::AgentVmWorkspaceBootstrap {
                    repo: sample_clone_repo(),
                    destination: None,
                    warm: crate::vm_git::WorkspaceWarmMode::None,
                },
                prompt: crate::agent_run::AgentPrompt::new("p"),
                stage: crate::agent_plan::Stage::Plan,
                correlation_id: None,
                read_plan_id: Some(PlanId::new()),
            },
            &state,
        )
        .await;

        match resp {
            ServerMessage::Error { message } => {
                assert!(
                    message.contains("plan") && message.contains("read_plan_id"),
                    "got: {message}",
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
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

    /// Record an `Accepted` decision against `plan_id`. Addenda are
    /// schema-gated on an accepted decision, so the surfacing tests
    /// land this row before each addendum.
    async fn accept_plan(
        state: &Arc<BrokerState<InMemStore>>,
        plan_id: crate::agent_plan::PlanId,
        decided_at: UnixMillis,
    ) {
        state
            .audit
            .record_plan_decision(&crate::audit::PlanDecisionRecord {
                plan_id,
                decided_at,
                outcome: DecisionOutcome::Accepted,
                decider: Decider::try_new("cli:test").unwrap(),
            })
            .unwrap();
    }

    /// Record an executor `agent_run` and the matching `plan_addendum`
    /// row, returning the new `AddendumId`. The executor run is bound
    /// to `plan_id` via `read_plan_id` and tagged `stage = Execute` so
    /// the schema-side addendum precondition trigger is satisfied.
    /// `plan_id` must already carry an `Accepted` decision (see
    /// [`accept_plan`]) — the addendum trigger refuses the insert
    /// otherwise.
    async fn record_executor_run_and_addendum(
        state: &Arc<BrokerState<InMemStore>>,
        session_id: SessionId,
        plan_id: crate::agent_plan::PlanId,
        submitted_at: UnixMillis,
        body_text: &str,
    ) -> crate::agent_plan::AddendumId {
        let executor_run = crate::agent_run::AgentRunId::new();
        let addendum_id = crate::agent_plan::AddendumId::new();
        let body = crate::agent_plan::PlanBody::try_new(body_text).unwrap();
        state
            .audit
            .record_agent_run(&crate::audit::AgentRunAuditRecord {
                run_id: executor_run,
                session_id,
                requested_at: UnixMillis::from_millis(1_700_000_000),
                agent_kind: AgentKind::Claude,
                prompt: crate::agent_run::AgentPrompt::new("execute this plan").summary(),
                correlation_id: None,
                stage: crate::agent_plan::Stage::Execute,
                read_plan_id: Some(plan_id),
            })
            .unwrap();
        state
            .audit
            .record_plan_addendum(&crate::audit::PlanAddendumRecord {
                addendum_id,
                plan_id,
                agent_run_id: executor_run,
                submitted_at,
                body,
            })
            .unwrap();
        addendum_id
    }

    /// Record an executor `agent_run` and the matching `plan_abort`
    /// row, returning the abort's `agent_run_id`. The executor run is
    /// bound to `plan_id` via `read_plan_id`, mirroring the broker
    /// invariant that execute-stage runs cite the plan they are
    /// executing. Unlike `record_executor_run_and_addendum`, the abort
    /// does not require the plan to have been accepted — the abort
    /// route deliberately bypasses the acceptance gate.
    async fn record_executor_run_and_abort(
        state: &Arc<BrokerState<InMemStore>>,
        session_id: SessionId,
        plan_id: crate::agent_plan::PlanId,
        aborted_at: UnixMillis,
        reason_text: &str,
    ) -> crate::agent_run::AgentRunId {
        let executor_run = crate::agent_run::AgentRunId::new();
        let reason = crate::agent_plan::PlanAbortReason::try_new(reason_text).unwrap();
        state
            .audit
            .record_agent_run(&crate::audit::AgentRunAuditRecord {
                run_id: executor_run,
                session_id,
                requested_at: UnixMillis::from_millis(1_700_000_000),
                agent_kind: AgentKind::Claude,
                prompt: crate::agent_run::AgentPrompt::new("execute this plan").summary(),
                correlation_id: None,
                stage: crate::agent_plan::Stage::Execute,
                read_plan_id: Some(plan_id),
            })
            .unwrap();
        state
            .audit
            .record_plan_abort(&crate::audit::PlanAbortRecord {
                plan_id,
                agent_run_id: executor_run,
                aborted_at,
                reason,
            })
            .unwrap();
        executor_run
    }

    /// Record a reviewer `agent_run` and the matching `plan_review`
    /// row, returning the new `ReviewId`. The reviewer run is bound to
    /// `plan_id` via `read_plan_id`, mirroring the broker invariant
    /// that review-stage runs always cite the plan they review.
    async fn record_review_run_and_review(
        state: &Arc<BrokerState<InMemStore>>,
        session_id: SessionId,
        plan_id: crate::agent_plan::PlanId,
        submitted_at: UnixMillis,
        verdict: crate::agent_plan::Verdict,
        feedback: Option<crate::agent_plan::PlanFeedback>,
    ) -> crate::agent_plan::ReviewId {
        let reviewer_run = crate::agent_run::AgentRunId::new();
        let review_id = crate::agent_plan::ReviewId::new();
        state
            .audit
            .record_agent_run(&crate::audit::AgentRunAuditRecord {
                run_id: reviewer_run,
                session_id,
                requested_at: UnixMillis::from_millis(1_700_000_000),
                agent_kind: AgentKind::Claude,
                prompt: crate::agent_run::AgentPrompt::new("review this plan").summary(),
                correlation_id: None,
                stage: crate::agent_plan::Stage::Review,
                read_plan_id: Some(plan_id),
            })
            .unwrap();
        state
            .audit
            .record_plan_review(&crate::audit::PlanReviewRecord {
                review_id,
                plan_id,
                agent_run_id: reviewer_run,
                submitted_at,
                verdict,
                feedback,
            })
            .unwrap();
        review_id
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

    /// A plan with no reviews, no addenda, and no decision surfaces
    /// `reviews: []`, `addenda: []`, and `decision: None` in the wire
    /// detail. The empty-Vec invariant matches the protocol-level
    /// "always emit []" decision.
    #[tokio::test]
    async fn show_plan_with_no_reviews_or_decision_returns_empty_reviews_and_none_decision() {
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

        let resp = dispatch_message(ClientMessage::ShowPlan { plan_id }, &state).await;
        let detail = match resp {
            ServerMessage::Plan { plan } => plan,
            other => panic!("expected Plan, got {other:?}"),
        };
        assert!(detail.reviews.is_empty());
        assert!(detail.decision.is_none());
        assert!(detail.addenda.is_empty());
    }

    /// A plan with reviews and an `Accepted` decision surfaces both on
    /// the wire. Each `PlanReviewRecord` is mapped to a `PlanReviewView`
    /// — verdict, feedback, and the reviewer's run id (under the
    /// `reviewer_run_id` rename) all round-trip.
    #[tokio::test]
    async fn show_plan_with_reviews_and_accepted_decision_returns_full_detail() {
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
        let feedback = crate::agent_plan::PlanFeedback::try_new("Looks good.").unwrap();
        let review_id = record_review_run_and_review(
            &state,
            session_id,
            plan_id,
            UnixMillis::from_millis(1_700_000_300),
            crate::agent_plan::Verdict::Approve,
            Some(feedback.clone()),
        )
        .await;
        let decided_at = UnixMillis::from_millis(1_700_000_400);
        state
            .audit
            .record_plan_decision(&crate::audit::PlanDecisionRecord {
                plan_id,
                decided_at,
                outcome: DecisionOutcome::Accepted,
                decider: Decider::try_new("cli:alice").unwrap(),
            })
            .unwrap();

        let resp = dispatch_message(ClientMessage::ShowPlan { plan_id }, &state).await;
        let detail = match resp {
            ServerMessage::Plan { plan } => plan,
            other => panic!("expected Plan, got {other:?}"),
        };
        assert_eq!(detail.reviews.len(), 1);
        let review = &detail.reviews[0];
        assert_eq!(review.review_id, review_id);
        assert_eq!(review.verdict, crate::agent_plan::Verdict::Approve);
        assert_eq!(review.feedback.as_ref(), Some(&feedback));
        assert_eq!(review.submitted_at.as_millis(), 1_700_000_300);
        let decision = detail.decision.expect("decision should be present");
        assert_eq!(decision.outcome, DecisionOutcome::Accepted);
        assert_eq!(decision.decided_at, decided_at);
    }

    /// A `RejectedRestart` decision surfaces the same way as `Accepted`
    /// — the handler does not filter on outcome.
    #[tokio::test]
    async fn show_plan_with_rejected_restart_decision_surfaces_outcome() {
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
            .record_plan_decision(&crate::audit::PlanDecisionRecord {
                plan_id,
                decided_at: UnixMillis::from_millis(1_700_000_500),
                outcome: DecisionOutcome::RejectedRestart,
                decider: Decider::try_new("cli:alice").unwrap(),
            })
            .unwrap();

        let resp = dispatch_message(ClientMessage::ShowPlan { plan_id }, &state).await;
        let detail = match resp {
            ServerMessage::Plan { plan } => plan,
            other => panic!("expected Plan, got {other:?}"),
        };
        let decision = detail.decision.expect("decision should be present");
        assert_eq!(decision.outcome, DecisionOutcome::RejectedRestart);
    }

    /// Reviews are surfaced in submission order (oldest first), and
    /// reviews against *other* plans are excluded by the per-plan
    /// filter in `list_plan_reviews_for_plan`.
    #[tokio::test]
    async fn show_plan_orders_reviews_oldest_first_and_excludes_other_plans() {
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
        let (_, other_plan_id) = record_planner_run_and_plan(
            &state,
            session_id,
            None,
            "# other plan",
            UnixMillis::from_millis(1_700_000_201),
        )
        .await;
        let first = record_review_run_and_review(
            &state,
            session_id,
            plan_id,
            UnixMillis::from_millis(1_700_000_300),
            crate::agent_plan::Verdict::RequestChanges,
            None,
        )
        .await;
        let second = record_review_run_and_review(
            &state,
            session_id,
            plan_id,
            UnixMillis::from_millis(1_700_000_400),
            crate::agent_plan::Verdict::Approve,
            None,
        )
        .await;
        // A review on a different plan must not leak into this listing.
        record_review_run_and_review(
            &state,
            session_id,
            other_plan_id,
            UnixMillis::from_millis(1_700_000_350),
            crate::agent_plan::Verdict::Approve,
            None,
        )
        .await;

        let resp = dispatch_message(ClientMessage::ShowPlan { plan_id }, &state).await;
        let detail = match resp {
            ServerMessage::Plan { plan } => plan,
            other => panic!("expected Plan, got {other:?}"),
        };
        assert_eq!(detail.reviews.len(), 2);
        assert_eq!(detail.reviews[0].review_id, first);
        assert_eq!(detail.reviews[1].review_id, second);
    }

    /// A plan with addenda surfaces them on the wire alongside the
    /// other fields. Each `PlanAddendumRecord` is mapped to a
    /// `PlanAddendumView` — body, addendum_id, and the executor's run
    /// id (under the `executor_run_id` rename) round-trip.
    #[tokio::test]
    async fn show_plan_with_addenda_returns_full_detail() {
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
        accept_plan(&state, plan_id, UnixMillis::from_millis(1_700_000_250)).await;
        let addendum_id = record_executor_run_and_addendum(
            &state,
            session_id,
            plan_id,
            UnixMillis::from_millis(1_700_000_500),
            "# Addendum\n\nMid-execution note.",
        )
        .await;

        let resp = dispatch_message(ClientMessage::ShowPlan { plan_id }, &state).await;
        let detail = match resp {
            ServerMessage::Plan { plan } => plan,
            other => panic!("expected Plan, got {other:?}"),
        };
        assert_eq!(detail.addenda.len(), 1);
        let addendum = &detail.addenda[0];
        assert_eq!(addendum.addendum_id, addendum_id);
        assert_eq!(addendum.submitted_at.as_millis(), 1_700_000_500);
        assert_eq!(addendum.body.as_str(), "# Addendum\n\nMid-execution note.");
    }

    /// Addenda are surfaced in submission order (oldest first), and
    /// addenda against *other* plans are excluded by the per-plan
    /// filter in `list_plan_addenda_for_plan`.
    #[tokio::test]
    async fn show_plan_orders_addenda_oldest_first_and_excludes_other_plans() {
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
        let (_, other_plan_id) = record_planner_run_and_plan(
            &state,
            session_id,
            None,
            "# other plan",
            UnixMillis::from_millis(1_700_000_201),
        )
        .await;
        accept_plan(&state, plan_id, UnixMillis::from_millis(1_700_000_250)).await;
        accept_plan(
            &state,
            other_plan_id,
            UnixMillis::from_millis(1_700_000_251),
        )
        .await;
        let first = record_executor_run_and_addendum(
            &state,
            session_id,
            plan_id,
            UnixMillis::from_millis(1_700_000_500),
            "# first",
        )
        .await;
        let second = record_executor_run_and_addendum(
            &state,
            session_id,
            plan_id,
            UnixMillis::from_millis(1_700_000_600),
            "# second",
        )
        .await;
        // An addendum on a different plan must not leak into this listing.
        record_executor_run_and_addendum(
            &state,
            session_id,
            other_plan_id,
            UnixMillis::from_millis(1_700_000_550),
            "# unrelated",
        )
        .await;

        let resp = dispatch_message(ClientMessage::ShowPlan { plan_id }, &state).await;
        let detail = match resp {
            ServerMessage::Plan { plan } => plan,
            other => panic!("expected Plan, got {other:?}"),
        };
        assert_eq!(detail.addenda.len(), 2);
        assert_eq!(detail.addenda[0].addendum_id, first);
        assert_eq!(detail.addenda[1].addendum_id, second);
    }

    /// `show_plan` joins the `plan_abort` row when an executor has
    /// hard-aborted the plan. The view's `executor_run_id` is the
    /// run that called the abort route, distinct from the planner
    /// run on `PlanSummary`. The abort does not require an accepted
    /// decision — the route deliberately bypasses the gate, and the
    /// joined view here reflects that.
    #[tokio::test]
    async fn show_plan_with_abort_returns_full_detail() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![], "o");
        let session_id = open_session(&state).await;
        let (planner_run_id, plan_id) = record_planner_run_and_plan(
            &state,
            session_id,
            None,
            "# plan",
            UnixMillis::from_millis(1_700_000_200),
        )
        .await;
        let executor_run = record_executor_run_and_abort(
            &state,
            session_id,
            plan_id,
            UnixMillis::from_millis(1_700_000_700),
            "Migration plan no longer viable: schema changed.",
        )
        .await;
        // Sanity: the abort's run is *not* the planner's run.
        assert_ne!(executor_run, planner_run_id);

        let resp = dispatch_message(ClientMessage::ShowPlan { plan_id }, &state).await;
        let detail = match resp {
            ServerMessage::Plan { plan } => plan,
            other => panic!("expected Plan, got {other:?}"),
        };
        let abort = detail.abort.as_ref().expect("abort view should be Some");
        assert_eq!(abort.executor_run_id, executor_run);
        assert_eq!(abort.aborted_at.as_millis(), 1_700_000_700);
        assert_eq!(
            abort.reason.as_str(),
            "Migration plan no longer viable: schema changed.",
        );
        // The abort path does not gate on the decision, so the
        // decision field is `None` here.
        assert!(detail.decision.is_none());
    }

    /// A plan with no abort row surfaces `abort = None`, distinct from
    /// the populated case above. Pins the "abort optionality" wire
    /// contract.
    #[tokio::test]
    async fn show_plan_without_abort_returns_none_abort() {
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

        let resp = dispatch_message(ClientMessage::ShowPlan { plan_id }, &state).await;
        let detail = match resp {
            ServerMessage::Plan { plan } => plan,
            other => panic!("expected Plan, got {other:?}"),
        };
        assert!(detail.abort.is_none());
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
