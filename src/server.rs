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
use std::path::Path;
use std::sync::{Arc, OnceLock};

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
    GitHubRequest, RequestId, SessionId, SessionRecord, TtlSeconds, UnixMillis,
};
use crate::core::{NotesRef, Sha256Hex};
use crate::git_push_approve::{RunApproveError, prepare_approve};
use crate::git_push_promote::{CommitError, PromoteRuntimeConfig};
use crate::git_push_staging::{GitPushStagingStore, StagedEntry, StagingError};
use crate::github::GitHubMinter;
use crate::github_git_db::GitDataHttp;
use crate::notes_repo::NotesRepo;
use crate::openai_chatgpt_auth::ChatgptOauthAuthority;
use crate::policy::{self, Decision, PolicyConfig};
use crate::protocol::{
    ClientMessage, ReconcileOutcome, RejectionReason, ServerMessage, StagedPushAuditView,
    StagedPushDetail, StagedPushSummary,
};
use crate::secret::SecretStore;
use crate::signing::WritSigningKey;
use crate::vm_git_bundle::GitSecretValue;
use crate::vm_git_mirror_cache::MirrorPins;

/// Staged-push approval subsystem (`list`/`show`/`reject`/`approve`/
/// `reconcile`), split out of this file to keep the dispatcher readable.
mod staged_push;

/// Run-agent orchestration (the `RunAgent` handler and its VM-dispatch
/// path), split out of this file to keep the dispatcher readable.
mod run_agent;
pub use run_agent::{
    AgentRunQueueFull, AgentRunSlots, AgentRunSlotsError, DEFAULT_MAX_CONCURRENT_AGENT_RUNS,
    DEFAULT_MAX_PENDING_AGENT_RUNS,
};
pub(crate) use run_agent::{AgentRunQueuePlace, AgentRunSlot};

/// Boot-time description of the child process that produces an agent
/// run's streams, and where those streams are kept. Pure data —
/// dispatch reads `command` and `args`, hands them to
/// [`crate::agent_run::AgentProcessPlan`], writes the prompt bytes to
/// the child's stdin, and captures both streams under `log_root`. The
/// shell — *which* binary writ launches — is set at boot; the wire
/// `RunAgent` request does not choose it, so a `RunAgent` caller cannot
/// smuggle in an arbitrary command.
///
/// `log_root` is not optional, because the host-spawn arm cannot run
/// without one: every run records an `agent_run_outcome` row naming the
/// files its streams landed in, so a spawn config with nowhere to put
/// them describes a run that could start but never be audited. The
/// daemon-wide root is [`crate::config::DaemonConfig::agent_run_log_root`],
/// checked once at boot and handed to both `RunAgent` arms; this field
/// is the host arm's copy of that same validated value.
///
/// Slice B accepts a single fixed command for the whole daemon; the
/// agent-kind selection that bailiff will eventually drive arrives in
/// slice C alongside the session-per-workflow refinement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunAgentSpawnConfig {
    pub command: std::path::PathBuf,
    pub args: Vec<String>,
    /// Which agent `command` is, as declared by the operator who configured
    /// it. Recorded on every host-spawned run's `agent_run` row, and the
    /// value a caller's session kind must agree with.
    pub agent_kind: crate::core::AgentKind,
    pub log_root: crate::config::AgentRunLogRoot,
    /// How long a host-spawned run may take before writd stops it, or `None`
    /// for the default of no bound at all. Parsed from
    /// `run_agent.spawn_timeout_secs`.
    pub timeout: Option<crate::agent_run::AgentRunTimeout>,
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
    /// How many agent runs may execute at once, across both `RunAgent` arms.
    ///
    /// Not inside `run_agent_spawn`: that is `None` on a daemon serving only the
    /// VM arm, and the bound has to hold for both. Same reason
    /// `agent_run_log_root` is a top-level config key.
    pub agent_run_slots: run_agent::AgentRunSlots,
    pub promote_runtime: Option<Arc<PromoteRuntimeConfig>>,
    /// The broker-wide transport every GitHub Git Data call runs over,
    /// built once and borrowed by each approve's short-lived
    /// [`GitDataClient`](crate::github_git_db::GitDataClient). Reach it
    /// through [`BrokerState::git_data_http`], never the field.
    ///
    /// Lazy rather than eager because most `BrokerState`s can never reach
    /// a Git Data call: the per-session broker VM (`writd broker`) and
    /// every test state boot with `staging_store: None`, and the approve
    /// handler refuses on that long before it wants a transport. Building
    /// one for them would pay the platform TLS root-store parse
    /// ([`GitDataHttp`]) for a transport that provably cannot be used.
    ///
    /// A `OnceLock` rather than an `Option` because "not built yet" and
    /// "not available" are different claims: every state *can* build one
    /// on demand (it needs no configuration), so there is no
    /// unconfigured arm for a caller to handle and no way to hold a state
    /// that owes an approve a transport it cannot produce.
    pub git_data_http: OnceLock<GitDataHttp>,
    /// Broker-wide registry pinning `(repo, rev)` mirror entries that an
    /// in-flight flake-input provision is materialising, so the clone handler's
    /// opportunistic eviction never deletes a mirror out from under a running
    /// `git clone --local`. Shared (cheap `Arc` clone) across every session.
    pub mirror_pins: MirrorPins,
    /// The broker-wide ChatGPT-OAuth refresh authority, built lazily on the
    /// first ChatGPT-authenticated OpenAI session and shared across every
    /// session thereafter. Sharing is load-bearing: the in-memory token
    /// cache and its pending-persist retry survive session teardown (a new
    /// per-session authority would reload the spent durable token and force
    /// a re-login), and concurrent sessions serialise their refreshes
    /// through the authority's single mutex rather than each racing its own
    /// refresh against the shared, rotation-invalidated refresh token. `None`
    /// until first use, and forever when ChatGPT-OAuth is not configured.
    /// See [`crate::openai_chatgpt_auth`] and
    /// [`crate::vm_http`]'s OpenAI proxy `build_extras`.
    pub chatgpt_oauth_authority: std::sync::Mutex<Option<Arc<ChatgptOauthAuthority>>>,
}

impl<S: SecretStore> BrokerState<S> {
    /// The shared Git Data transport, building it on first use.
    ///
    /// The build is synchronous and takes ~80 ms once the process has a
    /// warm platform root store — which a broker always does by this
    /// point, since [`GitHubMinter::new_registry`] built a `reqwest`
    /// client at boot. It happens at most once per broker; every approve
    /// after the first borrows the same transport.
    pub fn git_data_http(&self) -> &GitDataHttp {
        self.git_data_http.get_or_init(GitDataHttp::production)
    }
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
                // Accept, answer, and start in the background. The client that
                // sent this has its own deadline and writd never sees its EOF,
                // so anything awaited here is time in which the run's ids might
                // stop being deliverable — and a start completed after that
                // leaves a live VM the operator can only find by listing.
                // Answering from the accept removes that state by construction:
                // the caller holds the name of everything writd will start,
                // before writd starts it.
                match agent_vm.accept_agent_run_session(
                    state,
                    label,
                    agent_kind,
                    agent_model,
                    workspace,
                    prompt,
                    // `StartAgentRun` has no `purpose` field, and is not
                    // getting one speculatively: a run started this way is
                    // permanently `purpose: None` on the audit row, which is
                    // the truth about what the caller supplied.
                    crate::agent_vm_daemon::AgentRunTags {
                        correlation_id,
                        purpose: None,
                    },
                ) {
                    Ok(accepted) => {
                        let session_id = accepted.session_id();
                        let run_id = accepted.run_id();
                        let agent_vm = Arc::clone(agent_vm);
                        let state = Arc::clone(state);
                        tokio::spawn(async move {
                            // Nobody is waiting on this result, so it has to be
                            // legible where an operator will look: the log line
                            // here, and — for every failure downstream of the
                            // audit session being opened — a closed session with
                            // an unpaired `agent_run` row.
                            match agent_vm.complete_agent_run_session(state, accepted).await {
                                Ok(_started) => {}
                                // Not a failure: somebody asked for this, and
                                // `stop_session` has already recorded that they
                                // did. Logging it as an error would make the one
                                // outcome an operator deliberately caused the
                                // loudest thing in the file.
                                Err(
                                    crate::agent_vm_daemon::AgentVmDaemonError::AgentRunStoppedBeforeStart {
                                        ..
                                    },
                                ) => {}
                                Err(err) => {
                                    tracing::error!(
                                        session_id = %session_id,
                                        run_id = %run_id,
                                        error = %err,
                                        "accepted agent run did not start",
                                    );
                                }
                            }
                        });
                        ServerMessage::AgentRunAccepted { session_id, run_id }
                    }
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
            staged_push::list_staged_pushes(state, session_id).await
        }
        ClientMessage::ShowStagedPush { request_id } => {
            staged_push::show_staged_push(state, request_id).await
        }
        ClientMessage::RejectStagedPush {
            request_id,
            operator,
            reason,
        } => staged_push::reject_staged_push(state, request_id, operator, reason).await,
        ClientMessage::ApproveStagedPush {
            request_id,
            operator,
        } => staged_push::approve_staged_push(state, request_id, operator).await,
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator,
            outcome,
        } => staged_push::reconcile_staged_push(state, request_id, operator, outcome).await,
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
            run_agent::run_agent(
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
        ClientMessage::VerifyAgentRun {
            signed_metadata,
            signature,
        } => run_agent::verify_agent_run(state, &signed_metadata, &signature).await,
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
    let decision_record = decision.to_record();

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
        decision: &decision_record,
    }) {
        return CapabilityOutcome::Error {
            message: format!("request could not be recorded: {e}"),
        };
    }

    // The `Grant` carries the unforgeable authorization the minter needs;
    // `Deny` short-circuits before any mint.
    let authorization = match decision {
        Decision::Deny { reason } => {
            return CapabilityOutcome::Denied { reason };
        }
        Decision::Grant(authorization) => authorization,
    };

    let mint_result = state
        .minter
        .mint_for_agent(&state.secrets, session.agent_kind, authorization)
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
            // `Display` *and its source chain* (the `Display` itself caps
            // `ApiError.body` to 256 chars in `MintError`'s impl). The chain
            // matters: opaque outer Displays — notably reqwest's "error sending
            // request for url (...)" — hide the real DNS/TLS/connect cause in
            // their source. The agent only ever sees the bounded label form so
            // the protocol surface can't carry unbounded or sensitive backend
            // payloads — see `MintError::agent_message`.
            let audit_message = error_with_source_chain(&e);
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

/// Format an error together with its full `source()` chain. Outer `Display`s often
/// hide the real cause in their source — notably `reqwest`'s "error sending request
/// for url (...)", whose DNS/TLS/connect detail lives only in the source chain — so
/// the audit log (the system of record for mint failures) and the nix-cache
/// upstream logs record the whole chain.
pub(crate) fn error_with_source_chain(error: &dyn std::error::Error) -> String {
    use std::fmt::Write as _;
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let _ = write!(message, ": {cause}");
        source = cause.source();
    }
    message
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
///
/// That mode check is defence-in-depth, not writ's trust boundary: a
/// hostile local uid is out of the threat model (see §1 of
/// `docs/design/architecture.md`). Keep it — it is what makes "if you
/// can open the socket, you are trusted" true rather than merely
/// assumed — but don't grow it into an ownership or ancestor check.
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
mod approve_crash_tests;
#[cfg(test)]
mod approve_rival_tests;
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
