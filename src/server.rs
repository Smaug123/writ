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
    GitHubRequest, RequestId, SessionId, SessionRecord, TtlSeconds, UnixMillis,
};
use crate::core::{NotesRef, Sha256Hex};
use crate::git_push_approve::{RunApproveError, prepare_approve};
use crate::git_push_promote::{CommitError, PromoteRuntimeConfig};
use crate::git_push_staging::{GitPushStagingStore, StagedEntry, StagingError};
use crate::github::GitHubMinter;
use crate::notes_repo::NotesRepo;
use crate::openai_chatgpt_auth::ChatgptOauthAuthority;
use crate::policy::{self, Decision, PolicyConfig};
use crate::protocol::{
    ClientMessage, ReconcileOutcome, RejectionReason, ServerMessage, SignedRunMetadata,
    StagedPushAuditView, StagedPushDetail, StagedPushSummary,
};
use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use crate::secret::SecretStore;
use crate::signing::WritSigningKey;
use crate::vm_git_bundle::GitSecretValue;
use crate::vm_git_mirror_cache::MirrorPins;

/// Staged-push approval subsystem (`list`/`show`/`reject`/`approve`/
/// `reconcile`), split out of this file to keep the dispatcher readable.
mod staged_push;

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
