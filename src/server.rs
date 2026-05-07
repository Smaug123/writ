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

use crate::agent_vm_daemon::AgentVmDaemon;
use crate::audit::{AuditLog, PreMintRecord};
use crate::core::{
    CapabilityRequest, GrantedScope, PolicyDecision, RequestId, SessionId, SessionRecord,
    TtlSeconds, UnixMillis,
};
use crate::github::GitHubMinter;
use crate::policy::{self, PolicyConfig};
use crate::protocol::{ClientMessage, ServerMessage};
use crate::secret::SecretStore;

/// Shared state for the broker. Wrapped in `Arc` so connections spawned
/// onto different tokio tasks can all reference the same audit log and
/// minter config.
pub struct BrokerState<S: SecretStore> {
    pub audit: AuditLog,
    pub minter: GitHubMinter<S>,
    pub policy: PolicyConfig,
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
            if state.minter.requires_agent_kind() && agent_kind.is_none() {
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
            if state.minter.requires_agent_kind() && agent_kind.is_none() {
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
        ClientMessage::ListAgentVms => match agent_vm {
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
    }
}

fn missing_agent_kind_for_registry_response() -> ServerMessage {
    ServerMessage::Error {
        message: "agent kind is required when github_apps is configured; open the session with --agent claude or --agent codex".into(),
    }
}

async fn dispatch_capability<S: SecretStore + Send + Sync>(
    session_id: SessionId,
    capability: CapabilityRequest,
    state: &Arc<BrokerState<S>>,
) -> ServerMessage {
    match request_capability(session_id, capability, state).await {
        CapabilityOutcome::Granted { token, expires_at } => {
            ServerMessage::TokenGranted { token, expires_at }
        }
        CapabilityOutcome::Denied { reason } => ServerMessage::Denied { reason },
        CapabilityOutcome::UnknownSession { session_id } => ServerMessage::Error {
            message: format!("unknown session {session_id}"),
        },
        CapabilityOutcome::ClosedSession { session_id } => ServerMessage::Error {
            message: format!("session {session_id} is closed"),
        },
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
        .mint_for_agent(session.agent_kind, github_scope, ttl)
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
                eprintln!("AUDIT WRITE FAILED for jti={}: {e}", grant.jti);
                return CapabilityOutcome::Error {
                    message: format!(
                        "credential was minted but could not be recorded; not delivering: {e}"
                    ),
                };
            }
            CapabilityOutcome::Granted { token, expires_at }
        }

        Err(e) => {
            let error_str = e.to_string();
            if let Err(ae) =
                state
                    .audit
                    .record_mint_failure(request_id, UnixMillis::now(), &error_str)
            {
                return CapabilityOutcome::Error {
                    message: format!(
                        "mint failed and the failure could not be recorded: {ae} \
                         (original mint error: {error_str})"
                    ),
                };
            }
            CapabilityOutcome::Error { message: error_str }
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
                eprintln!("connection error: {e}");
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
        let minter = GitHubMinter::new(
            GitHubAppConfig {
                app_id: 42,
                installation_id: 999,
                installation_owner: owner.into(),
                private_key_secret: pk,
                api_base: server.uri(),
            },
            store,
        );
        Arc::new(BrokerState {
            audit: AuditLog::open_in_memory().unwrap(),
            minter,
            policy: PolicyConfig {
                writable_repos: writable,
                default_ttl: crate::core::TtlSeconds::new(3600).unwrap(),
            },
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
        let minter = GitHubMinter::new_registry(
            GitHubAppRegistryConfig::for_agent_apps(apps).unwrap(),
            store,
        );
        Arc::new(BrokerState {
            audit: AuditLog::open_in_memory().unwrap(),
            minter,
            policy: PolicyConfig {
                writable_repos: Vec::new(),
                default_ttl: crate::core::TtlSeconds::new(3600).unwrap(),
            },
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
                agent_kind: None,
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
                agent_kind: None,
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
                agent_kind: None,
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

        let list = dispatch_message(ClientMessage::ListAgentVms, &state).await;
        assert_eq!(
            list,
            ServerMessage::Error {
                message: "agent VM runtime is not configured".into()
            }
        );
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
    async fn request_on_closed_session_returns_error_without_minting() {
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

        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("closed"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }

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
    async fn request_for_unknown_session_returns_error() {
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

        match resp {
            ServerMessage::Error { message } => {
                assert!(message.contains("unknown session"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
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
    async fn legacy_github_config_uses_legacy_app_even_when_agent_kind_is_set() {
        let server = MockServer::start().await;
        let state = make_state(&server, vec![repo("o", "n")], "o");
        let session_id = open_session_with_agent_kind(&state, Some(AgentKind::Codex)).await;

        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_legacy_token",
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
                assert_eq!(token, "ghs_legacy_token");
            }
            other => panic!("expected TokenGranted, got {other:?}"),
        }

        let grants = state.audit.list_grants_for_session(session_id).unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].github_app_id, Some(42));
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
                assert!(message.contains("github_apps"), "got: {message}");
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
            agent_kind: None,
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
        open_session_with_agent_kind(state, None).await
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
