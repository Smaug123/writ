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

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::audit::{AuditLog, AuditedRequest, GrantOutcome};
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
pub async fn dispatch_message<S: SecretStore + Send + Sync>(
    msg: ClientMessage,
    state: &Arc<BrokerState<S>>,
) -> ServerMessage {
    match msg {
        ClientMessage::OpenSession { label, agent_model } => {
            let session_id = SessionId::new();
            let record = SessionRecord {
                session_id,
                label,
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
    }
}

async fn dispatch_capability<S: SecretStore + Send + Sync>(
    session_id: SessionId,
    capability: CapabilityRequest,
    state: &Arc<BrokerState<S>>,
) -> ServerMessage {
    // Validate the session exists *and* is still open before minting
    // anything. If we didn't check and later discovered the FK violation
    // (or session-closed invariant violation) at audit-write time, the
    // token would already be live with no audit row — the worst possible
    // outcome for audit integrity. The audit layer also re-checks
    // "session is open" inside its own transaction because the minter's
    // `await` gives a window in which CloseSession can land between here
    // and there; that check is the authoritative one, this one just
    // avoids a wasted mint in the common (non-racy) case and produces a
    // cleaner error message for the client.
    match state.audit.get_session(session_id) {
        Ok(None) => {
            return ServerMessage::Error {
                message: format!("unknown session {session_id}"),
            };
        }
        Ok(Some(s)) if s.closed_at.is_some() => {
            return ServerMessage::Error {
                message: format!("session {session_id} is closed"),
            };
        }
        Err(e) => {
            return ServerMessage::Error {
                message: e.to_string(),
            };
        }
        Ok(Some(_)) => {}
    }

    let request_id = RequestId::new();
    let received_at = UnixMillis::now();
    let decision = policy::decide(&capability, &state.policy);

    // Early-return on Deny: no await point follows, so the &decision
    // borrow is trivially scoped.
    if let PolicyDecision::Deny { reason } = &decision {
        let reason = reason.clone();
        if let Err(e) = state.audit.record(&AuditedRequest {
            request_id,
            session_id,
            received_at,
            request: &capability,
            decision: &decision,
            grant_outcome: GrantOutcome::NotMinted,
        }) {
            return ServerMessage::Error {
                message: format!(
                    "policy denied the request but the denial could not be recorded: {e}"
                ),
            };
        }
        return ServerMessage::Denied { reason };
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

    let mint_result = state.minter.mint(github_scope, ttl).await;

    match mint_result {
        Ok(minted) => {
            let expires_at = minted.expires_at();
            let (token, grant) = minted.into_grant_and_token(request_id, session_id);
            if let Err(e) = state.audit.record(&AuditedRequest {
                request_id,
                session_id,
                received_at,
                request: &capability,
                decision: &decision,
                grant_outcome: GrantOutcome::Granted(&grant),
            }) {
                // The audit log is the system of record. Delivering a token
                // that isn't recorded would violate the broker's core
                // invariant ("no unaudited grant"). The minted token is
                // wasted; it expires on its own without ever being used.
                // A transient disk issue will resolve on retry; a permanent
                // one (full disk, corrupt DB) must be fixed by the operator.
                eprintln!("AUDIT WRITE FAILED for jti={}: {e}", grant.jti);
                return ServerMessage::Error {
                    message: format!(
                        "credential was minted but could not be recorded; not delivering: {e}"
                    ),
                };
            }
            ServerMessage::TokenGranted { token, expires_at }
        }

        Err(e) => {
            let error_str = e.to_string();
            if let Err(ae) = state.audit.record(&AuditedRequest {
                request_id,
                session_id,
                received_at,
                request: &capability,
                decision: &decision,
                grant_outcome: GrantOutcome::MintFailed { error: &error_str },
            }) {
                return ServerMessage::Error {
                    message: format!(
                        "mint failed and the failure could not be recorded: {ae} \
                         (original mint error: {error_str})"
                    ),
                };
            }
            ServerMessage::Error { message: error_str }
        }
    }
}

async fn handle_connection<S: SecretStore + Send + Sync + 'static>(
    stream: UnixStream,
    state: Arc<BrokerState<S>>,
) -> io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let response = match serde_json::from_str::<ClientMessage>(&line) {
            Err(e) => ServerMessage::Error {
                message: format!("invalid request: {e}"),
            },
            Ok(msg) => dispatch_message(msg, &state).await,
        };
        let mut json = serde_json::to_string(&response).expect("ServerMessage always serializes");
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
    }
    Ok(())
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

    // Try to connect to the existing socket. A successful connection means
    // another writd is alive; refuse to displace it. A failed connection
    // means the socket file (if any) is stale; remove it and bind fresh.
    if let Ok(_probe) = std::os::unix::net::UnixStream::connect(socket_path) {
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
        Ok(_) => {
            std::fs::remove_file(socket_path)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let listener = UnixListener::bind(socket_path)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, state).await {
                eprintln!("connection error: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{GitHubAccess, RepoRef};
    use crate::github::{GitHubAppConfig, GitHubMinter};
    use crate::policy::PolicyConfig;
    use crate::secret::{SecretError, SecretKey, SecretStore};
    use std::collections::HashMap;
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

    // --- Policy decisions ------------------------------------------------

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
        // Give the listener time to bind
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let stream = UnixStream::connect(&sock_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        // Open session
        let open_msg = serde_json::to_string(&ClientMessage::OpenSession {
            label: Some("integration".into()),
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

    async fn open_session<S: SecretStore + Send + Sync>(state: &Arc<BrokerState<S>>) -> SessionId {
        match dispatch_message(
            ClientMessage::OpenSession {
                label: None,
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
}
