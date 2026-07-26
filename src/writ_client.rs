//! Bailiff-side client for writ's Unix-socket RPC.
//!
//! Speaks the same newline-terminated JSON framing the broker accepts
//! (see `src/server.rs:1322`). Today the only verb exposed is
//! [`WritClient::run_agent`]; future bailiff verbs (plan submit,
//! review attach, …) hang off the same client.
//!
//! Wire framing: one [`ClientMessage`] per line, one [`ServerMessage`]
//! per line in reply. Reads are bounded by a per-line cap so a
//! malformed broker can't make bailiff allocate without bound. The
//! cap matches the broker-side `read_line_bounded` limit and is sized
//! for the worst-case JSON expansion of a 1 MiB `AgentPrompt` (6:1
//! when every byte is an ASCII control character that `serde_json`
//! encodes as `\u00XX`).
//!
//! Errors are tagged so callers can react without string-matching: a
//! transport failure is distinct from a writ-side [`ServerMessage::Error`],
//! which is distinct from "writ returned a reply that wasn't
//! [`ServerMessage::RunAgentCompleted`]" (the only legal answer to a
//! [`ClientMessage::RunAgent`]).
//!
//! See `docs/plans/2026-05-14-bailiff-split.md` slice B6.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::agent_run::AgentPrompt;
use crate::core::{AgentKind, CapabilitySet, NotesRef, SessionId, SshSignature};
use crate::protocol::{ClientMessage, ServerMessage, SignedRunMetadata};
use crate::vm_git::{AgentVmWorkspaceBootstrap, GitObjectId};

/// Matches the broker-side cap in `src/server.rs`. The largest legal
/// reply is a `RunAgentCompleted` whose canonical metadata plus
/// signed envelope reference fit in a few KiB, so the cap is set by
/// the request side (the broker accepting a worst-case-escaped 1 MiB
/// `AgentPrompt`). Both ends share a single ceiling so the framing
/// contract stays symmetric. A peer that frames a single line larger
/// than this is treated as broken.
const MAX_LINE_BYTES: usize = 6 * crate::agent_run::MAX_AGENT_PROMPT_BYTES + 64 * 1024;

/// What writ returned for a `RunAgent` request that ran to completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunAgentCompleted {
    pub output_oid: GitObjectId,
    pub signed_metadata: SignedRunMetadata,
    pub signature: SshSignature,
}

/// Arguments to [`WritClient::run_agent`]. Mirrors
/// [`ClientMessage::RunAgent`] one-for-one; an explicit struct keeps
/// the call site readable when more fields land later in the slice.
#[derive(Clone, Debug)]
pub struct RunAgentRequest {
    pub prompt: AgentPrompt,
    pub capabilities: Vec<CapabilitySet>,
    pub purpose: String,
    pub output_ref: NotesRef,
    /// Optional audit session id binding the run. When `Some`, the
    /// caller has already opened the session via
    /// [`WritClient::open_session`] (or otherwise) and writ will stamp
    /// the same id into the signed metadata; when `None`, writ mints a
    /// fresh id for the signature alone. Bailiff's slice-C plan-submit
    /// and plan-review workflows pre-open and pass `Some(_)`; the VM-
    /// mode plan-implement workflow passes `None` because writ's VM
    /// dispatch arm mints the audit session itself (it would reject a
    /// caller-supplied id alongside a workspace bootstrap).
    pub session_id: Option<SessionId>,
    /// When `Some`, writd dispatches the agent into a per-run VM
    /// provisioned per the bootstrap; when `None`, writd takes the
    /// host-spawn path. Required for any run carrying a
    /// `WorkspaceWrite` capability — the broker rejects that
    /// combination if `workspace` is `None`. Bailiff's `submit_implement`
    /// sets this; the read-side `submit_plan` / `submit_review`
    /// workflows leave it `None`.
    pub workspace: Option<AgentVmWorkspaceBootstrap>,
    /// Agent kind to pin onto the per-run VM. Required by writd's VM
    /// dispatch arm when `workspace` is `Some` (the broker has no
    /// default and rejects the request rather than guess). Ignored
    /// on the host-spawn path.
    pub agent_kind: Option<AgentKind>,
    /// Agent model identifier the broker hands to the VM's
    /// `/v1/agent-runs/<id>/config` response. Required alongside
    /// `agent_kind` in VM mode; free-form string the broker does not
    /// parse. Ignored on the host-spawn path.
    pub agent_model: Option<String>,
}

/// Tagged failure mode of [`WritClient::run_agent`]. The split between
/// `Connect`, `Write`, `Read*`, `WritError`, and `UnexpectedMessage`
/// lets bailiff distinguish "couldn't reach writ" from "writ said no"
/// from "writ said something I don't understand" without parsing
/// prose. Source paths are included on transport errors so an operator
/// can tell which socket was tried.
#[derive(Debug, Error)]
pub enum WritClientError {
    #[error("cannot connect to writ at {}: {source}", path.display())]
    Connect {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// `serde_json::to_string` refused the [`ClientMessage`]. The only
    /// path that lands here in practice is a `RunAgent` workspace whose
    /// `destination: PathBuf` carries non-UTF-8 bytes (legal on Unix,
    /// inexpressible in JSON); the bailiff CLI rejects this at the
    /// `--workspace-destination` flag, but the `WritClient` API is
    /// public and any other consumer should see a typed error rather
    /// than a panic.
    #[error("encoding request to writ as JSON failed: {source}")]
    Serialize {
        #[source]
        source: serde_json::Error,
    },
    #[error("writing request to writ failed: {source}")]
    Write {
        #[source]
        source: io::Error,
    },
    #[error("reading reply from writ failed: {source}")]
    ReadFraming {
        #[source]
        source: io::Error,
    },
    #[error("writ closed the connection before replying")]
    ReadEof,
    #[error("decoding writ reply as JSON failed: {source}")]
    ReadDecode {
        #[source]
        source: serde_json::Error,
    },
    /// Writ accepted the request shape but refused the run. The
    /// message is whatever writ put in [`ServerMessage::Error`].
    #[error("writ refused the request: {message}")]
    WritError { message: String },
    /// Writ rejected the request because the caller-supplied
    /// `session_id` doesn't correspond to any session writ knows about.
    /// Distinct from [`Self::WritError`] so callers can drive retries
    /// (e.g. reopen the session) off the variant instead of parsing
    /// prose.
    #[error("writ does not know session {session_id}")]
    UnknownSession { session_id: SessionId },
    /// Writ rejected the request because the caller-supplied
    /// `session_id` refers to a session that's already closed. The
    /// caller almost certainly raced an earlier close; surface the id
    /// so the cleanup path can react without parsing prose.
    #[error("writ session {session_id} is already closed")]
    ClosedSession { session_id: SessionId },
    /// Writ returned a structured reply that isn't a legal answer to
    /// `RunAgent`. The only legal answer is
    /// [`ServerMessage::RunAgentCompleted`] (success) or
    /// [`ServerMessage::Error`] (which becomes [`Self::WritError`]).
    /// Anything else is a protocol bug.
    #[error("writ replied with an unexpected message: {summary}")]
    UnexpectedMessage { summary: String },
}

/// Async client over a Unix socket to writ. A fresh instance owns one
/// connection; `run_agent` consumes the connection so each RPC is a
/// fresh socket. This matches the writ CLI's one-shot pattern and
/// keeps writ's per-connection read loop honest about EOF cleanup.
pub struct WritClient {
    socket_path: PathBuf,
}

impl WritClient {
    /// Construct a client that will dial `socket_path` per RPC. No IO
    /// happens at construction time; the path is resolved on the
    /// first RPC.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Path the client will dial. Kept as an accessor so callers can
    /// surface the same path that any subsequent error message will
    /// reference.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Send a `RunAgent` request and wait for `RunAgentCompleted`.
    ///
    /// Synchronous from the caller's perspective: returns when writ
    /// has spawned the agent, the agent has run to completion, writ
    /// has written the envelope blob, and writ's reply has been
    /// parsed off the wire. Cancellation cancels the read but not
    /// writ's side effects — by the time writ has accepted the
    /// request, it has committed to either replying or erroring.
    pub async fn run_agent(
        &self,
        req: RunAgentRequest,
    ) -> Result<RunAgentCompleted, WritClientError> {
        let reply = self
            .roundtrip(ClientMessage::RunAgent {
                prompt: req.prompt,
                capabilities: req.capabilities,
                purpose: req.purpose,
                output_ref: req.output_ref,
                session_id: req.session_id,
                workspace: req.workspace,
                agent_kind: req.agent_kind,
                agent_model: req.agent_model,
            })
            .await?;
        match reply {
            ServerMessage::RunAgentCompleted {
                output_oid,
                signed_metadata,
                signature,
            } => Ok(RunAgentCompleted {
                output_oid,
                signed_metadata,
                signature,
            }),
            ServerMessage::Error { message } => Err(WritClientError::WritError { message }),
            ServerMessage::UnknownSession { session_id } => {
                Err(WritClientError::UnknownSession { session_id })
            }
            ServerMessage::ClosedSession { session_id } => {
                Err(WritClientError::ClosedSession { session_id })
            }
            other => Err(WritClientError::UnexpectedMessage {
                summary: format!("{other:?}"),
            }),
        }
    }

    /// Open a writ session and return its broker-assigned id. Used by
    /// bailiff's slice-C plan workflows to wrap a single `RunAgent`
    /// call in an authority/audit window; per the 2026-05-16 session
    /// model each agent run opens its own session, so callers should
    /// close this id once their `RunAgent` returns rather than
    /// threading it into later workflow stages.
    pub async fn open_session(
        &self,
        label: Option<String>,
        agent_kind: Option<AgentKind>,
        agent_model: Option<String>,
    ) -> Result<SessionId, WritClientError> {
        let reply = self
            .roundtrip(ClientMessage::OpenSession {
                label,
                agent_kind,
                agent_model,
            })
            .await?;
        match reply {
            ServerMessage::SessionOpened { session_id } => Ok(session_id),
            ServerMessage::Error { message } => Err(WritClientError::WritError { message }),
            other => Err(WritClientError::UnexpectedMessage {
                summary: format!("{other:?}"),
            }),
        }
    }

    /// Close a previously-opened session. Returns `Ok(())` on
    /// `SessionClosed`; surfaces broker `Error` and unexpected replies
    /// the same way [`Self::run_agent`] does so callers can react
    /// without parsing prose.
    pub async fn close_session(&self, session_id: SessionId) -> Result<(), WritClientError> {
        let reply = self
            .roundtrip(ClientMessage::CloseSession { session_id })
            .await?;
        match reply {
            ServerMessage::SessionClosed => Ok(()),
            ServerMessage::Error { message } => Err(WritClientError::WritError { message }),
            other => Err(WritClientError::UnexpectedMessage {
                summary: format!("{other:?}"),
            }),
        }
    }

    /// Dial, write one framed [`ClientMessage`], read one framed
    /// [`ServerMessage`]. Shared by every RPC on this client so the
    /// framing contract (one connection per call, newline-delimited
    /// JSON, bounded reads) lives in one place.
    async fn roundtrip(&self, msg: ClientMessage) -> Result<ServerMessage, WritClientError> {
        let stream =
            UnixStream::connect(&self.socket_path)
                .await
                .map_err(|e| WritClientError::Connect {
                    path: self.socket_path.clone(),
                    source: e,
                })?;
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        let mut json =
            serde_json::to_string(&msg).map_err(|source| WritClientError::Serialize { source })?;
        json.push('\n');
        writer
            .write_all(json.as_bytes())
            .await
            .map_err(|e| WritClientError::Write { source: e })?;
        writer
            .flush()
            .await
            .map_err(|e| WritClientError::Write { source: e })?;

        let bytes = read_line_bounded(&mut reader, MAX_LINE_BYTES)
            .await
            .map_err(|e| WritClientError::ReadFraming { source: e })?
            .ok_or(WritClientError::ReadEof)?;
        serde_json::from_slice(&bytes).map_err(|e| WritClientError::ReadDecode { source: e })
    }
}

/// Mirror of `server::read_line_bounded`. Duplicated rather than
/// re-exported so the framing contract is documented at both ends of
/// the wire; a divergence between the two would be a real protocol
/// bug, not an import-path detail.
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
                    format!("reply line exceeds {max}-byte limit"),
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
                format!("reply line exceeds {max}-byte limit"),
            ));
        }
        buf.extend_from_slice(available);
        reader.consume(len);
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests use [`UnixStream::pair`] to stand in for a real
    //! writ broker. They cover the framing contract end-to-end on a
    //! socket but stop short of exercising writ's spawner — that's
    //! the integration test's job. The split is deliberate: framing
    //! bugs surface here as fast unit failures, and the slower
    //! integration test only has to assert the end-to-end story.
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::Mutex;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::agent_run::AgentPrompt;
    use crate::core::{
        AgentKind, NotesRef, RepoRef, SessionId, Sha256Hex, SshKeyFingerprint, SshSignature,
        UnixMillis,
    };
    use crate::protocol::{ClientMessage, SignedRunMetadata};
    use crate::vm_git::{AgentVmWorkspaceBootstrap, GitCloneRepo, GitObjectId, WorkspaceWarmMode};

    fn sample_request() -> RunAgentRequest {
        RunAgentRequest {
            prompt: AgentPrompt::new("noop"),
            capabilities: vec![],
            purpose: "test".to_string(),
            output_ref: NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap(),
            session_id: None,
            workspace: None,
            agent_kind: None,
            agent_model: None,
        }
    }

    fn sample_workspace_bootstrap() -> AgentVmWorkspaceBootstrap {
        AgentVmWorkspaceBootstrap {
            repo: GitCloneRepo::new(RepoRef {
                owner: "smaug123".into(),
                name: "writ".into(),
            })
            .unwrap(),
            destination: Some(std::path::PathBuf::from("/workspace/writ")),
            warm: WorkspaceWarmMode::DevShell,
        }
    }

    fn sample_object_id() -> GitObjectId {
        std::iter::repeat_n('a', 40)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    fn sample_session_id() -> SessionId {
        "00000000-0000-0000-0000-000000000001".parse().unwrap()
    }

    fn sample_signed_metadata() -> SignedRunMetadata {
        SignedRunMetadata {
            run_id: "f2f2f2f2-0000-0000-0000-000000000001".parse().unwrap(),
            session_id: sample_session_id(),
            prompt_sha256: Sha256Hex::try_new(std::iter::repeat_n('a', 64).collect::<String>())
                .unwrap(),
            output_envelope_sha256: Sha256Hex::try_new(
                std::iter::repeat_n('b', 64).collect::<String>(),
            )
            .unwrap(),
            capabilities: vec![],
            exit_code: 0,
            completed_at: UnixMillis::from_millis(1_700_000_000_000),
            signing_key_fingerprint: SshKeyFingerprint::try_new(
                "SHA256:Wn0p0WC9F8bJ35rwTRsLP6w8b9ZsZh4HX0FYpC0Zg",
            )
            .unwrap(),
        }
    }

    fn sample_signature() -> SshSignature {
        SshSignature::try_new(
            "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ...\n-----END SSH SIGNATURE-----",
        )
        .unwrap()
    }

    /// One-shot test broker bound to a tempdir socket. Holds a queue
    /// of replies; each accepted connection reads one line, decodes
    /// it, records it, then writes the next queued reply. The
    /// `JoinHandle` is kept so tests can await termination after
    /// closing the socket.
    struct StubBroker {
        socket_path: PathBuf,
        requests: Arc<Mutex<Vec<ClientMessage>>>,
        _task: JoinHandle<()>,
        _dir: tempfile::TempDir,
    }

    impl StubBroker {
        async fn start(reply: ServerMessage) -> Self {
            Self::start_with_replies(vec![reply]).await
        }

        async fn start_with_replies(replies: Vec<ServerMessage>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let socket_path = dir.path().join("writ.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let req_clone = Arc::clone(&requests);
            let mut replies = replies.into_iter();
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let Some(reply) = replies.next() else {
                        return;
                    };
                    let (reader, mut writer) = stream.into_split();
                    let mut lines = BufReader::new(reader).lines();
                    if let Ok(Some(line)) = lines.next_line().await
                        && let Ok(msg) = serde_json::from_str::<ClientMessage>(&line)
                    {
                        req_clone.lock().await.push(msg);
                    }
                    let mut json = serde_json::to_string(&reply).unwrap();
                    json.push('\n');
                    let _ = writer.write_all(json.as_bytes()).await;
                    let _ = writer.shutdown().await;
                }
            });
            Self {
                socket_path,
                requests,
                _task: task,
                _dir: dir,
            }
        }

        async fn observed_requests(&self) -> Vec<ClientMessage> {
            self.requests.lock().await.clone()
        }
    }

    /// Happy path: client sends `RunAgent`, broker replies
    /// `RunAgentCompleted`, client decodes the structured reply.
    #[tokio::test]
    async fn run_agent_round_trips_completed_reply() {
        let oid = sample_object_id();
        let meta = sample_signed_metadata();
        let sig = sample_signature();
        let broker = StubBroker::start(ServerMessage::RunAgentCompleted {
            output_oid: oid.clone(),
            signed_metadata: meta.clone(),
            signature: sig.clone(),
        })
        .await;

        let client = WritClient::new(&broker.socket_path);
        let got = client.run_agent(sample_request()).await.unwrap();
        assert_eq!(got.output_oid, oid);
        assert_eq!(got.signed_metadata, meta);
        assert_eq!(got.signature, sig);

        // The broker actually saw a `RunAgent` framed on one line.
        let seen = broker.observed_requests().await;
        assert_eq!(seen.len(), 1);
        assert!(matches!(seen[0], ClientMessage::RunAgent { .. }));
    }

    /// The request fields make it onto the wire verbatim — purpose
    /// in particular round-trips byte-for-byte so audit reconciliation
    /// downstream can rely on writ never reinterpreting it.
    #[tokio::test]
    async fn run_agent_serializes_request_fields_verbatim() {
        let broker = StubBroker::start(ServerMessage::RunAgentCompleted {
            output_oid: sample_object_id(),
            signed_metadata: sample_signed_metadata(),
            signature: sample_signature(),
        })
        .await;

        let mut req = sample_request();
        req.purpose = "plan-stage:abc123".to_string();
        let client = WritClient::new(&broker.socket_path);
        client.run_agent(req.clone()).await.unwrap();

        let seen = broker.observed_requests().await;
        match &seen[0] {
            ClientMessage::RunAgent {
                purpose,
                output_ref,
                ..
            } => {
                assert_eq!(purpose, "plan-stage:abc123");
                assert_eq!(output_ref, &req.output_ref);
            }
            other => panic!("expected RunAgent, got {other:?}"),
        }
    }

    /// Workspace bootstrap on the `RunAgentRequest` lands on the wire
    /// under the `workspace` field of `ClientMessage::RunAgent`, and
    /// the paired `agent_kind` / `agent_model` ride along verbatim.
    /// Slice VM3 wires bailiff's `submit_implement` to set these so
    /// the broker dispatches into the per-run VM arm; a regression
    /// that drops any of the three on the floor would surface here as
    /// a `None` on the captured wire message instead of being noticed
    /// only when the VM dispatch arm rejects the request.
    #[tokio::test]
    async fn run_agent_serializes_workspace_and_agent_identity_verbatim() {
        let broker = StubBroker::start(ServerMessage::RunAgentCompleted {
            output_oid: sample_object_id(),
            signed_metadata: sample_signed_metadata(),
            signature: sample_signature(),
        })
        .await;

        let workspace = sample_workspace_bootstrap();
        let mut req = sample_request();
        req.workspace = Some(workspace.clone());
        req.agent_kind = Some(AgentKind::Claude);
        req.agent_model = Some("claude-opus-4-7".into());

        let client = WritClient::new(&broker.socket_path);
        client.run_agent(req).await.unwrap();

        let seen = broker.observed_requests().await;
        match &seen[0] {
            ClientMessage::RunAgent {
                workspace: wire_workspace,
                agent_kind: wire_kind,
                agent_model: wire_model,
                ..
            } => {
                assert_eq!(wire_workspace.as_ref(), Some(&workspace));
                assert_eq!(*wire_kind, Some(AgentKind::Claude));
                assert_eq!(wire_model.as_deref(), Some("claude-opus-4-7"));
            }
            other => panic!("expected RunAgent, got {other:?}"),
        }
    }

    /// A `RunAgentRequest` whose workspace `destination` carries
    /// non-UTF-8 bytes (legal `PathBuf` content on Unix) must come back
    /// as a typed `WritClientError::Serialize`, not a panic from the
    /// `serde_json::to_string` call inside `roundtrip`. The bailiff CLI
    /// validates its `--workspace-destination` flag before constructing
    /// a `RunAgentRequest`, but `WritClient` is a public API and any
    /// other consumer that hands in a non-UTF-8 path must observe an
    /// error variant they can react to without parsing prose.
    #[tokio::test]
    #[cfg(unix)]
    async fn run_agent_returns_serialize_error_for_non_utf8_workspace_destination() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        // The broker is wired up but should never actually see a line:
        // the client should fail before writing. `start` is enough — the
        // broker queues one reply that simply goes unused.
        let broker = StubBroker::start(ServerMessage::RunAgentCompleted {
            output_oid: sample_object_id(),
            signed_metadata: sample_signed_metadata(),
            signature: sample_signature(),
        })
        .await;

        let bad_destination = PathBuf::from(OsString::from_vec(vec![0xff, 0xfe, 0xfd]));
        let workspace = AgentVmWorkspaceBootstrap {
            repo: GitCloneRepo::new(RepoRef {
                owner: "smaug123".into(),
                name: "writ".into(),
            })
            .unwrap(),
            destination: Some(bad_destination),
            warm: WorkspaceWarmMode::DevShell,
        };

        let mut req = sample_request();
        req.workspace = Some(workspace);
        req.agent_kind = Some(AgentKind::Claude);
        req.agent_model = Some("claude-opus-4-7".into());

        let client = WritClient::new(&broker.socket_path);
        let err = client.run_agent(req).await.unwrap_err();
        assert!(
            matches!(err, WritClientError::Serialize { .. }),
            "expected Serialize, got {err:?}",
        );

        // And the broker must not have received any framed request:
        // `serde_json::to_string` failed before the write hit the wire,
        // so the stub's accept loop sees no line.
        assert!(
            broker.observed_requests().await.is_empty(),
            "client must fail before writing when serialization refuses the message",
        );
    }

    /// A structured `ServerMessage::Error` becomes
    /// `WritClientError::WritError`, not a parse failure: the
    /// message round-trips so callers can surface it.
    #[tokio::test]
    async fn run_agent_surfaces_writ_error_reply() {
        let broker = StubBroker::start(ServerMessage::Error {
            message: "policy denied: missing capability".to_string(),
        })
        .await;
        let client = WritClient::new(&broker.socket_path);
        let err = client.run_agent(sample_request()).await.unwrap_err();
        match err {
            WritClientError::WritError { message } => {
                assert_eq!(message, "policy denied: missing capability")
            }
            other => panic!("expected WritError, got {other:?}"),
        }
    }

    /// A structurally-valid `ServerMessage` that isn't the legal
    /// answer to `RunAgent` becomes `UnexpectedMessage`, distinct
    /// from both decode errors and `WritError`. Callers can react
    /// to "writ violated the protocol" without parsing prose.
    #[tokio::test]
    async fn run_agent_rejects_unexpected_reply_variant() {
        let broker = StubBroker::start(ServerMessage::SessionClosed).await;
        let client = WritClient::new(&broker.socket_path);
        let err = client.run_agent(sample_request()).await.unwrap_err();
        assert!(
            matches!(err, WritClientError::UnexpectedMessage { .. }),
            "expected UnexpectedMessage, got {err:?}"
        );
    }

    /// `UnknownSession` is a typed failure mode, not a protocol bug:
    /// the broker speaks it when a caller-supplied `session_id` doesn't
    /// match any audit row. The client surfaces the id so cleanup can
    /// dispatch on the variant rather than parse prose.
    #[tokio::test]
    async fn run_agent_surfaces_unknown_session_reply() {
        let stale = sample_session_id();
        let broker = StubBroker::start(ServerMessage::UnknownSession { session_id: stale }).await;
        let client = WritClient::new(&broker.socket_path);
        let mut req = sample_request();
        req.session_id = Some(stale);
        let err = client.run_agent(req).await.unwrap_err();
        match err {
            WritClientError::UnknownSession { session_id } => assert_eq!(session_id, stale),
            other => panic!("expected UnknownSession, got {other:?}"),
        }
    }

    /// `ClosedSession` is the racier sibling of `UnknownSession`: a
    /// session that existed at one point but has already been closed.
    /// Same routing — distinct typed variant, id round-trips.
    #[tokio::test]
    async fn run_agent_surfaces_closed_session_reply() {
        let stale = sample_session_id();
        let broker = StubBroker::start(ServerMessage::ClosedSession { session_id: stale }).await;
        let client = WritClient::new(&broker.socket_path);
        let mut req = sample_request();
        req.session_id = Some(stale);
        let err = client.run_agent(req).await.unwrap_err();
        match err {
            WritClientError::ClosedSession { session_id } => assert_eq!(session_id, stale),
            other => panic!("expected ClosedSession, got {other:?}"),
        }
    }

    /// `open_session` returns the broker-minted id and frames an
    /// `OpenSession` message verbatim (label, agent kind, model all
    /// land in the request).
    #[tokio::test]
    async fn open_session_round_trips_session_opened_reply() {
        let session_id = sample_session_id();
        let broker = StubBroker::start(ServerMessage::SessionOpened { session_id }).await;
        let client = WritClient::new(&broker.socket_path);
        let got = client
            .open_session(
                Some("plan-submit:abc".into()),
                Some(AgentKind::Claude),
                Some("claude-test".into()),
            )
            .await
            .unwrap();
        assert_eq!(got, session_id);

        let seen = broker.observed_requests().await;
        match &seen[0] {
            ClientMessage::OpenSession {
                label,
                agent_kind,
                agent_model,
            } => {
                assert_eq!(label.as_deref(), Some("plan-submit:abc"));
                assert_eq!(*agent_kind, Some(AgentKind::Claude));
                assert_eq!(agent_model.as_deref(), Some("claude-test"));
            }
            other => panic!("expected OpenSession, got {other:?}"),
        }
    }

    /// A broker `Error` reply to `OpenSession` becomes `WritError`,
    /// not a parse failure: bailiff's `submit_plan` can surface the
    /// reason without string-matching.
    #[tokio::test]
    async fn open_session_surfaces_writ_error_reply() {
        let broker = StubBroker::start(ServerMessage::Error {
            message: "audit insert failed".into(),
        })
        .await;
        let client = WritClient::new(&broker.socket_path);
        let err = client.open_session(None, None, None).await.unwrap_err();
        match err {
            WritClientError::WritError { message } => assert_eq!(message, "audit insert failed"),
            other => panic!("expected WritError, got {other:?}"),
        }
    }

    /// Any reply that isn't `SessionOpened` (or `Error`) is a
    /// protocol bug — distinct from `WritError` so the caller can
    /// react without parsing prose.
    #[tokio::test]
    async fn open_session_rejects_unexpected_reply_variant() {
        let broker = StubBroker::start(ServerMessage::SessionClosed).await;
        let client = WritClient::new(&broker.socket_path);
        let err = client.open_session(None, None, None).await.unwrap_err();
        assert!(
            matches!(err, WritClientError::UnexpectedMessage { .. }),
            "expected UnexpectedMessage, got {err:?}"
        );
    }

    /// `close_session` returns `Ok(())` on `SessionClosed` and
    /// frames the request with the supplied id.
    #[tokio::test]
    async fn close_session_round_trips_session_closed_reply() {
        let session_id = sample_session_id();
        let broker = StubBroker::start(ServerMessage::SessionClosed).await;
        let client = WritClient::new(&broker.socket_path);
        client.close_session(session_id).await.unwrap();

        let seen = broker.observed_requests().await;
        match &seen[0] {
            ClientMessage::CloseSession {
                session_id: seen_id,
            } => assert_eq!(*seen_id, session_id),
            other => panic!("expected CloseSession, got {other:?}"),
        }
    }

    /// `close_session` distinguishes a structured broker error
    /// ("unknown session") from "writ said something else" — the
    /// caller drives the cleanup retry off the variant, not a string
    /// match.
    #[tokio::test]
    async fn close_session_surfaces_writ_error_reply() {
        let broker = StubBroker::start(ServerMessage::Error {
            message: "session not found".into(),
        })
        .await;
        let client = WritClient::new(&broker.socket_path);
        let err = client.close_session(sample_session_id()).await.unwrap_err();
        assert!(
            matches!(err, WritClientError::WritError { .. }),
            "expected WritError, got {err:?}"
        );
    }

    /// No listener at the configured path is `Connect`, not a panic
    /// or a generic IO error — operators see the path they tried.
    #[tokio::test]
    async fn run_agent_reports_connect_failure_with_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.sock");
        let client = WritClient::new(&missing);
        let err = client.run_agent(sample_request()).await.unwrap_err();
        match err {
            WritClientError::Connect { path, .. } => assert_eq!(path, missing),
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    /// Broker accepts the connection, reads the request, then closes
    /// without writing a reply: client distinguishes this from a
    /// transport failure. The stub *must* drain the request line before
    /// dropping — on Linux, dropping with unread data in the receive
    /// queue triggers an RST instead of a clean FIN, which would surface
    /// as `ReadFraming(ConnectionReset)` rather than `ReadEof`.
    #[tokio::test]
    async fn run_agent_reports_eof_when_broker_closes_silently() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("writ.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let _task = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (reader, _writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();
                let _ = lines.next_line().await;
            }
        });

        let client = WritClient::new(&socket_path);
        let err = client.run_agent(sample_request()).await.unwrap_err();
        assert!(
            matches!(err, WritClientError::ReadEof),
            "expected ReadEof, got {err:?}"
        );
    }

    /// Broker writes bytes that aren't a `ServerMessage`: surfaces as
    /// `ReadDecode`, not `UnexpectedMessage` (which is reserved for
    /// structurally-valid-but-wrong-variant replies).
    #[tokio::test]
    async fn run_agent_reports_decode_failure_on_garbage_reply() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("writ.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let _task = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (_r, mut w) = stream.into_split();
                let _ = w.write_all(b"not json at all\n").await;
                let _ = w.shutdown().await;
            }
        });

        let client = WritClient::new(&socket_path);
        let err = client.run_agent(sample_request()).await.unwrap_err();
        assert!(
            matches!(err, WritClientError::ReadDecode { .. }),
            "expected ReadDecode, got {err:?}"
        );
    }

    /// A reply longer than `MAX_LINE_BYTES` without a newline trips
    /// the bounded read — bailiff doesn't OOM if writ misbehaves.
    #[tokio::test]
    async fn run_agent_caps_oversize_reply() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("writ.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let _task = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (_r, mut w) = stream.into_split();
                let big = vec![b'x'; MAX_LINE_BYTES + 1024];
                let _ = w.write_all(&big).await;
                let _ = w.shutdown().await;
            }
        });

        let client = WritClient::new(&socket_path);
        let err = client.run_agent(sample_request()).await.unwrap_err();
        assert!(
            matches!(err, WritClientError::ReadFraming { .. }),
            "expected ReadFraming, got {err:?}"
        );
    }

    /// `read_line_bounded` strips the trailing `\r` so callers can
    /// match against bytes without worrying about CRLF.
    #[tokio::test]
    async fn read_line_bounded_strips_cr() {
        let mut input = &b"hello\r\n"[..];
        let line = read_line_bounded(&mut input, 64).await.unwrap().unwrap();
        assert_eq!(&line, b"hello");
    }

    /// Stream-pair sanity check: a writer-side stream that closes
    /// without writing yields `Ok(None)` from `read_line_bounded`,
    /// matching the EOF semantics `WritClient` translates to
    /// `ReadEof`.
    #[tokio::test]
    async fn read_line_bounded_returns_none_on_clean_eof_over_pair() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(b);
        let mut reader = BufReader::new(a);
        // Short timeout so the test fails fast if EOF detection breaks.
        let line = tokio::time::timeout(Duration::from_secs(2), read_line_bounded(&mut reader, 64))
            .await
            .unwrap()
            .unwrap();
        assert!(line.is_none());
    }
}

#[cfg(test)]
mod end_to_end_tests {
    //! Slice B's headline contract test: bailiff sends `RunAgent` over
    //! the writ Unix socket; writ runs the (no-op) child, signs the
    //! envelope, writes it as a Git note in writ's bare repo, and
    //! returns `RunAgentCompleted`. Bailiff then fetches writ's notes
    //! ref into its own bare repo and verifies the signature.
    //!
    //! Every hop is exercised against the real binaries and real
    //! crypto — no mocked socket, no mocked spawner, no mocked git.
    //! The only mock is the GitHub installation-token endpoint, which
    //! `RunAgent` never touches but which `BrokerState` requires a
    //! non-empty registry for.
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::sync::Mutex as AsyncMutex;
    use wiremock::MockServer;

    use super::*;
    use crate::agent_run::{AgentPrompt, sha256_hex};
    use crate::audit::AuditLog;
    use crate::core::{AgentKind, CapabilitySet, NotesRef, RepoRef, TtlSeconds};
    use crate::github::{GitHubAppConfig, GitHubAppRegistryConfig, GitHubMinter};
    use crate::notes_repo::NotesRepo;
    use crate::policy::PolicyConfig;
    use crate::run_envelope::SignedRunEnvelope;
    use crate::run_verify::{AllowedSigners, verify_run_envelope};
    use crate::secret::{SecretError, SecretKey, SecretStore};
    use crate::server::{
        BrokerState, RunAgentSpawnConfig, prepare_broker_listener, serve_broker_with_agent_vm,
    };
    use crate::signing::WritSigningKey;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");
    const TEST_PRIV: &str = include_str!("../tests/fixtures/rsa_test_1.pem");

    /// In-memory `SecretStore`. The production-grade `FileSecretStore`
    /// would do here too, but that needs disk and key derivation; for
    /// a test that only stores the GitHub-app PEM to satisfy
    /// `BrokerState`'s non-empty registry invariant, an in-memory map
    /// is the smallest dependency that works.
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

    /// End-to-end socket round-trip.
    ///
    /// What this exercises that the unit tests above and the slice-B5
    /// round-trip (`src/run_verify.rs`) don't:
    /// - `WritClient::run_agent` over a real Unix socket against
    ///   `serve_broker_with_agent_vm`'s real accept loop.
    /// - Full `dispatch_message` `RunAgent` path: spawn `/bin/cat` as
    ///   the noop agent, capture stdout, sign metadata, persist note.
    /// - `NotesRepo::fetch_from_remote` pulling writ's notes ref into
    ///   a separate bailiff-side bare repo via the real `git fetch`.
    /// - `verify_run_envelope` against an `AllowedSigners` parsed from
    ///   the published OpenSSH public key, completing the trust chain.
    ///
    /// A regression anywhere in this chain — protocol framing, JSON
    /// serialisation, spawn config, signing namespace, notes write,
    /// fetch refspec, digest binding, sshsig verification — fails this
    /// test rather than getting caught by a downstream consumer.
    #[tokio::test]
    async fn run_agent_round_trips_over_socket_against_real_broker() {
        // --- Broker bring-up (writ side) ----------------------------
        let tmp = tempfile::tempdir().unwrap();
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");

        // `BrokerState` requires a non-empty GitHub registry; RunAgent
        // never mints a token so the wiremock URL is unused. The
        // smallest dependency that satisfies the invariant.
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
            signing_key: Some(signing_key.clone()),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: cat,
                args: Vec::new(),
            }),
            promote_runtime: None,
            git_data_http: crate::github_git_db::GitDataHttp::production(),
            mirror_pins: crate::vm_git_mirror_cache::MirrorPins::new(),
            chatgpt_oauth_authority: Default::default(),
        });

        // Bind a tempsocket and spawn the broker accept loop. The
        // listener is owned by the spawned task; the test reaches it
        // through the path. `prepare_broker_listener` refuses to bind
        // in a directory with group/world bits — `tempfile::tempdir`
        // default is 0755 on macOS, so we explicitly chmod 700.
        use std::os::unix::fs::PermissionsExt;
        let socket_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let socket_path = socket_dir.path().join("writ.sock");
        let listener = prepare_broker_listener(&socket_path).await.unwrap();
        let broker_state = Arc::clone(&state);
        let broker_task = tokio::spawn(async move {
            // `agent_vm = None` matches the production daemon paths
            // that don't run a daemon-managed VM. RunAgent doesn't
            // touch the agent-vm daemon either.
            let _ = serve_broker_with_agent_vm(listener, broker_state, None).await;
        });

        // --- Client request (bailiff side) --------------------------
        let prompt_text = "noop\n";
        let output_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
        let client = WritClient::new(&socket_path);
        let completed = tokio::time::timeout(
            Duration::from_secs(15),
            client.run_agent(RunAgentRequest {
                prompt: AgentPrompt::new(prompt_text),
                capabilities: vec![CapabilitySet::WorkspaceRead {
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
            }),
        )
        .await
        .expect("round-trip must complete within 15s")
        .expect("RunAgent must succeed");

        // The reply carries writ's signing-key fingerprint and the
        // child's exit status (0 for `cat` reading EOF).
        assert_eq!(
            completed.signed_metadata.signing_key_fingerprint,
            signing_key.fingerprint()
        );
        assert_eq!(completed.signed_metadata.exit_code, 0);
        assert_eq!(
            completed.signed_metadata.prompt_sha256.as_str(),
            sha256_hex(prompt_text.as_bytes())
        );

        // --- Cross-daemon note transfer (bailiff fetch) -------------
        // Bailiff doesn't open writ's repo directly; it fetches the
        // notes ref into its own bare repo. Using the real `git
        // fetch` from `NotesRepo::fetch_from_remote` here exercises
        // the same code path bailiff will run in production.
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let output_oid = completed.output_oid.clone();
        let body = {
            let bailiff = Arc::new(AsyncMutex::new(bailiff_repo));
            let bailiff_clone = Arc::clone(&bailiff);
            let writ_repo_path_clone = writ_repo_path.clone();
            let output_ref_clone = output_ref.clone();
            let oid_clone = output_oid.clone();
            // `NotesRepo` operations are blocking (they shell out to
            // git); wrap in `spawn_blocking` so we don't stall the
            // tokio runtime. A short async lock keeps the
            // single-writer invariant on bailiff's repo.
            tokio::task::spawn_blocking(move || {
                let bailiff = bailiff_clone.blocking_lock();
                bailiff
                    .fetch_from_remote(
                        &writ_repo_path_clone,
                        &["+refs/notes/writ/v1/*:refs/notes/writ/v1/*"],
                    )
                    .expect("bailiff must fetch writ's notes ref");
                bailiff
                    .read_note(&output_ref_clone, &oid_clone)
                    .expect("bailiff must read the fetched note")
            })
            .await
            .unwrap()
        };

        // --- Verification (bailiff side) ----------------------------
        // The verifier sees only the bytes that survived the round
        // trip — none of the in-memory `completed` values. If any hop
        // (envelope encoding, note storage, git fetch) had silently
        // mangled the payload, the digest binding inside the envelope
        // would catch it.
        let envelope = SignedRunEnvelope::from_bytes(&body).unwrap();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        verify_run_envelope(&envelope, &allowed)
            .expect("fetched envelope must verify under writ's published key");

        // And the verified envelope's metadata is byte-identical to
        // what writ returned on the wire — the wire shape and the
        // persisted shape agree.
        assert_eq!(envelope.metadata, completed.signed_metadata);
        assert_eq!(envelope.signature, completed.signature);

        broker_task.abort();
        let _ = broker_task.await;
    }

    /// A prompt at the high end of the `MAX_AGENT_PROMPT_BYTES`
    /// ceiling — and dominated by ASCII control characters, so
    /// `serde_json` expands every byte to a 6-character `\u00XX`
    /// escape — fits through the framing layer without being
    /// clipped by `read_line_bounded`. Pins the cross-end agreement
    /// that `MAX_LINE_BYTES` accommodates the *worst-case* serialized
    /// size of a wire-valid `AgentPrompt`, not just the raw byte
    /// length, so a prompt that the prompt validator accepts is
    /// always a frame the broker accepts.
    #[tokio::test]
    async fn run_agent_carries_large_prompt_through_framing() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let cat = find_in_path("cat").expect("cat must be on PATH");

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
            signing_key: Some(signing_key.clone()),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: cat,
                args: Vec::new(),
            }),
            promote_runtime: None,
            git_data_http: crate::github_git_db::GitDataHttp::production(),
            mirror_pins: crate::vm_git_mirror_cache::MirrorPins::new(),
            chatgpt_oauth_authority: Default::default(),
        });
        let socket_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let socket_path = socket_dir.path().join("writ.sock");
        let listener = prepare_broker_listener(&socket_path).await.unwrap();
        let broker_state = Arc::clone(&state);
        let broker_task = tokio::spawn(async move {
            let _ = serve_broker_with_agent_vm(listener, broker_state, None).await;
        });

        // 1 MiB minus a small margin (control char `\u{0001}` is one
        // byte raw, but the prompt validator counts raw bytes; the
        // margin protects against any future tightening of the
        // ceiling). Every byte is `\u{0001}`, which serde_json
        // escapes as the 6-character literal \u0001 — exactly the 6:1
        // worst-case expansion the cap is sized for.
        let big = "\u{0001}".repeat(crate::agent_run::MAX_AGENT_PROMPT_BYTES - 4096);
        let prompt = AgentPrompt::new(&big);
        let output_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
        let client = WritClient::new(&socket_path);
        let completed = tokio::time::timeout(
            Duration::from_secs(30),
            client.run_agent(RunAgentRequest {
                prompt,
                capabilities: vec![CapabilitySet::WorkspaceRead {
                    repo: RepoRef {
                        owner: "smaug123".into(),
                        name: "writ".into(),
                    },
                }],
                purpose: "large-prompt".into(),
                output_ref,
                session_id: None,
                workspace: None,
                agent_kind: None,
                agent_model: None,
            }),
        )
        .await
        .expect("large-prompt round-trip must complete within 30s")
        .expect("large-prompt RunAgent must succeed");
        assert_eq!(completed.signed_metadata.exit_code, 0);
        assert_eq!(
            completed.signed_metadata.prompt_sha256.as_str(),
            sha256_hex(big.as_bytes())
        );

        broker_task.abort();
        let _ = broker_task.await;
    }
}
