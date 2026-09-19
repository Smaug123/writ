//! What the integration suites share: the constants and small values every
//! scenario uses, a stub broker that records what a workflow sends, and a
//! writ repo holding one signed envelope for the workflows to verify.
//!
//! Each test binary compiles this file on its own and uses a subset of it,
//! hence the `dead_code` allowance.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use writ::agent_run::{AgentRunId, sha256_hex};
use writ::core::{CapabilitySet, NotesRef, RepoRef, SessionId, UnixMillis};
use writ::notes_repo::NotesRepo;
use writ::protocol::{ClientMessage, ServerMessage, SignedRunMetadata};
use writ::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use writ::run_verify::AllowedSigners;
use writ::signing::WritSigningKey;
use writ::test_support::{ED25519_SIGNING_PEM as SIGNING_PEM, ED25519_SIGNING_PUB as SIGNING_PUB};
use writ::vm_git::GitObjectId;

/// The plan body every scenario uses. Also the agent's stdout, since the
/// planner's stdout *is* the plan body.
pub const PLAN_BODY: &str = "# Plan\n\nReplace bar with baz.\n";

pub const WRIT_OUTPUT_REF: &str = "refs/notes/writ/v1/agent-outputs";

/// Fixed so recorded traces do not depend on a random id. The broker picks
/// session ids in production; the stub picks this one.
pub fn stub_session_id() -> SessionId {
    "3f2504e0-4f89-41d3-9a0c-0305e82c3301".parse().unwrap()
}

pub fn repo_ref() -> RepoRef {
    RepoRef {
        owner: "smaug123".into(),
        name: "writ".into(),
    }
}

pub fn writ_output_ref() -> NotesRef {
    NotesRef::try_new(WRIT_OUTPUT_REF).unwrap()
}

pub fn allowed_signers() -> AllowedSigners {
    AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap()
}

/// Stub broker: answers the version handshake, reads one [`ClientMessage`]
/// per connection, records it, and replies with the next scripted
/// [`ServerMessage`].
///
/// One message per connection matches `WritClient`'s round-trip shape: it
/// dials per RPC. Replies are consumed in order, so a scenario scripts
/// exactly as many as its workflow should send — a workflow that sends more
/// is still *recorded*, then hung up on, so the extra RPC shows up as a
/// fixture diff rather than only as a transport error the caller might
/// swallow. With no replies at all it is a pure recorder: every RPC is
/// observed and none is answered.
pub struct StubBroker {
    pub socket_path: PathBuf,
    requests: Arc<AsyncMutex<Vec<ClientMessage>>>,
    _task: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl StubBroker {
    pub async fn start(replies: Vec<ServerMessage>) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = dir.path().join("writ.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let requests = Arc::new(AsyncMutex::new(Vec::new()));
        let req_clone = Arc::clone(&requests);
        let mut replies = replies.into_iter();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                // The daemon's own handshake rule, not a second copy of it: a
                // stub that accepted a version writd would refuse would be
                // testing a protocol nothing speaks.
                if !writ::server::answer_host_handshake(&mut reader, &mut writer)
                    .await
                    .unwrap_or(false)
                {
                    continue;
                }
                let mut lines = reader.lines();
                // Record *before* looking for a reply. Draining the request
                // first is what makes the zero-RPC assertions mean anything:
                // a stub that returned without reading when it had no
                // scripted reply would give a workflow that sent an RPC before
                // its gate an EOF, a transport error `expect_err` accepts, and
                // an empty `observed()`, so the check would pass on exactly
                // the regression it exists to catch.
                if let Ok(Some(line)) = lines.next_line().await
                    && let Ok(msg) = serde_json::from_str::<ClientMessage>(&line)
                {
                    req_clone.lock().await.push(msg);
                }
                let Some(reply) = replies.next() else {
                    // Unscripted request: recorded, then hung up on.
                    continue;
                };
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

    pub async fn observed(&self) -> Vec<ClientMessage> {
        self.requests.lock().await.clone()
    }
}

/// The signed envelope's output: [`PLAN_BODY`] on stdout, nothing on stderr.
pub fn plan_output_bytes() -> Vec<u8> {
    OutputEnvelope {
        stdout: PLAN_BODY.as_bytes().to_vec(),
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    }
    .to_bytes()
}

/// A writ repo holding one signed envelope whose stdout is [`PLAN_BODY`],
/// plus the OID it is attached at.
///
/// Every scenario reuses one envelope: the workflows fetch writ's notes ref
/// and verify whatever `RunAgentCompleted` points at, so the stub's reply can
/// name this same OID for the planner, reviewer, and implementer runs alike,
/// and a pre-RPC envelope read always succeeds, so a refusal can only come
/// from the gate.
pub struct WritSide {
    pub repo_path: PathBuf,
    pub oid: GitObjectId,
    pub metadata: SignedRunMetadata,
    pub signature: writ::core::SshSignature,
}

pub fn build_writ_side(dir: &Path) -> WritSide {
    let repo = NotesRepo::init_or_open(dir.join("writ-bare")).unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let output_bytes = plan_output_bytes();
    let metadata = SignedRunMetadata {
        run_id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
            .parse::<AgentRunId>()
            .unwrap(),
        session_id: stub_session_id(),
        prompt_sha256: sha256_hex(b"prompt"),
        output_envelope_sha256: sha256_hex(&output_bytes),
        capabilities: vec![CapabilitySet::WorkspaceRead { repo: repo_ref() }],
        exit_code: 0,
        completed_at: UnixMillis::from_millis(1_700_000_000_000),
        signing_key_fingerprint: signing_key.fingerprint(),
    };
    let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
    let envelope = SignedRunEnvelope {
        metadata: metadata.clone(),
        output: output_bytes,
        signature: signature.clone(),
    };
    let oid = repo
        .write_note(
            &writ_output_ref(),
            b"writ-side-seed",
            &serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
    WritSide {
        repo_path: repo.path().to_path_buf(),
        oid,
        metadata,
        signature,
    }
}
