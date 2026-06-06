//! `RunAgent` dispatch: spawning, signing, capture caps, and agent-VM gating.

use super::test_support::*;
use super::*;
use crate::core::{AgentKind, RepoRef};
use wiremock::MockServer;

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
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap(),
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
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap(),
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
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap(),
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

    const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");

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
    let base =
        Arc::try_unwrap(base).unwrap_or_else(|_| panic!("make_state Arc must be uniquely held"));
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
        mirror_pins: base.mirror_pins,
    });

    let prompt_text = "hello world from cat\n";
    let output_ref = crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
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

    const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");

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
        mirror_pins: base.mirror_pins,
    });

    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("ignored"),
            capabilities: Vec::new(),
            purpose: "non-zero-exit".into(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
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

    const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");

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
        mirror_pins: base.mirror_pins,
    });

    let output_ref = crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
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

    const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");

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
        mirror_pins: base.mirror_pins,
    });

    let output_ref = crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
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

    const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");

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
        mirror_pins: base.mirror_pins,
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
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
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

    const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");

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
        mirror_pins: base.mirror_pins,
    });

    let bogus = SessionId::new();
    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("hi"),
            capabilities: Vec::new(),
            purpose: "unknown-session".into(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
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

    const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");

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
        mirror_pins: base.mirror_pins,
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
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
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
