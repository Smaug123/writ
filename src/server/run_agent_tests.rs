//! `RunAgent` dispatch: spawning, signing, capture caps, and agent-VM gating.

use super::test_support::*;
use super::*;
use crate::core::{AgentKind, RepoRef, SshSignature};
use crate::protocol::SignedRunMetadata;
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
            purpose: "test".parse().unwrap(),
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
            purpose: "implement-stage".parse().unwrap(),
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
            purpose: "implement-stage".parse().unwrap(),
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
    let fixture = make_run_agent_state(&server, cat, Vec::new());
    let state = &fixture.state;
    let verifying_key = fixture.signing_key.verifying_key();
    let fingerprint = fixture.signing_key.fingerprint();
    let session_id = open_session(state).await;

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
            purpose: "round-trip-test".parse().unwrap(),
            output_ref: output_ref.clone(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
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

    let false_bin = find_in_path("false").expect("false must be on PATH for the test");
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(&server, false_bin, Vec::new());
    let state = &fixture.state;
    let session_id = open_session(state).await;

    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("ignored"),
            capabilities: Vec::new(),
            purpose: "non-zero-exit".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
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

/// A configured `spawn_timeout_secs` reaches an actual host run, ends it, and
/// is recorded as writ's doing.
///
/// End-to-end on purpose. Every step between the config key and the audit row
/// is somewhere the deadline could be silently dropped — the plan builder, the
/// spawn config, the blocking-pool hop — and none of those is visible from a
/// unit test of the runner. The agent here sleeps for 300 seconds, so no
/// outcome this test observes has "it finished on its own" as an explanation.
#[tokio::test]
async fn a_configured_timeout_ends_a_host_run_and_the_log_says_writ_ended_it() {
    let sh = find_in_path_any(&["sh", "bash"]);
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(&server, sh, vec!["-c".into(), "sleep 300".into()])
        .with_agent_timeout(crate::agent_run::AgentRunTimeout::from_secs(1).unwrap());
    let state = &fixture.state;
    let session_id = open_session(state).await;

    let started = std::time::Instant::now();
    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("this will not finish"),
            capabilities: Vec::new(),
            purpose: "timeout".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;
    let elapsed = started.elapsed();

    let run_id = match resp {
        ServerMessage::RunAgentCompleted {
            signed_metadata, ..
        } => signed_metadata.run_id,
        other => panic!("expected RunAgentCompleted, got {other:?}"),
    };
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "the run took {elapsed:?}, so the deadline is not reaching the host arm"
    );

    // A timed-out run is a *completed* run in the log — the request row is
    // paired, not left dangling — because writ knows exactly how it ended.
    let outcome = state
        .audit
        .get_agent_run_outcome(run_id)
        .unwrap()
        .expect("a timed-out run records its outcome");
    assert_eq!(
        outcome.outcome.status,
        crate::agent_run::AgentRunTerminalStatus::TimedOut
    );
    assert_eq!(outcome.outcome.exit_code, -1);
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

    let sh = find_in_path_any(&["sh", "bash"]);
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(
        &server,
        sh,
        vec!["-c".into(), "printf out; printf err 1>&2; exit 0".into()],
    );
    let state = &fixture.state;
    let session_id = open_session(state).await;

    let output_ref = crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("ignored"),
            capabilities: Vec::new(),
            purpose: "stderr-capture".parse().unwrap(),
            output_ref: output_ref.clone(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
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

    let sh = find_in_path_any(&["sh", "bash"]);
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(
        &server,
        sh,
        // Emit MAX_RUN_AGENT_STREAM_BYTES + 1 KiB of stdout so
        // the cap path runs without depending on shell-builtin
        // performance for many megabytes of output. dd with a
        // 1 MiB block size and (cap_mib + 1 / 1024) reps would
        // be tidier, but `head -c` from /dev/zero is portable
        // across BSD and GNU userland.
        vec![
            "-c".into(),
            format!("head -c {} /dev/zero", MAX_RUN_AGENT_STREAM_BYTES + 1024),
        ],
    );
    let state = &fixture.state;
    let session_id = open_session(state).await;

    let output_ref = crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("ignored"),
            capabilities: Vec::new(),
            purpose: "truncation".parse().unwrap(),
            output_ref: output_ref.clone(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;

    let (output_oid, run_id) = match resp {
        ServerMessage::RunAgentCompleted {
            output_oid,
            signed_metadata,
            ..
        } => (output_oid, signed_metadata.run_id),
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

    // The audit row must tell the same story as the envelope: an operator
    // who opens `stdout_path` sees exactly the retained prefix, and
    // `truncated` warns them it is a prefix. `byte_len` describes the file,
    // not the stream the child produced — that number is deliberately not
    // recorded (see `AgentRunStreamSummary`).
    let outcome = state
        .audit
        .get_agent_run_outcome(run_id)
        .unwrap()
        .expect("a completed host-spawn run has an outcome row");
    assert!(outcome.outcome.stdout.truncated);
    assert_eq!(
        outcome.outcome.stdout.byte_len,
        MAX_RUN_AGENT_STREAM_BYTES as u64,
    );
    assert_eq!(
        std::fs::metadata(&outcome.outcome.stdout.path)
            .unwrap()
            .len(),
        MAX_RUN_AGENT_STREAM_BYTES as u64,
    );
    assert!(!outcome.outcome.stderr.truncated);
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

    let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(&server, cat, Vec::new());
    let state = &fixture.state;

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
            purpose: "bound-session".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
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
    let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(&server, cat, Vec::new());
    let state = &fixture.state;

    let bogus = SessionId::new();
    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("hi"),
            capabilities: Vec::new(),
            purpose: "unknown-session".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(bogus),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
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

    let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(&server, cat, Vec::new());
    let state = &fixture.state;

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
            purpose: "closed-session".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;
    match resp {
        ServerMessage::ClosedSession { session_id: seen } => assert_eq!(seen, session_id),
        other => panic!("expected ClosedSession, got {other:?}"),
    }
}

/// A host-spawned run records the same `(agent_run, agent_run_outcome)`
/// pair the VM arm records, naming the files its streams landed in.
///
/// Before this, the host arm wrote *no* audit rows at all: bailiff's submit
/// and review stages ran real agents that left no trace in the log writ
/// claims is complete by construction ("because the only way to act is to
/// obtain a grant, the SQLite log *is* the history"). The row is what makes
/// the run visible; the stream paths are what make its output retrievable
/// once the wire response is gone.
#[tokio::test]
async fn a_host_spawned_run_records_an_audit_pair_naming_its_streams() {
    let sh = find_in_path_any(&["sh", "bash"]);
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(
        &server,
        sh,
        vec!["-c".into(), "printf out; printf err 1>&2".into()],
    );
    let state = &fixture.state;
    let session_id = open_session(state).await;

    let prompt_text = "audited prompt";
    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new(prompt_text),
            capabilities: Vec::new(),
            purpose: "audit-pair".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;
    let signed_metadata = match resp {
        ServerMessage::RunAgentCompleted {
            signed_metadata, ..
        } => signed_metadata,
        other => panic!("expected RunAgentCompleted, got {other:?}"),
    };
    let run_id = signed_metadata.run_id;

    let request = state
        .audit
        .get_agent_run(run_id)
        .unwrap()
        .expect("a host-spawn run records its request row");
    assert_eq!(request.session_id, session_id);
    // Identity comes from the session row, which is where the caller fixed it
    // at `OpenSession` — the host arm has no per-run agent identity to read.
    assert_eq!(request.agent_kind, AgentKind::Claude);
    assert_eq!(
        request.prompt.sha256_hex,
        crate::agent_run::sha256_hex(prompt_text.as_bytes()),
    );
    assert_eq!(request.prompt.byte_len, prompt_text.len() as u64);

    let outcome = state
        .audit
        .get_agent_run_outcome(run_id)
        .unwrap()
        .expect("a completed host-spawn run records its outcome row");
    assert_eq!(outcome.outcome.run_id, run_id);
    assert_eq!(
        outcome.outcome.status,
        crate::agent_run::AgentRunTerminalStatus::Succeeded,
    );
    assert_eq!(outcome.outcome.exit_code, 0);

    // The paths on the row are absolute and hold what the child wrote, so an
    // operator reading the log can open them without knowing writd's config.
    let run_dir = fixture.run_dir(run_id);
    assert_eq!(outcome.outcome.stdout.path, run_dir.join("stdout.log"));
    assert_eq!(outcome.outcome.stderr.path, run_dir.join("stderr.log"));
    assert_eq!(std::fs::read(&outcome.outcome.stdout.path).unwrap(), b"out");
    assert_eq!(std::fs::read(&outcome.outcome.stderr.path).unwrap(), b"err");
    assert!(!outcome.outcome.stdout.truncated);
    assert_eq!(outcome.outcome.stdout.byte_len, 3);
    assert_eq!(
        outcome.outcome.stdout.sha256_hex,
        crate::agent_run::sha256_hex(b"out"),
    );
}

/// The run id in the signed envelope is the run id in the audit log.
///
/// This is the provenance join a verifier needs: given a signed note from
/// bailiff's repo, `signed_metadata.run_id` must find the `agent_run` row
/// that authorised it. The host arm used to mint its envelope run id
/// independently of any audit row (there was none), so the id in a note
/// pointed at nothing.
#[tokio::test]
async fn the_signed_envelope_and_the_audit_row_name_the_same_run() {
    let cat = find_in_path("cat").expect("cat must be on PATH");
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(&server, cat, Vec::new());
    let state = &fixture.state;
    let session_id = open_session(state).await;

    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("hi"),
            capabilities: Vec::new(),
            purpose: "provenance".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;
    let signed_metadata = match resp {
        ServerMessage::RunAgentCompleted {
            signed_metadata, ..
        } => signed_metadata,
        other => panic!("expected RunAgentCompleted, got {other:?}"),
    };

    let audited = state
        .audit
        .agent_run_for_session(session_id)
        .unwrap()
        .expect("the session has exactly one run");
    assert_eq!(
        audited.run_id, signed_metadata.run_id,
        "the envelope's run id must be the audited run id, not a second minting",
    );
    assert_eq!(audited.session_id, signed_metadata.session_id);
}

/// A host-spawn `RunAgent` with no `session_id` is refused.
///
/// It used to be accepted, and the broker minted a fresh `SessionId` that it
/// stamped into the signed envelope *without opening a session row*. The
/// envelope then claimed a session no verifier could ever resolve, and the
/// run could not be audited at all: an `agent_run` row's `session_id` is a
/// foreign key onto `session`. Refusing is the honest answer — bailiff
/// already opens a session for every host-spawn stage.
#[tokio::test]
async fn run_agent_refuses_a_host_spawn_with_no_session() {
    let cat = find_in_path("cat").expect("cat must be on PATH");
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(&server, cat, Vec::new());
    let state = &fixture.state;

    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("hi"),
            capabilities: Vec::new(),
            purpose: "sessionless".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: None,
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;
    let ServerMessage::Error { message } = resp else {
        panic!("expected ServerMessage::Error, got {resp:?}");
    };
    assert!(
        message.contains("session_id"),
        "the refusal must name the missing field, got: {message}",
    );
    // Refused before the child ran, so nothing was created on disk. There is
    // no session to look for a run row under — which is the point.
    assert!(!fixture.log_root.exists());
}

/// A session with no agent kind cannot host a run, because
/// `agent_run.agent_kind` is the row's record of *what* ran and the host arm
/// has nowhere else to read it from. Refuse with the same guidance the
/// registry path gives, rather than inventing an identity for the log.
///
/// The session is written straight through the audit API because
/// `OpenSession` already refuses a kindless session over the wire — so this
/// row is the shape only a *pre-existing* database can hold (the column is
/// nullable). That is exactly why the branch has to exist: the type permits
/// the row, so the handler must have an answer for it.
#[tokio::test]
async fn run_agent_refuses_a_host_spawn_whose_session_never_named_an_agent() {
    use crate::core::SessionRecord;

    let cat = find_in_path("cat").expect("cat must be on PATH");
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(&server, cat, Vec::new());
    let state = &fixture.state;
    let session_id = SessionId::new();
    state
        .audit
        .open_session(&SessionRecord {
            session_id,
            label: None,
            agent_kind: None,
            agent_model: None,
            opened_at: UnixMillis::now(),
            closed_at: None,
        })
        .expect("open a kindless session directly");

    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("hi"),
            capabilities: Vec::new(),
            purpose: "no-agent-kind".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;
    let ServerMessage::Error { message } = resp else {
        panic!("expected ServerMessage::Error, got {resp:?}");
    };
    assert!(
        message.contains("agent kind") && message.contains("--agent"),
        "the refusal must tell the operator how to fix it, got: {message}",
    );
    assert!(
        state
            .audit
            .agent_run_for_session(session_id)
            .unwrap()
            .is_none(),
        "refused before recording anything against the session",
    );
    assert!(!fixture.log_root.exists());
}

/// A session opened for a different agent than the daemon actually spawns is
/// refused, before anything runs or is recorded.
///
/// The `agent_run` row records the *configured* kind, because the operator who
/// chose `spawn_command` is the only party who knows what that binary is. But
/// the session's kind is not inert — it routes credential mints to a GitHub
/// App — so a session claiming an identity this daemon cannot run would mint
/// as one agent and execute as another. bailiff's `--agent` defaults to
/// `claude` whatever writd is configured with, so this is reachable without
/// anyone doing something strange.
#[tokio::test]
async fn run_agent_refuses_a_session_opened_for_a_different_agent_than_it_spawns() {
    let cat = find_in_path("cat").expect("cat must be on PATH");
    let server = MockServer::start().await;
    // The fixture's registry knows Claude, so open a Codex session directly:
    // the disagreement under test is with the *spawn* config, not the registry.
    let mut fixture = make_run_agent_state(&server, cat, Vec::new());
    let state = Arc::get_mut(&mut fixture.state).expect("fresh Arc has no other handles");
    state
        .run_agent_spawn
        .as_mut()
        .expect("the fixture configures a spawn")
        .agent_kind = AgentKind::Codex;
    let state = &fixture.state;
    let session_id = open_session(state).await;

    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("hi"),
            capabilities: Vec::new(),
            purpose: "kind-mismatch".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;
    let ServerMessage::Error { message } = resp else {
        panic!("expected ServerMessage::Error, got {resp:?}");
    };
    assert!(
        message.contains("claude") && message.contains("codex"),
        "the refusal must name both kinds so the operator can see which to change, got: {message}",
    );
    assert!(
        state
            .audit
            .agent_run_for_session(session_id)
            .unwrap()
            .is_none(),
        "refused before recording a run",
    );
    assert!(!fixture.log_root.exists(), "refused before spawning");
}

/// The audit row records the kind the *daemon* is configured to spawn, not
/// the one the caller declared — they are required to agree, so this pins
/// which side is the source of truth.
#[tokio::test]
async fn the_audit_row_records_the_configured_agent_kind() {
    let cat = find_in_path("cat").expect("cat must be on PATH");
    let server = MockServer::start().await;
    let mut fixture = make_run_agent_state(&server, cat, Vec::new());
    let state = Arc::get_mut(&mut fixture.state).expect("fresh Arc has no other handles");
    state
        .run_agent_spawn
        .as_mut()
        .expect("the fixture configures a spawn")
        .agent_kind = AgentKind::Codex;
    let state = &fixture.state;
    let session_id = open_session_with_agent_kind(state, Some(AgentKind::Codex)).await;

    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("hi"),
            capabilities: Vec::new(),
            purpose: "configured-kind".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;
    let run_id = match resp {
        ServerMessage::RunAgentCompleted {
            signed_metadata, ..
        } => signed_metadata.run_id,
        other => panic!("expected RunAgentCompleted, got {other:?}"),
    };
    assert_eq!(
        state
            .audit
            .get_agent_run(run_id)
            .unwrap()
            .unwrap()
            .agent_kind,
        AgentKind::Codex,
    );
}

/// The caller's `purpose` lands on the audit row verbatim.
///
/// The value used here is the one that forced `purpose` to be its own
/// column rather than a reuse of `correlation_id`: the colon in
/// bailiff's `review:plan-abc` is outside that column's character class,
/// so routing a purpose through it would have turned a valid request
/// into a parse error.
#[tokio::test]
async fn a_host_spawned_run_records_the_callers_purpose() {
    let cat = find_in_path("cat").expect("cat must be on PATH");
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(&server, cat, Vec::new());
    let state = &fixture.state;
    let session_id = open_session(state).await;

    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("hi"),
            capabilities: Vec::new(),
            purpose: "review:plan-abc".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;
    let run_id = match resp {
        ServerMessage::RunAgentCompleted {
            signed_metadata, ..
        } => signed_metadata.run_id,
        other => panic!("expected RunAgentCompleted, got {other:?}"),
    };

    let request = state.audit.get_agent_run(run_id).unwrap().unwrap();
    assert_eq!(
        request.purpose.as_ref().map(|p| p.as_str()),
        Some("review:plan-abc"),
    );
    // The two tags are independent: `RunAgent` has no correlation id to
    // give, so recording a purpose must not invent one.
    assert!(request.correlation_id.is_none());
}

/// An agent that exits non-zero still *ran*, so its outcome row is
/// `Failed` with the exit code — not a missing row. The plan is explicit
/// that writ signs the partial and the audit row records the non-zero exit.
#[tokio::test]
async fn a_failed_host_spawn_records_a_failed_outcome() {
    let false_bin = find_in_path("false").expect("false must be on PATH");
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(&server, false_bin, Vec::new());
    let state = &fixture.state;
    let session_id = open_session(state).await;

    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("ignored"),
            capabilities: Vec::new(),
            purpose: "failed-run".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;
    let run_id = match resp {
        ServerMessage::RunAgentCompleted {
            signed_metadata, ..
        } => signed_metadata.run_id,
        other => panic!("expected RunAgentCompleted, got {other:?}"),
    };

    let outcome = state
        .audit
        .get_agent_run_outcome(run_id)
        .unwrap()
        .expect("a run that exited non-zero still has an outcome");
    assert_eq!(
        outcome.outcome.status,
        crate::agent_run::AgentRunTerminalStatus::Failed,
    );
    assert_eq!(outcome.outcome.exit_code, 1);
}

/// A run whose child could never start leaves its `agent_run` row
/// deliberately unpaired rather than inventing an outcome for it.
///
/// Writing a row saying "did not run" would fabricate a terminal status the
/// run never had, and worse, the outcome row's primary key is the run id, so
/// a fabricated row consumes the run's only outcome slot forever. An unpaired
/// request row is exactly what "a run was requested and we cannot say how it
/// went" looks like.
///
/// Note what is *not* asserted: `scan_unpaired_effect_rows` does not range
/// over `agent_run`, deliberately — an unpaired row there is
/// indistinguishable from a run still in flight, so the boot scan would
/// false-positive on every live run (see `EFFECT_AUDIT_PAIRS`). Resolving
/// these belongs to the agent-run lifecycle, not to the generic backstop.
#[tokio::test]
async fn a_host_spawn_that_cannot_start_leaves_its_run_row_for_reconciliation() {
    let server = MockServer::start().await;
    let missing = std::path::PathBuf::from("/nonexistent/bin/definitely-not-an-agent");
    let fixture = make_run_agent_state(&server, missing, Vec::new());
    let state = &fixture.state;
    let session_id = open_session(state).await;

    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("hi"),
            capabilities: Vec::new(),
            purpose: "unspawnable".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;
    let ServerMessage::Error { message } = resp else {
        panic!("expected ServerMessage::Error, got {resp:?}");
    };
    assert!(
        message.contains("definitely-not-an-agent"),
        "the error must name the command the operator configured, got: {message}",
    );

    let audited = state
        .audit
        .agent_run_for_session(session_id)
        .unwrap()
        .expect("the attempt is recorded even though it never ran");
    assert!(
        state
            .audit
            .get_agent_run_outcome(audited.run_id)
            .unwrap()
            .is_none(),
        "a run that never started must not be given a fabricated outcome",
    );
    // The request row is a faithful record of the attempt: the prompt it was
    // asked to run, under the session that asked.
    assert_eq!(audited.session_id, session_id);
    assert_eq!(
        audited.prompt.sha256_hex,
        crate::agent_run::sha256_hex(b"hi"),
    );
}

/// The audit row, the signed envelope, and the bytes on disk tell one story,
/// whatever the agent wrote.
///
/// Three independently-computed descriptions of the same run meet here: the
/// capture hashes each stream as it streams past, the file is what actually
/// landed, and the envelope is re-read off that file before signing. A
/// swapped stdout/stderr path, a summary hashing the wrong buffer, or an
/// envelope built from a stale in-memory copy all agree with themselves and
/// only disagree with each other — so the property is the cross-check, and
/// per-stream example tests could not replace it.
///
/// Sampled rather than swept: each case spawns a real child, so the case
/// count is deliberately small (same reasoning as the double-crash property).
#[test]
fn the_audit_row_and_the_envelope_agree_with_the_bytes_on_disk() {
    use proptest::test_runner::{Config, TestRunner};

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let server = rt.block_on(MockServer::start());
    let sh = find_in_path_any(&["sh", "bash"]);

    let mut config = Config::with_cases(12);
    config.source_file = Some(file!());
    // Same reasoning as `double_crash_sampled_pairs_recover_to_one_approved_publish`:
    // the case body drives async work on the shared runtime above, so forking
    // it into a fresh process would run something else entirely.
    config.fork = false;
    config.timeout = 0;
    // The alphabet excludes `'` and `\` so each stream's text can be embedded
    // in a single-quoted `sh -c` argument without escaping — the child's job
    // here is to emit exact bytes, not to exercise a shell quoter.
    let text = || proptest::string::string_regex("[a-zA-Z0-9 ]{0,64}").unwrap();
    TestRunner::new(config)
        .run(&(text(), text(), 0i32..=7), |(out, err, exit_code)| {
            rt.block_on(one_agreement_case(&server, &sh, &out, &err, exit_code))
        })
        .unwrap_or_else(|err| panic!("audit/envelope/disk agreement property failed: {err}"));
}

async fn one_agreement_case(
    server: &MockServer,
    sh: &std::path::Path,
    out: &str,
    err: &str,
    exit_code: i32,
) -> Result<(), proptest::test_runner::TestCaseError> {
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use proptest::prop_assert_eq;

    let fixture = make_run_agent_state(
        server,
        sh.to_path_buf(),
        vec![
            "-c".into(),
            format!("printf '%s' '{out}'; printf '%s' '{err}' 1>&2; exit {exit_code}"),
        ],
    );
    let state = &fixture.state;
    let session_id = open_session(state).await;
    let output_ref = crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();

    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("prompt"),
            capabilities: Vec::new(),
            purpose: "agreement".parse().unwrap(),
            output_ref: output_ref.clone(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
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

    let outcome = state
        .audit
        .get_agent_run_outcome(signed_metadata.run_id)
        .unwrap()
        .expect("a completed run has an outcome row");
    prop_assert_eq!(outcome.outcome.exit_code, exit_code);
    prop_assert_eq!(
        &outcome.outcome.status,
        &if exit_code == 0 {
            crate::agent_run::AgentRunTerminalStatus::Succeeded
        } else {
            crate::agent_run::AgentRunTerminalStatus::Failed
        }
    );

    let notes_repo_handle = state.notes_repo.as_ref().unwrap().clone();
    let body =
        tokio::task::spawn_blocking(move || notes_repo_handle.read_note(&output_ref, &output_oid))
            .await
            .unwrap()
            .unwrap();
    let envelope = SignedRunEnvelope::from_bytes(&body).unwrap();
    let output_envelope = OutputEnvelope::from_bytes(&envelope.output).unwrap();

    for (name, summary, expected, in_envelope) in [
        (
            "stdout",
            &outcome.outcome.stdout,
            out,
            &output_envelope.stdout,
        ),
        (
            "stderr",
            &outcome.outcome.stderr,
            err,
            &output_envelope.stderr,
        ),
    ] {
        let on_disk = std::fs::read(&summary.path)
            .unwrap_or_else(|e| panic!("{name} log {} unreadable: {e}", summary.path.display()));
        prop_assert_eq!(&on_disk, &expected.as_bytes(), "{} on disk", name);
        prop_assert_eq!(summary.byte_len, on_disk.len() as u64, "{} byte_len", name);
        prop_assert_eq!(
            &summary.sha256_hex,
            &crate::agent_run::sha256_hex(&on_disk),
            "{} sha256",
            name
        );
        prop_assert_eq!(!summary.truncated, true, "{} was not capped", name);
        prop_assert_eq!(in_envelope, &on_disk, "{} in the envelope", name);
    }
    Ok(())
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

/// Run a real host-spawn `RunAgent` and return the note it produced plus the
/// fixture that produced it, so a provenance test starts from a genuine run
/// rather than a hand-built one.
async fn run_one_agent(args: Vec<String>) -> (RunAgentFixture, SignedRunMetadata, SshSignature) {
    let sh = find_in_path_any(&["sh", "bash"]);
    let server = MockServer::start().await;
    let fixture = make_run_agent_state(&server, sh, args);
    let session_id = open_session(&fixture.state).await;
    let resp = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("provenance prompt"),
            capabilities: Vec::new(),
            purpose: "provenance".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        &fixture.state,
    )
    .await;
    match resp {
        ServerMessage::RunAgentCompleted {
            signed_metadata,
            signature,
            ..
        } => (fixture, signed_metadata, signature),
        other => panic!("expected RunAgentCompleted, got {other:?}"),
    }
}

async fn verify(
    fixture: &RunAgentFixture,
    signed_metadata: &SignedRunMetadata,
    signature: &SshSignature,
) -> crate::run_provenance::RunProvenanceVerdict {
    let resp = dispatch_message(
        ClientMessage::VerifyAgentRun {
            signed_metadata: signed_metadata.clone(),
            signature: signature.clone(),
        },
        &fixture.state,
    )
    .await;
    match resp {
        ServerMessage::AgentRunProvenance { verdict } => verdict,
        other => panic!("expected AgentRunProvenance, got {other:?}"),
    }
}

/// The note writ just produced is corroborated by writ's own log.
///
/// End-to-end rather than against a hand-built pair: this is the only test
/// that can catch the two halves being *individually* right and jointly
/// wrong — a signer and a row-writer that disagree about, say, which
/// timestamp `completed_at` means would each pass their own tests.
#[tokio::test]
async fn a_note_writ_just_signed_is_corroborated_by_its_own_log() {
    let (fixture, signed_metadata, signature) =
        run_one_agent(vec!["-c".into(), "printf out; printf err 1>&2".into()]).await;

    let verdict = verify(&fixture, &signed_metadata, &signature).await;
    assert!(
        verdict.is_corroborated(),
        "writ must corroborate the note it just signed, got {verdict:?}",
    );
}

/// Altering the note after signing is caught as a bad signature, not as a
/// field mismatch.
///
/// The distinction is the point: once the bytes no longer verify, the fields
/// are unattributed, so reporting "the exit code disagrees" would dress an
/// unverified claim up as evidence about a run.
#[tokio::test]
async fn a_note_altered_after_signing_is_rejected_before_any_field_is_compared() {
    let (fixture, signed_metadata, signature) =
        run_one_agent(vec!["-c".into(), "true".into()]).await;

    let mut tampered = signed_metadata.clone();
    tampered.exit_code = 42;
    let verdict = verify(&fixture, &tampered, &signature).await;
    assert_eq!(
        verdict,
        crate::run_provenance::RunProvenanceVerdict::SignatureInvalid
    );
}

/// A note signed by some other writ is not ours to vouch for, and says so
/// distinctly from tampering.
#[tokio::test]
async fn a_note_from_another_daemon_is_reported_as_not_ours() {
    let (fixture, signed_metadata, signature) =
        run_one_agent(vec!["-c".into(), "true".into()]).await;

    // Re-sign the same metadata with a different key, so the note is
    // internally valid — just not this daemon's.
    const OTHER_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing_other.key");
    let other = crate::signing::WritSigningKey::from_openssh_pem(OTHER_PEM).unwrap();
    let mut foreign = signed_metadata.clone();
    foreign.signing_key_fingerprint = other.fingerprint();
    let foreign_signature = other.sign(&foreign.canonical_bytes()).unwrap();

    let verdict = verify(&fixture, &foreign, &foreign_signature).await;
    match verdict {
        crate::run_provenance::RunProvenanceVerdict::NotOurs { fingerprint } => {
            assert_eq!(fingerprint, other.fingerprint());
        }
        other => panic!("expected NotOurs, got {other:?}"),
    }
    // The signature was valid for its own key; the point is that writ refuses
    // to speak for a key it does not hold, not that it found a forgery.
    drop(signature);
}

/// A genuine note whose run the log has never heard of is `UnknownRun` — not
/// a clean bill of health.
#[tokio::test]
async fn a_note_for_a_run_the_log_never_recorded_is_unknown_not_corroborated() {
    let (fixture, signed_metadata, _) = run_one_agent(vec!["-c".into(), "true".into()]).await;

    // Re-sign a note for a run id that was never recorded, so the signature
    // is genuine and only the log is missing it.
    let signing_key = fixture.signing_key.clone();
    let mut orphan = signed_metadata.clone();
    orphan.run_id = crate::agent_run::AgentRunId::new();
    let orphan_signature = signing_key.sign(&orphan.canonical_bytes()).unwrap();

    let verdict = verify(&fixture, &orphan, &orphan_signature).await;
    match verdict {
        crate::run_provenance::RunProvenanceVerdict::UnknownRun { run_id } => {
            assert_eq!(run_id, orphan.run_id);
        }
        other => panic!("expected UnknownRun, got {other:?}"),
    }
    assert!(
        !verify(&fixture, &orphan, &orphan_signature)
            .await
            .is_corroborated()
    );
}

/// A stream file rewritten after the run is caught when the note is checked,
/// because the output digest is re-derived from the file rather than taken
/// from the note.
#[tokio::test]
async fn a_stream_file_rewritten_after_the_run_fails_the_provenance_check() {
    let (fixture, signed_metadata, signature) =
        run_one_agent(vec!["-c".into(), "printf original".into()]).await;
    // Corroborated before the tamper, so the failure below is the tamper.
    assert!(
        verify(&fixture, &signed_metadata, &signature)
            .await
            .is_corroborated()
    );

    let outcome = fixture
        .state
        .audit
        .get_agent_run_outcome(signed_metadata.run_id)
        .unwrap()
        .expect("the run recorded an outcome");
    std::fs::write(&outcome.outcome.stdout.path, b"replaced").unwrap();

    let resp = dispatch_message(
        ClientMessage::VerifyAgentRun {
            signed_metadata: signed_metadata.clone(),
            signature,
        },
        &fixture.state,
    )
    .await;
    // The re-derivation refuses outright: the file disagrees with its own
    // outcome row, so there is no honest digest to compare against the note.
    let ServerMessage::Error { message } = resp else {
        panic!("expected an Error refusing to re-derive, got {resp:?}");
    };
    assert!(
        message.contains("no longer matches"),
        "the error must name the tampered file, got: {message}",
    );
}

/// A `RunAgent` fixture whose agent records its own lifetime, so a test can
/// reconstruct how many runs were ever in flight together.
///
/// The script appends one line when it starts and one when it finishes. Small
/// `>>` writes to the same file are atomic under `O_APPEND`, so the file is a
/// faithful interleaving of the runs rather than a lossy one, and replaying it
/// as +1/-1 gives the concurrency at every instant.
fn overlap_recording_agent(dir: &std::path::Path, ledger: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join("agent.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n\
             echo start >> '{ledger}'\n\
             # Long enough that every queued run would overlap if nothing bounded\n\
             # them, short enough to keep the suite quick.\n\
             sleep 0.4\n\
             echo end >> '{ledger}'\n",
            ledger = ledger.display(),
        ),
    )
    .unwrap();
    let mut perms = std::fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script, perms).unwrap();
    script
}

/// Replay the ledger as +1 per start and -1 per end, returning the high-water
/// mark.
fn peak_concurrency(ledger: &std::path::Path) -> usize {
    let text = std::fs::read_to_string(ledger).unwrap_or_default();
    let mut live = 0usize;
    let mut peak = 0usize;
    for line in text.lines() {
        match line.trim() {
            "start" => {
                live += 1;
                peak = peak.max(live);
            }
            "end" => live = live.saturating_sub(1),
            other => panic!("unexpected ledger line {other:?}"),
        }
    }
    peak
}

/// Concurrent `RunAgent` calls are bounded, and the ones over the bound wait
/// their turn rather than being refused.
///
/// Both halves matter and neither implies the other. A daemon that refused the
/// surplus would also keep the peak at the limit, and a daemon that queued
/// without bounding would also complete every request; only asserting both says
/// "queued, not dropped".
///
/// Each in-flight host run costs a blocking-pool thread (of tokio's 512, shared
/// with notes writes and every other `spawn_blocking` here), two OS threads for
/// the stream captures, and a child process — so an unbounded burst is a real
/// resource commitment, not just untidy.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_runs_are_bounded_and_the_surplus_queues() {
    let tmp = tempfile::tempdir().unwrap();
    let ledger = tmp.path().join("ledger");
    let agent = overlap_recording_agent(tmp.path(), &ledger);

    let server = MockServer::start().await;
    let mut fixture = make_run_agent_state(&server, agent, Vec::new());
    // Pinned here rather than read from the state's own configuration. Asserting
    // `peak <= state.agent_run_slots.limit()` would compare the mechanism with
    // itself and hold for *any* limit, including one high enough to be no bound
    // at all — a mutation raising the default sailed through that version. It
    // would also scale the burst with the default, so raising it would silently
    // make this test spawn dozens of processes.
    const LIMIT: usize = 2;
    {
        let inner = Arc::get_mut(&mut fixture.state).expect("fresh fixture Arc is unshared");
        // The queue is deliberately not the thing under test here: this test is
        // about the surplus *queueing*, so it needs a depth the burst cannot
        // reach.
        inner.agent_run_slots = spacious_queue(std::num::NonZeroUsize::new(LIMIT).unwrap());
    }
    let state = &fixture.state;
    let limit = LIMIT;
    let session_id = open_session(state).await;

    // Comfortably more than the bound, so the queue is exercised rather than
    // merely present.
    let burst = limit * 3;
    let mut runs = tokio::task::JoinSet::new();
    for i in 0..burst {
        let state = Arc::clone(state);
        runs.spawn(async move {
            dispatch_message(
                ClientMessage::RunAgent {
                    prompt: crate::agent_run::AgentPrompt::new(format!("run {i}")),
                    capabilities: Vec::new(),
                    purpose: "concurrency-bound-test".parse().unwrap(),
                    output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs")
                        .unwrap(),
                    session_id: Some(session_id),
                    workspace: None,
                    agent_kind: None,
                    agent_model: None,
                },
                &state,
            )
            .await
        });
    }

    let mut completed = 0usize;
    while let Some(joined) = runs.join_next().await {
        match joined.unwrap() {
            ServerMessage::RunAgentCompleted { .. } => completed += 1,
            other => panic!("every queued run must eventually run: got {other:?}"),
        }
    }

    assert_eq!(
        completed, burst,
        "the surplus must queue and complete, not be refused"
    );
    let peak = peak_concurrency(&ledger);
    assert!(
        peak <= limit,
        "at most {limit} agents may run at once; {peak} overlapped"
    );
    assert!(
        peak > 1,
        "with a bound above one the runs should actually overlap; a peak of \
         {peak} means this test never exercised concurrency at all"
    );
}

/// The shipped default is two concurrent runs.
///
/// Pinned separately from the mechanism test, which now fixes its own limit:
/// "the bound is enforced" and "the bound is 2" are different claims, and a test
/// that reads the limit out of the state it is testing can only ever check the
/// first. Changing this number should be a deliberate edit here.
#[test]
fn the_default_concurrency_bound_is_two() {
    assert_eq!(DEFAULT_MAX_CONCURRENT_AGENT_RUNS.get(), 2);
}

/// Every path that starts an agent run takes a slot.
///
/// A source scan, because the alternative is no coverage at all: the VM paths
/// need a real agent-VM runtime, so the end-to-end concurrency test cannot reach
/// them, and a mutation deleting a VM-side `acquire` survived it silently.
///
/// There are exactly two acquire sites, shaped differently on purpose. The host
/// arm's run ends when its handler returns, so a function-scoped slot *is* the
/// run's lifetime. A VM run's does not: `StartAgentRun` answers as soon as the
/// VM is up, so `start_agent_run_session` acquires and hands the slot to the
/// running session, which releases it at teardown. Both `RunAgent`'s VM arm and
/// `StartAgentRun` funnel through that one function — which is why
/// `run_agent_in_vm` must *not* acquire: two slots for one run would let a
/// single request exhaust the default limit and then wait on itself.
///
/// A backstop, not a proof. It shows an `acquire` is present where one belongs
/// and absent where it does not, not that the placement is right; the host arm's
/// placement is checked by `concurrent_runs_are_bounded_and_the_surplus_queues`.
#[test]
fn every_path_that_starts_an_agent_run_takes_a_slot() {
    /// The function's body, delimited by brace matching.
    ///
    /// Not by scanning for a closing brace at a fixed indent: these functions
    /// live at two different nesting depths (one in a module, one in an `impl`),
    /// and an indent-based terminator silently truncated the module-level one at
    /// its first inner block — which read as "the host arm does not acquire".
    fn body_of<'a>(source: &'a str, signature: &str) -> &'a str {
        let at = source.find(signature).unwrap_or_else(|| {
            panic!("{signature:?} not found; rename the guard along with the function")
        });
        let open = at + source[at..].find('{').expect("a function has a body");
        let mut depth = 0usize;
        for (offset, ch) in source[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &source[at..open + offset];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced braces after {signature:?}")
    }

    let dispatch = include_str!("run_agent.rs");
    assert!(
        body_of(dispatch, "pub(super) async fn run_agent<").contains("agent_run_slots.enqueue()"),
        "the host arm runs the agent inside its own handler, so it must hold a \
         slot for that handler's lifetime — and the only route to one is through \
         the queue-depth bound"
    );
    assert!(
        !body_of(dispatch, "async fn run_agent_in_vm<").contains("agent_run_slots.enqueue()"),
        "the VM arm must not take a slot of its own: it starts its run through \
         `start_agent_run_session`, which takes one, and two slots for one run \
         would deadlock at the default limit"
    );

    let daemon = include_str!("../agent_vm_daemon/daemon_impl.rs");
    let session_start = body_of(daemon, "pub async fn start_agent_run_session<");
    // Any form of the wait counts here; *which* one each caller chooses is
    // asserted by `only_the_vm_path_bounds_how_long_it_will_queue`. This guard is
    // about the slot being taken at all.
    assert!(
        session_start.contains(".enqueue()"),
        "every VM agent run starts here — `RunAgent`'s VM arm and `StartAgentRun` \
         both — so this is the one place that can bound them"
    );
}

/// A limit the semaphore cannot represent is refused, not panicked on.
///
/// `tokio::sync::Semaphore::new` panics above `MAX_PERMITS`, and this limit is
/// operator input, so without the check a config file could crash writd during
/// startup — a stack trace where the operator needs a sentence naming the field.
#[test]
fn a_limit_above_the_semaphores_ceiling_is_refused() {
    let too_many =
        std::num::NonZeroUsize::new(tokio::sync::Semaphore::MAX_PERMITS + 1).expect("non-zero");
    let at_ceiling =
        std::num::NonZeroUsize::new(tokio::sync::Semaphore::MAX_PERMITS).expect("non-zero");

    // Each field is checked, and the message must name the one that is wrong: an
    // error that could describe either sends an operator to edit the wrong line.
    let err = AgentRunSlots::new(too_many, at_ceiling)
        .expect_err("above MAX_PERMITS must not be accepted");
    let msg = err.to_string();
    assert!(
        msg.contains("max_concurrent_agent_runs"),
        "the error must name the config field an operator would have to edit; got {msg:?}"
    );

    let err = AgentRunSlots::new(at_ceiling, too_many)
        .expect_err("the queue bound is operator input too, and can crash the same way");
    let msg = err.to_string();
    assert!(
        msg.contains("max_pending_agent_runs"),
        "the error must name the config field an operator would have to edit; got {msg:?}"
    );

    // The boundary itself is representable, so the check refuses only what it
    // must — and the boundary is on the *sum*, since that is what the admission
    // semaphore holds.
    let one_below =
        std::num::NonZeroUsize::new(tokio::sync::Semaphore::MAX_PERMITS - 1).expect("non-zero");
    assert!(AgentRunSlots::new(one_below, NON_ZERO_ONE).is_ok());
}

/// A bounded wait gives up rather than hanging, and returns nothing when it does.
///
/// The distinction that matters: a caller that times out must not end up holding
/// a slot it does not know about, because the work it would unblock is work
/// nobody is waiting for.
#[tokio::test(start_paused = true)]
async fn a_bounded_wait_gives_up_when_no_slot_frees() {
    let slots = spacious_queue(std::num::NonZeroUsize::new(1).unwrap());
    let held = slots.enqueue().unwrap().wait_for_slot().await;
    assert_eq!(slots.available(), 0);

    let refused = slots
        .enqueue()
        .unwrap()
        .wait_for_slot_with(AgentRunQueueing::UpTo(std::time::Duration::from_secs(30)))
        .await;
    assert_eq!(
        refused.err(),
        Some(std::time::Duration::from_secs(30)),
        "with the only slot held, a bounded wait must expire rather than hang — \
         and report back the budget it actually spent"
    );
    assert_eq!(
        slots.available(),
        0,
        "a wait that gave up must not have taken anything with it"
    );

    drop(held);
    let granted = slots
        .enqueue()
        .unwrap()
        .wait_for_slot_with(AgentRunQueueing::UpTo(std::time::Duration::from_secs(30)))
        .await;
    assert!(
        granted.is_ok(),
        "once a slot frees, the same bounded wait must succeed — this is a queue \
         with a deadline, not a refusal dressed up as one"
    );
}

/// Slots with the concurrency bound under test and a queue too deep to be the
/// thing under test. Used by the tests about *waiting*, so that a change to the
/// queue default cannot silently turn one of them into a test about admission.
fn spacious_queue(limit: std::num::NonZeroUsize) -> AgentRunSlots {
    AgentRunSlots::new(limit, std::num::NonZeroUsize::new(1024).unwrap()).unwrap()
}

/// The shipped default queue depth is 64.
///
/// Pinned separately from the mechanism, for the same reason as
/// [`the_default_concurrency_bound_is_two`]: "the queue is bounded" and "the
/// bound is 64" are different claims, and only the second can catch a careless
/// edit to the number.
#[test]
fn the_default_pending_bound_is_sixty_four() {
    assert_eq!(DEFAULT_MAX_PENDING_AGENT_RUNS.get(), 64);
}

/// Over the bound, a run is refused at once rather than queued — and the bound
/// is on running *and* waiting together.
///
/// The property the owner asked for, stated as a test: a caller that writd
/// cannot promise to serve gets an answer *now*. Three halves, really — that the
/// refusal happens (rather than an unbounded wait), that it happens without
/// blocking (which is why this test would hang rather than fail if `enqueue`
/// ever became async), and that an executing run still counts, so the daemon
/// holds at most `limit + queue_limit` runs however they are distributed.
#[tokio::test(start_paused = true)]
async fn a_run_over_the_admission_bound_is_refused_rather_than_queued() {
    let slots = AgentRunSlots::new(NON_ZERO_ONE, std::num::NonZeroUsize::new(2).unwrap()).unwrap();

    let running = slots.enqueue().unwrap().wait_for_slot().await;
    assert_eq!(
        slots.admission_available(),
        2,
        "a run that is executing is still an admitted run: dropping its claim \
         when it started running would let the daemon hold more than the two \
         numbers add up to"
    );

    let first = slots.enqueue().expect("one of the two spare admissions");
    let second = slots.enqueue().expect("the other");
    assert_eq!(slots.admission_available(), 0);

    let refused = slots
        .enqueue()
        .expect_err("a fourth run is past running-plus-waiting");
    let msg = refused.to_string();
    for expected in [
        "max_pending_agent_runs",
        "max_concurrent_agent_runs",
        "retry",
    ] {
        assert!(
            msg.contains(expected),
            "the refusal must say what happened and what to do about it, naming \
             the fields an operator would raise; {expected:?} missing from {msg:?}"
        );
    }

    // And it is a refusal, not a delay: room reappears only when a run leaves.
    drop(first);
    slots
        .enqueue()
        .expect("a departed run must give its admission back");

    drop(second);
    drop(running);
}

/// A run that could start immediately is never refused.
///
/// Codex found this on the first version, which counted waiters in their own
/// semaphore and vacated a place when its slot was granted. A request passing
/// through an *idle* slot still held queue depth for the instant it was in
/// transit, so with a small `max_pending_agent_runs` a concurrent request could
/// be refused while execution capacity sat unused — a refusal caused by timing
/// rather than by load, which is exactly what an explicit "try again later" must
/// never mean.
///
/// Counting running and waiting as one admission makes it arithmetic rather than
/// timing: exhausted admission means `running + waiting == limit + queue_limit`
/// and `waiting <= queue_limit`, so `running >= limit`. Asserted here over the
/// small shapes where the old bug reproduced, in the form the property is
/// actually stated: **whenever `enqueue` refuses, no slot was free**.
#[tokio::test(start_paused = true)]
async fn a_run_that_could_start_at_once_is_never_refused() {
    for (limit, queue_limit) in [(2, 1), (1, 1), (3, 1), (2, 2)] {
        let slots = AgentRunSlots::new(
            std::num::NonZeroUsize::new(limit).unwrap(),
            std::num::NonZeroUsize::new(queue_limit).unwrap(),
        )
        .unwrap();

        // Fill the whole admission, granting slots to as many as will take them
        // — the state the old implementation could reach with idle slots.
        let mut running = Vec::new();
        let mut waiting = Vec::new();
        for _ in 0..limit {
            running.push(slots.enqueue().unwrap().wait_for_slot().await);
        }
        for _ in 0..queue_limit {
            waiting.push(slots.enqueue().expect("still inside the admission bound"));
        }

        assert!(
            slots.enqueue().is_err(),
            "with {limit}+{queue_limit} runs held, admission must be exhausted"
        );
        assert_eq!(
            slots.available(),
            0,
            "and a refusal must mean every slot is busy: refusing a run that \
             could have started at once is the bug this shape exists to catch \
             (limit {limit}, queue {queue_limit})"
        );

        // The converse, on the way back down: give one slot back and the next
        // request is admitted rather than refused.
        running.pop();
        assert!(
            slots.enqueue().is_ok(),
            "a freed slot must be reachable again (limit {limit}, queue {queue_limit})"
        );
    }
}

/// Two representable limits whose *sum* is not are refused, not wrapped.
///
/// The admission semaphore holds the sum, so the sum is what must fit. `usize`
/// addition would wrap to something small and silently install a bound far
/// tighter than either configured number — the opposite failure to the one an
/// operator setting a large limit is trying to avoid.
#[test]
fn limits_that_are_individually_fine_but_sum_too_high_are_refused() {
    let half = std::num::NonZeroUsize::new(tokio::sync::Semaphore::MAX_PERMITS / 2 + 1).unwrap();
    let err = AgentRunSlots::new(half, half).expect_err("their sum is over the ceiling");
    let msg = err.to_string();
    assert!(
        msg.contains("max_concurrent_agent_runs")
            && msg.contains("max_pending_agent_runs")
            && msg.contains("sum"),
        "the error must name both fields and say it is their sum at fault, since \
         neither one alone is wrong; got {msg:?}"
    );
}

const NON_ZERO_ONE: std::num::NonZeroUsize = std::num::NonZeroUsize::new(1).unwrap();

/// Only the VM path bounds its wait; the host arm still queues indefinitely.
///
/// The asymmetry is the point, so it is pinned rather than left to a reader
/// comparing two files. A VM run's slot is released by a human stopping the
/// session, and its caller is a CLI holding a socket open with its own deadline,
/// so an unbounded wait there strands a VM nobody can name. A host run ends by
/// itself, so its queue drains unattended and a caller that waits is waiting for
/// something that will actually happen.
#[test]
fn only_the_vm_path_bounds_how_long_it_will_queue() {
    let daemon = include_str!("../agent_vm_daemon/daemon_impl.rs");
    assert!(
        daemon.contains("wait_for_slot_with(queueing)"),
        "the VM session start must take its wait policy from the caller: the two \
         callers differ in whether anyone is still listening when it ends"
    );

    // And the callers must choose the policy that matches their own shape.
    let start_agent_run = include_str!("../server.rs");
    assert!(
        start_agent_run.contains("AgentRunQueueing::UpTo("),
        "`StartAgentRun` answers a client with its own deadline, so its wait must \
         be bounded — otherwise a slot granted later boots a VM whose id reaches \
         nobody"
    );

    let dispatch = include_str!("run_agent.rs");
    assert!(
        dispatch.contains("AgentRunQueueing::UntilASlotFrees"),
        "`RunAgent`'s VM arm holds its caller for the whole run, so it must queue \
         rather than refuse a surplus workflow"
    );
    assert!(
        dispatch.contains("place.wait_for_slot().await"),
        "the host arm keeps the unbounded wait: its runs end without \
         intervention, so its queue drains on its own. The queue-depth bound in \
         front of it changed whether that wait can be *joined*, not how long a \
         place in it is worth holding"
    );
}

/// A session closed *while a run is queued* is reported as closed, not as a
/// generic failure.
///
/// The precheck happens before the wait, and the host arm's wait has no bound,
/// so by the time a slot frees the answer may have changed. `begin_effect` does
/// refuse a closed session — but as an opaque audit error, so a caller that
/// waited minutes for its turn would learn only that something went wrong.
///
/// Getting this test to mean anything took a correction. Its first version closed
/// the session immediately after dispatching, which was fast enough that the
/// *pre-acquire* check answered — so it passed with the recheck deleted, proving
/// nothing. The permit is now held by the test itself, and the test refuses to
/// conclude anything unless it has confirmed the request is parked past its
/// precheck: if the request has already answered by then, the assertion below
/// says so rather than reporting success.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_closed_while_queued_is_reported_as_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let ledger = tmp.path().join("ledger");
    let agent = overlap_recording_agent(tmp.path(), &ledger);

    let server = MockServer::start().await;
    let mut fixture = make_run_agent_state(&server, agent, Vec::new());
    {
        let inner = Arc::get_mut(&mut fixture.state).expect("fresh fixture Arc is unshared");
        inner.agent_run_slots = spacious_queue(std::num::NonZeroUsize::new(1).unwrap());
    }
    let state = &fixture.state;
    let session_id = open_session(state).await;

    // Held here rather than by another run: the test controls exactly when the
    // queued request is allowed to proceed, so the window it is parked in is not
    // a matter of scheduling luck.
    let held = state
        .agent_run_slots
        .enqueue()
        .unwrap()
        .wait_for_slot()
        .await;
    assert_eq!(state.agent_run_slots.available(), 0);

    let queued = tokio::spawn({
        let state = Arc::clone(state);
        async move {
            dispatch_message(
                ClientMessage::RunAgent {
                    prompt: crate::agent_run::AgentPrompt::new("queued"),
                    capabilities: Vec::new(),
                    purpose: "closed-while-queued".parse().unwrap(),
                    output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs")
                        .unwrap(),
                    session_id: Some(session_id),
                    workspace: None,
                    agent_kind: None,
                    agent_model: None,
                },
                &state,
            )
            .await
        }
    });

    // Long enough for the request to clear its preconditions and park on the
    // permit. Generous rather than tight: overshooting costs a moment, while
    // undershooting is caught by the assertion after the close.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        !queued.is_finished(),
        "the request must still be waiting for a permit; if it has already \
         answered, it never reached the queue and this test proves nothing"
    );

    state
        .audit
        .close_session(session_id, crate::core::UnixMillis::now())
        .unwrap();

    // Still parked *after* the close: so whatever it answers now, it answers on
    // the far side of the wait, which is the only place the recheck runs.
    assert!(
        !queued.is_finished(),
        "closing a session must not wake a queued request early; if it answered \
         here it did so from the pre-acquire check and the recheck is untested"
    );

    drop(held);
    let answer = queued.await.unwrap();
    assert!(
        matches!(answer, ServerMessage::ClosedSession { session_id: got } if got == session_id),
        "a session closed during the queue must come back as ClosedSession, not \
         as an opaque failure; got {answer:?}"
    );
}

/// A `RunAgent` caller past the queue bound is told so, immediately, over the
/// wire it is already holding.
///
/// The end-to-end half of the queue bound: the unit tests above pin the
/// mechanism, and this pins that the *dispatcher* consults it and that the
/// refusal reaches a client rather than becoming another kind of wait. The
/// distinction the owner asked for is the one asserted last — the caller learns
/// its request failed while it is still connected, instead of being parked
/// indefinitely with no way to tell scheduled from forgotten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_agent_caller_over_the_queue_bound_is_refused_while_still_connected() {
    let tmp = tempfile::tempdir().unwrap();
    let ledger = tmp.path().join("ledger");
    let agent = overlap_recording_agent(tmp.path(), &ledger);

    let server = MockServer::start().await;
    let mut fixture = make_run_agent_state(&server, agent, Vec::new());
    {
        let inner = Arc::get_mut(&mut fixture.state).expect("fresh fixture Arc is unshared");
        // One running, one waiting, and nothing else admitted: the smallest
        // configuration in which "the queue is full" is a state the dispatcher
        // can actually reach.
        inner.agent_run_slots = AgentRunSlots::new(
            std::num::NonZeroUsize::new(1).unwrap(),
            std::num::NonZeroUsize::new(1).unwrap(),
        )
        .unwrap();
    }
    let state = &fixture.state;
    let session_id = open_session(state).await;

    // The test holds the whole admission — one running, one waiting — so the
    // request below cannot be admitted, and cannot merely be *slow* to be
    // admitted, which is what would make this test pass for the wrong reason.
    let held_slot = state
        .agent_run_slots
        .enqueue()
        .unwrap()
        .wait_for_slot()
        .await;
    let held_place = state.agent_run_slots.enqueue().unwrap();
    assert_eq!(state.agent_run_slots.available(), 0);
    assert_eq!(state.agent_run_slots.admission_available(), 0);

    let started = std::time::Instant::now();
    let answer = dispatch_message(
        ClientMessage::RunAgent {
            prompt: crate::agent_run::AgentPrompt::new("over the bound"),
            capabilities: Vec::new(),
            purpose: "queue-full".parse().unwrap(),
            output_ref: crate::core::NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        },
        state,
    )
    .await;
    let elapsed = started.elapsed();

    let ServerMessage::Error { message } = &answer else {
        panic!("a run over the queue bound must be refused, got {answer:?}");
    };
    assert!(
        message.contains("max_pending_agent_runs") && message.contains("retry"),
        "the refusal must say what happened and that retrying later is the right \
         response, not merely that something went wrong; got {message:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the refusal must be immediate — a caller over the bound is refused \
         precisely so it does not wait; took {elapsed:?}"
    );

    // Nothing was recorded, which is the other half of "this request failed":
    // a refused run must not leave a row claiming writd was asked to do it.
    assert_eq!(
        state
            .audit
            .agent_run_for_session(session_id)
            .expect("audit read"),
        None,
        "a run writd refused to queue must leave no agent_run row behind"
    );

    drop(held_place);
    drop(held_slot);
}
