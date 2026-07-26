//! Recorded baselines of the writ RPCs each bailiff workflow emits.
//!
//! **This exists to be captured before slice 3, not because it is
//! useful on its own.** Slice 3 of
//! `docs/plans/2026-07-26-bailiff-workflow-as-data.md` collapses
//! `submit_plan` / `submit_review` / `submit_implement` into three
//! values of one `StageSpec` executed by a single interpreter. The
//! claim that the collapse changes no behaviour is only checkable
//! against a record of the behaviour taken *beforehand*; captured
//! afterwards it would merely restate whatever the interpreter does.
//!
//! Each scenario drives a real workflow against a stub broker that
//! records every [`ClientMessage`] it receives, and compares the
//! sequence to a checked-in fixture under `tests/fixtures/rpc-traces/`.
//! Set `UPDATE_RPC_TRACES=1` to rewrite the fixtures; a diff in that
//! rewrite is precisely the review surface slice 3 needs.
//!
//! # What is pinned, and what is deliberately not
//!
//! Pinned: the *sequence* of messages, their variants, and every field
//! bailiff chooses — prompt bytes (so prompt composition is covered),
//! capability sets, `purpose`, `output_ref`, and which session id (if
//! any) each `RunAgent` is bound to.
//!
//! Not pinned: anything the broker chooses. Session ids come from the
//! stub's scripted reply and are fixed to a constant here, so the
//! fixtures stay stable without post-hoc normalisation.
//!
//! The pre-RPC scenarios are as load-bearing as the happy paths: a
//! refused gate must emit *zero* messages, which is the property that
//! keeps a rejected workflow from burning a writ audit row, and the
//! one most easily lost when three bespoke functions become one
//! interpreter.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use bailiff::bailiff_decision::{Decider, Decision};
use bailiff::bailiff_plan_implement::{
    SubmitImplementError, SubmitImplementInputs, submit_implement,
};
use bailiff::bailiff_plan_note::{
    DecisionNote, PlanId, PlanNote, ReviewNote, plan_notes_ref, plan_review_seed_blob_bytes,
    plan_submission_seed_blob_bytes,
};
use bailiff::bailiff_plan_review::{SubmitReviewError, SubmitReviewInputs, submit_review};
use bailiff::bailiff_plan_submit::{SubmitPlanError, SubmitPlanInputs, submit_plan};
use bailiff::bailiff_plan_write::write_decision_note;
use writ::agent_run::{AgentPrompt, AgentRunId, sha256_hex};
use writ::core::{AgentKind, CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
use writ::notes_repo::NotesRepo;
use writ::protocol::{ClientMessage, ServerMessage, SignedRunMetadata};
use writ::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use writ::run_verify::AllowedSigners;
use writ::signing::WritSigningKey;
use writ::vm_git::{GitCloneRepo, GitObjectId, WorkspaceWarmMode};
use writ::writ_client::WritClient;

const SIGNING_PEM: &str = include_str!("fixtures/ed25519_test_signing.key");
const SIGNING_PUB: &str = include_str!("fixtures/ed25519_test_signing.key.pub");
/// A key bailiff does not trust, used to force note verification to
/// fail after an otherwise-successful run.
const OTHER_PEM: &str = include_str!("fixtures/ed25519_test_signing_other.key");

/// The plan body every scenario uses. Also the agent's stdout, since
/// the planner's stdout *is* the plan body.
const PLAN_BODY: &str = "# Plan\n\nReplace bar with baz.\n";

const WRIT_OUTPUT_REF: &str = "refs/notes/writ/v1/agent-outputs";

/// Fixed so recorded traces do not depend on a random id. The broker
/// picks session ids in production; the stub picks this one.
fn stub_session_id() -> SessionId {
    "3f2504e0-4f89-41d3-9a0c-0305e82c3301".parse().unwrap()
}

fn repo_ref() -> RepoRef {
    RepoRef {
        owner: "smaug123".into(),
        name: "writ".into(),
    }
}

fn writ_output_ref() -> NotesRef {
    NotesRef::try_new(WRIT_OUTPUT_REF).unwrap()
}

/// Stub broker: reads one [`ClientMessage`] per connection, records it,
/// and replies with the next scripted [`ServerMessage`].
///
/// One message per connection matches `WritClient`'s round-trip shape:
/// it dials per RPC. Replies are consumed in order, so a scenario
/// scripts exactly as many as its workflow should send — a workflow
/// that sends more is still *recorded*, then hung up on, so the extra
/// RPC shows up as a fixture diff rather than only as a transport
/// error the caller might swallow.
struct StubBroker {
    socket_path: PathBuf,
    requests: Arc<AsyncMutex<Vec<ClientMessage>>>,
    _task: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl StubBroker {
    async fn start(replies: Vec<ServerMessage>) -> Self {
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
                let mut lines = BufReader::new(reader).lines();
                // Record *before* looking for a reply. Draining the
                // request first is what makes the zero-RPC fixtures
                // mean anything: with no scripted reply the earlier
                // version returned without reading, so a workflow that
                // sent an RPC before its gate got an EOF, surfaced a
                // transport error that `expect_err` happily accepted,
                // and left `observed()` empty — the fixture passed on
                // exactly the regression it exists to catch.
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

    async fn observed(&self) -> Vec<ClientMessage> {
        self.requests.lock().await.clone()
    }
}

/// A signed envelope whose stdout is [`PLAN_BODY`], plus the OID it is
/// attached at in a freshly built writ repo.
///
/// Every scenario reuses one envelope: the workflows fetch writ's notes
/// ref and verify whatever `RunAgentCompleted` points at, so the stub's
/// reply can name this same OID for the planner, reviewer, and
/// implementer runs alike.
struct WritSide {
    repo_path: PathBuf,
    oid: GitObjectId,
    metadata: SignedRunMetadata,
    signature: writ::core::SshSignature,
    untrusted_oid: GitObjectId,
    untrusted_metadata: SignedRunMetadata,
    untrusted_signature: writ::core::SshSignature,
}

fn build_writ_side(dir: &Path) -> WritSide {
    let repo = NotesRepo::init_or_open(dir.join("writ-bare")).unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();

    let output = OutputEnvelope {
        stdout: PLAN_BODY.as_bytes().to_vec(),
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let output_bytes = output.to_bytes();
    let metadata = SignedRunMetadata {
        run_id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
            .parse::<AgentRunId>()
            .unwrap(),
        session_id: stub_session_id(),
        prompt_sha256: Sha256Hex::try_new(sha256_hex(b"prompt")).unwrap(),
        output_envelope_sha256: Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap(),
        capabilities: vec![CapabilitySet::WorkspaceRead { repo: repo_ref() }],
        exit_code: 0,
        completed_at: UnixMillis::from_millis(1_700_000_000_000),
        signing_key_fingerprint: signing_key.fingerprint(),
    };
    let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
    let envelope = SignedRunEnvelope {
        metadata: metadata.clone(),
        output: output_bytes.clone(),
        signature: signature.clone(),
    };

    let oid = repo
        .write_note(
            &writ_output_ref(),
            b"trace-baseline-seed",
            &serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();

    // A second, identically-shaped envelope signed by a key bailiff
    // does not trust.
    let other_key = WritSigningKey::from_openssh_pem(OTHER_PEM).unwrap();
    let mut untrusted_metadata = metadata.clone();
    untrusted_metadata.signing_key_fingerprint = other_key.fingerprint();
    let untrusted_signature = other_key
        .sign(&untrusted_metadata.canonical_bytes())
        .unwrap();
    let untrusted_envelope = SignedRunEnvelope {
        metadata: untrusted_metadata.clone(),
        output: output_bytes,
        signature: untrusted_signature.clone(),
    };
    let untrusted_oid = repo
        .write_note(
            &writ_output_ref(),
            b"trace-baseline-untrusted-seed",
            &serde_json::to_vec(&untrusted_envelope).unwrap(),
        )
        .unwrap();

    WritSide {
        repo_path: repo.path().to_path_buf(),
        oid,
        metadata,
        signature,
        untrusted_oid,
        untrusted_metadata,
        untrusted_signature,
    }
}

impl WritSide {
    /// The reply a workflow's `RunAgent` should get: an envelope that
    /// is really on disk and really verifies.
    fn run_agent_completed(&self) -> ServerMessage {
        ServerMessage::RunAgentCompleted {
            output_oid: self.oid.clone(),
            signed_metadata: self.metadata.clone(),
            signature: self.signature.clone(),
        }
    }

    /// A reply whose signed metadata names a *different* session than
    /// the one bailiff opened. The mismatch check runs before envelope
    /// verification, so the signature deliberately no longer matches —
    /// this scenario is about the earlier branch.
    /// A reply pointing at an envelope signed by a key bailiff does
    /// not trust, attached in the same writ repo.
    ///
    /// This is how a *post-run* note-write failure is provoked for
    /// `review`: narrowing `allowed_signers` instead would fail the
    /// planner envelope during the pre-RPC read, so no session would
    /// ever open and the trace would be empty — which is what a first
    /// attempt at this scenario actually recorded.
    fn untrusted_run_agent_completed(&self) -> ServerMessage {
        ServerMessage::RunAgentCompleted {
            output_oid: self.untrusted_oid.clone(),
            signed_metadata: self.untrusted_metadata.clone(),
            signature: self.untrusted_signature.clone(),
        }
    }

    fn run_agent_completed_for_other_session(&self) -> ServerMessage {
        let mut metadata = self.metadata.clone();
        metadata.session_id = "9f8e7d6c-5b4a-4392-8180-706f5e4d3c2b".parse().unwrap();
        ServerMessage::RunAgentCompleted {
            output_oid: self.oid.clone(),
            signed_metadata: metadata,
            signature: self.signature.clone(),
        }
    }

    fn plan_note(&self, plan_id: PlanId) -> PlanNote {
        PlanNote {
            plan_id,
            purpose: "plan-submit".into(),
            writ_output_oid: self.oid.clone(),
            signed_metadata: self.metadata.clone(),
            signature: self.signature.clone(),
        }
    }

    fn review_note(&self, plan_id: PlanId) -> ReviewNote {
        ReviewNote {
            plan_id,
            purpose: "plan-review".into(),
            writ_output_oid: self.oid.clone(),
            signed_metadata: self.metadata.clone(),
            signature: self.signature.clone(),
        }
    }
}

fn allowed_signers() -> AllowedSigners {
    AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap()
}

fn fixed_plan_id() -> PlanId {
    PlanId::from_uuid("11111111-2222-4333-8444-555555555555".parse().unwrap())
}

fn plant(repo: &NotesRepo, plan_id: PlanId, seed: Vec<u8>, body: Vec<u8>) {
    repo.write_note(&plan_notes_ref(plan_id), &seed, &body)
        .unwrap();
}

fn submit_inputs(plan_id: PlanId) -> SubmitPlanInputs {
    SubmitPlanInputs {
        prompt: AgentPrompt::try_new("Draft a plan.").unwrap(),
        capabilities: vec![CapabilitySet::WorkspaceRead { repo: repo_ref() }],
        purpose: "plan-submit".into(),
        writ_output_ref: writ_output_ref(),
        session_label: Some("plan-submit:trace".into()),
        session_agent_kind: Some(AgentKind::Claude),
        session_agent_model: Some("claude-test".into()),
        plan_id,
    }
}

fn review_inputs(plan_id: PlanId) -> SubmitReviewInputs {
    SubmitReviewInputs {
        plan_id,
        reviewer_instructions: AgentPrompt::try_new("Evaluate.").unwrap(),
        capabilities: vec![CapabilitySet::WorkspaceRead { repo: repo_ref() }],
        purpose: "plan-review".into(),
        writ_output_ref: writ_output_ref(),
        session_label: Some("plan-review:trace".into()),
        session_agent_kind: Some(AgentKind::Claude),
        session_agent_model: Some("claude-test".into()),
    }
}

fn implement_inputs(plan_id: PlanId) -> SubmitImplementInputs {
    SubmitImplementInputs {
        plan_id,
        feature_prompt: AgentPrompt::try_new("Build it.").unwrap(),
        capabilities: vec![CapabilitySet::WorkspaceWrite { repo: repo_ref() }],
        purpose: "plan-implement".into(),
        writ_output_ref: writ_output_ref(),
        session_agent_kind: AgentKind::Claude,
        session_agent_model: "claude-test".into(),
        workspace: writ::vm_git::AgentVmWorkspaceBootstrap {
            repo: GitCloneRepo::new(repo_ref()).unwrap(),
            destination: None,
            warm: WorkspaceWarmMode::None,
        },
    }
}

/// Compare `observed` against the checked-in fixture, or rewrite it
/// when `UPDATE_RPC_TRACES=1`.
fn assert_trace(name: &str, observed: &[ClientMessage]) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rpc-traces")
        .join(format!("{name}.json"));
    let rendered = format!("{}\n", serde_json::to_string_pretty(observed).unwrap());

    // Exactly "1", not merely "set". A runner exporting
    // `UPDATE_RPC_TRACES=0` to mean *disabled* would otherwise rewrite
    // every fixture and return without comparing anything, turning the
    // baseline off precisely where it is relied on.
    if std::env::var("UPDATE_RPC_TRACES").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(rendered.as_bytes()).unwrap();
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing RPC-trace baseline {}: {e}. Capture it with UPDATE_RPC_TRACES=1.",
            path.display(),
        )
    });
    assert_eq!(
        rendered, expected,
        "the writ RPCs emitted by `{name}` no longer match the recorded baseline. If slice 3 \
         is meant to preserve behaviour, this diff is a bug; if a change is intended, rerun \
         with UPDATE_RPC_TRACES=1 and review the diff as part of the change.",
    );
}

#[tokio::test]
async fn submit_emits_open_run_close() {
    let tmp = tempfile::tempdir().unwrap();
    let writ = build_writ_side(tmp.path());
    let broker = StubBroker::start(vec![
        ServerMessage::SessionOpened {
            session_id: stub_session_id(),
        },
        writ.run_agent_completed(),
        ServerMessage::SessionClosed,
    ])
    .await;

    let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap());
    let client = WritClient::new(&broker.socket_path);
    submit_plan(
        &client,
        Arc::clone(&bailiff),
        &writ.repo_path,
        allowed_signers(),
        submit_inputs(fixed_plan_id()),
    )
    .await
    .expect("submit_plan must succeed against the stub");

    assert_trace("submit_happy", &broker.observed().await);
}

#[tokio::test]
async fn review_emits_open_run_close() {
    let tmp = tempfile::tempdir().unwrap();
    let writ = build_writ_side(tmp.path());
    let broker = StubBroker::start(vec![
        ServerMessage::SessionOpened {
            session_id: stub_session_id(),
        },
        writ.run_agent_completed(),
        ServerMessage::SessionClosed,
    ])
    .await;

    let plan_id = fixed_plan_id();
    let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap());
    plant(
        &bailiff,
        plan_id,
        plan_submission_seed_blob_bytes(plan_id),
        writ.plan_note(plan_id).canonical_bytes(),
    );

    let client = WritClient::new(&broker.socket_path);
    submit_review(
        &client,
        Arc::clone(&bailiff),
        &writ.repo_path,
        allowed_signers(),
        review_inputs(plan_id),
    )
    .await
    .expect("submit_review must succeed against the stub");

    assert_trace("review_happy", &broker.observed().await);
}

/// The implementer run is VM-dispatched: the broker mints and closes
/// its own audit session, so bailiff sends `RunAgent` alone. That
/// asymmetry with submit/review is the axis slice 3's `StageSpec` has
/// to model as a DU rather than a boolean, and this trace is what pins
/// it.
#[tokio::test]
async fn implement_emits_run_agent_only() {
    let tmp = tempfile::tempdir().unwrap();
    let writ = build_writ_side(tmp.path());
    let broker = StubBroker::start(vec![writ.run_agent_completed()]).await;

    let plan_id = fixed_plan_id();
    let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap());
    plant(
        &bailiff,
        plan_id,
        plan_submission_seed_blob_bytes(plan_id),
        writ.plan_note(plan_id).canonical_bytes(),
    );
    plant(
        &bailiff,
        plan_id,
        plan_review_seed_blob_bytes(plan_id),
        writ.review_note(plan_id).canonical_bytes(),
    );
    write_decision_note(
        &bailiff,
        &DecisionNote {
            plan_id,
            outcome: Decision::Accepted,
            decider: Decider::try_new("cli:trace").unwrap(),
            decided_at: UnixMillis::from_millis(1_700_000_000_000),
        },
    )
    .unwrap();

    let client = WritClient::new(&broker.socket_path);
    submit_implement(
        &client,
        Arc::clone(&bailiff),
        &writ.repo_path,
        allowed_signers(),
        implement_inputs(plan_id),
    )
    .await
    .expect("submit_implement must succeed against the stub");

    assert_trace("implement_happy", &broker.observed().await);
}

/// Every refused gate emits nothing at all.
///
/// Recorded as three separate fixtures rather than one assertion so a
/// slice-3 interpreter that leaks an `OpenSession` before consulting
/// the relation fails on the specific stage that leaked.
#[tokio::test]
async fn refused_gates_emit_no_rpcs() {
    let tmp = tempfile::tempdir().unwrap();
    let writ = build_writ_side(tmp.path());
    let plan_id = fixed_plan_id();

    // `submit` from a plan that already has a submission note.
    {
        let broker = StubBroker::start(vec![]).await;
        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("b1")).unwrap());
        plant(
            &bailiff,
            plan_id,
            plan_submission_seed_blob_bytes(plan_id),
            writ.plan_note(plan_id).canonical_bytes(),
        );
        let client = WritClient::new(&broker.socket_path);
        submit_plan(
            &client,
            bailiff,
            &writ.repo_path,
            allowed_signers(),
            submit_inputs(plan_id),
        )
        .await
        .expect_err("submit must refuse a plan id that already exists");
        assert_trace("submit_refused", &broker.observed().await);
    }

    // `review` from a plan with no submission at all.
    {
        let broker = StubBroker::start(vec![]).await;
        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("b2")).unwrap());
        let client = WritClient::new(&broker.socket_path);
        submit_review(
            &client,
            bailiff,
            &writ.repo_path,
            allowed_signers(),
            review_inputs(plan_id),
        )
        .await
        .expect_err("review must refuse an unsubmitted plan");
        assert_trace("review_refused", &broker.observed().await);
    }

    // `implement` from a submitted-but-unreviewed plan.
    {
        let broker = StubBroker::start(vec![]).await;
        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("b3")).unwrap());
        plant(
            &bailiff,
            plan_id,
            plan_submission_seed_blob_bytes(plan_id),
            writ.plan_note(plan_id).canonical_bytes(),
        );
        let client = WritClient::new(&broker.socket_path);
        submit_implement(
            &client,
            bailiff,
            &writ.repo_path,
            allowed_signers(),
            implement_inputs(plan_id),
        )
        .await
        .expect_err("implement must refuse an unreviewed plan");
        assert_trace("implement_refused", &broker.observed().await);
    }
}

/// After a session is open, a failing `RunAgent` must still be
/// followed by `CloseSession`.
///
/// This is the contract both `submit_plan` and `submit_review`
/// document at length ("from here on, every early return must close
/// the session"), and it is the sad path most easily lost in slice 3:
/// an interpreter that propagates the run error with `?` before its
/// cleanup arm leaks the session, and no happy-path or pre-RPC fixture
/// would notice. The plan asks for "happy *and each sad path*"; this
/// is the half that was missing from the first capture.
///
/// The leak would be invisible in writ's audit log too — the session
/// row simply never closes — so the trace is the cheapest place to
/// pin it.
#[tokio::test]
async fn a_failed_run_still_closes_the_session() {
    // submit
    {
        let tmp = tempfile::tempdir().unwrap();
        let writ = build_writ_side(tmp.path());
        let broker = StubBroker::start(vec![
            ServerMessage::SessionOpened {
                session_id: stub_session_id(),
            },
            ServerMessage::Error {
                message: "agent runner unavailable".into(),
            },
            ServerMessage::SessionClosed,
        ])
        .await;

        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap());
        let client = WritClient::new(&broker.socket_path);
        submit_plan(
            &client,
            bailiff,
            &writ.repo_path,
            allowed_signers(),
            submit_inputs(fixed_plan_id()),
        )
        .await
        .expect_err("a broker error must surface");

        assert_trace("submit_run_agent_error", &broker.observed().await);
    }

    // review
    {
        let tmp = tempfile::tempdir().unwrap();
        let writ = build_writ_side(tmp.path());
        let broker = StubBroker::start(vec![
            ServerMessage::SessionOpened {
                session_id: stub_session_id(),
            },
            ServerMessage::Error {
                message: "agent runner unavailable".into(),
            },
            ServerMessage::SessionClosed,
        ])
        .await;

        let plan_id = fixed_plan_id();
        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap());
        plant(
            &bailiff,
            plan_id,
            plan_submission_seed_blob_bytes(plan_id),
            writ.plan_note(plan_id).canonical_bytes(),
        );

        let client = WritClient::new(&broker.socket_path);
        submit_review(
            &client,
            bailiff,
            &writ.repo_path,
            allowed_signers(),
            review_inputs(plan_id),
        )
        .await
        .expect_err("a broker error must surface");

        assert_trace("review_run_agent_error", &broker.observed().await);
    }
}

/// The remaining post-`OpenSession` branches, one fixture each.
///
/// `submit_plan` and `submit_review` can each fail in four distinct
/// places after the session opens — the run itself, the session-id
/// cross-check, the note fetch/verify/write, and the final close — and
/// every one of them must still emit `CloseSession`. A shared
/// interpreter that gets any single branch wrong leaks a session while
/// the happy-path and zero-RPC fixtures stay green, which is exactly
/// the hole this suite exists to close.
///
/// `OpenSession` failing is the one branch with a *different* shape:
/// there is no session to clean up, so the trace is one message long.
/// Pinning it stops an interpreter from "helpfully" closing a session
/// it never opened.
#[tokio::test]
async fn every_post_open_failure_branch_has_a_trace() {
    // --- OpenSession refused: one message, no cleanup. ---
    for (name, is_review) in [
        ("submit_open_session_error", false),
        ("review_open_session_error", true),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let writ = build_writ_side(tmp.path());
        let broker = StubBroker::start(vec![ServerMessage::Error {
            message: "no agent kind configured".into(),
        }])
        .await;
        let plan_id = fixed_plan_id();
        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("b")).unwrap());
        let client = WritClient::new(&broker.socket_path);
        if is_review {
            plant(
                &bailiff,
                plan_id,
                plan_submission_seed_blob_bytes(plan_id),
                writ.plan_note(plan_id).canonical_bytes(),
            );
            submit_review(
                &client,
                bailiff,
                &writ.repo_path,
                allowed_signers(),
                review_inputs(plan_id),
            )
            .await
            .expect_err("a refused OpenSession must surface");
        } else {
            submit_plan(
                &client,
                bailiff,
                &writ.repo_path,
                allowed_signers(),
                submit_inputs(plan_id),
            )
            .await
            .expect_err("a refused OpenSession must surface");
        }
        assert_trace(name, &broker.observed().await);
    }

    // --- Session-id cross-check fails after a successful run. ---
    for (name, is_review) in [
        ("submit_session_id_mismatch", false),
        ("review_session_id_mismatch", true),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let writ = build_writ_side(tmp.path());
        let broker = StubBroker::start(vec![
            ServerMessage::SessionOpened {
                session_id: stub_session_id(),
            },
            writ.run_agent_completed_for_other_session(),
            ServerMessage::SessionClosed,
        ])
        .await;
        let plan_id = fixed_plan_id();
        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("b")).unwrap());
        let client = WritClient::new(&broker.socket_path);
        if is_review {
            plant(
                &bailiff,
                plan_id,
                plan_submission_seed_blob_bytes(plan_id),
                writ.plan_note(plan_id).canonical_bytes(),
            );
            submit_review(
                &client,
                bailiff,
                &writ.repo_path,
                allowed_signers(),
                review_inputs(plan_id),
            )
            .await
            .expect_err("a session-id mismatch must surface");
        } else {
            submit_plan(
                &client,
                bailiff,
                &writ.repo_path,
                allowed_signers(),
                submit_inputs(plan_id),
            )
            .await
            .expect_err("a session-id mismatch must surface");
        }
        assert_trace(name, &broker.observed().await);
    }

    // --- Note verify/write fails after a successful run: the run is
    // --- fine, but its envelope is signed by a key bailiff does not
    // --- trust. `allowed_signers` stays trusted so that review's
    // --- pre-RPC read of the *planner* envelope still succeeds and a
    // --- session really does open.
    for (name, is_review) in [
        ("submit_write_note_failure", false),
        ("review_write_note_failure", true),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let writ = build_writ_side(tmp.path());
        let broker = StubBroker::start(vec![
            ServerMessage::SessionOpened {
                session_id: stub_session_id(),
            },
            writ.untrusted_run_agent_completed(),
            ServerMessage::SessionClosed,
        ])
        .await;
        let plan_id = fixed_plan_id();
        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("b")).unwrap());
        let client = WritClient::new(&broker.socket_path);
        if is_review {
            plant(
                &bailiff,
                plan_id,
                plan_submission_seed_blob_bytes(plan_id),
                writ.plan_note(plan_id).canonical_bytes(),
            );
            submit_review(
                &client,
                bailiff,
                &writ.repo_path,
                allowed_signers(),
                review_inputs(plan_id),
            )
            .await
            .expect_err("an untrusted signer must fail the note write");
        } else {
            submit_plan(
                &client,
                bailiff,
                &writ.repo_path,
                allowed_signers(),
                submit_inputs(plan_id),
            )
            .await
            .expect_err("an untrusted signer must fail the note write");
        }
        assert_trace(name, &broker.observed().await);
    }
}

/// The implementer's post-RPC failures still emit `RunAgent` alone.
///
/// Session ownership is the axis slice 3 must model as a DU, and the
/// happy path alone does not pin it: an interpreter could plausibly
/// add caller-side `OpenSession`/`CloseSession` cleanup on the *error*
/// branch only — precisely where a broker-managed session most looks
/// like it needs tidying up — and every other implement fixture would
/// stay green.
#[tokio::test]
async fn implement_failures_still_own_no_session() {
    for (name, reply) in [
        (
            "implement_run_agent_error",
            ServerMessage::Error {
                message: "agent runner unavailable".into(),
            },
        ),
        ("implement_write_note_failure", ServerMessage::SessionClosed),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let writ = build_writ_side(tmp.path());
        // The second case replies with an envelope bailiff will not
        // accept, so the failure lands in the note write.
        let reply = match name {
            "implement_write_note_failure" => writ.untrusted_run_agent_completed(),
            _ => reply,
        };
        let broker = StubBroker::start(vec![reply]).await;

        let plan_id = fixed_plan_id();
        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("b")).unwrap());
        plant(
            &bailiff,
            plan_id,
            plan_submission_seed_blob_bytes(plan_id),
            writ.plan_note(plan_id).canonical_bytes(),
        );
        plant(
            &bailiff,
            plan_id,
            plan_review_seed_blob_bytes(plan_id),
            writ.review_note(plan_id).canonical_bytes(),
        );
        write_decision_note(
            &bailiff,
            &DecisionNote {
                plan_id,
                outcome: Decision::Accepted,
                decider: Decider::try_new("cli:trace").unwrap(),
                decided_at: UnixMillis::from_millis(1_700_000_000_000),
            },
        )
        .unwrap();

        let client = WritClient::new(&broker.socket_path);
        let err = submit_implement(
            &client,
            bailiff,
            &writ.repo_path,
            allowed_signers(),
            implement_inputs(plan_id),
        )
        .await
        .expect_err("this scenario must fail");
        assert!(
            !matches!(err, SubmitImplementError::IllegalTransition { .. }),
            "the gate must have passed; got {err:?}",
        );

        assert_trace(name, &broker.observed().await);
    }
}

/// Failures *after* the gate but *before* `OpenSession` must still emit
/// nothing.
///
/// `review_refused` only covers exiting at the gate itself. Between the
/// gate and the session there are two more ways to fail — the planner
/// envelope not verifying, and the composed prompt exceeding the byte
/// cap — and an interpreter that opened the session immediately after
/// the gate would burn an audit row on both while `review_refused`
/// stayed green.
#[tokio::test]
async fn review_failures_before_open_session_emit_nothing() {
    // Legal state, but the planner envelope does not verify.
    {
        let tmp = tempfile::tempdir().unwrap();
        let writ = build_writ_side(tmp.path());
        let broker = StubBroker::start(vec![]).await;
        let plan_id = fixed_plan_id();
        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("b")).unwrap());
        // The submission note points at the *untrusted* envelope, so
        // the state is `Submitted` and the gate passes.
        plant(
            &bailiff,
            plan_id,
            plan_submission_seed_blob_bytes(plan_id),
            PlanNote {
                plan_id,
                purpose: "plan-submit".into(),
                writ_output_oid: writ.untrusted_oid.clone(),
                signed_metadata: writ.untrusted_metadata.clone(),
                signature: writ.untrusted_signature.clone(),
            }
            .canonical_bytes(),
        );
        let client = WritClient::new(&broker.socket_path);
        let err = submit_review(
            &client,
            bailiff,
            &writ.repo_path,
            allowed_signers(),
            review_inputs(plan_id),
        )
        .await
        .expect_err("an unverifiable planner envelope must fail");
        assert!(
            matches!(err, SubmitReviewError::ReadPlanEnvelope(_)),
            "expected ReadPlanEnvelope, got {err:?}",
        );
        assert_trace("review_envelope_unverifiable", &broker.observed().await);
    }

    // Legal state and a verifiable envelope, but the composed prompt
    // overflows the cap.
    {
        let tmp = tempfile::tempdir().unwrap();
        let writ = build_writ_side(tmp.path());
        let broker = StubBroker::start(vec![]).await;
        let plan_id = fixed_plan_id();
        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("b")).unwrap());
        plant(
            &bailiff,
            plan_id,
            plan_submission_seed_blob_bytes(plan_id),
            writ.plan_note(plan_id).canonical_bytes(),
        );
        let mut inputs = review_inputs(plan_id);
        // Just under the cap on its own; over it once the separator and
        // plan body are appended.
        inputs.reviewer_instructions =
            AgentPrompt::try_new("x".repeat(writ::agent_run::MAX_AGENT_PROMPT_BYTES - 16)).unwrap();
        let client = WritClient::new(&broker.socket_path);
        let err = submit_review(&client, bailiff, &writ.repo_path, allowed_signers(), inputs)
            .await
            .expect_err("an oversized composed prompt must fail");
        assert!(
            matches!(err, SubmitReviewError::ComposeReviewerPrompt(_)),
            "expected ComposeReviewerPrompt, got {err:?}",
        );
        assert_trace("review_prompt_too_large", &broker.observed().await);
    }
}

/// A failing `CloseSession` is the one branch the request trace alone
/// cannot distinguish, so these assert the *returned error* as well.
///
/// The two cases differ in a way an interpreter can easily get
/// backwards. On the happy path a close failure is the only thing that
/// went wrong, so it is surfaced. During cleanup after an earlier
/// failure it is deliberately swallowed, because the original error is
/// the actionable one. Both emit an identical open→run→close trace, so
/// only the error variant tells them apart.
#[tokio::test]
async fn close_session_failures_surface_the_right_error() {
    // Happy run, failing close: the close error is what the caller sees.
    {
        let tmp = tempfile::tempdir().unwrap();
        let writ = build_writ_side(tmp.path());
        let broker = StubBroker::start(vec![
            ServerMessage::SessionOpened {
                session_id: stub_session_id(),
            },
            writ.run_agent_completed(),
            ServerMessage::Error {
                message: "close failed".into(),
            },
        ])
        .await;
        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("b")).unwrap());
        let client = WritClient::new(&broker.socket_path);
        let err = submit_plan(
            &client,
            bailiff,
            &writ.repo_path,
            allowed_signers(),
            submit_inputs(fixed_plan_id()),
        )
        .await
        .expect_err("a failing close must surface");
        assert!(
            matches!(err, SubmitPlanError::CloseSession { .. }),
            "a close failure on the happy path must surface as CloseSession, got {err:?}",
        );
        assert_trace("submit_close_session_error", &broker.observed().await);
    }

    // Failing run *and* failing close: the run error wins.
    {
        let tmp = tempfile::tempdir().unwrap();
        let writ = build_writ_side(tmp.path());
        let broker = StubBroker::start(vec![
            ServerMessage::SessionOpened {
                session_id: stub_session_id(),
            },
            ServerMessage::Error {
                message: "agent runner unavailable".into(),
            },
            ServerMessage::Error {
                message: "close failed".into(),
            },
        ])
        .await;
        let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("b")).unwrap());
        let client = WritClient::new(&broker.socket_path);
        let err = submit_plan(
            &client,
            bailiff,
            &writ.repo_path,
            allowed_signers(),
            submit_inputs(fixed_plan_id()),
        )
        .await
        .expect_err("the run failure must surface");
        assert!(
            matches!(err, SubmitPlanError::RunAgent { .. }),
            "a cleanup close failure must not replace the original error, got {err:?}",
        );
        assert_trace("submit_cleanup_close_error", &broker.observed().await);
    }
}
