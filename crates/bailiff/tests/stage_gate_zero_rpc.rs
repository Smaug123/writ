//! The gate property, over **every** plan state rather than one per
//! stage: a stage the transition relation forbids performs zero writ
//! RPCs.
//!
//! Slice 3 of `docs/plans/2026-07-26-bailiff-workflow-as-data.md`.
//! `rpc_trace_baseline.rs` pins this for three states — one refusal per
//! workflow — because a fixture records one scenario. This file sweeps
//! the whole 3 × 7 grid.
//!
//! The property is what keeps a rejected workflow from burning a writ
//! audit row, and on the implement path from opening a
//! `WorkspaceWrite`-capable run whose side effects no later note-write
//! rejection can undo. It is also the property most easily lost when a
//! phase is reordered, since "gate first" is an ordering rather than a
//! type.
//!
//! # Two things this file is careful about
//!
//! **Zero RPCs is not enough.** A workflow that failed for an
//! unrelated pre-RPC reason — an unreadable repo, an unverifiable
//! envelope — also emits zero RPCs, so "the trace was empty" alone
//! cannot distinguish "correctly refused" from "broke earlier". Every
//! forbidden case therefore also requires the error to be
//! `IllegalTransition` naming the state that was planted.
//!
//! **Zero RPCs is not enough on its own, either**: a workflow that
//! never spoke to writ at all would satisfy it everywhere. So the
//! *allowed* combinations are driven too, and required to emit at
//! least one RPC. Without that control the whole file passes against a
//! workflow with the agent run deleted.
//!
//! # Planting
//!
//! States are planted from `PlanState::presence()` — the same
//! definition `derive_state` is the inverse of — rather than from a
//! hand-written note list per state, so this file cannot encode a
//! sixth opinion about what each state's notes are. Each planting is
//! then read back through `summarize_plan` and required to produce the
//! state it was asked for, so a mistake here fails as a planting
//! error rather than as a mysterious gate result.

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
    DecisionNote, ImplementAttempt, ImplementNote, PlanId, PlanNote, ReviewNote,
    plan_decision_seed_blob_bytes, plan_implement_seed_blob_bytes, plan_notes_ref,
    plan_review_seed_blob_bytes, plan_submission_seed_blob_bytes,
};
use bailiff::bailiff_plan_read::summarize_plan;
use bailiff::bailiff_plan_review::{SubmitReviewError, SubmitReviewInputs, submit_review};
use bailiff::bailiff_plan_state::{NotePresence, PlanState, allows};
use bailiff::bailiff_plan_submit::{SubmitPlanError, SubmitPlanInputs, submit_plan};
use bailiff::bailiff_stage::AgentStage;
use writ::agent_run::{AgentPrompt, AgentRunId, sha256_hex};
use writ::core::{AgentKind, CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
use writ::notes_repo::NotesRepo;
use writ::protocol::{ClientMessage, SignedRunMetadata};
use writ::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use writ::run_verify::AllowedSigners;
use writ::signing::WritSigningKey;
use writ::vm_git::{AgentVmWorkspaceBootstrap, GitCloneRepo, GitObjectId, WorkspaceWarmMode};
use writ::writ_client::WritClient;

const SIGNING_PEM: &str = include_str!("fixtures/ed25519_test_signing.key");
const SIGNING_PUB: &str = include_str!("fixtures/ed25519_test_signing.key.pub");
const PLAN_BODY: &str = "# Plan\n\nReplace bar with baz.\n";
const WRIT_OUTPUT_REF: &str = "refs/notes/writ/v1/agent-outputs";

fn repo_ref() -> RepoRef {
    RepoRef {
        owner: "smaug123".into(),
        name: "writ".into(),
    }
}

fn writ_output_ref() -> NotesRef {
    NotesRef::try_new(WRIT_OUTPUT_REF).unwrap()
}

fn allowed_signers() -> AllowedSigners {
    AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap()
}

/// Records every [`ClientMessage`] it receives and replies to none of
/// them.
///
/// Never replying is deliberate. Every case here either refuses before
/// any RPC (so there is nothing to reply to) or is an allowed case
/// where the assertion is "at least one RPC was sent" — for which the
/// workflow's subsequent transport failure is irrelevant. Recording
/// happens *before* the hang-up, so an RPC sent by a workflow that
/// should have refused is still observed.
struct RecordingBroker {
    socket_path: PathBuf,
    requests: Arc<AsyncMutex<Vec<ClientMessage>>>,
    _task: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl RecordingBroker {
    async fn start() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = dir.path().join("writ.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let requests = Arc::new(AsyncMutex::new(Vec::new()));
        let req_clone = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();
                if let Ok(Some(line)) = lines.next_line().await
                    && let Ok(msg) = serde_json::from_str::<ClientMessage>(&line)
                {
                    req_clone.lock().await.push(msg);
                }
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

/// A writ repo holding one signed envelope whose stdout is
/// [`PLAN_BODY`], so the pre-RPC envelope read succeeds and a refusal
/// can only come from the gate.
struct WritSide {
    repo_path: PathBuf,
    oid: GitObjectId,
    metadata: SignedRunMetadata,
    signature: writ::core::SshSignature,
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
        session_id: "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
            .parse::<SessionId>()
            .unwrap(),
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
        output: output_bytes,
        signature: signature.clone(),
    };
    let oid = repo
        .write_note(
            &writ_output_ref(),
            b"stage-gate-seed",
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

/// The note set to plant for `state`.
///
/// [`PlanState::presence`] is `None` for exactly one state,
/// [`PlanState::Corrupt`], which is *defined* as "a note set no legal
/// sequence produces" and so has no canonical presence to return. One
/// concrete unreachable set stands in: a verdict with no submission
/// beneath it, which is the anomaly `plan decide` could manufacture in
/// a single command before slice 1 gated it.
fn presence_for(state: PlanState) -> NotePresence {
    state.presence().unwrap_or(NotePresence {
        ref_exists: true,
        submission: false,
        decision: Some(Decision::Accepted),
        review: false,
        implement: false,
    })
}

/// Write the notes `presence` describes, then read the plan back and
/// require it to be in `state`.
///
/// The read-back is not ceremony: it is what makes a planting bug fail
/// here, loudly, instead of downstream as a gate result nobody can
/// explain.
fn plant(repo: &NotesRepo, writ: &WritSide, plan_id: PlanId, state: PlanState) {
    let presence = presence_for(state);
    let plan_ref = plan_notes_ref(plan_id);

    if presence.submission {
        let note = PlanNote {
            plan_id,
            purpose: "plan-submit".parse().unwrap(),
            writ_output_oid: writ.oid.clone(),
            signed_metadata: writ.metadata.clone(),
            signature: writ.signature.clone(),
        };
        repo.write_note(
            &plan_ref,
            &plan_submission_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();
    }
    if presence.review {
        let note = ReviewNote {
            plan_id,
            purpose: "plan-review".parse().unwrap(),
            writ_output_oid: writ.oid.clone(),
            signed_metadata: writ.metadata.clone(),
            signature: writ.signature.clone(),
        };
        repo.write_note(
            &plan_ref,
            &plan_review_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();
    }
    if let Some(outcome) = presence.decision {
        let note = DecisionNote {
            plan_id,
            outcome,
            decider: Decider::try_new("cli:test").unwrap(),
            decided_at: UnixMillis::from_millis(1_700_000_001_000),
        };
        repo.write_note(
            &plan_ref,
            &plan_decision_seed_blob_bytes(plan_id),
            &note.canonical_bytes(),
        )
        .unwrap();
    }
    if presence.implement {
        let note = ImplementNote {
            plan_id,
            purpose: "plan-implement".parse().unwrap(),
            writ_output_oid: writ.oid.clone(),
            signed_metadata: writ.metadata.clone(),
            signature: writ.signature.clone(),
        };
        repo.write_note(
            &plan_ref,
            &plan_implement_seed_blob_bytes(plan_id, ImplementAttempt::FIRST),
            &note.canonical_bytes(),
        )
        .unwrap();
    }

    let observed = summarize_plan(repo, plan_id).unwrap().state();
    assert_eq!(
        observed, state,
        "planting {state} produced a plan in state {observed}; the presence table and the \
         note writers disagree",
    );
}

/// What a driven workflow reported, reduced to the one distinction
/// this file cares about.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// The gate refused, naming this state.
    IllegalTransition(PlanState),
    /// Anything else — including success. Carries the rendering so a
    /// failure message says what actually happened.
    Other(String),
}

async fn drive(
    stage: AgentStage,
    client: &WritClient,
    bailiff: Arc<NotesRepo>,
    writ: &WritSide,
    plan_id: PlanId,
) -> Refusal {
    match stage {
        AgentStage::Submit => {
            let inputs = SubmitPlanInputs {
                prompt: AgentPrompt::try_new("Draft a plan.").unwrap(),
                capabilities: vec![CapabilitySet::WorkspaceRead { repo: repo_ref() }],
                purpose: "plan-submit".parse().unwrap(),
                writ_output_ref: writ_output_ref(),
                session_label: None,
                session_agent_kind: Some(AgentKind::Claude),
                session_agent_model: None,
                plan_id,
            };
            match submit_plan(client, bailiff, &writ.repo_path, allowed_signers(), inputs).await {
                Err(SubmitPlanError::IllegalTransition { source, .. }) => {
                    Refusal::IllegalTransition(source.state)
                }
                other => Refusal::Other(format!("{other:?}")),
            }
        }
        AgentStage::Review => {
            let inputs = SubmitReviewInputs {
                plan_id,
                reviewer_instructions: AgentPrompt::try_new("Evaluate.").unwrap(),
                capabilities: vec![CapabilitySet::WorkspaceRead { repo: repo_ref() }],
                purpose: "plan-review".parse().unwrap(),
                writ_output_ref: writ_output_ref(),
                session_label: None,
                session_agent_kind: Some(AgentKind::Claude),
                session_agent_model: None,
            };
            match submit_review(client, bailiff, &writ.repo_path, allowed_signers(), inputs).await {
                Err(SubmitReviewError::IllegalTransition { source, .. }) => {
                    Refusal::IllegalTransition(source.state)
                }
                other => Refusal::Other(format!("{other:?}")),
            }
        }
        AgentStage::Implement => {
            let inputs = SubmitImplementInputs {
                plan_id,
                feature_prompt: AgentPrompt::try_new("Build it.").unwrap(),
                capabilities: vec![CapabilitySet::WorkspaceWrite { repo: repo_ref() }],
                purpose: "plan-implement".parse().unwrap(),
                writ_output_ref: writ_output_ref(),
                session_agent_kind: AgentKind::Claude,
                session_agent_model: "claude-test".into(),
                workspace: AgentVmWorkspaceBootstrap {
                    repo: GitCloneRepo::new(repo_ref()).unwrap(),
                    destination: None,
                    warm: WorkspaceWarmMode::None,
                },
            };
            match submit_implement(client, bailiff, &writ.repo_path, allowed_signers(), inputs)
                .await
            {
                Err(SubmitImplementError::IllegalTransition { source, .. }) => {
                    Refusal::IllegalTransition(source.state)
                }
                other => Refusal::Other(format!("{other:?}")),
            }
        }
    }
}

/// The whole 3 × 7 grid, in one test so the forbidden and allowed
/// halves cannot drift apart or be run separately.
///
/// Forbidden ⇒ zero RPCs *and* an `IllegalTransition` naming the
/// planted state. Allowed ⇒ at least one RPC. The second half is the
/// control: without it, a workflow that had lost its agent run
/// entirely would pass the first half everywhere.
#[tokio::test]
async fn a_forbidden_stage_emits_no_rpcs_and_an_allowed_one_emits_some() {
    let tmp = tempfile::tempdir().unwrap();
    let writ = build_writ_side(tmp.path());
    let bailiff = Arc::new(NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap());

    let mut forbidden = 0usize;
    let mut permitted = 0usize;

    for &state in PlanState::ALL {
        for stage in AgentStage::ALL {
            // A fresh plan id per case, so one case's notes are not
            // another's starting state.
            let plan_id = PlanId::new();
            plant(&bailiff, &writ, plan_id, state);

            let broker = RecordingBroker::start().await;
            let client = WritClient::new(&broker.socket_path);
            let outcome = drive(stage, &client, Arc::clone(&bailiff), &writ, plan_id).await;
            let observed = broker.observed().await;

            match allows(state, stage.precondition()) {
                Err(_) => {
                    forbidden += 1;
                    // RPC count first, *then* the error variant. The
                    // other order hides this assertion: a stage that
                    // ran when it should not have fails the variant
                    // check too, and the earlier assertion is the one
                    // that fires — so the count is never observed to
                    // catch anything. Verified by mutation: deleting
                    // `submit`'s gate must fail on this line, not the
                    // next.
                    assert!(
                        observed.is_empty(),
                        "{stage:?} from {state} is forbidden but emitted {observed:?}",
                    );
                    assert_eq!(
                        outcome,
                        Refusal::IllegalTransition(state),
                        "{stage:?} from {state} emitted no RPC, but refused for the wrong \
                         reason — an unrelated pre-RPC failure looks identical on the wire",
                    );
                }
                Ok(()) => {
                    permitted += 1;
                    assert!(
                        !observed.is_empty(),
                        "{stage:?} from {state} is legal but emitted no writ RPC at all; the \
                         zero-RPC assertions above would pass vacuously against this",
                    );
                }
            }
        }
    }

    // The grid was actually swept, and the split is exactly what the
    // relation says it should be. Counts rather than `> 0`: a relation
    // that forbade or permitted everything would pass a non-emptiness
    // check while making one half of this test vacuous.
    assert_eq!(
        forbidden + permitted,
        PlanState::ALL.len() * AgentStage::ALL.len()
    );
    // Four legal (stage, state) pairs: submit from `absent`, review
    // from `submitted`, implement from `accepted` — and, since slice 4,
    // **implement from `implemented`**, because fan-out is N
    // implementer runs on one accepted plan. That fourth pair crossing
    // from the forbidden half to the permitted half is slice 4's
    // behaviour delta, written here as a number so it cannot be
    // absorbed silently: this file derives both halves from `allows`,
    // so without the count a widened relation would just quietly move
    // cases across.
    assert_eq!(permitted, 4, "the permitted half of the grid changed");
    assert_eq!(forbidden, PlanState::ALL.len() * AgentStage::ALL.len() - 4);
}
