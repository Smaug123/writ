//! Full slice-C handshake against a real writ broker. Mirrors the
//! slice-B5 round-trip in `writ_client.rs` and tacks
//! `write_plan_note` on the end: bailiff sends `RunAgent`, writ
//! signs and persists the envelope, then bailiff drives
//! `write_plan_note` to fetch the envelope, verify it, and store
//! a `PlanNote` keyed on the plan id.
//!
//! A regression anywhere in the chain — protocol framing, signing
//! namespace, notes write, fetch refspec, envelope/reply
//! agreement, plan-note serialisation — fails this test rather
//! than getting caught by a downstream consumer.
use std::sync::Arc;
use std::time::Duration;
use writ::test_support::{SpawnedBroker, cat_run_agent_spawn, claude_broker_state};

use tokio::sync::Mutex as AsyncMutex;
use wiremock::MockServer;

use super::*;
use crate::bailiff_plan_note::{
    ImplementAttempt, ImplementNote, PlanId, PlanNote, ReviewNote, plan_notes_ref,
};
use writ::agent_run::AgentPrompt;
use writ::core::{AgentKind, CapabilitySet, NotesRef, RepoRef};
use writ::notes_repo::NotesRepo;
use writ::run_verify::AllowedSigners;
use writ::signing::WritSigningKey;
use writ::writ_client::{RunAgentRequest, WritClient};

use writ::test_support::ED25519_SIGNING_PEM as SIGNING_PEM;
use writ::test_support::ED25519_SIGNING_PUB as SIGNING_PUB;

#[tokio::test]
async fn write_plan_note_completes_after_real_broker_round_trip() {
    // --- Broker bring-up (writ side) ----------------------------
    let tmp = tempfile::tempdir().unwrap();
    let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let bailiff_repo_handle = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let github_server = MockServer::start().await;
    let mut state = claude_broker_state(&github_server.uri(), "o");
    state.notes_repo = Some(Arc::new(writ_repo));
    state.signing_key = Some(signing_key.clone());
    state.run_agent_spawn = Some(cat_run_agent_spawn(tmp.path()));
    let state = Arc::new(state);
    let broker_task = SpawnedBroker::start(Arc::clone(&state)).await;
    let socket_path = broker_task.socket_path.clone();

    // --- Client request (bailiff side) --------------------------
    let prompt_text = "noop\n";
    let writ_notes_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
    let purpose: writ::agent_run::RunPurpose = "plan-submit".parse().unwrap();
    let client = WritClient::new(&socket_path);
    // The host-spawn arm records the run against the caller's session, which
    // is what `run_stage_under_owned_session` opens in the real stage runners.
    let session_id = client
        .open_session(None, Some(AgentKind::Claude), None)
        .await
        .expect("open session");
    let completed = tokio::time::timeout(
        Duration::from_secs(15),
        client.run_agent(RunAgentRequest {
            prompt: AgentPrompt::try_new(prompt_text).unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            purpose: purpose.clone(),
            output_ref: writ_notes_ref.clone(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        }),
    )
    .await
    .expect("RunAgent must complete within 15s")
    .expect("RunAgent must succeed");

    // --- Plan-note write (bailiff side) -------------------------
    // `write_plan_note` is blocking (shells out to git); wrap it
    // in `spawn_blocking` so we don't stall the runtime. A short
    // async lock on the bailiff repo keeps the single-writer
    // invariant visible at the call site.
    let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
    let plan_id = PlanId::new();
    let completed_clone = completed.clone();
    let writ_notes_ref_clone = writ_notes_ref.clone();
    let bailiff = Arc::new(AsyncMutex::new(bailiff_repo_handle));
    let bailiff_for_block = Arc::clone(&bailiff);
    let returned_oid = tokio::task::spawn_blocking(move || {
        let bailiff = bailiff_for_block.blocking_lock();
        write_stage_note(
            &bailiff,
            &StageNoteTarget {
                slot: StageNoteSlot::Submission,
                plan_id,
                writ_repo_path: writ_repo_path.clone(),
                allowed_signers: allowed.clone(),
            },
            &writ_notes_ref_clone,
            purpose.to_string(),
            &completed_clone,
        )
    })
    .await
    .unwrap()
    .expect("write_plan_note must succeed under the trusted-signer keyring")
    .target_oid;

    // --- Read back the plan note from bailiff's repo ------------
    let bailiff_for_read = Arc::clone(&bailiff);
    let plan_ref = plan_notes_ref(plan_id);
    let body = tokio::task::spawn_blocking(move || {
        let bailiff = bailiff_for_read.blocking_lock();
        bailiff.read_note(&plan_ref, &returned_oid)
    })
    .await
    .unwrap()
    .expect("bailiff-side plan note must be readable at the returned OID");
    let note =
        PlanNote::from_canonical_bytes(&body).expect("bailiff-side body must decode as PlanNote");

    // The note carries the plan-id bailiff allocated, the purpose
    // bailiff sent on the wire, the writ-side OID writ returned,
    // and the signed metadata + signature the broker produced.
    assert_eq!(note.plan_id, plan_id);
    assert_eq!(note.purpose, "plan-submit");
    assert_eq!(note.writ_output_oid, completed.output_oid);
    assert_eq!(note.signed_metadata, completed.signed_metadata);
    assert_eq!(note.signature, completed.signature);

    broker_task.stop().await;
}

/// Full handshake against a real writ broker: bailiff
/// sends `RunAgent` for a reviewer run, writ signs and persists
/// the envelope, then bailiff drives `write_review_note` to fetch
/// the envelope, verify it, and store a `ReviewNote` keyed on the
/// plan id. Parallel to
/// [`write_plan_note_completes_after_real_broker_round_trip`];
/// the only material differences are the helper under test, the
/// purpose string, and the read-back type.
#[tokio::test]
async fn write_review_note_completes_after_real_broker_round_trip() {
    // --- Broker bring-up (writ side) ----------------------------
    let tmp = tempfile::tempdir().unwrap();
    let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let bailiff_repo_handle = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let github_server = MockServer::start().await;
    let mut state = claude_broker_state(&github_server.uri(), "o");
    state.notes_repo = Some(Arc::new(writ_repo));
    state.signing_key = Some(signing_key.clone());
    state.run_agent_spawn = Some(cat_run_agent_spawn(tmp.path()));
    let state = Arc::new(state);
    let broker_task = SpawnedBroker::start(Arc::clone(&state)).await;
    let socket_path = broker_task.socket_path.clone();

    // --- Client request (bailiff side) --------------------------
    let prompt_text = "reviewer-prompt + plan body\n";
    let writ_notes_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
    let purpose: writ::agent_run::RunPurpose = "plan-review".parse().unwrap();
    let client = WritClient::new(&socket_path);
    // The host-spawn arm records the run against the caller's session, which
    // is what `run_stage_under_owned_session` opens in the real stage runners.
    let session_id = client
        .open_session(None, Some(AgentKind::Claude), None)
        .await
        .expect("open session");
    let completed = tokio::time::timeout(
        Duration::from_secs(15),
        client.run_agent(RunAgentRequest {
            prompt: AgentPrompt::try_new(prompt_text).unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            purpose: purpose.clone(),
            output_ref: writ_notes_ref.clone(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        }),
    )
    .await
    .expect("RunAgent must complete within 15s")
    .expect("RunAgent must succeed");

    // --- Review-note write (bailiff side) -----------------------
    // `write_review_note` is blocking (shells out to git); wrap
    // it in `spawn_blocking` so we don't stall the runtime. Same
    // `AsyncMutex<NotesRepo>` shape the plan-note round-trip uses.
    let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
    let plan_id = PlanId::new();
    let completed_clone = completed.clone();
    let writ_notes_ref_clone = writ_notes_ref.clone();
    let bailiff = Arc::new(AsyncMutex::new(bailiff_repo_handle));
    let bailiff_for_block = Arc::clone(&bailiff);
    let returned_oid = tokio::task::spawn_blocking(move || {
        let bailiff = bailiff_for_block.blocking_lock();
        write_stage_note(
            &bailiff,
            &StageNoteTarget {
                slot: StageNoteSlot::Review,
                plan_id,
                writ_repo_path: writ_repo_path.clone(),
                allowed_signers: allowed.clone(),
            },
            &writ_notes_ref_clone,
            purpose.to_string(),
            &completed_clone,
        )
    })
    .await
    .unwrap()
    .expect("write_review_note must succeed under the trusted-signer keyring")
    .target_oid;

    // --- Read back the review note from bailiff's repo ----------
    let bailiff_for_read = Arc::clone(&bailiff);
    let plan_ref = plan_notes_ref(plan_id);
    let body = tokio::task::spawn_blocking(move || {
        let bailiff = bailiff_for_read.blocking_lock();
        bailiff.read_note(&plan_ref, &returned_oid)
    })
    .await
    .unwrap()
    .expect("bailiff-side review note must be readable at the returned OID");
    let note = ReviewNote::from_canonical_bytes(&body)
        .expect("bailiff-side body must decode as ReviewNote");

    assert_eq!(note.plan_id, plan_id);
    assert_eq!(note.purpose, "plan-review");
    assert_eq!(note.writ_output_oid, completed.output_oid);
    assert_eq!(note.signed_metadata, completed.signed_metadata);
    assert_eq!(note.signature, completed.signature);

    broker_task.stop().await;
}

/// Full slice-E handshake against a real writ broker: bailiff
/// sends `RunAgent` for an implementer run, writ signs and persists
/// the envelope, then bailiff drives `write_implement_note` to
/// fetch the envelope, verify it, and store an `ImplementNote`
/// keyed on the plan id. Parallel to
/// [`write_plan_note_completes_after_real_broker_round_trip`] and
/// [`write_review_note_completes_after_real_broker_round_trip`];
/// the only material differences are the helper under test, the
/// purpose string, and the read-back type.
#[tokio::test]
async fn write_implement_note_completes_after_real_broker_round_trip() {
    // --- Broker bring-up (writ side) ----------------------------
    let tmp = tempfile::tempdir().unwrap();
    let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let bailiff_repo_handle = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let github_server = MockServer::start().await;
    let mut state = claude_broker_state(&github_server.uri(), "o");
    state.notes_repo = Some(Arc::new(writ_repo));
    state.signing_key = Some(signing_key.clone());
    state.run_agent_spawn = Some(cat_run_agent_spawn(tmp.path()));
    let state = Arc::new(state);
    let broker_task = SpawnedBroker::start(Arc::clone(&state)).await;
    let socket_path = broker_task.socket_path.clone();

    // --- Client request (bailiff side) --------------------------
    let prompt_text = "implementer-prompt + plan body\n";
    let writ_notes_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
    let purpose: writ::agent_run::RunPurpose = "plan-implement".parse().unwrap();
    let client = WritClient::new(&socket_path);
    // The host-spawn arm records the run against the caller's session, which
    // is what `run_stage_under_owned_session` opens in the real stage runners.
    let session_id = client
        .open_session(None, Some(AgentKind::Claude), None)
        .await
        .expect("open session");
    let completed = tokio::time::timeout(
        Duration::from_secs(15),
        client.run_agent(RunAgentRequest {
            prompt: AgentPrompt::try_new(prompt_text).unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            purpose: purpose.clone(),
            output_ref: writ_notes_ref.clone(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        }),
    )
    .await
    .expect("RunAgent must complete within 15s")
    .expect("RunAgent must succeed");

    // --- Implement-note write (bailiff side) --------------------
    // `write_implement_note` is blocking (shells out to git); wrap
    // it in `spawn_blocking` so we don't stall the runtime. Same
    // `AsyncMutex<NotesRepo>` shape the plan-note and review-note
    // round-trips use.
    let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
    let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
    let plan_id = PlanId::new();
    let completed_clone = completed.clone();
    let writ_notes_ref_clone = writ_notes_ref.clone();
    let bailiff = Arc::new(AsyncMutex::new(bailiff_repo_handle));
    let bailiff_for_block = Arc::clone(&bailiff);
    let returned_oid = tokio::task::spawn_blocking(move || {
        let bailiff = bailiff_for_block.blocking_lock();
        write_stage_note(
            &bailiff,
            &StageNoteTarget {
                slot: StageNoteSlot::Implement(ImplementAttempt::FIRST),
                plan_id,
                writ_repo_path: writ_repo_path.clone(),
                allowed_signers: allowed.clone(),
            },
            &writ_notes_ref_clone,
            purpose.to_string(),
            &completed_clone,
        )
    })
    .await
    .unwrap()
    .expect("write_implement_note must succeed under the trusted-signer keyring")
    .target_oid;

    // --- Read back the implement note from bailiff's repo -------
    let bailiff_for_read = Arc::clone(&bailiff);
    let plan_ref = plan_notes_ref(plan_id);
    let body = tokio::task::spawn_blocking(move || {
        let bailiff = bailiff_for_read.blocking_lock();
        bailiff.read_note(&plan_ref, &returned_oid)
    })
    .await
    .unwrap()
    .expect("bailiff-side implement note must be readable at the returned OID");
    let note = ImplementNote::from_canonical_bytes(&body)
        .expect("bailiff-side body must decode as ImplementNote");

    assert_eq!(note.plan_id, plan_id);
    assert_eq!(note.purpose, "plan-implement");
    assert_eq!(note.writ_output_oid, completed.output_oid);
    assert_eq!(note.signed_metadata, completed.signed_metadata);
    assert_eq!(note.signature, completed.signature);

    broker_task.stop().await;
}
