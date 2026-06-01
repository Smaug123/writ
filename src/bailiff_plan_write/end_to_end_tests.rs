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
use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Mutex as AsyncMutex;
use wiremock::MockServer;

use super::*;
use crate::agent_run::AgentPrompt;
use crate::audit::AuditLog;
use crate::bailiff_plan_note::{ImplementNote, PlanId, PlanNote, ReviewNote, plan_notes_ref};
use crate::core::{AgentKind, CapabilitySet, NotesRef, RepoRef, TtlSeconds};
use crate::github::{GitHubAppConfig, GitHubAppRegistryConfig, GitHubMinter};
use crate::notes_repo::NotesRepo;
use crate::policy::PolicyConfig;
use crate::run_verify::AllowedSigners;
use crate::secret::{SecretError, SecretKey, SecretStore};
use crate::server::{
    BrokerState, RunAgentSpawnConfig, prepare_broker_listener, serve_broker_with_agent_vm,
};
use crate::signing::WritSigningKey;
use crate::writ_client::{RunAgentRequest, WritClient};

const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");
const SIGNING_PUB: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key.pub");
const TEST_PRIV: &str = include_str!("../../tests/fixtures/rsa_test_1.pem");

/// In-memory `SecretStore`. Same minimal shim as the writ_client
/// end-to-end test uses — production runs against
/// `FileSecretStore`, but for a test that only stores the
/// GitHub-app PEM to satisfy `BrokerState`'s non-empty registry
/// invariant, an in-memory map is enough.
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

#[tokio::test]
async fn write_plan_note_completes_after_real_broker_round_trip() {
    // --- Broker bring-up (writ side) ----------------------------
    let tmp = tempfile::tempdir().unwrap();
    let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let bailiff_repo_handle = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
    let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");

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
    });

    let socket_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = socket_dir.path().join("writ.sock");
    let listener = prepare_broker_listener(&socket_path).await.unwrap();
    let broker_state = Arc::clone(&state);
    let broker_task = tokio::spawn(async move {
        let _ = serve_broker_with_agent_vm(listener, broker_state, None).await;
    });

    // --- Client request (bailiff side) --------------------------
    let prompt_text = "noop\n";
    let writ_notes_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
    let purpose = "plan-submit".to_string();
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
            purpose: purpose.clone(),
            output_ref: writ_notes_ref.clone(),
            session_id: None,
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
        write_plan_note(
            &bailiff,
            &writ_repo_path,
            &writ_notes_ref_clone,
            plan_id,
            purpose.clone(),
            &completed_clone,
            &allowed,
        )
    })
    .await
    .unwrap()
    .expect("write_plan_note must succeed under the trusted-signer keyring");

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

    broker_task.abort();
    let _ = broker_task.await;
}

/// Full slice-D2 handshake against a real writ broker: bailiff
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
    let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");

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
    });

    let socket_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = socket_dir.path().join("writ.sock");
    let listener = prepare_broker_listener(&socket_path).await.unwrap();
    let broker_state = Arc::clone(&state);
    let broker_task = tokio::spawn(async move {
        let _ = serve_broker_with_agent_vm(listener, broker_state, None).await;
    });

    // --- Client request (bailiff side) --------------------------
    let prompt_text = "reviewer-prompt + plan body\n";
    let writ_notes_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
    let purpose = "plan-review".to_string();
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
            purpose: purpose.clone(),
            output_ref: writ_notes_ref.clone(),
            session_id: None,
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
        write_review_note(
            &bailiff,
            &writ_repo_path,
            &writ_notes_ref_clone,
            plan_id,
            purpose.clone(),
            &completed_clone,
            &allowed,
        )
    })
    .await
    .unwrap()
    .expect("write_review_note must succeed under the trusted-signer keyring");

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

    broker_task.abort();
    let _ = broker_task.await;
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
    let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");

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
    });

    let socket_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = socket_dir.path().join("writ.sock");
    let listener = prepare_broker_listener(&socket_path).await.unwrap();
    let broker_state = Arc::clone(&state);
    let broker_task = tokio::spawn(async move {
        let _ = serve_broker_with_agent_vm(listener, broker_state, None).await;
    });

    // --- Client request (bailiff side) --------------------------
    let prompt_text = "implementer-prompt + plan body\n";
    let writ_notes_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
    let purpose = "plan-implement".to_string();
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
            purpose: purpose.clone(),
            output_ref: writ_notes_ref.clone(),
            session_id: None,
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
        write_implement_note(
            &bailiff,
            &writ_repo_path,
            &writ_notes_ref_clone,
            plan_id,
            purpose.clone(),
            &completed_clone,
            &allowed,
        )
    })
    .await
    .unwrap()
    .expect("write_implement_note must succeed under the trusted-signer keyring");

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

    broker_task.abort();
    let _ = broker_task.await;
}
