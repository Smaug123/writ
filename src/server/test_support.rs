//! Shared fixtures and broker-state builders for the `server` test
//! modules.
//!
//! `super::*` re-exports the production items and `server.rs`'s private
//! `use` aliases; the explicit imports below add what the parent does
//! not pull in. Helpers are `pub(super)` so the sibling `*_tests`
//! modules can reach them.

use super::*;
use crate::core::{AgentKind, RepoRef};
use crate::github::{GitHubAppConfig, GitHubAppRegistryConfig, GitHubMinter};
use crate::policy::PolicyConfig;
use crate::secret::{SecretError, SecretKey, SecretStore};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use wiremock::MockServer;

#[derive(Default)]
pub(super) struct InMemStore(Mutex<HashMap<String, String>>);

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
const TEST_PRIV: &str = include_str!("../../tests/fixtures/rsa_test_1.pem");

/// Walk `PATH` looking for `name`. Returns the first match.
/// The `run_agent` tests need real tools (`cat`, `false`,
/// `sh`/`bash`) and the production `RunAgentSpawnConfig` carries
/// an absolute path, so tests resolve one at setup. Hardcoding
/// `/bin/...` or `/usr/bin/...` works on macOS dev hosts but not
/// in Nix CI sandboxes where coreutils live under `/nix/store/`.
pub(super) fn find_in_path(name: &str) -> Option<std::path::PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Like [`find_in_path`] but tries several names in order. Used
/// for the shell — Nix stdenv reliably provides `bash` on PATH
/// but `sh` may be a symlink that isn't always in scope.
pub(super) fn find_in_path_any(names: &[&str]) -> std::path::PathBuf {
    for name in names {
        if let Some(path) = find_in_path(name) {
            return path;
        }
    }
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    panic!("could not locate any of {names:?} in PATH ({path_var:?})");
}

pub(super) fn make_state(
    server: &MockServer,
    writable: Vec<RepoRef>,
    owner: &str,
) -> Arc<BrokerState<InMemStore>> {
    let pk = SecretKey::new("gh-app-pk").unwrap();
    let store = InMemStore::default();
    store.put(&pk, TEST_PRIV).unwrap();
    let mut apps = BTreeMap::new();
    apps.insert(
        AgentKind::Claude,
        GitHubAppConfig {
            app_id: 42,
            installation_id: 999,
            installation_owner: owner.into(),
            private_key_secret: pk,
            api_base: server.uri(),
        },
    );
    let minter = GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap());
    Arc::new(BrokerState {
        audit: Arc::new(AuditLog::open_in_memory().unwrap()),
        minter,
        secrets: store,
        policy: PolicyConfig {
            writable_repos: writable,
            default_ttl: crate::core::TtlSeconds::new(3600).unwrap(),
        },
        staging_store: None,
        notes_repo: None,
        signing_key: None,
        run_agent_spawn: None,
        promote_runtime: None,
    })
}

pub(super) fn make_agent_registry_state(server: &MockServer) -> Arc<BrokerState<InMemStore>> {
    make_agent_registry_state_for_agents(server, &[AgentKind::Claude, AgentKind::Codex])
}

pub(super) fn make_agent_registry_state_for_agents(
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
    let minter = GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap());
    Arc::new(BrokerState {
        audit: Arc::new(AuditLog::open_in_memory().unwrap()),
        minter,
        secrets: store,
        policy: PolicyConfig {
            writable_repos: Vec::new(),
            default_ttl: crate::core::TtlSeconds::new(3600).unwrap(),
        },
        staging_store: None,
        notes_repo: None,
        signing_key: None,
        run_agent_spawn: None,
        promote_runtime: None,
    })
}

pub(super) fn repo(owner: &str, name: &str) -> RepoRef {
    RepoRef {
        owner: owner.into(),
        name: name.into(),
    }
}

pub(super) fn expiry_str_from_now(secs: i64) -> String {
    let t = time::OffsetDateTime::now_utc() + time::Duration::seconds(secs);
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// Build a `BrokerState` whose `staging_store` points at a fresh temp
/// directory. Returned alongside the `TempDir` so the caller keeps the
/// staging root alive for the duration of the test.
pub(super) fn make_state_with_staging(
    server: &MockServer,
) -> (Arc<BrokerState<InMemStore>>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let store = GitPushStagingStore::open(tmp.path().join("staging")).unwrap();
    // Installation owner matches `sample_clone_repo()`'s "owner/repo"
    // so the minter's repository-belongs-to-installation check
    // passes when an approve test reaches the mint step. Tests that
    // don't mint are unaffected by the owner string.
    let mut state = make_state(server, vec![], "owner");
    let inner = Arc::get_mut(&mut state).expect("fresh Arc has no other handles");
    inner.staging_store = Some(Arc::new(store));
    (state, tmp)
}

/// `make_state_with_staging` extended with the two extra pieces an
/// approve handler needs to reach its load step: a
/// [`PromoteRuntimeConfig`] (built against a fake git binary path
/// and a per-test work_root under the same tempdir as staging) and
/// a [`WritSigningKey`] (from the shared fixture). The fake git
/// path is deliberately unused in slice B1e.2c — this slice never
/// spawns git, it only proves the configured-state guards admit a
/// well-formed request through to the load. B1e.2d/2e will swap in
/// the system git for the integration tests that actually fetch
/// and unbundle.
pub(super) fn make_state_with_approve_ready(
    server: &MockServer,
) -> (Arc<BrokerState<InMemStore>>, tempfile::TempDir) {
    use crate::git_push_promote::PromoteRuntimeConfig;
    use crate::signing::WritSigningKey;
    use crate::vm_git_bundle::{GitCloneBaseUrl, GitCredentialBoundary, GitSecretEnvVar};
    const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");

    let (mut state, tmp) = make_state_with_staging(server);
    let work_root = tmp.path().join("promote");
    std::fs::create_dir_all(&work_root).unwrap();
    let runtime = PromoteRuntimeConfig::new(
        // Slice B1e.2c never spawns git; the fake path is fine
        // and is replaced by `which git` in the follow-up slices.
        PathBuf::from("/nonexistent/bin/git"),
        GitCloneBaseUrl::github(),
        GitCredentialBoundary::new(
            PathBuf::from("/nonexistent/bin/askpass"),
            GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap(),
        )
        .unwrap(),
        work_root,
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();

    let inner = Arc::get_mut(&mut state).expect("fresh Arc has no other handles");
    inner.promote_runtime = Some(Arc::new(runtime));
    inner.signing_key = Some(signing_key);
    (state, tmp)
}

pub(super) fn sample_clone_repo() -> crate::vm_git::GitCloneRepo {
    "owner/repo".parse().unwrap()
}

pub(super) fn sample_branch() -> crate::vm_git::GitBranchName {
    "feature/x".parse().unwrap()
}

pub(super) fn sample_object_id(nibble: char) -> crate::vm_git::GitObjectId {
    std::iter::repeat_n(nibble, 40)
        .collect::<String>()
        .parse()
        .unwrap()
}

/// Mirror of the same-named helper in `audit::git_push::tests`; the
/// values aren't significant — the tests that consume this just
/// need a `PromoteMintAudit` whose shape passes the DAO's column
/// checks when transitioning an attempt to `Uncertain`.
pub(super) fn sample_promote_mint_audit() -> PromoteMintAudit {
    PromoteMintAudit {
        jti: crate::core::Jti::new(),
        github_app_id: 42,
        issued_at: UnixMillis::from_millis(1_700_000_190),
        expires_at: UnixMillis::from_millis(1_700_000_490),
    }
}

/// Stage a push on disk *and* record the matching audit row plus a
/// `Staged` outcome row so the resolution trigger admits operator
/// decisions against the resulting request id. Returns the request id.
pub(super) async fn stage_with_staged_outcome(
    state: &Arc<BrokerState<InMemStore>>,
    session_id: SessionId,
    bundle: Vec<u8>,
    staged_at: UnixMillis,
    received_at: UnixMillis,
) -> RequestId {
    let request_id = stage_with_audit(state, session_id, bundle, staged_at, received_at).await;
    state
        .audit
        .record_git_push_outcome(&crate::audit::GitPushOutcomeRecord {
            push_request_id: request_id,
            completed_at: received_at,
            result: crate::audit::GitPushOutcomeResult::Staged,
            github_status: None,
            message: "staged for operator review",
        })
        .unwrap();
    request_id
}

/// Stage a push on disk *and* record the matching audit row so the
/// joined Show view has both halves available. Returns the request id.
pub(super) async fn stage_with_audit(
    state: &Arc<BrokerState<InMemStore>>,
    session_id: SessionId,
    bundle: Vec<u8>,
    staged_at: UnixMillis,
    received_at: UnixMillis,
) -> RequestId {
    let request_id = RequestId::new();
    let metadata = crate::vm_git::VmGitPushMetadata::new(
        sample_clone_repo(),
        sample_branch(),
        Some(sample_object_id('a')),
        sample_object_id('b'),
    );
    let staging = state
        .staging_store
        .as_ref()
        .expect("staging configured")
        .clone();
    let bundle_for_stage = bundle.clone();
    tokio::task::spawn_blocking(move || {
        staging
            .stage(request_id, staged_at, metadata, bundle_for_stage)
            .unwrap();
    })
    .await
    .unwrap();
    state
        .audit
        .record_git_push_request(&crate::audit::GitPushRequestRecord {
            push_request_id: request_id,
            session_id,
            received_at,
            repo: sample_clone_repo(),
            branch: sample_branch(),
            expected_remote_head: Some(sample_object_id('a')),
            new_head: sample_object_id('b'),
            correlation_id: None,
        })
        .unwrap();
    request_id
}

pub(super) fn reason(text: &str) -> RejectionReason {
    RejectionReason::try_new(text).expect("test reason fits the bound")
}

/// Stage a push, start an approve attempt, drive it to `Uncertain`,
/// then mark it boot-observed so the row is eligible for manual
/// reconciliation. Returns `(request_id, predecessor_attempt_id)`.
/// Mirrors the `Uncertain` survivor case boot reconcile leaves on
/// disk after a daemon restart.
pub(super) async fn stage_with_boot_observed_uncertain_attempt(
    state: &Arc<BrokerState<InMemStore>>,
    timeline_base_ms: i64,
) -> (RequestId, ApproveAttemptId) {
    let session_id = open_session(state).await;
    let request_id = stage_with_staged_outcome(
        state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(timeline_base_ms),
        UnixMillis::from_millis(timeline_base_ms + 500),
    )
    .await;
    let attempt_id = ApproveAttemptId::new();
    state
        .audit
        .start_approve_attempt(
            attempt_id,
            request_id,
            "alice",
            UnixMillis::from_millis(timeline_base_ms + 1_000),
        )
        .unwrap();
    state
        .audit
        .mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
        .unwrap();
    state
        .audit
        .mark_attempt_boot_observed(
            attempt_id,
            UnixMillis::from_millis(timeline_base_ms + 2_000),
        )
        .unwrap();
    (request_id, attempt_id)
}

/// Stage a push, start an approve attempt, drive it through
/// `Uncertain` to `Resolved(PostPatchFailure)`. The predecessor is
/// terminal and does not require a boot-observed marker —
/// reconciliation is admitted directly.
pub(super) async fn stage_with_post_patch_failure_attempt(
    state: &Arc<BrokerState<InMemStore>>,
    timeline_base_ms: i64,
) -> (RequestId, ApproveAttemptId) {
    let session_id = open_session(state).await;
    let request_id = stage_with_staged_outcome(
        state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(timeline_base_ms),
        UnixMillis::from_millis(timeline_base_ms + 500),
    )
    .await;
    let attempt_id = ApproveAttemptId::new();
    state
        .audit
        .start_approve_attempt(
            attempt_id,
            request_id,
            "alice",
            UnixMillis::from_millis(timeline_base_ms + 1_000),
        )
        .unwrap();
    state
        .audit
        .mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
        .unwrap();
    state
        .audit
        .complete_attempt_post_patch_failure(
            attempt_id,
            "github 502 on update_ref",
            UnixMillis::from_millis(timeline_base_ms + 2_000),
        )
        .unwrap();
    (request_id, attempt_id)
}

pub(super) async fn open_session<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
) -> SessionId {
    open_session_with_agent_kind(state, Some(AgentKind::Claude)).await
}

pub(super) async fn open_session_with_agent_kind<S: SecretStore + Send + Sync + 'static>(
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

/// Wait for the spawned listener to finish binding. A short retry
/// loop beats `sleep(N)` because it succeeds the moment the bind
/// completes (fast path on unloaded CI) and still bounds the total
/// wait so a bug in `run()` surfaces as a test failure rather than
/// a hang.
pub(super) async fn connect_with_retries(sock_path: &Path) -> UnixStream {
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
