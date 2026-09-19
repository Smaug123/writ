use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use crate::audit::AuditLog;
use crate::config::AgentRunLogRoot;
use crate::core::{AgentKind, RepoRef, TtlSeconds};
use crate::github::{GitHubAppConfig, GitHubAppRegistryConfig, GitHubMinter};
use crate::policy::PolicyConfig;
use crate::secret::{SecretKey, SecretStore};
use crate::server::{
    BrokerState, RunAgentSpawnConfig, prepare_broker_listener, serve_broker_with_agent_vm,
};
use crate::vm_git_mirror_cache::MirrorPins;

use super::{InMemorySecretStore, RSA_TEST_1_PEM, required_tool};

/// The secret-store key every test registry stores its GitHub App key under.
pub const GITHUB_APP_SECRET: &str = "gh-app-pk";

/// One GitHub App for `agent` (app 42, installation 999) whose private key is
/// [`RSA_TEST_1_PEM`] under [`GITHUB_APP_SECRET`] in `secrets`, minting
/// against `api_base` (a wiremock server, normally) for repositories owned
/// by `installation_owner`.
pub fn github_app(
    secrets: &InMemorySecretStore,
    agent: AgentKind,
    api_base: &str,
    installation_owner: &str,
) -> BTreeMap<AgentKind, GitHubAppConfig> {
    let pk = SecretKey::new(GITHUB_APP_SECRET).unwrap();
    secrets.put(&pk, RSA_TEST_1_PEM).unwrap();
    let mut apps = BTreeMap::new();
    apps.insert(
        agent,
        GitHubAppConfig {
            app_id: 42,
            installation_id: 999,
            installation_owner: installation_owner.into(),
            private_key_secret: pk,
            api_base: api_base.into(),
        },
    );
    apps
}

/// A [`BrokerState`] with every optional subsystem off: an in-memory audit
/// log, the given registry and secrets, an empty write allowlist with a one
/// hour default TTL, and no staging, notes repo, signing key, run-agent spawn
/// or promote runtime. Tests set the fields they need and wrap it in an `Arc`.
pub fn broker_state<S: SecretStore>(
    secrets: S,
    apps: BTreeMap<AgentKind, GitHubAppConfig>,
) -> BrokerState<S> {
    BrokerState {
        audit: Arc::new(AuditLog::open_in_memory().unwrap()),
        minter: GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap()),
        secrets,
        policy: PolicyConfig {
            writable_repos: Vec::<RepoRef>::new(),
            default_ttl: TtlSeconds::new(3600).unwrap(),
        },
        staging_store: None,
        notes_repo: None,
        signing_key: None,
        run_agent_spawn: None,
        agent_run_slots: Default::default(),
        promote_runtime: None,
        git_data_http: std::sync::OnceLock::new(),
        mirror_pins: MirrorPins::new(),
        chatgpt_oauth_authority: Default::default(),
    }
}

/// [`broker_state`] with the usual single Claude App ([`github_app`]) in a
/// fresh in-memory store: the state most tests start from.
pub fn claude_broker_state(
    api_base: &str,
    installation_owner: &str,
) -> BrokerState<InMemorySecretStore> {
    let secrets = InMemorySecretStore::default();
    let apps = github_app(&secrets, AgentKind::Claude, api_base, installation_owner);
    broker_state(secrets, apps)
}

/// A host-spawn [`RunAgentSpawnConfig`] whose agent is `cat` (echoes its
/// prompt as its output) and whose stream logs land under
/// `tmp/agent-runs`. The directory is deliberately not created: the host arm
/// creates run directories itself, and a test that finds streams there has
/// also shown that.
pub fn cat_run_agent_spawn(tmp: &Path) -> RunAgentSpawnConfig {
    RunAgentSpawnConfig {
        command: required_tool("cat"),
        args: Vec::new(),
        agent_kind: AgentKind::Claude,
        log_root: AgentRunLogRoot::check(tmp.join("agent-runs"))
            .expect("a tempdir-rooted log path is absolute"),
        timeout: None,
    }
}

/// A broker serving `state` on a Unix socket for the life of the value.
///
/// The socket lives in its own `0700` tempdir (`prepare_broker_listener`
/// refuses a group- or world-accessible directory) that is removed when this
/// is dropped; the accept loop is aborted then too.
pub struct SpawnedBroker {
    pub socket_path: std::path::PathBuf,
    task: tokio::task::JoinHandle<()>,
    _socket_dir: tempfile::TempDir,
}

impl SpawnedBroker {
    /// Serve `state` with no daemon-managed agent VM, as every host-spawn
    /// production path does.
    pub async fn start<S: SecretStore + Send + Sync + 'static>(state: Arc<BrokerState<S>>) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let socket_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let socket_path = socket_dir.path().join("writ.sock");
        let listener = prepare_broker_listener(&socket_path).await.unwrap();
        let task = tokio::spawn(async move {
            let _ = serve_broker_with_agent_vm(listener, state, None).await;
        });
        Self {
            socket_path,
            task,
            _socket_dir: socket_dir,
        }
    }

    /// Stop the accept loop and wait for it to go.
    pub async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for SpawnedBroker {
    fn drop(&mut self) {
        self.task.abort();
    }
}
