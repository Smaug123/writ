//! Daemon-owned agent VM lifecycle orchestration.
//!
//! This module is the bridge between the Unix-socket broker protocol, the
//! managed Apple-container lifecycle runner, and the per-session VM HTTP
//! runtime. It keeps the authority-bearing ordering local: bind the VM HTTP
//! listener, install PF for the selected port through managed start, then
//! spawn the HTTP task only after the VM lifecycle reports success.

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::agent_vm_lifecycle::{
    AgentVmGuestEnvVar, AgentVmLifecycleConfigError, AgentVmResources, AgentVmSessionManagerError,
    AgentVmSessionPlan, AgentVmSessionStateError, AgentVmSessionStateStore, AgentVmToolPaths,
    ContainerImage, Ipv6IsolationMode, cleanup_managed_agent_vm_session,
    remove_managed_agent_vm_session_state, start_managed_agent_vm_session,
};
use crate::audit::AuditError;
use crate::core::{
    AgentNetwork, AgentNetworkPool, AgentVmConfigError, BrokerPorts, SessionId, SessionRecord,
    UnixMillis,
};
use crate::secret::SecretStore;
use crate::server::BrokerState;
use crate::vm_http::{
    RunningVmHttpGitSession, VM_NIX_BASIC_LOGIN, VM_NIX_CACHE_PATH_PREFIX, VmHttpGitRuntimeConfig,
    VmHttpGitRuntimeError, VmHttpGitRuntimeShutdownError, prepare_vm_http_git_session,
};

pub use crate::vm_client::{
    VM_BROKER_TOKEN_ENV as AGENT_VM_BROKER_TOKEN_ENV, VM_BROKER_URL_ENV as AGENT_VM_BROKER_URL_ENV,
};

pub const AGENT_VM_NIX_CACHE_URL_ENV: &str = "WRIT_NIX_CACHE_URL";
pub const AGENT_VM_NIX_BASIC_LOGIN_ENV: &str = "WRIT_NIX_BASIC_LOGIN";
pub const AGENT_VM_NIX_NETRC_ENV: &str = "WRIT_NIX_NETRC";
pub const AGENT_VM_NIX_NETRC_PATH: &str = "/run/writ-agent-vm/netrc";
pub const AGENT_VM_NIX_CONF_DIR_ENV: &str = "NIX_CONF_DIR";
pub const AGENT_VM_NIX_CONF_DIR: &str = "/run/writ-agent-vm/nix-conf";

const AGENT_VM_GUEST_NIX_SETUP_SCRIPT: &str = r#"set -eu
: "${WRIT_BROKER_TOKEN:?}"
: "${WRIT_NIX_CACHE_URL:?}"
: "${WRIT_NIX_BASIC_LOGIN:?}"
: "${WRIT_NIX_NETRC:?}"
: "${NIX_CONF_DIR:?}"

case "$WRIT_NIX_CACHE_URL" in
  http://*|https://*) ;;
  *) echo "WRIT_NIX_CACHE_URL must be http or https" >&2; exit 64 ;;
esac

cache_authority="${WRIT_NIX_CACHE_URL#http://}"
if [ "$cache_authority" = "$WRIT_NIX_CACHE_URL" ]; then
  cache_authority="${WRIT_NIX_CACHE_URL#https://}"
fi
cache_host="${cache_authority%%/*}"
cache_host="${cache_host%%:*}"
if [ -z "$cache_host" ]; then
  echo "WRIT_NIX_CACHE_URL has no host" >&2
  exit 64
fi

mkdir -p /run/writ-agent-vm "$NIX_CONF_DIR"
umask 077
printf 'machine %s login %s password %s\n' \
  "$cache_host" "$WRIT_NIX_BASIC_LOGIN" "$WRIT_BROKER_TOKEN" > "$WRIT_NIX_NETRC"
{
  printf 'experimental-features = nix-command\n'
  printf 'netrc-file = %s\n' "$WRIT_NIX_NETRC"
  printf 'access-tokens =\n'
  printf 'substituters = %s\n' "$WRIT_NIX_CACHE_URL"
  printf 'trusted-public-keys =\n'
} > "$NIX_CONF_DIR/nix.conf"

exec "$@"
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmDaemonRuntimeConfig {
    lifecycle: AgentVmLifecycleRuntimeConfig,
    vm_http: VmHttpGitRuntimeConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmLifecycleRuntimeConfig {
    pool: AgentNetworkPool,
    subnet_index_min: u16,
    subnet_index_max: u16,
    state_store: AgentVmSessionStateStore,
    ipv6_mode: Ipv6IsolationMode,
    image: ContainerImage,
    resources: AgentVmResources,
    tools: AgentVmToolPaths,
}

pub struct AgentVmDaemon {
    config: AgentVmDaemonRuntimeConfig,
    running: Mutex<HashMap<SessionId, RunningVmHttpGitSession>>,
    lifecycle_lock: Mutex<()>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmStarted {
    session_id: SessionId,
    broker_url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentVmDaemonRuntimeConfigError {
    #[error("managed agent VM HTTP bind address must be 0.0.0.0, got {0}")]
    NonWildcardVmHttpBindAddr(Ipv4Addr),
}

#[derive(Debug, thiserror::Error)]
pub enum AgentVmLifecycleRuntimeConfigError {
    #[error("agent VM subnet index range is empty: minimum {min} is greater than maximum {max}")]
    EmptySubnetIndexRange { min: u16, max: u16 },
    #[error(transparent)]
    AgentVm(#[from] AgentVmConfigError),
}

#[derive(Debug, thiserror::Error)]
pub enum AgentVmDaemonError {
    #[error("agent VM guest command must not be empty")]
    EmptyGuestCommand,
    #[error("no available agent VM subnet index in configured range {min}-{max}")]
    NoAvailableSubnet { min: u16, max: u16 },
    #[error("agent VM start for session {session_id} failed: {source}")]
    StartFailed {
        session_id: SessionId,
        #[source]
        source: Box<AgentVmDaemonError>,
    },
    #[error(transparent)]
    AgentVm(#[from] AgentVmConfigError),
    #[error(transparent)]
    LifecycleConfig(#[from] AgentVmLifecycleConfigError),
    #[error(transparent)]
    State(#[from] AgentVmSessionStateError),
    #[error(transparent)]
    VmHttp(#[from] VmHttpGitRuntimeError),
    #[error(transparent)]
    Manager(#[from] AgentVmSessionManagerError),
    #[error("agent VM lifecycle task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("agent VM audit operation failed: {0}")]
    Audit(#[from] AuditError),
    #[error(transparent)]
    HttpShutdown(#[from] VmHttpGitRuntimeShutdownError),
    #[error(
        "agent VM stop failed to close audit session and shut down VM HTTP task: audit: {audit}; http: {http}"
    )]
    StopBothFailed {
        audit: Box<AuditError>,
        http: Box<VmHttpGitRuntimeShutdownError>,
    },
}

impl AgentVmDaemonRuntimeConfig {
    pub fn new(
        lifecycle: AgentVmLifecycleRuntimeConfig,
        vm_http: VmHttpGitRuntimeConfig,
    ) -> Result<Self, AgentVmDaemonRuntimeConfigError> {
        if !vm_http.bind_addr().is_unspecified() {
            return Err(AgentVmDaemonRuntimeConfigError::NonWildcardVmHttpBindAddr(
                vm_http.bind_addr(),
            ));
        }
        Ok(Self { lifecycle, vm_http })
    }

    pub fn lifecycle(&self) -> &AgentVmLifecycleRuntimeConfig {
        &self.lifecycle
    }

    pub fn vm_http(&self) -> &VmHttpGitRuntimeConfig {
        &self.vm_http
    }
}

impl AgentVmLifecycleRuntimeConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: AgentNetworkPool,
        subnet_index_min: u16,
        subnet_index_max: u16,
        state_store: AgentVmSessionStateStore,
        ipv6_mode: Ipv6IsolationMode,
        image: ContainerImage,
        resources: AgentVmResources,
        tools: AgentVmToolPaths,
    ) -> Result<Self, AgentVmLifecycleRuntimeConfigError> {
        if subnet_index_min > subnet_index_max {
            return Err(AgentVmLifecycleRuntimeConfigError::EmptySubnetIndexRange {
                min: subnet_index_min,
                max: subnet_index_max,
            });
        }
        pool.allocate(subnet_index_min)?;
        pool.allocate(subnet_index_max)?;
        Ok(Self {
            pool,
            subnet_index_min,
            subnet_index_max,
            state_store,
            ipv6_mode,
            image,
            resources,
            tools,
        })
    }

    pub fn pool(&self) -> AgentNetworkPool {
        self.pool
    }

    pub fn subnet_index_min(&self) -> u16 {
        self.subnet_index_min
    }

    pub fn subnet_index_max(&self) -> u16 {
        self.subnet_index_max
    }

    pub fn state_store(&self) -> &AgentVmSessionStateStore {
        &self.state_store
    }
}

impl AgentVmDaemon {
    pub fn new(config: AgentVmDaemonRuntimeConfig) -> Self {
        Self {
            config,
            running: Mutex::new(HashMap::new()),
            lifecycle_lock: Mutex::new(()),
        }
    }

    pub fn config(&self) -> &AgentVmDaemonRuntimeConfig {
        &self.config
    }

    pub async fn start_session<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        label: Option<String>,
        agent_model: Option<String>,
        guest_command: Vec<String>,
    ) -> Result<AgentVmStarted, AgentVmDaemonError> {
        // The lower lifecycle layer keeps dual-stack manual starts compatible
        // with image defaults. The daemon API is stricter: the host protocol
        // should say exactly what the authority-bearing guest will execute.
        if guest_command.is_empty() {
            return Err(AgentVmDaemonError::EmptyGuestCommand);
        }

        let _guard = self.lifecycle_lock.lock().await;
        let session_id = SessionId::new();
        state.audit.open_session(&SessionRecord {
            session_id,
            label,
            agent_model,
            opened_at: UnixMillis::now(),
            closed_at: None,
        })?;

        match self
            .start_session_after_audit_opened(Arc::clone(&state), session_id, guest_command)
            .await
        {
            Ok(started) => Ok(started),
            Err(err) => {
                close_audit_session_best_effort(&state, session_id);
                Err(AgentVmDaemonError::StartFailed {
                    session_id,
                    source: Box::new(err),
                })
            }
        }
    }

    pub async fn stop_session<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: &Arc<BrokerState<S>>,
        session_id: SessionId,
    ) -> Result<(), AgentVmDaemonError> {
        let _guard = self.lifecycle_lock.lock().await;

        let store = self.config.lifecycle.state_store.clone();
        let tools = self.config.lifecycle.tools.clone();
        tokio::task::spawn_blocking(move || {
            cleanup_managed_agent_vm_session(&store, session_id, tools)
        })
        .await??;

        let audit_close = state.audit.close_session(session_id, UnixMillis::now());
        let http_shutdown = match self.running.lock().await.remove(&session_id) {
            Some(running) => running.shutdown().await,
            None => Ok(()),
        };

        match (audit_close, http_shutdown) {
            (Ok(()), Ok(())) => {
                let store = self.config.lifecycle.state_store.clone();
                tokio::task::spawn_blocking(move || {
                    remove_managed_agent_vm_session_state(&store, session_id)
                })
                .await??;
                Ok(())
            }
            (Err(audit), Ok(())) => Err(AgentVmDaemonError::Audit(audit)),
            (Ok(()), Err(http)) => Err(AgentVmDaemonError::HttpShutdown(http)),
            (Err(audit), Err(http)) => Err(AgentVmDaemonError::StopBothFailed {
                audit: Box::new(audit),
                http: Box::new(http),
            }),
        }
    }

    async fn start_session_after_audit_opened<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        session_id: SessionId,
        guest_command: Vec<String>,
    ) -> Result<AgentVmStarted, AgentVmDaemonError> {
        let lifecycle = self.config.lifecycle.clone();
        let (subnet_index, network) =
            tokio::task::spawn_blocking(move || choose_subnet_index(&lifecycle)).await??;
        let prepared = prepare_vm_http_git_session(
            Arc::clone(&state),
            &self.config.vm_http,
            session_id,
            network.ipv4(),
        )
        .await?;
        let broker_port = prepared.broker_port();
        let broker_url = format!("http://{}:{}/", network.ipv4_gateway(), broker_port.get());
        let nix_cache_url = nix_cache_url_for_broker_url(&broker_url);
        let broker_ports = BrokerPorts::new([broker_port])?;
        let guest_env = vec![
            AgentVmGuestEnvVar::new(AGENT_VM_BROKER_URL_ENV, broker_url.clone())?,
            AgentVmGuestEnvVar::new(
                AGENT_VM_BROKER_TOKEN_ENV,
                prepared.bearer_token().as_str().to_string(),
            )?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_CACHE_URL_ENV, nix_cache_url)?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_BASIC_LOGIN_ENV, VM_NIX_BASIC_LOGIN)?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_NETRC_ENV, AGENT_VM_NIX_NETRC_PATH)?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_CONF_DIR_ENV, AGENT_VM_NIX_CONF_DIR)?,
        ];
        let guest_command = wrap_guest_command_with_nix_setup(guest_command);
        let plan = AgentVmSessionPlan::new_with_guest_env(
            session_id,
            self.config.lifecycle.pool,
            subnet_index,
            broker_ports,
            self.config.vm_http.broker_port_range(),
            self.config.lifecycle.ipv6_mode,
            self.config.lifecycle.image.clone(),
            guest_env,
            guest_command,
            self.config.lifecycle.resources,
            self.config.lifecycle.tools.clone(),
        )?;

        let store = self.config.lifecycle.state_store.clone();
        let plan_for_start = plan.clone();
        tokio::task::spawn_blocking(move || {
            start_managed_agent_vm_session(&store, &plan_for_start)
        })
        .await??;

        let running = prepared.spawn();
        self.running.lock().await.insert(session_id, running);
        Ok(AgentVmStarted {
            session_id,
            broker_url,
        })
    }

    #[cfg(test)]
    fn choose_subnet_index(&self) -> Result<(u16, AgentNetwork), AgentVmDaemonError> {
        choose_subnet_index(&self.config.lifecycle)
    }
}

fn choose_subnet_index(
    lifecycle: &AgentVmLifecycleRuntimeConfig,
) -> Result<(u16, AgentNetwork), AgentVmDaemonError> {
    let used = lifecycle
        .state_store
        .load_all()?
        .into_iter()
        .map(|state| state.subnet_index())
        .collect::<BTreeSet<_>>();
    for index in lifecycle.subnet_index_min..=lifecycle.subnet_index_max {
        if !used.contains(&index) {
            let network = lifecycle.pool.allocate(index)?;
            return Ok((index, network));
        }
    }
    Err(AgentVmDaemonError::NoAvailableSubnet {
        min: lifecycle.subnet_index_min,
        max: lifecycle.subnet_index_max,
    })
}

fn nix_cache_url_for_broker_url(broker_url: &str) -> String {
    format!(
        "{}{}",
        broker_url.trim_end_matches('/'),
        VM_NIX_CACHE_PATH_PREFIX
    )
}

fn wrap_guest_command_with_nix_setup(guest_command: Vec<String>) -> Vec<String> {
    let mut wrapped = vec![
        "sh".to_string(),
        "-c".to_string(),
        AGENT_VM_GUEST_NIX_SETUP_SCRIPT.to_string(),
        "writ-agent-vm-nix-setup".to_string(),
    ];
    wrapped.extend(guest_command);
    wrapped
}

impl AgentVmStarted {
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn broker_url(&self) -> &str {
        &self.broker_url
    }
}

fn close_audit_session_best_effort<S: SecretStore + Send + Sync>(
    state: &BrokerState<S>,
    session_id: SessionId,
) {
    if let Err(err) = state.audit.close_session(session_id, UnixMillis::now()) {
        eprintln!("agent VM start cleanup could not close audit session {session_id}: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex as StdMutex;

    use crate::audit::AuditLog;
    use proptest::prelude::*;

    use crate::core::{
        BrokerPort, BrokerPortRange, BrokerPorts, Ipv4Cidr, Ipv6Cidr, RepoRef, TtlSeconds,
    };
    use crate::github::{GitHubAppConfig, GitHubMinter};
    use crate::policy::PolicyConfig;
    use crate::secret::{SecretError, SecretKey};
    use crate::vm_git_bundle::{GitCredentialBoundary, GitSecretEnvVar};
    use crate::vm_http::VmHttpGitCloneConfig;

    #[derive(Default)]
    struct InMemStore(StdMutex<std::collections::HashMap<String, String>>);

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

    fn make_state() -> Arc<BrokerState<InMemStore>> {
        make_state_with_audit(AuditLog::open_in_memory().unwrap())
    }

    fn make_state_with_audit(audit: AuditLog) -> Arc<BrokerState<InMemStore>> {
        let key = SecretKey::new("gh-app-pk").unwrap();
        Arc::new(BrokerState {
            audit,
            minter: GitHubMinter::new(
                GitHubAppConfig {
                    app_id: 42,
                    installation_id: 999,
                    installation_owner: "o".into(),
                    private_key_secret: key,
                    api_base: "http://127.0.0.1".into(),
                },
                InMemStore::default(),
            ),
            policy: PolicyConfig {
                writable_repos: Vec::<RepoRef>::new(),
                default_ttl: TtlSeconds::new(3600).unwrap(),
            },
        })
    }

    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }

    fn write_fake_tool(
        dir: &Path,
        args_log: &Path,
        env_path_log: &Path,
        env_log: &Path,
    ) -> PathBuf {
        let path = dir.join("fake-tool");
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"inspect\" ]; then\n\
             printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
             fi\n\
             if [ \"$1\" = \"run\" ]; then\n\
             while [ \"$#\" -gt 0 ]; do\n\
             if [ \"$1\" = \"--env-file\" ]; then\n\
             printf '%s\\n' \"$2\" > {env_path_log}\n\
             cat \"$2\" > {env_log}\n\
             fi\n\
             shift\n\
             done\n\
             fi\n\
             exit 0\n",
            args_log = shell_quote(args_log),
            env_path_log = shell_quote(env_path_log),
            env_log = shell_quote(env_log),
        );
        fs::write(&path, script).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn write_fake_network_create_failure_tool(dir: &Path, args_log: &Path) -> PathBuf {
        let path = dir.join("fake-failing-tool");
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> {args_log}\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"create\" ]; then\n\
             exit 42\n\
             fi\n\
             exit 0\n",
            args_log = shell_quote(args_log),
        );
        fs::write(&path, script).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn agent_vm_pool() -> AgentNetworkPool {
        AgentNetworkPool::new(
            Ipv4Cidr::new("192.168.0.0".parse().unwrap(), 16).unwrap(),
            Ipv6Cidr::new("fd83:b6f2:e57::".parse().unwrap(), 48).unwrap(),
        )
        .unwrap()
    }

    fn daemon_config(
        dir: &Path,
        fake_tool: &Path,
    ) -> (AgentVmDaemonRuntimeConfig, AgentVmSessionStateStore) {
        daemon_config_with_subnet_range(dir, fake_tool, 252, 253)
    }

    fn daemon_config_with_subnet_range(
        dir: &Path,
        fake_tool: &Path,
        subnet_index_min: u16,
        subnet_index_max: u16,
    ) -> (AgentVmDaemonRuntimeConfig, AgentVmSessionStateStore) {
        let state_store = AgentVmSessionStateStore::new(dir.join("state"));
        let lifecycle = AgentVmLifecycleRuntimeConfig::new(
            agent_vm_pool(),
            subnet_index_min,
            subnet_index_max,
            state_store.clone(),
            Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
            ContainerImage::new("alpine:latest").unwrap(),
            AgentVmResources::new(1, 512).unwrap(),
            AgentVmToolPaths::new(fake_tool, fake_tool, fake_tool),
        )
        .unwrap();
        let credential =
            GitCredentialBoundary::new(fake_tool, GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap())
                .unwrap();
        let git_clone = VmHttpGitCloneConfig::new(
            fake_tool,
            credential,
            dir.join("git-work"),
            std::time::Duration::from_secs(1),
            1024 * 1024,
        )
        .unwrap();
        (
            AgentVmDaemonRuntimeConfig::new(
                lifecycle,
                VmHttpGitRuntimeConfig::new(
                    "0.0.0.0".parse().unwrap(),
                    BrokerPortRange::new(1024, 65535).unwrap(),
                    git_clone,
                ),
            )
            .unwrap(),
            state_store,
        )
    }

    fn occupy_subnet(store: &AgentVmSessionStateStore, index: u16) {
        let plan = AgentVmSessionPlan::new(
            SessionId::from_uuid(uuid::Uuid::from_u128(0x1000 + u128::from(index))),
            agent_vm_pool(),
            index,
            BrokerPorts::new([BrokerPort::new(51375).unwrap()]).unwrap(),
            BrokerPortRange::new(1024, 65535).unwrap(),
            Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
            ContainerImage::new("alpine:latest").unwrap(),
            vec!["sleep".into(), "600".into()],
            AgentVmResources::new(1, 512).unwrap(),
            AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo"),
        )
        .unwrap();
        store.create_starting(&plan).unwrap();
    }

    #[tokio::test]
    async fn daemon_start_injects_vm_http_env_without_persisting_token_and_stop_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let env_path_log = dir.path().join("env-path.log");
        let env_log = dir.path().join("env.log");
        let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
        let (config, state_store) = daemon_config(dir.path(), &fake_tool);
        let daemon = AgentVmDaemon::new(config);
        let state = make_state();

        let started = daemon
            .start_session(
                Arc::clone(&state),
                Some("agent vm".into()),
                Some("gpt-test".into()),
                vec!["sleep".into(), "600".into()],
            )
            .await
            .unwrap();

        assert!(started.broker_url().starts_with("http://192.168.252.1:"));
        let audit_session = state
            .audit
            .get_session(started.session_id())
            .unwrap()
            .unwrap();
        assert_eq!(audit_session.label.as_deref(), Some("agent vm"));
        assert!(audit_session.closed_at.is_none());

        let env = fs::read_to_string(&env_log).unwrap();
        assert!(env.contains(&format!(
            "{AGENT_VM_BROKER_URL_ENV}={}",
            started.broker_url()
        )));
        assert!(env.contains(&format!("{AGENT_VM_BROKER_TOKEN_ENV}=writ-vm-")));
        assert!(env.contains(&format!(
            "{AGENT_VM_NIX_CACHE_URL_ENV}={}",
            nix_cache_url_for_broker_url(started.broker_url())
        )));
        assert!(env.contains(&format!(
            "{AGENT_VM_NIX_BASIC_LOGIN_ENV}={VM_NIX_BASIC_LOGIN}"
        )));
        assert!(env.contains(&format!(
            "{AGENT_VM_NIX_NETRC_ENV}={AGENT_VM_NIX_NETRC_PATH}"
        )));
        assert!(env.contains(&format!(
            "{AGENT_VM_NIX_CONF_DIR_ENV}={AGENT_VM_NIX_CONF_DIR}"
        )));
        let args = fs::read_to_string(&args_log).unwrap();
        assert!(args.contains("--env-file"));
        assert!(args.contains("writ-agent-vm-nix-setup"));
        assert!(!args.contains("writ-vm-"), "{args}");
        let state_json = fs::read_to_string(
            dir.path()
                .join("state")
                .join(format!("{}.json", started.session_id())),
        )
        .unwrap();
        assert!(!state_json.contains("writ-vm-"), "{state_json}");
        let env_path = fs::read_to_string(&env_path_log).unwrap();
        assert!(
            !Path::new(env_path.trim()).exists(),
            "guest env file should be removed after container run"
        );

        daemon
            .stop_session(&state, started.session_id())
            .await
            .unwrap();
        assert!(state_store.load(started.session_id()).is_err());
        let audit_session = state
            .audit
            .get_session(started.session_id())
            .unwrap()
            .unwrap();
        assert!(audit_session.closed_at.is_some());
    }

    #[tokio::test]
    async fn daemon_stop_does_not_close_audit_session_when_vm_state_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let env_path_log = dir.path().join("env-path.log");
        let env_log = dir.path().join("env.log");
        let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
        let (config, _state_store) = daemon_config(dir.path(), &fake_tool);
        let daemon = AgentVmDaemon::new(config);
        let state = make_state();
        let session_id = SessionId::new();
        state
            .audit
            .open_session(&SessionRecord {
                session_id,
                label: Some("ordinary broker session".into()),
                agent_model: None,
                opened_at: UnixMillis::now(),
                closed_at: None,
            })
            .unwrap();

        let err = daemon.stop_session(&state, session_id).await.unwrap_err();

        assert!(matches!(
            err,
            AgentVmDaemonError::Manager(AgentVmSessionManagerError::State(
                AgentVmSessionStateError::NotFound { .. }
            ))
        ));
        let audit_session = state.audit.get_session(session_id).unwrap().unwrap();
        assert!(audit_session.closed_at.is_none());
    }

    #[tokio::test]
    async fn daemon_start_failure_after_audit_open_closes_audit_session() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let env_path_log = dir.path().join("env-path.log");
        let env_log = dir.path().join("env.log");
        let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
        let (config, state_store) = daemon_config(dir.path(), &fake_tool);
        occupy_subnet(&state_store, 252);
        occupy_subnet(&state_store, 253);
        let daemon = AgentVmDaemon::new(config);
        let audit_db = dir.path().join("audit.db");
        let state = make_state_with_audit(AuditLog::open(&audit_db).unwrap());

        let err = daemon
            .start_session(
                Arc::clone(&state),
                Some("subnet pool exhausted".into()),
                None,
                vec!["sleep".into(), "600".into()],
            )
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            AgentVmDaemonError::StartFailed {
                session_id: _,
                source
            } if matches!(*source, AgentVmDaemonError::NoAvailableSubnet { min: 252, max: 253 })
        ));
        let conn = rusqlite::Connection::open(audit_db).unwrap();
        let (rows, closed): (i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(CASE WHEN closed_at IS NOT NULL THEN 1 ELSE 0 END), 0) \
                 FROM session WHERE label = 'subnet pool exhausted'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((rows, closed), (1, 1));
    }

    #[tokio::test]
    async fn daemon_start_failure_after_vm_http_prepare_does_not_register_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let fake_tool = write_fake_network_create_failure_tool(dir.path(), &args_log);
        let (config, state_store) = daemon_config(dir.path(), &fake_tool);
        let daemon = AgentVmDaemon::new(config);
        let state = make_state();

        let err = daemon
            .start_session(
                Arc::clone(&state),
                Some("container network create fails".into()),
                None,
                vec!["sleep".into(), "600".into()],
            )
            .await
            .unwrap_err();

        let session_id = match err {
            AgentVmDaemonError::StartFailed { session_id, source } => {
                assert!(matches!(*source, AgentVmDaemonError::Manager(_)));
                session_id
            }
            other => panic!("unexpected start error: {other:?}"),
        };
        assert!(daemon.running.lock().await.is_empty());
        assert!(state_store.load(session_id).is_err());
        let audit_session = state.audit.get_session(session_id).unwrap().unwrap();
        assert!(audit_session.closed_at.is_some());
    }

    #[test]
    fn nix_cache_url_is_the_broker_url_under_the_cache_route() {
        assert_eq!(
            nix_cache_url_for_broker_url("http://192.168.252.1:51375/"),
            "http://192.168.252.1:51375/v1/nix/cache"
        );
        assert_eq!(
            nix_cache_url_for_broker_url("http://192.168.252.1:51375"),
            "http://192.168.252.1:51375/v1/nix/cache"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn nix_setup_wrapper_preserves_guest_command_argv(
            guest_command in prop::collection::vec(any::<String>(), 1..16),
        ) {
            let wrapped = wrap_guest_command_with_nix_setup(guest_command.clone());
            prop_assert_eq!(&wrapped[..4], &[
                "sh".to_string(),
                "-c".to_string(),
                AGENT_VM_GUEST_NIX_SETUP_SCRIPT.to_string(),
                "writ-agent-vm-nix-setup".to_string(),
            ]);
            prop_assert_eq!(&wrapped[4..], guest_command.as_slice());
            prop_assert!(!wrapped.join("\n").contains("writ-vm-"));
        }

        #[test]
        fn choose_subnet_index_returns_first_unused_or_reports_full(
            min in 0u16..=250,
            occupied in prop::collection::vec(any::<bool>(), 1..=6),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let args_log = dir.path().join("args.log");
            let env_path_log = dir.path().join("env-path.log");
            let env_log = dir.path().join("env.log");
            let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
            let max = min + occupied.len() as u16 - 1;
            let (config, state_store) =
                daemon_config_with_subnet_range(dir.path(), &fake_tool, min, max);
            for (offset, is_occupied) in occupied.iter().copied().enumerate() {
                if is_occupied {
                    occupy_subnet(&state_store, min + offset as u16);
                }
            }
            let daemon = AgentVmDaemon::new(config);
            let expected = occupied
                .iter()
                .position(|is_occupied| !*is_occupied)
                .map(|offset| min + offset as u16);

            match expected {
                Some(index) => prop_assert_eq!(daemon.choose_subnet_index().unwrap().0, index),
                None => match daemon.choose_subnet_index() {
                    Err(AgentVmDaemonError::NoAvailableSubnet { min: err_min, max: err_max }) => {
                        prop_assert_eq!(err_min, min);
                        prop_assert_eq!(err_max, max);
                    }
                    other => prop_assert!(false, "unexpected subnet selection result: {other:?}"),
                },
            }
        }
    }
}
