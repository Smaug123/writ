//! Daemon-owned agent VM lifecycle orchestration.
//!
//! This module is the bridge between the Unix-socket broker protocol, the
//! managed Apple-container lifecycle runner, and the per-session VM HTTP
//! runtime. It keeps the authority-bearing ordering local: bind the VM HTTP
//! listener, install PF for the selected port through managed start, then
//! spawn the HTTP task only after the VM lifecycle reports success.

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::agent_run::{AgentPrompt, AgentRunId};
use crate::agent_vm_lifecycle::{
    AgentVmGuestEnvVar, AgentVmLifecycleConfigError, AgentVmResources, AgentVmSessionManagerError,
    AgentVmSessionPlan, AgentVmSessionStateError, AgentVmSessionStateStore, AgentVmToolPaths,
    ContainerImage, Ipv6IsolationMode, cleanup_managed_agent_vm_session,
    remove_managed_agent_vm_session_state, start_managed_agent_vm_session,
};
use crate::audit::{AgentRunAuditRecord, AgentVmWorkspaceBootstrapAuditRecord, AuditError};
use crate::core::{
    AgentKind, AgentNetwork, AgentNetworkPool, AgentVmConfigError, BrokerPorts, SessionId,
    SessionRecord, UnixMillis,
};
use crate::process_spawn;
use crate::protocol::AgentVmSessionInfo;
use crate::secret::SecretStore;
use crate::server::BrokerState;
use crate::vm_git::{
    AgentVmWorkspaceBootstrap, DEFAULT_DEVSHELL_ATTR, DEFAULT_WORKSPACE_BRANCH, WorkspaceWarmMode,
    default_workspace_destination, nix_develop_command_args,
};
use crate::vm_http::{
    RunningVmHttpSession, VM_NIX_BASIC_LOGIN, VM_NIX_CACHE_PATH_PREFIX, VmHttpAgentRunService,
    VmHttpRuntimeConfig, VmHttpRuntimeError, VmHttpRuntimeShutdownError,
    prepare_vm_http_session_with_agent_runs,
};

pub use crate::vm_client::{
    VM_BROKER_TOKEN_ENV as AGENT_VM_BROKER_TOKEN_ENV, VM_BROKER_URL_ENV as AGENT_VM_BROKER_URL_ENV,
};

pub const AGENT_VM_NIX_CACHE_URL_ENV: &str = "WRIT_NIX_CACHE_URL";
pub const AGENT_VM_NIX_BASIC_LOGIN_ENV: &str = "WRIT_NIX_BASIC_LOGIN";
pub const AGENT_VM_NIX_NETRC_ENV: &str = "WRIT_NIX_NETRC";
pub const AGENT_VM_NIX_NETRC_PATH: &str = "/run/writ-agent-vm/netrc";
pub const AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV: &str = "WRIT_NIX_TRUSTED_PUBLIC_KEYS";
pub const AGENT_VM_NIX_CONF_DIR_ENV: &str = "NIX_CONF_DIR";
pub const AGENT_VM_NIX_CONF_DIR: &str = "/run/writ-agent-vm/nix-conf";
const AGENT_VM_WORKSPACE_BROKER_READY_PATH: &str = "/run/writ-agent-vm/broker-ready";
const AGENT_VM_WORKSPACE_BOOTSTRAP_OK_PATH: &str = "/run/writ-agent-vm/bootstrap-ok";
const AGENT_VM_WORKSPACE_BOOTSTRAP_FAILED_PATH: &str = "/run/writ-agent-vm/bootstrap-failed";
const AGENT_VM_WORKSPACE_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLL_INTERVAL: Duration = Duration::from_millis(500);
const AGENT_VM_WORKSPACE_BOOTSTRAP_SLOW_POLL_INTERVAL: Duration = Duration::from_secs(2);
const AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLLS: u32 = 10;
const AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT: usize = 16 * 1024;

const AGENT_VM_GUEST_NIX_SETUP_SCRIPT: &str = r#"set -eu
: "${WRIT_BROKER_TOKEN:?}"
: "${WRIT_NIX_CACHE_URL:?}"
: "${WRIT_NIX_BASIC_LOGIN:?}"
: "${WRIT_NIX_NETRC:?}"
: "${WRIT_NIX_TRUSTED_PUBLIC_KEYS:=}"
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

netrc_dir="${WRIT_NIX_NETRC%/*}"
if [ "$netrc_dir" = "$WRIT_NIX_NETRC" ]; then
  netrc_dir=.
fi
mkdir -p "$netrc_dir" "$NIX_CONF_DIR"
umask 077
printf 'machine %s login %s password %s\n' \
  "$cache_host" "$WRIT_NIX_BASIC_LOGIN" "$WRIT_BROKER_TOKEN" > "$WRIT_NIX_NETRC"
{
  printf 'experimental-features = nix-command\n'
  printf 'netrc-file = %s\n' "$WRIT_NIX_NETRC"
  printf 'access-tokens =\n'
  printf 'substituters = %s\n' "$WRIT_NIX_CACHE_URL"
  if [ -n "$WRIT_NIX_TRUSTED_PUBLIC_KEYS" ]; then
    printf 'trusted-public-keys = %s\n' "$WRIT_NIX_TRUSTED_PUBLIC_KEYS"
  else
    printf 'trusted-public-keys =\n'
  fi
} > "$NIX_CONF_DIR/nix.conf"

exec "$@"
"#;

const AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT: &str = r#"set -eu
: "${WRIT_BROKER_TOKEN:?}"
: "${WRIT_NIX_CACHE_URL:?}"
: "${WRIT_NIX_BASIC_LOGIN:?}"
: "${WRIT_NIX_NETRC:?}"
: "${WRIT_NIX_TRUSTED_PUBLIC_KEYS:=}"
: "${NIX_CONF_DIR:?}"

repo="$1"
destination="$2"
warm="$3"
shift 3

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

netrc_dir="${WRIT_NIX_NETRC%/*}"
if [ "$netrc_dir" = "$WRIT_NIX_NETRC" ]; then
  netrc_dir=.
fi
mkdir -p "$netrc_dir" "$NIX_CONF_DIR" /run/writ-agent-vm
umask 077
printf 'machine %s login %s password %s\n' \
  "$cache_host" "$WRIT_NIX_BASIC_LOGIN" "$WRIT_BROKER_TOKEN" > "$WRIT_NIX_NETRC"
{
  printf 'experimental-features = nix-command flakes\n'
  printf 'netrc-file = %s\n' "$WRIT_NIX_NETRC"
  printf 'access-tokens =\n'
  printf 'substituters = %s\n' "$WRIT_NIX_CACHE_URL"
  if [ -n "$WRIT_NIX_TRUSTED_PUBLIC_KEYS" ]; then
    printf 'trusted-public-keys = %s\n' "$WRIT_NIX_TRUSTED_PUBLIC_KEYS"
  else
    printf 'trusted-public-keys =\n'
  fi
} > "$NIX_CONF_DIR/nix.conf"

while [ ! -f /run/writ-agent-vm/broker-ready ]; do
  sleep 0.2
done

set +e
writ-vm workspace init "$repo" "$destination" --warm "$warm" \
  > /run/writ-agent-vm/bootstrap.stdout \
  2> /run/writ-agent-vm/bootstrap.stderr
code=$?
set -e
if [ "$code" -ne 0 ]; then
  set +e
  {
    printf 'writ-vm workspace init failed with exit %s\n' "$code"
    if [ -s /run/writ-agent-vm/bootstrap.stderr ]; then
      printf '%s\n' 'stderr:'
      cat /run/writ-agent-vm/bootstrap.stderr
    fi
  } > /run/writ-agent-vm/bootstrap-failed
  set -e
  # Stay alive so the daemon can inspect bootstrap-failed before the lifecycle
  # cleanup path tears the VM down. Exiting here races the daemon's poller.
  while :; do sleep 3600; done
fi

rm -f /run/writ-agent-vm/bootstrap.stdout /run/writ-agent-vm/bootstrap.stderr
if ! cd "$destination"; then
  set +e
  printf 'workspace destination disappeared before agent exec: %s\n' "$destination" \
    > /run/writ-agent-vm/bootstrap-failed
  set -e
  while :; do sleep 3600; done
fi
touch /run/writ-agent-vm/bootstrap-ok
# Run the agent as a child rather than exec-ing it, so the container outlives
# the agent. Otherwise an agent that finishes (or crashes) within the
# daemon's poll interval can race the bootstrap-ok signal: the next poll
# would see a dying container instead of the ok file. The daemon owns
# teardown via the stop API.
set +e
"$@" > /run/writ-agent-vm/agent.stdout 2> /run/writ-agent-vm/agent.stderr
agent_code=$?
set -e
printf '%s\n' "$agent_code" > /run/writ-agent-vm/agent.exit
while :; do sleep 3600; done
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmDaemonRuntimeConfig {
    lifecycle: AgentVmLifecycleRuntimeConfig,
    vm_http: VmHttpRuntimeConfig,
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
    running: Mutex<HashMap<SessionId, RunningVmHttpSession>>,
    lifecycle_lock: Mutex<()>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmStarted {
    session_id: SessionId,
    broker_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRunStarted {
    session_id: SessionId,
    run_id: AgentRunId,
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
    #[error("agent VM workspace destination must be absolute: {0}")]
    RelativeWorkspaceDestination(PathBuf),
    #[error("agent VM workspace destination must be valid UTF-8: {0}")]
    NonUtf8WorkspaceDestination(PathBuf),
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
    VmHttp(#[from] VmHttpRuntimeError),
    #[error(transparent)]
    Manager(#[from] AgentVmSessionManagerError),
    #[error("agent VM lifecycle task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("agent VM workspace bootstrap {step} command could not be spawned: {source}")]
    WorkspaceBootstrapSpawn {
        step: &'static str,
        source: std::io::Error,
    },
    #[error("agent VM workspace bootstrap {step} command failed with status {status}: {stderr}")]
    WorkspaceBootstrapCommandFailed {
        step: &'static str,
        status: String,
        stderr: String,
    },
    #[error("agent VM workspace bootstrap failed: {message}")]
    WorkspaceBootstrapFailed { message: String },
    #[error("agent VM workspace bootstrap timed out after {timeout:?}")]
    WorkspaceBootstrapTimedOut { timeout: Duration },
    #[error(
        "agent VM workspace bootstrap failed ({bootstrap}), and cleanup also failed: {cleanup}"
    )]
    WorkspaceBootstrapCleanupFailed { bootstrap: String, cleanup: String },
    #[error("agent VM audit operation failed: {0}")]
    Audit(#[from] AuditError),
    #[error(transparent)]
    HttpShutdown(#[from] VmHttpRuntimeShutdownError),
    #[error(
        "agent VM stop failed to close audit session and shut down VM HTTP task: audit: {audit}; http: {http}"
    )]
    StopBothFailed {
        audit: Box<AuditError>,
        http: Box<VmHttpRuntimeShutdownError>,
    },
}

impl AgentVmDaemonRuntimeConfig {
    pub fn new(
        lifecycle: AgentVmLifecycleRuntimeConfig,
        vm_http: VmHttpRuntimeConfig,
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

    pub fn vm_http(&self) -> &VmHttpRuntimeConfig {
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
        agent_kind: Option<AgentKind>,
        agent_model: Option<String>,
        workspace: Option<AgentVmWorkspaceBootstrap>,
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
            agent_kind,
            agent_model,
            opened_at: UnixMillis::now(),
            closed_at: None,
        })?;

        let start_result = async {
            if let Some(workspace) = workspace.as_ref() {
                let record = workspace_bootstrap_audit_record(session_id, workspace)?;
                state.audit.record_agent_vm_workspace_bootstrap(&record)?;
            }
            self.start_session_after_audit_opened(
                Arc::clone(&state),
                session_id,
                workspace,
                guest_command,
                None,
            )
            .await
        }
        .await;

        match start_result {
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

    pub async fn start_agent_run_session<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        label: Option<String>,
        agent_kind: AgentKind,
        agent_model: String,
        workspace: AgentVmWorkspaceBootstrap,
        prompt: AgentPrompt,
    ) -> Result<AgentRunStarted, AgentVmDaemonError> {
        let _guard = self.lifecycle_lock.lock().await;
        let session_id = SessionId::new();
        let run_id = AgentRunId::new();
        state.audit.open_session(&SessionRecord {
            session_id,
            label,
            agent_kind: Some(agent_kind),
            agent_model: Some(agent_model.clone()),
            opened_at: UnixMillis::now(),
            closed_at: None,
        })?;

        let start_result = async {
            let workspace_record = workspace_bootstrap_audit_record(session_id, &workspace)?;
            state
                .audit
                .record_agent_vm_workspace_bootstrap(&workspace_record)?;
            state.audit.record_agent_run(&AgentRunAuditRecord {
                run_id,
                session_id,
                requested_at: UnixMillis::now(),
                agent_kind,
                prompt: prompt.summary(),
            })?;
            let agent_runs = VmHttpAgentRunService::new(
                Arc::clone(&state),
                self.config.vm_http.agent_run_log_root(),
            );
            agent_runs.insert_run_config(run_id, prompt.clone(), agent_model.clone());
            let guest_command = build_agent_run_guest_command(agent_kind, run_id, workspace.warm);
            self.start_session_after_audit_opened(
                Arc::clone(&state),
                session_id,
                Some(workspace),
                guest_command,
                Some(agent_runs),
            )
            .await
        }
        .await;

        match start_result {
            Ok(started) => Ok(AgentRunStarted {
                session_id: started.session_id(),
                run_id,
                broker_url: started.broker_url().to_string(),
            }),
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

    async fn release_and_wait_for_workspace_bootstrap(
        &self,
        vm_name: &str,
    ) -> Result<(), AgentVmDaemonError> {
        self.release_and_wait_for_workspace_bootstrap_with_timeout(
            vm_name,
            AGENT_VM_WORKSPACE_BOOTSTRAP_TIMEOUT,
        )
        .await
    }

    async fn release_and_wait_for_workspace_bootstrap_with_timeout(
        &self,
        vm_name: &str,
        timeout: Duration,
    ) -> Result<(), AgentVmDaemonError> {
        self.run_container_exec_shell(
            vm_name,
            "release workspace bootstrap",
            &format!(
                "mkdir -p /run/writ-agent-vm && touch {}",
                AGENT_VM_WORKSPACE_BROKER_READY_PATH
            ),
        )
        .await?;

        let start = Instant::now();
        let mut poll_count = 0;
        loop {
            let output = self
                .run_container_exec_shell(
                    vm_name,
                    "inspect workspace bootstrap",
                    &format!(
                        "if [ -f {ok} ]; then printf ok; \
                         elif [ -f {failed} ]; then printf 'failed\\n'; cat {failed}; \
                         else printf pending; fi",
                        ok = AGENT_VM_WORKSPACE_BOOTSTRAP_OK_PATH,
                        failed = AGENT_VM_WORKSPACE_BOOTSTRAP_FAILED_PATH,
                    ),
                )
                .await?;
            let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if status == "ok" {
                return Ok(());
            }
            if let Some(message) = status.strip_prefix("failed") {
                let message = normalise_workspace_bootstrap_failure_message(message.trim());
                return Err(AgentVmDaemonError::WorkspaceBootstrapFailed {
                    message: if message.is_empty() {
                        "guest did not report a failure message".into()
                    } else {
                        message
                    },
                });
            }
            if start.elapsed() >= timeout {
                return Err(AgentVmDaemonError::WorkspaceBootstrapTimedOut { timeout });
            }
            let poll_interval = workspace_bootstrap_poll_interval(poll_count);
            poll_count = poll_count.saturating_add(1);
            tokio::time::sleep(poll_interval).await;
        }
    }

    async fn run_container_exec_shell(
        &self,
        vm_name: &str,
        step: &'static str,
        script: &str,
    ) -> Result<std::process::Output, AgentVmDaemonError> {
        let container = self.config.lifecycle.tools.container().to_path_buf();
        let vm_name = vm_name.to_string();
        let script = script.to_string();
        let output = tokio::task::spawn_blocking(move || {
            let mut command = Command::new(container);
            command
                .args(["exec", &vm_name, "sh", "-c", &script])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            process_spawn::output(&mut command)
        })
        .await?
        .map_err(|source| AgentVmDaemonError::WorkspaceBootstrapSpawn { step, source })?;
        if output.status.success() {
            return Ok(output);
        }
        Err(AgentVmDaemonError::WorkspaceBootstrapCommandFailed {
            step,
            status: output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".into()),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    async fn cleanup_failed_started_session(
        &self,
        session_id: SessionId,
    ) -> Result<(), AgentVmDaemonError> {
        let store = self.config.lifecycle.state_store.clone();
        let tools = self.config.lifecycle.tools.clone();
        tokio::task::spawn_blocking(move || {
            cleanup_managed_agent_vm_session(&store, session_id, tools)
        })
        .await??;

        if let Some(running) = self.running.lock().await.remove(&session_id) {
            running.shutdown().await?;
        }

        let store = self.config.lifecycle.state_store.clone();
        tokio::task::spawn_blocking(move || {
            remove_managed_agent_vm_session_state(&store, session_id)
        })
        .await??;
        Ok(())
    }

    pub async fn list_sessions(&self) -> Result<Vec<AgentVmSessionInfo>, AgentVmDaemonError> {
        // Listing is observational. Avoid the lifecycle mutex so an operator
        // can inspect persisted cleanup obligations while a start/stop is slow
        // or wedged; the state-store lock and running-runtime mutex provide a
        // bounded snapshot that may be retried.
        let store = self.config.lifecycle.state_store.clone();
        let states = tokio::task::spawn_blocking(move || store.load_all()).await??;
        let running = self.running.lock().await;
        Ok(states
            .into_iter()
            .map(|state| AgentVmSessionInfo {
                session_id: state.session_id(),
                status: state.status(),
                subnet_index: state.subnet_index(),
                vm_name: state.names().vm().to_string(),
                network_name: state.names().network().to_string(),
                broker_urls: state
                    .broker_urls()
                    .into_iter()
                    .map(|url| url.as_str().to_string())
                    .collect(),
                runtime_attached: running.contains_key(&state.session_id()),
            })
            .collect())
    }

    async fn start_session_after_audit_opened<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        session_id: SessionId,
        workspace: Option<AgentVmWorkspaceBootstrap>,
        guest_command: Vec<String>,
        agent_runs: Option<VmHttpAgentRunService<S>>,
    ) -> Result<AgentVmStarted, AgentVmDaemonError> {
        let lifecycle = self.config.lifecycle.clone();
        let (subnet_index, network) =
            tokio::task::spawn_blocking(move || choose_subnet_index(&lifecycle)).await??;
        let prepared = prepare_vm_http_session_with_agent_runs(
            Arc::clone(&state),
            &self.config.vm_http,
            session_id,
            network.ipv4(),
            agent_runs,
        )
        .await?;
        let broker_port = prepared.broker_port();
        let broker_url = format!("http://{}:{}/", network.ipv4_gateway(), broker_port.get());
        let nix_cache_url = nix_cache_url_for_broker_url(&broker_url);
        let trusted_public_keys = self
            .config
            .vm_http
            .nix_cache()
            .trusted_public_keys()
            .nix_conf_value();
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
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV, trusted_public_keys)?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_CONF_DIR_ENV, AGENT_VM_NIX_CONF_DIR)?,
        ];
        let guest_command = wrap_guest_command(workspace.as_ref(), guest_command)?;
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
        if workspace.is_some()
            && let Err(err) = self
                .release_and_wait_for_workspace_bootstrap(plan.names().vm())
                .await
        {
            let bootstrap = err.to_string();
            if let Err(cleanup) = self.cleanup_failed_started_session(session_id).await {
                return Err(AgentVmDaemonError::WorkspaceBootstrapCleanupFailed {
                    bootstrap,
                    cleanup: cleanup.to_string(),
                });
            }
            return Err(err);
        }
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

fn wrap_guest_command(
    workspace: Option<&AgentVmWorkspaceBootstrap>,
    guest_command: Vec<String>,
) -> Result<Vec<String>, AgentVmDaemonError> {
    match workspace {
        Some(workspace) => wrap_guest_command_with_workspace_bootstrap(workspace, guest_command),
        None => Ok(wrap_guest_command_with_nix_setup(guest_command)),
    }
}

fn wrap_guest_command_with_nix_setup(guest_command: Vec<String>) -> Vec<String> {
    shell_wrapped_command(
        AGENT_VM_GUEST_NIX_SETUP_SCRIPT,
        "writ-agent-vm-nix-setup",
        std::iter::empty::<String>(),
        guest_command,
    )
}

fn wrap_guest_command_with_workspace_bootstrap(
    workspace: &AgentVmWorkspaceBootstrap,
    guest_command: Vec<String>,
) -> Result<Vec<String>, AgentVmDaemonError> {
    let destination = workspace_destination(workspace)?;
    let destination_arg = destination
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| AgentVmDaemonError::NonUtf8WorkspaceDestination(destination.clone()))?;
    Ok(shell_wrapped_command(
        AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT,
        "writ-agent-vm-workspace-bootstrap",
        [
            workspace.repo.to_string(),
            destination_arg,
            workspace_warm_arg(workspace.warm).to_string(),
        ],
        guest_command,
    ))
}

fn shell_wrapped_command(
    script: &str,
    argv0: &str,
    prefix_args: impl IntoIterator<Item = String>,
    guest_command: Vec<String>,
) -> Vec<String> {
    let mut wrapped = vec![
        "sh".to_string(),
        "-c".to_string(),
        script.to_string(),
        argv0.into(),
    ];
    wrapped.extend(prefix_args);
    wrapped.extend(guest_command);
    wrapped
}

fn build_agent_run_guest_command(
    agent_kind: AgentKind,
    run_id: AgentRunId,
    warm: WorkspaceWarmMode,
) -> Vec<String> {
    let mut command = vec![
        "writ-vm".to_string(),
        "agent".to_string(),
        "run".to_string(),
        "--run-id".to_string(),
        run_id.to_string(),
        "--agent".to_string(),
        agent_kind.as_str().to_string(),
    ];
    if warm != WorkspaceWarmMode::DevShell {
        return command;
    }

    let mut wrapped = vec!["nix".to_string()];
    wrapped.extend(nix_develop_command_args(DEFAULT_DEVSHELL_ATTR));
    wrapped.append(&mut command);
    wrapped
}

fn workspace_destination(
    workspace: &AgentVmWorkspaceBootstrap,
) -> Result<PathBuf, AgentVmDaemonError> {
    let destination = workspace
        .destination
        .clone()
        .unwrap_or_else(|| default_workspace_destination(&workspace.repo));
    if !destination.is_absolute() {
        return Err(AgentVmDaemonError::RelativeWorkspaceDestination(
            destination,
        ));
    }
    Ok(destination)
}

fn workspace_bootstrap_audit_record(
    session_id: SessionId,
    workspace: &AgentVmWorkspaceBootstrap,
) -> Result<AgentVmWorkspaceBootstrapAuditRecord, AgentVmDaemonError> {
    let destination = workspace_destination(workspace)?;
    let destination = destination
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| AgentVmDaemonError::NonUtf8WorkspaceDestination(destination.clone()))?;
    Ok(AgentVmWorkspaceBootstrapAuditRecord {
        session_id,
        requested_at: UnixMillis::now(),
        repo: workspace.repo.to_string(),
        destination,
        branch: DEFAULT_WORKSPACE_BRANCH.to_string(),
        warm: workspace_warm_arg(workspace.warm).to_string(),
    })
}

fn workspace_warm_arg(mode: WorkspaceWarmMode) -> &'static str {
    match mode {
        WorkspaceWarmMode::None => "none",
        WorkspaceWarmMode::Sources => "sources",
        WorkspaceWarmMode::DevShell => "devshell",
    }
}

fn workspace_bootstrap_poll_interval(poll_count: u32) -> Duration {
    if poll_count < AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLLS {
        AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLL_INTERVAL
    } else {
        AGENT_VM_WORKSPACE_BOOTSTRAP_SLOW_POLL_INTERVAL
    }
}

fn normalise_workspace_bootstrap_failure_message(raw: &str) -> String {
    let mut out = String::new();
    let mut truncated = false;
    for ch in raw.chars() {
        let ch = if ch.is_control() && ch != '\n' && ch != '\t' {
            '?'
        } else {
            ch
        };
        if out.len() + ch.len_utf8() > AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT {
            truncated = true;
            break;
        }
        out.push(ch);
    }
    if truncated {
        out.push_str("\n[truncated]");
    }
    out
}

impl AgentVmStarted {
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn broker_url(&self) -> &str {
        &self.broker_url
    }
}

impl AgentRunStarted {
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn run_id(&self) -> AgentRunId {
        self.run_id
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
    use std::process::Command;
    use std::sync::Mutex as StdMutex;

    use crate::audit::AuditLog;
    use proptest::prelude::*;

    use crate::agent_vm_lifecycle::AgentVmSessionStateStatus;
    use crate::core::{
        BrokerPort, BrokerPortRange, BrokerPorts, Ipv4Cidr, Ipv6Cidr, RepoRef, TtlSeconds,
    };
    use crate::github::{GitHubAppConfig, GitHubMinter};
    use crate::nix_cache::NixTrustedPublicKeys;
    use crate::policy::PolicyConfig;
    use crate::secret::{SecretError, SecretKey};
    use crate::vm_git_bundle::{GitCredentialBoundary, GitSecretEnvVar};
    use crate::vm_http::{VmHttpGitCloneConfig, VmHttpNixCacheConfig};

    const TEST_NIX_CACHE_PUBLIC_KEY: &str =
        "cache.example-1:IsGkyTbr2sed7tWowgiPcI0ZHhBAHoGQ7TyYRweyzwE=";
    const SECOND_TEST_NIX_CACHE_PUBLIC_KEY: &str =
        "cache.example-2:KinekIvGUnCJ2dP5u+7MmV9svoga1i9pbI98OXh+zZg=";

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

    fn write_fake_workspace_failure_tool(
        dir: &Path,
        args_log: &Path,
        env_path_log: &Path,
        env_log: &Path,
    ) -> PathBuf {
        let path = dir.join("fake-workspace-failure-tool");
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
             if [ \"$1\" = \"exec\" ]; then\n\
             case \"${{5:-}}\" in\n\
             *bootstrap-failed*) printf 'failed\\nsimulated workspace failure\\n' ;;\n\
             esac\n\
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

    fn write_fake_workspace_success_tool(
        dir: &Path,
        args_log: &Path,
        env_path_log: &Path,
        env_log: &Path,
    ) -> PathBuf {
        let path = dir.join("fake-workspace-success-tool");
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
             if [ \"$1\" = \"exec\" ]; then\n\
             case \"${{5:-}}\" in\n\
             *bootstrap-failed*) printf 'ok' ;;\n\
             esac\n\
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
                VmHttpRuntimeConfig::new(
                    "0.0.0.0".parse().unwrap(),
                    BrokerPortRange::new(1024, 65535).unwrap(),
                    git_clone,
                    VmHttpNixCacheConfig::new_with_trusted_public_keys(
                        "http://127.0.0.1:9",
                        1024 * 1024,
                        1024 * 1024,
                        NixTrustedPublicKeys::from_strings([TEST_NIX_CACHE_PUBLIC_KEY]).unwrap(),
                    )
                    .unwrap(),
                    dir.join("agent-runs"),
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
                Some(AgentKind::Codex),
                Some("gpt-test".into()),
                None,
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
        assert_eq!(audit_session.agent_kind, Some(AgentKind::Codex));
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
            "{AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV}={TEST_NIX_CACHE_PUBLIC_KEY}"
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

        let sessions = daemon.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, started.session_id());
        assert_eq!(sessions[0].status, AgentVmSessionStateStatus::Running);
        assert_eq!(sessions[0].subnet_index, 252);
        assert_eq!(
            sessions[0].vm_name.as_str(),
            format!("writ-agent-vm-{}", started.session_id())
        );
        assert_eq!(
            sessions[0].network_name.as_str(),
            format!("writ-agent-net-{}", started.session_id())
        );
        assert_eq!(
            sessions[0].broker_urls.as_slice(),
            &[started.broker_url().to_string()]
        );
        assert!(sessions[0].runtime_attached);

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
                agent_kind: None,
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
                None,
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
                None,
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

    #[tokio::test]
    async fn daemon_workspace_bootstrap_success_records_audit_intent() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let env_path_log = dir.path().join("env-path.log");
        let env_log = dir.path().join("env.log");
        let fake_tool =
            write_fake_workspace_success_tool(dir.path(), &args_log, &env_path_log, &env_log);
        let (config, _) = daemon_config(dir.path(), &fake_tool);
        let state = make_state();
        let daemon = AgentVmDaemon::new(config);
        let workspace = AgentVmWorkspaceBootstrap {
            repo: "owner/repo".parse().unwrap(),
            destination: None,
            warm: WorkspaceWarmMode::Sources,
        };

        let started = daemon
            .start_session(
                Arc::clone(&state),
                Some("workspace bootstrap success".into()),
                None,
                None,
                Some(workspace),
                vec!["codex".into()],
            )
            .await
            .unwrap();

        let audit_record = state
            .audit
            .get_agent_vm_workspace_bootstrap(started.session_id())
            .unwrap()
            .unwrap();
        assert_eq!(audit_record.repo, "owner/repo");
        assert_eq!(audit_record.destination, "/workspace/repo");
        assert_eq!(audit_record.branch, DEFAULT_WORKSPACE_BRANCH);
        assert_eq!(audit_record.warm, "sources");

        daemon
            .stop_session(&state, started.session_id())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn daemon_workspace_bootstrap_failure_removes_state_and_closes_audit_session() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let env_path_log = dir.path().join("env-path.log");
        let env_log = dir.path().join("env.log");
        let fake_tool =
            write_fake_workspace_failure_tool(dir.path(), &args_log, &env_path_log, &env_log);
        let (config, state_store) = daemon_config(dir.path(), &fake_tool);
        let state = make_state();
        let daemon = AgentVmDaemon::new(config);
        let workspace = AgentVmWorkspaceBootstrap {
            repo: "owner/repo".parse().unwrap(),
            destination: Some(PathBuf::from("/workspace/repo")),
            warm: WorkspaceWarmMode::None,
        };

        let err = daemon
            .start_session(
                Arc::clone(&state),
                Some("workspace bootstrap failure".into()),
                None,
                None,
                Some(workspace),
                vec!["codex".into()],
            )
            .await
            .unwrap_err();

        let session_id = match err {
            AgentVmDaemonError::StartFailed { session_id, source } => {
                assert!(matches!(
                    *source,
                    AgentVmDaemonError::WorkspaceBootstrapFailed { .. }
                ));
                session_id
            }
            other => panic!("unexpected workspace bootstrap error: {other:?}"),
        };
        assert!(state_store.load_all().unwrap().is_empty());
        assert!(daemon.running.lock().await.is_empty());
        let audit_session = state.audit.get_session(session_id).unwrap().unwrap();
        assert_eq!(
            audit_session.label.as_deref(),
            Some("workspace bootstrap failure")
        );
        assert!(audit_session.closed_at.is_some());
        let audit_record = state
            .audit
            .get_agent_vm_workspace_bootstrap(session_id)
            .unwrap()
            .unwrap();
        assert_eq!(audit_record.repo, "owner/repo");
        assert_eq!(audit_record.destination, "/workspace/repo");
        assert_eq!(audit_record.warm, "none");
    }

    #[tokio::test]
    async fn daemon_list_reports_persisted_session_without_runtime_as_detached() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let env_path_log = dir.path().join("env-path.log");
        let env_log = dir.path().join("env.log");
        let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
        let (config, state_store) = daemon_config(dir.path(), &fake_tool);
        occupy_subnet(&state_store, 252);
        let state = state_store.load_all().unwrap().pop().unwrap();
        let daemon = AgentVmDaemon::new(config);

        let sessions = daemon.list_sessions().await.unwrap();

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, state.session_id());
        assert_eq!(sessions[0].status, AgentVmSessionStateStatus::Starting);
        assert_eq!(sessions[0].subnet_index, state.subnet_index());
        assert_eq!(sessions[0].vm_name.as_str(), state.names().vm());
        assert_eq!(sessions[0].network_name.as_str(), state.names().network());
        assert_eq!(
            sessions[0].broker_urls.as_slice(),
            &["http://192.168.252.1:51375/".to_string()]
        );
        assert!(!sessions[0].runtime_attached);
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

    #[test]
    fn guest_nix_setup_script_writes_configured_trusted_public_keys() {
        let dir = tempfile::tempdir().unwrap();
        let netrc = dir.path().join("run").join("netrc");
        let nix_conf_dir = dir.path().join("nix-conf");
        let trusted_public_keys =
            format!("{TEST_NIX_CACHE_PUBLIC_KEY} {SECOND_TEST_NIX_CACHE_PUBLIC_KEY}");

        let status = Command::new("sh")
            .arg("-c")
            .arg(AGENT_VM_GUEST_NIX_SETUP_SCRIPT)
            .arg("writ-agent-vm-nix-setup")
            .arg("true")
            .env("WRIT_BROKER_TOKEN", "writ-vm-token")
            .env(
                "WRIT_NIX_CACHE_URL",
                "http://192.168.252.1:51375/v1/nix/cache",
            )
            .env("WRIT_NIX_BASIC_LOGIN", VM_NIX_BASIC_LOGIN)
            .env("WRIT_NIX_NETRC", &netrc)
            .env(AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV, &trusted_public_keys)
            .env("NIX_CONF_DIR", &nix_conf_dir)
            .status()
            .unwrap();

        assert!(status.success());
        let nix_conf = fs::read_to_string(nix_conf_dir.join("nix.conf")).unwrap();
        assert!(nix_conf.contains(&format!("trusted-public-keys = {trusted_public_keys}\n")));
        let netrc = fs::read_to_string(netrc).unwrap();
        assert_eq!(
            netrc,
            "machine 192.168.252.1 login writ-vm password writ-vm-token\n"
        );
    }

    #[test]
    fn non_workspace_nix_setup_does_not_enable_flakes() {
        assert!(AGENT_VM_GUEST_NIX_SETUP_SCRIPT.contains("experimental-features = nix-command"));
        assert!(!AGENT_VM_GUEST_NIX_SETUP_SCRIPT.contains("nix-command flakes"));
        assert!(AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT.contains("nix-command flakes"));
    }

    #[test]
    fn agent_run_guest_command_contains_run_id_and_agent_but_not_prompt() {
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000201".parse().unwrap();
        let prompt = AgentPrompt::new("SECRET prompt");

        let command =
            build_agent_run_guest_command(AgentKind::Claude, run_id, WorkspaceWarmMode::Sources);

        assert_eq!(
            command,
            vec![
                "writ-vm",
                "agent",
                "run",
                "--run-id",
                "00000000-0000-0000-0000-000000000201",
                "--agent",
                "claude",
            ]
        );
        assert!(!format!("{command:?}").contains(prompt.as_str()));
    }

    #[test]
    fn agent_run_devshell_command_wraps_without_adding_prompt() {
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000202".parse().unwrap();
        let prompt = AgentPrompt::new("SECRET prompt");

        let command =
            build_agent_run_guest_command(AgentKind::Codex, run_id, WorkspaceWarmMode::DevShell);

        assert!(command.starts_with(&[
            "nix".to_string(),
            "--option".to_string(),
            "builders".to_string(),
            "".to_string(),
        ]));
        assert!(command.ends_with(&[
            "writ-vm".to_string(),
            "agent".to_string(),
            "run".to_string(),
            "--run-id".to_string(),
            "00000000-0000-0000-0000-000000000202".to_string(),
            "--agent".to_string(),
            "codex".to_string(),
        ]));
        assert!(!format!("{command:?}").contains(prompt.as_str()));
    }

    #[test]
    fn workspace_bootstrap_script_mentions_sentinel_paths() {
        assert!(
            AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT
                .contains(AGENT_VM_WORKSPACE_BROKER_READY_PATH)
        );
        assert!(
            AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT
                .contains(AGENT_VM_WORKSPACE_BOOTSTRAP_OK_PATH)
        );
        assert!(
            AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT
                .contains(AGENT_VM_WORKSPACE_BOOTSTRAP_FAILED_PATH)
        );
    }

    #[test]
    fn workspace_bootstrap_poll_interval_backs_off_after_initial_polls() {
        assert_eq!(
            workspace_bootstrap_poll_interval(0),
            AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLL_INTERVAL
        );
        assert_eq!(
            workspace_bootstrap_poll_interval(AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLLS - 1),
            AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLL_INTERVAL
        );
        assert_eq!(
            workspace_bootstrap_poll_interval(AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLLS),
            AGENT_VM_WORKSPACE_BOOTSTRAP_SLOW_POLL_INTERVAL
        );
    }

    #[test]
    fn workspace_bootstrap_failure_message_is_bounded_and_control_scrubbed() {
        let raw = format!(
            "\u{1b}[31m{}\u{7}",
            "x".repeat(AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT + 32)
        );

        let message = normalise_workspace_bootstrap_failure_message(&raw);

        assert!(
            message.len()
                <= AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT + "\n[truncated]".len()
        );
        assert!(!message.contains('\u{1b}'));
        assert!(message.ends_with("[truncated]"));
    }

    #[tokio::test]
    async fn workspace_bootstrap_wait_reports_timeout_at_supplied_bound() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let env_path_log = dir.path().join("env-path.log");
        let env_log = dir.path().join("env.log");
        let fake_tool = write_fake_tool(dir.path(), &args_log, &env_path_log, &env_log);
        let (config, _) = daemon_config(dir.path(), &fake_tool);
        let daemon = AgentVmDaemon::new(config);

        let err = daemon
            .release_and_wait_for_workspace_bootstrap_with_timeout(
                "writ-agent-vm-test",
                Duration::ZERO,
            )
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            AgentVmDaemonError::WorkspaceBootstrapTimedOut {
                timeout: Duration::ZERO
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_bootstrap_rejects_non_utf8_destination() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let workspace = AgentVmWorkspaceBootstrap {
            repo: "owner/repo".parse().unwrap(),
            destination: Some(PathBuf::from(OsString::from_vec(vec![b'/', 0xff]))),
            warm: WorkspaceWarmMode::None,
        };

        let err = wrap_guest_command_with_workspace_bootstrap(&workspace, vec!["true".into()])
            .unwrap_err();

        assert!(matches!(
            err,
            AgentVmDaemonError::NonUtf8WorkspaceDestination(_)
        ));
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
        fn workspace_bootstrap_wrapper_preserves_guest_command_argv(
            guest_command in prop::collection::vec(any::<String>(), 1..16),
            warm in prop_oneof![
                Just(WorkspaceWarmMode::None),
                Just(WorkspaceWarmMode::Sources),
                Just(WorkspaceWarmMode::DevShell),
            ],
        ) {
            let workspace = AgentVmWorkspaceBootstrap {
                repo: "owner/repo".parse().unwrap(),
                destination: Some(PathBuf::from("/workspace/repo")),
                warm,
            };
            let wrapped = wrap_guest_command_with_workspace_bootstrap(&workspace, guest_command.clone()).unwrap();
            prop_assert_eq!(&wrapped[..4], &[
                "sh".to_string(),
                "-c".to_string(),
                AGENT_VM_GUEST_WORKSPACE_BOOTSTRAP_SCRIPT.to_string(),
                "writ-agent-vm-workspace-bootstrap".to_string(),
            ]);
            prop_assert_eq!(&wrapped[4..7], &[
                "owner/repo".to_string(),
                "/workspace/repo".to_string(),
                workspace_warm_arg(warm).to_string(),
            ]);
            prop_assert_eq!(&wrapped[7..], guest_command.as_slice());
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
