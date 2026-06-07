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

use crate::agent_run::{AgentPrompt, AgentRunId, CorrelationId};
use crate::agent_vm_lifecycle::{
    AgentVmGuestEnvVar, AgentVmLifecycleConfigError, AgentVmResources, AgentVmSessionManagerError,
    AgentVmSessionPlan, AgentVmSessionState, AgentVmSessionStateError, AgentVmSessionStateStore,
    AgentVmToolPaths, ContainerImage, Ipv6IsolationMode, claim_agent_vm_session_subnet,
    cleanup_managed_agent_vm_session, complete_agent_vm_session_start,
    remove_managed_agent_vm_session_state,
};
use crate::audit::{AgentRunAuditRecord, AuditError, AuditLog};
use crate::core::{
    AgentKind, AgentNetwork, AgentNetworkPool, AgentVmConfigError, BrokerPorts, SessionId,
    SessionRecord, UnixMillis,
};
use crate::git_push_staging::GitPushStagingStore;
use crate::process_spawn;
use crate::protocol::AgentVmSessionInfo;
use crate::secret::SecretStore;
use crate::server::BrokerState;
use crate::vm_git::AgentVmWorkspaceBootstrap;
use crate::vm_http::{
    RunningVmHttpSession, VM_NIX_BASIC_LOGIN, VM_NIX_CACHE_PATH_PREFIX, VmHttpAgentRunService,
    VmHttpGitPushService, VmHttpRuntimeConfig, VmHttpRuntimeError, VmHttpRuntimeShutdownError,
    prepare_vm_http_session_with_agent_runs,
};

pub use crate::vm_client::{
    VM_BROKER_TOKEN_ENV as AGENT_VM_BROKER_TOKEN_ENV, VM_BROKER_URL_ENV as AGENT_VM_BROKER_URL_ENV,
};

mod guest_command;
use guest_command::{
    build_agent_run_guest_command, workspace_bootstrap_audit_record, wrap_guest_command,
};

mod materialize;
pub use materialize::{
    MaterializeVmEnvelopeError, MaterializedVmRunEnvelope, materialize_vm_signed_envelope,
};

mod run_outcome;
pub use run_outcome::{WaitForAgentRunOutcomeError, wait_for_agent_run_outcome};

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
/// Prepended to a truncated failure message. The marker leads (rather than
/// trails) because the truncation keeps the *tail* of the output: Nix prints the
/// line that actually explains the failure last, after a long run of
/// `copying path ...` substitution progress.
const AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TRUNCATION_MARKER: &str = "[truncated]\n";

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
    /// Serialises the load-state → choose-subnet → write-`Starting`-record
    /// window so concurrent starts cannot pick the same subnet index. Held
    /// only across that fast window; the slow VM boot in
    /// [`complete_agent_vm_session_start`] runs unlocked so unrelated sessions
    /// can boot in parallel.
    subnet_allocation_lock: Mutex<()>,
    /// Per-session lifecycle locks keyed by [`SessionId`]. Start and stop of
    /// the *same* session serialise here; unrelated sessions don't. Entries
    /// are evicted once no other task holds a handle.
    session_locks: Mutex<HashMap<SessionId, Arc<Mutex<()>>>>,
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
    #[error("could not open git push staging store at {path:?}: {source}")]
    GitPushStagingOpen {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Report from [`AgentVmDaemon::reconcile_persisted_sessions`].
///
/// On boot, every persisted session is a cleanup obligation: the previous
/// `writd` process owned the broker bearer token, the VM HTTP listener
/// socket, and the runtime handle, none of which survive a crash. The guest
/// inside such a VM cannot authenticate against the new broker, so we tear
/// down the VM, firewall, and network and close out the audit row rather
/// than try to resume the session.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct AgentVmReconcileReport {
    cleaned: Vec<SessionId>,
    failed: Vec<AgentVmReconcileFailure>,
}

#[derive(Debug)]
pub struct AgentVmReconcileFailure {
    session_id: SessionId,
    stage: AgentVmReconcileStage,
    error: AgentVmReconcileStageError,
}

/// Which step of the per-session reconcile sequence reported the failure.
///
/// Ordering is `Cleanup` → `AuditClose` → `StateRemove`. A failure short-
/// circuits the remaining stages so the state record is preserved for retry
/// on the next boot.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AgentVmReconcileStage {
    /// Tear down the VM, firewall anchors, and network via the persisted
    /// state record. Idempotent against partially-cleaned infrastructure.
    Cleanup,
    /// Close the audit-DB session row. Idempotent against already-closed
    /// rows: the `UPDATE` only matches `closed_at IS NULL`.
    AuditClose,
    /// Remove the persisted state record so the subnet index and per-session
    /// names are released for reuse.
    StateRemove,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentVmReconcileStageError {
    #[error(transparent)]
    Manager(#[from] AgentVmSessionManagerError),
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error("reconcile worker task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Debug, thiserror::Error)]
pub enum AgentVmReconcileError {
    #[error("could not load persisted agent VM session records: {0}")]
    LoadAll(#[source] AgentVmSessionStateError),
    #[error("reconcile load-all worker task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
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

impl AgentVmReconcileReport {
    pub fn cleaned(&self) -> &[SessionId] {
        &self.cleaned
    }

    pub fn failed(&self) -> &[AgentVmReconcileFailure] {
        &self.failed
    }

    pub fn is_clean(&self) -> bool {
        self.failed.is_empty()
    }
}

impl AgentVmReconcileFailure {
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn stage(&self) -> AgentVmReconcileStage {
        self.stage
    }

    pub fn error(&self) -> &AgentVmReconcileStageError {
        &self.error
    }
}

impl AgentVmReconcileStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cleanup => "cleanup",
            Self::AuditClose => "audit_close",
            Self::StateRemove => "state_remove",
        }
    }
}

impl PartialEq for AgentVmReconcileFailure {
    fn eq(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.stage == other.stage
            && self.error.to_string() == other.error.to_string()
    }
}

impl Eq for AgentVmReconcileFailure {}

impl AgentVmDaemon {
    pub fn new(config: AgentVmDaemonRuntimeConfig) -> Self {
        Self {
            config,
            running: Mutex::new(HashMap::new()),
            subnet_allocation_lock: Mutex::new(()),
            session_locks: Mutex::new(HashMap::new()),
        }
    }

    async fn session_lock_handle(&self, session_id: SessionId) -> Arc<Mutex<()>> {
        let mut locks = self.session_locks.lock().await;
        Arc::clone(
            locks
                .entry(session_id)
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    /// Drops the per-session lock map entry if no task is holding or waiting
    /// for it. Caller must have already dropped its own [`Arc`] handle so the
    /// strong count reflects only the map's own reference.
    async fn drop_idle_session_lock(&self, session_id: SessionId) {
        let mut locks = self.session_locks.lock().await;
        if let Some(lock) = locks.get(&session_id)
            && Arc::strong_count(lock) == 1
        {
            locks.remove(&session_id);
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

        let session_id = SessionId::new();
        let session_lock = self.session_lock_handle(session_id).await;
        let outcome = async {
            let _session_guard = session_lock.lock().await;
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

            start_result.map_err(|err| {
                close_audit_session_best_effort(&state, session_id);
                AgentVmDaemonError::StartFailed {
                    session_id,
                    source: Box::new(err),
                }
            })
        }
        .await;

        drop(session_lock);
        self.drop_idle_session_lock(session_id).await;
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn start_agent_run_session<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        label: Option<String>,
        agent_kind: AgentKind,
        agent_model: String,
        workspace: AgentVmWorkspaceBootstrap,
        prompt: AgentPrompt,
        correlation_id: Option<CorrelationId>,
    ) -> Result<AgentRunStarted, AgentVmDaemonError> {
        let session_id = SessionId::new();
        let run_id = AgentRunId::new();
        let session_lock = self.session_lock_handle(session_id).await;
        let outcome = async {
            let _session_guard = session_lock.lock().await;
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
                    correlation_id: correlation_id.clone(),
                })?;
                let agent_runs = VmHttpAgentRunService::new(
                    Arc::clone(&state),
                    self.config.vm_http.agent_run_log_root(),
                );
                agent_runs.insert_run_config(run_id, prompt.clone(), agent_model.clone());
                let guest_command =
                    build_agent_run_guest_command(agent_kind, run_id, workspace.warm);
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

            start_result
                .map(|started| AgentRunStarted {
                    session_id: started.session_id(),
                    run_id,
                    broker_url: started.broker_url().to_string(),
                })
                .map_err(|err| {
                    close_audit_session_best_effort(&state, session_id);
                    AgentVmDaemonError::StartFailed {
                        session_id,
                        source: Box::new(err),
                    }
                })
        }
        .await;

        drop(session_lock);
        self.drop_idle_session_lock(session_id).await;
        outcome
    }

    pub async fn stop_session<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: &Arc<BrokerState<S>>,
        session_id: SessionId,
    ) -> Result<(), AgentVmDaemonError> {
        let session_lock = self.session_lock_handle(session_id).await;
        let _session_guard = session_lock.lock().await;

        let result = self.stop_session_locked(state, session_id).await;

        drop(_session_guard);
        drop(session_lock);
        self.drop_idle_session_lock(session_id).await;
        result
    }

    /// Run the blocking VM/firewall/network teardown for `session_id` on a
    /// blocking thread. The nested result preserves the join-vs-manager
    /// distinction the reconcile sweep maps onto its per-stage error; the
    /// stop/cleanup paths flatten it with `??`.
    async fn spawn_cleanup_session(
        &self,
        session_id: SessionId,
    ) -> Result<Result<(), AgentVmSessionManagerError>, tokio::task::JoinError> {
        let store = self.config.lifecycle.state_store.clone();
        let tools = self.config.lifecycle.tools.clone();
        tokio::task::spawn_blocking(move || {
            cleanup_managed_agent_vm_session(&store, session_id, tools)
        })
        .await
    }

    /// Remove the persisted state record for `session_id` on a blocking
    /// thread, releasing its subnet index and per-session names. Nested
    /// result as in [`Self::spawn_cleanup_session`].
    async fn spawn_remove_session_state(
        &self,
        session_id: SessionId,
    ) -> Result<Result<(), AgentVmSessionManagerError>, tokio::task::JoinError> {
        let store = self.config.lifecycle.state_store.clone();
        tokio::task::spawn_blocking(move || {
            remove_managed_agent_vm_session_state(&store, session_id)
        })
        .await
    }

    async fn stop_session_locked<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: &Arc<BrokerState<S>>,
        session_id: SessionId,
    ) -> Result<(), AgentVmDaemonError> {
        self.spawn_cleanup_session(session_id).await??;

        let audit_close = state.audit.close_session(session_id, UnixMillis::now());
        let http_shutdown = match self.running.lock().await.remove(&session_id) {
            Some(running) => running.shutdown().await,
            None => Ok(()),
        };

        match (audit_close, http_shutdown) {
            (Ok(()), Ok(())) => {
                self.spawn_remove_session_state(session_id).await??;
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
                .stdin(std::process::Stdio::null())
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
        self.spawn_cleanup_session(session_id).await??;

        if let Some(running) = self.running.lock().await.remove(&session_id) {
            running.shutdown().await?;
        }

        self.spawn_remove_session_state(session_id).await??;
        Ok(())
    }

    /// Treat every persisted session as a cleanup obligation and drive it to
    /// completion: tear down the VM/firewall/network via the persisted facts,
    /// close the audit row, then remove the state record.
    ///
    /// MUST be called before [`crate::server::run_with_agent_vm`] begins
    /// accepting connections. Subnet selection in `start_session` is driven
    /// by `state_store.load_all()`; accepting new starts before reconcile
    /// completes would race the new session against the persisted one that
    /// is about to be freed, either colliding on the subnet index (rejected,
    /// noisy) or — worse — letting the new session win and leaking the old
    /// VM's network.
    ///
    /// Per-session failures are collected into the report; the sweep keeps
    /// going. A failed session keeps its state record so the next boot
    /// retries. `LoadAll` failure aborts before any session is touched and
    /// is surfaced as the outer `Err`.
    pub async fn reconcile_persisted_sessions(
        &self,
        audit: &Arc<AuditLog>,
    ) -> Result<AgentVmReconcileReport, AgentVmReconcileError> {
        let store = self.config.lifecycle.state_store.clone();
        let states = tokio::task::spawn_blocking(move || store.load_all())
            .await?
            .map_err(AgentVmReconcileError::LoadAll)?;

        let mut report = AgentVmReconcileReport::default();
        for state in states {
            let session_id = state.session_id();
            match self.reconcile_one_session(audit, session_id).await {
                Ok(()) => report.cleaned.push(session_id),
                Err((stage, error)) => report.failed.push(AgentVmReconcileFailure {
                    session_id,
                    stage,
                    error,
                }),
            }
        }
        Ok(report)
    }

    async fn reconcile_one_session(
        &self,
        audit: &Arc<AuditLog>,
        session_id: SessionId,
    ) -> Result<(), (AgentVmReconcileStage, AgentVmReconcileStageError)> {
        match self.spawn_cleanup_session(session_id).await {
            Err(join) => return Err((AgentVmReconcileStage::Cleanup, join.into())),
            Ok(Err(err)) => return Err((AgentVmReconcileStage::Cleanup, err.into())),
            Ok(Ok(())) => {}
        }

        if let Err(err) = audit.close_session(session_id, UnixMillis::now()) {
            return Err((AgentVmReconcileStage::AuditClose, err.into()));
        }

        match self.spawn_remove_session_state(session_id).await {
            Err(join) => return Err((AgentVmReconcileStage::StateRemove, join.into())),
            Ok(Err(err)) => return Err((AgentVmReconcileStage::StateRemove, err.into())),
            Ok(Ok(())) => {}
        }

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
        // Hold subnet_allocation_lock from `choose_subnet_index` through the
        // `claim_agent_vm_session_subnet` write, so the load+pick+commit
        // window is atomic across concurrent starts. The slow VM boot in
        // `complete_agent_vm_session_start` runs after the lock is released.
        let (prepared, plan, starting, broker_url) = {
            let _subnet_guard = self.subnet_allocation_lock.lock().await;
            let lifecycle = self.config.lifecycle.clone();
            let (subnet_index, network) =
                tokio::task::spawn_blocking(move || choose_subnet_index(&lifecycle)).await??;
            let staging_root = self.config.vm_http.git_push_staging_root().to_path_buf();
            let staging_store = {
                let path = staging_root.clone();
                tokio::task::spawn_blocking(move || GitPushStagingStore::open(path))
                    .await?
                    .map_err(|source| AgentVmDaemonError::GitPushStagingOpen {
                        path: staging_root,
                        source,
                    })?
            };
            let git_push = VmHttpGitPushService::new(
                Arc::clone(&state),
                Arc::new(staging_store),
                self.config.vm_http.git_push_body_limits(),
            );
            let prepared = prepare_vm_http_session_with_agent_runs(
                Arc::clone(&state),
                &self.config.vm_http,
                session_id,
                network.ipv4(),
                agent_runs,
                Some(git_push),
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
            let plan_for_claim = plan.clone();
            let starting: AgentVmSessionState = tokio::task::spawn_blocking(move || {
                claim_agent_vm_session_subnet(&store, &plan_for_claim)
            })
            .await??;
            (prepared, plan, starting, broker_url)
        };

        let store = self.config.lifecycle.state_store.clone();
        let plan_for_start = plan.clone();
        tokio::task::spawn_blocking(move || {
            complete_agent_vm_session_start(&store, &plan_for_start, starting)
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

fn workspace_bootstrap_poll_interval(poll_count: u32) -> Duration {
    if poll_count < AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLLS {
        AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLL_INTERVAL
    } else {
        AGENT_VM_WORKSPACE_BOOTSTRAP_SLOW_POLL_INTERVAL
    }
}

fn normalise_workspace_bootstrap_failure_message(raw: &str) -> String {
    // Replace terminal-corrupting control characters (anything other than
    // newlines and tabs) so echoing the message back to the operator is safe.
    let scrubbed: String = raw
        .chars()
        .map(|ch| {
            if ch.is_control() && ch != '\n' && ch != '\t' {
                '?'
            } else {
                ch
            }
        })
        .collect();

    if scrubbed.len() <= AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT {
        return scrubbed;
    }

    // Keep the tail, not the head: Nix prints the line that actually explains
    // the failure last, after a long run of `copying path ...` substitution
    // progress, so the head is noise and the tail is the diagnosis. Take at most
    // LIMIT bytes from the end, snapping forward to a char boundary so we never
    // split a multi-byte character.
    let mut start = scrubbed.len() - AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT;
    while !scrubbed.is_char_boundary(start) {
        start += 1;
    }
    format!(
        "{AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TRUNCATION_MARKER}{}",
        &scrubbed[start..]
    )
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
        tracing::warn!(
            session_id = %session_id,
            error = %err,
            "agent VM start cleanup could not close audit session",
        );
    }
}

#[cfg(test)]
mod guest_command_tests;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod materialize_tests;
#[cfg(test)]
mod run_outcome_tests;
#[cfg(test)]
mod test_support;

/// Property-based specification for the daemon's subnet allocator.
///
/// The example/edge-case tests in the sibling `*_tests` modules pin
/// specific scenarios; this module asserts the selection contract holds
/// for *arbitrary* occupancy: `choose_subnet_index` returns the first
/// unused index in the configured range, or reports the range full with
/// its exact bounds.
#[cfg(test)]
mod spec {
    use super::test_support::*;
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

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
