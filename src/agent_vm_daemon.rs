//! Daemon-owned agent VM lifecycle orchestration.
//!
//! This module is the bridge between the Unix-socket broker protocol, the
//! managed Apple-container lifecycle runner, and the per-session VM HTTP
//! runtime. It keeps the authority-bearing ordering local: bind the VM HTTP
//! listener, install PF for the selected port through managed start, then
//! spawn the HTTP task only after the VM lifecycle reports success.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, watch};

use crate::agent_run::{AgentPrompt, AgentRunId, CorrelationId};
use crate::agent_vm_lifecycle::{
    AgentVmGuestEnvVar, AgentVmLifecycleConfigError, AgentVmNames, AgentVmResources,
    AgentVmSessionManagerError, AgentVmSessionPlan, AgentVmSessionState, AgentVmSessionStateError,
    AgentVmSessionStateStatus, AgentVmSessionStateStore, AgentVmToolPaths, BoundedOutput,
    BrokerPlacement, ContainerImage, HostIface, Ipv6IsolationMode, NetworkHealth, ProbeDebounce,
    ProbeObservation, ProcessInvocation, ProcessInvocationError, claim_agent_vm_session_subnet,
    cleanup_managed_agent_vm_session, complete_agent_vm_session_start, evaluate_host_path,
    host_interfaces, remove_managed_agent_vm_session_state, start_agent_vm_session,
};
use crate::audit::{
    AgentRunAuditRecord, AgentVmNetworkHealthEventRecord, AuditError, AuditLog, NixCacheAuditEntry,
    NixCacheAuditRoute,
};
use crate::broker_log_forwarder::BrokerLogForwarder;
use crate::broker_vm::{
    BROKER_VM_LOG_FILE, BrokerVmSessionPaths, BrokerVmSessionRequest, broker_url,
    materialize_broker_vm_session,
};
use crate::broker_vm_runner::launch_broker_vm;
use crate::core::{
    AgentKind, AgentNetwork, AgentNetworkPool, AgentVmConfigError, BrokerPort, BrokerPorts,
    SessionId, SessionRecord, UnixMillis,
};
use crate::git_push_staging::GitPushStagingStore;
use crate::protocol::AgentVmSessionInfo;
use crate::secret::SecretStore;
use crate::server::BrokerState;
use crate::vm_git::AgentVmWorkspaceBootstrap;
use crate::vm_http::{
    RunningVmHttpSession, VM_NIX_BASIC_LOGIN, VM_NIX_CACHE_PATH_PREFIX, VM_NIX_PREWARM_PATH_PREFIX,
    VmHttpAgentRunService, VmHttpBearerToken, VmHttpGitPushService, VmHttpRuntimeConfig,
    VmHttpRuntimeError, VmHttpRuntimeShutdownError, prepare_vm_http_session_with_agent_runs,
};

pub use crate::vm_git::{
    VM_BROKER_TOKEN_ENV as AGENT_VM_BROKER_TOKEN_ENV, VM_BROKER_URL_ENV as AGENT_VM_BROKER_URL_ENV,
};

mod guest_command;
use guest_command::{
    build_agent_run_guest_command, workspace_bootstrap_audit_record, wrap_guest_command,
};

mod run_outcome;
pub use run_outcome::{WaitForAgentRunOutcomeError, wait_for_agent_run_outcome};

/// The `AgentVmDaemon` method impl (session start/stop/reconcile orchestration)
/// lives here; the struct and its supporting types stay in this module. Split
/// out to keep `agent_vm_daemon.rs` readable.
mod daemon_impl;

pub const AGENT_VM_NIX_CACHE_URL_ENV: &str = "WRIT_NIX_CACHE_URL";
/// The strict, pre-warm-only substituter URL. Injected only when the broker has
/// a `nix_prewarm_cache_dir` configured: its presence is what switches the
/// guest's devShell warm onto the local-only `/v1/nix/prewarm` view. Absent (no
/// pre-warming in this deployment), the warm keeps the session-default proxied
/// substituter, exactly as before. Same env-var name the guest reads as
/// [`crate::vm_git::VM_NIX_PREWARM_URL_ENV`] — this is the host-facing alias.
pub use crate::vm_git::VM_NIX_PREWARM_URL_ENV as AGENT_VM_NIX_PREWARM_URL_ENV;
pub const AGENT_VM_NIX_BASIC_LOGIN_ENV: &str = "WRIT_NIX_BASIC_LOGIN";
pub const AGENT_VM_NIX_NETRC_ENV: &str = "WRIT_NIX_NETRC";
pub const AGENT_VM_NIX_NETRC_PATH: &str = "/run/writ-agent-vm/netrc";
pub const AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV: &str = "WRIT_NIX_TRUSTED_PUBLIC_KEYS";
pub const AGENT_VM_NIX_CONF_DIR_ENV: &str = "NIX_CONF_DIR";
/// The boot-time egress gate's expected IPv6 posture, set from the lifecycle
/// `ipv6_mode`: `1` (the guest must hold no global-scope IPv6 address) only for
/// `Ipv4OnlyNoGuestIpv6`, `0` for `DualStackRequired` (which provisions a ULA
/// deliberately). The IPv4-egress and broker checks are mode-independent and
/// always run; only the no-IPv6 assertion is gated on this.
pub const AGENT_VM_EGRESS_GATE_REQUIRE_NO_IPV6_ENV: &str = "WRIT_EGRESS_GATE_REQUIRE_NO_IPV6";
pub const AGENT_VM_NIX_CONF_DIR: &str = "/run/writ-agent-vm/nix-conf";
const AGENT_VM_WORKSPACE_BROKER_READY_PATH: &str = "/run/writ-agent-vm/broker-ready";
const AGENT_VM_WORKSPACE_BOOTSTRAP_OK_PATH: &str = "/run/writ-agent-vm/bootstrap-ok";
const AGENT_VM_WORKSPACE_BOOTSTRAP_FAILED_PATH: &str = "/run/writ-agent-vm/bootstrap-failed";
const AGENT_VM_WORKSPACE_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// How long the daemon waits for a broker VM to boot and publish its ready file
/// (broker_placement = vm) before giving up and tearing it down.
const BROKER_VM_READY_TIMEOUT: Duration = Duration::from_secs(3 * 60);
/// How often the daemon polls the broker VM's ready file on the shared mount.
const BROKER_VM_READY_POLL_INTERVAL: Duration = Duration::from_millis(250);
const AGENT_VM_WORKSPACE_BOOTSTRAP_SLOW_POLL_INTERVAL: Duration = Duration::from_secs(2);
const AGENT_VM_WORKSPACE_BOOTSTRAP_QUICK_POLLS: u32 = 10;
const AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT: usize = 16 * 1024;
/// Hard cap on the bytes captured from a single guest `container exec` during
/// the workspace-bootstrap wait. The inspect script's payload is a
/// guest-controlled failure file (read from inside a VM we treat as
/// compromised); without a cap a hostile guest could stream unbounded output
/// and exhaust host memory. This is the authority-side backstop: it does not
/// rely on the guest cooperating, and exceeding it is treated as abuse that
/// fails the bootstrap.
const AGENT_VM_CONTAINER_EXEC_OUTPUT_LIMIT: usize = 1024 * 1024;
/// How many trailing bytes of the guest's `bootstrap-failed` file the inspect
/// script cooperatively `tail`s. The guest writes the *whole* failure stream
/// (see `guest_command`'s `GUEST_WORKSPACE_BOOTSTRAP_TAIL`), which for a large
/// Nix warm can far exceed the capture cap. Because the actionable Nix error
/// prints last, tailing guest-side delivers it within the cap, so
/// [`normalise_workspace_bootstrap_failure_message`] still receives the tail it
/// is designed to keep — a plain `cat` of a multi-MiB failure would instead
/// trip the head-truncation cap and discard the diagnosis. Larger than the
/// message limit so `normalise` still marks the result truncated, and (asserted
/// below) strictly under the capture cap so a well-behaved guest never trips
/// [`AgentVmDaemonError::WorkspaceBootstrapOutputTooLarge`]. This is an
/// ergonomics aid, not a security bound: a hostile guest that ignores it is
/// still caught by the authority-side cap.
const AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TAIL_CAPTURE: usize =
    4 * AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_MESSAGE_LIMIT;
const _: () = assert!(
    AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TAIL_CAPTURE < AGENT_VM_CONTAINER_EXEC_OUTPUT_LIMIT,
    "the cooperative failure tail must stay below the exec capture cap so a \
     well-behaved guest never trips WorkspaceBootstrapOutputTooLarge",
);
/// Prepended to a truncated failure message. The marker leads (rather than
/// trails) because the truncation keeps the *tail* of the output: Nix prints the
/// line that actually explains the failure last, after a long run of
/// `copying path ...` substitution progress.
const AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TRUNCATION_MARKER: &str = "[truncated]\n";
const AGENT_VM_WORKSPACE_BOOTSTRAP_PREWARM_SAMPLE_LIMIT: usize = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmDaemonRuntimeConfig {
    lifecycle: AgentVmLifecycleRuntimeConfig,
    vm_http: VmHttpRuntimeConfig,
    /// Where per-run stdout/stderr logs go. Configured at the top level of the
    /// daemon config, not in `vm_http` (see
    /// [`DaemonConfig::agent_run_log_root`](crate::config::DaemonConfig::agent_run_log_root));
    /// the agent-VM runtime holds it because the VM arm is what writes there.
    agent_run_log_root: crate::config::AgentRunLogRoot,
}

/// Host facts the broker-VM (`broker_placement = vm`) arm needs that are *not*
/// fields of the parsed config: the raw host config text `broker_config_json`
/// derives the broker config from, and the host's **effective** audit DB path
/// (after the `--audit-db` override / config / default are resolved) the broker
/// reopens through the mounted audit directory. Bundled so they are present as a
/// unit — both or neither — and only for the vm arm.
#[derive(Clone, Debug, Eq, PartialEq)]
struct BrokerVmHostFacts {
    host_config_json: String,
    host_audit_db: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmLifecycleRuntimeConfig {
    pool: AgentNetworkPool,
    subnet_index_min: u16,
    subnet_index_max: u16,
    state_store: AgentVmSessionStateStore,
    ipv6_mode: Ipv6IsolationMode,
    broker_placement: BrokerPlacement,
    image: ContainerImage,
    /// Image for the dedicated broker VM, required only when
    /// `broker_placement == Vm` (the `new` constructor enforces this). `None`
    /// for the host-broker path, which runs no second VM.
    broker_image: Option<ContainerImage>,
    /// Host facts the vm arm needs (raw config text, effective audit DB path),
    /// attached post-construction by [`Self::with_broker_vm_host_facts`] because
    /// they are runtime facts (the file's raw text; the resolved audit path), not
    /// parsed config fields. Retained only for `broker_placement == Vm`; `None`
    /// for host placement and until the builder runs.
    broker_vm_host_facts: Option<BrokerVmHostFacts>,
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
    /// Host-observed broker reachability per running session, published by the
    /// network-health monitor and read by [`Self::list_sessions`]. Transient
    /// runtime state — deliberately not persisted to the lifecycle record.
    network_health: Arc<std::sync::Mutex<HashMap<SessionId, NetworkHealth>>>,
    /// The single daemon-lifetime network-health monitor, spawned lazily on the
    /// first session start (it needs an [`AuditLog`] handle, which arrives with
    /// the start request, not at construction).
    health_monitor: std::sync::Mutex<Option<NetworkHealthMonitorHandle>>,
    /// Live `broker_placement = vm` sessions, each mapped to the forwarder
    /// tailing its broker VM's mirrored log file. The vm arm keeps no in-process
    /// broker (so nothing in `running`), but the session is still runtime-attached
    /// to this daemon; this map lets [`Self::list_sessions`] report it as attached
    /// rather than orphaned, and lets teardown drain+stop the log tail.
    vm_broker_attached: Mutex<HashMap<SessionId, BrokerLogForwarder>>,
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
    #[error(
        "broker_placement = vm requires an agent_vm.lifecycle.broker_image (the dedicated broker VM image)"
    )]
    BrokerImageRequiredForVmPlacement,
    #[error(
        "broker_placement = vm requires ipv6_mode = ipv4_only_no_guest_ipv6: the broker VM creates \
         an IPv4-only internal network and the broker host-PF override is IPv4-only"
    )]
    VmPlacementRequiresIpv4Only,
    #[error(transparent)]
    AgentVm(#[from] AgentVmConfigError),
}

#[derive(Debug, thiserror::Error)]
pub enum AgentVmDaemonError {
    #[error("agent VM guest command must not be empty")]
    EmptyGuestCommand,
    #[error(
        "broker_placement = vm requires a session agent_kind (the broker mints with that agent's \
         GitHub App and selects its proxy secret); none was supplied"
    )]
    AgentKindRequiredForVmBroker,
    #[error(
        "agent-run sessions are not supported with broker_placement = vm: the v1 broker VM serves \
         clone + nix-cache + proxies only, with no agent-run route. Use broker_placement = host."
    )]
    AgentRunUnsupportedForVmBroker,
    #[error(
        "broker_placement = vm runtime config is incomplete (missing {0}); this is a writd wiring \
         bug — the daemon should carry it for vm placement"
    )]
    VmBrokerRuntimeConfigIncomplete(&'static str),
    #[error("bringing up the broker VM for session {session_id} failed: {source}")]
    BrokerVmLaunch {
        session_id: SessionId,
        #[source]
        source: crate::broker_vm_runner::BrokerVmLaunchError,
    },
    #[error("materialising broker VM session material failed: {0}")]
    BrokerVmMaterialize(#[from] crate::broker_vm::BrokerVmSessionError),
    #[error("cannot resolve the host audit DB path for the broker VM mount: {0}")]
    BrokerVmAuditDbPath(#[source] std::io::Error),
    #[error("refusing to mount the broker VM audit directory read-write: {0}")]
    BrokerVmAuditDirNotDedicated(#[from] crate::config::AuditDirNotDedicated),
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
    #[error(
        "agent VM workspace bootstrap {step} command did not complete within its {timeout:?} deadline"
    )]
    WorkspaceBootstrapExecTimedOut {
        step: &'static str,
        timeout: Duration,
    },
    #[error(
        "agent VM workspace bootstrap {step} command produced more than {limit} bytes of output"
    )]
    WorkspaceBootstrapOutputTooLarge { step: &'static str, limit: usize },
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
    #[error(transparent)]
    BrokerMaterialRemove(#[from] BrokerMaterialRemoveError),
}

/// Removing a stopped session's per-session broker material dir (copied secrets
/// included) failed. Surfaced — not swallowed — so the caller keeps the persisted
/// state record: that record is the only reconciliation obligation, and dropping
/// it would strand the copied secrets on disk with nothing left to drive a retry.
/// The daemon owns the material-path policy, so this is a daemon-layer error
/// rather than an [`AgentVmSessionManagerError`].
#[derive(Debug, thiserror::Error)]
#[error("removing broker VM material dir {path} failed: {source}")]
pub struct BrokerMaterialRemoveError {
    path: PathBuf,
    source: std::io::Error,
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
/// Ordering is `Cleanup` → `AuditClose` → `MaterialRemove` → `StateRemove`. A
/// failure short-circuits the remaining stages so the state record is preserved
/// for retry on the next boot.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AgentVmReconcileStage {
    /// Tear down the VM, firewall anchors, and network via the persisted
    /// state record. Idempotent against partially-cleaned infrastructure.
    Cleanup,
    /// Close the audit-DB session row. Idempotent against already-closed
    /// rows: the `UPDATE` only matches `closed_at IS NULL`.
    AuditClose,
    /// Remove the per-session broker material dir (copied secrets included)
    /// now that teardown has confirmed the broker VM — which mounts it
    /// read-only — is gone. Ordered before `StateRemove` so a removal failure
    /// keeps the state record, leaving the reconciliation obligation for the
    /// next boot rather than stranding the copied secrets on disk. A no-op
    /// (absence-based) for host placement, whose material dir never existed.
    MaterialRemove,
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
    #[error(transparent)]
    Material(#[from] BrokerMaterialRemoveError),
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
        agent_run_log_root: crate::config::AgentRunLogRoot,
    ) -> Result<Self, AgentVmDaemonRuntimeConfigError> {
        Self::check_bind_addr(vm_http.bind_addr())?;
        Ok(Self {
            lifecycle,
            vm_http,
            agent_run_log_root,
        })
    }

    /// The daemon-level invariant [`Self::new`] enforces, over the one field it
    /// actually reads.
    ///
    /// Exposed separately, and taking the bare address rather than a built
    /// `VmHttpRuntimeConfig`, so config validation can check it as what it is:
    /// an independent field. Demanding the whole runtime config would make this
    /// failure hide behind any *other* fault in the section, and would push it
    /// after the point where the section's directories get created. `new` still
    /// calls it, so there is one definition rather than two.
    pub fn check_bind_addr(bind_addr: Ipv4Addr) -> Result<(), AgentVmDaemonRuntimeConfigError> {
        if !bind_addr.is_unspecified() {
            return Err(AgentVmDaemonRuntimeConfigError::NonWildcardVmHttpBindAddr(
                bind_addr,
            ));
        }
        Ok(())
    }

    /// Attach the vm-arm host facts to the lifecycle config (see
    /// [`AgentVmLifecycleRuntimeConfig::with_broker_vm_host_facts`]). A no-op for
    /// host placement, so writd can call it unconditionally.
    pub fn with_broker_vm_host_facts(
        mut self,
        host_config_json: &str,
        host_audit_db: &Path,
    ) -> Self {
        self.lifecycle = self
            .lifecycle
            .with_broker_vm_host_facts(host_config_json, host_audit_db);
        self
    }

    pub fn lifecycle(&self) -> &AgentVmLifecycleRuntimeConfig {
        &self.lifecycle
    }

    pub fn vm_http(&self) -> &VmHttpRuntimeConfig {
        &self.vm_http
    }

    pub fn agent_run_log_root(&self) -> &Path {
        self.agent_run_log_root.as_path()
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
        broker_placement: BrokerPlacement,
        image: ContainerImage,
        broker_image: Option<ContainerImage>,
        resources: AgentVmResources,
        tools: AgentVmToolPaths,
    ) -> Result<Self, AgentVmLifecycleRuntimeConfigError> {
        if subnet_index_min > subnet_index_max {
            return Err(AgentVmLifecycleRuntimeConfigError::EmptySubnetIndexRange {
                min: subnet_index_min,
                max: subnet_index_max,
            });
        }
        // Enforce the broker_image invariant at the type boundary: `Some` iff
        // `Vm`. The vm arm launches a second VM from the image (so it is
        // required, else nothing runs), and host placement runs no broker VM (so
        // any image is ignored) — keeping `broker_image()` meaningful regardless
        // of which constructor path built the config.
        let broker_image = match broker_placement {
            BrokerPlacement::Vm => Some(
                broker_image
                    .ok_or(AgentVmLifecycleRuntimeConfigError::BrokerImageRequiredForVmPlacement)?,
            ),
            BrokerPlacement::Host => None,
        };
        // The broker VM creates an IPv4-only `--internal` network and the broker
        // host-PF override rejects an IPv6 firewall scope, so vm placement is
        // incompatible with dual-stack. Reject it here rather than launch a broker
        // VM whose agent start then fails every time.
        if broker_placement == BrokerPlacement::Vm
            && ipv6_mode == Ipv6IsolationMode::DualStackRequired
        {
            return Err(AgentVmLifecycleRuntimeConfigError::VmPlacementRequiresIpv4Only);
        }
        pool.allocate(subnet_index_min)?;
        pool.allocate(subnet_index_max)?;
        Ok(Self {
            pool,
            subnet_index_min,
            subnet_index_max,
            state_store,
            ipv6_mode,
            broker_placement,
            image,
            broker_image,
            broker_vm_host_facts: None,
            resources,
            tools,
        })
    }

    /// Attach the host facts the vm broker arm needs (the raw host config text the
    /// broker config is derived from, and the effective audit DB path). A no-op
    /// for host placement — these are meaningless without a broker VM — so the
    /// caller (writd) can supply them unconditionally and the Some-iff-`Vm`
    /// invariant holds regardless. Supplied post-construction because neither is a
    /// parsed config field: the raw text is what writd read off disk, and the
    /// audit path is resolved from `--audit-db` / config / default.
    pub fn with_broker_vm_host_facts(
        mut self,
        host_config_json: &str,
        host_audit_db: &Path,
    ) -> Self {
        self.broker_vm_host_facts = match self.broker_placement {
            BrokerPlacement::Vm => Some(BrokerVmHostFacts {
                host_config_json: host_config_json.to_string(),
                host_audit_db: host_audit_db.to_path_buf(),
            }),
            BrokerPlacement::Host => None,
        };
        self
    }

    /// Where the broker runs for this runtime. See [`BrokerPlacement`]. The
    /// session-start path branches on this to decide whether to spin the broker
    /// up in-process on the host (`Host`) or in a dedicated VM (`Vm`).
    pub fn broker_placement(&self) -> BrokerPlacement {
        self.broker_placement
    }

    /// The dedicated broker VM image; `Some` exactly when
    /// `broker_placement == Vm` (enforced by [`Self::new`]).
    pub fn broker_image(&self) -> Option<&ContainerImage> {
        self.broker_image.as_ref()
    }

    /// The raw host config text the vm arm derives the broker config from; `Some`
    /// only for `broker_placement == Vm` once [`Self::with_broker_vm_host_facts`]
    /// has run.
    pub fn host_config_json(&self) -> Option<&str> {
        self.broker_vm_host_facts
            .as_ref()
            .map(|facts| facts.host_config_json.as_str())
    }

    /// The host's effective audit DB path the vm arm mounts into the broker VM;
    /// `Some` only for `broker_placement == Vm` once
    /// [`Self::with_broker_vm_host_facts`] has run.
    pub fn host_audit_db(&self) -> Option<&Path> {
        self.broker_vm_host_facts
            .as_ref()
            .map(|facts| facts.host_audit_db.as_path())
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
            Self::MaterialRemove => "material_remove",
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

/// How often the network-health monitor re-checks every running session's
/// host-side broker reachability. Cheap: one shared `getifaddrs` snapshot per
/// tick regardless of the number of sessions.
const NETWORK_HEALTH_PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// Handle to the single daemon-lifetime network-health monitor task. Dropping
/// the daemon signals shutdown and aborts the task.
struct NetworkHealthMonitorHandle {
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

/// One monitor tick over an already-resolved set of `(session, gateway)` pairs.
///
/// Pure but for the shared `published` map it updates: it folds each session's
/// host-path observation into that session's debounce, publishes any changed
/// health value, and returns the islanding transitions (`-> Unreachable`) the
/// caller should audit. Debounce and published entries for sessions no longer
/// present are pruned. Kept side-effect-thin so it is unit-testable without a
/// container, the disk, or the clock.
fn network_health_tick(
    snapshot: &std::io::Result<Vec<HostIface>>,
    sessions: &[(SessionId, Ipv4Addr)],
    debounces: &mut HashMap<SessionId, ProbeDebounce>,
    published: &std::sync::Mutex<HashMap<SessionId, NetworkHealth>>,
) -> Vec<(SessionId, crate::agent_vm_lifecycle::HealthTransition, u32)> {
    let alive: HashSet<SessionId> = sessions.iter().map(|(id, _)| *id).collect();
    let mut islanding = Vec::new();
    for (session_id, gateway) in sessions {
        let observation = match snapshot {
            Ok(ifaces) => evaluate_host_path(ifaces, *gateway),
            // A snapshot we could not take is not evidence of islanding.
            Err(_) => ProbeObservation::Indeterminate,
        };
        let debounce = debounces.entry(*session_id).or_default();
        if let Some(transition) = debounce.observe(observation) {
            published.lock().unwrap().insert(*session_id, transition.to);
            if transition.is_islanding() {
                islanding.push((*session_id, transition, debounce.consecutive_failures()));
            }
        }
    }
    debounces.retain(|id, _| alive.contains(id));
    published.lock().unwrap().retain(|id, _| alive.contains(id));
    islanding
}

/// The daemon-lifetime monitor loop. Every `interval` it takes one host
/// interface snapshot (via `snapshot`, injected so tests can drive it) and
/// evaluates every running session's gateway against it, recording one audit
/// event per islanding transition (best-effort). Detection is entirely
/// host-side; the untrusted guest is never probed.
async fn run_network_health_monitor<F>(
    state_store: AgentVmSessionStateStore,
    pool: AgentNetworkPool,
    published: Arc<std::sync::Mutex<HashMap<SessionId, NetworkHealth>>>,
    audit: Arc<AuditLog>,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
    snapshot: F,
) where
    F: Fn() -> std::io::Result<Vec<HostIface>> + Send + Sync + 'static,
{
    let mut debounces: HashMap<SessionId, ProbeDebounce> = HashMap::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(interval) => {}
        }
        if *shutdown.borrow() {
            break;
        }

        let snapshot = snapshot();
        let store = state_store.clone();
        let states = match tokio::task::spawn_blocking(move || store.load_all()).await {
            Ok(Ok(states)) => states,
            // A transient load failure (or join error) says nothing about any
            // session's network; try again next tick.
            _ => continue,
        };
        let sessions: Vec<(SessionId, Ipv4Addr)> = states
            .iter()
            .filter(|state| state.status() == AgentVmSessionStateStatus::Running)
            .filter_map(|state| {
                pool.allocate(state.subnet_index())
                    .ok()
                    .map(|network| (state.session_id(), network.ipv4_gateway()))
            })
            .collect();

        for (session_id, transition, consecutive_failures) in
            network_health_tick(&snapshot, &sessions, &mut debounces, &published)
        {
            let record = AgentVmNetworkHealthEventRecord {
                session_id,
                observed_at: UnixMillis::now(),
                from_health: transition.from,
                to_health: transition.to,
                consecutive_failures,
            };
            if let Err(err) = audit.record_agent_vm_network_health_event(&record) {
                tracing::warn!(
                    session_id = %session_id,
                    error = %err,
                    "failed to record agent VM network-health event",
                );
            }
        }
    }
}

impl Drop for AgentVmDaemon {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.health_monitor.lock()
            && let Some(handle) = guard.take()
        {
            let _ = handle.shutdown.send(true);
            handle.task.abort();
        }
    }
}

#[cfg(test)]
mod broker_image_invariant_tests {
    use super::*;
    use crate::core::{Ipv4Cidr, Ipv6Cidr};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn build(
        placement: BrokerPlacement,
        broker_image: Option<&str>,
    ) -> Result<AgentVmLifecycleRuntimeConfig, AgentVmLifecycleRuntimeConfigError> {
        let pool = AgentNetworkPool::new(
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
            Ipv6Cidr::new("fd83:b6f2:e57::".parse::<Ipv6Addr>().unwrap(), 48).unwrap(),
        )
        .unwrap();
        AgentVmLifecycleRuntimeConfig::new(
            pool,
            252,
            253,
            AgentVmSessionStateStore::new("/tmp/writ-test-broker-image-invariant"),
            Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
            placement,
            ContainerImage::new("agent:latest").unwrap(),
            broker_image.map(|image| ContainerImage::new(image).unwrap()),
            AgentVmResources::new(1, 512).unwrap(),
            AgentVmToolPaths::new("/bin/container", "/bin/pf", "/bin/sudo"),
        )
    }

    #[test]
    fn host_discards_a_supplied_broker_image() {
        // Even the public constructor keeps `broker_image()` == None for Host.
        let cfg = build(BrokerPlacement::Host, Some("broker:latest")).unwrap();
        assert!(cfg.broker_image().is_none());
    }

    #[test]
    fn vm_requires_and_keeps_the_broker_image() {
        assert!(matches!(
            build(BrokerPlacement::Vm, None),
            Err(AgentVmLifecycleRuntimeConfigError::BrokerImageRequiredForVmPlacement)
        ));
        let cfg = build(BrokerPlacement::Vm, Some("broker:latest")).unwrap();
        assert_eq!(
            cfg.broker_image().map(ContainerImage::as_str),
            Some("broker:latest")
        );
    }

    #[test]
    fn vm_placement_rejects_dual_stack() {
        // The broker VM creates an IPv4-only internal network and its host-PF
        // override is IPv4-only, so vm + dual-stack is rejected at construction.
        let pool = AgentNetworkPool::new(
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
            Ipv6Cidr::new("fd83:b6f2:e57::".parse::<Ipv6Addr>().unwrap(), 48).unwrap(),
        )
        .unwrap();
        let result = AgentVmLifecycleRuntimeConfig::new(
            pool,
            252,
            253,
            AgentVmSessionStateStore::new("/tmp/writ-test-vm-dual-stack"),
            Ipv6IsolationMode::DualStackRequired,
            BrokerPlacement::Vm,
            ContainerImage::new("agent:latest").unwrap(),
            Some(ContainerImage::new("broker:latest").unwrap()),
            AgentVmResources::new(1, 512).unwrap(),
            AgentVmToolPaths::new("/bin/container", "/bin/pf", "/bin/sudo"),
        );
        assert!(matches!(
            result,
            Err(AgentVmLifecycleRuntimeConfigError::VmPlacementRequiresIpv4Only)
        ));
    }

    #[test]
    fn broker_audit_paths_resolve_relative_db_to_a_nonempty_mount_dir() {
        // A relative single-component audit DB path must not yield an empty mount
        // source (Path::parent() of "audit.db" is Some("")).
        let (db, dir) = resolve_broker_audit_paths(Path::new("audit.db")).unwrap();
        assert!(db.is_absolute());
        assert!(
            !dir.as_os_str().is_empty() && dir.is_absolute(),
            "mount dir must be a real absolute path, got {dir:?}"
        );
        // An absolute path's directory is preserved.
        let (_, dir) = resolve_broker_audit_paths(Path::new("/var/lib/writ/audit.db")).unwrap();
        assert_eq!(dir, Path::new("/var/lib/writ"));
    }
}

#[cfg(test)]
mod network_health_monitor_tests {
    use super::*;

    fn snapshot_with_gateway(gateway: Ipv4Addr) -> std::io::Result<Vec<HostIface>> {
        Ok(vec![
            HostIface {
                name: "lo0".into(),
                addr: Ipv4Addr::LOCALHOST,
                up: true,
                loopback: true,
            },
            HostIface {
                name: "vmenet0".into(),
                addr: gateway,
                up: true,
                loopback: false,
            },
        ])
    }

    fn snapshot_without_gateway() -> std::io::Result<Vec<HostIface>> {
        Ok(vec![HostIface {
            name: "lo0".into(),
            addr: Ipv4Addr::LOCALHOST,
            up: true,
            loopback: true,
        }])
    }

    fn published_health(
        published: &std::sync::Mutex<HashMap<SessionId, NetworkHealth>>,
        id: SessionId,
    ) -> Option<NetworkHealth> {
        published.lock().unwrap().get(&id).copied()
    }

    #[test]
    fn flips_to_unreachable_after_threshold_then_recovers() {
        let id = SessionId::new();
        let gateway = Ipv4Addr::new(192, 168, 252, 1);
        let sessions = vec![(id, gateway)];
        let mut debounces = HashMap::new();
        let published = std::sync::Mutex::new(HashMap::new());

        // A healthy tick publishes Reachable (Unknown -> Reachable is not islanding).
        let events = network_health_tick(
            &snapshot_with_gateway(gateway),
            &sessions,
            &mut debounces,
            &published,
        );
        assert!(events.is_empty());
        assert_eq!(
            published_health(&published, id),
            Some(NetworkHealth::Reachable)
        );

        // THRESHOLD-1 unreachable ticks: still Reachable, no event yet.
        for _ in 0..(crate::agent_vm_lifecycle::NETWORK_HEALTH_FAILURE_THRESHOLD - 1) {
            let events = network_health_tick(
                &snapshot_without_gateway(),
                &sessions,
                &mut debounces,
                &published,
            );
            assert!(events.is_empty());
        }
        assert_eq!(
            published_health(&published, id),
            Some(NetworkHealth::Reachable)
        );

        // The threshold-th unreachable tick: exactly one islanding event.
        let events = network_health_tick(
            &snapshot_without_gateway(),
            &sessions,
            &mut debounces,
            &published,
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, id);
        assert!(events[0].1.is_islanding());
        assert_eq!(
            published_health(&published, id),
            Some(NetworkHealth::Unreachable)
        );

        // Recovery flips back to Reachable and emits no islanding event.
        let events = network_health_tick(
            &snapshot_with_gateway(gateway),
            &sessions,
            &mut debounces,
            &published,
        );
        assert!(events.iter().all(|event| !event.1.is_islanding()));
        assert_eq!(
            published_health(&published, id),
            Some(NetworkHealth::Reachable)
        );
    }

    #[test]
    fn indeterminate_snapshot_never_islands() {
        let id = SessionId::new();
        let gateway = Ipv4Addr::new(192, 168, 252, 1);
        let sessions = vec![(id, gateway)];
        let mut debounces = HashMap::new();
        let published = std::sync::Mutex::new(HashMap::new());
        let failed: std::io::Result<Vec<HostIface>> =
            Err(std::io::Error::other("getifaddrs failed"));

        for _ in 0..(crate::agent_vm_lifecycle::NETWORK_HEALTH_FAILURE_THRESHOLD + 2) {
            let events = network_health_tick(&failed, &sessions, &mut debounces, &published);
            assert!(events.is_empty());
        }
        // Health stays Unknown — a snapshot we could not take is not islanding.
        assert_eq!(published_health(&published, id), None);
    }

    #[test]
    fn prunes_sessions_that_disappear() {
        let id = SessionId::new();
        let gateway = Ipv4Addr::new(192, 168, 252, 1);
        let mut debounces = HashMap::new();
        let published = std::sync::Mutex::new(HashMap::new());

        network_health_tick(
            &snapshot_with_gateway(gateway),
            &[(id, gateway)],
            &mut debounces,
            &published,
        );
        assert!(published.lock().unwrap().contains_key(&id));

        // A tick that no longer lists the session prunes its state.
        network_health_tick(
            &snapshot_with_gateway(gateway),
            &[],
            &mut debounces,
            &published,
        );
        assert!(!published.lock().unwrap().contains_key(&id));
        assert!(debounces.is_empty());
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

/// Resolve the host audit DB path and the directory the broker VM mounts to reach
/// it. Returns `(absolute_db, mount_dir)`. The path is made absolute (relative to
/// writd's cwd, where the host opened the DB) first, so a relative single-component
/// path like `audit.db` — whose `parent()` is empty — does not yield a `source=`
/// (empty) virtiofs mount the broker VM cannot open.
fn resolve_broker_audit_paths(
    host_audit_db: &Path,
) -> Result<(PathBuf, PathBuf), AgentVmDaemonError> {
    let absolute =
        std::path::absolute(host_audit_db).map_err(AgentVmDaemonError::BrokerVmAuditDbPath)?;
    let mount_dir = absolute
        .parent()
        .ok_or(AgentVmDaemonError::VmBrokerRuntimeConfigIncomplete(
            "host_audit_db parent",
        ))?
        .to_path_buf();
    Ok((absolute, mount_dir))
}

/// Remove a directory tree, treating an already-absent path as success. Used for
/// the best-effort removal of a session's broker-VM material directory.
fn remove_dir_all_if_present(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn nix_prewarm_url_for_broker_url(broker_url: &str) -> String {
    format!(
        "{}{}",
        broker_url.trim_end_matches('/'),
        VM_NIX_PREWARM_PATH_PREFIX
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

fn workspace_bootstrap_prewarm_diagnostic_from_audit(
    audit: &AuditLog,
    session_id: SessionId,
) -> Option<String> {
    let entries = match audit.list_nix_cache_requests_for_session(session_id) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::warn!(
                %session_id,
                error = %err,
                "could not read Nix cache audit rows for workspace bootstrap diagnostic",
            );
            return None;
        }
    };
    workspace_bootstrap_prewarm_diagnostic(&entries)
}

fn workspace_bootstrap_prewarm_diagnostic(entries: &[NixCacheAuditEntry]) -> Option<String> {
    let mut narinfo_hits = 0usize;
    let mut narinfo_misses = 0usize;
    let mut nar_hits = 0usize;
    let mut nar_misses = 0usize;
    let mut missing_narinfo_hashes = Vec::new();

    for entry in entries {
        if !is_prewarm_target(&entry.target) {
            continue;
        }
        match (entry.route, entry.http_status) {
            (NixCacheAuditRoute::NarInfo, Some(200)) => narinfo_hits += 1,
            (NixCacheAuditRoute::NarInfo, Some(404)) => {
                narinfo_misses += 1;
                if missing_narinfo_hashes.len() < AGENT_VM_WORKSPACE_BOOTSTRAP_PREWARM_SAMPLE_LIMIT
                {
                    missing_narinfo_hashes.push(prewarm_narinfo_hash(&entry.target));
                }
            }
            (NixCacheAuditRoute::Nar, Some(200)) => nar_hits += 1,
            (NixCacheAuditRoute::Nar, Some(404)) => nar_misses += 1,
            (NixCacheAuditRoute::CacheInfo | NixCacheAuditRoute::Unsupported, _)
            | (NixCacheAuditRoute::NarInfo | NixCacheAuditRoute::Nar, _) => {}
        }
    }

    if narinfo_misses == 0 && nar_misses == 0 {
        return None;
    }

    let mut lines = vec![format!(
        "pre-warm cache diagnostic: strict /v1/nix/prewarm substituter had misses during \
         workspace bootstrap (narinfo: {narinfo_misses} missing, {narinfo_hits} served; \
         nar: {nar_misses} missing, {nar_hits} served)."
    )];
    if !missing_narinfo_hashes.is_empty() {
        lines.push(format!(
            "first missing narinfo hashes: {}",
            missing_narinfo_hashes.join(", ")
        ));
    }
    lines.push(
        "refresh the pre-warm cache for this repo/commit, or retry with \
         `--warm sources`/`--warm none` if devShell warming is not required."
            .to_string(),
    );
    Some(lines.join("\n"))
}

fn is_prewarm_target(target: &str) -> bool {
    target
        .strip_prefix(VM_NIX_PREWARM_PATH_PREFIX)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn prewarm_narinfo_hash(target: &str) -> String {
    target
        .strip_prefix(VM_NIX_PREWARM_PATH_PREFIX)
        .and_then(|suffix| suffix.strip_prefix('/'))
        .and_then(|suffix| suffix.strip_suffix(".narinfo"))
        .filter(|hash| !hash.contains('/'))
        .unwrap_or(target)
        .to_string()
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
