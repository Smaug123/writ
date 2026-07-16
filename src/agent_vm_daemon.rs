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
/// The strict, pre-warm-only substituter URL. Injected only when the broker has
/// a `nix_prewarm_cache_dir` configured: its presence is what switches the
/// guest's devShell warm onto the local-only `/v1/nix/prewarm` view. Absent (no
/// pre-warming in this deployment), the warm keeps the session-default proxied
/// substituter, exactly as before.
pub const AGENT_VM_NIX_PREWARM_URL_ENV: &str = "WRIT_NIX_PREWARM_URL";
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
    ) -> Result<Self, AgentVmDaemonRuntimeConfigError> {
        if !vm_http.bind_addr().is_unspecified() {
            return Err(AgentVmDaemonRuntimeConfigError::NonWildcardVmHttpBindAddr(
                vm_http.bind_addr(),
            ));
        }
        Ok(Self { lifecycle, vm_http })
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

impl AgentVmDaemon {
    pub fn new(config: AgentVmDaemonRuntimeConfig) -> Self {
        Self {
            config,
            running: Mutex::new(HashMap::new()),
            subnet_allocation_lock: Mutex::new(()),
            session_locks: Mutex::new(HashMap::new()),
            network_health: Arc::new(std::sync::Mutex::new(HashMap::new())),
            health_monitor: std::sync::Mutex::new(None),
            vm_broker_attached: Mutex::new(HashMap::new()),
        }
    }

    /// Spawn the daemon-lifetime network-health monitor if it is not already
    /// running. Called on the first session start, when an [`AuditLog`] handle
    /// is available. The monitor inspects only the host's own interfaces; it
    /// never probes the untrusted guest.
    fn ensure_network_health_monitor(&self, audit: Arc<AuditLog>) {
        let mut guard = self.health_monitor.lock().unwrap();
        if guard.is_some() {
            return;
        }
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_network_health_monitor(
            self.config.lifecycle.state_store.clone(),
            self.config.lifecycle.pool,
            Arc::clone(&self.network_health),
            audit,
            NETWORK_HEALTH_PROBE_INTERVAL,
            shutdown_rx,
            host_interfaces,
        ));
        *guard = Some(NetworkHealthMonitorHandle {
            shutdown: shutdown_tx,
            task,
        });
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
                    agent_kind,
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
                    Some(agent_kind),
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
    ///
    /// Teardown only. Removing the per-session material dir (copied secrets) is
    /// a separate [`Self::spawn_remove_broker_material`] step the callers run
    /// once this confirms the broker VM — which mounts the material read-only —
    /// is gone, so its failure can keep the state record for retry instead of
    /// being swallowed here.
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

    /// Run [`Self::spawn_cleanup_session`], flattening the join result and the
    /// inner teardown result into one error type.
    async fn run_cleanup_session(&self, session_id: SessionId) -> Result<(), AgentVmDaemonError> {
        match self.spawn_cleanup_session(session_id).await {
            Ok(inner) => inner.map_err(Into::into),
            Err(join) => Err(join.into()),
        }
    }

    /// The root under which each session's broker-VM host material lives
    /// (`<state_dir>/broker-vm/<session_id>/…`). Derived from the state directory
    /// so the start arm (which writes the material) and stop/reconcile (which
    /// remove it via [`Self::spawn_remove_broker_material`]) agree without extra
    /// configuration.
    fn broker_material_root(&self) -> PathBuf {
        self.config.lifecycle.state_store.dir().join("broker-vm")
    }

    /// Spawn a log tail for a broker VM, pointed at its mirrored log file on the
    /// shared session mount. Used at start, and to re-attach when a stop/cleanup
    /// fails with the broker VM (and its log) still live.
    fn spawn_broker_log_forwarder(&self, session_id: SessionId) -> BrokerLogForwarder {
        BrokerLogForwarder::spawn(
            BrokerVmSessionPaths::new(&self.broker_material_root(), session_id)
                .staging_dir()
                .join(BROKER_VM_LOG_FILE),
            session_id,
            BROKER_VM_READY_POLL_INTERVAL,
        )
    }

    /// Re-attach a broker-VM log tail (only when `had` — i.e. there was one) after
    /// a failed stop/cleanup, so a still-live session stays observable and
    /// retryable rather than appearing orphaned with forwarding stopped.
    async fn reattach_broker_log_forwarder_if(&self, had: bool, session_id: SessionId) {
        if had {
            let forwarder = self.spawn_broker_log_forwarder(session_id);
            self.vm_broker_attached
                .lock()
                .await
                .insert(session_id, forwarder);
        }
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

    /// Remove this session's per-session broker material dir — copied secrets
    /// included — on a blocking thread. Nested result as in
    /// [`Self::spawn_cleanup_session`].
    ///
    /// MUST run only after teardown has confirmed the broker VM (which mounts
    /// the material read-only) is gone, and MUST precede
    /// [`Self::spawn_remove_session_state`]: a removal failure is surfaced, not
    /// swallowed, so the caller keeps the persisted state record. That record is
    /// the sole reconciliation obligation, so dropping it while the copied
    /// secrets remain would strand them on disk with nothing to drive a retry.
    /// Absence-based (a missing dir is a success), so it is a no-op for host
    /// placement — whose material dir never existed — and idempotent on retry.
    async fn spawn_remove_broker_material(
        &self,
        session_id: SessionId,
    ) -> Result<Result<(), BrokerMaterialRemoveError>, tokio::task::JoinError> {
        let session_dir = BrokerVmSessionPaths::new(&self.broker_material_root(), session_id)
            .session_dir()
            .to_path_buf();
        tokio::task::spawn_blocking(move || {
            remove_dir_all_if_present(&session_dir).map_err(|source| BrokerMaterialRemoveError {
                path: session_dir,
                source,
            })
        })
        .await
    }

    async fn stop_session_locked<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: &Arc<BrokerState<S>>,
        session_id: SessionId,
    ) -> Result<(), AgentVmDaemonError> {
        // Drain+stop the broker log tail *before* cleanup — a successful stop
        // removes the per-session material dir that holds the log file (the
        // `spawn_remove_broker_material` step below), so a drain afterwards would
        // find nothing and lose the tail. Remove first so the lock is not held
        // across the drain await.
        let forwarder = self.vm_broker_attached.lock().await.remove(&session_id);
        let had_forwarder = forwarder.is_some();
        if let Some(forwarder) = forwarder {
            forwarder.drain_and_stop().await;
        }

        if let Err(err) = self.run_cleanup_session(session_id).await {
            // Cleanup failed: teardown leaves the material dir (and log) for the
            // retry, so the broker VM may still be live. Re-attach a fresh log tail
            // so the session stays reported as attached (not orphaned) and keeps
            // forwarding until a later stop succeeds.
            //
            // A `Stop` cleanup error means the state record existed — so this IS a
            // managed agent-VM session — but the VM/PF/network teardown failed.
            // Revoke broker authority anyway, independently of the teardown: close
            // the audit session (the broker refuses to mint once `closed_at` is set)
            // and shut down + drop the in-process broker, so a possibly-still-live
            // guest is left de-authorised rather than authorised. A missing state
            // record (`State`/`NotFound` — e.g. an ordinary broker session that was
            // never an agent VM) is excluded, so an unrelated session's audit row is
            // not closed. The persisted state record is kept for retry regardless.
            if matches!(
                &err,
                AgentVmDaemonError::Manager(AgentVmSessionManagerError::Stop(_))
            ) {
                close_audit_session_best_effort(state, session_id);
                if let Some(running) = self.running.lock().await.remove(&session_id)
                    && let Err(shutdown) = running.shutdown().await
                {
                    tracing::warn!(
                        session_id = %session_id,
                        error = %shutdown,
                        "agent VM stop could not shut down broker after teardown failure",
                    );
                }
            }
            self.reattach_broker_log_forwarder_if(had_forwarder, session_id)
                .await;
            return Err(err);
        }

        let audit_close = state.audit.close_session(session_id, UnixMillis::now());
        let http_shutdown = match self.running.lock().await.remove(&session_id) {
            Some(running) => running.shutdown().await,
            None => Ok(()),
        };

        match (audit_close, http_shutdown) {
            (Ok(()), Ok(())) => {
                // Remove the copied secrets before dropping the state record, so a
                // removal failure keeps the record (and thus the reconciliation
                // obligation) rather than stranding the secrets on disk.
                self.spawn_remove_broker_material(session_id).await??;
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

    /// Signal the guest that the broker is up (so the boot-time egress gate's
    /// positive control + broker-ready wait can proceed), then wait for the
    /// guest's bootstrap sentinels. Used for EVERY session: both guest scripts
    /// run the gate and signal bootstrap-ok/failed identically, so a gate
    /// failure is surfaced here rather than returning a "started" VM the gate
    /// then kills. Released only after the broker has spawned, so it cannot lie.
    async fn release_and_wait_for_workspace_bootstrap_with_timeout(
        &self,
        vm_name: &str,
        timeout: Duration,
    ) -> Result<(), AgentVmDaemonError> {
        // The whole release+wait dance shares one budget: `timeout`. Every
        // `container exec` runs under the *remaining* budget so a wedged guest
        // exec cannot outlast it (the elapsed check used to sit only *after*
        // the exec returned, so a hung exec never reached it). The guest is
        // treated as compromised, so this bound is authority-side, not advisory.
        let start = Instant::now();

        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(AgentVmDaemonError::WorkspaceBootstrapTimedOut { timeout });
        }
        self.run_container_exec_shell(
            vm_name,
            "release guest bootstrap",
            &format!(
                "mkdir -p /run/writ-agent-vm && touch {}",
                AGENT_VM_WORKSPACE_BROKER_READY_PATH
            ),
            remaining,
        )
        .await?;

        let mut poll_count = 0;
        loop {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(AgentVmDaemonError::WorkspaceBootstrapTimedOut { timeout });
            }
            let output = self
                .run_container_exec_shell(
                    vm_name,
                    "inspect workspace bootstrap",
                    &format!(
                        "if [ -f {ok} ]; then printf ok; \
                         elif [ -f {failed} ]; then printf 'failed\\n'; tail -c {tail} {failed}; \
                         else printf pending; fi",
                        ok = AGENT_VM_WORKSPACE_BOOTSTRAP_OK_PATH,
                        failed = AGENT_VM_WORKSPACE_BOOTSTRAP_FAILED_PATH,
                        tail = AGENT_VM_WORKSPACE_BOOTSTRAP_FAILURE_TAIL_CAPTURE,
                    ),
                    remaining,
                )
                .await?;
            let status = output.stdout.trim();
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

    /// Run `sh -c <script>` inside the guest VM via `container exec`, capturing
    /// its output under a byte cap and the whole invocation under `deadline`.
    ///
    /// Both bounds matter because the guest is untrusted: the payload of the
    /// bootstrap inspect is a guest-controlled file, so an unbounded read could
    /// exhaust host memory, and a wedged exec could hang past the caller's
    /// overall timeout. [`ProcessInvocation::run_capturing_output_bounded`] caps
    /// the capture (and kills the child if it floods), and `kill_on_drop` means
    /// the outer `tokio::time::timeout` cancelling the future kills the child
    /// rather than leaking it.
    async fn run_container_exec_shell(
        &self,
        vm_name: &str,
        step: &'static str,
        script: &str,
        deadline: Duration,
    ) -> Result<BoundedOutput, AgentVmDaemonError> {
        let invocation = ProcessInvocation::new(
            self.config.lifecycle.tools.container(),
            ["exec", vm_name, "sh", "-c", script],
        );
        let output = match tokio::time::timeout(
            deadline,
            invocation.run_capturing_output_bounded(AGENT_VM_CONTAINER_EXEC_OUTPUT_LIMIT),
        )
        .await
        {
            Err(_elapsed) => {
                return Err(AgentVmDaemonError::WorkspaceBootstrapExecTimedOut {
                    step,
                    timeout: deadline,
                });
            }
            Ok(Err(ProcessInvocationError::Run { source, .. })) => {
                return Err(AgentVmDaemonError::WorkspaceBootstrapSpawn { step, source });
            }
            Ok(Err(other)) => {
                return Err(AgentVmDaemonError::WorkspaceBootstrapSpawn {
                    step,
                    source: std::io::Error::other(other.to_string()),
                });
            }
            Ok(Ok(output)) => output,
        };
        if output.truncated {
            return Err(AgentVmDaemonError::WorkspaceBootstrapOutputTooLarge {
                step,
                limit: AGENT_VM_CONTAINER_EXEC_OUTPUT_LIMIT,
            });
        }
        match output.status {
            Some(status) if status.success() => Ok(output),
            status => Err(AgentVmDaemonError::WorkspaceBootstrapCommandFailed {
                step,
                status: status
                    .and_then(|status| status.code())
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".into()),
                stderr: output.stderr.trim().to_string(),
            }),
        }
    }

    async fn cleanup_failed_started_session(
        &self,
        session_id: SessionId,
    ) -> Result<(), AgentVmDaemonError> {
        // Drain the log tail *before* the material dir holding the log file is
        // removed (the `spawn_remove_broker_material` step below). A fully-started
        // (inserted) session drains here; a start that failed before insertion
        // drained its own local forwarder already, so this is then a no-op.
        let forwarder = self.vm_broker_attached.lock().await.remove(&session_id);
        let had_forwarder = forwarder.is_some();
        if let Some(forwarder) = forwarder {
            forwarder.drain_and_stop().await;
        }

        if let Err(err) = self.run_cleanup_session(session_id).await {
            // Failed teardown leaves the material dir (and log) for the retry, so
            // re-attach a fresh tail to keep a still-live session observable.
            self.reattach_broker_log_forwarder_if(had_forwarder, session_id)
                .await;
            return Err(err);
        }

        if let Some(running) = self.running.lock().await.remove(&session_id) {
            running.shutdown().await?;
        }

        // Remove the copied secrets before dropping the state record: a removal
        // failure keeps the record so the reconciliation obligation survives.
        self.spawn_remove_broker_material(session_id).await??;
        self.spawn_remove_session_state(session_id).await??;
        Ok(())
    }

    /// Treat every persisted session as a cleanup obligation and drive it to
    /// completion: tear down the VM/firewall/network via the persisted facts and
    /// close the audit row (revoking broker authority) — each attempted regardless
    /// of the other's outcome — then remove the per-session material dir (copied
    /// secrets), and finally remove the state record.
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
        // Run infrastructure teardown AND authority revocation independently: a
        // failure of either must not skip the other. Every persisted session here
        // is a managed agent-VM session; teardown removes its (possibly autonomous)
        // broker VM, and closing the audit row revokes that broker's authority to
        // mint — the host broker and any broker VM both consult `closed_at` before
        // minting.
        //
        // Both are attempted before either is reported: skipping the close on a
        // teardown failure would leave a still-live broker VM holding authority (the
        // original fail-open), and skipping teardown on a close failure would leave
        // the broker VM running — worse, under `SQLITE_BUSY` held by that very VM,
        // tearing it down is often what frees the audit-DB lock so a later retry can
        // close. Any failure keeps the state record (we stop before removing it) so
        // the next boot retries, and the daemon refuses to start while an obligation
        // remains.
        let cleanup = self.spawn_cleanup_session(session_id).await;
        let audit_close = audit.close_session(session_id, UnixMillis::now());

        // A teardown failure (a still-live VM) is the more urgent condition, so
        // report it; retain any co-occurring audit-close failure in the log rather
        // than dropping it silently.
        let cleanup_failure = match cleanup {
            Err(join) => Some((AgentVmReconcileStage::Cleanup, join.into())),
            Ok(Err(err)) => Some((AgentVmReconcileStage::Cleanup, err.into())),
            Ok(Ok(())) => None,
        };
        if let Some(failure) = cleanup_failure {
            if let Err(err) = &audit_close {
                tracing::warn!(
                    session_id = %session_id,
                    error = %err,
                    "agent VM reconcile could not close audit session (teardown also failed)",
                );
            }
            return Err(failure);
        }
        if let Err(err) = audit_close {
            return Err((AgentVmReconcileStage::AuditClose, err.into()));
        }

        // Remove the copied secrets before the state record: a failure here keeps
        // the record so this session is retried on the next boot rather than the
        // secrets being stranded with no reconciliation obligation left.
        match self.spawn_remove_broker_material(session_id).await {
            Err(join) => return Err((AgentVmReconcileStage::MaterialRemove, join.into())),
            Ok(Err(err)) => return Err((AgentVmReconcileStage::MaterialRemove, err.into())),
            Ok(Ok(())) => {}
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
        let vm_attached = self.vm_broker_attached.lock().await;
        // A session is runtime-attached if its in-process broker is live (host) or
        // it is a live vm-broker session (no in-process broker, tracked separately).
        let attached = |id: &SessionId| running.contains_key(id) || vm_attached.contains_key(id);
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
                runtime_attached: attached(&state.session_id()),
                // Health is only meaningful for a runtime-attached session (the
                // monitor publishes it); a detached/persisted-only session is
                // genuinely Unknown here.
                network_health: if attached(&state.session_id()) {
                    self.network_health
                        .lock()
                        .unwrap()
                        .get(&state.session_id())
                        .copied()
                        .unwrap_or(NetworkHealth::Unknown)
                } else {
                    NetworkHealth::Unknown
                },
            })
            .collect())
    }

    /// The guest environment variables shared by both broker placements: the
    /// broker URL and bearer token the agent authenticates with, the nix-cache
    /// proxy and trust config (served by the broker wherever it runs), the
    /// egress-gate IPv6 posture, and the strict pre-warm substituter when set.
    fn build_agent_guest_env(
        &self,
        broker_url: &str,
        bearer_token: &str,
    ) -> Result<Vec<AgentVmGuestEnvVar>, AgentVmDaemonError> {
        let trusted_public_keys = self
            .config
            .vm_http
            .nix_cache()
            .trusted_public_keys()
            .nix_conf_value();
        let mut guest_env = vec![
            AgentVmGuestEnvVar::new(AGENT_VM_BROKER_URL_ENV, broker_url.to_string())?,
            AgentVmGuestEnvVar::new(AGENT_VM_BROKER_TOKEN_ENV, bearer_token.to_string())?,
            AgentVmGuestEnvVar::new(
                AGENT_VM_NIX_CACHE_URL_ENV,
                nix_cache_url_for_broker_url(broker_url),
            )?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_BASIC_LOGIN_ENV, VM_NIX_BASIC_LOGIN)?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_NETRC_ENV, AGENT_VM_NIX_NETRC_PATH)?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_TRUSTED_PUBLIC_KEYS_ENV, trusted_public_keys)?,
            AgentVmGuestEnvVar::new(AGENT_VM_NIX_CONF_DIR_ENV, AGENT_VM_NIX_CONF_DIR)?,
        ];
        // Tell the boot-time egress gate whether to enforce no-guest-IPv6.
        // Exhaustive over the mode so a future variant must decide: the dual-stack
        // mode provisions a ULA on purpose, so only the no-guest-IPv6 mode forbids
        // a global-scope address.
        let require_no_ipv6 = match self.config.lifecycle.ipv6_mode {
            Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 => "1",
            Ipv6IsolationMode::DualStackRequired => "0",
        };
        guest_env.push(AgentVmGuestEnvVar::new(
            AGENT_VM_EGRESS_GATE_REQUIRE_NO_IPV6_ENV,
            require_no_ipv6,
        )?);
        // Advertise the strict pre-warm-only substituter exactly when the broker
        // actually serves it: its presence pins the devShell warm to the broker's
        // /v1/nix/prewarm so the warm is provably served offline from the
        // pre-warm + flake-input archives. Both placements now serve it — the host
        // broker directly, the vm broker via the re-pointed nix_prewarm_cache_dir
        // and its read-only mount (see broker_vm::with_prewarm_cache_mount) — so
        // the sole gate is whether the operator configured a pre-warm dir.
        if self.config.vm_http.nix_prewarm_cache_dir().is_some() {
            guest_env.push(AgentVmGuestEnvVar::new(
                AGENT_VM_NIX_PREWARM_URL_ENV,
                nix_prewarm_url_for_broker_url(broker_url),
            )?);
        }
        Ok(guest_env)
    }

    async fn start_session_after_audit_opened<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        session_id: SessionId,
        agent_kind: Option<AgentKind>,
        workspace: Option<AgentVmWorkspaceBootstrap>,
        guest_command: Vec<String>,
        agent_runs: Option<VmHttpAgentRunService<S>>,
    ) -> Result<AgentVmStarted, AgentVmDaemonError> {
        // Broker placement seam (see docs/vmnet-accept-bug-and-broker-vm-plan.md):
        // the host path runs an in-process broker; the vm path runs the broker in a
        // dedicated VM, working around the macOS vmnet accept() defect. The vm arm
        // diverges enough (no in-process broker, broker launched before the agent)
        // that it lives in its own method.
        match self.config.lifecycle.broker_placement {
            BrokerPlacement::Host => {}
            BrokerPlacement::Vm => {
                // The v1 broker VM serves clone + nix-cache + proxies only — no
                // agent-run config/outcome routes. Reject an agent-run session
                // up front rather than start a VM whose guest would 404 fetching
                // its run config and leave RunAgent waiting for an outcome that
                // can never be uploaded.
                if agent_runs.is_some() {
                    return Err(AgentVmDaemonError::AgentRunUnsupportedForVmBroker);
                }
                return self
                    .start_vm_broker_session(
                        state,
                        session_id,
                        agent_kind,
                        workspace,
                        guest_command,
                    )
                    .await;
            }
        }

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
            let broker_ports = BrokerPorts::new([broker_port])?;
            let guest_env =
                self.build_agent_guest_env(&broker_url, prepared.bearer_token().as_str())?;
            let guest_command = wrap_guest_command(workspace.as_ref(), guest_command)?;
            let plan = self.build_agent_plan(
                session_id,
                subnet_index,
                broker_ports,
                guest_env,
                guest_command,
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
        // Start the host-side network-health monitor (idempotent). Lazy here
        // because it needs the audit handle, which arrives with the request.
        self.ensure_network_health_monitor(Arc::clone(&state.audit));
        // Release broker-ready and wait for the guest's bootstrap sentinels for
        // EVERY session: both guest scripts run the egress gate and signal
        // bootstrap-ok/failed, so a gate failure (or workspace-init failure) is
        // surfaced before we report the session started.
        if let Err(mut err) = self
            .release_and_wait_for_workspace_bootstrap(plan.names().vm())
            .await
        {
            self.annotate_workspace_bootstrap_error_with_prewarm_audit(
                state.audit.as_ref(),
                session_id,
                &mut err,
            );
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

    /// Build the agent VM plan from the daemon's lifecycle config. Shared by both
    /// placements; the vm arm builds it twice (a claim plan with an empty guest
    /// env, then a boot plan with the broker VM's URL once discovered).
    fn build_agent_plan(
        &self,
        session_id: SessionId,
        subnet_index: u16,
        broker_ports: BrokerPorts,
        guest_env: Vec<AgentVmGuestEnvVar>,
        guest_command: Vec<String>,
    ) -> Result<AgentVmSessionPlan, AgentVmDaemonError> {
        Ok(AgentVmSessionPlan::new_with_guest_env(
            session_id,
            self.config.lifecycle.pool,
            subnet_index,
            broker_ports,
            self.config.vm_http.broker_port_range(),
            self.config.lifecycle.ipv6_mode,
            self.config.lifecycle.broker_placement,
            self.config.lifecycle.image.clone(),
            guest_env,
            guest_command,
            self.config.lifecycle.resources,
            self.config.lifecycle.tools.clone(),
        )?)
    }

    /// The `broker_placement = vm` start arm: bring up a dedicated broker VM, point
    /// the agent VM at it, and reap everything on any failure.
    ///
    /// Unlike the host arm there is no in-process broker. The broker VM must come
    /// up first (it creates the shared `--internal` network the agent joins), so
    /// the order is: reserve the subnet (claim, under the lock) → materialise the
    /// broker session material + launch the broker VM (unlocked, slow) → discover
    /// its IP → boot the agent VM with the broker URL + bearer + PF allow target →
    /// promote to Running → release and wait for bootstrap.
    ///
    /// The agent boot uses `start_agent_vm_session` + `mark_running` rather than
    /// `complete_agent_vm_session_start`: the latter removes the claimed record on
    /// a boot failure, but here the record (Vm placement) is exactly what lets one
    /// `cleanup_failed_started_session` reap the agent VM *and* the broker VM and
    /// its material (see the persisted-state teardown). So any failure past the
    /// claim routes through that single rollback.
    async fn start_vm_broker_session<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        session_id: SessionId,
        agent_kind: Option<AgentKind>,
        workspace: Option<AgentVmWorkspaceBootstrap>,
        guest_command: Vec<String>,
    ) -> Result<AgentVmStarted, AgentVmDaemonError> {
        // vm placement needs an agent_kind (which app the broker mints with) and
        // the host facts writd threads in; missing host facts are a wiring bug.
        let agent_kind = agent_kind.ok_or(AgentVmDaemonError::AgentKindRequiredForVmBroker)?;
        let broker_image = self
            .config
            .lifecycle
            .broker_image()
            .ok_or(AgentVmDaemonError::VmBrokerRuntimeConfigIncomplete(
                "broker_image",
            ))?
            .clone();
        let host_config_json = self
            .config
            .lifecycle
            .host_config_json()
            .ok_or(AgentVmDaemonError::VmBrokerRuntimeConfigIncomplete(
                "host_config_json",
            ))?
            .to_string();
        let (host_audit_db, audit_dir) =
            resolve_broker_audit_paths(self.config.lifecycle.host_audit_db().ok_or(
                AgentVmDaemonError::VmBrokerRuntimeConfigIncomplete("host_audit_db"),
            )?)?;

        // The broker binds a fixed port inside its own VM (each broker VM is a
        // distinct IP, so the same port is reusable across sessions).
        let broker_port = self.config.vm_http.broker_port_range().min();
        let broker_ports = BrokerPorts::new([broker_port])?;
        let guest_command = wrap_guest_command(workspace.as_ref(), guest_command)?;

        // Reserve the subnet atomically (choose + claim under the lock). The
        // persisted record carries no guest env, so the claim plan uses an empty
        // one; the boot plan below carries the real broker URL once discovered.
        let (subnet_index, network) = {
            let _subnet_guard = self.subnet_allocation_lock.lock().await;
            let lifecycle = self.config.lifecycle.clone();
            let (subnet_index, network) =
                tokio::task::spawn_blocking(move || choose_subnet_index(&lifecycle)).await??;
            let claim_plan = self.build_agent_plan(
                session_id,
                subnet_index,
                broker_ports.clone(),
                Vec::new(),
                guest_command.clone(),
            )?;
            let store = self.config.lifecycle.state_store.clone();
            tokio::task::spawn_blocking(move || claim_agent_vm_session_subnet(&store, &claim_plan))
                .await??;
            (subnet_index, network)
        };

        // Start tailing the broker VM's mirrored log file *before* launch, so that
        // even a readiness timeout (the broker never publishes `ready`) still
        // forwards the broker's own egress-probe/startup diagnostics to the host.
        // The broker truncates+appends this file on the shared session mount; it
        // need not exist yet (the tailer tolerates absence).
        let broker_log_forwarder = self.spawn_broker_log_forwarder(session_id);

        // Everything past the claim reaps via cleanup_failed_started_session on any
        // error (it tears down the agent VM, the broker VM, the material, and the
        // record — see cleanup_managed_agent_vm_session for vm placement).
        let outcome = self
            .complete_vm_broker_start(
                Arc::clone(&state),
                session_id,
                agent_kind,
                &broker_image,
                &host_config_json,
                &host_audit_db,
                &audit_dir,
                broker_port,
                broker_ports,
                subnet_index,
                network,
                guest_command,
            )
            .await;
        match outcome {
            Ok(broker_url) => {
                // No in-process broker to register, but the session is live; track
                // it (and keep tailing its logs) so list_sessions reports it as
                // attached, not orphaned. The tail is drained+stopped on teardown.
                self.vm_broker_attached
                    .lock()
                    .await
                    .insert(session_id, broker_log_forwarder);
                Ok(AgentVmStarted {
                    session_id,
                    broker_url,
                })
            }
            Err(err) => {
                // Forward whatever the broker VM logged up to now — typically the
                // failure itself — then stop the tail, before the VM is torn down.
                // Done up front so it runs on both the keep-VM and cleanup paths,
                // and log the top-level reason host-side (this path was otherwise
                // silent in the daemon's own logs).
                broker_log_forwarder.drain_and_stop().await;
                tracing::warn!(
                    %session_id,
                    error = %err,
                    "agent VM start failed (broker_placement = vm)",
                );
                // Debug escape hatch: leave the failed session's broker + agent VMs
                // (and its Starting state record) in place so an operator can
                // `container logs writ-broker-vm-<session-id>` and `container exec`
                // into it to diagnose. Stop it manually afterwards with
                // `writ agent-vm stop <session-id>`. Default behaviour (knob unset)
                // reaps everything as usual.
                if std::env::var_os("WRIT_KEEP_FAILED_BROKER_VM").is_some() {
                    tracing::warn!(
                        %session_id,
                        "WRIT_KEEP_FAILED_BROKER_VM set: leaving the failed broker VM \
                         (writ-broker-vm-<session-id>) and its agent VM running for \
                         debugging; stop with `writ agent-vm stop <session-id>`",
                    );
                    return Err(err);
                }
                let failure = err.to_string();
                if let Err(cleanup) = self.cleanup_failed_started_session(session_id).await {
                    return Err(AgentVmDaemonError::WorkspaceBootstrapCleanupFailed {
                        bootstrap: failure,
                        cleanup: cleanup.to_string(),
                    });
                }
                Err(err)
            }
        }
    }

    /// The fallible tail of [`Self::start_vm_broker_session`], after the subnet has
    /// been claimed: materialise + launch the broker VM, boot the agent against it,
    /// and wait for bootstrap. Returns the broker URL on success; any error is
    /// rolled back by the caller via `cleanup_failed_started_session`.
    #[allow(clippy::too_many_arguments)]
    async fn complete_vm_broker_start<S: SecretStore + Send + Sync + 'static>(
        &self,
        state: Arc<BrokerState<S>>,
        session_id: SessionId,
        agent_kind: AgentKind,
        broker_image: &ContainerImage,
        host_config_json: &str,
        host_audit_db: &Path,
        audit_dir: &Path,
        broker_port: BrokerPort,
        broker_ports: BrokerPorts,
        subnet_index: u16,
        network: AgentNetwork,
        guest_command: Vec<String>,
    ) -> Result<String, AgentVmDaemonError> {
        let paths = BrokerVmSessionPaths::new(&self.broker_material_root(), session_id);
        // The broker creates and owns the shared internal network the agent joins;
        // its name is the agent network name (session-id derived).
        let internal_network = AgentVmNames::for_session(session_id).network().to_string();
        let bearer = VmHttpBearerToken::generate();
        let bearer_token = bearer.as_str().to_string();

        // Materialise the broker session material (config, spec, bearer, ephemeral
        // secret store) and the launch plan. Synchronous IO, so off the runtime.
        let request = BrokerVmSessionRequest {
            session_id,
            agent_kind,
            image: broker_image.clone(),
            container_tool: self.config.lifecycle.tools.container().to_path_buf(),
            internal_network: internal_network.clone(),
            agent_subnet: network.ipv4(),
            bind_addr: self.config.vm_http.bind_addr(),
            broker_port,
            resources: self.config.lifecycle.resources,
            host_audit_db: host_audit_db.to_path_buf(),
            staging_dir: paths.staging_dir(),
            secrets_dir: paths.secrets_dir(),
            audit_dir: audit_dir.to_path_buf(),
        };
        let host_config_json = host_config_json.to_string();
        let state_for_secrets = Arc::clone(&state);
        let broker_plan = tokio::task::spawn_blocking(move || {
            materialize_broker_vm_session(
                &request,
                &host_config_json,
                &bearer,
                &state_for_secrets.secrets,
            )
        })
        .await??;

        // Authoritative compartment guard: the broker VM is about to
        // read-write-mount the audit DB's directory. Enforce that it holds only
        // the audit DB and its SQLite sidecars — nothing host-owned the guest
        // could replace and the host would then re-read or execute. This runs
        // after materialisation, so every lazily-written file (per-session broker
        // material, socket, bearer, notes) that could land under a misconfigured
        // audit directory already exists and is seen. Any error rolls back via
        // the caller's `cleanup_failed_started_session`.
        let host_audit_db_for_check = host_audit_db.to_path_buf();
        tokio::task::spawn_blocking(move || {
            crate::config::ensure_audit_dir_is_dedicated(&host_audit_db_for_check)
        })
        .await??;

        // Launch the broker VM and discover its address on the shared network.
        let broker_ipv4 = launch_broker_vm(
            &broker_plan,
            &paths.staging_dir().join("ready"),
            broker_port,
            BROKER_VM_READY_TIMEOUT,
            BROKER_VM_READY_POLL_INTERVAL,
        )
        .await
        .map_err(|source| AgentVmDaemonError::BrokerVmLaunch { session_id, source })?;
        let broker_url = broker_url(broker_ipv4, broker_port);

        // Boot the agent VM pointed at the broker VM: WRIT_BROKER_URL + token in the
        // guest env, and the host PF allow target set to the broker VM's IP.
        let guest_env = self.build_agent_guest_env(&broker_url, &bearer_token)?;
        let boot_plan = self
            .build_agent_plan(
                session_id,
                subnet_index,
                broker_ports,
                guest_env,
                guest_command,
            )?
            .with_broker_pf_host(broker_ipv4);

        let store = self.config.lifecycle.state_store.clone();
        let boot_plan_for_start = boot_plan.clone();
        // start_agent_vm_session rolls back its own agent infrastructure (VM + PF,
        // not the broker-owned network) on a boot failure; the broker VM is reaped
        // by the caller's cleanup_failed_started_session.
        tokio::task::spawn_blocking(move || start_agent_vm_session(&boot_plan_for_start))
            .await?
            .map_err(AgentVmSessionManagerError::Start)?;
        let store_for_running = store.clone();
        let starting =
            tokio::task::spawn_blocking(move || store_for_running.load(session_id)).await??;
        // Promote to Running while recording the discovered broker VM IP, so
        // list_sessions reports the real broker URL (not the subnet gateway).
        tokio::task::spawn_blocking(move || {
            store.mark_running_with_broker_ipv4(&starting, broker_ipv4)
        })
        .await??;

        self.ensure_network_health_monitor(Arc::clone(&state.audit));
        if let Err(mut err) = self
            .release_and_wait_for_workspace_bootstrap(boot_plan.names().vm())
            .await
        {
            self.annotate_workspace_bootstrap_error_with_prewarm_audit(
                state.audit.as_ref(),
                session_id,
                &mut err,
            );
            return Err(err);
        }
        Ok(broker_url)
    }

    fn annotate_workspace_bootstrap_error_with_prewarm_audit(
        &self,
        audit: &AuditLog,
        session_id: SessionId,
        err: &mut AgentVmDaemonError,
    ) {
        if self.config.vm_http.nix_prewarm_cache_dir().is_none() {
            return;
        }
        if !matches!(err, AgentVmDaemonError::WorkspaceBootstrapFailed { .. }) {
            return;
        }
        let Some(diagnostic) = workspace_bootstrap_prewarm_diagnostic_from_audit(audit, session_id)
        else {
            return;
        };
        if let AgentVmDaemonError::WorkspaceBootstrapFailed { message } = err {
            if !message.is_empty() {
                message.push_str("\n\n");
            }
            message.push_str(&diagnostic);
        }
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
