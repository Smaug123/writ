//! Persistent session state for `agent_vm_lifecycle`: the in-memory
//! `AgentVmSessionState` record, its on-disk `Persisted*` JSON schema and
//! serde round-trip, and the `AgentVmSessionStateStore` that owns the
//! state directory (atomic writes, a single store-wide file lock, and
//! corruption-rejecting loads), plus default state-directory resolution.
//!
//! `super::*` re-exports the planning/domain types and private helpers
//! (`AgentVmSessionPlan`, `AgentVmSessionStopPlan`, `derive_session_network`,
//! the status enum, …) this layer reads; the explicit `use` covers the one
//! `crate::core` type the parent module does not itself import.

use super::*;
use std::net::Ipv4Addr;
use std::os::unix::fs::OpenOptionsExt;

use crate::agent_vm_firewall::PfInstallPhase;
use crate::agent_vm_locked_lifecycle::{
    FirewallFacts, GuestFacts, GuestSecurityLocked, LOCKED_RELEASE_SIGNAL, LockedLifecycle,
    LockedPhase, ReleaseAttempted,
};
use crate::core::PfInterface;

#[derive(Debug, thiserror::Error)]
pub enum AgentVmSessionStateError {
    #[error("agent VM state file already exists for session {session_id}: {path}")]
    AlreadyExists {
        session_id: SessionId,
        path: PathBuf,
    },
    #[error("agent VM state file does not exist for session {session_id}: {path}")]
    NotFound {
        session_id: SessionId,
        path: PathBuf,
    },
    #[error("cannot {operation} agent VM state file {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid JSON in agent VM state file {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("unsupported agent VM state version {version}; supported version is {supported}")]
    UnsupportedVersion { version: u32, supported: u32 },
    #[error("corrupt agent VM state: {message}")]
    Corrupt { message: String },
    #[error("agent VM state mismatch for session {session_id}: {message}")]
    StateMismatch {
        session_id: SessionId,
        message: String,
    },
    #[error(
        "agent VM subnet index {subnet_index} is already allocated to session {existing_session_id}; cannot allocate it to session {requested_session_id}"
    )]
    SubnetIndexAlreadyAllocated {
        subnet_index: u16,
        existing_session_id: SessionId,
        requested_session_id: SessionId,
    },
}

/// Which schema version a loaded record was written under.
///
/// Provenance, not a knob. A [`StateSchema::V2`] record was written by a
/// daemon that had no phase model, so it carries everything teardown needs and
/// nothing else — it can never be reported as locked, because there is no
/// locked section in a v2 file to report. Loading one is how an operator who
/// upgraded without draining gets their sessions cleaned up rather than a
/// refusal; the intended upgrade drains first and so never sees one.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StateSchema {
    V2,
    V3,
}

impl StateSchema {
    /// Whether the record is good for teardown and nothing else.
    pub fn is_cleanup_only(self) -> bool {
        matches!(self, Self::V2)
    }
}

/// What a record says about where its session got to.
///
/// Two profiles, two models. The shipped profiles have the coarse
/// `Starting`/`Running` they have always had; `ipv4_only_locked_v1` has the
/// ordered phases of [`crate::agent_vm_locked_lifecycle`], because its release
/// step is a gate whose "was it sent?" the daemon must be able to answer after
/// a crash. Keeping them as one DU rather than one struct with optional fields
/// is what stops a legacy record carrying half a phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionLifecycle {
    Legacy(AgentVmSessionStateStatus),
    Locked(LockedLifecycle),
}

impl SessionLifecycle {
    /// The coarse status, for listings and for the legacy transitions.
    ///
    /// A projection, not a second source of truth: a locked session is
    /// `Running` exactly once its workload was released, and `Starting` before
    /// that. Anything that needs to know *which* phase asks
    /// [`AgentVmSessionState::locked_phase`].
    pub fn status(&self) -> AgentVmSessionStateStatus {
        match self {
            Self::Legacy(status) => *status,
            Self::Locked(locked) => {
                if locked.phase() == LockedPhase::WorkloadReleased {
                    AgentVmSessionStateStatus::Running
                } else {
                    AgentVmSessionStateStatus::Starting
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmSessionState {
    lifecycle: SessionLifecycle,
    /// Which schema the record was read from. A record this process built
    /// (rather than loaded) is [`StateSchema::V3`]: it is what we would write.
    schema: StateSchema,
    session_id: SessionId,
    pool: AgentNetworkPool,
    subnet_index: u16,
    network: AgentNetwork,
    names: AgentVmNames,
    broker_ports: BrokerPorts,
    broker_port_range: BrokerPortRange,
    ipv6_mode: Ipv6IsolationMode,
    /// Persisted so a later managed stop / boot reconcile tears the session down
    /// with the right ownership: `Vm` sessions installed no host PF and share a
    /// broker-owned network, so their cleanup removes the agent VM only.
    broker_placement: BrokerPlacement,
    /// The broker endpoint the agent reaches. `None` (host placement) means the
    /// subnet gateway; `Some` (vm placement) is the broker VM's discovered IP,
    /// recorded when the session is promoted to Running so listings report the
    /// real URL rather than the gateway.
    broker_ipv4: Option<Ipv4Addr>,
    image: ContainerImage,
    guest_command: Vec<String>,
    resources: AgentVmResources,
}

/// Persistent record of which sessions exist and their lifecycle state.
///
/// **Single-owner invariant:** a state directory has exactly one owner. Either
/// a single `writd` runs against it, or ad-hoc CLI invocations
/// (`writ-agent-vm-runner managed-start` / `managed-stop`) act on it — never
/// both, and never two daemons. The store's internal file lock serialises
/// individual operations, but the daemon's split start/stop forms release
/// that lock between sub-steps for parallelism, so an external process
/// touching the same `SessionId` mid-flight could remove a `Starting` record
/// before the daemon's boot creates infrastructure to clean up, orphaning
/// that infrastructure. We do not defend against this in code: the invariant
/// is documented and operational.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmSessionStateStore {
    dir: PathBuf,
}

#[derive(Debug)]
pub(super) struct AgentVmSessionStateLock {
    _file: File,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedAgentVmSessionState {
    version: u32,
    status: AgentVmSessionStateStatus,
    /// The locked profile's phase and facts. Absent on every v2 record (the
    /// field did not exist) and on every v3 record for a legacy profile, which
    /// is what makes "a v2 record is never reported as locked" structural
    /// rather than a rule someone has to remember.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    locked: Option<PersistedLockedLifecycle>,
    session_id: SessionId,
    ipv4_pool: String,
    ipv6_pool: String,
    subnet_index: u16,
    ipv4_cidr: String,
    ipv6_cidr: String,
    firewall_ipv6_cidr: Option<String>,
    network_name: String,
    vm_name: String,
    broker_ports: Vec<u16>,
    broker_port_min: u16,
    broker_port_max: u16,
    ipv6_mode: PersistedIpv6IsolationMode,
    // Defaulted so version-2 records written before the field existed (all host
    // placement, since vm placement was never enabled) load as `Host`.
    #[serde(default)]
    broker_placement: BrokerPlacement,
    // The broker VM's discovered IP (vm placement only); defaulted so older
    // records (host placement, no broker VM) load as `None` = gateway.
    #[serde(default)]
    broker_ipv4: Option<Ipv4Addr>,
    image: String,
    guest_command: Vec<String>,
    cpus: u16,
    memory_mib: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistedIpv6IsolationMode {
    DualStackRequired,
    Ipv4OnlyNoGuestIpv6,
    Ipv4OnlyLockedV1,
}

/// The locked lifecycle on the wire.
///
/// Loose where [`LockedLifecycle`] is tight: the phase is a string and the
/// facts are optional, because that is what JSON can say. `from_persisted`
/// turns it into the DU and refuses every combination the DU cannot express —
/// a released workload with no interfaces, a claimed session carrying an ABI —
/// so the looseness stops at the boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedLockedLifecycle {
    phase: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    firewall_install_phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    isolation_abi: Option<u32>,
}

/// The schema this binary writes.
const AGENT_VM_SESSION_STATE_VERSION: u32 = 3;

/// The oldest schema this binary reads. A v2 record loads as
/// [`StateSchema::V2`]: cleanup-only, never locked. Rolling *back* is what
/// fails closed — a daemon that only knows v2 refuses a v3 record outright
/// rather than reading a locked session as a legacy one, which is why the
/// upgrade note says to drain v3 sessions before rolling back.
const AGENT_VM_SESSION_STATE_MIN_READ_VERSION: u32 = 2;

impl AgentVmSessionState {
    /// The record a start claims before it creates anything.
    ///
    /// A locked plan claims a *locked* record, at
    /// [`LockedPhase::Claimed`] — the phase whose own docs say the session id
    /// and subnet are allocated and nothing exists on the host, which is
    /// exactly what a claim is. Every other profile claims a legacy record
    /// carrying `status`. That dispatch is what makes the locked phases
    /// reachable at all: `advance_locked` refuses a record that is not already
    /// locked, so a locked session that claimed a legacy record could never
    /// record a single phase.
    pub(super) fn from_start_plan(
        plan: &AgentVmSessionPlan,
        status: AgentVmSessionStateStatus,
    ) -> Self {
        let lifecycle = match plan.ipv6_mode {
            Ipv6IsolationMode::Ipv4OnlyLockedV1 => {
                SessionLifecycle::Locked(LockedLifecycle::Claimed)
            }
            Ipv6IsolationMode::DualStackRequired | Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 => {
                SessionLifecycle::Legacy(status)
            }
        };
        Self {
            lifecycle,
            // Built here rather than read, so it is what this binary writes.
            schema: StateSchema::V3,
            session_id: plan.session_id,
            pool: plan.pool,
            subnet_index: plan.subnet_index(),
            network: plan.network,
            names: plan.names.clone(),
            broker_ports: plan.broker_ports.clone(),
            broker_port_range: plan.broker_port_range,
            ipv6_mode: plan.ipv6_mode,
            broker_placement: plan.broker_placement,
            // The broker VM's IP is unknown at claim; the vm arm records it when
            // promoting to Running (see mark_running_with_broker_ipv4).
            broker_ipv4: None,
            image: plan.image.clone(),
            guest_command: plan.guest_command.clone(),
            resources: plan.resources,
        }
    }

    /// A copy of this record under `lifecycle`.
    ///
    /// Test-only, and not a bypass of anything: the gate on running a locked
    /// session is `ConfiguredIpv6Profile::admit`, which refuses the profile
    /// outright, and no production path can reach this because nothing builds
    /// a `LockedLifecycle` — the typestates that make one are only produced by
    /// the locked start path, which Stage E2 writes. Tests need locked records
    /// now so that the reader, the release gate and reconciliation can be
    /// pinned before anything can produce one.
    #[cfg(test)]
    pub(crate) fn with_locked_lifecycle_for_test(&self, lifecycle: LockedLifecycle) -> Self {
        Self {
            lifecycle: SessionLifecycle::Locked(lifecycle),
            ..self.clone()
        }
    }

    #[cfg(test)]
    pub(super) fn from_json_bytes(raw: &[u8]) -> Result<Self, AgentVmSessionStateError> {
        let persisted: PersistedAgentVmSessionState =
            serde_json::from_slice(raw).map_err(|source| AgentVmSessionStateError::Json {
                path: PathBuf::from("<memory>"),
                source,
            })?;
        Self::from_persisted(persisted)
    }

    fn from_json_file(path: &Path, raw: &[u8]) -> Result<Self, AgentVmSessionStateError> {
        let persisted: PersistedAgentVmSessionState =
            serde_json::from_slice(raw).map_err(|source| AgentVmSessionStateError::Json {
                path: path.to_path_buf(),
                source,
            })?;
        Self::from_persisted(persisted)
    }

    fn from_persisted(
        persisted: PersistedAgentVmSessionState,
    ) -> Result<Self, AgentVmSessionStateError> {
        let schema = match persisted.version {
            AGENT_VM_SESSION_STATE_MIN_READ_VERSION => StateSchema::V2,
            AGENT_VM_SESSION_STATE_VERSION => StateSchema::V3,
            version => {
                return Err(AgentVmSessionStateError::UnsupportedVersion {
                    version,
                    supported: AGENT_VM_SESSION_STATE_VERSION,
                });
            }
        };
        // A v2 writer had no `locked` field, so a v2 record carrying one was
        // not written by a v2 writer. Refuse rather than read it: the version
        // is the only claim about the shape, and a record whose shape and
        // version disagree is one we cannot say anything about.
        if schema.is_cleanup_only() && persisted.locked.is_some() {
            return Err(corrupt_state(
                "schema v2 record carries a locked lifecycle section".to_string(),
            ));
        }
        let lifecycle = match persisted.locked {
            None => SessionLifecycle::Legacy(persisted.status),
            Some(locked) => SessionLifecycle::Locked(locked_lifecycle_from_persisted(locked)?),
        };

        let ipv4_pool = parse_state_ipv4_cidr("ipv4_pool", &persisted.ipv4_pool)?;
        let ipv6_pool = parse_state_ipv6_cidr("ipv6_pool", &persisted.ipv6_pool)?;
        let pool = AgentNetworkPool::new(ipv4_pool, ipv6_pool)
            .map_err(|err| corrupt_state(format!("invalid network pool: {err}")))?;
        let recorded_ipv4 = parse_state_ipv4_cidr("ipv4_cidr", &persisted.ipv4_cidr)?;
        let recorded_ipv6 = parse_state_ipv6_cidr("ipv6_cidr", &persisted.ipv6_cidr)?;
        let firewall_ipv6 = persisted
            .firewall_ipv6_cidr
            .as_deref()
            .map(|raw| parse_state_ipv6_cidr("firewall_ipv6_cidr", raw))
            .transpose()?;
        let broker_ports = BrokerPorts::new(
            persisted
                .broker_ports
                .iter()
                .copied()
                .map(crate::core::BrokerPort::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| corrupt_state(format!("invalid broker port: {err}")))?,
        )
        .map_err(|err| corrupt_state(format!("invalid broker ports: {err}")))?;
        let broker_port_range =
            BrokerPortRange::new(persisted.broker_port_min, persisted.broker_port_max)
                .map_err(|err| corrupt_state(format!("invalid broker port range: {err}")))?;
        let ipv6_mode: Ipv6IsolationMode = persisted.ipv6_mode.into();
        let image = ContainerImage::new(persisted.image)
            .map_err(|err| corrupt_state(format!("invalid image: {err}")))?;
        let resources = AgentVmResources::new(persisted.cpus, persisted.memory_mib)
            .map_err(|err| corrupt_state(format!("invalid resources: {err}")))?;

        broker_port_range
            .require_contains(&broker_ports)
            .map_err(|err| corrupt_state(format!("invalid broker ports: {err}")))?;
        if ipv6_mode.requires_guest_command() && persisted.guest_command.is_empty() {
            return Err(corrupt_state(
                "a held-until-released profile requires an explicit guest command",
            ));
        }

        let (network, names) =
            derive_session_network(persisted.session_id, pool, persisted.subnet_index)
                .map_err(|err| corrupt_state(format!("invalid session network: {err}")))?;

        if network.ipv4() != recorded_ipv4 {
            return Err(corrupt_state(format!(
                "recorded IPv4 subnet {recorded_ipv4} does not match pool/index allocation {}",
                network.ipv4()
            )));
        }
        if network.ipv6() != recorded_ipv6 {
            return Err(corrupt_state(format!(
                "recorded IPv6 subnet {recorded_ipv6} does not match pool/index allocation {}",
                network.ipv6()
            )));
        }
        if persisted.network_name != names.network() {
            return Err(corrupt_state(format!(
                "recorded network name {:?} does not match session-derived name {:?}",
                persisted.network_name,
                names.network()
            )));
        }
        if persisted.vm_name != names.vm() {
            return Err(corrupt_state(format!(
                "recorded VM name {:?} does not match session-derived name {:?}",
                persisted.vm_name,
                names.vm()
            )));
        }
        if firewall_ipv6 != firewall_ipv6_cidr_for_mode(ipv6_mode, network) {
            return Err(corrupt_state(
                "recorded firewall IPv6 scope does not match IPv6 mode".to_string(),
            ));
        }

        Ok(Self {
            lifecycle,
            schema,
            session_id: persisted.session_id,
            pool,
            subnet_index: persisted.subnet_index,
            network,
            names,
            broker_ports,
            broker_port_range,
            ipv6_mode,
            broker_placement: persisted.broker_placement,
            broker_ipv4: persisted.broker_ipv4,
            image,
            guest_command: persisted.guest_command,
            resources,
        })
    }

    pub(super) fn to_json_bytes(&self) -> Result<Vec<u8>, AgentVmSessionStateError> {
        serde_json::to_vec_pretty(&PersistedAgentVmSessionState::from(self)).map_err(|source| {
            AgentVmSessionStateError::Json {
                path: PathBuf::from("<memory>"),
                source,
            }
        })
    }

    /// The legacy `Starting`/`Running` transition. Locked sessions do not
    /// have one: their progress is a phase, and only a typestate moves it.
    fn with_status(
        &self,
        status: AgentVmSessionStateStatus,
    ) -> Result<Self, AgentVmSessionStateError> {
        // A v2 record is a teardown obligation, not a session to promote.
        // Promoting one would rewrite it as v3 — leaving the caller holding a
        // value that no longer matches what is on disk — and would treat a
        // record that predates the phase model as a live session.
        if self.schema.is_cleanup_only() {
            return Err(state_mismatch(
                self.session_id,
                "a schema v2 record is a cleanup obligation, not a session to promote",
            ));
        }
        match &self.lifecycle {
            SessionLifecycle::Legacy(_) => Ok(Self {
                lifecycle: SessionLifecycle::Legacy(status),
                ..self.clone()
            }),
            SessionLifecycle::Locked(_) => Err(state_mismatch(
                self.session_id,
                "a locked session advances by phase, not by status",
            )),
        }
    }

    /// The coarse status. See [`SessionLifecycle::status`] for what it means
    /// for a locked session.
    pub fn status(&self) -> AgentVmSessionStateStatus {
        self.lifecycle.status()
    }

    pub fn lifecycle(&self) -> &SessionLifecycle {
        &self.lifecycle
    }

    /// How far a locked session's start got, or `None` for a session under a
    /// profile that has no phases.
    pub fn locked_phase(&self) -> Option<LockedPhase> {
        match &self.lifecycle {
            SessionLifecycle::Legacy(_) => None,
            SessionLifecycle::Locked(locked) => Some(locked.phase()),
        }
    }

    /// Which schema this record was read from. See [`StateSchema`].
    pub fn schema(&self) -> StateSchema {
        self.schema
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn subnet_index(&self) -> u16 {
        self.subnet_index
    }

    pub fn network(&self) -> AgentNetwork {
        self.network
    }

    pub fn names(&self) -> &AgentVmNames {
        &self.names
    }

    pub fn ipv6_mode(&self) -> Ipv6IsolationMode {
        self.ipv6_mode
    }

    /// Where this session's broker runs. Drives placement-aware teardown: a `Vm`
    /// session also has a dedicated broker VM (and a shared network the broker
    /// arm owns) to tear down beyond the agent VM.
    pub fn broker_placement(&self) -> BrokerPlacement {
        self.broker_placement
    }

    pub fn broker_urls(&self) -> Vec<BrokerUrl> {
        // Host placement reaches the broker on the subnet gateway; vm placement on
        // the broker VM's discovered IP (recorded at Running promotion).
        let broker_host = self
            .broker_ipv4
            .unwrap_or_else(|| self.network.ipv4_gateway());
        self.broker_ports
            .as_slice()
            .iter()
            .map(|port| BrokerUrl(format!("http://{broker_host}:{}/", port.get())))
            .collect()
    }

    pub fn to_stop_plan(&self, tools: AgentVmToolPaths) -> AgentVmSessionStopPlan {
        AgentVmSessionStopPlan::from_validated_parts(
            self.session_id,
            self.pool,
            self.network,
            firewall_ipv6_cidr_for_mode(self.ipv6_mode, self.network),
            self.names.clone(),
            self.broker_placement,
            tools,
        )
    }
}

/// The `container kill --signal USR1` that releases a locked workload.
///
/// Minted only by [`AgentVmSessionStateStore::record_release_attempted`], and
/// only once that call has persisted [`LockedPhase::ReleaseAttempted`]. There
/// is no other constructor and the field is private to this module, so "the
/// record is written before the signal is sent" is not a rule the release path
/// has to remember — it is the only way to get hold of the thing to send.
///
/// Why it matters: the signal's outcome is not knowable. A `kill` that fails
/// or times out does not prove the signal was not delivered, and the daemon
/// can die between delivery and recording it. A record written afterwards
/// would therefore be a record that can say "never released" of a workload
/// that is running.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseSignal(ProcessInvocation);

impl ReleaseSignal {
    pub fn invocation(&self) -> &ProcessInvocation {
        &self.0
    }
}

/// What [`AgentVmSessionStateStore::record_release_attempted`] hands back: the
/// updated record, the phase value the start path carries on with, and the one
/// signal it may send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRelease {
    pub state: AgentVmSessionState,
    pub attempted: ReleaseAttempted,
    pub signal: ReleaseSignal,
}

impl AgentVmSessionStateStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn path_for(&self, session_id: SessionId) -> PathBuf {
        self.dir.join(format!("{session_id}.json"))
    }

    /// The state directory root. The daemon derives its per-session broker-VM
    /// material root from this so the start arm (which writes the material) and
    /// teardown (which removes it) agree on the location.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn lock_path(&self) -> PathBuf {
        self.dir.join(".store.lock")
    }

    pub fn create_starting(
        &self,
        plan: &AgentVmSessionPlan,
    ) -> Result<AgentVmSessionState, AgentVmSessionStateError> {
        let _lock = self.lock_store()?;
        self.create_starting_unlocked(plan)
    }

    pub fn mark_running(
        &self,
        state: &AgentVmSessionState,
    ) -> Result<AgentVmSessionState, AgentVmSessionStateError> {
        let _lock = self.lock_store()?;
        self.mark_running_unlocked(state)
    }

    /// Promote a claimed `Starting` record to `Running` while recording the broker
    /// VM's discovered IP, so listings report the real broker URL. The vm arm uses
    /// this in place of [`Self::mark_running`]; `state` must still match the
    /// unchanged Starting record (its `broker_ipv4` is `None` from the claim).
    pub fn mark_running_with_broker_ipv4(
        &self,
        state: &AgentVmSessionState,
        broker_ipv4: Ipv4Addr,
    ) -> Result<AgentVmSessionState, AgentVmSessionStateError> {
        let _lock = self.lock_store()?;
        let current = self.load_unlocked(state.session_id())?;
        if &current != state || state.status() != AgentVmSessionStateStatus::Starting {
            return Err(state_mismatch(
                state.session_id(),
                "running promotion requires the unchanged Starting state record",
            ));
        }
        let mut running = state.with_status(AgentVmSessionStateStatus::Running)?;
        running.broker_ipv4 = Some(broker_ipv4);
        self.write_replace(&running)?;
        Ok(running)
    }

    pub(super) fn create_starting_unlocked(
        &self,
        plan: &AgentVmSessionPlan,
    ) -> Result<AgentVmSessionState, AgentVmSessionStateError> {
        let state = AgentVmSessionState::from_start_plan(plan, AgentVmSessionStateStatus::Starting);
        self.require_subnet_index_unallocated_unlocked(&state)?;
        self.write_new(&state)?;
        Ok(state)
    }

    fn require_subnet_index_unallocated_unlocked(
        &self,
        requested: &AgentVmSessionState,
    ) -> Result<(), AgentVmSessionStateError> {
        for existing in self.load_all_unlocked()? {
            if existing.session_id() != requested.session_id()
                && existing.subnet_index() == requested.subnet_index()
            {
                return Err(AgentVmSessionStateError::SubnetIndexAlreadyAllocated {
                    subnet_index: requested.subnet_index(),
                    existing_session_id: existing.session_id(),
                    requested_session_id: requested.session_id(),
                });
            }
        }
        Ok(())
    }

    pub(super) fn mark_running_unlocked(
        &self,
        state: &AgentVmSessionState,
    ) -> Result<AgentVmSessionState, AgentVmSessionStateError> {
        let current = self.load_unlocked(state.session_id())?;
        if &current != state || state.status() != AgentVmSessionStateStatus::Starting {
            return Err(state_mismatch(
                state.session_id(),
                "running promotion requires the unchanged Starting state record",
            ));
        }
        let running = state.with_status(AgentVmSessionStateStatus::Running)?;
        self.write_replace(&running)?;
        Ok(running)
    }

    /// Advance a locked session to its next phase.
    ///
    /// Refuses a phase that is not strictly later than the recorded one, and
    /// refuses [`LockedPhase::ReleaseAttempted`] outright: that phase has its
    /// own door ([`Self::record_release_attempted`]), which is what ties
    /// writing it to minting the signal.
    pub fn advance_locked(
        &self,
        state: &AgentVmSessionState,
        lifecycle: LockedLifecycle,
    ) -> Result<AgentVmSessionState, AgentVmSessionStateError> {
        if lifecycle.phase() == LockedPhase::ReleaseAttempted {
            return Err(state_mismatch(
                state.session_id(),
                "release_attempted is written by record_release_attempted, which mints the signal",
            ));
        }
        let _lock = self.lock_store()?;
        self.write_locked_unlocked(state, lifecycle)
    }

    /// Persist [`LockedPhase::ReleaseAttempted`] and hand back the signal to
    /// send. See [`ReleaseSignal`] for why this is one call.
    ///
    /// Takes the [`GuestSecurityLocked`] value by move: the caller must hold
    /// the proof that the guest locked itself and its interface-scoped anchor
    /// was read back, and it cannot hold that proof twice.
    pub fn record_release_attempted(
        &self,
        state: &AgentVmSessionState,
        locked: GuestSecurityLocked,
        tools: &AgentVmToolPaths,
    ) -> Result<RecordedRelease, AgentVmSessionStateError> {
        let attempted = locked.release_attempted();
        let _lock = self.lock_store()?;
        let state = self.write_locked_unlocked(state, attempted.lifecycle())?;
        // Only now, with the record on disk, does the signal exist.
        let signal = ReleaseSignal(ProcessInvocation::new(
            tools.container(),
            [
                "kill".to_string(),
                "--signal".to_string(),
                LOCKED_RELEASE_SIGNAL.to_string(),
                state.names().vm().to_string(),
            ],
        ));
        Ok(RecordedRelease {
            state,
            attempted,
            signal,
        })
    }

    fn write_locked_unlocked(
        &self,
        state: &AgentVmSessionState,
        lifecycle: LockedLifecycle,
    ) -> Result<AgentVmSessionState, AgentVmSessionStateError> {
        let current = self.load_unlocked(state.session_id())?;
        if &current != state {
            return Err(state_mismatch(
                state.session_id(),
                "advancing a locked session requires the unchanged state record",
            ));
        }
        let Some(recorded) = state.locked_phase() else {
            return Err(state_mismatch(
                state.session_id(),
                "only a locked session advances by phase",
            ));
        };
        // One equality, covering every question: that this is the next step,
        // and that it carries the recorded facts forward unchanged. See
        // `LockedLifecycle::previous`.
        let SessionLifecycle::Locked(recorded_lifecycle) = state.lifecycle() else {
            unreachable!("locked_phase() above returned Some")
        };
        if lifecycle.previous().as_ref() != Some(recorded_lifecycle) {
            let message = if lifecycle.previous().map(|previous| previous.phase())
                == Some(recorded_lifecycle.phase())
            {
                "an advance carries the recorded facts forward unchanged".to_string()
            } else {
                format!(
                    "locked phase {} is not the step after the recorded {recorded}",
                    lifecycle.phase()
                )
            };
            return Err(state_mismatch(state.session_id(), message));
        }
        let advanced = AgentVmSessionState {
            lifecycle: SessionLifecycle::Locked(lifecycle),
            ..state.clone()
        };
        self.write_replace(&advanced)?;
        Ok(advanced)
    }

    /// Overwrite an existing record with `state`. See
    /// [`AgentVmSessionState::with_locked_lifecycle_for_test`] for why the
    /// tests need this and why it bypasses no gate.
    #[cfg(test)]
    pub(crate) fn overwrite_for_test(
        &self,
        state: &AgentVmSessionState,
    ) -> Result<(), AgentVmSessionStateError> {
        let _lock = self.lock_store()?;
        self.write_replace(state)
    }

    pub fn load(
        &self,
        session_id: SessionId,
    ) -> Result<AgentVmSessionState, AgentVmSessionStateError> {
        self.require_state_file_exists(session_id)?;
        let _lock = self.lock_existing_store()?;
        self.load_unlocked(session_id)
    }

    pub fn load_all(&self) -> Result<Vec<AgentVmSessionState>, AgentVmSessionStateError> {
        match fs::metadata(&self.dir) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(AgentVmSessionStateError::Io {
                    operation: "stat directory",
                    path: self.dir.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotADirectory,
                        "agent VM state path is not a directory",
                    ),
                });
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(AgentVmSessionStateError::Io {
                    operation: "stat directory",
                    path: self.dir.clone(),
                    source,
                });
            }
        }
        let _lock = self.open_lock(true)?;
        self.load_all_unlocked()
    }

    pub(super) fn load_unlocked(
        &self,
        session_id: SessionId,
    ) -> Result<AgentVmSessionState, AgentVmSessionStateError> {
        let path = self.path_for(session_id);
        let raw = fs::read(&path).map_err(|source| match source.kind() {
            std::io::ErrorKind::NotFound => AgentVmSessionStateError::NotFound {
                session_id,
                path: path.clone(),
            },
            _ => AgentVmSessionStateError::Io {
                operation: "read",
                path: path.clone(),
                source,
            },
        })?;
        let state = AgentVmSessionState::from_json_file(&path, &raw)?;
        if state.session_id() != session_id {
            return Err(corrupt_state(format!(
                "state file {} contains session {}, but was loaded as session {session_id}",
                path.display(),
                state.session_id()
            )));
        }
        Ok(state)
    }

    fn load_all_unlocked(&self) -> Result<Vec<AgentVmSessionState>, AgentVmSessionStateError> {
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(|source| AgentVmSessionStateError::Io {
            operation: "read directory",
            path: self.dir.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| AgentVmSessionStateError::Io {
                operation: "read directory entry",
                path: self.dir.clone(),
                source,
            })?;
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                paths.push(path);
            }
        }
        paths.sort();

        let mut states = Vec::with_capacity(paths.len());
        for path in paths {
            let raw_session_id =
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .ok_or_else(|| {
                        corrupt_state(format!(
                            "state file {} does not have a UTF-8 session-id filename",
                            path.display()
                        ))
                    })?;
            let session_id = raw_session_id.parse::<SessionId>().map_err(|err| {
                corrupt_state(format!(
                    "state file {} does not have a valid session-id filename: {err}",
                    path.display()
                ))
            })?;
            states.push(self.load_unlocked(session_id)?);
        }
        Ok(states)
    }

    pub fn remove(&self, session_id: SessionId) -> Result<(), AgentVmSessionStateError> {
        let _lock = self.lock_store()?;
        self.remove_unlocked(session_id)
    }

    pub(super) fn remove_unlocked(
        &self,
        session_id: SessionId,
    ) -> Result<(), AgentVmSessionStateError> {
        let path = self.path_for(session_id);
        fs::remove_file(&path).map_err(|source| match source.kind() {
            std::io::ErrorKind::NotFound => AgentVmSessionStateError::NotFound {
                session_id,
                path: path.clone(),
            },
            _ => AgentVmSessionStateError::Io {
                operation: "remove",
                path: path.clone(),
                source,
            },
        })?;
        self.sync_dir()
    }

    fn require_state_file_exists(
        &self,
        session_id: SessionId,
    ) -> Result<(), AgentVmSessionStateError> {
        let path = self.path_for(session_id);
        fs::metadata(&path)
            .map(|_| ())
            .map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => AgentVmSessionStateError::NotFound {
                    session_id,
                    path: path.clone(),
                },
                _ => AgentVmSessionStateError::Io {
                    operation: "stat",
                    path: path.clone(),
                    source,
                },
            })
    }

    pub(super) fn lock_store(&self) -> Result<AgentVmSessionStateLock, AgentVmSessionStateError> {
        self.ensure_dir()?;
        self.open_lock(true)
    }

    fn lock_existing_store(&self) -> Result<AgentVmSessionStateLock, AgentVmSessionStateError> {
        self.open_lock(false)
    }

    fn open_lock(&self, create: bool) -> Result<AgentVmSessionStateLock, AgentVmSessionStateError> {
        let path = self.lock_path();
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        if create {
            options.create(true);
        }
        options.mode(0o600);
        let file = options
            .open(&path)
            .map_err(|source| AgentVmSessionStateError::Io {
                operation: "open lock",
                path: path.clone(),
                source,
            })?;
        lock_file_exclusive(&file, &path)?;
        Ok(AgentVmSessionStateLock { _file: file })
    }

    fn write_new(&self, state: &AgentVmSessionState) -> Result<(), AgentVmSessionStateError> {
        self.ensure_dir()?;
        let final_path = self.path_for(state.session_id());
        let temp_path = self.temp_path(state.session_id());
        write_complete_file(&temp_path, &state.to_json_bytes()?)?;
        let link_result = fs::hard_link(&temp_path, &final_path);
        match link_result {
            Ok(()) => {
                let _ = fs::remove_file(&temp_path);
                self.sync_dir()
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&temp_path);
                Err(AgentVmSessionStateError::AlreadyExists {
                    session_id: state.session_id(),
                    path: final_path,
                })
            }
            Err(source) => {
                let _ = fs::remove_file(&temp_path);
                Err(AgentVmSessionStateError::Io {
                    operation: "create link",
                    path: final_path,
                    source,
                })
            }
        }
    }

    fn write_replace(&self, state: &AgentVmSessionState) -> Result<(), AgentVmSessionStateError> {
        self.ensure_dir()?;
        let final_path = self.path_for(state.session_id());
        let temp_path = self.temp_path(state.session_id());
        write_complete_file(&temp_path, &state.to_json_bytes()?)?;
        fs::rename(&temp_path, &final_path).map_err(|source| AgentVmSessionStateError::Io {
            operation: "replace",
            path: final_path.clone(),
            source,
        })?;
        self.sync_dir()
    }

    fn ensure_dir(&self) -> Result<(), AgentVmSessionStateError> {
        writ_core::private_fs::create_dir_all_0700(&self.dir).map_err(|source| {
            AgentVmSessionStateError::Io {
                operation: "create directory",
                path: self.dir.clone(),
                source,
            }
        })
    }

    fn sync_dir(&self) -> Result<(), AgentVmSessionStateError> {
        let dir = File::open(&self.dir).map_err(|source| AgentVmSessionStateError::Io {
            operation: "open directory",
            path: self.dir.clone(),
            source,
        })?;
        dir.sync_all()
            .map_err(|source| AgentVmSessionStateError::Io {
                operation: "sync directory",
                path: self.dir.clone(),
                source,
            })
    }

    fn temp_path(&self, session_id: SessionId) -> PathBuf {
        self.dir
            .join(format!(".{session_id}.{}.tmp", Uuid::new_v4()))
    }
}

impl From<&AgentVmSessionState> for PersistedAgentVmSessionState {
    fn from(value: &AgentVmSessionState) -> Self {
        Self {
            version: AGENT_VM_SESSION_STATE_VERSION,
            // The projection, so an older *reader* of this field — and an
            // operator reading the file — still sees a coarse status it
            // understands. The locked section below is the authority.
            status: value.lifecycle.status(),
            locked: match &value.lifecycle {
                SessionLifecycle::Legacy(_) => None,
                SessionLifecycle::Locked(locked) => Some(locked_lifecycle_to_persisted(locked)),
            },
            session_id: value.session_id,
            ipv4_pool: value.pool.ipv4_base().to_string(),
            ipv6_pool: value.pool.ipv6_base().to_string(),
            subnet_index: value.subnet_index,
            ipv4_cidr: value.network.ipv4().to_string(),
            ipv6_cidr: value.network.ipv6().to_string(),
            firewall_ipv6_cidr: value
                .ipv6_mode
                .has_firewall_ipv6_cidr()
                .then(|| value.network.ipv6().to_string()),
            network_name: value.names.network().to_string(),
            vm_name: value.names.vm().to_string(),
            broker_ports: value
                .broker_ports
                .as_slice()
                .iter()
                .map(|port| port.get())
                .collect(),
            broker_port_min: value.broker_port_range.min().get(),
            broker_port_max: value.broker_port_range.max().get(),
            ipv6_mode: value.ipv6_mode.into(),
            broker_placement: value.broker_placement,
            broker_ipv4: value.broker_ipv4,
            image: value.image.as_str().to_string(),
            guest_command: value.guest_command.clone(),
            cpus: value.resources.cpus(),
            memory_mib: value.resources.memory_mib(),
        }
    }
}

fn locked_lifecycle_to_persisted(locked: &LockedLifecycle) -> PersistedLockedLifecycle {
    PersistedLockedLifecycle {
        phase: locked.phase().as_str().to_string(),
        interfaces: locked
            .firewall()
            .map(|firewall| {
                firewall
                    .interfaces()
                    .iter()
                    .map(|interface| interface.as_str().to_string())
                    .collect()
            })
            .unwrap_or_default(),
        firewall_install_phase: locked
            .firewall()
            .map(|firewall| firewall.install_phase().as_str().to_string()),
        isolation_abi: locked.guest().map(|guest| guest.isolation_abi()),
    }
}

/// Rebuild the [`LockedLifecycle`] DU from the wire form, refusing every
/// combination the DU cannot express.
///
/// The phase decides which facts must be present, so a record that reached
/// `release_attempted` without naming the interfaces its anchor was scoped to
/// is corrupt — not a released session with an empty interface list, which is
/// what a tolerant reader would hand to teardown.
fn locked_lifecycle_from_persisted(
    persisted: PersistedLockedLifecycle,
) -> Result<LockedLifecycle, AgentVmSessionStateError> {
    let phase = LockedPhase::parse(&persisted.phase)
        .ok_or_else(|| corrupt_state(format!("unknown locked phase {:?}", persisted.phase)))?;

    let firewall = match (
        phase >= LockedPhase::FinalFirewallInstalled,
        persisted.interfaces.is_empty(),
        persisted.firewall_install_phase.as_deref(),
    ) {
        (false, true, None) => None,
        (false, ..) => {
            return Err(corrupt_state(format!(
                "locked phase {phase} carries firewall facts it cannot have"
            )));
        }
        (true, false, Some(install_phase)) => {
            let interfaces = persisted
                .interfaces
                .iter()
                .map(|name| PfInterface::new(name.clone()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| corrupt_state(format!("invalid locked interface: {err}")))?;
            let install_phase = PfInstallPhase::parse(install_phase).ok_or_else(|| {
                corrupt_state(format!("unknown firewall install phase {install_phase:?}"))
            })?;
            Some(
                FirewallFacts::new(interfaces, install_phase)
                    .map_err(|err| corrupt_state(err.to_string()))?,
            )
        }
        (true, ..) => {
            return Err(corrupt_state(format!(
                "locked phase {phase} is missing the firewall facts it implies"
            )));
        }
    };

    let guest = match (
        phase >= LockedPhase::GuestSecurityLocked,
        persisted.isolation_abi,
    ) {
        (false, None) => None,
        (true, Some(abi)) => Some(GuestFacts::new(abi)),
        (false, Some(_)) => {
            return Err(corrupt_state(format!(
                "locked phase {phase} carries a guest isolation ABI it cannot have"
            )));
        }
        (true, None) => {
            return Err(corrupt_state(format!(
                "locked phase {phase} is missing the guest isolation ABI it implies"
            )));
        }
    };

    Ok(match (phase, firewall, guest) {
        (LockedPhase::Claimed, None, None) => LockedLifecycle::Claimed,
        (LockedPhase::NetworkValidated, None, None) => LockedLifecycle::NetworkValidated,
        (LockedPhase::AgentVmStarted, None, None) => LockedLifecycle::AgentVmStarted,
        (LockedPhase::FinalFirewallInstalled, Some(firewall), None) => {
            LockedLifecycle::FinalFirewallInstalled(firewall)
        }
        (LockedPhase::GuestSecurityLocked, Some(firewall), Some(guest)) => {
            LockedLifecycle::GuestSecurityLocked(firewall, guest)
        }
        (LockedPhase::ReleaseAttempted, Some(firewall), Some(guest)) => {
            LockedLifecycle::ReleaseAttempted(firewall, guest)
        }
        (LockedPhase::WorkloadReleased, Some(firewall), Some(guest)) => {
            LockedLifecycle::WorkloadReleased(firewall, guest)
        }
        // Unreachable: the two matches above already established, per phase,
        // exactly which facts are present. Fail closed rather than panic.
        (phase, _, _) => {
            return Err(corrupt_state(format!(
                "locked phase {phase} does not agree with its recorded facts"
            )));
        }
    })
}

impl From<Ipv6IsolationMode> for PersistedIpv6IsolationMode {
    fn from(value: Ipv6IsolationMode) -> Self {
        match value {
            Ipv6IsolationMode::DualStackRequired => Self::DualStackRequired,
            Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 => Self::Ipv4OnlyNoGuestIpv6,
            Ipv6IsolationMode::Ipv4OnlyLockedV1 => Self::Ipv4OnlyLockedV1,
        }
    }
}

impl From<PersistedIpv6IsolationMode> for Ipv6IsolationMode {
    fn from(value: PersistedIpv6IsolationMode) -> Self {
        match value {
            PersistedIpv6IsolationMode::DualStackRequired => Self::DualStackRequired,
            PersistedIpv6IsolationMode::Ipv4OnlyNoGuestIpv6 => Self::Ipv4OnlyNoGuestIpv6,
            PersistedIpv6IsolationMode::Ipv4OnlyLockedV1 => Self::Ipv4OnlyLockedV1,
        }
    }
}

/// Create `path` exclusively at mode 0600, write `contents`, and fsync.
fn write_complete_file(path: &Path, contents: &[u8]) -> Result<(), AgentVmSessionStateError> {
    writ_core::private_fs::write_new_0600(path, contents).map_err(|source| {
        AgentVmSessionStateError::Io {
            operation: "write",
            path: path.to_path_buf(),
            source,
        }
    })
}

fn lock_file_exclusive(file: &File, path: &Path) -> Result<(), AgentVmSessionStateError> {
    // SAFETY: `flock` only observes the valid file descriptor borrowed from
    // `file`; the descriptor remains open for the lifetime of the returned
    // lock guard.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(AgentVmSessionStateError::Io {
            operation: "lock",
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        })
    }
}

fn parse_state_ipv4_cidr(
    field: &'static str,
    raw: &str,
) -> Result<Ipv4Cidr, AgentVmSessionStateError> {
    parse_state_cidr(field, raw, "IPv4", Ipv4Cidr::new)
}

fn parse_state_ipv6_cidr(
    field: &'static str,
    raw: &str,
) -> Result<Ipv6Cidr, AgentVmSessionStateError> {
    parse_state_cidr(field, raw, "IPv6", Ipv6Cidr::new)
}

fn parse_state_cidr<A, C>(
    field: &'static str,
    raw: &str,
    family: &'static str,
    construct: impl FnOnce(A, u8) -> Result<C, AgentVmConfigError>,
) -> Result<C, AgentVmSessionStateError>
where
    A: std::str::FromStr,
    A::Err: std::fmt::Display,
{
    let (addr, prefix) = raw
        .split_once('/')
        .ok_or_else(|| corrupt_state(format!("{field} must be a CIDR, got {raw:?}")))?;
    let addr = addr
        .parse::<A>()
        .map_err(|err| corrupt_state(format!("{field} has invalid {family} address: {err}")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|err| corrupt_state(format!("{field} has invalid prefix: {err}")))?;
    construct(addr, prefix)
        .map_err(|err| corrupt_state(format!("{field} is not a valid {family} CIDR: {err}")))
}

fn corrupt_state(message: impl Into<String>) -> AgentVmSessionStateError {
    AgentVmSessionStateError::Corrupt {
        message: message.into(),
    }
}

fn state_mismatch(session_id: SessionId, message: impl Into<String>) -> AgentVmSessionStateError {
    AgentVmSessionStateError::StateMismatch {
        session_id,
        message: message.into(),
    }
}

/// Where per-session agent-VM state lives when the operator has not said.
///
/// This function was the shape [`crate::config::default_paths`] generalised —
/// alone among writ's default paths, it already filtered empty values and
/// refused rather than inventing `/tmp`. It now *is* that machinery rather
/// than a hand-rolled twin beside it, so the claim that
/// [`crate::config::default_paths::DEFAULT_PATHS`] enumerates every location
/// writ derives stays true.
pub fn default_agent_vm_state_dir() -> Result<PathBuf, crate::config::BaseDirError> {
    crate::config::default_paths::AGENT_VM_STATE_DIR.resolve()
}
