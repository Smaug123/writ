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

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AgentVmStateDirError {
    #[error("HOME is not set; pass --state-dir or set WRIT_AGENT_VM_STATE_DIR")]
    HomeUnset,
    #[error("XDG_STATE_HOME must be an absolute path when set, got {path}")]
    XdgStateHomeRelative { path: PathBuf },
    #[error("HOME must be an absolute path when deriving agent VM state dir, got {path}")]
    HomeRelative { path: PathBuf },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmSessionState {
    status: AgentVmSessionStateStatus,
    session_id: SessionId,
    pool: AgentNetworkPool,
    subnet_index: u16,
    network: AgentNetwork,
    names: AgentVmNames,
    broker_ports: BrokerPorts,
    broker_port_range: BrokerPortRange,
    ipv6_mode: Ipv6IsolationMode,
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
}

const AGENT_VM_SESSION_STATE_VERSION: u32 = 2;

impl AgentVmSessionState {
    pub(super) fn from_start_plan(
        plan: &AgentVmSessionPlan,
        status: AgentVmSessionStateStatus,
    ) -> Self {
        Self {
            status,
            session_id: plan.session_id,
            pool: plan.pool,
            subnet_index: plan.subnet_index(),
            network: plan.network,
            names: plan.names.clone(),
            broker_ports: plan.broker_ports.clone(),
            broker_port_range: plan.broker_port_range,
            ipv6_mode: plan.ipv6_mode,
            image: plan.image.clone(),
            guest_command: plan.guest_command.clone(),
            resources: plan.resources,
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
        if persisted.version != AGENT_VM_SESSION_STATE_VERSION {
            return Err(AgentVmSessionStateError::UnsupportedVersion {
                version: persisted.version,
                supported: AGENT_VM_SESSION_STATE_VERSION,
            });
        }

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
        let ipv6_mode = persisted.ipv6_mode.into();
        let image = ContainerImage::new(persisted.image)
            .map_err(|err| corrupt_state(format!("invalid image: {err}")))?;
        let resources = AgentVmResources::new(persisted.cpus, persisted.memory_mib)
            .map_err(|err| corrupt_state(format!("invalid resources: {err}")))?;

        broker_port_range
            .require_contains(&broker_ports)
            .map_err(|err| corrupt_state(format!("invalid broker ports: {err}")))?;
        if ipv6_mode == Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 && persisted.guest_command.is_empty()
        {
            return Err(corrupt_state(
                "IPv4-only guest IPv6 preflight requires an explicit guest command",
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
            status: persisted.status,
            session_id: persisted.session_id,
            pool,
            subnet_index: persisted.subnet_index,
            network,
            names,
            broker_ports,
            broker_port_range,
            ipv6_mode,
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

    fn with_status(&self, status: AgentVmSessionStateStatus) -> Self {
        Self {
            status,
            ..self.clone()
        }
    }

    pub fn status(&self) -> AgentVmSessionStateStatus {
        self.status
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

    pub fn broker_urls(&self) -> Vec<BrokerUrl> {
        self.broker_ports
            .as_slice()
            .iter()
            .map(|port| {
                BrokerUrl(format!(
                    "http://{}:{}/",
                    self.network.ipv4_gateway(),
                    port.get()
                ))
            })
            .collect()
    }

    pub fn to_stop_plan(&self, tools: AgentVmToolPaths) -> AgentVmSessionStopPlan {
        AgentVmSessionStopPlan::from_validated_parts(
            self.session_id,
            self.pool,
            self.network,
            firewall_ipv6_cidr_for_mode(self.ipv6_mode, self.network),
            self.names.clone(),
            tools,
        )
    }
}

impl AgentVmSessionStateStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn path_for(&self, session_id: SessionId) -> PathBuf {
        self.dir.join(format!("{session_id}.json"))
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
        let running = state.with_status(AgentVmSessionStateStatus::Running);
        self.write_replace(&running)?;
        Ok(running)
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder
                .create(&self.dir)
                .map_err(|source| AgentVmSessionStateError::Io {
                    operation: "create directory",
                    path: self.dir.clone(),
                    source,
                })?;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700)).map_err(
                |source| AgentVmSessionStateError::Io {
                    operation: "set directory permissions",
                    path: self.dir.clone(),
                    source,
                },
            )?;
            Ok(())
        }

        #[cfg(not(unix))]
        {
            fs::create_dir_all(&self.dir).map_err(|source| AgentVmSessionStateError::Io {
                operation: "create directory",
                path: self.dir.clone(),
                source,
            })
        }
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
            status: value.status,
            session_id: value.session_id,
            ipv4_pool: value.pool.ipv4_base().to_string(),
            ipv6_pool: value.pool.ipv6_base().to_string(),
            subnet_index: value.subnet_index,
            ipv4_cidr: value.network.ipv4().to_string(),
            ipv6_cidr: value.network.ipv6().to_string(),
            firewall_ipv6_cidr: match value.ipv6_mode {
                Ipv6IsolationMode::DualStackRequired => Some(value.network.ipv6().to_string()),
                Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 => None,
            },
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
            image: value.image.as_str().to_string(),
            guest_command: value.guest_command.clone(),
            cpus: value.resources.cpus(),
            memory_mib: value.resources.memory_mib(),
        }
    }
}

impl From<Ipv6IsolationMode> for PersistedIpv6IsolationMode {
    fn from(value: Ipv6IsolationMode) -> Self {
        match value {
            Ipv6IsolationMode::DualStackRequired => Self::DualStackRequired,
            Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 => Self::Ipv4OnlyNoGuestIpv6,
        }
    }
}

impl From<PersistedIpv6IsolationMode> for Ipv6IsolationMode {
    fn from(value: PersistedIpv6IsolationMode) -> Self {
        match value {
            PersistedIpv6IsolationMode::DualStackRequired => Self::DualStackRequired,
            PersistedIpv6IsolationMode::Ipv4OnlyNoGuestIpv6 => Self::Ipv4OnlyNoGuestIpv6,
        }
    }
}

fn write_complete_file(path: &Path, contents: &[u8]) -> Result<(), AgentVmSessionStateError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| AgentVmSessionStateError::Io {
            operation: "create",
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(contents)
        .map_err(|source| AgentVmSessionStateError::Io {
            operation: "write",
            path: path.to_path_buf(),
            source,
        })?;
    file.sync_all()
        .map_err(|source| AgentVmSessionStateError::Io {
            operation: "sync",
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(unix)]
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

#[cfg(not(unix))]
fn lock_file_exclusive(_file: &File, _path: &Path) -> Result<(), AgentVmSessionStateError> {
    Ok(())
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

pub fn default_agent_vm_state_dir() -> Result<PathBuf, AgentVmStateDirError> {
    default_agent_vm_state_dir_from_env(
        std::env::var_os("XDG_STATE_HOME"),
        std::env::var_os("HOME"),
    )
}

pub(super) fn default_agent_vm_state_dir_from_env(
    xdg_state_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, AgentVmStateDirError> {
    if let Some(dir) = xdg_state_home.filter(|dir| !dir.as_os_str().is_empty()) {
        let dir = PathBuf::from(dir);
        if !dir.is_absolute() {
            return Err(AgentVmStateDirError::XdgStateHomeRelative { path: dir });
        }
        return Ok(dir.join("writ/agent-vm-sessions"));
    }

    let home = home
        .filter(|home| !home.as_os_str().is_empty())
        .ok_or(AgentVmStateDirError::HomeUnset)?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err(AgentVmStateDirError::HomeRelative { path: home });
    }
    Ok(home.join(".local/state/writ/agent-vm-sessions"))
}
