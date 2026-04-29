//! Unprivileged lifecycle planning for Apple-container agent VM sessions.
//!
//! This module keeps the session launch as data: create the Apple internal
//! network, install the already-validated PF session anchor through the helper,
//! then start the VM. The small imperative edge at the bottom interprets those
//! descriptions as process invocations.

use std::ffi::OsString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::{
    AgentNetwork, AgentNetworkPool, AgentVmConfigError, BrokerPortRange, BrokerPorts, Ipv4Cidr,
    Ipv6Cidr, SessionId,
};

const IPV4_ONLY_PRELAUNCH_SCRIPT: &str = concat!(
    "set -eu\n",
    "mkdir -p /run/writ-agent-vm\n",
    "while [ ! -f /run/writ-agent-vm/start ]; do sleep 0.2; done\n",
    "exec \"$@\"",
);

const GUEST_IPV6_PROBE_SCRIPT: &str = r#"set -e
if ! command -v ip >/dev/null 2>&1; then echo writ-ip-command-missing; exit 77; fi
ip -6 -o addr show 2>&1
ip -6 route show default 2>&1"#;

const GUEST_IPV6_PROBE_UNAVAILABLE_MARKER: &str = "writ-ip-command-missing";
const GUEST_IPV6_PROBE_ATTEMPTS: usize = 40;
const GUEST_IPV6_PROBE_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
// Apple Container removals can lag command return briefly. Keep the
// postcondition wait bounded: after three seconds, report that cleanup could
// not prove absence instead of claiming success.
const RESOURCE_ABSENCE_ATTEMPTS: usize = 30;
const RESOURCE_ABSENCE_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmSessionPlan {
    session_id: SessionId,
    pool: AgentNetworkPool,
    network: AgentNetwork,
    names: AgentVmNames,
    broker_ports: BrokerPorts,
    broker_port_range: BrokerPortRange,
    ipv6_mode: Ipv6IsolationMode,
    image: ContainerImage,
    guest_command: Vec<String>,
    resources: AgentVmResources,
    tools: AgentVmToolPaths,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmSessionStopPlan {
    session_id: SessionId,
    pool: AgentNetworkPool,
    network: AgentNetwork,
    firewall_ipv6: Option<Ipv6Cidr>,
    names: AgentVmNames,
    tools: AgentVmToolPaths,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmNames {
    network: String,
    vm: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerImage(String);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AgentVmResources {
    cpus: u16,
    memory_mib: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmToolPaths {
    container: PathBuf,
    pf_helper: PathBuf,
    sudo: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessInvocation {
    program: PathBuf,
    args: Vec<OsString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResourcePresenceProbe {
    invocation: ProcessInvocation,
    name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppleNetworkInspection {
    ipv4_subnet: Ipv4Cidr,
    ipv4_gateway: Ipv4Addr,
    ipv6_subnet: Option<Ipv6Cidr>,
    ipv6_gateway: Option<Ipv6Addr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerUrl(String);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ipv6IsolationMode {
    DualStackRequired,
    Ipv4OnlyNoGuestIpv6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestIpv6Inspection {
    addresses: Vec<Ipv6Addr>,
    default_routes: Vec<String>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CompletedStartStep {
    None,
    NetworkCreated,
    FirewallInstalled,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StartOutcome {
    Started,
    CreateNetworkFailed,
    InspectNetworkFailed,
    ParseNetworkInspectionFailed,
    ValidateNetworkInspectionFailed,
    InstallFirewallFailed,
    StartVmFailed,
    ProbeGuestIpv6Failed,
    ValidateGuestIpv6Failed,
    ReleaseGuestCommandFailed,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AgentVmLifecycleConfigError {
    #[error(transparent)]
    AgentVm(#[from] AgentVmConfigError),
    #[error("container image must not be empty")]
    EmptyImage,
    #[error("CPU count must be at least 1")]
    EmptyCpuCount,
    #[error("memory must be at least 1 MiB")]
    EmptyMemory,
    #[error("IPv4-only guest IPv6 preflight requires an explicit guest command")]
    EmptyGuestCommandForIpv4OnlyNoGuestIpv6,
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessInvocationError {
    #[error("cannot run {program} {args}: {source}")]
    Run {
        program: String,
        args: String,
        source: std::io::Error,
    },
    #[error("{program} {args} failed with status {status}: {stderr}")]
    Failed {
        program: String,
        args: String,
        status: String,
        stderr: String,
    },
    #[error("{program} {args} still lists resource after cleanup: {message}")]
    ResourceStillPresent {
        program: String,
        args: String,
        message: String,
    },
}

#[derive(Debug)]
pub struct CleanupErrors {
    count: usize,
    summary: String,
    errors: Vec<ProcessInvocationError>,
}

#[derive(Debug, thiserror::Error)]
pub enum StartFailure {
    #[error(transparent)]
    Process(#[from] ProcessInvocationError),
    #[error(transparent)]
    NetworkInspection(#[from] NetworkInspectionError),
    #[error(transparent)]
    GuestIpv6Inspection(#[from] GuestIpv6InspectionError),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NetworkInspectionError {
    #[error("container network inspect output is missing {0}")]
    MissingField(&'static str),
    #[error("container network inspect field {field} has invalid value {value:?}: {message}")]
    InvalidField {
        field: &'static str,
        value: String,
        message: String,
    },
    #[error("inspected IPv4 subnet {actual} does not match planned subnet {expected}")]
    Ipv4SubnetMismatch {
        expected: Ipv4Cidr,
        actual: Ipv4Cidr,
    },
    #[error("inspected IPv4 gateway {actual} does not match planned gateway {expected}")]
    Ipv4GatewayMismatch {
        expected: Ipv4Addr,
        actual: Ipv4Addr,
    },
    #[error("inspected IPv6 subnet {actual} does not match planned subnet {expected}")]
    Ipv6SubnetMismatch {
        expected: Ipv6Cidr,
        actual: Ipv6Cidr,
    },
    #[error("inspected IPv6 gateway {gateway} is outside planned subnet {subnet}")]
    Ipv6GatewayOutsideSubnet { subnet: Ipv6Cidr, gateway: Ipv6Addr },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GuestIpv6InspectionError {
    #[error("guest image cannot prove IPv6 posture because it does not provide the `ip` command")]
    ProbeToolUnavailable,
    #[error("guest IPv6 probe output has invalid address {value:?}: {message}")]
    InvalidAddress { value: String, message: String },
    #[error("guest has non-link-local IPv6 address {0}")]
    NonLinkLocalAddress(Ipv6Addr),
    #[error("guest has IPv6 default route: {0}")]
    DefaultRoute(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AgentVmLifecycleRunError {
    #[error(transparent)]
    Start(Box<StartFailure>),
    #[error("start failed: {original}; cleanup also failed: {cleanup}")]
    CleanupAfterFailure {
        #[source]
        original: Box<StartFailure>,
        cleanup: Box<CleanupErrors>,
    },
}

impl From<StartFailure> for AgentVmLifecycleRunError {
    fn from(value: StartFailure) -> Self {
        Self::Start(Box::new(value))
    }
}

impl CleanupErrors {
    fn new(errors: Vec<ProcessInvocationError>) -> Self {
        assert!(!errors.is_empty());
        let summary = errors
            .iter()
            .enumerate()
            .map(|(index, err)| format!("{}: {err}", index + 1))
            .collect::<Vec<_>>()
            .join("; ");
        Self {
            count: errors.len(),
            summary,
            errors,
        }
    }

    pub fn errors(&self) -> &[ProcessInvocationError] {
        &self.errors
    }
}

impl std::fmt::Display for CleanupErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} cleanup step(s) failed: {}", self.count, self.summary)
    }
}

impl std::error::Error for CleanupErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.errors
            .first()
            .map(|err| err as &(dyn std::error::Error + 'static))
    }
}

pub fn cleanup_step_after_start_outcome(outcome: StartOutcome) -> Option<CompletedStartStep> {
    match outcome {
        StartOutcome::Started => None,
        StartOutcome::CreateNetworkFailed => Some(CompletedStartStep::None),
        StartOutcome::InspectNetworkFailed
        | StartOutcome::ParseNetworkInspectionFailed
        | StartOutcome::ValidateNetworkInspectionFailed
        | StartOutcome::InstallFirewallFailed => Some(CompletedStartStep::NetworkCreated),
        StartOutcome::StartVmFailed
        | StartOutcome::ProbeGuestIpv6Failed
        | StartOutcome::ValidateGuestIpv6Failed
        | StartOutcome::ReleaseGuestCommandFailed => Some(CompletedStartStep::FirewallInstalled),
    }
}

impl AgentVmSessionPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: SessionId,
        pool: AgentNetworkPool,
        subnet_index: u16,
        broker_ports: BrokerPorts,
        broker_port_range: BrokerPortRange,
        ipv6_mode: Ipv6IsolationMode,
        image: ContainerImage,
        guest_command: Vec<String>,
        resources: AgentVmResources,
        tools: AgentVmToolPaths,
    ) -> Result<Self, AgentVmLifecycleConfigError> {
        broker_port_range.require_contains(&broker_ports)?;
        if ipv6_mode == Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 && guest_command.is_empty() {
            return Err(AgentVmLifecycleConfigError::EmptyGuestCommandForIpv4OnlyNoGuestIpv6);
        }
        let network = pool.allocate(subnet_index)?;
        Ok(Self {
            session_id,
            pool,
            network,
            names: AgentVmNames::for_session(session_id),
            broker_ports,
            broker_port_range,
            ipv6_mode,
            image,
            guest_command,
            resources,
            tools,
        })
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn network(&self) -> AgentNetwork {
        self.network
    }

    pub fn ipv6_mode(&self) -> Ipv6IsolationMode {
        self.ipv6_mode
    }

    pub fn names(&self) -> &AgentVmNames {
        &self.names
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

    pub fn start_invocations(&self) -> Vec<ProcessInvocation> {
        let mut invocations = vec![
            self.create_network_invocation(),
            self.inspect_network_invocation(),
            self.install_firewall_invocation(),
            self.start_vm_invocation(),
        ];
        if self.ipv6_mode == Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 {
            invocations.push(self.probe_guest_ipv6_invocation());
            invocations.push(self.release_guest_command_invocation());
        }
        invocations
    }

    pub fn stop_invocations(&self) -> Vec<ProcessInvocation> {
        self.stop_plan().stop_invocations()
    }

    pub fn cleanup_after_partial_start(
        &self,
        completed: CompletedStartStep,
    ) -> Vec<ProcessInvocation> {
        match completed {
            CompletedStartStep::None => Vec::new(),
            CompletedStartStep::NetworkCreated => self.stop_plan().network_removal_invocations(),
            CompletedStartStep::FirewallInstalled => self.stop_plan().stop_invocations(),
        }
    }

    pub fn cleanup_after_start_outcome(&self, outcome: StartOutcome) -> Vec<ProcessInvocation> {
        match cleanup_step_after_start_outcome(outcome) {
            Some(step) => self.cleanup_after_partial_start(step),
            None => Vec::new(),
        }
    }

    pub fn stop_plan(&self) -> AgentVmSessionStopPlan {
        AgentVmSessionStopPlan {
            session_id: self.session_id,
            pool: self.pool,
            network: self.network,
            firewall_ipv6: self.firewall_ipv6_cidr(),
            names: self.names.clone(),
            tools: self.tools.clone(),
        }
    }

    fn firewall_ipv6_cidr(&self) -> Option<Ipv6Cidr> {
        match self.ipv6_mode {
            Ipv6IsolationMode::DualStackRequired => Some(self.network.ipv6()),
            Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 => None,
        }
    }

    fn create_network_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.tools.container.clone(),
            [
                "network".to_string(),
                "create".to_string(),
                "--internal".to_string(),
                "--subnet".to_string(),
                self.network.ipv4().to_string(),
                self.names.network.clone(),
            ],
        )
    }

    fn inspect_network_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.tools.container.clone(),
            [
                "network".to_string(),
                "inspect".to_string(),
                self.names.network.clone(),
            ],
        )
    }

    pub fn validate_network_inspection(
        &self,
        inspection: &AppleNetworkInspection,
    ) -> Result<(), NetworkInspectionError> {
        if inspection.ipv4_subnet != self.network.ipv4() {
            return Err(NetworkInspectionError::Ipv4SubnetMismatch {
                expected: self.network.ipv4(),
                actual: inspection.ipv4_subnet,
            });
        }
        if inspection.ipv4_gateway != self.network.ipv4_gateway() {
            return Err(NetworkInspectionError::Ipv4GatewayMismatch {
                expected: self.network.ipv4_gateway(),
                actual: inspection.ipv4_gateway,
            });
        }
        match self.ipv6_mode {
            Ipv6IsolationMode::DualStackRequired => {
                self.validate_dual_stack_ipv6_inspection(inspection)?;
            }
            Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 => {
                validate_ipv4_only_observed_ipv6(inspection)?;
            }
        }
        Ok(())
    }

    fn validate_dual_stack_ipv6_inspection(
        &self,
        inspection: &AppleNetworkInspection,
    ) -> Result<(), NetworkInspectionError> {
        let expected_ipv6 = self.network.ipv6();
        match (inspection.ipv6_subnet, inspection.ipv6_gateway) {
            (Some(ipv6_subnet), Some(ipv6_gateway)) => {
                if ipv6_subnet != expected_ipv6 {
                    return Err(NetworkInspectionError::Ipv6SubnetMismatch {
                        expected: expected_ipv6,
                        actual: ipv6_subnet,
                    });
                }
                if !expected_ipv6.contains_addr(ipv6_gateway) {
                    return Err(NetworkInspectionError::Ipv6GatewayOutsideSubnet {
                        subnet: expected_ipv6,
                        gateway: ipv6_gateway,
                    });
                }
                Ok(())
            }
            (Some(_), None) => Err(NetworkInspectionError::MissingField("ipv6Gateway")),
            (None, Some(_)) => Err(NetworkInspectionError::MissingField("ipv6Subnet")),
            (None, None) => Err(NetworkInspectionError::MissingField("ipv6Subnet")),
        }
    }

    fn install_firewall_invocation(&self) -> ProcessInvocation {
        let mut args = vec![
            self.tools.pf_helper.as_os_str().to_os_string(),
            OsString::from("install"),
            OsString::from("--session-id"),
            OsString::from(self.session_id.to_string()),
            OsString::from("--ipv4-pool"),
            OsString::from(self.pool.ipv4_base().to_string()),
            OsString::from("--ipv6-pool"),
            OsString::from(self.pool.ipv6_base().to_string()),
            OsString::from("--ipv4-cidr"),
            OsString::from(self.network.ipv4().to_string()),
        ];
        if self.ipv6_mode == Ipv6IsolationMode::DualStackRequired {
            args.push(OsString::from("--ipv6-cidr"));
            args.push(OsString::from(self.network.ipv6().to_string()));
        }
        for port in self.broker_ports.as_slice() {
            args.push(OsString::from("--broker-port"));
            args.push(OsString::from(port.get().to_string()));
        }
        args.extend([
            OsString::from("--broker-port-min"),
            OsString::from(self.broker_port_range.min().get().to_string()),
            OsString::from("--broker-port-max"),
            OsString::from(self.broker_port_range.max().get().to_string()),
        ]);
        ProcessInvocation::new(self.tools.sudo.clone(), args)
    }

    fn start_vm_invocation(&self) -> ProcessInvocation {
        let mut args = vec![
            "run".to_string(),
            "--name".to_string(),
            self.names.vm.clone(),
            "--network".to_string(),
            self.names.network.clone(),
            "--cpus".to_string(),
            self.resources.cpus.to_string(),
            "--memory".to_string(),
            format!("{}m", self.resources.memory_mib),
            "-d".to_string(),
            self.image.as_str().to_string(),
        ];
        if self.ipv6_mode == Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 {
            args.extend([
                "sh".to_string(),
                "-c".to_string(),
                IPV4_ONLY_PRELAUNCH_SCRIPT.to_string(),
                "writ-agent-vm-prelaunch".to_string(),
            ]);
        }
        args.extend(self.guest_command.iter().cloned());
        ProcessInvocation::new(self.tools.container.clone(), args)
    }

    fn probe_guest_ipv6_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.tools.container.clone(),
            [
                "exec".to_string(),
                self.names.vm.clone(),
                "sh".to_string(),
                "-c".to_string(),
                GUEST_IPV6_PROBE_SCRIPT.to_string(),
            ],
        )
    }

    fn release_guest_command_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.tools.container.clone(),
            [
                "exec".to_string(),
                self.names.vm.clone(),
                "sh".to_string(),
                "-c".to_string(),
                "mkdir -p /run/writ-agent-vm && touch /run/writ-agent-vm/start".to_string(),
            ],
        )
    }
}

impl AgentVmSessionStopPlan {
    pub fn new(
        session_id: SessionId,
        pool: AgentNetworkPool,
        subnet_index: u16,
        ipv6_mode: Ipv6IsolationMode,
        tools: AgentVmToolPaths,
    ) -> Result<Self, AgentVmLifecycleConfigError> {
        let network = pool.allocate(subnet_index)?;
        let firewall_ipv6 = match ipv6_mode {
            Ipv6IsolationMode::DualStackRequired => Some(network.ipv6()),
            Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 => None,
        };
        Ok(Self {
            session_id,
            pool,
            network,
            firewall_ipv6,
            names: AgentVmNames::for_session(session_id),
            tools,
        })
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn network(&self) -> AgentNetwork {
        self.network
    }

    pub fn names(&self) -> &AgentVmNames {
        &self.names
    }

    pub fn stop_invocations(&self) -> Vec<ProcessInvocation> {
        let mut invocations = self.vm_removal_invocations();
        invocations.push(self.remove_firewall_invocation());
        invocations.extend(self.network_removal_invocations());
        invocations
    }

    fn vm_removal_invocations(&self) -> Vec<ProcessInvocation> {
        vec![
            ProcessInvocation::new(
                self.tools.container.clone(),
                ["rm".to_string(), "-f".to_string(), self.names.vm.clone()],
            ),
            ProcessInvocation::new(
                self.tools.container.clone(),
                ["stop".to_string(), self.names.vm.clone()],
            ),
            ProcessInvocation::new(
                self.tools.container.clone(),
                ["delete".to_string(), self.names.vm.clone()],
            ),
            ProcessInvocation::new(
                self.tools.container.clone(),
                ["rm".to_string(), self.names.vm.clone()],
            ),
        ]
    }

    fn vm_presence_probe(&self) -> ResourcePresenceProbe {
        ResourcePresenceProbe::new(
            ProcessInvocation::new(
                self.tools.container.clone(),
                [
                    "list".to_string(),
                    "--all".to_string(),
                    "--quiet".to_string(),
                ],
            ),
            self.names.vm.clone(),
        )
    }

    fn remove_firewall_invocation(&self) -> ProcessInvocation {
        let mut args = vec![
            self.tools.pf_helper.as_os_str().to_os_string(),
            OsString::from("remove"),
            OsString::from("--session-id"),
            OsString::from(self.session_id.to_string()),
            OsString::from("--ipv4-pool"),
            OsString::from(self.pool.ipv4_base().to_string()),
            OsString::from("--ipv6-pool"),
            OsString::from(self.pool.ipv6_base().to_string()),
            OsString::from("--ipv4-cidr"),
            OsString::from(self.network.ipv4().to_string()),
        ];
        if let Some(ipv6) = self.firewall_ipv6 {
            args.extend([
                OsString::from("--ipv6-cidr"),
                OsString::from(ipv6.to_string()),
            ]);
        }
        ProcessInvocation::new(self.tools.sudo.clone(), args)
    }

    fn network_removal_invocations(&self) -> Vec<ProcessInvocation> {
        vec![
            ProcessInvocation::new(
                self.tools.container.clone(),
                [
                    "network".to_string(),
                    "rm".to_string(),
                    self.names.network.clone(),
                ],
            ),
            ProcessInvocation::new(
                self.tools.container.clone(),
                [
                    "network".to_string(),
                    "delete".to_string(),
                    self.names.network.clone(),
                ],
            ),
        ]
    }

    fn network_presence_probe(&self) -> ResourcePresenceProbe {
        ResourcePresenceProbe::new(
            ProcessInvocation::new(
                self.tools.container.clone(),
                [
                    "network".to_string(),
                    "list".to_string(),
                    "--quiet".to_string(),
                ],
            ),
            self.names.network.clone(),
        )
    }
}

impl AgentVmNames {
    pub fn for_session(session_id: SessionId) -> Self {
        let names = Self {
            network: format!("writ-agent-net-{session_id}"),
            vm: format!("writ-agent-vm-{session_id}"),
        };
        debug_assert!(names.network.len() <= 63);
        debug_assert!(names.vm.len() <= 63);
        names
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn vm(&self) -> &str {
        &self.vm
    }
}

impl ContainerImage {
    pub fn new(image: impl Into<String>) -> Result<Self, AgentVmLifecycleConfigError> {
        let image = image.into();
        if image.trim().is_empty() {
            return Err(AgentVmLifecycleConfigError::EmptyImage);
        }
        Ok(Self(image))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AgentVmResources {
    pub fn new(cpus: u16, memory_mib: u32) -> Result<Self, AgentVmLifecycleConfigError> {
        if cpus == 0 {
            return Err(AgentVmLifecycleConfigError::EmptyCpuCount);
        }
        if memory_mib == 0 {
            return Err(AgentVmLifecycleConfigError::EmptyMemory);
        }
        Ok(Self { cpus, memory_mib })
    }

    pub fn cpus(self) -> u16 {
        self.cpus
    }

    pub fn memory_mib(self) -> u32 {
        self.memory_mib
    }
}

impl AgentVmToolPaths {
    pub fn new(
        container: impl Into<PathBuf>,
        pf_helper: impl Into<PathBuf>,
        sudo: impl Into<PathBuf>,
    ) -> Self {
        Self {
            container: container.into(),
            pf_helper: pf_helper.into(),
            sudo: sudo.into(),
        }
    }
}

impl ProcessInvocation {
    pub fn new(
        program: impl Into<PathBuf>,
        args: impl IntoIterator<Item = impl Into<OsString>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    pub fn args_lossy(&self) -> Vec<String> {
        self.args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    pub fn display_shell(&self) -> String {
        std::iter::once(shell_quote(&self.program.display().to_string()))
            .chain(
                self.args
                    .iter()
                    .map(|arg| shell_quote(&arg.to_string_lossy())),
            )
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn run(&self) -> Result<(), ProcessInvocationError> {
        let output = self.output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(self.failed_from_output(output))
    }

    fn failed_from_output(&self, output: std::process::Output) -> ProcessInvocationError {
        ProcessInvocationError::Failed {
            program: self.program.display().to_string(),
            args: self.args_display(),
            status: output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".into()),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        }
    }

    fn resource_still_present(&self, message: impl Into<String>) -> ProcessInvocationError {
        ProcessInvocationError::ResourceStillPresent {
            program: self.program.display().to_string(),
            args: self.args_display(),
            message: message.into(),
        }
    }

    fn output(&self) -> Result<std::process::Output, ProcessInvocationError> {
        Command::new(&self.program)
            .args(&self.args)
            .output()
            .map_err(|source| ProcessInvocationError::Run {
                program: self.program.display().to_string(),
                args: self.args_display(),
                source,
            })
    }

    fn args_display(&self) -> String {
        self.args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl ResourcePresenceProbe {
    fn new(invocation: ProcessInvocation, name: String) -> Self {
        Self { invocation, name }
    }

    fn contains_resource(&self) -> Result<bool, ProcessInvocationError> {
        let output = self.invocation.output()?;
        if !output.status.success() {
            return Err(self.invocation.failed_from_output(output));
        }
        Ok(resource_list_contains_exact_line(
            &output.stdout,
            &self.name,
        ))
    }

    fn resource_still_present(&self, message: impl Into<String>) -> ProcessInvocationError {
        self.invocation.resource_still_present(message)
    }
}

impl AppleNetworkInspection {
    pub fn parse(raw: &str) -> Result<Self, NetworkInspectionError> {
        let ipv4_subnet = parse_ipv4_cidr_field("ipv4Subnet", &require_field(raw, "ipv4Subnet")?)?;
        let ipv4_gateway =
            parse_ipv4_addr_field("ipv4Gateway", &require_field(raw, "ipv4Gateway")?)?;
        let ipv6_subnet = extract_network_field(raw, "ipv6Subnet")
            .map(|raw| parse_ipv6_cidr_field("ipv6Subnet", &raw))
            .transpose()?;
        let ipv6_gateway = extract_network_field(raw, "ipv6Gateway")
            .map(|raw| parse_ipv6_addr_field("ipv6Gateway", &raw))
            .transpose()?;
        Ok(Self {
            ipv4_subnet,
            ipv4_gateway,
            ipv6_subnet,
            ipv6_gateway,
        })
    }

    pub fn ipv4_subnet(&self) -> Ipv4Cidr {
        self.ipv4_subnet
    }

    pub fn ipv4_gateway(&self) -> Ipv4Addr {
        self.ipv4_gateway
    }

    pub fn ipv6_subnet(&self) -> Option<Ipv6Cidr> {
        self.ipv6_subnet
    }

    pub fn ipv6_gateway(&self) -> Option<Ipv6Addr> {
        self.ipv6_gateway
    }
}

impl GuestIpv6Inspection {
    pub fn parse(raw: &str) -> Result<Self, GuestIpv6InspectionError> {
        let mut addresses = Vec::new();
        let mut default_routes = Vec::new();
        for line in raw.lines().map(str::trim).filter(|line| !line.is_empty()) {
            if line == GUEST_IPV6_PROBE_UNAVAILABLE_MARKER {
                return Err(GuestIpv6InspectionError::ProbeToolUnavailable);
            }
            if line.starts_with("default ") {
                default_routes.push(line.to_string());
                continue;
            }
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let Some(inet6_index) = fields.iter().position(|field| *field == "inet6") else {
                continue;
            };
            let Some(raw_addr) = fields.get(inet6_index + 1) else {
                continue;
            };
            let addr = raw_addr
                .split_once('/')
                .map(|(addr, _)| addr)
                .unwrap_or(raw_addr)
                .parse::<Ipv6Addr>()
                .map_err(|e| GuestIpv6InspectionError::InvalidAddress {
                    value: (*raw_addr).to_string(),
                    message: e.to_string(),
                })?;
            addresses.push(addr);
        }
        Ok(Self {
            addresses,
            default_routes,
        })
    }

    pub fn require_no_routable_ipv6(&self) -> Result<(), GuestIpv6InspectionError> {
        if let Some(addr) = self
            .addresses
            .iter()
            .copied()
            .find(|addr| !ipv6_addr_is_local_only(*addr))
        {
            return Err(GuestIpv6InspectionError::NonLinkLocalAddress(addr));
        }
        if let Some(route) = self.default_routes.first() {
            return Err(GuestIpv6InspectionError::DefaultRoute(route.clone()));
        }
        Ok(())
    }

    pub fn addresses(&self) -> &[Ipv6Addr] {
        &self.addresses
    }

    pub fn default_routes(&self) -> &[String] {
        &self.default_routes
    }
}

impl BrokerUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn start_agent_vm_session(plan: &AgentVmSessionPlan) -> Result<(), AgentVmLifecycleRunError> {
    if let Err(err) = plan.create_network_invocation().run() {
        return Err(StartFailure::from(err).into());
    }

    let inspect_invocation = plan.inspect_network_invocation();
    let inspection_output = match inspect_invocation.output() {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            let err = inspect_invocation.failed_from_output(output);
            return fail_after_cleanup(err.into(), plan, StartOutcome::InspectNetworkFailed);
        }
        Err(err) => {
            return fail_after_cleanup(err.into(), plan, StartOutcome::InspectNetworkFailed);
        }
    };
    let inspection =
        match AppleNetworkInspection::parse(&String::from_utf8_lossy(&inspection_output.stdout)) {
            Ok(inspection) => inspection,
            Err(err) => {
                return fail_after_cleanup(
                    err.into(),
                    plan,
                    StartOutcome::ParseNetworkInspectionFailed,
                );
            }
        };
    if let Err(err) = plan.validate_network_inspection(&inspection) {
        return fail_after_cleanup(
            err.into(),
            plan,
            StartOutcome::ValidateNetworkInspectionFailed,
        );
    }
    if let Err(err) = plan.install_firewall_invocation().run() {
        return fail_after_cleanup(err.into(), plan, StartOutcome::InstallFirewallFailed);
    }
    if let Err(err) = plan.start_vm_invocation().run() {
        return fail_after_cleanup(err.into(), plan, StartOutcome::StartVmFailed);
    }
    if plan.ipv6_mode == Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 {
        let guest_ipv6 = match wait_for_guest_ipv6_inspection(plan) {
            Ok(inspection) => inspection,
            Err(err) => {
                return fail_after_cleanup(err, plan, StartOutcome::ProbeGuestIpv6Failed);
            }
        };
        if let Err(err) = guest_ipv6.require_no_routable_ipv6() {
            return fail_after_cleanup(err.into(), plan, StartOutcome::ValidateGuestIpv6Failed);
        }
        if let Err(err) = plan.release_guest_command_invocation().run() {
            return fail_after_cleanup(err.into(), plan, StartOutcome::ReleaseGuestCommandFailed);
        }
    }
    Ok(())
}

pub fn stop_agent_vm_session(plan: &AgentVmSessionStopPlan) -> Result<(), CleanupErrors> {
    run_stop_plan_cleanup(plan)
}

fn fail_after_cleanup<T>(
    original: StartFailure,
    plan: &AgentVmSessionPlan,
    outcome: StartOutcome,
) -> Result<T, AgentVmLifecycleRunError> {
    match run_cleanup_after_start_outcome(plan, outcome) {
        Ok(()) => Err(original.into()),
        Err(cleanup) => Err(AgentVmLifecycleRunError::CleanupAfterFailure {
            original: Box::new(original),
            cleanup: Box::new(cleanup),
        }),
    }
}

fn run_cleanup_after_start_outcome(
    plan: &AgentVmSessionPlan,
    outcome: StartOutcome,
) -> Result<(), CleanupErrors> {
    match cleanup_step_after_start_outcome(outcome) {
        Some(CompletedStartStep::NetworkCreated) => {
            single_cleanup_result(run_network_cleanup_until_absent(&plan.stop_plan()))
        }
        Some(CompletedStartStep::FirewallInstalled) => run_stop_plan_cleanup(&plan.stop_plan()),
        Some(CompletedStartStep::None) | None => Ok(()),
    }
}

fn single_cleanup_result(result: Result<(), ProcessInvocationError>) -> Result<(), CleanupErrors> {
    result.map_err(|err| CleanupErrors::new(vec![err]))
}

fn run_stop_plan_cleanup(plan: &AgentVmSessionStopPlan) -> Result<(), CleanupErrors> {
    let mut errors = Vec::new();
    if let Err(err) = run_vm_cleanup_until_absent(plan) {
        errors.push(err);
    }
    if let Err(err) = plan.remove_firewall_invocation().run() {
        errors.push(err);
    }
    if let Err(err) = run_network_cleanup_until_absent(plan) {
        errors.push(err);
    }
    finish_cleanup_errors(errors)
}

fn finish_cleanup_errors(errors: Vec<ProcessInvocationError>) -> Result<(), CleanupErrors> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(CleanupErrors::new(errors))
    }
}

fn run_vm_cleanup_until_absent(
    plan: &AgentVmSessionStopPlan,
) -> Result<(), ProcessInvocationError> {
    run_cleanup_until_resource_absent(
        &plan.vm_presence_probe(),
        plan.vm_removal_invocations(),
        "VM still appears in container list after removal attempts",
    )
}

fn run_network_cleanup_until_absent(
    plan: &AgentVmSessionStopPlan,
) -> Result<(), ProcessInvocationError> {
    run_cleanup_until_resource_absent(
        &plan.network_presence_probe(),
        plan.network_removal_invocations(),
        "network still appears in container network list after removal attempts",
    )
}

fn run_cleanup_until_resource_absent(
    probe: &ResourcePresenceProbe,
    removals: Vec<ProcessInvocation>,
    still_present: &'static str,
) -> Result<(), ProcessInvocationError> {
    let removals_len = removals.len();
    run_cleanup_until_resource_absent_with(
        removals_len,
        RESOURCE_ABSENCE_ATTEMPTS,
        || probe.contains_resource(),
        |index| {
            // Absence from Apple Container's list output is the cleanup
            // contract; individual removal commands may race or report
            // already-removed resources after an earlier attempt succeeded.
            let _ = removals[index].run();
        },
        || std::thread::sleep(RESOURCE_ABSENCE_DELAY),
        || probe.resource_still_present(still_present),
    )
}

fn run_cleanup_until_resource_absent_with<E>(
    removal_count: usize,
    absence_attempts: usize,
    mut contains_resource: impl FnMut() -> Result<bool, E>,
    mut run_removal: impl FnMut(usize),
    mut wait_before_next_probe: impl FnMut(),
    resource_still_present: impl FnOnce() -> E,
) -> Result<(), E> {
    let mut first_presence_error = match contains_resource() {
        Ok(false) => return Ok(()),
        Ok(true) => None,
        Err(err) => Some(err),
    };
    for removal_index in 0..removal_count {
        run_removal(removal_index);
        match contains_resource() {
            Ok(false) => return Ok(()),
            Ok(true) => {}
            Err(err) => {
                if first_presence_error.is_none() {
                    first_presence_error = Some(err);
                }
            }
        }
    }
    for attempt in 0..absence_attempts {
        match contains_resource() {
            Ok(false) => return Ok(()),
            Ok(true) => {}
            Err(err) => {
                if first_presence_error.is_none() {
                    first_presence_error = Some(err);
                }
            }
        }
        if attempt + 1 < absence_attempts {
            wait_before_next_probe();
        }
    }
    if let Some(err) = first_presence_error {
        return Err(err);
    }
    Err(resource_still_present())
}

fn resource_list_contains_exact_line(raw: &[u8], name: &str) -> bool {
    String::from_utf8_lossy(raw)
        .lines()
        .any(|line| line.trim() == name)
}

fn wait_for_guest_ipv6_inspection(
    plan: &AgentVmSessionPlan,
) -> Result<GuestIpv6Inspection, StartFailure> {
    let invocation = plan.probe_guest_ipv6_invocation();
    let mut last_error = None;
    for attempt in 0..GUEST_IPV6_PROBE_ATTEMPTS {
        match invocation.output() {
            Ok(output) if output.status.success() => {
                return Ok(GuestIpv6Inspection::parse(&String::from_utf8_lossy(
                    &output.stdout,
                ))?);
            }
            Ok(output)
                if output.status.code() == Some(77)
                    && String::from_utf8_lossy(&output.stdout)
                        .contains(GUEST_IPV6_PROBE_UNAVAILABLE_MARKER) =>
            {
                return Err(GuestIpv6InspectionError::ProbeToolUnavailable.into());
            }
            Ok(output) => last_error = Some(invocation.failed_from_output(output)),
            Err(err) => last_error = Some(err),
        }
        if attempt + 1 < GUEST_IPV6_PROBE_ATTEMPTS {
            std::thread::sleep(GUEST_IPV6_PROBE_DELAY);
        }
    }
    Err(last_error
        .expect("guest IPv6 probe attempts must record their last error")
        .into())
}

fn require_field(raw: &str, key: &'static str) -> Result<String, NetworkInspectionError> {
    extract_network_field(raw, key).ok_or(NetworkInspectionError::MissingField(key))
}

fn extract_network_field(raw: &str, key: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw)
        && let Some(found) = find_json_string(&value, key)
    {
        return Some(found);
    }
    for line in raw.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix(key) else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) else {
            continue;
        };
        let value = rest
            .trim()
            .trim_end_matches(',')
            .trim_matches('"')
            .trim()
            .to_string();
        if field_value_is_present(&value) {
            return Some(value);
        }
    }
    None
}

fn find_json_string(value: &serde_json::Value, key: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(fields) => {
            for (field, value) in fields {
                if field == key
                    && let Some(raw) = value.as_str()
                    && field_value_is_present(raw)
                {
                    return Some(raw.to_string());
                }
                if let Some(found) = find_json_string(value, key) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => {
            items.iter().find_map(|item| find_json_string(item, key))
        }
        _ => None,
    }
}

fn field_value_is_present(value: &str) -> bool {
    !value.is_empty() && !matches!(value.to_ascii_lowercase().as_str(), "null" | "none")
}

fn parse_ipv4_cidr_field(
    field: &'static str,
    raw: &str,
) -> Result<Ipv4Cidr, NetworkInspectionError> {
    let (addr, prefix) = split_cidr_field(field, raw)?;
    let addr = addr
        .parse::<Ipv4Addr>()
        .map_err(|e| NetworkInspectionError::InvalidField {
            field,
            value: raw.to_string(),
            message: e.to_string(),
        })?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|e| NetworkInspectionError::InvalidField {
            field,
            value: raw.to_string(),
            message: e.to_string(),
        })?;
    Ipv4Cidr::new(addr, prefix).map_err(|e| NetworkInspectionError::InvalidField {
        field,
        value: raw.to_string(),
        message: e.to_string(),
    })
}

fn parse_ipv6_cidr_field(
    field: &'static str,
    raw: &str,
) -> Result<Ipv6Cidr, NetworkInspectionError> {
    let (addr, prefix) = split_cidr_field(field, raw)?;
    let addr = addr
        .parse::<Ipv6Addr>()
        .map_err(|e| NetworkInspectionError::InvalidField {
            field,
            value: raw.to_string(),
            message: e.to_string(),
        })?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|e| NetworkInspectionError::InvalidField {
            field,
            value: raw.to_string(),
            message: e.to_string(),
        })?;
    Ipv6Cidr::new(addr, prefix).map_err(|e| NetworkInspectionError::InvalidField {
        field,
        value: raw.to_string(),
        message: e.to_string(),
    })
}

fn parse_ipv4_addr_field(
    field: &'static str,
    raw: &str,
) -> Result<Ipv4Addr, NetworkInspectionError> {
    raw.split_once('/')
        .map(|(addr, _)| addr)
        .unwrap_or(raw)
        .parse::<Ipv4Addr>()
        .map_err(|e| NetworkInspectionError::InvalidField {
            field,
            value: raw.to_string(),
            message: e.to_string(),
        })
}

fn parse_ipv6_addr_field(
    field: &'static str,
    raw: &str,
) -> Result<Ipv6Addr, NetworkInspectionError> {
    raw.split_once('/')
        .map(|(addr, _)| addr)
        .unwrap_or(raw)
        .parse::<Ipv6Addr>()
        .map_err(|e| NetworkInspectionError::InvalidField {
            field,
            value: raw.to_string(),
            message: e.to_string(),
        })
}

fn split_cidr_field<'a>(
    field: &'static str,
    raw: &'a str,
) -> Result<(&'a str, &'a str), NetworkInspectionError> {
    raw.split_once('/')
        .ok_or_else(|| NetworkInspectionError::InvalidField {
            field,
            value: raw.to_string(),
            message: "CIDR value must contain '/'".into(),
        })
}

fn ipv6_addr_is_local_only(addr: Ipv6Addr) -> bool {
    addr.is_loopback() || addr.is_unspecified() || ipv6_addr_is_link_local(addr)
}

fn ipv6_addr_is_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

fn validate_ipv4_only_observed_ipv6(
    inspection: &AppleNetworkInspection,
) -> Result<(), NetworkInspectionError> {
    let Some(ipv6_subnet) = inspection.ipv6_subnet else {
        return match inspection.ipv6_gateway {
            Some(_) => Err(NetworkInspectionError::MissingField("ipv6Subnet")),
            None => Ok(()),
        };
    };
    if ipv6_subnet.prefix() != 64 {
        return Err(NetworkInspectionError::InvalidField {
            field: "ipv6Subnet",
            value: ipv6_subnet.to_string(),
            message: "IPv4-only mode only accepts observed IPv6 /64 subnets".into(),
        });
    }
    if !ipv6_cidr_is_ula(ipv6_subnet) {
        return Err(NetworkInspectionError::InvalidField {
            field: "ipv6Subnet",
            value: ipv6_subnet.to_string(),
            message: "IPv4-only mode only accepts observed IPv6 ULA subnets".into(),
        });
    }
    if let Some(ipv6_gateway) = inspection.ipv6_gateway
        && !ipv6_subnet.contains_addr(ipv6_gateway)
    {
        return Err(NetworkInspectionError::Ipv6GatewayOutsideSubnet {
            subnet: ipv6_subnet,
            gateway: ipv6_gateway,
        });
    }
    Ok(())
}

fn ipv6_cidr_is_ula(cidr: Ipv6Cidr) -> bool {
    (cidr.network().segments()[0] & 0xfe00) == 0xfc00
}

fn shell_quote(raw: &str) -> String {
    if !raw.is_empty()
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '='))
    {
        raw.to_string()
    } else {
        format!("'{}'", raw.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use proptest::prelude::*;
    use uuid::Uuid;

    use super::*;
    use crate::core::{BrokerPort, Ipv4Cidr, Ipv6Cidr};

    fn session_id() -> SessionId {
        SessionId::from_uuid(Uuid::from_u128(0x51b8_fd0f_6c10_454c_b0e6_7df1_d60e_2e6d))
    }

    fn pool() -> AgentNetworkPool {
        AgentNetworkPool::new(
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
            Ipv6Cidr::new(
                Ipv6Addr::from(0xfd83_b6f2_0e57_0000_0000_0000_0000_0000u128),
                48,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn ports() -> BrokerPorts {
        BrokerPorts::new([BrokerPort::new(51375).unwrap()]).unwrap()
    }

    fn arb_start_outcome() -> impl Strategy<Value = StartOutcome> {
        prop_oneof![
            Just(StartOutcome::Started),
            Just(StartOutcome::CreateNetworkFailed),
            Just(StartOutcome::InspectNetworkFailed),
            Just(StartOutcome::ParseNetworkInspectionFailed),
            Just(StartOutcome::ValidateNetworkInspectionFailed),
            Just(StartOutcome::InstallFirewallFailed),
            Just(StartOutcome::StartVmFailed),
            Just(StartOutcome::ProbeGuestIpv6Failed),
            Just(StartOutcome::ValidateGuestIpv6Failed),
            Just(StartOutcome::ReleaseGuestCommandFailed),
        ]
    }

    fn plan(index: u16) -> AgentVmSessionPlan {
        plan_with_ipv6_mode(index, Ipv6IsolationMode::DualStackRequired)
    }

    fn plan_with_ipv6_mode(index: u16, ipv6_mode: Ipv6IsolationMode) -> AgentVmSessionPlan {
        AgentVmSessionPlan::new(
            session_id(),
            pool(),
            index,
            ports(),
            BrokerPortRange::new(49152, 65535).unwrap(),
            ipv6_mode,
            ContainerImage::new("alpine:latest").unwrap(),
            vec!["sleep".into(), "600".into()],
            AgentVmResources::new(1, 512).unwrap(),
            AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo"),
        )
        .unwrap()
    }

    fn inspection_for_plan(plan: &AgentVmSessionPlan) -> AppleNetworkInspection {
        let network = plan.network();
        AppleNetworkInspection {
            ipv4_subnet: network.ipv4(),
            ipv4_gateway: network.ipv4_gateway(),
            ipv6_subnet: Some(network.ipv6()),
            ipv6_gateway: Some(Ipv6Addr::from(u128::from(network.ipv6().network()) + 1)),
        }
    }

    #[test]
    fn start_invocations_create_network_then_inspect_then_firewall_then_vm() {
        let invocations = plan(252).start_invocations();
        assert_eq!(invocations.len(), 4);
        assert_eq!(
            invocations[0].args_lossy(),
            [
                "network",
                "create",
                "--internal",
                "--subnet",
                "192.168.252.0/24",
                "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            ]
        );
        assert_eq!(
            invocations[1].args_lossy(),
            [
                "network",
                "inspect",
                "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            ]
        );
        assert_eq!(invocations[2].program(), Path::new("sudo"));
        let firewall_args = invocations[2].args_lossy();
        assert_eq!(&firewall_args[0..2], ["writ-agent-vm-pf-helper", "install"]);
        assert!(firewall_args.contains(&"--ipv6-cidr".to_string()));
        let vm_args = invocations[3].args_lossy();
        assert_eq!(&vm_args[0..2], ["run", "--name"]);
        assert!(
            vm_args.contains(&"writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string())
        );
    }

    #[test]
    fn ipv4_only_start_invocations_probe_before_releasing_guest_command() {
        let invocations =
            plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6).start_invocations();
        assert_eq!(invocations.len(), 6);
        let firewall_args = invocations[2].args_lossy();
        assert_eq!(&firewall_args[0..2], ["writ-agent-vm-pf-helper", "install"]);
        assert!(!firewall_args.contains(&"--ipv6-cidr".to_string()));

        let start_vm_args = invocations[3].args_lossy();
        assert_eq!(&start_vm_args[0..2], ["run", "--name"]);
        assert!(start_vm_args.contains(&"sh".to_string()));
        assert!(start_vm_args.contains(&"-c".to_string()));
        assert!(
            start_vm_args
                .iter()
                .any(|arg| arg.contains("/run/writ-agent-vm/start") && arg.contains("exec \"$@\""))
        );
        assert!(start_vm_args.ends_with(&[
            "writ-agent-vm-prelaunch".into(),
            "sleep".into(),
            "600".into()
        ]));

        assert_eq!(
            invocations[4].args_lossy(),
            [
                "exec",
                "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
                "sh",
                "-c",
                GUEST_IPV6_PROBE_SCRIPT,
            ]
        );
        assert_eq!(
            invocations[5].args_lossy(),
            [
                "exec",
                "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
                "sh",
                "-c",
                "mkdir -p /run/writ-agent-vm && touch /run/writ-agent-vm/start",
            ]
        );
    }

    #[test]
    fn stop_invocations_remove_vm_then_firewall_then_network() {
        let invocations = plan(252).stop_invocations();
        assert_eq!(invocations.len(), 7);
        assert_eq!(
            invocations[0].args_lossy(),
            [
                "rm",
                "-f",
                "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            ]
        );
        assert_eq!(
            invocations[1].args_lossy(),
            ["stop", "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",]
        );
        assert_eq!(
            invocations[2].args_lossy(),
            [
                "delete",
                "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            ]
        );
        assert_eq!(
            invocations[3].args_lossy(),
            ["rm", "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",]
        );
        let firewall_args = invocations[4].args_lossy();
        assert_eq!(&firewall_args[0..2], ["writ-agent-vm-pf-helper", "remove"]);
        assert_eq!(
            invocations[5].args_lossy(),
            [
                "network",
                "rm",
                "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            ]
        );
        assert_eq!(
            invocations[6].args_lossy(),
            [
                "network",
                "delete",
                "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            ]
        );
    }

    #[test]
    fn ipv4_only_stop_invocations_omit_ipv6_firewall_scope() {
        let invocations =
            plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6).stop_invocations();
        let firewall_args = invocations[4].args_lossy();
        assert_eq!(&firewall_args[0..2], ["writ-agent-vm-pf-helper", "remove"]);
        assert!(!firewall_args.contains(&"--ipv6-cidr".to_string()));
    }

    #[test]
    fn stop_cleanup_presence_probes_use_quiet_lists() {
        let stop_plan = plan(252).stop_plan();
        assert_eq!(
            stop_plan.vm_presence_probe().invocation.args_lossy(),
            ["list", "--all", "--quiet"]
        );
        assert_eq!(
            stop_plan.network_presence_probe().invocation.args_lossy(),
            ["network", "list", "--quiet"]
        );
    }

    #[test]
    fn resource_list_presence_requires_an_exact_quiet_line() {
        let name = "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d";
        let listed = format!("other\n{name}\n{name}-old\n");
        assert!(resource_list_contains_exact_line(listed.as_bytes(), name));
        assert!(!resource_list_contains_exact_line(
            format!("{name}-old\nother\n").as_bytes(),
            name
        ));
        assert!(!resource_list_contains_exact_line(
            format!("prefix-{name}\n").as_bytes(),
            name
        ));
    }

    #[test]
    fn failed_firewall_install_cleans_up_network_only() {
        let cleanup = plan(252).cleanup_after_partial_start(CompletedStartStep::NetworkCreated);
        assert_eq!(cleanup.len(), 2);
        let args = cleanup[0].args_lossy();
        assert_eq!(&args[0..2], ["network", "rm"]);
        let args = cleanup[1].args_lossy();
        assert_eq!(&args[0..2], ["network", "delete"]);
    }

    #[test]
    fn failed_vm_start_removes_vm_then_firewall_then_network() {
        let cleanup = plan(252).cleanup_after_partial_start(CompletedStartStep::FirewallInstalled);
        assert_eq!(cleanup.len(), 7);
        let remove_vm_args = cleanup[0].args_lossy();
        let delete_vm_args = cleanup[2].args_lossy();
        let remove_firewall_args = cleanup[4].args_lossy();
        let remove_network_args = cleanup[5].args_lossy();
        assert_eq!(&remove_vm_args[0..2], ["rm", "-f"]);
        assert_eq!(&delete_vm_args[0..1], ["delete"]);
        assert_eq!(
            &remove_firewall_args[0..2],
            ["writ-agent-vm-pf-helper", "remove"]
        );
        assert_eq!(&remove_network_args[0..2], ["network", "rm"]);
    }

    #[test]
    fn broker_url_uses_host_only_gateway_and_broker_port() {
        let urls = plan(252).broker_urls();
        assert_eq!(urls[0].as_str(), "http://192.168.252.1:51375/");
    }

    #[test]
    fn network_inspect_without_ipv6_is_explicitly_mode_dependent() {
        let raw = r#"
            mode: hostOnly
            ipv4Subnet: 192.168.252.0/24
            ipv4Gateway: 192.168.252.1
        "#;
        let inspection = AppleNetworkInspection::parse(raw).unwrap();
        assert_eq!(
            plan(252).validate_network_inspection(&inspection),
            Err(NetworkInspectionError::MissingField("ipv6Subnet"))
        );
        plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6)
            .validate_network_inspection(&inspection)
            .unwrap();
    }

    proptest! {
        #[test]
        fn ipv4_only_mode_accepts_observed_ula_ipv6_without_treating_it_as_pf_scope(index in any::<u8>()) {
            let alternate_index = u16::from(index.wrapping_add(1));
            let index = u16::from(index);
            let dual_stack_plan = plan(index);
            let ipv4_only_plan = plan_with_ipv6_mode(index, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
            let matching = inspection_for_plan(&dual_stack_plan);

            let matching_subnet_without_gateway = AppleNetworkInspection {
                ipv6_gateway: None,
                ..matching.clone()
            };
            prop_assert_eq!(
                dual_stack_plan.validate_network_inspection(&matching_subnet_without_gateway),
                Err(NetworkInspectionError::MissingField("ipv6Gateway"))
            );
            prop_assert_eq!(
                ipv4_only_plan.validate_network_inspection(&matching_subnet_without_gateway),
                Ok(())
            );

            let alternate = pool().allocate(alternate_index).unwrap();
            let apple_chosen_subnet_without_gateway = AppleNetworkInspection {
                ipv6_subnet: Some(alternate.ipv6()),
                ipv6_gateway: None,
                ..matching.clone()
            };
            prop_assert_eq!(
                ipv4_only_plan.validate_network_inspection(&apple_chosen_subnet_without_gateway),
                Ok(())
            );

            let public_subnet_without_gateway = AppleNetworkInspection {
                ipv6_subnet: Some(Ipv6Cidr::new("2001:db8::".parse().unwrap(), 64).unwrap()),
                ipv6_gateway: None,
                ..matching.clone()
            };
            let got_invalid_public_subnet = matches!(
                ipv4_only_plan.validate_network_inspection(&public_subnet_without_gateway),
                Err(NetworkInspectionError::InvalidField { field: "ipv6Subnet", .. })
            );
            prop_assert!(got_invalid_public_subnet);

            let gateway_without_subnet = AppleNetworkInspection {
                ipv6_subnet: None,
                ..matching.clone()
            };
            prop_assert_eq!(
                ipv4_only_plan.validate_network_inspection(&gateway_without_subnet),
                Err(NetworkInspectionError::MissingField("ipv6Subnet"))
            );

            let outside_gateway = AppleNetworkInspection {
                ipv6_subnet: Some(alternate.ipv6()),
                ipv6_gateway: Some(Ipv6Addr::from(u128::from(alternate.ipv6().network()) + (1u128 << 64))),
                ..matching
            };
            let got_gateway_outside_subnet = matches!(
                ipv4_only_plan.validate_network_inspection(&outside_gateway),
                Err(NetworkInspectionError::Ipv6GatewayOutsideSubnet { .. })
            );
            prop_assert!(got_gateway_outside_subnet);
        }
    }

    #[test]
    fn network_inspect_parser_accepts_nested_json() {
        let raw = serde_json::json!({
            "network": {
                "ipv4Subnet": "192.168.252.0/24",
                "ipv4Gateway": "192.168.252.1/24",
                "nested": {
                    "ipv6Subnet": "fd83:b6f2:e57:fc::/64",
                    "ipv6Gateway": "fd83:b6f2:e57:fc::1/64"
                }
            }
        })
        .to_string();
        let parsed = AppleNetworkInspection::parse(&raw).unwrap();
        assert_eq!(parsed.ipv4_subnet().to_string(), "192.168.252.0/24");
        assert_eq!(parsed.ipv4_gateway(), Ipv4Addr::new(192, 168, 252, 1));
        assert_eq!(
            parsed.ipv6_subnet().unwrap().to_string(),
            "fd83:b6f2:e57:fc::/64"
        );
        assert_eq!(
            parsed.ipv6_gateway(),
            Some(Ipv6Addr::from(
                0xfd83_b6f2_0e57_00fc_0000_0000_0000_0001u128
            ))
        );
    }

    #[test]
    fn network_inspection_must_match_the_allocated_session_network() {
        let plan = plan(252);
        let matching = AppleNetworkInspection::parse(
            r#"
            ipv4Subnet: 192.168.252.0/24
            ipv4Gateway: 192.168.252.1
            ipv6Subnet: fd83:b6f2:e57:fc::/64
            ipv6Gateway: fd83:b6f2:e57:fc::1
            "#,
        )
        .unwrap();
        plan.validate_network_inspection(&matching).unwrap();

        let wrong_v6 = AppleNetworkInspection::parse(
            r#"
            ipv4Subnet: 192.168.252.0/24
            ipv4Gateway: 192.168.252.1
            ipv6Subnet: fd83:b6f2:e57:fd::/64
            ipv6Gateway: fd83:b6f2:e57:fd::1
            "#,
        )
        .unwrap();
        assert!(matches!(
            plan.validate_network_inspection(&wrong_v6),
            Err(NetworkInspectionError::Ipv6SubnetMismatch { .. })
        ));
    }

    #[test]
    fn image_and_resources_reject_empty_values() {
        assert_eq!(
            ContainerImage::new(" "),
            Err(AgentVmLifecycleConfigError::EmptyImage)
        );
        assert_eq!(
            AgentVmResources::new(0, 512),
            Err(AgentVmLifecycleConfigError::EmptyCpuCount)
        );
        assert_eq!(
            AgentVmResources::new(1, 0),
            Err(AgentVmLifecycleConfigError::EmptyMemory)
        );
        assert_eq!(
            AgentVmSessionPlan::new(
                session_id(),
                pool(),
                252,
                ports(),
                BrokerPortRange::new(49152, 65535).unwrap(),
                Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
                ContainerImage::new("alpine:latest").unwrap(),
                Vec::new(),
                AgentVmResources::new(1, 512).unwrap(),
                AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo"),
            ),
            Err(AgentVmLifecycleConfigError::EmptyGuestCommandForIpv4OnlyNoGuestIpv6)
        );
    }

    #[test]
    fn guest_ipv6_posture_accepts_link_local_only() {
        let inspection = GuestIpv6Inspection::parse(
            r#"
            1: lo    inet6 ::1/128 scope host
            2: eth0    inet6 fe80::1234/64 scope link
            "#,
        )
        .unwrap();
        inspection.require_no_routable_ipv6().unwrap();
        assert_eq!(inspection.addresses().len(), 2);
        assert!(inspection.default_routes().is_empty());
    }

    #[test]
    fn guest_ipv6_posture_rejects_global_scope_addresses_and_default_routes() {
        let address =
            GuestIpv6Inspection::parse("2: eth0    inet6 fd83:b6f2:e57:fc::2/64 scope global")
                .unwrap()
                .require_no_routable_ipv6()
                .unwrap_err();
        assert!(matches!(
            address,
            GuestIpv6InspectionError::NonLinkLocalAddress(addr)
                if addr == Ipv6Addr::from(0xfd83_b6f2_0e57_00fc_0000_0000_0000_0002u128)
        ));

        let route = GuestIpv6Inspection::parse("default via fe80::1 dev eth0 metric 1024")
            .unwrap()
            .require_no_routable_ipv6()
            .unwrap_err();
        assert!(matches!(route, GuestIpv6InspectionError::DefaultRoute(_)));
    }

    #[test]
    fn guest_ipv6_posture_reports_missing_probe_tool() {
        assert_eq!(
            GuestIpv6Inspection::parse(GUEST_IPV6_PROBE_UNAVAILABLE_MARKER),
            Err(GuestIpv6InspectionError::ProbeToolUnavailable)
        );
    }

    #[test]
    fn guest_ipv6_probe_script_fails_closed_on_partial_probe_failure() {
        assert!(GUEST_IPV6_PROBE_SCRIPT.starts_with("set -e\n"));
        assert!(GUEST_IPV6_PROBE_SCRIPT.contains("addr show 2>&1"));
        assert!(GUEST_IPV6_PROBE_SCRIPT.contains("route show default 2>&1"));
    }

    #[test]
    fn cleanup_collects_every_failed_step() {
        let mut errors = Vec::new();
        for invocation in [
            ProcessInvocation::new("/tmp/writ-missing-cleanup-one", ["one"]),
            ProcessInvocation::new("/tmp/writ-missing-cleanup-two", ["two"]),
        ] {
            errors.push(invocation.run().unwrap_err());
        }
        let errors = finish_cleanup_errors(errors).unwrap_err();
        assert_eq!(errors.errors().len(), 2);
        assert!(errors.to_string().contains("2 cleanup step(s) failed"));
    }

    #[test]
    fn cleanup_absence_loop_stops_after_first_absent_probe() {
        let mut outcomes = VecDeque::from([Ok(true), Ok(false)]);
        let mut removals = Vec::new();
        let mut waits = 0;
        run_cleanup_until_resource_absent_with(
            3,
            5,
            || outcomes.pop_front().expect("unexpected extra probe"),
            |index| removals.push(index),
            || waits += 1,
            || "still present",
        )
        .unwrap();
        assert_eq!(removals, vec![0]);
        assert_eq!(waits, 0);
        assert!(outcomes.is_empty());
    }

    #[test]
    fn cleanup_absence_loop_tries_every_removal_before_polling() {
        let mut outcomes = VecDeque::from([Ok(true), Ok(true), Ok(true), Ok(false)]);
        let mut removals = Vec::new();
        let mut waits = 0;
        run_cleanup_until_resource_absent_with(
            2,
            3,
            || outcomes.pop_front().expect("unexpected extra probe"),
            |index| removals.push(index),
            || waits += 1,
            || "still present",
        )
        .unwrap();
        assert_eq!(removals, vec![0, 1]);
        assert_eq!(waits, 0);
        assert!(outcomes.is_empty());
    }

    #[test]
    fn cleanup_absence_loop_surfaces_first_presence_probe_error() {
        let mut outcomes = VecDeque::from([
            Err("first probe failed"),
            Err("second probe failed"),
            Err("third probe failed"),
            Err("fourth probe failed"),
            Err("fifth probe failed"),
        ]);
        let mut removals = Vec::new();
        let mut waits = 0;
        let err = run_cleanup_until_resource_absent_with(
            2,
            2,
            || outcomes.pop_front().expect("unexpected extra probe"),
            |index| removals.push(index),
            || waits += 1,
            || "still present",
        )
        .unwrap_err();
        assert_eq!(err, "first probe failed");
        assert_eq!(removals, vec![0, 1]);
        assert_eq!(waits, 1);
        assert!(outcomes.is_empty());
    }

    #[test]
    fn cleanup_absence_loop_reports_still_present_after_bounded_retries() {
        let mut outcomes = VecDeque::from([Ok(true), Ok(true), Ok(true), Ok(true), Ok(true)]);
        let mut removals = Vec::new();
        let mut waits = 0;
        let err = run_cleanup_until_resource_absent_with(
            2,
            2,
            || outcomes.pop_front().expect("unexpected extra probe"),
            |index| removals.push(index),
            || waits += 1,
            || "still present",
        )
        .unwrap_err();
        assert_eq!(err, "still present");
        assert_eq!(removals, vec![0, 1]);
        assert_eq!(waits, 1);
        assert!(outcomes.is_empty());
    }

    #[test]
    fn resource_still_present_error_names_cleanup_postcondition() {
        let err = ProcessInvocation::new("container", ["list", "--quiet"])
            .resource_still_present("VM still appears in container list");
        assert!(matches!(
            err,
            ProcessInvocationError::ResourceStillPresent { message, .. }
                if message == "VM still appears in container list"
        ));
    }

    proptest! {
        #[test]
        fn planned_network_matches_pool_allocation(index in any::<u8>()) {
            let index = u16::from(index);
            let plan = plan(index);
            prop_assert_eq!(plan.network(), pool().allocate(index).unwrap());
        }

        #[test]
        fn start_outcome_maps_to_the_expected_cleanup(outcome in arb_start_outcome()) {
            let cleanup = plan(7).cleanup_after_start_outcome(outcome);
            let expected_len = match outcome {
                StartOutcome::Started | StartOutcome::CreateNetworkFailed => 0,
                StartOutcome::InspectNetworkFailed
                | StartOutcome::ParseNetworkInspectionFailed
                | StartOutcome::ValidateNetworkInspectionFailed
                | StartOutcome::InstallFirewallFailed => 2,
                StartOutcome::StartVmFailed
                | StartOutcome::ProbeGuestIpv6Failed
                | StartOutcome::ValidateGuestIpv6Failed
                | StartOutcome::ReleaseGuestCommandFailed => 7,
            };
            prop_assert_eq!(cleanup.len(), expected_len);
            let only_removes = cleanup.iter().all(|cmd| {
                let rendered = cmd.display_shell();
                !rendered.contains(" network create ") && !rendered.contains(" install ") && !rendered.contains(" run ")
            });
            prop_assert!(only_removes);
        }

        #[test]
        fn network_inspection_accepts_exact_match_and_rejects_each_mutated_field(index in any::<u8>()) {
            let alternate_index = u16::from(index.wrapping_add(1));
            let index = u16::from(index);
            let plan = plan(index);
            let matching = inspection_for_plan(&plan);
            prop_assert_eq!(plan.validate_network_inspection(&matching), Ok(()));

            let alternate = pool().allocate(alternate_index).unwrap();

            let wrong_v4_subnet = AppleNetworkInspection {
                ipv4_subnet: alternate.ipv4(),
                ..matching.clone()
            };
            let got_v4_subnet_mismatch = matches!(
                plan.validate_network_inspection(&wrong_v4_subnet),
                Err(NetworkInspectionError::Ipv4SubnetMismatch { .. })
            );
            prop_assert!(got_v4_subnet_mismatch);

            let wrong_v4_gateway = AppleNetworkInspection {
                ipv4_gateway: Ipv4Addr::from(u32::from(plan.network().ipv4_gateway()) + 1),
                ..matching.clone()
            };
            let got_v4_gateway_mismatch = matches!(
                plan.validate_network_inspection(&wrong_v4_gateway),
                Err(NetworkInspectionError::Ipv4GatewayMismatch { .. })
            );
            prop_assert!(got_v4_gateway_mismatch);

            let wrong_v6_subnet = AppleNetworkInspection {
                ipv6_subnet: Some(alternate.ipv6()),
                ..matching.clone()
            };
            let got_v6_subnet_mismatch = matches!(
                plan.validate_network_inspection(&wrong_v6_subnet),
                Err(NetworkInspectionError::Ipv6SubnetMismatch { .. })
            );
            prop_assert!(got_v6_subnet_mismatch);

            let wrong_v6_gateway = AppleNetworkInspection {
                ipv6_gateway: Some(Ipv6Addr::from(u128::from(alternate.ipv6().network()) + 1)),
                ..matching
            };
            let got_v6_gateway_mismatch = matches!(
                plan.validate_network_inspection(&wrong_v6_gateway),
                Err(NetworkInspectionError::Ipv6GatewayOutsideSubnet { .. })
            );
            prop_assert!(got_v6_gateway_mismatch);
        }

        #[test]
        fn guest_ipv6_posture_rejects_any_ula_address(
            second in any::<u8>(),
            third in any::<u16>(),
            fourth in any::<u16>(),
            host in 1u16..=u16::MAX,
        ) {
            let first_segment = 0xfd00u16 | u16::from(second);
            let addr = Ipv6Addr::new(first_segment, third, fourth, 0, 0, 0, 0, host);
            let raw = format!("2: eth0    inet6 {addr}/64 scope global");
            let got = GuestIpv6Inspection::parse(&raw)
                .unwrap()
                .require_no_routable_ipv6();
            prop_assert_eq!(got, Err(GuestIpv6InspectionError::NonLinkLocalAddress(addr)));
        }

        #[test]
        fn guest_ipv6_posture_accepts_any_link_local_address(
            low_first_segment_bits in 0u16..=0x003f,
            second in any::<u16>(),
            third in any::<u16>(),
            host in any::<u16>(),
        ) {
            let addr = Ipv6Addr::new(0xfe80 | low_first_segment_bits, second, third, 0, 0, 0, 0, host);
            let raw = format!("2: eth0    inet6 {addr}/64 scope link");
            GuestIpv6Inspection::parse(&raw)
                .unwrap()
                .require_no_routable_ipv6()
                .unwrap();
        }
    }
}
