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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmSessionPlan {
    session_id: SessionId,
    pool: AgentNetworkPool,
    network: AgentNetwork,
    names: AgentVmNames,
    broker_ports: BrokerPorts,
    broker_port_range: BrokerPortRange,
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
pub struct AppleNetworkInspection {
    ipv4_subnet: Ipv4Cidr,
    ipv4_gateway: Ipv4Addr,
    ipv6_subnet: Ipv6Cidr,
    ipv6_gateway: Ipv6Addr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerUrl(String);

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

#[derive(Debug, thiserror::Error)]
pub enum AgentVmLifecycleRunError {
    #[error(transparent)]
    Start(#[from] StartFailure),
    #[error("start failed: {original}; cleanup also failed: {cleanup}")]
    CleanupAfterFailure {
        #[source]
        original: StartFailure,
        cleanup: CleanupErrors,
    },
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
        StartOutcome::StartVmFailed => Some(CompletedStartStep::FirewallInstalled),
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
        image: ContainerImage,
        guest_command: Vec<String>,
        resources: AgentVmResources,
        tools: AgentVmToolPaths,
    ) -> Result<Self, AgentVmLifecycleConfigError> {
        broker_port_range.require_contains(&broker_ports)?;
        let network = pool.allocate(subnet_index)?;
        Ok(Self {
            session_id,
            pool,
            network,
            names: AgentVmNames::for_session(session_id),
            broker_ports,
            broker_port_range,
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
        vec![
            self.create_network_invocation(),
            self.inspect_network_invocation(),
            self.install_firewall_invocation(),
            self.start_vm_invocation(),
        ]
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
            CompletedStartStep::NetworkCreated => {
                vec![self.stop_plan().remove_network_invocation()]
            }
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
            names: self.names.clone(),
            tools: self.tools.clone(),
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
        if inspection.ipv6_subnet != self.network.ipv6() {
            return Err(NetworkInspectionError::Ipv6SubnetMismatch {
                expected: self.network.ipv6(),
                actual: inspection.ipv6_subnet,
            });
        }
        if !self.network.ipv6().contains_addr(inspection.ipv6_gateway) {
            return Err(NetworkInspectionError::Ipv6GatewayOutsideSubnet {
                subnet: self.network.ipv6(),
                gateway: inspection.ipv6_gateway,
            });
        }
        Ok(())
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
            OsString::from("--ipv6-cidr"),
            OsString::from(self.network.ipv6().to_string()),
        ];
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
        args.extend(self.guest_command.iter().cloned());
        ProcessInvocation::new(self.tools.container.clone(), args)
    }
}

impl AgentVmSessionStopPlan {
    pub fn new(
        session_id: SessionId,
        pool: AgentNetworkPool,
        subnet_index: u16,
        tools: AgentVmToolPaths,
    ) -> Result<Self, AgentVmLifecycleConfigError> {
        let network = pool.allocate(subnet_index)?;
        Ok(Self {
            session_id,
            pool,
            network,
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
        vec![
            self.remove_vm_invocation(),
            self.remove_firewall_invocation(),
            self.remove_network_invocation(),
        ]
    }

    fn remove_vm_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.tools.container.clone(),
            ["rm".to_string(), "-f".to_string(), self.names.vm.clone()],
        )
    }

    fn remove_firewall_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.tools.sudo.clone(),
            [
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
                OsString::from("--ipv6-cidr"),
                OsString::from(self.network.ipv6().to_string()),
            ],
        )
    }

    fn remove_network_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.tools.container.clone(),
            [
                "network".to_string(),
                "rm".to_string(),
                self.names.network.clone(),
            ],
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
        Err(ProcessInvocationError::Failed {
            program: self.program.display().to_string(),
            args: self.args_display(),
            status: output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".into()),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
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

impl AppleNetworkInspection {
    pub fn parse(raw: &str) -> Result<Self, NetworkInspectionError> {
        let ipv4_subnet = parse_ipv4_cidr_field("ipv4Subnet", &require_field(raw, "ipv4Subnet")?)?;
        let ipv4_gateway =
            parse_ipv4_addr_field("ipv4Gateway", &require_field(raw, "ipv4Gateway")?)?;
        let ipv6_subnet = parse_ipv6_cidr_field("ipv6Subnet", &require_field(raw, "ipv6Subnet")?)?;
        let ipv6_gateway =
            parse_ipv6_addr_field("ipv6Gateway", &require_field(raw, "ipv6Gateway")?)?;
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

    pub fn ipv6_subnet(&self) -> Ipv6Cidr {
        self.ipv6_subnet
    }

    pub fn ipv6_gateway(&self) -> Ipv6Addr {
        self.ipv6_gateway
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
            let err = ProcessInvocationError::Failed {
                program: inspect_invocation.program.display().to_string(),
                args: inspect_invocation.args_display(),
                status: output
                    .status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".into()),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            };
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
    Ok(())
}

pub fn stop_agent_vm_session(plan: &AgentVmSessionStopPlan) -> Result<(), CleanupErrors> {
    run_cleanup(plan.stop_invocations())
}

fn fail_after_cleanup<T>(
    original: StartFailure,
    plan: &AgentVmSessionPlan,
    outcome: StartOutcome,
) -> Result<T, AgentVmLifecycleRunError> {
    match run_cleanup(plan.cleanup_after_start_outcome(outcome)) {
        Ok(()) => Err(original.into()),
        Err(cleanup) => Err(AgentVmLifecycleRunError::CleanupAfterFailure { original, cleanup }),
    }
}

fn run_cleanup(invocations: Vec<ProcessInvocation>) -> Result<(), CleanupErrors> {
    let mut errors = Vec::new();
    for invocation in invocations {
        if let Err(err) = invocation.run() {
            errors.push(err);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(CleanupErrors::new(errors))
    }
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
        ]
    }

    fn plan(index: u16) -> AgentVmSessionPlan {
        AgentVmSessionPlan::new(
            session_id(),
            pool(),
            index,
            ports(),
            BrokerPortRange::new(49152, 65535).unwrap(),
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
            ipv6_subnet: network.ipv6(),
            ipv6_gateway: Ipv6Addr::from(u128::from(network.ipv6().network()) + 1),
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
        let vm_args = invocations[3].args_lossy();
        assert_eq!(&vm_args[0..2], ["run", "--name"]);
        assert!(
            vm_args.contains(&"writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string())
        );
    }

    #[test]
    fn stop_invocations_remove_vm_then_firewall_then_network() {
        let invocations = plan(252).stop_invocations();
        assert_eq!(invocations.len(), 3);
        assert_eq!(
            invocations[0].args_lossy(),
            [
                "rm",
                "-f",
                "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            ]
        );
        let firewall_args = invocations[1].args_lossy();
        assert_eq!(&firewall_args[0..2], ["writ-agent-vm-pf-helper", "remove"]);
        assert_eq!(
            invocations[2].args_lossy(),
            [
                "network",
                "rm",
                "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            ]
        );
    }

    #[test]
    fn failed_firewall_install_cleans_up_network_only() {
        let cleanup = plan(252).cleanup_after_partial_start(CompletedStartStep::NetworkCreated);
        assert_eq!(cleanup.len(), 1);
        let args = cleanup[0].args_lossy();
        assert_eq!(&args[0..2], ["network", "rm"]);
    }

    #[test]
    fn failed_vm_start_removes_vm_then_firewall_then_network() {
        let cleanup = plan(252).cleanup_after_partial_start(CompletedStartStep::FirewallInstalled);
        assert_eq!(cleanup.len(), 3);
        let remove_vm_args = cleanup[0].args_lossy();
        let remove_firewall_args = cleanup[1].args_lossy();
        let remove_network_args = cleanup[2].args_lossy();
        assert_eq!(&remove_vm_args[0..2], ["rm", "-f"]);
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
    fn network_inspect_parser_requires_ipv6_fields() {
        let raw = r#"
            mode: hostOnly
            ipv4Subnet: 192.168.252.0/24
            ipv4Gateway: 192.168.252.1
        "#;
        assert_eq!(
            AppleNetworkInspection::parse(raw),
            Err(NetworkInspectionError::MissingField("ipv6Subnet"))
        );
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
        assert_eq!(parsed.ipv6_subnet().to_string(), "fd83:b6f2:e57:fc::/64");
        assert_eq!(
            parsed.ipv6_gateway(),
            Ipv6Addr::from(0xfd83_b6f2_0e57_00fc_0000_0000_0000_0001u128)
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
    }

    #[test]
    fn cleanup_collects_every_failed_step() {
        let errors = run_cleanup(vec![
            ProcessInvocation::new("/tmp/writ-missing-cleanup-one", ["one"]),
            ProcessInvocation::new("/tmp/writ-missing-cleanup-two", ["two"]),
        ])
        .unwrap_err();
        assert_eq!(errors.errors().len(), 2);
        assert!(errors.to_string().contains("2 cleanup step(s) failed"));
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
                | StartOutcome::InstallFirewallFailed => 1,
                StartOutcome::StartVmFailed => 3,
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
            let index = u16::from(index);
            let plan = plan(index);
            let matching = inspection_for_plan(&plan);
            prop_assert_eq!(plan.validate_network_inspection(&matching), Ok(()));

            let alternate = pool().allocate(u16::from(index.wrapping_add(1))).unwrap();

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
                ipv6_subnet: alternate.ipv6(),
                ..matching.clone()
            };
            let got_v6_subnet_mismatch = matches!(
                plan.validate_network_inspection(&wrong_v6_subnet),
                Err(NetworkInspectionError::Ipv6SubnetMismatch { .. })
            );
            prop_assert!(got_v6_subnet_mismatch);

            let wrong_v6_gateway = AppleNetworkInspection {
                ipv6_gateway: Ipv6Addr::from(u128::from(alternate.ipv6().network()) + 1),
                ..matching
            };
            let got_v6_gateway_mismatch = matches!(
                plan.validate_network_inspection(&wrong_v6_gateway),
                Err(NetworkInspectionError::Ipv6GatewayOutsideSubnet { .. })
            );
            prop_assert!(got_v6_gateway_mismatch);
        }
    }
}
