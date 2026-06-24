//! Unprivileged lifecycle planning for Apple-container agent VM sessions.
//!
//! This module keeps the session launch as data: create the Apple internal
//! network, install the already-validated PF session anchor through the helper,
//! then start the VM. The small imperative edge at the bottom interprets those
//! descriptions as process invocations.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::broker_vm::{BrokerVmNames, broker_vm_removal_invocations};
use crate::core::{
    AgentNetwork, AgentNetworkPool, AgentVmConfigError, BrokerPortRange, BrokerPorts, Ipv4Cidr,
    Ipv6Cidr, SessionId,
};
use crate::process_spawn;

mod parse;
use parse::validate_ipv4_only_observed_ipv6;
pub use parse::{
    AppleNetworkInspection, GuestIpv6Inspection, GuestIpv6InspectionError, NetworkInspectionError,
};
mod state_store;
pub use state_store::{
    AgentVmSessionState, AgentVmSessionStateError, AgentVmSessionStateStore, AgentVmStateDirError,
    default_agent_vm_state_dir,
};
mod network_health;
#[cfg(unix)]
pub use network_health::host_interfaces;
pub use network_health::{
    HealthTransition, HostIface, NETWORK_HEALTH_FAILURE_THRESHOLD, NetworkHealth, ProbeDebounce,
    ProbeObservation, evaluate_host_path,
};

const IPV4_ONLY_PRELAUNCH_SCRIPT: &str = concat!(
    "set -eu\n",
    "mkdir -p /run/writ-agent-vm\n",
    "while [ ! -f /run/writ-agent-vm/start ]; do sleep 0.2; done\n",
    "exec \"$@\"",
);

/// Under [`Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6`], the guest's start sequence
/// runs this in the guest: it first *enforces* "no guest IPv6" by disabling
/// IPv6 in the guest kernel, then reports the resulting state for
/// [`GuestIpv6Inspection`] to validate.
///
/// Why enforce, not just observe: the agent network is created `--internal`
/// and IPv4-only (no `--subnet-v6`), but the host's Apple `container`/vmnet
/// layer can still advertise IPv6 Router Advertisements on the shared vmnet —
/// observed after a macOS update (26.5.1 / `container` 0.11.0): a guest with
/// default `accept_ra` SLAACs a global-scope ULA (`fd…/64 … proto kernel_ra`)
/// a beat after boot, defeating the no-guest-IPv6 posture. Refusing the RA at
/// the *network* layer is not in our control (vmnet sends it regardless of the
/// network's own v6 config), so we refuse it at the *guest kernel* layer:
/// `disable_ipv6=1` on `all` (which flushes every existing IPv6 address,
/// including any already SLAAC'd) and `default` (so any interface that appears
/// later is born without IPv6). Verified on a throwaway container: the write
/// drops the RA-acquired address immediately.
///
/// Enforce and report are one atomic guest exec, so there is no window between
/// a separate "disable" and "probe" in which a fresh RA could re-add an
/// address. The report is still load-bearing: if the disable writes had failed
/// (e.g. a read-only `/proc`), the RA address would remain and
/// [`GuestIpv6Inspection::require_no_routable_ipv6`] would fail the start — the
/// validation confirms the enforcement actually took.
///
/// Fail-closed enforcement: for each sysctl that EXISTS we write `1` and then
/// read it back, failing the start unless it actually reads `1`. Only an
/// *absent* path is tolerated (a guest kernel with no IPv6 has nothing to
/// disable and cannot acquire an RA address). A present-but-unwritable sysctl
/// — `container exec` as a non-root user, a read-only `/proc/sys` — must NOT
/// pass: the read-back is what catches it, independent of why the write didn't
/// take, rather than trusting the `ip -6` snapshot (which could look clean if
/// the RA simply has not arrived yet, only to gain the ULA moments later).
const GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT: &str = r#"set -e
for scope in all default; do
  path="/proc/sys/net/ipv6/conf/$scope/disable_ipv6"
  [ -e "$path" ] || continue
  printf 1 > "$path" 2>/dev/null || true
  read -r state < "$path" 2>/dev/null || state=
  [ "$state" = 1 ] || { echo "writ-ipv6-not-disabled $path=$state"; exit 1; }
done
if ! command -v ip >/dev/null 2>&1; then echo writ-ip-command-missing; exit 77; fi
ip -6 -o addr show 2>&1
ip -6 route show default 2>&1"#;

const GUEST_IPV6_PROBE_UNAVAILABLE_MARKER: &str = "writ-ip-command-missing";
const GUEST_IPV6_PROBE_ATTEMPTS: usize = 40;
const _: () = assert!(
    GUEST_IPV6_PROBE_ATTEMPTS > 0,
    "wait_for_guest_ipv6_inspection requires at least one attempt"
);
const GUEST_IPV6_PROBE_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
// Apple Container removals can lag command return briefly. Keep the
// postcondition wait bounded: after three seconds, report that cleanup could
// not prove absence instead of claiming success.
const RESOURCE_ABSENCE_ATTEMPTS: usize = 30;
const RESOURCE_ABSENCE_DELAY: std::time::Duration = std::time::Duration::from_millis(100);
const GUEST_ENV_FILE_DISPLAY: &str = "<runtime-env-file>";
// Keep this list in sync with guestRuntimeDirs in flake.nix. The image
// provides conventional mount targets, and the lifecycle makes them writable
// per-session tmpfs state at container start.
const AGENT_VM_TMPFS_MOUNTS: &[&str] = &["/tmp", "/run", "/var/tmp", "/root"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmSessionPlan {
    session_id: SessionId,
    pool: AgentNetworkPool,
    subnet_index: u16,
    network: AgentNetwork,
    names: AgentVmNames,
    broker_ports: BrokerPorts,
    broker_port_range: BrokerPortRange,
    ipv6_mode: Ipv6IsolationMode,
    /// Where the session's broker runs. In `Vm` mode the broker arm owns the
    /// shared network (created/inspected before the agent), so the agent's start
    /// sequence and failure-cleanup omit the network create/remove (host PF still
    /// applies — `--internal` does not isolate the agent from host services).
    broker_placement: BrokerPlacement,
    /// IPv4 endpoint the host PF allows the agent to reach on the broker ports.
    /// `None` (host placement) defaults to the subnet gateway. For vm placement
    /// it is the broker VM's discovered IP, so the agent reaches its broker VM
    /// while the gateway and the rest of the subnet stay blocked.
    broker_pf_host: Option<Ipv4Addr>,
    image: ContainerImage,
    guest_env: Vec<AgentVmGuestEnvVar>,
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
    /// In `Vm` mode the broker arm owns the shared network and no host PF was
    /// installed, so teardown removes the agent VM only.
    broker_placement: BrokerPlacement,
    tools: AgentVmToolPaths,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmNames {
    network: String,
    vm: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerImage(String);

#[derive(Clone, Eq, PartialEq)]
pub struct AgentVmGuestEnvVar {
    name: String,
    value: String,
}

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
pub enum AgentVmStartInvocation {
    Static(ProcessInvocation),
    RuntimeGuestEnvFile {
        invocation: ProcessInvocation,
        display_shell: String,
    },
}

/// One step in the start sequence. [`start_agent_vm_session`] interprets these
/// in order; [`AgentVmSessionPlan::start_invocations`] projects them for
/// dry-run display. Each variant's type fixes which [`StartOutcome`] variants
/// its internal failures can produce; `step_failure_outcomes` and
/// `step_cleanup_phase` make that mapping explicit, and a property test pins
/// it to [`cleanup_step_after_start_outcome`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentVmStartStep {
    CreateNetwork(ProcessInvocation),
    InspectAndValidateNetwork(ProcessInvocation),
    InstallFirewall(ProcessInvocation),
    StartVm(AgentVmStartInvocation),
    ProbeAndValidateGuestIpv6 { probe_invocation: ProcessInvocation },
    ReleaseGuestCommand(ProcessInvocation),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResourcePresenceProbe {
    invocation: ProcessInvocation,
    name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerUrl(String);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6IsolationMode {
    DualStackRequired,
    Ipv4OnlyNoGuestIpv6,
}

/// Where the per-session vm_http broker runs.
///
/// `Host` (the default) spins the broker up in-process on the macOS host and the
/// guest reaches it at the subnet gateway — today's behavior. `Vm` runs the
/// broker in a dedicated trusted VM so the agent→broker `accept()` happens in
/// Linux, working around the macOS `container`/vmnet defect where the host's
/// `accept()` returns a not-connected socket for guest connections (see
/// `docs/vmnet-accept-bug-and-broker-vm-plan.md`).
///
/// This is a selectable placement, not a one-way migration: `Host` stays the
/// default and the revert target, so when the vmnet bug is fixed the `Vm`
/// machinery can be bypassed (and later deleted) by flipping this back.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BrokerPlacement {
    #[default]
    Host,
    Vm,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentVmSessionStateStatus {
    Starting,
    Running,
}

impl AgentVmSessionStateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
        }
    }
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
    #[error("guest environment variable name must not be empty")]
    EmptyGuestEnvName,
    #[error("guest environment variable name must start with ASCII letter or underscore: {0}")]
    InvalidGuestEnvNameStart(String),
    #[error(
        "guest environment variable name must contain only ASCII letters, digits, or underscores: {0}"
    )]
    InvalidGuestEnvNameByte(String),
    #[error("guest environment variable {name} value must not contain NUL or newline bytes")]
    InvalidGuestEnvValue { name: String },
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
    #[error(transparent)]
    GuestEnvironment(#[from] GuestEnvironmentError),
}

#[derive(Debug, thiserror::Error)]
pub enum GuestEnvironmentError {
    #[error("cannot {operation} guest environment file {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
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

#[derive(Debug, thiserror::Error)]
pub enum AgentVmSessionManagerError {
    #[error(transparent)]
    State(#[from] AgentVmSessionStateError),
    #[error(transparent)]
    Start(#[from] AgentVmLifecycleRunError),
    #[error(transparent)]
    Stop(#[from] CleanupErrors),
    #[error("start failed: {start}; removing state also failed: {state}")]
    StartStateCleanup {
        start: Box<AgentVmLifecycleRunError>,
        state: Box<AgentVmSessionStateError>,
    },
    #[error(
        "session started but recording running state failed: {state}; starting state remains for cleanup"
    )]
    RunningStateUpdateAfterStart {
        state: Box<AgentVmSessionStateError>,
    },
    /// The VM, firewall, and network cleanup succeeded; only the local state
    /// record removal failed. Retrying managed stop is safe and should remove
    /// the stale record once the state directory is writable again.
    #[error("session stopped but removing state failed: {state}")]
    StateRemoveAfterStop {
        state: Box<AgentVmSessionStateError>,
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

    /// Consume into the underlying errors, so a caller running additional cleanup
    /// (e.g. the broker VM teardown) can merge them into one [`CleanupErrors`].
    pub fn into_errors(self) -> Vec<ProcessInvocationError> {
        self.errors
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
        // The convenience constructor (no guest env) is host-mode only; the vm
        // arm always supplies guest env via `new_with_guest_env`.
        Self::new_with_guest_env(
            session_id,
            pool,
            subnet_index,
            broker_ports,
            broker_port_range,
            ipv6_mode,
            BrokerPlacement::Host,
            image,
            Vec::new(),
            guest_command,
            resources,
            tools,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_guest_env(
        session_id: SessionId,
        pool: AgentNetworkPool,
        subnet_index: u16,
        broker_ports: BrokerPorts,
        broker_port_range: BrokerPortRange,
        ipv6_mode: Ipv6IsolationMode,
        broker_placement: BrokerPlacement,
        image: ContainerImage,
        guest_env: Vec<AgentVmGuestEnvVar>,
        guest_command: Vec<String>,
        resources: AgentVmResources,
        tools: AgentVmToolPaths,
    ) -> Result<Self, AgentVmLifecycleConfigError> {
        broker_port_range.require_contains(&broker_ports)?;
        if ipv6_mode == Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 && guest_command.is_empty() {
            return Err(AgentVmLifecycleConfigError::EmptyGuestCommandForIpv4OnlyNoGuestIpv6);
        }
        let (network, names) = derive_session_network(session_id, pool, subnet_index)?;
        Ok(Self {
            session_id,
            pool,
            subnet_index,
            network,
            names,
            broker_ports,
            broker_port_range,
            ipv6_mode,
            broker_placement,
            broker_pf_host: None,
            image,
            guest_env,
            guest_command,
            resources,
            tools,
        })
    }

    /// Set the host-PF allow target to the broker VM's IP (vm placement). Without
    /// this the PF allows the subnet gateway (the host-broker default).
    pub fn with_broker_pf_host(mut self, broker_pf_host: Ipv4Addr) -> Self {
        self.broker_pf_host = Some(broker_pf_host);
        self
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn network(&self) -> AgentNetwork {
        self.network
    }

    pub fn subnet_index(&self) -> u16 {
        self.subnet_index
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

    /// Describes the start sequence as a vector of steps. When guest
    /// environment variables are configured, the VM-start step's
    /// [`AgentVmStartInvocation`] is the
    /// [`AgentVmStartInvocation::RuntimeGuestEnvFile`] form;
    /// [`start_agent_vm_session`] writes the real 0600 env file immediately
    /// before invoking `container run`.
    pub fn start_steps(&self) -> Vec<AgentVmStartStep> {
        let mut steps = Vec::new();
        // Host mode creates the agent's own network; the vm arm shares a network
        // the broker arm has already created (and removes), so the agent start
        // skips CreateNetwork. Everything else — inspect/validate and **host PF**
        // — still runs: `--internal` blocks internet egress but NOT host
        // reachability (the macOS gateway 192.168.x.1 is still on the link), so
        // the agent VM must be PF-filtered from host services exactly as in host
        // mode.
        if self.broker_placement == BrokerPlacement::Host {
            steps.push(AgentVmStartStep::CreateNetwork(
                self.create_network_invocation(),
            ));
        }
        steps.push(AgentVmStartStep::InspectAndValidateNetwork(
            self.inspect_network_invocation(),
        ));
        steps.push(AgentVmStartStep::InstallFirewall(
            self.install_firewall_invocation(),
        ));
        steps.push(AgentVmStartStep::StartVm(self.start_vm_invocation()));
        if self.ipv6_mode == Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 {
            // Enforce-then-verify the no-guest-IPv6 posture in one guest exec
            // (the script disables IPv6 in the guest kernel before reporting;
            // see GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT), then release the guest
            // command only once the posture is confirmed.
            steps.push(AgentVmStartStep::ProbeAndValidateGuestIpv6 {
                probe_invocation: self.enforce_and_probe_guest_ipv6_invocation(),
            });
            steps.push(AgentVmStartStep::ReleaseGuestCommand(
                self.release_guest_command_invocation(),
            ));
        }
        steps
    }

    pub fn start_invocations(&self) -> Vec<AgentVmStartInvocation> {
        self.start_steps()
            .into_iter()
            .map(AgentVmStartStep::into_display_invocation)
            .collect()
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
            // Host removes the network it created. In vm mode the broker arm owns
            // the shared network and no firewall is installed in this phase yet,
            // so there is nothing for the agent to clean up.
            CompletedStartStep::NetworkCreated => match self.broker_placement {
                BrokerPlacement::Host => self.stop_plan().network_removal_invocations(),
                BrokerPlacement::Vm => Vec::new(),
            },
            // `stop_invocations` is placement-aware: host removes the VM, host PF,
            // and the network; vm removes the VM and host PF only (the broker arm
            // owns the network). Both keep the host PF removal — `--internal`
            // does not isolate the agent from host services.
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
            broker_placement: self.broker_placement,
            tools: self.tools.clone(),
        }
    }

    fn firewall_ipv6_cidr(&self) -> Option<Ipv6Cidr> {
        firewall_ipv6_cidr_for_mode(self.ipv6_mode, self.network)
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
                let expected_gateway = Ipv6Addr::from(u128::from(expected_ipv6.network()) + 1);
                if ipv6_gateway != expected_gateway {
                    return Err(NetworkInspectionError::Ipv6GatewayMismatch {
                        expected: expected_gateway,
                        actual: ipv6_gateway,
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
        // Retarget the PF allow rule to the broker VM (vm placement). Absent for
        // host placement, where the helper defaults to the subnet gateway.
        if let Some(broker_pf_host) = self.broker_pf_host {
            args.push(OsString::from("--broker-host"));
            args.push(OsString::from(broker_pf_host.to_string()));
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

    fn start_vm_invocation(&self) -> AgentVmStartInvocation {
        let invocation = self.start_vm_invocation_with_env_file(None);
        if self.guest_env.is_empty() {
            AgentVmStartInvocation::Static(invocation)
        } else {
            AgentVmStartInvocation::RuntimeGuestEnvFile {
                invocation,
                display_shell: self
                    .start_vm_invocation_with_env_file(Some(Path::new(GUEST_ENV_FILE_DISPLAY)))
                    .display_shell(),
            }
        }
    }

    fn start_vm_invocation_with_env_file(&self, env_file: Option<&Path>) -> ProcessInvocation {
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
        ];
        for mount in AGENT_VM_TMPFS_MOUNTS {
            args.extend(["--tmpfs".to_string(), (*mount).to_string()]);
        }
        if let Some(env_file) = env_file {
            args.extend(["--env-file".to_string(), env_file.display().to_string()]);
        }
        args.push(self.image.as_str().to_string());
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

    fn run_start_vm_invocation(&self) -> Result<(), StartFailure> {
        if self.guest_env.is_empty() {
            return self
                .start_vm_invocation_with_env_file(None)
                .run()
                .map_err(StartFailure::from);
        }
        let env_file = TempGuestEnvFile::create(&self.guest_env)?;
        // This relies on Apple Container consuming --env-file before
        // `container run -d` returns; the host-side temp file is deleted as soon
        // as the run command has accepted it.
        self.start_vm_invocation_with_env_file(Some(env_file.path()))
            .run()
            .map_err(StartFailure::from)
    }

    fn enforce_and_probe_guest_ipv6_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.tools.container.clone(),
            [
                "exec".to_string(),
                self.names.vm.clone(),
                "sh".to_string(),
                "-c".to_string(),
                GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT.to_string(),
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
        broker_placement: BrokerPlacement,
        tools: AgentVmToolPaths,
    ) -> Result<Self, AgentVmLifecycleConfigError> {
        let network = pool.allocate(subnet_index)?;
        let firewall_ipv6 = firewall_ipv6_cidr_for_mode(ipv6_mode, network);
        Ok(Self {
            session_id,
            pool,
            network,
            firewall_ipv6,
            names: AgentVmNames::for_session(session_id),
            broker_placement,
            tools,
        })
    }

    fn from_validated_parts(
        session_id: SessionId,
        pool: AgentNetworkPool,
        network: AgentNetwork,
        firewall_ipv6: Option<Ipv6Cidr>,
        names: AgentVmNames,
        broker_placement: BrokerPlacement,
        tools: AgentVmToolPaths,
    ) -> Self {
        // Persisted state has already been parsed and cross-checked against the
        // pool, subnet index, session-derived names, and IPv6 mode. Reusing the
        // recorded network keeps cleanup tied to exactly the facts that start
        // persisted, rather than reinterpreting caller-supplied stop arguments.
        Self {
            session_id,
            pool,
            network,
            firewall_ipv6,
            names,
            broker_placement,
            tools,
        }
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
        // Both placements remove the agent VM and its host PF anchor: an
        // `--internal` network blocks internet egress but not host reachability,
        // so the agent VM is PF-filtered from host services in vm mode too. Only
        // the shared network differs — in vm mode the broker arm owns and removes
        // it, so the agent teardown leaves it alone.
        let mut invocations = self.vm_removal_invocations();
        invocations.push(self.remove_firewall_invocation());
        if self.broker_placement == BrokerPlacement::Host {
            invocations.extend(self.network_removal_invocations());
        }
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

impl std::fmt::Debug for AgentVmGuestEnvVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentVmGuestEnvVar")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl AgentVmGuestEnvVar {
    /// Construct one environment variable for the transient Apple Container
    /// env file. This type enforces shell-style names and single-line values;
    /// callers should only pass value bytes that Apple's env-file parser will
    /// preserve literally. The daemon currently uses values such as broker
    /// URLs, paths, cache public-key lists, and opaque bearer tokens, which
    /// avoid leading/trailing whitespace, `#`, and additional `=` parser
    /// ambiguities.
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, AgentVmLifecycleConfigError> {
        let name = name.into();
        let value = value.into();
        validate_guest_env_name(&name)?;
        if value
            .bytes()
            .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
        {
            return Err(AgentVmLifecycleConfigError::InvalidGuestEnvValue { name });
        }
        Ok(Self { name, value })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

struct TempGuestEnvFile {
    path: PathBuf,
}

impl TempGuestEnvFile {
    fn create(vars: &[AgentVmGuestEnvVar]) -> Result<Self, GuestEnvironmentError> {
        let path = std::env::temp_dir().join(format!("writ-agent-vm-env-{}", Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|source| GuestEnvironmentError::Io {
                operation: "create",
                path: path.clone(),
                source,
            })?;
        for var in vars {
            writeln!(file, "{}={}", var.name(), var.value()).map_err(|source| {
                GuestEnvironmentError::Io {
                    operation: "write",
                    path: path.clone(),
                    source,
                }
            })?;
        }
        file.sync_all()
            .map_err(|source| GuestEnvironmentError::Io {
                operation: "sync",
                path: path.clone(),
                source,
            })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempGuestEnvFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
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

    pub fn container(&self) -> &Path {
        &self.container
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

    pub fn run(&self) -> Result<(), ProcessInvocationError> {
        let output = self.output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(self.failed_from_output(output))
    }

    /// Run the invocation and return its captured stdout on success (used to
    /// parse `container inspect` output). Errors identically to [`Self::run`] on
    /// a non-zero exit.
    pub fn run_capturing_stdout(&self) -> Result<String, ProcessInvocationError> {
        let output = self.output()?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(self.failed_from_output(output))
        }
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
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        process_spawn::output(&mut command).map_err(|source| ProcessInvocationError::Run {
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

impl AgentVmStartInvocation {
    pub fn program(&self) -> &Path {
        self.invocation().program()
    }

    pub fn args_lossy(&self) -> Vec<String> {
        self.invocation().args_lossy()
    }

    pub fn display_shell(&self) -> String {
        match self {
            Self::Static(invocation) => invocation.display_shell(),
            Self::RuntimeGuestEnvFile { display_shell, .. } => display_shell.clone(),
        }
    }

    fn invocation(&self) -> &ProcessInvocation {
        match self {
            Self::Static(invocation) | Self::RuntimeGuestEnvFile { invocation, .. } => invocation,
        }
    }
}

impl AgentVmStartStep {
    pub fn into_display_invocation(self) -> AgentVmStartInvocation {
        match self {
            Self::CreateNetwork(inv)
            | Self::InspectAndValidateNetwork(inv)
            | Self::InstallFirewall(inv)
            | Self::ReleaseGuestCommand(inv) => AgentVmStartInvocation::Static(inv),
            Self::StartVm(inv) => inv,
            Self::ProbeAndValidateGuestIpv6 { probe_invocation } => {
                AgentVmStartInvocation::Static(probe_invocation)
            }
        }
    }
}

/// Cleanup phase active *during* `step`: the resources that need tearing down
/// if `step` fails. The property test
/// `step_cleanup_phase_agrees_with_outcome_oracle` pins this to
/// [`cleanup_step_after_start_outcome`] for every outcome the step can
/// produce.
pub fn step_cleanup_phase(step: &AgentVmStartStep) -> CompletedStartStep {
    match step {
        AgentVmStartStep::CreateNetwork(_) => CompletedStartStep::None,
        AgentVmStartStep::InspectAndValidateNetwork(_) | AgentVmStartStep::InstallFirewall(_) => {
            CompletedStartStep::NetworkCreated
        }
        AgentVmStartStep::StartVm(_)
        | AgentVmStartStep::ProbeAndValidateGuestIpv6 { .. }
        | AgentVmStartStep::ReleaseGuestCommand(_) => CompletedStartStep::FirewallInstalled,
    }
}

/// Every [`StartOutcome`] (other than `Started`) the step can produce on
/// failure. The runner is required to use only these outcomes for the step.
pub fn step_failure_outcomes(step: &AgentVmStartStep) -> Vec<StartOutcome> {
    match step {
        AgentVmStartStep::CreateNetwork(_) => vec![StartOutcome::CreateNetworkFailed],
        AgentVmStartStep::InspectAndValidateNetwork(_) => vec![
            StartOutcome::InspectNetworkFailed,
            StartOutcome::ParseNetworkInspectionFailed,
            StartOutcome::ValidateNetworkInspectionFailed,
        ],
        AgentVmStartStep::InstallFirewall(_) => vec![StartOutcome::InstallFirewallFailed],
        AgentVmStartStep::StartVm(_) => vec![StartOutcome::StartVmFailed],
        AgentVmStartStep::ProbeAndValidateGuestIpv6 { .. } => vec![
            StartOutcome::ProbeGuestIpv6Failed,
            StartOutcome::ValidateGuestIpv6Failed,
        ],
        AgentVmStartStep::ReleaseGuestCommand(_) => vec![StartOutcome::ReleaseGuestCommandFailed],
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

impl BrokerUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn start_agent_vm_session(plan: &AgentVmSessionPlan) -> Result<(), AgentVmLifecycleRunError> {
    for step in plan.start_steps() {
        if let Err((failure, outcome)) = run_start_step(plan, &step) {
            return fail_after_cleanup(failure, plan, outcome);
        }
    }
    Ok(())
}

/// Execute a single start step. Errors carry the [`StartOutcome`] the runner
/// reports to [`fail_after_cleanup`]; the property test
/// `step_cleanup_phase_agrees_with_outcome_oracle` pins the outcome set per
/// step type to [`cleanup_step_after_start_outcome`].
fn run_start_step(
    plan: &AgentVmSessionPlan,
    step: &AgentVmStartStep,
) -> Result<(), (StartFailure, StartOutcome)> {
    match step {
        AgentVmStartStep::CreateNetwork(invocation) => invocation
            .run()
            .map_err(|err| (err.into(), StartOutcome::CreateNetworkFailed)),
        AgentVmStartStep::InspectAndValidateNetwork(invocation) => {
            let output = match invocation.output() {
                Ok(out) if out.status.success() => out,
                Ok(out) => {
                    return Err((
                        invocation.failed_from_output(out).into(),
                        StartOutcome::InspectNetworkFailed,
                    ));
                }
                Err(err) => return Err((err.into(), StartOutcome::InspectNetworkFailed)),
            };
            let inspection =
                AppleNetworkInspection::parse(&String::from_utf8_lossy(&output.stdout))
                    .map_err(|err| (err.into(), StartOutcome::ParseNetworkInspectionFailed))?;
            plan.validate_network_inspection(&inspection)
                .map_err(|err| (err.into(), StartOutcome::ValidateNetworkInspectionFailed))
        }
        AgentVmStartStep::InstallFirewall(invocation) => invocation
            .run()
            .map_err(|err| (err.into(), StartOutcome::InstallFirewallFailed)),
        AgentVmStartStep::StartVm(_) => plan
            .run_start_vm_invocation()
            .map_err(|err| (err, StartOutcome::StartVmFailed)),
        AgentVmStartStep::ProbeAndValidateGuestIpv6 { probe_invocation } => {
            let inspection = wait_for_guest_ipv6_inspection(probe_invocation)
                .map_err(|err| (err, StartOutcome::ProbeGuestIpv6Failed))?;
            inspection
                .require_no_routable_ipv6()
                .map_err(|err| (err.into(), StartOutcome::ValidateGuestIpv6Failed))
        }
        AgentVmStartStep::ReleaseGuestCommand(invocation) => invocation
            .run()
            .map_err(|err| (err.into(), StartOutcome::ReleaseGuestCommandFailed)),
    }
}

pub fn stop_agent_vm_session(plan: &AgentVmSessionStopPlan) -> Result<(), CleanupErrors> {
    run_stop_plan_cleanup(plan)
}

/// Atomic managed start for callers without external per-session locking.
/// Holds the state-store file lock for the entire start (subnet claim, VM
/// boot, status promotion) so a concurrent same-session stop cannot interleave
/// and orphan started infrastructure. Used by the CLI runner.
///
/// The daemon does not call this; instead it uses the split forms
/// [`claim_agent_vm_session_subnet`] + [`complete_agent_vm_session_start`]
/// (and per-session in-process locks) so unrelated sessions can boot in
/// parallel.
pub fn start_managed_agent_vm_session(
    store: &AgentVmSessionStateStore,
    plan: &AgentVmSessionPlan,
) -> Result<AgentVmSessionState, AgentVmSessionManagerError> {
    let _lock = store.lock_store()?;
    let starting = store.create_starting_unlocked(plan)?;
    if let Err(start) = start_agent_vm_session(plan) {
        if start_failure_left_dirty_infrastructure(&start) {
            return Err(start.into());
        }
        return match store.remove_unlocked(plan.session_id()) {
            Ok(()) => Err(start.into()),
            Err(state) => Err(AgentVmSessionManagerError::StartStateCleanup {
                start: Box::new(start),
                state: Box::new(state),
            }),
        };
    }
    store.mark_running_unlocked(&starting).map_err(|state| {
        AgentVmSessionManagerError::RunningStateUpdateAfterStart {
            state: Box::new(state),
        }
    })
}

/// Reserve the subnet for a new session by writing a `Starting` state record.
///
/// Holds the state-store file lock only for the create step. Callers MUST
/// serialise this and the matching [`complete_agent_vm_session_start`] (and
/// any concurrent stop on the same session) externally — the file lock is
/// released between them, and a concurrent stop on the same `SessionId` would
/// orphan the infrastructure that boot is about to start.
///
/// In-process: the daemon satisfies this contract via per-`SessionId`
/// mutexes. Cross-process: the
/// [single-owner invariant on `AgentVmSessionStateStore`][AgentVmSessionStateStore]
/// rules out a second process touching the same state directory, so no
/// interprocess lock is needed.
pub fn claim_agent_vm_session_subnet(
    store: &AgentVmSessionStateStore,
    plan: &AgentVmSessionPlan,
) -> Result<AgentVmSessionState, AgentVmSessionManagerError> {
    Ok(store.create_starting(plan)?)
}

/// Boot the VM for a session whose subnet has already been claimed via
/// [`claim_agent_vm_session_subnet`], then promote the state record to
/// `Running`.
///
/// Runs the slow VM boot without holding the state-store file lock; only
/// `mark_running` (or rollback `remove`) re-takes the lock for the brief
/// status transition. See [`claim_agent_vm_session_subnet`] for the caller
/// serialisation contract.
pub fn complete_agent_vm_session_start(
    store: &AgentVmSessionStateStore,
    plan: &AgentVmSessionPlan,
    starting: AgentVmSessionState,
) -> Result<AgentVmSessionState, AgentVmSessionManagerError> {
    if let Err(start) = start_agent_vm_session(plan) {
        if start_failure_left_dirty_infrastructure(&start) {
            return Err(start.into());
        }
        return match store.remove(plan.session_id()) {
            Ok(()) => Err(start.into()),
            Err(state) => Err(AgentVmSessionManagerError::StartStateCleanup {
                start: Box::new(start),
                state: Box::new(state),
            }),
        };
    }
    store.mark_running(&starting).map_err(|state| {
        AgentVmSessionManagerError::RunningStateUpdateAfterStart {
            state: Box::new(state),
        }
    })
}

fn start_failure_left_dirty_infrastructure(error: &AgentVmLifecycleRunError) -> bool {
    matches!(error, AgentVmLifecycleRunError::CleanupAfterFailure { .. })
}

/// Atomic managed stop for callers without external per-session locking.
/// Holds the state-store file lock across load, infra teardown, and state
/// removal so a concurrent same-session start cannot interleave. Used by the
/// CLI runner; the daemon uses the split forms below under per-session locks.
pub fn stop_managed_agent_vm_session(
    store: &AgentVmSessionStateStore,
    session_id: SessionId,
    tools: AgentVmToolPaths,
) -> Result<(), AgentVmSessionManagerError> {
    let _lock = store.lock_store()?;
    let state = store.load_unlocked(session_id)?;
    cleanup_managed_agent_vm_session_unlocked(&state, tools)?;
    remove_managed_agent_vm_session_state_unlocked(store, session_id)
}

/// Run VM, firewall, and network cleanup while preserving the persisted state
/// record. The daemon uses this split form so audit close and VM HTTP shutdown
/// can fail without losing the cleanup facts needed for a retry.
///
/// The state-store file lock is taken only for the brief `load`; the slow VM
/// teardown runs unlocked. Callers MUST serialise this and the matching
/// [`remove_managed_agent_vm_session_state`] against any concurrent operation
/// on the same `SessionId` externally — see [`claim_agent_vm_session_subnet`]
/// for the same caveat. The daemon satisfies this contract via per-session
/// in-process mutexes.
pub fn cleanup_managed_agent_vm_session(
    store: &AgentVmSessionStateStore,
    session_id: SessionId,
    tools: AgentVmToolPaths,
) -> Result<(), AgentVmSessionManagerError> {
    let state = store.load(session_id)?;
    cleanup_managed_agent_vm_session_unlocked(&state, tools)
}

/// Remove a managed session state record after all daemon-side stop effects
/// have completed successfully. Pairs with [`cleanup_managed_agent_vm_session`]
/// under the same external-serialisation contract.
pub fn remove_managed_agent_vm_session_state(
    store: &AgentVmSessionStateStore,
    session_id: SessionId,
) -> Result<(), AgentVmSessionManagerError> {
    store
        .remove(session_id)
        .map_err(|state| AgentVmSessionManagerError::StateRemoveAfterStop {
            state: Box::new(state),
        })
}

fn remove_managed_agent_vm_session_state_unlocked(
    store: &AgentVmSessionStateStore,
    session_id: SessionId,
) -> Result<(), AgentVmSessionManagerError> {
    store.remove_unlocked(session_id).map_err(|state| {
        AgentVmSessionManagerError::StateRemoveAfterStop {
            state: Box::new(state),
        }
    })
}

fn cleanup_managed_agent_vm_session_unlocked(
    state: &AgentVmSessionState,
    tools: AgentVmToolPaths,
) -> Result<(), AgentVmSessionManagerError> {
    // No wildcard: adding a future status must revisit managed-stop cleanup
    // semantics before this match compiles.
    match state.status() {
        // A managed start that failed during rollback intentionally leaves a
        // Starting record behind. It carries the same cleanup facts as a
        // Running record, so managed stop must accept both.
        AgentVmSessionStateStatus::Starting | AgentVmSessionStateStatus::Running => {}
    }
    // Capture the container tool before `to_stop_plan` consumes `tools`; the vm
    // placement broker teardown needs it after the agent VM is stopped.
    let container = tools.container().to_path_buf();
    let mut errors = match stop_agent_vm_session(&state.to_stop_plan(tools)) {
        Ok(()) => Vec::new(),
        Err(agent) => agent.into_errors(),
    };
    // For vm placement the broker arm owns a dedicated broker VM plus the shared
    // network the agent only joined; tear them down *after* the agent VM is gone
    // (so removing the shared network is safe). Idempotent + absence-based like the
    // agent VM/network cleanup, so lagging Apple Container removals and
    // already-absent resources on retry don't fail the stop. Failures are
    // collected alongside the agent ones. All names derive from session identity,
    // so no launch plan is needed. (The per-session host material dir — copied
    // secrets included — is removed by the daemon, which owns that path policy.)
    if state.broker_placement() == BrokerPlacement::Vm
        && let Err(broker) = run_broker_vm_cleanup_until_absent(
            &container,
            state.session_id(),
            state.names().network(),
        )
    {
        errors.extend(broker.into_errors());
    }
    finish_cleanup_errors(errors).map_err(Into::into)
}

fn derive_session_network(
    session_id: SessionId,
    pool: AgentNetworkPool,
    subnet_index: u16,
) -> Result<(AgentNetwork, AgentVmNames), AgentVmLifecycleConfigError> {
    Ok((
        pool.allocate(subnet_index)?,
        AgentVmNames::for_session(session_id),
    ))
}

fn firewall_ipv6_cidr_for_mode(
    ipv6_mode: Ipv6IsolationMode,
    network: AgentNetwork,
) -> Option<Ipv6Cidr> {
    match ipv6_mode {
        Ipv6IsolationMode::DualStackRequired => Some(network.ipv6()),
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 => None,
    }
}

fn validate_guest_env_name(name: &str) -> Result<(), AgentVmLifecycleConfigError> {
    let Some(first) = name.bytes().next() else {
        return Err(AgentVmLifecycleConfigError::EmptyGuestEnvName);
    };
    if !first.is_ascii_alphabetic() && first != b'_' {
        return Err(AgentVmLifecycleConfigError::InvalidGuestEnvNameStart(
            name.to_string(),
        ));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(AgentVmLifecycleConfigError::InvalidGuestEnvNameByte(
            name.to_string(),
        ));
    }
    Ok(())
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
        // Network-created phase: the firewall is not yet installed. Host removes
        // the network it created; vm has nothing to clean (the broker arm owns
        // the shared network).
        Some(CompletedStartStep::NetworkCreated) => match plan.broker_placement {
            BrokerPlacement::Host => {
                single_cleanup_result(run_network_cleanup_until_absent(&plan.stop_plan()))
            }
            BrokerPlacement::Vm => Ok(()),
        },
        // Firewall-installed phase: `run_stop_plan_cleanup` branches on placement
        // exactly like the planned-cleanup helper — host removes VM+PF+network,
        // vm removes VM+PF (the broker arm owns the network). Both remove the PF
        // anchor, so a vm start failure cannot strand host filtering.
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
    // Both placements remove the host PF anchor (an `--internal` network does not
    // isolate the agent from host services).
    if let Err(err) = plan.remove_firewall_invocation().run() {
        errors.push(err);
    }
    // Only host mode removes the network: in vm mode the broker arm owns and
    // tears down the shared network, so removing it here would destroy a resource
    // this session never created.
    if plan.broker_placement == BrokerPlacement::Host
        && let Err(err) = run_network_cleanup_until_absent(plan)
    {
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

/// Idempotent, absence-based teardown of a vm session's broker resources, matching
/// the agent VM/network cleanup: each resource — the broker VM, then its egress
/// network, then the shared internal network — is removed and probed out of the
/// container / network list, so a removal that lags after the command returns and
/// a resource already absent on a retry both resolve to success rather than a
/// fatal error. The shared internal network is removed last and only after the
/// agent VM has been torn down (the caller's responsibility). Failures across the
/// three are collected. All names derive from session identity (no launch plan).
fn run_broker_vm_cleanup_until_absent(
    container_tool: &Path,
    session_id: SessionId,
    internal_network: &str,
) -> Result<(), CleanupErrors> {
    let names = BrokerVmNames::for_session(session_id);
    let list_containers = || {
        ProcessInvocation::new(
            container_tool.to_path_buf(),
            [
                "list".to_string(),
                "--all".to_string(),
                "--quiet".to_string(),
            ],
        )
    };
    let list_networks = || {
        ProcessInvocation::new(
            container_tool.to_path_buf(),
            [
                "network".to_string(),
                "list".to_string(),
                "--quiet".to_string(),
            ],
        )
    };
    // Presence probes in the same resource order as `broker_vm_removal_invocations`
    // (broker VM, egress network, shared internal network), so each shared removal
    // command is paired with the right probe.
    let probes = [
        (
            ResourcePresenceProbe::new(list_containers(), names.vm().to_string()),
            "broker VM still appears in container list after removal attempts",
        ),
        (
            ResourcePresenceProbe::new(list_networks(), names.egress_network().to_string()),
            "broker egress network still appears in network list after removal attempts",
        ),
        (
            ResourcePresenceProbe::new(list_networks(), internal_network.to_string()),
            "shared internal network still appears in network list after removal attempts",
        ),
    ];
    let removals = broker_vm_removal_invocations(container_tool, &names, internal_network);
    let mut errors = Vec::new();
    for ((probe, still_present), removal) in probes.into_iter().zip(removals) {
        if let Err(err) = run_cleanup_until_resource_absent(&probe, vec![removal], still_present) {
            errors.push(err);
        }
    }
    finish_cleanup_errors(errors)
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
    invocation: &ProcessInvocation,
) -> Result<GuestIpv6Inspection, StartFailure> {
    for attempt in 0..GUEST_IPV6_PROBE_ATTEMPTS {
        let err = match invocation.output() {
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
            Ok(output) => invocation.failed_from_output(output),
            Err(err) => err,
        };
        if attempt + 1 == GUEST_IPV6_PROBE_ATTEMPTS {
            return Err(err.into());
        }
        std::thread::sleep(GUEST_IPV6_PROBE_DELAY);
    }
    unreachable!("GUEST_IPV6_PROBE_ATTEMPTS > 0 ensures the loop body always returns")
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
mod cleanup_tests;
#[cfg(test)]
mod guest_env_tests;
#[cfg(test)]
mod invocation_tests;
#[cfg(test)]
mod network_inspection_tests;
#[cfg(test)]
mod state_store_tests;
#[cfg(test)]
mod test_support;

/// Property-based specification for `agent_vm_lifecycle`.
///
/// The example/edge-case tests in the sibling `*_tests` modules pin
/// specific scenarios; this module asserts the same contracts hold
/// for *arbitrary* inputs — plan/pool allocation, the start-outcome →
/// cleanup mapping, network-inspection matching, guest IPv6 posture
/// and persisted-state round-tripping.
#[cfg(test)]
mod spec {
    use super::test_support::*;
    use super::*;
    use crate::core::BrokerPort;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use uuid::Uuid;

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

    fn arb_ipv6_mode() -> impl Strategy<Value = Ipv6IsolationMode> {
        prop_oneof![
            Just(Ipv6IsolationMode::DualStackRequired),
            Just(Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6),
        ]
    }

    fn arb_broker_ports_and_range() -> impl Strategy<Value = (BrokerPorts, BrokerPortRange)> {
        (
            prop::collection::vec(1024u16..=65535, 1..=4),
            0u16..=1024,
            0u16..=1024,
        )
            .prop_map(|(ports, min_slack, max_slack)| {
                let broker_ports = BrokerPorts::new(
                    ports
                        .iter()
                        .copied()
                        .map(BrokerPort::new)
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap(),
                )
                .unwrap();
                let min_port = broker_ports
                    .as_slice()
                    .iter()
                    .map(|port| port.get())
                    .min()
                    .unwrap();
                let max_port = broker_ports
                    .as_slice()
                    .iter()
                    .map(|port| port.get())
                    .max()
                    .unwrap();
                let range_min = min_port.saturating_sub(min_slack).max(1024);
                let range_max = max_port.saturating_add(max_slack);
                (
                    broker_ports,
                    BrokerPortRange::new(range_min, range_max).unwrap(),
                )
            })
    }

    fn arb_plan() -> impl Strategy<Value = AgentVmSessionPlan> {
        (
            any::<u128>(),
            any::<u8>(),
            any::<u8>(),
            any::<u16>(),
            any::<u16>(),
            any::<u8>(),
            arb_broker_ports_and_range(),
            arb_ipv6_mode(),
            "[a-z][a-z0-9]{0,7}(:[a-z0-9]{1,8})?",
            prop::collection::vec("[a-z][a-z0-9_-]{0,7}", 1..=4),
            1u16..=8,
            64u32..=8192,
        )
            .prop_map(
                |(
                    raw_session_id,
                    ipv4_second_octet,
                    ula_suffix,
                    ipv6_second_segment,
                    ipv6_third_segment,
                    subnet_index,
                    (broker_ports, broker_port_range),
                    ipv6_mode,
                    image,
                    guest_command,
                    cpus,
                    memory_mib,
                )| {
                    let pool = AgentNetworkPool::new(
                        Ipv4Cidr::new(Ipv4Addr::new(10, ipv4_second_octet, 0, 0), 16).unwrap(),
                        Ipv6Cidr::new(
                            Ipv6Addr::new(
                                0xfd00 | u16::from(ula_suffix),
                                ipv6_second_segment,
                                ipv6_third_segment,
                                0,
                                0,
                                0,
                                0,
                                0,
                            ),
                            48,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    AgentVmSessionPlan::new(
                        SessionId::from_uuid(Uuid::from_u128(raw_session_id)),
                        pool,
                        u16::from(subnet_index),
                        broker_ports,
                        broker_port_range,
                        ipv6_mode,
                        ContainerImage::new(image).unwrap(),
                        guest_command,
                        AgentVmResources::new(cpus, memory_mib).unwrap(),
                        AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo"),
                    )
                    .unwrap()
                },
            )
    }

    fn arb_state_status() -> impl Strategy<Value = AgentVmSessionStateStatus> {
        prop_oneof![
            Just(AgentVmSessionStateStatus::Starting),
            Just(AgentVmSessionStateStatus::Running),
        ]
    }

    fn arb_guest_env_value() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![1u32..=9, 11u32..=12, 14u32..=0xd7ff, 0xe000u32..=0x10ffff]
                .prop_map(|codepoint| char::from_u32(codepoint).unwrap()),
            0..=64,
        )
        .prop_map(|chars| chars.into_iter().collect())
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

    fn state_json_value(state: &AgentVmSessionState) -> serde_json::Value {
        serde_json::from_slice(&state.to_json_bytes().unwrap()).unwrap()
    }

    fn assert_state_json_rejected(raw: serde_json::Value) {
        let encoded = serde_json::to_vec(&raw).unwrap();
        let err = AgentVmSessionState::from_json_bytes(&encoded).unwrap_err();
        assert!(matches!(err, AgentVmSessionStateError::Corrupt { .. }));
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

    proptest! {
        #[test]
        fn guest_environment_accepts_any_shell_name_and_single_line_value(
            name in "[A-Za-z_][A-Za-z0-9_]{0,32}",
            value in arb_guest_env_value(),
        ) {
            let var = AgentVmGuestEnvVar::new(name.clone(), value.clone()).unwrap();

            prop_assert_eq!(var.name(), name);
            prop_assert_eq!(var.value(), value);
        }
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

        /// The runner reports a step's failure as one of `step_failure_outcomes(step)`,
        /// and `fail_after_cleanup` then asks the oracle which cleanup phase to run.
        /// For the runner to agree with `step_cleanup_phase` by construction, every
        /// outcome the step can produce must map to that step's cleanup phase.
        #[test]
        fn step_cleanup_phase_agrees_with_outcome_oracle(plan in arb_plan()) {
            for step in plan.start_steps() {
                let phase = step_cleanup_phase(&step);
                for outcome in step_failure_outcomes(&step) {
                    prop_assert_eq!(
                        cleanup_step_after_start_outcome(outcome),
                        Some(phase),
                        "step {:?} outcome {:?} disagrees with oracle",
                        step,
                        outcome,
                    );
                }
            }
        }
    }

    proptest! {

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
                ..matching.clone()
            };
            let got_v6_gateway_mismatch = matches!(
                plan.validate_network_inspection(&wrong_v6_gateway),
                Err(NetworkInspectionError::Ipv6GatewayMismatch { .. })
            );
            prop_assert!(got_v6_gateway_mismatch);

            // Gateway in subnet but not the canonical first host address: PF
            // pins to network+1, so anything else must be rejected up-front.
            let in_subnet_wrong_v6_gateway = AppleNetworkInspection {
                ipv6_gateway: Some(Ipv6Addr::from(u128::from(plan.network().ipv6().network()) + 2)),
                ..matching
            };
            let got_in_subnet_mismatch = matches!(
                plan.validate_network_inspection(&in_subnet_wrong_v6_gateway),
                Err(NetworkInspectionError::Ipv6GatewayMismatch { .. })
            );
            prop_assert!(got_in_subnet_mismatch);
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

        #[test]
        fn persisted_session_state_roundtrips_to_the_same_stop_plan(
            plan in arb_plan(),
            status in arb_state_status(),
        ) {
            let state = AgentVmSessionState::from_start_plan(
                &plan,
                status,
            );
            let encoded = state.to_json_bytes().unwrap();
            let decoded = AgentVmSessionState::from_json_bytes(&encoded).unwrap();

            prop_assert_eq!(&decoded, &state);
            prop_assert_eq!(
                decoded
                    .to_stop_plan(AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo"))
                    .stop_invocations(),
                plan.stop_plan().stop_invocations()
            );
        }

        #[test]
        fn persisted_session_state_rejects_each_mutated_cross_checked_field(
            plan in arb_plan(),
        ) {
            let state = AgentVmSessionState::from_start_plan(
                &plan,
                AgentVmSessionStateStatus::Running,
            );
            let alternate = plan
                .pool
                .allocate((plan.subnet_index().wrapping_add(1)) % 256)
                .unwrap();
            let mut rejected = 0;

            let mut wrong_session_id = state_json_value(&state);
            wrong_session_id["session_id"] = serde_json::Value::String(
                SessionId::from_uuid(Uuid::from_u128(state.session_id().as_uuid().as_u128() ^ 1))
                    .to_string(),
            );
            assert_state_json_rejected(wrong_session_id);
            rejected += 1;

            let current_ipv4_base = plan.pool.ipv4_base().network().octets();
            let mut wrong_ipv4_pool = state_json_value(&state);
            wrong_ipv4_pool["ipv4_pool"] = serde_json::Value::String(
                Ipv4Cidr::new(
                    Ipv4Addr::new(10, current_ipv4_base[1].wrapping_add(1), 0, 0),
                    16,
                )
                .unwrap()
                .to_string(),
            );
            assert_state_json_rejected(wrong_ipv4_pool);
            rejected += 1;

            let current_ipv6_base = plan.pool.ipv6_base().network().segments();
            let mut wrong_ipv6_pool = state_json_value(&state);
            wrong_ipv6_pool["ipv6_pool"] = serde_json::Value::String(
                Ipv6Cidr::new(
                    Ipv6Addr::new(
                        current_ipv6_base[0] ^ 0x0100,
                        current_ipv6_base[1],
                        current_ipv6_base[2],
                        0,
                        0,
                        0,
                        0,
                        0,
                    ),
                    48,
                )
                .unwrap()
                .to_string(),
            );
            assert_state_json_rejected(wrong_ipv6_pool);
            rejected += 1;

            let mut wrong_subnet_index = state_json_value(&state);
            wrong_subnet_index["subnet_index"] =
                serde_json::Value::from(u64::from((plan.subnet_index().wrapping_add(1)) % 256));
            assert_state_json_rejected(wrong_subnet_index);
            rejected += 1;

            let mut wrong_ipv4 = state_json_value(&state);
            wrong_ipv4["ipv4_cidr"] = serde_json::Value::String(alternate.ipv4().to_string());
            assert_state_json_rejected(wrong_ipv4);
            rejected += 1;

            let mut wrong_ipv6 = state_json_value(&state);
            wrong_ipv6["ipv6_cidr"] = serde_json::Value::String(alternate.ipv6().to_string());
            assert_state_json_rejected(wrong_ipv6);
            rejected += 1;

            let mut wrong_network_name = state_json_value(&state);
            wrong_network_name["network_name"] =
                serde_json::Value::String(format!("{}-wrong", state.names().network()));
            assert_state_json_rejected(wrong_network_name);
            rejected += 1;

            let mut wrong_vm_name = state_json_value(&state);
            wrong_vm_name["vm_name"] =
                serde_json::Value::String(format!("{}-wrong", state.names().vm()));
            assert_state_json_rejected(wrong_vm_name);
            rejected += 1;

            let mut wrong_firewall_ipv6 = state_json_value(&state);
            wrong_firewall_ipv6["firewall_ipv6_cidr"] = match plan.ipv6_mode() {
                Ipv6IsolationMode::DualStackRequired => serde_json::Value::Null,
                Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6 => {
                    serde_json::Value::String(state.network().ipv6().to_string())
                }
            };
            assert_state_json_rejected(wrong_firewall_ipv6);
            rejected += 1;

            prop_assert_eq!(rejected, 9);
        }
    }
}
