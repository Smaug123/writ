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
    AppleNetworkInspection, GuestBridgeDiscovery, GuestBridgeDiscoveryError, GuestIpv6Inspection,
    GuestIpv6InspectionError, NetworkInspectionError, parse_bridge_for_gateway,
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

/// The `ProcessInvocation` execution primitive (spawn a child, capture its
/// output) lives here; the type and its result/error types stay in this
/// module. Split out to keep `agent_vm_lifecycle.rs` readable.
mod invocation;

/// The `AgentVmSessionPlan` construction logic (start-step state machine +
/// invocation builders) lives here; the struct stays in this module. Split
/// out to keep `agent_vm_lifecycle.rs` readable.
mod plan;

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
///
/// The read-back uses `cat` command substitution, not `read`: BusyBox `read`
/// (the guest image's `sh`) returns non-zero reading `/proc/sys` sysctls even
/// when it correctly assigns the value, so the earlier `read … || state=` wiped
/// the just-read `1` to empty and failed every start on Apple `container` 1.0.0.
/// `$(cat …)` returns the value regardless of `read`'s exit quirk and strips the
/// trailing newline, so a genuine `0`/empty (write did not take) still fails
/// closed while a real `1` passes.
const GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT: &str = r#"set -e
for scope in all default; do
  path="/proc/sys/net/ipv6/conf/$scope/disable_ipv6"
  [ -e "$path" ] || continue
  printf 1 > "$path" 2>/dev/null || true
  state="$(cat "$path" 2>/dev/null)" || state=
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

/// Apple Container label key stamped on the session's network and agent VM,
/// carrying the [`AgentVmOwnerToken`] of the start attempt that created them.
const AGENT_VM_OWNER_LABEL: &str = "writ.owner";

/// A per-start-attempt token stamped (via `--label writ.owner=…`) on the network
/// and agent VM this attempt creates. **Informational only** — surfaced by
/// `container inspect` so an operator can see which writ start owns a resource.
///
/// It deliberately does *not* gate failure cleanup. Resource names are
/// host-global but ownership is only per-`--state-dir`, so making cleanup safe
/// against a concurrent same-name owner would need host-global coordination this
/// design lacks — and that only matters when a `SessionId` is *deliberately
/// reused* across state directories (or the raw runner). Normal ids are random v4
/// UUIDs that never collide, and the prove-absence steps already fail the common
/// conflict cleanly; the narrow concurrent-reuse race is accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmOwnerToken(String);

impl AgentVmOwnerToken {
    /// A fresh random token. Every start attempt gets its own, so no two
    /// concurrent attempts (even for the same `SessionId`) share one.
    pub fn generate() -> Self {
        Self(format!("writ-{}", Uuid::new_v4().simple()))
    }

    /// Wrap a caller-supplied token (used by tests for a deterministic label).
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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
    /// Per-attempt ownership token stamped on the network and agent VM this start
    /// creates. Defaults to a fresh random token per plan (so it is impossible to
    /// forget); tests pin it via [`Self::with_owner_token`] for deterministic
    /// labels. Not persisted — ownership only matters for *this* start's failure
    /// cleanup; managed stop tears down a session it already owns.
    owner_token: AgentVmOwnerToken,
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

/// The captured result of a [`ProcessInvocation`] run under a byte cap, for
/// callers that need the output even on failure — e.g. polling `container
/// inspect` (whose non-zero exit while the VM is still being created is benign)
/// or salvaging `container logs` when the tool itself exits non-zero.
///
/// `status` is `None` when the child was killed to enforce the cap (or before it
/// exited on its own); `truncated` records whether either stream hit the cap.
#[derive(Clone, Debug)]
pub struct BoundedOutput {
    pub status: Option<std::process::ExitStatus>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

impl BoundedOutput {
    /// stdout and stderr concatenated (stdout first), for diagnostics that do not
    /// care which stream a line came from.
    pub fn combined(self) -> String {
        let mut out = self.stdout;
        if !self.stderr.is_empty() {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&self.stderr);
        }
        out
    }
}

/// The byte-bounded *tail* captured by
/// [`ProcessInvocation::run_capturing_merged_tail`]: the last `max_bytes` of a
/// command's merged output, for salvaging the newest lines of a crash log.
#[derive(Clone, Debug)]
pub struct CapturedTail {
    /// The retained tail (lossy UTF-8; a byte split mid-codepoint becomes a
    /// replacement char).
    pub text: String,
    /// Whether older bytes were discarded to stay within the cap.
    pub truncated: bool,
}

/// Append `bytes` to a tail ring buffer that retains only its last `max_bytes`,
/// bumping `total` by the bytes seen. Draining older bytes here (rather than at
/// the end) bounds retained memory to `max_bytes` regardless of stream length.
fn push_ring_tail(
    ring: &mut std::collections::VecDeque<u8>,
    total: &mut usize,
    bytes: &[u8],
    max_bytes: usize,
) {
    *total = total.saturating_add(bytes.len());
    ring.extend(bytes.iter().copied());
    while ring.len() > max_bytes {
        ring.pop_front();
    }
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
    /// Host-only pre-create ownership check: confirm the session's network does
    /// not already exist before `CreateNetwork` runs. Runs first so a network we
    /// did not create is never subsequently torn down.
    ProbeNetworkAbsent(ResourcePresenceProbe),
    CreateNetwork(ProcessInvocation),
    InspectAndValidateNetwork(ProcessInvocation),
    InstallFirewall(ProcessInvocation),
    /// Pre-start ownership check: confirm the session's agent VM does not already
    /// exist before `StartVm` runs, so a VM we did not create is never torn down.
    /// Both placements create the agent VM, so both probe for it.
    ProbeVmAbsent(ResourcePresenceProbe),
    StartVm(AgentVmStartInvocation),
    /// `Ipv4OnlyNoGuestIpv6` only: after the VM (and thus its host bridge) is up,
    /// re-load the session PF anchor with an interface-scoped IPv6 deny on the
    /// agent's bridge and members. The privileged pf-helper discovers those
    /// interfaces itself (`--deny-guest-ipv6`), from the session gateway, so this
    /// is a static invocation — the runner passes no interface names.
    InstallGuestIpv6Deny(ProcessInvocation),
    ProbeAndValidateGuestIpv6 {
        probe_invocation: ProcessInvocation,
    },
    ReleaseGuestCommand(ProcessInvocation),
}

/// A "does resource N appear in the output of list command C" probe. Carried
/// opaquely inside [`AgentVmStartStep::ProbeNetworkAbsent`] so the pre-create
/// existence check is one of the projected start steps (and thus visible in
/// dry-run), not a hidden side effect. Its internals stay private.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourcePresenceProbe {
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

/// The infrastructure that exists when a start fails, named for the last
/// resource successfully created — hence what cleanup must tear down. "No
/// cleanup at all" (success, or a failure before anything was created) is
/// carried by `Option::None` out of [`cleanup_step_after_start_outcome`], so
/// there is no "nothing" variant here.
///
/// Each phase is a superset of the previous, and every resource in a phase was
/// created by a step that ran only after its absence was confirmed (network,
/// VM) or after our own install succeeded (PF anchor) — so tearing them down is
/// always ownership-safe.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CompletedStartStep {
    /// The network exists.
    NetworkCreated,
    /// The network and the host PF anchor exist; no VM yet.
    FirewallInstalled,
    /// The network, PF anchor, and agent VM exist.
    VmStarted,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StartOutcome {
    Started,
    /// The pre-create network-absence probe failed (present, or unprobeable):
    /// nothing was created, so no cleanup.
    NetworkAbsenceProbeFailed,
    CreateNetworkFailed,
    InspectNetworkFailed,
    ParseNetworkInspectionFailed,
    ValidateNetworkInspectionFailed,
    InstallFirewallFailed,
    /// The pre-start VM-absence probe failed: the network and PF anchor exist and
    /// are ours, but the VM is not — clean back through the network and PF only.
    VmAbsenceProbeFailed,
    StartVmFailed,
    /// The post-start re-install of the session PF anchor with the interface-scoped
    /// IPv6 deny failed — the pf-helper could not discover the agent's bridge, or
    /// the load failed. The network, PF anchor, and VM exist and are ours.
    InstallGuestIpv6DenyFailed,
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
    /// The command could not be spawned at all (missing/non-executable binary,
    /// fork failure). It provably never executed, so it performed no side
    /// effects — start-failure cleanup relies on this to skip cleanup for a
    /// creating step whose command never ran.
    #[error("cannot run {program} {args}: {source}")]
    Run {
        program: String,
        args: String,
        source: std::io::Error,
    },
    /// The command spawned but collecting its exit status/output failed. Unlike
    /// [`Self::Run`], the command *did* execute and may have performed its side
    /// effect before the wait failed, so cleanup must not treat it as a no-op.
    #[error("{program} {args} spawned but collecting its result failed: {source}")]
    WaitOutput {
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
    /// A network already bearing this session's name existed before we tried to
    /// create it. The name is host-global but ownership is per-state-dir, so it
    /// may belong to another owner; we refuse to create — and, crucially,
    /// start-failure cleanup must not remove it.
    #[error(
        "network {network} already exists before create; refusing (it may belong to another owner)"
    )]
    NetworkAlreadyPresent { network: String },
    /// The pre-create existence probe itself failed, so absence could not be
    /// established. `network create` was never attempted, so nothing was created
    /// — cleanup must remove nothing (a probe failure is not evidence the network
    /// is ours).
    #[error("failed to probe for a pre-existing network before create: {source}")]
    NetworkPresenceProbeFailed {
        #[source]
        source: ProcessInvocationError,
    },
    /// An agent VM already bearing this session's name existed before start. Like
    /// the network, the name is host-global but ownership is per-state-dir, so we
    /// refuse rather than start — and cleanup must not remove the VM.
    #[error("agent VM {vm} already exists before start; refusing (it may belong to another owner)")]
    VmAlreadyPresent { vm: String },
    /// The pre-start VM existence probe itself failed, so VM ownership could not
    /// be established. Cleanup removes the network and PF anchor (ours) but not
    /// the VM.
    #[error("failed to probe for a pre-existing agent VM before start: {source}")]
    VmPresenceProbeFailed {
        #[source]
        source: ProcessInvocationError,
    },
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

/// Which cleanup phase to run after a start step fails, reported as the
/// [`CompletedStartStep`] to tear down back through, or `None` when nothing was
/// created and there is nothing to clean.
///
/// Each creating step runs only after the resource it creates was proven absent
/// (network, VM) or after our own PF install succeeded, so a failure's phase is
/// exactly the resources that exist and are ours:
/// - the absence probes (`NetworkAbsenceProbeFailed`, `VmAbsenceProbeFailed`)
///   found the resource present/unprobeable, so *that* resource is not ours;
/// - `NetworkAbsenceProbeFailed` created nothing → `None`;
/// - a network/inspect failure, and an *atomic* firewall-install failure (its
///   `pfctl -a … -f` load is all-or-nothing, leaving no session anchor), clean
///   back through `NetworkCreated`;
/// - a VM-absence-probe failure cleans the already-created network and PF anchor
///   but not the foreign VM → `FirewallInstalled`;
/// - a VM-start or later failure cleans everything, including the VM we started
///   → `VmStarted`.
pub fn cleanup_step_after_start_outcome(outcome: StartOutcome) -> Option<CompletedStartStep> {
    match outcome {
        StartOutcome::Started | StartOutcome::NetworkAbsenceProbeFailed => None,
        StartOutcome::CreateNetworkFailed
        | StartOutcome::InspectNetworkFailed
        | StartOutcome::ParseNetworkInspectionFailed
        | StartOutcome::ValidateNetworkInspectionFailed => Some(CompletedStartStep::NetworkCreated),
        // A firewall install that *ran* may have loaded the PF anchor before
        // failing (e.g. the helper is killed, or its post-load stdout breaks),
        // since the `pfctl -a … -f` load is atomic but the command can still exit
        // nonzero afterwards. So clean the anchor + network. A true spawn failure
        // (the helper never ran) is demoted to `NetworkCreated` in
        // `cleanup_phase_for_failure`.
        StartOutcome::InstallFirewallFailed | StartOutcome::VmAbsenceProbeFailed => {
            Some(CompletedStartStep::FirewallInstalled)
        }
        StartOutcome::StartVmFailed
        | StartOutcome::InstallGuestIpv6DenyFailed
        | StartOutcome::ProbeGuestIpv6Failed
        | StartOutcome::ValidateGuestIpv6Failed
        | StartOutcome::ReleaseGuestCommandFailed => Some(CompletedStartStep::VmStarted),
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
            Self::ProbeNetworkAbsent(probe) | Self::ProbeVmAbsent(probe) => {
                AgentVmStartInvocation::Static(probe.into_invocation())
            }
            Self::CreateNetwork(inv)
            | Self::InspectAndValidateNetwork(inv)
            | Self::InstallFirewall(inv)
            | Self::InstallGuestIpv6Deny(inv)
            | Self::ReleaseGuestCommand(inv) => AgentVmStartInvocation::Static(inv),
            Self::StartVm(inv) => inv,
            Self::ProbeAndValidateGuestIpv6 { probe_invocation } => {
                AgentVmStartInvocation::Static(probe_invocation)
            }
        }
    }
}

/// Cleanup phase to run if `step` fails, or `None` when its failure leaves
/// nothing to clean. The absence-probe steps create nothing themselves, so their
/// phase reflects only what earlier steps created: `ProbeNetworkAbsent` runs
/// first (nothing yet → `None`), while `ProbeVmAbsent` runs after the network and
/// PF anchor exist (→ `FirewallInstalled`, network + PF, no VM). `InstallFirewall`
/// may have loaded its anchor before failing, so it too cleans back through
/// `FirewallInstalled` (a true spawn failure is demoted in
/// `cleanup_phase_for_failure`). The property test
/// `step_cleanup_phase_agrees_with_outcome_oracle` pins this to
/// [`cleanup_step_after_start_outcome`] for every outcome the step can produce.
pub fn step_cleanup_phase(step: &AgentVmStartStep) -> Option<CompletedStartStep> {
    match step {
        AgentVmStartStep::ProbeNetworkAbsent(_) => None,
        AgentVmStartStep::CreateNetwork(_) | AgentVmStartStep::InspectAndValidateNetwork(_) => {
            Some(CompletedStartStep::NetworkCreated)
        }
        AgentVmStartStep::InstallFirewall(_) | AgentVmStartStep::ProbeVmAbsent(_) => {
            Some(CompletedStartStep::FirewallInstalled)
        }
        AgentVmStartStep::StartVm(_)
        | AgentVmStartStep::InstallGuestIpv6Deny(_)
        | AgentVmStartStep::ProbeAndValidateGuestIpv6 { .. }
        | AgentVmStartStep::ReleaseGuestCommand(_) => Some(CompletedStartStep::VmStarted),
    }
}

/// Every [`StartOutcome`] (other than `Started`) the step can produce on
/// failure. The runner is required to use only these outcomes for the step.
pub fn step_failure_outcomes(step: &AgentVmStartStep) -> Vec<StartOutcome> {
    match step {
        AgentVmStartStep::ProbeNetworkAbsent(_) => vec![StartOutcome::NetworkAbsenceProbeFailed],
        AgentVmStartStep::CreateNetwork(_) => vec![StartOutcome::CreateNetworkFailed],
        AgentVmStartStep::InspectAndValidateNetwork(_) => vec![
            StartOutcome::InspectNetworkFailed,
            StartOutcome::ParseNetworkInspectionFailed,
            StartOutcome::ValidateNetworkInspectionFailed,
        ],
        AgentVmStartStep::InstallFirewall(_) => vec![StartOutcome::InstallFirewallFailed],
        AgentVmStartStep::ProbeVmAbsent(_) => vec![StartOutcome::VmAbsenceProbeFailed],
        AgentVmStartStep::StartVm(_) => vec![StartOutcome::StartVmFailed],
        AgentVmStartStep::InstallGuestIpv6Deny(_) => {
            vec![StartOutcome::InstallGuestIpv6DenyFailed]
        }
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

    /// The underlying list command, for projecting the probe into the dry-run
    /// start-invocation sequence.
    fn into_invocation(self) -> ProcessInvocation {
        self.invocation
    }
}

impl BrokerUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Run the start sequence, tearing down this session's own infrastructure on
/// failure.
///
/// **Ownership.** All resource names derive from the plan's `SessionId`, and
/// failure cleanup removes resources *by that name*. Each creating step
/// (`CreateNetwork`, `StartVm`) is preceded by an absence probe
/// (`ProbeNetworkAbsent`, `ProbeVmAbsent`) that reports
/// [`StartFailure::NetworkAlreadyPresent`] / [`StartFailure::VmAlreadyPresent`] —
/// which cleanup leaves untouched — if the resource already exists when the start
/// begins, so *this function's* in-start cleanup performs no teardown on that
/// conflict. Names are host-global but ownership is only per-`--state-dir`, and a
/// foreign same-name resource only exists when a `SessionId` is deliberately
/// reused across state directories (or the raw runner) — normal ids are random v4
/// UUIDs that never collide. Reuse is accepted as a fail case, and the failure may
/// be messy there: the managed daemon's outer rollback tears the session's
/// resources down *unconditionally by name*, so on the daemon path a refused
/// foreign resource can still be removed. The `writ.owner` label stamped on the
/// created resources is informational (see [`AgentVmOwnerToken`]); it does not
/// gate cleanup.
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
        // Prove absence before creating. The network name is host-global but
        // ownership is per-state-dir (or the caller may be the unmanaged raw
        // path), so a network already bearing this session's name is not ours to
        // create — nor, on a later failure, to remove. Refuse rather than risk
        // disrupting another owner's live session. Only after this confirms
        // absence does CreateNetwork run, so a create failure can safely be
        // cleaned as our own partial creation. Best-effort: a concurrent creator
        // in the window between this probe and create still races; true
        // exclusivity needs the managed state-store lock.
        AgentVmStartStep::ProbeNetworkAbsent(probe) => match probe.contains_resource() {
            Ok(true) => Err((
                StartFailure::NetworkAlreadyPresent {
                    network: plan.names().network().to_string(),
                },
                StartOutcome::NetworkAbsenceProbeFailed,
            )),
            Ok(false) => Ok(()),
            // The probe failed, so create never ran and nothing was created:
            // the outcome maps to no teardown.
            Err(source) => Err((
                StartFailure::NetworkPresenceProbeFailed { source },
                StartOutcome::NetworkAbsenceProbeFailed,
            )),
        },
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
        // Prove the agent VM absent before starting it (the network and PF anchor
        // already exist and are ours). A present or unprobeable VM is not ours, so
        // refuse — cleanup then removes the network and PF but not the VM.
        AgentVmStartStep::ProbeVmAbsent(probe) => match probe.contains_resource() {
            Ok(true) => Err((
                StartFailure::VmAlreadyPresent {
                    vm: plan.names().vm().to_string(),
                },
                StartOutcome::VmAbsenceProbeFailed,
            )),
            Ok(false) => Ok(()),
            Err(source) => Err((
                StartFailure::VmPresenceProbeFailed { source },
                StartOutcome::VmAbsenceProbeFailed,
            )),
        },
        AgentVmStartStep::StartVm(_) => plan
            .run_start_vm_invocation()
            .map_err(|err| (err, StartOutcome::StartVmFailed)),
        AgentVmStartStep::InstallGuestIpv6Deny(invocation) => invocation
            .run()
            .map_err(|err| (err.into(), StartOutcome::InstallGuestIpv6DenyFailed)),
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
    let agent_result = stop_agent_vm_session(&state.to_stop_plan(tools));
    // A clean agent teardown means the agent VM was proven absent (and its
    // firewall/network cleanup succeeded) — the precondition for removing the shared
    // internal network the broker arm owns. A conservative proxy: if any agent-side
    // step errored we preserve the shared network, fail closed, and let a later
    // retry remove it once the agent VM is provably gone.
    let agent_vm_absent = agent_result.is_ok();
    let mut errors = match agent_result {
        Ok(()) => Vec::new(),
        Err(agent) => agent.into_errors(),
    };
    // For vm placement the broker arm owns a dedicated broker VM plus the shared
    // network the agent only joined; tear them down *after* the agent VM is gone.
    // Idempotent + absence-based like the agent VM/network cleanup, so lagging Apple
    // Container removals and already-absent resources on retry don't fail the stop.
    // The shared-network step is gated on `agent_vm_absent` so a possibly-live agent
    // is never stranded off its network prematurely. Failures are collected
    // alongside the agent ones. All names derive from session identity, so no launch
    // plan is needed. (The per-session host material dir — copied secrets included —
    // is removed by the daemon, which owns that path policy.)
    if state.broker_placement() == BrokerPlacement::Vm
        && let Err(broker) = run_broker_vm_cleanup_until_absent(
            &container,
            state.session_id(),
            state.names().network(),
            agent_vm_absent,
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
    match run_cleanup_for_phase(plan, cleanup_phase_for_failure(outcome, &original)) {
        Ok(()) => Err(original.into()),
        Err(cleanup) => Err(AgentVmLifecycleRunError::CleanupAfterFailure {
            original: Box::new(original),
            cleanup: Box::new(cleanup),
        }),
    }
}

/// Refine the outcome→phase mapping by failure kind. Almost always the outcome
/// alone determines cleanup, because each creating step runs only after its
/// resource was proven absent. The one exception: a *creating command* that never
/// spawned (`ProcessInvocationError::Run`, which is spawn-only) created nothing,
/// so it must be demoted below its own resource. This matters when the container
/// tool becomes unavailable between the absence probe and the create/run command
/// (removed or made non-executable): routing cleanup through the same missing
/// tool would otherwise fail and strand a recovery record for infrastructure that
/// never existed. A post-spawn `WaitOutput` or a nonzero `Failed` exit may have
/// created the resource, so those still use the outcome's phase.
fn cleanup_phase_for_failure(
    outcome: StartOutcome,
    original: &StartFailure,
) -> Option<CompletedStartStep> {
    let never_spawned = matches!(
        original,
        StartFailure::Process(ProcessInvocationError::Run { .. })
    );
    if never_spawned {
        match outcome {
            // `network create` is the first creating step: nothing exists yet.
            StartOutcome::CreateNetworkFailed => return None,
            // The firewall helper never ran, so no anchor was loaded; only the
            // already-created network exists.
            StartOutcome::InstallFirewallFailed => return Some(CompletedStartStep::NetworkCreated),
            // `container run` never started the VM; the network and PF anchor
            // already exist and are ours.
            StartOutcome::StartVmFailed => return Some(CompletedStartStep::FirewallInstalled),
            _ => {}
        }
    }
    cleanup_step_after_start_outcome(outcome)
}

/// Cleanup after a *start* failure, by phase. Each resource is removed by name;
/// no ownership check is attempted.
///
/// The `writ.owner` label stamped on the network and VM is informational only
/// (visible via `container inspect`). It deliberately does *not* gate cleanup:
/// making failure cleanup safe against a concurrent same-name owner would require
/// host-global coordination the per-`--state-dir` design lacks, and that only
/// matters when a session id is *deliberately reused* across state directories
/// (or the raw runner) — normal session ids are random v4 UUIDs that never
/// collide. The prove-absence steps make the common conflict (the resource
/// already exists when the start begins) fail cleanly without any teardown; the
/// residual is the narrow window where two concurrent reused-id starts both
/// probe absent, which we accept may fail messily. See [`AgentVmOwnerToken`].
fn run_cleanup_for_phase(
    plan: &AgentVmSessionPlan,
    phase: Option<CompletedStartStep>,
) -> Result<(), CleanupErrors> {
    let stop = plan.stop_plan();
    match phase {
        // Network-created phase: the firewall is not yet installed. Host removes
        // the network it created; vm has nothing to clean (the broker arm owns
        // the shared network).
        Some(CompletedStartStep::NetworkCreated) => match plan.broker_placement {
            BrokerPlacement::Host => single_cleanup_result(run_network_cleanup_until_absent(&stop)),
            BrokerPlacement::Vm => Ok(()),
        },
        // Firewall-installed phase: PF anchor + (host) network, but no VM — the VM
        // was never started (its absence probe failed, or the firewall step did).
        Some(CompletedStartStep::FirewallInstalled) => {
            finish_cleanup_errors(firewall_then_network_cleanup_errors(&stop))
        }
        // Vm-started phase: host removes VM+PF+network, vm removes VM+PF.
        Some(CompletedStartStep::VmStarted) => run_stop_plan_cleanup(&stop),
        None => Ok(()),
    }
}

fn single_cleanup_result(result: Result<(), ProcessInvocationError>) -> Result<(), CleanupErrors> {
    result.map_err(|err| CleanupErrors::new(vec![err]))
}

fn run_stop_plan_cleanup(plan: &AgentVmSessionStopPlan) -> Result<(), CleanupErrors> {
    let errors = stop_plan_cleanup_errors(run_vm_cleanup_until_absent(plan), || {
        firewall_then_network_cleanup_errors(plan)
    });
    finish_cleanup_errors(errors)
}

/// Sequence the stop-plan teardown so the host PF anchor outlives the agent VM.
///
/// The PF anchor is the *only* thing isolating the (untrusted) agent VM from host
/// services: an `--internal` network blocks internet egress but not host
/// reachability, so a live guest with no anchor can reach arbitrary host
/// services. The firewall — and, in host placement, the shared network — is
/// therefore removed **only once the agent VM is proven absent** from the
/// container list. If absence cannot be proven (the VM still lists, or the
/// presence probe itself errored), the anchor is preserved and only the
/// VM-cleanup error is surfaced; the removal is retried by a later idempotent
/// stop/reconcile once the VM is gone. Fail closed: never widen a possibly-live
/// guest's reach to the host by dropping its firewall before the VM it isolates.
fn stop_plan_cleanup_errors(
    vm_cleanup: Result<(), ProcessInvocationError>,
    remove_firewall_then_network: impl FnOnce() -> Vec<ProcessInvocationError>,
) -> Vec<ProcessInvocationError> {
    match vm_cleanup {
        Ok(()) => remove_firewall_then_network(),
        Err(vm) => vec![vm],
    }
}

fn firewall_then_network_cleanup_errors(
    plan: &AgentVmSessionStopPlan,
) -> Vec<ProcessInvocationError> {
    let mut errors = Vec::new();
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
    errors
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
/// fatal error. The shared internal network is removed last, and only when
/// `remove_shared_network` — set by the caller once the agent VM (which also joins
/// that network) is proven absent. While the agent VM cannot be proven gone the
/// shared network is preserved, mirroring the agent-side fail-closed rule in
/// [`stop_plan_cleanup_errors`]: never drop a network a possibly-live agent still
/// sits on. The broker VM and its egress network are always removed (killing the
/// broker VM revokes its authority source). Failures are collected. All names
/// derive from session identity (no launch plan).
fn run_broker_vm_cleanup_until_absent(
    container_tool: &Path,
    session_id: SessionId,
    internal_network: &str,
    remove_shared_network: bool,
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
    // The shared internal network is the last (probe, removal) pair; drop it from
    // the sequence when the agent VM is not proven absent, preserving the network a
    // possibly-live agent still sits on. The broker VM + egress network pairs always
    // run.
    let step_count = if remove_shared_network {
        probes.len()
    } else {
        probes.len() - 1
    };
    let mut errors = Vec::new();
    for ((probe, still_present), removal) in probes.into_iter().zip(removals).take(step_count) {
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
            Just(StartOutcome::NetworkAbsenceProbeFailed),
            Just(StartOutcome::CreateNetworkFailed),
            Just(StartOutcome::InspectNetworkFailed),
            Just(StartOutcome::ParseNetworkInspectionFailed),
            Just(StartOutcome::ValidateNetworkInspectionFailed),
            Just(StartOutcome::InstallFirewallFailed),
            Just(StartOutcome::VmAbsenceProbeFailed),
            Just(StartOutcome::StartVmFailed),
            Just(StartOutcome::InstallGuestIpv6DenyFailed),
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
                // Success, or a network-absence-probe failure that created nothing.
                StartOutcome::Started | StartOutcome::NetworkAbsenceProbeFailed => 0,
                // Network / inspect failure: remove the network (rm + delete = 2).
                StartOutcome::CreateNetworkFailed
                | StartOutcome::InspectNetworkFailed
                | StartOutcome::ParseNetworkInspectionFailed
                | StartOutcome::ValidateNetworkInspectionFailed => 2,
                // Firewall-install failure (may have loaded the anchor) or a
                // VM-absence-probe failure: PF removal (1) + network (2), no VM.
                StartOutcome::InstallFirewallFailed | StartOutcome::VmAbsenceProbeFailed => 3,
                // VM started (or later): VM (4) + PF (1) + network (2).
                StartOutcome::StartVmFailed
                | StartOutcome::InstallGuestIpv6DenyFailed
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
                        phase,
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
