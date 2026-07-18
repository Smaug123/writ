//! Session-teardown execution for the agent-VM lifecycle.
//!
//! Once a [`super::AgentVmSessionStopPlan`] (or a partial-start failure) says
//! *what* to tear down, these helpers *run* it: they issue the stop
//! invocations, poll `container`/network resources until each is provably
//! absent (bounded retries), and fold the per-step [`super::ProcessInvocationError`]s
//! into a single [`super::CleanupErrors`]. The plan construction lives in
//! [`super::plan`]; the shared low-level helpers this module leans on
//! (`resource_list_contains_exact_line`, `shell_quote`, `derive_session_network`)
//! stay at the module root and are reached via `super`. Extracted from
//! `agent_vm_lifecycle.rs` to keep that file readable; behaviour is unchanged.

use super::*;

pub(super) fn fail_after_cleanup<T>(
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
pub(super) fn cleanup_phase_for_failure(
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

pub(super) fn run_stop_plan_cleanup(plan: &AgentVmSessionStopPlan) -> Result<(), CleanupErrors> {
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
pub(super) fn stop_plan_cleanup_errors(
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

pub(super) fn finish_cleanup_errors(
    errors: Vec<ProcessInvocationError>,
) -> Result<(), CleanupErrors> {
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
pub(super) fn run_broker_vm_cleanup_until_absent(
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

pub(super) fn run_cleanup_until_resource_absent_with<E>(
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
