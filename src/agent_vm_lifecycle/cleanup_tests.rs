//! Example/edge-case tests for cleanup error aggregation and the
//! bounded resource-absence polling loop.
use super::test_support::*;
use super::*;
use std::collections::VecDeque;

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
fn stop_cleanup_removes_firewall_and_network_once_vm_absent() {
    let mut removed = false;
    let errors = stop_plan_cleanup_errors(Ok(()), || {
        removed = true;
        Vec::new()
    });
    assert!(
        removed,
        "the firewall (and network) removal must run once the agent VM is proven absent"
    );
    assert!(errors.is_empty());
}

#[test]
fn stop_cleanup_preserves_firewall_when_vm_absence_unproven() {
    // The agent VM could not be proven absent (still lists after removal attempts):
    // the PF anchor is the only thing isolating a possibly-live guest from host
    // services, so it MUST NOT be dropped. The removal closure must not run.
    let vm_err = ProcessInvocation::new("container", ["list", "--all", "--quiet"])
        .resource_still_present("VM still appears in container list after removal attempts");
    let mut removed = false;
    let errors = stop_plan_cleanup_errors(Err(vm_err), || {
        removed = true;
        Vec::new()
    });
    assert!(
        !removed,
        "the PF anchor (and network) must be preserved until the VM is proven absent"
    );
    assert_eq!(
        errors.len(),
        1,
        "the VM-cleanup error is surfaced so the stop is retried"
    );
    assert!(matches!(
        errors[0],
        ProcessInvocationError::ResourceStillPresent { .. }
    ));
}

#[test]
fn stop_cleanup_surfaces_firewall_errors_after_vm_removed() {
    // Once the VM is gone the anchor removal runs; its errors still propagate.
    let fw_err = ProcessInvocation::new("/tmp/writ-missing-pf-helper", ["remove"])
        .run()
        .unwrap_err();
    let errors = stop_plan_cleanup_errors(Ok(()), || vec![fw_err]);
    assert_eq!(errors.len(), 1);
    assert!(matches!(errors[0], ProcessInvocationError::Run { .. }));
}

#[test]
fn broker_vm_cleanup_preserves_shared_network_until_agent_absent() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let args_log = dir.path().join("args.log");
    let tool = dir.path().join("fake-container");
    // `network list` reports the shared network present; `list --all` (broker VM)
    // reports absent. So the broker VM and egress steps resolve fast; only the
    // shared-network step would ever issue a `network rm` for the shared net.
    let script = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$*\" >> '{log}'\n\
         if [ \"$1\" = network ] && [ \"$2\" = list ]; then printf '%s\\n' writ-shared-net; fi\n\
         exit 0\n",
        log = args_log.display(),
    );
    std::fs::write(&tool, script).unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o700)).unwrap();

    // Agent VM not proven absent (`remove_shared_network = false`): the shared
    // network the agent also joins must be preserved, so no `network rm` for it.
    run_broker_vm_cleanup_until_absent(&tool, session_id(), "writ-shared-net", false).unwrap();

    let args = std::fs::read_to_string(&args_log).unwrap();
    assert!(
        !args.contains("network rm"),
        "the shared internal network must be preserved while the agent VM is \
         unproven-absent; args:\n{args}"
    );
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

/// Catches drift if a new `StartOutcome` is added but no step variant
/// produces it: the runner would silently never report the new outcome.
#[test]
fn every_failure_outcome_is_producible_by_some_step() {
    let mut produced: Vec<StartOutcome> = Vec::new();
    for mode in [
        Ipv6IsolationMode::DualStackRequired,
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
    ] {
        for step in plan_with_ipv6_mode(7, mode).start_steps() {
            for outcome in step_failure_outcomes(&step) {
                if !produced.contains(&outcome) {
                    produced.push(outcome);
                }
            }
        }
    }

    for outcome in [
        StartOutcome::NetworkAbsenceProbeFailed,
        StartOutcome::CreateNetworkFailed,
        StartOutcome::InspectNetworkFailed,
        StartOutcome::ParseNetworkInspectionFailed,
        StartOutcome::ValidateNetworkInspectionFailed,
        StartOutcome::InstallFirewallFailed,
        StartOutcome::VmAbsenceProbeFailed,
        StartOutcome::StartVmFailed,
        StartOutcome::DiscoverBridgeFailed,
        StartOutcome::InstallIpv6DenyFailed,
        StartOutcome::ProbeGuestIpv6Failed,
        StartOutcome::ValidateGuestIpv6Failed,
        StartOutcome::ReleaseGuestCommandFailed,
    ] {
        assert!(produced.contains(&outcome), "no step produces {outcome:?}",);
    }
    assert_eq!(produced.len(), 13, "produced = {produced:?}");
}
