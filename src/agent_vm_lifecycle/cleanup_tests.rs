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
        StartOutcome::ProbeGuestIpv6Failed,
        StartOutcome::ValidateGuestIpv6Failed,
        StartOutcome::ReleaseGuestCommandFailed,
    ] {
        assert!(produced.contains(&outcome), "no step produces {outcome:?}",);
    }
    assert_eq!(produced.len(), 11, "produced = {produced:?}");
}
