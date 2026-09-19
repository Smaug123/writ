//! Tests for the locked lifecycle model.
//!
//! The headline property — that [`ReleaseAttempted`] cannot be reached
//! without [`GuestSecurityLocked`] and [`FinalFirewallInstalled`] — is a
//! compile-time fact, not one of these tests: the only constructor is
//! `GuestSecurityLocked::release_attempted`, which consumes the value, and
//! `GuestSecurityLocked`'s only constructor consumes a
//! `FinalFirewallInstalled`. A start path that skipped either would not
//! compile, so there is nothing here to assert about it. What *is* asserted is
//! everything the types cannot say: that the chain reaches every phase in
//! order, that each phase's snapshot carries exactly its own facts, and that
//! nothing is lost on the way through the release gate.

use proptest::prelude::*;

use super::*;

fn interfaces(names: &[&str]) -> Vec<PfInterface> {
    names
        .iter()
        .map(|name| PfInterface::new(*name).expect("test interface name"))
        .collect()
}

fn firewall_facts() -> FirewallFacts {
    FirewallFacts::new(
        interfaces(&["bridge100", "vmenet0"]),
        PfInstallPhase::Reresolve,
    )
}

fn guest_facts() -> GuestFacts {
    GuestFacts::new(1)
}

/// Walk the whole chain once, collecting each step's snapshot.
///
/// This is the only way to build the later phases, which is the point: the
/// function reads as the sequence itself.
fn walk() -> Vec<LockedLifecycle> {
    let claimed = Claimed::new();
    let mut snapshots = vec![claimed.lifecycle()];

    let network_validated = claimed.network_validated();
    snapshots.push(network_validated.lifecycle());

    let vm_started = network_validated.agent_vm_started();
    snapshots.push(vm_started.lifecycle());

    let firewalled = vm_started.final_firewall_installed(firewall_facts());
    snapshots.push(firewalled.lifecycle());

    let locked = firewalled.guest_security_locked(guest_facts());
    snapshots.push(locked.lifecycle());

    let attempted = locked.release_attempted();
    snapshots.push(attempted.lifecycle());

    let released = attempted.workload_released();
    snapshots.push(released.lifecycle());

    snapshots
}

#[test]
fn the_chain_reaches_every_phase_in_order() {
    let phases: Vec<LockedPhase> = walk().iter().map(LockedLifecycle::phase).collect();
    assert_eq!(phases, LockedPhase::ALL.to_vec());
}

#[test]
fn the_phases_are_ordered_by_how_far_the_start_got() {
    for pair in LockedPhase::ALL.windows(2) {
        assert!(
            pair[0] < pair[1],
            "{:?} must precede {:?}: `<` is what everything else keys off",
            pair[0],
            pair[1]
        );
    }
}

/// Each snapshot carries exactly the facts its phase implies — no more (a
/// claimed session naming interfaces it cannot know) and no fewer (a released
/// workload whose anchor scope is unrecorded).
#[test]
fn each_phase_carries_exactly_its_own_facts() {
    for lifecycle in walk() {
        let phase = lifecycle.phase();
        assert_eq!(
            lifecycle.firewall().is_some(),
            phase >= LockedPhase::FinalFirewallInstalled,
            "{phase} firewall facts"
        );
        assert_eq!(
            lifecycle.guest().is_some(),
            phase >= LockedPhase::GuestSecurityLocked,
            "{phase} guest facts"
        );
        if let Some(firewall) = lifecycle.firewall() {
            assert_eq!(firewall, &firewall_facts(), "{phase} kept the facts given");
        }
        if let Some(guest) = lifecycle.guest() {
            assert_eq!(guest, guest_facts(), "{phase} kept the facts given");
        }
    }
}

/// The release gate loses nothing: what the host proved before it decided to
/// release is exactly what the record written at the gate says.
#[test]
fn the_release_gate_carries_its_proof_through_unchanged() {
    let locked = Claimed::new()
        .network_validated()
        .agent_vm_started()
        .final_firewall_installed(firewall_facts())
        .guest_security_locked(guest_facts());
    let before = locked.lifecycle();

    let attempted = locked.release_attempted();
    assert_eq!(attempted.firewall(), before.firewall().unwrap());
    assert_eq!(Some(attempted.guest()), before.guest());

    let released = attempted.workload_released();
    assert_eq!(released.firewall(), before.firewall().unwrap());
    assert_eq!(Some(released.guest()), before.guest());
}

/// From the gate onwards the daemon cannot say whether the workload is
/// running, so it must not claim to.
#[test]
fn a_workload_may_be_running_from_the_gate_onwards() {
    for phase in LockedPhase::ALL {
        assert_eq!(
            phase.workload_may_be_running(),
            matches!(
                phase,
                LockedPhase::ReleaseAttempted | LockedPhase::WorkloadReleased
            ),
            "{phase}"
        );
    }
}

#[test]
fn phase_names_are_distinct_and_round_trip() {
    let mut names: Vec<&str> = LockedPhase::ALL.iter().map(|p| p.as_str()).collect();
    names.sort_unstable();
    let distinct = names.len();
    names.dedup();
    assert_eq!(names.len(), distinct, "two phases share a spelling");

    for phase in LockedPhase::ALL {
        assert_eq!(LockedPhase::parse(phase.as_str()), Some(phase));
        assert_eq!(phase.to_string(), phase.as_str());
    }
}

proptest! {
    /// Only the spelling a phase writes parses back as that phase. The
    /// persisted record is the consumer: a phase read loosely would be a
    /// session whose progress the daemon guessed.
    #[test]
    fn only_a_phase_spelling_parses(text in "[ -~]{0,40}") {
        match LockedPhase::parse(&text) {
            Some(phase) => prop_assert_eq!(phase.as_str(), text.as_str()),
            None => prop_assert!(
                LockedPhase::ALL.iter().all(|phase| phase.as_str() != text),
                "refused a spelling a phase writes"
            ),
        }
    }

    /// The same for the firewall install phase, which the record persists the
    /// same way.
    #[test]
    fn only_an_install_phase_spelling_parses(text in "[ -~]{0,40}") {
        match PfInstallPhase::parse(&text) {
            Some(phase) => prop_assert_eq!(phase.as_str(), text.as_str()),
            None => prop_assert!(
                PfInstallPhase::ALL.iter().all(|phase| phase.as_str() != text),
                "refused a spelling an install phase writes"
            ),
        }
    }
}
