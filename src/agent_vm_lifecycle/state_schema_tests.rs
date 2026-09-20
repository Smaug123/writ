//! Tests for state schema v3: what a record may say about a locked session,
//! what a v2 record may be used for, and the release gate's ordering.
//!
//! Stage E1 of `docs/plans/2026-09-01-ipv4-only-locked-v1.md`.

use super::test_support::*;
use super::*;
use crate::agent_vm_firewall::PfInstallPhase;
use crate::agent_vm_locked_lifecycle::{
    Claimed, FirewallFacts, GuestFacts, LOCKED_RELEASE_SIGNAL, LockedLifecycle, LockedPhase,
};
use crate::core::PfInterface;
use crate::test_support::{shell_quote_path, write_executable_script};
use proptest::prelude::*;
use serde_json::{Value, json};

fn legacy_state() -> AgentVmSessionState {
    let plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    AgentVmSessionState::from_start_plan(&plan, AgentVmSessionStateStatus::Running)
}

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
    .expect("a final firewall names at least one interface")
}

fn guest_facts() -> GuestFacts {
    GuestFacts::new(1)
}

/// Every phase's lifecycle value, built by walking the typestate chain — the
/// only way to build them, which is the point of the chain.
fn every_lifecycle() -> Vec<LockedLifecycle> {
    let claimed = Claimed::new();
    let claimed_snapshot = claimed.lifecycle();
    let network = claimed.network_validated();
    let network_snapshot = network.lifecycle();
    let vm = network.agent_vm_started();
    let vm_snapshot = vm.lifecycle();
    let firewalled = vm.final_firewall_installed(firewall_facts());
    let firewalled_snapshot = firewalled.lifecycle();
    let locked = firewalled.guest_security_locked(guest_facts());
    let locked_snapshot = locked.lifecycle();
    let attempted = locked.release_attempted();
    let attempted_snapshot = attempted.lifecycle();
    let released_snapshot = attempted.workload_released().lifecycle();
    vec![
        claimed_snapshot,
        network_snapshot,
        vm_snapshot,
        firewalled_snapshot,
        locked_snapshot,
        attempted_snapshot,
        released_snapshot,
    ]
}

fn firewall_lifecycle() -> LockedLifecycle {
    Claimed::new()
        .network_validated()
        .agent_vm_started()
        .final_firewall_installed(firewall_facts())
        .lifecycle()
}

fn locked_lifecycle() -> LockedLifecycle {
    Claimed::new()
        .network_validated()
        .agent_vm_started()
        .final_firewall_installed(firewall_facts())
        .guest_security_locked(guest_facts())
        .lifecycle()
}

fn json_of(state: &AgentVmSessionState) -> Value {
    serde_json::from_slice(&state.to_json_bytes().unwrap()).unwrap()
}

fn load(json: &Value) -> Result<AgentVmSessionState, AgentVmSessionStateError> {
    AgentVmSessionState::from_json_bytes(&serde_json::to_vec(json).unwrap())
}

/// The same record as `state`, written the way the daemon before this change
/// wrote it: schema v2, no locked section.
fn as_v2(state: &AgentVmSessionState) -> Value {
    let mut json = json_of(state);
    let object = json.as_object_mut().unwrap();
    object.insert("version".into(), json!(2));
    object.remove("locked");
    json
}

// --- what this binary writes ------------------------------------------------

#[test]
fn a_record_this_binary_writes_is_schema_v3() {
    let json = json_of(&legacy_state());
    assert_eq!(json["version"], json!(3));
    assert_eq!(
        legacy_state().schema(),
        StateSchema::V3,
        "a record built here is what we would write"
    );
}

#[test]
fn a_legacy_record_carries_no_locked_section() {
    let json = json_of(&legacy_state());
    assert!(
        json.as_object().unwrap().get("locked").is_none(),
        "a session under a profile with no phases must not carry one: {json}"
    );
    assert_eq!(legacy_state().locked_phase(), None);
}

#[test]
fn an_unknown_schema_version_is_refused() {
    for version in [0, 1, 4, 99] {
        let mut json = json_of(&legacy_state());
        json.as_object_mut()
            .unwrap()
            .insert("version".into(), json!(version));
        assert!(
            matches!(
                load(&json),
                Err(AgentVmSessionStateError::UnsupportedVersion { version: found, .. })
                    if found == version
            ),
            "version {version} must be refused, not guessed at"
        );
    }
}

// --- the v2 reader ----------------------------------------------------------

#[test]
fn a_v2_record_loads_as_cleanup_only_and_is_never_locked() {
    let state = legacy_state();
    let restored = load(&as_v2(&state)).expect("a v2 record still loads");

    assert_eq!(restored.schema(), StateSchema::V2);
    assert!(restored.schema().is_cleanup_only());
    assert_eq!(
        restored.locked_phase(),
        None,
        "there is no locked section in a v2 file to report"
    );
    assert!(matches!(restored.lifecycle(), SessionLifecycle::Legacy(_)));

    // And what it is for: a stop plan.
    let tools = AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo");
    let stop = restored.to_stop_plan(tools).stop_invocations();
    assert!(
        stop.iter()
            .any(|inv| inv.args_lossy().first().map(String::as_str) == Some("network")),
        "a v2 record must still tear its network down: {stop:?}"
    );
}

/// A v2 writer had no `locked` field, so a v2 record carrying one was not
/// written by a v2 writer. The version is the only claim about the shape, and
/// a file whose shape and version disagree is one we can say nothing about.
#[test]
fn a_v2_record_carrying_a_locked_section_is_refused() {
    let mut json = as_v2(&legacy_state());
    json.as_object_mut()
        .unwrap()
        .insert("locked".into(), json!({ "phase": "claimed" }));
    assert!(matches!(
        load(&json),
        Err(AgentVmSessionStateError::Corrupt { .. })
    ));
}

/// Rolling back fails closed. A daemon that only knows v2 uses the same exact
/// version check this one uses for an unknown version, so a v3 record is
/// refused rather than read as a legacy session.
#[test]
fn a_v3_record_is_not_readable_as_v2() {
    let json = json_of(&locked_state());
    assert_eq!(json["version"], json!(3));
    assert!(
        json.as_object().unwrap().contains_key("locked"),
        "the section a v2 reader has no field for: {json}"
    );
}

// --- the locked section -----------------------------------------------------

fn locked_state() -> AgentVmSessionState {
    legacy_state().with_locked_lifecycle_for_test(locked_lifecycle())
}

#[test]
fn every_locked_lifecycle_round_trips_through_the_record() {
    for lifecycle in every_lifecycle() {
        let state = legacy_state().with_locked_lifecycle_for_test(lifecycle.clone());
        let restored = load(&json_of(&state)).expect("locked record round-trips");
        assert_eq!(restored, state, "{:?}", lifecycle.phase());
        assert_eq!(restored.locked_phase(), Some(lifecycle.phase()));
        assert_eq!(
            restored.lifecycle(),
            &SessionLifecycle::Locked(lifecycle.clone())
        );
    }
}

/// The coarse status is a projection, so an operator (and an older reader of
/// that field) sees something true: a locked session is running exactly once
/// its workload was released.
#[test]
fn the_coarse_status_of_a_locked_record_tracks_the_release() {
    for lifecycle in every_lifecycle() {
        let phase = lifecycle.phase();
        let state = legacy_state().with_locked_lifecycle_for_test(lifecycle);
        let expected = if phase == LockedPhase::WorkloadReleased {
            AgentVmSessionStateStatus::Running
        } else {
            AgentVmSessionStateStatus::Starting
        };
        assert_eq!(state.status(), expected, "{phase}");
        assert_eq!(
            json_of(&state)["status"],
            json!(expected.as_str()),
            "{phase}"
        );
    }
}

/// The wire form is loose (a string and three optional fields); the DU is
/// tight. Every combination the DU cannot express must be refused at the
/// boundary rather than handed to teardown as a released session with no
/// interfaces.
#[test]
fn a_locked_section_whose_facts_disagree_with_its_phase_is_refused() {
    let facts = [
        ("interfaces", json!(["bridge100"])),
        ("firewall_install_phase", json!("reresolve")),
        ("isolation_abi", json!(1)),
    ];
    let mut checked = 0usize;
    for phase in LockedPhase::ALL {
        // Every subset of the three fact groups, against every phase.
        for mask in 0u8..8 {
            let mut locked = serde_json::Map::new();
            locked.insert("phase".into(), json!(phase.as_str()));
            for (bit, (key, value)) in facts.iter().enumerate() {
                if mask & (1 << bit) != 0 {
                    locked.insert((*key).into(), value.clone());
                }
            }
            let mut json = json_of(&legacy_state());
            json.as_object_mut()
                .unwrap()
                .insert("locked".into(), Value::Object(locked));

            // The one coherent combination per phase: the facts the phase
            // implies, and no others. `interfaces` and `firewall_install_phase`
            // travel together.
            let wants_firewall = phase >= LockedPhase::FinalFirewallInstalled;
            let wants_guest = phase >= LockedPhase::GuestSecurityLocked;
            let coherent = (mask & 0b001 != 0) == wants_firewall
                && (mask & 0b010 != 0) == wants_firewall
                && (mask & 0b100 != 0) == wants_guest;

            let loaded = load(&json);
            checked += 1;
            if coherent {
                let loaded = loaded.unwrap_or_else(|err| {
                    panic!("{phase} with exactly its own facts must load: {err}")
                });
                assert_eq!(loaded.locked_phase(), Some(phase));
            } else {
                assert!(
                    matches!(loaded, Err(AgentVmSessionStateError::Corrupt { .. })),
                    "{phase} with fact mask {mask:03b} must be refused, got {loaded:?}"
                );
            }
        }
    }
    assert_eq!(checked, LockedPhase::ALL.len() * 8, "the whole grid");
}

#[test]
fn an_unreadable_phase_or_install_phase_is_refused() {
    for locked in [
        json!({ "phase": "released" }),
        json!({ "phase": "" }),
        json!({ "phase": "Claimed" }),
        json!({
            "phase": "final_firewall_installed",
            "interfaces": ["bridge100"],
            "firewall_install_phase": "somewhere",
        }),
        json!({
            "phase": "final_firewall_installed",
            "interfaces": ["bridge 100"],
            "firewall_install_phase": "reresolve",
        }),
    ] {
        let mut json = json_of(&legacy_state());
        json.as_object_mut()
            .unwrap()
            .insert("locked".into(), locked.clone());
        assert!(
            matches!(load(&json), Err(AgentVmSessionStateError::Corrupt { .. })),
            "{locked} must be refused"
        );
    }
}

proptest! {
    /// Whatever the interfaces and ABI, a record round-trips unchanged: the
    /// allowlist of what teardown will scope its removal to is exactly what
    /// the install recorded.
    #[test]
    fn locked_facts_survive_the_round_trip(
        names in prop::collection::vec("[a-z]{2,6}[0-9]{1,3}", 1..4),
        install_phase in prop::sample::select(&PfInstallPhase::ALL[..]),
        abi in 0u32..1000,
    ) {
        let lifecycle = LockedLifecycle::WorkloadReleased(
            FirewallFacts::new(interfaces(&names.iter().map(String::as_str).collect::<Vec<_>>()), install_phase).unwrap(),
            GuestFacts::new(abi),
        );
        let state = legacy_state().with_locked_lifecycle_for_test(lifecycle);
        prop_assert_eq!(load(&json_of(&state)).unwrap(), state);
    }
}

// --- advancing a locked session ---------------------------------------------

/// A store holding one locked session at `lifecycle`.
fn locked_store(
    lifecycle: LockedLifecycle,
) -> (
    tempfile::TempDir,
    AgentVmSessionStateStore,
    AgentVmSessionState,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path());
    let plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    let starting = store.create_starting(&plan).unwrap();
    let locked = starting.with_locked_lifecycle_for_test(lifecycle);
    store.overwrite_for_test(&locked).unwrap();
    (dir, store, locked)
}

/// `release_attempted` has one door, and it is the one that mints the signal.
/// A second way to write the phase would be a way to write it without being
/// obliged to have the signal in hand.
#[test]
fn advancing_cannot_write_the_release_phase() {
    let (_dir, store, locked) = locked_store(locked_lifecycle());
    let attempted = LockedLifecycle::ReleaseAttempted(firewall_facts(), guest_facts());

    let err = store
        .advance_locked(&locked, attempted)
        .expect_err("release_attempted is not an ordinary advance");
    assert!(matches!(
        err,
        AgentVmSessionStateError::StateMismatch { .. }
    ));
    assert_eq!(
        store.load(locked.session_id()).unwrap().locked_phase(),
        Some(LockedPhase::GuestSecurityLocked)
    );
}

#[test]
fn advancing_refuses_a_legacy_record_and_a_stale_one() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path());
    let plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    let legacy = store.create_starting(&plan).unwrap();

    let err = store
        .advance_locked(&legacy, firewall_lifecycle())
        .expect_err("a legacy session has no phases");
    assert!(matches!(
        err,
        AgentVmSessionStateError::StateMismatch { .. }
    ));

    let (_dir, store, claimed) = locked_store(Claimed::new().lifecycle());
    let network = Claimed::new().network_validated().lifecycle();
    let advanced = store.advance_locked(&claimed, network.clone()).unwrap();
    let err = store
        .advance_locked(&claimed, network)
        .expect_err("the caller's record is no longer the recorded one");
    assert!(matches!(
        err,
        AgentVmSessionStateError::StateMismatch { .. }
    ));
    assert_eq!(store.load(claimed.session_id()).unwrap(), advanced);
}

// --- the release gate -------------------------------------------------------

/// A fake `container` that appends its argv to `log` and then behaves as
/// `fault` says.
fn fake_container(dir: &Path, log: &Path, fault: &str) -> PathBuf {
    write_executable_script(
        dir,
        "container",
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\ncase '{fault}' in\n  fails) exit 7 ;;\nesac\nexit 0\n",
            log = shell_quote_path(log),
        ),
    )
}

/// The record is on disk before the signal exists, so no outcome of the
/// `kill` can leave a released workload behind a record saying it was never
/// released.
///
/// The outcomes worth naming are: it succeeded, it failed, and it never ran —
/// which is where a timed-out `kill` and a daemon that died before sending
/// one both land, because neither leaves the host any more certain than the
/// other about whether the guest got the signal.
#[test]
fn the_release_is_recorded_before_the_signal_can_be_sent() {
    for outcome in ["succeeds", "fails", "never runs"] {
        let (dir, store, locked) = locked_store(locked_lifecycle());
        let log = dir.path().join("container.log");
        let container = fake_container(dir.path(), &log, outcome);
        let tools = AgentVmToolPaths::new(&container, "writ-agent-vm-pf-helper", "sudo");

        let guest_locked = Claimed::new()
            .network_validated()
            .agent_vm_started()
            .final_firewall_installed(firewall_facts())
            .guest_security_locked(guest_facts());
        let recorded = store
            .record_release_attempted(&locked, guest_locked, &tools)
            .expect("recording the intent to release");

        // Holding the signal at all means the record is already written, and
        // the tool has not run: there was no way to run it before now.
        assert_eq!(
            store.load(locked.session_id()).unwrap().locked_phase(),
            Some(LockedPhase::ReleaseAttempted),
            "{outcome}: the record precedes the signal"
        );
        assert!(!log.exists(), "{outcome}: nothing has been sent yet");
        assert_eq!(
            recorded.state.locked_phase(),
            Some(LockedPhase::ReleaseAttempted)
        );
        assert_eq!(
            recorded.signal.invocation().args_lossy(),
            vec![
                "kill".to_string(),
                "--signal".to_string(),
                LOCKED_RELEASE_SIGNAL.to_string(),
                locked.names().vm().to_string(),
            ],
            "{outcome}: the signal is the one the initializer waits for"
        );

        if outcome != "never runs" {
            let sent = recorded.signal.invocation().run();
            assert_eq!(
                sent.is_ok(),
                outcome == "succeeds",
                "{outcome}: the fake tool reported what the case says"
            );
            assert_eq!(
                std::fs::read_to_string(&log).unwrap().trim(),
                format!(
                    "kill --signal {LOCKED_RELEASE_SIGNAL} {}",
                    locked.names().vm()
                ),
                "{outcome}: and it ran exactly once, after the record"
            );
        }

        assert_eq!(
            store.load(locked.session_id()).unwrap().locked_phase(),
            Some(LockedPhase::ReleaseAttempted),
            "{outcome}: and it still says so afterwards"
        );
    }
}

/// The phase after the gate is reachable only from the value the gate handed
/// back, so a `kill` that reported success is the only thing that can record
/// one.
#[test]
fn only_the_recorded_attempt_can_become_a_released_workload() {
    let (_dir, store, locked) = locked_store(locked_lifecycle());
    let tools = AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo");
    let guest_locked = Claimed::new()
        .network_validated()
        .agent_vm_started()
        .final_firewall_installed(firewall_facts())
        .guest_security_locked(guest_facts());

    let recorded = store
        .record_release_attempted(&locked, guest_locked, &tools)
        .unwrap();
    let released = recorded.attempted.workload_released();
    let state = store
        .advance_locked(&recorded.state, released.lifecycle())
        .expect("a successful kill advances past the gate");
    assert_eq!(state.locked_phase(), Some(LockedPhase::WorkloadReleased));
    assert_eq!(state.status(), AgentVmSessionStateStatus::Running);
}

// --- what a record must never be able to say --------------------------------

/// An anchor with no interfaces scopes nothing, so there is no such thing as
/// `FinalFirewallInstalled` without one.
///
/// The reader already refuses it. Letting the *writer* produce it would mean a
/// record that cannot be read back — and since `load_all` fails as a whole,
/// one such record would stop reconciliation reaching any session.
#[test]
fn firewall_facts_need_at_least_one_interface() {
    assert!(FirewallFacts::new(Vec::new(), PfInstallPhase::Reresolve).is_err());
    assert!(FirewallFacts::new(interfaces(&["bridge100"]), PfInstallPhase::Reresolve).is_ok());
}

/// Whatever can be built can be read back. The generator's range is the
/// type's range, so there is no shape the writer admits and the reader does
/// not.
#[test]
fn nothing_a_writer_can_build_is_unreadable() {
    let (_dir, store, claimed) = locked_store(Claimed::new().lifecycle());
    let advanced = store
        .advance_locked(&claimed, Claimed::new().network_validated().lifecycle())
        .unwrap();
    let advanced = store
        .advance_locked(
            &advanced,
            Claimed::new()
                .network_validated()
                .agent_vm_started()
                .lifecycle(),
        )
        .unwrap();
    let advanced = store
        .advance_locked(&advanced, firewall_lifecycle())
        .unwrap();
    assert_eq!(store.load(claimed.session_id()).unwrap(), advanced);
    assert!(
        store.load_all().is_ok(),
        "one unreadable record would hide every other session from reconcile"
    );
}

/// Advancing is one step. The snapshot union is publicly constructible, so the
/// store is the only thing standing between a caller and a record that claims
/// a workload was released without the host ever having decided to release it.
#[test]
fn advancing_is_one_step_at_a_time() {
    let lifecycles: Vec<LockedLifecycle> = every_lifecycle();
    for (from_index, from) in lifecycles.iter().enumerate() {
        for (to_index, to) in lifecycles.iter().enumerate() {
            let (_dir, store, state) = locked_store(from.clone());
            let result = store.advance_locked(&state, to.clone());
            let adjacent = to_index == from_index + 1;
            let is_the_gate = to.phase() == LockedPhase::ReleaseAttempted;
            if adjacent && !is_the_gate {
                assert!(
                    result.is_ok(),
                    "{} -> {} is the next step",
                    from.phase(),
                    to.phase()
                );
            } else {
                assert!(
                    result.is_err(),
                    "{} -> {} is not an advance",
                    from.phase(),
                    to.phase()
                );
                assert_eq!(
                    store.load(state.session_id()).unwrap(),
                    state,
                    "a refused advance changes nothing"
                );
            }
        }
    }
}

/// Facts accumulate; they are not rewritten. An advance that changed the
/// interfaces an earlier phase recorded would be teardown scoping its removal
/// to something the install never loaded.
#[test]
fn advancing_cannot_rewrite_the_facts_an_earlier_phase_recorded() {
    let (_dir, store, state) = locked_store(firewall_lifecycle());
    let other = FirewallFacts::new(interfaces(&["bridge200"]), PfInstallPhase::Reresolve).unwrap();

    let err = store
        .advance_locked(
            &state,
            LockedLifecycle::GuestSecurityLocked(other, guest_facts()),
        )
        .expect_err("the firewall facts are not the caller's to change");
    assert!(matches!(
        err,
        AgentVmSessionStateError::StateMismatch { .. }
    ));
    assert_eq!(store.load(state.session_id()).unwrap(), state);
}

/// The same for the guest's evidence. The ABI in the record is what the
/// *running guest* announced when it locked itself; an advance that replaced
/// it would be the daemon rewriting the one fact it has about what it
/// released, and `record_release_attempted` would mint the signal on the
/// rewritten version.
#[test]
fn advancing_cannot_rewrite_the_guest_evidence_an_earlier_phase_recorded() {
    let other_guest = GuestFacts::new(guest_facts().isolation_abi() + 1);

    // Through the gate: a proof carrying a different ABI is not this session's.
    let (_dir, store, locked) = locked_store(locked_lifecycle());
    let tools = AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo");
    let other_proof = Claimed::new()
        .network_validated()
        .agent_vm_started()
        .final_firewall_installed(firewall_facts())
        .guest_security_locked(other_guest);
    let err = store
        .record_release_attempted(&locked, other_proof, &tools)
        .expect_err("the recorded evidence is not the caller's to change");
    assert!(matches!(
        err,
        AgentVmSessionStateError::StateMismatch { .. }
    ));
    assert_eq!(
        store.load(locked.session_id()).unwrap(),
        locked,
        "and no signal was minted, because nothing was written"
    );

    // And past it: the same for the step after the gate.
    let (_dir, store, attempted) = locked_store(LockedLifecycle::ReleaseAttempted(
        firewall_facts(),
        guest_facts(),
    ));
    let err = store
        .advance_locked(
            &attempted,
            LockedLifecycle::WorkloadReleased(firewall_facts(), other_guest),
        )
        .expect_err("the recorded evidence is not the caller's to change");
    assert!(matches!(
        err,
        AgentVmSessionStateError::StateMismatch { .. }
    ));
    assert_eq!(store.load(attempted.session_id()).unwrap(), attempted);
}

/// A v2 record is a teardown obligation. Promoting one would rewrite it as v3
/// — leaving the caller holding a value that no longer matches what is on disk
/// — and would treat a record that predates the phase model as a live session.
#[test]
fn a_cleanup_only_record_cannot_be_promoted() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path());
    let plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    let starting = store.create_starting(&plan).unwrap();

    // Rewrite it on disk the way the daemon before this change wrote it.
    let v2 = as_v2(&starting);
    std::fs::write(
        store.path_for(plan.session_id()),
        serde_json::to_vec(&v2).unwrap(),
    )
    .unwrap();
    let loaded = store.load(plan.session_id()).unwrap();
    assert_eq!(loaded.schema(), StateSchema::V2);

    for result in [
        store.mark_running(&loaded),
        store.mark_running_with_broker_ipv4(&loaded, "192.168.252.9".parse().unwrap()),
    ] {
        let err = result.expect_err("a v2 record is not a session to promote");
        assert!(matches!(
            err,
            AgentVmSessionStateError::StateMismatch { .. }
        ));
    }
    assert_eq!(
        store.load(plan.session_id()).unwrap(),
        loaded,
        "and it is still the v2 record it was"
    );
}

/// Any lifecycle, with the facts varied independently of the phase.
fn arb_locked_lifecycle() -> impl Strategy<Value = LockedLifecycle> {
    (
        0usize..LockedPhase::ALL.len(),
        prop::collection::vec("[a-z]{2,6}[0-9]{1,3}", 1..3),
        prop::sample::select(&PfInstallPhase::ALL[..]),
        0u32..3,
    )
        .prop_map(|(index, names, install_phase, abi)| {
            let firewall = FirewallFacts::new(
                interfaces(&names.iter().map(String::as_str).collect::<Vec<_>>()),
                install_phase,
            )
            .expect("the generator names at least one interface");
            let guest = GuestFacts::new(abi);
            match LockedPhase::ALL[index] {
                LockedPhase::Claimed => LockedLifecycle::Claimed,
                LockedPhase::NetworkValidated => LockedLifecycle::NetworkValidated,
                LockedPhase::AgentVmStarted => LockedLifecycle::AgentVmStarted,
                LockedPhase::FinalFirewallInstalled => {
                    LockedLifecycle::FinalFirewallInstalled(firewall)
                }
                LockedPhase::GuestSecurityLocked => {
                    LockedLifecycle::GuestSecurityLocked(firewall, guest)
                }
                LockedPhase::ReleaseAttempted => LockedLifecycle::ReleaseAttempted(firewall, guest),
                LockedPhase::WorkloadReleased => LockedLifecycle::WorkloadReleased(firewall, guest),
            }
        })
}

/// A pair that is a genuine step about half the time, so both answers below
/// are reached.
fn arb_advance() -> impl Strategy<Value = (LockedLifecycle, LockedLifecycle)> {
    (
        arb_locked_lifecycle(),
        any::<bool>(),
        arb_locked_lifecycle(),
    )
        .prop_map(|(to, genuine, other)| {
            let from = if genuine {
                to.previous().unwrap_or(LockedLifecycle::Claimed)
            } else {
                other
            };
            (from, to)
        })
}

proptest! {
    // Fewer cases than the default, because each one writes and re-reads a
    // real record and the writes are fsynced: at the default this block costs
    // five seconds to restate a rule that is *pure*. What the rule says is
    // covered exhaustively and for free by
    // `rewinding_a_snapshot_yields_the_one_before_it`; what these cases add is
    // that the store applies it, which does not need hundreds of them.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// An advance is exactly a rewind: the store accepts a lifecycle iff
    /// rewinding it yields the recorded one, and refuses the release phase
    /// whatever it rewinds to.
    ///
    /// This is the whole contract in one statement, over facts that vary
    /// independently of the phase — which is where the field-by-field guards
    /// this replaced kept leaving a gap.
    #[test]
    fn an_advance_is_exactly_a_rewind((from, to) in arb_advance()) {
        let (_dir, store, state) = locked_store(from.clone());
        let accepted = to.previous().as_ref() == Some(&from)
            && to.phase() != LockedPhase::ReleaseAttempted;

        let result = store.advance_locked(&state, to.clone());
        prop_assert_eq!(
            result.is_ok(),
            accepted,
            "{:?} -> {:?}",
            from.phase(),
            to.phase()
        );
        if accepted {
            let reloaded = store.load(state.session_id()).unwrap();
            prop_assert_eq!(reloaded.lifecycle(), &SessionLifecycle::Locked(to));
        } else {
            prop_assert_eq!(store.load(state.session_id()).unwrap(), state);
        }
    }
}

/// The generator reaches both answers, so the property above is not vacuous
/// on either side.
#[test]
fn the_advance_generator_reaches_both_answers() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let mut accepted = 0usize;
    let mut refused = 0usize;
    for _ in 0..256 {
        let (from, to) = arb_advance().new_tree(&mut runner).unwrap().current();
        if to.previous().as_ref() == Some(&from) && to.phase() != LockedPhase::ReleaseAttempted {
            accepted += 1;
        } else {
            refused += 1;
        }
    }
    assert!(
        accepted >= 20,
        "only {accepted} of 256 advances were accepted"
    );
    assert!(refused >= 20, "only {refused} of 256 advances were refused");
}
