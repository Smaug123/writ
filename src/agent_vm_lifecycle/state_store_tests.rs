//! Example/edge-case tests for the persistent session-state store:
//! the managed start/stop lifecycle, atomic record handling, lock
//! semantics, corruption rejection, default state-dir resolution and
//! file permissions.
use super::test_support::*;
use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn cleanup_error() -> ProcessInvocationError {
    ProcessInvocationError::ResourceStillPresent {
        program: "container".into(),
        args: "network list --quiet".into(),
        message: "network still appears in list".into(),
    }
}

fn start_process_error() -> StartFailure {
    StartFailure::Process(ProcessInvocationError::Run {
        program: "container".into(),
        args: "network create".into(),
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
    })
}

#[cfg(unix)]
fn write_executable_script(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, contents).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

#[test]
fn managed_start_preserves_state_when_partial_start_cleanup_failed() {
    let error = AgentVmLifecycleRunError::CleanupAfterFailure {
        original: Box::new(start_process_error()),
        cleanup: Box::new(CleanupErrors::new(vec![cleanup_error()])),
    };
    assert!(start_failure_left_dirty_infrastructure(&error));

    let clean_error = AgentVmLifecycleRunError::Start(Box::new(start_process_error()));
    assert!(!start_failure_left_dirty_infrastructure(&clean_error));
}

#[test]
fn managed_stop_failure_leaves_state_record_for_retry() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path());
    let plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    let starting = store.create_starting(&plan).unwrap();
    let running = store.mark_running(&starting).unwrap();
    let missing_tool = dir.path().join("missing-tool");

    let err = stop_managed_agent_vm_session(
        &store,
        plan.session_id(),
        AgentVmToolPaths::new(&missing_tool, &missing_tool, &missing_tool),
    )
    .unwrap_err();
    assert!(matches!(err, AgentVmSessionManagerError::Stop(_)));
    assert_eq!(store.load(plan.session_id()).unwrap(), running);
}

#[cfg(unix)]
#[test]
fn managed_cleanup_success_preserves_state_until_explicit_remove() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let ok_tool = write_executable_script(dir.path(), "ok-tool", "#!/bin/sh\nexit 0\n");
    let plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    let starting = store.create_starting(&plan).unwrap();
    let running = store.mark_running(&starting).unwrap();

    cleanup_managed_agent_vm_session(
        &store,
        plan.session_id(),
        AgentVmToolPaths::new(&ok_tool, &ok_tool, &ok_tool),
    )
    .unwrap();
    assert_eq!(store.load(plan.session_id()).unwrap(), running);

    remove_managed_agent_vm_session_state(&store, plan.session_id()).unwrap();
    let missing = store.load(plan.session_id()).unwrap_err();
    assert!(matches!(missing, AgentVmSessionStateError::NotFound { .. }));
}

#[cfg(unix)]
#[test]
fn managed_cleanup_of_a_vm_session_tears_down_the_broker_vm() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let plan = plan_with_broker_placement(252, BrokerPlacement::Vm);
    let id = plan.session_id();
    // A *stateful* fake container/sudo: `list`/`network list` report a resource as
    // present until `rm`/`network rm` marks it removed, so the absence-based
    // cleanup observes each resource present, removes it, then probes it gone —
    // exactly the agent VM/network cleanup contract. Pure POSIX shell (markers via
    // `: >`, no external commands), so it runs in the no-/bin/rm Nix sandbox too.
    let state = dir.path().join("fakestate");
    fs::create_dir_all(state.join("vm")).unwrap();
    fs::create_dir_all(state.join("net")).unwrap();
    fs::create_dir_all(state.join("removed")).unwrap();
    for vm in [
        format!("writ-agent-vm-{id}"),
        format!("writ-broker-vm-{id}"),
    ] {
        fs::write(state.join("vm").join(&vm), b"").unwrap();
    }
    for net in [
        format!("writ-broker-egress-{id}"),
        format!("writ-agent-net-{id}"),
    ] {
        fs::write(state.join("net").join(&net), b"").unwrap();
    }
    let tool = write_executable_script(
        dir.path(),
        "fake-container",
        &format!(
            "#!/bin/sh\n\
             S={state}\n\
             if [ \"$1\" = list ]; then for f in \"$S\"/vm/*; do [ -e \"$f\" ] || continue; n=\"${{f##*/}}\"; [ -e \"$S/removed/$n\" ] || echo \"$n\"; done; exit 0; fi\n\
             if [ \"$1\" = network ] && [ \"$2\" = list ]; then for f in \"$S\"/net/*; do [ -e \"$f\" ] || continue; n=\"${{f##*/}}\"; [ -e \"$S/removed/$n\" ] || echo \"$n\"; done; exit 0; fi\n\
             if [ \"$1\" = network ] && [ \"$2\" = rm ]; then : > \"$S/removed/$3\"; exit 0; fi\n\
             if [ \"$1\" = rm ] || [ \"$1\" = stop ] || [ \"$1\" = delete ]; then for a in \"$@\"; do n=\"$a\"; done; : > \"$S/removed/$n\"; exit 0; fi\n\
             exit 0\n",
            state = state.display(),
        ),
    );
    let starting = store.create_starting(&plan).unwrap();
    store.mark_running(&starting).unwrap();

    cleanup_managed_agent_vm_session(
        &store,
        plan.session_id(),
        AgentVmToolPaths::new(&tool, &tool, &tool),
    )
    .unwrap();

    // Cleanup succeeding already means the absence probes confirmed each broker
    // resource gone; assert each was actually issued a removal (its removed-marker
    // exists): the broker VM, its egress network, and the shared internal network.
    for removed in [
        format!("writ-broker-vm-{id}"),
        format!("writ-broker-egress-{id}"),
        format!("writ-agent-net-{id}"),
    ] {
        assert!(
            state.join("removed").join(&removed).exists(),
            "broker resource not torn down: {removed}"
        );
    }
}

#[cfg(unix)]
#[test]
fn managed_cleanup_of_a_vm_session_is_idempotent_when_resources_already_absent() {
    // The retry / already-torn-down case Apple Container removals make real: every
    // resource reports absent (empty list), so cleanup must succeed without ever
    // treating an already-gone broker resource as a fatal error.
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let tool = write_executable_script(dir.path(), "fake-container", "#!/bin/sh\nexit 0\n");
    let plan = plan_with_broker_placement(252, BrokerPlacement::Vm);
    let starting = store.create_starting(&plan).unwrap();
    store.mark_running(&starting).unwrap();

    cleanup_managed_agent_vm_session(
        &store,
        plan.session_id(),
        AgentVmToolPaths::new(&tool, &tool, &tool),
    )
    .expect("already-absent broker resources must not fail the stop");
}

#[cfg(unix)]
#[test]
fn managed_cleanup_of_a_host_session_runs_no_broker_teardown() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let log = dir.path().join("argv.log");
    let tool = write_executable_script(
        dir.path(),
        "fake-container",
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\nexit 0\n",
            log.display()
        ),
    );
    let plan = plan_with_broker_placement(252, BrokerPlacement::Host);
    let starting = store.create_starting(&plan).unwrap();
    store.mark_running(&starting).unwrap();

    cleanup_managed_agent_vm_session(
        &store,
        plan.session_id(),
        AgentVmToolPaths::new(&tool, &tool, &tool),
    )
    .unwrap();

    let logged = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !logged.contains("writ-broker-vm-"),
        "host placement must run no broker VM teardown:\n{logged}"
    );
}

#[cfg(unix)]
#[test]
fn managed_start_then_managed_stop_success_removes_state_record() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let ok_tool = write_executable_script(
        dir.path(),
        "ok-tool",
        "#!/bin/sh\n\
         if [ \"$1\" = \"network\" ] && [ \"$2\" = \"inspect\" ]; then\n\
         printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
         fi\n\
         exit 0\n",
    );
    let base_plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    let plan = AgentVmSessionPlan::new(
        base_plan.session_id(),
        base_plan.pool,
        base_plan.subnet_index(),
        base_plan.broker_ports.clone(),
        base_plan.broker_port_range,
        base_plan.ipv6_mode(),
        base_plan.image.clone(),
        base_plan.guest_command.clone(),
        base_plan.resources,
        AgentVmToolPaths::new(&ok_tool, &ok_tool, &ok_tool),
    )
    .unwrap();

    let running = start_managed_agent_vm_session(&store, &plan).unwrap();
    assert_eq!(running.status(), AgentVmSessionStateStatus::Running);
    stop_managed_agent_vm_session(
        &store,
        plan.session_id(),
        AgentVmToolPaths::new(&ok_tool, &ok_tool, &ok_tool),
    )
    .unwrap();

    let missing = store.load(plan.session_id()).unwrap_err();
    assert!(matches!(missing, AgentVmSessionStateError::NotFound { .. }));
}

#[cfg(unix)]
#[test]
fn ipv4_only_start_reinstalls_firewall_with_guest_ipv6_deny_after_vm_start() {
    // Drives the *real* post-start path: after StartVm, the runner re-invokes the
    // pf-helper with `--deny-guest-ipv6` so the privileged helper discovers the
    // bridge itself and installs the interface-scoped IPv6 deny. (The fake helper
    // here only records that it was asked; the discovery logic is covered by the
    // pf-helper's own tests and the real-hardware prove script.)
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let log = dir.path().join("argv.log");
    let tool = write_executable_script(
        dir.path(),
        "logging-tool",
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{log}\"\n\
             if [ \"$1\" = \"network\" ] && [ \"$2\" = \"inspect\" ]; then\n\
             printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
             fi\n\
             exit 0\n",
            log = log.display(),
        ),
    );
    let base_plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    let plan = AgentVmSessionPlan::new(
        base_plan.session_id(),
        base_plan.pool,
        base_plan.subnet_index(),
        base_plan.broker_ports.clone(),
        base_plan.broker_port_range,
        base_plan.ipv6_mode(),
        base_plan.image.clone(),
        base_plan.guest_command.clone(),
        base_plan.resources,
        AgentVmToolPaths::new(&tool, &tool, &tool),
    )
    .unwrap();

    start_managed_agent_vm_session(&store, &plan).unwrap();

    let logged = std::fs::read_to_string(&log).unwrap();
    // Exactly one pf-helper install requests the guest-IPv6 deny (the post-start
    // re-install), and it points the helper at ifconfig for discovery.
    let deny_installs: Vec<&str> = logged
        .lines()
        .filter(|l| l.contains(" install ") && l.contains("--deny-guest-ipv6"))
        .collect();
    assert_eq!(deny_installs.len(), 1, "log:\n{logged}");
    // The runner passes no discovery tool path — the helper uses a fixed one.
    assert!(
        !deny_installs[0].contains("--ifconfig"),
        "{}",
        deny_installs[0]
    );
    // A pre-start install (no guest-IPv6 deny) precedes it: the v4 rules are up
    // before the VM boots.
    assert!(
        logged
            .lines()
            .any(|l| l.contains(" install ") && !l.contains("--deny-guest-ipv6")),
        "log:\n{logged}"
    );
}

#[cfg(unix)]
#[test]
fn vm_placement_start_failure_rolls_back_the_agent_vm_and_pf_not_the_network() {
    // Drives the *real* rollback path: in vm mode a StartVm failure removes the
    // agent VM and its host PF anchor, but never the broker-owned shared network.
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let log = dir.path().join("argv.log");
    let marker = dir.path().join("vm-exists");
    // A stateful fake container/sudo/pf-helper: `network inspect` reports the
    // shared subnet (so InspectAndValidate passes); StartVm (`run`) creates the
    // VM then fails; removal commands delete it; `list` reports it present iff the
    // marker exists, so the real cleanup loop runs the removal then sees absence.
    let tool = write_executable_script(
        dir.path(),
        "fail-startvm",
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{log}\"\n\
             if [ \"$1\" = network ] && [ \"$2\" = inspect ]; then\n\
             printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'\n\
             exit 0\n\
             fi\n\
             case \"$1\" in\n\
             run) touch \"{marker}\"; exit 1 ;;\n\
             rm|stop|delete) rm -f \"{marker}\"; exit 0 ;;\n\
             list) [ -f \"{marker}\" ] && printf '%s\\n' \"writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d\"; exit 0 ;;\n\
             *) exit 0 ;;\n\
             esac\n",
            log = log.display(),
            marker = marker.display(),
        ),
    );
    let plan = AgentVmSessionPlan::new_with_guest_env(
        session_id(),
        pool(),
        252,
        ports(),
        BrokerPortRange::new(49152, 65535).unwrap(),
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
        BrokerPlacement::Vm,
        ContainerImage::new("writ-broker-vm:latest").unwrap(),
        Vec::new(),
        vec!["sleep".into(), "600".into()],
        AgentVmResources::new(1, 512).unwrap(),
        AgentVmToolPaths::new(&tool, &tool, &tool),
    )
    .unwrap();

    let err = start_managed_agent_vm_session(&store, &plan).unwrap_err();
    // Clean rollback: the StartVm failure surfaces directly, not as a
    // CleanupAfterFailure (which is what a wrong full-stop cleanup would cause).
    assert!(
        matches!(
            err,
            AgentVmSessionManagerError::Start(AgentVmLifecycleRunError::Start(_))
        ),
        "{err:?}"
    );

    let argv = std::fs::read_to_string(&log).unwrap();
    // vm inspects and PF-installs (host protection), but does not create the
    // network (the broker arm did)...
    assert!(argv.contains("network inspect"), "{argv}");
    assert!(argv.contains("install"), "{argv}"); // pf-helper install
    assert!(!argv.contains("network create"), "{argv}");
    // ...StartVm was attempted (and failed)...
    assert!(argv.contains("run "), "{argv}");
    // ...and rollback removed the agent VM and the PF anchor, but not the
    // broker-owned network.
    assert!(argv.contains("rm -f writ-agent-vm-"), "{argv}");
    assert!(argv.contains("remove"), "{argv}"); // pf-helper remove
    assert!(!argv.contains("network rm"), "{argv}");
    assert!(!argv.contains("network delete"), "{argv}");
}

#[cfg(unix)]
#[test]
fn host_placement_start_tears_down_a_network_that_create_left_behind_on_failure() {
    // A `container network create` that registers the network and *then* exits
    // nonzero must not orphan it: managed start must tear the network down even
    // though the create command reported failure. Regression for the "failed
    // commands are assumed to have left no residue" gap — the teardown is
    // idempotent and absence-based, so tearing down a maybe-created resource is
    // always safe, and leaving it stranded would let a reused subnet collide with
    // an orphaned network after the recovery record is dropped.
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let log = dir.path().join("argv.log");
    let marker = dir.path().join("network-exists");
    let network_name = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6)
        .names()
        .network()
        .to_string();
    // A stateful fake `container`: `network create` registers the network then
    // fails; `network rm`/`delete` deregister it; `network list` reports it
    // present iff the marker exists, so the absence-based cleanup runs the removal
    // then observes it gone.
    let tool = write_executable_script(
        dir.path(),
        "create-fails-dirty",
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{log}\"\n\
             if [ \"$1\" = network ] && [ \"$2\" = create ]; then touch \"{marker}\"; exit 1; fi\n\
             if [ \"$1\" = network ] && [ \"$2\" = rm ]; then rm -f \"{marker}\"; exit 0; fi\n\
             if [ \"$1\" = network ] && [ \"$2\" = delete ]; then rm -f \"{marker}\"; exit 0; fi\n\
             if [ \"$1\" = network ] && [ \"$2\" = list ]; then [ -f \"{marker}\" ] && printf '%s\\n' \"{network}\"; exit 0; fi\n\
             exit 0\n",
            log = log.display(),
            marker = marker.display(),
            network = network_name,
        ),
    );
    let plan = AgentVmSessionPlan::new(
        session_id(),
        pool(),
        252,
        ports(),
        BrokerPortRange::new(49152, 65535).unwrap(),
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
        ContainerImage::new("alpine:latest").unwrap(),
        vec!["sleep".into(), "600".into()],
        AgentVmResources::new(1, 512).unwrap(),
        AgentVmToolPaths::new(&tool, &tool, &tool),
    )
    .unwrap();

    let err = start_managed_agent_vm_session(&store, &plan).unwrap_err();

    // Cleanup succeeded (the stranded network was torn down), so the failure
    // surfaces as a plain Start error, not CleanupAfterFailure.
    assert!(
        matches!(
            err,
            AgentVmSessionManagerError::Start(AgentVmLifecycleRunError::Start(_))
        ),
        "{err:?}"
    );

    // The create command left a network behind; managed start must have removed
    // it rather than trusting the nonzero exit to mean nothing was created.
    let argv = fs::read_to_string(&log).unwrap();
    assert!(argv.contains("network create"), "{argv}");
    assert!(argv.contains("network rm"), "{argv}");
    assert!(
        !marker.exists(),
        "create left a network behind that managed start failed to tear down:\n{argv}"
    );

    // With the orphan cleaned, dropping the recovery record is correct.
    let missing = store.load(plan.session_id()).unwrap_err();
    assert!(matches!(missing, AgentVmSessionStateError::NotFound { .. }));
}

#[cfg(unix)]
#[test]
fn host_placement_start_drops_the_record_when_the_tool_cannot_spawn() {
    // A missing / non-executable container tool fails to *spawn* (the pre-create
    // probe is the first command to run, so it fails first). Nothing was created,
    // so no infrastructure exists to recover and cleanup would only route through
    // the same unavailable binary. Managed start must therefore drop the recovery
    // record and free the subnet rather than retaining a spurious Starting claim
    // that repeated attempts would use to exhaust the pool.
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let missing_tool = dir.path().join("definitely-not-a-real-tool");
    let plan = AgentVmSessionPlan::new(
        session_id(),
        pool(),
        252,
        ports(),
        BrokerPortRange::new(49152, 65535).unwrap(),
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
        ContainerImage::new("alpine:latest").unwrap(),
        vec!["sleep".into(), "600".into()],
        AgentVmResources::new(1, 512).unwrap(),
        AgentVmToolPaths::new(&missing_tool, &missing_tool, &missing_tool),
    )
    .unwrap();

    let err = start_managed_agent_vm_session(&store, &plan).unwrap_err();

    // Nothing ran to completion, so the failure is a plain Start error, not a
    // CleanupAfterFailure (which would strand the record).
    assert!(
        matches!(
            err,
            AgentVmSessionManagerError::Start(AgentVmLifecycleRunError::Start(_))
        ),
        "{err:?}"
    );
    let missing = store.load(plan.session_id()).unwrap_err();
    assert!(
        matches!(missing, AgentVmSessionStateError::NotFound { .. }),
        "a spawn failure that created nothing must not leave a subnet-claiming record"
    );
}

#[cfg(unix)]
#[test]
fn host_placement_start_refuses_and_removes_nothing_when_the_network_predates_it() {
    // A network already bearing this session's name (another owner, another
    // --state-dir, or a leak) must not be torn down by a start that did not
    // create it. The CreateNetwork step probes first, and on finding it present
    // refuses without issuing any removal.
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let log = dir.path().join("argv.log");
    let network_name = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6)
        .names()
        .network()
        .to_string();
    // Fake container: `network list` always reports the network present (it
    // predates us); everything else logs and succeeds.
    let tool = write_executable_script(
        dir.path(),
        "network-predates",
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{log}\"\n\
             if [ \"$1\" = network ] && [ \"$2\" = list ]; then printf '%s\\n' \"{network}\"; exit 0; fi\n\
             exit 0\n",
            log = log.display(),
            network = network_name,
        ),
    );
    let plan = AgentVmSessionPlan::new(
        session_id(),
        pool(),
        252,
        ports(),
        BrokerPortRange::new(49152, 65535).unwrap(),
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
        ContainerImage::new("alpine:latest").unwrap(),
        vec!["sleep".into(), "600".into()],
        AgentVmResources::new(1, 512).unwrap(),
        AgentVmToolPaths::new(&tool, &tool, &tool),
    )
    .unwrap();

    let err = start_managed_agent_vm_session(&store, &plan).unwrap_err();
    assert!(
        matches!(
            err,
            AgentVmSessionManagerError::Start(AgentVmLifecycleRunError::Start(ref start))
                if matches!(**start, StartFailure::NetworkAlreadyPresent { .. })
        ),
        "{err:?}"
    );

    // Never created the network, and — crucially — never tried to remove it.
    let argv = fs::read_to_string(&log).unwrap();
    assert!(!argv.contains("network create"), "{argv}");
    assert!(!argv.contains("network rm"), "{argv}");
    assert!(!argv.contains("network delete"), "{argv}");

    // No infrastructure was created, so no recovery record is retained.
    let missing = store.load(plan.session_id()).unwrap_err();
    assert!(matches!(missing, AgentVmSessionStateError::NotFound { .. }));
}

#[cfg(unix)]
#[test]
fn host_placement_start_removes_nothing_when_the_pre_create_probe_fails() {
    // If the existence probe itself fails (here `network list` exits nonzero),
    // create was never attempted, so nothing is ours: the start must refuse and
    // issue no network removal, and must not strand a recovery record.
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let log = dir.path().join("argv.log");
    // Fake container: `network list` fails (nonzero, a `Failed` process error —
    // not a spawn failure); anything else logs and succeeds.
    let tool = write_executable_script(
        dir.path(),
        "probe-fails",
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{log}\"\n\
             if [ \"$1\" = network ] && [ \"$2\" = list ]; then echo 'boom' >&2; exit 1; fi\n\
             exit 0\n",
            log = log.display(),
        ),
    );
    let plan = AgentVmSessionPlan::new(
        session_id(),
        pool(),
        252,
        ports(),
        BrokerPortRange::new(49152, 65535).unwrap(),
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
        ContainerImage::new("alpine:latest").unwrap(),
        vec!["sleep".into(), "600".into()],
        AgentVmResources::new(1, 512).unwrap(),
        AgentVmToolPaths::new(&tool, &tool, &tool),
    )
    .unwrap();

    let err = start_managed_agent_vm_session(&store, &plan).unwrap_err();
    assert!(
        matches!(
            err,
            AgentVmSessionManagerError::Start(AgentVmLifecycleRunError::Start(ref start))
                if matches!(**start, StartFailure::NetworkPresenceProbeFailed { .. })
        ),
        "{err:?}"
    );

    let argv = fs::read_to_string(&log).unwrap();
    assert!(!argv.contains("network create"), "{argv}");
    assert!(!argv.contains("network rm"), "{argv}");
    assert!(!argv.contains("network delete"), "{argv}");

    let missing = store.load(plan.session_id()).unwrap_err();
    assert!(matches!(missing, AgentVmSessionStateError::NotFound { .. }));
}

#[cfg(unix)]
#[test]
fn host_placement_start_refuses_and_removes_no_vm_when_the_agent_vm_predates_it() {
    // An agent VM already bearing this session's name (another owner / --state-dir)
    // must not be torn down by a start that did not create it. The ProbeVmAbsent
    // step (after the network + PF are created) finds it present and refuses,
    // cleaning back the network + PF it *did* create but never touching the VM.
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let log = dir.path().join("argv.log");
    let marker = dir.path().join("network-exists");
    let network_name = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6)
        .names()
        .network()
        .to_string();
    let vm_name = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6)
        .names()
        .vm()
        .to_string();
    // Fake container/sudo: `network list` reports the network present iff the
    // create marker exists (so the pre-create probe sees absent, then create
    // registers it, and cleanup can remove it); `list` (VM probe) always reports
    // the agent VM present; `network inspect` reports the subnet; everything logs.
    let tool = write_executable_script(
        dir.path(),
        "vm-predates",
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{log}\"\n\
             if [ \"$1\" = network ] && [ \"$2\" = list ]; then [ -f \"{marker}\" ] && printf '%s\\n' \"{network}\"; exit 0; fi\n\
             if [ \"$1\" = network ] && [ \"$2\" = create ]; then touch \"{marker}\"; exit 0; fi\n\
             if [ \"$1\" = network ] && [ \"$2\" = rm ]; then rm -f \"{marker}\"; exit 0; fi\n\
             if [ \"$1\" = network ] && [ \"$2\" = delete ]; then rm -f \"{marker}\"; exit 0; fi\n\
             if [ \"$1\" = network ] && [ \"$2\" = inspect ]; then printf '%s\\n' 'ipv4Subnet: 192.168.252.0/24' 'ipv4Gateway: 192.168.252.1'; exit 0; fi\n\
             if [ \"$1\" = list ]; then printf '%s\\n' \"{vm}\"; exit 0; fi\n\
             exit 0\n",
            log = log.display(),
            marker = marker.display(),
            network = network_name,
            vm = vm_name,
        ),
    );
    let plan = AgentVmSessionPlan::new(
        session_id(),
        pool(),
        252,
        ports(),
        BrokerPortRange::new(49152, 65535).unwrap(),
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
        ContainerImage::new("alpine:latest").unwrap(),
        vec!["sleep".into(), "600".into()],
        AgentVmResources::new(1, 512).unwrap(),
        AgentVmToolPaths::new(&tool, &tool, &tool),
    )
    .unwrap();

    let err = start_managed_agent_vm_session(&store, &plan).unwrap_err();
    assert!(
        matches!(
            err,
            AgentVmSessionManagerError::Start(AgentVmLifecycleRunError::Start(ref start))
                if matches!(**start, StartFailure::VmAlreadyPresent { .. })
        ),
        "{err:?}"
    );

    let argv = fs::read_to_string(&log).unwrap();
    // Never ran the VM, and never tried to remove it (no `rm -f <vm>` etc.).
    assert!(!argv.contains("run "), "{argv}");
    assert!(!argv.contains(&format!("rm -f {vm_name}")), "{argv}");
    assert!(!argv.contains(&format!("delete {vm_name}")), "{argv}");
    // But it did clean the network it created.
    assert!(argv.contains("network rm"), "{argv}");

    let missing = store.load(plan.session_id()).unwrap_err();
    assert!(matches!(missing, AgentVmSessionStateError::NotFound { .. }));
}

#[test]
fn a_creating_command_that_never_spawned_is_demoted_below_its_own_resource() {
    // A spawn failure (`Run`) proves the command never executed, so it created
    // nothing: demote below its own resource so cleanup does not route through the
    // now-missing tool and strand a record. A post-spawn wait failure or a nonzero
    // exit may have created the resource, so those keep the outcome's phase.
    let create_spawn = StartFailure::Process(ProcessInvocationError::Run {
        program: "container".into(),
        args: "network create".into(),
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
    });
    assert_eq!(
        cleanup_phase_for_failure(StartOutcome::CreateNetworkFailed, &create_spawn),
        None
    );

    let run_spawn = StartFailure::Process(ProcessInvocationError::Run {
        program: "container".into(),
        args: "run".into(),
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
    });
    assert_eq!(
        cleanup_phase_for_failure(StartOutcome::StartVmFailed, &run_spawn),
        Some(CompletedStartStep::FirewallInstalled)
    );

    // A firewall install that never spawned loaded no anchor: only the network is
    // ours (demoted from FirewallInstalled to NetworkCreated).
    let install_spawn = StartFailure::Process(ProcessInvocationError::Run {
        program: "sudo".into(),
        args: "writ-agent-vm-pf-helper install".into(),
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
    });
    assert_eq!(
        cleanup_phase_for_failure(StartOutcome::InstallFirewallFailed, &install_spawn),
        Some(CompletedStartStep::NetworkCreated)
    );
    // A firewall install that ran but failed may have loaded the anchor → keep the
    // FirewallInstalled phase.
    let install_nonzero = StartFailure::Process(ProcessInvocationError::Failed {
        program: "sudo".into(),
        args: "writ-agent-vm-pf-helper install".into(),
        status: "1".into(),
        stderr: String::new(),
    });
    assert_eq!(
        cleanup_phase_for_failure(StartOutcome::InstallFirewallFailed, &install_nonzero),
        Some(CompletedStartStep::FirewallInstalled)
    );

    // Wait failure and nonzero exit both keep the outcome's phase (maybe created).
    let create_wait = StartFailure::Process(ProcessInvocationError::WaitOutput {
        program: "container".into(),
        args: "network create".into(),
        source: std::io::Error::from(std::io::ErrorKind::BrokenPipe),
    });
    assert_eq!(
        cleanup_phase_for_failure(StartOutcome::CreateNetworkFailed, &create_wait),
        Some(CompletedStartStep::NetworkCreated)
    );
    let run_nonzero = StartFailure::Process(ProcessInvocationError::Failed {
        program: "container".into(),
        args: "run".into(),
        status: "1".into(),
        stderr: String::new(),
    });
    assert_eq!(
        cleanup_phase_for_failure(StartOutcome::StartVmFailed, &run_nonzero),
        Some(CompletedStartStep::VmStarted)
    );
}

#[test]
fn outcome_maps_to_the_phase_that_reflects_what_exists() {
    // The absence-probe outcomes clean nothing of their own resource: the network
    // probe runs first (nothing exists yet), the VM probe runs after the network
    // and PF are ours (so it cleans those but not the foreign VM). A create /
    // inspect failure cleans the network; a firewall-install failure (may have
    // loaded the anchor) cleans network + PF; a VM-start or later failure cleans
    // everything.
    use StartOutcome::*;
    assert_eq!(
        cleanup_step_after_start_outcome(NetworkAbsenceProbeFailed),
        None
    );
    for network_phase in [
        CreateNetworkFailed,
        InspectNetworkFailed,
        ParseNetworkInspectionFailed,
        ValidateNetworkInspectionFailed,
    ] {
        assert_eq!(
            cleanup_step_after_start_outcome(network_phase),
            Some(CompletedStartStep::NetworkCreated),
            "{network_phase:?}"
        );
    }
    for firewall_phase in [InstallFirewallFailed, VmAbsenceProbeFailed] {
        assert_eq!(
            cleanup_step_after_start_outcome(firewall_phase),
            Some(CompletedStartStep::FirewallInstalled),
            "{firewall_phase:?}"
        );
    }
    for vm_phase in [
        StartVmFailed,
        ProbeGuestIpv6Failed,
        ValidateGuestIpv6Failed,
        ReleaseGuestCommandFailed,
    ] {
        assert_eq!(
            cleanup_step_after_start_outcome(vm_phase),
            Some(CompletedStartStep::VmStarted),
            "{vm_phase:?}"
        );
    }
}

#[test]
fn vm_placement_persists_and_stop_removes_the_agent_vm_and_pf_not_the_network() {
    // The placement survives the persisted record, so a later managed stop /
    // reconcile (which rebuilds the stop plan from state) removes the agent VM
    // and its host PF anchor — but not the broker-owned network.
    let plan = plan_with_broker_placement(252, BrokerPlacement::Vm);
    let state = AgentVmSessionState::from_start_plan(&plan, AgentVmSessionStateStatus::Running);
    let restored = AgentVmSessionState::from_json_bytes(&state.to_json_bytes().unwrap()).unwrap();
    assert_eq!(restored, state, "broker_placement must round-trip");

    let tools = AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo");
    let stop = restored.to_stop_plan(tools).stop_invocations();
    assert!(
        stop.iter()
            .any(|inv| inv.args_lossy().starts_with(&["rm".into(), "-f".into()])),
        "vm stop must remove the agent VM: {stop:?}"
    );
    assert!(
        stop.iter().any(|inv| inv
            .args_lossy()
            .contains(&"writ-agent-vm-pf-helper".to_string())),
        "vm stop must remove host PF: {stop:?}"
    );
    assert!(
        !stop
            .iter()
            .any(|inv| inv.args_lossy().first().map(String::as_str) == Some("network")),
        "vm stop must not remove the broker-owned network: {stop:?}"
    );
}

#[test]
fn pre_placement_record_loads_as_host_and_stops_network_and_pf() {
    // A version-2 record written before broker_placement existed must default to
    // Host (serde default) and still tear down the network + PF.
    let plan = plan_with_broker_placement(252, BrokerPlacement::Host);
    let state = AgentVmSessionState::from_start_plan(&plan, AgentVmSessionStateStatus::Running);
    let mut json: serde_json::Value =
        serde_json::from_slice(&state.to_json_bytes().unwrap()).unwrap();
    json.as_object_mut().unwrap().remove("broker_placement");
    let restored =
        AgentVmSessionState::from_json_bytes(&serde_json::to_vec(&json).unwrap()).unwrap();
    assert_eq!(restored, state, "absent broker_placement must load as Host");

    let tools = AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo");
    let stop = restored.to_stop_plan(tools).stop_invocations();
    assert!(
        stop.iter()
            .any(|inv| inv.args_lossy().first().map(String::as_str) == Some("network")),
        "host record must still remove the network: {stop:?}"
    );
}

#[test]
fn mark_running_does_not_recreate_removed_starting_record() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path());
    let plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    let starting = store.create_starting(&plan).unwrap();

    store.remove(plan.session_id()).unwrap();
    let err = store.mark_running(&starting).unwrap_err();

    assert!(matches!(err, AgentVmSessionStateError::NotFound { .. }));
    assert!(!store.path_for(plan.session_id()).exists());
}

#[test]
fn mark_running_rejects_changed_starting_record_as_state_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path());
    let plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    let starting = store.create_starting(&plan).unwrap();
    let already_running = store.mark_running(&starting).unwrap();

    let err = store.mark_running(&starting).unwrap_err();

    assert!(matches!(
        err,
        AgentVmSessionStateError::StateMismatch { session_id, .. }
            if session_id == plan.session_id()
    ));
    assert_eq!(store.load(plan.session_id()).unwrap(), already_running);
}

#[test]
fn state_store_rejects_duplicate_live_session_records() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path());
    let plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);

    let starting = store.create_starting(&plan).unwrap();
    assert_eq!(starting.status(), AgentVmSessionStateStatus::Starting);
    let duplicate = store.create_starting(&plan).unwrap_err();
    assert!(matches!(
        duplicate,
        AgentVmSessionStateError::AlreadyExists { .. }
    ));

    let running = store.mark_running(&starting).unwrap();
    assert_eq!(running.status(), AgentVmSessionStateStatus::Running);
    assert_eq!(store.load(plan.session_id()).unwrap(), running);

    store.remove(plan.session_id()).unwrap();
    let missing = store.load(plan.session_id()).unwrap_err();
    assert!(matches!(missing, AgentVmSessionStateError::NotFound { .. }));
}

#[test]
fn state_store_rejects_duplicate_live_subnet_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path());
    let first = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    let second = AgentVmSessionPlan::new(
        SessionId::from_uuid(Uuid::from_u128(first.session_id().as_uuid().as_u128() ^ 1)),
        pool(),
        first.subnet_index(),
        ports(),
        BrokerPortRange::new(49152, 65535).unwrap(),
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
        ContainerImage::new("alpine:latest").unwrap(),
        vec!["sleep".into(), "600".into()],
        AgentVmResources::new(1, 512).unwrap(),
        AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo"),
    )
    .unwrap();
    store.create_starting(&first).unwrap();

    let err = store.create_starting(&second).unwrap_err();

    assert!(matches!(
        err,
        AgentVmSessionStateError::SubnetIndexAlreadyAllocated {
            subnet_index: 252,
            existing_session_id,
            requested_session_id,
        } if existing_session_id == first.session_id()
            && requested_session_id == second.session_id()
    ));
}

#[test]
fn state_store_uses_one_store_lock_file_instead_of_per_session_lock_files() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path());
    for index in [1, 2, 3] {
        let plan = plan_with_ipv6_mode(index, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
        store.create_starting(&plan).unwrap();
        store.remove(plan.session_id()).unwrap();
    }

    let lock_files = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().ends_with(".lock"))
        .collect::<Vec<_>>();

    assert_eq!(lock_files, vec![OsString::from(".store.lock")]);
}

#[test]
fn state_store_load_missing_session_does_not_create_missing_store() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let store = AgentVmSessionStateStore::new(&state_dir);
    let session_id = session_id();

    let err = store.load(session_id).unwrap_err();

    assert!(matches!(err, AgentVmSessionStateError::NotFound { .. }));
    assert!(!state_dir.exists());
}

#[test]
fn state_store_load_missing_session_does_not_create_lock_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path());
    let session_id = session_id();

    let err = store.load(session_id).unwrap_err();

    assert!(matches!(err, AgentVmSessionStateError::NotFound { .. }));
    assert!(!dir.path().join(".store.lock").exists());
}

#[test]
fn state_store_load_all_accepts_existing_directory_before_first_write() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    fs::create_dir(&state_dir).unwrap();
    let store = AgentVmSessionStateStore::new(&state_dir);

    assert_eq!(store.load_all().unwrap(), Vec::new());
    assert!(state_dir.join(".store.lock").exists());
}

#[test]
fn state_store_rejects_record_whose_contents_do_not_match_filename_session() {
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path());
    let plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    let state = store.create_starting(&plan).unwrap();
    let requested =
        SessionId::from_uuid(Uuid::from_u128(state.session_id().as_uuid().as_u128() ^ 1));
    fs::write(store.path_for(requested), state.to_json_bytes().unwrap()).unwrap();

    let err = store.load(requested).unwrap_err();

    assert!(matches!(
        err,
        AgentVmSessionStateError::Corrupt { message }
            if message.contains("contains session")
    ));
}

#[cfg(unix)]
#[test]
fn state_store_lock_blocks_another_process() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("child-ready");
    let store = AgentVmSessionStateStore::new(dir.path());
    let lock = store.lock_store().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("state_store_child_lock_probe")
        .arg("--ignored")
        .env("WRIT_LOCK_PROBE_STATE_DIR", dir.path())
        .env("WRIT_LOCK_PROBE_MARKER", &marker)
        .spawn()
        .unwrap();

    wait_for_path(&marker);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(child.try_wait().unwrap().is_none());

    drop(lock);
    let status = wait_for_child(&mut child);
    assert!(status.success(), "child lock probe failed with {status}");
}

#[cfg(unix)]
#[test]
#[ignore]
fn state_store_child_lock_probe() {
    let Some(state_dir) = std::env::var_os("WRIT_LOCK_PROBE_STATE_DIR") else {
        return;
    };
    let Some(marker) = std::env::var_os("WRIT_LOCK_PROBE_MARKER") else {
        return;
    };
    fs::write(marker, b"ready").unwrap();
    let store = AgentVmSessionStateStore::new(PathBuf::from(state_dir));
    let plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);
    store.create_starting(&plan).unwrap();
}

#[cfg(unix)]
fn wait_for_path(path: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn wait_for_child(child: &mut std::process::Child) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            panic!("timed out waiting for child lock probe");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

// The three `default_state_dir_*` tests that stood here moved to
// `config::default_paths::tests` when this resolver was folded into the
// shared table: they asserted exactly the properties that now hold for every
// entry (empty means unset, relative is refused, an absent base is an error
// rather than a `/tmp` guess), and asserting them for this one location while
// the table quantifies over all of them would be the weaker of the two.

#[cfg(unix)]
#[test]
fn state_store_creates_private_directory_and_file_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let store = AgentVmSessionStateStore::new(&state_dir);
    let plan = plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6);

    store.create_starting(&plan).unwrap();

    let dir_mode = fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777;
    let file_mode = fs::metadata(store.path_for(plan.session_id()))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_eq!(file_mode, 0o600);
}
