//! Example/edge-case tests for the persistent session-state store:
//! the managed start/stop lifecycle, atomic record handling, lock
//! semantics, corruption rejection, default state-dir resolution and
//! file permissions.
use super::state_store::default_agent_vm_state_dir_from_env;
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
fn vm_placement_start_failure_rolls_back_the_agent_vm_only() {
    // Drives the *real* rollback path (not just the planned-cleanup helper): in
    // vm mode a StartVm failure must remove the agent VM only and never touch the
    // broker-owned shared network or host PF.
    let dir = tempfile::tempdir().unwrap();
    let store = AgentVmSessionStateStore::new(dir.path().join("state"));
    let log = dir.path().join("argv.log");
    let marker = dir.path().join("vm-exists");
    // A stateful fake container: StartVm (`run`) creates the VM then fails;
    // removal commands delete it; `list` reports it present iff the marker
    // exists. This lets the real cleanup loop (probe → remove → probe) run the
    // removal and then observe absence, i.e. a clean rollback.
    let tool = write_executable_script(
        dir.path(),
        "fail-startvm",
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{log}\"\n\
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
    // No network/PF provisioning start steps in vm mode...
    assert!(!argv.contains("network create"), "{argv}");
    assert!(!argv.contains("network inspect"), "{argv}");
    assert!(!argv.contains("install"), "{argv}"); // pf-helper install
    // ...StartVm was attempted (and failed)...
    assert!(argv.contains("run "), "{argv}");
    // ...and rollback removed the agent VM only, not the broker-owned net/PF.
    assert!(argv.contains("rm -f writ-agent-vm-"), "{argv}");
    assert!(!argv.contains("network rm"), "{argv}");
    assert!(!argv.contains("network delete"), "{argv}");
    assert!(!argv.contains("remove"), "{argv}"); // pf-helper remove
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

#[test]
fn default_state_dir_treats_empty_xdg_as_unset_and_uses_home() {
    let got = default_agent_vm_state_dir_from_env(
        Some(OsString::from("")),
        Some(OsString::from("/Users/example")),
    )
    .unwrap();
    assert_eq!(
        got,
        PathBuf::from("/Users/example/.local/state/writ/agent-vm-sessions")
    );
}

#[test]
fn default_state_dir_fails_when_home_is_unset_or_empty() {
    assert_eq!(
        default_agent_vm_state_dir_from_env(None, None),
        Err(AgentVmStateDirError::HomeUnset)
    );
    assert_eq!(
        default_agent_vm_state_dir_from_env(None, Some(OsString::from(""))),
        Err(AgentVmStateDirError::HomeUnset)
    );
}

#[test]
fn default_state_dir_rejects_relative_environment_paths() {
    assert_eq!(
        default_agent_vm_state_dir_from_env(
            Some(OsString::from("relative/state")),
            Some(OsString::from("/Users/example")),
        ),
        Err(AgentVmStateDirError::XdgStateHomeRelative {
            path: PathBuf::from("relative/state")
        })
    );
    assert_eq!(
        default_agent_vm_state_dir_from_env(None, Some(OsString::from("relative/home"))),
        Err(AgentVmStateDirError::HomeRelative {
            path: PathBuf::from("relative/home")
        })
    );
}

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
