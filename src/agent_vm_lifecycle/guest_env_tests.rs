//! Example/edge-case tests for guest environment variables
//! (redaction, shell-safety validation) and guest IPv6 posture
//! parsing/validation.
use super::test_support::*;
use super::*;

#[test]
fn guest_environment_is_redacted_and_uses_env_file_in_start_invocation() {
    let plan = AgentVmSessionPlan::new_with_guest_env(
        session_id(),
        pool(),
        252,
        ports(),
        BrokerPortRange::new(49152, 65535).unwrap(),
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
        BrokerPlacement::Host,
        ContainerImage::new("alpine:latest").unwrap(),
        vec![
            AgentVmGuestEnvVar::new("WRIT_BROKER_URL", "http://192.168.252.1:51375/").unwrap(),
            AgentVmGuestEnvVar::new("WRIT_BROKER_TOKEN", "writ-vm-secret").unwrap(),
        ],
        vec!["sleep".into(), "600".into()],
        AgentVmResources::new(1, 512).unwrap(),
        AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo"),
    )
    .unwrap();

    let debug = format!("{plan:?}");
    assert!(!debug.contains("writ-vm-secret"), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");

    let start_invocations = plan.start_invocations();
    let AgentVmStartInvocation::RuntimeGuestEnvFile {
        invocation,
        display_shell,
    } = &start_invocations[3]
    else {
        panic!("guest env should make VM start a runtime-env-file step");
    };
    let start = invocation.args_lossy();
    assert!(!start.iter().any(|arg| arg == "--env-file"));
    assert!(!start.iter().any(|arg| arg.contains("writ-vm-secret")));
    assert!(display_shell.contains("--env-file"));
    assert!(display_shell.contains(GUEST_ENV_FILE_DISPLAY));
    assert!(!display_shell.contains("writ-vm-secret"));
}

#[test]
fn guest_environment_rejects_shell_unsafe_names_and_env_file_breaking_values() {
    assert!(matches!(
        AgentVmGuestEnvVar::new("1BAD", "value"),
        Err(AgentVmLifecycleConfigError::InvalidGuestEnvNameStart(_))
    ));
    assert!(matches!(
        AgentVmGuestEnvVar::new("BAD-NAME", "value"),
        Err(AgentVmLifecycleConfigError::InvalidGuestEnvNameByte(_))
    ));
    assert!(matches!(
        AgentVmGuestEnvVar::new("GOOD_NAME", "line\nbreak"),
        Err(AgentVmLifecycleConfigError::InvalidGuestEnvValue { .. })
    ));
}

#[test]
fn guest_ipv6_posture_accepts_link_local_only() {
    let inspection = GuestIpv6Inspection::parse(
        r#"
        1: lo    inet6 ::1/128 scope host
        2: eth0    inet6 fe80::1234/64 scope link
        "#,
    )
    .unwrap();
    inspection.require_no_routable_ipv6().unwrap();
    assert_eq!(inspection.addresses().len(), 2);
    assert!(inspection.default_routes().is_empty());
}

#[test]
fn guest_ipv6_posture_rejects_global_scope_addresses_and_default_routes() {
    let address =
        GuestIpv6Inspection::parse("2: eth0    inet6 fd83:b6f2:e57:fc::2/64 scope global")
            .unwrap()
            .require_no_routable_ipv6()
            .unwrap_err();
    assert!(matches!(
        address,
        GuestIpv6InspectionError::NonLinkLocalAddress(addr)
            if addr == Ipv6Addr::from(0xfd83_b6f2_0e57_00fc_0000_0000_0000_0002u128)
    ));

    let route = GuestIpv6Inspection::parse("default via fe80::1 dev eth0 metric 1024")
        .unwrap()
        .require_no_routable_ipv6()
        .unwrap_err();
    assert!(matches!(route, GuestIpv6InspectionError::DefaultRoute(_)));
}

#[test]
fn guest_ipv6_posture_reports_missing_probe_tool() {
    assert_eq!(
        GuestIpv6Inspection::parse(GUEST_IPV6_PROBE_UNAVAILABLE_MARKER),
        Err(GuestIpv6InspectionError::ProbeToolUnavailable)
    );
}

#[test]
fn guest_ipv6_enforce_and_probe_script_disables_then_fails_closed_on_partial_probe_failure() {
    // `set -e` so a probe whose `ip` half partially fails aborts non-zero
    // (the runner then fails the start) rather than reporting an incomplete,
    // falsely-clean posture.
    assert!(GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT.starts_with("set -e\n"));
    // Enforce "no guest IPv6" before reporting: disable IPv6 in the guest
    // kernel (all + default), flushing any RA-acquired address, so a host
    // vmnet Router Advertisement cannot leave the guest with a routable ULA.
    assert!(GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT.contains("conf/$scope/disable_ipv6"));
    assert!(GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT.contains("for scope in all default"));
    // Fail closed: only an ABSENT sysctl is tolerated; a present one must read
    // back `1`, so a present-but-unwritable path fails the start rather than
    // releasing the guest command with IPv6 still live.
    assert!(GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT.contains("[ -e \"$path\" ] || continue"));
    assert!(GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT.contains("read -r state < \"$path\""));
    assert!(GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT.contains("[ \"$state\" = 1 ]"));
    assert!(GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT.contains("writ-ipv6-not-disabled"));
    // Then report the resulting state for validation.
    assert!(GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT.contains("addr show 2>&1"));
    assert!(GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT.contains("route show default 2>&1"));
}
