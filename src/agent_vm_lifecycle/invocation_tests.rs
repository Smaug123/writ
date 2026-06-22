//! Example/edge-case tests for the start/stop `ProcessInvocation`
//! sequences: ordering, IPv4-only variations, cleanup ordering,
//! presence-probe shape and the broker URL.
use super::test_support::*;
use super::*;

#[test]
fn start_invocations_create_network_then_inspect_then_firewall_then_vm() {
    let invocations = plan(252).start_invocations();
    assert_eq!(invocations.len(), 4);
    assert_eq!(
        invocations[0].args_lossy(),
        [
            "network",
            "create",
            "--internal",
            "--subnet",
            "192.168.252.0/24",
            "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        ]
    );
    assert_eq!(
        invocations[1].args_lossy(),
        [
            "network",
            "inspect",
            "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        ]
    );
    assert_eq!(invocations[2].program(), Path::new("sudo"));
    let firewall_args = invocations[2].args_lossy();
    assert_eq!(&firewall_args[0..2], ["writ-agent-vm-pf-helper", "install"]);
    assert!(firewall_args.contains(&"--ipv6-cidr".to_string()));
    let vm_args = invocations[3].args_lossy();
    assert_eq!(&vm_args[0..2], ["run", "--name"]);
    assert!(vm_args.contains(&"writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string()));
    assert_tmpfs_mounts_present(&vm_args);
}

#[test]
fn ipv4_only_start_invocations_probe_before_releasing_guest_command() {
    let invocations =
        plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6).start_invocations();
    assert_eq!(invocations.len(), 6);
    let firewall_args = invocations[2].args_lossy();
    assert_eq!(&firewall_args[0..2], ["writ-agent-vm-pf-helper", "install"]);
    assert!(!firewall_args.contains(&"--ipv6-cidr".to_string()));

    let start_vm_args = invocations[3].args_lossy();
    assert_eq!(&start_vm_args[0..2], ["run", "--name"]);
    assert_tmpfs_mounts_present(&start_vm_args);
    assert!(start_vm_args.contains(&"sh".to_string()));
    assert!(start_vm_args.contains(&"-c".to_string()));
    assert!(
        start_vm_args
            .iter()
            .any(|arg| arg.contains("/run/writ-agent-vm/start") && arg.contains("exec \"$@\""))
    );
    assert!(start_vm_args.ends_with(&[
        "writ-agent-vm-prelaunch".into(),
        "sleep".into(),
        "600".into()
    ]));

    assert_eq!(
        invocations[4].args_lossy(),
        [
            "exec",
            "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            "sh",
            "-c",
            GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT,
        ]
    );
    assert_eq!(
        invocations[5].args_lossy(),
        [
            "exec",
            "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            "sh",
            "-c",
            "mkdir -p /run/writ-agent-vm && touch /run/writ-agent-vm/start",
        ]
    );
}

#[test]
fn stop_invocations_remove_vm_then_firewall_then_network() {
    let invocations = plan(252).stop_invocations();
    assert_eq!(invocations.len(), 7);
    assert_eq!(
        invocations[0].args_lossy(),
        [
            "rm",
            "-f",
            "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        ]
    );
    assert_eq!(
        invocations[1].args_lossy(),
        ["stop", "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",]
    );
    assert_eq!(
        invocations[2].args_lossy(),
        [
            "delete",
            "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        ]
    );
    assert_eq!(
        invocations[3].args_lossy(),
        ["rm", "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",]
    );
    let firewall_args = invocations[4].args_lossy();
    assert_eq!(&firewall_args[0..2], ["writ-agent-vm-pf-helper", "remove"]);
    assert_eq!(
        invocations[5].args_lossy(),
        [
            "network",
            "rm",
            "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        ]
    );
    assert_eq!(
        invocations[6].args_lossy(),
        [
            "network",
            "delete",
            "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        ]
    );
}

#[test]
fn ipv4_only_stop_invocations_omit_ipv6_firewall_scope() {
    let invocations =
        plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6).stop_invocations();
    let firewall_args = invocations[4].args_lossy();
    assert_eq!(&firewall_args[0..2], ["writ-agent-vm-pf-helper", "remove"]);
    assert!(!firewall_args.contains(&"--ipv6-cidr".to_string()));
}

#[test]
fn stop_cleanup_presence_probes_use_quiet_lists() {
    let stop_plan = plan(252).stop_plan();
    assert_eq!(
        stop_plan.vm_presence_probe().invocation.args_lossy(),
        ["list", "--all", "--quiet"]
    );
    assert_eq!(
        stop_plan.network_presence_probe().invocation.args_lossy(),
        ["network", "list", "--quiet"]
    );
}

#[test]
fn resource_list_presence_requires_an_exact_quiet_line() {
    let name = "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d";
    let listed = format!("other\n{name}\n{name}-old\n");
    assert!(resource_list_contains_exact_line(listed.as_bytes(), name));
    assert!(!resource_list_contains_exact_line(
        format!("{name}-old\nother\n").as_bytes(),
        name
    ));
    assert!(!resource_list_contains_exact_line(
        format!("prefix-{name}\n").as_bytes(),
        name
    ));
}

#[test]
fn failed_firewall_install_cleans_up_network_only() {
    let cleanup = plan(252).cleanup_after_partial_start(CompletedStartStep::NetworkCreated);
    assert_eq!(cleanup.len(), 2);
    let args = cleanup[0].args_lossy();
    assert_eq!(&args[0..2], ["network", "rm"]);
    let args = cleanup[1].args_lossy();
    assert_eq!(&args[0..2], ["network", "delete"]);
}

#[test]
fn failed_vm_start_removes_vm_then_firewall_then_network() {
    let cleanup = plan(252).cleanup_after_partial_start(CompletedStartStep::FirewallInstalled);
    assert_eq!(cleanup.len(), 7);
    let remove_vm_args = cleanup[0].args_lossy();
    let delete_vm_args = cleanup[2].args_lossy();
    let remove_firewall_args = cleanup[4].args_lossy();
    let remove_network_args = cleanup[5].args_lossy();
    assert_eq!(&remove_vm_args[0..2], ["rm", "-f"]);
    assert_eq!(&delete_vm_args[0..1], ["delete"]);
    assert_eq!(
        &remove_firewall_args[0..2],
        ["writ-agent-vm-pf-helper", "remove"]
    );
    assert_eq!(&remove_network_args[0..2], ["network", "rm"]);
}

#[test]
fn vm_placement_start_skips_network_and_firewall_steps() {
    // The broker arm owns the shared network and there is no host PF, so the
    // agent start begins at StartVm (then the IPv4-only probe/release).
    let steps = plan_with_broker_placement(252, BrokerPlacement::Vm).start_steps();
    assert!(
        matches!(steps.first(), Some(AgentVmStartStep::StartVm(_))),
        "vm start must begin with StartVm, got {steps:?}"
    );
    assert!(
        !steps.iter().any(|s| matches!(
            s,
            AgentVmStartStep::CreateNetwork(_)
                | AgentVmStartStep::InspectAndValidateNetwork(_)
                | AgentVmStartStep::InstallFirewall(_)
        )),
        "vm start must not create/inspect the network or install PF: {steps:?}"
    );
    // Host placement is unchanged: it still provisions network + firewall first.
    let host = plan_with_broker_placement(252, BrokerPlacement::Host).start_steps();
    assert!(matches!(
        host.first(),
        Some(AgentVmStartStep::CreateNetwork(_))
    ));
}

#[test]
fn vm_placement_failed_start_removes_the_agent_vm_only() {
    // The broker arm tears down the broker VM, egress net, and shared net, so a
    // failed agent start in vm mode cleans up just the agent VM (no PF, no net).
    let cleanup = plan_with_broker_placement(252, BrokerPlacement::Vm)
        .cleanup_after_partial_start(CompletedStartStep::FirewallInstalled);
    assert!(
        cleanup
            .iter()
            .all(|inv| inv.program() == Path::new("container")),
        "vm cleanup must only touch the agent VM via container: {cleanup:?}"
    );
    assert!(
        !cleanup.iter().any(|inv| {
            let args = inv.args_lossy();
            args.first().map(String::as_str) == Some("network")
                || args.contains(&"writ-agent-vm-pf-helper".to_string())
        }),
        "vm cleanup must not remove the shared network or PF: {cleanup:?}"
    );
    assert!(
        cleanup
            .iter()
            .any(|inv| inv.args_lossy().starts_with(&["rm".into(), "-f".into()])),
        "vm cleanup must remove the agent VM: {cleanup:?}"
    );
}

#[test]
fn broker_url_uses_host_only_gateway_and_broker_port() {
    let urls = plan(252).broker_urls();
    assert_eq!(urls[0].as_str(), "http://192.168.252.1:51375/");
}

fn assert_tmpfs_mounts_present(args: &[String]) {
    let tmpfs_mounts = args
        .windows(2)
        .filter_map(|window| (window[0] == "--tmpfs").then_some(window[1].as_str()))
        .collect::<Vec<_>>();
    assert_eq!(tmpfs_mounts, AGENT_VM_TMPFS_MOUNTS);
}
