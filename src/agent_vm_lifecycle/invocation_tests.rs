//! Example/edge-case tests for the start/stop `ProcessInvocation`
//! sequences: ordering, IPv4-only variations, cleanup ordering,
//! presence-probe shape and the broker URL.
use super::test_support::*;
use super::*;

#[test]
fn start_invocations_probe_create_inspect_firewall_probe_vm_then_vm() {
    let invocations = plan(252).start_invocations();
    assert_eq!(invocations.len(), 6);
    // Each creating step is preceded by its absence probe, and dry-run shows both
    // probes (and the permissions they need) rather than hiding them.
    assert_eq!(invocations[0].args_lossy(), ["network", "list", "--quiet"]);
    assert_eq!(
        invocations[1].args_lossy(),
        [
            "network",
            "create",
            "--internal",
            "--label",
            "writ.owner=writ-test-owner",
            "--subnet",
            "192.168.252.0/24",
            "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        ]
    );
    assert_eq!(
        invocations[2].args_lossy(),
        [
            "network",
            "inspect",
            "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        ]
    );
    assert_eq!(invocations[3].program(), Path::new("sudo"));
    let firewall_args = invocations[3].args_lossy();
    assert_eq!(&firewall_args[0..2], ["writ-agent-vm-pf-helper", "install"]);
    assert!(firewall_args.contains(&"--ipv6-cidr".to_string()));
    // The agent-VM absence probe runs just before `run`.
    assert_eq!(invocations[4].args_lossy(), ["list", "--all", "--quiet"]);
    let vm_args = invocations[5].args_lossy();
    assert_eq!(&vm_args[0..2], ["run", "--name"]);
    assert!(vm_args.contains(&"writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string()));
    assert_tmpfs_mounts_present(&vm_args);
}

#[test]
fn ipv4_only_start_invocations_probe_before_releasing_guest_command() {
    let invocations =
        plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6).start_invocations();
    assert_eq!(invocations.len(), 9);
    // Index 0 is the network-absence probe, index 4 the agent-VM absence probe.
    assert_eq!(invocations[0].args_lossy(), ["network", "list", "--quiet"]);
    assert_eq!(invocations[4].args_lossy(), ["list", "--all", "--quiet"]);
    let firewall_args = invocations[3].args_lossy();
    assert_eq!(&firewall_args[0..2], ["writ-agent-vm-pf-helper", "install"]);
    assert!(!firewall_args.contains(&"--ipv6-cidr".to_string()));
    // The pre-start install carries no interface deny (the bridge is not up yet).
    assert!(!firewall_args.contains(&"--ipv6-deny-interface".to_string()));

    let start_vm_args = invocations[5].args_lossy();
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

    // Index 6: the post-start bridge discovery — `ifconfig` with no arguments,
    // between StartVm and the guest IPv6 probe, so the host IPv6 deny is installed
    // before the guest command is ever released.
    assert!(invocations[6].args_lossy().is_empty());
    assert_eq!(invocations[6].display_shell(), "ifconfig");

    assert_eq!(
        invocations[7].args_lossy(),
        [
            "exec",
            "writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            "sh",
            "-c",
            GUEST_IPV6_ENFORCE_AND_PROBE_SCRIPT,
        ]
    );
    assert_eq!(
        invocations[8].args_lossy(),
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
    let cleanup = plan(252).cleanup_after_partial_start(CompletedStartStep::VmStarted);
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
fn firewall_installed_phase_removes_pf_and_network_but_not_the_vm() {
    // Reached when the VM was never started (its absence probe failed): remove the
    // PF anchor and the network we created, but issue no VM teardown.
    let cleanup = plan(252).cleanup_after_partial_start(CompletedStartStep::FirewallInstalled);
    assert_eq!(cleanup.len(), 3);
    assert_eq!(
        &cleanup[0].args_lossy()[0..2],
        ["writ-agent-vm-pf-helper", "remove"]
    );
    assert_eq!(&cleanup[1].args_lossy()[0..2], ["network", "rm"]);
    assert_eq!(&cleanup[2].args_lossy()[0..2], ["network", "delete"]);
    assert!(
        !cleanup.iter().any(|inv| {
            let args = inv.args_lossy();
            args.first().map(String::as_str) == Some("rm")
                || args.first().map(String::as_str) == Some("delete")
                || args.first().map(String::as_str) == Some("stop")
        }),
        "the firewall-installed phase must not tear down the VM: {cleanup:?}"
    );
}

#[test]
fn vm_placement_start_skips_only_network_creation_and_keeps_host_pf() {
    // The broker arm creates the shared network, so the agent start skips
    // CreateNetwork — but it still inspects the network and installs host PF
    // (an `--internal` net does not isolate the agent from host services).
    let steps = plan_with_broker_placement(252, BrokerPlacement::Vm).start_steps();
    assert!(
        !steps
            .iter()
            .any(|s| matches!(s, AgentVmStartStep::CreateNetwork(_))),
        "vm start must not create the shared network: {steps:?}"
    );
    // The broker owns the shared network, so vm start must not probe it for
    // absence either — the probe belongs only to the host path that creates it.
    assert!(
        !steps
            .iter()
            .any(|s| matches!(s, AgentVmStartStep::ProbeNetworkAbsent(_))),
        "vm start must not probe the broker-owned network: {steps:?}"
    );
    assert!(
        matches!(
            steps.first(),
            Some(AgentVmStartStep::InspectAndValidateNetwork(_))
        ),
        "vm start must still inspect the network first: {steps:?}"
    );
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, AgentVmStartStep::InstallFirewall(_))),
        "vm start must still install host PF: {steps:?}"
    );
    // Both placements create the agent VM, so both probe for its absence first.
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, AgentVmStartStep::ProbeVmAbsent(_))),
        "vm start must probe the agent VM for absence: {steps:?}"
    );
    // Host placement probes for the network's absence, then creates it.
    let host = plan_with_broker_placement(252, BrokerPlacement::Host).start_steps();
    assert!(matches!(
        host.first(),
        Some(AgentVmStartStep::ProbeNetworkAbsent(_))
    ));
    assert!(
        host.iter()
            .any(|s| matches!(s, AgentVmStartStep::CreateNetwork(_))),
        "host start must still create the network: {host:?}"
    );
}

#[test]
fn vm_placement_failed_start_removes_the_agent_vm_and_pf_but_not_the_network() {
    // The broker arm owns the shared network, so a failed agent start cleans up
    // the agent VM and its host PF anchor — but not the broker-owned network.
    let cleanup = plan_with_broker_placement(252, BrokerPlacement::Vm)
        .cleanup_after_partial_start(CompletedStartStep::VmStarted);
    assert!(
        cleanup.iter().any(|inv| {
            inv.args_lossy()
                .starts_with(&["rm".to_string(), "-f".to_string()])
        }),
        "vm cleanup must remove the agent VM: {cleanup:?}"
    );
    assert!(
        cleanup.iter().any(|inv| inv
            .args_lossy()
            .contains(&"writ-agent-vm-pf-helper".to_string())),
        "vm cleanup must remove host PF: {cleanup:?}"
    );
    assert!(
        !cleanup
            .iter()
            .any(|inv| inv.args_lossy().first().map(String::as_str) == Some("network")),
        "vm cleanup must not remove the broker-owned network: {cleanup:?}"
    );
}

#[test]
fn vm_broker_pf_host_retargets_the_firewall_install_to_the_broker_vm_ip() {
    fn firewall_args(plan: &AgentVmSessionPlan) -> Vec<String> {
        plan.start_steps()
            .into_iter()
            .find_map(|s| match s {
                AgentVmStartStep::InstallFirewall(inv) => Some(inv.args_lossy()),
                _ => None,
            })
            .expect("start installs PF")
    }

    // vm placement with a discovered broker VM IP passes --broker-host so the PF
    // allow rule targets the broker VM, not the gateway.
    let vm = plan_with_broker_placement(252, BrokerPlacement::Vm)
        .with_broker_pf_host(std::net::Ipv4Addr::new(192, 168, 252, 5));
    let vm_args = firewall_args(&vm);
    let pos = vm_args
        .iter()
        .position(|a| a == "--broker-host")
        .expect("--broker-host present for vm");
    assert_eq!(vm_args[pos + 1], "192.168.252.5");

    // Host placement omits it (the helper defaults to the subnet gateway).
    let host_args = firewall_args(&plan_with_broker_placement(252, BrokerPlacement::Host));
    assert!(
        !host_args.iter().any(|a| a == "--broker-host"),
        "{host_args:?}"
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

#[tokio::test]
async fn run_capturing_output_bounded_returns_full_small_output() {
    let inv = ProcessInvocation::new(
        std::path::PathBuf::from("/bin/sh"),
        ["-c".to_string(), "printf hello".to_string()],
    );
    let out = inv.run_capturing_output_bounded(1024).await.unwrap();
    assert!(!out.truncated, "small output must not be flagged truncated");
    assert_eq!(out.stdout, "hello");
    assert!(
        out.status.is_some_and(|s| s.success()),
        "the process must exit successfully: {:?}",
        out.status
    );
}

#[tokio::test]
async fn run_capturing_output_bounded_caps_and_does_not_hang_on_a_flood() {
    // The child writes far more than the cap (then exits); the capture must stop
    // at the cap, flag truncation, and return promptly rather than draining or
    // hanging (a regression guard for the bounded/killable log + inspect probes).
    let inv = ProcessInvocation::new(
        std::path::PathBuf::from("/bin/sh"),
        ["-c".to_string(), "head -c 4096 /dev/zero".to_string()],
    );
    let out = inv.run_capturing_output_bounded(64).await.unwrap();
    assert!(out.truncated, "output beyond the cap must flag truncation");
    assert_eq!(out.stdout.len(), 64, "stdout must be capped at max_bytes");
}

#[tokio::test]
async fn run_capturing_output_bounded_keeps_exactly_max_bytes_without_flagging_truncation() {
    // An output of exactly the cap followed by EOF is complete, not truncated,
    // and the child exits cleanly — the capture must not kill it (which would
    // forge a kill signal in place of its real exit status).
    let inv = ProcessInvocation::new(
        std::path::PathBuf::from("/bin/sh"),
        ["-c".to_string(), "head -c 64 /dev/zero".to_string()],
    );
    let out = inv.run_capturing_output_bounded(64).await.unwrap();
    assert!(
        !out.truncated,
        "output of exactly max_bytes must not flag truncation"
    );
    assert_eq!(out.stdout.len(), 64);
    assert!(
        out.status.is_some_and(|s| s.success()),
        "a clean exit at exactly the cap must be preserved, not killed: {:?}",
        out.status
    );
}

#[tokio::test]
async fn run_capturing_merged_tail_keeps_short_output_whole() {
    let inv = ProcessInvocation::new(
        std::path::PathBuf::from("/bin/sh"),
        ["-c".to_string(), "printf 'the-whole-log'".to_string()],
    );
    let out = inv.run_capturing_merged_tail(1024).await.unwrap();
    assert!(
        !out.truncated,
        "output within the cap must not flag truncation"
    );
    assert_eq!(out.text, "the-whole-log");
}

#[tokio::test]
async fn run_capturing_merged_tail_keeps_the_newest_bytes() {
    // Unlike the head-keeping bounded capture, the tail capture must retain the
    // *end* of a stream that exceeds the cap — that is where a crash log's
    // actual error lives. Bracket a large filler with distinct start/end
    // markers; only the end marker may survive.
    let inv = ProcessInvocation::new(
        std::path::PathBuf::from("/bin/sh"),
        [
            "-c".to_string(),
            "printf OLDSTART; head -c 20000 /dev/zero; printf NEWEND".to_string(),
        ],
    );
    let out = inv.run_capturing_merged_tail(64).await.unwrap();
    assert!(out.truncated, "a stream past the cap must flag truncation");
    assert!(out.text.len() <= 64, "the tail must stay within the cap");
    assert!(
        out.text.contains("NEWEND"),
        "the newest bytes (the error) must survive: {:?}",
        out.text
    );
    assert!(
        !out.text.contains("OLDSTART"),
        "the oldest bytes must be discarded: {:?}",
        out.text
    );
}

#[tokio::test]
async fn run_capturing_merged_tail_does_not_hang_on_a_large_one_sided_stream() {
    // Draining to EOF (never stopping early) means a flood is discarded, not
    // wedged; the child exits and the call returns promptly.
    let inv = ProcessInvocation::new(
        std::path::PathBuf::from("/bin/sh"),
        ["-c".to_string(), "head -c 524288 /dev/zero".to_string()],
    );
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        inv.run_capturing_merged_tail(64),
    )
    .await
    .expect("merged tail must not hang on a large stream")
    .expect("spawn must succeed");
    assert!(out.truncated);
    assert!(out.text.len() <= 64);
}

#[tokio::test]
async fn run_capturing_output_bounded_does_not_deadlock_on_a_one_sided_flood_past_the_pipe_buffer()
{
    // Regression: a child that floods *one* stream far past the OS pipe buffer
    // (~64 KiB) while writing nothing to the other must not wedge the capture.
    // If we stop draining stdout at the cap but still wait for stderr EOF, the
    // child blocks on the full stdout pipe and never exits (so never closes
    // stderr) -> deadlock. The capture must kill the child once a stream caps
    // and reap it, returning promptly regardless of whether the other stream
    // ever EOFs. The outer timeout turns a deadlock into a failure instead of a
    // hung test; a healthy capture returns in milliseconds.
    //
    // The trailing `; :` is load-bearing: it forces the shell to *fork* `head`
    // as a grandchild rather than exec-optimizing into it (a single simple
    // command is exec'd by bash but not by dash). Killing the shell then leaves
    // `head` orphaned, still holding the *stderr* write-end open while blocked
    // on the undrained stdout pipe — so a capture that waits for stderr EOF
    // hangs. Without the fork this reproduces only on dash (Linux CI), not on
    // macOS's bash `/bin/sh`.
    let inv = ProcessInvocation::new(
        std::path::PathBuf::from("/bin/sh"),
        // 512 KiB of stdout, far past the pipe buffer; not one byte of stderr.
        ["-c".to_string(), "head -c 524288 /dev/zero; :".to_string()],
    );
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        inv.run_capturing_output_bounded(64),
    )
    .await
    .expect("capture must not deadlock on a one-sided flood past the pipe buffer")
    .expect("spawn must succeed");
    assert!(out.truncated, "a flood past the cap must flag truncation");
    assert_eq!(out.stdout.len(), 64, "stdout must be capped at max_bytes");
}
