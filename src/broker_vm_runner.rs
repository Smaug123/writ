//! Imperative shell that executes a [`BrokerVmPlan`] (the broker-in-VM arm; see
//! `docs/vmnet-accept-bug-and-broker-vm-plan.md`).
//!
//! The plan in [`crate::broker_vm`] is pure data; this module runs it: create
//! the egress network, start the broker VM, wait for it to publish its ready
//! file (host-side, via the shared material mount), and discover its address on
//! the internal network with `container inspect`. Teardown is the inverse, run
//! best-effort. Process execution is offloaded to `spawn_blocking` (the
//! `container` CLI is synchronous); the ready-file wait is async.

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use crate::agent_vm_lifecycle::ProcessInvocationError;
use crate::broker_vm::{BrokerInspectError, BrokerVmPlan, parse_broker_ipv4_on_network};

#[derive(Debug, thiserror::Error)]
pub enum BrokerVmLaunchError {
    #[error("creating the broker egress network failed: {0}")]
    EgressNetwork(#[source] ProcessInvocationError),
    #[error("starting the broker VM failed: {0}")]
    RunBroker(#[source] ProcessInvocationError),
    #[error("the broker VM did not publish its ready file within {0:?}")]
    ReadyTimeout(Duration),
    #[error("polling the broker ready file {path} failed: {source}")]
    ReadyPoll {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("inspecting the broker VM failed: {0}")]
    Inspect(#[source] ProcessInvocationError),
    #[error("could not determine the broker VM's address: {0}")]
    AddressDiscovery(#[source] BrokerInspectError),
    #[error("a broker VM worker task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

/// Start the broker VM and return its IPv4 address on the internal network.
///
/// Sequence: create the egress network → `container run` the broker → wait
/// (bounded by `ready_timeout`, polling every `poll_interval`) for `ready_file`
/// to appear on the host side of the material mount → `container inspect` and
/// read the broker's address on `plan.internal_network()`.
///
/// On any error the broker VM and egress network may be partially created; the
/// caller is responsible for [`teardown_broker_vm`].
pub async fn launch_broker_vm(
    plan: &BrokerVmPlan,
    ready_file: &Path,
    ready_timeout: Duration,
    poll_interval: Duration,
) -> Result<Ipv4Addr, BrokerVmLaunchError> {
    let egress = plan.create_egress_network_invocation();
    tokio::task::spawn_blocking(move || egress.run())
        .await?
        .map_err(BrokerVmLaunchError::EgressNetwork)?;

    let run = plan.run_invocation();
    tokio::task::spawn_blocking(move || run.run())
        .await?
        .map_err(BrokerVmLaunchError::RunBroker)?;

    match tokio::time::timeout(
        ready_timeout,
        wait_for_ready_file(ready_file, poll_interval),
    )
    .await
    {
        Ok(result) => result?,
        Err(_elapsed) => return Err(BrokerVmLaunchError::ReadyTimeout(ready_timeout)),
    }

    let inspect = plan.inspect_invocation();
    let json = tokio::task::spawn_blocking(move || inspect.run_capturing_stdout())
        .await?
        .map_err(BrokerVmLaunchError::Inspect)?;
    parse_broker_ipv4_on_network(&json, plan.internal_network())
        .map_err(BrokerVmLaunchError::AddressDiscovery)
}

/// Best-effort teardown of a broker VM and its egress network. Runs every stop
/// invocation regardless of earlier failures (so a stuck VM removal can't strand
/// the network) and returns the messages of any that failed, for the caller to
/// log. An empty vec means a clean teardown.
pub async fn teardown_broker_vm(plan: &BrokerVmPlan) -> Vec<String> {
    let mut failures = Vec::new();
    for invocation in plan.stop_invocations() {
        match tokio::task::spawn_blocking(move || invocation.run()).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => failures.push(err.to_string()),
            Err(join) => failures.push(format!("broker VM teardown worker task failed: {join}")),
        }
    }
    failures
}

async fn wait_for_ready_file(
    path: &Path,
    poll_interval: Duration,
) -> Result<(), BrokerVmLaunchError> {
    loop {
        match path.try_exists() {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(source) => {
                return Err(BrokerVmLaunchError::ReadyPoll {
                    path: path.display().to_string(),
                    source,
                });
            }
        }
        tokio::time::sleep(poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_vm_lifecycle::{AgentVmResources, ContainerImage};
    use crate::core::{Ipv4Cidr, SessionId};
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    const INTERNAL_NET: &str = "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d";

    /// A fake `container` that logs every argv line to `args_log` and answers
    /// `inspect` with a running-VM JSON carrying `broker_ip` on the internal net.
    fn write_fake_container(dir: &Path, args_log: &Path, broker_ip: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let tool = dir.join("fake-container");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> "{log}"
if [ "$1" = inspect ]; then
  cat <<'JSON'
[ {{ "status": {{ "networks": [
  {{ "network": "{net}", "ipv4Address": "{ip}/24", "ipv4Gateway": "192.168.252.1" }}
], "state": "running" }} }} ]
JSON
fi
exit 0
"#,
            log = args_log.display(),
            net = INTERNAL_NET,
            ip = broker_ip,
        );
        std::fs::write(&tool, script).unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        tool
    }

    fn plan_with_tool(tool: &Path, dir: &Path) -> BrokerVmPlan {
        BrokerVmPlan::new(
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d"
                .parse::<SessionId>()
                .unwrap(),
            ContainerImage::new("writ-broker-vm:latest").unwrap(),
            INTERNAL_NET,
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
            AgentVmResources::new(2, 1024).unwrap(),
            tool,
            dir.join("session"),
            dir.join("secrets"),
            dir.join("audit"),
        )
    }

    #[tokio::test]
    async fn launch_creates_egress_runs_broker_then_discovers_ip() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let tool = write_fake_container(dir.path(), &args_log, "192.168.252.3");
        let plan = plan_with_tool(&tool, dir.path());

        // The (fake) broker has already published readiness on the mount.
        let ready = dir.path().join("ready");
        std::fs::write(&ready, "18080\n").unwrap();

        let ip = launch_broker_vm(
            &plan,
            &ready,
            Duration::from_secs(5),
            Duration::from_millis(10),
        )
        .await
        .unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 252, 3));

        // Ordered: egress network created, broker run, then inspected.
        let log = std::fs::read_to_string(&args_log).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        let egress = lines
            .iter()
            .position(|l| l.starts_with("network create"))
            .expect("egress network created");
        let run = lines
            .iter()
            .position(|l| l.starts_with("run "))
            .expect("broker run");
        let inspect = lines
            .iter()
            .position(|l| l.starts_with("inspect "))
            .expect("inspected");
        assert!(egress < run && run < inspect, "unexpected order: {lines:?}");
    }

    #[tokio::test]
    async fn launch_times_out_when_the_broker_never_becomes_ready() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let tool = write_fake_container(dir.path(), &args_log, "192.168.252.3");
        let plan = plan_with_tool(&tool, dir.path());

        // No ready file is ever written.
        let ready = dir.path().join("ready");
        let err = launch_broker_vm(
            &plan,
            &ready,
            Duration::from_millis(80),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, BrokerVmLaunchError::ReadyTimeout(_)), "{err}");
    }

    #[tokio::test]
    async fn teardown_removes_the_vm_then_the_egress_network() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let tool = write_fake_container(dir.path(), &args_log, "192.168.252.3");
        let plan = plan_with_tool(&tool, dir.path());

        let failures = teardown_broker_vm(&plan).await;
        assert!(failures.is_empty(), "clean teardown expected: {failures:?}");

        let log = std::fs::read_to_string(&args_log).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        let rm = lines
            .iter()
            .position(|l| l.starts_with("rm -f writ-broker-vm-"))
            .expect("vm removed");
        let net_rm = lines
            .iter()
            .position(|l| l.starts_with("network rm writ-broker-egress-"))
            .expect("egress network removed");
        assert!(
            rm < net_rm,
            "vm must be removed before its network: {lines:?}"
        );
    }
}
