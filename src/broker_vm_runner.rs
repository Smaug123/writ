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
use std::time::{Duration, Instant};

use crate::agent_vm_lifecycle::ProcessInvocationError;
use crate::broker_protocol::{BROKER_PROTOCOL_VERSION, BrokerReadyDoc, BrokerReadyDocError};
use crate::broker_vm::{
    BrokerInspectError, BrokerVmPlan, BrokerVmState, parse_broker_ipv4_on_network,
    parse_broker_state,
};
use crate::core::BrokerPort;

/// How much of the broker's log tail to fold into an
/// [`BrokerVmLaunchError::ExitedBeforeReady`] — enough for a clap parse error or
/// a config-load failure, bounded so a chatty broker can't blow up the host
/// error string.
const BROKER_LOG_CAPTURE_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum BrokerVmLaunchError {
    #[error("creating the shared internal network failed: {0}")]
    InternalNetwork(#[source] ProcessInvocationError),
    #[error("creating the broker egress network failed: {0}")]
    EgressNetwork(#[source] ProcessInvocationError),
    #[error("starting the broker VM failed: {0}")]
    RunBroker(#[source] ProcessInvocationError),
    #[error("the broker VM did not publish its ready file within {0:?}")]
    ReadyTimeout(Duration),
    #[error(
        "the broker VM exited (state: {state}) before publishing its ready file. This usually \
         means the broker image is older than the host `writd` — e.g. it rejects a broker CLI \
         flag the host now passes — so rebuild it with `writ agent-vm build-broker-image`. \
         Broker logs:\n{logs}"
    )]
    ExitedBeforeReady { state: String, logs: String },
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
    #[error("could not read the broker ready file {path}: {source}")]
    ReadyRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse the broker ready file {path}: {source}")]
    ReadyParse {
        path: String,
        #[source]
        source: BrokerReadyDocError,
    },
    #[error(
        "broker VM protocol mismatch: the broker image speaks protocol v{guest}, but this host \
         requires v{host}. The broker image is out of date — rebuild it with \
         `writ agent-vm build-broker-image`."
    )]
    ProtocolMismatch { host: u32, guest: u32 },
    #[error(
        "broker VM published port {got} in its ready file but the host assigned it port {expected}"
    )]
    ReadyPortMismatch { expected: u16, got: u16 },
    #[error("a broker VM worker task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

/// Start the broker VM and return its IPv4 address on the internal network.
///
/// Sequence: create the shared internal network (the broker arm owns it) → create
/// the egress network → `container run` the broker → wait (bounded by
/// `ready_timeout`, polling every `poll_interval`) for `ready_file` to appear on
/// the host side of the material mount, failing fast if the broker VM exits first
/// → validate the broker's protocol version and bound port against
/// `expected_port` (rejecting a stale image) → `container inspect` and read the
/// broker's address on `plan.internal_network()`.
///
/// On any error the networks and broker VM may be partially created; the caller
/// is responsible for [`teardown_broker_vm`].
pub async fn launch_broker_vm(
    plan: &BrokerVmPlan,
    ready_file: &Path,
    expected_port: BrokerPort,
    ready_timeout: Duration,
    poll_interval: Duration,
) -> Result<Ipv4Addr, BrokerVmLaunchError> {
    // The broker starts first, so it creates the shared network the agent later
    // joins (and removes it on teardown).
    let internal = plan.create_internal_network_invocation();
    tokio::task::spawn_blocking(move || internal.run())
        .await?
        .map_err(BrokerVmLaunchError::InternalNetwork)?;

    let egress = plan.create_egress_network_invocation();
    tokio::task::spawn_blocking(move || egress.run())
        .await?
        .map_err(BrokerVmLaunchError::EgressNetwork)?;

    let run = plan.run_invocation();
    tokio::task::spawn_blocking(move || run.run())
        .await?
        .map_err(BrokerVmLaunchError::RunBroker)?;

    wait_for_ready_or_exit(plan, ready_file, ready_timeout, poll_interval).await?;
    gate_ready_doc(ready_file, expected_port)?;

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

/// Wait for the broker to publish `ready_file`, but fail fast if the broker VM
/// exits first. Polls both the ready file and (via `container inspect`) the VM's
/// lifecycle state every `poll_interval`, up to `ready_timeout`:
///
/// - ready file present → `Ok`.
/// - VM observed in a terminal state before the file appears → `ExitedBeforeReady`
///   with the broker's captured logs — turning the old 180s opaque timeout into a
///   seconds-fast, self-explaining error for a stale/broken image.
/// - neither, until the deadline → `ReadyTimeout` (unchanged behaviour for a VM
///   that is up but slow, or whose crash state we don't recognise).
async fn wait_for_ready_or_exit(
    plan: &BrokerVmPlan,
    ready_file: &Path,
    ready_timeout: Duration,
    poll_interval: Duration,
) -> Result<(), BrokerVmLaunchError> {
    let start = Instant::now();
    loop {
        if ready_file_exists(ready_file)? {
            return Ok(());
        }
        // Liveness: has the broker VM exited before publishing readiness? A failure
        // to run or parse `inspect` (e.g. the VM is not yet created) is benign —
        // it degrades to "not terminal", and we keep waiting.
        let inspect = plan.inspect_invocation();
        let inspected = tokio::task::spawn_blocking(move || inspect.run_capturing_output()).await?;
        if let Ok(output) = inspected
            && output.status.success()
            && let BrokerVmState::Terminal(state) = parse_broker_state(&output.stdout)
        {
            // The broker can bind, publish `ready`, and exit between our file
            // check and this inspect; re-check the file so that benign race is not
            // misreported as a crash.
            if ready_file_exists(ready_file)? {
                return Ok(());
            }
            let logs = capture_broker_logs(plan).await;
            return Err(BrokerVmLaunchError::ExitedBeforeReady { state, logs });
        }
        if start.elapsed() >= ready_timeout {
            return Err(BrokerVmLaunchError::ReadyTimeout(ready_timeout));
        }
        tokio::time::sleep(poll_interval).await;
    }
}

fn ready_file_exists(path: &Path) -> Result<bool, BrokerVmLaunchError> {
    path.try_exists()
        .map_err(|source| BrokerVmLaunchError::ReadyPoll {
            path: path.display().to_string(),
            source,
        })
}

/// Read and validate the broker's ready document once it has appeared: the
/// broker's protocol version must match this host's (a mismatch means a stale
/// broker image), and the port it bound must be the one the host assigned. A
/// legacy bare-port ready file from a pre-handshake image parses as protocol
/// version 0, so it too fails the version gate with an actionable error.
fn gate_ready_doc(ready_file: &Path, expected_port: BrokerPort) -> Result<(), BrokerVmLaunchError> {
    let contents =
        std::fs::read_to_string(ready_file).map_err(|source| BrokerVmLaunchError::ReadyRead {
            path: ready_file.display().to_string(),
            source,
        })?;
    let doc =
        BrokerReadyDoc::parse(&contents).map_err(|source| BrokerVmLaunchError::ReadyParse {
            path: ready_file.display().to_string(),
            source,
        })?;
    if doc.protocol_version != BROKER_PROTOCOL_VERSION {
        return Err(BrokerVmLaunchError::ProtocolMismatch {
            host: BROKER_PROTOCOL_VERSION,
            guest: doc.protocol_version,
        });
    }
    if doc.broker_port != expected_port.get() {
        return Err(BrokerVmLaunchError::ReadyPortMismatch {
            expected: expected_port.get(),
            got: doc.broker_port,
        });
    }
    Ok(())
}

/// Best-effort capture of the broker VM's log tail for diagnostics; never fails
/// the launch — if `container logs` is unavailable we substitute a short note so
/// the error still explains what happened.
async fn capture_broker_logs(plan: &BrokerVmPlan) -> String {
    let logs = plan.logs_invocation();
    match tokio::task::spawn_blocking(move || logs.run_capturing_output()).await {
        Ok(Ok(output)) => {
            let combined = output.combined();
            let trimmed = combined.trim();
            if trimmed.is_empty() {
                "(broker logs were empty)".to_string()
            } else {
                tail(trimmed, BROKER_LOG_CAPTURE_BYTES)
            }
        }
        Ok(Err(err)) => format!("(could not read broker logs: {err})"),
        Err(join) => format!("(broker log capture task failed: {join})"),
    }
}

/// The last `max_bytes` of `s`, snapped up to a UTF-8 char boundary, prefixed
/// with an ellipsis when truncated.
fn tail(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut start = s.len() - max_bytes;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    format!("…{}", &s[start..])
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

    /// A fake `container` whose VM has already exited: `inspect` reports state
    /// "stopped" with no attachments, and `logs` prints `log_line` — modelling a
    /// broker that crashed at startup (e.g. a stale image rejecting a CLI flag).
    fn write_fake_container_exited(dir: &Path, args_log: &Path, log_line: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let tool = dir.join("fake-container-exited");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> "{log}"
if [ "$1" = inspect ]; then
  cat <<'JSON'
[ {{ "status": {{ "networks": [], "state": "stopped" }} }} ]
JSON
fi
if [ "$1" = logs ]; then
  printf '%s\n' "{log_line}"
fi
exit 0
"#,
            log = args_log.display(),
            log_line = log_line,
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
    async fn launch_creates_networks_runs_broker_then_discovers_ip() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let tool = write_fake_container(dir.path(), &args_log, "192.168.252.3");
        let plan = plan_with_tool(&tool, dir.path());

        // The (fake) broker has already published a well-formed ready doc.
        let ready = dir.path().join("ready");
        std::fs::write(&ready, BrokerReadyDoc::current(18080).to_ready_file()).unwrap();

        let ip = launch_broker_vm(
            &plan,
            &ready,
            BrokerPort::new(18080).unwrap(),
            Duration::from_secs(5),
            Duration::from_millis(10),
        )
        .await
        .unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 252, 3));

        // Ordered: shared internal network, then egress, then broker run, then
        // inspect.
        let log = std::fs::read_to_string(&args_log).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        let internal = lines
            .iter()
            .position(|l| l.starts_with("network create --internal"))
            .expect("shared internal network created");
        let egress = lines
            .iter()
            .position(|l| l.starts_with("network create writ-broker-egress"))
            .expect("egress network created");
        let run = lines
            .iter()
            .position(|l| l.starts_with("run "))
            .expect("broker run");
        let inspect = lines
            .iter()
            .position(|l| l.starts_with("inspect "))
            .expect("inspected");
        assert!(
            internal < egress && egress < run && run < inspect,
            "unexpected order: {lines:?}"
        );
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
            BrokerPort::new(18080).unwrap(),
            Duration::from_millis(80),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, BrokerVmLaunchError::ReadyTimeout(_)), "{err}");
    }

    #[tokio::test]
    async fn launch_fails_fast_when_the_broker_exits_before_ready() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let tool = write_fake_container_exited(
            dir.path(),
            &args_log,
            "broker boot error: unexpected argument --log-file",
        );
        let plan = plan_with_tool(&tool, dir.path());

        // The ready file is never created (the broker died first).
        let ready = dir.path().join("ready");

        let start = std::time::Instant::now();
        let err = launch_broker_vm(
            &plan,
            &ready,
            BrokerPort::new(18080).unwrap(),
            // A deliberately generous timeout: fast-fail must beat it by far.
            Duration::from_secs(20),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        let waited = start.elapsed();

        match err {
            BrokerVmLaunchError::ExitedBeforeReady { state, logs } => {
                assert_eq!(state, "stopped");
                assert!(
                    logs.contains("--log-file"),
                    "logs should carry the broker's crash reason: {logs}"
                );
            }
            other => panic!("expected ExitedBeforeReady, got {other}"),
        }
        assert!(
            waited < Duration::from_secs(5),
            "should fail fast on broker exit, not wait out the timeout; waited {waited:?}"
        );
    }

    #[tokio::test]
    async fn launch_rejects_a_stale_broker_image_by_protocol_version() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let tool = write_fake_container(dir.path(), &args_log, "192.168.252.3");
        let plan = plan_with_tool(&tool, dir.path());

        // A pre-handshake broker image publishes a bare port (parses as version 0).
        let ready = dir.path().join("ready");
        std::fs::write(&ready, "18080\n").unwrap();

        let err = launch_broker_vm(
            &plan,
            &ready,
            BrokerPort::new(18080).unwrap(),
            Duration::from_secs(5),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        match err {
            BrokerVmLaunchError::ProtocolMismatch { host, guest } => {
                assert_eq!(host, BROKER_PROTOCOL_VERSION);
                assert_eq!(guest, 0);
            }
            other => panic!("expected ProtocolMismatch, got {other}"),
        }
    }

    #[tokio::test]
    async fn launch_rejects_a_broker_that_bound_the_wrong_port() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let tool = write_fake_container(dir.path(), &args_log, "192.168.252.3");
        let plan = plan_with_tool(&tool, dir.path());

        // Well-formed, current-version doc — but the broker bound a different port
        // than the host assigned.
        let ready = dir.path().join("ready");
        std::fs::write(&ready, BrokerReadyDoc::current(19999).to_ready_file()).unwrap();

        let err = launch_broker_vm(
            &plan,
            &ready,
            BrokerPort::new(18080).unwrap(),
            Duration::from_secs(5),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                BrokerVmLaunchError::ReadyPortMismatch {
                    expected: 18080,
                    got: 19999
                }
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn teardown_removes_the_vm_then_both_networks() {
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
        let egress_rm = lines
            .iter()
            .position(|l| l.starts_with("network rm writ-broker-egress-"))
            .expect("egress network removed");
        let internal_rm = lines
            .iter()
            .position(|l| l.starts_with(&format!("network rm {INTERNAL_NET}")))
            .expect("shared internal network removed");
        // VM first, then egress, then the shared internal network (which is only
        // free once the agent VM has also been stopped by the orchestrator).
        assert!(
            rm < egress_rm && egress_rm < internal_rm,
            "unexpected teardown order: {lines:?}"
        );
    }
}
