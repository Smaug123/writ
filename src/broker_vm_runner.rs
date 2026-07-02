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

/// How long to wait for `container logs` to produce the crash-log tail before
/// giving up with a placeholder note. The broker VM is already known to have
/// exited; this keeps a wedged `container logs` from stalling the fast
/// `ExitedBeforeReady` path all the way out to the ready timeout (which would
/// reintroduce the very opaque 180s failure this path exists to prevent).
const BROKER_LOG_CAPTURE_TIMEOUT: Duration = Duration::from_secs(5);

/// Byte cap on a single `container inspect` liveness poll. The status JSON is
/// small; the cap just guarantees the read is bounded regardless of what the
/// container tool emits.
const BROKER_INSPECT_CAP_BYTES: usize = 1024 * 1024;

/// Byte cap on the broker's ready file. A well-formed [`BrokerReadyDoc`] is a
/// few hundred bytes; this generous cap just guarantees a stale or misbehaving
/// broker cannot force an unbounded host allocation by writing a huge ready
/// file that we would otherwise slurp whole before validating it.
const BROKER_READY_DOC_MAX_BYTES: u64 = 64 * 1024;

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
    #[error(
        "the broker ready file {path} is larger than the {max}-byte cap; refusing to read it (a \
         well-formed ready document is a few hundred bytes, so this is a broken or hostile broker)"
    )]
    ReadyTooLarge { path: String, max: u64 },
    #[error(
        "the broker ready file {path} is not a regular file (a symlink, FIFO, or similar); \
         refusing to read it — the broker mount is untrusted"
    )]
    ReadyNotRegularFile { path: String },
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

    // Bound the whole ready/liveness wait by `ready_timeout`. The wait polls a
    // blocking `container inspect`; a wedged container service would otherwise
    // never return, hanging the launch past the deadline (the internal loop can
    // only notice the deadline *between* inspect calls). The outer timeout makes
    // `ReadyTimeout` a hard ceiling regardless.
    match tokio::time::timeout(
        ready_timeout,
        wait_for_ready_or_exit(plan, ready_file, poll_interval),
    )
    .await
    {
        Ok(result) => result?,
        Err(_elapsed) => return Err(BrokerVmLaunchError::ReadyTimeout(ready_timeout)),
    }
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
/// exits first:
///
/// - ready file present → `Ok`.
/// - VM observed in a terminal state before the file appears → `ExitedBeforeReady`
///   with the broker's captured logs — turning the old 180s opaque timeout into a
///   seconds-fast, self-explaining error for a stale/broken image.
///
/// The two checks run as *independent* concurrent pollers raced with `select!`,
/// so the fast ready-file `stat` keeps its own `poll_interval` cadence and is
/// never starved behind a slow `container inspect`: a broker that becomes ready
/// while an inspect call is in flight is noticed immediately. `select!` is
/// `biased` toward readiness so a broker that raced ready-then-exit is reported
/// `Ok`, not as a crash.
///
/// Both pollers loop until they conclude; the caller wraps this in
/// `tokio::time::timeout(ready_timeout, …)`, which yields `ReadyTimeout` on a
/// healthy-but-slow VM and — via `kill_on_drop` — bounds a wedged `inspect`.
async fn wait_for_ready_or_exit(
    plan: &BrokerVmPlan,
    ready_file: &Path,
    poll_interval: Duration,
) -> Result<(), BrokerVmLaunchError> {
    tokio::select! {
        biased;
        result = poll_ready_file(ready_file, poll_interval) => result,
        result = poll_broker_liveness(plan, ready_file, poll_interval) => result,
    }
}

/// Poll `ready_file` every `poll_interval` until it appears (→ `Ok`). Runs on
/// its own cadence, independent of any `inspect` latency.
async fn poll_ready_file(
    ready_file: &Path,
    poll_interval: Duration,
) -> Result<(), BrokerVmLaunchError> {
    loop {
        if ready_file_exists(ready_file)? {
            return Ok(());
        }
        tokio::time::sleep(poll_interval).await;
    }
}

/// Poll the broker VM's lifecycle via `container inspect` every `poll_interval`;
/// return `ExitedBeforeReady` (with captured logs) the first time it is observed
/// terminal without the ready file present. A failure to run or parse `inspect`
/// (e.g. the VM is not yet created) is benign — it degrades to "not terminal"
/// and we keep polling. Never returns `Ok` on its own; readiness is the
/// [`poll_ready_file`] branch's job. `kill_on_drop` in the bounded runner means a
/// wedged inspect is killed when the caller's outer timeout drops this future.
async fn poll_broker_liveness(
    plan: &BrokerVmPlan,
    ready_file: &Path,
    poll_interval: Duration,
) -> Result<(), BrokerVmLaunchError> {
    loop {
        let inspect = plan.inspect_invocation();
        let inspected = inspect
            .run_capturing_output_bounded(BROKER_INSPECT_CAP_BYTES)
            .await;
        if let Ok(output) = inspected
            && output.status.is_some_and(|status| status.success())
            && let BrokerVmState::Terminal(state) = parse_broker_state(&output.stdout)
        {
            // The broker can bind, publish `ready`, and exit before this inspect
            // observes the terminal state; re-check the file so that benign race
            // is not misreported as a crash.
            if ready_file_exists(ready_file)? {
                return Ok(());
            }
            let logs = capture_broker_logs(plan).await;
            return Err(BrokerVmLaunchError::ExitedBeforeReady { state, logs });
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

/// Read the broker's ready file into a `String`, treating it as untrusted input
/// because it lives on the broker-controlled mount:
///
/// - `O_NOFOLLOW` refuses a symlink at `open`, so a compromised broker cannot
///   point `ready` at a host-readable file and leak its bytes through a parse
///   error.
/// - `O_NONBLOCK` means opening a FIFO returns immediately instead of blocking
///   the daemon forever waiting for a writer.
/// - The opened fd is `fstat`-checked to be a regular file before any read, so
///   a FIFO/socket/device is rejected rather than read.
/// - The read itself is capped at [`BROKER_READY_DOC_MAX_BYTES`]; an oversize
///   file is rejected rather than slurped.
fn read_ready_file_bounded(ready_file: &Path) -> Result<String, BrokerVmLaunchError> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let read_err = |source| BrokerVmLaunchError::ReadyRead {
        path: ready_file.display().to_string(),
        source,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(ready_file)
        .map_err(read_err)?;
    // Reject anything that is not a plain file (FIFO, socket, device, dir) — a
    // `O_NONBLOCK` FIFO opens fine, so this fstat is what actually refuses it.
    if !file.metadata().map_err(read_err)?.file_type().is_file() {
        return Err(BrokerVmLaunchError::ReadyNotRegularFile {
            path: ready_file.display().to_string(),
        });
    }
    // Read one byte past the cap so an over-cap file is detectable rather than
    // silently truncated into a doc that might parse.
    let mut buf = Vec::new();
    file.take(BROKER_READY_DOC_MAX_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(read_err)?;
    if buf.len() as u64 > BROKER_READY_DOC_MAX_BYTES {
        return Err(BrokerVmLaunchError::ReadyTooLarge {
            path: ready_file.display().to_string(),
            max: BROKER_READY_DOC_MAX_BYTES,
        });
    }
    String::from_utf8(buf).map_err(|_| {
        read_err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ready file was not valid UTF-8",
        ))
    })
}

/// Read and validate the broker's ready document once it has appeared: the
/// broker's protocol version must match this host's (a mismatch means a stale
/// broker image), and the port it bound must be the one the host assigned. A
/// legacy bare-port ready file from a pre-handshake image parses as protocol
/// version 0, so it too fails the version gate with an actionable error.
fn gate_ready_doc(ready_file: &Path, expected_port: BrokerPort) -> Result<(), BrokerVmLaunchError> {
    let contents = read_ready_file_bounded(ready_file)?;
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
/// the launch — if `container logs` is unavailable or slow we substitute a short
/// note so the error still explains what happened. The broker VM is already
/// known to have exited, so this is bounded by [`BROKER_LOG_CAPTURE_TIMEOUT`]:
/// a wedged `container logs` must not stall the fast crash path.
async fn capture_broker_logs(plan: &BrokerVmPlan) -> String {
    let logs = plan.logs_invocation();
    // `run_capturing_merged_tail` keeps the *newest* bytes, so when a chatty
    // crash exceeds the cap we retain the final lines (which carry the error).
    match tokio::time::timeout(
        BROKER_LOG_CAPTURE_TIMEOUT,
        logs.run_capturing_merged_tail(BROKER_LOG_CAPTURE_BYTES),
    )
    .await
    {
        Err(_elapsed) => {
            format!("(broker logs did not complete within {BROKER_LOG_CAPTURE_TIMEOUT:?})")
        }
        Ok(Err(err)) => format!("(could not read broker logs: {err})"),
        Ok(Ok(captured)) => {
            let trimmed = captured.text.trim();
            if trimmed.is_empty() {
                "(broker logs were empty)".to_string()
            } else if captured.truncated {
                format!("…{trimmed}")
            } else {
                trimmed.to_string()
            }
        }
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

    /// A fake `container` whose `inspect` blocks far longer than any test's ready
    /// timeout (modelling a wedged container service) and never publishes a ready
    /// file — used to prove the ready wait is bounded by `ready_timeout` even when
    /// the liveness probe itself stalls.
    fn write_fake_container_inspect_hangs(dir: &Path, args_log: &Path, sleep_secs: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let tool = dir.join("fake-container-inspect-hangs");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> "{log}"
if [ "$1" = inspect ]; then sleep {sleep_secs}; fi
exit 0
"#,
            log = args_log.display(),
            sleep_secs = sleep_secs,
        );
        std::fs::write(&tool, script).unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        tool
    }

    /// A fake `container` whose VM has exited (like [`write_fake_container_exited`])
    /// but whose `logs` subcommand *hangs* — modelling a wedged log retrieval. Used
    /// to prove the crash path still returns promptly (bounded by the log-capture
    /// timeout) instead of stalling out to the ready timeout.
    fn write_fake_container_exited_logs_hang(dir: &Path, args_log: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let tool = dir.join("fake-container-exited-logs-hang");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> "{log}"
if [ "$1" = inspect ]; then
  cat <<'JSON'
[ {{ "status": {{ "networks": [], "state": "stopped" }} }} ]
JSON
fi
if [ "$1" = logs ]; then exec sleep 300; fi
exit 0
"#,
            log = args_log.display(),
        );
        std::fs::write(&tool, script).unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        tool
    }

    /// A fake `container` whose `inspect` is *slow* (sleeps `sleep_secs`) but then
    /// answers with a healthy running-VM JSON carrying `broker_ip`. Models a
    /// container service under load: the ready-file poll must still notice a
    /// broker that becomes ready while an inspect call is in flight.
    fn write_fake_container_slow_inspect(
        dir: &Path,
        args_log: &Path,
        broker_ip: &str,
        sleep_secs: u32,
    ) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let tool = dir.join("fake-container-slow-inspect");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> "{log}"
if [ "$1" = inspect ]; then
  sleep {sleep_secs}
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
            sleep_secs = sleep_secs,
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
    async fn launch_times_out_even_when_inspect_hangs() {
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        // `inspect` blocks for a long time (120s) while the ready timeout is a
        // short 300ms, so the two possible outcomes are far apart in wall-clock:
        // a correct impl returns in ~ready_timeout because the outer
        // `tokio::time::timeout` preempts the in-flight (async, `kill_on_drop`)
        // inspect, whereas an impl that let a synchronous inspect block the
        // reactor could only return once inspect finished, i.e. ~120s. The
        // assertion bound sits between them (see below).
        let tool = write_fake_container_inspect_hangs(dir.path(), &args_log, 120);
        let plan = plan_with_tool(&tool, dir.path());
        let ready = dir.path().join("ready"); // never created

        let start = std::time::Instant::now();
        let err = launch_broker_vm(
            &plan,
            &ready,
            BrokerPort::new(18080).unwrap(),
            Duration::from_millis(300),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        let waited = start.elapsed();

        assert!(matches!(err, BrokerVmLaunchError::ReadyTimeout(_)), "{err}");
        // The bound only has to separate "bounded by ready_timeout" (~300ms) from
        // "bounded by the inspect hang" (~120s), so it is deliberately generous:
        // this is a current-thread runtime whose 300ms timer can fire seconds late
        // under heavy machine load (a full Nix build in parallel has been seen to
        // push it past 5s), and a real-time assertion tuned close to ready_timeout
        // flakes. 30s is well above any plausible scheduling slop yet far below
        // the 120s inspect hang, so it still fails loudly if the timeout ever stops
        // preempting a wedged inspect. `kill_on_drop` reaps the hung child the
        // moment the timeout fires, so the passing case never actually waits 120s.
        assert!(
            waited < Duration::from_secs(30),
            "the ready wait must be bounded by ready_timeout despite a hung inspect; waited {waited:?}"
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

    #[test]
    fn gate_ready_doc_rejects_an_oversize_ready_file() {
        // A stale/hostile broker can write an arbitrarily large ready file; the
        // gate must refuse it rather than slurp it whole. `{` keeps it plausibly
        // JSON-shaped so we know it's the size cap, not a parse error, firing.
        let dir = tempfile::tempdir().unwrap();
        let ready = dir.path().join("ready");
        let oversize = vec![b'{'; BROKER_READY_DOC_MAX_BYTES as usize + 4096];
        std::fs::write(&ready, oversize).unwrap();

        match gate_ready_doc(&ready, BrokerPort::new(18080).unwrap()) {
            Err(BrokerVmLaunchError::ReadyTooLarge { max, .. }) => {
                assert_eq!(max, BROKER_READY_DOC_MAX_BYTES);
            }
            other => panic!("expected ReadyTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn gate_ready_doc_accepts_a_ready_file_at_the_size_cap() {
        // A doc padded (via an ignored field) right up to the cap must still be
        // read and validated — the boundary is inclusive.
        let dir = tempfile::tempdir().unwrap();
        let ready = dir.path().join("ready");
        let mut doc = BrokerReadyDoc::current(18080).to_ready_file();
        let pad = BROKER_READY_DOC_MAX_BYTES as usize - doc.len();
        // A trailing comment/whitespace line the tolerant parser ignores.
        doc.push_str(&" ".repeat(pad));
        assert_eq!(doc.len() as u64, BROKER_READY_DOC_MAX_BYTES);
        std::fs::write(&ready, &doc).unwrap();

        gate_ready_doc(&ready, BrokerPort::new(18080).unwrap())
            .expect("a ready doc exactly at the cap must be accepted");
    }

    #[tokio::test]
    async fn launch_reports_a_placeholder_when_broker_log_capture_hangs() {
        // The broker VM exited, but `container logs` wedges. The crash path must
        // still return `ExitedBeforeReady` promptly (bounded by the log-capture
        // timeout) with a placeholder, not stall out to the ready timeout and
        // reintroduce the opaque long failure. (~BROKER_LOG_CAPTURE_TIMEOUT wall.)
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        let tool = write_fake_container_exited_logs_hang(dir.path(), &args_log);
        let plan = plan_with_tool(&tool, dir.path());
        let ready = dir.path().join("ready"); // never created

        let start = std::time::Instant::now();
        let err = launch_broker_vm(
            &plan,
            &ready,
            BrokerPort::new(18080).unwrap(),
            // Generous ready timeout: the log-capture bound must beat it by far.
            Duration::from_secs(120),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        let waited = start.elapsed();

        match err {
            BrokerVmLaunchError::ExitedBeforeReady { state, logs } => {
                assert_eq!(state, "stopped");
                assert!(
                    logs.contains("did not complete"),
                    "a wedged log capture should yield a timeout placeholder: {logs}"
                );
            }
            other => panic!("expected ExitedBeforeReady, got {other}"),
        }
        assert!(
            waited < BROKER_LOG_CAPTURE_TIMEOUT + Duration::from_secs(10),
            "the crash path must be bounded by the log-capture timeout, not the ready timeout; \
             waited {waited:?}"
        );
    }

    #[test]
    fn gate_ready_doc_refuses_a_symlinked_ready_file() {
        // The broker mount is untrusted: a `ready` symlink must not be followed,
        // or a compromised broker could point it at a host-readable file and leak
        // its first bytes through the `Malformed` parse error.
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("host-secret.txt");
        std::fs::write(&secret, "TOP-SECRET-HOST-CONTENTS").unwrap();
        let ready = dir.path().join("ready");
        std::os::unix::fs::symlink(&secret, &ready).unwrap();

        let err = gate_ready_doc(&ready, BrokerPort::new(18080).unwrap()).unwrap_err();
        assert!(
            !err.to_string().contains("TOP-SECRET"),
            "a symlinked host file's contents must never be read or leaked: {err}"
        );
    }

    #[test]
    fn gate_ready_doc_refuses_a_fifo_ready_file_without_hanging() {
        // A `ready` FIFO must be rejected, not opened-and-read, or the daemon
        // blocks forever waiting for a writer. Run in a thread so a regression
        // surfaces as a bounded timeout rather than hanging the whole suite.
        use std::os::unix::ffi::OsStrExt as _;
        let dir = tempfile::tempdir().unwrap();
        let ready = dir.path().join("ready");
        let c_path = std::ffi::CString::new(ready.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) },
            0,
            "mkfifo failed"
        );

        let (tx, rx) = std::sync::mpsc::channel();
        let ready_for_thread = ready.clone();
        std::thread::spawn(move || {
            let _ = tx.send(gate_ready_doc(
                &ready_for_thread,
                BrokerPort::new(18080).unwrap(),
            ));
        });
        let result = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("reading a FIFO ready file must not hang the daemon");
        assert!(
            matches!(result, Err(BrokerVmLaunchError::ReadyNotRegularFile { .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn launch_notices_readiness_even_while_inspect_is_slow() {
        // Regression: the ready-file poll must run on its own cadence, decoupled
        // from `container inspect` latency. A healthy broker can publish its ready
        // doc while an inspect call is stalled; the launch must notice the file
        // rather than wait out `ready_timeout` behind the slow inspect.
        let dir = tempfile::tempdir().unwrap();
        let args_log = dir.path().join("args.log");
        // inspect sleeps ~1s then reports a running VM; the ready timeout is
        // shorter, so an inspect-then-file loop would fire ReadyTimeout behind it.
        let tool = write_fake_container_slow_inspect(dir.path(), &args_log, "192.168.252.3", 1);
        let plan = plan_with_tool(&tool, dir.path());

        // The broker becomes ready shortly after launch begins — mid-inspect.
        let ready = dir.path().join("ready");
        let ready_writer = ready.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            std::fs::write(
                &ready_writer,
                BrokerReadyDoc::current(18080).to_ready_file(),
            )
            .unwrap();
        });

        let ip = tokio::time::timeout(
            Duration::from_secs(10),
            launch_broker_vm(
                &plan,
                &ready,
                BrokerPort::new(18080).unwrap(),
                // Shorter than the inspect sleep: the ready poll must win on its own.
                Duration::from_millis(600),
                Duration::from_millis(20),
            ),
        )
        .await
        .expect("launch must not hang")
        .expect("a broker that becomes ready during a slow inspect must be detected");
        assert_eq!(ip, Ipv4Addr::new(192, 168, 252, 3));
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
