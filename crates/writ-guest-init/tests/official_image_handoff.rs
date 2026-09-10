//! Stage B3's trusted evidence: the *official image*, started by a container
//! runtime under the locked capability profile, observed from the host.
//!
//! Stage B2 proved the interpreter against a bespoke user namespace. This test
//! proves the image the daemon will actually run: the runtime launches
//! `/bin/writ-agent-vm-guest-init` from the image as the container's initial
//! process with exactly `LOCKED_CAPABILITY_ARGV_PROFILE`, the host reads the
//! `security-ready` record from the container's log channel, reads PID 1's
//! status *before* releasing it (the awaiting-release acceptance type), sends
//! `USR1`, and then reads what the released workload printed: its own
//! `/proc/self/status` (the released acceptance type), `ip -6 addr` and
//! `ip -6 route`, and a smoke run of `git`, `nix`, `claude`, and `codex` as
//! UID 1000.
//!
//! Two runtimes drive the same sequence. On the Linux CI runner it is Docker,
//! against the x86_64 image loaded from the Nix-built OCI archive; on an Apple
//! Silicon host it is Apple `container`, against the aarch64 image, which is
//! the real platform. The two CLIs agree on every verb this test uses except
//! how the host reads PID 1's pre-release status (Docker exposes the host PID
//! to read `/proc` directly; `container` runs a VM, so it is read through a
//! pre-release `exec`, which the locked profile permits *before* release).
//!
//! `#[ignore]`d: it needs a runtime and a loaded image, named by environment
//! variables, so CI and a developer run it explicitly:
//!
//! ```sh
//! WRIT_GUEST_IMAGE_RUNTIME=docker WRIT_GUEST_IMAGE_REF=writ-agent-vm-guest:latest \
//!   cargo test -p writ-guest-init --test official_image_handoff -- --ignored
//! ```
//!
//! `WRIT_GUEST_IMAGE_TOOL` overrides the runtime's executable path.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use writ_guest_init::capability_argv::LOCKED_CAPABILITY_ARGV_PROFILE;
use writ_guest_init::proc_status::{LockedAwaitingRelease, LockedReleased, ProcStatus};
use writ_guest_init::record::{GuestInitRecord, ISOLATION_ABI_VERSION};

const INITIALIZER: &str = "/bin/writ-agent-vm-guest-init";
const RELEASED_MARKER: &str = "===RELEASED-WORKLOAD-RAN===";
const IPV6_ADDR_MARKER: &str = "===IPV6-ADDR===";
const IPV6_ROUTE_MARKER: &str = "===IPV6-ROUTE===";
const SMOKE_MARKER: &str = "===SMOKE===";
const DONE_MARKER: &str = "===DONE===";
const SMOKE_TOOLS: [&str; 4] = ["git", "nix", "claude", "codex"];

/// Booting a VM and chowning the Nix store take real time on the Apple
/// runtime; Docker is quicker. Both are bounded here.
const READY_DEADLINE: Duration = Duration::from_secs(180);
const DONE_DEADLINE: Duration = Duration::from_secs(180);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The workload the initializer releases into: everything the host wants to
/// see, bracketed by markers so the log can be sectioned.
fn workload_script() -> String {
    let smoke = SMOKE_TOOLS
        .iter()
        .map(|t| {
            format!(
                "if v=$({t} --version 2>&1); then echo \"SMOKE {t} ok: $v\"; \
                 else echo \"SMOKE {t} FAIL: $v\"; fi"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "echo {RELEASED_MARKER}\n\
         cat /proc/self/status\n\
         echo {IPV6_ADDR_MARKER}\n\
         ip -6 addr\n\
         echo {IPV6_ROUTE_MARKER}\n\
         ip -6 route\n\
         echo {SMOKE_MARKER}\n\
         echo \"uid=$(id -u) gid=$(id -g) groups=$(id -G)\"\n\
         {smoke}\n\
         echo {DONE_MARKER}\n"
    )
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Runtime {
    Docker,
    AppleContainer,
}

impl Runtime {
    fn from_env() -> Self {
        match std::env::var("WRIT_GUEST_IMAGE_RUNTIME").as_deref() {
            Ok("docker") => Self::Docker,
            Ok("apple-container") => Self::AppleContainer,
            other => panic!(
                "WRIT_GUEST_IMAGE_RUNTIME must be `docker` or `apple-container`, got {other:?}"
            ),
        }
    }

    fn default_tool(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::AppleContainer => "container",
        }
    }

    /// Runtime-specific `run` flags. Docker masks `/proc/sys` read-only by
    /// default, which would fail the IPv6 sysctl steps for a reason unrelated
    /// to the image, so it is asked for unconfined system paths (the test's
    /// container is not the thing being confined); it also gets no network,
    /// which leaves `lo` and the sysctl tree as the handoff needs them. The
    /// Apple runtime is left on its default network so the handoff runs
    /// against real vmnet router advertisements.
    fn run_flags(self) -> Vec<&'static str> {
        match self {
            Self::Docker => vec![
                "--network",
                "none",
                "--security-opt",
                "systempaths=unconfined",
            ],
            Self::AppleContainer => vec![],
        }
    }
}

struct Harness {
    runtime: Runtime,
    tool: String,
    image: String,
    name: String,
}

struct ToolOutput {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Harness {
    fn from_env() -> Self {
        let runtime = Runtime::from_env();
        let tool = std::env::var("WRIT_GUEST_IMAGE_TOOL")
            .unwrap_or_else(|_| runtime.default_tool().to_string());
        let image = std::env::var("WRIT_GUEST_IMAGE_REF")
            .expect("WRIT_GUEST_IMAGE_REF must name the loaded official image");
        let name = format!(
            "writ-b3-image-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        Self {
            runtime,
            tool,
            image,
            name,
        }
    }

    fn run_tool(&self, args: &[&str]) -> ToolOutput {
        let mut command = Command::new(&self.tool);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Through the workspace's retrying primitive, as the spawn-hygiene
        // guard requires.
        let output = writ_core::process_spawn::output(&mut command)
            .unwrap_or_else(|e| panic!("could not spawn {} {args:?}: {e}", self.tool));
        ToolOutput {
            ok: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    fn must(&self, args: &[&str]) -> ToolOutput {
        let out = self.run_tool(args);
        assert!(
            out.ok,
            "{} {args:?} failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.tool, out.stdout, out.stderr
        );
        out
    }

    /// Start the container detached: the initializer as the initial process,
    /// under exactly the locked capability profile, wrapping `workload`.
    fn start(&self, extra_env: &[(&str, &str)], workload: &str) {
        let mut args: Vec<&str> = vec!["run", "--detach", "--name", &self.name];
        args.extend(self.runtime.run_flags());
        args.extend(LOCKED_CAPABILITY_ARGV_PROFILE);
        args.extend(["--env", "HOME=/home/writ"]);
        let env_args: Vec<String> = extra_env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        for e in &env_args {
            args.extend(["--env", e.as_str()]);
        }
        args.extend([self.image.as_str(), INITIALIZER, "sh", "-c", workload]);
        self.must(&args);
    }

    fn logs(&self) -> String {
        let out = self.run_tool(&["logs", &self.name]);
        // Both runtimes interleave the container's stderr into the log
        // channel; a failed `logs` (container gone) yields what it printed.
        format!("{}{}", out.stdout, out.stderr)
    }

    /// Poll the log channel until `pred` holds, or the deadline passes.
    fn wait_for_log(&self, deadline: Duration, what: &str, pred: impl Fn(&str) -> bool) -> String {
        let start = Instant::now();
        loop {
            let logs = self.logs();
            if pred(&logs) {
                return logs;
            }
            if start.elapsed() > deadline {
                self.cleanup();
                panic!("timed out after {deadline:?} waiting for {what}\n--- logs ---\n{logs}");
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// PID 1's `/proc/<pid>/status`, read from the host side before release.
    fn awaiting_status(&self) -> String {
        match self.runtime {
            Runtime::Docker => {
                let pid = self
                    .must(&["inspect", "-f", "{{.State.Pid}}", &self.name])
                    .stdout
                    .trim()
                    .to_string();
                assert!(
                    pid.parse::<u32>().is_ok_and(|p| p > 0),
                    "docker did not report a host PID for the container: {pid:?}"
                );
                std::fs::read_to_string(format!("/proc/{pid}/status"))
                    .unwrap_or_else(|e| panic!("read host /proc/{pid}/status: {e}"))
            }
            Runtime::AppleContainer => {
                self.must(&["exec", &self.name, "cat", "/proc/1/status"])
                    .stdout
            }
        }
    }

    fn release(&self) {
        self.must(&["kill", "--signal", "USR1", &self.name]);
    }

    fn cleanup(&self) {
        match self.runtime {
            Runtime::Docker => {
                self.run_tool(&["rm", "-f", &self.name]);
            }
            Runtime::AppleContainer => {
                self.run_tool(&["stop", &self.name]);
                self.run_tool(&["rm", &self.name]);
            }
        }
    }
}

fn record_lines(logs: &str) -> Vec<&str> {
    logs.lines()
        .filter(|l| l.starts_with("writ-agent-vm-guest-init"))
        .collect()
}

fn section<'a>(logs: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let (_, rest) = logs.split_once(start)?;
    let (body, _) = rest.split_once(end)?;
    Some(body)
}

#[test]
#[ignore = "needs a container runtime and the built official image; see the module docs. Run with --ignored"]
fn official_image_handoff_releases_to_the_locked_identity_and_tools_run() {
    let harness = Harness::from_env();
    harness.start(&[], &workload_script());

    // 1. The ready record appears, exactly as the ABI spells it, before any
    //    release; a failure record here is the image failing its own handoff.
    let logs = harness.wait_for_log(READY_DEADLINE, "the security-ready record", |logs| {
        !record_lines(logs).is_empty()
    });
    let records = record_lines(&logs);
    assert_eq!(
        records.len(),
        1,
        "expected exactly one record before release, got {records:?}\n--- logs ---\n{logs}"
    );
    assert_eq!(
        GuestInitRecord::parse(records[0]),
        Ok(GuestInitRecord::SecurityReady {
            abi: ISOLATION_ABI_VERSION
        }),
        "record line {:?}\n--- logs ---\n{logs}",
        records[0]
    );
    assert!(
        !logs.contains(RELEASED_MARKER),
        "the workload ran before the host released it\n--- logs ---\n{logs}"
    );

    // 2. Host-observed: PID 1 parked in the release wait is the locked
    //    identity with USR1 visibly blocked.
    let awaiting_text = harness.awaiting_status();
    let awaiting = ProcStatus::parse(awaiting_text.trim()).unwrap_or_else(|e| {
        harness.cleanup();
        panic!("pre-release PID 1 status did not parse: {e}\n{awaiting_text}")
    });
    if let Err(violations) = LockedAwaitingRelease::verify(&awaiting) {
        harness.cleanup();
        panic!(
            "parked PID 1 is not the awaiting-release locked identity (the host would refuse \
             to release it): {violations:?}\n{awaiting_text}"
        );
    }

    // 3. Release, and wait for the workload to finish.
    harness.release();
    let logs = harness.wait_for_log(DONE_DEADLINE, "the workload to finish", |logs| {
        logs.contains(DONE_MARKER)
    });
    harness.cleanup();

    // The record was emitted once, not again after release.
    assert_eq!(
        record_lines(&logs).len(),
        1,
        "the ready record must be emitted exactly once\n--- logs ---\n{logs}"
    );

    // 4. The released workload's own status is the locked identity.
    let status_text = section(&logs, RELEASED_MARKER, IPV6_ADDR_MARKER)
        .unwrap_or_else(|| panic!("no released status section\n--- logs ---\n{logs}"));
    let status = ProcStatus::parse(status_text.trim())
        .unwrap_or_else(|e| panic!("released status did not parse: {e}\n{status_text}"));
    LockedReleased::verify(&status).unwrap_or_else(|violations| {
        panic!("released workload is not the locked identity: {violations:?}\n{status_text}")
    });

    // 5. No IPv6 address or live route survived, as seen by iproute2 in the
    //    released guest (the initializer verified this itself; the host does
    //    not take its word for it).
    let addrs = section(&logs, IPV6_ADDR_MARKER, IPV6_ROUTE_MARKER)
        .unwrap_or_else(|| panic!("no ip -6 addr section\n--- logs ---\n{logs}"));
    let stray_addrs: Vec<&str> = addrs
        .lines()
        .filter(|l| l.contains("inet6") && !l.contains("::1/128"))
        .collect();
    assert!(
        stray_addrs.is_empty(),
        "IPv6 addresses survived the handoff: {stray_addrs:?}\n{addrs}"
    );
    let routes = section(&logs, IPV6_ROUTE_MARKER, SMOKE_MARKER)
        .unwrap_or_else(|| panic!("no ip -6 route section\n--- logs ---\n{logs}"));
    let live_routes: Vec<&str> = routes
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|l| {
            !(l.starts_with("::1 ")
                || l.starts_with("unreachable ")
                || l.starts_with("prohibit ")
                || l.starts_with("blackhole "))
        })
        .collect();
    assert!(
        live_routes.is_empty(),
        "live IPv6 routes survived the handoff: {live_routes:?}\n{routes}"
    );

    // 6. Smoke: the identity is 1000:1000 with no supplementary groups, and
    //    each tool starts and prints a version as that identity.
    let smoke = section(&logs, SMOKE_MARKER, DONE_MARKER)
        .unwrap_or_else(|| panic!("no smoke section\n--- logs ---\n{logs}"));
    assert!(
        smoke
            .lines()
            .any(|l| l.trim() == "uid=1000 gid=1000 groups=1000"),
        "workload identity is not 1000:1000 with no supplementary groups\n{smoke}"
    );
    for tool in SMOKE_TOOLS {
        assert!(
            smoke
                .lines()
                .any(|l| l.starts_with(&format!("SMOKE {tool} ok:"))),
            "{tool} did not start as the locked identity\n{smoke}"
        );
    }
}

/// A handoff step that fails inside the image prevents `exec`: one bounded
/// failure record, and the workload never runs. Injected by pointing the
/// Nix-store directory under a regular file so creating it fails, exactly as
/// the B2 test does, but through the image's own initializer.
#[test]
#[ignore = "needs a container runtime and the built official image; see the module docs. Run with --ignored"]
fn official_image_injected_failure_prevents_exec() {
    let harness = Harness::from_env();
    harness.start(
        &[("WRIT_GUEST_INIT_NIX_STORE_DIR", "/etc/passwd/nope")],
        "echo THIS-MUST-NOT-PRINT",
    );
    harness.wait_for_log(READY_DEADLINE, "a record line", |logs| {
        !record_lines(logs).is_empty()
    });
    // Give a wrongly-released workload time to print, then read the whole log
    // once more and stop looking.
    std::thread::sleep(Duration::from_secs(2));
    let logs = harness.logs();
    harness.cleanup();

    let records = record_lines(&logs);
    assert_eq!(
        records.len(),
        1,
        "expected exactly one record, got {records:?}\n--- logs ---\n{logs}"
    );
    match GuestInitRecord::parse(records[0]) {
        Ok(GuestInitRecord::HandoffFailed { .. }) => {}
        other => panic!(
            "expected a HandoffFailed record, got {other:?} from {:?}",
            records[0]
        ),
    }
    assert!(
        !logs.contains("THIS-MUST-NOT-PRINT"),
        "the workload ran after a failed handoff\n--- logs ---\n{logs}"
    );
}
