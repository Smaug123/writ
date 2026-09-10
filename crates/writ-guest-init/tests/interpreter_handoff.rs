//! The interpreter, run for real and observed from the host side.
//!
//! This is Stage B2's trusted evidence: the binary performs the whole handoff
//! against a real kernel, and the host reads the released `/proc/self/status`.
//! On the actual hardware the interpreter is PID 1 in an Apple `container`
//! guest launched with the locked capability profile; CI has neither, so the
//! test reproduces the essential environment with an *unprivileged* user
//! namespace: inside it the process is uid 0 with a full capability set and a
//! private network and mount namespace, exactly the authority the handoff
//! consumes and then discards. Reaching the locked identity's fixed uid 1000
//! needs a mapped sub-uid range, which `unshare --map-auto` sets up via
//! `newuidmap`/`newgidmap`; CI runners provide a `/etc/subuid` range and the
//! setuid helpers. The handoff chowns its directories to that sub-uid, which
//! only works on a filesystem the user namespace owns, so the namespace mounts
//! its own tmpfs for them (see `namespace_program`).
//!
//! The whole thing is Linux-only. On any other target it compiles to nothing.
//!
//! Both tests are `#[ignore]`d, so they compile (and are clippy-checked) in CI
//! but do not run there. They cannot: a GitHub runner's `/` carries locked,
//! shared mounts, so an unprivileged nested user namespace can neither make `/`
//! private (`unshare --mount` is denied) nor add a mount to the shared tree
//! (it would propagate into the host namespace) — and without a tmpfs the
//! namespace owns, the handoff's chown to the mapped sub-uid is refused. Run
//! them on demand on a user-namespace-capable host (a `/etc/subuid` range plus
//! setuid `newuidmap`/`newgidmap`, and a `/` a nested userns may remount):
//! `cargo test -p writ-guest-init --test interpreter_handoff -- --ignored`.
//! The runtime evidence CI and the hardware rely on comes instead from Stage
//! B3's official-image integration test and Stage E3's on-hardware proof.

#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};

use writ_guest_init::proc_status::{LockedAwaitingRelease, LockedReleased, ProcStatus};
use writ_guest_init::record::{GuestInitRecord, ISOLATION_ABI_VERSION};

/// The interpreter binary, built by cargo for this test.
const BIN: &str = env!("CARGO_BIN_EXE_writ-agent-vm-guest-init");
/// The line the success-path workload prints before its status, so the host
/// can find where the interpreter's output ends and the workload's begins.
const RELEASED_MARKER: &str = "===RELEASED-WORKLOAD-RAN===";
/// Markers bracketing PID 1's status as read while parked in the release wait.
const AWAITING_START: &str = "===AWAITING-STATUS===";
const AWAITING_END: &str = "===END-AWAITING-STATUS===";

/// The program run inside the user+net+mount namespace. The fixed directories
/// live on a `tmpfs` the namespace mounts itself: the interpreter chowns them
/// to a mapped sub-uid, and a nested user namespace can only do that on a
/// filesystem its own user namespace owns — a pre-existing disk filesystem
/// (owned by the initial user namespace) refuses the chown with `EPERM`. The
/// mount namespace is entered with `--propagation unchanged`, because the
/// default `make-rprivate /` that `unshare --mount` performs is itself refused
/// on a runner whose `/` carries locked mounts; instead the tmpfs mountpoint is
/// bind-mounted to itself and made private on its own, so the tmpfs neither
/// needs a root-propagation change nor leaks back to the host. Interfaces still
/// come from `/proc/net/dev` and the IPv6 sysctls from `/proc/sys/net`, both of
/// which follow the network namespace, so the fresh netns shows only `lo`
/// without any sysfs mount.
///
/// The interpreter runs as a child rather than via `exec`, so the script
/// survives it: it waits for the handoff to park in the release wait, then
/// captures PID 1's `/proc/<pid>/status` exactly as the host would read it —
/// the awaiting-release status, in which `SIGUSR1` must be *visibly* blocked —
/// before releasing it with `SIGUSR1`. The release is safe whenever it lands:
/// the interpreter blocks `SIGUSR1` as its very first action, and because the
/// wait is armed before the record is emitted, a signal that arrives during the
/// handoff is held pending and consumed by the wait.
fn namespace_program(env_lines: &str, workload: &str) -> String {
    format!(
        r#"set -eu
d=$(mktemp -d)
mount --bind "$d" "$d"
mount --make-private "$d"
mount -t tmpfs tmpfs "$d"
mkdir -p "$d/run" "$d/home" "$d/workspace" "$d/nix"
export WRIT_GUEST_INIT_RUNTIME_DIR="$d/run"
export WRIT_GUEST_INIT_HOME_DIR="$d/home"
export WRIT_GUEST_INIT_WORKSPACE_DIR="$d/workspace"
export WRIT_GUEST_INIT_NIX_STORE_DIR="$d/nix"
{env_lines}
"{BIN}" {workload} &
pid=$!
sleep 1
echo "===AWAITING-STATUS==="
cat "/proc/$pid/status" 2>/dev/null || true
echo "===END-AWAITING-STATUS==="
kill -USR1 "$pid" 2>/dev/null || true
if wait "$pid"; then rc=0; else rc=$?; fi
exit "$rc"
"#
    )
}

/// Run the namespace program under an unprivileged user namespace and return
/// (stdout, stderr, exit_ok). Panics with diagnostics if `unshare` cannot be
/// spawned at all.
fn run_in_userns(env_lines: &str, workload: &str) -> (String, String, bool) {
    let program = namespace_program(env_lines, workload);
    let mut command = Command::new("unshare");
    command
        .args([
            "--user",
            "--net",
            "--mount",
            "--propagation",
            "unchanged",
            "--map-root-user",
            "--map-auto",
            "bash",
            "-c",
            &program,
        ])
        // `process_spawn::output` inherits stdio by default, so ask for the
        // pipes the host reads back explicitly, and give the child EOF on stdin.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Spawn through the workspace's retrying primitive, as the spawn-hygiene
    // guard requires: a spawn the OS refuses outright is retried, not reported
    // as a failure.
    let output = writ_core::process_spawn::output(&mut command).unwrap_or_else(|e| {
        panic!(
            "could not spawn `unshare` (needed for the unprivileged user \
             namespace this test runs the interpreter in): {e}"
        )
    });
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.success(),
    )
}

/// Releasing the handoff yields the locked identity, run enough times that a
/// signal-timing regression (a release wait armed too late) would show as a
/// terminated process on some run. The wait is armed before readiness, so the
/// workload runs every time.
#[test]
#[ignore = "needs an unprivileged-userns-capable host; see the module docs. Run with --ignored"]
fn userns_locked_handoff_releases_to_the_locked_identity() {
    let workload = "sh -c 'echo ===RELEASED-WORKLOAD-RAN===; cat /proc/self/status'";
    for iteration in 0..5 {
        let (stdout, stderr, ok) = run_in_userns("", workload);
        assert!(
            ok,
            "iteration {iteration}: interpreter did not exit cleanly\n\
             --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        );

        // The ready record is emitted, exactly as the ABI spells it.
        let ready_line = stdout
            .lines()
            .find(|l| l.starts_with("writ-agent-vm-guest-init"))
            .unwrap_or_else(|| {
                panic!(
                    "iteration {iteration}: no record line\nstdout:\n{stdout}\nstderr:\n{stderr}"
                )
            });
        assert_eq!(
            GuestInitRecord::parse(ready_line),
            Ok(GuestInitRecord::SecurityReady {
                abi: ISOLATION_ABI_VERSION
            }),
            "iteration {iteration}: ready line {ready_line:?}"
        );

        // While parked, PID 1's status is exactly what the host's release gate
        // reads and requires: the locked identity with SIGUSR1 *visibly*
        // blocked. This is what a `sigwait`-based wait would fail (the kernel
        // clears the waited signal from the visible mask), so it is checked
        // here, not only the released status below.
        let awaiting_text = stdout
            .split_once(AWAITING_START)
            .and_then(|(_, rest)| rest.split_once(AWAITING_END))
            .map(|(section, _)| section)
            .unwrap_or_else(|| {
                panic!("iteration {iteration}: no awaiting-status section\nstdout:\n{stdout}\nstderr:\n{stderr}")
            });
        let awaiting = ProcStatus::parse(awaiting_text.trim()).unwrap_or_else(|e| {
            panic!("iteration {iteration}: awaiting status did not parse: {e}\n{awaiting_text}")
        });
        LockedAwaitingRelease::verify(&awaiting).unwrap_or_else(|violations| {
            panic!(
                "iteration {iteration}: parked PID 1 is not the awaiting-release locked identity \
                 (the host would reject it): {violations:?}"
            )
        });

        // The workload ran (the wait was armed), and its /proc/self/status is
        // the released locked identity: uid/gid 1000, no caps, NoNewPrivs, and
        // SIGUSR1 unblocked again.
        let status_text = stdout
            .split_once(RELEASED_MARKER)
            .map(|(_, rest)| rest)
            .unwrap_or_else(|| {
                panic!(
                    "iteration {iteration}: workload never ran (release wait not armed?)\n\
                 stdout:\n{stdout}\nstderr:\n{stderr}"
                )
            });
        let status = ProcStatus::parse(status_text.trim()).unwrap_or_else(|e| {
            panic!("iteration {iteration}: released status did not parse: {e}\n{status_text}")
        });
        LockedReleased::verify(&status).unwrap_or_else(|violations| {
            panic!(
                "iteration {iteration}: released status is not the locked identity: {violations:?}"
            )
        });
    }
}

/// A step that fails aborts the handoff: one bounded failure record is
/// emitted, the workload never runs, and the interpreter exits non-zero.
/// Injected by pointing the Nix-store directory under a regular file, so
/// creating it fails.
#[test]
#[ignore = "needs an unprivileged-userns-capable host; see the module docs. Run with --ignored"]
fn userns_injected_failure_prevents_exec_and_emits_one_failure_record() {
    let env_lines = "touch \"$d/afile\"\nexport WRIT_GUEST_INIT_NIX_STORE_DIR=\"$d/afile/nope\"";
    let workload = "sh -c 'echo THIS-MUST-NOT-PRINT'";
    let (stdout, stderr, ok) = run_in_userns(env_lines, workload);

    assert!(
        !ok,
        "the interpreter must fail when a handoff step cannot run\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("THIS-MUST-NOT-PRINT"),
        "the workload ran after a failed handoff\nstdout:\n{stdout}"
    );

    let record_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.starts_with("writ-agent-vm-guest-init"))
        .collect();
    assert_eq!(
        record_lines.len(),
        1,
        "expected exactly one record, got {record_lines:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    match GuestInitRecord::parse(record_lines[0]) {
        Ok(GuestInitRecord::HandoffFailed { .. }) => {}
        other => panic!(
            "expected a HandoffFailed record, got {other:?} from {:?}",
            record_lines[0]
        ),
    }
}
