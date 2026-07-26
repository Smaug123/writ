//! Supervise a host subprocess with a timeout and process-group SIGKILL.
//!
//! Several host flows shell out to long-running tools against untrusted
//! inputs — VM clone/push replay drive `git`, flake-input provisioning
//! drives `nix flake archive`. Each independently needs the same delicate
//! mechanism: resolve the program before the environment is cleared, spawn
//! it as the leader of its own process group, bound its wall-clock with a
//! timeout, and on timeout (or even on normal exit) SIGKILL the whole group
//! so no helper the tool forked into the group can outlive it or hold a
//! captured stdout pipe open.
//!
//! This module is that shared core. Callers own the policy: they build the
//! [`Command`] (program, argv, env, cwd, stdin) and map the
//! program-agnostic [`SupervisorError`] into their own step-tagged error
//! types. The supervisor owns only the parts that are subtle and must not
//! diverge between callers: the race-free `waitid(WNOWAIT)` observation, the
//! process-group kill, and the stdout/stderr drains.

use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::process::Command;

use crate::process_spawn;

mod capture;

use capture::{Absorb, CaptureBuffer, CapturePolicy};

const CHILD_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Upper bound on captured stderr. A [`StderrMode::Capture`] child's stderr is
/// drained to EOF (so it never stalls on a full pipe) but only a line-aligned
/// tail of at most this many bytes is retained: a verbose or hostile child
/// cannot make the host buffer unbounded diagnostics, and a tool's fatal
/// message is typically its last line, so the tail is the informative part.
pub(crate) const STDERR_CAPTURE_TAIL_CAP: usize = 8 * 1024;

/// Whether the supervisor should capture the child's stdout or discard it.
///
/// Stdin is the caller's responsibility (set on the [`Command`] before calling
/// [`run_supervised`]); the supervisor manages stdout and stderr because those
/// are the channels whose pipes it must drain to avoid a deadlock against a
/// child that writes more than one pipe buffer's worth.
///
/// [`Capture`](StdoutMode::Capture) carries an explicit `byte_cap`: the drain
/// retains at most that many bytes, and a child that writes more is rejected
/// (the group is SIGKILLed and the run surfaces
/// [`SupervisedOutcome::StdoutCapExceeded`]) instead of letting the host buffer
/// unbounded output. Callers that process untrusted input (a guest-controlled
/// git bundle whose `rev-list` output the broker parses one object per line)
/// rely on this bound to keep a hostile input from OOM-killing the broker.
#[derive(Copy, Clone)]
pub(crate) enum StdoutMode {
    Discard,
    Capture { byte_cap: usize },
}

/// Whether the supervisor should capture the child's stderr or discard it.
///
/// Capture is bounded (see [`STDERR_CAPTURE_TAIL_CAP`]) and tail-biased, so it
/// is safe even against a child that streams unbounded diagnostics. Callers
/// that must not retain any child diagnostics at all (e.g. a hostile flake
/// evaluation) pass [`StderrMode::Discard`].
#[derive(Copy, Clone)]
pub(crate) enum StderrMode {
    Discard,
    Capture,
}

/// The result of a supervised run that spawned and was waited on without a
/// supervisor-level failure. A non-zero exit is *not* an error here — it is
/// reported as [`SupervisedOutcome::Exited`] with the failing status, so the
/// caller decides whether a non-success exit is fatal for its flow.
pub(crate) enum SupervisedOutcome {
    Exited {
        status: ExitStatus,
        /// The child provably never ran a single instruction, so re-running it
        /// repeats nothing — see [`child_vanished_before_running`]. Only ever
        /// true on the blocking arm, which is where the observation is taken.
        ///
        /// A caller may use this to retry an otherwise **non-idempotent**
        /// command: the claim is not "this command is safe to repeat" but "this
        /// child had no effect to repeat".
        ran_nothing: bool,
        stdout: Vec<u8>,
        /// Line-aligned tail-capped stderr when the run used
        /// [`StderrMode::Capture`], empty under [`StderrMode::Discard`]. Not yet
        /// redacted — a caller that may have bound a secret into the child's
        /// environment must sanitise this before surfacing it. The line
        /// alignment guarantees truncation can only strand *complete* lines, so
        /// a caller redacting per line/segment need never chase a mid-line
        /// fragment left by the cap.
        stderr: Vec<u8>,
    },
    TimedOut,
    /// The child wrote more than the [`StdoutMode::Capture`] `byte_cap` to
    /// stdout, so the supervisor stopped draining and SIGKILLed the whole
    /// group. `cap` is the exceeded bound. No stdout is returned: it is
    /// deliberately discarded rather than surfaced truncated, because a caller
    /// that parses the output (e.g. one object per `rev-list` line) must reject
    /// the whole run, not act on a prefix. Only ever produced under
    /// [`StdoutMode::Capture`]; a [`StdoutMode::Discard`] run cannot reach it.
    StdoutCapExceeded {
        cap: usize,
    },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SupervisorError {
    #[error(
        "program must be absolute or discoverable on PATH before clearing the child environment: {0}"
    )]
    ProgramNotFound(PathBuf),
    #[error("cannot canonicalize {field} path {path}: {source}")]
    Canonicalize {
        field: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("command could not be spawned: {0}")]
    Spawn(std::io::Error),
    #[error("command wait failed: {0}")]
    Wait(std::io::Error),
    #[error("command did not expose a child process id")]
    MissingProcessId,
    #[error("child process id {0} cannot be represented as a process group id")]
    InvalidProcessId(u32),
    #[error("process group {pgid} could not be killed after child exit: {source}")]
    KillProcessGroup {
        pgid: libc::pid_t,
        source: std::io::Error,
    },
    #[error("writing the child's stdin failed after {written} of {total} bytes: {source}")]
    StdinWrite {
        written: usize,
        total: usize,
        source: std::io::Error,
    },
    #[error("reading the child's captured stdout failed: {0}")]
    CaptureRead(std::io::Error),
}

/// Spawn `command` as a process-group leader, wait up to `timeout` for it to
/// exit, then SIGKILL the whole group regardless of outcome.
///
/// The caller must have fully configured `command` (program, argv, env, cwd,
/// stdin) *except* stdout, stderr, and the process group, which this function
/// sets from `stdout_mode`/`stderr_mode` and `process_group(0)` so the
/// kill-the-group contract holds. The returned [`SupervisedOutcome`]
/// distinguishes a clean exit (with its status and any captured stdout/stderr)
/// from a timeout.
pub(crate) async fn run_supervised(
    command: &mut Command,
    timeout: Duration,
    stdout_mode: StdoutMode,
    stderr_mode: StderrMode,
) -> Result<SupervisedOutcome, SupervisorError> {
    let stdout_byte_cap = match stdout_mode {
        StdoutMode::Discard => None,
        StdoutMode::Capture { byte_cap } => Some(byte_cap),
    };
    command.stdout(match stdout_mode {
        StdoutMode::Discard => Stdio::null(),
        StdoutMode::Capture { .. } => Stdio::piped(),
    });
    command.stderr(match stderr_mode {
        StderrMode::Discard => Stdio::null(),
        StderrMode::Capture => Stdio::piped(),
    });
    command.process_group(0);

    let mut child = process_spawn::spawn_async(command)
        .await
        .map_err(SupervisorError::Spawn)?;
    let pid = child.id().ok_or(SupervisorError::MissingProcessId)?;
    let pgid = process_group_id(pid)?;
    // Set by the stdout drain when the child exceeds `byte_cap`. It is a
    // one-way, monotonic wake-up hint: the poll loop reads it each tick so it
    // can break out promptly and SIGKILL the group instead of blocking on a
    // child that has stalled writing into the now-unread pipe until the
    // wall-clock timeout fires. The drain's return value stays authoritative —
    // the `Exited` arm re-checks the flag after joining the drain to close the
    // race where the child exits in the same tick the cap is crossed.
    let stdout_capped = Arc::new(AtomicBool::new(false));
    // Drain stdout/stderr concurrently with the child's lifetime so a child
    // that writes more than one pipe buffer's worth before we reach `wait()`
    // cannot stall on a full pipe. A drain task only reaches EOF once every fd
    // pointing at the write end is closed — that includes any helper the tool
    // forked into the same process group, so we rely on the group SIGKILL
    // further down to close inherited pipes when the leader has exited.
    let stdout_drain = match stdout_byte_cap {
        None => None,
        Some(byte_cap) => {
            let stdout = child
                .stdout
                .take()
                .expect("stdout was configured as Stdio::piped()");
            Some(tokio::spawn(drain_under_policy(
                stdout,
                CapturePolicy::RejectOverCap { cap: byte_cap },
                Arc::clone(&stdout_capped),
            )))
        }
    };
    let stderr_drain = match stderr_mode {
        StderrMode::Discard => None,
        StderrMode::Capture => {
            let stderr = child
                .stderr
                .take()
                .expect("stderr was configured as Stdio::piped()");
            Some(tokio::spawn(drain_under_policy(
                stderr,
                CapturePolicy::TailCap {
                    cap: STDERR_CAPTURE_TAIL_CAP,
                },
                // Its own flag, never read: a tail cap truncates instead of
                // overrunning, so stderr must not be able to trip the stdout
                // cap rejection even if the policy were changed later.
                Arc::new(AtomicBool::new(false)),
            )))
        }
    };
    let mut cleanup_guard = ProcessGroupCleanupGuard::new(pgid);
    match wait_for_child_exit_before_reap(pgid, timeout, &stdout_capped).await? {
        ChildExitObservation::Exited => {
            cleanup_guard.mark_child_exit_observed();
            cleanup_guard.kill_now()?;
            let status = child.wait().await;
            cleanup_guard.disarm();
            let status = status.map_err(SupervisorError::Wait)?;
            let stdout = match stdout_drain {
                Some(handle) => handle.await.unwrap_or_default(),
                None => Vec::new(),
            };
            let stderr = match stderr_drain {
                Some(handle) => handle.await.unwrap_or_default(),
                None => Vec::new(),
            };
            // Race backstop: the child may have written past the cap and exited
            // before the poll loop observed the flag. The drain has now fully
            // joined, so the flag is settled — reject rather than surface the
            // over-cap prefix.
            if stdout_capped.load(Ordering::Acquire) {
                return Ok(SupervisedOutcome::StdoutCapExceeded {
                    cap: stdout_byte_cap.expect("cap only set under Capture"),
                });
            }
            Ok(SupervisedOutcome::Exited {
                status,
                // The async arm takes no proof-of-life probe: its callers replay
                // git against a staging repo and do not want an automatic re-run.
                ran_nothing: false,
                stdout,
                stderr,
            })
        }
        ChildExitObservation::StdoutCapExceeded => {
            // The child overran the stdout cap and the drain stopped reading and
            // dropped the read end of the pipe. A child mid-write then takes
            // SIGPIPE and dies before we reach `killpg`, so — exactly as in the
            // `Exited` arm — `killpg` can find no live member and report a benign
            // EPERM on macOS. Mark the exit as observed so that EPERM is
            // tolerated: we own this group (we created it with `process_group(0)`)
            // and can always signal a live member, so EPERM here can only mean
            // the group is already empty, never a real permission failure.
            cleanup_guard.mark_child_exit_observed();
            cleanup_guard.kill_now()?;
            let _ = child.wait().await;
            cleanup_guard.disarm();
            if let Some(handle) = stdout_drain {
                let _ = handle.await;
            }
            if let Some(handle) = stderr_drain {
                let _ = handle.await;
            }
            Ok(SupervisedOutcome::StdoutCapExceeded {
                cap: stdout_byte_cap.expect("cap only set under Capture"),
            })
        }
        ChildExitObservation::TimedOut => {
            cleanup_guard.kill_now()?;
            let _ = child.wait().await;
            cleanup_guard.disarm();
            if let Some(handle) = stdout_drain {
                let _ = handle.await;
            }
            if let Some(handle) = stderr_drain {
                let _ = handle.await;
            }
            Ok(SupervisedOutcome::TimedOut)
        }
    }
}

/// Drain `reader` under `policy`, publishing an overrun to `capped` as soon as
/// it happens so the supervisor's poll loop can break out and SIGKILL the group
/// rather than waiting for the wall clock.
///
/// The whole stream is consumed under [`CapturePolicy::TailCap`] so the child
/// never stalls on a full pipe; under [`CapturePolicy::RejectOverCap`] the drain
/// stops at the overrun, because the capture is already void and the group is
/// about to die. Read errors end the drain with whatever was accumulated so far
/// (best-effort: a diagnostic is not worth failing a run over). All byte
/// accounting — the bound, the tail alignment, the discard-on-overrun — lives in
/// [`CaptureBuffer`], shared with the blocking supervisor.
async fn drain_under_policy<R>(
    mut reader: R,
    policy: CapturePolicy,
    capped: Arc<AtomicBool>,
) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buffer = CaptureBuffer::new(policy);
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buffer.push(&chunk[..n]) == Absorb::Stop {
                    if buffer.overran() {
                        capped.store(true, Ordering::Release);
                    }
                    break;
                }
            }
        }
    }
    buffer.finish()
}

/// Proof-of-life probe, taken immediately after `spawn()` returns and before we
/// touch the child: `true` when `getpgid(pid)` reports `ESRCH`.
///
/// This is *proof the child never ran*, not a heuristic, and the reason is the
/// zombie rule. We have not reaped the child yet, so a process that had run and
/// exited — however briefly, however it died — would still hold an unreaped
/// entry in the process table, and `getpgid` on it would succeed. `ESRCH` means
/// there is no entry at all: the pid we were handed never became a live process.
///
/// This is the mark left by the macOS "phantom SIGKILL" (see
/// `docs/known-test-flakes.md`): `spawn()` succeeds and yields a pid whose
/// process is already gone microseconds later. Roughly 1 spawn in 2000 under the
/// parallel test suite's load.
///
/// Being a probe of a *live* condition it can only race one way: if the kernel
/// has not yet torn the entry down we return `false` and decline to report a
/// vanish. That is the safe direction — a missed retry is a rare test failure, a
/// wrongly-granted one could re-run a command that had already taken effect.
///
/// Introduced in `f36b4c0` against `notes_repo`'s own spawn; it lives here now
/// because the supervisor owns the spawn, and the observation has to be taken
/// between `spawn` and `wait`.
pub(crate) fn child_vanished_before_running(pid: u32) -> bool {
    // SAFETY: `getpgid` is async-signal-safe and reads no memory we own.
    let probed = unsafe { libc::getpgid(pid as libc::pid_t) };
    probed == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

/// Whether a finished child provably ran nothing, and so may be re-run.
///
/// Both conjuncts are load-bearing:
///
/// * `vanished_before_running` — the [`child_vanished_before_running`] proof.
///   This is what makes a retry safe *irrespective of the command*: it does not
///   assume `notes add` or `update-ref` may be repeated, it establishes that this
///   child never ran, so there is nothing to repeat.
/// * killed by `SIGKILL` — a guard against the one way the probe could lie. If
///   some dependency ever set `SIGCHLD` to `SIG_IGN`, children would be
///   auto-reaped and a *successful* fast child could also probe as `ESRCH`; but
///   such a child cannot be reaped by us afterwards, so it surfaces as a wait
///   error rather than reaching this predicate with a signal status.
///
/// Note what is deliberately *not* used: emptiness of stdout or stderr. That was
/// the first formulation and it is unsound — a `Discard` stdout is empty by
/// construction, so for mutating callers the test would be vacuous, and a child
/// killed *after* committing its ref would have been replayed.
pub(crate) fn child_ran_nothing(vanished_before_running: bool, status: &ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt;
    vanished_before_running && status.signal() == Some(libc::SIGKILL)
}

/// Blocking twin of [`run_supervised`], for callers that are not on an async
/// runtime.
///
/// Same guarantees, same [`SupervisedOutcome`], same [`CaptureBuffer`] byte-cap
/// policy, same process-group SIGKILL: the point of having this at all is that a
/// synchronous caller should not have to choose between "no timeout" and "become
/// async". `notes_repo` is the caller — it holds a `std::sync::Mutex` across the
/// whole git invocation, which cannot be held across an `await`, so making it
/// async would trade this problem for a worse one.
///
/// Unlike the async twin this also owns **stdin**, because a blocking caller
/// cannot write stdin and drain stdout concurrently without either a thread or
/// this loop. Writing stdin to completion *before* draining stdout deadlocks
/// against a child that fills its stdout pipe while we are still writing, so
/// stdin is driven non-blockingly alongside the reads.
///
/// One event loop does everything: `poll(2)` on whichever of stdin/stdout/stderr
/// is still live, a `waitid(WNOWAIT)` exit probe, and a deadline check. Because
/// every phase is inside the one deadline, this bounds the *whole* call — even
/// the post-exit drain, where a stray process holding an inherited pipe open
/// could otherwise stall forever.
pub(crate) fn run_supervised_blocking(
    command: &mut std::process::Command,
    timeout: Duration,
    stdin_input: Option<&[u8]>,
    stdout_mode: StdoutMode,
    stderr_mode: StderrMode,
) -> Result<SupervisedOutcome, SupervisorError> {
    run_supervised_blocking_probed(
        command,
        timeout,
        stdin_input,
        stdout_mode,
        stderr_mode,
        child_vanished_before_running,
    )
}

/// [`run_supervised_blocking`] with an injectable proof-of-life probe.
///
/// A genuinely born-dead child cannot be forged on demand — the kernel decides —
/// so a test that wants to drive the `ran_nothing` path supplies its own probe.
/// It is an explicit argument rather than hidden indirection, and
/// [`run_supervised_blocking`] is the only production caller.
pub(crate) fn run_supervised_blocking_probed(
    command: &mut std::process::Command,
    timeout: Duration,
    stdin_input: Option<&[u8]>,
    stdout_mode: StdoutMode,
    stderr_mode: StderrMode,
    probe: impl FnOnce(u32) -> bool,
) -> Result<SupervisedOutcome, SupervisorError> {
    use std::os::unix::process::CommandExt;

    let stdout_byte_cap = match stdout_mode {
        StdoutMode::Discard => None,
        StdoutMode::Capture { byte_cap } => Some(byte_cap),
    };
    command.stdin(match stdin_input {
        Some(_) => Stdio::piped(),
        None => Stdio::null(),
    });
    command.stdout(match stdout_mode {
        StdoutMode::Discard => Stdio::null(),
        StdoutMode::Capture { .. } => Stdio::piped(),
    });
    command.stderr(match stderr_mode {
        StderrMode::Discard => Stdio::null(),
        StderrMode::Capture => Stdio::piped(),
    });
    command.process_group(0);

    let mut child = process_spawn::spawn(command).map_err(SupervisorError::Spawn)?;

    // Probe before touching the child: the zombie rule this relies on only holds
    // while the child is unreaped, so it has to happen here and nowhere later.
    let vanished_before_running = probe(child.id());

    // Everything after the spawn runs inside `supervise_blocking_child` so that
    // *no* error path can return while the child is still un-reaped. `?` on a
    // post-spawn failure (an `fcntl`, a `poll`, a `waitid`) would otherwise skip
    // the `child.wait()` below, and `std::process::Child::drop` deliberately does
    // not reap — so each such failure would leave a zombie until the daemon
    // exits. The failures are individually near-impossible; the leak is
    // unbounded, which is the asymmetry that matters.
    let pgid = match process_group_id(child.id()) {
        Ok(pgid) => pgid,
        Err(err) => {
            // No pgid means no group to signal; still reap the child we made.
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
    };
    let mut cleanup_guard = ProcessGroupCleanupGuard::new(pgid);
    let outcome = supervise_blocking_child(
        &mut child,
        &mut cleanup_guard,
        timeout,
        stdin_input,
        stdout_byte_cap,
    );
    let BlockingRunState {
        observation,
        stdout_buf,
        stderr_buf,
        child_exited,
        stdin_write_error,
        stdout_read_error,
    } = match outcome {
        Ok(state) => state,
        Err(err) => {
            // Kill the group and reap before surfacing, so a supervision failure
            // costs us an error and not a process-table entry.
            let _ = cleanup_guard.kill_now_io();
            let _ = child.wait();
            cleanup_guard.disarm();
            return Err(err);
        }
    };

    if !child_exited {
        if matches!(observation, ChildExitObservation::StdoutCapExceeded) {
            // The over-cap rejection closed the read end of stdout, so a child
            // mid-write takes SIGPIPE and can already be dead — in which case
            // `killpg` finds no signalable member and reports a benign EPERM on
            // macOS. Mark the exit as observed so that EPERM is tolerated: we own
            // this group (we created it with `process_group(0)`) and can always
            // signal a live member, so EPERM here can only mean the group is
            // already empty, never a real permission failure. Same reasoning as
            // the async twin's `StdoutCapExceeded` arm.
            cleanup_guard.mark_child_exit_observed();
        }
        // Hold a kill failure rather than returning on it: we still owe the child
        // a `wait`, and `std::process::Child::drop` does not reap. Returning here
        // would surface the right error and leak a process — the same trap as the
        // post-spawn paths above, one arm further on.
        if let Err(err) = cleanup_guard.kill_now() {
            let _ = child.wait();
            cleanup_guard.disarm();
            return Err(err);
        }
    }
    let status = child.wait();
    cleanup_guard.disarm();

    match observation {
        ChildExitObservation::Exited => {
            let status = status.map_err(SupervisorError::Wait)?;
            // Settled-flag backstop, mirroring the async twin: the drain may have
            // crossed the cap in the same iteration the child exited.
            if stdout_buf.overran() {
                return Ok(SupervisedOutcome::StdoutCapExceeded {
                    cap: stdout_byte_cap.expect("cap only set under Capture"),
                });
            }
            let ran_nothing = child_ran_nothing(vanished_before_running, &status);
            // A born-dead child is retried by the caller, and its `EPIPE` on stdin
            // is a symptom of that rather than a delivery failure — so the held
            // error is discarded in exactly that case and surfaced in every other.
            if !ran_nothing && let Some((written, source)) = stdin_write_error {
                return Err(SupervisorError::StdinWrite {
                    written,
                    total: stdin_input.map_or(0, |b| b.len()),
                    source,
                });
            }
            // A failed stdout read means the capture is a prefix, not an answer.
            if let Some(err) = stdout_read_error {
                return Err(SupervisorError::CaptureRead(err));
            }
            Ok(SupervisedOutcome::Exited {
                ran_nothing,
                status,
                stdout: stdout_buf.finish(),
                stderr: stderr_buf.finish(),
            })
        }
        ChildExitObservation::StdoutCapExceeded => Ok(SupervisedOutcome::StdoutCapExceeded {
            cap: stdout_byte_cap.expect("cap only set under Capture"),
        }),
        ChildExitObservation::TimedOut => Ok(SupervisedOutcome::TimedOut),
    }
}

/// The event loop of [`run_supervised_blocking`], factored out so its caller can
/// guarantee the child is reaped on every error path.
///
/// Returns how the child left the loop plus the two capture buffers. Does not
/// reap, kill on the way out, or interpret the exit status: those belong to the
/// caller, which is the only place that can sequence them correctly against the
/// cleanup guard.
fn supervise_blocking_child(
    child: &mut std::process::Child,
    cleanup_guard: &mut ProcessGroupCleanupGuard,
    timeout: Duration,
    stdin_input: Option<&[u8]>,
    stdout_byte_cap: Option<usize>,
) -> Result<BlockingRunState, SupervisorError> {
    let pgid = process_group_id(child.id())?;

    // `Option` is the "still live" marker for each stream: taking a handle out
    // closes that fd, which is exactly how we signal EOF to the child (stdin) or
    // stop reading (an over-cap stdout).
    let mut stdin_pipe = child.stdin.take();
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    for fd in [
        stdin_pipe.as_ref().map(as_raw),
        stdout_pipe.as_ref().map(as_raw),
        stderr_pipe.as_ref().map(as_raw),
    ]
    .into_iter()
    .flatten()
    {
        set_nonblocking(fd).map_err(SupervisorError::Wait)?;
    }

    let mut stdout_buf = CaptureBuffer::new(CapturePolicy::RejectOverCap {
        cap: stdout_byte_cap.unwrap_or(0),
    });
    let mut stderr_buf = CaptureBuffer::new(CapturePolicy::TailCap {
        cap: STDERR_CAPTURE_TAIL_CAP,
    });
    let mut stdin_remaining = stdin_input.unwrap_or(&[]);
    // Bytes written so far, plus the failure, when a stdin write did not
    // complete. Settled after the wait, because a born-dead child surfaces here
    // first as `EPIPE`.
    let mut stdin_write_error: Option<(usize, std::io::Error)> = None;
    let mut stdout_read_error: Option<std::io::Error> = None;

    let deadline = std::time::Instant::now() + timeout;
    let observation: ChildExitObservation;
    let mut child_exited = false;

    loop {
        if stdout_buf.overran() {
            observation = ChildExitObservation::StdoutCapExceeded;
            break;
        }
        // Done only when the child is gone *and* both pipes have hit EOF, so a
        // child that exits with bytes still in flight does not lose them.
        if child_exited && stdout_pipe.is_none() && stderr_pipe.is_none() {
            observation = ChildExitObservation::Exited;
            break;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            // Reaching here means we did *not* finish: the arm above already
            // broke out with `Exited` if the child was gone and both captures had
            // hit EOF. So either the child is still alive, or something still
            // holds a capture pipe open and its output is incomplete.
            //
            // Report a timeout in both cases. An earlier version returned
            // `Exited` when the leader had been seen to exit, reasoning that the
            // caller should get the command's real status — but that hands back a
            // *truncated* stdout as a successful result, and `for-each-ref`
            // output one refname per line is indistinguishable from a complete,
            // shorter listing. Losing notes silently is far worse than a timeout.
            observation = ChildExitObservation::TimedOut;
            break;
        }
        let slice = std::cmp::min(CHILD_EXIT_POLL_INTERVAL, deadline - now);

        let mut fds: Vec<libc::pollfd> = Vec::with_capacity(3);
        // Index bookkeeping: `poll` returns results positionally, so remember
        // which slot each stream took (or -1 when it is not being polled).
        let mut stdin_slot = -1i32;
        let mut stdout_slot = -1i32;
        let mut stderr_slot = -1i32;
        if let Some(pipe) = stdin_pipe.as_ref()
            && !stdin_remaining.is_empty()
        {
            stdin_slot = fds.len() as i32;
            fds.push(pollfd_for(as_raw(pipe), libc::POLLOUT));
        }
        if let Some(pipe) = stdout_pipe.as_ref() {
            stdout_slot = fds.len() as i32;
            fds.push(pollfd_for(as_raw(pipe), libc::POLLIN));
        }
        if let Some(pipe) = stderr_pipe.as_ref() {
            stderr_slot = fds.len() as i32;
            fds.push(pollfd_for(as_raw(pipe), libc::POLLIN));
        }

        if fds.is_empty() {
            // No live stream to wait on: just pace the exit probe.
            std::thread::sleep(slice);
        } else {
            poll_wait(&mut fds, slice).map_err(SupervisorError::Wait)?;
        }

        if stdin_slot >= 0
            && fds[stdin_slot as usize].revents != 0
            && let Some(pipe) = stdin_pipe.as_mut()
        {
            match write_available(pipe, stdin_remaining) {
                // Hold the error rather than treating a short write as EOF. A
                // child that closed stdin early (EPIPE) may still exit 0, and
                // reporting that as success would mean `git hash-object --stdin`
                // returning the id of a *truncated* body — silent corruption of
                // the very data the note is meant to attest. Whether this is the
                // born-dead flake or a real broken pipe is not decidable yet; the
                // wait below settles it (same reasoning as f36b4c0).
                Err(source) => {
                    stdin_write_error = Some((
                        stdin_input.map_or(0, |b| b.len()) - stdin_remaining.len(),
                        source,
                    ));
                    stdin_remaining = &[];
                    stdin_pipe = None;
                }
                Ok(written) => stdin_remaining = &stdin_remaining[written..],
            }
        }
        if stdin_remaining.is_empty() {
            // Drop the writer so a child reading to EOF is not left waiting.
            stdin_pipe = None;
        }

        if stdout_slot >= 0 && fds[stdout_slot as usize].revents != 0 {
            // A read failure on *captured stdout* is fatal: the caller parses
            // these bytes, so a short buffer is a wrong answer, not a degraded
            // one. (Before this branch, `wait_with_output` surfaced such failures
            // as `GitWait`; preserve that rather than silently truncating.)
            if let Some(err) = drain_available(&mut stdout_pipe, &mut stdout_buf) {
                stdout_read_error = Some(err);
            }
        }
        if stderr_slot >= 0 && fds[stderr_slot as usize].revents != 0 {
            // Stderr stays best-effort: it is a diagnostic, and losing part of one
            // must not fail an otherwise-successful command.
            let _ = drain_available(&mut stderr_pipe, &mut stderr_buf);
        }

        if !child_exited && child_has_exited_without_reaping(pgid)? {
            child_exited = true;
            // Kill the group the moment the leader is gone: any helper it forked
            // into the group holds a copy of the stdout/stderr write end, and
            // until those close the pipes never reach EOF.
            cleanup_guard.mark_child_exit_observed();
            cleanup_guard.kill_now()?;
        }
    }

    Ok(BlockingRunState {
        observation,
        stdout_buf,
        stderr_buf,
        child_exited,
        stdin_write_error,
        stdout_read_error,
    })
}

/// How a supervised child left [`supervise_blocking_child`]'s event loop.
struct BlockingRunState {
    observation: ChildExitObservation,
    stdout_buf: CaptureBuffer,
    stderr_buf: CaptureBuffer,
    child_exited: bool,
    /// Set when stdin was not fully delivered; settled by the caller, because a
    /// born-dead child shows up here first and must be retried, not reported.
    stdin_write_error: Option<(usize, std::io::Error)>,
    /// Set when reading captured stdout failed, which invalidates the capture.
    stdout_read_error: Option<std::io::Error>,
}

fn as_raw<T: std::os::fd::AsRawFd>(handle: &T) -> libc::c_int {
    handle.as_raw_fd()
}

fn pollfd_for(fd: libc::c_int, events: libc::c_short) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

/// Put `fd` in non-blocking mode so the single-threaded event loop can read and
/// write without any one stream being able to block the others (or the deadline).
fn set_nonblocking(fd: libc::c_int) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Wait up to `slice` for any of `fds` to become ready. `EINTR` is reported as
/// "nothing ready": the caller's loop re-derives its state from scratch each
/// iteration, so a spurious early return is harmless.
fn poll_wait(fds: &mut [libc::pollfd], slice: Duration) -> std::io::Result<()> {
    let millis = libc::c_int::try_from(slice.as_millis()).unwrap_or(libc::c_int::MAX);
    let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) };
    if ready == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            for fd in fds.iter_mut() {
                fd.revents = 0;
            }
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

/// Most reads one [`drain_available`] call will perform before yielding back to
/// the supervisor loop, even if more data is waiting.
///
/// This is what makes the blocking supervisor's timeout **unconditional**. Without
/// it, the drain reads until the pipe runs dry, so a child (or a group of them)
/// refilling the pipe at least as fast as one reader empties it would keep the
/// single-threaded loop inside the drain and starve the deadline check. In
/// practice a lone reader out-paces a lone writer and `EAGAIN` arrives quickly —
/// but "in practice" is a scheduling accident, not a guarantee, and a bound we
/// cannot state is a bound we do not have. Capping the reads per call costs one
/// extra `poll` per 512 KiB of output and makes the deadline hold by construction.
const MAX_READS_PER_DRAIN: usize = 64;

/// Read what is currently available from `pipe` into `buffer` — at most
/// [`MAX_READS_PER_DRAIN`] reads — taking the pipe out of `pipe` on EOF, on an
/// over-cap rejection, or on a read error.
///
/// Setting `pipe` to `None` closes the fd, which is what makes an over-cap
/// rejection prompt: the child's next write takes `SIGPIPE` instead of blocking
/// on a pipe nobody is draining.
///
/// Returning with data still buffered is safe: the caller's `poll` reports the fd
/// ready again immediately, so the only effect is that the deadline and exit
/// probes get a turn in between.
fn drain_available<R: std::io::Read>(
    pipe: &mut Option<R>,
    buffer: &mut CaptureBuffer,
) -> Option<std::io::Error> {
    let reader = pipe.as_mut()?;
    let mut chunk = [0u8; 8192];
    let mut reads = 0;
    while reads < MAX_READS_PER_DRAIN {
        reads += 1;
        match reader.read(&mut chunk) {
            Ok(0) => {
                *pipe = None;
                return None;
            }
            Ok(n) => {
                if buffer.push(&chunk[..n]) == Absorb::Stop {
                    *pipe = None;
                    return None;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return None,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                // Retry without consuming the budget: no progress was made.
                reads -= 1;
                continue;
            }
            // Report the failure and stop; the caller decides whether losing
            // bytes on this stream invalidates the run (it does for captured
            // stdout, which is parsed; it does not for stderr diagnostics).
            Err(err) => {
                *pipe = None;
                return Some(err);
            }
        }
    }
    None
}

/// Write as much of `bytes` as the pipe will currently accept, returning the
/// count consumed. A would-block is zero bytes, not an error.
fn write_available<W: std::io::Write>(pipe: &mut W, bytes: &[u8]) -> std::io::Result<usize> {
    match pipe.write(bytes) {
        Ok(n) => Ok(n),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(0)
        }
        Err(err) => Err(err),
    }
}

/// Resolve a program to an executable, canonicalised path the same way the
/// supervised child will, *before* the environment is cleared.
///
/// An absolute path must point at an executable file; a single-component
/// basename is searched on `PATH`. `field` labels the path in
/// [`SupervisorError::Canonicalize`] so callers can attribute the failure to
/// their own config key (e.g. `"git_program"`, `"nix_program"`).
pub(crate) async fn resolve_program(
    program: &Path,
    field: &'static str,
) -> Result<PathBuf, SupervisorError> {
    if program.is_absolute() {
        return match tokio::fs::metadata(program).await {
            Ok(metadata) if is_executable_file(&metadata) => {
                canonicalize_path(field, program).await
            }
            Ok(_) => Err(SupervisorError::ProgramNotFound(program.to_path_buf())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Err(SupervisorError::ProgramNotFound(program.to_path_buf()))
            }
            Err(source) => Err(SupervisorError::Canonicalize {
                field,
                path: program.to_path_buf(),
                source,
            }),
        };
    }
    if program.components().count() != 1 {
        return Err(SupervisorError::ProgramNotFound(program.to_path_buf()));
    }

    let Some(path) = std::env::var_os("PATH") else {
        return Err(SupervisorError::ProgramNotFound(program.to_path_buf()));
    };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        match tokio::fs::metadata(&candidate).await {
            Ok(metadata) if is_executable_file(&metadata) => {
                return canonicalize_path(field, &candidate).await;
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(SupervisorError::Canonicalize {
                    field,
                    path: candidate,
                    source,
                });
            }
        }
    }
    Err(SupervisorError::ProgramNotFound(program.to_path_buf()))
}

async fn canonicalize_path(field: &'static str, path: &Path) -> Result<PathBuf, SupervisorError> {
    tokio::fs::canonicalize(path)
        .await
        .map_err(|source| SupervisorError::Canonicalize {
            field,
            path: path.to_path_buf(),
            source,
        })
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn is_executable_file(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !metadata.is_file() {
        return false;
    }
    let mode = metadata.permissions().mode();
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return mode & 0o111 != 0;
    }
    if metadata.uid() == euid {
        return mode & 0o100 != 0;
    }
    if metadata.gid() == unsafe { libc::getegid() }
        || current_supplementary_groups().contains(&metadata.gid())
    {
        return mode & 0o010 != 0;
    }
    mode & 0o001 != 0
}

enum ChildExitObservation {
    Exited,
    TimedOut,
    StdoutCapExceeded,
}

async fn wait_for_child_exit_before_reap(
    pid: libc::pid_t,
    timeout: Duration,
    stdout_capped: &AtomicBool,
) -> Result<ChildExitObservation, SupervisorError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        // Checked before the exit probe so an overrun that coincides with the
        // child exiting is reported as the (more specific, actionable) cap
        // rejection rather than a plain exit.
        if stdout_capped.load(Ordering::Acquire) {
            return Ok(ChildExitObservation::StdoutCapExceeded);
        }
        if child_has_exited_without_reaping(pid)? {
            return Ok(ChildExitObservation::Exited);
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(ChildExitObservation::TimedOut);
        }
        tokio::time::sleep(std::cmp::min(CHILD_EXIT_POLL_INTERVAL, deadline - now)).await;
    }
}

fn child_has_exited_without_reaping(pid: libc::pid_t) -> Result<bool, SupervisorError> {
    pid_has_exited_without_reaping(pid).map_err(SupervisorError::Wait)
}

/// Has `pid` exited, *without* reaping it?
///
/// `waitid(WNOWAIT)` is the load-bearing detail and the reason this is shared
/// rather than re-derived: leaving the child un-reaped keeps its pid claimed, so
/// the pid (and therefore the process group id that equals it) cannot be recycled
/// by the kernel. A caller that reaps first and signals afterwards has a window in
/// which its `killpg` can hit an unrelated group that inherited the pid. Every
/// group kill in this codebase is ordered observe-then-kill-then-reap because of
/// this, and getting that order wrong is silent and rare.
pub(crate) fn pid_has_exited_without_reaping(pid: libc::pid_t) -> std::io::Result<bool> {
    let mut status = MaybeUninit::<libc::siginfo_t>::zeroed();
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            status.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }

    let status = unsafe { status.assume_init() };
    let observed_pid = unsafe { status.si_pid() };
    Ok(observed_pid != 0)
}

/// Poll [`pid_has_exited_without_reaping`] until the leader is observed exited.
///
/// Unbounded by design: the caller wants the pid held un-reaped until exit is
/// observed so its subsequent group kill is race-free. Callers that need a
/// deadline use [`run_supervised`] / [`run_supervised_blocking`] instead.
pub(crate) async fn wait_for_pid_exit_no_reap(pid: libc::pid_t) -> std::io::Result<bool> {
    loop {
        if pid_has_exited_without_reaping(pid)? {
            return Ok(true);
        }
        tokio::time::sleep(CHILD_EXIT_POLL_INTERVAL).await;
    }
}

fn process_group_id(pid: u32) -> Result<libc::pid_t, SupervisorError> {
    pid.try_into()
        .map_err(|_| SupervisorError::InvalidProcessId(pid))
}

/// Guarantees a process group is SIGKILLed on *every* exit path — including a
/// panic or a cancelled future — until explicitly disarmed.
///
/// Declaration order matters when this sits alongside the `Child` it guards:
/// locals drop in reverse declaration order, so the guard must be declared
/// **after** the child. That way an unwind drops the guard first, and its
/// `killpg` runs while the leader pid is still un-reaped (so the pgid is still
/// ours). Declared before the child, the child would drop first, free the
/// leader's pid, and the guard's `killpg` could land on a recycled group.
pub(crate) struct ProcessGroupCleanupGuard {
    pgid: libc::pid_t,
    child_exit_observed: bool,
    armed: bool,
}

impl ProcessGroupCleanupGuard {
    pub(crate) fn new(pgid: libc::pid_t) -> Self {
        Self {
            pgid,
            child_exit_observed: false,
            armed: true,
        }
    }

    /// Record that the leader's exit has been observed via
    /// [`pid_has_exited_without_reaping`], which is the only condition under
    /// which a macOS `EPERM` from `killpg` is safe to treat as success.
    pub(crate) fn mark_child_exit_observed(&mut self) {
        self.child_exit_observed = true;
    }

    pub(crate) fn kill_now(&self) -> Result<(), SupervisorError> {
        kill_process_group_inner(self.pgid, self.child_exit_observed)
    }

    /// Kill the group, reporting failure as an `io::Error` for callers outside
    /// the [`SupervisorError`] world.
    pub(crate) fn kill_now_io(&self) -> std::io::Result<()> {
        kill_process_group(self.pgid, self.child_exit_observed)
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = kill_process_group_inner(self.pgid, self.child_exit_observed);
        }
    }
}

fn current_supplementary_groups() -> Vec<libc::gid_t> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return Vec::new();
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    let actual = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if actual <= 0 {
        return Vec::new();
    }
    groups.truncate(actual as usize);
    groups
}

fn kill_process_group_inner(
    pgid: libc::pid_t,
    child_exit_observed: bool,
) -> Result<(), SupervisorError> {
    kill_process_group(pgid, child_exit_observed)
        .map_err(|source| SupervisorError::KillProcessGroup { pgid, source })
}

/// SIGKILL a process group this process created, tolerating exactly the two
/// benign outcomes and no others.
///
/// The single definition of the group kill. Both benign cases are easy to get
/// wrong in opposite directions — swallow too much and a real permission failure
/// becomes invisible; swallow too little and normal shutdown reports a spurious
/// error:
///
/// * `ESRCH` — the group is already gone. Always fine.
/// * `EPERM` — macOS reports this once the leader has exited and no signalable
///   member remains. Tolerated **only** when `child_exit_observed`, because we
///   own this group (created with `process_group(0)`) and can always signal a
///   live member: with the exit observed, `EPERM` can only mean "already empty".
///   Without it, `EPERM` means something else and must surface.
pub(crate) fn kill_process_group(
    pgid: libc::pid_t,
    child_exit_observed: bool,
) -> std::io::Result<()> {
    // The child was spawned with process_group(0), making its pid the process
    // group id inherited by any ordinary helpers it starts.
    if unsafe { libc::killpg(pgid, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let source = std::io::Error::last_os_error();
    match source.raw_os_error() {
        Some(libc::ESRCH) => Ok(()),
        Some(libc::EPERM) if child_exit_observed => Ok(()),
        _ => Err(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locate an executable on `PATH`, preserving the caller-visible path so
    /// the basename survives `execve` (mirrors the clean_git test helper).
    pub(super) fn locate_on_path(name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::var_os("PATH").expect("PATH must be set in tests");
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if let Ok(meta) = std::fs::metadata(&candidate)
                && meta.is_file()
                && (meta.permissions().mode() & 0o111) != 0
            {
                return candidate;
            }
        }
        panic!("required test tool {name} not found on PATH");
    }

    #[tokio::test]
    async fn captures_stdout_and_stderr_on_nonzero_exit() {
        let mut command = Command::new(locate_on_path("sh"));
        command.arg("-c").arg("printf out; printf err 1>&2; exit 3");
        let outcome = run_supervised(
            &mut command,
            Duration::from_secs(10),
            StdoutMode::Capture { byte_cap: 4096 },
            StderrMode::Capture,
        )
        .await
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::Exited {
                status,
                stdout,
                stderr,
                ..
            } => {
                assert_eq!(status.code(), Some(3));
                assert_eq!(stdout, b"out");
                assert_eq!(stderr, b"err");
            }
            SupervisedOutcome::TimedOut => panic!("sh exited well within the timeout"),
            SupervisedOutcome::StdoutCapExceeded { cap } => {
                panic!("3 bytes of stdout are well under the {cap}-byte cap")
            }
        }
    }

    #[tokio::test]
    async fn discarded_stderr_is_empty() {
        let mut command = Command::new(locate_on_path("sh"));
        command.arg("-c").arg("printf noise 1>&2; exit 0");
        let outcome = run_supervised(
            &mut command,
            Duration::from_secs(10),
            StdoutMode::Discard,
            StderrMode::Discard,
        )
        .await
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::Exited { stderr, .. } => assert!(stderr.is_empty()),
            SupervisedOutcome::TimedOut => panic!("sh exited well within the timeout"),
            SupervisedOutcome::StdoutCapExceeded { .. } => {
                panic!("stdout is discarded, so the cap is never evaluated")
            }
        }
    }

    #[tokio::test]
    async fn captured_stderr_is_tail_capped_against_a_verbose_child() {
        // A child that streams far more than the cap must not stall (its stderr
        // is fully drained) and must not blow the bound (only the tail is kept),
        // while the final complete line — the informative fatal message — and
        // the line alignment both survive.
        let mut command = Command::new(locate_on_path("sh"));
        command.arg("-c").arg(format!(
            "i=0; while [ $i -lt {n} ]; do printf 'noise-line-padding\\n' 1>&2; i=$((i+1)); done; printf 'fatal: the-tail\\n' 1>&2; exit 1",
            n = (STDERR_CAPTURE_TAIL_CAP / 19) + 500,
        ));
        let outcome = run_supervised(
            &mut command,
            Duration::from_secs(30),
            StdoutMode::Discard,
            StderrMode::Capture,
        )
        .await
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::Exited { stderr, .. } => {
                assert!(
                    stderr.len() <= STDERR_CAPTURE_TAIL_CAP,
                    "stderr {} exceeded cap {STDERR_CAPTURE_TAIL_CAP}",
                    stderr.len()
                );
                assert!(
                    stderr.ends_with(b"fatal: the-tail\n"),
                    "the informative tail must be retained"
                );
                // Line alignment: the retained tail starts at a line boundary,
                // never mid-line.
                assert!(
                    stderr.starts_with(b"noise-line-padding\n"),
                    "the retained tail must begin on a line boundary, got {:?}",
                    String::from_utf8_lossy(&stderr[..stderr.len().min(40)])
                );
            }
            SupervisedOutcome::TimedOut => panic!("verbose child should still exit promptly"),
            SupervisedOutcome::StdoutCapExceeded { .. } => {
                panic!("stdout is discarded, so the cap is never evaluated")
            }
        }
    }

    #[tokio::test]
    async fn stdout_capture_returns_full_output_at_the_cap_boundary() {
        // Exactly `cap` bytes is *not* an overrun (the drain rejects on
        // `len > cap`), so the whole output is returned intact.
        let mut command = Command::new(locate_on_path("sh"));
        command.arg("-c").arg("printf aaaa");
        let outcome = run_supervised(
            &mut command,
            Duration::from_secs(10),
            StdoutMode::Capture { byte_cap: 4 },
            StderrMode::Discard,
        )
        .await
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::Exited { stdout, .. } => assert_eq!(stdout, b"aaaa"),
            other => panic!(
                "expected Exited with the full 4-byte output, got a different outcome: {}",
                outcome_name(&other)
            ),
        }
    }

    #[tokio::test]
    async fn stdout_capture_rejects_and_kills_when_child_overruns_the_cap() {
        // A child that streams far more than the cap must be rejected — not
        // buffered unbounded — and the supervisor must break out and SIGKILL
        // promptly rather than wait for the wall-clock timeout. A 30s timeout
        // with a child that would take minutes to emit 64 MiB proves the kill
        // is driven by the cap, not the clock.
        let mut command = Command::new(locate_on_path("sh"));
        // An unbounded shell-builtin writer (no external binary, so no PATH
        // dependency): it keeps writing until the cap trips and we SIGKILL it.
        command
            .arg("-c")
            .arg("while :; do printf 'writ-overrun-padding\\n'; done");
        let outcome = run_supervised(
            &mut command,
            Duration::from_secs(30),
            StdoutMode::Capture {
                byte_cap: 64 * 1024,
            },
            StderrMode::Discard,
        )
        .await
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::StdoutCapExceeded { cap } => assert_eq!(cap, 64 * 1024),
            other => panic!("expected StdoutCapExceeded, got {}", outcome_name(&other)),
        }
    }

    fn outcome_name(outcome: &SupervisedOutcome) -> &'static str {
        match outcome {
            SupervisedOutcome::Exited { .. } => "Exited",
            SupervisedOutcome::TimedOut => "TimedOut",
            SupervisedOutcome::StdoutCapExceeded { .. } => "StdoutCapExceeded",
        }
    }
}

/// Parity tests for [`run_supervised_blocking`].
///
/// The blocking and async supervisors are two implementations of one contract,
/// which is precisely the arrangement that drifts. These deliberately mirror the
/// async tests above case for case, so a behavioural change to one that is not
/// made to the other shows up as a failing test rather than as two subtly
/// different disciplines that each look complete where they are defined.
#[cfg(test)]
mod blocking_tests {
    use super::tests::locate_on_path;
    use super::*;

    fn sh(script: &str) -> std::process::Command {
        let mut command = std::process::Command::new(locate_on_path("sh"));
        command.arg("-c").arg(script);
        command
    }

    fn outcome_name(outcome: &SupervisedOutcome) -> &'static str {
        match outcome {
            SupervisedOutcome::Exited { .. } => "Exited",
            SupervisedOutcome::TimedOut => "TimedOut",
            SupervisedOutcome::StdoutCapExceeded { .. } => "StdoutCapExceeded",
        }
    }

    /// Mirrors `captures_stdout_and_stderr_on_nonzero_exit`.
    #[test]
    fn captures_stdout_and_stderr_on_nonzero_exit() {
        let outcome = run_supervised_blocking(
            &mut sh("printf out; printf err 1>&2; exit 3"),
            Duration::from_secs(10),
            None,
            StdoutMode::Capture { byte_cap: 4096 },
            StderrMode::Capture,
        )
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::Exited {
                status,
                stdout,
                stderr,
                ..
            } => {
                assert_eq!(status.code(), Some(3));
                assert_eq!(stdout, b"out");
                assert_eq!(stderr, b"err");
            }
            other => panic!("expected Exited, got {}", outcome_name(&other)),
        }
    }

    /// Mirrors `discarded_stderr_is_empty`, and additionally pins that a
    /// `Discard` stdout can never be reported as an overrun: the cap is not
    /// evaluated when there is no pipe to read.
    #[test]
    fn discarded_streams_are_empty_and_never_overrun() {
        let outcome = run_supervised_blocking(
            &mut sh("printf lots-of-output; printf noise 1>&2; exit 0"),
            Duration::from_secs(10),
            None,
            StdoutMode::Discard,
            StderrMode::Discard,
        )
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::Exited {
                status,
                stdout,
                stderr,
                ..
            } => {
                assert!(status.success());
                assert!(stdout.is_empty());
                assert!(stderr.is_empty());
            }
            other => panic!("expected Exited, got {}", outcome_name(&other)),
        }
    }

    /// Mirrors `stdout_capture_returns_full_output_at_the_cap_boundary`: exactly
    /// `cap` bytes is not an overrun.
    #[test]
    fn stdout_capture_returns_full_output_at_the_cap_boundary() {
        let outcome = run_supervised_blocking(
            &mut sh("printf aaaa"),
            Duration::from_secs(10),
            None,
            StdoutMode::Capture { byte_cap: 4 },
            StderrMode::Discard,
        )
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::Exited { stdout, .. } => assert_eq!(stdout, b"aaaa"),
            other => panic!("expected Exited, got {}", outcome_name(&other)),
        }
    }

    /// Mirrors `stdout_capture_rejects_and_kills_when_child_overruns_the_cap`.
    /// The generous timeout against a child that never stops writing proves the
    /// cap ends the run, not the clock.
    #[test]
    fn stdout_capture_rejects_when_child_overruns_the_cap() {
        let outcome = run_supervised_blocking(
            &mut sh("while :; do printf 'writ-overrun-padding\\n'; done"),
            Duration::from_secs(30),
            None,
            StdoutMode::Capture {
                byte_cap: 64 * 1024,
            },
            StderrMode::Discard,
        )
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::StdoutCapExceeded { cap } => assert_eq!(cap, 64 * 1024),
            other => panic!("expected StdoutCapExceeded, got {}", outcome_name(&other)),
        }
    }

    /// Mirrors `captured_stderr_is_tail_capped_against_a_verbose_child`.
    #[test]
    fn captured_stderr_is_tail_capped_against_a_verbose_child() {
        let outcome = run_supervised_blocking(
            &mut sh(&format!(
                "i=0; while [ $i -lt {n} ]; do printf 'noise-line-padding\\n' 1>&2; i=$((i+1)); done; printf 'fatal: the-tail\\n' 1>&2; exit 1",
                n = (STDERR_CAPTURE_TAIL_CAP / 19) + 500,
            )),
            Duration::from_secs(30),
            None,
            StdoutMode::Discard,
            StderrMode::Capture,
        )
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::Exited { stderr, .. } => {
                assert!(
                    stderr.len() <= STDERR_CAPTURE_TAIL_CAP,
                    "stderr {} exceeded cap {STDERR_CAPTURE_TAIL_CAP}",
                    stderr.len()
                );
                assert!(
                    stderr.ends_with(b"fatal: the-tail\n"),
                    "the informative tail must be retained"
                );
                assert!(
                    stderr.starts_with(b"noise-line-padding\n"),
                    "the retained tail must begin on a line boundary"
                );
            }
            other => panic!("expected Exited, got {}", outcome_name(&other)),
        }
    }

    /// A child that never exits is killed at the deadline rather than waited on.
    /// The assertion on elapsed time is the point: a regression to an unbounded
    /// wait would hang the suite rather than fail it, so the bound is checked
    /// explicitly.
    #[test]
    fn times_out_a_child_that_never_exits() {
        let started = std::time::Instant::now();
        let outcome = run_supervised_blocking(
            &mut sh("while :; do :; done"),
            Duration::from_millis(300),
            None,
            StdoutMode::Capture { byte_cap: 4096 },
            StderrMode::Capture,
        )
        .expect("supervised sh run");
        assert!(
            matches!(outcome, SupervisedOutcome::TimedOut),
            "expected TimedOut, got {}",
            outcome_name(&outcome)
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the run must end at the deadline, took {:?}",
            started.elapsed()
        );
    }

    /// stdin is delivered to the child.
    #[test]
    fn writes_stdin_to_the_child() {
        let outcome = run_supervised_blocking(
            &mut sh("cat"),
            Duration::from_secs(10),
            Some(b"note body bytes"),
            StdoutMode::Capture { byte_cap: 4096 },
            StderrMode::Capture,
        )
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::Exited { stdout, .. } => assert_eq!(stdout, b"note body bytes"),
            other => panic!("expected Exited, got {}", outcome_name(&other)),
        }
    }

    /// The deadlock this supervisor's single event loop exists to prevent: a
    /// child that echoes far more than one pipe buffer's worth while we are still
    /// writing far more than one pipe buffer's worth to its stdin.
    ///
    /// Writing stdin to completion before draining stdout — the obvious
    /// implementation, and what a blocking caller reaches for — wedges here: the
    /// child blocks writing into a stdout pipe nobody is reading, and we block
    /// writing into a stdin pipe the child has stopped reading. Neither side can
    /// proceed. A generous timeout means a regression fails with `TimedOut`
    /// rather than hanging the suite.
    #[test]
    fn interleaves_stdin_and_stdout_instead_of_deadlocking() {
        // 1 MiB each way, far past any platform pipe buffer (64 KiB on Linux,
        // 16 KiB typical on macOS).
        let payload = vec![b'z'; 1024 * 1024];
        let outcome = run_supervised_blocking(
            &mut sh("cat"),
            Duration::from_secs(30),
            Some(&payload),
            StdoutMode::Capture {
                byte_cap: 4 * 1024 * 1024,
            },
            StderrMode::Capture,
        )
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::Exited { status, stdout, .. } => {
                assert!(status.success());
                assert_eq!(
                    stdout.len(),
                    payload.len(),
                    "the whole payload must round-trip"
                );
                assert_eq!(stdout, payload);
            }
            other => panic!(
                "expected Exited; a {} here means stdin and stdout were not \
                 interleaved",
                outcome_name(&other)
            ),
        }
    }

    /// The born-dead predicate is a proof, not a heuristic: it fires only when
    /// the proof-of-life probe found no process at all AND the child died by
    /// SIGKILL.
    ///
    /// The negative cases are the important ones. A child that ran and was killed
    /// (probe found it alive) must never be retried, and neither must a clean
    /// exit. An earlier formulation keyed on empty stdout/stderr instead, which is
    /// unsound: a discarded stdout is empty by construction, so a `notes add`
    /// killed *after* committing its ref would have been replayed.
    ///
    /// From #354 (`f36b4c0`); the predicate moved here when the supervisor took
    /// ownership of the spawn.
    #[test]
    fn only_a_child_that_never_existed_counts_as_having_run_nothing() {
        use std::os::unix::process::ExitStatusExt;
        let sigkilled = ExitStatus::from_raw(9);
        let clean_exit = ExitStatus::from_raw(0);

        assert!(
            child_ran_nothing(true, &sigkilled),
            "vanished before running and SIGKILLed: the flake, safe to re-run"
        );
        assert!(
            !child_ran_nothing(false, &sigkilled),
            "a child the probe found ALIVE ran, and must not be re-run even \
             though it died by the same signal"
        );
        assert!(
            !child_ran_nothing(true, &clean_exit),
            "a clean exit is not the flake, whatever the probe saw"
        );
        assert!(
            !child_ran_nothing(false, &clean_exit),
            "an ordinary successful child is never retried"
        );
    }

    /// A child that floods stderr *forever* must still hit the deadline.
    ///
    /// This is where the blocking supervisor could diverge from its async twin in
    /// a way that matters. The async version drains on separate tasks, so its
    /// timeout fires regardless of how much the child emits. This version is
    /// single-threaded, so a drain that read until the pipe ran dry would never
    /// return to the deadline check against a writer that refills as fast as one
    /// reader empties — and stderr is the bad case, because a tail cap truncates
    /// instead of stopping the drain, so no overrun breaks the loop.
    /// [`MAX_READS_PER_DRAIN`] is what forecloses that.
    ///
    /// Honest limitation: this test passed even before that bound existed, because
    /// one reader out-paces one writer and `EAGAIN` arrives quickly. It guards the
    /// deadline against a fast flood; it does not by itself demonstrate the bound
    /// is load-bearing. The bound is there so the guarantee does not rest on
    /// scheduling, which no single test can establish.
    #[test]
    fn times_out_a_child_that_floods_stderr_forever() {
        let started = std::time::Instant::now();
        let outcome = run_supervised_blocking(
            &mut sh("while :; do printf 'endless-diagnostic-noise\n' 1>&2; done"),
            Duration::from_millis(500),
            None,
            StdoutMode::Discard,
            StderrMode::Capture,
        )
        .expect("supervised sh run");
        assert!(
            matches!(outcome, SupervisedOutcome::TimedOut),
            "expected TimedOut, got {}",
            outcome_name(&outcome)
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "a drain that reads until the pipe runs dry starves the deadline              check; took {:?}",
            started.elapsed()
        );
    }

    /// A child that exits without reading its stdin must not be reported as a
    /// success when we only delivered a prefix.
    ///
    /// This is the sharpest edge in the whole module. `notes_repo` pipes note
    /// bodies and seed blobs into `git hash-object --stdin`, which exits 0 and
    /// prints the id of *whatever it read*. Treating the resulting `EPIPE` as a
    /// benign early EOF — which an earlier version of this loop did, with a
    /// comment saying the exit status was the verdict — means persisting an object
    /// id that attests to truncated content. Silent corruption of the audit trail,
    /// from a write error we already held in our hand.
    #[test]
    fn a_partially_delivered_stdin_is_never_reported_as_success() {
        // Far more than any pipe buffer, against a child that reads none of it.
        let payload = vec![b'z'; 4 * 1024 * 1024];
        let outcome = run_supervised_blocking(
            &mut sh("exit 0"),
            Duration::from_secs(30),
            Some(&payload),
            StdoutMode::Capture { byte_cap: 4096 },
            StderrMode::Capture,
        );
        match outcome {
            Err(SupervisorError::StdinWrite { written, total, .. }) => {
                assert_eq!(total, payload.len());
                assert!(
                    written < total,
                    "the failure only makes sense for a short write; wrote {written} of {total}"
                );
            }
            Err(other) => panic!("expected StdinWrite, got {other:?}"),
            Ok(SupervisedOutcome::Exited { status, .. }) => panic!(
                "a child that read none of a {} byte payload and exited {:?} must \
                 not be reported as success",
                payload.len(),
                status.code()
            ),
            Ok(other) => panic!("expected StdinWrite, got {}", outcome_name(&other)),
        }
    }

    /// A helper the child forks into its own process group must not outlive the
    /// run: it holds a copy of the stdout write end, so without the group kill
    /// the drain never reaches EOF.
    #[test]
    fn kills_a_helper_left_in_the_process_group() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let marker = tmp.path().join("helper.pid");
        let sleep = locate_on_path("sleep");
        let outcome = run_supervised_blocking(
            &mut sh(&format!(
                "{sleep} 600 & printf '%s' \"$!\" > {marker}; exit 0",
                sleep = sleep.display(),
                marker = marker.display()
            )),
            Duration::from_secs(30),
            None,
            StdoutMode::Capture { byte_cap: 4096 },
            StderrMode::Capture,
        )
        .expect("supervised sh run");
        assert!(
            matches!(outcome, SupervisedOutcome::Exited { .. }),
            "expected Exited, got {}",
            outcome_name(&outcome)
        );
        let pid: libc::pid_t = std::fs::read_to_string(&marker)
            .expect("helper pid marker")
            .trim()
            .parse()
            .expect("helper pid is numeric");
        // The kill is synchronous with the return; reaping is the kernel's, so
        // poll briefly for the helper to disappear.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "helper pid {pid} survived; the process group was not killed"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}
