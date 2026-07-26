//! Spawn helpers that retry briefly on a *refused* spawn.
//!
//! Every errno the classifier accepts shares one property: the
//! `fork`/`posix_spawn`/`execve` was rejected outright, so the child never ran
//! and nothing half-happened. That is what makes retrying correct rather than
//! merely hopeful — a spawn that *succeeded* and then exited non-zero is a
//! command result, never routed through here.
//!
//! Two flavours of refusal occur in practice. One classifier
//! recognises both — but they get *different deadlines*, because they clear on
//! timescales four orders of magnitude apart:
//!
//! * `ETXTBSY` ("Text file busy") — `execve` refuses a program file that any
//!   process holds open for writing. In a multi-threaded harness a `fork()` in
//!   another thread can inherit a sibling's still-open writable fd to a
//!   freshly-written script. Rust opens files `O_CLOEXEC`, so the fd closes as
//!   soon as that sibling execs: the window is *microseconds*.
//! * `EAGAIN` / `ENOMEM` / `EMFILE` / `ENFILE` — the process table
//!   (`RLIMIT_NPROC`), memory, or the fd table momentarily had no room. This
//!   clears as concurrent children exit, but a *sustained* fork-pressure peak
//!   lasts far longer than the `ETXTBSY` window, so it is given seconds.
//!
//! One *classification* is the point; one *deadline* is not. These helpers
//! previously coexisted with a second, `notes_repo`-local retry loop that
//! recognised exactly the resource errnos and *not* `ETXTBSY`, while this module
//! recognised `ETXTBSY` and *not* the resource errnos — so each caller was flaky
//! under precisely the pressure the other had been hardened against. Merging them
//! onto a single 2s deadline then over-waited the `ETXTBSY` path, which
//! poll-loop callers pay per spawn; hence one classifier, two bounds. Anything
//! that spawns a child goes through here.

use std::io;
use std::time::{Duration, Instant};

/// Why a spawn was refused, for the two classes that clear on their own.
///
/// One classifier, but two variants, because the classes are not
/// interchangeable: they clear on timescales four orders of magnitude apart, and
/// the right patience for one is the wrong patience for the other. Collapsing
/// them to a single deadline forces a choice between under-waiting the slow case
/// (a flake) and over-waiting the fast case (latency on a hot path that spawns in
/// a poll loop). Naming the classes lets each carry its own bound while keeping a
/// single place where "is this retryable?" is decided.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpawnRefusal {
    /// `ETXTBSY`: `execve` refused a program file that some process holds open
    /// for writing. A sibling thread's `fork` inherited a writable fd; it closes
    /// on that child's `exec`, so the window is *microseconds*.
    TextBusy,
    /// `EAGAIN` / `ENOMEM` / `EMFILE` / `ENFILE`: the process table, memory, or
    /// the fd table momentarily had no room. Clears as concurrent children exit,
    /// but a *sustained* fork-pressure peak lasts far longer than the `ETXTBSY`
    /// window.
    ResourceExhausted,
}

#[derive(Clone, Copy, Debug)]
struct RetryConfig {
    text_busy_deadline: Duration,
    resource_deadline: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl RetryConfig {
    fn deadline_for(&self, refusal: SpawnRefusal) -> Duration {
        match refusal {
            SpawnRefusal::TextBusy => self.text_busy_deadline,
            SpawnRefusal::ResourceExhausted => self.resource_deadline,
        }
    }
}

/// Both bounds are on elapsed *time*, not an attempt count: these conditions
/// clear on their own schedule, so N tries is either too shallow for a sustained
/// peak or an unbounded spin. The first attempt is immediate, so the happy path
/// pays nothing.
///
/// `text_busy_deadline` is ~4 orders of magnitude of headroom over the
/// microsecond `ETXTBSY` window. It is deliberately *not* raised to match the
/// resource bound: several call sites spawn in a tight poll loop and assert on
/// end-to-end latency (`broker_vm_runner`'s readiness poll fast-fails and is
/// tested against a 5s budget), so a 2s per-spawn ceiling there buys nothing and
/// costs real responsiveness.
///
/// `resource_deadline` is 2s because a 500ms ceiling was observed to still flake
/// under parallel-test fork pressure.
const DEFAULT_RETRY: RetryConfig = RetryConfig {
    text_busy_deadline: Duration::from_millis(500),
    resource_deadline: Duration::from_secs(2),
    initial_backoff: Duration::from_millis(2),
    max_backoff: Duration::from_millis(50),
};

/// Classify a failed spawn, returning `None` if it must not be retried.
///
/// Permanent failures are deliberately excluded: `ENOENT` (program not on
/// `PATH`), `EACCES`, `ENOEXEC`, and any error that maps to neither a refusal
/// errno nor a refusal `ErrorKind` must fail fast, because retrying only delays a
/// diagnosis that will not change.
///
/// Both the raw errno and the mapped [`io::ErrorKind`] are consulted. A real
/// spawn failure always carries an errno, so the errno arm is the operative one;
/// the kind arm covers an error that reached us already classified but stripped
/// of its errno, and means the classifier cannot silently narrow if std maps a
/// future refusal to a kind alone. `EMFILE`/`ENFILE` have no stable `ErrorKind`
/// variant, which is why the errno list cannot be dropped in favour of kinds.
fn classify_spawn_refusal(err: &io::Error) -> Option<SpawnRefusal> {
    match err.raw_os_error() {
        Some(libc::ETXTBSY) => return Some(SpawnRefusal::TextBusy),
        Some(libc::EAGAIN) | Some(libc::ENOMEM) | Some(libc::EMFILE) | Some(libc::ENFILE) => {
            return Some(SpawnRefusal::ResourceExhausted);
        }
        _ => {}
    }
    match err.kind() {
        io::ErrorKind::ExecutableFileBusy => Some(SpawnRefusal::TextBusy),
        io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory => {
            Some(SpawnRefusal::ResourceExhausted)
        }
        _ => None,
    }
}

fn retry_sync_with<T>(config: RetryConfig, mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let start = Instant::now();
    let mut backoff = config.initial_backoff;
    loop {
        match op() {
            Ok(v) => return Ok(v),
            Err(err) => {
                // The deadline follows the error we actually saw, re-derived each
                // attempt: a run that starts as `ETXTBSY` and becomes `EAGAIN`
                // (or vice versa) gets the patience the current condition
                // deserves, not whichever class happened to appear first.
                let Some(refusal) = classify_spawn_refusal(&err) else {
                    return Err(err);
                };
                if Instant::now() + backoff > start + config.deadline_for(refusal) {
                    return Err(err);
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(config.max_backoff);
            }
        }
    }
}

/// Spawn a child process, retrying briefly on a refused spawn — one the OS
/// rejected outright, so the child never ran (`ETXTBSY`, `EAGAIN`, `ENOMEM`,
/// `EMFILE`, `ENFILE`). Any other failure is returned on the first attempt.
pub fn spawn(command: &mut std::process::Command) -> io::Result<std::process::Child> {
    retry_sync_with(DEFAULT_RETRY, || command.spawn())
}

/// Run a command to completion, retrying briefly on a refused spawn from the
/// initial spawn. Equivalent to `Command::output` for the wait-and-collect
/// behaviour, but applies the retry to the spawn step. The caller must
/// configure stdio explicitly: unlike `Command::output`, this inherits
/// the parent's stdin/stdout/stderr by default rather than defaulting
/// stdin to null and stdout/stderr to piped. Pass `Stdio::null()` for
/// stdin if the child should see EOF.
pub fn output(command: &mut std::process::Command) -> io::Result<std::process::Output> {
    wait_collecting(spawn(command)?)
}

/// Collect a spawned child's output, **always waiting for it to exit** — even if
/// draining its pipes fails. `std::process::Child::wait_with_output` returns on a
/// pipe read error *without* waiting, leaving the child running; a caller that
/// treats a collection error as "the command ran" (and then, say, cleans up based
/// on the resulting state) would otherwise race a still-live child that can still
/// perform its side effect.
///
/// A concurrent reader thread is used only when *both* streams are piped (else one
/// full pipe could deadlock draining the other). With zero or one piped stream —
/// the common case for inherited/null stdio, and for calls that pipe only
/// stderr — everything drains inline, so no thread is spawned and a tight
/// `RLIMIT_NPROC` cannot fail an otherwise valid command.
pub fn wait_collecting(mut child: std::process::Child) -> io::Result<std::process::Output> {
    // Drop any piped stdin before waiting, exactly as `Child::wait_with_output`
    // does: a child that reads to EOF would otherwise block forever on the
    // parent-held writer, hanging the wait.
    drop(child.stdin.take());
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    // A `wait` error means the child was already reaped elsewhere (`ECHILD`), so
    // it is not running — we must *not* kill by PID (it may have been recycled to
    // an unrelated process); the readers still reach EOF because the process is
    // gone. On return the process has exited.
    let (stdout, stderr, status) = if stdout_pipe.is_some() && stderr_pipe.is_some() {
        // Two live pipes: drain one on a thread while draining the other inline.
        // `thread::spawn` *panics* under thread exhaustion, so use
        // `thread::Builder::spawn`, which surfaces the failure.
        match spawn_pipe_reader(stderr_pipe) {
            Ok(stderr_reader) => {
                let stdout = read_pipe(stdout_pipe);
                let status = child.wait();
                let stderr = stderr_reader.join().unwrap_or_else(|_| Ok(Vec::new()));
                (stdout, stderr, status)
            }
            Err(err) => {
                // Report the collection failure — don't fabricate a command
                // result. Closing the stderr reader can `SIGPIPE`-kill the child,
                // so its exit status here may be collector-induced. Still reap the
                // child (no leak) without deadlocking: its stderr read end is
                // already closed by the failed spawn, and draining stdout inline
                // keeps it from blocking on a full pipe. No PID-based kill (which
                // could hit a recycled PID under an auto/external reaper).
                let _ = read_pipe(stdout_pipe);
                let _ = child.wait();
                return Err(err);
            }
        }
    } else {
        // At most one pipe: drain it inline, then wait. No deadlock is possible
        // with a single pipe, and no thread is needed.
        let stdout = read_pipe(stdout_pipe);
        let stderr = read_pipe(stderr_pipe);
        let status = child.wait();
        (stdout, stderr, status)
    };
    Ok(std::process::Output {
        status: status?,
        stdout: stdout?,
        stderr: stderr?,
    })
}

/// Drain `pipe` to end-of-file (empty when `None`).
fn read_pipe<R: std::io::Read>(pipe: Option<R>) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    if let Some(mut pipe) = pipe {
        pipe.read_to_end(&mut buf)?;
    }
    Ok(buf)
}

/// Spawn a thread that drains `pipe` to end-of-file. Uses `thread::Builder` so
/// thread-creation failure surfaces as an `io::Error` rather than a panic.
fn spawn_pipe_reader<R: std::io::Read + Send + 'static>(
    pipe: Option<R>,
) -> io::Result<std::thread::JoinHandle<io::Result<Vec<u8>>>> {
    std::thread::Builder::new().spawn(move || read_pipe(pipe))
}

/// Async twin of [`spawn`]: identical classification and backoff schedule, but
/// yields to the runtime between attempts instead of blocking the thread.
#[cfg(feature = "host")]
pub async fn spawn_async(
    command: &mut tokio::process::Command,
) -> io::Result<tokio::process::Child> {
    let config = DEFAULT_RETRY;
    let start = Instant::now();
    let mut backoff = config.initial_backoff;
    loop {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(err) => {
                let Some(refusal) = classify_spawn_refusal(&err) else {
                    return Err(err);
                };
                if Instant::now() + backoff > start + config.deadline_for(refusal) {
                    return Err(err);
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(config.max_backoff);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn etxtbsy() -> io::Error {
        io::Error::from(io::ErrorKind::ExecutableFileBusy)
    }

    fn fast_config() -> RetryConfig {
        RetryConfig {
            text_busy_deadline: Duration::from_millis(50),
            resource_deadline: Duration::from_millis(50),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
        }
    }

    /// The whole all-or-nothing class is retryable, not just `ETXTBSY`. Each of
    /// these means the spawn was *refused* — the child never ran — so a retry
    /// re-runs nothing. Two callers previously each recognised a disjoint subset
    /// (`process_spawn` only `ETXTBSY`; `notes_repo` only the resource errnos),
    /// so each was flaky under exactly the pressure the other guarded against.
    #[test]
    fn every_all_or_nothing_spawn_refusal_is_retryable() {
        for errno in [
            libc::ETXTBSY,
            libc::EAGAIN,
            libc::ENOMEM,
            libc::EMFILE,
            libc::ENFILE,
        ] {
            assert!(
                classify_spawn_refusal(&io::Error::from_raw_os_error(errno)).is_some(),
                "errno {errno} refuses the spawn outright and must be retryable"
            );
        }
    }

    /// A spawn that failed for a *permanent* reason must fail on the first
    /// attempt: retrying `ENOENT` (git not installed) or `EACCES` only converts
    /// a crisp error into a delayed one, and an error with no OS errno cannot be
    /// classified at all so must not be assumed transient.
    #[test]
    fn permanent_spawn_failures_are_not_retryable() {
        for errno in [libc::ENOENT, libc::EACCES, libc::EINVAL, libc::ENOEXEC] {
            assert!(
                classify_spawn_refusal(&io::Error::from_raw_os_error(errno)).is_none(),
                "errno {errno} is permanent and must fail fast"
            );
        }
        assert!(classify_spawn_refusal(&io::Error::other("no errno")).is_none());
    }

    /// `EAGAIN` — the sustained-fork-pressure case `notes_repo` was hardened
    /// against — must now be absorbed by the shared retry loop too.
    #[test]
    fn retries_on_resource_exhaustion_then_succeeds() {
        let calls = Cell::new(0);
        let result = retry_sync_with(fast_config(), || {
            let n = calls.get() + 1;
            calls.set(n);
            if n < 3 {
                Err(io::Error::from_raw_os_error(libc::EAGAIN))
            } else {
                Ok(n)
            }
        })
        .unwrap();
        assert_eq!(result, 3);
        assert_eq!(calls.get(), 3);
    }

    /// Each errno maps to the class whose deadline suits it. Getting this mapping
    /// backwards would be invisible — both classes still retry — but would under-wait
    /// the sustained case and over-wait the fast one.
    #[test]
    fn errno_map_to_the_right_refusal_class() {
        assert_eq!(
            classify_spawn_refusal(&io::Error::from_raw_os_error(libc::ETXTBSY)),
            Some(SpawnRefusal::TextBusy)
        );
        for errno in [libc::EAGAIN, libc::ENOMEM, libc::EMFILE, libc::ENFILE] {
            assert_eq!(
                classify_spawn_refusal(&io::Error::from_raw_os_error(errno)),
                Some(SpawnRefusal::ResourceExhausted),
                "errno {errno} is resource exhaustion"
            );
        }
    }

    /// The resource deadline must be generous enough for a *sustained*
    /// fork-pressure peak: `notes_repo` chose 2s after observing that a 500ms
    /// ceiling still flaked, and unifying the retry must not regress that caller.
    #[test]
    fn resource_deadline_covers_sustained_fork_pressure() {
        assert!(
            DEFAULT_RETRY.resource_deadline >= Duration::from_secs(2),
            "resource deadline {:?} is too short for a sustained fork-pressure peak",
            DEFAULT_RETRY.resource_deadline
        );
    }

    /// The `ETXTBSY` deadline must stay well under the resource one.
    ///
    /// The `ETXTBSY` window is microseconds, and callers that spawn in a poll loop
    /// pay this bound per attempt on their fast-fail path — `broker_vm_runner`'s
    /// readiness poll asserts it fast-fails inside 5s. Raising this to match the
    /// resource deadline (which a first cut of the unification did) buys nothing
    /// and turns that budget into a flake.
    #[test]
    fn text_busy_deadline_stays_short_for_latency_sensitive_pollers() {
        assert!(
            DEFAULT_RETRY.text_busy_deadline <= Duration::from_millis(500),
            "ETXTBSY deadline {:?} is far longer than the microsecond window it \
             covers, and poll-loop callers pay it per spawn",
            DEFAULT_RETRY.text_busy_deadline
        );
        assert!(
            DEFAULT_RETRY.text_busy_deadline < DEFAULT_RETRY.resource_deadline,
            "the two classes clear on different timescales and must not share a bound"
        );
    }

    /// A persistent `ETXTBSY` gives up on its own (shorter) deadline, not the
    /// resource one — the behaviour the latency assertion above depends on.
    #[test]
    fn persistent_text_busy_gives_up_on_the_text_busy_deadline() {
        let config = RetryConfig {
            text_busy_deadline: Duration::from_millis(20),
            resource_deadline: Duration::from_secs(30),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
        };
        let started = Instant::now();
        let err = retry_sync_with(config, || {
            Err::<(), _>(io::Error::from_raw_os_error(libc::ETXTBSY))
        })
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ETXTBSY));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "gave up after {:?}; the resource deadline leaked into the ETXTBSY path",
            started.elapsed()
        );
    }

    #[test]
    fn returns_ok_immediately_when_op_succeeds() {
        let calls = Cell::new(0);
        let result = retry_sync_with(fast_config(), || {
            calls.set(calls.get() + 1);
            Ok::<_, io::Error>(42)
        })
        .unwrap();
        assert_eq!(result, 42);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn retries_on_etxtbsy_then_succeeds() {
        let calls = Cell::new(0);
        let result = retry_sync_with(fast_config(), || {
            let n = calls.get() + 1;
            calls.set(n);
            if n < 3 { Err(etxtbsy()) } else { Ok(n) }
        })
        .unwrap();
        assert_eq!(result, 3);
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn does_not_retry_non_etxtbsy_errors() {
        let calls = Cell::new(0);
        let err = retry_sync_with(fast_config(), || {
            calls.set(calls.get() + 1);
            Err::<(), _>(io::Error::from(io::ErrorKind::PermissionDenied))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn returns_etxtbsy_after_deadline() {
        let calls = Cell::new(0);
        let err = retry_sync_with(fast_config(), || {
            calls.set(calls.get() + 1);
            Err::<(), _>(etxtbsy())
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ExecutableFileBusy);
        assert!(
            calls.get() >= 2,
            "expected at least one retry, got {}",
            calls.get()
        );
    }

    #[cfg(unix)]
    #[test]
    fn wait_collecting_captures_both_streams_and_reaps_the_child() {
        use std::process::{Command, Stdio};
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "printf out; printf err >&2; exit 3"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = wait_collecting(spawn(&mut command).unwrap()).unwrap();
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
        assert_eq!(output.status.code(), Some(3));
    }

    #[cfg(unix)]
    #[test]
    fn wait_collecting_drops_piped_stdin_so_a_stdin_reader_does_not_hang() {
        // The command reads stdin to EOF (`cat`). With stdin piped but never
        // written, `wait_collecting` must drop the writer so the child sees EOF
        // and exits; otherwise the wait hangs forever. Bound the call in a thread
        // so a regression fails fast instead of wedging the test run.
        use std::process::{Command, Stdio};
        use std::sync::mpsc;
        use std::time::Duration;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "cat; printf done"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let _ = tx.send(wait_collecting(spawn(&mut command).unwrap()));
        });
        let output = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("wait_collecting hung — piped stdin was not dropped")
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"done");
    }

    #[cfg(unix)]
    #[test]
    fn wait_collecting_does_not_deadlock_on_a_one_sided_flood() {
        // A child that floods one stream far past the OS pipe buffer while writing
        // nothing to the other must not wedge the wait: both pipes are drained
        // concurrently, so the child never blocks on a full pipe.
        use std::process::{Command, Stdio};
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "head -c 1048576 /dev/zero"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = wait_collecting(spawn(&mut command).unwrap()).unwrap();
        assert_eq!(output.stdout.len(), 1_048_576);
        assert!(output.status.success());
    }
}
