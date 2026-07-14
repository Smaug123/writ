//! Spawn helpers that retry briefly on transient `ETXTBSY`.
//!
//! `execve` returns `ETXTBSY` ("Text file busy") when any process holds a
//! writable file descriptor to the target program. In a multi-threaded
//! test harness, a `fork()` in another thread can inherit a sibling's
//! still-open writable fd, causing `exec` of a freshly-installed script
//! to fail. Rust opens files with `O_CLOEXEC`, so the inherited fd closes
//! as soon as the sibling's child execs; retrying for a short window is
//! the standard mitigation.

use std::io;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
struct RetryConfig {
    deadline: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
}

const DEFAULT_RETRY: RetryConfig = RetryConfig {
    deadline: Duration::from_millis(500),
    initial_backoff: Duration::from_millis(2),
    max_backoff: Duration::from_millis(50),
};

fn is_transient_etxtbsy(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::ExecutableFileBusy
}

fn retry_sync_with<T>(config: RetryConfig, mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let deadline = Instant::now() + config.deadline;
    let mut backoff = config.initial_backoff;
    loop {
        match op() {
            Ok(v) => return Ok(v),
            Err(err) if is_transient_etxtbsy(&err) && Instant::now() + backoff <= deadline => {
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(config.max_backoff);
            }
            Err(err) => return Err(err),
        }
    }
}

/// Spawn a child process, retrying briefly on `ETXTBSY`.
pub fn spawn(command: &mut std::process::Command) -> io::Result<std::process::Child> {
    retry_sync_with(DEFAULT_RETRY, || command.spawn())
}

/// Run a command to completion, retrying briefly on `ETXTBSY` from the
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
/// perform its side effect. Draining both pipes on separate threads keeps a
/// one-sided flood from deadlocking the wait.
pub fn wait_collecting(mut child: std::process::Child) -> io::Result<std::process::Output> {
    // Drop any piped stdin before waiting, exactly as `Child::wait_with_output`
    // does: a child that reads to EOF would otherwise block forever on the
    // parent-held writer, hanging the wait.
    drop(child.stdin.take());
    // Spawn the pipe readers fallibly. `thread::spawn` *panics* under thread
    // exhaustion; unwinding would drop the child without reaping it, leaking a
    // live process. Killing here is safe — the child was just spawned and not yet
    // waited, so its identity is certain (no PID-reuse hazard).
    let stdout_reader = match spawn_pipe_reader(child.stdout.take()) {
        Ok(reader) => reader,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
    };
    let stderr_reader = match spawn_pipe_reader(child.stderr.take()) {
        Ok(reader) => reader,
        Err(err) => {
            // Kill the child so the already-running stdout reader hits EOF and its
            // join returns, then surface the error.
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            return Err(err);
        }
    };
    // Wait unconditionally so the child is reaped regardless of pipe outcome: on
    // return the process has exited. A `wait` error means the child was already
    // reaped elsewhere (`ECHILD`), so it is not running — we must *not* kill by
    // PID (it may have been recycled to an unrelated process); the readers still
    // reach EOF because the process is gone.
    let status = child.wait();
    let stdout = stdout_reader.join().unwrap_or_else(|_| Ok(Vec::new()));
    let stderr = stderr_reader.join().unwrap_or_else(|_| Ok(Vec::new()));
    Ok(std::process::Output {
        status: status?,
        stdout: stdout?,
        stderr: stderr?,
    })
}

/// Spawn a thread that drains `pipe` to end-of-file. Uses `thread::Builder` so
/// thread-creation failure surfaces as an `io::Error` rather than a panic.
fn spawn_pipe_reader<R: std::io::Read + Send + 'static>(
    pipe: Option<R>,
) -> io::Result<std::thread::JoinHandle<io::Result<Vec<u8>>>> {
    std::thread::Builder::new().spawn(move || {
        let mut pipe = pipe;
        let mut buf = Vec::new();
        if let Some(pipe) = pipe.as_mut() {
            pipe.read_to_end(&mut buf)?;
        }
        Ok(buf)
    })
}

#[cfg(feature = "host")]
pub async fn spawn_async(
    command: &mut tokio::process::Command,
) -> io::Result<tokio::process::Child> {
    let config = DEFAULT_RETRY;
    let deadline = Instant::now() + config.deadline;
    let mut backoff = config.initial_backoff;
    loop {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(err) if is_transient_etxtbsy(&err) && Instant::now() + backoff <= deadline => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(config.max_backoff);
            }
            Err(err) => return Err(err),
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
            deadline: Duration::from_millis(50),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
        }
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
