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
    spawn(command)?.wait_with_output()
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
}
