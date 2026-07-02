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
use std::time::Duration;

use tokio::process::Command;

use crate::process_spawn;

const CHILD_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Upper bound on captured stderr. A [`StderrMode::Capture`] child's stderr is
/// drained to EOF (so it never stalls on a full pipe) but only a line-aligned
/// tail of at most this many bytes is retained: a verbose or hostile child
/// cannot make the host buffer unbounded diagnostics, and a tool's fatal
/// message is typically its last line, so the tail is the informative part.
const STDERR_CAPTURE_TAIL_CAP: usize = 8 * 1024;

/// Whether the supervisor should capture the child's stdout or discard it.
///
/// Stdin is the caller's responsibility (set on the [`Command`] before calling
/// [`run_supervised`]); the supervisor manages stdout and stderr because those
/// are the channels whose pipes it must drain to avoid a deadlock against a
/// child that writes more than one pipe buffer's worth.
#[derive(Copy, Clone)]
pub(crate) enum StdoutMode {
    Discard,
    Capture,
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
    command.stdout(match stdout_mode {
        StdoutMode::Discard => Stdio::null(),
        StdoutMode::Capture => Stdio::piped(),
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
    // Drain stdout/stderr concurrently with the child's lifetime so a child
    // that writes more than one pipe buffer's worth before we reach `wait()`
    // cannot stall on a full pipe. A drain task only reaches EOF once every fd
    // pointing at the write end is closed — that includes any helper the tool
    // forked into the same process group, so we rely on the group SIGKILL
    // further down to close inherited pipes when the leader has exited.
    let stdout_drain = match stdout_mode {
        StdoutMode::Discard => None,
        StdoutMode::Capture => {
            let mut stdout = child
                .stdout
                .take()
                .expect("stdout was configured as Stdio::piped()");
            Some(tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = Vec::new();
                let _ = stdout.read_to_end(&mut buf).await;
                buf
            }))
        }
    };
    let stderr_drain = match stderr_mode {
        StderrMode::Discard => None,
        StderrMode::Capture => {
            let stderr = child
                .stderr
                .take()
                .expect("stderr was configured as Stdio::piped()");
            Some(tokio::spawn(drain_to_tail_cap(
                stderr,
                STDERR_CAPTURE_TAIL_CAP,
            )))
        }
    };
    let mut cleanup_guard = ProcessGroupCleanupGuard::new(pgid);
    match wait_for_child_exit_before_reap(pgid, timeout).await? {
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
            Ok(SupervisedOutcome::Exited {
                status,
                stdout,
                stderr,
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

/// Drain `reader` to EOF, retaining a line-aligned tail of at most `cap` bytes.
///
/// The whole stream is consumed so the child never stalls on a full pipe, but
/// memory stays bounded by `cap` (plus one read chunk): a verbose or hostile
/// child cannot make the host buffer unbounded output. The tail is kept
/// because a tool's fatal message is typically its last output. When the cap
/// truncates the head, the retained tail's first (partial) line is dropped so
/// every retained line is complete — see the body for why that soundness
/// property matters to a downstream secret redactor. Read errors end the drain
/// with whatever was accumulated so far, matching the best-effort
/// `read_to_end` used for stdout.
async fn drain_to_tail_cap<R>(mut reader: R, cap: usize) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > cap {
                    let excess = buf.len() - cap;
                    buf.drain(..excess);
                    truncated = true;
                }
            }
        }
    }
    // On truncation the retained tail begins at an arbitrary byte, so its first
    // line is a partial fragment of whatever preceded the cap. Drop it so every
    // retained line is complete. This is what keeps a downstream redactor sound:
    // a secret (a git token — no embedded newline) that straddled the cap would
    // otherwise survive as an unredactable partial fragment at the front. The
    // cost is one already-incomplete line. When the whole tail is one unbroken
    // line (no newline at all), it is dropped entirely — safe over sorry.
    if truncated {
        match buf.iter().position(|&b| b == b'\n') {
            Some(newline) => {
                buf.drain(..=newline);
            }
            None => buf.clear(),
        }
    }
    buf
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
}

async fn wait_for_child_exit_before_reap(
    pid: libc::pid_t,
    timeout: Duration,
) -> Result<ChildExitObservation, SupervisorError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
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
        return Err(SupervisorError::Wait(std::io::Error::last_os_error()));
    }

    let status = unsafe { status.assume_init() };
    let observed_pid = unsafe { status.si_pid() };
    Ok(observed_pid != 0)
}

fn process_group_id(pid: u32) -> Result<libc::pid_t, SupervisorError> {
    pid.try_into()
        .map_err(|_| SupervisorError::InvalidProcessId(pid))
}

struct ProcessGroupCleanupGuard {
    pgid: libc::pid_t,
    child_exit_observed: bool,
    armed: bool,
}

impl ProcessGroupCleanupGuard {
    fn new(pgid: libc::pid_t) -> Self {
        Self {
            pgid,
            child_exit_observed: false,
            armed: true,
        }
    }

    fn mark_child_exit_observed(&mut self) {
        self.child_exit_observed = true;
    }

    fn kill_now(&self) -> Result<(), SupervisorError> {
        kill_process_group_inner(self.pgid, self.child_exit_observed)
    }

    fn disarm(&mut self) {
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
    // The child was spawned with process_group(0), making its pid the process
    // group id inherited by any ordinary helpers it starts.
    let killed = unsafe { libc::killpg(pgid, libc::SIGKILL) };
    if killed == 0 {
        return Ok(());
    }
    let source = std::io::Error::last_os_error();
    if source.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    // On macOS, killpg can report EPERM after waitid(WNOWAIT) observes that
    // the leader has exited and there are no signalable live members left.
    if child_exit_observed && source.raw_os_error() == Some(libc::EPERM) {
        return Ok(());
    }
    Err(SupervisorError::KillProcessGroup { pgid, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locate an executable on `PATH`, preserving the caller-visible path so
    /// the basename survives `execve` (mirrors the clean_git test helper).
    fn locate_on_path(name: &str) -> PathBuf {
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
    async fn drain_to_tail_cap_keeps_all_when_under_cap() {
        // No truncation: content passes through verbatim, even without a
        // trailing newline and even with no newline at all.
        let data = b"short output".to_vec();
        let out = drain_to_tail_cap(&data[..], 4096).await;
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn drain_to_tail_cap_drops_partial_leading_line_on_truncation() {
        // The last `cap` bytes of "aaaa\nbbbb\ncccc\n" are "bb\ncccc\n"; the
        // leading "bb" is a fragment of a truncated line and must be dropped so
        // only complete lines remain (the property a redactor relies on).
        let data = b"aaaa\nbbbb\ncccc\n".to_vec();
        let out = drain_to_tail_cap(&data[..], 8).await;
        assert_eq!(out, b"cccc\n");
    }

    #[tokio::test]
    async fn drain_to_tail_cap_clears_when_truncated_tail_has_no_newline() {
        // A single unbroken over-cap line has no complete line to keep, so the
        // whole (necessarily partial) tail is dropped rather than surfaced.
        let data = b"aaaaaaaaaa".to_vec();
        let out = drain_to_tail_cap(&data[..], 4).await;
        assert!(out.is_empty(), "expected empty, got {out:?}");
    }

    #[tokio::test]
    async fn captures_stdout_and_stderr_on_nonzero_exit() {
        let mut command = Command::new(locate_on_path("sh"));
        command.arg("-c").arg("printf out; printf err 1>&2; exit 3");
        let outcome = run_supervised(
            &mut command,
            Duration::from_secs(10),
            StdoutMode::Capture,
            StderrMode::Capture,
        )
        .await
        .expect("supervised sh run");
        match outcome {
            SupervisedOutcome::Exited {
                status,
                stdout,
                stderr,
            } => {
                assert_eq!(status.code(), Some(3));
                assert_eq!(stdout, b"out");
                assert_eq!(stderr, b"err");
            }
            SupervisedOutcome::TimedOut => panic!("sh exited well within the timeout"),
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
        }
    }
}
