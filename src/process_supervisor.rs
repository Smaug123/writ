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
//! [`Command`] (program, argv, env, cwd, stdin/stderr) and map the
//! program-agnostic [`SupervisorError`] into their own step-tagged error
//! types. The supervisor owns only the parts that are subtle and must not
//! diverge between callers: the race-free `waitid(WNOWAIT)` observation, the
//! process-group kill, and the stdout drain.

use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::process::Command;

use crate::process_spawn;

const CHILD_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Whether the supervisor should capture the child's stdout or discard it.
///
/// Stderr and stdin are the caller's responsibility (set on the [`Command`]
/// before calling [`run_supervised`]); the supervisor only manages stdout
/// because it is the channel whose pipe it must drain to avoid a deadlock
/// against a child that writes more than one pipe buffer's worth.
#[derive(Copy, Clone)]
pub(crate) enum StdoutMode {
    Discard,
    Capture,
}

/// The result of a supervised run that spawned and was waited on without a
/// supervisor-level failure. A non-zero exit is *not* an error here — it is
/// reported as [`SupervisedOutcome::Exited`] with the failing status, so the
/// caller decides whether a non-success exit is fatal for its flow.
pub(crate) enum SupervisedOutcome {
    Exited { status: ExitStatus, stdout: Vec<u8> },
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
/// stdin, stderr) *except* stdout and the process group, which this function
/// sets from `stdout_mode` and `process_group(0)` so the kill-the-group
/// contract holds. The returned [`SupervisedOutcome`] distinguishes a clean
/// exit (with its status and any captured stdout) from a timeout.
pub(crate) async fn run_supervised(
    command: &mut Command,
    timeout: Duration,
    stdout_mode: StdoutMode,
) -> Result<SupervisedOutcome, SupervisorError> {
    command.stdout(match stdout_mode {
        StdoutMode::Discard => Stdio::null(),
        StdoutMode::Capture => Stdio::piped(),
    });
    command.process_group(0);

    let mut child = process_spawn::spawn_async(command)
        .await
        .map_err(SupervisorError::Spawn)?;
    let pid = child.id().ok_or(SupervisorError::MissingProcessId)?;
    let pgid = process_group_id(pid)?;
    // Drain stdout concurrently with the child's lifetime so a child that
    // writes more than one pipe buffer's worth before we reach `wait()`
    // cannot stall on a full pipe. The drain task only reaches EOF once
    // every fd pointing at the write end is closed — that includes any
    // helper the tool forked into the same process group, so we rely on the
    // group SIGKILL further down to close inherited stdouts when the leader
    // has exited.
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
            Ok(SupervisedOutcome::Exited { status, stdout })
        }
        ChildExitObservation::TimedOut => {
            cleanup_guard.kill_now()?;
            let _ = child.wait().await;
            cleanup_guard.disarm();
            if let Some(handle) = stdout_drain {
                let _ = handle.await;
            }
            Ok(SupervisedOutcome::TimedOut)
        }
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
