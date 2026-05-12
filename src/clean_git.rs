//! Run Git subprocesses with a hardened, host-controlled environment.
//!
//! Several host-side flows (VM clone bundle creation, the upcoming VM push
//! replay engine) shell out to `git` against untrusted inputs. Each of those
//! flows independently needs the same defensive setup: strip the parent
//! environment, deny system/user/repo-local config discovery, run from a
//! known cwd, kill the process group on timeout, and observe the child's
//! exit without a race against signal delivery. This module is the small
//! shared core; callers wrap it with their own step-tagged error types and
//! plan/validation layers.

use std::ffi::OsString;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::process::Command;

use crate::process_spawn;

/// Environment variables prepended to every clean-Git invocation.
///
/// - `GIT_CONFIG_NOSYSTEM=1` disables `/etc/gitconfig`.
/// - `GIT_CONFIG_GLOBAL=/dev/null` disables `~/.gitconfig` and `$XDG_CONFIG_HOME/git/config`.
/// - `GIT_CONFIG_COUNT=0` disables any inherited `GIT_CONFIG_PARAMETERS`.
/// - `HOME=/dev/null` defends against helpers that look up dotfiles under `$HOME`
///   regardless of the `GIT_CONFIG_*` overrides (credential helpers, hook
///   scripts, third-party tools invoked via `core.editor`/`pre-receive`/etc).
pub(crate) const CLEAN_GIT_CONFIG_ENV: [(&str, &str); 4] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_COUNT", "0"),
    ("HOME", "/dev/null"),
];
// Git discovers repository-local config by walking up from cwd. Running from
// root prevents a broker-local `.git/config` from rewriting a pinned HTTPS URL.
pub(crate) const CLEAN_GIT_CURRENT_DIR: &str = "/";
const CHILD_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// A fully-specified Git invocation: resolved program, argv, env, and the
/// names of any secret env variables the runtime should populate from a
/// caller-supplied secret value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CleanGitInvocation {
    program: PathBuf,
    args: Vec<OsString>,
    env: Vec<CleanGitEnv>,
    required_secret_env: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CleanGitEnv {
    name: String,
    value: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CleanGitError {
    #[error(
        "git program must be absolute or discoverable on PATH before clearing the child environment: {0}"
    )]
    GitProgramNotFound(PathBuf),
    #[error("cannot canonicalize {field} path {path}: {source}")]
    Canonicalize {
        field: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Git command could not be spawned: {0}")]
    Spawn(std::io::Error),
    #[error("Git command wait failed: {0}")]
    Wait(std::io::Error),
    #[error("Git command timed out after {0:?}")]
    TimedOut(Duration),
    #[error("Git command failed with status {0}")]
    Failed(ExitStatus),
    #[error("Git command did not expose a child process id")]
    MissingProcessId,
    #[error("Git child process id {0} cannot be represented as a process group id")]
    InvalidProcessId(u32),
    #[error("Git process group {pgid} could not be killed after Git child exit: {source}")]
    KillProcessGroup {
        pgid: libc::pid_t,
        source: std::io::Error,
    },
}

impl CleanGitInvocation {
    pub(crate) fn new(
        program: PathBuf,
        args: impl IntoIterator<Item = impl Into<OsString>>,
        env: Vec<CleanGitEnv>,
        required_secret_env: Vec<String>,
    ) -> Self {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
            env,
            required_secret_env,
        }
    }

    pub(crate) fn program(&self) -> &Path {
        &self.program
    }

    pub(crate) fn args(&self) -> &[OsString] {
        &self.args
    }

    pub(crate) fn env(&self) -> &[CleanGitEnv] {
        &self.env
    }

    pub(crate) fn required_secret_env(&self) -> &[String] {
        &self.required_secret_env
    }

    #[cfg(test)]
    pub(crate) fn display_args_lossy(&self) -> Vec<String> {
        self.args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }
}

impl CleanGitEnv {
    pub(crate) fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn value(&self) -> &str {
        &self.value
    }
}

/// Build the per-invocation env vector containing only the hardened
/// `GIT_CONFIG_*` and `HOME` entries.
pub(crate) fn clean_git_config_env() -> Vec<CleanGitEnv> {
    CLEAN_GIT_CONFIG_ENV
        .into_iter()
        .map(|(name, value)| CleanGitEnv::new(name, value))
        .collect()
}

/// Run a Git invocation under the clean environment.
///
/// `secret` is the value to bind to each name in `invocation.required_secret_env()`.
/// It is an invariant violation if the invocation declares secret env vars but
/// no secret is supplied. Supplying a secret for an invocation with no declared
/// secret env vars is silently a no-op so callers can share a credential cache
/// across heterogeneous invocations.
pub(crate) async fn run_clean_git(
    invocation: &CleanGitInvocation,
    timeout: Duration,
    secret: Option<&str>,
) -> Result<(), CleanGitError> {
    debug_assert!(
        invocation.required_secret_env().is_empty() || secret.is_some(),
        "invocation declared required_secret_env but no secret was supplied"
    );

    let program = resolve_program_for_clean_env(invocation.program()).await?;
    let mut command = Command::new(program);
    command.env_clear();
    command.args(invocation.args());
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    command.current_dir(CLEAN_GIT_CURRENT_DIR);
    command.process_group(0);
    for env in invocation.env() {
        command.env(env.name(), env.value());
    }
    if let Some(secret_value) = secret {
        for secret_env in invocation.required_secret_env() {
            command.env(secret_env, secret_value);
        }
    }

    let mut child = process_spawn::spawn_async(&mut command)
        .await
        .map_err(CleanGitError::Spawn)?;
    let pid = child.id().ok_or(CleanGitError::MissingProcessId)?;
    let pgid = process_group_id(pid)?;
    let mut cleanup_guard = ProcessGroupCleanupGuard::new(pgid);
    match wait_for_child_exit_before_reap(pgid, timeout).await? {
        ChildExitObservation::Exited => {
            cleanup_guard.mark_child_exit_observed();
            cleanup_guard.kill_now()?;
            let status = child.wait().await;
            cleanup_guard.disarm();
            let status = status.map_err(CleanGitError::Wait)?;
            if status.success() {
                Ok(())
            } else {
                Err(CleanGitError::Failed(status))
            }
        }
        ChildExitObservation::TimedOut => {
            cleanup_guard.kill_now()?;
            let _ = child.wait().await;
            cleanup_guard.disarm();
            Err(CleanGitError::TimedOut(timeout))
        }
    }
}

pub(crate) async fn resolve_program_for_clean_env(
    program: &Path,
) -> Result<PathBuf, CleanGitError> {
    if program.is_absolute() {
        return match tokio::fs::metadata(program).await {
            Ok(metadata) if is_executable_file(&metadata) => {
                canonicalize_path("git_program", program).await
            }
            Ok(_) => Err(CleanGitError::GitProgramNotFound(program.to_path_buf())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Err(CleanGitError::GitProgramNotFound(program.to_path_buf()))
            }
            Err(source) => Err(CleanGitError::Canonicalize {
                field: "git_program",
                path: program.to_path_buf(),
                source,
            }),
        };
    }
    if program.components().count() != 1 {
        return Err(CleanGitError::GitProgramNotFound(program.to_path_buf()));
    }

    let Some(path) = std::env::var_os("PATH") else {
        return Err(CleanGitError::GitProgramNotFound(program.to_path_buf()));
    };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        match tokio::fs::metadata(&candidate).await {
            Ok(metadata) if is_executable_file(&metadata) => {
                return canonicalize_path("git_program", &candidate).await;
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CleanGitError::Canonicalize {
                    field: "git_program",
                    path: candidate,
                    source,
                });
            }
        }
    }
    Err(CleanGitError::GitProgramNotFound(program.to_path_buf()))
}

async fn canonicalize_path(field: &'static str, path: &Path) -> Result<PathBuf, CleanGitError> {
    tokio::fs::canonicalize(path)
        .await
        .map_err(|source| CleanGitError::Canonicalize {
            field,
            path: path.to_path_buf(),
            source,
        })
}

enum ChildExitObservation {
    Exited,
    TimedOut,
}

async fn wait_for_child_exit_before_reap(
    pid: libc::pid_t,
    timeout: Duration,
) -> Result<ChildExitObservation, CleanGitError> {
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

fn child_has_exited_without_reaping(pid: libc::pid_t) -> Result<bool, CleanGitError> {
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
        return Err(CleanGitError::Wait(std::io::Error::last_os_error()));
    }

    let status = unsafe { status.assume_init() };
    let observed_pid = unsafe { status.si_pid() };
    Ok(observed_pid != 0)
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

fn process_group_id(pid: u32) -> Result<libc::pid_t, CleanGitError> {
    pid.try_into()
        .map_err(|_| CleanGitError::InvalidProcessId(pid))
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

    fn kill_now(&self) -> Result<(), CleanGitError> {
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
) -> Result<(), CleanGitError> {
    // The child was spawned with process_group(0), making its pid the process
    // group id inherited by any ordinary Git helpers it starts.
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
    Err(CleanGitError::KillProcessGroup { pgid, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_git_config_env_pins_known_entries() {
        let env = clean_git_config_env();
        let pairs: Vec<(&str, &str)> = env.iter().map(|e| (e.name(), e.value())).collect();
        assert_eq!(
            pairs,
            vec![
                ("GIT_CONFIG_NOSYSTEM", "1"),
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_CONFIG_COUNT", "0"),
                ("HOME", "/dev/null"),
            ]
        );
    }

    #[test]
    fn clean_git_config_env_constant_matches_helper() {
        let helper = clean_git_config_env();
        for (pair, env) in CLEAN_GIT_CONFIG_ENV.iter().zip(helper.iter()) {
            assert_eq!(pair.0, env.name());
            assert_eq!(pair.1, env.value());
        }
        assert_eq!(CLEAN_GIT_CONFIG_ENV.len(), helper.len());
    }
}
