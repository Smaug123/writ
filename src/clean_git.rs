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
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::process::Command;

use crate::process_supervisor::{self, StderrMode, StdoutMode, SupervisedOutcome, SupervisorError};

/// Environment variables prepended to every clean-Git invocation.
///
/// Re-exported from [`writ_core::git_env`], which is the single definition for
/// the whole workspace and documents what each variable denies. Kept as a
/// `clean_git` name because several call sites import it from here.
pub(crate) use writ_core::git_env::CLEAN_GIT_CONFIG_ENV;
// Git discovers repository-local config by walking up from cwd. Running from
// root prevents a broker-local `.git/config` from rewriting a pinned HTTPS URL.
pub(crate) const CLEAN_GIT_CURRENT_DIR: &str = "/";

/// Stdout byte cap for clean-Git commands whose output is a single short line —
/// `cat-file -t` (a type word), `rev-parse` (one object id), or
/// `rev-parse --is-shallow-repository` (`true`/`false`). Real output is at most
/// ~65 bytes; 4 KiB leaves generous headroom while still bounding a
/// malfunctioning or hostile `git` that streams unbounded stdout on one of
/// these plumbing commands. Commands with genuinely variable-size output (a
/// `rev-list` walk over an untrusted bundle) pass their own, larger cap.
pub(crate) const SMALL_STDOUT_CAP: usize = 4 * 1024;

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
    #[error("Git command failed with status {status}: {stderr}")]
    Failed {
        status: ExitStatus,
        /// The child's captured stderr, tail-capped and with any bound secret
        /// redacted (see [`sanitize_git_stderr`]). Carries the real diagnosis
        /// (`Authentication failed`, `Could not resolve host`, …) that a bare
        /// exit status hides.
        stderr: String,
    },
    #[error("Git command did not expose a child process id")]
    MissingProcessId,
    #[error("Git child process id {0} cannot be represented as a process group id")]
    InvalidProcessId(u32),
    #[error("Git process group {pgid} could not be killed after Git child exit: {source}")]
    KillProcessGroup {
        pgid: libc::pid_t,
        source: std::io::Error,
    },
    #[error(
        "Git command wrote more than the {cap}-byte stdout capture cap; the process group was killed and the output discarded"
    )]
    StdoutCapExceeded { cap: usize },
}

// Map the program-agnostic supervisor failures back onto the Git-flavoured
// variants this module's callers already match on, so the shared supervision
// loop is an implementation detail rather than a wire-visible change.
impl From<SupervisorError> for CleanGitError {
    fn from(err: SupervisorError) -> Self {
        match err {
            SupervisorError::ProgramNotFound(path) => CleanGitError::GitProgramNotFound(path),
            SupervisorError::Canonicalize {
                field,
                path,
                source,
            } => CleanGitError::Canonicalize {
                field,
                path,
                source,
            },
            SupervisorError::Spawn(source) => CleanGitError::Spawn(source),
            SupervisorError::Wait(source) => CleanGitError::Wait(source),
            SupervisorError::MissingProcessId => CleanGitError::MissingProcessId,
            SupervisorError::InvalidProcessId(pid) => CleanGitError::InvalidProcessId(pid),
            SupervisorError::KillProcessGroup { pgid, source } => {
                CleanGitError::KillProcessGroup { pgid, source }
            }
        }
    }
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

/// Run a Git invocation under the clean environment, discarding stdout.
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
    run_clean_git_inner(invocation, timeout, secret, StdoutMode::Discard)
        .await
        .map(|_| ())
}

/// Run a Git invocation under the clean environment and return the bytes
/// the child wrote to stdout.
///
/// Same hardening as [`run_clean_git`]; the only difference is the stdout
/// disposition. Use this when the result of the command is encoded in the
/// child's stdout (e.g. `cat-file -t` returns the object's type), not just
/// in the exit code.
///
/// `stdout_byte_cap` bounds the captured output: a child that writes more is
/// killed (process group SIGKILLed) and the call fails with
/// [`CleanGitError::StdoutCapExceeded`] rather than letting the host buffer
/// unbounded bytes. Every caller must state its bound — [`SMALL_STDOUT_CAP`]
/// for single-line plumbing commands, a larger explicit cap for commands whose
/// output size is driven by untrusted input.
pub(crate) async fn run_clean_git_capture_stdout(
    invocation: &CleanGitInvocation,
    timeout: Duration,
    stdout_byte_cap: usize,
    secret: Option<&str>,
) -> Result<Vec<u8>, CleanGitError> {
    run_clean_git_inner(
        invocation,
        timeout,
        secret,
        StdoutMode::Capture {
            byte_cap: stdout_byte_cap,
        },
    )
    .await
}

async fn run_clean_git_inner(
    invocation: &CleanGitInvocation,
    timeout: Duration,
    secret: Option<&str>,
    stdout_mode: StdoutMode,
) -> Result<Vec<u8>, CleanGitError> {
    debug_assert!(
        invocation.required_secret_env().is_empty() || secret.is_some(),
        "invocation declared required_secret_env but no secret was supplied"
    );

    let program = resolve_program_for_clean_env(invocation.program()).await?;
    let mut command = Command::new(program);
    command.env_clear();
    command.args(invocation.args());
    command.stdin(Stdio::null());
    command.current_dir(CLEAN_GIT_CURRENT_DIR);
    for env in invocation.env() {
        command.env(env.name(), env.value());
    }
    if let Some(secret_value) = secret {
        for secret_env in invocation.required_secret_env() {
            command.env(secret_env, secret_value);
        }
    }

    // The supervisor owns stdout/stderr disposition, the process group, the
    // spawn, the timeout, and the group SIGKILL; this module keeps only the
    // Git-specific environment hardening and the success/exit-status policy.
    // Stderr is captured so a failure surfaces git's real diagnosis rather than
    // a bare exit code; it is sanitised (secret-redacted) before it escapes.
    match process_supervisor::run_supervised(
        &mut command,
        timeout,
        stdout_mode,
        StderrMode::Capture,
    )
    .await?
    {
        SupervisedOutcome::Exited {
            status,
            stdout,
            stderr,
            ran_nothing: _,
        } => {
            if status.success() {
                Ok(stdout)
            } else {
                Err(CleanGitError::Failed {
                    status,
                    stderr: sanitize_git_stderr(&stderr, secret),
                })
            }
        }
        SupervisedOutcome::TimedOut => Err(CleanGitError::TimedOut(timeout)),
        SupervisedOutcome::StdoutCapExceeded { cap } => {
            Err(CleanGitError::StdoutCapExceeded { cap })
        }
    }
}

/// Turn captured stderr bytes into a bounded, secret-free diagnostic string.
///
/// The bytes are a *line-aligned* tail-capped capture from the supervisor: on
/// truncation the partial leading line is dropped, so every retained line is
/// complete. Truncation can therefore strand a full trailing *segment* of the
/// secret (a complete retained line) but never a mid-line fragment. We redact
/// the whole secret **and each of its newline-delimited segments**, so the
/// redaction is complete without assuming the secret is single-line — for the
/// real credential (a newline-free git token) the only segment is the token
/// itself, so this is exactly a token redaction; for any multi-line secret a
/// retained complete segment is still removed.
///
/// Redacting the token is defence in depth (git's HTTPS transport takes it via
/// the askpass helper and does not normally echo it, but a future flow or a
/// helper that logs a credentialed URL must never leak it). We lossily decode,
/// redact, and trim; an empty capture becomes a stable placeholder so the error
/// `Display` stays readable.
fn sanitize_git_stderr(stderr: &[u8], secret: Option<&str>) -> String {
    let mut text = String::from_utf8_lossy(stderr).into_owned();
    if let Some(secret) = secret {
        for fragment in std::iter::once(secret).chain(secret.split('\n')) {
            if !fragment.is_empty() {
                text = text.replace(fragment, "<redacted>");
            }
        }
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        "<no stderr captured>".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Resolve `git` to a canonical executable path with the Git-specific
/// `git_program` field label, delegating to the shared supervisor resolver.
///
/// Kept as a `clean_git`-named wrapper because several call sites already
/// import `clean_git::resolve_program_for_clean_env`; behaviour and error
/// shape are unchanged.
pub(crate) async fn resolve_program_for_clean_env(
    program: &Path,
) -> Result<PathBuf, CleanGitError> {
    process_supervisor::resolve_program(program, "git_program")
        .await
        .map_err(CleanGitError::from)
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
                // Not covered by `GIT_CONFIG_COUNT=0`: git parses this on an
                // independent path, so `-c`-style injection needs its own denial.
                ("GIT_CONFIG_PARAMETERS", ""),
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

    /// Locate an executable on `PATH` without resolving symlinks.
    /// Mirrors `resolve_program_for_clean_env` but preserves the
    /// caller-visible path so the basename survives into `argv[0]`
    /// after `execve` — critical on Nix where coreutils is a
    /// multi-call binary dispatched by `basename(argv[0])`.
    fn locate_on_path(name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::var_os("PATH").expect("PATH must be set in tests");
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            match std::fs::metadata(&candidate) {
                Ok(meta) if meta.is_file() && (meta.permissions().mode() & 0o111) != 0 => {
                    return candidate;
                }
                _ => {}
            }
        }
        panic!("required test tool {name} not found on PATH");
    }

    /// Runtime probe: spawn a subprocess via the clean-git harness and
    /// confirm only the hardened env entries (plus a small allowlist
    /// of shell-startup names) reach the child.
    ///
    /// We wrap `env` in a `sh` script rather than invoking `env` directly
    /// because:
    ///   * `resolve_program_for_clean_env` canonicalises symlinks, and
    ///   * on Nix, the `env` on `PATH` is a symlink into a multi-call
    ///     coreutils binary that dispatches by `basename(argv[0])`.
    ///
    /// Exec'ing the canonical store path would set `argv[0]` to the
    /// coreutils target, and coreutils would fail with a help message.
    /// Routing through `sh -c 'exec <path-with-name-env>'` keeps the
    /// `env` basename in `argv[0]` so coreutils dispatches correctly.
    /// The cost is that `sh` adds a few startup variables (PWD, SHLVL,
    /// `_`, OLDPWD); we allowlist those and assert that anything else
    /// observed must be one of the hardened entries with the
    /// expected value.
    #[tokio::test]
    async fn run_clean_git_subprocess_sees_only_hardened_env_vars() {
        use std::collections::BTreeMap;
        use std::os::unix::fs::PermissionsExt;

        let sh = locate_on_path("sh");
        let env_bin = locate_on_path("env");
        let tempdir = tempfile::tempdir().expect("tempdir for env probe");
        let probe = tempdir.path().join("env-probe");
        let script = format!("#!{}\nexec {}\n", sh.display(), env_bin.display());
        std::fs::write(&probe, script).expect("write env probe");
        let mut perms = std::fs::metadata(&probe).expect("probe meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&probe, perms).expect("chmod env probe");

        let invocation = CleanGitInvocation::new(
            probe,
            std::iter::empty::<OsString>(),
            clean_git_config_env(),
            Vec::new(),
        );
        let stdout = run_clean_git_capture_stdout(
            &invocation,
            Duration::from_secs(10),
            SMALL_STDOUT_CAP,
            None,
        )
        .await
        .unwrap_or_else(|err| {
            // A `Spawn(ETXTBSY)` here means a sibling test's `fork()`
            // held a writable fd to the just-written probe past the
            // retry ceiling under parallel-test load; any other
            // variant points elsewhere. Surface the exact error so a
            // future flake is self-diagnosing rather than a bare
            // "env probe must succeed".
            panic!("env probe must succeed, but clean-git run failed: {err:?}");
        });
        let text = std::str::from_utf8(&stdout).expect("env output is UTF-8");

        let hardened: BTreeMap<&str, &str> = [
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_COUNT", "0"),
            ("GIT_CONFIG_PARAMETERS", ""),
            ("HOME", "/dev/null"),
        ]
        .into_iter()
        .collect();
        // sh implicitly exports a handful of names on startup. They are not
        // parent-process leakage: PWD/OLDPWD reflect the cwd we passed in,
        // SHLVL/`_` are sh internals. We tolerate them rather than assert
        // their absence so the test stays portable across sh variants.
        const SH_STARTUP: &[&str] = &["PWD", "OLDPWD", "SHLVL", "_"];

        let mut observed: BTreeMap<String, String> = BTreeMap::new();
        for line in text.lines() {
            let Some((name, value)) = line.split_once('=') else {
                panic!("env probe output has malformed line {line:?}");
            };
            observed.insert(name.to_string(), value.to_string());
        }
        for (name, value) in &observed {
            if let Some(&expected) = hardened.get(name.as_str()) {
                assert_eq!(
                    value, expected,
                    "hardened env {name} reached the subprocess with the wrong value"
                );
                continue;
            }
            if SH_STARTUP.contains(&name.as_str()) {
                continue;
            }
            panic!(
                "subprocess saw unexpected env {name}={value:?}; \
                 env_clear/hardened-env wiring leaked"
            );
        }
        for want in hardened.keys() {
            assert!(
                observed.contains_key(*want),
                "subprocess missing hardened env var {want}; observed output: {text:?}"
            );
        }
    }

    /// A non-zero exit surfaces the child's stderr in `CleanGitError::Failed`,
    /// with any bound secret redacted — the whole point of capturing stderr is
    /// that a failure carries its real diagnosis, and the whole risk is that
    /// the diagnosis leaks a credential.
    #[tokio::test]
    async fn run_clean_git_failure_surfaces_redacted_stderr() {
        use std::os::unix::fs::PermissionsExt;

        let sh = locate_on_path("sh");
        let tempdir = tempfile::tempdir().expect("tempdir for fail probe");
        let probe = tempdir.path().join("fail-probe");
        // Echo a diagnostic that embeds the bound secret, then fail. `printf`
        // is a shell builtin so this needs no PATH (env is cleared).
        let script = format!(
            "#!{}\nprintf 'fatal: boom for %s\\n' \"$SEKRIT\" 1>&2\nexit 7\n",
            sh.display()
        );
        std::fs::write(&probe, script).expect("write fail probe");
        let mut perms = std::fs::metadata(&probe).expect("probe meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&probe, perms).expect("chmod fail probe");

        let invocation = CleanGitInvocation::new(
            probe,
            std::iter::empty::<OsString>(),
            clean_git_config_env(),
            vec!["SEKRIT".to_string()],
        );
        let err = run_clean_git(&invocation, Duration::from_secs(10), Some("s3cr3t-token"))
            .await
            .expect_err("probe exits non-zero");
        match err {
            CleanGitError::Failed { status, stderr } => {
                assert_eq!(status.code(), Some(7));
                assert!(
                    stderr.contains("fatal: boom"),
                    "stderr diagnosis must be surfaced, got {stderr:?}"
                );
                assert!(
                    !stderr.contains("s3cr3t-token"),
                    "the bound secret must be redacted, got {stderr:?}"
                );
                assert!(
                    stderr.contains("<redacted>"),
                    "redaction marker expected, got {stderr:?}"
                );
            }
            other => panic!("expected CleanGitError::Failed, got {other:?}"),
        }
    }

    /// A child that streams unbounded stdout is rejected with
    /// `StdoutCapExceeded` (not buffered to exhaustion), and the run returns
    /// promptly — a 30s timeout against a child that never stops writing proves
    /// the cap, not the clock, ends it.
    #[tokio::test]
    async fn run_clean_git_capture_rejects_unbounded_stdout() {
        let sh = locate_on_path("sh");
        let invocation = CleanGitInvocation::new(
            sh,
            [
                OsString::from("-c"),
                // Unbounded stdout via shell builtins only (no PATH needed under
                // the cleared environment).
                OsString::from("while :; do printf 'writ-overrun-padding\\n'; done"),
            ],
            clean_git_config_env(),
            Vec::new(),
        );
        let err =
            run_clean_git_capture_stdout(&invocation, Duration::from_secs(30), 64 * 1024, None)
                .await
                .expect_err("unbounded stdout must be rejected");
        match err {
            CleanGitError::StdoutCapExceeded { cap } => assert_eq!(cap, 64 * 1024),
            other => panic!("expected CleanGitError::StdoutCapExceeded, got {other:?}"),
        }
    }

    /// End-to-end guard against a secret leaking as a truncation-boundary
    /// fragment: a child floods stderr so the bound secret sits on a single
    /// over-cap line (its own line's start is truncated away). The supervisor's
    /// line-aligned tail drops that partial line wholesale, so neither the
    /// secret nor a fragment of it reaches the surfaced error — while the
    /// trailing complete fatal line survives.
    #[tokio::test]
    async fn run_clean_git_does_not_leak_secret_at_the_truncation_boundary() {
        use std::os::unix::fs::PermissionsExt;

        let sh = locate_on_path("sh");
        let tempdir = tempfile::tempdir().expect("tempdir for flood probe");
        let probe = tempdir.path().join("flood-probe");
        // ~13 KiB of newline-free filler, then the secret (still on that same
        // unbroken line), then a complete trailing line. The cap (8 KiB) lands
        // inside the giant line, so the retained tail begins mid-line; alignment
        // drops the whole line (secret and all).
        let script = format!(
            "#!{sh}\n\
             i=0\n\
             while [ $i -lt 1300 ]; do printf 'ABCDEFGHIJ' 1>&2; i=$((i+1)); done\n\
             printf 'TOK-%s-END' \"$SEKRIT\" 1>&2\n\
             printf '\\nfatal: boundary-test done\\n' 1>&2\n\
             exit 5\n",
            sh = sh.display()
        );
        std::fs::write(&probe, script).expect("write flood probe");
        let mut perms = std::fs::metadata(&probe).expect("probe meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&probe, perms).expect("chmod flood probe");

        let invocation = CleanGitInvocation::new(
            probe,
            std::iter::empty::<OsString>(),
            clean_git_config_env(),
            vec!["SEKRIT".to_string()],
        );
        let secret = "s3cr3t-boundary-xyz";
        let err = run_clean_git(&invocation, Duration::from_secs(20), Some(secret))
            .await
            .expect_err("probe exits non-zero");
        match err {
            CleanGitError::Failed { status, stderr } => {
                assert_eq!(status.code(), Some(5));
                assert!(
                    !stderr.contains(secret),
                    "the secret must not leak, got {stderr:?}"
                );
                // Even a fragment (the surrounding `TOK-...-END` marker) must be
                // gone: the whole truncated line was dropped, not just the exact
                // token redacted.
                assert!(
                    !stderr.contains("TOK-"),
                    "no fragment of the truncated secret line may survive, got {stderr:?}"
                );
                assert!(
                    stderr.contains("fatal: boundary-test done"),
                    "the trailing complete line must survive, got {stderr:?}"
                );
            }
            other => panic!("expected CleanGitError::Failed, got {other:?}"),
        }
    }

    #[test]
    fn sanitize_git_stderr_redacts_and_bounds() {
        assert_eq!(
            sanitize_git_stderr(b"  using tok=abc123 here \n", Some("abc123")),
            "using tok=<redacted> here"
        );
        // No secret bound: content passes through trimmed.
        assert_eq!(sanitize_git_stderr(b"fatal: nope\n", None), "fatal: nope");
        // Empty secret is not redacted to a marker (would match everywhere).
        assert_eq!(sanitize_git_stderr(b"hello", Some("")), "hello");
        // Empty capture yields a stable placeholder.
        assert_eq!(sanitize_git_stderr(b"   \n", None), "<no stderr captured>");
        // Multi-line secret: a full trailing segment stranded on a retained
        // line is redacted even though the whole secret string is not present.
        assert_eq!(
            sanitize_git_stderr(b"BBBB tail", Some("AAAA\nBBBB")),
            "<redacted> tail"
        );
    }
}
