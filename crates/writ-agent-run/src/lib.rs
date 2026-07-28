//! Prompt and output contract for managed agent runs.
//!
//! The prompt is data, not process structure: it may cross an authenticated
//! broker channel, but it should not be embedded in argv, shell snippets,
//! environment variables, lifecycle state, or audit rows. Agent stdout/stderr
//! are captured as private files with bounded retained bytes and metadata that
//! can be audited without storing the stream bodies in SQLite.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

pub const VM_AGENT_RUN_PATH_PREFIX: &str = "/v1/agent-runs";
pub const MAX_AGENT_PROMPT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_AGENT_RUN_STREAM_CAPTURE_BYTES: u64 = 1024 * 1024;
pub const VM_AGENT_RUN_OUTCOME_PATH_SUFFIX: &str = "outcome";

/// Inclusive bounds on a [`CorrelationId`]. The lower bound rejects
/// the empty string at parse time so the audit column never has to
/// distinguish "absent" from "zero-length present".
pub const MIN_CORRELATION_ID_BYTES: usize = 1;
pub const MAX_CORRELATION_ID_BYTES: usize = 64;

#[derive(Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentRunId(Uuid);

#[derive(Clone, Eq, PartialEq)]
pub struct AgentPrompt(String);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentPromptSummary {
    pub byte_len: u64,
    pub sha256_hex: String,
    pub redacted_preview: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunTerminalStatus {
    Succeeded,
    Failed,
}

/// What an agent run's stream looks like **in the audit log**: the bytes that
/// are actually at `path`, plus whether there were more.
///
/// `byte_len` and `sha256_hex` describe the retained bytes — the file — and
/// nothing else. That is the only reading under which they can be checked
/// against anything: the row is what survives, and the row's `path` is what an
/// operator opens. When `truncated`, the stream *was* longer, and how much
/// longer is deliberately not recorded, because on the VM path that number is
/// a claim by an untrusted guest.
///
/// A run that has just been captured knows more than this — see
/// [`AgentRunStreamCapture`], which carries both the retained and the whole
/// stream and projects down to this type. Keep the two apart: this one is a
/// lossy projection, and it is also what gets read back out of SQLite, where
/// the fuller information no longer exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentRunStreamSummary {
    pub path: PathBuf,
    pub byte_len: u64,
    pub sha256_hex: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentRunOutcome {
    pub run_id: AgentRunId,
    pub status: AgentRunTerminalStatus,
    pub exit_code: i32,
    pub stdout: AgentRunStreamSummary,
    pub stderr: AgentRunStreamSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentRunStreamUpload {
    pub byte_len: u64,
    pub sha256_hex: String,
    pub truncated: bool,
    pub retained_sha256_hex: String,
    pub retained_base64: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmAgentRunOutcomeUpload {
    pub run_id: AgentRunId,
    pub status: AgentRunTerminalStatus,
    pub exit_code: i32,
    pub stdout: AgentRunStreamUpload,
    pub stderr: AgentRunStreamUpload,
}

/// Wire shape for `GET /v1/agent-runs/<id>/config`. Carries the prompt
/// and model the broker pinned to this agent run; the VM-side wrapper
/// feeds the prompt directly to the agent process with no further
/// composition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmAgentRunConfigResponse {
    run_id: AgentRunId,
    prompt: AgentPrompt,
    model: String,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("agent prompt is {byte_len} bytes, exceeding the {max_bytes}-byte limit")]
pub struct AgentPromptError {
    byte_len: usize,
    max_bytes: usize,
}

impl AgentRunId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl Default for AgentRunId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::str::FromStr for AgentRunId {
    type Err = uuid::Error;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        raw.parse().map(Self)
    }
}

impl fmt::Display for AgentRunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for AgentRunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentRunId({})", self.0)
    }
}

impl AgentPrompt {
    pub fn try_new(prompt: impl Into<String>) -> Result<Self, AgentPromptError> {
        let prompt = prompt.into();
        let byte_len = prompt.len();
        if byte_len > MAX_AGENT_PROMPT_BYTES {
            return Err(AgentPromptError {
                byte_len,
                max_bytes: MAX_AGENT_PROMPT_BYTES,
            });
        }
        Ok(Self(prompt))
    }

    /// Test-only convenience constructor. Panics on an over-limit prompt, so it
    /// is gated to test builds and the `test-support` feature (which downstream
    /// test crates enable) rather than exposed as production API — production
    /// code parses via [`AgentPrompt::try_new`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(prompt: impl Into<String>) -> Self {
        Self::try_new(prompt).expect("test prompt must be within the agent prompt limit")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn byte_len(&self) -> u64 {
        self.0.len() as u64
    }

    #[cfg(feature = "host")]
    pub fn summary(&self) -> AgentPromptSummary {
        AgentPromptSummary {
            byte_len: self.byte_len(),
            sha256_hex: sha256_hex(self.as_bytes()),
            redacted_preview: "<redacted>".to_string(),
        }
    }
}

impl Serialize for AgentPrompt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AgentPrompt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let prompt = String::deserialize(deserializer)?;
        Self::try_new(prompt).map_err(serde::de::Error::custom)
    }
}

impl VmAgentRunConfigResponse {
    pub fn new(run_id: AgentRunId, prompt: AgentPrompt, model: impl Into<String>) -> Self {
        Self {
            run_id,
            prompt,
            model: model.into(),
        }
    }

    pub fn run_id(&self) -> AgentRunId {
        self.run_id
    }

    pub fn prompt(&self) -> &AgentPrompt {
        &self.prompt
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn into_parts(self) -> (AgentPrompt, String) {
        (self.prompt, self.model)
    }
}

impl fmt::Debug for AgentPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentPrompt")
            .field("byte_len", &self.byte_len())
            .field("value", &"<redacted>")
            .finish()
    }
}

pub fn vm_agent_run_config_path(run_id: AgentRunId) -> String {
    format!("{VM_AGENT_RUN_PATH_PREFIX}/{run_id}/config")
}

pub fn vm_agent_run_outcome_path(run_id: AgentRunId) -> String {
    format!("{VM_AGENT_RUN_PATH_PREFIX}/{run_id}/{VM_AGENT_RUN_OUTCOME_PATH_SUFFIX}")
}

#[cfg(any(feature = "host", feature = "vm-client"))]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    hex_lower(digest.as_ref())
}

/// SHA-256 over bytes that arrive a chunk at a time, yielding the same
/// lowercase hex [`sha256_hex`] does.
///
/// Streams too big to hold are hashed in more than one place — the run capture
/// measures a pipe as it writes it to disk, and the host re-measures that file
/// when building the envelope — and those digests get compared to each other.
/// One implementation is what makes the comparison meaningful, so this exists
/// rather than a `ring::digest::Context` at each site.
#[cfg(any(feature = "host", feature = "vm-client"))]
pub struct Sha256Stream(ring::digest::Context);

#[cfg(any(feature = "host", feature = "vm-client"))]
impl Sha256Stream {
    pub fn new() -> Self {
        Self(ring::digest::Context::new(&ring::digest::SHA256))
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub fn finish_hex(self) -> String {
        hex_lower(self.0.finish().as_ref())
    }
}

#[cfg(any(feature = "host", feature = "vm-client"))]
impl Default for Sha256Stream {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "host", feature = "vm-client"))]
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

// --- CorrelationId ----------------------------------------------------

/// Opaque caller-supplied identifier tying related agent runs and git
/// pushes together. Per the broker design (§"Correlation ID"), the
/// broker validates only as a safe id — bounded length, restricted
/// character class — and never interprets the contents. The upstream
/// orchestrator (today: a human; later: a separate agent) decides
/// what the id means.
///
/// Character class is `[A-Za-z0-9_-]` and length is
/// [`MIN_CORRELATION_ID_BYTES`]..=[`MAX_CORRELATION_ID_BYTES`]. The
/// class is deliberately narrow: no dots, slashes, or colons — that
/// way a correlation id cannot pose as a path segment or scheme
/// component if it ever leaks into a URL.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CorrelationId(String);

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CorrelationIdError {
    #[error(
        "correlation id must be {min}..={max} bytes; got {got}",
        min = MIN_CORRELATION_ID_BYTES,
        max = MAX_CORRELATION_ID_BYTES,
    )]
    InvalidLength { got: usize },
    #[error("correlation id byte at offset {at} is {byte:?}; expected [A-Za-z0-9_-]")]
    InvalidByte { at: usize, byte: u8 },
}

impl CorrelationId {
    pub fn try_new(raw: impl Into<String>) -> Result<Self, CorrelationIdError> {
        let raw = raw.into();
        let len = raw.len();
        if !(MIN_CORRELATION_ID_BYTES..=MAX_CORRELATION_ID_BYTES).contains(&len) {
            return Err(CorrelationIdError::InvalidLength { got: len });
        }
        for (at, byte) in raw.bytes().enumerate() {
            let ok = byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_';
            if !ok {
                return Err(CorrelationIdError::InvalidByte { at, byte });
            }
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CorrelationId({:?})", self.0)
    }
}

impl FromStr for CorrelationId {
    type Err = CorrelationIdError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::try_new(raw)
    }
}

impl Serialize for CorrelationId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CorrelationId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(any(feature = "host", feature = "vm-client"))]
mod process_runner {
    use std::ffi::OsString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::thread;

    use writ_core::process_spawn;

    use super::{
        AgentPrompt, AgentRunId, AgentRunOutcome, AgentRunStreamSummary, AgentRunTerminalStatus,
        DEFAULT_AGENT_RUN_STREAM_CAPTURE_BYTES,
    };

    /// One captured stream, as measured at the moment of capture: both the
    /// bytes kept on disk and the whole stream that went past.
    ///
    /// Two pairs, because the two quantities answer different questions and
    /// conflating them is how a truncation offset ends up pointing past the
    /// bytes it describes. `retained_*` describes the file at `path` — what an
    /// operator can open, and what the audit row stores. `full_*` describes
    /// everything the child emitted, which is what the guest reports upstream
    /// so the host can see how much was lost.
    ///
    /// They coincide exactly when nothing was dropped, which is why
    /// [`truncated`](Self::truncated) is derived rather than stored: a capture
    /// claiming truncation while having kept the whole stream is not a state
    /// worth being able to build.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AgentRunStreamCapture {
        pub path: PathBuf,
        /// Length of the bytes at `path`.
        pub retained_byte_len: u64,
        /// SHA-256 of the bytes at `path`.
        pub retained_sha256_hex: String,
        /// Length of the whole stream, retained or not.
        pub full_byte_len: u64,
        /// SHA-256 of the whole stream, retained or not.
        pub full_sha256_hex: String,
    }

    impl AgentRunStreamCapture {
        /// Whether the stream outran the capture cap. Derived: it is exactly
        /// "we kept less than we saw".
        pub fn truncated(&self) -> bool {
            self.full_byte_len > self.retained_byte_len
        }

        /// Project onto the audit-facing [`AgentRunStreamSummary`], keeping the
        /// pair that describes the bytes on disk.
        ///
        /// This is the *only* way a summary is built from a capture, which is
        /// what makes the summary's meaning uniform no matter which arm of
        /// `RunAgent` produced it. The host arm records this directly; on the VM
        /// path the guest sends both pairs and the broker re-derives the same
        /// projection from bytes it has verified for itself.
        pub fn to_summary(&self) -> AgentRunStreamSummary {
            AgentRunStreamSummary {
                path: self.path.clone(),
                byte_len: self.retained_byte_len,
                sha256_hex: self.retained_sha256_hex.clone(),
                truncated: self.truncated(),
            }
        }
    }

    /// A finished agent run as measured by whoever ran it, before any of it is
    /// narrowed for the audit log.
    ///
    /// [`AgentRunOutcome`] is the same run seen through the audit row's
    /// vocabulary; [`to_outcome`](Self::to_outcome) is the narrowing.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AgentRunCapture {
        pub run_id: AgentRunId,
        pub status: AgentRunTerminalStatus,
        pub exit_code: i32,
        pub stdout: AgentRunStreamCapture,
        pub stderr: AgentRunStreamCapture,
    }

    impl AgentRunCapture {
        pub fn to_outcome(&self) -> AgentRunOutcome {
            AgentRunOutcome {
                run_id: self.run_id,
                status: self.status.clone(),
                exit_code: self.exit_code,
                stdout: self.stdout.to_summary(),
                stderr: self.stderr.to_summary(),
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AgentProcessPlan {
        run_id: AgentRunId,
        program: PathBuf,
        args: Vec<OsString>,
        cwd: Option<PathBuf>,
        env: Vec<(OsString, OsString)>,
        env_remove: Vec<OsString>,
        max_stream_capture_bytes: u64,
    }

    #[derive(Debug, thiserror::Error)]
    pub enum AgentProcessRunError {
        #[error("agent program path must not be empty")]
        EmptyProgram,
        #[error("cannot {operation} agent run log directory {path}: {source}")]
        LogDir {
            operation: &'static str,
            path: PathBuf,
            source: std::io::Error,
        },
        #[error("cannot create agent run stream file {path}: {source}")]
        StreamFile {
            path: PathBuf,
            source: std::io::Error,
        },
        #[error("agent process could not be spawned: {0}")]
        Spawn(std::io::Error),
        #[error("agent prompt could not be written to stdin: {0}")]
        PromptWrite(std::io::Error),
        #[error("agent process wait failed: {0}")]
        Wait(std::io::Error),
        #[error("agent {stream} stream capture thread failed: {panic}")]
        StreamThread { stream: &'static str, panic: String },
        #[error("cannot start the agent {stream} stream capture thread: {source}")]
        StreamThreadSpawn {
            stream: &'static str,
            source: std::io::Error,
        },
        #[error("cannot capture agent stream {path}: {source}")]
        StreamCapture {
            path: PathBuf,
            source: std::io::Error,
        },
    }

    impl AgentProcessPlan {
        pub fn new(
            run_id: AgentRunId,
            program: impl Into<PathBuf>,
            args: impl IntoIterator<Item = OsString>,
        ) -> Result<Self, AgentProcessRunError> {
            let program = program.into();
            if program.as_os_str().is_empty() {
                return Err(AgentProcessRunError::EmptyProgram);
            }
            Ok(Self {
                run_id,
                program,
                args: args.into_iter().collect(),
                cwd: None,
                env: Vec::new(),
                env_remove: Vec::new(),
                max_stream_capture_bytes: DEFAULT_AGENT_RUN_STREAM_CAPTURE_BYTES,
            })
        }

        pub fn run_id(&self) -> AgentRunId {
            self.run_id
        }

        pub fn program(&self) -> &Path {
            &self.program
        }

        pub fn args(&self) -> &[OsString] {
            &self.args
        }

        pub fn env(&self) -> &[(OsString, OsString)] {
            &self.env
        }

        pub fn env_remove(&self) -> &[OsString] {
            &self.env_remove
        }

        pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
            self.cwd = Some(cwd.into());
            self
        }

        pub fn with_env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
            self.env.push((key.into(), value.into()));
            self
        }

        pub fn with_env_remove(mut self, key: impl Into<OsString>) -> Self {
            self.env_remove.push(key.into());
            self
        }

        pub fn with_max_stream_capture_bytes(mut self, max: u64) -> Self {
            self.max_stream_capture_bytes = max;
            self
        }
    }

    pub fn run_agent_process(
        plan: &AgentProcessPlan,
        prompt: &AgentPrompt,
        log_root: &Path,
    ) -> Result<AgentRunCapture, AgentProcessRunError> {
        // Stream files are durable audit artifacts. The lifecycle owner must
        // define retention and quota policy for this log root.
        ensure_private_dir(log_root)?;
        let run_dir = log_root.join(plan.run_id.to_string());
        create_private_dir(&run_dir)?;
        let stdout_path = run_dir.join("stdout.log");
        let stderr_path = run_dir.join("stderr.log");

        let child = {
            let mut command = Command::new(&plan.program);
            command
                .args(&plan.args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(cwd) = &plan.cwd {
                command.current_dir(cwd);
            }
            for key in &plan.env_remove {
                command.env_remove(key);
            }
            command.envs(plan.env.iter().map(|(key, value)| (key, value)));
            process_spawn::spawn(&mut command).map_err(AgentProcessRunError::Spawn)?
        };

        // From here on every failure must leave no agent behind: see
        // `ChildGuard`.
        let mut child = ChildGuard(Some(child));

        let stdout = child
            .as_mut()
            .stdout
            .take()
            .expect("stdout was configured as piped before spawn");
        let stderr = child
            .as_mut()
            .stderr
            .take()
            .expect("stderr was configured as piped before spawn");
        let max_stdout = plan.max_stream_capture_bytes;
        let max_stderr = plan.max_stream_capture_bytes;
        let stdout_thread =
            spawn_capture_thread("stdout", stdout, stdout_path.clone(), max_stdout)?;
        let stderr_thread =
            spawn_capture_thread("stderr", stderr, stderr_path.clone(), max_stderr)?;

        write_prompt_to_stdin(
            child
                .as_mut()
                .stdin
                .take()
                .expect("stdin was configured as piped before spawn"),
            prompt,
        )?;

        let status = child.wait()?;
        let stdout = join_capture_thread("stdout", stdout_thread)??;
        let stderr = join_capture_thread("stderr", stderr_thread)??;
        let exit_code = exit_code(status);
        Ok(AgentRunCapture {
            run_id: plan.run_id,
            status: if status.success() {
                AgentRunTerminalStatus::Succeeded
            } else {
                AgentRunTerminalStatus::Failed
            },
            exit_code,
            stdout,
            stderr,
        })
    }

    /// Owns the spawned agent from the moment it exists until the run ends,
    /// killing and reaping it on any path that does not wait for it.
    ///
    /// `std::process::Child` does neither of those on drop — by design, but it
    /// means an early return anywhere after the spawn leaves the agent running
    /// with nobody waiting for it. That is worse than a leak here: the run's
    /// audit session is about to close, so the process would outlive the
    /// authority that permitted it, still holding the broker token it was
    /// started with, and still writing to the stream files an outcome row will
    /// never describe.
    ///
    /// A guard rather than a `kill` at each `?`: the invariant is "this
    /// function does not return while the agent runs", and only something that
    /// owns the child can enforce that against paths nobody wrote by hand —
    /// including a panic in between.
    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn as_mut(&mut self) -> &mut Child {
            self.0
                .as_mut()
                .expect("the child is taken only by `wait`, which consumes the guard")
        }

        /// Wait for the agent to exit, disarming the guard.
        ///
        /// Takes `self` because after this the child is reaped: a second wait
        /// would be an error, and the guard has nothing left to protect. If the
        /// wait itself fails the child goes back under the guard's drop, which
        /// kills it — a wait that failed tells us nothing about whether the
        /// agent is still running.
        fn wait(mut self) -> Result<std::process::ExitStatus, AgentProcessRunError> {
            match self.as_mut().wait() {
                Ok(status) => {
                    self.0 = None;
                    Ok(status)
                }
                Err(err) => Err(AgentProcessRunError::Wait(err)),
            }
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let Some(mut child) = self.0.take() else {
                return;
            };
            // Both results are deliberately ignored: this runs on a path that
            // is already failing, and an agent that exited on its own between
            // the failure and here makes `kill` fail with no consequence.
            // Reaping after the kill is what keeps the zombie from outliving
            // the daemon.
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Start one capture thread, failing rather than panicking when the OS
    /// cannot give us a thread.
    ///
    /// `thread::spawn` panics on failure, which under thread exhaustion would
    /// unwind past the running agent. The guard would still reap it — that is
    /// what the guard is for — but a daemon that reports "cannot start a
    /// capture thread" is far easier to act on than one whose handler panicked.
    fn spawn_capture_thread<R: Read + Send + 'static>(
        stream: &'static str,
        reader: R,
        path: PathBuf,
        max_capture_bytes: u64,
    ) -> Result<
        thread::JoinHandle<Result<AgentRunStreamCapture, AgentProcessRunError>>,
        AgentProcessRunError,
    > {
        thread::Builder::new()
            .name(format!("writ-agent-{stream}"))
            .spawn(move || capture_stream(reader, path, max_capture_bytes))
            .map_err(|source| AgentProcessRunError::StreamThreadSpawn { stream, source })
    }

    /// Feed the prompt to the child on stdin, tolerating a broken pipe.
    ///
    /// An agent that exits before consuming its whole prompt — one that fails
    /// fast, or simply does not read stdin — leaves the parent writing into a
    /// pipe whose read end has closed, which is `EPIPE`. That is a fact about
    /// how the agent behaved, not a failure of the run: the child still has an
    /// exit status and streams, and those are exactly what the caller wants to
    /// record.
    ///
    /// Treating it as fatal cost the guest path its outcome entirely.
    /// `writ-vm`'s stage runner propagates this error *before* it uploads an
    /// outcome, so an agent that died in milliseconds left its `agent_run` row
    /// unpaired and made writd wait out the full 30-minute
    /// `RUN_AGENT_VM_TIMEOUT` for a result that was never coming. The host-spawn
    /// path had always tolerated the same broken pipe; now both do.
    ///
    /// Every other write error stays fatal. Those describe a parent that cannot
    /// deliver the prompt, not a child that declined to read it — and a run
    /// whose agent was fed a *truncated* prompt is not the run that was asked
    /// for, so it must not be reported as one.
    ///
    /// Takes `stdin` by value: dropping it closes the pipe, which is what tells
    /// a child that *does* read to stop waiting for more.
    fn write_prompt_to_stdin(
        mut stdin: std::process::ChildStdin,
        prompt: &AgentPrompt,
    ) -> Result<(), AgentProcessRunError> {
        match stdin.write_all(prompt.as_bytes()) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            Err(err) => Err(AgentProcessRunError::PromptWrite(err)),
        }
    }

    /// Drain `reader` to EOF, keeping at most `max_capture_bytes` of it at
    /// `path` and measuring both what was kept and what went past.
    ///
    /// Always drains: bytes past the cap are read and dropped rather than left
    /// in the pipe, so a child that writes more than the cap is never blocked
    /// on a full buffer.
    ///
    /// `pub(super)` so the crate's tests can drive it over an in-memory reader.
    /// Its contract is about bytes, not processes; pinning it through a shell
    /// script would mostly test the script.
    pub(super) fn capture_stream<R: Read>(
        mut reader: R,
        path: PathBuf,
        max_capture_bytes: u64,
    ) -> Result<AgentRunStreamCapture, AgentProcessRunError> {
        let mut file = create_private_file(&path)?;
        let mut total = 0u64;
        let mut captured = 0u64;
        let mut buffer = [0u8; 8192];
        let mut full_hash = super::Sha256Stream::new();
        let mut retained_hash = super::Sha256Stream::new();
        loop {
            let read =
                reader
                    .read(&mut buffer)
                    .map_err(|source| AgentProcessRunError::StreamCapture {
                        path: path.clone(),
                        source,
                    })?;
            if read == 0 {
                break;
            }
            let chunk = &buffer[..read];
            full_hash.update(chunk);
            total = total.saturating_add(read as u64);
            if captured < max_capture_bytes {
                let remaining = (max_capture_bytes - captured) as usize;
                let to_write = remaining.min(read);
                let kept = &chunk[..to_write];
                file.write_all(kept)
                    .map_err(|source| AgentProcessRunError::StreamCapture {
                        path: path.clone(),
                        source,
                    })?;
                retained_hash.update(kept);
                captured += to_write as u64;
            }
        }
        file.sync_all()
            .map_err(|source| AgentProcessRunError::StreamCapture {
                path: path.clone(),
                source,
            })?;
        Ok(AgentRunStreamCapture {
            path,
            retained_byte_len: captured,
            retained_sha256_hex: retained_hash.finish_hex(),
            full_byte_len: total,
            full_sha256_hex: full_hash.finish_hex(),
        })
    }

    fn ensure_private_dir(path: &Path) -> Result<(), AgentProcessRunError> {
        match fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() => set_private_dir_permissions(path),
            Ok(_) => Err(AgentProcessRunError::LogDir {
                operation: "inspect",
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotADirectory,
                    "agent run log root is not a directory",
                ),
            }),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                create_private_dir(path)
            }
            Err(source) => Err(AgentProcessRunError::LogDir {
                operation: "inspect",
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    fn create_private_dir(path: &Path) -> Result<(), AgentProcessRunError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder
                .create(path)
                .map_err(|source| AgentProcessRunError::LogDir {
                    operation: "create",
                    path: path.to_path_buf(),
                    source,
                })?;
            // DirBuilderExt::mode is still subject to umask, so enforce the
            // runtime invariant after creation.
            set_private_dir_permissions(path)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(path).map_err(|source| AgentProcessRunError::LogDir {
                operation: "create",
                path: path.to_path_buf(),
                source,
            })
        }
    }

    fn set_private_dir_permissions(path: &Path) -> Result<(), AgentProcessRunError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
                AgentProcessRunError::LogDir {
                    operation: "set permissions on",
                    path: path.to_path_buf(),
                    source,
                }
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(())
        }
    }

    fn create_private_file(path: &Path) -> Result<File, AgentProcessRunError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(path)
            .map_err(|source| AgentProcessRunError::StreamFile {
                path: path.to_path_buf(),
                source,
            })
    }

    fn exit_code(status: std::process::ExitStatus) -> i32 {
        status.code().unwrap_or(-1)
    }

    fn join_capture_thread(
        stream: &'static str,
        thread: thread::JoinHandle<Result<AgentRunStreamCapture, AgentProcessRunError>>,
    ) -> Result<Result<AgentRunStreamCapture, AgentProcessRunError>, AgentProcessRunError> {
        thread
            .join()
            .map_err(|panic| AgentProcessRunError::StreamThread {
                stream,
                panic: panic_payload_message(panic.as_ref()),
            })
    }

    fn panic_payload_message(panic: &(dyn std::any::Any + Send)) -> String {
        if let Some(message) = panic.downcast_ref::<&str>() {
            return (*message).to_string();
        }
        if let Some(message) = panic.downcast_ref::<String>() {
            return message.clone();
        }
        "<non-string panic payload>".to_string()
    }

    #[cfg(all(test, unix))]
    mod child_guard_tests {
        use super::ChildGuard;
        use std::process::{Command, Stdio};

        /// Whether a pid names a live process. `kill -0` signals nothing; it only
        /// asks whether the process could be signalled, which is exactly the
        /// question. A reaped child answers no.
        fn is_running(pid: u32) -> bool {
            Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("kill(1) is available")
                .success()
        }

        /// Dropping the guard without waiting kills and reaps the agent.
        ///
        /// This is the whole point of the guard: every `?` after the spawn in
        /// `run_agent_process` — a prompt that could not be written, a capture
        /// thread the OS refused — returns through here, and a `std::process::Child`
        /// dropped on its own would leave the agent running with nobody waiting for
        /// it, outliving the audit session that authorised it.
        ///
        /// A 300-second sleep so the assertion cannot pass by the child simply
        /// having finished.
        #[test]
        fn dropping_the_guard_kills_and_reaps_the_agent() {
            let child = Command::new("sleep")
                .arg("300")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("sleep(1) is available");
            let pid = child.id();
            let guard = ChildGuard(Some(child));
            assert!(
                is_running(pid),
                "the agent should be running before the drop"
            );

            drop(guard);

            assert!(
                !is_running(pid),
                "pid {pid} outlived its guard: a failing run must not leave an agent behind",
            );
        }

        /// Waiting through the guard disarms it, so the drop does not then try to
        /// kill and reap a pid the OS is free to have reassigned.
        #[test]
        fn waiting_through_the_guard_disarms_it() {
            let child = Command::new("true")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("true(1) is available");
            let status = ChildGuard(Some(child)).wait().expect("wait must succeed");
            assert!(status.success());
        }
    }
}

#[cfg(any(feature = "host", feature = "vm-client"))]
pub use process_runner::{
    AgentProcessPlan, AgentProcessRunError, AgentRunCapture, AgentRunStreamCapture,
    run_agent_process,
};

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    #[cfg(feature = "host")]
    use std::ffi::OsString;
    #[cfg(feature = "host")]
    use std::fs;
    #[cfg(all(feature = "host", unix))]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(feature = "host")]
    use std::path::Path;

    #[test]
    fn prompt_debug_redacts_prompt() {
        let prompt = AgentPrompt::new("SECRET prompt with 'quotes' and $(commands)");

        let debug = format!("{prompt:?}");

        assert!(!debug.contains(prompt.as_str()), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    #[test]
    fn correlation_id_accepts_safe_alphanumeric_underscore_dash() {
        for ok in [
            "a",
            "ABC",
            "feat-2026-05-11",
            "task_123",
            "Z9_-",
            // exactly max length
            &"a".repeat(MAX_CORRELATION_ID_BYTES),
        ] {
            let parsed = CorrelationId::try_new(ok)
                .unwrap_or_else(|e| panic!("expected {ok:?} to parse, got {e}"));
            assert_eq!(parsed.as_str(), ok);
        }
    }

    #[test]
    fn correlation_id_rejects_empty_too_long_and_bad_chars() {
        // empty
        assert!(matches!(
            CorrelationId::try_new(""),
            Err(CorrelationIdError::InvalidLength { got: 0 })
        ));
        // one over max
        let too_long = "a".repeat(MAX_CORRELATION_ID_BYTES + 1);
        assert!(matches!(
            CorrelationId::try_new(&too_long),
            Err(CorrelationIdError::InvalidLength { .. })
        ));
        // forbidden bytes — path/scheme-style separators
        for bad in [
            "foo.bar", "foo/bar", "foo:bar", "foo bar", "foo\nbar", "foo!",
        ] {
            let err = CorrelationId::try_new(bad).unwrap_err();
            assert!(
                matches!(err, CorrelationIdError::InvalidByte { .. }),
                "expected InvalidByte for {bad:?}, got {err:?}",
            );
        }
    }

    #[test]
    fn correlation_id_serde_is_bare_string_and_roundtrips() {
        let c = CorrelationId::try_new("plan-2026-05-11_42").unwrap();
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#""plan-2026-05-11_42""#);
        let back: CorrelationId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
        // invalid wire payloads are rejected on parse
        assert!(serde_json::from_str::<CorrelationId>(r#""bad/id""#).is_err());
        assert!(serde_json::from_str::<CorrelationId>(r#""""#).is_err());
    }

    #[cfg(feature = "host")]
    #[test]
    fn prompt_summary_records_metadata_without_prompt_text() {
        let prompt = AgentPrompt::new("SECRET prompt\nsecond line");

        let summary = prompt.summary();

        assert_eq!(summary.byte_len, prompt.byte_len());
        assert_eq!(summary.sha256_hex.len(), 64);
        let debug = format!("{summary:?}");
        assert!(!debug.contains(prompt.as_str()), "{debug}");
        assert_eq!(summary.redacted_preview, "<redacted>");
    }

    #[test]
    fn prompt_rejects_oversize_values_at_constructor_and_json_boundary() {
        let oversize = "x".repeat(MAX_AGENT_PROMPT_BYTES + 1);

        let err = AgentPrompt::try_new(oversize.clone()).unwrap_err();

        assert_eq!(err.byte_len, MAX_AGENT_PROMPT_BYTES + 1);
        assert_eq!(err.max_bytes, MAX_AGENT_PROMPT_BYTES);
        let json = serde_json::to_string(&oversize).unwrap();
        let err = serde_json::from_str::<AgentPrompt>(&json).unwrap_err();
        assert!(
            err.to_string().contains("exceeding the 1048576-byte limit"),
            "{err}"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]
        #[test]
        fn prompt_rejects_oversize_values(extra in 1usize..=4096usize) {
            let byte_len = MAX_AGENT_PROMPT_BYTES + extra;
            let oversize = "x".repeat(byte_len);

            let err = AgentPrompt::try_new(oversize).unwrap_err();

            prop_assert_eq!(err.byte_len, byte_len);
            prop_assert_eq!(err.max_bytes, MAX_AGENT_PROMPT_BYTES);
        }
    }

    #[cfg(feature = "host")]
    proptest! {
        #[test]
        fn prompt_debug_and_summary_do_not_contain_secret_suffix(suffix in "[A-Za-z0-9]{1,80}") {
            let secret_suffix = format!("SECRET_SUFFIX_{suffix}");
            let prompt = AgentPrompt::new(format!("SECRET_PROMPT_VALUE::{secret_suffix}"));
            let debug = format!("{prompt:?}");
            let summary = prompt.summary();
            let summary_debug = format!("{summary:?}");

            prop_assert!(!debug.contains(prompt.as_str()), "{debug}");
            prop_assert!(!debug.contains(&secret_suffix), "{debug}");
            prop_assert!(!summary.redacted_preview.contains("SECRET_PROMPT_VALUE"));
            prop_assert!(!summary_debug.contains(&secret_suffix), "{summary_debug}");
            prop_assert!(!summary_debug.contains(prompt.as_str()), "{summary_debug}");
        }
    }

    #[test]
    fn config_route_contains_run_id_not_prompt() {
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000001".parse().unwrap();

        assert_eq!(
            vm_agent_run_config_path(run_id),
            "/v1/agent-runs/00000000-0000-0000-0000-000000000001/config"
        );
    }

    #[test]
    fn vm_agent_run_config_response_round_trips() {
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000203".parse().unwrap();
        let original = VmAgentRunConfigResponse::new(
            run_id,
            AgentPrompt::new("feature prompt"),
            "gpt-5.4-mini",
        );

        let wire = serde_json::to_string(&original).unwrap();
        let roundtripped: VmAgentRunConfigResponse = serde_json::from_str(&wire).unwrap();
        assert_eq!(roundtripped, original);
    }

    /// A wire payload with an unknown extra key must be rejected at
    /// parse time. Pinned because `deny_unknown_fields` is the only
    /// guard now that the hand-rolled visitor (which previously
    /// enforced the field set) is gone.
    #[test]
    fn vm_agent_run_config_response_rejects_unknown_field() {
        let json = r#"{
            "run_id": "00000000-0000-0000-0000-000000000204",
            "prompt": "hello",
            "model": "gpt-5.4-mini",
            "stage": "execute"
        }"#;
        let err = serde_json::from_str::<VmAgentRunConfigResponse>(json).unwrap_err();
        assert!(err.to_string().contains("stage"), "{err}");
    }

    #[cfg(feature = "host")]
    #[test]
    fn fake_agent_success_gets_prompt_on_stdin_and_captures_streams() {
        let dir = tempfile::tempdir().unwrap();
        let stdin_path = dir.path().join("stdin.txt");
        let fake = write_fake_agent(dir.path(), 0, "fake stdout\n", "fake stderr\n");
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000101".parse().unwrap();
        let prompt = AgentPrompt::new("quote: ' \"\ncommand: $(do-not-run)");
        let plan =
            AgentProcessPlan::new(run_id, fake, [stdin_path.as_os_str().to_os_string()]).unwrap();

        let outcome = run_agent_process(&plan, &prompt, &dir.path().join("logs")).unwrap();

        assert_eq!(fs::read_to_string(&stdin_path).unwrap(), prompt.as_str());
        assert_eq!(outcome.status, AgentRunTerminalStatus::Succeeded);
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(
            fs::read_to_string(&outcome.stdout.path).unwrap(),
            "fake stdout\n"
        );
        assert_eq!(
            fs::read_to_string(&outcome.stderr.path).unwrap(),
            "fake stderr\n"
        );
        // Nothing was dropped, so the retained and full pairs coincide.
        assert_eq!(
            outcome.stdout.retained_byte_len,
            "fake stdout\n".len() as u64
        );
        assert_eq!(outcome.stdout.full_byte_len, "fake stdout\n".len() as u64);
        assert_eq!(
            outcome.stderr.retained_byte_len,
            "fake stderr\n".len() as u64
        );
        assert_eq!(outcome.stderr.full_byte_len, "fake stderr\n".len() as u64);
        assert!(!outcome.stdout.truncated());
        assert!(!outcome.stderr.truncated());
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(dir.path().join("logs"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(dir.path().join("logs").join(run_id.to_string()))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(outcome.stdout.path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[cfg(feature = "host")]
    #[test]
    fn fake_agent_failure_is_an_agent_outcome_with_streams() {
        let dir = tempfile::tempdir().unwrap();
        let stdin_path = dir.path().join("stdin.txt");
        let fake = write_fake_agent(
            dir.path(),
            7,
            "stdout before failure\n",
            "stderr before failure\n",
        );
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000102".parse().unwrap();
        let prompt = AgentPrompt::new("fail this run");
        let plan =
            AgentProcessPlan::new(run_id, fake, [stdin_path.as_os_str().to_os_string()]).unwrap();

        let outcome = run_agent_process(&plan, &prompt, &dir.path().join("logs")).unwrap();

        assert_eq!(fs::read_to_string(&stdin_path).unwrap(), prompt.as_str());
        assert_eq!(outcome.status, AgentRunTerminalStatus::Failed);
        assert_eq!(outcome.exit_code, 7);
        assert_eq!(
            fs::read_to_string(&outcome.stdout.path).unwrap(),
            "stdout before failure\n"
        );
        assert_eq!(
            fs::read_to_string(&outcome.stderr.path).unwrap(),
            "stderr before failure\n"
        );
    }

    /// An agent that exits without reading its prompt still produces a run.
    ///
    /// The prompt is larger than any platform's pipe buffer, so the write
    /// cannot complete into the kernel and then find the child gone: it must
    /// still be writing when the read end closes, which is `EPIPE`. That makes
    /// the broken pipe deterministic rather than a race the test might miss.
    ///
    /// What matters is that the child's exit status and streams survive it —
    /// this is a fact about how the agent chose to behave, not a failure of the
    /// run.
    #[cfg(feature = "host")]
    #[test]
    fn an_agent_that_ignores_its_prompt_still_yields_an_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let fake = write_ignore_stdin_fake_agent(dir.path(), 3);
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000105".parse().unwrap();
        // Comfortably past the 16-64 KiB a pipe will hold, and within
        // MAX_AGENT_PROMPT_BYTES.
        let prompt = AgentPrompt::new("p".repeat(256 * 1024));
        let plan = AgentProcessPlan::new(run_id, fake, [] as [OsString; 0]).unwrap();

        let outcome = run_agent_process(&plan, &prompt, &dir.path().join("logs")).unwrap();

        assert_eq!(outcome.status, AgentRunTerminalStatus::Failed);
        assert_eq!(outcome.exit_code, 3);
        assert_eq!(
            fs::read_to_string(&outcome.stdout.path).unwrap(),
            "ignored your prompt\n"
        );
    }

    #[cfg(feature = "host")]
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(12))]

        /// Whether the prompt fits the pipe buffer decides whether the write
        /// finishes before the child is gone — so it decides whether `EPIPE`
        /// happens at all. An agent that ignores stdin must yield the same
        /// outcome either side of that boundary: the run is defined by how the
        /// child terminated, not by how much of the prompt the kernel happened
        /// to accept first.
        ///
        /// Few cases on purpose: each one spawns a real process.
        #[test]
        fn an_ignored_prompt_yields_the_childs_own_outcome_at_any_size(
            // Spans a pipe buffer (16-64 KiB) from well under to well over.
            prompt_bytes in 0usize..=(256 * 1024),
            exit_code in 0i32..=255,
        ) {
            let dir = tempfile::tempdir().unwrap();
            let fake = write_ignore_stdin_fake_agent(dir.path(), exit_code);
            let prompt = AgentPrompt::new("p".repeat(prompt_bytes));
            let plan =
                AgentProcessPlan::new(AgentRunId::new(), fake, [] as [OsString; 0]).unwrap();

            let outcome = run_agent_process(&plan, &prompt, &dir.path().join("logs"))
                .map_err(|err| TestCaseError::fail(format!("{err}")))?;

            prop_assert_eq!(outcome.exit_code, exit_code);
            prop_assert_eq!(
                &outcome.status,
                if exit_code == 0 {
                    &AgentRunTerminalStatus::Succeeded
                } else {
                    &AgentRunTerminalStatus::Failed
                }
            );
            prop_assert_eq!(
                fs::read_to_string(&outcome.stdout.path).unwrap(),
                "ignored your prompt\n"
            );
        }
    }

    #[cfg(feature = "host")]
    proptest! {
        /// The oracle for what a capture's two pairs mean.
        ///
        /// `retained_*` must describe the bytes on disk — checkable by reading
        /// the file back — and `full_*` must describe the whole stream, at
        /// every cap either side of the stream's length. Getting this wrong is
        /// not a cosmetic mislabelling: the audit row keeps only one pair, and
        /// the signed envelope derives its truncation offset from it, so a
        /// summary carrying the full length would mark a cut point past the
        /// bytes it is describing.
        #[test]
        fn a_capture_measures_both_what_it_kept_and_what_it_saw(
            stream in prop::collection::vec(any::<u8>(), 0..4096),
            cap in 0u64..4096,
        ) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("stream.log");

            let capture = process_runner::capture_stream(
                std::io::Cursor::new(stream.clone()),
                path.clone(),
                cap,
            )
                .map_err(|err| TestCaseError::fail(format!("{err}")))?;

            let on_disk = fs::read(&path).unwrap();
            // What is kept is a prefix of what was seen, bounded by the cap.
            prop_assert_eq!(&on_disk[..], &stream[..on_disk.len()]);
            prop_assert!(on_disk.len() as u64 <= cap);
            // The retained pair describes the file, exactly.
            prop_assert_eq!(capture.retained_byte_len, on_disk.len() as u64);
            prop_assert_eq!(&capture.retained_sha256_hex, &sha256_hex(&on_disk));
            // The full pair describes the stream, however much was kept.
            prop_assert_eq!(capture.full_byte_len, stream.len() as u64);
            prop_assert_eq!(&capture.full_sha256_hex, &sha256_hex(&stream));
            // Truncation is derived from the two, never asserted on its own.
            prop_assert_eq!(capture.truncated(), on_disk.len() < stream.len());

            // The projection the audit row stores keeps the pair that describes
            // the file — the one an operator can verify against `path`.
            let summary = capture.to_summary();
            prop_assert_eq!(&summary.path, &path);
            prop_assert_eq!(summary.byte_len, capture.retained_byte_len);
            prop_assert_eq!(&summary.sha256_hex, &capture.retained_sha256_hex);
            prop_assert_eq!(summary.truncated, capture.truncated());
        }
    }

    #[cfg(feature = "host")]
    #[test]
    fn fake_agent_large_streams_are_drained_counted_and_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let fake = write_large_stream_fake_agent(dir.path());
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000103".parse().unwrap();
        let prompt = AgentPrompt::new("large stream run");
        let plan = AgentProcessPlan::new(run_id, fake, [] as [OsString; 0])
            .unwrap()
            .with_max_stream_capture_bytes(128);

        let outcome = run_agent_process(&plan, &prompt, &dir.path().join("logs")).unwrap();

        assert_eq!(outcome.status, AgentRunTerminalStatus::Succeeded);
        // The child emitted 4096 bytes; 128 of them survive on disk. Both
        // numbers are recorded, and the retained one is the one that describes
        // the file — which is what the audit row will keep.
        assert_eq!(outcome.stdout.full_byte_len, 4096);
        assert_eq!(outcome.stderr.full_byte_len, 4096);
        assert_eq!(outcome.stdout.retained_byte_len, 128);
        assert_eq!(outcome.stderr.retained_byte_len, 128);
        assert!(outcome.stdout.truncated());
        assert!(outcome.stderr.truncated());
        assert_eq!(fs::metadata(&outcome.stdout.path).unwrap().len(), 128);
        assert_eq!(fs::metadata(&outcome.stderr.path).unwrap().len(), 128);
        assert_eq!(outcome.stdout.to_summary().byte_len, 128);
        assert_eq!(
            outcome.stdout.to_summary().sha256_hex,
            sha256_hex(&fs::read(&outcome.stdout.path).unwrap())
        );
    }

    #[cfg(feature = "host")]
    #[test]
    fn agent_process_plan_env_overrides_env_remove_for_same_key() {
        // Regression: when a key appears in both `with_env_remove` and `with_env`,
        // the `with_env` value must reach the child. The first writ-vm codex run
        // failed with `Missing environment variable: OPENAI_API_KEY` because the
        // remove was applied after the set, wiping it.
        let dir = tempfile::tempdir().unwrap();
        let fake = write_env_dump_fake_agent(dir.path(), "WRIT_TEST_ENV_KEY");
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000104".parse().unwrap();
        let prompt = AgentPrompt::new("env override probe");
        let plan = AgentProcessPlan::new(run_id, fake, [] as [OsString; 0])
            .unwrap()
            .with_env_remove("WRIT_TEST_ENV_KEY")
            .with_env("WRIT_TEST_ENV_KEY", "set-by-with-env");

        let outcome = run_agent_process(&plan, &prompt, &dir.path().join("logs")).unwrap();

        assert_eq!(outcome.status, AgentRunTerminalStatus::Succeeded);
        assert_eq!(
            fs::read_to_string(&outcome.stdout.path).unwrap(),
            "set-by-with-env\n"
        );
    }

    #[cfg(feature = "host")]
    fn write_env_dump_fake_agent(dir: &Path, env_key: &str) -> std::path::PathBuf {
        let path = dir.join("env-dump-agent.sh");
        let env_key = shell_single_quote(env_key);
        let script = format!(
            "#!/bin/sh\n\
             cat > /dev/null\n\
             printf '%s\\n' \"${{{env_key}-<unset>}}\"\n",
        );
        fs::write(&path, script).unwrap();
        make_executable(&path);
        path
    }

    #[cfg(feature = "host")]
    fn write_fake_agent(
        dir: &Path,
        exit_code: i32,
        stdout: &str,
        stderr: &str,
    ) -> std::path::PathBuf {
        let path = dir.join("fake-agent.sh");
        let stdout = shell_single_quote(stdout);
        let stderr = shell_single_quote(stderr);
        let script = format!(
            "#!/bin/sh\n\
             cat > \"$1\"\n\
             printf '%s' '{stdout}'\n\
             printf '%s' '{stderr}' >&2\n\
             exit {exit_code}\n",
        );
        fs::write(&path, script).unwrap();
        make_executable(&path);
        path
    }

    /// An agent that never reads stdin and exits at once, closing the read end
    /// of the prompt pipe under the writer's feet.
    #[cfg(feature = "host")]
    fn write_ignore_stdin_fake_agent(dir: &Path, exit_code: i32) -> std::path::PathBuf {
        let path = dir.join("ignore-stdin-agent.sh");
        let script = format!(
            "#!/bin/sh\n\
             printf 'ignored your prompt\\n'\n\
             exit {exit_code}\n",
        );
        fs::write(&path, script).unwrap();
        make_executable(&path);
        path
    }

    #[cfg(feature = "host")]
    fn write_large_stream_fake_agent(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("large-stream-agent.sh");
        fs::write(
            &path,
            "#!/bin/sh\n\
             i=0\n\
             while [ \"$i\" -lt 4096 ]; do printf o; i=$((i + 1)); done\n\
             i=0\n\
             while [ \"$i\" -lt 4096 ]; do printf e >&2; i=$((i + 1)); done\n",
        )
        .unwrap();
        make_executable(&path);
        path
    }

    #[cfg(all(feature = "host", unix))]
    fn make_executable(path: &Path) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(all(feature = "host", not(unix)))]
    fn make_executable(_path: &Path) {}

    #[cfg(feature = "host")]
    fn shell_single_quote(value: &str) -> String {
        value.replace('\'', "'\\''")
    }
}
