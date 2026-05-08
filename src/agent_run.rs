//! Prompt and output contract for managed agent runs.
//!
//! The prompt is data, not process structure: it may cross an authenticated
//! broker channel, but it should not be embedded in argv, shell snippets,
//! environment variables, lifecycle state, or audit rows. Agent stdout/stderr
//! are captured as private files with bounded retained bytes and metadata that
//! can be audited without storing the stream bodies in SQLite.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

pub const VM_AGENT_RUN_PATH_PREFIX: &str = "/v1/agent-runs";
pub const MAX_AGENT_PROMPT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_AGENT_RUN_STREAM_CAPTURE_BYTES: u64 = 1024 * 1024;
pub const VM_AGENT_RUN_OUTCOME_PATH_SUFFIX: &str = "outcome";

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmAgentRunPromptResponse {
    run_id: AgentRunId,
    prompt: AgentPrompt,
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

    #[cfg(test)]
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

impl VmAgentRunPromptResponse {
    pub fn new(run_id: AgentRunId, prompt: AgentPrompt) -> Self {
        Self { run_id, prompt }
    }

    pub fn run_id(&self) -> AgentRunId {
        self.run_id
    }

    pub fn prompt(&self) -> &AgentPrompt {
        &self.prompt
    }

    pub fn into_prompt(self) -> AgentPrompt {
        self.prompt
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

pub fn vm_agent_run_prompt_path(run_id: AgentRunId) -> String {
    format!("{VM_AGENT_RUN_PATH_PREFIX}/{run_id}/prompt")
}

pub fn vm_agent_run_outcome_path(run_id: AgentRunId) -> String {
    format!("{VM_AGENT_RUN_PATH_PREFIX}/{run_id}/{VM_AGENT_RUN_OUTCOME_PATH_SUFFIX}")
}

#[cfg(any(feature = "host", feature = "vm-client"))]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    hex_lower(digest.as_ref())
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

#[cfg(any(feature = "host", feature = "vm-client"))]
mod process_runner {
    use std::ffi::OsString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::thread;

    use super::{
        AgentPrompt, AgentRunId, AgentRunOutcome, AgentRunStreamSummary, AgentRunTerminalStatus,
        DEFAULT_AGENT_RUN_STREAM_CAPTURE_BYTES,
    };

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
    ) -> Result<AgentRunOutcome, AgentProcessRunError> {
        // Stream files are durable audit artifacts. The lifecycle owner must
        // define retention and quota policy for this log root.
        ensure_private_dir(log_root)?;
        let run_dir = log_root.join(plan.run_id.to_string());
        create_private_dir(&run_dir)?;
        let stdout_path = run_dir.join("stdout.log");
        let stderr_path = run_dir.join("stderr.log");

        let mut child = {
            let mut command = Command::new(&plan.program);
            command
                .args(&plan.args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(cwd) = &plan.cwd {
                command.current_dir(cwd);
            }
            command.envs(plan.env.iter().map(|(key, value)| (key, value)));
            for key in &plan.env_remove {
                command.env_remove(key);
            }
            command.spawn().map_err(AgentProcessRunError::Spawn)?
        };

        let stdout = child
            .stdout
            .take()
            .expect("stdout was configured as piped before spawn");
        let stderr = child
            .stderr
            .take()
            .expect("stderr was configured as piped before spawn");
        let max_stdout = plan.max_stream_capture_bytes;
        let max_stderr = plan.max_stream_capture_bytes;
        let stdout_thread = thread::spawn({
            let stdout_path = stdout_path.clone();
            move || capture_stream(stdout, stdout_path, max_stdout)
        });
        let stderr_thread = thread::spawn({
            let stderr_path = stderr_path.clone();
            move || capture_stream(stderr, stderr_path, max_stderr)
        });

        child
            .stdin
            .take()
            .expect("stdin was configured as piped before spawn")
            .write_all(prompt.as_bytes())
            .map_err(AgentProcessRunError::PromptWrite)?;

        let status = child.wait().map_err(AgentProcessRunError::Wait)?;
        let stdout = join_capture_thread("stdout", stdout_thread)??;
        let stderr = join_capture_thread("stderr", stderr_thread)??;
        let exit_code = exit_code(status);
        Ok(AgentRunOutcome {
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

    fn capture_stream<R: Read>(
        mut reader: R,
        path: PathBuf,
        max_capture_bytes: u64,
    ) -> Result<AgentRunStreamSummary, AgentProcessRunError> {
        let mut file = create_private_file(&path)?;
        let mut total = 0u64;
        let mut captured = 0u64;
        let mut buffer = [0u8; 8192];
        let mut hash_context = ring::digest::Context::new(&ring::digest::SHA256);
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
            hash_context.update(chunk);
            total = total.saturating_add(read as u64);
            if captured < max_capture_bytes {
                let remaining = (max_capture_bytes - captured) as usize;
                let to_write = remaining.min(read);
                file.write_all(&chunk[..to_write]).map_err(|source| {
                    AgentProcessRunError::StreamCapture {
                        path: path.clone(),
                        source,
                    }
                })?;
                captured += to_write as u64;
            }
        }
        file.sync_all()
            .map_err(|source| AgentProcessRunError::StreamCapture {
                path: path.clone(),
                source,
            })?;
        Ok(AgentRunStreamSummary {
            path,
            byte_len: total,
            sha256_hex: super::hex_lower(hash_context.finish().as_ref()),
            truncated: total > max_capture_bytes,
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
        thread: thread::JoinHandle<Result<AgentRunStreamSummary, AgentProcessRunError>>,
    ) -> Result<Result<AgentRunStreamSummary, AgentProcessRunError>, AgentProcessRunError> {
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
}

#[cfg(any(feature = "host", feature = "vm-client"))]
pub use process_runner::{AgentProcessPlan, AgentProcessRunError, run_agent_process};

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
    fn prompt_route_contains_run_id_not_prompt() {
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000001".parse().unwrap();

        assert_eq!(
            vm_agent_run_prompt_path(run_id),
            "/v1/agent-runs/00000000-0000-0000-0000-000000000001/prompt"
        );
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
        assert_eq!(outcome.stdout.byte_len, "fake stdout\n".len() as u64);
        assert_eq!(outcome.stderr.byte_len, "fake stderr\n".len() as u64);
        assert!(!outcome.stdout.truncated);
        assert!(!outcome.stderr.truncated);
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
        assert_eq!(outcome.stdout.byte_len, 4096);
        assert_eq!(outcome.stderr.byte_len, 4096);
        assert!(outcome.stdout.truncated);
        assert!(outcome.stderr.truncated);
        assert_eq!(fs::metadata(&outcome.stdout.path).unwrap().len(), 128);
        assert_eq!(fs::metadata(&outcome.stderr.path).unwrap().len(), 128);
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
