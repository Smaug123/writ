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

/// Inclusive bounds on a [`RunPurpose`]. The lower bound rejects the
/// empty string for the same reason as [`MIN_CORRELATION_ID_BYTES`]:
/// the audit column is nullable, and `NULL` must mean exactly one
/// thing. The upper bound keeps a purpose to one terminal line and
/// bounds what a caller can deposit in an append-only log.
pub const MIN_RUN_PURPOSE_BYTES: usize = 1;
pub const MAX_RUN_PURPOSE_BYTES: usize = 128;

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

/// How an agent run ended, from the point of view of whoever was waiting for
/// it.
///
/// `Failed` and `TimedOut` are kept apart because they attribute the ending to
/// different parties. `Failed` is the agent's own verdict — it ran to
/// completion and exited non-zero. `TimedOut` is *writ's* verdict: the agent was
/// still running when its deadline passed and writ killed it, so the agent never
/// reported anything at all. An operator reading the audit log needs to tell
/// "the agent decided this run failed" from "writ decided this run had gone on
/// long enough", and folding the second into the first would make that
/// impossible after the fact.
///
/// A `TimedOut` run still carries an `exit_code`, and it is `-1` — writ kills
/// with a signal, and `-1` is already this crate's encoding for "died by signal,
/// no exit code" (see `exit_code`). That is correct rather than a placeholder,
/// but it is not what distinguishes a timeout: the status is.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunTerminalStatus {
    Succeeded,
    Failed,
    TimedOut,
}

impl AgentRunTerminalStatus {
    /// Every variant, so that tests which must range over all of them extend
    /// themselves when a variant is added rather than silently continuing to
    /// cover the old set.
    pub const ALL: [Self; 3] = [Self::Succeeded, Self::Failed, Self::TimedOut];
}

/// The statuses a *guest* is allowed to assert about its own run.
///
/// Deliberately narrower than [`AgentRunTerminalStatus`]: the guest is
/// untrusted, and `TimedOut` means "writ stopped this run", which is a claim
/// only writ is in a position to make. If the guest could report it, one audit
/// value would carry two meanings — "the host enforced a deadline" on one arm
/// and "the guest said so" on the other — and neither could be relied on.
///
/// This is the parse step, not a validation step: the guest's wire type is
/// *this* enum, so `"timed_out"` from a guest fails to deserialise and never
/// reaches code that could act on it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestReportedRunStatus {
    Succeeded,
    Failed,
}

impl From<GuestReportedRunStatus> for AgentRunTerminalStatus {
    fn from(status: GuestReportedRunStatus) -> Self {
        match status {
            GuestReportedRunStatus::Succeeded => Self::Succeeded,
            GuestReportedRunStatus::Failed => Self::Failed,
        }
    }
}

/// Refusal from [`GuestReportedRunStatus::try_from`]: a status the guest may
/// not speak.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("a guest may not report an agent run as timed out; only writ enforces run deadlines")]
pub struct GuestCannotReportStatus;

impl TryFrom<AgentRunTerminalStatus> for GuestReportedRunStatus {
    type Error = GuestCannotReportStatus;
    fn try_from(status: AgentRunTerminalStatus) -> Result<Self, Self::Error> {
        match status {
            AgentRunTerminalStatus::Succeeded => Ok(Self::Succeeded),
            AgentRunTerminalStatus::Failed => Ok(Self::Failed),
            AgentRunTerminalStatus::TimedOut => Err(GuestCannotReportStatus),
        }
    }
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
    /// Narrower than the audit-side status on purpose — see
    /// [`GuestReportedRunStatus`].
    pub status: GuestReportedRunStatus,
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

// --- RunPurpose -------------------------------------------------------

/// Caller-supplied opaque tag saying what a run was *for*, recorded
/// verbatim on the `agent_run` audit row. Writ never interprets the
/// contents: the upstream orchestrator decides what a purpose means
/// and matches on it by equality (bailiff writes `"plan-submit"`,
/// `"review:plan-abc"`, and whatever an operator passes to
/// `--purpose`).
///
/// Invariants:
/// - [`MIN_RUN_PURPOSE_BYTES`]..=[`MAX_RUN_PURPOSE_BYTES`] bytes
/// - every byte is printable ASCII, `0x20..=0x7e`
/// - no leading or trailing space
///
/// The value is stored verbatim and never normalised — [`as_str`] returns
/// the caller's bytes unchanged, because an audit row that silently
/// differs from what the caller sent is not a record of what happened.
///
/// [`as_str`]: Self::as_str
///
/// # Why printable ASCII, when a purpose is prose
///
/// A purpose is a join key an orchestrator reconciles on, and it lands
/// in an append-only log that can never be corrected. The hazard is
/// therefore two purposes that are unequal as keys but identical on
/// screen. Printable ASCII excludes, *by construction* rather than by
/// blocklist, every invisible and control character that could produce
/// one: NUL, CR/LF, ESC, the C1 range, zero-width spaces, and bidi
/// overrides. An allow-Unicode class cannot get there — it would need a
/// blocklist of format characters, which is wrong by default the moment
/// Unicode gains a member, and it would still admit the confusables
/// (Cyrillic `а` is an ordinary lowercase letter) that motivate it.
///
/// The cost is that a purpose must be written in Latin script. That is a
/// loud parse-time rejection rather than a silent corruption, and the
/// class is trivially widened later — every value valid today stays
/// valid — whereas a log full of Unicode purposes could not be narrowed.
///
/// What this does *not* promise: that two purposes cannot render
/// *similarly*. `l`/`1`/`I`, `O`/`0`, and runs of interior spaces all
/// survive, deliberately — a quoted render distinguishes them, and they
/// are a lesser hazard than a character with no glyph at all.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RunPurpose(String);

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RunPurposeError {
    #[error("purpose must not be empty")]
    Empty,
    #[error(
        "purpose must be at most {max} bytes; got {got}",
        max = MAX_RUN_PURPOSE_BYTES,
    )]
    TooLong { got: usize },
    #[error("purpose byte at offset {at} is {byte:#04x}; expected printable ASCII (0x20..=0x7e)")]
    ForbiddenByte { at: usize, byte: u8 },
    #[error("purpose must not start or end with a space")]
    SurroundingSpace,
}

impl RunPurpose {
    pub fn try_new(raw: impl Into<String>) -> Result<Self, RunPurposeError> {
        let raw = raw.into();
        let len = raw.len();
        if len < MIN_RUN_PURPOSE_BYTES {
            return Err(RunPurposeError::Empty);
        }
        if len > MAX_RUN_PURPOSE_BYTES {
            return Err(RunPurposeError::TooLong { got: len });
        }
        for (at, byte) in raw.bytes().enumerate() {
            if !(0x20..=0x7e).contains(&byte) {
                return Err(RunPurposeError::ForbiddenByte { at, byte });
            }
        }
        // Checked after the byte scan, so the class violation is reported
        // in preference to the shape one: a purpose containing a newline
        // should be told about the newline. Space is the only whitespace
        // the class admits, which is what makes this test exhaustive.
        if raw.starts_with(' ') || raw.ends_with(' ') {
            return Err(RunPurposeError::SurroundingSpace);
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RunPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for RunPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RunPurpose({:?})", self.0)
    }
}

impl FromStr for RunPurpose {
    type Err = RunPurposeError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::try_new(raw)
    }
}

impl Serialize for RunPurpose {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RunPurpose {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

/// How long writ will let one agent run before killing it.
///
/// A newtype rather than a bare `Duration` because the absent case has to stay
/// distinguishable: `Option<AgentRunTimeout>` reads as "bounded or not", where
/// an `Option<Duration>` invites `Duration::ZERO` to mean either "no timeout" or
/// "kill immediately". Zero is refused here so it can mean neither.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AgentRunTimeout(std::time::Duration);

/// Upper bound on a configured timeout.
///
/// Not a policy about how long runs may be — a year is already far past any
/// real one — but a guard on arithmetic. The runner turns a timeout into a
/// deadline with `Instant::now() + timeout`, which **panics** on overflow, so
/// without a ceiling a config of `u64::MAX` would be accepted at boot and then
/// panic every host run, inside `spawn_blocking`, where it reads as a run
/// abandoned after starting rather than as the configuration error it is.
pub const MAX_AGENT_RUN_TIMEOUT_SECS: u64 = 365 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AgentRunTimeoutError {
    #[error("an agent run timeout must be greater than zero; omit the key entirely for no timeout")]
    Zero,
    #[error(
        "an agent run timeout of {secs}s exceeds the maximum of {MAX_AGENT_RUN_TIMEOUT_SECS}s; \
         omit the key entirely for no timeout"
    )]
    TooLong { secs: u64 },
}

impl AgentRunTimeout {
    pub const fn try_new(timeout: std::time::Duration) -> Result<Self, AgentRunTimeoutError> {
        if timeout.is_zero() {
            return Err(AgentRunTimeoutError::Zero);
        }
        if timeout.as_secs() > MAX_AGENT_RUN_TIMEOUT_SECS {
            return Err(AgentRunTimeoutError::TooLong {
                secs: timeout.as_secs(),
            });
        }
        Ok(Self(timeout))
    }

    pub const fn from_secs(secs: u64) -> Result<Self, AgentRunTimeoutError> {
        Self::try_new(std::time::Duration::from_secs(secs))
    }

    pub const fn get(self) -> std::time::Duration {
        self.0
    }
}

/// Parsed at deserialisation, not checked later.
///
/// This is what keeps a bad value from costing anything: writd's boot both
/// creates things (a notes repo, a signing key) and *migrates the audit DB*
/// before it would otherwise reach a check of this field, so a config refused
/// at that point has already made changes that a rollback to the previous
/// binary cannot undo — the older binary refuses a schema it does not
/// recognise. Refusing here means the daemon never starts booting at all.
impl<'de> Deserialize<'de> for AgentRunTimeout {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let secs = u64::deserialize(d)?;
        Self::from_secs(secs).map_err(serde::de::Error::custom)
    }
}

// Deliberately **not** `Serialize`. The config key is whole seconds, but the
// type admits any positive `Duration` — the tests use milliseconds — so a
// seconds-shaped serialiser is lossy in a way that bites: 500ms would write as
// `0`, which this type's own `Deserialize` then refuses. There is no caller that
// needs to write one of these (the config is read-only), so the fix is to not
// have a second representation at all rather than to pick which way it lies.

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
        AgentRunTimeout, DEFAULT_AGENT_RUN_STREAM_CAPTURE_BYTES,
    };

    /// How often a deadline-bounded run checks whether its agent has exited.
    ///
    /// Polling rather than a blocking wait with a timeout, because there is no
    /// portable one: the alternatives are all platform-specific (`pidfd` on
    /// Linux, `kqueue` on BSD) or need the child moved onto a thread that then
    /// cannot be interrupted. Agent runs are minutes-to-hours long and the
    /// deadlines that bound them are the same order, so a granularity of a
    /// quarter-second is far below anything an operator configures, and the
    /// cost is four `waitpid(WNOHANG)` calls a second on one blocked thread.
    const EXIT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

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
        timeout: Option<AgentRunTimeout>,
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
        // "stream thread" rather than "stream capture thread": the same two
        // variants now cover the prompt writer on `stdin`, which is not a
        // capture, and an operator reading "stdin stream capture thread failed"
        // would go looking for the wrong thing.
        #[error("agent {stream} stream thread failed: {panic}")]
        StreamThread { stream: &'static str, panic: String },
        #[error("cannot start the agent {stream} stream thread: {source}")]
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
                timeout: None,
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

        /// Bound this run: if the agent is still alive after `timeout`, writ
        /// kills it and the run ends [`AgentRunTerminalStatus::TimedOut`].
        ///
        /// Absent by default, and the default path is genuinely unbounded — a
        /// plan with no timeout blocks in `wait(2)` exactly as it always has,
        /// rather than polling to a deadline of infinity.
        pub fn with_timeout(mut self, timeout: AgentRunTimeout) -> Self {
            self.timeout = Some(timeout);
            self
        }

        pub fn timeout(&self) -> Option<AgentRunTimeout> {
            self.timeout
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
            put_in_own_process_group(&mut command);
            process_spawn::spawn(&mut command).map_err(AgentProcessRunError::Spawn)?
        };
        // Taken here, not further down, because *here* is when the agent starts
        // consuming the operator's budget. Every line below this — three thread
        // spawns, two file creations — can be delayed arbitrarily by scheduler
        // contention while the child is already running, and a deadline
        // measured from after them would give a one-second timeout more than a
        // second of agent. Taken after the spawn rather than before it so that
        // `process_spawn`'s retries on a refused spawn do not eat the budget
        // either.
        let started = std::time::Instant::now();

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

        let stdin = child
            .as_mut()
            .stdin
            .take()
            .expect("stdin was configured as piped before spawn");

        // The prompt goes to its own thread so that waiting for the agent is
        // the only thing this thread blocks on. That is what makes
        // `plan.timeout` a real bound: written inline, a 1 MiB prompt to an
        // agent that neither reads stdin nor exits blocks in `write(2)` against
        // a 64 KiB pipe buffer, and the deadline below is never reached at all.
        //
        // It costs an ordering change on the unbounded path: a fatal
        // prompt-write error is now reported after the agent exits rather than
        // instead of waiting for it. In practice the only write error a live
        // child can produce is `EPIPE`, which means it exited — so the wait
        // that now comes first returns immediately.
        let prompt_thread = spawn_prompt_thread(stdin, prompt.clone())?;

        // One deadline for the whole call, measured from when the agent started
        // rather than from here. "The run may take at most this long" is a
        // promise about the call, not about one of the things the call waits on
        // — and this call waits on two: the agent, and then the threads
        // draining its streams.
        //
        // `checked_add` cannot fail for an `AgentRunTimeout`, which is capped at
        // `MAX_AGENT_RUN_TIMEOUT_SECS` precisely so this arithmetic is total; a
        // `None` here would mean that cap had been raised past what an `Instant`
        // can hold, and treating it as "no deadline" is the safe reading.
        let deadline = plan
            .timeout
            .and_then(|timeout| started.checked_add(timeout.get()));
        let ended = child.wait_to_deadline(deadline)?;

        // The agent is gone, so the run is over — and a run that is over tears
        // down what it started. Sweep the group unconditionally, whether the
        // agent exited by itself or writ ended it, and whether or not this run
        // was ever given a deadline.
        //
        // Two things follow from doing it here rather than on the timeout path
        // alone. Containment stops being a property only bounded runs have: an
        // operator who configures no timeout still gets a run that leaves
        // nothing behind. And the run stops being able to hang on its own
        // leftovers — anything the agent forked inherited the stream pipes, so
        // the capture threads below see no EOF while a descendant holds one,
        // which held a finished run open for a descendant's entire lifetime.
        child.kill_group();

        // The sweep above is the last thing that needs the group addressable, so
        // the leader is released here — `child` had been holding it unreaped
        // precisely to keep the pgid ours. See `writ_core::process_group`.
        //
        // **Anything added between the sweep and this line must not need the
        // group**, and anything that does need it belongs above the reap. That
        // is the whole constraint: releasing the pid releases the pgid, because
        // they are the same number.
        //
        // Reaping before the drains rather than after them matters when a drain
        // does not finish — a descendant outside the group can hold a stream
        // open indefinitely — because the leader would otherwise sit as a zombie
        // for exactly as long as the stall. Nothing here fixes the stall itself;
        // it just does not add a second leak to it.
        let ended = child.reap(ended)?;

        join_prompt_thread(prompt_thread)??;
        let stdout = join_capture_thread("stdout", stdout_thread)??;
        let stderr = join_capture_thread("stderr", stderr_thread)??;
        let (status, exit_code) = match ended {
            AgentRunEnd::Exited(status) => (
                if status.success() {
                    AgentRunTerminalStatus::Succeeded
                } else {
                    AgentRunTerminalStatus::Failed
                },
                exit_code(status),
            ),
            AgentRunEnd::KilledAtDeadline => {
                (AgentRunTerminalStatus::TimedOut, SIGNAL_DEATH_EXIT_CODE)
            }
        };
        Ok(AgentRunCapture {
            run_id: plan.run_id,
            status,
            exit_code,
            stdout,
            stderr,
        })
    }

    /// How an agent process ended, as observed by the thread waiting for it.
    ///
    /// Separate from [`AgentRunTerminalStatus`] because it answers a narrower
    /// question — what the OS told us — and because `KilledAtDeadline` carries
    /// no exit status deliberately: a child writ killed has none worth
    /// recording, and inventing one from the reaped signal would put a number
    /// in the audit row that describes writ's action rather than the agent's.
    enum AgentRunEnd {
        Exited(std::process::ExitStatus),
        KilledAtDeadline,
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
    /// function does not return while the process it spawned runs", and only
    /// something that owns the child can enforce that against paths nobody
    /// wrote by hand — including a panic in between.
    ///
    /// **Its reach on the failure path is that one process.** `kill(2)` signals
    /// a pid, so an agent that had already forked — or a `spawn_command` that is
    /// a wrapper script around the real binary — leaves descendants the `Drop`
    /// below does not touch. The ordinary paths do not have that gap: they call
    /// [`Self::kill_group`], which signals the whole group. The `Drop` keeps the
    /// narrower reach deliberately, because it runs while something is already
    /// failing and a group sweep there would sleep — see
    /// `writ_core::process_group::sweep_process_group` — on a path whose job is
    /// to give the pid back and get out.
    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn as_mut(&mut self) -> &mut Child {
            self.0
                .as_mut()
                .expect("the child is taken only by `wait`, which consumes the guard")
        }

        /// Wait for the agent, killing its process group if it is still alive
        /// when `deadline` passes.
        ///
        /// Either way the agent ends up **observed** rather than reaped. Every
        /// run now sweeps its group once the agent is gone, and a group kill is
        /// only safe while the leader's pid is still claimed — see
        /// `writ_core::process_group`. [`Self::reap`] is what finally releases
        /// it, after the last thing that needed the group to be addressable.
        ///
        /// With no deadline this is still one blocking call — no polling, no
        /// timer. "Unbounded" is the absence of a deadline rather than a
        /// deadline set to infinity. What changed is only *which* blocking call:
        /// `waitid(WEXITED | WNOWAIT)` rather than `wait(2)`, because the latter
        /// reaps and a reaped pid can be recycled onto a group writ does not
        /// own.
        fn wait_to_deadline(
            &mut self,
            deadline: Option<std::time::Instant>,
        ) -> Result<AgentExit, AgentProcessRunError> {
            let Some(deadline) = deadline else {
                return self.wait_without_reaping();
            };
            loop {
                if self.has_exited()? {
                    return Ok(AgentExit::Observed {
                        killed_by_writ: false,
                    });
                }
                let now = std::time::Instant::now();
                let Some(remaining) = deadline.checked_duration_since(now) else {
                    self.kill_group();
                    return Ok(AgentExit::Observed {
                        killed_by_writ: true,
                    });
                };
                thread::sleep(sleep_before_next_poll(remaining, EXIT_POLL_INTERVAL));
            }
        }

        /// Block until the agent exits, leaving it unreaped.
        ///
        /// **Disarms the guard on `ECHILD`**, for the reason [`Self::has_exited`]
        /// gives: that error is the one that means the pid is *gone*, so a
        /// `Drop` that went on to kill it would be signalling a stranger.
        #[cfg(unix)]
        fn wait_without_reaping(&mut self) -> Result<AgentExit, AgentProcessRunError> {
            let pid = agent_pid(self.as_mut())?;
            match writ_core::process_group::wait_for_pid_without_reaping(pid) {
                Ok(()) => Ok(AgentExit::Observed {
                    killed_by_writ: false,
                }),
                Err(source) => {
                    let err = AgentProcessRunError::Wait(source);
                    if is_no_such_child(&err) {
                        self.0 = None;
                    }
                    Err(err)
                }
            }
        }

        /// Off Unix there is no way to wait without consuming the status — and
        /// no process group to keep addressable either, since the sweep there
        /// reaches the one process through the `Child` itself. Reaping here is
        /// both unavoidable and harmless.
        #[cfg(not(unix))]
        fn wait_without_reaping(&mut self) -> Result<AgentExit, AgentProcessRunError> {
            let mut child = self
                .0
                .take()
                .expect("the guard is disarmed only by a wait or a reap");
            child
                .wait()
                .map(AgentExit::Reaped)
                .map_err(AgentProcessRunError::Wait)
        }

        /// Reap the agent and say how the run ended.
        ///
        /// Three outcomes, and which one it is turns on who ended the process:
        ///
        /// * an exit **code** means the agent decided — even if it did so a
        ///   moment after its deadline, in the window between the last poll and
        ///   the kill. Recording that as `TimedOut` would be a claim about who
        ///   ended the run, and it would be wrong.
        /// * death by `SIGKILL` **when writ sent one** is the timeout.
        /// * death by any other signal is somebody else's doing — an
        ///   operator's `SIGTERM`, an OOM killer — and is recorded as the
        ///   failure it is rather than attributed to a deadline writ enforced.
        fn reap(mut self, exit: AgentExit) -> Result<AgentRunEnd, AgentProcessRunError> {
            let (status, killed_by_writ) = match exit {
                #[cfg(not(unix))]
                AgentExit::Reaped(status) => (status, false),
                AgentExit::Observed { killed_by_writ } => {
                    let mut child = self
                        .0
                        .take()
                        .expect("the guard is disarmed only by a wait or a reap");
                    let status = child.wait().map_err(AgentProcessRunError::Wait)?;
                    (status, killed_by_writ)
                }
            };
            if status.code().is_some() || !killed_by_writ || !died_by_sigkill(status) {
                return Ok(AgentRunEnd::Exited(status));
            }
            Ok(AgentRunEnd::KilledAtDeadline)
        }

        /// Has the agent exited, without consuming its status?
        ///
        /// **Disarms the guard on `ECHILD`**, which is the one failure that
        /// means the pid is *gone*: somebody else reaped it — `SIGCHLD`
        /// ignored, `SA_NOCLDWAIT`, an outer reaper — so the number is free for
        /// the OS to hand to an unrelated process. Propagating the error with
        /// the guard still armed would send its `Drop` to kill that stranger.
        /// This is the same reasoning the unbounded path encodes by taking the
        /// child before it waits; the polling path has to state it explicitly
        /// because it keeps the child across many probes.
        fn has_exited(&mut self) -> Result<bool, AgentProcessRunError> {
            match self.probe_exited() {
                Err(err) if is_no_such_child(&err) => {
                    self.0 = None;
                    Err(err)
                }
                other => other,
            }
        }

        fn probe_exited(&mut self) -> Result<bool, AgentProcessRunError> {
            let child = self
                .0
                .as_mut()
                .expect("the guard is disarmed only by a wait or a reap");
            has_exited_without_reaping(child)
        }

        /// SIGKILL the agent's whole process group, falling back to the one
        /// process where there are no groups.
        ///
        /// Failures are deliberately not surfaced. An agent that exited between
        /// the last poll and here empties the group, which is an ordinary
        /// ending rather than something the caller can act on, and every other
        /// case belongs to a pid this guard still owns unreaped.
        fn kill_group(&mut self) {
            let Some(child) = self.0.as_mut() else {
                return;
            };
            if !kill_agent_process_group(child.id()) {
                let _ = child.kill();
            }
        }
    }

    /// How the agent's lifetime ended, before its status has been collected.
    ///
    /// On Unix there is only `Observed`: every run sweeps its process group once
    /// the agent is gone, and that is safe only while the leader is still
    /// unreaped, so no path here may reap early. `killed_by_writ` is what later
    /// separates a deadline from an agent's own ending.
    #[derive(Debug)]
    enum AgentExit {
        /// Reaped by the wait itself, because the platform offers no way to
        /// observe an exit without consuming it. Off Unix that costs nothing:
        /// there are no process groups to keep addressable.
        #[cfg(not(unix))]
        Reaped(std::process::ExitStatus),
        Observed {
            killed_by_writ: bool,
        },
    }

    /// Is this the error that means the pid no longer exists to be waited on?
    #[cfg(unix)]
    fn is_no_such_child(err: &AgentProcessRunError) -> bool {
        let AgentProcessRunError::Wait(err) = err else {
            return false;
        };
        err.raw_os_error() == Some(libc::ECHILD)
    }

    #[cfg(not(unix))]
    fn is_no_such_child(_err: &AgentProcessRunError) -> bool {
        false
    }

    /// Did this status describe a process killed by `SIGKILL`?
    ///
    /// `false` off Unix, where there are no signals to distinguish and a
    /// code-less status is as much as the platform says.
    #[cfg(unix)]
    fn died_by_sigkill(status: std::process::ExitStatus) -> bool {
        use std::os::unix::process::ExitStatusExt;
        status.signal() == Some(libc::SIGKILL)
    }

    #[cfg(not(unix))]
    fn died_by_sigkill(_status: std::process::ExitStatus) -> bool {
        true
    }

    /// Observe a child's exit without consuming its status, so the pid — and
    /// with it the process group id — stays claimed.
    #[cfg(unix)]
    fn has_exited_without_reaping(child: &mut Child) -> Result<bool, AgentProcessRunError> {
        let pid = agent_pid(child)?;
        writ_core::process_group::pid_has_exited_without_reaping(pid)
            .map_err(AgentProcessRunError::Wait)
    }

    /// The agent's pid in the signed form the wait and signal calls take.
    ///
    /// Fails rather than casting. A pid too large for `pid_t` would wrap to a
    /// negative number, and a negative pid is a different request entirely —
    /// `kill(2)` reads it as a process group. Unreachable for a child of this
    /// process on any real platform, which is why it is an error rather than a
    /// case with behaviour.
    #[cfg(unix)]
    fn agent_pid(child: &Child) -> Result<libc::pid_t, AgentProcessRunError> {
        writ_core::process_group::process_group_id(child.id()).ok_or_else(|| {
            AgentProcessRunError::Wait(std::io::Error::other(format!(
                "agent process id {} cannot be represented as a pid",
                child.id()
            )))
        })
    }

    /// Off Unix there is no way to observe an exit without consuming it, and no
    /// process group to protect by trying; `try_wait` is the whole of what the
    /// platform offers.
    #[cfg(not(unix))]
    fn has_exited_without_reaping(child: &mut Child) -> Result<bool, AgentProcessRunError> {
        child
            .try_wait()
            .map(|status| status.is_some())
            .map_err(AgentProcessRunError::Wait)
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

    /// How long to sleep before checking again, given how much of the deadline
    /// is left.
    ///
    /// **Never sleeps past the deadline**, which is the whole content of this
    /// function. Sleeping a full interval when less than an interval remains
    /// would let an agent that exited *after* its deadline — but before the
    /// next poll — be found already-exited and recorded as having succeeded:
    /// an agent that blew its deadline reported as one that met it. That is a
    /// wrong answer, not a late one.
    ///
    /// Pulled out as a pure function so that invariant can be property-tested
    /// exhaustively. Left inline it is only observable through a race — the
    /// difference shows up solely when an agent exits inside the overshoot
    /// window — and a test of that would be a sub-interval timing assertion,
    /// exactly the kind this repo's flake notes warn against. The scheduler
    /// still decides when the sleep actually returns; what is proved here is
    /// that writ never *asks* to sleep past the deadline.
    const fn sleep_before_next_poll(
        remaining: std::time::Duration,
        poll_interval: std::time::Duration,
    ) -> std::time::Duration {
        if remaining.as_nanos() < poll_interval.as_nanos() {
            remaining
        } else {
            poll_interval
        }
    }

    /// Give the agent its own process group, so that a deadline has something
    /// to signal that covers the whole run.
    ///
    /// Killing a pid reaches one process. That is not enough to end a run:
    /// every descendant the agent left behind inherits its stdout and stderr
    /// pipes, so the capture threads see no EOF and the run cannot be assembled
    /// until the last of them exits. Measured, not assumed — a fake agent that
    /// backgrounds a `sleep` keeps a killed run pending for exactly as long as
    /// the `sleep`, and real coding agents spawn subprocesses constantly. A
    /// deadline that only reaches agents which never fork would be a bound in
    /// name only.
    ///
    /// The group is set on **every** run, and **every** run sweeps it once the
    /// agent is gone — deadline or no deadline. A finished run tears down what
    /// it started, which is the only version of "finished" that is worth
    /// stating: an operator who configures no timeout would otherwise get
    /// containment as an accident of having set one.
    ///
    /// What the sweep reaches is the group, so it reaches everything the agent
    /// started that did not deliberately leave — see
    /// [`kill_agent_process_group`] for the fork race it also has to survive,
    /// and `docs/design/architecture.md` §5.2 for the boundary.
    ///
    /// A side effect worth naming: a new group is not in the daemon's, so a
    /// terminal signal sent to writd's group no longer reaches agents. For a
    /// daemon whose children outlive interactive sessions that is the behaviour
    /// we want anyway.
    #[cfg(unix)]
    fn put_in_own_process_group(command: &mut Command) {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    #[cfg(not(unix))]
    fn put_in_own_process_group(_command: &mut Command) {}

    /// Signal the agent's whole process group.
    ///
    /// Returns whether the group was signalled; on anything but Unix there are
    /// no process groups here and the caller falls back to the one process.
    ///
    /// Delegates to `writ_core::process_group`, which is the codebase's single
    /// definition of this — the errno cases it tolerates and the reason it is
    /// safe to tolerate them took several rounds of review to state, and a
    /// second copy here would be a second place to get them wrong. The
    /// precondition that definition requires is that the leader is still
    /// unreaped; every caller here kills before it waits.
    ///
    /// `empty_group_is_benign` is true because that is exactly the case at
    /// hand: the agent may have exited between the last poll and this kill,
    /// which empties the group, and that is an ordinary ending rather than a
    /// failure to report.
    ///
    /// Uses the *repeated* sweep rather than one kill. Every caller here signals
    /// the group immediately after the agent's exit, which is precisely when a
    /// descendant is most likely to be mid-`fork` and so to be missed — measured
    /// at 32 escapes in 80 runs with a single kill. See
    /// [`writ_core::process_group::sweep_process_group`].
    #[cfg(unix)]
    fn kill_agent_process_group(pid: u32) -> bool {
        let Some(pgid) = writ_core::process_group::process_group_id(pid) else {
            return false;
        };
        writ_core::process_group::sweep_process_group(pgid, true).is_ok()
    }

    #[cfg(not(unix))]
    fn kill_agent_process_group(_pid: u32) -> bool {
        false
    }

    /// Start the thread that feeds the agent its prompt.
    ///
    /// Fails rather than panics when the OS cannot give us a thread, for the
    /// reason [`spawn_capture_thread`] gives.
    fn spawn_prompt_thread(
        stdin: std::process::ChildStdin,
        prompt: AgentPrompt,
    ) -> Result<thread::JoinHandle<Result<(), AgentProcessRunError>>, AgentProcessRunError> {
        thread::Builder::new()
            .name("writ-agent-prompt".to_string())
            .spawn(move || write_prompt_to_stdin(stdin, &prompt))
            .map_err(|source| AgentProcessRunError::StreamThreadSpawn {
                stream: "stdin",
                source,
            })
    }

    fn join_prompt_thread(
        thread: thread::JoinHandle<Result<(), AgentProcessRunError>>,
    ) -> Result<Result<(), AgentProcessRunError>, AgentProcessRunError> {
        thread
            .join()
            .map_err(|panic| AgentProcessRunError::StreamThread {
                stream: "stdin",
                panic: panic_payload_message(panic.as_ref()),
            })
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

    /// The exit code recorded for a process that died by signal rather than by
    /// returning one.
    ///
    /// Not a real exit code — Unix codes are 0-255, so no agent can produce it
    /// — which is what makes it usable as the encoding for "there was no exit
    /// code". A run writ killed at its deadline records this too, and is told
    /// apart from any other signal death by its
    /// [`AgentRunTerminalStatus::TimedOut`] status, not by this number.
    const SIGNAL_DEATH_EXIT_CODE: i32 = -1;

    fn exit_code(status: std::process::ExitStatus) -> i32 {
        status.code().unwrap_or(SIGNAL_DEATH_EXIT_CODE)
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

    #[cfg(test)]
    mod poll_tests {
        use super::sleep_before_next_poll;
        use proptest::prelude::*;
        use std::time::Duration;

        proptest! {
            /// The invariant the deadline rests on: writ never asks to sleep
            /// past the point it means to act.
            ///
            /// Exhaustive over both arguments rather than over the handful of
            /// values a process-driven test could reach, and it holds for a
            /// poll interval of any size — so raising `EXIT_POLL_INTERVAL`
            /// later cannot quietly widen the window in which an agent that
            /// blew its deadline gets recorded as having met it.
            #[test]
            fn a_poll_never_sleeps_past_the_deadline(
                remaining_nanos in 0u64..=u64::MAX,
                poll_nanos in 1u64..=u64::MAX,
            ) {
                let remaining = Duration::from_nanos(remaining_nanos);
                let poll_interval = Duration::from_nanos(poll_nanos);

                let slept = sleep_before_next_poll(remaining, poll_interval);

                prop_assert!(slept <= remaining, "slept {slept:?} of {remaining:?}");
                prop_assert!(slept <= poll_interval, "slept {slept:?} past one poll");
                // And it is the *longest* such sleep: a function returning
                // `Duration::ZERO` would satisfy both bounds above while
                // turning the wait into a busy loop.
                prop_assert_eq!(slept, remaining.min(poll_interval));
            }
        }
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

        /// Block until `pid` has exited, leaving it unreaped so its exit status
        /// is still there to be read.
        ///
        /// `waitid` rather than `waitpid`, measured rather than assumed: Darwin
        /// rejects `WNOWAIT` on `waitpid` with `EINVAL`, so the `waitpid`
        /// spelling of this loops forever on macOS. Blocking rather than
        /// polling because there is nothing to poll for — the caller needs the
        /// child to have exited, and this returns exactly then.
        fn wait_for_exit_without_reaping(pid: u32) {
            // SAFETY: `waitid` writes only through the out-pointer to a local
            // `siginfo_t` that outlives the call. `WNOWAIT` leaves the child
            // unreaped, which is the point: `kill_at_deadline` must still find
            // a status to read.
            let found = unsafe {
                let mut info: libc::siginfo_t = std::mem::zeroed();
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            assert_eq!(found, 0, "waiting for pid {pid} to exit failed");
        }

        /// An agent that finished on its own just before the deadline kill is
        /// recorded as having finished, not as having been stopped.
        ///
        /// The deadline path cannot avoid this window: it decides to kill, and
        /// in the microseconds before the signal lands the agent may exit by
        /// itself. Attributing that run to writ would put a claim about *who
        /// ended it* into an append-only log, wrongly. The reaped status tells
        /// the two apart — writ kills with a signal, and a signalled child has
        /// no exit code — so a code means the agent got there first.
        ///
        /// Deterministic where the race is not: the child here has provably
        /// exited (`true` plus a wait for it to become a zombie) before writ's
        /// kill, which is the same state the race produces.
        #[test]
        fn an_agent_that_beat_the_deadline_kill_reports_its_own_exit() {
            use super::{AgentExit, AgentRunEnd};

            let child = Command::new("true")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("true(1) is available");
            let pid = child.id();
            let mut guard = ChildGuard(Some(child));
            // Unreaped but exited — a zombie — which is exactly what the loop
            // sees when the agent finishes between its last poll and the kill.
            // Waited for rather than assumed: `true` has to actually get there.
            //
            // Not `is_running`: `kill -0` succeeds on a zombie, because the pid
            // is still there until someone reaps it, so that check can never go
            // false here and a loop on it would never end.
            wait_for_exit_without_reaping(pid);

            // Exactly what the deadline path does: kill the group, then reap,
            // having believed the agent was still running.
            guard.kill_group();
            let ended = guard
                .reap(AgentExit::Observed {
                    killed_by_writ: true,
                })
                .expect("reaping an exited child succeeds");

            match ended {
                AgentRunEnd::Exited(status) => assert_eq!(status.code(), Some(0)),
                AgentRunEnd::KilledAtDeadline => {
                    panic!("an agent that exited on its own was recorded as stopped by writ")
                }
            }
        }

        /// A probe that finds the pid already gone disarms the guard, so the
        /// `Drop` cannot signal whoever holds that number next.
        ///
        /// `ECHILD` means somebody else reaped the child — `SIGCHLD` ignored,
        /// `SA_NOCLDWAIT`, an outer reaper — and a reaped pid is immediately
        /// available for reuse. Returning the error with the guard still armed
        /// would send `Drop`'s `kill` to a stranger.
        ///
        /// Provoked by reaping the child out from under the guard, which is
        /// exactly the state those three causes produce.
        #[test]
        fn a_probe_that_finds_the_pid_gone_disarms_the_guard() {
            let mut child = Command::new("true")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("true(1) is available");
            let pid = child.id();
            // Reap it here, releasing the pid — the guard is about to look for
            // a child that no longer exists.
            child.wait().expect("the direct wait reaps it");
            let mut guard = ChildGuard(Some(child));

            let err = guard
                .has_exited()
                .expect_err("waiting on a reaped pid must fail");

            assert!(
                super::is_no_such_child(&err),
                "expected ECHILD, got {err}: this test no longer provokes the \
                 case it exists for"
            );
            assert!(
                guard.0.is_none(),
                "pid {pid} was released, so the guard must be disarmed rather \
                 than left to kill whatever holds that number next"
            );
        }

        /// An agent killed by somebody else's signal is not recorded as having
        /// hit writ's deadline.
        ///
        /// `SIGTERM` from an operator, or an OOM kill, lands in the same window
        /// as writ's own kill and produces the same shape of status: no exit
        /// code. Reading every code-less status as "writ stopped this" would
        /// put writ's name on an ending it had nothing to do with. The signal
        /// is what tells them apart.
        #[test]
        fn an_agent_killed_by_another_signal_is_not_recorded_as_a_timeout() {
            use super::{AgentExit, AgentRunEnd};

            let child = Command::new("sleep")
                .arg("300")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("sleep(1) is available");
            let pid = child.id();
            let guard = ChildGuard(Some(child));

            // Somebody else ends it, with a signal that is not writ's.
            assert!(
                Command::new("kill")
                    .args(["-TERM", &pid.to_string()])
                    .status()
                    .expect("kill(1) is available")
                    .success()
            );
            wait_for_exit_without_reaping(pid);

            let ended = guard
                .reap(AgentExit::Observed {
                    killed_by_writ: true,
                })
                .expect("reaping a signalled child succeeds");

            match ended {
                AgentRunEnd::Exited(status) => {
                    use std::os::unix::process::ExitStatusExt;
                    assert_eq!(status.signal(), Some(libc::SIGTERM));
                }
                AgentRunEnd::KilledAtDeadline => {
                    panic!("a SIGTERM from elsewhere was recorded as writ's deadline")
                }
            }
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

        /// An unbounded wait observes the agent without reaping it, leaving the
        /// pid — and so the process group id, which equals it — still ours.
        ///
        /// This is what makes the sweep that follows safe. Production kills the
        /// group between the wait and the reap, and a wait that reaped would
        /// free the pid for the OS to hand to somebody else, so the kill could
        /// land on a group writ never created. The unbounded path used to reap
        /// here, which was fine only while it never swept.
        ///
        /// Driven through `wait_to_deadline(None)` — the path production takes
        /// — rather than a method only this test calls.
        #[test]
        fn an_unbounded_wait_leaves_the_agent_unreaped() {
            let child = Command::new("true")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("true(1) is available");
            let mut guard = ChildGuard(Some(child));

            let exit = guard.wait_to_deadline(None).expect("wait must succeed");

            assert!(
                matches!(
                    exit,
                    super::AgentExit::Observed {
                        killed_by_writ: false
                    }
                ),
                "an unbounded wait must observe rather than reap, and must not \
                 claim writ ended a run that ended itself"
            );
            // Still there to be reaped, which is the property the sweep needs.
            let ended = guard
                .reap(exit)
                .expect("an observed agent is still there to be reaped");
            match ended {
                super::AgentRunEnd::Exited(status) => assert!(status.success()),
                super::AgentRunEnd::KilledAtDeadline => {
                    panic!("nothing killed this agent; it exited on its own")
                }
            }
        }

        /// The blocking wait disarms the guard when it finds the pid already
        /// gone, so the `Drop` cannot signal whoever holds that number next.
        ///
        /// The same `ECHILD` hazard `a_probe_that_finds_the_pid_gone_disarms_the_guard`
        /// covers for the polling path. It needs its own test because it is a
        /// second call site with its own disarm: the unbounded path no longer
        /// takes the child before waiting — it cannot, since the sweep needs it
        /// — so the protection that used to be structural is now explicit, and
        /// explicit code is what regresses silently.
        #[test]
        fn an_unbounded_wait_that_finds_the_pid_gone_disarms_the_guard() {
            let mut child = Command::new("true")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("true(1) is available");
            let pid = child.id();
            // Reaped out from under the guard, which is the state an ignored
            // `SIGCHLD` or an outer reaper produces.
            child.wait().expect("the direct wait reaps it");
            let mut guard = ChildGuard(Some(child));

            let err = guard
                .wait_to_deadline(None)
                .expect_err("waiting on a reaped pid must fail");

            assert!(
                super::is_no_such_child(&err),
                "expected ECHILD, got {err}: this test no longer provokes the \
                 case it exists for"
            );
            assert!(
                guard.0.is_none(),
                "pid {pid} was released, so the guard must be disarmed rather \
                 than left to kill whatever holds that number next"
            );
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
    use std::time::Duration;

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

    /// The documented invariant, restated independently of
    /// [`RunPurpose::try_new`]. This is the oracle the property below
    /// compares against: two expressions of one rule, so a change to
    /// either that is not a change to both shows up as a counterexample
    /// rather than as a test that was quietly updated to agree.
    fn reference_accepts_run_purpose(raw: &str) -> bool {
        (MIN_RUN_PURPOSE_BYTES..=MAX_RUN_PURPOSE_BYTES).contains(&raw.len())
            && raw.bytes().all(|b| (0x20..=0x7e).contains(&b))
            && !raw.starts_with(' ')
            && !raw.ends_with(' ')
    }

    /// Strings drawn to straddle the boundary: valid-shaped ASCII, ASCII
    /// with a space at either end, anything at all (control bytes,
    /// non-ASCII), and lengths either side of the cap. A uniform
    /// `any::<String>()` would almost never produce an *accepted* value,
    /// so the property would pass while only ever testing rejection.
    ///
    /// The `edge` arm exists because uniform generation is hopeless at
    /// hitting a *specific* byte: widening the accepted range by one to
    /// admit `0x7f` was caught only by the example test until this arm
    /// was added, because nothing else here produces a lone DEL. Search
    /// the boundary deliberately rather than hoping to stumble onto it.
    fn run_purpose_candidate() -> impl Strategy<Value = String> {
        let edge = (
            proptest::sample::select(vec![
                '\u{1f}', ' ', '!', '~', '\u{7f}', '\u{80}', '\u{a0}', '\u{200b}',
            ]),
            "[A-Za-z]{0,8}",
            "[A-Za-z]{0,8}",
        )
            .prop_map(|(edge, before, after)| format!("{before}{edge}{after}"));
        prop_oneof![
            "[ -~]{0,140}",
            "[A-Za-z0-9:._/#-]{0,40}",
            " {0,2}[ -~]{0,20} {0,2}",
            any::<String>(),
            "[\\PC]{0,40}",
            edge,
            Just(String::new()),
            Just("a".repeat(MAX_RUN_PURPOSE_BYTES)),
            Just("a".repeat(MAX_RUN_PURPOSE_BYTES + 1)),
        ]
    }

    proptest! {
        /// `try_new` accepts exactly the documented class — no more, no
        /// less. Stated against a reference predicate rather than as a
        /// list of examples, because the failure that matters is a rule
        /// that is subtly wider than documented (an off-by-one on the
        /// cap, a byte range that lets 0x7f through), which no example
        /// anyone thinks to write will catch.
        #[test]
        fn run_purpose_accepts_exactly_the_documented_class(raw in run_purpose_candidate()) {
            prop_assert_eq!(
                RunPurpose::try_new(raw.clone()).is_ok(),
                reference_accepts_run_purpose(&raw),
                "disagreement on {:?}", raw,
            );
        }

        /// An accepted purpose is stored and re-emitted byte-for-byte.
        /// The audit row is a record of what the caller sent; a type that
        /// trimmed, normalised, or case-folded would make the log
        /// disagree with the request that produced it.
        #[test]
        fn an_accepted_purpose_round_trips_verbatim(raw in run_purpose_candidate()) {
            prop_assume!(reference_accepts_run_purpose(&raw));
            let purpose = RunPurpose::try_new(raw.clone()).expect("reference says it parses");
            prop_assert_eq!(purpose.as_str(), raw.as_str());
            prop_assert_eq!(purpose.to_string(), raw.clone());

            // Serde is the wire boundary, so it must be the same parser:
            // a purpose that arrives as JSON must be exactly as
            // constrained as one built in process, or the wire is a way
            // in for values the type forbids.
            let json = serde_json::to_string(&purpose).expect("a string serialises");
            prop_assert_eq!(&json, &serde_json::to_string(&raw).expect("a string serialises"));
            let back: RunPurpose = serde_json::from_str(&json).expect("its own output parses");
            prop_assert_eq!(back, purpose);
        }

        /// Nothing reaches `RunPurpose` through serde that `try_new`
        /// would refuse. Without this, the newtype documents an invariant
        /// the deserialiser does not enforce, and the wire becomes the
        /// back door.
        #[test]
        fn deserialising_accepts_exactly_what_try_new_accepts(raw in run_purpose_candidate()) {
            let json = serde_json::to_string(&raw).expect("a string serialises");
            let parsed = serde_json::from_str::<RunPurpose>(&json);
            prop_assert_eq!(
                parsed.is_ok(),
                RunPurpose::try_new(raw.clone()).is_ok(),
                "serde and try_new disagree on {:?}", raw,
            );
        }
    }

    /// The values callers actually send parse, and each rejection names
    /// its own reason. The property above pins the *set*; this pins that
    /// the errors are useful, and that the real vocabulary is inside it.
    #[test]
    fn run_purpose_accepts_real_tags_and_names_each_rejection() {
        for ok in [
            "plan-submit",
            "plan-review",
            "plan-implement",
            "review:plan-abc",
            "plan-stage:abc123",
            // An operator's free text: spaces and punctuation are the
            // reason the class is not `CorrelationId`'s.
            "review of plan #3",
            "~",
            &"a".repeat(MAX_RUN_PURPOSE_BYTES),
        ] {
            let parsed = RunPurpose::try_new(ok)
                .unwrap_or_else(|e| panic!("expected {ok:?} to parse, got {e}"));
            assert_eq!(parsed.as_str(), ok);
        }

        assert_eq!(RunPurpose::try_new(""), Err(RunPurposeError::Empty));
        assert_eq!(
            RunPurpose::try_new("a".repeat(MAX_RUN_PURPOSE_BYTES + 1)),
            Err(RunPurposeError::TooLong {
                got: MAX_RUN_PURPOSE_BYTES + 1
            }),
        );
        assert_eq!(
            RunPurpose::try_new(" leading"),
            Err(RunPurposeError::SurroundingSpace),
        );
        assert_eq!(
            RunPurpose::try_new("trailing "),
            Err(RunPurposeError::SurroundingSpace),
        );
        // A lone space is both empty-ish and surrounded; it must not slip
        // through as a purpose that renders as nothing.
        assert_eq!(
            RunPurpose::try_new(" "),
            Err(RunPurposeError::SurroundingSpace),
        );

        // The characters the class exists to exclude: each would be
        // invisible or line-breaking in a log, a terminal, or a listing.
        for (bad, at, byte) in [
            ("nul\0byte", 3, 0u8),
            ("two\nlines", 3, b'\n'),
            ("carriage\rreturn", 8, b'\r'),
            ("tab\tseparated", 3, b'\t'),
            ("esc\x1b[31m", 3, 0x1b),
            ("del\x7f", 3, 0x7f),
            // Cyrillic 'а' — a homoglyph of ASCII 'a', and the reason an
            // allow-Unicode class could not deliver the property.
            ("plan-\u{0430}", 5, 0xd0),
            // Zero-width space: two purposes, one rendering.
            ("plan\u{200b}review", 4, 0xe2),
            // Right-to-left override.
            ("plan\u{202e}review", 4, 0xe2),
        ] {
            assert_eq!(
                RunPurpose::try_new(bad),
                Err(RunPurposeError::ForbiddenByte { at, byte }),
                "expected {bad:?} to be rejected at offset {at}",
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

    /// An agent that outlives its deadline is stopped, and the log says writ
    /// stopped it.
    ///
    /// The fake sleeps far longer than the deadline, so "it finished on its
    /// own" is not an explanation available for any observed outcome here.
    ///
    /// Every assertion here is one the agent cannot satisfy by accident: it
    /// sleeps for 300 seconds, so it can never exit early, whatever the machine
    /// is doing.
    #[cfg(feature = "host")]
    #[test]
    fn an_agent_still_running_at_its_deadline_is_killed_and_recorded_as_timed_out() {
        let dir = tempfile::tempdir().unwrap();
        let fake = write_sleeping_fake_agent(dir.path(), /* reads_stdin */ true);
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000301".parse().unwrap();
        let plan = AgentProcessPlan::new(run_id, fake, [] as [OsString; 0])
            .unwrap()
            .with_timeout(AgentRunTimeout::try_new(Duration::from_secs(3)).unwrap());

        let started = std::time::Instant::now();
        let outcome = run_within(
            plan,
            AgentPrompt::new("this run will not finish"),
            dir.path().join("logs"),
            Duration::from_secs(30),
        );
        let elapsed = started.elapsed();

        assert_eq!(outcome.status, AgentRunTerminalStatus::TimedOut);
        assert_eq!(outcome.exit_code, -1);
        // The fake sleeps for 300s. Anything under that proves the deadline
        // rather than the sleep ended the run; the bound is loose because it is
        // asserting "not 300 seconds", not measuring scheduler latency.
        assert!(
            elapsed < Duration::from_secs(30),
            "the run took {elapsed:?}, so the deadline did not end it"
        );
        // The stream files exist and the run is describable. What the agent had
        // *emitted* by the time it was killed is deliberately not asserted: it
        // depends on how far the agent got and on what its libc had flushed,
        // neither of which writ controls or promises. Asserting it made this
        // test fail under a loaded suite for a reason that was not a defect.
        assert!(outcome.stdout.path.is_file());
        assert!(outcome.stderr.path.is_file());
    }

    /// The deadline covers the *whole* run, including feeding the agent its
    /// prompt.
    ///
    /// This is the case that a deadline placed only around the wait would miss
    /// entirely. The prompt is far larger than any pipe buffer and the agent
    /// never reads it, so the write cannot complete; if the prompt were written
    /// inline before the wait, writd would block in `write(2)` and the deadline
    /// below would never be evaluated at all.
    ///
    /// Bounded from the test side (see [`run_within`]) precisely because the
    /// regression it guards is a hang: a test that hung here would report as a
    /// timed-out test run rather than as this assertion failing.
    #[cfg(feature = "host")]
    #[test]
    fn a_deadline_also_bounds_an_agent_that_never_reads_its_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let fake = write_sleeping_fake_agent(dir.path(), /* reads_stdin */ false);
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000302".parse().unwrap();
        let plan = AgentProcessPlan::new(run_id, fake, [] as [OsString; 0])
            .unwrap()
            .with_timeout(AgentRunTimeout::try_new(Duration::from_millis(500)).unwrap());

        let outcome = run_within(
            plan,
            // Comfortably past the 16-64 KiB a pipe will hold.
            AgentPrompt::new("p".repeat(256 * 1024)),
            dir.path().join("logs"),
            Duration::from_secs(30),
        );

        assert_eq!(outcome.status, AgentRunTerminalStatus::TimedOut);
    }

    /// The deadline bounds a run whose agent forked — which is every real one.
    ///
    /// This is the case that decides whether the timeout is a bound or a
    /// decoration. Killing a pid reaches one process; a descendant that
    /// inherited the stdout/stderr pipes keeps the capture threads from ever
    /// seeing EOF, so the run cannot be assembled until *it* exits, however
    /// long after the deadline that is. Before the process-group kill this test
    /// failed by exceeding a 60-second backstop on a 500ms deadline.
    ///
    /// The fake's descendant would hold the pipes for 60 seconds, so the timing
    /// assertion has no other explanation available to it.
    #[cfg(all(feature = "host", unix))]
    #[test]
    fn a_deadline_reaches_a_descendant_holding_the_streams() {
        let dir = tempfile::tempdir().unwrap();
        let descendant_lifetime = Duration::from_secs(60);
        let fake = write_forking_fake_agent(dir.path(), descendant_lifetime);
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000307".parse().unwrap();
        let plan = AgentProcessPlan::new(run_id, fake, [] as [OsString; 0])
            .unwrap()
            .with_timeout(AgentRunTimeout::try_new(Duration::from_millis(500)).unwrap());

        let started = std::time::Instant::now();
        let outcome = run_within(
            plan,
            AgentPrompt::new("fork and outlive me"),
            dir.path().join("logs"),
            descendant_lifetime / 2,
        );
        let elapsed = started.elapsed();

        assert_eq!(outcome.status, AgentRunTerminalStatus::TimedOut);
        assert!(
            elapsed < descendant_lifetime / 2,
            "the run took {elapsed:?}, so the descendant outlived the deadline"
        );
    }

    /// The deadline bounds the run even when the agent itself finished long
    /// before it — because what is left holding the run open is a descendant
    /// with the stream pipes.
    ///
    /// This is the half a deadline placed only around the wait for the agent
    /// cannot reach: the wait is *over*, so there is nothing left for a
    /// wait-shaped deadline to fire on, and yet the run cannot be assembled
    /// until the capture threads see EOF. Measured before the fix at a reader
    /// blocked for the descendant's full lifetime after the agent exited in
    /// milliseconds.
    ///
    /// The agent here exits immediately and its descendant would hold the pipes
    /// for a minute, so the timing assertion has no other explanation.
    #[cfg(all(feature = "host", unix))]
    #[test]
    fn a_deadline_bounds_a_finished_agents_surviving_descendant() {
        let dir = tempfile::tempdir().unwrap();
        let descendant_lifetime = Duration::from_secs(60);
        let fake = write_quick_exit_forking_fake_agent(dir.path(), descendant_lifetime);
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000308".parse().unwrap();
        let plan = AgentProcessPlan::new(run_id, fake, [] as [OsString; 0])
            .unwrap()
            .with_timeout(AgentRunTimeout::try_new(Duration::from_millis(500)).unwrap());

        let started = std::time::Instant::now();
        let outcome = run_within(
            plan,
            AgentPrompt::new("exit at once, leave something behind"),
            dir.path().join("logs"),
            descendant_lifetime / 2,
        );
        let elapsed = started.elapsed();

        // Only the bound is asserted. *Which* ending gets recorded depends on
        // whether the agent reached its own `exit` before the deadline, and at
        // a deadline this short that is a race against process spawn — it
        // failed exactly that way under a loaded suite. Both answers are
        // correct there, and both are bounded, which is the claim. That writ
        // names the agent's own ending when the agent does finish first is
        // pinned by `an_agent_that_finishes_inside_its_deadline_reports_its_own_outcome`,
        // whose deadline is long enough not to race.
        assert!(
            elapsed < descendant_lifetime / 2,
            "the run took {elapsed:?}: the descendant outlived the deadline"
        );
        // Whichever ending it was, the run produced one rather than hanging.
        assert!(matches!(
            outcome.status,
            AgentRunTerminalStatus::Succeeded | AgentRunTerminalStatus::TimedOut
        ));
    }

    /// A run that ends by itself tears down what it started — with no deadline
    /// configured at all.
    ///
    /// This is the default path, and until now it swept nothing: an agent that
    /// exited in milliseconds left the run blocked in the capture-thread join
    /// for as long as a descendant held the stream pipes, and that descendant
    /// then outlived the run entirely. A finished run is supposed to be
    /// finished.
    ///
    /// The fake's descendant would hold the pipes for a minute and the plan
    /// carries no timeout, so a run that returns in a fraction of that has had
    /// its group swept — there is nothing else in the code that could end the
    /// wait. The return itself is the proof that the pipes closed: this fake
    /// never closes a descriptor, so the only way EOF arrives is the death of
    /// what was holding it.
    ///
    /// **Repeated, because the thing being tested is a race.** A sweep sent the
    /// instant the agent exits can miss a descendant that is mid-`fork`, and one
    /// trial would then pass against a sweep that is wrong three times in five:
    /// measured at 32 escapes in 80 single-kill trials. Over this many trials a
    /// sweep with that hole survives about twice in a thousand runs, so a green
    /// test means the retry is doing its job rather than that the dice were
    /// kind. See `writ_core::process_group::sweep_process_group`.
    #[cfg(all(feature = "host", unix))]
    #[test]
    fn a_run_that_ends_by_itself_sweeps_its_process_group() {
        const TRIALS: u32 = 12;
        let dir = tempfile::tempdir().unwrap();
        let descendant_lifetime = Duration::from_secs(60);
        let fake = write_quick_exit_forking_fake_agent(dir.path(), descendant_lifetime);

        for trial in 0..TRIALS {
            let run_id: AgentRunId = format!("00000000-0000-0000-0000-0000003090{trial:02}")
                .parse()
                .unwrap();
            let plan = AgentProcessPlan::new(run_id, fake.clone(), [] as [OsString; 0]).unwrap();
            assert!(
                plan.timeout().is_none(),
                "this test is about the unbounded path; a timeout would prove the wrong thing"
            );

            let started = std::time::Instant::now();
            let outcome = run_within(
                plan,
                AgentPrompt::new("exit at once, leave something behind"),
                dir.path().join("logs"),
                descendant_lifetime / 2,
            );
            let elapsed = started.elapsed();

            assert!(
                elapsed < descendant_lifetime / 2,
                "trial {trial} took {elapsed:?}: its descendant outlived the run"
            );
            // The sweep never changes what writ reports. It happens after the
            // agent has exited, so the agent's own verdict is still the run's
            // verdict — writ tidying up behind a successful run must not make it
            // look killed.
            assert_eq!(outcome.status, AgentRunTerminalStatus::Succeeded);
            assert_eq!(outcome.exit_code, 0);
        }
    }

    /// A deadline that is not reached changes nothing: the agent's own verdict
    /// and exit code are what get recorded.
    #[cfg(feature = "host")]
    #[test]
    fn an_agent_that_finishes_inside_its_deadline_reports_its_own_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let stdin_path = dir.path().join("stdin.txt");
        let fake = write_fake_agent(dir.path(), 7, "did the work\n", "");
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000303".parse().unwrap();
        let prompt = AgentPrompt::new("finish quickly");
        let plan = AgentProcessPlan::new(run_id, fake, [stdin_path.as_os_str().to_os_string()])
            .unwrap()
            .with_timeout(AgentRunTimeout::try_new(Duration::from_secs(120)).unwrap());

        let outcome = run_within(
            plan,
            prompt.clone(),
            dir.path().join("logs"),
            Duration::from_secs(60),
        );

        assert_eq!(outcome.status, AgentRunTerminalStatus::Failed);
        assert_eq!(outcome.exit_code, 7);
        // The prompt still arrives in full despite being written from another
        // thread now.
        assert_eq!(fs::read_to_string(&stdin_path).unwrap(), prompt.as_str());
    }

    /// A plan with no timeout waits, however long that takes.
    ///
    /// Weak on its own — it cannot distinguish "waited" from "waited a while"
    /// — but it pins the thing the user asked for: absent configuration, the
    /// behaviour is the unbounded one, and an agent that takes longer than any
    /// plausible default is not cut off.
    #[cfg(feature = "host")]
    #[test]
    fn an_agent_with_no_deadline_is_waited_for() {
        let dir = tempfile::tempdir().unwrap();
        let fake = write_slow_fake_agent(dir.path(), Duration::from_secs(2));
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000304".parse().unwrap();
        let plan = AgentProcessPlan::new(run_id, fake, [] as [OsString; 0]).unwrap();
        assert!(plan.timeout().is_none(), "no timeout was configured");

        let outcome = run_within(
            plan,
            AgentPrompt::new("take your time"),
            dir.path().join("logs"),
            Duration::from_secs(60),
        );

        assert_eq!(outcome.status, AgentRunTerminalStatus::Succeeded);
        assert_eq!(outcome.exit_code, 0);
    }

    /// An agent that outlives its deadline is timed out even if it would have
    /// finished within the next poll.
    ///
    /// The deadline is what decides, not the polling that implements it. With a
    /// 1ms deadline against an agent that exits after 100ms, a wait loop that
    /// slept a whole 250ms interval before re-checking would find the agent
    /// already exited and record the run as having *succeeded* — an agent that
    /// blew its deadline reported as one that met it. That is a wrong answer,
    /// not a late one, which is why the sleep is clamped to the time remaining.
    ///
    /// Deterministic in the direction that matters: the agent cannot exit
    /// *earlier* than its sleep, so this cannot report a spurious failure. A
    /// machine loaded enough to delay the whole run past 250ms would make the
    /// unclamped version pass too, so the only risk here is a missed
    /// regression, never a false one.
    #[cfg(feature = "host")]
    #[test]
    fn an_agent_that_blows_its_deadline_is_timed_out_not_rounded_up_to_a_poll() {
        let dir = tempfile::tempdir().unwrap();
        let fake = write_slow_fake_agent(dir.path(), Duration::from_millis(100));
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000305".parse().unwrap();
        let plan = AgentProcessPlan::new(run_id, fake, [] as [OsString; 0])
            .unwrap()
            .with_timeout(AgentRunTimeout::try_new(Duration::from_millis(1)).unwrap());

        let outcome = run_within(
            plan,
            AgentPrompt::new("stop almost immediately"),
            dir.path().join("logs"),
            Duration::from_secs(30),
        );

        assert_eq!(outcome.status, AgentRunTerminalStatus::TimedOut);
    }

    #[test]
    fn an_agent_run_timeout_admits_exactly_the_representable_positive_range() {
        assert_eq!(
            AgentRunTimeout::try_new(Duration::ZERO),
            Err(AgentRunTimeoutError::Zero)
        );
        assert_eq!(
            AgentRunTimeout::try_new(Duration::from_nanos(1))
                .unwrap()
                .get(),
            Duration::from_nanos(1)
        );
        assert_eq!(
            AgentRunTimeout::from_secs(u64::MAX),
            Err(AgentRunTimeoutError::TooLong { secs: u64::MAX })
        );
        // The ceiling exists to keep `Instant::now() + timeout` from panicking,
        // so the check that matters is that the largest accepted value can
        // actually be turned into a deadline.
        let max = AgentRunTimeout::from_secs(MAX_AGENT_RUN_TIMEOUT_SECS).unwrap();
        assert!(std::time::Instant::now().checked_add(max.get()).is_some());
    }

    /// A guest may report that its run succeeded or failed, and may not report
    /// that it timed out — the broker is the only party that stops runs.
    #[test]
    fn a_guest_cannot_report_a_run_as_timed_out() {
        assert_eq!(
            GuestReportedRunStatus::try_from(AgentRunTerminalStatus::Succeeded),
            Ok(GuestReportedRunStatus::Succeeded)
        );
        assert_eq!(
            GuestReportedRunStatus::try_from(AgentRunTerminalStatus::Failed),
            Ok(GuestReportedRunStatus::Failed)
        );
        assert_eq!(
            GuestReportedRunStatus::try_from(AgentRunTerminalStatus::TimedOut),
            Err(GuestCannotReportStatus)
        );
    }

    /// The refusal above is enforced at the wire, not only in Rust: a guest
    /// that hand-rolls the JSON cannot get `timed_out` past deserialisation.
    #[test]
    fn a_guest_outcome_upload_rejects_a_timed_out_status_on_the_wire() {
        let upload = |status: &str| {
            format!(
                r#"{{"run_id":"00000000-0000-0000-0000-000000000306",
                    "status":"{status}","exit_code":0,
                    "stdout":{{"byte_len":0,"sha256_hex":"","truncated":false,
                               "retained_sha256_hex":"","retained_base64":""}},
                    "stderr":{{"byte_len":0,"sha256_hex":"","truncated":false,
                               "retained_sha256_hex":"","retained_base64":""}}}}"#
            )
        };
        serde_json::from_str::<VmAgentRunOutcomeUpload>(&upload("failed"))
            .expect("a guest may report failure");
        let err = serde_json::from_str::<VmAgentRunOutcomeUpload>(&upload("timed_out"))
            .expect_err("a guest may not report a timeout");
        assert!(err.to_string().contains("timed_out"), "{err}");
    }

    /// Run an agent on another thread and fail if it has not returned within
    /// `bound`.
    ///
    /// Every deadline test needs this: the failure mode under test is "the run
    /// never returns", and calling `run_agent_process` directly would turn a
    /// regression into a hung test process — which reports as an infrastructure
    /// problem rather than as this behaviour being broken. `bound` is a
    /// backstop, orders of magnitude above the deadlines under test, not a
    /// second assertion about timing.
    #[cfg(feature = "host")]
    fn run_within(
        plan: AgentProcessPlan,
        prompt: AgentPrompt,
        log_root: std::path::PathBuf,
        bound: Duration,
    ) -> AgentRunCapture {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(run_agent_process(&plan, &prompt, &log_root));
        });
        match rx.recv_timeout(bound) {
            Ok(result) => result.expect("the run produced an outcome"),
            Err(_) => panic!("the agent run did not return within {bound:?}"),
        }
    }

    /// An agent that announces itself and then sleeps for far longer than any
    /// deadline a test sets, optionally draining stdin first.
    ///
    /// `reads_stdin: false` is the case that blocks a prompt writer: the agent
    /// never drains the pipe and never exits, so the read end stays open with
    /// nobody reading it.
    #[cfg(feature = "host")]
    fn write_sleeping_fake_agent(dir: &Path, reads_stdin: bool) -> std::path::PathBuf {
        let path = dir.join(if reads_stdin {
            "sleeping-agent.sh"
        } else {
            "sleeping-deaf-agent.sh"
        });
        let drain = if reads_stdin { "cat > /dev/null\n" } else { "" };
        // The `printf` runs in a subshell so that its output is *flushed*
        // before the agent is killed. `sh` buffers a pipe, and `SIGKILL` runs
        // no atexit handlers, so an inline `printf` here leaves "starting" in
        // the dead shell's buffer and the capture is empty. That is a real
        // property of killing a process rather than a quirk of the fake — a
        // timed-out agent loses whatever it had buffered — and the subshell
        // (a fork, which flushes when it exits) is how this fake emits bytes
        // that have genuinely left the process.
        let script = format!(
            "#!/bin/sh\n\
             ( printf 'starting\\n' )\n\
             {drain}\
             sleep 300\n",
        );
        fs::write(&path, script).unwrap();
        make_executable(&path);
        path
    }

    /// An agent that leaves a descendant holding its stdout/stderr pipes, then
    /// sleeps past any deadline a test sets.
    #[cfg(feature = "host")]
    fn write_forking_fake_agent(dir: &Path, descendant_lifetime: Duration) -> std::path::PathBuf {
        let path = dir.join("forking-agent.sh");
        let seconds = descendant_lifetime.as_secs();
        // The descendant *writes* to stdout at the end of its life, so that it
        // demonstrably holds the write end for its whole lifetime rather than
        // merely having inherited a descriptor the shell might have closed.
        // Without the write there is nothing in the script that requires the
        // pipe to still be open, and a test whose premise is "a descendant
        // holds the streams" has to make that true by construction.
        let script = format!(
            "#!/bin/sh\n\
             ( sleep {seconds}; printf 'late\\n' ) &\n\
             sleep 300\n",
        );
        fs::write(&path, script).unwrap();
        make_executable(&path);
        path
    }

    /// An agent that exits at once, leaving a descendant holding its
    /// stdout/stderr pipes behind it.
    #[cfg(feature = "host")]
    fn write_quick_exit_forking_fake_agent(
        dir: &Path,
        descendant_lifetime: Duration,
    ) -> std::path::PathBuf {
        let path = dir.join("quick-exit-forking-agent.sh");
        let seconds = descendant_lifetime.as_secs_f64();
        // The descendant writes at the end of its life for the reason given in
        // `write_forking_fake_agent`: it is what makes "holds the streams" true
        // by construction rather than by assumption.
        let script = format!(
            "#!/bin/sh\n\
             ( sleep {seconds}; printf 'late\\n' ) &\n\
             exit 0\n",
        );
        fs::write(&path, script).unwrap();
        make_executable(&path);
        path
    }

    /// An agent that takes a while and then succeeds.
    ///
    /// Fractional seconds, because a caller asking for 100ms and silently
    /// getting `sleep 0` would leave a test measuring nothing. Both coreutils
    /// and macOS `sleep` accept them.
    #[cfg(feature = "host")]
    fn write_slow_fake_agent(dir: &Path, sleep: Duration) -> std::path::PathBuf {
        let path = dir.join("slow-agent.sh");
        let seconds = sleep.as_secs_f64();
        let script = format!(
            "#!/bin/sh\n\
             cat > /dev/null\n\
             sleep {seconds}\n\
             exit 0\n",
        );
        fs::write(&path, script).unwrap();
        make_executable(&path);
        path
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
