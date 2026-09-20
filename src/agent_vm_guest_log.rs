//! The host's read side of a locked guest's one-way record channel.
//!
//! A locked workload is released with `container kill --signal USR1`, and the
//! host may send that signal only once it has observed the guest initializer
//! report a finished handoff. This module is that observation: it reads
//! `container logs` under a byte cap and a deadline and says what the log
//! reports. Stage E2 of `docs/plans/2026-09-01-ipv4-only-locked-v1.md`.
//!
//! # Why a log and not an `exec`
//!
//! The guest is compromised from the moment the agent command starts, and
//! layer 2 promises that the host creates no fresh privileged process inside
//! a locked container after that point (`docs/design/ipv4-only-network-confinement.md`,
//! "Enforcement layer 2"). `container logs` reads a stream the host already
//! owns; `container exec` would be a new process with whatever authority the
//! runtime grants it. The channel is therefore one-way: the guest writes a
//! line, the host reads it, and the host's reply is a signal, not a command.
//!
//! # What the host will act on
//!
//! One line that is exactly a rendered [`GuestInitRecord`], naming the ABI
//! this host implements. Everything else is refused:
//!
//! - A line carrying the record prefix that does not parse is
//!   [`GuestLogScanError::Malformed`] rather than a line to skip. The prefix
//!   is the initializer's, so a line wearing it that this host cannot read is
//!   a disagreement about the handoff contract.
//! - Two records are [`GuestLogScanError::Repeated`]. A correct initializer
//!   emits one and then parks in `sigwait` or exits, so a second means
//!   something else is writing to the channel.
//! - An ABI this host does not implement is
//!   [`SecurityReadyError::AbiVersion`], though Stage D already refused an
//!   image whose *label* named one. The label is what the image claims; this
//!   is what the running initializer announced. They compile from one file in
//!   `crates/writ-guest-init`, which is what makes a disagreement between
//!   them worth refusing rather than reconciling.
//! - A log the host could not read whole — a flood past the cap, a wedged
//!   `container logs`, a tool that exits non-zero — is
//!   [`SecurityReadyError::Unread`]. A truncated log could be missing the
//!   record that would have refused, so a partial read is not acted on.
//!
//! Each of these leaves the workload unreleased, and Stage E1's phases record
//! how far the start got.
//!
//! # Bounds, and what they assume
//!
//! Neither reader follows the log; each reads it whole, under its own bounds,
//! until it finds a record or runs out of time.
//!
//! [`GuestLogChannel`] reads the pre-release window, which has one writer —
//! PID 1, before any repository-controlled code exists — so its bounds are
//! sized for one short record and refuse a chatty log rather than
//! accommodating it. [`GuestBootstrapChannel`] reads what the released
//! workload reports, which is a different thing in every respect that
//! matters: a log the workload is writing to, over the minutes a Nix warm can
//! take, for an outcome that ends a wait and reaches an operator and carries
//! no authority. Two types, so neither can perform the other's wait and
//! neither set of bounds can be spent on the other's read.
//!
//! A record must *begin* its line, because accepting one embedded in a longer
//! line would let a line's framing be chosen by whoever wrote it. That rests
//! on `container logs` handing back the guest's stdio lines as the guest
//! wrote them, which was measured rather than assumed: on Apple `container`
//! 1.4.1 (macOS 25G72), a container whose command `printf`s one line yields
//! exactly those bytes and a bare `\n` — no timestamp, no prefix, no carriage
//! return — and the kernel's messages are on `--boot`, a stream the record
//! never appears in. A runtime that did decorate lines would make a correct
//! guest read as silent here and the start time out, which is the safe
//! direction.

use std::path::Path;
use std::time::{Duration, Instant};

use writ_guest_init::record::{
    BoundedMessage, BoundedMessageError, GuestInitRecord, ISOLATION_ABI_VERSION, RECORD_PREFIX,
    RecordParseError,
};

use crate::agent_vm_lifecycle::ProcessInvocation;
use crate::agent_vm_locked_lifecycle::GuestFacts;
use crate::agent_vm_probe::{BoundedProbe, ProbeRunFailure, run_bounded_probe};

/// The most bytes of pre-release log the host will read.
///
/// Not a budget to spend: the window holds one record, so this is the point
/// past which a pre-release log is anomalous and reading further is the wrong
/// move. The headroom over a single record is for a runtime that decorates
/// each line.
pub const GUEST_LOG_MAX_BYTES: usize = 8 * 1024;

/// How long one `container logs` invocation may take before it is killed.
///
/// Bounds the *tool*, not the wait: a wedged `container logs` must not consume
/// the whole release deadline in one tick.
pub const GUEST_LOG_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the host waits between reads.
///
/// Flat, with no backoff: the wait is short, the read is cheap, and the cost
/// of noticing the record late is a guest parked in `sigwait` for longer than
/// it needed to be.
pub const GUEST_LOG_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How long the host waits for the guest to publish its record before giving
/// up and tearing the session down.
///
/// Sized for the VM boot that precedes the handoff, not for the handoff,
/// which is a handful of `chown`s, sysctl writes and capability calls.
pub const GUEST_SECURITY_READY_TIMEOUT: Duration = Duration::from_secs(120);

/// The most bytes of post-release log the host will read.
///
/// Wider than the pre-release cap because the writer is different: everything
/// the workspace bootstrap and the released command print to PID 1's stdout
/// lands here, where the pre-release window holds one record from one trusted
/// writer. The number is the cap the sentinel path already applies to a single
/// guest read, so moving the outcome onto this channel does not widen what a
/// hostile guest can make the host buffer. Exceeding it still refuses rather
/// than reads a prefix.
pub const GUEST_BOOTSTRAP_LOG_MAX_BYTES: usize = 1024 * 1024;

/// How long the host waits between reads of the post-release channel.
///
/// Flat, and slower than the pre-release interval: a workspace bootstrap that
/// warms a devShell takes minutes, so noticing its outcome a second late costs
/// nothing, while re-reading a megabyte-capped log four times a second for
/// twenty minutes costs a host-side spawn each time.
pub const GUEST_BOOTSTRAP_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How long the host waits for the guest to report its bootstrap outcome.
///
/// The same twenty minutes the sentinel path allows, and for the same reason:
/// the wait spans a Nix warm of a devShell that has not been substituted yet.
pub const GUEST_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(20 * 60);

// --- the pure scan ----------------------------------------------------------

/// What a locked guest's log says about its handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestHandoffReport {
    /// The initializer has published nothing yet.
    Silent,
    /// `security-ready`: the handoff completed, every capability is gone, and
    /// the release wait is armed.
    Ready(GuestFacts),
    /// `handoff-failed`: a step failed and the workload was never started.
    /// Names the step's index in the handoff plan and the initializer's own
    /// bounded reason.
    Failed {
        step_index: usize,
        message: BoundedMessage,
    },
}

/// Why a log does not say one thing.
///
/// Generic over the parse error because the channel carries two vocabularies
/// with two parsers, while the *shape* of the refusal is the same for both.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GuestLogScanError<E: std::error::Error> {
    /// A line carries the record prefix but is not a record this host reads.
    #[error("log line {line} carries the record prefix but is not a record: {source}")]
    Malformed { line: usize, source: E },
    /// More than one record. Each writer on this channel emits at most one.
    #[error("the log carries {count} records; at most one is expected")]
    Repeated { count: usize },
}

/// The at-most-one record carrying `prefix`, parsed by `parse`.
///
/// Shared by both vocabularies, and the whole of what they have in common.
/// One trailing carriage return per line is dropped first: whether the
/// container's stdout is a pipe or a terminal is the runtime's business rather
/// than a fact about the record, and a stripped `\r` cannot turn one record
/// into another. A record must *begin* its line — see the module docs for the
/// measurement behind that.
///
/// Lines are parsed as they are found, so the first thing wrong with a log in
/// reading order is the thing reported: a malformed line before a second
/// record is a malformed line, not a count.
fn sole_record<T, E: std::error::Error>(
    text: &str,
    prefix: &str,
    parse: impl Fn(&str) -> Result<T, E>,
) -> Result<Option<T>, GuestLogScanError<E>> {
    let mut found = None;
    let mut count = 0usize;
    for (index, raw) in text.split('\n').enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if !line.starts_with(prefix) {
            continue;
        }
        let record = parse(line).map_err(|source| GuestLogScanError::Malformed {
            line: index + 1,
            source,
        })?;
        count += 1;
        found.get_or_insert(record);
    }
    if count > 1 {
        return Err(GuestLogScanError::Repeated { count });
    }
    Ok(found)
}

/// Read a chunk of `container logs` output as the initializer's report.
///
/// Lines without [`RECORD_PREFIX`] are not the initializer's and are skipped;
/// lines with it are records or errors, never noise. One trailing carriage
/// return per line is dropped first: whether the container's stdout is a pipe
/// or a terminal is the runtime's business rather than a fact about the
/// record, and a stripped `\r` cannot turn one record into another.
pub fn scan_guest_log(
    text: &str,
) -> Result<GuestHandoffReport, GuestLogScanError<RecordParseError>> {
    let found = sole_record(text, RECORD_PREFIX, GuestInitRecord::parse)?;
    Ok(match found {
        None => GuestHandoffReport::Silent,
        Some(GuestInitRecord::SecurityReady { abi }) => {
            GuestHandoffReport::Ready(GuestFacts::new(abi))
        }
        Some(GuestInitRecord::HandoffFailed {
            step_index,
            message,
        }) => GuestHandoffReport::Failed {
            step_index,
            message,
        },
    })
}

// --- the post-release vocabulary --------------------------------------------

/// The prefix a workspace-bootstrap record carries.
///
/// Deliberately **not** [`RECORD_PREFIX`]. The two vocabularies share a
/// channel and nothing else: the initializer's record is published before any
/// repository-controlled code exists and gates the release, while a bootstrap
/// record is printed *after* release by code running as the same UID as PID 1,
/// which can print whatever it likes.
///
/// Separate prefixes make that separation structural rather than a rule
/// someone remembers. A workload printing a `security-ready` line is not
/// making a claim the bootstrap reader will look at, and a bootstrap record
/// appearing in the pre-release window is not something the release gate will
/// look at either — neither reader can see the other's vocabulary at all.
pub const BOOTSTRAP_RECORD_PREFIX: &str = "writ-agent-vm-bootstrap";

/// The most bytes a rendered bootstrap record may occupy.
///
/// The reason is bounded by `BoundedMessage`, exactly as the guest's failure
/// file is today, so migrating to this channel does not widen what an operator
/// can be made to read.
pub const BOOTSTRAP_RECORD_MAX_BYTES: usize = 512;

const BOOTSTRAP_TAG_OK: &str = "ok";
const BOOTSTRAP_TAG_FAILED: &str = "failed";

/// What the guest's bootstrap said about itself.
///
/// Untrusted by construction. It ends a wait, it is reported to an operator,
/// and it carries no authority: a forged success harms only the agent that
/// forged it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestBootstrapRecord {
    /// The workspace bootstrap and the egress gate both passed, and the guest
    /// command is running.
    Ok,
    /// Something before the guest command failed, with a bounded reason.
    Failed { message: BoundedMessage },
}

/// Why a line is not a [`GuestBootstrapRecord`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BootstrapRecordParseError {
    #[error("input contains a newline; a record is a single line")]
    ContainsNewline,
    #[error("input is {len} bytes, over the {BOOTSTRAP_RECORD_MAX_BYTES}-byte bound")]
    TooLong { len: usize },
    #[error("line does not begin with the bootstrap prefix {BOOTSTRAP_RECORD_PREFIX:?}")]
    MissingPrefix,
    #[error("unknown bootstrap tag {0:?}")]
    UnknownTag(String),
    #[error("the ok record has trailing data: {0:?}")]
    TrailingData(String),
    #[error("the failure reason is not a bounded message: {0}")]
    BadReason(#[from] BoundedMessageError),
}

impl GuestBootstrapRecord {
    /// The record as one line, without a trailing newline.
    pub fn render(&self) -> String {
        match self {
            Self::Ok => format!("{BOOTSTRAP_RECORD_PREFIX} {BOOTSTRAP_TAG_OK}"),
            Self::Failed { message } => format!(
                "{BOOTSTRAP_RECORD_PREFIX} {BOOTSTRAP_TAG_FAILED} {}",
                message.as_str()
            ),
        }
    }

    /// Parse one line, accepting nothing that is not exactly a rendered
    /// record.
    pub fn parse(line: &str) -> Result<Self, BootstrapRecordParseError> {
        use BootstrapRecordParseError::*;
        if line.contains('\n') {
            return Err(ContainsNewline);
        }
        if line.len() > BOOTSTRAP_RECORD_MAX_BYTES {
            return Err(TooLong { len: line.len() });
        }
        let rest = line
            .strip_prefix(BOOTSTRAP_RECORD_PREFIX)
            .and_then(|rest| rest.strip_prefix(' '))
            .ok_or(MissingPrefix)?;
        let (tag, body) = match rest.split_once(' ') {
            Some((tag, body)) => (tag, Some(body)),
            None => (rest, None),
        };
        match (tag, body) {
            (BOOTSTRAP_TAG_OK, None) => Ok(Self::Ok),
            (BOOTSTRAP_TAG_OK, Some(rest)) => Err(TrailingData(rest.to_string())),
            // The reason is the rest of the line, so an empty one is a record
            // with an empty reason rather than a malformed record.
            (BOOTSTRAP_TAG_FAILED, body) => Ok(Self::Failed {
                message: BoundedMessage::parse(body.unwrap_or(""))?,
            }),
            (other, _) => Err(UnknownTag(other.to_string())),
        }
    }
}

/// What one bounded read of the post-release channel reports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestBootstrapReport {
    /// The guest has printed no bootstrap record yet.
    Pending,
    Finished(GuestBootstrapRecord),
}

/// Read a chunk of `container logs` output as the guest's bootstrap outcome.
///
/// Sees only [`BOOTSTRAP_RECORD_PREFIX`] lines, so an initializer record —
/// including one a released workload printed itself — is not a bootstrap
/// outcome and is skipped like any other output.
pub fn scan_bootstrap_log(
    text: &str,
) -> Result<GuestBootstrapReport, GuestLogScanError<BootstrapRecordParseError>> {
    Ok(
        match sole_record(text, BOOTSTRAP_RECORD_PREFIX, GuestBootstrapRecord::parse)? {
            None => GuestBootstrapReport::Pending,
            Some(record) => GuestBootstrapReport::Finished(record),
        },
    )
}

// --- the bounded reader -----------------------------------------------------

/// Why a bounded wait for a record ended with nothing to act on.
///
/// Generic over the parse error for the same reason [`GuestLogScanError`] is:
/// the two vocabularies are refused differently, the wait around them is not.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ChannelWaitError<E: std::error::Error> {
    /// The log could not be read whole. A truncated log could be missing what
    /// would have refused, so a partial read is not acted on.
    #[error("the guest's log could not be read: {0}")]
    Unread(ProbeRunFailure),
    /// The log was read, and does not say one thing.
    #[error("the guest's log does not say one thing: {0}")]
    Unreadable(#[from] GuestLogScanError<E>),
    /// Nothing was published before the deadline.
    #[error("the guest published no record within {timeout:?}")]
    Silent { timeout: Duration },
}

/// One bounded wait on a guest's log: the command, and every bound on it.
///
/// Holds no state and no handle — reading is running a command — and knows
/// nothing about either vocabulary. Each channel below is this plus a scan,
/// which is what keeps the two waits from drifting apart while their bounds
/// and their standing stay different.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ChannelWait {
    probe: BoundedProbe,
    poll_interval: Duration,
    overall_timeout: Duration,
}

impl ChannelWait {
    /// Plain `container logs <vm>`, with neither `-n` nor `--boot`. `-n` would
    /// keep the *last* n lines, which is the wrong end: a guest that flooded
    /// the log could push the record out of the window and be read as silent,
    /// where reading it all and refusing the overrun fails closed instead.
    /// `--boot` is the VM's boot log, a different stream that neither writer
    /// on this channel uses.
    fn reading(
        container_tool: &Path,
        vm_name: &str,
        byte_cap: usize,
        poll_interval: Duration,
        overall_timeout: Duration,
    ) -> Self {
        Self {
            probe: BoundedProbe {
                invocation: ProcessInvocation::new(
                    container_tool.to_path_buf(),
                    ["logs".to_string(), vm_name.to_string()],
                ),
                byte_cap,
                timeout: GUEST_LOG_READ_TIMEOUT,
            },
            poll_interval,
            overall_timeout,
        }
    }

    /// Read the log until `scan` reports a record, or the wait runs out.
    ///
    /// `scan` answers `Ok(None)` for a log that has not spoken yet, so what
    /// counts as "yet" stays with the vocabulary; everything else here is the
    /// bound.
    ///
    /// `overall_timeout` bounds the whole wait: both the read and the sleep
    /// between reads ([`Self::next_poll_sleep`]) run under whichever is
    /// shorter, their own bound or what is left, so neither can outlast the
    /// wait by outliving the clock check that follows it. A read the *budget*
    /// cut short reports [`ChannelWaitError::Silent`] rather than a tool
    /// timeout: with no time left the host cannot tell a wedged `container
    /// logs` from a guest that had not spoken yet, so it makes the claim that
    /// holds either way.
    async fn await_record<T, E: std::error::Error>(
        &self,
        what: &'static str,
        scan: impl Fn(&str) -> Result<Option<T>, GuestLogScanError<E>>,
    ) -> Result<T, ChannelWaitError<E>> {
        let start = Instant::now();
        loop {
            let remaining = self.overall_timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(self.silent());
            }
            let budget_is_the_bound = remaining <= self.probe.timeout;
            let probe = BoundedProbe {
                timeout: remaining.min(self.probe.timeout),
                ..self.probe.clone()
            };
            let text = match run_bounded_probe(&probe, what).await {
                Ok(text) => text,
                Err(ProbeRunFailure::TimedOut) if budget_is_the_bound => {
                    return Err(self.silent());
                }
                Err(failure) => return Err(ChannelWaitError::Unread(failure)),
            };
            if let Some(record) = scan(&text)? {
                return Ok(record);
            }
            tokio::time::sleep(self.next_poll_sleep(start.elapsed())).await;
        }
    }

    /// How long to wait before the next read, `elapsed` into the wait.
    ///
    /// Capped by what is left as well as by the poll interval, so the wait is
    /// bounded by `overall_timeout` rather than by it plus one interval. A
    /// zero result sleeps for no time and the check at the top of the loop is
    /// the one that ends the wait.
    ///
    /// Separated out because it is the whole of that bound and it is pure:
    /// a property can hold it over every combination of interval, budget and
    /// elapsed time, where a test that drove the loop and timed it would be
    /// measuring process spawn latency.
    fn next_poll_sleep(&self, elapsed: Duration) -> Duration {
        self.poll_interval
            .min(self.overall_timeout.saturating_sub(elapsed))
    }

    fn silent<E: std::error::Error>(&self) -> ChannelWaitError<E> {
        ChannelWaitError::Silent {
            timeout: self.overall_timeout,
        }
    }
}

/// Why the host will not release this guest.
///
/// Every variant leaves the workload unreleased, and none is worth reading
/// again for: a log that said two things has said them, and a guest that
/// announced an ABI this host does not implement will announce it again.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SecurityReadyError {
    /// The log could not be read whole.
    #[error("the guest's log could not be read: {0}")]
    Unread(ProbeRunFailure),
    /// The log was read, and does not say one thing.
    #[error("the guest's log does not say one thing: {0}")]
    Unreadable(#[from] GuestLogScanError<RecordParseError>),
    /// The initializer reported a failed handoff step. The workload never
    /// started, so there is nothing to release.
    #[error("the guest initializer failed at handoff step {step_index}: {message}")]
    HandoffFailed { step_index: usize, message: String },
    /// The initializer announced an ABI this host does not implement.
    #[error("the guest announced isolation ABI {guest}; this host implements {host}")]
    AbiVersion { host: u32, guest: u32 },
    /// The guest published nothing before the deadline.
    #[error("the guest published no record within {timeout:?}")]
    Silent { timeout: Duration },
}

impl From<ChannelWaitError<RecordParseError>> for SecurityReadyError {
    fn from(error: ChannelWaitError<RecordParseError>) -> Self {
        match error {
            ChannelWaitError::Unread(failure) => Self::Unread(failure),
            ChannelWaitError::Unreadable(scan) => Self::Unreadable(scan),
            ChannelWaitError::Silent { timeout } => Self::Silent { timeout },
        }
    }
}

/// One locked guest's pre-release record channel, as the bounds the host will
/// read it under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestLogChannel(ChannelWait);

impl GuestLogChannel {
    /// The channel a daemon reads before the release, under this module's
    /// bounds.
    pub fn new(container_tool: &Path, vm_name: &str) -> Self {
        Self(ChannelWait::reading(
            container_tool,
            vm_name,
            GUEST_LOG_MAX_BYTES,
            GUEST_LOG_POLL_INTERVAL,
            GUEST_SECURITY_READY_TIMEOUT,
        ))
    }

    /// The command the host will run to read this channel, so it can be
    /// inspected without being run.
    pub fn probe(&self) -> &BoundedProbe {
        &self.0.probe
    }

    /// The same channel with waiting bounds a test can sit through, rather
    /// than ones sized for a VM boot.
    #[cfg(test)]
    pub(crate) fn with_wait_bounds_for_test(
        mut self,
        poll_interval: Duration,
        overall_timeout: Duration,
    ) -> Self {
        self.0.poll_interval = poll_interval;
        self.0.overall_timeout = overall_timeout;
        self
    }

    /// The same channel with a shorter per-read deadline, for a test that has
    /// to wait out a tool which is hanging on purpose.
    #[cfg(test)]
    fn with_read_bounds_for_test(mut self, timeout: Duration) -> Self {
        self.0.probe.timeout = timeout;
        self
    }

    /// Wait for the guest to publish a `security-ready` record it is this
    /// host's business to act on.
    ///
    /// The only `Ok` is a record that parses, stands alone, and names the ABI
    /// this host implements: the precondition Stage E1's
    /// `FinalFirewallInstalled::guest_security_locked` takes, and it takes
    /// these [`GuestFacts`].
    pub async fn await_security_ready(&self) -> Result<GuestFacts, SecurityReadyError> {
        let report = self
            .0
            .await_record("guest record channel read", |text| {
                Ok(match scan_guest_log(text)? {
                    GuestHandoffReport::Silent => None,
                    reported => Some(reported),
                })
            })
            .await?;
        match report {
            GuestHandoffReport::Ready(guest) => {
                let announced = guest.isolation_abi();
                if announced != ISOLATION_ABI_VERSION {
                    return Err(SecurityReadyError::AbiVersion {
                        host: ISOLATION_ABI_VERSION,
                        guest: announced,
                    });
                }
                Ok(guest)
            }
            GuestHandoffReport::Failed {
                step_index,
                message,
            } => Err(SecurityReadyError::HandoffFailed {
                step_index,
                message: message.as_str().to_string(),
            }),
            // `await_record` returns only on a record, and `Silent` is the
            // absence of one.
            GuestHandoffReport::Silent => Err(SecurityReadyError::Silent {
                timeout: self.0.overall_timeout,
            }),
        }
    }
}

/// The same guest's post-release channel, under bounds of its own.
///
/// A separate type rather than a second method on [`GuestLogChannel`] because
/// the two waits have nothing in common but the command they run. This one
/// reads a log that repository-controlled code is writing to, for an outcome
/// that carries no authority, over the minutes a Nix warm can take; that one
/// reads a log with a single trusted writer, for the fact that gates the
/// release, over a VM boot. Neither type can perform the other's wait, so
/// neither set of bounds can be spent on the other's read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestBootstrapChannel(ChannelWait);

impl GuestBootstrapChannel {
    /// The channel a daemon reads after the release, under this module's
    /// post-release bounds.
    pub fn new(container_tool: &Path, vm_name: &str) -> Self {
        Self(ChannelWait::reading(
            container_tool,
            vm_name,
            GUEST_BOOTSTRAP_LOG_MAX_BYTES,
            GUEST_BOOTSTRAP_POLL_INTERVAL,
            GUEST_BOOTSTRAP_TIMEOUT,
        ))
    }

    /// The command the host will run to read this channel.
    pub fn probe(&self) -> &BoundedProbe {
        &self.0.probe
    }

    /// The same channel with waiting bounds a test can sit through.
    #[cfg(test)]
    pub(crate) fn with_wait_bounds_for_test(
        mut self,
        poll_interval: Duration,
        overall_timeout: Duration,
    ) -> Self {
        self.0.poll_interval = poll_interval;
        self.0.overall_timeout = overall_timeout;
        self
    }

    /// Wait for the guest to report how its bootstrap went.
    ///
    /// Both outcomes are `Ok`: this is a report, not a verdict. A failure is
    /// the guest saying what went wrong — the host's own conclusions about a
    /// bootstrap that failed are the caller's to draw — while the errors here
    /// are the host being unable to read the channel at all.
    ///
    /// Nothing that carries authority may key off the success. The workload
    /// runs as the same UID as PID 1 by this point and can print whatever it
    /// likes, so a forged `ok` ends this wait and reaches an operator, and
    /// that is the whole of what it can do.
    pub async fn await_bootstrap(
        &self,
    ) -> Result<GuestBootstrapRecord, ChannelWaitError<BootstrapRecordParseError>> {
        self.0
            .await_record("guest bootstrap channel read", |text| {
                Ok(match scan_bootstrap_log(text)? {
                    GuestBootstrapReport::Pending => None,
                    GuestBootstrapReport::Finished(record) => Some(record),
                })
            })
            .await
    }
}

#[cfg(test)]
mod tests;
