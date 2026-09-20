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
//! The reader does not follow the log and does not read it after release. The
//! pre-release window has one writer — PID 1, before any
//! repository-controlled code exists — so the bounds below are sized for one
//! short record and refuse a chatty log rather than accommodating it. The
//! post-release channel carries records with entirely different standing
//! (anything the workload cares to print) and gets its own reader.
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
    BoundedMessage, GuestInitRecord, ISOLATION_ABI_VERSION, RECORD_PREFIX, RecordParseError,
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

/// Why a log does not say one thing about the handoff.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GuestLogScanError {
    /// A line carries the record prefix but is not a record this host reads.
    #[error("log line {line} carries the record prefix but is not a record: {source}")]
    Malformed {
        line: usize,
        source: RecordParseError,
    },
    /// More than one record. The initializer emits exactly one.
    #[error("the log carries {count} records; a correct initializer emits one")]
    Repeated { count: usize },
}

/// Read a chunk of `container logs` output as the initializer's report.
///
/// Lines without [`RECORD_PREFIX`] are not the initializer's and are skipped;
/// lines with it are records or errors, never noise. One trailing carriage
/// return per line is dropped first: whether the container's stdout is a pipe
/// or a terminal is the runtime's business rather than a fact about the
/// record, and a stripped `\r` cannot turn one record into another.
pub fn scan_guest_log(text: &str) -> Result<GuestHandoffReport, GuestLogScanError> {
    let mut found: Option<GuestInitRecord> = None;
    let mut count = 0usize;
    for (index, raw) in text.split('\n').enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if !line.starts_with(RECORD_PREFIX) {
            continue;
        }
        let record =
            GuestInitRecord::parse(line).map_err(|source| GuestLogScanError::Malformed {
                line: index + 1,
                source,
            })?;
        count += 1;
        found.get_or_insert(record);
    }
    if count > 1 {
        return Err(GuestLogScanError::Repeated { count });
    }
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

// --- the bounded reader -----------------------------------------------------

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
    Unreadable(#[from] GuestLogScanError),
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

/// One locked guest's record channel, as the bounds the host will read it
/// under.
///
/// Holds no state and no handle: reading is running a command, so the channel
/// is the command plus every bound on it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestLogChannel {
    probe: BoundedProbe,
    poll_interval: Duration,
    overall_timeout: Duration,
}

impl GuestLogChannel {
    /// The channel a daemon reads, under this module's bounds.
    ///
    /// Plain `container logs <vm>`, with neither `-n` nor `--boot`. `-n` would
    /// keep the *last* n lines, which is the wrong end: a guest that flooded
    /// the log could push the record out of the window and be read as silent,
    /// where reading it all and refusing the overrun fails closed instead.
    /// `--boot` is the VM's boot log, a different stream that the initializer
    /// does not write to.
    pub fn new(container_tool: &Path, vm_name: &str) -> Self {
        Self {
            probe: BoundedProbe {
                invocation: ProcessInvocation::new(
                    container_tool.to_path_buf(),
                    ["logs".to_string(), vm_name.to_string()],
                ),
                byte_cap: GUEST_LOG_MAX_BYTES,
                timeout: GUEST_LOG_READ_TIMEOUT,
            },
            poll_interval: GUEST_LOG_POLL_INTERVAL,
            overall_timeout: GUEST_SECURITY_READY_TIMEOUT,
        }
    }

    /// The command the host will run to read this channel, so it can be
    /// inspected without being run.
    pub fn probe(&self) -> &BoundedProbe {
        &self.probe
    }

    /// The same channel with waiting bounds a test can sit through, rather
    /// than ones sized for a VM boot.
    #[cfg(test)]
    pub(crate) fn with_wait_bounds_for_test(
        mut self,
        poll_interval: Duration,
        overall_timeout: Duration,
    ) -> Self {
        self.poll_interval = poll_interval;
        self.overall_timeout = overall_timeout;
        self
    }

    /// The same channel with a shorter per-read deadline, for a test that has
    /// to wait out a tool which is hanging on purpose.
    #[cfg(test)]
    fn with_read_bounds_for_test(mut self, timeout: Duration) -> Self {
        self.probe.timeout = timeout;
        self
    }

    /// Read the log once, under `deadline` rather than the probe's own, and
    /// say what it reports.
    async fn read_within(
        &self,
        deadline: Duration,
    ) -> Result<GuestHandoffReport, SecurityReadyError> {
        let probe = BoundedProbe {
            timeout: deadline.min(self.probe.timeout),
            ..self.probe.clone()
        };
        let text = run_bounded_probe(&probe, "guest record channel read")
            .await
            .map_err(SecurityReadyError::Unread)?;
        Ok(scan_guest_log(&text)?)
    }

    /// Wait for the guest to publish a `security-ready` record it is this
    /// host's business to act on.
    ///
    /// The only `Ok` is a record that parses, stands alone, and names the ABI
    /// this host implements: the precondition Stage E1's
    /// `FinalFirewallInstalled::guest_security_locked` takes, and it takes
    /// these [`GuestFacts`].
    ///
    /// `overall_timeout` bounds the whole wait: both the read and the sleep
    /// between reads (`next_poll_sleep`) run under whichever is
    /// shorter, their own bound or what is left, so neither can outlast the
    /// wait by outliving the clock check that follows it. A read the *budget* cut short reports
    /// [`SecurityReadyError::Silent`] rather than a tool timeout: with no time
    /// left the host cannot tell a wedged `container logs` from a guest that
    /// had not spoken yet, so it makes the claim that holds either way.
    pub async fn await_security_ready(&self) -> Result<GuestFacts, SecurityReadyError> {
        let start = Instant::now();
        loop {
            let remaining = self.overall_timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(self.silent());
            }
            let budget_is_the_bound = remaining <= self.probe.timeout;
            let report = match self.read_within(remaining).await {
                Err(SecurityReadyError::Unread(ProbeRunFailure::TimedOut))
                    if budget_is_the_bound =>
                {
                    return Err(self.silent());
                }
                other => other?,
            };
            match report {
                GuestHandoffReport::Ready(guest) => {
                    let announced = guest.isolation_abi();
                    if announced != ISOLATION_ABI_VERSION {
                        return Err(SecurityReadyError::AbiVersion {
                            host: ISOLATION_ABI_VERSION,
                            guest: announced,
                        });
                    }
                    return Ok(guest);
                }
                GuestHandoffReport::Failed {
                    step_index,
                    message,
                } => {
                    return Err(SecurityReadyError::HandoffFailed {
                        step_index,
                        message: message.as_str().to_string(),
                    });
                }
                GuestHandoffReport::Silent => {}
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

    fn silent(&self) -> SecurityReadyError {
        SecurityReadyError::Silent {
            timeout: self.overall_timeout,
        }
    }
}

#[cfg(test)]
mod tests;
