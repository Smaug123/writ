//! One bounded, supervised read of a host tool's stdout.
//!
//! Two subsystems need the same thing and must not disagree about it: the
//! locked profile's admission evidence
//! ([`crate::agent_vm_locked_admission`]) reads five host tools to decide
//! whether a session may start at all, and the guest record channel
//! ([`crate::agent_vm_guest_log`]) reads `container logs` to decide whether a
//! started guest may be released. Both run a tool the host chose, both must
//! stop waiting inside a deadline, and both must refuse rather than read a
//! prefix of an output that overran its cap.
//!
//! The policy is [`run_bounded_probe`]'s, in one place, so a change to it
//! reaches both. What each caller does with the result is its own: a probe
//! that yields nothing closes admission for one, and leaves a workload
//! unreleased for the other.

use std::time::Duration;

use crate::agent_vm_lifecycle::ProcessInvocation;
use crate::process_supervisor::{self, StderrMode, StdoutMode, SupervisedOutcome, SupervisorError};

/// One probe: what to run, how much of its output to accept, how long to
/// wait for it.
///
/// Inert data with no invariant between its fields, so the fields are public:
/// this describes a command, it does not authorise one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedProbe {
    pub invocation: ProcessInvocation,
    pub byte_cap: usize,
    pub timeout: Duration,
}

/// Why a probe produced no output.
///
/// Every one of these is a fact about the *run*, not about what was run: the
/// detail behind [`ProbeRunFailure::Spawn`] (the `std::io::Error`) is logged
/// by [`run_bounded_probe`] rather than carried here, because a caller
/// deciding what to do next needs to know that the tool said nothing, not the
/// errno behind it. A probe that ran and printed something unreadable is a
/// success here; parsing is the caller's, and its failure is the caller's to
/// describe.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProbeRunFailure {
    /// The tool could not be started at all.
    #[error("the probe could not be started")]
    Spawn,
    /// The tool did not exit within the probe's deadline and was killed.
    #[error("the probe did not finish within its deadline")]
    TimedOut,
    /// The tool wrote more than the probe's byte cap and was killed.
    #[error("the probe wrote more output than its cap allows")]
    OutputTooLarge,
    /// The tool exited non-zero, or on a signal.
    #[error("the probe exited unsuccessfully")]
    Failed,
    /// The tool started, but the host lost the ability to supervise it — it
    /// could not be waited on, or its process group could not be killed. The
    /// run's outcome is unknown, which is not a fact.
    #[error("the probe could not be supervised to completion")]
    Unsupervised,
}

/// Run one probe under its cap and deadline, yielding its stdout or why there
/// is none.
///
/// Through `process_supervisor::run_supervised`, so the probe is spawned as
/// the leader of its own process group and the whole group is SIGKILLed when
/// the deadline expires or the capture is rejected. Killing only the direct
/// child would not do: the privileged admission probes are `sudo` wrapping
/// the helper wrapping `pfctl`, and a wedged `pfctl` would outlive a `sudo`
/// we killed on its own, holding the captured pipe open and accumulating with
/// every refused start.
///
/// The one thing the group kill cannot promise is the privileged half. `sudo`
/// puts a *root* process on the other side of the boundary — its own, since
/// it `exec`s the command directly when no policy close hook is needed — and
/// an unprivileged daemon's `kill(2)` on that is `EPERM`. The supervisor
/// bounds the reap that follows such a kill rather than waiting on it, so the
/// deadline still holds for the daemon; what it does not hold for is the root
/// process, whose lifetime is the helper's own bounds to keep. The guarantee
/// is therefore the weaker, stated one: the daemon stops waiting inside its
/// deadline and reports the fact as unread — and it may leave a wedged root
/// helper behind while doing so.
///
/// `what` names the caller's purpose in the warning this logs, so an operator
/// reading the daemon's log can tell an admission probe from a log read.
pub async fn run_bounded_probe(
    probe: &BoundedProbe,
    what: &'static str,
) -> Result<String, ProbeRunFailure> {
    let mut command = tokio::process::Command::new(probe.invocation.program());
    command
        .args(probe.invocation.args())
        .stdin(std::process::Stdio::null());
    let outcome = process_supervisor::run_supervised(
        &mut command,
        probe.timeout,
        StdoutMode::Capture {
            byte_cap: probe.byte_cap,
        },
        StderrMode::Capture,
    )
    .await;
    match outcome {
        Err(SupervisorError::Spawn(error)) => {
            tracing::warn!(
                probe = %probe.invocation.display_shell(),
                %error,
                "{what} could not be started"
            );
            Err(ProbeRunFailure::Spawn)
        }
        Err(error) => {
            tracing::warn!(
                probe = %probe.invocation.display_shell(),
                %error,
                "{what} could not be supervised"
            );
            Err(ProbeRunFailure::Unsupervised)
        }
        Ok(SupervisedOutcome::TimedOut) => {
            tracing::warn!(
                probe = %probe.invocation.display_shell(),
                timeout_secs = probe.timeout.as_secs(),
                "{what} timed out"
            );
            Err(ProbeRunFailure::TimedOut)
        }
        Ok(SupervisedOutcome::StdoutCapExceeded { cap }) => {
            tracing::warn!(
                probe = %probe.invocation.display_shell(),
                byte_cap = cap,
                "{what} exceeded its output cap"
            );
            Err(ProbeRunFailure::OutputTooLarge)
        }
        Ok(SupervisedOutcome::Exited {
            status,
            stdout,
            stderr,
            ..
        }) => {
            if status.success() {
                Ok(String::from_utf8_lossy(&stdout).into_owned())
            } else {
                tracing::warn!(
                    probe = %probe.invocation.display_shell(),
                    %status,
                    stderr = %String::from_utf8_lossy(&stderr).trim(),
                    "{what} failed"
                );
                Err(ProbeRunFailure::Failed)
            }
        }
    }
}
