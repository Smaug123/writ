//! The daemon's interpreter for the locked profile's start sequence.
//!
//! Stage E2c-2 of `docs/plans/2026-09-01-ipv4-only-locked-v1.md`. Everything
//! the locked start needs now exists as data: the sequence
//! ([`LockedStartStep`]), the phases it establishes
//! ([`crate::agent_vm_locked_lifecycle`]), the readback
//! ([`crate::agent_vm_locked_start`]) and the guest's record channel
//! ([`crate::agent_vm_guest_log`]). This is what walks them.
//!
//! Still unreachable in production: `ConfiguredIpv6Profile::admit` refuses the
//! profile, so nothing builds a locked plan to hand to
//! [`run_locked_start`]. Stage E2c-3 opens that door.
//!
//! # Why it is not the legacy interpreter
//!
//! `start_agent_vm_session` is synchronous and has no state store. The locked
//! tail is neither: the guest handshake is a bounded async poll, and the
//! release is a [`ReleaseSignal`] the store mints. So the locked start is its
//! own function, taking the store, and the legacy path refuses the mode
//! outright rather than half-running it.
//!
//! # What "advance" means here
//!
//! Two things move together at every step, and neither may move alone.
//!
//! The **typestate** is the proof carried forward: each phase's value is
//! constructible only from its predecessor, so the compiler holds the order.
//! The **record** is what the host would find after a crash. Every step
//! writes the record *before* the effect whose completion it would otherwise
//! have to infer — most sharply at the release, where
//! [`AgentVmSessionStateStore::record_release_attempted`] hands back the only
//! `ReleaseSignal` in existence and does so only after writing
//! `ReleaseAttempted`.
//!
//! Nothing here retries. Every failure leaves the workload unreleased and the
//! session's phase saying how far it got, which is what boot reconcile reads.
//!
//! # What gates the release, and what does not
//!
//! Two facts, both host-observed: the image the runtime actually built
//! (`LockedContainerShape`, which also confirms PID 1 *is* the initializer,
//! running as root, with no interposed runtime init), and the initializer's
//! own `security-ready` record.
//!
//! Deliberately *not* a third: a pre-release read of the guest's
//! `/proc/1/status` against
//! [`LockedAwaitingRelease`](writ_guest_init::proc_status). Stage B1 built
//! that type and Stage E3's proof reads it on hardware, but making it a
//! production gate would mean a `container exec` into the guest — the one
//! move layer 2 exists to avoid — to learn something the two facts above
//! already bound: the initializer is the one from the admitted image, and it
//! published the record its own handoff emits only after the capability drop
//! it is asserting. A `/proc` read would catch an *admitted image whose
//! initializer is buggy*, which is a real if narrow gap; it is E3's to close
//! with evidence rather than this path's to close with an exec. See the plan
//! note under Stage E2c-2.

use crate::agent_vm_firewall::PfInstallPhase;
use crate::agent_vm_guest_log::{GuestLogChannel, SecurityReadyError};
use crate::agent_vm_lifecycle::{
    AgentVmSessionPlan, AgentVmSessionState, AgentVmSessionStateStore, AgentVmToolPaths,
    ProcessInvocation, ReleaseSignal,
};
use crate::agent_vm_locked_admission::ImageDigest;
use crate::agent_vm_locked_lifecycle::{Claimed, FirewallFacts, NoInterfacesError};
use crate::agent_vm_locked_start::{
    LockedContainerShape, LockedShapeMismatch, LockedShapeParseError, LockedStartStep,
};
use crate::agent_vm_pf_helper_protocol::{
    PF_HELPER_INSTALL_REPORT_MAX_BYTES, PfHelperInstallReportDoc,
};
use crate::agent_vm_probe::{BoundedProbe, ProbeRunFailure, run_bounded_probe};
use std::time::Duration;

/// How long any one `container` command in the sequence may take.
///
/// The create resolves an image and the start boots a VM, so this is sized
/// for a cold runtime rather than for a command.
pub const LOCKED_CONTAINER_STEP_TIMEOUT: Duration = Duration::from_secs(120);

/// The most output any `container` step in the sequence may produce.
///
/// Only the readback's `container inspect` has anything to say; the others are
/// expected to be quiet, and a chatty one is refused rather than read.
pub const LOCKED_CONTAINER_STEP_MAX_BYTES: usize = 64 * 1024;

/// Why a locked start did not finish.
///
/// Each variant names the step that stopped it, because the phase in the
/// record says how far the session got and this says why it got no further.
/// None of them is retryable in place: the caller tears the session down.
#[derive(Debug, thiserror::Error)]
pub enum LockedStartError {
    #[error("the locked start's {step} step could not be run: {source}")]
    StepUnrun {
        step: &'static str,
        source: ProbeRunFailure,
    },
    #[error("the created VM could not be read back: {0}")]
    ShapeUnreadable(#[from] LockedShapeParseError),
    #[error("the created VM is not the one that was asked for: {0}")]
    ShapeMismatch(#[from] LockedShapeMismatch),
    #[error("the firewall install could not be run: {source}")]
    FirewallUnrun {
        source: Box<crate::agent_vm_lifecycle::ProcessInvocationError>,
    },
    #[error("the firewall install reported nothing this host can read: {0}")]
    FirewallReportUnreadable(String),
    #[error("the firewall install reported no interfaces: {0}")]
    FirewallWithoutInterfaces(#[from] NoInterfacesError),
    #[error("the firewall install stopped at {reached}, not {expected}")]
    FirewallIncomplete {
        reached: PfInstallPhase,
        expected: PfInstallPhase,
    },
    #[error("the guest was not released: {0}")]
    GuestNotReady(#[from] SecurityReadyError),
    #[error("the session's guest environment could not be written: {0}")]
    GuestEnvironmentUnwritten(#[from] crate::agent_vm_lifecycle::GuestEnvironmentError),
    #[error("the session's phase could not be recorded: {0}")]
    PhaseNotRecorded(#[from] crate::agent_vm_lifecycle::AgentVmSessionStateError),
    /// The signal was sent and reported success, and then the record could
    /// not be updated to say so. The workload is running; the record says
    /// `ReleaseAttempted`, which is the phase that means exactly this.
    #[error("the workload was released but the final phase could not be recorded: {source}")]
    ReleasedButNotRecorded {
        source: crate::agent_vm_lifecycle::AgentVmSessionStateError,
    },
    /// The signal was minted and sending it failed or could not be observed.
    /// The record already says `ReleaseAttempted`, so the workload may be
    /// running: see [`LockedPhase::workload_may_be_running`](crate::agent_vm_locked_lifecycle::LockedPhase::workload_may_be_running).
    #[error("the release signal was recorded but not confirmed sent: {source}")]
    ReleaseUnconfirmed { source: ProbeRunFailure },
}

impl LockedStartError {
    /// Whether the workload may be running despite this failure.
    ///
    /// True from the release onwards, and only there. A failed or timed-out
    /// `kill` does not prove non-delivery, and a `kill` that *succeeded*
    /// before the final write failed proves the opposite — so both answer
    /// yes. Everything earlier failed with the guest still parked in
    /// `sigwait`.
    pub fn workload_may_be_running(&self) -> bool {
        match self {
            Self::ReleaseUnconfirmed { .. } | Self::ReleasedButNotRecorded { .. } => true,
            Self::StepUnrun { .. }
            | Self::ShapeUnreadable(_)
            | Self::ShapeMismatch(_)
            | Self::FirewallUnrun { .. }
            | Self::FirewallReportUnreadable(_)
            | Self::FirewallWithoutInterfaces(_)
            | Self::FirewallIncomplete { .. }
            | Self::GuestNotReady(_)
            | Self::GuestEnvironmentUnwritten(_)
            | Self::PhaseNotRecorded(_) => false,
        }
    }
}

/// Run the locked start for a session whose record has already been claimed.
///
/// `state` is the `Claimed` record [`AgentVmSessionStateStore::create_starting`]
/// wrote, and `admitted_image` is the digest Stage D's evidence admitted — the
/// readback accepts no other. The shared network and bootstrap-firewall prefix
/// has already run; this is everything from the VM onwards.
///
/// `guest_channel` is passed in rather than built here so the bounds the host
/// waits under are the caller's to state: a daemon uses
/// [`GuestLogChannel::new`]'s, which are sized for a VM boot.
///
/// On success the record says [`LockedPhase::WorkloadReleased`](crate::agent_vm_locked_lifecycle::LockedPhase::WorkloadReleased) and the guest
/// is running its own command. On failure the record says how far it got and
/// the caller cleans up; [`LockedStartError::workload_may_be_running`] says
/// whether the guest may have been let go first.
pub async fn run_locked_start(
    store: &AgentVmSessionStateStore,
    plan: &AgentVmSessionPlan,
    tools: &AgentVmToolPaths,
    state: AgentVmSessionState,
    admitted_image: &ImageDigest,
    guest_channel: &GuestLogChannel,
) -> Result<AgentVmSessionState, LockedStartError> {
    // Written before the sequence is built, because the create's `--env-file`
    // names it, and dropped as soon as the create has read it — the same
    // lifetime the legacy launch gives it.
    let guest_env = plan.create_guest_env_file()?;
    let sequence = plan.locked_start_sequence(guest_env.as_ref().map(|file| file.path()));
    let claimed = Claimed::new();

    // The prefix has run, so the network exists, is validated, and carries the
    // bootstrap anchor. That is what `NetworkValidated` means.
    let network_validated = claimed.network_validated();
    let state = store.advance_locked(&state, network_validated.lifecycle())?;

    for step in &sequence {
        if let LockedStartStep::CreateVm(invocation) = step {
            run_quiet(invocation, "create", LOCKED_CONTAINER_STEP_TIMEOUT).await?;
        }
    }
    drop(guest_env);
    let shape = read_back(&sequence).await?;
    shape.verify(admitted_image)?;
    for step in &sequence {
        if let LockedStartStep::StartVm(invocation) = step {
            run_quiet(invocation, "start", LOCKED_CONTAINER_STEP_TIMEOUT).await?;
        }
    }
    let agent_vm_started = network_validated.agent_vm_started();
    let state = store.advance_locked(&state, agent_vm_started.lifecycle())?;

    let firewall = install_final_firewall(&sequence).await?;
    let final_firewall = agent_vm_started.final_firewall_installed(firewall);
    let state = store.advance_locked(&state, final_firewall.lifecycle())?;

    let guest = guest_channel.await_security_ready().await?;
    let guest_security_locked = final_firewall.guest_security_locked(guest);
    let state = store.advance_locked(&state, guest_security_locked.lifecycle())?;

    // The one door: the record is written and the signal minted together, so
    // the daemon cannot send a signal it has not first written down. There is
    // no way to get this wrong from here — `send_release` needs a
    // `ReleaseSignal`, and the store is the only thing that makes one — so the
    // test asserts the consequence (the record already says `ReleaseAttempted`
    // when the `kill` runs) rather than guarding the order here.
    let release = store.record_release_attempted(&state, guest_security_locked, tools)?;
    send_release(&release.signal).await?;
    let released = release.attempted.workload_released();
    store
        .advance_locked(&release.state, released.lifecycle())
        .map_err(|source| LockedStartError::ReleasedButNotRecorded { source })
}

/// Run a step expected to say nothing, and refuse it if it does not succeed.
async fn run_quiet(
    invocation: &ProcessInvocation,
    step: &'static str,
    timeout: Duration,
) -> Result<String, LockedStartError> {
    let probe = BoundedProbe {
        invocation: invocation.clone(),
        byte_cap: LOCKED_CONTAINER_STEP_MAX_BYTES,
        timeout,
    };
    run_bounded_probe(&probe, "locked start step")
        .await
        .map_err(|source| LockedStartError::StepUnrun { step, source })
}

async fn read_back(sequence: &[LockedStartStep]) -> Result<LockedContainerShape, LockedStartError> {
    let invocation = sequence
        .iter()
        .find_map(|step| match step {
            LockedStartStep::VerifyVm(invocation) => Some(invocation),
            _ => None,
        })
        .expect("the locked sequence has a verify step");
    let stdout = run_quiet(invocation, "verify", LOCKED_CONTAINER_STEP_TIMEOUT).await?;
    Ok(LockedContainerShape::parse(&stdout)?)
}

/// Install the interface-scoped anchor and read the facts it reports.
///
/// The install's own report is the source of the interfaces: the helper
/// resolves them from the session gateway and the host does not guess. An
/// install that stopped short of [`PfInstallPhase::Reresolve`] is refused,
/// because the phases after the load are the ones that check the anchor says
/// what was asked for.
///
/// # Why this one is not deadline-bounded
///
/// Every other step here runs under [`run_bounded_probe`], which stops
/// *waiting* at its deadline but cannot stop the process: the helper runs
/// behind `sudo`, so the root half is beyond an unprivileged daemon's
/// `kill(2)`. For a read that is harmless — the fact is simply unread. For an
/// *install* it is not. Abandoning a running install lets the daemon move on
/// to teardown, flush the session anchor, and have the helper load its rules
/// afterwards, leaving an anchor behind for a session that no longer exists.
///
/// So the install is waited for. The capture is still bounded in *bytes*, so
/// a chatty helper cannot exhaust host memory, but the daemon does not
/// continue until the privileged half has finished — which is also what the
/// legacy launch does with the same command.
async fn install_final_firewall(
    sequence: &[LockedStartStep],
) -> Result<FirewallFacts, LockedStartError> {
    let invocation = sequence
        .iter()
        .find_map(|step| match step {
            LockedStartStep::InstallFinalFirewall(invocation) => Some(invocation),
            _ => None,
        })
        .expect("the locked sequence has a firewall step");
    let output = invocation
        .run_capturing_output_bounded(PF_HELPER_INSTALL_REPORT_MAX_BYTES)
        .await
        .map_err(|source| LockedStartError::FirewallUnrun {
            source: Box::new(source),
        })?;
    if output.truncated || !output.status.is_some_and(|status| status.success()) {
        return Err(LockedStartError::FirewallReportUnreadable(format!(
            "the install exited {:?} (truncated: {})",
            output.status, output.truncated
        )));
    }
    let stdout = output.stdout;
    let report = PfHelperInstallReportDoc::parse(stdout.trim())
        .map_err(|error| LockedStartError::FirewallReportUnreadable(error.to_string()))?;
    if report.phase() != PfInstallPhase::Reresolve {
        return Err(LockedStartError::FirewallIncomplete {
            reached: report.phase(),
            expected: PfInstallPhase::Reresolve,
        });
    }
    Ok(FirewallFacts::new(
        report.interfaces().to_vec(),
        report.phase(),
    )?)
}

/// Send the one signal that exists.
///
/// A failure here is not a failure to release: the `kill` may have been
/// delivered and the report lost. The record already says
/// `LockedPhase::ReleaseAttempted`, which is what makes that answerable.
async fn send_release(signal: &ReleaseSignal) -> Result<(), LockedStartError> {
    let probe = BoundedProbe {
        invocation: signal.invocation().clone(),
        byte_cap: LOCKED_CONTAINER_STEP_MAX_BYTES,
        timeout: LOCKED_CONTAINER_STEP_TIMEOUT,
    };
    run_bounded_probe(&probe, "locked release signal")
        .await
        .map(|_| ())
        .map_err(|source| LockedStartError::ReleaseUnconfirmed { source })
}

#[cfg(test)]
mod tests;
