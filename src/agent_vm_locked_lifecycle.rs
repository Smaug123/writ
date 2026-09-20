//! The `ipv4_only_locked_v1` start sequence as an ordered, typed lifecycle.
//!
//! Stage E1 of `docs/plans/2026-09-01-ipv4-only-locked-v1.md`, and inert for
//! the same reason Stage D was: no session can be in the locked mode until
//! Stage E2 gives `Ipv6IsolationMode` a variant for it, so nothing in
//! production builds the values below. What lands here is the model the locked
//! start path will be written against, and the persisted shape (schema v3)
//! that records how far one got.
//!
//! # Two representations, deliberately
//!
//! Moving forward and looking back are different problems, so they have
//! different types.
//!
//! **The typestates** ([`Claimed`] … [`WorkloadReleased`]) are how a *live*
//! start advances. Each is a distinct type holding exactly the facts proven by
//! the time it exists, and each is constructible only by consuming its
//! predecessor. There is no other constructor, so the order is a compile-time
//! fact rather than a convention: in particular [`ReleaseAttempted`] can be
//! reached only from [`GuestSecurityLocked`], which can be reached only from
//! [`FinalFirewallInstalled`]. A start path that tried to release a guest
//! whose security it had not observed, or whose interface-scoped anchor it had
//! not read back, would not compile.
//!
//! **The snapshot** ([`LockedLifecycle`]) is what a persisted record says, and
//! what reconciliation reads. It is a discriminated union with one variant per
//! phase, carrying that phase's facts and no others — so a record cannot claim
//! to have released a workload while carrying no interfaces, which is a state
//! reconciliation would otherwise have to guess about. Loading one does *not*
//! yield a typestate: a record read from disk is an observation, not a licence
//! to carry on, and the only way to move a session forward is to have started
//! it in this process.
//!
//! # The release gate
//!
//! [`ReleaseAttempted`] is persisted *before* `container kill --signal USR1`
//! is sent, and the ordering is structural: the signal is a
//! [`ReleaseSignal`](crate::agent_vm_lifecycle::ReleaseSignal), which only the
//! state store mints, and only after the record is written. The signal's
//! outcome is not knowable — a failed or timed-out `kill` does not prove
//! non-delivery, and the daemon can die between delivery and recording it — so
//! a session found in `ReleaseAttempted` is treated exactly as one found in
//! `WorkloadReleased`: authority revoked, then cleaned up, never resumed and
//! never signalled again.

use crate::agent_vm_firewall::PfInstallPhase;
use crate::core::PfInterface;

/// The signal the host sends to release a locked workload, as
/// `container kill --signal` spells it.
///
/// `SIGUSR1` is what the guest initializer parks in `sigwait` for, having
/// blocked it before it published `security-ready`; see
/// `crates/writ-guest-init`.
pub const LOCKED_RELEASE_SIGNAL: &str = "USR1";

/// How far a locked session's start got, as one ordered value.
///
/// Separate from [`LockedLifecycle`], which carries each phase's facts: this
/// is the part that is compared, ordered, logged and shown to an operator.
/// Ordering is the sequence itself, so `<` reads as "got less far".
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LockedPhase {
    /// The session id and subnet are allocated; nothing exists on the host.
    Claimed,
    /// The network was created and inspected, and the bootstrap anchor is
    /// loaded. No interface is known yet — the guest's bridge does not exist
    /// until the VM starts.
    NetworkValidated,
    /// The agent VM is running its initializer, which holds for release.
    AgentVmStarted,
    /// The interface-scoped anchor is installed over the bootstrap one, with
    /// the bridge and its members resolved, loaded, read back exactly, and the
    /// interfaces resolved again.
    FinalFirewallInstalled,
    /// The guest initializer published its `security-ready` record: it has
    /// dropped every capability and become the unprivileged fixed identity.
    GuestSecurityLocked,
    /// The release signal is about to be sent, and this was written down
    /// first. See the module docs: this phase is indistinguishable from
    /// [`Self::WorkloadReleased`] as far as anything that matters is
    /// concerned.
    ReleaseAttempted,
    /// The release signal was sent and reported success.
    WorkloadReleased,
}

impl LockedPhase {
    /// Every phase, in order.
    pub const ALL: [Self; 7] = [
        Self::Claimed,
        Self::NetworkValidated,
        Self::AgentVmStarted,
        Self::FinalFirewallInstalled,
        Self::GuestSecurityLocked,
        Self::ReleaseAttempted,
        Self::WorkloadReleased,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::NetworkValidated => "network_validated",
            Self::AgentVmStarted => "agent_vm_started",
            Self::FinalFirewallInstalled => "final_firewall_installed",
            Self::GuestSecurityLocked => "guest_security_locked",
            Self::ReleaseAttempted => "release_attempted",
            Self::WorkloadReleased => "workload_released",
        }
    }

    /// Parse the spelling [`Self::as_str`] writes, and nothing else.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|phase| phase.as_str() == text)
    }

    /// Whether a session in this phase must be treated as having had its
    /// workload released.
    ///
    /// True from [`Self::ReleaseAttempted`] on, because the signal's outcome
    /// is not knowable: see the module docs. Reconciliation uses this to
    /// decide nothing — it cleans up either way — but an operator report that
    /// said "never released" of a `ReleaseAttempted` session would be stating
    /// something the daemon does not know.
    pub fn workload_may_be_running(self) -> bool {
        self >= Self::ReleaseAttempted
    }
}

impl std::fmt::Display for LockedPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the host proved about the session's PF anchor when it installed the
/// interface-scoped one.
///
/// The interfaces are the identity the anchor's rules are scoped to; teardown
/// needs them, and an operator reading a stuck session needs them more. The
/// install phase is the last one that completed, which is
/// [`PfInstallPhase::Reresolve`] for an install that finished — the field
/// exists so a record written by a *failed* install says where it stopped
/// rather than implying it got all the way.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirewallFacts {
    interfaces: Vec<PfInterface>,
    install_phase: PfInstallPhase,
}

/// Why a set of firewall facts is not one.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the final firewall is scoped to at least one interface")]
pub struct NoInterfacesError;

impl FirewallFacts {
    /// An anchor with no interfaces scopes nothing, so there is no such thing
    /// as a final firewall without one — and a value the writer could build
    /// and the reader could not accept would be a record that stops
    /// reconciliation reaching *any* session, since `load_all` fails whole.
    pub fn new(
        interfaces: Vec<PfInterface>,
        install_phase: PfInstallPhase,
    ) -> Result<Self, NoInterfacesError> {
        if interfaces.is_empty() {
            return Err(NoInterfacesError);
        }
        Ok(Self {
            interfaces,
            install_phase,
        })
    }

    pub fn interfaces(&self) -> &[PfInterface] {
        &self.interfaces
    }

    pub fn install_phase(&self) -> PfInstallPhase {
        self.install_phase
    }
}

/// What the guest's `security-ready` record told the host.
///
/// The ABI is the initializer's, read from the record it published — not the
/// image label Stage D's admission checked. They are held equal by
/// construction (`crates/writ-guest-init` compiles both from one file), so
/// recording the one the *running guest* announced is what makes a
/// disagreement visible rather than assumed away.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GuestFacts {
    isolation_abi: u32,
}

impl GuestFacts {
    pub fn new(isolation_abi: u32) -> Self {
        Self { isolation_abi }
    }

    pub fn isolation_abi(self) -> u32 {
        self.isolation_abi
    }
}

/// What a persisted record says about a locked session: the phase it reached,
/// and exactly the facts that phase implies.
///
/// One variant per [`LockedPhase`], so there is no record that claims to have
/// released a workload without naming the interfaces its anchor was scoped to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LockedLifecycle {
    Claimed,
    NetworkValidated,
    AgentVmStarted,
    FinalFirewallInstalled(FirewallFacts),
    GuestSecurityLocked(FirewallFacts, GuestFacts),
    ReleaseAttempted(FirewallFacts, GuestFacts),
    WorkloadReleased(FirewallFacts, GuestFacts),
}

impl LockedLifecycle {
    pub fn phase(&self) -> LockedPhase {
        match self {
            Self::Claimed => LockedPhase::Claimed,
            Self::NetworkValidated => LockedPhase::NetworkValidated,
            Self::AgentVmStarted => LockedPhase::AgentVmStarted,
            Self::FinalFirewallInstalled(_) => LockedPhase::FinalFirewallInstalled,
            Self::GuestSecurityLocked(_, _) => LockedPhase::GuestSecurityLocked,
            Self::ReleaseAttempted(_, _) => LockedPhase::ReleaseAttempted,
            Self::WorkloadReleased(_, _) => LockedPhase::WorkloadReleased,
        }
    }

    /// The firewall facts, for the phases that have them.
    pub fn firewall(&self) -> Option<&FirewallFacts> {
        match self {
            Self::Claimed | Self::NetworkValidated | Self::AgentVmStarted => None,
            Self::FinalFirewallInstalled(firewall)
            | Self::GuestSecurityLocked(firewall, _)
            | Self::ReleaseAttempted(firewall, _)
            | Self::WorkloadReleased(firewall, _) => Some(firewall),
        }
    }

    /// The snapshot this one must have been advanced *from*, or `None` for
    /// the first phase.
    ///
    /// This is what "advance" means, as one value rather than as a list of
    /// things to check. [`LockedLifecycle`] is publicly constructible, so the
    /// store is the only thing between a caller and a record; comparing the
    /// rewound snapshot with the recorded one asks, in a single equality,
    /// every question a field-by-field guard would have to remember to ask —
    /// that the step is the next one, that the interfaces are the ones the
    /// install loaded, that the ABI is the one the guest announced. A phase
    /// that later gains a fact is covered without touching the store, because
    /// the fact is part of the value being compared.
    pub fn previous(&self) -> Option<LockedLifecycle> {
        match self {
            Self::Claimed => None,
            Self::NetworkValidated => Some(Self::Claimed),
            Self::AgentVmStarted => Some(Self::NetworkValidated),
            Self::FinalFirewallInstalled(_) => Some(Self::AgentVmStarted),
            Self::GuestSecurityLocked(firewall, _) => {
                Some(Self::FinalFirewallInstalled(firewall.clone()))
            }
            Self::ReleaseAttempted(firewall, guest) => {
                Some(Self::GuestSecurityLocked(firewall.clone(), *guest))
            }
            Self::WorkloadReleased(firewall, guest) => {
                Some(Self::ReleaseAttempted(firewall.clone(), *guest))
            }
        }
    }

    /// The guest facts, for the phases that have them.
    pub fn guest(&self) -> Option<GuestFacts> {
        match self {
            Self::Claimed
            | Self::NetworkValidated
            | Self::AgentVmStarted
            | Self::FinalFirewallInstalled(_) => None,
            Self::GuestSecurityLocked(_, guest)
            | Self::ReleaseAttempted(_, guest)
            | Self::WorkloadReleased(_, guest) => Some(*guest),
        }
    }
}

// --- the typestates ---------------------------------------------------------
//
// Each holds the facts proven by the time it exists, and each is built only
// from its predecessor. The unit fields are private, so this module is the one
// place that can mint one — and it only ever does so from the value before it.

/// The session id and subnet are allocated; nothing exists on the host yet.
///
/// The one phase with a public constructor, because it is where a start
/// begins. Everything after it is reachable only by going through it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claimed(());

/// The network exists and validated, and the bootstrap anchor is loaded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkValidated(());

/// The agent VM is running its initializer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmStarted(());

/// The interface-scoped anchor is installed and read back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalFirewallInstalled(FirewallFacts);

/// The guest published its `security-ready` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestSecurityLocked(FirewallFacts, GuestFacts);

/// The release signal is about to be sent, and this has been written down.
///
/// Constructible only from [`GuestSecurityLocked`], which is constructible
/// only from [`FinalFirewallInstalled`]: the design's rule that a workload is
/// never released without both is enforced by the compiler, not by review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseAttempted(FirewallFacts, GuestFacts);

/// The release signal was sent and reported success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadReleased(FirewallFacts, GuestFacts);

impl Claimed {
    /// Begin a locked session's start.
    pub fn new() -> Self {
        Self(())
    }

    /// The network was created, inspected and validated, and the bootstrap
    /// anchor is loaded.
    pub fn network_validated(self) -> NetworkValidated {
        NetworkValidated(())
    }

    pub fn lifecycle(&self) -> LockedLifecycle {
        LockedLifecycle::Claimed
    }
}

impl Default for Claimed {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkValidated {
    /// The agent VM was started and its initializer is holding for release.
    pub fn agent_vm_started(self) -> AgentVmStarted {
        AgentVmStarted(())
    }

    pub fn lifecycle(&self) -> LockedLifecycle {
        LockedLifecycle::NetworkValidated
    }
}

impl AgentVmStarted {
    /// The interface-scoped anchor replaced the bootstrap one, and the helper
    /// reported which interfaces it was resolved to and which install phase it
    /// completed.
    pub fn final_firewall_installed(self, firewall: FirewallFacts) -> FinalFirewallInstalled {
        FinalFirewallInstalled(firewall)
    }

    pub fn lifecycle(&self) -> LockedLifecycle {
        LockedLifecycle::AgentVmStarted
    }
}

impl FinalFirewallInstalled {
    /// The guest initializer's `security-ready` record was read from the
    /// host's own bounded `container logs` channel.
    pub fn guest_security_locked(self, guest: GuestFacts) -> GuestSecurityLocked {
        GuestSecurityLocked(self.0, guest)
    }

    pub fn firewall(&self) -> &FirewallFacts {
        &self.0
    }

    pub fn lifecycle(&self) -> LockedLifecycle {
        LockedLifecycle::FinalFirewallInstalled(self.0.clone())
    }
}

impl GuestSecurityLocked {
    /// Declare the intent to release.
    ///
    /// Deliberately *not* the thing that sends the signal: sending it requires
    /// a [`ReleaseSignal`](crate::agent_vm_lifecycle::ReleaseSignal), which
    /// only the state store mints, and only once this value's
    /// [`Self::lifecycle`] has been persisted.
    pub fn release_attempted(self) -> ReleaseAttempted {
        ReleaseAttempted(self.0, self.1)
    }

    pub fn firewall(&self) -> &FirewallFacts {
        &self.0
    }

    pub fn guest(&self) -> GuestFacts {
        self.1
    }

    pub fn lifecycle(&self) -> LockedLifecycle {
        LockedLifecycle::GuestSecurityLocked(self.0.clone(), self.1)
    }
}

impl ReleaseAttempted {
    /// The signal was sent and reported success.
    pub fn workload_released(self) -> WorkloadReleased {
        WorkloadReleased(self.0, self.1)
    }

    pub fn firewall(&self) -> &FirewallFacts {
        &self.0
    }

    pub fn guest(&self) -> GuestFacts {
        self.1
    }

    pub fn lifecycle(&self) -> LockedLifecycle {
        LockedLifecycle::ReleaseAttempted(self.0.clone(), self.1)
    }
}

impl WorkloadReleased {
    pub fn firewall(&self) -> &FirewallFacts {
        &self.0
    }

    pub fn guest(&self) -> GuestFacts {
        self.1
    }

    pub fn lifecycle(&self) -> LockedLifecycle {
        LockedLifecycle::WorkloadReleased(self.0.clone(), self.1)
    }
}

#[cfg(test)]
mod tests;
