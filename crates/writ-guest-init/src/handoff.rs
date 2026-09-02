//! The ordered steps of the one-way handoff, and a model of the privilege
//! rules they run under.
//!
//! The steps are data ([`HandoffStep`]); the interpreter that performs them
//! is a separate Linux-only binary. Their order is the whole point. Dropping
//! the bounding set needs `CAP_SETPCAP`, and changing UID discards it;
//! `setgroups` and `setresgid` need `CAP_SETGID`, and changing UID discards
//! that too. So the privileged steps must all precede the identity change,
//! and an earlier draft of this design got that wrong in prose. Rather than
//! trust prose again, [`simulate`] is a small reference model of those rules:
//! it accepts a plan iff the kernel would let every step succeed *and* the
//! plan ends, exactly once, in a verification that finds the locked state.
//! The tests hold the canonical plan and every precedence rule against it,
//! over plans that reorder, drop, and duplicate the canonical steps.

use std::collections::BTreeSet;

use crate::capability_argv::TemporaryCapability;
use crate::{LOCKED_GID, LOCKED_UID};

/// A Linux network interface name, as the guest sees it.
///
/// Bounded to `IFNAMSIZ - 1` bytes with no separator or whitespace, because
/// it is spliced into a `/proc/sys/net/ipv6/conf/<name>/...` path.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct InterfaceName(String);

/// Why a string is not an interface name.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InterfaceNameError {
    #[error("interface name is empty")]
    Empty,
    #[error("interface name {0:?} is longer than 15 bytes")]
    TooLong(String),
    #[error("interface name {0:?} contains a path separator, whitespace, or control byte")]
    ForbiddenByte(String),
    #[error("interface name {0:?} is a path component that does not name an interface")]
    DotName(String),
}

impl InterfaceName {
    /// `IFNAMSIZ - 1`.
    pub const MAX_LEN: usize = 15;

    pub fn new(name: impl Into<String>) -> Result<Self, InterfaceNameError> {
        let name = name.into();
        if name.is_empty() {
            return Err(InterfaceNameError::Empty);
        }
        if name.len() > Self::MAX_LEN {
            return Err(InterfaceNameError::TooLong(name));
        }
        if name == "." || name == ".." {
            return Err(InterfaceNameError::DotName(name));
        }
        if name
            .bytes()
            .any(|b| b == b'/' || b == b'\0' || b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(InterfaceNameError::ForbiddenByte(name));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Which `/proc/sys/net/ipv6/conf/<scope>/` tree a sysctl is written under.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum SysctlScope {
    /// `all`: applies to every existing interface.
    All,
    /// `default`: applies to interfaces created later.
    Default,
    /// One named interface, because `all` does not reliably reach every
    /// per-interface value on every kernel.
    Interface(InterfaceName),
}

impl SysctlScope {
    /// The path component under `conf/`.
    pub fn path_component(&self) -> &str {
        match self {
            Self::All => "all",
            Self::Default => "default",
            Self::Interface(name) => name.as_str(),
        }
    }
}

/// An IPv6 sysctl the handoff writes.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum Ipv6Sysctl {
    AcceptRa,
    Autoconf,
    RouterSolicitations,
    DisableIpv6,
}

impl Ipv6Sysctl {
    /// The order they are written in: the acquisition paths are closed
    /// first, then IPv6 is switched off, which also flushes existing
    /// addresses.
    pub const ALL: [Self; 4] = [
        Self::AcceptRa,
        Self::Autoconf,
        Self::RouterSolicitations,
        Self::DisableIpv6,
    ];

    /// The file name under the scope directory.
    pub fn file_name(self) -> &'static str {
        match self {
            Self::AcceptRa => "accept_ra",
            Self::Autoconf => "autoconf",
            Self::RouterSolicitations => "router_solicitations",
            Self::DisableIpv6 => "disable_ipv6",
        }
    }

    /// The value the locked profile writes.
    pub fn locked_value(self) -> &'static str {
        match self {
            Self::AcceptRa | Self::Autoconf | Self::RouterSolicitations => "0",
            Self::DisableIpv6 => "1",
        }
    }

    /// Whether a missing sysctl file is a handoff failure. The three
    /// acquisition sysctls are written "where present" (not every kernel
    /// exposes every one for every scope); `disable_ipv6` must exist, because
    /// it is what the verification step relies on.
    pub fn must_exist(self) -> bool {
        matches!(self, Self::DisableIpv6)
    }
}

/// A directory the initializer hands to the locked identity.
///
/// Named rather than pathed: the official image fixes the paths, and the
/// interpreter maps these onto them. Nothing outside this set is chowned.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum OwnedDirectory {
    /// The guest runtime directory (`/run/writ-agent-vm` today).
    Runtime,
    /// The locked identity's home.
    Home,
    /// The workspace the agent runs in.
    Workspace,
    /// The writable, private Nix store.
    NixStore,
}

impl OwnedDirectory {
    pub const ALL: [Self; 4] = [Self::Runtime, Self::Home, Self::Workspace, Self::NixStore];
}

/// One step of the handoff. The interpreter performs them in order and stops
/// at the first failure; the workload is never started after a failure.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum HandoffStep {
    /// Create one of the fixed directories if it is absent (`/run` is a
    /// fresh tmpfs at launch, so the runtime directory never pre-exists),
    /// then `chown -R LOCKED_UID:LOCKED_GID` it. One step, because a
    /// directory created for the locked identity is never meant to be left
    /// root-owned even for an instant.
    PrepareOwnedDirectory(OwnedDirectory),
    /// Write one IPv6 sysctl under one scope.
    WriteSysctl {
        scope: SysctlScope,
        sysctl: Ipv6Sysctl,
    },
    /// Assert no non-loopback IPv6 address and no IPv6 route exists.
    VerifyNoIpv6,
    /// `prctl(PR_CAPBSET_DROP)` for every capability. Needs `CAP_SETPCAP`.
    DropBoundingSet,
    /// Clear the inheritable and ambient sets. Needs no capability.
    ClearInheritableAndAmbient,
    /// `prctl(PR_SET_NO_NEW_PRIVS, 1)`. Needs no capability.
    SetNoNewPrivs,
    /// `setgroups(0, NULL)`. Needs `CAP_SETGID`.
    ClearSupplementaryGroups,
    /// `setresgid(g, g, g)`. Needs `CAP_SETGID`.
    SetResgid(u32),
    /// `setresuid(u, u, u)` with `KEEPCAPS` off, so leaving UID 0 clears the
    /// permitted and effective sets. Needs `CAP_SETUID`, and is the last step
    /// that needs anything.
    SetResuid(u32),
    /// Re-read identity, every capability set, `NoNewPrivs`, and the IPv6
    /// posture, and refuse to continue unless all are as the locked identity
    /// requires.
    VerifyLockedIdentity,
}

/// The canonical handoff for a guest with the given interfaces present.
///
/// The interface list is what the initializer enumerated at start; `all` and
/// `default` are always written, and each named interface additionally, so a
/// per-interface value `all` does not reach is still set.
pub fn handoff_plan(interfaces: &[InterfaceName]) -> Vec<HandoffStep> {
    let mut steps = Vec::new();
    for dir in OwnedDirectory::ALL {
        steps.push(HandoffStep::PrepareOwnedDirectory(dir));
    }
    let scopes: Vec<SysctlScope> = [SysctlScope::All, SysctlScope::Default]
        .into_iter()
        .chain(interfaces.iter().cloned().map(SysctlScope::Interface))
        .collect();
    for sysctl in Ipv6Sysctl::ALL {
        for scope in &scopes {
            steps.push(HandoffStep::WriteSysctl {
                scope: scope.clone(),
                sysctl,
            });
        }
    }
    steps.push(HandoffStep::VerifyNoIpv6);
    steps.push(HandoffStep::DropBoundingSet);
    steps.push(HandoffStep::ClearInheritableAndAmbient);
    steps.push(HandoffStep::SetNoNewPrivs);
    steps.push(HandoffStep::ClearSupplementaryGroups);
    steps.push(HandoffStep::SetResgid(LOCKED_GID));
    steps.push(HandoffStep::SetResuid(LOCKED_UID));
    steps.push(HandoffStep::VerifyLockedIdentity);
    steps
}

/// A reference model of the process the handoff runs in.
///
/// Deliberately small: UID, GID, the five capability sets restricted to the
/// temporary capabilities (nothing else is ever held), `NoNewPrivs`, and
/// enough bookkeeping to know whether the IPv6 and ownership steps have been
/// done. It encodes the Linux rules the handoff depends on:
///
/// - creating and `chown`ing a directory for another identity needs
///   effective `CAP_CHOWN` (creation as UID 0 needs nothing further);
/// - writing a net sysctl needs UID 0 (the file is root-writable) and
///   effective `CAP_NET_ADMIN`;
/// - dropping the bounding set needs effective `CAP_SETPCAP`;
/// - `setgroups` and `setresgid` need effective `CAP_SETGID`;
/// - `setresuid` needs effective `CAP_SETUID`, and leaving UID 0 with
///   `KEEPCAPS` off clears the permitted, effective, and ambient sets;
/// - lowering the inheritable or ambient set, and setting `NoNewPrivs`, need
///   nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessModel {
    uid: u32,
    gid: u32,
    supplementary_groups_cleared: bool,
    effective: BTreeSet<TemporaryCapability>,
    permitted: BTreeSet<TemporaryCapability>,
    inheritable: BTreeSet<TemporaryCapability>,
    ambient: BTreeSet<TemporaryCapability>,
    bounding: BTreeSet<TemporaryCapability>,
    no_new_privs: bool,
    disable_ipv6_written: BTreeSet<SysctlScope>,
    ipv6_verified: bool,
    owned: BTreeSet<OwnedDirectory>,
    /// Set by [`HandoffStep::VerifyLockedIdentity`]. The verification is the
    /// last thing the initializer does before parking, so no step may follow
    /// it in the model, and a plan that never sets this is not a handoff.
    handed_off: bool,
}

impl ProcessModel {
    /// PID 1 as `container run` with the locked argv profile starts it: UID 0,
    /// the temporary capabilities in the effective, permitted, and bounding
    /// sets.
    ///
    /// The profile pins nothing about the inheritable and ambient sets (what
    /// a launcher puts there varies by runtime), so the model takes the worst
    /// case and starts them full. That is what makes
    /// [`HandoffStep::ClearInheritableAndAmbient`] load-bearing rather than
    /// decorative: a plan without it leaves the inheritable set non-empty,
    /// and the final verification refuses it, as the real one would if the
    /// launcher had populated the set.
    pub fn at_launch() -> Self {
        let temporary: BTreeSet<_> = TemporaryCapability::ALL.into_iter().collect();
        Self {
            uid: 0,
            gid: 0,
            supplementary_groups_cleared: false,
            effective: temporary.clone(),
            permitted: temporary.clone(),
            inheritable: temporary.clone(),
            ambient: temporary.clone(),
            bounding: temporary,
            no_new_privs: false,
            disable_ipv6_written: BTreeSet::new(),
            ipv6_verified: false,
            owned: BTreeSet::new(),
            handed_off: false,
        }
    }

    /// Whether the model is in the state the locked workload must run in.
    pub fn is_locked(&self, interfaces: &[InterfaceName]) -> Result<(), LockedStateViolation> {
        if self.uid != LOCKED_UID {
            return Err(LockedStateViolation::Uid(self.uid));
        }
        if self.gid != LOCKED_GID {
            return Err(LockedStateViolation::Gid(self.gid));
        }
        if !self.supplementary_groups_cleared {
            return Err(LockedStateViolation::SupplementaryGroups);
        }
        for (name, set) in [
            ("effective", &self.effective),
            ("permitted", &self.permitted),
            ("inheritable", &self.inheritable),
            ("ambient", &self.ambient),
            ("bounding", &self.bounding),
        ] {
            if !set.is_empty() {
                return Err(LockedStateViolation::CapabilitySetNotEmpty(name));
            }
        }
        if !self.no_new_privs {
            return Err(LockedStateViolation::NoNewPrivsUnset);
        }
        if !self.ipv6_verified {
            return Err(LockedStateViolation::Ipv6Unverified);
        }
        let mut required: BTreeSet<SysctlScope> = [SysctlScope::All, SysctlScope::Default].into();
        required.extend(interfaces.iter().cloned().map(SysctlScope::Interface));
        if let Some(missing) = required.difference(&self.disable_ipv6_written).next() {
            return Err(LockedStateViolation::DisableIpv6NotWritten(missing.clone()));
        }
        if let Some(dir) = OwnedDirectory::ALL.iter().find(|d| !self.owned.contains(d)) {
            return Err(LockedStateViolation::DirectoryNotOwned(*dir));
        }
        Ok(())
    }
}

/// Why a model state is not the locked state.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LockedStateViolation {
    #[error("uid is {0}, not {LOCKED_UID}")]
    Uid(u32),
    #[error("gid is {0}, not {LOCKED_GID}")]
    Gid(u32),
    #[error("supplementary groups were not cleared")]
    SupplementaryGroups,
    #[error("the {0} capability set is not empty")]
    CapabilitySetNotEmpty(&'static str),
    #[error("NoNewPrivs is not set")]
    NoNewPrivsUnset,
    #[error("IPv6 absence was not verified")]
    Ipv6Unverified,
    #[error("disable_ipv6 was not written for scope {}", .0.path_component())]
    DisableIpv6NotWritten(SysctlScope),
    #[error("{0:?} was not handed to the locked identity")]
    DirectoryNotOwned(OwnedDirectory),
}

/// Why a step could not run in the model.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StepRefusal {
    #[error("needs effective {0:?}, which the process no longer holds")]
    MissingCapability(TemporaryCapability),
    #[error("needs uid 0, but the process is uid {0}")]
    NotRoot(u32),
    #[error("cannot verify IPv6 absence before disable_ipv6 is written for every scope")]
    Ipv6NotYetDisabled,
    #[error("the locked identity is not established: {0}")]
    NotLocked(#[from] LockedStateViolation),
    /// The plan ended without ever reaching
    /// [`HandoffStep::VerifyLockedIdentity`]. Reported at index
    /// `steps.len()`, the step that is missing.
    #[error("the plan does not end with the locked-identity verification")]
    NotTerminal,
    /// A step came after [`HandoffStep::VerifyLockedIdentity`], which is the
    /// last thing the initializer does before parking. A second verification
    /// is refused the same way.
    #[error("the locked-identity verification already ran; nothing runs after it")]
    AfterVerification,
}

/// The step at which a simulation stopped, and why.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("step {index} ({step:?}) refused: {reason}")]
pub struct SimulationFailure {
    pub index: usize,
    pub step: HandoffStep,
    pub reason: StepRefusal,
}

/// Run the steps against the model from launch, stopping at the first the
/// kernel rules would refuse. Success means every step ran and the model
/// ended handed off: [`HandoffStep::VerifyLockedIdentity`] ran exactly once,
/// as the last step, and found the locked state. A plan that runs out
/// without verifying, verifies and then keeps going, verifies twice, or
/// omits a step the verification depends on is not a handoff. The
/// verification sees every mandatory step because the model starts with
/// every set the handoff must empty non-empty (see
/// [`ProcessModel::at_launch`]), so omitting any of them leaves a trace.
pub fn simulate(
    steps: &[HandoffStep],
    interfaces: &[InterfaceName],
) -> Result<ProcessModel, SimulationFailure> {
    let mut model = ProcessModel::at_launch();
    for (index, step) in steps.iter().enumerate() {
        model
            .apply(step, interfaces)
            .map_err(|reason| SimulationFailure {
                index,
                step: step.clone(),
                reason,
            })?;
    }
    if model.handed_off {
        Ok(model)
    } else {
        Err(SimulationFailure {
            index: steps.len(),
            step: HandoffStep::VerifyLockedIdentity,
            reason: StepRefusal::NotTerminal,
        })
    }
}

impl ProcessModel {
    fn require(&self, capability: TemporaryCapability) -> Result<(), StepRefusal> {
        if self.effective.contains(&capability) {
            Ok(())
        } else {
            Err(StepRefusal::MissingCapability(capability))
        }
    }

    fn apply(
        &mut self,
        step: &HandoffStep,
        interfaces: &[InterfaceName],
    ) -> Result<(), StepRefusal> {
        if self.handed_off {
            return Err(StepRefusal::AfterVerification);
        }
        match step {
            HandoffStep::PrepareOwnedDirectory(dir) => {
                self.require(TemporaryCapability::Chown)?;
                self.owned.insert(*dir);
            }
            HandoffStep::WriteSysctl { scope, sysctl } => {
                if self.uid != 0 {
                    return Err(StepRefusal::NotRoot(self.uid));
                }
                self.require(TemporaryCapability::NetAdmin)?;
                if *sysctl == Ipv6Sysctl::DisableIpv6 {
                    self.disable_ipv6_written.insert(scope.clone());
                }
            }
            HandoffStep::VerifyNoIpv6 => {
                let mut required: BTreeSet<SysctlScope> =
                    [SysctlScope::All, SysctlScope::Default].into();
                required.extend(interfaces.iter().cloned().map(SysctlScope::Interface));
                if !required.is_subset(&self.disable_ipv6_written) {
                    return Err(StepRefusal::Ipv6NotYetDisabled);
                }
                self.ipv6_verified = true;
            }
            HandoffStep::DropBoundingSet => {
                self.require(TemporaryCapability::Setpcap)?;
                self.bounding.clear();
            }
            HandoffStep::ClearInheritableAndAmbient => {
                self.inheritable.clear();
                self.ambient.clear();
            }
            HandoffStep::SetNoNewPrivs => {
                self.no_new_privs = true;
            }
            HandoffStep::ClearSupplementaryGroups => {
                self.require(TemporaryCapability::Setgid)?;
                self.supplementary_groups_cleared = true;
            }
            HandoffStep::SetResgid(gid) => {
                if self.gid != *gid {
                    self.require(TemporaryCapability::Setgid)?;
                }
                self.gid = *gid;
            }
            HandoffStep::SetResuid(uid) => {
                if self.uid != *uid {
                    self.require(TemporaryCapability::Setuid)?;
                }
                let leaving_root = self.uid == 0 && *uid != 0;
                self.uid = *uid;
                if leaving_root {
                    // KEEPCAPS is off: the transition clears these.
                    self.permitted.clear();
                    self.effective.clear();
                    self.ambient.clear();
                }
            }
            HandoffStep::VerifyLockedIdentity => {
                self.is_locked(interfaces)?;
                self.handed_off = true;
            }
        }
        Ok(())
    }
}

/// The precedence rules the handoff order must satisfy, stated directly.
///
/// This is the second description of the same constraint as [`simulate`],
/// and the tests hold the two equivalent: an order is accepted by the model
/// iff it has no violation here. Each rule is one sentence a reviewer can
/// check against the design.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrecedenceViolation {
    /// A step that needs a capability or UID 0 came after the identity
    /// change, which discards both. Preparing a directory, writing a sysctl,
    /// dropping the bounding set, and clearing groups always need one;
    /// `setresgid`/`setresuid` need one only when they actually change the
    /// id, since the kernel lets any process re-assert the ids it holds.
    PrivilegedStepAfterIdentityChange(HandoffStep),
    /// IPv6 absence was verified before `disable_ipv6` was written for every
    /// scope.
    VerifyNoIpv6BeforeDisable,
    /// The final verification is not the last step, is not the only one, a
    /// step it depends on is missing, or the UID or GID the plan ends with
    /// is not the locked one.
    VerifyLockedIdentityNotLast,
}

/// Every precedence rule the given order breaks.
pub fn precedence_violations(
    steps: &[HandoffStep],
    interfaces: &[InterfaceName],
) -> Vec<PrecedenceViolation> {
    let mut violations = Vec::new();

    let (mut uid, mut gid) = (0u32, 0u32);
    let mut identity_changed = false;
    for step in steps {
        let privileged = match step {
            HandoffStep::PrepareOwnedDirectory(_)
            | HandoffStep::WriteSysctl { .. }
            | HandoffStep::DropBoundingSet
            | HandoffStep::ClearSupplementaryGroups => true,
            HandoffStep::SetResgid(g) => *g != gid,
            HandoffStep::SetResuid(u) => *u != uid,
            HandoffStep::VerifyNoIpv6
            | HandoffStep::ClearInheritableAndAmbient
            | HandoffStep::SetNoNewPrivs
            | HandoffStep::VerifyLockedIdentity => false,
        };
        if identity_changed && privileged {
            violations.push(PrecedenceViolation::PrivilegedStepAfterIdentityChange(
                step.clone(),
            ));
        }
        match step {
            HandoffStep::SetResgid(g) => gid = *g,
            HandoffStep::SetResuid(u) => {
                if uid == 0 && *u != 0 {
                    identity_changed = true;
                }
                uid = *u;
            }
            _ => {}
        }
    }

    let mut required: BTreeSet<SysctlScope> = [SysctlScope::All, SysctlScope::Default].into();
    required.extend(interfaces.iter().cloned().map(SysctlScope::Interface));
    let mut written = BTreeSet::new();
    for step in steps {
        match step {
            HandoffStep::WriteSysctl {
                scope,
                sysctl: Ipv6Sysctl::DisableIpv6,
            } => {
                written.insert(scope.clone());
            }
            HandoffStep::VerifyNoIpv6 if !required.is_subset(&written) => {
                violations.push(PrecedenceViolation::VerifyNoIpv6BeforeDisable);
                break;
            }
            _ => {}
        }
    }

    let is_last_and_complete = steps.last() == Some(&HandoffStep::VerifyLockedIdentity)
        && steps[..steps.len() - 1]
            .iter()
            .all(|s| *s != HandoffStep::VerifyLockedIdentity)
        && {
            // Everything the verification checks must have happened.
            let has = |p: &dyn Fn(&HandoffStep) -> bool| steps.iter().any(p);
            OwnedDirectory::ALL
                .iter()
                .all(|d| has(&|s| *s == HandoffStep::PrepareOwnedDirectory(*d)))
                && has(&|s| *s == HandoffStep::VerifyNoIpv6)
                && has(&|s| *s == HandoffStep::DropBoundingSet)
                && has(&|s| *s == HandoffStep::ClearInheritableAndAmbient)
                && has(&|s| *s == HandoffStep::SetNoNewPrivs)
                && has(&|s| *s == HandoffStep::ClearSupplementaryGroups)
                // The identity the plan *ends* with, not whether some step
                // once set it: a later `setresgid` can move it again.
                && gid == LOCKED_GID
                && uid == LOCKED_UID
        };
    if !is_last_and_complete {
        violations.push(PrecedenceViolation::VerifyLockedIdentityNotLast);
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_interface_name() -> impl Strategy<Value = InterfaceName> {
        // Built to be valid rather than filtered: a letter-led token of 1..=15
        // ASCII letters/digits.
        "[a-z][a-z0-9]{0,14}".prop_map(|s| InterfaceName::new(s).unwrap())
    }

    fn arb_interfaces() -> impl Strategy<Value = Vec<InterfaceName>> {
        proptest::collection::btree_set(arb_interface_name(), 0..4)
            .prop_map(|set| set.into_iter().collect())
    }

    /// The canonical plan, spelled out for one interface, so a reader can
    /// compare it with the design's numbered steps without running anything.
    #[test]
    fn the_canonical_plan_matches_the_design() {
        let eth0 = InterfaceName::new("eth0").unwrap();
        let plan = handoff_plan(std::slice::from_ref(&eth0));
        let ws = |scope: SysctlScope, sysctl| HandoffStep::WriteSysctl { scope, sysctl };
        let iface = || SysctlScope::Interface(eth0.clone());
        let expected = vec![
            HandoffStep::PrepareOwnedDirectory(OwnedDirectory::Runtime),
            HandoffStep::PrepareOwnedDirectory(OwnedDirectory::Home),
            HandoffStep::PrepareOwnedDirectory(OwnedDirectory::Workspace),
            HandoffStep::PrepareOwnedDirectory(OwnedDirectory::NixStore),
            ws(SysctlScope::All, Ipv6Sysctl::AcceptRa),
            ws(SysctlScope::Default, Ipv6Sysctl::AcceptRa),
            ws(iface(), Ipv6Sysctl::AcceptRa),
            ws(SysctlScope::All, Ipv6Sysctl::Autoconf),
            ws(SysctlScope::Default, Ipv6Sysctl::Autoconf),
            ws(iface(), Ipv6Sysctl::Autoconf),
            ws(SysctlScope::All, Ipv6Sysctl::RouterSolicitations),
            ws(SysctlScope::Default, Ipv6Sysctl::RouterSolicitations),
            ws(iface(), Ipv6Sysctl::RouterSolicitations),
            ws(SysctlScope::All, Ipv6Sysctl::DisableIpv6),
            ws(SysctlScope::Default, Ipv6Sysctl::DisableIpv6),
            ws(iface(), Ipv6Sysctl::DisableIpv6),
            HandoffStep::VerifyNoIpv6,
            HandoffStep::DropBoundingSet,
            HandoffStep::ClearInheritableAndAmbient,
            HandoffStep::SetNoNewPrivs,
            HandoffStep::ClearSupplementaryGroups,
            HandoffStep::SetResgid(LOCKED_GID),
            HandoffStep::SetResuid(LOCKED_UID),
            HandoffStep::VerifyLockedIdentity,
        ];
        assert_eq!(plan, expected);
    }

    /// The mistake an earlier draft of the design made in prose: lose the
    /// set-ID capabilities before the calls that need them. Here it is the
    /// smallest version, `setgroups` after `setresuid`. The model refuses it
    /// at `setgroups` for want of `CAP_SETGID`, which is the `EPERM` the
    /// initializer would have hit inside a VM.
    #[test]
    fn dropping_setgid_before_setgroups_cannot_complete() {
        let mut steps = handoff_plan(&[]);
        let setgroups = steps
            .iter()
            .position(|s| *s == HandoffStep::ClearSupplementaryGroups)
            .unwrap();
        let moved = steps.remove(setgroups);
        let resuid = steps
            .iter()
            .position(|s| matches!(s, HandoffStep::SetResuid(_)))
            .unwrap();
        steps.insert(resuid + 1, moved);
        let failure = simulate(&steps, &[]).expect_err("must not complete");
        assert_eq!(failure.step, HandoffStep::ClearSupplementaryGroups);
        assert_eq!(
            failure.reason,
            StepRefusal::MissingCapability(TemporaryCapability::Setgid)
        );
    }

    #[test]
    fn interface_names_are_bounded_and_path_safe() {
        assert!(InterfaceName::new("eth0").is_ok());
        assert!(InterfaceName::new("a".repeat(15)).is_ok());
        assert_eq!(
            InterfaceName::new("a".repeat(16)),
            Err(InterfaceNameError::TooLong("a".repeat(16)))
        );
        assert_eq!(InterfaceName::new(""), Err(InterfaceNameError::Empty));
        for bad in ["eth 0", "eth/0", "eth\n0", "eth\u{0}0"] {
            assert!(
                matches!(
                    InterfaceName::new(bad),
                    Err(InterfaceNameError::ForbiddenByte(_))
                ),
                "{bad:?}"
            );
        }
        for dot in [".", ".."] {
            assert!(matches!(
                InterfaceName::new(dot),
                Err(InterfaceNameError::DotName(_))
            ));
        }
    }

    /// One edit to a plan. A uniformly random permutation almost always
    /// violates something, so some kinds are small: a few adjacent swaps, or
    /// one step relocated, dropped, or duplicated, which keeps the accepting
    /// side of the agreement property populated (dropping an `accept_ra`
    /// write, say, or duplicating a no-op, is still a handoff). Drop and
    /// Duplicate are what the first generator lacked: it only ever permuted
    /// the canonical plan, so a model that checked the last step alone
    /// agreed with the rules on everything it was shown.
    ///
    /// Indices are reduced modulo the plan's current length when applied, so
    /// a sequence of edits never goes out of bounds and none is filtered.
    #[derive(Clone, Debug)]
    enum Mutation {
        Shuffle(Vec<usize>),
        AdjacentSwaps(Vec<usize>),
        /// Take the step at one position and re-insert it at another,
        /// leaving everything else in order: a single step far out of place,
        /// such as an unprivileged step moved after the final verification,
        /// or the verification moved into the middle.
        Relocate {
            from: usize,
            to: usize,
        },
        /// Remove the step at a position.
        Drop(usize),
        /// Insert a copy of the step at `from` so that it lands at `to`.
        Duplicate {
            from: usize,
            to: usize,
        },
        /// Rewrite the id argument of the `nth` `setresgid`/`setresuid` step
        /// (modulo how many there are; a no-op if there are none). The only
        /// edit that reaches ids other than the locked one: back to 0, or to
        /// some other identity entirely.
        Retarget {
            nth: usize,
            id: u32,
        },
    }

    fn arb_mutation(len: usize) -> impl Strategy<Value = Mutation> {
        prop_oneof![
            Just((0..len).collect::<Vec<_>>())
                .prop_shuffle()
                .prop_map(Mutation::Shuffle),
            proptest::collection::vec(0..len.saturating_sub(1), 0..4)
                .prop_map(Mutation::AdjacentSwaps),
            (0..len, 0..len).prop_map(|(from, to)| Mutation::Relocate { from, to }),
            (0..len).prop_map(Mutation::Drop),
            (0..len, 0..=len).prop_map(|(from, to)| Mutation::Duplicate { from, to }),
            (
                0..len,
                prop_oneof![
                    Just(0u32),
                    Just(LOCKED_GID),
                    Just(LOCKED_GID + 1),
                    any::<u32>()
                ]
            )
                .prop_map(|(nth, id)| Mutation::Retarget { nth, id }),
        ]
    }

    /// Between one and three edits, applied in order.
    fn arb_mutations(len: usize) -> impl Strategy<Value = Vec<Mutation>> {
        proptest::collection::vec(arb_mutation(len), 1..=3)
    }

    fn apply_mutation(steps: &[HandoffStep], mutation: &Mutation) -> Vec<HandoffStep> {
        let len = steps.len();
        if len == 0 {
            return Vec::new();
        }
        let at = |i: usize| i % len;
        match mutation {
            Mutation::Shuffle(perm) => {
                // A permutation of the generator's length; over a shorter
                // plan, reduce and keep first occurrences, then append the
                // positions it missed, so the result is still a permutation.
                let mut seen = BTreeSet::new();
                let mut order: Vec<usize> = perm
                    .iter()
                    .map(|&i| at(i))
                    .filter(|i| seen.insert(*i))
                    .collect();
                order.extend((0..len).filter(|i| !seen.contains(i)));
                order.iter().map(|&i| steps[i].clone()).collect()
            }
            Mutation::AdjacentSwaps(swaps) => {
                let mut out = steps.to_vec();
                if len >= 2 {
                    for &i in swaps {
                        let i = i % (len - 1);
                        out.swap(i, i + 1);
                    }
                }
                out
            }
            Mutation::Relocate { from, to } => {
                let mut out = steps.to_vec();
                let step = out.remove(at(*from));
                out.insert(at(*to), step);
                out
            }
            Mutation::Drop(i) => {
                let mut out = steps.to_vec();
                out.remove(at(*i));
                out
            }
            Mutation::Duplicate { from, to } => {
                let mut out = steps.to_vec();
                let step = out[at(*from)].clone();
                out.insert(to % (len + 1), step);
                out
            }
            Mutation::Retarget { nth, id } => {
                let mut out = steps.to_vec();
                let id_steps: Vec<usize> = out
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| {
                        matches!(s, HandoffStep::SetResgid(_) | HandoffStep::SetResuid(_))
                    })
                    .map(|(i, _)| i)
                    .collect();
                if let Some(&i) = id_steps.get(nth % id_steps.len().max(1)) {
                    out[i] = match &out[i] {
                        HandoffStep::SetResgid(_) => HandoffStep::SetResgid(*id),
                        HandoffStep::SetResuid(_) => HandoffStep::SetResuid(*id),
                        _ => unreachable!(),
                    };
                }
                out
            }
        }
    }

    fn apply_mutations(steps: &[HandoffStep], mutations: &[Mutation]) -> Vec<HandoffStep> {
        mutations
            .iter()
            .fold(steps.to_vec(), |plan, m| apply_mutation(&plan, m))
    }

    /// The shapes the first generator never produced, spelled out: a plan
    /// that runs out before verifying, and one that verifies and keeps
    /// going. Both are refused by the model and by the rules.
    #[test]
    fn a_plan_that_does_not_end_in_verification_is_refused() {
        let failure = simulate(&[], &[]).expect_err("an empty plan is not a handoff");
        assert_eq!(failure.reason, StepRefusal::NotTerminal);
        assert_eq!(failure.index, 0);

        let mut unverified = handoff_plan(&[]);
        assert_eq!(unverified.pop(), Some(HandoffStep::VerifyLockedIdentity));
        let failure = simulate(&unverified, &[]).expect_err("the plan must verify");
        assert_eq!(failure.reason, StepRefusal::NotTerminal);
        assert_eq!(failure.index, unverified.len());
        assert!(
            precedence_violations(&unverified, &[])
                .contains(&PrecedenceViolation::VerifyLockedIdentityNotLast)
        );

        // A harmless step after the verification: the verification itself
        // passes (nothing it checks is missing), and the step after it is
        // refused for coming after the handoff.
        let mut early = handoff_plan(&[]);
        let harmless = HandoffStep::WriteSysctl {
            scope: SysctlScope::All,
            sysctl: Ipv6Sysctl::AcceptRa,
        };
        let at = early.iter().position(|s| *s == harmless).unwrap();
        let step = early.remove(at);
        early.push(step); // ..., VerifyLockedIdentity, WriteSysctl(all, accept_ra)
        let failure = simulate(&early, &[]).expect_err("verification must be last");
        assert_eq!(failure.reason, StepRefusal::AfterVerification);
        assert_eq!(failure.index, early.len() - 1);
        assert!(
            precedence_violations(&early, &[])
                .contains(&PrecedenceViolation::VerifyLockedIdentityNotLast)
        );
    }

    /// The second review's finding: a model that checked only the last step
    /// accepted a plan without `ClearInheritableAndAmbient` (nothing in the
    /// model showed its absence) and a plan ending in two verifications,
    /// while the rules refused both. Now the model refuses both too, and for
    /// the reason the kernel would.
    #[test]
    fn a_plan_missing_a_mandatory_step_or_verifying_twice_is_refused() {
        let mut without_clear = handoff_plan(&[]);
        let at = without_clear
            .iter()
            .position(|s| *s == HandoffStep::ClearInheritableAndAmbient)
            .unwrap();
        without_clear.remove(at);
        let failure = simulate(&without_clear, &[]).expect_err("the inheritable set survives");
        assert_eq!(failure.step, HandoffStep::VerifyLockedIdentity);
        assert_eq!(
            failure.reason,
            StepRefusal::NotLocked(LockedStateViolation::CapabilitySetNotEmpty("inheritable"))
        );
        assert!(
            precedence_violations(&without_clear, &[])
                .contains(&PrecedenceViolation::VerifyLockedIdentityNotLast)
        );

        let mut twice = handoff_plan(&[]);
        twice.push(HandoffStep::VerifyLockedIdentity);
        let failure = simulate(&twice, &[]).expect_err("verification runs once");
        assert_eq!(failure.reason, StepRefusal::AfterVerification);
        assert_eq!(failure.index, twice.len() - 1);
        assert!(
            precedence_violations(&twice, &[])
                .contains(&PrecedenceViolation::VerifyLockedIdentityNotLast)
        );
    }

    /// The third review's finding: the rules checked that a
    /// `SetResgid(LOCKED_GID)` step *exists*, so a later `SetResgid(0)`,
    /// still before the UID change and so still permitted, left the final
    /// GID unlocked while the rules saw nothing. The rules must judge the
    /// final identity, not the presence of a step that once set it.
    #[test]
    fn an_id_changed_back_after_being_locked_is_refused_by_both_oracles() {
        let plan = handoff_plan(&[]);
        let resgid = plan
            .iter()
            .position(|s| *s == HandoffStep::SetResgid(LOCKED_GID))
            .unwrap();
        let resuid = plan
            .iter()
            .position(|s| *s == HandoffStep::SetResuid(LOCKED_UID))
            .unwrap();
        for (label, step, at) in [
            ("gid back to 0", HandoffStep::SetResgid(0), resgid + 1),
            (
                "gid to another id",
                HandoffStep::SetResgid(LOCKED_GID + 1),
                resgid + 1,
            ),
            (
                "uid to another id",
                HandoffStep::SetResuid(LOCKED_UID + 1),
                resuid,
            ),
        ] {
            let mut steps = plan.clone();
            steps.insert(at, step);
            let simulated = simulate(&steps, &[]);
            let violations = precedence_violations(&steps, &[]);
            assert!(simulated.is_err(), "{label}: model accepted {steps:?}");
            assert!(!violations.is_empty(), "{label}: rules accepted {steps:?}");
        }
    }

    /// Every mandatory step is mandatory in *both* oracles: dropping any one
    /// of them from the canonical plan is refused by the model and by the
    /// rules. Spelled out per step so a regression names the step.
    #[test]
    fn every_mandatory_step_is_load_bearing_in_both_oracles() {
        let plan = handoff_plan(&[]);
        for (index, step) in plan.iter().enumerate() {
            let mut without = plan.clone();
            without.remove(index);
            let optional = matches!(
                step,
                HandoffStep::WriteSysctl {
                    sysctl: Ipv6Sysctl::AcceptRa
                        | Ipv6Sysctl::Autoconf
                        | Ipv6Sysctl::RouterSolicitations,
                    ..
                }
            );
            let simulated = simulate(&without, &[]);
            let violations = precedence_violations(&without, &[]);
            assert_eq!(
                simulated.is_ok(),
                optional,
                "dropping {step:?}: model says {:?}",
                simulated.as_ref().map(|_| ()).map_err(|e| e.to_string())
            );
            assert_eq!(
                violations.is_empty(),
                optional,
                "dropping {step:?}: rules say {violations:?}"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// The canonical plan completes for any interface set and leaves the
        /// model locked.
        #[test]
        fn the_canonical_plan_completes_and_locks(interfaces in arb_interfaces()) {
            let model = simulate(&handoff_plan(&interfaces), &interfaces)
                .unwrap_or_else(|e| panic!("{e}"));
            prop_assert_eq!(model.is_locked(&interfaces), Ok(()));
            prop_assert!(precedence_violations(&handoff_plan(&interfaces), &interfaces).is_empty());
        }

        /// The model and the precedence rules are two statements of one
        /// constraint: a plan runs to completion in the model iff it breaks
        /// no precedence rule. Over reorderings, drops, and duplications of
        /// the canonical plan, composed up to three deep.
        #[test]
        fn the_model_and_the_precedence_rules_agree(
            (interfaces, mutations) in arb_interfaces().prop_flat_map(|i| {
                let len = handoff_plan(&i).len();
                (Just(i), arb_mutations(len))
            }),
        ) {
            let steps = apply_mutations(&handoff_plan(&interfaces), &mutations);
            let simulated = simulate(&steps, &interfaces);
            let violations = precedence_violations(&steps, &interfaces);
            prop_assert_eq!(
                simulated.is_ok(),
                violations.is_empty(),
                "model says {:?} but precedence rules say {:?} for {:?} (from {:?})",
                simulated.as_ref().map(|_| ()).map_err(|e| e.to_string()),
                violations,
                steps,
                mutations
            );
        }

        /// A plan the model accepts is locked at the end, whatever was done
        /// to it: acceptance is never vacuous.
        #[test]
        fn an_accepted_plan_ends_locked(
            (interfaces, mutations) in arb_interfaces().prop_flat_map(|i| {
                let len = handoff_plan(&i).len();
                (Just(i), arb_mutations(len))
            }),
        ) {
            let steps = apply_mutations(&handoff_plan(&interfaces), &mutations);
            if let Ok(model) = simulate(&steps, &interfaces) {
                prop_assert_eq!(model.is_locked(&interfaces), Ok(()));
                prop_assert_eq!(steps.last(), Some(&HandoffStep::VerifyLockedIdentity));
                prop_assert_eq!(
                    steps.iter().filter(|s| **s == HandoffStep::VerifyLockedIdentity).count(),
                    1
                );
            }
        }
    }

    /// The agreement property must see both outcomes, and see them from
    /// each kind of edit, or it is only testing one half of the equivalence
    /// on the shapes that matter. Measured on the generator directly.
    #[test]
    fn the_mutation_generator_reaches_both_outcomes_for_every_kind() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(4000));
        // Per kind: (accepted, refused), for single-edit cases only, so each
        // count is attributable to its kind.
        let counts: [(std::cell::Cell<u32>, std::cell::Cell<u32>); 6] =
            std::array::from_fn(|_| (std::cell::Cell::new(0), std::cell::Cell::new(0)));
        let kind = |m: &Mutation| match m {
            Mutation::Shuffle(_) => 0,
            Mutation::AdjacentSwaps(_) => 1,
            Mutation::Relocate { .. } => 2,
            Mutation::Drop(_) => 3,
            Mutation::Duplicate { .. } => 4,
            Mutation::Retarget { .. } => 5,
        };
        runner
            .run(
                &arb_interfaces().prop_flat_map(|i| {
                    let len = handoff_plan(&i).len();
                    (Just(i), arb_mutation(len))
                }),
                |(interfaces, mutation)| {
                    let steps = apply_mutation(&handoff_plan(&interfaces), &mutation);
                    let (accepted, refused) = &counts[kind(&mutation)];
                    if simulate(&steps, &interfaces).is_ok() {
                        accepted.set(accepted.get() + 1);
                    } else {
                        refused.set(refused.get() + 1);
                    }
                    Ok(())
                },
            )
            .unwrap();
        let counts = counts.map(|(a, r)| (a.get(), r.get()));
        // ~670 cases per kind. A uniform shuffle of a ~24-step plan is
        // essentially never accepted, so Shuffle is held only to refusals.
        // For the rest, the rarer side is measured at roughly 15% (a single
        // swap, relocation, or duplication is refused only when it touches
        // one of the few order-sensitive steps; a retarget is accepted only
        // for the locked id), which is ~100 of ~670 with a standard
        // deviation of ~9. Forty is more than six standard deviations below
        // that, so a miss here is a generator change, not a seed.
        assert!(counts[0].1 >= 200, "shuffle refused only {counts:?}");
        for (name, (accepted, refused)) in ["swaps", "relocate", "drop", "duplicate", "retarget"]
            .iter()
            .zip(&counts[1..])
        {
            assert!(
                *accepted >= 40 && *refused >= 40,
                "{name}: accepted {accepted}, refused {refused}: {counts:?}"
            );
        }
    }
}
