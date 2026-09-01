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
//! it accepts an order iff the kernel would let every step succeed, and the
//! tests hold the canonical plan and every precedence rule against it.

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
    /// `chown -R LOCKED_UID:LOCKED_GID` on one of the fixed directories.
    ChownOwnedDirectory(OwnedDirectory),
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
        steps.push(HandoffStep::ChownOwnedDirectory(dir));
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
/// - `chown` of a root-owned directory needs effective `CAP_CHOWN`;
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
}

impl ProcessModel {
    /// PID 1 as `container run` with the locked argv profile starts it: UID 0,
    /// the temporary capabilities in the effective, permitted, and bounding
    /// sets, nothing inheritable or ambient.
    pub fn at_launch() -> Self {
        let temporary: BTreeSet<_> = TemporaryCapability::ALL.into_iter().collect();
        Self {
            uid: 0,
            gid: 0,
            supplementary_groups_cleared: false,
            effective: temporary.clone(),
            permitted: temporary.clone(),
            inheritable: BTreeSet::new(),
            ambient: BTreeSet::new(),
            bounding: temporary,
            no_new_privs: false,
            disable_ipv6_written: BTreeSet::new(),
            ipv6_verified: false,
            owned: BTreeSet::new(),
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
/// kernel rules would refuse. Success means every step ran *and* the final
/// verification found the locked state.
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
    Ok(model)
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
        match step {
            HandoffStep::ChownOwnedDirectory(dir) => {
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
    /// change, which discards both.
    PrivilegedStepAfterIdentityChange(HandoffStep),
    /// IPv6 absence was verified before `disable_ipv6` was written for every
    /// scope.
    VerifyNoIpv6BeforeDisable,
    /// The final verification is not the last step, or a step it depends on
    /// is missing.
    VerifyLockedIdentityNotLast,
}

/// Every precedence rule the given order breaks.
pub fn precedence_violations(
    steps: &[HandoffStep],
    interfaces: &[InterfaceName],
) -> Vec<PrecedenceViolation> {
    let mut violations = Vec::new();

    let identity_change = steps
        .iter()
        .position(|s| matches!(s, HandoffStep::SetResuid(uid) if *uid != 0));
    if let Some(at) = identity_change {
        for step in &steps[at + 1..] {
            let privileged = matches!(
                step,
                HandoffStep::ChownOwnedDirectory(_)
                    | HandoffStep::WriteSysctl { .. }
                    | HandoffStep::DropBoundingSet
                    | HandoffStep::ClearSupplementaryGroups
                    | HandoffStep::SetResgid(_)
                    | HandoffStep::SetResuid(_)
            );
            if privileged {
                violations.push(PrecedenceViolation::PrivilegedStepAfterIdentityChange(
                    step.clone(),
                ));
            }
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
                .all(|d| has(&|s| *s == HandoffStep::ChownOwnedDirectory(*d)))
                && has(&|s| *s == HandoffStep::VerifyNoIpv6)
                && has(&|s| *s == HandoffStep::DropBoundingSet)
                && has(&|s| *s == HandoffStep::ClearInheritableAndAmbient)
                && has(&|s| *s == HandoffStep::SetNoNewPrivs)
                && has(&|s| *s == HandoffStep::ClearSupplementaryGroups)
                && has(&|s| *s == HandoffStep::SetResgid(LOCKED_GID))
                && has(&|s| *s == HandoffStep::SetResuid(LOCKED_UID))
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
            HandoffStep::ChownOwnedDirectory(OwnedDirectory::Runtime),
            HandoffStep::ChownOwnedDirectory(OwnedDirectory::Home),
            HandoffStep::ChownOwnedDirectory(OwnedDirectory::Workspace),
            HandoffStep::ChownOwnedDirectory(OwnedDirectory::NixStore),
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

    /// One way of reordering the canonical plan. A uniformly random
    /// permutation almost always violates something, so half the cases
    /// instead apply a few adjacent swaps to the canonical order, which
    /// keeps the accepting side of the property populated.
    #[derive(Clone, Debug)]
    enum Reorder {
        Shuffle(Vec<usize>),
        AdjacentSwaps(Vec<usize>),
    }

    fn arb_reorder(len: usize) -> impl Strategy<Value = Reorder> {
        prop_oneof![
            Just((0..len).collect::<Vec<_>>())
                .prop_shuffle()
                .prop_map(Reorder::Shuffle),
            proptest::collection::vec(0..len.saturating_sub(1), 0..4)
                .prop_map(Reorder::AdjacentSwaps),
        ]
    }

    fn apply_reorder(steps: &[HandoffStep], reorder: &Reorder) -> Vec<HandoffStep> {
        match reorder {
            Reorder::Shuffle(perm) => perm.iter().map(|&i| steps[i].clone()).collect(),
            Reorder::AdjacentSwaps(swaps) => {
                let mut out = steps.to_vec();
                for &i in swaps {
                    out.swap(i, i + 1);
                }
                out
            }
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
        /// constraint: an order runs to completion in the model iff it
        /// breaks no precedence rule.
        #[test]
        fn the_model_and_the_precedence_rules_agree(
            (interfaces, reorder) in arb_interfaces().prop_flat_map(|i| {
                let len = handoff_plan(&i).len();
                (Just(i), arb_reorder(len))
            }),
        ) {
            let steps = apply_reorder(&handoff_plan(&interfaces), &reorder);
            let simulated = simulate(&steps, &interfaces);
            let violations = precedence_violations(&steps, &interfaces);
            prop_assert_eq!(
                simulated.is_ok(),
                violations.is_empty(),
                "model says {:?} but precedence rules say {:?} for {:?}",
                simulated.as_ref().map(|_| ()).map_err(|e| e.to_string()),
                violations,
                steps
            );
        }
    }

    /// The agreement property must see both outcomes, or it is only testing
    /// one half of the equivalence. Measured on the generator directly.
    #[test]
    fn the_reorder_generator_reaches_both_outcomes() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(2000));
        let (accepted, refused) = (std::cell::Cell::new(0u32), std::cell::Cell::new(0u32));
        runner
            .run(
                &arb_interfaces().prop_flat_map(|i| {
                    let len = handoff_plan(&i).len();
                    (Just(i), arb_reorder(len))
                }),
                |(interfaces, reorder)| {
                    let steps = apply_reorder(&handoff_plan(&interfaces), &reorder);
                    if simulate(&steps, &interfaces).is_ok() {
                        accepted.set(accepted.get() + 1);
                    } else {
                        refused.set(refused.get() + 1);
                    }
                    Ok(())
                },
            )
            .unwrap();
        // Half the cases are 0..3 adjacent swaps of a ~24-step plan, of which
        // most are harmless; a uniformly random permutation is essentially
        // never accepted. Both sides should be in the hundreds.
        let (accepted, refused) = (accepted.get(), refused.get());
        assert!(accepted >= 200, "accepted only {accepted} of 2000");
        assert!(refused >= 200, "refused only {refused} of 2000");
    }
}
