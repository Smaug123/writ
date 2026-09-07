//! What `/proc/<pid>/status` must say about a locked process, at each of the
//! two moments the host judges it.
//!
//! The locked identity itself is one shape: every capability set zero,
//! `NoNewPrivs` set, UID and GID all [`LOCKED_UID`]/[`LOCKED_GID`], no
//! supplementary groups. But the `SIGUSR1` bit of `SigBlk` must read
//! *differently* at the two moments a status document is read, and a single
//! acceptance check would reject one of them:
//!
//! - **Awaiting release.** The host reads PID 1's status via a bounded
//!   `container exec` after it sees `security-ready` and before it sends
//!   `SIGUSR1`, while the only code in the guest is still trusted. PID 1 is
//!   parked in `sigwait` on a set that blocks `SIGUSR1`, so the bit must be
//!   *set*: a clear bit means the wait is not armed, and a signal sent now
//!   would kill PID 1 or be lost. This is [`LockedAwaitingRelease`], the proof
//!   the host's release gate requires.
//! - **Released.** After release the initializer restores the mask and
//!   `exec`s the workload, which inherits the mask as it stands. Here the bit
//!   must be *clear*, or the workload has silently lost a signal it may use.
//!   This is [`LockedReleased`], the proof the Linux CI oracle requires of the
//!   process the initializer `exec`ed.
//!
//! The two proofs are distinct types so the release gate cannot be handed a
//! post-exec proof, nor the CI oracle a pre-release one; every other field is
//! judged identically by both.

use std::collections::BTreeMap;

use crate::{LOCKED_GID, LOCKED_UID};

/// The Linux signal number of `SIGUSR1`; bit `SIGUSR1 - 1` in `SigBlk`.
pub const SIGUSR1: u32 = 10;

/// The `SigBlk` bit that says `SIGUSR1` is blocked.
const USR1_BIT: u64 = 1u64 << (SIGUSR1 - 1);

/// The fields of `/proc/<pid>/status` the locked identity is judged on.
///
/// Other lines are ignored on parse; these must all be present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcStatus {
    /// Real, effective, saved, filesystem.
    pub uid: [u32; 4],
    /// Real, effective, saved, filesystem.
    pub gid: [u32; 4],
    pub groups: Vec<u32>,
    pub cap_inh: u64,
    pub cap_prm: u64,
    pub cap_eff: u64,
    pub cap_bnd: u64,
    pub cap_amb: u64,
    pub no_new_privs: u8,
    pub sig_blk: u64,
}

/// Why a status document did not parse.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProcStatusParseError {
    #[error("line {line} has no ':' separator: {text:?}")]
    NoSeparator { line: usize, text: String },
    #[error("field {field} appears twice")]
    Duplicate { field: &'static str },
    #[error("field {field} is missing")]
    Missing { field: &'static str },
    #[error("field {field} has {count} values, expected {expected}")]
    WrongArity {
        field: &'static str,
        count: usize,
        expected: usize,
    },
    #[error("field {field} value {value:?} is not {kind}")]
    BadValue {
        field: &'static str,
        value: String,
        kind: &'static str,
    },
}

const FIELDS: [&str; 10] = [
    "Uid",
    "Gid",
    "Groups",
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
    "NoNewPrivs",
    "SigBlk",
];

impl ProcStatus {
    /// Parse the text of a status file. Tolerates unknown lines and any
    /// order; refuses a duplicated or missing judged field.
    pub fn parse(text: &str) -> Result<Self, ProcStatusParseError> {
        let mut seen: BTreeMap<&'static str, &str> = BTreeMap::new();
        for (index, raw) in text.lines().enumerate() {
            if raw.trim().is_empty() {
                continue;
            }
            let Some((key, value)) = raw.split_once(':') else {
                return Err(ProcStatusParseError::NoSeparator {
                    line: index + 1,
                    text: raw.to_string(),
                });
            };
            if let Some(field) = FIELDS.iter().find(|f| **f == key.trim())
                && seen.insert(field, value.trim()).is_some()
            {
                return Err(ProcStatusParseError::Duplicate { field });
            }
        }
        let get = |field: &'static str| -> Result<&str, ProcStatusParseError> {
            seen.get(field)
                .copied()
                .ok_or(ProcStatusParseError::Missing { field })
        };
        let dec = |field: &'static str, value: &str| -> Result<u32, ProcStatusParseError> {
            value.parse().map_err(|_| ProcStatusParseError::BadValue {
                field,
                value: value.to_string(),
                kind: "a decimal integer",
            })
        };
        let hex = |field: &'static str| -> Result<u64, ProcStatusParseError> {
            let value = get(field)?;
            u64::from_str_radix(value, 16).map_err(|_| ProcStatusParseError::BadValue {
                field,
                value: value.to_string(),
                kind: "a hexadecimal mask",
            })
        };
        let four = |field: &'static str| -> Result<[u32; 4], ProcStatusParseError> {
            let values: Vec<u32> = get(field)?
                .split_whitespace()
                .map(|v| dec(field, v))
                .collect::<Result<_, _>>()?;
            values
                .as_slice()
                .try_into()
                .map_err(|_| ProcStatusParseError::WrongArity {
                    field,
                    count: values.len(),
                    expected: 4,
                })
        };
        let groups = get("Groups")?
            .split_whitespace()
            .map(|v| dec("Groups", v))
            .collect::<Result<Vec<_>, _>>()?;
        let no_new_privs = {
            let value = get("NoNewPrivs")?;
            match value {
                "0" => 0,
                "1" => 1,
                other => {
                    return Err(ProcStatusParseError::BadValue {
                        field: "NoNewPrivs",
                        value: other.to_string(),
                        kind: "0 or 1",
                    });
                }
            }
        };
        Ok(Self {
            uid: four("Uid")?,
            gid: four("Gid")?,
            groups,
            cap_inh: hex("CapInh")?,
            cap_prm: hex("CapPrm")?,
            cap_eff: hex("CapEff")?,
            cap_bnd: hex("CapBnd")?,
            cap_amb: hex("CapAmb")?,
            no_new_privs,
            sig_blk: hex("SigBlk")?,
        })
    }

    /// Render in the kernel's format. Used by the interpreter's tests and the
    /// host's fixtures; the kernel's own output parses identically.
    pub fn render(&self) -> String {
        let four = |v: [u32; 4]| v.iter().map(u32::to_string).collect::<Vec<_>>().join("\t");
        let groups = self
            .groups
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "Uid:\t{}\nGid:\t{}\nGroups:\t{}{}\nCapInh:\t{:016x}\nCapPrm:\t{:016x}\nCapEff:\t{:016x}\n\
             CapBnd:\t{:016x}\nCapAmb:\t{:016x}\nNoNewPrivs:\t{}\nSigBlk:\t{:016x}\n",
            four(self.uid),
            four(self.gid),
            groups,
            if self.groups.is_empty() { "" } else { " " },
            self.cap_inh,
            self.cap_prm,
            self.cap_eff,
            self.cap_bnd,
            self.cap_amb,
            self.no_new_privs,
            self.sig_blk,
        )
    }

    /// Whether `SigBlk` has the `SIGUSR1` bit set.
    pub fn usr1_blocked(&self) -> bool {
        self.sig_blk & USR1_BIT != 0
    }
}

/// The two moments a locked process's status is read, distinguished by what
/// the `SIGUSR1` bit of `SigBlk` must say.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum SignalWaitPhase {
    /// PID 1 has emitted `security-ready` and is parked in `sigwait`; the
    /// bit must be set, or the wait is not armed.
    AwaitingRelease,
    /// The initializer has restored the mask and `exec`ed the workload; the
    /// bit must be clear, or the workload inherited a blocked signal.
    Released,
}

impl SignalWaitPhase {
    pub const ALL: [Self; 2] = [Self::AwaitingRelease, Self::Released];

    /// The `SIGUSR1` violation this phase finds in a mask, if any.
    fn usr1_violation(self, sig_blk: u64) -> Option<IdentityViolation> {
        let blocked = sig_blk & USR1_BIT != 0;
        match (self, blocked) {
            (Self::AwaitingRelease, false) => Some(IdentityViolation::Usr1NotBlocked(sig_blk)),
            (Self::Released, true) => Some(IdentityViolation::Usr1Blocked(sig_blk)),
            _ => None,
        }
    }
}

/// One way a status document fails to be the locked identity at the phase
/// it was judged for.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdentityViolation {
    #[error("Uid slot {slot} is {value}, not {LOCKED_UID}")]
    Uid { slot: usize, value: u32 },
    #[error("Gid slot {slot} is {value}, not {LOCKED_GID}")]
    Gid { slot: usize, value: u32 },
    #[error("supplementary groups are {0:?}, not empty")]
    Groups(Vec<u32>),
    #[error("{set} is {value:#x}, not 0")]
    Capability { set: &'static str, value: u64 },
    #[error("NoNewPrivs is {0}, not 1")]
    NoNewPrivs(u8),
    /// Only [`SignalWaitPhase::Released`] reports this.
    #[error("SIGUSR1 is blocked (SigBlk {0:#x}); the initializer must unblock it before exec")]
    Usr1Blocked(u64),
    /// Only [`SignalWaitPhase::AwaitingRelease`] reports this.
    #[error("SIGUSR1 is not blocked (SigBlk {0:#x}); the release wait is not armed")]
    Usr1NotBlocked(u64),
}

/// Every way `status` departs from the locked identity as judged at `phase`.
fn violations(status: &ProcStatus, phase: SignalWaitPhase) -> Vec<IdentityViolation> {
    let mut violations = Vec::new();
    for (slot, value) in status.uid.iter().enumerate() {
        if *value != LOCKED_UID {
            violations.push(IdentityViolation::Uid {
                slot,
                value: *value,
            });
        }
    }
    for (slot, value) in status.gid.iter().enumerate() {
        if *value != LOCKED_GID {
            violations.push(IdentityViolation::Gid {
                slot,
                value: *value,
            });
        }
    }
    if !status.groups.is_empty() {
        violations.push(IdentityViolation::Groups(status.groups.clone()));
    }
    for (set, value) in [
        ("CapInh", status.cap_inh),
        ("CapPrm", status.cap_prm),
        ("CapEff", status.cap_eff),
        ("CapBnd", status.cap_bnd),
        ("CapAmb", status.cap_amb),
    ] {
        if value != 0 {
            violations.push(IdentityViolation::Capability { set, value });
        }
    }
    if status.no_new_privs != 1 {
        violations.push(IdentityViolation::NoNewPrivs(status.no_new_privs));
    }
    violations.extend(phase.usr1_violation(status.sig_blk));
    violations
}

/// Proof that a status document describes the locked identity parked in the
/// release wait, with `SIGUSR1` blocked. What the host's release gate needs.
///
/// Constructible only through [`LockedAwaitingRelease::verify`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedAwaitingRelease(());

impl LockedAwaitingRelease {
    /// Every way the document departs from the locked identity awaiting
    /// release, or the proof that it does not.
    pub fn verify(status: &ProcStatus) -> Result<Self, Vec<IdentityViolation>> {
        let violations = violations(status, SignalWaitPhase::AwaitingRelease);
        if violations.is_empty() {
            Ok(Self(()))
        } else {
            Err(violations)
        }
    }
}

/// Proof that a status document describes the locked identity after release,
/// with `SIGUSR1` unblocked. What the CI oracle needs of the `exec`ed
/// workload.
///
/// Constructible only through [`LockedReleased::verify`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedReleased(());

impl LockedReleased {
    /// Every way the document departs from the released locked identity, or
    /// the proof that it does not.
    pub fn verify(status: &ProcStatus) -> Result<Self, Vec<IdentityViolation>> {
        let violations = violations(status, SignalWaitPhase::Released);
        if violations.is_empty() {
            Ok(Self(()))
        } else {
            Err(violations)
        }
    }
}

/// The status document the locked identity produces at `phase`, with every
/// judged field at its required value.
pub fn locked_status(phase: SignalWaitPhase) -> ProcStatus {
    ProcStatus {
        uid: [LOCKED_UID; 4],
        gid: [LOCKED_GID; 4],
        groups: Vec::new(),
        cap_inh: 0,
        cap_prm: 0,
        cap_eff: 0,
        cap_bnd: 0,
        cap_amb: 0,
        no_new_privs: 1,
        sig_blk: match phase {
            SignalWaitPhase::AwaitingRelease => USR1_BIT,
            SignalWaitPhase::Released => 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Judge at a phase, returning the violation list either way.
    fn verify_at(
        status: &ProcStatus,
        phase: SignalWaitPhase,
    ) -> Result<(), Vec<IdentityViolation>> {
        match phase {
            SignalWaitPhase::AwaitingRelease => LockedAwaitingRelease::verify(status).map(|_| ()),
            SignalWaitPhase::Released => LockedReleased::verify(status).map(|_| ()),
        }
    }

    /// A document as the kernel prints it for a root process at container
    /// launch, with the unrelated lines the kernel also prints.
    const ROOT_AT_LAUNCH: &str = "Name:\twrit-agent-vm-guest-init\n\
Umask:\t0022\n\
State:\tS (sleeping)\n\
Tgid:\t1\n\
Pid:\t1\n\
Uid:\t0\t0\t0\t0\n\
Gid:\t0\t0\t0\t0\n\
Groups:\t \n\
NStgid:\t1\n\
CapInh:\t0000000000000000\n\
CapPrm:\t00000000000010c1\n\
CapEff:\t00000000000010c1\n\
CapBnd:\t00000000000010c1\n\
CapAmb:\t0000000000000000\n\
NoNewPrivs:\t0\n\
Seccomp:\t0\n\
SigBlk:\t0000000000000200\n\
Threads:\t1\n";

    #[test]
    fn parses_a_kernel_shaped_document_and_finds_every_violation() {
        let status = ProcStatus::parse(ROOT_AT_LAUNCH).unwrap();
        assert_eq!(status.uid, [0; 4]);
        assert_eq!(status.groups, Vec::<u32>::new());
        assert_eq!(status.cap_eff, 0x10c1);
        assert_eq!(status.sig_blk, 0x200);
        assert!(status.usr1_blocked());

        // Judged as a released workload: 4 uid + 4 gid + 3 non-zero cap sets
        // + NoNewPrivs + SIGUSR1 blocked.
        let released = LockedReleased::verify(&status).unwrap_err();
        assert_eq!(released.len(), 13, "{released:?}");
        assert!(released.contains(&IdentityViolation::Usr1Blocked(0x200)));
        assert!(released.contains(&IdentityViolation::Capability {
            set: "CapBnd",
            value: 0x10c1
        }));

        // Judged as awaiting release: the same, minus the signal, which is
        // exactly as it should be for a process parked in sigwait.
        let awaiting = LockedAwaitingRelease::verify(&status).unwrap_err();
        assert_eq!(awaiting.len(), 12, "{awaiting:?}");
        assert!(!awaiting.iter().any(|v| matches!(
            v,
            IdentityViolation::Usr1Blocked(_) | IdentityViolation::Usr1NotBlocked(_)
        )));
    }

    /// The bug the second review found: the host reads the status *before*
    /// release, while PID 1 is parked in sigwait with SIGUSR1 blocked, so the
    /// gate must accept that state and refuse the unblocked one; the
    /// post-exec oracle wants the opposite.
    #[test]
    fn each_phase_accepts_its_own_locked_document_and_refuses_the_others() {
        let parked = locked_status(SignalWaitPhase::AwaitingRelease);
        let released = locked_status(SignalWaitPhase::Released);
        assert!(parked.usr1_blocked());
        assert!(!released.usr1_blocked());

        assert!(LockedAwaitingRelease::verify(&parked).is_ok());
        assert_eq!(
            LockedAwaitingRelease::verify(&released),
            Err(vec![IdentityViolation::Usr1NotBlocked(0)])
        );

        assert!(LockedReleased::verify(&released).is_ok());
        assert_eq!(
            LockedReleased::verify(&parked),
            Err(vec![IdentityViolation::Usr1Blocked(USR1_BIT)])
        );

        for phase in SignalWaitPhase::ALL {
            let locked = locked_status(phase);
            assert_eq!(ProcStatus::parse(&locked.render()).unwrap(), locked);
        }
    }

    #[test]
    fn missing_duplicate_and_malformed_fields_are_refused_by_name() {
        let without_bnd = ROOT_AT_LAUNCH.replace("CapBnd:\t00000000000010c1\n", "");
        assert_eq!(
            ProcStatus::parse(&without_bnd),
            Err(ProcStatusParseError::Missing { field: "CapBnd" })
        );
        let twice = format!("{ROOT_AT_LAUNCH}Uid:\t0\t0\t0\t0\n");
        assert_eq!(
            ProcStatus::parse(&twice),
            Err(ProcStatusParseError::Duplicate { field: "Uid" })
        );
        let three_uids = ROOT_AT_LAUNCH.replace("Uid:\t0\t0\t0\t0\n", "Uid:\t0\t0\t0\n");
        assert_eq!(
            ProcStatus::parse(&three_uids),
            Err(ProcStatusParseError::WrongArity {
                field: "Uid",
                count: 3,
                expected: 4
            })
        );
        let bad_nnp = ROOT_AT_LAUNCH.replace("NoNewPrivs:\t0\n", "NoNewPrivs:\t2\n");
        assert!(matches!(
            ProcStatus::parse(&bad_nnp),
            Err(ProcStatusParseError::BadValue {
                field: "NoNewPrivs",
                ..
            })
        ));
    }

    fn arb_status() -> impl Strategy<Value = ProcStatus> {
        (
            proptest::array::uniform4(any::<u32>()),
            proptest::array::uniform4(any::<u32>()),
            proptest::collection::vec(any::<u32>(), 0..4),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            0u8..=1,
            any::<u64>(),
        )
            .prop_map(
                |(
                    uid,
                    gid,
                    groups,
                    cap_inh,
                    cap_prm,
                    cap_eff,
                    cap_bnd,
                    cap_amb,
                    no_new_privs,
                    sig_blk,
                )| {
                    ProcStatus {
                        uid,
                        gid,
                        groups,
                        cap_inh,
                        cap_prm,
                        cap_eff,
                        cap_bnd,
                        cap_amb,
                        no_new_privs,
                        sig_blk,
                    }
                },
            )
    }

    fn arb_phase() -> impl Strategy<Value = SignalWaitPhase> {
        proptest::sample::select(SignalWaitPhase::ALL.to_vec())
    }

    /// One field of a phase's locked document, edited to a value that is not
    /// the locked one for that phase. Constructed to differ, never filtered.
    #[derive(Clone, Debug)]
    enum Edit {
        Uid(usize, u32),
        Gid(usize, u32),
        Groups(Vec<u32>),
        Cap(&'static str, u64),
        NoNewPrivs,
        /// A `SigBlk` mask with the SIGUSR1 bit at the wrong value for the
        /// phase: clear when awaiting release, set when released.
        Usr1(u64),
    }

    fn arb_edit(phase: SignalWaitPhase) -> impl Strategy<Value = Edit> {
        let non_locked_id = any::<u32>().prop_map(|v| if v == LOCKED_UID { v + 1 } else { v });
        let non_zero_u64 = any::<u64>().prop_map(|v| if v == 0 { 1 } else { v });
        let wrong_usr1 = any::<u64>().prop_map(move |v| match phase {
            SignalWaitPhase::AwaitingRelease => v & !USR1_BIT,
            SignalWaitPhase::Released => v | USR1_BIT,
        });
        prop_oneof![
            (0..4usize, non_locked_id.clone()).prop_map(|(s, v)| Edit::Uid(s, v)),
            (0..4usize, non_locked_id).prop_map(|(s, v)| Edit::Gid(s, v)),
            proptest::collection::vec(any::<u32>(), 1..4).prop_map(Edit::Groups),
            (
                proptest::sample::select(vec!["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]),
                non_zero_u64
            )
                .prop_map(|(s, v)| Edit::Cap(s, v)),
            Just(Edit::NoNewPrivs),
            wrong_usr1.prop_map(Edit::Usr1),
        ]
    }

    impl Edit {
        fn apply(&self, status: &mut ProcStatus) {
            match self {
                Edit::Uid(slot, v) => status.uid[*slot] = *v,
                Edit::Gid(slot, v) => status.gid[*slot] = *v,
                Edit::Groups(g) => status.groups = g.clone(),
                Edit::Cap(set, v) => match *set {
                    "CapInh" => status.cap_inh = *v,
                    "CapPrm" => status.cap_prm = *v,
                    "CapEff" => status.cap_eff = *v,
                    "CapBnd" => status.cap_bnd = *v,
                    "CapAmb" => status.cap_amb = *v,
                    _ => unreachable!(),
                },
                Edit::NoNewPrivs => status.no_new_privs = 0,
                Edit::Usr1(mask) => status.sig_blk = *mask,
            }
        }

        fn names_itself(&self, phase: SignalWaitPhase, violation: &IdentityViolation) -> bool {
            match (self, violation) {
                (Edit::Uid(s, v), IdentityViolation::Uid { slot, value }) => {
                    s == slot && v == value
                }
                (Edit::Gid(s, v), IdentityViolation::Gid { slot, value }) => {
                    s == slot && v == value
                }
                (Edit::Groups(g), IdentityViolation::Groups(seen)) => g == seen,
                (Edit::Cap(s, v), IdentityViolation::Capability { set, value }) => {
                    s == set && v == value
                }
                (Edit::NoNewPrivs, IdentityViolation::NoNewPrivs(0)) => true,
                (Edit::Usr1(m), IdentityViolation::Usr1NotBlocked(seen)) => {
                    phase == SignalWaitPhase::AwaitingRelease && m == seen
                }
                (Edit::Usr1(m), IdentityViolation::Usr1Blocked(seen)) => {
                    phase == SignalWaitPhase::Released && m == seen
                }
                _ => false,
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// Render then parse is the identity over every document, including
        /// ones no kernel would produce, so the parser is not relying on
        /// values being small or masks being sparse.
        #[test]
        fn render_parse_round_trips(status in arb_status()) {
            prop_assert_eq!(ProcStatus::parse(&status.render()).unwrap(), status);
        }

        /// Editing one field of a phase's locked document away from its
        /// locked value produces exactly one violation under that phase, and
        /// it names that field and the value it saw.
        #[test]
        fn one_edit_yields_exactly_the_violation_that_names_it(
            (phase, edit) in arb_phase().prop_flat_map(|p| (Just(p), arb_edit(p))),
        ) {
            let mut status = locked_status(phase);
            edit.apply(&mut status);
            let violations = verify_at(&status, phase)
                .expect_err("an edited locked document must not verify");
            prop_assert_eq!(violations.len(), 1, "{:?} at {:?} -> {:?}", edit, phase, violations);
            prop_assert!(
                edit.names_itself(phase, &violations[0]),
                "{:?} at {:?} -> {:?}", edit, phase, violations
            );
            // And it survives the wire: the parsed rendering says the same.
            let reparsed = ProcStatus::parse(&status.render()).unwrap();
            prop_assert_eq!(verify_at(&reparsed, phase), Err(violations));
        }

        /// The two phases judge every field except the SIGUSR1 bit
        /// identically, and judge that bit oppositely: for any document,
        /// exactly one phase reports a SIGUSR1 violation, and the two
        /// violation lists are otherwise equal. So no document is accepted
        /// by both proofs, and the split changes nothing but the signal.
        #[test]
        fn the_phases_differ_only_in_the_usr1_bit(status in arb_status()) {
            let is_usr1 = |v: &IdentityViolation| matches!(
                v,
                IdentityViolation::Usr1Blocked(_) | IdentityViolation::Usr1NotBlocked(_)
            );
            let awaiting = violations(&status, SignalWaitPhase::AwaitingRelease);
            let released = violations(&status, SignalWaitPhase::Released);
            let usr1_awaiting: Vec<IdentityViolation> =
                awaiting.iter().filter(|v| is_usr1(v)).cloned().collect();
            let usr1_released: Vec<IdentityViolation> =
                released.iter().filter(|v| is_usr1(v)).cloned().collect();
            if status.usr1_blocked() {
                prop_assert_eq!(usr1_awaiting, Vec::new());
                prop_assert_eq!(usr1_released, vec![IdentityViolation::Usr1Blocked(status.sig_blk)]);
            } else {
                prop_assert_eq!(usr1_awaiting, vec![IdentityViolation::Usr1NotBlocked(status.sig_blk)]);
                prop_assert_eq!(usr1_released, Vec::new());
            }
            let rest = |vs: &[IdentityViolation]| -> Vec<IdentityViolation> {
                vs.iter().filter(|v| !is_usr1(v)).cloned().collect()
            };
            prop_assert_eq!(rest(&awaiting), rest(&released));
        }
    }

    /// The edit generator must reach every judged field, at each phase.
    #[test]
    fn the_edit_generator_reaches_every_field() {
        for phase in SignalWaitPhase::ALL {
            let mut runner =
                proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(2000));
            let counts: [std::cell::Cell<u32>; 6] = [const { std::cell::Cell::new(0) }; 6];
            runner
                .run(&arb_edit(phase), |edit| {
                    let slot = &counts[match edit {
                        Edit::Uid(..) => 0,
                        Edit::Gid(..) => 1,
                        Edit::Groups(_) => 2,
                        Edit::Cap(..) => 3,
                        Edit::NoNewPrivs => 4,
                        Edit::Usr1(_) => 5,
                    }];
                    slot.set(slot.get() + 1);
                    Ok(())
                })
                .unwrap();
            let counts = counts.map(|c| c.get());
            // Six kinds drawn uniformly over 2000 cases; fewer than 150 of
            // any one kind has probability far below 1e-11.
            for (kind, count) in ["uid", "gid", "groups", "cap", "nnp", "usr1"]
                .iter()
                .zip(counts)
            {
                assert!(
                    count >= 150,
                    "edit kind {kind} seen only {count} times at {phase:?}: {counts:?}"
                );
            }
        }
    }
}
