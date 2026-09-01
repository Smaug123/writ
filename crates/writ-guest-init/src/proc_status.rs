//! What `/proc/<pid>/status` must say about a released workload.
//!
//! The host reads the initializer's status file, via a bounded
//! `container exec` *before* release while the only code in the guest is
//! still trusted, and refuses to release unless it parses to
//! [`LockedIdentity`]. This is the one place the locked identity's shape is
//! written down: every capability set zero, `NoNewPrivs` set, UID and GID
//! all [`LOCKED_UID`]/[`LOCKED_GID`], no supplementary groups, and `SIGUSR1`
//! not blocked (the initializer blocks it to wait on it, and must unblock it
//! before `exec` or the workload inherits a blocked signal).

use std::collections::BTreeMap;

use crate::{LOCKED_GID, LOCKED_UID};

/// The Linux signal number of `SIGUSR1`; bit `SIGUSR1 - 1` in `SigBlk`.
pub const SIGUSR1: u32 = 10;

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
}

/// One way a status document fails to be the locked identity.
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
    #[error("SIGUSR1 is blocked (SigBlk {0:#x}); the initializer must unblock it before exec")]
    Usr1Blocked(u64),
}

/// Proof that a status document describes the locked identity.
///
/// Constructible only through [`LockedIdentity::verify`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedIdentity(());

impl LockedIdentity {
    /// Every way the document departs from the locked identity, or the
    /// proof that it does not.
    pub fn verify(status: &ProcStatus) -> Result<Self, Vec<IdentityViolation>> {
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
        if status.sig_blk & (1u64 << (SIGUSR1 - 1)) != 0 {
            violations.push(IdentityViolation::Usr1Blocked(status.sig_blk));
        }
        if violations.is_empty() {
            Ok(Self(()))
        } else {
            Err(violations)
        }
    }
}

/// The status document the locked identity produces, with every judged
/// field at its required value.
pub fn locked_status() -> ProcStatus {
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
        sig_blk: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
        let violations = LockedIdentity::verify(&status).unwrap_err();
        // 4 uid + 4 gid + 3 non-zero cap sets + NoNewPrivs + SIGUSR1 blocked.
        assert_eq!(violations.len(), 13, "{violations:?}");
        assert!(violations.contains(&IdentityViolation::Usr1Blocked(0x200)));
        assert!(violations.contains(&IdentityViolation::Capability {
            set: "CapBnd",
            value: 0x10c1
        }));
    }

    #[test]
    fn the_locked_document_is_accepted_and_round_trips() {
        let locked = locked_status();
        assert!(LockedIdentity::verify(&locked).is_ok());
        assert_eq!(ProcStatus::parse(&locked.render()).unwrap(), locked);
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

    /// One field of the locked document, edited to a value that is not the
    /// locked one. Constructed to differ, never filtered.
    #[derive(Clone, Debug)]
    enum Edit {
        Uid(usize, u32),
        Gid(usize, u32),
        Groups(Vec<u32>),
        Cap(&'static str, u64),
        NoNewPrivs,
        BlockUsr1(u64),
    }

    fn arb_edit() -> impl Strategy<Value = Edit> {
        let non_locked_id = any::<u32>().prop_map(|v| if v == LOCKED_UID { v + 1 } else { v });
        let non_zero_u64 = any::<u64>().prop_map(|v| if v == 0 { 1 } else { v });
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
            // Any mask with the SIGUSR1 bit set.
            any::<u64>().prop_map(|v| Edit::BlockUsr1(v | (1 << (SIGUSR1 - 1)))),
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
                Edit::BlockUsr1(mask) => status.sig_blk = *mask,
            }
        }

        fn names_itself(&self, violation: &IdentityViolation) -> bool {
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
                (Edit::BlockUsr1(m), IdentityViolation::Usr1Blocked(seen)) => m == seen,
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

        /// Editing one field of the locked document away from its locked
        /// value produces exactly one violation, and it names that field and
        /// the value it saw.
        #[test]
        fn one_edit_yields_exactly_the_violation_that_names_it(edit in arb_edit()) {
            let mut status = locked_status();
            edit.apply(&mut status);
            let violations = LockedIdentity::verify(&status)
                .expect_err("an edited locked document must not verify");
            prop_assert_eq!(violations.len(), 1, "{:?} -> {:?}", edit, violations);
            prop_assert!(edit.names_itself(&violations[0]), "{:?} -> {:?}", edit, violations);
            // And it survives the wire: the parsed rendering says the same.
            let reparsed = ProcStatus::parse(&status.render()).unwrap();
            prop_assert_eq!(LockedIdentity::verify(&reparsed), Err(violations));
        }
    }

    /// The edit generator must reach every judged field.
    #[test]
    fn the_edit_generator_reaches_every_field() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(2000));
        let counts: [std::cell::Cell<u32>; 6] = [const { std::cell::Cell::new(0) }; 6];
        runner
            .run(&arb_edit(), |edit| {
                let slot = &counts[match edit {
                    Edit::Uid(..) => 0,
                    Edit::Gid(..) => 1,
                    Edit::Groups(_) => 2,
                    Edit::Cap(..) => 3,
                    Edit::NoNewPrivs => 4,
                    Edit::BlockUsr1(_) => 5,
                }];
                slot.set(slot.get() + 1);
                Ok(())
            })
            .unwrap();
        let counts = counts.map(|c| c.get());
        // Six kinds drawn uniformly over 2000 cases; fewer than 150 of any
        // one kind has probability far below 1e-11.
        for (kind, count) in ["uid", "gid", "groups", "cap", "nnp", "usr1"]
            .iter()
            .zip(counts)
        {
            assert!(
                count >= 150,
                "edit kind {kind} seen only {count} times: {counts:?}"
            );
        }
    }
}
