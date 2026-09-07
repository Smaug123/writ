//! The `container run` capability arguments the initializer is launched with.
//!
//! Apple `container` starts the guest's PID 1 with a Linux capability set
//! chosen on the command line. The locked profile drops everything and adds
//! back exactly the capabilities the handoff needs, for exactly as long as it
//! needs them. Two things are fixed here rather than assembled at the call
//! site: the set itself, derived from [`TemporaryCapability::ALL`] so the
//! argument list and the design's list cannot drift apart, and a parser that
//! accepts the rendered profile and nothing else, so a flag that grows, moves,
//! or is respelled is a test failure rather than a quietly wider capability
//! set.

/// A capability PID 1 holds between launch and the handoff.
///
/// Every variant is consumed by a step of the handoff and gone by the time
/// the workload runs. `CAP_NET_RAW`, `CAP_SYS_ADMIN`, `CAP_BPF`, and
/// `CAP_SYS_PTRACE` are never granted, which is why they are not variants.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum TemporaryCapability {
    /// To take ownership of the fixed runtime, home, workspace, and Nix
    /// directories for the locked identity.
    Chown,
    /// To clear supplementary groups and change GID.
    Setgid,
    /// To change UID.
    Setuid,
    /// To drop the bounding set. Consumed *before* the identity change, which
    /// discards it.
    Setpcap,
    /// To write the IPv6 sysctls.
    NetAdmin,
}

impl TemporaryCapability {
    /// Every temporary capability, in the order the argv profile names them.
    pub const ALL: [Self; 5] = [
        Self::Chown,
        Self::Setgid,
        Self::Setuid,
        Self::Setpcap,
        Self::NetAdmin,
    ];

    /// The spelling `container run --cap-add` expects.
    pub fn container_name(self) -> &'static str {
        match self {
            Self::Chown => "CHOWN",
            Self::Setgid => "SETGID",
            Self::Setuid => "SETUID",
            Self::Setpcap => "SETPCAP",
            Self::NetAdmin => "NET_ADMIN",
        }
    }
}

/// The rendered profile, spelled out so a reader can see it without running
/// anything. [`locked_capability_argv_profile`] derives the same list from
/// [`TemporaryCapability::ALL`]; a test holds the two equal.
pub const LOCKED_CAPABILITY_ARGV_PROFILE: [&str; 12] = [
    "--cap-drop",
    "ALL",
    "--cap-add",
    "CHOWN",
    "--cap-add",
    "SETGID",
    "--cap-add",
    "SETUID",
    "--cap-add",
    "SETPCAP",
    "--cap-add",
    "NET_ADMIN",
];

/// The capability arguments, in order, for the locked profile's
/// `container run`.
pub fn locked_capability_argv_profile() -> Vec<String> {
    let mut argv = vec!["--cap-drop".to_string(), "ALL".to_string()];
    for capability in TemporaryCapability::ALL {
        argv.push("--cap-add".to_string());
        argv.push(capability.container_name().to_string());
    }
    argv
}

/// Proof that an argument slice is exactly the locked profile.
///
/// Constructible only through [`parse_locked_capability_argv_profile`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LockedCapabilityArgvProfile(());

/// Where an argument slice first departs from the locked profile.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LockedCapabilityArgvParseError {
    /// The slice differs at `position`: `expected` is what the profile has
    /// there (`None` past its end), `found` is what the slice has (`None`
    /// past its end).
    #[error(
        "agent VM capability argv is not the locked-v1 profile: at position {position} \
         expected {expected:?}, found {found:?}"
    )]
    Mismatch {
        position: usize,
        expected: Option<&'static str>,
        found: Option<String>,
    },
}

/// Accept an argument slice iff it equals the locked profile exactly.
///
/// Order, spelling, duplicates, omissions, additions, and `--flag=value`
/// alternatives are all rejected; the error names the first position that
/// differs.
pub fn parse_locked_capability_argv_profile(
    argv: &[String],
) -> Result<LockedCapabilityArgvProfile, LockedCapabilityArgvParseError> {
    let expected = LOCKED_CAPABILITY_ARGV_PROFILE;
    let longest = argv.len().max(expected.len());
    for position in 0..longest {
        let want = expected.get(position).copied();
        let have = argv.get(position).map(String::as_str);
        if want != have {
            return Err(LockedCapabilityArgvParseError::Mismatch {
                position,
                expected: want,
                found: have.map(str::to_string),
            });
        }
    }
    Ok(LockedCapabilityArgvProfile(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::cell::Cell;

    /// The spelled-out constant and the derived list are the same list, so
    /// the design's capability set has one definition.
    #[test]
    fn the_constant_and_the_derived_profile_agree() {
        let derived = locked_capability_argv_profile();
        assert_eq!(derived, LOCKED_CAPABILITY_ARGV_PROFILE.map(str::to_string));
        assert!(parse_locked_capability_argv_profile(&derived).is_ok());
    }

    /// The forbidden capabilities are not in the profile, by name.
    #[test]
    fn never_granted_capabilities_are_absent() {
        for forbidden in ["NET_RAW", "SYS_ADMIN", "BPF", "SYS_PTRACE"] {
            assert!(
                !LOCKED_CAPABILITY_ARGV_PROFILE.contains(&forbidden),
                "{forbidden} must never be granted"
            );
        }
    }

    /// One edit to the rendered profile.
    #[derive(Clone, Debug)]
    enum Mutation {
        Remove(usize),
        /// Swap two positions whose values differ, so the result is a
        /// different list.
        Swap(usize, usize),
        Duplicate(usize),
        Insert(usize, String),
        /// Replace a position with a value different from what is there.
        Replace(usize, String),
    }

    impl Mutation {
        fn kind(&self) -> &'static str {
            match self {
                Self::Remove(_) => "remove",
                Self::Swap(..) => "swap",
                Self::Duplicate(_) => "duplicate",
                Self::Insert(..) => "insert",
                Self::Replace(..) => "replace",
            }
        }

        /// Apply to the profile. Every variant is constructed so the result
        /// differs from the profile; the property asserts that as a sanity
        /// check on the generator rather than filtering.
        fn apply(&self, profile: &[String]) -> Vec<String> {
            let mut out = profile.to_vec();
            match self {
                Self::Remove(i) => {
                    out.remove(*i);
                }
                Self::Swap(i, j) => out.swap(*i, *j),
                Self::Duplicate(i) => out.insert(*i, profile[*i].clone()),
                Self::Insert(i, s) => out.insert(*i, s.clone()),
                Self::Replace(i, s) => out[*i] = s.clone(),
            }
            out
        }
    }

    /// Plausible-looking foreign tokens: other capability names, flag
    /// spellings, and arbitrary short strings.
    fn arb_token() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("NET_RAW".to_string()),
            Just("SYS_ADMIN".to_string()),
            Just("--cap-add=NET_ADMIN".to_string()),
            Just("--cap-drop".to_string()),
            Just("--cap-add".to_string()),
            Just("ALL".to_string()),
            Just("net_admin".to_string()),
            "[A-Z_a-z0-9=-]{0,12}",
        ]
    }

    fn arb_mutation() -> impl Strategy<Value = Mutation> {
        let n = LOCKED_CAPABILITY_ARGV_PROFILE.len();
        let profile = LOCKED_CAPABILITY_ARGV_PROFILE;
        // Position pairs with different contents, enumerated rather than
        // filtered.
        let distinct_pairs: Vec<(usize, usize)> = (0..n)
            .flat_map(|i| (0..n).map(move |j| (i, j)))
            .filter(|(i, j)| i < j && profile[*i] != profile[*j])
            .collect();
        prop_oneof![
            (0..n).prop_map(Mutation::Remove),
            proptest::sample::select(distinct_pairs).prop_map(|(i, j)| Mutation::Swap(i, j)),
            (0..n).prop_map(Mutation::Duplicate),
            (0..=n, arb_token()).prop_map(|(i, s)| Mutation::Insert(i, s)),
            (0..n, arb_token()).prop_flat_map(move |(i, s)| {
                // A replacement equal to the existing token is not a
                // mutation; construct one that differs by appending a byte in
                // that case rather than discarding the case.
                let s = if s == profile[i] { format!("{s}_") } else { s };
                Just(Mutation::Replace(i, s))
            }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// Any single edit to the profile is refused, and the refusal points
        /// at a position no later than the edit.
        #[test]
        fn any_single_edit_is_refused(mutation in arb_mutation()) {
            let profile = locked_capability_argv_profile();
            let mutated = mutation.apply(&profile);
            prop_assert_ne!(&mutated, &profile, "generator produced a non-mutation: {:?}", mutation);

            let err = parse_locked_capability_argv_profile(&mutated)
                .expect_err("a mutated profile must not parse");
            let LockedCapabilityArgvParseError::Mismatch { position, .. } = err;
            // A removal, swap, or replacement changes what sits at the edited
            // position itself. A duplicate, or an insert of the token already
            // there, leaves that position looking right and first differs one
            // later, so the bound is one looser for those.
            let latest = match &mutation {
                Mutation::Remove(i) | Mutation::Swap(i, _) | Mutation::Replace(i, _) => *i,
                Mutation::Duplicate(i) | Mutation::Insert(i, _) => *i + 1,
            };
            prop_assert!(
                position <= latest,
                "mismatch reported at {position} but the edit was at or before {latest}: {:?}",
                mutation
            );
        }
    }

    /// The mutation generator must reach every kind of edit, or the property
    /// above is only testing some of them. Measured on the generator
    /// directly: five kinds drawn uniformly over 2000 cases, and fewer than
    /// 200 of any one kind has probability far below 1e-11.
    #[test]
    fn the_mutation_generator_reaches_every_kind() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(2000));
        let counts: [Cell<u32>; 5] = [const { Cell::new(0) }; 5];
        runner
            .run(&arb_mutation(), |mutation| {
                let slot = &counts[match mutation.kind() {
                    "remove" => 0,
                    "swap" => 1,
                    "duplicate" => 2,
                    "insert" => 3,
                    "replace" => 4,
                    other => panic!("unknown mutation kind {other}"),
                }];
                slot.set(slot.get() + 1);
                Ok(())
            })
            .unwrap();
        let counts = counts.map(|c| c.get());
        for (kind, count) in ["remove", "swap", "duplicate", "insert", "replace"]
            .iter()
            .zip(counts)
        {
            assert!(
                count >= 200,
                "mutation kind {kind} seen only {count} times: {counts:?}"
            );
        }
    }
}
