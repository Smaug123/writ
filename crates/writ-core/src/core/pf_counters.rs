//! A session anchor's labelled rule counters, as `pfctl -a <anchor> -vsr`
//! prints them.
//!
//! PF keeps a packet and byte counter per loaded rule, and `-v` prints them
//! under each rule. They are the host-owned evidence the vertical proof
//! grades on (design record, evidence protocol rule 1): a deny counter that
//! rose by at least the number of probes the host commanded is proof the
//! rule decided those frames, where a guest's "I could not connect" is not.
//! A snapshot is keyed by (label, interface): the attached anchor stamps the
//! same label on the bridge rule and on each `vmenet` member's rule, so the
//! label alone is not a key, and the interface is in the rule text. A
//! subnet-scoped deny of the bootstrap anchor has a label and no interface.
//! Unlabelled rules (the allows) carry no key and are not counted.
//!
//! The rule lines are the same text `-sr` prints, parsed with the exact
//! readback grammar, so a snapshot of an anchor holding a rule this crate
//! never rendered is an error rather than a partial answer. The counter line
//! is pfctl's `  [ Evaluations: N  Packets: N  Bytes: N  States: N  ]`, whose
//! column padding varies with the numbers' widths, so any run of spaces is
//! accepted between its fields; any other bracketed line under a rule (the
//! `[ Inserted: uid U pid P ]` line) is skipped.

use std::collections::BTreeMap;

use super::agent_vm::PfInterface;
use super::pf_readback::{PfReadbackRule, is_valid_label};

/// What one counter belongs to: a labelled rule, on the interface it is
/// scoped to if it is scoped to one.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PfCounterKey {
    label: String,
    interface: Option<PfInterface>,
}

impl PfCounterKey {
    /// `None` if the label is not one the readback grammar can carry.
    pub fn new(label: impl Into<String>, interface: Option<PfInterface>) -> Option<Self> {
        let label = label.into();
        is_valid_label(&label).then_some(Self { label, interface })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn interface(&self) -> Option<&PfInterface> {
        self.interface.as_ref()
    }
}

impl std::fmt::Display for PfCounterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.interface {
            Some(interface) => write!(f, "{:?} on {interface}", self.label),
            None => write!(f, "{:?}", self.label),
        }
    }
}

/// One rule's counters: packets and bytes, both directions summed, as pfctl
/// prints them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PfCounters {
    pub packets: u64,
    pub bytes: u64,
}

/// Every labelled rule's counters at one reading of the anchor.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PfCounterSnapshot {
    counters: BTreeMap<PfCounterKey, PfCounters>,
}

/// The rise of every counter between two snapshots of the same loaded
/// anchor, componentwise later minus earlier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfCounterDelta {
    counters: BTreeMap<PfCounterKey, PfCounters>,
}

/// Why two snapshots have no delta.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PfCounterDeltaError {
    /// The snapshots count different rules: `missing` are in the earlier
    /// snapshot only, `extra` in the later only. They are not readings of the
    /// same anchor.
    #[error("the two snapshots count different rules: missing {missing:?}, extra {extra:?}")]
    KeySetsDiffer {
        missing: Vec<PfCounterKey>,
        extra: Vec<PfCounterKey>,
    },
    /// A counter fell. Counters only rise between readings of one loaded
    /// anchor, so the anchor was reloaded in between and the two readings
    /// are not comparable.
    #[error(
        "counter {key} fell from {before:?} to {after:?}: the anchor was reloaded between the snapshots"
    )]
    Decreased {
        key: PfCounterKey,
        before: PfCounters,
        after: PfCounters,
    },
}

/// Why a `pfctl -vsr` dump did not parse as a session anchor's counters.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PfCountersParseError {
    /// A rule line is not one this crate renders, spelled as pfctl prints it.
    #[error("verbose readback line {line_number} is not a session anchor rule: {line:?}")]
    UnrecognisedRule { line_number: usize, line: String },
    /// A rule has no `[ Evaluations: ... ]` line under it.
    #[error("the rule at verbose readback line {line_number} has no counter line")]
    MissingCounters { line_number: usize },
    /// A rule has more than one `[ Evaluations: ... ]` line under it.
    #[error("the rule at verbose readback line {line_number} has more than one counter line")]
    RepeatedCounters { line_number: usize },
    /// A bracketed line under a rule is not a counter line this parser reads.
    #[error("verbose readback line {line_number} is not a counter line: {line:?}")]
    UnrecognisedCounters { line_number: usize, line: String },
    /// Two rules share a key, so their counters cannot be told apart.
    #[error("rule {key} appears twice in the anchor")]
    DuplicateKey { key: PfCounterKey },
}

impl PfCounterSnapshot {
    /// Assemble a snapshot, refusing a key that appears twice (returned as
    /// the error).
    pub fn new(
        entries: impl IntoIterator<Item = (PfCounterKey, PfCounters)>,
    ) -> Result<Self, PfCounterKey> {
        let mut counters = BTreeMap::new();
        for (key, value) in entries {
            if counters.insert(key.clone(), value).is_some() {
                return Err(key);
            }
        }
        Ok(Self { counters })
    }

    pub fn get(&self, key: &PfCounterKey) -> Option<PfCounters> {
        self.counters.get(key).copied()
    }

    /// Every counter, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&PfCounterKey, PfCounters)> {
        self.counters.iter().map(|(key, value)| (key, *value))
    }

    pub fn len(&self) -> usize {
        self.counters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    /// How far every counter rose from `self` to `later`. Defined only for
    /// two readings of the same loaded anchor: the same keys, none fallen.
    pub fn delta(&self, later: &Self) -> Result<PfCounterDelta, PfCounterDeltaError> {
        let missing: Vec<_> = self
            .counters
            .keys()
            .filter(|key| !later.counters.contains_key(*key))
            .cloned()
            .collect();
        let extra: Vec<_> = later
            .counters
            .keys()
            .filter(|key| !self.counters.contains_key(*key))
            .cloned()
            .collect();
        if !missing.is_empty() || !extra.is_empty() {
            return Err(PfCounterDeltaError::KeySetsDiffer { missing, extra });
        }
        let mut counters = BTreeMap::new();
        for (key, before) in &self.counters {
            let after = later.counters[key];
            let rise = match (
                after.packets.checked_sub(before.packets),
                after.bytes.checked_sub(before.bytes),
            ) {
                (Some(packets), Some(bytes)) => PfCounters { packets, bytes },
                _ => {
                    return Err(PfCounterDeltaError::Decreased {
                        key: key.clone(),
                        before: *before,
                        after,
                    });
                }
            };
            counters.insert(key.clone(), rise);
        }
        Ok(PfCounterDelta { counters })
    }
}

impl PfCounterDelta {
    pub fn get(&self, key: &PfCounterKey) -> Option<PfCounters> {
        self.counters.get(key).copied()
    }

    /// Every rise, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&PfCounterKey, PfCounters)> {
        self.counters.iter().map(|(key, value)| (key, *value))
    }

    pub fn len(&self) -> usize {
        self.counters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }
}

impl PfReadbackRule {
    /// The counter key this rule's counters are filed under: none for an
    /// unlabelled rule.
    pub fn counter_key(&self) -> Option<PfCounterKey> {
        match self {
            Self::Allow { .. } => None,
            Self::Deny { label, .. } => PfCounterKey::new(label.clone(), None),
            Self::InterfaceDeny {
                interface, label, ..
            } => PfCounterKey::new(label.clone(), Some(interface.clone())),
        }
    }
}

/// The indentation every line pfctl prints under a rule starts with.
const COUNTER_LINE_PREFIX: &str = "  [ ";

/// `  [ Evaluations: N  Packets: N  Bytes: N  States: N  ]`, with any run of
/// spaces between the fields.
fn parse_counter_line(line: &str) -> Option<PfCounters> {
    let body = line.strip_prefix(COUNTER_LINE_PREFIX)?.strip_suffix(']')?;
    let mut fields = body.split_ascii_whitespace();
    let mut expect = |name: &str| -> Option<u64> {
        (fields.next()? == name).then_some(())?;
        let digits = fields.next()?;
        (!digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (digits.len() == 1 || !digits.starts_with('0')))
        .then(|| digits.parse().ok())
        .flatten()
    };
    let _evaluations = expect("Evaluations:")?;
    let packets = expect("Packets:")?;
    let bytes = expect("Bytes:")?;
    let _states = expect("States:")?;
    fields
        .next()
        .is_none()
        .then_some(PfCounters { packets, bytes })
}

/// Parse a `pfctl -a <anchor> -vsr` dump into the labelled rules' counters.
/// Every rule line must be a session anchor rule as pfctl prints it, each
/// followed by exactly one counter line (other bracketed lines under it are
/// skipped), and every line must end in a newline.
pub fn parse_pf_verbose_readback(text: &str) -> Result<PfCounterSnapshot, PfCountersParseError> {
    use PfCountersParseError::*;
    let mut entries = Vec::new();
    // The rule most recently read and not yet filed, with its line number
    // and its counters once its counter line has been seen.
    let mut pending: Option<(usize, Option<PfCounterKey>, Option<PfCounters>)> = None;
    let mut rest = text;
    let mut line_number = 0;
    let file = |pending: Option<(usize, Option<PfCounterKey>, Option<PfCounters>)>,
                entries: &mut Vec<(PfCounterKey, PfCounters)>|
     -> Result<(), PfCountersParseError> {
        match pending {
            None => Ok(()),
            Some((line_number, _, None)) => Err(MissingCounters { line_number }),
            Some((_, key, Some(counters))) => {
                if let Some(key) = key {
                    entries.push((key, counters));
                }
                Ok(())
            }
        }
    };
    while !rest.is_empty() {
        line_number += 1;
        // Without a terminating newline the last line is not what pfctl
        // printed, so refuse it rather than accept a truncated dump.
        let Some((line, after)) = rest.split_once('\n') else {
            return Err(UnrecognisedRule {
                line_number,
                line: rest.to_string(),
            });
        };
        rest = after;
        if line.starts_with(COUNTER_LINE_PREFIX) {
            let Some((rule_line, key, seen)) = pending.take() else {
                return Err(UnrecognisedCounters {
                    line_number,
                    line: line.to_string(),
                });
            };
            if line.starts_with("  [ Evaluations: ") {
                if seen.is_some() {
                    return Err(RepeatedCounters {
                        line_number: rule_line,
                    });
                }
                let counters = parse_counter_line(line).ok_or_else(|| UnrecognisedCounters {
                    line_number,
                    line: line.to_string(),
                })?;
                pending = Some((rule_line, key, Some(counters)));
            } else {
                // `[ Inserted: uid U pid P ]` and whatever else pfctl files
                // under a rule: not counters, not an error.
                pending = Some((rule_line, key, seen));
            }
            continue;
        }
        file(pending.take(), &mut entries)?;
        let rule = PfReadbackRule::parse_line(line).ok_or_else(|| UnrecognisedRule {
            line_number,
            line: line.to_string(),
        })?;
        pending = Some((line_number, rule.counter_key(), None));
    }
    file(pending.take(), &mut entries)?;
    PfCounterSnapshot::new(entries).map_err(|key| DuplicateKey { key })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use proptest::prelude::*;

    use super::super::SessionId;
    use super::super::agent_vm::{
        AgentNetworkPool, BrokerPort, BrokerPorts, IpFamily, Ipv4Cidr, Ipv6Cidr, PfCidr, PfHost,
        session_attached_pf_ruleset, session_firewall_pf_ruleset,
    };
    use super::super::pf_readback::render_pf_readback;
    use super::*;

    /// One rule of a verbose dump: the rule, its counters, and the padding
    /// pfctl's `%-8llu`-style columns leave, which this generator varies so
    /// the parser is held to "any run of spaces", not one width.
    #[derive(Clone, Debug)]
    struct VerboseRule {
        rule: PfReadbackRule,
        evaluations: u64,
        counters: PfCounters,
        states: u64,
        pads: [u8; 4],
        inserted: Option<(u32, u32)>,
    }

    /// Render as pfctl's `print_rule` does with `-v`: the rule, the counter
    /// line, and, unless suppressed, the `Inserted` line.
    fn render_verbose(rules: &[VerboseRule]) -> String {
        let mut out = String::new();
        for rule in rules {
            out.push_str(&render_pf_readback(std::slice::from_ref(&rule.rule)));
            out.push_str(&format!(
                "  [ Evaluations: {}{}Packets: {}{}Bytes: {}{}States: {}{}]\n",
                rule.evaluations,
                " ".repeat(usize::from(rule.pads[0]) + 1),
                rule.counters.packets,
                " ".repeat(usize::from(rule.pads[1]) + 1),
                rule.counters.bytes,
                " ".repeat(usize::from(rule.pads[2]) + 1),
                rule.states,
                " ".repeat(usize::from(rule.pads[3]) + 1),
            ));
            if let Some((uid, pid)) = rule.inserted {
                out.push_str(&format!("  [ Inserted: uid {uid} pid {pid} ]\n"));
            }
        }
        out
    }

    fn arb_counters() -> impl Strategy<Value = PfCounters> {
        prop_oneof![
            3 => (0u64..1000, 0u64..100_000),
            1 => (any::<u64>(), any::<u64>()),
        ]
        .prop_map(|(packets, bytes)| PfCounters { packets, bytes })
    }

    fn arb_verbose(rule: PfReadbackRule) -> impl Strategy<Value = VerboseRule> {
        (
            any::<u64>(),
            arb_counters(),
            0u64..100,
            any::<[u8; 4]>().prop_map(|pads| pads.map(|pad| pad % 12)),
            prop::option::of((any::<u32>(), any::<u32>())),
        )
            .prop_map(
                move |(evaluations, counters, states, pads, inserted)| VerboseRule {
                    rule: rule.clone(),
                    evaluations,
                    counters,
                    states,
                    pads,
                    inserted,
                },
            )
    }

    fn pool() -> AgentNetworkPool {
        AgentNetworkPool::new(
            Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            Ipv6Cidr::new(Ipv6Addr::new(0xfd00, 0x7772, 0x6974, 0, 0, 0, 0, 0), 48).unwrap(),
        )
        .unwrap()
    }

    /// The readback of a real session anchor: attached on a bridge with
    /// several members, or the bootstrap pair.
    fn arb_session_readback() -> impl Strategy<Value = Vec<PfReadbackRule>> {
        (
            any::<u128>(),
            prop::collection::btree_set(1024u16..=u16::MAX, 1..4),
            any::<u8>(),
            prop::option::of((0u16..1000, prop::collection::btree_set(0u16..1000, 1..4))),
        )
            .prop_map(|(session, ports, slot, attached)| {
                let session_id = SessionId::from_uuid(uuid::Uuid::from_u128(session));
                let ports =
                    BrokerPorts::new(ports.into_iter().map(|port| BrokerPort::new(port).unwrap()))
                        .unwrap();
                let ipv4 = Ipv4Cidr::new(Ipv4Addr::new(10, 200, slot, 0), 24).unwrap();
                let network = pool().claim_firewall(ipv4, None).unwrap();
                match attached {
                    Some((bridge, members)) => {
                        let interfaces: Vec<_> = std::iter::once(format!("bridge{bridge}"))
                            .chain(members.into_iter().map(|m| format!("vmenet{m}")))
                            .map(|name| PfInterface::new(name).unwrap())
                            .collect();
                        session_attached_pf_ruleset(session_id, network, &ports, None, &interfaces)
                            .unwrap()
                            .readback_rules()
                    }
                    None => session_firewall_pf_ruleset(session_id, network, &ports, None)
                        .readback_rules(),
                }
            })
    }

    fn arb_verbose_session() -> impl Strategy<Value = Vec<VerboseRule>> {
        arb_session_readback()
            .prop_flat_map(|rules| rules.into_iter().map(arb_verbose).collect::<Vec<_>>())
    }

    fn arb_label() -> impl Strategy<Value = String> {
        "[ -!#-~]{0,24}"
    }

    fn arb_interface() -> impl Strategy<Value = PfInterface> {
        "[a-zA-Z][a-zA-Z0-9]{0,14}".prop_map(|name| PfInterface::new(name).unwrap())
    }

    fn arb_key() -> impl Strategy<Value = PfCounterKey> {
        (arb_label(), prop::option::of(arb_interface()))
            .prop_map(|(label, interface)| PfCounterKey::new(label, interface).unwrap())
    }

    fn arb_snapshot() -> impl Strategy<Value = PfCounterSnapshot> {
        prop::collection::btree_map(arb_key(), arb_counters(), 0..8)
            .prop_map(|counters| PfCounterSnapshot { counters })
    }

    /// A pair of snapshots biased towards being comparable: most often the
    /// same keys with every counter risen, but also with a key dropped, a
    /// key added, or a counter fallen.
    fn arb_snapshot_pair() -> impl Strategy<Value = (PfCounterSnapshot, PfCounterSnapshot)> {
        (
            arb_snapshot(),
            prop::collection::vec(arb_counters(), 8),
            0u8..8,
            arb_key(),
            arb_counters(),
        )
            .prop_flat_map(|(earlier, rises, edit, new_key, new_counters)| {
                let mut later = earlier.counters.clone();
                for ((_, value), rise) in later.iter_mut().zip(rises) {
                    value.packets = value.packets.saturating_add(rise.packets);
                    value.bytes = value.bytes.saturating_add(rise.bytes);
                }
                let keys: Vec<_> = later.keys().cloned().collect();
                let pick = prop::sample::select(if keys.is_empty() {
                    vec![new_key.clone()]
                } else {
                    keys
                });
                (
                    Just(earlier),
                    Just(later),
                    Just(edit),
                    Just(new_key),
                    Just(new_counters),
                    pick,
                )
            })
            .prop_map(
                |(earlier, mut later, edit, new_key, new_counters, picked)| {
                    match edit {
                        0 => {
                            later.remove(&picked);
                        }
                        1 => {
                            later.insert(new_key, new_counters);
                        }
                        // A counter below its earlier reading; from zero there is
                        // nowhere lower to go, so that case stays a rise.
                        2 => {
                            if let (Some(before), Some(value)) =
                                (earlier.get(&picked), later.get_mut(&picked))
                            {
                                value.packets = before.packets.saturating_sub(1);
                            }
                        }
                        3 => {
                            if let (Some(before), Some(value)) =
                                (earlier.get(&picked), later.get_mut(&picked))
                            {
                                value.bytes = before.bytes.saturating_sub(1);
                            }
                        }
                        _ => {}
                    }
                    (earlier, PfCounterSnapshot { counters: later })
                },
            )
    }

    /// What `delta` must say, computed the slow way.
    fn reference_delta(
        earlier: &PfCounterSnapshot,
        later: &PfCounterSnapshot,
    ) -> Result<BTreeMap<PfCounterKey, PfCounters>, ()> {
        let same_keys = earlier.counters.keys().eq(later.counters.keys());
        if !same_keys {
            return Err(());
        }
        let mut out = BTreeMap::new();
        for (key, before) in &earlier.counters {
            let after = later.counters[key];
            if after.packets < before.packets || after.bytes < before.bytes {
                return Err(());
            }
            out.insert(
                key.clone(),
                PfCounters {
                    packets: after.packets - before.packets,
                    bytes: after.bytes - before.bytes,
                },
            );
        }
        Ok(out)
    }

    #[test]
    fn a_documented_verbose_dump_parses_to_its_labelled_counters() {
        let text = "pass in quick on bridge100 inet proto tcp from 10.200.7.0/24 to 10.200.7.1 port = 49152 flags S/SA keep state\n\
                    \x20 [ Evaluations: 12        Packets: 8         Bytes: 640        States: 1     ]\n\
                    \x20 [ Inserted: uid 0 pid 4242 ]\n\
                    block return in quick on bridge100 inet all label \"writ deny agent v4 iface\"\n\
                    \x20 [ Evaluations: 4         Packets: 3         Bytes: 180        States: 0     ]\n\
                    \x20 [ Inserted: uid 0 pid 4242 ]\n\
                    block return in quick on bridge100 inet6 all label \"writ deny agent v6 iface\"\n\
                    \x20 [ Evaluations: 0         Packets: 0         Bytes: 0          States: 0     ]\n\
                    \x20 [ Inserted: uid 0 pid 4242 ]\n";
        let snapshot = parse_pf_verbose_readback(text).unwrap();
        let bridge = PfInterface::new("bridge100").unwrap();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(
            snapshot
                .get(&PfCounterKey::new("writ deny agent v4 iface", Some(bridge.clone())).unwrap()),
            Some(PfCounters {
                packets: 3,
                bytes: 180
            })
        );
        assert_eq!(
            snapshot.get(&PfCounterKey::new("writ deny agent v6 iface", Some(bridge)).unwrap()),
            Some(PfCounters {
                packets: 0,
                bytes: 0
            })
        );
    }

    #[test]
    fn the_empty_dump_is_the_empty_snapshot() {
        assert_eq!(
            parse_pf_verbose_readback(""),
            Ok(PfCounterSnapshot::default())
        );
    }

    #[test]
    fn a_rule_without_a_counter_line_is_refused() {
        let rule =
            "block return in quick on bridge100 inet all label \"writ deny agent v4 iface\"\n";
        assert_eq!(
            parse_pf_verbose_readback(rule),
            Err(PfCountersParseError::MissingCounters { line_number: 1 })
        );
        let two_rules = format!("{rule}{rule}");
        assert_eq!(
            parse_pf_verbose_readback(&two_rules),
            Err(PfCountersParseError::MissingCounters { line_number: 1 })
        );
        let counters_first = "  [ Evaluations: 0  Packets: 0  Bytes: 0  States: 0  ]\n";
        assert_eq!(
            parse_pf_verbose_readback(counters_first),
            Err(PfCountersParseError::UnrecognisedCounters {
                line_number: 1,
                line: counters_first.trim_end().to_string(),
            })
        );
        let repeated = format!("{rule}{counters_first}{counters_first}");
        assert_eq!(
            parse_pf_verbose_readback(&repeated),
            Err(PfCountersParseError::RepeatedCounters { line_number: 1 })
        );
    }

    #[test]
    fn a_foreign_rule_is_refused_not_skipped() {
        let text = "block drop out all\n  [ Evaluations: 0  Packets: 0  Bytes: 0  States: 0  ]\n";
        assert_eq!(
            parse_pf_verbose_readback(text),
            Err(PfCountersParseError::UnrecognisedRule {
                line_number: 1,
                line: "block drop out all".to_string(),
            })
        );
    }

    proptest! {
        /// Every labelled rule's counters come back under its (label,
        /// interface) key, the unlabelled allows do not appear, and nothing
        /// else does.
        #[test]
        fn parsing_a_session_anchors_verbose_dump_recovers_every_labelled_counter(
            rules in arb_verbose_session(),
        ) {
            let text = render_verbose(&rules);
            let snapshot = parse_pf_verbose_readback(&text).unwrap();
            let expected: Vec<(PfCounterKey, PfCounters)> = rules
                .iter()
                .filter_map(|rule| rule.rule.counter_key().map(|key| (key, rule.counters)))
                .collect();
            prop_assert_eq!(snapshot.len(), expected.len());
            for (key, counters) in &expected {
                prop_assert_eq!(snapshot.get(key), Some(*counters), "{}", key);
            }
            let allows = rules
                .iter()
                .filter(|rule| matches!(rule.rule, PfReadbackRule::Allow { .. }))
                .count();
            prop_assert!(allows > 0, "the session generator always renders an allow");
            prop_assert!(
                snapshot.iter().all(|(key, _)| key.label().starts_with("writ deny agent ")),
                "{:?}", snapshot
            );
        }

        /// The same (label, interface) twice is an error naming the key, not
        /// a silently summed or overwritten counter.
        #[test]
        fn a_repeated_labelled_rule_is_refused(
            rules in arb_verbose_session(),
            pick in any::<prop::sample::Index>(),
        ) {
            let labelled: Vec<&VerboseRule> = rules
                .iter()
                .filter(|rule| rule.rule.counter_key().is_some())
                .collect();
            let duplicate = labelled[pick.index(labelled.len())].clone();
            let key = duplicate.rule.counter_key().unwrap();
            let mut with_duplicate = rules.clone();
            with_duplicate.push(duplicate);
            prop_assert_eq!(
                parse_pf_verbose_readback(&render_verbose(&with_duplicate)),
                Err(PfCountersParseError::DuplicateKey { key })
            );
        }

        /// `delta` is defined exactly when the key sets agree and nothing
        /// fell, and is then componentwise `later - earlier`.
        #[test]
        fn delta_agrees_with_the_reference((earlier, later) in arb_snapshot_pair()) {
            match (earlier.delta(&later), reference_delta(&earlier, &later)) {
                (Ok(delta), Ok(expected)) => {
                    prop_assert_eq!(delta.counters, expected);
                }
                (Err(err), Err(())) => {
                    match err {
                        PfCounterDeltaError::KeySetsDiffer { missing, extra } => {
                            prop_assert!(!missing.is_empty() || !extra.is_empty());
                            prop_assert!(missing.iter().all(|k| !later.counters.contains_key(k)));
                            prop_assert!(extra.iter().all(|k| !earlier.counters.contains_key(k)));
                        }
                        PfCounterDeltaError::Decreased { key, before, after } => {
                            prop_assert_eq!(earlier.get(&key), Some(before));
                            prop_assert_eq!(later.get(&key), Some(after));
                            prop_assert!(after.packets < before.packets || after.bytes < before.bytes);
                        }
                    }
                }
                (delta, expected) => prop_assert!(false, "delta {:?} vs reference {:?}", delta, expected),
            }
        }

        /// The delta from a snapshot to itself is all zeros.
        #[test]
        fn the_delta_to_the_same_snapshot_is_zero(snapshot in arb_snapshot()) {
            let delta = snapshot.delta(&snapshot).unwrap();
            prop_assert_eq!(delta.len(), snapshot.len());
            prop_assert!(delta.iter().all(|(_, rise)| rise == PfCounters::default()));
        }
    }

    /// The delta property is only evidence if the pairs reach every
    /// verdict; count them.
    #[test]
    fn the_snapshot_pair_generator_reaches_every_verdict() {
        use proptest::strategy::ValueTree;
        use proptest::test_runner::TestRunner;
        let mut runner = TestRunner::deterministic();
        let (mut defined, mut differ, mut decreased) = (0usize, 0usize, 0usize);
        for _ in 0..4000 {
            let (earlier, later) = arb_snapshot_pair().new_tree(&mut runner).unwrap().current();
            match earlier.delta(&later) {
                Ok(_) => defined += 1,
                Err(PfCounterDeltaError::KeySetsDiffer { .. }) => differ += 1,
                Err(PfCounterDeltaError::Decreased { .. }) => decreased += 1,
            }
        }
        assert!(defined >= 300, "defined {defined} of 4000");
        assert!(differ >= 300, "differ {differ} of 4000");
        assert!(decreased >= 300, "decreased {decreased} of 4000");
    }

    /// The generated verbose dumps exercise both anchors and both labels.
    #[test]
    fn the_verbose_session_generator_reaches_both_anchors() {
        use proptest::strategy::ValueTree;
        use proptest::test_runner::TestRunner;
        let mut runner = TestRunner::deterministic();
        let (mut attached, mut bootstrap) = (0usize, 0usize);
        for _ in 0..500 {
            let rules = arb_verbose_session()
                .new_tree(&mut runner)
                .unwrap()
                .current();
            let scoped = rules
                .iter()
                .any(|rule| matches!(rule.rule, PfReadbackRule::InterfaceDeny { .. }));
            if scoped {
                attached += 1;
            } else {
                bootstrap += 1;
            }
        }
        assert!(attached >= 100, "attached {attached} of 500");
        assert!(bootstrap >= 100, "bootstrap {bootstrap} of 500");
    }

    #[test]
    fn counter_keys_follow_the_rule_shape() {
        let interface = PfInterface::new("bridge100").unwrap();
        let allow = PfReadbackRule::Allow {
            interface: Some(interface.clone()),
            source: PfCidr::Inet(Ipv4Cidr::new(Ipv4Addr::new(10, 200, 7, 0), 24).unwrap()),
            destination: PfHost::Inet(Ipv4Addr::new(10, 200, 7, 1)),
            port: BrokerPort::new(49152).unwrap(),
        };
        assert_eq!(allow.counter_key(), None);
        let deny = PfReadbackRule::Deny {
            source: PfCidr::Inet(Ipv4Cidr::new(Ipv4Addr::new(10, 200, 7, 0), 24).unwrap()),
            label: "writ deny agent v4".to_string(),
        };
        assert_eq!(
            deny.counter_key(),
            PfCounterKey::new("writ deny agent v4", None)
        );
        let iface_deny = PfReadbackRule::InterfaceDeny {
            interface: interface.clone(),
            family: IpFamily::Inet6,
            label: "writ deny agent v6 iface".to_string(),
        };
        assert_eq!(
            iface_deny.counter_key(),
            PfCounterKey::new("writ deny agent v6 iface", Some(interface))
        );
        assert_eq!(PfCounterKey::new("has a \" quote", None), None);
    }
}
