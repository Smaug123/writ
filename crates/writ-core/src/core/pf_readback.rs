//! A session anchor as `pfctl -a <anchor> -sr` prints it back.
//!
//! [`render_pf`](super::render_pf) produces the text the helper *loads*; PF
//! normalises it on the way in, so what `pfctl -sr` prints afterwards is a
//! different text: the `$broker_ports` macro is expanded into one `pass` rule
//! per port with `port = N`, and pfctl appends the `flags S/SA` default that
//! `keep state` on TCP implies. The privileged helper proves the loaded anchor
//! is exactly the intended one by parsing that readback into
//! [`PfReadbackRule`]s and comparing them for equality with
//! [`PfRuleset::readback_rules`], so both directions of the readback grammar
//! live here, next to the ruleset type, where they cannot drift apart.
//!
//! The grammar is exact: a line parses only if it is byte-for-byte what
//! [`render_pf_readback`] would print for the parsed rule. Anything else,
//! including an extra space or a rule shape this module does not render, is a
//! parse error, and the helper treats an unparseable readback as a failed
//! install rather than guessing what PF loaded.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::agent_vm::{
    BrokerPort, IpFamily, Ipv4Cidr, Ipv6Cidr, PfCidr, PfHost, PfInterface, PfRule, PfRuleset,
};

/// One rule of a session anchor, as `pfctl -sr` prints it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PfReadbackRule {
    /// `pass in quick [on <interface>] <af> proto tcp from <source> to <destination> port = <port> flags S/SA keep state`
    Allow {
        interface: Option<PfInterface>,
        source: PfCidr,
        destination: PfHost,
        port: BrokerPort,
    },
    /// `block return in quick <af> from <source> to any label "<label>"`
    Deny { source: PfCidr, label: String },
    /// `block return in quick on <interface> <af> all label "<label>"`
    InterfaceDeny {
        interface: PfInterface,
        family: IpFamily,
        label: String,
    },
}

/// Why a `pfctl -sr` readback did not parse as a session anchor.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PfReadbackParseError {
    /// The line is not one of the three rule shapes a session anchor holds,
    /// spelled exactly as pfctl prints them.
    #[error("readback line {line_number} is not a session anchor rule: {line:?}")]
    UnrecognisedRule { line_number: usize, line: String },
}

impl PfRuleset {
    /// The rules `pfctl -sr` prints once this ruleset is loaded, in load
    /// order, with each allow expanded into one rule per broker port.
    pub fn readback_rules(&self) -> Vec<PfReadbackRule> {
        let mut rules = Vec::new();
        for rule in self.rules() {
            match rule {
                PfRule::Allow(allow) => {
                    for port in self.broker_ports().as_slice() {
                        rules.push(PfReadbackRule::Allow {
                            interface: allow.interface().cloned(),
                            source: allow.source(),
                            destination: allow.destination(),
                            port: *port,
                        });
                    }
                }
                PfRule::Deny(deny) => rules.push(PfReadbackRule::Deny {
                    source: deny.source(),
                    label: deny.label().to_string(),
                }),
                PfRule::InterfaceDeny(deny) => rules.push(PfReadbackRule::InterfaceDeny {
                    interface: deny.interface().clone(),
                    family: deny.family(),
                    label: deny.label().to_string(),
                }),
            }
        }
        rules
    }
}

impl PfReadbackRule {
    fn render_line(&self) -> String {
        match self {
            Self::Allow {
                interface,
                source,
                destination,
                port,
            } => format!(
                "pass in quick {}{} proto tcp from {source} to {destination} port = {} flags S/SA keep state",
                interface
                    .as_ref()
                    .map(|interface| format!("on {interface} "))
                    .unwrap_or_default(),
                source.family().pf_name(),
                port.get(),
            ),
            Self::Deny { source, label } => format!(
                "block return in quick {} from {source} to any label \"{label}\"",
                source.family().pf_name(),
            ),
            Self::InterfaceDeny {
                interface,
                family,
                label,
            } => format!(
                "block return in quick on {interface} {} all label \"{label}\"",
                family.pf_name(),
            ),
        }
    }

    pub(crate) fn parse_line(line: &str) -> Option<Self> {
        if let Some(rest) = line.strip_prefix("pass in quick ") {
            return Self::parse_allow(rest);
        }
        if let Some(rest) = line.strip_prefix("block return in quick on ") {
            return Self::parse_interface_deny(rest);
        }
        if let Some(rest) = line.strip_prefix("block return in quick ") {
            return Self::parse_deny(rest);
        }
        None
    }

    /// `[on <interface> ]<af> proto tcp from <source> to <destination> port = <port> flags S/SA keep state`
    fn parse_allow(rest: &str) -> Option<Self> {
        let (interface, rest) = match rest.strip_prefix("on ") {
            Some(rest) => {
                let (interface, rest) = rest.split_once(' ')?;
                (Some(PfInterface::new(interface).ok()?), rest)
            }
            None => (None, rest),
        };
        let (family, rest) = parse_family(rest)?;
        let rest = rest.strip_prefix("proto tcp from ")?;
        let (source, rest) = rest.split_once(" to ")?;
        let source = parse_cidr(family, source)?;
        let (destination, rest) = rest.split_once(" port = ")?;
        let destination = parse_host(family, destination)?;
        let port = rest.strip_suffix(" flags S/SA keep state")?;
        let port = parse_port(port)?;
        Some(Self::Allow {
            interface,
            source,
            destination,
            port,
        })
    }

    /// `<af> from <source> to any label "<label>"`
    fn parse_deny(rest: &str) -> Option<Self> {
        let (family, rest) = parse_family(rest)?;
        let rest = rest.strip_prefix("from ")?;
        let (source, rest) = rest.split_once(" to any label ")?;
        let source = parse_cidr(family, source)?;
        let label = parse_label(rest)?;
        Some(Self::Deny { source, label })
    }

    /// `<interface> <af> all label "<label>"`
    fn parse_interface_deny(rest: &str) -> Option<Self> {
        let (interface, rest) = rest.split_once(' ')?;
        let interface = PfInterface::new(interface).ok()?;
        let (family, rest) = parse_family(rest)?;
        let rest = rest.strip_prefix("all label ")?;
        let label = parse_label(rest)?;
        Some(Self::InterfaceDeny {
            interface,
            family,
            label,
        })
    }
}

/// `inet ` or `inet6 `, returning the family and what follows the space.
fn parse_family(rest: &str) -> Option<(IpFamily, &str)> {
    if let Some(rest) = rest.strip_prefix("inet6 ") {
        Some((IpFamily::Inet6, rest))
    } else {
        rest.strip_prefix("inet ")
            .map(|rest| (IpFamily::Inet, rest))
    }
}

/// `<network>/<prefix>` in the given family, refusing host bits and any
/// non-canonical spelling of the address (Rust's `Display` is the canonical
/// one, and pfctl's `inet_ntop` output agrees with it).
fn parse_cidr(family: IpFamily, text: &str) -> Option<PfCidr> {
    let (address, prefix) = text.split_once('/')?;
    let prefix = parse_decimal_u8(prefix)?;
    let cidr = match family {
        IpFamily::Inet => {
            let address = parse_canonical::<Ipv4Addr>(address)?;
            PfCidr::Inet(Ipv4Cidr::new(address, prefix).ok()?)
        }
        IpFamily::Inet6 => {
            let address = parse_canonical::<Ipv6Addr>(address)?;
            PfCidr::Inet6(Ipv6Cidr::new(address, prefix).ok()?)
        }
    };
    (cidr.to_string() == text).then_some(cidr)
}

fn parse_host(family: IpFamily, text: &str) -> Option<PfHost> {
    match family {
        IpFamily::Inet => parse_canonical::<Ipv4Addr>(text).map(PfHost::Inet),
        IpFamily::Inet6 => parse_canonical::<Ipv6Addr>(text).map(PfHost::Inet6),
    }
}

/// Parse and require the canonical spelling: `Ipv6Addr::from_str` accepts
/// uncompressed and mixed-case forms that neither pfctl nor this module ever
/// prints.
fn parse_canonical<T: std::str::FromStr + std::fmt::Display>(text: &str) -> Option<T> {
    let value = text.parse::<T>().ok()?;
    (value.to_string() == text).then_some(value)
}

/// A decimal without sign, leading zeros, or surrounding whitespace.
fn is_canonical_decimal(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text.len() == 1 || !text.starts_with('0'))
}

fn parse_decimal_u8(text: &str) -> Option<u8> {
    is_canonical_decimal(text)
        .then(|| text.parse().ok())
        .flatten()
}

fn parse_port(text: &str) -> Option<BrokerPort> {
    if !is_canonical_decimal(text) {
        return None;
    }
    // A port below 1024 cannot be one this crate rendered.
    BrokerPort::new(text.parse().ok()?).ok()
}

/// `"<label>"`, where the label is printable ASCII without a double quote:
/// pfctl prints labels verbatim, so a label that needed escaping could not be
/// read back unambiguously, and the renderer never emits one.
fn parse_label(text: &str) -> Option<String> {
    let label = text.strip_prefix('"')?.strip_suffix('"')?;
    is_valid_label(label).then(|| label.to_string())
}

/// The labels this grammar can round-trip: printable ASCII, no `"`.
pub fn is_valid_label(label: &str) -> bool {
    label
        .bytes()
        .all(|b| (0x20..0x7f).contains(&b) && b != b'"')
}

/// Render rules exactly as `pfctl -sr` prints them: one per line, each
/// newline-terminated, nothing else.
pub fn render_pf_readback(rules: &[PfReadbackRule]) -> String {
    let mut out = String::new();
    for rule in rules {
        out.push_str(&rule.render_line());
        out.push('\n');
    }
    out
}

/// Parse a `pfctl -a <anchor> -sr` dump. Accepts exactly the strings
/// [`render_pf_readback`] produces: every line must be one rule as pfctl
/// prints it, and the text ends with the last rule's newline (an empty dump is
/// the empty rule list). A rule this module does not render, or any other
/// spelling of one it does, is an error naming the line.
pub fn parse_pf_readback(text: &str) -> Result<Vec<PfReadbackRule>, PfReadbackParseError> {
    let mut rules = Vec::new();
    let mut rest = text;
    let mut line_number = 0;
    while !rest.is_empty() {
        line_number += 1;
        // Without a terminating newline the last line is not what pfctl
        // printed, so refuse it rather than accept a truncated dump.
        let Some((line, after)) = rest.split_once('\n') else {
            return Err(PfReadbackParseError::UnrecognisedRule {
                line_number,
                line: rest.to_string(),
            });
        };
        rest = after;
        match PfReadbackRule::parse_line(line) {
            Some(rule) => rules.push(rule),
            None => {
                return Err(PfReadbackParseError::UnrecognisedRule {
                    line_number,
                    line: line.to_string(),
                });
            }
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::super::SessionId;
    use super::super::agent_vm::{
        AgentNetworkPool, BrokerPorts, session_attached_pf_ruleset, session_firewall_pf_ruleset,
        session_pf_ruleset,
    };
    use super::*;

    fn arb_ipv4_cidr() -> impl Strategy<Value = Ipv4Cidr> {
        (any::<u32>(), 0u8..=32).prop_map(|(raw, prefix)| {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Ipv4Cidr::new(Ipv4Addr::from(raw & mask), prefix).unwrap()
        })
    }

    /// Biased toward addresses with zero runs, so RFC 5952 compression (the
    /// place where two address printers could disagree) is exercised.
    fn arb_ipv6_addr() -> impl Strategy<Value = Ipv6Addr> {
        prop::collection::vec(prop_oneof![3 => Just(0u16), 2 => any::<u16>()], 8).prop_map(
            |segments| {
                let mut raw = [0u16; 8];
                raw.copy_from_slice(&segments);
                Ipv6Addr::from(raw)
            },
        )
    }

    fn arb_ipv6_cidr() -> impl Strategy<Value = Ipv6Cidr> {
        (arb_ipv6_addr(), 0u8..=128).prop_map(|(addr, prefix)| {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            Ipv6Cidr::new(Ipv6Addr::from(u128::from(addr) & mask), prefix).unwrap()
        })
    }

    fn arb_port() -> impl Strategy<Value = BrokerPort> {
        (1024u16..=u16::MAX).prop_map(|port| BrokerPort::new(port).unwrap())
    }

    fn arb_label() -> impl Strategy<Value = String> {
        "[ -!#-~]{0,40}"
    }

    fn arb_interface() -> impl Strategy<Value = PfInterface> {
        "[a-zA-Z][a-zA-Z0-9]{0,14}".prop_map(|name| PfInterface::new(name).unwrap())
    }

    fn arb_family() -> impl Strategy<Value = IpFamily> {
        prop_oneof![Just(IpFamily::Inet), Just(IpFamily::Inet6)]
    }

    fn arb_rule() -> impl Strategy<Value = PfReadbackRule> {
        prop_oneof![
            (
                prop::option::of(arb_interface()),
                arb_ipv4_cidr(),
                any::<u32>(),
                arb_port()
            )
                .prop_map(|(interface, source, dst, port)| PfReadbackRule::Allow {
                    interface,
                    source: PfCidr::Inet(source),
                    destination: PfHost::Inet(Ipv4Addr::from(dst)),
                    port,
                }),
            (
                prop::option::of(arb_interface()),
                arb_ipv6_cidr(),
                arb_ipv6_addr(),
                arb_port()
            )
                .prop_map(|(interface, source, dst, port)| PfReadbackRule::Allow {
                    interface,
                    source: PfCidr::Inet6(source),
                    destination: PfHost::Inet6(dst),
                    port,
                }),
            (arb_ipv4_cidr(), arb_label()).prop_map(|(source, label)| PfReadbackRule::Deny {
                source: PfCidr::Inet(source),
                label,
            }),
            (arb_ipv6_cidr(), arb_label()).prop_map(|(source, label)| PfReadbackRule::Deny {
                source: PfCidr::Inet6(source),
                label,
            }),
            (arb_interface(), arb_family(), arb_label()).prop_map(|(interface, family, label)| {
                PfReadbackRule::InterfaceDeny {
                    interface,
                    family,
                    label,
                }
            }),
        ]
    }

    fn arb_rules() -> impl Strategy<Value = Vec<PfReadbackRule>> {
        prop::collection::vec(arb_rule(), 0..12)
    }

    /// A real session ruleset, as the shipped renderer builds it: any pool,
    /// any subnet in it, an IPv4-only or dual-stack bootstrap anchor with an
    /// optional broker host override, or the attached anchor on any number
    /// of interfaces.
    fn arb_session_ruleset() -> impl Strategy<Value = PfRuleset> {
        (
            any::<u128>(),
            prop::collection::btree_set(1024u16..=u16::MAX, 1..6),
            any::<u8>(),
            any::<u16>(),
            any::<bool>(),
            prop::option::of(1u8..=254),
            prop::collection::vec(arb_interface(), 0..4),
        )
            .prop_map(
                |(session, ports, v4_slot, v6_slot, dual_stack, broker_host, interfaces)| {
                    let session_id = SessionId::from_uuid(uuid::Uuid::from_u128(session));
                    let ports = BrokerPorts::new(
                        ports.into_iter().map(|port| BrokerPort::new(port).unwrap()),
                    )
                    .unwrap();
                    let pool = AgentNetworkPool::new(
                        Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                        Ipv6Cidr::new(Ipv6Addr::new(0xfd00, 0x7772, 0x6974, 0, 0, 0, 0, 0), 48)
                            .unwrap(),
                    )
                    .unwrap();
                    let ipv4 = Ipv4Cidr::new(Ipv4Addr::new(10, 200, v4_slot, 0), 24).unwrap();
                    let ipv6 = Ipv6Cidr::new(
                        Ipv6Addr::new(0xfd00, 0x7772, 0x6974, v6_slot, 0, 0, 0, 0),
                        64,
                    )
                    .unwrap();
                    if dual_stack {
                        // The dual-stack scope: no broker override, no
                        // interface denies (both are refused with an IPv6
                        // scope by the shell's constructor).
                        let network = pool.claim(ipv4, ipv6).unwrap();
                        session_pf_ruleset(session_id, network, &ports)
                    } else {
                        let network = pool.claim_firewall(ipv4, None).unwrap();
                        let broker_host =
                            broker_host.map(|host| Ipv4Addr::new(10, 200, v4_slot, host));
                        if interfaces.is_empty() {
                            session_firewall_pf_ruleset(session_id, network, &ports, broker_host)
                        } else {
                            session_attached_pf_ruleset(
                                session_id,
                                network,
                                &ports,
                                broker_host,
                                &interfaces,
                            )
                            .unwrap()
                        }
                    }
                },
            )
    }

    #[test]
    fn readback_of_the_documented_session_is_the_pfctl_normal_form() {
        let session_id = SessionId::from_uuid(
            uuid::Uuid::parse_str("0e3a2b52-0a2d-4f7c-9b9e-1d9c3e4f5a6b").unwrap(),
        );
        let pool = AgentNetworkPool::new(
            Ipv4Cidr::new(Ipv4Addr::new(10, 200, 0, 0), 16).unwrap(),
            Ipv6Cidr::new(Ipv6Addr::new(0xfd00, 0x7772, 0x6974, 0, 0, 0, 0, 0), 48).unwrap(),
        )
        .unwrap();
        let network = pool
            .claim_firewall(
                Ipv4Cidr::new(Ipv4Addr::new(10, 200, 7, 0), 24).unwrap(),
                None,
            )
            .unwrap();
        let ports = BrokerPorts::new([
            BrokerPort::new(49153).unwrap(),
            BrokerPort::new(49152).unwrap(),
        ])
        .unwrap();
        let interfaces = [
            PfInterface::new("bridge100").unwrap(),
            PfInterface::new("vmenet0").unwrap(),
        ];
        let bootstrap = session_firewall_pf_ruleset(session_id, network, &ports, None);
        // What `pfctl -nvf` printed for the rendered file on macOS 15: the
        // macro expanded per port in ascending order, `port = N`, and the
        // `flags S/SA` default made explicit.
        let expected = "pass in quick inet proto tcp from 10.200.7.0/24 to 10.200.7.1 port = 49152 flags S/SA keep state\n\
                        pass in quick inet proto tcp from 10.200.7.0/24 to 10.200.7.1 port = 49153 flags S/SA keep state\n\
                        block return in quick inet from 10.200.7.0/24 to any label \"writ deny agent v4\"\n";
        assert_eq!(render_pf_readback(&bootstrap.readback_rules()), expected);
        assert_eq!(parse_pf_readback(expected), Ok(bootstrap.readback_rules()));

        let attached =
            session_attached_pf_ruleset(session_id, network, &ports, None, &interfaces).unwrap();
        // What `pfctl -nvf` printed on macOS 26 for the attached anchor: the
        // interface scope precedes the family, and `all` stays `all`.
        let expected = "pass in quick on bridge100 inet proto tcp from 10.200.7.0/24 to 10.200.7.1 port = 49152 flags S/SA keep state\n\
                        pass in quick on bridge100 inet proto tcp from 10.200.7.0/24 to 10.200.7.1 port = 49153 flags S/SA keep state\n\
                        block return in quick on bridge100 inet all label \"writ deny agent v4 iface\"\n\
                        block return in quick on bridge100 inet6 all label \"writ deny agent v6 iface\"\n\
                        pass in quick on vmenet0 inet proto tcp from 10.200.7.0/24 to 10.200.7.1 port = 49152 flags S/SA keep state\n\
                        pass in quick on vmenet0 inet proto tcp from 10.200.7.0/24 to 10.200.7.1 port = 49153 flags S/SA keep state\n\
                        block return in quick on vmenet0 inet all label \"writ deny agent v4 iface\"\n\
                        block return in quick on vmenet0 inet6 all label \"writ deny agent v6 iface\"\n";
        assert_eq!(render_pf_readback(&attached.readback_rules()), expected);
        assert_eq!(parse_pf_readback(expected), Ok(attached.readback_rules()));
    }

    #[test]
    fn the_empty_dump_is_the_empty_rule_list() {
        assert_eq!(parse_pf_readback(""), Ok(Vec::new()));
        assert_eq!(render_pf_readback(&[]), "");
    }

    proptest! {
        #[test]
        fn parse_inverts_render(rules in arb_rules()) {
            let text = render_pf_readback(&rules);
            prop_assert_eq!(parse_pf_readback(&text), Ok(rules));
        }

        #[test]
        fn a_session_ruleset_reads_back_as_itself(ruleset in arb_session_ruleset()) {
            let rules = ruleset.readback_rules();
            let text = render_pf_readback(&rules);
            prop_assert_eq!(parse_pf_readback(&text), Ok(rules.clone()));
            // Each allow becomes one rule per port and each deny one rule, in
            // load order: the readback carries the whole ruleset.
            let ports = ruleset.broker_ports().as_slice().len();
            let expected: Vec<usize> = ruleset
                .rules()
                .iter()
                .map(|rule| match rule {
                    PfRule::Allow(_) => ports,
                    PfRule::Deny(_) | PfRule::InterfaceDeny(_) => 1,
                })
                .collect();
            let mut actual = Vec::new();
            let mut rest = rules.as_slice();
            for rule in ruleset.rules() {
                let n = match rule {
                    PfRule::Allow(_) => ports,
                    PfRule::Deny(_) | PfRule::InterfaceDeny(_) => 1,
                };
                let (head, tail) = rest.split_at(n.min(rest.len()));
                let same_kind = head.iter().all(|read| matches!(
                    (rule, read),
                    (PfRule::Allow(_), PfReadbackRule::Allow { .. })
                        | (PfRule::Deny(_), PfReadbackRule::Deny { .. })
                        | (PfRule::InterfaceDeny(_), PfReadbackRule::InterfaceDeny { .. })
                ));
                prop_assert!(same_kind, "readback rules out of order: {:?}", rules);
                actual.push(head.len());
                rest = tail;
            }
            prop_assert_eq!(actual, expected);
            prop_assert!(rest.is_empty(), "readback has extra rules: {:?}", rest);
        }

        /// Exactness: whatever the parser accepts, it accepts as exactly one
        /// rendering. Inputs are rendered dumps with random byte-level edits,
        /// so the accepted set is probed from both sides.
        #[test]
        fn anything_accepted_renders_back_to_itself((text, edited) in arb_edited_dump()) {
            match parse_pf_readback(&text) {
                Ok(rules) => prop_assert_eq!(render_pf_readback(&rules), text.clone()),
                Err(PfReadbackParseError::UnrecognisedRule { line_number, line }) => {
                    prop_assert!(edited, "an unedited dump was refused at line {line_number}: {line:?}");
                }
            }
        }
    }

    /// The edit property is only evidence if the edits land on both sides of
    /// the boundary; check the generator actually reaches both.
    #[test]
    fn the_edited_dump_generator_reaches_both_verdicts() {
        use proptest::strategy::ValueTree;
        use proptest::test_runner::TestRunner;
        let mut runner = TestRunner::deterministic();
        let (mut accepted, mut refused) = (0usize, 0usize);
        for _ in 0..2000 {
            let (text, _) = arb_edited_dump().new_tree(&mut runner).unwrap().current();
            match parse_pf_readback(&text) {
                Ok(_) => accepted += 1,
                Err(_) => refused += 1,
            }
        }
        assert!(accepted >= 200, "accepted {accepted} of 2000");
        assert!(refused >= 200, "refused {refused} of 2000");
    }

    /// A rendered dump, optionally with one byte-level edit: an inserted
    /// space, a deleted byte, a case flip, or a replaced byte. `edited` says
    /// whether any edit was applied, so a refusal of an unedited dump can be
    /// told apart from a refusal the edit caused.
    fn arb_edited_dump() -> impl Strategy<Value = (String, bool)> {
        (
            arb_rules(),
            prop::option::of((any::<prop::sample::Index>(), 0u8..4, any::<u8>())),
        )
            .prop_map(|(rules, edit)| {
                let text = render_pf_readback(&rules);
                let Some((index, kind, byte)) = edit else {
                    return (text, false);
                };
                if text.is_empty() {
                    return (text, false);
                }
                let mut bytes = text.into_bytes();
                let at = index.index(bytes.len());
                match kind {
                    0 => bytes.insert(at, b' '),
                    1 => {
                        bytes.remove(at);
                    }
                    2 => bytes[at] = bytes[at].to_ascii_uppercase(),
                    _ => bytes[at] = byte,
                }
                (String::from_utf8_lossy(&bytes).into_owned(), true)
            })
    }
}
