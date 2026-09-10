//! A packet-decision model over a session anchor, as an oracle for the two
//! shapes [`session_firewall_pf_ruleset`] and [`session_attached_pf_ruleset`]
//! build.
//!
//! PF evaluates `quick` rules first-match-wins, and a packet no rule of the
//! anchor matches is left to whatever follows the anchor in the main ruleset.
//! [`decide`] is that evaluation over the inert [`PfRule`] list, so the
//! properties below can state what each anchor does to *every* packet rather
//! than what its text looks like: the attached anchor passes exactly the
//! intended broker tuple on a resolved interface and blocks everything else
//! there, whatever the source, and decides nothing on any other interface; the
//! bootstrap anchor passes the tuple and blocks the rest of the session
//! subnet's traffic wherever it arrives, and leaves an out-of-subnet source
//! undecided, which is why it is replaced. This is a model of PF's matching,
//! not PF; `tests/pf_readback_real_pfctl.rs` is where the real pfctl checks
//! the rule text, and the lifecycle proof is where the loaded anchor is
//! exercised.

use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;

use super::SessionId;
use super::agent_vm::{
    AgentFirewallNetwork, AgentNetworkPool, BrokerPort, BrokerPorts, IpFamily, Ipv4Cidr, Ipv6Cidr,
    PfCidr, PfHost, PfInterface, PfRule, PfRuleset, session_attached_pf_ruleset,
    session_firewall_pf_ruleset, session_pf_ruleset,
};

#[derive(Clone, Copy, Debug)]
enum Endpoints {
    Inet {
        source: Ipv4Addr,
        destination: Ipv4Addr,
    },
    Inet6 {
        source: Ipv6Addr,
        destination: Ipv6Addr,
    },
}

impl Endpoints {
    fn family(self) -> IpFamily {
        match self {
            Self::Inet { .. } => IpFamily::Inet,
            Self::Inet6 { .. } => IpFamily::Inet6,
        }
    }

    fn source_in(self, cidr: PfCidr) -> bool {
        match (self, cidr) {
            (Self::Inet { source, .. }, PfCidr::Inet(cidr)) => cidr.contains_addr(source),
            (Self::Inet6 { source, .. }, PfCidr::Inet6(cidr)) => cidr.contains_addr(source),
            _ => false,
        }
    }

    fn destination_is(self, host: PfHost) -> bool {
        match (self, host) {
            (Self::Inet { destination, .. }, PfHost::Inet(host)) => destination == host,
            (Self::Inet6 { destination, .. }, PfHost::Inet6(host)) => destination == host,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Transport {
    Tcp { destination_port: u16 },
    Other,
}

/// An inbound frame as PF sees it: the host interface it arrived on, its
/// addresses, and its transport.
#[derive(Clone, Debug)]
struct Packet {
    interface: PfInterface,
    endpoints: Endpoints,
    transport: Transport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    Pass,
    Block,
}

fn rule_matches(rule: &PfRule, broker_ports: &BrokerPorts, packet: &Packet) -> bool {
    match rule {
        PfRule::Allow(rule) => {
            let on_interface = rule
                .interface()
                .is_none_or(|interface| *interface == packet.interface);
            let to_broker_port = match packet.transport {
                Transport::Tcp { destination_port } => broker_ports
                    .as_slice()
                    .iter()
                    .any(|port| port.get() == destination_port),
                Transport::Other => false,
            };
            on_interface
                && packet.endpoints.source_in(rule.source())
                && packet.endpoints.destination_is(rule.destination())
                && to_broker_port
        }
        PfRule::Deny(rule) => packet.endpoints.source_in(rule.source()),
        PfRule::InterfaceDeny(rule) => {
            *rule.interface() == packet.interface && rule.family() == packet.endpoints.family()
        }
    }
}

/// First-match-wins over `quick` rules; `None` when the anchor does not
/// decide the packet.
fn decide(ruleset: &PfRuleset, packet: &Packet) -> Option<Verdict> {
    ruleset
        .rules()
        .iter()
        .find(|rule| rule_matches(rule, ruleset.broker_ports(), packet))
        .map(|rule| match rule {
            PfRule::Allow(_) => Verdict::Pass,
            PfRule::Deny(_) | PfRule::InterfaceDeny(_) => Verdict::Block,
        })
}

/// The one tuple a session may use: TCP from inside the subnet to the broker
/// host on a broker port.
fn intended(source: PfCidr, broker: PfHost, broker_ports: &BrokerPorts, packet: &Packet) -> bool {
    let to_broker_port = match packet.transport {
        Transport::Tcp { destination_port } => broker_ports
            .as_slice()
            .iter()
            .any(|port| port.get() == destination_port),
        Transport::Other => false,
    };
    packet.endpoints.source_in(source) && packet.endpoints.destination_is(broker) && to_broker_port
}

/// The facts the generators share with the property: what the anchor was
/// built from.
#[derive(Clone, Debug)]
struct Session {
    session_id: SessionId,
    ipv4: Ipv4Cidr,
    ipv6: Option<Ipv6Cidr>,
    broker_ports: BrokerPorts,
    broker_ipv4_host: Option<Ipv4Addr>,
}

impl Session {
    fn pool() -> AgentNetworkPool {
        AgentNetworkPool::new(
            Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            Ipv6Cidr::new(Ipv6Addr::new(0xfd00, 0x7772, 0x6974, 0, 0, 0, 0, 0), 48).unwrap(),
        )
        .unwrap()
    }

    fn network(&self) -> AgentFirewallNetwork {
        Self::pool().claim_firewall(self.ipv4, self.ipv6).unwrap()
    }

    fn broker_ipv4(&self) -> PfHost {
        PfHost::Inet(
            self.broker_ipv4_host
                .unwrap_or_else(|| self.network().ipv4_gateway()),
        )
    }

    fn broker_ipv6(&self) -> Option<PfHost> {
        self.ipv6
            .map(|ipv6| PfHost::Inet6(Ipv6Addr::from(u128::from(ipv6.network()) + 1)))
    }

    fn bootstrap(&self) -> PfRuleset {
        match self.ipv6 {
            // The dual-stack constructor is the same anchor through the
            // dual-stack network type; exercise it as its callers do.
            Some(ipv6) => {
                assert!(self.broker_ipv4_host.is_none());
                let network = Self::pool().claim(self.ipv4, ipv6).unwrap();
                session_pf_ruleset(self.session_id, network, &self.broker_ports)
            }
            None => session_firewall_pf_ruleset(
                self.session_id,
                self.network(),
                &self.broker_ports,
                self.broker_ipv4_host,
            ),
        }
    }

    fn attached(&self, interfaces: &[PfInterface]) -> PfRuleset {
        session_attached_pf_ruleset(
            self.session_id,
            self.network(),
            &self.broker_ports,
            self.broker_ipv4_host,
            interfaces,
        )
        .unwrap()
    }

    /// What the anchor exists to let through.
    fn intended(&self, packet: &Packet) -> bool {
        let v4 = intended(
            PfCidr::Inet(self.ipv4),
            self.broker_ipv4(),
            &self.broker_ports,
            packet,
        );
        let v6 = match (self.ipv6, self.broker_ipv6()) {
            (Some(ipv6), Some(broker)) => {
                intended(PfCidr::Inet6(ipv6), broker, &self.broker_ports, packet)
            }
            _ => false,
        };
        v4 || v6
    }

    /// Whether the packet's source is inside the session's subnet of its
    /// family: what the bootstrap anchor's denies match on.
    fn source_in_subnet(&self, packet: &Packet) -> bool {
        packet.endpoints.source_in(PfCidr::Inet(self.ipv4))
            || self
                .ipv6
                .is_some_and(|ipv6| packet.endpoints.source_in(PfCidr::Inet6(ipv6)))
    }
}

fn arb_session(dual_stack: bool) -> impl Strategy<Value = Session> {
    (
        any::<u128>(),
        prop::collection::btree_set(1024u16..=u16::MAX, 1..5),
        any::<u8>(),
        any::<u16>(),
        prop::option::of(1u8..=254),
    )
        .prop_map(
            move |(session, ports, v4_slot, v6_slot, broker_host)| Session {
                session_id: SessionId::from_uuid(uuid::Uuid::from_u128(session)),
                ipv4: Ipv4Cidr::new(Ipv4Addr::new(10, 200, v4_slot, 0), 24).unwrap(),
                ipv6: dual_stack.then(|| {
                    Ipv6Cidr::new(
                        Ipv6Addr::new(0xfd00, 0x7772, 0x6974, v6_slot, 0, 0, 0, 0),
                        64,
                    )
                    .unwrap()
                }),
                broker_ports: BrokerPorts::new(
                    ports.into_iter().map(|port| BrokerPort::new(port).unwrap()),
                )
                .unwrap(),
                // A broker host override is refused alongside an IPv6 scope.
                broker_ipv4_host: if dual_stack {
                    None
                } else {
                    broker_host.map(|host| Ipv4Addr::new(10, 200, v4_slot, host))
                },
            },
        )
}

/// The VM's resolved interfaces, named as the helper's discovery names them.
fn arb_resolved_interfaces() -> impl Strategy<Value = Vec<PfInterface>> {
    (0u16..1000, prop::collection::btree_set(0u16..1000, 1..4)).prop_map(|(bridge, members)| {
        std::iter::once(format!("bridge{bridge}"))
            .chain(members.into_iter().map(|member| format!("vmenet{member}")))
            .map(|name| PfInterface::new(name).unwrap())
            .collect()
    })
}

/// An interface that is never a resolved one: resolved names start with
/// `bridge` or `vmenet`, these never do.
fn arb_unrelated_interface() -> impl Strategy<Value = PfInterface> {
    prop_oneof![
        (0u8..10).prop_map(|n| format!("en{n}")),
        (0u8..10).prop_map(|n| format!("utun{n}")),
        Just("lo0".to_string()),
    ]
    .prop_map(|name| PfInterface::new(name).unwrap())
}

/// A packet biased towards the boundary: most often on a resolved interface,
/// IPv4, TCP, from inside the subnet, to the broker, on a broker port, with
/// each of those flipped a quarter of the time, so both verdicts and "no
/// verdict" are all reached (see `the_packet_generator_reaches_every_verdict`).
fn arb_packet(session: Session, resolved: Vec<PfInterface>) -> impl Strategy<Value = Packet> {
    let interface = prop_oneof![
        3 => prop::sample::select(resolved),
        1 => arb_unrelated_interface(),
    ];
    let v4_source = prop_oneof![
        3 => (0u8..=255).prop_map({
            let ipv4 = session.ipv4;
            move |host| Ipv4Addr::from(u32::from(ipv4.network()) | u32::from(host))
        }),
        1 => any::<u32>().prop_map(Ipv4Addr::from),
    ];
    let v4_destination = prop_oneof![
        3 => Just(match session.broker_ipv4() {
            PfHost::Inet(host) => host,
            PfHost::Inet6(_) => unreachable!(),
        }),
        1 => any::<u32>().prop_map(Ipv4Addr::from),
    ];
    let v6_prefix = session
        .ipv6
        .map(|ipv6| u128::from(ipv6.network()))
        .unwrap_or(0xfd00_7772_6974_0000_0000_0000_0000_0000);
    let v6_broker = session
        .broker_ipv6()
        .map(|host| match host {
            PfHost::Inet6(host) => host,
            PfHost::Inet(_) => unreachable!(),
        })
        .unwrap_or(Ipv6Addr::from(v6_prefix + 1));
    let v6_source = prop_oneof![
        3 => any::<u64>().prop_map(move |host| Ipv6Addr::from(v6_prefix | u128::from(host))),
        1 => any::<u128>().prop_map(Ipv6Addr::from),
    ];
    let v6_destination = prop_oneof![
        3 => Just(v6_broker),
        1 => any::<u128>().prop_map(Ipv6Addr::from),
    ];
    let endpoints = prop_oneof![
        7 => (v4_source, v4_destination).prop_map(|(source, destination)| Endpoints::Inet { source, destination }),
        1 => (v6_source, v6_destination).prop_map(|(source, destination)| Endpoints::Inet6 { source, destination }),
    ];
    let ports: Vec<u16> = session
        .broker_ports
        .as_slice()
        .iter()
        .map(|port| port.get())
        .collect();
    let transport = prop_oneof![
        6 => prop::sample::select(ports).prop_map(|destination_port| Transport::Tcp { destination_port }),
        2 => any::<u16>().prop_map(|destination_port| Transport::Tcp { destination_port }),
        1 => Just(Transport::Other),
    ];
    (interface, endpoints, transport).prop_map(|(interface, endpoints, transport)| Packet {
        interface,
        endpoints,
        transport,
    })
}

fn arb_attached_case() -> impl Strategy<Value = (Session, Vec<PfInterface>, Packet)> {
    (arb_session(false), arb_resolved_interfaces()).prop_flat_map(|(session, resolved)| {
        let packet = arb_packet(session.clone(), resolved.clone());
        (Just(session), Just(resolved), packet)
    })
}

fn arb_bootstrap_case() -> impl Strategy<Value = (Session, Packet)> {
    (any::<bool>(), arb_resolved_interfaces()).prop_flat_map(|(dual_stack, resolved)| {
        arb_session(dual_stack).prop_flat_map(move |session| {
            let packet = arb_packet(session.clone(), resolved.clone());
            (Just(session), packet)
        })
    })
}

proptest! {
    /// The attached anchor: on a resolved interface, exactly the intended
    /// tuple passes and everything else is blocked, whatever the source;
    /// on any other interface the anchor decides nothing.
    #[test]
    fn the_attached_anchor_decides_every_packet_on_its_interfaces_and_no_other(
        (session, resolved, packet) in arb_attached_case(),
    ) {
        let ruleset = session.attached(&resolved);
        let verdict = decide(&ruleset, &packet);
        if resolved.contains(&packet.interface) {
            let expected = if session.intended(&packet) { Verdict::Pass } else { Verdict::Block };
            prop_assert_eq!(verdict, Some(expected), "{:?}", packet);
        } else {
            prop_assert_eq!(verdict, None, "{:?}", packet);
        }
    }

    /// The bootstrap anchor: the intended tuple passes and the rest of the
    /// subnet's traffic is blocked wherever it arrives; a source outside the
    /// subnet is not decided at all.
    #[test]
    fn the_bootstrap_anchor_decides_by_source_subnet_only(
        (session, packet) in arb_bootstrap_case(),
    ) {
        let ruleset = session.bootstrap();
        let verdict = decide(&ruleset, &packet);
        let expected = if session.intended(&packet) {
            Some(Verdict::Pass)
        } else if session.source_in_subnet(&packet) {
            Some(Verdict::Block)
        } else {
            None
        };
        prop_assert_eq!(verdict, expected, "{:?}", packet);
    }

    /// The attached anchor's shape, rule by rule: per interface an IPv4
    /// allow for the broker tuple, an IPv4 deny, and an IPv6 deny, and no
    /// rule without an interface.
    #[test]
    fn the_attached_anchor_is_three_rules_per_interface_in_order(
        (session, resolved) in (arb_session(false), arb_resolved_interfaces()),
    ) {
        let ruleset = session.attached(&resolved);
        let rules = ruleset.rules();
        prop_assert_eq!(rules.len(), 3 * resolved.len());
        for (interface, group) in resolved.iter().zip(rules.chunks(3)) {
            match group {
                [PfRule::Allow(allow), PfRule::InterfaceDeny(v4), PfRule::InterfaceDeny(v6)] => {
                    prop_assert_eq!(allow.interface(), Some(interface));
                    prop_assert_eq!(allow.source(), PfCidr::Inet(session.ipv4));
                    prop_assert_eq!(allow.destination(), session.broker_ipv4());
                    prop_assert_eq!(v4.interface(), interface);
                    prop_assert_eq!(v4.family(), IpFamily::Inet);
                    prop_assert_eq!(v6.interface(), interface);
                    prop_assert_eq!(v6.family(), IpFamily::Inet6);
                }
                other => prop_assert!(false, "unexpected rule group: {:?}", other),
            }
        }
    }

    /// The bootstrap anchor's shape: the subnet-scoped allow and deny, and
    /// the IPv6 pair after them for a dual-stack scope; nothing carries an
    /// interface.
    #[test]
    fn the_bootstrap_anchor_is_the_subnet_scoped_pair(
        session in any::<bool>().prop_flat_map(arb_session),
    ) {
        let ruleset = session.bootstrap();
        let rules = ruleset.rules();
        let allows: Vec<_> = rules.iter().filter_map(|rule| match rule {
            PfRule::Allow(allow) => Some(allow),
            _ => None,
        }).collect();
        let denies: Vec<_> = rules.iter().filter_map(|rule| match rule {
            PfRule::Deny(deny) => Some(deny),
            _ => None,
        }).collect();
        let families = if session.ipv6.is_some() { 2 } else { 1 };
        prop_assert_eq!(rules.len(), 2 * families);
        prop_assert_eq!(allows.len(), families);
        prop_assert_eq!(denies.len(), families);
        prop_assert!(allows.iter().all(|allow| allow.interface().is_none()));
        prop_assert!(rules.iter().all(|rule| !matches!(rule, PfRule::InterfaceDeny(_))));
        prop_assert_eq!(allows[0].source(), PfCidr::Inet(session.ipv4));
        prop_assert_eq!(allows[0].destination(), session.broker_ipv4());
        prop_assert_eq!(denies[0].source(), PfCidr::Inet(session.ipv4));
        if let Some(ipv6) = session.ipv6 {
            prop_assert_eq!(allows[1].source(), PfCidr::Inet6(ipv6));
            prop_assert_eq!(Some(allows[1].destination()), session.broker_ipv6());
            prop_assert_eq!(denies[1].source(), PfCidr::Inet6(ipv6));
        }
    }
}

/// The two decision properties are only evidence if the packets reach every
/// verdict on both anchors; count them.
#[test]
fn the_packet_generator_reaches_every_verdict() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    const SAMPLES: usize = 4000;
    // Each expected share is well above a quarter of the samples' share of
    // the smallest arm; the thresholds are a fraction of the expected counts.
    const MIN: usize = 150;

    let mut attached = [0usize; 3];
    for _ in 0..SAMPLES {
        let (session, resolved, packet) =
            arb_attached_case().new_tree(&mut runner).unwrap().current();
        let index = match decide(&session.attached(&resolved), &packet) {
            Some(Verdict::Pass) => 0,
            Some(Verdict::Block) => 1,
            None => 2,
        };
        attached[index] += 1;
    }
    assert!(
        attached.iter().all(|count| *count >= MIN),
        "attached [pass, block, none] = {attached:?} of {SAMPLES}"
    );

    let mut bootstrap = [0usize; 3];
    for _ in 0..SAMPLES {
        let (session, packet) = arb_bootstrap_case()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let index = match decide(&session.bootstrap(), &packet) {
            Some(Verdict::Pass) => 0,
            Some(Verdict::Block) => 1,
            None => 2,
        };
        bootstrap[index] += 1;
    }
    assert!(
        bootstrap.iter().all(|count| *count >= MIN),
        "bootstrap [pass, block, none] = {bootstrap:?} of {SAMPLES}"
    );
}
