//! Pure data model for the future Apple-container agent VM isolation layer.
//!
//! This module deliberately does not call `container`, `pfctl`, or any
//! privileged helper. It describes the session network and the PF rules we
//! intend to install; an imperative edge can interpret those descriptions
//! later.
//!
//! TODO: add the matching teardown description before wiring this to a helper:
//! the helper must be able to flush the session anchor and kill live PF states
//! for the allocated session subnets.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::SessionId;

const AGENT_IPV4_PREFIX: u8 = 24;
const AGENT_IPV6_PREFIX: u8 = 64;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix: u8,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipv6Cidr {
    network: Ipv6Addr,
    prefix: u8,
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BrokerPort(u16);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerPorts(Vec<BrokerPort>);

/// A session network that was allocated from an [`AgentNetworkPool`].
///
/// Fields are private and the constructor is private so the type carries the
/// proof that the network came from the broker-managed pool.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AgentNetwork {
    ipv4: Ipv4Cidr,
    ipv6: Ipv6Cidr,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AgentNetworkPool {
    ipv4_base: Ipv4Cidr,
    ipv6_base: Ipv6Cidr,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IpFamily {
    Inet,
    Inet6,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PfCidr {
    Inet(Ipv4Cidr),
    Inet6(Ipv6Cidr),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfAnchorName(String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfAllowRule {
    source: PfCidr,
    destination_ports: BrokerPorts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfDenyRule {
    source: PfCidr,
    label: String,
}

/// Inert PF ruleset description for one agent session.
///
/// `anchor` names the PF anchor the helper should load this ruleset into. It
/// is not rendered inside the rules body; the helper supplies it to `pfctl`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfRuleset {
    anchor: PfAnchorName,
    allow: Vec<PfAllowRule>,
    deny: Vec<PfDenyRule>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AgentVmConfigError {
    #[error("invalid CIDR prefix {prefix}; maximum is {max}")]
    PrefixOutOfRange { prefix: u8, max: u8 },
    #[error("CIDR address {address}/{prefix} is not the network address")]
    HostBitsSet { address: String, prefix: u8 },
    #[error("agent IPv4 subnets must be /24, got /{0}")]
    AgentIpv4Prefix(u8),
    #[error("agent IPv6 subnets must be /64, got /{0}")]
    AgentIpv6Prefix(u8),
    #[error("agent IPv4 pool prefix must not be longer than /24, got /{0}")]
    AgentIpv4PoolPrefix(u8),
    #[error("agent IPv6 pool prefix must not be longer than /64, got /{0}")]
    AgentIpv6PoolPrefix(u8),
    #[error("agent IPv4 pool must be inside RFC1918 private space, got {0}")]
    NonPrivateIpv4Pool(Ipv4Cidr),
    #[error("agent IPv6 pool must be inside fc00::/7 ULA space, got {0}")]
    NonUlaIpv6Pool(Ipv6Cidr),
    #[error("broker port 0 asks the OS to choose a port and is not a stable broker endpoint")]
    BrokerPortZero,
    #[error("broker port must be unprivileged, got {0}")]
    PrivilegedBrokerPort(u16),
    #[error("at least one broker port is required")]
    EmptyBrokerPorts,
    #[error("subnet index {index} does not fit inside base prefix /{base_prefix}")]
    SubnetIndexOutOfRange { index: u16, base_prefix: u8 },
}

impl Ipv4Cidr {
    pub fn new(network: Ipv4Addr, prefix: u8) -> Result<Self, AgentVmConfigError> {
        if prefix > 32 {
            return Err(AgentVmConfigError::PrefixOutOfRange { prefix, max: 32 });
        }
        let raw = u32::from(network);
        if raw & !ipv4_mask(prefix) != 0 {
            return Err(AgentVmConfigError::HostBitsSet {
                address: network.to_string(),
                prefix,
            });
        }
        Ok(Self { network, prefix })
    }

    pub fn network(self) -> Ipv4Addr {
        self.network
    }

    pub fn prefix(self) -> u8 {
        self.prefix
    }

    pub fn contains_subnet(self, other: Self) -> bool {
        self.prefix <= other.prefix
            && (u32::from(other.network) & ipv4_mask(self.prefix)) == u32::from(self.network)
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

impl Ipv6Cidr {
    pub fn new(network: Ipv6Addr, prefix: u8) -> Result<Self, AgentVmConfigError> {
        if prefix > 128 {
            return Err(AgentVmConfigError::PrefixOutOfRange { prefix, max: 128 });
        }
        let raw = u128::from(network);
        if raw & !ipv6_mask(prefix) != 0 {
            return Err(AgentVmConfigError::HostBitsSet {
                address: network.to_string(),
                prefix,
            });
        }
        Ok(Self { network, prefix })
    }

    pub fn network(self) -> Ipv6Addr {
        self.network
    }

    pub fn prefix(self) -> u8 {
        self.prefix
    }

    pub fn contains_subnet(self, other: Self) -> bool {
        self.prefix <= other.prefix
            && (u128::from(other.network) & ipv6_mask(self.prefix)) == u128::from(self.network)
    }
}

impl std::fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

impl BrokerPort {
    pub fn new(port: u16) -> Result<Self, AgentVmConfigError> {
        if port == 0 {
            return Err(AgentVmConfigError::BrokerPortZero);
        }
        if port < 1024 {
            return Err(AgentVmConfigError::PrivilegedBrokerPort(port));
        }
        Ok(Self(port))
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

impl BrokerPorts {
    pub fn new(ports: impl IntoIterator<Item = BrokerPort>) -> Result<Self, AgentVmConfigError> {
        let unique: BTreeSet<_> = ports.into_iter().collect();
        if unique.is_empty() {
            return Err(AgentVmConfigError::EmptyBrokerPorts);
        }
        Ok(Self(unique.into_iter().collect()))
    }

    pub fn as_slice(&self) -> &[BrokerPort] {
        &self.0
    }

    fn render_pf_set(&self) -> String {
        self.0
            .iter()
            .map(|p| p.get().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl AgentNetwork {
    fn new(ipv4: Ipv4Cidr, ipv6: Ipv6Cidr) -> Result<Self, AgentVmConfigError> {
        if ipv4.prefix != AGENT_IPV4_PREFIX {
            return Err(AgentVmConfigError::AgentIpv4Prefix(ipv4.prefix));
        }
        if ipv6.prefix != AGENT_IPV6_PREFIX {
            return Err(AgentVmConfigError::AgentIpv6Prefix(ipv6.prefix));
        }
        Ok(Self { ipv4, ipv6 })
    }

    pub fn ipv4(self) -> Ipv4Cidr {
        self.ipv4
    }

    pub fn ipv6(self) -> Ipv6Cidr {
        self.ipv6
    }
}

impl AgentNetworkPool {
    pub fn new(ipv4_base: Ipv4Cidr, ipv6_base: Ipv6Cidr) -> Result<Self, AgentVmConfigError> {
        if ipv4_base.prefix > AGENT_IPV4_PREFIX {
            return Err(AgentVmConfigError::AgentIpv4PoolPrefix(ipv4_base.prefix));
        }
        if ipv6_base.prefix > AGENT_IPV6_PREFIX {
            return Err(AgentVmConfigError::AgentIpv6PoolPrefix(ipv6_base.prefix));
        }
        if !is_rfc1918_cidr(ipv4_base) {
            return Err(AgentVmConfigError::NonPrivateIpv4Pool(ipv4_base));
        }
        if !is_ula_cidr(ipv6_base) {
            return Err(AgentVmConfigError::NonUlaIpv6Pool(ipv6_base));
        }
        Ok(Self {
            ipv4_base,
            ipv6_base,
        })
    }

    pub fn ipv4_base(self) -> Ipv4Cidr {
        self.ipv4_base
    }

    pub fn ipv6_base(self) -> Ipv6Cidr {
        self.ipv6_base
    }

    pub fn allocate(self, index: u16) -> Result<AgentNetwork, AgentVmConfigError> {
        let ipv4 = allocate_ipv4_agent_subnet(self.ipv4_base, index)?;
        let ipv6 = allocate_ipv6_agent_subnet(self.ipv6_base, index)?;
        AgentNetwork::new(ipv4, ipv6)
    }
}

impl IpFamily {
    fn pf_name(self) -> &'static str {
        match self {
            Self::Inet => "inet",
            Self::Inet6 => "inet6",
        }
    }
}

impl PfCidr {
    pub fn family(self) -> IpFamily {
        match self {
            Self::Inet(_) => IpFamily::Inet,
            Self::Inet6(_) => IpFamily::Inet6,
        }
    }
}

impl std::fmt::Display for PfCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inet(c) => c.fmt(f),
            Self::Inet6(c) => c.fmt(f),
        }
    }
}

impl PfAnchorName {
    fn for_session(session_id: SessionId) -> Self {
        Self(format!("writ/session/{session_id}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PfAllowRule {
    fn new(source: PfCidr, destination_ports: BrokerPorts) -> Self {
        Self {
            source,
            destination_ports,
        }
    }

    pub fn family(&self) -> IpFamily {
        self.source.family()
    }

    pub fn source(&self) -> PfCidr {
        self.source
    }

    pub fn destination_ports(&self) -> &BrokerPorts {
        &self.destination_ports
    }
}

impl PfDenyRule {
    fn new(source: PfCidr, label: impl Into<String>) -> Self {
        Self {
            source,
            label: label.into(),
        }
    }

    pub fn family(&self) -> IpFamily {
        self.source.family()
    }

    pub fn source(&self) -> PfCidr {
        self.source
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}

impl PfRuleset {
    fn new(anchor: PfAnchorName, allow: Vec<PfAllowRule>, deny: Vec<PfDenyRule>) -> Self {
        Self {
            anchor,
            allow,
            deny,
        }
    }

    pub fn anchor(&self) -> &PfAnchorName {
        &self.anchor
    }

    pub fn allow(&self) -> &[PfAllowRule] {
        &self.allow
    }

    pub fn deny(&self) -> &[PfDenyRule] {
        &self.deny
    }
}

pub fn session_pf_ruleset(
    session_id: SessionId,
    network: AgentNetwork,
    broker_ports: &BrokerPorts,
) -> PfRuleset {
    let ports = broker_ports.clone();
    PfRuleset::new(
        PfAnchorName::for_session(session_id),
        vec![
            PfAllowRule::new(PfCidr::Inet(network.ipv4()), ports.clone()),
            PfAllowRule::new(PfCidr::Inet6(network.ipv6()), ports),
        ],
        vec![
            PfDenyRule::new(PfCidr::Inet(network.ipv4()), "writ deny agent v4"),
            PfDenyRule::new(PfCidr::Inet6(network.ipv6()), "writ deny agent v6"),
        ],
    )
}

pub fn render_pf(ruleset: &PfRuleset) -> String {
    let mut out = String::new();
    if let Some(ports) = broker_ports_macro(ruleset) {
        out.push_str(&format!(
            "broker_ports = \"{{ {} }}\"\n\n",
            ports.render_pf_set()
        ));
    }
    for rule in ruleset.allow() {
        out.push_str(&format!(
            "pass in quick {} proto tcp from {} to any port $broker_ports keep state\n",
            rule.family().pf_name(),
            rule.source(),
        ));
    }
    out.push('\n');
    for rule in ruleset.deny() {
        out.push_str(&format!(
            "block return in quick {} from {} to any label \"{}\"\n",
            rule.family().pf_name(),
            rule.source(),
            rule.label(),
        ));
    }
    out
}

fn broker_ports_macro(ruleset: &PfRuleset) -> Option<&BrokerPorts> {
    ruleset.allow().first().map(PfAllowRule::destination_ports)
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn is_rfc1918_cidr(cidr: Ipv4Cidr) -> bool {
    [
        Ipv4Cidr {
            network: Ipv4Addr::new(10, 0, 0, 0),
            prefix: 8,
        },
        Ipv4Cidr {
            network: Ipv4Addr::new(172, 16, 0, 0),
            prefix: 12,
        },
        Ipv4Cidr {
            network: Ipv4Addr::new(192, 168, 0, 0),
            prefix: 16,
        },
    ]
    .into_iter()
    .any(|private| private.contains_subnet(cidr))
}

fn is_ula_cidr(cidr: Ipv6Cidr) -> bool {
    Ipv6Cidr {
        network: Ipv6Addr::from(0xfc00u128 << 112),
        prefix: 7,
    }
    .contains_subnet(cidr)
}

fn allocate_ipv4_agent_subnet(base: Ipv4Cidr, index: u16) -> Result<Ipv4Cidr, AgentVmConfigError> {
    if base.prefix > AGENT_IPV4_PREFIX {
        return Err(AgentVmConfigError::SubnetIndexOutOfRange {
            index,
            base_prefix: base.prefix,
        });
    }
    let capacity = 1u32 << (AGENT_IPV4_PREFIX - base.prefix);
    if u32::from(index) >= capacity {
        return Err(AgentVmConfigError::SubnetIndexOutOfRange {
            index,
            base_prefix: base.prefix,
        });
    }
    let raw = u32::from(base.network) + (u32::from(index) << (32 - AGENT_IPV4_PREFIX));
    Ipv4Cidr::new(Ipv4Addr::from(raw), AGENT_IPV4_PREFIX)
}

fn allocate_ipv6_agent_subnet(base: Ipv6Cidr, index: u16) -> Result<Ipv6Cidr, AgentVmConfigError> {
    if base.prefix > AGENT_IPV6_PREFIX {
        return Err(AgentVmConfigError::SubnetIndexOutOfRange {
            index,
            base_prefix: base.prefix,
        });
    }
    let capacity = 1u128 << (AGENT_IPV6_PREFIX - base.prefix);
    if u128::from(index) >= capacity {
        return Err(AgentVmConfigError::SubnetIndexOutOfRange {
            index,
            base_prefix: base.prefix,
        });
    }
    let raw = u128::from(base.network) + (u128::from(index) << (128 - AGENT_IPV6_PREFIX));
    Ipv6Cidr::new(Ipv6Addr::from(raw), AGENT_IPV6_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use uuid::Uuid;

    fn session_id() -> SessionId {
        SessionId::from_uuid(Uuid::from_u128(1))
    }

    fn sample_pool() -> AgentNetworkPool {
        AgentNetworkPool::new(
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 126, 0), 24).unwrap(),
            Ipv6Cidr::new("fd83:b6f2:e57:f536::".parse().unwrap(), 64).unwrap(),
        )
        .unwrap()
    }

    fn sample_ports() -> BrokerPorts {
        BrokerPorts::new([
            BrokerPort::new(18081).unwrap(),
            BrokerPort::new(18080).unwrap(),
            BrokerPort::new(18080).unwrap(),
        ])
        .unwrap()
    }

    fn arb_private_ipv4_base() -> impl Strategy<Value = Ipv4Cidr> {
        prop_oneof![
            arb_ipv4_base_in(Ipv4Addr::new(10, 0, 0, 0), 8, AGENT_IPV4_PREFIX),
            arb_ipv4_base_in(Ipv4Addr::new(172, 16, 0, 0), 12, AGENT_IPV4_PREFIX),
            arb_ipv4_base_in(Ipv4Addr::new(192, 168, 0, 0), 16, AGENT_IPV4_PREFIX),
        ]
    }

    fn arb_private_ipv4_base_with_multiple_agent_subnets() -> impl Strategy<Value = Ipv4Cidr> {
        prop_oneof![
            arb_ipv4_base_in(Ipv4Addr::new(10, 0, 0, 0), 8, AGENT_IPV4_PREFIX - 1),
            arb_ipv4_base_in(Ipv4Addr::new(172, 16, 0, 0), 12, AGENT_IPV4_PREFIX - 1),
            arb_ipv4_base_in(Ipv4Addr::new(192, 168, 0, 0), 16, AGENT_IPV4_PREFIX - 1),
        ]
    }

    fn arb_ipv4_base_in(
        range_base: Ipv4Addr,
        range_prefix: u8,
        max_prefix: u8,
    ) -> BoxedStrategy<Ipv4Cidr> {
        (range_prefix..=max_prefix)
            .prop_flat_map(move |prefix| {
                let slots = 1u32 << (prefix - range_prefix);
                (Just(prefix), 0u32..slots)
            })
            .prop_map(move |(prefix, slot)| {
                let raw = u32::from(range_base) + (slot << (32 - prefix));
                Ipv4Cidr::new(Ipv4Addr::from(raw), prefix).unwrap()
            })
            .boxed()
    }

    fn arb_ula_ipv6_base() -> impl Strategy<Value = Ipv6Cidr> {
        arb_ula_ipv6_base_up_to(AGENT_IPV6_PREFIX)
    }

    fn arb_ula_ipv6_base_with_multiple_agent_subnets() -> impl Strategy<Value = Ipv6Cidr> {
        arb_ula_ipv6_base_up_to(AGENT_IPV6_PREFIX - 1)
    }

    fn arb_ula_ipv6_base_up_to(max_prefix: u8) -> BoxedStrategy<Ipv6Cidr> {
        (7u8..=max_prefix)
            .prop_flat_map(|prefix| {
                let slots = 1u64 << (prefix - 7);
                (Just(prefix), 0u64..slots)
            })
            .prop_map(|(prefix, slot)| {
                let raw = (0xfc00u128 << 112) + (u128::from(slot) << (128 - prefix));
                Ipv6Cidr::new(Ipv6Addr::from(raw), prefix).unwrap()
            })
            .boxed()
    }

    fn arb_pool_and_index() -> impl Strategy<Value = (AgentNetworkPool, u16)> {
        (arb_private_ipv4_base(), arb_ula_ipv6_base()).prop_flat_map(|(ipv4, ipv6)| {
            let pool = AgentNetworkPool::new(ipv4, ipv6).unwrap();
            let capacity = pool_index_capacity(pool);
            arb_index_below(capacity).prop_map(move |index| (pool, index))
        })
    }

    fn arb_pool_and_distinct_indexes() -> impl Strategy<Value = (AgentNetworkPool, u16, u16)> {
        (
            arb_private_ipv4_base_with_multiple_agent_subnets(),
            arb_ula_ipv6_base_with_multiple_agent_subnets(),
        )
            .prop_flat_map(|(ipv4, ipv6)| {
                let pool = AgentNetworkPool::new(ipv4, ipv6).unwrap();
                let capacity = pool_index_capacity(pool);
                arb_index_below(capacity).prop_flat_map(move |left| {
                    let rest = capacity - 1;
                    arb_index_below(rest).prop_map(move |offset| {
                        let right = (u32::from(left) + 1 + u32::from(offset)) % capacity;
                        (pool, left, right as u16)
                    })
                })
            })
    }

    fn arb_pool_and_next_index() -> impl Strategy<Value = (AgentNetworkPool, u16)> {
        (
            arb_private_ipv4_base_with_multiple_agent_subnets(),
            arb_ula_ipv6_base_with_multiple_agent_subnets(),
        )
            .prop_flat_map(|(ipv4, ipv6)| {
                let pool = AgentNetworkPool::new(ipv4, ipv6).unwrap();
                let capacity = pool_index_capacity(pool);
                arb_index_below(capacity - 1).prop_map(move |index| (pool, index))
            })
    }

    fn arb_broker_ports() -> impl Strategy<Value = BrokerPorts> {
        prop::collection::vec(1024u16..=u16::MAX, 1..8).prop_map(|ports| {
            BrokerPorts::new(ports.into_iter().map(|port| BrokerPort::new(port).unwrap())).unwrap()
        })
    }

    fn arb_index_below(capacity: u32) -> BoxedStrategy<u16> {
        assert!((1..=65536).contains(&capacity));
        if capacity == 65536 {
            any::<u16>().boxed()
        } else {
            (0..capacity as u16).boxed()
        }
    }

    fn pool_index_capacity(pool: AgentNetworkPool) -> u32 {
        let ipv4_capacity = 1u32 << (AGENT_IPV4_PREFIX - pool.ipv4_base().prefix());
        let ipv6_capacity = 1u128 << (AGENT_IPV6_PREFIX - pool.ipv6_base().prefix());
        let bounded_ipv6_capacity = u32::try_from(ipv6_capacity).unwrap_or(65536);
        ipv4_capacity.min(bounded_ipv6_capacity).min(65536)
    }

    fn count_number_token(haystack: &str, needle: u16) -> usize {
        let rendered = needle.to_string();
        haystack
            .split(|c: char| !c.is_ascii_digit())
            .filter(|part| *part == rendered)
            .count()
    }

    #[test]
    fn broker_ports_are_unprivileged_sorted_and_deduped() {
        assert!(matches!(
            BrokerPort::new(0),
            Err(AgentVmConfigError::BrokerPortZero)
        ));
        assert!(matches!(
            BrokerPort::new(1023),
            Err(AgentVmConfigError::PrivilegedBrokerPort(1023))
        ));
        let ports = sample_ports();
        assert_eq!(
            ports.as_slice().iter().map(|p| p.get()).collect::<Vec<_>>(),
            vec![18080, 18081],
        );
    }

    #[test]
    fn pool_rejects_public_ipv4_and_non_ula_ipv6() {
        assert!(matches!(
            AgentNetworkPool::new(
                Ipv4Cidr::new(Ipv4Addr::new(8, 8, 8, 0), 24).unwrap(),
                Ipv6Cidr::new("fd83:b6f2:e57:f536::".parse().unwrap(), 64).unwrap(),
            ),
            Err(AgentVmConfigError::NonPrivateIpv4Pool(_))
        ));
        assert!(matches!(
            AgentNetworkPool::new(
                Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                Ipv6Cidr::new("2001:db8::".parse().unwrap(), 32).unwrap(),
            ),
            Err(AgentVmConfigError::NonUlaIpv6Pool(_))
        ));
    }

    #[test]
    fn network_pool_allocates_expected_subnets() {
        let pool = AgentNetworkPool::new(
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
            Ipv6Cidr::new("fd83:b6f2:e57::".parse().unwrap(), 48).unwrap(),
        )
        .unwrap();
        let first = pool.allocate(0).unwrap();
        let second = pool.allocate(1).unwrap();
        assert_eq!(first.ipv4().to_string(), "192.168.0.0/24");
        assert_eq!(second.ipv4().to_string(), "192.168.1.0/24");
        assert_eq!(first.ipv6().to_string(), "fd83:b6f2:e57::/64");
        assert_eq!(second.ipv6().to_string(), "fd83:b6f2:e57:1::/64");
    }

    #[test]
    fn agent_network_requires_container_session_prefixes() {
        assert!(matches!(
            AgentNetwork::new(
                Ipv4Cidr::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
                Ipv6Cidr::new("fd83:b6f2:e57:f536::".parse().unwrap(), 64).unwrap(),
            ),
            Err(AgentVmConfigError::AgentIpv4Prefix(16))
        ));
        assert!(matches!(
            AgentNetwork::new(
                Ipv4Cidr::new(Ipv4Addr::new(192, 168, 126, 0), 24).unwrap(),
                Ipv6Cidr::new("fd83:b6f2:e57::".parse().unwrap(), 48).unwrap(),
            ),
            Err(AgentVmConfigError::AgentIpv6Prefix(48))
        ));
    }

    #[test]
    fn network_pool_rejects_index_outside_base() {
        let pool = AgentNetworkPool::new(
            Ipv4Cidr::new(Ipv4Addr::new(10, 9, 8, 0), 24).unwrap(),
            Ipv6Cidr::new("fd83:b6f2:e57:f536::".parse().unwrap(), 64).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            pool.allocate(1),
            Err(AgentVmConfigError::SubnetIndexOutOfRange { .. })
        ));
    }

    #[test]
    fn session_pf_ruleset_is_structured_and_inspectable() {
        let network = sample_pool().allocate(0).unwrap();
        let ruleset = session_pf_ruleset(session_id(), network, &sample_ports());

        assert_eq!(
            ruleset.anchor().as_str(),
            "writ/session/00000000-0000-0000-0000-000000000001",
        );
        assert_eq!(ruleset.allow().len(), 2);
        assert_eq!(ruleset.deny().len(), 2);
        assert_eq!(ruleset.allow()[0].source(), PfCidr::Inet(network.ipv4()));
        assert_eq!(ruleset.allow()[1].source(), PfCidr::Inet6(network.ipv6()));
        assert_eq!(ruleset.deny()[0].label(), "writ deny agent v4");
        assert_eq!(ruleset.deny()[1].label(), "writ deny agent v6");
    }

    #[test]
    fn render_pf_renders_ruleset_body_without_anchor() {
        let network = sample_pool().allocate(0).unwrap();
        let ruleset = session_pf_ruleset(session_id(), network, &sample_ports());
        assert_eq!(
            render_pf(&ruleset),
            concat!(
                "broker_ports = \"{ 18080, 18081 }\"\n",
                "\n",
                "pass in quick inet proto tcp from 192.168.126.0/24 to any port $broker_ports keep state\n",
                "pass in quick inet6 proto tcp from fd83:b6f2:e57:f536::/64 to any port $broker_ports keep state\n",
                "\n",
                "block return in quick inet from 192.168.126.0/24 to any label \"writ deny agent v4\"\n",
                "block return in quick inet6 from fd83:b6f2:e57:f536::/64 to any label \"writ deny agent v6\"\n",
            ),
        );
    }

    proptest! {
        #[test]
        fn ipv4_constructor_rejects_any_host_bit(raw in any::<u32>(), prefix in 0u8..32) {
            let bad = (raw & ipv4_mask(prefix)) | 1;
            prop_assert!(
                matches!(
                    Ipv4Cidr::new(Ipv4Addr::from(bad), prefix),
                    Err(AgentVmConfigError::HostBitsSet { .. })
                ),
                "expected HostBitsSet for {bad:#010x}/{prefix}"
            );
        }

        #[test]
        fn ipv6_constructor_rejects_any_host_bit(raw in any::<u128>(), prefix in 0u8..128) {
            let bad = (raw & ipv6_mask(prefix)) | 1;
            prop_assert!(
                matches!(
                    Ipv6Cidr::new(Ipv6Addr::from(bad), prefix),
                    Err(AgentVmConfigError::HostBitsSet { .. })
                ),
                "expected HostBitsSet for {bad:#034x}/{prefix}"
            );
        }

        #[test]
        fn allocated_subnets_stay_inside_base((pool, index) in arb_pool_and_index()) {
            let network = pool.allocate(index).unwrap();
            prop_assert!(pool.ipv4_base().contains_subnet(network.ipv4()));
            prop_assert!(pool.ipv6_base().contains_subnet(network.ipv6()));
        }

        #[test]
        fn different_indexes_allocate_different_subnets((pool, left, right) in arb_pool_and_distinct_indexes()) {
            let left = pool.allocate(left).unwrap();
            let right = pool.allocate(right).unwrap();
            prop_assert_ne!(left.ipv4(), right.ipv4());
            prop_assert_ne!(left.ipv6(), right.ipv6());
        }

        #[test]
        fn ipv4_allocation_stride_is_one_slash_24((pool, index) in arb_pool_and_next_index()) {
            let left = pool.allocate(index).unwrap();
            let right = pool.allocate(index + 1).unwrap();
            prop_assert_eq!(u32::from(right.ipv4().network()) - u32::from(left.ipv4().network()), 256);
        }

        #[test]
        fn rendered_ports_are_sorted_deduped_and_defined_once(ports in arb_broker_ports()) {
            let network = sample_pool().allocate(0).unwrap();
            let ruleset = session_pf_ruleset(session_id(), network, &ports);
            let rendered = render_pf(&ruleset);

            for port in ports.as_slice() {
                prop_assert_eq!(count_number_token(&rendered, port.get()), 1);
            }
            prop_assert!(rendered.contains("port $broker_ports"));
        }
    }
}
