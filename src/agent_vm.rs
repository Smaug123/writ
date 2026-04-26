//! Pure model for the future Apple-container agent VM isolation layer.
//!
//! This module deliberately does not call `container`, `pfctl`, or any
//! privileged helper. It describes the session network and the PF rules we
//! intend to install; an imperative edge can interpret those descriptions
//! later.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::core::SessionId;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfFilterRules {
    pub anchor: String,
    pub rules: String,
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
}

impl AgentNetwork {
    pub fn new(ipv4: Ipv4Cidr, ipv6: Ipv6Cidr) -> Result<Self, AgentVmConfigError> {
        if ipv4.prefix != 24 {
            return Err(AgentVmConfigError::AgentIpv4Prefix(ipv4.prefix));
        }
        if ipv6.prefix != 64 {
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
    pub fn new(ipv4_base: Ipv4Cidr, ipv6_base: Ipv6Cidr) -> Self {
        Self {
            ipv4_base,
            ipv6_base,
        }
    }

    pub fn allocate(self, index: u16) -> Result<AgentNetwork, AgentVmConfigError> {
        let ipv4 = allocate_ipv4_agent_subnet(self.ipv4_base, index)?;
        let ipv6 = allocate_ipv6_agent_subnet(self.ipv6_base, index)?;
        AgentNetwork::new(ipv4, ipv6)
    }
}

pub fn render_pf_filter_rules(
    session_id: SessionId,
    network: AgentNetwork,
    broker_ports: &BrokerPorts,
) -> PfFilterRules {
    let ports = broker_ports
        .as_slice()
        .iter()
        .map(|p| p.get().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let anchor = format!("writ/session/{session_id}");
    let rules = format!(
        concat!(
            "agent4 = \"{}\"\n",
            "agent6 = \"{}\"\n",
            "broker_ports = \"{{ {} }}\"\n",
            "\n",
            "pass in quick inet proto tcp from $agent4 to any port $broker_ports keep state\n",
            "pass in quick inet6 proto tcp from $agent6 to any port $broker_ports keep state\n",
            "\n",
            "block return in quick inet from $agent4 to any label \"writ deny agent v4\"\n",
            "block return in quick inet6 from $agent6 to any label \"writ deny agent v6\"\n",
        ),
        network.ipv4(),
        network.ipv6(),
        ports,
    );
    PfFilterRules { anchor, rules }
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

fn allocate_ipv4_agent_subnet(base: Ipv4Cidr, index: u16) -> Result<Ipv4Cidr, AgentVmConfigError> {
    const AGENT_PREFIX: u8 = 24;
    if base.prefix > AGENT_PREFIX {
        return Err(AgentVmConfigError::SubnetIndexOutOfRange {
            index,
            base_prefix: base.prefix,
        });
    }
    let capacity = 1u32 << (AGENT_PREFIX - base.prefix);
    if u32::from(index) >= capacity {
        return Err(AgentVmConfigError::SubnetIndexOutOfRange {
            index,
            base_prefix: base.prefix,
        });
    }
    let raw = u32::from(base.network) + (u32::from(index) << (32 - AGENT_PREFIX));
    Ipv4Cidr::new(Ipv4Addr::from(raw), AGENT_PREFIX)
}

fn allocate_ipv6_agent_subnet(base: Ipv6Cidr, index: u16) -> Result<Ipv6Cidr, AgentVmConfigError> {
    const AGENT_PREFIX: u8 = 64;
    if base.prefix > AGENT_PREFIX {
        return Err(AgentVmConfigError::SubnetIndexOutOfRange {
            index,
            base_prefix: base.prefix,
        });
    }
    let capacity = 1u128 << (AGENT_PREFIX - base.prefix);
    if u128::from(index) >= capacity {
        return Err(AgentVmConfigError::SubnetIndexOutOfRange {
            index,
            base_prefix: base.prefix,
        });
    }
    let raw = u128::from(base.network) + (u128::from(index) << (128 - AGENT_PREFIX));
    Ipv6Cidr::new(Ipv6Addr::from(raw), AGENT_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use uuid::Uuid;

    fn session_id() -> SessionId {
        SessionId::from_uuid(Uuid::from_u128(1))
    }

    fn sample_network() -> AgentNetwork {
        AgentNetwork::new(
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

    #[test]
    fn cidr_constructors_reject_host_bits() {
        assert!(matches!(
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 1), 24),
            Err(AgentVmConfigError::HostBitsSet { .. })
        ));
        assert!(matches!(
            Ipv6Cidr::new("fd83:b6f2:e57:f536::1".parse().unwrap(), 64),
            Err(AgentVmConfigError::HostBitsSet { .. })
        ));
    }

    #[test]
    fn broker_ports_are_unprivileged_sorted_and_deduped() {
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
    fn network_pool_allocates_expected_subnets() {
        let pool = AgentNetworkPool::new(
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
            Ipv6Cidr::new("fd83:b6f2:e57::".parse().unwrap(), 48).unwrap(),
        );
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
        );
        assert!(matches!(
            pool.allocate(1),
            Err(AgentVmConfigError::SubnetIndexOutOfRange { .. })
        ));
    }

    #[test]
    fn pf_rules_allow_broker_ports_then_block_everything_else() {
        let rendered = render_pf_filter_rules(session_id(), sample_network(), &sample_ports());
        assert_eq!(
            rendered.anchor,
            "writ/session/00000000-0000-0000-0000-000000000001",
        );
        assert_eq!(
            rendered.rules,
            concat!(
                "agent4 = \"192.168.126.0/24\"\n",
                "agent6 = \"fd83:b6f2:e57:f536::/64\"\n",
                "broker_ports = \"{ 18080, 18081 }\"\n",
                "\n",
                "pass in quick inet proto tcp from $agent4 to any port $broker_ports keep state\n",
                "pass in quick inet6 proto tcp from $agent6 to any port $broker_ports keep state\n",
                "\n",
                "block return in quick inet from $agent4 to any label \"writ deny agent v4\"\n",
                "block return in quick inet6 from $agent6 to any label \"writ deny agent v6\"\n",
            ),
        );
    }

    proptest! {
        #[test]
        fn allocated_subnets_stay_inside_base(index in 0u16..256) {
            let pool = AgentNetworkPool::new(
                Ipv4Cidr::new(Ipv4Addr::new(172, 31, 0, 0), 16).unwrap(),
                Ipv6Cidr::new("fd00:1234:5678::".parse().unwrap(), 48).unwrap(),
            );
            let network = pool.allocate(index).unwrap();
            prop_assert!(Ipv4Cidr::new(Ipv4Addr::new(172, 31, 0, 0), 16).unwrap().contains_subnet(network.ipv4()));
            prop_assert!(Ipv6Cidr::new("fd00:1234:5678::".parse().unwrap(), 48).unwrap().contains_subnet(network.ipv6()));
        }

        #[test]
        fn different_indexes_allocate_different_subnets(a in 0u16..256, b in 0u16..256) {
            prop_assume!(a != b);
            let pool = AgentNetworkPool::new(
                Ipv4Cidr::new(Ipv4Addr::new(172, 30, 0, 0), 16).unwrap(),
                Ipv6Cidr::new("fd00:abcd:ef01::".parse().unwrap(), 48).unwrap(),
            );
            let left = pool.allocate(a).unwrap();
            let right = pool.allocate(b).unwrap();
            prop_assert_ne!(left.ipv4(), right.ipv4());
            prop_assert_ne!(left.ipv6(), right.ipv6());
        }
    }
}
