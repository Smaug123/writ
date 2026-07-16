//! Pure parsing and validation of external tool output for
//! `agent_vm_lifecycle`: the Apple `container network inspect` payload
//! (`AppleNetworkInspection`) and the guest IPv6 posture probe
//! (`GuestIpv6Inspection`), together with their structured error types.
//!
//! Everything here is a total function from `&str` to a parsed value or
//! a typed error: no IO, no process spawning. The imperative edge that
//! produces these strings lives in the parent module.

use super::GUEST_IPV6_PROBE_UNAVAILABLE_MARKER;
use crate::core::{AgentVmConfigError, Ipv4Cidr, Ipv6Cidr, PfInterface};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NetworkInspectionError {
    #[error("container network inspect output is missing {0}")]
    MissingField(&'static str),
    #[error("container network inspect field {field} has invalid value {value:?}: {message}")]
    InvalidField {
        field: &'static str,
        value: String,
        message: String,
    },
    #[error("inspected IPv4 subnet {actual} does not match planned subnet {expected}")]
    Ipv4SubnetMismatch {
        expected: Ipv4Cidr,
        actual: Ipv4Cidr,
    },
    #[error("inspected IPv4 gateway {actual} does not match planned gateway {expected}")]
    Ipv4GatewayMismatch {
        expected: Ipv4Addr,
        actual: Ipv4Addr,
    },
    #[error("inspected IPv6 subnet {actual} does not match planned subnet {expected}")]
    Ipv6SubnetMismatch {
        expected: Ipv6Cidr,
        actual: Ipv6Cidr,
    },
    #[error("inspected IPv6 gateway {gateway} is outside planned subnet {subnet}")]
    Ipv6GatewayOutsideSubnet { subnet: Ipv6Cidr, gateway: Ipv6Addr },
    #[error("inspected IPv6 gateway {actual} does not match planned gateway {expected}")]
    Ipv6GatewayMismatch {
        expected: Ipv6Addr,
        actual: Ipv6Addr,
    },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GuestIpv6InspectionError {
    #[error("guest image cannot prove IPv6 posture because it does not provide the `ip` command")]
    ProbeToolUnavailable,
    #[error("guest IPv6 probe output has invalid address {value:?}: {message}")]
    InvalidAddress { value: String, message: String },
    #[error("guest has non-link-local IPv6 address {0}")]
    NonLinkLocalAddress(Ipv6Addr),
    #[error("guest has IPv6 default route: {0}")]
    DefaultRoute(String),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GuestBridgeDiscoveryError {
    #[error("no host interface carries the agent session gateway {0} (the bridge is not up yet)")]
    NoBridgeForGateway(Ipv4Addr),
    #[error("more than one host interface carries the agent session gateway {0}")]
    MultipleBridgesForGateway(Ipv4Addr),
    #[error("host interface name is not usable in a PF rule: {0}")]
    InvalidInterfaceName(#[from] AgentVmConfigError),
}

/// The host-side interfaces that carry one agent VM's traffic: the vmnet bridge
/// that holds the session's IPv4 gateway, plus the bridge's member interface(s)
/// (the `vmenet*` the guest is attached to).
///
/// This is what the `Ipv4OnlyNoGuestIpv6` backstop scopes its IPv6 deny to.
/// Scoping to *both* the bridge and its member removes any dependence on which
/// interface macOS PF happens to filter bridged IPv6 on; neither carries any
/// legitimate IPv6 in this mode, so denying all IPv6 on them is safe and cannot
/// touch the IPv4 broker path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestBridgeDiscovery {
    bridge: PfInterface,
    members: Vec<PfInterface>,
}

impl GuestBridgeDiscovery {
    pub fn bridge(&self) -> &PfInterface {
        &self.bridge
    }

    pub fn members(&self) -> &[PfInterface] {
        &self.members
    }

    /// The full set of interfaces to install the IPv6 deny on: the bridge first,
    /// then each member, de-duplicated while preserving order.
    pub fn deny_interfaces(&self) -> Vec<PfInterface> {
        let mut out = Vec::with_capacity(self.members.len() + 1);
        for iface in std::iter::once(&self.bridge).chain(self.members.iter()) {
            if !out.contains(iface) {
                out.push(iface.clone());
            }
        }
        out
    }
}

/// One interface stanza scraped from `ifconfig` output.
struct IfconfigStanza {
    name: String,
    carries_gateway: bool,
    members: Vec<String>,
}

/// Find the vmnet bridge that carries `gateway` (the agent session's IPv4
/// gateway, which macOS assigns to the bridge interface), and its member
/// interfaces, from `ifconfig` output.
///
/// The bridge exists only after the agent VM starts, and its name (`bridgeN`)
/// and member (`vmenetN`) are assigned by vmnet in start order, so they cannot
/// be predicted — but the session's gateway *is* known, and macOS puts it on the
/// bridge (`inet 192.168.x.1`), giving a stable, per-session key. Fails closed:
/// if no interface (or more than one) carries the gateway, the caller must not
/// release the guest without the backstop.
pub fn parse_bridge_for_gateway(
    ifconfig_output: &str,
    gateway: Ipv4Addr,
) -> Result<GuestBridgeDiscovery, GuestBridgeDiscoveryError> {
    let mut stanzas: Vec<IfconfigStanza> = Vec::new();
    for line in ifconfig_output.lines() {
        // A top-level interface header starts at column 0 as `name: flags=...`;
        // every attribute line (inet, member:, Configuration:, …) is indented, so
        // leading whitespace distinguishes them.
        let is_header = !line.is_empty() && !line.starts_with([' ', '\t']) && line.contains(':');
        if is_header {
            let name = line.split(':').next().unwrap_or_default().to_string();
            stanzas.push(IfconfigStanza {
                name,
                carries_gateway: false,
                members: Vec::new(),
            });
            continue;
        }
        let Some(stanza) = stanzas.last_mut() else {
            continue;
        };
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            // `inet <addr> netmask …`. Match the exact address token, never a
            // substring, so 192.168.221.1 does not match 192.168.221.10.
            if rest
                .split_whitespace()
                .next()
                .and_then(|tok| tok.parse::<Ipv4Addr>().ok())
                == Some(gateway)
            {
                stanza.carries_gateway = true;
            }
        } else if let Some(rest) = trimmed.strip_prefix("member:")
            && let Some(member) = rest.split_whitespace().next()
        {
            stanza.members.push(member.to_string());
        }
    }

    let mut matching = stanzas.into_iter().filter(|s| s.carries_gateway);
    let bridge_stanza = matching
        .next()
        .ok_or(GuestBridgeDiscoveryError::NoBridgeForGateway(gateway))?;
    if matching.next().is_some() {
        return Err(GuestBridgeDiscoveryError::MultipleBridgesForGateway(
            gateway,
        ));
    }
    let bridge = PfInterface::new(bridge_stanza.name)?;
    let members = bridge_stanza
        .members
        .into_iter()
        .map(PfInterface::new)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GuestBridgeDiscovery { bridge, members })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppleNetworkInspection {
    pub(super) ipv4_subnet: Ipv4Cidr,
    pub(super) ipv4_gateway: Ipv4Addr,
    pub(super) ipv6_subnet: Option<Ipv6Cidr>,
    pub(super) ipv6_gateway: Option<Ipv6Addr>,
}

impl AppleNetworkInspection {
    pub fn parse(raw: &str) -> Result<Self, NetworkInspectionError> {
        let ipv4_subnet = parse_ipv4_cidr_field("ipv4Subnet", &require_field(raw, "ipv4Subnet")?)?;
        let ipv4_gateway =
            parse_ipv4_addr_field("ipv4Gateway", &require_field(raw, "ipv4Gateway")?)?;
        let ipv6_subnet = extract_network_field(raw, "ipv6Subnet")
            .map(|raw| parse_ipv6_cidr_field("ipv6Subnet", &raw))
            .transpose()?;
        let ipv6_gateway = extract_network_field(raw, "ipv6Gateway")
            .map(|raw| parse_ipv6_addr_field("ipv6Gateway", &raw))
            .transpose()?;
        Ok(Self {
            ipv4_subnet,
            ipv4_gateway,
            ipv6_subnet,
            ipv6_gateway,
        })
    }

    pub fn ipv4_subnet(&self) -> Ipv4Cidr {
        self.ipv4_subnet
    }

    pub fn ipv4_gateway(&self) -> Ipv4Addr {
        self.ipv4_gateway
    }

    pub fn ipv6_subnet(&self) -> Option<Ipv6Cidr> {
        self.ipv6_subnet
    }

    pub fn ipv6_gateway(&self) -> Option<Ipv6Addr> {
        self.ipv6_gateway
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestIpv6Inspection {
    addresses: Vec<Ipv6Addr>,
    default_routes: Vec<String>,
}

impl GuestIpv6Inspection {
    pub fn parse(raw: &str) -> Result<Self, GuestIpv6InspectionError> {
        let mut addresses = Vec::new();
        let mut default_routes = Vec::new();
        for line in raw.lines().map(str::trim).filter(|line| !line.is_empty()) {
            if line == GUEST_IPV6_PROBE_UNAVAILABLE_MARKER {
                return Err(GuestIpv6InspectionError::ProbeToolUnavailable);
            }
            if line.starts_with("default ") {
                default_routes.push(line.to_string());
                continue;
            }
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let Some(inet6_index) = fields.iter().position(|field| *field == "inet6") else {
                continue;
            };
            let Some(raw_addr) = fields.get(inet6_index + 1) else {
                continue;
            };
            let addr = raw_addr
                .split_once('/')
                .map(|(addr, _)| addr)
                .unwrap_or(raw_addr)
                .parse::<Ipv6Addr>()
                .map_err(|e| GuestIpv6InspectionError::InvalidAddress {
                    value: (*raw_addr).to_string(),
                    message: e.to_string(),
                })?;
            addresses.push(addr);
        }
        Ok(Self {
            addresses,
            default_routes,
        })
    }

    pub fn require_no_routable_ipv6(&self) -> Result<(), GuestIpv6InspectionError> {
        if let Some(addr) = self
            .addresses
            .iter()
            .copied()
            .find(|addr| !ipv6_addr_is_local_only(*addr))
        {
            return Err(GuestIpv6InspectionError::NonLinkLocalAddress(addr));
        }
        if let Some(route) = self.default_routes.first() {
            return Err(GuestIpv6InspectionError::DefaultRoute(route.clone()));
        }
        Ok(())
    }

    pub fn addresses(&self) -> &[Ipv6Addr] {
        &self.addresses
    }

    pub fn default_routes(&self) -> &[String] {
        &self.default_routes
    }
}

fn require_field(raw: &str, key: &'static str) -> Result<String, NetworkInspectionError> {
    extract_network_field(raw, key).ok_or(NetworkInspectionError::MissingField(key))
}

fn extract_network_field(raw: &str, key: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw)
        && let Some(found) = find_json_string(&value, key)
    {
        return Some(found);
    }
    for line in raw.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix(key) else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) else {
            continue;
        };
        let value = rest
            .trim()
            .trim_end_matches(',')
            .trim_matches('"')
            .trim()
            .to_string();
        if field_value_is_present(&value) {
            return Some(value);
        }
    }
    None
}

fn find_json_string(value: &serde_json::Value, key: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(fields) => {
            for (field, value) in fields {
                if field == key
                    && let Some(raw) = value.as_str()
                    && field_value_is_present(raw)
                {
                    return Some(raw.to_string());
                }
                if let Some(found) = find_json_string(value, key) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => {
            items.iter().find_map(|item| find_json_string(item, key))
        }
        _ => None,
    }
}

fn field_value_is_present(value: &str) -> bool {
    !value.is_empty() && !matches!(value.to_ascii_lowercase().as_str(), "null" | "none")
}

/// Build an `InvalidField` error for `field`, recording the offending
/// `raw` value and a `Display` cause. Collapses the error arm that the
/// field parsers below otherwise repeat verbatim.
fn invalid_field(
    field: &'static str,
    raw: &str,
    message: impl std::fmt::Display,
) -> NetworkInspectionError {
    NetworkInspectionError::InvalidField {
        field,
        value: raw.to_string(),
        message: message.to_string(),
    }
}

/// The address portion of a possibly-`addr/prefix` field.
fn addr_part(raw: &str) -> &str {
    raw.split_once('/').map(|(addr, _)| addr).unwrap_or(raw)
}

fn parse_ipv4_cidr_field(
    field: &'static str,
    raw: &str,
) -> Result<Ipv4Cidr, NetworkInspectionError> {
    let (addr, prefix) = split_cidr_field(field, raw)?;
    let addr = addr
        .parse::<Ipv4Addr>()
        .map_err(|e| invalid_field(field, raw, e))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|e| invalid_field(field, raw, e))?;
    Ipv4Cidr::new(addr, prefix).map_err(|e| invalid_field(field, raw, e))
}

fn parse_ipv6_cidr_field(
    field: &'static str,
    raw: &str,
) -> Result<Ipv6Cidr, NetworkInspectionError> {
    let (addr, prefix) = split_cidr_field(field, raw)?;
    let addr = addr
        .parse::<Ipv6Addr>()
        .map_err(|e| invalid_field(field, raw, e))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|e| invalid_field(field, raw, e))?;
    Ipv6Cidr::new(addr, prefix).map_err(|e| invalid_field(field, raw, e))
}

fn parse_ipv4_addr_field(
    field: &'static str,
    raw: &str,
) -> Result<Ipv4Addr, NetworkInspectionError> {
    addr_part(raw)
        .parse::<Ipv4Addr>()
        .map_err(|e| invalid_field(field, raw, e))
}

fn parse_ipv6_addr_field(
    field: &'static str,
    raw: &str,
) -> Result<Ipv6Addr, NetworkInspectionError> {
    addr_part(raw)
        .parse::<Ipv6Addr>()
        .map_err(|e| invalid_field(field, raw, e))
}

fn split_cidr_field<'a>(
    field: &'static str,
    raw: &'a str,
) -> Result<(&'a str, &'a str), NetworkInspectionError> {
    raw.split_once('/')
        .ok_or_else(|| invalid_field(field, raw, "CIDR value must contain '/'"))
}

fn ipv6_addr_is_local_only(addr: Ipv6Addr) -> bool {
    addr.is_loopback() || addr.is_unspecified() || ipv6_addr_is_link_local(addr)
}

fn ipv6_addr_is_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

pub(super) fn validate_ipv4_only_observed_ipv6(
    inspection: &AppleNetworkInspection,
) -> Result<(), NetworkInspectionError> {
    let Some(ipv6_subnet) = inspection.ipv6_subnet else {
        return match inspection.ipv6_gateway {
            Some(_) => Err(NetworkInspectionError::MissingField("ipv6Subnet")),
            None => Ok(()),
        };
    };
    if ipv6_subnet.prefix() != 64 {
        return Err(NetworkInspectionError::InvalidField {
            field: "ipv6Subnet",
            value: ipv6_subnet.to_string(),
            message: "IPv4-only mode only accepts observed IPv6 /64 subnets".into(),
        });
    }
    if !ipv6_cidr_is_ula(ipv6_subnet) {
        return Err(NetworkInspectionError::InvalidField {
            field: "ipv6Subnet",
            value: ipv6_subnet.to_string(),
            message: "IPv4-only mode only accepts observed IPv6 ULA subnets".into(),
        });
    }
    if let Some(ipv6_gateway) = inspection.ipv6_gateway
        && !ipv6_subnet.contains_addr(ipv6_gateway)
    {
        return Err(NetworkInspectionError::Ipv6GatewayOutsideSubnet {
            subnet: ipv6_subnet,
            gateway: ipv6_gateway,
        });
    }
    Ok(())
}

fn ipv6_cidr_is_ula(cidr: Ipv6Cidr) -> bool {
    (cidr.network().segments()[0] & 0xfe00) == 0xfc00
}
