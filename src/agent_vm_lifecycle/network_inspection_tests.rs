//! Example/edge-case tests for parsing and validating the Apple
//! `container network inspect` output, plus image/resource config
//! validation.
use super::test_support::*;
use super::*;
use std::net::Ipv4Addr;

#[test]
fn network_inspect_without_ipv6_is_explicitly_mode_dependent() {
    let raw = r#"
        mode: hostOnly
        ipv4Subnet: 192.168.252.0/24
        ipv4Gateway: 192.168.252.1
    "#;
    let inspection = AppleNetworkInspection::parse(raw).unwrap();
    assert_eq!(
        plan(252).validate_network_inspection(&inspection),
        Err(NetworkInspectionError::MissingField("ipv6Subnet"))
    );
    plan_with_ipv6_mode(252, Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6)
        .validate_network_inspection(&inspection)
        .unwrap();
}

#[test]
fn network_inspect_parser_accepts_nested_json() {
    let raw = serde_json::json!({
        "network": {
            "ipv4Subnet": "192.168.252.0/24",
            "ipv4Gateway": "192.168.252.1/24",
            "nested": {
                "ipv6Subnet": "fd83:b6f2:e57:fc::/64",
                "ipv6Gateway": "fd83:b6f2:e57:fc::1/64"
            }
        }
    })
    .to_string();
    let parsed = AppleNetworkInspection::parse(&raw).unwrap();
    assert_eq!(parsed.ipv4_subnet().to_string(), "192.168.252.0/24");
    assert_eq!(parsed.ipv4_gateway(), Ipv4Addr::new(192, 168, 252, 1));
    assert_eq!(
        parsed.ipv6_subnet().unwrap().to_string(),
        "fd83:b6f2:e57:fc::/64"
    );
    assert_eq!(
        parsed.ipv6_gateway(),
        Some(Ipv6Addr::from(
            0xfd83_b6f2_0e57_00fc_0000_0000_0000_0001u128
        ))
    );
}

#[test]
fn network_inspection_must_match_the_allocated_session_network() {
    let plan = plan(252);
    let matching = AppleNetworkInspection::parse(
        r#"
        ipv4Subnet: 192.168.252.0/24
        ipv4Gateway: 192.168.252.1
        ipv6Subnet: fd83:b6f2:e57:fc::/64
        ipv6Gateway: fd83:b6f2:e57:fc::1
        "#,
    )
    .unwrap();
    plan.validate_network_inspection(&matching).unwrap();

    let wrong_v6 = AppleNetworkInspection::parse(
        r#"
        ipv4Subnet: 192.168.252.0/24
        ipv4Gateway: 192.168.252.1
        ipv6Subnet: fd83:b6f2:e57:fd::/64
        ipv6Gateway: fd83:b6f2:e57:fd::1
        "#,
    )
    .unwrap();
    assert!(matches!(
        plan.validate_network_inspection(&wrong_v6),
        Err(NetworkInspectionError::Ipv6SubnetMismatch { .. })
    ));
}

#[test]
fn image_and_resources_reject_empty_values() {
    assert_eq!(
        ContainerImage::new(" "),
        Err(AgentVmLifecycleConfigError::EmptyImage)
    );
    assert_eq!(
        AgentVmResources::new(0, 512),
        Err(AgentVmLifecycleConfigError::EmptyCpuCount)
    );
    assert_eq!(
        AgentVmResources::new(1, 0),
        Err(AgentVmLifecycleConfigError::EmptyMemory)
    );
    assert_eq!(
        AgentVmSessionPlan::new(
            session_id(),
            pool(),
            252,
            ports(),
            BrokerPortRange::new(49152, 65535).unwrap(),
            Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
            ContainerImage::new("alpine:latest").unwrap(),
            Vec::new(),
            AgentVmResources::new(1, 512).unwrap(),
            AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo", "ifconfig"),
        ),
        Err(AgentVmLifecycleConfigError::EmptyGuestCommandForIpv4OnlyNoGuestIpv6)
    );
}

/// Two concurrent agent VMs, verbatim-shaped `ifconfig` output (trimmed from a
/// real macOS 26 / `container` 1.0.0 run): each session's gateway sits on its
/// own `bridgeN`, whose member is a `vmenetN`.
const TWO_BRIDGE_IFCONFIG: &str = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 172.20.10.2 netmask 0xfffffff0 broadcast 172.20.10.15
bridge100: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500 index 25
\tether fe:b2:14:ac:08:64
\tinet 192.168.221.1 netmask 0xffffff00 broadcast 192.168.221.255
\tinet6 fe80::fcb2:14ff:feac:864%bridge100 prefixlen 64 scopeid 0x19
\tinet6 fd63:866e:9743:5687:4cc:2cbc:101:9b86 prefixlen 64 tentative autoconf secured
\tConfiguration:
\t\tid 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
\tmember: vmenet0 flags=20003<LEARNING,DISCOVER,VIRTIO>
\t\tifmaxaddr 0 port 24 priority 0 path cost 0
\tAddress cache:
\t\tfa:d6:51:95:4:9b Vlan1 vmenet0 1200 flags=0<>
bridge101: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500 index 27
\tinet 192.168.222.1 netmask 0xffffff00 broadcast 192.168.222.255
\tinet6 fe80::fcb2:14ff:feac:865%bridge101 prefixlen 64 scopeid 0x1b
\tmember: vmenet1 flags=20003<LEARNING,DISCOVER,VIRTIO>
";

#[test]
fn discovery_maps_each_session_gateway_to_its_own_bridge_and_member() {
    let a = parse_bridge_for_gateway(TWO_BRIDGE_IFCONFIG, Ipv4Addr::new(192, 168, 221, 1)).unwrap();
    assert_eq!(a.bridge().as_str(), "bridge100");
    assert_eq!(
        a.members()
            .iter()
            .map(PfInterface::as_str)
            .collect::<Vec<_>>(),
        vec!["vmenet0"]
    );
    assert_eq!(
        a.deny_interfaces()
            .iter()
            .map(PfInterface::as_str)
            .collect::<Vec<_>>(),
        vec!["bridge100", "vmenet0"]
    );

    let b = parse_bridge_for_gateway(TWO_BRIDGE_IFCONFIG, Ipv4Addr::new(192, 168, 222, 1)).unwrap();
    assert_eq!(b.bridge().as_str(), "bridge101");
    assert_eq!(
        b.members()
            .iter()
            .map(PfInterface::as_str)
            .collect::<Vec<_>>(),
        vec!["vmenet1"]
    );
}

#[test]
fn discovery_fails_closed_when_no_interface_carries_the_gateway() {
    let err =
        parse_bridge_for_gateway(TWO_BRIDGE_IFCONFIG, Ipv4Addr::new(192, 168, 99, 1)).unwrap_err();
    assert!(matches!(
        err,
        GuestBridgeDiscoveryError::NoBridgeForGateway(_)
    ));
}

#[test]
fn discovery_matches_the_gateway_address_exactly_not_as_a_prefix() {
    // A bridge whose inet is 192.168.221.10 must not answer a query for
    // 192.168.221.1 — substring matching would silently deny the wrong bridge.
    let ifconfig = "\
bridge100: flags=8863<UP> mtu 1500\n\
\tinet 192.168.221.10 netmask 0xffffff00 broadcast 192.168.221.255\n\
\tmember: vmenet0 flags=20003<VIRTIO>\n";
    let err = parse_bridge_for_gateway(ifconfig, Ipv4Addr::new(192, 168, 221, 1)).unwrap_err();
    assert!(matches!(
        err,
        GuestBridgeDiscoveryError::NoBridgeForGateway(_)
    ));
    // The bridge that really holds .10 is found for a query on .10.
    let found = parse_bridge_for_gateway(ifconfig, Ipv4Addr::new(192, 168, 221, 10)).unwrap();
    assert_eq!(found.bridge().as_str(), "bridge100");
}
