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
            AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo"),
        ),
        Err(AgentVmLifecycleConfigError::EmptyGuestCommandForIpv4OnlyNoGuestIpv6)
    );
}
