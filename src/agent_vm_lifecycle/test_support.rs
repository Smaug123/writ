//! Shared fixtures for the `agent_vm_lifecycle` test modules.
//! Hoisted here so the per-concern `*_tests` modules and the inline
//! `spec` module reuse one set of plan/pool constructors instead of
//! each re-defining them.
//!
//! `super::*` re-exports the production items and the `crate::core`
//! types that `agent_vm_lifecycle` pulls in privately; the explicit
//! `use`s below cover the test-only constructors these helpers call.

use super::*;
use crate::core::BrokerPort;
use std::net::{Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

pub(super) fn session_id() -> SessionId {
    SessionId::from_uuid(Uuid::from_u128(0x51b8_fd0f_6c10_454c_b0e6_7df1_d60e_2e6d))
}

pub(super) fn pool() -> AgentNetworkPool {
    AgentNetworkPool::new(
        Ipv4Cidr::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
        Ipv6Cidr::new(
            Ipv6Addr::from(0xfd83_b6f2_0e57_0000_0000_0000_0000_0000u128),
            48,
        )
        .unwrap(),
    )
    .unwrap()
}

pub(super) fn ports() -> BrokerPorts {
    BrokerPorts::new([BrokerPort::new(51375).unwrap()]).unwrap()
}

pub(super) fn plan(index: u16) -> AgentVmSessionPlan {
    plan_with_ipv6_mode(index, Ipv6IsolationMode::DualStackRequired)
}

pub(super) fn plan_with_ipv6_mode(index: u16, ipv6_mode: Ipv6IsolationMode) -> AgentVmSessionPlan {
    AgentVmSessionPlan::new(
        session_id(),
        pool(),
        index,
        ports(),
        BrokerPortRange::new(49152, 65535).unwrap(),
        ipv6_mode,
        ContainerImage::new("alpine:latest").unwrap(),
        vec!["sleep".into(), "600".into()],
        AgentVmResources::new(1, 512).unwrap(),
        AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo"),
    )
    .unwrap()
}

pub(super) fn plan_with_broker_placement(
    index: u16,
    broker_placement: BrokerPlacement,
) -> AgentVmSessionPlan {
    AgentVmSessionPlan::new_with_guest_env(
        session_id(),
        pool(),
        index,
        ports(),
        BrokerPortRange::new(49152, 65535).unwrap(),
        Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
        broker_placement,
        ContainerImage::new("alpine:latest").unwrap(),
        Vec::new(),
        vec!["sleep".into(), "600".into()],
        AgentVmResources::new(1, 512).unwrap(),
        AgentVmToolPaths::new("container", "writ-agent-vm-pf-helper", "sudo"),
    )
    .unwrap()
}
