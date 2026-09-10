//! The readback grammar against the real `pfctl`.
//!
//! `writ::core::render_pf_readback` claims to print a session ruleset exactly
//! as `pfctl -sr` will after loading it. The only authority on that is pfctl
//! itself, so this test renders generated rulesets with `render_pf`, hands each
//! to `pfctl -nvf` (parse and echo the normalised rules, load nothing, no root
//! needed), and requires the echo to be the macro line followed by exactly the
//! rendered readback.
//!
//! Ignored by default because CI runs on Linux, which has no pfctl; run it on
//! macOS with `cargo test --test pf_readback_real_pfctl -- --ignored`. It
//! fails, not skips, if `/sbin/pfctl` is missing, so it cannot pass vacuously
//! where it is meant to run.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, TestRunner};
use writ::core::{
    AgentNetworkPool, BrokerPort, BrokerPorts, Ipv4Cidr, Ipv6Cidr, PfInterface, PfRuleset,
    SessionId, render_pf, render_pf_readback, session_firewall_pf_ruleset, session_pf_ruleset,
};

const PFCTL: &str = "/sbin/pfctl";

fn arb_interface() -> impl Strategy<Value = PfInterface> {
    "[a-zA-Z][a-zA-Z0-9]{0,14}".prop_map(|name| PfInterface::new(name).unwrap())
}

/// Any session ruleset the shipped renderer can build: IPv4-only or
/// dual-stack scope, optional broker-host override, any deny interfaces,
/// several ports.
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
                let ports =
                    BrokerPorts::new(ports.into_iter().map(|port| BrokerPort::new(port).unwrap()))
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
                    let network = pool.claim(ipv4, ipv6).unwrap();
                    session_pf_ruleset(session_id, network, &ports)
                } else {
                    let network = pool.claim_firewall(ipv4, None).unwrap();
                    let broker_host = broker_host.map(|host| Ipv4Addr::new(10, 200, v4_slot, host));
                    session_firewall_pf_ruleset(
                        session_id,
                        network,
                        &ports,
                        broker_host,
                        &interfaces,
                    )
                }
            },
        )
}

fn pfctl_normalises(rendered: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.conf");
    std::fs::write(&path, rendered).unwrap();
    let mut command = Command::new(PFCTL);
    command
        .arg("-nvf")
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = writ::process_spawn::output(&mut command).expect("spawn pfctl");
    assert!(
        output.status.success(),
        "pfctl -nvf failed: {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("pfctl output is UTF-8")
}

#[test]
#[ignore = "needs macOS pfctl; run explicitly with --ignored"]
fn pfctl_echoes_every_generated_ruleset_as_its_rendered_readback() {
    assert!(
        std::path::Path::new(PFCTL).exists(),
        "{PFCTL} is missing: this test only means something where pfctl exists"
    );
    let mut runner = TestRunner::new(Config::default());
    let strategy = arb_session_ruleset();
    for _ in 0..256 {
        let ruleset = strategy.new_tree(&mut runner).unwrap().current();
        let rendered = render_pf(&ruleset);
        // `-v` echoes the macro definition line before the normalised rules.
        let macro_line = rendered.lines().next().unwrap();
        let expected = format!(
            "{macro_line}\n{}",
            render_pf_readback(&ruleset.readback_rules())
        );
        let actual = pfctl_normalises(&rendered);
        assert_eq!(actual, expected, "rendered file:\n{rendered}");
    }
}
