//! Render the PF anchor name or rules for the Apple-container VM proof harness.
//!
//! This is intentionally a thin command-line edge around `core::agent_vm`.
//! The policy remains in the pure core model; scripts and future privileged
//! helpers should consume the rendered description rather than duplicating it.

use std::net::{Ipv4Addr, Ipv6Addr};

use clap::{Parser, Subcommand};
use writ::core::{
    AgentNetworkPool, BrokerPort, BrokerPorts, Ipv4Cidr, Ipv6Cidr, SessionId, render_pf,
    session_pf_ruleset,
};

#[derive(Parser)]
#[command(name = "writ-render-agent-vm-pf")]
struct Args {
    /// Session UUID used in the PF anchor path.
    #[arg(long)]
    session_id: String,

    /// Agent IPv4 subnet, currently one /24 Apple container network.
    #[arg(long)]
    ipv4_cidr: String,

    /// Agent IPv6 prefix, currently one /64 Apple container network.
    #[arg(long)]
    ipv6_cidr: String,

    /// Broker port to allow from the VM. May be supplied more than once.
    #[arg(long = "broker-port", required = true)]
    broker_ports: Vec<u16>,

    #[command(subcommand)]
    output: Output,
}

#[derive(Subcommand)]
enum Output {
    /// Print only the PF anchor path.
    Anchor,
    /// Print only the PF rules body for that anchor.
    Rules,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let session_id: SessionId = args
        .session_id
        .parse()
        .map_err(|e| format!("invalid session ID: {e}"))?;
    let ipv4 = parse_ipv4_cidr(&args.ipv4_cidr)?;
    let ipv6 = parse_ipv6_cidr(&args.ipv6_cidr)?;
    if ipv4.prefix() != 24 {
        return Err(format!("agent IPv4 subnet must be /24, got {ipv4}").into());
    }
    if ipv6.prefix() != 64 {
        return Err(format!("agent IPv6 prefix must be /64, got {ipv6}").into());
    }

    let pool = AgentNetworkPool::new(ipv4, ipv6)?;
    let network = pool.allocate(0)?;
    let broker_ports = BrokerPorts::new(
        args.broker_ports
            .into_iter()
            .map(BrokerPort::new)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let ruleset = session_pf_ruleset(session_id, network, &broker_ports);

    match args.output {
        Output::Anchor => println!("{}", ruleset.anchor().as_str()),
        Output::Rules => print!("{}", render_pf(&ruleset)),
    }
    Ok(())
}

fn parse_ipv4_cidr(raw: &str) -> Result<Ipv4Cidr, Box<dyn std::error::Error>> {
    let (addr, prefix) = split_cidr(raw)?;
    Ok(Ipv4Cidr::new(
        addr.parse::<Ipv4Addr>()?,
        prefix.parse::<u8>()?,
    )?)
}

fn parse_ipv6_cidr(raw: &str) -> Result<Ipv6Cidr, Box<dyn std::error::Error>> {
    let (addr, prefix) = split_cidr(raw)?;
    Ok(Ipv6Cidr::new(
        addr.parse::<Ipv6Addr>()?,
        prefix.parse::<u8>()?,
    )?)
}

fn split_cidr(raw: &str) -> Result<(&str, &str), Box<dyn std::error::Error>> {
    raw.split_once('/')
        .ok_or_else(|| format!("CIDR value must contain '/', got {raw:?}").into())
}
