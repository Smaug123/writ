//! Manual privileged PF helper for Apple-container agent VM sessions.
//!
//! This binary is intended to be run with root privileges for now. It accepts
//! structured session firewall operations, validates them against configured
//! network and broker-port ranges, then performs only scoped `pfctl` changes.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use writ::agent_vm_firewall::{
    SessionFirewallInstall, SessionFirewallRemoval, discover_session_bridge_interfaces,
    install_session_firewall, remove_session_firewall,
};
use writ::core::{
    AgentNetworkPool, BrokerPort, BrokerPortRange, BrokerPorts, Ipv4Cidr, Ipv6Cidr, SessionId,
};

#[derive(Parser)]
#[command(name = "writ-agent-vm-pf-helper", about = "writ agent VM PF helper")]
struct Cli {
    /// Path to pfctl.
    #[arg(long, default_value = "pfctl", env = "WRIT_PFCTL")]
    pfctl: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Validate and install PF rules for one agent VM session.
    Install(InstallArgs),
    /// Remove PF rules and matching live states for one agent VM session.
    Remove(RemoveArgs),
}

#[derive(Args)]
struct InstallArgs {
    #[command(flatten)]
    session: SessionNetworkArgs,

    /// Broker port to allow from the VM. May be supplied more than once.
    #[arg(long = "broker-port", required = true)]
    broker_ports: Vec<u16>,

    /// Minimum allowed broker listener port.
    #[arg(long, default_value_t = 49152)]
    broker_port_min: u16,

    /// Maximum allowed broker listener port.
    #[arg(long, default_value_t = 65535)]
    broker_port_max: u16,

    /// IPv4 endpoint the agent is allowed to reach on the broker ports. Defaults
    /// to the subnet gateway (the host broker). For broker_placement = vm, pass
    /// the broker VM's IP on the agent subnet so the agent reaches its broker VM
    /// while the gateway and the rest of the subnet stay blocked.
    #[arg(long)]
    broker_host: Option<String>,

    /// Install the `Ipv4OnlyNoGuestIpv6` backstop: block *all* IPv6 on the agent
    /// VM's host bridge (and its `vmenet` members) so a root guest cannot
    /// re-acquire IPv6 via a host vmnet router advertisement. The interfaces are
    /// discovered *here*, at the privileged boundary, by matching the session
    /// gateway in `ifconfig` output — never trusted from the caller. Requires the
    /// agent VM (hence its bridge) to be running, and is rejected with `--ipv6-cidr`.
    #[arg(long)]
    deny_guest_ipv6: bool,

    /// Path to `ifconfig`, used to discover the agent VM's bridge for
    /// `--deny-guest-ipv6`.
    #[arg(long, default_value = "/sbin/ifconfig", env = "WRIT_IFCONFIG")]
    ifconfig: PathBuf,
}

#[derive(Args)]
struct RemoveArgs {
    #[command(flatten)]
    session: SessionNetworkArgs,
}

#[derive(Args)]
struct SessionNetworkArgs {
    /// Session UUID used in the PF anchor path.
    #[arg(long)]
    session_id: String,

    /// Broker-owned IPv4 pool from which the session subnet must come.
    #[arg(long)]
    ipv4_pool: String,

    /// Broker-owned IPv6 pool from which any session prefix must come.
    #[arg(long)]
    ipv6_pool: String,

    /// Agent session IPv4 subnet. Must be a /24 inside --ipv4-pool.
    #[arg(long)]
    ipv4_cidr: String,

    /// Agent session IPv6 prefix. If present, must be a /64 inside --ipv6-pool.
    #[arg(long)]
    ipv6_cidr: Option<String>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    writ::telemetry::init("warn")?;
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Install(args) => {
            let parsed = parse_session_network(&args.session)?;
            let broker_ports = BrokerPorts::new(
                args.broker_ports
                    .into_iter()
                    .map(BrokerPort::new)
                    .collect::<Result<Vec<_>, _>>()?,
            )?;
            let broker_port_range =
                BrokerPortRange::new(args.broker_port_min, args.broker_port_max)?;
            let broker_host = args
                .broker_host
                .as_deref()
                .map(|raw| raw.parse::<Ipv4Addr>())
                .transpose()
                .map_err(|e| format!("invalid --broker-host: {e}"))?;
            // Discover the deny interfaces here, from the pool-validated session
            // gateway — the privileged boundary never trusts caller-supplied
            // interface names. The agent's own vmenet must have attached, so
            // require its member: host placement has one (the agent's), vm
            // placement shares the bridge with the broker VM, so require two (the
            // broker's plus the agent's). `--broker-host` is set exactly for vm
            // placement, so it distinguishes the two.
            let ipv6_deny_interfaces = if args.deny_guest_ipv6 {
                let gateway = parsed
                    .pool
                    .claim_firewall(parsed.ipv4, parsed.ipv6)?
                    .ipv4_gateway();
                let min_members = if broker_host.is_some() { 2 } else { 1 };
                discover_session_bridge_interfaces(&args.ifconfig, gateway, min_members)?
                    .deny_interfaces()
            } else {
                Vec::new()
            };
            let install = SessionFirewallInstall::new(
                parsed.session_id,
                parsed.pool,
                parsed.ipv4,
                parsed.ipv6,
                broker_ports,
                broker_port_range,
                broker_host,
                ipv6_deny_interfaces,
            )?;
            install_session_firewall(&cli.pfctl, &install)?;
            println!("{}", install.ruleset().anchor().as_str());
        }
        Cmd::Remove(args) => {
            let parsed = parse_session_network(&args.session)?;
            let removal = SessionFirewallRemoval::new(
                parsed.session_id,
                parsed.pool,
                parsed.ipv4,
                parsed.ipv6,
            )?;
            remove_session_firewall(&cli.pfctl, &removal)?;
        }
    }
    Ok(())
}

struct ParsedSessionNetwork {
    session_id: SessionId,
    pool: AgentNetworkPool,
    ipv4: Ipv4Cidr,
    ipv6: Option<Ipv6Cidr>,
}

fn parse_session_network(
    args: &SessionNetworkArgs,
) -> Result<ParsedSessionNetwork, Box<dyn std::error::Error>> {
    let session_id: SessionId = args
        .session_id
        .parse()
        .map_err(|e| format!("invalid session ID: {e}"))?;
    let ipv4_pool = parse_ipv4_cidr(&args.ipv4_pool)?;
    let ipv6_pool = parse_ipv6_cidr(&args.ipv6_pool)?;
    let ipv4 = parse_ipv4_cidr(&args.ipv4_cidr)?;
    let ipv6 = args.ipv6_cidr.as_deref().map(parse_ipv6_cidr).transpose()?;
    Ok(ParsedSessionNetwork {
        session_id,
        pool: AgentNetworkPool::new(ipv4_pool, ipv6_pool)?,
        ipv4,
        ipv6,
    })
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
