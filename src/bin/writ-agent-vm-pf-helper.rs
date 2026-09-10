//! Manual privileged PF helper for Apple-container agent VM sessions.
//!
//! This binary is intended to be run with root privileges for now. It accepts
//! structured session firewall operations, validates them against configured
//! network and broker-port ranges, then performs only scoped `pfctl` changes.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use clap::{Args, Parser, Subcommand};
use writ::agent_vm_firewall::{
    SessionFirewallInstall, SessionFirewallRemoval, discover_session_bridge_interfaces,
    install_session_firewall, remove_session_firewall,
};
use writ::agent_vm_pf_helper_protocol::PfHelperProtocolDoc;
use writ::core::{
    AgentNetworkPool, BrokerPort, BrokerPortRange, BrokerPorts, Ipv4Cidr, Ipv6Cidr, SessionId,
};

// Fixed, root-owned paths for every executable this helper runs. Deliberately
// not CLI/env options: a caller-supplied (or `PATH`-resolved) executable would
// be arbitrary root code execution when the helper runs under sudo. The library
// functions still take the path as a parameter so tests can inject a fake; only
// this binary pins them.
const SYSTEM_PFCTL: &str = "/sbin/pfctl";
const SYSTEM_IFCONFIG: &str = "/sbin/ifconfig";

#[derive(Parser)]
#[command(name = "writ-agent-vm-pf-helper", about = "writ agent VM PF helper")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Report this helper's protocol name and version as one bounded JSON
    /// object, without running `pfctl` or `ifconfig` at all. The daemon reads
    /// it as admission evidence for `ipv4_only_locked_v1`.
    ProtocolVersion,
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

/// The executables the helper may run. Production pins the system paths
/// ([`SYSTEM_PFCTL`], [`SYSTEM_IFCONFIG`]); tests inject recorders here, at the
/// unprivileged dispatch, never through the CLI.
struct HelperTools<'a> {
    pfctl: &'a Path,
    ifconfig: &'a Path,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    writ::telemetry::init("warn")?;
    let cli = Cli::parse();
    let tools = HelperTools {
        pfctl: Path::new(SYSTEM_PFCTL),
        ifconfig: Path::new(SYSTEM_IFCONFIG),
    };
    if let Some(line) = execute(cli.cmd, &tools)? {
        println!("{line}");
    }
    Ok(())
}

/// Interpret one command. Returns the single line to print on success, if any.
fn execute(
    cmd: Cmd,
    tools: &HelperTools<'_>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match cmd {
        Cmd::ProtocolVersion => Ok(Some(PfHelperProtocolDoc::current().render())),
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
            // interface names. The discovery tool is a fixed, root-owned system
            // path (never a caller-supplied executable, which would be arbitrary
            // root code execution). The agent's own vmenet must have attached, so
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
                discover_session_bridge_interfaces(tools.ifconfig, gateway, min_members)?
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
            install_session_firewall(tools.pfctl, &install)?;
            Ok(Some(install.ruleset().anchor().as_str().to_string()))
        }
        Cmd::Remove(args) => {
            let parsed = parse_session_network(&args.session)?;
            let removal = SessionFirewallRemoval::new(
                parsed.session_id,
                parsed.pool,
                parsed.ipv4,
                parsed.ipv6,
            )?;
            remove_session_firewall(tools.pfctl, &removal)?;
            Ok(None)
        }
    }
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    /// A stand-in for `pfctl`/`ifconfig` that appends every argument vector it
    /// is invoked with to a log beside itself and otherwise succeeds silently.
    fn write_recorder(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
        let path = dir.join(name);
        let log = dir.join(format!("{name}.calls"));
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexit 0\n",
                log.display()
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&path, perms).unwrap();
        (path, log)
    }

    fn recorded_calls(log: &Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn session_args() -> SessionNetworkArgs {
        SessionNetworkArgs {
            session_id: "0e3a2b52-0a2d-4f7c-9b9e-1d9c3e4f5a6b".to_string(),
            ipv4_pool: "10.200.0.0/16".to_string(),
            ipv6_pool: "fd00:7772:6974::/48".to_string(),
            ipv4_cidr: "10.200.7.0/24".to_string(),
            ipv6_cidr: None,
        }
    }

    #[test]
    fn protocol_version_is_a_standalone_subcommand() {
        let cli = Cli::try_parse_from(["writ-agent-vm-pf-helper", "protocol-version"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::ProtocolVersion));
        // It takes no session facts: any argument is a usage error, so a caller
        // cannot smuggle an install through the probe's spelling.
        assert!(
            Cli::try_parse_from([
                "writ-agent-vm-pf-helper",
                "protocol-version",
                "--session-id",
                "x"
            ])
            .is_err()
        );
    }

    #[test]
    fn protocol_version_invokes_no_tool_and_prints_the_current_document() {
        let dir = tempfile::tempdir().unwrap();
        let (pfctl, pfctl_log) = write_recorder(dir.path(), "pfctl");
        let (ifconfig, ifconfig_log) = write_recorder(dir.path(), "ifconfig");
        let tools = HelperTools {
            pfctl: &pfctl,
            ifconfig: &ifconfig,
        };

        let line = execute(Cmd::ProtocolVersion, &tools).unwrap().unwrap();

        assert_eq!(
            PfHelperProtocolDoc::parse(&line),
            Ok(PfHelperProtocolDoc::current())
        );
        assert_eq!(recorded_calls(&pfctl_log), Vec::<String>::new());
        assert_eq!(recorded_calls(&ifconfig_log), Vec::<String>::new());

        // The recorders are live: a command that does touch PF shows up in the
        // same log, so the empty log above is evidence and not a broken probe.
        execute(
            Cmd::Remove(RemoveArgs {
                session: session_args(),
            }),
            &tools,
        )
        .unwrap();
        assert!(!recorded_calls(&pfctl_log).is_empty());
        assert_eq!(recorded_calls(&ifconfig_log), Vec::<String>::new());
    }
}
