//! Manual privileged PF helper for Apple-container agent VM sessions.
//!
//! This binary is intended to be run with root privileges for now. It accepts
//! structured session firewall operations, validates them against configured
//! network and broker-port ranges, then performs only scoped `pfctl` changes.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use clap::{Args, Parser, Subcommand};
use writ::agent_vm_firewall::{
    DenyGuestIpv6, SessionFirewallRemoval, SessionFirewallSpec, SessionFirewallTools,
    install_session_firewall, pf_preflight, remove_session_firewall,
};
use writ::agent_vm_pf_helper_protocol::{
    PfHelperInstallReportDoc, PfHelperPreflightDoc, PfHelperProtocolDoc,
};
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
    /// Report the host-local PF facts every session install is conditional on
    /// (PF enabled, where `anchor "writ/session/*"` sits in the main ruleset,
    /// any `pass` translation rules loaded) as one bounded JSON object. Runs
    /// only `pfctl` status queries; loads, flushes, and kills nothing. The
    /// daemon reads it as admission evidence for `ipv4_only_locked_v1`.
    Preflight,
    /// Validate and install PF rules for one agent VM session, then read the
    /// anchor back and require it to be exactly the intended ruleset. Prints
    /// one bounded JSON object naming the anchor, the interfaces the IPv6 deny
    /// resolved to, and the last phase completed; a failure names its phase on
    /// stderr and exits non-zero.
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
    /// gateway in `ifconfig` output — never trusted from the caller — and
    /// discovered again after the load, which must find the same names. Requires
    /// the agent VM (hence its bridge) to be running, and is rejected with
    /// `--ipv6-cidr`.
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

fn run() -> Result<(), Box<dyn std::error::Error>> {
    writ::telemetry::init("warn")?;
    let cli = Cli::parse();
    let tools = SessionFirewallTools {
        pfctl: Path::new(SYSTEM_PFCTL),
        ifconfig: Path::new(SYSTEM_IFCONFIG),
    };
    if let Some(line) = execute(cli.cmd, tools)? {
        println!("{line}");
    }
    Ok(())
}

/// Interpret one command. Returns the single line to print on success, if any.
fn execute(
    cmd: Cmd,
    tools: SessionFirewallTools<'_>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match cmd {
        Cmd::ProtocolVersion => Ok(Some(PfHelperProtocolDoc::current().render())),
        Cmd::Preflight => {
            let report = pf_preflight(tools.pfctl)?;
            Ok(Some(PfHelperPreflightDoc::new(report).render()))
        }
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
            // The deny interfaces are discovered by the library, from the
            // pool-validated session gateway — the privileged boundary never
            // trusts caller-supplied interface names, and the discovery tool is
            // a fixed, root-owned system path. The agent's own vmenet must have
            // attached, so require its member: host placement has one (the
            // agent's), vm placement shares the bridge with the broker VM, so
            // require two (the broker's plus the agent's). `--broker-host` is
            // set exactly for vm placement, so it distinguishes the two.
            let deny_guest_ipv6 = args.deny_guest_ipv6.then_some(DenyGuestIpv6 {
                min_members: if broker_host.is_some() { 2 } else { 1 },
            });
            let spec = SessionFirewallSpec::new(
                parsed.session_id,
                parsed.pool,
                parsed.ipv4,
                parsed.ipv6,
                broker_ports,
                broker_port_range,
                broker_host,
                deny_guest_ipv6,
            )?;
            let report = install_session_firewall(tools, &spec)?;
            Ok(Some(PfHelperInstallReportDoc::verified(&report).render()))
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

    use writ::agent_vm_firewall::SessionAnchorPlacement;

    use super::*;

    /// A stand-in for `pfctl`/`ifconfig` that appends every argument vector it
    /// is invoked with to a log beside itself, answers `-s info` as an enabled
    /// PF, and otherwise succeeds silently.
    fn write_recorder(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
        let path = dir.join(name);
        let log = dir.join(format!("{name}.calls"));
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n\
                 [ \"$*\" = '-s info' ] && printf 'Status: Enabled for 0 days 00:00:01\\n'\n\
                 exit 0\n",
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
    fn protocol_version_and_preflight_are_standalone_subcommands() {
        let cli = Cli::try_parse_from(["writ-agent-vm-pf-helper", "protocol-version"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::ProtocolVersion));
        let cli = Cli::try_parse_from(["writ-agent-vm-pf-helper", "preflight"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Preflight));
        // They take no session facts: any argument is a usage error, so a
        // caller cannot smuggle an install through the probe's spelling.
        for probe in ["protocol-version", "preflight"] {
            assert!(
                Cli::try_parse_from(["writ-agent-vm-pf-helper", probe, "--session-id", "x"])
                    .is_err()
            );
        }
    }

    #[test]
    fn protocol_version_invokes_no_tool_and_prints_the_current_document() {
        let dir = tempfile::tempdir().unwrap();
        let (pfctl, pfctl_log) = write_recorder(dir.path(), "pfctl");
        let (ifconfig, ifconfig_log) = write_recorder(dir.path(), "ifconfig");
        let tools = SessionFirewallTools {
            pfctl: &pfctl,
            ifconfig: &ifconfig,
        };

        let line = execute(Cmd::ProtocolVersion, tools).unwrap().unwrap();

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
            tools,
        )
        .unwrap();
        assert!(!recorded_calls(&pfctl_log).is_empty());
        assert_eq!(recorded_calls(&ifconfig_log), Vec::<String>::new());
    }

    #[test]
    fn preflight_runs_only_status_queries_and_prints_a_parseable_report() {
        let dir = tempfile::tempdir().unwrap();
        let (pfctl, pfctl_log) = write_recorder(dir.path(), "pfctl");
        let (ifconfig, ifconfig_log) = write_recorder(dir.path(), "ifconfig");
        let tools = SessionFirewallTools {
            pfctl: &pfctl,
            ifconfig: &ifconfig,
        };

        let line = execute(Cmd::Preflight, tools).unwrap().unwrap();

        let doc = PfHelperPreflightDoc::parse(&line).unwrap();
        // The recorder answers only `-s info`; every other query reads as
        // empty, so the report says: enabled, anchor absent, nothing loaded.
        assert!(doc.report().pf_enabled);
        assert_eq!(doc.report().session_anchor, SessionAnchorPlacement::Absent);
        assert_eq!(doc.report().pass_translation_rules, Vec::new());

        let calls = recorded_calls(&pfctl_log);
        assert_eq!(calls, vec!["-s info", "-sr", "-sn", "-v -sA"]);
        // Nothing that changes PF: no load (`-f`), flush (`-F`), or state kill
        // (`-k`).
        for call in &calls {
            for mutating in ["-f", "-F", "-k"] {
                assert!(
                    !call.split(' ').any(|arg| arg == mutating),
                    "preflight ran a mutating pfctl call: {call}"
                );
            }
        }
        assert_eq!(recorded_calls(&ifconfig_log), Vec::<String>::new());
    }
}
