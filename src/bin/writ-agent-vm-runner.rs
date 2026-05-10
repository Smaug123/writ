//! Manual unprivileged runner for Apple-container agent VM sessions.
//!
//! The runner owns lifecycle ordering around Apple `container`; privileged PF
//! changes still go through `writ-agent-vm-pf-helper`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use writ::agent_vm_lifecycle::{
    AgentVmResources, AgentVmSessionPlan, AgentVmSessionStateStore, AgentVmSessionStopPlan,
    AgentVmStartInvocation, AgentVmToolPaths, ContainerImage, Ipv6IsolationMode, ProcessInvocation,
    default_agent_vm_state_dir, start_agent_vm_session, start_managed_agent_vm_session,
    stop_agent_vm_session, stop_managed_agent_vm_session,
};
use writ::core::{
    AgentNetworkPool, BrokerPort, BrokerPortRange, BrokerPorts, Ipv4Cidr, Ipv6Cidr, SessionId,
};

#[derive(Parser)]
#[command(
    name = "writ-agent-vm-runner",
    about = "writ agent VM lifecycle runner"
)]
struct Cli {
    /// Path to Apple container CLI.
    #[arg(long, default_value = "container", env = "WRIT_CONTAINER")]
    container: PathBuf,

    /// Path to sudo.
    #[arg(long, default_value = "sudo", env = "WRIT_SUDO")]
    sudo: PathBuf,

    /// Path to writ-agent-vm-pf-helper. Defaults to a sibling of this binary.
    #[arg(long, env = "WRIT_AGENT_VM_PF_HELPER")]
    pf_helper: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create network, validate inspect output, install firewall, and start VM.
    Start(StartArgs),
    /// Remove VM, firewall, and network for one session.
    Stop(StopArgs),
    /// Start a VM session and persist the cleanup facts needed for managed stop.
    ManagedStart(ManagedStartArgs),
    /// Stop a VM session using only its persisted state record.
    ManagedStop(ManagedStopArgs),
}

#[derive(Args)]
struct StartArgs {
    #[command(flatten)]
    session: SessionArgs,

    /// Broker port to allow from the VM. May be supplied more than once.
    #[arg(long = "broker-port", required = true)]
    broker_ports: Vec<u16>,

    /// Minimum allowed broker listener port.
    #[arg(long, default_value_t = 49152)]
    broker_port_min: u16,

    /// Maximum allowed broker listener port.
    #[arg(long, default_value_t = 65535)]
    broker_port_max: u16,

    /// OCI image to run.
    #[arg(long, default_value = "alpine:latest")]
    image: String,

    /// VM CPU count.
    #[arg(long, default_value_t = 1)]
    cpus: u16,

    /// VM memory in MiB.
    #[arg(long, default_value_t = 512)]
    memory_mib: u32,

    /// IPv6 isolation posture required before the guest command is released.
    #[arg(long, value_enum, default_value = "dual-stack-required")]
    ipv6_mode: Ipv6ModeArg,

    /// Print commands instead of executing them.
    #[arg(long)]
    dry_run: bool,

    /// Optional command appended after the image. Use `--` before it.
    #[arg(last = true)]
    guest_command: Vec<String>,
}

#[derive(Args)]
struct StopArgs {
    #[command(flatten)]
    session: SessionArgs,

    /// IPv6 isolation mode used when the session was started.
    #[arg(long, value_enum)]
    ipv6_mode: Ipv6ModeArg,

    /// Print commands instead of executing them.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args)]
struct ManagedStartArgs {
    #[command(flatten)]
    start: StartArgs,

    /// Directory for managed session state records.
    #[arg(long, env = "WRIT_AGENT_VM_STATE_DIR")]
    state_dir: Option<PathBuf>,
}

#[derive(Args)]
struct ManagedStopArgs {
    /// Session UUID whose persisted state should drive cleanup.
    #[arg(long)]
    session_id: String,

    /// Directory for managed session state records.
    #[arg(long, env = "WRIT_AGENT_VM_STATE_DIR")]
    state_dir: Option<PathBuf>,

    /// Print commands instead of executing them.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args)]
struct SessionArgs {
    /// Session UUID used in VM/network names and PF anchors.
    #[arg(long)]
    session_id: String,

    /// Broker-owned IPv4 pool.
    #[arg(long)]
    ipv4_pool: String,

    /// Broker-owned IPv6 pool.
    #[arg(long)]
    ipv6_pool: String,

    /// Session subnet index inside both pools.
    #[arg(long)]
    subnet_index: u16,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum Ipv6ModeArg {
    /// Require Apple network inspect to report and match the planned IPv6 subnet.
    DualStackRequired,
    /// Allow missing Apple IPv6 inspect data only after proving the guest has no routable IPv6.
    Ipv4OnlyNoGuestIpv6,
}

impl From<Ipv6ModeArg> for Ipv6IsolationMode {
    fn from(value: Ipv6ModeArg) -> Self {
        match value {
            Ipv6ModeArg::DualStackRequired => Self::DualStackRequired,
            Ipv6ModeArg::Ipv4OnlyNoGuestIpv6 => Self::Ipv4OnlyNoGuestIpv6,
        }
    }
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
    let tools = AgentVmToolPaths::new(
        cli.container,
        cli.pf_helper.unwrap_or_else(default_pf_helper_path),
        cli.sudo,
    );

    match cli.cmd {
        Cmd::Start(args) => {
            let dry_run = args.dry_run;
            let plan = build_start_plan(args, tools)?;
            if dry_run {
                print_start_invocations(&plan.start_invocations());
            } else {
                start_agent_vm_session(&plan)?;
                println!("session_id={}", plan.session_id());
                println!("network={}", plan.names().network());
                println!("vm={}", plan.names().vm());
                for url in plan.broker_urls() {
                    println!("broker_url={}", url.as_str());
                }
            }
        }
        Cmd::Stop(args) => {
            let dry_run = args.dry_run;
            let plan = build_stop_plan(args, tools)?;
            if dry_run {
                print_invocations(&plan.stop_invocations());
            } else {
                stop_agent_vm_session(&plan)?;
            }
        }
        Cmd::ManagedStart(args) => {
            let dry_run = args.start.dry_run;
            let state_dir = args.state_dir;
            let plan = build_start_plan(args.start, tools)?;
            if dry_run {
                print_start_invocations(&plan.start_invocations());
            } else {
                let state_dir = resolve_state_dir(state_dir)?;
                let store = AgentVmSessionStateStore::new(state_dir);
                let state = start_managed_agent_vm_session(&store, &plan)?;
                println!("session_id={}", state.session_id());
                println!("network={}", state.names().network());
                println!("vm={}", state.names().vm());
                for url in state.broker_urls() {
                    println!("broker_url={}", url.as_str());
                }
            }
        }
        Cmd::ManagedStop(args) => {
            let dry_run = args.dry_run;
            let session_id = parse_session_id(&args.session_id)?;
            let state_dir = resolve_state_dir(args.state_dir)?;
            let store = AgentVmSessionStateStore::new(state_dir);
            if dry_run {
                let state = store.load(session_id)?;
                print_invocations(&state.to_stop_plan(tools).stop_invocations());
            } else {
                stop_managed_agent_vm_session(&store, session_id, tools)?;
            }
        }
    }
    Ok(())
}

fn resolve_state_dir(state_dir: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(match state_dir {
        Some(path) => path,
        None => default_agent_vm_state_dir()?,
    })
}

fn build_start_plan(
    args: StartArgs,
    tools: AgentVmToolPaths,
) -> Result<AgentVmSessionPlan, Box<dyn std::error::Error>> {
    let parsed = parse_session(&args.session)?;
    let broker_ports = BrokerPorts::new(
        args.broker_ports
            .into_iter()
            .map(BrokerPort::new)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let broker_port_range = BrokerPortRange::new(args.broker_port_min, args.broker_port_max)?;
    Ok(AgentVmSessionPlan::new(
        parsed.session_id,
        parsed.pool,
        args.session.subnet_index,
        broker_ports,
        broker_port_range,
        args.ipv6_mode.into(),
        ContainerImage::new(args.image)?,
        args.guest_command,
        AgentVmResources::new(args.cpus, args.memory_mib)?,
        tools,
    )?)
}

fn build_stop_plan(
    args: StopArgs,
    tools: AgentVmToolPaths,
) -> Result<AgentVmSessionStopPlan, Box<dyn std::error::Error>> {
    let parsed = parse_session(&args.session)?;
    Ok(AgentVmSessionStopPlan::new(
        parsed.session_id,
        parsed.pool,
        args.session.subnet_index,
        args.ipv6_mode.into(),
        tools,
    )?)
}

struct ParsedSession {
    session_id: SessionId,
    pool: AgentNetworkPool,
}

fn parse_session(args: &SessionArgs) -> Result<ParsedSession, Box<dyn std::error::Error>> {
    let session_id = parse_session_id(&args.session_id)?;
    let ipv4_pool = parse_ipv4_cidr(&args.ipv4_pool)?;
    let ipv6_pool = parse_ipv6_cidr(&args.ipv6_pool)?;
    Ok(ParsedSession {
        session_id,
        pool: AgentNetworkPool::new(ipv4_pool, ipv6_pool)?,
    })
}

fn parse_session_id(raw: &str) -> Result<SessionId, Box<dyn std::error::Error>> {
    raw.parse()
        .map_err(|e| format!("invalid session ID: {e}").into())
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

fn print_invocations(invocations: &[ProcessInvocation]) {
    for invocation in invocations {
        println!("{}", invocation.display_shell());
    }
}

fn print_start_invocations(invocations: &[AgentVmStartInvocation]) {
    for invocation in invocations {
        println!("{}", invocation.display_shell());
    }
}

fn default_pf_helper_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.parent()
                .map(|parent| parent.join("writ-agent-vm-pf-helper"))
        })
        .unwrap_or_else(|| PathBuf::from("writ-agent-vm-pf-helper"))
}

#[cfg(test)]
mod tests {
    use clap::error::ErrorKind;

    use super::*;

    #[test]
    fn stop_requires_explicit_ipv6_mode() {
        let err = match Cli::try_parse_from([
            "writ-agent-vm-runner",
            "stop",
            "--session-id",
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            "--ipv4-pool",
            "192.168.0.0/16",
            "--ipv6-pool",
            "fd83:b6f2:e57::/48",
            "--subnet-index",
            "252",
        ]) {
            Ok(_) => panic!("stop parsed without explicit IPv6 mode"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn stop_accepts_explicit_ipv6_mode() {
        let cli = Cli::try_parse_from([
            "writ-agent-vm-runner",
            "stop",
            "--session-id",
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            "--ipv4-pool",
            "192.168.0.0/16",
            "--ipv6-pool",
            "fd83:b6f2:e57::/48",
            "--subnet-index",
            "252",
            "--ipv6-mode",
            "ipv4-only-no-guest-ipv6",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::Stop(args) => assert_eq!(args.ipv6_mode, Ipv6ModeArg::Ipv4OnlyNoGuestIpv6),
            Cmd::Start(_) | Cmd::ManagedStart(_) | Cmd::ManagedStop(_) => {
                panic!("expected stop command")
            }
        }
    }

    #[test]
    fn managed_stop_requires_only_session_id_for_cleanup_scope() {
        let cli = Cli::try_parse_from([
            "writ-agent-vm-runner",
            "managed-stop",
            "--session-id",
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::ManagedStop(args) => {
                assert_eq!(args.session_id, "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d");
            }
            Cmd::Start(_) | Cmd::Stop(_) | Cmd::ManagedStart(_) => {
                panic!("expected managed-stop command")
            }
        }
    }
}
