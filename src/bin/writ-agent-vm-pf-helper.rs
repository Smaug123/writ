//! Manual privileged PF helper for Apple-container agent VM sessions.
//!
//! This binary is intended to be run with root privileges for now. It accepts
//! structured session firewall operations, validates them against the pools
//! and broker-port range in its root-owned policy file, then performs only
//! scoped `pfctl` changes.

use std::net::Ipv4Addr;
use std::path::Path;

use clap::{Args, Parser, Subcommand};
use writ::agent_vm_firewall::{
    DenyGuestIpv6, SessionFirewallRemoval, SessionFirewallSpec, SessionFirewallTools,
    install_session_firewall, pf_preflight, remove_session_firewall,
};
use writ::agent_vm_pf_helper_policy::{
    PF_HELPER_POLICY_PATH, PF_HELPER_POLICY_REQUIRED_OWNER, PfHelperPolicy, load_pf_helper_policy,
    parse_ipv4_cidr, parse_ipv6_cidr,
};
use writ::agent_vm_pf_helper_protocol::{
    PfHelperInstallReportDoc, PfHelperPreflightDoc, PfHelperProtocolDoc,
};
use writ::core::{BrokerPort, BrokerPorts, Ipv4Cidr, Ipv6Cidr, SessionId};

// Fixed, root-owned paths for every executable this helper runs. Deliberately
// not CLI/env options: a caller-supplied (or `PATH`-resolved) executable would
// be arbitrary root code execution when the helper runs under sudo. The library
// functions still take the path as a parameter so tests can inject a fake; only
// this binary pins them. The policy file's path and required owner are pinned
// for the same reason: a caller-chosen policy would hand the bounds back to the
// caller they bound.
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
    /// object, without reading the policy file or running `pfctl` or
    /// `ifconfig` at all. The daemon reads it as admission evidence for
    /// `ipv4_only_locked_v1`.
    ProtocolVersion,
    /// Report the host-local PF facts every session install is conditional on
    /// (the policy file's bounds, PF enabled, where `anchor "writ/session/*"`
    /// sits in the main ruleset, any `pass` translation rules loaded) as one
    /// bounded JSON object. Refuses if the policy file does not load. Runs
    /// only `pfctl` status queries; loads, flushes, and kills nothing. The
    /// daemon reads it as admission evidence for `ipv4_only_locked_v1`.
    Preflight,
    /// Validate a session against the policy file and install its PF rules,
    /// then read the anchor back and require it to be exactly the intended
    /// ruleset. Prints one bounded JSON object naming the anchor, the
    /// interfaces the IPv6 deny resolved to, and the last phase completed; a
    /// failure names its phase on stderr and exits non-zero.
    Install(InstallArgs),
    /// Remove PF rules and matching live states for one agent VM session.
    Remove(RemoveArgs),
}

#[derive(Args)]
struct InstallArgs {
    #[command(flatten)]
    session: SessionNetworkArgs,

    /// Broker port to allow from the VM. May be supplied more than once. Every
    /// port must lie inside the policy file's broker-port range.
    #[arg(long = "broker-port", required = true)]
    broker_ports: Vec<u16>,

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

    /// Agent session IPv4 subnet. Must be a /24 inside the policy file's
    /// IPv4 pool.
    #[arg(long)]
    ipv4_cidr: String,

    /// Agent session IPv6 prefix. If present, must be a /64 inside the policy
    /// file's IPv6 pool.
    #[arg(long)]
    ipv6_cidr: Option<String>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Everything the helper reaches outside its arguments: the two system tools
/// and the policy file. Production pins all of it here; tests inject a
/// temporary directory's worth at the unprivileged dispatch, never through
/// the CLI.
#[derive(Copy, Clone)]
struct Helper<'a> {
    tools: SessionFirewallTools<'a>,
    policy_path: &'a Path,
    policy_owner: u32,
}

impl Helper<'_> {
    fn policy(&self) -> Result<PfHelperPolicy, Box<dyn std::error::Error>> {
        Ok(load_pf_helper_policy(self.policy_path, self.policy_owner)?)
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    writ::telemetry::init("warn")?;
    let cli = Cli::parse();
    let helper = Helper {
        tools: SessionFirewallTools {
            pfctl: Path::new(SYSTEM_PFCTL),
            ifconfig: Path::new(SYSTEM_IFCONFIG),
        },
        policy_path: Path::new(PF_HELPER_POLICY_PATH),
        policy_owner: PF_HELPER_POLICY_REQUIRED_OWNER,
    };
    if let Some(line) = execute(cli.cmd, helper)? {
        println!("{line}");
    }
    Ok(())
}

/// Interpret one command. Returns the single line to print on success, if any.
fn execute(cmd: Cmd, helper: Helper<'_>) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match cmd {
        Cmd::ProtocolVersion => Ok(Some(PfHelperProtocolDoc::current().render())),
        Cmd::Preflight => {
            let policy = helper.policy()?;
            let report = pf_preflight(helper.tools.pfctl)?;
            Ok(Some(PfHelperPreflightDoc::new(report, policy).render()))
        }
        Cmd::Install(args) => {
            let policy = helper.policy()?;
            let parsed = parse_session_network(&args.session)?;
            let broker_ports = BrokerPorts::new(
                args.broker_ports
                    .into_iter()
                    .map(BrokerPort::new)
                    .collect::<Result<Vec<_>, _>>()?,
            )?;
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
                policy.pool(),
                parsed.ipv4,
                parsed.ipv6,
                broker_ports,
                policy.broker_port_range(),
                broker_host,
                deny_guest_ipv6,
            )?;
            let report = install_session_firewall(helper.tools, &spec)?;
            Ok(Some(PfHelperInstallReportDoc::verified(&report).render()))
        }
        Cmd::Remove(args) => {
            let policy = helper.policy()?;
            let parsed = parse_session_network(&args.session)?;
            let removal = SessionFirewallRemoval::new(
                parsed.session_id,
                policy.pool(),
                parsed.ipv4,
                parsed.ipv6,
            )?;
            remove_session_firewall(helper.tools.pfctl, &removal)?;
            Ok(None)
        }
    }
}

struct ParsedSessionNetwork {
    session_id: SessionId,
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
    let ipv4 = parse_ipv4_cidr(&args.ipv4_cidr).map_err(|e| format!("invalid --ipv4-cidr: {e}"))?;
    let ipv6 = args
        .ipv6_cidr
        .as_deref()
        .map(|raw| parse_ipv6_cidr(raw).map_err(|e| format!("invalid --ipv6-cidr: {e}")))
        .transpose()?;
    Ok(ParsedSessionNetwork {
        session_id,
        ipv4,
        ipv6,
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use clap::error::ErrorKind;
    use writ::agent_vm_firewall::SessionAnchorPlacement;
    use writ::core::{AgentNetworkPool, BrokerPortRange};

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

    fn policy() -> PfHelperPolicy {
        PfHelperPolicy::new(
            AgentNetworkPool::new(
                parse_ipv4_cidr("10.200.0.0/16").unwrap(),
                parse_ipv6_cidr("fd00:7772:6974::/48").unwrap(),
            )
            .unwrap(),
            BrokerPortRange::new(49152, 65535).unwrap(),
        )
    }

    /// A private directory holding the recorders and, unless `policy` is
    /// `None`, a policy file owned by this test's user.
    struct Fixture {
        dir: tempfile::TempDir,
        pfctl: PathBuf,
        pfctl_log: PathBuf,
        ifconfig: PathBuf,
        ifconfig_log: PathBuf,
        policy_path: PathBuf,
    }

    impl Fixture {
        fn new(policy: Option<PfHelperPolicy>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let (pfctl, pfctl_log) = write_recorder(dir.path(), "pfctl");
            let (ifconfig, ifconfig_log) = write_recorder(dir.path(), "ifconfig");
            let policy_path = dir.path().join("agent-vm-pf-policy.json");
            if let Some(policy) = policy {
                std::fs::write(&policy_path, policy.render()).unwrap();
                std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o644))
                    .unwrap();
            }
            Self {
                dir,
                pfctl,
                pfctl_log,
                ifconfig,
                ifconfig_log,
                policy_path,
            }
        }

        fn helper(&self) -> Helper<'_> {
            Helper {
                tools: SessionFirewallTools {
                    pfctl: &self.pfctl,
                    ifconfig: &self.ifconfig,
                },
                policy_path: &self.policy_path,
                // SAFETY: getuid has no preconditions and cannot fail.
                policy_owner: unsafe { libc::getuid() },
            }
        }
    }

    fn session_args() -> SessionNetworkArgs {
        SessionNetworkArgs {
            session_id: "0e3a2b52-0a2d-4f7c-9b9e-1d9c3e4f5a6b".to_string(),
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

    /// The bounds are the policy file's, not the caller's: the v1 arguments
    /// that carried them are refused outright, so a daemon that still passes
    /// them fails closed rather than being silently ignored.
    #[test]
    fn the_v1_bounds_arguments_are_no_longer_accepted() {
        for (cmd, flag, value) in [
            ("install", "--ipv4-pool", "10.200.0.0/16"),
            ("install", "--ipv6-pool", "fd00:7772:6974::/48"),
            ("install", "--broker-port-min", "49152"),
            ("install", "--broker-port-max", "65535"),
            ("remove", "--ipv4-pool", "10.200.0.0/16"),
            ("remove", "--ipv6-pool", "fd00:7772:6974::/48"),
        ] {
            let err = match Cli::try_parse_from([
                "writ-agent-vm-pf-helper",
                cmd,
                "--session-id",
                "0e3a2b52-0a2d-4f7c-9b9e-1d9c3e4f5a6b",
                "--ipv4-cidr",
                "10.200.7.0/24",
                "--broker-port",
                "49152",
                flag,
                value,
            ]) {
                Ok(_) => panic!("{cmd} {flag} was accepted"),
                Err(err) => err,
            };
            assert_eq!(
                err.kind(),
                ErrorKind::UnknownArgument,
                "{cmd} {flag}: {err}"
            );
        }
    }

    #[test]
    fn protocol_version_reads_nothing_and_prints_the_current_document() {
        // No policy file at all: the probe must still answer, because it is
        // what the daemon reads before anything else is trusted.
        let fixture = Fixture::new(None);

        let line = execute(Cmd::ProtocolVersion, fixture.helper())
            .unwrap()
            .unwrap();

        assert_eq!(
            PfHelperProtocolDoc::parse(&line),
            Ok(PfHelperProtocolDoc::current())
        );
        assert_eq!(PfHelperProtocolDoc::current().version(), 2);
        assert_eq!(recorded_calls(&fixture.pfctl_log), Vec::<String>::new());
        assert_eq!(recorded_calls(&fixture.ifconfig_log), Vec::<String>::new());
    }

    #[test]
    fn install_remove_and_preflight_refuse_without_a_loadable_policy() {
        let fixture = Fixture::new(None);
        let helper = fixture.helper();
        let commands = [
            Cmd::Preflight,
            Cmd::Install(InstallArgs {
                session: session_args(),
                broker_ports: vec![49152],
                broker_host: None,
                deny_guest_ipv6: false,
            }),
            Cmd::Remove(RemoveArgs {
                session: session_args(),
            }),
        ];
        for cmd in commands {
            let err = execute(cmd, helper).unwrap_err().to_string();
            assert!(err.contains("policy file"), "{err}");
        }
        // Nothing was touched: the policy is read before any tool runs.
        assert_eq!(recorded_calls(&fixture.pfctl_log), Vec::<String>::new());
        assert_eq!(recorded_calls(&fixture.ifconfig_log), Vec::<String>::new());

        // The recorders are live: with a policy, a remove shows up in the
        // same log, so the empty log above is evidence and not a broken probe.
        let fixture = Fixture::new(Some(policy()));
        execute(
            Cmd::Remove(RemoveArgs {
                session: session_args(),
            }),
            fixture.helper(),
        )
        .unwrap();
        assert!(!recorded_calls(&fixture.pfctl_log).is_empty());
        assert_eq!(recorded_calls(&fixture.ifconfig_log), Vec::<String>::new());
        drop(fixture.dir);
    }

    #[test]
    fn session_facts_are_validated_against_the_policy_not_the_caller() {
        let fixture = Fixture::new(Some(policy()));
        // A subnet outside the policy's pool is refused before any tool runs,
        // for install and remove alike.
        let outside = SessionNetworkArgs {
            ipv4_cidr: "192.168.7.0/24".to_string(),
            ..session_args()
        };
        let err = execute(
            Cmd::Install(InstallArgs {
                session: outside,
                broker_ports: vec![49152],
                broker_host: None,
                deny_guest_ipv6: false,
            }),
            fixture.helper(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not inside configured pool"), "{err}");
        let err = execute(
            Cmd::Remove(RemoveArgs {
                session: SessionNetworkArgs {
                    ipv4_cidr: "192.168.7.0/24".to_string(),
                    ..session_args()
                },
            }),
            fixture.helper(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not inside configured pool"), "{err}");
        // A port outside the policy's range likewise.
        let err = execute(
            Cmd::Install(InstallArgs {
                session: session_args(),
                broker_ports: vec![8080],
                broker_host: None,
                deny_guest_ipv6: false,
            }),
            fixture.helper(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("outside configured range"), "{err}");
        assert_eq!(recorded_calls(&fixture.pfctl_log), Vec::<String>::new());
    }

    #[test]
    fn preflight_runs_only_status_queries_and_prints_a_parseable_report() {
        let fixture = Fixture::new(Some(policy()));

        let line = execute(Cmd::Preflight, fixture.helper()).unwrap().unwrap();

        let doc = PfHelperPreflightDoc::parse(&line).unwrap();
        assert_eq!(doc.policy(), policy());
        // The recorder answers only `-s info`; every other query reads as
        // empty, so the report says: enabled, anchor absent, nothing loaded.
        assert!(doc.report().pf_enabled);
        assert_eq!(doc.report().session_anchor, SessionAnchorPlacement::Absent);
        assert_eq!(doc.report().pass_translation_rules, Vec::new());

        let calls = recorded_calls(&fixture.pfctl_log);
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
        assert_eq!(recorded_calls(&fixture.ifconfig_log), Vec::<String>::new());
    }
}
