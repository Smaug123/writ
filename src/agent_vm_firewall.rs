//! Manual PF helper for Apple-container agent VM sessions.
//!
//! The pure constructors validate that a requested session firewall belongs to
//! broker-owned network and port ranges. The executor is intentionally small:
//! it interprets those validated descriptions as scoped `pfctl` calls.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use uuid::Uuid;

use crate::agent_vm_lifecycle::{
    GuestBridgeDiscovery, GuestBridgeDiscoveryError, parse_bridge_for_gateway,
};
use crate::core::{
    AgentFirewallNetwork, AgentNetworkPool, AgentVmConfigError, BrokerPortRange, BrokerPorts,
    Ipv4Cidr, Ipv6Cidr, PfAnchorName, PfInterface, PfRuleset, SessionId, render_pf,
    session_firewall_pf_ruleset,
};
use crate::process_supervisor::{self, StderrMode, StdoutMode, SupervisedOutcome};

/// The host bridge for a session's network is created a beat after `container
/// run` returns and its members attach shortly after, so the privileged helper
/// retries discovery on this cadence before failing closed.
const BRIDGE_DISCOVERY_ATTEMPTS: u32 = 40;
const _: () = assert!(
    BRIDGE_DISCOVERY_ATTEMPTS > 0,
    "discover_session_bridge_interfaces requires at least one attempt"
);
const BRIDGE_DISCOVERY_DELAY: Duration = Duration::from_millis(250);

#[derive(Debug, thiserror::Error)]
pub enum BridgeDiscoveryError {
    #[error("cannot run {program}: {source}")]
    Run {
        program: String,
        source: std::io::Error,
    },
    #[error("{program} failed with status {status}: {stderr}")]
    Failed {
        program: String,
        status: String,
        stderr: String,
    },
    #[error(transparent)]
    Discovery(#[from] GuestBridgeDiscoveryError),
}

/// Discover the agent VM's host bridge and `vmenet` members by running
/// `ifconfig` and matching the session gateway — the privileged boundary's
/// *independent* source of truth for which interfaces the IPv6 deny may target.
///
/// The helper never trusts caller-supplied interface names: it derives them here
/// from the (pool-validated) session gateway, so a direct malicious invocation
/// cannot make it load a PF rule on an unrelated host interface (e.g. `en0`).
/// Retries while the bridge/members are still coming up and fails closed
/// otherwise (see [`parse_bridge_for_gateway`] for the per-attempt rules).
pub fn discover_session_bridge_interfaces(
    ifconfig: &Path,
    gateway: Ipv4Addr,
    min_members: usize,
) -> Result<GuestBridgeDiscovery, BridgeDiscoveryError> {
    let mut last: Option<BridgeDiscoveryError> = None;
    for attempt in 0..BRIDGE_DISCOVERY_ATTEMPTS {
        let err: BridgeDiscoveryError = match capture_output(Command::new(ifconfig)) {
            Ok(output) if output.status.success() => {
                match parse_bridge_for_gateway(
                    &String::from_utf8_lossy(&output.stdout),
                    gateway,
                    min_members,
                ) {
                    Ok(discovery) => return Ok(discovery),
                    Err(
                        err @ (GuestBridgeDiscoveryError::NoBridgeForGateway(_)
                        | GuestBridgeDiscoveryError::BridgeMembersNotReady { .. }),
                    ) => err.into(),
                    Err(err) => return Err(err.into()),
                }
            }
            Ok(output) => BridgeDiscoveryError::Failed {
                program: ifconfig.display().to_string(),
                status: output
                    .status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".into()),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            },
            Err(source) => BridgeDiscoveryError::Run {
                program: ifconfig.display().to_string(),
                source,
            },
        };
        last = Some(err);
        if attempt + 1 < BRIDGE_DISCOVERY_ATTEMPTS {
            std::thread::sleep(BRIDGE_DISCOVERY_DELAY);
        }
    }
    Err(last.expect("BRIDGE_DISCOVERY_ATTEMPTS > 0 guarantees at least one attempt"))
}

pub const SESSION_BOOTSTRAP_ANCHOR: &str = r#"anchor "writ/session/*""#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionFirewallInstall {
    network: AgentFirewallNetwork,
    ruleset: PfRuleset,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionFirewallRemoval {
    network: AgentFirewallNetwork,
    anchor: PfAnchorName,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfctlInvocation {
    args: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PfctlError {
    #[error("cannot write temporary PF rules file {path}: {source}")]
    TempRulesFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot run {program} {args}: {source}")]
    Run {
        program: String,
        args: String,
        source: std::io::Error,
    },
    #[error("{program} {args} failed with status {status}: {stderr}")]
    Failed {
        program: String,
        args: String,
        status: String,
        stderr: String,
    },
    #[error("PF ruleset is missing required bootstrap anchor: {0}")]
    MissingBootstrapAnchor(&'static str),
    #[error("PF is not enabled")]
    PfDisabled,
    #[error("PF session anchor {anchor} still contains rules after removal: {rules}")]
    SessionAnchorNotEmpty { anchor: String, rules: String },
}

impl SessionFirewallInstall {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: SessionId,
        pool: AgentNetworkPool,
        ipv4: Ipv4Cidr,
        ipv6: Option<Ipv6Cidr>,
        broker_ports: BrokerPorts,
        broker_port_range: BrokerPortRange,
        broker_ipv4_host: Option<Ipv4Addr>,
        ipv6_deny_interfaces: Vec<PfInterface>,
    ) -> Result<Self, AgentVmConfigError> {
        broker_port_range.require_contains(&broker_ports)?;
        let network = pool.claim_firewall(ipv4, ipv6)?;
        if let Some(broker_host) = broker_ipv4_host {
            // The override whitelists this address on the broker ports before the
            // blanket deny, so it must be inside the session subnet — otherwise a
            // bad inspect result or manual invocation could open a non-broker
            // host. And it must be an IPv4-only scope: a dual-stack scope would
            // still allow the agent to the host IPv6 gateway.
            if !network.ipv4().contains_addr(broker_host) {
                return Err(AgentVmConfigError::BrokerHostOutsideSubnet {
                    broker_host,
                    subnet: network.ipv4(),
                });
            }
            if network.ipv6().is_some() {
                return Err(AgentVmConfigError::BrokerHostWithIpv6FirewallScope);
            }
        }
        // An interface-scoped IPv6 deny is the `Ipv4OnlyNoGuestIpv6` backstop; it
        // blocks *all* IPv6 on the agent VM's bridge. Pairing it with an IPv6
        // firewall scope (dual-stack) would contradict that scope's IPv6 allow, so
        // make the "backstop only when there is no legitimate guest IPv6" invariant
        // a construction error rather than a silently self-cancelling ruleset.
        if !ipv6_deny_interfaces.is_empty() && network.ipv6().is_some() {
            return Err(AgentVmConfigError::Ipv6DenyInterfaceWithIpv6Scope);
        }
        Ok(Self {
            network,
            ruleset: session_firewall_pf_ruleset(
                session_id,
                network,
                &broker_ports,
                broker_ipv4_host,
                &ipv6_deny_interfaces,
            ),
        })
    }

    pub fn network(&self) -> AgentFirewallNetwork {
        self.network
    }

    pub fn ruleset(&self) -> &PfRuleset {
        &self.ruleset
    }

    pub fn rendered_rules(&self) -> String {
        render_pf(&self.ruleset)
    }

    pub fn validate_invocation(&self, rules_file: &Path) -> PfctlInvocation {
        PfctlInvocation::new(vec![
            "-n".to_string(),
            "-f".to_string(),
            rules_file.display().to_string(),
        ])
    }

    pub fn load_invocation(&self, rules_file: &Path) -> PfctlInvocation {
        PfctlInvocation::new(vec![
            "-a".to_string(),
            self.ruleset.anchor().as_str().to_string(),
            "-f".to_string(),
            rules_file.display().to_string(),
        ])
    }
}

impl SessionFirewallRemoval {
    pub fn new(
        session_id: SessionId,
        pool: AgentNetworkPool,
        ipv4: Ipv4Cidr,
        ipv6: Option<Ipv6Cidr>,
    ) -> Result<Self, AgentVmConfigError> {
        let network = pool.claim_firewall(ipv4, ipv6)?;
        Ok(Self {
            network,
            anchor: PfAnchorName::for_session(session_id),
        })
    }

    pub fn network(self) -> AgentFirewallNetwork {
        self.network
    }

    pub fn anchor(&self) -> &PfAnchorName {
        &self.anchor
    }

    pub fn invocations(&self) -> Vec<PfctlInvocation> {
        let mut invocations = vec![PfctlInvocation::new(vec![
            "-k".to_string(),
            self.network.ipv4().to_string(),
            "-k".to_string(),
            "0.0.0.0/0".to_string(),
        ])];
        if let Some(ipv6) = self.network.ipv6() {
            invocations.push(PfctlInvocation::new(vec![
                "-k".to_string(),
                ipv6.to_string(),
                "-k".to_string(),
                "::/0".to_string(),
            ]));
        }
        invocations.push(PfctlInvocation::new([
            "-a",
            self.anchor.as_str(),
            "-F",
            "rules",
        ]));
        invocations
    }
}

impl PfctlInvocation {
    pub fn new(args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Run the command and return its raw output, erroring only if pfctl could
    /// not be executed at all — NOT on a non-zero exit. For status-query reads
    /// (`-sr`) where pfctl may exit non-zero on an empty/absent anchor yet still
    /// print the (empty) ruleset to stdout.
    fn output(&self, pfctl: &Path) -> Result<Output, PfctlError> {
        let mut command = Command::new(pfctl);
        command.args(&self.args);
        capture_output(command).map_err(|source| PfctlError::Run {
            program: pfctl.display().to_string(),
            args: self.args.join(" "),
            source,
        })
    }

    fn run(&self, pfctl: &Path) -> Result<Output, PfctlError> {
        let output = self.output(pfctl)?;
        if output.status.success() {
            return Ok(output);
        }
        Err(PfctlError::Failed {
            program: pfctl.display().to_string(),
            args: self.args.join(" "),
            status: output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".into()),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

/// Wall-clock bound on a single `pfctl`/`ifconfig` invocation. Both are small
/// local system binaries that answer in milliseconds; the bound exists so a
/// wedged one fails visibly instead of parking the privileged helper.
const PF_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on captured stdout. The largest legitimate output is a full `ifconfig`
/// listing or a session anchor's ruleset — kilobytes. 1 MiB is far beyond either
/// and bounds a malfunctioning binary.
const PF_COMMAND_STDOUT_CAP: usize = 1024 * 1024;

/// Run `command` to completion under the shared supervisor and collect its
/// output.
///
/// Goes through [`process_supervisor::run_supervised_blocking`] rather than
/// `process_spawn::output` for a specific reason: `process_spawn::output` drains
/// two piped streams by spawning a reader thread, and that `thread::Builder`
/// spawn is *not* covered by the spawn-refusal retry. Under thread/process
/// exhaustion it fails **after** `pfctl` has already run, so the caller would see
/// "cannot run pfctl" for a command that may have just installed or flushed
/// firewall rules — the worst possible misreport for this subsystem. The
/// supervisor drains both pipes from one non-blocking `poll(2)` loop, so no
/// thread is involved and that window does not exist.
///
/// Supervision also gets `pfctl` a timeout and a process-group kill, which it
/// previously had neither of. `Stdio::null()` on stdin is deliberate: neither
/// binary reads stdin here, and inheriting the parent's would let a misinvocation
/// block on the terminal.
///
/// The spawn retry inside the supervisor never fires in production —
/// `/sbin/ifconfig` and `/sbin/pfctl` are stable system binaries, not files writ
/// writes — but it keeps the pfctl unit tests, which write a fake `pfctl` and
/// immediately exec it alongside other process-spawning tests, robust under load.
fn capture_output(mut command: Command) -> std::io::Result<Output> {
    capture_output_with_timeout(&mut command, PF_COMMAND_TIMEOUT)
}

/// [`capture_output`] with an explicit deadline. Only tests shorten it;
/// production always uses [`PF_COMMAND_TIMEOUT`].
fn capture_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> std::io::Result<Output> {
    command.stdin(std::process::Stdio::null());
    let outcome = process_supervisor::run_supervised_blocking(
        command,
        timeout,
        None,
        StdoutMode::Capture {
            byte_cap: PF_COMMAND_STDOUT_CAP,
        },
        StderrMode::Capture,
    )
    .map_err(|err| std::io::Error::other(err.to_string()))?;
    match outcome {
        SupervisedOutcome::Exited {
            status,
            stdout,
            stderr,
            // pfctl/ifconfig are idempotent status queries and rule loads; a
            // born-dead retry belongs with the caller that needs it (notes_repo),
            // not here.
            ran_nothing: _,
        } => Ok(Output {
            status,
            stdout,
            stderr,
        }),
        // Both of these killed the process group, so the command's effect is
        // indeterminate. Surface an error rather than a synthesised exit status:
        // a caller must not read "did not succeed" as "did not act".
        SupervisedOutcome::TimedOut => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "command did not finish within {timeout:?}; its process group \
                 was killed and its effect is indeterminate"
            ),
        )),
        SupervisedOutcome::StdoutCapExceeded { cap } => Err(std::io::Error::other(format!(
            "command wrote more than the {cap}-byte stdout cap; its process \
             group was killed and its effect is indeterminate"
        ))),
    }
}

pub fn pf_rules_contain_session_bootstrap(rules: &str) -> bool {
    rules.lines().any(|line| {
        let line = line.trim();
        line == SESSION_BOOTSTRAP_ANCHOR || line == r#"anchor "writ/session/*" all"#
    })
}

pub fn pf_info_says_enabled(info: &str) -> bool {
    info.lines().any(|line| {
        let line = line.trim();
        line == "Status: Enabled" || line.starts_with("Status: Enabled ")
    })
}

/// True if a `pfctl -a <anchor> -sr` dump still lists any rule. An emptied
/// anchor prints nothing; a stale one lists its rules. Mirrors the proof's
/// `grep -q '[^[:space:]]'`: any non-whitespace content means rules remain.
pub fn pf_anchor_has_rules(rules: &str) -> bool {
    rules.chars().any(|c| !c.is_whitespace())
}

pub fn ensure_pf_enabled(pfctl: &Path) -> Result<(), PfctlError> {
    let output = PfctlInvocation::new(["-s", "info"]).run(pfctl)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if pf_info_says_enabled(&stdout) {
        Ok(())
    } else {
        Err(PfctlError::PfDisabled)
    }
}

pub fn ensure_session_bootstrap_anchor(pfctl: &Path) -> Result<(), PfctlError> {
    let output = PfctlInvocation::new(["-sr"]).run(pfctl)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if pf_rules_contain_session_bootstrap(&stdout) {
        Ok(())
    } else {
        Err(PfctlError::MissingBootstrapAnchor(SESSION_BOOTSTRAP_ANCHOR))
    }
}

/// Read back the session anchor and fail if it still lists rules. A flush that
/// exits 0 but leaves rules (a wrong anchor name, a pfctl edge case) would
/// otherwise leak this session's rules under the catch-all `writ/session/*`
/// bootstrap anchor — and the guest-side egress gate cannot catch it, since the
/// VM is gone by the time we tear down.
pub fn ensure_session_anchor_empty(pfctl: &Path, anchor: &PfAnchorName) -> Result<(), PfctlError> {
    // `.output()`, not `.run()`: pfctl may exit non-zero on an empty/absent
    // anchor while still printing the (empty) ruleset, so key off stdout
    // content — never the exit code — exactly as the proof does.
    let output = PfctlInvocation::new([
        "-a".to_string(),
        anchor.as_str().to_string(),
        "-sr".to_string(),
    ])
    .output(pfctl)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if pf_anchor_has_rules(&stdout) {
        Err(PfctlError::SessionAnchorNotEmpty {
            anchor: anchor.as_str().to_string(),
            rules: stdout.trim().to_string(),
        })
    } else {
        Ok(())
    }
}

pub fn install_session_firewall(
    pfctl: &Path,
    install: &SessionFirewallInstall,
) -> Result<(), PfctlError> {
    ensure_pf_enabled(pfctl)?;
    ensure_session_bootstrap_anchor(pfctl)?;
    let rendered_rules = install.rendered_rules();
    let rules_file = TempRulesFile::create(&rendered_rules)?;
    install.validate_invocation(rules_file.path()).run(pfctl)?;
    install.load_invocation(rules_file.path()).run(pfctl)?;
    Ok(())
}

pub fn remove_session_firewall(
    pfctl: &Path,
    removal: &SessionFirewallRemoval,
) -> Result<(), PfctlError> {
    let mut first_error = None;
    for invocation in removal.invocations() {
        if let Err(err) = invocation.run(pfctl)
            && first_error.is_none()
        {
            first_error = Some(err);
        }
    }
    if let Some(err) = first_error {
        return Err(err);
    }
    // Every removal invocation reported success; confirm the anchor is actually
    // empty before declaring the session torn down (fail-closed on a stale
    // anchor rather than leaking its rules).
    ensure_session_anchor_empty(pfctl, removal.anchor())
}

struct TempRulesFile {
    path: PathBuf,
}

impl TempRulesFile {
    fn create(contents: &str) -> Result<Self, PfctlError> {
        let path = std::env::temp_dir().join(format!("writ-pf-{}.conf", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|source| PfctlError::TempRulesFile {
                path: path.clone(),
                source,
            })?;
        file.write_all(contents.as_bytes())
            .map_err(|source| PfctlError::TempRulesFile {
                path: path.clone(),
                source,
            })?;
        file.sync_all()
            .map_err(|source| PfctlError::TempRulesFile {
                path: path.clone(),
                source,
            })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRulesFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::core::{BrokerPort, BrokerPorts};

    fn session_id() -> SessionId {
        SessionId::from_uuid(Uuid::from_u128(1))
    }

    fn pool() -> AgentNetworkPool {
        AgentNetworkPool::new(
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
            Ipv6Cidr::new(
                Ipv6Addr::from(0xfd83_b6f2_0e57_f536_0000_0000_0000_0000u128),
                64,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn ipv4() -> Ipv4Cidr {
        Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap()
    }

    fn ipv6() -> Ipv6Cidr {
        Ipv6Cidr::new(
            Ipv6Addr::from(0xfd83_b6f2_0e57_f536_0000_0000_0000_0000u128),
            64,
        )
        .unwrap()
    }

    fn ports() -> BrokerPorts {
        BrokerPorts::new([BrokerPort::new(65000).unwrap()]).unwrap()
    }

    #[test]
    fn install_description_rejects_port_outside_helper_range() {
        let err = SessionFirewallInstall::new(
            session_id(),
            pool(),
            ipv4(),
            Some(ipv6()),
            ports(),
            BrokerPortRange::new(49152, 64999).unwrap(),
            None,
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            AgentVmConfigError::BrokerPortOutsideRange {
                port: 65000,
                min: 49152,
                max: 64999,
            }
        );
    }

    #[test]
    fn install_description_rejects_subnet_outside_pool() {
        let err = SessionFirewallInstall::new(
            session_id(),
            pool(),
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 253, 0), 24).unwrap(),
            Some(ipv6()),
            ports(),
            BrokerPortRange::new(49152, 65535).unwrap(),
            None,
            Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            AgentVmConfigError::AgentIpv4SubnetOutsidePool { .. }
        ));
    }

    #[test]
    fn install_accepts_a_broker_host_inside_an_ipv4_only_subnet() {
        let install = SessionFirewallInstall::new(
            session_id(),
            pool(),
            ipv4(),
            None,
            ports(),
            BrokerPortRange::new(49152, 65535).unwrap(),
            Some(Ipv4Addr::new(192, 168, 252, 5)),
            Vec::new(),
        )
        .unwrap();
        assert!(
            install
                .rendered_rules()
                .contains("to 192.168.252.5 port $broker_ports")
        );
    }

    #[test]
    fn install_rejects_a_broker_host_outside_the_session_subnet() {
        let err = SessionFirewallInstall::new(
            session_id(),
            pool(),
            ipv4(),
            None,
            ports(),
            BrokerPortRange::new(49152, 65535).unwrap(),
            Some(Ipv4Addr::new(10, 0, 0, 5)),
            Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            AgentVmConfigError::BrokerHostOutsideSubnet { .. }
        ));
    }

    #[test]
    fn install_rejects_a_broker_host_with_a_dual_stack_scope() {
        let err = SessionFirewallInstall::new(
            session_id(),
            pool(),
            ipv4(),
            Some(ipv6()),
            ports(),
            BrokerPortRange::new(49152, 65535).unwrap(),
            Some(Ipv4Addr::new(192, 168, 252, 5)),
            Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            AgentVmConfigError::BrokerHostWithIpv6FirewallScope
        ));
    }

    #[test]
    fn install_renders_interface_scoped_ipv6_deny_for_an_ipv4_only_scope() {
        let install = SessionFirewallInstall::new(
            session_id(),
            pool(),
            ipv4(),
            None,
            ports(),
            BrokerPortRange::new(49152, 65535).unwrap(),
            None,
            vec![
                PfInterface::new("bridge100").unwrap(),
                PfInterface::new("vmenet0").unwrap(),
            ],
        )
        .unwrap();
        let rendered = install.rendered_rules();
        assert!(
            rendered.contains(
                "block return in quick on bridge100 inet6 all label \"writ deny agent v6 iface\""
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "block return in quick on vmenet0 inet6 all label \"writ deny agent v6 iface\""
            ),
            "{rendered}"
        );
    }

    #[test]
    fn install_rejects_an_interface_deny_alongside_an_ipv6_scope() {
        let err = SessionFirewallInstall::new(
            session_id(),
            pool(),
            ipv4(),
            Some(ipv6()),
            ports(),
            BrokerPortRange::new(49152, 65535).unwrap(),
            None,
            vec![PfInterface::new("bridge100").unwrap()],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            AgentVmConfigError::Ipv6DenyInterfaceWithIpv6Scope
        ));
    }

    #[test]
    fn bootstrap_check_requires_direct_session_anchor() {
        assert!(pf_rules_contain_session_bootstrap(
            r#"
            anchor "com.apple/*" all
            anchor "writ/session/*" all
            "#
        ));
        assert!(!pf_rules_contain_session_bootstrap(
            r#"
            anchor "com.apple/*" all
            anchor "writ/*" all
            "#
        ));
    }

    #[test]
    fn pf_enabled_check_reads_status_line_exactly() {
        assert!(pf_info_says_enabled(
            r#"
            Status: Enabled for 0 days 00:01:02
            Debug: Urgent
            "#
        ));
        assert!(!pf_info_says_enabled(
            r#"
            Status: Disabled
            Debug: Urgent
            "#
        ));
    }

    #[test]
    fn removal_invocations_are_scoped_to_session_anchor_and_subnets() {
        let removal =
            SessionFirewallRemoval::new(session_id(), pool(), ipv4(), Some(ipv6())).unwrap();
        let invocations = removal
            .invocations()
            .into_iter()
            .map(|i| i.args().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(
            invocations,
            vec![
                vec!["-k", "192.168.252.0/24", "-k", "0.0.0.0/0"]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<_>>(),
                vec!["-k", "fd83:b6f2:e57:f536::/64", "-k", "::/0"]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<_>>(),
                vec![
                    "-a",
                    "writ/session/00000000-0000-0000-0000-000000000001",
                    "-F",
                    "rules",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>(),
            ]
        );
    }

    #[test]
    fn ipv4_only_removal_skips_ipv6_state_kill() {
        let removal = SessionFirewallRemoval::new(session_id(), pool(), ipv4(), None).unwrap();
        let invocations = removal
            .invocations()
            .into_iter()
            .map(|i| i.args().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(
            invocations,
            vec![
                vec!["-k", "192.168.252.0/24", "-k", "0.0.0.0/0"]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<_>>(),
                vec![
                    "-a",
                    "writ/session/00000000-0000-0000-0000-000000000001",
                    "-F",
                    "rules",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>(),
            ]
        );
    }

    #[test]
    fn anchor_has_rules_detects_any_nonwhitespace() {
        // An emptied anchor prints nothing; a stale one lists its rules.
        assert!(!pf_anchor_has_rules(""));
        assert!(!pf_anchor_has_rules("\n  \t\n"));
        assert!(pf_anchor_has_rules("block drop out all\n"));
        assert!(pf_anchor_has_rules("   pass in quick proto tcp   "));
    }

    /// A wedged `pfctl` is killed at the deadline rather than parking the
    /// privileged helper forever.
    ///
    /// `pfctl` invocations previously had no timeout at all. Routing them through
    /// the shared supervisor is what supplies one; this pins that it is actually
    /// wired up, since a supervisor call with a generous timeout looks identical
    /// to an unsupervised one until something hangs.
    #[test]
    fn a_wedged_pf_command_is_killed_at_the_deadline() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("hanging-pfctl");
        // `read` from a fifo-less stdin returns immediately, so sleep instead —
        // located absolutely because the supervisor does not clear the env here,
        // but PATH lookups inside the script are not worth relying on.
        std::fs::write(&tool, "#!/bin/sh\nwhile :; do sleep 1; done\n").unwrap();
        let mut perms = std::fs::metadata(&tool).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tool, perms).unwrap();

        let started = std::time::Instant::now();
        let mut command = Command::new(&tool);
        let err = capture_output_with_timeout(&mut command, Duration::from_millis(300))
            .expect_err("a child that never exits must not be waited on forever");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "expected a timeout, got {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "must return at the deadline, took {:?}",
            started.elapsed()
        );
    }

    /// A fake `pfctl` that prints `sr_output` and exits `sr_exit` for
    /// `-a <anchor> -sr`, and exits 0 for every other invocation — so a flush
    /// can "succeed" yet leave the anchor non-empty, and a status read can exit
    /// non-zero while still reporting an empty ruleset.
    fn write_fake_pfctl_with_sr_exit(dir: &Path, sr_output: &str, sr_exit: i32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("fake-pfctl");
        let script = format!(
            "#!/bin/sh\n\
             if [ \"$1\" = \"-a\" ] && [ \"$3\" = \"-sr\" ]; then printf '%s' '{}'; exit {}; fi\n\
             exit 0\n",
            sr_output.replace('\'', r"'\''"),
            sr_exit,
        );
        std::fs::write(&path, script).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    fn write_fake_pfctl(dir: &Path, sr_output: &str) -> PathBuf {
        write_fake_pfctl_with_sr_exit(dir, sr_output, 0)
    }

    #[test]
    fn remove_session_firewall_verifies_the_anchor_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let pfctl = write_fake_pfctl(dir.path(), "");
        let removal =
            SessionFirewallRemoval::new(session_id(), pool(), ipv4(), Some(ipv6())).unwrap();
        remove_session_firewall(&pfctl, &removal).unwrap();
    }

    #[test]
    fn remove_session_firewall_errors_on_a_stale_anchor() {
        let dir = tempfile::tempdir().unwrap();
        // The flush exits 0, but the anchor still lists a rule.
        let pfctl = write_fake_pfctl(dir.path(), "block drop out all\n");
        let removal =
            SessionFirewallRemoval::new(session_id(), pool(), ipv4(), Some(ipv6())).unwrap();
        let err = remove_session_firewall(&pfctl, &removal).unwrap_err();
        assert!(
            matches!(err, PfctlError::SessionAnchorNotEmpty { .. }),
            "expected SessionAnchorNotEmpty, got {err:?}"
        );
    }

    #[test]
    fn remove_session_firewall_tolerates_nonzero_sr_exit_on_empty_anchor() {
        // pfctl may exit non-zero reading an emptied/absent anchor while still
        // printing an empty ruleset; that must not false-fail a clean teardown.
        let dir = tempfile::tempdir().unwrap();
        let pfctl = write_fake_pfctl_with_sr_exit(dir.path(), "", 1);
        let removal =
            SessionFirewallRemoval::new(session_id(), pool(), ipv4(), Some(ipv6())).unwrap();
        remove_session_firewall(&pfctl, &removal).unwrap();
    }

    fn write_fake_ifconfig(dir: &Path, output: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("fake-ifconfig");
        let script = format!(
            "#!/bin/sh\nprintf '%s' '{}'\n",
            output.replace('\'', r"'\''")
        );
        std::fs::write(&path, script).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[test]
    fn discover_session_bridge_interfaces_reads_ifconfig_and_returns_the_deny_set() {
        // The privileged helper's own discovery: run ifconfig, match the gateway,
        // and return the bridge plus its vmenet member. (The rejection/member rules
        // are exercised without the retry delay by the `parse_bridge_for_gateway`
        // tests; this covers the ifconfig-running wrapper's happy path.)
        let dir = tempfile::tempdir().unwrap();
        let ifconfig = write_fake_ifconfig(
            dir.path(),
            "bridge100: flags=8863<UP> mtu 1500\n\
             \tinet 192.168.252.1 netmask 0xffffff00 broadcast 192.168.252.255\n\
             \tmember: vmenet0 flags=20003<VIRTIO>\n",
        );
        let discovery =
            discover_session_bridge_interfaces(&ifconfig, Ipv4Addr::new(192, 168, 252, 1), 1)
                .unwrap();
        assert_eq!(
            discovery
                .deny_interfaces()
                .iter()
                .map(PfInterface::as_str)
                .collect::<Vec<_>>(),
            vec!["bridge100", "vmenet0"]
        );
    }
}
