//! Manual PF helper for Apple-container agent VM sessions.
//!
//! The pure constructors validate that a requested session firewall belongs to
//! broker-owned network and port ranges. The executor is intentionally small:
//! it interprets those validated descriptions as scoped `pfctl` calls.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use uuid::Uuid;

use crate::core::{
    AgentNetwork, AgentNetworkPool, AgentVmConfigError, BrokerPortRange, BrokerPorts, Ipv4Cidr,
    Ipv6Cidr, PfAnchorName, PfRuleset, SessionId, render_pf, session_pf_ruleset,
};

pub const SESSION_BOOTSTRAP_ANCHOR: &str = r#"anchor "writ/session/*""#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionFirewallInstall {
    network: AgentNetwork,
    ruleset: PfRuleset,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionFirewallRemoval {
    network: AgentNetwork,
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
}

impl SessionFirewallInstall {
    pub fn new(
        session_id: SessionId,
        pool: AgentNetworkPool,
        ipv4: Ipv4Cidr,
        ipv6: Ipv6Cidr,
        broker_ports: BrokerPorts,
        broker_port_range: BrokerPortRange,
    ) -> Result<Self, AgentVmConfigError> {
        broker_port_range.require_contains(&broker_ports)?;
        let network = pool.claim(ipv4, ipv6)?;
        Ok(Self {
            network,
            ruleset: session_pf_ruleset(session_id, network, &broker_ports),
        })
    }

    pub fn network(&self) -> AgentNetwork {
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
        ipv6: Ipv6Cidr,
    ) -> Result<Self, AgentVmConfigError> {
        let network = pool.claim(ipv4, ipv6)?;
        Ok(Self {
            network,
            anchor: PfAnchorName::for_session(session_id),
        })
    }

    pub fn network(self) -> AgentNetwork {
        self.network
    }

    pub fn anchor(&self) -> &PfAnchorName {
        &self.anchor
    }

    pub fn invocations(&self) -> Vec<PfctlInvocation> {
        vec![
            PfctlInvocation::new(vec![
                "-k".to_string(),
                self.network.ipv4().to_string(),
                "-k".to_string(),
                "0.0.0.0/0".to_string(),
            ]),
            PfctlInvocation::new(vec![
                "-k".to_string(),
                self.network.ipv6().to_string(),
                "-k".to_string(),
                "::/0".to_string(),
            ]),
            PfctlInvocation::new(["-a", self.anchor.as_str(), "-F", "rules"]),
        ]
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

    fn run(&self, pfctl: &Path) -> Result<Output, PfctlError> {
        let output = Command::new(pfctl)
            .args(&self.args)
            .output()
            .map_err(|source| PfctlError::Run {
                program: pfctl.display().to_string(),
                args: self.args.join(" "),
                source,
            })?;
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
    match first_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
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
            ipv6(),
            ports(),
            BrokerPortRange::new(49152, 64999).unwrap(),
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
            ipv6(),
            ports(),
            BrokerPortRange::new(49152, 65535).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            AgentVmConfigError::AgentIpv4SubnetOutsidePool { .. }
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
        let removal = SessionFirewallRemoval::new(session_id(), pool(), ipv4(), ipv6()).unwrap();
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
}
