//! Pure-data launch plan for the per-session **broker VM** (the
//! `broker_placement = vm` arm; see `docs/vmnet-accept-bug-and-broker-vm-plan.md`).
//!
//! This computes *descriptions* — the `container` invocations and the on-disk
//! session material the broker VM consumes — without performing any IO beyond
//! the explicit material writer. The daemon executor (a later slice) runs these
//! invocations, discovers the broker VM's address, and points the agent VM at
//! it. Keeping the plan pure makes the `container` argv unit-testable against the
//! fake-`container` pattern and ties the material to the slice-3 `writd broker`
//! reader as its oracle.
//!
//! **Topology (per session).** The agent VM and broker VM share one `--internal`
//! network (no NAT ⇒ the agent has no egress by topology). The broker VM is also
//! attached to a second, non-`--internal` network for its own egress (GitHub /
//! Anthropic / nix upstream). Apple `container` has no `--ip` flag, so the broker
//! VM's address on the internal network is *discovered* after start (via
//! `container inspect`) rather than pinned here — the broker port, by contrast,
//! is fixed by us (the broker binds it inside its own VM).
//!
//! **Verified against Apple `container` 1.0.0:** `--network` repeats for
//! dual-homing; bind mounts use `--mount type=virtiofs,source=,target=[,readonly]`;
//! egress is a network created *without* `--internal`. (Host-verify on a real
//! image: the virtiofs mount `type` token and that a no-`--internal` network NATs.)

use std::path::{Path, PathBuf};

use crate::agent_vm_lifecycle::{AgentVmResources, ContainerImage, ProcessInvocation};
use crate::broker_session::BrokerSessionSpec;
use crate::core::{BrokerPort, SessionId};
use crate::vm_http::VmHttpBearerToken;

/// Guest mount target for the per-session material directory (config, session
/// spec, bearer token written by the host; ready file written by the broker).
/// Mounted read-write so the broker can publish its ready file back to the host.
pub const BROKER_VM_SESSION_DIR: &str = "/writ/session";
/// Guest mount target for the host's file secret store (read-only: the broker
/// only reads it, via `FileSecretStore::open`).
pub const BROKER_VM_SECRETS_DIR: &str = "/writ/secrets";
/// Guest mount target for the durable audit directory (read-write).
pub const BROKER_VM_AUDIT_DIR: &str = "/writ/audit";

const SESSION_SPEC_FILE: &str = "session-spec.json";
const BEARER_TOKEN_FILE: &str = "bearer-token";
const CONFIG_FILE: &str = "config.json";
const READY_FILE: &str = "ready";

/// Conventional writable scratch dirs the broker image expects as per-session
/// tmpfs (mirrors the agent VM's set).
const BROKER_VM_TMPFS_MOUNTS: &[&str] = &["/tmp", "/run", "/var/tmp"];

/// The container/network names for one session's broker VM. The *internal*
/// network is owned by the agent-VM plan and shared; only the broker VM and its
/// egress network are named here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerVmNames {
    vm: String,
    egress_network: String,
}

impl BrokerVmNames {
    pub fn for_session(session_id: SessionId) -> Self {
        Self {
            vm: format!("writ-broker-vm-{session_id}"),
            egress_network: format!("writ-broker-egress-{session_id}"),
        }
    }

    pub fn vm(&self) -> &str {
        &self.vm
    }

    pub fn egress_network(&self) -> &str {
        &self.egress_network
    }
}

/// A host→guest bind mount for the broker VM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerVmMount {
    source: PathBuf,
    target: String,
    readonly: bool,
}

impl BrokerVmMount {
    /// Render the `--mount` value (`type=virtiofs,source=…,target=…[,readonly]`).
    fn to_mount_arg(&self) -> String {
        let mut arg = format!(
            "type=virtiofs,source={},target={}",
            self.source.display(),
            self.target
        );
        if self.readonly {
            arg.push_str(",readonly");
        }
        arg
    }
}

/// The pure-data plan for launching one session's broker VM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerVmPlan {
    names: BrokerVmNames,
    image: ContainerImage,
    /// The shared `--internal` network (owned by the agent-VM plan).
    internal_network: String,
    resources: AgentVmResources,
    container_tool: PathBuf,
    mounts: Vec<BrokerVmMount>,
}

impl BrokerVmPlan {
    /// Build the plan from the host-side facts. `staging_dir`, `secret_store_dir`
    /// and `audit_dir` are *host* paths the executor has materialised; they are
    /// mounted at the well-known guest targets above.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: SessionId,
        image: ContainerImage,
        internal_network: impl Into<String>,
        resources: AgentVmResources,
        container_tool: impl Into<PathBuf>,
        staging_dir: impl Into<PathBuf>,
        secret_store_dir: impl Into<PathBuf>,
        audit_dir: impl Into<PathBuf>,
    ) -> Self {
        let mounts = vec![
            BrokerVmMount {
                source: staging_dir.into(),
                target: BROKER_VM_SESSION_DIR.to_string(),
                readonly: false,
            },
            BrokerVmMount {
                source: secret_store_dir.into(),
                target: BROKER_VM_SECRETS_DIR.to_string(),
                readonly: true,
            },
            BrokerVmMount {
                source: audit_dir.into(),
                target: BROKER_VM_AUDIT_DIR.to_string(),
                readonly: false,
            },
        ];
        Self {
            names: BrokerVmNames::for_session(session_id),
            image,
            internal_network: internal_network.into(),
            resources,
            container_tool: container_tool.into(),
            mounts,
        }
    }

    pub fn names(&self) -> &BrokerVmNames {
        &self.names
    }

    /// Guest path of the ready file the broker publishes; the host watches the
    /// host-side end of the session mount for it.
    pub fn guest_ready_file(&self) -> String {
        format!("{BROKER_VM_SESSION_DIR}/{READY_FILE}")
    }

    /// The `writd broker` argument vector, referencing the well-known guest paths.
    fn broker_command(&self) -> Vec<String> {
        vec![
            "writd".to_string(),
            "broker".to_string(),
            "--config".to_string(),
            format!("{BROKER_VM_SESSION_DIR}/{CONFIG_FILE}"),
            "--session-spec".to_string(),
            format!("{BROKER_VM_SESSION_DIR}/{SESSION_SPEC_FILE}"),
            "--bearer-token-file".to_string(),
            format!("{BROKER_VM_SESSION_DIR}/{BEARER_TOKEN_FILE}"),
            "--ready-file".to_string(),
            self.guest_ready_file(),
        ]
    }

    /// `container network create <egress>` — no `--internal`, so the broker VM
    /// gets NAT egress on this interface. No `--subnet`: the address space is
    /// irrelevant (nothing else attaches), so let `container` assign one.
    pub fn create_egress_network_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.container_tool.clone(),
            [
                "network".to_string(),
                "create".to_string(),
                self.names.egress_network.clone(),
            ],
        )
    }

    /// `container run …` for the broker VM: dual-homed (internal + egress),
    /// secrets/audit/session bind-mounted, running `writd broker`.
    pub fn run_invocation(&self) -> ProcessInvocation {
        let mut args = vec![
            "run".to_string(),
            "--name".to_string(),
            self.names.vm.clone(),
            "--network".to_string(),
            self.internal_network.clone(),
            "--network".to_string(),
            self.names.egress_network.clone(),
            "--cpus".to_string(),
            self.resources.cpus().to_string(),
            "--memory".to_string(),
            format!("{}m", self.resources.memory_mib()),
        ];
        for mount in BROKER_VM_TMPFS_MOUNTS {
            args.extend(["--tmpfs".to_string(), (*mount).to_string()]);
        }
        for mount in &self.mounts {
            args.extend(["--mount".to_string(), mount.to_mount_arg()]);
        }
        args.push("-d".to_string());
        args.push(self.image.as_str().to_string());
        args.extend(self.broker_command());
        ProcessInvocation::new(self.container_tool.clone(), args)
    }

    /// Idempotent teardown: force-remove the broker VM, then remove its egress
    /// network. The shared internal network is torn down by the agent-VM stop
    /// plan, so it is intentionally absent here.
    pub fn stop_invocations(&self) -> Vec<ProcessInvocation> {
        vec![
            ProcessInvocation::new(
                self.container_tool.clone(),
                ["rm".to_string(), "-f".to_string(), self.names.vm.clone()],
            ),
            ProcessInvocation::new(
                self.container_tool.clone(),
                [
                    "network".to_string(),
                    "rm".to_string(),
                    self.names.egress_network.clone(),
                ],
            ),
        ]
    }
}

/// The agent VM reaches the broker at this URL. The IP is discovered from the
/// broker VM's internal-network interface after it starts; the port is the fixed
/// port the broker binds inside its own VM.
pub fn broker_url(broker_ipv4: std::net::Ipv4Addr, broker_port: BrokerPort) -> String {
    format!("http://{broker_ipv4}:{}/", broker_port.get())
}

/// Write the per-session material the broker VM reads (the session spec and the
/// bearer token) into `staging_dir`, each `0600`. The directory itself is created
/// `0700` if absent. The broker's config file is written by the executor (it
/// needs the full daemon config); this writes the two pieces the host owns
/// directly. Round-trips through the slice-3 readers (see tests).
pub fn write_session_material(
    staging_dir: &Path,
    spec: &BrokerSessionSpec,
    bearer: &VmHttpBearerToken,
) -> std::io::Result<()> {
    create_private_dir(staging_dir)?;
    write_private_file(
        &staging_dir.join(SESSION_SPEC_FILE),
        spec.to_json().as_bytes(),
    )?;
    write_private_file(
        &staging_dir.join(BEARER_TOKEN_FILE),
        bearer.as_str().as_bytes(),
    )?;
    Ok(())
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    if dir.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir(dir)
}

#[cfg(unix)]
fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker_session::read_bearer_token_file;
    use crate::core::Ipv4Cidr;
    use std::net::Ipv4Addr;

    fn session_id() -> SessionId {
        "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap()
    }

    fn sample_plan() -> BrokerVmPlan {
        BrokerVmPlan::new(
            session_id(),
            ContainerImage::new("writ-broker-vm:latest").unwrap(),
            "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            AgentVmResources::new(2, 1024).unwrap(),
            "/usr/local/bin/container",
            "/var/run/writ/broker/51b8/session",
            "/var/lib/writ/secrets",
            "/var/lib/writ/audit",
        )
    }

    #[test]
    fn names_are_session_scoped_and_distinct_from_agent() {
        let names = BrokerVmNames::for_session(session_id());
        assert_eq!(
            names.vm(),
            "writ-broker-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d"
        );
        assert_eq!(
            names.egress_network(),
            "writ-broker-egress-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d"
        );
    }

    #[test]
    fn egress_network_is_created_without_internal() {
        let args = sample_plan()
            .create_egress_network_invocation()
            .args_lossy();
        assert_eq!(
            args,
            vec![
                "network",
                "create",
                "writ-broker-egress-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            ]
        );
        assert!(!args.iter().any(|a| a == "--internal"));
    }

    #[test]
    fn run_invocation_is_dual_homed_with_mounts_and_broker_command() {
        let plan = sample_plan();
        let inv = plan.run_invocation();
        assert_eq!(inv.program(), Path::new("/usr/local/bin/container"));
        let args = inv.args_lossy();

        // Dual-homed: internal network first, then the broker's egress network.
        let networks: Vec<&String> = args
            .iter()
            .zip(args.iter().skip(1))
            .filter(|(flag, _)| *flag == "--network")
            .map(|(_, name)| name)
            .collect();
        assert_eq!(
            networks,
            vec![
                "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
                "writ-broker-egress-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            ]
        );

        // The three bind mounts, with the secret store read-only.
        assert!(args.contains(&format!(
            "type=virtiofs,source=/var/run/writ/broker/51b8/session,target={BROKER_VM_SESSION_DIR}"
        )));
        assert!(args.contains(&format!(
            "type=virtiofs,source=/var/lib/writ/secrets,target={BROKER_VM_SECRETS_DIR},readonly"
        )));
        assert!(args.contains(&format!(
            "type=virtiofs,source=/var/lib/writ/audit,target={BROKER_VM_AUDIT_DIR}"
        )));

        // Detached, correct image, then the writd broker command pointing at the
        // mounted material.
        let image_at = args
            .iter()
            .position(|a| a == "writ-broker-vm:latest")
            .unwrap();
        assert_eq!(args[image_at - 1], "-d");
        assert_eq!(
            &args[image_at + 1..],
            &[
                "writd".to_string(),
                "broker".to_string(),
                "--config".to_string(),
                format!("{BROKER_VM_SESSION_DIR}/config.json"),
                "--session-spec".to_string(),
                format!("{BROKER_VM_SESSION_DIR}/session-spec.json"),
                "--bearer-token-file".to_string(),
                format!("{BROKER_VM_SESSION_DIR}/bearer-token"),
                "--ready-file".to_string(),
                format!("{BROKER_VM_SESSION_DIR}/ready"),
            ]
        );
    }

    #[test]
    fn stop_invocations_remove_vm_then_egress_network() {
        let stops: Vec<Vec<String>> = sample_plan()
            .stop_invocations()
            .iter()
            .map(ProcessInvocation::args_lossy)
            .collect();
        assert_eq!(
            stops,
            vec![
                vec![
                    "rm".to_string(),
                    "-f".to_string(),
                    "writ-broker-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string(),
                ],
                vec![
                    "network".to_string(),
                    "rm".to_string(),
                    "writ-broker-egress-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string(),
                ],
            ]
        );
    }

    #[test]
    fn broker_url_is_http_ip_port() {
        let url = broker_url(
            Ipv4Addr::new(192, 168, 252, 3),
            BrokerPort::new(18080).unwrap(),
        );
        assert_eq!(url, "http://192.168.252.3:18080/");
    }

    #[test]
    fn written_material_round_trips_through_the_slice3_readers() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("session");
        let spec = BrokerSessionSpec::new(
            session_id(),
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
            Ipv4Addr::UNSPECIFIED,
            18080,
        );
        let bearer = VmHttpBearerToken::generate();
        write_session_material(&staging, &spec, &bearer).unwrap();

        let read_spec = BrokerSessionSpec::read_file(&staging.join("session-spec.json")).unwrap();
        assert_eq!(read_spec, spec);
        let read_bearer = read_bearer_token_file(&staging.join("bearer-token")).unwrap();
        assert_eq!(read_bearer.as_str(), bearer.as_str());
    }

    #[cfg(unix)]
    #[test]
    fn written_material_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("session");
        let spec = BrokerSessionSpec::new(
            session_id(),
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
            Ipv4Addr::UNSPECIFIED,
            18080,
        );
        write_session_material(&staging, &spec, &VmHttpBearerToken::generate()).unwrap();
        let dir_mode = std::fs::metadata(&staging).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "staging dir must be private");
        let spec_mode = std::fs::metadata(staging.join("session-spec.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(spec_mode, 0o600, "session spec must be private");
        let token_mode = std::fs::metadata(staging.join("bearer-token"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(token_mode, 0o600, "bearer token must be private");
    }
}
