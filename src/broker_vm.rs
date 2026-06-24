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

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::agent_vm_lifecycle::{AgentVmResources, ContainerImage, ProcessInvocation};
use crate::broker_session::BrokerSessionSpec;
use crate::config::DaemonConfig;
use crate::core::{AgentKind, BrokerPort, Ipv4Cidr, SessionId};
use crate::secret::{FileSecretStore, SecretError, SecretKey, SecretStore};
use crate::vm_http::{VmHttpBearerToken, VmHttpOpenAiProxyAuthKind};

/// Guest mount target for the per-session material directory (config, session
/// spec, bearer token written by the host; ready file written by the broker).
/// Mounted read-write so the broker can publish its ready file back to the host.
pub const BROKER_VM_SESSION_DIR: &str = "/writ/session";
/// Guest mount target for the host's file secret store (read-only: the broker
/// only reads it, via `FileSecretStore::open`).
pub const BROKER_VM_SECRETS_DIR: &str = "/writ/secrets";
/// Guest mount target for the durable audit directory (read-write). The audit
/// DB *file* keeps the host's basename within this directory (see
/// [`broker_config_json`]), so the broker opens the same SQLite file the host
/// created the session row in.
pub const BROKER_VM_AUDIT_DIR: &str = "/writ/audit";
/// Guest working root for the broker (on tmpfs inside the VM): clone scratch,
/// bundle staging, the local nix-cache. Ephemeral per VM lifetime.
pub const BROKER_VM_WORK_ROOT: &str = "/tmp/writ-broker-work";

// Guest executable paths the broker **image** must provide. The derived broker
// config points the vm_http executables at these, since the host's own
// git/nix/askpass paths (e.g. Homebrew git, a host libexec askpass) do not exist
// in the VM, which mounts only session/secrets/audit.
/// Guest `git` the broker spawns for clone/bundle.
pub const BROKER_VM_GIT_PROGRAM: &str = "/bin/git";
/// Guest `nix` (used by nix-dependent endpoints).
pub const BROKER_VM_NIX_PROGRAM: &str = "/bin/nix";
/// Guest `GIT_ASKPASS` helper that echoes the minted token from the configured
/// `token_env`. The broker image must ship this (the host's libexec one is not
/// mounted).
pub const BROKER_VM_ASKPASS_PROGRAM: &str = "/bin/writ-git-askpass";

const SESSION_SPEC_FILE: &str = "session-spec.json";
const BEARER_TOKEN_FILE: &str = "bearer-token";
const CONFIG_FILE: &str = "config.json";
const READY_FILE: &str = "ready";

/// Conventional writable scratch dirs the broker image expects as per-session
/// tmpfs (mirrors the agent VM's set).
const BROKER_VM_TMPFS_MOUNTS: &[&str] = &["/tmp", "/run", "/var/tmp"];

/// Guest prologue that runs before `writd broker` to keep the broker's default
/// route on the **egress** interface. Apple `container` puts the default route on
/// the first-attached network (so the plan attaches egress first); as
/// defense-in-depth this also drops any default route still pinned to the
/// no-egress `--internal` interface, identified by its on-link subnet (`$1`).
///
/// Deliberately uses **only `ip` and POSIX shell builtins** — no `awk`/`grep`/`sed`,
/// which the production guest image forbids (see `productionForbiddenBins` in
/// flake.nix); `ip` is a guaranteed guest binary. It also avoids `set -e`, so a
/// missing route or no-match can't abort the script before `exec "$@"` — the
/// route repair is best-effort, with egress-first ordering as the real guarantee.
/// (`ip` must likewise be present in the broker image; host-verify the route
/// behaviour on real hardware.)
const BROKER_VM_ROUTE_FIX_SCRIPT: &str = concat!(
    "internal_cidr=\"$1\"\n",
    "shift\n",
    "internal_if=\"\"\n",
    "while read -r subnet kw dev _rest; do\n",
    "  [ \"$kw\" = dev ] || continue\n",
    "  [ \"$subnet\" = \"$internal_cidr\" ] || continue\n",
    "  internal_if=\"$dev\"\n",
    "  break\n",
    "done <<EOF\n",
    "$(ip -o -4 route show scope link 2>/dev/null || true)\n",
    "EOF\n",
    "if [ -n \"$internal_if\" ]; then\n",
    "  while ip route del default dev \"$internal_if\" 2>/dev/null; do :; done\n",
    "fi\n",
    "exec \"$@\"",
);

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
    /// The shared internal subnet, so the route-fix prologue can identify (and
    /// demote) the no-egress interface.
    internal_cidr: Ipv4Cidr,
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
        internal_cidr: Ipv4Cidr,
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
            internal_cidr,
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

    /// `container network create --internal --subnet <cidr> <shared-net>` — the
    /// **shared** internal network the broker and agent both attach to. The
    /// broker arm owns it: it starts first (so it must create the network the
    /// agent later joins) and removes it on teardown. No NAT (`--internal`), so
    /// the agent has no egress by topology.
    pub fn create_internal_network_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.container_tool.clone(),
            [
                "network".to_string(),
                "create".to_string(),
                "--internal".to_string(),
                "--subnet".to_string(),
                self.internal_cidr.to_string(),
                self.internal_network.clone(),
            ],
        )
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

    /// `container run …` for the broker VM: dual-homed (egress + internal),
    /// secrets/audit/session bind-mounted, running `writd broker` behind the
    /// route-fix prologue.
    ///
    /// The egress network is attached **first**: Apple `container` puts the
    /// default route on the first-attached network, so this keeps the broker's
    /// outbound traffic on the NAT interface rather than the no-egress internal
    /// one (the prologue then demotes any stray internal default as backup).
    pub fn run_invocation(&self) -> ProcessInvocation {
        let mut args = vec![
            "run".to_string(),
            "--name".to_string(),
            self.names.vm.clone(),
            "--network".to_string(),
            self.names.egress_network.clone(),
            "--network".to_string(),
            self.internal_network.clone(),
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
        // Wrap the broker command in the route-fix prologue (egress default
        // route), passing the internal subnet so it can identify that interface.
        args.extend([
            "sh".to_string(),
            "-c".to_string(),
            BROKER_VM_ROUTE_FIX_SCRIPT.to_string(),
            "writ-broker-route-fix".to_string(),
            self.internal_cidr.to_string(),
        ]);
        args.extend(self.broker_command());
        ProcessInvocation::new(self.container_tool.clone(), args)
    }

    /// `container inspect <broker vm>` — its JSON carries the broker's address on
    /// the internal network once running (see [`parse_broker_ipv4_on_network`]).
    pub fn inspect_invocation(&self) -> ProcessInvocation {
        ProcessInvocation::new(
            self.container_tool.clone(),
            ["inspect".to_string(), self.names.vm.clone()],
        )
    }

    /// The shared internal network this broker attaches to; used to pick the
    /// right attachment out of `container inspect` output.
    pub fn internal_network(&self) -> &str {
        &self.internal_network
    }

    /// Idempotent teardown: force-remove the broker VM, then remove its egress
    /// network, then the **shared internal network** the broker arm created.
    ///
    /// The internal network is removed last and must run only after the *agent*
    /// VM has already been stopped (the daemon's vm-arm orchestration stops the
    /// agent VM before tearing the broker down) — otherwise the network is still
    /// in use. The agent VM's own stop plan removes the agent VM only.
    pub fn stop_invocations(&self) -> Vec<ProcessInvocation> {
        broker_vm_removal_invocations(&self.container_tool, &self.names, &self.internal_network)
    }
}

/// The destructive teardown commands for one session's broker VM, in order:
/// force-remove the broker VM, remove its egress network, then the shared
/// internal network (only free once the agent VM has also been stopped). No
/// launch parameters are needed, so the daemon's persisted-state cleanup and
/// `managed-stop --dry-run` reconstruct exactly the commands the real stop runs.
/// The stop path wraps each with an absence probe; these are the side-effecting
/// commands, mirroring the agent VM's removal-invocation list.
pub fn broker_vm_removal_invocations(
    container_tool: &Path,
    names: &BrokerVmNames,
    internal_network: &str,
) -> Vec<ProcessInvocation> {
    vec![
        ProcessInvocation::new(
            container_tool.to_path_buf(),
            ["rm".to_string(), "-f".to_string(), names.vm().to_string()],
        ),
        ProcessInvocation::new(
            container_tool.to_path_buf(),
            [
                "network".to_string(),
                "rm".to_string(),
                names.egress_network().to_string(),
            ],
        ),
        ProcessInvocation::new(
            container_tool.to_path_buf(),
            [
                "network".to_string(),
                "rm".to_string(),
                internal_network.to_string(),
            ],
        ),
    ]
}

/// Host directory layout for one session's broker-VM material, all under a single
/// per-session directory (`<root>/<session_id>`). The daemon writes the staging +
/// secret mounts here at start and removes the whole directory at teardown, so a
/// stopped session leaves no derived config, session spec, bearer token, or
/// copied secrets behind. The durable audit directory lives elsewhere and is
/// never part of this.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerVmSessionPaths {
    session_dir: PathBuf,
}

impl BrokerVmSessionPaths {
    /// `root` is the daemon's broker-material root (e.g. `<state_dir>/broker-vm`);
    /// each session's material lives in a `<session_id>` subdirectory of it.
    pub fn new(root: &Path, session_id: SessionId) -> Self {
        Self {
            session_dir: root.join(session_id.to_string()),
        }
    }

    /// The per-session directory holding all of this session's broker material;
    /// removing it is the teardown.
    pub fn session_dir(&self) -> &Path {
        &self.session_dir
    }

    /// Read-write staging mount (derived config, session spec, bearer token in;
    /// ready file out). Consumed by the start arm's materializer.
    pub fn staging_dir(&self) -> PathBuf {
        self.session_dir.join("session")
    }

    /// Read-only secret-store mount (the ephemeral copied-secret export).
    /// Consumed by the start arm's materializer.
    pub fn secrets_dir(&self) -> PathBuf {
        self.session_dir.join("secrets")
    }
}

/// The agent VM reaches the broker at this URL. The IP is discovered from the
/// broker VM's internal-network interface after it starts; the port is the fixed
/// port the broker binds inside its own VM.
pub fn broker_url(broker_ipv4: Ipv4Addr, broker_port: BrokerPort) -> String {
    format!("http://{broker_ipv4}:{}/", broker_port.get())
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerConfigError {
    #[error("host config is not valid JSON: {0}")]
    Json(serde_json::Error),
    #[error("host config top level is not a JSON object")]
    NotObject,
    #[error("host config has no agent_vm.vm_http section to derive the broker vm_http config from")]
    MissingVmHttp,
    #[error("derived broker config could not be serialised: {0}")]
    Serialize(serde_json::Error),
}

/// Optional `vm_http` features whose backing directories live on the *host* and
/// would be meaningless (or wrong) inside the broker VM. The first broker slice
/// serves clone + upstream nix-cache + proxies only, so these are dropped — each
/// then defaults under the guest `work_root` (or stays disabled). Durable/host-
/// mounted variants are a later slice (see the plan doc §9.5/§9.6).
const BROKER_DROPPED_VM_HTTP_KEYS: &[&str] = &[
    "flake_mirror_cache_dir",
    "flake_input_cache_dir",
    "flake_materialize_scratch_dir",
    "nix_prewarm_cache_dir",
    "agent_run_log_root",
    "git_push_staging_root",
];

/// Derive the broker VM's daemon config from the host daemon config: keep
/// github_apps / policy / proxy settings, but rewrite the secret store, audit DB,
/// and `vm_http` working root to the mounted guest locations and pin the broker
/// port. Operates on the raw JSON so every operator setting the broker reads is
/// preserved without depending on the (deserialize-only) typed config.
///
/// `work_root` is a parameter (not the [`BROKER_VM_WORK_ROOT`] constant) so tests
/// can point `vm_http.to_runtime_config()` — the oracle that this config is one
/// the broker accepts — at a temp dir instead of materialising the guest path.
///
/// `host_audit_db` is the host's **effective** audit DB path (after the
/// `--audit-db` CLI override and the default are applied — *not* just the config
/// field), so the broker opens the same SQLite file through the mounted audit
/// directory that the host created the open session row in.
pub fn broker_config_json(
    host_config_json: &str,
    broker_port: BrokerPort,
    work_root: &str,
    host_audit_db: &Path,
) -> Result<String, BrokerConfigError> {
    let mut config: serde_json::Value =
        serde_json::from_str(host_config_json).map_err(BrokerConfigError::Json)?;
    let obj = config.as_object_mut().ok_or(BrokerConfigError::NotObject)?;

    // The broker opens the host's audit DB through the mounted audit directory,
    // keeping the host's filename so it is the *same* SQLite file (a sibling
    // would miss the open session row). The directory is mounted by the executor.
    let audit_basename = host_audit_db
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("audit.db");

    // Secrets and audit move to their mounted guest locations.
    obj.insert(
        "secret_store".to_string(),
        serde_json::json!({ "type": "file", "path": BROKER_VM_SECRETS_DIR }),
    );
    obj.insert(
        "audit_db".to_string(),
        serde_json::Value::String(format!("{BROKER_VM_AUDIT_DIR}/{audit_basename}")),
    );

    let vm_http = obj
        .get_mut("agent_vm")
        .and_then(|agent_vm| agent_vm.get_mut("vm_http"))
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(BrokerConfigError::MissingVmHttp)?;
    vm_http.insert(
        "work_root".to_string(),
        serde_json::Value::String(work_root.to_string()),
    );
    // Pin the broker to exactly the fixed port (min == max), so the session
    // spec's port is the only one in range — the broker entrypoint range-checks
    // the spec against this.
    vm_http.insert(
        "broker_port_min".to_string(),
        serde_json::json!(broker_port.get()),
    );
    vm_http.insert(
        "broker_port_max".to_string(),
        serde_json::json!(broker_port.get()),
    );
    // Point the executables at the broker image's guest paths; the host's own
    // git/nix/askpass paths are not mounted into the VM. (`token_env` and
    // `git_clone_base_url` are not paths, so they carry over unchanged.)
    vm_http.insert(
        "git_program".to_string(),
        serde_json::Value::String(BROKER_VM_GIT_PROGRAM.to_string()),
    );
    vm_http.insert(
        "nix_program".to_string(),
        serde_json::Value::String(BROKER_VM_NIX_PROGRAM.to_string()),
    );
    vm_http.insert(
        "askpass_program".to_string(),
        serde_json::Value::String(BROKER_VM_ASKPASS_PROGRAM.to_string()),
    );
    for key in BROKER_DROPPED_VM_HTTP_KEYS {
        vm_http.remove(*key);
    }

    serde_json::to_string_pretty(&config).map_err(BrokerConfigError::Serialize)
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerSecretExportError {
    #[error("cannot reset the ephemeral broker secret store at {path}: {source}")]
    ResetDir {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot open the ephemeral broker secret store at {path}: {source}")]
    Open {
        path: String,
        #[source]
        source: SecretError,
    },
    #[error("cannot read secret {key:?} from the host secret store: {source}")]
    HostRead {
        key: String,
        #[source]
        source: SecretError,
    },
    #[error("the host secret store has no value for {0:?}, which the broker needs")]
    Missing(String),
    #[error("cannot write secret {key:?} to the ephemeral broker secret store: {source}")]
    Write {
        key: String,
        #[source]
        source: SecretError,
    },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum BrokerSecretSelectionError {
    #[error(
        "the OpenAI proxy uses chatgpt_oauth, which refreshes its token by writing back to the \
         secret store; a broker VM mounts secrets read-only and the export is ephemeral, so the \
         refresh would be lost. Use authorization_bearer, or run broker_placement = host."
    )]
    ChatgptOauthUnsupported,
}

/// The secret-store keys a broker VM needs for a session with this `agent_kind`:
/// that agent's GitHub App private key (the minter selects the app by the
/// session's `agent_kind`, so only that one is reachable) and that agent's proxy
/// auth secret (claude → `claude_proxy`, codex → `openai_proxy`). Scoped to the
/// session so unrelated agents' keys never enter the VM, and a missing *other*
/// agent's key can't block this session.
///
/// The signing key is excluded — the v1 broker has no agent-run/git-push route.
/// `chatgpt_oauth` is rejected: it mutates the secret store at runtime, which the
/// read-only ephemeral export cannot support (see [`BrokerSecretSelectionError`]).
pub fn broker_secret_keys(
    config: &DaemonConfig,
    agent_kind: AgentKind,
) -> Result<Vec<SecretKey>, BrokerSecretSelectionError> {
    let mut keys = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push = |key: &SecretKey, keys: &mut Vec<SecretKey>| {
        if seen.insert(key.as_str().to_string()) {
            keys.push(key.clone());
        }
    };
    // Only the app for this session's agent_kind can ever mint.
    if let Some(app) = config.github_apps.agent_apps().get(&agent_kind) {
        push(&app.private_key_secret, &mut keys);
    }
    // Each agent talks to exactly one upstream, hence one proxy.
    if let Some(agent_vm) = &config.agent_vm {
        let vm_http = &agent_vm.vm_http;
        match agent_kind {
            AgentKind::Claude => {
                if let Some(claude) = &vm_http.claude_proxy {
                    push(&claude.auth_secret, &mut keys);
                }
            }
            AgentKind::Codex => {
                if let Some(openai) = &vm_http.openai_proxy {
                    if openai.auth_kind == VmHttpOpenAiProxyAuthKind::ChatgptOauth {
                        return Err(BrokerSecretSelectionError::ChatgptOauthUnsupported);
                    }
                    push(&openai.auth_secret, &mut keys);
                }
            }
        }
    }
    Ok(keys)
}

/// Inject the broker's secrets into a fresh **file** secret store at `dest_dir`,
/// reading each from the host store (whatever its backend — keychain or file).
/// This is what lets a keyring host serve `broker_placement = vm`: the host reads
/// the keychain once and writes an ephemeral file store to mount into the broker
/// VM (the executor removes it on teardown). A missing key is fatal — the broker
/// would fail later — so it is surfaced here.
///
/// `dest_dir` ends up either a **complete** store or **absent**, never stale or
/// partial: it is cleared first (a retried launch must not keep secrets the
/// broker no longer needs) and removed again if any read/write fails (so a
/// half-populated store is never left to be mounted).
pub fn export_broker_secrets(
    host_store: &dyn SecretStore,
    keys: &[SecretKey],
    dest_dir: &Path,
) -> Result<(), BrokerSecretExportError> {
    if dest_dir.exists() {
        std::fs::remove_dir_all(dest_dir).map_err(|source| BrokerSecretExportError::ResetDir {
            path: dest_dir.display().to_string(),
            source,
        })?;
    }
    let result = write_broker_secret_store(host_store, keys, dest_dir);
    if result.is_err() {
        // Best-effort: don't leave a partial store behind for the executor to
        // mount (it aborts on this error, but a later retry also re-clears).
        let _ = std::fs::remove_dir_all(dest_dir);
    }
    result
}

fn write_broker_secret_store(
    host_store: &dyn SecretStore,
    keys: &[SecretKey],
    dest_dir: &Path,
) -> Result<(), BrokerSecretExportError> {
    let dest = FileSecretStore::create_or_open(dest_dir.to_path_buf()).map_err(|source| {
        BrokerSecretExportError::Open {
            path: dest_dir.display().to_string(),
            source,
        }
    })?;
    for key in keys {
        let value = host_store
            .get(key)
            .map_err(|source| BrokerSecretExportError::HostRead {
                key: key.as_str().to_string(),
                source,
            })?
            .ok_or_else(|| BrokerSecretExportError::Missing(key.as_str().to_string()))?;
        dest.put(key, &value)
            .map_err(|source| BrokerSecretExportError::Write {
                key: key.as_str().to_string(),
                source,
            })?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum BrokerInspectError {
    #[error("container inspect output is not valid JSON: {0}")]
    Json(String),
    #[error("container inspect output is empty or not a JSON array of containers")]
    NoContainer,
    #[error(
        "container inspect output has no running attachment for network {0:?} \
         (is the broker VM running and attached to the internal network?)"
    )]
    NetworkNotFound(String),
    #[error("network {network:?} attachment is missing an ipv4Address")]
    MissingAddress { network: String },
    #[error("network {network:?} ipv4Address {value:?} is not a valid IPv4 address: {message}")]
    InvalidAddress {
        network: String,
        value: String,
        message: String,
    },
}

/// Extract the broker VM's IPv4 address on `network_name` from `container inspect`
/// JSON, so the agent's `WRIT_BROKER_URL` can point at it (Apple `container` has
/// no `--ip`, so the address is only known after the VM starts).
///
/// The address lives at `[0].status.networks[]` where `.network == network_name`,
/// as `.ipv4Address` in `addr/prefix` form. Verified against Apple `container`
/// 1.0.0 (`status.networks` is empty until the container is running, which
/// surfaces here as [`BrokerInspectError::NetworkNotFound`]).
pub fn parse_broker_ipv4_on_network(
    inspect_json: &str,
    network_name: &str,
) -> Result<Ipv4Addr, BrokerInspectError> {
    let value: serde_json::Value =
        serde_json::from_str(inspect_json).map_err(|e| BrokerInspectError::Json(e.to_string()))?;
    let container = value
        .as_array()
        .and_then(|containers| containers.first())
        .ok_or(BrokerInspectError::NoContainer)?;
    let attachment = container
        .get("status")
        .and_then(|status| status.get("networks"))
        .and_then(|networks| networks.as_array())
        .into_iter()
        .flatten()
        .find(|attachment| {
            attachment
                .get("network")
                .and_then(serde_json::Value::as_str)
                == Some(network_name)
        })
        .ok_or_else(|| BrokerInspectError::NetworkNotFound(network_name.to_string()))?;
    let raw = attachment
        .get("ipv4Address")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BrokerInspectError::MissingAddress {
            network: network_name.to_string(),
        })?;
    let addr = raw.split_once('/').map(|(addr, _)| addr).unwrap_or(raw);
    addr.parse::<Ipv4Addr>()
        .map_err(|e| BrokerInspectError::InvalidAddress {
            network: network_name.to_string(),
            value: raw.to_string(),
            message: e.to_string(),
        })
}

/// Write the per-session material the broker VM reads (the session spec and the
/// bearer token) into `staging_dir`, each `0600`, in a `0700` directory. The
/// broker's config file is written by the executor (it needs the full daemon
/// config); this writes the two pieces the host owns directly.
///
/// Safe to call on a **reused** staging directory (a retried launch): any stale
/// `ready` marker is cleared first — otherwise the host, which watches that
/// mounted file to decide the broker is serving, could read a previous run's
/// marker before the new `writd broker` binds — and material files are forced to
/// `0600` even when overwriting a pre-existing inode. Round-trips through the
/// slice-3 readers (see tests).
pub fn write_session_material(
    staging_dir: &Path,
    spec: &BrokerSessionSpec,
    bearer: &VmHttpBearerToken,
) -> std::io::Result<()> {
    create_private_dir(staging_dir)?;
    // Clear a stale readiness marker from a prior attempt before launch.
    match std::fs::remove_file(staging_dir.join(READY_FILE)) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
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
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    if dir.exists() {
        // Enforce 0700 on a reused directory too (DirBuilder::mode only applies
        // when creating), so a looser pre-existing dir can't expose material.
        return std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    std::fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.exists() {
        return Ok(());
    }
    std::fs::create_dir(dir)
}

#[cfg(unix)]
fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // `OpenOptions::mode` only applies when creating a new inode; on a retried
    // launch `path` may already exist with looser perms, so force 0600
    // explicitly. The bearer token must never be group/world-readable.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(contents)
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// The host-side, **non-secret** facts needed to bring up one session's broker
/// VM, gathered as pure data (dependency rejection: the daemon supplies these;
/// this module reads nothing from daemon state). The two secrets — the bearer
/// token and the host secret store — are passed separately to
/// [`materialize_broker_vm_session`] so this descriptor stays safe to `Debug`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerVmSessionRequest {
    /// The session this broker serves.
    pub session_id: SessionId,
    /// Selects which GitHub App key and proxy secret the broker may use — hence
    /// which secrets are exported into its read-only store (see
    /// [`broker_secret_keys`]).
    pub agent_kind: AgentKind,
    /// The broker VM guest image (ships `writd` + git/nix/askpass at the
    /// well-known guest paths).
    pub image: ContainerImage,
    /// The `container` CLI the executor runs.
    pub container_tool: PathBuf,
    /// The shared `--internal` network the broker creates and the agent joins.
    pub internal_network: String,
    /// That network's subnet — also the agent subnet recorded in the session
    /// spec, and what the route-fix prologue uses to demote the no-egress link.
    pub agent_subnet: Ipv4Cidr,
    /// The address the broker binds inside its own VM (the `vm_http` bind addr,
    /// which the daemon constrains to `0.0.0.0`).
    pub bind_addr: Ipv4Addr,
    /// The fixed port the broker binds; the derived broker config pins the
    /// allowed range to exactly this port.
    pub broker_port: BrokerPort,
    /// CPU/memory for the broker VM.
    pub resources: AgentVmResources,
    /// The host's **effective** audit DB path; the broker reopens the same file
    /// through the mounted audit directory (keeping the basename).
    pub host_audit_db: PathBuf,
    /// Host directory mounted read-write at the guest session dir (config,
    /// session spec, bearer token in; ready file out).
    pub staging_dir: PathBuf,
    /// Host directory mounted read-only as the broker's file secret store.
    pub secrets_dir: PathBuf,
    /// Host directory mounted read-write as the durable audit directory.
    pub audit_dir: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerVmSessionError {
    #[error("the host config is not valid JSON: {0}")]
    HostConfigParse(serde_json::Error),
    #[error("selecting the broker's secrets failed: {0}")]
    SecretSelection(#[from] BrokerSecretSelectionError),
    #[error("deriving the broker config failed: {0}")]
    Config(#[from] BrokerConfigError),
    #[error("writing broker session material under {dir} failed: {source}")]
    Material {
        dir: String,
        #[source]
        source: std::io::Error,
    },
    #[error("exporting the broker's secrets failed: {0}")]
    SecretExport(#[from] BrokerSecretExportError),
}

/// Write the broker VM's staging material: the session spec + bearer token (via
/// [`write_session_material`]) and the derived config.json (`0600`). Grouped so
/// [`materialize_broker_vm_session`] treats the staging write as one step (its
/// caller clears the dir on any failure).
fn write_broker_staging(
    staging_dir: &Path,
    spec: &BrokerSessionSpec,
    bearer: &VmHttpBearerToken,
    config_json: &str,
) -> std::io::Result<()> {
    write_session_material(staging_dir, spec, bearer)?;
    write_private_file(&staging_dir.join(CONFIG_FILE), config_json.as_bytes())
}

/// Best-effort removal of a per-session path, whether it is a directory tree or a
/// single file (a non-directory left by a prior attempt). Used to clear the
/// staging + secret dirs on a failed materialization. A missing path is a no-op.
fn remove_path_all(path: &Path) {
    if std::fs::remove_dir_all(path).is_err() {
        let _ = std::fs::remove_file(path);
    }
}

/// Materialise everything one broker VM reads — its derived config, the session
/// spec, the bearer token, and an ephemeral file secret store — into the
/// request's host directories, and return the [`BrokerVmPlan`] that launches it.
/// The caller hands that plan to [`crate::broker_vm_runner::launch_broker_vm`];
/// this runs no `container` commands itself (functional core, imperative shell).
///
/// **All-or-nothing.** On success the staging + secret dirs hold complete
/// material; on *any* failure they are cleared, so an aborted or rejected launch
/// leaves nothing to be mounted — even on a retry over a previous attempt's
/// directories, where an early validation rejection (e.g. a config now using
/// chatgpt_oauth) would otherwise leave stale config/bearer/secrets behind. The
/// durable, host-shared audit dir is never touched. Safe to re-run on the same
/// directories: a successful run resets the secret store, clears any stale
/// `ready` marker, and re-forces material to `0600` (see [`write_session_material`]).
pub fn materialize_broker_vm_session(
    request: &BrokerVmSessionRequest,
    host_config_json: &str,
    bearer: &VmHttpBearerToken,
    host_store: &dyn SecretStore,
) -> Result<BrokerVmPlan, BrokerVmSessionError> {
    let outcome =
        materialize_broker_vm_session_inner(request, host_config_json, bearer, host_store);
    if outcome.is_err() {
        // Any failure leaves nothing to mount: clear the per-session staging +
        // secret dirs (which this function owns) — but never the durable audit dir.
        remove_path_all(&request.secrets_dir);
        remove_path_all(&request.staging_dir);
    }
    outcome
}

fn materialize_broker_vm_session_inner(
    request: &BrokerVmSessionRequest,
    host_config_json: &str,
    bearer: &VmHttpBearerToken,
    host_store: &dyn SecretStore,
) -> Result<BrokerVmPlan, BrokerVmSessionError> {
    // Parse the host config once for secret selection; `broker_config_json`
    // reparses the raw text so every operator setting survives the rewrite
    // untyped. Both reject the same malformed input, so this is fail-closed.
    let config: DaemonConfig =
        serde_json::from_str(host_config_json).map_err(BrokerVmSessionError::HostConfigParse)?;
    // Select (and validate) the secrets before touching disk: an unsupported
    // session fails with nothing materialised.
    let keys = broker_secret_keys(&config, request.agent_kind)?;
    let config_json = broker_config_json(
        host_config_json,
        request.broker_port,
        BROKER_VM_WORK_ROOT,
        &request.host_audit_db,
    )?;

    // Secrets first (self-cleaning on failure), then staging.
    export_broker_secrets(host_store, &keys, &request.secrets_dir)?;
    let spec = BrokerSessionSpec::new(
        request.session_id,
        request.agent_subnet,
        request.bind_addr,
        request.broker_port,
    );
    write_broker_staging(&request.staging_dir, &spec, bearer, &config_json).map_err(|source| {
        BrokerVmSessionError::Material {
            dir: request.staging_dir.display().to_string(),
            source,
        }
    })?;

    Ok(BrokerVmPlan::new(
        request.session_id,
        request.image.clone(),
        request.internal_network.clone(),
        request.agent_subnet,
        request.resources,
        request.container_tool.clone(),
        request.staging_dir.clone(),
        request.secrets_dir.clone(),
        request.audit_dir.clone(),
    ))
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
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
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
    fn internal_network_is_created_internal_with_the_shared_subnet() {
        let args = sample_plan()
            .create_internal_network_invocation()
            .args_lossy();
        assert_eq!(
            args,
            vec![
                "network",
                "create",
                "--internal",
                "--subnet",
                "192.168.252.0/24",
                "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
            ]
        );
    }

    #[test]
    fn run_invocation_is_dual_homed_with_mounts_and_broker_command() {
        let plan = sample_plan();
        let inv = plan.run_invocation();
        assert_eq!(inv.program(), Path::new("/usr/local/bin/container"));
        let args = inv.args_lossy();

        // Dual-homed, egress network first so the default route lands on the NAT
        // interface, then the shared internal network.
        let networks: Vec<&String> = args
            .iter()
            .zip(args.iter().skip(1))
            .filter(|(flag, _)| *flag == "--network")
            .map(|(_, name)| name)
            .collect();
        assert_eq!(
            networks,
            vec![
                "writ-broker-egress-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
                "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
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

        // Detached, correct image, then the route-fix prologue wrapping the
        // writd broker command pointing at the mounted material.
        let image_at = args
            .iter()
            .position(|a| a == "writ-broker-vm:latest")
            .unwrap();
        assert_eq!(args[image_at - 1], "-d");
        assert_eq!(
            &args[image_at + 1..image_at + 6],
            &[
                "sh".to_string(),
                "-c".to_string(),
                BROKER_VM_ROUTE_FIX_SCRIPT.to_string(),
                "writ-broker-route-fix".to_string(),
                "192.168.252.0/24".to_string(),
            ]
        );
        assert_eq!(
            &args[image_at + 6..],
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
    fn route_fix_prologue_targets_the_internal_subnet_and_demotes_it() {
        // The prologue must receive the internal CIDR and drop default routes on
        // the matching interface, so the broker's egress survives dual-homing.
        assert!(BROKER_VM_ROUTE_FIX_SCRIPT.contains("ip route del default dev"));
        // Must use only tools the production guest image allows: no awk/grep/sed
        // (forbidden), and no `set -e` (so a no-match can't abort before exec).
        for forbidden in ["awk", "grep", "sed", "set -e"] {
            assert!(
                !BROKER_VM_ROUTE_FIX_SCRIPT.contains(forbidden),
                "route-fix prologue must not use {forbidden:?}"
            );
        }
        let args = sample_plan().run_invocation().args_lossy();
        let fix_at = args
            .iter()
            .position(|a| a == "writ-broker-route-fix")
            .expect("route-fix prologue is present");
        assert_eq!(args[fix_at + 1], "192.168.252.0/24");
    }

    #[test]
    fn stop_invocations_remove_vm_then_egress_then_shared_internal_network() {
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
                vec![
                    "network".to_string(),
                    "rm".to_string(),
                    "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string(),
                ],
            ]
        );
    }

    #[test]
    fn removal_invocations_from_identity_match_the_plan_in_order() {
        // The daemon cleanup and dry-run reconstruct teardown from session
        // identity; it must be exactly the plan's stop sequence, in order: broker
        // VM, egress network, shared internal network.
        let plan = sample_plan();
        let names = BrokerVmNames::for_session(session_id());
        let from_identity = broker_vm_removal_invocations(
            Path::new("/usr/local/bin/container"),
            &names,
            "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d",
        );
        let args = |invs: &[ProcessInvocation]| -> Vec<Vec<String>> {
            invs.iter().map(ProcessInvocation::args_lossy).collect()
        };
        assert_eq!(args(&from_identity), args(&plan.stop_invocations()));
        assert_eq!(
            args(&from_identity),
            vec![
                vec![
                    "rm".to_string(),
                    "-f".to_string(),
                    format!("writ-broker-vm-{}", session_id())
                ],
                vec![
                    "network".to_string(),
                    "rm".to_string(),
                    format!("writ-broker-egress-{}", session_id())
                ],
                vec![
                    "network".to_string(),
                    "rm".to_string(),
                    "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string()
                ],
            ]
        );
    }

    #[test]
    fn session_paths_are_one_per_session_dir_with_known_mounts() {
        let paths = BrokerVmSessionPaths::new(Path::new("/var/lib/writ/broker-vm"), session_id());
        assert_eq!(
            paths.session_dir(),
            Path::new("/var/lib/writ/broker-vm/51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d")
        );
        // staging + secrets both live under the one per-session dir, so removing
        // session_dir() removes everything (copied secrets included).
        assert!(paths.staging_dir().starts_with(paths.session_dir()));
        assert!(paths.secrets_dir().starts_with(paths.session_dir()));
        assert_ne!(paths.staging_dir(), paths.secrets_dir());
    }

    #[test]
    fn broker_url_is_http_ip_port() {
        let url = broker_url(
            Ipv4Addr::new(192, 168, 252, 3),
            BrokerPort::new(18080).unwrap(),
        );
        assert_eq!(url, "http://192.168.252.3:18080/");
    }

    /// Shape captured verbatim from `container inspect` (Apple container 1.0.0) on
    /// a running VM: an array of one container with `status.networks[]` entries
    /// carrying `network` + `ipv4Address` (`addr/prefix`).
    fn inspect_json(networks: &str) -> String {
        format!(
            r#"[
              {{
                "id": "writ-broker-vm-abc",
                "status": {{
                  "networks": [{networks}],
                  "startedDate": "2026-06-22T17:01:04Z",
                  "state": "running"
                }}
              }}
            ]"#
        )
    }

    #[test]
    fn parses_broker_ipv4_on_the_internal_network() {
        // Two attachments (egress + internal); must pick the internal one.
        let json = inspect_json(
            r#"
            {"network":"writ-broker-egress-abc","ipv4Address":"192.168.64.5/24","ipv4Gateway":"192.168.64.1"},
            {"network":"writ-net","ipv4Address":"192.168.252.3/24","ipv4Gateway":"192.168.252.1","macAddress":"fe:6c:2d:f5:08:69","mtu":1280}
            "#,
        );
        let ip = parse_broker_ipv4_on_network(&json, "writ-net").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 252, 3));
    }

    #[test]
    fn missing_network_is_an_error() {
        let json =
            inspect_json(r#"{"network":"writ-broker-egress-abc","ipv4Address":"192.168.64.5/24"}"#);
        assert_eq!(
            parse_broker_ipv4_on_network(&json, "writ-net"),
            Err(BrokerInspectError::NetworkNotFound("writ-net".to_string()))
        );
    }

    #[test]
    fn stopped_container_has_no_running_attachment() {
        // `status.networks` is empty until the container is running.
        let json = inspect_json("");
        assert_eq!(
            parse_broker_ipv4_on_network(&json, "writ-net"),
            Err(BrokerInspectError::NetworkNotFound("writ-net".to_string()))
        );
    }

    #[test]
    fn missing_or_invalid_address_is_an_error() {
        let no_addr = inspect_json(r#"{"network":"writ-net","ipv4Gateway":"192.168.252.1"}"#);
        assert_eq!(
            parse_broker_ipv4_on_network(&no_addr, "writ-net"),
            Err(BrokerInspectError::MissingAddress {
                network: "writ-net".to_string()
            })
        );
        let bad_addr = inspect_json(r#"{"network":"writ-net","ipv4Address":"not-an-ip/24"}"#);
        assert!(matches!(
            parse_broker_ipv4_on_network(&bad_addr, "writ-net"),
            Err(BrokerInspectError::InvalidAddress { .. })
        ));
    }

    #[test]
    fn non_json_is_an_error() {
        assert!(matches!(
            parse_broker_ipv4_on_network("not json", "writ-net"),
            Err(BrokerInspectError::Json(_))
        ));
        assert_eq!(
            parse_broker_ipv4_on_network("[]", "writ-net"),
            Err(BrokerInspectError::NoContainer)
        );
    }

    /// A host daemon config whose `vm_http` sets host-path-only features (a
    /// prewarm dir, a mirror cache, host staging roots) that must not survive
    /// into the broker VM.
    fn host_config_json() -> String {
        r#"{
            "github_apps": { "claude": {
                "app_id": 1, "installation_id": 2,
                "installation_owner": "o", "private_key_secret": "pk"
            } },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "secret_store": { "type": "keyring", "service": "writ" },
            "audit_db": "/Users/me/Library/writ/audit.db",
            "agent_vm": {
                "lifecycle": {
                    "ipv4_pool": "192.168.0.0/16",
                    "ipv6_pool": "fd83:b6f2:e57::/48",
                    "subnet_index_min": 252,
                    "subnet_index_max": 253,
                    "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                    "ipv6_mode": "ipv4_only_no_guest_ipv6",
                    "image": "writ-agent-vm-guest:latest",
                    "cpus": 1, "memory_mib": 512
                },
                "vm_http": {
                    "bind_addr": "0.0.0.0",
                    "broker_port_min": 18080,
                    "broker_port_max": 18090,
                    "git_program": "/usr/bin/git",
                    "git_clone_base_url": "https://github.com",
                    "askpass_program": "/usr/local/libexec/writ-git-askpass",
                    "work_root": "/Users/me/Library/writ/git-work",
                    "clone_timeout_secs": 30,
                    "max_bundle_bytes": 1048576,
                    "nix_cache_url": "https://cache.nixos.org",
                    "nix_cache_trusted_public_keys": [],
                    "nix_cache_max_metadata_bytes": 1048576,
                    "nix_cache_max_nar_bytes": 67108864,
                    "nix_prewarm_cache_dir": "/Users/me/Library/writ/prewarm",
                    "flake_mirror_cache_dir": "/Users/me/Library/writ/mirror",
                    "agent_run_log_root": "/Users/me/Library/writ/agent-runs",
                    "git_push_staging_root": "/Users/me/Library/writ/git-push"
                }
            }
        }"#
        .to_string()
    }

    #[test]
    fn broker_config_rewrites_paths_pins_port_and_drops_host_features() {
        use crate::config::{DaemonConfig, SecretStoreConfig};

        // A path that does NOT yet exist, so `to_runtime_config` creates it 0700
        // (as it does for the real guest work_root); a pre-existing 0755 dir is
        // correctly rejected as insecure.
        let tmp = tempfile::tempdir().unwrap();
        let work_root = tmp.path().join("broker-work");
        let json = broker_config_json(
            &host_config_json(),
            BrokerPort::new(18080).unwrap(),
            work_root.to_str().unwrap(),
            Path::new("/Users/me/Library/writ/audit.db"),
        )
        .unwrap();

        let config: DaemonConfig = serde_json::from_str(&json).unwrap();
        // Secrets and audit point at the mounted guest locations.
        match config.secret_store {
            SecretStoreConfig::File { ref path } => {
                assert_eq!(path.to_str().unwrap(), BROKER_VM_SECRETS_DIR)
            }
            other => panic!("expected a file secret store, got {other:?}"),
        }
        assert_eq!(
            config.audit_db.as_deref(),
            Some(Path::new("/writ/audit/audit.db"))
        );

        // The vm_http config is one the broker accepts (the strong oracle), the
        // port is pinned, and the host-only features are gone.
        let vm_http = config.agent_vm.expect("agent_vm present").vm_http;
        // Executables point at the broker image's guest paths, not the host's.
        assert_eq!(vm_http.git_program, PathBuf::from(BROKER_VM_GIT_PROGRAM));
        assert_eq!(vm_http.nix_program, PathBuf::from(BROKER_VM_NIX_PROGRAM));
        assert_eq!(
            vm_http.askpass_program,
            PathBuf::from(BROKER_VM_ASKPASS_PROGRAM)
        );
        let runtime = vm_http.to_runtime_config().unwrap();
        let fixed = BrokerPort::new(18080).unwrap();
        assert!(runtime.broker_port_range().contains(fixed));
        assert!(
            !runtime
                .broker_port_range()
                .contains(BrokerPort::new(18090).unwrap())
        );
        assert!(
            runtime.nix_prewarm_cache_dir().is_none(),
            "prewarm must be disabled in the v1 broker"
        );
        assert!(
            runtime.flake_provision().is_none(),
            "flake provisioning must be disabled in the v1 broker"
        );
    }

    #[test]
    fn broker_config_uses_the_effective_audit_db_basename_over_the_config_field() {
        use crate::config::DaemonConfig;
        // The host config field says `audit.db`, but the *effective* audit DB
        // (e.g. selected via `--audit-db`) has a different basename. The broker
        // must follow the effective path — the file the host opened the session
        // in — not the stale config field.
        let json = broker_config_json(
            &host_config_json(),
            BrokerPort::new(18080).unwrap(),
            "/tmp/x",
            Path::new("/var/run/writ/sessions.sqlite"),
        )
        .unwrap();
        let config: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            config.audit_db.as_deref(),
            Some(Path::new("/writ/audit/sessions.sqlite"))
        );
    }

    #[test]
    fn broker_config_requires_a_vm_http_section() {
        let no_vm_http = r#"{
            "github_apps": {},
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "secret_store": { "type": "keyring", "service": "writ" }
        }"#;
        assert!(matches!(
            broker_config_json(
                no_vm_http,
                BrokerPort::new(18080).unwrap(),
                "/tmp/x",
                Path::new("/var/lib/writ/audit.db"),
            ),
            Err(BrokerConfigError::MissingVmHttp)
        ));
    }

    /// Two GitHub apps that *share* a private-key secret (so dedup is exercised)
    /// plus a claude proxy with its own auth secret.
    fn secret_config() -> crate::config::DaemonConfig {
        let json = r#"{
            "github_apps": {
                "claude": { "app_id": 1, "installation_id": 2,
                            "installation_owner": "o", "private_key_secret": "claude-pk" },
                "codex":  { "app_id": 3, "installation_id": 4,
                            "installation_owner": "o", "private_key_secret": "codex-pk" }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "secret_store": { "type": "keyring", "service": "writ" },
            "agent_vm": {
                "lifecycle": {
                    "ipv4_pool": "192.168.0.0/16", "ipv6_pool": "fd83:b6f2:e57::/48",
                    "subnet_index_min": 252, "subnet_index_max": 253,
                    "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                    "ipv6_mode": "ipv4_only_no_guest_ipv6",
                    "image": "writ-agent-vm-guest:latest", "cpus": 1, "memory_mib": 512
                },
                "vm_http": {
                    "bind_addr": "0.0.0.0", "broker_port_min": 18080, "broker_port_max": 18090,
                    "git_clone_base_url": "https://github.com",
                    "askpass_program": "/usr/local/libexec/writ-git-askpass",
                    "work_root": "/tmp/wr", "clone_timeout_secs": 30, "max_bundle_bytes": 1048576,
                    "nix_cache_url": "https://cache.nixos.org",
                    "nix_cache_trusted_public_keys": [],
                    "nix_cache_max_metadata_bytes": 1048576, "nix_cache_max_nar_bytes": 67108864,
                    "claude_proxy": {
                        "upstream_base_url": "https://api.anthropic.com",
                        "auth_secret": "anthropic-api-key", "auth_kind": "x_api_key",
                        "anthropic_version": "2023-06-01", "timeout_secs": 60,
                        "max_request_bytes": 2097152, "max_response_bytes": 8388608
                    }
                }
            }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    fn secret_strs(config: &crate::config::DaemonConfig, agent: AgentKind) -> Vec<String> {
        broker_secret_keys(config, agent)
            .unwrap()
            .iter()
            .map(|k| k.as_str().to_string())
            .collect()
    }

    #[test]
    fn broker_secret_keys_for_claude_selects_only_the_claude_app_and_proxy() {
        // Claude session: its app key + the claude proxy secret; never codex's
        // app key (the broker can't mint with it).
        assert_eq!(
            secret_strs(&secret_config(), AgentKind::Claude),
            vec!["claude-pk", "anthropic-api-key"]
        );
    }

    #[test]
    fn broker_secret_keys_for_codex_selects_only_the_codex_app() {
        // Codex session: its app key only (secret_config has no openai proxy).
        // Crucially excludes claude-pk and the anthropic proxy secret.
        assert_eq!(
            secret_strs(&secret_config(), AgentKind::Codex),
            vec!["codex-pk"]
        );
    }

    #[test]
    fn broker_secret_keys_rejects_chatgpt_oauth_for_vm_brokers() {
        // A codex session whose openai proxy refreshes its token by writing the
        // secret store can't be served by a read-only ephemeral export.
        let json = r#"{
            "github_apps": { "codex": { "app_id": 1, "installation_id": 2,
                "installation_owner": "o", "private_key_secret": "codex-pk" } },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "secret_store": { "type": "keyring", "service": "writ" },
            "agent_vm": {
                "lifecycle": {
                    "ipv4_pool": "192.168.0.0/16", "ipv6_pool": "fd83:b6f2:e57::/48",
                    "subnet_index_min": 252, "subnet_index_max": 253,
                    "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                    "ipv6_mode": "ipv4_only_no_guest_ipv6",
                    "image": "writ-agent-vm-guest:latest", "cpus": 1, "memory_mib": 512
                },
                "vm_http": {
                    "bind_addr": "0.0.0.0", "broker_port_min": 18080, "broker_port_max": 18090,
                    "git_clone_base_url": "https://github.com",
                    "askpass_program": "/usr/local/libexec/writ-git-askpass",
                    "work_root": "/tmp/wr", "clone_timeout_secs": 30, "max_bundle_bytes": 1048576,
                    "nix_cache_url": "https://cache.nixos.org",
                    "nix_cache_trusted_public_keys": [],
                    "nix_cache_max_metadata_bytes": 1048576, "nix_cache_max_nar_bytes": 67108864,
                    "openai_proxy": {
                        "upstream_base_url": "https://chatgpt.com/backend-api/codex",
                        "auth_secret": "chatgpt-bundle", "auth_kind": "chatgpt_oauth",
                        "timeout_secs": 60, "max_request_bytes": 2097152,
                        "max_response_bytes": 8388608
                    }
                }
            }
        }"#;
        let config: crate::config::DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            broker_secret_keys(&config, AgentKind::Codex),
            Err(BrokerSecretSelectionError::ChatgptOauthUnsupported)
        );
    }

    #[test]
    fn export_broker_secrets_copies_only_the_needed_keys() {
        let host_dir = tempfile::tempdir().unwrap();
        let host = FileSecretStore::create_or_open(host_dir.path().join("host")).unwrap();
        host.put(&SecretKey::new("claude-pk").unwrap(), "PEM-DATA")
            .unwrap();
        host.put(&SecretKey::new("anthropic-api-key").unwrap(), "sk-abc")
            .unwrap();
        host.put(&SecretKey::new("codex-pk").unwrap(), "other")
            .unwrap();

        let dest_dir = tempfile::tempdir().unwrap();
        let dest_store = dest_dir.path().join("secrets");
        let keys = broker_secret_keys(&secret_config(), AgentKind::Claude).unwrap();
        export_broker_secrets(&host, &keys, &dest_store).unwrap();

        let injected = FileSecretStore::open(dest_store).unwrap();
        assert_eq!(
            injected.get(&SecretKey::new("claude-pk").unwrap()).unwrap(),
            Some("PEM-DATA".to_string())
        );
        assert_eq!(
            injected
                .get(&SecretKey::new("anthropic-api-key").unwrap())
                .unwrap(),
            Some("sk-abc".to_string())
        );
        // The other agent's app key is never copied into a Claude session's VM.
        assert_eq!(
            injected.get(&SecretKey::new("codex-pk").unwrap()).unwrap(),
            None
        );
    }

    #[test]
    fn export_broker_secrets_fails_on_a_missing_secret_and_leaves_no_store() {
        let host_dir = tempfile::tempdir().unwrap();
        let host = FileSecretStore::create_or_open(host_dir.path().join("host")).unwrap();
        // host is missing `claude-pk` and `anthropic-api-key`.
        let dest_dir = tempfile::tempdir().unwrap();
        let dest = dest_dir.path().join("secrets");
        let keys = broker_secret_keys(&secret_config(), AgentKind::Claude).unwrap();
        assert!(matches!(
            export_broker_secrets(&host, &keys, &dest),
            Err(BrokerSecretExportError::Missing(key)) if key == "claude-pk"
        ));
        // A failed export must not leave a (partial) store to be mounted.
        assert!(!dest.exists(), "partial store must be removed on failure");
    }

    #[test]
    fn export_broker_secrets_clears_a_reused_store_of_stale_secrets() {
        let host_dir = tempfile::tempdir().unwrap();
        let host = FileSecretStore::create_or_open(host_dir.path().join("host")).unwrap();
        host.put(&SecretKey::new("claude-pk").unwrap(), "PEM-DATA")
            .unwrap();
        host.put(&SecretKey::new("anthropic-api-key").unwrap(), "sk-abc")
            .unwrap();

        // A prior attempt left a now-unneeded secret in the export dir.
        let dest_dir = tempfile::tempdir().unwrap();
        let dest = dest_dir.path().join("secrets");
        {
            let stale = FileSecretStore::create_or_open(dest.clone()).unwrap();
            stale
                .put(&SecretKey::new("stale-key").unwrap(), "leftover")
                .unwrap();
        }

        let keys = broker_secret_keys(&secret_config(), AgentKind::Claude).unwrap();
        export_broker_secrets(&host, &keys, &dest).unwrap();

        let injected = FileSecretStore::open(dest).unwrap();
        assert_eq!(
            injected.get(&SecretKey::new("stale-key").unwrap()).unwrap(),
            None,
            "stale secret from a prior attempt must be cleared"
        );
        assert_eq!(
            injected.get(&SecretKey::new("claude-pk").unwrap()).unwrap(),
            Some("PEM-DATA".to_string())
        );
    }

    #[test]
    fn written_material_round_trips_through_the_slice3_readers() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("session");
        let spec = BrokerSessionSpec::new(
            session_id(),
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
            Ipv4Addr::UNSPECIFIED,
            BrokerPort::new(18080).unwrap(),
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
    fn reused_staging_dir_clears_ready_and_reforces_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("session");
        let spec = BrokerSessionSpec::new(
            session_id(),
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
            Ipv4Addr::UNSPECIFIED,
            BrokerPort::new(18080).unwrap(),
        );
        // First launch, then simulate a prior run leaving a stale ready marker
        // and a world-readable bearer token (e.g. a crashed/retried attempt).
        write_session_material(&staging, &spec, &VmHttpBearerToken::generate()).unwrap();
        std::fs::write(staging.join("ready"), "18080\n").unwrap();
        std::fs::set_permissions(
            staging.join("bearer-token"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        // Re-materialising for the retry must clear the stale marker and tighten
        // perms back to 0600.
        write_session_material(&staging, &spec, &VmHttpBearerToken::generate()).unwrap();
        assert!(
            !staging.join("ready").exists(),
            "stale ready marker must be cleared before relaunch"
        );
        let token_mode = std::fs::metadata(staging.join("bearer-token"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(token_mode, 0o600, "overwrite must re-force 0600");
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
            BrokerPort::new(18080).unwrap(),
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

    // ----- materialize_broker_vm_session ------------------------------------

    /// A keyring-backed host config the materializer rewrites for a broker VM: a
    /// claude app + claude proxy (a Claude session needs `claude-pk` +
    /// `anthropic-api-key`) and a codex app (whose key must NOT enter a Claude
    /// VM). Mirrors a real host config so `broker_config_json` is exercised.
    fn materialize_host_config_json() -> String {
        r#"{
            "github_apps": {
                "claude": { "app_id": 1, "installation_id": 2,
                            "installation_owner": "o", "private_key_secret": "claude-pk" },
                "codex":  { "app_id": 3, "installation_id": 4,
                            "installation_owner": "o", "private_key_secret": "codex-pk" }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "secret_store": { "type": "keyring", "service": "writ" },
            "audit_db": "/Users/me/Library/writ/audit.db",
            "agent_vm": {
                "lifecycle": {
                    "ipv4_pool": "192.168.0.0/16", "ipv6_pool": "fd83:b6f2:e57::/48",
                    "subnet_index_min": 252, "subnet_index_max": 253,
                    "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                    "ipv6_mode": "ipv4_only_no_guest_ipv6",
                    "image": "writ-agent-vm-guest:latest", "cpus": 1, "memory_mib": 512
                },
                "vm_http": {
                    "bind_addr": "0.0.0.0", "broker_port_min": 18080, "broker_port_max": 18090,
                    "git_clone_base_url": "https://github.com",
                    "askpass_program": "/usr/local/libexec/writ-git-askpass",
                    "work_root": "/Users/me/Library/writ/git-work",
                    "clone_timeout_secs": 30, "max_bundle_bytes": 1048576,
                    "nix_cache_url": "https://cache.nixos.org",
                    "nix_cache_trusted_public_keys": [],
                    "nix_cache_max_metadata_bytes": 1048576, "nix_cache_max_nar_bytes": 67108864,
                    "claude_proxy": {
                        "upstream_base_url": "https://api.anthropic.com",
                        "auth_secret": "anthropic-api-key", "auth_kind": "x_api_key",
                        "anthropic_version": "2023-06-01", "timeout_secs": 60,
                        "max_request_bytes": 2097152, "max_response_bytes": 8388608
                    }
                }
            }
        }"#
        .to_string()
    }

    /// As above but the codex agent's openai proxy refreshes via `chatgpt_oauth`,
    /// which a read-only ephemeral export cannot serve — the materializer must
    /// reject it before writing anything.
    fn chatgpt_oauth_host_config_json() -> String {
        r#"{
            "github_apps": { "codex": { "app_id": 1, "installation_id": 2,
                "installation_owner": "o", "private_key_secret": "codex-pk" } },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "secret_store": { "type": "keyring", "service": "writ" },
            "agent_vm": {
                "lifecycle": {
                    "ipv4_pool": "192.168.0.0/16", "ipv6_pool": "fd83:b6f2:e57::/48",
                    "subnet_index_min": 252, "subnet_index_max": 253,
                    "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                    "ipv6_mode": "ipv4_only_no_guest_ipv6",
                    "image": "writ-agent-vm-guest:latest", "cpus": 1, "memory_mib": 512
                },
                "vm_http": {
                    "bind_addr": "0.0.0.0", "broker_port_min": 18080, "broker_port_max": 18090,
                    "git_clone_base_url": "https://github.com",
                    "askpass_program": "/usr/local/libexec/writ-git-askpass",
                    "work_root": "/tmp/wr", "clone_timeout_secs": 30, "max_bundle_bytes": 1048576,
                    "nix_cache_url": "https://cache.nixos.org",
                    "nix_cache_trusted_public_keys": [],
                    "nix_cache_max_metadata_bytes": 1048576, "nix_cache_max_nar_bytes": 67108864,
                    "openai_proxy": {
                        "upstream_base_url": "https://chatgpt.com/backend-api/codex",
                        "auth_secret": "chatgpt-bundle", "auth_kind": "chatgpt_oauth",
                        "timeout_secs": 60, "max_request_bytes": 2097152,
                        "max_response_bytes": 8388608
                    }
                }
            }
        }"#
        .to_string()
    }

    fn host_store_with(entries: &[(&str, &str)]) -> (tempfile::TempDir, FileSecretStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::create_or_open(dir.path().join("host")).unwrap();
        for (key, value) in entries {
            store.put(&SecretKey::new(*key).unwrap(), value).unwrap();
        }
        (dir, store)
    }

    fn materialize_request(work: &Path) -> BrokerVmSessionRequest {
        BrokerVmSessionRequest {
            session_id: session_id(),
            agent_kind: AgentKind::Claude,
            image: ContainerImage::new("writ-broker-vm:latest").unwrap(),
            container_tool: PathBuf::from("/usr/local/bin/container"),
            internal_network: "writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".to_string(),
            agent_subnet: Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap(),
            bind_addr: Ipv4Addr::UNSPECIFIED,
            broker_port: BrokerPort::new(18080).unwrap(),
            resources: AgentVmResources::new(2, 1024).unwrap(),
            host_audit_db: PathBuf::from("/Users/me/Library/writ/audit.db"),
            staging_dir: work.join("session"),
            secrets_dir: work.join("secrets"),
            audit_dir: work.join("audit"),
        }
    }

    #[test]
    fn materialize_writes_material_the_broker_readers_accept() {
        let (_host_dir, host) = host_store_with(&[
            ("claude-pk", "PEM-DATA"),
            ("anthropic-api-key", "sk-abc"),
            ("codex-pk", "other"),
        ]);
        let work = tempfile::tempdir().unwrap();
        let request = materialize_request(work.path());
        let bearer = VmHttpBearerToken::generate();
        let token = bearer.as_str().to_string();

        let plan = materialize_broker_vm_session(
            &request,
            &materialize_host_config_json(),
            &bearer,
            &host,
        )
        .unwrap();

        // config.json is exactly what broker_config_json produces (its own
        // correctness is tested separately) and still parses as a broker config.
        let written_config =
            std::fs::read_to_string(request.staging_dir.join("config.json")).unwrap();
        let expected_config = broker_config_json(
            &materialize_host_config_json(),
            BrokerPort::new(18080).unwrap(),
            BROKER_VM_WORK_ROOT,
            Path::new("/Users/me/Library/writ/audit.db"),
        )
        .unwrap();
        assert_eq!(written_config, expected_config);
        let _: crate::config::DaemonConfig = serde_json::from_str(&written_config).unwrap();

        // The session spec round-trips through the broker's own reader (oracle).
        let spec =
            BrokerSessionSpec::read_file(&request.staging_dir.join("session-spec.json")).unwrap();
        assert_eq!(spec.session_id, session_id());
        assert_eq!(
            spec.agent_ipv4_cidr,
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 252, 0), 24).unwrap()
        );
        assert_eq!(spec.bind_addr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(spec.broker_port, 18080);

        // The bearer token round-trips through the broker's reader.
        let read_bearer =
            read_bearer_token_file(&request.staging_dir.join("bearer-token")).unwrap();
        assert_eq!(read_bearer.as_str(), token);

        // The exported store holds exactly the Claude session's keys — never the
        // codex app key.
        let injected = FileSecretStore::open(request.secrets_dir.clone()).unwrap();
        assert_eq!(
            injected.get(&SecretKey::new("claude-pk").unwrap()).unwrap(),
            Some("PEM-DATA".to_string())
        );
        assert_eq!(
            injected
                .get(&SecretKey::new("anthropic-api-key").unwrap())
                .unwrap(),
            Some("sk-abc".to_string())
        );
        assert_eq!(
            injected.get(&SecretKey::new("codex-pk").unwrap()).unwrap(),
            None
        );

        // The returned plan mounts those exact dirs and runs `writd broker`.
        let args = plan.run_invocation().args_lossy();
        assert!(args.contains(&format!(
            "type=virtiofs,source={},target={BROKER_VM_SECRETS_DIR},readonly",
            request.secrets_dir.display()
        )));
        assert!(args.contains(&format!(
            "type=virtiofs,source={},target={BROKER_VM_SESSION_DIR}",
            request.staging_dir.display()
        )));
        assert!(args.windows(2).any(|w| w[0] == "writd" && w[1] == "broker"));
    }

    #[test]
    fn materialize_rejects_chatgpt_oauth_and_writes_nothing() {
        let (_host_dir, host) = host_store_with(&[("codex-pk", "PEM")]);
        let work = tempfile::tempdir().unwrap();
        let mut request = materialize_request(work.path());
        request.agent_kind = AgentKind::Codex;

        let err = materialize_broker_vm_session(
            &request,
            &chatgpt_oauth_host_config_json(),
            &VmHttpBearerToken::generate(),
            &host,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BrokerVmSessionError::SecretSelection(
                BrokerSecretSelectionError::ChatgptOauthUnsupported
            )
        ));
        assert!(
            !request.secrets_dir.exists(),
            "a rejected session must leave no secret store"
        );
        assert!(
            !request.staging_dir.exists(),
            "a rejected session must leave no staging material"
        );
    }

    #[test]
    fn materialize_clears_prior_material_when_a_retry_is_rejected() {
        // A successful materialization, then a retry on the SAME dirs whose config
        // now switches the agent to chatgpt_oauth — rejected at selection, an early
        // return before any write. The prior attempt's material must not survive.
        let (_host_dir, host) = host_store_with(&[
            ("claude-pk", "PEM"),
            ("anthropic-api-key", "sk"),
            ("codex-pk", "p"),
        ]);
        let work = tempfile::tempdir().unwrap();
        let request = materialize_request(work.path());
        materialize_broker_vm_session(
            &request,
            &materialize_host_config_json(),
            &VmHttpBearerToken::generate(),
            &host,
        )
        .unwrap();
        assert!(request.staging_dir.join("config.json").exists());
        assert!(request.secrets_dir.exists());

        let mut retry = materialize_request(work.path());
        retry.agent_kind = AgentKind::Codex;
        let err = materialize_broker_vm_session(
            &retry,
            &chatgpt_oauth_host_config_json(),
            &VmHttpBearerToken::generate(),
            &host,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BrokerVmSessionError::SecretSelection(
                BrokerSecretSelectionError::ChatgptOauthUnsupported
            )
        ));
        // Stale config/bearer/ready marker and copied secrets from the prior run
        // must be gone — a rejected retry leaves nothing to mount.
        assert!(
            !request.staging_dir.exists(),
            "stale staging material from the prior attempt must be cleared"
        );
        assert!(
            !request.secrets_dir.exists(),
            "stale exported secrets from the prior attempt must be cleared"
        );
    }

    #[test]
    fn materialize_fails_on_a_missing_secret_and_writes_nothing() {
        // Host store is missing claude-pk / anthropic-api-key.
        let (_host_dir, host) = host_store_with(&[]);
        let work = tempfile::tempdir().unwrap();
        let request = materialize_request(work.path());

        let err = materialize_broker_vm_session(
            &request,
            &materialize_host_config_json(),
            &VmHttpBearerToken::generate(),
            &host,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BrokerVmSessionError::SecretExport(BrokerSecretExportError::Missing(key))
                if key == "claude-pk"
        ));
        assert!(!request.secrets_dir.exists(), "no partial secret store");
        // Secrets are exported before staging is written, so a missing key leaves
        // no staging material behind either.
        assert!(
            !request.staging_dir.exists(),
            "no staging material when secret export fails first"
        );
    }

    #[cfg(unix)]
    #[test]
    fn materialize_rolls_back_exported_secrets_when_staging_fails() {
        let (_host_dir, host) =
            host_store_with(&[("claude-pk", "PEM"), ("anthropic-api-key", "sk")]);
        let work = tempfile::tempdir().unwrap();
        let request = materialize_request(work.path());
        // Force the staging write to fail *after* secret export: pre-create the
        // staging path as a regular file, so writing material under it fails
        // (ENOTDIR). The export of the secret store still succeeds first.
        std::fs::write(&request.staging_dir, b"not a dir").unwrap();

        let err = materialize_broker_vm_session(
            &request,
            &materialize_host_config_json(),
            &VmHttpBearerToken::generate(),
            &host,
        )
        .unwrap_err();
        assert!(matches!(err, BrokerVmSessionError::Material { .. }));
        // The ephemeral store of copied host secrets must not survive an aborted
        // launch.
        assert!(
            !request.secrets_dir.exists(),
            "exported secrets must be rolled back when staging fails"
        );
    }

    #[cfg(unix)]
    #[test]
    fn materialized_config_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_host_dir, host) =
            host_store_with(&[("claude-pk", "PEM"), ("anthropic-api-key", "sk")]);
        let work = tempfile::tempdir().unwrap();
        let request = materialize_request(work.path());
        materialize_broker_vm_session(
            &request,
            &materialize_host_config_json(),
            &VmHttpBearerToken::generate(),
            &host,
        )
        .unwrap();
        let mode = std::fs::metadata(request.staging_dir.join("config.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "broker config may carry policy and must be private"
        );
    }

    #[test]
    fn materialize_is_safe_to_rerun_and_clears_a_stale_ready_marker() {
        let (_host_dir, host) =
            host_store_with(&[("claude-pk", "PEM"), ("anthropic-api-key", "sk")]);
        let work = tempfile::tempdir().unwrap();
        let request = materialize_request(work.path());
        materialize_broker_vm_session(
            &request,
            &materialize_host_config_json(),
            &VmHttpBearerToken::generate(),
            &host,
        )
        .unwrap();
        // Simulate a prior broker having published readiness on the mount.
        std::fs::write(request.staging_dir.join("ready"), "18080\n").unwrap();

        materialize_broker_vm_session(
            &request,
            &materialize_host_config_json(),
            &VmHttpBearerToken::generate(),
            &host,
        )
        .unwrap();
        assert!(
            !request.staging_dir.join("ready").exists(),
            "a relaunch must clear the stale ready marker before the broker rebinds"
        );
    }
}
