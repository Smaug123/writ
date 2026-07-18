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
use crate::broker_session::{BrokerSessionSpec, GuestAbsPath};
use crate::config::DaemonConfig;
use crate::core::{AgentKind, BrokerPort, Ipv4Cidr, SessionId};
use crate::secret::{FileSecretStore, SecretError, SecretKey, SecretStore};
use crate::vm_http::{VmHttpBearerToken, VmHttpOpenAiProxyAuthKind};

/// The `BrokerVmPlan` launch/teardown invocation builders live here; the struct
/// stays in this module. Split out to keep `broker_vm.rs` readable.
mod plan;

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
///
/// Because this whole directory is mounted **read-write** into the broker VM,
/// it must be dedicated to the audit DB (and its WAL/journal) — anything else in
/// it (the host secret store, a config file, an executable) would be reachable
/// read-write here, bypassing the scoped read-only [`BROKER_VM_SECRETS_DIR`]
/// export. The daemon enforces this at broker-VM mount time (and best-effort at
/// startup); see [`crate::config::ensure_audit_dir_is_dedicated`].
pub const BROKER_VM_AUDIT_DIR: &str = "/writ/audit";
/// Guest working root for the broker (on tmpfs inside the VM): clone scratch,
/// bundle staging, the local nix-cache. Ephemeral per VM lifetime.
pub const BROKER_VM_WORK_ROOT: &str = "/tmp/writ-broker-work";
/// Guest mount target for the host's pre-warmed devShell-closure cache
/// (read-only: the broker only reads it). Present only when the host config sets
/// `nix_prewarm_cache_dir`; [`broker_config_json`] re-points the broker's
/// `nix_prewarm_cache_dir` here (and [`BrokerVmPlan::with_prewarm_cache_mount`]
/// bind-mounts the host dir), so the in-VM broker serves the pre-warm archive
/// local-first exactly as the host broker does.
pub const BROKER_VM_PREWARM_DIR: &str = "/writ/prewarm";

// Guest executable paths the broker **image** must provide. The derived broker
// config points the vm_http executables at these, since the host's own
// git/nix/askpass paths (e.g. Homebrew git, a host libexec askpass) do not exist
// in the VM, which mounts only session/secrets/audit.
/// Guest `git` the broker spawns for clone/bundle.
pub const BROKER_VM_GIT_PROGRAM: &str = "/bin/git";
/// Guest `nix` (used by nix-dependent endpoints).
pub const BROKER_VM_NIX_PROGRAM: &str = "/bin/nix";
/// Guest `GIT_ASKPASS` helper that echoes the minted token from
/// [`BROKER_VM_GIT_TOKEN_ENV`]. The broker image must ship this (the host's
/// libexec one is not mounted).
pub const BROKER_VM_ASKPASS_PROGRAM: &str = "/bin/writ-git-askpass";
/// The env var the broker image's askpass reads the minted token from. The
/// derived broker config pins `token_env` to this, since the image's askpass is
/// fixed (a custom host token_env would otherwise break authenticated clones).
pub const BROKER_VM_GIT_TOKEN_ENV: &str = "WRIT_GIT_TOKEN";

const SESSION_SPEC_FILE: &str = "session-spec.json";
const BEARER_TOKEN_FILE: &str = "bearer-token";
const CONFIG_FILE: &str = "config.json";
const READY_FILE: &str = "ready";
/// Filename (within [`BROKER_VM_SESSION_DIR`]) the broker mirrors its JSON
/// tracing to; the host daemon tails the host-side end of the session mount
/// (see the host-side `broker_log_forwarder`). Public so the daemon can build
/// the host-side path without re-deriving the name.
pub const BROKER_VM_LOG_FILE: &str = "broker.log.jsonl";

/// How many trailing log lines the host requests from `container logs` when
/// salvaging a crashed broker's output. Requesting a bounded tail from the
/// container tool (rather than capturing the whole log and truncating after the
/// fact) keeps a chatty crash path from buffering an unbounded amount on the
/// host. A crash reason (clap error, config failure, panic) fits comfortably.
const BROKER_LOG_TAIL_LINES: u32 = 200;

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
/// would be meaningless (or wrong) inside the broker VM, so they are dropped —
/// each then defaults under the guest `work_root` (or stays disabled).
///
/// `flake_mirror_cache_dir` is deliberately *not* here: it is re-pointed at the
/// guest work_root (see [`broker_config_json`]) to enable flake-input
/// provisioning, which the no-egress agent VM depends on. `flake_input_cache_dir`
/// and `flake_materialize_scratch_dir` stay dropped because they auto-default
/// under work_root once provisioning is on. `nix_prewarm_cache_dir` is *also* not
/// here: like the mirror cache it is re-pointed (at [`BROKER_VM_PREWARM_DIR`],
/// the read-only mount [`BrokerVmPlan::with_prewarm_cache_mount`] provides), so
/// the in-VM broker serves the operator's pre-warmed closure exactly as the host
/// broker does. `agent_run_log_root` / `git_push_staging_root` stay disabled: the
/// v1 broker serves no agent-run or git-push routes.
const BROKER_DROPPED_VM_HTTP_KEYS: &[&str] = &[
    "flake_input_cache_dir",
    "flake_materialize_scratch_dir",
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
    // git/nix/askpass paths are not mounted into the VM. (`git_clone_base_url` is
    // not a path, so it carries over unchanged.)
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
    // Pin token_env to the variable the broker image's askpass reads. The image's
    // /bin/writ-git-askpass is fixed, so a custom host token_env would otherwise
    // leave git without a password and break authenticated clones.
    vm_http.insert(
        "token_env".to_string(),
        serde_json::Value::String(BROKER_VM_GIT_TOKEN_ENV.to_string()),
    );
    // Enable flake-input provisioning in the broker VM by pointing the mirror
    // cache (which both backs the /v1/nix/flake/provision endpoint and is retained
    // by the clone handler) at the guest work_root. The no-egress agent VM gets its
    // locked flake inputs from the broker, so this is always on for vm placement —
    // independent of whether the host broker configured it. The input-cache and
    // materialize-scratch dirs auto-default under work_root, so they stay dropped.
    vm_http.insert(
        "flake_mirror_cache_dir".to_string(),
        serde_json::Value::String(format!("{work_root}/flake-mirror")),
    );
    // Re-point the pre-warm cache dir at its read-only guest mount
    // ([`BROKER_VM_PREWARM_DIR`], provided by `with_prewarm_cache_mount`) exactly
    // when the host configured one, so the in-VM broker serves the pre-warmed
    // closure local-first. A present string is rewritten; a `null` or absent value
    // is removed, leaving the broker with no pre-warm archive (identical to
    // before, and consistent with no mount being added). The guest path is absent
    // on the host but `validate_nix_prewarm_cache_dir` tolerates a missing dir, so
    // this config is accepted whether validated on the host or in the VM.
    match vm_http.get("nix_prewarm_cache_dir") {
        Some(value) if value.is_string() => {
            vm_http.insert(
                "nix_prewarm_cache_dir".to_string(),
                serde_json::Value::String(BROKER_VM_PREWARM_DIR.to_string()),
            );
        }
        _ => {
            vm_http.remove("nix_prewarm_cache_dir");
        }
    }
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
/// The broker VM's lifecycle state, as classified from `container inspect`.
///
/// Only definitively-terminal states (the container has stopped and will never
/// become ready) are `Terminal`; everything else — a still-`running` VM, a
/// not-yet-created one, a transient `creating`/`stopping`, or unparseable JSON —
/// is `Running`/`Unknown`, which the readiness wait keeps polling through. Being
/// conservative here means an unrecognised terminal string degrades to the old
/// timeout behaviour rather than a false "the broker crashed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerVmState {
    Running,
    Terminal(String),
    Unknown,
}

/// Classify the broker VM's state from `container inspect` JSON. The state lives
/// at `[0].status.state` (a sibling of the `networks` array
/// [`parse_broker_ipv4_on_network`] reads). Verified against Apple `container`
/// 1.0.0, whose stopped containers report `"state": "stopped"`.
pub fn parse_broker_state(inspect_json: &str) -> BrokerVmState {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(inspect_json) else {
        return BrokerVmState::Unknown;
    };
    let state = value
        .as_array()
        .and_then(|containers| containers.first())
        .and_then(|container| container.get("status"))
        .and_then(|status| status.get("state"))
        .and_then(serde_json::Value::as_str);
    match state {
        Some("running") => BrokerVmState::Running,
        Some(terminal @ ("stopped" | "exited" | "failed")) => {
            BrokerVmState::Terminal(terminal.to_string())
        }
        _ => BrokerVmState::Unknown,
    }
}

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

/// Guest path of the ready file the broker atomically creates once it is
/// serving; the host watches the host-mount side of the session dir for it. Now
/// carried in the session spec rather than on the argv.
fn broker_guest_ready_file() -> GuestAbsPath {
    GuestAbsPath::new(format!("{BROKER_VM_SESSION_DIR}/{READY_FILE}"))
        .expect("broker guest ready-file path is absolute")
}

/// Guest path the broker mirrors its JSON tracing to, for the host daemon to
/// tail (see `broker_log_forwarder`). Also carried in the spec, not the argv.
fn broker_guest_log_file() -> GuestAbsPath {
    GuestAbsPath::new(format!("{BROKER_VM_SESSION_DIR}/{BROKER_VM_LOG_FILE}"))
        .expect("broker guest log-file path is absolute")
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
        broker_guest_ready_file(),
        broker_guest_log_file(),
    );
    write_broker_staging(&request.staging_dir, &spec, bearer, &config_json).map_err(|source| {
        BrokerVmSessionError::Material {
            dir: request.staging_dir.display().to_string(),
            source,
        }
    })?;

    // Mount the host's pre-warm cache dir (if configured) read-only into the
    // broker VM; `broker_config_json` above re-pointed the broker's
    // `nix_prewarm_cache_dir` at the matching guest target. Read from the same
    // typed config `broker_config_json` rewrote.
    //
    // Only mount a dir that actually exists: `validate_nix_prewarm_cache_dir`
    // deliberately tolerates a configured-but-absent path (so an operator can set
    // it before the builder fills it), and virtiofs would fail `container run` on
    // a missing source. Skipping the mount for an absent dir leaves the broker's
    // /writ/prewarm unmounted, so its own validator tolerates the `NotFound` and
    // serves an empty pre-warm cache — exactly what host placement does for the
    // same configured-but-absent state.
    let host_prewarm_dir = config
        .agent_vm
        .as_ref()
        .and_then(|agent_vm| agent_vm.vm_http.nix_prewarm_cache_dir.clone())
        .filter(|dir| dir.is_dir());

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
    )
    .with_prewarm_cache_mount(host_prewarm_dir))
}

#[cfg(test)]
mod tests;
