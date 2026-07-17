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
        // Changing this argv is a host↔broker contract change: bump
        // `BROKER_PROTOCOL_VERSION` and rebuild the broker image (see
        // `broker_contract_fingerprint_is_pinned`).
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
            ]
        );
    }

    /// CI pin for the host↔broker contract. It combines the broker CLI flag names
    /// the host passes with the on-disk schema of the ready document. If you change
    /// either — add/rename a broker CLI flag, or change `BrokerReadyDoc`'s shape
    /// (the exhaustive struct literal below fails to compile on a field addition) —
    /// this test fails. When it does, update the snapshot **and** bump
    /// `BROKER_PROTOCOL_VERSION` (and rebuild the broker image). The session-spec
    /// schema is guarded independently by its own `version` field and the
    /// `broker_session` tests.
    #[test]
    fn broker_contract_fingerprint_is_pinned() {
        let args = sample_plan().run_invocation().args_lossy();
        let broker_at = args
            .iter()
            .position(|a| a == "broker")
            .expect("broker subcommand present");
        let flags: Vec<&str> = args[broker_at..]
            .iter()
            .filter(|a| a.starts_with("--"))
            .map(String::as_str)
            .collect();

        // A fully-populated ready doc pins the field names and which fields
        // serialize; the exhaustive literal forces an update on a field addition.
        // `protocol_version` is sourced from the real constant (not a literal), so
        // bumping `BROKER_PROTOCOL_VERSION` alone breaks this snapshot too — the
        // token cannot silently drift from the version the broker actually stamps.
        let ready_doc = crate::broker_protocol::BrokerReadyDoc {
            protocol_version: crate::broker_protocol::BROKER_PROTOCOL_VERSION,
            broker_port: 18080,
            writd_build: Some("pinned".to_string()),
        };
        let fingerprint = format!(
            "broker-cli-flags: {}\nready-doc: {}",
            flags.join(" "),
            serde_json::to_string(&ready_doc).unwrap(),
        );

        assert_eq!(
            fingerprint,
            "broker-cli-flags: --config --session-spec --bearer-token-file\n\
             ready-doc: {\"protocol_version\":2,\"broker_port\":18080,\"writd_build\":\"pinned\"}",
            "the host↔broker contract changed. Update this snapshot AND bump \
             BROKER_PROTOCOL_VERSION (and rebuild the broker image)."
        );
    }

    #[test]
    fn logs_invocation_requests_a_bounded_tail() {
        // The crash-log capture must ask the container tool for only the last N
        // lines, so a broker that emitted a huge log before crashing cannot force
        // the host to buffer it all.
        let args = sample_plan().logs_invocation().args_lossy();
        assert_eq!(args[0], "logs");
        assert_eq!(args[1], "-n");
        assert_eq!(args[2], BROKER_LOG_TAIL_LINES.to_string());
        assert!(
            args[3].starts_with("writ-broker-vm-"),
            "last arg must be the broker VM name: {args:?}"
        );
        assert_eq!(args.len(), 4);
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

    #[test]
    fn parse_broker_state_reads_running() {
        assert_eq!(
            parse_broker_state(&inspect_json("")),
            BrokerVmState::Running
        );
    }

    #[test]
    fn parse_broker_state_classifies_stopped_like_states_as_terminal() {
        for terminal in ["stopped", "exited", "failed"] {
            let json = format!(r#"[{{"status":{{"state":"{terminal}"}}}}]"#);
            assert_eq!(
                parse_broker_state(&json),
                BrokerVmState::Terminal(terminal.to_string()),
                "state {terminal:?} should be terminal"
            );
        }
    }

    #[test]
    fn parse_broker_state_is_unknown_for_transient_or_absent_states() {
        // Transient states, an empty container list, missing state, and unparseable
        // JSON must all degrade to Unknown so the readiness wait keeps polling
        // rather than falsely declaring the broker crashed.
        for json in [
            r#"[{"status":{"state":"creating"}}]"#,
            r#"[{"status":{"state":"stopping"}}]"#,
            r#"[{"status":{}}]"#,
            "[]",
            "not json",
        ] {
            assert_eq!(
                parse_broker_state(json),
                BrokerVmState::Unknown,
                "json {json:?} should be Unknown"
            );
        }
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
        assert_eq!(
            runtime.nix_prewarm_cache_dir(),
            Some(Path::new(BROKER_VM_PREWARM_DIR)),
            "the host's pre-warm dir must be re-pointed at its read-only guest mount"
        );
        // Flake provisioning is ENABLED in the broker VM (re-pointed mirror cache):
        // the no-egress agent VM gets its locked flake inputs from the broker.
        assert!(
            runtime.flake_provision().is_some(),
            "flake provisioning must be enabled in the broker VM"
        );
    }

    #[test]
    fn broker_config_enables_flake_provisioning_under_the_guest_work_root() {
        use crate::config::DaemonConfig;
        // The mirror cache (which enables provisioning and is retained by clone)
        // must land under the guest work_root, not a host path.
        let json = broker_config_json(
            &host_config_json(),
            BrokerPort::new(18080).unwrap(),
            BROKER_VM_WORK_ROOT,
            Path::new("/var/lib/writ/audit.db"),
        )
        .unwrap();
        let config: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            config
                .agent_vm
                .unwrap()
                .vm_http
                .flake_mirror_cache_dir
                .as_deref(),
            Some(Path::new("/tmp/writ-broker-work/flake-mirror")),
        );
    }

    #[test]
    fn broker_config_repoints_prewarm_dir_at_the_guest_mount() {
        use crate::config::DaemonConfig;
        // The host set nix_prewarm_cache_dir to a host path; the broker must see it
        // re-pointed at the read-only guest mount so it serves the pre-warmed
        // closure local-first (mirrors flake_mirror_cache_dir).
        let json = broker_config_json(
            &host_config_json(),
            BrokerPort::new(18080).unwrap(),
            BROKER_VM_WORK_ROOT,
            Path::new("/var/lib/writ/audit.db"),
        )
        .unwrap();
        let config: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            config
                .agent_vm
                .unwrap()
                .vm_http
                .nix_prewarm_cache_dir
                .as_deref(),
            Some(Path::new(BROKER_VM_PREWARM_DIR)),
        );
    }

    #[test]
    fn broker_config_drops_prewarm_dir_when_host_has_none() {
        use crate::config::DaemonConfig;
        // A host that configured no pre-warm dir leaves the broker with none, so no
        // pre-warm route is served (and no mount is added) — identical to before.
        let host = host_config_json().replace(
            "\"nix_prewarm_cache_dir\": \"/Users/me/Library/writ/prewarm\",\n",
            "",
        );
        assert!(
            !host.contains("nix_prewarm_cache_dir"),
            "test setup removed the pre-warm dir"
        );
        let json = broker_config_json(
            &host,
            BrokerPort::new(18080).unwrap(),
            BROKER_VM_WORK_ROOT,
            Path::new("/var/lib/writ/audit.db"),
        )
        .unwrap();
        let config: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert!(
            config
                .agent_vm
                .unwrap()
                .vm_http
                .nix_prewarm_cache_dir
                .is_none(),
        );
    }

    #[test]
    fn with_prewarm_cache_mount_adds_a_readonly_mount_when_set() {
        let plan = sample_plan()
            .with_prewarm_cache_mount(Some(PathBuf::from("/Users/me/Library/writ/prewarm")));
        let args = plan.run_invocation().args_lossy();
        assert!(
            args.contains(&format!(
                "type=virtiofs,source=/Users/me/Library/writ/prewarm,target={BROKER_VM_PREWARM_DIR},readonly"
            )),
            "the host pre-warm dir must be bind-mounted read-only: {args:?}"
        );
    }

    #[test]
    fn with_prewarm_cache_mount_none_adds_no_mount() {
        let plan = sample_plan().with_prewarm_cache_mount(None);
        let args = plan.run_invocation().args_lossy();
        assert!(
            !args.iter().any(|a| a.contains(BROKER_VM_PREWARM_DIR)),
            "no pre-warm dir configured means no pre-warm mount: {args:?}"
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
    fn broker_config_pins_token_env_to_the_image_askpass_var() {
        use crate::config::DaemonConfig;
        // A custom host token_env must be rewritten to the var the broker image's
        // fixed askpass reads, else git gets no password in the broker VM.
        let host = host_config_json().replace(
            r#""git_clone_base_url": "https://github.com","#,
            r#""git_clone_base_url": "https://github.com", "token_env": "CUSTOM_TOKEN","#,
        );
        assert!(
            host.contains("CUSTOM_TOKEN"),
            "test setup injected token_env"
        );
        let json = broker_config_json(
            &host,
            BrokerPort::new(18080).unwrap(),
            "/tmp/x",
            Path::new("/var/lib/writ/audit.db"),
        )
        .unwrap();
        let config: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            config.agent_vm.unwrap().vm_http.token_env,
            BROKER_VM_GIT_TOKEN_ENV
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
            GuestAbsPath::new("/writ/session/ready").unwrap(),
            GuestAbsPath::new("/writ/session/broker.log.jsonl").unwrap(),
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
            GuestAbsPath::new("/writ/session/ready").unwrap(),
            GuestAbsPath::new("/writ/session/broker.log.jsonl").unwrap(),
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
            GuestAbsPath::new("/writ/session/ready").unwrap(),
            GuestAbsPath::new("/writ/session/broker.log.jsonl").unwrap(),
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
    fn materialize_mounts_the_host_prewarm_dir_when_configured() {
        // A host config that sets nix_prewarm_cache_dir at an EXISTING dir must
        // produce a plan that bind-mounts *that host path* read-only into the
        // broker VM, so the re-pointed broker config (which names the guest target)
        // has something to read there.
        let prewarm = tempfile::tempdir().unwrap();
        let prewarm_path = prewarm.path().display().to_string();
        let host_config = materialize_host_config_json().replace(
            "\"nix_cache_max_nar_bytes\": 67108864,",
            &format!(
                "\"nix_cache_max_nar_bytes\": 67108864, \"nix_prewarm_cache_dir\": \"{prewarm_path}\","
            ),
        );
        let (_host_dir, host) = host_store_with(&[
            ("claude-pk", "PEM-DATA"),
            ("anthropic-api-key", "sk-abc"),
            ("codex-pk", "other"),
        ]);
        let work = tempfile::tempdir().unwrap();
        let request = materialize_request(work.path());
        let bearer = VmHttpBearerToken::generate();

        let plan = materialize_broker_vm_session(&request, &host_config, &bearer, &host).unwrap();
        let args = plan.run_invocation().args_lossy();
        assert!(
            args.contains(&format!(
                "type=virtiofs,source={prewarm_path},target={BROKER_VM_PREWARM_DIR},readonly"
            )),
            "the configured host pre-warm dir must be mounted read-only: {args:?}"
        );
    }

    #[test]
    fn materialize_skips_the_prewarm_mount_when_the_host_dir_is_absent() {
        // A configured-but-not-yet-created pre-warm dir is a tolerated state (the
        // validator accepts it). It must NOT crash the broker VM launch by mounting
        // a missing virtiofs source: materialize succeeds and adds no mount, so the
        // broker serves an empty pre-warm cache — as host placement does.
        let host_config = materialize_host_config_json().replace(
            "\"nix_cache_max_nar_bytes\": 67108864,",
            "\"nix_cache_max_nar_bytes\": 67108864, \"nix_prewarm_cache_dir\": \"/no/such/prewarm/dir\",",
        );
        let (_host_dir, host) = host_store_with(&[
            ("claude-pk", "PEM-DATA"),
            ("anthropic-api-key", "sk-abc"),
            ("codex-pk", "other"),
        ]);
        let work = tempfile::tempdir().unwrap();
        let request = materialize_request(work.path());
        let bearer = VmHttpBearerToken::generate();

        let plan = materialize_broker_vm_session(&request, &host_config, &bearer, &host).unwrap();
        let args = plan.run_invocation().args_lossy();
        assert!(
            !args.iter().any(|a| a.contains(BROKER_VM_PREWARM_DIR)),
            "an absent configured pre-warm dir must not be mounted: {args:?}"
        );
    }

    #[test]
    fn materialize_adds_no_prewarm_mount_when_host_has_none() {
        // The default materialize host config sets no pre-warm dir, so the plan
        // carries only the three base mounts — no /writ/prewarm.
        let (_host_dir, host) = host_store_with(&[
            ("claude-pk", "PEM-DATA"),
            ("anthropic-api-key", "sk-abc"),
            ("codex-pk", "other"),
        ]);
        let work = tempfile::tempdir().unwrap();
        let request = materialize_request(work.path());
        let bearer = VmHttpBearerToken::generate();

        let plan = materialize_broker_vm_session(
            &request,
            &materialize_host_config_json(),
            &bearer,
            &host,
        )
        .unwrap();
        let args = plan.run_invocation().args_lossy();
        assert!(
            !args.iter().any(|a| a.contains(BROKER_VM_PREWARM_DIR)),
            "no pre-warm dir configured means no pre-warm mount: {args:?}"
        );
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
