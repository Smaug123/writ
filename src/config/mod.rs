//! Daemon configuration loaded from a JSON file at startup.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use writ_core::byte_size::ByteSize;

use crate::agent_vm_daemon::{
    AgentVmDaemonRuntimeConfig, AgentVmDaemonRuntimeConfigError, AgentVmLifecycleRuntimeConfig,
    AgentVmLifecycleRuntimeConfigError,
};
use crate::agent_vm_lifecycle::{
    AgentVmLifecycleConfigError, AgentVmResources, AgentVmSessionStateStore, AgentVmStateDirError,
    AgentVmToolPaths, BrokerPlacement, ContainerImage, Ipv6IsolationMode,
    default_agent_vm_state_dir,
};
use crate::core::{AgentNetworkPool, AgentVmConfigError, BrokerPortRange, Ipv4Cidr, Ipv6Cidr};
use crate::flake_lock::{FlakeProvisionBounds, FlakeProvisionBoundsError};
use crate::flake_provision_from_mirror::MirrorFlakeProvisionConfig;
use crate::github::GitHubAppRegistryConfig;
use crate::nix_binary_cache::{NixTrustedPublicKeys, NixTrustedPublicKeysError};
use crate::notes_repo::{NotesRepo, NotesRepoError};
use crate::policy::PolicyConfig;
use crate::secret::{SecretKey, SecretStore};
use crate::server::RunAgentSpawnConfig;
use crate::signing::{EnsureOutcome, SigningKeyStoreError, ensure_signing_key};
use crate::vm_git::{VmGitPushBodyLimits, VmGitPushBodyLimitsError};
use crate::vm_git_bundle::{
    DEFAULT_GIT_CLONE_BASE_URL, GitCloneBaseUrl, GitCloneBundlePlanError, GitCredentialBoundary,
    GitSecretEnvVar, GitSecretEnvVarError,
};
use crate::vm_git_mirror_cache::{MirrorCache, MirrorCacheBounds};
use crate::vm_http::{
    DEFAULT_CLAUDE_ANTHROPIC_VERSION, VmHttpClaudeProxyAuthKind, VmHttpClaudeProxyConfig,
    VmHttpClaudeProxyConfigError, VmHttpFlakeProvisionConfig, VmHttpGitCloneConfig,
    VmHttpNixCacheConfig, VmHttpNixCacheConfigError, VmHttpOpenAiProxyAuthKind,
    VmHttpOpenAiProxyConfig, VmHttpOpenAiProxyConfigError, VmHttpRuntimeConfig,
};

pub(crate) mod accumulate;
pub use accumulate::Errors;
use accumulate::{Accumulator, all_recorded};

mod audit_dir;
pub use audit_dir::{
    AuditDirNotDedicated, LegacyAuditDbNotMigrated, ensure_audit_db_entry_is_regular_file,
    ensure_audit_dir_is_dedicated, legacy_audit_db_needs_migration, legacy_default_audit_db_path,
    path_entry_present,
};

/// Top-level daemon configuration. Loaded from a JSON file at startup;
/// runtime-mutable config is not a goal for v1.
///
/// Example config:
/// ```json
/// {
///   "github_apps": {
///     "claude": {
///       "app_id": 12345,
///       "installation_id": 67890,
///       "installation_owner": "smaug123",
///       "private_key_secret": "claude-gh-app-pk"
///     }
///   },
///   "policy": {
///     "default_ttl": 3600,
///     "writable_repos": ["smaug123/writ"]
///   },
///   "run_agent": {
///     "spawn_command": "/usr/local/bin/claude",
///     "spawn_args": ["--headless"]
///   }
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// Agent-keyed GitHub Apps. The session's [`crate::core::AgentKind`] selects which App
    /// mints tokens. Must contain at least one entry; sessions whose
    /// `agent_kind` is absent or has no entry here are refused at request
    /// time.
    pub github_apps: GitHubAppRegistryConfig,
    pub policy: PolicyConfig,
    /// Optional static configuration for agent-VM HTTP sessions. It does not
    /// start a VM by itself; per-session lifecycle code supplies the session
    /// ID and source subnet before binding a listener.
    #[serde(default)]
    pub agent_vm: Option<AgentVmDaemonConfig>,
    /// Where long-lived secrets (notably the GitHub App private key) are
    /// stored. Defaults to the file backend at [`default_secret_store_path`];
    /// set to `{ "type": "keyring" }` to opt in to the OS keychain.
    #[serde(default = "default_secret_store_config")]
    pub secret_store: SecretStoreConfig,
    /// Override the default Unix socket path. If absent, uses
    /// `$XDG_RUNTIME_DIR/writ/writd.sock` (see [`crate::server::default_socket_path`]).
    #[serde(default)]
    pub socket_path: Option<PathBuf>,
    /// Override the default audit DB path. If absent, uses
    /// `$XDG_DATA_HOME/writ/audit/audit.db` (see [`default_audit_db_path`]).
    /// The DB's directory is mounted read-write into the broker VM under
    /// `broker_placement = vm`, so it must hold nothing but the audit DB; see
    /// [`ensure_audit_dir_is_dedicated`].
    #[serde(default)]
    pub audit_db: Option<PathBuf>,
    /// Optional read-only JSON HTTP listener for external UIs (web,
    /// TUI, MCP, `curl`). Absent by default — when absent, no
    /// listener is started and no bearer file is written. See
    /// `docs/plans/2026-05-12-ui-data-api.md`.
    #[serde(default)]
    pub ui_http: Option<UiHttpConfig>,
    /// Configuration for the `RunAgent` dispatch path. Absent means
    /// the daemon refuses `RunAgent` with an explicit "not configured"
    /// reply; present means writd opens (or initialises) the bare
    /// notes repo, ensures the signing key in the secret store, and
    /// wires the spawn config into [`crate::server::BrokerState`]. See
    /// [`RunAgentDaemonConfig`].
    #[serde(default)]
    pub run_agent: Option<RunAgentDaemonConfig>,
    /// Directory under which writd keeps one subdirectory per agent run
    /// holding that run's captured `stdout.log` and `stderr.log`. Defaults to
    /// [`default_agent_run_log_root`].
    ///
    /// **Today's writer is the VM `RunAgent` arm only**: it materialises the
    /// streams the guest uploads into `<root>/<run-id>/`. The host-spawn arm
    /// keeps its child's output in memory and writes no files, so a host-only
    /// daemon creates this root and leaves it empty. That arm records no audit
    /// rows either; giving it the pair is the follow-up this key is
    /// preparation for, and needs on-disk paths to point the rows at.
    ///
    /// It is top-level rather than under `agent_vm` because neither section
    /// can own it: `ClientMessage::StartAgentRun` reaches the VM arm with no
    /// `run_agent` section configured at all, and a daemon that serves only
    /// host-spawn runs has no `agent_vm` section.
    ///
    /// The paths recorded on `agent_run_outcome` rows are absolute, so moving
    /// this root leaves already-recorded runs resolvable where they were
    /// written.
    #[serde(default)]
    pub agent_run_log_root: Option<PathBuf>,
}

/// Configuration for the read-only UI HTTP transport. Distinct from
/// the host Unix socket and the per-VM HTTP listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiHttpConfig {
    /// Bind address. Must be loopback in v1: the bearer file is the
    /// access boundary, and a non-loopback bind would need TLS and a
    /// reworked threat model.
    pub bind: SocketAddr,
    /// Override the path the daemon writes the bearer file to.
    /// Defaults to [`default_ui_http_bearer_path`].
    #[serde(default)]
    pub bearer_path: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum UiHttpConfigError {
    #[error("ui_http.bind must be a loopback address (got {0})")]
    NonLoopbackBind(SocketAddr),
    #[error(
        "ui_http.bind must specify a fixed non-zero port (got {0}); \
         the documented API requires a stable port for clients to connect to"
    )]
    EphemeralPortBind(SocketAddr),
}

impl UiHttpConfig {
    /// Reject bind addresses that are not loopback or that request
    /// an ephemeral port. Called at daemon startup before the
    /// listener is bound so the operator sees the error immediately
    /// rather than discovering a public-facing listener — or a
    /// daemon that picks a different port on every restart — by
    /// accident.
    ///
    /// The two faults are independent — `0.0.0.0:0` is both — so both are
    /// reported rather than only whichever is checked first.
    pub fn validate(&self) -> Result<(), Errors<UiHttpConfigError>> {
        let mut errors = Accumulator::new();
        if !self.bind.ip().is_loopback() {
            let _ = errors.record::<()>(Err(UiHttpConfigError::NonLoopbackBind(self.bind)));
        }
        if self.bind.port() == 0 {
            let _ = errors.record::<()>(Err(UiHttpConfigError::EphemeralPortBind(self.bind)));
        }
        errors.finish()
    }

    pub fn bearer_path_or_default(&self) -> PathBuf {
        self.bearer_path
            .clone()
            .unwrap_or_else(default_ui_http_bearer_path)
    }
}

/// Default location for the UI HTTP bearer file. Lives next to the
/// Unix socket so the same `$XDG_RUNTIME_DIR/writ/` directory holds
/// the runtime-secret material that consumers need to talk to the
/// daemon.
pub fn default_ui_http_bearer_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        PathBuf::from(dir).join("writ/ui-bearer")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
        PathBuf::from(home).join(".local/run/writ/ui-bearer")
    }
}

/// Configuration for the `RunAgent` dispatch path. Absent from
/// [`DaemonConfig`] means the daemon refuses `RunAgent` with an
/// explicit "not configured" reply — useful for agent-VM-only test
/// boots and for staged rollout.
///
/// Present means writd:
/// 1. opens (or initialises) the bare `NotesRepo` at
///    [`Self::notes_repo_path_or_default`] for envelope storage,
/// 2. loads or ensures the writ signing key under
///    [`Self::signing_key_secret_or_default`] in the secret store,
/// 3. uses [`Self::spawn_command`] + [`Self::spawn_args`] as the child
///    binary every `RunAgent` invocation drives.
///
/// **KNOWN GAP — per-`AgentKind` spawn dispatch.** [`Self::spawn_command`]
/// today is a *single* binary for the whole daemon. Slice C's only
/// agent kind is the planner so this suffices, but slice D (review,
/// likely a different agent kind) will need per-kind selection. The
/// follow-up reshapes both this struct and
/// [`crate::server::RunAgentSpawnConfig`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunAgentDaemonConfig {
    /// Absolute path to the bare git repository writ uses to store
    /// signed-run envelope notes. Defaults to
    /// `$XDG_DATA_HOME/writ/repo`. Initialised idempotently at
    /// boot via [`crate::notes_repo::NotesRepo::init_or_open`], so
    /// re-running writd is safe.
    #[serde(default)]
    pub notes_repo_path: Option<PathBuf>,
    /// `SecretStore` key under which the writ signing-key PEM is
    /// stored. Defaults to `writ-signing-key`. On first boot the
    /// daemon generates a fresh Ed25519 keypair and persists it here;
    /// every subsequent boot loads the same key.
    #[serde(default)]
    pub signing_key_secret: Option<SecretKey>,
    /// Absolute path to the child binary writd spawns for every
    /// `RunAgent` call. Required when the section is present.
    pub spawn_command: PathBuf,
    /// Extra args passed to [`Self::spawn_command`] before the prompt
    /// arrives on the child's stdin.
    #[serde(default)]
    pub spawn_args: Vec<String>,
}

/// Default `SecretStore` key under which writd persists its SSH
/// signing key. Exposed so the same string drives the operator-facing
/// CLI (`writ key inspect`, future) and the daemon boot path.
pub const DEFAULT_WRIT_SIGNING_KEY_SECRET: &str = "writ-signing-key";

impl RunAgentDaemonConfig {
    /// Resolve [`Self::notes_repo_path`] against the documented default
    /// so callers don't repeat the fallback logic.
    pub fn notes_repo_path_or_default(&self) -> PathBuf {
        self.notes_repo_path
            .clone()
            .unwrap_or_else(default_notes_repo_path)
    }

    /// Resolve [`Self::signing_key_secret`] against the documented
    /// default ([`DEFAULT_WRIT_SIGNING_KEY_SECRET`]). The default name
    /// is a static string that satisfies [`SecretKey::new`]'s
    /// parse-don't-validate constraint, so the `expect` is correct.
    pub fn signing_key_secret_or_default(&self) -> SecretKey {
        self.signing_key_secret.clone().unwrap_or_else(|| {
            SecretKey::new(DEFAULT_WRIT_SIGNING_KEY_SECRET)
                .expect("DEFAULT_WRIT_SIGNING_KEY_SECRET is a valid SecretKey")
        })
    }

    /// Realise the on-disk side effects this config declares: open (or
    /// initialise) the bare notes repo, load or generate the signing
    /// key in the secret store, and return them together with the
    /// spawn config. The three values feed straight into
    /// [`crate::server::BrokerState`].
    ///
    /// The signing key is loaded via
    /// [`crate::signing::ensure_signing_key`], so first boot generates
    /// and persists a fresh Ed25519 keypair; every subsequent boot
    /// returns the same key. The returned [`EnsureOutcome`] lets the
    /// caller log "generated new key" once at INFO/WARN level.
    pub fn materialize(
        &self,
        store: &dyn SecretStore,
    ) -> Result<RunAgentBootState, RunAgentBootError> {
        let notes_repo_path = self.notes_repo_path_or_default();
        let notes_repo = NotesRepo::init_or_open(&notes_repo_path).map_err(|source| {
            RunAgentBootError::NotesRepo {
                path: notes_repo_path.clone(),
                source,
            }
        })?;
        let signing_key_secret = self.signing_key_secret_or_default();
        let signing_outcome = ensure_signing_key(store, &signing_key_secret).map_err(|source| {
            RunAgentBootError::SigningKey {
                key: signing_key_secret.as_str().to_string(),
                source,
            }
        })?;
        Ok(RunAgentBootState {
            notes_repo,
            signing: signing_outcome,
            spawn: RunAgentSpawnConfig {
                command: self.spawn_command.clone(),
                args: self.spawn_args.clone(),
            },
        })
    }
}

/// The triple writd hands to [`crate::server::BrokerState`] when
/// [`RunAgentDaemonConfig`] is present. Carrying [`EnsureOutcome`]
/// (rather than a bare [`crate::signing::WritSigningKey`]) lets the
/// boot path log first-boot generation distinctly from "loaded
/// existing key".
#[derive(Debug)]
pub struct RunAgentBootState {
    pub notes_repo: NotesRepo,
    pub signing: EnsureOutcome,
    pub spawn: RunAgentSpawnConfig,
}

/// Failure modes of [`RunAgentDaemonConfig::materialize`]. Each
/// variant carries the path or key the operator needs to fix.
#[derive(Debug, thiserror::Error)]
pub enum RunAgentBootError {
    #[error("opening writ notes repo at {path}: {source}", path = path.display())]
    NotesRepo {
        path: PathBuf,
        #[source]
        source: NotesRepoError,
    },
    #[error("ensuring writ signing key under secret {key:?}: {source}")]
    SigningKey {
        key: String,
        #[source]
        source: SigningKeyStoreError,
    },
}

/// Default location for writ's bare notes repo. Sits alongside the
/// audit DB under `$XDG_DATA_HOME/writ/` so a single backup of that
/// directory captures both writ's audit log and its signed-run
/// envelopes.
///
/// **Must agree with `bailiff`'s `default_writ_repo_path` in
/// `src/bin/bailiff.rs`** — bailiff fetches notes from this same
/// location when the operator runs with stock defaults. The two are
/// independent functions because the bailiff binary doesn't link
/// against writd's `config` module, so the convention is duplicated.
/// If you move the path, move it on both sides at once.
pub fn default_notes_repo_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(dir).join("writ/repo")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
        PathBuf::from(home).join(".local/share/writ/repo")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVmDaemonConfig {
    pub lifecycle: AgentVmLifecycleConfig,
    pub vm_http: AgentVmHttpConfig,
}

/// JSON-deserialized lifecycle settings for daemon-managed agent VMs. Convert
/// with [`AgentVmLifecycleConfig::to_runtime_config`] before use; runtime code
/// receives [`AgentVmLifecycleRuntimeConfig`] instead.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVmLifecycleConfig {
    pub ipv4_pool: String,
    pub ipv6_pool: String,
    pub subnet_index_min: u16,
    pub subnet_index_max: u16,
    #[serde(default = "default_container_program")]
    pub container: PathBuf,
    #[serde(default = "default_sudo_program")]
    pub sudo: PathBuf,
    pub pf_helper: PathBuf,
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    pub ipv6_mode: Ipv6IsolationMode,
    /// Where the per-session broker runs; defaults to [`BrokerPlacement::Host`]
    /// (today's in-process host broker). Set to `vm` to run the broker in a
    /// dedicated VM, working around the macOS vmnet `accept()` defect.
    #[serde(default)]
    pub broker_placement: BrokerPlacement,
    pub image: String,
    /// Image for the dedicated broker VM. Required when `broker_placement = vm`
    /// (validated in [`Self::to_runtime_config`]); ignored for the host broker.
    #[serde(default)]
    pub broker_image: Option<String>,
    pub cpus: u16,
    pub memory_mib: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVmHttpConfig {
    #[serde(default = "default_vm_http_bind_addr")]
    pub bind_addr: Ipv4Addr,
    pub broker_port_min: u16,
    pub broker_port_max: u16,
    #[serde(default = "default_vm_http_git_program")]
    pub git_program: PathBuf,
    /// `nix` binary the broker runs to provision a flake's locked inputs
    /// (`nix flake archive`). Only used when flake-input provisioning is
    /// enabled (`flake_mirror_cache_dir` set).
    #[serde(default = "default_vm_http_nix_program")]
    pub nix_program: PathBuf,
    #[serde(default = "default_git_clone_base_url")]
    pub git_clone_base_url: String,
    pub askpass_program: PathBuf,
    #[serde(default = "default_vm_git_token_env")]
    pub token_env: String,
    #[serde(default = "default_vm_http_work_root")]
    pub work_root: PathBuf,
    #[serde(default = "default_clone_timeout_secs")]
    pub clone_timeout_secs: u64,
    #[serde(default = "default_max_bundle_bytes")]
    pub max_bundle_bytes: ByteSize,
    #[serde(default = "default_nix_cache_url")]
    pub nix_cache_url: String,
    #[serde(default = "default_nix_cache_trusted_public_keys")]
    pub nix_cache_trusted_public_keys: Vec<String>,
    #[serde(default = "default_nix_cache_max_metadata_bytes")]
    pub nix_cache_max_metadata_bytes: ByteSize,
    #[serde(default = "default_nix_cache_max_nar_bytes")]
    pub nix_cache_max_nar_bytes: ByteSize,
    /// Directory of the broker-local, content-addressed flake-input cache the
    /// nix-cache endpoint serves local-first (before proxying upstream).
    /// `None` defaults to `<work_root>/flake-input-cache`. Flake-input
    /// provisioning (a later bootstrap stage) populates it; an empty directory
    /// leaves nix-cache behaviour identical to upstream-only.
    #[serde(default)]
    pub flake_input_cache_dir: Option<PathBuf>,
    /// Directory of a durable, operator-managed pre-warmed devShell-closure
    /// cache, served local-first **ahead of** `flake_input_cache_dir`. `None`
    /// (the default) means no pre-warm dir — behaviour is identical to before.
    ///
    /// Unlike `flake_input_cache_dir`, the broker only *reads* this dir; an
    /// egress builder populates it out of band (`nix copy --to file://…
    /// ?secret-key=…`), so it is never created or written by the broker, and a
    /// missing/empty dir simply serves nothing. Its signed, input-addressed
    /// paths are admitted iff their key is in `nix_cache_trusted_public_keys`
    /// (the same list the guest verifies against) — there is no separate
    /// pre-warm key.
    #[serde(default)]
    pub nix_prewarm_cache_dir: Option<PathBuf>,
    /// Directory of the `(repo, rev)`-keyed cache that retains each clone's bare
    /// mirror for later flake-input provisioning. `None` (the default) keeps the
    /// historical behaviour — the mirror is discarded once its bundle is read.
    /// The cache holds bare clones of possibly-private repositories, so the
    /// directory is created owner-only (0700) on first use.
    ///
    /// Setting this also enables the `/v1/nix/flake/provision` endpoint, which
    /// re-derives a checkout from a retained mirror; with the cache absent there
    /// is nothing to provision from, so the endpoint stays disabled.
    #[serde(default)]
    pub flake_mirror_cache_dir: Option<PathBuf>,
    /// Eviction ceiling on the number of retained mirrors. After each clone an
    /// opportunistic pass evicts oldest-first (skipping mirrors an in-flight
    /// provision has pinned) until the cache is under both this and
    /// `flake_mirror_cache_max_bytes`. Only meaningful with
    /// `flake_mirror_cache_dir` set.
    #[serde(default = "default_flake_mirror_cache_max_entries")]
    pub flake_mirror_cache_max_entries: usize,
    /// Eviction ceiling on the total bytes the retained mirrors occupy. See
    /// `flake_mirror_cache_max_entries`.
    #[serde(default = "default_flake_mirror_cache_max_bytes")]
    pub flake_mirror_cache_max_bytes: ByteSize,
    /// Directory under which the broker materialises throwaway local clones to
    /// run `nix flake archive` against. `None` defaults to
    /// `<work_root>/flake-materialize`. Created owner-only (0700).
    #[serde(default)]
    pub flake_materialize_scratch_dir: Option<PathBuf>,
    /// Maximum number of locked flake inputs the broker will provision in one
    /// request; a lock with more inputs is refused fail-closed.
    #[serde(default = "default_flake_provision_max_input_count")]
    pub flake_provision_max_input_count: usize,
    /// Maximum total bytes the broker will archive for one provision request;
    /// an over-budget archive is not published (fail-closed).
    #[serde(default = "default_flake_provision_max_total_bytes")]
    pub flake_provision_max_total_bytes: ByteSize,
    /// Timeout (seconds) for the `nix flake archive` step of one provision
    /// request.
    #[serde(default = "default_flake_provision_timeout_secs")]
    pub flake_provision_timeout_secs: u64,
    #[serde(default)]
    pub claude_proxy: Option<AgentVmHttpClaudeProxyConfig>,
    #[serde(default)]
    pub openai_proxy: Option<AgentVmHttpOpenAiProxyConfig>,
    #[serde(default)]
    pub git_push_staging_root: Option<PathBuf>,
    #[serde(default = "default_git_push_max_body_bytes")]
    pub git_push_max_body_bytes: ByteSize,
    #[serde(default = "default_git_push_max_metadata_bytes")]
    pub git_push_max_metadata_bytes: ByteSize,
    #[serde(default = "default_git_push_max_bundle_bytes")]
    pub git_push_max_bundle_bytes: ByteSize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVmHttpClaudeProxyConfig {
    pub upstream_base_url: String,
    pub auth_secret: SecretKey,
    pub auth_kind: VmHttpClaudeProxyAuthKind,
    #[serde(default = "default_claude_anthropic_version")]
    pub anthropic_version: String,
    pub timeout_secs: u64,
    pub max_request_bytes: ByteSize,
    pub max_response_bytes: ByteSize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVmHttpOpenAiProxyConfig {
    pub upstream_base_url: String,
    pub auth_secret: SecretKey,
    pub auth_kind: VmHttpOpenAiProxyAuthKind,
    pub timeout_secs: u64,
    pub max_request_bytes: ByteSize,
    pub max_response_bytes: ByteSize,
}

/// Which secret backend to use. The file backend is recommended for
/// headless Linux hosts; the keyring backend uses the OS native keychain
/// (macOS Keychain or freedesktop Secret Service).
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretStoreConfig {
    File {
        path: PathBuf,
    },
    Keyring {
        #[serde(default = "default_keyring_service")]
        service: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum AgentVmHttpConfigError {
    #[error(transparent)]
    BrokerPortRange(#[from] AgentVmConfigError),
    #[error(transparent)]
    TokenEnv(#[from] GitSecretEnvVarError),
    #[error(transparent)]
    GitClone(#[from] GitCloneBundlePlanError),
    #[error(transparent)]
    NixCache(#[from] VmHttpNixCacheConfigError),
    #[error(transparent)]
    NixTrustedPublicKeys(#[from] NixTrustedPublicKeysError),
    #[error(transparent)]
    ClaudeProxy(#[from] VmHttpClaudeProxyConfigError),
    #[error(transparent)]
    OpenAiProxy(#[from] VmHttpOpenAiProxyConfigError),
    #[error(transparent)]
    GitPushBodyLimits(#[from] VmGitPushBodyLimitsError),
    #[error("git push staging root path must not be empty")]
    EmptyGitPushStagingRoot,
    #[error("git push staging root path must be absolute: {0:?}")]
    RelativeGitPushStagingRoot(PathBuf),
    #[error("git push staging root {path:?} could not be created: {source}")]
    GitPushStagingRootCreate {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("git push staging root {path:?} is not writable: {source}")]
    GitPushStagingRootProbe {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("vm_http work root {path:?} could not be created at mode 0700: {source}")]
    WorkRootCreate {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("vm_http work root {path:?} is not a directory")]
    WorkRootNotDirectory { path: PathBuf },
    #[error(
        "vm_http work root {path:?} has group/world access bits (mode {mode:04o}); \
         use a dedicated 0700 directory"
    )]
    WorkRootInsecure { path: PathBuf, mode: u32 },
    #[error("flake input cache dir path must not be empty")]
    EmptyFlakeInputCacheDir,
    #[error("flake input cache dir path must be absolute: {0:?}")]
    RelativeFlakeInputCacheDir(PathBuf),
    #[error("flake input cache dir {path:?} could not be created: {source}")]
    FlakeInputCacheDirCreate {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("flake input cache dir {path:?} is not writable: {source}")]
    FlakeInputCacheDirProbe {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("nix pre-warm cache dir path must not be empty")]
    EmptyNixPrewarmCacheDir,
    #[error("nix pre-warm cache dir path must be absolute: {0:?}")]
    RelativeNixPrewarmCacheDir(PathBuf),
    #[error("nix pre-warm cache dir {path:?} exists but is not a listable directory: {source}")]
    NixPrewarmCacheDirUnusable {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("flake mirror cache dir path must not be empty")]
    EmptyFlakeMirrorCacheDir,
    #[error("flake mirror cache dir path must be absolute: {0:?}")]
    RelativeFlakeMirrorCacheDir(PathBuf),
    #[error("flake materialize scratch dir path must not be empty")]
    EmptyFlakeMaterializeScratchDir,
    #[error("flake materialize scratch dir path must be absolute: {0:?}")]
    RelativeFlakeMaterializeScratchDir(PathBuf),
    #[error(transparent)]
    FlakeProvisionBounds(#[from] FlakeProvisionBoundsError),
}

/// What [`check_daemon_sections`] resolved: the optional agent-VM runtime
/// config, and the agent-run log root — which is not optional, because it is
/// resolved from a default when the operator names none.
#[derive(Debug)]
pub struct CheckedDaemonSections {
    pub agent_vm: Option<AgentVmDaemonRuntimeConfig>,
    pub agent_run_log_root: AgentRunLogRoot,
}

/// Validate every daemon section that can be checked before writd takes an
/// irreversible step, reporting all the failures together.
///
/// Takes the sections rather than the whole [`DaemonConfig`] because the
/// binary destructures it first. Living here — rather than being assembled in
/// `writd` — keeps the accumulator vocabulary, and in particular the `Failed`
/// marker, inside this crate.
///
/// `agent_run_log_root` is [`DaemonConfig::agent_run_log_root`] verbatim;
/// `None` resolves to [`default_agent_run_log_root`]. It is checked and
/// created unconditionally, because it is not a subsystem's directory — see
/// that field for which arm writes there today.
pub fn check_daemon_sections(
    agent_vm: Option<&AgentVmDaemonConfig>,
    ui_http: Option<&UiHttpConfig>,
    agent_run_log_root: Option<&Path>,
) -> Result<CheckedDaemonSections, Errors<DaemonConfigError>> {
    let mut errors = Accumulator::new();
    let agent_vm = errors.record_many(agent_vm.map(AgentVmDaemonConfig::check).transpose());
    let ui_http = errors.record_many(ui_http.map(UiHttpConfig::validate).transpose());
    let agent_run_log_root = errors.record_from(AgentRunLogRoot::check(
        agent_run_log_root
            .map(Path::to_path_buf)
            .unwrap_or_else(default_agent_run_log_root),
    ));
    let (agent_vm, _ui_http, agent_run_log_root) =
        errors.unpack(all_recorded!(agent_vm, ui_http, agent_run_log_root))?;

    // Only now, with every section checked, is it right to create anything.
    // Creating the log root and materialising the agent-VM plan are
    // independent effects, so both run and both report: an unwritable log root
    // must not hide an unwritable push-staging root, and vice versa.
    // `materialize` is handed the *checked* root rather than waiting on the
    // prepared one, which is the same path — preparation creates and proves it
    // writable, it does not rewrite it. Either order is safe: the log root is
    // created owner-only, so if it happens to sit under a not-yet-existing
    // `vm_http.work_root` it leaves that parent at 0700, which is exactly what
    // `ensure_vm_http_work_root_private` demands.
    let mut errors = Accumulator::new();
    let prepared = errors.record_from(agent_run_log_root.prepare());
    let agent_vm = errors.record_many(
        agent_vm
            .map(|plan| plan.materialize(agent_run_log_root.clone()))
            .transpose(),
    );
    let (agent_vm, ()) = errors.unpack(all_recorded!(agent_vm, prepared))?;
    Ok(CheckedDaemonSections {
        agent_vm,
        agent_run_log_root,
    })
}

/// A problem found while turning a [`DaemonConfig`] into runtime state.
///
/// Exists so failures from the independent top-level sections accumulate into
/// one report: without a common type, a bad `agent_vm` section would be
/// reported and a bad `ui_http` section only discovered on the next boot.
#[derive(Debug, thiserror::Error)]
pub enum DaemonConfigError {
    #[error(transparent)]
    AgentVm(#[from] AgentVmDaemonConfigError),
    #[error(transparent)]
    UiHttp(#[from] UiHttpConfigError),
    #[error(transparent)]
    AgentRunLogRoot(#[from] AgentRunLogRootError),
}

/// An `agent_run_log_root` that has passed its text checks: non-empty and
/// absolute.
///
/// Parse-don't-validate for the one config value that is threaded *through*
/// the section validators rather than parsed by one of them. Without it,
/// [`AgentVmDaemonConfig::to_runtime_config`] would take a bare `PathBuf` and
/// a caller could hand it a relative path, producing an apparently-valid
/// runtime config whose first agent-run outcome fails at upload time.
///
/// Being checked is *not* being prepared: [`Self::prepare`] is the separate
/// effectful step, the same split `check_writable_root` /
/// `prepare_writable_root` give the `vm_http` roots, so that a config can be
/// rejected on its text without anything having been created.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRunLogRoot(PathBuf);

impl AgentRunLogRoot {
    /// The pure half: the same two text checks the `vm_http` roots get, in
    /// this key's own vocabulary.
    pub fn check(path: PathBuf) -> Result<Self, AgentRunLogRootError> {
        if path.as_os_str().is_empty() {
            return Err(AgentRunLogRootError::Empty);
        }
        if !path.is_absolute() {
            return Err(AgentRunLogRootError::Relative(path));
        }
        Ok(Self(path))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    /// The effectful half: create the directory **owner-only** if absent, then
    /// prove the daemon can write into it.
    ///
    /// Owner-only is not decoration. Per-run subdirectories hold agent output
    /// that `agent_run_outcome` rows point at, and a group- or world-writable
    /// parent lets another local user rename or delete them, silently
    /// invalidating what the audit log claims is on disk. The runtime already
    /// insists on this — `writ_agent_run`'s `ensure_private_dir` chmods the
    /// root to 0700 before each run — so creating it any other way here would
    /// only mean the mode changed out from under the operator later.
    ///
    /// The mode applies to every component this creates, which is what makes
    /// the *nested* case safe: an operator who keeps the old
    /// `<vm_http.work_root>/agent-runs` layout has this create `work_root`
    /// itself, and `ensure_vm_http_work_root_private` refuses a work root with
    /// any group or world bit set. At 0700 it accepts, so the two roots can be
    /// prepared in either order.
    pub fn prepare(&self) -> Result<(), AgentRunLogRootError> {
        create_private_dir_all(&self.0).map_err(|source| AgentRunLogRootError::Create {
            path: self.0.clone(),
            source,
        })?;
        probe_writable(&self.0, ".writ-agent-run-log-probe").map_err(|source| {
            AgentRunLogRootError::Probe {
                path: self.0.clone(),
                source,
            }
        })
    }
}

/// Create `path` and any missing parents with mode 0700, and pin the mode of
/// `path` itself even when it already existed.
///
/// `DirBuilderExt::mode` is masked by the process umask, and says nothing
/// about a directory that was already there, so the explicit `set_permissions`
/// is what actually makes the postcondition hold. Only the leaf is pinned: an
/// existing parent belongs to whoever made it, and tightening it here would be
/// mutating a directory this config never named.
fn create_private_dir_all(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Faults in the top-level `agent_run_log_root` key.
///
/// Its own type, not an `agent_vm` one: the root is a top-level key, so a
/// daemon with no `agent_vm` section at all still has one and can still get it
/// wrong.
#[derive(Debug, thiserror::Error)]
pub enum AgentRunLogRootError {
    #[error("agent run log root path must not be empty")]
    Empty,
    #[error("agent run log root path must be absolute: {0:?}")]
    Relative(PathBuf),
    #[error("agent run log root {path:?} could not be created: {source}")]
    Create {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("agent run log root {path:?} is not writable: {source}")]
    Probe {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum AgentVmDaemonConfigError {
    #[error(transparent)]
    VmHttp(#[from] AgentVmHttpConfigError),
    #[error(transparent)]
    AgentVm(#[from] AgentVmConfigError),
    #[error(transparent)]
    Lifecycle(#[from] AgentVmLifecycleConfigError),
    #[error(transparent)]
    StateDir(#[from] AgentVmStateDirError),
    #[error(transparent)]
    LifecycleRuntime(#[from] AgentVmLifecycleRuntimeConfigError),
    #[error(transparent)]
    Runtime(#[from] AgentVmDaemonRuntimeConfigError),
    #[error("agent VM config field {field} has invalid CIDR {value:?}: {message}")]
    InvalidCidr {
        field: &'static str,
        value: String,
        message: String,
    },
}

impl AgentVmDaemonConfig {
    /// Validate both subsections and build the runtime config.
    ///
    /// Equivalent to [`Self::check`] followed by
    /// [`AgentVmDaemonPlan::materialize`]; a caller that also validates
    /// *sibling* config sections should use those two directly, so that this
    /// section creates nothing until those siblings have been checked too.
    pub fn to_runtime_config(
        &self,
        agent_run_log_root: AgentRunLogRoot,
    ) -> Result<AgentVmDaemonRuntimeConfig, Errors<AgentVmDaemonConfigError>> {
        self.check()?.materialize(agent_run_log_root)
    }

    /// Run every check that touches nothing across both subsections, and
    /// return the plan for the checks that do.
    ///
    /// The lifecycle and vm_http sections are independent, so a mistake in one
    /// must not hide every mistake in the other; both are checked here.
    /// Lifecycle validation touches nothing, and `vm_http`'s filesystem work is
    /// deferred into a [`VmHttpPlan`], so a config rejected on its text leaves
    /// no directories behind no matter which section was at fault.
    pub fn check(&self) -> Result<AgentVmDaemonPlan, Errors<AgentVmDaemonConfigError>> {
        let mut errors = Accumulator::new();
        let lifecycle = errors.record_many(self.lifecycle.to_runtime_config());
        let vm_http_plan = errors.record_many(self.vm_http.check());
        // The daemon-level bind invariant reads one already-typed field, so it
        // is checked straight off the raw config: independent of whatever else
        // the section got wrong, and well before the plan creates anything.
        let _bind_addr = errors.record_from(AgentVmDaemonRuntimeConfig::check_bind_addr(
            self.vm_http.bind_addr,
        ));
        let (lifecycle, vm_http) = errors.unpack(all_recorded!(lifecycle, vm_http_plan))?;
        Ok(AgentVmDaemonPlan { lifecycle, vm_http })
    }
}

/// An `agent_vm` section that has passed every check that touches nothing,
/// carrying its `vm_http` subsection's still-unexecuted [`VmHttpPlan`].
///
/// The same split as [`VmHttpPlan`], one level up, so that it *composes*: a
/// caller validating sibling sections can hold this while it checks them, and
/// materialize only once the whole config is known good.
#[derive(Debug)]
pub struct AgentVmDaemonPlan {
    lifecycle: AgentVmLifecycleRuntimeConfig,
    vm_http: VmHttpPlan,
}

impl AgentVmDaemonPlan {
    /// Create the planned directories and assemble the runtime config.
    ///
    /// `agent_run_log_root` comes from the top level of the config rather than
    /// this section (see [`DaemonConfig::agent_run_log_root`]); the agent-VM
    /// runtime carries it because the VM arm is one of its two writers.
    pub fn materialize(
        self,
        agent_run_log_root: AgentRunLogRoot,
    ) -> Result<AgentVmDaemonRuntimeConfig, Errors<AgentVmDaemonConfigError>> {
        let vm_http = self.vm_http.materialize().map_err(Errors::map_into)?;
        AgentVmDaemonRuntimeConfig::new(self.lifecycle, vm_http, agent_run_log_root)
            .map_err(|err| Errors::single(err.into()))
    }
}

impl AgentVmLifecycleConfig {
    /// Validate the `lifecycle` section, reporting every independent problem
    /// in one pass. See [`AgentVmHttpConfig::to_runtime_config`] for the
    /// shape; the same rules apply here.
    pub fn to_runtime_config(
        &self,
    ) -> Result<AgentVmLifecycleRuntimeConfig, Errors<AgentVmDaemonConfigError>> {
        let mut errors = Accumulator::new();
        let ipv4_pool = errors.record(parse_ipv4_cidr_config("ipv4_pool", &self.ipv4_pool));
        let ipv6_pool = errors.record(parse_ipv6_cidr_config("ipv6_pool", &self.ipv6_pool));
        let pool = all_recorded!(ipv4_pool, ipv6_pool)
            .and_then(|(v4, v6)| errors.record_from(AgentNetworkPool::new(v4, v6)));
        let state_dir = match &self.state_dir {
            Some(path) => Ok(path.clone()),
            None => errors.record_from(default_agent_vm_state_dir()),
        };
        // Only the vm arm runs a broker VM, so `broker_image` is meaningful only
        // there. Ignore it entirely for host placement (as documented), so a
        // stray/empty value on a host config can't reject startup and
        // `broker_image()` stays `Some` exactly when placement is `Vm`.
        let broker_image = match self.broker_placement {
            BrokerPlacement::Vm => errors.record_from(
                self.broker_image
                    .as_ref()
                    .map(|image| ContainerImage::new(image.clone()))
                    .transpose(),
            ),
            BrokerPlacement::Host => Ok(None),
        };
        let image = errors.record_from(ContainerImage::new(self.image.clone()));
        let resources = errors.record_from(AgentVmResources::new(self.cpus, self.memory_mib));

        let (pool, state_dir, broker_image, image, resources) = errors.unpack(all_recorded!(
            pool,
            state_dir,
            broker_image,
            image,
            resources,
        ))?;
        AgentVmLifecycleRuntimeConfig::new(
            pool,
            self.subnet_index_min,
            self.subnet_index_max,
            AgentVmSessionStateStore::new(state_dir),
            self.ipv6_mode,
            self.broker_placement,
            image,
            broker_image,
            resources,
            AgentVmToolPaths::new(
                self.container.clone(),
                self.pf_helper.clone(),
                self.sudo.clone(),
            ),
        )
        .map_err(|err| Errors::single(err.into()))
    }
}

/// A `vm_http` section that has passed every check that can be made without
/// touching the filesystem, together with the directories that still have to
/// be created before the broker can run.
///
/// This is the interpreter pattern applied to config validation: [`AgentVmHttpConfig::check`]
/// computes an inert description of what needs to exist, and
/// [`VmHttpPlan::materialize`] carries it out. Separating them is what lets a
/// caller validating *several* sections check all of them before any one of
/// them creates anything — otherwise a fault in a sibling section would still
/// leave this one's directories behind.
#[derive(Debug)]
pub struct VmHttpPlan {
    runtime: VmHttpRuntimeConfig,
    work_root: PathBuf,
    /// In creation order. The work root is prepared before any of these, so a
    /// root beneath it is never created by `create_dir_all` at the process
    /// umask.
    roots: Vec<RootPlan>,
}

/// One directory [`VmHttpPlan::materialize`] must create and prove writable.
#[derive(Debug)]
struct RootPlan {
    kind: WritableRoot,
    path: PathBuf,
}

impl VmHttpPlan {
    /// Create the planned directories and prove the broker can write to them,
    /// accumulating failures across all of them.
    pub fn materialize(self) -> Result<VmHttpRuntimeConfig, Errors<AgentVmHttpConfigError>> {
        let mut errors = Accumulator::new();
        // `prepare_git_work_root` refuses to clone into a work root whose mode
        // has group/world bits set, but `prepare_writable_root` below creates
        // the staging/log subdirs with `create_dir_all`, which propagates the
        // process umask to the freshly-created `work_root` parent (typically
        // 0755). Ensure work_root itself is 0700 before that runs so the
        // out-of-the-box defaults — where the user never names `work_root`
        // explicitly — survive the first clone request.
        let work_root_ready = errors.record(ensure_vm_http_work_root_private(&self.work_root));
        // Every root waits on the work root, including one the operator named
        // explicitly. Whether a named root is *really* a descendant cannot be
        // decided reliably here: it need not exist yet, so it cannot be
        // canonicalised, and a lexical `starts_with` is case-sensitive and blind
        // to symlinks and `..`. Getting that wrong in the permissive direction
        // mutates the filesystem on behalf of a config that has already been
        // rejected — a rejected work root is often one that merely *exists* with
        // loose permissions, and `create_dir_all` of a child inside it succeeds
        // happily. So take the conservative branch uniformly.
        //
        // The cost is one extra round-trip in the narrow case where the work
        // root and some other root are both broken: the operator learns the
        // second root is unwritable only after fixing the work root. Every
        // *textual* fault in those roots was already reported by `check`, which
        // does not gate on anything.
        for root in self.roots {
            let _ = work_root_ready
                .and_then(|()| errors.record(prepare_writable_root(root.kind, root.path)));
        }
        errors.finish().map(|()| self.runtime)
    }
}

impl AgentVmHttpConfig {
    /// Validate the whole `vm_http` section and build its runtime config,
    /// reporting **every** independent problem rather than stopping at the
    /// first.
    ///
    /// Equivalent to [`Self::check`] followed by [`VmHttpPlan::materialize`];
    /// callers validating several sections should use those two directly, so
    /// that no section creates anything until all of them have been checked.
    pub fn to_runtime_config(&self) -> Result<VmHttpRuntimeConfig, Errors<AgentVmHttpConfigError>> {
        self.check()?.materialize()
    }

    /// Run every check that touches nothing, and return the plan for the
    /// checks that do.
    ///
    /// The shape is uniform: each check is `record`ed into an accumulator,
    /// which stores failures instead of short-circuiting, and a check whose
    /// own inputs failed is *skipped* rather than reported — the operator
    /// should see a root cause once, not a cascade of its consequences.
    pub fn check(&self) -> Result<VmHttpPlan, Errors<AgentVmHttpConfigError>> {
        let mut errors = Accumulator::new();

        // --- Pure checks. Independent of each other and of the filesystem, so
        // every one of them runs on every call.
        let broker_port_range = errors.record_from(BrokerPortRange::new(
            self.broker_port_min,
            self.broker_port_max,
        ));
        let token_env = errors.record_from(GitSecretEnvVar::new(self.token_env.clone()));
        let clone_base_url = errors.record_from(GitCloneBaseUrl::parse(&self.git_clone_base_url));
        let trusted_public_keys = errors.record_from(NixTrustedPublicKeys::from_strings(
            self.nix_cache_trusted_public_keys.clone(),
        ));
        let git_push_body_limits = errors.record_from(VmGitPushBodyLimits::new(
            self.git_push_max_body_bytes,
            self.git_push_max_metadata_bytes,
            self.git_push_max_bundle_bytes,
        ));
        let claude_proxy = errors.record(
            self.claude_proxy
                .as_ref()
                .map(AgentVmHttpClaudeProxyConfig::to_runtime_config)
                .transpose(),
        );
        let openai_proxy = errors.record(
            self.openai_proxy
                .as_ref()
                .map(AgentVmHttpOpenAiProxyConfig::to_runtime_config)
                .transpose(),
        );
        // The nix-cache URL and its size limits are checked here, separately
        // from the trusted-key list, so a malformed key cannot hide a malformed
        // URL; the keys are attached below once both have parsed.
        let nix_cache = errors.record_from(VmHttpNixCacheConfig::new(
            &self.nix_cache_url,
            self.nix_cache_max_metadata_bytes,
            self.nix_cache_max_nar_bytes,
        ));
        // The work root is shape-checked before `ensure_vm_http_work_root_private`
        // may run: that function creates the directory, and on a relative path it
        // would create one relative to the daemon's cwd.
        let work_root = errors.record(check_work_root(&self.work_root));
        let nix_prewarm_cache_dir = errors.record(
            self.nix_prewarm_cache_dir
                .clone()
                .map(validate_nix_prewarm_cache_dir)
                .transpose(),
        );
        let mirror_cache_dir = errors.record(
            self.flake_mirror_cache_dir
                .clone()
                .map(validate_flake_mirror_cache_dir)
                .transpose(),
        );
        // An explicitly configured root's shape is independent of the work
        // root, so it is checked even when the work root is broken. A *derived*
        // root only inherits the work root's fate: reporting it too would just
        // echo the same mistake back twice.
        let git_push_staging_root = checked_root(
            &mut errors,
            WritableRoot::GitPushStaging,
            self.git_push_staging_root.as_deref(),
            "git-push-staging",
            work_root,
        );
        // The broker-local flake-input archive lives under work_root by default,
        // alongside the agent-run and git-push roots. Wiring it as the nix-cache
        // local cache makes the endpoint serve archived inputs local-first; an
        // empty directory (nothing provisioned yet) is byte-identical to
        // upstream-only serving.
        let flake_input_cache_dir = checked_root(
            &mut errors,
            WritableRoot::FlakeInputCache,
            self.flake_input_cache_dir.as_deref(),
            "flake-input-cache",
            work_root,
        );
        // Provisioning is switched on by `flake_mirror_cache_dir`, so its knobs
        // are checked whenever the operator has asked for it — keyed off the
        // field's *presence*, not off whether its path passed, so a bad mirror
        // path does not hide bad bounds.
        let provision_requested = self.flake_mirror_cache_dir.is_some();
        let flake_provision_bounds = provision_requested
            .then(|| {
                errors.record_from(FlakeProvisionBounds::new(
                    self.flake_provision_max_input_count,
                    self.flake_provision_max_total_bytes,
                    Duration::from_secs(self.flake_provision_timeout_secs),
                ))
            })
            .transpose();
        let flake_materialize_scratch_dir = provision_requested
            .then(|| match &self.flake_materialize_scratch_dir {
                Some(path) => errors.record(validate_flake_materialize_scratch_dir(path.clone())),
                None => work_root.map(|root| root.join("flake-materialize")),
            })
            .transpose();

        // Composites, each built from checks that have already passed. Both
        // are pure, so they belong above the checkpoint.
        let credential = token_env.and_then(|token_env| {
            errors.record_from(GitCredentialBoundary::new(
                self.askpass_program.clone(),
                token_env,
            ))
        });
        let git_clone = all_recorded!(credential, clone_base_url, work_root).and_then(
            |(credential, clone_base_url, work_root)| {
                errors.record_from(VmHttpGitCloneConfig::new_with_clone_base_url(
                    self.git_program.clone(),
                    clone_base_url,
                    credential,
                    work_root.to_path_buf(),
                    Duration::from_secs(self.clone_timeout_secs),
                    self.max_bundle_bytes,
                ))
            },
        );

        let (
            work_root,
            broker_port_range,
            git_clone,
            nix_cache,
            trusted_public_keys,
            claude_proxy,
            openai_proxy,
            git_push_staging_root,
            git_push_body_limits,
            flake_input_cache_dir,
            mirror_cache_dir,
            nix_prewarm_cache_dir,
            flake_provision_bounds,
            flake_materialize_scratch_dir,
        ) = errors.unpack(all_recorded!(
            work_root,
            broker_port_range,
            git_clone,
            nix_cache,
            trusted_public_keys,
            claude_proxy,
            openai_proxy,
            git_push_staging_root,
            git_push_body_limits,
            flake_input_cache_dir,
            mirror_cache_dir,
            nix_prewarm_cache_dir,
            flake_provision_bounds,
            flake_materialize_scratch_dir,
        ))?;

        // Everything below is assembly: every value is already validated, so
        // there is nothing left that can fail.

        // When configured, retain each clone's bare mirror for later
        // flake-input provisioning; the cache creates its (owner-only) directory
        // on first insert. `None` keeps the discard-after-bundle behaviour. The
        // same cache backs the flake-provision endpoint below, so clone +
        // provision share one fetch.
        let mirror_cache = mirror_cache_dir.map(MirrorCache::new);
        // The eviction bounds only matter when the cache is enabled; pair them
        // with the cache so the clone handler runs a bounded pass after retain.
        let mirror_gc_bounds = mirror_cache.as_ref().map(|_| {
            MirrorCacheBounds::new(
                self.flake_mirror_cache_max_entries,
                self.flake_mirror_cache_max_bytes,
            )
        });
        let git_clone = git_clone
            .with_mirror_cache(mirror_cache.clone())
            .with_mirror_gc_bounds(mirror_gc_bounds);
        // Flake-input provisioning re-derives a checkout from a retained mirror,
        // so it is enabled exactly when the mirror cache is. It archives the
        // committed, locked inputs into the very same shared CA cache the
        // nix-cache endpoint serves local-first, so the guest realises them
        // through the substituter it already trusts.
        let flake_provision = match (
            mirror_cache,
            flake_materialize_scratch_dir,
            flake_provision_bounds,
        ) {
            (Some(mirror_cache), Some(scratch_root), Some(bounds)) => {
                let provision = MirrorFlakeProvisionConfig::new(
                    self.git_program.clone(),
                    self.nix_program.clone(),
                    scratch_root,
                    flake_input_cache_dir.clone(),
                    bounds,
                    Duration::from_secs(self.clone_timeout_secs),
                );
                Some(VmHttpFlakeProvisionConfig::new(provision, mirror_cache))
            }
            // The scratch dir and bounds are computed exactly when the mirror
            // cache dir is configured, so the mixed cases cannot arise.
            _ => None,
        };
        // Local archives served local-first, in order: a durable, operator-
        // managed pre-warmed closure cache (when configured) ahead of the
        // auto-provisioned flake-input cache. The pre-warm dir is read-only to
        // the broker — the egress builder writes it out of band — so it is not
        // created here; an absent/empty dir simply serves nothing. Trust for its
        // signed paths rides the existing `nix_cache_trusted_public_keys`
        // (the same list the guest verifies against), so no separate key.
        let mut local_cache_dirs = Vec::new();
        if let Some(prewarm) = &nix_prewarm_cache_dir {
            local_cache_dirs.push(prewarm.clone());
        }
        local_cache_dirs.push(flake_input_cache_dir.clone());
        let nix_cache = nix_cache
            .with_trusted_public_keys(trusted_public_keys)
            .with_local_cache_dirs(local_cache_dirs);
        let runtime = VmHttpRuntimeConfig::new_with_proxies(
            self.bind_addr,
            broker_port_range,
            git_clone,
            nix_cache,
            claude_proxy,
            openai_proxy,
            git_push_staging_root.clone(),
            git_push_body_limits,
        )
        .with_flake_provision(flake_provision)
        .with_nix_prewarm_cache_dir(nix_prewarm_cache_dir);
        // The directories are named but not yet created; `materialize` does
        // that, once every section the caller cares about has been checked.
        // Order matters: the work root is prepared first (see
        // `VmHttpPlan::materialize`), then these in turn.
        let roots = vec![
            RootPlan {
                kind: WritableRoot::GitPushStaging,
                path: git_push_staging_root,
            },
            RootPlan {
                kind: WritableRoot::FlakeInputCache,
                path: flake_input_cache_dir,
            },
        ];
        Ok(VmHttpPlan {
            runtime,
            work_root: work_root.to_path_buf(),
            roots,
        })
    }
}

/// Shape-check one writable root: the explicitly configured path when the
/// operator named one, otherwise `<work_root>/<default_subdir>`.
///
/// Kept as a helper because the roots differ only in their kind, their
/// field, and their default subdirectory — and because the configured/derived
/// distinction is the subtle part, worth stating once. A configured path
/// stands on its own, so it is checked even when the work root is broken; a
/// derived one inherits the work root's fate, and reporting it too would echo
/// the same mistake back to the operator twice.
fn checked_root(
    errors: &mut Accumulator<AgentVmHttpConfigError>,
    kind: WritableRoot,
    configured: Option<&Path>,
    default_subdir: &str,
    work_root: Result<&Path, accumulate::Failed>,
) -> Result<PathBuf, accumulate::Failed> {
    match configured {
        Some(path) => errors.record(check_writable_root(kind, path.to_path_buf())),
        None => work_root.map(|root| root.join(default_subdir)),
    }
}

/// Shape-check the configured work root before anything creates it.
///
/// Reuses [`GitCloneBundlePlanError`]'s field-tagged variants rather than
/// inventing a parallel taxonomy: these are the same two checks
/// [`VmHttpGitCloneConfig::new_with_clone_base_url`] performs, hoisted so they
/// run before the directory-creating code below rather than after it.
fn check_work_root(path: &Path) -> Result<&Path, AgentVmHttpConfigError> {
    if path.as_os_str().is_empty() {
        return Err(GitCloneBundlePlanError::EmptyPath { field: "work_root" }.into());
    }
    if !path.is_absolute() {
        return Err(GitCloneBundlePlanError::RelativePath {
            field: "work_root",
            path: path.to_path_buf(),
        }
        .into());
    }
    Ok(path)
}

impl AgentVmHttpClaudeProxyConfig {
    fn to_runtime_config(&self) -> Result<VmHttpClaudeProxyConfig, AgentVmHttpConfigError> {
        Ok(VmHttpClaudeProxyConfig::new_with_anthropic_version(
            &self.upstream_base_url,
            self.auth_secret.clone(),
            self.auth_kind,
            &self.anthropic_version,
            Duration::from_secs(self.timeout_secs),
            self.max_request_bytes,
            self.max_response_bytes,
        )?)
    }
}

impl AgentVmHttpOpenAiProxyConfig {
    fn to_runtime_config(&self) -> Result<VmHttpOpenAiProxyConfig, AgentVmHttpConfigError> {
        Ok(VmHttpOpenAiProxyConfig::new(
            &self.upstream_base_url,
            self.auth_secret.clone(),
            self.auth_kind,
            Duration::from_secs(self.timeout_secs),
            self.max_request_bytes,
            self.max_response_bytes,
        )?)
    }
}

fn ensure_vm_http_work_root_private(path: &Path) -> Result<(), AgentVmHttpConfigError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => return validate_existing_work_root(path, &metadata),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(AgentVmHttpConfigError::WorkRootCreate {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|source| {
            AgentVmHttpConfigError::WorkRootCreate {
                path: parent.to_path_buf(),
                source,
            }
        })?;
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            // TOCTOU: the directory appeared between our existence check and
            // the create. Validate it the same way as any pre-existing dir
            // rather than fail; the alternative invents a phantom startup
            // error whenever two daemons race on the default path.
            let metadata = std::fs::symlink_metadata(path).map_err(|source| {
                AgentVmHttpConfigError::WorkRootCreate {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            return validate_existing_work_root(path, &metadata);
        }
        Err(source) => {
            return Err(AgentVmHttpConfigError::WorkRootCreate {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    // mode(0o700) is the requested mode; the process umask still applies, so
    // set the final mode explicitly to keep the result reliably private.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|source| {
        AgentVmHttpConfigError::WorkRootCreate {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn validate_existing_work_root(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), AgentVmHttpConfigError> {
    use std::os::unix::fs::PermissionsExt;

    // Mirror `prepare_git_work_root` so an existing dir with loose permissions
    // fails fast at startup rather than letting the daemon boot and then
    // rejecting every clone request at runtime.
    if !metadata.is_dir() {
        return Err(AgentVmHttpConfigError::WorkRootNotDirectory {
            path: path.to_path_buf(),
        });
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(AgentVmHttpConfigError::WorkRootInsecure {
            path: path.to_path_buf(),
            mode: mode & 0o777,
        });
    }
    Ok(())
}

/// One of the two writable directories the broker keeps beneath its `vm_http`
/// work root. Both are validated identically — non-empty, absolute, creatable,
/// writable — and differ only in which error variants name them and in the
/// probe filename, so the *kind* is data and the checks are written once.
///
/// The agent-run log root is validated the same way but is *not* one of these:
/// it hangs off the top level of the config, not `vm_http`, because both
/// `RunAgent` arms write under it. It shares the effectful half
/// ([`create_and_probe`]) and reports through [`AgentRunLogRootError`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum WritableRoot {
    GitPushStaging,
    FlakeInputCache,
}

impl WritableRoot {
    /// A distinct probe filename per root so two roots that happen to be
    /// configured to the same directory cannot collide on `create_new`.
    fn probe_prefix(self) -> &'static str {
        match self {
            Self::GitPushStaging => ".writ-git-push-staging-probe",
            Self::FlakeInputCache => ".writ-flake-input-cache-probe",
        }
    }

    fn empty(self) -> AgentVmHttpConfigError {
        match self {
            Self::GitPushStaging => AgentVmHttpConfigError::EmptyGitPushStagingRoot,
            Self::FlakeInputCache => AgentVmHttpConfigError::EmptyFlakeInputCacheDir,
        }
    }

    fn relative(self, path: PathBuf) -> AgentVmHttpConfigError {
        match self {
            Self::GitPushStaging => AgentVmHttpConfigError::RelativeGitPushStagingRoot(path),
            Self::FlakeInputCache => AgentVmHttpConfigError::RelativeFlakeInputCacheDir(path),
        }
    }

    fn fault(self, path: PathBuf, fault: RootPreparationFault) -> AgentVmHttpConfigError {
        match (self, fault) {
            (Self::GitPushStaging, RootPreparationFault::Create(source)) => {
                AgentVmHttpConfigError::GitPushStagingRootCreate { path, source }
            }
            (Self::GitPushStaging, RootPreparationFault::Probe(source)) => {
                AgentVmHttpConfigError::GitPushStagingRootProbe { path, source }
            }
            (Self::FlakeInputCache, RootPreparationFault::Create(source)) => {
                AgentVmHttpConfigError::FlakeInputCacheDirCreate { path, source }
            }
            (Self::FlakeInputCache, RootPreparationFault::Probe(source)) => {
                AgentVmHttpConfigError::FlakeInputCacheDirProbe { path, source }
            }
        }
    }
}

/// Which step of preparing a root failed, before it is named in any particular
/// config section's vocabulary. Exists so the shared preparation steps can be
/// written once for roots that report through different error types.
enum RootPreparationFault {
    Create(std::io::Error),
    Probe(std::io::Error),
}

/// Prove this process can actually write into `path`, rather than discovering
/// otherwise at request time. The directory must already exist — creation is
/// the caller's, because the roots differ in what permissions they demand.
///
/// `probe_prefix` distinguishes the probe file per root so two roots
/// configured to the same directory cannot collide on `create_new`.
fn probe_writable(path: &Path, probe_prefix: &str) -> Result<(), std::io::Error> {
    let probe = path.join(format!(
        "{}-{}-{}",
        probe_prefix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .and_then(|mut file| {
            use std::io::Write as _;
            file.write_all(b"probe")?;
            file.sync_all()
        })?;
    std::fs::remove_file(&probe)
}

/// The pure half of validating a writable root: does the *configured text*
/// name a usable directory?
///
/// Split from [`prepare_writable_root`] so a config can be rejected on its
/// text alone without any directory having been created — a typo should leave
/// no debris, and the whole point of checking every field in one pass is that
/// the checks must be safe to run even when a sibling field is broken.
fn check_writable_root(
    kind: WritableRoot,
    path: PathBuf,
) -> Result<PathBuf, AgentVmHttpConfigError> {
    if path.as_os_str().is_empty() {
        return Err(kind.empty());
    }
    if !path.is_absolute() {
        return Err(kind.relative(path));
    }
    Ok(path)
}

/// The effectful half: create the directory if absent, then prove the broker
/// can actually write into it, rather than discovering otherwise at request
/// time. Expects a path that has already passed [`check_writable_root`].
fn prepare_writable_root(
    kind: WritableRoot,
    path: PathBuf,
) -> Result<PathBuf, AgentVmHttpConfigError> {
    std::fs::create_dir_all(&path)
        .map_err(|source| kind.fault(path.clone(), RootPreparationFault::Create(source)))?;
    probe_writable(&path, kind.probe_prefix())
        .map_err(|source| kind.fault(path.clone(), RootPreparationFault::Probe(source)))?;
    Ok(path)
}

/// Validate a configured flake mirror cache directory: a non-empty absolute
/// path. The owner-only directory is created lazily on first insert by
/// [`MirrorCache`], so this only fails fast on a misconfigured path rather than
/// creating or probing anything.
fn validate_flake_mirror_cache_dir(path: PathBuf) -> Result<PathBuf, AgentVmHttpConfigError> {
    if path.as_os_str().is_empty() {
        return Err(AgentVmHttpConfigError::EmptyFlakeMirrorCacheDir);
    }
    if !path.is_absolute() {
        return Err(AgentVmHttpConfigError::RelativeFlakeMirrorCacheDir(path));
    }
    Ok(path)
}

/// Validate a configured nix pre-warm cache directory: a non-empty absolute
/// path that, *if it exists*, the broker can both list and open children of.
/// Unlike the flake-input cache, the broker only *reads* this dir (an egress
/// builder populates it out of band), so this never creates or writes it — a
/// still-absent path is tolerated (set the path before populating).
///
/// The broker uses an existing dir two ways, each needing a different bit, so it
/// must have **both**:
///   - it LISTS the dir — `local_cache_has_narinfo` gates the synthetic
///     `nix-cache-info` on whether any local dir holds a narinfo — which needs
///     **read** (`r`);
///   - it OPENS children by name — serving `<prewarm>/<hash>.narinfo` — which
///     needs **search** (`x`).
///
/// A dir missing either bit silently breaks a pre-warm-only, no-egress guest: no
/// search bit fails every narinfo open closed (502); no read bit makes the
/// cache-info preflight proxy the (unreachable) upstream, so Nix rejects the
/// substituter before requesting any local path. Both must fail fast here rather
/// than at request time, when the local-first path would treat them as
/// authoritative and never fall through to the flake-input cache or upstream.
/// (The broker runs as the invoking user, not root, so the bits are enforced.)
fn validate_nix_prewarm_cache_dir(path: PathBuf) -> Result<PathBuf, AgentVmHttpConfigError> {
    if path.as_os_str().is_empty() {
        return Err(AgentVmHttpConfigError::EmptyNixPrewarmCacheDir);
    }
    if !path.is_absolute() {
        return Err(AgentVmHttpConfigError::RelativeNixPrewarmCacheDir(path));
    }
    // Listability (read): `read_dir` opens the dir for enumeration.
    match std::fs::read_dir(&path) {
        // Absent: tolerated, so the path can be set before the builder fills it.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(path),
        // A file (`ENOTDIR`) or an unreadable dir (`EACCES`): unusable.
        Err(source) => {
            return Err(AgentVmHttpConfigError::NixPrewarmCacheDirUnusable { path, source });
        }
        Ok(_) => {}
    }
    // Searchability (execute): `lstat` of a child name resolves through the dir,
    // needing only its search bit. `NotFound` (the probe child is simply absent)
    // confirms search works; `EACCES` denies it.
    let probe = path.join(".writ-prewarm-cache-search-probe");
    match std::fs::symlink_metadata(&probe) {
        Ok(_) => Ok(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(path),
        Err(source) => Err(AgentVmHttpConfigError::NixPrewarmCacheDirUnusable { path, source }),
    }
}

/// Validate a configured flake materialize scratch directory: a non-empty
/// absolute path. `materialize_flake_tree` creates it owner-only (0700) on
/// first use and refuses a relative path (it runs git from `cwd=/`), so this
/// only fails fast on a misconfigured path rather than creating anything.
fn validate_flake_materialize_scratch_dir(
    path: PathBuf,
) -> Result<PathBuf, AgentVmHttpConfigError> {
    if path.as_os_str().is_empty() {
        return Err(AgentVmHttpConfigError::EmptyFlakeMaterializeScratchDir);
    }
    if !path.is_absolute() {
        return Err(AgentVmHttpConfigError::RelativeFlakeMaterializeScratchDir(
            path,
        ));
    }
    Ok(path)
}

fn default_git_push_max_body_bytes() -> ByteSize {
    // 65 MiB: headroom over the bundle limit for metadata + framing overhead.
    ByteSize::mib(65)
}

fn default_git_push_max_metadata_bytes() -> ByteSize {
    ByteSize::kib(16)
}

fn default_git_push_max_bundle_bytes() -> ByteSize {
    ByteSize::mib(64)
}

fn default_claude_anthropic_version() -> String {
    DEFAULT_CLAUDE_ANTHROPIC_VERSION.into()
}

fn default_keyring_service() -> String {
    "writ".into()
}

fn default_container_program() -> PathBuf {
    PathBuf::from("container")
}

fn default_sudo_program() -> PathBuf {
    PathBuf::from("sudo")
}

fn default_vm_git_token_env() -> String {
    "WRIT_GIT_TOKEN".into()
}

fn default_git_clone_base_url() -> String {
    DEFAULT_GIT_CLONE_BASE_URL.into()
}

fn default_vm_http_bind_addr() -> Ipv4Addr {
    // The runtime config rejects any non-wildcard bind, so this is the only
    // value that survives validation; expressing it as a default lets callers
    // omit the field entirely instead of repeating the lone valid choice.
    Ipv4Addr::UNSPECIFIED
}

fn default_vm_http_git_program() -> PathBuf {
    PathBuf::from("git")
}
fn default_vm_http_nix_program() -> PathBuf {
    PathBuf::from("nix")
}
fn default_flake_provision_max_input_count() -> usize {
    256
}
fn default_flake_provision_max_total_bytes() -> ByteSize {
    ByteSize::gib(2)
}
fn default_flake_provision_timeout_secs() -> u64 {
    600
}
fn default_flake_mirror_cache_max_entries() -> usize {
    64
}
fn default_flake_mirror_cache_max_bytes() -> ByteSize {
    ByteSize::gib(10)
}

/// Crate-visible so the promote-config wiring test can assert against
/// the real default rather than a copy of it: this value is a *network*
/// budget, and the point of that test is that it never reaches a
/// deadline on a local pipe read.
pub(crate) fn default_clone_timeout_secs() -> u64 {
    300
}

fn default_max_bundle_bytes() -> ByteSize {
    ByteSize::mib(64)
}

fn default_nix_cache_url() -> String {
    "https://cache.nixos.org".into()
}

/// Default trusted public keys for the Nix substituter. Matches the
/// `cache.nixos.org-1` key Nix itself ships, so a config that takes the default
/// [`default_nix_cache_url`] can still verify the signed narinfos served from
/// it. The guest wrapper writes this list verbatim into `trusted-public-keys`,
/// which overrides Nix's built-in list — so an empty default would silently
/// reject every signed path from the public cache.
fn default_nix_cache_trusted_public_keys() -> Vec<String> {
    vec!["cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=".into()]
}

fn default_nix_cache_max_metadata_bytes() -> ByteSize {
    ByteSize::mib(1)
}

fn default_nix_cache_max_nar_bytes() -> ByteSize {
    ByteSize::mib(512)
}

/// Default agent-VM working directory. Sits under `$XDG_STATE_HOME/writ/`
/// alongside `agent-vm-sessions`, falling back to `~/.local/state/writ/` when
/// XDG is unset — matching [`default_agent_vm_state_dir`].
pub fn default_vm_http_work_root() -> PathBuf {
    // Treat an empty `XDG_STATE_HOME` as unset (matches
    // `default_agent_vm_state_dir`). Without this filter, an environment that
    // exports `XDG_STATE_HOME=` would yield the relative path `writ/vm-work`
    // and the absolute-path check downstream would refuse the daemon config —
    // even though the `HOME` fallback would have worked.
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME").filter(|dir| !dir.as_os_str().is_empty())
    {
        PathBuf::from(dir).join("writ/vm-work")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
        PathBuf::from(home).join(".local/state/writ/vm-work")
    }
}

fn parse_ipv4_cidr_config(
    field: &'static str,
    raw: &str,
) -> Result<Ipv4Cidr, AgentVmDaemonConfigError> {
    let (addr, prefix) =
        raw.split_once('/')
            .ok_or_else(|| AgentVmDaemonConfigError::InvalidCidr {
                field,
                value: raw.to_string(),
                message: "missing '/'".into(),
            })?;
    let addr = addr
        .parse::<Ipv4Addr>()
        .map_err(|err| AgentVmDaemonConfigError::InvalidCidr {
            field,
            value: raw.to_string(),
            message: err.to_string(),
        })?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|err| AgentVmDaemonConfigError::InvalidCidr {
            field,
            value: raw.to_string(),
            message: err.to_string(),
        })?;
    Ipv4Cidr::new(addr, prefix).map_err(AgentVmDaemonConfigError::from)
}

fn parse_ipv6_cidr_config(
    field: &'static str,
    raw: &str,
) -> Result<Ipv6Cidr, AgentVmDaemonConfigError> {
    let (addr, prefix) =
        raw.split_once('/')
            .ok_or_else(|| AgentVmDaemonConfigError::InvalidCidr {
                field,
                value: raw.to_string(),
                message: "missing '/'".into(),
            })?;
    let addr = addr
        .parse::<Ipv6Addr>()
        .map_err(|err| AgentVmDaemonConfigError::InvalidCidr {
            field,
            value: raw.to_string(),
            message: err.to_string(),
        })?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|err| AgentVmDaemonConfigError::InvalidCidr {
            field,
            value: raw.to_string(),
            message: err.to_string(),
        })?;
    Ipv6Cidr::new(addr, prefix).map_err(AgentVmDaemonConfigError::from)
}

fn default_secret_store_config() -> SecretStoreConfig {
    SecretStoreConfig::File {
        path: default_secret_store_path(),
    }
}

/// Default base directory for the file secret store. Matches the
/// `$XDG_DATA_HOME/writ/` location called out in `docs/design/broker.md`.
pub fn default_secret_store_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(dir).join("writ/secrets")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
        PathBuf::from(home).join(".local/share/writ/secrets")
    }
}

/// Default location for the daemon config file.
pub fn default_config_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(dir).join("writ/config.json")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
        PathBuf::from(home).join(".config/writ/config.json")
    }
}

/// Default location for the SQLite audit database. The DB lives in a dedicated
/// `audit/` directory (not directly under `writ/`) because the broker VM mounts
/// the audit DB's *parent directory* read-write; anything else in that directory
/// would be exposed read-write inside the broker VM. See
/// [`ensure_audit_dir_is_dedicated`].
/// Default root for per-run agent stdout/stderr logs. A sibling of the audit
/// DB's directory rather than a child of the agent-VM work root: the streams
/// outlive the run that produced them and are pointed at by audit rows, so
/// they belong with writ's durable state and not with a subsystem's scratch
/// space.
pub fn default_agent_run_log_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(dir).join("writ/agent-runs")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
        PathBuf::from(home).join(".local/share/writ/agent-runs")
    }
}

pub fn default_audit_db_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(dir).join("writ/audit/audit.db")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
        PathBuf::from(home).join(".local/share/writ/audit/audit.db")
    }
}

#[cfg(test)]
mod tests;
