//! Daemon configuration loaded from a JSON file at startup.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::agent_vm_daemon::{
    AgentVmDaemonRuntimeConfig, AgentVmDaemonRuntimeConfigError, AgentVmLifecycleRuntimeConfig,
    AgentVmLifecycleRuntimeConfigError,
};
use crate::agent_vm_lifecycle::{
    AgentVmLifecycleConfigError, AgentVmResources, AgentVmSessionStateStore, AgentVmStateDirError,
    AgentVmToolPaths, ContainerImage, Ipv6IsolationMode, default_agent_vm_state_dir,
};
use crate::core::{AgentNetworkPool, AgentVmConfigError, BrokerPortRange, Ipv4Cidr, Ipv6Cidr};
use crate::flake_lock::{FlakeProvisionBounds, FlakeProvisionBoundsError};
use crate::flake_provision_from_mirror::MirrorFlakeProvisionConfig;
use crate::github::GitHubAppRegistryConfig;
use crate::nix_cache::{NixTrustedPublicKeys, NixTrustedPublicKeysError};
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
    /// `$XDG_DATA_HOME/writ/audit.db` (see [`default_audit_db_path`]).
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
    pub fn validate(&self) -> Result<(), UiHttpConfigError> {
        if !self.bind.ip().is_loopback() {
            return Err(UiHttpConfigError::NonLoopbackBind(self.bind));
        }
        if self.bind.port() == 0 {
            return Err(UiHttpConfigError::EphemeralPortBind(self.bind));
        }
        Ok(())
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
    pub image: String,
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
    pub max_bundle_bytes: u64,
    #[serde(default = "default_nix_cache_url")]
    pub nix_cache_url: String,
    #[serde(default = "default_nix_cache_trusted_public_keys")]
    pub nix_cache_trusted_public_keys: Vec<String>,
    #[serde(default = "default_nix_cache_max_metadata_bytes")]
    pub nix_cache_max_metadata_bytes: u64,
    #[serde(default = "default_nix_cache_max_nar_bytes")]
    pub nix_cache_max_nar_bytes: u64,
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
    pub flake_mirror_cache_max_bytes: u64,
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
    pub flake_provision_max_total_bytes: u64,
    /// Timeout (seconds) for the `nix flake archive` step of one provision
    /// request.
    #[serde(default = "default_flake_provision_timeout_secs")]
    pub flake_provision_timeout_secs: u64,
    #[serde(default)]
    pub claude_proxy: Option<AgentVmHttpClaudeProxyConfig>,
    #[serde(default)]
    pub openai_proxy: Option<AgentVmHttpOpenAiProxyConfig>,
    #[serde(default)]
    pub agent_run_log_root: Option<PathBuf>,
    #[serde(default)]
    pub git_push_staging_root: Option<PathBuf>,
    #[serde(default = "default_git_push_max_body_bytes")]
    pub git_push_max_body_bytes: usize,
    #[serde(default = "default_git_push_max_metadata_bytes")]
    pub git_push_max_metadata_bytes: usize,
    #[serde(default = "default_git_push_max_bundle_bytes")]
    pub git_push_max_bundle_bytes: usize,
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
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVmHttpOpenAiProxyConfig {
    pub upstream_base_url: String,
    pub auth_secret: SecretKey,
    pub auth_kind: VmHttpOpenAiProxyAuthKind,
    pub timeout_secs: u64,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
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
    #[error("agent run log root path must not be empty")]
    EmptyAgentRunLogRoot,
    #[error("agent run log root path must be absolute: {0:?}")]
    RelativeAgentRunLogRoot(PathBuf),
    #[error("agent run log root {path:?} could not be created: {source}")]
    AgentRunLogRootCreate {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("agent run log root {path:?} is not writable: {source}")]
    AgentRunLogRootProbe {
        path: PathBuf,
        source: std::io::Error,
    },
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
    pub fn to_runtime_config(
        &self,
    ) -> Result<AgentVmDaemonRuntimeConfig, AgentVmDaemonConfigError> {
        Ok(AgentVmDaemonRuntimeConfig::new(
            self.lifecycle.to_runtime_config()?,
            self.vm_http.to_runtime_config()?,
        )?)
    }
}

impl AgentVmLifecycleConfig {
    pub fn to_runtime_config(
        &self,
    ) -> Result<AgentVmLifecycleRuntimeConfig, AgentVmDaemonConfigError> {
        let ipv4_pool = parse_ipv4_cidr_config("ipv4_pool", &self.ipv4_pool)?;
        let ipv6_pool = parse_ipv6_cidr_config("ipv6_pool", &self.ipv6_pool)?;
        let pool = AgentNetworkPool::new(ipv4_pool, ipv6_pool)?;
        let state_dir = match &self.state_dir {
            Some(path) => path.clone(),
            None => default_agent_vm_state_dir()?,
        };
        Ok(AgentVmLifecycleRuntimeConfig::new(
            pool,
            self.subnet_index_min,
            self.subnet_index_max,
            AgentVmSessionStateStore::new(state_dir),
            self.ipv6_mode,
            ContainerImage::new(self.image.clone())?,
            AgentVmResources::new(self.cpus, self.memory_mib)?,
            AgentVmToolPaths::new(
                self.container.clone(),
                self.pf_helper.clone(),
                self.sudo.clone(),
            ),
        )?)
    }
}

impl AgentVmHttpConfig {
    pub fn to_runtime_config(&self) -> Result<VmHttpRuntimeConfig, AgentVmHttpConfigError> {
        let broker_port_range = BrokerPortRange::new(self.broker_port_min, self.broker_port_max)?;
        let token_env = GitSecretEnvVar::new(self.token_env.clone())?;
        let credential = GitCredentialBoundary::new(self.askpass_program.clone(), token_env)?;
        let clone_base_url = GitCloneBaseUrl::parse(&self.git_clone_base_url)?;
        let git_clone = VmHttpGitCloneConfig::new_with_clone_base_url(
            self.git_program.clone(),
            clone_base_url,
            credential,
            self.work_root.clone(),
            Duration::from_secs(self.clone_timeout_secs),
            self.max_bundle_bytes,
        )?;
        // When configured, retain each clone's bare mirror for later
        // flake-input provisioning; the cache creates its (owner-only) directory
        // on first insert. `None` keeps the discard-after-bundle behaviour. The
        // same cache backs the flake-provision endpoint below, so clone +
        // provision share one fetch.
        let mirror_cache = self
            .flake_mirror_cache_dir
            .clone()
            .map(validate_flake_mirror_cache_dir)
            .transpose()?
            .map(MirrorCache::new);
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
        // `prepare_git_work_root` refuses to clone into a work root whose mode
        // has group/world bits set, but `validate_*_root` below creates the
        // staging/log subdirs with `create_dir_all`, which propagates the
        // process umask to the freshly-created `work_root` parent (typically
        // 0755). Ensure work_root itself is 0700 before that runs so the
        // out-of-the-box defaults — where the user never names `work_root`
        // explicitly — survive the first clone request.
        ensure_vm_http_work_root_private(&self.work_root)?;
        let trusted_public_keys =
            NixTrustedPublicKeys::from_strings(self.nix_cache_trusted_public_keys.clone())?;
        // The broker-local flake-input archive lives under work_root by default,
        // alongside the agent-run and git-push roots. Wiring it as the nix-cache
        // local cache makes the endpoint serve archived inputs local-first; an
        // empty directory (nothing provisioned yet) is byte-identical to
        // upstream-only serving.
        let flake_input_cache_dir = match &self.flake_input_cache_dir {
            Some(path) => path.clone(),
            None => self.work_root.join("flake-input-cache"),
        };
        let flake_input_cache_dir = validate_flake_input_cache_dir(flake_input_cache_dir)?;
        // Flake-input provisioning re-derives a checkout from a retained mirror,
        // so it is enabled exactly when the mirror cache is. It archives the
        // committed, locked inputs into the very same shared CA cache the
        // nix-cache endpoint serves local-first, so the guest realises them
        // through the substituter it already trusts.
        let flake_provision = match mirror_cache {
            Some(mirror_cache) => {
                let scratch_root = match &self.flake_materialize_scratch_dir {
                    Some(path) => path.clone(),
                    None => self.work_root.join("flake-materialize"),
                };
                let scratch_root = validate_flake_materialize_scratch_dir(scratch_root)?;
                let bounds = FlakeProvisionBounds::new(
                    self.flake_provision_max_input_count,
                    self.flake_provision_max_total_bytes,
                    Duration::from_secs(self.flake_provision_timeout_secs),
                )?;
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
            None => None,
        };
        // Local archives served local-first, in order: a durable, operator-
        // managed pre-warmed closure cache (when configured) ahead of the
        // auto-provisioned flake-input cache. The pre-warm dir is read-only to
        // the broker — the egress builder writes it out of band — so it is not
        // created here; an absent/empty dir simply serves nothing. Trust for its
        // signed paths rides the existing `nix_cache_trusted_public_keys`
        // (the same list the guest verifies against), so no separate key.
        let mut local_cache_dirs = Vec::new();
        if let Some(prewarm) = &self.nix_prewarm_cache_dir {
            local_cache_dirs.push(validate_nix_prewarm_cache_dir(prewarm.clone())?);
        }
        local_cache_dirs.push(flake_input_cache_dir);
        let nix_cache = VmHttpNixCacheConfig::new_with_trusted_public_keys(
            &self.nix_cache_url,
            self.nix_cache_max_metadata_bytes,
            self.nix_cache_max_nar_bytes,
            trusted_public_keys,
        )?
        .with_local_cache_dirs(local_cache_dirs);
        let claude_proxy = self
            .claude_proxy
            .as_ref()
            .map(AgentVmHttpClaudeProxyConfig::to_runtime_config)
            .transpose()?;
        let openai_proxy = self
            .openai_proxy
            .as_ref()
            .map(AgentVmHttpOpenAiProxyConfig::to_runtime_config)
            .transpose()?;
        let agent_run_log_root = match &self.agent_run_log_root {
            Some(path) => path.clone(),
            None => self.work_root.join("agent-runs"),
        };
        let agent_run_log_root = validate_agent_run_log_root(agent_run_log_root)?;
        let git_push_staging_root = match &self.git_push_staging_root {
            Some(path) => path.clone(),
            None => self.work_root.join("git-push-staging"),
        };
        let git_push_staging_root = validate_git_push_staging_root(git_push_staging_root)?;
        let git_push_body_limits = VmGitPushBodyLimits::new(
            self.git_push_max_body_bytes,
            self.git_push_max_metadata_bytes,
            self.git_push_max_bundle_bytes,
        )?;
        Ok(VmHttpRuntimeConfig::new_with_proxies(
            self.bind_addr,
            broker_port_range,
            git_clone,
            nix_cache,
            claude_proxy,
            openai_proxy,
            agent_run_log_root,
            git_push_staging_root,
            git_push_body_limits,
        )
        .with_flake_provision(flake_provision))
    }
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

fn validate_agent_run_log_root(path: PathBuf) -> Result<PathBuf, AgentVmHttpConfigError> {
    if path.as_os_str().is_empty() {
        return Err(AgentVmHttpConfigError::EmptyAgentRunLogRoot);
    }
    if !path.is_absolute() {
        return Err(AgentVmHttpConfigError::RelativeAgentRunLogRoot(path));
    }
    std::fs::create_dir_all(&path).map_err(|source| {
        AgentVmHttpConfigError::AgentRunLogRootCreate {
            path: path.clone(),
            source,
        }
    })?;
    let probe = path.join(format!(
        ".writ-agent-run-log-probe-{}-{}",
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
        })
        .map_err(|source| AgentVmHttpConfigError::AgentRunLogRootProbe {
            path: path.clone(),
            source,
        })?;
    std::fs::remove_file(&probe).map_err(|source| {
        AgentVmHttpConfigError::AgentRunLogRootProbe {
            path: path.clone(),
            source,
        }
    })?;
    Ok(path)
}

fn validate_git_push_staging_root(path: PathBuf) -> Result<PathBuf, AgentVmHttpConfigError> {
    if path.as_os_str().is_empty() {
        return Err(AgentVmHttpConfigError::EmptyGitPushStagingRoot);
    }
    if !path.is_absolute() {
        return Err(AgentVmHttpConfigError::RelativeGitPushStagingRoot(path));
    }
    std::fs::create_dir_all(&path).map_err(|source| {
        AgentVmHttpConfigError::GitPushStagingRootCreate {
            path: path.clone(),
            source,
        }
    })?;
    let probe = path.join(format!(
        ".writ-git-push-staging-probe-{}-{}",
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
        })
        .map_err(|source| AgentVmHttpConfigError::GitPushStagingRootProbe {
            path: path.clone(),
            source,
        })?;
    std::fs::remove_file(&probe).map_err(|source| {
        AgentVmHttpConfigError::GitPushStagingRootProbe {
            path: path.clone(),
            source,
        }
    })?;
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

fn validate_flake_input_cache_dir(path: PathBuf) -> Result<PathBuf, AgentVmHttpConfigError> {
    if path.as_os_str().is_empty() {
        return Err(AgentVmHttpConfigError::EmptyFlakeInputCacheDir);
    }
    if !path.is_absolute() {
        return Err(AgentVmHttpConfigError::RelativeFlakeInputCacheDir(path));
    }
    std::fs::create_dir_all(&path).map_err(|source| {
        AgentVmHttpConfigError::FlakeInputCacheDirCreate {
            path: path.clone(),
            source,
        }
    })?;
    let probe = path.join(format!(
        ".writ-flake-input-cache-probe-{}-{}",
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
        })
        .map_err(|source| AgentVmHttpConfigError::FlakeInputCacheDirProbe {
            path: path.clone(),
            source,
        })?;
    std::fs::remove_file(&probe).map_err(|source| {
        AgentVmHttpConfigError::FlakeInputCacheDirProbe {
            path: path.clone(),
            source,
        }
    })?;
    Ok(path)
}

fn default_git_push_max_body_bytes() -> usize {
    // 65 MiB: headroom over the bundle limit for metadata + framing overhead.
    65 * 1024 * 1024
}

fn default_git_push_max_metadata_bytes() -> usize {
    16 * 1024
}

fn default_git_push_max_bundle_bytes() -> usize {
    64 * 1024 * 1024
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
fn default_flake_provision_max_total_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}
fn default_flake_provision_timeout_secs() -> u64 {
    600
}
fn default_flake_mirror_cache_max_entries() -> usize {
    64
}
fn default_flake_mirror_cache_max_bytes() -> u64 {
    10 * 1024 * 1024 * 1024
}

fn default_clone_timeout_secs() -> u64 {
    300
}

fn default_max_bundle_bytes() -> u64 {
    64 * 1024 * 1024
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

fn default_nix_cache_max_metadata_bytes() -> u64 {
    1024 * 1024
}

fn default_nix_cache_max_nar_bytes() -> u64 {
    512 * 1024 * 1024
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

/// Default location for the SQLite audit database.
pub fn default_audit_db_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(dir).join("writ/audit.db")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
        PathBuf::from(home).join(".local/share/writ/audit.db")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::AgentKind;
    use crate::github::GitHubAppRegistryConfigError;

    const TEST_NIX_CACHE_PUBLIC_KEY: &str =
        "cache.example-1:IsGkyTbr2sed7tWowgiPcI0ZHhBAHoGQ7TyYRweyzwE=";

    #[test]
    fn parses_minimal_config() {
        // No `secret_store` key — the file backend at
        // `default_secret_store_path()` is the documented default.
        let json = r#"{
            "github_apps": {
                "claude": {
                    "app_id": 42,
                    "installation_id": 999,
                    "installation_owner": "smaug123",
                    "private_key_secret": "gh-app-pk"
                }
            },
            "policy": {
                "default_ttl": 3600,
                "writable_repos": []
            }
        }"#;
        let c: DaemonConfig = serde_json::from_str(json).unwrap();
        let claude = &c.github_apps.agent_apps()[&AgentKind::Claude];
        assert_eq!(claude.app_id, 42);
        assert_eq!(claude.api_base, "https://api.github.com");
        assert_eq!(c.policy.default_ttl.as_i64(), 3600);
        assert!(c.agent_vm.is_none());
        assert!(c.socket_path.is_none());
        assert!(c.ui_http.is_none());
        assert!(c.run_agent.is_none());
        assert!(
            matches!(&c.secret_store, SecretStoreConfig::File { path } if *path == default_secret_store_path())
        );
    }

    #[test]
    fn parses_ui_http_config() {
        let json = r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "pk"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "ui_http": { "bind": "127.0.0.1:7378" }
        }"#;
        let c: DaemonConfig = serde_json::from_str(json).unwrap();
        let ui = c.ui_http.as_ref().expect("ui_http parsed");
        assert_eq!(ui.bind.to_string(), "127.0.0.1:7378");
        assert!(ui.bearer_path.is_none());
        assert_eq!(ui.bearer_path_or_default(), default_ui_http_bearer_path());
        ui.validate().expect("loopback bind validates");
    }

    #[test]
    fn parses_ui_http_config_with_bearer_path() {
        let json = r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "pk"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "ui_http": {
                "bind": "127.0.0.1:7378",
                "bearer_path": "/tmp/writ/ui-bearer"
            }
        }"#;
        let c: DaemonConfig = serde_json::from_str(json).unwrap();
        let ui = c.ui_http.as_ref().expect("ui_http parsed");
        assert_eq!(
            ui.bearer_path_or_default(),
            std::path::PathBuf::from("/tmp/writ/ui-bearer")
        );
    }

    #[test]
    fn ui_http_validate_rejects_non_loopback_bind() {
        let cfg = UiHttpConfig {
            bind: "0.0.0.0:7378".parse().unwrap(),
            bearer_path: None,
        };
        let err = cfg.validate().expect_err("non-loopback rejected");
        assert!(matches!(err, UiHttpConfigError::NonLoopbackBind(_)));
    }

    #[test]
    fn ui_http_validate_rejects_ephemeral_port() {
        let cfg = UiHttpConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            bearer_path: None,
        };
        let err = cfg.validate().expect_err("port 0 rejected");
        assert!(
            matches!(err, UiHttpConfigError::EphemeralPortBind(addr) if addr.port() == 0),
            "got: {err:?}"
        );
    }

    #[test]
    fn ui_http_validate_accepts_ipv6_loopback() {
        let cfg = UiHttpConfig {
            bind: "[::1]:7378".parse().unwrap(),
            bearer_path: None,
        };
        cfg.validate().expect("::1 is loopback");
    }

    #[test]
    fn ui_http_config_rejects_unknown_fields() {
        let json = r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "pk"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "ui_http": {
                "bind": "127.0.0.1:7378",
                "unknown_key": true
            }
        }"#;
        let err = serde_json::from_str::<DaemonConfig>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown_key"),
            "expected unknown-field error mentioning unknown_key, got: {err}"
        );
    }

    #[test]
    fn parses_config_with_overrides() {
        let json = r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "pk",
                    "api_base": "https://github.example.com/api/v3"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": ["o/n"] },
            "secret_store": { "type": "keyring" },
            "socket_path": "/tmp/test.sock",
            "audit_db": "/tmp/audit.db"
        }"#;
        let c: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            c.github_apps.agent_apps()[&AgentKind::Claude].api_base,
            "https://github.example.com/api/v3"
        );
        assert_eq!(
            c.socket_path.as_deref(),
            Some(std::path::Path::new("/tmp/test.sock"))
        );
        assert!(
            matches!(c.secret_store, SecretStoreConfig::Keyring { service } if service == "writ")
        );
    }

    #[test]
    fn parses_agent_keyed_github_apps() {
        let json = r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "claude-pk"
                },
                "codex": {
                    "app_id": 3,
                    "installation_id": 4,
                    "installation_owner": "o",
                    "private_key_secret": "codex-pk"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] }
        }"#;
        let c: DaemonConfig = serde_json::from_str(json).unwrap();

        assert_eq!(
            c.github_apps.agent_apps()[&AgentKind::Claude]
                .private_key_secret
                .as_str(),
            "claude-pk"
        );
        assert_eq!(
            c.github_apps.agent_apps()[&AgentKind::Codex]
                .private_key_secret
                .as_str(),
            "codex-pk"
        );
    }

    #[test]
    fn rejects_empty_github_apps_map() {
        let json = r#"{
            "github_apps": {},
            "policy": { "default_ttl": 600, "writable_repos": [] }
        }"#;

        let err = serde_json::from_str::<DaemonConfig>(json).unwrap_err();
        assert!(
            err.to_string()
                .contains(&GitHubAppRegistryConfigError::Empty.to_string()),
            "expected Empty error, got: {err}"
        );
    }

    #[test]
    fn rejects_legacy_github_field() {
        let json = r#"{
            "github": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
            },
            "github_apps": {
                "claude": {
                    "app_id": 3,
                    "installation_id": 4,
                    "installation_owner": "o",
                    "private_key_secret": "claude-pk"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] }
        }"#;

        let err = serde_json::from_str::<DaemonConfig>(json).unwrap_err();
        assert!(
            err.to_string().contains("github"),
            "expected unknown-field error mentioning `github`, got: {err}"
        );
    }

    #[test]
    fn parses_agent_vm_config_and_converts_to_runtime_config() {
        let work_root = unique_config_test_path("work-root");
        let agent_run_log_root = unique_config_test_path("agent-runs");
        let git_push_staging_root = unique_config_test_path("git-push-staging");
        let mut json: serde_json::Value = serde_json::from_str(
            r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "pk"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "agent_vm": {
                "lifecycle": {
                    "ipv4_pool": "192.168.0.0/16",
                    "ipv6_pool": "fd83:b6f2:e57::/48",
                    "subnet_index_min": 252,
                    "subnet_index_max": 253,
                    "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                    "state_dir": "/var/folders/writ/agent-vm-state",
                    "ipv6_mode": "ipv4_only_no_guest_ipv6",
                    "image": "alpine:latest",
                    "cpus": 1,
                    "memory_mib": 512
                },
                "vm_http": {
                    "bind_addr": "0.0.0.0",
                    "broker_port_min": 18080,
                    "broker_port_max": 18081,
                    "git_program": "/usr/bin/git",
                    "git_clone_base_url": "https://github.com",
                    "askpass_program": "/usr/local/libexec/writ-git-askpass",
                    "work_root": "/var/folders/writ/git-work",
                    "clone_timeout_secs": 30,
                    "max_bundle_bytes": 1048576,
                    "nix_cache_url": "https://cache.nixos.org",
                    "nix_cache_trusted_public_keys": [
                        "cache.example-1:IsGkyTbr2sed7tWowgiPcI0ZHhBAHoGQ7TyYRweyzwE="
                    ],
                    "nix_cache_max_metadata_bytes": 1048576,
                    "nix_cache_max_nar_bytes": 67108864,
                    "claude_proxy": {
                        "upstream_base_url": "https://api.anthropic.com",
                        "auth_secret": "anthropic-api-key",
                        "auth_kind": "x_api_key",
                        "anthropic_version": "2023-06-01",
                        "timeout_secs": 60,
                        "max_request_bytes": 2097152,
                        "max_response_bytes": 8388608
                    },
                    "agent_run_log_root": "/var/folders/writ/agent-runs"
                }
            }
        }"#,
        )
        .unwrap();
        json["agent_vm"]["vm_http"]["work_root"] =
            serde_json::Value::String(work_root.to_string_lossy().into_owned());
        json["agent_vm"]["vm_http"]["agent_run_log_root"] =
            serde_json::Value::String(agent_run_log_root.to_string_lossy().into_owned());
        json["agent_vm"]["vm_http"]["git_push_staging_root"] =
            serde_json::Value::String(git_push_staging_root.to_string_lossy().into_owned());
        let c: DaemonConfig = serde_json::from_value(json).unwrap();
        let agent_vm = c.agent_vm.unwrap();

        let runtime = agent_vm.to_runtime_config().unwrap();

        assert_eq!(runtime.vm_http().bind_addr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(runtime.vm_http().broker_port_range().min().get(), 18080);
        assert_eq!(runtime.vm_http().broker_port_range().max().get(), 18081);
        assert_eq!(runtime.vm_http().git_clone().work_root(), work_root);
        assert_eq!(
            runtime.vm_http().nix_cache().upstream_base_url().as_str(),
            "https://cache.nixos.org/"
        );
        assert_eq!(
            runtime.vm_http().nix_cache().max_metadata_bytes(),
            1_048_576
        );
        assert_eq!(runtime.vm_http().nix_cache().max_nar_bytes(), 67_108_864);
        // Omitted from JSON, so the local flake-input cache defaults under
        // work_root and is the sole local cache dir wired into the nix-cache
        // config (no pre-warm dir configured).
        assert_eq!(
            runtime.vm_http().nix_cache().local_cache_dirs(),
            [work_root.join("flake-input-cache")],
        );
        assert_eq!(
            runtime
                .vm_http()
                .nix_cache()
                .trusted_public_keys()
                .nix_conf_value(),
            TEST_NIX_CACHE_PUBLIC_KEY
        );
        let claude_proxy = runtime.vm_http().claude_proxy().unwrap();
        assert_eq!(
            claude_proxy.upstream_base_url().as_str(),
            "https://api.anthropic.com/"
        );
        assert_eq!(claude_proxy.auth_secret().as_str(), "anthropic-api-key");
        assert_eq!(claude_proxy.auth_kind(), VmHttpClaudeProxyAuthKind::XApiKey);
        assert_eq!(
            claude_proxy.anthropic_version().to_str().unwrap(),
            "2023-06-01"
        );
        assert_eq!(claude_proxy.max_request_bytes(), 2_097_152);
        assert_eq!(claude_proxy.max_response_bytes(), 8_388_608);
        assert_eq!(runtime.vm_http().agent_run_log_root(), agent_run_log_root);
        assert_eq!(
            runtime.vm_http().git_push_staging_root(),
            git_push_staging_root
        );
        assert_eq!(
            runtime.vm_http().git_push_body_limits(),
            VmGitPushBodyLimits::new(
                default_git_push_max_body_bytes(),
                default_git_push_max_metadata_bytes(),
                default_git_push_max_bundle_bytes(),
            )
            .unwrap()
        );
        assert_eq!(runtime.lifecycle().subnet_index_min(), 252);
        assert_eq!(runtime.lifecycle().subnet_index_max(), 253);
    }

    #[test]
    fn parses_agent_vm_config_with_oauth_claude_proxy_auth_kind() {
        let work_root = unique_config_test_path("work-root");
        let agent_run_log_root = unique_config_test_path("agent-runs");
        let mut json: serde_json::Value = serde_json::from_str(
            r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "pk"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "agent_vm": {
                "lifecycle": {
                    "ipv4_pool": "192.168.0.0/16",
                    "ipv6_pool": "fd83:b6f2:e57::/48",
                    "subnet_index_min": 252,
                    "subnet_index_max": 253,
                    "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                    "state_dir": "/var/folders/writ/agent-vm-state",
                    "ipv6_mode": "ipv4_only_no_guest_ipv6",
                    "image": "alpine:latest",
                    "cpus": 1,
                    "memory_mib": 512
                },
                "vm_http": {
                    "bind_addr": "0.0.0.0",
                    "broker_port_min": 18080,
                    "broker_port_max": 18081,
                    "git_program": "/usr/bin/git",
                    "git_clone_base_url": "https://github.com",
                    "askpass_program": "/usr/local/libexec/writ-git-askpass",
                    "work_root": "/var/folders/writ/git-work",
                    "clone_timeout_secs": 30,
                    "max_bundle_bytes": 1048576,
                    "nix_cache_url": "https://cache.nixos.org",
                    "nix_cache_trusted_public_keys": [],
                    "nix_cache_max_metadata_bytes": 1048576,
                    "nix_cache_max_nar_bytes": 67108864,
                    "claude_proxy": {
                        "upstream_base_url": "https://api.anthropic.com",
                        "auth_secret": "anthropic-oauth-token",
                        "auth_kind": "oauth",
                        "anthropic_version": "2023-06-01",
                        "timeout_secs": 60,
                        "max_request_bytes": 2097152,
                        "max_response_bytes": 8388608
                    },
                    "agent_run_log_root": "/var/folders/writ/agent-runs"
                }
            }
        }"#,
        )
        .unwrap();
        json["agent_vm"]["vm_http"]["work_root"] =
            serde_json::Value::String(work_root.to_string_lossy().into_owned());
        json["agent_vm"]["vm_http"]["agent_run_log_root"] =
            serde_json::Value::String(agent_run_log_root.to_string_lossy().into_owned());
        let c: DaemonConfig = serde_json::from_value(json).unwrap();
        let agent_vm = c.agent_vm.unwrap();

        let runtime = agent_vm.to_runtime_config().unwrap();
        let claude_proxy = runtime.vm_http().claude_proxy().unwrap();
        assert_eq!(claude_proxy.auth_secret().as_str(), "anthropic-oauth-token");
        assert_eq!(claude_proxy.auth_kind(), VmHttpClaudeProxyAuthKind::OAuth);
    }

    fn unique_config_test_path(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "writ-config-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn valid_agent_vm_http_config() -> AgentVmHttpConfig {
        let work_root = unique_config_test_path("work-root");
        AgentVmHttpConfig {
            bind_addr: Ipv4Addr::UNSPECIFIED,
            broker_port_min: 18080,
            broker_port_max: 18081,
            git_program: PathBuf::from("/usr/bin/git"),
            nix_program: PathBuf::from("/usr/bin/nix"),
            git_clone_base_url: DEFAULT_GIT_CLONE_BASE_URL.into(),
            askpass_program: PathBuf::from("/usr/local/libexec/writ-git-askpass"),
            token_env: "WRIT_GIT_TOKEN".into(),
            work_root,
            clone_timeout_secs: 30,
            max_bundle_bytes: 1_048_576,
            nix_cache_url: "https://cache.nixos.org".into(),
            nix_cache_trusted_public_keys: Vec::new(),
            nix_cache_max_metadata_bytes: 1_048_576,
            nix_cache_max_nar_bytes: 67_108_864,
            flake_input_cache_dir: None,
            nix_prewarm_cache_dir: None,
            flake_mirror_cache_dir: None,
            flake_mirror_cache_max_entries: default_flake_mirror_cache_max_entries(),
            flake_mirror_cache_max_bytes: default_flake_mirror_cache_max_bytes(),
            flake_materialize_scratch_dir: None,
            flake_provision_max_input_count: default_flake_provision_max_input_count(),
            flake_provision_max_total_bytes: default_flake_provision_max_total_bytes(),
            flake_provision_timeout_secs: default_flake_provision_timeout_secs(),
            claude_proxy: None,
            openai_proxy: None,
            agent_run_log_root: None,
            git_push_staging_root: None,
            git_push_max_body_bytes: default_git_push_max_body_bytes(),
            git_push_max_metadata_bytes: default_git_push_max_metadata_bytes(),
            git_push_max_bundle_bytes: default_git_push_max_bundle_bytes(),
        }
    }

    fn valid_agent_vm_lifecycle_config() -> AgentVmLifecycleConfig {
        AgentVmLifecycleConfig {
            ipv4_pool: "192.168.0.0/16".into(),
            ipv6_pool: "fd83:b6f2:e57::/48".into(),
            subnet_index_min: 252,
            subnet_index_max: 253,
            container: PathBuf::from("container"),
            sudo: PathBuf::from("sudo"),
            pf_helper: PathBuf::from("/usr/local/libexec/writ-agent-vm-pf-helper"),
            state_dir: Some(PathBuf::from("/var/folders/writ/agent-vm-state")),
            ipv6_mode: Ipv6IsolationMode::Ipv4OnlyNoGuestIpv6,
            image: "alpine:latest".into(),
            cpus: 1,
            memory_mib: 512,
        }
    }

    #[test]
    fn agent_vm_config_rejects_non_wildcard_vm_http_bind_address() {
        let mut vm_http = valid_agent_vm_http_config();
        vm_http.bind_addr = Ipv4Addr::LOCALHOST;
        let c = AgentVmDaemonConfig {
            lifecycle: valid_agent_vm_lifecycle_config(),
            vm_http,
        };

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmDaemonConfigError::Runtime(
                AgentVmDaemonRuntimeConfigError::NonWildcardVmHttpBindAddr(addr)
            )) if addr == Ipv4Addr::LOCALHOST
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_privileged_broker_port() {
        let mut c = valid_agent_vm_http_config();
        c.broker_port_min = 80;

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::BrokerPortRange(
                AgentVmConfigError::PrivilegedBrokerPort(80)
            ))
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_empty_broker_port_range() {
        let mut c = valid_agent_vm_http_config();
        c.broker_port_min = 18081;
        c.broker_port_max = 18080;

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::BrokerPortRange(
                AgentVmConfigError::EmptyBrokerPortRange {
                    min: 18081,
                    max: 18080
                }
            ))
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_invalid_token_env() {
        let mut c = valid_agent_vm_http_config();
        c.token_env = "bad-name".into();

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::TokenEnv(
                GitSecretEnvVarError::InvalidByte(raw)
            )) if raw == "bad-name"
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_empty_git_program() {
        let mut c = valid_agent_vm_http_config();
        c.git_program = PathBuf::new();

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::GitClone(
                GitCloneBundlePlanError::EmptyPath {
                    field: "git_program"
                }
            ))
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_unsafe_git_clone_base_url() {
        let mut c = valid_agent_vm_http_config();
        c.git_clone_base_url = "ssh://github.com".into();

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::GitClone(
                GitCloneBundlePlanError::UnsupportedGitCloneBaseUrlScheme { scheme, .. }
            )) if scheme == "ssh"
        ));

        c.git_clone_base_url = "https://user:token@github.com".into();
        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::GitClone(
                GitCloneBundlePlanError::GitCloneBaseUrlHasCredentials(_)
            ))
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_relative_askpass_program() {
        let mut c = valid_agent_vm_http_config();
        c.askpass_program = PathBuf::from("askpass");

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::GitClone(
                GitCloneBundlePlanError::RelativePath {
                    field: "askpass_program",
                    path
                }
            )) if path.as_os_str() == "askpass"
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_relative_work_root() {
        let mut c = valid_agent_vm_http_config();
        c.work_root = PathBuf::from("relative");

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::GitClone(
                GitCloneBundlePlanError::RelativePath {
                    field: "work_root",
                    path
                }
            )) if path.as_os_str() == "relative"
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_zero_clone_timeout() {
        let mut c = valid_agent_vm_http_config();
        c.clone_timeout_secs = 0;

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::GitClone(
                GitCloneBundlePlanError::ZeroTimeout
            ))
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_zero_max_bundle_bytes() {
        let mut c = valid_agent_vm_http_config();
        c.max_bundle_bytes = 0;

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::GitClone(
                GitCloneBundlePlanError::ZeroMaxBundleBytes
            ))
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_invalid_nix_cache_url() {
        let mut c = valid_agent_vm_http_config();
        c.nix_cache_url = "file:///nix/cache".into();

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::NixCache(
                VmHttpNixCacheConfigError::UnsupportedUpstreamScheme { .. }
            ))
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_zero_nix_cache_metadata_limit() {
        let mut c = valid_agent_vm_http_config();
        c.nix_cache_max_metadata_bytes = 0;

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::NixCache(
                VmHttpNixCacheConfigError::EmptyMaxMetadataBytes
            ))
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_zero_nix_cache_nar_limit() {
        let mut c = valid_agent_vm_http_config();
        c.nix_cache_max_nar_bytes = 0;

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::NixCache(
                VmHttpNixCacheConfigError::EmptyMaxNarBytes
            ))
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_invalid_nix_cache_trusted_public_key() {
        let mut c = valid_agent_vm_http_config();
        c.nix_cache_trusted_public_keys = vec![format!(
            "cache key:{}",
            TEST_NIX_CACHE_PUBLIC_KEY.split_once(':').unwrap().1
        )];

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::NixTrustedPublicKeys(err))
                if err.index() == 0 && err.raw().starts_with("cache key:")
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_invalid_claude_proxy_url() {
        let mut c = valid_agent_vm_http_config();
        c.claude_proxy = Some(AgentVmHttpClaudeProxyConfig {
            upstream_base_url: "file:///api".into(),
            auth_secret: SecretKey::new("anthropic-api-key").unwrap(),
            auth_kind: VmHttpClaudeProxyAuthKind::XApiKey,
            anthropic_version: DEFAULT_CLAUDE_ANTHROPIC_VERSION.into(),
            timeout_secs: 60,
            max_request_bytes: 1_048_576,
            max_response_bytes: 8_388_608,
        });

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::ClaudeProxy(
                VmHttpClaudeProxyConfigError::UnsupportedUpstreamScheme { .. }
            ))
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_zero_claude_proxy_request_limit() {
        let mut c = valid_agent_vm_http_config();
        c.claude_proxy = Some(AgentVmHttpClaudeProxyConfig {
            upstream_base_url: "https://api.anthropic.com".into(),
            auth_secret: SecretKey::new("anthropic-api-key").unwrap(),
            auth_kind: VmHttpClaudeProxyAuthKind::XApiKey,
            anthropic_version: DEFAULT_CLAUDE_ANTHROPIC_VERSION.into(),
            timeout_secs: 60,
            max_request_bytes: 0,
            max_response_bytes: 8_388_608,
        });

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::ClaudeProxy(
                VmHttpClaudeProxyConfigError::EmptyMaxRequestBytes
            ))
        ));
    }

    /// Every field that has a `serde(default = ...)` should produce its
    /// documented value when omitted from the JSON. The minimal config below
    /// supplies only the three fields without defaults (`broker_port_*`,
    /// `askpass_program`); everything else must come from the default fns.
    #[test]
    fn agent_vm_http_config_applies_defaults_for_omitted_fields() {
        let json = r#"{
            "broker_port_min": 18080,
            "broker_port_max": 18081,
            "askpass_program": "/usr/local/libexec/writ-git-askpass"
        }"#;
        let c: AgentVmHttpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(c.bind_addr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(c.git_program, PathBuf::from("git"));
        assert_eq!(c.git_clone_base_url, DEFAULT_GIT_CLONE_BASE_URL);
        assert_eq!(c.token_env, "WRIT_GIT_TOKEN");
        assert_eq!(c.work_root, default_vm_http_work_root());
        assert_eq!(c.clone_timeout_secs, 300);
        assert_eq!(c.max_bundle_bytes, 64 * 1024 * 1024);
        assert_eq!(c.nix_cache_url, "https://cache.nixos.org");
        assert_eq!(
            c.nix_cache_trusted_public_keys,
            vec!["cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=".to_string()]
        );
        assert_eq!(c.nix_cache_max_metadata_bytes, 1024 * 1024);
        assert_eq!(c.nix_cache_max_nar_bytes, 512 * 1024 * 1024);
        assert!(c.claude_proxy.is_none());
        assert!(c.openai_proxy.is_none());
        assert!(c.agent_run_log_root.is_none());
        assert!(c.git_push_staging_root.is_none());
        assert!(c.flake_input_cache_dir.is_none());
        assert!(c.flake_mirror_cache_dir.is_none());
    }

    #[test]
    fn agent_vm_http_config_rejects_relative_agent_run_log_root() {
        let mut c = valid_agent_vm_http_config();
        c.agent_run_log_root = Some(PathBuf::from("agent-runs"));

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::RelativeAgentRunLogRoot(path))
                if path.as_os_str() == "agent-runs"
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_unwritable_agent_run_log_root() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("not-a-directory");
        std::fs::write(&path, b"file").unwrap();
        let mut c = valid_agent_vm_http_config();
        c.agent_run_log_root = Some(path.clone());

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::AgentRunLogRootCreate {
                path: failed,
                ..
            }) if failed == path
        ));
    }

    /// A typo on a top-level field (e.g. `agentVm` instead of `agent_vm`)
    /// would otherwise be silently ignored — `agent_vm` then falls back to
    /// its `Option<…>` default and the daemon starts without VM HTTP setup.
    /// `deny_unknown_fields` forces a hard failure at config load time.
    #[test]
    fn daemon_config_rejects_unknown_top_level_field() {
        let json = r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "pk"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "agentVm": { "lifecycle": {}, "vm_http": {} }
        }"#;
        let err = serde_json::from_str::<DaemonConfig>(json).unwrap_err();
        assert!(
            err.to_string().contains("agentVm"),
            "error should mention the unknown field, got: {err}"
        );
    }

    #[test]
    fn agent_vm_http_config_rejects_relative_git_push_staging_root() {
        let mut c = valid_agent_vm_http_config();
        c.git_push_staging_root = Some(PathBuf::from("git-push-staging"));

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::RelativeGitPushStagingRoot(path))
                if path.as_os_str() == "git-push-staging"
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_unwritable_git_push_staging_root() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("not-a-directory");
        std::fs::write(&path, b"file").unwrap();
        let mut c = valid_agent_vm_http_config();
        c.git_push_staging_root = Some(path.clone());

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::GitPushStagingRootCreate {
                path: failed,
                ..
            }) if failed == path
        ));
    }

    #[test]
    fn agent_vm_http_config_wires_explicit_flake_input_cache_dir() {
        let flake_cache = unique_config_test_path("flake-input-cache");
        let mut c = valid_agent_vm_http_config();
        c.flake_input_cache_dir = Some(flake_cache.clone());

        let runtime = c.to_runtime_config().unwrap();

        assert_eq!(
            runtime.nix_cache().local_cache_dirs(),
            std::slice::from_ref(&flake_cache),
        );
    }

    #[test]
    fn agent_vm_http_config_rejects_relative_flake_input_cache_dir() {
        let mut c = valid_agent_vm_http_config();
        c.flake_input_cache_dir = Some(PathBuf::from("flake-input-cache"));

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::RelativeFlakeInputCacheDir(path))
                if path.as_os_str() == "flake-input-cache"
        ));
    }

    #[test]
    fn agent_vm_http_config_wires_prewarm_cache_dir_first() {
        let prewarm = unique_config_test_path("nix-prewarm-cache");
        let flake_cache = unique_config_test_path("flake-input-cache");
        let mut c = valid_agent_vm_http_config();
        c.nix_prewarm_cache_dir = Some(prewarm.clone());
        c.flake_input_cache_dir = Some(flake_cache.clone());

        let runtime = c.to_runtime_config().unwrap();

        // Served local-first in order: the durable pre-warm dir ahead of the
        // auto-provisioned flake-input dir.
        assert_eq!(
            runtime.nix_cache().local_cache_dirs(),
            [prewarm.clone(), flake_cache.clone()],
        );
    }

    #[test]
    fn agent_vm_http_config_tolerates_a_missing_prewarm_cache_dir() {
        // Unlike the flake-input cache, the broker only reads the pre-warm dir
        // (an egress builder writes it out of band), so config must NOT create or
        // probe it: a not-yet-populated path is accepted and left untouched.
        let prewarm = unique_config_test_path("nix-prewarm-cache-absent");
        assert!(!prewarm.exists());
        let mut c = valid_agent_vm_http_config();
        c.nix_prewarm_cache_dir = Some(prewarm.clone());

        let runtime = c.to_runtime_config().unwrap();

        assert_eq!(
            runtime.nix_cache().local_cache_dirs().first(),
            Some(&prewarm)
        );
        assert!(
            !prewarm.exists(),
            "config must not create the read-only pre-warm dir",
        );
    }

    #[test]
    fn agent_vm_http_config_rejects_relative_prewarm_cache_dir() {
        let mut c = valid_agent_vm_http_config();
        c.nix_prewarm_cache_dir = Some(PathBuf::from("nix-prewarm-cache"));

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::RelativeNixPrewarmCacheDir(path))
                if path.as_os_str() == "nix-prewarm-cache"
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_prewarm_cache_dir_that_is_not_a_directory() {
        // A typo pointing the (read-only, never-created) pre-warm dir at a file
        // must fail fast: otherwise every narinfo lookup would hit an I/O error
        // and fail closed before the flake-input cache or upstream is tried.
        let not_a_dir = unique_config_test_path("nix-prewarm-not-a-dir");
        std::fs::write(&not_a_dir, b"oops").unwrap();
        let mut c = valid_agent_vm_http_config();
        c.nix_prewarm_cache_dir = Some(not_a_dir.clone());

        let result = c.to_runtime_config();
        std::fs::remove_file(&not_a_dir).ok();

        assert!(matches!(
            result,
            Err(AgentVmHttpConfigError::NixPrewarmCacheDirUnusable { path, .. })
                if path == not_a_dir
        ));
    }

    #[cfg(unix)]
    #[test]
    fn agent_vm_http_config_rejects_non_searchable_prewarm_cache_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        // Root bypasses the directory search bit, so the invariant is only
        // observable as a non-root user — which is how the broker runs. Skip
        // under root rather than assert a rejection that cannot happen there.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        // A dir that is listable (r) but not searchable (no x): `read_dir` would
        // succeed, yet every `<dir>/<hash>.narinfo` open would 502. The
        // child-stat probe must reject it.
        let dir = unique_config_test_path("nix-prewarm-no-search");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o400)).unwrap();
        let mut c = valid_agent_vm_http_config();
        c.nix_prewarm_cache_dir = Some(dir.clone());

        let result = c.to_runtime_config();
        // Restore searchable perms so cleanup can remove the dir.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
        std::fs::remove_dir(&dir).ok();

        assert!(matches!(
            result,
            Err(AgentVmHttpConfigError::NixPrewarmCacheDirUnusable { path, .. })
                if path == dir
        ));
    }

    #[cfg(unix)]
    #[test]
    fn agent_vm_http_config_rejects_non_readable_prewarm_cache_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        // Root bypasses the read bit too; skip there (the broker runs non-root).
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        // A dir that is searchable (x) but not listable (no r): children open by
        // name, but `local_cache_has_narinfo`'s `read_dir` would hit EACCES,
        // making a pre-warm-only no-egress guest proxy cache-info to an
        // unreachable upstream. Require listability too.
        let dir = unique_config_test_path("nix-prewarm-no-read");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o100)).unwrap();
        let mut c = valid_agent_vm_http_config();
        c.nix_prewarm_cache_dir = Some(dir.clone());

        let result = c.to_runtime_config();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
        std::fs::remove_dir(&dir).ok();

        assert!(matches!(
            result,
            Err(AgentVmHttpConfigError::NixPrewarmCacheDirUnusable { path, .. })
                if path == dir
        ));
    }

    #[test]
    fn agent_vm_http_config_wires_explicit_flake_mirror_cache_dir() {
        let mirror_cache = unique_config_test_path("flake-mirror-cache");
        let mut c = valid_agent_vm_http_config();
        c.flake_mirror_cache_dir = Some(mirror_cache.clone());

        let runtime = c.to_runtime_config().unwrap();

        assert_eq!(
            runtime.git_clone().mirror_cache().map(|cache| cache.root()),
            Some(mirror_cache.as_path())
        );
    }

    #[test]
    fn agent_vm_http_config_defaults_to_no_mirror_cache() {
        let runtime = valid_agent_vm_http_config().to_runtime_config().unwrap();
        // Retention is opt-in: without the dir, the clone handler discards the
        // mirror exactly as before, and there is nothing to bound.
        assert!(runtime.git_clone().mirror_cache().is_none());
        assert!(runtime.git_clone().mirror_gc_bounds().is_none());
    }

    #[test]
    fn agent_vm_http_config_pairs_gc_bounds_with_the_mirror_cache() {
        let mut c = valid_agent_vm_http_config();
        c.flake_mirror_cache_dir = Some(unique_config_test_path("flake-mirror-cache"));
        c.flake_mirror_cache_max_entries = 7;
        c.flake_mirror_cache_max_bytes = 4096;

        let runtime = c.to_runtime_config().unwrap();

        // Eviction bounds are wired exactly when the cache they bound exists.
        assert_eq!(
            runtime.git_clone().mirror_gc_bounds(),
            Some(crate::vm_git_mirror_cache::MirrorCacheBounds::new(7, 4096))
        );
    }

    #[test]
    fn agent_vm_http_config_rejects_relative_flake_mirror_cache_dir() {
        let mut c = valid_agent_vm_http_config();
        c.flake_mirror_cache_dir = Some(PathBuf::from("flake-mirror-cache"));

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::RelativeFlakeMirrorCacheDir(path))
                if path.as_os_str() == "flake-mirror-cache"
        ));
    }

    #[test]
    fn agent_vm_http_config_enables_flake_provision_with_the_mirror_cache() {
        let mut c = valid_agent_vm_http_config();
        c.flake_mirror_cache_dir = Some(unique_config_test_path("flake-mirror-cache"));

        let runtime = c.to_runtime_config().unwrap();

        // Provisioning re-derives a checkout from the retained mirror, so it is
        // enabled exactly when the mirror cache is configured.
        assert!(runtime.flake_provision().is_some());
    }

    #[test]
    fn agent_vm_http_config_disables_flake_provision_without_the_mirror_cache() {
        let runtime = valid_agent_vm_http_config().to_runtime_config().unwrap();
        // With nothing to provision from, the endpoint stays disabled even
        // though the flake-input cache is always wired for serving.
        assert!(runtime.flake_provision().is_none());
    }

    #[test]
    fn agent_vm_http_config_rejects_relative_flake_materialize_scratch_dir() {
        let mut c = valid_agent_vm_http_config();
        c.flake_mirror_cache_dir = Some(unique_config_test_path("flake-mirror-cache"));
        c.flake_materialize_scratch_dir = Some(PathBuf::from("flake-materialize"));

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::RelativeFlakeMaterializeScratchDir(path))
                if path.as_os_str() == "flake-materialize"
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_zero_flake_provision_input_bound() {
        let mut c = valid_agent_vm_http_config();
        c.flake_mirror_cache_dir = Some(unique_config_test_path("flake-mirror-cache"));
        c.flake_provision_max_input_count = 0;

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::FlakeProvisionBounds(_))
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_unwritable_flake_input_cache_dir() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("not-a-directory");
        std::fs::write(&path, b"file").unwrap();
        let mut c = valid_agent_vm_http_config();
        c.flake_input_cache_dir = Some(path.clone());

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::FlakeInputCacheDirCreate {
                path: failed,
                ..
            }) if failed == path
        ));
    }

    #[test]
    fn agent_vm_http_config_rejects_zero_git_push_body_limit() {
        let mut c = valid_agent_vm_http_config();
        c.git_push_max_metadata_bytes = 0;

        assert!(matches!(
            c.to_runtime_config(),
            Err(AgentVmHttpConfigError::GitPushBodyLimits(
                VmGitPushBodyLimitsError::EmptyMaxMetadataBytes
            ))
        ));
    }

    /// `to_runtime_config` must leave the work root at 0700, because the
    /// guest-side `prepare_git_work_root` rejects any group/world bits and a
    /// fresh install relies on the daemon — not the user — to create the
    /// default work root.
    #[test]
    fn agent_vm_http_config_creates_work_root_at_mode_0700() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        // Pick a path that does not yet exist so `to_runtime_config` is the
        // one that creates the directory.
        let work_root = temp.path().join("fresh-vm-work");
        let mut c = valid_agent_vm_http_config();
        c.work_root = work_root.clone();

        c.to_runtime_config().expect("runtime config builds");

        let mode = std::fs::symlink_metadata(&work_root)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "work_root {} should be private (0700), got {:04o}",
            work_root.display(),
            mode & 0o777
        );
    }

    /// A pre-existing work_root with group/world bits must fail startup, not
    /// silently boot a daemon whose clone route is unusable.
    #[test]
    fn agent_vm_http_config_rejects_existing_work_root_with_loose_perms() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let work_root = temp.path().join("loose-vm-work");
        std::fs::create_dir(&work_root).unwrap();
        std::fs::set_permissions(&work_root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut c = valid_agent_vm_http_config();
        c.work_root = work_root.clone();

        let err = c.to_runtime_config().expect_err("loose perms rejected");
        assert!(
            matches!(
                err,
                AgentVmHttpConfigError::WorkRootInsecure { ref path, mode }
                    if *path == work_root && mode == 0o755
            ),
            "expected WorkRootInsecure, got {err:?}"
        );
    }

    #[test]
    fn agent_vm_http_config_accepts_existing_work_root_at_mode_0700() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let work_root = temp.path().join("strict-vm-work");
        std::fs::create_dir(&work_root).unwrap();
        std::fs::set_permissions(&work_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut c = valid_agent_vm_http_config();
        c.work_root = work_root.clone();

        c.to_runtime_config()
            .expect("pre-existing 0700 work_root accepted");

        let mode = std::fs::symlink_metadata(&work_root)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn agent_vm_http_config_rejects_work_root_that_is_a_file() {
        let temp = tempfile::tempdir().unwrap();
        let work_root = temp.path().join("not-a-dir");
        std::fs::write(&work_root, b"file").unwrap();
        let mut c = valid_agent_vm_http_config();
        c.work_root = work_root.clone();

        let err = c.to_runtime_config().expect_err("non-directory rejected");
        assert!(
            matches!(
                err,
                AgentVmHttpConfigError::WorkRootNotDirectory { ref path } if *path == work_root
            ),
            "expected WorkRootNotDirectory, got {err:?}"
        );
    }

    #[test]
    fn agent_vm_http_config_defaults_git_push_staging_root_to_work_root_subdir() {
        // Use a non-existent subpath so `ensure_vm_http_work_root_private`
        // creates the work root at 0700 (the failure mode it exists to
        // prevent). Passing `temp.path()` directly would hand the validator a
        // 0755 dir on systems where `tempfile` honours the default umask.
        let temp = tempfile::tempdir().unwrap();
        let work_root = temp.path().join("vm-work");
        let mut c = valid_agent_vm_http_config();
        c.work_root = work_root.clone();
        c.git_push_staging_root = None;

        let runtime = c.to_runtime_config().unwrap();

        assert_eq!(
            runtime.git_push_staging_root(),
            work_root.join("git-push-staging")
        );
    }

    #[test]
    fn agent_vm_http_config_defaults_flake_input_cache_dir_to_work_root_subdir() {
        let temp = tempfile::tempdir().unwrap();
        let work_root = temp.path().join("vm-work");
        let mut c = valid_agent_vm_http_config();
        c.work_root = work_root.clone();
        c.flake_input_cache_dir = None;

        let runtime = c.to_runtime_config().unwrap();

        assert_eq!(
            runtime.nix_cache().local_cache_dirs(),
            [work_root.join("flake-input-cache")],
        );
    }

    #[test]
    fn rejects_invalid_secret_key_name_in_config() {
        let json = r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "bad/key"
                }
            },
            "policy": { "default_ttl": 300 },
            "secret_store": { "type": "file", "path": "/tmp" }
        }"#;
        assert!(serde_json::from_str::<DaemonConfig>(json).is_err());
    }

    /// `run_agent` is optional: an absent section parses cleanly and
    /// the daemon will refuse RunAgent at request time.
    #[test]
    fn parses_config_without_run_agent_section() {
        let json = r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "pk"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] }
        }"#;
        let c: DaemonConfig = serde_json::from_str(json).unwrap();
        assert!(c.run_agent.is_none());
    }

    /// `run_agent` minimal shape: only `spawn_command` is required;
    /// `notes_repo_path`, `signing_key_secret`, and `spawn_args`
    /// default. The accessors return the documented defaults.
    #[test]
    fn parses_run_agent_section_with_defaults() {
        let json = r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "pk"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "run_agent": { "spawn_command": "/usr/bin/claude" }
        }"#;
        let c: DaemonConfig = serde_json::from_str(json).unwrap();
        let cfg = c.run_agent.expect("run_agent parsed");
        assert_eq!(cfg.spawn_command, PathBuf::from("/usr/bin/claude"));
        assert!(cfg.spawn_args.is_empty());
        assert!(cfg.notes_repo_path.is_none());
        assert!(cfg.signing_key_secret.is_none());
        assert_eq!(cfg.notes_repo_path_or_default(), default_notes_repo_path());
        assert_eq!(
            cfg.signing_key_secret_or_default().as_str(),
            DEFAULT_WRIT_SIGNING_KEY_SECRET
        );
    }

    /// `run_agent` with every field overridden — pins the field names
    /// on the wire so a config-file rename is a visible breaking
    /// change.
    #[test]
    fn parses_run_agent_section_with_all_fields() {
        let json = r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "pk"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "run_agent": {
                "spawn_command": "/opt/agents/claude",
                "spawn_args": ["--headless", "--no-color"],
                "notes_repo_path": "/var/lib/writ/notes",
                "signing_key_secret": "custom-signing"
            }
        }"#;
        let c: DaemonConfig = serde_json::from_str(json).unwrap();
        let cfg = c.run_agent.expect("run_agent parsed");
        assert_eq!(cfg.spawn_command, PathBuf::from("/opt/agents/claude"));
        assert_eq!(cfg.spawn_args, vec!["--headless", "--no-color"]);
        assert_eq!(
            cfg.notes_repo_path_or_default(),
            PathBuf::from("/var/lib/writ/notes")
        );
        assert_eq!(
            cfg.signing_key_secret_or_default().as_str(),
            "custom-signing"
        );
    }

    /// `deny_unknown_fields` on `RunAgentDaemonConfig` keeps the
    /// config schema honest: a typo'd key name is rejected at parse
    /// time, not silently dropped.
    #[test]
    fn run_agent_section_rejects_unknown_fields() {
        let json = r#"{
            "github_apps": {
                "claude": {
                    "app_id": 1,
                    "installation_id": 2,
                    "installation_owner": "o",
                    "private_key_secret": "pk"
                }
            },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "run_agent": {
                "spawn_command": "/bin/true",
                "spwan_args": []
            }
        }"#;
        let err = serde_json::from_str::<DaemonConfig>(json).unwrap_err();
        assert!(err.to_string().contains("spwan_args"));
    }

    /// `materialize` is idempotent across boots: the first call
    /// generates and persists a fresh signing key (and creates the
    /// bare notes repo on disk); the second call loads the same key
    /// and reuses the same repo. This is the boot-time invariant
    /// writd relies on.
    #[test]
    fn materialize_persists_signing_key_and_initialises_notes_repo() {
        use crate::secret::{SecretError, SecretStore};
        use std::collections::HashMap;
        use std::sync::Mutex;

        #[derive(Default)]
        struct InMem(Mutex<HashMap<String, String>>);
        impl SecretStore for InMem {
            fn get(&self, key: &SecretKey) -> Result<Option<String>, SecretError> {
                Ok(self.0.lock().unwrap().get(key.as_str()).cloned())
            }
            fn put(&self, key: &SecretKey, value: &str) -> Result<(), SecretError> {
                self.0
                    .lock()
                    .unwrap()
                    .insert(key.as_str().to_string(), value.to_string());
                Ok(())
            }
            fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
                self.0.lock().unwrap().remove(key.as_str());
                Ok(())
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let cfg = RunAgentDaemonConfig {
            notes_repo_path: Some(tmp.path().join("notes-repo")),
            signing_key_secret: Some(SecretKey::new("writ-signing-key").unwrap()),
            spawn_command: PathBuf::from("/bin/cat"),
            spawn_args: vec![],
        };
        let store = InMem::default();

        let first = cfg.materialize(&store).unwrap();
        assert!(
            first.signing.was_generated(),
            "first boot generates the key"
        );
        let fp = first.signing.signing_key().fingerprint();
        assert!(first.notes_repo.path().exists());
        assert_eq!(first.spawn.command, PathBuf::from("/bin/cat"));

        let second = cfg.materialize(&store).unwrap();
        assert!(
            !second.signing.was_generated(),
            "second boot loads the existing key"
        );
        assert_eq!(
            second.signing.signing_key().fingerprint(),
            fp,
            "fingerprint is stable across boots — same key material",
        );
    }
}
