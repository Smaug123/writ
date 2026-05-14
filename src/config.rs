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
use crate::github::GitHubAppRegistryConfig;
use crate::nix_cache::{NixTrustedPublicKeys, NixTrustedPublicKeysError};
use crate::policy::PolicyConfig;
use crate::secret::SecretKey;
use crate::vm_git::{VmGitPushBodyLimits, VmGitPushBodyLimitsError};
use crate::vm_git_bundle::{
    DEFAULT_GIT_CLONE_BASE_URL, GitCloneBaseUrl, GitCloneBundlePlanError, GitCredentialBoundary,
    GitSecretEnvVar, GitSecretEnvVarError,
};
use crate::vm_http::{
    DEFAULT_CLAUDE_ANTHROPIC_VERSION, VmHttpClaudeProxyAuthKind, VmHttpClaudeProxyConfig,
    VmHttpClaudeProxyConfigError, VmHttpGitCloneConfig, VmHttpNixCacheConfig,
    VmHttpNixCacheConfigError, VmHttpOpenAiProxyAuthKind, VmHttpOpenAiProxyConfig,
    VmHttpOpenAiProxyConfigError, VmHttpRuntimeConfig,
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
///   }
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// Agent-keyed GitHub Apps. The session's [`AgentKind`] selects which App
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
    /// `$XDG_RUNTIME_DIR/writ/writd.sock` (see [`server::default_socket_path`]).
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
        let nix_cache = VmHttpNixCacheConfig::new_with_trusted_public_keys(
            &self.nix_cache_url,
            self.nix_cache_max_metadata_bytes,
            self.nix_cache_max_nar_bytes,
            trusted_public_keys,
        )?;
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
        ))
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
}
