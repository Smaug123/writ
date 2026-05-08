//! Daemon configuration loaded from a JSON file at startup.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
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
use crate::core::{
    AgentKind, AgentNetworkPool, AgentVmConfigError, BrokerPortRange, Ipv4Cidr, Ipv6Cidr,
};
use crate::github::GitHubAppConfig;
use crate::nix_cache::{NixTrustedPublicKeys, NixTrustedPublicKeysError};
use crate::policy::PolicyConfig;
use crate::secret::SecretKey;
use crate::vm_git_bundle::{
    DEFAULT_GIT_CLONE_BASE_URL, GitCloneBaseUrl, GitCloneBundlePlanError, GitCredentialBoundary,
    GitSecretEnvVar, GitSecretEnvVarError,
};
use crate::vm_http::{
    DEFAULT_CLAUDE_ANTHROPIC_VERSION, VmHttpClaudeProxyAuthKind, VmHttpClaudeProxyConfig,
    VmHttpClaudeProxyConfigError, VmHttpGitCloneConfig, VmHttpGitRuntimeConfig,
    VmHttpNixCacheConfig, VmHttpNixCacheConfigError, VmHttpOpenAiProxyAuthKind,
    VmHttpOpenAiProxyConfig, VmHttpOpenAiProxyConfigError,
};

/// Top-level daemon configuration. Loaded from a JSON file at startup;
/// runtime-mutable config is not a goal for v1.
///
/// Example config:
/// ```json
/// {
///   "github": {
///     "app_id": 12345,
///     "installation_id": 67890,
///     "installation_owner": "smaug123",
///     "private_key_secret": "gh-app-pk"
///   },
///   "policy": {
///     "default_ttl": 3600,
///     "writable_repos": ["smaug123/writ"]
///   }
/// }
/// ```
#[derive(Debug, Deserialize)]
pub struct DaemonConfig {
    /// Legacy single GitHub App configuration. Mutually exclusive with
    /// `github_apps`.
    #[serde(default)]
    pub github: Option<GitHubAppConfig>,
    /// Agent-keyed GitHub Apps. Use this when Claude and Codex should push
    /// under different GitHub App identities.
    #[serde(default)]
    pub github_apps: BTreeMap<AgentKind, GitHubAppConfig>,
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
    pub bind_addr: Ipv4Addr,
    pub broker_port_min: u16,
    pub broker_port_max: u16,
    pub git_program: PathBuf,
    #[serde(default = "default_git_clone_base_url")]
    pub git_clone_base_url: String,
    pub askpass_program: PathBuf,
    #[serde(default = "default_vm_git_token_env")]
    pub token_env: String,
    pub work_root: PathBuf,
    pub clone_timeout_secs: u64,
    pub max_bundle_bytes: u64,
    pub nix_cache_url: String,
    #[serde(default)]
    pub nix_cache_trusted_public_keys: Vec<String>,
    pub nix_cache_max_metadata_bytes: u64,
    pub nix_cache_max_nar_bytes: u64,
    #[serde(default)]
    pub claude_proxy: Option<AgentVmHttpClaudeProxyConfig>,
    #[serde(default)]
    pub openai_proxy: Option<AgentVmHttpOpenAiProxyConfig>,
    #[serde(default)]
    pub agent_run_log_root: Option<PathBuf>,
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
    pub fn to_runtime_config(&self) -> Result<VmHttpGitRuntimeConfig, AgentVmHttpConfigError> {
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
        Ok(VmHttpGitRuntimeConfig::new_with_proxies(
            self.bind_addr,
            broker_port_range,
            git_clone,
            nix_cache,
            claude_proxy,
            openai_proxy,
            agent_run_log_root,
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
    use crate::github::{GitHubAppRegistryConfig, GitHubAppRegistryConfigError};

    const TEST_NIX_CACHE_PUBLIC_KEY: &str =
        "cache.example-1:IsGkyTbr2sed7tWowgiPcI0ZHhBAHoGQ7TyYRweyzwE=";

    #[test]
    fn parses_minimal_config() {
        // No `secret_store` key — the file backend at
        // `default_secret_store_path()` is the documented default.
        let json = r#"{
            "github": {
                "app_id": 42,
                "installation_id": 999,
                "installation_owner": "smaug123",
                "private_key_secret": "gh-app-pk"
            },
            "policy": {
                "default_ttl": 3600,
                "writable_repos": []
            }
        }"#;
        let c: DaemonConfig = serde_json::from_str(json).unwrap();
        let github = c.github.as_ref().unwrap();
        assert_eq!(github.app_id, 42);
        assert_eq!(github.api_base, "https://api.github.com");
        assert!(c.github_apps.is_empty());
        assert_eq!(c.policy.default_ttl.as_i64(), 3600);
        assert!(c.agent_vm.is_none());
        assert!(c.socket_path.is_none());
        assert!(
            matches!(&c.secret_store, SecretStoreConfig::File { path } if *path == default_secret_store_path())
        );
        let DaemonConfig {
            github,
            github_apps,
            ..
        } = c;
        assert!(GitHubAppRegistryConfig::from_parts(github, github_apps).is_ok());
    }

    #[test]
    fn parses_config_with_overrides() {
        let json = r#"{
            "github": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk",
                "api_base": "https://github.example.com/api/v3"
            },
            "policy": { "default_ttl": 600, "writable_repos": ["o/n"] },
            "secret_store": { "type": "keyring" },
            "socket_path": "/tmp/test.sock",
            "audit_db": "/tmp/audit.db"
        }"#;
        let c: DaemonConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            c.github.as_ref().unwrap().api_base,
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
        let DaemonConfig {
            github,
            github_apps,
            ..
        } = c;
        let registry = GitHubAppRegistryConfig::from_parts(github, github_apps).unwrap();

        assert!(registry.legacy_app().is_none());
        assert_eq!(
            registry.agent_apps()[&AgentKind::Claude]
                .private_key_secret
                .as_str(),
            "claude-pk"
        );
        assert_eq!(
            registry.agent_apps()[&AgentKind::Codex]
                .private_key_secret
                .as_str(),
            "codex-pk"
        );
    }

    #[test]
    fn rejects_ambiguous_github_app_config_shapes() {
        let json = r#"{
            "github": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "legacy-pk"
            },
            "github_apps": {
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

        assert!(matches!(
            GitHubAppRegistryConfig::from_parts(c.github, c.github_apps),
            Err(GitHubAppRegistryConfigError::Ambiguous)
        ));
    }

    #[test]
    fn parses_agent_vm_config_and_converts_to_runtime_config() {
        let work_root = unique_config_test_path("work-root");
        let agent_run_log_root = unique_config_test_path("agent-runs");
        let mut json: serde_json::Value = serde_json::from_str(
            r#"{
            "github": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
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
        assert_eq!(runtime.lifecycle().subnet_index_min(), 252);
        assert_eq!(runtime.lifecycle().subnet_index_max(), 253);
    }

    #[test]
    fn parses_agent_vm_config_with_oauth_claude_proxy_auth_kind() {
        let work_root = unique_config_test_path("work-root");
        let agent_run_log_root = unique_config_test_path("agent-runs");
        let mut json: serde_json::Value = serde_json::from_str(
            r#"{
            "github": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
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

    #[test]
    fn rejects_invalid_secret_key_name_in_config() {
        let json = r#"{
            "github": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "bad/key"
            },
            "policy": { "default_ttl": 300 },
            "secret_store": { "type": "file", "path": "/tmp" }
        }"#;
        assert!(serde_json::from_str::<DaemonConfig>(json).is_err());
    }
}
