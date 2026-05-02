//! Daemon configuration loaded from a JSON file at startup.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::core::{AgentVmConfigError, BrokerPortRange};
use crate::github::GitHubAppConfig;
use crate::policy::PolicyConfig;
use crate::vm_git::{
    GitCloneBundlePlanError, GitCredentialBoundary, GitSecretEnvVar, GitSecretEnvVarError,
};
use crate::vm_http::{VmHttpGitCloneConfig, VmHttpGitRuntimeConfig};

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
    pub github: GitHubAppConfig,
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
    pub vm_http: AgentVmHttpConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVmHttpConfig {
    pub bind_addr: Ipv4Addr,
    pub broker_port_min: u16,
    pub broker_port_max: u16,
    pub git_program: PathBuf,
    pub askpass_program: PathBuf,
    #[serde(default = "default_vm_git_token_env")]
    pub token_env: String,
    pub work_root: PathBuf,
    pub clone_timeout_secs: u64,
    pub max_bundle_bytes: u64,
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
}

impl AgentVmHttpConfig {
    pub fn to_runtime_config(&self) -> Result<VmHttpGitRuntimeConfig, AgentVmHttpConfigError> {
        let broker_port_range = BrokerPortRange::new(self.broker_port_min, self.broker_port_max)?;
        let token_env = GitSecretEnvVar::new(self.token_env.clone())?;
        let credential = GitCredentialBoundary::new(self.askpass_program.clone(), token_env)?;
        let git_clone = VmHttpGitCloneConfig::new(
            self.git_program.clone(),
            credential,
            self.work_root.clone(),
            Duration::from_secs(self.clone_timeout_secs),
            self.max_bundle_bytes,
        )?;
        Ok(VmHttpGitRuntimeConfig::new(
            self.bind_addr,
            broker_port_range,
            git_clone,
        ))
    }
}

fn default_keyring_service() -> String {
    "writ".into()
}

fn default_vm_git_token_env() -> String {
    "WRIT_GIT_TOKEN".into()
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
        assert_eq!(c.github.app_id, 42);
        assert_eq!(c.github.api_base, "https://api.github.com");
        assert_eq!(c.policy.default_ttl.as_i64(), 3600);
        assert!(c.agent_vm.is_none());
        assert!(c.socket_path.is_none());
        assert!(
            matches!(c.secret_store, SecretStoreConfig::File { path } if path == default_secret_store_path())
        );
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
        assert_eq!(c.github.api_base, "https://github.example.com/api/v3");
        assert_eq!(
            c.socket_path.as_deref(),
            Some(std::path::Path::new("/tmp/test.sock"))
        );
        assert!(
            matches!(c.secret_store, SecretStoreConfig::Keyring { service } if service == "writ")
        );
    }

    #[test]
    fn parses_agent_vm_http_config_and_converts_to_runtime_config() {
        let json = r#"{
            "github": {
                "app_id": 1,
                "installation_id": 2,
                "installation_owner": "o",
                "private_key_secret": "pk"
            },
            "policy": { "default_ttl": 600, "writable_repos": [] },
            "agent_vm": {
                "vm_http": {
                    "bind_addr": "0.0.0.0",
                    "broker_port_min": 18080,
                    "broker_port_max": 18081,
                    "git_program": "/usr/bin/git",
                    "askpass_program": "/usr/local/libexec/writ-git-askpass",
                    "work_root": "/var/folders/writ/git-work",
                    "clone_timeout_secs": 30,
                    "max_bundle_bytes": 1048576
                }
            }
        }"#;
        let c: DaemonConfig = serde_json::from_str(json).unwrap();
        let agent_vm = c.agent_vm.unwrap();

        let runtime = agent_vm.vm_http.to_runtime_config().unwrap();

        assert_eq!(runtime.bind_addr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(runtime.broker_port_range().min().get(), 18080);
        assert_eq!(runtime.broker_port_range().max().get(), 18081);
        assert_eq!(
            runtime.git_clone().work_root(),
            PathBuf::from("/var/folders/writ/git-work")
        );
    }

    fn valid_agent_vm_http_config() -> AgentVmHttpConfig {
        AgentVmHttpConfig {
            bind_addr: Ipv4Addr::UNSPECIFIED,
            broker_port_min: 18080,
            broker_port_max: 18081,
            git_program: PathBuf::from("/usr/bin/git"),
            askpass_program: PathBuf::from("/usr/local/libexec/writ-git-askpass"),
            token_env: "WRIT_GIT_TOKEN".into(),
            work_root: PathBuf::from("/var/folders/writ/git-work"),
            clone_timeout_secs: 30,
            max_bundle_bytes: 1_048_576,
        }
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
