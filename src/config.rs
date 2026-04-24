//! Daemon configuration loaded from a JSON file at startup.

use std::path::PathBuf;

use serde::Deserialize;

use crate::github::GitHubAppConfig;
use crate::policy::PolicyConfig;

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

fn default_keyring_service() -> String {
    "writ".into()
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
