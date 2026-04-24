//! `writd` — the writ broker daemon.
//!
//! Loads config, opens the audit log and secret store, then listens on
//! a Unix socket. Exits on fatal errors only; individual connection
//! errors are logged and do not bring down the server.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use writ::audit::AuditLog;
use writ::config::{DaemonConfig, SecretStoreConfig, default_audit_db_path, default_config_path};
use writ::github::GitHubMinter;
use writ::secret::{FileSecretStore, KeyringSecretStore, SecretStore};
use writ::server::{BrokerState, default_socket_path, run};

#[derive(Parser)]
#[command(name = "writd", about = "writ broker daemon")]
struct Args {
    /// Path to the JSON config file.
    #[arg(long, short = 'c')]
    config: Option<PathBuf>,

    /// Override the Unix socket path from config.
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Override the audit DB path from config.
    #[arg(long)]
    audit_db: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let config_path = args.config.unwrap_or_else(default_config_path);
    let json = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("cannot read config {}: {e}", config_path.display()))?;
    let config: DaemonConfig = serde_json::from_str(&json)
        .map_err(|e| format!("invalid config {}: {e}", config_path.display()))?;

    let socket_path = args
        .socket
        .or(config.socket_path)
        .unwrap_or_else(default_socket_path);

    let audit_db_path = args
        .audit_db
        .or(config.audit_db)
        .unwrap_or_else(default_audit_db_path);

    if let Some(parent) = audit_db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let audit = AuditLog::open(&audit_db_path)?;
    let policy = config.policy;
    let github = config.github;

    // Dispatch on the secret store type at the binary boundary so the
    // library stays fully generic. Both arms produce the same concrete
    // `BrokerState<Box<dyn SecretStore>>`, just via different constructors.
    let store: Box<dyn SecretStore> = match config.secret_store {
        SecretStoreConfig::File { path } => Box::new(FileSecretStore::create_or_open(path)?),
        SecretStoreConfig::Keyring { service } => Box::new(KeyringSecretStore::new(service)),
    };

    let state = Arc::new(BrokerState {
        audit,
        minter: GitHubMinter::new(github, store),
        policy,
    });

    eprintln!("writd: listening on {}", socket_path.display());
    run(&socket_path, state).await?;
    Ok(())
}
