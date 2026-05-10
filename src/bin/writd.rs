//! `writd` — the writ broker daemon.
//!
//! Loads config, opens the audit log and secret store, then listens on
//! a Unix socket. Exits on fatal errors only; individual connection
//! errors are logged and do not bring down the server.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use writ::agent_vm_daemon::AgentVmDaemon;
use writ::audit::AuditLog;
use writ::config::{DaemonConfig, SecretStoreConfig, default_audit_db_path, default_config_path};
use writ::github::{GitHubAppRegistryConfig, GitHubMinter};
use writ::secret::{FileSecretStore, KeyringSecretStore, SecretStore};
use writ::server::{BrokerState, default_socket_path, run_with_agent_vm};

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
    writ::telemetry::init("info")?;
    let args = Args::parse();

    let config_path = args.config.unwrap_or_else(default_config_path);
    let json = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("cannot read config {}: {e}", config_path.display()))?;
    let config: DaemonConfig = serde_json::from_str(&json)
        .map_err(|e| format!("invalid config {}: {e}", config_path.display()))?;
    let DaemonConfig {
        github,
        github_apps,
        policy,
        agent_vm,
        secret_store,
        socket_path,
        audit_db,
    } = config;
    let github = GitHubAppRegistryConfig::from_parts(github, github_apps)?;

    let socket_path = args
        .socket
        .or(socket_path)
        .unwrap_or_else(default_socket_path);

    let audit_db_path = args
        .audit_db
        .or(audit_db)
        .unwrap_or_else(default_audit_db_path);
    let agent_vm = agent_vm
        .as_ref()
        .map(|agent_vm| agent_vm.to_runtime_config())
        .transpose()?;

    if let Some(parent) = audit_db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let audit = AuditLog::open(&audit_db_path)?;

    // Dispatch on the secret store type at the binary boundary so the
    // library stays fully generic. Both arms produce the same concrete
    // `BrokerState<Box<dyn SecretStore>>`, just via different constructors.
    let store: Box<dyn SecretStore> = match secret_store {
        SecretStoreConfig::File { path } => Box::new(FileSecretStore::create_or_open(path)?),
        SecretStoreConfig::Keyring { service } => Box::new(KeyringSecretStore::new(service)),
    };

    let state = Arc::new(BrokerState {
        audit: Arc::new(audit),
        minter: GitHubMinter::new_registry(github, store),
        policy,
    });

    tracing::info!(
        socket_path = %socket_path.display(),
        "broker listening",
    );
    let agent_vm = agent_vm.map(|config| {
        let runtime = Arc::new(AgentVmDaemon::new(config));
        let vm_http = runtime.config().vm_http();
        tracing::info!(
            bind_addr = %vm_http.bind_addr(),
            broker_port_min = vm_http.broker_port_range().min().get(),
            broker_port_max = vm_http.broker_port_range().max().get(),
            "agent VM runtime configured",
        );
        runtime
    });
    if let Some(agent_vm) = &agent_vm {
        let lifecycle = agent_vm.config().lifecycle();
        tracing::info!(
            subnet_index_min = lifecycle.subnet_index_min(),
            subnet_index_max = lifecycle.subnet_index_max(),
            "agent VM subnet range",
        );
    }
    run_with_agent_vm(&socket_path, state, agent_vm).await?;
    Ok(())
}
