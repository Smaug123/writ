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
use writ::boot_reconcile::reconcile_pending_approve_attempts;
use writ::config::{DaemonConfig, SecretStoreConfig, default_audit_db_path, default_config_path};
use writ::core::UnixMillis;
use writ::git_push_staging::GitPushStagingStore;
use writ::github::GitHubMinter;
use writ::secret::{FileSecretStore, KeyringSecretStore, SecretStore};
use writ::server::{
    BrokerState, default_socket_path, prepare_broker_listener, serve_broker_with_agent_vm,
};
use writ::ui_http::{
    UiHttpBearerToken, UiHttpService, bind_ui_http_listener, run_ui_http_until_shutdown,
    write_bearer_file,
};

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
        github_apps,
        policy,
        agent_vm,
        secret_store,
        socket_path,
        audit_db,
        ui_http,
        run_agent,
    } = config;

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

    // The staging store and the agent-VM daemon both read the same root
    // out of vm_http. Open it once here so the broker can serve promote
    // queries even when the in-memory agent-VM runtime is not attached.
    let staging_store = agent_vm
        .as_ref()
        .map(|cfg| {
            let path = cfg.vm_http().git_push_staging_root().to_path_buf();
            GitPushStagingStore::open(path.clone())
                .map(Arc::new)
                .map_err(|e| format!("cannot open git push staging store at {path:?}: {e}"))
        })
        .transpose()?;

    // Bind the broker Unix socket *before* anything that touches
    // disk-shared singleton state (the signing key in the secret
    // store, the agent-VM on-disk session ledger, the UI bearer
    // file). Bind succeeds for exactly one process per socket path,
    // so it is the cleanest ownership claim available; without this
    // ordering, two concurrent first-boots could both reach
    // `ensure_signing_key` and overwrite each other's freshly
    // generated key, leaving the surviving daemon signing with a
    // key that is no longer the stored trust anchor.
    let broker_listener = prepare_broker_listener(&socket_path).await?;

    // Now that the broker socket is bound, this process is the sole
    // owner of the audit DB for the lifetime of the bind. Sweep approve
    // attempts left non-terminal by a prior crash: `Started` rows are
    // recovered to `Resolved(PrePatchFailure)` so the affected pushes
    // become rejectable/retryable, and `Uncertain` rows are logged to
    // AUDIT_WRITE_FAILURE_TARGET and left in place for operator
    // reconciliation (B2). Reconcile MUST happen after the bind: a
    // second `writd` racing the live daemon's startup would otherwise
    // mutate the shared DB before its bind fails on `AddrInUse`, and
    // could resolve the live process's legitimate in-flight `Started`
    // attempt as a fake "broker restart" failure. The bind succeeds for
    // exactly one process per socket path, so the reconcile call below
    // is single-writer by construction.
    //
    // Reconcile MUST also complete before any request handler runs, so
    // it sits before the agent-VM and broker spawn calls — the audit
    // DB is the single source of truth, and a DAO failure here is
    // correctness-fatal.
    let reconcile_report = reconcile_pending_approve_attempts(&audit, UnixMillis::now())?;
    if !reconcile_report.is_empty() {
        tracing::warn!(
            recovered_started = reconcile_report.recovered_started.len(),
            requires_reconcile = reconcile_report.flagged_uncertain.len(),
            "reconciled approve attempts left in non-terminal state at last shutdown",
        );
    }

    let (notes_repo, signing_key, run_agent_spawn) = match run_agent.as_ref() {
        Some(cfg) => {
            let boot = cfg
                .materialize(&*store)
                .map_err(|e| format!("cannot materialize RunAgent state from config: {e}"))?;
            let fingerprint = boot.signing.signing_key().fingerprint();
            if boot.signing.was_generated() {
                // Bailiff's `AllowedSigners::from_openssh_lines` parses
                // the one-line OpenSSH public-key format, deriving the
                // fingerprint internally. Logging the public-key line
                // (not just the fingerprint) is what the operator
                // actually needs to paste into the allowed-signers
                // file.
                let public_key_line = boot
                    .signing
                    .signing_key()
                    .verifying_key()
                    .to_openssh()
                    .map_err(|e| {
                        format!("cannot serialise newly-generated writ public key: {e}")
                    })?;
                tracing::warn!(
                    fingerprint = %fingerprint,
                    public_key = %public_key_line,
                    secret_key = %cfg.signing_key_secret_or_default(),
                    notes_repo_path = %boot.notes_repo.path().display(),
                    "generated new writ signing key on first boot — \
                     add the public_key line above to bailiff's \
                     allowed-signers file",
                );
            } else {
                tracing::info!(
                    fingerprint = %fingerprint,
                    notes_repo_path = %boot.notes_repo.path().display(),
                    "loaded writ signing key from secret store",
                );
            }
            (
                Some(Arc::new(boot.notes_repo)),
                Some(boot.signing.into_signing_key()),
                Some(boot.spawn),
            )
        }
        None => {
            tracing::info!("RunAgent dispatch not configured; serving Error replies");
            (None, None, None)
        }
    };

    let promote_runtime = agent_vm
        .as_ref()
        .map(|cfg| Arc::new(cfg.vm_http().git_clone().to_promote_runtime_config()));

    let state = Arc::new(BrokerState {
        audit: Arc::new(audit),
        minter: GitHubMinter::new_registry(github_apps),
        secrets: store,
        policy,
        staging_store,
        notes_repo,
        signing_key,
        run_agent_spawn,
        promote_runtime,
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
        let report = agent_vm.reconcile_persisted_sessions(&state.audit).await?;
        if !report.cleaned().is_empty() {
            tracing::warn!(
                count = report.cleaned().len(),
                "reconciled orphaned agent VM sessions on boot",
            );
            for session_id in report.cleaned() {
                tracing::warn!(session_id = %session_id, "reconciled agent VM session");
            }
        }
        if !report.is_clean() {
            for failure in report.failed() {
                tracing::error!(
                    session_id = %failure.session_id(),
                    stage = failure.stage().as_str(),
                    error = %failure.error(),
                    "agent VM reconcile failure",
                );
            }
            return Err(format!(
                "agent VM reconciliation left {} session(s) uncleaned; refusing to start",
                report.failed().len()
            )
            .into());
        }
    }
    if let Some(ui_http) = ui_http {
        ui_http.validate()?;
        // Inside this block we also bind the UI listener before
        // touching the bearer, so a stale UI-port collision doesn't
        // overwrite the live daemon's bearer either.
        let listener = bind_ui_http_listener(ui_http.bind).await?;
        let bound = listener.local_addr()?;
        let bearer = UiHttpBearerToken::generate();
        let bearer_path = ui_http.bearer_path_or_default();
        write_bearer_file(&bearer_path, &bearer)?;
        let service = UiHttpService::new(Arc::clone(&state.audit), agent_vm.clone(), bearer);
        // The broker's main accept loop has no shutdown signal today,
        // so the UI HTTP runner pairs with a never-fires watch and is
        // torn down by process exit; once the broker grows a real
        // shutdown signal this receiver can hang off it.
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tracing::info!(
            bind = %bound,
            bearer_path = %bearer_path.display(),
            "ui http listening",
        );
        tokio::spawn(async move {
            if let Err(err) = run_ui_http_until_shutdown(listener, service, shutdown_rx).await {
                tracing::error!(error = %err, "ui http listener exited with error");
            }
        });
        // Keep the sender alive for the daemon lifetime so the receiver
        // does not observe `Err` on `changed()` and exit early.
        std::mem::forget(_shutdown_tx);
    }

    serve_broker_with_agent_vm(broker_listener, state, agent_vm).await?;
    Ok(())
}
