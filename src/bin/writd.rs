//! `writd` — the writ broker daemon.
//!
//! Loads config, opens the audit log and secret store, then listens on
//! a Unix socket. Exits on fatal errors only; individual connection
//! errors are logged and do not bring down the server.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};

use writ::agent_vm_daemon::AgentVmDaemon;
use writ::agent_vm_lifecycle::BrokerPlacement;
use writ::audit::AuditLog;
use writ::boot_reconcile::{
    reconcile_orphaned_staged_carriers, reconcile_pending_approve_attempts,
    reconcile_unpaired_effect_rows,
};
use writ::broker_entrypoint::{BrokerArgs, run_broker};
use writ::broker_session::BrokerSessionSpec;
use writ::config::default_paths;
use writ::config::{
    DaemonConfig, LegacyAuditDbNotMigrated, SecretStoreConfig, check_daemon_sections,
    ensure_audit_db_entry_is_regular_file, ensure_audit_dir_is_dedicated,
    legacy_audit_db_needs_migration, legacy_default_audit_db_path, path_entry_present,
};
use writ::core::UnixMillis;
use writ::git_push_staging::GitPushStagingStore;
use writ::github::GitHubMinter;
use writ::secret::{FileSecretStore, KeyringSecretStore, SecretStore};
use writ::server::{BrokerState, prepare_broker_listener, serve_broker_with_agent_vm};
use writ::ui_http::{
    UiHttpBearerToken, UiHttpService, bind_ui_http_listener, run_ui_http_until_shutdown,
    write_bearer_file,
};

#[derive(Parser)]
#[command(name = "writd", about = "writ broker daemon")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

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

#[derive(Subcommand)]
enum Command {
    /// Serve a single agent-VM HTTP session on a fixed port (the
    /// `broker_placement = vm` arm). The host launcher owns the audit session
    /// and supplies the session spec and bearer token out-of-band; see
    /// `docs/vmnet-accept-bug-and-broker-vm-plan.md`.
    Broker {
        /// Path to the JSON daemon config file (secret store must be `file`).
        #[arg(long, short = 'c')]
        config: PathBuf,

        /// Path to the JSON session spec (session id, agent subnet, fixed
        /// `bind_addr:broker_port`).
        #[arg(long)]
        session_spec: PathBuf,

        /// Path to the per-session bearer-token file.
        #[arg(long)]
        bearer_token_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            // Print via `Display`, not the `main() -> Result` default (`{err:?}`):
            // Debug-formatting a boxed `String` escapes quotes and newlines, which
            // would mangle multi-line actionable messages — notably the audit-DB
            // migration recovery command. Return an exit *code* (rather than
            // `process::exit`) so `#[tokio::main]` drops the runtime and runs
            // spawned tasks' destructors (process-group / temp-file guards).
            eprintln!("Error: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Parse before installing telemetry: the global subscriber installs only
    // once, and the broker subcommand adds a second (file) sink whose path it
    // learns only from the parsed session spec (read below).
    let args = Args::parse();

    match args.command {
        Some(Command::Broker {
            config,
            session_spec,
            bearer_token_file,
        }) => {
            // The broker's log-sink path lives in the session spec, so the spec
            // must be read before telemetry is installed. A spec read/parse
            // failure therefore predates telemetry and prints to stderr — which
            // the host's broker-VM liveness check surfaces via `container logs`
            // (a version-skewed / stale-image spec is exactly this failure class).
            let spec = match BrokerSessionSpec::read_file(&session_spec) {
                Ok(spec) => spec,
                Err(err) => {
                    eprintln!("writd broker: cannot load session spec: {err}");
                    return Err(err.into());
                }
            };
            writ::telemetry::init_with_file("info", Some(spec.log_file.as_path()))?;
            // Log any broker failure via `tracing` before returning: telemetry
            // (with the file sink) is installed, so this reaches the host tailer.
            // A bare `?` would instead print only to the guest's stderr, leaving
            // early startup failures (bad config, missing store, bind error)
            // looking like a silent ready-file timeout on the host.
            if let Err(err) = run_broker(BrokerArgs {
                config,
                session_spec: spec,
                bearer_token_file,
            })
            .await
            {
                tracing::error!(error = %err, "writd broker exited with error");
                return Err(err.into());
            }
            return Ok(());
        }
        None => {}
    }

    writ::telemetry::init("info")?;
    run_host_daemon(args.config, args.socket, args.audit_db).await
}

/// The default `writd` mode: the host broker daemon listening on a Unix socket.
async fn run_host_daemon(
    config: Option<PathBuf>,
    socket: Option<PathBuf>,
    audit_db: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = default_paths::CONFIG_FILE.or_resolve(config)?;
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
        audit_db: audit_db_config,
        ui_http,
        run_agent,
        agent_run_log_root,
        max_concurrent_agent_runs,
    } = config;

    // Built here, before writd creates directories, opens and reconciles the
    // audit DB, generates signing material, or binds the socket. It is pure
    // validation of a config value, and a config writd will refuse should be
    // refused before it has changed anything on disk — otherwise a typo leaves
    // durable side effects behind on the way to the error message.
    let agent_run_slots = writ::server::AgentRunSlots::new(
        max_concurrent_agent_runs.unwrap_or(writ::server::DEFAULT_MAX_CONCURRENT_AGENT_RUNS),
    )
    .map_err(|e| format!("invalid config {}: {e}", config_path.display()))?;

    let socket_path = default_paths::SOCKET.or_resolve(socket.or(socket_path))?;

    let audit_db_selected = audit_db.or(audit_db_config);
    let used_default_audit_db = audit_db_selected.is_none();
    let audit_db_path = default_paths::AUDIT_DB.or_resolve(audit_db_selected)?;

    // The default audit DB path moved into a dedicated `audit/` directory so the
    // broker VM can mount it read-write without exposing the secret store. An
    // install that relied on the old default still has its system-of-record at
    // the legacy path; opening the new default would silently start an empty
    // audit log and fork history (reconciliation and the UI would lose every
    // prior session and grant), so refuse and tell the operator to migrate.
    if used_default_audit_db {
        // Resolved through the same `DefaultPath` machinery as the current
        // default, so this cannot silently probe a different base directory
        // than the one writd is about to open.
        let legacy = legacy_default_audit_db_path()?;
        // "new already migrated" means opening the new path yields the existing
        // DB rather than forking — a *following* existence check, so a dangling
        // symlink at the new path counts as absent and migration still fires
        // (the preflight below rejects the symlink itself before any open).
        let new_exists = audit_db_path
            .try_exists()
            .map_err(|e| format!("cannot probe audit DB path {audit_db_path:?}: {e}"))?;
        // Legacy is migration *state*: detect the entry even as a dangling
        // symlink (non-following) so an unavailable target is not read as
        // "already migrated". Both fail closed on a probe error.
        let legacy_exists = path_entry_present(&legacy)
            .map_err(|e| format!("cannot probe legacy audit DB path {legacy:?}: {e}"))?;
        if legacy_audit_db_needs_migration(true, new_exists, legacy_exists) {
            let new_parent = audit_db_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default();
            // Stringify so `main`'s `{:?}` printing surfaces the actionable
            // Display message rather than the struct's derived Debug form.
            return Err(LegacyAuditDbNotMigrated {
                legacy,
                new: audit_db_path.clone(),
                new_parent,
            }
            .to_string()
            .into());
        }
    }

    // Create the audit DB's directory now — before the compartment guard — so
    // the guard's canonicalisation resolves the real mount directory. Without an
    // existing directory a case-insensitive host (default macOS APFS) would let
    // an audit dir `.../AUDIT` and a secret dir `.../audit/...` compare as
    // disjoint even though `create_dir_all` later treats them as one directory.
    if let Some(parent) = audit_db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Validate every section that can be checked before the daemon starts
    // taking irreversible steps, and report all the failures together. An
    // operator fixing a config should get the whole list, not one problem per
    // restart — which is also why `ui_http` is checked *here* rather than at
    // the point its listener is bound, hundreds of lines and one socket bind,
    // one signing key and two reconcile passes later.
    let checked = check_daemon_sections(
        agent_vm.as_ref(),
        ui_http.as_ref(),
        agent_run_log_root.as_deref(),
        secret_store.as_ref(),
        run_agent.as_ref(),
    )
    .map_err(|errors| errors.to_string())?;
    let agent_vm = checked.agent_vm;
    // Both of these are environment-derived defaults, resolved inside the
    // preflight above rather than at their point of use: the secret store so
    // its failure joins the same report as every other config error, and the
    // bearer path so the daemon cannot get as far as binding listeners before
    // discovering it has nowhere to write a token.
    let secret_store = checked.secret_store;
    let ui_http_bearer_path = checked.ui_http_bearer_path;
    // Likewise the notes repo: `materialize` runs after the audit DB is open,
    // the socket is bound and the reconcile passes have run, so a path that
    // could not be derived would abort boot having already left side effects.
    let notes_repo_path = checked.notes_repo_path;
    // Both `RunAgent` arms write per-run stdout/stderr here, and the absolute
    // paths land on `agent_run_outcome` rows — so the operator needs to know
    // which directory this boot resolved, whether they configured it or took
    // the default.
    tracing::info!(
        agent_run_log_root = %checked.agent_run_log_root.as_path().display(),
        "agent run logs directory",
    );

    // Attach the vm-arm host facts (raw config text + effective audit DB path)
    // the broker-VM placement needs but cannot read from the parsed config. A
    // no-op for host placement, so it is unconditional here.
    let agent_vm = agent_vm.map(|cfg| cfg.with_broker_vm_host_facts(&json, &audit_db_path));

    // Under vm placement the audit directory is mounted read-write into a broker
    // VM, so the audit DB path must not redirect the host's open. A compromised
    // broker VM that outlived a prior daemon (still holding the mount) could
    // plant a symlink or hard link at audit.db. Two layers: a best-effort
    // preflight for a clear early error and to catch hard links (which
    // `NOFOLLOW` does not — a guest cannot forge a cross-filesystem hard link
    // through the mount, so only an operator can, and that is not TOCTOU-raced),
    // and an atomic `SQLITE_OPEN_NOFOLLOW` open that closes the check-then-open
    // race for symlinks. Host placement runs no broker VM that could plant a link.
    let vm_placement = agent_vm
        .as_ref()
        .is_some_and(|cfg| cfg.lifecycle().broker_placement() == BrokerPlacement::Vm);
    let audit = if vm_placement {
        ensure_audit_db_entry_is_regular_file(&audit_db_path).map_err(|err| err.to_string())?;
        AuditLog::open_no_follow(&audit_db_path)?
    } else {
        AuditLog::open(&audit_db_path)?
    };

    // P1 compartment guard (best-effort at startup): with `broker_placement =
    // vm` the broker VM read-write-mounts the audit DB's *parent directory* (see
    // `resolve_broker_audit_paths`), so it must contain only the audit DB and its
    // SQLite sidecars — no config file, executable, secret, or socket the guest
    // could replace and the host would then re-read or run. Here it catches
    // whatever already exists at startup for early operator feedback; the
    // authoritative, complete check runs at broker-VM mount time (in
    // `AgentVmDaemon`), when every lazily-written file exists. Host placement
    // runs no broker VM and mounts nothing, so the check is vm-only.
    if vm_placement {
        ensure_audit_dir_is_dedicated(&audit_db_path).map_err(|err| err.to_string())?;
    }

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

    // Sweep approve attempts left non-terminal by a prior crash:
    // `Started` rows are recovered to `Resolved(PrePatchFailure)` so
    // the affected pushes become rejectable/retryable, and `Uncertain`
    // rows are logged to AUDIT_WRITE_FAILURE_TARGET and left in place
    // for operator reconciliation (B2).
    //
    // Reconcile MUST happen after the broker bind: a second `writd`
    // started against the same socket path would otherwise mutate the
    // shared DB before its bind fails on `AddrInUse`, and could resolve
    // the live process's legitimate in-flight `Started` attempt as a
    // fake "broker restart" failure. The bind is the singleton claim
    // for the socket path, so this call is single-writer with respect
    // to any other daemon configured against the same socket.
    //
    // Single-writer-ness against the *audit DB* is an operator-config
    // invariant, not a runtime guarantee: nothing here stops an
    // operator from pointing two daemons at the same `--audit-db` via
    // different `--socket` paths. That same operator-config invariant
    // is already load-bearing for the signing key in the secret store,
    // the agent-VM on-disk session ledger, and the UI HTTP bearer
    // file. A DB-scoped lock that covers all of them is a separate
    // slice (see follow-up tracked alongside #69).
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

    // Repair staged-push carriers left on disk without a `staged` outcome
    // row by a crash between staging and the outcome write — otherwise
    // they sit in `promote list` unable to be approved or rejected. Same
    // ordering constraints as the approve-attempt reconcile above: after
    // the socket bind (singleton claim), before any request handler runs.
    // Only runs when the staging store is configured (agent-VM mode).
    if let Some(staging) = staging_store.as_ref() {
        // Derive the recovery read bound from the *live* accepted metadata
        // size so it tracks config rather than a hard-coded cap that could
        // reject a legitimately-staged receipt. `staging_store` is `Some`
        // only when the agent-VM config (which carries the body limits)
        // is present, so the limit is always available here.
        let max_metadata_bytes = agent_vm
            .as_ref()
            .expect("staging store is configured only alongside the agent-VM config")
            .vm_http()
            .git_push_body_limits()
            .max_metadata_bytes();
        let max_receipt_bytes = writ::git_push_staging::recovery_receipt_bound(max_metadata_bytes);
        let recovered = reconcile_orphaned_staged_carriers(
            &audit,
            staging,
            max_receipt_bytes,
            UnixMillis::now(),
        )?;
        if !recovered.is_empty() {
            tracing::warn!(
                recovered_staged_carriers = recovered.len(),
                "recovered staged push carriers left without an outcome row at last shutdown",
            );
        }
    }

    let (notes_repo, signing_key, run_agent_spawn) = match run_agent.as_ref() {
        Some(cfg) => {
            let boot = cfg
                .materialize(
                    &*store,
                    checked.agent_run_log_root.clone(),
                    notes_repo_path
                        .expect("a run_agent section resolves its notes repo in preflight"),
                )
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
        agent_run_slots,
        promote_runtime,
        git_data_http: std::sync::OnceLock::new(),
        mirror_pins: writ::vm_git_mirror_cache::MirrorPins::new(),
        chatgpt_oauth_authority: Default::default(),
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

    // Durable backstop for the "complete by construction" audit-pair invariant:
    // flag any brokered-effect request row left without its outcome by a crash (or
    // an unreconciled handler failure) mid-effect. Deliberately runs *after*
    // `reconcile_persisted_sessions` above: under `broker_placement = vm` a broker
    // VM persisted by a previously-crashed host daemon keeps writing this audit DB
    // (over its virtiofs mount) until that pass closes and tears it down, so a scan
    // any earlier could miss a row inserted post-scan, or falsely flag a row that
    // is merely in-flight. After teardown the DB is quiescent for those sessions.
    // Still unconditional (the proxy / nix-cache / flake-provision tables exist in
    // any mode), still fail-fast, and — because the staged-carrier sweep ran
    // earlier — a git-push carrier that sweep could recover is already paired, so
    // only genuinely-stuck rows are flagged.
    let unpaired = reconcile_unpaired_effect_rows(&state.audit)?;
    if !unpaired.is_empty() {
        let total_rows: u64 = unpaired.iter().map(|finding| finding.count).sum();
        tracing::warn!(
            unpaired_effect_tables = unpaired.len(),
            unpaired_effect_rows = total_rows,
            "brokered effect request rows left without an outcome at last shutdown \
             (see AUDIT_WRITE_FAILURE events for the affected tables)",
        );
    }

    if let Some(ui_http) = ui_http {
        // Already validated up front, alongside the rest of the config.
        // Inside this block we also bind the UI listener before
        // touching the bearer, so a stale UI-port collision doesn't
        // overwrite the live daemon's bearer either.
        let listener = bind_ui_http_listener(ui_http.bind).await?;
        let bound = listener.local_addr()?;
        let bearer = UiHttpBearerToken::generate();
        let bearer_path =
            ui_http_bearer_path.expect("a ui_http section resolves its bearer path in preflight");
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
