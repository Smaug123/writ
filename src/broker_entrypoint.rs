//! The `writd broker` subcommand: a broker that serves a *single* agent-VM HTTP
//! session on a *fixed* port, for the `broker_placement = vm` arm (see
//! `docs/vmnet-accept-bug-and-broker-vm-plan.md`).
//!
//! The host launcher owns the audit session and hands this process its runtime
//! material out-of-band: the daemon config, a [`BrokerSessionSpec`] (which
//! session, which agent subnet, which fixed `bind_addr:broker_port`), and a
//! bearer-token file. This process validates all of that, binds the *named*
//! port (vs. the host daemon's OS-chosen ephemeral port), serves the session,
//! and signals readiness by atomically creating `--ready-file` only once the
//! listener is accepting.
//!
//! Differences from the host daemon (`writd` with no subcommand) are deliberate
//! and load-bearing:
//! - Secret store must be `file` (a host-mounted directory that must already
//!   exist); a `keyring` store has no meaning inside the broker VM.
//! - Only the `vm_http` slice of the agent-VM config is consumed — the lifecycle
//!   config (subnet pool, container tooling) is the *host's* concern and is not
//!   validated here.
//! - The session must already be open in the shared audit DB; this process
//!   never opens or closes sessions.
//! - This first slice serves the clone/nix-cache/proxy surface only: no
//!   agent-run dispatch route and no git-push staging route (both deferred).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::audit::{AuditError, AuditLog};
use crate::broker_session::{
    BearerTokenFileError, BrokerSessionSpec, BrokerSessionSpecError, read_bearer_token_file,
};
use crate::config::{
    AgentVmHttpConfigError, DaemonConfig, SecretStoreConfig, default_audit_db_path,
};
use crate::core::{AgentVmConfigError, BrokerPort, BrokerPortRange, SessionId};
use crate::github::GitHubMinter;
use crate::secret::{FileSecretStore, SecretError, SecretStore};
use crate::server::BrokerState;
use crate::vm_git_mirror_cache::MirrorPins;
use crate::vm_http::{
    PreparedVmHttpSession, VmHttpBindError, VmHttpRuntimeError, VmHttpRuntimeShutdownError,
    bind_vm_http_listener, prepare_vm_http_session_on_listener,
};

/// How long graceful shutdown is allowed to run before the session is dropped
/// (which aborts the runtime task). Bounds teardown so a stuck in-flight handler
/// cannot wedge the broker open past a SIGTERM.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Inputs for [`run_broker`], parsed from the `writd broker` command line.
#[derive(Debug, Clone)]
pub struct BrokerArgs {
    pub config: PathBuf,
    pub session_spec: PathBuf,
    pub bearer_token_file: PathBuf,
    pub ready_file: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerRunError {
    #[error("cannot read config {path}: {source}")]
    ConfigRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid config {path}: {source}")]
    ConfigParse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "broker mode requires a `file` secret store (a host-mounted directory); \
         the configured secret store is `keyring`, which has no meaning inside the broker VM"
    )]
    SecretStoreNotFile,
    #[error("cannot open file secret store: {source}")]
    SecretStoreOpen {
        #[source]
        source: SecretError,
    },
    #[error("broker mode requires an `agent_vm` config section to source the vm_http runtime")]
    AgentVmConfigMissing,
    #[error("invalid vm_http config: {0}")]
    VmHttpConfig(#[from] AgentVmHttpConfigError),
    #[error(transparent)]
    SessionSpec(#[from] BrokerSessionSpecError),
    #[error(transparent)]
    BearerToken(#[from] BearerTokenFileError),
    #[error("session spec broker_port is invalid: {source}")]
    BrokerPort {
        #[source]
        source: AgentVmConfigError,
    },
    #[error(
        "session spec broker_port {port} is outside the configured vm_http broker port range \
         {min}..={max}"
    )]
    BrokerPortOutOfRange { port: u16, min: u16, max: u16 },
    #[error("cannot open audit DB {path}: {source}")]
    AuditOpen {
        path: String,
        #[source]
        source: AuditError,
    },
    #[error("cannot look up audit session: {source}")]
    SessionLookup {
        #[source]
        source: AuditError,
    },
    #[error(
        "audit session {0} is not open (the host launcher must open it before the broker starts)"
    )]
    SessionNotOpen(SessionId),
    #[error("audit session {0} is already closed; the broker refuses to serve a closed session")]
    SessionClosed(SessionId),
    #[error("cannot bind broker listener: {0}")]
    Bind(#[from] VmHttpBindError),
    #[error("cannot assemble vm_http session: {0}")]
    Prepare(#[from] VmHttpRuntimeError),
    #[error("cannot write ready file {path}: {source}")]
    ReadyFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("broker shutdown failed: {0}")]
    Shutdown(#[from] VmHttpRuntimeShutdownError),
}

/// Open the secret store, enforcing the broker-mode invariant that it is a
/// `file` store that *already exists* — `FileSecretStore::open` (not
/// `create_or_open`) means a missing or mis-mounted host directory fails loudly
/// at startup instead of silently materialising an empty store.
fn open_file_secret_store(
    secret_store: &SecretStoreConfig,
) -> Result<Box<dyn SecretStore>, BrokerRunError> {
    match secret_store {
        SecretStoreConfig::File { path } => {
            let store = FileSecretStore::open(path.clone())
                .map_err(|source| BrokerRunError::SecretStoreOpen { source })?;
            Ok(Box::new(store))
        }
        SecretStoreConfig::Keyring { .. } => Err(BrokerRunError::SecretStoreNotFile),
    }
}

/// The session named by the spec must already be open in the shared audit DB:
/// the host launcher owns the session lifecycle, and this process never opens or
/// closes sessions. Refuse to serve an unknown or already-closed session.
fn verify_session_open(audit: &AuditLog, session_id: SessionId) -> Result<(), BrokerRunError> {
    match audit
        .get_session(session_id)
        .map_err(|source| BrokerRunError::SessionLookup { source })?
    {
        None => Err(BrokerRunError::SessionNotOpen(session_id)),
        Some(record) if record.closed_at.is_some() => {
            Err(BrokerRunError::SessionClosed(session_id))
        }
        Some(_) => Ok(()),
    }
}

/// The spec carries the fixed listener port (a runtime fact the host chose);
/// the config carries the allowed range (a policy guardrail). The port must be a
/// valid broker port (non-zero, non-privileged) *and* inside the configured
/// range, so a typo can't make the broker listen somewhere PF won't allow.
fn validate_broker_port(port: u16, range: BrokerPortRange) -> Result<BrokerPort, BrokerRunError> {
    let broker_port =
        BrokerPort::new(port).map_err(|source| BrokerRunError::BrokerPort { source })?;
    if !range.contains(broker_port) {
        return Err(BrokerRunError::BrokerPortOutOfRange {
            port,
            min: range.min().get(),
            max: range.max().get(),
        });
    }
    Ok(broker_port)
}

/// Atomically publish the ready file: write a sibling temp file then rename it
/// into place, so a reader either sees the complete file or no file at all. The
/// content is the bound broker port (a non-empty, self-identifying signal).
fn write_ready_file_atomic(path: &Path, broker_port: BrokerPort) -> Result<(), BrokerRunError> {
    let ready_err = |source: std::io::Error| BrokerRunError::ReadyFile {
        path: path.display().to_string(),
        source,
    };
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = parent.unwrap_or_else(|| Path::new("."));
    // The broker port is unique per broker process, so it uniquely names the
    // temp file within the (host-owned) ready-file directory.
    let tmp = dir.join(format!(".writd-broker-ready.{}.tmp", broker_port.get()));
    std::fs::write(&tmp, format!("{}\n", broker_port.get())).map_err(ready_err)?;
    std::fs::rename(&tmp, path).map_err(|source| {
        // Best-effort cleanup so a failed rename does not leave the temp behind.
        let _ = std::fs::remove_file(&tmp);
        ready_err(source)
    })
}

/// Validate all inputs and assemble the (not-yet-serving) vm_http session on its
/// fixed listener. Splitting this from [`serve_broker`] keeps every fail-fast
/// check testable without spawning a server or waiting on a signal.
async fn prepare_broker(
    args: &BrokerArgs,
) -> Result<PreparedVmHttpSession<Box<dyn SecretStore>>, BrokerRunError> {
    let config_json =
        std::fs::read_to_string(&args.config).map_err(|source| BrokerRunError::ConfigRead {
            path: args.config.display().to_string(),
            source,
        })?;
    let config: DaemonConfig =
        serde_json::from_str(&config_json).map_err(|source| BrokerRunError::ConfigParse {
            path: args.config.display().to_string(),
            source,
        })?;

    let secrets = open_file_secret_store(&config.secret_store)?;

    // Only the vm_http slice is consumed; the lifecycle config (subnet pool,
    // container tooling) is the host's concern and is intentionally not
    // validated here (no `to_runtime_config()` on the whole agent_vm config).
    let agent_vm = config
        .agent_vm
        .ok_or(BrokerRunError::AgentVmConfigMissing)?;
    let vm_http_config = agent_vm.vm_http.to_runtime_config()?;

    let spec = BrokerSessionSpec::read_file(&args.session_spec)?;
    let broker_port = validate_broker_port(spec.broker_port, vm_http_config.broker_port_range())?;
    let bearer = read_bearer_token_file(&args.bearer_token_file)?;

    let audit_db_path = config.audit_db.unwrap_or_else(default_audit_db_path);
    let audit = AuditLog::open(&audit_db_path).map_err(|source| BrokerRunError::AuditOpen {
        path: audit_db_path.display().to_string(),
        source,
    })?;
    verify_session_open(&audit, spec.session_id)?;

    // The vm_http git-clone path reuses the broker's promote runtime config; the
    // remaining BrokerState fields are the host-daemon-only surfaces (notes repo,
    // signing key, run-agent dispatch, push staging) which this first broker
    // slice does not serve.
    let promote_runtime = Some(Arc::new(
        vm_http_config.git_clone().to_promote_runtime_config(),
    ));
    let state = Arc::new(BrokerState {
        audit: Arc::new(audit),
        minter: GitHubMinter::new_registry(config.github_apps),
        secrets,
        policy: config.policy,
        staging_store: None,
        notes_repo: None,
        signing_key: None,
        run_agent_spawn: None,
        promote_runtime,
        mirror_pins: MirrorPins::new(),
    });

    let listener = bind_vm_http_listener(spec.bind_addr, broker_port).await?;
    let prepared = prepare_vm_http_session_on_listener(
        state,
        &vm_http_config,
        spec.session_id,
        spec.agent_ipv4_cidr,
        bearer,
        listener,
        // No agent-run dispatch route and no git-push staging route in this
        // first broker slice (both deferred).
        None,
        None,
    )?;
    Ok(prepared)
}

/// Start accepting traffic, publish readiness, and serve until `shutdown`
/// resolves, then drain within [`SHUTDOWN_GRACE`].
///
/// `shutdown` is injected so tests can drive teardown deterministically;
/// [`run_broker`] passes the real SIGTERM/SIGINT future.
async fn serve_broker(
    prepared: PreparedVmHttpSession<Box<dyn SecretStore>>,
    ready_file: Option<&Path>,
    shutdown: impl Future<Output = ()>,
    grace: Duration,
) -> Result<(), BrokerRunError> {
    let broker_port = prepared.broker_port();
    // The listener was bound in `prepare_broker`, so the socket is in LISTEN
    // state (connections queue in the backlog) from here on; `spawn` hands it to
    // the accept loop. The ready file is therefore written strictly after the
    // port is connectable.
    let running = prepared.spawn();
    if let Some(ready_file) = ready_file {
        write_ready_file_atomic(ready_file, broker_port)?;
    }
    tracing::info!(broker_port = broker_port.get(), "broker session serving");

    shutdown.await;
    tracing::info!("broker received shutdown signal; draining");

    // Bounded graceful shutdown: if draining overruns the grace period, the
    // RunningVmHttpSession is dropped, whose Drop aborts the runtime task — so
    // this function always returns promptly after a shutdown signal.
    match tokio::time::timeout(grace, running.shutdown()).await {
        Ok(result) => result.map_err(BrokerRunError::from),
        Err(_) => {
            tracing::warn!(
                grace_secs = grace.as_secs(),
                "broker drain exceeded grace period; aborting in-flight handlers",
            );
            Ok(())
        }
    }
}

/// Resolve when the process receives SIGTERM or SIGINT.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler for broker");
        let mut interrupt =
            signal(SignalKind::interrupt()).expect("install SIGINT handler for broker");
        tokio::select! {
            _ = term.recv() => {}
            _ = interrupt.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Entry point for `writd broker`: validate, bind the fixed port, serve the
/// single session until SIGTERM/SIGINT, then drain within the grace period.
pub async fn run_broker(args: BrokerArgs) -> Result<(), BrokerRunError> {
    let prepared = prepare_broker(&args).await?;
    serve_broker(
        prepared,
        args.ready_file.as_deref(),
        shutdown_signal(),
        SHUTDOWN_GRACE,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{SessionRecord, UnixMillis};

    fn open_session_record(session_id: SessionId) -> SessionRecord {
        SessionRecord {
            session_id,
            label: None,
            agent_kind: None,
            agent_model: None,
            opened_at: UnixMillis::from_millis(1_700_000_000),
            closed_at: None,
        }
    }

    #[test]
    fn enforce_file_secret_store_rejects_keyring() {
        let cfg = SecretStoreConfig::Keyring {
            service: "writ".into(),
        };
        assert!(matches!(
            open_file_secret_store(&cfg),
            Err(BrokerRunError::SecretStoreNotFile)
        ));
    }

    #[test]
    fn enforce_file_secret_store_requires_existing_directory() {
        // `open` (not `create_or_open`) must fail on a path that was never
        // initialised as a secret store, so a bad host mount is caught at boot.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("never-created");
        let cfg = SecretStoreConfig::File { path: missing };
        assert!(matches!(
            open_file_secret_store(&cfg),
            Err(BrokerRunError::SecretStoreOpen { .. })
        ));
    }

    #[test]
    fn enforce_file_secret_store_opens_initialised_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets");
        // Initialise it the way the host would, then prove `open` accepts it.
        FileSecretStore::create_or_open(path.clone()).unwrap();
        assert!(open_file_secret_store(&SecretStoreConfig::File { path }).is_ok());
    }

    #[test]
    fn verify_session_open_accepts_open_session() {
        let audit = AuditLog::open_in_memory().unwrap();
        let session_id = SessionId::new();
        audit
            .open_session(&open_session_record(session_id))
            .unwrap();
        assert!(verify_session_open(&audit, session_id).is_ok());
    }

    #[test]
    fn verify_session_open_rejects_missing_session() {
        let audit = AuditLog::open_in_memory().unwrap();
        let session_id = SessionId::new();
        assert!(matches!(
            verify_session_open(&audit, session_id),
            Err(BrokerRunError::SessionNotOpen(s)) if s == session_id
        ));
    }

    #[test]
    fn verify_session_open_rejects_closed_session() {
        let audit = AuditLog::open_in_memory().unwrap();
        let session_id = SessionId::new();
        audit
            .open_session(&open_session_record(session_id))
            .unwrap();
        audit
            .close_session(session_id, UnixMillis::from_millis(1_700_000_500))
            .unwrap();
        assert!(matches!(
            verify_session_open(&audit, session_id),
            Err(BrokerRunError::SessionClosed(s)) if s == session_id
        ));
    }

    #[test]
    fn validate_broker_port_accepts_in_range_port() {
        let range = BrokerPortRange::new(18080, 18090).unwrap();
        let port = validate_broker_port(18085, range).unwrap();
        assert_eq!(port.get(), 18085);
    }

    #[test]
    fn validate_broker_port_rejects_out_of_range_port() {
        let range = BrokerPortRange::new(18080, 18090).unwrap();
        assert!(matches!(
            validate_broker_port(18100, range),
            Err(BrokerRunError::BrokerPortOutOfRange {
                port: 18100,
                min: 18080,
                max: 18090,
            })
        ));
    }

    #[test]
    fn validate_broker_port_rejects_privileged_port() {
        let range = BrokerPortRange::new(18080, 18090).unwrap();
        assert!(matches!(
            validate_broker_port(80, range),
            Err(BrokerRunError::BrokerPort { .. })
        ));
    }

    #[test]
    fn write_ready_file_atomic_writes_port_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let ready = dir.path().join("ready");
        let port = BrokerPort::new(18085).unwrap();
        write_ready_file_atomic(&ready, port).unwrap();
        assert_eq!(std::fs::read_to_string(&ready).unwrap(), "18085\n");
        // No stray temp file left in the directory.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "ready")
            .collect();
        assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
    }

    async fn free_loopback_port() -> u16 {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    /// A minimal daemon config whose `vm_http` slice converts cleanly. The
    /// lifecycle section only has to *parse* — broker mode never converts it.
    fn broker_config_json(
        secret_dir: &Path,
        audit_db: &Path,
        work_root: &Path,
        port: u16,
    ) -> String {
        format!(
            r#"{{
                "github_apps": {{
                    "claude": {{
                        "app_id": 1,
                        "installation_id": 2,
                        "installation_owner": "o",
                        "private_key_secret": "pk"
                    }}
                }},
                "policy": {{ "default_ttl": 600, "writable_repos": [] }},
                "secret_store": {{ "type": "file", "path": "{secret_dir}" }},
                "audit_db": "{audit_db}",
                "agent_vm": {{
                    "lifecycle": {{
                        "ipv4_pool": "192.168.0.0/16",
                        "ipv6_pool": "fd83:b6f2:e57::/48",
                        "subnet_index_min": 252,
                        "subnet_index_max": 253,
                        "pf_helper": "/usr/local/libexec/writ-agent-vm-pf-helper",
                        "ipv6_mode": "ipv4_only_no_guest_ipv6",
                        "image": "alpine:latest",
                        "cpus": 1,
                        "memory_mib": 512
                    }},
                    "vm_http": {{
                        "bind_addr": "127.0.0.1",
                        "broker_port_min": {port},
                        "broker_port_max": {port},
                        "git_program": "/usr/bin/git",
                        "git_clone_base_url": "https://github.com",
                        "askpass_program": "/usr/local/libexec/writ-git-askpass",
                        "work_root": "{work_root}",
                        "clone_timeout_secs": 30,
                        "max_bundle_bytes": 1048576,
                        "nix_cache_url": "https://cache.nixos.org",
                        "nix_cache_trusted_public_keys": [],
                        "nix_cache_max_metadata_bytes": 1048576,
                        "nix_cache_max_nar_bytes": 67108864
                    }}
                }}
            }}"#,
            secret_dir = secret_dir.display(),
            audit_db = audit_db.display(),
            work_root = work_root.display(),
        )
    }

    async fn http_request_over_tcp(port: u16, request: &str) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    /// End-to-end: a real config + spec + token file drives `prepare_broker` to
    /// bind the *fixed* port from the spec, and `serve_broker` to publish the
    /// ready file only once the port is serving, authenticate with the
    /// file-supplied bearer, and drain cleanly on the injected shutdown.
    #[tokio::test]
    async fn prepare_and_serve_broker_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let port = free_loopback_port().await;

        // The host owns the secret store (must pre-exist) and the audit session.
        let secret_dir = dir.path().join("secrets");
        FileSecretStore::create_or_open(secret_dir.clone()).unwrap();
        let audit_db = dir.path().join("audit.db");
        let session_id = SessionId::new();
        {
            let audit = AuditLog::open(&audit_db).unwrap();
            audit
                .open_session(&open_session_record(session_id))
                .unwrap();
        }

        let config_path = dir.path().join("config.json");
        let work_root = dir.path().join("work-root");
        std::fs::write(
            &config_path,
            broker_config_json(&secret_dir, &audit_db, &work_root, port),
        )
        .unwrap();

        let spec_path = dir.path().join("session-spec.json");
        std::fs::write(
            &spec_path,
            format!(
                r#"{{"version":1,"session_id":"{session_id}","agent_ipv4_cidr":"127.0.0.0/8",
                     "bind_addr":"127.0.0.1","broker_port":{port}}}"#
            ),
        )
        .unwrap();

        let token = "writ-vm-itoken";
        let token_path = dir.path().join("bearer-token");
        std::fs::write(&token_path, format!("{token}\n")).unwrap();

        let ready_path = dir.path().join("ready");

        let args = BrokerArgs {
            config: config_path,
            session_spec: spec_path,
            bearer_token_file: token_path,
            ready_file: Some(ready_path.clone()),
        };

        let prepared = prepare_broker(&args).await.unwrap();
        assert_eq!(
            prepared.broker_port().get(),
            port,
            "must bind the fixed spec port"
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let serve_fut = serve_broker(
            prepared,
            Some(ready_path.as_path()),
            async move {
                let _ = shutdown_rx.await;
            },
            Duration::from_secs(5),
        );

        let control_fut = async {
            // The ready file appears strictly after the port is serving.
            for _ in 0..500 {
                if ready_path.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(ready_path.exists(), "ready file should appear once serving");

            let unauth = http_request_over_tcp(
                port,
                "GET /v1/session HTTP/1.1\r\nHost: broker\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(
                unauth.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
                "unauthenticated request must be rejected: {unauth}"
            );

            let authed = http_request_over_tcp(
                port,
                &format!(
                    "GET /v1/session HTTP/1.1\r\nHost: broker\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
                ),
            )
            .await;
            assert!(
                authed.starts_with("HTTP/1.1 200 OK\r\n"),
                "file-supplied bearer must authenticate: {authed}"
            );
            assert!(
                authed.contains(&session_id.to_string()),
                "session response should name the session: {authed}"
            );

            let _ = shutdown_tx.send(());
        };

        let (serve_result, ()) = tokio::join!(serve_fut, control_fut);
        serve_result.unwrap();
        assert_eq!(
            std::fs::read_to_string(&ready_path).unwrap(),
            format!("{port}\n")
        );
    }
}
