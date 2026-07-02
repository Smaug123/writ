//! The `writd broker` subcommand: a broker that serves a *single* agent-VM HTTP
//! session on a *fixed* port, for the `broker_placement = vm` arm (see
//! `docs/vmnet-accept-bug-and-broker-vm-plan.md`).
//!
//! The host launcher owns the audit session and hands this process its runtime
//! material out-of-band: the daemon config, a [`BrokerSessionSpec`] (which
//! session, which agent subnet, which fixed `bind_addr:broker_port`), and a
//! bearer-token file. This process validates all of that, binds the *named*
//! port (vs. the host daemon's OS-chosen ephemeral port), serves the session,
//! and signals readiness by atomically creating the ready file named in the
//! session spec only once the listener is accepting.
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
use std::time::{Duration, Instant};

use crate::audit::{AuditError, AuditLog};
use crate::broker_protocol::BrokerReadyDoc;
use crate::broker_session::{BearerTokenFileError, BrokerSessionSpec, read_bearer_token_file};
use crate::config::{
    AgentVmHttpConfigError, DaemonConfig, SecretStoreConfig, default_audit_db_path,
};
use crate::core::{AgentKind, AgentVmConfigError, BrokerPort, BrokerPortRange, SessionId};
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

// The broker proves it can actually reach its GitHub API egress dependency
// before it publishes readiness, so the agent never connects (and mints) until
// the per-session egress NAT is forwarding. A freshly-created egress network can
// take a few seconds to warm up; a single early mint that races that warmup
// black-holes its SYN and times out at the connect layer (libcurl-from-inside
// works seconds later — the failure is purely temporal). Gating readiness on a
// real egress probe removes the race; failing loud after the deadline keeps the
// broker's "I can mint" guarantee honest rather than serving a broker that can't.
const EGRESS_PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const EGRESS_PROBE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const EGRESS_PROBE_INTERVAL: Duration = Duration::from_secs(2);
const EGRESS_PROBE_DEADLINE: Duration = Duration::from_secs(90);

/// Inputs for [`run_broker`]. The `writd broker` bin parses the argv paths and,
/// crucially, reads + parses the session spec itself (so telemetry can be
/// installed from the spec's log-file field before `run_broker` runs); interior
/// code therefore receives the typed [`BrokerSessionSpec`], not a path. The
/// spec also carries the ready-file target, so neither is a CLI argument — the
/// `writd broker` argv is frozen to `--config --session-spec --bearer-token-file`.
#[derive(Debug, Clone)]
pub struct BrokerArgs {
    pub config: PathBuf,
    pub session_spec: BrokerSessionSpec,
    pub bearer_token_file: PathBuf,
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
    #[error(
        "broker egress dependency {url} was unreachable after {attempts} attempt(s) over \
         {elapsed_secs}s, so the broker cannot mint tokens or proxy the nix cache: {cause}"
    )]
    EgressUnavailable {
        url: String,
        attempts: u32,
        elapsed_secs: u64,
        cause: String,
    },
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
///
/// Returns the session's selected `agent_kind` (the daemon records it at open
/// time): a broker VM serves exactly one session, so this picks the single
/// GitHub App — and thus the single API root — this broker can ever mint
/// against, which is what the egress readiness gate probes.
fn verify_session_open(
    audit: &AuditLog,
    session_id: SessionId,
) -> Result<Option<AgentKind>, BrokerRunError> {
    match audit
        .get_session(session_id)
        .map_err(|source| BrokerRunError::SessionLookup { source })?
    {
        None => Err(BrokerRunError::SessionNotOpen(session_id)),
        Some(record) if record.closed_at.is_some() => {
            Err(BrokerRunError::SessionClosed(session_id))
        }
        Some(record) => Ok(record.agent_kind),
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
/// content is a [`BrokerReadyDoc`] carrying this broker's protocol version and
/// bound port, so the host can gate a stale image (see
/// [`crate::broker_protocol`]) rather than time out opaquely.
fn write_ready_file_atomic(path: &Path, broker_port: BrokerPort) -> Result<(), BrokerRunError> {
    let ready_err = |source: std::io::Error| BrokerRunError::ReadyFile {
        path: path.display().to_string(),
        source,
    };
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = parent.unwrap_or_else(|| Path::new("."));
    // Derive the temp name from the *target* file name plus this process's PID,
    // not from the broker port: two brokers can share a ready-file directory
    // while reusing the same fixed port (distinct bind addrs, or separate
    // network namespaces), and a port-only temp name would let one broker's
    // rename consume the other's half-written temp — spuriously failing
    // readiness on a listener that is already serving. Per-target + per-process
    // keeps each broker's temp private.
    let target_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("writd-broker-ready");
    let tmp = dir.join(format!(".{target_name}.{}.tmp", std::process::id()));
    let doc = BrokerReadyDoc::current(broker_port.get());
    std::fs::write(&tmp, doc.to_ready_file()).map_err(ready_err)?;
    std::fs::rename(&tmp, path).map_err(|source| {
        // Best-effort cleanup so a failed rename does not leave the temp behind.
        let _ = std::fs::remove_file(&tmp);
        ready_err(source)
    })
}

/// Validate all inputs and assemble the (not-yet-serving) vm_http session on its
/// fixed listener. Splitting this from [`serve_broker`] keeps every fail-fast
/// check testable without spawning a server or waiting on a signal.
/// The fixed-listener session plus the egress dependencies the broker must be
/// able to reach before it publishes readiness. Returned by [`prepare_broker`]
/// so [`run_broker`] can gate readiness on egress without re-reading the config.
struct PreparedBroker {
    session: PreparedVmHttpSession<Box<dyn SecretStore>>,
    /// The GitHub API root of the session's own App (by its `agent_kind`) to
    /// probe for egress — at most one entry; empty if the session's agent_kind
    /// resolves to no configured App.
    egress_probe_urls: Vec<String>,
}

async fn prepare_broker(args: &BrokerArgs) -> Result<PreparedBroker, BrokerRunError> {
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

    // The spec is already parsed by the bin (it needed the log-file field to set
    // up telemetry before this runs); interior code just reads the typed value.
    let spec = &args.session_spec;
    let broker_port = validate_broker_port(spec.broker_port, vm_http_config.broker_port_range())?;
    let bearer = read_bearer_token_file(&args.bearer_token_file)?;

    let audit_db_path = config.audit_db.unwrap_or_else(default_audit_db_path);
    let audit = AuditLog::open(&audit_db_path).map_err(|source| BrokerRunError::AuditOpen {
        path: audit_db_path.display().to_string(),
        source,
    })?;
    let session_agent_kind = verify_session_open(&audit, spec.session_id)?;

    // The vm_http git-clone path reuses the broker's promote runtime config; the
    // remaining BrokerState fields are the host-daemon-only surfaces (notes repo,
    // signing key, run-agent dispatch, push staging) which this first broker
    // slice does not serve.
    let promote_runtime = Some(Arc::new(
        vm_http_config.git_clone().to_promote_runtime_config(),
    ));

    // Egress dependency to confirm before publishing readiness: the API root of
    // the *one* GitHub App this session can mint against (by its agent_kind).
    // Probing every configured App would let an unrelated App's endpoint being
    // down (e.g. a GHES Codex App while this is a github.com Claude session)
    // block a broker that could never use it. An unresolvable agent_kind leaves
    // this empty (no gate) — the minter surfaces that misconfiguration itself.
    // Computed before `config.github_apps` is moved into the minter below.
    let egress_probe_urls: Vec<String> = session_agent_kind
        .as_ref()
        .and_then(|kind| config.github_apps.agent_apps().get(kind))
        .map(|app| vec![format!("{}/", app.api_base.trim_end_matches('/'))])
        .unwrap_or_default();

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
    Ok(PreparedBroker {
        session: prepared,
        egress_probe_urls,
    })
}

/// Block until every configured egress dependency answers an HTTP request, or
/// fail once `deadline` elapses. Wiring only: it builds the reqwest client and
/// delegates the retry/deadline logic to [`wait_for_egress_with`], which is what
/// the tests drive with a fake probe.
async fn wait_for_egress(
    urls: &[String],
    deadline: Duration,
    interval: Duration,
) -> Result<(), BrokerRunError> {
    let client = reqwest::Client::builder()
        .user_agent("writ/0.1")
        .connect_timeout(EGRESS_PROBE_CONNECT_TIMEOUT)
        .timeout(EGRESS_PROBE_REQUEST_TIMEOUT)
        .build()
        .expect("reqwest client constructs with default config");
    wait_for_egress_with(urls, deadline, interval, move |url, attempt_timeout| {
        // Clone the (Arc-backed) client into the future so it owns its handle —
        // no borrow to entangle the probe's lifetime.
        let client = client.clone();
        async move {
            // reqwest's *own* per-request timeout spans connect→response and aborts
            // the request cleanly; capping it by the time left makes the deadline a
            // hard ceiling. (A `tokio::time::timeout` wrapper does not bound it: the
            // dropped future leaves a detached connect task whose teardown can hang
            // until the OS connect timeout.) Any response (even 4xx/5xx) means the
            // egress path forwarded; only transport errors retry.
            client
                .get(&url)
                .timeout(attempt_timeout)
                .send()
                .await
                .map(|response| response.status().as_u16())
                .map_err(|err| crate::server::error_with_source_chain(&err))
        }
    })
    .await
}

/// The retry/deadline core of the egress gate, generic over the probe so it is
/// testable without a real network. `probe(url, attempt_timeout)` returns the
/// upstream status on success or an error string (the source chain) on a
/// transport failure; it must honor `attempt_timeout` so the deadline stays a
/// hard bound. Each attempt is logged so the warmup duration is visible.
async fn wait_for_egress_with<F, Fut>(
    urls: &[String],
    deadline: Duration,
    interval: Duration,
    probe: F,
) -> Result<(), BrokerRunError>
where
    F: Fn(String, Duration) -> Fut,
    Fut: Future<Output = Result<u16, String>>,
{
    let start = Instant::now();
    for url in urls {
        let mut attempt = 0u32;
        let mut last_error: Option<String> = None;
        loop {
            let remaining = deadline.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(BrokerRunError::EgressUnavailable {
                    url: url.clone(),
                    attempts: attempt,
                    elapsed_secs: start.elapsed().as_secs(),
                    cause: last_error.unwrap_or_else(|| {
                        "egress deadline elapsed before any probe completed".to_string()
                    }),
                });
            }
            attempt += 1;
            // Cap each probe by the time left so a black-holed connect can't overrun
            // the deadline by a whole request timeout.
            let attempt_timeout = remaining.min(EGRESS_PROBE_REQUEST_TIMEOUT);
            match probe(url.clone(), attempt_timeout).await {
                Ok(status) => {
                    tracing::info!(
                        %url,
                        attempt,
                        status,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        "broker egress dependency reachable",
                    );
                    break;
                }
                Err(cause) => {
                    tracing::warn!(
                        %url,
                        attempt,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        error = %cause,
                        "broker egress dependency not ready; retrying",
                    );
                    last_error = Some(cause);
                    // Don't sleep past the deadline; the loop-top check then ends it.
                    let remaining_after = deadline.saturating_sub(start.elapsed());
                    tokio::time::sleep(interval.min(remaining_after)).await;
                }
            }
        }
    }
    Ok(())
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
    // Gate readiness on real egress: don't publish the ready file (which the host
    // watches before booting the agent) until the broker can actually reach
    // GitHub. This closes the startup race where the agent's first mint outran
    // the per-session egress NAT warmup and black-holed its connect.
    wait_for_egress(
        &prepared.egress_probe_urls,
        EGRESS_PROBE_DEADLINE,
        EGRESS_PROBE_INTERVAL,
    )
    .await?;
    serve_broker(
        prepared.session,
        Some(args.session_spec.ready_file.as_path()),
        shutdown_signal(),
        SHUTDOWN_GRACE,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{SessionRecord, UnixMillis};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn wait_for_egress_succeeds_on_any_http_response() {
        let server = MockServer::start().await;
        // A 500 is still a *response* — the egress path forwarded the request and
        // got an answer, which is all the readiness gate cares about.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let urls = vec![format!("{}/", server.uri())];
        wait_for_egress(&urls, Duration::from_secs(5), Duration::from_millis(10))
            .await
            .expect("a reachable dependency (even a 500) confirms egress");
    }

    #[tokio::test]
    async fn wait_for_egress_errors_after_deadline_when_unreachable() {
        // Port 1 is reliably closed, so every attempt is a transport error and
        // the gate must give up once the (tiny, test-sized) deadline elapses.
        let urls = vec!["http://127.0.0.1:1/".to_string()];
        let err = wait_for_egress(&urls, Duration::from_millis(200), Duration::from_millis(20))
            .await
            .expect_err("an unreachable dependency must fail the readiness gate");
        match err {
            BrokerRunError::EgressUnavailable { url, attempts, .. } => {
                assert!(url.contains("127.0.0.1:1"), "{url}");
                assert!(attempts >= 1, "attempts={attempts}");
            }
            other => panic!("expected EgressUnavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn egress_loop_retries_a_failing_probe_until_it_succeeds() {
        use std::sync::atomic::{AtomicU32, Ordering};
        // Models the production race the gate exists to fix: the first probes fail
        // (egress NAT still warming) and a later one succeeds, so the gate passes.
        let calls = AtomicU32::new(0);
        let urls = vec!["https://api.example/".to_string()];
        wait_for_egress_with(
            &urls,
            Duration::from_secs(5),
            Duration::from_millis(5),
            |_url, _attempt_timeout| {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 2 {
                        Err("connect error: egress still warming".to_string())
                    } else {
                        Ok(200)
                    }
                }
            },
        )
        .await
        .expect("the gate must pass once a probe finally succeeds");
        assert!(
            calls.load(Ordering::SeqCst) >= 3,
            "expected the gate to retry before the third (succeeding) probe",
        );
    }

    #[tokio::test]
    async fn egress_loop_honors_deadline_with_a_permanently_slow_probe() {
        // The probe consumes exactly the per-attempt budget it is handed, then
        // fails — a deterministic stand-in for a black hole. The loop must cap each
        // attempt by the time left so the *total* wait is ~the deadline, not a
        // whole request timeout (let alone deadline * attempts).
        let urls = vec!["https://api.example/".to_string()];
        let start = Instant::now();
        let err = wait_for_egress_with(
            &urls,
            Duration::from_millis(300),
            Duration::from_millis(10),
            |_url, attempt_timeout| async move {
                tokio::time::sleep(attempt_timeout).await;
                Err::<u16, String>("connect error: operation timed out".to_string())
            },
        )
        .await
        .expect_err("a permanently slow probe must hit the deadline");
        let waited = start.elapsed();
        assert!(
            matches!(err, BrokerRunError::EgressUnavailable { .. }),
            "{err:?}"
        );
        assert!(
            waited < Duration::from_secs(2),
            "the deadline must be a hard bound; waited {waited:?}",
        );
    }

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
    fn verify_session_open_returns_the_sessions_agent_kind() {
        // The egress readiness gate probes the API root of the session's own App,
        // so the session lookup must surface the recorded agent_kind verbatim.
        let audit = AuditLog::open_in_memory().unwrap();
        let session_id = SessionId::new();
        let mut record = open_session_record(session_id);
        record.agent_kind = Some(AgentKind::Codex);
        audit.open_session(&record).unwrap();
        assert_eq!(
            verify_session_open(&audit, session_id).unwrap(),
            Some(AgentKind::Codex),
        );
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
        let doc = crate::broker_protocol::BrokerReadyDoc::parse(
            &std::fs::read_to_string(&ready).unwrap(),
        )
        .unwrap();
        assert_eq!(doc.broker_port, 18085);
        assert_eq!(
            doc.protocol_version,
            crate::broker_protocol::BROKER_PROTOCOL_VERSION
        );
        // No stray temp file left in the directory.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "ready")
            .collect();
        assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
    }

    #[test]
    fn write_ready_file_atomic_distinct_targets_share_no_temp() {
        // Two brokers reusing the same fixed port but writing distinct ready
        // files in one directory must not race on a shared temp name.
        let dir = tempfile::tempdir().unwrap();
        let port = BrokerPort::new(18085).unwrap();
        let ready_a = dir.path().join("ready-a");
        let ready_b = dir.path().join("ready-b");
        write_ready_file_atomic(&ready_a, port).unwrap();
        write_ready_file_atomic(&ready_b, port).unwrap();
        for ready in [&ready_a, &ready_b] {
            let doc = crate::broker_protocol::BrokerReadyDoc::parse(
                &std::fs::read_to_string(ready).unwrap(),
            )
            .unwrap();
            assert_eq!(doc.broker_port, 18085);
        }
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            names.len(),
            2,
            "only the two ready files should remain: {names:?}"
        );
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

        let ready_path = dir.path().join("ready");
        let log_path = dir.path().join("broker.log.jsonl");
        let spec_path = dir.path().join("session-spec.json");
        std::fs::write(
            &spec_path,
            format!(
                r#"{{"version":2,"session_id":"{session_id}","agent_ipv4_cidr":"127.0.0.0/8",
                     "bind_addr":"127.0.0.1","broker_port":{port},
                     "ready_file":"{ready}","log_file":"{log}"}}"#,
                ready = ready_path.display(),
                log = log_path.display(),
            ),
        )
        .unwrap();
        let spec = BrokerSessionSpec::read_file(&spec_path).unwrap();

        let token = "writ-vm-itoken";
        let token_path = dir.path().join("bearer-token");
        std::fs::write(&token_path, format!("{token}\n")).unwrap();

        let args = BrokerArgs {
            config: config_path,
            session_spec: spec,
            bearer_token_file: token_path,
        };

        let prepared = prepare_broker(&args).await.unwrap();
        assert_eq!(
            prepared.session.broker_port().get(),
            port,
            "must bind the fixed spec port"
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let serve_fut = serve_broker(
            prepared.session,
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
        let doc = crate::broker_protocol::BrokerReadyDoc::parse(
            &std::fs::read_to_string(&ready_path).unwrap(),
        )
        .unwrap();
        assert_eq!(doc.broker_port, port);
        assert_eq!(
            doc.protocol_version,
            crate::broker_protocol::BROKER_PROTOCOL_VERSION
        );
    }
}
