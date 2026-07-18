//! VM-facing broker HTTP endpoint.
//!
//! This is deliberately separate from the host Unix-socket protocol. The VM
//! endpoint authenticates one managed agent VM session with a bearer secret and
//! a source-subnet check, then exposes only VM-safe broker operations.

mod agent_runs;
mod broker_effect;
mod claude_proxy;
mod flake_provision;
mod git_clone;
mod git_push;
mod nix_cache;
mod openai_proxy;
mod proxy_common;

pub use agent_runs::VmHttpAgentRunService;
use agent_runs::{
    parse_agent_run_config_target, parse_agent_run_outcome_target, route_agent_run_config_request,
    route_agent_run_outcome_request,
};
use broker_effect::broker_effect;
use claude_proxy::VmHttpClaudeProxyService;
pub use claude_proxy::{
    DEFAULT_CLAUDE_ANTHROPIC_VERSION, VmHttpClaudeProxyAuthKind, VmHttpClaudeProxyConfig,
    VmHttpClaudeProxyConfigError,
};
pub use flake_provision::{VmHttpFlakeProvisionConfig, VmHttpFlakeProvisionService};
use flake_provision::{is_flake_provision_target, route_flake_provision_request};
pub use git_clone::{VmHttpGitCloneConfig, VmHttpGitCloneService};
use git_clone::{is_git_clone_target, route_git_clone_request};
pub use git_push::VmHttpGitPushService;
use git_push::{is_git_push_target, route_git_push_request};
#[cfg(test)]
use nix_cache::route_nix_cache_request_without_upstream;
pub use nix_cache::{
    VM_NIX_BASIC_LOGIN, VM_NIX_CACHE_PATH_PREFIX, VM_NIX_PREWARM_PATH_PREFIX, VmHttpNixCacheConfig,
    VmHttpNixCacheConfigError, VmHttpNixCacheService,
};
use nix_cache::{is_nix_cache_target, record_nix_cache_local_response, route_nix_cache_request};
use openai_proxy::VmHttpOpenAiProxyService;
pub use openai_proxy::{
    VmHttpOpenAiProxyAuthKind, VmHttpOpenAiProxyConfig, VmHttpOpenAiProxyConfigError,
};
use proxy_common::{
    ClaudeBackend, OpenAiBackend, ProxyBackend, ProxyEffect, ProxyStream,
    record_proxy_local_response,
};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, Limited, combinators::UnsyncBoxBody};
use hyper::body::{Body as HyperBody, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::audit::{NixCacheAuditDecision, ProxyAuditDecision};
use crate::bearer::is_bearer_token_byte;
use crate::core::{BrokerPort, BrokerPortRange, Ipv4Cidr, SessionId};
use crate::secret::SecretStore;
use crate::server::BrokerState;
use crate::vm_git::VmGitPushBodyLimits;

const MAX_VM_HTTP_BODY_BYTES: usize = 64 * 1024;
const MAX_VM_HTTP_AGENT_RUN_OUTCOME_BODY_BYTES: usize = 4 * 1024 * 1024;
const VM_HTTP_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const EPHEMERAL_BIND_ATTEMPTS: usize = 32;
const MAX_VM_HTTP_CONNECTIONS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpSession {
    session_id: SessionId,
    source_ipv4: Ipv4Cidr,
    bearer_token: VmHttpBearerToken,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VmHttpBearerToken(String);

#[derive(Debug)]
pub struct BoundVmHttpListener {
    listener: TcpListener,
    broker_port: BrokerPort,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpRequest {
    method: String,
    target: String,
    authorization: Option<String>,
    content_length: Option<usize>,
    headers: Vec<VmHttpHeader>,
    peer_addr: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VmHttpHeader {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpRuntimeConfig {
    bind_addr: Ipv4Addr,
    broker_port_range: BrokerPortRange,
    git_clone: VmHttpGitCloneConfig,
    nix_cache: VmHttpNixCacheConfig,
    claude_proxy: Option<VmHttpClaudeProxyConfig>,
    openai_proxy: Option<VmHttpOpenAiProxyConfig>,
    agent_run_log_root: PathBuf,
    git_push_staging_root: PathBuf,
    git_push_body_limits: VmGitPushBodyLimits,
    /// Flake-input provisioning. `None` disables the `/v1/nix/flake/provision`
    /// endpoint (it answers `404`); it is enabled only when the `(repo, rev)`
    /// mirror cache that backs it is configured, since provisioning re-derives
    /// the checkout from a retained mirror.
    flake_provision: Option<VmHttpFlakeProvisionConfig>,
    /// The operator-managed pre-warm cache dir, when configured. The serving
    /// side only sees the role-agnostic ordered dir list inside `nix_cache`;
    /// this records the *role* so the daemon can tell whether pre-warming is in
    /// effect (and so advertise the strict `/v1/nix/prewarm` substituter to the
    /// guest warm). `None` leaves the warm on the proxied view, as before.
    nix_prewarm_cache_dir: Option<PathBuf>,
}

pub struct PreparedVmHttpSession<S: SecretStore + Send + Sync + 'static> {
    listener: BoundVmHttpListener,
    session: VmHttpSession,
    git_clone: VmHttpGitCloneService<S>,
    nix_cache: VmHttpNixCacheService<S>,
    proxies: VmHttpProxies<S>,
    agent_runs: Option<VmHttpAgentRunService<S>>,
    git_push: Option<VmHttpGitPushService<S>>,
    flake_provision: Option<VmHttpFlakeProvisionService<S>>,
}

pub(in crate::vm_http) struct VmHttpProxies<S: SecretStore + Send + Sync + 'static> {
    pub(in crate::vm_http) claude: Option<VmHttpClaudeProxyService<S>>,
    pub(in crate::vm_http) openai: Option<VmHttpOpenAiProxyService<S>>,
}

impl<S: SecretStore + Send + Sync + 'static> Clone for VmHttpProxies<S> {
    fn clone(&self) -> Self {
        Self {
            claude: self.claude.clone(),
            openai: self.openai.clone(),
        }
    }
}

struct VmHttpServices<S: SecretStore + Send + Sync + 'static> {
    git_clone: Option<VmHttpGitCloneService<S>>,
    nix_cache: Option<VmHttpNixCacheService<S>>,
    claude_proxy: Option<VmHttpClaudeProxyService<S>>,
    openai_proxy: Option<VmHttpOpenAiProxyService<S>>,
    agent_runs: Option<VmHttpAgentRunService<S>>,
    git_push: Option<VmHttpGitPushService<S>>,
    flake_provision: Option<VmHttpFlakeProvisionService<S>>,
}

pub struct RunningVmHttpSession {
    broker_port: BrokerPort,
    bearer_token: VmHttpBearerToken,
    shutdown: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VmHttpAuthorization {
    Allow,
    Deny(VmHttpAuthError),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VmHttpAuthError {
    MissingCredentials,
    WrongCredentials,
    SourceOutsideSessionSubnet,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum VmHttpConfigError {
    #[error("VM HTTP bearer token must not be empty")]
    EmptyBearerToken,
    #[error("VM HTTP bearer token must contain only unreserved ASCII token characters")]
    InvalidBearerToken,
}

#[derive(Debug, thiserror::Error)]
pub enum VmHttpBindError {
    #[error("cannot bind VM HTTP listener: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not bind a VM HTTP port in allowed range {min}-{max} after {attempts} attempts")]
    NoAllowedPort { attempts: usize, min: u16, max: u16 },
}

#[derive(Debug, thiserror::Error)]
pub enum VmHttpRuntimeError {
    #[error(transparent)]
    Bind(#[from] VmHttpBindError),
    #[error("cannot construct Claude proxy HTTP client: {0}")]
    ClaudeProxyClient(reqwest::Error),
    #[error("cannot construct OpenAI proxy HTTP client: {0}")]
    OpenAiProxyClient(reqwest::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum VmHttpRuntimeShutdownError {
    #[error("VM HTTP task join failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("VM HTTP server failed: {0}")]
    Server(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
enum VmHttpParseError {
    #[error("duplicate Authorization header")]
    DuplicateAuthorization,
    #[error("duplicate Content-Length header")]
    DuplicateContentLength,
    #[error("invalid Content-Length header")]
    InvalidContentLength,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum VmHttpStatus {
    Ok,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    Conflict,
    Gone,
    UnprocessableContent,
    BadGateway,
    InternalServerError,
    Upstream(u16),
}

#[derive(Debug, Eq, PartialEq)]
struct VmHttpResponse {
    status: VmHttpStatus,
    content_type: &'static str,
    body: Vec<u8>,
    content_length: Option<u64>,
    www_authenticate: Option<&'static str>,
    headers: Vec<VmHttpResponseHeader>,
}

#[derive(Debug, Eq, PartialEq)]
struct VmHttpResponseHeader {
    name: &'static str,
    value: String,
}

#[derive(Serialize)]
struct SessionResponse {
    session_id: SessionId,
    api: &'static str,
    version: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum VmHttpAuthScheme {
    Bearer,
    Basic,
}

enum VmHttpDispatch {
    Buffered(VmHttpResponse),
    ClaudeProxyStream(ProxyStream<ClaudeBackend>),
    OpenAiProxyStream(ProxyStream<OpenAiBackend>),
}

impl VmHttpSession {
    pub fn new(
        session_id: SessionId,
        source_ipv4: Ipv4Cidr,
        bearer_token: VmHttpBearerToken,
    ) -> Self {
        Self {
            session_id,
            source_ipv4,
            bearer_token,
        }
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn source_ipv4(&self) -> Ipv4Cidr {
        self.source_ipv4
    }

    pub fn bearer_token(&self) -> &VmHttpBearerToken {
        &self.bearer_token
    }
}

impl VmHttpBearerToken {
    pub fn generate() -> Self {
        Self(format!(
            "writ-vm-{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ))
    }

    pub fn new(raw: impl Into<String>) -> Result<Self, VmHttpConfigError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(VmHttpConfigError::EmptyBearerToken);
        }
        if !raw.bytes().all(is_bearer_token_byte) {
            return Err(VmHttpConfigError::InvalidBearerToken);
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for VmHttpBearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VmHttpBearerToken(<redacted>)")
    }
}

impl BoundVmHttpListener {
    pub fn broker_port(&self) -> BrokerPort {
        self.broker_port
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn into_listener(self) -> TcpListener {
        self.listener
    }
}

impl VmHttpRequest {
    pub fn new(
        method: impl Into<String>,
        target: impl Into<String>,
        authorization: Option<String>,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            method: method.into(),
            target: target.into(),
            authorization,
            content_length: None,
            headers: Vec::new(),
            peer_addr,
        }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl<S: SecretStore + Send + Sync + 'static> VmHttpServices<S> {
    fn none() -> Self {
        Self {
            git_clone: None,
            nix_cache: None,
            claude_proxy: None,
            openai_proxy: None,
            agent_runs: None,
            git_push: None,
            flake_provision: None,
        }
    }

    fn with_git(
        git_clone: VmHttpGitCloneService<S>,
        nix_cache: VmHttpNixCacheService<S>,
        proxies: VmHttpProxies<S>,
        agent_runs: Option<VmHttpAgentRunService<S>>,
        git_push: Option<VmHttpGitPushService<S>>,
        flake_provision: Option<VmHttpFlakeProvisionService<S>>,
    ) -> Self {
        Self {
            git_clone: Some(git_clone),
            nix_cache: Some(nix_cache),
            claude_proxy: proxies.claude,
            openai_proxy: proxies.openai,
            agent_runs,
            git_push,
            flake_provision,
        }
    }
}

impl<S: SecretStore + Send + Sync + 'static> Clone for VmHttpServices<S> {
    fn clone(&self) -> Self {
        Self {
            git_clone: self.git_clone.clone(),
            nix_cache: self.nix_cache.clone(),
            claude_proxy: self.claude_proxy.clone(),
            openai_proxy: self.openai_proxy.clone(),
            agent_runs: self.agent_runs.clone(),
            git_push: self.git_push.clone(),
            flake_provision: self.flake_provision.clone(),
        }
    }
}

impl VmHttpRuntimeConfig {
    pub fn new(
        bind_addr: Ipv4Addr,
        broker_port_range: BrokerPortRange,
        git_clone: VmHttpGitCloneConfig,
        nix_cache: VmHttpNixCacheConfig,
        agent_run_log_root: impl Into<PathBuf>,
        git_push_staging_root: impl Into<PathBuf>,
        git_push_body_limits: VmGitPushBodyLimits,
    ) -> Self {
        Self::new_with_claude_proxy(
            bind_addr,
            broker_port_range,
            git_clone,
            nix_cache,
            None,
            agent_run_log_root,
            git_push_staging_root,
            git_push_body_limits,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_claude_proxy(
        bind_addr: Ipv4Addr,
        broker_port_range: BrokerPortRange,
        git_clone: VmHttpGitCloneConfig,
        nix_cache: VmHttpNixCacheConfig,
        claude_proxy: Option<VmHttpClaudeProxyConfig>,
        agent_run_log_root: impl Into<PathBuf>,
        git_push_staging_root: impl Into<PathBuf>,
        git_push_body_limits: VmGitPushBodyLimits,
    ) -> Self {
        Self::new_with_proxies(
            bind_addr,
            broker_port_range,
            git_clone,
            nix_cache,
            claude_proxy,
            None,
            agent_run_log_root,
            git_push_staging_root,
            git_push_body_limits,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_proxies(
        bind_addr: Ipv4Addr,
        broker_port_range: BrokerPortRange,
        git_clone: VmHttpGitCloneConfig,
        nix_cache: VmHttpNixCacheConfig,
        claude_proxy: Option<VmHttpClaudeProxyConfig>,
        openai_proxy: Option<VmHttpOpenAiProxyConfig>,
        agent_run_log_root: impl Into<PathBuf>,
        git_push_staging_root: impl Into<PathBuf>,
        git_push_body_limits: VmGitPushBodyLimits,
    ) -> Self {
        Self {
            bind_addr,
            broker_port_range,
            git_clone,
            nix_cache,
            claude_proxy,
            openai_proxy,
            agent_run_log_root: agent_run_log_root.into(),
            git_push_staging_root: git_push_staging_root.into(),
            git_push_body_limits,
            flake_provision: None,
            nix_prewarm_cache_dir: None,
        }
    }

    /// Enable flake-input provisioning with the given config. `None` (the
    /// default) leaves the `/v1/nix/flake/provision` endpoint disabled.
    pub fn with_flake_provision(
        mut self,
        flake_provision: Option<VmHttpFlakeProvisionConfig>,
    ) -> Self {
        self.flake_provision = flake_provision;
        self
    }

    pub fn flake_provision(&self) -> Option<&VmHttpFlakeProvisionConfig> {
        self.flake_provision.as_ref()
    }

    /// Record the configured pre-warm cache dir (see the field docs). The same
    /// path must already lead the nix-cache config's ordered local dir list;
    /// this records only the role.
    pub fn with_nix_prewarm_cache_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.nix_prewarm_cache_dir = dir;
        self
    }

    pub fn nix_prewarm_cache_dir(&self) -> Option<&Path> {
        self.nix_prewarm_cache_dir.as_deref()
    }

    pub fn bind_addr(&self) -> Ipv4Addr {
        self.bind_addr
    }

    pub fn broker_port_range(&self) -> BrokerPortRange {
        self.broker_port_range
    }

    pub fn git_clone(&self) -> &VmHttpGitCloneConfig {
        &self.git_clone
    }

    pub fn nix_cache(&self) -> &VmHttpNixCacheConfig {
        &self.nix_cache
    }

    pub fn claude_proxy(&self) -> Option<&VmHttpClaudeProxyConfig> {
        self.claude_proxy.as_ref()
    }

    pub fn openai_proxy(&self) -> Option<&VmHttpOpenAiProxyConfig> {
        self.openai_proxy.as_ref()
    }

    pub fn agent_run_log_root(&self) -> &Path {
        &self.agent_run_log_root
    }

    pub fn git_push_staging_root(&self) -> &Path {
        &self.git_push_staging_root
    }

    pub fn git_push_body_limits(&self) -> VmGitPushBodyLimits {
        self.git_push_body_limits
    }
}

impl<S: SecretStore + Send + Sync + 'static> PreparedVmHttpSession<S> {
    pub fn broker_port(&self) -> BrokerPort {
        self.listener.broker_port()
    }

    pub fn bearer_token(&self) -> &VmHttpBearerToken {
        self.session.bearer_token()
    }

    pub fn session(&self) -> &VmHttpSession {
        &self.session
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start accepting VM HTTP requests.
    ///
    /// Call this only after installing PF rules for [`Self::broker_port`] and
    /// after the VM start plan has the matching bearer token. The prepared
    /// listener is already bound before `spawn`, but no guest connection can be
    /// accepted until this method hands the listener to the runtime task.
    pub fn spawn(self) -> RunningVmHttpSession {
        let broker_port = self.listener.broker_port();
        let bearer_token = self.session.bearer_token().clone();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_vm_http_with_services_until_shutdown(
            self.listener.into_listener(),
            self.session,
            self.git_clone,
            self.nix_cache,
            self.proxies,
            self.agent_runs,
            self.git_push,
            self.flake_provision,
            shutdown_rx,
        ));
        RunningVmHttpSession {
            broker_port,
            bearer_token,
            shutdown: shutdown_tx,
            task: Some(task),
        }
    }
}

impl RunningVmHttpSession {
    pub fn broker_port(&self) -> BrokerPort {
        self.broker_port
    }

    pub fn bearer_token(&self) -> &VmHttpBearerToken {
        &self.bearer_token
    }

    /// Request graceful shutdown and wait for the VM HTTP runtime task to exit.
    ///
    /// Prefer this explicit path during lifecycle teardown. Dropping the handle
    /// still signals shutdown and aborts the task as a last-resort cleanup path,
    /// but `shutdown` is the path that observes runtime failures.
    pub async fn shutdown(mut self) -> Result<(), VmHttpRuntimeShutdownError> {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
}

impl Drop for RunningVmHttpSession {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub async fn bind_ephemeral_vm_http_listener(
    bind_addr: Ipv4Addr,
    allowed_ports: BrokerPortRange,
) -> Result<BoundVmHttpListener, VmHttpBindError> {
    let min = allowed_ports.min().get();
    let max = allowed_ports.max().get();
    let mut attempts = 0;

    for _ in 0..EPHEMERAL_BIND_ATTEMPTS {
        attempts += 1;
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(bind_addr), 0)).await?;
        let port = listener.local_addr()?.port();
        let Ok(broker_port) = BrokerPort::new(port) else {
            continue;
        };
        if allowed_ports.contains(broker_port) {
            return Ok(BoundVmHttpListener {
                listener,
                broker_port,
            });
        }
    }

    let width = u32::from(max) - u32::from(min) + 1;
    let start = (uuid::Uuid::new_v4().as_u128() % u128::from(width)) as u32;
    for offset in 0..width {
        let port = min + ((start + offset) % width) as u16;
        let broker_port =
            BrokerPort::new(port).expect("ports inside a BrokerPortRange are broker ports");
        attempts += 1;
        match TcpListener::bind(SocketAddr::new(IpAddr::V4(bind_addr), port)).await {
            Ok(listener) => {
                return Ok(BoundVmHttpListener {
                    listener,
                    broker_port,
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(err) => return Err(VmHttpBindError::Io(err)),
        }
    }

    Err(VmHttpBindError::NoAllowedPort { attempts, min, max })
}

/// Bind the VM HTTP listener on a *specific* broker port (vs.
/// [`bind_ephemeral_vm_http_listener`], which lets the OS pick within a range).
///
/// Used when the broker URL must be known ahead of time rather than discovered
/// after binding — e.g. a broker that runs in its own VM, whose `host:port` the
/// host launcher hands to the agent VM before the broker is reachable.
pub async fn bind_vm_http_listener(
    bind_addr: Ipv4Addr,
    port: BrokerPort,
) -> Result<BoundVmHttpListener, VmHttpBindError> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(bind_addr), port.get())).await?;
    Ok(BoundVmHttpListener {
        listener,
        broker_port: port,
    })
}

/// Bind and prepare a per-session VM HTTP runtime without accepting traffic.
///
/// The returned listener owns a concrete broker port before the VM is started.
/// Lifecycle code should install PF rules for [`PreparedVmHttpSession::broker_port`],
/// pass [`PreparedVmHttpSession::bearer_token`] to the guest, and only then
/// call [`PreparedVmHttpSession::spawn`].
pub async fn prepare_vm_http_session<S: SecretStore + Send + Sync + 'static>(
    state: Arc<BrokerState<S>>,
    config: &VmHttpRuntimeConfig,
    session_id: SessionId,
    source_ipv4: Ipv4Cidr,
) -> Result<PreparedVmHttpSession<S>, VmHttpRuntimeError> {
    prepare_vm_http_session_with_agent_runs(state, config, session_id, source_ipv4, None, None)
        .await
}

pub async fn prepare_vm_http_session_with_agent_runs<S: SecretStore + Send + Sync + 'static>(
    state: Arc<BrokerState<S>>,
    config: &VmHttpRuntimeConfig,
    session_id: SessionId,
    source_ipv4: Ipv4Cidr,
    agent_runs: Option<VmHttpAgentRunService<S>>,
    git_push: Option<VmHttpGitPushService<S>>,
) -> Result<PreparedVmHttpSession<S>, VmHttpRuntimeError> {
    let listener =
        bind_ephemeral_vm_http_listener(config.bind_addr, config.broker_port_range).await?;
    prepare_vm_http_session_on_listener(
        state,
        config,
        session_id,
        source_ipv4,
        VmHttpBearerToken::generate(),
        listener,
        agent_runs,
        git_push,
    )
}

/// Assemble a per-session VM HTTP runtime on an already-bound listener with a
/// caller-supplied bearer token.
///
/// [`prepare_vm_http_session_with_agent_runs`] is the host-broker path: it binds
/// an ephemeral port and generates the bearer itself, since the daemon owns both.
/// This variant takes the listener and bearer as inputs, for when both must be
/// fixed ahead of time and shared — e.g. a broker that runs in its own VM
/// (`broker_placement = vm`), where the host launcher hands the *same* broker URL
/// (a fixed port) and bearer token to the agent VM. The service assembly is
/// identical; only how the listener and bearer are obtained differs.
#[allow(clippy::too_many_arguments)]
pub fn prepare_vm_http_session_on_listener<S: SecretStore + Send + Sync + 'static>(
    state: Arc<BrokerState<S>>,
    config: &VmHttpRuntimeConfig,
    session_id: SessionId,
    source_ipv4: Ipv4Cidr,
    bearer_token: VmHttpBearerToken,
    listener: BoundVmHttpListener,
    agent_runs: Option<VmHttpAgentRunService<S>>,
    git_push: Option<VmHttpGitPushService<S>>,
) -> Result<PreparedVmHttpSession<S>, VmHttpRuntimeError> {
    let session = VmHttpSession::new(session_id, source_ipv4, bearer_token);
    let git_clone = VmHttpGitCloneService::new(Arc::clone(&state), config.git_clone.clone());
    let nix_cache = VmHttpNixCacheService::new(Arc::clone(&state), config.nix_cache.clone());
    let claude_proxy = config
        .claude_proxy
        .clone()
        .map(|config| VmHttpClaudeProxyService::new(Arc::clone(&state), config))
        .transpose()
        .map_err(VmHttpRuntimeError::ClaudeProxyClient)?;
    let openai_proxy = config
        .openai_proxy
        .clone()
        .map(|config| VmHttpOpenAiProxyService::new(Arc::clone(&state), config))
        .transpose()
        .map_err(VmHttpRuntimeError::OpenAiProxyClient)?;
    let flake_provision = config
        .flake_provision
        .clone()
        .map(|config| VmHttpFlakeProvisionService::new(Arc::clone(&state), config));
    Ok(PreparedVmHttpSession {
        listener,
        session,
        git_clone,
        nix_cache,
        proxies: VmHttpProxies {
            claude: claude_proxy,
            openai: openai_proxy,
        },
        agent_runs,
        git_push,
        flake_provision,
    })
}

pub async fn run_vm_http(listener: TcpListener, session: VmHttpSession) -> std::io::Result<()> {
    // No external shutdown signal: callers that choose this convenience
    // wrapper stop it by aborting the owning task.
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    run_vm_http_until_shutdown(listener, session, shutdown_rx).await
}

pub async fn run_vm_http_until_shutdown(
    listener: TcpListener,
    session: VmHttpSession,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    run_vm_http_runtime_until_shutdown::<Box<dyn SecretStore>>(
        listener,
        session,
        VmHttpServices::none(),
        shutdown,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(in crate::vm_http) async fn run_vm_http_with_services_until_shutdown<
    S: SecretStore + Send + Sync + 'static,
>(
    listener: TcpListener,
    session: VmHttpSession,
    git_clone: VmHttpGitCloneService<S>,
    nix_cache: VmHttpNixCacheService<S>,
    proxies: VmHttpProxies<S>,
    agent_runs: Option<VmHttpAgentRunService<S>>,
    git_push: Option<VmHttpGitPushService<S>>,
    flake_provision: Option<VmHttpFlakeProvisionService<S>>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    run_vm_http_runtime_until_shutdown(
        listener,
        session,
        VmHttpServices::with_git(
            git_clone,
            nix_cache,
            proxies,
            agent_runs,
            git_push,
            flake_provision,
        ),
        shutdown,
    )
    .await
}

async fn run_vm_http_runtime_until_shutdown<S: SecretStore + Send + Sync + 'static>(
    listener: TcpListener,
    session: VmHttpSession,
    services: VmHttpServices<S>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let mut handlers = JoinSet::new();

    loop {
        if *shutdown.borrow() {
            break;
        }

        tokio::select! {
            biased;

            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }

            // Poll completed handlers before accepting another connection so
            // a ready accept stream cannot accumulate completed JoinSet tasks.
            Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                report_vm_http_handler_result(result);
            }

            accepted = listener.accept(), if handlers.len() < MAX_VM_HTTP_CONNECTIONS => {
                let (stream, peer_addr) = accepted?;
                let session = session.clone();
                let services = services.clone();
                handlers.spawn(async move {
                    handle_vm_http_connection(stream, peer_addr, session, services).await
                });
            }
        }
    }

    while let Some(result) = handlers.join_next().await {
        report_vm_http_handler_result(result);
    }

    Ok(())
}

pub fn authorize_vm_http_request(
    session: &VmHttpSession,
    request: &VmHttpRequest,
) -> VmHttpAuthorization {
    authorize_vm_http_request_with_scheme(session, request, auth_scheme_for_target(&request.target))
}

fn authorize_vm_http_request_with_scheme(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    scheme: VmHttpAuthScheme,
) -> VmHttpAuthorization {
    let IpAddr::V4(source) = request.peer_addr.ip() else {
        return VmHttpAuthorization::Deny(VmHttpAuthError::SourceOutsideSessionSubnet);
    };
    if !session.source_ipv4.contains_addr(source) {
        return VmHttpAuthorization::Deny(VmHttpAuthError::SourceOutsideSessionSubnet);
    }
    let Some(header) = request.authorization.as_deref() else {
        return VmHttpAuthorization::Deny(VmHttpAuthError::MissingCredentials);
    };
    match scheme {
        VmHttpAuthScheme::Bearer => authorize_bearer_header(session, header),
        VmHttpAuthScheme::Basic => authorize_basic_header(session, header),
    }
}

fn authorize_bearer_header(session: &VmHttpSession, header: &str) -> VmHttpAuthorization {
    let Some(token) = header.strip_prefix("Bearer ") else {
        return VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials);
    };
    use subtle::ConstantTimeEq as _;
    if token
        .as_bytes()
        .ct_eq(session.bearer_token.as_str().as_bytes())
        .into()
    {
        VmHttpAuthorization::Allow
    } else {
        VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
    }
}

fn authorize_basic_header(session: &VmHttpSession, header: &str) -> VmHttpAuthorization {
    use subtle::ConstantTimeEq as _;
    let Some(encoded) = header.strip_prefix("Basic ") else {
        return VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials);
    };
    let expected = basic_authorization_value(session);
    if encoded.as_bytes().ct_eq(expected.as_bytes()).into() {
        VmHttpAuthorization::Allow
    } else {
        VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
    }
}

fn basic_authorization_value(session: &VmHttpSession) -> String {
    use base64::Engine as _;
    let credentials = format!("{VM_NIX_BASIC_LOGIN}:{}", session.bearer_token.as_str());
    base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
}

fn auth_scheme_for_target(target: &str) -> VmHttpAuthScheme {
    if is_nix_cache_target(target) {
        VmHttpAuthScheme::Basic
    } else {
        VmHttpAuthScheme::Bearer
    }
}

async fn handle_vm_http_connection<S: SecretStore + Send + Sync + 'static>(
    stream: TcpStream,
    peer_addr: SocketAddr,
    session: VmHttpSession,
    services: VmHttpServices<S>,
) -> std::io::Result<()> {
    let span = tracing::info_span!(
        "vm_http.connection",
        session_id = %session.session_id(),
        peer = %peer_addr,
    );
    handle_vm_http_connection_with_read_timeout(
        stream,
        peer_addr,
        session,
        services,
        VM_HTTP_READ_TIMEOUT,
    )
    .instrument(span)
    .await
}

async fn handle_vm_http_connection_with_read_timeout<S, T>(
    stream: T,
    peer_addr: SocketAddr,
    session: VmHttpSession,
    services: VmHttpServices<S>,
    read_timeout: std::time::Duration,
) -> std::io::Result<()>
where
    S: SecretStore + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let session = Arc::new(session);
    let services = Arc::new(services);
    let result = http1::Builder::new()
        .keep_alive(false)
        .timer(TokioTimer::new())
        .header_read_timeout(read_timeout)
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req: http::Request<Incoming>| {
                let session = Arc::clone(&session);
                let services = (*services).clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        serve_vm_http_request(&session, peer_addr, req, services, read_timeout)
                            .await,
                    )
                }
            }),
        )
        .await;
    if let Err(err) = result {
        // Hyper's connection-level errors (peer closed, parse failure,
        // header-read timeout) match the previous behaviour of swallowing
        // bad-input from the peer rather than surfacing them as I/O errors.
        tracing::warn!(error = %err, "vm http connection ended with hyper error");
    }
    Ok(())
}

#[cfg(test)]
fn dispatch_vm_http_head(
    session: &VmHttpSession,
    peer_addr: SocketAddr,
    method: &str,
    target: &str,
    authorization: Option<&str>,
) -> VmHttpResponse {
    let mut request = VmHttpRequest::new(
        method,
        target,
        authorization.map(|s| s.to_string()),
        peer_addr,
    );
    if let Some(value) = authorization {
        request.headers.push(VmHttpHeader {
            name: "Authorization".into(),
            value: value.to_string(),
        });
    }
    let auth_scheme = auth_scheme_for_target(&request.target);
    match authorize_vm_http_request_with_scheme(session, &request, auth_scheme) {
        VmHttpAuthorization::Allow if is_nix_cache_target(&request.target) => {
            route_nix_cache_request_without_upstream(&request)
        }
        VmHttpAuthorization::Allow => route_session_endpoint(session, &request),
        VmHttpAuthorization::Deny(err) => auth_error_response(auth_scheme, err),
    }
}

#[cfg(test)]
pub(super) struct DispatchedTestResponse {
    pub(super) status: VmHttpStatus,
    pub(super) content_type: String,
    pub(super) body: Vec<u8>,
    pub(super) headers: http::HeaderMap,
}

#[cfg(test)]
impl DispatchedTestResponse {
    pub(super) async fn from_hyper_response(
        response: http::Response<UnsyncBoxBody<Bytes, std::io::Error>>,
    ) -> Self {
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .expect("test response body collects without I/O error")
            .to_bytes()
            .to_vec();
        let content_type = parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        Self {
            status: VmHttpStatus::from_code(parts.status.as_u16()),
            content_type,
            body,
            headers: parts.headers,
        }
    }

    /// Collects a response whose body may abort mid-stream, returning the
    /// terminal body result separately from the head. Status and headers are
    /// captured before the body is polled, so they reflect the committed
    /// response head even when the body then errors — this is exactly the
    /// case a streaming proxy hits when the upstream fails or overflows after
    /// the 200 has already been sent.
    pub(super) async fn from_hyper_response_allow_body_error(
        response: http::Response<UnsyncBoxBody<Bytes, std::io::Error>>,
    ) -> (http::response::Parts, Result<Vec<u8>, std::io::Error>) {
        let (parts, body) = response.into_parts();
        let body = body.collect().await.map(|buf| buf.to_bytes().to_vec());
        (parts, body)
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn dispatch_vm_http_head_and_body<S>(
    session: &VmHttpSession,
    peer_addr: SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
    services: VmHttpServices<S>,
    read_timeout: std::time::Duration,
) -> DispatchedTestResponse
where
    S: SecretStore + Send + Sync + 'static,
{
    let mut builder = http::Request::builder().method(method).uri(target);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(http_body_util::Full::new(Bytes::from(body)))
        .expect("test request builds with valid method/uri/headers");
    let response = serve_vm_http_request(session, peer_addr, request, services, read_timeout).await;
    DispatchedTestResponse::from_hyper_response(response).await
}

async fn serve_vm_http_request<S, B>(
    session: &VmHttpSession,
    peer_addr: SocketAddr,
    request: http::Request<B>,
    services: VmHttpServices<S>,
    read_timeout: std::time::Duration,
) -> http::Response<UnsyncBoxBody<Bytes, std::io::Error>>
where
    S: SecretStore + Send + Sync + 'static,
    B: HyperBody<Data = Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let (parts, body) = request.into_parts();
    let request = match VmHttpRequest::from_hyper_parts(&parts, peer_addr) {
        Ok(request) => request,
        Err(err) => {
            let response = VmHttpResponse::text(VmHttpStatus::BadRequest, err.to_string());
            log_vm_http_request(session, "?", "?", response.status.code());
            return response.into_hyper_response();
        }
    };
    let auth_scheme = auth_scheme_for_target(&request.target);
    let dispatch: VmHttpDispatch =
        match authorize_vm_http_request_with_scheme(session, &request, auth_scheme) {
            VmHttpAuthorization::Allow => {
                let body_bytes = match route_request_body_limit(&request, &services) {
                    None => Vec::new(),
                    Some(max) => {
                        match read_request_body_with_limit(body, max, read_timeout).await {
                            Ok(bytes) => bytes,
                            Err(response) => {
                                log_vm_http_request(
                                    session,
                                    &request.method,
                                    &request.target,
                                    response.status.code(),
                                );
                                return response.into_hyper_response();
                            }
                        }
                    }
                };
                route_authenticated_vm_http_request(session, &request, body_bytes, services).await
            }
            VmHttpAuthorization::Deny(err) => {
                let response = auth_error_response(auth_scheme, err);
                if is_nix_cache_target(&request.target) {
                    record_nix_cache_local_response(
                        services.nix_cache.as_ref(),
                        session,
                        &request,
                        NixCacheAuditDecision::Deny {
                            reason: vm_http_auth_error_reason(err).to_string(),
                        },
                        response,
                        None,
                    )
                    .into()
                } else if let Some(route) = ClaudeBackend::classify_proxy_target(&request.target)
                    && let Some(service) = services.claude_proxy.as_ref()
                {
                    record_proxy_local_response::<ClaudeBackend, _>(
                        service,
                        session,
                        &request,
                        route,
                        ProxyAuditDecision::Deny {
                            reason: vm_http_auth_error_reason(err).to_string(),
                        },
                        response,
                        None,
                    )
                    .into()
                } else if let Some(route) = OpenAiBackend::classify_proxy_target(&request.target)
                    && let Some(service) = services.openai_proxy.as_ref()
                {
                    record_proxy_local_response::<OpenAiBackend, _>(
                        service,
                        session,
                        &request,
                        route,
                        ProxyAuditDecision::Deny {
                            reason: vm_http_auth_error_reason(err).to_string(),
                        },
                        response,
                        None,
                    )
                    .into()
                } else {
                    response.into()
                }
            }
        };
    log_vm_http_request(
        session,
        &request.method,
        &request.target,
        dispatch.status_code(),
    );
    dispatch.into_hyper_response()
}

async fn read_request_body_with_limit<B>(
    body: B,
    max: usize,
    read_timeout: std::time::Duration,
) -> Result<Vec<u8>, VmHttpResponse>
where
    B: HyperBody<Data = Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let limited = Limited::new(body, max);
    match tokio::time::timeout(read_timeout, limited.collect()).await {
        Err(_) => Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "incomplete request body",
        )),
        Ok(Ok(collected)) => Ok(collected.to_bytes().to_vec()),
        Ok(Err(err)) => {
            // `Limited::collect` returns boxed errors; the downcast lets us
            // distinguish between a max-byte cap from the inner body's I/O
            // failure so the response can carry an accurate diagnostic.
            if err.is::<http_body_util::LengthLimitError>() {
                Err(VmHttpResponse::text(
                    VmHttpStatus::BadRequest,
                    format!("HTTP request body exceeds {max}-byte limit"),
                ))
            } else {
                Err(VmHttpResponse::text(
                    VmHttpStatus::BadRequest,
                    "incomplete request body",
                ))
            }
        }
    }
}

fn log_vm_http_request(session: &VmHttpSession, method: &str, target: &str, status: u16) {
    tracing::info!(
        session_id = %session.session_id(),
        method,
        target,
        status,
        "vm http request",
    );
}

fn auth_error_response(scheme: VmHttpAuthScheme, err: VmHttpAuthError) -> VmHttpResponse {
    match err {
        VmHttpAuthError::SourceOutsideSessionSubnet => {
            VmHttpResponse::text(VmHttpStatus::Forbidden, "source outside session subnet")
        }
        VmHttpAuthError::MissingCredentials => match scheme {
            VmHttpAuthScheme::Bearer => {
                VmHttpResponse::unauthorized("Bearer", "missing bearer token")
            }
            VmHttpAuthScheme::Basic => VmHttpResponse::unauthorized(
                "Basic realm=\"writ-nix-cache\"",
                "missing basic credentials",
            ),
        },
        VmHttpAuthError::WrongCredentials => match scheme {
            VmHttpAuthScheme::Bearer => {
                VmHttpResponse::unauthorized("Bearer", "invalid bearer token")
            }
            VmHttpAuthScheme::Basic => VmHttpResponse::unauthorized(
                "Basic realm=\"writ-nix-cache\"",
                "invalid basic credentials",
            ),
        },
    }
}

/// The maximum request body bytes a route is prepared to consume; `None`
/// means the route does not read its body, and any declared body should be
/// left in the connection.
fn route_request_body_limit<S: SecretStore + Send + Sync + 'static>(
    request: &VmHttpRequest,
    services: &VmHttpServices<S>,
) -> Option<usize> {
    if is_nix_cache_target(&request.target) {
        return None;
    }
    if ClaudeBackend::is_proxy_target(&request.target) {
        return services
            .claude_proxy
            .as_ref()
            .map(|service| service.config.max_request_bytes());
    }
    if OpenAiBackend::is_proxy_target(&request.target) {
        return services
            .openai_proxy
            .as_ref()
            .map(|service| service.config.max_request_bytes());
    }
    if is_git_clone_target(&request.target)
        && request.method == "POST"
        && services.git_clone.is_some()
    {
        return Some(MAX_VM_HTTP_BODY_BYTES);
    }
    if is_git_push_target(&request.target) && request.method == "POST" {
        return services
            .git_push
            .as_ref()
            .map(|service| service.body_limits().max_body_bytes());
    }
    if is_flake_provision_target(&request.target)
        && request.method == "POST"
        && services.flake_provision.is_some()
    {
        return Some(MAX_VM_HTTP_BODY_BYTES);
    }
    if parse_agent_run_outcome_target(&request.target).is_some()
        && request.method == "POST"
        && services.agent_runs.is_some()
    {
        return Some(MAX_VM_HTTP_AGENT_RUN_OUTCOME_BODY_BYTES);
    }
    None
}

async fn route_authenticated_vm_http_request<S>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    body: Vec<u8>,
    services: VmHttpServices<S>,
) -> VmHttpDispatch
where
    S: SecretStore + Send + Sync + 'static,
{
    if is_nix_cache_target(&request.target) {
        return route_nix_cache_request(session, request, services.nix_cache).await;
    }

    if ClaudeBackend::is_proxy_target(&request.target) {
        let Some(service) = services.claude_proxy else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        let effect = ProxyEffect::<ClaudeBackend, _>::classify(&service, session, request, body);
        return broker_effect(service.audit(), effect).await;
    }

    if OpenAiBackend::is_proxy_target(&request.target) {
        let Some(service) = services.openai_proxy else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        let effect = ProxyEffect::<OpenAiBackend, _>::classify(&service, session, request, body);
        return broker_effect(service.audit(), effect).await;
    }

    if is_git_clone_target(&request.target) {
        let Some(service) = services.git_clone else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        return route_git_clone_request(session, request, body, service)
            .await
            .into();
    }

    if is_git_push_target(&request.target) {
        let Some(service) = services.git_push else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        return route_git_push_request(session, request, body, service)
            .await
            .into();
    }

    if is_flake_provision_target(&request.target) {
        let Some(service) = services.flake_provision else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        return route_flake_provision_request(session, request, body, service)
            .await
            .into();
    }

    if let Some(run_id) = parse_agent_run_config_target(&request.target) {
        let Some(service) = services.agent_runs else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        if request.method != "GET" {
            return VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed")
                .into();
        }
        return route_agent_run_config_request(run_id, &service).into();
    }

    if let Some(run_id) = parse_agent_run_outcome_target(&request.target) {
        let Some(service) = services.agent_runs else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        if request.method != "POST" {
            return VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed")
                .into();
        }
        return route_agent_run_outcome_request(run_id, session.session_id(), &body, &service)
            .into();
    }

    route_session_endpoint(session, request).into()
}

fn vm_http_auth_error_reason(err: VmHttpAuthError) -> &'static str {
    match err {
        VmHttpAuthError::MissingCredentials => "missing credentials",
        VmHttpAuthError::WrongCredentials => "wrong credentials",
        VmHttpAuthError::SourceOutsideSessionSubnet => "source outside session subnet",
    }
}

fn route_session_endpoint(session: &VmHttpSession, request: &VmHttpRequest) -> VmHttpResponse {
    match (request.method.as_str(), request.target.as_str()) {
        ("GET", "/v1/session") => VmHttpResponse::json(
            VmHttpStatus::Ok,
            &SessionResponse {
                session_id: session.session_id,
                api: "writ-vm-http",
                version: 1,
            },
        ),
        ("GET", _) => VmHttpResponse::text(VmHttpStatus::NotFound, "not found"),
        (_, "/v1/session") => {
            VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed")
        }
        _ => VmHttpResponse::text(VmHttpStatus::NotFound, "not found"),
    }
}

impl VmHttpRequest {
    fn from_hyper_parts(
        parts: &http::request::Parts,
        peer_addr: SocketAddr,
    ) -> Result<Self, VmHttpParseError> {
        let method = parts.method.as_str().to_string();
        let target = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        let authorization = single_header_value(
            &parts.headers,
            http::header::AUTHORIZATION,
            VmHttpParseError::DuplicateAuthorization,
        )?;
        let content_length = single_header_value(
            &parts.headers,
            http::header::CONTENT_LENGTH,
            VmHttpParseError::DuplicateContentLength,
        )?
        .map(|s| parse_content_length(&s))
        .transpose()?;

        let headers = parts
            .headers
            .iter()
            .filter_map(|(name, value)| {
                let value = std::str::from_utf8(value.as_bytes()).ok()?.to_string();
                Some(VmHttpHeader {
                    name: name.as_str().to_string(),
                    value,
                })
            })
            .collect();

        Ok(VmHttpRequest {
            method,
            target,
            authorization,
            content_length,
            headers,
            peer_addr,
        })
    }
}

fn single_header_value(
    headers: &http::HeaderMap,
    name: http::header::HeaderName,
    duplicate_err: VmHttpParseError,
) -> Result<Option<String>, VmHttpParseError> {
    let mut iter = headers.get_all(name).into_iter();
    let first = iter.next();
    if iter.next().is_some() {
        return Err(duplicate_err);
    }
    Ok(first.and_then(|v| std::str::from_utf8(v.as_bytes()).ok().map(str::to_string)))
}

fn parse_content_length(value: &str) -> Result<usize, VmHttpParseError> {
    // RFC 7230 §3.3.2 requires `1*DIGIT`, so reject empty values and any sign
    // prefix that `usize::from_str` would otherwise accept (e.g. "+5").
    if value.is_empty() || value.starts_with('+') || value.starts_with('-') {
        return Err(VmHttpParseError::InvalidContentLength);
    }
    value
        .parse::<usize>()
        .map_err(|_| VmHttpParseError::InvalidContentLength)
}

impl VmHttpResponse {
    fn json<T: Serialize>(status: VmHttpStatus, value: &T) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(value).expect("VM HTTP response always serializes"),
            content_length: None,
            www_authenticate: None,
            headers: Vec::new(),
        }
    }

    fn text(status: VmHttpStatus, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.into().into_bytes(),
            content_length: None,
            www_authenticate: None,
            headers: Vec::new(),
        }
    }

    fn unauthorized(challenge: &'static str, body: impl Into<String>) -> Self {
        Self {
            status: VmHttpStatus::Unauthorized,
            content_type: "text/plain; charset=utf-8",
            body: body.into().into_bytes(),
            content_length: None,
            www_authenticate: Some(challenge),
            headers: Vec::new(),
        }
    }

    fn with_content_length(mut self, content_length: Option<u64>) -> Self {
        self.content_length = content_length;
        self
    }

    fn into_hyper_response(self) -> http::Response<UnsyncBoxBody<Bytes, std::io::Error>> {
        let mut builder = http::Response::builder()
            .status(self.status.code())
            .header(http::header::CONTENT_TYPE, self.content_type)
            .header(http::header::CONNECTION, "close");
        if let Some(content_length) = self.content_length {
            builder = builder.header(http::header::CONTENT_LENGTH, content_length);
        }
        if let Some(challenge) = self.www_authenticate {
            builder = builder.header(http::header::WWW_AUTHENTICATE, challenge);
        }
        for header in self.headers {
            builder = builder.header(header.name, header.value);
        }
        let body: UnsyncBoxBody<Bytes, std::io::Error> = if self.body.is_empty() {
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed_unsync()
        } else {
            Full::new(Bytes::from(self.body))
                .map_err(|never| match never {})
                .boxed_unsync()
        };
        builder
            .body(body)
            .expect("VmHttpResponse always builds a valid hyper response")
    }
}

impl From<VmHttpResponse> for VmHttpDispatch {
    fn from(response: VmHttpResponse) -> Self {
        Self::Buffered(response)
    }
}

impl VmHttpDispatch {
    fn into_hyper_response(self) -> http::Response<UnsyncBoxBody<Bytes, std::io::Error>> {
        match self {
            Self::Buffered(response) => response.into_hyper_response(),
            Self::ClaudeProxyStream(stream) => stream.into_hyper_response(),
            Self::OpenAiProxyStream(stream) => stream.into_hyper_response(),
        }
    }

    fn status_code(&self) -> u16 {
        match self {
            Self::Buffered(response) => response.status.code(),
            Self::ClaudeProxyStream(stream) => stream.upstream_status(),
            Self::OpenAiProxyStream(stream) => stream.upstream_status(),
        }
    }

    #[cfg(test)]
    fn into_buffered(self) -> VmHttpResponse {
        match self {
            Self::Buffered(response) => response,
            Self::ClaudeProxyStream(_) | Self::OpenAiProxyStream(_) => {
                panic!("expected buffered VM HTTP response")
            }
        }
    }
}

impl VmHttpStatus {
    fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::Conflict => 409,
            Self::Gone => 410,
            Self::UnprocessableContent => 422,
            Self::BadGateway => 502,
            Self::InternalServerError => 500,
            Self::Upstream(code) => code,
        }
    }

    #[cfg(test)]
    fn from_code(code: u16) -> Self {
        match code {
            200 => Self::Ok,
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            405 => Self::MethodNotAllowed,
            409 => Self::Conflict,
            410 => Self::Gone,
            422 => Self::UnprocessableContent,
            500 => Self::InternalServerError,
            502 => Self::BadGateway,
            other => Self::Upstream(other),
        }
    }
}

fn report_vm_http_handler_result(result: Result<std::io::Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::warn!(error = %err, "vm http connection error"),
        Err(err) => tracing::error!(error = %err, "vm http connection task failed"),
    }
}

#[cfg(test)]
mod tests;
