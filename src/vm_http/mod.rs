//! VM-facing broker HTTP endpoint.
//!
//! This is deliberately separate from the host Unix-socket protocol. The VM
//! endpoint authenticates one managed agent VM session with a bearer secret and
//! a source-subnet check, then exposes only VM-safe broker operations.

mod agent_runs;
mod claude_proxy;
mod git_clone;
mod nix_cache;
mod openai_proxy;
mod proxy_common;

pub use agent_runs::VmHttpAgentRunService;
use agent_runs::{
    parse_agent_run_config_target, parse_agent_run_outcome_target, route_agent_run_config_request,
    route_agent_run_outcome_request,
};
pub use claude_proxy::{
    DEFAULT_CLAUDE_ANTHROPIC_VERSION, VmHttpClaudeProxyAuthKind, VmHttpClaudeProxyConfig,
    VmHttpClaudeProxyConfigError, VmHttpClaudeProxyService,
};
use claude_proxy::{record_claude_proxy_local_response, route_claude_proxy_request};
pub use git_clone::{VmHttpGitCloneConfig, VmHttpGitCloneService};
use git_clone::{is_git_clone_target, route_git_clone_request};
#[cfg(test)]
use nix_cache::route_nix_cache_request_without_upstream;
pub use nix_cache::{
    VM_NIX_BASIC_LOGIN, VM_NIX_CACHE_PATH_PREFIX, VmHttpNixCacheConfig, VmHttpNixCacheConfigError,
    VmHttpNixCacheService,
};
use nix_cache::{is_nix_cache_target, record_nix_cache_local_response, route_nix_cache_request};
pub use openai_proxy::{
    VmHttpOpenAiProxyAuthKind, VmHttpOpenAiProxyConfig, VmHttpOpenAiProxyConfigError,
    VmHttpOpenAiProxyService,
};
use openai_proxy::{record_openai_proxy_local_response, route_openai_proxy_request};
use proxy_common::{ClaudeBackend, OpenAiBackend, ProxyBackend, ProxyStream};

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

use crate::audit::{ClaudeProxyAuditDecision, NixCacheAuditDecision, OpenAiProxyAuditDecision};
use crate::bearer::is_bearer_token_byte;
use crate::core::{BrokerPort, BrokerPortRange, Ipv4Cidr, SessionId};
use crate::secret::SecretStore;
use crate::server::BrokerState;

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
}

pub struct PreparedVmHttpSession<S: SecretStore + Send + Sync + 'static> {
    listener: BoundVmHttpListener,
    session: VmHttpSession,
    git_clone: VmHttpGitCloneService<S>,
    nix_cache: VmHttpNixCacheService<S>,
    proxies: VmHttpProxies<S>,
    agent_runs: Option<VmHttpAgentRunService<S>>,
}

pub struct VmHttpProxies<S: SecretStore> {
    pub claude: Option<VmHttpClaudeProxyService<S>>,
    pub openai: Option<VmHttpOpenAiProxyService<S>>,
}

impl<S: SecretStore> VmHttpProxies<S> {
    pub fn none() -> Self {
        Self {
            claude: None,
            openai: None,
        }
    }
}

impl<S: SecretStore> Clone for VmHttpProxies<S> {
    fn clone(&self) -> Self {
        Self {
            claude: self.claude.clone(),
            openai: self.openai.clone(),
        }
    }
}

struct VmHttpServices<S: SecretStore> {
    git_clone: Option<VmHttpGitCloneService<S>>,
    nix_cache: Option<VmHttpNixCacheService<S>>,
    claude_proxy: Option<VmHttpClaudeProxyService<S>>,
    openai_proxy: Option<VmHttpOpenAiProxyService<S>>,
    agent_runs: Option<VmHttpAgentRunService<S>>,
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
    Gone,
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

impl<S: SecretStore> VmHttpServices<S> {
    fn none() -> Self {
        Self {
            git_clone: None,
            nix_cache: None,
            claude_proxy: None,
            openai_proxy: None,
            agent_runs: None,
        }
    }

    fn with_git(
        git_clone: VmHttpGitCloneService<S>,
        nix_cache: VmHttpNixCacheService<S>,
        proxies: VmHttpProxies<S>,
        agent_runs: Option<VmHttpAgentRunService<S>>,
    ) -> Self {
        Self {
            git_clone: Some(git_clone),
            nix_cache: Some(nix_cache),
            claude_proxy: proxies.claude,
            openai_proxy: proxies.openai,
            agent_runs,
        }
    }
}

impl<S: SecretStore> Clone for VmHttpServices<S> {
    fn clone(&self) -> Self {
        Self {
            git_clone: self.git_clone.clone(),
            nix_cache: self.nix_cache.clone(),
            claude_proxy: self.claude_proxy.clone(),
            openai_proxy: self.openai_proxy.clone(),
            agent_runs: self.agent_runs.clone(),
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
    ) -> Self {
        Self::new_with_claude_proxy(
            bind_addr,
            broker_port_range,
            git_clone,
            nix_cache,
            None,
            agent_run_log_root,
        )
    }

    pub fn new_with_claude_proxy(
        bind_addr: Ipv4Addr,
        broker_port_range: BrokerPortRange,
        git_clone: VmHttpGitCloneConfig,
        nix_cache: VmHttpNixCacheConfig,
        claude_proxy: Option<VmHttpClaudeProxyConfig>,
        agent_run_log_root: impl Into<PathBuf>,
    ) -> Self {
        Self::new_with_proxies(
            bind_addr,
            broker_port_range,
            git_clone,
            nix_cache,
            claude_proxy,
            None,
            agent_run_log_root,
        )
    }

    pub fn new_with_proxies(
        bind_addr: Ipv4Addr,
        broker_port_range: BrokerPortRange,
        git_clone: VmHttpGitCloneConfig,
        nix_cache: VmHttpNixCacheConfig,
        claude_proxy: Option<VmHttpClaudeProxyConfig>,
        openai_proxy: Option<VmHttpOpenAiProxyConfig>,
        agent_run_log_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            bind_addr,
            broker_port_range,
            git_clone,
            nix_cache,
            claude_proxy,
            openai_proxy,
            agent_run_log_root: agent_run_log_root.into(),
        }
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
    prepare_vm_http_session_with_agent_runs(state, config, session_id, source_ipv4, None).await
}

pub async fn prepare_vm_http_session_with_agent_runs<S: SecretStore + Send + Sync + 'static>(
    state: Arc<BrokerState<S>>,
    config: &VmHttpRuntimeConfig,
    session_id: SessionId,
    source_ipv4: Ipv4Cidr,
    agent_runs: Option<VmHttpAgentRunService<S>>,
) -> Result<PreparedVmHttpSession<S>, VmHttpRuntimeError> {
    let listener =
        bind_ephemeral_vm_http_listener(config.bind_addr, config.broker_port_range).await?;
    let session = VmHttpSession::new(session_id, source_ipv4, VmHttpBearerToken::generate());
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

pub async fn run_vm_http_with_services_until_shutdown<S: SecretStore + Send + Sync + 'static>(
    listener: TcpListener,
    session: VmHttpSession,
    git_clone: VmHttpGitCloneService<S>,
    nix_cache: VmHttpNixCacheService<S>,
    proxies: VmHttpProxies<S>,
    agent_runs: Option<VmHttpAgentRunService<S>>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    run_vm_http_runtime_until_shutdown(
        listener,
        session,
        VmHttpServices::with_git(git_clone, nix_cache, proxies, agent_runs),
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
                    record_claude_proxy_local_response(
                        service,
                        session,
                        &request,
                        route,
                        ClaudeProxyAuditDecision::Deny {
                            reason: vm_http_auth_error_reason(err).to_string(),
                        },
                        response,
                        None,
                    )
                    .into()
                } else if let Some(route) = OpenAiBackend::classify_proxy_target(&request.target)
                    && let Some(service) = services.openai_proxy.as_ref()
                {
                    record_openai_proxy_local_response(
                        service,
                        session,
                        &request,
                        route,
                        OpenAiProxyAuditDecision::Deny {
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
fn route_request_body_limit<S: SecretStore>(
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
    S: SecretStore + Send + Sync,
{
    if is_nix_cache_target(&request.target) {
        return route_nix_cache_request(session, request, services.nix_cache).await;
    }

    if ClaudeBackend::is_proxy_target(&request.target) {
        let Some(service) = services.claude_proxy else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        return route_claude_proxy_request(session, request, body, &service).await;
    }

    if OpenAiBackend::is_proxy_target(&request.target) {
        let Some(service) = services.openai_proxy else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        return route_openai_proxy_request(session, request, body, &service).await;
    }

    if is_git_clone_target(&request.target) {
        let Some(service) = services.git_clone else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        return route_git_clone_request(session, request, body, service)
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
        return route_agent_run_outcome_request(run_id, &body, &service).into();
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
            Self::ClaudeProxyStream(stream) => stream.upstream_status,
            Self::OpenAiProxyStream(stream) => stream.upstream_status,
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
            Self::Gone => 410,
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
            410 => Self::Gone,
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
mod tests {
    use std::collections::HashMap;
    use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    use base64::Engine as _;
    use proptest::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wiremock::MockServer;

    use super::*;
    use crate::agent_run::AgentRunId;
    use crate::audit::AuditLog;
    use crate::core::{Ipv6Cidr, SessionRecord, TtlSeconds, UnixMillis};
    use crate::github::{GitHubAppConfig, GitHubMinter};
    use crate::policy::PolicyConfig;
    use crate::secret::{SecretError, SecretKey};
    use crate::vm_git::VM_GIT_CLONE_PATH;
    use crate::vm_git_bundle::{GitCredentialBoundary, GitSecretEnvVar};

    const TEST_GIT_CLONE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    type TestVmHttpServices = VmHttpServices<Box<dyn SecretStore>>;

    pub(super) fn no_services() -> TestVmHttpServices {
        VmHttpServices::none()
    }

    pub(super) fn services_with_claude_proxy(
        claude_proxy: VmHttpClaudeProxyService<Box<dyn SecretStore>>,
    ) -> TestVmHttpServices {
        VmHttpServices {
            git_clone: None,
            nix_cache: None,
            claude_proxy: Some(claude_proxy),
            openai_proxy: None,
            agent_runs: None,
        }
    }

    #[derive(Default)]
    struct InMemStore(Mutex<HashMap<String, String>>);

    impl SecretStore for InMemStore {
        fn get(&self, key: &SecretKey) -> Result<Option<String>, SecretError> {
            Ok(self.0.lock().unwrap().get(key.as_str()).cloned())
        }

        fn put(&self, key: &SecretKey, value: &str) -> Result<(), SecretError> {
            self.0
                .lock()
                .unwrap()
                .insert(key.as_str().to_string(), value.to_string());
            Ok(())
        }

        fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
            self.0.lock().unwrap().remove(key.as_str());
            Ok(())
        }
    }

    const TEST_PRIV: &str = include_str!("../../tests/fixtures/rsa_test_1.pem");

    pub(super) fn session_for_subnet(ipv4: Ipv4Cidr) -> VmHttpSession {
        VmHttpSession::new(
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
            ipv4,
            token(),
        )
    }

    pub(super) fn token() -> VmHttpBearerToken {
        VmHttpBearerToken::new("test-token-0123456789abcdef").unwrap()
    }

    pub(super) fn make_broker_state(server: &MockServer) -> Arc<BrokerState<Box<dyn SecretStore>>> {
        make_broker_state_with_extra_secret(server, None)
    }

    pub(super) fn make_broker_state_with_extra_secret(
        server: &MockServer,
        extra_secret: Option<(SecretKey, &str)>,
    ) -> Arc<BrokerState<Box<dyn SecretStore>>> {
        let pk = SecretKey::new("gh-app-pk").unwrap();
        let store = InMemStore::default();
        store.put(&pk, TEST_PRIV).unwrap();
        if let Some((key, value)) = extra_secret {
            store.put(&key, value).unwrap();
        }
        Arc::new(BrokerState {
            audit: Arc::new(AuditLog::open_in_memory().unwrap()),
            minter: GitHubMinter::new(
                GitHubAppConfig {
                    app_id: 42,
                    installation_id: 999,
                    installation_owner: "o".into(),
                    private_key_secret: pk,
                    api_base: server.uri(),
                },
                Box::new(store) as Box<dyn SecretStore>,
            ),
            policy: PolicyConfig {
                writable_repos: vec![],
                default_ttl: TtlSeconds::new(3600).unwrap(),
            },
        })
    }

    pub(super) fn open_audit_session(
        state: &BrokerState<Box<dyn SecretStore>>,
        session_id: SessionId,
    ) {
        state
            .audit
            .open_session(&SessionRecord {
                session_id,
                label: Some("vm-http-test".into()),
                agent_kind: None,
                agent_model: None,
                opened_at: UnixMillis::now(),
                closed_at: None,
            })
            .unwrap();
    }

    pub(super) fn write_fake_git(dir: &Path) -> PathBuf {
        write_fake_git_with_bundle_epilogue(dir, "")
    }

    pub(super) fn write_fake_git_with_bundle_epilogue(
        dir: &Path,
        bundle_epilogue: &str,
    ) -> PathBuf {
        let git = dir.join("fake-git.sh");
        let log_path = shell_single_quote(&dir.join("fake-git.log"));
        let shell = required_test_tool("sh");
        let mkdir = shell_single_quote(&required_test_tool("mkdir"));
        let script = format!(
            r#"#!{shell}
set -eu
printf '%s\n' "$*" >> {log}
case " $* " in
  *" clone "*)
    if [ "${{WRIT_GIT_TOKEN:-}}" != "ghs_vm_token" ]; then
      exit 41
    fi
    mirror=
    for arg do mirror=$arg; done
    {mkdir} -p "$mirror"
    ;;
  *" bundle create "*)
    if [ "${{WRIT_GIT_TOKEN+x}}" = x ]; then
      exit 42
    fi
    bundle=
    after_separator=0
    for arg do
      if [ "$after_separator" = 1 ]; then
        bundle=$arg
        break
      fi
      if [ "$arg" = "--" ]; then
        after_separator=1
      fi
    done
    if [ -z "$bundle" ]; then
      exit 43
    fi
    printf 'bundle-from-fake-git\n' > "$bundle"
    {bundle_epilogue}
    ;;
  *)
    exit 64
    ;;
esac
"#,
            shell = shell.display(),
            log = log_path,
            mkdir = mkdir,
            bundle_epilogue = bundle_epilogue,
        );
        std::fs::write(&git, script).unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o700)).unwrap();
        git
    }

    pub(super) fn shell_single_quote(path: &Path) -> String {
        let raw = path.to_string_lossy();
        format!("'{}'", raw.replace('\'', "'\\''"))
    }

    pub(super) fn required_test_tool(name: &str) -> PathBuf {
        let path = std::env::var_os("PATH")
            .unwrap_or_else(|| panic!("PATH must contain {name} for vm_http tests"));
        for dir in std::env::split_paths(&path) {
            let candidate = if dir.is_absolute() {
                dir.join(name)
            } else {
                std::env::current_dir().unwrap().join(dir).join(name)
            };
            match std::fs::metadata(&candidate) {
                Ok(metadata)
                    if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 =>
                {
                    return candidate;
                }
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => panic!("failed to inspect {}: {err}", candidate.display()),
            }
        }
        panic!("required test tool {name} not found on PATH");
    }

    fn write_fake_askpass(dir: &Path) -> PathBuf {
        let askpass = dir.join("fake-askpass.sh");
        let shell = required_test_tool("sh");
        std::fs::write(&askpass, format!("#!{}\nexit 1\n", shell.display())).unwrap();
        std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700)).unwrap();
        askpass
    }

    pub(super) fn git_clone_config_for_test(
        temp: &tempfile::TempDir,
        fake_git: PathBuf,
    ) -> VmHttpGitCloneConfig {
        let askpass = write_fake_askpass(temp.path());
        let credential =
            GitCredentialBoundary::new(askpass, GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap())
                .unwrap();
        VmHttpGitCloneConfig::new(
            fake_git,
            credential,
            temp.path().join("git-work"),
            TEST_GIT_CLONE_TIMEOUT,
            1024,
        )
        .unwrap()
    }

    pub(super) fn nix_cache_config_for_test() -> VmHttpNixCacheConfig {
        VmHttpNixCacheConfig::new("http://127.0.0.1:9", 1024, 1024).unwrap()
    }

    fn request(source: Ipv4Addr, authorization: Option<String>) -> VmHttpRequest {
        VmHttpRequest::new(
            "GET",
            "/v1/session",
            authorization,
            SocketAddr::V4(SocketAddrV4::new(source, 34567)),
        )
    }

    pub(super) fn bearer(value: &str) -> String {
        format!("Bearer {value}")
    }

    pub(super) fn basic(value: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{VM_NIX_BASIC_LOGIN}:{value}").as_bytes())
        )
    }

    pub(super) async fn serve_raw_http_once(response: String) -> (String, Arc<Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_for_task = Arc::clone(&captured);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let read = stream.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..read]);
                if let Some(head_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let head_end = head_end + 4;
                    let head = String::from_utf8_lossy(&request[..head_end]);
                    let content_length = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    while request.len() < head_end + content_length {
                        let read = stream.read(&mut buf).await.unwrap();
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buf[..read]);
                    }
                    break;
                }
            }
            *captured_for_task.lock().unwrap() = String::from_utf8_lossy(&request).into_owned();
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (format!("http://{addr}/"), captured)
    }

    pub(super) fn raw_http_response(status: &str, content_type: &str, body: &[u8]) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        )
    }

    pub(super) fn raw_http_response_with_headers(
        status: &str,
        content_type: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> String {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len(),
        );
        for (name, value) in headers {
            response.push_str(&format!("{name}: {value}\r\n"));
        }
        response.push_str("\r\n");
        response.push_str(&String::from_utf8_lossy(body));
        response
    }

    fn arbitrary_socket_addr() -> impl Strategy<Value = SocketAddr> {
        prop_oneof![
            (any::<[u8; 4]>(), any::<u16>())
                .prop_map(|(octets, port)| SocketAddr::new(Ipv4Addr::from(octets).into(), port)),
            (any::<[u16; 8]>(), any::<u16>()).prop_map(|(segments, port)| {
                SocketAddr::new(
                    Ipv6Addr::new(
                        segments[0],
                        segments[1],
                        segments[2],
                        segments[3],
                        segments[4],
                        segments[5],
                        segments[6],
                        segments[7],
                    )
                    .into(),
                    port,
                )
            }),
        ]
    }

    fn arbitrary_header() -> impl Strategy<Value = Option<String>> {
        prop::option::of(
            prop::collection::vec(any::<char>(), 0..128)
                .prop_map(|chars| chars.into_iter().collect()),
        )
    }

    #[test]
    fn bearer_token_debug_redacts_secret() {
        let token = token();
        assert_eq!(format!("{token:?}"), "VmHttpBearerToken(<redacted>)");
    }

    #[test]
    fn bearer_token_rejects_empty_or_header_unsafe_values() {
        assert_eq!(
            VmHttpBearerToken::new(""),
            Err(VmHttpConfigError::EmptyBearerToken)
        );
        assert_eq!(
            VmHttpBearerToken::new("has space"),
            Err(VmHttpConfigError::InvalidBearerToken)
        );
        assert_eq!(
            VmHttpBearerToken::new("has\nnewline"),
            Err(VmHttpConfigError::InvalidBearerToken)
        );
        for token in ["has+plus", "has/slash", "has=equals", "has:colon", "has@at"] {
            assert_eq!(
                VmHttpBearerToken::new(token),
                Err(VmHttpConfigError::InvalidBearerToken),
                "accepted {token:?}"
            );
        }
    }

    #[test]
    fn generated_bearer_tokens_are_distinct_and_header_safe() {
        let first = VmHttpBearerToken::generate();
        let second = VmHttpBearerToken::generate();
        assert_ne!(first, second);
        assert!(first.as_str().bytes().all(is_bearer_token_byte));
    }

    proptest! {
        #[test]
        fn authorization_accepts_any_source_inside_session_subnet(
            second in any::<u8>(),
            third in any::<u8>(),
            host in 1u8..=254,
        ) {
            let subnet = Ipv4Cidr::new(Ipv4Addr::new(10, second, third, 0), 24).unwrap();
            let session = session_for_subnet(subnet);
            let source = Ipv4Addr::new(10, second, third, host);
            let got = authorize_vm_http_request(&session, &request(source, Some(bearer(token().as_str()))));
            prop_assert_eq!(got, VmHttpAuthorization::Allow);
        }

        #[test]
        fn authorization_rejects_any_source_outside_session_subnet(
            second in any::<u8>(),
            third in any::<u8>(),
            other_third in any::<u8>(),
            host in 1u8..=254,
        ) {
            let subnet = Ipv4Cidr::new(Ipv4Addr::new(10, second, third, 0), 24).unwrap();
            let session = session_for_subnet(subnet);
            let outside_third = if other_third == third { other_third.wrapping_add(1) } else { other_third };
            let source = Ipv4Addr::new(10, second, outside_third, host);
            let got = authorize_vm_http_request(&session, &request(source, Some(bearer(token().as_str()))));
            prop_assert_eq!(
                got,
                VmHttpAuthorization::Deny(VmHttpAuthError::SourceOutsideSessionSubnet)
            );
        }

        #[test]
        fn authorization_is_total_for_any_peer_and_header(
            second in any::<u8>(),
            third in any::<u8>(),
            peer_addr in arbitrary_socket_addr(),
            authorization in arbitrary_header(),
        ) {
            let subnet = Ipv4Cidr::new(Ipv4Addr::new(10, second, third, 0), 24).unwrap();
            let session = session_for_subnet(subnet);
            let request = VmHttpRequest::new("GET", "/v1/session", authorization, peer_addr);
            let _ = authorize_vm_http_request(&session, &request);
        }
    }

    #[test]
    fn authorization_rejects_missing_or_wrong_bearer_token() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let source = Ipv4Addr::new(10, 1, 2, 42);

        assert_eq!(
            authorize_vm_http_request(&session, &request(source, None)),
            VmHttpAuthorization::Deny(VmHttpAuthError::MissingCredentials)
        );
        assert_eq!(
            authorize_vm_http_request(&session, &request(source, Some("Basic nope".into()))),
            VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
        );
        assert_eq!(
            authorize_vm_http_request(&session, &request(source, Some(bearer("wrong")))),
            VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
        );
    }

    #[test]
    fn non_nix_routes_do_not_accept_basic_auth() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let source = Ipv4Addr::new(10, 1, 2, 42);

        assert_eq!(
            authorize_vm_http_request(&session, &request(source, Some(basic(token().as_str())))),
            VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
        );
    }

    #[test]
    fn authorization_rejects_ipv6_sources() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let request = VmHttpRequest::new(
            "GET",
            "/v1/session",
            Some(bearer(token().as_str())),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 34567, 0, 0)),
        );
        assert_eq!(
            authorize_vm_http_request(&session, &request),
            VmHttpAuthorization::Deny(VmHttpAuthError::SourceOutsideSessionSubnet)
        );
    }

    #[test]
    fn parser_rejects_duplicate_authorization_header() {
        let request = http::Request::builder()
            .method("GET")
            .uri("/v1/session")
            .header("authorization", "Bearer a")
            .header("authorization", "Bearer b")
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        let err = VmHttpRequest::from_hyper_parts(
            &parts,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        )
        .unwrap_err();
        assert_eq!(err, VmHttpParseError::DuplicateAuthorization);
    }

    #[test]
    fn parser_rejects_duplicate_content_length_header() {
        let request = http::Request::builder()
            .method("POST")
            .uri("/v1/git/clone")
            .header("content-length", "2")
            .header("content-length", "2")
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        let err = VmHttpRequest::from_hyper_parts(
            &parts,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        )
        .unwrap_err();
        assert_eq!(err, VmHttpParseError::DuplicateContentLength);
    }

    #[test]
    fn parser_rejects_duplicate_authorization_when_one_value_is_non_utf8() {
        let invalid = http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap();
        let request = http::Request::builder()
            .method("GET")
            .uri("/v1/session")
            .header("authorization", "Bearer a")
            .header("authorization", invalid)
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        let err = VmHttpRequest::from_hyper_parts(
            &parts,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        )
        .unwrap_err();
        assert_eq!(err, VmHttpParseError::DuplicateAuthorization);
    }

    #[test]
    fn parser_rejects_duplicate_content_length_when_one_value_is_non_utf8() {
        let invalid = http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap();
        let request = http::Request::builder()
            .method("POST")
            .uri("/v1/git/clone")
            .header("content-length", "5")
            .header("content-length", invalid)
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        let err = VmHttpRequest::from_hyper_parts(
            &parts,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        )
        .unwrap_err();
        assert_eq!(err, VmHttpParseError::DuplicateContentLength);
    }

    #[test]
    fn authenticated_session_route_returns_session_identity() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let bearer_auth = bearer(token().as_str());
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            "GET",
            "/v1/session",
            Some(bearer_auth.as_str()),
        );
        assert_eq!(response.status, VmHttpStatus::Ok);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["session_id"], session.session_id().to_string());
        assert_eq!(body["api"], "writ-vm-http");
        assert_eq!(body["version"], 1);
    }

    #[test]
    fn every_route_requires_auth_before_path_or_method_checks() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            "POST",
            "/not-real",
            None,
        );
        assert_eq!(response.status, VmHttpStatus::Unauthorized);
    }

    #[test]
    fn authenticated_unknown_route_is_not_found() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let bearer_auth = bearer(token().as_str());
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            "GET",
            "/unknown",
            Some(bearer_auth.as_str()),
        );
        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn disabled_agent_run_config_route_is_not_found() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000402".parse().unwrap();
        let target = crate::agent_run::vm_agent_run_config_path(run_id);
        let request = VmHttpRequest::new(
            "GET",
            &target,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        );

        let response =
            route_authenticated_vm_http_request(&session, &request, Vec::new(), no_services())
                .await
                .into_buffered();

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn authorization_runs_before_body_limit_enforcement() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let oversized = (MAX_VM_HTTP_BODY_BYTES + 1).to_string();
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            "POST",
            VM_GIT_CLONE_PATH,
            &[("content-length", oversized.as_str())],
            Vec::new(),
            no_services(),
            VM_HTTP_READ_TIMEOUT,
        )
        .await;
        assert_eq!(response.status, VmHttpStatus::Unauthorized);
    }

    #[tokio::test]
    async fn session_route_does_not_read_declared_body() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let bearer_auth = bearer(token().as_str());
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dispatch_vm_http_head_and_body(
                &session,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
                "GET",
                "/v1/session",
                &[
                    ("authorization", bearer_auth.as_str()),
                    ("content-length", "1"),
                ],
                Vec::new(),
                no_services(),
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("session route must not wait for a declared body");

        assert_eq!(response.status, VmHttpStatus::Ok);
    }

    #[tokio::test]
    async fn prepare_vm_http_session_returns_in_range_broker_port_and_redacted_token() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let temp = tempfile::tempdir().unwrap();
        let range = BrokerPortRange::new(1024, 65535).unwrap();
        let config = VmHttpRuntimeConfig::new(
            Ipv4Addr::LOCALHOST,
            range,
            git_clone_config_for_test(&temp, write_fake_git(temp.path())),
            nix_cache_config_for_test(),
            temp.path().join("agent-runs"),
        );
        let session_id = "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap();
        let source_ipv4 = Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap();

        let prepared = prepare_vm_http_session(state, &config, session_id, source_ipv4)
            .await
            .unwrap();

        assert!(range.contains(prepared.broker_port()));
        assert_eq!(prepared.session().session_id(), session_id);
        assert_eq!(prepared.session().source_ipv4(), source_ipv4);
        assert!(prepared.bearer_token().as_str().starts_with("writ-vm-"));
        assert!(
            !format!("{:?}", prepared.bearer_token()).contains(prepared.bearer_token().as_str())
        );
    }

    #[tokio::test]
    async fn running_runtime_serves_session_and_shuts_down() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let temp = tempfile::tempdir().unwrap();
        let config = VmHttpRuntimeConfig::new(
            Ipv4Addr::LOCALHOST,
            BrokerPortRange::new(1024, 65535).unwrap(),
            git_clone_config_for_test(&temp, write_fake_git(temp.path())),
            nix_cache_config_for_test(),
            temp.path().join("agent-runs"),
        );
        let session_id = "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap();
        let source_ipv4 = Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap();
        let prepared = prepare_vm_http_session(state, &config, session_id, source_ipv4)
            .await
            .unwrap();
        let addr = prepared.local_addr().unwrap();
        let token = prepared.bearer_token().as_str().to_string();

        let running = prepared.spawn();
        let response = request_over_tcp(
            addr,
            &format!(
                "GET /v1/session HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\n\r\n",
                bearer(&token)
            ),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains(&session_id.to_string()), "{response}");
        assert_eq!(running.bearer_token().as_str(), token);
        running.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn bind_ephemeral_listener_reserves_an_allowed_broker_port() {
        let range = BrokerPortRange::new(1024, 65535).unwrap();
        let bound = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
            .await
            .unwrap();
        assert!(range.contains(bound.broker_port()));
        let addr = bound.local_addr().unwrap();
        let second_bind = TcpListener::bind(addr).await.unwrap_err();
        assert_eq!(second_bind.kind(), std::io::ErrorKind::AddrInUse);
        drop(bound);
    }

    #[tokio::test]
    async fn bind_ephemeral_listener_scans_exact_small_allowed_range() {
        for _ in 0..64 {
            let probe = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);

            let range = BrokerPortRange::new(port, port).unwrap();
            match bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range).await {
                Ok(bound) => {
                    assert_eq!(bound.broker_port().get(), port);
                    return;
                }
                Err(VmHttpBindError::NoAllowedPort { .. }) => {}
                Err(err) => panic!("unexpected bind error: {err}"),
            }
        }

        panic!("could not find a reusable one-port range for VM HTTP bind test");
    }

    #[tokio::test]
    async fn bind_ephemeral_listener_fails_when_small_allowed_range_is_occupied() {
        let occupied = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let port = occupied.local_addr().unwrap().port();
        let range = BrokerPortRange::new(port, port).unwrap();

        let err = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
            .await
            .unwrap_err();

        match err {
            VmHttpBindError::NoAllowedPort { min, max, .. } => {
                assert_eq!(min, port);
                assert_eq!(max, port);
            }
            VmHttpBindError::Io(err) => panic!("unexpected IO error: {err}"),
        }
    }

    #[tokio::test]
    async fn vm_http_server_serves_authenticated_session_request() {
        let range = BrokerPortRange::new(1024, 65535).unwrap();
        let bound = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
            .await
            .unwrap();
        let addr = bound.local_addr().unwrap();
        let session = VmHttpSession::new(
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
            Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
            token(),
        );
        let server = tokio::spawn(run_vm_http(bound.into_listener(), session.clone()));

        let response = request_over_tcp(
            addr,
            &format!(
                "GET /v1/session HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\n\r\n",
                bearer(token().as_str())
            ),
        )
        .await;

        server.abort();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.contains(&session.session_id().to_string()),
            "{response}"
        );
    }

    #[tokio::test]
    async fn vm_http_server_rejects_missing_auth() {
        let range = BrokerPortRange::new(1024, 65535).unwrap();
        let bound = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
            .await
            .unwrap();
        let addr = bound.local_addr().unwrap();
        let session = VmHttpSession::new(
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
            Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
            token(),
        );
        let server = tokio::spawn(run_vm_http(bound.into_listener(), session));

        let response =
            request_over_tcp(addr, "GET /v1/session HTTP/1.1\r\nHost: localhost\r\n\r\n").await;

        server.abort();
        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
            "{response}"
        );
        assert!(response.contains("www-authenticate: Bearer"), "{response}");
    }

    #[tokio::test]
    async fn vm_http_server_exits_when_shutdown_signal_set() {
        let range = BrokerPortRange::new(1024, 65535).unwrap();
        let bound = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
            .await
            .unwrap();
        let session = VmHttpSession::new(
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
            Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
            token(),
        );
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(run_vm_http_until_shutdown(
            bound.into_listener(),
            session,
            shutdown_rx,
        ));

        shutdown_tx.send(true).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires host Nix; proves real Nix netrc auth against the VM HTTP cache route"]
    async fn nix_cli_can_authenticate_to_vm_http_nix_cache_route_with_netrc() {
        let _nix = required_test_tool("nix");
        let temp = tempfile::tempdir().unwrap();
        let netrc = temp.path().join("netrc");
        let token = token();
        std::fs::write(
            &netrc,
            format!(
                "machine 127.0.0.1 login {VM_NIX_BASIC_LOGIN} password {}\n",
                token.as_str()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&netrc, std::fs::Permissions::from_mode(0o600)).unwrap();

        let range = BrokerPortRange::new(1024, 65535).unwrap();
        let bound = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
            .await
            .unwrap();
        let addr = bound.local_addr().unwrap();
        let session = VmHttpSession::new(
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
            Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
            token.clone(),
        );
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(run_vm_http_until_shutdown(
            bound.into_listener(),
            session,
            shutdown_rx,
        ));

        let store_url = format!(
            "http://127.0.0.1:{port}{VM_NIX_CACHE_PATH_PREFIX}",
            port = addr.port()
        );
        let store_path = "/nix/store/00000000000000000000000000000000-writ-nix-route-proof";
        let args = [
            "path-info",
            "--refresh",
            "--store",
            &store_url,
            "--option",
            "experimental-features",
            "nix-command",
            "--option",
            "access-tokens",
            "",
            "--option",
            "substituters",
            "",
            "--option",
            "trusted-public-keys",
            "",
            "--option",
            "netrc-file",
            netrc.to_str().unwrap(),
            store_path,
        ];
        for arg in &args {
            assert!(!arg.contains(token.as_str()), "token leaked into Nix argv");
        }
        assert!(!store_url.contains(token.as_str()));

        let home = temp.path().join("home");
        let xdg_config = temp.path().join("xdg-config");
        let nix_conf = temp.path().join("nix-conf");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&xdg_config).unwrap();
        std::fs::create_dir(&nix_conf).unwrap();
        std::fs::write(nix_conf.join("nix.conf"), "").unwrap();

        let output = tokio::process::Command::new("nix")
            .args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &xdg_config)
            .env("NIX_CONF_DIR", &nix_conf)
            .env("NIX_CONFIG", "")
            .env("TMPDIR", std::env::temp_dir())
            .output()
            .await
            .unwrap();

        shutdown_tx.send(true).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "proof path should miss in the skeleton cache\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(!stdout.contains(token.as_str()), "token leaked to stdout");
        assert!(!stderr.contains(token.as_str()), "token leaked to stderr");
        assert!(!stderr.contains("401"), "Nix was not authorized:\n{stderr}");
        assert!(!stderr.contains("403"), "Nix was forbidden:\n{stderr}");
        assert!(
            stderr.contains("404") || stderr.contains("is not valid"),
            "expected authenticated cache miss, got status {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }

    async fn request_over_tcp(addr: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    #[test]
    fn source_subnet_can_be_taken_from_agent_network_ipv4() {
        let pool = crate::core::AgentNetworkPool::new(
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
            Ipv6Cidr::new("fd83:b6f2:e57::".parse::<std::net::Ipv6Addr>().unwrap(), 48).unwrap(),
        )
        .unwrap();
        let network = pool.allocate(252).unwrap();
        let session = VmHttpSession::new(
            session_for_subnet(network.ipv4()).session_id(),
            network.ipv4(),
            token(),
        );
        assert_eq!(session.source_ipv4(), network.ipv4());
    }
}
