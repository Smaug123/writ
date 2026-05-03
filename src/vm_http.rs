//! VM-facing broker HTTP endpoint.
//!
//! This is deliberately separate from the host Unix-socket protocol. The VM
//! endpoint authenticates one managed agent VM session with a bearer secret and
//! a source-subnet check, then exposes only VM-safe broker operations.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::bearer::is_bearer_token_byte;
use crate::core::{
    BrokerPort, BrokerPortRange, CapabilityRequest, GitHubAccess, GitHubRequest, Ipv4Cidr,
    SessionId,
};
use crate::secret::SecretStore;
use crate::server::{BrokerState, CapabilityOutcome, request_capability};
use crate::vm_git::{
    GIT_BUNDLE_CONTENT_TYPE, VM_GIT_CLONE_PATH, VmGitCloneErrorCode, VmGitCloneErrorResponse,
    VmGitCloneRequest,
};
use crate::vm_git_bundle::{
    GitCloneBundlePlan, GitCloneBundlePlanError, GitCloneBundleRunError, GitCredentialBoundary,
    GitSecretValue, GitSecretValueError, run_git_clone_bundle,
};

const MAX_VM_HTTP_HEAD_BYTES: usize = 16 * 1024;
const MAX_VM_HTTP_BODY_BYTES: usize = 64 * 1024;
const VM_HTTP_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const EPHEMERAL_BIND_ATTEMPTS: usize = 32;
const MAX_VM_HTTP_CONNECTIONS: usize = 256;
pub const VM_NIX_CACHE_PATH_PREFIX: &str = "/v1/nix/cache";
const VM_NIX_CACHE_INFO_PATH: &str = "/v1/nix/cache/nix-cache-info";
const VM_NIX_BASIC_LOGIN: &str = "writ-vm";

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
    peer_addr: SocketAddr,
}

pub struct VmHttpGitCloneService<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    config: VmHttpGitCloneConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpGitRuntimeConfig {
    bind_addr: Ipv4Addr,
    broker_port_range: BrokerPortRange,
    git_clone: VmHttpGitCloneConfig,
}

pub struct PreparedVmHttpGitSession<S: SecretStore + Send + Sync + 'static> {
    listener: BoundVmHttpListener,
    session: VmHttpSession,
    git_clone: VmHttpGitCloneService<S>,
}

pub struct RunningVmHttpGitSession {
    broker_port: BrokerPort,
    bearer_token: VmHttpBearerToken,
    shutdown: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpGitCloneConfig {
    git_program: PathBuf,
    credential: GitCredentialBoundary,
    work_root: PathBuf,
    timeout: std::time::Duration,
    max_bundle_bytes: u64,
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
pub enum VmHttpGitRuntimeError {
    #[error(transparent)]
    Bind(#[from] VmHttpBindError),
}

#[derive(Debug, thiserror::Error)]
pub enum VmHttpGitRuntimeShutdownError {
    #[error("VM HTTP task join failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("VM HTTP server failed: {0}")]
    Server(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
enum VmHttpParseError {
    #[error("HTTP request line is missing")]
    MissingRequestLine,
    #[error("HTTP request line must be METHOD TARGET VERSION")]
    MalformedRequestLine,
    #[error("unsupported HTTP version {0}")]
    UnsupportedVersion(String),
    #[error("malformed HTTP header")]
    MalformedHeader,
    #[error("duplicate Authorization header")]
    DuplicateAuthorization,
    #[error("duplicate Content-Length header")]
    DuplicateContentLength,
    #[error("invalid Content-Length header")]
    InvalidContentLength,
    #[error("Transfer-Encoding is not supported")]
    UnsupportedTransferEncoding,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum VmHttpStatus {
    Ok,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    Gone,
    InternalServerError,
}

#[derive(Debug, Eq, PartialEq)]
struct VmHttpResponse {
    status: VmHttpStatus,
    content_type: &'static str,
    body: Vec<u8>,
    www_authenticate: Option<&'static str>,
}

#[derive(Debug, Eq, PartialEq)]
struct VmHttpHeadRead {
    raw_head: Vec<u8>,
    buffered_body: Vec<u8>,
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum VmNixCacheRoute {
    CacheInfo,
    NarInfo,
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
            peer_addr,
        }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl<S: SecretStore> VmHttpGitCloneService<S> {
    pub fn new(broker_state: Arc<BrokerState<S>>, config: VmHttpGitCloneConfig) -> Self {
        Self {
            broker_state,
            config,
        }
    }
}

impl<S: SecretStore> Clone for VmHttpGitCloneService<S> {
    fn clone(&self) -> Self {
        Self {
            broker_state: Arc::clone(&self.broker_state),
            config: self.config.clone(),
        }
    }
}

impl VmHttpGitRuntimeConfig {
    pub fn new(
        bind_addr: Ipv4Addr,
        broker_port_range: BrokerPortRange,
        git_clone: VmHttpGitCloneConfig,
    ) -> Self {
        Self {
            bind_addr,
            broker_port_range,
            git_clone,
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
}

impl VmHttpGitCloneConfig {
    pub fn new(
        git_program: impl Into<PathBuf>,
        credential: GitCredentialBoundary,
        work_root: impl Into<PathBuf>,
        timeout: std::time::Duration,
        max_bundle_bytes: u64,
    ) -> Result<Self, GitCloneBundlePlanError> {
        let git_program = git_program.into();
        let work_root = work_root.into();
        if git_program.as_os_str().is_empty() {
            return Err(GitCloneBundlePlanError::EmptyPath {
                field: "git_program",
            });
        }
        if work_root.as_os_str().is_empty() {
            return Err(GitCloneBundlePlanError::EmptyPath { field: "work_root" });
        }
        if !work_root.is_absolute() {
            return Err(GitCloneBundlePlanError::RelativePath {
                field: "work_root",
                path: work_root,
            });
        }
        if timeout.is_zero() {
            return Err(GitCloneBundlePlanError::ZeroTimeout);
        }
        if max_bundle_bytes == 0 {
            return Err(GitCloneBundlePlanError::ZeroMaxBundleBytes);
        }
        Ok(Self {
            git_program,
            credential,
            work_root,
            timeout,
            max_bundle_bytes,
        })
    }

    pub fn work_root(&self) -> &Path {
        &self.work_root
    }

    fn plan_for_request(
        &self,
        request: VmGitCloneRequest,
    ) -> Result<GitCloneBundlePlan, GitCloneBundlePlanError> {
        let work_dir = self
            .work_root
            .join(format!("clone-{}", uuid::Uuid::new_v4().simple()));
        let bundle_path = work_dir.join("repo.bundle");
        GitCloneBundlePlan::new(
            self.git_program.clone(),
            request,
            self.credential.clone(),
            work_dir,
            bundle_path,
            self.timeout,
            self.max_bundle_bytes,
        )
    }
}

impl<S: SecretStore + Send + Sync + 'static> PreparedVmHttpGitSession<S> {
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
    pub fn spawn(self) -> RunningVmHttpGitSession {
        let broker_port = self.listener.broker_port();
        let bearer_token = self.session.bearer_token().clone();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_vm_http_with_git_until_shutdown(
            self.listener.into_listener(),
            self.session,
            self.git_clone,
            shutdown_rx,
        ));
        RunningVmHttpGitSession {
            broker_port,
            bearer_token,
            shutdown: shutdown_tx,
            task: Some(task),
        }
    }
}

impl RunningVmHttpGitSession {
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
    pub async fn shutdown(mut self) -> Result<(), VmHttpGitRuntimeShutdownError> {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
}

impl Drop for RunningVmHttpGitSession {
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

/// Bind and prepare a per-session VM HTTP Git runtime without accepting traffic.
///
/// The returned listener owns a concrete broker port before the VM is started.
/// Lifecycle code should install PF rules for [`PreparedVmHttpGitSession::broker_port`],
/// pass [`PreparedVmHttpGitSession::bearer_token`] to the guest, and only then
/// call [`PreparedVmHttpGitSession::spawn`].
pub async fn prepare_vm_http_git_session<S: SecretStore + Send + Sync + 'static>(
    state: Arc<BrokerState<S>>,
    config: &VmHttpGitRuntimeConfig,
    session_id: SessionId,
    source_ipv4: Ipv4Cidr,
) -> Result<PreparedVmHttpGitSession<S>, VmHttpGitRuntimeError> {
    let listener =
        bind_ephemeral_vm_http_listener(config.bind_addr, config.broker_port_range).await?;
    let session = VmHttpSession::new(session_id, source_ipv4, VmHttpBearerToken::generate());
    let git_clone = VmHttpGitCloneService::new(state, config.git_clone.clone());
    Ok(PreparedVmHttpGitSession {
        listener,
        session,
        git_clone,
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
    run_vm_http_runtime_until_shutdown::<Box<dyn SecretStore>>(listener, session, None, shutdown)
        .await
}

pub async fn run_vm_http_with_git_until_shutdown<S: SecretStore + Send + Sync + 'static>(
    listener: TcpListener,
    session: VmHttpSession,
    git_clone: VmHttpGitCloneService<S>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    run_vm_http_runtime_until_shutdown(listener, session, Some(git_clone), shutdown).await
}

async fn run_vm_http_runtime_until_shutdown<S: SecretStore + Send + Sync + 'static>(
    listener: TcpListener,
    session: VmHttpSession,
    git_clone: Option<VmHttpGitCloneService<S>>,
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
                let git_clone = git_clone.clone();
                handlers.spawn(async move {
                    handle_vm_http_connection(stream, peer_addr, session, git_clone).await
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
    if constant_time_eq(token.as_bytes(), session.bearer_token.as_str().as_bytes()) {
        VmHttpAuthorization::Allow
    } else {
        VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
    }
}

fn authorize_basic_header(session: &VmHttpSession, header: &str) -> VmHttpAuthorization {
    let Some(encoded) = header.strip_prefix("Basic ") else {
        return VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials);
    };
    let expected = basic_authorization_value(session);
    if constant_time_eq(encoded.as_bytes(), expected.as_bytes()) {
        VmHttpAuthorization::Allow
    } else {
        VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
    }
}

fn basic_authorization_value(session: &VmHttpSession) -> String {
    let credentials = format!("{VM_NIX_BASIC_LOGIN}:{}", session.bearer_token.as_str());
    base64_standard(credentials.as_bytes())
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
    git_clone: Option<VmHttpGitCloneService<S>>,
) -> std::io::Result<()> {
    handle_vm_http_connection_with_read_timeout(
        stream,
        peer_addr,
        session,
        git_clone,
        VM_HTTP_READ_TIMEOUT,
    )
    .await
}

async fn handle_vm_http_connection_with_read_timeout<S, T>(
    mut stream: T,
    peer_addr: SocketAddr,
    session: VmHttpSession,
    git_clone: Option<VmHttpGitCloneService<S>>,
    read_timeout: std::time::Duration,
) -> std::io::Result<()>
where
    S: SecretStore + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let head = match tokio::time::timeout(
        read_timeout,
        read_http_head_bounded(&mut stream, MAX_VM_HTTP_HEAD_BYTES),
    )
    .await
    {
        Err(_) => return Ok(()),
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::InvalidData => {
            let response = VmHttpResponse::text(VmHttpStatus::BadRequest, err.to_string());
            return stream.write_all(&response.to_bytes()).await;
        }
        Ok(Err(err)) => return Err(err),
        Ok(Ok(head)) => head,
    };

    let response = dispatch_vm_http_head_and_body(
        &session,
        peer_addr,
        head,
        &mut stream,
        git_clone,
        read_timeout,
    )
    .await;
    stream.write_all(&response.to_bytes()).await
}

#[cfg(test)]
fn dispatch_vm_http_head(
    session: &VmHttpSession,
    peer_addr: SocketAddr,
    raw: &[u8],
) -> VmHttpResponse {
    let request = match parse_http_head(raw, peer_addr) {
        Ok(request) => request,
        Err(err) => return VmHttpResponse::text(VmHttpStatus::BadRequest, err.to_string()),
    };
    let auth_scheme = auth_scheme_for_target(&request.target);
    match authorize_vm_http_request_with_scheme(session, &request, auth_scheme) {
        VmHttpAuthorization::Allow if is_nix_cache_target(&request.target) => {
            route_nix_cache_request(&request)
        }
        VmHttpAuthorization::Allow => route_session_endpoint(session, &request),
        VmHttpAuthorization::Deny(err) => auth_error_response(auth_scheme, err),
    }
}

async fn dispatch_vm_http_head_and_body<S, R>(
    session: &VmHttpSession,
    peer_addr: SocketAddr,
    head: VmHttpHeadRead,
    stream: &mut R,
    git_clone: Option<VmHttpGitCloneService<S>>,
    read_timeout: std::time::Duration,
) -> VmHttpResponse
where
    S: SecretStore + Send + Sync,
    R: AsyncRead + Unpin,
{
    let request = match parse_http_head(&head.raw_head, peer_addr) {
        Ok(request) => request,
        Err(err) => return VmHttpResponse::text(VmHttpStatus::BadRequest, err.to_string()),
    };
    let auth_scheme = auth_scheme_for_target(&request.target);
    match authorize_vm_http_request_with_scheme(session, &request, auth_scheme) {
        VmHttpAuthorization::Allow => {
            route_authenticated_vm_http_request(
                session,
                &request,
                head.buffered_body,
                stream,
                git_clone,
                read_timeout,
            )
            .await
        }
        VmHttpAuthorization::Deny(err) => auth_error_response(auth_scheme, err),
    }
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

async fn route_authenticated_vm_http_request<S, R>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    buffered_body: Vec<u8>,
    stream: &mut R,
    git_clone: Option<VmHttpGitCloneService<S>>,
    read_timeout: std::time::Duration,
) -> VmHttpResponse
where
    S: SecretStore + Send + Sync,
    R: AsyncRead + Unpin,
{
    if is_nix_cache_target(&request.target) {
        return route_nix_cache_request(request);
    }

    if request.target == VM_GIT_CLONE_PATH {
        let Some(service) = git_clone else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
        };
        if request.method != "POST" {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
        }
        let body = match read_http_body_for_git_clone_route(
            stream,
            request.content_length.unwrap_or(0),
            buffered_body,
            read_timeout,
        )
        .await
        {
            Ok(body) => body,
            Err(response) => return response,
        };
        return handle_git_clone_request(session, &body, service).await;
    }

    route_session_endpoint(session, request)
}

fn route_nix_cache_request(request: &VmHttpRequest) -> VmHttpResponse {
    let Some(route) = classify_nix_cache_target(&request.target) else {
        return VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
    };
    match (request.method.as_str(), route) {
        ("GET", VmNixCacheRoute::CacheInfo) => VmHttpResponse::text(
            VmHttpStatus::Ok,
            "StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 40\n",
        ),
        ("HEAD", VmNixCacheRoute::CacheInfo) => VmHttpResponse::text(VmHttpStatus::Ok, ""),
        ("GET" | "HEAD", VmNixCacheRoute::NarInfo) => {
            VmHttpResponse::text(VmHttpStatus::NotFound, "not found")
        }
        (_, VmNixCacheRoute::CacheInfo | VmNixCacheRoute::NarInfo) => {
            VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed")
        }
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

fn is_nix_cache_target(target: &str) -> bool {
    target == VM_NIX_CACHE_PATH_PREFIX
        || target == VM_NIX_CACHE_INFO_PATH
        || target
            .strip_prefix(VM_NIX_CACHE_PATH_PREFIX)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn classify_nix_cache_target(target: &str) -> Option<VmNixCacheRoute> {
    if target == VM_NIX_CACHE_INFO_PATH {
        return Some(VmNixCacheRoute::CacheInfo);
    }
    let suffix = target.strip_prefix(&format!("{VM_NIX_CACHE_PATH_PREFIX}/"))?;
    let hash = suffix.strip_suffix(".narinfo")?;
    if is_nix_store_hash_part(hash) {
        Some(VmNixCacheRoute::NarInfo)
    } else {
        None
    }
}

fn is_nix_store_hash_part(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
}

async fn read_http_body_for_git_clone_route<R: AsyncRead + Unpin>(
    stream: &mut R,
    content_length: usize,
    buffered_body: Vec<u8>,
    read_timeout: std::time::Duration,
) -> Result<Vec<u8>, VmHttpResponse> {
    match tokio::time::timeout(
        read_timeout,
        read_http_body_bounded(
            stream,
            content_length,
            buffered_body,
            MAX_VM_HTTP_BODY_BYTES,
        ),
    )
    .await
    {
        Err(_) => Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "incomplete request body",
        )),
        Ok(Ok(body)) => Ok(body),
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::InvalidData => Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            err.to_string(),
        )),
        Ok(Err(_)) => Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "incomplete request body",
        )),
    }
}

async fn handle_git_clone_request<S: SecretStore + Send + Sync>(
    session: &VmHttpSession,
    body: &[u8],
    service: VmHttpGitCloneService<S>,
) -> VmHttpResponse {
    let request = match serde_json::from_slice::<VmGitCloneRequest>(body) {
        Ok(request) => request,
        Err(err) => {
            return git_error_response(
                VmHttpStatus::BadRequest,
                VmGitCloneErrorCode::InvalidRequest,
                format!("invalid Git clone request: {err}"),
            );
        }
    };

    let capability = git_clone_authorization_request(&request);
    let outcome = request_capability(session.session_id, capability, &service.broker_state).await;
    let token = match git_clone_token_from_capability_outcome(outcome) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let secret = match GitSecretValue::new(token) {
        Ok(secret) => secret,
        Err(err) => {
            return git_error_response(
                VmHttpStatus::InternalServerError,
                VmGitCloneErrorCode::CloneFailed,
                git_secret_error_message(err),
            );
        }
    };
    let plan = match service.config.plan_for_request(request) {
        Ok(plan) => plan,
        Err(err) => {
            return git_error_response(
                VmHttpStatus::InternalServerError,
                VmGitCloneErrorCode::CloneFailed,
                format!("invalid Git clone service configuration: {err}"),
            );
        }
    };

    match run_git_clone_bundle_and_read(&plan, &secret).await {
        Ok(bundle) => VmHttpResponse {
            status: VmHttpStatus::Ok,
            content_type: GIT_BUNDLE_CONTENT_TYPE,
            body: bundle,
            www_authenticate: None,
        },
        Err(message) => git_error_response(
            VmHttpStatus::InternalServerError,
            VmGitCloneErrorCode::CloneFailed,
            message,
        ),
    }
}

fn git_clone_authorization_request(request: &VmGitCloneRequest) -> CapabilityRequest {
    CapabilityRequest::GitHub(GitHubRequest::Contents {
        access: GitHubAccess::Read,
        repo: request.repo().as_repo_ref().clone(),
    })
}

fn git_clone_token_from_capability_outcome(
    outcome: CapabilityOutcome,
) -> Result<String, VmHttpResponse> {
    match outcome {
        CapabilityOutcome::Granted { token, .. } => Ok(token),
        CapabilityOutcome::Denied { reason } => Err(git_error_response(
            VmHttpStatus::Forbidden,
            VmGitCloneErrorCode::Denied,
            reason,
        )),
        CapabilityOutcome::UnknownSession { .. } => Err(git_error_response(
            VmHttpStatus::Unauthorized,
            VmGitCloneErrorCode::Denied,
            "session is not active",
        )),
        CapabilityOutcome::ClosedSession { .. } => Err(git_error_response(
            VmHttpStatus::Gone,
            VmGitCloneErrorCode::Denied,
            "session is closed",
        )),
        CapabilityOutcome::Error { message } => {
            eprintln!("VM HTTP Git clone credential request failed: {message}");
            Err(git_error_response(
                VmHttpStatus::InternalServerError,
                VmGitCloneErrorCode::CloneFailed,
                "credential request failed",
            ))
        }
    }
}

async fn run_git_clone_bundle_and_read(
    plan: &GitCloneBundlePlan,
    secret: &GitSecretValue,
) -> Result<Vec<u8>, String> {
    prepare_git_work_root(plan.work_dir().parent().ok_or_else(|| {
        format!(
            "Git clone work directory has no parent: {}",
            plan.work_dir().display()
        )
    })?)
    .await?;

    let work_dir = plan.work_dir().to_path_buf();
    let run_result = async {
        run_git_clone_bundle(plan, secret)
            .await
            .map_err(git_clone_run_error_message)?;
        // TODO: stream the bundle into the HTTP response instead of buffering
        // it here once the VM HTTP response type supports streaming bodies.
        tokio::fs::read(plan.bundle_path()).await.map_err(|err| {
            format!(
                "cannot read Git bundle {}: {err}",
                plan.bundle_path().display()
            )
        })
    }
    .await;

    let cleanup_result = match tokio::fs::remove_dir_all(&work_dir).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "cannot remove Git clone work directory {}: {err}",
            work_dir.display()
        )),
    };

    match (run_result, cleanup_result) {
        (Ok(bundle), Ok(())) => Ok(bundle),
        (Ok(_), Err(cleanup)) => Err(format!(
            "Git clone completed but temporary artifacts were not removed: {cleanup}"
        )),
        (Err(original), Ok(())) => Err(original),
        (Err(original), Err(cleanup)) => Err(format!("{original}; additionally, {cleanup}")),
    }
}

async fn prepare_git_work_root(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => validate_git_work_root_metadata(path, &metadata),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = tokio::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(path).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|err| {
                        format!(
                            "cannot inspect Git clone work root {}: {err}",
                            path.display()
                        )
                    })?;
                    return validate_git_work_root_metadata(path, &metadata);
                }
                Err(err) => {
                    return Err(format!(
                        "cannot create Git clone work root {}: {err}",
                        path.display()
                    ));
                }
            }
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .await
                .map_err(|err| {
                    format!(
                        "cannot set Git clone work root permissions for {}: {err}",
                        path.display()
                    )
                })
        }
        Err(err) => Err(format!(
            "cannot inspect Git clone work root {}: {err}",
            path.display()
        )),
    }
}

fn validate_git_work_root_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    if !metadata.is_dir() {
        return Err(format!(
            "Git clone work root is not a directory: {}",
            path.display()
        ));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "Git clone work root {} has group/world access bits (mode {:04o}); \
             use a dedicated 0700 directory",
            path.display(),
            mode & 0o777
        ));
    }
    Ok(())
}

fn git_error_response(
    status: VmHttpStatus,
    error: VmGitCloneErrorCode,
    message: impl Into<String>,
) -> VmHttpResponse {
    VmHttpResponse::json(status, &VmGitCloneErrorResponse::new(error, message))
}

fn git_secret_error_message(err: GitSecretValueError) -> String {
    format!("minted Git credential cannot be passed to Git: {err}")
}

fn git_clone_run_error_message(err: GitCloneBundleRunError) -> String {
    format!("Git clone failed: {err}")
}

async fn read_http_head_bounded<R: AsyncRead + Unpin>(
    stream: &mut R,
    max: usize,
) -> std::io::Result<VmHttpHeadRead> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before complete HTTP header",
            ));
        }

        buf.extend_from_slice(&chunk[..read]);
        if let Some(index) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            let head_end = index + 4;
            if head_end > max {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("HTTP request header exceeds {max}-byte limit"),
                ));
            }
            let buffered_body = buf.split_off(head_end);
            return Ok(VmHttpHeadRead {
                raw_head: buf,
                buffered_body,
            });
        }
        if buf.len() > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("HTTP request header exceeds {max}-byte limit"),
            ));
        }
    }
}

async fn read_http_body_bounded<R: AsyncRead + Unpin>(
    stream: &mut R,
    content_length: usize,
    mut buffered_body: Vec<u8>,
    max: usize,
) -> std::io::Result<Vec<u8>> {
    if content_length > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("HTTP request body exceeds {max}-byte limit"),
        ));
    }
    if buffered_body.len() >= content_length {
        buffered_body.truncate(content_length);
        return Ok(buffered_body);
    }

    let mut body = buffered_body;
    let already_buffered = body.len();
    body.resize(content_length, 0);
    stream.read_exact(&mut body[already_buffered..]).await?;
    Ok(body)
}

fn parse_http_head(raw: &[u8], peer_addr: SocketAddr) -> Result<VmHttpRequest, VmHttpParseError> {
    let head = std::str::from_utf8(raw).map_err(|_| VmHttpParseError::MalformedHeader)?;
    let head = head
        .split_once("\r\n\r\n")
        .map(|(head, _)| head)
        .ok_or(VmHttpParseError::MalformedHeader)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(VmHttpParseError::MissingRequestLine)?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or(VmHttpParseError::MalformedRequestLine)?;
    let target = request_parts
        .next()
        .ok_or(VmHttpParseError::MalformedRequestLine)?;
    let version = request_parts
        .next()
        .ok_or(VmHttpParseError::MalformedRequestLine)?;
    if request_parts.next().is_some() {
        return Err(VmHttpParseError::MalformedRequestLine);
    }
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(VmHttpParseError::UnsupportedVersion(version.to_string()));
    }

    let mut authorization = None;
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(VmHttpParseError::MalformedHeader);
        };
        if name.eq_ignore_ascii_case("authorization") {
            if authorization.is_some() {
                return Err(VmHttpParseError::DuplicateAuthorization);
            }
            authorization = Some(value.trim().to_string());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(VmHttpParseError::DuplicateContentLength);
            }
            let value = value.trim();
            if value.is_empty() || value.starts_with('+') || value.starts_with('-') {
                return Err(VmHttpParseError::InvalidContentLength);
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| VmHttpParseError::InvalidContentLength)?,
            );
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(VmHttpParseError::UnsupportedTransferEncoding);
        }
    }

    Ok(VmHttpRequest {
        method: method.to_string(),
        target: target.to_string(),
        authorization,
        content_length,
        peer_addr,
    })
}

impl VmHttpResponse {
    fn json<T: Serialize>(status: VmHttpStatus, value: &T) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(value).expect("VM HTTP response always serializes"),
            www_authenticate: None,
        }
    }

    fn text(status: VmHttpStatus, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.into().into_bytes(),
            www_authenticate: None,
        }
    }

    fn unauthorized(challenge: &'static str, body: impl Into<String>) -> Self {
        Self {
            status: VmHttpStatus::Unauthorized,
            content_type: "text/plain; charset=utf-8",
            body: body.into().into_bytes(),
            www_authenticate: Some(challenge),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status.status_line(),
            self.content_type,
            self.body.len()
        )
        .into_bytes();
        if let Some(challenge) = self.www_authenticate {
            out.extend_from_slice(format!("WWW-Authenticate: {challenge}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

impl VmHttpStatus {
    fn status_line(self) -> &'static str {
        match self {
            Self::Ok => "200 OK",
            Self::BadRequest => "400 Bad Request",
            Self::Unauthorized => "401 Unauthorized",
            Self::Forbidden => "403 Forbidden",
            Self::NotFound => "404 Not Found",
            Self::MethodNotAllowed => "405 Method Not Allowed",
            Self::Gone => "410 Gone",
            Self::InternalServerError => "500 Internal Server Error",
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    // The loop count depends only on the expected session secret length, not
    // on the attacker-supplied candidate token length.
    for (index, right_byte) in right.iter().copied().enumerate() {
        let left_byte = left.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

fn base64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);

        out.push(ALPHABET[usize::from(first >> 2)] as char);
        out.push(ALPHABET[usize::from(((first & 0b0000_0011) << 4) | (second >> 4))] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[usize::from(((second & 0b0000_1111) << 2) | (third >> 6))] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[usize::from(third & 0b0011_1111)] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn report_vm_http_handler_result(result: Result<std::io::Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => eprintln!("VM HTTP connection error: {err}"),
        Err(err) => eprintln!("VM HTTP connection task failed: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    use proptest::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::audit::AuditLog;
    use crate::core::{Ipv6Cidr, RepoRef, SessionRecord, TtlSeconds, UnixMillis};
    use crate::github::{GitHubAppConfig, GitHubMinter};
    use crate::policy::PolicyConfig;
    use crate::secret::{SecretError, SecretKey};
    use crate::vm_git::GitCloneRepo;
    use crate::vm_git_bundle::GitSecretEnvVar;

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

    const TEST_PRIV: &str = include_str!("../tests/fixtures/rsa_test_1.pem");

    fn session_for_subnet(ipv4: Ipv4Cidr) -> VmHttpSession {
        VmHttpSession::new(
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
            ipv4,
            token(),
        )
    }

    fn token() -> VmHttpBearerToken {
        VmHttpBearerToken::new("test-token-0123456789abcdef").unwrap()
    }

    fn repo(owner: &str, name: &str) -> RepoRef {
        RepoRef {
            owner: owner.into(),
            name: name.into(),
        }
    }

    fn make_broker_state(server: &MockServer) -> Arc<BrokerState<Box<dyn SecretStore>>> {
        let pk = SecretKey::new("gh-app-pk").unwrap();
        let store = InMemStore::default();
        store.put(&pk, TEST_PRIV).unwrap();
        Arc::new(BrokerState {
            audit: AuditLog::open_in_memory().unwrap(),
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

    fn open_audit_session(state: &BrokerState<Box<dyn SecretStore>>, session_id: SessionId) {
        state
            .audit
            .open_session(&SessionRecord {
                session_id,
                label: Some("vm-http-test".into()),
                agent_model: None,
                opened_at: UnixMillis::now(),
                closed_at: None,
            })
            .unwrap();
    }

    fn expiry_str_from_now(secs: i64) -> String {
        let t = time::OffsetDateTime::now_utc() + time::Duration::seconds(secs);
        t.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    }

    fn write_fake_git(dir: &Path) -> PathBuf {
        write_fake_git_with_bundle_epilogue(dir, "")
    }

    fn write_fake_git_with_bundle_epilogue(dir: &Path, bundle_epilogue: &str) -> PathBuf {
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

    fn shell_single_quote(path: &Path) -> String {
        let raw = path.to_string_lossy();
        format!("'{}'", raw.replace('\'', "'\\''"))
    }

    fn required_test_tool(name: &str) -> PathBuf {
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

    fn git_clone_service_for_test(
        state: &Arc<BrokerState<Box<dyn SecretStore>>>,
        temp: &tempfile::TempDir,
        fake_git: PathBuf,
    ) -> VmHttpGitCloneService<Box<dyn SecretStore>> {
        VmHttpGitCloneService::new(Arc::clone(state), git_clone_config_for_test(temp, fake_git))
    }

    fn git_clone_config_for_test(
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
            std::time::Duration::from_secs(5),
            1024,
        )
        .unwrap()
    }

    fn request(source: Ipv4Addr, authorization: Option<String>) -> VmHttpRequest {
        VmHttpRequest::new(
            "GET",
            "/v1/session",
            authorization,
            SocketAddr::V4(SocketAddrV4::new(source, 34567)),
        )
    }

    fn bearer(value: &str) -> String {
        format!("Bearer {value}")
    }

    fn basic(value: &str) -> String {
        format!(
            "Basic {}",
            base64_standard(format!("{VM_NIX_BASIC_LOGIN}:{value}").as_bytes())
        )
    }

    fn nix_cache_request(
        method: impl Into<String>,
        target: impl Into<String>,
        source: Ipv4Addr,
        authorization: Option<String>,
    ) -> VmHttpRequest {
        VmHttpRequest::new(
            method,
            target,
            authorization,
            SocketAddr::V4(SocketAddrV4::new(source, 34567)),
        )
    }

    fn arb_nix_hash_part() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop::sample::select(
                b"0123456789abcdfghijklmnpqrsvwxyz"
                    .iter()
                    .copied()
                    .map(char::from)
                    .collect::<Vec<_>>(),
            ),
            32,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    fn arb_wrong_length_nix_hash_part() -> impl Strategy<Value = String> {
        prop_oneof![0usize..32, 33usize..64].prop_flat_map(|len| {
            prop::collection::vec(
                prop::sample::select(
                    b"0123456789abcdfghijklmnpqrsvwxyz"
                        .iter()
                        .copied()
                        .map(char::from)
                        .collect::<Vec<_>>(),
                ),
                len,
            )
            .prop_map(|chars| chars.into_iter().collect())
        })
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

    #[test]
    fn bearer_token_comparison_rejects_prefixes_and_suffixes() {
        let expected = b"test-token";
        assert!(constant_time_eq(expected, expected));
        assert!(!constant_time_eq(b"test", expected));
        assert!(!constant_time_eq(b"test-token-extra", expected));
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
        fn parse_http_head_is_total_for_bounded_bytes(
            raw in prop::collection::vec(any::<u8>(), 0..MAX_VM_HTTP_HEAD_BYTES + 1),
        ) {
            let peer_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345));
            let _ = parse_http_head(&raw, peer_addr);
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

        #[test]
        fn valid_nix_store_hash_parts_are_narinfo_routes(hash in arb_nix_hash_part()) {
            let target = format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo");
            prop_assert_eq!(classify_nix_cache_target(&target), Some(VmNixCacheRoute::NarInfo));
        }

        #[test]
        fn wrong_length_nix_store_hash_parts_are_not_narinfo_routes(hash in arb_wrong_length_nix_hash_part()) {
            let target = format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo");
            prop_assert_eq!(classify_nix_cache_target(&target), None);
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
    fn nix_cache_routes_accept_basic_auth_only() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let source = Ipv4Addr::new(10, 1, 2, 42);

        assert_eq!(
            authorize_vm_http_request(
                &session,
                &nix_cache_request(
                    "GET",
                    VM_NIX_CACHE_INFO_PATH,
                    source,
                    Some(basic(token().as_str()))
                ),
            ),
            VmHttpAuthorization::Allow
        );
        assert_eq!(
            authorize_vm_http_request(
                &session,
                &nix_cache_request(
                    "GET",
                    VM_NIX_CACHE_INFO_PATH,
                    source,
                    Some(bearer(token().as_str()))
                ),
            ),
            VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
        );
        assert_eq!(
            authorize_vm_http_request(
                &session,
                &nix_cache_request("GET", VM_NIX_CACHE_INFO_PATH, source, Some(basic("wrong"))),
            ),
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
    fn nix_cache_auth_challenge_is_basic() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            format!("GET {VM_NIX_CACHE_INFO_PATH} HTTP/1.1\r\n\r\n").as_bytes(),
        );

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        let wire = String::from_utf8(response.to_bytes()).unwrap();
        assert!(
            wire.contains("WWW-Authenticate: Basic realm=\"writ-nix-cache\""),
            "{wire}"
        );
        assert!(!wire.contains("WWW-Authenticate: Bearer"), "{wire}");
    }

    #[test]
    fn nix_cache_info_route_returns_binary_cache_metadata() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            format!(
                "GET {VM_NIX_CACHE_INFO_PATH} HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
                basic(token().as_str())
            )
            .as_bytes(),
        );

        assert_eq!(response.status, VmHttpStatus::Ok);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains("StoreDir: /nix/store"), "{body}");
        assert!(body.contains("WantMassQuery: 0"), "{body}");
        assert!(body.contains("Priority: 40"), "{body}");
    }

    #[test]
    fn nix_cache_narinfo_route_returns_controlled_miss() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let target = format!("{VM_NIX_CACHE_PATH_PREFIX}/00000000000000000000000000000000.narinfo");
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            format!(
                "GET {target} HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
                basic(token().as_str())
            )
            .as_bytes(),
        );

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[test]
    fn nix_cache_path_classifier_rejects_non_cache_protocol_paths() {
        for target in [
            VM_NIX_CACHE_PATH_PREFIX,
            "/v1/nix/cache/",
            "/v1/nix/cache/not-a-store-hash.narinfo",
            "/v1/nix/cache/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.narinfo",
            "/v1/nix/cache/00000000000000000000000000000000.nar",
            "/v1/nix/cache/subdir/00000000000000000000000000000000.narinfo",
            "/v1/nix/cacheevil/00000000000000000000000000000000.narinfo",
        ] {
            assert_eq!(
                classify_nix_cache_target(target),
                None,
                "accepted {target:?}"
            );
        }
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
        let raw = b"GET /v1/session HTTP/1.1\r\nAuthorization: Bearer a\r\nauthorization: Bearer b\r\n\r\n";
        let err = parse_http_head(
            raw,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        )
        .unwrap_err();
        assert_eq!(err, VmHttpParseError::DuplicateAuthorization);
    }

    #[test]
    fn parser_rejects_duplicate_content_length_header() {
        let raw =
            b"POST /v1/git/clone HTTP/1.1\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\n{}";
        let err = parse_http_head(
            raw,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        )
        .unwrap_err();
        assert_eq!(err, VmHttpParseError::DuplicateContentLength);
    }

    #[test]
    fn parser_rejects_transfer_encoding_header() {
        let raw = b"POST /v1/git/clone HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let err = parse_http_head(
            raw,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        )
        .unwrap_err();
        assert_eq!(err, VmHttpParseError::UnsupportedTransferEncoding);
    }

    #[test]
    fn authenticated_session_route_returns_session_identity() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            format!(
                "GET /v1/session HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
                bearer(token().as_str())
            )
            .as_bytes(),
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
            b"POST /not-real HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status, VmHttpStatus::Unauthorized);
    }

    #[test]
    fn authenticated_unknown_route_is_not_found() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            format!(
                "GET /unknown HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
                bearer(token().as_str())
            )
            .as_bytes(),
        );
        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn disabled_git_clone_route_is_not_found_for_all_methods() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345));

        for method in ["GET", "POST"] {
            let request = VmHttpRequest::new(
                method,
                VM_GIT_CLONE_PATH,
                Some(bearer(token().as_str())),
                peer,
            );
            let mut stream = tokio::io::empty();
            let response = route_authenticated_vm_http_request(
                &session,
                &request,
                Vec::new(),
                &mut stream,
                None::<VmHttpGitCloneService<Box<dyn SecretStore>>>,
                VM_HTTP_READ_TIMEOUT,
            )
            .await;

            assert_eq!(response.status, VmHttpStatus::NotFound);
        }
    }

    #[tokio::test]
    async fn enabled_git_clone_route_is_not_found_for_non_post_methods() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let temp = tempfile::tempdir().unwrap();
        let service = git_clone_service_for_test(&state, &temp, write_fake_git(temp.path()));
        let request = VmHttpRequest::new(
            "GET",
            VM_GIT_CLONE_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
        );

        let mut stream = tokio::io::empty();
        let response = route_authenticated_vm_http_request(
            &session,
            &request,
            Vec::new(),
            &mut stream,
            Some(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[test]
    fn git_clone_capability_denial_maps_to_forbidden_error_response() {
        let response = git_clone_token_from_capability_outcome(CapabilityOutcome::Denied {
            reason: "policy says no".into(),
        })
        .unwrap_err();

        assert_eq!(response.status, VmHttpStatus::Forbidden);
        let body: VmGitCloneErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmGitCloneErrorCode::Denied);
        assert_eq!(body.message(), "policy says no");
    }

    #[test]
    fn git_clone_authorization_request_grants_github_contents_read_scope() {
        let request =
            VmGitCloneRequest::new(GitCloneRepo::new(repo("smaug123", "writ")).unwrap(), None);

        match git_clone_authorization_request(&request) {
            CapabilityRequest::GitHub(GitHubRequest::Contents { access, repo }) => {
                assert_eq!(access, GitHubAccess::Read);
                assert_eq!(repo, "smaug123/writ".parse::<RepoRef>().unwrap());
            }
            other => panic!("unexpected capability: {other:?}"),
        }
    }

    #[tokio::test]
    async fn bounded_reader_accepts_terminator_at_limit_before_body_bytes() {
        let head = b"GET /v1/session HTTP/1.1\r\n\r\n";
        let mut input = head.to_vec();
        input.extend_from_slice(b"body ignored after header");
        let (mut client, mut server) = tokio::io::duplex(input.len() + 1);

        client.write_all(&input).await.unwrap();
        drop(client);

        let got = read_http_head_bounded(&mut server, head.len())
            .await
            .unwrap();
        assert_eq!(got.raw_head, head);
        assert_eq!(got.buffered_body, b"body ignored after header");
    }

    #[tokio::test]
    async fn body_reader_preserves_body_bytes_buffered_with_header() {
        let head = b"POST /v1/git/clone HTTP/1.1\r\nContent-Length: 14\r\n\r\n";
        let mut input = head.to_vec();
        input.extend_from_slice(br#"{"repo":"o/n"}extra pipelined bytes"#);
        let (mut client, mut server) = tokio::io::duplex(input.len() + 1);

        client.write_all(&input).await.unwrap();
        drop(client);

        let got_head = read_http_head_bounded(&mut server, MAX_VM_HTTP_HEAD_BYTES)
            .await
            .unwrap();
        let request = parse_http_head(
            &got_head.raw_head,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
        )
        .unwrap();
        let body = read_http_body_bounded(
            &mut server,
            request.content_length.unwrap(),
            got_head.buffered_body,
            MAX_VM_HTTP_BODY_BYTES,
        )
        .await
        .unwrap();

        assert_eq!(body, br#"{"repo":"o/n"}"#);
    }

    #[tokio::test]
    async fn authorization_runs_before_body_limit_enforcement() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let raw_head = format!(
            "POST {VM_GIT_CLONE_PATH} HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_VM_HTTP_BODY_BYTES + 1
        )
        .into_bytes();
        let mut stream = tokio::io::empty();
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            VmHttpHeadRead {
                raw_head,
                buffered_body: Vec::new(),
            },
            &mut stream,
            None::<VmHttpGitCloneService<Box<dyn SecretStore>>>,
            VM_HTTP_READ_TIMEOUT,
        )
        .await;
        assert_eq!(response.status, VmHttpStatus::Unauthorized);
    }

    #[tokio::test]
    async fn session_route_does_not_read_declared_body() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let raw_head = format!(
            "GET /v1/session HTTP/1.1\r\nAuthorization: {}\r\nContent-Length: 1\r\n\r\n",
            bearer(token().as_str())
        )
        .into_bytes();
        let (_client, mut stream) = tokio::io::duplex(1);

        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dispatch_vm_http_head_and_body(
                &session,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
                VmHttpHeadRead {
                    raw_head,
                    buffered_body: Vec::new(),
                },
                &mut stream,
                None::<VmHttpGitCloneService<Box<dyn SecretStore>>>,
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("session route must not wait for a declared body");

        assert_eq!(response.status, VmHttpStatus::Ok);
    }

    #[tokio::test]
    async fn disabled_git_clone_route_does_not_read_declared_body() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let raw_head = format!(
            "POST {VM_GIT_CLONE_PATH} HTTP/1.1\r\nAuthorization: {}\r\nContent-Length: 1\r\n\r\n",
            bearer(token().as_str())
        )
        .into_bytes();
        let (_client, mut stream) = tokio::io::duplex(1);

        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dispatch_vm_http_head_and_body(
                &session,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
                VmHttpHeadRead {
                    raw_head,
                    buffered_body: Vec::new(),
                },
                &mut stream,
                None::<VmHttpGitCloneService<Box<dyn SecretStore>>>,
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("disabled Git clone route must not wait for a declared body");

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn enabled_git_clone_non_post_route_does_not_read_declared_body() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let temp = tempfile::tempdir().unwrap();
        let service = git_clone_service_for_test(&state, &temp, write_fake_git(temp.path()));
        let raw_head = format!(
            "GET {VM_GIT_CLONE_PATH} HTTP/1.1\r\nAuthorization: {}\r\nContent-Length: 1\r\n\r\n",
            bearer(token().as_str())
        )
        .into_bytes();
        let (_client, mut stream) = tokio::io::duplex(1);

        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dispatch_vm_http_head_and_body(
                &session,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
                VmHttpHeadRead {
                    raw_head,
                    buffered_body: Vec::new(),
                },
                &mut stream,
                Some(service),
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("non-POST Git clone route must not wait for a declared body");

        assert_eq!(response.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn nix_cache_route_does_not_read_declared_body() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let raw_head = format!(
            "GET {VM_NIX_CACHE_INFO_PATH} HTTP/1.1\r\nAuthorization: {}\r\nContent-Length: 1\r\n\r\n",
            basic(token().as_str())
        )
        .into_bytes();
        let (_client, mut stream) = tokio::io::duplex(1);

        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dispatch_vm_http_head_and_body(
                &session,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
                VmHttpHeadRead {
                    raw_head,
                    buffered_body: Vec::new(),
                },
                &mut stream,
                None::<VmHttpGitCloneService<Box<dyn SecretStore>>>,
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("Nix cache route must not wait for a declared body");

        assert_eq!(response.status, VmHttpStatus::Ok);
    }

    #[tokio::test]
    async fn git_clone_work_root_is_created_private_and_existing_loose_dir_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let created = temp.path().join("created");
        prepare_git_work_root(&created).await.unwrap();
        let created_mode = std::fs::metadata(&created).unwrap().permissions().mode() & 0o777;
        assert_eq!(created_mode, 0o700);

        let loose = temp.path().join("loose");
        std::fs::create_dir(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = prepare_git_work_root(&loose).await.unwrap_err();
        assert!(err.contains("group/world access bits"), "{err}");
    }

    #[tokio::test]
    async fn prepare_vm_http_git_session_returns_in_range_broker_port_and_redacted_token() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let temp = tempfile::tempdir().unwrap();
        let range = BrokerPortRange::new(1024, 65535).unwrap();
        let config = VmHttpGitRuntimeConfig::new(
            Ipv4Addr::LOCALHOST,
            range,
            git_clone_config_for_test(&temp, write_fake_git(temp.path())),
        );
        let session_id = "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap();
        let source_ipv4 = Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap();

        let prepared = prepare_vm_http_git_session(state, &config, session_id, source_ipv4)
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
    async fn running_git_runtime_serves_session_and_shuts_down() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let temp = tempfile::tempdir().unwrap();
        let config = VmHttpGitRuntimeConfig::new(
            Ipv4Addr::LOCALHOST,
            BrokerPortRange::new(1024, 65535).unwrap(),
            git_clone_config_for_test(&temp, write_fake_git(temp.path())),
        );
        let session_id = "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap();
        let source_ipv4 = Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap();
        let prepared = prepare_vm_http_git_session(state, &config, session_id, source_ipv4)
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
    async fn git_clone_route_rejects_malformed_json_without_minting() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let temp = tempfile::tempdir().unwrap();
        let service = git_clone_service_for_test(&state, &temp, write_fake_git(temp.path()));

        let response = handle_git_clone_request(&session, b"{not json", service).await;

        assert_eq!(response.status, VmHttpStatus::BadRequest);
        let body: VmGitCloneErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmGitCloneErrorCode::InvalidRequest);
        assert!(
            state
                .audit
                .list_grants_for_session(session.session_id())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn git_clone_route_maps_inactive_sessions_to_client_errors() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        let temp = tempfile::tempdir().unwrap();
        let clone_repo = GitCloneRepo::new(repo("o", "n")).unwrap();
        let request_body = serde_json::to_vec(&VmGitCloneRequest::new(clone_repo, None)).unwrap();

        let unknown_service =
            git_clone_service_for_test(&state, &temp, write_fake_git(temp.path()));
        let unknown_response =
            handle_git_clone_request(&session, &request_body, unknown_service).await;

        assert_eq!(unknown_response.status, VmHttpStatus::Unauthorized);
        let unknown_body: VmGitCloneErrorResponse =
            serde_json::from_slice(&unknown_response.body).unwrap();
        assert_eq!(unknown_body.error(), VmGitCloneErrorCode::Denied);
        assert_eq!(unknown_body.message(), "session is not active");
        assert!(
            !unknown_body
                .message()
                .contains(&session.session_id().to_string())
        );

        open_audit_session(&state, session.session_id());
        state
            .audit
            .close_session(session.session_id(), UnixMillis::now())
            .unwrap();

        let closed_service = git_clone_service_for_test(&state, &temp, write_fake_git(temp.path()));
        let closed_response =
            handle_git_clone_request(&session, &request_body, closed_service).await;

        assert_eq!(closed_response.status, VmHttpStatus::Gone);
        let closed_body: VmGitCloneErrorResponse =
            serde_json::from_slice(&closed_response.body).unwrap();
        assert_eq!(closed_body.error(), VmGitCloneErrorCode::Denied);
        assert_eq!(closed_body.message(), "session is closed");
        assert!(
            state
                .audit
                .list_grants_for_session(session.session_id())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn git_clone_route_hides_host_mint_errors_from_vm_response() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(
                ResponseTemplate::new(500).set_body_string("backend detail /private/tmp/secret"),
            )
            .expect(1)
            .mount(&github)
            .await;

        let temp = tempfile::tempdir().unwrap();
        let service = git_clone_service_for_test(&state, &temp, write_fake_git(temp.path()));
        let clone_repo = GitCloneRepo::new(repo("o", "n")).unwrap();
        let body = serde_json::to_vec(&VmGitCloneRequest::new(clone_repo, None)).unwrap();

        let response = handle_git_clone_request(&session, &body, service).await;

        assert_eq!(response.status, VmHttpStatus::InternalServerError);
        let body: VmGitCloneErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmGitCloneErrorCode::CloneFailed);
        assert_eq!(body.message(), "credential request failed");
        assert!(!body.message().contains("/private/tmp/secret"));
    }

    #[tokio::test]
    async fn git_clone_route_reports_cleanup_failure_without_returning_bundle() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_vm_token",
                "expires_at": expiry_str_from_now(3600),
                "permissions": {"contents": "read", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"full_name": "o/n"}]
            })))
            .expect(1)
            .mount(&github)
            .await;

        let temp = tempfile::tempdir().unwrap();
        let chmod = shell_single_quote(&required_test_tool("chmod"));
        let fake_git = write_fake_git_with_bundle_epilogue(
            temp.path(),
            &format!(
                r#"work_dir=${{bundle%/*}}
work_root=${{work_dir%/*}}
{chmod} 500 "$work_root""#
            ),
        );
        let service = git_clone_service_for_test(&state, &temp, fake_git);
        let clone_repo = GitCloneRepo::new(repo("o", "n")).unwrap();
        let body = serde_json::to_vec(&VmGitCloneRequest::new(clone_repo, None)).unwrap();

        let response = handle_git_clone_request(&session, &body, service).await;

        let work_root = temp.path().join("git-work");
        std::fs::set_permissions(&work_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(response.status, VmHttpStatus::InternalServerError);
        let body: VmGitCloneErrorResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.error(), VmGitCloneErrorCode::CloneFailed);
        assert!(
            body.message()
                .contains("temporary artifacts were not removed"),
            "{}",
            body.message()
        );
        assert!(!body.message().contains("bundle-from-fake-git"));
        assert_eq!(std::fs::read_dir(work_root).unwrap().count(), 1);
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
        assert!(response.contains("WWW-Authenticate: Bearer"), "{response}");
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

    #[tokio::test]
    async fn vm_http_git_clone_route_mints_host_token_and_returns_bundle() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = VmHttpSession::new(
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
            Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
            token(),
        );
        open_audit_session(&state, session.session_id());
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_vm_token",
                "expires_at": expiry_str_from_now(3600),
                "permissions": {"contents": "read", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"full_name": "o/n"}]
            })))
            .expect(1)
            .mount(&github)
            .await;

        let temp = tempfile::tempdir().unwrap();
        let fake_git = write_fake_git(temp.path());
        let service = git_clone_service_for_test(&state, &temp, fake_git);

        let range = BrokerPortRange::new(1024, 65535).unwrap();
        let bound = bind_ephemeral_vm_http_listener(Ipv4Addr::LOCALHOST, range)
            .await
            .unwrap();
        let addr = bound.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(run_vm_http_with_git_until_shutdown(
            bound.into_listener(),
            session.clone(),
            service,
            shutdown_rx,
        ));

        let clone_repo = GitCloneRepo::new(repo("o", "n")).unwrap();
        let body = serde_json::to_string(&VmGitCloneRequest::new(clone_repo, None)).unwrap();
        let response = request_over_tcp(
            addr,
            &format!(
                "POST {VM_GIT_CLONE_PATH} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                bearer(token().as_str()),
                body.len(),
                body
            ),
        )
        .await;

        shutdown_tx.send(true).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.contains(&format!("Content-Type: {GIT_BUNDLE_CONTENT_TYPE}\r\n")),
            "{response}"
        );
        assert!(response.ends_with("bundle-from-fake-git\n"), "{response}");
        assert_eq!(
            state
                .audit
                .list_grants_for_session(session.session_id())
                .unwrap()
                .len(),
            1
        );

        let git_log = std::fs::read_to_string(temp.path().join("fake-git.log")).unwrap();
        assert!(git_log.contains("https://github.com/o/n.git"), "{git_log}");
        assert!(!git_log.contains("ghs_vm_token"), "{git_log}");
        let work_root_entries = std::fs::read_dir(temp.path().join("git-work"))
            .unwrap()
            .count();
        assert_eq!(work_root_entries, 0);
    }

    #[tokio::test]
    async fn vm_http_read_timeout_does_not_cancel_slow_git_clone_execution() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = VmHttpSession::new(
            "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap(),
            Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
            token(),
        );
        open_audit_session(&state, session.session_id());
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_delay(std::time::Duration::from_millis(100))
                    .set_body_json(serde_json::json!({
                        "token": "ghs_vm_token",
                        "expires_at": expiry_str_from_now(3600),
                        "permissions": {"contents": "read", "metadata": "read"},
                        "repository_selection": "selected",
                        "repositories": [{"full_name": "o/n"}]
                    })),
            )
            .expect(1)
            .mount(&github)
            .await;

        let temp = tempfile::tempdir().unwrap();
        let fake_git = write_fake_git(temp.path());
        let service = git_clone_service_for_test(&state, &temp, fake_git);

        let clone_repo = GitCloneRepo::new(repo("o", "n")).unwrap();
        let body = serde_json::to_string(&VmGitCloneRequest::new(clone_repo, None)).unwrap();
        let request = format!(
            "POST {VM_GIT_CLONE_PATH} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            bearer(token().as_str()),
            body.len(),
            body
        );
        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(handle_vm_http_connection_with_read_timeout(
            server_io,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
            session,
            Some(service),
            std::time::Duration::from_millis(20),
        ));

        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        server.await.unwrap().unwrap();
        let response = String::from_utf8(response).unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.ends_with("bundle-from-fake-git\n"), "{response}");
        let work_root_entries = std::fs::read_dir(temp.path().join("git-work"))
            .unwrap()
            .count();
        assert_eq!(work_root_entries, 0);
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
