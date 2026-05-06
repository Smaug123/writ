//! VM-facing broker HTTP endpoint.
//!
//! This is deliberately separate from the host Unix-socket protocol. The VM
//! endpoint authenticates one managed agent VM session with a bearer secret and
//! a source-subnet check, then exposes only VM-safe broker operations.

use std::collections::HashMap;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::audit::{
    AuditError, NixCacheAuditDecision, NixCacheAuditRoute, NixCacheOutcomeRecord,
    NixCacheRequestRecord,
};
use crate::bearer::is_bearer_token_byte;
use crate::core::{
    BrokerPort, BrokerPortRange, CapabilityRequest, GitHubAccess, GitHubRequest, Ipv4Cidr,
    RequestId, SessionId, UnixMillis,
};
use crate::nix_cache::{
    NixCacheNarFileName, NixNarBodyHashError, NixNarCompression, NixNarHash, NixNarInfo,
    NixNarInfoError, NixNarSize, NixStoreHashPart, NixTrustedPublicKeys,
    parse_signed_narinfo_for_store_hash,
};
use crate::secret::SecretStore;
use crate::server::{BrokerState, CapabilityOutcome, request_capability};
use crate::vm_git::{
    GIT_BUNDLE_CONTENT_TYPE, VM_GIT_CLONE_PATH, VmGitCloneErrorCode, VmGitCloneErrorResponse,
    VmGitCloneRequest,
};
use crate::vm_git_bundle::{
    GitCloneBaseUrl, GitCloneBundlePlan, GitCloneBundlePlanError, GitCloneBundleRunError,
    GitCloneBundleSource, GitCredentialBoundary, GitSecretValue, GitSecretValueError,
    run_git_clone_bundle,
};

const MAX_VM_HTTP_HEAD_BYTES: usize = 16 * 1024;
const MAX_VM_HTTP_BODY_BYTES: usize = 64 * 1024;
const VM_HTTP_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const EPHEMERAL_BIND_ATTEMPTS: usize = 32;
const MAX_VM_HTTP_CONNECTIONS: usize = 256;
pub const VM_NIX_CACHE_PATH_PREFIX: &str = "/v1/nix/cache";
const VM_NIX_CACHE_INFO_PATH: &str = "/v1/nix/cache/nix-cache-info";
pub const VM_NIX_BASIC_LOGIN: &str = "writ-vm";
const XZ_DECODER_MEMLIMIT_OVERHEAD: u64 = 16 * 1024 * 1024;

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

pub struct VmHttpNixCacheService<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    config: VmHttpNixCacheConfig,
    client: reqwest::Client,
    // This service is constructed once per prepared VM HTTP session. Admission
    // state is intentionally kept for that session runtime lifetime. Entries
    // are small, and eviction would risk turning a valid NAR follow-up request
    // into an order-dependent cache miss.
    admitted_nars: Arc<Mutex<HashMap<NixCacheNarFileName, VmHttpNixCacheAdmittedNar>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpGitRuntimeConfig {
    bind_addr: Ipv4Addr,
    broker_port_range: BrokerPortRange,
    git_clone: VmHttpGitCloneConfig,
    nix_cache: VmHttpNixCacheConfig,
}

pub struct PreparedVmHttpGitSession<S: SecretStore + Send + Sync + 'static> {
    listener: BoundVmHttpListener,
    session: VmHttpSession,
    git_clone: VmHttpGitCloneService<S>,
    nix_cache: VmHttpNixCacheService<S>,
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
    clone_base_url: GitCloneBaseUrl,
    credential: GitCredentialBoundary,
    work_root: PathBuf,
    timeout: std::time::Duration,
    max_bundle_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpNixCacheConfig {
    upstream_base_url: reqwest::Url,
    max_metadata_bytes: u64,
    max_nar_bytes: u64,
    trusted_public_keys: NixTrustedPublicKeys,
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

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum VmHttpNixCacheConfigError {
    #[error("Nix cache upstream URL must not be empty")]
    EmptyUpstreamUrl,
    #[error("Nix cache upstream URL {raw:?} is invalid: {message}")]
    InvalidUpstreamUrl { raw: String, message: String },
    #[error("Nix cache upstream URL {raw:?} uses unsupported scheme {scheme:?}")]
    UnsupportedUpstreamScheme { raw: String, scheme: String },
    #[error("Nix cache upstream URL must not contain embedded credentials: {0:?}")]
    UpstreamUrlHasCredentials(String),
    #[error("Nix cache upstream URL must not contain a query or fragment: {0:?}")]
    UpstreamUrlHasQueryOrFragment(String),
    #[error("Nix cache max metadata bytes must be greater than zero")]
    EmptyMaxMetadataBytes,
    #[error("Nix cache max NAR bytes must be greater than zero")]
    EmptyMaxNarBytes,
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
    BadGateway,
    InternalServerError,
}

#[derive(Debug, Eq, PartialEq)]
struct VmHttpResponse {
    status: VmHttpStatus,
    content_type: &'static str,
    body: Vec<u8>,
    content_length: Option<u64>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum VmNixCacheRoute {
    CacheInfo,
    NarInfo { hash: NixStoreHashPart },
    Nar { file: NixCacheNarFileName },
}

#[derive(Debug)]
struct VmHttpNixCacheProxyFetch {
    response: VmHttpResponse,
    upstream_url: String,
    upstream_status: Option<u16>,
    response_bytes: u64,
    error: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VmHttpNixCacheAdmittedNar {
    file: NixCacheNarFileName,
    compression: NixNarCompression,
    nar_hash: NixNarHash,
    nar_size: NixNarSize,
}

enum VmHttpDispatch {
    Buffered(VmHttpResponse),
}

#[derive(Debug, thiserror::Error)]
enum VmHttpNixCacheBodyReadError {
    #[error("Nix cache upstream response body read failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Nix cache upstream response exceeds {max} bytes")]
    ResponseTooLarge { max: u64 },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum VmHttpNixCacheNarLengthError {
    Missing,
    TooLarge { max: u64, actual: u64 },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
enum VmHttpNixCacheNarAdmissionError {
    #[error("signed narinfo NarSize {actual} exceeds configured max {max}")]
    NarSizeTooLarge { max: u64, actual: u64 },
    #[error("signed narinfo NarHash cannot be verified by the broker: {source}")]
    InvalidNarHash { source: NixNarBodyHashError },
    #[error("signed narinfo conflicts with earlier metadata for NAR {file}")]
    ConflictingNarFile { file: NixCacheNarFileName },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
enum VmHttpNixCacheNarVerifyError {
    #[error("NAR verification task failed: {message}")]
    VerifierTask { message: String },
    #[error("compressed NAR body could not be decoded: {message}")]
    Decode { message: String },
    #[error("decoded NAR size {actual} does not match signed NarSize {expected}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("NAR body hash is invalid: {0}")]
    Hash(#[from] NixNarBodyHashError),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum VmHttpNixCacheNarBodyLengthError {
    Mismatch { expected: u64, actual: u64 },
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

impl<S: SecretStore> VmHttpNixCacheService<S> {
    pub fn new(broker_state: Arc<BrokerState<S>>, config: VmHttpNixCacheConfig) -> Self {
        Self {
            broker_state,
            config,
            client: reqwest::Client::new(),
            admitted_nars: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S: SecretStore> Clone for VmHttpNixCacheService<S> {
    fn clone(&self) -> Self {
        Self {
            broker_state: Arc::clone(&self.broker_state),
            config: self.config.clone(),
            client: self.client.clone(),
            admitted_nars: Arc::clone(&self.admitted_nars),
        }
    }
}

impl VmHttpGitRuntimeConfig {
    pub fn new(
        bind_addr: Ipv4Addr,
        broker_port_range: BrokerPortRange,
        git_clone: VmHttpGitCloneConfig,
        nix_cache: VmHttpNixCacheConfig,
    ) -> Self {
        Self {
            bind_addr,
            broker_port_range,
            git_clone,
            nix_cache,
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
}

impl VmHttpGitCloneConfig {
    pub fn new(
        git_program: impl Into<PathBuf>,
        credential: GitCredentialBoundary,
        work_root: impl Into<PathBuf>,
        timeout: std::time::Duration,
        max_bundle_bytes: u64,
    ) -> Result<Self, GitCloneBundlePlanError> {
        Self::new_with_clone_base_url(
            git_program,
            GitCloneBaseUrl::github(),
            credential,
            work_root,
            timeout,
            max_bundle_bytes,
        )
    }

    pub fn new_with_clone_base_url(
        git_program: impl Into<PathBuf>,
        clone_base_url: GitCloneBaseUrl,
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
            clone_base_url,
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
        GitCloneBundlePlan::new_with_source(
            self.git_program.clone(),
            GitCloneBundleSource::new(request, self.clone_base_url.clone()),
            self.credential.clone(),
            work_dir,
            bundle_path,
            self.timeout,
            self.max_bundle_bytes,
        )
    }
}

impl VmHttpNixCacheConfig {
    pub fn new(
        upstream_base_url: impl AsRef<str>,
        max_metadata_bytes: u64,
        max_nar_bytes: u64,
    ) -> Result<Self, VmHttpNixCacheConfigError> {
        Self::new_with_trusted_public_keys(
            upstream_base_url,
            max_metadata_bytes,
            max_nar_bytes,
            NixTrustedPublicKeys::empty(),
        )
    }

    pub fn new_with_trusted_public_keys(
        upstream_base_url: impl AsRef<str>,
        max_metadata_bytes: u64,
        max_nar_bytes: u64,
        trusted_public_keys: NixTrustedPublicKeys,
    ) -> Result<Self, VmHttpNixCacheConfigError> {
        let raw = upstream_base_url.as_ref();
        if raw.is_empty() {
            return Err(VmHttpNixCacheConfigError::EmptyUpstreamUrl);
        }
        if max_metadata_bytes == 0 {
            return Err(VmHttpNixCacheConfigError::EmptyMaxMetadataBytes);
        }
        if max_nar_bytes == 0 {
            return Err(VmHttpNixCacheConfigError::EmptyMaxNarBytes);
        }
        let mut url = reqwest::Url::parse(raw).map_err(|err| {
            VmHttpNixCacheConfigError::InvalidUpstreamUrl {
                raw: raw.to_string(),
                message: err.to_string(),
            }
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(VmHttpNixCacheConfigError::UnsupportedUpstreamScheme {
                raw: raw.to_string(),
                scheme: url.scheme().to_string(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(VmHttpNixCacheConfigError::UpstreamUrlHasCredentials(
                raw.to_string(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(VmHttpNixCacheConfigError::UpstreamUrlHasQueryOrFragment(
                raw.to_string(),
            ));
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        Ok(Self {
            upstream_base_url: url,
            max_metadata_bytes,
            max_nar_bytes,
            trusted_public_keys,
        })
    }

    pub fn upstream_base_url(&self) -> &reqwest::Url {
        &self.upstream_base_url
    }

    pub fn max_metadata_bytes(&self) -> u64 {
        self.max_metadata_bytes
    }

    pub fn max_nar_bytes(&self) -> u64 {
        self.max_nar_bytes
    }

    pub fn trusted_public_keys(&self) -> &NixTrustedPublicKeys {
        &self.trusted_public_keys
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
            self.nix_cache,
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
    let git_clone = VmHttpGitCloneService::new(Arc::clone(&state), config.git_clone.clone());
    let nix_cache = VmHttpNixCacheService::new(state, config.nix_cache.clone());
    Ok(PreparedVmHttpGitSession {
        listener,
        session,
        git_clone,
        nix_cache,
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
        listener, session, None, None, shutdown,
    )
    .await
}

pub async fn run_vm_http_with_git_until_shutdown<S: SecretStore + Send + Sync + 'static>(
    listener: TcpListener,
    session: VmHttpSession,
    git_clone: VmHttpGitCloneService<S>,
    nix_cache: VmHttpNixCacheService<S>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    run_vm_http_runtime_until_shutdown(
        listener,
        session,
        Some(git_clone),
        Some(nix_cache),
        shutdown,
    )
    .await
}

async fn run_vm_http_runtime_until_shutdown<S: SecretStore + Send + Sync + 'static>(
    listener: TcpListener,
    session: VmHttpSession,
    git_clone: Option<VmHttpGitCloneService<S>>,
    nix_cache: Option<VmHttpNixCacheService<S>>,
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
                let nix_cache = nix_cache.clone();
                handlers.spawn(async move {
                    handle_vm_http_connection(stream, peer_addr, session, git_clone, nix_cache).await
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
    nix_cache: Option<VmHttpNixCacheService<S>>,
) -> std::io::Result<()> {
    handle_vm_http_connection_with_read_timeout(
        stream,
        peer_addr,
        session,
        git_clone,
        nix_cache,
        VM_HTTP_READ_TIMEOUT,
    )
    .await
}

async fn handle_vm_http_connection_with_read_timeout<S, T>(
    mut stream: T,
    peer_addr: SocketAddr,
    session: VmHttpSession,
    git_clone: Option<VmHttpGitCloneService<S>>,
    nix_cache: Option<VmHttpNixCacheService<S>>,
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

    let dispatch = dispatch_vm_http_head_and_body(
        &session,
        peer_addr,
        head,
        &mut stream,
        git_clone,
        nix_cache,
        read_timeout,
    )
    .await;
    dispatch.write_to(&mut stream).await
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
            route_nix_cache_request_without_upstream(&request)
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
    nix_cache: Option<VmHttpNixCacheService<S>>,
    read_timeout: std::time::Duration,
) -> VmHttpDispatch
where
    S: SecretStore + Send + Sync,
    R: AsyncRead + Unpin,
{
    let request = match parse_http_head(&head.raw_head, peer_addr) {
        Ok(request) => request,
        Err(err) => {
            return VmHttpResponse::text(VmHttpStatus::BadRequest, err.to_string()).into();
        }
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
                nix_cache,
                read_timeout,
            )
            .await
        }
        VmHttpAuthorization::Deny(err) => {
            let response = auth_error_response(auth_scheme, err);
            if is_nix_cache_target(&request.target) {
                return record_nix_cache_local_response(
                    nix_cache.as_ref(),
                    session,
                    &request,
                    NixCacheAuditDecision::Deny {
                        reason: nix_cache_auth_error_reason(err).to_string(),
                    },
                    response,
                    None,
                )
                .into();
            }
            response.into()
        }
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
    nix_cache: Option<VmHttpNixCacheService<S>>,
    read_timeout: std::time::Duration,
) -> VmHttpDispatch
where
    S: SecretStore + Send + Sync,
    R: AsyncRead + Unpin,
{
    if is_nix_cache_target(&request.target) {
        return route_nix_cache_request(session, request, nix_cache).await;
    }

    if request.target == VM_GIT_CLONE_PATH {
        let Some(service) = git_clone else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        if request.method != "POST" {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
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
            Err(response) => return response.into(),
        };
        return handle_git_clone_request(session, &body, service)
            .await
            .into();
    }

    route_session_endpoint(session, request).into()
}

async fn route_nix_cache_request<S: SecretStore>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    service: Option<VmHttpNixCacheService<S>>,
) -> VmHttpDispatch {
    let Some(service) = service else {
        return route_nix_cache_request_without_upstream(request).into();
    };
    let Some(route) = classify_nix_cache_target(&request.target) else {
        let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
        return record_nix_cache_local_response(
            Some(&service),
            session,
            request,
            NixCacheAuditDecision::Allow,
            response,
            None,
        )
        .into();
    };

    if !matches!(request.method.as_str(), "GET" | "HEAD") {
        let response = VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed");
        return record_nix_cache_local_response(
            Some(&service),
            session,
            request,
            NixCacheAuditDecision::Allow,
            response,
            Some(&route),
        )
        .into();
    }

    let request_id = RequestId::new();
    if let Err(err) = record_nix_cache_request(
        &service,
        request_id,
        session,
        request,
        NixCacheAuditDecision::Allow,
        Some(&route),
    ) {
        eprintln!("VM HTTP Nix cache audit request write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed")
            .into();
    }

    let fetch = service.fetch_route(request.method.as_str(), &route).await;
    if let Err(err) = record_nix_cache_outcome(&service, request_id, &fetch) {
        eprintln!("VM HTTP Nix cache audit outcome write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed")
            .into();
    }
    fetch.response.into()
}

fn record_nix_cache_local_response<S: SecretStore>(
    service: Option<&VmHttpNixCacheService<S>>,
    session: &VmHttpSession,
    request: &VmHttpRequest,
    decision: NixCacheAuditDecision,
    response: VmHttpResponse,
    route: Option<&VmNixCacheRoute>,
) -> VmHttpResponse {
    let Some(service) = service else {
        return response;
    };
    let request_id = RequestId::new();
    if let Err(err) =
        record_nix_cache_request(service, request_id, session, request, decision, route)
    {
        eprintln!("VM HTTP Nix cache audit request write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed");
    }
    let fetch = VmHttpNixCacheProxyFetch {
        upstream_url: String::new(),
        upstream_status: None,
        response_bytes: response.body.len() as u64,
        error: None,
        response,
    };
    if let Err(err) = record_nix_cache_outcome(service, request_id, &fetch) {
        eprintln!("VM HTTP Nix cache audit outcome write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed");
    }
    fetch.response
}

fn record_nix_cache_request<S: SecretStore>(
    service: &VmHttpNixCacheService<S>,
    request_id: RequestId,
    session: &VmHttpSession,
    request: &VmHttpRequest,
    decision: NixCacheAuditDecision,
    route: Option<&VmNixCacheRoute>,
) -> Result<(), AuditError> {
    service
        .broker_state
        .audit
        .record_nix_cache_request(&NixCacheRequestRecord {
            request_id,
            session_id: session.session_id(),
            received_at: UnixMillis::now(),
            method: &request.method,
            target: &request.target,
            route: nix_cache_audit_route(request, route),
            decision: &decision,
        })
}

fn record_nix_cache_outcome<S: SecretStore>(
    service: &VmHttpNixCacheService<S>,
    request_id: RequestId,
    fetch: &VmHttpNixCacheProxyFetch,
) -> Result<(), AuditError> {
    let upstream_url = if fetch.upstream_url.is_empty() {
        None
    } else {
        Some(fetch.upstream_url.as_str())
    };
    service
        .broker_state
        .audit
        .record_nix_cache_outcome(&NixCacheOutcomeRecord {
            request_id,
            completed_at: UnixMillis::now(),
            http_status: fetch.response.status.code(),
            upstream_url,
            upstream_status: fetch.upstream_status,
            response_bytes: fetch.response_bytes,
            error: fetch.error,
        })
}

fn nix_cache_audit_route(
    request: &VmHttpRequest,
    route: Option<&VmNixCacheRoute>,
) -> NixCacheAuditRoute {
    let route = route
        .cloned()
        .or_else(|| classify_nix_cache_target(&request.target));
    match route {
        Some(VmNixCacheRoute::CacheInfo) => NixCacheAuditRoute::CacheInfo,
        Some(VmNixCacheRoute::NarInfo { .. }) => NixCacheAuditRoute::NarInfo,
        Some(VmNixCacheRoute::Nar { .. }) => NixCacheAuditRoute::Nar,
        None => NixCacheAuditRoute::Unsupported,
    }
}

fn nix_cache_auth_error_reason(err: VmHttpAuthError) -> &'static str {
    match err {
        VmHttpAuthError::MissingCredentials => "missing credentials",
        VmHttpAuthError::WrongCredentials => "wrong credentials",
        VmHttpAuthError::SourceOutsideSessionSubnet => "source outside session subnet",
    }
}

fn route_nix_cache_request_without_upstream(request: &VmHttpRequest) -> VmHttpResponse {
    let Some(route) = classify_nix_cache_target(&request.target) else {
        return VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
    };
    match (request.method.as_str(), route) {
        ("GET", VmNixCacheRoute::CacheInfo) => VmHttpResponse::text(
            VmHttpStatus::Ok,
            "StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 40\n",
        ),
        ("HEAD", VmNixCacheRoute::CacheInfo) => VmHttpResponse::text(VmHttpStatus::Ok, ""),
        ("GET" | "HEAD", VmNixCacheRoute::NarInfo { .. } | VmNixCacheRoute::Nar { .. }) => {
            VmHttpResponse::text(VmHttpStatus::NotFound, "not found")
        }
        (
            _,
            VmNixCacheRoute::CacheInfo
            | VmNixCacheRoute::NarInfo { .. }
            | VmNixCacheRoute::Nar { .. },
        ) => VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed"),
    }
}

impl<S: SecretStore> VmHttpNixCacheService<S> {
    async fn fetch_route(&self, method: &str, route: &VmNixCacheRoute) -> VmHttpNixCacheProxyFetch {
        match route {
            VmNixCacheRoute::CacheInfo | VmNixCacheRoute::NarInfo { .. } => {
                self.fetch_metadata(method, route).await
            }
            VmNixCacheRoute::Nar { .. } => self.fetch_nar(method, route).await,
        }
    }

    async fn fetch_metadata(
        &self,
        method: &str,
        route: &VmNixCacheRoute,
    ) -> VmHttpNixCacheProxyFetch {
        let url = self.upstream_url(route);
        let upstream_url = url.to_string();
        let is_head = method == "HEAD";
        let method = match method {
            "GET" => reqwest::Method::GET,
            "HEAD" => reqwest::Method::HEAD,
            _ => unreachable!("caller filters Nix cache proxy methods"),
        };
        let response = match self.client.request(method, url).send().await {
            Ok(response) => response,
            Err(err) => {
                eprintln!("VM HTTP Nix cache upstream request failed: {err}");
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache upstream failed");
                return VmHttpNixCacheProxyFetch {
                    upstream_url,
                    upstream_status: None,
                    response_bytes: response.body.len() as u64,
                    error: Some("upstream request failed"),
                    response,
                };
            }
        };
        let upstream_status = response.status();
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
            return VmHttpNixCacheProxyFetch {
                upstream_url,
                upstream_status: Some(404),
                response_bytes: response.body.len() as u64,
                error: None,
                response,
            };
        }
        if response.status() != reqwest::StatusCode::OK {
            let status = response.status();
            eprintln!("VM HTTP Nix cache upstream returned status {status}");
            let response = VmHttpResponse::text(
                VmHttpStatus::BadGateway,
                "nix cache upstream returned unsupported status",
            );
            return VmHttpNixCacheProxyFetch {
                upstream_url,
                upstream_status: Some(status.as_u16()),
                response_bytes: response.body.len() as u64,
                error: Some("unsupported upstream status"),
                response,
            };
        }
        let content_length = upstream_content_length(&response);
        if content_length.is_some_and(|len| len > self.config.max_metadata_bytes) {
            let response =
                VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache upstream failed");
            return VmHttpNixCacheProxyFetch {
                upstream_url,
                upstream_status: Some(upstream_status.as_u16()),
                response_bytes: response.body.len() as u64,
                error: Some("upstream response too large"),
                response,
            };
        }
        if is_head {
            let response =
                VmHttpResponse::text(VmHttpStatus::Ok, "").with_content_length(content_length);
            return VmHttpNixCacheProxyFetch {
                upstream_url,
                upstream_status: Some(200),
                response_bytes: 0,
                error: None,
                response,
            };
        }
        let body = match read_upstream_body_bounded(response, self.config.max_metadata_bytes).await
        {
            Ok(body) => body,
            Err(err) => {
                eprintln!("VM HTTP Nix cache upstream body read failed: {err}");
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache upstream failed");
                return VmHttpNixCacheProxyFetch {
                    upstream_url,
                    upstream_status: Some(upstream_status.as_u16()),
                    response_bytes: response.body.len() as u64,
                    error: Some(err.audit_error_label()),
                    response,
                };
            }
        };
        if let VmNixCacheRoute::NarInfo { hash } = route {
            let narinfo = match parse_signed_narinfo_for_store_hash(
                &body,
                hash,
                self.config.trusted_public_keys(),
            ) {
                Ok(narinfo) => narinfo,
                Err(err) => {
                    eprintln!("VM HTTP Nix cache upstream narinfo was rejected: {err}");
                    let error = narinfo_audit_error_label(&err);
                    let response =
                        VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache upstream failed");
                    return VmHttpNixCacheProxyFetch {
                        upstream_url,
                        upstream_status: Some(upstream_status.as_u16()),
                        response_bytes: response.body.len() as u64,
                        error: Some(error),
                        response,
                    };
                }
            };
            if let Err(err) = self.admit_narinfo(&narinfo) {
                eprintln!("VM HTTP Nix cache upstream narinfo admission failed: {err}");
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache upstream failed");
                return VmHttpNixCacheProxyFetch {
                    upstream_url,
                    upstream_status: Some(upstream_status.as_u16()),
                    response_bytes: response.body.len() as u64,
                    error: Some(err.audit_error_label()),
                    response,
                };
            }
        }
        let response_bytes = body.len() as u64;
        VmHttpNixCacheProxyFetch {
            upstream_url,
            upstream_status: Some(200),
            response_bytes,
            error: None,
            response: VmHttpResponse {
                status: VmHttpStatus::Ok,
                content_type: "text/plain; charset=utf-8",
                body,
                content_length: None,
                www_authenticate: None,
            },
        }
    }

    async fn fetch_nar(&self, method: &str, route: &VmNixCacheRoute) -> VmHttpNixCacheProxyFetch {
        let VmNixCacheRoute::Nar { file } = route else {
            unreachable!("caller dispatches only NAR routes to fetch_nar");
        };
        let Some(admission) = self.admitted_nar(file) else {
            let response =
                VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache upstream failed");
            return VmHttpNixCacheProxyFetch {
                upstream_url: String::new(),
                upstream_status: None,
                response_bytes: response.body.len() as u64,
                error: Some("unadmitted upstream nar"),
                response,
            };
        };
        let url = self.upstream_url(route);
        let upstream_url = url.to_string();
        let is_head = method == "HEAD";
        let method = match method {
            "GET" => reqwest::Method::GET,
            "HEAD" => reqwest::Method::HEAD,
            _ => unreachable!("caller filters Nix cache proxy methods"),
        };
        let response = match self.client.request(method, url).send().await {
            Ok(response) => response,
            Err(err) => {
                eprintln!("VM HTTP Nix cache NAR upstream request failed: {err}");
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache upstream failed");
                return VmHttpNixCacheProxyFetch {
                    upstream_url,
                    upstream_status: None,
                    response_bytes: response.body.len() as u64,
                    error: Some("upstream request failed"),
                    response,
                };
            }
        };
        let upstream_status = response.status();
        if upstream_status == reqwest::StatusCode::NOT_FOUND {
            let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
            return VmHttpNixCacheProxyFetch {
                upstream_url,
                upstream_status: Some(404),
                response_bytes: response.body.len() as u64,
                error: None,
                response,
            };
        }
        if upstream_status != reqwest::StatusCode::OK {
            eprintln!("VM HTTP Nix cache NAR upstream returned status {upstream_status}");
            let response = VmHttpResponse::text(
                VmHttpStatus::BadGateway,
                "nix cache upstream returned unsupported status",
            );
            return VmHttpNixCacheProxyFetch {
                upstream_url,
                upstream_status: Some(upstream_status.as_u16()),
                response_bytes: response.body.len() as u64,
                error: Some("unsupported upstream status"),
                response,
            };
        }

        let content_length = match validate_nar_content_length(
            upstream_content_length(&response),
            self.config.max_nar_bytes,
        ) {
            Ok(content_length) => content_length,
            Err(error) => {
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache upstream failed");
                return VmHttpNixCacheProxyFetch {
                    upstream_url,
                    upstream_status: Some(upstream_status.as_u16()),
                    response_bytes: response.body.len() as u64,
                    error: Some(error.audit_error_label()),
                    response,
                };
            }
        };

        if is_head {
            let response = VmHttpResponse {
                status: VmHttpStatus::Ok,
                content_type: "application/x-nix-nar",
                body: Vec::new(),
                content_length: Some(content_length),
                www_authenticate: None,
            };
            return VmHttpNixCacheProxyFetch {
                upstream_url,
                upstream_status: Some(200),
                response_bytes: 0,
                error: None,
                response,
            };
        }

        let body = match read_upstream_body_bounded(response, self.config.max_nar_bytes).await {
            Ok(body) => body,
            Err(err) => {
                eprintln!("VM HTTP Nix cache NAR upstream body read failed: {err}");
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache upstream failed");
                return VmHttpNixCacheProxyFetch {
                    upstream_url,
                    upstream_status: Some(upstream_status.as_u16()),
                    response_bytes: response.body.len() as u64,
                    error: Some(err.audit_error_label()),
                    response,
                };
            }
        };
        if let Err(err) = validate_nar_body_length(body.len() as u64, content_length) {
            let response =
                VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache upstream failed");
            return VmHttpNixCacheProxyFetch {
                upstream_url,
                upstream_status: Some(upstream_status.as_u16()),
                response_bytes: body.len() as u64,
                error: Some(err.audit_error_label()),
                response,
            };
        }
        let response_bytes = body.len() as u64;
        let body =
            match verify_nar_body_on_blocking_thread(admission, body, self.config.max_nar_bytes)
                .await
            {
                Ok(body) => body,
                Err(err) => {
                    eprintln!("VM HTTP Nix cache NAR body was rejected: {err}");
                    let response =
                        VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache upstream failed");
                    return VmHttpNixCacheProxyFetch {
                        upstream_url,
                        upstream_status: Some(upstream_status.as_u16()),
                        response_bytes,
                        error: Some(err.audit_error_label()),
                        response,
                    };
                }
            };
        VmHttpNixCacheProxyFetch {
            upstream_url,
            upstream_status: Some(200),
            response_bytes,
            error: None,
            response: VmHttpResponse {
                status: VmHttpStatus::Ok,
                // Nix takes the compression contract from the admitted
                // narinfo URL/Compression metadata. Binary caches commonly use
                // this content type for both raw and compressed NAR payloads.
                content_type: "application/x-nix-nar",
                body,
                content_length: Some(content_length),
                www_authenticate: None,
            },
        }
    }

    fn upstream_url(&self, route: &VmNixCacheRoute) -> reqwest::Url {
        let path = match route {
            VmNixCacheRoute::CacheInfo => "nix-cache-info".to_string(),
            VmNixCacheRoute::NarInfo { hash } => format!("{}.narinfo", hash.as_str()),
            VmNixCacheRoute::Nar { file } => format!("nar/{file}"),
        };
        self.config
            .upstream_base_url
            .join(&path)
            .expect("Nix cache route paths are URL-safe relative paths")
    }

    fn admit_narinfo(&self, narinfo: &NixNarInfo) -> Result<(), VmHttpNixCacheNarAdmissionError> {
        let admission = VmHttpNixCacheAdmittedNar::from_narinfo(narinfo);
        let actual = admission.nar_size.get();
        let max = self.config.max_nar_bytes;
        if actual > max {
            return Err(VmHttpNixCacheNarAdmissionError::NarSizeTooLarge { max, actual });
        }
        admission
            .nar_hash
            .validate_sha256_body_hash_shape()
            .map_err(|source| VmHttpNixCacheNarAdmissionError::InvalidNarHash { source })?;

        let mut admitted_nars = self
            .admitted_nars
            .lock()
            .expect("Nix cache admission lock should not be poisoned");
        if let Some(existing) = admitted_nars.get(&admission.file)
            && existing != &admission
        {
            return Err(VmHttpNixCacheNarAdmissionError::ConflictingNarFile {
                file: admission.file,
            });
        }
        admitted_nars.insert(admission.file.clone(), admission);
        Ok(())
    }

    fn admitted_nar(&self, file: &NixCacheNarFileName) -> Option<VmHttpNixCacheAdmittedNar> {
        self.admitted_nars
            .lock()
            .expect("Nix cache admission lock should not be poisoned")
            .get(file)
            .cloned()
    }
}

fn upstream_content_length(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

async fn read_upstream_body_bounded(
    mut response: reqwest::Response,
    max: u64,
) -> Result<Vec<u8>, VmHttpNixCacheBodyReadError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let chunk_len = u64::try_from(chunk.len()).expect("HTTP chunk length fits in u64");
        let new_len = (body.len() as u64)
            .checked_add(chunk_len)
            .expect("HTTP response byte count overflowed before configured bound check");
        if new_len > max {
            return Err(VmHttpNixCacheBodyReadError::ResponseTooLarge { max });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl VmHttpNixCacheBodyReadError {
    fn audit_error_label(&self) -> &'static str {
        match self {
            Self::Request(_) => "upstream body read failed",
            Self::ResponseTooLarge { .. } => "upstream response too large",
        }
    }
}

fn validate_nar_content_length(
    content_length: Option<u64>,
    max: u64,
) -> Result<u64, VmHttpNixCacheNarLengthError> {
    let Some(content_length) = content_length else {
        return Err(VmHttpNixCacheNarLengthError::Missing);
    };
    if content_length > max {
        return Err(VmHttpNixCacheNarLengthError::TooLarge {
            max,
            actual: content_length,
        });
    }
    Ok(content_length)
}

fn validate_nar_body_length(
    actual: u64,
    expected: u64,
) -> Result<(), VmHttpNixCacheNarBodyLengthError> {
    if actual == expected {
        Ok(())
    } else {
        Err(VmHttpNixCacheNarBodyLengthError::Mismatch { expected, actual })
    }
}

impl VmHttpNixCacheNarLengthError {
    fn audit_error_label(self) -> &'static str {
        match self {
            Self::Missing => "upstream nar content length missing",
            Self::TooLarge { .. } => "upstream nar response too large",
        }
    }
}

impl VmHttpNixCacheNarBodyLengthError {
    fn audit_error_label(self) -> &'static str {
        match self {
            Self::Mismatch { .. } => "upstream nar content length mismatch",
        }
    }
}

impl VmHttpNixCacheNarAdmissionError {
    fn audit_error_label(&self) -> &'static str {
        match self {
            Self::NarSizeTooLarge { .. } => "upstream narinfo NarSize too large",
            Self::ConflictingNarFile { .. } => "conflicting upstream narinfo metadata",
            Self::InvalidNarHash { source } => nar_body_hash_error_label(source),
        }
    }
}

impl VmHttpNixCacheAdmittedNar {
    fn from_narinfo(narinfo: &NixNarInfo) -> Self {
        Self {
            file: narinfo.nar_file().clone(),
            compression: narinfo.compression(),
            nar_hash: narinfo.nar_hash().clone(),
            nar_size: narinfo.nar_size(),
        }
    }
}

async fn verify_nar_body_on_blocking_thread(
    admission: VmHttpNixCacheAdmittedNar,
    body: Vec<u8>,
    max_nar_bytes: u64,
) -> Result<Vec<u8>, VmHttpNixCacheNarVerifyError> {
    tokio::task::spawn_blocking(move || {
        verify_nar_body(&admission, &body, max_nar_bytes)?;
        Ok(body)
    })
    .await
    .map_err(|err| VmHttpNixCacheNarVerifyError::VerifierTask {
        message: err.to_string(),
    })?
}

fn verify_nar_body(
    admission: &VmHttpNixCacheAdmittedNar,
    body: &[u8],
    max_nar_bytes: u64,
) -> Result<(), VmHttpNixCacheNarVerifyError> {
    match admission.compression {
        NixNarCompression::None => verify_raw_nar_body(admission, body),
        NixNarCompression::Xz => {
            // Peak memory is bounded by compressed Content-Length plus signed
            // NarSize plus the explicit decoder-state memlimit below;
            // decompression runs on the blocking pool because xz is
            // synchronous and can be CPU-heavy on hostile input.
            let raw_body = decode_xz_nar_body(body, admission.nar_size.get(), max_nar_bytes)?;
            verify_raw_nar_body(admission, &raw_body)
        }
    }
}

fn verify_raw_nar_body(
    admission: &VmHttpNixCacheAdmittedNar,
    raw_body: &[u8],
) -> Result<(), VmHttpNixCacheNarVerifyError> {
    let actual = raw_body.len() as u64;
    let expected = admission.nar_size.get();
    if actual != expected {
        return Err(VmHttpNixCacheNarVerifyError::SizeMismatch { expected, actual });
    }
    admission.nar_hash.verify_sha256_body(raw_body)?;
    Ok(())
}

fn decode_xz_nar_body(
    body: &[u8],
    expected_size: u64,
    max_nar_bytes: u64,
) -> Result<Vec<u8>, VmHttpNixCacheNarVerifyError> {
    let memlimit = xz_decoder_memlimit(max_nar_bytes)?;
    let stream = xz2::stream::Stream::new_stream_decoder(memlimit, xz2::stream::CONCATENATED)
        .map_err(|err| VmHttpNixCacheNarVerifyError::Decode {
            message: err.to_string(),
        })?;
    let capacity =
        usize::try_from(expected_size).map_err(|_| VmHttpNixCacheNarVerifyError::Decode {
            message: format!("signed NarSize {expected_size} does not fit in usize"),
        })?;
    let mut decoder = xz2::read::XzDecoder::new_stream(std::io::Cursor::new(body), stream);
    let mut decoded = Vec::with_capacity(capacity);
    let mut chunk = [0_u8; 8192];
    loop {
        let read =
            decoder
                .read(&mut chunk)
                .map_err(|err| VmHttpNixCacheNarVerifyError::Decode {
                    message: err.to_string(),
                })?;
        if read == 0 {
            break;
        }
        decoded.extend_from_slice(&chunk[..read]);
        if decoded.len() as u64 > expected_size {
            return Err(VmHttpNixCacheNarVerifyError::SizeMismatch {
                expected: expected_size,
                actual: decoded.len() as u64,
            });
        }
    }
    Ok(decoded)
}

fn xz_decoder_memlimit(max_nar_bytes: u64) -> Result<u64, VmHttpNixCacheNarVerifyError> {
    max_nar_bytes
        .checked_add(XZ_DECODER_MEMLIMIT_OVERHEAD)
        .ok_or_else(|| VmHttpNixCacheNarVerifyError::Decode {
            message: format!(
                "configured max NAR bytes {max_nar_bytes} leaves no room for xz decoder overhead"
            ),
        })
}

impl VmHttpNixCacheNarVerifyError {
    fn audit_error_label(&self) -> &'static str {
        match self {
            Self::Decode { .. } => "upstream nar decompression failed",
            Self::SizeMismatch { .. } => "mismatched upstream nar size",
            Self::Hash(source) => nar_body_hash_error_label(source),
            Self::VerifierTask { .. } => "nar verification task failed",
        }
    }
}

fn nar_body_hash_error_label(error: &NixNarBodyHashError) -> &'static str {
    match error {
        NixNarBodyHashError::UnsupportedAlgorithm { .. } => {
            "unsupported upstream nar hash algorithm"
        }
        NixNarBodyHashError::InvalidDigestLength { .. }
        | NixNarBodyHashError::InvalidDigestByte => "invalid upstream nar hash digest",
        NixNarBodyHashError::Mismatch { .. } => "mismatched upstream nar hash",
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
    if let Some(file) = target.strip_prefix(&format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/")) {
        return NixCacheNarFileName::new(file)
            .ok()
            .map(|file| VmNixCacheRoute::Nar { file });
    }
    let suffix = target.strip_prefix(&format!("{VM_NIX_CACHE_PATH_PREFIX}/"))?;
    let hash = suffix.strip_suffix(".narinfo")?;
    if NixStoreHashPart::validate(hash).is_err() {
        return None;
    }
    let hash = NixStoreHashPart::new(hash).expect("validated Nix store hash should parse");
    Some(VmNixCacheRoute::NarInfo { hash })
}

fn narinfo_audit_error_label(err: &NixNarInfoError) -> &'static str {
    match err {
        NixNarInfoError::InvalidUtf8 => "invalid upstream narinfo utf8",
        NixNarInfoError::MissingStorePath => "missing upstream narinfo StorePath",
        NixNarInfoError::DuplicateStorePath => "duplicate upstream narinfo StorePath",
        NixNarInfoError::EmptyStorePath => "empty upstream narinfo StorePath",
        NixNarInfoError::InvalidStorePath { .. } => "invalid upstream narinfo StorePath",
        NixNarInfoError::MissingUrl => "missing upstream narinfo URL",
        NixNarInfoError::DuplicateUrl => "duplicate upstream narinfo URL",
        NixNarInfoError::EmptyUrl => "empty upstream narinfo URL",
        NixNarInfoError::UnsupportedUrl(_) | NixNarInfoError::InvalidNarFile { .. } => {
            "invalid upstream narinfo URL"
        }
        NixNarInfoError::MissingCompression => "missing upstream narinfo Compression",
        NixNarInfoError::DuplicateCompression => "duplicate upstream narinfo Compression",
        NixNarInfoError::EmptyCompression => "empty upstream narinfo Compression",
        NixNarInfoError::InvalidCompression { .. } => "invalid upstream narinfo Compression",
        NixNarInfoError::MissingNarHash => "missing upstream narinfo NarHash",
        NixNarInfoError::DuplicateNarHash => "duplicate upstream narinfo NarHash",
        NixNarInfoError::EmptyNarHash => "empty upstream narinfo NarHash",
        NixNarInfoError::InvalidNarHash { .. } => "invalid upstream narinfo NarHash",
        NixNarInfoError::MissingNarSize => "missing upstream narinfo NarSize",
        NixNarInfoError::DuplicateNarSize => "duplicate upstream narinfo NarSize",
        NixNarInfoError::EmptyNarSize => "empty upstream narinfo NarSize",
        NixNarInfoError::InvalidNarSize { .. } => "invalid upstream narinfo NarSize",
        NixNarInfoError::MissingReferences => "missing upstream narinfo References",
        NixNarInfoError::DuplicateReferences => "duplicate upstream narinfo References",
        NixNarInfoError::InvalidReferences { .. } => "invalid upstream narinfo References",
        NixNarInfoError::MissingSignature => "missing upstream narinfo Sig",
        NixNarInfoError::InvalidSignature { .. } => "invalid upstream narinfo Sig",
        NixNarInfoError::UntrustedSignatureKey => "untrusted upstream narinfo Sig key",
        NixNarInfoError::SignatureMismatch => "mismatched upstream narinfo Sig",
        NixNarInfoError::StorePathHashMismatch { .. } => {
            "mismatched upstream narinfo StorePath hash"
        }
    }
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
            content_length: None,
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
            content_length: None,
            www_authenticate: None,
        }
    }

    fn text(status: VmHttpStatus, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.into().into_bytes(),
            content_length: None,
            www_authenticate: None,
        }
    }

    fn unauthorized(challenge: &'static str, body: impl Into<String>) -> Self {
        Self {
            status: VmHttpStatus::Unauthorized,
            content_type: "text/plain; charset=utf-8",
            body: body.into().into_bytes(),
            content_length: None,
            www_authenticate: Some(challenge),
        }
    }

    fn with_content_length(mut self, content_length: Option<u64>) -> Self {
        self.content_length = content_length;
        self
    }

    fn to_bytes(&self) -> Vec<u8> {
        let content_length = self.content_length.unwrap_or(self.body.len() as u64);
        let mut out = format!(
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status.status_line(),
            self.content_type,
            content_length
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

impl From<VmHttpResponse> for VmHttpDispatch {
    fn from(response: VmHttpResponse) -> Self {
        Self::Buffered(response)
    }
}

impl VmHttpDispatch {
    async fn write_to<W: AsyncWrite + Unpin>(self, out: &mut W) -> std::io::Result<()> {
        match self {
            Self::Buffered(response) => out.write_all(&response.to_bytes()).await,
        }
    }

    #[cfg(test)]
    fn into_buffered(self) -> VmHttpResponse {
        match self {
            Self::Buffered(response) => response,
        }
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
            Self::BadGateway => "502 Bad Gateway",
            Self::InternalServerError => "500 Internal Server Error",
        }
    }

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
    use std::io::Write as _;
    use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    use base64::Engine as _;
    use proptest::prelude::*;
    use ring::signature::KeyPair as _;
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

    const TEST_GIT_CLONE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    const TEST_NIX_CACHE_PUBLIC_KEY: &str =
        "cache.example:IsGkyTbr2sed7tWowgiPcI0ZHhBAHoGQ7TyYRweyzwE=";
    const TEST_SIGNED_NARINFO: &str = concat!(
        "StorePath: /nix/store/rzv95bakh41zrn5ji23pfc11x5vq2z4d-src\n",
        "URL: nar/05cwbm7srkm5hvm6s7pa8yw2n57vgfrfmsz3p2sy8h9cnki9415f.nar.xz\n",
        "Compression: xz\n",
        "FileHash: sha256:05cwbm7srkm5hvm6s7pa8yw2n57vgfrfmsz3p2sy8h9cnki9415f\n",
        "FileSize: 128\n",
        "NarHash: sha256:0n62ny3wh4ayp887m60r6ja1p7hrdqnlaq2avb1177zc5gmm6nny\n",
        "NarSize: 120\n",
        "References: \n",
        "Sig: cache.example:ioaqsTngbhwHmkI+4GKXEkuV0WvrIQ0+SUVlVvIix5A7h31h6oE5hpQbq/rGvH10QLVtYm82sdIM3e2SBGqMAA==\n",
        "CA: fixed:sha256:1ivkzvg86cqy19yf9bg4aaqf6a9prfbjn18jclk6k2w2c9is5kf1\n",
    );
    const TEST_NAR_FILE: &str = "05cwbm7srkm5hvm6s7pa8yw2n57vgfrfmsz3p2sy8h9cnki9415f.nar.xz";
    const TEST_RAW_NAR_BASE64: &str = concat!(
        "DQAAAAAAAABuaXgtYXJjaGl2ZS0xAAAAAQAAAAAAAAAoAAAAAAAAAAQAAAAAAAAAdHlwZQAAAAAH",
        "AAAAAAAAAHJlZ3VsYXIACAAAAAAAAABjb250ZW50cwUAAAAAAAAAcHJvb2YAAAABAAAAAAAAACkA",
        "AAAAAAAA",
    );
    const TEST_SIGNING_KEY_NAME: &str = "cache.example";

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
            TEST_GIT_CLONE_TIMEOUT,
            1024,
        )
        .unwrap()
    }

    fn nix_cache_config_for_test() -> VmHttpNixCacheConfig {
        VmHttpNixCacheConfig::new("http://127.0.0.1:9", 1024, 1024).unwrap()
    }

    fn nix_cache_service_for_test(
        state: &Arc<BrokerState<Box<dyn SecretStore>>>,
        server: &MockServer,
        max_metadata_bytes: u64,
    ) -> VmHttpNixCacheService<Box<dyn SecretStore>> {
        nix_cache_service_for_test_with_limits(state, server, max_metadata_bytes, 1024)
    }

    fn nix_cache_service_for_test_with_limits(
        state: &Arc<BrokerState<Box<dyn SecretStore>>>,
        server: &MockServer,
        max_metadata_bytes: u64,
        max_nar_bytes: u64,
    ) -> VmHttpNixCacheService<Box<dyn SecretStore>> {
        VmHttpNixCacheService::new(
            Arc::clone(state),
            VmHttpNixCacheConfig::new(server.uri(), max_metadata_bytes, max_nar_bytes).unwrap(),
        )
    }

    fn signed_nix_cache_service_for_test(
        state: &Arc<BrokerState<Box<dyn SecretStore>>>,
        server: &MockServer,
        max_metadata_bytes: u64,
    ) -> VmHttpNixCacheService<Box<dyn SecretStore>> {
        signed_nix_cache_service_for_test_with_limits(state, server, max_metadata_bytes, 1024)
    }

    fn signed_nix_cache_service_for_test_with_limits(
        state: &Arc<BrokerState<Box<dyn SecretStore>>>,
        server: &MockServer,
        max_metadata_bytes: u64,
        max_nar_bytes: u64,
    ) -> VmHttpNixCacheService<Box<dyn SecretStore>> {
        VmHttpNixCacheService::new(
            Arc::clone(state),
            VmHttpNixCacheConfig::new_with_trusted_public_keys(
                server.uri(),
                max_metadata_bytes,
                max_nar_bytes,
                NixTrustedPublicKeys::from_strings([TEST_NIX_CACHE_PUBLIC_KEY]).unwrap(),
            )
            .unwrap(),
        )
    }

    fn signed_nix_cache_service_for_test_with_key(
        state: &Arc<BrokerState<Box<dyn SecretStore>>>,
        server: &MockServer,
        trusted_key: String,
        max_nar_bytes: u64,
    ) -> VmHttpNixCacheService<Box<dyn SecretStore>> {
        VmHttpNixCacheService::new(
            Arc::clone(state),
            VmHttpNixCacheConfig::new_with_trusted_public_keys(
                server.uri(),
                4096,
                max_nar_bytes,
                NixTrustedPublicKeys::from_strings([trusted_key]).unwrap(),
            )
            .unwrap(),
        )
    }

    fn test_ed25519_key_pair() -> ring::signature::Ed25519KeyPair {
        ring::signature::Ed25519KeyPair::from_seed_unchecked(&[7_u8; 32]).unwrap()
    }

    fn trusted_public_key_for_test(
        name: &str,
        key_pair: &ring::signature::Ed25519KeyPair,
    ) -> String {
        format!("{name}:{}", base64_standard(key_pair.public_key().as_ref()))
    }

    fn nar_hash_for_body(body: &[u8]) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, body);
        let digest: [u8; 32] = digest
            .as_ref()
            .try_into()
            .expect("ring SHA-256 digest length should be 32 bytes");
        format!(
            "sha256:{}",
            crate::nix_cache::nix_base32_encode_sha256_digest(&digest)
        )
    }

    fn signed_test_narinfo(
        key_pair: &ring::signature::Ed25519KeyPair,
        store_hash: &str,
        store_name: &str,
        nar_file: &str,
        compression: NixNarCompression,
        nar_hash: &str,
        nar_size: u64,
    ) -> String {
        let store_path = format!("/nix/store/{store_hash}-{store_name}");
        let fingerprint = format!("1;{store_path};{nar_hash};{nar_size};");
        let signature = base64_standard(key_pair.sign(fingerprint.as_bytes()).as_ref());
        format!(
            "StorePath: {store_path}\n\
             URL: nar/{nar_file}\n\
             Compression: {compression}\n\
             NarHash: {nar_hash}\n\
             NarSize: {nar_size}\n\
             References: \n\
             Sig: {TEST_SIGNING_KEY_NAME}:{signature}\n",
        )
    }

    fn test_raw_nar_body() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(TEST_RAW_NAR_BASE64)
            .unwrap()
    }

    fn test_xz_nar_body() -> Vec<u8> {
        xz_nar_body_for(&test_raw_nar_body())
    }

    fn xz_nar_body_for(raw: &[u8]) -> Vec<u8> {
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
        encoder.write_all(raw).unwrap();
        encoder.finish().unwrap()
    }

    fn multi_stream_xz_body_for(raw: &[u8]) -> Vec<u8> {
        let split = raw.len() / 2;
        let mut body = xz_nar_body_for(&raw[..split]);
        body.extend_from_slice(&xz_nar_body_for(&raw[split..]));
        body
    }

    fn admitted_nar_for_body(
        file: &str,
        compression: NixNarCompression,
        raw_body: &[u8],
    ) -> VmHttpNixCacheAdmittedNar {
        VmHttpNixCacheAdmittedNar {
            file: NixCacheNarFileName::new(file).unwrap(),
            compression,
            nar_hash: NixNarHash::new(nar_hash_for_body(raw_body)).unwrap(),
            nar_size: NixNarSize::new(&raw_body.len().to_string()).unwrap(),
        }
    }

    fn test_signed_narinfo() -> NixNarInfo {
        let expected_hash = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
        let keys = NixTrustedPublicKeys::from_strings([TEST_NIX_CACHE_PUBLIC_KEY]).unwrap();
        parse_signed_narinfo_for_store_hash(TEST_SIGNED_NARINFO.as_bytes(), &expected_hash, &keys)
            .unwrap()
    }

    fn admit_test_nar(service: &VmHttpNixCacheService<Box<dyn SecretStore>>) {
        service.admit_narinfo(&test_signed_narinfo()).unwrap();
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

    fn arb_nix_nar_file_char() -> impl Strategy<Value = char> {
        prop::sample::select(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._+"
                .iter()
                .copied()
                .map(char::from)
                .collect::<Vec<_>>(),
        )
    }

    fn arb_nix_nar_file_edge_char() -> impl Strategy<Value = char> {
        prop::sample::select(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+"
                .iter()
                .copied()
                .map(char::from)
                .collect::<Vec<_>>(),
        )
    }

    fn arb_invalid_nix_nar_file_char() -> impl Strategy<Value = char> {
        let invalid_ascii = (0u8..=127)
            .filter(|byte| {
                !((*byte).is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'+'))
            })
            .map(char::from)
            .collect::<Vec<_>>();
        prop_oneof![
            prop::sample::select(invalid_ascii),
            prop::sample::select(vec!['é', 'λ', '\u{80}', '\u{2028}']),
        ]
    }

    fn arb_nix_nar_file() -> impl Strategy<Value = String> {
        prop_oneof![
            arb_nix_nar_file_edge_char().prop_map(|c| c.to_string()),
            (
                arb_nix_nar_file_edge_char(),
                prop::collection::vec(arb_nix_nar_file_char(), 0..=62),
                arb_nix_nar_file_edge_char(),
            )
                .prop_map(|(first, middle, last)| {
                    let mut out = String::with_capacity(middle.len() + 2);
                    out.push(first);
                    out.extend(middle);
                    out.push(last);
                    out
                }),
        ]
    }

    fn arb_nix_nar_file_with_invalid_char() -> impl Strategy<Value = String> {
        (
            arb_nix_nar_file_edge_char(),
            prop::collection::vec(arb_nix_nar_file_char(), 0..=16),
            arb_invalid_nix_nar_file_char(),
            prop::collection::vec(arb_nix_nar_file_char(), 0..=16),
            arb_nix_nar_file_edge_char(),
        )
            .prop_map(|(first, before, invalid, after, last)| {
                let mut out = String::with_capacity(before.len() + after.len() + 3);
                out.push(first);
                out.extend(before);
                out.push(invalid);
                out.extend(after);
                out.push(last);
                out
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
            let parsed_hash = NixStoreHashPart::new(hash).unwrap();
            prop_assert_eq!(
                classify_nix_cache_target(&target),
                Some(VmNixCacheRoute::NarInfo { hash: parsed_hash })
            );
        }

        #[test]
        fn wrong_length_nix_store_hash_parts_are_not_narinfo_routes(hash in arb_wrong_length_nix_hash_part()) {
            let target = format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo");
            prop_assert_eq!(classify_nix_cache_target(&target), None);
        }

        #[test]
        fn valid_nix_cache_nar_filenames_are_nar_routes(file in arb_nix_nar_file()) {
            let target = format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{file}");
            let parsed_file = NixCacheNarFileName::new(file).unwrap();
            prop_assert_eq!(
                classify_nix_cache_target(&target),
                Some(VmNixCacheRoute::Nar { file: parsed_file })
            );
        }

        #[test]
        fn invalid_nix_cache_nar_filename_characters_are_not_nar_routes(file in arb_nix_nar_file_with_invalid_char()) {
            let target = format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{file}");
            prop_assert_eq!(classify_nix_cache_target(&target), None);
        }

        #[test]
        fn generated_nar_bodies_verify_against_their_admitted_metadata(
            raw_body in prop::collection::vec(any::<u8>(), 0..512),
            use_xz in any::<bool>(),
        ) {
            let compression = if use_xz {
                NixNarCompression::Xz
            } else {
                NixNarCompression::None
            };
            let wire_body = if use_xz {
                xz_nar_body_for(&raw_body)
            } else {
                raw_body.clone()
            };
            let admission = admitted_nar_for_body("generated.nar", compression, &raw_body);
            verify_nar_body(&admission, &wire_body, 512).unwrap();
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
    fn nix_cache_config_normalizes_base_urls_and_rejects_unsafe_shapes() {
        let config =
            VmHttpNixCacheConfig::new("https://cache.example.test/base", 1024, 2048).unwrap();
        assert_eq!(
            config.upstream_base_url().as_str(),
            "https://cache.example.test/base/"
        );

        assert_eq!(
            VmHttpNixCacheConfig::new("", 1024, 2048),
            Err(VmHttpNixCacheConfigError::EmptyUpstreamUrl)
        );
        assert_eq!(
            VmHttpNixCacheConfig::new("https://cache.example.test", 0, 2048),
            Err(VmHttpNixCacheConfigError::EmptyMaxMetadataBytes)
        );
        assert_eq!(
            VmHttpNixCacheConfig::new("https://cache.example.test", 1024, 0),
            Err(VmHttpNixCacheConfigError::EmptyMaxNarBytes)
        );
        assert!(matches!(
            VmHttpNixCacheConfig::new("file:///nix/store", 1024, 2048),
            Err(VmHttpNixCacheConfigError::UnsupportedUpstreamScheme { .. })
        ));
        assert!(matches!(
            VmHttpNixCacheConfig::new("https://user:pass@cache.example.test", 1024, 2048),
            Err(VmHttpNixCacheConfigError::UpstreamUrlHasCredentials(_))
        ));
        assert!(matches!(
            VmHttpNixCacheConfig::new("https://cache.example.test?x=1", 1024, 2048),
            Err(VmHttpNixCacheConfigError::UpstreamUrlHasQueryOrFragment(_))
        ));
    }

    #[test]
    fn nix_cache_nar_length_must_be_declared_and_bounded() {
        assert_eq!(validate_nar_content_length(Some(42), 42), Ok(42));
        assert_eq!(
            validate_nar_content_length(None, 42),
            Err(VmHttpNixCacheNarLengthError::Missing)
        );
        assert_eq!(
            validate_nar_content_length(Some(43), 42),
            Err(VmHttpNixCacheNarLengthError::TooLarge {
                max: 42,
                actual: 43
            })
        );
    }

    #[test]
    fn xz_nar_body_rejects_decoded_size_smaller_than_signed_size() {
        let raw_body = test_raw_nar_body();
        let short_body = &raw_body[..raw_body.len() - 1];
        let admission = admitted_nar_for_body(TEST_NAR_FILE, NixNarCompression::Xz, &raw_body);

        let result = verify_nar_body(&admission, &xz_nar_body_for(short_body), 1024);

        assert_eq!(
            result,
            Err(VmHttpNixCacheNarVerifyError::SizeMismatch {
                expected: raw_body.len() as u64,
                actual: short_body.len() as u64,
            })
        );
    }

    #[test]
    fn xz_nar_body_accepts_concatenated_streams() {
        let raw_body = test_raw_nar_body();
        let admission = admitted_nar_for_body(TEST_NAR_FILE, NixNarCompression::Xz, &raw_body);

        verify_nar_body(&admission, &multi_stream_xz_body_for(&raw_body), 1024).unwrap();
    }

    async fn route_nix_cache_with_service(
        session: &VmHttpSession,
        method: &str,
        target: String,
        service: VmHttpNixCacheService<Box<dyn SecretStore>>,
    ) -> VmHttpResponse {
        let request = nix_cache_request(
            method,
            target,
            Ipv4Addr::LOCALHOST,
            Some(basic(token().as_str())),
        );
        let mut stream = tokio::io::empty();
        route_authenticated_vm_http_request(
            session,
            &request,
            Vec::new(),
            &mut stream,
            None::<VmHttpGitCloneService<Box<dyn SecretStore>>>,
            Some(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await
        .into_buffered()
    }

    #[tokio::test]
    async fn nix_cache_info_route_proxies_bounded_upstream_metadata() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let upstream_body = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n";
        Mock::given(method("GET"))
            .and(path("/cache/nix-cache-info"))
            .respond_with(ResponseTemplate::new(200).set_body_string(upstream_body))
            .expect(1)
            .mount(&upstream)
            .await;
        let service = VmHttpNixCacheService::new(
            Arc::clone(&state),
            VmHttpNixCacheConfig::new(format!("{}/cache", upstream.uri()), 1024, 1024).unwrap(),
        );

        let response =
            route_nix_cache_with_service(&session, "GET", VM_NIX_CACHE_INFO_PATH.into(), service)
                .await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        assert_eq!(String::from_utf8(response.body).unwrap(), upstream_body);
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::CacheInfo);
        assert_eq!(entries[0].decision, NixCacheAuditDecision::Allow);
        assert_eq!(entries[0].http_status, Some(200));
        assert_eq!(entries[0].upstream_status, Some(200));
        assert_eq!(entries[0].response_bytes, Some(upstream_body.len() as u64));
        assert!(
            entries[0]
                .upstream_url
                .as_deref()
                .unwrap()
                .ends_with("/cache/nix-cache-info")
        );
    }

    #[tokio::test]
    async fn nix_cache_narinfo_route_proxies_valid_narinfo_paths() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let hash = "rzv95bakh41zrn5ji23pfc11x5vq2z4d";
        Mock::given(method("GET"))
            .and(path(format!("/{hash}.narinfo")))
            .respond_with(ResponseTemplate::new(200).set_body_string(TEST_SIGNED_NARINFO))
            .expect(1)
            .mount(&upstream)
            .await;
        let service = signed_nix_cache_service_for_test(&state, &upstream, 1024);
        let service_for_admission_check = service.clone();

        let response = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
            service,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        assert_eq!(response.body, TEST_SIGNED_NARINFO.as_bytes());
        assert!(
            service_for_admission_check
                .admitted_nar(&NixCacheNarFileName::new(TEST_NAR_FILE).unwrap())
                .is_some()
        );
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::NarInfo);
        assert_eq!(entries[0].decision, NixCacheAuditDecision::Allow);
        assert_eq!(entries[0].http_status, Some(200));
        assert_eq!(entries[0].upstream_status, Some(200));
    }

    #[tokio::test]
    async fn nix_cache_narinfo_route_rejects_admitted_nar_size_above_limit() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let hash = "rzv95bakh41zrn5ji23pfc11x5vq2z4d";
        Mock::given(method("GET"))
            .and(path(format!("/{hash}.narinfo")))
            .respond_with(ResponseTemplate::new(200).set_body_string(TEST_SIGNED_NARINFO))
            .expect(1)
            .mount(&upstream)
            .await;
        let service = signed_nix_cache_service_for_test_with_limits(&state, &upstream, 1024, 119);

        let response = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
            service,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::BadGateway);
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::NarInfo);
        assert_eq!(entries[0].http_status, Some(502));
        assert_eq!(entries[0].upstream_status, Some(200));
        assert_eq!(
            entries[0].error.as_deref(),
            Some("upstream narinfo NarSize too large")
        );
    }

    #[tokio::test]
    async fn nix_cache_narinfo_route_rejects_conflicting_admission_for_same_nar_file() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let key_pair = test_ed25519_key_pair();
        let trusted_key = trusted_public_key_for_test(TEST_SIGNING_KEY_NAME, &key_pair);
        let hash_a = "00000000000000000000000000000000";
        let hash_b = "11111111111111111111111111111111";
        let body_a = signed_test_narinfo(
            &key_pair,
            hash_a,
            "proof-a",
            "shared.nar",
            NixNarCompression::None,
            &nar_hash_for_body(b"first"),
            5,
        );
        let body_b = signed_test_narinfo(
            &key_pair,
            hash_b,
            "proof-b",
            "shared.nar",
            NixNarCompression::None,
            &nar_hash_for_body(b"second"),
            6,
        );
        Mock::given(method("GET"))
            .and(path(format!("/{hash_a}.narinfo")))
            .respond_with(ResponseTemplate::new(200).set_body_string(body_a))
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/{hash_b}.narinfo")))
            .respond_with(ResponseTemplate::new(200).set_body_string(body_b))
            .expect(1)
            .mount(&upstream)
            .await;
        let service =
            signed_nix_cache_service_for_test_with_key(&state, &upstream, trusted_key, 64);

        let first = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash_a}.narinfo"),
            service.clone(),
        )
        .await;
        let second = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash_b}.narinfo"),
            service,
        )
        .await;

        assert_eq!(first.status, VmHttpStatus::Ok);
        assert_eq!(second.status, VmHttpStatus::BadGateway);
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].decision, NixCacheAuditDecision::Allow);
        assert_eq!(entries[1].route, NixCacheAuditRoute::NarInfo);
        assert_eq!(entries[1].http_status, Some(502));
        assert_eq!(entries[1].upstream_status, Some(200));
        assert_eq!(
            entries[1].error.as_deref(),
            Some("conflicting upstream narinfo metadata")
        );
    }

    #[tokio::test]
    async fn nix_cache_narinfo_route_rejects_unverifiable_nar_hash_shapes_at_admission() {
        let cases = [
            (
                "00000000000000000000000000000000",
                "sha512:0000000000000000000000000000000000000000000000000000",
                "unsupported upstream nar hash algorithm",
            ),
            (
                "11111111111111111111111111111111",
                "sha256:0",
                "invalid upstream nar hash digest",
            ),
            (
                "22222222222222222222222222222222",
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "invalid upstream nar hash digest",
            ),
        ];
        for (hash, nar_hash, expected_error) in cases {
            let upstream = MockServer::start().await;
            let state = make_broker_state(&upstream);
            let session =
                session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
            open_audit_session(&state, session.session_id());
            let key_pair = test_ed25519_key_pair();
            let trusted_key = trusted_public_key_for_test(TEST_SIGNING_KEY_NAME, &key_pair);
            let body = signed_test_narinfo(
                &key_pair,
                hash,
                "proof",
                "proof.nar",
                NixNarCompression::None,
                nar_hash,
                5,
            );
            Mock::given(method("GET"))
                .and(path(format!("/{hash}.narinfo")))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .expect(1)
                .mount(&upstream)
                .await;
            let service =
                signed_nix_cache_service_for_test_with_key(&state, &upstream, trusted_key, 64);

            let response = route_nix_cache_with_service(
                &session,
                "GET",
                format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
                service,
            )
            .await;

            assert_eq!(response.status, VmHttpStatus::BadGateway, "{nar_hash}");
            let entries = state
                .audit
                .list_nix_cache_requests_for_session(session.session_id())
                .unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].route, NixCacheAuditRoute::NarInfo);
            assert_eq!(entries[0].http_status, Some(502));
            assert_eq!(entries[0].upstream_status, Some(200));
            assert_eq!(entries[0].error.as_deref(), Some(expected_error));
        }
    }

    #[tokio::test]
    async fn nix_cache_narinfo_route_rejects_unsafe_nar_urls() {
        for nar_url in [
            "https://cache.example/nar/proof.nar.xz",
            "../proof.nar.xz",
            "nar/subdir/proof.nar.xz",
            "/nar/proof.nar.xz",
            "nar/proof.nar.xz?download=1",
        ] {
            let upstream = MockServer::start().await;
            let state = make_broker_state(&upstream);
            let session =
                session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
            open_audit_session(&state, session.session_id());
            let hash = "00000000000000000000000000000000";
            Mock::given(method("GET"))
                .and(path(format!("/{hash}.narinfo")))
                .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                    "StorePath: /nix/store/00000000000000000000000000000000-proof\nURL: {nar_url}\nCompression: xz\nNarHash: sha256:0\nNarSize: 120\nReferences: \nSig: cache.example:ioaqsTngbhwHmkI+4GKXEkuV0WvrIQ0+SUVlVvIix5A7h31h6oE5hpQbq/rGvH10QLVtYm82sdIM3e2SBGqMAA==\n"
                )))
                .expect(1)
                .mount(&upstream)
                .await;
            let service = nix_cache_service_for_test(&state, &upstream, 1024);

            let response = route_nix_cache_with_service(
                &session,
                "GET",
                format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
                service,
            )
            .await;

            assert_eq!(response.status, VmHttpStatus::BadGateway, "{nar_url}");
            let entries = state
                .audit
                .list_nix_cache_requests_for_session(session.session_id())
                .unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].route, NixCacheAuditRoute::NarInfo);
            assert_eq!(entries[0].http_status, Some(502));
            assert_eq!(entries[0].upstream_status, Some(200));
            assert_eq!(
                entries[0].error.as_deref(),
                Some("invalid upstream narinfo URL")
            );
        }
    }

    #[tokio::test]
    async fn nix_cache_narinfo_route_rejects_duplicate_nar_urls() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let hash = "00000000000000000000000000000000";
        Mock::given(method("GET"))
            .and(path(format!("/{hash}.narinfo")))
            .respond_with(ResponseTemplate::new(200).set_body_string(concat!(
                "StorePath: /nix/store/00000000000000000000000000000000-proof\n",
                "URL: nar/proof.nar.xz\n",
                "URL: nar/other.nar.xz\n",
                "Compression: xz\n",
                "NarHash: sha256:0\n",
                "NarSize: 120\n",
                "References: \n",
                "Sig: cache.example:ioaqsTngbhwHmkI+4GKXEkuV0WvrIQ0+SUVlVvIix5A7h31h6oE5hpQbq/rGvH10QLVtYm82sdIM3e2SBGqMAA==\n",
            )))
            .expect(1)
            .mount(&upstream)
            .await;
        let service = nix_cache_service_for_test(&state, &upstream, 1024);

        let response = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
            service,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::BadGateway);
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].http_status, Some(502));
        assert_eq!(entries[0].upstream_status, Some(200));
        assert_eq!(
            entries[0].error.as_deref(),
            Some("duplicate upstream narinfo URL")
        );
    }

    #[tokio::test]
    async fn nix_cache_narinfo_route_rejects_store_path_hash_mismatch() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let requested_hash = "00000000000000000000000000000000";
        let upstream_hash = "11111111111111111111111111111111";
        Mock::given(method("GET"))
            .and(path(format!("/{requested_hash}.narinfo")))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                "StorePath: /nix/store/{upstream_hash}-proof\nURL: nar/proof.nar.xz\nCompression: xz\nNarHash: sha256:0\nNarSize: 120\nReferences: \nSig: cache.example:ioaqsTngbhwHmkI+4GKXEkuV0WvrIQ0+SUVlVvIix5A7h31h6oE5hpQbq/rGvH10QLVtYm82sdIM3e2SBGqMAA==\n"
            )))
            .expect(1)
            .mount(&upstream)
            .await;
        let service = nix_cache_service_for_test(&state, &upstream, 1024);

        let response = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/{requested_hash}.narinfo"),
            service,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::BadGateway);
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::NarInfo);
        assert_eq!(entries[0].http_status, Some(502));
        assert_eq!(entries[0].upstream_status, Some(200));
        assert_eq!(
            entries[0].error.as_deref(),
            Some("mismatched upstream narinfo StorePath hash")
        );
    }

    #[tokio::test]
    async fn nix_cache_narinfo_route_requires_trusted_signature() {
        let cases = [
            (
                TEST_SIGNED_NARINFO.replace(
                    "Sig: cache.example:ioaqsTngbhwHmkI+4GKXEkuV0WvrIQ0+SUVlVvIix5A7h31h6oE5hpQbq/rGvH10QLVtYm82sdIM3e2SBGqMAA==\n",
                    "",
                ),
                "missing upstream narinfo Sig",
            ),
            (
                TEST_SIGNED_NARINFO.replace("Sig: cache.example:", "Sig: cache.other:"),
                "untrusted upstream narinfo Sig key",
            ),
            (
                TEST_SIGNED_NARINFO.replace(
                    "ioaqsTngbhwHmkI+4GKXEkuV0WvrIQ0+SUVlVvIix5A7h31h6oE5hpQbq/rGvH10QLVtYm82sdIM3e2SBGqMAA==",
                    "AoaqsTngbhwHmkI+4GKXEkuV0WvrIQ0+SUVlVvIix5A7h31h6oE5hpQbq/rGvH10QLVtYm82sdIM3e2SBGqMAA==",
                ),
                "mismatched upstream narinfo Sig",
            ),
        ];

        for (body, expected_error) in cases {
            let upstream = MockServer::start().await;
            let state = make_broker_state(&upstream);
            let session =
                session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
            open_audit_session(&state, session.session_id());
            let hash = "rzv95bakh41zrn5ji23pfc11x5vq2z4d";
            Mock::given(method("GET"))
                .and(path(format!("/{hash}.narinfo")))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .expect(1)
                .mount(&upstream)
                .await;
            let service = signed_nix_cache_service_for_test(&state, &upstream, 2048);

            let response = route_nix_cache_with_service(
                &session,
                "GET",
                format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
                service,
            )
            .await;

            assert_eq!(response.status, VmHttpStatus::BadGateway);
            let entries = state
                .audit
                .list_nix_cache_requests_for_session(session.session_id())
                .unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].route, NixCacheAuditRoute::NarInfo);
            assert_eq!(entries[0].http_status, Some(502));
            assert_eq!(entries[0].upstream_status, Some(200));
            assert_eq!(entries[0].error.as_deref(), Some(expected_error));
        }
    }

    #[tokio::test]
    async fn nix_cache_nar_route_requires_prior_signed_narinfo_admission() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let service = signed_nix_cache_service_for_test(&state, &upstream, 1024);

        let response = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{TEST_NAR_FILE}"),
            service,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::BadGateway);
        upstream.verify().await;
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::Nar);
        assert_eq!(entries[0].http_status, Some(502));
        assert_eq!(entries[0].upstream_status, None);
        assert_eq!(entries[0].error.as_deref(), Some("unadmitted upstream nar"));
    }

    #[tokio::test]
    async fn nix_cache_nar_route_buffers_verifies_and_audits_nar_body() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let nar_body = test_xz_nar_body();
        Mock::given(method("GET"))
            .and(path(format!("/nar/{TEST_NAR_FILE}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/x-nix-nar")
                    .set_body_bytes(nar_body.clone()),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        let service = signed_nix_cache_service_for_test_with_limits(&state, &upstream, 1024, 1024);
        admit_test_nar(&service);

        let response = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{TEST_NAR_FILE}"),
            service,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        assert_eq!(response.content_type, "application/x-nix-nar");
        assert_eq!(response.content_length, Some(nar_body.len() as u64));
        assert_eq!(response.body, nar_body);
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::Nar);
        assert_eq!(entries[0].decision, NixCacheAuditDecision::Allow);
        assert_eq!(entries[0].http_status, Some(200));
        assert_eq!(entries[0].upstream_status, Some(200));
        assert_eq!(entries[0].response_bytes, Some(response.body.len() as u64));
        assert_eq!(entries[0].error, None);
        assert!(
            entries[0]
                .upstream_url
                .as_deref()
                .unwrap()
                .ends_with(&format!("/nar/{TEST_NAR_FILE}"))
        );
    }

    #[tokio::test]
    async fn nix_cache_nar_route_verifies_uncompressed_nar_body() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let key_pair = test_ed25519_key_pair();
        let trusted_key = trusted_public_key_for_test(TEST_SIGNING_KEY_NAME, &key_pair);
        let hash = "00000000000000000000000000000000";
        let nar_file = "plain.nar";
        let nar_body = b"plain-nar-body".to_vec();
        let narinfo = signed_test_narinfo(
            &key_pair,
            hash,
            "plain",
            nar_file,
            NixNarCompression::None,
            &nar_hash_for_body(&nar_body),
            nar_body.len() as u64,
        );
        Mock::given(method("GET"))
            .and(path(format!("/{hash}.narinfo")))
            .respond_with(ResponseTemplate::new(200).set_body_string(narinfo))
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/nar/{nar_file}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/x-nix-nar")
                    .set_body_bytes(nar_body.clone()),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        let service =
            signed_nix_cache_service_for_test_with_key(&state, &upstream, trusted_key, 64);

        let narinfo_response = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
            service.clone(),
        )
        .await;
        let nar_response = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{nar_file}"),
            service,
        )
        .await;

        assert_eq!(narinfo_response.status, VmHttpStatus::Ok);
        assert_eq!(nar_response.status, VmHttpStatus::Ok);
        assert_eq!(nar_response.content_type, "application/x-nix-nar");
        assert_eq!(nar_response.content_length, Some(nar_body.len() as u64));
        assert_eq!(nar_response.body, nar_body);
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].decision, NixCacheAuditDecision::Allow);
        assert_eq!(entries[1].route, NixCacheAuditRoute::Nar);
        assert_eq!(entries[1].decision, NixCacheAuditDecision::Allow);
        assert_eq!(entries[1].error, None);
    }

    #[tokio::test]
    async fn nix_cache_nar_route_rejects_hash_mismatch_before_forwarding_body() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let mut raw = test_raw_nar_body();
        let tampered_index = raw.len() - 2;
        raw[tampered_index] ^= 0x01;
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&raw).unwrap();
        let tampered = encoder.finish().unwrap();
        Mock::given(method("GET"))
            .and(path(format!("/nar/{TEST_NAR_FILE}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tampered))
            .expect(1)
            .mount(&upstream)
            .await;
        let service = signed_nix_cache_service_for_test_with_limits(&state, &upstream, 1024, 1024);
        admit_test_nar(&service);

        let response = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{TEST_NAR_FILE}"),
            service,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::BadGateway);
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::Nar);
        assert_eq!(entries[0].http_status, Some(502));
        assert_eq!(entries[0].upstream_status, Some(200));
        assert_eq!(
            entries[0].error.as_deref(),
            Some("mismatched upstream nar hash")
        );
    }

    #[tokio::test]
    async fn nix_cache_nar_route_rejects_decoded_size_mismatch() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let mut raw = test_raw_nar_body();
        raw.push(0);
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&raw).unwrap();
        let oversized = encoder.finish().unwrap();
        Mock::given(method("GET"))
            .and(path(format!("/nar/{TEST_NAR_FILE}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized))
            .expect(1)
            .mount(&upstream)
            .await;
        let service = signed_nix_cache_service_for_test_with_limits(&state, &upstream, 1024, 1024);
        admit_test_nar(&service);

        let response = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{TEST_NAR_FILE}"),
            service,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::BadGateway);
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].error.as_deref(),
            Some("mismatched upstream nar size")
        );
    }

    #[tokio::test]
    async fn nix_cache_nar_head_is_bounded_and_requires_admission() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        Mock::given(method("HEAD"))
            .and(path(format!("/nar/{TEST_NAR_FILE}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Length", "123")
                    .insert_header("Content-Type", "application/x-nix-nar"),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        let service = signed_nix_cache_service_for_test_with_limits(&state, &upstream, 1024, 1024);
        admit_test_nar(&service);

        let response = route_nix_cache_with_service(
            &session,
            "HEAD",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{TEST_NAR_FILE}"),
            service,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        assert_eq!(response.content_type, "application/x-nix-nar");
        assert!(response.body.is_empty());
        let wire = String::from_utf8(response.to_bytes()).unwrap();
        assert!(wire.contains("Content-Length: 123\r\n"), "{wire}");
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::Nar);
        assert_eq!(entries[0].response_bytes, Some(0));
        assert_eq!(entries[0].error, None);
    }

    #[tokio::test]
    async fn nix_cache_nar_route_rejects_oversized_declared_nar() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        Mock::given(method("GET"))
            .and(path(format!("/nar/{TEST_NAR_FILE}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 129]))
            .expect(1)
            .mount(&upstream)
            .await;
        let service = signed_nix_cache_service_for_test_with_limits(&state, &upstream, 1024, 128);
        admit_test_nar(&service);

        let response = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{TEST_NAR_FILE}"),
            service,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::BadGateway);
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::Nar);
        assert_eq!(entries[0].http_status, Some(502));
        assert_eq!(entries[0].upstream_status, Some(200));
        assert_eq!(
            entries[0].error.as_deref(),
            Some("upstream nar response too large")
        );
    }

    #[tokio::test]
    async fn nix_cache_route_maps_upstream_404_to_controlled_miss() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let hash = "00000000000000000000000000000000";
        Mock::given(method("GET"))
            .and(path(format!("/{hash}.narinfo")))
            .respond_with(ResponseTemplate::new(404).set_body_string("upstream details"))
            .expect(1)
            .mount(&upstream)
            .await;
        let service = nix_cache_service_for_test(&state, &upstream, 1024);

        let response = route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
            service,
        )
        .await;

        assert_eq!(response.status, VmHttpStatus::NotFound);
        assert_eq!(String::from_utf8(response.body).unwrap(), "not found");
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].http_status, Some(404));
        assert_eq!(entries[0].upstream_status, Some(404));
        assert_eq!(entries[0].error, None);
    }

    #[tokio::test]
    async fn nix_cache_route_rejects_oversized_upstream_metadata() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        Mock::given(method("GET"))
            .and(path("/nix-cache-info"))
            .respond_with(ResponseTemplate::new(200).set_body_string("123456"))
            .expect(1)
            .mount(&upstream)
            .await;
        let service = nix_cache_service_for_test(&state, &upstream, 5);

        let response =
            route_nix_cache_with_service(&session, "GET", VM_NIX_CACHE_INFO_PATH.into(), service)
                .await;

        assert_eq!(response.status, VmHttpStatus::BadGateway);
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].http_status, Some(502));
        assert_eq!(entries[0].upstream_status, Some(200));
        assert_eq!(
            entries[0].error.as_deref(),
            Some("upstream response too large")
        );
    }

    #[tokio::test]
    async fn nix_cache_route_audits_unsupported_upstream_status() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        Mock::given(method("GET"))
            .and(path("/nix-cache-info"))
            .respond_with(ResponseTemplate::new(500).set_body_string("backend detail"))
            .expect(1)
            .mount(&upstream)
            .await;
        let service = nix_cache_service_for_test(&state, &upstream, 1024);

        let response =
            route_nix_cache_with_service(&session, "GET", VM_NIX_CACHE_INFO_PATH.into(), service)
                .await;

        assert_eq!(response.status, VmHttpStatus::BadGateway);
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].http_status, Some(502));
        assert_eq!(entries[0].upstream_status, Some(500));
        assert_eq!(
            entries[0].error.as_deref(),
            Some("unsupported upstream status")
        );
    }

    #[tokio::test]
    async fn nix_cache_route_rejects_non_get_head_without_contacting_upstream() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let service = nix_cache_service_for_test(&state, &upstream, 1024);

        let response =
            route_nix_cache_with_service(&session, "POST", VM_NIX_CACHE_INFO_PATH.into(), service)
                .await;

        assert_eq!(response.status, VmHttpStatus::MethodNotAllowed);
        upstream.verify().await;
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::CacheInfo);
        assert_eq!(entries[0].http_status, Some(405));
        assert_eq!(entries[0].upstream_url, None);
    }

    #[tokio::test]
    async fn nix_cache_auth_denial_is_audited_without_contacting_upstream() {
        let upstream = MockServer::start().await;
        let state = make_broker_state(&upstream);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let service = nix_cache_service_for_test(&state, &upstream, 1024);
        let raw_head = format!("GET {VM_NIX_CACHE_INFO_PATH} HTTP/1.1\r\n\r\n").into_bytes();
        let mut stream = tokio::io::empty();

        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            VmHttpHeadRead {
                raw_head,
                buffered_body: Vec::new(),
            },
            &mut stream,
            None::<VmHttpGitCloneService<Box<dyn SecretStore>>>,
            Some(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        upstream.verify().await;
        let entries = state
            .audit
            .list_nix_cache_requests_for_session(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].decision,
            NixCacheAuditDecision::Deny {
                reason: "missing credentials".into()
            }
        );
        assert_eq!(entries[0].route, NixCacheAuditRoute::CacheInfo);
        assert_eq!(entries[0].http_status, Some(401));
        assert_eq!(entries[0].upstream_url, None);
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
            "/v1/nix/cache/nar",
            "/v1/nix/cache/nar/",
            "/v1/nix/cache/nar/.",
            "/v1/nix/cache/nar/.hidden",
            "/v1/nix/cache/nar/proof.",
            "/v1/nix/cache/nar/../proof.nar",
            "/v1/nix/cache/nar/subdir/proof.nar",
            "/v1/nix/cache/nar/proof nar",
            "/v1/nix/cache/nar/proof%2Fnar",
            "/v1/nix/cache/nar/proof.nar?download=1",
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
                None,
                VM_HTTP_READ_TIMEOUT,
            )
            .await
            .into_buffered();

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
            None,
            VM_HTTP_READ_TIMEOUT,
        )
        .await
        .into_buffered();

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
            None,
            VM_HTTP_READ_TIMEOUT,
        )
        .await
        .into_buffered();
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
                None,
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("session route must not wait for a declared body")
        .into_buffered();

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
                None,
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("disabled Git clone route must not wait for a declared body")
        .into_buffered();

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
                None,
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("non-POST Git clone route must not wait for a declared body")
        .into_buffered();

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
                None,
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("Nix cache route must not wait for a declared body")
        .into_buffered();

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
            nix_cache_config_for_test(),
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
            nix_cache_config_for_test(),
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
            VmHttpNixCacheService::new(Arc::clone(&state), nix_cache_config_for_test()),
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
            None,
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
