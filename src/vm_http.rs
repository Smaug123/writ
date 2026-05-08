//! VM-facing broker HTTP endpoint.
//!
//! This is deliberately separate from the host Unix-socket protocol. The VM
//! endpoint authenticates one managed agent VM session with a bearer secret and
//! a source-subnet check, then exposes only VM-safe broker operations.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::agent_run::{
    AgentPrompt, AgentRunId, AgentRunOutcome, AgentRunStreamSummary, AgentRunStreamUpload,
    VM_AGENT_RUN_OUTCOME_PATH_SUFFIX, VM_AGENT_RUN_PATH_PREFIX, VmAgentRunConfigResponse,
    VmAgentRunOutcomeUpload,
};
use crate::audit::{
    AgentRunOutcomeAuditRecord, AuditError, ClaudeProxyAuditDecision, ClaudeProxyAuditRoute,
    ClaudeProxyOutcomeRecord, ClaudeProxyRequestRecord, NixCacheAuditDecision, NixCacheAuditRoute,
    NixCacheOutcomeRecord, NixCacheRequestRecord, OpenAiProxyAuditDecision, OpenAiProxyAuditRoute,
    OpenAiProxyOutcomeRecord, OpenAiProxyRequestRecord,
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
use crate::openai_chatgpt_auth::{
    CHATGPT_OAUTH_REFRESH_LEEWAY_SECONDS, CHATGPT_OAUTH_REFRESH_URL, ChatgptOauthAuthority,
    ChatgptOauthAuthorityConfig, ChatgptOauthError, ChatgptUpstreamHeaders, SystemClock,
};
use crate::secret::{SecretKey, SecretStore};
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
const MAX_VM_HTTP_AGENT_RUN_OUTCOME_BODY_BYTES: usize = 4 * 1024 * 1024;
// The JSON upload cap bounds retained bytes on the wire. This larger cap is a
// defense-in-depth bound on the guest-reported full stream length, which is
// intentionally not trusted for truncated-stream audit rows.
const MAX_AGENT_RUN_STREAM_AUDIT_BYTES: u64 = 1024 * 1024 * 1024;
const VM_HTTP_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const EPHEMERAL_BIND_ATTEMPTS: usize = 32;
const MAX_VM_HTTP_CONNECTIONS: usize = 256;
pub const VM_NIX_CACHE_PATH_PREFIX: &str = "/v1/nix/cache";
const VM_NIX_CACHE_INFO_PATH: &str = "/v1/nix/cache/nix-cache-info";
pub const VM_NIX_BASIC_LOGIN: &str = "writ-vm";
const XZ_DECODER_MEMLIMIT_OVERHEAD: u64 = 16 * 1024 * 1024;
const VM_CLAUDE_MESSAGES_PATH: &str = "/v1/messages";
const VM_CLAUDE_COUNT_TOKENS_PATH: &str = "/v1/messages/count_tokens";
const VM_CLAUDE_MODELS_PREFIX: &str = "/v1/models/";
pub const DEFAULT_CLAUDE_ANTHROPIC_VERSION: &str = "2023-06-01";
const VM_OPENAI_RESPONSES_PATH: &str = "/v1/responses";
const VM_OPENAI_RESPONSES_PREFIX: &str = "/v1/responses/";
const VM_OPENAI_RESPONSE_CANCEL_SUFFIX: &str = "/cancel";
const VM_OPENAI_MODELS_PATH: &str = "/v1/models";
const VM_OPENAI_MODELS_PREFIX: &str = "/v1/models/";

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

pub struct VmHttpClaudeProxyService<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    config: VmHttpClaudeProxyConfig,
    client: reqwest::Client,
}

pub struct VmHttpOpenAiProxyService<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    config: VmHttpOpenAiProxyConfig,
    client: reqwest::Client,
    /// Refresh authority for the ChatGPT-OAuth auth kind. Kept behind
    /// an `Arc` so cloned services share a single in-memory cache and
    /// refresh-mutex; that turns concurrent guest requests into one
    /// upstream refresh rather than a thundering herd.
    chatgpt_authority: Option<Arc<ChatgptOauthAuthority>>,
}

#[derive(Clone, Debug)]
pub struct VmHttpAgentRunService {
    run_configs: Arc<Mutex<HashMap<AgentRunId, AgentRunInflight>>>,
    log_root: PathBuf,
}

#[derive(Clone, Debug)]
struct AgentRunInflight {
    prompt: AgentPrompt,
    model: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpGitRuntimeConfig {
    bind_addr: Ipv4Addr,
    broker_port_range: BrokerPortRange,
    git_clone: VmHttpGitCloneConfig,
    nix_cache: VmHttpNixCacheConfig,
    claude_proxy: Option<VmHttpClaudeProxyConfig>,
    openai_proxy: Option<VmHttpOpenAiProxyConfig>,
    agent_run_log_root: PathBuf,
}

pub struct PreparedVmHttpGitSession<S: SecretStore + Send + Sync + 'static> {
    listener: BoundVmHttpListener,
    session: VmHttpSession,
    git_clone: VmHttpGitCloneService<S>,
    nix_cache: VmHttpNixCacheService<S>,
    proxies: VmHttpProxies<S>,
    agent_runs: Option<VmHttpAgentRunService>,
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
    agent_runs: Option<VmHttpAgentRunService>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpClaudeProxyConfig {
    upstream_base_url: reqwest::Url,
    auth_secret: SecretKey,
    auth_kind: VmHttpClaudeProxyAuthKind,
    anthropic_version: reqwest::header::HeaderValue,
    timeout: std::time::Duration,
    max_request_bytes: usize,
    max_response_bytes: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmHttpClaudeProxyAuthKind {
    XApiKey,
    AuthorizationBearer,
    #[serde(rename = "oauth")]
    OAuth,
}

const ANTHROPIC_OAUTH_BETA_HEADER_VALUE: &str = "oauth-2025-04-20";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpOpenAiProxyConfig {
    upstream_base_url: reqwest::Url,
    auth_secret: SecretKey,
    auth_kind: VmHttpOpenAiProxyAuthKind,
    chatgpt_refresh_url: reqwest::Url,
    timeout: std::time::Duration,
    max_request_bytes: usize,
    max_response_bytes: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmHttpOpenAiProxyAuthKind {
    /// Static bearer token; the broker reads it from the secret store
    /// and attaches it as `Authorization: Bearer …`. Suitable for
    /// OpenAI API keys.
    AuthorizationBearer,
    /// ChatGPT-login OAuth: the secret store holds a `codex login`
    /// auth.json blob. The broker keeps the access token fresh
    /// against `https://auth.openai.com/oauth/token` and injects the
    /// `ChatGPT-Account-ID` and (when applicable) `X-OpenAI-Fedramp`
    /// headers expected by the Responses API.
    ChatgptOauth,
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

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum VmHttpClaudeProxyConfigError {
    #[error("Claude proxy upstream URL must not be empty")]
    EmptyUpstreamUrl,
    #[error("Claude proxy upstream URL {raw:?} is invalid: {message}")]
    InvalidUpstreamUrl { raw: String, message: String },
    #[error("Claude proxy upstream URL {raw:?} uses unsupported scheme {scheme:?}")]
    UnsupportedUpstreamScheme { raw: String, scheme: String },
    #[error("Claude proxy upstream URL must not contain embedded credentials: {0:?}")]
    UpstreamUrlHasCredentials(String),
    #[error("Claude proxy upstream URL must not contain a query or fragment: {0:?}")]
    UpstreamUrlHasQueryOrFragment(String),
    #[error("Claude proxy request timeout must be greater than zero")]
    EmptyTimeout,
    #[error("Claude proxy max request bytes must be greater than zero")]
    EmptyMaxRequestBytes,
    #[error("Claude proxy max request bytes exceeds this platform's usize range")]
    MaxRequestBytesTooLarge,
    #[error("Claude proxy max response bytes must be greater than zero")]
    EmptyMaxResponseBytes,
    #[error("Claude proxy Anthropic version must not be empty")]
    EmptyAnthropicVersion,
    #[error("Claude proxy Anthropic version is not a valid HTTP header value: {message}")]
    InvalidAnthropicVersion { message: String },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum VmHttpOpenAiProxyConfigError {
    #[error("OpenAI proxy upstream URL must not be empty")]
    EmptyUpstreamUrl,
    #[error("OpenAI proxy upstream URL {raw:?} is invalid: {message}")]
    InvalidUpstreamUrl { raw: String, message: String },
    #[error("OpenAI proxy upstream URL {raw:?} uses unsupported scheme {scheme:?}")]
    UnsupportedUpstreamScheme { raw: String, scheme: String },
    #[error("OpenAI proxy upstream URL must not contain embedded credentials: {0:?}")]
    UpstreamUrlHasCredentials(String),
    #[error("OpenAI proxy upstream URL must not contain a query or fragment: {0:?}")]
    UpstreamUrlHasQueryOrFragment(String),
    #[error("OpenAI proxy request timeout must be greater than zero")]
    EmptyTimeout,
    #[error("OpenAI proxy max request bytes must be greater than zero")]
    EmptyMaxRequestBytes,
    #[error("OpenAI proxy max request bytes exceeds this platform's usize range")]
    MaxRequestBytesTooLarge,
    #[error("OpenAI proxy max response bytes must be greater than zero")]
    EmptyMaxResponseBytes,
    #[error("OpenAI proxy ChatGPT refresh URL {raw:?} is invalid: {message}")]
    InvalidChatgptRefreshUrl { raw: String, message: String },
    #[error("OpenAI proxy ChatGPT refresh URL {raw:?} uses unsupported scheme {scheme:?}")]
    UnsupportedChatgptRefreshScheme { raw: String, scheme: String },
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
    #[error("cannot construct Claude proxy HTTP client: {0}")]
    ClaudeProxyClient(reqwest::Error),
    #[error("cannot construct OpenAI proxy HTTP client: {0}")]
    OpenAiProxyClient(reqwest::Error),
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

#[derive(Debug)]
struct VmHttpClaudeProxyFetch {
    response: VmHttpResponse,
    upstream_url: Option<String>,
    upstream_status: Option<u16>,
    response_bytes: u64,
    error: Option<&'static str>,
}

struct VmHttpClaudeProxyStream<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    request_id: RequestId,
    response: reqwest::Response,
    upstream_url: String,
    upstream_status: u16,
    content_type: &'static str,
    headers: Vec<VmHttpResponseHeader>,
    max_response_bytes: u64,
}

#[derive(Debug)]
struct VmHttpOpenAiProxyFetch {
    response: VmHttpResponse,
    upstream_url: Option<String>,
    upstream_status: Option<u16>,
    response_bytes: u64,
    error: Option<&'static str>,
}

struct VmHttpOpenAiProxyStream<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    request_id: RequestId,
    response: reqwest::Response,
    upstream_url: String,
    upstream_status: u16,
    content_type: &'static str,
    headers: Vec<VmHttpResponseHeader>,
    max_response_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VmHttpNixCacheAdmittedNar {
    file: NixCacheNarFileName,
    compression: NixNarCompression,
    nar_hash: NixNarHash,
    nar_size: NixNarSize,
}

enum VmHttpDispatch<S: SecretStore> {
    Buffered(VmHttpResponse),
    ClaudeProxyStream(VmHttpClaudeProxyStream<S>),
    OpenAiProxyStream(VmHttpOpenAiProxyStream<S>),
}

#[derive(Debug, thiserror::Error)]
enum VmHttpNixCacheBodyReadError {
    #[error("Nix cache upstream response body read failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Nix cache upstream response exceeds {max} bytes")]
    ResponseTooLarge { max: u64 },
}

#[derive(Debug, thiserror::Error)]
enum VmHttpClaudeProxyBodyReadError {
    #[error("Claude proxy upstream response body read failed after {bytes_read} bytes: {source}")]
    Request {
        source: reqwest::Error,
        bytes_read: u64,
    },
    #[error("Claude proxy upstream response exceeds {max} bytes after {bytes_read} bytes")]
    ResponseTooLarge { max: u64, bytes_read: u64 },
}

#[derive(Debug, thiserror::Error)]
enum VmHttpOpenAiProxyBodyReadError {
    #[error("OpenAI proxy upstream response body read failed after {bytes_read} bytes: {source}")]
    Request {
        source: reqwest::Error,
        bytes_read: u64,
    },
    #[error("OpenAI proxy upstream response exceeds {max} bytes after {bytes_read} bytes")]
    ResponseTooLarge { max: u64, bytes_read: u64 },
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
            headers: Vec::new(),
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

impl<S: SecretStore> VmHttpClaudeProxyService<S> {
    pub fn new(
        broker_state: Arc<BrokerState<S>>,
        config: VmHttpClaudeProxyConfig,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .connect_timeout(config.timeout)
            .read_timeout(config.timeout)
            .build()?;
        Ok(Self {
            broker_state,
            config,
            client,
        })
    }

    fn upstream_request_builder(
        &self,
        request: &VmHttpRequest,
        body: Vec<u8>,
        headers: Vec<ClaudeProxyForwardHeader>,
    ) -> Result<(String, reqwest::RequestBuilder), Box<VmHttpClaudeProxyFetch>> {
        let Some(route) = classify_claude_proxy_target(&request.target) else {
            let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
            return Err(Box::new(VmHttpClaudeProxyFetch {
                response_bytes: response.body.len() as u64,
                response,
                upstream_url: None,
                upstream_status: None,
                error: None,
            }));
        };
        let Some(url) = self.upstream_url(&request.target) else {
            let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
            return Err(Box::new(VmHttpClaudeProxyFetch {
                response_bytes: response.body.len() as u64,
                response,
                upstream_url: None,
                upstream_status: None,
                error: None,
            }));
        };
        let upstream_url = url.to_string();
        let secret = match self
            .broker_state
            .secret_store()
            .get(self.config.auth_secret())
        {
            Ok(Some(secret)) if !secret.is_empty() => secret,
            Ok(_) => {
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "Claude proxy auth missing");
                return Err(Box::new(VmHttpClaudeProxyFetch {
                    response_bytes: response.body.len() as u64,
                    response,
                    upstream_url: Some(upstream_url),
                    upstream_status: None,
                    error: Some("upstream auth missing"),
                }));
            }
            Err(err) => {
                eprintln!("VM HTTP Claude proxy auth secret load failed: {err}");
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "Claude proxy auth failed");
                return Err(Box::new(VmHttpClaudeProxyFetch {
                    response_bytes: response.body.len() as u64,
                    response,
                    upstream_url: Some(upstream_url),
                    upstream_status: None,
                    error: Some("upstream auth load failed"),
                }));
            }
        };

        let mut builder = self.client.request(claude_proxy_route_method(route), url);
        if !body.is_empty() {
            builder = builder.body(body);
        }
        for header in headers {
            builder = builder.header(header.name, header.value);
        }
        builder = match self.config.auth_kind() {
            VmHttpClaudeProxyAuthKind::XApiKey => builder.header("x-api-key", secret),
            VmHttpClaudeProxyAuthKind::AuthorizationBearer => builder.bearer_auth(secret),
            VmHttpClaudeProxyAuthKind::OAuth => builder
                .bearer_auth(secret)
                .header("anthropic-beta", ANTHROPIC_OAUTH_BETA_HEADER_VALUE),
        };
        Ok((upstream_url, builder))
    }

    async fn fetch(
        &self,
        request: &VmHttpRequest,
        body: Vec<u8>,
        headers: Vec<ClaudeProxyForwardHeader>,
    ) -> VmHttpClaudeProxyFetch {
        let (upstream_url, builder) = match self.upstream_request_builder(request, body, headers) {
            Ok(parts) => parts,
            Err(fetch) => return *fetch,
        };

        let response = match builder.send().await {
            Ok(response) => response,
            Err(err) => {
                eprintln!("VM HTTP Claude proxy upstream request failed: {err}");
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "Claude proxy upstream failed");
                return VmHttpClaudeProxyFetch {
                    response_bytes: response.body.len() as u64,
                    response,
                    upstream_url: Some(upstream_url),
                    upstream_status: None,
                    error: Some("upstream request failed"),
                };
            }
        };

        let upstream_status = response.status();
        let content_type = claude_proxy_response_content_type(&response);
        let response_headers = claude_proxy_response_headers(response.headers());
        let body = match read_claude_upstream_body_bounded(response, self.config.max_response_bytes)
            .await
        {
            Ok(body) => body,
            Err(err) => {
                eprintln!("VM HTTP Claude proxy upstream body read failed: {err}");
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "Claude proxy upstream failed");
                return VmHttpClaudeProxyFetch {
                    response_bytes: err.bytes_read(),
                    response,
                    upstream_url: Some(upstream_url),
                    upstream_status: Some(upstream_status.as_u16()),
                    error: Some(err.audit_error_label()),
                };
            }
        };
        let response_bytes = body.len() as u64;
        VmHttpClaudeProxyFetch {
            response: VmHttpResponse {
                status: VmHttpStatus::Upstream(upstream_status.as_u16()),
                content_type,
                body,
                content_length: None,
                www_authenticate: None,
                headers: response_headers,
            },
            upstream_url: Some(upstream_url),
            upstream_status: Some(upstream_status.as_u16()),
            response_bytes,
            error: None,
        }
    }

    async fn fetch_stream(
        &self,
        request_id: RequestId,
        request: &VmHttpRequest,
        body: Vec<u8>,
        headers: Vec<ClaudeProxyForwardHeader>,
    ) -> Result<VmHttpClaudeProxyStream<S>, VmHttpClaudeProxyFetch> {
        let (upstream_url, builder) = self
            .upstream_request_builder(request, body, headers)
            .map_err(|fetch| *fetch)?;
        let response = match builder.send().await {
            Ok(response) => response,
            Err(err) => {
                eprintln!("VM HTTP Claude proxy upstream request failed: {err}");
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "Claude proxy upstream failed");
                return Err(VmHttpClaudeProxyFetch {
                    response_bytes: response.body.len() as u64,
                    response,
                    upstream_url: Some(upstream_url),
                    upstream_status: None,
                    error: Some("upstream request failed"),
                });
            }
        };
        let upstream_status = response.status().as_u16();
        let content_type = claude_proxy_response_content_type(&response);
        let headers = claude_proxy_response_headers(response.headers());
        Ok(VmHttpClaudeProxyStream {
            broker_state: Arc::clone(&self.broker_state),
            request_id,
            response,
            upstream_url,
            upstream_status,
            content_type,
            headers,
            max_response_bytes: self.config.max_response_bytes,
        })
    }

    fn upstream_url(&self, target: &str) -> Option<reqwest::Url> {
        let path = claude_proxy_target_path(target);
        let relative: Cow<'static, str> = match path {
            VM_CLAUDE_MESSAGES_PATH => "v1/messages".into(),
            VM_CLAUDE_COUNT_TOKENS_PATH => "v1/messages/count_tokens".into(),
            _ => format!("v1/models/{}", claude_proxy_model_id(path)?).into(),
        };
        Some(
            self.config
                .upstream_base_url
                .join(&relative)
                .expect("Claude proxy route paths are URL-safe relative paths"),
        )
    }
}

fn claude_proxy_route_method(route: ClaudeProxyAuditRoute) -> reqwest::Method {
    match route {
        ClaudeProxyAuditRoute::Messages | ClaudeProxyAuditRoute::CountTokens => {
            reqwest::Method::POST
        }
        ClaudeProxyAuditRoute::Models => reqwest::Method::GET,
        ClaudeProxyAuditRoute::Unsupported => {
            unreachable!("Unsupported routes are rejected before method selection")
        }
    }
}

impl<S: SecretStore> Clone for VmHttpClaudeProxyService<S> {
    fn clone(&self) -> Self {
        Self {
            broker_state: Arc::clone(&self.broker_state),
            config: self.config.clone(),
            client: self.client.clone(),
        }
    }
}

impl<S: SecretStore> VmHttpClaudeProxyStream<S> {
    async fn write_to<W: AsyncWrite + Unpin>(mut self, out: &mut W) -> std::io::Result<()> {
        write_http_response_head(
            out,
            VmHttpStatus::Upstream(self.upstream_status),
            self.content_type,
            None,
            None,
            &self.headers,
        )
        .await?;

        let mut response_bytes = 0u64;
        let mut error = None;
        let mut write_error = None;
        loop {
            let chunk = match self.response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(err) => {
                    eprintln!("VM HTTP Claude proxy streaming body read failed: {err}");
                    error = Some("upstream body read failed");
                    break;
                }
            };
            let chunk_len = u64::try_from(chunk.len()).expect("HTTP chunk length fits in u64");
            let new_len = response_bytes
                .checked_add(chunk_len)
                .expect("HTTP response byte count overflowed before configured bound check");
            if new_len > self.max_response_bytes {
                error = Some("upstream response too large");
                response_bytes = new_len;
                break;
            }
            if let Err(err) = out.write_all(&chunk).await {
                error = Some("guest response write failed");
                write_error = Some(err);
                break;
            }
            response_bytes = new_len;
        }

        if let Err(err) =
            self.broker_state
                .audit
                .record_claude_proxy_outcome(&ClaudeProxyOutcomeRecord {
                    request_id: self.request_id,
                    completed_at: UnixMillis::now(),
                    http_status: self.upstream_status,
                    upstream_url: Some(self.upstream_url.as_str()),
                    upstream_status: Some(self.upstream_status),
                    response_bytes,
                    error,
                })
        {
            eprintln!("VM HTTP Claude proxy streaming audit outcome write failed: {err}");
        }

        match write_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

impl<S: SecretStore> VmHttpOpenAiProxyService<S> {
    pub fn new(
        broker_state: Arc<BrokerState<S>>,
        config: VmHttpOpenAiProxyConfig,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .connect_timeout(config.timeout)
            .read_timeout(config.timeout)
            .build()?;
        let chatgpt_authority = match config.auth_kind() {
            VmHttpOpenAiProxyAuthKind::AuthorizationBearer => None,
            VmHttpOpenAiProxyAuthKind::ChatgptOauth => {
                let refresh_client = reqwest::Client::builder()
                    .connect_timeout(config.timeout)
                    .read_timeout(config.timeout)
                    .build()?;
                let authority_config = ChatgptOauthAuthorityConfig {
                    secret_key: config.auth_secret().clone(),
                    refresh_url: config.chatgpt_refresh_url().clone(),
                    http_client: refresh_client,
                    clock: Arc::new(SystemClock),
                    leeway_seconds: CHATGPT_OAUTH_REFRESH_LEEWAY_SECONDS,
                };
                Some(Arc::new(ChatgptOauthAuthority::new(authority_config)))
            }
        };
        Ok(Self {
            broker_state,
            config,
            client,
            chatgpt_authority,
        })
    }

    async fn resolve_upstream_auth(&self) -> Result<UpstreamAuth, Box<VmHttpOpenAiProxyFetch>> {
        match self.config.auth_kind() {
            VmHttpOpenAiProxyAuthKind::AuthorizationBearer => {
                let secret = match self
                    .broker_state
                    .secret_store()
                    .get(self.config.auth_secret())
                {
                    Ok(Some(secret)) if !secret.is_empty() => secret,
                    Ok(_) => {
                        return Err(Box::new(openai_proxy_auth_failure(
                            "OpenAI proxy auth missing",
                            "upstream auth missing",
                        )));
                    }
                    Err(err) => {
                        eprintln!("VM HTTP OpenAI proxy auth secret load failed: {err}");
                        return Err(Box::new(openai_proxy_auth_failure(
                            "OpenAI proxy auth failed",
                            "upstream auth load failed",
                        )));
                    }
                };
                Ok(UpstreamAuth::Bearer(secret))
            }
            VmHttpOpenAiProxyAuthKind::ChatgptOauth => {
                let authority = self
                    .chatgpt_authority
                    .as_ref()
                    .expect("ChatGPT OAuth service constructed with authority");
                let store = self.broker_state.secret_store();
                match authority.current_headers(store).await {
                    Ok(headers) => Ok(UpstreamAuth::ChatgptOauth(headers)),
                    Err(err) => {
                        let label = err.audit_error_label();
                        eprintln!("VM HTTP OpenAI proxy ChatGPT auth resolution failed: {err}");
                        let body = match err {
                            ChatgptOauthError::LoginRequired
                            | ChatgptOauthError::BundleMalformed(_) => {
                                "OpenAI proxy ChatGPT login required"
                            }
                            ChatgptOauthError::RefreshTransient(_) => {
                                "OpenAI proxy ChatGPT refresh failed"
                            }
                            ChatgptOauthError::SecretStore(_) => "OpenAI proxy auth failed",
                        };
                        Err(Box::new(openai_proxy_auth_failure(body, label)))
                    }
                }
            }
        }
    }

    async fn upstream_request_builder(
        &self,
        request: &VmHttpRequest,
        body: Vec<u8>,
        headers: Vec<OpenAiProxyForwardHeader>,
    ) -> Result<(String, reqwest::RequestBuilder), Box<VmHttpOpenAiProxyFetch>> {
        let Some(route) = classify_openai_proxy_target(&request.target) else {
            let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
            return Err(Box::new(VmHttpOpenAiProxyFetch {
                response_bytes: response.body.len() as u64,
                response,
                upstream_url: None,
                upstream_status: None,
                error: None,
            }));
        };
        let Some(url) = self.upstream_url(&request.target) else {
            let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
            return Err(Box::new(VmHttpOpenAiProxyFetch {
                response_bytes: response.body.len() as u64,
                response,
                upstream_url: None,
                upstream_status: None,
                error: None,
            }));
        };
        let upstream_url = url.to_string();
        let upstream_auth = self.resolve_upstream_auth().await.map_err(|mut fetch| {
            fetch.upstream_url = Some(upstream_url.clone());
            fetch
        })?;

        let mut builder = self.client.request(openai_proxy_route_method(route), url);
        if !body.is_empty() {
            builder = builder.body(body);
        }
        for header in headers {
            builder = builder.header(header.name, header.value);
        }
        builder = upstream_auth.apply_to(builder);
        Ok((upstream_url, builder))
    }

    async fn fetch(
        &self,
        request: &VmHttpRequest,
        body: Vec<u8>,
        headers: Vec<OpenAiProxyForwardHeader>,
    ) -> VmHttpOpenAiProxyFetch {
        let (upstream_url, builder) =
            match self.upstream_request_builder(request, body, headers).await {
                Ok(parts) => parts,
                Err(fetch) => return *fetch,
            };

        let response = match builder.send().await {
            Ok(response) => response,
            Err(err) => {
                eprintln!("VM HTTP OpenAI proxy upstream request failed: {err}");
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "OpenAI proxy upstream failed");
                return VmHttpOpenAiProxyFetch {
                    response_bytes: response.body.len() as u64,
                    response,
                    upstream_url: Some(upstream_url),
                    upstream_status: None,
                    error: Some("upstream request failed"),
                };
            }
        };

        let upstream_status = response.status();
        let content_type = openai_proxy_response_content_type(&response);
        let response_headers = openai_proxy_response_headers(response.headers());
        let body = match read_openai_upstream_body_bounded(response, self.config.max_response_bytes)
            .await
        {
            Ok(body) => body,
            Err(err) => {
                eprintln!("VM HTTP OpenAI proxy upstream body read failed: {err}");
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "OpenAI proxy upstream failed");
                return VmHttpOpenAiProxyFetch {
                    response_bytes: err.bytes_read(),
                    response,
                    upstream_url: Some(upstream_url),
                    upstream_status: Some(upstream_status.as_u16()),
                    error: Some(err.audit_error_label()),
                };
            }
        };
        let response_bytes = body.len() as u64;
        VmHttpOpenAiProxyFetch {
            response: VmHttpResponse {
                status: VmHttpStatus::Upstream(upstream_status.as_u16()),
                content_type,
                body,
                content_length: None,
                www_authenticate: None,
                headers: response_headers,
            },
            upstream_url: Some(upstream_url),
            upstream_status: Some(upstream_status.as_u16()),
            response_bytes,
            error: None,
        }
    }

    async fn fetch_stream(
        &self,
        request_id: RequestId,
        request: &VmHttpRequest,
        body: Vec<u8>,
        headers: Vec<OpenAiProxyForwardHeader>,
    ) -> Result<VmHttpOpenAiProxyStream<S>, VmHttpOpenAiProxyFetch> {
        let (upstream_url, builder) = self
            .upstream_request_builder(request, body, headers)
            .await
            .map_err(|fetch| *fetch)?;
        let response = match builder.send().await {
            Ok(response) => response,
            Err(err) => {
                eprintln!("VM HTTP OpenAI proxy upstream request failed: {err}");
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, "OpenAI proxy upstream failed");
                return Err(VmHttpOpenAiProxyFetch {
                    response_bytes: response.body.len() as u64,
                    response,
                    upstream_url: Some(upstream_url),
                    upstream_status: None,
                    error: Some("upstream request failed"),
                });
            }
        };
        let upstream_status = response.status().as_u16();
        let content_type = openai_proxy_response_content_type(&response);
        let headers = openai_proxy_response_headers(response.headers());
        Ok(VmHttpOpenAiProxyStream {
            broker_state: Arc::clone(&self.broker_state),
            request_id,
            response,
            upstream_url,
            upstream_status,
            content_type,
            headers,
            max_response_bytes: self.config.max_response_bytes,
        })
    }

    fn upstream_url(&self, target: &str) -> Option<reqwest::Url> {
        let path = openai_proxy_target_path(target);
        // ChatGPT-OAuth requests target `https://chatgpt.com/backend-api/codex/`
        // which exposes endpoints as bare names (e.g. `/codex/responses`),
        // whereas `https://api.openai.com/` exposes them under the `v1/`
        // prefix. The broker's `upstream_base_url` already encodes the
        // path-prefix portion (`/codex/` or `/v1/`); the per-route relative
        // joined here must match the wire shape codex itself uses for that
        // auth mode (see `model-provider-info`'s `to_api_provider`).
        let prefix = match self.config.auth_kind() {
            VmHttpOpenAiProxyAuthKind::AuthorizationBearer => "v1/",
            VmHttpOpenAiProxyAuthKind::ChatgptOauth => "",
        };
        let relative: Cow<'static, str> = if path == VM_OPENAI_RESPONSES_PATH {
            format!("{prefix}responses").into()
        } else if path == VM_OPENAI_MODELS_PATH {
            format!("{prefix}models").into()
        } else if let Some(id) = openai_proxy_response_cancel_id(path) {
            format!("{prefix}responses/{id}/cancel").into()
        } else if let Some(id) = openai_proxy_model_id(path) {
            format!("{prefix}models/{id}").into()
        } else {
            return None;
        };
        Some(
            self.config
                .upstream_base_url
                .join(&relative)
                .expect("OpenAI proxy route paths are URL-safe relative paths"),
        )
    }
}

fn openai_proxy_route_method(route: OpenAiProxyAuditRoute) -> reqwest::Method {
    match route {
        OpenAiProxyAuditRoute::Responses | OpenAiProxyAuditRoute::ResponseCancel => {
            reqwest::Method::POST
        }
        OpenAiProxyAuditRoute::Models => reqwest::Method::GET,
        OpenAiProxyAuditRoute::Unsupported => {
            unreachable!("Unsupported routes are rejected before method selection")
        }
    }
}

impl<S: SecretStore> Clone for VmHttpOpenAiProxyService<S> {
    fn clone(&self) -> Self {
        Self {
            broker_state: Arc::clone(&self.broker_state),
            config: self.config.clone(),
            client: self.client.clone(),
            chatgpt_authority: self.chatgpt_authority.as_ref().map(Arc::clone),
        }
    }
}

/// Resolved upstream authentication for a single OpenAI proxy request.
///
/// We resolve into a small enum so the request builder applies the
/// scheme-specific headers in one place. The `Bearer` variant matches a
/// static API key; the `ChatgptOauth` variant carries the freshly
/// rotated access token plus the ChatGPT-specific response headers
/// (`ChatGPT-Account-ID`, optional `X-OpenAI-Fedramp`).
enum UpstreamAuth {
    Bearer(String),
    ChatgptOauth(ChatgptUpstreamHeaders),
}

impl UpstreamAuth {
    fn apply_to(self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            UpstreamAuth::Bearer(secret) => builder.bearer_auth(secret),
            UpstreamAuth::ChatgptOauth(headers) => {
                let mut builder = builder.bearer_auth(headers.access_token);
                if let Some(account_id) = headers.account_id {
                    builder = builder.header("ChatGPT-Account-ID", account_id);
                }
                if headers.is_fedramp_account {
                    builder = builder.header("X-OpenAI-Fedramp", "true");
                }
                builder
            }
        }
    }
}

fn openai_proxy_auth_failure(body: &'static str, label: &'static str) -> VmHttpOpenAiProxyFetch {
    let response = VmHttpResponse::text(VmHttpStatus::BadGateway, body);
    VmHttpOpenAiProxyFetch {
        response_bytes: response.body.len() as u64,
        response,
        upstream_url: None,
        upstream_status: None,
        error: Some(label),
    }
}

impl<S: SecretStore> VmHttpOpenAiProxyStream<S> {
    async fn write_to<W: AsyncWrite + Unpin>(mut self, out: &mut W) -> std::io::Result<()> {
        write_http_response_head(
            out,
            VmHttpStatus::Upstream(self.upstream_status),
            self.content_type,
            None,
            None,
            &self.headers,
        )
        .await?;

        let mut response_bytes = 0u64;
        let mut error = None;
        let mut write_error = None;
        loop {
            let chunk = match self.response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(err) => {
                    eprintln!("VM HTTP OpenAI proxy streaming body read failed: {err}");
                    error = Some("upstream body read failed");
                    break;
                }
            };
            let chunk_len = u64::try_from(chunk.len()).expect("HTTP chunk length fits in u64");
            let new_len = response_bytes
                .checked_add(chunk_len)
                .expect("HTTP response byte count overflowed before configured bound check");
            if new_len > self.max_response_bytes {
                error = Some("upstream response too large");
                response_bytes = new_len;
                break;
            }
            if let Err(err) = out.write_all(&chunk).await {
                error = Some("guest response write failed");
                write_error = Some(err);
                break;
            }
            response_bytes = new_len;
        }

        if let Err(err) =
            self.broker_state
                .audit
                .record_openai_proxy_outcome(&OpenAiProxyOutcomeRecord {
                    request_id: self.request_id,
                    completed_at: UnixMillis::now(),
                    http_status: self.upstream_status,
                    upstream_url: Some(self.upstream_url.as_str()),
                    upstream_status: Some(self.upstream_status),
                    response_bytes,
                    error,
                })
        {
            eprintln!("VM HTTP OpenAI proxy streaming audit outcome write failed: {err}");
        }

        match write_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

impl VmHttpAgentRunService {
    pub fn with_log_root(log_root: impl Into<PathBuf>) -> Self {
        Self {
            run_configs: Arc::new(Mutex::new(HashMap::new())),
            log_root: log_root.into(),
        }
    }

    pub fn insert_run_config(
        &self,
        run_id: AgentRunId,
        prompt: AgentPrompt,
        model: impl Into<String>,
    ) {
        self.run_configs
            .lock()
            .expect("agent run config lock should not be poisoned")
            .insert(
                run_id,
                AgentRunInflight {
                    prompt,
                    model: model.into(),
                },
            );
    }

    fn take_run_config(&self, run_id: AgentRunId) -> Option<AgentRunInflight> {
        self.run_configs
            .lock()
            .expect("agent run config lock should not be poisoned")
            .remove(&run_id)
    }

    fn log_root(&self) -> &Path {
        &self.log_root
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
        agent_runs: Option<VmHttpAgentRunService>,
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

impl VmHttpGitRuntimeConfig {
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

impl VmHttpClaudeProxyConfig {
    pub fn new(
        upstream_base_url: impl AsRef<str>,
        auth_secret: SecretKey,
        auth_kind: VmHttpClaudeProxyAuthKind,
        timeout: std::time::Duration,
        max_request_bytes: u64,
        max_response_bytes: u64,
    ) -> Result<Self, VmHttpClaudeProxyConfigError> {
        Self::new_with_anthropic_version(
            upstream_base_url,
            auth_secret,
            auth_kind,
            DEFAULT_CLAUDE_ANTHROPIC_VERSION,
            timeout,
            max_request_bytes,
            max_response_bytes,
        )
    }

    pub fn new_with_anthropic_version(
        upstream_base_url: impl AsRef<str>,
        auth_secret: SecretKey,
        auth_kind: VmHttpClaudeProxyAuthKind,
        anthropic_version: impl AsRef<str>,
        timeout: std::time::Duration,
        max_request_bytes: u64,
        max_response_bytes: u64,
    ) -> Result<Self, VmHttpClaudeProxyConfigError> {
        let raw = upstream_base_url.as_ref();
        let raw_anthropic_version = anthropic_version.as_ref();
        if raw.is_empty() {
            return Err(VmHttpClaudeProxyConfigError::EmptyUpstreamUrl);
        }
        if raw_anthropic_version.is_empty() {
            return Err(VmHttpClaudeProxyConfigError::EmptyAnthropicVersion);
        }
        let anthropic_version = reqwest::header::HeaderValue::from_str(raw_anthropic_version)
            .map_err(
                |err| VmHttpClaudeProxyConfigError::InvalidAnthropicVersion {
                    message: err.to_string(),
                },
            )?;
        if timeout.is_zero() {
            return Err(VmHttpClaudeProxyConfigError::EmptyTimeout);
        }
        if max_request_bytes == 0 {
            return Err(VmHttpClaudeProxyConfigError::EmptyMaxRequestBytes);
        }
        let max_request_bytes = usize::try_from(max_request_bytes)
            .map_err(|_| VmHttpClaudeProxyConfigError::MaxRequestBytesTooLarge)?;
        if max_response_bytes == 0 {
            return Err(VmHttpClaudeProxyConfigError::EmptyMaxResponseBytes);
        }
        let mut url = reqwest::Url::parse(raw).map_err(|err| {
            VmHttpClaudeProxyConfigError::InvalidUpstreamUrl {
                raw: raw.to_string(),
                message: err.to_string(),
            }
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(VmHttpClaudeProxyConfigError::UnsupportedUpstreamScheme {
                raw: raw.to_string(),
                scheme: url.scheme().to_string(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(VmHttpClaudeProxyConfigError::UpstreamUrlHasCredentials(
                raw.to_string(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(VmHttpClaudeProxyConfigError::UpstreamUrlHasQueryOrFragment(
                raw.to_string(),
            ));
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        Ok(Self {
            upstream_base_url: url,
            auth_secret,
            auth_kind,
            anthropic_version,
            timeout,
            max_request_bytes,
            max_response_bytes,
        })
    }

    pub fn upstream_base_url(&self) -> &reqwest::Url {
        &self.upstream_base_url
    }

    pub fn auth_secret(&self) -> &SecretKey {
        &self.auth_secret
    }

    pub fn auth_kind(&self) -> VmHttpClaudeProxyAuthKind {
        self.auth_kind
    }

    pub fn anthropic_version(&self) -> &reqwest::header::HeaderValue {
        &self.anthropic_version
    }

    pub fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    pub fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }
}

impl VmHttpOpenAiProxyConfig {
    pub fn new(
        upstream_base_url: impl AsRef<str>,
        auth_secret: SecretKey,
        auth_kind: VmHttpOpenAiProxyAuthKind,
        timeout: std::time::Duration,
        max_request_bytes: u64,
        max_response_bytes: u64,
    ) -> Result<Self, VmHttpOpenAiProxyConfigError> {
        let raw = upstream_base_url.as_ref();
        if raw.is_empty() {
            return Err(VmHttpOpenAiProxyConfigError::EmptyUpstreamUrl);
        }
        if timeout.is_zero() {
            return Err(VmHttpOpenAiProxyConfigError::EmptyTimeout);
        }
        if max_request_bytes == 0 {
            return Err(VmHttpOpenAiProxyConfigError::EmptyMaxRequestBytes);
        }
        let max_request_bytes = usize::try_from(max_request_bytes)
            .map_err(|_| VmHttpOpenAiProxyConfigError::MaxRequestBytesTooLarge)?;
        if max_response_bytes == 0 {
            return Err(VmHttpOpenAiProxyConfigError::EmptyMaxResponseBytes);
        }
        let mut url = reqwest::Url::parse(raw).map_err(|err| {
            VmHttpOpenAiProxyConfigError::InvalidUpstreamUrl {
                raw: raw.to_string(),
                message: err.to_string(),
            }
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(VmHttpOpenAiProxyConfigError::UnsupportedUpstreamScheme {
                raw: raw.to_string(),
                scheme: url.scheme().to_string(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(VmHttpOpenAiProxyConfigError::UpstreamUrlHasCredentials(
                raw.to_string(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(VmHttpOpenAiProxyConfigError::UpstreamUrlHasQueryOrFragment(
                raw.to_string(),
            ));
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        let chatgpt_refresh_url = reqwest::Url::parse(CHATGPT_OAUTH_REFRESH_URL)
            .expect("CHATGPT_OAUTH_REFRESH_URL is a static, well-formed absolute URL");
        Ok(Self {
            upstream_base_url: url,
            auth_secret,
            auth_kind,
            chatgpt_refresh_url,
            timeout,
            max_request_bytes,
            max_response_bytes,
        })
    }

    /// Override the ChatGPT-OAuth refresh endpoint. Tests use this to
    /// point at a `wiremock` server; production keeps the default.
    pub fn with_chatgpt_refresh_url(
        mut self,
        raw: impl AsRef<str>,
    ) -> Result<Self, VmHttpOpenAiProxyConfigError> {
        let raw = raw.as_ref();
        let url = reqwest::Url::parse(raw).map_err(|err| {
            VmHttpOpenAiProxyConfigError::InvalidChatgptRefreshUrl {
                raw: raw.to_string(),
                message: err.to_string(),
            }
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(
                VmHttpOpenAiProxyConfigError::UnsupportedChatgptRefreshScheme {
                    raw: raw.to_string(),
                    scheme: url.scheme().to_string(),
                },
            );
        }
        self.chatgpt_refresh_url = url;
        Ok(self)
    }

    pub fn upstream_base_url(&self) -> &reqwest::Url {
        &self.upstream_base_url
    }

    pub fn auth_secret(&self) -> &SecretKey {
        &self.auth_secret
    }

    pub fn auth_kind(&self) -> VmHttpOpenAiProxyAuthKind {
        self.auth_kind
    }

    pub fn chatgpt_refresh_url(&self) -> &reqwest::Url {
        &self.chatgpt_refresh_url
    }

    pub fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    pub fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
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
            self.proxies,
            self.agent_runs,
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
    prepare_vm_http_git_session_with_agent_runs(state, config, session_id, source_ipv4, None).await
}

pub async fn prepare_vm_http_git_session_with_agent_runs<S: SecretStore + Send + Sync + 'static>(
    state: Arc<BrokerState<S>>,
    config: &VmHttpGitRuntimeConfig,
    session_id: SessionId,
    source_ipv4: Ipv4Cidr,
    agent_runs: Option<VmHttpAgentRunService>,
) -> Result<PreparedVmHttpGitSession<S>, VmHttpGitRuntimeError> {
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
        .map_err(VmHttpGitRuntimeError::ClaudeProxyClient)?;
    let openai_proxy = config
        .openai_proxy
        .clone()
        .map(|config| VmHttpOpenAiProxyService::new(Arc::clone(&state), config))
        .transpose()
        .map_err(VmHttpGitRuntimeError::OpenAiProxyClient)?;
    Ok(PreparedVmHttpGitSession {
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

pub async fn run_vm_http_with_git_until_shutdown<S: SecretStore + Send + Sync + 'static>(
    listener: TcpListener,
    session: VmHttpSession,
    git_clone: VmHttpGitCloneService<S>,
    nix_cache: VmHttpNixCacheService<S>,
    proxies: VmHttpProxies<S>,
    agent_runs: Option<VmHttpAgentRunService>,
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
    services: VmHttpServices<S>,
) -> std::io::Result<()> {
    handle_vm_http_connection_with_read_timeout(
        stream,
        peer_addr,
        session,
        services,
        VM_HTTP_READ_TIMEOUT,
    )
    .await
}

async fn handle_vm_http_connection_with_read_timeout<S, T>(
    mut stream: T,
    peer_addr: SocketAddr,
    session: VmHttpSession,
    services: VmHttpServices<S>,
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
        services,
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
    services: VmHttpServices<S>,
    read_timeout: std::time::Duration,
) -> VmHttpDispatch<S>
where
    S: SecretStore + Send + Sync,
    R: AsyncRead + Unpin,
{
    let request = match parse_http_head(&head.raw_head, peer_addr) {
        Ok(request) => request,
        Err(err) => {
            let dispatch: VmHttpDispatch<S> =
                VmHttpResponse::text(VmHttpStatus::BadRequest, err.to_string()).into();
            log_vm_http_request(session, "?", "?", dispatch.status_code());
            return dispatch;
        }
    };
    let auth_scheme = auth_scheme_for_target(&request.target);
    let dispatch: VmHttpDispatch<S> =
        match authorize_vm_http_request_with_scheme(session, &request, auth_scheme) {
            VmHttpAuthorization::Allow => {
                route_authenticated_vm_http_request(
                    session,
                    &request,
                    head.buffered_body,
                    stream,
                    services,
                    read_timeout,
                )
                .await
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
                } else if let Some(route) = classify_claude_proxy_target(&request.target)
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
                } else if let Some(route) = classify_openai_proxy_target(&request.target)
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
    dispatch
}

fn log_vm_http_request(session: &VmHttpSession, method: &str, target: &str, status: u16) {
    eprintln!(
        "writd: vm http session={} {} {} -> {}",
        session.session_id(),
        method,
        target,
        status,
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

async fn route_authenticated_vm_http_request<S, R>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    buffered_body: Vec<u8>,
    stream: &mut R,
    services: VmHttpServices<S>,
    read_timeout: std::time::Duration,
) -> VmHttpDispatch<S>
where
    S: SecretStore + Send + Sync,
    R: AsyncRead + Unpin,
{
    if is_nix_cache_target(&request.target) {
        return route_nix_cache_request(session, request, services.nix_cache).await;
    }

    if is_claude_proxy_target(&request.target) {
        let Some(service) = services.claude_proxy else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        let body = match read_http_body_for_claude_proxy_route(
            stream,
            request.content_length.unwrap_or(0),
            buffered_body,
            read_timeout,
            service.config.max_request_bytes(),
        )
        .await
        {
            Ok(body) => body,
            Err(response) => return response.into(),
        };
        return route_claude_proxy_request(session, request, body, &service).await;
    }

    if is_openai_proxy_target(&request.target) {
        let Some(service) = services.openai_proxy else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        let body = match read_http_body_for_openai_proxy_route(
            stream,
            request.content_length.unwrap_or(0),
            buffered_body,
            read_timeout,
            service.config.max_request_bytes(),
        )
        .await
        {
            Ok(body) => body,
            Err(response) => return response.into(),
        };
        return route_openai_proxy_request(session, request, body, &service).await;
    }

    if request.target == VM_GIT_CLONE_PATH {
        let Some(service) = services.git_clone else {
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
        let Some(broker_state) = services
            .git_clone
            .as_ref()
            .map(|service| Arc::clone(&service.broker_state))
        else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        let Some(service) = services.agent_runs else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        if request.method != "POST" {
            return VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed")
                .into();
        }
        let body = match read_http_body_for_agent_run_outcome_route(
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
        return route_agent_run_outcome_request(run_id, &body, &service, &broker_state).into();
    }

    route_session_endpoint(session, request).into()
}

async fn route_nix_cache_request<S: SecretStore>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    service: Option<VmHttpNixCacheService<S>>,
) -> VmHttpDispatch<S> {
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
    };

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

fn vm_http_auth_error_reason(err: VmHttpAuthError) -> &'static str {
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
                headers: Vec::new(),
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
                headers: Vec::new(),
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
                headers: Vec::new(),
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

async fn read_claude_upstream_body_bounded(
    mut response: reqwest::Response,
    max: u64,
) -> Result<Vec<u8>, VmHttpClaudeProxyBodyReadError> {
    let mut body = Vec::new();
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(source) => {
                return Err(VmHttpClaudeProxyBodyReadError::Request {
                    source,
                    bytes_read: body.len() as u64,
                });
            }
        };
        let chunk_len = u64::try_from(chunk.len()).expect("HTTP chunk length fits in u64");
        let new_len = (body.len() as u64)
            .checked_add(chunk_len)
            .expect("HTTP response byte count overflowed before configured bound check");
        if new_len > max {
            return Err(VmHttpClaudeProxyBodyReadError::ResponseTooLarge {
                max,
                bytes_read: new_len,
            });
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

impl VmHttpClaudeProxyBodyReadError {
    fn audit_error_label(&self) -> &'static str {
        match self {
            Self::Request { .. } => "upstream body read failed",
            Self::ResponseTooLarge { .. } => "upstream response too large",
        }
    }

    fn bytes_read(&self) -> u64 {
        match self {
            Self::Request { bytes_read, .. } | Self::ResponseTooLarge { bytes_read, .. } => {
                *bytes_read
            }
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

fn is_claude_proxy_target(target: &str) -> bool {
    classify_claude_proxy_target(target).is_some()
}

fn classify_claude_proxy_target(target: &str) -> Option<ClaudeProxyAuditRoute> {
    // Match on the path only. Anthropic's clients pass through query params
    // such as `?beta=true` that select endpoint variants; the broker's policy
    // is to drop those (similar to the `anthropic-beta` header allowlist) and
    // forward a path-only request upstream.
    let path = claude_proxy_target_path(target);
    match path {
        VM_CLAUDE_MESSAGES_PATH => Some(ClaudeProxyAuditRoute::Messages),
        VM_CLAUDE_COUNT_TOKENS_PATH => Some(ClaudeProxyAuditRoute::CountTokens),
        _ if claude_proxy_model_id(path).is_some() => Some(ClaudeProxyAuditRoute::Models),
        _ if path.starts_with("/v1/messages/")
            || path.starts_with("/v1/messages/count_tokens/")
            || path.starts_with(VM_CLAUDE_MODELS_PREFIX)
            || path == "/v1/models" =>
        {
            Some(ClaudeProxyAuditRoute::Unsupported)
        }
        _ => None,
    }
}

fn claude_proxy_target_path(target: &str) -> &str {
    target
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(target)
}

fn claude_proxy_model_id(path: &str) -> Option<&str> {
    let suffix = path.strip_prefix(VM_CLAUDE_MODELS_PREFIX)?;
    if suffix.is_empty() || !suffix.bytes().all(is_claude_model_id_byte) {
        return None;
    }
    Some(suffix)
}

fn is_claude_model_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

struct ClaudeProxyForwardHeader {
    name: reqwest::header::HeaderName,
    value: reqwest::header::HeaderValue,
}

fn claude_proxy_forward_headers(
    headers: &[VmHttpHeader],
    anthropic_version: &reqwest::header::HeaderValue,
    auth_kind: VmHttpClaudeProxyAuthKind,
) -> Result<Vec<ClaudeProxyForwardHeader>, &'static str> {
    let mut forwarded = Vec::new();
    let mut saw_content_type = false;
    let mut saw_accept = false;
    let mut saw_user_agent = false;
    let mut saw_anthropic_beta = false;
    let anthropic_beta_name = reqwest::header::HeaderName::from_static("anthropic-beta");

    for header in headers {
        let Some(name) = claude_proxy_forward_header_name(&header.name, auth_kind) else {
            continue;
        };
        let duplicate = if name == reqwest::header::CONTENT_TYPE {
            std::mem::replace(&mut saw_content_type, true)
        } else if name == reqwest::header::ACCEPT {
            std::mem::replace(&mut saw_accept, true)
        } else if name == reqwest::header::USER_AGENT {
            std::mem::replace(&mut saw_user_agent, true)
        } else if name == anthropic_beta_name {
            std::mem::replace(&mut saw_anthropic_beta, true)
        } else {
            unreachable!("Claude proxy forward header classifier returned an unknown header")
        };
        if duplicate {
            return Err("duplicate forwarded Claude header");
        }
        let value = reqwest::header::HeaderValue::from_str(&header.value)
            .map_err(|_| "invalid forwarded Claude header value")?;
        forwarded.push(ClaudeProxyForwardHeader { name, value });
    }
    forwarded.push(ClaudeProxyForwardHeader {
        name: reqwest::header::HeaderName::from_static("anthropic-version"),
        value: anthropic_version.clone(),
    });
    Ok(forwarded)
}

fn claude_proxy_forward_header_name(
    raw: &str,
    auth_kind: VmHttpClaudeProxyAuthKind,
) -> Option<reqwest::header::HeaderName> {
    // Allowlist only. The default policy drops anthropic-beta because beta
    // features can opt into capabilities the operator has not authorized
    // (e.g. extended file retention, computer-use tool surfaces), so the
    // broker — not the guest — decides which betas to enable. The OAuth
    // auth path is the exception: it exists to host Claude Code, whose
    // request shape includes betas the CLI emits itself, so the broker
    // forwards anthropic-beta from the guest while still injecting its own
    // oauth-2025-04-20 alongside. Anthropic-Version is added separately
    // by the broker and is never forwarded from the guest.
    if raw.eq_ignore_ascii_case("content-type") {
        return Some(reqwest::header::CONTENT_TYPE);
    }
    if raw.eq_ignore_ascii_case("accept") {
        return Some(reqwest::header::ACCEPT);
    }
    if raw.eq_ignore_ascii_case("user-agent") {
        return Some(reqwest::header::USER_AGENT);
    }
    if auth_kind == VmHttpClaudeProxyAuthKind::OAuth && raw.eq_ignore_ascii_case("anthropic-beta") {
        return Some(reqwest::header::HeaderName::from_static("anthropic-beta"));
    }
    None
}

fn claude_proxy_response_content_type(response: &reqwest::Response) -> &'static str {
    let Some(content_type) = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return "application/json";
    };
    match content_type.split(';').next().map(str::trim) {
        Some(media_type) if media_type.eq_ignore_ascii_case("application/json") => {
            "application/json"
        }
        Some(media_type) if media_type.eq_ignore_ascii_case("application/problem+json") => {
            "application/problem+json"
        }
        Some(media_type) if media_type.eq_ignore_ascii_case("text/event-stream") => {
            "text/event-stream"
        }
        Some(media_type) if media_type.eq_ignore_ascii_case("text/plain") => {
            "text/plain; charset=utf-8"
        }
        Some(media_type) if media_type.eq_ignore_ascii_case("application/octet-stream") => {
            "application/octet-stream"
        }
        _ => "application/json",
    }
}

fn claude_proxy_response_headers(
    headers: &reqwest::header::HeaderMap,
) -> Vec<VmHttpResponseHeader> {
    let mut out = Vec::new();
    for (name, value) in headers {
        let Some(forward_name) = claude_proxy_response_header_name(name.as_str()) else {
            continue;
        };
        let Ok(value) = value.to_str() else {
            continue;
        };
        out.push(VmHttpResponseHeader {
            name: forward_name,
            value: value.to_string(),
        });
    }
    out
}

fn claude_proxy_response_header_name(raw: &str) -> Option<&'static str> {
    if raw.eq_ignore_ascii_case("request-id") {
        return Some("Request-Id");
    }
    if raw.eq_ignore_ascii_case("retry-after") {
        return Some("Retry-After");
    }
    if raw.eq_ignore_ascii_case("anthropic-ratelimit-requests-limit") {
        return Some("Anthropic-Ratelimit-Requests-Limit");
    }
    if raw.eq_ignore_ascii_case("anthropic-ratelimit-requests-remaining") {
        return Some("Anthropic-Ratelimit-Requests-Remaining");
    }
    if raw.eq_ignore_ascii_case("anthropic-ratelimit-requests-reset") {
        return Some("Anthropic-Ratelimit-Requests-Reset");
    }
    if raw.eq_ignore_ascii_case("anthropic-ratelimit-tokens-limit") {
        return Some("Anthropic-Ratelimit-Tokens-Limit");
    }
    if raw.eq_ignore_ascii_case("anthropic-ratelimit-tokens-remaining") {
        return Some("Anthropic-Ratelimit-Tokens-Remaining");
    }
    if raw.eq_ignore_ascii_case("anthropic-ratelimit-tokens-reset") {
        return Some("Anthropic-Ratelimit-Tokens-Reset");
    }
    None
}

fn claude_proxy_request_wants_streaming(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("stream").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

async fn route_claude_proxy_request<S: SecretStore>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    body: Vec<u8>,
    service: &VmHttpClaudeProxyService<S>,
) -> VmHttpDispatch<S> {
    let route = classify_claude_proxy_target(&request.target)
        .expect("caller only routes classified Claude proxy targets");
    if route == ClaudeProxyAuditRoute::Unsupported {
        let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
        return record_claude_proxy_local_response(
            service,
            session,
            request,
            route,
            ClaudeProxyAuditDecision::Deny {
                reason: "unsupported Claude proxy route".into(),
            },
            response,
            None,
        )
        .into();
    }
    if request.method != claude_proxy_route_method(route).as_str() {
        let response = VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed");
        return record_claude_proxy_local_response(
            service,
            session,
            request,
            route,
            ClaudeProxyAuditDecision::Deny {
                reason: "method not allowed".into(),
            },
            response,
            None,
        )
        .into();
    }

    let headers = match claude_proxy_forward_headers(
        &request.headers,
        service.config.anthropic_version(),
        service.config.auth_kind(),
    ) {
        Ok(headers) => headers,
        Err(reason) => {
            let response = VmHttpResponse::text(VmHttpStatus::BadRequest, reason);
            return record_claude_proxy_local_response(
                service,
                session,
                request,
                route,
                ClaudeProxyAuditDecision::Deny {
                    reason: reason.into(),
                },
                response,
                Some(reason),
            )
            .into();
        }
    };

    let request_id = RequestId::new();
    if let Err(err) =
        service
            .broker_state
            .audit
            .record_claude_proxy_request(&ClaudeProxyRequestRecord {
                request_id,
                session_id: session.session_id,
                received_at: UnixMillis::now(),
                method: &request.method,
                target: &request.target,
                route,
                decision: &ClaudeProxyAuditDecision::Allow,
            })
    {
        eprintln!("VM HTTP Claude proxy audit request write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed")
            .into();
    }

    if claude_proxy_request_wants_streaming(&body) {
        match service
            .fetch_stream(request_id, request, body, headers)
            .await
        {
            Ok(stream) => return VmHttpDispatch::ClaudeProxyStream(stream),
            Err(fetch) => {
                if let Err(err) = service.broker_state.audit.record_claude_proxy_outcome(
                    &ClaudeProxyOutcomeRecord {
                        request_id,
                        completed_at: UnixMillis::now(),
                        http_status: fetch.response.status.code(),
                        upstream_url: fetch.upstream_url.as_deref(),
                        upstream_status: fetch.upstream_status,
                        response_bytes: fetch.response_bytes,
                        error: fetch.error,
                    },
                ) {
                    eprintln!("VM HTTP Claude proxy audit outcome write failed: {err}");
                    return VmHttpResponse::text(
                        VmHttpStatus::InternalServerError,
                        "audit write failed",
                    )
                    .into();
                }
                return fetch.response.into();
            }
        }
    }

    let fetch = service.fetch(request, body, headers).await;
    if let Err(err) =
        service
            .broker_state
            .audit
            .record_claude_proxy_outcome(&ClaudeProxyOutcomeRecord {
                request_id,
                completed_at: UnixMillis::now(),
                http_status: fetch.response.status.code(),
                upstream_url: fetch.upstream_url.as_deref(),
                upstream_status: fetch.upstream_status,
                response_bytes: fetch.response_bytes,
                error: fetch.error,
            })
    {
        eprintln!("VM HTTP Claude proxy audit outcome write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed")
            .into();
    }
    fetch.response.into()
}

fn record_claude_proxy_local_response<S: SecretStore>(
    service: &VmHttpClaudeProxyService<S>,
    session: &VmHttpSession,
    request: &VmHttpRequest,
    route: ClaudeProxyAuditRoute,
    decision: ClaudeProxyAuditDecision,
    response: VmHttpResponse,
    error: Option<&'static str>,
) -> VmHttpResponse {
    let request_id = RequestId::new();
    if let Err(err) =
        service
            .broker_state
            .audit
            .record_claude_proxy_request(&ClaudeProxyRequestRecord {
                request_id,
                session_id: session.session_id,
                received_at: UnixMillis::now(),
                method: &request.method,
                target: &request.target,
                route,
                decision: &decision,
            })
    {
        eprintln!("VM HTTP Claude proxy audit request write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed");
    }
    if let Err(err) =
        service
            .broker_state
            .audit
            .record_claude_proxy_outcome(&ClaudeProxyOutcomeRecord {
                request_id,
                completed_at: UnixMillis::now(),
                http_status: response.status.code(),
                upstream_url: None,
                upstream_status: None,
                response_bytes: response.body.len() as u64,
                error,
            })
    {
        eprintln!("VM HTTP Claude proxy audit outcome write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed");
    }
    response
}

async fn read_openai_upstream_body_bounded(
    mut response: reqwest::Response,
    max: u64,
) -> Result<Vec<u8>, VmHttpOpenAiProxyBodyReadError> {
    let mut body = Vec::new();
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(source) => {
                return Err(VmHttpOpenAiProxyBodyReadError::Request {
                    source,
                    bytes_read: body.len() as u64,
                });
            }
        };
        let chunk_len = u64::try_from(chunk.len()).expect("HTTP chunk length fits in u64");
        let new_len = (body.len() as u64)
            .checked_add(chunk_len)
            .expect("HTTP response byte count overflowed before configured bound check");
        if new_len > max {
            return Err(VmHttpOpenAiProxyBodyReadError::ResponseTooLarge {
                max,
                bytes_read: new_len,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl VmHttpOpenAiProxyBodyReadError {
    fn audit_error_label(&self) -> &'static str {
        match self {
            Self::Request { .. } => "upstream body read failed",
            Self::ResponseTooLarge { .. } => "upstream response too large",
        }
    }

    fn bytes_read(&self) -> u64 {
        match self {
            Self::Request { bytes_read, .. } | Self::ResponseTooLarge { bytes_read, .. } => {
                *bytes_read
            }
        }
    }
}

fn is_openai_proxy_target(target: &str) -> bool {
    classify_openai_proxy_target(target).is_some()
}

fn classify_openai_proxy_target(target: &str) -> Option<OpenAiProxyAuditRoute> {
    // Match on the path only. The OpenAI clients pass through query params
    // such as `?include[]=...` on Responses; the broker drops them and
    // forwards a path-only request upstream so the guest can't expand the
    // surface area beyond what the broker has explicitly classified.
    let path = openai_proxy_target_path(target);
    if path == VM_OPENAI_RESPONSES_PATH {
        return Some(OpenAiProxyAuditRoute::Responses);
    }
    if path == VM_OPENAI_MODELS_PATH {
        return Some(OpenAiProxyAuditRoute::Models);
    }
    if openai_proxy_response_cancel_id(path).is_some() {
        return Some(OpenAiProxyAuditRoute::ResponseCancel);
    }
    if openai_proxy_model_id(path).is_some() {
        return Some(OpenAiProxyAuditRoute::Models);
    }
    if path.starts_with(VM_OPENAI_RESPONSES_PREFIX) || path.starts_with(VM_OPENAI_MODELS_PREFIX) {
        return Some(OpenAiProxyAuditRoute::Unsupported);
    }
    None
}

fn openai_proxy_target_path(target: &str) -> &str {
    target
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(target)
}

fn openai_proxy_model_id(path: &str) -> Option<&str> {
    let suffix = path.strip_prefix(VM_OPENAI_MODELS_PREFIX)?;
    if suffix.is_empty() || !suffix.bytes().all(is_openai_id_byte) {
        return None;
    }
    Some(suffix)
}

fn openai_proxy_response_cancel_id(path: &str) -> Option<&str> {
    let suffix = path.strip_prefix(VM_OPENAI_RESPONSES_PREFIX)?;
    let id = suffix.strip_suffix(VM_OPENAI_RESPONSE_CANCEL_SUFFIX)?;
    if id.is_empty() || !id.bytes().all(is_openai_id_byte) {
        return None;
    }
    Some(id)
}

fn is_openai_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

struct OpenAiProxyForwardHeader {
    name: reqwest::header::HeaderName,
    value: reqwest::header::HeaderValue,
}

fn openai_proxy_forward_headers(
    headers: &[VmHttpHeader],
    auth_kind: VmHttpOpenAiProxyAuthKind,
) -> Result<Vec<OpenAiProxyForwardHeader>, &'static str> {
    let mut forwarded = Vec::new();
    let mut saw_content_type = false;
    let mut saw_accept = false;
    let mut saw_user_agent = false;

    for header in headers {
        let Some(name) = openai_proxy_forward_header_name(&header.name, auth_kind) else {
            continue;
        };
        let duplicate = if name == reqwest::header::CONTENT_TYPE {
            std::mem::replace(&mut saw_content_type, true)
        } else if name == reqwest::header::ACCEPT {
            std::mem::replace(&mut saw_accept, true)
        } else if name == reqwest::header::USER_AGENT {
            std::mem::replace(&mut saw_user_agent, true)
        } else {
            unreachable!("OpenAI proxy forward header classifier returned an unknown header")
        };
        if duplicate {
            return Err("duplicate forwarded OpenAI header");
        }
        let value = reqwest::header::HeaderValue::from_str(&header.value)
            .map_err(|_| "invalid forwarded OpenAI header value")?;
        forwarded.push(OpenAiProxyForwardHeader { name, value });
    }
    Ok(forwarded)
}

fn openai_proxy_forward_header_name(
    raw: &str,
    _auth_kind: VmHttpOpenAiProxyAuthKind,
) -> Option<reqwest::header::HeaderName> {
    // Allowlist only. Anything that influences upstream auth, billing scope,
    // or feature flags is dropped: `Authorization` is injected by the broker,
    // and `OpenAI-Organization`/`OpenAI-Project` are dropped because a host
    // secret with multi-org/-project access would otherwise let the guest
    // pick the upstream scope. If the broker ever needs to pin one, it must
    // come from host config and be injected host-side.
    if raw.eq_ignore_ascii_case("content-type") {
        return Some(reqwest::header::CONTENT_TYPE);
    }
    if raw.eq_ignore_ascii_case("accept") {
        return Some(reqwest::header::ACCEPT);
    }
    if raw.eq_ignore_ascii_case("user-agent") {
        return Some(reqwest::header::USER_AGENT);
    }
    None
}

fn openai_proxy_response_content_type(response: &reqwest::Response) -> &'static str {
    let Some(content_type) = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return "application/json";
    };
    match content_type.split(';').next().map(str::trim) {
        Some(media_type) if media_type.eq_ignore_ascii_case("application/json") => {
            "application/json"
        }
        Some(media_type) if media_type.eq_ignore_ascii_case("application/problem+json") => {
            "application/problem+json"
        }
        Some(media_type) if media_type.eq_ignore_ascii_case("text/event-stream") => {
            "text/event-stream"
        }
        Some(media_type) if media_type.eq_ignore_ascii_case("text/plain") => {
            "text/plain; charset=utf-8"
        }
        Some(media_type) if media_type.eq_ignore_ascii_case("application/octet-stream") => {
            "application/octet-stream"
        }
        _ => "application/json",
    }
}

fn openai_proxy_response_headers(
    headers: &reqwest::header::HeaderMap,
) -> Vec<VmHttpResponseHeader> {
    let mut out = Vec::new();
    for (name, value) in headers {
        let Some(forward_name) = openai_proxy_response_header_name(name.as_str()) else {
            continue;
        };
        let Ok(value) = value.to_str() else {
            continue;
        };
        out.push(VmHttpResponseHeader {
            name: forward_name,
            value: value.to_string(),
        });
    }
    out
}

fn openai_proxy_response_header_name(raw: &str) -> Option<&'static str> {
    if raw.eq_ignore_ascii_case("openai-version") {
        return Some("Openai-Version");
    }
    if raw.eq_ignore_ascii_case("openai-organization") {
        return Some("Openai-Organization");
    }
    if raw.eq_ignore_ascii_case("openai-processing-ms") {
        return Some("Openai-Processing-Ms");
    }
    if raw.eq_ignore_ascii_case("x-request-id") {
        return Some("X-Request-Id");
    }
    if raw.eq_ignore_ascii_case("retry-after") {
        return Some("Retry-After");
    }
    if raw.eq_ignore_ascii_case("x-ratelimit-limit-requests") {
        return Some("X-Ratelimit-Limit-Requests");
    }
    if raw.eq_ignore_ascii_case("x-ratelimit-limit-tokens") {
        return Some("X-Ratelimit-Limit-Tokens");
    }
    if raw.eq_ignore_ascii_case("x-ratelimit-remaining-requests") {
        return Some("X-Ratelimit-Remaining-Requests");
    }
    if raw.eq_ignore_ascii_case("x-ratelimit-remaining-tokens") {
        return Some("X-Ratelimit-Remaining-Tokens");
    }
    if raw.eq_ignore_ascii_case("x-ratelimit-reset-requests") {
        return Some("X-Ratelimit-Reset-Requests");
    }
    if raw.eq_ignore_ascii_case("x-ratelimit-reset-tokens") {
        return Some("X-Ratelimit-Reset-Tokens");
    }
    None
}

fn openai_proxy_request_wants_streaming(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("stream").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

async fn route_openai_proxy_request<S: SecretStore>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    body: Vec<u8>,
    service: &VmHttpOpenAiProxyService<S>,
) -> VmHttpDispatch<S> {
    let route = classify_openai_proxy_target(&request.target)
        .expect("caller only routes classified OpenAI proxy targets");
    if route == OpenAiProxyAuditRoute::Unsupported {
        let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
        return record_openai_proxy_local_response(
            service,
            session,
            request,
            route,
            OpenAiProxyAuditDecision::Deny {
                reason: "unsupported OpenAI proxy route".into(),
            },
            response,
            None,
        )
        .into();
    }
    if request.method != openai_proxy_route_method(route).as_str() {
        let response = VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed");
        return record_openai_proxy_local_response(
            service,
            session,
            request,
            route,
            OpenAiProxyAuditDecision::Deny {
                reason: "method not allowed".into(),
            },
            response,
            None,
        )
        .into();
    }

    let headers = match openai_proxy_forward_headers(&request.headers, service.config.auth_kind()) {
        Ok(headers) => headers,
        Err(reason) => {
            let response = VmHttpResponse::text(VmHttpStatus::BadRequest, reason);
            return record_openai_proxy_local_response(
                service,
                session,
                request,
                route,
                OpenAiProxyAuditDecision::Deny {
                    reason: reason.into(),
                },
                response,
                Some(reason),
            )
            .into();
        }
    };

    let request_id = RequestId::new();
    if let Err(err) =
        service
            .broker_state
            .audit
            .record_openai_proxy_request(&OpenAiProxyRequestRecord {
                request_id,
                session_id: session.session_id,
                received_at: UnixMillis::now(),
                method: &request.method,
                target: &request.target,
                route,
                decision: &OpenAiProxyAuditDecision::Allow,
            })
    {
        eprintln!("VM HTTP OpenAI proxy audit request write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed")
            .into();
    }

    if openai_proxy_request_wants_streaming(&body) {
        match service
            .fetch_stream(request_id, request, body, headers)
            .await
        {
            Ok(stream) => return VmHttpDispatch::OpenAiProxyStream(stream),
            Err(fetch) => {
                if let Err(err) = service.broker_state.audit.record_openai_proxy_outcome(
                    &OpenAiProxyOutcomeRecord {
                        request_id,
                        completed_at: UnixMillis::now(),
                        http_status: fetch.response.status.code(),
                        upstream_url: fetch.upstream_url.as_deref(),
                        upstream_status: fetch.upstream_status,
                        response_bytes: fetch.response_bytes,
                        error: fetch.error,
                    },
                ) {
                    eprintln!("VM HTTP OpenAI proxy audit outcome write failed: {err}");
                    return VmHttpResponse::text(
                        VmHttpStatus::InternalServerError,
                        "audit write failed",
                    )
                    .into();
                }
                return fetch.response.into();
            }
        }
    }

    let fetch = service.fetch(request, body, headers).await;
    if let Err(err) =
        service
            .broker_state
            .audit
            .record_openai_proxy_outcome(&OpenAiProxyOutcomeRecord {
                request_id,
                completed_at: UnixMillis::now(),
                http_status: fetch.response.status.code(),
                upstream_url: fetch.upstream_url.as_deref(),
                upstream_status: fetch.upstream_status,
                response_bytes: fetch.response_bytes,
                error: fetch.error,
            })
    {
        eprintln!("VM HTTP OpenAI proxy audit outcome write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed")
            .into();
    }
    fetch.response.into()
}

fn record_openai_proxy_local_response<S: SecretStore>(
    service: &VmHttpOpenAiProxyService<S>,
    session: &VmHttpSession,
    request: &VmHttpRequest,
    route: OpenAiProxyAuditRoute,
    decision: OpenAiProxyAuditDecision,
    response: VmHttpResponse,
    error: Option<&'static str>,
) -> VmHttpResponse {
    let request_id = RequestId::new();
    if let Err(err) =
        service
            .broker_state
            .audit
            .record_openai_proxy_request(&OpenAiProxyRequestRecord {
                request_id,
                session_id: session.session_id,
                received_at: UnixMillis::now(),
                method: &request.method,
                target: &request.target,
                route,
                decision: &decision,
            })
    {
        eprintln!("VM HTTP OpenAI proxy audit request write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed");
    }
    if let Err(err) =
        service
            .broker_state
            .audit
            .record_openai_proxy_outcome(&OpenAiProxyOutcomeRecord {
                request_id,
                completed_at: UnixMillis::now(),
                http_status: response.status.code(),
                upstream_url: None,
                upstream_status: None,
                response_bytes: response.body.len() as u64,
                error,
            })
    {
        eprintln!("VM HTTP OpenAI proxy audit outcome write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed");
    }
    response
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

fn parse_agent_run_config_target(target: &str) -> Option<AgentRunId> {
    let suffix = target
        .strip_prefix(VM_AGENT_RUN_PATH_PREFIX)?
        .strip_prefix('/')?;
    let raw_id = suffix.strip_suffix("/config")?;
    if raw_id.contains('/') {
        return None;
    }
    raw_id.parse().ok()
}

fn parse_agent_run_outcome_target(target: &str) -> Option<AgentRunId> {
    let suffix = target
        .strip_prefix(VM_AGENT_RUN_PATH_PREFIX)?
        .strip_prefix('/')?;
    let raw_id = suffix.strip_suffix(&format!("/{VM_AGENT_RUN_OUTCOME_PATH_SUFFIX}"))?;
    if raw_id.contains('/') {
        return None;
    }
    raw_id.parse().ok()
}

fn route_agent_run_config_request(
    run_id: AgentRunId,
    service: &VmHttpAgentRunService,
) -> VmHttpResponse {
    let Some(inflight) = service.take_run_config(run_id) else {
        return VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
    };
    VmHttpResponse::json(
        VmHttpStatus::Ok,
        &VmAgentRunConfigResponse::new(run_id, inflight.prompt, inflight.model),
    )
}

fn route_agent_run_outcome_request(
    run_id: AgentRunId,
    body: &[u8],
    service: &VmHttpAgentRunService,
    broker_state: &BrokerState<impl SecretStore>,
) -> VmHttpResponse {
    match broker_state.audit.get_agent_run_outcome(run_id) {
        Ok(Some(_)) => return VmHttpResponse::text(VmHttpStatus::Ok, "ok"),
        Ok(None) => {}
        Err(err) => {
            eprintln!("VM HTTP agent run outcome audit lookup failed: {err}");
            return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit read failed");
        }
    }
    let upload = match serde_json::from_slice::<VmAgentRunOutcomeUpload>(body) {
        Ok(upload) => upload,
        Err(_) => return VmHttpResponse::text(VmHttpStatus::BadRequest, "invalid outcome JSON"),
    };
    if upload.run_id != run_id {
        return VmHttpResponse::text(VmHttpStatus::BadRequest, "outcome run ID mismatch");
    }

    let outcome = match materialize_agent_run_outcome_upload(upload, service.log_root()) {
        Ok(outcome) => outcome,
        Err(response) => return response,
    };
    if let Err(err) = broker_state
        .audit
        .record_agent_run_outcome(&AgentRunOutcomeAuditRecord {
            completed_at: UnixMillis::now(),
            outcome,
        })
    {
        eprintln!("VM HTTP agent run outcome audit write failed: {err}");
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed");
    }
    VmHttpResponse::text(VmHttpStatus::Ok, "ok")
}

fn materialize_agent_run_outcome_upload(
    upload: VmAgentRunOutcomeUpload,
    log_root: &Path,
) -> Result<AgentRunOutcome, VmHttpResponse> {
    if !log_root.is_absolute() {
        return Err(VmHttpResponse::text(
            VmHttpStatus::InternalServerError,
            "agent run log root is invalid",
        ));
    }
    let run_dir = log_root.join(upload.run_id.to_string());
    create_private_dir(&run_dir).map_err(|err| {
        eprintln!("VM HTTP agent run outcome log directory write failed: {err}");
        VmHttpResponse::text(
            VmHttpStatus::InternalServerError,
            "agent run log write failed",
        )
    })?;
    let stdout_path = run_dir.join("stdout.log");
    let stderr_path = run_dir.join("stderr.log");
    let stdout = materialize_agent_run_stream(upload.stdout, &stdout_path)?;
    let stderr = materialize_agent_run_stream(upload.stderr, &stderr_path)?;
    Ok(AgentRunOutcome {
        run_id: upload.run_id,
        status: upload.status,
        exit_code: upload.exit_code,
        stdout,
        stderr,
    })
}

fn materialize_agent_run_stream(
    upload: AgentRunStreamUpload,
    path: &Path,
) -> Result<AgentRunStreamSummary, VmHttpResponse> {
    let retained = decode_base64_standard(&upload.retained_base64).map_err(|_| {
        VmHttpResponse::text(VmHttpStatus::BadRequest, "invalid outcome stream base64")
    })?;
    let retained_len = retained.len() as u64;
    if upload.byte_len > MAX_AGENT_RUN_STREAM_AUDIT_BYTES {
        return Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "outcome stream byte count exceeds audit limit",
        ));
    }
    if !is_sha256_hex(&upload.sha256_hex) || !is_sha256_hex(&upload.retained_sha256_hex) {
        return Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "invalid outcome stream hash",
        ));
    }
    if crate::agent_run::sha256_hex(&retained) != upload.retained_sha256_hex {
        return Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "outcome stream retained hash mismatch",
        ));
    }
    if retained_len > upload.byte_len {
        return Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "outcome stream retained bytes exceed total byte count",
        ));
    }
    if upload.truncated {
        if retained_len >= upload.byte_len {
            return Err(VmHttpResponse::text(
                VmHttpStatus::BadRequest,
                "truncated outcome stream must have uncaptured bytes",
            ));
        }
    } else if retained_len != upload.byte_len {
        return Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "untruncated outcome stream retained bytes must match total byte count",
        ));
    } else if crate::agent_run::sha256_hex(&retained) != upload.sha256_hex {
        return Err(VmHttpResponse::text(
            VmHttpStatus::BadRequest,
            "untruncated outcome stream hash mismatch",
        ));
    }

    let (audited_byte_len, audited_sha256_hex) = if upload.truncated {
        (retained_len, upload.retained_sha256_hex)
    } else {
        (upload.byte_len, upload.sha256_hex)
    };

    write_private_file(path, &retained).map_err(|err| {
        eprintln!("VM HTTP agent run outcome stream write failed: {err}");
        VmHttpResponse::text(
            VmHttpStatus::InternalServerError,
            "agent run log write failed",
        )
    })?;
    Ok(AgentRunStreamSummary {
        path: path.to_path_buf(),
        byte_len: audited_byte_len,
        sha256_hex: audited_sha256_hex,
        truncated: upload.truncated,
    })
}

fn is_sha256_hex(raw: &str) -> bool {
    // Lowercase-only: agent_run::sha256_hex emits lowercase, and the
    // downstream byte-string comparison is case-sensitive. Accepting
    // uppercase here would only let it fail later with a misleading hash
    // mismatch error.
    raw.len() == 64
        && raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

fn write_private_file(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read(path)?;
            if existing == body {
                return Ok(());
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists with different contents", path.display()),
            ));
        }
        Err(err) => return Err(err),
    };
    use std::io::Write as _;
    file.write_all(body)?;
    file.sync_all()
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

async fn read_http_body_for_claude_proxy_route<R: AsyncRead + Unpin>(
    stream: &mut R,
    content_length: usize,
    buffered_body: Vec<u8>,
    read_timeout: std::time::Duration,
    max: usize,
) -> Result<Vec<u8>, VmHttpResponse> {
    read_http_body_for_route(stream, content_length, buffered_body, read_timeout, max).await
}

async fn read_http_body_for_openai_proxy_route<R: AsyncRead + Unpin>(
    stream: &mut R,
    content_length: usize,
    buffered_body: Vec<u8>,
    read_timeout: std::time::Duration,
    max: usize,
) -> Result<Vec<u8>, VmHttpResponse> {
    read_http_body_for_route(stream, content_length, buffered_body, read_timeout, max).await
}

async fn read_http_body_for_agent_run_outcome_route<R: AsyncRead + Unpin>(
    stream: &mut R,
    content_length: usize,
    buffered_body: Vec<u8>,
    read_timeout: std::time::Duration,
) -> Result<Vec<u8>, VmHttpResponse> {
    read_http_body_for_route(
        stream,
        content_length,
        buffered_body,
        read_timeout,
        MAX_VM_HTTP_AGENT_RUN_OUTCOME_BODY_BYTES,
    )
    .await
}

async fn read_http_body_for_route<R: AsyncRead + Unpin>(
    stream: &mut R,
    content_length: usize,
    buffered_body: Vec<u8>,
    read_timeout: std::time::Duration,
    max: usize,
) -> Result<Vec<u8>, VmHttpResponse> {
    match tokio::time::timeout(
        read_timeout,
        read_http_body_bounded(stream, content_length, buffered_body, max),
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
            headers: Vec::new(),
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
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(VmHttpParseError::MalformedHeader);
        };
        let value = value.trim().to_string();
        headers.push(VmHttpHeader {
            name: name.to_string(),
            value: value.clone(),
        });
        if name.eq_ignore_ascii_case("authorization") {
            if authorization.is_some() {
                return Err(VmHttpParseError::DuplicateAuthorization);
            }
            authorization = Some(value.clone());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(VmHttpParseError::DuplicateContentLength);
            }
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
        headers,
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
        for header in &self.headers {
            out.extend_from_slice(format!("{}: {}\r\n", header.name, header.value).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

async fn write_http_response_head<W: AsyncWrite + Unpin>(
    out: &mut W,
    status: VmHttpStatus,
    content_type: &'static str,
    content_length: Option<u64>,
    www_authenticate: Option<&'static str>,
    headers: &[VmHttpResponseHeader],
) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nConnection: close\r\n",
        status.status_line(),
        content_type,
    );
    if let Some(content_length) = content_length {
        head.push_str(&format!("Content-Length: {content_length}\r\n"));
    }
    if let Some(challenge) = www_authenticate {
        head.push_str(&format!("WWW-Authenticate: {challenge}\r\n"));
    }
    for header in headers {
        head.push_str(&format!("{}: {}\r\n", header.name, header.value));
    }
    head.push_str("\r\n");
    out.write_all(head.as_bytes()).await
}

impl<S: SecretStore> From<VmHttpResponse> for VmHttpDispatch<S> {
    fn from(response: VmHttpResponse) -> Self {
        Self::Buffered(response)
    }
}

impl<S: SecretStore> VmHttpDispatch<S> {
    async fn write_to<W: AsyncWrite + Unpin>(self, out: &mut W) -> std::io::Result<()> {
        match self {
            Self::Buffered(response) => out.write_all(&response.to_bytes()).await,
            Self::ClaudeProxyStream(response) => response.write_to(out).await,
            Self::OpenAiProxyStream(response) => response.write_to(out).await,
        }
    }

    fn status_code(&self) -> u16 {
        match self {
            Self::Buffered(response) => response.status.code(),
            Self::ClaudeProxyStream(response) => response.upstream_status,
            Self::OpenAiProxyStream(response) => response.upstream_status,
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
    fn status_line(self) -> Cow<'static, str> {
        match self {
            Self::Ok => "200 OK".into(),
            Self::BadRequest => "400 Bad Request".into(),
            Self::Unauthorized => "401 Unauthorized".into(),
            Self::Forbidden => "403 Forbidden".into(),
            Self::NotFound => "404 Not Found".into(),
            Self::MethodNotAllowed => "405 Method Not Allowed".into(),
            Self::Gone => "410 Gone".into(),
            Self::BadGateway => "502 Bad Gateway".into(),
            Self::InternalServerError => "500 Internal Server Error".into(),
            Self::Upstream(200) => "200 OK".into(),
            Self::Upstream(400) => "400 Bad Request".into(),
            Self::Upstream(401) => "401 Unauthorized".into(),
            Self::Upstream(403) => "403 Forbidden".into(),
            Self::Upstream(404) => "404 Not Found".into(),
            Self::Upstream(429) => "429 Too Many Requests".into(),
            Self::Upstream(500) => "500 Internal Server Error".into(),
            Self::Upstream(529) => "529 Overloaded".into(),
            Self::Upstream(code) => format!("{code} Upstream").into(),
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
            Self::Upstream(code) => code,
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

fn decode_base64_standard(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(input)
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

    type TestVmHttpServices = VmHttpServices<Box<dyn SecretStore>>;

    fn no_services() -> TestVmHttpServices {
        VmHttpServices::none()
    }

    fn services_with_git(
        git_clone: VmHttpGitCloneService<Box<dyn SecretStore>>,
    ) -> TestVmHttpServices {
        VmHttpServices {
            git_clone: Some(git_clone),
            nix_cache: None,
            claude_proxy: None,
            openai_proxy: None,
            agent_runs: None,
        }
    }

    fn services_with_nix_cache(
        nix_cache: VmHttpNixCacheService<Box<dyn SecretStore>>,
    ) -> TestVmHttpServices {
        VmHttpServices {
            git_clone: None,
            nix_cache: Some(nix_cache),
            claude_proxy: None,
            openai_proxy: None,
            agent_runs: None,
        }
    }

    fn services_with_claude_proxy(
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

    fn services_with_openai_proxy(
        openai_proxy: VmHttpOpenAiProxyService<Box<dyn SecretStore>>,
    ) -> TestVmHttpServices {
        VmHttpServices {
            git_clone: None,
            nix_cache: None,
            claude_proxy: None,
            openai_proxy: Some(openai_proxy),
            agent_runs: None,
        }
    }
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
        make_broker_state_with_extra_secret(server, None)
    }

    fn make_broker_state_with_extra_secret(
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
                agent_kind: None,
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

    async fn serve_raw_http_once(response: String) -> (String, Arc<Mutex<String>>) {
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

    fn raw_http_response(status: &str, content_type: &str, body: &[u8]) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        )
    }

    fn raw_http_response_with_headers(
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

    #[test]
    fn classify_claude_proxy_target_recognizes_supported_routes() {
        assert_eq!(
            classify_claude_proxy_target("/v1/messages"),
            Some(ClaudeProxyAuditRoute::Messages),
        );
        assert_eq!(
            classify_claude_proxy_target("/v1/messages/count_tokens"),
            Some(ClaudeProxyAuditRoute::CountTokens),
        );
        assert_eq!(
            classify_claude_proxy_target("/v1/models/claude-haiku-4-5-20251001"),
            Some(ClaudeProxyAuditRoute::Models),
        );
    }

    #[test]
    fn classify_claude_proxy_target_treats_models_listing_and_empty_id_as_unsupported() {
        assert_eq!(
            classify_claude_proxy_target("/v1/models"),
            Some(ClaudeProxyAuditRoute::Unsupported),
        );
        assert_eq!(
            classify_claude_proxy_target("/v1/models/"),
            Some(ClaudeProxyAuditRoute::Unsupported),
        );
        assert_eq!(
            classify_claude_proxy_target("/v1/models/foo/bar"),
            Some(ClaudeProxyAuditRoute::Unsupported),
        );
    }

    #[test]
    fn classify_claude_proxy_target_rejects_unrelated_paths() {
        assert_eq!(classify_claude_proxy_target("/v2/models/foo"), None);
        assert_eq!(classify_claude_proxy_target("/health"), None);
        assert_eq!(classify_claude_proxy_target(""), None);
    }

    #[test]
    fn classify_claude_proxy_target_strips_query_string() {
        assert_eq!(
            classify_claude_proxy_target("/v1/messages?beta=true"),
            Some(ClaudeProxyAuditRoute::Messages),
        );
        assert_eq!(
            classify_claude_proxy_target("/v1/messages/count_tokens?beta=true"),
            Some(ClaudeProxyAuditRoute::CountTokens),
        );
        assert_eq!(
            classify_claude_proxy_target("/v1/models/claude-haiku-4-5-20251001?beta=true"),
            Some(ClaudeProxyAuditRoute::Models),
        );
    }

    #[test]
    fn classify_openai_proxy_target_recognizes_supported_routes() {
        assert_eq!(
            classify_openai_proxy_target("/v1/responses"),
            Some(OpenAiProxyAuditRoute::Responses),
        );
        assert_eq!(
            classify_openai_proxy_target("/v1/responses/resp_abc123/cancel"),
            Some(OpenAiProxyAuditRoute::ResponseCancel),
        );
        assert_eq!(
            classify_openai_proxy_target("/v1/models"),
            Some(OpenAiProxyAuditRoute::Models),
        );
        assert_eq!(
            classify_openai_proxy_target("/v1/models/gpt-5"),
            Some(OpenAiProxyAuditRoute::Models),
        );
    }

    #[test]
    fn classify_openai_proxy_target_treats_unsupported_subpaths_as_unsupported() {
        assert_eq!(
            classify_openai_proxy_target("/v1/responses/resp_abc123"),
            Some(OpenAiProxyAuditRoute::Unsupported),
        );
        assert_eq!(
            classify_openai_proxy_target("/v1/responses/"),
            Some(OpenAiProxyAuditRoute::Unsupported),
        );
        assert_eq!(
            classify_openai_proxy_target("/v1/responses/resp_abc/cancel/extra"),
            Some(OpenAiProxyAuditRoute::Unsupported),
        );
        assert_eq!(
            classify_openai_proxy_target("/v1/models/"),
            Some(OpenAiProxyAuditRoute::Unsupported),
        );
        assert_eq!(
            classify_openai_proxy_target("/v1/models/foo/bar"),
            Some(OpenAiProxyAuditRoute::Unsupported),
        );
    }

    #[test]
    fn classify_openai_proxy_target_rejects_unrelated_paths() {
        assert_eq!(classify_openai_proxy_target("/v1/chat/completions"), None);
        assert_eq!(classify_openai_proxy_target("/v2/responses"), None);
        assert_eq!(classify_openai_proxy_target("/health"), None);
        assert_eq!(classify_openai_proxy_target(""), None);
    }

    #[test]
    fn classify_openai_proxy_target_strips_query_string() {
        assert_eq!(
            classify_openai_proxy_target("/v1/responses?include%5B%5D=foo"),
            Some(OpenAiProxyAuditRoute::Responses),
        );
        assert_eq!(
            classify_openai_proxy_target("/v1/responses/resp_abc/cancel?x=1"),
            Some(OpenAiProxyAuditRoute::ResponseCancel),
        );
        assert_eq!(
            classify_openai_proxy_target("/v1/models?x=1"),
            Some(OpenAiProxyAuditRoute::Models),
        );
        assert_eq!(
            classify_openai_proxy_target("/v1/models/gpt-5?x=1"),
            Some(OpenAiProxyAuditRoute::Models),
        );
    }

    #[test]
    fn openai_proxy_forward_headers_drops_authorization_and_unrelated_headers() {
        let headers = vec![
            VmHttpHeader {
                name: "Authorization".into(),
                value: "Bearer guest-token".into(),
            },
            VmHttpHeader {
                name: "Cookie".into(),
                value: "session=guest".into(),
            },
            VmHttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            },
            VmHttpHeader {
                name: "Accept".into(),
                value: "text/event-stream".into(),
            },
            VmHttpHeader {
                name: "User-Agent".into(),
                value: "codex-cli/1.0".into(),
            },
            VmHttpHeader {
                name: "OpenAI-Organization".into(),
                value: "org_test".into(),
            },
            VmHttpHeader {
                name: "OpenAI-Project".into(),
                value: "proj_test".into(),
            },
        ];

        let forwarded =
            openai_proxy_forward_headers(&headers, VmHttpOpenAiProxyAuthKind::AuthorizationBearer)
                .unwrap();
        let names: Vec<_> = forwarded
            .iter()
            .map(|h| h.name.as_str().to_owned())
            .collect();
        assert!(names.iter().any(|n| n == "content-type"));
        assert!(names.iter().any(|n| n == "accept"));
        assert!(names.iter().any(|n| n == "user-agent"));
        assert!(!names.iter().any(|n| n == "openai-organization"));
        assert!(!names.iter().any(|n| n == "openai-project"));
        assert!(!names.iter().any(|n| n == "authorization"));
        assert!(!names.iter().any(|n| n == "cookie"));
    }

    #[test]
    fn openai_proxy_forward_headers_drops_guest_org_and_project_for_all_auth_kinds() {
        // Threat: the host secret may have access to multiple OpenAI
        // organizations or projects. If we forwarded guest-supplied
        // `OpenAI-Organization`/`OpenAI-Project` headers we'd let the guest
        // pick the upstream auth/billing scope. These must be dropped — like
        // `Authorization` — and any host-side scoping has to be injected by
        // the broker, never trusted from the guest.
        let headers = vec![
            VmHttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            },
            VmHttpHeader {
                name: "OpenAI-Organization".into(),
                value: "org-attacker".into(),
            },
            VmHttpHeader {
                name: "OpenAI-Project".into(),
                value: "proj-attacker".into(),
            },
        ];
        for auth_kind in [
            VmHttpOpenAiProxyAuthKind::AuthorizationBearer,
            VmHttpOpenAiProxyAuthKind::ChatgptOauth,
        ] {
            let forwarded = openai_proxy_forward_headers(&headers, auth_kind).unwrap();
            let names: Vec<_> = forwarded
                .iter()
                .map(|h| h.name.as_str().to_owned())
                .collect();
            assert!(
                !names
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case("openai-organization")),
                "{auth_kind:?}: guest-supplied OpenAI-Organization must not be forwarded",
            );
            assert!(
                !names
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case("openai-project")),
                "{auth_kind:?}: guest-supplied OpenAI-Project must not be forwarded",
            );
            assert!(
                names.iter().any(|n| n.eq_ignore_ascii_case("content-type")),
                "{auth_kind:?}: Content-Type should still pass through",
            );
        }
    }

    #[test]
    fn openai_proxy_forward_headers_rejects_duplicate_allowed_header() {
        let headers = vec![
            VmHttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            },
            VmHttpHeader {
                name: "content-type".into(),
                value: "application/json".into(),
            },
        ];
        let result =
            openai_proxy_forward_headers(&headers, VmHttpOpenAiProxyAuthKind::AuthorizationBearer);
        assert!(result.is_err());
    }

    #[test]
    fn openai_proxy_response_header_name_allowlists_observability_headers() {
        assert_eq!(
            openai_proxy_response_header_name("X-Request-Id"),
            Some("X-Request-Id"),
        );
        assert_eq!(
            openai_proxy_response_header_name("retry-after"),
            Some("Retry-After"),
        );
        assert_eq!(
            openai_proxy_response_header_name("x-ratelimit-remaining-tokens"),
            Some("X-Ratelimit-Remaining-Tokens"),
        );
        assert_eq!(openai_proxy_response_header_name("set-cookie"), None);
    }

    #[test]
    fn openai_proxy_request_wants_streaming_reads_top_level_stream_field() {
        assert!(openai_proxy_request_wants_streaming(
            br#"{"model":"gpt-5","stream":true}"#
        ));
        assert!(!openai_proxy_request_wants_streaming(
            br#"{"model":"gpt-5","stream":false}"#
        ));
        assert!(!openai_proxy_request_wants_streaming(
            br#"{"model":"gpt-5"}"#
        ));
        assert!(!openai_proxy_request_wants_streaming(b"not-json"));
    }

    #[test]
    fn openai_proxy_config_accepts_chatgpt_oauth_and_defaults_refresh_url() {
        let secret = SecretKey::new("openai-chatgpt-auth").unwrap();
        let config = VmHttpOpenAiProxyConfig::new(
            "https://api.openai.com/v1/",
            secret,
            VmHttpOpenAiProxyAuthKind::ChatgptOauth,
            std::time::Duration::from_secs(5),
            1024,
            1024,
        )
        .unwrap();
        assert_eq!(
            config.chatgpt_refresh_url().as_str(),
            CHATGPT_OAUTH_REFRESH_URL,
        );
    }

    #[test]
    fn openai_proxy_config_with_chatgpt_refresh_url_overrides_default() {
        let secret = SecretKey::new("openai-chatgpt-auth").unwrap();
        let config = VmHttpOpenAiProxyConfig::new(
            "https://api.openai.com/v1/",
            secret,
            VmHttpOpenAiProxyAuthKind::ChatgptOauth,
            std::time::Duration::from_secs(5),
            1024,
            1024,
        )
        .unwrap()
        .with_chatgpt_refresh_url("https://example.test/refresh")
        .unwrap();
        assert_eq!(
            config.chatgpt_refresh_url().as_str(),
            "https://example.test/refresh",
        );
    }

    #[test]
    fn openai_proxy_config_with_chatgpt_refresh_url_rejects_invalid_url() {
        let secret = SecretKey::new("openai-chatgpt-auth").unwrap();
        let err = VmHttpOpenAiProxyConfig::new(
            "https://api.openai.com/v1/",
            secret,
            VmHttpOpenAiProxyAuthKind::ChatgptOauth,
            std::time::Duration::from_secs(5),
            1024,
            1024,
        )
        .unwrap()
        .with_chatgpt_refresh_url("not-a-url")
        .unwrap_err();
        assert!(matches!(
            err,
            VmHttpOpenAiProxyConfigError::InvalidChatgptRefreshUrl { .. }
        ));
    }

    #[test]
    fn openai_proxy_config_with_chatgpt_refresh_url_rejects_unsupported_scheme() {
        let secret = SecretKey::new("openai-chatgpt-auth").unwrap();
        let err = VmHttpOpenAiProxyConfig::new(
            "https://api.openai.com/v1/",
            secret,
            VmHttpOpenAiProxyAuthKind::ChatgptOauth,
            std::time::Duration::from_secs(5),
            1024,
            1024,
        )
        .unwrap()
        .with_chatgpt_refresh_url("ftp://example.test/refresh")
        .unwrap_err();
        assert!(matches!(
            err,
            VmHttpOpenAiProxyConfigError::UnsupportedChatgptRefreshScheme { .. }
        ));
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
    fn claude_proxy_upstream_join_preserves_non_root_base_path() {
        let config = VmHttpClaudeProxyConfig::new(
            "https://proxy.example.test/anthropic",
            SecretKey::new("anthropic-api-key").unwrap(),
            VmHttpClaudeProxyAuthKind::XApiKey,
            std::time::Duration::from_secs(5),
            1024,
            1024,
        )
        .unwrap();

        assert_eq!(
            config.upstream_base_url().as_str(),
            "https://proxy.example.test/anthropic/"
        );
        assert_eq!(
            config
                .upstream_base_url()
                .join("v1/messages")
                .unwrap()
                .as_str(),
            "https://proxy.example.test/anthropic/v1/messages"
        );
        assert_eq!(
            config
                .upstream_base_url()
                .join("v1/messages/count_tokens")
                .unwrap()
                .as_str(),
            "https://proxy.example.test/anthropic/v1/messages/count_tokens"
        );
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

    #[test]
    fn agent_run_config_route_returns_prompt_and_model_once() {
        let temp = tempfile::tempdir().unwrap();
        let service = VmHttpAgentRunService::with_log_root(temp.path().join("agent-runs"));
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000401".parse().unwrap();
        let prompt = AgentPrompt::new("SECRET prompt");
        service.insert_run_config(run_id, prompt.clone(), "gpt-5.4-mini");

        let response = route_agent_run_config_request(run_id, &service);

        assert_eq!(response.status, VmHttpStatus::Ok);
        let body: VmAgentRunConfigResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.run_id(), run_id);
        assert_eq!(body.prompt(), &prompt);
        assert_eq!(body.model(), "gpt-5.4-mini");
        let debug = format!("{body:?}");
        assert!(!debug.contains(prompt.as_str()), "{debug}");

        let second = route_agent_run_config_request(run_id, &service);
        assert_eq!(second.status, VmHttpStatus::NotFound);
    }

    #[tokio::test]
    async fn agent_run_outcome_route_records_audit_and_materializes_retained_streams() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000402".parse().unwrap();
        state
            .audit
            .record_agent_run(&crate::audit::AgentRunAuditRecord {
                run_id,
                session_id: session.session_id(),
                requested_at: UnixMillis::now(),
                agent_kind: crate::core::AgentKind::Claude,
                prompt: AgentPrompt::new("prompt").summary(),
            })
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let service = VmHttpAgentRunService::with_log_root(temp.path().join("agent-runs"));
        let upload = VmAgentRunOutcomeUpload {
            run_id,
            status: crate::agent_run::AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: AgentRunStreamUpload {
                byte_len: 6,
                sha256_hex: crate::agent_run::sha256_hex(b"Hello\n"),
                truncated: false,
                retained_sha256_hex: crate::agent_run::sha256_hex(b"Hello\n"),
                retained_base64: base64_standard(b"Hello\n"),
            },
            stderr: AgentRunStreamUpload {
                byte_len: 0,
                sha256_hex: crate::agent_run::sha256_hex(b""),
                truncated: false,
                retained_sha256_hex: crate::agent_run::sha256_hex(b""),
                retained_base64: base64_standard(b""),
            },
        };
        let body = serde_json::to_vec(&upload).unwrap();
        let prewritten =
            materialize_agent_run_outcome_upload(upload.clone(), service.log_root()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&prewritten.stdout.path).unwrap(),
            "Hello\n"
        );

        let response = route_agent_run_outcome_request(run_id, &body, &service, &state);

        assert_eq!(response.status, VmHttpStatus::Ok);
        let outcome = state.audit.get_agent_run_outcome(run_id).unwrap().unwrap();
        assert_eq!(
            outcome.outcome.status,
            crate::agent_run::AgentRunTerminalStatus::Succeeded
        );
        assert_eq!(
            std::fs::read_to_string(&outcome.outcome.stdout.path).unwrap(),
            "Hello\n"
        );
        assert!(outcome.outcome.stdout.path.starts_with(temp.path()));

        let retried = route_agent_run_outcome_request(run_id, &body, &service, &state);
        assert_eq!(retried.status, VmHttpStatus::Ok);
    }

    #[tokio::test]
    async fn agent_run_outcome_rejects_unbounded_or_mismatched_truncated_streams() {
        let github = MockServer::start().await;
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let run_id: AgentRunId = "00000000-0000-0000-0000-000000000403".parse().unwrap();
        state
            .audit
            .record_agent_run(&crate::audit::AgentRunAuditRecord {
                run_id,
                session_id: session.session_id(),
                requested_at: UnixMillis::now(),
                agent_kind: crate::core::AgentKind::Claude,
                prompt: AgentPrompt::new("prompt").summary(),
            })
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let service = VmHttpAgentRunService::with_log_root(temp.path().join("agent-runs"));
        let valid_stderr = AgentRunStreamUpload {
            byte_len: 0,
            sha256_hex: crate::agent_run::sha256_hex(b""),
            truncated: false,
            retained_sha256_hex: crate::agent_run::sha256_hex(b""),
            retained_base64: base64_standard(b""),
        };
        let upload = VmAgentRunOutcomeUpload {
            run_id,
            status: crate::agent_run::AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: AgentRunStreamUpload {
                byte_len: u64::MAX,
                sha256_hex: crate::agent_run::sha256_hex(b"untrusted full stream"),
                truncated: true,
                retained_sha256_hex: crate::agent_run::sha256_hex(b"H"),
                retained_base64: base64_standard(b"H"),
            },
            stderr: valid_stderr.clone(),
        };

        let response = route_agent_run_outcome_request(
            run_id,
            &serde_json::to_vec(&upload).unwrap(),
            &service,
            &state,
        );

        assert_eq!(response.status, VmHttpStatus::BadRequest);
        let upload = VmAgentRunOutcomeUpload {
            stdout: AgentRunStreamUpload {
                byte_len: 2,
                sha256_hex: crate::agent_run::sha256_hex(b"Hi"),
                truncated: true,
                retained_sha256_hex: crate::agent_run::sha256_hex(b"not-H"),
                retained_base64: base64_standard(b"H"),
            },
            stderr: valid_stderr.clone(),
            ..upload
        };
        let response = route_agent_run_outcome_request(
            run_id,
            &serde_json::to_vec(&upload).unwrap(),
            &service,
            &state,
        );
        assert_eq!(response.status, VmHttpStatus::BadRequest);

        let upload = VmAgentRunOutcomeUpload {
            stdout: AgentRunStreamUpload {
                byte_len: 2,
                sha256_hex: crate::agent_run::sha256_hex(b"unverified full stream"),
                truncated: true,
                retained_sha256_hex: crate::agent_run::sha256_hex(b"H"),
                retained_base64: base64_standard(b"H"),
            },
            stderr: valid_stderr,
            ..upload
        };
        let response = route_agent_run_outcome_request(
            run_id,
            &serde_json::to_vec(&upload).unwrap(),
            &service,
            &state,
        );
        assert_eq!(response.status, VmHttpStatus::Ok);
        let outcome = state.audit.get_agent_run_outcome(run_id).unwrap().unwrap();
        assert_eq!(outcome.outcome.stdout.byte_len, 1);
        assert_eq!(
            outcome.outcome.stdout.sha256_hex,
            crate::agent_run::sha256_hex(b"H")
        );
    }

    #[tokio::test]
    async fn claude_proxy_strips_guest_auth_and_injects_host_auth() {
        let upstream_body = br#"{"content":[{"type":"text","text":"Hello from upstream"}]}"#;
        let (upstream_url, captured) = serve_raw_http_once(raw_http_response_with_headers(
            "200 OK",
            "application/json",
            &[
                ("request-id", "req-test-123"),
                ("anthropic-ratelimit-requests-remaining", "42"),
            ],
            upstream_body,
        ))
        .await;
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("anthropic-api-key").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "host-anthropic-key")),
        );
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpClaudeProxyService::new(
            Arc::clone(&state),
            VmHttpClaudeProxyConfig::new_with_anthropic_version(
                upstream_url,
                secret_key,
                VmHttpClaudeProxyAuthKind::XApiKey,
                "2024-10-22",
                std::time::Duration::from_secs(5),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let mut request = VmHttpRequest::new(
            "POST",
            VM_CLAUDE_MESSAGES_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
        );
        request.headers = vec![
            VmHttpHeader {
                name: "Authorization".into(),
                value: bearer(token().as_str()),
            },
            VmHttpHeader {
                name: "X-Api-Key".into(),
                value: "guest-x-api-key".into(),
            },
            VmHttpHeader {
                name: "Cookie".into(),
                value: "session=guest".into(),
            },
            VmHttpHeader {
                name: "Anthropic-Version".into(),
                value: "2023-06-01".into(),
            },
            VmHttpHeader {
                name: "Anthropic-Beta".into(),
                value: "guest-beta".into(),
            },
            VmHttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            },
        ];

        let response = route_claude_proxy_request(
            &session,
            &request,
            br#"{"model":"test"}"#.to_vec(),
            &service,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::Upstream(200));
        assert_eq!(response.content_type, "application/json");
        assert_eq!(response.body, upstream_body);
        assert_eq!(
            response.headers,
            vec![
                VmHttpResponseHeader {
                    name: "Request-Id",
                    value: "req-test-123".into(),
                },
                VmHttpResponseHeader {
                    name: "Anthropic-Ratelimit-Requests-Remaining",
                    value: "42".into(),
                },
            ]
        );
        let upstream_request = captured.lock().unwrap().clone();
        let lower = upstream_request.to_ascii_lowercase();
        assert!(
            upstream_request.starts_with("POST /v1/messages HTTP/1.1"),
            "{upstream_request}"
        );
        assert!(
            lower.contains("x-api-key: host-anthropic-key"),
            "{upstream_request}"
        );
        assert!(
            lower.contains("anthropic-version: 2024-10-22"),
            "{upstream_request}"
        );
        assert!(!lower.contains("anthropic-beta:"), "{upstream_request}");
        assert!(
            lower.contains("content-type: application/json"),
            "{upstream_request}"
        );
        assert!(
            !upstream_request.contains(token().as_str()),
            "{upstream_request}"
        );
        assert!(
            !upstream_request.contains("guest-x-api-key"),
            "{upstream_request}"
        );
        assert!(!lower.contains("cookie:"), "{upstream_request}");
        assert!(
            upstream_request.ends_with(r#"{"model":"test"}"#),
            "{upstream_request}"
        );
    }

    #[tokio::test]
    async fn claude_proxy_messages_with_beta_query_strips_to_upstream_path() {
        let upstream_body = br#"{"content":[]}"#;
        let (upstream_url, captured) = serve_raw_http_once(raw_http_response(
            "200 OK",
            "application/json",
            upstream_body,
        ))
        .await;
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("anthropic-api-key").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "host-anthropic-key")),
        );
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpClaudeProxyService::new(
            Arc::clone(&state),
            VmHttpClaudeProxyConfig::new(
                upstream_url,
                secret_key,
                VmHttpClaudeProxyAuthKind::XApiKey,
                std::time::Duration::from_secs(5),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let request = VmHttpRequest::new(
            "POST",
            "/v1/messages?beta=true",
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
        );

        let response = route_claude_proxy_request(
            &session,
            &request,
            br#"{"model":"test"}"#.to_vec(),
            &service,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::Upstream(200));
        let upstream_request = captured.lock().unwrap().clone();
        assert!(
            upstream_request.starts_with("POST /v1/messages HTTP/1.1"),
            "{upstream_request}"
        );
        assert!(!upstream_request.contains("?beta="), "{upstream_request}");
        let entries = state
            .audit
            .list_claude_proxy_requests_for_session_for_test(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, ClaudeProxyAuditRoute::Messages);
        assert_eq!(entries[0].1, ClaudeProxyAuditDecision::Allow);
        assert_eq!(entries[0].2, Some(200));
    }

    #[tokio::test]
    async fn claude_proxy_models_route_proxies_get_to_upstream() {
        let upstream_body = br#"{"id":"claude-haiku-4-5-20251001","type":"model"}"#;
        let (upstream_url, captured) = serve_raw_http_once(raw_http_response(
            "200 OK",
            "application/json",
            upstream_body,
        ))
        .await;
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("anthropic-api-key").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "host-anthropic-key")),
        );
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpClaudeProxyService::new(
            Arc::clone(&state),
            VmHttpClaudeProxyConfig::new(
                upstream_url,
                secret_key,
                VmHttpClaudeProxyAuthKind::XApiKey,
                std::time::Duration::from_secs(5),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let request = VmHttpRequest::new(
            "GET",
            "/v1/models/claude-haiku-4-5-20251001",
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
        );

        let response = route_claude_proxy_request(&session, &request, Vec::new(), &service)
            .await
            .into_buffered();

        assert_eq!(response.status, VmHttpStatus::Upstream(200));
        assert_eq!(response.body, upstream_body);
        let upstream_request = captured.lock().unwrap().clone();
        assert!(
            upstream_request.starts_with("GET /v1/models/claude-haiku-4-5-20251001 HTTP/1.1"),
            "{upstream_request}"
        );
        assert!(
            upstream_request
                .to_ascii_lowercase()
                .contains("x-api-key: host-anthropic-key"),
            "{upstream_request}"
        );
        let entries = state
            .audit
            .list_claude_proxy_requests_for_session_for_test(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, ClaudeProxyAuditRoute::Models);
        assert_eq!(entries[0].1, ClaudeProxyAuditDecision::Allow);
        assert_eq!(entries[0].2, Some(200));
    }

    #[tokio::test]
    async fn claude_proxy_models_route_rejects_post_with_method_not_allowed() {
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("anthropic-api-key").unwrap();
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpClaudeProxyService::new(
            Arc::clone(&state),
            VmHttpClaudeProxyConfig::new(
                "http://127.0.0.1:9/",
                secret_key,
                VmHttpClaudeProxyAuthKind::XApiKey,
                std::time::Duration::from_millis(10),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let request = VmHttpRequest::new(
            "POST",
            "/v1/models/claude-haiku-4-5-20251001",
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
        );

        let response = route_claude_proxy_request(&session, &request, Vec::new(), &service)
            .await
            .into_buffered();

        assert_eq!(response.status, VmHttpStatus::MethodNotAllowed);
        let entries = state
            .audit
            .list_claude_proxy_requests_for_session_for_test(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, ClaudeProxyAuditRoute::Models);
        assert_eq!(
            entries[0].1,
            ClaudeProxyAuditDecision::Deny {
                reason: "method not allowed".into()
            }
        );
        assert_eq!(entries[0].2, Some(405));
    }

    #[tokio::test]
    async fn claude_proxy_missing_host_secret_is_bad_gateway_without_upstream_call() {
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("anthropic-api-key").unwrap();
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpClaudeProxyService::new(
            Arc::clone(&state),
            VmHttpClaudeProxyConfig::new(
                "http://127.0.0.1:9/",
                secret_key,
                VmHttpClaudeProxyAuthKind::XApiKey,
                std::time::Duration::from_millis(10),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let request = VmHttpRequest::new(
            "POST",
            VM_CLAUDE_MESSAGES_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
        );

        let response = route_claude_proxy_request(
            &session,
            &request,
            br#"{"model":"test"}"#.to_vec(),
            &service,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::BadGateway);
        assert_eq!(
            String::from_utf8(response.body).unwrap(),
            "Claude proxy auth missing"
        );
    }

    #[tokio::test]
    async fn claude_proxy_bearer_auth_overrides_guest_authorization() {
        let upstream_body = br#"{"content":[]}"#;
        let (upstream_url, captured) = serve_raw_http_once(raw_http_response(
            "200 OK",
            "application/json",
            upstream_body,
        ))
        .await;
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("anthropic-bearer-token").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "host-bearer-token")),
        );
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpClaudeProxyService::new(
            Arc::clone(&state),
            VmHttpClaudeProxyConfig::new(
                upstream_url,
                secret_key,
                VmHttpClaudeProxyAuthKind::AuthorizationBearer,
                std::time::Duration::from_secs(5),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let mut request = VmHttpRequest::new(
            "POST",
            VM_CLAUDE_MESSAGES_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
        );
        request.headers = vec![VmHttpHeader {
            name: "Authorization".into(),
            value: "Bearer guest-evil".into(),
        }];

        let response = route_claude_proxy_request(
            &session,
            &request,
            br#"{"model":"test"}"#.to_vec(),
            &service,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::Upstream(200));
        let upstream_request = captured.lock().unwrap().clone();
        let lower = upstream_request.to_ascii_lowercase();
        assert!(
            lower.contains("authorization: bearer host-bearer-token"),
            "{upstream_request}"
        );
        assert!(
            !upstream_request.contains("guest-evil"),
            "{upstream_request}"
        );
        assert!(
            !upstream_request.contains(token().as_str()),
            "{upstream_request}"
        );
    }

    #[tokio::test]
    async fn claude_proxy_oauth_injects_bearer_and_oauth_beta_header() {
        let upstream_body = br#"{"content":[]}"#;
        let (upstream_url, captured) = serve_raw_http_once(raw_http_response(
            "200 OK",
            "application/json",
            upstream_body,
        ))
        .await;
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("anthropic-oauth-token").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "host-oauth-token")),
        );
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpClaudeProxyService::new(
            Arc::clone(&state),
            VmHttpClaudeProxyConfig::new(
                upstream_url,
                secret_key,
                VmHttpClaudeProxyAuthKind::OAuth,
                std::time::Duration::from_secs(5),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let mut request = VmHttpRequest::new(
            "POST",
            VM_CLAUDE_MESSAGES_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
        );
        request.headers = vec![
            VmHttpHeader {
                name: "Authorization".into(),
                value: "Bearer guest-evil".into(),
            },
            VmHttpHeader {
                name: "X-Api-Key".into(),
                value: "guest-x-api-key".into(),
            },
            VmHttpHeader {
                name: "Anthropic-Beta".into(),
                value: "context-management-2025-06-27".into(),
            },
            VmHttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            },
        ];

        let response = route_claude_proxy_request(
            &session,
            &request,
            br#"{"model":"test"}"#.to_vec(),
            &service,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::Upstream(200));
        let upstream_request = captured.lock().unwrap().clone();
        let lower = upstream_request.to_ascii_lowercase();
        assert!(
            lower.contains("authorization: bearer host-oauth-token"),
            "{upstream_request}"
        );
        assert!(
            lower.contains("anthropic-beta: oauth-2025-04-20"),
            "{upstream_request}"
        );
        assert!(
            lower.contains("anthropic-beta: context-management-2025-06-27"),
            "{upstream_request}"
        );
        assert!(!lower.contains("x-api-key:"), "{upstream_request}");
        assert!(
            !upstream_request.contains("guest-evil"),
            "{upstream_request}"
        );
        assert!(
            !upstream_request.contains("guest-x-api-key"),
            "{upstream_request}"
        );
        assert!(
            !upstream_request.contains(token().as_str()),
            "{upstream_request}"
        );
    }

    #[tokio::test]
    async fn claude_proxy_rejects_duplicate_forwarded_headers() {
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("anthropic-api-key").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "host-anthropic-key")),
        );
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpClaudeProxyService::new(
            Arc::clone(&state),
            VmHttpClaudeProxyConfig::new(
                "http://127.0.0.1:9/",
                secret_key,
                VmHttpClaudeProxyAuthKind::XApiKey,
                std::time::Duration::from_millis(10),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let mut request = VmHttpRequest::new(
            "POST",
            VM_CLAUDE_MESSAGES_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
        );
        request.headers = vec![
            VmHttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            },
            VmHttpHeader {
                name: "content-type".into(),
                value: "text/plain".into(),
            },
        ];

        let response = route_claude_proxy_request(
            &session,
            &request,
            br#"{"model":"test"}"#.to_vec(),
            &service,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::BadRequest);
    }

    #[tokio::test]
    async fn claude_proxy_streams_sse_and_records_outcome_after_write() {
        let upstream_body = b"event: message_start\n\ndata: {\"type\":\"done\"}\n\n";
        let (upstream_url, _captured) = serve_raw_http_once(raw_http_response_with_headers(
            "200 OK",
            "text/event-stream",
            &[("request-id", "req-stream-123")],
            upstream_body,
        ))
        .await;
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("anthropic-api-key").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "host-anthropic-key")),
        );
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpClaudeProxyService::new(
            Arc::clone(&state),
            VmHttpClaudeProxyConfig::new(
                upstream_url,
                secret_key,
                VmHttpClaudeProxyAuthKind::XApiKey,
                std::time::Duration::from_secs(5),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let request = VmHttpRequest::new(
            "POST",
            VM_CLAUDE_MESSAGES_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
        );
        let dispatch = route_claude_proxy_request(
            &session,
            &request,
            br#"{"model":"test","stream":true}"#.to_vec(),
            &service,
        )
        .await;
        let request_id = match &dispatch {
            VmHttpDispatch::ClaudeProxyStream(stream) => stream.request_id,
            VmHttpDispatch::Buffered(response) => {
                panic!("expected streaming response, got {response:?}")
            }
            VmHttpDispatch::OpenAiProxyStream(_) => {
                panic!("expected Claude streaming response, got OpenAI streaming response")
            }
        };
        assert!(
            state
                .audit
                .claude_proxy_outcome_for_test(request_id)
                .unwrap()
                .is_none(),
            "streaming outcome must not be recorded before the response is written"
        );
        let (mut client, mut server) = tokio::io::duplex(4096);

        let writer = tokio::spawn(async move { dispatch.write_to(&mut server).await.unwrap() });
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        writer.await.unwrap();
        let response = String::from_utf8(response).unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.contains("Content-Type: text/event-stream\r\n"),
            "{response}"
        );
        assert!(!response.contains("Content-Length:"), "{response}");
        assert!(
            response.contains("Request-Id: req-stream-123\r\n"),
            "{response}"
        );
        assert!(
            response.ends_with(std::str::from_utf8(upstream_body).unwrap()),
            "{response}"
        );
        let outcome = state
            .audit
            .claude_proxy_outcome_for_test(request_id)
            .unwrap()
            .expect("streaming outcome should be recorded after write_to");
        assert_eq!(outcome, (200, upstream_body.len() as u64, None));
    }

    #[tokio::test]
    async fn claude_proxy_streaming_records_response_too_large() {
        let upstream_body = b"0123456789";
        let (upstream_url, _captured) = serve_raw_http_once(raw_http_response_with_headers(
            "200 OK",
            "text/event-stream",
            &[],
            upstream_body,
        ))
        .await;
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("anthropic-api-key").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "host-anthropic-key")),
        );
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpClaudeProxyService::new(
            Arc::clone(&state),
            VmHttpClaudeProxyConfig::new(
                upstream_url,
                secret_key,
                VmHttpClaudeProxyAuthKind::XApiKey,
                std::time::Duration::from_secs(5),
                1024,
                5,
            )
            .unwrap(),
        )
        .unwrap();
        let request = VmHttpRequest::new(
            "POST",
            VM_CLAUDE_MESSAGES_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34567)),
        );
        let dispatch = route_claude_proxy_request(
            &session,
            &request,
            br#"{"model":"test","stream":true}"#.to_vec(),
            &service,
        )
        .await;
        let request_id = match &dispatch {
            VmHttpDispatch::ClaudeProxyStream(stream) => stream.request_id,
            VmHttpDispatch::Buffered(response) => {
                panic!("expected streaming response, got {response:?}")
            }
            VmHttpDispatch::OpenAiProxyStream(_) => {
                panic!("expected Claude streaming response, got OpenAI streaming response")
            }
        };
        let (mut client, mut server) = tokio::io::duplex(4096);

        let writer = tokio::spawn(async move { dispatch.write_to(&mut server).await.unwrap() });
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        writer.await.unwrap();
        let response = String::from_utf8(response).unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.contains("Content-Type: text/event-stream\r\n"),
            "{response}"
        );
        assert!(
            !response.ends_with(std::str::from_utf8(upstream_body).unwrap()),
            "{response}"
        );
        let outcome = state
            .audit
            .claude_proxy_outcome_for_test(request_id)
            .unwrap()
            .expect("streaming outcome should be recorded after write_to");
        assert_eq!(
            outcome,
            (
                200,
                upstream_body.len() as u64,
                Some("upstream response too large".to_string())
            )
        );
    }

    #[tokio::test]
    async fn claude_proxy_auth_denial_is_audited_without_contacting_upstream() {
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("anthropic-api-key").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "host-anthropic-key")),
        );
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpClaudeProxyService::new(
            Arc::clone(&state),
            VmHttpClaudeProxyConfig::new(
                "http://127.0.0.1:9/",
                secret_key,
                VmHttpClaudeProxyAuthKind::XApiKey,
                std::time::Duration::from_millis(10),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let raw_head = format!("POST {VM_CLAUDE_MESSAGES_PATH} HTTP/1.1\r\n\r\n").into_bytes();
        let mut stream = tokio::io::empty();

        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            VmHttpHeadRead {
                raw_head,
                buffered_body: Vec::new(),
            },
            &mut stream,
            services_with_claude_proxy(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        let entries = state
            .audit
            .list_claude_proxy_requests_for_session_for_test(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, ClaudeProxyAuditRoute::Messages);
        assert_eq!(
            entries[0].1,
            ClaudeProxyAuditDecision::Deny {
                reason: "missing credentials".into()
            }
        );
        assert_eq!(entries[0].2, Some(401));
    }

    #[tokio::test]
    async fn openai_proxy_strips_guest_auth_and_injects_host_bearer() {
        let upstream_body = br#"{"id":"resp_xyz","output":[]}"#;
        let (upstream_url, captured) = serve_raw_http_once(raw_http_response_with_headers(
            "200 OK",
            "application/json",
            &[
                ("x-request-id", "req_123"),
                ("openai-organization", "org-test"),
                ("x-ratelimit-remaining-requests", "99"),
                ("set-cookie", "session=should-be-dropped"),
            ],
            upstream_body,
        ))
        .await;
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("openai-api-key").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "host-openai-key")),
        );
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpOpenAiProxyService::new(
            Arc::clone(&state),
            VmHttpOpenAiProxyConfig::new(
                upstream_url,
                secret_key,
                VmHttpOpenAiProxyAuthKind::AuthorizationBearer,
                std::time::Duration::from_secs(5),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let mut request = VmHttpRequest::new(
            "POST",
            VM_OPENAI_RESPONSES_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34568)),
        );
        request.headers = vec![
            VmHttpHeader {
                name: "Authorization".into(),
                value: bearer(token().as_str()),
            },
            VmHttpHeader {
                name: "Cookie".into(),
                value: "session=guest".into(),
            },
            VmHttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            },
            VmHttpHeader {
                name: "OpenAI-Organization".into(),
                value: "org-guest".into(),
            },
        ];

        let response = route_openai_proxy_request(
            &session,
            &request,
            br#"{"model":"gpt-5"}"#.to_vec(),
            &service,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::Upstream(200));
        assert_eq!(response.content_type, "application/json");
        assert_eq!(response.body, upstream_body);
        let header_names: Vec<_> = response.headers.iter().map(|h| h.name).collect();
        assert!(header_names.contains(&"X-Request-Id"));
        assert!(header_names.contains(&"Openai-Organization"));
        assert!(header_names.contains(&"X-Ratelimit-Remaining-Requests"));
        assert!(
            !header_names
                .iter()
                .any(|n| n.eq_ignore_ascii_case("set-cookie"))
        );
        let upstream_request = captured.lock().unwrap().clone();
        let lower = upstream_request.to_ascii_lowercase();
        assert!(
            upstream_request.starts_with("POST /v1/responses HTTP/1.1"),
            "{upstream_request}"
        );
        assert!(
            lower.contains("authorization: bearer host-openai-key"),
            "{upstream_request}"
        );
        // Guest-supplied OpenAI-Organization must never reach upstream: a
        // multi-org host secret would otherwise let the guest pick the
        // billing/auth scope.
        assert!(
            !lower.contains("openai-organization:"),
            "{upstream_request}"
        );
        assert!(
            lower.contains("content-type: application/json"),
            "{upstream_request}"
        );
        assert!(
            !upstream_request.contains(token().as_str()),
            "{upstream_request}"
        );
        assert!(!lower.contains("cookie:"), "{upstream_request}");
        assert!(
            upstream_request.ends_with(r#"{"model":"gpt-5"}"#),
            "{upstream_request}"
        );
        let entries = state
            .audit
            .list_openai_proxy_requests_for_session_for_test(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, OpenAiProxyAuditRoute::Responses);
        assert_eq!(entries[0].1, OpenAiProxyAuditDecision::Allow);
        assert_eq!(entries[0].2, Some(200));
    }

    #[tokio::test]
    async fn openai_proxy_auth_denial_is_audited_without_contacting_upstream() {
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("openai-api-key").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "host-openai-key")),
        );
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpOpenAiProxyService::new(
            Arc::clone(&state),
            VmHttpOpenAiProxyConfig::new(
                "http://127.0.0.1:9/",
                secret_key,
                VmHttpOpenAiProxyAuthKind::AuthorizationBearer,
                std::time::Duration::from_millis(10),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let raw_head = format!("POST {VM_OPENAI_RESPONSES_PATH} HTTP/1.1\r\n\r\n").into_bytes();
        let mut stream = tokio::io::empty();

        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            VmHttpHeadRead {
                raw_head,
                buffered_body: Vec::new(),
            },
            &mut stream,
            services_with_openai_proxy(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        let entries = state
            .audit
            .list_openai_proxy_requests_for_session_for_test(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, OpenAiProxyAuditRoute::Responses);
        assert_eq!(
            entries[0].1,
            OpenAiProxyAuditDecision::Deny {
                reason: "missing credentials".into()
            }
        );
        assert_eq!(entries[0].2, Some(401));
    }

    #[tokio::test]
    async fn openai_proxy_unsupported_route_is_audited_with_404() {
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("openai-api-key").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "host-openai-key")),
        );
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpOpenAiProxyService::new(
            Arc::clone(&state),
            VmHttpOpenAiProxyConfig::new(
                "http://127.0.0.1:9/",
                secret_key,
                VmHttpOpenAiProxyAuthKind::AuthorizationBearer,
                std::time::Duration::from_millis(10),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let request = VmHttpRequest::new(
            "POST",
            "/v1/responses/resp_abc/extra",
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34569)),
        );
        let response = route_openai_proxy_request(&session, &request, Vec::new(), &service)
            .await
            .into_buffered();
        assert_eq!(response.status, VmHttpStatus::NotFound);
        let entries = state
            .audit
            .list_openai_proxy_requests_for_session_for_test(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, OpenAiProxyAuditRoute::Unsupported);
        assert!(matches!(
            entries[0].1,
            OpenAiProxyAuditDecision::Deny { .. }
        ));
        assert_eq!(entries[0].2, Some(404));
    }

    fn b64url_for_test(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn jwt_for_test(payload: &serde_json::Value) -> String {
        let header = b64url_for_test(br#"{"alg":"HS256","typ":"JWT"}"#);
        let body = b64url_for_test(serde_json::to_vec(payload).unwrap().as_slice());
        let sig = b64url_for_test(b"sig");
        format!("{header}.{body}.{sig}")
    }

    fn chatgpt_auth_bundle_json(
        access_exp_unix: i64,
        account_id: &str,
        fedramp: bool,
        refresh_token: &str,
    ) -> String {
        let access_token = jwt_for_test(&serde_json::json!({"exp": access_exp_unix}));
        let id_token = jwt_for_test(&serde_json::json!({
            "exp": access_exp_unix + 86400,
            "https://api.openai.com/auth": {
                "chatgpt_account_id": account_id,
                "chatgpt_account_is_fedramp": fedramp,
            }
        }));
        serde_json::to_string(&serde_json::json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": serde_json::Value::Null,
            "tokens": {
                "id_token": id_token,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "account_id": account_id,
            },
            "last_refresh": "2026-01-01T00:00:00Z",
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn openai_proxy_chatgpt_oauth_injects_bearer_account_and_fedramp_headers() {
        let upstream_body = br#"{"id":"resp_xyz","output":[]}"#;
        let (upstream_url, captured) = serve_raw_http_once(raw_http_response_with_headers(
            "200 OK",
            "application/json",
            &[("x-request-id", "req_123")],
            upstream_body,
        ))
        .await;
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("openai-chatgpt-auth").unwrap();
        let far_future = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let bundle =
            chatgpt_auth_bundle_json(far_future, "acct-rotated-7", true, "refresh-token-123");
        let state =
            make_broker_state_with_extra_secret(&github, Some((secret_key.clone(), &bundle)));
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpOpenAiProxyService::new(
            Arc::clone(&state),
            VmHttpOpenAiProxyConfig::new(
                upstream_url,
                secret_key,
                VmHttpOpenAiProxyAuthKind::ChatgptOauth,
                std::time::Duration::from_secs(5),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let request = VmHttpRequest::new(
            "POST",
            VM_OPENAI_RESPONSES_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34570)),
        );

        let response = route_openai_proxy_request(
            &session,
            &request,
            br#"{"model":"gpt-5"}"#.to_vec(),
            &service,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::Upstream(200));
        let upstream_request = captured.lock().unwrap().clone();
        let lower = upstream_request.to_ascii_lowercase();
        // ChatGPT-OAuth upstreams expose bare paths under
        // `/backend-api/codex/`; the broker joins `responses` to
        // `upstream_base_url`, which here resolves to `/responses`.
        assert!(
            upstream_request.starts_with("POST /responses HTTP/1.1"),
            "{upstream_request}"
        );
        // Authorization carries the JWT access_token from the bundle, not a static API key.
        assert!(
            lower.contains("authorization: bearer "),
            "{upstream_request}"
        );
        assert!(
            !lower.contains("authorization: bearer host-openai-key"),
            "{upstream_request}"
        );
        assert!(
            lower.contains("chatgpt-account-id: acct-rotated-7"),
            "{upstream_request}"
        );
        assert!(
            lower.contains("x-openai-fedramp: true"),
            "{upstream_request}"
        );
        // The dummy guest bearer must not leak upstream.
        assert!(
            !upstream_request.contains(token().as_str()),
            "{upstream_request}"
        );
    }

    #[tokio::test]
    async fn openai_proxy_chatgpt_oauth_refreshes_stale_token_against_override_url() {
        let upstream_body = br#"{"id":"resp_xyz","output":[]}"#;
        let (upstream_url, captured) = serve_raw_http_once(raw_http_response_with_headers(
            "200 OK",
            "application/json",
            &[],
            upstream_body,
        ))
        .await;
        let refresh_server = MockServer::start().await;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let stale_exp = now - 60;
        let fresh_access_token = jwt_for_test(&serde_json::json!({"exp": now + 3600}));
        let fresh_id_token = jwt_for_test(&serde_json::json!({
            "exp": now + 86400,
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "acct-after-refresh",
                "chatgpt_account_is_fedramp": false,
            }
        }));
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": fresh_id_token,
                "access_token": fresh_access_token,
                "refresh_token": "refresh-rotated",
            })))
            .expect(1)
            .mount(&refresh_server)
            .await;

        let github = MockServer::start().await;
        let secret_key = SecretKey::new("openai-chatgpt-auth").unwrap();
        let bundle = chatgpt_auth_bundle_json(stale_exp, "acct-before", false, "refresh-stale");
        let state =
            make_broker_state_with_extra_secret(&github, Some((secret_key.clone(), &bundle)));
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpOpenAiProxyService::new(
            Arc::clone(&state),
            VmHttpOpenAiProxyConfig::new(
                upstream_url,
                secret_key.clone(),
                VmHttpOpenAiProxyAuthKind::ChatgptOauth,
                std::time::Duration::from_secs(5),
                1024,
                1024,
            )
            .unwrap()
            .with_chatgpt_refresh_url(format!("{}/oauth/token", refresh_server.uri()))
            .unwrap(),
        )
        .unwrap();
        let request = VmHttpRequest::new(
            "POST",
            VM_OPENAI_RESPONSES_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34571)),
        );

        let response = route_openai_proxy_request(
            &session,
            &request,
            br#"{"model":"gpt-5"}"#.to_vec(),
            &service,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::Upstream(200));
        let upstream_request = captured.lock().unwrap().clone();
        let lower = upstream_request.to_ascii_lowercase();
        assert!(
            lower.contains(
                &format!("authorization: bearer {fresh_access_token}").to_ascii_lowercase()
            ),
            "{upstream_request}"
        );
        // The id_token's account_id rotated on refresh; we must use the new one.
        assert!(
            lower.contains("chatgpt-account-id: acct-after-refresh"),
            "{upstream_request}"
        );
        assert!(!lower.contains("acct-before"), "{upstream_request}");
        // Stored bundle should now carry the rotated tokens.
        let raw = state
            .secret_store()
            .get(&secret_key)
            .unwrap()
            .expect("secret persisted");
        let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            stored["tokens"]["access_token"].as_str().unwrap(),
            fresh_access_token,
        );
        assert_eq!(
            stored["tokens"]["refresh_token"].as_str().unwrap(),
            "refresh-rotated",
        );
    }

    #[tokio::test]
    async fn openai_proxy_chatgpt_oauth_returns_502_with_login_required_when_secret_missing() {
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("openai-chatgpt-auth").unwrap();
        let state = make_broker_state(&github);
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 32).unwrap());
        open_audit_session(&state, session.session_id());
        let service = VmHttpOpenAiProxyService::new(
            Arc::clone(&state),
            VmHttpOpenAiProxyConfig::new(
                "http://127.0.0.1:9/",
                secret_key,
                VmHttpOpenAiProxyAuthKind::ChatgptOauth,
                std::time::Duration::from_millis(50),
                1024,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let request = VmHttpRequest::new(
            "POST",
            VM_OPENAI_RESPONSES_PATH,
            Some(bearer(token().as_str())),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 34572)),
        );

        let response = route_openai_proxy_request(
            &session,
            &request,
            br#"{"model":"gpt-5"}"#.to_vec(),
            &service,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::BadGateway);
        let entries = state
            .audit
            .list_openai_proxy_requests_for_session_for_test(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, OpenAiProxyAuditRoute::Responses);
        assert_eq!(entries[0].1, OpenAiProxyAuditDecision::Allow);
        assert_eq!(entries[0].2, Some(502));
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
            services_with_nix_cache(service),
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
            services_with_nix_cache(service),
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
                no_services(),
                VM_HTTP_READ_TIMEOUT,
            )
            .await
            .into_buffered();

            assert_eq!(response.status, VmHttpStatus::NotFound);
        }
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

        let mut stream = tokio::io::empty();
        let response = route_authenticated_vm_http_request(
            &session,
            &request,
            Vec::new(),
            &mut stream,
            no_services(),
            VM_HTTP_READ_TIMEOUT,
        )
        .await
        .into_buffered();

        assert_eq!(response.status, VmHttpStatus::NotFound);
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
            services_with_git(service),
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
            no_services(),
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
                no_services(),
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
                no_services(),
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
                services_with_git(service),
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
                no_services(),
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
            temp.path().join("agent-runs"),
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
            temp.path().join("agent-runs"),
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
            VmHttpProxies::none(),
            None,
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
            services_with_git(service),
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
