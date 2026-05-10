//! VM-facing broker HTTP endpoint.
//!
//! This is deliberately separate from the host Unix-socket protocol. The VM
//! endpoint authenticates one managed agent VM session with a bearer secret and
//! a source-subnet check, then exposes only VM-safe broker operations.

mod claude_proxy;
mod nix_cache;
mod openai_proxy;

pub use claude_proxy::{
    DEFAULT_CLAUDE_ANTHROPIC_VERSION, VmHttpClaudeProxyAuthKind, VmHttpClaudeProxyConfig,
    VmHttpClaudeProxyConfigError, VmHttpClaudeProxyService,
};
pub use nix_cache::{
    VM_NIX_BASIC_LOGIN, VM_NIX_CACHE_PATH_PREFIX, VmHttpNixCacheConfig,
    VmHttpNixCacheConfigError, VmHttpNixCacheService,
};
pub use openai_proxy::{
    VmHttpOpenAiProxyAuthKind, VmHttpOpenAiProxyConfig, VmHttpOpenAiProxyConfigError,
    VmHttpOpenAiProxyService,
};
use claude_proxy::{
    VmHttpClaudeProxyStream, classify_claude_proxy_target, is_claude_proxy_target,
    record_claude_proxy_local_response, route_claude_proxy_request,
};
use nix_cache::{is_nix_cache_target, record_nix_cache_local_response, route_nix_cache_request};
#[cfg(test)]
use nix_cache::route_nix_cache_request_without_upstream;
use openai_proxy::{
    VmHttpOpenAiProxyStream, classify_openai_proxy_target, is_openai_proxy_target,
    record_openai_proxy_local_response, route_openai_proxy_request,
};

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use http_body_util::{BodyExt, Empty, Full, Limited, combinators::UnsyncBoxBody};
use hyper::body::{Body as HyperBody, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::agent_run::{
    AgentPrompt, AgentRunId, AgentRunOutcome, AgentRunStreamSummary, AgentRunStreamUpload,
    VM_AGENT_RUN_OUTCOME_PATH_SUFFIX, VM_AGENT_RUN_PATH_PREFIX, VmAgentRunConfigResponse,
    VmAgentRunOutcomeUpload,
};
use crate::audit::{
    AgentRunOutcomeAuditRecord, ClaudeProxyAuditDecision, ClaudeProxyOutcomeRecord,
    NixCacheAuditDecision, OpenAiProxyAuditDecision, OpenAiProxyOutcomeRecord,
};
use crate::bearer::is_bearer_token_byte;
use crate::core::{
    BrokerPort, BrokerPortRange, CapabilityRequest, GitHubAccess, GitHubRequest, Ipv4Cidr,
    RequestId, SessionId, UnixMillis,
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

const MAX_VM_HTTP_BODY_BYTES: usize = 64 * 1024;
const MAX_VM_HTTP_AGENT_RUN_OUTCOME_BODY_BYTES: usize = 4 * 1024 * 1024;
// The JSON upload cap bounds retained bytes on the wire. This larger cap is a
// defense-in-depth bound on the guest-reported full stream length, which is
// intentionally not trusted for truncated-stream audit rows.
const MAX_AGENT_RUN_STREAM_AUDIT_BYTES: u64 = 1024 * 1024 * 1024;
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

pub struct VmHttpGitCloneService<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    config: VmHttpGitCloneConfig,
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

enum VmHttpDispatch<S: SecretStore> {
    Buffered(VmHttpResponse),
    ClaudeProxyStream(VmHttpClaudeProxyStream<S>),
    OpenAiProxyStream(VmHttpOpenAiProxyStream<S>),
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

#[derive(Copy, Clone, Debug)]
enum ProxyAuditKind {
    Claude,
    OpenAi,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ProxyStreamState {
    Streaming,
    UpstreamEnded,
    UpstreamError,
    OverMax,
}

struct ProxyStreamAudit<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    kind: ProxyAuditKind,
    request_id: RequestId,
    upstream_url: String,
    upstream_status: u16,
}

struct ProxyStreamBody<S: SecretStore> {
    inner: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
    audit: Option<ProxyStreamAudit<S>>,
    max_response_bytes: u64,
    response_bytes: u64,
    state: ProxyStreamState,
}

impl<S: SecretStore> HyperBody for ProxyStreamBody<S> {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let me = self.get_mut();
        if me.state != ProxyStreamState::Streaming {
            return Poll::Ready(None);
        }
        match me.inner.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                me.state = ProxyStreamState::UpstreamEnded;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                eprintln!(
                    "VM HTTP {} proxy streaming body read failed: {err}",
                    proxy_audit_label(me.audit.as_ref().map(|a| a.kind)),
                );
                me.state = ProxyStreamState::UpstreamError;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(chunk))) => {
                let chunk_len =
                    u64::try_from(chunk.len()).expect("HTTP chunk length fits in u64");
                let new_len = me
                    .response_bytes
                    .checked_add(chunk_len)
                    .expect("HTTP response byte count overflowed before configured bound check");
                if new_len > me.max_response_bytes {
                    me.response_bytes = new_len;
                    me.state = ProxyStreamState::OverMax;
                    return Poll::Ready(None);
                }
                me.response_bytes = new_len;
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.state != ProxyStreamState::Streaming
    }
}

impl<S: SecretStore> Drop for ProxyStreamBody<S> {
    fn drop(&mut self) {
        let Some(audit) = self.audit.take() else {
            return;
        };
        let error = match self.state {
            ProxyStreamState::Streaming => Some("guest response write failed"),
            ProxyStreamState::UpstreamEnded => None,
            ProxyStreamState::UpstreamError => Some("upstream body read failed"),
            ProxyStreamState::OverMax => Some("upstream response too large"),
        };
        let response_bytes = self.response_bytes;
        match audit.kind {
            ProxyAuditKind::Claude => {
                if let Err(err) = audit.broker_state.audit.record_claude_proxy_outcome(
                    &ClaudeProxyOutcomeRecord {
                        request_id: audit.request_id,
                        completed_at: UnixMillis::now(),
                        http_status: audit.upstream_status,
                        upstream_url: Some(audit.upstream_url.as_str()),
                        upstream_status: Some(audit.upstream_status),
                        response_bytes,
                        error,
                    },
                ) {
                    eprintln!(
                        "VM HTTP Claude proxy streaming audit outcome write failed: {err}"
                    );
                }
            }
            ProxyAuditKind::OpenAi => {
                if let Err(err) = audit.broker_state.audit.record_openai_proxy_outcome(
                    &OpenAiProxyOutcomeRecord {
                        request_id: audit.request_id,
                        completed_at: UnixMillis::now(),
                        http_status: audit.upstream_status,
                        upstream_url: Some(audit.upstream_url.as_str()),
                        upstream_status: Some(audit.upstream_status),
                        response_bytes,
                        error,
                    },
                ) {
                    eprintln!(
                        "VM HTTP OpenAI proxy streaming audit outcome write failed: {err}"
                    );
                }
            }
        }
    }
}

fn proxy_audit_label(kind: Option<ProxyAuditKind>) -> &'static str {
    match kind {
        Some(ProxyAuditKind::Claude) => "Claude",
        Some(ProxyAuditKind::OpenAi) => "OpenAI",
        None => "?",
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
        eprintln!("VM HTTP connection: {err}");
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
    let response =
        serve_vm_http_request(session, peer_addr, request, services, read_timeout).await;
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
    let dispatch: VmHttpDispatch<S> =
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
    if is_claude_proxy_target(&request.target) {
        return services
            .claude_proxy
            .as_ref()
            .map(|service| service.config.max_request_bytes());
    }
    if is_openai_proxy_target(&request.target) {
        return services
            .openai_proxy
            .as_ref()
            .map(|service| service.config.max_request_bytes());
    }
    if request.target == VM_GIT_CLONE_PATH
        && request.method == "POST"
        && services.git_clone.is_some()
    {
        return Some(MAX_VM_HTTP_BODY_BYTES);
    }
    if parse_agent_run_outcome_target(&request.target).is_some()
        && request.method == "POST"
        && services.agent_runs.is_some()
        && services.git_clone.is_some()
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
) -> VmHttpDispatch<S>
where
    S: SecretStore + Send + Sync,
{
    if is_nix_cache_target(&request.target) {
        return route_nix_cache_request(session, request, services.nix_cache).await;
    }

    if is_claude_proxy_target(&request.target) {
        let Some(service) = services.claude_proxy else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
        };
        return route_claude_proxy_request(session, request, body, &service).await;
    }

    if is_openai_proxy_target(&request.target) {
        let Some(service) = services.openai_proxy else {
            return VmHttpResponse::text(VmHttpStatus::NotFound, "not found").into();
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
        return route_agent_run_outcome_request(run_id, &body, &service, &broker_state).into();
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
    let retained = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(&upload.retained_base64)
            .map_err(|_| {
                VmHttpResponse::text(VmHttpStatus::BadRequest, "invalid outcome stream base64")
            })?
    };
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

        let mut authorization: Option<String> = None;
        let mut content_length: Option<usize> = None;
        let mut headers = Vec::new();
        for (name, value) in parts.headers.iter() {
            let Ok(value_str) = std::str::from_utf8(value.as_bytes()) else {
                continue;
            };
            let value_str = value_str.to_string();
            headers.push(VmHttpHeader {
                name: name.as_str().to_string(),
                value: value_str.clone(),
            });
            if name.as_str().eq_ignore_ascii_case("authorization") {
                if authorization.is_some() {
                    return Err(VmHttpParseError::DuplicateAuthorization);
                }
                authorization = Some(value_str);
                continue;
            }
            if name.as_str().eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return Err(VmHttpParseError::DuplicateContentLength);
                }
                if value_str.is_empty() || value_str.starts_with('+') || value_str.starts_with('-')
                {
                    return Err(VmHttpParseError::InvalidContentLength);
                }
                content_length = Some(
                    value_str
                        .parse::<usize>()
                        .map_err(|_| VmHttpParseError::InvalidContentLength)?,
                );
            }
        }

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

impl<S: SecretStore> From<VmHttpResponse> for VmHttpDispatch<S> {
    fn from(response: VmHttpResponse) -> Self {
        Self::Buffered(response)
    }
}

impl<S: SecretStore + Send + Sync + 'static> VmHttpDispatch<S> {
    fn into_hyper_response(self) -> http::Response<UnsyncBoxBody<Bytes, std::io::Error>> {
        match self {
            Self::Buffered(response) => response.into_hyper_response(),
            Self::ClaudeProxyStream(stream) => stream.into_hyper_response(),
            Self::OpenAiProxyStream(stream) => stream.into_hyper_response(),
        }
    }
}

impl<S: SecretStore> VmHttpDispatch<S> {
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

    use base64::Engine as _;
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

    const TEST_GIT_CLONE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    type TestVmHttpServices = VmHttpServices<Box<dyn SecretStore>>;

    pub(super) fn no_services() -> TestVmHttpServices {
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

    fn repo(owner: &str, name: &str) -> RepoRef {
        RepoRef {
            owner: owner.into(),
            name: name.into(),
        }
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
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b"Hello\n"),
            },
            stderr: AgentRunStreamUpload {
                byte_len: 0,
                sha256_hex: crate::agent_run::sha256_hex(b""),
                truncated: false,
                retained_sha256_hex: crate::agent_run::sha256_hex(b""),
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b""),
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
            retained_base64: base64::engine::general_purpose::STANDARD.encode(b""),
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
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b"H"),
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
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b"H"),
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
                retained_base64: base64::engine::general_purpose::STANDARD.encode(b"H"),
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
            let response = route_authenticated_vm_http_request(
                &session,
                &request,
                Vec::new(),
                no_services(),
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

        let response = route_authenticated_vm_http_request(
            &session,
            &request,
            Vec::new(),
            no_services(),
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

        let response = route_authenticated_vm_http_request(
            &session,
            &request,
            Vec::new(),
            services_with_git(service),
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
    async fn disabled_git_clone_route_does_not_read_declared_body() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let bearer_auth = bearer(token().as_str());
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dispatch_vm_http_head_and_body(
                &session,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
                "POST",
                VM_GIT_CLONE_PATH,
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
        let bearer_auth = bearer(token().as_str());
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dispatch_vm_http_head_and_body(
                &session,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
                "GET",
                VM_GIT_CLONE_PATH,
                &[
                    ("authorization", bearer_auth.as_str()),
                    ("content-length", "1"),
                ],
                Vec::new(),
                services_with_git(service),
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("non-POST Git clone route must not wait for a declared body");

        assert_eq!(response.status, VmHttpStatus::NotFound);
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
            response.contains(&format!("content-type: {GIT_BUNDLE_CONTENT_TYPE}\r\n")),
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
