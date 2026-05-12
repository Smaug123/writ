//! Read-only JSON HTTP transport for external UIs.
//!
//! Distinct from the host Unix socket (the primary control plane,
//! line-delimited JSON, all reads and writes) and the per-VM HTTP
//! listeners (guest-to-host, bearer-and-subnet-gated, exposes
//! authority-bearing operations to a managed VM). This listener is
//! bound to a loopback address, authenticated with a single bearer
//! token written to a 0600 file at daemon start, and exposes only GET
//! endpoints that join broker state into JSON suitable for a web UI,
//! TUI, MCP wrapper, or ad-hoc `curl`.
//!
//! See `docs/plans/2026-05-12-ui-data-api.md` for the design.

mod agent_vms;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::{Empty, Full, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::agent_vm_daemon::AgentVmDaemon;
use crate::audit::AuditLog;
use crate::bearer::is_bearer_token_byte;

pub use agent_vms::{AgentVmDetailResponse, AgentVmListResponse, AgentVmRow};

const UI_HTTP_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const MAX_UI_HTTP_CONNECTIONS: usize = 64;

/// Bearer token guarding the UI HTTP listener.
///
/// Format mirrors [`crate::vm_http::VmHttpBearerToken`]: a `writ-ui-`
/// prefix followed by two UUID-simple hex strings (64 hex chars = 128
/// bits each, 256 bits total). The format is incidental — what
/// matters is that the wire syntax is a single token of unreserved
/// ASCII characters and that the token is generated from the kernel
/// CSPRNG.
#[derive(Clone, Eq, PartialEq)]
pub struct UiHttpBearerToken(String);

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum UiHttpBearerTokenError {
    #[error("UI HTTP bearer token must not be empty")]
    Empty,
    #[error("UI HTTP bearer token must contain only unreserved ASCII token characters")]
    InvalidCharacter,
}

impl UiHttpBearerToken {
    pub fn generate() -> Self {
        Self(format!(
            "writ-ui-{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ))
    }

    pub fn new(raw: impl Into<String>) -> Result<Self, UiHttpBearerTokenError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(UiHttpBearerTokenError::Empty);
        }
        if !raw.bytes().all(is_bearer_token_byte) {
            return Err(UiHttpBearerTokenError::InvalidCharacter);
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for UiHttpBearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UiHttpBearerToken(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UiHttpBearerWriteError {
    #[error("cannot create UI HTTP bearer parent directory {path:?}: {source}")]
    ParentDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "UI HTTP bearer parent {path:?} has group/world access bits (mode {mode:04o}); \
         refusing to write the bearer file: any local user could observe or substitute the token. \
         Fix with: chmod 700 {path:?}"
    )]
    NonPrivateParent { path: PathBuf, mode: u32 },
    #[error("cannot write UI HTTP bearer file {path:?}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot install UI HTTP bearer file {path:?}: {source}")]
    Rename {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Write `token` to `path` (0600), replacing any prior contents. The
/// write goes via a sibling temp file followed by `rename`, so a
/// reader either sees the previous bearer or the new one — never a
/// half-written body.
///
/// If the parent directory does not exist it is created with mode
/// `0700`: this directory holds runtime secrets and shares the same
/// invariant as the socket parent (writ's other startup code refuses
/// to bind a socket inside a parent with group/world bits). An
/// existing parent is not chmod'd — we don't silently loosen or
/// tighten a directory the operator already created — but if it
/// has any group/world access bits we refuse to write, because a
/// shared-writable parent lets a local attacker pre-create the
/// `.tmp` file as a symlink and observe or substitute the token
/// before `rename` lands.
///
/// We unlink any pre-existing `.tmp` (left behind by a previous
/// crash, or planted by an attacker if the parent's privacy
/// invariant ever lapses) before opening with `O_CREAT | O_EXCL`,
/// which refuses to follow symlinks. Combined with the parent
/// privacy check, this means a successful open returns a fresh
/// file in our trusted directory.
pub fn write_bearer_file(
    path: &Path,
    token: &UiHttpBearerToken,
) -> Result<(), UiHttpBearerWriteError> {
    use std::io::Write as _;
    use std::os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    };

    if let Some(parent) = path.parent() {
        if parent.exists() {
            let meta =
                std::fs::metadata(parent).map_err(|source| UiHttpBearerWriteError::ParentDir {
                    path: parent.to_path_buf(),
                    source,
                })?;
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(UiHttpBearerWriteError::NonPrivateParent {
                    path: parent.to_path_buf(),
                    mode,
                });
            }
        } else {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|source| UiHttpBearerWriteError::ParentDir {
                    path: parent.to_path_buf(),
                    source,
                })?;
        }
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(UiHttpBearerWriteError::Write {
                path: tmp.clone(),
                source,
            });
        }
    }
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|source| UiHttpBearerWriteError::Write {
                path: tmp.clone(),
                source,
            })?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| UiHttpBearerWriteError::Write {
                path: tmp.clone(),
                source,
            })?;
        f.write_all(token.as_str().as_bytes())
            .map_err(|source| UiHttpBearerWriteError::Write {
                path: tmp.clone(),
                source,
            })?;
        f.sync_all()
            .map_err(|source| UiHttpBearerWriteError::Write {
                path: tmp.clone(),
                source,
            })?;
    }
    std::fs::rename(&tmp, path).map_err(|source| UiHttpBearerWriteError::Rename {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

/// Holds the joined data sources that UI HTTP routes read.
///
/// `audit` is the SQLite audit log: always present. `agent_vm` is the
/// running VM daemon: optional, because a broker started without
/// `agent_vm` configured has no VM listing to expose. The `bearer` is
/// the token that gates every request.
#[derive(Clone)]
pub struct UiHttpService {
    audit: Arc<AuditLog>,
    agent_vm: Option<Arc<AgentVmDaemon>>,
    bearer: Arc<UiHttpBearerToken>,
}

impl UiHttpService {
    pub fn new(
        audit: Arc<AuditLog>,
        agent_vm: Option<Arc<AgentVmDaemon>>,
        bearer: UiHttpBearerToken,
    ) -> Self {
        Self {
            audit,
            agent_vm,
            bearer: Arc::new(bearer),
        }
    }

    pub fn bearer(&self) -> &UiHttpBearerToken {
        &self.bearer
    }

    pub(crate) fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub(crate) fn agent_vm(&self) -> Option<&AgentVmDaemon> {
        self.agent_vm.as_deref()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UiHttpRuntimeError {
    #[error("cannot bind UI HTTP listener on {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
}

pub async fn bind_ui_http_listener(addr: SocketAddr) -> Result<TcpListener, UiHttpRuntimeError> {
    TcpListener::bind(addr)
        .await
        .map_err(|source| UiHttpRuntimeError::Bind { addr, source })
}

/// Accept-loop entry point. Returns when `shutdown` fires `true`.
pub async fn run_ui_http_until_shutdown(
    listener: TcpListener,
    service: UiHttpService,
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
            Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                report_ui_http_handler_result(result);
            }
            accepted = listener.accept(), if handlers.len() < MAX_UI_HTTP_CONNECTIONS => {
                let (stream, peer_addr) = accepted?;
                let service = service.clone();
                handlers.spawn(async move {
                    handle_ui_http_connection(stream, peer_addr, service).await
                });
            }
        }
    }

    while let Some(result) = handlers.join_next().await {
        report_ui_http_handler_result(result);
    }
    Ok(())
}

fn report_ui_http_handler_result(result: Result<std::io::Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::warn!(error = %err, "ui http connection error"),
        Err(err) => tracing::error!(error = %err, "ui http connection task failed"),
    }
}

async fn handle_ui_http_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    service: UiHttpService,
) -> std::io::Result<()> {
    let span = tracing::info_span!("ui_http.connection", peer = %peer_addr);
    handle_ui_http_connection_inner(stream, service)
        .instrument(span)
        .await
}

async fn handle_ui_http_connection_inner(
    stream: TcpStream,
    service: UiHttpService,
) -> std::io::Result<()> {
    let service = Arc::new(service);
    let result = http1::Builder::new()
        .keep_alive(false)
        .timer(TokioTimer::new())
        .header_read_timeout(UI_HTTP_READ_TIMEOUT)
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req: http::Request<Incoming>| {
                let service = Arc::clone(&service);
                async move {
                    Ok::<_, std::convert::Infallible>(serve_ui_http_request(&service, req).await)
                }
            }),
        )
        .await;
    if let Err(err) = result {
        tracing::warn!(error = %err, "ui http connection ended with hyper error");
    }
    Ok(())
}

/// One-line tag used in error JSON bodies. Clients branch on the
/// tag rather than parsing free-form prose.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum UiHttpErrorTag {
    MissingBearer,
    InvalidBearer,
    MethodNotAllowed,
    NotFound,
    MalformedSessionId,
    UnknownSession,
    Internal,
}

impl UiHttpErrorTag {
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingBearer => "missing_bearer",
            Self::InvalidBearer => "invalid_bearer",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::NotFound => "not_found",
            Self::MalformedSessionId => "malformed_session_id",
            Self::UnknownSession => "unknown_session",
            Self::Internal => "internal",
        }
    }

    fn status(self) -> u16 {
        match self {
            Self::MissingBearer | Self::InvalidBearer => 401,
            Self::MethodNotAllowed => 405,
            Self::NotFound | Self::MalformedSessionId | Self::UnknownSession => 404,
            Self::Internal => 503,
        }
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed: Option<Vec<&'static str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

pub(crate) struct UiHttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl UiHttpResponse {
    pub(crate) fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self {
            status,
            body: serde_json::to_vec(value).expect("UI HTTP response always serializes"),
        }
    }

    pub(crate) fn error(tag: UiHttpErrorTag) -> Self {
        Self::error_with(tag, None, None, None)
    }

    pub(crate) fn error_with_session_id(tag: UiHttpErrorTag, session_id: String) -> Self {
        Self::error_with(tag, Some(session_id), None, None)
    }

    pub(crate) fn error_method_not_allowed(allowed: Vec<&'static str>) -> Self {
        Self::error_with(UiHttpErrorTag::MethodNotAllowed, None, Some(allowed), None)
    }

    pub(crate) fn error_internal(message: String) -> Self {
        Self::error_with(UiHttpErrorTag::Internal, None, None, Some(message))
    }

    fn error_with(
        tag: UiHttpErrorTag,
        session_id: Option<String>,
        allowed: Option<Vec<&'static str>>,
        message: Option<String>,
    ) -> Self {
        let body = ErrorBody {
            error: tag.as_str(),
            session_id,
            allowed,
            message,
        };
        Self::json(tag.status(), &body)
    }

    fn into_hyper_response(self) -> http::Response<UnsyncBoxBody<Bytes, std::io::Error>> {
        let mut builder = http::Response::builder()
            .status(self.status)
            .header(
                http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .header(http::header::CONNECTION, "close");
        if self.status == 401 {
            builder = builder.header(http::header::WWW_AUTHENTICATE, "Bearer");
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
            .expect("UiHttpResponse always builds a valid hyper response")
    }
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
}

async fn serve_ui_http_request<B>(
    service: &UiHttpService,
    request: http::Request<B>,
) -> http::Response<UnsyncBoxBody<Bytes, std::io::Error>>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let response = dispatch_ui_http_request(service, request).await;
    response.into_hyper_response()
}

async fn dispatch_ui_http_request<B>(
    service: &UiHttpService,
    request: http::Request<B>,
) -> UiHttpResponse
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let (parts, _body) = request.into_parts();
    if let Err(response) = authorize(service.bearer(), &parts.headers) {
        log_ui_http_request(parts.method.as_str(), parts.uri.path(), response.status);
        return response;
    }
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.path().to_string())
        .unwrap_or_else(|| "/".into());
    let method = parts.method.as_str().to_string();
    let response = route(service, &method, &path).await;
    log_ui_http_request(&method, &path, response.status);
    response
}

fn log_ui_http_request(method: &str, target: &str, status: u16) {
    tracing::info!(method, target, status, "ui http request");
}

fn authorize(
    expected: &UiHttpBearerToken,
    headers: &http::HeaderMap,
) -> Result<(), UiHttpResponse> {
    use subtle::ConstantTimeEq as _;
    let mut iter = headers.get_all(http::header::AUTHORIZATION).into_iter();
    let first = iter.next();
    if iter.next().is_some() {
        return Err(UiHttpResponse::error(UiHttpErrorTag::InvalidBearer));
    }
    let Some(value) = first else {
        return Err(UiHttpResponse::error(UiHttpErrorTag::MissingBearer));
    };
    let Ok(header) = std::str::from_utf8(value.as_bytes()) else {
        return Err(UiHttpResponse::error(UiHttpErrorTag::InvalidBearer));
    };
    let Some(token) = header.strip_prefix("Bearer ") else {
        return Err(UiHttpResponse::error(UiHttpErrorTag::InvalidBearer));
    };
    if token.as_bytes().ct_eq(expected.as_str().as_bytes()).into() {
        Ok(())
    } else {
        Err(UiHttpResponse::error(UiHttpErrorTag::InvalidBearer))
    }
}

async fn route(service: &UiHttpService, method: &str, path: &str) -> UiHttpResponse {
    // Health-check is the one route that never depends on broker state;
    // it lets the operator verify the listener + bearer round-trip
    // before anything else is configured.
    if path == "/v1/health" {
        if method != "GET" {
            return UiHttpResponse::error_method_not_allowed(vec!["GET"]);
        }
        return UiHttpResponse::json(200, &HealthResponse { ok: true });
    }

    if path == "/v1/agent-vms" {
        if method != "GET" {
            return UiHttpResponse::error_method_not_allowed(vec!["GET"]);
        }
        return agent_vms::list(service).await;
    }

    if let Some(suffix) = path.strip_prefix("/v1/agent-vms/") {
        if method != "GET" {
            return UiHttpResponse::error_method_not_allowed(vec!["GET"]);
        }
        if suffix.is_empty() || suffix.contains('/') {
            return UiHttpResponse::error(UiHttpErrorTag::NotFound);
        }
        return agent_vms::detail(service, suffix).await;
    }

    UiHttpResponse::error(UiHttpErrorTag::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::SessionId;
    use bytes::Bytes;
    use http_body_util::Full;

    fn make_service(bearer: &str) -> UiHttpService {
        let audit = Arc::new(AuditLog::open_in_memory().unwrap());
        UiHttpService::new(audit, None, UiHttpBearerToken::new(bearer).unwrap())
    }

    async fn body_string(response: http::Response<UnsyncBoxBody<Bytes, std::io::Error>>) -> String {
        let (_, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn empty_request(
        method: &str,
        target: &str,
        bearer: Option<&str>,
    ) -> http::Request<Full<Bytes>> {
        let mut builder = http::Request::builder().method(method).uri(target);
        if let Some(b) = bearer {
            builder = builder.header(http::header::AUTHORIZATION, format!("Bearer {b}"));
        }
        builder.body(Full::new(Bytes::new())).unwrap()
    }

    #[tokio::test]
    async fn health_returns_ok_with_bearer() {
        let service = make_service("ui-test-bearer-123");
        let resp = serve_ui_http_request(
            &service,
            empty_request("GET", "/v1/health", Some("ui-test-bearer-123")),
        )
        .await;
        assert_eq!(resp.status(), 200);
        let body = body_string(resp).await;
        assert!(body.contains("\"ok\":true"));
    }

    #[tokio::test]
    async fn missing_bearer_returns_401_with_tag() {
        let service = make_service("ui-test-bearer-123");
        let resp = serve_ui_http_request(&service, empty_request("GET", "/v1/health", None)).await;
        assert_eq!(resp.status(), 401);
        let www = resp
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .map(|v| v.to_str().unwrap().to_string());
        assert_eq!(www.as_deref(), Some("Bearer"));
        let body = body_string(resp).await;
        assert!(
            body.contains("\"error\":\"missing_bearer\""),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn wrong_bearer_returns_401_invalid() {
        let service = make_service("ui-test-bearer-123");
        let resp =
            serve_ui_http_request(&service, empty_request("GET", "/v1/health", Some("wrong")))
                .await;
        assert_eq!(resp.status(), 401);
        let body = body_string(resp).await;
        assert!(
            body.contains("\"error\":\"invalid_bearer\""),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn non_bearer_authorization_returns_401_invalid() {
        let service = make_service("ui-test-bearer-123");
        let mut req = empty_request("GET", "/v1/health", None);
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        let resp = serve_ui_http_request(&service, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn duplicate_authorization_headers_rejected() {
        let service = make_service("ui-test-bearer-123");
        let mut req = empty_request("GET", "/v1/health", Some("ui-test-bearer-123"));
        req.headers_mut().append(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer ui-test-bearer-123"),
        );
        let resp = serve_ui_http_request(&service, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn post_on_health_returns_405_with_allowed_list() {
        let service = make_service("ui-test-bearer-123");
        let resp = serve_ui_http_request(
            &service,
            empty_request("POST", "/v1/health", Some("ui-test-bearer-123")),
        )
        .await;
        assert_eq!(resp.status(), 405);
        let body = body_string(resp).await;
        assert!(
            body.contains("\"error\":\"method_not_allowed\""),
            "body: {body}"
        );
        assert!(body.contains("\"GET\""), "body: {body}");
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let service = make_service("ui-test-bearer-123");
        let resp = serve_ui_http_request(
            &service,
            empty_request("GET", "/v1/nope", Some("ui-test-bearer-123")),
        )
        .await;
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn agent_vms_list_without_daemon_returns_empty_list() {
        let service = make_service("ui-test-bearer-123");
        let resp = serve_ui_http_request(
            &service,
            empty_request("GET", "/v1/agent-vms", Some("ui-test-bearer-123")),
        )
        .await;
        assert_eq!(resp.status(), 200);
        let body = body_string(resp).await;
        assert_eq!(body, "{\"agent_vms\":[]}");
    }

    #[tokio::test]
    async fn agent_vms_detail_without_daemon_returns_404_unknown() {
        let service = make_service("ui-test-bearer-123");
        let id = SessionId::new();
        let target = format!("/v1/agent-vms/{}", id);
        let resp = serve_ui_http_request(
            &service,
            empty_request("GET", &target, Some("ui-test-bearer-123")),
        )
        .await;
        assert_eq!(resp.status(), 404);
        let body = body_string(resp).await;
        assert!(
            body.contains("\"error\":\"unknown_session\""),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn agent_vms_detail_with_garbage_id_returns_404_malformed() {
        let service = make_service("ui-test-bearer-123");
        let resp = serve_ui_http_request(
            &service,
            empty_request(
                "GET",
                "/v1/agent-vms/not-a-uuid",
                Some("ui-test-bearer-123"),
            ),
        )
        .await;
        assert_eq!(resp.status(), 404);
        let body = body_string(resp).await;
        assert!(
            body.contains("\"error\":\"malformed_session_id\""),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn bearer_token_redacts_in_debug() {
        let token = UiHttpBearerToken::new("ui-test-secret-abc").unwrap();
        let debug = format!("{:?}", token);
        assert!(
            !debug.contains("ui-test-secret-abc"),
            "debug leaked: {debug}"
        );
        assert!(debug.contains("redacted"), "debug: {debug}");
    }

    #[test]
    fn bearer_token_rejects_invalid_characters() {
        assert_eq!(
            UiHttpBearerToken::new(""),
            Err(UiHttpBearerTokenError::Empty)
        );
        assert_eq!(
            UiHttpBearerToken::new("space inside"),
            Err(UiHttpBearerTokenError::InvalidCharacter)
        );
    }

    #[test]
    fn write_bearer_file_writes_0600_and_token_matches() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("subdir/ui-bearer");
        let token = UiHttpBearerToken::generate();
        write_bearer_file(&path, &token).unwrap();
        let read = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read, token.as_str());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }

    #[test]
    fn write_bearer_file_creates_parent_with_0700() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("fresh-parent");
        let path = parent.join("ui-bearer");
        let token = UiHttpBearerToken::generate();
        write_bearer_file(&path, &token).unwrap();
        let mode = std::fs::metadata(&parent).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "expected 0700, got {:o}", mode & 0o777);
    }

    /// `tempfile::tempdir()` honours the process umask, so on a
    /// typical macOS dev box the tempdir comes back as `0o755`. The
    /// production-side parent-privacy check correctly rejects that,
    /// so tests that exercise `write_bearer_file` against an existing
    /// parent must pin the parent to `0o700` themselves.
    fn private_tempdir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        tmp
    }

    #[test]
    fn write_bearer_file_forces_0600_when_temp_exists_with_loose_perms() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = private_tempdir();
        let path = tmp.path().join("ui-bearer");
        let stale_tmp = tmp.path().join("ui-bearer.tmp");
        std::fs::write(&stale_tmp, "stale").unwrap();
        std::fs::set_permissions(&stale_tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        let token = UiHttpBearerToken::generate();
        write_bearer_file(&path, &token).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "expected 0600 even when stale temp existed, got {:o}",
            mode & 0o777
        );
        let read = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read, token.as_str());
    }

    #[test]
    fn write_bearer_file_rejects_non_private_parent() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("public-parent");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = parent.join("ui-bearer");
        let token = UiHttpBearerToken::generate();
        let err = write_bearer_file(&path, &token).expect_err("non-private parent rejected");
        match err {
            UiHttpBearerWriteError::NonPrivateParent {
                path: rejected,
                mode,
            } => {
                assert_eq!(rejected, parent);
                assert_eq!(mode, 0o755);
            }
            other => panic!("expected NonPrivateParent, got {other:?}"),
        }
        assert!(!path.exists(), "bearer must not be written");
    }

    /// If a local attacker plants `ui-bearer.tmp` as a symlink to a
    /// world-readable victim file, the trusted-parent invariant
    /// ensures the symlink can't appear there in the first place;
    /// but in case the invariant is ever bypassed (e.g. a future
    /// caller skipped the parent check), `create_new` would refuse
    /// to follow the symlink. This test demonstrates that the
    /// stale-temp cleanup path replaces the symlink rather than
    /// writing through it.
    #[test]
    fn write_bearer_file_unlinks_stale_temp_symlink() {
        let tmp = private_tempdir();
        let path = tmp.path().join("ui-bearer");
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, "original-contents").unwrap();
        let stale_tmp = tmp.path().join("ui-bearer.tmp");
        std::os::unix::fs::symlink(&victim, &stale_tmp).unwrap();
        let token = UiHttpBearerToken::generate();
        write_bearer_file(&path, &token).unwrap();
        let victim_contents = std::fs::read_to_string(&victim).unwrap();
        assert_eq!(
            victim_contents, "original-contents",
            "symlink target must not be overwritten"
        );
        let bearer_contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(bearer_contents, token.as_str());
    }

    #[test]
    fn write_bearer_file_replaces_existing() {
        let tmp = private_tempdir();
        let path = tmp.path().join("ui-bearer");
        let t1 = UiHttpBearerToken::new("first-token-xyz").unwrap();
        let t2 = UiHttpBearerToken::new("second-token-xyz").unwrap();
        write_bearer_file(&path, &t1).unwrap();
        write_bearer_file(&path, &t2).unwrap();
        let read = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read, t2.as_str());
    }

    /// End-to-end: bind a real TCP listener on a loopback ephemeral port,
    /// run the accept loop, issue a request through a fresh TCP socket,
    /// and assert that the listener serves the expected JSON. This is
    /// the only test that catches hyper integration regressions —
    /// the rest exercise the request pipeline at the `serve_ui_http_request`
    /// seam.
    #[tokio::test]
    async fn listener_round_trip_over_tcp() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let listener = bind_ui_http_listener(bind).await.unwrap();
        let local = listener.local_addr().unwrap();
        let service = make_service("ui-test-bearer-tcp");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(run_ui_http_until_shutdown(listener, service, shutdown_rx));

        let mut stream = tokio::net::TcpStream::connect(local).await.unwrap();
        let request = "GET /v1/health HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Authorization: Bearer ui-test-bearer-tcp\r\n\
             Connection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8(buf).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
        assert!(
            response.contains("\"ok\":true"),
            "response body missing ok flag: {response}"
        );

        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
    }

    /// Auditor-side fields (label, agent_kind, opened_at) propagate into
    /// the list row when the session is open in the audit log but the
    /// daemon is unavailable. With no daemon the list is empty, so this
    /// test asserts the negative case at the listener seam.
    #[tokio::test]
    async fn list_route_returns_envelope_with_empty_array_when_daemon_absent() {
        let service = make_service("ui-test-bearer-123");
        let resp = serve_ui_http_request(
            &service,
            empty_request("GET", "/v1/agent-vms", Some("ui-test-bearer-123")),
        )
        .await;
        assert_eq!(resp.status(), 200);
        let ct = resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string());
        assert_eq!(ct.as_deref(), Some("application/json; charset=utf-8"));
        let conn = resp
            .headers()
            .get(http::header::CONNECTION)
            .map(|v| v.to_str().unwrap().to_string());
        assert_eq!(conn.as_deref(), Some("close"));
        let body = body_string(resp).await;
        assert_eq!(body, "{\"agent_vms\":[]}");
    }
}
