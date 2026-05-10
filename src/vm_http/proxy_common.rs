//! Shared helpers used by both the Claude and OpenAI VM HTTP proxies.
//!
//! Anything in here is identical between the two backends — request-target
//! parsing, JSON-streaming detection, the upstream content-type allowlist,
//! the chunked upstream body reader, and the carrier types used to hand a
//! buffered fetch or a streaming upstream response back to the dispatcher.
//! Backend-specific routing, authentication, and audit shape are selected
//! through the `ProxyBackend` trait; the orchestration logic that follows
//! the request all the way to the upstream and back lives here generically.

use std::borrow::Cow;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use http_body_util::BodyExt as _;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::{Body as HyperBody, Frame};

use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, AuditLog, ClaudeProxyOutcomeRecord,
    OpenAiProxyOutcomeRecord,
};
use crate::core::{RequestId, SessionId, UnixMillis};
use crate::openai_chatgpt_auth::ChatgptUpstreamHeaders;
use crate::secret::SecretStore;
use crate::server::BrokerState;

use super::{
    VmHttpDispatch, VmHttpHeader, VmHttpRequest, VmHttpResponse, VmHttpResponseHeader,
    VmHttpSession, VmHttpStatus,
};

const ANTHROPIC_OAUTH_BETA_HEADER_VALUE: &str = "oauth-2025-04-20";

/// Resolved upstream authentication for a single proxy request.
///
/// Each backend resolves its scheme-specific config (a static API key,
/// a refreshed OAuth bundle) into one of these variants, and the
/// request builder applies the wire-level headers in one place. New
/// auth shapes are added here, not in the per-backend builder paths.
pub(super) enum UpstreamAuth {
    /// `x-api-key: <secret>`. Used by Claude with a static Anthropic API key.
    XApiKey(String),
    /// `Authorization: Bearer <secret>`. Used for OpenAI API keys and for
    /// Claude's plain-bearer auth shape.
    Bearer(String),
    /// `Authorization: Bearer <secret>` plus `anthropic-beta: oauth-…`.
    /// Used by Claude's OAuth (Claude-Code-style) auth shape.
    AnthropicOauth(String),
    /// ChatGPT-login OAuth: bearer access token plus the
    /// `ChatGPT-Account-ID` and (when applicable) `X-OpenAI-Fedramp`
    /// headers expected by the Responses API.
    ChatgptOauth(ChatgptUpstreamHeaders),
}

impl UpstreamAuth {
    pub(super) fn apply_to(self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            UpstreamAuth::XApiKey(secret) => builder.header("x-api-key", secret),
            UpstreamAuth::Bearer(secret) => builder.bearer_auth(secret),
            UpstreamAuth::AnthropicOauth(secret) => builder
                .bearer_auth(secret)
                .header("anthropic-beta", ANTHROPIC_OAUTH_BETA_HEADER_VALUE),
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

/// Strip the query string from a request target.
///
/// We forward path-only requests upstream so the guest cannot expand the
/// surface area beyond what the broker has explicitly classified.
pub(super) fn proxy_target_path(target: &str) -> &str {
    target
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(target)
}

/// Bytes accepted in path-segment identifiers (model IDs, response IDs).
pub(super) fn is_proxy_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

/// Inspect a request body for `{"stream": true}` at the top level.
///
/// Used to decide whether to forward the upstream response as a streamed
/// hyper body or buffer it. Anything other than `true` (missing field,
/// invalid JSON) means buffer.
pub(super) fn proxy_request_wants_streaming(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("stream").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

/// Map an upstream response's `Content-Type` to the small allowlist of
/// types we relay back to the guest. Anything off the allowlist is
/// normalised to `application/json` to keep the guest-facing surface
/// predictable.
pub(super) fn proxy_response_content_type(response: &reqwest::Response) -> &'static str {
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

/// Failure reading the upstream proxy response body up to a configured cap.
///
/// Both variants record the number of bytes already accepted so the audit
/// log captures partial-read sizes.
#[derive(Debug, thiserror::Error)]
pub(super) enum ProxyUpstreamBodyError {
    #[error("upstream response body read failed after {bytes_read} bytes: {source}")]
    Request {
        source: reqwest::Error,
        bytes_read: u64,
    },
    #[error("upstream response exceeds {max} bytes after {bytes_read} bytes")]
    ResponseTooLarge { max: u64, bytes_read: u64 },
}

impl ProxyUpstreamBodyError {
    pub(super) fn audit_error_label(&self) -> &'static str {
        match self {
            Self::Request { .. } => "upstream body read failed",
            Self::ResponseTooLarge { .. } => "upstream response too large",
        }
    }

    pub(super) fn bytes_read(&self) -> u64 {
        match self {
            Self::Request { bytes_read, .. } | Self::ResponseTooLarge { bytes_read, .. } => {
                *bytes_read
            }
        }
    }
}

/// Read an upstream response body into memory, bailing out as soon as
/// the configured `max` byte count would be exceeded.
pub(super) async fn read_upstream_body_bounded(
    mut response: reqwest::Response,
    max: u64,
) -> Result<Vec<u8>, ProxyUpstreamBodyError> {
    let mut body = Vec::new();
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(source) => {
                return Err(ProxyUpstreamBodyError::Request {
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
            return Err(ProxyUpstreamBodyError::ResponseTooLarge {
                max,
                bytes_read: new_len,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Selector for the audit log a streaming proxy response writes its
/// outcome record to. Implementations are zero-sized markers; the
/// trait is implemented at the type level so dispatch is static.
///
/// Outcome recording on this trait is best-effort and asymmetric with
/// the buffered path's `ProxyBackend::record_outcome_audit`; see
/// `record_outcome` for why.
pub(super) trait ProxyAudit: 'static {
    /// Human-readable backend label for diagnostic logging.
    const DISPLAY_NAME: &'static str;
    /// Persist a streaming-proxy outcome record. Infallible by design:
    /// this is called from `ProxyStreamBody::drop` after the response
    /// body has already started flowing to the guest, so there is no
    /// HTTP status left to fail with. Audit-write failures are emitted
    /// to tracing under `AUDIT_WRITE_FAILURE_TARGET` and swallowed; the
    /// guest's response is unaffected and the request row remains in
    /// the audit log without a paired outcome row.
    ///
    /// Deliberately asymmetric with the buffered path
    /// (`ProxyBackend::record_outcome_audit`), which is fallible and
    /// 500s the guest on audit-write failure because the response has
    /// not yet been sent there. Reconciliation of orphaned request
    /// rows is an audit-log concern, not a transport concern.
    fn record_outcome(audit_log: &AuditLog, fields: ProxyOutcomeFields<'_>);
}

/// Audit decision attached to a recorded proxy request.
/// Borrow-friendly mirror of [`crate::audit::ProxyAuditDecision`]: the
/// orchestration code often holds a `&'static str` for the deny
/// reason, so accepting a `Cow` here avoids forcing the call site to
/// allocate. The conversion to the owned audit-record shape happens
/// in [`proxy_decision_to_owned`] just before the audit write.
#[derive(Debug)]
pub(super) enum ProxyAuditDecision<'a> {
    Allow,
    Deny { reason: Cow<'a, str> },
}

/// Translate the borrow-friendly orchestration decision into the
/// owned shape every per-backend audit-record write expects. Single
/// implementation because the per-backend
/// `*ProxyAuditDecision` types are all aliases of the same
/// `crate::audit::ProxyAuditDecision`.
pub(super) fn proxy_decision_to_owned(
    decision: &ProxyAuditDecision<'_>,
) -> crate::audit::ProxyAuditDecision {
    match decision {
        ProxyAuditDecision::Allow => crate::audit::ProxyAuditDecision::Allow,
        ProxyAuditDecision::Deny { reason } => crate::audit::ProxyAuditDecision::Deny {
            reason: reason.clone().into_owned(),
        },
    }
}

/// Fields handed to a `ProxyBackend::record_request_audit` call, mirroring
/// the structurally-identical per-backend request records.
#[derive(Copy, Clone, Debug)]
pub(super) struct ProxyRequestFields<'a, R> {
    pub(super) request_id: RequestId,
    pub(super) session_id: SessionId,
    pub(super) received_at: UnixMillis,
    pub(super) method: &'a str,
    pub(super) target: &'a str,
    pub(super) route: R,
    pub(super) decision: &'a ProxyAuditDecision<'a>,
}

/// Common configuration accessors the generic VM HTTP proxy service
/// reads from a backend's per-provider config. Per-backend configs
/// expose more (auth secrets, request caps, anthropic-version, ChatGPT
/// refresh URL) via inherent methods; this trait only carries what the
/// generic transport layer needs.
pub(super) trait ProxyBackendConfig: Clone + Send + Sync + 'static {
    fn upstream_base_url(&self) -> &reqwest::Url;
    fn timeout(&self) -> std::time::Duration;
    fn max_response_bytes(&self) -> u64;
}

/// Per-backend behaviour the VM HTTP proxy dispatcher relies on.
///
/// Implementations are zero-sized types (one per upstream provider)
/// that select a target/route classification, an auth-shape selector,
/// a header allowlist, an upstream-URL shape, an auth-resolution
/// strategy, and the audit-record types. Audit-log selection for the
/// streaming-Drop path is inherited via the `ProxyAudit` supertrait,
/// so a single backend marker carries every per-provider decision the
/// dispatcher needs to make.
pub(super) trait ProxyBackend: ProxyAudit + Sized {
    /// The audit-log route enum the backend classifies a target into
    /// (e.g., `ClaudeProxyAuditRoute`).
    type Route: Copy + Send + 'static;
    /// The auth-shape selector this backend supports (e.g.,
    /// `VmHttpClaudeProxyAuthKind`).
    type AuthKind: Copy;
    /// Per-provider config carrying the upstream URL, timeouts, the
    /// auth secret, and any backend-specific knobs.
    type Config: ProxyBackendConfig;
    /// Per-service in-memory state that does not belong on `Config`.
    /// Today this is the ChatGPT-OAuth refresh authority for the
    /// OpenAI backend and `()` for Claude.
    type Extras: Clone + Send + Sync + 'static;

    /// Body returned to the guest when the upstream call fails (e.g.
    /// connection error, body read failure). One per backend so the
    /// guest can tell `Claude proxy upstream failed` from
    /// `OpenAI proxy upstream failed`.
    const UPSTREAM_FAIL_BODY: &'static str;
    /// Audit decision reason recorded when a guest hits a path the
    /// backend classifies but does not actually proxy.
    const UNSUPPORTED_ROUTE_REASON: &'static str;
    /// `kind = …` field on the tracing record emitted when a request
    /// audit-write fails.
    const REQUEST_AUDIT_KIND: &'static str;
    /// `kind = …` field on the tracing record emitted when an outcome
    /// audit-write fails.
    const OUTCOME_AUDIT_KIND: &'static str;

    /// Classify a guest-facing request target into one of this
    /// backend's audit routes, or `None` if the target is not a proxy
    /// request for this backend.
    fn classify_proxy_target(target: &str) -> Option<Self::Route>;

    /// Whether the target belongs to this backend at all. Defaulted
    /// via `classify_proxy_target` so backend impls only state the
    /// classification once.
    fn is_proxy_target(target: &str) -> bool {
        Self::classify_proxy_target(target).is_some()
    }

    /// Whether a classified route is one the broker will refuse rather
    /// than forward. Used by the dispatcher to short-circuit before
    /// any upstream call.
    fn route_is_unsupported(route: Self::Route) -> bool;

    /// HTTP method the broker uses on the upstream call for a
    /// classified, supported route.
    fn route_method(route: Self::Route) -> reqwest::Method;

    /// Map a guest-supplied request header name into the canonical
    /// header name to forward upstream. Returning `None` drops the
    /// header. The `auth_kind` argument is used because some headers
    /// (e.g., `anthropic-beta`) are only forwarded for specific auth
    /// shapes.
    fn forward_header_name(
        raw: &str,
        auth_kind: Self::AuthKind,
    ) -> Option<reqwest::header::HeaderName>;

    /// Map an upstream response header name into the canonical header
    /// name to forward back to the guest. Returning `None` drops the
    /// header.
    fn response_header_name(raw: &str) -> Option<&'static str>;

    /// Compute the relative upstream path (joined onto
    /// `Config::upstream_base_url`) for a guest request target, or
    /// `None` if this backend would not actually proxy that target.
    fn relative_upstream_path(target: &str, config: &Self::Config) -> Option<Cow<'static, str>>;

    /// Build the per-request list of forwarded headers from the
    /// guest's request headers, applying the backend's allowlist and
    /// any backend-injected header (e.g. Claude's `Anthropic-Version`).
    fn forward_headers(
        request_headers: &[VmHttpHeader],
        config: &Self::Config,
    ) -> Result<Vec<ProxyForwardHeader>, &'static str>;

    /// Build the per-service `Extras` value at construction time from
    /// the validated config. Returning `Err` aborts service
    /// construction (currently only the OpenAI ChatGPT-OAuth path uses
    /// this to build a refresh authority).
    fn build_extras(config: &Self::Config) -> Result<Self::Extras, reqwest::Error>;

    /// Resolve the per-request upstream auth from the secret store and
    /// any per-backend extras (e.g. the ChatGPT-OAuth refresh
    /// authority). Errors carry a guest-facing failure response so the
    /// caller does not need to know the per-backend failure shape.
    fn resolve_upstream_auth<S>(
        config: &Self::Config,
        extras: &Self::Extras,
        secret_store: &S,
    ) -> impl Future<Output = Result<UpstreamAuth, Box<ProxyFetch>>> + Send
    where
        S: SecretStore + Send + Sync + ?Sized;

    /// Persist a per-backend proxy-request audit record (translating
    /// from the shared `ProxyRequestFields` to the per-backend
    /// `*ProxyRequestRecord` shape). Fallible because the route
    /// dispatcher converts an audit-write failure into a 500 to the
    /// guest, separately from the tracing record.
    fn record_request_audit(
        audit_log: &AuditLog,
        fields: ProxyRequestFields<'_, Self::Route>,
    ) -> Result<(), AuditError>;

    /// Persist a per-backend proxy-outcome audit record. Used from the
    /// route dispatcher; the streaming-Drop path uses
    /// `ProxyAudit::record_outcome` instead, which is infallible.
    fn record_outcome_audit(
        audit_log: &AuditLog,
        fields: ProxyOutcomeFields<'_>,
    ) -> Result<(), AuditError>;

    /// Wrap an opened `ProxyStream<Self>` into the carrier variant the
    /// VM HTTP dispatcher uses. Today this is `VmHttpDispatch::ClaudeProxyStream`
    /// or `VmHttpDispatch::OpenAiProxyStream`; the trait method keeps
    /// the variant choice with the backend.
    fn into_vm_http_dispatch(stream: ProxyStream<Self>) -> VmHttpDispatch;
}

/// Backend marker selecting the Claude proxy: its routing/header
/// allowlist (via `ProxyBackend`) and its audit log (via `ProxyAudit`).
pub(super) struct ClaudeBackend;

impl ProxyAudit for ClaudeBackend {
    const DISPLAY_NAME: &'static str = "Claude";

    fn record_outcome(audit_log: &AuditLog, fields: ProxyOutcomeFields<'_>) {
        if let Err(err) = audit_log.record_claude_proxy_outcome(&ClaudeProxyOutcomeRecord {
            request_id: fields.request_id,
            completed_at: fields.completed_at,
            http_status: fields.http_status,
            upstream_url: fields.upstream_url,
            upstream_status: fields.upstream_status,
            response_bytes: fields.response_bytes,
            error: fields.error,
        }) {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "claude_proxy_streaming_outcome",
                request_id = %fields.request_id,
                error = %err,
                "audit write failed",
            );
        }
    }
}

/// Backend marker selecting the OpenAI proxy: its routing/header
/// allowlist (via `ProxyBackend`) and its audit log (via `ProxyAudit`).
pub(super) struct OpenAiBackend;

impl ProxyAudit for OpenAiBackend {
    const DISPLAY_NAME: &'static str = "OpenAI";

    fn record_outcome(audit_log: &AuditLog, fields: ProxyOutcomeFields<'_>) {
        if let Err(err) = audit_log.record_openai_proxy_outcome(&OpenAiProxyOutcomeRecord {
            request_id: fields.request_id,
            completed_at: fields.completed_at,
            http_status: fields.http_status,
            upstream_url: fields.upstream_url,
            upstream_status: fields.upstream_status,
            response_bytes: fields.response_bytes,
            error: fields.error,
        }) {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "openai_proxy_streaming_outcome",
                request_id = %fields.request_id,
                error = %err,
                "audit write failed",
            );
        }
    }
}

/// Fields handed to a `ProxyAudit::record_outcome` call. The two
/// existing audit-record types (`ClaudeProxyOutcomeRecord` /
/// `OpenAiProxyOutcomeRecord`) are nominally distinct but structurally
/// identical; this struct lets the caller build them once and the
/// trait impl pick the right one.
#[derive(Copy, Clone, Debug)]
pub(super) struct ProxyOutcomeFields<'a> {
    pub(super) request_id: RequestId,
    pub(super) completed_at: UnixMillis,
    pub(super) http_status: u16,
    pub(super) upstream_url: Option<&'a str>,
    pub(super) upstream_status: Option<u16>,
    pub(super) response_bytes: u64,
    pub(super) error: Option<&'static str>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum ProxyStreamState {
    Streaming,
    UpstreamEnded,
    UpstreamError,
    OverMax,
}

pub(super) struct ProxyStreamAudit {
    pub(super) audit_log: Arc<AuditLog>,
    pub(super) request_id: RequestId,
    pub(super) upstream_url: String,
    pub(super) upstream_status: u16,
}

pub(super) struct ProxyStreamBody<A: ProxyAudit> {
    pub(super) inner: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
    pub(super) audit: Option<ProxyStreamAudit>,
    pub(super) max_response_bytes: u64,
    pub(super) response_bytes: u64,
    pub(super) state: ProxyStreamState,
    pub(super) _audit_kind: PhantomData<fn() -> A>,
}

impl<A: ProxyAudit> HyperBody for ProxyStreamBody<A> {
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
                tracing::warn!(
                    proxy = A::DISPLAY_NAME,
                    error = %err,
                    "vm http proxy streaming body read failed",
                );
                me.state = ProxyStreamState::UpstreamError;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(chunk))) => {
                let chunk_len = u64::try_from(chunk.len()).expect("HTTP chunk length fits in u64");
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

impl<A: ProxyAudit> Drop for ProxyStreamBody<A> {
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
        A::record_outcome(
            &audit.audit_log,
            ProxyOutcomeFields {
                request_id: audit.request_id,
                completed_at: UnixMillis::now(),
                http_status: audit.upstream_status,
                upstream_url: Some(audit.upstream_url.as_str()),
                upstream_status: Some(audit.upstream_status),
                response_bytes: self.response_bytes,
                error,
            },
        );
    }
}

/// One forwarded request header. The set of headers the broker forwards is
/// backend-specific (see `claude_proxy_forward_header_name` and
/// `openai_proxy_forward_header_name`), but the carrier shape is identical.
pub(super) struct ProxyForwardHeader {
    pub(super) name: reqwest::header::HeaderName,
    pub(super) value: reqwest::header::HeaderValue,
}

/// A buffered upstream fetch result.
///
/// Identical between backends: the only thing that varies is which audit
/// log the dispatcher records the outcome to, and that is decided by the
/// caller, not this struct.
#[derive(Debug)]
pub(super) struct ProxyFetch {
    pub(super) response: VmHttpResponse,
    pub(super) upstream_url: Option<String>,
    pub(super) upstream_status: Option<u16>,
    pub(super) response_bytes: u64,
    pub(super) error: Option<&'static str>,
}

/// A streaming upstream response that has been opened but whose body
/// has not yet been forwarded to the guest. The audit-log selector
/// `A` is a type parameter so completion-record routing is statically
/// dispatched.
pub(crate) struct ProxyStream<A: ProxyAudit> {
    pub(super) audit_log: Arc<AuditLog>,
    pub(super) request_id: RequestId,
    pub(super) response: reqwest::Response,
    pub(super) upstream_url: String,
    pub(super) upstream_status: u16,
    pub(super) content_type: &'static str,
    pub(super) headers: Vec<VmHttpResponseHeader>,
    pub(super) max_response_bytes: u64,
    pub(super) _audit_kind: PhantomData<fn() -> A>,
}

impl<A: ProxyAudit> ProxyStream<A> {
    pub(super) fn into_hyper_response(
        self,
    ) -> http::Response<UnsyncBoxBody<Bytes, std::io::Error>> {
        let body = ProxyStreamBody::<A> {
            inner: Box::pin(self.response.bytes_stream()),
            audit: Some(ProxyStreamAudit {
                audit_log: self.audit_log,
                request_id: self.request_id,
                upstream_url: self.upstream_url,
                upstream_status: self.upstream_status,
            }),
            max_response_bytes: self.max_response_bytes,
            response_bytes: 0,
            state: ProxyStreamState::Streaming,
            _audit_kind: PhantomData,
        };
        let mut builder = http::Response::builder()
            .status(self.upstream_status)
            .header(http::header::CONTENT_TYPE, self.content_type)
            .header(http::header::CONNECTION, "close");
        for header in self.headers {
            builder = builder.header(header.name, header.value);
        }
        builder
            .body(body.boxed_unsync())
            .expect("ProxyStream always builds a valid hyper response")
    }
}

/// Generic VM HTTP proxy service. The backend type-parameter `B`
/// chooses the routing/header allowlist, the upstream URL shape, the
/// auth-resolution strategy, and the audit-record shape; everything
/// else (the reqwest client, the request-buffering and streaming code
/// paths, the upstream body cap) is identical across providers and
/// lives here. Per-backend callers reach this type through the
/// `VmHttpClaudeProxyService` / `VmHttpOpenAiProxyService` aliases.
pub(super) struct VmHttpProxyService<B: ProxyBackend, S: SecretStore + Send + Sync + 'static> {
    pub(super) broker_state: Arc<BrokerState<S>>,
    pub(super) config: B::Config,
    client: reqwest::Client,
    extras: B::Extras,
    _backend: PhantomData<fn() -> B>,
}

impl<B: ProxyBackend, S: SecretStore + Send + Sync + 'static> VmHttpProxyService<B, S> {
    pub(super) fn new(
        broker_state: Arc<BrokerState<S>>,
        config: B::Config,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .connect_timeout(config.timeout())
            .read_timeout(config.timeout())
            .build()?;
        let extras = B::build_extras(&config)?;
        Ok(Self {
            broker_state,
            config,
            client,
            extras,
            _backend: PhantomData,
        })
    }

    fn upstream_url(&self, target: &str) -> Option<reqwest::Url> {
        let relative = B::relative_upstream_path(target, &self.config)?;
        Some(
            self.config
                .upstream_base_url()
                .join(&relative)
                .expect("proxy backend route paths are URL-safe relative paths"),
        )
    }

    async fn upstream_request_builder(
        &self,
        request: &VmHttpRequest,
        body: Vec<u8>,
        headers: Vec<ProxyForwardHeader>,
    ) -> Result<(String, reqwest::RequestBuilder), Box<ProxyFetch>> {
        let Some(route) = B::classify_proxy_target(&request.target) else {
            let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
            return Err(Box::new(ProxyFetch {
                response_bytes: response.body.len() as u64,
                response,
                upstream_url: None,
                upstream_status: None,
                error: None,
            }));
        };
        let Some(url) = self.upstream_url(&request.target) else {
            let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
            return Err(Box::new(ProxyFetch {
                response_bytes: response.body.len() as u64,
                response,
                upstream_url: None,
                upstream_status: None,
                error: None,
            }));
        };
        let upstream_url = url.to_string();
        let upstream_auth =
            B::resolve_upstream_auth(&self.config, &self.extras, &self.broker_state.secrets)
                .await
                .map_err(|mut fetch| {
                    fetch.upstream_url = Some(upstream_url.clone());
                    fetch
                })?;

        let mut builder = self.client.request(B::route_method(route), url);
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
        headers: Vec<ProxyForwardHeader>,
    ) -> ProxyFetch {
        let (upstream_url, builder) =
            match self.upstream_request_builder(request, body, headers).await {
                Ok(parts) => parts,
                Err(fetch) => return *fetch,
            };

        let response = match builder.send().await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(
                    proxy = B::DISPLAY_NAME,
                    upstream_url = %upstream_url,
                    error = %err,
                    "vm http proxy upstream request failed",
                );
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, B::UPSTREAM_FAIL_BODY);
                return ProxyFetch {
                    response_bytes: response.body.len() as u64,
                    response,
                    upstream_url: Some(upstream_url),
                    upstream_status: None,
                    error: Some("upstream request failed"),
                };
            }
        };

        let upstream_status = response.status();
        let content_type = proxy_response_content_type(&response);
        let response_headers = collect_response_headers::<B>(response.headers());
        let body =
            match read_upstream_body_bounded(response, self.config.max_response_bytes()).await {
                Ok(body) => body,
                Err(err) => {
                    tracing::warn!(
                        proxy = B::DISPLAY_NAME,
                        upstream_url = %upstream_url,
                        upstream_status = upstream_status.as_u16(),
                        error = %err,
                        "vm http proxy upstream body read failed",
                    );
                    let response =
                        VmHttpResponse::text(VmHttpStatus::BadGateway, B::UPSTREAM_FAIL_BODY);
                    return ProxyFetch {
                        response_bytes: err.bytes_read(),
                        response,
                        upstream_url: Some(upstream_url),
                        upstream_status: Some(upstream_status.as_u16()),
                        error: Some(err.audit_error_label()),
                    };
                }
            };
        let response_bytes = body.len() as u64;
        ProxyFetch {
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
        headers: Vec<ProxyForwardHeader>,
    ) -> Result<ProxyStream<B>, ProxyFetch> {
        let (upstream_url, builder) = self
            .upstream_request_builder(request, body, headers)
            .await
            .map_err(|fetch| *fetch)?;
        let response = match builder.send().await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(
                    proxy = B::DISPLAY_NAME,
                    request_id = %request_id,
                    upstream_url = %upstream_url,
                    error = %err,
                    "vm http proxy upstream request failed",
                );
                let response =
                    VmHttpResponse::text(VmHttpStatus::BadGateway, B::UPSTREAM_FAIL_BODY);
                return Err(ProxyFetch {
                    response_bytes: response.body.len() as u64,
                    response,
                    upstream_url: Some(upstream_url),
                    upstream_status: None,
                    error: Some("upstream request failed"),
                });
            }
        };
        let upstream_status = response.status().as_u16();
        let content_type = proxy_response_content_type(&response);
        let headers = collect_response_headers::<B>(response.headers());
        Ok(ProxyStream {
            audit_log: Arc::clone(&self.broker_state.audit),
            request_id,
            response,
            upstream_url,
            upstream_status,
            content_type,
            headers,
            max_response_bytes: self.config.max_response_bytes(),
            _audit_kind: PhantomData,
        })
    }
}

impl<B: ProxyBackend, S: SecretStore + Send + Sync + 'static> Clone for VmHttpProxyService<B, S> {
    fn clone(&self) -> Self {
        Self {
            broker_state: Arc::clone(&self.broker_state),
            config: self.config.clone(),
            client: self.client.clone(),
            extras: self.extras.clone(),
            _backend: PhantomData,
        }
    }
}

fn collect_response_headers<B: ProxyBackend>(
    headers: &reqwest::header::HeaderMap,
) -> Vec<VmHttpResponseHeader> {
    let mut out = Vec::new();
    for (name, value) in headers {
        let Some(forward_name) = B::response_header_name(name.as_str()) else {
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

/// Generic dispatcher for an authenticated VM HTTP proxy request that
/// targets a backend `B`. Identical to the per-backend
/// `route_*_proxy_request` functions it replaces; the only thing that
/// varies between providers is what the trait methods select.
pub(super) async fn route_proxy_request<B, S>(
    session: &VmHttpSession,
    request: &VmHttpRequest,
    body: Vec<u8>,
    service: &VmHttpProxyService<B, S>,
) -> VmHttpDispatch
where
    B: ProxyBackend,
    S: SecretStore + Send + Sync + 'static,
{
    let route = B::classify_proxy_target(&request.target)
        .expect("caller only routes classified proxy targets");
    if B::route_is_unsupported(route) {
        let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
        return record_proxy_local_response::<B, S>(
            service,
            session,
            request,
            route,
            ProxyAuditDecision::Deny {
                reason: Cow::Borrowed(B::UNSUPPORTED_ROUTE_REASON),
            },
            response,
            None,
        )
        .into();
    }
    if request.method != B::route_method(route).as_str() {
        let response = VmHttpResponse::text(VmHttpStatus::MethodNotAllowed, "method not allowed");
        return record_proxy_local_response::<B, S>(
            service,
            session,
            request,
            route,
            ProxyAuditDecision::Deny {
                reason: Cow::Borrowed("method not allowed"),
            },
            response,
            None,
        )
        .into();
    }

    let headers = match B::forward_headers(&request.headers, &service.config) {
        Ok(headers) => headers,
        Err(reason) => {
            let response = VmHttpResponse::text(VmHttpStatus::BadRequest, reason);
            return record_proxy_local_response::<B, S>(
                service,
                session,
                request,
                route,
                ProxyAuditDecision::Deny {
                    reason: Cow::Borrowed(reason),
                },
                response,
                Some(reason),
            )
            .into();
        }
    };

    let request_id = RequestId::new();
    if let Err(response) = record_proxy_request_or_500::<B>(
        &service.broker_state.audit,
        ProxyRequestFields {
            request_id,
            session_id: session.session_id(),
            received_at: UnixMillis::now(),
            method: &request.method,
            target: &request.target,
            route,
            decision: &ProxyAuditDecision::Allow,
        },
    ) {
        return response.into();
    }

    if proxy_request_wants_streaming(&body) {
        match service
            .fetch_stream(request_id, request, body, headers)
            .await
        {
            Ok(stream) => return B::into_vm_http_dispatch(stream),
            Err(fetch) => {
                if let Err(response) = record_proxy_outcome_or_500::<B>(
                    &service.broker_state.audit,
                    ProxyOutcomeFields {
                        request_id,
                        completed_at: UnixMillis::now(),
                        http_status: fetch.response.status.code(),
                        upstream_url: fetch.upstream_url.as_deref(),
                        upstream_status: fetch.upstream_status,
                        response_bytes: fetch.response_bytes,
                        error: fetch.error,
                    },
                ) {
                    return response.into();
                }
                return fetch.response.into();
            }
        }
    }

    let fetch = service.fetch(request, body, headers).await;
    if let Err(response) = record_proxy_outcome_or_500::<B>(
        &service.broker_state.audit,
        ProxyOutcomeFields {
            request_id,
            completed_at: UnixMillis::now(),
            http_status: fetch.response.status.code(),
            upstream_url: fetch.upstream_url.as_deref(),
            upstream_status: fetch.upstream_status,
            response_bytes: fetch.response_bytes,
            error: fetch.error,
        },
    ) {
        return response.into();
    }
    fetch.response.into()
}

/// Generic helper for recording a locally-generated VM HTTP proxy
/// response (not an upstream fetch). Replaces the per-backend
/// `record_*_proxy_local_response` functions.
pub(super) fn record_proxy_local_response<B, S>(
    service: &VmHttpProxyService<B, S>,
    session: &VmHttpSession,
    request: &VmHttpRequest,
    route: B::Route,
    decision: ProxyAuditDecision<'_>,
    response: VmHttpResponse,
    error: Option<&'static str>,
) -> VmHttpResponse
where
    B: ProxyBackend,
    S: SecretStore + Send + Sync + 'static,
{
    let request_id = RequestId::new();
    if let Err(failure) = record_proxy_request_or_500::<B>(
        &service.broker_state.audit,
        ProxyRequestFields {
            request_id,
            session_id: session.session_id(),
            received_at: UnixMillis::now(),
            method: &request.method,
            target: &request.target,
            route,
            decision: &decision,
        },
    ) {
        return failure;
    }
    if let Err(failure) = record_proxy_outcome_or_500::<B>(
        &service.broker_state.audit,
        ProxyOutcomeFields {
            request_id,
            completed_at: UnixMillis::now(),
            http_status: response.status.code(),
            upstream_url: None,
            upstream_status: None,
            response_bytes: response.body.len() as u64,
            error,
        },
    ) {
        return failure;
    }
    response
}

fn record_proxy_request_or_500<B: ProxyBackend>(
    audit_log: &AuditLog,
    fields: ProxyRequestFields<'_, B::Route>,
) -> Result<(), VmHttpResponse> {
    let request_id = fields.request_id;
    if let Err(err) = B::record_request_audit(audit_log, fields) {
        tracing::error!(
            target: AUDIT_WRITE_FAILURE_TARGET,
            kind = B::REQUEST_AUDIT_KIND,
            request_id = %request_id,
            error = %err,
            "audit write failed",
        );
        return Err(VmHttpResponse::text(
            VmHttpStatus::InternalServerError,
            "audit write failed",
        ));
    }
    Ok(())
}

fn record_proxy_outcome_or_500<B: ProxyBackend>(
    audit_log: &AuditLog,
    fields: ProxyOutcomeFields<'_>,
) -> Result<(), VmHttpResponse> {
    let request_id = fields.request_id;
    if let Err(err) = B::record_outcome_audit(audit_log, fields) {
        tracing::error!(
            target: AUDIT_WRITE_FAILURE_TARGET,
            kind = B::OUTCOME_AUDIT_KIND,
            request_id = %request_id,
            error = %err,
            "audit write failed",
        );
        return Err(VmHttpResponse::text(
            VmHttpStatus::InternalServerError,
            "audit write failed",
        ));
    }
    Ok(())
}
