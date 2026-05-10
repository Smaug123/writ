//! Shared helpers used by both the Claude and OpenAI VM HTTP proxies.
//!
//! Anything in here is identical between the two backends — request-target
//! parsing, JSON-streaming detection, the upstream content-type allowlist,
//! the chunked upstream body reader, and the carrier types used to hand a
//! buffered fetch or a streaming upstream response back to the dispatcher.
//! Backend-specific routing, authentication, and audit shape live in
//! `claude_proxy` and `openai_proxy`.

use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use http_body_util::BodyExt as _;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::{Body as HyperBody, Frame};

use crate::audit::{ClaudeProxyOutcomeRecord, OpenAiProxyOutcomeRecord};
use crate::core::{RequestId, UnixMillis};
use crate::openai_chatgpt_auth::ChatgptUpstreamHeaders;
use crate::secret::SecretStore;
use crate::server::BrokerState;

use super::{VmHttpResponse, VmHttpResponseHeader};

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
pub(super) trait ProxyAudit: 'static {
    /// Human-readable backend label for diagnostic logging.
    const DISPLAY_NAME: &'static str;
    fn record_outcome<S: SecretStore>(
        broker_state: &BrokerState<S>,
        fields: ProxyOutcomeFields<'_>,
    );
}

/// Per-backend behaviour the VM HTTP proxy dispatcher relies on.
///
/// Implementations are zero-sized types (one per upstream provider)
/// that select a target/route classification, an auth-shape selector,
/// and a header allowlist. Audit-log selection is inherited via the
/// `ProxyAudit` supertrait, so a single backend marker carries every
/// per-provider decision the dispatcher needs to make. Routing and
/// request execution still live in the per-backend modules pending
/// the unified service struct.
pub(super) trait ProxyBackend: ProxyAudit {
    /// The audit-log route enum the backend classifies a target into
    /// (e.g., `ClaudeProxyAuditRoute`).
    type Route: Copy + Send + 'static;
    /// The auth-shape selector this backend supports (e.g.,
    /// `VmHttpClaudeProxyAuthKind`).
    type AuthKind: Copy;

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
}

/// Backend marker selecting the Claude proxy: its routing/header
/// allowlist (via `ProxyBackend`) and its audit log (via `ProxyAudit`).
pub(super) struct ClaudeBackend;

impl ProxyAudit for ClaudeBackend {
    const DISPLAY_NAME: &'static str = "Claude";

    fn record_outcome<S: SecretStore>(
        broker_state: &BrokerState<S>,
        fields: ProxyOutcomeFields<'_>,
    ) {
        if let Err(err) =
            broker_state
                .audit
                .record_claude_proxy_outcome(&ClaudeProxyOutcomeRecord {
                    request_id: fields.request_id,
                    completed_at: fields.completed_at,
                    http_status: fields.http_status,
                    upstream_url: fields.upstream_url,
                    upstream_status: fields.upstream_status,
                    response_bytes: fields.response_bytes,
                    error: fields.error,
                })
        {
            eprintln!("VM HTTP Claude proxy streaming audit outcome write failed: {err}");
        }
    }
}

/// Backend marker selecting the OpenAI proxy: its routing/header
/// allowlist (via `ProxyBackend`) and its audit log (via `ProxyAudit`).
pub(super) struct OpenAiBackend;

impl ProxyAudit for OpenAiBackend {
    const DISPLAY_NAME: &'static str = "OpenAI";

    fn record_outcome<S: SecretStore>(
        broker_state: &BrokerState<S>,
        fields: ProxyOutcomeFields<'_>,
    ) {
        if let Err(err) =
            broker_state
                .audit
                .record_openai_proxy_outcome(&OpenAiProxyOutcomeRecord {
                    request_id: fields.request_id,
                    completed_at: fields.completed_at,
                    http_status: fields.http_status,
                    upstream_url: fields.upstream_url,
                    upstream_status: fields.upstream_status,
                    response_bytes: fields.response_bytes,
                    error: fields.error,
                })
        {
            eprintln!("VM HTTP OpenAI proxy streaming audit outcome write failed: {err}");
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

pub(super) struct ProxyStreamAudit<S: SecretStore> {
    pub(super) broker_state: Arc<BrokerState<S>>,
    pub(super) request_id: RequestId,
    pub(super) upstream_url: String,
    pub(super) upstream_status: u16,
}

pub(super) struct ProxyStreamBody<S: SecretStore, A: ProxyAudit> {
    pub(super) inner: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
    pub(super) audit: Option<ProxyStreamAudit<S>>,
    pub(super) max_response_bytes: u64,
    pub(super) response_bytes: u64,
    pub(super) state: ProxyStreamState,
    pub(super) _audit_kind: PhantomData<fn() -> A>,
}

impl<S: SecretStore, A: ProxyAudit> HyperBody for ProxyStreamBody<S, A> {
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

impl<S: SecretStore, A: ProxyAudit> Drop for ProxyStreamBody<S, A> {
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
            &audit.broker_state,
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
pub(crate) struct ProxyStream<S: SecretStore, A: ProxyAudit> {
    pub(super) broker_state: Arc<BrokerState<S>>,
    pub(super) request_id: RequestId,
    pub(super) response: reqwest::Response,
    pub(super) upstream_url: String,
    pub(super) upstream_status: u16,
    pub(super) content_type: &'static str,
    pub(super) headers: Vec<VmHttpResponseHeader>,
    pub(super) max_response_bytes: u64,
    pub(super) _audit_kind: PhantomData<fn() -> A>,
}

impl<S: SecretStore + Send + Sync + 'static, A: ProxyAudit> ProxyStream<S, A> {
    pub(super) fn into_hyper_response(
        self,
    ) -> http::Response<UnsyncBoxBody<Bytes, std::io::Error>> {
        let body = ProxyStreamBody::<S, A> {
            inner: Box::pin(self.response.bytes_stream()),
            audit: Some(ProxyStreamAudit {
                broker_state: self.broker_state,
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
