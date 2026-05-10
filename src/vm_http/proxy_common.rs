//! Shared helpers used by both the Claude and OpenAI VM HTTP proxies.
//!
//! Anything in here is identical between the two backends — request-target
//! parsing, JSON-streaming detection, the upstream content-type allowlist,
//! the chunked upstream body reader, and the carrier types used to hand a
//! buffered fetch or a streaming upstream response back to the dispatcher.
//! Backend-specific routing, authentication, and audit shape live in
//! `claude_proxy` and `openai_proxy`.

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
use crate::secret::SecretStore;
use crate::server::BrokerState;

use super::{VmHttpResponse, VmHttpResponseHeader};

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

/// Identifies which audit log a streaming proxy response writes its outcome
/// record to. The Claude and OpenAI dispatchers carry the same structural
/// payload; the kind tag selects the audit shape on completion.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum ProxyAuditKind {
    Claude,
    OpenAi,
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
    pub(super) kind: ProxyAuditKind,
    pub(super) request_id: RequestId,
    pub(super) upstream_url: String,
    pub(super) upstream_status: u16,
}

pub(super) struct ProxyStreamBody<S: SecretStore> {
    pub(super) inner: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
    pub(super) audit: Option<ProxyStreamAudit<S>>,
    pub(super) max_response_bytes: u64,
    pub(super) response_bytes: u64,
    pub(super) state: ProxyStreamState,
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
                tracing::warn!(
                    proxy = proxy_audit_label(me.audit.as_ref().map(|a| a.kind)),
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
                    eprintln!("VM HTTP Claude proxy streaming audit outcome write failed: {err}");
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
                    eprintln!("VM HTTP OpenAI proxy streaming audit outcome write failed: {err}");
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

/// A streaming upstream response that has been opened but whose body has
/// not yet been forwarded to the guest. The `kind` selects which audit
/// shape is written when the streaming body finishes.
pub(crate) struct ProxyStream<S: SecretStore> {
    pub(super) broker_state: Arc<BrokerState<S>>,
    pub(super) request_id: RequestId,
    pub(super) response: reqwest::Response,
    pub(super) upstream_url: String,
    pub(super) upstream_status: u16,
    pub(super) content_type: &'static str,
    pub(super) headers: Vec<VmHttpResponseHeader>,
    pub(super) max_response_bytes: u64,
    pub(super) kind: ProxyAuditKind,
}

impl<S: SecretStore + Send + Sync + 'static> ProxyStream<S> {
    pub(super) fn into_hyper_response(
        self,
    ) -> http::Response<UnsyncBoxBody<Bytes, std::io::Error>> {
        let body = ProxyStreamBody {
            inner: Box::pin(self.response.bytes_stream()),
            audit: Some(ProxyStreamAudit {
                broker_state: self.broker_state,
                kind: self.kind,
                request_id: self.request_id,
                upstream_url: self.upstream_url,
                upstream_status: self.upstream_status,
            }),
            max_response_bytes: self.max_response_bytes,
            response_bytes: 0,
            state: ProxyStreamState::Streaming,
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
