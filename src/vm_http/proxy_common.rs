//! Shared helpers used by both the Claude and OpenAI VM HTTP proxies.
//!
//! Anything in here is identical between the two backends — request-target
//! parsing, JSON-streaming detection, the upstream content-type allowlist,
//! and the chunked upstream body reader. Backend-specific routing,
//! authentication, and audit shape live in `claude_proxy` and `openai_proxy`.

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
