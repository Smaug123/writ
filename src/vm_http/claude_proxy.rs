//! Claude proxy: forwards `/v1/messages`, `/v1/messages/count_tokens`, and
//! `/v1/models/{model_id}` requests from the guest VM to Anthropic (or a
//! configured upstream), injecting host-side auth and stripping guest auth.

use std::borrow::Cow;

use serde::Deserialize;

use crate::audit::{
    AuditError, AuditLog, ClaudeProxyAuditRoute, ClaudeProxyOutcomeRecord, ClaudeProxyRequestRecord,
};
use crate::secret::{SecretKey, SecretStore};

use super::proxy_common::{
    ClaudeBackend, ProxyBackend, ProxyBackendConfig, ProxyFetch, ProxyForwardHeader,
    ProxyOutcomeFields, ProxyRequestFields, ProxyStream, UpstreamAuth, VmHttpProxyService,
    is_proxy_id_byte, proxy_decision_to_owned, proxy_target_path,
};
use super::{VmHttpDispatch, VmHttpHeader, VmHttpResponse, VmHttpStatus};

pub(super) const VM_CLAUDE_MESSAGES_PATH: &str = "/v1/messages";
pub(super) const VM_CLAUDE_COUNT_TOKENS_PATH: &str = "/v1/messages/count_tokens";
pub(super) const VM_CLAUDE_MODELS_PREFIX: &str = "/v1/models/";
pub const DEFAULT_CLAUDE_ANTHROPIC_VERSION: &str = "2023-06-01";
const ANTHROPIC_OAUTH_TOKEN_PREFIX: &str = "sk-ant-oat01-";

pub(super) type VmHttpClaudeProxyService<S> = VmHttpProxyService<ClaudeBackend, S>;

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

fn claude_proxy_auth_failure(body: &'static str, label: &'static str) -> ProxyFetch {
    let response = VmHttpResponse::text(VmHttpStatus::BadGateway, body);
    ProxyFetch {
        response_bytes: response.body.len() as u64,
        response,
        upstream_url: None,
        upstream_status: None,
        error: Some(label),
    }
}

fn claude_proxy_upstream_auth(
    secret: String,
    auth_kind: VmHttpClaudeProxyAuthKind,
) -> Result<UpstreamAuth, Box<ProxyFetch>> {
    if auth_kind == VmHttpClaudeProxyAuthKind::XApiKey
        && secret.starts_with(ANTHROPIC_OAUTH_TOKEN_PREFIX)
    {
        return Err(Box::new(claude_proxy_auth_failure(
            "Claude proxy auth_kind x_api_key cannot use an Anthropic OAuth token; set \
             claude_proxy.auth_kind to oauth",
            "upstream auth kind mismatch",
        )));
    }

    Ok(match auth_kind {
        VmHttpClaudeProxyAuthKind::XApiKey => UpstreamAuth::XApiKey(secret),
        VmHttpClaudeProxyAuthKind::AuthorizationBearer => UpstreamAuth::Bearer(secret),
        VmHttpClaudeProxyAuthKind::OAuth => UpstreamAuth::AnthropicOauth(secret),
    })
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

impl ProxyBackendConfig for VmHttpClaudeProxyConfig {
    fn upstream_base_url(&self) -> &reqwest::Url {
        &self.upstream_base_url
    }

    fn timeout(&self) -> std::time::Duration {
        self.timeout
    }

    fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }
}

impl ProxyBackend for ClaudeBackend {
    type Route = ClaudeProxyAuditRoute;
    type AuthKind = VmHttpClaudeProxyAuthKind;
    type Config = VmHttpClaudeProxyConfig;
    type Extras = ();

    const UPSTREAM_FAIL_BODY: &'static str = "Claude proxy upstream failed";
    const UNSUPPORTED_ROUTE_REASON: &'static str = "unsupported Claude proxy route";
    const REQUEST_AUDIT_KIND: &'static str = "claude_proxy_request";
    const OUTCOME_AUDIT_KIND: &'static str = "claude_proxy_outcome";

    fn classify_proxy_target(target: &str) -> Option<ClaudeProxyAuditRoute> {
        // Match on the path only. Anthropic's clients pass through query
        // params such as `?beta=true` that select endpoint variants; the
        // broker's policy is to drop those (similar to the `anthropic-beta`
        // header allowlist) and forward a path-only request upstream.
        let path = proxy_target_path(target);
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

    fn route_is_unsupported(route: ClaudeProxyAuditRoute) -> bool {
        matches!(route, ClaudeProxyAuditRoute::Unsupported)
    }

    fn route_method(route: ClaudeProxyAuditRoute) -> reqwest::Method {
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

    fn relative_upstream_path(
        target: &str,
        _config: &VmHttpClaudeProxyConfig,
    ) -> Option<Cow<'static, str>> {
        let path = proxy_target_path(target);
        Some(match path {
            VM_CLAUDE_MESSAGES_PATH => "v1/messages".into(),
            VM_CLAUDE_COUNT_TOKENS_PATH => "v1/messages/count_tokens".into(),
            _ => format!("v1/models/{}", claude_proxy_model_id(path)?).into(),
        })
    }

    fn forward_headers(
        request_headers: &[VmHttpHeader],
        config: &VmHttpClaudeProxyConfig,
    ) -> Result<Vec<ProxyForwardHeader>, &'static str> {
        claude_proxy_forward_headers(
            request_headers,
            config.anthropic_version(),
            config.auth_kind(),
        )
    }

    fn build_extras(_config: &VmHttpClaudeProxyConfig) -> Result<(), reqwest::Error> {
        Ok(())
    }

    async fn resolve_upstream_auth<S>(
        config: &VmHttpClaudeProxyConfig,
        _extras: &(),
        secret_store: &S,
    ) -> Result<UpstreamAuth, Box<ProxyFetch>>
    where
        S: SecretStore + Send + Sync + ?Sized,
    {
        let secret = match secret_store.get(config.auth_secret()) {
            Ok(Some(secret)) if !secret.is_empty() => secret,
            Ok(_) => {
                return Err(Box::new(claude_proxy_auth_failure(
                    "Claude proxy auth missing",
                    "upstream auth missing",
                )));
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "vm http claude proxy auth secret load failed",
                );
                return Err(Box::new(claude_proxy_auth_failure(
                    "Claude proxy auth failed",
                    "upstream auth load failed",
                )));
            }
        };
        claude_proxy_upstream_auth(secret, config.auth_kind())
    }

    fn record_request_audit(
        audit_log: &AuditLog,
        fields: ProxyRequestFields<'_, ClaudeProxyAuditRoute>,
    ) -> Result<(), AuditError> {
        let decision = proxy_decision_to_owned(fields.decision);
        audit_log.record_claude_proxy_request(&ClaudeProxyRequestRecord {
            request_id: fields.request_id,
            session_id: fields.session_id,
            received_at: fields.received_at,
            method: fields.method,
            target: fields.target,
            route: fields.route,
            decision: &decision,
        })
    }

    fn record_outcome_audit(
        audit_log: &AuditLog,
        fields: ProxyOutcomeFields<'_>,
    ) -> Result<(), AuditError> {
        audit_log.record_claude_proxy_outcome(&ClaudeProxyOutcomeRecord {
            request_id: fields.request_id,
            completed_at: fields.completed_at,
            http_status: fields.http_status,
            upstream_url: fields.upstream_url,
            upstream_status: fields.upstream_status,
            response_bytes: fields.response_bytes,
            error: fields.error,
        })
    }

    fn into_vm_http_dispatch(stream: ProxyStream<Self>) -> VmHttpDispatch {
        VmHttpDispatch::ClaudeProxyStream(stream)
    }

    fn forward_header_name(
        raw: &str,
        auth_kind: VmHttpClaudeProxyAuthKind,
    ) -> Option<reqwest::header::HeaderName> {
        // Allowlist only. The default policy drops anthropic-beta because
        // beta features can opt into capabilities the operator has not
        // authorized (e.g. extended file retention, computer-use tool
        // surfaces), so the broker — not the guest — decides which betas
        // to enable. The OAuth auth path is the exception: it exists to
        // host Claude Code, whose request shape includes betas the CLI
        // emits itself, so the broker forwards anthropic-beta from the
        // guest while still injecting its own oauth-2025-04-20 alongside.
        // Anthropic-Version is added separately by the broker and is
        // never forwarded from the guest.
        if raw.eq_ignore_ascii_case("content-type") {
            return Some(reqwest::header::CONTENT_TYPE);
        }
        if raw.eq_ignore_ascii_case("accept") {
            return Some(reqwest::header::ACCEPT);
        }
        if raw.eq_ignore_ascii_case("user-agent") {
            return Some(reqwest::header::USER_AGENT);
        }
        if auth_kind == VmHttpClaudeProxyAuthKind::OAuth
            && raw.eq_ignore_ascii_case("anthropic-beta")
        {
            return Some(reqwest::header::HeaderName::from_static("anthropic-beta"));
        }
        None
    }

    fn response_header_name(raw: &str) -> Option<&'static str> {
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
}

fn claude_proxy_model_id(path: &str) -> Option<&str> {
    let suffix = path.strip_prefix(VM_CLAUDE_MODELS_PREFIX)?;
    if suffix.is_empty() || !suffix.bytes().all(is_proxy_id_byte) {
        return None;
    }
    Some(suffix)
}

fn claude_proxy_forward_headers(
    headers: &[VmHttpHeader],
    anthropic_version: &reqwest::header::HeaderValue,
    auth_kind: VmHttpClaudeProxyAuthKind,
) -> Result<Vec<ProxyForwardHeader>, &'static str> {
    let mut forwarded = Vec::new();
    let mut saw_content_type = false;
    let mut saw_accept = false;
    let mut saw_user_agent = false;
    let mut saw_anthropic_beta = false;
    let anthropic_beta_name = reqwest::header::HeaderName::from_static("anthropic-beta");

    for header in headers {
        let Some(name) = ClaudeBackend::forward_header_name(&header.name, auth_kind) else {
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
        forwarded.push(ProxyForwardHeader { name, value });
    }
    forwarded.push(ProxyForwardHeader {
        name: reqwest::header::HeaderName::from_static("anthropic-version"),
        value: anthropic_version.clone(),
    });
    Ok(forwarded)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use wiremock::MockServer;

    use super::super::VmHttpSession;
    use super::super::proxy_common::route_proxy_request;
    use super::super::tests::{
        bearer, make_broker_state, make_broker_state_with_extra_secret, open_audit_session,
        raw_http_response, raw_http_response_with_headers, serve_raw_http_once,
        services_with_claude_proxy, session_for_subnet, token,
    };
    use super::super::{
        DispatchedTestResponse, VM_HTTP_READ_TIMEOUT, VmHttpDispatch, VmHttpHeader, VmHttpRequest,
        VmHttpResponseHeader, VmHttpStatus, dispatch_vm_http_head_and_body,
    };
    use super::*;
    use crate::audit::{ClaudeProxyAuditDecision, ClaudeProxyAuditRoute};
    use crate::core::Ipv4Cidr;
    use crate::secret::SecretKey;
    use std::sync::Arc;

    async fn route_claude_proxy_request<S: SecretStore + Send + Sync + 'static>(
        session: &VmHttpSession,
        request: &VmHttpRequest,
        body: Vec<u8>,
        service: &VmHttpClaudeProxyService<S>,
    ) -> VmHttpDispatch {
        route_proxy_request::<ClaudeBackend, _>(session, request, body, service).await
    }

    #[test]
    fn classify_claude_proxy_target_recognizes_supported_routes() {
        assert_eq!(
            ClaudeBackend::classify_proxy_target("/v1/messages"),
            Some(ClaudeProxyAuditRoute::Messages),
        );
        assert_eq!(
            ClaudeBackend::classify_proxy_target("/v1/messages/count_tokens"),
            Some(ClaudeProxyAuditRoute::CountTokens),
        );
        assert_eq!(
            ClaudeBackend::classify_proxy_target("/v1/models/claude-haiku-4-5-20251001"),
            Some(ClaudeProxyAuditRoute::Models),
        );
    }

    #[test]
    fn classify_claude_proxy_target_treats_models_listing_and_empty_id_as_unsupported() {
        assert_eq!(
            ClaudeBackend::classify_proxy_target("/v1/models"),
            Some(ClaudeProxyAuditRoute::Unsupported),
        );
        assert_eq!(
            ClaudeBackend::classify_proxy_target("/v1/models/"),
            Some(ClaudeProxyAuditRoute::Unsupported),
        );
        assert_eq!(
            ClaudeBackend::classify_proxy_target("/v1/models/foo/bar"),
            Some(ClaudeProxyAuditRoute::Unsupported),
        );
    }

    #[test]
    fn classify_claude_proxy_target_rejects_unrelated_paths() {
        assert_eq!(ClaudeBackend::classify_proxy_target("/v2/models/foo"), None);
        assert_eq!(ClaudeBackend::classify_proxy_target("/health"), None);
        assert_eq!(ClaudeBackend::classify_proxy_target(""), None);
    }

    #[test]
    fn classify_claude_proxy_target_strips_query_string() {
        assert_eq!(
            ClaudeBackend::classify_proxy_target("/v1/messages?beta=true"),
            Some(ClaudeProxyAuditRoute::Messages),
        );
        assert_eq!(
            ClaudeBackend::classify_proxy_target("/v1/messages/count_tokens?beta=true"),
            Some(ClaudeProxyAuditRoute::CountTokens),
        );
        assert_eq!(
            ClaudeBackend::classify_proxy_target("/v1/models/claude-haiku-4-5-20251001?beta=true"),
            Some(ClaudeProxyAuditRoute::Models),
        );
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
    async fn claude_proxy_x_api_key_rejects_oauth_token_shape_before_upstream() {
        let github = MockServer::start().await;
        let secret_key = SecretKey::new("anthropic-api-key").unwrap();
        let state = make_broker_state_with_extra_secret(
            &github,
            Some((secret_key.clone(), "sk-ant-oat01-host-oauth-token")),
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
        let body = String::from_utf8(response.body).unwrap();
        assert!(
            body.contains("set claude_proxy.auth_kind to oauth"),
            "{body}"
        );
        let entries = state
            .audit
            .list_claude_proxy_requests_for_session_for_test(session.session_id())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, ClaudeProxyAuditRoute::Messages);
        assert_eq!(entries[0].1, ClaudeProxyAuditDecision::Allow);
        assert_eq!(entries[0].2, Some(502));
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
                panic!("Claude route produced an OpenAI stream")
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
        let response =
            DispatchedTestResponse::from_hyper_response(dispatch.into_hyper_response()).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        assert_eq!(response.content_type, "text/event-stream");
        assert!(
            !response.headers.contains_key(http::header::CONTENT_LENGTH),
            "{:?}",
            response.headers
        );
        assert_eq!(
            response
                .headers
                .get("request-id")
                .and_then(|v| v.to_str().ok()),
            Some("req-stream-123")
        );
        assert_eq!(response.body, upstream_body);
        let outcome = state
            .audit
            .claude_proxy_outcome_for_test(request_id)
            .unwrap()
            .expect("streaming outcome should be recorded after the body is collected");
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
                panic!("Claude route produced an OpenAI stream")
            }
        };
        let response =
            DispatchedTestResponse::from_hyper_response(dispatch.into_hyper_response()).await;

        assert_eq!(response.status, VmHttpStatus::Ok);
        assert_eq!(response.content_type, "text/event-stream");
        assert_ne!(response.body, upstream_body);
        let outcome = state
            .audit
            .claude_proxy_outcome_for_test(request_id)
            .unwrap()
            .expect("streaming outcome should be recorded after the body is collected");
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
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "POST",
            VM_CLAUDE_MESSAGES_PATH,
            &[],
            Vec::new(),
            services_with_claude_proxy(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await;

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
}
