//! OpenAI proxy: forwards `/v1/responses`, `/v1/responses/{id}/cancel`, and
//! `/v1/models[/{model_id}]` requests from the guest VM to OpenAI (or a
//! configured upstream), injecting host-side auth and stripping guest auth.

use std::borrow::Cow;
use std::sync::Arc;

use serde::Deserialize;

use crate::audit::{
    AuditError, AuditLog, OpenAiProxyAuditDecision, OpenAiProxyAuditRoute,
    OpenAiProxyOutcomeRecord, OpenAiProxyRequestRecord,
};
use crate::openai_chatgpt_auth::{
    CHATGPT_OAUTH_REFRESH_LEEWAY_SECONDS, CHATGPT_OAUTH_REFRESH_URL, ChatgptOauthAuthority,
    ChatgptOauthAuthorityConfig, ChatgptOauthError, SystemClock,
};
use crate::secret::{SecretKey, SecretStore};

use super::proxy_common::{
    OpenAiBackend, ProxyAuditDecision, ProxyBackend, ProxyBackendConfig, ProxyFetch,
    ProxyForwardHeader, ProxyOutcomeFields, ProxyRequestFields, ProxyStream, UpstreamAuth,
    VmHttpProxyService, is_proxy_id_byte, proxy_target_path,
};
use super::{VmHttpDispatch, VmHttpHeader, VmHttpResponse, VmHttpStatus};

pub(super) const VM_OPENAI_RESPONSES_PATH: &str = "/v1/responses";
pub(super) const VM_OPENAI_RESPONSES_PREFIX: &str = "/v1/responses/";
pub(super) const VM_OPENAI_RESPONSE_CANCEL_SUFFIX: &str = "/cancel";
pub(super) const VM_OPENAI_MODELS_PATH: &str = "/v1/models";
pub(super) const VM_OPENAI_MODELS_PREFIX: &str = "/v1/models/";

pub(super) type VmHttpOpenAiProxyService<S> = VmHttpProxyService<OpenAiBackend, S>;

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

fn openai_proxy_auth_failure(body: &'static str, label: &'static str) -> ProxyFetch {
    let response = VmHttpResponse::text(VmHttpStatus::BadGateway, body);
    ProxyFetch {
        response_bytes: response.body.len() as u64,
        response,
        upstream_url: None,
        upstream_status: None,
        error: Some(label),
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

impl ProxyBackendConfig for VmHttpOpenAiProxyConfig {
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

impl ProxyBackend for OpenAiBackend {
    type Route = OpenAiProxyAuditRoute;
    type AuthKind = VmHttpOpenAiProxyAuthKind;
    type Config = VmHttpOpenAiProxyConfig;
    type Extras = Option<Arc<ChatgptOauthAuthority>>;

    const UPSTREAM_FAIL_BODY: &'static str = "OpenAI proxy upstream failed";
    const UNSUPPORTED_ROUTE_REASON: &'static str = "unsupported OpenAI proxy route";
    const REQUEST_AUDIT_KIND: &'static str = "openai_proxy_request";
    const OUTCOME_AUDIT_KIND: &'static str = "openai_proxy_outcome";

    fn classify_proxy_target(target: &str) -> Option<OpenAiProxyAuditRoute> {
        // Match on the path only. The OpenAI clients pass through query
        // params such as `?include[]=...` on Responses; the broker drops
        // them and forwards a path-only request upstream so the guest
        // can't expand the surface area beyond what the broker has
        // explicitly classified.
        let path = proxy_target_path(target);
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
        if path.starts_with(VM_OPENAI_RESPONSES_PREFIX) || path.starts_with(VM_OPENAI_MODELS_PREFIX)
        {
            return Some(OpenAiProxyAuditRoute::Unsupported);
        }
        None
    }

    fn route_is_unsupported(route: OpenAiProxyAuditRoute) -> bool {
        matches!(route, OpenAiProxyAuditRoute::Unsupported)
    }

    fn route_method(route: OpenAiProxyAuditRoute) -> reqwest::Method {
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

    fn relative_upstream_path(
        target: &str,
        config: &VmHttpOpenAiProxyConfig,
    ) -> Option<Cow<'static, str>> {
        let path = proxy_target_path(target);
        // ChatGPT-OAuth requests target `https://chatgpt.com/backend-api/codex/`
        // which exposes endpoints as bare names (e.g. `/codex/responses`),
        // whereas `https://api.openai.com/` exposes them under the `v1/`
        // prefix. The broker's `upstream_base_url` already encodes the
        // path-prefix portion (`/codex/` or `/v1/`); the per-route relative
        // joined here must match the wire shape codex itself uses for that
        // auth mode (see `model-provider-info`'s `to_api_provider`).
        let prefix = match config.auth_kind() {
            VmHttpOpenAiProxyAuthKind::AuthorizationBearer => "v1/",
            VmHttpOpenAiProxyAuthKind::ChatgptOauth => "",
        };
        Some(if path == VM_OPENAI_RESPONSES_PATH {
            format!("{prefix}responses").into()
        } else if path == VM_OPENAI_MODELS_PATH {
            format!("{prefix}models").into()
        } else if let Some(id) = openai_proxy_response_cancel_id(path) {
            format!("{prefix}responses/{id}/cancel").into()
        } else if let Some(id) = openai_proxy_model_id(path) {
            format!("{prefix}models/{id}").into()
        } else {
            return None;
        })
    }

    fn forward_headers(
        request_headers: &[VmHttpHeader],
        config: &VmHttpOpenAiProxyConfig,
    ) -> Result<Vec<ProxyForwardHeader>, &'static str> {
        openai_proxy_forward_headers(request_headers, config.auth_kind())
    }

    fn build_extras(
        config: &VmHttpOpenAiProxyConfig,
    ) -> Result<Option<Arc<ChatgptOauthAuthority>>, reqwest::Error> {
        match config.auth_kind() {
            VmHttpOpenAiProxyAuthKind::AuthorizationBearer => Ok(None),
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
                Ok(Some(Arc::new(ChatgptOauthAuthority::new(authority_config))))
            }
        }
    }

    async fn resolve_upstream_auth<S>(
        config: &VmHttpOpenAiProxyConfig,
        extras: &Option<Arc<ChatgptOauthAuthority>>,
        secret_store: &S,
    ) -> Result<UpstreamAuth, Box<ProxyFetch>>
    where
        S: SecretStore + Send + Sync + ?Sized,
    {
        match config.auth_kind() {
            VmHttpOpenAiProxyAuthKind::AuthorizationBearer => {
                let secret = match secret_store.get(config.auth_secret()) {
                    Ok(Some(secret)) if !secret.is_empty() => secret,
                    Ok(_) => {
                        return Err(Box::new(openai_proxy_auth_failure(
                            "OpenAI proxy auth missing",
                            "upstream auth missing",
                        )));
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "vm http openai proxy auth secret load failed",
                        );
                        return Err(Box::new(openai_proxy_auth_failure(
                            "OpenAI proxy auth failed",
                            "upstream auth load failed",
                        )));
                    }
                };
                Ok(UpstreamAuth::Bearer(secret))
            }
            VmHttpOpenAiProxyAuthKind::ChatgptOauth => {
                let authority = extras
                    .as_ref()
                    .expect("ChatGPT OAuth service constructed with authority");
                match authority.current_headers(secret_store).await {
                    Ok(headers) => Ok(UpstreamAuth::ChatgptOauth(headers)),
                    Err(err) => {
                        let label = err.audit_error_label();
                        tracing::warn!(
                            error_label = label,
                            error = %err,
                            "vm http openai proxy chatgpt auth resolution failed",
                        );
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

    fn record_request_audit(
        audit_log: &AuditLog,
        fields: ProxyRequestFields<'_, OpenAiProxyAuditRoute>,
    ) -> Result<(), AuditError> {
        let decision = decision_to_openai(fields.decision);
        audit_log.record_openai_proxy_request(&OpenAiProxyRequestRecord {
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
        audit_log.record_openai_proxy_outcome(&OpenAiProxyOutcomeRecord {
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
        VmHttpDispatch::OpenAiProxyStream(stream)
    }

    fn forward_header_name(
        raw: &str,
        _auth_kind: VmHttpOpenAiProxyAuthKind,
    ) -> Option<reqwest::header::HeaderName> {
        // Allowlist only. Anything that influences upstream auth, billing
        // scope, or feature flags is dropped: `Authorization` is injected
        // by the broker, and `OpenAI-Organization`/`OpenAI-Project` are
        // dropped because a host secret with multi-org/-project access
        // would otherwise let the guest pick the upstream scope. If the
        // broker ever needs to pin one, it must come from host config and
        // be injected host-side.
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

    fn response_header_name(raw: &str) -> Option<&'static str> {
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
}

fn openai_proxy_model_id(path: &str) -> Option<&str> {
    let suffix = path.strip_prefix(VM_OPENAI_MODELS_PREFIX)?;
    if suffix.is_empty() || !suffix.bytes().all(is_proxy_id_byte) {
        return None;
    }
    Some(suffix)
}

fn openai_proxy_response_cancel_id(path: &str) -> Option<&str> {
    let suffix = path.strip_prefix(VM_OPENAI_RESPONSES_PREFIX)?;
    let id = suffix.strip_suffix(VM_OPENAI_RESPONSE_CANCEL_SUFFIX)?;
    if id.is_empty() || !id.bytes().all(is_proxy_id_byte) {
        return None;
    }
    Some(id)
}

fn openai_proxy_forward_headers(
    headers: &[VmHttpHeader],
    auth_kind: VmHttpOpenAiProxyAuthKind,
) -> Result<Vec<ProxyForwardHeader>, &'static str> {
    let mut forwarded = Vec::new();
    let mut saw_content_type = false;
    let mut saw_accept = false;
    let mut saw_user_agent = false;

    for header in headers {
        let Some(name) = OpenAiBackend::forward_header_name(&header.name, auth_kind) else {
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
        forwarded.push(ProxyForwardHeader { name, value });
    }
    Ok(forwarded)
}

fn decision_to_openai(decision: &ProxyAuditDecision<'_>) -> OpenAiProxyAuditDecision {
    match decision {
        ProxyAuditDecision::Allow => OpenAiProxyAuditDecision::Allow,
        ProxyAuditDecision::Deny { reason } => OpenAiProxyAuditDecision::Deny {
            reason: reason.clone().into_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use base64::Engine as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::super::proxy_common::{proxy_request_wants_streaming, route_proxy_request};
    use super::super::tests::{
        bearer, make_broker_state, make_broker_state_with_extra_secret, open_audit_session,
        raw_http_response_with_headers, serve_raw_http_once, session_for_subnet, token,
    };
    use super::super::{
        VM_HTTP_READ_TIMEOUT, VmHttpDispatch, VmHttpHeader, VmHttpRequest, VmHttpServices,
        VmHttpSession, VmHttpStatus, dispatch_vm_http_head_and_body,
    };
    use super::*;
    use crate::audit::{OpenAiProxyAuditDecision, OpenAiProxyAuditRoute};
    use crate::core::Ipv4Cidr;
    use crate::secret::{SecretKey, SecretStore};

    async fn route_openai_proxy_request<S: SecretStore + Send + Sync + 'static>(
        session: &VmHttpSession,
        request: &VmHttpRequest,
        body: Vec<u8>,
        service: &VmHttpOpenAiProxyService<S>,
    ) -> VmHttpDispatch {
        route_proxy_request::<OpenAiBackend, _>(session, request, body, service).await
    }

    fn services_with_openai_proxy(
        openai_proxy: VmHttpOpenAiProxyService<Box<dyn SecretStore>>,
    ) -> VmHttpServices<Box<dyn SecretStore>> {
        VmHttpServices {
            git_clone: None,
            nix_cache: None,
            claude_proxy: None,
            openai_proxy: Some(openai_proxy),
            agent_runs: None,
            git_push: None,
        }
    }

    #[test]
    fn classify_openai_proxy_target_recognizes_supported_routes() {
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/responses"),
            Some(OpenAiProxyAuditRoute::Responses),
        );
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/responses/resp_abc123/cancel"),
            Some(OpenAiProxyAuditRoute::ResponseCancel),
        );
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/models"),
            Some(OpenAiProxyAuditRoute::Models),
        );
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/models/gpt-5"),
            Some(OpenAiProxyAuditRoute::Models),
        );
    }

    #[test]
    fn classify_openai_proxy_target_treats_unsupported_subpaths_as_unsupported() {
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/responses/resp_abc123"),
            Some(OpenAiProxyAuditRoute::Unsupported),
        );
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/responses/"),
            Some(OpenAiProxyAuditRoute::Unsupported),
        );
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/responses/resp_abc/cancel/extra"),
            Some(OpenAiProxyAuditRoute::Unsupported),
        );
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/models/"),
            Some(OpenAiProxyAuditRoute::Unsupported),
        );
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/models/foo/bar"),
            Some(OpenAiProxyAuditRoute::Unsupported),
        );
    }

    #[test]
    fn classify_openai_proxy_target_rejects_unrelated_paths() {
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/chat/completions"),
            None
        );
        assert_eq!(OpenAiBackend::classify_proxy_target("/v2/responses"), None);
        assert_eq!(OpenAiBackend::classify_proxy_target("/health"), None);
        assert_eq!(OpenAiBackend::classify_proxy_target(""), None);
    }

    #[test]
    fn classify_openai_proxy_target_strips_query_string() {
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/responses?include%5B%5D=foo"),
            Some(OpenAiProxyAuditRoute::Responses),
        );
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/responses/resp_abc/cancel?x=1"),
            Some(OpenAiProxyAuditRoute::ResponseCancel),
        );
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/models?x=1"),
            Some(OpenAiProxyAuditRoute::Models),
        );
        assert_eq!(
            OpenAiBackend::classify_proxy_target("/v1/models/gpt-5?x=1"),
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
            OpenAiBackend::response_header_name("X-Request-Id"),
            Some("X-Request-Id"),
        );
        assert_eq!(
            OpenAiBackend::response_header_name("retry-after"),
            Some("Retry-After"),
        );
        assert_eq!(
            OpenAiBackend::response_header_name("x-ratelimit-remaining-tokens"),
            Some("X-Ratelimit-Remaining-Tokens"),
        );
        assert_eq!(OpenAiBackend::response_header_name("set-cookie"), None);
    }

    #[test]
    fn openai_proxy_request_wants_streaming_reads_top_level_stream_field() {
        assert!(proxy_request_wants_streaming(
            br#"{"model":"gpt-5","stream":true}"#
        ));
        assert!(!proxy_request_wants_streaming(
            br#"{"model":"gpt-5","stream":false}"#
        ));
        assert!(!proxy_request_wants_streaming(br#"{"model":"gpt-5"}"#));
        assert!(!proxy_request_wants_streaming(b"not-json"));
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
        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "POST",
            VM_OPENAI_RESPONSES_PATH,
            &[],
            Vec::new(),
            services_with_openai_proxy(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await;

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
}
