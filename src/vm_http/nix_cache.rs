//! Nix cache: serves the binary-cache protocol on the broker's VM-facing HTTP
//! endpoint, forwarding `nix-cache-info`, `*.narinfo`, and NAR fetches to a
//! configured upstream while admitting only signed narinfos and verifying NAR
//! bodies before they reach the guest.

use std::collections::HashMap;
use std::io::Read as _;
use std::sync::{Arc, Mutex};

use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, NixCacheAuditDecision, NixCacheAuditRoute,
    NixCacheOutcomeRecord, NixCacheRequestRecord,
};
use crate::core::{RequestId, UnixMillis};
use crate::nix_cache::{
    NixCacheNarFileName, NixNarBodyHashError, NixNarCompression, NixNarHash, NixNarInfo,
    NixNarInfoError, NixNarSize, NixStoreHashPart, NixTrustedPublicKeys,
    parse_signed_narinfo_for_store_hash,
};
use crate::secret::SecretStore;
use crate::server::BrokerState;

use super::{VmHttpDispatch, VmHttpRequest, VmHttpResponse, VmHttpSession, VmHttpStatus};

pub const VM_NIX_CACHE_PATH_PREFIX: &str = "/v1/nix/cache";
pub(super) const VM_NIX_CACHE_INFO_PATH: &str = "/v1/nix/cache/nix-cache-info";
pub const VM_NIX_BASIC_LOGIN: &str = "writ-vm";
const XZ_DECODER_MEMLIMIT_OVERHEAD: u64 = 16 * 1024 * 1024;

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
pub struct VmHttpNixCacheConfig {
    upstream_base_url: reqwest::Url,
    max_metadata_bytes: u64,
    max_nar_bytes: u64,
    trusted_public_keys: NixTrustedPublicKeys,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum VmNixCacheRoute {
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

pub(super) async fn route_nix_cache_request<S: SecretStore>(
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
        tracing::error!(
            target: AUDIT_WRITE_FAILURE_TARGET,
            kind = "nix_cache_request",
            request_id = %request_id,
            error = %err,
            "audit write failed",
        );
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed")
            .into();
    }

    let fetch = service.fetch_route(request.method.as_str(), &route).await;
    if let Err(err) = record_nix_cache_outcome(&service, request_id, &fetch) {
        tracing::error!(
            target: AUDIT_WRITE_FAILURE_TARGET,
            kind = "nix_cache_outcome",
            request_id = %request_id,
            error = %err,
            "audit write failed",
        );
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed")
            .into();
    }
    fetch.response.into()
}

pub(super) fn record_nix_cache_local_response<S: SecretStore>(
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
        tracing::error!(
            target: AUDIT_WRITE_FAILURE_TARGET,
            kind = "nix_cache_request",
            request_id = %request_id,
            error = %err,
            "audit write failed",
        );
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
        tracing::error!(
            target: AUDIT_WRITE_FAILURE_TARGET,
            kind = "nix_cache_outcome",
            request_id = %request_id,
            error = %err,
            "audit write failed",
        );
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

pub(super) fn route_nix_cache_request_without_upstream(request: &VmHttpRequest) -> VmHttpResponse {
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
                tracing::warn!(
                    upstream_url = %upstream_url,
                    error = %err,
                    "vm http nix cache upstream request failed",
                );
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
            tracing::warn!(
                upstream_url = %upstream_url,
                upstream_status = status.as_u16(),
                "vm http nix cache upstream returned unsupported status",
            );
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
                tracing::warn!(
                    upstream_url = %upstream_url,
                    error = %err,
                    "vm http nix cache upstream body read failed",
                );
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
                    tracing::warn!(
                        upstream_url = %upstream_url,
                        error = %err,
                        "vm http nix cache upstream narinfo was rejected",
                    );
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
                tracing::warn!(
                    upstream_url = %upstream_url,
                    error = %err,
                    "vm http nix cache upstream narinfo admission failed",
                );
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
                tracing::warn!(
                    upstream_url = %upstream_url,
                    error = %err,
                    "vm http nix cache NAR upstream request failed",
                );
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
            tracing::warn!(
                upstream_url = %upstream_url,
                upstream_status = upstream_status.as_u16(),
                "vm http nix cache NAR upstream returned unsupported status",
            );
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
                tracing::warn!(
                    upstream_url = %upstream_url,
                    error = %err,
                    "vm http nix cache NAR upstream body read failed",
                );
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
                    tracing::warn!(
                        upstream_url = %upstream_url,
                        error = %err,
                        "vm http nix cache NAR body was rejected",
                    );
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

pub(super) fn is_nix_cache_target(target: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use base64::Engine as _;
    use proptest::prelude::*;
    use ring::signature::KeyPair as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::super::tests::{
        basic, bearer, make_broker_state, open_audit_session, session_for_subnet, token,
    };
    use super::super::{
        VM_HTTP_READ_TIMEOUT, VmHttpRequest, VmHttpServices, VmHttpStatus, dispatch_vm_http_head,
        dispatch_vm_http_head_and_body, route_authenticated_vm_http_request,
    };
    use super::*;
    use crate::core::Ipv4Cidr;

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

    pub(super) fn services_with_nix_cache(
        nix_cache: VmHttpNixCacheService<Box<dyn SecretStore>>,
    ) -> VmHttpServices<Box<dyn SecretStore>> {
        VmHttpServices {
            git_clone: None,
            nix_cache: Some(nix_cache),
            claude_proxy: None,
            openai_proxy: None,
            agent_runs: None,
            git_push: None,
            plans: None,
        }
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
        format!(
            "{name}:{}",
            base64::engine::general_purpose::STANDARD.encode(key_pair.public_key().as_ref())
        )
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
        let signature = base64::engine::general_purpose::STANDARD
            .encode(key_pair.sign(fingerprint.as_bytes()).as_ref());
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

    proptest! {
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
    fn nix_cache_routes_accept_basic_auth_only() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let source = Ipv4Addr::new(10, 1, 2, 42);

        assert_eq!(
            super::super::authorize_vm_http_request(
                &session,
                &nix_cache_request(
                    "GET",
                    VM_NIX_CACHE_INFO_PATH,
                    source,
                    Some(basic(token().as_str()))
                ),
            ),
            super::super::VmHttpAuthorization::Allow
        );
        assert_eq!(
            super::super::authorize_vm_http_request(
                &session,
                &nix_cache_request(
                    "GET",
                    VM_NIX_CACHE_INFO_PATH,
                    source,
                    Some(bearer(token().as_str()))
                ),
            ),
            super::super::VmHttpAuthorization::Deny(
                super::super::VmHttpAuthError::WrongCredentials
            )
        );
        assert_eq!(
            super::super::authorize_vm_http_request(
                &session,
                &nix_cache_request("GET", VM_NIX_CACHE_INFO_PATH, source, Some(basic("wrong"))),
            ),
            super::super::VmHttpAuthorization::Deny(
                super::super::VmHttpAuthError::WrongCredentials
            )
        );
    }

    #[test]
    fn nix_cache_auth_challenge_is_basic() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            "GET",
            VM_NIX_CACHE_INFO_PATH,
            None,
        );

        assert_eq!(response.status, VmHttpStatus::Unauthorized);
        let challenge = response
            .www_authenticate
            .expect("nix cache must issue a Basic challenge");
        assert!(
            challenge.starts_with("Basic realm=\"writ-nix-cache\""),
            "{challenge}"
        );
        assert!(!challenge.contains("Bearer"), "{challenge}");
    }

    #[test]
    fn nix_cache_info_route_returns_binary_cache_metadata() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let basic_auth = basic(token().as_str());
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            "GET",
            VM_NIX_CACHE_INFO_PATH,
            Some(basic_auth.as_str()),
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
        let basic_auth = basic(token().as_str());
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            "GET",
            &target,
            Some(basic_auth.as_str()),
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
        session: &super::super::VmHttpSession,
        method: &str,
        target: String,
        service: VmHttpNixCacheService<Box<dyn SecretStore>>,
    ) -> super::super::VmHttpResponse {
        let request = nix_cache_request(
            method,
            target,
            Ipv4Addr::LOCALHOST,
            Some(basic(token().as_str())),
        );
        route_authenticated_vm_http_request(
            session,
            &request,
            Vec::new(),
            services_with_nix_cache(service),
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
        assert_eq!(response.content_length, Some(123));
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

        let response = dispatch_vm_http_head_and_body(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            "GET",
            VM_NIX_CACHE_INFO_PATH,
            &[],
            Vec::new(),
            services_with_nix_cache(service),
            VM_HTTP_READ_TIMEOUT,
        )
        .await;

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

    #[tokio::test]
    async fn nix_cache_route_does_not_read_declared_body() {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let basic_auth = basic(token().as_str());
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dispatch_vm_http_head_and_body(
                &session,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
                "GET",
                VM_NIX_CACHE_INFO_PATH,
                &[
                    ("authorization", basic_auth.as_str()),
                    ("content-length", "1"),
                ],
                Vec::new(),
                super::super::tests::no_services(),
                VM_HTTP_READ_TIMEOUT,
            ),
        )
        .await
        .expect("Nix cache route must not wait for a declared body");

        assert_eq!(response.status, VmHttpStatus::Ok);
    }
}
