//! Nix cache: serves the binary-cache protocol on the broker's VM-facing HTTP
//! endpoint, forwarding `nix-cache-info`, `*.narinfo`, and NAR fetches to a
//! configured upstream while admitting only signed narinfos and verifying NAR
//! bodies before they reach the guest.
//!
//! This module is the imperative shell that wires the request-classification
//! (`route`), config validation (`config`), NAR verification (`nar_verify`) and
//! local-archive file IO (`local_cache`) submodules into the proxy service and
//! its audit trail.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, NixCacheAuditDecision, NixCacheAuditRoute,
    NixCacheOutcomeRecord, NixCacheRequestRecord,
};
use crate::core::{RequestId, UnixMillis};
use crate::nix_cache::{
    NixCacheNarFileName, NixContentAddressedNarInfoError, NixNarBodyHashError, NixNarInfo,
    NixNarInfoError, NixStoreHashPart, parse_content_addressed_narinfo_for_store_hash,
    parse_signed_narinfo_for_store_hash,
};
use crate::secret::SecretStore;
use crate::server::BrokerState;

use super::{VmHttpDispatch, VmHttpRequest, VmHttpResponse, VmHttpSession, VmHttpStatus};

mod config;
mod local_cache;
mod nar_verify;
mod route;

pub use config::{VmHttpNixCacheConfig, VmHttpNixCacheConfigError};
pub use route::{VM_NIX_BASIC_LOGIN, VM_NIX_CACHE_PATH_PREFIX};

use local_cache::{
    LocalCacheFile, LocalCacheStat, local_file_url, read_local_cache_file, stat_local_cache_file,
};
use nar_verify::{
    VmHttpNixCacheAdmittedNar, nar_body_hash_error_label, validate_nar_body_length,
    validate_nar_content_length, verify_nar_body_on_blocking_thread,
};
use route::{VM_NIX_CACHE_INFO_BODY, VmNixCacheRoute, classify_nix_cache_target};
// Re-exported for `super` (the `vm_http` dispatcher), which routes to these but
// does not define them. `route_nix_cache_request_without_upstream` is also used
// directly below when no upstream service is configured.
pub(super) use route::{is_nix_cache_target, route_nix_cache_request_without_upstream};

#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod local_cache_tests;
#[cfg(test)]
mod nar_verify_tests;
#[cfg(test)]
mod proxy_tests;
#[cfg(test)]
mod route_tests;
#[cfg(test)]
mod test_support;

pub struct VmHttpNixCacheService<S: SecretStore> {
    broker_state: Arc<BrokerState<S>>,
    config: VmHttpNixCacheConfig,
    client: reqwest::Client,
    // This service is constructed once per prepared VM HTTP session. Admission
    // state is intentionally kept for that session runtime lifetime. Entries
    // are small, and eviction would risk turning a valid NAR follow-up request
    // into an order-dependent cache miss.
    admitted_nars: Arc<Mutex<HashMap<NixCacheNarFileName, VmHttpNixCacheNarEntry>>>,
}

#[derive(Debug)]
struct VmHttpNixCacheProxyFetch {
    response: VmHttpResponse,
    upstream_url: String,
    upstream_status: Option<u16>,
    response_bytes: u64,
    error: Option<&'static str>,
}

/// Where an admitted NAR is fetched from. The source is decided when the
/// *narinfo* is admitted and pins where the matching NAR comes from, so a NAR
/// admitted from the signed upstream is never shadowed by a same-named file in
/// the local archive (and vice-versa).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum VmNixCacheNarSource {
    /// Admitted from the broker's local archive (a content-addressed narinfo);
    /// the NAR is served authoritatively from `local_cache_dir/nar/<file>`.
    Local,
    /// Admitted from the signed upstream; the NAR is fetched from the upstream.
    Upstream,
}

/// An admitted NAR plus where it is served from. Equality of the admission
/// (content metadata) alone gates the conflict check; the source is bookkeeping
/// for routing the NAR fetch.
#[derive(Clone, Debug)]
struct VmHttpNixCacheNarEntry {
    admission: VmHttpNixCacheAdmittedNar,
    source: VmNixCacheNarSource,
}

#[derive(Debug, thiserror::Error)]
enum VmHttpNixCacheBodyReadError {
    #[error("Nix cache upstream response body read failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Nix cache upstream response exceeds {max} bytes")]
    ResponseTooLarge { max: u64 },
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
    }

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

impl<S: SecretStore> VmHttpNixCacheService<S> {
    async fn fetch_route(&self, method: &str, route: &VmNixCacheRoute) -> VmHttpNixCacheProxyFetch {
        match route {
            VmNixCacheRoute::CacheInfo => {
                // Serve the cache metadata locally whenever a local archive is
                // configured, so the guest's mandatory pre-flight
                // `nix-cache-info` does not depend on upstream reachability — a
                // no-egress guest can substitute the local archive even if the
                // upstream cache is momentarily unavailable. Without a local
                // archive this proxies the upstream exactly as before.
                if self.config.local_cache_dir().is_some() {
                    local_cache_info(method)
                } else {
                    self.fetch_metadata(method, route).await
                }
            }
            VmNixCacheRoute::NarInfo { hash } => {
                // Local-first: a content-addressed narinfo in the broker's
                // archive is served (and admitted) without contacting the
                // upstream; a local miss falls through to the signed upstream
                // proxy, so an empty/absent local cache behaves identically.
                if let Some(fetch) = self.try_serve_local_narinfo(method, hash).await {
                    return fetch;
                }
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
                return upstream_failure(upstream_url, None, "upstream request failed");
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
        if content_length.is_some_and(|len| len > self.config.max_metadata_bytes()) {
            return upstream_failure(
                upstream_url,
                Some(upstream_status.as_u16()),
                "upstream response too large",
            );
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
        let body =
            match read_upstream_body_bounded(response, self.config.max_metadata_bytes()).await {
                Ok(body) => body,
                Err(err) => {
                    tracing::warn!(
                        upstream_url = %upstream_url,
                        error = %err,
                        "vm http nix cache upstream body read failed",
                    );
                    return upstream_failure(
                        upstream_url,
                        Some(upstream_status.as_u16()),
                        err.audit_error_label(),
                    );
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
                    return upstream_failure(
                        upstream_url,
                        Some(upstream_status.as_u16()),
                        narinfo_audit_error_label(&err),
                    );
                }
            };
            if let Err(err) = self.admit_narinfo(&narinfo, VmNixCacheNarSource::Upstream) {
                tracing::warn!(
                    upstream_url = %upstream_url,
                    error = %err,
                    "vm http nix cache upstream narinfo admission failed",
                );
                return upstream_failure(
                    upstream_url,
                    Some(upstream_status.as_u16()),
                    err.audit_error_label(),
                );
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
        let Some(entry) = self.admitted_nar(file) else {
            return upstream_failure(String::new(), None, "unadmitted upstream nar");
        };
        let admission = entry.admission;
        // The NAR's source was pinned when its narinfo was admitted. A NAR
        // admitted from the local archive is served authoritatively from disk
        // (so an upstream-admitted NAR is never broken by a same-named local
        // file, and vice-versa); only an upstream admission proxies the upstream.
        if entry.source == VmNixCacheNarSource::Local {
            let dir = self
                .config
                .local_cache_dir()
                .expect("a local NAR admission implies a configured local cache");
            let nar_path = dir.join("nar").join(file.as_str());
            return self.serve_local_nar(method, &nar_path, &admission).await;
        }
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
                return upstream_failure(upstream_url, None, "upstream request failed");
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
            self.config.max_nar_bytes(),
        ) {
            Ok(content_length) => content_length,
            Err(error) => {
                return upstream_failure(
                    upstream_url,
                    Some(upstream_status.as_u16()),
                    error.audit_error_label(),
                );
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

        let body = match read_upstream_body_bounded(response, self.config.max_nar_bytes()).await {
            Ok(body) => body,
            Err(err) => {
                tracing::warn!(
                    upstream_url = %upstream_url,
                    error = %err,
                    "vm http nix cache NAR upstream body read failed",
                );
                return upstream_failure(
                    upstream_url,
                    Some(upstream_status.as_u16()),
                    err.audit_error_label(),
                );
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
            match verify_nar_body_on_blocking_thread(admission, body, self.config.max_nar_bytes())
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

    /// Serve a narinfo from the broker's local flake-input archive, local-first.
    ///
    /// `Some` means the request was handled locally: either the
    /// content-addressed narinfo was served (and its NAR admitted), or a
    /// present-but-uncertifiable / oversized / unreadable local file failed
    /// closed. `None` means there is no local cache or no file for this hash, so
    /// the caller proxies the upstream exactly as before. A present file is
    /// authoritative — we never silently fall through to the upstream for it,
    /// because the upstream cannot hold these CA input-source paths anyway.
    async fn try_serve_local_narinfo(
        &self,
        method: &str,
        hash: &NixStoreHashPart,
    ) -> Option<VmHttpNixCacheProxyFetch> {
        let dir = self.config.local_cache_dir()?;
        let path = dir.join(format!("{}.narinfo", hash.as_str()));
        let local_url = local_file_url(&path);
        let bytes = match read_local_cache_file(&path, self.config.max_metadata_bytes()).await {
            LocalCacheFile::Missing => return None,
            LocalCacheFile::TooLarge => {
                return Some(local_failure(local_url, "local narinfo too large"));
            }
            LocalCacheFile::Io(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "vm http nix cache local narinfo read failed",
                );
                return Some(local_failure(local_url, "local narinfo read failed"));
            }
            LocalCacheFile::Bytes(bytes) => bytes,
        };
        let narinfo = match parse_content_addressed_narinfo_for_store_hash(&bytes, hash) {
            Ok(narinfo) => narinfo,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "vm http nix cache local narinfo was refused",
                );
                return Some(local_failure(local_url, local_ca_narinfo_error_label(&err)));
            }
        };
        if let Err(err) = self.admit_narinfo(&narinfo, VmNixCacheNarSource::Local) {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "vm http nix cache local narinfo admission failed",
            );
            return Some(local_failure(local_url, err.audit_error_label()));
        }
        if method == "HEAD" {
            let content_length = bytes.len() as u64;
            let response = VmHttpResponse::text(VmHttpStatus::Ok, "")
                .with_content_length(Some(content_length));
            return Some(VmHttpNixCacheProxyFetch {
                upstream_url: local_url,
                upstream_status: None,
                response_bytes: 0,
                error: None,
                response,
            });
        }
        // Serve the narinfo bytes verbatim — including the self-certifying CA —
        // so the guest accepts the path unsigned, exactly as it would from a
        // local `file://` substituter.
        let response_bytes = bytes.len() as u64;
        Some(VmHttpNixCacheProxyFetch {
            upstream_url: local_url,
            upstream_status: None,
            response_bytes,
            error: None,
            response: VmHttpResponse {
                status: VmHttpStatus::Ok,
                content_type: "text/plain; charset=utf-8",
                body: bytes,
                content_length: None,
                www_authenticate: None,
                headers: Vec::new(),
            },
        })
    }

    /// Serve a locally-admitted NAR authoritatively from the broker's archive at
    /// `nar_path`. The narinfo was admitted from the local archive, so the NAR is
    /// expected on disk; an absent / oversized / unreadable / hash-mismatched
    /// file fails closed rather than proxying the upstream (which cannot hold a
    /// content-addressed flake-input NAR anyway). The body is verified against
    /// the admitted narinfo before it is served, defence in depth against
    /// on-disk tamper.
    async fn serve_local_nar(
        &self,
        method: &str,
        nar_path: &Path,
        admission: &VmHttpNixCacheAdmittedNar,
    ) -> VmHttpNixCacheProxyFetch {
        let local_url = local_file_url(nar_path);
        if method == "HEAD" {
            // HEAD needs only the (bounded) length — never buffer a potentially
            // large NAR just to discard it.
            return match stat_local_cache_file(nar_path, self.config.max_nar_bytes()).await {
                LocalCacheStat::Missing => {
                    local_failure(local_url, "local nar missing for admitted path")
                }
                LocalCacheStat::TooLarge => local_failure(local_url, "local nar too large"),
                LocalCacheStat::Io(err) => {
                    tracing::warn!(
                        path = %nar_path.display(),
                        error = %err,
                        "vm http nix cache local nar stat failed",
                    );
                    local_failure(local_url, "local nar read failed")
                }
                LocalCacheStat::Len(content_length) => VmHttpNixCacheProxyFetch {
                    upstream_url: local_url,
                    upstream_status: None,
                    response_bytes: 0,
                    error: None,
                    response: VmHttpResponse {
                        status: VmHttpStatus::Ok,
                        content_type: "application/x-nix-nar",
                        body: Vec::new(),
                        content_length: Some(content_length),
                        www_authenticate: None,
                        headers: Vec::new(),
                    },
                },
            };
        }
        let body = match read_local_cache_file(nar_path, self.config.max_nar_bytes()).await {
            LocalCacheFile::Missing => {
                return local_failure(local_url, "local nar missing for admitted path");
            }
            LocalCacheFile::TooLarge => return local_failure(local_url, "local nar too large"),
            LocalCacheFile::Io(err) => {
                tracing::warn!(
                    path = %nar_path.display(),
                    error = %err,
                    "vm http nix cache local nar read failed",
                );
                return local_failure(local_url, "local nar read failed");
            }
            LocalCacheFile::Bytes(body) => body,
        };
        let content_length = body.len() as u64;
        let response_bytes = content_length;
        let body = match verify_nar_body_on_blocking_thread(
            admission.clone(),
            body,
            self.config.max_nar_bytes(),
        )
        .await
        {
            Ok(body) => body,
            Err(err) => {
                tracing::warn!(
                    path = %nar_path.display(),
                    error = %err,
                    "vm http nix cache local nar body was rejected",
                );
                let response = VmHttpResponse::text(
                    VmHttpStatus::BadGateway,
                    "nix cache local archive failed",
                );
                return VmHttpNixCacheProxyFetch {
                    upstream_url: local_url,
                    upstream_status: None,
                    response_bytes,
                    error: Some(err.audit_error_label()),
                    response,
                };
            }
        };
        VmHttpNixCacheProxyFetch {
            upstream_url: local_url,
            upstream_status: None,
            response_bytes,
            error: None,
            response: VmHttpResponse {
                status: VmHttpStatus::Ok,
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
            .upstream_base_url()
            .join(&path)
            .expect("Nix cache route paths are URL-safe relative paths")
    }

    fn admit_narinfo(
        &self,
        narinfo: &NixNarInfo,
        source: VmNixCacheNarSource,
    ) -> Result<(), VmHttpNixCacheNarAdmissionError> {
        let admission = VmHttpNixCacheAdmittedNar::from_narinfo(narinfo);
        let actual = admission.nar_size.get();
        let max = self.config.max_nar_bytes();
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
        // The conflict check is on the admission *content* only: a NAR file name
        // is content-addressed, so re-admitting the same file with different
        // metadata is a poisoning attempt. The source is not part of identity.
        let source = match admitted_nars.get(&admission.file) {
            Some(existing) if existing.admission != admission => {
                return Err(VmHttpNixCacheNarAdmissionError::ConflictingNarFile {
                    file: admission.file,
                });
            }
            // Once a NAR is admitted from the local archive, keep serving it
            // locally even if a later content-identical upstream admission
            // arrives (local-first, no egress).
            Some(existing) if existing.source == VmNixCacheNarSource::Local => {
                VmNixCacheNarSource::Local
            }
            _ => source,
        };
        admitted_nars.insert(
            admission.file.clone(),
            VmHttpNixCacheNarEntry { admission, source },
        );
        Ok(())
    }

    fn admitted_nar(&self, file: &NixCacheNarFileName) -> Option<VmHttpNixCacheNarEntry> {
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

impl VmHttpNixCacheNarAdmissionError {
    fn audit_error_label(&self) -> &'static str {
        match self {
            Self::NarSizeTooLarge { .. } => "upstream narinfo NarSize too large",
            Self::ConflictingNarFile { .. } => "conflicting upstream narinfo metadata",
            Self::InvalidNarHash { source } => nar_body_hash_error_label(source),
        }
    }
}

/// A fail-closed upstream proxy outcome: HTTP 502 with the generic
/// "nix cache upstream failed" body, recording `upstream_status` (when the
/// upstream replied) and the audit `error` label. Mirrors [`local_failure`] for
/// the local-archive path. The body is opaque to the guest.
fn upstream_failure(
    upstream_url: String,
    upstream_status: Option<u16>,
    error: &'static str,
) -> VmHttpNixCacheProxyFetch {
    let response = VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache upstream failed");
    VmHttpNixCacheProxyFetch {
        upstream_url,
        upstream_status,
        response_bytes: response.body.len() as u64,
        error: Some(error),
        response,
    }
}

/// Synthesize the `nix-cache-info` response locally (no upstream round-trip).
/// Audited with no upstream URL or status, since nothing was proxied.
fn local_cache_info(method: &str) -> VmHttpNixCacheProxyFetch {
    let response = if method == "HEAD" {
        VmHttpResponse::text(VmHttpStatus::Ok, "")
    } else {
        VmHttpResponse::text(VmHttpStatus::Ok, VM_NIX_CACHE_INFO_BODY)
    };
    let response_bytes = response.body.len() as u64;
    VmHttpNixCacheProxyFetch {
        upstream_url: String::new(),
        upstream_status: None,
        response_bytes,
        error: None,
        response,
    }
}

/// A fail-closed local outcome: HTTP 502, no upstream status, with `error` set
/// for the audit row. The body is opaque to the guest.
fn local_failure(upstream_url: String, error: &'static str) -> VmHttpNixCacheProxyFetch {
    let response = VmHttpResponse::text(VmHttpStatus::BadGateway, "nix cache local archive failed");
    VmHttpNixCacheProxyFetch {
        upstream_url,
        upstream_status: None,
        response_bytes: response.body.len() as u64,
        error: Some(error),
        response,
    }
}

fn local_ca_narinfo_error_label(err: &NixContentAddressedNarInfoError) -> &'static str {
    match err {
        NixContentAddressedNarInfoError::NarInfo(err) => narinfo_audit_error_label(err),
        NixContentAddressedNarInfoError::MissingContentAddress => {
            "local narinfo missing content address"
        }
        NixContentAddressedNarInfoError::NotSelfCertifying { .. } => {
            "local narinfo not self-certifying"
        }
        NixContentAddressedNarInfoError::StorePathNotContentDerived { .. } => {
            "local narinfo store path not content-derived"
        }
    }
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
