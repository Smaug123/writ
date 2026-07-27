//! Nix cache: serves the binary-cache protocol on the broker's VM-facing HTTP
//! endpoint, forwarding `nix-cache-info`, `*.narinfo`, and NAR fetches to a
//! configured upstream while admitting only signed narinfos and verifying NAR
//! bodies before they reach the guest.
//!
//! Two views over the same service: `/v1/nix/cache` serves the local archives
//! local-first and falls through to the upstream proxy, while `/v1/nix/prewarm`
//! serves the local archives *only* (a miss is a `404`, never an upstream
//! fetch) so the devShell warm can be pinned to the pre-warmed closure.
//!
//! This module is the imperative shell that wires the request-classification
//! (`route`), config validation (`config`), NAR verification (`nar_verify`) and
//! local-archive file IO (`local_cache`) submodules into the proxy service and
//! its audit trail.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use writ_core::byte_size::ByteSize;

use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, NixCacheAuditDecision, NixCacheAuditRoute,
    NixCacheOutcomeRecord, NixCacheRequestRecord,
};
use crate::core::{RequestId, UnixMillis};
use crate::nix_binary_cache::{
    NixCacheNarFileName, NixLocalNarInfoError, NixNarBodyHashError, NixNarInfo, NixNarInfoError,
    NixStoreHashPart, parse_local_admissible_narinfo_for_store_hash,
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
pub use route::{VM_NIX_BASIC_LOGIN, VM_NIX_CACHE_PATH_PREFIX, VM_NIX_PREWARM_PATH_PREFIX};

use local_cache::{
    LocalCacheFile, LocalCacheStat, local_file_url, read_local_cache_file, stat_local_cache_file,
};
use nar_verify::{
    VmHttpNixCacheAdmittedNar, nar_body_hash_error_label, validate_nar_body_length,
    validate_nar_content_length, verify_nar_body_on_blocking_thread,
};
use route::{VM_NIX_CACHE_INFO_BODY, VmNixCacheRoute, VmNixCacheView, classify_nix_cache_target};
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
    /// Admitted from the broker's local archive at
    /// `local_cache_dirs()[dir_index]`; the NAR is served authoritatively from
    /// that same dir's `nar/<file>` (so a NAR is never served from a different
    /// local dir than the one whose narinfo admitted it).
    Local { dir_index: usize },
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
    let Some((view, route)) = classify_nix_cache_target(&request.target) else {
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
    // The audit row is written coalesced with the outcome *after* the fetch (a
    // cache serve grants no authority, so its request row need not be durable
    // before the action — one commit beats two on the audit-write `fsync`
    // path). But refuse a closed/unknown session *before* doing any cache I/O
    // on its behalf: the coalesced write re-checks inside its transaction, yet
    // only after the fetch has run. This read-only check adds no commit.
    if let Err(err) = service
        .broker_state
        .audit
        .require_session_open(session.session_id())
    {
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
    // Stamp arrival before the fetch so `received_at` still reflects when the
    // request came in; the request row is written together with its outcome in
    // one commit after the fetch (see `record_nix_cache_request_and_outcome`).
    let received_at = UnixMillis::now();
    let fetch = service
        .fetch_route(request.method.as_str(), view, &route)
        .await;
    if let Err(err) = record_nix_cache_request_and_outcome(
        &service,
        request_id,
        received_at,
        session,
        request,
        NixCacheAuditDecision::Allow,
        Some(&route),
        &fetch,
    ) {
        tracing::error!(
            target: AUDIT_WRITE_FAILURE_TARGET,
            kind = "nix_cache_request_and_outcome",
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
    let received_at = UnixMillis::now();
    let fetch = VmHttpNixCacheProxyFetch {
        upstream_url: String::new(),
        upstream_status: None,
        response_bytes: response.body.len() as u64,
        error: None,
        response,
    };
    if let Err(err) = record_nix_cache_request_and_outcome(
        service,
        request_id,
        received_at,
        session,
        request,
        decision,
        route,
        &fetch,
    ) {
        tracing::error!(
            target: AUDIT_WRITE_FAILURE_TARGET,
            kind = "nix_cache_request_and_outcome",
            request_id = %request_id,
            error = %err,
            "audit write failed",
        );
        return VmHttpResponse::text(VmHttpStatus::InternalServerError, "audit write failed");
    }
    fetch.response
}

/// Record a Nix cache request and its outcome as one audit commit. `received_at`
/// is captured by the caller before the fetch so it still marks arrival, while
/// `completed_at` is stamped here at write time. Coalescing the two rows keeps a
/// request row from ever landing without its outcome and halves the audit-write
/// `fsync` count on the (authority-free) cache serve path.
#[allow(clippy::too_many_arguments)]
fn record_nix_cache_request_and_outcome<S: SecretStore>(
    service: &VmHttpNixCacheService<S>,
    request_id: RequestId,
    received_at: UnixMillis,
    session: &VmHttpSession,
    request: &VmHttpRequest,
    decision: NixCacheAuditDecision,
    route: Option<&VmNixCacheRoute>,
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
        .record_nix_cache_request_and_outcome(
            &NixCacheRequestRecord {
                request_id,
                session_id: session.session_id(),
                received_at,
                method: &request.method,
                target: &request.target,
                route: nix_cache_audit_route(request, route),
                decision: &decision,
            },
            &NixCacheOutcomeRecord {
                request_id,
                completed_at: UnixMillis::now(),
                http_status: fetch.response.status.code(),
                upstream_url,
                upstream_status: audit_upstream_status(fetch.upstream_status),
                response_bytes: fetch.response_bytes,
                error: fetch.error,
            },
        )
}

fn audit_upstream_status(status: Option<u16>) -> Option<u16> {
    status.filter(|status| (100..=599).contains(status))
}

fn nix_cache_audit_route(
    request: &VmHttpRequest,
    route: Option<&VmNixCacheRoute>,
) -> NixCacheAuditRoute {
    let route = route
        .cloned()
        .or_else(|| classify_nix_cache_target(&request.target).map(|(_view, route)| route));
    match route {
        Some(VmNixCacheRoute::CacheInfo) => NixCacheAuditRoute::CacheInfo,
        Some(VmNixCacheRoute::NarInfo { .. }) => NixCacheAuditRoute::NarInfo,
        Some(VmNixCacheRoute::Nar { .. }) => NixCacheAuditRoute::Nar,
        None => NixCacheAuditRoute::Unsupported,
    }
}

impl<S: SecretStore> VmHttpNixCacheService<S> {
    async fn fetch_route(
        &self,
        method: &str,
        view: VmNixCacheView,
        route: &VmNixCacheRoute,
    ) -> VmHttpNixCacheProxyFetch {
        match route {
            VmNixCacheRoute::CacheInfo => match view {
                // Serve the cache metadata locally only once the archive holds
                // something to serve, so the guest's mandatory pre-flight
                // `nix-cache-info` is decoupled from upstream reachability
                // exactly when that buys resilience — a no-egress guest can
                // substitute a provisioned local archive even if the upstream
                // cache is momentarily unavailable. A configured-but-empty
                // archive (nothing provisioned yet) has nothing to serve, so it
                // proxies the upstream exactly as before and stays
                // byte-identical to upstream-only.
                VmNixCacheView::Proxied => {
                    if self.local_cache_has_narinfo().await {
                        local_cache_info(method)
                    } else {
                        self.fetch_metadata(method, route).await
                    }
                }
                // The pre-warm-only view has no upstream to defer to: the
                // synthetic metadata is always the answer, even over empty
                // archives (an empty cache is a valid cache that simply misses
                // every narinfo; Nix rejects a substituter whose
                // `nix-cache-info` errors, so this must never 404).
                VmNixCacheView::LocalOnly => local_cache_info(method),
            },
            VmNixCacheRoute::NarInfo { hash } => {
                // Local-first on both views: a narinfo in the broker's archives
                // is served (and admitted) without contacting the upstream. On
                // a local miss the proxied view falls through to the signed
                // upstream proxy; the pre-warm-only view answers a clean miss,
                // so the warm fails fast instead of substituting a path that
                // was never warmed.
                if let Some(fetch) = self.try_serve_local_narinfo(method, hash).await {
                    return fetch;
                }
                match view {
                    VmNixCacheView::Proxied => self.fetch_metadata(method, route).await,
                    VmNixCacheView::LocalOnly => local_not_found(),
                }
            }
            VmNixCacheRoute::Nar { .. } => self.fetch_nar(method, view, route).await,
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
                    error = %crate::server::error_with_source_chain(&err),
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
            let response = VmHttpResponse::text(VmHttpStatus::Ok, "")
                .with_content_length(content_length.map(ByteSize::get));
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

    async fn fetch_nar(
        &self,
        method: &str,
        view: VmNixCacheView,
        route: &VmNixCacheRoute,
    ) -> VmHttpNixCacheProxyFetch {
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
        if let VmNixCacheNarSource::Local { dir_index } = entry.source {
            let dir = self
                .config
                .local_cache_dirs()
                .get(dir_index)
                .expect("a local NAR admission pins a configured local cache dir");
            let nar_path = dir.join("nar").join(file.as_str());
            return self.serve_local_nar(method, &nar_path).await;
        }
        // An upstream-admitted NAR can only be served by proxying the upstream,
        // which the pre-warm-only view exists to forbid. Reachable only if the
        // guest admits a narinfo through the proxied view and then asks the
        // pre-warm view for its NAR (Nix itself never splits a substituter's
        // narinfo/NAR fetches across base URLs); fail closed rather than proxy.
        if view == VmNixCacheView::LocalOnly {
            return local_failure(
                String::new(),
                "upstream-admitted nar refused on pre-warm route",
            );
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
                    error = %crate::server::error_with_source_chain(&err),
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
                content_length: Some(content_length.get()),
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
        if let Err(err) = validate_nar_body_length(ByteSize::of(body.len()), content_length) {
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
                content_length: Some(content_length.get()),
                www_authenticate: None,
                headers: Vec::new(),
            },
        }
    }

    /// Whether any local archive currently holds at least one narinfo to serve.
    /// Gates the synthetic `nix-cache-info`: its upstream-independence only
    /// earns its keep when there is local content to substitute, so when every
    /// configured dir is empty or absent the broker proxies the upstream and
    /// stays byte-identical to upstream-only. `nix-cache-info` is requested once
    /// per substituter pre-flight, so the directory scan (short-circuiting on
    /// the first servable narinfo in the first dir that has one) is off the hot
    /// path.
    async fn local_cache_has_narinfo(&self) -> bool {
        for dir in self.config.local_cache_dirs() {
            let mut entries = match tokio::fs::read_dir(dir).await {
                Ok(entries) => entries,
                // A missing or unreadable archive dir has nothing to serve.
                Err(_) => continue,
            };
            while let Ok(Some(entry)) = entries.next_entry().await {
                if is_servable_local_narinfo_name(&entry.file_name()) {
                    return true;
                }
            }
        }
        false
    }

    /// Serve a narinfo from the broker's local archives, local-first and in
    /// configured order (pre-warm dir before flake-input dir).
    ///
    /// A local narinfo is admitted if it is self-certifying (a content-addressed
    /// flake input) **or** signed by a trusted key (a pre-warmed devShell-closure
    /// path, whose input-addressed outputs are not self-certifying).
    ///
    /// `Some` means the request was handled locally by the first dir that holds
    /// `<hash>.narinfo`: either an admissible narinfo was served (and its NAR
    /// admitted, pinned to *that* dir), or a present-but-inadmissible / oversized
    /// / unreadable file in that dir failed closed. A present file is
    /// authoritative for its dir — we neither fall through to a later dir nor to
    /// the upstream for a hash a dir already claims. `None` means *no* dir holds
    /// the hash, so the caller proxies the upstream exactly as before.
    async fn try_serve_local_narinfo(
        &self,
        method: &str,
        hash: &NixStoreHashPart,
    ) -> Option<VmHttpNixCacheProxyFetch> {
        for (dir_index, dir) in self.config.local_cache_dirs().iter().enumerate() {
            let path = dir.join(format!("{}.narinfo", hash.as_str()));
            let local_url = local_file_url(&path);
            let bytes = match read_local_cache_file(&path, self.config.max_metadata_bytes()).await {
                // Absent from this dir: try the next one (a later dir, or finally
                // the upstream).
                LocalCacheFile::Missing => continue,
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
            let narinfo = match parse_local_admissible_narinfo_for_store_hash(
                &bytes,
                hash,
                self.config.trusted_public_keys(),
            ) {
                Ok(narinfo) => narinfo,
                Err(err) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %err,
                        "vm http nix cache local narinfo was refused",
                    );
                    return Some(local_failure(local_url, local_narinfo_error_label(&err)));
                }
            };
            if let Err(err) = self.admit_narinfo(&narinfo, VmNixCacheNarSource::Local { dir_index })
            {
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
            // Serve the narinfo bytes verbatim — including the self-certifying CA
            // or the Sig line — so the guest accepts the path exactly as it would
            // from a local `file://` substituter: a CA path unsigned, a signed
            // path after re-verifying the signature against its own trusted keys.
            let response_bytes = bytes.len() as u64;
            return Some(VmHttpNixCacheProxyFetch {
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
            });
        }
        None
    }

    /// Serve a locally-admitted NAR authoritatively from the broker's archive at
    /// `nar_path`. The narinfo was admitted from the local archive, so the NAR is
    /// expected on disk; an absent / oversized / unreadable file fails closed
    /// rather than proxying the upstream (which cannot hold a content-addressed
    /// flake-input NAR anyway).
    ///
    /// The on-disk bytes are served verbatim — the broker does *not* decompress
    /// and re-hash them against the admitted narinfo on every serve. The local
    /// archive is a broker-owned, read-only mount the broker itself provisioned
    /// (`nix flake archive` → `merge_into_cache`); its narinfo is admitted only
    /// when self-certifying (a content-addressed flake input) or signed by a
    /// trusted key, and the guest re-verifies every NAR against that narinfo
    /// before it enters the store. Re-decompressing and re-hashing the whole NAR
    /// on every serve (the old defence-in-depth against on-disk tamper) put a
    /// full xz-decode + SHA-256 on the hot path of *every* substitution for no
    /// integrity the narinfo admission and the guest's own verification don't
    /// already provide; on-disk corruption now surfaces as the guest rejecting
    /// the NAR rather than a broker 502. The compressed read stays bounded by
    /// `max_nar_bytes`, so response size is still capped. Upstream-admitted NARs
    /// (untrusted) are still fully verified — see [`Self::fetch_nar`].
    async fn serve_local_nar(&self, method: &str, nar_path: &Path) -> VmHttpNixCacheProxyFetch {
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
        if ByteSize::from_bytes(actual) > max {
            return Err(VmHttpNixCacheNarAdmissionError::NarSizeTooLarge {
                max: max.get(),
                actual,
            });
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
            // Once a NAR is admitted from a local archive, keep serving it from
            // that same local dir even if a later content-identical admission
            // arrives — from the upstream or from another local dir (local-first,
            // no egress; the dir that first claimed the NAR keeps it).
            Some(existing) if matches!(existing.source, VmNixCacheNarSource::Local { .. }) => {
                existing.source
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

fn upstream_content_length(response: &reqwest::Response) -> Option<ByteSize> {
    response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()
        .map(ByteSize::from_bytes)
}

async fn read_upstream_body_bounded(
    mut response: reqwest::Response,
    max: ByteSize,
) -> Result<Vec<u8>, VmHttpNixCacheBodyReadError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let chunk_len = u64::try_from(chunk.len()).expect("HTTP chunk length fits in u64");
        let new_len = (body.len() as u64)
            .checked_add(chunk_len)
            .expect("HTTP response byte count overflowed before configured bound check");
        if ByteSize::from_bytes(new_len) > max {
            return Err(VmHttpNixCacheBodyReadError::ResponseTooLarge { max: max.get() });
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

/// Whether a directory entry name is one `try_serve_local_narinfo` would serve:
/// exactly `<hash>.narinfo` for a valid store hash, matching the path it builds
/// (`format!("{}.narinfo", hash.as_str())`). The `.narinfo` extension alone is
/// not enough — a provisioning that was interrupted after copying a narinfo to
/// its temp sibling (`.writ-tmp-<uuid>-<hash>.narinfo`, see `flake_provision`)
/// but before the final rename shares the extension yet is never served, so it
/// must not advertise the archive as provisioned.
fn is_servable_local_narinfo_name(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_suffix(".narinfo"))
        .is_some_and(|hash| NixStoreHashPart::validate(hash).is_ok())
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

/// A clean local miss on the pre-warm-only view: HTTP 404 with no upstream
/// contact and no audit error — a miss is the expected answer for a path that
/// was never warmed, mirroring the proxied view's handling of an upstream 404.
fn local_not_found() -> VmHttpNixCacheProxyFetch {
    let response = VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
    VmHttpNixCacheProxyFetch {
        upstream_url: String::new(),
        upstream_status: None,
        response_bytes: response.body.len() as u64,
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

fn local_narinfo_error_label(err: &NixLocalNarInfoError) -> &'static str {
    match err {
        // A genuinely malformed / mislabelled local file: reuse the field-level
        // narinfo labels (the "upstream" wording is the shared label set).
        NixLocalNarInfoError::Malformed(err) => narinfo_audit_error_label(err),
        // Well-formed but admissible as neither self-certifying nor
        // trusted-signed (no usable CA, and no signature by a trusted key).
        NixLocalNarInfoError::UntrustedOrUnsigned(_) => {
            "local narinfo neither self-certifying nor trusted-signed"
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
