//! Example/edge-case tests for the local flake-input archive: serving narinfo
//! and NAR local-first (incl. HEAD and synthetic cache-info), the miss
//! fall-through to the signed upstream, and the fail-closed paths — uncertifiable
//! narinfo, over-budget file, on-disk tamper, missing NAR, and the non-regular
//! (symlink / FIFO) guards — plus the rule that an upstream-admitted NAR is
//! never shadowed by a same-named local file.

use std::net::Ipv4Addr;
use std::sync::Arc;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::tests::{make_broker_state, open_audit_session, session_for_subnet};
use super::route::VM_NIX_CACHE_INFO_PATH;
use super::test_support::*;
use super::*;
use crate::core::Ipv4Cidr;
use crate::nix_cache::NixTrustedPublicKeys;

#[tokio::test]
async fn local_archive_narinfo_and_nar_are_served_without_upstream() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let nar_file = "input.nar.xz";
    let (hash, narinfo_bytes, compressed) =
        write_local_ca_entry(cache.path(), "source", nar_file, b"local flake input nar");
    let service =
        nix_cache_service_with_local_cache(&state, DEAD_UPSTREAM, cache.path(), 4096, 4096);

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
    assert_eq!(narinfo_response.body, narinfo_bytes);
    assert_eq!(nar_response.status, VmHttpStatus::Ok);
    assert_eq!(nar_response.content_type, "application/x-nix-nar");
    assert_eq!(nar_response.content_length, Some(compressed.len() as u64));
    assert_eq!(nar_response.body, compressed);

    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].route, NixCacheAuditRoute::NarInfo);
    assert_eq!(entries[0].http_status, Some(200));
    assert_eq!(entries[0].upstream_status, None);
    assert_eq!(entries[0].error, None);
    assert!(
        entries[0]
            .upstream_url
            .as_deref()
            .is_some_and(|url| url.starts_with("file://")),
        "narinfo served locally should record a file:// source, got {:?}",
        entries[0].upstream_url,
    );
    assert_eq!(entries[1].route, NixCacheAuditRoute::Nar);
    assert_eq!(entries[1].http_status, Some(200));
    assert_eq!(entries[1].upstream_status, None);
    assert_eq!(entries[1].error, None);
    assert_eq!(
        entries[1].response_bytes,
        Some(compressed.len() as u64),
        "nar response bytes should match the compressed body",
    );
    assert!(
        entries[1]
            .upstream_url
            .as_deref()
            .is_some_and(|url| url.starts_with("file://")),
    );
}

#[tokio::test]
async fn local_archive_narinfo_head_returns_length_and_admits_the_nar() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let nar_file = "input.nar.xz";
    let (hash, narinfo_bytes, compressed) =
        write_local_ca_entry(cache.path(), "source", nar_file, b"head then get");
    let service =
        nix_cache_service_with_local_cache(&state, DEAD_UPSTREAM, cache.path(), 4096, 4096);

    let head = route_nix_cache_with_service(
        &session,
        "HEAD",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
        service.clone(),
    )
    .await;
    // A HEAD must still admit the path, so the following NAR GET succeeds.
    let nar = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{nar_file}"),
        service,
    )
    .await;

    assert_eq!(head.status, VmHttpStatus::Ok);
    assert!(head.body.is_empty());
    assert_eq!(head.content_length, Some(narinfo_bytes.len() as u64));
    assert_eq!(nar.status, VmHttpStatus::Ok);
    assert_eq!(nar.body, compressed);
}

#[tokio::test]
async fn local_cache_miss_falls_through_to_signed_upstream() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    // An empty local cache dir: every hash is a local miss.
    let cache = tempfile::tempdir().unwrap();
    let hash = "rzv95bakh41zrn5ji23pfc11x5vq2z4d";
    Mock::given(method("GET"))
        .and(path(format!("/{hash}.narinfo")))
        .respond_with(ResponseTemplate::new(200).set_body_string(TEST_SIGNED_NARINFO))
        .expect(1)
        .mount(&upstream)
        .await;
    let service = VmHttpNixCacheService::new(
        Arc::clone(&state),
        VmHttpNixCacheConfig::new_with_trusted_public_keys(
            upstream.uri(),
            1024,
            1024,
            NixTrustedPublicKeys::from_strings([TEST_NIX_CACHE_PUBLIC_KEY]).unwrap(),
        )
        .unwrap()
        .with_local_cache_dir(Some(cache.path().to_path_buf())),
    );

    let response = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
        service,
    )
    .await;

    assert_eq!(response.status, VmHttpStatus::Ok);
    assert_eq!(response.body, TEST_SIGNED_NARINFO.as_bytes());
    upstream.verify().await;
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].http_status, Some(200));
    assert_eq!(entries[0].upstream_status, Some(200));
    assert!(
        entries[0]
            .upstream_url
            .as_deref()
            .is_some_and(|url| url.ends_with(&format!("/{hash}.narinfo"))),
        "a local miss should proxy and audit the upstream URL, got {:?}",
        entries[0].upstream_url,
    );
}

#[tokio::test]
async fn local_signed_input_addressed_narinfo_and_nar_are_served_with_trusted_key() {
    // A pre-warmed devShell-closure path: a *signed*, input-addressed narinfo
    // (no CA field) whose key the broker trusts. The local archive must serve it
    // local-first, exactly as it serves a self-certifying CA flake input -- this
    // is the capability PW1 adds on top of FK's CA-only local serving.
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let key_pair = test_ed25519_key_pair();
    let store_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let nar_file = "prewarm-closure.nar.xz";
    let (narinfo_bytes, compressed) = write_local_signed_entry(
        cache.path(),
        &key_pair,
        store_hash,
        "writ-prewarm-closure",
        nar_file,
        b"a compiled devShell output",
    );
    let trusted = NixTrustedPublicKeys::from_strings([trusted_public_key_for_test(
        TEST_SIGNING_KEY_NAME,
        &key_pair,
    )])
    .unwrap();
    let service = nix_cache_service_with_local_cache_and_trusted_keys(
        &state,
        DEAD_UPSTREAM,
        cache.path(),
        trusted,
        4096,
        4096,
    );

    let narinfo_response = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/{store_hash}.narinfo"),
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
    // Served verbatim, Sig line intact, so the guest can verify it independently.
    assert_eq!(narinfo_response.body, narinfo_bytes);
    assert_eq!(nar_response.status, VmHttpStatus::Ok);
    assert_eq!(nar_response.content_type, "application/x-nix-nar");
    assert_eq!(nar_response.content_length, Some(compressed.len() as u64));
    assert_eq!(nar_response.body, compressed);

    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].route, NixCacheAuditRoute::NarInfo);
    assert_eq!(entries[0].http_status, Some(200));
    assert_eq!(entries[0].error, None);
    assert!(
        entries[0]
            .upstream_url
            .as_deref()
            .is_some_and(|url| url.starts_with("file://")),
        "a trusted-signed local narinfo must be served from the local archive, not upstream: {:?}",
        entries[0].upstream_url,
    );
    assert_eq!(entries[1].route, NixCacheAuditRoute::Nar);
    assert_eq!(entries[1].http_status, Some(200));
    assert_eq!(entries[1].error, None);
    assert!(
        entries[1]
            .upstream_url
            .as_deref()
            .is_some_and(|url| url.starts_with("file://")),
    );
}

#[tokio::test]
async fn local_signed_narinfo_with_untrusted_key_fails_closed() {
    // The same signed, input-addressed narinfo, but the broker trusts no keys:
    // it is admissible by neither the CA path (no CA) nor the signature path
    // (untrusted key), so it fails closed against the dead upstream rather than
    // serving an unvouched-for path. This is the security gate PW1 rests on.
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let key_pair = test_ed25519_key_pair();
    let store_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_local_signed_entry(
        cache.path(),
        &key_pair,
        store_hash,
        "writ-prewarm-closure",
        "prewarm-closure.nar.xz",
        b"a compiled devShell output",
    );
    let service = nix_cache_service_with_local_cache_and_trusted_keys(
        &state,
        DEAD_UPSTREAM,
        cache.path(),
        NixTrustedPublicKeys::empty(),
        4096,
        4096,
    );

    let response = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/{store_hash}.narinfo"),
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
    assert_eq!(entries[0].upstream_status, None);
    assert_eq!(
        entries[0].error.as_deref(),
        Some("local narinfo neither self-certifying nor trusted-signed"),
    );
}

#[tokio::test]
async fn local_cache_info_is_served_synthetically_without_upstream() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    // A *provisioned* local archive + a dead upstream: the mandatory cache-info
    // pre-flight is served synthetically so the guest reaches the local-first
    // narinfo/NAR paths rather than rejecting the substituter. (An empty archive
    // instead proxies the upstream — see
    // `cache_info_proxies_upstream_when_local_cache_empty`.)
    write_local_ca_entry(
        cache.path(),
        "source",
        "input.nar.xz",
        b"local flake input nar",
    );
    let service =
        nix_cache_service_with_local_cache(&state, DEAD_UPSTREAM, cache.path(), 4096, 4096);

    let response =
        route_nix_cache_with_service(&session, "GET", VM_NIX_CACHE_INFO_PATH.into(), service).await;

    assert_eq!(response.status, VmHttpStatus::Ok);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains("StoreDir: /nix/store"), "{body}");
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].route, NixCacheAuditRoute::CacheInfo);
    assert_eq!(entries[0].http_status, Some(200));
    assert_eq!(entries[0].upstream_status, None);
    assert_eq!(entries[0].upstream_url, None);
    assert_eq!(entries[0].error, None);
}

#[tokio::test]
async fn cache_info_proxies_upstream_when_local_cache_empty() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    // A configured-but-empty local archive has nothing to serve, so cache-info
    // is proxied (not synthesised): a still-unprovisioned broker stays
    // byte-identical to upstream-only and the upstream sees the request.
    let cache = tempfile::tempdir().unwrap();
    let upstream_body = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n";
    Mock::given(method("GET"))
        .and(path("/nix-cache-info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(upstream_body))
        .expect(1)
        .mount(&upstream)
        .await;
    let service =
        nix_cache_service_with_local_cache(&state, &upstream.uri(), cache.path(), 1024, 1024);

    let response =
        route_nix_cache_with_service(&session, "GET", VM_NIX_CACHE_INFO_PATH.into(), service).await;

    assert_eq!(response.status, VmHttpStatus::Ok);
    assert_eq!(String::from_utf8(response.body).unwrap(), upstream_body);
    upstream.verify().await;
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].route, NixCacheAuditRoute::CacheInfo);
    assert_eq!(entries[0].upstream_status, Some(200));
    assert!(
        entries[0]
            .upstream_url
            .as_deref()
            .is_some_and(|url| url.ends_with("/nix-cache-info")),
        "an empty local cache must proxy + audit the upstream cache-info, got {:?}",
        entries[0].upstream_url,
    );
}

#[tokio::test]
async fn cache_info_ignores_stale_provisioning_temp_narinfo_and_proxies_upstream() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    // Provisioning was interrupted after copying a narinfo to its temp sibling
    // (`.writ-tmp-<uuid>-<hash>.narinfo`) but before the final rename, so the
    // only `.narinfo`-suffixed file is one `try_serve_local_narinfo` will never
    // read (it serves `<hash>.narinfo` only). The archive is effectively empty,
    // so cache-info must proxy the upstream rather than synthesise a cache for
    // content it cannot serve.
    let cache = tempfile::tempdir().unwrap();
    let hash = "rzv95bakh41zrn5ji23pfc11x5vq2z4d";
    std::fs::write(
        cache
            .path()
            .join(format!(".writ-tmp-0123456789abcdef-{hash}.narinfo")),
        b"StorePath: /nix/store/rzv95bakh41zrn5ji23pfc11x5vq2z4d-src\n",
    )
    .unwrap();
    let upstream_body = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n";
    Mock::given(method("GET"))
        .and(path("/nix-cache-info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(upstream_body))
        .expect(1)
        .mount(&upstream)
        .await;
    let service =
        nix_cache_service_with_local_cache(&state, &upstream.uri(), cache.path(), 1024, 1024);

    let response =
        route_nix_cache_with_service(&session, "GET", VM_NIX_CACHE_INFO_PATH.into(), service).await;

    assert_eq!(response.status, VmHttpStatus::Ok);
    assert_eq!(String::from_utf8(response.body).unwrap(), upstream_body);
    upstream.verify().await;
}

#[tokio::test]
async fn local_narinfo_present_but_not_self_certifying_fails_closed() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let hash = "00000000000000000000000000000000";
    // A narinfo whose CA is `text:` rather than the required recursive
    // `fixed:r:sha256:` (so it is not self-certifying) and which carries no
    // signature — present, so it is authoritative and fails closed rather than
    // proxying the (dead) upstream. Post-PW1 the refusal lands at the signature
    // stage (neither self-certifying nor trusted-signed), not the CA stage.
    let nar_hash = nar_hash_for_body(b"whatever");
    let nar_digest = nar_hash.strip_prefix("sha256:").unwrap();
    let narinfo = format!(
        "StorePath: /nix/store/{hash}-source\nURL: nar/input.nar.xz\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 8\nReferences: \nCA: text:sha256:{nar_digest}\n"
    );
    std::fs::write(
        cache.path().join(format!("{hash}.narinfo")),
        narinfo.as_bytes(),
    )
    .unwrap();
    let service =
        nix_cache_service_with_local_cache(&state, DEAD_UPSTREAM, cache.path(), 4096, 4096);

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
    assert_eq!(entries[0].upstream_status, None);
    assert_eq!(
        entries[0].error.as_deref(),
        Some("local narinfo neither self-certifying nor trusted-signed"),
    );
}

#[tokio::test]
async fn local_narinfo_over_metadata_budget_fails_closed() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let (hash, _, _) =
        write_local_ca_entry(cache.path(), "source", "input.nar.xz", b"local nar body");
    // A metadata budget smaller than the narinfo file forces a fail-closed.
    let service = nix_cache_service_with_local_cache(&state, DEAD_UPSTREAM, cache.path(), 8, 4096);

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
    assert_eq!(entries[0].error.as_deref(), Some("local narinfo too large"));
    assert_eq!(entries[0].upstream_status, None);
}

#[tokio::test]
async fn local_nar_body_tamper_is_rejected_before_serving() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let nar_file = "input.nar.xz";
    let (hash, _, _) =
        write_local_ca_entry(cache.path(), "source", nar_file, b"trusted local body");
    // Overwrite the on-disk NAR with a different (valid xz) body: its hash no
    // longer matches the admitted narinfo, so serving must fail closed.
    std::fs::write(
        cache.path().join("nar").join(nar_file),
        xz_nar_body_for(b"tampered body of different length"),
    )
    .unwrap();
    let service =
        nix_cache_service_with_local_cache(&state, DEAD_UPSTREAM, cache.path(), 4096, 4096);

    let narinfo = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
        service.clone(),
    )
    .await;
    let nar = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{nar_file}"),
        service,
    )
    .await;

    assert_eq!(narinfo.status, VmHttpStatus::Ok);
    assert_eq!(nar.status, VmHttpStatus::BadGateway);
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].route, NixCacheAuditRoute::Nar);
    assert_eq!(entries[1].http_status, Some(502));
    assert_eq!(entries[1].upstream_status, None);
    assert_eq!(
        entries[1].error.as_deref(),
        Some("mismatched upstream nar size"),
    );
}

#[tokio::test]
async fn upstream_admitted_nar_is_not_shadowed_by_a_local_file() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let hash = "rzv95bakh41zrn5ji23pfc11x5vq2z4d";
    let nar_body = test_xz_nar_body();
    // The signed narinfo is only upstream (no `<hash>.narinfo` locally), so it
    // proxies and admits from the upstream.
    Mock::given(method("GET"))
        .and(path(format!("/{hash}.narinfo")))
        .respond_with(ResponseTemplate::new(200).set_body_string(TEST_SIGNED_NARINFO))
        .expect(1)
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/nar/{TEST_NAR_FILE}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(nar_body.clone()))
        .expect(1)
        .mount(&upstream)
        .await;
    // A garbage local NAR sharing the upstream narinfo's URL name must NOT
    // shadow the valid signed upstream NAR.
    std::fs::create_dir_all(cache.path().join("nar")).unwrap();
    std::fs::write(
        cache.path().join("nar").join(TEST_NAR_FILE),
        xz_nar_body_for(b"unrelated local content"),
    )
    .unwrap();
    let service = VmHttpNixCacheService::new(
        Arc::clone(&state),
        VmHttpNixCacheConfig::new_with_trusted_public_keys(
            upstream.uri(),
            1024,
            1024,
            NixTrustedPublicKeys::from_strings([TEST_NIX_CACHE_PUBLIC_KEY]).unwrap(),
        )
        .unwrap()
        .with_local_cache_dir(Some(cache.path().to_path_buf())),
    );

    let narinfo = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
        service.clone(),
    )
    .await;
    let nar = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{TEST_NAR_FILE}"),
        service,
    )
    .await;

    assert_eq!(narinfo.status, VmHttpStatus::Ok);
    assert_eq!(nar.status, VmHttpStatus::Ok);
    // The valid upstream body, not the local garbage.
    assert_eq!(nar.body, nar_body);
    upstream.verify().await;
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].route, NixCacheAuditRoute::Nar);
    assert_eq!(entries[1].http_status, Some(200));
    assert_eq!(entries[1].upstream_status, Some(200));
    assert!(
        entries[1]
            .upstream_url
            .as_deref()
            .is_some_and(|url| url.ends_with(&format!("/nar/{TEST_NAR_FILE}"))),
        "an upstream-admitted NAR must be fetched from the upstream, got {:?}",
        entries[1].upstream_url,
    );
}

#[tokio::test]
async fn local_admitted_nar_missing_on_disk_fails_closed() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let nar_file = "input.nar.xz";
    let (hash, _, _) = write_local_ca_entry(cache.path(), "source", nar_file, b"present then gone");
    // Remove the NAR after the narinfo is in place: a local (authoritative)
    // admission whose NAR is missing must fail closed, not proxy the upstream.
    std::fs::remove_file(cache.path().join("nar").join(nar_file)).unwrap();
    let service =
        nix_cache_service_with_local_cache(&state, DEAD_UPSTREAM, cache.path(), 4096, 4096);

    let narinfo = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
        service.clone(),
    )
    .await;
    let nar = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{nar_file}"),
        service,
    )
    .await;

    assert_eq!(narinfo.status, VmHttpStatus::Ok);
    assert_eq!(nar.status, VmHttpStatus::BadGateway);
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].route, NixCacheAuditRoute::Nar);
    assert_eq!(entries[1].http_status, Some(502));
    assert_eq!(entries[1].upstream_status, None);
    assert_eq!(
        entries[1].error.as_deref(),
        Some("local nar missing for admitted path"),
    );
}

#[cfg(unix)]
#[tokio::test]
async fn local_nar_non_regular_file_is_refused_not_opened() {
    // FIFO-class guard: a non-regular cache entry (here a symlink, which on
    // Unix could point at a FIFO) at the NAR path must be refused via lstat
    // before opening — opening a FIFO for read would block the request. The
    // narinfo is admitted from a regular file; the NAR is then swapped for a
    // symlink to a valid sibling and must fail closed (not be followed).
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let nar_file = "input.nar.xz";
    let (hash, _, _) = write_local_ca_entry(cache.path(), "source", nar_file, b"regular then link");
    // Replace the regular NAR with a symlink to a valid sibling NAR file.
    let nar_path = cache.path().join("nar").join(nar_file);
    let target = cache.path().join("nar").join("target.nar.xz");
    std::fs::write(&target, xz_nar_body_for(b"symlink target body")).unwrap();
    std::fs::remove_file(&nar_path).unwrap();
    std::os::unix::fs::symlink(&target, &nar_path).unwrap();
    let service =
        nix_cache_service_with_local_cache(&state, DEAD_UPSTREAM, cache.path(), 4096, 4096);

    let narinfo = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
        service.clone(),
    )
    .await;
    let nar = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{nar_file}"),
        service,
    )
    .await;

    assert_eq!(narinfo.status, VmHttpStatus::Ok);
    assert_eq!(nar.status, VmHttpStatus::BadGateway);
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries[1].route, NixCacheAuditRoute::Nar);
    assert_eq!(entries[1].http_status, Some(502));
    assert_eq!(
        entries[1].error.as_deref(),
        Some("local nar missing for admitted path"),
    );
}

#[cfg(unix)]
#[tokio::test]
async fn local_nar_fifo_does_not_block_and_is_refused() {
    use std::os::unix::ffi::OsStrExt as _;

    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let nar_file = "input.nar.xz";
    let (hash, _, _) = write_local_ca_entry(cache.path(), "source", nar_file, b"regular then fifo");
    // Replace the regular NAR with a FIFO: opening it for read blocks until a
    // writer appears unless the open is non-blocking. There is no writer here,
    // so a blocking open would hang the request forever.
    let nar_path = cache.path().join("nar").join(nar_file);
    std::fs::remove_file(&nar_path).unwrap();
    let c_path = std::ffi::CString::new(nar_path.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
    let service =
        nix_cache_service_with_local_cache(&state, DEAD_UPSTREAM, cache.path(), 4096, 4096);

    let narinfo = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
        service.clone(),
    )
    .await;
    let nar = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        route_nix_cache_with_service(
            &session,
            "GET",
            format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{nar_file}"),
            service,
        ),
    )
    .await
    .expect("a FIFO NAR must not block the request");

    assert_eq!(narinfo.status, VmHttpStatus::Ok);
    assert_eq!(nar.status, VmHttpStatus::BadGateway);
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries[1].route, NixCacheAuditRoute::Nar);
    assert_eq!(entries[1].http_status, Some(502));
    assert_eq!(
        entries[1].error.as_deref(),
        Some("local nar missing for admitted path"),
    );
}

#[tokio::test]
async fn local_nar_head_returns_content_length_without_the_body() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let nar_file = "input.nar.xz";
    let (hash, _, compressed) =
        write_local_ca_entry(cache.path(), "source", nar_file, b"head this nar");
    let service =
        nix_cache_service_with_local_cache(&state, DEAD_UPSTREAM, cache.path(), 4096, 4096);

    let narinfo = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
        service.clone(),
    )
    .await;
    let head = route_nix_cache_with_service(
        &session,
        "HEAD",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/nar/{nar_file}"),
        service,
    )
    .await;

    assert_eq!(narinfo.status, VmHttpStatus::Ok);
    assert_eq!(head.status, VmHttpStatus::Ok);
    assert_eq!(head.content_type, "application/x-nix-nar");
    assert!(head.body.is_empty());
    assert_eq!(head.content_length, Some(compressed.len() as u64));
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries[1].route, NixCacheAuditRoute::Nar);
    assert_eq!(entries[1].http_status, Some(200));
    assert_eq!(entries[1].response_bytes, Some(0));
    assert_eq!(entries[1].error, None);
}
