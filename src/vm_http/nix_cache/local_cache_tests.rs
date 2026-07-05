//! Example/edge-case tests for the local flake-input archive: serving narinfo
//! and NAR local-first (incl. HEAD and synthetic cache-info), the miss
//! fall-through to the signed upstream, and the fail-closed paths — uncertifiable
//! narinfo, over-budget file, on-disk tamper, missing NAR, and the non-regular
//! (symlink / FIFO) guards — plus the rule that an upstream-admitted NAR is
//! never shadowed by a same-named local file.
//!
//! The `prewarm_view_*` tests at the bottom cover the `/v1/nix/prewarm`
//! local-only view: the same local archives, but a miss is a `404` and the
//! upstream is never contacted.

use std::net::Ipv4Addr;
use std::sync::Arc;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::tests::{make_broker_state, open_audit_session, session_for_subnet};
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
        .with_local_cache_dirs(vec![cache.path().to_path_buf()]),
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
async fn prewarm_dir_is_served_local_first_ahead_of_the_flake_input_dir() {
    // Two local archives [pre-warm, flake-input]; a signed closure path lives in
    // the pre-warm dir and the flake-input dir is empty. The pre-warm dir serves
    // it local-first.
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let prewarm = tempfile::tempdir().unwrap();
    let flake_input = tempfile::tempdir().unwrap();
    let key_pair = test_ed25519_key_pair();
    let store_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let nar_file = "prewarm-closure.nar.xz";
    let (narinfo_bytes, compressed) = write_local_signed_entry(
        prewarm.path(),
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
    let service = nix_cache_service_with_local_cache_dirs_and_trusted_keys(
        &state,
        DEAD_UPSTREAM,
        vec![
            prewarm.path().to_path_buf(),
            flake_input.path().to_path_buf(),
        ],
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
    assert_eq!(narinfo_response.body, narinfo_bytes);
    assert_eq!(nar_response.status, VmHttpStatus::Ok);
    assert_eq!(nar_response.body, compressed);
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    let prewarm_prefix = format!("file://{}", prewarm.path().display());
    assert!(
        entries.iter().all(|e| e
            .upstream_url
            .as_deref()
            .is_some_and(|u| u.starts_with(&prewarm_prefix))),
        "both responses must be served from the pre-warm dir, got {:?}",
        entries
            .iter()
            .map(|e| e.upstream_url.clone())
            .collect::<Vec<_>>(),
    );
}

#[tokio::test]
async fn a_hash_absent_from_the_first_dir_is_served_and_nar_routed_from_the_second() {
    // The pre-warm dir does not hold this hash; the flake-input dir holds a CA
    // entry for it. Serving must fall through to the second dir for the narinfo
    // AND fetch its NAR from that same (second) dir — the dir-routing invariant.
    // A routing bug that read the NAR from the first dir would 502 (missing).
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let prewarm = tempfile::tempdir().unwrap(); // present but lacks this hash
    let flake_input = tempfile::tempdir().unwrap();
    let nar_file = "input.nar.xz";
    let (hash, narinfo_bytes, compressed) =
        write_local_ca_entry(flake_input.path(), "source", nar_file, b"a flake input nar");
    let service = nix_cache_service_with_local_cache_dirs_and_trusted_keys(
        &state,
        DEAD_UPSTREAM,
        vec![
            prewarm.path().to_path_buf(),
            flake_input.path().to_path_buf(),
        ],
        NixTrustedPublicKeys::empty(), // CA needs no key
        4096,
        4096,
    );

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
    assert_eq!(nar_response.body, compressed);
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    let flake_prefix = format!("file://{}", flake_input.path().display());
    assert!(
        entries[1]
            .upstream_url
            .as_deref()
            .is_some_and(|u| u.starts_with(&flake_prefix)),
        "the NAR must be served from the second (flake-input) dir, got {:?}",
        entries[1].upstream_url,
    );
}

#[tokio::test]
async fn cache_info_synthesised_when_only_the_prewarm_dir_is_nonempty() {
    // `nix-cache-info` is synthesised (not proxied) when *any* local dir has a
    // servable narinfo — here only the pre-warm dir does.
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let prewarm = tempfile::tempdir().unwrap();
    let flake_input = tempfile::tempdir().unwrap(); // empty
    let key_pair = test_ed25519_key_pair();
    write_local_signed_entry(
        prewarm.path(),
        &key_pair,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "writ-prewarm-closure",
        "prewarm-closure.nar.xz",
        b"a compiled devShell output",
    );
    let trusted = NixTrustedPublicKeys::from_strings([trusted_public_key_for_test(
        TEST_SIGNING_KEY_NAME,
        &key_pair,
    )])
    .unwrap();
    let service = nix_cache_service_with_local_cache_dirs_and_trusted_keys(
        &state,
        DEAD_UPSTREAM,
        vec![
            prewarm.path().to_path_buf(),
            flake_input.path().to_path_buf(),
        ],
        trusted,
        4096,
        4096,
    );

    let response =
        route_nix_cache_with_service(&session, "GET", VM_NIX_CACHE_INFO_PATH.into(), service).await;

    assert_eq!(response.status, VmHttpStatus::Ok);
    assert!(
        String::from_utf8(response.body)
            .unwrap()
            .contains("StoreDir: /nix/store")
    );
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(
        entries[0].upstream_url, None,
        "cache-info must be synthesised, not proxied",
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
async fn local_nar_body_is_served_verbatim_trusting_the_mount() {
    // The broker serves its own read-only, broker-provisioned local archive
    // verbatim: it does NOT decompress and re-hash the NAR against the admitted
    // narinfo on every serve. The narinfo is admitted only when self-certifying
    // (as here, a content-addressed flake input) or trusted-signed, and the
    // guest re-verifies each NAR against it before it enters the store — so an
    // on-disk NAR that no longer matches its narinfo is the guest's to reject,
    // not something the broker spends a full xz-decode + SHA-256 catching on
    // every substitution.
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let nar_file = "input.nar.xz";
    let (hash, _, _) =
        write_local_ca_entry(cache.path(), "source", nar_file, b"trusted local body");
    // Overwrite the on-disk NAR with a different (valid xz) body whose hash and
    // size no longer match the admitted narinfo. The broker still serves it
    // verbatim — verification is the guest's job.
    let tampered = xz_nar_body_for(b"tampered body of different length");
    std::fs::write(cache.path().join("nar").join(nar_file), &tampered).unwrap();
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
    assert_eq!(nar.status, VmHttpStatus::Ok);
    assert_eq!(nar.content_type, "application/x-nix-nar");
    assert_eq!(nar.content_length, Some(tampered.len() as u64));
    assert_eq!(nar.body, tampered);
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].route, NixCacheAuditRoute::Nar);
    assert_eq!(entries[1].http_status, Some(200));
    assert_eq!(entries[1].upstream_status, None);
    assert_eq!(entries[1].error, None);
    assert_eq!(entries[1].response_bytes, Some(tampered.len() as u64));
}

/// The cache serve path coalesces its audit request+outcome into one commit
/// *after* the fetch, but a closed (or unknown) audit session must still be
/// refused *before* the broker does any cache I/O on its behalf — otherwise a
/// session whose authority window has closed could still drive an upstream
/// fetch that leaves no audit trail. A local miss on the proxied view would
/// normally fall through to the upstream, so any upstream contact fails here.
#[tokio::test]
async fn closed_session_is_refused_before_any_upstream_fetch() {
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    state
        .audit
        .close_session(session.session_id(), crate::core::UnixMillis::now())
        .unwrap();
    let cache = tempfile::tempdir().unwrap();
    let hash = "rzv95bakh41zrn5ji23pfc11x5vq2z4d";
    Mock::given(method("GET"))
        .and(path(format!("/{hash}.narinfo")))
        .respond_with(ResponseTemplate::new(200).set_body_string("unused"))
        .expect(0)
        .mount(&upstream)
        .await;
    let service =
        nix_cache_service_with_local_cache(&state, &upstream.uri(), cache.path(), 1024, 1024);

    let response = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_CACHE_PATH_PREFIX}/{hash}.narinfo"),
        service,
    )
    .await;

    assert_eq!(response.status, VmHttpStatus::InternalServerError);
    // `expect(0)`: the upstream must not have been contacted.
    upstream.verify().await;
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert!(
        entries.is_empty(),
        "closed session must write no audit rows"
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
        .with_local_cache_dirs(vec![cache.path().to_path_buf()]),
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

#[tokio::test]
async fn prewarm_view_serves_a_trusted_signed_closure_path_without_upstream() {
    // The strict warm's substituter: a signed, input-addressed closure path in
    // the pre-warm dir is served (narinfo + NAR) through `/v1/nix/prewarm`
    // against a dead upstream, proving the view needs no proxy.
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let prewarm = tempfile::tempdir().unwrap();
    let key_pair = test_ed25519_key_pair();
    let store_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let nar_file = "prewarm-closure.nar.xz";
    let (narinfo_bytes, compressed) = write_local_signed_entry(
        prewarm.path(),
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
        prewarm.path(),
        trusted,
        4096,
        4096,
    );

    let narinfo_response = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_PREWARM_PATH_PREFIX}/{store_hash}.narinfo"),
        service.clone(),
    )
    .await;
    let nar_response = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_PREWARM_PATH_PREFIX}/nar/{nar_file}"),
        service,
    )
    .await;

    assert_eq!(narinfo_response.status, VmHttpStatus::Ok);
    assert_eq!(narinfo_response.body, narinfo_bytes);
    assert_eq!(nar_response.status, VmHttpStatus::Ok);
    assert_eq!(nar_response.content_type, "application/x-nix-nar");
    assert_eq!(nar_response.body, compressed);
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries.iter().all(|e| e
            .upstream_url
            .as_deref()
            .is_some_and(|url| url.starts_with("file://"))),
        "both responses must come from the local archive: {:?}",
        entries
            .iter()
            .map(|e| e.upstream_url.clone())
            .collect::<Vec<_>>(),
    );
}

#[tokio::test]
async fn prewarm_view_serves_the_flake_input_dir_too() {
    // The strict warm still needs the FK CA input archive (eval inputs); the
    // pre-warm view serves the whole ordered dir list, with the NAR routed from
    // the dir that admitted it (here the second, flake-input dir).
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let prewarm = tempfile::tempdir().unwrap(); // present but lacks this hash
    let flake_input = tempfile::tempdir().unwrap();
    let nar_file = "input.nar.xz";
    let (hash, narinfo_bytes, compressed) =
        write_local_ca_entry(flake_input.path(), "source", nar_file, b"a flake input nar");
    let service = nix_cache_service_with_local_cache_dirs_and_trusted_keys(
        &state,
        DEAD_UPSTREAM,
        vec![
            prewarm.path().to_path_buf(),
            flake_input.path().to_path_buf(),
        ],
        NixTrustedPublicKeys::empty(),
        4096,
        4096,
    );

    let narinfo_response = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_PREWARM_PATH_PREFIX}/{hash}.narinfo"),
        service.clone(),
    )
    .await;
    let nar_response = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_PREWARM_PATH_PREFIX}/nar/{nar_file}"),
        service,
    )
    .await;

    assert_eq!(narinfo_response.status, VmHttpStatus::Ok);
    assert_eq!(narinfo_response.body, narinfo_bytes);
    assert_eq!(nar_response.status, VmHttpStatus::Ok);
    assert_eq!(nar_response.body, compressed);
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    let flake_prefix = format!("file://{}", flake_input.path().display());
    assert!(
        entries[1]
            .upstream_url
            .as_deref()
            .is_some_and(|u| u.starts_with(&flake_prefix)),
        "the NAR must be served from the flake-input dir, got {:?}",
        entries[1].upstream_url,
    );
}

#[tokio::test]
async fn prewarm_view_narinfo_miss_is_a_404_not_an_upstream_proxy() {
    // The strict guarantee: a hash absent from every local dir 404s on the
    // pre-warm view even though a live upstream *would* serve it (the same
    // request through `/v1/nix/cache` proxies). `expect(0)` proves the pre-warm
    // view never contacted the upstream.
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap(); // empty: every hash is a local miss
    let hash = "rzv95bakh41zrn5ji23pfc11x5vq2z4d";
    Mock::given(method("GET"))
        .and(path(format!("/{hash}.narinfo")))
        .respond_with(ResponseTemplate::new(200).set_body_string(TEST_SIGNED_NARINFO))
        .expect(0)
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
        .with_local_cache_dirs(vec![cache.path().to_path_buf()]),
    );

    let response = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_PREWARM_PATH_PREFIX}/{hash}.narinfo"),
        service,
    )
    .await;

    assert_eq!(response.status, VmHttpStatus::NotFound);
    upstream.verify().await;
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].route, NixCacheAuditRoute::NarInfo);
    assert_eq!(entries[0].http_status, Some(404));
    assert_eq!(entries[0].upstream_url, None);
    assert_eq!(entries[0].upstream_status, None);
    assert_eq!(entries[0].error, None);
}

#[tokio::test]
async fn prewarm_view_cache_info_is_synthetic_even_when_archives_are_empty() {
    // Unlike the proxied view (which proxies cache-info while the archive is
    // empty), the pre-warm view always synthesises it: an empty cache is a
    // valid cache that misses every narinfo, and Nix rejects a substituter
    // whose cache-info errors.
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap(); // empty
    Mock::given(method("GET"))
        .and(path("/nix-cache-info"))
        .respond_with(ResponseTemplate::new(200).set_body_string("StoreDir: /nix/store\n"))
        .expect(0)
        .mount(&upstream)
        .await;
    let service =
        nix_cache_service_with_local_cache(&state, &upstream.uri(), cache.path(), 1024, 1024);

    let response = route_nix_cache_with_service(
        &session,
        "GET",
        VM_NIX_PREWARM_CACHE_INFO_PATH.into(),
        service,
    )
    .await;

    assert_eq!(response.status, VmHttpStatus::Ok);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains("StoreDir: /nix/store"), "{body}");
    upstream.verify().await;
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].route, NixCacheAuditRoute::CacheInfo);
    assert_eq!(entries[0].upstream_url, None);
}

#[tokio::test]
async fn prewarm_view_narinfo_present_but_inadmissible_fails_closed_not_404() {
    // The 404-on-miss contract is for *absent* hashes only: a present but
    // inadmissible narinfo (signed by an untrusted key) is authoritative for
    // its dir and fails closed with a 502, exactly as on the proxied view — it
    // must not be soft-missed into "never warmed".
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
        NixTrustedPublicKeys::empty(), // the signing key is not trusted
        4096,
        4096,
    );

    let response = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_PREWARM_PATH_PREFIX}/{store_hash}.narinfo"),
        service,
    )
    .await;

    assert_eq!(response.status, VmHttpStatus::BadGateway);
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(
        entries[0].error.as_deref(),
        Some("local narinfo neither self-certifying nor trusted-signed"),
    );
}

#[tokio::test]
async fn prewarm_view_refuses_an_upstream_admitted_nar() {
    // A narinfo admitted from the upstream through the proxied view pins its
    // NAR to the upstream; asking the pre-warm view for that NAR must fail
    // closed rather than proxy. `expect(0)` on the NAR endpoint proves it.
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
    Mock::given(method("GET"))
        .and(path(format!("/nar/{TEST_NAR_FILE}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(test_xz_nar_body()))
        .expect(0)
        .mount(&upstream)
        .await;
    let service = signed_nix_cache_service_for_test(&state, &upstream, 1024);

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
        format!("{VM_NIX_PREWARM_PATH_PREFIX}/nar/{TEST_NAR_FILE}"),
        service,
    )
    .await;

    assert_eq!(narinfo.status, VmHttpStatus::Ok);
    assert_eq!(nar.status, VmHttpStatus::BadGateway);
    upstream.verify().await;
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].route, NixCacheAuditRoute::Nar);
    assert_eq!(entries[1].http_status, Some(502));
    assert_eq!(
        entries[1].error.as_deref(),
        Some("upstream-admitted nar refused on pre-warm route"),
    );
}

#[tokio::test]
async fn nar_admitted_via_prewarm_view_is_served_locally_through_the_cache_view() {
    // Source pinning holds across views: a narinfo admitted from the local
    // archive via the pre-warm view serves its NAR from that same dir even
    // when the NAR is requested through the proxied `/v1/nix/cache` view.
    let upstream = MockServer::start().await;
    let state = make_broker_state(&upstream);
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
    open_audit_session(&state, session.session_id());
    let cache = tempfile::tempdir().unwrap();
    let nar_file = "input.nar.xz";
    let (hash, _, compressed) =
        write_local_ca_entry(cache.path(), "source", nar_file, b"cross-view pinning");
    let service =
        nix_cache_service_with_local_cache(&state, DEAD_UPSTREAM, cache.path(), 4096, 4096);

    let narinfo = route_nix_cache_with_service(
        &session,
        "GET",
        format!("{VM_NIX_PREWARM_PATH_PREFIX}/{hash}.narinfo"),
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
    assert_eq!(nar.status, VmHttpStatus::Ok);
    assert_eq!(nar.body, compressed);
    let entries = state
        .audit
        .list_nix_cache_requests_for_session(session.session_id())
        .unwrap();
    assert!(
        entries[1]
            .upstream_url
            .as_deref()
            .is_some_and(|url| url.starts_with("file://")),
        "the NAR must be served from the pinned local dir, got {:?}",
        entries[1].upstream_url,
    );
}
