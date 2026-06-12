//! Example/edge-case tests for the upstream-proxy path: metadata and narinfo
//! forwarding, NAR buffering + verification, the admission rejections (size,
//! conflict, unverifiable hash, unsafe/duplicate URL, store-path mismatch,
//! untrusted signature), and the audited failure/denial responses. These drive
//! a `wiremock` upstream end-to-end through the authenticated dispatcher.

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::tests::{make_broker_state, open_audit_session, session_for_subnet};
use super::super::{VM_HTTP_READ_TIMEOUT, dispatch_vm_http_head_and_body};
use super::test_support::*;
use super::*;
use crate::core::Ipv4Cidr;
use crate::nix_cache::NixNarCompression;

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
        route_nix_cache_with_service(&session, "GET", VM_NIX_CACHE_INFO_PATH.into(), service).await;

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
    let service = signed_nix_cache_service_for_test_with_key(&state, &upstream, trusted_key, 64);

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
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
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
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
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
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
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
    let service = signed_nix_cache_service_for_test_with_key(&state, &upstream, trusted_key, 64);

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
        route_nix_cache_with_service(&session, "GET", VM_NIX_CACHE_INFO_PATH.into(), service).await;

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
        route_nix_cache_with_service(&session, "GET", VM_NIX_CACHE_INFO_PATH.into(), service).await;

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
