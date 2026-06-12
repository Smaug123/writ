//! Example/edge-case tests for the Nix-cache request surface that needs no
//! upstream: Basic-auth gating and challenge, the synthetic `nix-cache-info`
//! and controlled-miss responses, the path classifier's rejection table, and
//! the no-body guarantee. The arbitrary-input classification spec lives inline
//! in `route.rs`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use super::super::tests::{basic, bearer, no_services, session_for_subnet, token};
use super::super::{
    VM_HTTP_READ_TIMEOUT, VmHttpAuthError, VmHttpAuthorization, authorize_vm_http_request,
    dispatch_vm_http_head, dispatch_vm_http_head_and_body,
};
use super::test_support::*;
use super::*;
use crate::core::Ipv4Cidr;

#[test]
fn nix_cache_routes_accept_basic_auth_only() {
    let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
    let source = Ipv4Addr::new(10, 1, 2, 42);

    assert_eq!(
        authorize_vm_http_request(
            &session,
            &nix_cache_request(
                "GET",
                VM_NIX_CACHE_INFO_PATH,
                source,
                Some(basic(token().as_str()))
            ),
        ),
        VmHttpAuthorization::Allow
    );
    assert_eq!(
        authorize_vm_http_request(
            &session,
            &nix_cache_request(
                "GET",
                VM_NIX_CACHE_INFO_PATH,
                source,
                Some(bearer(token().as_str()))
            ),
        ),
        VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
    );
    assert_eq!(
        authorize_vm_http_request(
            &session,
            &nix_cache_request("GET", VM_NIX_CACHE_INFO_PATH, source, Some(basic("wrong"))),
        ),
        VmHttpAuthorization::Deny(VmHttpAuthError::WrongCredentials)
    );
}

#[test]
fn nix_cache_auth_challenge_is_basic() {
    // Both serving views are nix-cache targets, so both take the Basic
    // challenge (the guest's netrc is keyed by host and covers either path).
    for target in [VM_NIX_CACHE_INFO_PATH, VM_NIX_PREWARM_CACHE_INFO_PATH] {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            "GET",
            target,
            None,
        );

        assert_eq!(response.status, VmHttpStatus::Unauthorized, "{target}");
        let challenge = response
            .www_authenticate
            .expect("nix cache must issue a Basic challenge");
        assert!(
            challenge.starts_with("Basic realm=\"writ-nix-cache\""),
            "{challenge}"
        );
        assert!(!challenge.contains("Bearer"), "{challenge}");
    }
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
    for prefix in [VM_NIX_CACHE_PATH_PREFIX, VM_NIX_PREWARM_PATH_PREFIX] {
        let session = session_for_subnet(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());
        let target = format!("{prefix}/00000000000000000000000000000000.narinfo");
        let basic_auth = basic(token().as_str());
        let response = dispatch_vm_http_head(
            &session,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 12345)),
            "GET",
            &target,
            Some(basic_auth.as_str()),
        );

        assert_eq!(response.status, VmHttpStatus::NotFound, "{target}");
    }
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
        VM_NIX_PREWARM_PATH_PREFIX,
        "/v1/nix/prewarm/",
        "/v1/nix/prewarm/not-a-store-hash.narinfo",
        "/v1/nix/prewarmevil/00000000000000000000000000000000.narinfo",
        "/v1/nix/prewarm/nar",
        "/v1/nix/prewarm/nar/",
        "/v1/nix/prewarm/nar/../proof.nar",
        "/v1/nix/prewarm/nar/subdir/proof.nar",
    ] {
        assert_eq!(
            classify_nix_cache_target(target),
            None,
            "accepted {target:?}"
        );
    }
}

#[test]
fn prewarm_view_targets_classify_to_local_only_routes() {
    assert_eq!(
        classify_nix_cache_target(VM_NIX_PREWARM_CACHE_INFO_PATH),
        Some((VmNixCacheView::LocalOnly, VmNixCacheRoute::CacheInfo)),
    );
    assert_eq!(
        classify_nix_cache_target(VM_NIX_CACHE_INFO_PATH),
        Some((VmNixCacheView::Proxied, VmNixCacheRoute::CacheInfo)),
    );
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
            no_services(),
            VM_HTTP_READ_TIMEOUT,
        ),
    )
    .await
    .expect("Nix cache route must not wait for a declared body");

    assert_eq!(response.status, VmHttpStatus::Ok);
}
