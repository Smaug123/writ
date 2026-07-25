//! Shared fixtures for the `nix_cache` test modules.
//!
//! Hoisted here so the per-concern `*_tests` modules and the inline `spec`
//! modules in `route`/`nar_verify` reuse one set of service constructors, NAR
//! and narinfo builders, and signing-key helpers instead of each re-defining
//! them. `super::*` re-exports the production items (and the `crate::nix_binary_cache`
//! parsers the parent pulls in privately); the explicit `use`s below cover the
//! `vm_http` test harness and the extra `crate::nix_binary_cache` value types these
//! helpers construct.

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use base64::Engine as _;
use ring::signature::KeyPair as _;
use wiremock::MockServer;

use super::super::tests::{basic, token};
use super::super::{VmHttpServices, resolve_and_route_authenticated_vm_http_request};
use super::*;
use crate::nix_binary_cache::{NixNarCompression, NixNarHash, NixNarSize, NixTrustedPublicKeys};

pub(super) const VM_NIX_CACHE_INFO_PATH: &str = "/v1/nix/cache/nix-cache-info";
pub(super) const VM_NIX_PREWARM_CACHE_INFO_PATH: &str = "/v1/nix/prewarm/nix-cache-info";
pub(super) const TEST_NIX_CACHE_PUBLIC_KEY: &str =
    "cache.example:IsGkyTbr2sed7tWowgiPcI0ZHhBAHoGQ7TyYRweyzwE=";
pub(super) const TEST_SIGNED_NARINFO: &str = concat!(
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
pub(super) const TEST_NAR_FILE: &str =
    "05cwbm7srkm5hvm6s7pa8yw2n57vgfrfmsz3p2sy8h9cnki9415f.nar.xz";
pub(super) const TEST_RAW_NAR_BASE64: &str = concat!(
    "DQAAAAAAAABuaXgtYXJjaGl2ZS0xAAAAAQAAAAAAAAAoAAAAAAAAAAQAAAAAAAAAdHlwZQAAAAAH",
    "AAAAAAAAAHJlZ3VsYXIACAAAAAAAAABjb250ZW50cwUAAAAAAAAAcHJvb2YAAAABAAAAAAAAACkA",
    "AAAAAAAA",
);
pub(super) const TEST_SIGNING_KEY_NAME: &str = "cache.example";

// A dead upstream: any fallthrough to the proxy fails to connect, so a 200
// proves the response was served entirely from the local archive.
pub(super) const DEAD_UPSTREAM: &str = "http://127.0.0.1:9";

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
        flake_provision: None,
    }
}

pub(super) fn nix_cache_service_for_test(
    state: &Arc<BrokerState<Box<dyn SecretStore>>>,
    server: &MockServer,
    max_metadata_bytes: u64,
) -> VmHttpNixCacheService<Box<dyn SecretStore>> {
    nix_cache_service_for_test_with_limits(state, server, max_metadata_bytes, 1024)
}

pub(super) fn nix_cache_service_for_test_with_limits(
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

pub(super) fn signed_nix_cache_service_for_test(
    state: &Arc<BrokerState<Box<dyn SecretStore>>>,
    server: &MockServer,
    max_metadata_bytes: u64,
) -> VmHttpNixCacheService<Box<dyn SecretStore>> {
    signed_nix_cache_service_for_test_with_limits(state, server, max_metadata_bytes, 1024)
}

pub(super) fn signed_nix_cache_service_for_test_with_limits(
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

pub(super) fn signed_nix_cache_service_for_test_with_key(
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

pub(super) fn nix_cache_service_with_local_cache(
    state: &Arc<BrokerState<Box<dyn SecretStore>>>,
    upstream_url: &str,
    cache_dir: &std::path::Path,
    max_metadata_bytes: u64,
    max_nar_bytes: u64,
) -> VmHttpNixCacheService<Box<dyn SecretStore>> {
    VmHttpNixCacheService::new(
        Arc::clone(state),
        VmHttpNixCacheConfig::new(upstream_url, max_metadata_bytes, max_nar_bytes)
            .unwrap()
            .with_local_cache_dirs(vec![cache_dir.to_path_buf()]),
    )
}

/// A local-archive service that also trusts `trusted_keys`, so the local path
/// can admit a *signed* input-addressed narinfo (a pre-warmed devShell-closure
/// path), not only a self-certifying content-addressed one.
pub(super) fn nix_cache_service_with_local_cache_and_trusted_keys(
    state: &Arc<BrokerState<Box<dyn SecretStore>>>,
    upstream_url: &str,
    cache_dir: &std::path::Path,
    trusted_keys: NixTrustedPublicKeys,
    max_metadata_bytes: u64,
    max_nar_bytes: u64,
) -> VmHttpNixCacheService<Box<dyn SecretStore>> {
    nix_cache_service_with_local_cache_dirs_and_trusted_keys(
        state,
        upstream_url,
        vec![cache_dir.to_path_buf()],
        trusted_keys,
        max_metadata_bytes,
        max_nar_bytes,
    )
}

/// A service serving an ordered list of local archives (pre-warm dir first,
/// then flake-input dir) that also trusts `trusted_keys`. The vehicle for the
/// PW2 multi-dir, local-first serving and per-dir NAR routing.
pub(super) fn nix_cache_service_with_local_cache_dirs_and_trusted_keys(
    state: &Arc<BrokerState<Box<dyn SecretStore>>>,
    upstream_url: &str,
    cache_dirs: Vec<std::path::PathBuf>,
    trusted_keys: NixTrustedPublicKeys,
    max_metadata_bytes: u64,
    max_nar_bytes: u64,
) -> VmHttpNixCacheService<Box<dyn SecretStore>> {
    VmHttpNixCacheService::new(
        Arc::clone(state),
        VmHttpNixCacheConfig::new_with_trusted_public_keys(
            upstream_url,
            max_metadata_bytes,
            max_nar_bytes,
            trusted_keys,
        )
        .unwrap()
        .with_local_cache_dirs(cache_dirs),
    )
}

pub(super) fn test_ed25519_key_pair() -> ring::signature::Ed25519KeyPair {
    ring::signature::Ed25519KeyPair::from_seed_unchecked(&[7_u8; 32]).unwrap()
}

pub(super) fn trusted_public_key_for_test(
    name: &str,
    key_pair: &ring::signature::Ed25519KeyPair,
) -> String {
    format!(
        "{name}:{}",
        base64::engine::general_purpose::STANDARD.encode(key_pair.public_key().as_ref())
    )
}

pub(super) fn nar_hash_for_body(body: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, body);
    let digest: [u8; 32] = digest
        .as_ref()
        .try_into()
        .expect("ring SHA-256 digest length should be 32 bytes");
    format!(
        "sha256:{}",
        crate::nix_binary_cache::nix_base32_encode_sha256_digest(&digest)
    )
}

pub(super) fn signed_test_narinfo(
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

pub(super) fn test_raw_nar_body() -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(TEST_RAW_NAR_BASE64)
        .unwrap()
}

pub(super) fn test_xz_nar_body() -> Vec<u8> {
    xz_nar_body_for(&test_raw_nar_body())
}

pub(super) fn xz_nar_body_for(raw: &[u8]) -> Vec<u8> {
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(raw).unwrap();
    encoder.finish().unwrap()
}

pub(super) fn multi_stream_xz_body_for(raw: &[u8]) -> Vec<u8> {
    let split = raw.len() / 2;
    let mut body = xz_nar_body_for(&raw[..split]);
    body.extend_from_slice(&xz_nar_body_for(&raw[split..]));
    body
}

pub(super) fn test_zstd_nar_body() -> Vec<u8> {
    zstd_nar_body_for(&test_raw_nar_body())
}

pub(super) fn zstd_nar_body_for(raw: &[u8]) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
    encoder.write_all(raw).unwrap();
    encoder.finish().unwrap()
}

/// A single zstd frame that advertises `window_log` in its header regardless of
/// how small the payload is, for exercising the decoder's window-size ceiling.
pub(super) fn zstd_nar_body_with_window_log(raw: &[u8], window_log: u32) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
    encoder.window_log(window_log).unwrap();
    encoder.write_all(raw).unwrap();
    encoder.finish().unwrap()
}

pub(super) fn multi_stream_zstd_body_for(raw: &[u8]) -> Vec<u8> {
    let split = raw.len() / 2;
    let mut body = zstd_nar_body_for(&raw[..split]);
    body.extend_from_slice(&zstd_nar_body_for(&raw[split..]));
    body
}

pub(super) fn admitted_nar_for_body(
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

pub(super) fn test_signed_narinfo() -> NixNarInfo {
    let expected_hash = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
    let keys = NixTrustedPublicKeys::from_strings([TEST_NIX_CACHE_PUBLIC_KEY]).unwrap();
    parse_signed_narinfo_for_store_hash(TEST_SIGNED_NARINFO.as_bytes(), &expected_hash, &keys)
        .unwrap()
}

pub(super) fn admit_test_nar(service: &VmHttpNixCacheService<Box<dyn SecretStore>>) {
    service
        .admit_narinfo(&test_signed_narinfo(), VmNixCacheNarSource::Upstream)
        .unwrap();
}

pub(super) fn nix_cache_request(
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

pub(super) async fn route_nix_cache_with_service(
    session: &VmHttpSession,
    method: &str,
    target: String,
    service: VmHttpNixCacheService<Box<dyn SecretStore>>,
) -> VmHttpResponse {
    let request = nix_cache_request(
        method,
        target,
        Ipv4Addr::LOCALHOST,
        Some(basic(token().as_str())),
    );
    resolve_and_route_authenticated_vm_http_request(
        session,
        &request,
        Vec::new(),
        services_with_nix_cache(service),
    )
    .await
    .into_buffered()
}

/// Write a pre-warm-style local entry: a *signed*, **input-addressed** narinfo
/// (no `CA` field at all — exactly what a compiled devShell-closure path is,
/// unlike a self-certifying flake input) signed by `key_pair` under
/// [`TEST_SIGNING_KEY_NAME`], plus the xz-compressed NAR at `nar/<file>`. The
/// store hash is the caller's (input-addressed paths are not content-derived).
/// Returns the narinfo and compressed-NAR bytes the served responses must
/// match. Trust the key with `trusted_public_key_for_test(TEST_SIGNING_KEY_NAME,
/// key_pair)`.
pub(super) fn write_local_signed_entry(
    cache_dir: &std::path::Path,
    key_pair: &ring::signature::Ed25519KeyPair,
    store_hash: &str,
    store_name: &str,
    nar_file: &str,
    raw_body: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let compressed = xz_nar_body_for(raw_body);
    let nar_hash = nar_hash_for_body(raw_body);
    let narinfo = signed_test_narinfo(
        key_pair,
        store_hash,
        store_name,
        nar_file,
        NixNarCompression::Xz,
        &nar_hash,
        raw_body.len() as u64,
    );
    std::fs::create_dir_all(cache_dir.join("nar")).unwrap();
    std::fs::write(
        cache_dir.join(format!("{store_hash}.narinfo")),
        narinfo.as_bytes(),
    )
    .unwrap();
    std::fs::write(cache_dir.join("nar").join(nar_file), &compressed).unwrap();
    (narinfo.into_bytes(), compressed)
}

/// Write a `nix flake archive`-style local entry: an unsigned narinfo whose
/// `CA: fixed:r:sha256:<digest>` self-certifies against its NarHash and whose
/// StorePath is the Nix fixed-output path derived from that content (so it
/// passes the broker's full self-certification), plus the xz-compressed NAR
/// at `nar/<file>`. Returns the derived store hash and the narinfo and
/// compressed-NAR bytes the served responses must match.
pub(super) fn write_local_ca_entry(
    cache_dir: &std::path::Path,
    store_name: &str,
    nar_file: &str,
    raw_body: &[u8],
) -> (String, Vec<u8>, Vec<u8>) {
    let compressed = xz_nar_body_for(raw_body);
    let nar_hash = nar_hash_for_body(raw_body);
    let nar_digest = nar_hash
        .strip_prefix("sha256:")
        .expect("nar_hash_for_body returns a sha256 hash");
    let store_hash =
        crate::nix_binary_cache::fixed_output_recursive_sha256_store_hash(nar_digest, store_name)
            .expect("a valid sha256 digest derives a store hash");
    let narinfo = format!(
        "StorePath: /nix/store/{store_hash}-{store_name}\nURL: nar/{nar_file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: {}\nReferences: \nCA: fixed:r:sha256:{nar_digest}\n",
        raw_body.len(),
    );
    std::fs::create_dir_all(cache_dir.join("nar")).unwrap();
    std::fs::write(
        cache_dir.join(format!("{store_hash}.narinfo")),
        narinfo.as_bytes(),
    )
    .unwrap();
    std::fs::write(cache_dir.join("nar").join(nar_file), &compressed).unwrap();
    (store_hash, narinfo.into_bytes(), compressed)
}
