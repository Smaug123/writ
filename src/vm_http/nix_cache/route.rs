//! Pure classification of the VM-facing binary-cache request targets, the
//! protocol path constants, and the upstream-less responder used when no
//! upstream proxy is configured. Everything here is a pure function of the
//! request: no IO, no service state.

use crate::nix_cache::{NixCacheNarFileName, NixStoreHashPart};

use super::super::{VmHttpRequest, VmHttpResponse, VmHttpStatus};

pub const VM_NIX_CACHE_PATH_PREFIX: &str = "/v1/nix/cache";
pub(super) const VM_NIX_CACHE_INFO_PATH: &str = "/v1/nix/cache/nix-cache-info";
pub const VM_NIX_BASIC_LOGIN: &str = "writ-vm";
/// The `nix-cache-info` body the broker advertises for the `/v1/nix/cache`
/// endpoint. `StoreDir` is the load-bearing field — it matches the upstream
/// (`/nix/store`) so the guest accepts the substituter — and it is served
/// synthetically (no upstream round-trip) whenever the endpoint can answer
/// locally.
pub(super) const VM_NIX_CACHE_INFO_BODY: &str =
    "StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 40\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::vm_http) enum VmNixCacheRoute {
    CacheInfo,
    NarInfo { hash: NixStoreHashPart },
    Nar { file: NixCacheNarFileName },
}

pub(in crate::vm_http) fn is_nix_cache_target(target: &str) -> bool {
    target == VM_NIX_CACHE_PATH_PREFIX
        || target == VM_NIX_CACHE_INFO_PATH
        || target
            .strip_prefix(VM_NIX_CACHE_PATH_PREFIX)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub(super) fn classify_nix_cache_target(target: &str) -> Option<VmNixCacheRoute> {
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

pub(in crate::vm_http) fn route_nix_cache_request_without_upstream(
    request: &VmHttpRequest,
) -> VmHttpResponse {
    let Some(route) = classify_nix_cache_target(&request.target) else {
        return VmHttpResponse::text(VmHttpStatus::NotFound, "not found");
    };
    match (request.method.as_str(), route) {
        ("GET", VmNixCacheRoute::CacheInfo) => {
            VmHttpResponse::text(VmHttpStatus::Ok, VM_NIX_CACHE_INFO_BODY)
        }
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

/// Property-based spec for [`classify_nix_cache_target`]: arbitrary valid
/// store-hash narinfo paths and NAR filenames classify to the matching route,
/// and arbitrary malformed ones (wrong-length hashes, illegal NAR-name bytes)
/// classify to nothing. Example/edge-case path rejections live in
/// `route_tests.rs`.
#[cfg(test)]
mod spec {
    use super::*;
    use proptest::prelude::*;

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
    }
}
