//! Example/edge-case tests for NAR length validation and xz/zstd verification:
//! a missing/oversized declared length, a decoded body shorter than the signed
//! size, legitimately concatenated streams, and a zstd frame whose advertised
//! window exceeds the decoder's ceiling. The all-inputs round-trip spec lives
//! inline in `nar_verify.rs`.

use super::nar_verify::{
    VmHttpNixCacheNarLengthError, VmHttpNixCacheNarVerifyError, ZSTD_DECODER_WINDOW_LOG_MAX,
    verify_nar_body,
};
use super::test_support::*;
use super::*;
use crate::nix_cache::NixNarCompression;

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

#[test]
fn zstd_nar_body_round_trips_against_admitted_metadata() {
    let raw_body = test_raw_nar_body();
    let admission = admitted_nar_for_body(TEST_NAR_FILE, NixNarCompression::Zstd, &raw_body);

    verify_nar_body(&admission, &zstd_nar_body_for(&raw_body), 1024).unwrap();
}

#[test]
fn zstd_nar_body_accepts_concatenated_frames() {
    let raw_body = test_raw_nar_body();
    let admission = admitted_nar_for_body(TEST_NAR_FILE, NixNarCompression::Zstd, &raw_body);

    verify_nar_body(&admission, &multi_stream_zstd_body_for(&raw_body), 1024).unwrap();
}

#[test]
fn zstd_nar_body_rejects_decoded_size_smaller_than_signed_size() {
    let raw_body = test_raw_nar_body();
    let short_body = &raw_body[..raw_body.len() - 1];
    let admission = admitted_nar_for_body(TEST_NAR_FILE, NixNarCompression::Zstd, &raw_body);

    let result = verify_nar_body(&admission, &zstd_nar_body_for(short_body), 1024);

    assert_eq!(
        result,
        Err(VmHttpNixCacheNarVerifyError::SizeMismatch {
            expected: raw_body.len() as u64,
            actual: short_body.len() as u64,
        })
    );
}

#[test]
fn zstd_nar_body_rejects_corrupt_frame() {
    let raw_body = test_raw_nar_body();
    let mut wire = zstd_nar_body_for(&raw_body);
    // Flip a byte inside the compressed payload (past the frame header) so the
    // frame no longer decodes to anything valid.
    let corrupt_index = wire.len() - 2;
    wire[corrupt_index] ^= 0xff;
    let admission = admitted_nar_for_body(TEST_NAR_FILE, NixNarCompression::Zstd, &raw_body);

    let result = verify_nar_body(&admission, &wire, 1024);

    assert!(
        matches!(result, Err(VmHttpNixCacheNarVerifyError::Decode { .. })),
        "corrupt zstd frame should fail to decode, got {result:?}",
    );
}

#[test]
fn zstd_nar_body_rejects_window_larger_than_decoder_ceiling() {
    // A tiny payload wrapped in a frame advertising a window one bit above the
    // decoder ceiling: it must be refused (never allocated) at decode time,
    // even though the payload itself is trivially small.
    let raw_body = b"small-but-hostile-window".to_vec();
    let hostile = zstd_nar_body_with_window_log(&raw_body, ZSTD_DECODER_WINDOW_LOG_MAX + 1);
    let admission = admitted_nar_for_body(TEST_NAR_FILE, NixNarCompression::Zstd, &raw_body);

    let result = verify_nar_body(&admission, &hostile, 1024);

    assert!(
        matches!(result, Err(VmHttpNixCacheNarVerifyError::Decode { .. })),
        "oversized-window zstd frame should be refused, got {result:?}",
    );
}

#[test]
fn zstd_nar_body_accepts_the_window_cache_nixos_org_advertises() {
    // cache.nixos.org's zstd NARs advertise windowLog 21 irrespective of NAR
    // size; a body that big must decode even when `max_nar_bytes` is smaller
    // than the advertised window, so the ceiling cannot track `max_nar_bytes`.
    const CACHE_WINDOW_LOG: u32 = 21;
    const _: () = assert!(CACHE_WINDOW_LOG <= ZSTD_DECODER_WINDOW_LOG_MAX);
    let raw_body = test_raw_nar_body();
    let wire = zstd_nar_body_with_window_log(&raw_body, CACHE_WINDOW_LOG);
    let admission = admitted_nar_for_body(TEST_NAR_FILE, NixNarCompression::Zstd, &raw_body);

    verify_nar_body(&admission, &wire, 1024).unwrap();
}
