//! Example/edge-case tests for NAR length validation and xz verification: a
//! missing/oversized declared length, a decoded body shorter than the signed
//! size, and a legitimately concatenated xz stream. The all-inputs round-trip
//! spec lives inline in `nar_verify.rs`.

use super::nar_verify::{
    VmHttpNixCacheNarLengthError, VmHttpNixCacheNarVerifyError, verify_nar_body,
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
