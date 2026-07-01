//! Verifying a NAR body against the metadata admitted from its narinfo: the
//! admitted-NAR descriptor, the declared/observed length checks, and the
//! (optionally xz-/zstd-decompressing) hash+size verification that runs on the
//! blocking pool. Pure given its inputs apart from the `spawn_blocking` hop.

use crate::nix_cache::{
    NixCacheNarFileName, NixNarBodyHashError, NixNarCompression, NixNarHash, NixNarInfo, NixNarSize,
};

const XZ_DECODER_MEMLIMIT_OVERHEAD: u64 = 16 * 1024 * 1024;

/// The zstd decode-window ceiling we admit, as a `windowLog` (log2 of the
/// window size in bytes). It cannot be derived from `max_nar_bytes`:
/// cache.nixos.org's zstd NARs come from a streaming compressor that advertises
/// `windowLog = 21` (a 2 MiB window) *regardless* of the NAR's own size, so a
/// size-derived ceiling would reject real content. We instead match libzstd's
/// own default limit (`ZSTD_WINDOWLOG_LIMIT_DEFAULT`), so the broker accepts
/// exactly the frames the guest's Nix would and refuses (rather than allocates)
/// any larger declared window — bounding peak decoder window memory at
/// 2^27 = 128 MiB per decode.
pub(super) const ZSTD_DECODER_WINDOW_LOG_MAX: u32 = 27;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct VmHttpNixCacheAdmittedNar {
    pub(super) file: NixCacheNarFileName,
    pub(super) compression: NixNarCompression,
    pub(super) nar_hash: NixNarHash,
    pub(super) nar_size: NixNarSize,
}

impl VmHttpNixCacheAdmittedNar {
    pub(super) fn from_narinfo(narinfo: &NixNarInfo) -> Self {
        Self {
            file: narinfo.nar_file().clone(),
            compression: narinfo.compression(),
            nar_hash: narinfo.nar_hash().clone(),
            nar_size: narinfo.nar_size(),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum VmHttpNixCacheNarLengthError {
    Missing,
    TooLarge { max: u64, actual: u64 },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum VmHttpNixCacheNarBodyLengthError {
    Mismatch { expected: u64, actual: u64 },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub(super) enum VmHttpNixCacheNarVerifyError {
    #[error("NAR verification task failed: {message}")]
    VerifierTask { message: String },
    #[error("compressed NAR body could not be decoded: {message}")]
    Decode { message: String },
    #[error("decoded NAR size {actual} does not match signed NarSize {expected}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("NAR body hash is invalid: {0}")]
    Hash(#[from] NixNarBodyHashError),
}

pub(super) fn validate_nar_content_length(
    content_length: Option<u64>,
    max: u64,
) -> Result<u64, VmHttpNixCacheNarLengthError> {
    let Some(content_length) = content_length else {
        return Err(VmHttpNixCacheNarLengthError::Missing);
    };
    if content_length > max {
        return Err(VmHttpNixCacheNarLengthError::TooLarge {
            max,
            actual: content_length,
        });
    }
    Ok(content_length)
}

pub(super) fn validate_nar_body_length(
    actual: u64,
    expected: u64,
) -> Result<(), VmHttpNixCacheNarBodyLengthError> {
    if actual == expected {
        Ok(())
    } else {
        Err(VmHttpNixCacheNarBodyLengthError::Mismatch { expected, actual })
    }
}

impl VmHttpNixCacheNarLengthError {
    pub(super) fn audit_error_label(self) -> &'static str {
        match self {
            Self::Missing => "upstream nar content length missing",
            Self::TooLarge { .. } => "upstream nar response too large",
        }
    }
}

impl VmHttpNixCacheNarBodyLengthError {
    pub(super) fn audit_error_label(self) -> &'static str {
        match self {
            Self::Mismatch { .. } => "upstream nar content length mismatch",
        }
    }
}

impl VmHttpNixCacheNarVerifyError {
    pub(super) fn audit_error_label(&self) -> &'static str {
        match self {
            Self::Decode { .. } => "upstream nar decompression failed",
            Self::SizeMismatch { .. } => "mismatched upstream nar size",
            Self::Hash(source) => nar_body_hash_error_label(source),
            Self::VerifierTask { .. } => "nar verification task failed",
        }
    }
}

pub(super) async fn verify_nar_body_on_blocking_thread(
    admission: VmHttpNixCacheAdmittedNar,
    body: Vec<u8>,
    max_nar_bytes: u64,
) -> Result<Vec<u8>, VmHttpNixCacheNarVerifyError> {
    tokio::task::spawn_blocking(move || {
        verify_nar_body(&admission, &body, max_nar_bytes)?;
        Ok(body)
    })
    .await
    .map_err(|err| VmHttpNixCacheNarVerifyError::VerifierTask {
        message: err.to_string(),
    })?
}

pub(super) fn verify_nar_body(
    admission: &VmHttpNixCacheAdmittedNar,
    body: &[u8],
    max_nar_bytes: u64,
) -> Result<(), VmHttpNixCacheNarVerifyError> {
    match admission.compression {
        NixNarCompression::None => verify_raw_nar_body(admission, body),
        NixNarCompression::Xz => {
            // Peak memory is bounded by compressed Content-Length plus signed
            // NarSize plus the explicit decoder-state memlimit below;
            // decompression runs on the blocking pool because xz is
            // synchronous and can be CPU-heavy on hostile input.
            let raw_body = decode_xz_nar_body(body, admission.nar_size.get(), max_nar_bytes)?;
            verify_raw_nar_body(admission, &raw_body)
        }
        NixNarCompression::Zstd => {
            // As for xz: the decoded output is capped at the signed NarSize by
            // the read loop, and the decoder's own window buffer is bounded by
            // an explicit windowLog ceiling (a frame declaring a larger window
            // is rejected, not allocated). See `ZSTD_DECODER_WINDOW_LOG_MAX`.
            let raw_body = decode_zstd_nar_body(body, admission.nar_size.get())?;
            verify_raw_nar_body(admission, &raw_body)
        }
    }
}

fn verify_raw_nar_body(
    admission: &VmHttpNixCacheAdmittedNar,
    raw_body: &[u8],
) -> Result<(), VmHttpNixCacheNarVerifyError> {
    let actual = raw_body.len() as u64;
    let expected = admission.nar_size.get();
    if actual != expected {
        return Err(VmHttpNixCacheNarVerifyError::SizeMismatch { expected, actual });
    }
    admission.nar_hash.verify_sha256_body(raw_body)?;
    Ok(())
}

fn decode_xz_nar_body(
    body: &[u8],
    expected_size: u64,
    max_nar_bytes: u64,
) -> Result<Vec<u8>, VmHttpNixCacheNarVerifyError> {
    let memlimit = xz_decoder_memlimit(max_nar_bytes)?;
    let stream = xz2::stream::Stream::new_stream_decoder(memlimit, xz2::stream::CONCATENATED)
        .map_err(|err| VmHttpNixCacheNarVerifyError::Decode {
            message: err.to_string(),
        })?;
    let decoder = xz2::read::XzDecoder::new_stream(std::io::Cursor::new(body), stream);
    read_decoded_bounded(decoder, expected_size)
}

fn decode_zstd_nar_body(
    body: &[u8],
    expected_size: u64,
) -> Result<Vec<u8>, VmHttpNixCacheNarVerifyError> {
    let mut decoder =
        zstd::stream::read::Decoder::new(std::io::Cursor::new(body)).map_err(|err| {
            VmHttpNixCacheNarVerifyError::Decode {
                message: err.to_string(),
            }
        })?;
    // Cap the decoder's window buffer so a frame declaring a larger window is
    // rejected up front rather than allocating it. Like xz's memlimit, this is
    // the peak-memory bound; the read loop separately caps decoded output.
    decoder
        .window_log_max(ZSTD_DECODER_WINDOW_LOG_MAX)
        .map_err(|err| VmHttpNixCacheNarVerifyError::Decode {
            message: err.to_string(),
        })?;
    read_decoded_bounded(decoder, expected_size)
}

/// Drain a decompressing reader into a buffer whose size is capped at the
/// signed `NarSize`: the moment the decoded stream exceeds it we bail with a
/// `SizeMismatch` rather than growing without bound. Shared by the xz and zstd
/// paths so both enforce the same output ceiling identically.
fn read_decoded_bounded(
    mut decoder: impl std::io::Read,
    expected_size: u64,
) -> Result<Vec<u8>, VmHttpNixCacheNarVerifyError> {
    let capacity =
        usize::try_from(expected_size).map_err(|_| VmHttpNixCacheNarVerifyError::Decode {
            message: format!("signed NarSize {expected_size} does not fit in usize"),
        })?;
    let mut decoded = Vec::with_capacity(capacity);
    let mut chunk = [0_u8; 8192];
    loop {
        let read =
            decoder
                .read(&mut chunk)
                .map_err(|err| VmHttpNixCacheNarVerifyError::Decode {
                    message: err.to_string(),
                })?;
        if read == 0 {
            break;
        }
        decoded.extend_from_slice(&chunk[..read]);
        if decoded.len() as u64 > expected_size {
            return Err(VmHttpNixCacheNarVerifyError::SizeMismatch {
                expected: expected_size,
                actual: decoded.len() as u64,
            });
        }
    }
    Ok(decoded)
}

fn xz_decoder_memlimit(max_nar_bytes: u64) -> Result<u64, VmHttpNixCacheNarVerifyError> {
    max_nar_bytes
        .checked_add(XZ_DECODER_MEMLIMIT_OVERHEAD)
        .ok_or_else(|| VmHttpNixCacheNarVerifyError::Decode {
            message: format!(
                "configured max NAR bytes {max_nar_bytes} leaves no room for xz decoder overhead"
            ),
        })
}

pub(super) fn nar_body_hash_error_label(error: &NixNarBodyHashError) -> &'static str {
    match error {
        NixNarBodyHashError::UnsupportedAlgorithm { .. } => {
            "unsupported upstream nar hash algorithm"
        }
        NixNarBodyHashError::InvalidDigestLength { .. }
        | NixNarBodyHashError::InvalidDigestByte => "invalid upstream nar hash digest",
        NixNarBodyHashError::Mismatch { .. } => "mismatched upstream nar hash",
    }
}

/// Property-based spec for [`verify_nar_body`]: any byte body, whether served
/// raw, xz-, or zstd-compressed, verifies against the admitted metadata derived
/// from that same body. Example mismatches (short bodies, concatenated streams,
/// missing/oversized lengths, oversized windows) live in `nar_verify_tests.rs`.
#[cfg(test)]
mod spec {
    use super::super::test_support::{admitted_nar_for_body, xz_nar_body_for, zstd_nar_body_for};
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn generated_nar_bodies_verify_against_their_admitted_metadata(
            raw_body in prop::collection::vec(any::<u8>(), 0..512),
            compression in prop::sample::select(&[
                NixNarCompression::None,
                NixNarCompression::Xz,
                NixNarCompression::Zstd,
            ]),
        ) {
            let wire_body = match compression {
                NixNarCompression::None => raw_body.clone(),
                NixNarCompression::Xz => xz_nar_body_for(&raw_body),
                NixNarCompression::Zstd => zstd_nar_body_for(&raw_body),
            };
            let admission = admitted_nar_for_body("generated.nar", compression, &raw_body);
            verify_nar_body(&admission, &wire_body, 512).unwrap();
        }
    }
}
