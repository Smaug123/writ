//! Host-side Nix binary-cache domain model: store paths, narinfo, NAR hashing,
//! Ed25519 signature verification, and cache-admission parsing. This is the pure
//! data-and-crypto layer; the HTTP service that serves the binary-cache protocol
//! to the no-egress guest lives in the `vm_http::nix_cache` module.

use base64::Engine as _;

const NIX_STORE_HASH_LEN: usize = 32;
const NIX_STORE_HASH_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
/// Truncated-SHA-256 length (in bytes) of a Nix store-path hash; the 32-char
/// store hash is this many bytes in nix-base32.
const NIX_STORE_PATH_HASH_LEN: usize = 20;
const NIX_SHA256_DIGEST_LEN: usize = 32;
const NIX_SHA256_BASE32_LEN: usize = 52;
const NIX_ED25519_PUBLIC_KEY_LEN: usize = 32;
const NIX_ED25519_SIGNATURE_LEN: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NixStoreHashPart(String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NixStorePath {
    raw: String,
    hash: NixStoreHashPart,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NixCacheNarFileName(String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NixNarHash(String);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NixNarSize(u64);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NixNarCompression {
    None,
    Xz,
    Zstd,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NixNarReferences(Vec<NixStorePath>);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NixNarSignature {
    key_name: String,
    signature: [u8; NIX_ED25519_SIGNATURE_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NixNarInfo {
    store_path: NixStorePath,
    nar_file: NixCacheNarFileName,
    compression: NixNarCompression,
    nar_hash: NixNarHash,
    nar_size: NixNarSize,
    references: NixNarReferences,
    signatures: Vec<NixNarSignature>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NixTrustedPublicKey {
    raw: String,
    name: String,
    public_key: [u8; NIX_ED25519_PUBLIC_KEY_LEN],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NixTrustedPublicKeys(Vec<NixTrustedPublicKey>);

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixTrustedPublicKeyError {
    #[error("trusted public key must not be empty")]
    Empty,
    #[error("trusted public key must be NAME:BASE64")]
    MissingSeparator,
    #[error("trusted public key name must not be empty")]
    EmptyName,
    #[error("trusted public key material must not be empty")]
    EmptyKey,
    #[error("trusted public key must contain exactly one ':' separator")]
    TooManySeparators,
    #[error("trusted public key name contains an invalid byte")]
    InvalidNameByte,
    #[error("trusted public key name is duplicated")]
    DuplicateName,
    #[error("trusted public key material contains an invalid base64 byte")]
    InvalidKeyByte,
    #[error("trusted public key base64 padding is invalid")]
    InvalidBase64Padding,
    #[error("trusted public key base64 length is invalid")]
    InvalidBase64Length,
    #[error("trusted public key must decode to a 32-byte Ed25519 public key")]
    InvalidPublicKeyLength,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixStoreHashPartError {
    #[error("Nix store hash must be exactly 32 bytes")]
    WrongLength,
    #[error("Nix store hash contains an invalid byte")]
    InvalidByte,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixStorePathError {
    #[error("Nix store path must start with /nix/store/")]
    MissingStorePrefix,
    #[error("Nix store path must not contain nested path segments")]
    NestedPathSegment,
    #[error("Nix store path must contain a '-' after the hash part")]
    MissingNameSeparator,
    #[error("Nix store path name must not be empty")]
    EmptyName,
    #[error("Nix store path hash is invalid: {0}")]
    InvalidHash(#[from] NixStoreHashPartError),
    #[error("Nix store path name contains an invalid byte")]
    InvalidNameByte,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixCacheNarFileNameError {
    #[error("NAR filename must not be empty")]
    Empty,
    #[error("NAR filename is too long; maximum is 255 bytes")]
    TooLong,
    #[error("NAR filename must not start or end with '.'")]
    DotBoundary,
    #[error("NAR filename must not contain '/'")]
    Slash,
    #[error("NAR filename contains an invalid byte")]
    InvalidByte,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixNarHashError {
    #[error("NarHash must be ALGORITHM:DIGEST")]
    MissingSeparator,
    #[error("NarHash must contain exactly one ':' separator")]
    TooManySeparators,
    #[error("NarHash algorithm must not be empty")]
    EmptyAlgorithm,
    #[error("NarHash digest must not be empty")]
    EmptyDigest,
    #[error("NarHash algorithm contains an invalid byte")]
    InvalidAlgorithmByte,
    #[error("NarHash digest contains an invalid byte")]
    InvalidDigestByte,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixNarBodyHashError {
    #[error("NarHash algorithm {algorithm:?} is not supported for broker-side NAR verification")]
    UnsupportedAlgorithm { algorithm: String },
    #[error("NarHash sha256 digest must be 52 Nix base32 bytes, got {actual}")]
    InvalidDigestLength { actual: usize },
    #[error("NarHash sha256 digest contains a non-Nix-base32 byte")]
    InvalidDigestByte,
    #[error("NAR body SHA-256 does not match NarHash")]
    Mismatch { expected: String, actual: String },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixNarSizeError {
    #[error("NarSize must contain only decimal digits")]
    InvalidByte,
    #[error("NarSize must be canonical decimal without leading zeroes")]
    LeadingZero,
    #[error("NarSize does not fit in u64")]
    Overflow,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixNarCompressionError {
    #[error("Compression value is not supported")]
    Unsupported,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixNarReferencesError {
    #[error("narinfo References contains an empty reference")]
    EmptyReference,
    #[error("narinfo References entry {raw:?} is invalid: {source}")]
    InvalidReference {
        raw: String,
        source: NixStorePathError,
    },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixNarSignatureError {
    #[error("Sig must be NAME:BASE64")]
    MissingSeparator,
    #[error("Sig key name must not be empty")]
    EmptyName,
    #[error("Sig value must not be empty")]
    EmptySignature,
    #[error("Sig must contain exactly one ':' separator")]
    TooManySeparators,
    #[error("Sig key name contains an invalid byte")]
    InvalidNameByte,
    #[error("Sig base64 is invalid")]
    InvalidBase64,
    #[error("Sig must decode to a 64-byte Ed25519 signature")]
    InvalidSignatureLength,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixNarInfoError {
    #[error("narinfo is not UTF-8")]
    InvalidUtf8,
    #[error("narinfo is missing StorePath")]
    MissingStorePath,
    #[error("narinfo contains duplicate StorePath")]
    DuplicateStorePath,
    #[error("narinfo StorePath must not be empty")]
    EmptyStorePath,
    #[error("narinfo StorePath {raw:?} is invalid: {source}")]
    InvalidStorePath {
        raw: String,
        source: NixStorePathError,
    },
    #[error("narinfo is missing URL")]
    MissingUrl,
    #[error("narinfo contains duplicate URL")]
    DuplicateUrl,
    #[error("narinfo URL must not be empty")]
    EmptyUrl,
    #[error("narinfo URL must be nar/<safe-filename>, got {0:?}")]
    UnsupportedUrl(String),
    #[error("narinfo URL {url:?} contains invalid NAR filename: {source}")]
    InvalidNarFile {
        url: String,
        source: NixCacheNarFileNameError,
    },
    #[error("narinfo is missing NarHash")]
    MissingNarHash,
    #[error("narinfo contains duplicate NarHash")]
    DuplicateNarHash,
    #[error("narinfo NarHash must not be empty")]
    EmptyNarHash,
    #[error("narinfo NarHash {raw:?} is invalid: {source}")]
    InvalidNarHash {
        raw: String,
        source: NixNarHashError,
    },
    #[error("narinfo is missing Compression")]
    MissingCompression,
    #[error("narinfo contains duplicate Compression")]
    DuplicateCompression,
    #[error("narinfo Compression must not be empty")]
    EmptyCompression,
    #[error("narinfo Compression {raw:?} is invalid: {source}")]
    InvalidCompression {
        raw: String,
        source: NixNarCompressionError,
    },
    #[error("narinfo is missing NarSize")]
    MissingNarSize,
    #[error("narinfo contains duplicate NarSize")]
    DuplicateNarSize,
    #[error("narinfo NarSize must not be empty")]
    EmptyNarSize,
    #[error("narinfo NarSize {raw:?} is invalid: {source}")]
    InvalidNarSize {
        raw: String,
        source: NixNarSizeError,
    },
    #[error("narinfo contains duplicate References")]
    DuplicateReferences,
    #[error("narinfo References {raw:?} is invalid: {source}")]
    InvalidReferences {
        raw: String,
        source: NixNarReferencesError,
    },
    #[error("narinfo is missing Sig")]
    MissingSignature,
    #[error("narinfo Sig {raw:?} is invalid: {source}")]
    InvalidSignature {
        raw: String,
        source: NixNarSignatureError,
    },
    #[error("narinfo has no signature from a configured trusted public key")]
    UntrustedSignatureKey,
    #[error("narinfo has a trusted-key signature, but none verify")]
    SignatureMismatch,
    #[error("narinfo StorePath hash {actual} does not match requested hash {expected}")]
    StorePathHashMismatch {
        expected: NixStoreHashPart,
        actual: NixStoreHashPart,
    },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("Nix trusted public key at index {index} {raw:?} is invalid: {source}")]
pub struct NixTrustedPublicKeysError {
    index: usize,
    raw: String,
    source: NixTrustedPublicKeyError,
}

impl NixStoreHashPart {
    pub fn new(raw: impl Into<String>) -> Result<Self, NixStoreHashPartError> {
        let raw = raw.into();
        Self::validate(&raw)?;
        Ok(Self(raw))
    }

    pub fn validate(raw: &str) -> Result<(), NixStoreHashPartError> {
        if raw.len() != NIX_STORE_HASH_LEN {
            return Err(NixStoreHashPartError::WrongLength);
        }
        if !raw
            .bytes()
            .all(|byte| NIX_STORE_HASH_ALPHABET.contains(&byte))
        {
            return Err(NixStoreHashPartError::InvalidByte);
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NixStoreHashPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl NixStorePath {
    pub fn new(raw: impl Into<String>) -> Result<Self, NixStorePathError> {
        let raw = raw.into();
        let Some(name) = raw.strip_prefix("/nix/store/") else {
            return Err(NixStorePathError::MissingStorePrefix);
        };
        if name.contains('/') {
            return Err(NixStorePathError::NestedPathSegment);
        }
        let Some((hash, name)) = name.split_once('-') else {
            return Err(NixStorePathError::MissingNameSeparator);
        };
        let hash = NixStoreHashPart::new(hash)?;
        if name.is_empty() {
            return Err(NixStorePathError::EmptyName);
        }
        if !name.bytes().all(is_nix_store_name_byte) {
            return Err(NixStorePathError::InvalidNameByte);
        }
        Ok(Self { raw, hash })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn hash(&self) -> &NixStoreHashPart {
        &self.hash
    }

    /// The name part after `/nix/store/<hash>-`.
    pub fn name(&self) -> &str {
        self.raw
            .strip_prefix("/nix/store/")
            .and_then(|rest| rest.split_once('-'))
            .map(|(_, name)| name)
            .expect("a parsed NixStorePath always has the /nix/store/<hash>-<name> shape")
    }
}

impl std::fmt::Display for NixStorePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl NixCacheNarFileName {
    pub fn new(raw: impl Into<String>) -> Result<Self, NixCacheNarFileNameError> {
        let raw = raw.into();
        Self::validate(&raw)?;
        Ok(Self(raw))
    }

    pub fn validate(raw: &str) -> Result<(), NixCacheNarFileNameError> {
        if raw.is_empty() {
            return Err(NixCacheNarFileNameError::Empty);
        }
        if raw.len() > 255 {
            return Err(NixCacheNarFileNameError::TooLong);
        }
        if raw.starts_with('.') || raw.ends_with('.') {
            return Err(NixCacheNarFileNameError::DotBoundary);
        }
        if raw.contains('/') {
            return Err(NixCacheNarFileNameError::Slash);
        }
        if !raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'+'))
        {
            return Err(NixCacheNarFileNameError::InvalidByte);
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NixCacheNarFileName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl NixNarHash {
    pub fn new(raw: impl Into<String>) -> Result<Self, NixNarHashError> {
        let raw = raw.into();
        let Some((algorithm, digest)) = raw.split_once(':') else {
            return Err(NixNarHashError::MissingSeparator);
        };
        if digest.contains(':') {
            return Err(NixNarHashError::TooManySeparators);
        }
        if algorithm.is_empty() {
            return Err(NixNarHashError::EmptyAlgorithm);
        }
        if digest.is_empty() {
            return Err(NixNarHashError::EmptyDigest);
        }
        if !algorithm.bytes().all(is_nix_hash_algorithm_byte) {
            return Err(NixNarHashError::InvalidAlgorithmByte);
        }
        if !digest.bytes().all(is_nix_hash_digest_byte) {
            return Err(NixNarHashError::InvalidDigestByte);
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn algorithm(&self) -> &str {
        self.0
            .split_once(':')
            .expect("parsed NarHash always contains algorithm separator")
            .0
    }

    pub fn digest(&self) -> &str {
        self.0
            .split_once(':')
            .expect("parsed NarHash always contains digest separator")
            .1
    }

    pub fn validate_sha256_body_hash_shape(&self) -> Result<(), NixNarBodyHashError> {
        let algorithm = self.algorithm();
        if algorithm != "sha256" {
            return Err(NixNarBodyHashError::UnsupportedAlgorithm {
                algorithm: algorithm.to_string(),
            });
        }
        let expected = self.digest();
        if expected.len() != NIX_SHA256_BASE32_LEN {
            return Err(NixNarBodyHashError::InvalidDigestLength {
                actual: expected.len(),
            });
        }
        if !expected
            .bytes()
            .all(|byte| NIX_STORE_HASH_ALPHABET.contains(&byte))
        {
            return Err(NixNarBodyHashError::InvalidDigestByte);
        }
        Ok(())
    }

    pub fn verify_sha256_body(&self, body: &[u8]) -> Result<(), NixNarBodyHashError> {
        // Keep this defensive check here even when the VM HTTP admission path
        // already checked the shape; this public method should be correct when
        // called directly.
        self.validate_sha256_body_hash_shape()?;
        let expected = self.digest();
        let digest = ring::digest::digest(&ring::digest::SHA256, body);
        let digest: [u8; NIX_SHA256_DIGEST_LEN] = digest
            .as_ref()
            .try_into()
            .expect("ring SHA-256 digest length should be 32 bytes");
        let actual = nix_base32_encode_sha256_digest(&digest);
        if actual != expected {
            return Err(NixNarBodyHashError::Mismatch {
                expected: expected.to_string(),
                actual,
            });
        }
        Ok(())
    }
}

impl NixNarSize {
    pub fn new(raw: &str) -> Result<Self, NixNarSizeError> {
        if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(NixNarSizeError::InvalidByte);
        }
        if raw.len() > 1 && raw.starts_with('0') {
            return Err(NixNarSizeError::LeadingZero);
        }
        let size = raw.parse().map_err(|_| NixNarSizeError::Overflow)?;
        Ok(Self(size))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for NixNarSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl NixNarCompression {
    pub fn new(raw: &str) -> Result<Self, NixNarCompressionError> {
        match raw {
            "none" => Ok(Self::None),
            "xz" => Ok(Self::Xz),
            "zstd" => Ok(Self::Zstd),
            _ => Err(NixNarCompressionError::Unsupported),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }
}

impl std::fmt::Display for NixNarCompression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl NixNarReferences {
    pub fn new(raw: &str) -> Result<Self, NixNarReferencesError> {
        if raw.is_empty() {
            return Ok(Self(Vec::new()));
        }
        let mut references = Vec::new();
        for reference in raw.split(' ') {
            if reference.is_empty() {
                return Err(NixNarReferencesError::EmptyReference);
            }
            let raw_path = format!("/nix/store/{reference}");
            let reference_path = NixStorePath::new(raw_path.clone()).map_err(|source| {
                NixNarReferencesError::InvalidReference {
                    raw: reference.to_string(),
                    source,
                }
            })?;
            references.push(reference_path);
        }
        Ok(Self(references))
    }

    pub fn iter(&self) -> impl Iterator<Item = &NixStorePath> {
        self.0.iter()
    }

    fn fingerprint_value(&self) -> String {
        self.0
            .iter()
            .map(NixStorePath::as_str)
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl NixNarSignature {
    pub fn new(raw: &str) -> Result<Self, NixNarSignatureError> {
        let Some((name, signature)) = raw.split_once(':') else {
            return Err(NixNarSignatureError::MissingSeparator);
        };
        if signature.contains(':') {
            return Err(NixNarSignatureError::TooManySeparators);
        }
        if name.is_empty() {
            return Err(NixNarSignatureError::EmptyName);
        }
        if signature.is_empty() {
            return Err(NixNarSignatureError::EmptySignature);
        }
        if !name.bytes().all(is_nix_key_name_byte) {
            return Err(NixNarSignatureError::InvalidNameByte);
        }
        let signature = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .map_err(|_| NixNarSignatureError::InvalidBase64)?;
        let signature = signature
            .try_into()
            .map_err(|_| NixNarSignatureError::InvalidSignatureLength)?;
        Ok(Self {
            key_name: name.to_string(),
            signature,
        })
    }

    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    pub fn signature(&self) -> &[u8; NIX_ED25519_SIGNATURE_LEN] {
        &self.signature
    }
}

impl NixNarInfo {
    pub fn store_path(&self) -> &NixStorePath {
        &self.store_path
    }

    pub fn nar_file(&self) -> &NixCacheNarFileName {
        &self.nar_file
    }

    pub fn compression(&self) -> NixNarCompression {
        self.compression
    }

    pub fn nar_hash(&self) -> &NixNarHash {
        &self.nar_hash
    }

    pub fn nar_size(&self) -> NixNarSize {
        self.nar_size
    }

    pub fn references(&self) -> &NixNarReferences {
        &self.references
    }

    pub fn signatures(&self) -> &[NixNarSignature] {
        &self.signatures
    }

    fn signature_fingerprint(&self) -> String {
        format!(
            "1;{};{};{};{}",
            self.store_path.as_str(),
            self.nar_hash.as_str(),
            self.nar_size,
            self.references.fingerprint_value(),
        )
    }
}

/// Raw, deduplicated narinfo fields, before any field is *required* or typed.
/// Borrows the narinfo text. Both the signed ([`parse_narinfo`]) and the
/// content-addressed ([`parse_content_addressed_narinfo_for_store_hash`])
/// parsers build on this; they differ only in which fields they then require.
struct RawNarInfoFields<'a> {
    store_path: Option<&'a str>,
    url: Option<&'a str>,
    compression: Option<&'a str>,
    nar_hash: Option<&'a str>,
    nar_size: Option<&'a str>,
    references: Option<&'a str>,
    content_address: Option<&'a str>,
    signatures: Vec<NixNarSignature>,
}

/// Scan a narinfo's `KEY: VALUE` lines into deduplicated raw fields, without
/// requiring any particular field to be present.
fn scan_narinfo_fields(raw: &str) -> Result<RawNarInfoFields<'_>, NixNarInfoError> {
    let mut store_path = None;
    let mut url = None;
    let mut compression = None;
    let mut nar_hash = None;
    let mut nar_size = None;
    let mut references = None;
    let mut content_address = None;
    let mut signatures = Vec::new();
    for line in raw.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        // Nix-generated narinfos use `URL: nar/...`; `URL:nar/...` is also
        // unambiguous. Tabs or extra spaces remain in the value and fail
        // closed against each field parser below.
        let value = value.strip_prefix(' ').unwrap_or(value);
        match key {
            "StorePath" => {
                if store_path.is_some() {
                    return Err(NixNarInfoError::DuplicateStorePath);
                }
                if value.is_empty() {
                    return Err(NixNarInfoError::EmptyStorePath);
                }
                store_path = Some(value);
            }
            "URL" => {
                if url.is_some() {
                    return Err(NixNarInfoError::DuplicateUrl);
                }
                if value.is_empty() {
                    return Err(NixNarInfoError::EmptyUrl);
                }
                url = Some(value);
            }
            "NarHash" => {
                if nar_hash.is_some() {
                    return Err(NixNarInfoError::DuplicateNarHash);
                }
                if value.is_empty() {
                    return Err(NixNarInfoError::EmptyNarHash);
                }
                nar_hash = Some(value);
            }
            "Compression" => {
                if compression.is_some() {
                    return Err(NixNarInfoError::DuplicateCompression);
                }
                if value.is_empty() {
                    return Err(NixNarInfoError::EmptyCompression);
                }
                compression = Some(value);
            }
            "NarSize" => {
                if nar_size.is_some() {
                    return Err(NixNarInfoError::DuplicateNarSize);
                }
                if value.is_empty() {
                    return Err(NixNarInfoError::EmptyNarSize);
                }
                nar_size = Some(value);
            }
            "References" => {
                if references.is_some() {
                    return Err(NixNarInfoError::DuplicateReferences);
                }
                references = Some(value);
            }
            "Sig" => {
                if value.is_empty() {
                    return Err(NixNarInfoError::InvalidSignature {
                        raw: value.to_string(),
                        source: NixNarSignatureError::EmptySignature,
                    });
                }
                let signature = NixNarSignature::new(value).map_err(|source| {
                    NixNarInfoError::InvalidSignature {
                        raw: value.to_string(),
                        source,
                    }
                })?;
                signatures.push(signature);
            }
            // `CA` is captured leniently (last value wins, no duplicate error):
            // it is advisory for the signed path and only *validated* by the
            // content-addressed parser. Real Nix narinfos carry exactly one.
            "CA" => {
                content_address = Some(value);
            }
            _ => {}
        }
    }
    Ok(RawNarInfoFields {
        store_path,
        url,
        compression,
        nar_hash,
        nar_size,
        references,
        content_address,
        signatures,
    })
}

/// Require and type every load-bearing narinfo field, *without* requiring a
/// signature. The signed path adds the signature requirement on top; the
/// content-addressed path adds the CA self-certification check instead.
fn build_narinfo(fields: RawNarInfoFields<'_>) -> Result<NixNarInfo, NixNarInfoError> {
    let store_path = fields.store_path.ok_or(NixNarInfoError::MissingStorePath)?;
    let store_path =
        NixStorePath::new(store_path).map_err(|source| NixNarInfoError::InvalidStorePath {
            raw: store_path.to_string(),
            source,
        })?;
    let url = fields.url.ok_or(NixNarInfoError::MissingUrl)?;
    let Some(file) = url.strip_prefix("nar/") else {
        return Err(NixNarInfoError::UnsupportedUrl(url.to_string()));
    };
    let nar_file =
        NixCacheNarFileName::new(file).map_err(|source| NixNarInfoError::InvalidNarFile {
            url: url.to_string(),
            source,
        })?;
    let nar_hash = fields.nar_hash.ok_or(NixNarInfoError::MissingNarHash)?;
    let nar_hash = NixNarHash::new(nar_hash).map_err(|source| NixNarInfoError::InvalidNarHash {
        raw: nar_hash.to_string(),
        source,
    })?;
    let compression = fields
        .compression
        .ok_or(NixNarInfoError::MissingCompression)?;
    let compression = NixNarCompression::new(compression).map_err(|source| {
        NixNarInfoError::InvalidCompression {
            raw: compression.to_string(),
            source,
        }
    })?;
    let nar_size = fields.nar_size.ok_or(NixNarInfoError::MissingNarSize)?;
    let nar_size = NixNarSize::new(nar_size).map_err(|source| NixNarInfoError::InvalidNarSize {
        raw: nar_size.to_string(),
        source,
    })?;
    // Nix omits the `References:` line entirely for a reference-free path (it
    // does not emit an empty `References: `), so an absent line means zero
    // references — not a malformed narinfo. cache.nixos.org relies on this and
    // signs the fingerprint over the empty reference set, so reading absent as
    // empty both matches the producer and keeps signature verification honest:
    // stripping a *non-empty* References line changes the fingerprint and fails
    // the signature.
    let references = fields.references.unwrap_or("");
    let references =
        NixNarReferences::new(references).map_err(|source| NixNarInfoError::InvalidReferences {
            raw: references.to_string(),
            source,
        })?;
    Ok(NixNarInfo {
        store_path,
        nar_file,
        compression,
        nar_hash,
        nar_size,
        references,
        signatures: fields.signatures,
    })
}

pub fn parse_narinfo(bytes: &[u8]) -> Result<NixNarInfo, NixNarInfoError> {
    let raw = std::str::from_utf8(bytes).map_err(|_| NixNarInfoError::InvalidUtf8)?;
    let fields = scan_narinfo_fields(raw)?;
    // Validate every other field before reporting a missing signature, so the
    // error precedence matches the historical single-pass parser.
    let narinfo = build_narinfo(fields)?;
    if narinfo.signatures.is_empty() {
        return Err(NixNarInfoError::MissingSignature);
    }
    Ok(narinfo)
}

pub fn parse_narinfo_for_store_hash(
    bytes: &[u8],
    expected: &NixStoreHashPart,
) -> Result<NixNarInfo, NixNarInfoError> {
    let narinfo = parse_narinfo(bytes)?;
    if narinfo.store_path.hash() != expected {
        return Err(NixNarInfoError::StorePathHashMismatch {
            expected: expected.clone(),
            actual: narinfo.store_path.hash().clone(),
        });
    }
    Ok(narinfo)
}

pub fn parse_signed_narinfo_for_store_hash(
    bytes: &[u8],
    expected: &NixStoreHashPart,
    trusted_public_keys: &NixTrustedPublicKeys,
) -> Result<NixNarInfo, NixNarInfoError> {
    let narinfo = parse_narinfo_for_store_hash(bytes, expected)?;
    verify_narinfo_signature(&narinfo, trusted_public_keys)?;
    Ok(narinfo)
}

/// The `CA` value prefix of a recursive ("r") SHA-256 fixed-output store path —
/// the only content-address form the broker admits unsigned. For such a path
/// the store object's identity is the SHA-256 of its NAR serialization, so the
/// `<digest>` after this prefix is exactly the path's NarHash digest.
const NIX_CA_RECURSIVE_SHA256_PREFIX: &str = "fixed:r:sha256:";

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixContentAddressedNarInfoError {
    /// The narinfo is malformed independently of content-addressing (bad
    /// field, or its StorePath hash does not match the requested hash).
    #[error(transparent)]
    NarInfo(#[from] NixNarInfoError),
    /// The narinfo carries no `CA` field, so the broker cannot self-certify it
    /// and would need a trusted signature it does not have.
    #[error("content-addressed narinfo is missing the CA field required to admit it unsigned")]
    MissingContentAddress,
    /// The narinfo has a `CA` field, but it is not a recursive-SHA256
    /// fixed-output whose digest equals NarHash — so verifying the NAR body
    /// would not verify the store path's identity. Refused.
    #[error(
        "content-addressed narinfo CA {content_address:?} is not a recursive-SHA256 fixed-output \
         whose digest equals NarHash {nar_hash:?}; only such self-certifying paths are admitted \
         unsigned"
    )]
    NotSelfCertifying {
        content_address: String,
        nar_hash: String,
    },
    /// The narinfo self-certifies by CA/NarHash, but its StorePath hash is not
    /// the reference-free Nix fixed-output path derived from that content
    /// address and store name — so the path's identity does not match its
    /// content (and the guest would reject it). Refused. A referenced CA path,
    /// which fetched flake inputs never are, also lands here: only the
    /// reference-free derivation is checked.
    #[error(
        "content-addressed narinfo StorePath {store_path:?} is not the reference-free fixed-output \
         path derived from its content address {content_address:?}"
    )]
    StorePathNotContentDerived {
        store_path: String,
        content_address: String,
    },
}

/// Parse a narinfo from the broker's *local* flake-input archive and admit it
/// for **unsigned** serving iff it is self-certifying: it carries a
/// recursive-SHA256 fixed-output content address (`CA: fixed:r:sha256:<digest>`)
/// whose digest equals its NarHash.
///
/// For such a path the store object's identity *is* the SHA-256 of the NAR the
/// broker later verifies, so verifying the NAR body against NarHash also
/// verifies the content address — no signature is required, and `nix flake
/// archive` produces exactly these (unsigned). Anything else — a missing CA, a
/// non-recursive or non-SHA256 CA, or a CA whose digest differs from NarHash —
/// is refused, because the broker cannot certify it without a trusted
/// signature. `expected` is the store hash from the request path; the narinfo's
/// StorePath must match it, so a `<hash>.narinfo` file always describes
/// `<hash>`.
pub fn parse_content_addressed_narinfo_for_store_hash(
    bytes: &[u8],
    expected: &NixStoreHashPart,
) -> Result<NixNarInfo, NixContentAddressedNarInfoError> {
    let raw = std::str::from_utf8(bytes).map_err(|_| NixNarInfoError::InvalidUtf8)?;
    let fields = scan_narinfo_fields(raw)?;
    // Capture the (owned) CA before `build_narinfo` consumes the borrowed fields.
    let content_address = fields.content_address.map(str::to_owned);
    let narinfo = build_narinfo(fields)?;
    if narinfo.store_path.hash() != expected {
        return Err(NixNarInfoError::StorePathHashMismatch {
            expected: expected.clone(),
            actual: narinfo.store_path.hash().clone(),
        }
        .into());
    }
    let content_address =
        content_address.ok_or(NixContentAddressedNarInfoError::MissingContentAddress)?;
    let self_certifying = narinfo.nar_hash.algorithm() == "sha256"
        && content_address.strip_prefix(NIX_CA_RECURSIVE_SHA256_PREFIX)
            == Some(narinfo.nar_hash.digest());
    if !self_certifying {
        return Err(NixContentAddressedNarInfoError::NotSelfCertifying {
            content_address,
            nar_hash: narinfo.nar_hash.as_str().to_owned(),
        });
    }
    // Fully self-certify: the StorePath hash must be the Nix fixed-output path
    // derived from the content address and store name, with no references (what
    // fetched flake inputs are). Otherwise the broker would be serving a path
    // whose identity does not match its content — which the guest would reject —
    // so fail closed here with a clear reason instead.
    let derived = if narinfo.references.iter().next().is_some() {
        None
    } else {
        fixed_output_recursive_sha256_store_hash(
            narinfo.nar_hash.digest(),
            narinfo.store_path.name(),
        )
    };
    if derived.as_deref() != Some(narinfo.store_path.hash().as_str()) {
        return Err(
            NixContentAddressedNarInfoError::StorePathNotContentDerived {
                store_path: narinfo.store_path.as_str().to_owned(),
                content_address,
            },
        );
    }
    Ok(narinfo)
}

/// Why a narinfo from the broker's *local* archive was not admissible for
/// serving. The local path admits a narinfo iff it is self-certifying
/// (content-addressed; see [`parse_content_addressed_narinfo_for_store_hash`])
/// *or* signed by a key the broker trusts — the latter being how a pre-warmed
/// devShell closure's input-addressed outputs, which are not self-certifying,
/// are served.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NixLocalNarInfoError {
    /// The narinfo is malformed independently of how it would be admitted (a bad
    /// field, or a StorePath hash that does not match the requested hash). This
    /// is terminal: a signature can never rescue a broken or mislabelled file.
    #[error(transparent)]
    Malformed(NixNarInfoError),
    /// The narinfo is well-formed for the requested hash but admissible as
    /// neither self-certifying nor trusted-signed: it carries no usable content
    /// address and no signature by a trusted key. The inner error is the
    /// signature-verification failure (missing / untrusted / mismatched).
    #[error("local narinfo is neither self-certifying nor signed by a trusted key: {0}")]
    UntrustedOrUnsigned(NixNarInfoError),
}

/// Admit a narinfo from the broker's *local* archive for serving iff it is
/// self-certifying **or** signed by a trusted key.
///
/// Content-addressing is tried first: it needs no key and is exactly what `nix
/// flake archive` writes for flake inputs. A well-formed-but-not-self-certifying
/// narinfo (no `CA`, or a `CA` that does not certify it) then falls back to
/// signature verification against `trusted_public_keys`, admitting a pre-warmed,
/// human-signed closure path whose input-addressed outputs are not
/// self-certifying. A *malformed* narinfo, or one whose StorePath hash does not
/// match `expected`, is terminal and never reaches the signature check.
///
/// This is only the broker half of the check: the guest re-verifies the served
/// narinfo's signature against its own `trusted-public-keys`, so a path the
/// broker admits by signature is still rejected by the guest unless the guest
/// trusts the same key.
pub fn parse_local_admissible_narinfo_for_store_hash(
    bytes: &[u8],
    expected: &NixStoreHashPart,
    trusted_public_keys: &NixTrustedPublicKeys,
) -> Result<NixNarInfo, NixLocalNarInfoError> {
    match parse_content_addressed_narinfo_for_store_hash(bytes, expected) {
        Ok(narinfo) => Ok(narinfo),
        // Malformed / wrong-hash: terminal. Do not mask it with a signature
        // attempt that would re-parse the same broken bytes.
        Err(NixContentAddressedNarInfoError::NarInfo(err)) => {
            Err(NixLocalNarInfoError::Malformed(err))
        }
        // Well-formed but not self-certifying (no CA, a non-self-certifying CA,
        // or a CA whose store path is not content-derived): admit iff a trusted
        // key signed it.
        Err(
            NixContentAddressedNarInfoError::MissingContentAddress
            | NixContentAddressedNarInfoError::NotSelfCertifying { .. }
            | NixContentAddressedNarInfoError::StorePathNotContentDerived { .. },
        ) => parse_signed_narinfo_for_store_hash(bytes, expected, trusted_public_keys)
            .map_err(NixLocalNarInfoError::UntrustedOrUnsigned),
    }
}

pub fn verify_narinfo_signature(
    narinfo: &NixNarInfo,
    trusted_public_keys: &NixTrustedPublicKeys,
) -> Result<(), NixNarInfoError> {
    let fingerprint = narinfo.signature_fingerprint();
    let mut saw_trusted_key = false;
    for signature in narinfo.signatures() {
        let Some(public_key) = trusted_public_keys.find(signature.key_name()) else {
            continue;
        };
        saw_trusted_key = true;
        let verifier = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            public_key.public_key(),
        );
        if verifier
            .verify(fingerprint.as_bytes(), signature.signature())
            .is_ok()
        {
            return Ok(());
        }
    }
    if saw_trusted_key {
        Err(NixNarInfoError::SignatureMismatch)
    } else {
        Err(NixNarInfoError::UntrustedSignatureKey)
    }
}

pub fn nix_base32_encode_sha256_digest(digest: &[u8; NIX_SHA256_DIGEST_LEN]) -> String {
    nix_base32_encode(digest)
}

/// Nix's little-endian base32 of an arbitrary byte slice (the encoding Nix uses
/// for store hashes and digests). The output length is `ceil(8 * len / 5)`.
fn nix_base32_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let len = (bytes.len() * 8 - 1) / 5 + 1;
    let mut encoded = String::with_capacity(len);
    for n in (0..len).rev() {
        let bit = n * 5;
        let byte_index = bit / 8;
        let bit_offset = bit % 8;
        let current = bytes[byte_index] as u16;
        let next = bytes.get(byte_index + 1).copied().unwrap_or(0) as u16;
        let value = (current >> bit_offset) | (next << (8 - bit_offset));
        encoded.push(NIX_STORE_HASH_ALPHABET[(value & 0x1f) as usize] as char);
    }
    encoded
}

/// Inverse of [`nix_base32_encode`] for a 52-character SHA-256 digest. Returns
/// `None` if the input is the wrong length, contains a non-alphabet byte, or
/// carries non-zero overflow bits (an invalid encoding).
fn nix_base32_decode_sha256(encoded: &str) -> Option<[u8; NIX_SHA256_DIGEST_LEN]> {
    if encoded.len() != NIX_SHA256_BASE32_LEN {
        return None;
    }
    let mut out = [0u8; NIX_SHA256_DIGEST_LEN];
    for (n, byte) in encoded.bytes().rev().enumerate() {
        let digit = NIX_STORE_HASH_ALPHABET.iter().position(|&c| c == byte)? as u16;
        let bit = n * 5;
        let byte_index = bit / 8;
        let bit_offset = (bit % 8) as u16;
        out[byte_index] |= ((digit << bit_offset) & 0xff) as u8;
        let carry = digit >> (8 - bit_offset);
        match out.get_mut(byte_index + 1) {
            Some(slot) => *slot |= carry as u8,
            None if carry != 0 => return None,
            None => {}
        }
    }
    Some(out)
}

/// XOR-fold `bytes` down to `out_len` bytes — Nix's `compressHash`.
fn compress_hash_xor(bytes: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    for (i, byte) in bytes.iter().enumerate() {
        out[i % out_len] ^= byte;
    }
    out
}

fn base16_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// The Nix store-path hash of a reference-free recursive-SHA256 fixed-output
/// (`source`) store object whose NAR hash is `nar_digest` (52 nix-base32 chars)
/// and whose name is `name`, reproducing Nix's `makeFixedOutputPath` /
/// `makeStorePath`. Returns `None` if `nar_digest` is not a valid nix-base32
/// SHA-256 digest.
///
/// This is what makes a `fixed:r:sha256` narinfo *self-certifying*: the store
/// path is a pure function of the content (its NAR hash) and name, so the
/// broker can confirm a local narinfo's identity without a signature — and Nix
/// derives the same path, so a guest accepts it. Verified against real
/// `nix flake archive` output in the tests.
pub(crate) fn fixed_output_recursive_sha256_store_hash(
    nar_digest: &str,
    name: &str,
) -> Option<String> {
    let hash = nix_base32_decode_sha256(nar_digest)?;
    let inner = format!("source:sha256:{}:/nix/store:{name}", base16_lower(&hash));
    let fingerprint = ring::digest::digest(&ring::digest::SHA256, inner.as_bytes());
    let compressed = compress_hash_xor(fingerprint.as_ref(), NIX_STORE_PATH_HASH_LEN);
    Some(nix_base32_encode(&compressed))
}

impl NixTrustedPublicKey {
    pub fn new(raw: impl Into<String>) -> Result<Self, NixTrustedPublicKeyError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(NixTrustedPublicKeyError::Empty);
        }
        let Some((name, key)) = raw.split_once(':') else {
            return Err(NixTrustedPublicKeyError::MissingSeparator);
        };
        if key.contains(':') {
            return Err(NixTrustedPublicKeyError::TooManySeparators);
        }
        if name.is_empty() {
            return Err(NixTrustedPublicKeyError::EmptyName);
        }
        if key.is_empty() {
            return Err(NixTrustedPublicKeyError::EmptyKey);
        }
        if !name.bytes().all(is_nix_key_name_byte) {
            return Err(NixTrustedPublicKeyError::InvalidNameByte);
        }
        validate_nix_key_base64(key)?;
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|_| NixTrustedPublicKeyError::InvalidBase64Length)?;
        let public_key = public_key
            .try_into()
            .map_err(|_| NixTrustedPublicKeyError::InvalidPublicKeyLength)?;
        let name = name.to_string();
        Ok(Self {
            raw,
            name,
            public_key,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn public_key(&self) -> &[u8; NIX_ED25519_PUBLIC_KEY_LEN] {
        &self.public_key
    }
}

impl NixTrustedPublicKeys {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn from_strings<I, S>(raws: I) -> Result<Self, NixTrustedPublicKeysError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut keys = Vec::new();
        for (index, raw) in raws.into_iter().enumerate() {
            let raw = raw.into();
            let key = NixTrustedPublicKey::new(raw.clone()).map_err(|source| {
                NixTrustedPublicKeysError {
                    index,
                    raw: raw.clone(),
                    source,
                }
            })?;
            if keys
                .iter()
                .any(|existing: &NixTrustedPublicKey| existing.name() == key.name())
            {
                return Err(NixTrustedPublicKeysError {
                    index,
                    raw,
                    source: NixTrustedPublicKeyError::DuplicateName,
                });
            }
            keys.push(key);
        }
        Ok(Self(keys))
    }

    pub fn nix_conf_value(&self) -> String {
        self.0
            .iter()
            .map(NixTrustedPublicKey::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn iter(&self) -> impl Iterator<Item = &NixTrustedPublicKey> {
        self.0.iter()
    }

    pub fn find(&self, name: &str) -> Option<&NixTrustedPublicKey> {
        self.0.iter().find(|key| key.name() == name)
    }
}

impl From<Vec<NixTrustedPublicKey>> for NixTrustedPublicKeys {
    fn from(keys: Vec<NixTrustedPublicKey>) -> Self {
        Self(keys)
    }
}

impl NixTrustedPublicKeysError {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn source(&self) -> &NixTrustedPublicKeyError {
        &self.source
    }
}

fn is_nix_key_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn is_nix_store_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
}

fn is_nix_hash_algorithm_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn is_nix_hash_digest_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
}

fn is_base64_material_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

fn validate_nix_key_base64(value: &str) -> Result<(), NixTrustedPublicKeyError> {
    let bytes = value.as_bytes();
    let first_padding = bytes.iter().position(|byte| *byte == b'=');
    let material = match first_padding {
        Some(index) => {
            let padding_len = bytes.len() - index;
            if padding_len > 2 || bytes[index..].iter().any(|byte| *byte != b'=') {
                return Err(NixTrustedPublicKeyError::InvalidBase64Padding);
            }
            if !bytes.len().is_multiple_of(4) {
                return Err(NixTrustedPublicKeyError::InvalidBase64Length);
            }
            &bytes[..index]
        }
        None => {
            if bytes.len() % 4 == 1 {
                return Err(NixTrustedPublicKeyError::InvalidBase64Length);
            }
            bytes
        }
    };
    if !material.iter().copied().all(is_base64_material_byte) {
        return Err(NixTrustedPublicKeyError::InvalidKeyByte);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
