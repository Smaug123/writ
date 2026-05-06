//! Host-side Nix binary-cache configuration types.

use base64::Engine as _;

const NIX_STORE_HASH_LEN: usize = 32;
const NIX_STORE_HASH_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
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
pub enum NixNarSizeError {
    #[error("NarSize must contain only decimal digits")]
    InvalidByte,
    #[error("NarSize must be canonical decimal without leading zeroes")]
    LeadingZero,
    #[error("NarSize does not fit in u64")]
    Overflow,
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
    #[error("narinfo is missing References")]
    MissingReferences,
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

pub fn parse_narinfo(bytes: &[u8]) -> Result<NixNarInfo, NixNarInfoError> {
    let raw = std::str::from_utf8(bytes).map_err(|_| NixNarInfoError::InvalidUtf8)?;
    let mut store_path = None;
    let mut url = None;
    let mut nar_hash = None;
    let mut nar_size = None;
    let mut references = None;
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
            _ => {}
        }
    }
    let store_path = store_path.ok_or(NixNarInfoError::MissingStorePath)?;
    let store_path =
        NixStorePath::new(store_path).map_err(|source| NixNarInfoError::InvalidStorePath {
            raw: store_path.to_string(),
            source,
        })?;
    let url = url.ok_or(NixNarInfoError::MissingUrl)?;
    let Some(file) = url.strip_prefix("nar/") else {
        return Err(NixNarInfoError::UnsupportedUrl(url.to_string()));
    };
    let nar_file =
        NixCacheNarFileName::new(file).map_err(|source| NixNarInfoError::InvalidNarFile {
            url: url.to_string(),
            source,
        })?;
    let nar_hash = nar_hash.ok_or(NixNarInfoError::MissingNarHash)?;
    let nar_hash = NixNarHash::new(nar_hash).map_err(|source| NixNarInfoError::InvalidNarHash {
        raw: nar_hash.to_string(),
        source,
    })?;
    let nar_size = nar_size.ok_or(NixNarInfoError::MissingNarSize)?;
    let nar_size = NixNarSize::new(nar_size).map_err(|source| NixNarInfoError::InvalidNarSize {
        raw: nar_size.to_string(),
        source,
    })?;
    let references = references.ok_or(NixNarInfoError::MissingReferences)?;
    let references =
        NixNarReferences::new(references).map_err(|source| NixNarInfoError::InvalidReferences {
            raw: references.to_string(),
            source,
        })?;
    if signatures.is_empty() {
        return Err(NixNarInfoError::MissingSignature);
    }
    Ok(NixNarInfo {
        store_path,
        nar_file,
        nar_hash,
        nar_size,
        references,
        signatures,
    })
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
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[derive(Copy, Clone, Debug)]
    enum NarInfoMutation {
        MissingStorePath,
        DuplicateStorePath,
        WrongStoreHash,
        BadStorePathPrefix,
        BadStorePathName,
        MissingUrl,
        DuplicateUrl,
        UnsafeUrl,
        MissingNarHash,
        DuplicateNarHash,
        MalformedNarHash,
        EmptyNarHashAlgorithm,
        BadNarHashAlgorithm,
        BadNarHashDigest,
        MissingNarSize,
        DuplicateNarSize,
        EmptyNarSize,
        BadNarSize,
        MissingReferences,
        DuplicateReferences,
        BadReferences,
        MissingSignature,
        BadSignature,
    }

    const TEST_PUBLIC_KEY: &str = "cache.example:IsGkyTbr2sed7tWowgiPcI0ZHhBAHoGQ7TyYRweyzwE=";
    const TEST_SIGNATURE: &str = "cache.example:ioaqsTngbhwHmkI+4GKXEkuV0WvrIQ0+SUVlVvIix5A7h31h6oE5hpQbq/rGvH10QLVtYm82sdIM3e2SBGqMAA==";
    const TEST_SIGNED_NARINFO: &str = concat!(
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
    const TEST_REFS_PUBLIC_KEY: &str = "cache.refs:BHW8e1tReqeVluuat3LaQIoeVPa7g2+8My8XCqqN1is=";
    const TEST_REFS_SIGNED_NARINFO: &str = concat!(
        "StorePath: /nix/store/9z4l1xiz8325yqi8f8q5ls6jv7jzaqam-root.txt\n",
        "URL: nar/1pfjl5iww7b44zgwajhlafpzm51i07f7lklksqj676dk3qjbwgaz.nar.xz\n",
        "Compression: xz\n",
        "FileHash: sha256:1pfjl5iww7b44zgwajhlafpzm51i07f7lklksqj676dk3qjbwgaz\n",
        "FileSize: 208\n",
        "NarHash: sha256:1m7hc9pwbk762qsf5yrv2nadbvr9lhzb76f3qia2a9x0gpxjbvm3\n",
        "NarSize: 216\n",
        "References: sx5305c45zn199v0gv0x7vnh3z9q658x-b.txt z2gxprmwxdfyrb4rka1629bvxxa429ga-a.txt\n",
        "Sig: cache.refs:9Cd6wxkYijT02Ik4HooBeoTA7asg4pv5aa0lV+BfA/XoJs1qycPUmHle3JE5NgEDUD5wuTBST3VcXzgj3NcvAg==\n",
        "CA: text:sha256:1a778zsfa68nz0220y8z93xnw4c1pbfwkk2kbwd2xas0qj3l467v\n",
    );

    fn valid_store_hash_part() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop::sample::select(NIX_STORE_HASH_ALPHABET.to_vec()),
            NIX_STORE_HASH_LEN..=NIX_STORE_HASH_LEN,
        )
        .prop_map(|bytes| String::from_utf8(bytes).unwrap())
    }

    fn valid_store_name() -> impl Strategy<Value = String> {
        let first = prop_oneof![b'a'..=b'z', b'A'..=b'Z', b'0'..=b'9', Just(b'_'),];
        let rest = prop::collection::vec(
            prop_oneof![
                b'a'..=b'z',
                b'A'..=b'Z',
                b'0'..=b'9',
                Just(b'+'),
                Just(b'-'),
                Just(b'.'),
                Just(b'_'),
                Just(b'?'),
                Just(b'='),
            ],
            0..80,
        );
        (first, rest).prop_map(|(first, rest)| {
            let mut bytes = Vec::with_capacity(1 + rest.len());
            bytes.push(first);
            bytes.extend(rest);
            String::from_utf8(bytes).unwrap()
        })
    }

    fn valid_nar_file_name() -> impl Strategy<Value = String> {
        let first = prop_oneof![b'a'..=b'z', b'A'..=b'Z', b'0'..=b'9', Just(b'_'),];
        let rest = prop::collection::vec(
            prop_oneof![
                b'a'..=b'z',
                b'A'..=b'Z',
                b'0'..=b'9',
                Just(b'-'),
                Just(b'.'),
                Just(b'_'),
                Just(b'+'),
            ],
            0..80,
        );
        (first, rest).prop_map(|(first, rest)| {
            let mut bytes = Vec::with_capacity(1 + rest.len());
            bytes.push(first);
            bytes.extend(rest);
            if bytes.last() == Some(&b'.') {
                *bytes.last_mut().unwrap() = b'x';
            }
            String::from_utf8(bytes).unwrap()
        })
    }

    fn valid_nar_hash() -> impl Strategy<Value = String> {
        let digest = prop::collection::vec(
            prop_oneof![
                b'a'..=b'z',
                b'A'..=b'Z',
                b'0'..=b'9',
                Just(b'+'),
                Just(b'/'),
                Just(b'='),
                Just(b'-'),
                Just(b'_'),
            ],
            1..80,
        );
        digest.prop_map(|digest| format!("sha256:{}", String::from_utf8(digest).unwrap()))
    }

    fn narinfo_non_semantic_field() -> impl Strategy<Value = String> {
        let name = prop_oneof![
            Just("Deriver"),
            Just("FileHash"),
            Just("FileSize"),
            Just("Compression"),
            Just("CA"),
        ];
        let value = prop::collection::vec(
            prop_oneof![
                b'a'..=b'z',
                b'A'..=b'Z',
                b'0'..=b'9',
                Just(b' '),
                Just(b':'),
                Just(b'/'),
                Just(b'.'),
                Just(b'-'),
                Just(b'_'),
                Just(b'='),
            ],
            0..80,
        );
        (name, value)
            .prop_map(|(name, value)| format!("{name}: {}\n", String::from_utf8(value).unwrap()))
    }

    fn narinfo_mutation() -> impl Strategy<Value = NarInfoMutation> {
        prop_oneof![
            Just(NarInfoMutation::MissingStorePath),
            Just(NarInfoMutation::DuplicateStorePath),
            Just(NarInfoMutation::WrongStoreHash),
            Just(NarInfoMutation::BadStorePathPrefix),
            Just(NarInfoMutation::BadStorePathName),
            Just(NarInfoMutation::MissingUrl),
            Just(NarInfoMutation::DuplicateUrl),
            Just(NarInfoMutation::UnsafeUrl),
            Just(NarInfoMutation::MissingNarHash),
            Just(NarInfoMutation::DuplicateNarHash),
            Just(NarInfoMutation::MalformedNarHash),
            Just(NarInfoMutation::EmptyNarHashAlgorithm),
            Just(NarInfoMutation::BadNarHashAlgorithm),
            Just(NarInfoMutation::BadNarHashDigest),
            Just(NarInfoMutation::MissingNarSize),
            Just(NarInfoMutation::DuplicateNarSize),
            Just(NarInfoMutation::EmptyNarSize),
            Just(NarInfoMutation::BadNarSize),
            Just(NarInfoMutation::MissingReferences),
            Just(NarInfoMutation::DuplicateReferences),
            Just(NarInfoMutation::BadReferences),
            Just(NarInfoMutation::MissingSignature),
            Just(NarInfoMutation::BadSignature),
        ]
    }

    fn different_hash(hash: &str) -> String {
        let mut bytes = hash.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).unwrap()
    }

    fn narinfo_body(hash: &str, name: &str, file: &str, nar_hash: &str) -> String {
        format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
        )
    }

    fn nar_hash_digest(nar_hash: &str) -> &str {
        nar_hash
            .split_once(':')
            .expect("valid_nar_hash always includes algorithm separator")
            .1
    }

    fn mutated_narinfo_body(
        mutation: NarInfoMutation,
        hash: &str,
        name: &str,
        file: &str,
        nar_hash: &str,
    ) -> String {
        match mutation {
            NarInfoMutation::MissingStorePath => {
                format!(
                    "URL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
                )
            }
            NarInfoMutation::DuplicateStorePath => format!(
                "StorePath: /nix/store/{hash}-{name}\nStorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NarInfoMutation::WrongStoreHash => {
                let wrong = different_hash(hash);
                narinfo_body(&wrong, name, file, nar_hash)
            }
            NarInfoMutation::BadStorePathPrefix => {
                format!(
                    "StorePath: /bad/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
                )
            }
            NarInfoMutation::BadStorePathName => {
                format!(
                    "StorePath: /nix/store/{hash}-{name}:bad\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
                )
            }
            NarInfoMutation::MissingUrl => {
                format!(
                    "StorePath: /nix/store/{hash}-{name}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
                )
            }
            NarInfoMutation::DuplicateUrl => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NarInfoMutation::UnsafeUrl => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/subdir/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NarInfoMutation::MissingNarHash => {
                format!(
                    "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
                )
            }
            NarInfoMutation::DuplicateNarHash => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NarInfoMutation::MalformedNarHash => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: sha256:{}:extra\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n",
                nar_hash_digest(nar_hash),
            ),
            NarInfoMutation::EmptyNarHashAlgorithm => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: :{}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n",
                nar_hash_digest(nar_hash),
            ),
            NarInfoMutation::BadNarHashAlgorithm => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: SHA256:{}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n",
                nar_hash_digest(nar_hash),
            ),
            NarInfoMutation::BadNarHashDigest => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}@\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NarInfoMutation::MissingNarSize => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NarInfoMutation::DuplicateNarSize => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NarInfoMutation::EmptyNarSize => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: \nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NarInfoMutation::BadNarSize => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 0120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NarInfoMutation::MissingReferences => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nSig: {TEST_SIGNATURE}\n"
            ),
            NarInfoMutation::DuplicateReferences => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NarInfoMutation::BadReferences => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: bad/reference\nSig: {TEST_SIGNATURE}\n"
            ),
            NarInfoMutation::MissingSignature => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \n"
            ),
            NarInfoMutation::BadSignature => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: bad signature\n"
            ),
        }
    }

    fn expected_mutation_error(
        mutation: NarInfoMutation,
        hash: &str,
        name: &str,
        file: &str,
        nar_hash: &str,
    ) -> NixNarInfoError {
        match mutation {
            NarInfoMutation::MissingStorePath => NixNarInfoError::MissingStorePath,
            NarInfoMutation::DuplicateStorePath => NixNarInfoError::DuplicateStorePath,
            NarInfoMutation::WrongStoreHash => NixNarInfoError::StorePathHashMismatch {
                expected: NixStoreHashPart::new(hash).unwrap(),
                actual: NixStoreHashPart::new(different_hash(hash)).unwrap(),
            },
            NarInfoMutation::BadStorePathPrefix => NixNarInfoError::InvalidStorePath {
                raw: format!("/bad/store/{hash}-{name}"),
                source: NixStorePathError::MissingStorePrefix,
            },
            NarInfoMutation::BadStorePathName => NixNarInfoError::InvalidStorePath {
                raw: format!("/nix/store/{hash}-{name}:bad"),
                source: NixStorePathError::InvalidNameByte,
            },
            NarInfoMutation::MissingUrl => NixNarInfoError::MissingUrl,
            NarInfoMutation::DuplicateUrl => NixNarInfoError::DuplicateUrl,
            NarInfoMutation::UnsafeUrl => NixNarInfoError::InvalidNarFile {
                url: format!("nar/subdir/{file}"),
                source: NixCacheNarFileNameError::Slash,
            },
            NarInfoMutation::MissingNarHash => NixNarInfoError::MissingNarHash,
            NarInfoMutation::DuplicateNarHash => NixNarInfoError::DuplicateNarHash,
            NarInfoMutation::MalformedNarHash => NixNarInfoError::InvalidNarHash {
                raw: format!("sha256:{}:extra", nar_hash_digest(nar_hash)),
                source: NixNarHashError::TooManySeparators,
            },
            NarInfoMutation::EmptyNarHashAlgorithm => NixNarInfoError::InvalidNarHash {
                raw: format!(":{}", nar_hash_digest(nar_hash)),
                source: NixNarHashError::EmptyAlgorithm,
            },
            NarInfoMutation::BadNarHashAlgorithm => NixNarInfoError::InvalidNarHash {
                raw: format!("SHA256:{}", nar_hash_digest(nar_hash)),
                source: NixNarHashError::InvalidAlgorithmByte,
            },
            NarInfoMutation::BadNarHashDigest => NixNarInfoError::InvalidNarHash {
                raw: format!("{nar_hash}@"),
                source: NixNarHashError::InvalidDigestByte,
            },
            NarInfoMutation::MissingNarSize => NixNarInfoError::MissingNarSize,
            NarInfoMutation::DuplicateNarSize => NixNarInfoError::DuplicateNarSize,
            NarInfoMutation::EmptyNarSize => NixNarInfoError::EmptyNarSize,
            NarInfoMutation::BadNarSize => NixNarInfoError::InvalidNarSize {
                raw: "0120".into(),
                source: NixNarSizeError::LeadingZero,
            },
            NarInfoMutation::MissingReferences => NixNarInfoError::MissingReferences,
            NarInfoMutation::DuplicateReferences => NixNarInfoError::DuplicateReferences,
            NarInfoMutation::BadReferences => NixNarInfoError::InvalidReferences {
                raw: "bad/reference".into(),
                source: NixNarReferencesError::InvalidReference {
                    raw: "bad/reference".into(),
                    source: NixStorePathError::NestedPathSegment,
                },
            },
            NarInfoMutation::MissingSignature => NixNarInfoError::MissingSignature,
            NarInfoMutation::BadSignature => NixNarInfoError::InvalidSignature {
                raw: "bad signature".into(),
                source: NixNarSignatureError::MissingSeparator,
            },
        }
    }

    fn valid_key_name() -> impl Strategy<Value = String> {
        let first = prop_oneof![b'a'..=b'z', b'A'..=b'Z', b'0'..=b'9',];
        let rest = prop::collection::vec(
            prop_oneof![
                b'a'..=b'z',
                b'A'..=b'Z',
                b'0'..=b'9',
                Just(b'-'),
                Just(b'.'),
                Just(b'_'),
                Just(b'~'),
            ],
            0..32,
        );
        (first, rest).prop_map(|(first, rest)| {
            let mut bytes = Vec::with_capacity(1 + rest.len());
            bytes.push(first);
            bytes.extend(rest);
            String::from_utf8(bytes).unwrap()
        })
    }

    fn valid_public_key_material() -> impl Strategy<Value = String> {
        prop::collection::vec(
            any::<u8>(),
            NIX_ED25519_PUBLIC_KEY_LEN..=NIX_ED25519_PUBLIC_KEY_LEN,
        )
        .prop_map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    fn invalid_name_char() -> impl Strategy<Value = char> {
        any::<char>().prop_filter("invalid Nix key name character", |ch| {
            !ch.is_ascii_alphanumeric() && !matches!(*ch, '-' | '.' | '_' | '~' | ':')
        })
    }

    fn invalid_base64_char() -> impl Strategy<Value = char> {
        prop_oneof![
            Just('-'),
            Just('_'),
            Just('.'),
            Just(' '),
            Just('\n'),
            Just('@'),
        ]
    }

    proptest! {
        #[test]
        fn valid_narinfo_parse_amid_arbitrary_other_fields(
            hash in valid_store_hash_part(),
            name in valid_store_name(),
            file in valid_nar_file_name(),
            nar_hash in valid_nar_hash(),
            before in prop::collection::vec(narinfo_non_semantic_field(), 0..8),
            after in prop::collection::vec(narinfo_non_semantic_field(), 0..8),
        ) {
            let raw = format!(
                "{}Deriver: /nix/store/00000000000000000000000000000000-proof:drv\nStorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n{}",
                before.concat(),
                after.concat(),
            );

            let expected_hash = NixStoreHashPart::new(hash.clone()).unwrap();
            let parsed = parse_narinfo_for_store_hash(raw.as_bytes(), &expected_hash).unwrap();

            prop_assert_eq!(parsed.store_path().as_str(), format!("/nix/store/{hash}-{name}"));
            prop_assert_eq!(parsed.store_path().hash().as_str(), hash.as_str());
            prop_assert_eq!(parsed.nar_file().as_str(), file.as_str());
            prop_assert_eq!(parsed.nar_hash().as_str(), nar_hash.as_str());
            prop_assert_eq!(parsed.nar_size().get(), 120);
        }

        #[test]
        fn mutated_load_bearing_narinfo_fields_are_rejected(
            hash in valid_store_hash_part(),
            name in valid_store_name(),
            file in valid_nar_file_name(),
            nar_hash in valid_nar_hash(),
            mutation in narinfo_mutation(),
        ) {
            let expected_hash = NixStoreHashPart::new(hash.clone()).unwrap();
            let raw = mutated_narinfo_body(mutation, &hash, &name, &file, &nar_hash);
            let expected = expected_mutation_error(mutation, &hash, &name, &file, &nar_hash);

            prop_assert_eq!(
                parse_narinfo_for_store_hash(raw.as_bytes(), &expected_hash),
                Err(expected),
                "mutation {:?} produced the wrong result for {:?}",
                mutation,
                raw,
            );
        }

        #[test]
        fn narinfo_parser_is_total_for_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let _ = parse_narinfo(&bytes);
        }

        #[test]
        fn generated_valid_trusted_public_keys_parse(
            name in valid_key_name(),
            key in valid_public_key_material(),
        ) {
            let raw = format!("{name}:{key}");
            let parsed = NixTrustedPublicKey::new(raw.clone()).unwrap();
            prop_assert_eq!(parsed.as_str(), raw);
            prop_assert_eq!(parsed.name(), name.as_str());
        }

        #[test]
        fn invalid_name_bytes_are_rejected(
            name in valid_key_name(),
            key in valid_public_key_material(),
            bad in invalid_name_char(),
        ) {
            let raw = format!("{name}{bad}:{key}");
            prop_assert_eq!(
                NixTrustedPublicKey::new(raw),
                Err(NixTrustedPublicKeyError::InvalidNameByte)
            );
        }

        #[test]
        fn invalid_base64_material_bytes_are_rejected(
            name in valid_key_name(),
            key in valid_public_key_material(),
            bad in invalid_base64_char(),
        ) {
            let mut key = key.into_bytes();
            key[0] = bad as u8;
            let key = String::from_utf8(key).unwrap();
            let raw = format!("{name}:{key}");
            prop_assert_eq!(
                NixTrustedPublicKey::new(raw),
                Err(NixTrustedPublicKeyError::InvalidKeyByte)
            );
        }

        #[test]
        fn trusted_public_keys_join_as_nix_conf_value(
            first_name in valid_key_name(),
            first_key in valid_public_key_material(),
            second_key in valid_public_key_material(),
        ) {
            let second_name = format!("{first_name}-other");
            let first = format!("{first_name}:{first_key}");
            let second = format!("{second_name}:{second_key}");
            let keys = NixTrustedPublicKeys::from_strings([first.clone(), second.clone()]).unwrap();
            prop_assert_eq!(keys.nix_conf_value(), format!("{first} {second}"));
        }
    }

    #[test]
    fn nix_generated_signed_narinfo_verifies_with_trusted_key() {
        let expected_hash = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
        let keys = NixTrustedPublicKeys::from_strings([TEST_PUBLIC_KEY]).unwrap();

        let parsed = parse_signed_narinfo_for_store_hash(
            TEST_SIGNED_NARINFO.as_bytes(),
            &expected_hash,
            &keys,
        )
        .unwrap();

        assert_eq!(parsed.nar_size().get(), 120);
        assert_eq!(parsed.references().iter().count(), 0);
        assert_eq!(parsed.signatures()[0].key_name(), "cache.example");
    }

    #[test]
    fn nix_generated_signed_narinfo_verifies_non_empty_references() {
        let expected_hash = NixStoreHashPart::new("9z4l1xiz8325yqi8f8q5ls6jv7jzaqam").unwrap();
        let keys = NixTrustedPublicKeys::from_strings([TEST_REFS_PUBLIC_KEY]).unwrap();

        let parsed = parse_signed_narinfo_for_store_hash(
            TEST_REFS_SIGNED_NARINFO.as_bytes(),
            &expected_hash,
            &keys,
        )
        .unwrap();

        let references = parsed
            .references()
            .iter()
            .map(NixStorePath::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            references,
            vec![
                "/nix/store/sx5305c45zn199v0gv0x7vnh3z9q658x-b.txt",
                "/nix/store/z2gxprmwxdfyrb4rka1629bvxxa429ga-a.txt",
            ],
        );
        assert_eq!(parsed.nar_size().get(), 216);
        assert_eq!(parsed.signatures()[0].key_name(), "cache.refs");
    }

    #[test]
    fn signed_narinfo_rejects_mutated_signed_fields() {
        let expected_hash = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
        let keys = NixTrustedPublicKeys::from_strings([TEST_PUBLIC_KEY]).unwrap();
        for mutated in [
            TEST_SIGNED_NARINFO.replace("NarSize: 120\n", "NarSize: 121\n"),
            TEST_SIGNED_NARINFO.replace(
                "NarHash: sha256:0n62ny3wh4ayp887m60r6ja1p7hrdqnlaq2avb1177zc5gmm6nny\n",
                "NarHash: sha256:1n62ny3wh4ayp887m60r6ja1p7hrdqnlaq2avb1177zc5gmm6nny\n",
            ),
            TEST_SIGNED_NARINFO.replace(
                "References: \n",
                "References: rzv95bakh41zrn5ji23pfc11x5vq2z4d-src\n",
            ),
        ] {
            assert_eq!(
                parse_signed_narinfo_for_store_hash(mutated.as_bytes(), &expected_hash, &keys),
                Err(NixNarInfoError::SignatureMismatch),
                "{mutated:?}",
            );
        }
    }

    #[test]
    fn signed_narinfo_requires_a_configured_trusted_key() {
        let expected_hash = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
        let keys = NixTrustedPublicKeys::empty();

        assert_eq!(
            parse_signed_narinfo_for_store_hash(
                TEST_SIGNED_NARINFO.as_bytes(),
                &expected_hash,
                &keys
            ),
            Err(NixNarInfoError::UntrustedSignatureKey),
        );
    }

    #[test]
    fn malformed_narinfo_urls_are_rejected() {
        let prefix = "StorePath: /nix/store/00000000000000000000000000000000-proof\n";
        let suffix =
            format!("NarHash: sha256:0\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n");
        let cases = vec![
            (
                format!("URL: nar/proof.nar\n{suffix}"),
                NixNarInfoError::MissingStorePath,
            ),
            (
                format!("StorePath: \nURL: nar/proof.nar\n{suffix}"),
                NixNarInfoError::EmptyStorePath,
            ),
            (
                format!("StorePath: /nix/store/x\nURL: nar/proof.nar\n{suffix}"),
                NixNarInfoError::InvalidStorePath {
                    raw: "/nix/store/x".into(),
                    source: NixStorePathError::MissingNameSeparator,
                },
            ),
            (
                format!(
                    "{prefix}StorePath: /nix/store/00000000000000000000000000000000-proof\nURL: nar/proof.nar\n{suffix}"
                ),
                NixNarInfoError::DuplicateStorePath,
            ),
            (format!("{prefix}{suffix}"), NixNarInfoError::MissingUrl),
            (
                format!("{prefix}URL: \n{suffix}"),
                NixNarInfoError::EmptyUrl,
            ),
            (
                "URL: nar/proof.nar\nURL: nar/other.nar\n".to_string(),
                NixNarInfoError::DuplicateUrl,
            ),
            (
                format!(
                    "{prefix}URL: nar/proof.nar\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
                ),
                NixNarInfoError::MissingNarHash,
            ),
            (
                format!(
                    "{prefix}URL: nar/proof.nar\nNarHash: \nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
                ),
                NixNarInfoError::EmptyNarHash,
            ),
            (
                format!(
                    "{prefix}URL: nar/proof.nar\nNarHash: sha256:0\nNarHash: sha256:0\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
                ),
                NixNarInfoError::DuplicateNarHash,
            ),
            (
                format!(
                    "{prefix}URL: nar/proof.nar\nNarHash: sha256:0:extra\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
                ),
                NixNarInfoError::InvalidNarHash {
                    raw: "sha256:0:extra".into(),
                    source: NixNarHashError::TooManySeparators,
                },
            ),
            (
                format!("{prefix}URL: https://cache.example/nar/proof.nar\n{suffix}"),
                NixNarInfoError::UnsupportedUrl("https://cache.example/nar/proof.nar".into()),
            ),
            (
                format!("{prefix}URL: ../proof.nar\n{suffix}"),
                NixNarInfoError::UnsupportedUrl("../proof.nar".into()),
            ),
            (
                format!("{prefix}URL: nar/subdir/proof.nar\n{suffix}"),
                NixNarInfoError::InvalidNarFile {
                    url: "nar/subdir/proof.nar".into(),
                    source: NixCacheNarFileNameError::Slash,
                },
            ),
            (
                format!("{prefix}URL: nar/proof.nar?download=1\n{suffix}"),
                NixNarInfoError::InvalidNarFile {
                    url: "nar/proof.nar?download=1".into(),
                    source: NixCacheNarFileNameError::InvalidByte,
                },
            ),
            (
                format!("{prefix}URL: nar/.proof.nar\n{suffix}"),
                NixNarInfoError::InvalidNarFile {
                    url: "nar/.proof.nar".into(),
                    source: NixCacheNarFileNameError::DotBoundary,
                },
            ),
            (
                format!("{prefix}URL: nar/proof.nar.\n{suffix}"),
                NixNarInfoError::InvalidNarFile {
                    url: "nar/proof.nar.".into(),
                    source: NixCacheNarFileNameError::DotBoundary,
                },
            ),
            (
                format!("{prefix}URL: /nar/proof.nar\n{suffix}"),
                NixNarInfoError::UnsupportedUrl("/nar/proof.nar".into()),
            ),
        ];

        for (raw, expected) in cases {
            assert_eq!(parse_narinfo(raw.as_bytes()), Err(expected), "{raw:?}");
        }
    }

    #[test]
    fn malformed_trusted_public_keys_are_rejected() {
        let cases = [
            ("", NixTrustedPublicKeyError::Empty),
            ("cache-key", NixTrustedPublicKeyError::MissingSeparator),
            (":QUJDRA==", NixTrustedPublicKeyError::EmptyName),
            ("cache.example-1:", NixTrustedPublicKeyError::EmptyKey),
            (
                "cache.example-1:QUJDRA==:extra",
                NixTrustedPublicKeyError::TooManySeparators,
            ),
            (
                "cache example-1:QUJDRA==",
                NixTrustedPublicKeyError::InvalidNameByte,
            ),
            (
                "cache.example-1:QUJDRA==\n",
                NixTrustedPublicKeyError::InvalidBase64Padding,
            ),
            (
                "cache.example-1:QUJDRA===",
                NixTrustedPublicKeyError::InvalidBase64Padding,
            ),
            (
                "cache.example-1:abcde",
                NixTrustedPublicKeyError::InvalidBase64Length,
            ),
            (
                "cache.example-1:QUJDRA==",
                NixTrustedPublicKeyError::InvalidPublicKeyLength,
            ),
        ];

        for (raw, expected) in cases {
            assert_eq!(NixTrustedPublicKey::new(raw), Err(expected), "{raw:?}");
        }
    }

    #[test]
    fn trusted_public_keys_error_reports_index_and_raw_value() {
        let valid_material = TEST_PUBLIC_KEY.split_once(':').unwrap().1;
        let bad_key = format!("bad key:{valid_material}");
        let err =
            NixTrustedPublicKeys::from_strings([TEST_PUBLIC_KEY, bad_key.as_str()]).unwrap_err();

        assert_eq!(err.index(), 1);
        assert_eq!(err.raw(), bad_key);
        assert_eq!(err.source(), &NixTrustedPublicKeyError::InvalidNameByte);
    }

    #[test]
    fn trusted_public_keys_reject_duplicate_names() {
        let first = TEST_PUBLIC_KEY;
        let second = format!(
            "cache.example:{}",
            TEST_REFS_PUBLIC_KEY.split_once(':').unwrap().1
        );

        let err = NixTrustedPublicKeys::from_strings([first, second.as_str()]).unwrap_err();

        assert_eq!(err.index(), 1);
        assert_eq!(err.raw(), second);
        assert_eq!(err.source(), &NixTrustedPublicKeyError::DuplicateName);
    }
}
