//! Host-side Nix binary-cache configuration types.

const NIX_STORE_HASH_LEN: usize = 32;
const NIX_STORE_HASH_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

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

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NixNarInfo {
    store_path: NixStorePath,
    nar_file: NixCacheNarFileName,
    nar_hash: NixNarHash,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NixTrustedPublicKey(String);

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
    #[error("trusted public key material contains an invalid base64 byte")]
    InvalidKeyByte,
    #[error("trusted public key base64 padding is invalid")]
    InvalidBase64Padding,
    #[error("trusted public key base64 length is invalid")]
    InvalidBase64Length,
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
}

pub fn parse_narinfo(bytes: &[u8]) -> Result<NixNarInfo, NixNarInfoError> {
    let raw = std::str::from_utf8(bytes).map_err(|_| NixNarInfoError::InvalidUtf8)?;
    let mut store_path = None;
    let mut url = None;
    let mut nar_hash = None;
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
    Ok(NixNarInfo {
        store_path,
        nar_file,
        nar_hash,
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
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
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
            let key = NixTrustedPublicKey::new(raw.clone())
                .map_err(|source| NixTrustedPublicKeysError { index, raw, source })?;
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
    }

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
            Just("Sig"),
            Just("Deriver"),
            Just("References"),
            Just("FileHash"),
            Just("FileSize"),
            Just("Compression"),
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
        ]
    }

    fn different_hash(hash: &str) -> String {
        let mut bytes = hash.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).unwrap()
    }

    fn narinfo_body(hash: &str, name: &str, file: &str, nar_hash: &str) -> String {
        format!("StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\n")
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
                format!("URL: nar/{file}\nNarHash: {nar_hash}\n")
            }
            NarInfoMutation::DuplicateStorePath => format!(
                "StorePath: /nix/store/{hash}-{name}\nStorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\n"
            ),
            NarInfoMutation::WrongStoreHash => {
                let wrong = different_hash(hash);
                narinfo_body(&wrong, name, file, nar_hash)
            }
            NarInfoMutation::BadStorePathPrefix => {
                format!(
                    "StorePath: /bad/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\n"
                )
            }
            NarInfoMutation::BadStorePathName => {
                format!(
                    "StorePath: /nix/store/{hash}-{name}:bad\nURL: nar/{file}\nNarHash: {nar_hash}\n"
                )
            }
            NarInfoMutation::MissingUrl => {
                format!("StorePath: /nix/store/{hash}-{name}\nNarHash: {nar_hash}\n")
            }
            NarInfoMutation::DuplicateUrl => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nURL: nar/{file}\nNarHash: {nar_hash}\n"
            ),
            NarInfoMutation::UnsafeUrl => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/subdir/{file}\nNarHash: {nar_hash}\n"
            ),
            NarInfoMutation::MissingNarHash => {
                format!("StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\n")
            }
            NarInfoMutation::DuplicateNarHash => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarHash: {nar_hash}\n"
            ),
            NarInfoMutation::MalformedNarHash => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: sha256:{}:extra\n",
                nar_hash_digest(nar_hash),
            ),
            NarInfoMutation::EmptyNarHashAlgorithm => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: :{}\n",
                nar_hash_digest(nar_hash),
            ),
            NarInfoMutation::BadNarHashAlgorithm => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: SHA256:{}\n",
                nar_hash_digest(nar_hash),
            ),
            NarInfoMutation::BadNarHashDigest => format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}@\n"
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

    fn valid_base64_key_material() -> impl Strategy<Value = String> {
        let alphabet = prop_oneof![
            b'a'..=b'z',
            b'A'..=b'Z',
            b'0'..=b'9',
            Just(b'+'),
            Just(b'/'),
        ];
        (1usize..16, 0usize..=2).prop_flat_map(move |(groups, padding)| {
            let material_len = groups * 4 - padding;
            prop::collection::vec(alphabet.clone(), material_len..=material_len).prop_map(
                move |mut bytes| {
                    bytes.extend(std::iter::repeat_n(b'=', padding));
                    String::from_utf8(bytes).unwrap()
                },
            )
        })
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
                "{}Sig: cache.example:abc:def\nDeriver: /nix/store/00000000000000000000000000000000-proof:drv\nReferences: aaa bbb:ccc\nStorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\n{}",
                before.concat(),
                after.concat(),
            );

            let expected_hash = NixStoreHashPart::new(hash.clone()).unwrap();
            let parsed = parse_narinfo_for_store_hash(raw.as_bytes(), &expected_hash).unwrap();

            prop_assert_eq!(parsed.store_path().as_str(), format!("/nix/store/{hash}-{name}"));
            prop_assert_eq!(parsed.store_path().hash().as_str(), hash.as_str());
            prop_assert_eq!(parsed.nar_file().as_str(), file.as_str());
            prop_assert_eq!(parsed.nar_hash().as_str(), nar_hash.as_str());
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
            key in valid_base64_key_material(),
        ) {
            let raw = format!("{name}:{key}");
            let parsed = NixTrustedPublicKey::new(raw.clone()).unwrap();
            prop_assert_eq!(parsed.as_str(), raw);
        }

        #[test]
        fn invalid_name_bytes_are_rejected(
            name in valid_key_name(),
            key in valid_base64_key_material(),
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
            key in valid_base64_key_material(),
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
            first_key in valid_base64_key_material(),
            second_name in valid_key_name(),
            second_key in valid_base64_key_material(),
        ) {
            let first = format!("{first_name}:{first_key}");
            let second = format!("{second_name}:{second_key}");
            let keys = NixTrustedPublicKeys::from_strings([first.clone(), second.clone()]).unwrap();
            prop_assert_eq!(keys.nix_conf_value(), format!("{first} {second}"));
        }
    }

    #[test]
    fn malformed_narinfo_urls_are_rejected() {
        let prefix = "StorePath: /nix/store/00000000000000000000000000000000-proof\n";
        let suffix = "NarHash: sha256:0\n";
        let cases = vec![
            (
                "URL: nar/proof.nar\nNarHash: sha256:0\n".to_string(),
                NixNarInfoError::MissingStorePath,
            ),
            (
                "StorePath: \nURL: nar/proof.nar\nNarHash: sha256:0\n".to_string(),
                NixNarInfoError::EmptyStorePath,
            ),
            (
                "StorePath: /nix/store/x\nURL: nar/proof.nar\nNarHash: sha256:0\n".to_string(),
                NixNarInfoError::InvalidStorePath {
                    raw: "/nix/store/x".into(),
                    source: NixStorePathError::MissingNameSeparator,
                },
            ),
            (
                "StorePath: /nix/store/00000000000000000000000000000000-proof\nStorePath: /nix/store/00000000000000000000000000000000-proof\nURL: nar/proof.nar\nNarHash: sha256:0\n".to_string(),
                NixNarInfoError::DuplicateStorePath,
            ),
            (
                "StorePath: /nix/store/00000000000000000000000000000000-proof\nNarHash: sha256:0\n".to_string(),
                NixNarInfoError::MissingUrl,
            ),
            (
                "StorePath: /nix/store/00000000000000000000000000000000-proof\nURL: \nNarHash: sha256:0\n".to_string(),
                NixNarInfoError::EmptyUrl,
            ),
            (
                "URL: nar/proof.nar\nURL: nar/other.nar\n".to_string(),
                NixNarInfoError::DuplicateUrl,
            ),
            (
                "StorePath: /nix/store/00000000000000000000000000000000-proof\nURL: nar/proof.nar\n".to_string(),
                NixNarInfoError::MissingNarHash,
            ),
            (
                "StorePath: /nix/store/00000000000000000000000000000000-proof\nURL: nar/proof.nar\nNarHash: \n".to_string(),
                NixNarInfoError::EmptyNarHash,
            ),
            (
                "StorePath: /nix/store/00000000000000000000000000000000-proof\nURL: nar/proof.nar\nNarHash: sha256:0\nNarHash: sha256:0\n".to_string(),
                NixNarInfoError::DuplicateNarHash,
            ),
            (
                "StorePath: /nix/store/00000000000000000000000000000000-proof\nURL: nar/proof.nar\nNarHash: sha256:0:extra\n".to_string(),
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
        ];

        for (raw, expected) in cases {
            assert_eq!(NixTrustedPublicKey::new(raw), Err(expected), "{raw:?}");
        }
    }

    #[test]
    fn trusted_public_keys_error_reports_index_and_raw_value() {
        let err =
            NixTrustedPublicKeys::from_strings(["cache.example-1:QUJDRA==", "bad key:QUJDRA=="])
                .unwrap_err();

        assert_eq!(err.index(), 1);
        assert_eq!(err.raw(), "bad key:QUJDRA==");
        assert_eq!(err.source(), &NixTrustedPublicKeyError::InvalidNameByte);
    }
}
