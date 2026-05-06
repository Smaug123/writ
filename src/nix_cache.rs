//! Host-side Nix binary-cache configuration types.

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
#[error("Nix trusted public key at index {index} {raw:?} is invalid: {source}")]
pub struct NixTrustedPublicKeysError {
    index: usize,
    raw: String,
    source: NixTrustedPublicKeyError,
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
