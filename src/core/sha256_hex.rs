//! Validated newtype for a SHA-256 digest expressed as 64 lowercase
//! hexadecimal characters.
//!
//! Used wherever the wire carries a hash that a downstream verifier
//! recomputes — most notably `SignedRunMetadata.prompt_sha256` and
//! `SignedRunMetadata.output_envelope_sha256`, the two digests that
//! bailiff (or any third party) re-derives to confirm a writ signature
//! covers the bytes it claims to cover. Constructing the wrapper at
//! the wire boundary means interior code can read `.as_str()` without
//! re-asserting "is this really hex?"
//!
//! Validation is intentionally narrow: 64 chars, all in `[0-9a-f]`.
//! Uppercase is rejected so two equal hashes always render to the same
//! string — picking either case as canonical is arbitrary, but keeping
//! exactly one case prevents accidental "valid signature, mismatched
//! casing" comparisons.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const SHA256_HEX_LEN: usize = 64;

/// A SHA-256 digest as 64 lowercase hex characters. Constructed only
/// via [`Sha256Hex::try_new`] (or its `FromStr` / `Deserialize`
/// equivalents).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    pub fn try_new(s: impl Into<String>) -> Result<Self, Sha256HexError> {
        let s = s.into();
        if s.len() != SHA256_HEX_LEN {
            return Err(Sha256HexError::WrongLength {
                got: s.len(),
                expected: SHA256_HEX_LEN,
            });
        }
        if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(Sha256HexError::NonLowercaseHex);
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for Sha256Hex {
    type Err = Sha256HexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl Serialize for Sha256Hex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Hex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::try_new(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Sha256HexError {
    #[error("sha256 hex must be {expected} characters, got {got}")]
    WrongLength { got: usize, expected: usize },
    #[error("sha256 hex must contain only lowercase [0-9a-f] characters")]
    NonLowercaseHex,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample() -> &'static str {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }

    #[test]
    fn accepts_64_lowercase_hex_chars() {
        let h = Sha256Hex::try_new(sample()).unwrap();
        assert_eq!(h.as_str(), sample());
    }

    #[test]
    fn rejects_short_input() {
        let err = Sha256Hex::try_new("abc").unwrap_err();
        assert_eq!(
            err,
            Sha256HexError::WrongLength {
                got: 3,
                expected: 64
            }
        );
    }

    #[test]
    fn rejects_long_input() {
        let too_long = format!("{}0", sample());
        let err = Sha256Hex::try_new(too_long).unwrap_err();
        assert_eq!(
            err,
            Sha256HexError::WrongLength {
                got: 65,
                expected: 64
            }
        );
    }

    #[test]
    fn rejects_uppercase() {
        let s = sample().to_ascii_uppercase();
        assert_eq!(Sha256Hex::try_new(s), Err(Sha256HexError::NonLowercaseHex));
    }

    #[test]
    fn rejects_non_hex_character() {
        // Replace one hex char with a non-hex symbol of equal length.
        let mut s = sample().to_string();
        s.replace_range(0..1, "g");
        assert_eq!(Sha256Hex::try_new(s), Err(Sha256HexError::NonLowercaseHex));
    }

    #[test]
    fn from_str_uses_try_new() {
        assert_eq!(Sha256Hex::from_str(sample()).unwrap().as_str(), sample());
        assert!(Sha256Hex::from_str("nope").is_err());
    }

    #[test]
    fn serialises_as_bare_string() {
        let h = Sha256Hex::try_new(sample()).unwrap();
        let j = serde_json::to_string(&h).unwrap();
        assert_eq!(j, format!("\"{}\"", sample()));
    }

    #[test]
    fn deserialises_through_try_new() {
        let j = format!("\"{}\"", sample());
        let back: Sha256Hex = serde_json::from_str(&j).unwrap();
        assert_eq!(back.as_str(), sample());
    }

    /// Wire payloads carrying a malformed digest must be rejected at
    /// parse time, with an error message a human operator can act on.
    #[test]
    fn deserialise_rejects_invalid_with_descriptive_error() {
        let err = serde_json::from_str::<Sha256Hex>(r#""not-a-hash""#).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("64") || msg.contains("hex"),
            "expected descriptive error, got: {msg}"
        );
    }
}
