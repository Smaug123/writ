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

const SHA256_HEX_LEN: usize = 64;

crate::validated_string! {
    /// A SHA-256 digest as 64 lowercase hex characters. Text from the wire
    /// enters via [`Sha256Hex::try_new`] (or its `FromStr` / `Deserialize`
    /// equivalents); a digest this process computed enters via
    /// [`Sha256Hex::from_digest`], which cannot fail.
    pub struct Sha256Hex;
    error = Sha256HexError;
    constructor = try_new;
    validate = validate_sha256_hex;
}

fn validate_sha256_hex(s: &str) -> Result<(), Sha256HexError> {
    if s.len() != SHA256_HEX_LEN {
        return Err(Sha256HexError::WrongLength {
            got: s.len(),
            expected: SHA256_HEX_LEN,
        });
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(Sha256HexError::NonLowercaseHex);
    }
    Ok(())
}

impl Sha256Hex {
    /// The canonical rendering of a raw 32-byte digest. Infallible by
    /// construction, so hashing code never round-trips through `try_new`
    /// and an `expect` to say what the type already guarantees.
    pub fn from_digest(digest: &[u8; 32]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(SHA256_HEX_LEN);
        for byte in digest {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Self(out)
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
    use proptest::prelude::*;

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

    fn candidates() -> impl Strategy<Value = String> {
        prop_oneof![
            "[0-9a-f]{64}",
            "[0-9a-fA-F]{62,66}",
            "[0-9a-g]{64}",
            ".{0,70}",
        ]
    }

    crate::validated_string_laws!(Sha256Hex, try_new, validate_sha256_hex, candidates());

    proptest::proptest! {
        /// `from_digest` renders exactly what `try_new` accepts, agreeing
        /// with the standard library's own lowercase-hex formatting.
        #[test]
        fn from_digest_is_the_canonical_rendering(digest in proptest::array::uniform32(0u8..)) {
            let rendered = Sha256Hex::from_digest(&digest);
            let reference: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            proptest::prop_assert_eq!(rendered.as_str(), reference.as_str());
            proptest::prop_assert_eq!(Sha256Hex::try_new(rendered.as_str()), Ok(rendered));
        }
    }
}
