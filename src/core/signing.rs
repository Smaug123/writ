//! Wire-level newtypes for writ-side signing artefacts: an SSH detached
//! signature and the public-key fingerprint that identifies which writ
//! signing key produced it.
//!
//! Bailiff resolves the fingerprint to a public key via a config-driven
//! SSH allowed-signers file (the same trust-anchor shape Git uses for
//! commit-signature verification) and then validates the signature
//! against the canonical bytes of `SignedRunMetadata`. See
//! `docs/plans/2026-05-14-bailiff-split.md`.
//!
//! v1 validation is intentionally narrow — enough to reject obvious
//! misuse at the wire (empty payloads, NUL bytes, missing format
//! markers), not full cryptographic correctness. The authoritative
//! gate is `ssh-keygen -Y verify` against the allowed-signers file,
//! which slice B will wire up. The newtypes exist now so the wire
//! shape is correct-by-construction in slice A2 before the verifier
//! lands.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const FINGERPRINT_PREFIX: &str = "SHA256:";
const SIGNATURE_BEGIN_MARKER: &str = "-----BEGIN SSH SIGNATURE-----";
const SIGNATURE_END_MARKER: &str = "-----END SSH SIGNATURE-----";

/// An SSH public-key fingerprint in the format `ssh-keygen -lf` and
/// the OpenSSH allowed-signers file use, e.g.
/// `SHA256:abc123def...`. The base64-ish suffix is treated as opaque
/// at v1; only the `SHA256:` prefix and "non-empty, no whitespace, no
/// NUL" rules are enforced. Bailiff's keyring resolution is what
/// turns the fingerprint into a public key for verification.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SshKeyFingerprint(String);

impl SshKeyFingerprint {
    pub fn try_new(s: impl Into<String>) -> Result<Self, SshKeyFingerprintError> {
        let s = s.into();
        if s.is_empty() {
            return Err(SshKeyFingerprintError::Empty);
        }
        if s.contains('\0') {
            return Err(SshKeyFingerprintError::NulByte);
        }
        if s.chars().any(char::is_whitespace) {
            return Err(SshKeyFingerprintError::Whitespace);
        }
        if !s.starts_with(FINGERPRINT_PREFIX) {
            return Err(SshKeyFingerprintError::MissingPrefix);
        }
        if s.len() == FINGERPRINT_PREFIX.len() {
            return Err(SshKeyFingerprintError::EmptyBody);
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SshKeyFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for SshKeyFingerprint {
    type Err = SshKeyFingerprintError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl Serialize for SshKeyFingerprint {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SshKeyFingerprint {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::try_new(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SshKeyFingerprintError {
    #[error("ssh key fingerprint must not be empty")]
    Empty,
    #[error("ssh key fingerprint must not contain NUL bytes")]
    NulByte,
    #[error("ssh key fingerprint must not contain whitespace")]
    Whitespace,
    #[error("ssh key fingerprint must start with `SHA256:`")]
    MissingPrefix,
    #[error("ssh key fingerprint body after `SHA256:` must not be empty")]
    EmptyBody,
}

/// A PEM-armoured SSH detached signature, as emitted by `ssh-keygen -Y
/// sign`. v1 validation checks the framing markers and that the body
/// is non-empty; full cryptographic verification is deferred to
/// `ssh-keygen -Y verify` at the bailiff boundary.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SshSignature(String);

impl SshSignature {
    pub fn try_new(s: impl Into<String>) -> Result<Self, SshSignatureError> {
        let s = s.into();
        if s.is_empty() {
            return Err(SshSignatureError::Empty);
        }
        if s.contains('\0') {
            return Err(SshSignatureError::NulByte);
        }
        let trimmed = s.trim();
        if !trimmed.starts_with(SIGNATURE_BEGIN_MARKER) {
            return Err(SshSignatureError::MissingBeginMarker);
        }
        if !trimmed.ends_with(SIGNATURE_END_MARKER) {
            return Err(SshSignatureError::MissingEndMarker);
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SshSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for SshSignature {
    type Err = SshSignatureError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl Serialize for SshSignature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SshSignature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::try_new(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SshSignatureError {
    #[error("ssh signature must not be empty")]
    Empty,
    #[error("ssh signature must not contain NUL bytes")]
    NulByte,
    #[error("ssh signature must start with `-----BEGIN SSH SIGNATURE-----`")]
    MissingBeginMarker,
    #[error("ssh signature must end with `-----END SSH SIGNATURE-----`")]
    MissingEndMarker,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample_fingerprint() -> &'static str {
        "SHA256:Wn0p/0WC9F8b/J35rwTRsLP6w8b9ZsZh4HX0FYpC0Zg"
    }

    fn sample_signature() -> String {
        format!("{SIGNATURE_BEGIN_MARKER}\nU1NIU0lHAAAAAQ...\n{SIGNATURE_END_MARKER}",)
    }

    // --- SshKeyFingerprint ------------------------------------------------

    #[test]
    fn fingerprint_accepts_well_formed() {
        let f = SshKeyFingerprint::try_new(sample_fingerprint()).unwrap();
        assert_eq!(f.as_str(), sample_fingerprint());
    }

    #[test]
    fn fingerprint_rejects_empty() {
        assert_eq!(
            SshKeyFingerprint::try_new(""),
            Err(SshKeyFingerprintError::Empty),
        );
    }

    #[test]
    fn fingerprint_rejects_missing_prefix() {
        assert_eq!(
            SshKeyFingerprint::try_new("MD5:abc"),
            Err(SshKeyFingerprintError::MissingPrefix),
        );
    }

    #[test]
    fn fingerprint_rejects_empty_body() {
        assert_eq!(
            SshKeyFingerprint::try_new("SHA256:"),
            Err(SshKeyFingerprintError::EmptyBody),
        );
    }

    #[test]
    fn fingerprint_rejects_nul_byte() {
        assert_eq!(
            SshKeyFingerprint::try_new("SHA256:abc\0def"),
            Err(SshKeyFingerprintError::NulByte),
        );
    }

    #[test]
    fn fingerprint_rejects_whitespace() {
        assert_eq!(
            SshKeyFingerprint::try_new("SHA256:abc def"),
            Err(SshKeyFingerprintError::Whitespace),
        );
        assert_eq!(
            SshKeyFingerprint::try_new("SHA256:abc\n"),
            Err(SshKeyFingerprintError::Whitespace),
        );
    }

    #[test]
    fn fingerprint_from_str_uses_try_new() {
        assert_eq!(
            SshKeyFingerprint::from_str(sample_fingerprint())
                .unwrap()
                .as_str(),
            sample_fingerprint(),
        );
        assert!(SshKeyFingerprint::from_str("").is_err());
    }

    #[test]
    fn fingerprint_serialises_as_bare_string() {
        let f = SshKeyFingerprint::try_new(sample_fingerprint()).unwrap();
        let j = serde_json::to_string(&f).unwrap();
        assert_eq!(j, format!("\"{}\"", sample_fingerprint()));
    }

    #[test]
    fn fingerprint_deserialises_through_try_new() {
        let j = format!("\"{}\"", sample_fingerprint());
        let back: SshKeyFingerprint = serde_json::from_str(&j).unwrap();
        assert_eq!(back.as_str(), sample_fingerprint());
    }

    #[test]
    fn fingerprint_deserialise_rejects_invalid_with_descriptive_error() {
        let err = serde_json::from_str::<SshKeyFingerprint>(r#""nope""#).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SHA256:"),
            "expected descriptive error, got: {msg}",
        );
    }

    // --- SshSignature -----------------------------------------------------

    #[test]
    fn signature_accepts_well_formed_pem() {
        let s = SshSignature::try_new(sample_signature()).unwrap();
        assert_eq!(s.as_str(), sample_signature());
    }

    #[test]
    fn signature_rejects_empty() {
        assert_eq!(SshSignature::try_new(""), Err(SshSignatureError::Empty));
    }

    #[test]
    fn signature_rejects_nul_byte() {
        let bad = format!("{SIGNATURE_BEGIN_MARKER}\nU1NI\0AAA\n{SIGNATURE_END_MARKER}");
        assert_eq!(SshSignature::try_new(bad), Err(SshSignatureError::NulByte),);
    }

    #[test]
    fn signature_rejects_missing_begin_marker() {
        let bad = format!("U1NIU0lHAAAAAQ...\n{SIGNATURE_END_MARKER}");
        assert_eq!(
            SshSignature::try_new(bad),
            Err(SshSignatureError::MissingBeginMarker),
        );
    }

    #[test]
    fn signature_rejects_missing_end_marker() {
        let bad = format!("{SIGNATURE_BEGIN_MARKER}\nU1NIU0lHAAAAAQ...");
        assert_eq!(
            SshSignature::try_new(bad),
            Err(SshSignatureError::MissingEndMarker),
        );
    }

    #[test]
    fn signature_from_str_uses_try_new() {
        let s = SshSignature::from_str(&sample_signature()).unwrap();
        assert_eq!(s.as_str(), sample_signature());
        assert!(SshSignature::from_str("").is_err());
    }

    #[test]
    fn signature_serialises_as_bare_string() {
        let s = SshSignature::try_new(sample_signature()).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: SshSignature = serde_json::from_str(&j).unwrap();
        assert_eq!(back.as_str(), sample_signature());
    }

    #[test]
    fn signature_deserialise_rejects_invalid_with_descriptive_error() {
        let err = serde_json::from_str::<SshSignature>(r#""nope""#).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("BEGIN SSH SIGNATURE") || msg.contains("END SSH SIGNATURE"),
            "expected descriptive error, got: {msg}",
        );
    }
}
