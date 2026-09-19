//! Wire-level newtypes for writ-side signing artefacts: an SSH detached
//! signature and the public-key fingerprint that identifies which writ
//! signing key produced it.
//!
//! Bailiff resolves the fingerprint to a public key via a config-driven
//! SSH allowed-signers file (the same trust-anchor shape Git uses for
//! commit-signature verification) and then validates the signature
//! against the canonical bytes of `SignedRunMetadata`.
//!
//! Validation here is intentionally narrow — enough to reject obvious
//! misuse at the wire (empty payloads, NUL bytes, missing format
//! markers), not cryptographic correctness. The authoritative gate is
//! `ssh-keygen -Y verify` against the allowed-signers file.

const FINGERPRINT_PREFIX: &str = "SHA256:";
const SIGNATURE_BEGIN_MARKER: &str = "-----BEGIN SSH SIGNATURE-----";
const SIGNATURE_END_MARKER: &str = "-----END SSH SIGNATURE-----";

crate::validated_string! {
    /// An SSH public-key fingerprint in the format `ssh-keygen -lf` and
    /// the OpenSSH allowed-signers file use, e.g.
    /// `SHA256:abc123def...`. The base64-ish suffix is treated as opaque
    /// at v1; only the `SHA256:` prefix and "non-empty, no whitespace, no
    /// NUL" rules are enforced. Bailiff's keyring resolution is what
    /// turns the fingerprint into a public key for verification.
    #[derive(Ord, PartialOrd)]
    pub struct SshKeyFingerprint;
    error = SshKeyFingerprintError;
    constructor = try_new;
    validate = validate_fingerprint;
}

fn validate_fingerprint(s: &str) -> Result<(), SshKeyFingerprintError> {
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
    Ok(())
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

crate::validated_string! {
    /// A PEM-armoured SSH detached signature, as emitted by `ssh-keygen -Y
    /// sign`. v1 validation checks the framing markers and that the body
    /// is non-empty; full cryptographic verification is deferred to
    /// `ssh-keygen -Y verify` at the bailiff boundary.
    pub struct SshSignature;
    error = SshSignatureError;
    constructor = try_new;
    validate = validate_signature;
}

fn validate_signature(s: &str) -> Result<(), SshSignatureError> {
    if s.is_empty() {
        return Err(SshSignatureError::Empty);
    }
    if s.contains('\0') {
        return Err(SshSignatureError::NulByte);
    }
    let trimmed = s.trim();
    let after_begin = trimmed
        .strip_prefix(SIGNATURE_BEGIN_MARKER)
        .ok_or(SshSignatureError::MissingBeginMarker)?;
    let body = after_begin
        .strip_suffix(SIGNATURE_END_MARKER)
        .ok_or(SshSignatureError::MissingEndMarker)?;
    // The two markers alone — with no signature bytes between them
    // — would pass a naive `starts_with` + `ends_with` pair, then
    // hand bailiff a payload `ssh-keygen -Y verify` is guaranteed
    // to reject. Catch it here so the verifier never sees it.
    if body.trim().is_empty() {
        return Err(SshSignatureError::EmptyBody);
    }
    Ok(())
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
    #[error("ssh signature body between the BEGIN/END markers must not be empty")]
    EmptyBody,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn fingerprint_candidates() -> impl Strategy<Value = String> {
        prop_oneof![
            "SHA256:[A-Za-z0-9+/]{0,44}",
            "(SHA256:)?[A-Za-z0-9+/ \\x00]{0,20}",
            any::<String>(),
        ]
    }

    /// Signatures assembled from optional markers, an arbitrary body and
    /// surrounding whitespace, so every framing rule is reached.
    fn signature_candidates() -> impl Strategy<Value = String> {
        let framed = (
            any::<bool>(),
            "[A-Za-z0-9+/= \\n]{0,20}",
            any::<bool>(),
            "[ \\n]{0,2}",
        )
            .prop_map(|(begin, body, end, ws)| {
                let begin = if begin { SIGNATURE_BEGIN_MARKER } else { "" };
                let end = if end { SIGNATURE_END_MARKER } else { "" };
                format!("{ws}{begin}{body}{end}{ws}")
            });
        prop_oneof![framed, any::<String>()]
    }

    mod fingerprint_laws {
        use super::*;
        crate::validated_string_laws!(
            SshKeyFingerprint,
            try_new,
            validate_fingerprint,
            fingerprint_candidates()
        );
    }

    mod signature_laws {
        use super::*;
        crate::validated_string_laws!(
            SshSignature,
            try_new,
            validate_signature,
            signature_candidates()
        );
    }

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

    /// A payload that is only the BEGIN and END markers — with no
    /// signature bytes between them — passes a naive starts_with /
    /// ends_with pair but is meaningless to a verifier. Catch it here
    /// rather than handing `ssh-keygen -Y verify` something guaranteed
    /// to fail.
    #[test]
    fn signature_rejects_empty_body_between_markers() {
        let bad = format!("{SIGNATURE_BEGIN_MARKER}{SIGNATURE_END_MARKER}");
        assert_eq!(
            SshSignature::try_new(bad),
            Err(SshSignatureError::EmptyBody),
        );

        let whitespace_only = format!("{SIGNATURE_BEGIN_MARKER}\n   \n\t\n{SIGNATURE_END_MARKER}");
        assert_eq!(
            SshSignature::try_new(whitespace_only),
            Err(SshSignatureError::EmptyBody),
        );
    }
}
