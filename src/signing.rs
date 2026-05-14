//! Operational SSHSIG signing for writ.
//!
//! The wire newtypes [`SshKeyFingerprint`] and [`SshSignature`] (in
//! [`crate::core`]) pin the *format* of an SSH signature on the
//! protocol surface; this module owns the *crypto*:
//! parsing an OpenSSH-format private key, signing canonical bytes with
//! it, and verifying a signature against a public key. The output armor
//! is OpenSSH's SSHSIG format (`-----BEGIN SSH SIGNATURE-----`…), the
//! same format `ssh-keygen -Y sign` produces and `ssh-keygen -Y verify`
//! consumes — and the same format Git's `gpg.format=ssh` uses for
//! signed commits. That parity is the point: a third party with a
//! clone of bailiff's repo plus its SSH allowed-signers file can
//! verify a writ-signed note with the same `ssh-keygen -Y verify`
//! invocation they'd run against a signed commit, no writ-specific
//! tooling.
//!
//! Namespace: every signature is bound to the constant
//! [`WRIT_SSHSIG_NAMESPACE`]. SSHSIG mixes the namespace into the
//! signed bytes so a signature minted for one purpose cannot be
//! replayed against a verifier that expects a different one — e.g. a
//! writ-namespaced signature cannot be passed off as a Git commit
//! signature (Git uses the `git` namespace). Both [`WritSigningKey::sign`]
//! and [`WritVerifyingKey::verify`] hardcode the namespace; callers do
//! not get to vary it.
//!
//! Algorithm: fingerprints and message hashes are SHA-256. This matches
//! the validation `SshKeyFingerprint::try_new` already imposes (`SHA256:`
//! prefix only) and the modern `ssh-keygen` default. Older hashes are
//! not accepted.
//!
//! Crate scope: which SSH key algorithms are actually accepted is
//! determined by the `ssh-key` Cargo features enabled in `Cargo.toml`.
//! Today only `ed25519` is on, so non-Ed25519 OpenSSH keys will fail at
//! `from_openssh_pem` — adding e.g. RSA support is a Cargo-features
//! change, not a code change here.
//!
//! Test fixtures: `tests/fixtures/ed25519_test_signing.key` (+ `.pub`)
//! is a fixed Ed25519 keypair used by this module's tests; never
//! reused for any real signing.

use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

use crate::core::{SshKeyFingerprint, SshKeyFingerprintError, SshSignature, SshSignatureError};

/// SSHSIG namespace bound into every writ-produced signature. Distinct
/// from `git` so a writ signature cannot impersonate a Git commit
/// signature minted with the same key.
pub const WRIT_SSHSIG_NAMESPACE: &str = "writ.run-agent";

/// A loaded writ signing keypair, capable of producing SSHSIG-armored
/// signatures over arbitrary canonical bytes.
///
/// Construct via [`WritSigningKey::from_openssh_pem`]. The wrapped
/// private key material is held in memory for the lifetime of this
/// value; callers are responsible for not persisting it outside the
/// designated `SecretStore`.
#[derive(Debug, Clone)]
pub struct WritSigningKey {
    inner: PrivateKey,
}

impl WritSigningKey {
    /// Parse an OpenSSH-armored private key (`-----BEGIN OPENSSH
    /// PRIVATE KEY-----`…). The key must be unencrypted — writ does
    /// not currently prompt for passphrases — and must use an
    /// algorithm enabled in the `ssh-key` Cargo feature set
    /// (Ed25519 today). RSA, ECDSA, DSA keys parse on the wire but
    /// cannot sign without their respective `ssh-key` features
    /// turned on; we reject them here so the misconfiguration shows
    /// up at boot rather than on the first run-agent call.
    pub fn from_openssh_pem(pem: &str) -> Result<Self, WritSigningKeyError> {
        let inner = PrivateKey::from_openssh(pem).map_err(WritSigningKeyError::ParseOpenSsh)?;
        if inner.is_encrypted() {
            return Err(WritSigningKeyError::Encrypted);
        }
        let alg = inner.algorithm();
        if !matches!(alg, ssh_key::Algorithm::Ed25519) {
            return Err(WritSigningKeyError::UnsupportedAlgorithm {
                algorithm: alg.as_str().to_string(),
            });
        }
        Ok(Self { inner })
    }

    /// SHA-256 fingerprint of the corresponding public key, in the
    /// canonical `SHA256:<base64>` form `ssh-keygen -lf` emits.
    pub fn fingerprint(&self) -> SshKeyFingerprint {
        fingerprint_of(self.inner.public_key())
    }

    /// The public half of this keypair. Hand this (or its OpenSSH
    /// serialisation) to verifiers; the private key never leaves
    /// this struct.
    pub fn verifying_key(&self) -> WritVerifyingKey {
        WritVerifyingKey {
            inner: self.inner.public_key().clone(),
        }
    }

    /// Produce an SSHSIG-armored detached signature over `msg`,
    /// bound to [`WRIT_SSHSIG_NAMESPACE`]. The returned
    /// [`SshSignature`] has already passed the wire-validation gate.
    pub fn sign(&self, msg: &[u8]) -> Result<SshSignature, WritSigningKeyError> {
        let sig = self
            .inner
            .sign(WRIT_SSHSIG_NAMESPACE, HashAlg::Sha256, msg)
            .map_err(WritSigningKeyError::Sign)?;
        let pem = sig
            .to_pem(LineEnding::LF)
            .map_err(WritSigningKeyError::Encode)?;
        SshSignature::try_new(pem).map_err(WritSigningKeyError::Newtype)
    }
}

/// The public half of a writ signing keypair. Used to verify
/// signatures and to publish the fingerprint a bailiff allowed-signers
/// file must list.
#[derive(Debug, Clone)]
pub struct WritVerifyingKey {
    inner: PublicKey,
}

impl WritVerifyingKey {
    /// Parse a one-line OpenSSH public key (`ssh-ed25519 AAAA…
    /// comment`) — the same shape `~/.ssh/id_ed25519.pub` holds.
    pub fn from_openssh(s: &str) -> Result<Self, WritSigningKeyError> {
        let inner = PublicKey::from_openssh(s).map_err(WritSigningKeyError::ParseOpenSsh)?;
        Ok(Self { inner })
    }

    /// SHA-256 fingerprint in the canonical `SHA256:<base64>` form.
    pub fn fingerprint(&self) -> SshKeyFingerprint {
        fingerprint_of(&self.inner)
    }

    /// Verify a writ-namespaced signature over `msg`. Fails if the
    /// signature is malformed, was minted under a different
    /// namespace, was signed by a different key, or no longer
    /// matches the message.
    pub fn verify(&self, msg: &[u8], signature: &SshSignature) -> Result<(), VerifyError> {
        let parsed: SshSig = signature.as_str().parse().map_err(VerifyError::ParseSig)?;
        self.inner
            .verify(WRIT_SSHSIG_NAMESPACE, msg, &parsed)
            .map_err(VerifyError::Verify)
    }
}

fn fingerprint_of(pk: &PublicKey) -> SshKeyFingerprint {
    let fp = pk.fingerprint(HashAlg::Sha256).to_string();
    // ssh-key's `Fingerprint::Display` always produces `SHA256:<base64>` for
    // `HashAlg::Sha256` — round-tripping it through our newtype is a
    // belt-and-braces parse to catch any future grammar drift.
    SshKeyFingerprint::try_new(fp).expect("ssh-key Fingerprint Display violates SHA256: grammar")
}

#[derive(Debug, thiserror::Error)]
pub enum WritSigningKeyError {
    #[error("OpenSSH key parse failed: {0}")]
    ParseOpenSsh(ssh_key::Error),
    #[error("private key is passphrase-encrypted; writ does not support encrypted keys")]
    Encrypted,
    #[error(
        "private key uses algorithm {algorithm:?}, which is not enabled in this build of writ \
         (only Ed25519 is supported today)"
    )]
    UnsupportedAlgorithm { algorithm: String },
    #[error("SSHSIG sign failed: {0}")]
    Sign(ssh_key::Error),
    #[error("SSHSIG PEM encoding failed: {0}")]
    Encode(ssh_key::Error),
    #[error("ssh-key produced an SSHSIG that fails our wire validation: {0}")]
    Newtype(SshSignatureError),
    #[error("ssh-key produced a fingerprint that fails our wire validation: {0}")]
    Fingerprint(SshKeyFingerprintError),
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("signature is not parseable SSHSIG armor: {0}")]
    ParseSig(ssh_key::Error),
    #[error("signature does not verify against this key: {0}")]
    Verify(ssh_key::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const PUBLIC_OPENSSH: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");
    const OTHER_PRIVATE_PEM: &str =
        include_str!("../tests/fixtures/ed25519_test_signing_other.key");
    const OTHER_PUBLIC_OPENSSH: &str =
        include_str!("../tests/fixtures/ed25519_test_signing_other.key.pub");
    /// Real OpenSSH-format Ed25519 private key, AES256-CTR-encrypted under
    /// the passphrase "passphrase". Used solely to exercise the encrypted
    /// branch in `from_openssh_pem`; never used for any signing.
    const ENCRYPTED_PRIVATE_PEM: &str =
        include_str!("../tests/fixtures/ed25519_test_encrypted.key");
    /// Real OpenSSH-format RSA private key, used solely to exercise the
    /// unsupported-algorithm branch in `from_openssh_pem`. Until the
    /// `rsa` Cargo feature is enabled on `ssh-key`, this key cannot
    /// produce signatures — so loading it must fail at construction
    /// rather than only when `sign()` is first called.
    const RSA_PRIVATE_PEM: &str = include_str!("../tests/fixtures/rsa_test_load_only.key");

    /// SHA-256 fingerprint produced by `ssh-keygen -lf` on the fixture
    /// public key. Pinning this in a test catches accidental
    /// algorithm or encoding drift in the fingerprint pipeline.
    const FIXTURE_FINGERPRINT: &str = "SHA256:cjW0LvEIdJwlkUZvl+qouk+FFuVjcIwHHzJAxLN7508";
    const OTHER_FIXTURE_FINGERPRINT: &str = "SHA256:nVDHkSCkoWuiyZvifyzGib3yXEA+tTexTY/CFjUTOMw";

    fn load() -> WritSigningKey {
        WritSigningKey::from_openssh_pem(PRIVATE_PEM).expect("fixture private key parses")
    }

    fn load_pub() -> WritVerifyingKey {
        WritVerifyingKey::from_openssh(PUBLIC_OPENSSH).expect("fixture public key parses")
    }

    #[test]
    fn fixture_private_key_parses() {
        let _ = load();
    }

    #[test]
    fn fingerprint_pins_to_ssh_keygen_output() {
        let key = load();
        assert_eq!(key.fingerprint().as_str(), FIXTURE_FINGERPRINT);
    }

    #[test]
    fn public_and_private_fingerprints_agree() {
        let priv_fp = load().fingerprint();
        let pub_fp = load_pub().fingerprint();
        assert_eq!(priv_fp, pub_fp);
        let derived_pub_fp = load().verifying_key().fingerprint();
        assert_eq!(derived_pub_fp, pub_fp);
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let key = load();
        let pubk = load_pub();
        let msg = b"the canonical bytes writ would sign go here";
        let sig = key.sign(msg).unwrap();
        pubk.verify(msg, &sig).unwrap();
    }

    /// Verification must reject a signature once a single message
    /// byte changes — the property writ's signature is meant to give
    /// bailiff.
    #[test]
    fn tampering_with_message_invalidates_signature() {
        let key = load();
        let pubk = load_pub();
        let msg = b"original bytes";
        let sig = key.sign(msg).unwrap();
        let tampered = b"original Bytes"; // single-bit flip
        let err = pubk
            .verify(tampered, &sig)
            .expect_err("tampered msg verifies");
        assert!(matches!(err, VerifyError::Verify(_)), "got: {err:?}");
    }

    /// A signature minted by one key must not verify under a
    /// different key — the property that makes the fingerprint
    /// gate meaningful.
    #[test]
    fn signature_from_other_key_is_rejected() {
        let other = WritSigningKey::from_openssh_pem(OTHER_PRIVATE_PEM).unwrap();
        let pubk = load_pub();
        let msg = b"signed by the wrong key";
        let sig = other.sign(msg).unwrap();
        let err = pubk
            .verify(msg, &sig)
            .expect_err("wrong-key sig verifies under right key");
        assert!(matches!(err, VerifyError::Verify(_)), "got: {err:?}");
    }

    #[test]
    fn other_fixture_fingerprint_matches() {
        let other = WritSigningKey::from_openssh_pem(OTHER_PRIVATE_PEM).unwrap();
        assert_eq!(other.fingerprint().as_str(), OTHER_FIXTURE_FINGERPRINT);
    }

    #[test]
    fn signature_passes_wire_newtype_grammar() {
        let key = load();
        let sig = key.sign(b"x").unwrap();
        assert!(sig.as_str().starts_with("-----BEGIN SSH SIGNATURE-----"));
        assert!(
            sig.as_str()
                .trim_end()
                .ends_with("-----END SSH SIGNATURE-----")
        );
    }

    /// An SSHSIG minted under a different namespace must fail
    /// verification — the property that prevents cross-purpose
    /// replay (e.g. a writ-signed blob being passed off as a Git
    /// commit signature, or vice versa).
    #[test]
    fn cross_namespace_signature_is_rejected() {
        let priv_key = PrivateKey::from_openssh(PRIVATE_PEM).unwrap();
        let msg = b"namespace-pinned message";
        // Sign under "git" (Git's commit-signing namespace), then ask
        // the writ-namespaced verifier to accept it.
        let foreign_sig = priv_key.sign("git", HashAlg::Sha256, msg).unwrap();
        let foreign_pem = foreign_sig.to_pem(LineEnding::LF).unwrap();
        let wire_sig = SshSignature::try_new(foreign_pem).unwrap();

        let pubk = load_pub();
        let err = pubk
            .verify(msg, &wire_sig)
            .expect_err("foreign-namespace sig verified under writ namespace");
        assert!(matches!(err, VerifyError::Verify(_)), "got: {err:?}");
    }

    /// Passphrase-encrypted OpenSSH private keys must be rejected
    /// explicitly rather than smuggled in as a generic parse failure,
    /// so the operator sees an actionable "decrypt the key before
    /// putting it in the SecretStore" message.
    #[test]
    fn encrypted_private_key_is_rejected() {
        match WritSigningKey::from_openssh_pem(ENCRYPTED_PRIVATE_PEM) {
            Err(WritSigningKeyError::Encrypted) => {}
            other => panic!("expected Encrypted, got {other:?}"),
        }
    }

    /// The two `.key.pub` fixtures must parse and have fingerprints
    /// distinct from each other — guards against accidentally
    /// committing two copies of the same key.
    #[test]
    fn other_public_openssh_fixture_parses_and_differs() {
        let primary = WritVerifyingKey::from_openssh(PUBLIC_OPENSSH).unwrap();
        let other = WritVerifyingKey::from_openssh(OTHER_PUBLIC_OPENSSH).unwrap();
        assert_ne!(primary.fingerprint(), other.fingerprint());
    }

    #[test]
    fn parse_failure_surfaces_as_typed_error() {
        let err = WritSigningKey::from_openssh_pem("not a key").unwrap_err();
        assert!(
            matches!(err, WritSigningKeyError::ParseOpenSsh(_)),
            "got: {err:?}"
        );
    }

    /// An OpenSSH-format key whose algorithm is not enabled in the
    /// `ssh-key` Cargo feature set (today: anything other than
    /// Ed25519, e.g. RSA) parses on the wire but cannot sign. Reject
    /// at load time so a misconfigured key surfaces at boot, not on
    /// the first run-agent call.
    #[test]
    fn rsa_private_key_is_rejected_at_load_time() {
        let err = WritSigningKey::from_openssh_pem(RSA_PRIVATE_PEM).unwrap_err();
        match err {
            WritSigningKeyError::UnsupportedAlgorithm { ref algorithm } => {
                assert!(
                    algorithm.contains("rsa") || algorithm.contains("RSA"),
                    "algorithm label should mention RSA, got {algorithm:?}"
                );
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    /// Distinct messages must yield distinct signatures (Ed25519 is
    /// deterministic, so the signature is a function of message
    /// bytes + namespace + key; same key + different message ⇒
    /// different signature is the basic correctness property).
    #[test]
    fn distinct_messages_produce_distinct_signatures() {
        let key = load();
        let a = key.sign(b"alpha").unwrap();
        let b = key.sign(b"beta").unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }
}
