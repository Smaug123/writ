//! Storage format for the signed-run note body.
//!
//! Writ's `RunAgent` handler captures three things per run: the agent's
//! raw stdout (the "output"), the canonical metadata it signed
//! ([`SignedRunMetadata`]), and the detached SSHSIG signature over those
//! metadata bytes. Together these form one [`SignedRunEnvelope`], which
//! writ encodes and stores as the body of a Git note in writ's bare
//! repo (see `bailiff-split` plan, slice B). Bailiff fetches the notes
//! ref later and decodes the envelope to verify the signature and
//! re-derive the prompt/output digests.
//!
//! **Why a wrapper rather than three blobs.** The pinned design decision
//! in `docs/plans/2026-05-14-bailiff-split.md` and the accompanying
//! memory note is: the envelope bytes go directly into the note body.
//! Bundling output + metadata + signature into one self-describing
//! object means a verifier with a `git clone` of writ's repo and an
//! allowed-signers file has everything needed for offline
//! verification — no separate blob lookups, no risk of `git gc`
//! pruning loose objects that aren't reachable from a ref.
//!
//! **Encoding.** JSON. The `output` field carries raw bytes via
//! `base64` so the wrapper round-trips arbitrary binary stdout.
//! `deny_unknown_fields` plus the strict newtype validators on
//! `metadata` and `signature` make any wire-level corruption surface
//! as a parse error at decode time, not as a silent signature mismatch.
//!
//! The encoding is **not** what gets signed. The signature covers
//! [`SignedRunMetadata::canonical_bytes`] only; the envelope wraps that
//! plus the output bytes the metadata's `output_envelope_sha256` binds
//! to. Verification on the read side is:
//!
//! 1. Decode the envelope.
//! 2. Verify `sha256(envelope.output) == envelope.metadata.output_envelope_sha256`.
//! 3. Verify `envelope.signature` against `envelope.metadata.canonical_bytes()`
//!    under the public key keyed by `envelope.metadata.signing_key_fingerprint`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::core::SshSignature;
use crate::protocol::SignedRunMetadata;

/// Self-contained record of one writ-signed agent run.
///
/// Encoded as the body of a Git note in writ's bare repo. Construction
/// is intentionally a plain struct literal — the producer is writ's
/// `RunAgent` handler and there is no benefit to threading a builder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRunEnvelope {
    pub metadata: SignedRunMetadata,
    pub signature: SshSignature,
    /// Raw stdout the agent produced, base64-encoded on the wire so
    /// the envelope round-trips arbitrary binary output. The decoded
    /// bytes are what `metadata.output_envelope_sha256` digests.
    #[serde(with = "base64_bytes")]
    pub output: Vec<u8>,
}

impl SignedRunEnvelope {
    /// Encode the envelope as JSON bytes ready to be written into a
    /// note body. Infallible: every field has a deterministic JSON
    /// representation and the in-memory wrapper is always valid.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self)
            .expect("SignedRunEnvelope serialises to JSON without IO; cannot fail")
    }

    /// Decode an envelope from JSON bytes. Returns a parse error if
    /// the input is malformed, carries an unknown field, fails any of
    /// the newtype validators on `metadata` or `signature`, or if the
    /// `output` field is not valid base64.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

mod base64_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        BASE64_STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{CapabilitySet, RepoRef, Sha256Hex, SshKeyFingerprint, UnixMillis};

    fn sample_metadata() -> SignedRunMetadata {
        SignedRunMetadata {
            run_id: "f2f2f2f2-0000-0000-0000-000000000001".parse().unwrap(),
            session_id: "00000000-0000-0000-0000-000000000001".parse().unwrap(),
            prompt_sha256: Sha256Hex::try_new(std::iter::repeat_n('a', 64).collect::<String>())
                .unwrap(),
            output_envelope_sha256: Sha256Hex::try_new(
                std::iter::repeat_n('b', 64).collect::<String>(),
            )
            .unwrap(),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "o".into(),
                    name: "n".into(),
                },
            }],
            exit_code: 0,
            completed_at: UnixMillis::from_millis(1_700_000_000_000),
            signing_key_fingerprint: SshKeyFingerprint::try_new(
                "SHA256:Wn0p0WC9F8bJ35rwTRsLP6w8b9ZsZh4HX0FYpC0Zg",
            )
            .unwrap(),
        }
    }

    fn sample_signature() -> SshSignature {
        SshSignature::try_new(
            "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ...\n-----END SSH SIGNATURE-----",
        )
        .unwrap()
    }

    #[test]
    fn round_trip_through_to_bytes_preserves_fields() {
        let env = SignedRunEnvelope {
            metadata: sample_metadata(),
            signature: sample_signature(),
            output: b"hello\nworld\n".to_vec(),
        };
        let bytes = env.to_bytes();
        let back = SignedRunEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(back, env);
    }

    /// Arbitrary binary bytes — including embedded NULs and high-byte
    /// non-UTF-8 — must survive an encode/decode round-trip byte-exact.
    /// The output channel from a noop child can legitimately produce
    /// any byte sequence, and a verifier re-hashes those exact bytes
    /// to check `output_envelope_sha256`.
    #[test]
    fn round_trip_preserves_arbitrary_binary_output() {
        let output: Vec<u8> = (0u8..=255).collect();
        let env = SignedRunEnvelope {
            metadata: sample_metadata(),
            signature: sample_signature(),
            output: output.clone(),
        };
        let back = SignedRunEnvelope::from_bytes(&env.to_bytes()).unwrap();
        assert_eq!(back.output, output);
    }

    /// Empty output is legal — a `true`-like child produces zero bytes,
    /// and the metadata's `output_envelope_sha256` still binds it via
    /// the well-defined SHA-256 of the empty string.
    #[test]
    fn round_trip_accepts_empty_output() {
        let env = SignedRunEnvelope {
            metadata: sample_metadata(),
            signature: sample_signature(),
            output: Vec::new(),
        };
        let back = SignedRunEnvelope::from_bytes(&env.to_bytes()).unwrap();
        assert_eq!(back.output, Vec::<u8>::new());
    }

    /// `deny_unknown_fields` catches a wire-level extra key at decode
    /// time. The envelope's three fields are a closed set; a silently
    /// accepted extra would let a producer attach unverified data that
    /// no verifier rules on.
    #[test]
    fn rejects_unknown_top_level_field() {
        let env = SignedRunEnvelope {
            metadata: sample_metadata(),
            signature: sample_signature(),
            output: b"hi".to_vec(),
        };
        let mut value: serde_json::Value = serde_json::to_value(&env).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::Value::Bool(true));
        let bytes = serde_json::to_vec(&value).unwrap();
        let err = SignedRunEnvelope::from_bytes(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("extra") || err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}",
        );
    }

    /// A non-base64 `output` field must be a hard decode error, not a
    /// silent treatment as empty bytes — otherwise a corrupted wrapper
    /// could pass the `output_envelope_sha256` check trivially for a
    /// metadata whose digest happens to be `sha256("")`.
    #[test]
    fn rejects_non_base64_output() {
        let mut value = serde_json::to_value(SignedRunEnvelope {
            metadata: sample_metadata(),
            signature: sample_signature(),
            output: b"ok".to_vec(),
        })
        .unwrap();
        value["output"] = serde_json::Value::String("not base64!!!".into());
        let bytes = serde_json::to_vec(&value).unwrap();
        let err = SignedRunEnvelope::from_bytes(&bytes).unwrap_err();
        // base64 errors carry their own messages — just confirm we
        // fail rather than silently producing an empty-output envelope.
        assert!(!err.to_string().is_empty());
    }

    /// Pin the wire-level key names and field order so a future
    /// serde-rename or struct-field reorder is a visible diff in this
    /// test rather than a silent break of every existing note in
    /// writ's repo. Inspecting the JSON string directly is necessary
    /// because `serde_json::Value` stores keys in a `BTreeMap` and
    /// re-sorts them alphabetically.
    #[test]
    fn pins_top_level_keys() {
        let env = SignedRunEnvelope {
            metadata: sample_metadata(),
            signature: sample_signature(),
            output: b"x".to_vec(),
        };
        let json = String::from_utf8(env.to_bytes()).unwrap();
        let metadata_at = json.find("\"metadata\"").unwrap();
        let signature_at = json.find("\"signature\"").unwrap();
        let output_at = json.find("\"output\"").unwrap();
        assert!(
            metadata_at < signature_at && signature_at < output_at,
            "expected metadata < signature < output in {json}",
        );
    }
}
