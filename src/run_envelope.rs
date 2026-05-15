//! Storage format for the signed-run note body.
//!
//! Writ's `RunAgent` handler captures three things per run: the
//! agent's [`OutputEnvelope`] (stdout + stderr + per-stream
//! truncation markers, framed as canonical JSON), the
//! [`SignedRunMetadata`] it signed, and the detached SSHSIG signature
//! over those metadata bytes. Together these form one
//! [`SignedRunEnvelope`], which writ encodes and stores as the body
//! of a Git note in writ's bare repo (see `bailiff-split` plan,
//! slice B). Bailiff fetches the notes ref later, decodes the
//! envelope, verifies the signature, and re-derives the prompt and
//! output digests.
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
//! **Encoding.** JSON. `SignedRunEnvelope.output` carries the
//! canonical bytes of an [`OutputEnvelope`] (itself JSON with
//! base64-encoded stdout and stderr) so the wrapper round-trips
//! arbitrary binary output and surfaces stderr to verifiers.
//! `deny_unknown_fields` plus the strict newtype validators on
//! `metadata` and `signature` make any wire-level corruption surface
//! as a parse error at decode time, not as a silent signature
//! mismatch.
//!
//! The encoding is **not** what gets signed. The signature covers
//! [`SignedRunMetadata::canonical_bytes`] only; the envelope wraps that
//! plus the output bytes the metadata's `output_envelope_sha256` binds
//! to. Verification on the read side is:
//!
//! 1. Decode the [`SignedRunEnvelope`].
//! 2. Verify `sha256(envelope.output) == envelope.metadata.output_envelope_sha256`.
//! 3. Verify `envelope.signature` against `envelope.metadata.canonical_bytes()`
//!    under the public key keyed by `envelope.metadata.signing_key_fingerprint`.
//! 4. Optionally [`OutputEnvelope::from_bytes`] the `output` field to
//!    inspect stdout, stderr, and the per-stream truncation markers.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::core::SshSignature;
use crate::protocol::SignedRunMetadata;

/// Framed stdout + stderr from one agent run, plus per-stream
/// truncation markers.
///
/// Serialised as compact JSON; the resulting bytes are exactly what
/// [`SignedRunMetadata::output_envelope_sha256`] digests and what gets
/// stored in [`SignedRunEnvelope::output`]. Separating stdout from
/// stderr (rather than concatenating) lets a verifier surface them
/// independently — meaningful for non-zero exits whose diagnostics
/// land on stderr — and the bool-free `_truncated_at: Option<u64>`
/// records the *byte offset* the read was cut at, not just a fact
/// that truncation occurred, so the captured prefix is unambiguous.
///
/// `deny_unknown_fields` keeps the field set closed against silent
/// future extensions; the strict newtype validators on the parent
/// envelope catch wire corruption elsewhere.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputEnvelope {
    /// Raw stdout bytes the agent produced, base64-encoded on the
    /// wire so the envelope round-trips arbitrary binary output.
    #[serde(with = "base64_bytes")]
    pub stdout: Vec<u8>,
    /// Raw stderr bytes the agent produced, base64-encoded on the
    /// wire. Captured under the same byte cap as stdout and signed
    /// alongside it.
    #[serde(with = "base64_bytes")]
    pub stderr: Vec<u8>,
    /// Byte offset at which writ stopped retaining stdout. `None`
    /// means the entire stream was kept; `Some(n)` means the first
    /// `n` bytes are in `stdout` and the rest were drained to keep
    /// the child from blocking.
    pub stdout_truncated_at: Option<u64>,
    /// Same shape as `stdout_truncated_at`, for stderr.
    pub stderr_truncated_at: Option<u64>,
}

impl OutputEnvelope {
    /// Canonical JSON serialisation. The resulting bytes are what
    /// `output_envelope_sha256` digests, so this is the *only*
    /// supported way to produce the bytes stored in
    /// [`SignedRunEnvelope::output`].
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("OutputEnvelope serialises to JSON without IO; cannot fail")
    }

    /// Decode an `OutputEnvelope` from canonical JSON bytes. Returns a
    /// parse error if the input is malformed, carries an unknown
    /// field, or has non-base64 stdout/stderr.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

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
    /// Canonical bytes of an [`OutputEnvelope`] (stdout + stderr +
    /// truncation markers), base64-encoded on the wire so the wrapper
    /// round-trips arbitrary binary content. These exact bytes are
    /// what `metadata.output_envelope_sha256` digests.
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

    /// Round-trip stdout + stderr through the framed envelope. Each
    /// stream must survive byte-exact and the truncation markers must
    /// be preserved verbatim — verifiers use the exact bytes to
    /// re-derive `output_envelope_sha256`, so any silent mutation here
    /// would surface as a signature-vs-content mismatch.
    #[test]
    fn output_envelope_round_trips_both_streams() {
        let env = OutputEnvelope {
            stdout: b"hello\n".to_vec(),
            stderr: b"oops\n".to_vec(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let back = OutputEnvelope::from_bytes(&env.to_bytes()).unwrap();
        assert_eq!(back, env);
    }

    /// Arbitrary binary bytes on either stream — including embedded
    /// NULs and the full 0..=255 range — must survive a round-trip
    /// byte-exact. The agent's output channels are opaque to writ,
    /// so any byte pattern is legitimate.
    #[test]
    fn output_envelope_round_trips_binary() {
        let stdout: Vec<u8> = (0u8..=255).collect();
        let mut stderr: Vec<u8> = (0u8..=255).rev().collect();
        stderr.push(0);
        stderr.push(255);
        let env = OutputEnvelope {
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let back = OutputEnvelope::from_bytes(&env.to_bytes()).unwrap();
        assert_eq!(back.stdout, stdout);
        assert_eq!(back.stderr, stderr);
    }

    /// Per-stream truncation markers must survive verbatim. The cap
    /// offset is what a verifier needs to know to decide whether to
    /// trust the partial capture, so any mismatch between the producer
    /// and consumer view of "where we stopped" is a correctness bug.
    #[test]
    fn output_envelope_round_trips_truncation_offsets() {
        let env = OutputEnvelope {
            stdout: vec![b'a'; 1024],
            stderr: vec![b'b'; 512],
            stdout_truncated_at: Some(1024),
            stderr_truncated_at: Some(512),
        };
        let back = OutputEnvelope::from_bytes(&env.to_bytes()).unwrap();
        assert_eq!(back, env);
    }

    /// `deny_unknown_fields` on the inner envelope catches a
    /// wire-level extra key at decode time, the same as the outer
    /// envelope. The four fields are a closed set bound by
    /// `output_envelope_sha256`; a silently accepted extra would let a
    /// producer attach unverified data that no verifier rules on.
    #[test]
    fn output_envelope_rejects_unknown_field() {
        let env = OutputEnvelope {
            stdout: b"o".to_vec(),
            stderr: b"e".to_vec(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let mut value: serde_json::Value = serde_json::to_value(&env).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::Value::Bool(true));
        let bytes = serde_json::to_vec(&value).unwrap();
        let err = OutputEnvelope::from_bytes(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("extra") || err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}",
        );
    }

    /// Pin the wire-level field names and order of `OutputEnvelope`.
    /// The bytes from [`OutputEnvelope::to_bytes`] are what
    /// `output_envelope_sha256` digests, so any rename or reorder
    /// would silently invalidate every existing signed note. Field
    /// order is taken from the struct declaration — same idiom as the
    /// outer envelope pin above.
    #[test]
    fn output_envelope_pins_field_order() {
        let env = OutputEnvelope {
            stdout: b"o".to_vec(),
            stderr: b"e".to_vec(),
            stdout_truncated_at: Some(1),
            stderr_truncated_at: Some(2),
        };
        let json = String::from_utf8(env.to_bytes()).unwrap();
        let stdout_at = json.find("\"stdout\"").unwrap();
        let stderr_at = json.find("\"stderr\"").unwrap();
        let stdout_trunc_at = json.find("\"stdout_truncated_at\"").unwrap();
        let stderr_trunc_at = json.find("\"stderr_truncated_at\"").unwrap();
        assert!(
            stdout_at < stderr_at
                && stderr_at < stdout_trunc_at
                && stdout_trunc_at < stderr_trunc_at,
            "expected stdout < stderr < stdout_truncated_at < stderr_truncated_at in {json}",
        );
    }
}
