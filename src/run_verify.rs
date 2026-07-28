//! Verifier-side of the writ→bailiff signed-run handshake.
//!
//! Writ produces a [`SignedRunEnvelope`] per agent run and writes it
//! into its own bare repo as a Git note (slices B3–B4). Bailiff fetches
//! the writ-owned notes refs as a Git remote and consumes the envelope
//! from its own clone. **This module is the consumer side.**
//!
//! [`verify_run_envelope`] is the entire verifier surface: a pure
//! function over an envelope and an [`AllowedSigners`] keyring that
//! returns `Ok(())` iff every check passes, and a tagged
//! [`VerifyError`] iff any one of them fails. The three checks are:
//!
//! 1. **Output binding.** `sha256(envelope.output)` must equal
//!    `envelope.metadata.output_envelope_sha256`. The signature does
//!    not directly cover the output bytes — it covers
//!    `metadata.canonical_bytes()`, which includes the output digest.
//!    Re-hashing here is what makes the signature transitively bind
//!    the captured stdout/stderr.
//! 2. **Signer recognition.** `envelope.metadata.signing_key_fingerprint`
//!    must be in the allowed-signers map. An unknown fingerprint
//!    rejects regardless of whether the signature is internally valid,
//!    because writ's trust anchor is *which* key signed, not just
//!    *whether* a key signed.
//! 3. **Signature verification.** The resolved [`WritVerifyingKey`]
//!    must verify the detached SSHSIG against
//!    `envelope.metadata.canonical_bytes()` under the
//!    `writ.run-agent` namespace.
//!
//! Failure is per-check tagged so a bailiff CLI can surface "the
//! output was tampered with" distinctly from "we don't know that
//! signer" — both are signature failures but the operator response
//! differs.
//!
//! The verifier is intentionally one-shot: no streaming, no partial
//! verification, no chain of trust beyond fingerprint→key. The Git
//! allowed-signers convention is the source of truth for the keyring
//! (see [`AllowedSigners::from_openssh_lines`]).

use std::collections::BTreeMap;

use crate::agent_run::sha256_hex;
use crate::core::{Sha256Hex, SshKeyFingerprint};
use crate::run_envelope::SignedRunEnvelope;
use crate::signing::{self, WritSigningKeyError, WritVerifyingKey};

/// In-memory keyring of `fingerprint → public key` that
/// [`verify_run_envelope`] consults to resolve a writ-produced
/// signature.
///
/// The map is keyed by [`SshKeyFingerprint`] so a verifier can ingest
/// keys in any order and still find the one a particular signature
/// announces. Construction is total: invalid lines surface as
/// [`AllowedSignersParseError`] at parse time, after which the map
/// is by construction free of bad entries.
///
/// **Trust model.** A fingerprint that isn't here is not trusted, full
/// stop. This is the same shape Git uses for commit-signature
/// verification: the allowed-signers file enumerates the public keys
/// you accept signatures from, and anything outside is rejected.
#[derive(Debug, Clone, Default)]
pub struct AllowedSigners {
    by_fingerprint: BTreeMap<SshKeyFingerprint, WritVerifyingKey>,
}

impl AllowedSigners {
    /// Build an empty keyring. Useful for negative tests; in
    /// production every verifier starts from a non-empty parse.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a keyring directly from a collection of public keys. The
    /// fingerprint of each key keys the map; if two keys share a
    /// fingerprint (an SHA-256 collision, structurally impossible in
    /// practice but accepted for testability) the later one wins.
    pub fn from_keys(keys: impl IntoIterator<Item = WritVerifyingKey>) -> Self {
        let by_fingerprint = keys
            .into_iter()
            .map(|key| (key.fingerprint(), key))
            .collect();
        Self { by_fingerprint }
    }

    /// Parse a Git/OpenSSH allowed-signers file: one entry per line in
    /// the form `principals [options] keytype base64-key [comment]`,
    /// with blank lines and lines whose first non-whitespace character
    /// is `#` skipped. The leading principals field is mandatory in
    /// the allowed-signers format — `* ssh-ed25519 AAAA…` is the most
    /// common shape — and options before the keytype (e.g.
    /// `cert-authority`, `namespaces="…"`) are accepted but
    /// **not interpreted**: v1's trust model is "fingerprint must be
    /// in the file"; principal matching and namespace pinning are
    /// orthogonal hardening that bailiff doesn't need yet.
    ///
    /// Bare OpenSSH public-key lines (`ssh-ed25519 AAAA…`, with no
    /// principals prefix) are also accepted so an operator can paste
    /// an `id_ed25519.pub` straight in without first wrapping it.
    ///
    /// The parser walks token boundaries from the left and takes the
    /// first suffix that `WritVerifyingKey::from_openssh` accepts.
    /// This is robust to operator-named principals that happen to
    /// share a prefix with a keytype, and to options whose values
    /// contain whitespace inside quotes (`namespaces="a b"`): the
    /// parse-attempt succeeds at the first byte offset that yields a
    /// real OpenSSH key, regardless of how earlier tokens were split.
    ///
    /// Returns a tagged error naming the line that failed.
    pub fn from_openssh_lines(s: &str) -> Result<Self, AllowedSignersParseError> {
        let mut by_fingerprint: BTreeMap<SshKeyFingerprint, WritVerifyingKey> = BTreeMap::new();
        let mut first_line_of: BTreeMap<SshKeyFingerprint, usize> = BTreeMap::new();
        for (idx, line) in s.lines().enumerate() {
            let line_number = idx + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let key = parse_allowed_signers_line(trimmed).map_err(|source| {
                AllowedSignersParseError::InvalidKeyLine {
                    line_number,
                    source,
                }
            })?;
            let fingerprint = key.fingerprint();
            if let Some(&first) = first_line_of.get(&fingerprint) {
                return Err(AllowedSignersParseError::DuplicateFingerprint {
                    fingerprint,
                    first_line: first,
                    second_line: line_number,
                });
            }
            first_line_of.insert(fingerprint.clone(), line_number);
            by_fingerprint.insert(fingerprint, key);
        }
        Ok(Self { by_fingerprint })
    }

    /// Return the verifying key registered for `fingerprint`, if any.
    pub fn lookup(&self, fingerprint: &SshKeyFingerprint) -> Option<&WritVerifyingKey> {
        self.by_fingerprint.get(fingerprint)
    }

    /// Iterate over every fingerprint registered in the keyring. The
    /// iteration order is stable and sorted because the backing store
    /// is a [`BTreeMap`]; useful for diagnostics.
    pub fn fingerprints(&self) -> impl Iterator<Item = &SshKeyFingerprint> {
        self.by_fingerprint.keys()
    }

    /// Total number of registered keys.
    pub fn len(&self) -> usize {
        self.by_fingerprint.len()
    }

    /// Equivalent to `self.len() == 0`. Convenient at call sites that
    /// want to short-circuit before attempting a verification.
    pub fn is_empty(&self) -> bool {
        self.by_fingerprint.is_empty()
    }
}

/// Walk `line` from the left, repeatedly trying
/// [`WritVerifyingKey::from_openssh`] on the suffix starting at each
/// whitespace-delimited token boundary, and return the first key that
/// parses. This is how the principals + options prefix of a Git
/// allowed-signers entry is stripped without committing to the full
/// grammar: instead of *parsing* the prefix, we *skip* tokens until
/// the remainder is recognisable as an OpenSSH public key.
///
/// The trim-and-retry approach handles options whose values contain
/// quoted whitespace (e.g. `namespaces="a b" ssh-ed25519 …`): even if
/// our tokeniser over-splits on the embedded space, the trim eventually
/// lands at the keytype byte offset, at which point the suffix parses.
/// It also tolerates operator-named principals that happen to start
/// with a keytype prefix, because we don't pattern-match on keytype
/// names — we just ask `from_openssh` whether the suffix is valid.
///
/// If no suffix parses, the most recently captured parse error is
/// returned. That preserves the underlying `ssh-key` error code for
/// the caller without inventing a new tag for "this isn't a
/// recognisable allowed-signers line either".
fn parse_allowed_signers_line(line: &str) -> Result<WritVerifyingKey, WritSigningKeyError> {
    let mut suffix = line;
    let mut last_error: Option<WritSigningKeyError> = None;
    loop {
        suffix = suffix.trim_start();
        if suffix.is_empty() {
            break;
        }
        match WritVerifyingKey::from_openssh(suffix) {
            Ok(key) => return Ok(key),
            Err(e) => last_error = Some(e),
        }
        let token_end = suffix.find(char::is_whitespace).unwrap_or(suffix.len());
        suffix = &suffix[token_end..];
    }
    // Every non-blank line goes through at least one parse attempt
    // before we get here (the caller filters blanks), so `last_error`
    // is always populated.
    Err(last_error.expect("non-blank line should yield at least one parse error"))
}

/// Anything that can go wrong parsing an allowed-signers list. Each
/// variant names the line so an operator can fix the source file
/// without bisecting.
#[derive(Debug, thiserror::Error)]
pub enum AllowedSignersParseError {
    #[error("line {line_number}: not a valid OpenSSH public key: {source}")]
    InvalidKeyLine {
        line_number: usize,
        #[source]
        source: WritSigningKeyError,
    },
    #[error(
        "line {second_line}: key fingerprint {fingerprint} duplicates a key first seen on line \
         {first_line}"
    )]
    DuplicateFingerprint {
        fingerprint: SshKeyFingerprint,
        first_line: usize,
        second_line: usize,
    },
}

/// Failure modes for [`verify_run_envelope`]. Each variant names a
/// specific check; together they cover the three steps the verifier
/// performs in order.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// `sha256(envelope.output)` did not match
    /// `envelope.metadata.output_envelope_sha256`. The signature
    /// covers the metadata (which includes the digest), so a
    /// mismatch here means the output bytes were swapped after writ
    /// produced them. The signature would still verify in isolation;
    /// we reject before getting there.
    #[error(
        "output digest mismatch: metadata claims {expected}, recomputed from envelope.output as \
         {actual}"
    )]
    OutputDigestMismatch {
        expected: Sha256Hex,
        actual: Sha256Hex,
    },
    /// The fingerprint advertised in
    /// `envelope.metadata.signing_key_fingerprint` is not in the
    /// supplied [`AllowedSigners`]. The signature might be
    /// cryptographically valid under a key we don't know — for the
    /// verifier's purposes that's the same as invalid.
    #[error("signing key {fingerprint} is not in the allowed-signers list")]
    UnknownSigner { fingerprint: SshKeyFingerprint },
    /// The SSHSIG signature failed verification against the
    /// canonical metadata bytes under the resolved key. The wrapped
    /// error preserves the specific crypto-level cause.
    #[error("signature verification failed: {0}")]
    SignatureInvalid(#[from] signing::VerifyError),
}

/// Check that an envelope's output bytes are the ones its metadata commits to.
///
/// The first of [`verify_run_envelope`]'s three checks, exposed on its own
/// because it is the one check a caller can want *without* a keyring — and the
/// one whose absence is silent. The signature covers the metadata, and the
/// metadata covers the output only through this digest, so an envelope whose
/// body was swapped after signing still has a perfectly valid signature over
/// perfectly authentic metadata. Nothing about the note announces the swap
/// except recomputing this.
///
/// That makes it the check to run before asking anyone *else* about a note:
/// a question answered from the metadata alone — "does writ's audit log
/// corroborate this?" — is answered correctly and means nothing, because the
/// bytes the asker actually holds were never part of the question.
pub fn check_output_digest(envelope: &SignedRunEnvelope) -> Result<(), VerifyError> {
    let actual_hex = sha256_hex(&envelope.output);
    let actual = Sha256Hex::try_new(actual_hex)
        .expect("sha256_hex returns canonical 64-lowercase-hex output");
    if actual.as_str() != envelope.metadata.output_envelope_sha256.as_str() {
        return Err(VerifyError::OutputDigestMismatch {
            expected: envelope.metadata.output_envelope_sha256.clone(),
            actual,
        });
    }
    Ok(())
}

/// Verify a `SignedRunEnvelope` end-to-end.
///
/// Runs the three checks documented at the module level in the order
/// they're listed there: output digest, signer recognition, signature.
/// The function does not decode `envelope.output` as an
/// [`crate::run_envelope::OutputEnvelope`] — that's an orthogonal
/// concern. A caller that successfully verifies can then decode the
/// output bytes with full confidence the metadata is authentic.
pub fn verify_run_envelope(
    envelope: &SignedRunEnvelope,
    allowed: &AllowedSigners,
) -> Result<(), VerifyError> {
    check_output_digest(envelope)?;

    let fingerprint = &envelope.metadata.signing_key_fingerprint;
    let Some(key) = allowed.lookup(fingerprint) else {
        return Err(VerifyError::UnknownSigner {
            fingerprint: fingerprint.clone(),
        });
    };

    key.verify(&envelope.metadata.canonical_bytes(), &envelope.signature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_run::AgentRunId;
    use crate::core::{CapabilitySet, RepoRef, SessionId, UnixMillis};
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::signing::WritSigningKey;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");
    const OTHER_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing_other.key.pub");

    /// Build a freshly-signed envelope under `signing_key`. The output
    /// envelope is empty and the metadata fields are filled with stable
    /// fixtures so a metadata-tamper test can mutate any one of them.
    fn freshly_signed(signing_key: &WritSigningKey) -> SignedRunEnvelope {
        let output = OutputEnvelope {
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let output_bytes = output.to_bytes();
        let output_sha = Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap();
        let prompt_sha = Sha256Hex::try_new(sha256_hex(b"prompt")).unwrap();
        let metadata = SignedRunMetadata {
            run_id: AgentRunId::new(),
            session_id: SessionId::new(),
            prompt_sha256: prompt_sha,
            output_envelope_sha256: output_sha,
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "smaug123".into(),
                    name: "writ".into(),
                },
            }],
            exit_code: 0,
            completed_at: UnixMillis::from_millis(1_700_000_000_000),
            signing_key_fingerprint: signing_key.fingerprint(),
        };
        let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
        SignedRunEnvelope {
            metadata,
            signature,
            output: output_bytes,
        }
    }

    /// Happy path: a freshly minted envelope verifies under an
    /// allowed-signers list containing exactly its signing key. This
    /// is the contract bailiff relies on, exercised end-to-end
    /// through the real crypto.
    #[test]
    fn verify_accepts_freshly_signed_envelope() {
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let envelope = freshly_signed(&signing_key);
        let allowed = AllowedSigners::from_keys([signing_key.verifying_key()]);
        verify_run_envelope(&envelope, &allowed).expect("happy path must verify");
    }

    /// Output tampering surfaces as a digest mismatch, not as a
    /// signature failure. The signature in isolation would still
    /// verify (we didn't touch metadata bytes), so re-hashing the
    /// output bytes is what catches the swap.
    #[test]
    fn verify_rejects_tampered_output() {
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let mut envelope = freshly_signed(&signing_key);
        // Flip a byte — but only after the build, so the metadata
        // digest still pins the *pre-tamper* bytes.
        envelope.output.push(0xFF);
        let allowed = AllowedSigners::from_keys([signing_key.verifying_key()]);
        match verify_run_envelope(&envelope, &allowed) {
            Err(VerifyError::OutputDigestMismatch { .. }) => {}
            other => panic!("expected OutputDigestMismatch, got {other:?}"),
        }
    }

    /// Metadata tampering breaks signature verification: changing
    /// any field of `SignedRunMetadata` changes `canonical_bytes`,
    /// and the signature was over the original bytes. The output
    /// digest is recomputed before the signature check, so an
    /// adversary who edits metadata must also rebuild the envelope
    /// output to match — which they can't do without the signing key.
    #[test]
    fn verify_rejects_tampered_metadata() {
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let mut envelope = freshly_signed(&signing_key);
        envelope.metadata.exit_code = envelope.metadata.exit_code.wrapping_add(1);
        let allowed = AllowedSigners::from_keys([signing_key.verifying_key()]);
        match verify_run_envelope(&envelope, &allowed) {
            Err(VerifyError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    /// A fingerprint not in the keyring rejects before the signature
    /// is even consulted. Important for "we don't trust this signer"
    /// to be a distinct outcome from "the signer's signature is bad."
    #[test]
    fn verify_rejects_unknown_signer() {
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let envelope = freshly_signed(&signing_key);
        let allowed = AllowedSigners::empty();
        match verify_run_envelope(&envelope, &allowed) {
            Err(VerifyError::UnknownSigner { fingerprint }) => {
                assert_eq!(fingerprint, signing_key.fingerprint());
            }
            other => panic!("expected UnknownSigner, got {other:?}"),
        }
    }

    /// A keyring containing *only* an unrelated key still rejects.
    /// Tests that lookup is keyed strictly on fingerprint, not on
    /// "any key in the keyring will do."
    #[test]
    fn verify_rejects_when_keyring_only_holds_other_keys() {
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let envelope = freshly_signed(&signing_key);
        let other = WritVerifyingKey::from_openssh(OTHER_PUB.trim()).unwrap();
        let allowed = AllowedSigners::from_keys([other]);
        match verify_run_envelope(&envelope, &allowed) {
            Err(VerifyError::UnknownSigner { fingerprint }) => {
                assert_eq!(fingerprint, signing_key.fingerprint());
            }
            other => panic!("expected UnknownSigner, got {other:?}"),
        }
    }

    /// Parser round-trip: a single canonical OpenSSH public key
    /// parses, and the resulting keyring resolves to a working
    /// verifier. Exercises the happy path of `from_openssh_lines`.
    #[test]
    fn allowed_signers_parses_single_key() {
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        assert_eq!(allowed.len(), 1);
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let envelope = freshly_signed(&signing_key);
        verify_run_envelope(&envelope, &allowed).expect("parsed keyring must verify");
    }

    /// Blank lines and `#` comments are skipped (not parse errors).
    /// The minimal allowed-signers format would be useless without
    /// header comments — operators want to label keys.
    #[test]
    fn allowed_signers_skips_blanks_and_comments() {
        let mut source = String::new();
        source.push_str("# writ signing keys, owned by patrick\n");
        source.push('\n');
        source.push_str("   # indented comment\n");
        source.push_str(SIGNING_PUB.trim());
        source.push('\n');
        let allowed = AllowedSigners::from_openssh_lines(&source).unwrap();
        assert_eq!(allowed.len(), 1);
    }

    /// Two valid OpenSSH keys with distinct fingerprints both land
    /// in the keyring. Insertion order doesn't matter (BTreeMap),
    /// but both must be reachable by their respective fingerprints.
    #[test]
    fn allowed_signers_loads_multiple_keys() {
        let mut source = String::new();
        source.push_str(SIGNING_PUB.trim());
        source.push('\n');
        source.push_str(OTHER_PUB.trim());
        source.push('\n');
        let allowed = AllowedSigners::from_openssh_lines(&source).unwrap();
        assert_eq!(allowed.len(), 2);

        let primary = WritVerifyingKey::from_openssh(SIGNING_PUB.trim()).unwrap();
        let other = WritVerifyingKey::from_openssh(OTHER_PUB.trim()).unwrap();
        assert!(allowed.lookup(&primary.fingerprint()).is_some());
        assert!(allowed.lookup(&other.fingerprint()).is_some());
    }

    /// A duplicate of an already-registered fingerprint is a hard
    /// parse error — silently overwriting would make "which key did
    /// I trust" ambiguous, which is precisely the question
    /// allowed-signers exists to answer.
    #[test]
    fn allowed_signers_rejects_duplicate_fingerprints() {
        let mut source = String::new();
        source.push_str(SIGNING_PUB.trim());
        source.push('\n');
        source.push_str(SIGNING_PUB.trim());
        source.push('\n');
        match AllowedSigners::from_openssh_lines(&source) {
            Err(AllowedSignersParseError::DuplicateFingerprint {
                first_line,
                second_line,
                ..
            }) => {
                assert_eq!(first_line, 1);
                assert_eq!(second_line, 2);
            }
            other => panic!("expected DuplicateFingerprint, got {other:?}"),
        }
    }

    /// Git's canonical allowed-signers form has the principals field
    /// as the first whitespace-separated token: `* ssh-ed25519 …`.
    /// This is what `ssh-keygen -Y verify` reads, so accepting it
    /// is the load-bearing interop property.
    #[test]
    fn allowed_signers_parses_line_with_star_principal() {
        let line = format!("* {}", SIGNING_PUB.trim());
        let allowed = AllowedSigners::from_openssh_lines(&line).unwrap();
        assert_eq!(allowed.len(), 1);
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let envelope = freshly_signed(&signing_key);
        verify_run_envelope(&envelope, &allowed)
            .expect("entry with `*` principal must produce a usable keyring");
    }

    /// A named principal (instead of the `*` wildcard) must parse the
    /// same way: bailiff doesn't interpret principal identifiers in
    /// v1, but the entry must still produce a usable keyring.
    #[test]
    fn allowed_signers_parses_line_with_named_principal() {
        let line = format!("writ-host-1 {}", SIGNING_PUB.trim());
        let allowed = AllowedSigners::from_openssh_lines(&line).unwrap();
        assert_eq!(allowed.len(), 1);
    }

    /// Pre-keytype options like `cert-authority` and `namespaces="…"`
    /// must be tolerated even though bailiff does not interpret them
    /// in v1. The parser walks token-by-token until the keytype, so
    /// any number of options can sit between principals and keytype.
    #[test]
    fn allowed_signers_parses_line_with_options() {
        let line = format!(
            "* cert-authority namespaces=\"writ.run-agent\" {}",
            SIGNING_PUB.trim()
        );
        let allowed = AllowedSigners::from_openssh_lines(&line).unwrap();
        assert_eq!(allowed.len(), 1);
    }

    /// A complete `ssh-keygen -Y verify`-shaped file with a header
    /// comment, a `*`-principal entry, and a named-principal entry
    /// parses cleanly with both keys retrievable by fingerprint. This
    /// is the realistic deployment-config shape.
    #[test]
    fn allowed_signers_parses_realistic_allowed_signers_file() {
        let source = format!(
            "# writ allowed signers\n\
             * {primary}\n\
             writ-host-2 {other}\n",
            primary = SIGNING_PUB.trim(),
            other = OTHER_PUB.trim(),
        );
        let allowed = AllowedSigners::from_openssh_lines(&source).unwrap();
        assert_eq!(allowed.len(), 2);
        let primary = WritVerifyingKey::from_openssh(SIGNING_PUB.trim()).unwrap();
        let other = WritVerifyingKey::from_openssh(OTHER_PUB.trim()).unwrap();
        assert!(allowed.lookup(&primary.fingerprint()).is_some());
        assert!(allowed.lookup(&other.fingerprint()).is_some());
    }

    /// A malformed key line names *which* line failed so the operator
    /// can fix their source file without bisecting.
    #[test]
    fn allowed_signers_reports_line_of_malformed_key() {
        let mut source = String::new();
        source.push_str("# header\n");
        source.push_str(SIGNING_PUB.trim());
        source.push('\n');
        source.push_str("this is not a key\n");
        match AllowedSigners::from_openssh_lines(&source) {
            Err(AllowedSignersParseError::InvalidKeyLine { line_number, .. }) => {
                assert_eq!(line_number, 3);
            }
            other => panic!("expected InvalidKeyLine, got {other:?}"),
        }
    }

    /// End-to-end slice B round-trip: writ writes a signed envelope
    /// as a Git note in its own bare repo, bailiff fetches the writ
    /// notes ref into its own bare repo, and the verifier confirms
    /// the round-tripped envelope under an allowed-signers list
    /// parsed from writ's published public key.
    ///
    /// This is the operational picture slice B is delivering: every
    /// hop in the chain — note write, git fetch, byte-exact note
    /// read, sshsig verification — is exercised against the real git
    /// binary and the real crypto, with no mocks. A regression in any
    /// one component (envelope encoding, notes-write stripspace,
    /// fetch refspec handling, sha256 binding, sshsig namespace)
    /// fails this test.
    #[test]
    fn round_trip_writ_writes_bailiff_fetches_and_verifies() {
        use crate::core::NotesRef;
        use crate::notes_repo::NotesRepo;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let bailiff_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let notes_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();

        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let envelope = freshly_signed(&signing_key);
        let envelope_bytes = envelope.to_bytes();

        // writ side: persist the envelope as a note keyed on the run id.
        let target_oid = writ_repo
            .write_note(
                &notes_ref,
                envelope.metadata.run_id.to_string().as_bytes(),
                &envelope_bytes,
            )
            .unwrap();

        // bailiff side: fetch writ's notes ref into our own repo, then read.
        bailiff_repo
            .fetch_from_remote(
                writ_repo.path(),
                &["+refs/notes/writ/v1/*:refs/notes/writ/v1/*"],
            )
            .unwrap();
        let fetched_bytes = bailiff_repo.read_note(&notes_ref, &target_oid).unwrap();
        assert_eq!(
            fetched_bytes, envelope_bytes,
            "fetched note must be byte-identical to the written envelope"
        );

        // Verify under an allowed-signers list parsed from the
        // OpenSSH-line form writ would publish to bailiff's
        // allowed-signers file.
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let decoded = SignedRunEnvelope::from_bytes(&fetched_bytes).unwrap();
        verify_run_envelope(&decoded, &allowed)
            .expect("round-tripped envelope must verify under writ's published key");
    }
}
