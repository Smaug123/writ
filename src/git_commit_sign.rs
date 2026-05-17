//! App-identity SSH signatures over GitHub-bound Git commits.
//!
//! GitHub's `POST /repos/{owner}/{repo}/git/commits` accepts an
//! optional `signature` field — a detached PGP or SSH-format
//! signature over the canonical commit object GitHub itself will
//! assemble from the other fields in the request. If the signature
//! matches GitHub's canonicalisation, the resulting commit publishes
//! with `verification.verified == true`; otherwise GitHub still
//! creates the commit but flags it as unverified.
//!
//! This module owns the two pieces needed to produce such a
//! signature for the staged-push promotion path:
//!
//! 1. [`canonical_commit_bytes`] — serialise the commit's structural
//!    fields into the byte sequence Git itself would store, in the
//!    exact form `git cat-file -p <commit>` round-trips. Crucially
//!    the timestamp is rendered as `<unix_seconds> <±HHMM>` (the
//!    format Git uses internally), *not* the RFC 3339 form
//!    [`crate::github_git_db::CommitIdentity`] uses on the wire to
//!    GitHub. GitHub converts the wire-side RFC 3339 back to the
//!    `<unix> <±HHMM>` form when assembling the commit, so signing
//!    over our reproduced bytes matches their assembly bit-for-bit.
//!
//! 2. [`crate::signing::WritSigningKey::sign_commit`] — produce an
//!    SSHSIG-armored detached signature over those bytes, namespaced
//!    [`crate::signing::GIT_SSHSIG_NAMESPACE`] so the standard
//!    `ssh-keygen -Y verify` workflow recognises it as a Git commit
//!    signature (and so it cannot be replayed against writ's own
//!    run-agent namespace, or vice versa).
//!
//! The two are composed by [`sign_commit_for_github`] for the
//! single-call-site walker integration.
//!
//! Canonicalisation is deterministic on a fixed-precision input —
//! the seconds-precision RFC 3339 timestamp `CommitIdentity::new`
//! truncates to means the only way [`canonical_commit_bytes`] can
//! fail is if the stored RFC 3339 string cannot be re-parsed. That
//! never happens in practice because the same crate produced both
//! the format and the parse, but the round-trip surface is honest
//! about it.

use crate::core::{SshSignature, SshSignatureError};
use crate::github_git_db::CommitIdentity;
use crate::signing::{WritSigningKey, WritSigningKeyError};
use crate::vm_git::GitObjectId;

/// Input bundle for canonicalising and signing a single commit.
///
/// Mirrors the fields GitHub's `create_commit` API takes (tree,
/// parents, author, committer, message) so that a single
/// `CommitSigningInput` describes both "what to sign" and "what to
/// send" — there is no opportunity for the two to drift.
///
/// `parents` is rendered in the order given, matching Git's left-
/// first parent convention for merges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitSigningInput<'a> {
    pub tree: &'a GitObjectId,
    pub parents: &'a [GitObjectId],
    pub author: &'a CommitIdentity,
    pub committer: &'a CommitIdentity,
    pub message: &'a str,
}

/// Serialise `input` into the canonical Git commit object bytes.
///
/// Output shape, byte-exact:
///
/// ```text
/// tree <40-hex>\n
/// parent <40-hex>\n           (one line per parent, in `parents` order)
/// ...
/// author <name> <<email>> <unix_ts> <±HHMM>\n
/// committer <name> <<email>> <unix_ts> <±HHMM>\n
/// \n
/// <message bytes verbatim>
/// ```
///
/// No gpgsig header is emitted: the result is the *unsigned*
/// canonical form, the bytes the signature will sign. Verifiers
/// produce the same bytes the same way (the canonical form is what
/// `commit <len>\0<bytes>` hashes to, so any tool that round-trips
/// a commit through Git's object database must agree on this
/// serialisation).
///
/// The timestamp conversion goes RFC 3339 → `OffsetDateTime` →
/// `(unix_timestamp, ±HHMM)`. Sub-minute offsets are not
/// representable in the Git on-wire form and are rounded by
/// `time::UtcOffset::whole_minutes`; in practice
/// `CommitIdentity::new` only stores minute-precision offsets
/// (RFC 3339 forbids finer precision) so the rounding never
/// triggers.
pub fn canonical_commit_bytes(
    input: &CommitSigningInput<'_>,
) -> Result<Vec<u8>, CanonicalCommitError> {
    let mut out = Vec::new();
    out.extend_from_slice(b"tree ");
    out.extend_from_slice(input.tree.as_str().as_bytes());
    out.push(b'\n');
    for parent in input.parents {
        out.extend_from_slice(b"parent ");
        out.extend_from_slice(parent.as_str().as_bytes());
        out.push(b'\n');
    }
    write_identity_line(&mut out, b"author", input.author)?;
    write_identity_line(&mut out, b"committer", input.committer)?;
    out.push(b'\n');
    out.extend_from_slice(input.message.as_bytes());
    Ok(out)
}

/// Sign `input` for GitHub: canonicalise, then sign with `key`.
///
/// Convenience over [`canonical_commit_bytes`] +
/// [`WritSigningKey::sign_commit`]; threading the two through the
/// walker call site is one less moving part.
pub fn sign_commit_for_github(
    key: &WritSigningKey,
    input: &CommitSigningInput<'_>,
) -> Result<SshSignature, CommitSignError> {
    let bytes = canonical_commit_bytes(input)?;
    key.sign_commit(&bytes).map_err(CommitSignError::Sign)
}

fn write_identity_line(
    out: &mut Vec<u8>,
    prefix: &[u8],
    identity: &CommitIdentity,
) -> Result<(), CanonicalCommitError> {
    let parsed = time::OffsetDateTime::parse(
        identity.date_rfc3339(),
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|source| CanonicalCommitError::DateParse {
        date: identity.date_rfc3339().to_string(),
        source,
    })?;
    let unix_ts = parsed.unix_timestamp();
    let offset = format_git_offset(parsed.offset());
    out.extend_from_slice(prefix);
    out.push(b' ');
    out.extend_from_slice(identity.name().as_bytes());
    out.extend_from_slice(b" <");
    out.extend_from_slice(identity.email().as_bytes());
    out.extend_from_slice(b"> ");
    out.extend_from_slice(unix_ts.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(offset.as_bytes());
    out.push(b'\n');
    Ok(())
}

/// Render a `UtcOffset` as Git's `±HHMM` form (no colon).
///
/// `+0000` for UTC, `+0530` for India, `-0500` for US Eastern in
/// winter. Sub-minute offsets are rounded down via
/// `whole_minutes()`; see the rustdoc on
/// [`canonical_commit_bytes`].
fn format_git_offset(offset: time::UtcOffset) -> String {
    let total_minutes = offset.whole_minutes();
    let sign = if total_minutes < 0 { '-' } else { '+' };
    let abs = total_minutes.unsigned_abs() as u32;
    let hours = abs / 60;
    let minutes = abs % 60;
    format!("{sign}{hours:02}{minutes:02}")
}

/// Failures from [`canonical_commit_bytes`].
#[derive(Debug, thiserror::Error)]
pub enum CanonicalCommitError {
    /// A [`CommitIdentity`]'s RFC 3339 timestamp could not be
    /// re-parsed. Indicates either the `time` crate's RFC 3339
    /// formatter and parser have diverged (a bug — they round-trip
    /// by contract) or that a `CommitIdentity` was constructed by
    /// some path that bypassed [`CommitIdentity::new`]'s validation.
    #[error("commit date {date:?} could not be re-parsed as RFC 3339: {source}")]
    DateParse {
        date: String,
        #[source]
        source: time::error::Parse,
    },
}

/// Failures from [`sign_commit_for_github`]. Either canonicalisation
/// failed (see [`CanonicalCommitError`]) or the SSH signing step
/// itself failed (see [`WritSigningKeyError`]).
#[derive(Debug, thiserror::Error)]
pub enum CommitSignError {
    #[error("commit canonicalisation failed: {0}")]
    Canonicalise(#[from] CanonicalCommitError),
    #[error("SSH commit signing failed: {0}")]
    Sign(WritSigningKeyError),
    /// The signed bytes round-tripped through the SSHSIG armorer
    /// produced a value that does not match the
    /// [`SshSignature`] wire-validation regex. Indicates a bug in
    /// the SSHSIG encoder rather than a bad input.
    #[error("SSHSIG armor did not pass wire validation: {0}")]
    Newtype(SshSignatureError),
}

#[cfg(test)]
mod tests {
    use ssh_key::SshSig;
    use time::macros::datetime;

    use super::*;
    use crate::signing::{GIT_SSHSIG_NAMESPACE, WRIT_SSHSIG_NAMESPACE};

    const PRIVATE_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const PUBLIC_OPENSSH: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");

    fn ascii_oid(nibble: char) -> GitObjectId {
        GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
    }

    fn identity(name: &str, email: &str, date: time::OffsetDateTime) -> CommitIdentity {
        CommitIdentity::new(name, email, date).expect("sample date is RFC 3339 representable")
    }

    fn load_signing_key() -> WritSigningKey {
        WritSigningKey::from_openssh_pem(PRIVATE_PEM).expect("fixture private key parses")
    }

    fn load_public_key() -> ssh_key::PublicKey {
        ssh_key::PublicKey::from_openssh(PUBLIC_OPENSSH).expect("fixture public key parses")
    }

    /// Reference: a single-parent commit with UTC dates serialises
    /// to exactly the bytes Git would store. The fixture is
    /// hand-derived from the documented format; if this test
    /// breaks, either the format has been miswritten or the wire
    /// has drifted from Git's on-disk shape.
    #[test]
    fn canonical_bytes_match_known_single_parent_utc_fixture() {
        let tree = ascii_oid('1');
        let parent = ascii_oid('2');
        let author = identity(
            "Alice",
            "alice@example.invalid",
            datetime!(2024-01-15 10:30:45 UTC),
        );
        let committer = identity(
            "Bot",
            "bot@example.invalid",
            datetime!(2024-01-15 10:30:50 UTC),
        );
        let message = "fix the thing\n\nCo-authored-by: B <b@example.invalid>\n";

        let bytes = canonical_commit_bytes(&CommitSigningInput {
            tree: &tree,
            parents: std::slice::from_ref(&parent),
            author: &author,
            committer: &committer,
            message,
        })
        .expect("canonicalise must succeed");

        // Hand-derived expected output. Unix timestamps:
        //   2024-01-15T10:30:45Z -> 1705314645
        //   2024-01-15T10:30:50Z -> 1705314650
        let expected = format!(
            "tree {tree}\n\
             parent {parent}\n\
             author Alice <alice@example.invalid> 1705314645 +0000\n\
             committer Bot <bot@example.invalid> 1705314650 +0000\n\
             \n\
             {message}",
            tree = tree.as_str(),
            parent = parent.as_str(),
            message = message,
        );
        assert_eq!(
            std::str::from_utf8(&bytes).expect("canonical bytes are UTF-8 for ASCII inputs"),
            expected,
        );
    }

    /// A root commit (no parents) emits no `parent` lines. The
    /// header lines, blank line, and verbatim message invariant
    /// still hold.
    #[test]
    fn canonical_bytes_handle_zero_parents() {
        let tree = ascii_oid('a');
        let author = identity("Alice", "a@x", datetime!(2024-01-15 10:30:45 UTC));
        let committer = identity("Alice", "a@x", datetime!(2024-01-15 10:30:45 UTC));
        let message = "root\n";

        let bytes = canonical_commit_bytes(&CommitSigningInput {
            tree: &tree,
            parents: &[],
            author: &author,
            committer: &committer,
            message,
        })
        .expect("canonicalise must succeed");

        let expected = format!(
            "tree {tree}\n\
             author Alice <a@x> 1705314645 +0000\n\
             committer Alice <a@x> 1705314645 +0000\n\
             \n\
             root\n",
            tree = tree.as_str(),
        );
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);
    }

    /// A merge commit with two parents emits two `parent` lines in
    /// the order supplied. Git distinguishes first-parent from
    /// subsequent parents, so the order must be preserved verbatim
    /// — a swap would change the commit's identity.
    #[test]
    fn canonical_bytes_handle_multiple_parents_in_order() {
        let tree = ascii_oid('1');
        let p1 = ascii_oid('a');
        let p2 = ascii_oid('b');
        let author = identity("Alice", "a@x", datetime!(2024-01-15 10:30:45 UTC));
        let committer = identity("Alice", "a@x", datetime!(2024-01-15 10:30:45 UTC));
        let message = "merge\n";

        let bytes = canonical_commit_bytes(&CommitSigningInput {
            tree: &tree,
            parents: &[p1.clone(), p2.clone()],
            author: &author,
            committer: &committer,
            message,
        })
        .expect("canonicalise must succeed");

        let expected = format!(
            "tree {tree}\n\
             parent {p1}\n\
             parent {p2}\n\
             author Alice <a@x> 1705314645 +0000\n\
             committer Alice <a@x> 1705314645 +0000\n\
             \n\
             merge\n",
            tree = tree.as_str(),
            p1 = p1.as_str(),
            p2 = p2.as_str(),
        );
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);
    }

    /// Non-UTC offsets render as `±HHMM` (no colon, four digits).
    /// US Eastern in winter is -05:00 in RFC 3339 form, -0500 in
    /// Git's canonical form.
    #[test]
    fn canonical_bytes_emit_non_utc_offset_in_hhmm_form() {
        let tree = ascii_oid('1');
        let author = identity("Alice", "a@x", datetime!(2024-01-15 05:30:45 -5:00));
        let committer = identity("Alice", "a@x", datetime!(2024-01-15 05:30:45 -5:00));
        let message = "x\n";

        let bytes = canonical_commit_bytes(&CommitSigningInput {
            tree: &tree,
            parents: &[],
            author: &author,
            committer: &committer,
            message,
        })
        .expect("canonicalise must succeed");

        // 2024-01-15T05:30:45-05:00 == 2024-01-15T10:30:45Z == 1705314645
        let expected = format!(
            "tree {tree}\n\
             author Alice <a@x> 1705314645 -0500\n\
             committer Alice <a@x> 1705314645 -0500\n\
             \n\
             x\n",
            tree = tree.as_str(),
        );
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);
    }

    /// India is +05:30 — a half-hour offset; the canonical form
    /// must preserve the minutes digit, not round to `+0500`.
    #[test]
    fn canonical_bytes_emit_half_hour_offset() {
        let tree = ascii_oid('1');
        let author = identity("Alice", "a@x", datetime!(2024-01-15 16:00:45 +5:30));
        let committer = identity("Alice", "a@x", datetime!(2024-01-15 16:00:45 +5:30));
        let message = "x\n";

        let bytes = canonical_commit_bytes(&CommitSigningInput {
            tree: &tree,
            parents: &[],
            author: &author,
            committer: &committer,
            message,
        })
        .expect("canonicalise must succeed");

        // 2024-01-15T16:00:45+05:30 == 2024-01-15T10:30:45Z == 1705314645
        let expected = format!(
            "tree {tree}\n\
             author Alice <a@x> 1705314645 +0530\n\
             committer Alice <a@x> 1705314645 +0530\n\
             \n\
             x\n",
            tree = tree.as_str(),
        );
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);
    }

    /// A commit signed by [`WritSigningKey::sign_commit`] must
    /// verify under the `"git"` SSHSIG namespace (the standard
    /// `ssh-keygen -Y verify` workflow Git itself uses) and must
    /// *not* verify under the writ-run-agent namespace. SSHSIG
    /// mixes the namespace into the hashed prefix, so namespace
    /// separation falls out of the primitive — but a regression
    /// that hardcoded the wrong constant would silently let a
    /// run-agent signature pass off as a commit signature, hence
    /// the explicit negative case.
    #[test]
    fn sign_commit_uses_git_namespace_so_verifies_under_git_not_writ() {
        let key = load_signing_key();
        let pubk = load_public_key();
        let bytes = b"tree abc\nauthor Alice <a@x> 0 +0000\ncommitter Alice <a@x> 0 +0000\n\nx\n";
        let sig = key.sign_commit(bytes).expect("sign must succeed");

        let parsed: SshSig = sig.as_str().parse().expect("armored sshsig parses");
        pubk.verify(GIT_SSHSIG_NAMESPACE, bytes, &parsed)
            .expect("commit signature must verify under git namespace");

        let writ_namespace_result = pubk.verify(WRIT_SSHSIG_NAMESPACE, bytes, &parsed);
        assert!(
            writ_namespace_result.is_err(),
            "commit signature must not verify under run-agent namespace"
        );
    }

    /// `WritSigningKey::sign` (run-agent namespace) and `sign_commit`
    /// (git namespace) operating on the same bytes with the same key
    /// must produce signatures that do not cross-verify. The
    /// existing run-agent tests cover one direction; this test
    /// covers the other so a future refactor that swapped namespaces
    /// would fail loudly.
    #[test]
    fn run_agent_signature_does_not_verify_as_a_commit_signature() {
        let key = load_signing_key();
        let pubk = load_public_key();
        let bytes = b"tree abc\nauthor Alice <a@x> 0 +0000\ncommitter Alice <a@x> 0 +0000\n\nx\n";
        let run_agent_sig = key.sign(bytes).expect("sign must succeed");

        let parsed: SshSig = run_agent_sig.as_str().parse().unwrap();
        let result = pubk.verify(GIT_SSHSIG_NAMESPACE, bytes, &parsed);
        assert!(
            result.is_err(),
            "run-agent-namespaced signature must not verify under git namespace"
        );
    }

    /// End-to-end: `sign_commit_for_github` produces a verifiable
    /// SSHSIG over the canonicalised bytes. This is the property
    /// the walker integration will lean on (the wire body's
    /// `signature` field round-trips through verification against
    /// the canonical bytes).
    #[test]
    fn sign_commit_for_github_signs_canonicalised_bytes() {
        let key = load_signing_key();
        let pubk = load_public_key();
        let tree = ascii_oid('1');
        let author = identity("Alice", "a@x", datetime!(2024-01-15 10:30:45 UTC));
        let committer = identity("Alice", "a@x", datetime!(2024-01-15 10:30:45 UTC));
        let input = CommitSigningInput {
            tree: &tree,
            parents: &[],
            author: &author,
            committer: &committer,
            message: "x\n",
        };

        let sig = sign_commit_for_github(&key, &input).expect("sign must succeed");
        let canonical = canonical_commit_bytes(&input).unwrap();

        let parsed: SshSig = sig.as_str().parse().unwrap();
        pubk.verify(GIT_SSHSIG_NAMESPACE, &canonical, &parsed)
            .expect("signature must verify against the canonicalised bytes");
    }

    /// Tampering with the canonicalised bytes (e.g. a single
    /// character change in the message) must invalidate the
    /// signature. The point of the signature is to attest to the
    /// exact bytes; a single-byte alteration is the smallest
    /// detectable change.
    #[test]
    fn signature_does_not_verify_after_byte_tamper() {
        let key = load_signing_key();
        let pubk = load_public_key();
        let bytes = b"tree abc\nauthor Alice <a@x> 0 +0000\ncommitter Alice <a@x> 0 +0000\n\nx\n";
        let sig = key.sign_commit(bytes).unwrap();

        let parsed: SshSig = sig.as_str().parse().unwrap();
        let mut tampered = bytes.to_vec();
        let last = tampered.len() - 2;
        tampered[last] = b'Y';
        let result = pubk.verify(GIT_SSHSIG_NAMESPACE, &tampered, &parsed);
        assert!(result.is_err(), "tampered canonical bytes must not verify");
    }
}
