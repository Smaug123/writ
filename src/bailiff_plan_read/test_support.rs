//! Shared fixtures and helpers for the `bailiff_plan_read` test
//! modules. Hoisted here so the per-verb `*_tests` modules and the
//! inline `spec` module don't each re-define the same tempdir-repo
//! plumbing, signing-key fixtures, and envelope builder.
//!
//! `super::*` re-exports the production items (`NotesRepo`, `NotesRef`,
//! …) that `bailiff_plan_read` pulls in; the explicit `use`s below
//! cover the test-only types these helpers construct. Mirrors
//! [`crate::bailiff_plan_write`]'s `test_support` sibling.

use super::*;
use crate::agent_run::{AgentRunId, sha256_hex};
use crate::core::{CapabilitySet, NotesRef, SessionId, Sha256Hex, UnixMillis};
use crate::protocol::SignedRunMetadata;
use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use crate::signing::WritSigningKey;
use tempfile::TempDir;

pub(super) const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");
pub(super) const SIGNING_PUB: &str =
    include_str!("../../tests/fixtures/ed25519_test_signing.key.pub");
pub(super) const OTHER_PEM: &str =
    include_str!("../../tests/fixtures/ed25519_test_signing_other.key");
pub(super) const OTHER_PUB: &str =
    include_str!("../../tests/fixtures/ed25519_test_signing_other.key.pub");

/// Bailiff's local notes ref for writ's per-run signed-output notes.
/// Spelled out as a literal here (rather than reusing the production
/// [`WRIT_AGENT_OUTPUTS_REF`]) so a typo in the production constant
/// surfaces as a test failure rather than passing vacuously.
pub(super) fn writ_notes_ref() -> NotesRef {
    NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
}

/// A fresh, empty bare repo standing in for bailiff's notes store.
pub(super) fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
    NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
}

/// Build a signed envelope from explicit payload parts. The signature
/// binds the generated metadata, so callers vary the inputs and still
/// get a cryptographically valid envelope back. The per-verb `freshly_signed`
/// wrappers pin their own fixed stdout/prompt/capabilities on top of this.
pub(super) fn signed_envelope(
    signing_key: &WritSigningKey,
    stdout: &[u8],
    prompt: &[u8],
    capabilities: Vec<CapabilitySet>,
) -> SignedRunEnvelope {
    let output = OutputEnvelope {
        stdout: stdout.to_vec(),
        stderr: Vec::new(),
        stdout_truncated_at: None,
        stderr_truncated_at: None,
    };
    let output_bytes = output.to_bytes();
    let output_sha = Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap();
    let prompt_sha = Sha256Hex::try_new(sha256_hex(prompt)).unwrap();
    let metadata = SignedRunMetadata {
        run_id: AgentRunId::new(),
        session_id: SessionId::new(),
        prompt_sha256: prompt_sha,
        output_envelope_sha256: output_sha,
        capabilities,
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
