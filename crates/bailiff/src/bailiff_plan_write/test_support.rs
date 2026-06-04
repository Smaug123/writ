//! Shared fixtures and helpers for the `bailiff_plan_write` test
//! modules. Hoisted here so the per-verb `*_tests` modules and the
//! inline `spec` module don't each re-define the same envelope builder
//! and tempdir-repo plumbing.
//!
//! `super::*` re-exports the production items (`NotesRepo`,
//! `RunAgentCompleted`, `AllowedSigners`, …) that bailiff_plan_write
//! pulls in privately; the explicit `use`s below cover the test-only
//! types those helpers construct.

use super::*;
use tempfile::TempDir;
use writ::agent_run::{AgentRunId, sha256_hex};
use writ::core::{CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
use writ::protocol::SignedRunMetadata;
use writ::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use writ::signing::WritSigningKey;

pub(super) const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");
pub(super) const SIGNING_PUB: &str =
    include_str!("../../tests/fixtures/ed25519_test_signing.key.pub");
pub(super) const OTHER_PUB: &str =
    include_str!("../../tests/fixtures/ed25519_test_signing_other.key.pub");

pub(super) fn writ_notes_ref() -> NotesRef {
    NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
}

pub(super) fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
    NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
}

/// Build a signed envelope from explicit payload parts. The signature
/// binds the generated metadata, so callers vary the inputs and still
/// get a cryptographically valid envelope back. The `spec` module
/// drives this with arbitrary payloads; `freshly_signed` is the fixed
/// default the example tests use.
pub(super) fn signed_envelope(
    signing_key: &WritSigningKey,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    prompt: &[u8],
    capabilities: Vec<CapabilitySet>,
    exit_code: i32,
    completed_at_millis: i64,
) -> SignedRunEnvelope {
    let output = OutputEnvelope {
        stdout,
        stderr,
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
        exit_code,
        completed_at: UnixMillis::from_millis(completed_at_millis),
        signing_key_fingerprint: signing_key.fingerprint(),
    };
    let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
    SignedRunEnvelope {
        metadata,
        signature,
        output: output_bytes,
    }
}

/// The canonical envelope the example tests use: a small fixed payload
/// signed under `signing_key`. Mirrors the `freshly_signed` helper in
/// `run_verify.rs` tests so the envelope shape is the realistic one
/// writ produces.
pub(super) fn freshly_signed(signing_key: &WritSigningKey) -> SignedRunEnvelope {
    signed_envelope(
        signing_key,
        b"hello".to_vec(),
        Vec::new(),
        b"prompt",
        vec![CapabilitySet::WorkspaceRead {
            repo: RepoRef {
                owner: "smaug123".into(),
                name: "writ".into(),
            },
        }],
        0,
        1_700_000_000_000,
    )
}

/// Prepare a writ repo containing one signed envelope keyed on the run
/// id, exactly the shape writ's `RunAgent` handler produces. Returns
/// the writ repo, the `RunAgentCompleted` reply bailiff would have
/// seen, and the envelope itself for tampering tests.
pub(super) fn writ_repo_with_envelope(
    tmp: &TempDir,
    signing_key: &WritSigningKey,
) -> (NotesRepo, RunAgentCompleted, SignedRunEnvelope) {
    let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let envelope = freshly_signed(signing_key);
    let target = writ_repo
        .write_note(
            &writ_notes_ref(),
            envelope.metadata.run_id.to_string().as_bytes(),
            &envelope.to_bytes(),
        )
        .unwrap();
    let completed = RunAgentCompleted {
        output_oid: target,
        signed_metadata: envelope.metadata.clone(),
        signature: envelope.signature.clone(),
    };
    (writ_repo, completed, envelope)
}
