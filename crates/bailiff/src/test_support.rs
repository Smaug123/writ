//! Test scaffolding shared by bailiff's test modules: the signing fixtures,
//! writ's notes ref, a fresh bailiff repo, and signed envelopes of the shape
//! writ's `RunAgent` handler produces.
//!
//! `writ::test_support` (behind writ's `test-support` feature) supplies the
//! pieces that are not bailiff-specific: the in-memory secret store, the
//! broker builders, PATH lookups and the key fixtures.

use tempfile::TempDir;
use writ::agent_run::{AgentRunId, sha256_hex};
use writ::core::{CapabilitySet, NotesRef, RepoRef, SessionId, UnixMillis};
use writ::notes_repo::NotesRepo;
use writ::protocol::SignedRunMetadata;
use writ::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use writ::signing::WritSigningKey;
use writ::writ_client::RunAgentCompleted;

pub(crate) use writ::test_support::ED25519_OTHER_PEM as OTHER_PEM;
pub(crate) use writ::test_support::ED25519_OTHER_PUB as OTHER_PUB;
pub(crate) use writ::test_support::ED25519_SIGNING_PEM as SIGNING_PEM;
pub(crate) use writ::test_support::ED25519_SIGNING_PUB as SIGNING_PUB;

/// Bailiff's local notes ref for writ's per-run signed-output notes. Spelled
/// out here rather than reusing the production constant, so a typo in that
/// constant surfaces as a test failure rather than passing vacuously.
pub(crate) fn writ_notes_ref() -> NotesRef {
    NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
}

/// A fresh, empty bare repo standing in for bailiff's notes store.
pub(crate) fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
    NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
}

/// Read access to `smaug123/writ`: the capability every sample run carries.
pub(crate) fn workspace_read_writ() -> CapabilitySet {
    CapabilitySet::WorkspaceRead {
        repo: RepoRef {
            owner: "smaug123".into(),
            name: "writ".into(),
        },
    }
}

/// A signed envelope from explicit payload parts. The signature binds the
/// generated metadata, so callers vary the inputs and still get a
/// cryptographically valid envelope back.
pub(crate) fn signed_envelope(
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
    let output_sha = sha256_hex(&output_bytes);
    let prompt_sha = sha256_hex(prompt);
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

/// [`signed_envelope`] for a run that printed `stdout` for `prompt` and
/// exited 0 at a fixed instant: what a stage's reader expects to find.
pub(crate) fn signed_output(
    signing_key: &WritSigningKey,
    stdout: &[u8],
    prompt: &[u8],
    capabilities: Vec<CapabilitySet>,
) -> SignedRunEnvelope {
    signed_envelope(
        signing_key,
        stdout.to_vec(),
        Vec::new(),
        prompt,
        capabilities,
        0,
        1_700_000_000_000,
    )
}

/// The canonical small envelope the example tests use: `hello` for
/// `prompt`, read access to `smaug123/writ`, signed under `signing_key`.
pub(crate) fn freshly_signed(signing_key: &WritSigningKey) -> SignedRunEnvelope {
    signed_output(
        signing_key,
        b"hello",
        b"prompt",
        vec![workspace_read_writ()],
    )
}

/// A writ repo holding `envelope` at its run id, exactly as writ's `RunAgent`
/// handler stores one, and the `RunAgentCompleted` reply bailiff would have
/// seen for it.
pub(crate) fn writ_repo_with_envelope(
    tmp: &TempDir,
    envelope: &SignedRunEnvelope,
) -> (NotesRepo, RunAgentCompleted) {
    let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
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
    (writ_repo, completed)
}
