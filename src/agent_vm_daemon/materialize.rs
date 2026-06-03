//! Build the signed-run envelope for a VM-mode `RunAgent` from the
//! guest-recorded outcome row plus the request-side facts.
//!
//! [`materialize_vm_signed_envelope`] is pure-with-IO: it reads the
//! guest-written stream files off disk, re-caps them, and signs the
//! canonical metadata. No network, no audit writes, no notes repo. The
//! parent daemon's `RunAgent` dispatch wires it between
//! [`super::wait_for_agent_run_outcome`] and the notes-repo write step.

use std::path::PathBuf;

use crate::core::SessionId;

/// Errors returned by [`materialize_vm_signed_envelope`].
///
/// `StreamRead` carries the failing stream and on-disk path verbatim
/// so the operator-facing message names the file the guest wrote (the
/// most likely cause of a read failure is a tmpfs that ran out, in
/// which case the path identifies the culprit directory).
/// `Sign` propagates the signing-key failure from
/// [`crate::signing::WritSigningKey::sign`].
#[derive(Debug, thiserror::Error)]
pub enum MaterializeVmEnvelopeError {
    #[error("read {stream} log file {}: {source}", path.display())]
    StreamRead {
        stream: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("sign canonical metadata: {0}")]
    Sign(#[source] crate::signing::WritSigningKeyError),
}

/// A materialised signed-run envelope plus its canonical bytes.
///
/// The envelope is what `ServerMessage::RunAgentCompleted` will return
/// (the dispatch arm pulls `metadata` and `signature` off it); the
/// bytes are what the notes-repo write step hands to
/// `notes_repo.write_note`. Returning both avoids re-serialising the
/// envelope a second time on the hot path.
#[derive(Debug)]
pub struct MaterializedVmRunEnvelope {
    pub envelope: crate::run_envelope::SignedRunEnvelope,
    pub envelope_bytes: Vec<u8>,
}

/// Build the signed-run envelope for a VM-mode `RunAgent` from the
/// guest-recorded outcome row plus the request-side facts (session id,
/// prompt hash, capabilities, signing key).
///
/// The metadata's `run_id`, `exit_code`, and `completed_at` come from
/// the outcome row — the *VM* is the source of truth for "what
/// happened inside the guest." The `session_id` reflects the
/// VM-minted audit session (the one start_agent_run_session opened),
/// not any caller-supplied id; that's what the FK chain references
/// and what a verifier should follow.
///
/// Streams are read off the on-disk paths the outcome row points at
/// and re-capped at `MAX_RUN_AGENT_STREAM_BYTES` (4 MiB) — the same
/// cap the host path applies. The guest-side audit
/// policy permits up to 1 GiB per stream, so the file on disk may be
/// substantially larger than the envelope can carry; the
/// `_truncated_at` marker on `OutputEnvelope` records the per-call
/// cap so verifiers tell prefix-from-whole.
///
/// This helper is pure-with-IO: no network, no audit writes, no notes
/// repo. The dispatch arm wires it between
/// [`wait_for_agent_run_outcome`](super::wait_for_agent_run_outcome) and
/// the notes-repo write step.
pub async fn materialize_vm_signed_envelope(
    outcome: &crate::audit::AgentRunOutcomeAuditRecord,
    session_id: SessionId,
    prompt_sha256: crate::core::Sha256Hex,
    capabilities: Vec<crate::core::CapabilitySet>,
    signing_key: &crate::signing::WritSigningKey,
) -> Result<MaterializedVmRunEnvelope, MaterializeVmEnvelopeError> {
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};

    let (stdout_bytes, stdout_host_truncated_at) = read_stream_capped_from_disk(
        "stdout",
        &outcome.outcome.stdout.path,
        crate::server::MAX_RUN_AGENT_STREAM_BYTES,
    )
    .await?;
    let (stderr_bytes, stderr_host_truncated_at) = read_stream_capped_from_disk(
        "stderr",
        &outcome.outcome.stderr.path,
        crate::server::MAX_RUN_AGENT_STREAM_BYTES,
    )
    .await?;
    // Two truncation layers stack on the VM path: the guest-side
    // capture cap (default 1 MiB per stream, configurable via
    // `DEFAULT_AGENT_RUN_STREAM_CAPTURE_BYTES`) decides what landed on
    // disk in the first place, and the host-side envelope cap
    // (`MAX_RUN_AGENT_STREAM_BYTES`, 4 MiB) re-bounds what we read off
    // disk. The on-disk file is at most the guest-retained prefix —
    // when the guest truncated, the file *is* the prefix and the
    // 4-MiB host cap doesn't fire, so `host_truncated_at` is `None`.
    // Without inspecting `outcome.outcome.<stream>.truncated`, a
    // 2-MiB-of-stdout run that the guest already cut to 1 MiB would
    // be signed as if 1 MiB were the whole stream — a verifier would
    // not see the prefix marker. Fall back to the guest-side flag
    // when the host cap didn't trigger; `byte_len` is the retained
    // prefix length when truncated, which is the correct cap point.
    let stdout_truncated_at = stdout_host_truncated_at.or(outcome
        .outcome
        .stdout
        .truncated
        .then_some(outcome.outcome.stdout.byte_len));
    let stderr_truncated_at = stderr_host_truncated_at.or(outcome
        .outcome
        .stderr
        .truncated
        .then_some(outcome.outcome.stderr.byte_len));

    let output_envelope = OutputEnvelope {
        stdout: stdout_bytes,
        stderr: stderr_bytes,
        stdout_truncated_at,
        stderr_truncated_at,
    };
    let output_envelope_bytes = output_envelope.to_bytes();
    let output_envelope_sha256_str = crate::agent_run::sha256_hex(&output_envelope_bytes);
    let output_envelope_sha256 = crate::core::Sha256Hex::try_new(output_envelope_sha256_str)
        .expect("sha256_hex returns canonical 64-lowercase-hex output");

    let metadata = SignedRunMetadata {
        run_id: outcome.outcome.run_id,
        session_id,
        prompt_sha256,
        output_envelope_sha256,
        capabilities,
        exit_code: outcome.outcome.exit_code,
        completed_at: outcome.completed_at,
        signing_key_fingerprint: signing_key.fingerprint(),
    };
    let canonical = metadata.canonical_bytes();
    let signature = signing_key
        .sign(&canonical)
        .map_err(MaterializeVmEnvelopeError::Sign)?;

    let envelope = SignedRunEnvelope {
        metadata,
        signature,
        output: output_envelope_bytes,
    };
    let envelope_bytes = envelope.to_bytes();
    Ok(MaterializedVmRunEnvelope {
        envelope,
        envelope_bytes,
    })
}

async fn read_stream_capped_from_disk(
    stream: &'static str,
    path: &std::path::Path,
    cap: usize,
) -> Result<(Vec<u8>, Option<u64>), MaterializeVmEnvelopeError> {
    let file = tokio::fs::File::open(path).await.map_err(|source| {
        MaterializeVmEnvelopeError::StreamRead {
            stream,
            path: path.to_path_buf(),
            source,
        }
    })?;
    crate::server::capture_stream_capped(file, cap)
        .await
        .map_err(|source| MaterializeVmEnvelopeError::StreamRead {
            stream,
            path: path.to_path_buf(),
            source,
        })
}
