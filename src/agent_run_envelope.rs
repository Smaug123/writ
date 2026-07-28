//! Build the signed-run envelope for a finished `RunAgent` from its
//! `agent_run_outcome` row plus the request-side facts.
//!
//! [`materialize_signed_run_envelope`] is pure-with-IO: it reads the recorded
//! stream files off disk, re-caps them, and signs the canonical metadata. No
//! network, no audit writes, no notes repo.
//!
//! **Both `RunAgent` arms come through here**, which is the point: the
//! envelope a verifier receives must mean the same thing whether the agent
//! ran on the host or inside a guest VM. Its inputs are the audit row and the
//! files that row names — never an in-memory capture — so the signed bytes
//! describe what actually survived the run, and the two arms cannot drift
//! into signing subtly different things. `crate::server`'s `run_agent`
//! dispatch wires it between the outcome row and the notes-repo write step.

use std::path::PathBuf;

use crate::core::SessionId;

/// Errors returned by [`materialize_signed_run_envelope`].
///
/// `StreamRead` carries the failing stream and on-disk path verbatim
/// so the operator-facing message names the file whoever ran the agent
/// wrote (the most likely cause of a read failure is a filesystem that
/// ran out, in which case the path identifies the culprit directory).
/// `Sign` propagates the signing-key failure from
/// [`crate::signing::WritSigningKey::sign`].
#[derive(Debug, thiserror::Error)]
pub enum MaterializeRunEnvelopeError {
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
pub struct MaterializedRunEnvelope {
    pub envelope: crate::run_envelope::SignedRunEnvelope,
    pub envelope_bytes: Vec<u8>,
}

/// Build the signed-run envelope for a finished `RunAgent` from its
/// outcome row plus the request-side facts (session id, prompt hash,
/// capabilities, signing key).
///
/// The metadata's `run_id`, `exit_code`, and `completed_at` come from
/// the outcome row — whoever ran the agent is the source of truth for
/// "what happened", and the row is what they recorded. `session_id` is
/// the session the run is *audited* under: the VM-minted one on the VM
/// arm (opened by `start_agent_run_session`), the caller's on the
/// host-spawn arm. Either way it is the session the `agent_run` row's
/// foreign key points at, which is what a verifier should follow.
///
/// Streams are read off the on-disk paths the outcome row points at
/// and re-capped at `MAX_RUN_AGENT_STREAM_BYTES` (4 MiB). On the host
/// arm the capture cap is that same 4 MiB, so the file *is* what the
/// envelope carries. On the VM arm the guest-side audit policy permits
/// up to 1 GiB per stream, so the file on disk may be substantially
/// larger than the envelope can carry; the `_truncated_at` marker on
/// `OutputEnvelope` records the per-call cap so verifiers tell
/// prefix-from-whole either way.
///
/// This helper is pure-with-IO: no network, no audit writes, no notes
/// repo. Each dispatch arm wires it between the outcome row and the
/// notes-repo write step.
pub async fn materialize_signed_run_envelope(
    outcome: &crate::audit::AgentRunOutcomeAuditRecord,
    session_id: SessionId,
    prompt_sha256: crate::core::Sha256Hex,
    capabilities: Vec<crate::core::CapabilitySet>,
    signing_key: &crate::signing::WritSigningKey,
) -> Result<MaterializedRunEnvelope, MaterializeRunEnvelopeError> {
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
    // Two truncation layers stack: the *capture* cap decided what landed on
    // disk in the first place (1 MiB per stream by default inside a guest,
    // per `DEFAULT_AGENT_RUN_STREAM_CAPTURE_BYTES`; 4 MiB on the host arm),
    // and the envelope cap (`MAX_RUN_AGENT_STREAM_BYTES`, 4 MiB) re-bounds
    // what we read back off disk. The file is at most the retained prefix, so
    // whenever the capture already truncated, the file *is* that prefix and
    // the read-back cap does not fire — `host_truncated_at` is `None` even
    // though the stream was longer. Without consulting
    // `outcome.outcome.<stream>.truncated` the envelope would then be signed
    // as if the prefix were the whole stream and a verifier would see no
    // marker: certain on the host arm (where the two caps are equal, so the
    // read-back cap *never* fires) and common on the VM arm. Fall back to the
    // recorded flag when the read-back cap didn't trigger; `byte_len` is the
    // retained prefix length when truncated, which is the correct cap point.
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
        .map_err(MaterializeRunEnvelopeError::Sign)?;

    let envelope = SignedRunEnvelope {
        metadata,
        signature,
        output: output_envelope_bytes,
    };
    let envelope_bytes = envelope.to_bytes();
    Ok(MaterializedRunEnvelope {
        envelope,
        envelope_bytes,
    })
}

async fn read_stream_capped_from_disk(
    stream: &'static str,
    path: &std::path::Path,
    cap: usize,
) -> Result<(Vec<u8>, Option<u64>), MaterializeRunEnvelopeError> {
    let file = tokio::fs::File::open(path).await.map_err(|source| {
        MaterializeRunEnvelopeError::StreamRead {
            stream,
            path: path.to_path_buf(),
            source,
        }
    })?;
    crate::server::capture_stream_capped(file, cap)
        .await
        .map_err(|source| MaterializeRunEnvelopeError::StreamRead {
            stream,
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests;
