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
//!
//! Reading the files back opens a window in which they can change, so the
//! bytes are checked against the row before they are signed — see
//! `check_matches_summary` for what that covers and what it cannot.

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
    #[error(
        "{stream} log file {} no longer matches the outcome row describing it \
         (row: {recorded_byte_len} bytes, {recorded_sha256}; file: {found_byte_len} bytes, {found_sha256})",
        path.display()
    )]
    StreamChanged {
        stream: &'static str,
        path: PathBuf,
        recorded_byte_len: u64,
        recorded_sha256: String,
        found_byte_len: u64,
        found_sha256: String,
    },
    #[error(
        "{stream} log file {} grew past the {cap}-byte read cap, but the outcome \
         row describing it records only {recorded_byte_len} retained bytes",
        path.display()
    )]
    StreamGrewPastCap {
        stream: &'static str,
        path: PathBuf,
        recorded_byte_len: u64,
        cap: usize,
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
/// Streams are read off the on-disk paths the outcome row points at and
/// re-capped at `MAX_RUN_AGENT_STREAM_BYTES` (4 MiB), which bounds this
/// call's memory footprint whatever is on disk. In practice neither arm
/// reaches that cap on the read: the host arm captures at the same 4 MiB, so
/// the file *is* what the envelope carries, and the VM arm's file is what the
/// broker wrote from the guest's upload, bounded by the outcome route's 4-MiB
/// body limit (and usually far below it, by the guest's own 1-MiB capture
/// cap). The re-cap stays because neither of those bounds is this module's to
/// enforce. What tells a verifier prefix-from-whole is the `_truncated_at`
/// marker on `OutputEnvelope`, which reflects the *capture's* truncation as
/// well as this read's.
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
        &outcome.outcome.stdout,
        crate::server::MAX_RUN_AGENT_STREAM_BYTES,
    )
    .await?;
    let (stderr_bytes, stderr_host_truncated_at) = read_stream_capped_from_disk(
        "stderr",
        &outcome.outcome.stderr,
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
    summary: &crate::agent_run::AgentRunStreamSummary,
    cap: usize,
) -> Result<(Vec<u8>, Option<u64>), MaterializeRunEnvelopeError> {
    let path = summary.path.as_path();
    let file = tokio::fs::File::open(path).await.map_err(|source| {
        MaterializeRunEnvelopeError::StreamRead {
            stream,
            path: path.to_path_buf(),
            source,
        }
    })?;
    let (bytes, truncated_at) = crate::server::capture_stream_capped(file, cap)
        .await
        .map_err(|source| MaterializeRunEnvelopeError::StreamRead {
            stream,
            path: path.to_path_buf(),
            source,
        })?;
    check_matches_summary(stream, summary, &bytes, truncated_at, cap)?;
    Ok((bytes, truncated_at))
}

/// Refuse to sign bytes the outcome row contradicts.
///
/// The row committed a length and a hash of the bytes *writ itself held* when
/// it wrote this file — computed by the host arm's capture, or re-derived by
/// the broker from the guest's upload before writing (the guest's own claim is
/// checked against the bytes at that point, so neither arm's recorded hash is
/// an unverified assertion). Between then and now, anything running as the
/// daemon's user can rewrite the file, including a detached helper left behind
/// by the very agent whose output this is. Signing whatever is on disk would
/// hand out a valid signature over bytes the audit log contradicts, and both
/// would look authoritative to whoever read them next.
///
/// So: verify, and fail rather than vouch. The truthful row stays; only the
/// envelope is withheld.
///
/// **What is checked depends on whether the whole file was read.** Below the
/// cap, `bytes` *is* the file, so length and hash are both re-derived. At or
/// past the cap the recorded hash covers retained bytes this read deliberately
/// did not finish, so it cannot be re-derived without reading the rest — up to
/// whatever the writer was allowed to retain. What remains checkable there is
/// that the row agrees the file runs past the cap at all: a row recording
/// fewer retained bytes than the cap cannot describe a file that still has
/// bytes beyond it.
fn check_matches_summary(
    stream: &'static str,
    summary: &crate::agent_run::AgentRunStreamSummary,
    bytes: &[u8],
    truncated_at: Option<u64>,
    cap: usize,
) -> Result<(), MaterializeRunEnvelopeError> {
    if truncated_at.is_some() {
        return if summary.byte_len > cap as u64 {
            Ok(())
        } else {
            Err(MaterializeRunEnvelopeError::StreamGrewPastCap {
                stream,
                path: summary.path.clone(),
                recorded_byte_len: summary.byte_len,
                cap,
            })
        };
    }
    let found_byte_len = bytes.len() as u64;
    let found_sha256 = crate::agent_run::sha256_hex(bytes);
    if found_byte_len == summary.byte_len && found_sha256 == summary.sha256_hex {
        return Ok(());
    }
    Err(MaterializeRunEnvelopeError::StreamChanged {
        stream,
        path: summary.path.clone(),
        recorded_byte_len: summary.byte_len,
        recorded_sha256: summary.sha256_hex.clone(),
        found_byte_len,
        found_sha256,
    })
}

#[cfg(test)]
mod tests;
