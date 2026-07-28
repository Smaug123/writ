//! Example/edge-case tests for [`super::materialize_signed_run_envelope`].
use super::*;
use crate::agent_run::AgentRunId;
use crate::core::UnixMillis;
use std::fs;
use std::path::Path;

/// Build an `AgentRunOutcomeAuditRecord` pointing at on-disk stdout
/// and stderr files containing the supplied bytes, with a summary that
/// honestly describes them — which is what a real run records.
///
/// A test that wants the *dishonest* case (a file that no longer matches its
/// row) builds the record here first and then rewrites the file, so the
/// mismatch is introduced the same way reality would introduce it: after the
/// row was written.
fn outcome_for_streams(
    run_dir: &Path,
    run_id: AgentRunId,
    exit_code: i32,
    stdout_bytes: &[u8],
    stderr_bytes: &[u8],
) -> crate::audit::AgentRunOutcomeAuditRecord {
    use crate::agent_run::{
        AgentRunOutcome, AgentRunStreamSummary, AgentRunTerminalStatus, sha256_hex,
    };
    fs::create_dir_all(run_dir).unwrap();
    let stdout_path = run_dir.join("stdout.log");
    let stderr_path = run_dir.join("stderr.log");
    fs::write(&stdout_path, stdout_bytes).unwrap();
    fs::write(&stderr_path, stderr_bytes).unwrap();
    let status = if exit_code == 0 {
        AgentRunTerminalStatus::Succeeded
    } else {
        AgentRunTerminalStatus::Failed
    };
    crate::audit::AgentRunOutcomeAuditRecord {
        completed_at: UnixMillis::from_millis(1_700_001_234),
        outcome: AgentRunOutcome {
            run_id,
            status,
            exit_code,
            stdout: AgentRunStreamSummary {
                path: stdout_path,
                byte_len: stdout_bytes.len() as u64,
                sha256_hex: sha256_hex(stdout_bytes),
                truncated: false,
            },
            stderr: AgentRunStreamSummary {
                path: stderr_path,
                byte_len: stderr_bytes.len() as u64,
                sha256_hex: sha256_hex(stderr_bytes),
                truncated: false,
            },
        },
    }
}

const TEST_SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");

/// The materializer reads stdout/stderr files written by the guest,
/// hashes the envelope, signs the metadata, and returns a
/// SignedRunEnvelope whose pieces a verifier can reassemble. This
/// test pins the happy path: an EC2-shaped capabilities list goes
/// in, the metadata's fields all reflect the VM-side outcome row
/// (run_id, exit_code, completed_at), and the signature verifies
/// against the envelope's canonical bytes.
#[tokio::test]
async fn materialize_vm_envelope_packs_streams_and_signs_metadata() {
    use crate::core::{CapabilitySet, RepoRef, Sha256Hex};
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::signing::WritSigningKey;

    let tmp = tempfile::tempdir().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(TEST_SIGNING_PEM).unwrap();
    let verifying_key = signing_key.verifying_key();
    let fingerprint = signing_key.fingerprint();

    let run_id = AgentRunId::new();
    let session_id = SessionId::new();
    let stdout = b"hello from inside the VM\n";
    let stderr = b"warning: noisy guest\n";
    let outcome = outcome_for_streams(
        &tmp.path().join(run_id.to_string()),
        run_id,
        0,
        stdout,
        stderr,
    );

    let prompt_sha256 = Sha256Hex::try_new(crate::agent_run::sha256_hex(b"prompt bytes")).unwrap();
    let capabilities = vec![CapabilitySet::WorkspaceWrite {
        repo: RepoRef {
            owner: "smaug123".into(),
            name: "writ".into(),
        },
    }];

    let materialized = materialize_signed_run_envelope(
        &outcome,
        session_id,
        prompt_sha256.clone(),
        capabilities.clone(),
        &signing_key,
    )
    .await
    .unwrap();

    // Metadata reflects what the VM observed, not what the
    // dispatcher made up at request time.
    assert_eq!(materialized.envelope.metadata.run_id, run_id);
    assert_eq!(materialized.envelope.metadata.session_id, session_id);
    assert_eq!(materialized.envelope.metadata.exit_code, 0);
    assert_eq!(
        materialized.envelope.metadata.completed_at,
        outcome.completed_at
    );
    assert_eq!(
        materialized.envelope.metadata.signing_key_fingerprint,
        fingerprint
    );
    assert_eq!(materialized.envelope.metadata.prompt_sha256, prompt_sha256);
    assert_eq!(materialized.envelope.metadata.capabilities, capabilities);

    // Detached signature verifies against the canonical metadata.
    verifying_key
        .verify(
            &materialized.envelope.metadata.canonical_bytes(),
            &materialized.envelope.signature,
        )
        .expect("signature must verify against canonical metadata");

    // Re-decoding the envelope from its bytes round-trips the
    // metadata + signature + output verbatim, and the inner
    // OutputEnvelope carries the streams the VM wrote.
    let decoded = SignedRunEnvelope::from_bytes(&materialized.envelope_bytes).unwrap();
    assert_eq!(decoded.metadata, materialized.envelope.metadata);
    assert_eq!(decoded.signature, materialized.envelope.signature);
    let output_envelope = OutputEnvelope::from_bytes(&decoded.output).unwrap();
    assert_eq!(output_envelope.stdout, stdout);
    assert_eq!(output_envelope.stderr, stderr);
    assert_eq!(output_envelope.stdout_truncated_at, None);
    assert_eq!(output_envelope.stderr_truncated_at, None);

    // The output_envelope_sha256 the metadata committed to matches
    // the hash of the envelope's serialised output bytes — a
    // verifier that re-encodes from the parsed form can re-derive
    // the same digest.
    assert_eq!(
        crate::agent_run::sha256_hex(&decoded.output),
        materialized
            .envelope
            .metadata
            .output_envelope_sha256
            .as_str(),
    );
}

/// A nonzero terminal exit must reach the signed metadata verbatim.
/// The host-path analogue (`run_agent_signs_non_zero_exit`) pins
/// the same invariant for synchronous spawns; the VM materializer
/// reads the exit code off the outcome row instead, but the wire
/// shape obligation is identical.
#[tokio::test]
async fn materialize_vm_envelope_propagates_nonzero_exit_code() {
    use crate::core::Sha256Hex;
    use crate::signing::WritSigningKey;

    let tmp = tempfile::tempdir().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(TEST_SIGNING_PEM).unwrap();
    let run_id = AgentRunId::new();
    let outcome = outcome_for_streams(
        &tmp.path().join(run_id.to_string()),
        run_id,
        7,
        b"",
        b"explosion in aisle 5\n",
    );

    let prompt_sha256 = Sha256Hex::try_new(crate::agent_run::sha256_hex(b"prompt")).unwrap();
    let materialized = materialize_signed_run_envelope(
        &outcome,
        SessionId::new(),
        prompt_sha256,
        vec![],
        &signing_key,
    )
    .await
    .unwrap();

    assert_eq!(materialized.envelope.metadata.exit_code, 7);
}

/// VM-side stream files are capped at 1 GiB (the audit-row policy
/// in `MAX_AGENT_RUN_STREAM_AUDIT_BYTES`) but the wire envelope's
/// per-call footprint must stay bounded at `MAX_RUN_AGENT_STREAM_BYTES`
/// (4 MiB) just as the host path does. The materializer re-caps when
/// reading off disk; the truncation marker on `OutputEnvelope` lets
/// verifiers tell prefix-from-whole.
#[tokio::test]
async fn materialize_vm_envelope_caps_streams_at_max_run_agent_stream_bytes() {
    use crate::core::Sha256Hex;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::signing::WritSigningKey;

    let tmp = tempfile::tempdir().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(TEST_SIGNING_PEM).unwrap();
    let run_id = AgentRunId::new();
    let cap = crate::server::MAX_RUN_AGENT_STREAM_BYTES;
    // Write cap + 1 KiB so the read overruns the cap on the very
    // last block, exercising the boundary clamp inside
    // `read_capped_and_hashed`.
    let stdout_bytes = vec![b'a'; cap + 1024];
    let outcome = outcome_for_streams(
        &tmp.path().join(run_id.to_string()),
        run_id,
        0,
        &stdout_bytes,
        b"",
    );

    let prompt_sha256 = Sha256Hex::try_new(crate::agent_run::sha256_hex(b"prompt")).unwrap();
    let materialized = materialize_signed_run_envelope(
        &outcome,
        SessionId::new(),
        prompt_sha256,
        vec![],
        &signing_key,
    )
    .await
    .unwrap();

    let decoded = SignedRunEnvelope::from_bytes(&materialized.envelope_bytes).unwrap();
    let output_envelope = OutputEnvelope::from_bytes(&decoded.output).unwrap();
    assert_eq!(output_envelope.stdout.len(), cap);
    assert_eq!(output_envelope.stdout_truncated_at, Some(cap as u64));
    assert!(output_envelope.stderr.is_empty());
    assert_eq!(output_envelope.stderr_truncated_at, None);
}

/// When the guest already truncated a stream (the VM HTTP runner
/// caps at `DEFAULT_AGENT_RUN_STREAM_CAPTURE_BYTES`, default 1 MiB)
/// the on-disk file is the retained prefix — strictly smaller than
/// the host's 4-MiB envelope cap. Without consulting
/// `outcome.<stream>.truncated`, the materialiser would sign the
/// prefix as if it were the whole stream. Pin: a guest-truncated
/// stream surfaces a non-None `*_truncated_at` marker pointing at
/// the retained byte length, so a verifier can tell the envelope
/// holds a prefix.
#[tokio::test]
async fn materialize_vm_envelope_preserves_guest_truncation_flag() {
    use crate::agent_run::{
        AgentRunOutcome, AgentRunStreamSummary, AgentRunTerminalStatus, sha256_hex,
    };
    use crate::core::Sha256Hex;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::signing::WritSigningKey;

    let tmp = tempfile::tempdir().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(TEST_SIGNING_PEM).unwrap();
    let run_id = AgentRunId::new();
    let run_dir = tmp.path().join(run_id.to_string());
    fs::create_dir_all(&run_dir).unwrap();
    // The retained prefix sits well under the host's 4-MiB cap so
    // `read_stream_capped_from_disk` returns host_truncated_at =
    // None. The audit row's `truncated: true` is what carries the
    // signal that this is a prefix.
    let stdout_prefix = vec![b'g'; 8 * 1024];
    let stdout_path = run_dir.join("stdout.log");
    let stderr_path = run_dir.join("stderr.log");
    fs::write(&stdout_path, &stdout_prefix).unwrap();
    fs::write(&stderr_path, b"").unwrap();
    let outcome = crate::audit::AgentRunOutcomeAuditRecord {
        completed_at: UnixMillis::from_millis(1_700_000_000),
        outcome: AgentRunOutcome {
            run_id,
            status: AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: AgentRunStreamSummary {
                path: stdout_path,
                byte_len: stdout_prefix.len() as u64,
                sha256_hex: sha256_hex(&stdout_prefix),
                truncated: true,
            },
            stderr: AgentRunStreamSummary {
                path: stderr_path,
                byte_len: 0,
                sha256_hex: sha256_hex(b""),
                truncated: false,
            },
        },
    };

    let prompt_sha256 = Sha256Hex::try_new(crate::agent_run::sha256_hex(b"prompt")).unwrap();
    let materialized = materialize_signed_run_envelope(
        &outcome,
        SessionId::new(),
        prompt_sha256,
        vec![],
        &signing_key,
    )
    .await
    .unwrap();

    let decoded = SignedRunEnvelope::from_bytes(&materialized.envelope_bytes).unwrap();
    let output_envelope = OutputEnvelope::from_bytes(&decoded.output).unwrap();
    assert_eq!(output_envelope.stdout, stdout_prefix);
    assert_eq!(
        output_envelope.stdout_truncated_at,
        Some(stdout_prefix.len() as u64),
        "guest truncation must reach the envelope marker even when the host cap doesn't fire",
    );
    assert_eq!(output_envelope.stderr_truncated_at, None);
}

/// A stream file that no longer matches the outcome row describing it must
/// not be signed.
///
/// The envelope is built by re-reading the file, but the row committed a
/// length and a hash of the bytes writ itself held when it wrote that file.
/// Between the two, anything running as the daemon's user can rewrite the
/// file — including a detached helper left behind by the very agent whose
/// output this is. Signing whatever is there would hand out a valid
/// signature over bytes the audit log contradicts, and *both* would look
/// authoritative to a reader. Refusing leaves the truthful row in place and
/// declines to vouch for the file.
#[tokio::test]
async fn a_stream_file_rewritten_after_its_outcome_row_is_refused() {
    use crate::core::Sha256Hex;
    use crate::signing::WritSigningKey;

    let tmp = tempfile::tempdir().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(TEST_SIGNING_PEM).unwrap();
    let run_id = AgentRunId::new();
    let outcome = outcome_for_streams(
        &tmp.path().join(run_id.to_string()),
        run_id,
        0,
        b"what the agent actually wrote",
        b"",
    );
    // The tamper: same run, same path, different bytes — and, deliberately,
    // the same length, so a length-only check would wave it through.
    fs::write(
        &outcome.outcome.stdout.path,
        b"what someone wrote instead!!!",
    )
    .unwrap();

    let prompt_sha256 = Sha256Hex::try_new(crate::agent_run::sha256_hex(b"prompt")).unwrap();
    let err = materialize_signed_run_envelope(
        &outcome,
        SessionId::new(),
        prompt_sha256,
        vec![],
        &signing_key,
    )
    .await
    .expect_err("a file that disagrees with its row must not be signed");
    let message = err.to_string();
    assert!(
        message.contains("stdout") && message.contains("no longer matches"),
        "the error must name the stream that changed, got: {message}",
    );
}

/// The same refusal when the file is longer than the read cap.
///
/// The check must not weaken past the cap. `read_capped_and_hashed` drains to
/// EOF regardless — it has to, to know the file ran over — so every byte is
/// read either way and the whole-file digest costs only the hashing. A
/// tamperer who keeps the length above the cap must not thereby buy a signature
/// over bytes the row contradicts.
#[tokio::test]
async fn a_stream_file_that_grew_past_the_read_cap_is_refused() {
    use crate::core::Sha256Hex;
    use crate::signing::WritSigningKey;

    let tmp = tempfile::tempdir().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(TEST_SIGNING_PEM).unwrap();
    let run_id = AgentRunId::new();
    let outcome = outcome_for_streams(
        &tmp.path().join(run_id.to_string()),
        run_id,
        0,
        b"a short, honest stream",
        b"",
    );
    let cap = crate::server::MAX_RUN_AGENT_STREAM_BYTES;
    fs::write(&outcome.outcome.stdout.path, vec![b'x'; cap + 1024]).unwrap();

    let prompt_sha256 = Sha256Hex::try_new(crate::agent_run::sha256_hex(b"prompt")).unwrap();
    let err = materialize_signed_run_envelope(
        &outcome,
        SessionId::new(),
        prompt_sha256,
        vec![],
        &signing_key,
    )
    .await
    .expect_err("a file longer than its row claims must not be signed");
    let message = err.to_string();
    assert!(
        message.contains("stdout") && message.contains("no longer matches"),
        "the error must name the stream that changed, got: {message}",
    );
}

/// An over-cap file replaced with *different* bytes of the same over-cap
/// length is still refused.
///
/// This is the case a length-only check past the cap would wave through: both
/// the row and the file agree the stream ran past 4 MiB, but the first 4 MiB —
/// the bytes that get signed — are not the audited ones. Only the whole-file
/// digest catches it.
#[tokio::test]
async fn an_over_cap_stream_file_swapped_for_different_bytes_is_refused() {
    use crate::core::Sha256Hex;
    use crate::signing::WritSigningKey;

    let tmp = tempfile::tempdir().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(TEST_SIGNING_PEM).unwrap();
    let run_id = AgentRunId::new();
    let cap = crate::server::MAX_RUN_AGENT_STREAM_BYTES;
    let audited = vec![b'a'; cap + 1024];
    let outcome = outcome_for_streams(
        &tmp.path().join(run_id.to_string()),
        run_id,
        0,
        &audited,
        b"",
    );
    // Same length, still past the cap, different bytes — including in the
    // prefix that would be signed.
    let swapped = vec![b'b'; cap + 1024];
    fs::write(&outcome.outcome.stdout.path, &swapped).unwrap();

    let prompt_sha256 = Sha256Hex::try_new(crate::agent_run::sha256_hex(b"prompt")).unwrap();
    let err = materialize_signed_run_envelope(
        &outcome,
        SessionId::new(),
        prompt_sha256,
        vec![],
        &signing_key,
    )
    .await
    .expect_err("an over-cap file whose contents changed must not be signed");
    let message = err.to_string();
    assert!(
        message.contains("stdout") && message.contains("no longer matches"),
        "the error must name the stream that changed, got: {message}",
    );
}

/// The re-read stops as soon as the file is longer than its row says, rather
/// than draining to EOF.
///
/// A file that keeps growing has no EOF: a host-spawned agent that leaves a
/// detached helper appending to its own stream file could hold `RunAgent`
/// reading and hashing forever, pinning the blocking-pool thread the run
/// occupies. The row already fixes the expected length, so one byte past it is
/// all the evidence a mismatch needs — everything after that is the attacker
/// choosing how long writ works for them.
///
/// Driven through an endless reader, with a timeout so a regression fails the
/// test instead of hanging it.
#[tokio::test]
async fn the_stream_read_stops_once_the_file_outgrows_its_row() {
    let expected_byte_len = 64u64;
    let readback = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        read_capped_and_hashed(
            tokio::io::repeat(b'x'),
            crate::server::MAX_RUN_AGENT_STREAM_BYTES,
            expected_byte_len,
        ),
    )
    .await
    .expect("the read must not chase an endless file")
    .expect("an endless reader yields no IO error");

    assert!(
        readback.file_byte_len > expected_byte_len,
        "it must read far enough to know the file outgrew its row",
    );
    // The bound is the row's length plus whatever one read returned past it,
    // not the whole stream. Anything near the 4-MiB cap means it kept going.
    assert!(
        readback.file_byte_len < crate::server::MAX_RUN_AGENT_STREAM_BYTES as u64,
        "it read {} bytes chasing a 64-byte row",
        readback.file_byte_len,
    );
}

/// A stream path that no longer names a regular file is refused, not read.
///
/// The host-spawn arm runs the agent as writd's own user, so it can find its
/// run directory and replace `stdout.log` with a FIFO before exiting. Opening
/// that FIFO blocks until someone writes, and reading it blocks with no EOF —
/// so neither the recorded length nor the recorded digest ever gets a chance
/// to catch anything, and the run hangs holding its thread. Refusing at open
/// is what turns that into an error naming the file.
///
/// Under a timeout, because the regression this pins is a hang.
#[tokio::test]
async fn a_stream_path_that_is_not_a_regular_file_is_refused() {
    use crate::core::Sha256Hex;
    use crate::signing::WritSigningKey;

    let tmp = tempfile::tempdir().unwrap();
    let signing_key = WritSigningKey::from_openssh_pem(TEST_SIGNING_PEM).unwrap();
    let run_id = AgentRunId::new();
    let outcome = outcome_for_streams(
        &tmp.path().join(run_id.to_string()),
        run_id,
        0,
        b"the bytes the row describes",
        b"",
    );
    // Swap the file for a FIFO, exactly as a departing agent could.
    let stdout_path = &outcome.outcome.stdout.path;
    fs::remove_file(stdout_path).unwrap();
    let mkfifo = std::process::Command::new("mkfifo")
        .arg(stdout_path)
        .status()
        .expect("mkfifo(1) is available");
    assert!(mkfifo.success(), "could not create the FIFO under test");

    let prompt_sha256 = Sha256Hex::try_new(crate::agent_run::sha256_hex(b"prompt")).unwrap();
    let err = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        materialize_signed_run_envelope(
            &outcome,
            SessionId::new(),
            prompt_sha256,
            vec![],
            &signing_key,
        ),
    )
    .await
    .expect("a FIFO in place of a log file must not hang the run")
    .expect_err("a FIFO in place of a log file must not be signed");
    let message = err.to_string();
    assert!(
        message.contains("stdout") && message.contains("not a regular file"),
        "the error must say what it refused and why, got: {message}",
    );
}
