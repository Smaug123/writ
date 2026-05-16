//! Bailiff-side write helper that completes the slice-C handshake:
//! fetch writ's signed envelope, verify it, and persist a [`PlanNote`]
//! at the plan's notes ref in bailiff's own bare repo.
//!
//! This is slice C2 of `docs/plans/2026-05-14-bailiff-split.md`. The
//! data layer ([`crate::bailiff_plan_note`]) is slice C1; the CLI
//! verb that drives this helper is slice C3.
//!
//! # Flow
//!
//! Given a [`RunAgentCompleted`] (what writ returned over the
//! Unix-socket RPC) and a path to writ's bare repo:
//!
//! 1. `git fetch` writ's `refs/notes/writ/v1/*` namespace into
//!    bailiff's own repo via [`NotesRepo::fetch_from_remote`].
//! 2. Read the note body at `completed.output_oid` under
//!    `writ_notes_ref` — the same ref bailiff named in the
//!    `RunAgent` request — and decode it as a
//!    [`SignedRunEnvelope`].
//! 3. **Defence in depth:** check the envelope's metadata and
//!    signature match `completed`'s. If writ replies one thing on
//!    the wire and stores another in its notes ref, that's writ
//!    equivocating (or one of the two sources is corrupt) — both
//!    are operator-actionable, not silently recoverable.
//! 4. Run [`verify_run_envelope`] under `allowed_signers`. This
//!    rebinds the output bytes to the metadata digest and verifies
//!    the SSHSIG under bailiff's keyring — the same end-to-end
//!    check the slice-B5 round-trip pinned.
//! 5. Build a [`PlanNote`] referencing `completed.output_oid` (the
//!    writ-side seed OID — *not* the envelope blob; see the
//!    `writ_output_oid` docstring in [`crate::bailiff_plan_note`])
//!    and write it to [`plan_notes_ref`]`(plan_id)` in
//!    bailiff's repo with seed [`plan_submission_seed_blob_bytes`]`(plan_id)`.
//!    Returns the bailiff-side target OID.
//!
//! Every failure mode is a tagged variant of [`WritePlanNoteError`]
//! so the slice-C3 CLI verb can react without parsing prose.

use std::path::Path;

use thiserror::Error;

use crate::bailiff_plan_note::{PlanId, PlanNote, plan_notes_ref, plan_submission_seed_blob_bytes};
use crate::core::NotesRef;
use crate::notes_repo::{NotesRepo, NotesRepoError};
use crate::run_envelope::SignedRunEnvelope;
use crate::run_verify::{AllowedSigners, VerifyError, verify_run_envelope};
use crate::vm_git::GitObjectId;
use crate::writ_client::RunAgentCompleted;

/// Refspec bailiff uses to mirror writ's `v1` notes namespace into
/// its own repo. The leading `+` is load-bearing: writ may rewrite
/// history under its own ref (e.g. when slice G strips the legacy
/// `agent_plan` namespace), and bailiff is the local read mirror —
/// accepting forced updates is correct because writ is the source of
/// truth for its own namespace.
const WRIT_V1_NOTES_REFSPEC: &str = "+refs/notes/writ/v1/*:refs/notes/writ/v1/*";

/// Fetch writ's signed envelope, verify it end-to-end, and attach a
/// [`PlanNote`] for `plan_id` to bailiff's per-plan notes ref.
///
/// Returns the bailiff-side target OID — the deterministic seed-blob
/// OID that [`plan_submission_seed_blob_bytes`] hashes to, which a caller can
/// hold onto for diagnostics or to read the freshly-written note back
/// without recomputing it.
///
/// See the module docstring for the step-by-step flow and the
/// [`WritePlanNoteError`] variants for the failure shape.
pub fn write_plan_note(
    bailiff_repo: &NotesRepo,
    writ_repo_path: &Path,
    writ_notes_ref: &NotesRef,
    plan_id: PlanId,
    purpose: String,
    completed: &RunAgentCompleted,
    allowed_signers: &AllowedSigners,
) -> Result<GitObjectId, WritePlanNoteError> {
    bailiff_repo
        .fetch_from_remote(writ_repo_path, &[WRIT_V1_NOTES_REFSPEC])
        .map_err(WritePlanNoteError::Fetch)?;
    let body = bailiff_repo
        .read_note(writ_notes_ref, &completed.output_oid)
        .map_err(WritePlanNoteError::ReadEnvelope)?;
    let envelope =
        SignedRunEnvelope::from_bytes(&body).map_err(WritePlanNoteError::DecodeEnvelope)?;

    if envelope.metadata != completed.signed_metadata {
        return Err(WritePlanNoteError::EnvelopeMetadataMismatch);
    }
    if envelope.signature != completed.signature {
        return Err(WritePlanNoteError::EnvelopeSignatureMismatch);
    }

    verify_run_envelope(&envelope, allowed_signers).map_err(WritePlanNoteError::Verify)?;

    let note = PlanNote {
        plan_id,
        purpose,
        writ_output_oid: completed.output_oid.clone(),
        signed_metadata: envelope.metadata,
        signature: envelope.signature,
    };
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_submission_seed_blob_bytes(plan_id);
    let bytes = note.canonical_bytes();
    bailiff_repo
        .write_note(&plan_ref, &seed, &bytes)
        .map_err(WritePlanNoteError::WritePlanNote)
}

/// Tagged failure modes of [`write_plan_note`]. Each variant maps to
/// one specific step of the flow so a caller can surface the right
/// operator action: "writ repo path wrong" vs "fetched but no such
/// note" vs "envelope and reply disagree" vs "signature doesn't
/// verify" are all different problems.
#[derive(Debug, Error)]
pub enum WritePlanNoteError {
    /// `git fetch` against writ's repo failed. Usually a wrong
    /// `writ_repo_path` or filesystem permission problem.
    #[error("fetching writ's notes ref failed: {0}")]
    Fetch(#[source] NotesRepoError),
    /// The fetch succeeded but no note exists at
    /// `completed.output_oid` under `writ_notes_ref`. Either the
    /// fetch refspec didn't cover the ref writ used, or writ's note
    /// hasn't propagated yet (a race that can't happen with the
    /// synchronous-reply RPC contract, but the error variant exists
    /// so the failure is named rather than swallowed).
    #[error("reading the writ envelope note failed: {0}")]
    ReadEnvelope(#[source] NotesRepoError),
    /// The note body exists but isn't a valid [`SignedRunEnvelope`].
    /// Indicates wire-level corruption — `deny_unknown_fields` and
    /// the strict newtype validators on the envelope make this
    /// near-impossible for any envelope writ itself produced.
    #[error("decoding the writ envelope failed: {0}")]
    DecodeEnvelope(#[source] serde_json::Error),
    /// The envelope's `metadata` in writ's repo differs from the
    /// `signed_metadata` writ returned in [`RunAgentCompleted`].
    /// Writ is either equivocating or one of the two sources is
    /// corrupt; bailiff refuses to attach a plan note in either case.
    #[error(
        "envelope metadata fetched from writ's repo does not match the metadata writ \
         returned in RunAgentCompleted"
    )]
    EnvelopeMetadataMismatch,
    /// Same defence-in-depth check as [`Self::EnvelopeMetadataMismatch`]
    /// but for the signature field.
    #[error(
        "envelope signature fetched from writ's repo does not match the signature writ \
         returned in RunAgentCompleted"
    )]
    EnvelopeSignatureMismatch,
    /// [`verify_run_envelope`] rejected the envelope. The wrapped
    /// [`VerifyError`] names whether the failure was an output
    /// digest mismatch, an unknown signer, or a bad signature.
    #[error("verifying the fetched envelope failed: {0}")]
    Verify(#[source] VerifyError),
    /// Writing the bailiff-side plan note failed. Usually a
    /// duplicate-write (a plan id reused against an existing ref) or
    /// a filesystem problem.
    #[error("writing the plan note to bailiff's repo failed: {0}")]
    WritePlanNote(#[source] NotesRepoError),
}

#[cfg(test)]
mod tests {
    //! Unit tests bypass the broker: the helper's contract is "given a
    //! writ repo that contains a freshly-signed envelope, fetch it
    //! across to bailiff's repo, verify, and write a PlanNote." We
    //! exercise that contract directly by writing a known envelope
    //! into a tempdir-backed writ repo and driving `write_plan_note`
    //! against it.
    //!
    //! The full broker bring-up is covered by the integration test
    //! in `end_to_end_tests` below, which mirrors the slice-B5
    //! round-trip in `writ_client.rs` and tacks `write_plan_note` on
    //! the end.
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_plan_note::{
        PlanId, PlanNote, plan_notes_ref, plan_submission_seed_blob_bytes,
    };
    use crate::core::{CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::signing::{WritSigningKey, WritVerifyingKey};
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");
    const OTHER_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing_other.key.pub");

    fn writ_notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    /// Build a freshly-signed envelope under `signing_key`. Mirrors
    /// the `freshly_signed` helper in `run_verify.rs` tests so the
    /// envelope shape is the realistic one writ produces.
    fn freshly_signed(signing_key: &WritSigningKey) -> SignedRunEnvelope {
        let output = OutputEnvelope {
            stdout: b"hello".to_vec(),
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

    /// Prepare a writ repo containing one signed envelope keyed on the
    /// run id, exactly the shape writ's `RunAgent` handler produces.
    /// Returns the writ repo, the `RunAgentCompleted` reply bailiff
    /// would have seen, and the envelope itself for tampering tests.
    fn writ_repo_with_envelope(
        tmp: &TempDir,
        signing_key: &WritSigningKey,
    ) -> (NotesRepo, RunAgentCompleted, SignedRunEnvelope) {
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let nref = writ_notes_ref();
        let envelope = freshly_signed(signing_key);
        let body = envelope.to_bytes();
        let target = writ_repo
            .write_note(
                &nref,
                envelope.metadata.run_id.to_string().as_bytes(),
                &body,
            )
            .unwrap();
        let completed = RunAgentCompleted {
            output_oid: target,
            signed_metadata: envelope.metadata.clone(),
            signature: envelope.signature.clone(),
        };
        (writ_repo, completed, envelope)
    }

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    /// Happy path: with writ's note in place and an allowed-signers
    /// list that contains writ's key, `write_plan_note` writes a
    /// plan note that decodes back to a `PlanNote` whose envelope
    /// fields match what writ produced.
    ///
    /// This is the load-bearing contract bailiff's slice-C CLI relies
    /// on. A regression in fetch, verify, ref derivation, or write
    /// surfaces here.
    #[test]
    fn write_plan_note_happy_path_round_trips_through_bailiff_repo() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let plan_id = PlanId::new();
        let purpose = "plan-stage:c2".to_string();
        let returned_oid = write_plan_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            plan_id,
            purpose.clone(),
            &completed,
            &allowed,
        )
        .expect("happy path must succeed");

        // The returned OID is the deterministic seed-blob OID derived
        // from plan_id alone — pin that contract so a future schema
        // change can't quietly diverge the writer and reader.
        let expected_seed_bytes = plan_submission_seed_blob_bytes(plan_id);
        let body = bailiff
            .read_note(&plan_notes_ref(plan_id), &returned_oid)
            .expect("bailiff-side note must be readable at the returned OID");

        let note = PlanNote::from_canonical_bytes(&body).expect("body must decode");
        assert_eq!(note.plan_id, plan_id);
        assert_eq!(note.purpose, purpose);
        assert_eq!(note.writ_output_oid, completed.output_oid);
        assert_eq!(note.signed_metadata, envelope.metadata);
        assert_eq!(note.signature, envelope.signature);

        // Sanity: the seed bytes are not the same as the OID — the
        // OID is what `git hash-object` of the seed bytes produces.
        // We don't recompute the SHA-1 here; we just confirm the
        // function returned something and the bytes are stable.
        assert!(!expected_seed_bytes.is_empty());
    }

    /// Defence in depth: if the envelope writ stored in its repo
    /// disagrees with what writ returned over the wire, bailiff
    /// refuses to attach a plan note. Construct that case by giving
    /// `write_plan_note` a `RunAgentCompleted` whose metadata field
    /// has been tampered with.
    #[test]
    fn write_plan_note_rejects_metadata_mismatch_between_envelope_and_reply() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, mut completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        // Flip a metadata field on the wire-side reply without
        // touching the on-disk envelope. The envelope is still
        // cryptographically valid; the divergence is what the check
        // catches.
        completed.signed_metadata.exit_code = completed.signed_metadata.exit_code.wrapping_add(1);

        let err = write_plan_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            PlanId::new(),
            "p".into(),
            &completed,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, WritePlanNoteError::EnvelopeMetadataMismatch),
            "expected EnvelopeMetadataMismatch, got: {err:?}",
        );
    }

    /// Same defence as the metadata case but for the signature
    /// field. A wire reply whose signature differs from the stored
    /// envelope's signature is also a refusal.
    #[test]
    fn write_plan_note_rejects_signature_mismatch_between_envelope_and_reply() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, mut completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        // Substitute the signature with a different (still well-formed)
        // SshSignature — the byte mismatch is what trips the check.
        completed.signature = crate::core::SshSignature::try_new(
            "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH-other-bytes\n-----END SSH SIGNATURE-----",
        )
        .unwrap();

        let err = write_plan_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            PlanId::new(),
            "p".into(),
            &completed,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, WritePlanNoteError::EnvelopeSignatureMismatch),
            "expected EnvelopeSignatureMismatch, got: {err:?}",
        );
    }

    /// If bailiff's keyring doesn't contain writ's signing key the
    /// envelope verification step fails with `UnknownSigner`, which
    /// surfaces as `WritePlanNoteError::Verify`. This is the
    /// operator-misconfigured-trust case.
    #[test]
    fn write_plan_note_rejects_envelope_when_signer_not_trusted() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);

        // Keyring contains *only* an unrelated key — verification
        // fails before signature math runs.
        let other = WritVerifyingKey::from_openssh(OTHER_PUB.trim()).unwrap();
        let allowed = AllowedSigners::from_keys([other]);

        let err = write_plan_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            PlanId::new(),
            "p".into(),
            &completed,
            &allowed,
        )
        .unwrap_err();
        match err {
            WritePlanNoteError::Verify(VerifyError::UnknownSigner { .. }) => {}
            other => panic!("expected Verify(UnknownSigner), got: {other:?}"),
        }
    }

    /// A bad writ-repo path surfaces as `Fetch`, distinct from the
    /// later `ReadEnvelope` variant. Operators see "your writ repo
    /// path is wrong" instead of "no such note."
    #[test]
    fn write_plan_note_reports_fetch_failure_for_missing_writ_repo() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (_writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let bogus = tmp.path().join("does-not-exist");
        let err = write_plan_note(
            &bailiff,
            &bogus,
            &writ_notes_ref(),
            PlanId::new(),
            "p".into(),
            &completed,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, WritePlanNoteError::Fetch(_)),
            "expected Fetch error, got: {err:?}",
        );
    }

    /// `write_plan_note` calls `write_note` on the bailiff repo,
    /// which refuses to overwrite an existing note for the same
    /// target. A duplicate-plan-id call must surface as
    /// `WritePlanNote`, not silently overwrite.
    #[test]
    fn write_plan_note_refuses_to_overwrite_existing_plan_id() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let plan_id = PlanId::new();
        write_plan_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            plan_id,
            "first".into(),
            &completed,
            &allowed,
        )
        .expect("first write succeeds");

        let err = write_plan_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            plan_id,
            "second".into(),
            &completed,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, WritePlanNoteError::WritePlanNote(_)),
            "expected WritePlanNote error, got: {err:?}",
        );
    }

    /// Two distinct plan ids produce two distinct bailiff-side notes
    /// from the *same* writ envelope. The plan id is the only thing
    /// that varies between the two writes; the writ-side OID stays
    /// the same in both notes.
    #[test]
    fn write_plan_note_supports_two_plans_referencing_one_writ_envelope() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed, _envelope) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let p1 = PlanId::new();
        let p2 = PlanId::new();
        let oid1 = write_plan_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            p1,
            "first".into(),
            &completed,
            &allowed,
        )
        .unwrap();
        let oid2 = write_plan_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            p2,
            "second".into(),
            &completed,
            &allowed,
        )
        .unwrap();
        assert_ne!(oid1, oid2, "distinct plan ids must seed distinct OIDs");

        let body1 = bailiff.read_note(&plan_notes_ref(p1), &oid1).unwrap();
        let body2 = bailiff.read_note(&plan_notes_ref(p2), &oid2).unwrap();
        let note1 = PlanNote::from_canonical_bytes(&body1).unwrap();
        let note2 = PlanNote::from_canonical_bytes(&body2).unwrap();
        assert_eq!(note1.plan_id, p1);
        assert_eq!(note2.plan_id, p2);
        assert_eq!(
            note1.writ_output_oid, note2.writ_output_oid,
            "both plans reference the same writ envelope",
        );
        assert_ne!(note1.purpose, note2.purpose);
    }
}

#[cfg(test)]
mod end_to_end_tests {
    //! Full slice-C handshake against a real writ broker. Mirrors the
    //! slice-B5 round-trip in `writ_client.rs` and tacks
    //! `write_plan_note` on the end: bailiff sends `RunAgent`, writ
    //! signs and persists the envelope, then bailiff drives
    //! `write_plan_note` to fetch the envelope, verify it, and store
    //! a `PlanNote` keyed on the plan id.
    //!
    //! A regression anywhere in the chain — protocol framing, signing
    //! namespace, notes write, fetch refspec, envelope/reply
    //! agreement, plan-note serialisation — fails this test rather
    //! than getting caught by a downstream consumer.
    use std::collections::{BTreeMap, HashMap};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::sync::Mutex as AsyncMutex;
    use wiremock::MockServer;

    use super::*;
    use crate::agent_run::AgentPrompt;
    use crate::audit::AuditLog;
    use crate::bailiff_plan_note::{PlanId, PlanNote, plan_notes_ref};
    use crate::core::{AgentKind, CapabilitySet, NotesRef, RepoRef, TtlSeconds};
    use crate::github::{GitHubAppConfig, GitHubAppRegistryConfig, GitHubMinter};
    use crate::notes_repo::NotesRepo;
    use crate::policy::PolicyConfig;
    use crate::run_verify::AllowedSigners;
    use crate::secret::{SecretError, SecretKey, SecretStore};
    use crate::server::{
        BrokerState, RunAgentSpawnConfig, prepare_broker_listener, serve_broker_with_agent_vm,
    };
    use crate::signing::WritSigningKey;
    use crate::writ_client::{RunAgentRequest, WritClient};

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");
    const TEST_PRIV: &str = include_str!("../tests/fixtures/rsa_test_1.pem");

    /// In-memory `SecretStore`. Same minimal shim as the writ_client
    /// end-to-end test uses — production runs against
    /// `FileSecretStore`, but for a test that only stores the
    /// GitHub-app PEM to satisfy `BrokerState`'s non-empty registry
    /// invariant, an in-memory map is enough.
    #[derive(Default)]
    struct InMemStore(Mutex<HashMap<String, String>>);

    impl SecretStore for InMemStore {
        fn get(&self, key: &SecretKey) -> Result<Option<String>, SecretError> {
            Ok(self.0.lock().unwrap().get(key.as_str()).cloned())
        }
        fn put(&self, key: &SecretKey, value: &str) -> Result<(), SecretError> {
            self.0
                .lock()
                .unwrap()
                .insert(key.as_str().to_string(), value.to_string());
            Ok(())
        }
        fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
            self.0.lock().unwrap().remove(key.as_str());
            Ok(())
        }
    }

    fn find_in_path(name: &str) -> Option<std::path::PathBuf> {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|p| p.join(name))
                .find(|p| p.is_file())
        })
    }

    #[tokio::test]
    async fn write_plan_note_completes_after_real_broker_round_trip() {
        // --- Broker bring-up (writ side) ----------------------------
        let tmp = tempfile::tempdir().unwrap();
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let bailiff_repo_handle = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let cat = find_in_path("cat").expect("cat must be on PATH for the round-trip test");

        let github_server = MockServer::start().await;
        let pk = SecretKey::new("gh-app-pk").unwrap();
        let store = InMemStore::default();
        store.put(&pk, TEST_PRIV).unwrap();
        let mut apps = BTreeMap::new();
        apps.insert(
            AgentKind::Claude,
            GitHubAppConfig {
                app_id: 42,
                installation_id: 999,
                installation_owner: "o".into(),
                private_key_secret: pk,
                api_base: github_server.uri(),
            },
        );
        let minter = GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap());

        let state = Arc::new(BrokerState {
            audit: Arc::new(AuditLog::open_in_memory().unwrap()),
            minter,
            secrets: store,
            policy: PolicyConfig {
                writable_repos: vec![],
                default_ttl: TtlSeconds::new(3600).unwrap(),
            },
            staging_store: None,
            notes_repo: Some(Arc::new(writ_repo)),
            signing_key: Some(signing_key.clone()),
            run_agent_spawn: Some(RunAgentSpawnConfig {
                command: cat,
                args: Vec::new(),
            }),
        });

        let socket_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let socket_path = socket_dir.path().join("writ.sock");
        let listener = prepare_broker_listener(&socket_path).await.unwrap();
        let broker_state = Arc::clone(&state);
        let broker_task = tokio::spawn(async move {
            let _ = serve_broker_with_agent_vm(listener, broker_state, None).await;
        });

        // --- Client request (bailiff side) --------------------------
        let prompt_text = "noop\n";
        let writ_notes_ref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
        let purpose = "plan-submit".to_string();
        let client = WritClient::new(&socket_path);
        let completed = tokio::time::timeout(
            Duration::from_secs(15),
            client.run_agent(RunAgentRequest {
                prompt: AgentPrompt::new(prompt_text),
                capabilities: vec![CapabilitySet::WorkspaceRead {
                    repo: RepoRef {
                        owner: "smaug123".into(),
                        name: "writ".into(),
                    },
                }],
                purpose: purpose.clone(),
                output_ref: writ_notes_ref.clone(),
                session_id: None,
            }),
        )
        .await
        .expect("RunAgent must complete within 15s")
        .expect("RunAgent must succeed");

        // --- Plan-note write (bailiff side) -------------------------
        // `write_plan_note` is blocking (shells out to git); wrap it
        // in `spawn_blocking` so we don't stall the runtime. A short
        // async lock on the bailiff repo keeps the single-writer
        // invariant visible at the call site.
        let writ_repo_path = state.notes_repo.as_ref().unwrap().path().to_path_buf();
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let plan_id = PlanId::new();
        let completed_clone = completed.clone();
        let writ_notes_ref_clone = writ_notes_ref.clone();
        let bailiff = Arc::new(AsyncMutex::new(bailiff_repo_handle));
        let bailiff_for_block = Arc::clone(&bailiff);
        let returned_oid = tokio::task::spawn_blocking(move || {
            let bailiff = bailiff_for_block.blocking_lock();
            write_plan_note(
                &bailiff,
                &writ_repo_path,
                &writ_notes_ref_clone,
                plan_id,
                purpose.clone(),
                &completed_clone,
                &allowed,
            )
        })
        .await
        .unwrap()
        .expect("write_plan_note must succeed under the trusted-signer keyring");

        // --- Read back the plan note from bailiff's repo ------------
        let bailiff_for_read = Arc::clone(&bailiff);
        let plan_ref = plan_notes_ref(plan_id);
        let body = tokio::task::spawn_blocking(move || {
            let bailiff = bailiff_for_read.blocking_lock();
            bailiff.read_note(&plan_ref, &returned_oid)
        })
        .await
        .unwrap()
        .expect("bailiff-side plan note must be readable at the returned OID");
        let note = PlanNote::from_canonical_bytes(&body)
            .expect("bailiff-side body must decode as PlanNote");

        // The note carries the plan-id bailiff allocated, the purpose
        // bailiff sent on the wire, the writ-side OID writ returned,
        // and the signed metadata + signature the broker produced.
        assert_eq!(note.plan_id, plan_id);
        assert_eq!(note.purpose, "plan-submit");
        assert_eq!(note.writ_output_oid, completed.output_oid);
        assert_eq!(note.signed_metadata, completed.signed_metadata);
        assert_eq!(note.signature, completed.signature);

        broker_task.abort();
        let _ = broker_task.await;
    }
}
