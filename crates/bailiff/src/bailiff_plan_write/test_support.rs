//! The `bailiff_plan_write` test modules' view of the crate's shared
//! scaffolding ([`crate::test_support`]), plus the one wrapper whose shape
//! these tests destructure.

use super::*;
use tempfile::TempDir;
use writ::run_envelope::SignedRunEnvelope;
use writ::signing::WritSigningKey;

pub(super) use crate::test_support::{
    OTHER_PUB, SIGNING_PEM, SIGNING_PUB, bailiff_repo, freshly_signed, signed_envelope,
    writ_notes_ref,
};

/// A writ repo holding a [`freshly_signed`] envelope, the reply bailiff would
/// have seen for it, and the envelope itself for tampering tests.
pub(super) fn writ_repo_with_envelope(
    tmp: &TempDir,
    signing_key: &WritSigningKey,
) -> (NotesRepo, RunAgentCompleted, SignedRunEnvelope) {
    let envelope = freshly_signed(signing_key);
    let (writ_repo, completed) = crate::test_support::writ_repo_with_envelope(tmp, &envelope);
    (writ_repo, completed, envelope)
}
