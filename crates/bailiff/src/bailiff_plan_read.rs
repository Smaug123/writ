//! Bailiff-side read helpers for per-plan notes. Sibling to
//! [`crate::bailiff_plan_write`]: where the write helpers attach the
//! bailiff-owned notes a plan accumulates, the read helpers project
//! them back into typed Rust values.
//!
//! Slice D1.4 of `docs/plans/2026-05-16-slice-d1-decide.md` introduced
//! the decision read; slice D2.3 of
//! `docs/plans/2026-05-16-slice-d2-review.md` added the review read at
//! the third seed-OID; slice D2.4a of the same review plan adds the
//! submission read so the `submit_review` workflow (D2.4b) can fetch
//! the planner's `writ_output_oid` and resolve it back to a plan body;
//! slice E3 of `docs/plans/2026-05-14-bailiff-split.md` adds the
//! implement read at the fourth seed-OID. All four read helpers pin
//! the same seed-OID convention the matching writers use, so a
//! round-trip through the per-plan ref doesn't depend on any registry
//! beyond the deterministic seed bytes.
//!
//! Slice E4a of the same plan lifts `read_plan_body_bytes` here from
//! `bailiff_plan_review` so the future `submit_implement` workflow can
//! reuse the same fetch-verify-decode chain without depending on the
//! review module; pure refactor, zero behaviour change.

use std::path::Path;
use std::string::FromUtf8Error;

use thiserror::Error;

use crate::bailiff_plan_note::{
    BAILIFF_PLAN_NOTES_REF_PREFIX, DecisionNote, DecisionNoteParseError, ImplementNote,
    ImplementNoteParseError, PlanId, PlanNote, PlanNoteParseError, ReviewNote,
    ReviewNoteParseError, plan_decision_seed_blob_bytes, plan_implement_seed_blob_bytes,
    plan_notes_ref, plan_review_seed_blob_bytes, plan_submission_seed_blob_bytes,
};
use crate::bailiff_plan_write::WRIT_V1_NOTES_REFSPEC;
use writ::core::NotesRef;
use writ::notes_repo::{NotesRepo, NotesRepoError};
use writ::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use writ::run_verify::{AllowedSigners, VerifyError, verify_run_envelope};
use writ::vm_git::GitObjectId;

// The read-projection types these helpers return now live in
// `bailiff_plan_view` so presentation code can depend on the types
// without depending on this reader. Re-exported here so the read
// functions, their tests, and the `bailiff` binary keep resolving
// them via `crate::bailiff_plan_read::…`.
pub(crate) use crate::bailiff_plan_view::SignedBailiffNote;
pub use crate::bailiff_plan_view::{
    BailiffPlanSummary, DecisionSummary, PlanFullView, SubmissionSummary, VerifiedSection,
};

/// Bailiff's local copy of writ's per-run signed-output notes ref.
/// `submit_plan` / `submit_review` / `submit_implement` fetch this
/// ref from writ at attest time, so the reader can always find an
/// envelope here when bailiff has been kept up to date.
///
/// Sibling to [`crate::bailiff_plan_write::WRIT_V1_NOTES_REFSPEC`] —
/// that pins the refspec the fetcher uses, this pins the single ref
/// name a reader looks up.
const WRIT_AGENT_OUTPUTS_REF: &str = "refs/notes/writ/v1/agent-outputs";

/// Read the decision note for `plan_id`, if one has been recorded.
/// Returns `Ok(None)` when no decision exists yet — both the
/// no-such-plan-id case (no notes ref for that plan) and the
/// plan-exists-but-undecided case (ref present, no annotation at the
/// decision seed's target OID) fold into the same `None` because both
/// mean "operator has not yet ruled on this plan."
///
/// Sibling to [`crate::bailiff_plan_write::write_decision_note`]: the
/// writer hashes [`plan_decision_seed_blob_bytes`] to pick the attach
/// OID, the reader hashes the same seed bytes to recover it, and
/// content-addressed storage makes the round-trip work without any
/// separate registry. The submission note ([`crate::bailiff_plan_note::PlanNote`])
/// is **not** consulted: D1 keeps decisions independently readable so
/// a future caller can ask "has this plan been decided?" without
/// gating on the submission being present.
pub fn read_decision_note(
    bailiff_repo: &NotesRepo,
    plan_id: PlanId,
) -> Result<Option<DecisionNote>, ReadDecisionError> {
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_decision_seed_blob_bytes(plan_id);
    let Some(body) = bailiff_repo
        .read_note_at_seed(&plan_ref, &seed)
        .map_err(ReadDecisionError::ReadNote)?
    else {
        return Ok(None);
    };
    let note = DecisionNote::from_canonical_bytes(&body).map_err(ReadDecisionError::Decode)?;
    if note.plan_id != plan_id {
        return Err(ReadDecisionError::PlanIdMismatch {
            requested: plan_id,
            found: note.plan_id,
        });
    }
    Ok(Some(note))
}

/// Tagged failure modes of [`read_decision_note`]. The two variants
/// distinguish "reading the bytes failed" from "bytes came back but
/// did not parse as a [`DecisionNote`]" so a caller can react
/// appropriately: the former is a filesystem or git problem
/// (operator-misconfigured repo path), the latter is on-disk
/// corruption or a schema regression.
#[derive(Debug, Error)]
pub enum ReadDecisionError {
    /// Reading the underlying note body from bailiff's repo failed
    /// for any reason other than absence. Absence (no decision yet)
    /// is folded into `Ok(None)` by [`read_decision_note`] and never
    /// surfaces here.
    #[error("reading the decision note from bailiff's repo failed: {0}")]
    ReadNote(#[source] NotesRepoError),
    /// The note body existed but did not parse as a
    /// [`DecisionNote`]. Indicates wire-level corruption — the
    /// canonical JSON shape is fixed and `deny_unknown_fields` plus
    /// the field-type validators make this near-impossible for any
    /// body [`crate::bailiff_plan_write::write_decision_note`] itself
    /// produced.
    #[error("decoding the decision note body failed: {0}")]
    Decode(#[source] DecisionNoteParseError),
    /// The note parsed cleanly but its embedded `plan_id` does not
    /// match the plan we were asked to read. Unreachable through
    /// [`crate::bailiff_plan_write::write_decision_note`] (which always
    /// derives the attach seed from `decision_note.plan_id`), so this
    /// surfaces only when bytes were planted via the low-level
    /// [`writ::notes_repo::NotesRepo::write_note`] path or pasted by
    /// hand after manual repo repair. Treat it as semantic corruption:
    /// a future acceptance gate must not be fooled into ruling on
    /// plan A by reading plan B's verdict.
    #[error(
        "decision note at plan {requested} carries embedded plan_id {found}; refusing to surface a cross-plan verdict"
    )]
    PlanIdMismatch { requested: PlanId, found: PlanId },
}

/// Read the review note for `plan_id`, if one has been recorded.
/// Returns `Ok(None)` when no review exists yet — both the
/// no-such-plan-id case (no notes ref for that plan) and the
/// plan-exists-but-unreviewed case (ref present, no annotation at the
/// review seed's target OID) fold into the same `None` because both
/// mean "writ has not produced a reviewer envelope for this plan."
///
/// Sibling to [`crate::bailiff_plan_write::write_review_note`]: the
/// writer hashes [`plan_review_seed_blob_bytes`] to pick the attach
/// OID, the reader hashes the same seed bytes to recover it, and
/// content-addressed storage makes the round-trip work without any
/// separate registry. Neither the submission nor the decision note is
/// consulted: D2 keeps reviews independently readable so a future
/// caller can ask "has this plan been reviewed?" without gating on
/// either of the other notes being present.
pub fn read_review_note(
    bailiff_repo: &NotesRepo,
    plan_id: PlanId,
) -> Result<Option<ReviewNote>, ReadReviewError> {
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_review_seed_blob_bytes(plan_id);
    let Some(body) = bailiff_repo
        .read_note_at_seed(&plan_ref, &seed)
        .map_err(ReadReviewError::ReadNote)?
    else {
        return Ok(None);
    };
    let note = ReviewNote::from_canonical_bytes(&body).map_err(ReadReviewError::Decode)?;
    if note.plan_id != plan_id {
        return Err(ReadReviewError::PlanIdMismatch {
            requested: plan_id,
            found: note.plan_id,
        });
    }
    Ok(Some(note))
}

/// Tagged failure modes of [`read_review_note`]. Same three-variant
/// shape as [`ReadDecisionError`]: filesystem/git read failure vs.
/// bytes-came-back-but-did-not-parse vs. semantic corruption
/// (cross-plan body planted under another plan's seed).
#[derive(Debug, Error)]
pub enum ReadReviewError {
    /// Reading the underlying note body from bailiff's repo failed
    /// for any reason other than absence. Absence (no review yet) is
    /// folded into `Ok(None)` by [`read_review_note`] and never
    /// surfaces here.
    #[error("reading the review note from bailiff's repo failed: {0}")]
    ReadNote(#[source] NotesRepoError),
    /// The note body existed but did not parse as a [`ReviewNote`].
    /// Indicates wire-level corruption — the canonical JSON shape is
    /// fixed and `deny_unknown_fields` plus the field-type validators
    /// make this near-impossible for any body
    /// [`crate::bailiff_plan_write::write_review_note`] itself produced.
    #[error("decoding the review note body failed: {0}")]
    Decode(#[source] ReviewNoteParseError),
    /// The note parsed cleanly but its embedded `plan_id` does not
    /// match the plan we were asked to read. Unreachable through
    /// [`crate::bailiff_plan_write::write_review_note`] (which always
    /// derives the attach seed from the `plan_id` argument it
    /// embeds in the note), so this surfaces only when bytes were
    /// planted via the low-level
    /// [`writ::notes_repo::NotesRepo::write_note`] path or pasted by
    /// hand after manual repo repair. Treat it as semantic corruption:
    /// a future reader rendering reviewer prose must not be fooled
    /// into displaying plan B's review when asked about plan A.
    #[error(
        "review note at plan {requested} carries embedded plan_id {found}; refusing to surface a cross-plan review"
    )]
    PlanIdMismatch { requested: PlanId, found: PlanId },
}

/// Read the submission note for `plan_id`, if one has been recorded.
/// Returns `Ok(None)` when no submission exists yet — both the
/// no-such-plan-id case (no notes ref for that plan) and the
/// plan-exists-but-not-submitted case (ref present, no annotation at
/// the submission seed's target OID) fold into the same `None`
/// because both mean "writ has not produced a planner envelope for
/// this plan yet."
///
/// Sibling to [`crate::bailiff_plan_write::write_plan_note`]: the
/// writer hashes [`plan_submission_seed_blob_bytes`] to pick the
/// attach OID, the reader hashes the same seed bytes to recover it,
/// and content-addressed storage makes the round-trip work without
/// any separate registry. Neither the decision nor the review note
/// is consulted: the submission stays independently readable so a
/// caller can ask "what planner envelope was submitted for this
/// plan?" without gating on the other two notes being present.
pub fn read_plan_note(
    bailiff_repo: &NotesRepo,
    plan_id: PlanId,
) -> Result<Option<PlanNote>, ReadPlanError> {
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_submission_seed_blob_bytes(plan_id);
    let Some(body) = bailiff_repo
        .read_note_at_seed(&plan_ref, &seed)
        .map_err(ReadPlanError::ReadNote)?
    else {
        return Ok(None);
    };
    let note = PlanNote::from_canonical_bytes(&body).map_err(ReadPlanError::Decode)?;
    if note.plan_id != plan_id {
        return Err(ReadPlanError::PlanIdMismatch {
            requested: plan_id,
            found: note.plan_id,
        });
    }
    Ok(Some(note))
}

/// Tagged failure modes of [`read_plan_note`]. Same three-variant
/// shape as [`ReadDecisionError`] / [`ReadReviewError`]:
/// filesystem/git read failure vs. bytes-came-back-but-did-not-parse
/// vs. semantic corruption (cross-plan body planted under another
/// plan's seed).
#[derive(Debug, Error)]
pub enum ReadPlanError {
    /// Reading the underlying note body from bailiff's repo failed
    /// for any reason other than absence. Absence (no submission
    /// yet) is folded into `Ok(None)` by [`read_plan_note`] and
    /// never surfaces here.
    #[error("reading the plan submission note from bailiff's repo failed: {0}")]
    ReadNote(#[source] NotesRepoError),
    /// The note body existed but did not parse as a [`PlanNote`].
    /// Indicates wire-level corruption — the canonical JSON shape is
    /// fixed and `deny_unknown_fields` plus the field-type validators
    /// make this near-impossible for any body
    /// [`crate::bailiff_plan_write::write_plan_note`] itself produced.
    #[error("decoding the plan submission note body failed: {0}")]
    Decode(#[source] PlanNoteParseError),
    /// The note parsed cleanly but its embedded `plan_id` does not
    /// match the plan we were asked to read. Unreachable through
    /// [`crate::bailiff_plan_write::write_plan_note`] (which always
    /// derives the attach seed from the `plan_id` argument it embeds
    /// in the note), so this surfaces only when bytes were planted
    /// via the low-level [`writ::notes_repo::NotesRepo::write_note`]
    /// path or pasted by hand after manual repo repair. Treat it as
    /// semantic corruption: the upcoming `submit_review` workflow
    /// must not be fooled into composing a reviewer prompt from
    /// plan B's body when asked about plan A.
    #[error(
        "plan submission note at plan {requested} carries embedded plan_id {found}; refusing to surface a cross-plan submission"
    )]
    PlanIdMismatch { requested: PlanId, found: PlanId },
}

/// Read the implement note for `plan_id`, if one has been recorded.
/// Returns `Ok(None)` when no implement exists yet — both the
/// no-such-plan-id case (no notes ref for that plan) and the
/// plan-exists-but-unimplemented case (ref present, no annotation at
/// the implement seed's target OID) fold into the same `None` because
/// both mean "writ has not produced an implementer envelope for this
/// plan yet."
///
/// Sibling to [`crate::bailiff_plan_write::write_implement_note`]: the
/// writer hashes [`plan_implement_seed_blob_bytes`] to pick the attach
/// OID, the reader hashes the same seed bytes to recover it, and
/// content-addressed storage makes the round-trip work without any
/// separate registry. None of the other three notes is consulted: the
/// implement stays independently readable so a caller can ask "has
/// this plan been implemented?" without gating on the others being
/// present.
pub fn read_implement_note(
    bailiff_repo: &NotesRepo,
    plan_id: PlanId,
) -> Result<Option<ImplementNote>, ReadImplementError> {
    let plan_ref = plan_notes_ref(plan_id);
    let seed = plan_implement_seed_blob_bytes(plan_id);
    let Some(body) = bailiff_repo
        .read_note_at_seed(&plan_ref, &seed)
        .map_err(ReadImplementError::ReadNote)?
    else {
        return Ok(None);
    };
    let note = ImplementNote::from_canonical_bytes(&body).map_err(ReadImplementError::Decode)?;
    if note.plan_id != plan_id {
        return Err(ReadImplementError::PlanIdMismatch {
            requested: plan_id,
            found: note.plan_id,
        });
    }
    Ok(Some(note))
}

/// Tagged failure modes of [`read_implement_note`]. Same three-variant
/// shape as [`ReadDecisionError`] / [`ReadReviewError`] /
/// [`ReadPlanError`]: filesystem/git read failure vs.
/// bytes-came-back-but-did-not-parse vs. semantic corruption
/// (cross-plan body planted under another plan's seed).
#[derive(Debug, Error)]
pub enum ReadImplementError {
    /// Reading the underlying note body from bailiff's repo failed
    /// for any reason other than absence. Absence (no implement yet)
    /// is folded into `Ok(None)` by [`read_implement_note`] and never
    /// surfaces here.
    #[error("reading the implement note from bailiff's repo failed: {0}")]
    ReadNote(#[source] NotesRepoError),
    /// The note body existed but did not parse as an [`ImplementNote`].
    /// Indicates wire-level corruption — the canonical JSON shape is
    /// fixed and `deny_unknown_fields` plus the field-type validators
    /// make this near-impossible for any body
    /// [`crate::bailiff_plan_write::write_implement_note`] itself
    /// produced.
    #[error("decoding the implement note body failed: {0}")]
    Decode(#[source] ImplementNoteParseError),
    /// The note parsed cleanly but its embedded `plan_id` does not
    /// match the plan we were asked to read. Unreachable through
    /// [`crate::bailiff_plan_write::write_implement_note`] (which
    /// always derives the attach seed from the `plan_id` argument it
    /// embeds in the note), so this surfaces only when bytes were
    /// planted via the low-level [`writ::notes_repo::NotesRepo::write_note`]
    /// path or pasted by hand after manual repo repair. Treat it as
    /// semantic corruption: a future caller rendering implementer
    /// output must not be fooled into surfacing plan B's implement
    /// when asked about plan A.
    #[error(
        "implement note at plan {requested} carries embedded plan_id {found}; refusing to surface a cross-plan implement"
    )]
    PlanIdMismatch { requested: PlanId, found: PlanId },
}

/// Enumerate every plan-id bailiff has any notes for, in the
/// lexicographic order [`NotesRepo::list_refs_under_prefix`] returns.
///
/// "Has any notes for" is a deliberate lower bar than "has a
/// submission for" — the underlying for-each-ref scan reports a plan
/// ref the moment any of the four seed-OIDs under it has a note
/// attached, so a plan with only a decision (or only a review) note
/// is still listed. The summary helper distinguishes those states via
/// [`BailiffPlanSummary::submission`] being `None`; that's where the
/// "workflow integrity" signal surfaces. Filtering here would hide
/// such states from list output, which is exactly when an operator
/// needs to see them.
///
/// Returned ids are not deduplicated because the underlying refs are
/// one-per-plan by construction (the ref name embeds the id and
/// `for-each-ref` returns each ref once).
pub fn list_plan_ids(bailiff_repo: &NotesRepo) -> Result<Vec<PlanId>, ListPlanIdsError> {
    let refs = bailiff_repo
        .list_refs_under_prefix(BAILIFF_PLAN_NOTES_REF_PREFIX)
        .map_err(ListPlanIdsError::Read)?;
    let mut ids = Vec::with_capacity(refs.len());
    for r in refs {
        // `list_refs_under_prefix` guarantees every returned ref starts
        // with the supplied prefix. A failure here would be a contract
        // violation in `NotesRepo`, not on-disk corruption — `expect`
        // rather than fold into the error type.
        let tail = r
            .as_str()
            .strip_prefix(BAILIFF_PLAN_NOTES_REF_PREFIX)
            .expect("list_refs_under_prefix returned a ref outside the requested prefix");
        let id = tail
            .parse::<PlanId>()
            .map_err(|source| ListPlanIdsError::ParseRef {
                raw_ref: r.as_str().to_string(),
                tail: tail.to_string(),
                source,
            })?;
        // `Uuid::parse_str` accepts non-canonical spellings (32 hex
        // characters without hyphens, uppercase hex) that
        // `plan_notes_ref(plan_id)` never emits — it always uses
        // `PlanId::Display` which is the lowercase-hyphenated canonical
        // form. If we let a non-canonical tail through, `summarize_plan`
        // would re-derive the ref name canonically, look there, and
        // find nothing — silently hiding the corrupted ref that
        // actually carries the notes. Reject up front so the operator
        // sees which on-disk ref is the offender.
        if tail != id.to_string() {
            return Err(ListPlanIdsError::NonCanonicalRef {
                raw_ref: r.as_str().to_string(),
                tail: tail.to_string(),
                canonical: id.to_string(),
            });
        }
        ids.push(id);
    }
    Ok(ids)
}

/// Tagged failure modes of [`list_plan_ids`]. The three variants
/// distinguish "reading the ref set from bailiff's repo failed" from
/// "a ref was returned whose tail isn't a parseable UUID" from "a ref
/// parses but uses a non-canonical UUID spelling." All three of the
/// latter two are semantic corruption — bailiff is the sole writer to
/// the `refs/notes/bailiff/v1/plans/` namespace and always uses
/// `plan_notes_ref(plan_id)` (i.e. `PlanId::Display`) to derive the
/// name, so any deviation means a manual `git update-ref` or an
/// external writer has injected state that bailiff cannot interpret.
#[derive(Debug, Error)]
pub enum ListPlanIdsError {
    /// Reading the ref set from bailiff's repo failed.
    #[error("listing bailiff plan refs failed: {0}")]
    Read(#[source] NotesRepoError),
    /// A ref under the plan prefix has a non-UUID tail. Surfaces the
    /// raw ref and the offending tail so the operator can locate the
    /// bad object.
    #[error("plan ref {raw_ref:?} has non-UUID tail {tail:?}: {source}")]
    ParseRef {
        raw_ref: String,
        tail: String,
        source: uuid::Error,
    },
    /// A ref under the plan prefix has a UUID tail that parses but is
    /// not the canonical lowercase-hyphenated form bailiff would write
    /// — for example, 32 unhyphenated hex characters or uppercase hex.
    /// Surfaces the raw ref, the tail as observed on disk, and the
    /// canonical spelling so the operator can rename or remove the
    /// offending ref.
    #[error(
        "plan ref {raw_ref:?} has non-canonical UUID tail {tail:?}; canonical form is {canonical:?}"
    )]
    NonCanonicalRef {
        raw_ref: String,
        tail: String,
        canonical: String,
    },
}

/// Read every per-plan note for `plan_id` and project them into a
/// summary suitable for `bailiff plan list`. One pass over the four
/// `read_*_note` helpers — four ref/seed lookups, no envelope reads.
/// The `submitted_at` / `reviewed_at` / `implemented_at` timestamps
/// are lifted from `SignedRunMetadata.completed_at` on the
/// corresponding notes, so no fetch into writ's repo is required.
///
/// Returns a summary with all four note projections folded in. A
/// missing submission folds into `submission: None` rather than an
/// error: the list view's job is to render what's there, and the
/// derived [`crate::bailiff_plan_state::PlanState::Corrupt`] flag surfaces the anomaly
/// instead.
pub fn summarize_plan(
    bailiff_repo: &NotesRepo,
    plan_id: PlanId,
) -> Result<BailiffPlanSummary, SummarizePlanError> {
    let submission = read_plan_note(bailiff_repo, plan_id)?.map(|note| SubmissionSummary {
        purpose: note.purpose,
        submitted_at: note.signed_metadata.completed_at,
    });
    let decision = read_decision_note(bailiff_repo, plan_id)?.map(|note| DecisionSummary {
        outcome: note.outcome,
        decider: note.decider,
        decided_at: note.decided_at,
    });
    let reviewed_at =
        read_review_note(bailiff_repo, plan_id)?.map(|note| note.signed_metadata.completed_at);
    let implemented_at =
        read_implement_note(bailiff_repo, plan_id)?.map(|note| note.signed_metadata.completed_at);
    Ok(BailiffPlanSummary {
        plan_id,
        submission,
        decision,
        reviewed_at,
        implemented_at,
    })
}

/// Tagged failure modes of [`summarize_plan`]. Each variant is a
/// straight pass-through of the underlying `Read*Error`, so an
/// operator sees the same diagnostic the per-note read would produce.
#[derive(Debug, Error)]
pub enum SummarizePlanError {
    #[error("reading plan submission note: {0}")]
    ReadPlan(#[from] ReadPlanError),
    #[error("reading decision note: {0}")]
    ReadDecision(#[from] ReadDecisionError),
    #[error("reading review note: {0}")]
    ReadReview(#[from] ReadReviewError),
    #[error("reading implement note: {0}")]
    ReadImplement(#[from] ReadImplementError),
}

/// Read the [`SignedRunEnvelope`] writ produced at `oid` from
/// bailiff's local copy of writ's `refs/notes/writ/v1/agent-outputs`
/// ref. Returns `Ok(None)` when no note is attached at `oid` — both
/// the no-such-ref case (writ's notes ref has never been fetched into
/// bailiff's repo) and the ref-exists-but-no-annotation case fold
/// into the same `None` because both mean "bailiff's local view does
/// not have an envelope at this OID."
///
/// The note body is the JSON-encoded envelope itself (per slice B's
/// "envelope in note body, not a separate blob" decision), so this
/// helper decodes straight into [`SignedRunEnvelope`]. Used by
/// [`read_full_plan`] to pair each signed bailiff note with its
/// envelope before verification.
pub fn read_writ_envelope_at_oid(
    bailiff_repo: &NotesRepo,
    oid: &GitObjectId,
) -> Result<Option<SignedRunEnvelope>, ReadWritEnvelopeError> {
    let writ_ref = NotesRef::try_new(WRIT_AGENT_OUTPUTS_REF)
        .expect("WRIT_AGENT_OUTPUTS_REF is a compile-time-valid notes ref");
    let Some(body) = bailiff_repo
        .read_note_if_present(&writ_ref, oid)
        .map_err(ReadWritEnvelopeError::Read)?
    else {
        return Ok(None);
    };
    let envelope = SignedRunEnvelope::from_bytes(&body).map_err(ReadWritEnvelopeError::Decode)?;
    Ok(Some(envelope))
}

/// Tagged failure modes of [`read_writ_envelope_at_oid`]. Absence is
/// not an error — both the ref-not-fetched and ref-present-but-empty
/// cases fold into `Ok(None)`. Surfaces here are:
///
/// - `Read`: git refused to read at all (permissions, broken repo) —
///   propagates the underlying [`NotesRepoError`].
/// - `Decode`: the note body existed but did not parse as
///   [`SignedRunEnvelope`]. Indicates wire-level corruption of a
///   writ-produced envelope.
#[derive(Debug, Error)]
pub enum ReadWritEnvelopeError {
    #[error("reading the writ output envelope note from bailiff's repo failed: {0}")]
    Read(#[source] NotesRepoError),
    #[error("decoding the writ output envelope body failed: {0}")]
    Decode(#[source] serde_json::Error),
}

/// Outcome of pairing a writ output OID with an envelope and running
/// the verifier. Internal projection consumed by [`wrap_section`];
/// the public surface is [`VerifiedSection`]. Separating this from
/// the per-section type means the read-and-verify step doesn't know
/// or care which kind of bailiff note (plan / review / implement)
/// will be paired with the outcome.
enum EnvelopeVerification {
    Verified(SignedRunEnvelope),
    Missing,
    Malformed(serde_json::Error),
    Failed(VerifyError),
}

/// Look up the envelope at `oid` in bailiff's local copy of writ's
/// notes ref, decode it, and verify it against `allowed`. Returns the
/// outcome as an [`EnvelopeVerification`] so [`read_full_plan`] can
/// pair each one with its bailiff-side note via [`wrap_section`].
///
/// Only the *read* failure on writ's notes ref propagates as an
/// `Err` — decode failures fold into [`EnvelopeVerification::Malformed`]
/// and verification failures into [`EnvelopeVerification::Failed`] so
/// the caller can render the rest of the plan even when one section
/// is broken.
fn read_and_verify_envelope(
    bailiff_repo: &NotesRepo,
    oid: &GitObjectId,
    allowed: &AllowedSigners,
) -> Result<EnvelopeVerification, NotesRepoError> {
    match read_writ_envelope_at_oid(bailiff_repo, oid) {
        Ok(Some(envelope)) => match verify_run_envelope(&envelope, allowed) {
            Ok(()) => Ok(EnvelopeVerification::Verified(envelope)),
            Err(error) => Ok(EnvelopeVerification::Failed(error)),
        },
        Ok(None) => Ok(EnvelopeVerification::Missing),
        Err(ReadWritEnvelopeError::Read(error)) => Err(error),
        Err(ReadWritEnvelopeError::Decode(error)) => Ok(EnvelopeVerification::Malformed(error)),
    }
}

/// Project a `(verification, note)` pair into the user-visible
/// [`VerifiedSection`]. For the `Verified` envelope outcome,
/// additionally checks that the note's copied `signed_metadata` and
/// `signature` match the envelope's — otherwise an operator could be
/// shown a stale or forged note alongside a legitimate envelope and
/// see the section render as "verified" when the visible note bytes
/// were not what writ signed.
fn wrap_section<T: SignedBailiffNote>(
    verification: EnvelopeVerification,
    note: T,
) -> VerifiedSection<T> {
    match verification {
        EnvelopeVerification::Verified(envelope) => {
            if &envelope.metadata == note.signed_metadata()
                && &envelope.signature == note.signature()
            {
                VerifiedSection::Verified { note, envelope }
            } else {
                VerifiedSection::NoteEnvelopeMismatch { note, envelope }
            }
        }
        EnvelopeVerification::Missing => VerifiedSection::WritEnvelopeMissing { note },
        EnvelopeVerification::Malformed(error) => {
            VerifiedSection::EnvelopeMalformed { note, error }
        }
        EnvelopeVerification::Failed(error) => VerifiedSection::SignatureFailure { note, error },
    }
}

/// For an optional bailiff-side signed note, read the corresponding
/// writ envelope, verify it, and wrap the outcome. Returns `Ok(None)`
/// when the note itself is absent — the no-yet-attached case for
/// review/implement sections, and the corrupt case for plan
/// submissions. Used three times by [`read_full_plan`], once per
/// concrete `T: SignedBailiffNote`.
fn read_and_project_section<T: SignedBailiffNote>(
    bailiff_repo: &NotesRepo,
    note: Option<T>,
    allowed: &AllowedSigners,
) -> Result<Option<VerifiedSection<T>>, ReadFullPlanError> {
    let Some(note) = note else {
        return Ok(None);
    };
    let verification = read_and_verify_envelope(bailiff_repo, note.writ_output_oid(), allowed)
        .map_err(ReadFullPlanError::ReadEnvelope)?;
    Ok(Some(wrap_section(verification, note)))
}

/// Read every per-plan note for `plan_id`, pair each signed note with
/// the writ envelope it references, and verify the envelope against
/// `allowed_signers`. Returns a [`PlanFullView`] with all four
/// projections folded in.
///
/// Per-section failure modes (envelope missing, envelope malformed,
/// signature invalid) surface inside the relevant
/// [`VerifiedSection`] rather than collapsing the whole view into an
/// `Err`. The two failure modes that *do* surface as `Err` are
/// (a) bailiff's own note reads (a broken bailiff repo is not
/// recoverable by reading less) and (b) the git read on writ's notes
/// ref (same reason). Both are recoverable by fixing the local repo,
/// not by re-running with a different plan id.
///
/// Pure-library: no socket, no fetches. F4 wires this to clap; a
/// future agent-facing API can reuse it without going through the
/// CLI.
pub fn read_full_plan(
    bailiff_repo: &NotesRepo,
    plan_id: PlanId,
    allowed_signers: &AllowedSigners,
) -> Result<PlanFullView, ReadFullPlanError> {
    let plan = read_and_project_section(
        bailiff_repo,
        read_plan_note(bailiff_repo, plan_id)?,
        allowed_signers,
    )?;
    let decision = read_decision_note(bailiff_repo, plan_id)?;
    let review = read_and_project_section(
        bailiff_repo,
        read_review_note(bailiff_repo, plan_id)?,
        allowed_signers,
    )?;
    let implement = read_and_project_section(
        bailiff_repo,
        read_implement_note(bailiff_repo, plan_id)?,
        allowed_signers,
    )?;
    Ok(PlanFullView {
        plan_id,
        plan,
        decision,
        review,
        implement,
    })
}

/// Tagged failure modes of [`read_full_plan`]. The four note-read
/// variants are pass-throughs of the per-section read errors so an
/// operator sees the same diagnostic the per-note helpers would
/// produce. `ReadEnvelope` covers a git failure reading writ's notes
/// ref from bailiff's repo — distinct from per-section
/// "envelope missing / malformed / signature failed," which surface
/// inside the [`VerifiedSection`] variants instead.
#[derive(Debug, Error)]
pub enum ReadFullPlanError {
    #[error("reading plan submission note: {0}")]
    ReadPlan(#[from] ReadPlanError),
    #[error("reading decision note: {0}")]
    ReadDecision(#[from] ReadDecisionError),
    #[error("reading review note: {0}")]
    ReadReview(#[from] ReadReviewError),
    #[error("reading implement note: {0}")]
    ReadImplement(#[from] ReadImplementError),
    #[error("reading writ output envelope from bailiff's repo: {0}")]
    ReadEnvelope(#[source] NotesRepoError),
}

/// Resolve the planner envelope referenced by `plan_note` and
/// return its stdout bytes (the plan body) as a UTF-8 [`String`].
///
/// Steps, each guarded by a distinct [`ReadPlanBodyError`] variant:
///
/// 1. Fetch writ's notes refspec into bailiff's repo (`Fetch`).
/// 2. Read the envelope note from writ's notes ref at
///    `plan_note.writ_output_oid` (`ReadEnvelope`).
/// 3. Decode the body as a [`SignedRunEnvelope`] (`DecodeEnvelope`).
/// 4. Defence-in-depth parity checks: the envelope on disk must
///    carry the same `metadata` and `signature` the plan note
///    recorded at submission time (`EnvelopeMetadataMismatch`,
///    `EnvelopeSignatureMismatch`). A divergence means either
///    bailiff's plan note or writ's repo was tampered with after
///    submission.
/// 5. Re-verify the envelope under `allowed_signers` so a tampered
///    `output` field (the signed payload) is caught before its
///    bytes are spliced into the reviewer prompt (`Verify`).
/// 6. Decode the envelope's `output` field as an [`OutputEnvelope`]
///    (`DecodeOutput`).
/// 7. Refuse to use truncated stdout (`OutputTruncated`) — a partial
///    plan body could mislead the reviewer into approving an
///    incomplete spec.
/// 8. UTF-8-decode the stdout bytes (`OutputNotUtf8`); the planner's
///    stdout *is* the plan body and a non-text body is a protocol
///    violation per `docs/plans/2026-05-16-slice-d2-review.md`.
///
/// Why re-verify? `write_plan_note` already ran
/// `verify_run_envelope` at submission time, so a fresh signature
/// check looks redundant. It is not: between submission and review
/// the envelope on disk could be replaced (manual repo repair, a
/// faulty mirror, etc.), and the plan body becomes part of the
/// reviewer prompt — the LLM acts on it. A second verify costs
/// microseconds and forecloses an entire class of "I tampered with
/// the planner's stdout between submission and review" attacks.
///
/// Empty stdout is rejected as a protocol violation: the design
/// doc treats the planner's stdout as the plan body, and a
/// zero-byte plan body means there is nothing for the reviewer to
/// react to. Bailing here keeps a reviewer session from being
/// opened against a vacuous prompt.
pub(crate) fn read_plan_body_bytes(
    bailiff_repo: &NotesRepo,
    writ_repo_path: &Path,
    writ_notes_ref: &NotesRef,
    plan_note: &PlanNote,
    allowed_signers: &AllowedSigners,
) -> Result<String, ReadPlanBodyError> {
    bailiff_repo
        .fetch_from_remote(writ_repo_path, &[WRIT_V1_NOTES_REFSPEC])
        .map_err(ReadPlanBodyError::Fetch)?;
    let body = bailiff_repo
        .read_note(writ_notes_ref, &plan_note.writ_output_oid)
        .map_err(ReadPlanBodyError::ReadEnvelope)?;
    let envelope =
        SignedRunEnvelope::from_bytes(&body).map_err(ReadPlanBodyError::DecodeEnvelope)?;
    if envelope.metadata != plan_note.signed_metadata {
        return Err(ReadPlanBodyError::EnvelopeMetadataMismatch);
    }
    if envelope.signature != plan_note.signature {
        return Err(ReadPlanBodyError::EnvelopeSignatureMismatch);
    }
    verify_run_envelope(&envelope, allowed_signers).map_err(ReadPlanBodyError::Verify)?;
    let output =
        OutputEnvelope::from_bytes(&envelope.output).map_err(ReadPlanBodyError::DecodeOutput)?;
    if let Some(stdout_truncated_at) = output.stdout_truncated_at {
        return Err(ReadPlanBodyError::OutputTruncated {
            stdout_truncated_at,
        });
    }
    if output.stdout.is_empty() {
        return Err(ReadPlanBodyError::OutputEmpty);
    }
    String::from_utf8(output.stdout).map_err(ReadPlanBodyError::OutputNotUtf8)
}

/// Tagged failure modes of the planner-envelope read step that
/// `submit_review` performs before composing the reviewer prompt.
/// Each variant pins one concrete step of the planner-envelope →
/// plan-body extraction so the workflow caller can map it to the
/// right operator message: "writ repo path wrong" vs "envelope on
/// disk diverges from the recorded plan note" vs "planner output
/// isn't text" are all distinct problems.
#[derive(Debug, Error)]
pub enum ReadPlanBodyError {
    /// `git fetch` against writ's repo failed. Usually a wrong
    /// `writ_repo_path` or a filesystem permission problem.
    #[error("fetching writ's notes ref failed: {0}")]
    Fetch(#[source] NotesRepoError),
    /// The fetch succeeded but no note exists at the plan note's
    /// `writ_output_oid` under `writ_notes_ref`. Either the fetch
    /// refspec didn't cover the ref writ used for the planner run,
    /// or writ's repo was pruned since submission.
    #[error("reading the planner envelope note failed: {0}")]
    ReadEnvelope(#[source] NotesRepoError),
    /// The note body exists but isn't a valid [`SignedRunEnvelope`].
    /// Indicates wire-level corruption — `deny_unknown_fields` and
    /// the strict newtype validators make this near-impossible for
    /// any envelope writ itself produced.
    #[error("decoding the planner envelope failed: {0}")]
    DecodeEnvelope(#[source] serde_json::Error),
    /// The envelope's `metadata` on disk differs from the
    /// `signed_metadata` the plan note recorded at submission time.
    /// Defence-in-depth: between submission and review, either
    /// bailiff's plan note or writ's repo was tampered with.
    /// Bailiff refuses to use the on-disk bytes for prompt
    /// composition in either case.
    #[error(
        "planner envelope metadata on disk does not match the metadata recorded in the plan \
         submission note"
    )]
    EnvelopeMetadataMismatch,
    /// Same defence-in-depth check as [`Self::EnvelopeMetadataMismatch`]
    /// but for the signature field. Pinned distinct from the metadata
    /// mismatch because the two have different operator
    /// implications: a metadata mismatch with a valid signature
    /// suggests bailiff's note was edited; a signature mismatch
    /// with matching metadata suggests writ's repo was replaced.
    #[error(
        "planner envelope signature on disk does not match the signature recorded in the plan \
         submission note"
    )]
    EnvelopeSignatureMismatch,
    /// [`verify_run_envelope`] rejected the envelope. The wrapped
    /// [`VerifyError`] names whether the failure was an output
    /// digest mismatch, an unknown signer, or a bad signature.
    /// Caught here so a tampered `output` field (the bytes the
    /// reviewer will see) never reaches the prompt composer.
    #[error("re-verifying the planner envelope failed: {0}")]
    Verify(#[source] VerifyError),
    /// The envelope verified but its `output` field doesn't decode
    /// as an [`OutputEnvelope`]. Indicates wire-level corruption
    /// inside the signed payload — would require the signing key
    /// to be compromised, since the digest covers these bytes.
    #[error("decoding the planner output envelope failed: {0}")]
    DecodeOutput(#[source] serde_json::Error),
    /// The planner's stdout was truncated by writ at byte offset
    /// `stdout_truncated_at`. The captured prefix is genuinely
    /// signed, but using only a prefix as the plan body could
    /// mislead the reviewer into approving an incomplete spec —
    /// the operator's recourse is to re-run the planner with a
    /// narrower scope so the body fits writ's per-stream cap.
    #[error("planner stdout was truncated at byte offset {stdout_truncated_at}")]
    OutputTruncated { stdout_truncated_at: u64 },
    /// The planner's stdout was zero bytes. The design contract
    /// treats the planner's stdout as the plan body, so a zero-byte
    /// stdout is a protocol violation: there is nothing for the
    /// reviewer to react to. Pinned distinct from
    /// [`Self::OutputNotUtf8`] because the operator's response
    /// differs: "the planner ran but emitted nothing" vs "the
    /// planner emitted binary garbage".
    #[error("planner stdout is empty")]
    OutputEmpty,
    /// The planner's stdout bytes are not valid UTF-8. The planner
    /// is contracted to emit a human-readable plan body; non-text
    /// output is a protocol violation. Surfacing the
    /// [`FromUtf8Error`] preserves the byte offset where the
    /// invalid sequence began.
    #[error("planner stdout is not valid UTF-8: {0}")]
    OutputNotUtf8(#[source] FromUtf8Error),
}

#[cfg(test)]
mod decision_tests;
#[cfg(test)]
mod full_plan_tests;
#[cfg(test)]
mod implement_tests;
#[cfg(test)]
mod list_tests;
#[cfg(test)]
mod plan_tests;
#[cfg(test)]
mod read_plan_body_tests;
#[cfg(test)]
mod review_tests;
#[cfg(test)]
mod test_support;

/// Property-based spec for the decision-note round-trip — the
/// load-bearing contract these read helpers exist to provide: the
/// writer's seed-OID derivation and the reader's must agree for
/// *every* note, not just the handful of fixtures the example tests
/// in `decision_tests` pin. Decisions are the cheapest verb (no
/// envelope, no signing), so the round-trip exercises the seed/ref
/// machinery directly. Each case drives a real git repo in a tempdir,
/// so the proptest case count is deliberately low — git fork/exec
/// dominates the wall-clock (mirrors `bailiff_plan_write::spec`).
#[cfg(test)]
mod spec {
    use super::*;
    use crate::bailiff_decision::{Decider, Decision};
    use crate::bailiff_plan_write::write_decision_note;
    use proptest::prelude::*;
    use tempfile::TempDir;
    use writ::core::UnixMillis;

    fn arb_outcome() -> impl Strategy<Value = Decision> {
        prop_oneof![Just(Decision::Accepted), Just(Decision::Rejected)]
    }

    // `Decider::try_new` accepts any non-empty, NUL-free string up to
    // 256 bytes; this charset stays comfortably inside that bound.
    const ARB_DECIDER: &str = "[a-zA-Z0-9:_-]{1,32}";

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Writing an arbitrary decision and reading it back recovers a
        /// byte-for-byte equal note. Generalises the fixed-value
        /// round-trips in `decision_tests` to arbitrary outcome,
        /// decider, and timestamp: any drift between the writer's and
        /// reader's seed-OID derivation surfaces here.
        #[test]
        fn decision_note_round_trips(
            outcome in arb_outcome(),
            decider in ARB_DECIDER,
            decided_at_millis in any::<i64>(),
        ) {
            let tmp = TempDir::new().unwrap();
            let bailiff = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
            let plan_id = PlanId::new();
            let note = DecisionNote {
                plan_id,
                outcome,
                decider: Decider::try_new(decider).unwrap(),
                decided_at: UnixMillis::from_millis(decided_at_millis),
            };
            write_decision_note(&bailiff, &note).unwrap();
            let read_back = read_decision_note(&bailiff, plan_id).unwrap();
            prop_assert_eq!(read_back.as_ref(), Some(&note));
        }

        /// A decision written for one plan is invisible to another:
        /// reading a never-written plan returns `None` even when the
        /// repo already holds an unrelated decision. Pins that the
        /// seed-OID derivation binds the *queried* `plan_id`.
        #[test]
        fn decision_note_does_not_leak_across_plans(
            outcome in arb_outcome(),
            decider in ARB_DECIDER,
            decided_at_millis in any::<i64>(),
        ) {
            let tmp = TempDir::new().unwrap();
            let bailiff = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
            let written = PlanId::new();
            let other = PlanId::new();
            prop_assume!(written != other);
            let note = DecisionNote {
                plan_id: written,
                outcome,
                decider: Decider::try_new(decider).unwrap(),
                decided_at: UnixMillis::from_millis(decided_at_millis),
            };
            write_decision_note(&bailiff, &note).unwrap();
            prop_assert!(read_decision_note(&bailiff, other).unwrap().is_none());
        }
    }
}
