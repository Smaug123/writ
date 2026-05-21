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

use crate::bailiff_decision::{Decider, Decision};
use crate::bailiff_plan_note::{
    BAILIFF_PLAN_NOTES_REF_PREFIX, DecisionNote, DecisionNoteParseError, ImplementNote,
    ImplementNoteParseError, PlanId, PlanNote, PlanNoteParseError, ReviewNote,
    ReviewNoteParseError, plan_decision_seed_blob_bytes, plan_implement_seed_blob_bytes,
    plan_notes_ref, plan_review_seed_blob_bytes, plan_submission_seed_blob_bytes,
};
use crate::bailiff_plan_write::WRIT_V1_NOTES_REFSPEC;
use crate::core::{NotesRef, UnixMillis};
use crate::notes_repo::{NotesRepo, NotesRepoError};
use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
use crate::run_verify::{AllowedSigners, VerifyError, verify_run_envelope};
use crate::vm_git::GitObjectId;

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
    /// [`crate::notes_repo::NotesRepo::write_note`] path or pasted by
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
    /// [`crate::notes_repo::NotesRepo::write_note`] path or pasted by
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
    /// via the low-level [`crate::notes_repo::NotesRepo::write_note`]
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
    /// planted via the low-level [`crate::notes_repo::NotesRepo::write_note`]
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

/// Aggregate per-plan view used by `bailiff plan list`. Each `Option`
/// field is `None` when the corresponding note has not been attached
/// to this plan's ref yet. The two-pass design (`list_plan_ids` then
/// `summarize_plan` per id) is one repo-read for the ref set plus four
/// reads per plan — symmetric with the existing read helpers and
/// requires no schema beyond the seed-OID convention they already
/// share.
///
/// Workflow state is derived from the field set via [`Self::state`];
/// the formatter pins the rendering. Keeping state as a method rather
/// than a stored field means a future caller (e.g. `bailiff plan
/// show`) can recompute it without going through the formatter.
///
/// Submission absent (`submission.is_none()`) is a possible-but-rare
/// state: the plan's ref exists (otherwise [`list_plan_ids`] wouldn't
/// have reported the id), yet no submission has been recorded.
/// Reachable only when a non-submission note was attached first (e.g.
/// a decision written before the plan submission landed) or when a
/// submission note was manually deleted after the fact. Surfaced as
/// [`WorkflowState::Corrupt`] so an operator sees the anomaly rather
/// than silently rendering an incomplete row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BailiffPlanSummary {
    pub plan_id: PlanId,
    pub submission: Option<SubmissionSummary>,
    pub decision: Option<DecisionSummary>,
    pub reviewed_at: Option<UnixMillis>,
    pub implemented_at: Option<UnixMillis>,
}

/// Submission-side projection: `purpose` (the opaque tag bailiff sent
/// to writ on `RunAgent`) and `submitted_at` (lifted from
/// `PlanNote.signed_metadata.completed_at` so the timestamp matches
/// what writ recorded for the planner run). Kept distinct from the
/// other timestamp fields because it is the only one with an
/// associated string, so collapsing it into a bare `Option<UnixMillis>`
/// would lose information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionSummary {
    pub purpose: String,
    pub submitted_at: UnixMillis,
}

/// Decision-side projection: outcome, decider, and timestamp. A
/// projection of [`DecisionNote`] rather than the note itself so the
/// summary type stays narrow — `summarize_plan` discards the
/// `plan_id` field on the note (already on the summary).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionSummary {
    pub outcome: Decision,
    pub decider: Decider,
    pub decided_at: UnixMillis,
}

/// High-level workflow state derived from the presence and content of
/// the four per-plan notes. The variant tree matches the workflow
/// progression — `Submitted` → (`Accepted` | `Rejected`) → `Reviewed`
/// → `Implemented` — except for `Corrupt`, which is the
/// ref-exists-without-submission anomaly.
///
/// State is "the highest workflow step reached," with one caveat:
/// `Rejected` is terminal in the sense that reviewer/implementer
/// stages should not run on a rejected plan, but the repo doesn't
/// enforce the workflow ordering — a manual write could attach a
/// review note to a rejected plan. The derivation prefers to surface
/// the latest stage present in the underlying data; that's why
/// `Implemented` overrides everything else, and `Reviewed` overrides
/// `Rejected` if both are present. The decision field stays visible
/// on the summary so the operator sees the conflict directly.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WorkflowState {
    /// Plan ref exists but no submission note is attached. Indicates
    /// either a workflow-ordering anomaly (non-submission note written
    /// first) or manual repo repair.
    Corrupt,
    /// Submission attached; no decision, review, or implement yet.
    Submitted,
    /// Submission + `Decision::Accepted`; no review or implement yet.
    Accepted,
    /// Submission + `Decision::Rejected`; no review or implement yet.
    Rejected,
    /// Submission + review note attached; no implement note yet.
    /// Decision may or may not be present — the derivation prefers
    /// the latest stage in the data.
    Reviewed,
    /// Implement note attached. Highest stage; overrides all others.
    Implemented,
}

impl WorkflowState {
    /// Stable lowercase string for CLI output. Mirrors the convention
    /// used by [`Decision::as_str`] so the rendered state column reads
    /// naturally next to `decision_outcome=accepted`.
    pub fn as_str(self) -> &'static str {
        match self {
            WorkflowState::Corrupt => "corrupt",
            WorkflowState::Submitted => "submitted",
            WorkflowState::Accepted => "accepted",
            WorkflowState::Rejected => "rejected",
            WorkflowState::Reviewed => "reviewed",
            WorkflowState::Implemented => "implemented",
        }
    }
}

impl std::fmt::Display for WorkflowState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl BailiffPlanSummary {
    /// Derived workflow state. See [`WorkflowState`] for the
    /// progression rule.
    pub fn state(&self) -> WorkflowState {
        if self.submission.is_none() {
            return WorkflowState::Corrupt;
        }
        if self.implemented_at.is_some() {
            return WorkflowState::Implemented;
        }
        if self.reviewed_at.is_some() {
            return WorkflowState::Reviewed;
        }
        match &self.decision {
            Some(d) => match d.outcome {
                Decision::Accepted => WorkflowState::Accepted,
                Decision::Rejected => WorkflowState::Rejected,
            },
            None => WorkflowState::Submitted,
        }
    }
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
/// derived [`WorkflowState::Corrupt`] flag surfaces the anomaly
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

/// Aggregate per-plan view used by `bailiff plan show` (slice F4).
/// Returned by [`read_full_plan`] after composing the four
/// `read_*_note` helpers and, for every available signed note,
/// pairing it with the writ envelope referenced by its
/// `writ_output_oid` and verifying the signature against
/// [`AllowedSigners`].
///
/// All four note fields are `Option`: a workflow-conformant plan has
/// every field set, but each can independently be absent. The plan
/// note is `Option<VerifiedSection<PlanNote>>` rather than bare
/// `VerifiedSection<PlanNote>` so the corrupt-state anomaly F2
/// surfaces in [`WorkflowState::Corrupt`] (ref exists, submission
/// note never attached) keeps being representable here. The decision
/// is `Option<DecisionNote>` because decision notes are bailiff-owned
/// and unsigned in this slice — no envelope to verify.
#[derive(Debug)]
pub struct PlanFullView {
    pub plan_id: PlanId,
    pub plan: Option<VerifiedSection<PlanNote>>,
    pub decision: Option<DecisionNote>,
    pub review: Option<VerifiedSection<ReviewNote>>,
    pub implement: Option<VerifiedSection<ImplementNote>>,
}

/// Pairs a bailiff-side signed note with the outcome of verifying its
/// referenced writ envelope. The four-way split mirrors what
/// `bailiff plan show` (slice F4) must surface:
///
/// - [`VerifiedSection::Verified`]: envelope present, decoded, and
///   end-to-end verified by [`verify_run_envelope`]. Carries both the
///   note and the envelope so the F4 renderer can project from
///   either without re-reading.
/// - [`VerifiedSection::WritEnvelopeMissing`]: bailiff's local copy
///   of writ's notes ref has no annotation at the note's
///   `writ_output_oid`. Either bailiff has not fetched writ's notes
///   since the envelope was minted, or the envelope has been deleted
///   from writ. Operator-recoverable by re-running the relevant
///   `submit*` verb.
/// - [`VerifiedSection::EnvelopeMalformed`]: an envelope body is
///   present at the OID but does not decode as
///   [`SignedRunEnvelope`]. Pure on-disk corruption — surfaces with
///   the underlying [`serde_json::Error`] so the operator can locate
///   the offending note blob.
/// - [`VerifiedSection::SignatureFailure`]: envelope decoded but
///   [`verify_run_envelope`] rejected it. The wrapped [`VerifyError`]
///   names the specific check that failed (output-digest mismatch,
///   signer not in allowed list, or signature invalid).
///
/// The reason to surface failure variants rather than fold them into
/// a top-level `Result<T, _>` is that `show` wants to print every
/// available section even when one fails to verify — collapsing a
/// single failed section into an `Err` would suppress the rest of
/// the plan history, exactly when an operator most needs to see it.
#[derive(Debug)]
pub enum VerifiedSection<T> {
    Verified {
        note: T,
        envelope: SignedRunEnvelope,
    },
    WritEnvelopeMissing {
        note: T,
    },
    EnvelopeMalformed {
        note: T,
        error: serde_json::Error,
    },
    SignatureFailure {
        note: T,
        error: VerifyError,
    },
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
/// [`VerifiedSection`]. The same shape works for every signed bailiff
/// note (`PlanNote`, `ReviewNote`, `ImplementNote`) because all three
/// expose `writ_output_oid` and carry a `signed_metadata` /
/// `signature` pair that the envelope at the OID already covers — so
/// the per-section pairing logic is purely "stash this note next to
/// its verification outcome."
fn wrap_section<T>(verification: EnvelopeVerification, note: T) -> VerifiedSection<T> {
    match verification {
        EnvelopeVerification::Verified(envelope) => VerifiedSection::Verified { note, envelope },
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
/// submissions. Used three times by [`read_full_plan`] with one
/// closure per call site projecting `writ_output_oid` off the
/// particular note type.
fn read_and_project_section<T>(
    bailiff_repo: &NotesRepo,
    note: Option<T>,
    oid_of: impl FnOnce(&T) -> &GitObjectId,
    allowed: &AllowedSigners,
) -> Result<Option<VerifiedSection<T>>, ReadFullPlanError> {
    let Some(note) = note else {
        return Ok(None);
    };
    let verification = read_and_verify_envelope(bailiff_repo, oid_of(&note), allowed)
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
        |n| &n.writ_output_oid,
        allowed_signers,
    )?;
    let decision = read_decision_note(bailiff_repo, plan_id)?;
    let review = read_and_project_section(
        bailiff_repo,
        read_review_note(bailiff_repo, plan_id)?,
        |n| &n.writ_output_oid,
        allowed_signers,
    )?;
    let implement = read_and_project_section(
        bailiff_repo,
        read_implement_note(bailiff_repo, plan_id)?,
        |n| &n.writ_output_oid,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bailiff_decision::{Decider, Decision};
    use crate::bailiff_plan_note::{
        DecisionNote, PlanId, plan_decision_seed_blob_bytes, plan_notes_ref,
        plan_submission_seed_blob_bytes,
    };
    use crate::bailiff_plan_write::write_decision_note;
    use crate::core::UnixMillis;
    use tempfile::TempDir;

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    fn sample_decision_note(plan_id: PlanId, outcome: Decision) -> DecisionNote {
        DecisionNote {
            plan_id,
            outcome,
            decider: Decider::try_new("cli:alice").unwrap(),
            decided_at: UnixMillis::from_millis(1_700_000_000_456),
        }
    }

    /// A plan with no decision note attached returns `Ok(None)`.
    /// Covers the fresh-repo case where the plan's notes ref does
    /// not exist at all — the most common state during normal
    /// operation (operator hasn't ruled on this plan yet).
    #[test]
    fn read_decision_note_returns_none_when_no_decision_recorded() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let result = read_decision_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None for an undecided plan, got: {result:?}"
        );
    }

    /// Load-bearing round-trip: writing a decision and reading it
    /// back recovers a byte-for-byte equal [`DecisionNote`]. Pins
    /// that the writer's seed-OID derivation matches the reader's
    /// — a divergence here would make every decision unrecoverable.
    #[test]
    fn read_decision_note_round_trips_through_write_decision_note() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let written = sample_decision_note(plan_id, Decision::Accepted);
        write_decision_note(&bailiff, &written).unwrap();

        let read_back = read_decision_note(&bailiff, plan_id).unwrap();
        assert_eq!(read_back.as_ref(), Some(&written));
    }

    /// Both outcomes round-trip — pin that the `Decision` enum's
    /// serde tagging stays compatible between writer and reader.
    /// A regression that flipped to a wrapped tagging
    /// (`{"outcome":{"Accepted":null}}`) would break readers writing
    /// the new shape against repos written by the old shape.
    #[test]
    fn read_decision_note_round_trips_both_outcomes() {
        for outcome in [Decision::Accepted, Decision::Rejected] {
            let tmp = TempDir::new().unwrap();
            let bailiff = bailiff_repo(&tmp);
            let plan_id = PlanId::new();
            let written = sample_decision_note(plan_id, outcome);
            write_decision_note(&bailiff, &written).unwrap();
            let read_back = read_decision_note(&bailiff, plan_id).unwrap();
            assert_eq!(read_back.as_ref(), Some(&written), "outcome {outcome:?}");
        }
    }

    /// A submission note alone is not a decision: `read_decision_note`
    /// must return `None` even when the plan's notes ref exists with
    /// a submission attached. Exercises the "ref present, no
    /// annotation at the decision seed's target" branch — the
    /// load-bearing read-side property the two-seeds-per-plan design
    /// exists to provide.
    #[test]
    fn read_decision_note_returns_none_when_only_submission_is_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        // Plant a submission-shaped note directly via `write_note`
        // — the body shape doesn't matter; we only care that the
        // submission's presence under the same ref doesn't fool the
        // decision reader into returning `Some(corrupt)`.
        let submission_seed = plan_submission_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &submission_seed, b"submission-body")
            .unwrap();

        let result = read_decision_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None with only submission present, got: {result:?}",
        );
    }

    /// Distinct plans don't cross-read: reading plan A's decision
    /// must not return plan B's. A regression that dropped `plan_id`
    /// from the ref derivation would silently make every plan share
    /// one decision; this test catches that by writing different
    /// outcomes to two plans and verifying each reader gets its own.
    #[test]
    fn read_decision_note_does_not_cross_read_between_plans() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let p1 = PlanId::new();
        let p2 = PlanId::new();
        write_decision_note(&bailiff, &sample_decision_note(p1, Decision::Accepted)).unwrap();
        write_decision_note(&bailiff, &sample_decision_note(p2, Decision::Rejected)).unwrap();

        let r1 = read_decision_note(&bailiff, p1).unwrap().unwrap();
        let r2 = read_decision_note(&bailiff, p2).unwrap().unwrap();
        assert_eq!(r1.plan_id, p1);
        assert_eq!(r1.outcome, Decision::Accepted);
        assert_eq!(r2.plan_id, p2);
        assert_eq!(r2.outcome, Decision::Rejected);
    }

    /// A semantically-corrupt body — one that parses cleanly as a
    /// `DecisionNote` but whose embedded `plan_id` belongs to a
    /// different plan — surfaces as `ReadDecisionError::PlanIdMismatch`
    /// rather than `Ok(Some(other_plans_decision))`. A future
    /// acceptance gate must never be fooled into ruling on plan A by
    /// reading plan B's verdict; the threat model has manual repo
    /// repair or a buggy low-level writer producing this state, and
    /// the read path is the right place to catch it because that's
    /// where the requested `plan_id` is in scope.
    #[test]
    fn read_decision_note_returns_plan_id_mismatch_when_body_carries_other_plan_id() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let queried = PlanId::new();
        let other = PlanId::new();
        assert_ne!(queried, other, "PlanId::new must not collide");

        // Plant a well-formed DecisionNote for `other` under `queried`'s
        // decision seed. The only way to reach this state is by
        // bypassing `write_decision_note` (which derives the seed from
        // `decision_note.plan_id`), so go through the low-level
        // `write_note` API directly.
        let queried_ref = plan_notes_ref(queried);
        let queried_seed = plan_decision_seed_blob_bytes(queried);
        let foreign_note = sample_decision_note(other, Decision::Accepted);
        bailiff
            .write_note(&queried_ref, &queried_seed, &foreign_note.canonical_bytes())
            .unwrap();

        let err = read_decision_note(&bailiff, queried).unwrap_err();
        match err {
            ReadDecisionError::PlanIdMismatch { requested, found } => {
                assert_eq!(requested, queried);
                assert_eq!(found, other);
            }
            other_err => panic!("expected PlanIdMismatch, got: {other_err:?}"),
        }
    }

    /// A corrupt body at the decision seed's target surfaces as
    /// `ReadDecisionError::Decode`, not as `Ok(None)` or as a
    /// generic `ReadNote` error. Construct the case by planting
    /// non-JSON bytes directly via `NotesRepo::write_note` at the
    /// decision seed — bypassing `write_decision_note` is the only
    /// way to produce this state in practice (the writer always
    /// produces canonical bytes), but the read-side must still
    /// classify it correctly.
    #[test]
    fn read_decision_note_returns_decode_error_on_corrupt_body() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);
        let decision_seed = plan_decision_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &decision_seed, b"not json at all")
            .unwrap();

        let err = read_decision_note(&bailiff, plan_id).unwrap_err();
        assert!(
            matches!(err, ReadDecisionError::Decode(_)),
            "expected Decode error, got: {err:?}",
        );
    }
}

#[cfg(test)]
mod review_tests {
    //! Tests for [`read_review_note`] — the slice D2.3 read counterpart
    //! to [`crate::bailiff_plan_write::write_review_note`]. The
    //! load-bearing round-trip test drives the actual writer so a
    //! future refactor that drifts the writer's seed-OID derivation
    //! from the reader's surfaces here; the remaining tests plant
    //! bodies directly via the low-level [`NotesRepo::write_note`] to
    //! avoid the broker setup the writer would otherwise require.
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_plan_note::{
        PlanId, ReviewNote, plan_notes_ref, plan_review_seed_blob_bytes,
        plan_submission_seed_blob_bytes,
    };
    use crate::bailiff_plan_write::write_review_note;
    use crate::core::{CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::run_verify::AllowedSigners;
    use crate::signing::WritSigningKey;
    use crate::vm_git::GitObjectId;
    use crate::writ_client::RunAgentCompleted;
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    fn writ_notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    /// Build a freshly-signed envelope under `signing_key`. Mirrors
    /// the same-named helper in `bailiff_plan_write::review_tests` so
    /// the envelope shape matches what writ produces today.
    fn freshly_signed(signing_key: &WritSigningKey) -> SignedRunEnvelope {
        let output = OutputEnvelope {
            stdout: b"reviewer prose".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let output_bytes = output.to_bytes();
        let output_sha = Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap();
        let prompt_sha = Sha256Hex::try_new(sha256_hex(b"reviewer-prompt")).unwrap();
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

    /// Stand up a writ repo containing one signed envelope and return
    /// the `RunAgentCompleted` reply bailiff would have seen, so the
    /// round-trip test can drive `write_review_note` end-to-end.
    fn writ_repo_with_envelope(
        tmp: &TempDir,
        signing_key: &WritSigningKey,
    ) -> (NotesRepo, RunAgentCompleted) {
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let envelope = freshly_signed(signing_key);
        let body = envelope.to_bytes();
        let target = writ_repo
            .write_note(
                &writ_notes_ref(),
                envelope.metadata.run_id.to_string().as_bytes(),
                &body,
            )
            .unwrap();
        let completed = RunAgentCompleted {
            output_oid: target,
            signed_metadata: envelope.metadata,
            signature: envelope.signature,
        };
        (writ_repo, completed)
    }

    /// Plant a ready-made [`ReviewNote`] directly at its review seed
    /// via the low-level [`NotesRepo::write_note`] API. Used by tests
    /// that don't need to exercise the full fetch-verify-attach path
    /// of [`write_review_note`] — e.g. cross-plan reads, decode
    /// failures.
    fn plant_review_note(bailiff: &NotesRepo, plan_id: PlanId, note: &ReviewNote) -> GitObjectId {
        let plan_ref = plan_notes_ref(plan_id);
        let seed = plan_review_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &seed, &note.canonical_bytes())
            .unwrap()
    }

    fn sample_review_note(plan_id: PlanId) -> ReviewNote {
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let envelope = freshly_signed(&signing_key);
        ReviewNote {
            plan_id,
            purpose: "plan-review".into(),
            writ_output_oid: GitObjectId::new("c".repeat(40)).unwrap(),
            signed_metadata: envelope.metadata,
            signature: envelope.signature,
        }
    }

    /// A plan with no review note attached returns `Ok(None)`. Covers
    /// the fresh-repo case where the plan's notes ref does not exist
    /// at all — the most common state during normal operation (writ
    /// has not produced a reviewer envelope yet).
    #[test]
    fn read_review_note_returns_none_when_no_review_recorded() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let result = read_review_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None for an unreviewed plan, got: {result:?}",
        );
    }

    /// Load-bearing round-trip: driving the real
    /// [`write_review_note`] then reading back via
    /// [`read_review_note`] recovers a byte-for-byte equal
    /// [`ReviewNote`]. Pins that the writer's seed-OID derivation
    /// matches the reader's — a divergence here would make every
    /// review unrecoverable.
    #[test]
    fn read_review_note_round_trips_through_write_review_note() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let plan_id = PlanId::new();
        let purpose = "plan-review".to_string();
        write_review_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            plan_id,
            purpose.clone(),
            &completed,
            &allowed,
        )
        .expect("write_review_note must succeed");

        let read_back = read_review_note(&bailiff, plan_id)
            .expect("read_review_note must succeed")
            .expect("read_review_note must return Some after a successful write");
        assert_eq!(read_back.plan_id, plan_id);
        assert_eq!(read_back.purpose, purpose);
        assert_eq!(read_back.writ_output_oid, completed.output_oid);
        assert_eq!(read_back.signed_metadata, completed.signed_metadata);
        assert_eq!(read_back.signature, completed.signature);
    }

    /// A submission note alone is not a review: `read_review_note`
    /// must return `None` even when the plan's notes ref exists with
    /// a submission attached. Exercises the "ref present, no
    /// annotation at the review seed's target" branch — the
    /// load-bearing read-side property the three-seeds-per-plan
    /// design exists to provide.
    #[test]
    fn read_review_note_returns_none_when_only_submission_is_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        let submission_seed = plan_submission_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &submission_seed, b"submission-body")
            .unwrap();

        let result = read_review_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None with only submission present, got: {result:?}",
        );
    }

    /// A decision note alone is not a review either. Same coexistence
    /// property as the submission case but for the third seed pair.
    /// Without this, a future suffix collision between `::decision`
    /// and `::review` would silently make every decision read as a
    /// review.
    #[test]
    fn read_review_note_returns_none_when_only_decision_is_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        let decision_seed = plan_decision_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &decision_seed, b"decision-body")
            .unwrap();

        let result = read_review_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None with only decision present, got: {result:?}",
        );
    }

    /// Distinct plans don't cross-read: reading plan A's review must
    /// not return plan B's. A regression that dropped `plan_id` from
    /// the ref derivation would silently make every plan share one
    /// review; this test catches that by planting different purposes
    /// for two plans and verifying each reader gets its own.
    #[test]
    fn read_review_note_does_not_cross_read_between_plans() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let p1 = PlanId::new();
        let p2 = PlanId::new();
        let mut note1 = sample_review_note(p1);
        note1.purpose = "first".into();
        let mut note2 = sample_review_note(p2);
        note2.purpose = "second".into();
        plant_review_note(&bailiff, p1, &note1);
        plant_review_note(&bailiff, p2, &note2);

        let r1 = read_review_note(&bailiff, p1).unwrap().unwrap();
        let r2 = read_review_note(&bailiff, p2).unwrap().unwrap();
        assert_eq!(r1.plan_id, p1);
        assert_eq!(r1.purpose, "first");
        assert_eq!(r2.plan_id, p2);
        assert_eq!(r2.purpose, "second");
    }

    /// A semantically-corrupt body — one that parses cleanly as a
    /// [`ReviewNote`] but whose embedded `plan_id` belongs to a
    /// different plan — surfaces as `ReadReviewError::PlanIdMismatch`
    /// rather than `Ok(Some(other_plans_review))`. A future caller
    /// rendering reviewer prose must never display plan B's review
    /// when asked about plan A; the threat model has manual repo
    /// repair or a buggy low-level writer producing this state, and
    /// the read path is the right place to catch it because that's
    /// where the requested `plan_id` is in scope.
    #[test]
    fn read_review_note_returns_plan_id_mismatch_when_body_carries_other_plan_id() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let queried = PlanId::new();
        let other = PlanId::new();
        assert_ne!(queried, other, "PlanId::new must not collide");

        // Plant a well-formed ReviewNote for `other` under `queried`'s
        // review seed. The only way to reach this state is by
        // bypassing `write_review_note` (which derives the seed from
        // the `plan_id` it embeds in the note), so go through the
        // low-level `write_note` API.
        let queried_ref = plan_notes_ref(queried);
        let queried_seed = plan_review_seed_blob_bytes(queried);
        let foreign_note = sample_review_note(other);
        bailiff
            .write_note(&queried_ref, &queried_seed, &foreign_note.canonical_bytes())
            .unwrap();

        let err = read_review_note(&bailiff, queried).unwrap_err();
        match err {
            ReadReviewError::PlanIdMismatch { requested, found } => {
                assert_eq!(requested, queried);
                assert_eq!(found, other);
            }
            other_err => panic!("expected PlanIdMismatch, got: {other_err:?}"),
        }
    }

    /// A corrupt body at the review seed's target surfaces as
    /// `ReadReviewError::Decode`, not as `Ok(None)` or as a generic
    /// `ReadNote` error. Construct the case by planting non-JSON
    /// bytes directly via `NotesRepo::write_note` at the review
    /// seed — bypassing `write_review_note` is the only way to
    /// produce this state in practice (the writer always produces
    /// canonical bytes), but the read-side must still classify it
    /// correctly.
    #[test]
    fn read_review_note_returns_decode_error_on_corrupt_body() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);
        let review_seed = plan_review_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &review_seed, b"not json at all")
            .unwrap();

        let err = read_review_note(&bailiff, plan_id).unwrap_err();
        assert!(
            matches!(err, ReadReviewError::Decode(_)),
            "expected Decode error, got: {err:?}",
        );
    }
}

#[cfg(test)]
mod plan_tests {
    //! Tests for [`read_plan_note`] — the slice D2.4a read counterpart
    //! to [`crate::bailiff_plan_write::write_plan_note`]. The
    //! load-bearing round-trip test drives the actual writer so a
    //! future refactor that drifts the writer's seed-OID derivation
    //! from the reader's surfaces here; the remaining tests plant
    //! bodies directly via the low-level [`NotesRepo::write_note`] to
    //! avoid the broker setup the writer would otherwise require.
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_plan_note::{
        PlanId, PlanNote, plan_decision_seed_blob_bytes, plan_notes_ref,
        plan_review_seed_blob_bytes, plan_submission_seed_blob_bytes,
    };
    use crate::bailiff_plan_write::write_plan_note;
    use crate::core::{CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::run_verify::AllowedSigners;
    use crate::signing::WritSigningKey;
    use crate::vm_git::GitObjectId;
    use crate::writ_client::RunAgentCompleted;
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    fn writ_notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    /// Build a freshly-signed envelope under `signing_key`. Mirrors
    /// the same-named helper in `bailiff_plan_write::tests` so the
    /// envelope shape matches what writ produces today.
    fn freshly_signed(signing_key: &WritSigningKey) -> SignedRunEnvelope {
        let output = OutputEnvelope {
            stdout: b"planner prose".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let output_bytes = output.to_bytes();
        let output_sha = Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap();
        let prompt_sha = Sha256Hex::try_new(sha256_hex(b"planner-prompt")).unwrap();
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

    /// Stand up a writ repo containing one signed envelope and return
    /// the `RunAgentCompleted` reply bailiff would have seen, so the
    /// round-trip test can drive `write_plan_note` end-to-end.
    fn writ_repo_with_envelope(
        tmp: &TempDir,
        signing_key: &WritSigningKey,
    ) -> (NotesRepo, RunAgentCompleted) {
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let envelope = freshly_signed(signing_key);
        let body = envelope.to_bytes();
        let target = writ_repo
            .write_note(
                &writ_notes_ref(),
                envelope.metadata.run_id.to_string().as_bytes(),
                &body,
            )
            .unwrap();
        let completed = RunAgentCompleted {
            output_oid: target,
            signed_metadata: envelope.metadata,
            signature: envelope.signature,
        };
        (writ_repo, completed)
    }

    /// Plant a ready-made [`PlanNote`] directly at its submission seed
    /// via the low-level [`NotesRepo::write_note`] API. Used by tests
    /// that don't need to exercise the full fetch-verify-attach path
    /// of [`write_plan_note`] — e.g. cross-plan reads, decode failures.
    fn plant_plan_note(bailiff: &NotesRepo, plan_id: PlanId, note: &PlanNote) -> GitObjectId {
        let plan_ref = plan_notes_ref(plan_id);
        let seed = plan_submission_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &seed, &note.canonical_bytes())
            .unwrap()
    }

    fn sample_plan_note(plan_id: PlanId) -> PlanNote {
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let envelope = freshly_signed(&signing_key);
        PlanNote {
            plan_id,
            purpose: "plan-submission".into(),
            writ_output_oid: GitObjectId::new("d".repeat(40)).unwrap(),
            signed_metadata: envelope.metadata,
            signature: envelope.signature,
        }
    }

    /// A plan with no submission note attached returns `Ok(None)`.
    /// Covers the fresh-repo case where the plan's notes ref does
    /// not exist at all — the most common state during normal
    /// operation (writ has not produced a planner envelope yet).
    #[test]
    fn read_plan_note_returns_none_when_no_submission_recorded() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let result = read_plan_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None for an unsubmitted plan, got: {result:?}",
        );
    }

    /// Load-bearing round-trip: driving the real
    /// [`write_plan_note`] then reading back via [`read_plan_note`]
    /// recovers a byte-for-byte equal [`PlanNote`]. Pins that the
    /// writer's seed-OID derivation matches the reader's — a
    /// divergence here would make every submission unrecoverable.
    #[test]
    fn read_plan_note_round_trips_through_write_plan_note() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let plan_id = PlanId::new();
        let purpose = "plan-submission".to_string();
        write_plan_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            plan_id,
            purpose.clone(),
            &completed,
            &allowed,
        )
        .expect("write_plan_note must succeed");

        let read_back = read_plan_note(&bailiff, plan_id)
            .expect("read_plan_note must succeed")
            .expect("read_plan_note must return Some after a successful write");
        assert_eq!(read_back.plan_id, plan_id);
        assert_eq!(read_back.purpose, purpose);
        assert_eq!(read_back.writ_output_oid, completed.output_oid);
        assert_eq!(read_back.signed_metadata, completed.signed_metadata);
        assert_eq!(read_back.signature, completed.signature);
    }

    /// A decision note alone is not a submission: `read_plan_note`
    /// must return `None` even when the plan's notes ref exists with
    /// a decision attached. Exercises the "ref present, no
    /// annotation at the submission seed's target" branch — the
    /// load-bearing read-side property the three-seeds-per-plan
    /// design exists to provide. Without this, a future suffix
    /// collision between `::decision` and the bare-`plan_id`
    /// submission seed would silently make every decision read as a
    /// submission.
    #[test]
    fn read_plan_note_returns_none_when_only_decision_is_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        let decision_seed = plan_decision_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &decision_seed, b"decision-body")
            .unwrap();

        let result = read_plan_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None with only decision present, got: {result:?}",
        );
    }

    /// A review note alone is not a submission either. Same
    /// coexistence property as the decision case but for the third
    /// seed pair: a future suffix collision between `::review` and
    /// the bare-`plan_id` submission seed would silently make every
    /// review read as a submission.
    #[test]
    fn read_plan_note_returns_none_when_only_review_is_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        let review_seed = plan_review_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &review_seed, b"review-body")
            .unwrap();

        let result = read_plan_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None with only review present, got: {result:?}",
        );
    }

    /// Distinct plans don't cross-read: reading plan A's submission
    /// must not return plan B's. A regression that dropped `plan_id`
    /// from the ref derivation would silently make every plan share
    /// one submission; this test catches that by planting different
    /// purposes for two plans and verifying each reader gets its own.
    #[test]
    fn read_plan_note_does_not_cross_read_between_plans() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let p1 = PlanId::new();
        let p2 = PlanId::new();
        let mut note1 = sample_plan_note(p1);
        note1.purpose = "first".into();
        let mut note2 = sample_plan_note(p2);
        note2.purpose = "second".into();
        plant_plan_note(&bailiff, p1, &note1);
        plant_plan_note(&bailiff, p2, &note2);

        let r1 = read_plan_note(&bailiff, p1).unwrap().unwrap();
        let r2 = read_plan_note(&bailiff, p2).unwrap().unwrap();
        assert_eq!(r1.plan_id, p1);
        assert_eq!(r1.purpose, "first");
        assert_eq!(r2.plan_id, p2);
        assert_eq!(r2.purpose, "second");
    }

    /// A semantically-corrupt body — one that parses cleanly as a
    /// [`PlanNote`] but whose embedded `plan_id` belongs to a
    /// different plan — surfaces as `ReadPlanError::PlanIdMismatch`
    /// rather than `Ok(Some(other_plans_submission))`. The upcoming
    /// `submit_review` workflow (D2.4b) resolves the submission's
    /// `writ_output_oid` to fetch the planner envelope; if a foreign
    /// plan's submission slipped past this check, the reviewer
    /// prompt for plan A would carry plan B's body. The threat model
    /// has manual repo repair or a buggy low-level writer producing
    /// this state, and the read path is the right place to catch it
    /// because that's where the requested `plan_id` is in scope.
    #[test]
    fn read_plan_note_returns_plan_id_mismatch_when_body_carries_other_plan_id() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let queried = PlanId::new();
        let other = PlanId::new();
        assert_ne!(queried, other, "PlanId::new must not collide");

        // Plant a well-formed PlanNote for `other` under `queried`'s
        // submission seed. The only way to reach this state is by
        // bypassing `write_plan_note` (which derives the seed from
        // the `plan_id` it embeds in the note), so go through the
        // low-level `write_note` API.
        let queried_ref = plan_notes_ref(queried);
        let queried_seed = plan_submission_seed_blob_bytes(queried);
        let foreign_note = sample_plan_note(other);
        bailiff
            .write_note(&queried_ref, &queried_seed, &foreign_note.canonical_bytes())
            .unwrap();

        let err = read_plan_note(&bailiff, queried).unwrap_err();
        match err {
            ReadPlanError::PlanIdMismatch { requested, found } => {
                assert_eq!(requested, queried);
                assert_eq!(found, other);
            }
            other_err => panic!("expected PlanIdMismatch, got: {other_err:?}"),
        }
    }

    /// A corrupt body at the submission seed's target surfaces as
    /// `ReadPlanError::Decode`, not as `Ok(None)` or as a generic
    /// `ReadNote` error. Construct the case by planting non-JSON
    /// bytes directly via `NotesRepo::write_note` at the submission
    /// seed — bypassing `write_plan_note` is the only way to produce
    /// this state in practice (the writer always produces canonical
    /// bytes), but the read-side must still classify it correctly.
    #[test]
    fn read_plan_note_returns_decode_error_on_corrupt_body() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);
        let submission_seed = plan_submission_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &submission_seed, b"not json at all")
            .unwrap();

        let err = read_plan_note(&bailiff, plan_id).unwrap_err();
        assert!(
            matches!(err, ReadPlanError::Decode(_)),
            "expected Decode error, got: {err:?}",
        );
    }
}

#[cfg(test)]
mod implement_tests {
    //! Tests for [`read_implement_note`] — the slice E3 read counterpart
    //! to [`crate::bailiff_plan_write::write_implement_note`]. Mirrors
    //! `review_tests` and `plan_tests`: the load-bearing round-trip
    //! test drives the actual writer so a future refactor that drifts
    //! the writer's seed-OID derivation from the reader's surfaces
    //! here; the remaining tests plant bodies directly via the
    //! low-level [`NotesRepo::write_note`] to avoid the broker setup
    //! the writer would otherwise require.
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_plan_note::{
        ImplementNote, PlanId, plan_implement_seed_blob_bytes, plan_notes_ref,
        plan_submission_seed_blob_bytes,
    };
    use crate::bailiff_plan_write::write_implement_note;
    use crate::core::{CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::run_verify::AllowedSigners;
    use crate::signing::WritSigningKey;
    use crate::vm_git::GitObjectId;
    use crate::writ_client::RunAgentCompleted;
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    fn writ_notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    /// Build a freshly-signed envelope under `signing_key`. Mirrors
    /// the same-named helper in `bailiff_plan_write::implement_tests`
    /// so the envelope shape matches what writ produces today.
    fn freshly_signed(signing_key: &WritSigningKey) -> SignedRunEnvelope {
        let output = OutputEnvelope {
            stdout: b"implementer prose".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let output_bytes = output.to_bytes();
        let output_sha = Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap();
        let prompt_sha = Sha256Hex::try_new(sha256_hex(b"implementer-prompt")).unwrap();
        let metadata = SignedRunMetadata {
            run_id: AgentRunId::new(),
            session_id: SessionId::new(),
            prompt_sha256: prompt_sha,
            output_envelope_sha256: output_sha,
            capabilities: vec![CapabilitySet::WorkspaceWrite {
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

    /// Stand up a writ repo containing one signed envelope and return
    /// the `RunAgentCompleted` reply bailiff would have seen, so the
    /// round-trip test can drive `write_implement_note` end-to-end.
    fn writ_repo_with_envelope(
        tmp: &TempDir,
        signing_key: &WritSigningKey,
    ) -> (NotesRepo, RunAgentCompleted) {
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let envelope = freshly_signed(signing_key);
        let body = envelope.to_bytes();
        let target = writ_repo
            .write_note(
                &writ_notes_ref(),
                envelope.metadata.run_id.to_string().as_bytes(),
                &body,
            )
            .unwrap();
        let completed = RunAgentCompleted {
            output_oid: target,
            signed_metadata: envelope.metadata,
            signature: envelope.signature,
        };
        (writ_repo, completed)
    }

    /// Plant a ready-made [`ImplementNote`] directly at its implement
    /// seed via the low-level [`NotesRepo::write_note`] API. Used by
    /// tests that don't need to exercise the full fetch-verify-attach
    /// path of [`write_implement_note`] — e.g. cross-plan reads, decode
    /// failures.
    fn plant_implement_note(
        bailiff: &NotesRepo,
        plan_id: PlanId,
        note: &ImplementNote,
    ) -> GitObjectId {
        let plan_ref = plan_notes_ref(plan_id);
        let seed = plan_implement_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &seed, &note.canonical_bytes())
            .unwrap()
    }

    fn sample_implement_note(plan_id: PlanId) -> ImplementNote {
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let envelope = freshly_signed(&signing_key);
        ImplementNote {
            plan_id,
            purpose: "plan-implement".into(),
            writ_output_oid: GitObjectId::new("d".repeat(40)).unwrap(),
            signed_metadata: envelope.metadata,
            signature: envelope.signature,
        }
    }

    /// A plan with no implement note attached returns `Ok(None)`.
    /// Covers the fresh-repo case where the plan's notes ref does not
    /// exist at all — the most common state during normal operation
    /// (writ has not produced an implementer envelope yet).
    #[test]
    fn read_implement_note_returns_none_when_no_implement_recorded() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let result = read_implement_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None for an unimplemented plan, got: {result:?}",
        );
    }

    /// Load-bearing round-trip: driving the real
    /// [`write_implement_note`] then reading back via
    /// [`read_implement_note`] recovers a byte-for-byte equal
    /// [`ImplementNote`]. Pins that the writer's seed-OID derivation
    /// matches the reader's — a divergence here would make every
    /// implement unrecoverable.
    #[test]
    fn read_implement_note_round_trips_through_write_implement_note() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let (writ_repo, completed) = writ_repo_with_envelope(&tmp, &signing_key);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();
        let plan_id = PlanId::new();
        let purpose = "plan-implement".to_string();
        write_implement_note(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            plan_id,
            purpose.clone(),
            &completed,
            &allowed,
        )
        .expect("write_implement_note must succeed");

        let read_back = read_implement_note(&bailiff, plan_id)
            .expect("read_implement_note must succeed")
            .expect("read_implement_note must return Some after a successful write");
        assert_eq!(read_back.plan_id, plan_id);
        assert_eq!(read_back.purpose, purpose);
        assert_eq!(read_back.writ_output_oid, completed.output_oid);
        assert_eq!(read_back.signed_metadata, completed.signed_metadata);
        assert_eq!(read_back.signature, completed.signature);
    }

    /// A submission note alone is not an implement: `read_implement_note`
    /// must return `None` even when the plan's notes ref exists with
    /// a submission attached. Exercises the "ref present, no
    /// annotation at the implement seed's target" branch — the
    /// load-bearing read-side property the four-seeds-per-plan design
    /// exists to provide.
    #[test]
    fn read_implement_note_returns_none_when_only_submission_is_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        let submission_seed = plan_submission_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &submission_seed, b"submission-body")
            .unwrap();

        let result = read_implement_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None with only submission present, got: {result:?}",
        );
    }

    /// A decision note alone is not an implement either. Without this,
    /// a future suffix collision between `::decision` and `::implement`
    /// would silently make every decision read as an implement.
    #[test]
    fn read_implement_note_returns_none_when_only_decision_is_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        let decision_seed = plan_decision_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &decision_seed, b"decision-body")
            .unwrap();

        let result = read_implement_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None with only decision present, got: {result:?}",
        );
    }

    /// A review note alone is not an implement. Closes the all-pairs
    /// coexistence matrix on the read side (the existing `review_tests`
    /// only cover submission + decision); without this, a future suffix
    /// collision between `::review` and `::implement` would silently
    /// make every review read as an implement.
    #[test]
    fn read_implement_note_returns_none_when_only_review_is_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);

        let review_seed = plan_review_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &review_seed, b"review-body")
            .unwrap();

        let result = read_implement_note(&bailiff, plan_id).unwrap();
        assert!(
            result.is_none(),
            "expected None with only review present, got: {result:?}",
        );
    }

    /// Distinct plans don't cross-read: reading plan A's implement
    /// must not return plan B's. A regression that dropped `plan_id`
    /// from the ref derivation would silently make every plan share
    /// one implement; this test catches that by planting different
    /// purposes for two plans and verifying each reader gets its own.
    #[test]
    fn read_implement_note_does_not_cross_read_between_plans() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let p1 = PlanId::new();
        let p2 = PlanId::new();
        let mut note1 = sample_implement_note(p1);
        note1.purpose = "first".into();
        let mut note2 = sample_implement_note(p2);
        note2.purpose = "second".into();
        plant_implement_note(&bailiff, p1, &note1);
        plant_implement_note(&bailiff, p2, &note2);

        let r1 = read_implement_note(&bailiff, p1).unwrap().unwrap();
        let r2 = read_implement_note(&bailiff, p2).unwrap().unwrap();
        assert_eq!(r1.plan_id, p1);
        assert_eq!(r1.purpose, "first");
        assert_eq!(r2.plan_id, p2);
        assert_eq!(r2.purpose, "second");
    }

    /// A semantically-corrupt body — one that parses cleanly as an
    /// [`ImplementNote`] but whose embedded `plan_id` belongs to a
    /// different plan — surfaces as `ReadImplementError::PlanIdMismatch`
    /// rather than `Ok(Some(other_plans_implement))`. A future caller
    /// rendering implementer output must never surface plan B's
    /// implement when asked about plan A; the threat model has manual
    /// repo repair or a buggy low-level writer producing this state,
    /// and the read path is the right place to catch it because that's
    /// where the requested `plan_id` is in scope.
    #[test]
    fn read_implement_note_returns_plan_id_mismatch_when_body_carries_other_plan_id() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let queried = PlanId::new();
        let other = PlanId::new();
        assert_ne!(queried, other, "PlanId::new must not collide");

        // Plant a well-formed ImplementNote for `other` under
        // `queried`'s implement seed. The only way to reach this state
        // is by bypassing `write_implement_note` (which derives the
        // seed from the `plan_id` it embeds in the note), so go
        // through the low-level `write_note` API.
        let queried_ref = plan_notes_ref(queried);
        let queried_seed = plan_implement_seed_blob_bytes(queried);
        let foreign_note = sample_implement_note(other);
        bailiff
            .write_note(&queried_ref, &queried_seed, &foreign_note.canonical_bytes())
            .unwrap();

        let err = read_implement_note(&bailiff, queried).unwrap_err();
        match err {
            ReadImplementError::PlanIdMismatch { requested, found } => {
                assert_eq!(requested, queried);
                assert_eq!(found, other);
            }
            other_err => panic!("expected PlanIdMismatch, got: {other_err:?}"),
        }
    }

    /// A corrupt body at the implement seed's target surfaces as
    /// `ReadImplementError::Decode`, not as `Ok(None)` or as a generic
    /// `ReadNote` error. Construct the case by planting non-JSON bytes
    /// directly via `NotesRepo::write_note` at the implement seed —
    /// bypassing `write_implement_note` is the only way to produce
    /// this state in practice (the writer always produces canonical
    /// bytes), but the read-side must still classify it correctly.
    #[test]
    fn read_implement_note_returns_decode_error_on_corrupt_body() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        let plan_ref = plan_notes_ref(plan_id);
        let implement_seed = plan_implement_seed_blob_bytes(plan_id);
        bailiff
            .write_note(&plan_ref, &implement_seed, b"not json at all")
            .unwrap();

        let err = read_implement_note(&bailiff, plan_id).unwrap_err();
        assert!(
            matches!(err, ReadImplementError::Decode(_)),
            "expected Decode error, got: {err:?}",
        );
    }
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
mod read_plan_body_tests {
    //! Unit tests for [`read_plan_body_bytes`]. Each test plants a
    //! known envelope in a writ repo via the same `NotesRepo`
    //! primitives the production writer uses, then probes a single
    //! failure mode. The helper is the new defence-in-depth surface
    //! for "bailiff reads its own signed envelopes back" so every
    //! variant of [`ReadPlanBodyError`] gets a pinned test.
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_plan_note::PlanId;
    use crate::core::{CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, UnixMillis};
    use crate::protocol::SignedRunMetadata;
    use crate::signing::WritSigningKey;
    use crate::vm_git::GitObjectId;
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const SIGNING_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing.key.pub");
    const OTHER_PUB: &str = include_str!("../tests/fixtures/ed25519_test_signing_other.key.pub");

    fn writ_notes_ref() -> NotesRef {
        NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
    }

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    /// Build an envelope around an arbitrary stdout payload. Used
    /// for tests that need to exercise the post-verify decode steps
    /// (truncation, UTF-8) — the envelope must sign whatever payload
    /// the test plants or `Verify` would fail first.
    fn signed_envelope_with_output(
        signing_key: &WritSigningKey,
        output: OutputEnvelope,
    ) -> SignedRunEnvelope {
        let output_bytes = output.to_bytes();
        let output_sha = Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap();
        let prompt_sha = Sha256Hex::try_new(sha256_hex(b"planner-prompt")).unwrap();
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

    /// Plant a known envelope in a writ repo, return the writ repo +
    /// the `PlanNote` bailiff would have recorded if it had run
    /// `write_plan_note` against this envelope.
    ///
    /// The `PlanNote` is the second input to `read_plan_body_bytes`;
    /// building it here (rather than via the real writer) keeps the
    /// test focused on the read-side behaviour and lets the negative
    /// tests poke at individual fields.
    fn writ_repo_and_plan_note(
        tmp: &TempDir,
        envelope: &SignedRunEnvelope,
    ) -> (NotesRepo, PlanNote) {
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let body = envelope.to_bytes();
        let oid = writ_repo
            .write_note(
                &writ_notes_ref(),
                envelope.metadata.run_id.to_string().as_bytes(),
                &body,
            )
            .unwrap();
        let plan_note = PlanNote {
            plan_id: PlanId::new(),
            purpose: "plan-submission".into(),
            writ_output_oid: oid,
            signed_metadata: envelope.metadata.clone(),
            signature: envelope.signature.clone(),
        };
        (writ_repo, plan_note)
    }

    /// Happy path: a freshly-signed envelope under a trusted key,
    /// stdout containing UTF-8 prose, no truncation. Returns the
    /// stdout bytes exactly.
    #[test]
    fn happy_path_returns_stdout_as_string() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let plan_body = "# Plan\n\nReplace bar with baz.\n";
        let output = OutputEnvelope {
            stdout: plan_body.as_bytes().to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let envelope = signed_envelope_with_output(&signing_key, output);
        let (writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let body = read_plan_body_bytes(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            &plan_note,
            &allowed,
        )
        .expect("happy path must extract the plan body");
        assert_eq!(body, plan_body);
    }

    /// `Fetch` failure when the writ repo path doesn't point to a
    /// usable repo. Construct the case by passing a temp directory
    /// that exists but contains no git repo.
    #[test]
    fn fetch_failure_when_writ_repo_path_is_not_a_repo() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let output = OutputEnvelope {
            stdout: b"body".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let envelope = signed_envelope_with_output(&signing_key, output);
        let (_writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let bogus_path = tmp.path().join("nonexistent");
        let err = read_plan_body_bytes(
            &bailiff,
            &bogus_path,
            &writ_notes_ref(),
            &plan_note,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, ReadPlanBodyError::Fetch(_)),
            "expected Fetch, got: {err:?}",
        );
    }

    /// `ReadEnvelope` failure when the OID recorded on the plan
    /// note isn't present in writ's repo. Build a plan note that
    /// references an OID nothing writes to.
    #[test]
    fn read_envelope_failure_when_oid_is_absent() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let output = OutputEnvelope {
            stdout: b"body".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let envelope = signed_envelope_with_output(&signing_key, output);
        let (writ_repo, mut plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
        // Replace the legitimate OID with one nothing was written
        // for. The OID is 40 hex chars; pick one no SHA-1 would
        // accidentally produce.
        plan_note.writ_output_oid = GitObjectId::new("e".repeat(40)).unwrap();
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let err = read_plan_body_bytes(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            &plan_note,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, ReadPlanBodyError::ReadEnvelope(_)),
            "expected ReadEnvelope, got: {err:?}",
        );
    }

    /// `DecodeEnvelope` failure when the bytes at the recorded OID
    /// aren't a valid `SignedRunEnvelope`. Plant non-JSON bytes
    /// directly at the OID and reference them from the plan note.
    #[test]
    fn decode_envelope_failure_when_body_is_not_envelope_json() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let writ_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
        let oid = writ_repo
            .write_note(&writ_notes_ref(), b"corrupt-seed", b"not json at all")
            .unwrap();
        let dummy_envelope = signed_envelope_with_output(
            &signing_key,
            OutputEnvelope {
                stdout: b"x".to_vec(),
                stderr: Vec::new(),
                stdout_truncated_at: None,
                stderr_truncated_at: None,
            },
        );
        let plan_note = PlanNote {
            plan_id: PlanId::new(),
            purpose: "plan-submission".into(),
            writ_output_oid: oid,
            signed_metadata: dummy_envelope.metadata,
            signature: dummy_envelope.signature,
        };
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let err = read_plan_body_bytes(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            &plan_note,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, ReadPlanBodyError::DecodeEnvelope(_)),
            "expected DecodeEnvelope, got: {err:?}",
        );
    }

    /// `EnvelopeMetadataMismatch` when the recorded plan-note
    /// metadata differs from the metadata on disk. Construct a
    /// plan note that records *different* metadata than what writ's
    /// repo carries — the helper must refuse rather than accept
    /// whichever copy is more recent.
    #[test]
    fn envelope_metadata_mismatch_when_plan_note_records_other_metadata() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let output = OutputEnvelope {
            stdout: b"body".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let envelope = signed_envelope_with_output(&signing_key, output);
        let (writ_repo, mut plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
        // Tweak the recorded metadata so it differs from what writ
        // signed — bump `exit_code` because it's covered by the
        // signature but doesn't change the digest of any other field.
        plan_note.signed_metadata.exit_code = 99;
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let err = read_plan_body_bytes(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            &plan_note,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, ReadPlanBodyError::EnvelopeMetadataMismatch),
            "expected EnvelopeMetadataMismatch, got: {err:?}",
        );
    }

    /// `EnvelopeSignatureMismatch` when the recorded plan-note
    /// signature differs from the signature on disk but the metadata
    /// matches. Sign a second envelope (different run id ⇒ different
    /// signed bytes ⇒ different signature) and splice its signature
    /// onto the plan note while keeping the on-disk envelope.
    #[test]
    fn envelope_signature_mismatch_when_plan_note_records_other_signature() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let output = OutputEnvelope {
            stdout: b"body".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let envelope = signed_envelope_with_output(&signing_key, output);
        let (writ_repo, mut plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
        // Sign a different envelope, take its signature, put it on
        // the plan note. The on-disk envelope's signature is still
        // the legitimate one; the plan note records a foreign one.
        let other_envelope = signed_envelope_with_output(
            &signing_key,
            OutputEnvelope {
                stdout: b"different body".to_vec(),
                stderr: Vec::new(),
                stdout_truncated_at: None,
                stderr_truncated_at: None,
            },
        );
        plan_note.signature = other_envelope.signature;
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let err = read_plan_body_bytes(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            &plan_note,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, ReadPlanBodyError::EnvelopeSignatureMismatch),
            "expected EnvelopeSignatureMismatch, got: {err:?}",
        );
    }

    /// `Verify` failure when the signing key isn't in the allowed
    /// signers set. Verifies the helper's defence-in-depth re-check
    /// catches an envelope whose signing key is no longer trusted —
    /// even though the plan note's recorded metadata and signature
    /// match the on-disk envelope.
    #[test]
    fn verify_failure_under_untrusted_signer() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let output = OutputEnvelope {
            stdout: b"body".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let envelope = signed_envelope_with_output(&signing_key, output);
        let (writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
        let bailiff = bailiff_repo(&tmp);
        // Allowed-signers set contains the *other* key, not writ's.
        let allowed = AllowedSigners::from_openssh_lines(OTHER_PUB).unwrap();

        let err = read_plan_body_bytes(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            &plan_note,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, ReadPlanBodyError::Verify(_)),
            "expected Verify, got: {err:?}",
        );
    }

    /// `DecodeOutput` failure when the `output` field decodes as
    /// envelope JSON but not as an `OutputEnvelope`. Built by
    /// signing a non-OutputEnvelope payload as the `output` bytes —
    /// the signature covers the digest of these bytes so the verify
    /// step passes, but the post-verify decode fails.
    #[test]
    fn decode_output_failure_when_output_is_not_output_envelope_json() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let output_bytes = b"not an output envelope".to_vec();
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
        let envelope = SignedRunEnvelope {
            metadata,
            signature,
            output: output_bytes,
        };
        let (writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let err = read_plan_body_bytes(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            &plan_note,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, ReadPlanBodyError::DecodeOutput(_)),
            "expected DecodeOutput, got: {err:?}",
        );
    }

    /// `OutputTruncated` when the planner's stdout was truncated by
    /// writ. The signature covers the truncation marker, so the
    /// envelope verifies — but using only a prefix as the plan body
    /// could mislead the reviewer, so the helper refuses.
    #[test]
    fn output_truncated_when_stdout_was_capped_by_writ() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let output = OutputEnvelope {
            stdout: b"prefix only".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: Some(11),
            stderr_truncated_at: None,
        };
        let envelope = signed_envelope_with_output(&signing_key, output);
        let (writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let err = read_plan_body_bytes(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            &plan_note,
            &allowed,
        )
        .unwrap_err();
        match err {
            ReadPlanBodyError::OutputTruncated {
                stdout_truncated_at,
            } => assert_eq!(stdout_truncated_at, 11),
            other => panic!("expected OutputTruncated, got: {other:?}"),
        }
    }

    /// `OutputEmpty` when the planner's stdout is zero bytes. The
    /// design contract treats planner stdout as the plan body, so
    /// an empty plan body is a protocol violation that must bail
    /// before any reviewer session opens.
    #[test]
    fn output_empty_when_stdout_is_zero_bytes() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let output = OutputEnvelope {
            stdout: Vec::new(),
            stderr: b"informational".to_vec(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let envelope = signed_envelope_with_output(&signing_key, output);
        let (writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let err = read_plan_body_bytes(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            &plan_note,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, ReadPlanBodyError::OutputEmpty),
            "expected OutputEmpty, got: {err:?}",
        );
    }

    /// `OutputNotUtf8` when the planner's stdout bytes aren't valid
    /// UTF-8. Plant a known-invalid sequence (lone 0xFF) and verify
    /// the helper rejects rather than lossily decoding.
    #[test]
    fn output_not_utf8_when_stdout_contains_invalid_bytes() {
        let tmp = TempDir::new().unwrap();
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let output = OutputEnvelope {
            stdout: vec![0xFF, 0xFE, 0xFD],
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let envelope = signed_envelope_with_output(&signing_key, output);
        let (writ_repo, plan_note) = writ_repo_and_plan_note(&tmp, &envelope);
        let bailiff = bailiff_repo(&tmp);
        let allowed = AllowedSigners::from_openssh_lines(SIGNING_PUB).unwrap();

        let err = read_plan_body_bytes(
            &bailiff,
            writ_repo.path(),
            &writ_notes_ref(),
            &plan_note,
            &allowed,
        )
        .unwrap_err();
        assert!(
            matches!(err, ReadPlanBodyError::OutputNotUtf8(_)),
            "expected OutputNotUtf8, got: {err:?}",
        );
    }
}

#[cfg(test)]
mod list_tests {
    //! Tests for [`list_plan_ids`] and [`summarize_plan`] — slice F2's
    //! aggregate read primitives. The helpers compose over the existing
    //! `read_*_note` siblings (already covered by their own modules) so
    //! these tests focus on:
    //!
    //! - ref enumeration: empty repo, multiple plans, lexicographic
    //!   ordering, parse failure on a non-UUID tail.
    //! - summary aggregation: each subset of the four notes maps to
    //!   the expected `BailiffPlanSummary` field set.
    //! - workflow-state derivation: every variant of [`WorkflowState`]
    //!   is reachable from a corresponding fixture.
    //!
    //! Notes are planted directly via [`NotesRepo::write_note`] rather
    //! than through the real write workflow because the summary helper
    //! is a pure read-side composition; exercising the write workflow
    //! end-to-end would require a writ broker per test, which is the
    //! existing round-trip tests' concern in the sibling modules.
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_decision::{Decider, Decision};
    use crate::bailiff_plan_note::{
        DecisionNote, ImplementNote, PlanId, PlanNote, ReviewNote, plan_decision_seed_blob_bytes,
        plan_implement_seed_blob_bytes, plan_notes_ref, plan_review_seed_blob_bytes,
        plan_submission_seed_blob_bytes,
    };
    use crate::core::{
        CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, SshSignature, UnixMillis,
    };
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::OutputEnvelope;
    use crate::signing::WritSigningKey;
    use crate::vm_git::GitObjectId;
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    /// Build a `SignedRunMetadata` + matching signature with a given
    /// `completed_at`. Reused across the three signed note types
    /// (`PlanNote`, `ReviewNote`, `ImplementNote`) because the read
    /// helpers only consult `completed_at` and the typed signature
    /// must round-trip through `from_canonical_bytes`. The signature
    /// is computed under the test signing key so the bytes are
    /// structurally valid even though no verifier runs in this test
    /// module.
    fn sample_metadata_and_signature(
        completed_at_millis: i64,
    ) -> (SignedRunMetadata, SshSignature) {
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let output = OutputEnvelope {
            stdout: b"agent stdout".to_vec(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let output_sha = Sha256Hex::try_new(sha256_hex(&output.to_bytes())).unwrap();
        let prompt_sha = Sha256Hex::try_new(sha256_hex(b"agent-prompt")).unwrap();
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
            completed_at: UnixMillis::from_millis(completed_at_millis),
            signing_key_fingerprint: signing_key.fingerprint(),
        };
        let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
        (metadata, signature)
    }

    fn plant_plan_note(
        bailiff: &NotesRepo,
        plan_id: PlanId,
        purpose: &str,
        submitted_at_millis: i64,
    ) {
        let (metadata, signature) = sample_metadata_and_signature(submitted_at_millis);
        let note = PlanNote {
            plan_id,
            purpose: purpose.to_string(),
            writ_output_oid: GitObjectId::new("a".repeat(40)).unwrap(),
            signed_metadata: metadata,
            signature,
        };
        bailiff
            .write_note(
                &plan_notes_ref(plan_id),
                &plan_submission_seed_blob_bytes(plan_id),
                &note.canonical_bytes(),
            )
            .unwrap();
    }

    fn plant_decision_note(
        bailiff: &NotesRepo,
        plan_id: PlanId,
        outcome: Decision,
        decider: &str,
        decided_at_millis: i64,
    ) {
        let note = DecisionNote {
            plan_id,
            outcome,
            decider: Decider::try_new(decider).unwrap(),
            decided_at: UnixMillis::from_millis(decided_at_millis),
        };
        bailiff
            .write_note(
                &plan_notes_ref(plan_id),
                &plan_decision_seed_blob_bytes(plan_id),
                &note.canonical_bytes(),
            )
            .unwrap();
    }

    fn plant_review_note(bailiff: &NotesRepo, plan_id: PlanId, reviewed_at_millis: i64) {
        let (metadata, signature) = sample_metadata_and_signature(reviewed_at_millis);
        let note = ReviewNote {
            plan_id,
            purpose: "plan-review".into(),
            writ_output_oid: GitObjectId::new("b".repeat(40)).unwrap(),
            signed_metadata: metadata,
            signature,
        };
        bailiff
            .write_note(
                &plan_notes_ref(plan_id),
                &plan_review_seed_blob_bytes(plan_id),
                &note.canonical_bytes(),
            )
            .unwrap();
    }

    fn plant_implement_note(bailiff: &NotesRepo, plan_id: PlanId, implemented_at_millis: i64) {
        let (metadata, signature) = sample_metadata_and_signature(implemented_at_millis);
        let note = ImplementNote {
            plan_id,
            purpose: "plan-implement".into(),
            writ_output_oid: GitObjectId::new("c".repeat(40)).unwrap(),
            signed_metadata: metadata,
            signature,
        };
        bailiff
            .write_note(
                &plan_notes_ref(plan_id),
                &plan_implement_seed_blob_bytes(plan_id),
                &note.canonical_bytes(),
            )
            .unwrap();
    }

    /// Empty repo has no plan refs → empty vec, exit success. Common
    /// state on a fresh bailiff install.
    #[test]
    fn list_plan_ids_returns_empty_vec_on_empty_repo() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        assert_eq!(list_plan_ids(&bailiff).unwrap(), Vec::<PlanId>::new());
    }

    /// Three plans with attached submission notes — listing returns
    /// the three ids in `for-each-ref` (lexicographic-by-ref-name)
    /// order. Pins the contract operators rely on when piping list
    /// output through `head -n` or similar.
    #[test]
    fn list_plan_ids_returns_plans_in_lexicographic_order() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let id_a = PlanId::from_uuid("0a000000-0000-4000-8000-000000000001".parse().unwrap());
        let id_b = PlanId::from_uuid("0b000000-0000-4000-8000-000000000002".parse().unwrap());
        let id_c = PlanId::from_uuid("0c000000-0000-4000-8000-000000000003".parse().unwrap());
        // Plant out of order to confirm the helper does not preserve
        // insertion order — only the ref-name lex order matters.
        plant_plan_note(&bailiff, id_c, "third", 3);
        plant_plan_note(&bailiff, id_a, "first", 1);
        plant_plan_note(&bailiff, id_b, "second", 2);
        let ids = list_plan_ids(&bailiff).unwrap();
        assert_eq!(ids, vec![id_a, id_b, id_c]);
    }

    /// A ref under the plan prefix whose tail is not a parseable UUID
    /// surfaces as `ListPlanIdsError::ParseRef` with the offending tail
    /// in the error payload. Constructed by planting a note under a
    /// manually-constructed ref name that bypasses
    /// `plan_notes_ref(plan_id)`. This is the corruption-detection
    /// signal: bailiff is the sole writer to the plan namespace, so
    /// the only way to reach this state is manual `git update-ref` or
    /// an external writer.
    #[test]
    fn list_plan_ids_returns_parse_error_on_non_uuid_tail() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        // The bad ref name still has to satisfy `NotesRef::try_new`'s
        // validators (no whitespace, no `..`, etc.) — using `garbage`
        // as the tail keeps the ref well-formed while the tail fails
        // UUID parsing.
        let bad_ref = NotesRef::try_new("refs/notes/bailiff/v1/plans/not-a-uuid").unwrap();
        bailiff
            .write_note(&bad_ref, b"seed-bytes", b"body")
            .unwrap();
        let err = list_plan_ids(&bailiff).unwrap_err();
        match err {
            ListPlanIdsError::ParseRef {
                raw_ref,
                tail,
                source: _,
            } => {
                assert_eq!(raw_ref, "refs/notes/bailiff/v1/plans/not-a-uuid");
                assert_eq!(tail, "not-a-uuid");
            }
            other => panic!("expected ParseRef, got: {other:?}"),
        }
    }

    /// `Uuid::parse_str` accepts non-canonical spellings (uppercase
    /// hex, 32 unhyphenated hex characters) that `plan_notes_ref`
    /// never emits. If `list_plan_ids` let those through, the
    /// downstream `summarize_plan` would re-derive the ref name in
    /// canonical lowercase-hyphenated form and look there — finding
    /// nothing and silently hiding the corrupted ref that actually
    /// carries the notes. Surface them as `NonCanonicalRef` so the
    /// operator sees which on-disk ref is the offender.
    #[test]
    fn list_plan_ids_rejects_uppercase_hex_uuid_tail() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let bad_ref =
            NotesRef::try_new("refs/notes/bailiff/v1/plans/AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")
                .unwrap();
        bailiff
            .write_note(&bad_ref, b"seed-bytes", b"body")
            .unwrap();
        let err = list_plan_ids(&bailiff).unwrap_err();
        match err {
            ListPlanIdsError::NonCanonicalRef {
                raw_ref,
                tail,
                canonical,
            } => {
                assert_eq!(
                    raw_ref,
                    "refs/notes/bailiff/v1/plans/AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"
                );
                assert_eq!(tail, "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE");
                assert_eq!(canonical, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
            }
            other => panic!("expected NonCanonicalRef, got: {other:?}"),
        }
    }

    /// The other non-canonical spelling `uuid` accepts: 32 hex
    /// characters without hyphens. Same risk and same fix as the
    /// uppercase case, separately pinned because the two code paths
    /// inside `Uuid::parse_str` are independent.
    #[test]
    fn list_plan_ids_rejects_unhyphenated_uuid_tail() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let bad_ref =
            NotesRef::try_new("refs/notes/bailiff/v1/plans/aaaaaaaabbbb4ccc8dddeeeeeeeeeeee")
                .unwrap();
        bailiff
            .write_note(&bad_ref, b"seed-bytes", b"body")
            .unwrap();
        let err = list_plan_ids(&bailiff).unwrap_err();
        match err {
            ListPlanIdsError::NonCanonicalRef {
                tail, canonical, ..
            } => {
                assert_eq!(tail, "aaaaaaaabbbb4ccc8dddeeeeeeeeeeee");
                assert_eq!(canonical, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
            }
            other => panic!("expected NonCanonicalRef, got: {other:?}"),
        }
    }

    /// A plan-id whose ref exists but carries no submission note
    /// (decision attached first, manual repo state) folds into
    /// `submission: None` rather than an error. Pin the surface so
    /// `bailiff plan list` keeps rendering the row instead of failing
    /// the whole command — the [`WorkflowState::Corrupt`] derivation
    /// is how the operator sees the anomaly.
    #[test]
    fn summarize_plan_returns_corrupt_state_when_only_decision_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        plant_decision_note(&bailiff, plan_id, Decision::Accepted, "cli:tester", 100);
        let summary = summarize_plan(&bailiff, plan_id).unwrap();
        assert_eq!(summary.plan_id, plan_id);
        assert!(summary.submission.is_none());
        assert!(summary.decision.is_some());
        assert!(summary.reviewed_at.is_none());
        assert!(summary.implemented_at.is_none());
        assert_eq!(summary.state(), WorkflowState::Corrupt);
    }

    /// Submission only: the four optionals are submission=Some,
    /// decision=None, reviewed_at=None, implemented_at=None.
    /// `purpose` and `submitted_at` come from the plan note's body and
    /// metadata; pin both.
    #[test]
    fn summarize_plan_returns_submission_only_when_just_submitted() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        plant_plan_note(&bailiff, plan_id, "fix-oauth-drift", 1_700_000_000_000);
        let summary = summarize_plan(&bailiff, plan_id).unwrap();
        let submission = summary
            .submission
            .as_ref()
            .expect("submission must be Some");
        assert_eq!(submission.purpose, "fix-oauth-drift");
        assert_eq!(submission.submitted_at.as_millis(), 1_700_000_000_000);
        assert!(summary.decision.is_none());
        assert!(summary.reviewed_at.is_none());
        assert!(summary.implemented_at.is_none());
        assert_eq!(summary.state(), WorkflowState::Submitted);
    }

    /// Submission + accept decision → state=accepted, decision fields
    /// projected from the note. A regression that swapped accept and
    /// reject would be catastrophically wrong but invisible to the
    /// `submitted` test above.
    #[test]
    fn summarize_plan_projects_accepted_decision() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        plant_plan_note(&bailiff, plan_id, "p", 1);
        plant_decision_note(&bailiff, plan_id, Decision::Accepted, "cli:alice", 2);
        let summary = summarize_plan(&bailiff, plan_id).unwrap();
        let decision = summary.decision.as_ref().expect("decision must be Some");
        assert_eq!(decision.outcome, Decision::Accepted);
        assert_eq!(decision.decider.as_str(), "cli:alice");
        assert_eq!(decision.decided_at.as_millis(), 2);
        assert_eq!(summary.state(), WorkflowState::Accepted);
    }

    /// Submission + reject decision → state=rejected.
    #[test]
    fn summarize_plan_projects_rejected_decision() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        plant_plan_note(&bailiff, plan_id, "p", 1);
        plant_decision_note(&bailiff, plan_id, Decision::Rejected, "cli:bob", 2);
        let summary = summarize_plan(&bailiff, plan_id).unwrap();
        assert_eq!(
            summary.decision.as_ref().map(|d| d.outcome),
            Some(Decision::Rejected),
        );
        assert_eq!(summary.state(), WorkflowState::Rejected);
    }

    /// Submission + accept + review → state=reviewed; `reviewed_at`
    /// lifted from the review note's signed metadata.
    #[test]
    fn summarize_plan_projects_reviewed_at_when_reviewed() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        plant_plan_note(&bailiff, plan_id, "p", 1);
        plant_decision_note(&bailiff, plan_id, Decision::Accepted, "cli:alice", 2);
        plant_review_note(&bailiff, plan_id, 1_700_000_001_000);
        let summary = summarize_plan(&bailiff, plan_id).unwrap();
        assert_eq!(
            summary.reviewed_at.map(|t| t.as_millis()),
            Some(1_700_000_001_000),
        );
        assert!(summary.implemented_at.is_none());
        assert_eq!(summary.state(), WorkflowState::Reviewed);
    }

    /// All four notes present → state=implemented; every projection
    /// populated. The "highest stage" rule means `Implemented` wins
    /// over `Reviewed` even though both notes are attached.
    #[test]
    fn summarize_plan_projects_implemented_at_when_implemented() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let plan_id = PlanId::new();
        plant_plan_note(&bailiff, plan_id, "p", 1);
        plant_decision_note(&bailiff, plan_id, Decision::Accepted, "cli:alice", 2);
        plant_review_note(&bailiff, plan_id, 3);
        plant_implement_note(&bailiff, plan_id, 1_700_000_002_000);
        let summary = summarize_plan(&bailiff, plan_id).unwrap();
        assert_eq!(
            summary.implemented_at.map(|t| t.as_millis()),
            Some(1_700_000_002_000),
        );
        assert_eq!(
            summary.reviewed_at.map(|t| t.as_millis()),
            Some(3),
            "reviewed_at must still surface even though state overrides to implemented",
        );
        assert_eq!(summary.state(), WorkflowState::Implemented);
    }

    /// `WorkflowState::as_str` pins the lowercase string the formatter
    /// writes; a rename would surface here rather than as a test-snapshot
    /// drift somewhere far from the source.
    #[test]
    fn workflow_state_as_str_is_stable_lowercase() {
        assert_eq!(WorkflowState::Corrupt.as_str(), "corrupt");
        assert_eq!(WorkflowState::Submitted.as_str(), "submitted");
        assert_eq!(WorkflowState::Accepted.as_str(), "accepted");
        assert_eq!(WorkflowState::Rejected.as_str(), "rejected");
        assert_eq!(WorkflowState::Reviewed.as_str(), "reviewed");
        assert_eq!(WorkflowState::Implemented.as_str(), "implemented");
        // Display must agree with as_str.
        assert_eq!(WorkflowState::Submitted.to_string(), "submitted");
    }
}

#[cfg(test)]
mod full_plan_tests {
    //! Tests for [`read_writ_envelope_at_oid`] and [`read_full_plan`] —
    //! slice F3's read-and-verify composition.
    //!
    //! Fixtures plant coherent writ runs (envelope + paired bailiff
    //! signed note pointing at the envelope's target OID) directly
    //! through [`NotesRepo::write_note`]. This bypasses the writ broker
    //! and the writ→bailiff fetch hop on purpose — those are the
    //! concern of the end-to-end round-trip in
    //! `run_verify::tests::round_trip_writ_writes_bailiff_fetches_and_verifies`.
    //! Here we exercise the pure read-side composition under the same
    //! crypto primitives.
    //!
    //! The four [`VerifiedSection`] variants are each driven by a
    //! distinct fault injection: missing envelope (no writ note at the
    //! OID), malformed envelope (non-JSON bytes), output tamper
    //! (envelope output bytes don't hash to the metadata's digest), and
    //! metadata tamper (canonical bytes diverge from what was signed,
    //! plus the signer-not-in-allowed-signers variant).
    use super::*;
    use crate::agent_run::{AgentRunId, sha256_hex};
    use crate::bailiff_decision::{Decider, Decision};
    use crate::bailiff_plan_note::{
        DecisionNote, ImplementNote, PlanId, PlanNote, ReviewNote, plan_decision_seed_blob_bytes,
        plan_implement_seed_blob_bytes, plan_notes_ref, plan_review_seed_blob_bytes,
        plan_submission_seed_blob_bytes,
    };
    use crate::core::{
        CapabilitySet, NotesRef, RepoRef, SessionId, Sha256Hex, SshSignature, UnixMillis,
    };
    use crate::protocol::SignedRunMetadata;
    use crate::run_envelope::{OutputEnvelope, SignedRunEnvelope};
    use crate::run_verify::VerifyError;
    use crate::signing::WritSigningKey;
    use crate::vm_git::GitObjectId;
    use tempfile::TempDir;

    const SIGNING_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing.key");
    const OTHER_PEM: &str = include_str!("../tests/fixtures/ed25519_test_signing_other.key");

    fn bailiff_repo(tmp: &TempDir) -> NotesRepo {
        NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap()
    }

    fn writ_notes_ref() -> NotesRef {
        NotesRef::try_new(WRIT_AGENT_OUTPUTS_REF).unwrap()
    }

    /// Build a `SignedRunMetadata` whose `output_envelope_sha256` binds
    /// to the canonical bytes of an empty [`OutputEnvelope`]. Used by
    /// every helper here so a paired envelope plants without any
    /// additional bookkeeping; the `seed_str` differentiates prompt
    /// digests across plants so the metadatas don't compare equal.
    fn build_metadata(
        signing_key: &WritSigningKey,
        completed_at_millis: i64,
        seed_str: &str,
    ) -> (SignedRunMetadata, Vec<u8>) {
        let output = OutputEnvelope {
            stdout: format!("{seed_str}-stdout").into_bytes(),
            stderr: Vec::new(),
            stdout_truncated_at: None,
            stderr_truncated_at: None,
        };
        let output_bytes = output.to_bytes();
        let output_sha = Sha256Hex::try_new(sha256_hex(&output_bytes)).unwrap();
        let prompt_sha = Sha256Hex::try_new(sha256_hex(seed_str.as_bytes())).unwrap();
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
            completed_at: UnixMillis::from_millis(completed_at_millis),
            signing_key_fingerprint: signing_key.fingerprint(),
        };
        (metadata, output_bytes)
    }

    /// Bundle of (writ envelope target OID, signed metadata, signature)
    /// returned by [`plant_run`]: enough for a paired bailiff signed
    /// note to reference and re-sign over the same metadata. Each
    /// `plant_run` call seeds a fresh [`AgentRunId`] so multiple runs
    /// in one test plant at distinct target OIDs.
    struct PlantedRun {
        writ_output_oid: GitObjectId,
        metadata: SignedRunMetadata,
        signature: SshSignature,
    }

    /// Build a fresh writ envelope under `signing_key`, plant it on
    /// bailiff's writ notes ref keyed by the run id, and return the
    /// projection a paired bailiff note will reuse. The envelope's
    /// output bytes are seeded by `seed_str` so the planted body is
    /// distinct across calls within one test.
    fn plant_run(
        bailiff: &NotesRepo,
        signing_key: &WritSigningKey,
        completed_at_millis: i64,
        seed_str: &str,
    ) -> PlantedRun {
        let (metadata, output_bytes) = build_metadata(signing_key, completed_at_millis, seed_str);
        let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
        let envelope = SignedRunEnvelope {
            metadata: metadata.clone(),
            signature: signature.clone(),
            output: output_bytes,
        };
        let writ_output_oid = bailiff
            .write_note(
                &writ_notes_ref(),
                metadata.run_id.to_string().as_bytes(),
                &envelope.to_bytes(),
            )
            .unwrap();
        PlantedRun {
            writ_output_oid,
            metadata,
            signature,
        }
    }

    fn plant_plan_note_for(bailiff: &NotesRepo, plan_id: PlanId, run: &PlantedRun) {
        let note = PlanNote {
            plan_id,
            purpose: "plan-submission".into(),
            writ_output_oid: run.writ_output_oid.clone(),
            signed_metadata: run.metadata.clone(),
            signature: run.signature.clone(),
        };
        bailiff
            .write_note(
                &plan_notes_ref(plan_id),
                &plan_submission_seed_blob_bytes(plan_id),
                &note.canonical_bytes(),
            )
            .unwrap();
    }

    fn plant_review_note_for(bailiff: &NotesRepo, plan_id: PlanId, run: &PlantedRun) {
        let note = ReviewNote {
            plan_id,
            purpose: "plan-review".into(),
            writ_output_oid: run.writ_output_oid.clone(),
            signed_metadata: run.metadata.clone(),
            signature: run.signature.clone(),
        };
        bailiff
            .write_note(
                &plan_notes_ref(plan_id),
                &plan_review_seed_blob_bytes(plan_id),
                &note.canonical_bytes(),
            )
            .unwrap();
    }

    fn plant_implement_note_for(bailiff: &NotesRepo, plan_id: PlanId, run: &PlantedRun) {
        let note = ImplementNote {
            plan_id,
            purpose: "plan-implement".into(),
            writ_output_oid: run.writ_output_oid.clone(),
            signed_metadata: run.metadata.clone(),
            signature: run.signature.clone(),
        };
        bailiff
            .write_note(
                &plan_notes_ref(plan_id),
                &plan_implement_seed_blob_bytes(plan_id),
                &note.canonical_bytes(),
            )
            .unwrap();
    }

    fn plant_decision_note_for(bailiff: &NotesRepo, plan_id: PlanId, outcome: Decision) {
        let note = DecisionNote {
            plan_id,
            outcome,
            decider: Decider::try_new("cli:alice").unwrap(),
            decided_at: UnixMillis::from_millis(1_700_000_500_000),
        };
        bailiff
            .write_note(
                &plan_notes_ref(plan_id),
                &plan_decision_seed_blob_bytes(plan_id),
                &note.canonical_bytes(),
            )
            .unwrap();
    }

    fn allowed_signers_for(signing_key: &WritSigningKey) -> AllowedSigners {
        AllowedSigners::from_keys([signing_key.verifying_key()])
    }

    /// Absent: bailiff has not fetched a writ envelope at this OID, so
    /// the read returns `Ok(None)`. Pins the "not fetched yet" case the
    /// `WritEnvelopeMissing` variant rests on.
    #[test]
    fn read_writ_envelope_at_oid_returns_none_when_absent() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let oid = GitObjectId::new("a".repeat(40)).unwrap();
        let result = read_writ_envelope_at_oid(&bailiff, &oid).unwrap();
        assert!(result.is_none());
    }

    /// Present: plant a real envelope, read by the returned OID, and
    /// the decoded envelope round-trips byte-equal in metadata and
    /// signature.
    #[test]
    fn read_writ_envelope_at_oid_round_trips_planted_envelope() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let run = plant_run(&bailiff, &signing_key, 1, "roundtrip");
        let envelope = read_writ_envelope_at_oid(&bailiff, &run.writ_output_oid)
            .unwrap()
            .expect("envelope was just planted");
        assert_eq!(envelope.metadata, run.metadata);
        assert_eq!(envelope.signature, run.signature);
    }

    /// Garbage body at a real OID: the read returns `Decode`, not
    /// `Ok(None)` and not `Read`. Pins the "envelope present but
    /// corrupted on disk" diagnostic.
    #[test]
    fn read_writ_envelope_at_oid_surfaces_decode_failure_on_garbage_body() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let oid = bailiff
            .write_note(&writ_notes_ref(), b"garbage-seed", b"not-json-at-all")
            .unwrap();
        match read_writ_envelope_at_oid(&bailiff, &oid) {
            Err(ReadWritEnvelopeError::Decode(_)) => {}
            other => panic!("expected Decode error, got {other:?}"),
        }
    }

    /// Happy path: plant + decision + review + implement, all signed
    /// by the same writ key listed in allowed-signers. Every section
    /// surfaces as [`VerifiedSection::Verified`] and the decision
    /// projects through unchanged.
    #[test]
    fn read_full_plan_returns_verified_view_when_all_four_sections_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let plan_id = PlanId::new();

        let plan_run = plant_run(&bailiff, &signing_key, 1, "plan");
        let review_run = plant_run(&bailiff, &signing_key, 2, "review");
        let implement_run = plant_run(&bailiff, &signing_key, 3, "implement");

        plant_plan_note_for(&bailiff, plan_id, &plan_run);
        plant_decision_note_for(&bailiff, plan_id, Decision::Accepted);
        plant_review_note_for(&bailiff, plan_id, &review_run);
        plant_implement_note_for(&bailiff, plan_id, &implement_run);

        let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
        assert_eq!(view.plan_id, plan_id);
        match view.plan.as_ref().expect("plan section must be present") {
            VerifiedSection::Verified { note, envelope } => {
                assert_eq!(note.plan_id, plan_id);
                assert_eq!(envelope.metadata, plan_run.metadata);
            }
            other => panic!("expected Verified plan section, got {other:?}"),
        }
        assert!(view.decision.is_some(), "decision must be present");
        match view
            .review
            .as_ref()
            .expect("review section must be present")
        {
            VerifiedSection::Verified { note, envelope } => {
                assert_eq!(note.plan_id, plan_id);
                assert_eq!(envelope.metadata, review_run.metadata);
            }
            other => panic!("expected Verified review section, got {other:?}"),
        }
        match view
            .implement
            .as_ref()
            .expect("implement section must be present")
        {
            VerifiedSection::Verified { note, envelope } => {
                assert_eq!(note.plan_id, plan_id);
                assert_eq!(envelope.metadata, implement_run.metadata);
            }
            other => panic!("expected Verified implement section, got {other:?}"),
        }
    }

    /// Plan-only: just the plan submission is planted. The other three
    /// fields surface as `None` (structural absence), not as failure
    /// variants — `None` and "failure to verify" are different
    /// states.
    #[test]
    fn read_full_plan_returns_only_plan_section_when_other_notes_missing() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let plan_id = PlanId::new();
        let plan_run = plant_run(&bailiff, &signing_key, 1, "plan-only");
        plant_plan_note_for(&bailiff, plan_id, &plan_run);
        let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
        assert!(matches!(view.plan, Some(VerifiedSection::Verified { .. })));
        assert!(view.decision.is_none());
        assert!(view.review.is_none());
        assert!(view.implement.is_none());
    }

    /// Corrupt anomaly: downstream notes (decision + review) present
    /// but plan submission absent. `view.plan = None` is representable
    /// because `plan` is `Option<VerifiedSection<_>>`, and the other
    /// available sections still render — exactly the property
    /// [`PlanFullView`]'s doc string promises.
    #[test]
    fn read_full_plan_returns_none_plan_when_only_downstream_notes_present() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let plan_id = PlanId::new();
        plant_decision_note_for(&bailiff, plan_id, Decision::Accepted);
        let review_run = plant_run(&bailiff, &signing_key, 2, "orphan-review");
        plant_review_note_for(&bailiff, plan_id, &review_run);
        let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
        assert!(view.plan.is_none(), "plan missing in corrupt state");
        assert!(view.decision.is_some());
        assert!(matches!(
            view.review,
            Some(VerifiedSection::Verified { .. })
        ));
        assert!(view.implement.is_none());
    }

    /// Writ envelope missing: a plan note references a synthetic OID
    /// where bailiff has no writ note. The section surfaces as
    /// [`VerifiedSection::WritEnvelopeMissing`] — the
    /// "operator forgot to fetch" recoverable state.
    #[test]
    fn read_full_plan_marks_section_when_writ_envelope_missing() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let plan_id = PlanId::new();

        let synthetic_oid = GitObjectId::new("d".repeat(40)).unwrap();
        let (metadata, _output_bytes) = build_metadata(&signing_key, 1, "no-envelope");
        let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
        let note = PlanNote {
            plan_id,
            purpose: "plan".into(),
            writ_output_oid: synthetic_oid.clone(),
            signed_metadata: metadata,
            signature,
        };
        bailiff
            .write_note(
                &plan_notes_ref(plan_id),
                &plan_submission_seed_blob_bytes(plan_id),
                &note.canonical_bytes(),
            )
            .unwrap();

        let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
        match view.plan.as_ref().unwrap() {
            VerifiedSection::WritEnvelopeMissing { note } => {
                assert_eq!(note.writ_output_oid, synthetic_oid);
            }
            other => panic!("expected WritEnvelopeMissing, got {other:?}"),
        }
    }

    /// Envelope body malformed: plant non-JSON bytes on the writ ref,
    /// capture the resulting OID, and point a plan note at it. The
    /// section surfaces as [`VerifiedSection::EnvelopeMalformed`] —
    /// distinct from missing (so an operator can tell "not fetched"
    /// from "fetched but corrupt").
    #[test]
    fn read_full_plan_marks_section_when_envelope_body_malformed() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let plan_id = PlanId::new();

        let malformed_oid = bailiff
            .write_note(&writ_notes_ref(), b"malformed-seed", b"<<not json>>")
            .unwrap();
        let (metadata, _output_bytes) = build_metadata(&signing_key, 1, "malformed-envelope");
        let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
        let note = PlanNote {
            plan_id,
            purpose: "plan".into(),
            writ_output_oid: malformed_oid.clone(),
            signed_metadata: metadata,
            signature,
        };
        bailiff
            .write_note(
                &plan_notes_ref(plan_id),
                &plan_submission_seed_blob_bytes(plan_id),
                &note.canonical_bytes(),
            )
            .unwrap();

        let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
        match view.plan.as_ref().unwrap() {
            VerifiedSection::EnvelopeMalformed { note, .. } => {
                assert_eq!(note.writ_output_oid, malformed_oid);
            }
            other => panic!("expected EnvelopeMalformed, got {other:?}"),
        }
    }

    /// Output digest mismatch: plant an envelope whose `output` bytes
    /// don't hash to the metadata's `output_envelope_sha256` claim,
    /// then verify under the legitimate signer. The verifier rejects
    /// at the digest step before consulting the signature.
    #[test]
    fn read_full_plan_marks_section_when_output_digest_mismatches() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let plan_id = PlanId::new();

        let (metadata, output_bytes) = build_metadata(&signing_key, 1, "digest-mismatch");
        let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
        // Swap the bound output bytes for an unrelated payload after
        // the metadata digest is fixed — re-hashing on the verifier
        // side will surface the divergence.
        let mut tampered_output = output_bytes.clone();
        tampered_output.push(0xFF);
        let envelope = SignedRunEnvelope {
            metadata: metadata.clone(),
            signature: signature.clone(),
            output: tampered_output,
        };
        let oid = bailiff
            .write_note(
                &writ_notes_ref(),
                metadata.run_id.to_string().as_bytes(),
                &envelope.to_bytes(),
            )
            .unwrap();
        let note = PlanNote {
            plan_id,
            purpose: "plan".into(),
            writ_output_oid: oid,
            signed_metadata: metadata,
            signature,
        };
        bailiff
            .write_note(
                &plan_notes_ref(plan_id),
                &plan_submission_seed_blob_bytes(plan_id),
                &note.canonical_bytes(),
            )
            .unwrap();

        let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
        match view.plan.as_ref().unwrap() {
            VerifiedSection::SignatureFailure {
                error: VerifyError::OutputDigestMismatch { .. },
                ..
            } => {}
            other => panic!("expected SignatureFailure(OutputDigestMismatch), got {other:?}"),
        }
    }

    /// Unknown signer: envelope is built and signed by writ key A, but
    /// allowed-signers contains only key B. The verifier rejects at
    /// the fingerprint-lookup step (before consulting the signature),
    /// surfacing as `SignatureFailure(UnknownSigner)`.
    #[test]
    fn read_full_plan_marks_section_when_signer_not_in_allowed_signers() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let other_key = WritSigningKey::from_openssh_pem(OTHER_PEM).unwrap();
        let primary_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let plan_id = PlanId::new();

        // Envelope and bailiff plan note are both signed by the
        // *other* key; the AllowedSigners passed to read_full_plan
        // contains only the *primary* key.
        let plan_run = plant_run(&bailiff, &other_key, 1, "signed-by-other");
        plant_plan_note_for(&bailiff, plan_id, &plan_run);

        let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&primary_key)).unwrap();
        match view.plan.as_ref().unwrap() {
            VerifiedSection::SignatureFailure {
                error: VerifyError::UnknownSigner { fingerprint },
                ..
            } => {
                assert_eq!(fingerprint, &other_key.fingerprint());
            }
            other => panic!("expected SignatureFailure(UnknownSigner), got {other:?}"),
        }
    }

    /// Metadata tamper: build and sign an envelope, then mutate one
    /// non-digest metadata field (`exit_code`) before encoding. The
    /// output digest still binds (we didn't touch the output bytes or
    /// `output_envelope_sha256`), the signer is known, but the
    /// signature no longer matches `canonical_bytes` — surfaces as
    /// `SignatureFailure(SignatureInvalid)`.
    #[test]
    fn read_full_plan_marks_section_when_metadata_tampered_post_sign() {
        let tmp = TempDir::new().unwrap();
        let bailiff = bailiff_repo(&tmp);
        let signing_key = WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap();
        let plan_id = PlanId::new();

        let (mut metadata, output_bytes) = build_metadata(&signing_key, 1, "metadata-tamper");
        let signature = signing_key.sign(&metadata.canonical_bytes()).unwrap();
        // Mutate after signing. The output digest still binds because
        // `output_envelope_sha256` is unchanged; only the exit code
        // diverges from what the signature covered.
        metadata.exit_code = metadata.exit_code.wrapping_add(1);
        let envelope = SignedRunEnvelope {
            metadata: metadata.clone(),
            signature: signature.clone(),
            output: output_bytes,
        };
        let oid = bailiff
            .write_note(
                &writ_notes_ref(),
                metadata.run_id.to_string().as_bytes(),
                &envelope.to_bytes(),
            )
            .unwrap();
        let note = PlanNote {
            plan_id,
            purpose: "plan".into(),
            writ_output_oid: oid,
            signed_metadata: metadata,
            signature,
        };
        bailiff
            .write_note(
                &plan_notes_ref(plan_id),
                &plan_submission_seed_blob_bytes(plan_id),
                &note.canonical_bytes(),
            )
            .unwrap();

        let view = read_full_plan(&bailiff, plan_id, &allowed_signers_for(&signing_key)).unwrap();
        match view.plan.as_ref().unwrap() {
            VerifiedSection::SignatureFailure {
                error: VerifyError::SignatureInvalid(_),
                ..
            } => {}
            other => panic!("expected SignatureFailure(SignatureInvalid), got {other:?}"),
        }
    }
}
