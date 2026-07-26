//! Plan read-projection types: the typed views produced by
//! [`crate::bailiff_plan_read`] and consumed by `cli` output formatting
//! and the `bailiff` binary. Split out from the reader so presentation
//! code depends only on these data types, not on the read/verify logic
//! (which pulls in `notes_repo`, `run_verify`, and git IO).

use crate::bailiff_decision::{Decider, Decision};
use crate::bailiff_plan_note::{DecisionNote, ImplementNote, PlanId, PlanNote, ReviewNote};
use crate::bailiff_plan_state::{NotePresence, PlanState, derive_state};
use writ::core::{SshSignature, UnixMillis};
use writ::protocol::SignedRunMetadata;
use writ::run_envelope::SignedRunEnvelope;
use writ::run_verify::VerifyError;
use writ::vm_git::GitObjectId;

/// Aggregate per-plan view used by `bailiff plan list`. Each `Option`
/// field is `None` when the corresponding note has not been attached
/// to this plan's ref yet. The two-pass design (`list_plan_ids` then
/// `summarize_plan` per id) is one repo-read for the ref set plus four
/// reads per plan — symmetric with the existing read helpers and
/// requires no schema beyond the seed-OID convention they already
/// share.
///
/// Workflow state is derived from the field set via [`Self::presence`]
/// and [`crate::bailiff_plan_state::derive_state`]; the formatter pins the
/// rendering. Keeping state as a method rather than a stored field
/// means a future caller (e.g. `bailiff plan show`) can recompute it
/// without going through the formatter.
///
/// Submission absent (`submission.is_none()`) is a possible-but-rare
/// state: the plan's ref exists (otherwise [`crate::bailiff_plan_read::list_plan_ids`] wouldn't
/// have reported the id), yet no submission has been recorded.
/// Reachable only when a non-submission note was attached first (e.g.
/// a decision written before the plan submission landed) or when a
/// submission note was manually deleted after the fact. Surfaced as
/// [`PlanState::Corrupt`] so an operator sees the anomaly rather
/// than silently rendering an incomplete row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BailiffPlanSummary {
    pub plan_id: PlanId,
    /// Whether the plan's ref exists on disk. `false` for an id that
    /// has never been submitted; `true` for every row `bailiff plan
    /// list` reports, since that command enumerates by ref existence.
    pub ref_exists: bool,
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

impl BailiffPlanSummary {
    /// Project this summary down to the observation the transition
    /// relation reasons about. Discards the timestamps and attribution
    /// the display layer needs and the machine does not.
    pub fn presence(&self) -> NotePresence {
        NotePresence {
            ref_exists: self.ref_exists,
            submission: self.submission.is_some(),
            decision: self.decision.as_ref().map(|d| d.outcome),
            review: self.reviewed_at.is_some(),
            implement: self.implemented_at.is_some(),
        }
    }

    /// Derived workflow state.
    ///
    /// Before slice 1 this method held its own derivation — "the
    /// highest workflow step reached" — which was a fourth encoding of
    /// the transition relation and disagreed with the three gates in
    /// the workflows. It now delegates, so a note set the workflows
    /// would refuse to produce renders as [`PlanState::Corrupt`]
    /// instead of being silently labelled with a stage it never
    /// legally reached. See
    /// `docs/plans/2026-07-26-bailiff-workflow-as-data.md`.
    pub fn state(&self) -> PlanState {
        derive_state(&self.presence())
    }
}

/// Aggregate per-plan view used by `bailiff plan show` (slice F4).
/// Returned by [`crate::bailiff_plan_read::read_full_plan`] after composing the four
/// `read_*_note` helpers and, for every available signed note,
/// pairing it with the writ envelope referenced by its
/// `writ_output_oid` and verifying the signature against
/// [`writ::run_verify::AllowedSigners`].
///
/// All four note fields are `Option`: a workflow-conformant plan has
/// every field set, but each can independently be absent. The plan
/// note is `Option<VerifiedSection<PlanNote>>` rather than bare
/// `VerifiedSection<PlanNote>` so the corrupt-state anomaly F2
/// surfaces in [`PlanState::Corrupt`] (ref exists, submission
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
/// referenced writ envelope. The five-way split mirrors what
/// `bailiff plan show` (slice F4) must surface:
///
/// - [`VerifiedSection::Verified`]: envelope present, decoded,
///   end-to-end verified by [`writ::run_verify::verify_run_envelope`], **and** the
///   note's copied `(signed_metadata, signature)` pair matches the
///   envelope's. Carries both the note and the envelope so the F4
///   renderer can project from either without re-reading.
/// - [`VerifiedSection::NoteEnvelopeMismatch`]: envelope verifies on
///   its own, but the bailiff note's `signed_metadata` /
///   `signature` copies don't match the envelope at the OID. A
///   tampered or stale note paired with a legitimate envelope must
///   never render as `Verified` — the bailiff note's stated
///   metadata is what the operator sees, and it has to be exactly
///   what writ signed.
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
///   [`writ::run_verify::verify_run_envelope`] rejected it. The wrapped [`VerifyError`]
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
    NoteEnvelopeMismatch {
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

/// Projection shared by the three signed bailiff note types
/// ([`PlanNote`], [`ReviewNote`], [`ImplementNote`]). Each carries the
/// same `(purpose, writ_output_oid, signed_metadata, signature)`
/// quadruple even though the surrounding fields (`plan_id`) differ;
/// this trait lets [`crate::bailiff_plan_read::read_full_plan`] dispatch the read-and-verify
/// path uniformly without unifying the note structs themselves, and
/// lets the F4 formatter render the three sections from a single
/// shared body.
///
/// **Not** a polymorphism point: the only implementors are the three
/// note types and the only consumers are [`crate::bailiff_plan_read::read_full_plan`] and the
/// F4 show-formatter. The trait is here as a static field-projection
/// abstraction (rule of three), not as an extension surface;
/// `pub(crate)` scopes it to the same library where both consumers
/// live so it does not leak to downstream code.
pub(crate) trait SignedBailiffNote {
    fn purpose(&self) -> &str;
    fn writ_output_oid(&self) -> &GitObjectId;
    fn signed_metadata(&self) -> &SignedRunMetadata;
    fn signature(&self) -> &SshSignature;
}

impl SignedBailiffNote for PlanNote {
    fn purpose(&self) -> &str {
        &self.purpose
    }
    fn writ_output_oid(&self) -> &GitObjectId {
        &self.writ_output_oid
    }
    fn signed_metadata(&self) -> &SignedRunMetadata {
        &self.signed_metadata
    }
    fn signature(&self) -> &SshSignature {
        &self.signature
    }
}

impl SignedBailiffNote for ReviewNote {
    fn purpose(&self) -> &str {
        &self.purpose
    }
    fn writ_output_oid(&self) -> &GitObjectId {
        &self.writ_output_oid
    }
    fn signed_metadata(&self) -> &SignedRunMetadata {
        &self.signed_metadata
    }
    fn signature(&self) -> &SshSignature {
        &self.signature
    }
}

impl SignedBailiffNote for ImplementNote {
    fn purpose(&self) -> &str {
        &self.purpose
    }
    fn writ_output_oid(&self) -> &GitObjectId {
        &self.writ_output_oid
    }
    fn signed_metadata(&self) -> &SignedRunMetadata {
        &self.signed_metadata
    }
    fn signature(&self) -> &SshSignature {
        &self.signature
    }
}
