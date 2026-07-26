//! The plan workflow's transition relation, in one place.
//!
//! Before this module, four sites each encoded their own answer to
//! "may this stage run now?", and no two agreed:
//!
//! - `plan_decide` read no precondition at all, so `bailiff plan
//!   decide` against an unsubmitted plan created the plan's ref and
//!   produced a [`PlanState::Corrupt`] row — the anomaly the display
//!   layer exists to *report*, manufactured by a sibling verb;
//! - [`crate::bailiff_plan_review::submit_review`] gated on the
//!   submission only, so a rejected plan reviewed happily;
//! - [`crate::bailiff_plan_implement::submit_implement`] gated on
//!   submission + `Accepted` + no prior implement, never reading the
//!   review note at all;
//! - `BailiffPlanSummary::state` derived a fourth relation for
//!   display, preferring "the latest stage present in the data".
//!
//! Everything the workflow knows about legality now lives here:
//! [`NotePresence`] is the observation, [`PlanState`] the position,
//! [`PlanStage`] the event, [`derive_state`] the parse, and [`allows`] the
//! relation. Call sites ask; they do not re-derive.
//!
//! **Corruption is defined by the relation, not listed separately.**
//! A note set is [`PlanState::Corrupt`] exactly when no legal sequence
//! of stages from [`PlanState::Absent`] could have produced it. That
//! makes the corruption detector and the gate two readings of one
//! definition rather than two encodings that can drift, and it is what
//! `reachable_presences_are_exactly_the_non_corrupt_states` checks by
//! walking the relation with a reference implementation that never
//! consults [`PlanState::presence`].
//!
//! **The write-side `AlreadyRecorded` errors stay.** This machine
//! subsumes all four of the old ad-hoc idempotency gates — `Decide` is
//! illegal from `Accepted`/`Rejected`, `Review` from `Reviewed`,
//! `Implement` from `Implemented` — but
//! [`writ::notes_repo::NotesRepo::write_note_if_absent`] keeps refusing
//! a second write at an occupied seed. That is the unkillable layer, in
//! the same sense as the approve path's SQL triggers
//! (`docs/plans/2026-07-25-approve-state-machine-as-a-type.md`): the
//! repo should refuse a contradiction even if every Rust caller above
//! it is wrong.
//!
//! See `docs/plans/2026-07-26-bailiff-workflow-as-data.md` slice 1.

use crate::bailiff_decision::Decision;

/// Declare an enum together with its exhaustive `ALL` list and its
/// stable lowercase wire spelling, from one variant⇒literal table.
///
/// The list and the variants are generated from the same tokens, so
/// `ALL` cannot fall behind a newly-added variant — which matters here
/// because every property in this module quantifies over `ALL`, and an
/// `ALL` missing a variant would silently weaken all of them at once.
/// `crates/writ-audit/src/git_push/approve_attempt.rs` has a
/// near-identical macro and records why (a reviewer found its
/// hand-written predecessor's completeness test proved less than it
/// claimed). The two are not shared: `bailiff` depends on `writ`, which
/// depends on `writ-audit`, so exporting one across that chain would
/// leak an audit-crate internal to a product-layer crate to save
/// twenty lines.
macro_rules! plan_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$vmeta:meta])*
                $variant:ident => $wire:literal,
            )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
        $vis enum $name {
            $(
                $(#[$vmeta])*
                $variant,
            )+
        }

        impl $name {
            /// Every variant, in declaration order. Generated from the
            /// variant list itself, so it is exhaustive by construction.
            pub const ALL: &'static [Self] = &[ $( Self::$variant, )+ ];

            /// Stable lowercase spelling for CLI output and error text.
            pub fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $wire, )+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

/// Which of the four per-plan notes exist, plus the decision's outcome
/// when there is one. The whole observation the transition relation
/// needs, and the only input [`derive_state`] takes.
///
/// This is the parse-don't-validate boundary: readers turn git state
/// into a `NotePresence` once, and everything downstream reasons about
/// the position rather than re-reading notes. `decision` is
/// `Option<Decision>` rather than a `bool` because the outcome is what
/// splits the workflow — `Accepted` and `Rejected` are different
/// positions, not one position with a flag.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct NotePresence {
    pub submission: bool,
    pub decision: Option<Decision>,
    pub review: bool,
    pub implement: bool,
}

impl NotePresence {
    /// Nothing recorded — the position a plan occupies before `submit`.
    pub const NONE: Self = Self {
        submission: false,
        decision: None,
        review: false,
        implement: false,
    };
}

plan_enum! {
    /// Where a plan stands, derived from its note set by [`derive_state`].
    ///
    /// The progression is `Absent` → `Submitted` → `Reviewed` →
    /// (`Accepted` | `Rejected`) → `Implemented`, with `Rejected`
    /// terminal and `Corrupt` off to the side.
    ///
    /// Review precedes the decision because reviewer feedback is an
    /// *input* to it: `docs/plans/2026-05-11-agent-plans.md` specifies
    /// "the review → decide → execute cycle" and "reviewer feedback is
    /// for the decision, not for execution", which is also why
    /// `submit_implement` deliberately keeps the review note out of
    /// the implementer's prompt.
    pub enum PlanState {
        /// No notes at all. A plan id that has never been submitted;
        /// the only position from which [`PlanStage::Submit`] is legal.
        ///
        /// Distinct from `Corrupt`, which the pre-slice-1 derivation
        /// conflated with it: "nothing has happened yet" and "notes
        /// exist in an impossible combination" call for opposite
        /// operator responses.
        Absent => "absent",
        /// A note set no legal stage sequence could have produced —
        /// for example a decision without a submission, or an
        /// implement note on a plan that was never reviewed. Reachable
        /// only by manual repo surgery (or by a pre-slice-1 binary),
        /// and denies every stage.
        Corrupt => "corrupt",
        /// Submission attached, awaiting review.
        Submitted => "submitted",
        /// Submitted and reviewed; the reviewer's findings are
        /// recorded and the plan is awaiting an operator verdict.
        Reviewed => "reviewed",
        /// Reviewed and accepted, awaiting implementation.
        Accepted => "accepted",
        /// Reviewed and rejected. Terminal: bailiff does no
        /// auto-anything, so the operator submits a fresh plan.
        Rejected => "rejected",
        /// Implemented. Terminal.
        Implemented => "implemented",
    }
}

plan_enum! {
    /// The four workflow events, one per mutating verb.
    pub enum PlanStage {
        Submit => "submit",
        Decide => "decide",
        Review => "review",
        Implement => "implement",
    }
}

impl PlanState {
    /// The note set this state corresponds to, or `None` for
    /// [`PlanState::Corrupt`] (which is *every* other note set, so it
    /// has no single presence).
    ///
    /// Read as the inverse of [`derive_state`]. It is a second encoding of
    /// the workflow's shape — [`PlanStage::legal_predecessors`] is the
    /// first — and the two are bound by
    /// `presence_agrees_with_the_transition_relation`, which walks the
    /// relation and checks each move lands on the successor's presence.
    /// Duplication that cannot silently diverge is a different animal
    /// from duplication that can.
    pub const fn presence(self) -> Option<NotePresence> {
        const fn p(
            decision: Option<Decision>,
            review: bool,
            implement: bool,
        ) -> Option<NotePresence> {
            Some(NotePresence {
                submission: true,
                decision,
                review,
                implement,
            })
        }
        match self {
            PlanState::Corrupt => None,
            PlanState::Absent => Some(NotePresence::NONE),
            PlanState::Submitted => p(None, false, false),
            PlanState::Reviewed => p(None, true, false),
            PlanState::Accepted => p(Some(Decision::Accepted), true, false),
            PlanState::Rejected => p(Some(Decision::Rejected), true, false),
            PlanState::Implemented => p(Some(Decision::Accepted), true, true),
        }
    }

    /// Position along the workflow's progression, or `None` for
    /// [`PlanState::Corrupt`], which is not on it.
    ///
    /// Used to tell "this stage has not become legal yet" from "this
    /// stage was already passed" — two refusals with opposite
    /// remedies. `Accepted` and `Rejected` share a rank because they
    /// are the same step's two outcomes.
    pub const fn rank(self) -> Option<u8> {
        match self {
            PlanState::Corrupt => None,
            PlanState::Absent => Some(0),
            PlanState::Submitted => Some(1),
            PlanState::Reviewed => Some(2),
            PlanState::Accepted | PlanState::Rejected => Some(3),
            PlanState::Implemented => Some(4),
        }
    }

    /// The stage that may run next, or `None` from a terminal or
    /// corrupt position. Powers the "run `bailiff plan X` first" hint
    /// in [`IllegalTransition`]'s message, so no call site hand-writes
    /// a remedy.
    pub fn next_stage(self) -> Option<PlanStage> {
        PlanStage::ALL
            .iter()
            .copied()
            .find(|stage| stage.legal_predecessors().contains(&self))
    }
}

impl PlanStage {
    /// Every state from which this stage may run.
    ///
    /// The relation is currently a chain — each stage has exactly one
    /// legal predecessor — but it is expressed as a set because a
    /// transition relation is a relation, and slice 4's fan-out and
    /// collect stages are not obviously single-predecessor. Costs a
    /// `contains` over a one-element slice.
    pub const fn legal_predecessors(self) -> &'static [PlanState] {
        match self {
            PlanStage::Submit => &[PlanState::Absent],
            PlanStage::Review => &[PlanState::Submitted],
            PlanStage::Decide => &[PlanState::Reviewed],
            PlanStage::Implement => &[PlanState::Accepted],
        }
    }
}

impl PlanStage {
    /// Did `state` already pass this stage?
    ///
    /// True when the plan is strictly beyond every position from which
    /// the stage could have run — which is exactly the repeated-command
    /// case (`decide` from `accepted`, `review` from `reviewed`,
    /// `implement` from `implemented`, `submit` from anything). No
    /// later stage can make such a request legal, so the remedy is a
    /// fresh plan, not "run X first".
    pub fn already_passed_from(self, state: PlanState) -> bool {
        let Some(rank) = state.rank() else {
            return false;
        };
        self.legal_predecessors()
            .iter()
            .filter_map(|p| p.rank())
            .all(|pred| rank > pred)
    }
}

/// Parse a note set into the plan's position.
///
/// Total: every one of the 24 possible `NotePresence` values maps to
/// exactly one [`PlanState`], and the 18 that no legal stage sequence
/// can produce map to [`PlanState::Corrupt`].
pub fn derive_state(presence: &NotePresence) -> PlanState {
    PlanState::ALL
        .iter()
        .copied()
        .find(|state| state.presence().as_ref() == Some(presence))
        .unwrap_or(PlanState::Corrupt)
}

/// The relation: may `stage` run from `state`?
pub fn allows(state: PlanState, stage: PlanStage) -> Result<(), IllegalTransition> {
    if stage.legal_predecessors().contains(&state) {
        Ok(())
    } else {
        Err(IllegalTransition { state, stage })
    }
}

/// A stage was asked for from a position that does not permit it.
///
/// Deliberately plan-agnostic: workflows wrap it in their own error
/// enum alongside the `plan_id`, matching how every other bailiff
/// error carries the id. The message names both the blocked stage's
/// requirement and — via [`PlanState::next_stage`] — the operator's
/// actual next command, so the four verbs no longer each hand-write
/// their own remedy text.
/// `Display` is hand-written rather than `thiserror`-derived because
/// the message is computed from the relation (the requirement list and
/// the remedy are both looked up, not spelled out), and `#[error]`'s
/// format string cannot call a method on `self`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IllegalTransition {
    pub state: PlanState,
    pub stage: PlanStage,
}

impl std::fmt::Display for IllegalTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let required = self
            .stage
            .legal_predecessors()
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(" or ");
        write!(
            f,
            "plan is {}; `{}` requires {required}. ",
            self.state, self.stage,
        )?;
        match self.state {
            // Corrupt has no next stage *and* is not terminal-by-
            // progression: the note set is impossible, so the remedy is
            // repair, not "submit a fresh plan".
            PlanState::Corrupt => f.write_str(
                "this plan's note set is one no legal sequence of stages could have produced; \
                 inspect it with `bailiff plan show` before doing anything else",
            ),
            // Repeated command. Pointing at the *next* stage here would
            // be actively misleading — running it cannot make this
            // request legal — and this is where the per-verb
            // "already recorded ... submit a fresh plan" messages the
            // transition relation replaced used to say so.
            _ if self.stage.already_passed_from(self.state) => write!(
                f,
                "this plan is already past `{}`; bailiff does not re-run a stage — submit a \
                 fresh plan if you want a different outcome",
                self.stage,
            ),
            _ => match self.state.next_stage() {
                Some(next) => write!(f, "run `bailiff plan {next}` first"),
                None => write!(
                    f,
                    "`{}` is terminal for this plan; submit a fresh plan to change course",
                    self.state
                ),
            },
        }
    }
}

impl std::error::Error for IllegalTransition {}

#[cfg(test)]
mod tests;
