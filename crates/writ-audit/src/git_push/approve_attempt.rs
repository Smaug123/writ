//! The approve-attempt state machine's vocabulary.
//!
//! The `git_push_approve_attempt` row stores its position in the machine
//! as two TEXT columns — `state` and (once terminal) `outcome` — whose
//! legal values are pinned by CHECK constraints in migration
//! `0003_approve_attempt_state_machine.sql`. The data-carrying
//! [`GitPushApproveAttemptState`] / [`GitPushApproveAttemptOutcome`] DUs
//! in the parent module are what the rest of the crate reasons about;
//! this module owns the *flat discriminants* those columns hold and the
//! only conversion between the two representations.
//!
//! Before this module existed the wire names were bare string literals
//! at every write site (`if state != "started"`, `&["started",
//! "uncertain"]`, `SET outcome = 'pre_patch_failure'`) with a one-way
//! `match` in the row parser. Adding an outcome meant grepping for
//! literals; a typo was a runtime `Invariant` error at best and a
//! silently-unreachable branch at worst. Centralising the codec makes
//! the discriminant set enumerable — [`ApproveAttemptStateName::ALL`] and
//! [`ApproveAttemptOutcomeName::ALL`] are what the schema-agreement
//! tests sweep to prove the Rust enum and the SQL CHECK admit exactly
//! the same strings.

use super::{GitPushApproveAttemptOutcome, GitPushApproveAttemptState};

/// The value of the `state` column: an approve attempt's position in the
/// forward-only lifecycle, without the payload each position carries.
///
/// Use this for column reads/writes and for talking about a state
/// *class*; use [`GitPushApproveAttemptState`] when the payload (mint,
/// outcome, completion time) matters.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ApproveAttemptStateName {
    Started,
    Uncertain,
    Resolved,
}

impl ApproveAttemptStateName {
    /// Every discriminant the `state` column may hold. Kept exhaustive by
    /// the `all_is_exhaustive` test below, which matches on a value of
    /// this type so a new variant fails to compile until it is listed.
    pub const ALL: &'static [Self] = &[Self::Started, Self::Uncertain, Self::Resolved];

    /// The string stored in the `state` column. Must match the CHECK
    /// constraint in migration 0003; `wire_names_match_schema_check`
    /// proves it does.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Uncertain => "uncertain",
            Self::Resolved => "resolved",
        }
    }

    /// Parse a `state` column value. `None` for anything outside the
    /// enum — the caller turns that into an `Invariant` error, since a
    /// row holding an unknown state is a schema-CHECK violation that
    /// should have been impossible.
    pub fn parse_wire(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.as_wire() == raw)
    }
}

/// The value of the `outcome` column: how a `Resolved` attempt ended,
/// without the payload (`new_app_tip` / `failure_detail`) the outcome
/// carries. `NULL` in the column corresponds to a non-`Resolved` state
/// and so has no variant here.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ApproveAttemptOutcomeName {
    Succeeded,
    PrePatchFailure,
    PostPatchFailure,
}

impl ApproveAttemptOutcomeName {
    /// Every discriminant the `outcome` column may hold. See
    /// [`ApproveAttemptStateName::ALL`] for how exhaustiveness is kept.
    pub const ALL: &'static [Self] = &[
        Self::Succeeded,
        Self::PrePatchFailure,
        Self::PostPatchFailure,
    ];

    /// The string stored in the `outcome` column.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::PrePatchFailure => "pre_patch_failure",
            Self::PostPatchFailure => "post_patch_failure",
        }
    }

    /// Parse an `outcome` column value. `None` for anything outside the
    /// enum, including the empty string.
    pub fn parse_wire(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_wire() == raw)
    }
}

impl GitPushApproveAttemptState {
    /// The `state` column value this state is stored as.
    pub fn name(&self) -> ApproveAttemptStateName {
        match self {
            Self::Started => ApproveAttemptStateName::Started,
            Self::Uncertain { .. } => ApproveAttemptStateName::Uncertain,
            Self::Resolved { .. } => ApproveAttemptStateName::Resolved,
        }
    }

    /// The `outcome` column value this state is stored as — `None` for
    /// the two non-terminal states, mirroring the column's NULL.
    pub fn outcome_name(&self) -> Option<ApproveAttemptOutcomeName> {
        match self {
            Self::Started | Self::Uncertain { .. } => None,
            Self::Resolved { outcome, .. } => Some(outcome.name()),
        }
    }
}

impl GitPushApproveAttemptOutcome {
    /// The `outcome` column value this outcome is stored as.
    pub fn name(&self) -> ApproveAttemptOutcomeName {
        match self {
            Self::Succeeded { .. } => ApproveAttemptOutcomeName::Succeeded,
            Self::PrePatchFailure { .. } => ApproveAttemptOutcomeName::PrePatchFailure,
            Self::PostPatchFailure { .. } => ApproveAttemptOutcomeName::PostPatchFailure,
        }
    }
}

#[cfg(test)]
mod tests;
