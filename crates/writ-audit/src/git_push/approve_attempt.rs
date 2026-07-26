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

/// Declare a column-discriminant enum alongside the strings its variants
/// are stored as, and generate `ALL` / `as_wire` / `parse_wire` from that
/// one table.
///
/// The point is that the variant list and the enumeration cannot
/// disagree: `ALL` is *generated from the same tokens as the variants*,
/// so there is no hand-maintained list to forget to extend, and no test
/// needed to check that it was extended. `as_wire` and `parse_wire` are
/// likewise two directions of one mapping rather than two matches that
/// have to be kept in step. (`parse_wire` is a `match` on the literals,
/// so it is a jump table, not a linear scan.)
///
/// This is the crate's only macro-generated type. It earns that by
/// removing an invariant from the "someone must remember" column: the
/// alternative — three hand-written items per enum plus a test that
/// cannot actually prove `ALL` is complete — is what the first draft of
/// this module had, and a reviewer was right to point out that the test
/// proved less than it claimed.
macro_rules! wire_name_enum {
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
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
        $vis enum $name {
            $(
                $(#[$vmeta])*
                $variant,
            )+
        }

        impl $name {
            /// Every discriminant this column may hold, in declaration
            /// order. Generated from the variant list itself, so it is
            /// exhaustive by construction.
            pub const ALL: &'static [Self] = &[ $( Self::$variant, )+ ];

            /// The string stored in the column. The set of these must
            /// equal the column's CHECK-constraint literals; the
            /// `rust_and_schema_admit_the_same_*` tests read the live
            /// DDL and assert exactly that.
            pub fn as_wire(self) -> &'static str {
                match self {
                    $( Self::$variant => $wire, )+
                }
            }

            /// Parse a column value. `None` for anything outside the
            /// enum — the caller turns that into an `Invariant` error,
            /// since a row holding an unknown value is a schema-CHECK
            /// violation that should have been impossible.
            pub fn parse_wire(raw: &str) -> Option<Self> {
                match raw {
                    $( $wire => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }
    };
}

wire_name_enum! {
    /// The value of the `state` column: an approve attempt's position in
    /// the forward-only lifecycle, without the payload each position
    /// carries.
    ///
    /// Use this for column reads/writes and for talking about a state
    /// *class*; use [`GitPushApproveAttemptState`] when the payload
    /// (mint, outcome, completion time) matters.
    pub enum ApproveAttemptStateName {
        Started => "started",
        Uncertain => "uncertain",
        Resolved => "resolved",
    }
}

wire_name_enum! {
    /// The value of the `outcome` column: how a `Resolved` attempt ended,
    /// without the payload (`new_app_tip` / `failure_detail`) the outcome
    /// carries. `NULL` in the column corresponds to a non-`Resolved`
    /// state and so has no variant here.
    pub enum ApproveAttemptOutcomeName {
        Succeeded => "succeeded",
        PrePatchFailure => "pre_patch_failure",
        PostPatchFailure => "post_patch_failure",
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
