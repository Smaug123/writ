//! The approve-attempt state machine: its vocabulary and its transition
//! relation.
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
//!
//! On top of that vocabulary sits [`apply`]: one total function from
//! (state, [`ApproveAttemptTransition`]) to either the next state or an
//! [`IllegalApproveTransition`]. Before it, the legal-transition relation
//! had no single Rust definition — it lived in the schema's
//! `forward_only` trigger *and*, independently, in a scatter of DAO
//! preflights (`if state != "started"`, an `allowed_states` slice
//! threaded through a helper, `UPDATE … WHERE state = 'started'`). The
//! triggers remain as the backstop; the DAO now asks this function and
//! persists what it returns.

use writ_core::core::UnixMillis;
use writ_vm_git::GitObjectId;

use super::{GitPushApproveAttemptOutcome, GitPushApproveAttemptState, PromoteMintAudit};

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

/// The attempt as the machine sees it: the row's position in the
/// lifecycle *plus* the credential the v7 mint ledger has recorded
/// against it.
///
/// The ledger looks like a side table but it is part of the attempt's
/// durable position, and migration 0007 says why: a distinct `minted`
/// state would have needed a full rebuild of a table with two incoming
/// foreign keys, so "the ledger records the same fact with a plain
/// CREATE TABLE". Two of the schema's triggers
/// (`mint_matches_ledger`, `resolve_carries_ledger_mint`) judge writes
/// against it, so a machine that could not see it would permit moves the
/// database refuses — which is exactly what it did before this type
/// existed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApproveAttempt {
    /// The `git_push_approve_attempt` row's state.
    pub state: GitPushApproveAttemptState,
    /// The credential recorded in `git_push_approve_attempt_mint`, if the
    /// attempt has minted. Only a `Started` attempt can gain one; the
    /// ledger is append-only, so it never goes back to `None`.
    pub ledger_mint: Option<PromoteMintAudit>,
}

impl ApproveAttempt {
    /// An attempt in `state` that has not minted.
    pub fn new(state: GitPushApproveAttemptState) -> Self {
        Self {
            state,
            ledger_mint: None,
        }
    }
}

/// A move the broker asks the machine to make. One variant per durable
/// step of `approve_staged_push`, carrying exactly the data that step
/// contributes.
///
/// These are *requests*, not facts: [`apply`] decides whether the move is
/// legal from the attempt's actual position. Construct one, apply it, and
/// persist what comes back — the DAO no longer decides for itself what a
/// given step may do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApproveAttemptTransition {
    /// Record the credential this attempt just minted, before the long
    /// prepare phase (staging fetch, unbundle, plan, uploads) runs. From
    /// here on the mint's identity survives a crash.
    RecordMint { mint: PromoteMintAudit },
    /// TX2: the broker has finished the lease check and is about to issue
    /// `update_ref`. Records the mint the PATCH will use. Once this
    /// commits the broker owes the audit log a resolution, and reject is
    /// refused in the interim.
    MarkUncertain { mint: PromoteMintAudit },
    /// TX3, happy path: `update_ref` was confirmed. Legal only from
    /// `Uncertain` — a `Started` attempt has provably issued no PATCH, so
    /// it cannot have succeeded.
    ResolveSucceeded {
        new_app_tip: GitObjectId,
        completed_at: UnixMillis,
    },
    /// Resolve as "failed before `update_ref` went out", provably
    /// retryable.
    ///
    /// The recorded mint is *derived*, not supplied: an `Uncertain` row
    /// carries its own, and a `Started` one carries whatever the ledger
    /// holds. That is what the schema's `resolve_carries_ledger_mint`
    /// trigger demands, so deriving it makes the rule impossible to
    /// forget at a call site.
    ResolvePrePatchFailure {
        detail: String,
        completed_at: UnixMillis,
    },
    /// Resolve as `PrePatchFailure` while recording a mint the caller
    /// holds that the ledger may not know (the ledger write itself
    /// failed). Legal only from `Started`, and only when it does not
    /// contradict a ledger row: an `Uncertain` row already carries its
    /// mint, so callers in that state use [`Self::ResolvePrePatchFailure`].
    CapturePrePatchFailure {
        detail: String,
        mint: PromoteMintAudit,
        completed_at: UnixMillis,
    },
    /// Resolve as "`update_ref` was issued and the result is unknown".
    /// Legal only from `Uncertain`, for the same reason `ResolveSucceeded`
    /// is: no PATCH can have gone out from `Started`.
    ResolvePostPatchFailure {
        detail: String,
        completed_at: UnixMillis,
    },
}

impl ApproveAttemptTransition {
    /// Short name for diagnostics. Not a wire format — nothing persists
    /// a transition, only the position it produces.
    pub fn label(&self) -> &'static str {
        match self {
            Self::RecordMint { .. } => "record-mint",
            Self::MarkUncertain { .. } => "mark-uncertain",
            Self::ResolveSucceeded { .. } => "resolve-succeeded",
            Self::ResolvePrePatchFailure { .. } => "resolve-pre-patch-failure",
            Self::CapturePrePatchFailure { .. } => "capture-pre-patch-failure",
            Self::ResolvePostPatchFailure { .. } => "resolve-post-patch-failure",
        }
    }
}

/// A transition the machine refuses, with enough context to say why in an
/// operator-facing error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IllegalApproveTransition {
    /// The state the attempt was actually in.
    pub from: ApproveAttemptStateName,
    /// [`ApproveAttemptTransition::label`] of the refused move.
    pub transition: &'static str,
    /// Why it is refused, in terms of the invariant being protected.
    pub because: &'static str,
}

impl std::fmt::Display for IllegalApproveTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "illegal approve-attempt transition {} from '{}': {}",
            self.transition,
            self.from.as_wire(),
            self.because,
        )
    }
}

impl std::error::Error for IllegalApproveTransition {}

/// The transition relation, in one place.
///
/// This is the Rust half of a machine whose other half is the schema's
/// `forward_only`, `mint_immutable`, `mint_matches_ledger`,
/// `resolve_carries_ledger_mint`, and `mint_ledger_requires_started`
/// triggers. The triggers stay — they are the unkillable layer, and
/// correctness-over-availability says the database should refuse a
/// contradiction even when every Rust caller is wrong. What changes is
/// that the Rust side is no longer a scatter of `if state != "started"`
/// preflights spread across the DAO: it is this function, and the DAO
/// persists what it returns.
///
/// `transition_agrees_with_the_schema` in the tests drives every
/// (position, transition) pair — including both ledger states — against a
/// real SQLite database and asserts the two halves accept the same moves,
/// so they cannot drift apart.
pub fn apply(
    attempt: &ApproveAttempt,
    transition: &ApproveAttemptTransition,
) -> Result<ApproveAttempt, IllegalApproveTransition> {
    use ApproveAttemptTransition as T;
    use GitPushApproveAttemptState as S;

    let refuse = |because| {
        Err(IllegalApproveTransition {
            from: attempt.state.name(),
            transition: transition.label(),
            because,
        })
    };
    let ledger = attempt.ledger_mint;
    // A mint the caller supplies must agree with the ledger row if there
    // is one: the audit log answers "which credential did this attempt
    // burn?" exactly once. (`mint_matches_ledger` enforces the same.)
    let contradicts_ledger =
        |supplied: PromoteMintAudit| ledger.is_some_and(|recorded| recorded != supplied);
    let resolved = |outcome, mint, completed_at| {
        Ok(ApproveAttempt {
            state: S::Resolved {
                outcome,
                mint,
                completed_at,
            },
            ledger_mint: ledger,
        })
    };

    match (&attempt.state, transition) {
        // The ledger write. Append-only and `started`-only, so the second
        // one is refused rather than overwriting the first.
        (S::Started, T::RecordMint { mint }) => {
            if ledger.is_some() {
                return refuse("the attempt has already recorded a mint");
            }
            Ok(ApproveAttempt {
                state: S::Started,
                ledger_mint: Some(*mint),
            })
        }
        (S::Uncertain { .. }, T::RecordMint { .. }) => {
            refuse("the mint ledger is only written while the attempt is 'started'")
        }

        // Started → Uncertain: the row takes on the mint of the PATCH
        // that is about to be issued.
        (S::Started, T::MarkUncertain { mint }) => {
            if contradicts_ledger(*mint) {
                return refuse("the mint ledger already records a different credential");
            }
            Ok(ApproveAttempt {
                state: S::Uncertain { mint: *mint },
                ledger_mint: ledger,
            })
        }

        // Started → Resolved(PrePatchFailure): the two pre-PATCH resolve
        // paths, differing only in where the recorded mint comes from.
        (
            S::Started,
            T::ResolvePrePatchFailure {
                detail,
                completed_at,
            },
        ) => resolved(
            GitPushApproveAttemptOutcome::PrePatchFailure {
                detail: detail.clone(),
            },
            ledger,
            *completed_at,
        ),
        (
            S::Started,
            T::CapturePrePatchFailure {
                detail,
                mint,
                completed_at,
            },
        ) => {
            if contradicts_ledger(*mint) {
                return refuse("the mint ledger already records a different credential");
            }
            resolved(
                GitPushApproveAttemptOutcome::PrePatchFailure {
                    detail: detail.clone(),
                },
                Some(*mint),
                *completed_at,
            )
        }

        // Uncertain → Resolved(any). The mint is carried forward verbatim
        // in every case: the audit log's promise is "this approval used
        // credential X", and the mint-immutability trigger holds us to it.
        (
            S::Uncertain { mint },
            T::ResolveSucceeded {
                new_app_tip,
                completed_at,
            },
        ) => resolved(
            GitPushApproveAttemptOutcome::Succeeded {
                new_app_tip: new_app_tip.clone(),
            },
            Some(*mint),
            *completed_at,
        ),
        (
            S::Uncertain { mint },
            T::ResolvePrePatchFailure {
                detail,
                completed_at,
            },
        ) => resolved(
            GitPushApproveAttemptOutcome::PrePatchFailure {
                detail: detail.clone(),
            },
            Some(*mint),
            *completed_at,
        ),
        (
            S::Uncertain { mint },
            T::ResolvePostPatchFailure {
                detail,
                completed_at,
            },
        ) => resolved(
            GitPushApproveAttemptOutcome::PostPatchFailure {
                detail: detail.clone(),
            },
            Some(*mint),
            *completed_at,
        ),

        // Everything else. Spelled out rather than collapsed into a
        // wildcard so each refusal can say which invariant it protects,
        // and so a new transition or state has to be considered here.
        (S::Started, T::ResolveSucceeded { .. } | T::ResolvePostPatchFailure { .. }) => {
            refuse("no PATCH can have been issued before the attempt is 'uncertain'")
        }
        (S::Uncertain { .. }, T::MarkUncertain { .. }) => {
            refuse("the attempt is already 'uncertain'")
        }
        (S::Uncertain { .. }, T::CapturePrePatchFailure { .. }) => {
            refuse("an 'uncertain' attempt already carries its mint")
        }
        (S::Resolved { .. }, _) => refuse("'resolved' is terminal"),
    }
}

#[cfg(test)]
mod tests;
