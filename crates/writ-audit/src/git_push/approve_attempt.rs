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

/// A move the broker asks the machine to make. One variant per durable
/// step of `approve_staged_push`, carrying exactly the data that step
/// contributes to the row.
///
/// These are *requests*, not facts: [`apply`] decides whether the move is
/// legal from the state the attempt is actually in. Construct one, apply
/// it, and persist the state that comes back — the DAO no longer decides
/// for itself what a given step may do.
///
/// The mint is supplied by the caller rather than looked up here: which
/// credential a resolve should record is a storage question (the v7
/// ledger, `git_push_approve_attempt_mint`, may hold one for a `Started`
/// attempt), and this module is pure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApproveAttemptTransition {
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
    /// retryable. `mint` is the credential the attempt already implies:
    /// the ledger mint for a `Started` row (`None` if it never minted),
    /// or `None` from `Uncertain`, whose own mint is carried forward.
    ResolvePrePatchFailure {
        detail: String,
        mint: Option<PromoteMintAudit>,
        completed_at: UnixMillis,
    },
    /// Resolve as `PrePatchFailure` while recording a mint the caller
    /// holds that the ledger may not know (the ledger write itself
    /// failed). Legal only from `Started`: an `Uncertain` row already
    /// carries its mint, and the schema's mint-immutability trigger
    /// governs it from there, so callers in that state use
    /// [`Self::ResolvePrePatchFailure`].
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
    /// a transition, only the state it produces.
    pub fn label(&self) -> &'static str {
        match self {
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
/// `git_push_approve_attempt_forward_only` and
/// `git_push_approve_attempt_mint_immutable` triggers. The triggers stay
/// — they are the unkillable layer, and correctness-over-availability
/// says the database should refuse a contradiction even when every Rust
/// caller is wrong. What changes is that the Rust side is no longer a
/// scatter of `if state != "started"` preflights spread across the DAO:
/// it is this function, and the DAO persists what it returns.
///
/// `transition_agrees_with_the_schema` in the tests drives every
/// (state, transition) pair against a real SQLite database and asserts
/// the two halves accept the same moves, so they cannot drift apart.
pub fn apply(
    state: &GitPushApproveAttemptState,
    transition: &ApproveAttemptTransition,
) -> Result<GitPushApproveAttemptState, IllegalApproveTransition> {
    use ApproveAttemptTransition as T;
    use GitPushApproveAttemptState as S;

    let refuse = |because| {
        Err(IllegalApproveTransition {
            from: state.name(),
            transition: transition.label(),
            because,
        })
    };

    match (state, transition) {
        // Started → Uncertain: the row takes on the mint of the PATCH
        // that is about to be issued.
        (S::Started, T::MarkUncertain { mint }) => Ok(S::Uncertain { mint: *mint }),

        // Started → Resolved(PrePatchFailure): the two pre-PATCH resolve
        // paths, differing only in where the recorded mint came from.
        (
            S::Started,
            T::ResolvePrePatchFailure {
                detail,
                mint,
                completed_at,
            },
        ) => Ok(S::Resolved {
            outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                detail: detail.clone(),
            },
            mint: *mint,
            completed_at: *completed_at,
        }),
        (
            S::Started,
            T::CapturePrePatchFailure {
                detail,
                mint,
                completed_at,
            },
        ) => Ok(S::Resolved {
            outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                detail: detail.clone(),
            },
            mint: Some(*mint),
            completed_at: *completed_at,
        }),

        // Uncertain → Resolved(any). The mint is carried forward verbatim
        // in every case: the audit log's promise is "this approval used
        // credential X", and the schema's mint-immutability trigger holds
        // us to it.
        (
            S::Uncertain { mint },
            T::ResolveSucceeded {
                new_app_tip,
                completed_at,
            },
        ) => Ok(S::Resolved {
            outcome: GitPushApproveAttemptOutcome::Succeeded {
                new_app_tip: new_app_tip.clone(),
            },
            mint: Some(*mint),
            completed_at: *completed_at,
        }),
        (
            S::Uncertain { mint },
            T::ResolvePrePatchFailure {
                detail,
                mint: supplied,
                completed_at,
            },
        ) => {
            if supplied.is_some_and(|supplied| supplied != *mint) {
                return refuse("the row's mint is immutable once recorded");
            }
            Ok(S::Resolved {
                outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                    detail: detail.clone(),
                },
                mint: Some(*mint),
                completed_at: *completed_at,
            })
        }
        (
            S::Uncertain { mint },
            T::ResolvePostPatchFailure {
                detail,
                completed_at,
            },
        ) => Ok(S::Resolved {
            outcome: GitPushApproveAttemptOutcome::PostPatchFailure {
                detail: detail.clone(),
            },
            mint: Some(*mint),
            completed_at: *completed_at,
        }),

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
