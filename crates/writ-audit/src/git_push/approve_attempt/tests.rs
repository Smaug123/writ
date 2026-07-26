//! Tests for the approve-attempt wire-name codec.
//!
//! The interesting ones are the *schema-agreement* sweeps. The Rust enums
//! and the CHECK constraints in migration 0003 are two encodings of one
//! discriminant set; these tests make SQLite the oracle for the Rust
//! side, so a name added, renamed, or removed on one side and not the
//! other fails here rather than at runtime against a real audit log.

use proptest::prelude::*;
use rusqlite::{OptionalExtension, params};

use super::super::test_support::*;
use super::*;
use crate::AuditLog;
use writ_core::core::{ApproveAttemptId, RequestId};

/// Distinct variants must not collide on the wire, or a row would parse
/// back as the wrong state.
#[test]
fn wire_names_are_distinct() {
    let states: std::collections::HashSet<_> = ApproveAttemptStateName::ALL
        .iter()
        .map(|s| s.as_wire())
        .collect();
    assert_eq!(states.len(), ApproveAttemptStateName::ALL.len());
    let outcomes: std::collections::HashSet<_> = ApproveAttemptOutcomeName::ALL
        .iter()
        .map(|o| o.as_wire())
        .collect();
    assert_eq!(outcomes.len(), ApproveAttemptOutcomeName::ALL.len());
}

proptest! {
    /// `parse_wire` accepts exactly the strings `as_wire` produces: it
    /// round-trips a real name and rejects everything else. Generating
    /// arbitrary strings (rather than a hand-picked reject list) is what
    /// catches an over-eager parser — a case-insensitive or
    /// prefix-matching implementation fails here.
    #[test]
    fn state_parse_wire_accepts_exactly_the_wire_names(raw in ".{0,24}") {
        let expected = ApproveAttemptStateName::ALL
            .iter()
            .copied()
            .find(|s| s.as_wire() == raw);
        prop_assert_eq!(ApproveAttemptStateName::parse_wire(&raw), expected);
    }

    #[test]
    fn outcome_parse_wire_accepts_exactly_the_wire_names(raw in ".{0,24}") {
        let expected = ApproveAttemptOutcomeName::ALL
            .iter()
            .copied()
            .find(|o| o.as_wire() == raw);
        prop_assert_eq!(ApproveAttemptOutcomeName::parse_wire(&raw), expected);
    }
}

#[test]
fn state_names_round_trip() {
    for name in ApproveAttemptStateName::ALL {
        assert_eq!(
            ApproveAttemptStateName::parse_wire(name.as_wire()),
            Some(*name)
        );
    }
    for name in ApproveAttemptOutcomeName::ALL {
        assert_eq!(
            ApproveAttemptOutcomeName::parse_wire(name.as_wire()),
            Some(*name)
        );
    }
}

/// The column shape a raw INSERT needs for a given position in the
/// machine. Written out per state/outcome because the cross-column
/// CHECKs in migration 0003 demand it: a `resolved` row needs an
/// outcome and a `completed_at`, `succeeded` needs a `new_app_tip` and
/// a mint, and so on.
///
/// This is deliberately the *only* place in the tests that restates the
/// row shape, and the matches below are wildcard-free: a new state or
/// outcome cannot be added to the Rust enums without someone writing
/// down what its row looks like — at which point the sweep below asks
/// SQLite whether the schema agrees that such a row is legal.
struct RowShape {
    state: String,
    outcome: Option<String>,
    completed_at: Option<i64>,
    new_app_tip: Option<String>,
    failure_detail: Option<String>,
    mint: bool,
}

fn shape_for_state(name: ApproveAttemptStateName) -> RowShape {
    match name {
        ApproveAttemptStateName::Started => RowShape {
            state: name.as_wire().into(),
            outcome: None,
            completed_at: None,
            new_app_tip: None,
            failure_detail: None,
            mint: false,
        },
        ApproveAttemptStateName::Uncertain => RowShape {
            state: name.as_wire().into(),
            outcome: None,
            completed_at: None,
            new_app_tip: None,
            failure_detail: None,
            mint: true,
        },
        // A `resolved` row must name an outcome; pick the simplest one.
        // The outcome sweep below covers the other two.
        ApproveAttemptStateName::Resolved => {
            shape_for_outcome(ApproveAttemptOutcomeName::PrePatchFailure)
        }
    }
}

fn shape_for_outcome(name: ApproveAttemptOutcomeName) -> RowShape {
    let base = RowShape {
        state: ApproveAttemptStateName::Resolved.as_wire().into(),
        outcome: Some(name.as_wire().into()),
        completed_at: Some(1_700_000_300),
        new_app_tip: None,
        failure_detail: None,
        mint: false,
    };
    match name {
        ApproveAttemptOutcomeName::Succeeded => RowShape {
            new_app_tip: Some(git_oid('3').as_str().to_string()),
            mint: true,
            ..base
        },
        ApproveAttemptOutcomeName::PrePatchFailure => RowShape {
            failure_detail: Some("walker refused".into()),
            ..base
        },
        ApproveAttemptOutcomeName::PostPatchFailure => RowShape {
            failure_detail: Some("transport drop after PATCH".into()),
            mint: true,
            ..base
        },
    }
}

/// Raw INSERT of one attempt row, bypassing the DAO so the schema is the
/// only thing judging the row. Returns the SQLite result verbatim.
fn try_insert_row(
    log: &AuditLog,
    push_request_id: RequestId,
    shape: &RowShape,
) -> Result<(), rusqlite::Error> {
    let mint = sample_promote_mint_audit();
    log.with_conn_mut(|c| {
        c.execute(
            "INSERT INTO git_push_approve_attempt (
                 attempt_id, push_request_id, operator, started_at,
                 state, outcome, completed_at, new_app_tip, failure_detail,
                 mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
             ) VALUES (?1, ?2, 'alice', 1700000200,
                       ?3, ?4, ?5, ?6, ?7,
                       ?8, ?9, ?10, ?11)",
            params![
                ApproveAttemptId::new().as_uuid().to_string(),
                push_request_id.as_uuid().to_string(),
                shape.state,
                shape.outcome,
                shape.completed_at,
                shape.new_app_tip,
                shape.failure_detail,
                shape.mint.then(|| mint.jti.as_uuid().to_string()),
                shape.mint.then_some(mint.github_app_id as i64),
                shape.mint.then_some(mint.issued_at.as_millis()),
                shape.mint.then_some(mint.expires_at.as_millis()),
            ],
        )
        .map(|_| ())
        .map_err(crate::AuditError::from)
    })
    .map_err(|e| match e {
        crate::AuditError::Sqlite(e) => e,
        other => panic!("unexpected audit error: {other:?}"),
    })
}

fn staged_log() -> (AuditLog, RequestId) {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    open_with_staged_request(&log, push_request_id);
    (log, push_request_id)
}

/// Every `state` value the Rust enum can produce is one the schema
/// admits. Fails if Rust gains a state the CHECK does not list.
#[test]
fn every_state_wire_name_is_accepted_by_the_schema() {
    for name in ApproveAttemptStateName::ALL {
        let (log, push_request_id) = staged_log();
        let result = try_insert_row(&log, push_request_id, &shape_for_state(*name));
        assert!(
            result.is_ok(),
            "schema rejected state {:?} ({}): {result:?}",
            name,
            name.as_wire(),
        );
    }
}

/// Every `outcome` value the Rust enum can produce is one the schema
/// admits.
#[test]
fn every_outcome_wire_name_is_accepted_by_the_schema() {
    for name in ApproveAttemptOutcomeName::ALL {
        let (log, push_request_id) = staged_log();
        let result = try_insert_row(&log, push_request_id, &shape_for_outcome(*name));
        assert!(
            result.is_ok(),
            "schema rejected outcome {:?} ({}): {result:?}",
            name,
            name.as_wire(),
        );
    }
}

proptest! {
    /// The CHECK is *enforced*, not merely declared: a row naming a state
    /// outside the enum is refused at INSERT. The probe row is the
    /// `started` shape (all terminal columns NULL), which satisfies every
    /// cross-column CHECK for any value of `state` — so the refusal is
    /// attributable to the `state IN (…)` enum CHECK alone.
    ///
    /// This is the runtime companion to
    /// `rust_and_schema_admit_the_same_state_names`, which is what
    /// actually pins the two vocabularies to each other; a random string
    /// will essentially never collide with a name the schema has gained,
    /// so this test alone could not detect a schema-only addition.
    #[test]
    fn schema_rejects_state_values_outside_the_enum(raw in "[a-z_]{1,16}") {
        prop_assume!(ApproveAttemptStateName::parse_wire(&raw).is_none());
        let (log, push_request_id) = staged_log();
        let shape = RowShape {
            state: raw.clone(),
            outcome: None,
            completed_at: None,
            new_app_tip: None,
            failure_detail: None,
            mint: false,
        };
        let result = try_insert_row(&log, push_request_id, &shape);
        prop_assert!(
            result.is_err(),
            "schema accepted unknown state {raw:?}, which the Rust enum cannot represent",
        );
    }

    /// Same for the `outcome` column. The probe is a bare `resolved` row:
    /// `completed_at` set, and *no* `new_app_tip`, `failure_detail`, or
    /// mint. That shape clears every cross-column CHECK for an outcome
    /// outside the enum — each of those CHECKs has the form
    /// `coalesce(outcome, '') <predicate> = (<column> IS NOT NULL)`, and
    /// an unknown outcome makes both sides false. An earlier draft set
    /// `failure_detail`, which made the RHS true while the LHS stayed
    /// false, so the row was refused by the *shape* CHECK and the test
    /// proved nothing about the enum CHECK.
    #[test]
    fn schema_rejects_outcome_values_outside_the_enum(raw in "[a-z_]{1,16}") {
        prop_assume!(ApproveAttemptOutcomeName::parse_wire(&raw).is_none());
        let (log, push_request_id) = staged_log();
        let shape = RowShape {
            state: ApproveAttemptStateName::Resolved.as_wire().into(),
            outcome: Some(raw.clone()),
            completed_at: Some(1_700_000_300),
            new_app_tip: None,
            failure_detail: None,
            mint: false,
        };
        let result = try_insert_row(&log, push_request_id, &shape);
        prop_assert!(
            result.is_err(),
            "schema accepted unknown outcome {raw:?}, which the Rust enum cannot represent",
        );
    }
}

/// The literals a `CHECK (<column> IN (…))` clause admits, read out of the
/// *live* schema (`sqlite_master` holds the CREATE TABLE text the
/// migrations actually ran). Reading the DDL is what makes the agreement
/// test bidirectional: the Rust side can be enumerated with `ALL`, and
/// this enumerates the SQL side, so set equality catches an addition,
/// removal, or rename on *either* side.
fn schema_enum_literals(log: &AuditLog, needle: &str) -> Vec<String> {
    let ddl: String = log
        .with_conn(|c| {
            c.query_row(
                "SELECT sql FROM sqlite_master
                  WHERE type = 'table' AND name = 'git_push_approve_attempt'",
                [],
                |row| row.get(0),
            )
            .map_err(crate::AuditError::from)
        })
        .unwrap();
    assert_eq!(
        ddl.matches(needle).count(),
        1,
        "{needle:?} must appear exactly once in the DDL for this extraction to be \
         unambiguous; the schema changed shape and this test needs revisiting",
    );
    let start = ddl.find(needle).unwrap() + needle.len();
    let end = start
        + ddl[start..]
            .find(')')
            .expect("the IN (…) list must be closed");
    ddl[start..end]
        .split(',')
        .map(|literal| literal.trim().trim_matches('\'').to_string())
        .collect()
}

fn sorted<T: Ord>(mut items: Vec<T>) -> Vec<T> {
    items.sort();
    items
}

/// The Rust enum and the `state` CHECK admit exactly the same strings.
///
/// This is the load-bearing agreement test. Both sides are enumerated —
/// `ALL` on the Rust side, the CHECK's literal list on the SQL side — so
/// a name added, removed, or renamed on either side fails here. In
/// particular a *schema-only* addition (the case a random-string probe
/// cannot realistically find) shows up as an extra literal.
#[test]
fn rust_and_schema_admit_the_same_state_names() {
    let (log, _) = staged_log();
    let from_rust = sorted(
        ApproveAttemptStateName::ALL
            .iter()
            .map(|n| n.as_wire().to_string())
            .collect(),
    );
    let from_schema = sorted(schema_enum_literals(&log, "state IN ("));
    assert_eq!(
        from_rust, from_schema,
        "ApproveAttemptStateName and the state CHECK constraint disagree",
    );
}

/// The same for the `outcome` column. The needle matches the column's own
/// `outcome IS NULL OR outcome IN (…)` CHECK; the cross-column CHECKs
/// spell it `coalesce(outcome, '') IN (…)`, which does not contain the
/// needle — and `schema_enum_literals` asserts the single match anyway.
#[test]
fn rust_and_schema_admit_the_same_outcome_names() {
    let (log, _) = staged_log();
    let from_rust = sorted(
        ApproveAttemptOutcomeName::ALL
            .iter()
            .map(|n| n.as_wire().to_string())
            .collect(),
    );
    let from_schema = sorted(schema_enum_literals(&log, "outcome IN ("));
    assert_eq!(
        from_rust, from_schema,
        "ApproveAttemptOutcomeName and the outcome CHECK constraint disagree",
    );
}

/// The data-carrying DUs report the discriminant their row stores.
#[test]
fn state_and_outcome_report_their_names() {
    let mint = sample_promote_mint_audit();
    assert_eq!(
        GitPushApproveAttemptState::Started.name(),
        ApproveAttemptStateName::Started
    );
    assert_eq!(GitPushApproveAttemptState::Started.outcome_name(), None);
    assert_eq!(
        GitPushApproveAttemptState::Uncertain { mint }.name(),
        ApproveAttemptStateName::Uncertain
    );
    let resolved = GitPushApproveAttemptState::Resolved {
        outcome: GitPushApproveAttemptOutcome::Succeeded {
            new_app_tip: git_oid('3'),
        },
        mint: Some(mint),
        completed_at: writ_core::core::UnixMillis::from_millis(1_700_000_300),
    };
    assert_eq!(resolved.name(), ApproveAttemptStateName::Resolved);
    assert_eq!(
        resolved.outcome_name(),
        Some(ApproveAttemptOutcomeName::Succeeded)
    );
    assert_eq!(
        GitPushApproveAttemptOutcome::PrePatchFailure { detail: "x".into() }.name(),
        ApproveAttemptOutcomeName::PrePatchFailure
    );
    assert_eq!(
        GitPushApproveAttemptOutcome::PostPatchFailure { detail: "x".into() }.name(),
        ApproveAttemptOutcomeName::PostPatchFailure
    );
}

// ---------------------------------------------------------------------
// The transition relation, checked against the schema
// ---------------------------------------------------------------------

/// The mutable columns of an attempt row. Both the seeding INSERT and the
/// probing UPDATE below go through this, so a "what would a hand-written
/// DAO emit for this step?" row can be built without consulting
/// [`apply`] — which is the whole point: the probe must be naive, or it
/// would be testing the machine against itself.
#[derive(Clone, Debug)]
struct AttemptColumns {
    state: ApproveAttemptStateName,
    outcome: Option<ApproveAttemptOutcomeName>,
    completed_at: Option<i64>,
    new_app_tip: Option<String>,
    failure_detail: Option<String>,
    mint: Option<PromoteMintAudit>,
}

/// The columns a state is stored as. Mirrors the DAO's
/// `write_attempt_state`; kept separate here so the test does not inherit
/// a bug from it.
fn columns_of(state: &GitPushApproveAttemptState) -> AttemptColumns {
    let (new_app_tip, failure_detail) = match state {
        GitPushApproveAttemptState::Started | GitPushApproveAttemptState::Uncertain { .. } => {
            (None, None)
        }
        GitPushApproveAttemptState::Resolved { outcome, .. } => match outcome {
            GitPushApproveAttemptOutcome::Succeeded { new_app_tip } => {
                (Some(new_app_tip.as_str().to_string()), None)
            }
            GitPushApproveAttemptOutcome::PrePatchFailure { detail }
            | GitPushApproveAttemptOutcome::PostPatchFailure { detail } => {
                (None, Some(detail.clone()))
            }
        },
    };
    AttemptColumns {
        state: state.name(),
        outcome: state.outcome_name(),
        completed_at: match state {
            GitPushApproveAttemptState::Resolved { completed_at, .. } => {
                Some(completed_at.as_millis())
            }
            _ => None,
        },
        new_app_tip,
        failure_detail,
        mint: match state {
            GitPushApproveAttemptState::Started => None,
            GitPushApproveAttemptState::Uncertain { mint } => Some(*mint),
            GitPushApproveAttemptState::Resolved { mint, .. } => *mint,
        },
    }
}

/// The row a *naive* writer would produce for `transition` applied to
/// `from` — one that writes the columns the step implies without asking
/// whether the step is *legal*. That distinction is the point: the probe
/// knows what a step records, the schema's triggers judge whether it may.
///
/// "What a step records" includes the mint a resolve carries, which for a
/// `Started` attempt comes from the ledger — a writer that skipped it
/// would be refused by `resolve_carries_ledger_mint` on a step that is
/// perfectly legal, and the oracle would be measuring the probe's
/// forgetfulness rather than the transition relation.
fn naive_columns(from: &ApproveAttempt, transition: &ApproveAttemptTransition) -> AttemptColumns {
    let carried = columns_of(&from.state).mint.or(from.ledger_mint);
    let base = AttemptColumns {
        state: ApproveAttemptStateName::Resolved,
        outcome: None,
        completed_at: Some(COMPLETED_AT),
        new_app_tip: None,
        failure_detail: None,
        mint: carried,
    };
    match transition {
        ApproveAttemptTransition::MarkUncertain { mint } => AttemptColumns {
            state: ApproveAttemptStateName::Uncertain,
            outcome: None,
            completed_at: None,
            mint: Some(*mint),
            ..base
        },
        ApproveAttemptTransition::ResolveSucceeded { new_app_tip, .. } => AttemptColumns {
            outcome: Some(ApproveAttemptOutcomeName::Succeeded),
            new_app_tip: Some(new_app_tip.as_str().to_string()),
            ..base
        },
        ApproveAttemptTransition::ResolvePrePatchFailure { detail, .. } => AttemptColumns {
            outcome: Some(ApproveAttemptOutcomeName::PrePatchFailure),
            failure_detail: Some(detail.clone()),
            ..base
        },
        // `RecordMint` writes the ledger table, not this row;
        // `schema_accepts_transition` dispatches before reaching here.
        ApproveAttemptTransition::RecordMint { .. } => base,
        ApproveAttemptTransition::CapturePrePatchFailure { detail, mint, .. } => AttemptColumns {
            outcome: Some(ApproveAttemptOutcomeName::PrePatchFailure),
            failure_detail: Some(detail.clone()),
            mint: Some(*mint),
            ..base
        },
        ApproveAttemptTransition::ResolvePostPatchFailure { detail, .. } => AttemptColumns {
            outcome: Some(ApproveAttemptOutcomeName::PostPatchFailure),
            failure_detail: Some(detail.clone()),
            ..base
        },
    }
}

/// Seed an attempt into `attempt`'s position by a *legal* path.
///
/// Not a single INSERT: the ledger trigger
/// `mint_ledger_requires_started` only admits a ledger row while the
/// attempt is `started`, so a position that combines a ledger mint with a
/// later state has to be built the way production builds it — insert
/// `started`, write the ledger row, then step forward. That the seeding
/// itself succeeds is a small bonus check that every position in the grid
/// is actually reachable.
fn seed_attempt(
    log: &AuditLog,
    push_request_id: RequestId,
    attempt_id: ApproveAttemptId,
    attempt: &ApproveAttempt,
) {
    let started = columns_of(&GitPushApproveAttemptState::Started);
    log.with_conn_mut(|c| {
        c.execute(
            "INSERT INTO git_push_approve_attempt (
                 attempt_id, push_request_id, operator, started_at,
                 state, outcome, completed_at, new_app_tip, failure_detail,
                 mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
             ) VALUES (?1, ?2, 'alice', 1700000200,
                       ?3, NULL, NULL, NULL, NULL,
                       NULL, NULL, NULL, NULL)",
            params![
                attempt_id.as_uuid().to_string(),
                push_request_id.as_uuid().to_string(),
                started.state.as_wire(),
            ],
        )
        .map(|_| ())
        .map_err(crate::AuditError::from)
    })
    .expect("seeding a started row must succeed");

    if let Some(mint) = attempt.ledger_mint {
        log.with_conn_mut(|c| {
            c.execute(
                "INSERT INTO git_push_approve_attempt_mint (
                     attempt_id, mint_jti, mint_github_app_id,
                     mint_issued_at, mint_expires_at, recorded_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 1700000210)",
                params![
                    attempt_id.as_uuid().to_string(),
                    mint.jti.as_uuid().to_string(),
                    mint.github_app_id as i64,
                    mint.issued_at.as_millis(),
                    mint.expires_at.as_millis(),
                ],
            )
            .map(|_| ())
            .map_err(crate::AuditError::from)
        })
        .expect("seeding a ledger row must succeed");
    }

    // Walk to the target position one legal step at a time.
    for step in path_to(&attempt.state) {
        assert!(
            schema_accepts(log, attempt_id, &columns_of(&step)),
            "seeding step to {:?} was refused by the schema",
            step.name(),
        );
    }
}

/// The intermediate states a legal path to `target` passes through,
/// `target` last. `Resolved(Succeeded)` and `Resolved(PostPatchFailure)`
/// are only reachable via `Uncertain`, which is the machine's own rule.
fn path_to(target: &GitPushApproveAttemptState) -> Vec<GitPushApproveAttemptState> {
    match target {
        GitPushApproveAttemptState::Started => vec![],
        GitPushApproveAttemptState::Uncertain { .. } => vec![target.clone()],
        GitPushApproveAttemptState::Resolved { outcome, mint, .. } => match outcome {
            // Reachable directly from `started`.
            GitPushApproveAttemptOutcome::PrePatchFailure { .. } => vec![target.clone()],
            GitPushApproveAttemptOutcome::Succeeded { .. }
            | GitPushApproveAttemptOutcome::PostPatchFailure { .. } => vec![
                GitPushApproveAttemptState::Uncertain {
                    mint: mint.expect("these outcomes always carry a mint"),
                },
                target.clone(),
            ],
        },
    }
}

/// Issue the naive write for a transition and report whether the schema
/// accepted it. `RecordMint` writes the ledger table; everything else
/// updates the attempt row.
fn schema_accepts_transition(
    log: &AuditLog,
    attempt_id: ApproveAttemptId,
    attempt: &ApproveAttempt,
    transition: &ApproveAttemptTransition,
) -> bool {
    if let ApproveAttemptTransition::RecordMint { mint } = transition {
        return log
            .with_conn_mut(|c| {
                c.execute(
                    "INSERT INTO git_push_approve_attempt_mint (
                         attempt_id, mint_jti, mint_github_app_id,
                         mint_issued_at, mint_expires_at, recorded_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 1700000220)",
                    params![
                        attempt_id.as_uuid().to_string(),
                        mint.jti.as_uuid().to_string(),
                        mint.github_app_id as i64,
                        mint.issued_at.as_millis(),
                        mint.expires_at.as_millis(),
                    ],
                )
                .map(|_| ())
                .map_err(crate::AuditError::from)
            })
            .is_ok();
    }
    schema_accepts(log, attempt_id, &naive_columns(attempt, transition))
}

/// Issue the naive UPDATE of the attempt row and report whether the
/// schema accepted it.
fn schema_accepts(log: &AuditLog, attempt_id: ApproveAttemptId, cols: &AttemptColumns) -> bool {
    log.with_conn_mut(|c| {
        c.execute(
            "UPDATE git_push_approve_attempt
                SET state = ?2,
                    outcome = ?3,
                    completed_at = ?4,
                    new_app_tip = ?5,
                    failure_detail = ?6,
                    mint_jti = ?7,
                    mint_github_app_id = ?8,
                    mint_issued_at = ?9,
                    mint_expires_at = ?10
              WHERE attempt_id = ?1",
            params![
                attempt_id.as_uuid().to_string(),
                cols.state.as_wire(),
                cols.outcome.map(|o| o.as_wire()),
                cols.completed_at,
                cols.new_app_tip,
                cols.failure_detail,
                cols.mint.map(|m| m.jti.as_uuid().to_string()),
                cols.mint.map(|m| m.github_app_id as i64),
                cols.mint.map(|m| m.issued_at.as_millis()),
                cols.mint.map(|m| m.expires_at.as_millis()),
            ],
        )
        .map(|_| ())
        .map_err(crate::AuditError::from)
    })
    .is_ok()
}

const COMPLETED_AT: i64 = 1_700_000_400;

/// Two *deterministic* credentials. The jti must be stable across calls:
/// the grid seeds a row with `mint_a()` and then offers transitions
/// carrying `mint_a()`, and "the same mint" has to actually be the same
/// one or the mint-immutability trigger fires and the pair stops testing
/// what it claims to. (`sample_promote_mint_audit` mints a fresh random
/// jti per call, which is right for the DAO tests and wrong here.)
fn mint_a() -> PromoteMintAudit {
    PromoteMintAudit {
        jti: writ_core::core::Jti::from_uuid(uuid::Uuid::from_u128(0xA11CE)),
        github_app_id: 42,
        issued_at: writ_core::core::UnixMillis::from_millis(1_700_000_190),
        expires_at: writ_core::core::UnixMillis::from_millis(1_700_000_490),
    }
}

/// A second, definitely-different credential — the "caller holds a mint
/// the row does not know about" case that the mint-immutability and
/// ledger-agreement triggers exist to refuse.
fn mint_b() -> PromoteMintAudit {
    PromoteMintAudit {
        jti: writ_core::core::Jti::from_uuid(uuid::Uuid::from_u128(0xB0B)),
        github_app_id: 43,
        ..mint_a()
    }
}

/// Every row state an attempt can be in, labelled for failure messages.
fn every_state() -> Vec<(&'static str, GitPushApproveAttemptState)> {
    let completed_at = writ_core::core::UnixMillis::from_millis(1_700_000_300);
    vec![
        ("started", GitPushApproveAttemptState::Started),
        (
            "uncertain",
            GitPushApproveAttemptState::Uncertain { mint: mint_a() },
        ),
        (
            "resolved/succeeded",
            GitPushApproveAttemptState::Resolved {
                outcome: GitPushApproveAttemptOutcome::Succeeded {
                    new_app_tip: git_oid('3'),
                },
                mint: Some(mint_a()),
                completed_at,
            },
        ),
        (
            "resolved/pre_patch_failure",
            GitPushApproveAttemptState::Resolved {
                outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                    detail: "walker refused".into(),
                },
                mint: None,
                completed_at,
            },
        ),
        (
            "resolved/pre_patch_failure+mint",
            GitPushApproveAttemptState::Resolved {
                outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                    detail: "walker refused".into(),
                },
                mint: Some(mint_a()),
                completed_at,
            },
        ),
        (
            "resolved/post_patch_failure",
            GitPushApproveAttemptState::Resolved {
                outcome: GitPushApproveAttemptOutcome::PostPatchFailure {
                    detail: "transport drop".into(),
                },
                mint: Some(mint_a()),
                completed_at,
            },
        ),
    ]
}

/// Every *position*: a row state crossed with whether the attempt has a
/// v7 ledger row. The ledger is part of the machine's state — two schema
/// triggers judge writes against it — so the grid has to sweep it, and
/// the reviewer who spotted that it did not was right.
///
/// Combinations the schema cannot represent are dropped rather than
/// papered over: a resolved row with a NULL mint alongside a ledger row
/// is refused by `resolve_carries_ledger_mint`, so it can never exist.
fn every_position() -> Vec<(String, ApproveAttempt)> {
    let mut out = Vec::new();
    for (state_label, state) in every_state() {
        out.push((state_label.to_string(), ApproveAttempt::new(state.clone())));

        let carries_no_mint = matches!(
            &state,
            GitPushApproveAttemptState::Resolved { mint: None, .. }
        );
        if carries_no_mint {
            continue;
        }
        out.push((
            format!("{state_label}+ledger"),
            ApproveAttempt {
                state,
                ledger_mint: Some(mint_a()),
            },
        ));
    }
    out
}

/// Every transition, including the mint variants that exercise the
/// immutability and ledger-agreement halves of the machine.
fn every_transition() -> Vec<(&'static str, ApproveAttemptTransition)> {
    let completed_at = writ_core::core::UnixMillis::from_millis(COMPLETED_AT);
    vec![
        (
            "record-mint/same",
            ApproveAttemptTransition::RecordMint { mint: mint_a() },
        ),
        (
            "record-mint/other",
            ApproveAttemptTransition::RecordMint { mint: mint_b() },
        ),
        (
            "mark-uncertain/same-mint",
            ApproveAttemptTransition::MarkUncertain { mint: mint_a() },
        ),
        (
            "mark-uncertain/other-mint",
            ApproveAttemptTransition::MarkUncertain { mint: mint_b() },
        ),
        (
            "resolve-succeeded",
            ApproveAttemptTransition::ResolveSucceeded {
                new_app_tip: git_oid('4'),
                completed_at,
            },
        ),
        (
            "resolve-pre-patch",
            ApproveAttemptTransition::ResolvePrePatchFailure {
                detail: "refused".into(),
                completed_at,
            },
        ),
        (
            "capture-pre-patch/other-mint",
            ApproveAttemptTransition::CapturePrePatchFailure {
                detail: "refused".into(),
                mint: mint_b(),
                completed_at,
            },
        ),
        (
            "capture-pre-patch/same-mint",
            ApproveAttemptTransition::CapturePrePatchFailure {
                detail: "refused".into(),
                mint: mint_a(),
                completed_at,
            },
        ),
        (
            "resolve-post-patch",
            ApproveAttemptTransition::ResolvePostPatchFailure {
                detail: "github 500".into(),
                completed_at,
            },
        ),
    ]
}

/// (position, transition) pairs where the Rust machine is deliberately
/// *stricter* than the schema, with the reason. Enumerated rather than
/// waved at, so that a new divergence — in either direction — fails the
/// oracle below instead of being absorbed silently.
fn deliberate_asymmetries() -> Vec<(&'static str, &'static str)> {
    vec![
        // `capture-pre-patch` means "resolve while recording a mint the
        // ledger may not know". From `uncertain` the row already carries
        // its mint, so the caller must use the plain resolve; the schema
        // has no way to express that caller-knowledge precondition and
        // would accept the write when the mint happens to match.
        // `capture_from_uncertain_is_stricter_than_the_schema` pins it.
        ("uncertain", "capture-pre-patch/same-mint"),
        ("uncertain+ledger", "capture-pre-patch/same-mint"),
    ]
}

/// **The oracle.** For every (position, transition) pair, the Rust
/// machine and the schema's triggers must agree on whether the move is
/// legal.
///
/// The Rust side is [`apply`]; the SQL side is the naive write that step
/// would perform, judged by the `forward_only`, `mint_immutable`,
/// `mint_matches_ledger`, `resolve_carries_ledger_mint`, and
/// `mint_ledger_requires_started` machinery. Because the probe is built
/// by `naive_columns` — which never consults `apply` — this is a genuine
/// comparison of two encodings rather than a tautology.
///
/// This is what makes the duplication safe: the triggers stay as the
/// unkillable backstop, and a change to either half that the other does
/// not follow fails here.
#[test]
fn transition_agrees_with_the_schema() {
    let asymmetries = deliberate_asymmetries();
    let mut checked = 0usize;
    for (position_label, attempt) in every_position() {
        for (transition_label, transition) in every_transition() {
            if asymmetries
                .iter()
                .any(|(p, t)| *p == position_label && *t == transition_label)
            {
                continue;
            }
            let (log, push_request_id) = staged_log();
            let attempt_id = ApproveAttemptId::new();
            seed_attempt(&log, push_request_id, attempt_id, &attempt);

            let rust_allows = apply(&attempt, &transition).is_ok();
            let schema_allows = schema_accepts_transition(&log, attempt_id, &attempt, &transition);

            assert_eq!(
                rust_allows, schema_allows,
                "machine and schema disagree on {transition_label} from {position_label}: \
                 rust_allows={rust_allows} schema_allows={schema_allows}",
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked,
        every_position().len() * every_transition().len() - asymmetries.len(),
        "every pair but the enumerated asymmetries must be checked",
    );
}

/// The deliberate asymmetry, stated outright: from `uncertain`, a
/// capturing resolve is refused by the machine even when the mint matches
/// and the schema would therefore accept the write. The DAO's contract is
/// that an `uncertain` attempt resolves through the plain path, which
/// carries the row's own mint forward.
#[test]
fn capture_from_uncertain_is_stricter_than_the_schema() {
    let attempt = ApproveAttempt::new(GitPushApproveAttemptState::Uncertain { mint: mint_a() });
    let transition = ApproveAttemptTransition::CapturePrePatchFailure {
        detail: "refused".into(),
        mint: mint_a(),
        completed_at: writ_core::core::UnixMillis::from_millis(COMPLETED_AT),
    };

    let refusal = apply(&attempt, &transition).unwrap_err();
    assert_eq!(refusal.from, ApproveAttemptStateName::Uncertain);
    assert_eq!(refusal.transition, "capture-pre-patch-failure");

    // …and the schema really would have taken it, which is why the
    // machine has to be the one saying no.
    let (log, push_request_id) = staged_log();
    let attempt_id = ApproveAttemptId::new();
    seed_attempt(&log, push_request_id, attempt_id, &attempt);
    assert!(schema_accepts_transition(
        &log,
        attempt_id,
        &attempt,
        &transition
    ));
}

/// A `Started` attempt that has already minted may not adopt a different
/// credential — the case the first draft of this machine got wrong,
/// because it could not see the ledger at all.
#[test]
fn a_minted_attempt_refuses_a_second_credential() {
    let attempt = ApproveAttempt {
        state: GitPushApproveAttemptState::Started,
        ledger_mint: Some(mint_a()),
    };
    for transition in [
        ApproveAttemptTransition::MarkUncertain { mint: mint_b() },
        ApproveAttemptTransition::CapturePrePatchFailure {
            detail: "refused".into(),
            mint: mint_b(),
            completed_at: writ_core::core::UnixMillis::from_millis(COMPLETED_AT),
        },
        ApproveAttemptTransition::RecordMint { mint: mint_b() },
    ] {
        let label = transition.label();
        assert!(
            apply(&attempt, &transition).is_err(),
            "{label} was allowed to replace a recorded credential",
        );
    }
}

/// A resolve from `Started` carries the ledger mint onto the row without
/// being told to — the rule `resolve_carries_ledger_mint` enforces, made
/// impossible to forget at a call site.
#[test]
fn resolving_a_minted_started_attempt_carries_the_ledger_mint() {
    let attempt = ApproveAttempt {
        state: GitPushApproveAttemptState::Started,
        ledger_mint: Some(mint_a()),
    };
    let next = apply(
        &attempt,
        &ApproveAttemptTransition::ResolvePrePatchFailure {
            detail: "walker refused".into(),
            completed_at: writ_core::core::UnixMillis::from_millis(COMPLETED_AT),
        },
    )
    .unwrap();
    assert_eq!(columns_of(&next.state).mint, Some(mint_a()));
    assert_eq!(next.ledger_mint, Some(mint_a()));
}

/// `apply` never invents a state that contradicts the transition it was
/// given: a resolve produces `Resolved` with that outcome, and
/// `mark-uncertain` produces `Uncertain` with the mint it was handed.
#[test]
fn apply_produces_the_state_the_transition_names() {
    for (_, attempt) in every_position() {
        for (_, transition) in every_transition() {
            let Ok(next) = apply(&attempt, &transition) else {
                continue;
            };
            let next = next.state;
            match &transition {
                ApproveAttemptTransition::RecordMint { .. } => {
                    assert_eq!(next, GitPushApproveAttemptState::Started);
                }
                ApproveAttemptTransition::MarkUncertain { mint } => {
                    assert_eq!(next, GitPushApproveAttemptState::Uncertain { mint: *mint });
                }
                ApproveAttemptTransition::ResolveSucceeded { .. } => {
                    assert_eq!(
                        next.outcome_name(),
                        Some(ApproveAttemptOutcomeName::Succeeded)
                    );
                }
                ApproveAttemptTransition::ResolvePrePatchFailure { .. }
                | ApproveAttemptTransition::CapturePrePatchFailure { .. } => {
                    assert_eq!(
                        next.outcome_name(),
                        Some(ApproveAttemptOutcomeName::PrePatchFailure)
                    );
                }
                ApproveAttemptTransition::ResolvePostPatchFailure { .. } => {
                    assert_eq!(
                        next.outcome_name(),
                        Some(ApproveAttemptOutcomeName::PostPatchFailure)
                    );
                }
            }
        }
    }
}

/// A mint, once recorded on the row, survives every legal transition
/// unchanged — the audit log's "this approval used credential X" promise,
/// asserted against the machine rather than against the trigger that
/// backs it up.
#[test]
fn legal_transitions_never_rewrite_a_recorded_mint() {
    for (position_label, attempt) in every_position() {
        let before = columns_of(&attempt.state).mint.or(attempt.ledger_mint);
        let Some(before) = before else { continue };
        for (transition_label, transition) in every_transition() {
            let Ok(next) = apply(&attempt, &transition) else {
                continue;
            };
            assert_eq!(
                columns_of(&next.state).mint,
                Some(before),
                "{transition_label} from {position_label} rewrote the recorded mint",
            );
        }
    }
}

// ---------------------------------------------------------------------
// The derived predicates, checked against the schema
// ---------------------------------------------------------------------

/// Positions enumerate exactly the (state, outcome) shapes the schema's
/// `(state = 'resolved') = (outcome IS NOT NULL)` CHECK admits.
#[test]
fn positions_enumerate_the_legal_column_shapes() {
    let positions = AttemptPosition::all();
    assert_eq!(
        positions.len(),
        5,
        "2 non-terminal + 3 outcomes: {positions:?}"
    );
    for position in &positions {
        assert_eq!(
            position.outcome.is_some(),
            position.state == ApproveAttemptStateName::Resolved,
            "{position:?} has an outcome iff it is resolved",
        );
    }
    // And every state a row can actually hold maps into the set.
    for (_, state) in every_state() {
        assert!(
            positions.contains(&state.position()),
            "{:?} is not an enumerated position",
            state.position(),
        );
    }
}

/// **The generated SQL selects exactly what the Rust predicate selects.**
///
/// This is what lets the two queries that used to spell out
/// "started|uncertain|resolved+post_patch" in SQL derive their clause from
/// `blocks_resolution` instead: seed one row per position, run the
/// generated clause against it, and compare with the predicate.
#[test]
fn sql_predicate_selects_what_rust_selects() {
    for predicate in [
        (
            "blocks_resolution",
            AttemptPosition::blocks_resolution as fn(AttemptPosition) -> bool,
        ),
        ("is_in_flight", AttemptPosition::is_in_flight),
        ("is_reconcilable", AttemptPosition::is_reconcilable),
    ] {
        let (label, rust_predicate) = predicate;
        let selected: Vec<_> = AttemptPosition::all()
            .into_iter()
            .filter(|p| rust_predicate(*p))
            .collect();
        let (clause, params) = position_predicate_sql(&selected, "state", "outcome", 2);

        for position in AttemptPosition::all() {
            let (log, push_request_id) = staged_log();
            let attempt_id = ApproveAttemptId::new();
            seed_attempt(
                &log,
                push_request_id,
                attempt_id,
                &ApproveAttempt::new(state_at(position)),
            );

            let matched: Option<i64> = log
                .with_conn(|c| {
                    c.query_row(
                        &format!(
                            "SELECT 1 FROM git_push_approve_attempt
                              WHERE attempt_id = ?1 AND {clause}"
                        ),
                        rusqlite::params_from_iter(
                            std::iter::once(attempt_id.as_uuid().to_string())
                                .chain(params.iter().map(|p| p.to_string())),
                        ),
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(crate::AuditError::from)
                })
                .unwrap();

            assert_eq!(
                matched.is_some(),
                rust_predicate(position),
                "{label}: SQL and Rust disagree about {position:?}",
            );
        }
    }
}

/// A representative state for a position, so the sweep above can seed a
/// real row for each one.
fn state_at(position: AttemptPosition) -> GitPushApproveAttemptState {
    let completed_at = writ_core::core::UnixMillis::from_millis(1_700_000_300);
    match (position.state, position.outcome) {
        (ApproveAttemptStateName::Started, _) => GitPushApproveAttemptState::Started,
        (ApproveAttemptStateName::Uncertain, _) => {
            GitPushApproveAttemptState::Uncertain { mint: mint_a() }
        }
        (ApproveAttemptStateName::Resolved, Some(outcome)) => {
            GitPushApproveAttemptState::Resolved {
                outcome: match outcome {
                    ApproveAttemptOutcomeName::Succeeded => {
                        GitPushApproveAttemptOutcome::Succeeded {
                            new_app_tip: git_oid('3'),
                        }
                    }
                    ApproveAttemptOutcomeName::PrePatchFailure => {
                        GitPushApproveAttemptOutcome::PrePatchFailure {
                            detail: "walker refused".into(),
                        }
                    }
                    ApproveAttemptOutcomeName::PostPatchFailure => {
                        GitPushApproveAttemptOutcome::PostPatchFailure {
                            detail: "transport drop".into(),
                        }
                    }
                },
                mint: Some(mint_a()),
                completed_at,
            }
        }
        (ApproveAttemptStateName::Resolved, None) => {
            unreachable!("a resolved position always names an outcome")
        }
    }
}

/// **`blocks_resolution` agrees with the trigger that enforces it.**
///
/// `git_push_resolution_refuses_active_approve` is the schema's version of
/// this predicate. Seed one attempt per position, try to write a
/// resolution row, and require the refusal to match the Rust answer.
#[test]
fn blocks_resolution_agrees_with_the_trigger() {
    for position in AttemptPosition::all() {
        let (log, push_request_id) = staged_log();
        let attempt_id = ApproveAttemptId::new();
        seed_attempt(
            &log,
            push_request_id,
            attempt_id,
            &ApproveAttempt::new(state_at(position)),
        );

        let accepted = log
            .with_conn_mut(|c| {
                c.execute(
                    "INSERT INTO git_push_resolution (
                         push_request_id, decided_at, decision, operator, reason,
                         mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                     ) VALUES (?1, 1700000500, 'rejected', 'alice', 'no thanks',
                               NULL, NULL, NULL, NULL)",
                    params![push_request_id.as_uuid().to_string()],
                )
                .map(|_| ())
                .map_err(crate::AuditError::from)
            })
            .is_ok();

        assert_eq!(
            !accepted,
            position.blocks_resolution(),
            "trigger and blocks_resolution disagree about {position:?}",
        );
    }
}

/// The relationship between the two predicates, stated rather than left
/// to be rediscovered: rejecting is blocked by everything that blocks a
/// resolution, *plus* an attempt that already succeeded — which does not
/// block the resolution row because the approve path writes one itself.
#[test]
fn reject_blocker_extends_blocks_resolution_by_success() {
    for position in AttemptPosition::all() {
        let already_approved = position.outcome == Some(ApproveAttemptOutcomeName::Succeeded);
        assert_eq!(
            position.reject_blocker().is_some(),
            position.blocks_resolution() || already_approved,
            "{position:?}",
        );
    }
}

/// An empty position set would render `IN ()`, which SQLite rejects; the
/// builder refuses rather than emitting a query that fails at runtime.
#[test]
#[should_panic(expected = "empty position set")]
fn empty_position_set_is_refused() {
    position_predicate_sql(&[], "state", "outcome", 1);
}
