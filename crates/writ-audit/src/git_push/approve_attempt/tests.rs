//! Tests for the approve-attempt wire-name codec.
//!
//! The interesting ones are the *schema-agreement* sweeps. The Rust enums
//! and the CHECK constraints in migration 0003 are two encodings of one
//! discriminant set; these tests make SQLite the oracle for the Rust
//! side, so a name added, renamed, or removed on one side and not the
//! other fails here rather than at runtime against a real audit log.

use proptest::prelude::*;
use rusqlite::params;

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
