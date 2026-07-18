//! Example-based tests for the push-request / outcome DAOs: recording
//! a request against an open/closed session, the staged-outcome
//! lifecycle, the `get_git_push` views before and after an outcome
//! lands, and the `correlation_id` CHECK constraint.

use super::test_support::*;
use super::*;
use proptest::prelude::*;

/// Raw request-table rows (every column, in insert order) for the guard/direct
/// equivalence proptest — the git-push analogue of `proxy_table`'s
/// `dump_request_rows`.
#[allow(clippy::type_complexity)]
fn dump_git_push_request_rows(
    log: &AuditLog,
) -> Vec<(
    String,
    String,
    i64,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
)> {
    log.with_conn(|c| {
        let mut stmt = c.prepare(
            "SELECT push_request_id, session_id, received_at, repo, branch, \
             expected_remote_head, new_head, correlation_id \
             FROM git_push_request ORDER BY rowid",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .unwrap()
}

#[allow(clippy::type_complexity)]
fn dump_git_push_outcome_rows(log: &AuditLog) -> Vec<(String, i64, String, Option<i64>, String)> {
    log.with_conn(|c| {
        let mut stmt = c.prepare(
            "SELECT push_request_id, completed_at, result, github_status, message \
             FROM git_push_outcome ORDER BY rowid",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .unwrap()
}

#[test]
fn git_push_request_requires_open_session_but_outcome_can_land_after_close() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    let push_request_id = RequestId::new();
    let request = sample_git_push_request_record(push_request_id, s.session_id);

    let missing = log.record_git_push_request(&request).unwrap_err();
    assert!(
        matches!(missing, AuditError::Invariant("session does not exist")),
        "got: {missing:?}"
    );

    log.open_session(&s).unwrap();
    log.record_git_push_request(&request).unwrap();
    log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_125))
        .unwrap();

    let closed_request = sample_git_push_request_record(RequestId::new(), s.session_id);
    let closed = log.record_git_push_request(&closed_request).unwrap_err();
    assert!(
        matches!(closed, AuditError::Invariant("session is closed")),
        "got: {closed:?}"
    );

    log.record_git_push_outcome(&GitPushOutcomeRecord {
        push_request_id,
        completed_at: UnixMillis::from_millis(1_700_000_130),
        result: GitPushOutcomeResult::ValidationFailed,
        github_status: None,
        message: "remote head moved",
    })
    .unwrap();
}

#[test]
fn git_push_outcome_without_request_is_rejected() {
    let log = AuditLog::open_in_memory().unwrap();
    let err = log
        .record_git_push_outcome(&GitPushOutcomeRecord {
            push_request_id: RequestId::new(),
            completed_at: UnixMillis::from_millis(1),
            result: GitPushOutcomeResult::Denied,
            github_status: None,
            message: "policy denied",
        })
        .unwrap_err();
    let AuditError::Sqlite(e) = err else {
        panic!("expected sqlite FK error, got: {err:?}");
    };
    assert!(
        e.to_string().to_lowercase().contains("foreign key"),
        "expected FK violation, got: {e}"
    );
}

#[test]
fn get_git_push_returns_none_when_request_missing() {
    let log = AuditLog::open_in_memory().unwrap();
    assert!(log.get_git_push(RequestId::new()).unwrap().is_none());
}

#[test]
fn get_git_push_returns_request_only_view_before_outcome() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    log.record_git_push_request(&sample_git_push_request_record(
        push_request_id,
        s.session_id,
    ))
    .unwrap();

    let entry = log.get_git_push(push_request_id).unwrap().unwrap();
    assert_eq!(entry.push_request_id, push_request_id);
    assert_eq!(entry.session_id, s.session_id);
    assert_eq!(entry.result, None);
    assert_eq!(entry.completed_at, None);
    assert_eq!(entry.resolution, None);
}

#[test]
fn get_git_push_returns_full_view_after_outcome() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    log.record_git_push_request(&sample_git_push_request_record(
        push_request_id,
        s.session_id,
    ))
    .unwrap();
    log.record_git_push_outcome(&GitPushOutcomeRecord {
        push_request_id,
        completed_at: UnixMillis::from_millis(1_700_000_130),
        result: GitPushOutcomeResult::Staged,
        github_status: None,
        message: "queued for review",
    })
    .unwrap();

    let entry = log.get_git_push(push_request_id).unwrap().unwrap();
    assert_eq!(entry.result, Some(GitPushOutcomeResult::Staged));
    assert_eq!(
        entry.completed_at,
        Some(UnixMillis::from_millis(1_700_000_130))
    );
    assert_eq!(entry.message.as_deref(), Some("queued for review"));
}

/// `result` strings written into the DB must match the strings the
/// `Serialize` impl produces. A future serde rename here would orphan
/// existing audit rows on disk; pin both representations together.
#[test]
fn outcome_result_sql_strings_match_serde_form() {
    let variants = [
        GitPushOutcomeResult::Denied,
        GitPushOutcomeResult::ValidationFailed,
        GitPushOutcomeResult::Staged,
    ];
    for v in variants {
        let json = serde_json::to_value(v).unwrap();
        assert_eq!(json, serde_json::Value::String(v.as_str().to_string()));
        let back: GitPushOutcomeResult = serde_json::from_value(json).unwrap();
        assert_eq!(back, v);
    }
}

#[test]
fn git_push_request_roundtrips_with_correlation_id() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    let correlation = CorrelationId::try_new("feat-abc_123").unwrap();
    let record = GitPushRequestRecord {
        correlation_id: Some(correlation.clone()),
        ..sample_git_push_request_record(push_request_id, s.session_id)
    };
    log.record_git_push_request(&record).unwrap();

    let entry = log.get_git_push(push_request_id).unwrap().unwrap();
    assert_eq!(entry.correlation_id, Some(correlation));
}

/// The CHECK constraint on `git_push_request.correlation_id` is the
/// belt-and-braces line of defence behind `CorrelationId::try_new`.
#[test]
fn git_push_request_correlation_id_check_constraint_rejects_invalid_bytes() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    let err = log
        .with_conn_mut(|c| {
            c.execute(
                "INSERT INTO git_push_request (
                         push_request_id, session_id, received_at, repo,
                         branch, expected_remote_head, new_head, correlation_id
                     ) VALUES (?1, ?2, 1, 'o/n', 'main', NULL, ?3, ?4)",
                params![
                    push_request_id.as_uuid().to_string(),
                    s.session_id.as_uuid().to_string(),
                    "a".repeat(40),
                    "bad/slash",
                ],
            )
            .map_err(AuditError::from)
        })
        .unwrap_err();
    assert!(err.to_string().contains("CHECK"), "got: {err:?}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The generic guard's two-phase path (`begin_effect` + `complete`) must be
    /// behaviour-preserving for the git-push base pair: it leaves both tables
    /// byte-for-byte identical to the direct `record_git_push_request` +
    /// `record_git_push_outcome`. The flake/proxy analogue; this is the
    /// equivalence the VM-HTTP driver relies on to adopt the guard for the base
    /// staging pair (a later stage) without changing a single persisted row.
    #[test]
    fn begin_then_complete_matches_the_direct_git_push_writers(
        result_pick in 0u8..3,
        github_status in proptest::option::of(100u16..=599),
        message in "[\\x01-\\x7e]{1,120}",
        has_expected_head in any::<bool>(),
        has_correlation in any::<bool>(),
    ) {
        let direct = AuditLog::open_in_memory().unwrap();
        let guarded = std::sync::Arc::new(AuditLog::open_in_memory().unwrap());
        let s = sample_session();
        direct.open_session(&s).unwrap();
        guarded.open_session(&s).unwrap();

        let push_request_id = RequestId::new();
        // Vary the NULL-able columns (expected_remote_head, correlation_id) across
        // present/absent; the fixed sample supplies the structured newtype fields
        // (repo/branch/oids) whose own parsing is exercised elsewhere.
        let request = GitPushRequestRecord {
            expected_remote_head: has_expected_head.then(|| git_oid('1')),
            correlation_id: has_correlation
                .then(|| CorrelationId::try_new("feat-42_xyz").unwrap()),
            ..sample_git_push_request_record(push_request_id, s.session_id)
        };
        let result = match result_pick {
            0 => GitPushOutcomeResult::Denied,
            1 => GitPushOutcomeResult::ValidationFailed,
            _ => GitPushOutcomeResult::Staged,
        };
        let outcome = GitPushOutcomeRecord {
            push_request_id,
            completed_at: UnixMillis::from_millis(1_700_000_130),
            result,
            github_status,
            message: &message,
        };

        direct.record_git_push_request(&request).unwrap();
        direct.record_git_push_outcome(&outcome).unwrap();
        guarded
            .begin_effect::<super::dao::GitPushAuditTable>(&request)
            .unwrap()
            .complete(&outcome)
            .unwrap();

        prop_assert_eq!(
            dump_git_push_request_rows(&direct),
            dump_git_push_request_rows(&guarded)
        );
        prop_assert_eq!(
            dump_git_push_outcome_rows(&direct),
            dump_git_push_outcome_rows(&guarded)
        );
    }
}
