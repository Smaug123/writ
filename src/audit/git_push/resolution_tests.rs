//! Example-based tests for `record_git_push_resolution`: the
//! approve/reject round-trip through `get_git_push`, the mint-column
//! triggers, and the guards that refuse a resolution while an approve
//! attempt is mid-flight.

use super::test_support::*;
use super::*;
#[test]
fn record_resolution_roundtrips_rejected_via_get_git_push() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    record_staged_request(&log, push_request_id, s.session_id);

    log.record_git_push_resolution(&GitPushResolutionRecord {
        push_request_id,
        decided_at: UnixMillis::from_millis(1_700_000_200),
        decision: GitPushResolution::Rejected,
        operator: "alice",
        reason: "leaks credentials",
    })
    .unwrap();

    let entry = log.get_git_push(push_request_id).unwrap().unwrap();
    assert_eq!(
        entry.resolution,
        Some(GitPushResolutionEntry {
            decided_at: UnixMillis::from_millis(1_700_000_200),
            decision: GitPushResolution::Rejected,
            operator: "alice".into(),
            reason: "leaks credentials".into(),
        })
    );

    let entries = log.list_git_pushes_for_session(s.session_id).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].resolution, entry.resolution);
}

#[test]
fn record_resolution_roundtrips_approved_with_mint_payload() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    record_staged_request(&log, push_request_id, s.session_id);
    let mint = sample_promote_mint_audit();

    log.record_git_push_resolution(&GitPushResolutionRecord {
        push_request_id,
        decided_at: UnixMillis::from_millis(1_700_000_200),
        decision: GitPushResolution::Approved(mint),
        operator: "alice",
        reason: "looks good",
    })
    .unwrap();

    let entry = log.get_git_push(push_request_id).unwrap().unwrap();
    assert_eq!(
        entry.resolution.unwrap().decision,
        GitPushResolution::Approved(mint)
    );
}

#[test]
fn record_resolution_rejected_persists_null_mint_columns() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    record_staged_request(&log, push_request_id, s.session_id);

    log.record_git_push_resolution(&GitPushResolutionRecord {
        push_request_id,
        decided_at: UnixMillis::from_millis(1_700_000_200),
        decision: GitPushResolution::Rejected,
        operator: "alice",
        reason: "leaks credentials",
    })
    .unwrap();

    let (jti, app_id, issued_at, expires_at): (
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    ) = log
        .with_conn(|c| {
            Ok(c.query_row(
                "SELECT mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at \
                     FROM git_push_resolution WHERE push_request_id = ?1",
                params![push_request_id.as_uuid().to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?)
        })
        .unwrap();
    assert_eq!(
        (jti, app_id, issued_at, expires_at),
        (None, None, None, None)
    );
}

#[test]
fn direct_insert_approved_without_mint_columns_is_rejected_by_trigger() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    record_staged_request(&log, push_request_id, s.session_id);

    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "INSERT INTO git_push_resolution (
                         push_request_id, decided_at, decision, operator, reason,
                         mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                     ) VALUES (?1, ?2, 'approved', 'alice', 'looks good',
                               NULL, NULL, NULL, NULL)",
                params![push_request_id.as_uuid().to_string(), 1_700_000_200_i64,],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string().contains("mint context must match decision"),
        "unexpected error: {err}"
    );
}

#[test]
fn direct_insert_rejected_with_mint_columns_is_rejected_by_trigger() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    record_staged_request(&log, push_request_id, s.session_id);
    let mint = sample_promote_mint_audit();

    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "INSERT INTO git_push_resolution (
                         push_request_id, decided_at, decision, operator, reason,
                         mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                     ) VALUES (?1, ?2, 'rejected', 'alice', 'no',
                               ?3, ?4, ?5, ?6)",
                params![
                    push_request_id.as_uuid().to_string(),
                    1_700_000_200_i64,
                    mint.jti.as_uuid().to_string(),
                    mint.github_app_id as i64,
                    mint.issued_at.as_millis(),
                    mint.expires_at.as_millis(),
                ],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string().contains("mint context must match decision"),
        "unexpected error: {err}"
    );
}

#[test]
fn record_resolution_rejects_when_outcome_not_staged() {
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
        result: GitPushOutcomeResult::Denied,
        github_status: None,
        message: "policy denied",
    })
    .unwrap();

    let err = log
        .record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id,
            decided_at: UnixMillis::from_millis(1_700_000_200),
            decision: GitPushResolution::Rejected,
            operator: "alice",
            reason: "too late",
        })
        .unwrap_err();
    let AuditError::Sqlite(e) = err else {
        panic!("expected sqlite trigger error, got: {err:?}");
    };
    assert!(
        e.to_string()
            .contains("git push must be staged to be resolved"),
        "unexpected error: {e}"
    );
}

#[test]
fn record_resolution_rejects_when_no_outcome() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    log.record_git_push_request(&sample_git_push_request_record(
        push_request_id,
        s.session_id,
    ))
    .unwrap();

    let err = log
        .record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id,
            decided_at: UnixMillis::from_millis(1_700_000_200),
            decision: GitPushResolution::Rejected,
            operator: "alice",
            reason: "no outcome yet",
        })
        .unwrap_err();
    let AuditError::Sqlite(e) = err else {
        panic!("expected sqlite trigger error, got: {err:?}");
    };
    assert!(
        e.to_string()
            .contains("git push must be staged to be resolved"),
        "unexpected error: {e}"
    );
}

#[test]
fn record_resolution_rejects_double_resolution() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    record_staged_request(&log, push_request_id, s.session_id);

    log.record_git_push_resolution(&GitPushResolutionRecord {
        push_request_id,
        decided_at: UnixMillis::from_millis(1_700_000_200),
        decision: GitPushResolution::Rejected,
        operator: "alice",
        reason: "first time",
    })
    .unwrap();

    let err = log
        .record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id,
            decided_at: UnixMillis::from_millis(1_700_000_210),
            decision: GitPushResolution::Rejected,
            operator: "bob",
            reason: "second time",
        })
        .unwrap_err();
    let AuditError::Sqlite(e) = err else {
        panic!("expected sqlite PK error, got: {err:?}");
    };
    assert!(
        e.to_string().to_lowercase().contains("unique")
            || e.to_string().to_lowercase().contains("primary key"),
        "expected PK violation, got: {e}"
    );
}

#[test]
fn record_resolution_rejects_empty_operator() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    record_staged_request(&log, push_request_id, s.session_id);

    let err = log
        .record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id,
            decided_at: UnixMillis::from_millis(1_700_000_200),
            decision: GitPushResolution::Rejected,
            operator: "",
            reason: "needs operator",
        })
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("git push resolution operator must not be empty")
        ),
        "got: {err:?}"
    );
}

#[test]
fn record_resolution_rejects_empty_reason() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    record_staged_request(&log, push_request_id, s.session_id);

    let err = log
        .record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id,
            decided_at: UnixMillis::from_millis(1_700_000_200),
            decision: GitPushResolution::Rejected,
            operator: "alice",
            reason: "",
        })
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("git push resolution reason must not be empty")
        ),
        "got: {err:?}"
    );
}

#[test]
fn resolution_decision_sql_strings_match_variant_kind() {
    assert_eq!(GitPushResolution::Rejected.kind_str(), "rejected");
    assert_eq!(
        GitPushResolution::Approved(sample_promote_mint_audit()).kind_str(),
        "approved"
    );
}

/// A `Started` approve attempt means the approve workflow is in
/// flight; allowing a reject row to commit would race the approve's
/// PATCH and leave the audit log claiming rejection of a push that
/// may already have been approved on GitHub.
#[test]
fn record_resolution_refused_when_attempt_started() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    log.start_approve_attempt(
        ApproveAttemptId::new(),
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();

    let err = log
        .record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id,
            decided_at: UnixMillis::from_millis(1_700_000_300),
            decision: GitPushResolution::Rejected,
            operator: "bob",
            reason: "too late",
        })
        .unwrap_err();
    let AuditError::Sqlite(e) = err else {
        panic!("expected sqlite trigger error, got: {err:?}");
    };
    assert!(
        e.to_string()
            .contains("approve attempt is in-flight or quarantined"),
        "unexpected error: {e}"
    );
}

/// An `Uncertain` attempt has promised the audit log that the PATCH
/// may have hit GitHub; reject must be refused at the schema layer.
#[test]
fn record_resolution_refused_when_attempt_uncertain() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let attempt_id = ApproveAttemptId::new();
    log.start_approve_attempt(
        attempt_id,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();
    log.mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
        .unwrap();

    let err = log
        .record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id,
            decided_at: UnixMillis::from_millis(1_700_000_300),
            decision: GitPushResolution::Rejected,
            operator: "bob",
            reason: "too late",
        })
        .unwrap_err();
    let AuditError::Sqlite(e) = err else {
        panic!("expected sqlite trigger error, got: {err:?}");
    };
    assert!(
        e.to_string()
            .contains("approve attempt is in-flight or quarantined"),
        "unexpected error: {e}"
    );
}

/// A `Resolved(PostPatchFailure)` attempt quarantines the push:
/// reject must be refused until manual reconciliation completes the
/// attempt to either `Succeeded` or `PrePatchFailure`.
#[test]
fn record_resolution_refused_when_attempt_post_patch_failure() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let attempt_id = ApproveAttemptId::new();
    log.start_approve_attempt(
        attempt_id,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();
    log.mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
        .unwrap();
    log.complete_attempt_post_patch_failure(
        attempt_id,
        "transport drop after PATCH",
        UnixMillis::from_millis(1_700_000_250),
    )
    .unwrap();

    let err = log
        .record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id,
            decided_at: UnixMillis::from_millis(1_700_000_300),
            decision: GitPushResolution::Rejected,
            operator: "bob",
            reason: "give up",
        })
        .unwrap_err();
    let AuditError::Sqlite(e) = err else {
        panic!("expected sqlite trigger error, got: {err:?}");
    };
    assert!(
        e.to_string()
            .contains("approve attempt is in-flight or quarantined"),
        "unexpected error: {e}"
    );
}

/// A `Resolved(PrePatchFailure)` attempt proves the PATCH was never
/// issued (mint failed, walker refused before TX2, etc.); the push
/// remains rejectable.
#[test]
fn record_resolution_allowed_after_pre_patch_failure() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let attempt_id = ApproveAttemptId::new();
    log.start_approve_attempt(
        attempt_id,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();
    log.complete_attempt_pre_patch_failure(
        attempt_id,
        "mint failed",
        UnixMillis::from_millis(1_700_000_210),
    )
    .unwrap();

    log.record_git_push_resolution(&GitPushResolutionRecord {
        push_request_id,
        decided_at: UnixMillis::from_millis(1_700_000_300),
        decision: GitPushResolution::Rejected,
        operator: "bob",
        reason: "operator chose to abandon",
    })
    .unwrap();

    let entry = log.get_git_push(push_request_id).unwrap().unwrap();
    let resolution = entry.resolution.expect("resolution must be present");
    assert_eq!(resolution.decision, GitPushResolution::Rejected);
    assert_eq!(resolution.operator, "bob");
}

/// Approve's own joint-TX completion must not be blocked by its own
/// in-flight attempt row. `complete_attempt_succeeded` flips the
/// attempt to `resolved`/`succeeded` *before* the resolution INSERT
/// runs (same TX), so by the time the trigger fires the row is no
/// longer in a blocking state.
#[test]
fn record_resolution_allowed_during_complete_attempt_succeeded() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let attempt_id = ApproveAttemptId::new();
    log.start_approve_attempt(
        attempt_id,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();
    let mint = sample_promote_mint_audit();
    log.mark_attempt_uncertain(attempt_id, mint).unwrap();
    let new_app_tip = git_oid('a');
    log.complete_attempt_succeeded(
        attempt_id,
        &new_app_tip,
        "alice",
        "ship it",
        UnixMillis::from_millis(1_700_000_220),
    )
    .unwrap();

    let entry = log.get_git_push(push_request_id).unwrap().unwrap();
    let resolution = entry.resolution.expect("resolution must be present");
    assert_eq!(resolution.decision, GitPushResolution::Approved(mint));
}
