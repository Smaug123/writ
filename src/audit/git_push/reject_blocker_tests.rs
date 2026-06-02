//! Example-based tests for the reject-blocker queries:
//! `approve_attempts_for_push` ordering, `reject_blocker_for_push`, and
//! `list_blocking_approve_attempts`.

use super::test_support::*;
use super::*;
#[test]
fn approve_attempts_for_push_returns_in_started_at_order() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let first = ApproveAttemptId::new();
    let second = ApproveAttemptId::new();
    let third = ApproveAttemptId::new();
    log.start_approve_attempt(
        second,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_220),
    )
    .unwrap();
    log.complete_attempt_pre_patch_failure(
        second,
        "first failure",
        UnixMillis::from_millis(1_700_000_221),
    )
    .unwrap();
    log.start_approve_attempt(
        first,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_210),
    )
    .unwrap();
    log.complete_attempt_pre_patch_failure(
        first,
        "earlier",
        UnixMillis::from_millis(1_700_000_211),
    )
    .unwrap();
    log.start_approve_attempt(
        third,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_230),
    )
    .unwrap();

    let ids: Vec<ApproveAttemptId> = log
        .approve_attempts_for_push(push_request_id)
        .unwrap()
        .into_iter()
        .map(|a| a.attempt_id)
        .collect();
    assert_eq!(ids, vec![first, second, third]);
}

#[test]
fn reject_blocker_for_push_returns_none_when_no_attempts() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);

    assert_eq!(log.reject_blocker_for_push(push_request_id).unwrap(), None);
}

#[test]
fn reject_blocker_for_push_ignores_pre_patch_failure_only() {
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
        "nope",
        UnixMillis::from_millis(1_700_000_210),
    )
    .unwrap();

    assert_eq!(log.reject_blocker_for_push(push_request_id).unwrap(), None);
}

#[test]
fn reject_blocker_for_push_flags_started_attempt() {
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

    assert_eq!(
        log.reject_blocker_for_push(push_request_id).unwrap(),
        Some(RejectBlocker::AttemptInFlight { attempt_id })
    );
}

#[test]
fn reject_blocker_for_push_flags_uncertain_attempt() {
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

    assert_eq!(
        log.reject_blocker_for_push(push_request_id).unwrap(),
        Some(RejectBlocker::AttemptInFlight { attempt_id })
    );
}

#[test]
fn reject_blocker_for_push_flags_already_approved() {
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
    log.complete_attempt_succeeded(
        attempt_id,
        &git_oid('a'),
        "alice",
        "looks good",
        UnixMillis::from_millis(1_700_000_220),
    )
    .unwrap();

    assert_eq!(
        log.reject_blocker_for_push(push_request_id).unwrap(),
        Some(RejectBlocker::AlreadyApproved { attempt_id })
    );
}

#[test]
fn reject_blocker_for_push_flags_post_patch_uncertain() {
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
    log.complete_attempt_post_patch_failure(
        attempt_id,
        "transport drop",
        UnixMillis::from_millis(1_700_000_220),
    )
    .unwrap();

    assert_eq!(
        log.reject_blocker_for_push(push_request_id).unwrap(),
        Some(RejectBlocker::PostPatchUncertain { attempt_id })
    );
}

#[test]
fn list_blocking_approve_attempts_is_empty_when_no_rows() {
    let log = AuditLog::open_in_memory().unwrap();
    assert!(log.list_blocking_approve_attempts().unwrap().is_empty());
}

#[test]
fn list_blocking_approve_attempts_returns_started_rows() {
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

    let blocking = log.list_blocking_approve_attempts().unwrap();
    assert_eq!(blocking.len(), 1);
    assert_eq!(blocking[0].attempt_id, attempt_id);
    assert_eq!(blocking[0].state, GitPushApproveAttemptState::Started);
}

#[test]
fn list_blocking_approve_attempts_returns_uncertain_rows() {
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

    let blocking = log.list_blocking_approve_attempts().unwrap();
    assert_eq!(blocking.len(), 1);
    assert_eq!(blocking[0].attempt_id, attempt_id);
    assert!(matches!(
        blocking[0].state,
        GitPushApproveAttemptState::Uncertain { .. }
    ));
}

#[test]
fn list_blocking_approve_attempts_excludes_resolved_rows() {
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
        "walker rejected",
        UnixMillis::from_millis(1_700_000_210),
    )
    .unwrap();

    assert!(log.list_blocking_approve_attempts().unwrap().is_empty());
}

/// Multiple non-terminal rows across different pushes must all
/// surface, ordered by `started_at` then `attempt_id`. The boot
/// reconcile worker relies on this ordering so that operator-facing
/// log lines remain stable across binary versions.
#[test]
fn list_blocking_approve_attempts_orders_by_started_at_then_id() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_a = RequestId::new();
    let push_b = RequestId::new();
    record_staged_request(&log, push_a, s.session_id);
    record_staged_request(&log, push_b, s.session_id);

    let older = ApproveAttemptId::new();
    let newer = ApproveAttemptId::new();
    log.start_approve_attempt(
        older,
        push_a,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();
    log.start_approve_attempt(
        newer,
        push_b,
        "alice",
        UnixMillis::from_millis(1_700_000_300),
    )
    .unwrap();

    let blocking = log.list_blocking_approve_attempts().unwrap();
    assert_eq!(blocking.len(), 2);
    assert_eq!(blocking[0].attempt_id, older);
    assert_eq!(blocking[1].attempt_id, newer);
}
