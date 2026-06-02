//! Example-based tests for the approve-attempt state machine: the
//! start / mark-uncertain / complete transitions, the forward-only and
//! mint-immutability triggers, and the per-state CHECK constraints.

use super::test_support::*;
use super::*;
#[test]
fn start_approve_attempt_requires_staged_outcome() {
    let log = AuditLog::open_in_memory().unwrap();
    let s = sample_session();
    log.open_session(&s).unwrap();
    let push_request_id = RequestId::new();
    log.record_git_push_request(&sample_git_push_request_record(
        push_request_id,
        s.session_id,
    ))
    .unwrap();
    // No outcome row yet — start_approve_attempt must refuse.

    let err = log
        .start_approve_attempt(
            ApproveAttemptId::new(),
            push_request_id,
            "alice",
            UnixMillis::from_millis(1_700_000_200),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("approve attempt requires staged outcome")
        ),
        "got: {err:?}"
    );

    // A `Denied` outcome (not `Staged`) is also insufficient.
    log.record_git_push_outcome(&GitPushOutcomeRecord {
        push_request_id,
        completed_at: UnixMillis::from_millis(1_700_000_130),
        result: GitPushOutcomeResult::Denied,
        github_status: None,
        message: "policy denied",
    })
    .unwrap();
    let err = log
        .start_approve_attempt(
            ApproveAttemptId::new(),
            push_request_id,
            "alice",
            UnixMillis::from_millis(1_700_000_201),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("approve attempt requires staged outcome")
        ),
        "got: {err:?}"
    );
}

#[test]
fn start_approve_attempt_rejects_empty_operator() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);

    let err = log
        .start_approve_attempt(
            ApproveAttemptId::new(),
            push_request_id,
            "",
            UnixMillis::from_millis(1_700_000_200),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("approve attempt operator must not be empty")
        ),
        "got: {err:?}"
    );
}

#[test]
fn start_approve_attempt_roundtrips_as_started_state() {
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

    let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
    assert_eq!(attempts.len(), 1);
    let attempt = &attempts[0];
    assert_eq!(attempt.attempt_id, attempt_id);
    assert_eq!(attempt.push_request_id, push_request_id);
    assert_eq!(attempt.operator, "alice");
    assert_eq!(attempt.started_at, UnixMillis::from_millis(1_700_000_200));
    assert_eq!(attempt.state, GitPushApproveAttemptState::Started);
}

/// A push with an existing rejected resolution must not accept a
/// new approve attempt. If it did, the eventual joint-TX completion
/// would fail at the resolution PRIMARY KEY conflict, but only
/// after `update_ref` may have advanced GitHub — exactly the
/// "audit row contradicts observable state" hole the state machine
/// is meant to close.
#[test]
fn start_approve_attempt_refused_when_already_resolved() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    log.record_git_push_resolution(&GitPushResolutionRecord {
        push_request_id,
        decided_at: UnixMillis::from_millis(1_700_000_150),
        decision: GitPushResolution::Rejected,
        operator: "alice",
        reason: "not now",
    })
    .unwrap();

    let err = log
        .start_approve_attempt(
            ApproveAttemptId::new(),
            push_request_id,
            "bob",
            UnixMillis::from_millis(1_700_000_200),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("approve attempt refused: push already has a resolution")
        ),
        "got: {err:?}"
    );
}

/// A second attempt while the first is still `Started` would race
/// the first attempt's PATCH if it advances to `update_ref`. Refuse
/// at the DAO so the state machine has one attempt in flight at a
/// time.
#[test]
fn start_approve_attempt_refused_when_prior_started() {
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
        .start_approve_attempt(
            ApproveAttemptId::new(),
            push_request_id,
            "bob",
            UnixMillis::from_millis(1_700_000_300),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant(
                "approve attempt refused: prior attempt is in-flight or quarantined"
            )
        ),
        "got: {err:?}"
    );
}

/// A second attempt while the first is `Uncertain` would issue a
/// fresh PATCH against a branch the first attempt's PATCH may
/// already have advanced. Refuse.
#[test]
fn start_approve_attempt_refused_when_prior_uncertain() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let first = ApproveAttemptId::new();
    log.start_approve_attempt(
        first,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();
    log.mark_attempt_uncertain(first, sample_promote_mint_audit())
        .unwrap();

    let err = log
        .start_approve_attempt(
            ApproveAttemptId::new(),
            push_request_id,
            "bob",
            UnixMillis::from_millis(1_700_000_300),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant(
                "approve attempt refused: prior attempt is in-flight or quarantined"
            )
        ),
        "got: {err:?}"
    );
}

/// A second attempt after a quarantined `PostPatchFailure` would
/// contradict the quarantine: that prior attempt's GitHub state is
/// unknown, and a new attempt could either succeed redundantly
/// (PATCH was honoured) or advance from a wrong base (PATCH was
/// not). Manual reconciliation must complete the quarantined
/// attempt before a fresh start is permitted.
#[test]
fn start_approve_attempt_refused_when_prior_post_patch_failure() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let first = ApproveAttemptId::new();
    log.start_approve_attempt(
        first,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();
    log.mark_attempt_uncertain(first, sample_promote_mint_audit())
        .unwrap();
    log.complete_attempt_post_patch_failure(
        first,
        "transport drop after PATCH",
        UnixMillis::from_millis(1_700_000_250),
    )
    .unwrap();

    let err = log
        .start_approve_attempt(
            ApproveAttemptId::new(),
            push_request_id,
            "bob",
            UnixMillis::from_millis(1_700_000_300),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant(
                "approve attempt refused: prior attempt is in-flight or quarantined"
            )
        ),
        "got: {err:?}"
    );
}

/// `pre_patch_failure` proves the PATCH was never issued, so a
/// fresh attempt is safe and admitted. This is the only retry path
/// before slice C's reconciliation tooling.
#[test]
fn start_approve_attempt_allowed_after_pre_patch_failure() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let first = ApproveAttemptId::new();
    log.start_approve_attempt(
        first,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();
    log.complete_attempt_pre_patch_failure(
        first,
        "mint failed",
        UnixMillis::from_millis(1_700_000_210),
    )
    .unwrap();

    let second = ApproveAttemptId::new();
    log.start_approve_attempt(
        second,
        push_request_id,
        "bob",
        UnixMillis::from_millis(1_700_000_300),
    )
    .unwrap();
    let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
    assert_eq!(attempts.len(), 2);
}

#[test]
fn mark_attempt_uncertain_succeeds_from_started() {
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

    let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
    assert_eq!(
        attempts[0].state,
        GitPushApproveAttemptState::Uncertain { mint }
    );
}

#[test]
fn mark_attempt_uncertain_rejects_already_uncertain() {
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

    // Second attempt to mark uncertain must surface an invariant.
    let err = log.mark_attempt_uncertain(attempt_id, mint).unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("approve attempt is not in 'started' state")
        ),
        "got: {err:?}"
    );
}

#[test]
fn complete_attempt_succeeded_writes_resolution_in_same_tx() {
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
        "looks good",
        UnixMillis::from_millis(1_700_000_220),
    )
    .unwrap();

    let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
    assert_eq!(
        attempts[0].state,
        GitPushApproveAttemptState::Resolved {
            outcome: GitPushApproveAttemptOutcome::Succeeded {
                new_app_tip: new_app_tip.clone(),
            },
            mint: Some(mint),
            completed_at: UnixMillis::from_millis(1_700_000_220),
        }
    );

    let entry = log.get_git_push(push_request_id).unwrap().unwrap();
    let resolution = entry.resolution.expect("resolution must be present");
    assert_eq!(resolution.decision, GitPushResolution::Approved(mint));
    assert_eq!(resolution.operator, "alice");
    assert_eq!(resolution.reason, "looks good");
    assert_eq!(
        resolution.decided_at,
        UnixMillis::from_millis(1_700_000_220)
    );
}

#[test]
fn complete_attempt_succeeded_rejects_when_not_uncertain() {
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

    // Still 'started' — succeeded is illegal from this state.
    let err = log
        .complete_attempt_succeeded(
            attempt_id,
            &git_oid('a'),
            "alice",
            "looks good",
            UnixMillis::from_millis(1_700_000_220),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("approve attempt is not in 'uncertain' state")
        ),
        "got: {err:?}"
    );
}

#[test]
fn complete_attempt_pre_patch_failure_from_started() {
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

    let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
    assert_eq!(
        attempts[0].state,
        GitPushApproveAttemptState::Resolved {
            outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                detail: "mint failed".into(),
            },
            mint: None,
            completed_at: UnixMillis::from_millis(1_700_000_210),
        }
    );
    // No git_push_resolution row was written.
    assert!(
        log.get_git_push(push_request_id)
            .unwrap()
            .unwrap()
            .resolution
            .is_none()
    );
}

#[test]
fn complete_attempt_pre_patch_failure_from_uncertain_preserves_mint() {
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
    log.complete_attempt_pre_patch_failure(
        attempt_id,
        "patch send aborted",
        UnixMillis::from_millis(1_700_000_220),
    )
    .unwrap();

    let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
    assert_eq!(
        attempts[0].state,
        GitPushApproveAttemptState::Resolved {
            outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                detail: "patch send aborted".into(),
            },
            mint: Some(mint),
            completed_at: UnixMillis::from_millis(1_700_000_220),
        }
    );
}

/// The "mint succeeded, walker failed before TX2" path from the
/// design doc. State transitions started → resolved(pre_patch_failure)
/// in a single UPDATE that also captures the mint that was minted
/// but never used. The audit row records the burned credential
/// even though no PATCH was issued.
#[test]
fn complete_attempt_pre_patch_failure_capturing_mint_from_started() {
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

    log.complete_attempt_pre_patch_failure_capturing_mint(
        attempt_id,
        mint,
        "walker refused non-fast-forward",
        UnixMillis::from_millis(1_700_000_215),
    )
    .unwrap();

    let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
    assert_eq!(
        attempts[0].state,
        GitPushApproveAttemptState::Resolved {
            outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                detail: "walker refused non-fast-forward".into(),
            },
            mint: Some(mint),
            completed_at: UnixMillis::from_millis(1_700_000_215),
        }
    );
    // No git_push_resolution row was written — only an approved
    // outcome writes one, and the resolution row is what reject
    // would later contradict.
    assert!(
        log.get_git_push(push_request_id)
            .unwrap()
            .unwrap()
            .resolution
            .is_none()
    );
}

/// Refuses from `Uncertain`: that row already carries its mint via
/// `mark_attempt_uncertain`, and the column-level immutability
/// trigger would block writing a different one. Callers in this
/// state must use the plain `complete_attempt_pre_patch_failure`.
#[test]
fn complete_attempt_pre_patch_failure_capturing_mint_refuses_uncertain() {
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

    let err = log
        .complete_attempt_pre_patch_failure_capturing_mint(
            attempt_id,
            mint,
            "should not be admitted",
            UnixMillis::from_millis(1_700_000_220),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant(
                "approve attempt: capturing-mint pre_patch_failure requires 'started' state"
            )
        ),
        "got: {err:?}"
    );
}

#[test]
fn complete_attempt_post_patch_failure_only_from_uncertain() {
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
    // From 'started' must fail.
    let err = log
        .complete_attempt_post_patch_failure(
            attempt_id,
            "boom",
            UnixMillis::from_millis(1_700_000_210),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant(
                "approve attempt is not in a state that admits this failure outcome"
            )
        ),
        "got: {err:?}"
    );

    // After mark_uncertain it must succeed.
    let mint = sample_promote_mint_audit();
    log.mark_attempt_uncertain(attempt_id, mint).unwrap();
    log.complete_attempt_post_patch_failure(
        attempt_id,
        "transport drop",
        UnixMillis::from_millis(1_700_000_220),
    )
    .unwrap();
    let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
    assert_eq!(
        attempts[0].state,
        GitPushApproveAttemptState::Resolved {
            outcome: GitPushApproveAttemptOutcome::PostPatchFailure {
                detail: "transport drop".into(),
            },
            mint: Some(mint),
            completed_at: UnixMillis::from_millis(1_700_000_220),
        }
    );
}

#[test]
fn complete_attempt_failure_rejects_empty_detail() {
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
    let err = log
        .complete_attempt_pre_patch_failure(attempt_id, "", UnixMillis::from_millis(1_700_000_210))
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("approve attempt failure detail must not be empty")
        ),
        "got: {err:?}"
    );
}

/// The `git_push_approve_attempt_forward_only` trigger refuses any
/// transition that isn't one of the three legal arrows.
#[test]
fn forward_only_trigger_blocks_reverting_resolved_to_started() {
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
        "no go",
        UnixMillis::from_millis(1_700_000_210),
    )
    .unwrap();

    // Try to UPDATE the row back to 'started' by raw SQL — trigger
    // must abort.
    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "UPDATE git_push_approve_attempt
                        SET state = 'started',
                            outcome = NULL,
                            completed_at = NULL,
                            failure_detail = NULL
                      WHERE attempt_id = ?1",
                params![attempt_id.as_uuid().to_string()],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("illegal git_push_approve_attempt state transition"),
        "unexpected error: {err}"
    );
}

/// The forward-only trigger also blocks `started → resolved(succeeded)`
/// jumping past the mandatory uncertain step.
#[test]
fn forward_only_trigger_blocks_started_to_succeeded() {
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

    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "UPDATE git_push_approve_attempt
                        SET state = 'resolved',
                            outcome = 'succeeded',
                            new_app_tip = ?2,
                            completed_at = ?3
                      WHERE attempt_id = ?1",
                params![
                    attempt_id.as_uuid().to_string(),
                    git_oid('a').as_str(),
                    1_700_000_210_i64,
                ],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("illegal git_push_approve_attempt state transition"),
        "unexpected error: {err}"
    );
}

/// `git_push_approve_attempt_mint_immutable` refuses any UPDATE that
/// changes a mint column once it has been written.
#[test]
fn mint_immutable_trigger_rejects_changed_mint_jti() {
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

    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "UPDATE git_push_approve_attempt
                        SET mint_jti = ?2
                      WHERE attempt_id = ?1",
                params![
                    attempt_id.as_uuid().to_string(),
                    Jti::new().as_uuid().to_string(),
                ],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("git_push_approve_attempt mint context is immutable once set"),
        "unexpected error: {err}"
    );
}

/// SQLite returns NULL from `outcome = 'succeeded'` when outcome is
/// NULL, and a CHECK that evaluates to NULL passes. Without the
/// `coalesce` wrapper a `started` row could be written with a
/// non-NULL `new_app_tip` and survive the schema, then trip the
/// `from_row` parser later. Direct INSERT here so we exercise the
/// CHECK itself rather than the DAO methods that already forbid the
/// shape via their query builders.
#[test]
fn check_constraint_rejects_started_row_with_new_app_tip() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let attempt_id = ApproveAttemptId::new();
    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "INSERT INTO git_push_approve_attempt
                        (attempt_id, push_request_id, operator, started_at,
                         state, new_app_tip)
                     VALUES (?1, ?2, 'alice', 1700000000,
                             'started', '0123456789abcdef0123456789abcdef01234567')",
                params![
                    attempt_id.as_uuid().to_string(),
                    push_request_id.as_uuid().to_string(),
                ],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("check"),
        "unexpected error: {err}"
    );
}

/// Parallel to the new_app_tip case: a non-NULL `failure_detail` on
/// a `started` row would slip past the schema if the cross-column
/// CHECK were not NULL-safe, because `outcome IN (...)` returns
/// NULL when outcome is NULL.
#[test]
fn check_constraint_rejects_started_row_with_failure_detail() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let attempt_id = ApproveAttemptId::new();
    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "INSERT INTO git_push_approve_attempt
                        (attempt_id, push_request_id, operator, started_at,
                         state, failure_detail)
                     VALUES (?1, ?2, 'alice', 1700000000,
                             'started', 'nope')",
                params![
                    attempt_id.as_uuid().to_string(),
                    push_request_id.as_uuid().to_string(),
                ],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("check"),
        "unexpected error: {err}"
    );
}

/// A `started` row with mint columns set is contradictory: mint
/// context is captured at the `started → uncertain` transition, so
/// `started` must have NULL mint. The schema CHECK refuses the
/// shape directly so manual SQL or a future migration cannot
/// produce it.
#[test]
fn check_constraint_rejects_started_row_with_mint() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let attempt_id = ApproveAttemptId::new();
    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "INSERT INTO git_push_approve_attempt
                        (attempt_id, push_request_id, operator, started_at,
                         state, mint_jti, mint_github_app_id,
                         mint_issued_at, mint_expires_at)
                     VALUES (?1, ?2, 'alice', 1700000000,
                             'started', ?3, 42, 1700000100, 1700003700)",
                params![
                    attempt_id.as_uuid().to_string(),
                    push_request_id.as_uuid().to_string(),
                    Jti::new().as_uuid().to_string(),
                ],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("check"),
        "unexpected error: {err}"
    );
}

/// An `uncertain` row must carry mint context. Without this CHECK,
/// manual SQL could land the row that `reject_blocker_for_push` is
/// meant to block on, but `git_push_approve_attempt_from_row` would
/// then refuse to parse it as an invariant error — making the
/// blocker query fail on the very state it exists to detect.
#[test]
fn check_constraint_rejects_uncertain_row_without_mint() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let attempt_id = ApproveAttemptId::new();
    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "INSERT INTO git_push_approve_attempt
                        (attempt_id, push_request_id, operator, started_at, state)
                     VALUES (?1, ?2, 'alice', 1700000000, 'uncertain')",
                params![
                    attempt_id.as_uuid().to_string(),
                    push_request_id.as_uuid().to_string(),
                ],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("check"),
        "unexpected error: {err}"
    );
}

/// A `resolved(succeeded)` row also requires mint — the
/// `complete_attempt_succeeded` path always arrives via `uncertain`
/// (which itself requires mint), but the column-level invariant
/// must not depend on that flow.
#[test]
fn check_constraint_rejects_resolved_succeeded_without_mint() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let attempt_id = ApproveAttemptId::new();
    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "INSERT INTO git_push_approve_attempt
                        (attempt_id, push_request_id, operator, started_at,
                         state, outcome, completed_at, new_app_tip)
                     VALUES (?1, ?2, 'alice', 1700000000,
                             'resolved', 'succeeded', 1700000200,
                             '0123456789abcdef0123456789abcdef01234567')",
                params![
                    attempt_id.as_uuid().to_string(),
                    push_request_id.as_uuid().to_string(),
                ],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("check"),
        "unexpected error: {err}"
    );
}

/// SQLite's `TEXT PRIMARY KEY` in a rowid table does not imply
/// NOT NULL. Without the explicit NOT NULL, a row with a NULL
/// `attempt_id` would be admitted; `from_row` would then surface a
/// SQLite read error and `reject_blocker_for_push` would fail on
/// the very row it is meant to classify.
#[test]
fn primary_key_constraint_rejects_null_attempt_id() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "INSERT INTO git_push_approve_attempt
                        (attempt_id, push_request_id, operator, started_at, state)
                     VALUES (NULL, ?1, 'alice', 1700000000, 'started')",
                params![push_request_id.as_uuid().to_string()],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("not null"),
        "unexpected error: {err}"
    );
}
