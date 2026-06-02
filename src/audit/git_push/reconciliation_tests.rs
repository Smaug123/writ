//! Example-based tests for the schema-v6 reconciliation path: applying
//! or refusing a reconciliation against each predecessor state, the
//! boot-observed gate, and the supersedes-immutability triggers.

use super::test_support::*;
use super::*;
#[test]
fn reconciliation_applied_writes_succeeded_row_carrying_predecessor_mint() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let (predecessor, mint) = drive_to_post_patch_failure(&log, push_request_id);
    let new_app_tip = git_oid('b');

    let reconciliation = ApproveAttemptId::new();
    log.record_reconciliation_attempt_applied(
        reconciliation,
        predecessor,
        &new_app_tip,
        "carol",
        "verified ref against GitHub",
        UnixMillis::from_millis(1_700_000_300),
    )
    .unwrap();

    let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
    assert_eq!(attempts.len(), 2);
    let recon = attempts
        .iter()
        .find(|a| a.attempt_id == reconciliation)
        .expect("reconciliation row must be present");
    assert_eq!(
        recon.state,
        GitPushApproveAttemptState::Resolved {
            outcome: GitPushApproveAttemptOutcome::Succeeded {
                new_app_tip: new_app_tip.clone(),
            },
            mint: Some(mint),
            completed_at: UnixMillis::from_millis(1_700_000_300),
        }
    );
    assert_eq!(recon.operator, "carol");

    // The joint TX wrote the resolution row carrying the
    // predecessor's mint — the audit log records the credential
    // that actually advanced GitHub, not a fresh mint at
    // reconciliation time.
    let entry = log.get_git_push(push_request_id).unwrap().unwrap();
    let resolution = entry.resolution.expect("resolution must be present");
    assert_eq!(resolution.decision, GitPushResolution::Approved(mint));
    assert_eq!(resolution.operator, "carol");
    assert_eq!(resolution.reason, "verified ref against GitHub");
}

#[test]
fn reconciliation_not_applied_writes_pre_patch_failure_without_resolution() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let (predecessor, mint) = drive_to_post_patch_failure(&log, push_request_id);

    let reconciliation = ApproveAttemptId::new();
    log.record_reconciliation_attempt_not_applied(
        reconciliation,
        predecessor,
        "carol",
        "verified ref unchanged on GitHub",
        UnixMillis::from_millis(1_700_000_300),
    )
    .unwrap();

    let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
    let recon = attempts
        .iter()
        .find(|a| a.attempt_id == reconciliation)
        .expect("reconciliation row must be present");
    assert_eq!(
        recon.state,
        GitPushApproveAttemptState::Resolved {
            outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                detail: "verified ref unchanged on GitHub".into(),
            },
            mint: Some(mint),
            completed_at: UnixMillis::from_millis(1_700_000_300),
        }
    );

    // No resolution row written: a "not applied" reconciliation
    // leaves the push in the same shape as a pre-PATCH failure.
    // Reject would write its own resolution row later.
    assert!(
        log.get_git_push(push_request_id)
            .unwrap()
            .unwrap()
            .resolution
            .is_none()
    );
}

#[test]
fn reconciliation_applied_clears_post_patch_blocker_from_reject() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let (predecessor, _) = drive_to_post_patch_failure(&log, push_request_id);

    assert_eq!(
        log.reject_blocker_for_push(push_request_id).unwrap(),
        Some(RejectBlocker::PostPatchUncertain {
            attempt_id: predecessor
        })
    );

    let reconciliation = ApproveAttemptId::new();
    log.record_reconciliation_attempt_applied(
        reconciliation,
        predecessor,
        &git_oid('b'),
        "carol",
        "verified ref against GitHub",
        UnixMillis::from_millis(1_700_000_300),
    )
    .unwrap();

    // The push is now `AlreadyApproved` (the reconciliation row
    // is `Resolved(Succeeded)`); the predecessor is hidden.
    assert_eq!(
        log.reject_blocker_for_push(push_request_id).unwrap(),
        Some(RejectBlocker::AlreadyApproved {
            attempt_id: reconciliation
        })
    );
}

#[test]
fn reconciliation_not_applied_unblocks_reject_and_subsequent_attempts() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let (predecessor, _) = drive_to_post_patch_failure(&log, push_request_id);

    let reconciliation = ApproveAttemptId::new();
    log.record_reconciliation_attempt_not_applied(
        reconciliation,
        predecessor,
        "carol",
        "verified ref unchanged",
        UnixMillis::from_millis(1_700_000_300),
    )
    .unwrap();

    // Reject is now admitted — the predecessor is superseded
    // and the reconciliation row's PrePatchFailure outcome is
    // not a blocker.
    assert_eq!(log.reject_blocker_for_push(push_request_id).unwrap(), None);

    // A fresh approve attempt is also admitted, mirroring the
    // post-`PrePatchFailure` retry path that v5 already allowed.
    let retry = ApproveAttemptId::new();
    log.start_approve_attempt(
        retry,
        push_request_id,
        "dave",
        UnixMillis::from_millis(1_700_000_400),
    )
    .unwrap();
}

#[test]
fn reconciliation_applied_against_uncertain_predecessor_admitted() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let predecessor = ApproveAttemptId::new();
    log.start_approve_attempt(
        predecessor,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();
    let mint = sample_promote_mint_audit();
    log.mark_attempt_uncertain(predecessor, mint).unwrap();
    // Simulate boot reconcile observing the Uncertain row across a
    // restart, which is what makes the row eligible for manual
    // reconciliation in the first place.
    log.mark_attempt_boot_observed(predecessor, UnixMillis::from_millis(1_700_000_250))
        .unwrap();

    let reconciliation = ApproveAttemptId::new();
    log.record_reconciliation_attempt_applied(
        reconciliation,
        predecessor,
        &git_oid('b'),
        "carol",
        "broker crashed mid-PATCH; verified ref applied",
        UnixMillis::from_millis(1_700_000_300),
    )
    .unwrap();

    // Boot reconcile no longer sees the uncertain predecessor —
    // a successful manual reconciliation cleared the quarantine.
    assert!(log.list_blocking_approve_attempts().unwrap().is_empty());
}

/// An `Uncertain` predecessor that has NOT been boot-observed must
/// be refused — the live broker process may still be racing the
/// PATCH to GitHub. Without this gate, an operator could supersede
/// the row while the worker is between TX2 and TX3 and a reject
/// would then commit under the cleared blocker, racing the
/// worker's eventual resolution write to GitHub.
#[test]
fn reconciliation_refused_when_uncertain_predecessor_not_boot_observed() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let predecessor = ApproveAttemptId::new();
    log.start_approve_attempt(
        predecessor,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();
    let mint = sample_promote_mint_audit();
    log.mark_attempt_uncertain(predecessor, mint).unwrap();
    // No mark_attempt_boot_observed call here — this row is from
    // the live broker process from the operator's perspective.

    let err = log
        .record_reconciliation_attempt_applied(
            ApproveAttemptId::new(),
            predecessor,
            &git_oid('b'),
            "carol",
            "verified ref applied",
            UnixMillis::from_millis(1_700_000_300),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant(
                "reconciliation of uncertain predecessor requires boot-observed marker"
            )
        ),
        "got: {err:?}"
    );

    // The not-applied path must refuse for the same reason.
    let err = log
        .record_reconciliation_attempt_not_applied(
            ApproveAttemptId::new(),
            predecessor,
            "carol",
            "verified ref did not apply",
            UnixMillis::from_millis(1_700_000_300),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant(
                "reconciliation of uncertain predecessor requires boot-observed marker"
            )
        ),
        "got: {err:?}"
    );

    // The push must remain blocked on the original Uncertain row —
    // critical for the contradiction-window guarantee.
    assert_eq!(
        log.list_blocking_approve_attempts().unwrap().len(),
        1,
        "the Uncertain row must still appear as a blocker"
    );
}

/// `Resolved(PostPatchFailure)` predecessors do NOT need a
/// boot-observed marker: a Resolved row is terminal, the
/// forward_only trigger refuses any UPDATE from it, so the live
/// broker provably won't race the reconciliation. The DAO must
/// admit reconciliation against a PostPatchFailure predecessor
/// even when no boot-observed marker exists.
#[test]
fn reconciliation_against_post_patch_failure_admitted_without_boot_observed() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let (predecessor, _) = drive_to_post_patch_failure(&log, push_request_id);
    // No mark_attempt_boot_observed call — PostPatchFailure is
    // terminal and does not need the gate.

    log.record_reconciliation_attempt_not_applied(
        ApproveAttemptId::new(),
        predecessor,
        "carol",
        "verified ref did not apply",
        UnixMillis::from_millis(1_700_000_500),
    )
    .unwrap();
}

/// `mark_attempt_boot_observed` is idempotent — boot reconcile
/// runs once per daemon startup, and across successive restarts
/// an `Uncertain` row that survives must not error a second call.
#[test]
fn mark_attempt_boot_observed_is_idempotent() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let attempt = ApproveAttemptId::new();
    log.start_approve_attempt(
        attempt,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();
    log.mark_attempt_uncertain(attempt, sample_promote_mint_audit())
        .unwrap();

    log.mark_attempt_boot_observed(attempt, UnixMillis::from_millis(1_700_000_250))
        .unwrap();
    // A second call must not error.
    log.mark_attempt_boot_observed(attempt, UnixMillis::from_millis(1_700_000_400))
        .unwrap();
}

#[test]
fn reconciliation_refused_when_predecessor_missing() {
    let log = AuditLog::open_in_memory().unwrap();
    let err = log
        .record_reconciliation_attempt_applied(
            ApproveAttemptId::new(),
            ApproveAttemptId::new(),
            &git_oid('b'),
            "carol",
            "no such predecessor",
            UnixMillis::from_millis(1_700_000_300),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("reconciliation predecessor does not exist")
        ),
        "got: {err:?}"
    );
}

#[test]
fn reconciliation_refused_when_predecessor_is_started() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let predecessor = ApproveAttemptId::new();
    log.start_approve_attempt(
        predecessor,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();

    let err = log
        .record_reconciliation_attempt_applied(
            ApproveAttemptId::new(),
            predecessor,
            &git_oid('b'),
            "carol",
            "should not be admitted",
            UnixMillis::from_millis(1_700_000_300),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("reconciliation predecessor is not in an eligible state")
        ),
        "got: {err:?}"
    );
}

#[test]
fn reconciliation_refused_when_predecessor_is_succeeded() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let predecessor = ApproveAttemptId::new();
    log.start_approve_attempt(
        predecessor,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_200),
    )
    .unwrap();
    let mint = sample_promote_mint_audit();
    log.mark_attempt_uncertain(predecessor, mint).unwrap();
    log.complete_attempt_succeeded(
        predecessor,
        &git_oid('a'),
        "alice",
        "ship it",
        UnixMillis::from_millis(1_700_000_220),
    )
    .unwrap();

    let err = log
        .record_reconciliation_attempt_not_applied(
            ApproveAttemptId::new(),
            predecessor,
            "carol",
            "no",
            UnixMillis::from_millis(1_700_000_300),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("reconciliation predecessor is not in an eligible state")
        ),
        "got: {err:?}"
    );
}

#[test]
fn reconciliation_refused_when_predecessor_already_superseded() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let (predecessor, _) = drive_to_post_patch_failure(&log, push_request_id);

    let first = ApproveAttemptId::new();
    log.record_reconciliation_attempt_not_applied(
        first,
        predecessor,
        "carol",
        "verified unchanged",
        UnixMillis::from_millis(1_700_000_300),
    )
    .unwrap();

    let err = log
        .record_reconciliation_attempt_not_applied(
            ApproveAttemptId::new(),
            predecessor,
            "dave",
            "second attempt",
            UnixMillis::from_millis(1_700_000_400),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("reconciliation predecessor has already been superseded")
        ),
        "got: {err:?}"
    );
}

#[test]
fn reconciliation_applied_rejects_empty_operator_and_reason() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let (predecessor, _) = drive_to_post_patch_failure(&log, push_request_id);

    let err = log
        .record_reconciliation_attempt_applied(
            ApproveAttemptId::new(),
            predecessor,
            &git_oid('b'),
            "",
            "reason",
            UnixMillis::from_millis(1_700_000_300),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("reconciliation attempt operator must not be empty")
        ),
        "got: {err:?}"
    );

    let err = log
        .record_reconciliation_attempt_applied(
            ApproveAttemptId::new(),
            predecessor,
            &git_oid('b'),
            "carol",
            "",
            UnixMillis::from_millis(1_700_000_300),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("reconciliation attempt reason must not be empty")
        ),
        "got: {err:?}"
    );
}

#[test]
fn reconciliation_not_applied_rejects_empty_operator_and_detail() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let (predecessor, _) = drive_to_post_patch_failure(&log, push_request_id);

    let err = log
        .record_reconciliation_attempt_not_applied(
            ApproveAttemptId::new(),
            predecessor,
            "",
            "detail",
            UnixMillis::from_millis(1_700_000_300),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("reconciliation attempt operator must not be empty")
        ),
        "got: {err:?}"
    );

    let err = log
        .record_reconciliation_attempt_not_applied(
            ApproveAttemptId::new(),
            predecessor,
            "carol",
            "",
            UnixMillis::from_millis(1_700_000_300),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Invariant("reconciliation attempt failure detail must not be empty")
        ),
        "got: {err:?}"
    );
}

/// Defence-in-depth: even when the DAO is bypassed by raw SQL, the
/// trigger refuses a reconciliation row that is not born terminal.
/// `state = 'started'` here would also fail the existing CHECK that
/// `(state = 'resolved') = (outcome IS NOT NULL)`, but the trigger
/// gives a reconciliation-specific message that pinpoints the
/// invariant the caller is violating.
#[test]
fn reconciliation_trigger_refuses_non_resolved_row() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let (predecessor, _) = drive_to_post_patch_failure(&log, push_request_id);

    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "INSERT INTO git_push_approve_attempt
                        (attempt_id, push_request_id, operator, started_at,
                         state, supersedes_attempt_id)
                     VALUES (?1, ?2, 'carol', 1700000300,
                             'uncertain', ?3)",
                params![
                    ApproveAttemptId::new().as_uuid().to_string(),
                    push_request_id.as_uuid().to_string(),
                    predecessor.as_uuid().to_string(),
                ],
            ))
        })
        .unwrap()
        .unwrap_err();
    // Either the born-terminal trigger or the existing CHECK
    // matches first depending on SQLite's evaluation order; both
    // are correctness-equivalent here.
    let msg = err.to_string();
    assert!(
        msg.contains("reconciliation attempt must be born resolved")
            || msg.to_lowercase().contains("check"),
        "got: {err}"
    );
}

/// Defence-in-depth: the trigger refuses a reconciliation row whose
/// outcome is `post_patch_failure`. Allowing that would let a
/// reconciliation be re-reconciled indefinitely, defeating the
/// "operator commits the answer" semantics.
#[test]
fn reconciliation_trigger_refuses_post_patch_failure_outcome() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);
    let (predecessor, mint) = drive_to_post_patch_failure(&log, push_request_id);

    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "INSERT INTO git_push_approve_attempt
                        (attempt_id, push_request_id, operator, started_at,
                         state, outcome, completed_at, failure_detail,
                         mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at,
                         supersedes_attempt_id)
                     VALUES (?1, ?2, 'carol', 1700000300,
                             'resolved', 'post_patch_failure', 1700000300, 'still uncertain',
                             ?3, ?4, ?5, ?6,
                             ?7)",
                params![
                    ApproveAttemptId::new().as_uuid().to_string(),
                    push_request_id.as_uuid().to_string(),
                    mint.jti.as_uuid().to_string(),
                    mint.github_app_id as i64,
                    mint.issued_at.as_millis(),
                    mint.expires_at.as_millis(),
                    predecessor.as_uuid().to_string(),
                ],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("reconciliation attempt must be born resolved"),
        "got: {err}"
    );
}

/// The same-push trigger refuses a reconciliation row that
/// references a different push from its predecessor. Without this,
/// a manual SQL writer could "clear" a quarantine on push A by
/// writing a row that the resolution INSERT then lands on push B.
#[test]
fn reconciliation_trigger_refuses_cross_push_reference() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_a = RequestId::new();
    let push_b = RequestId::new();
    let s = sample_session();
    log.open_session(&s).unwrap();
    record_staged_request(&log, push_a, s.session_id);
    record_staged_request(&log, push_b, s.session_id);
    let (predecessor, mint) = drive_to_post_patch_failure(&log, push_a);

    // INSERT a row that names push_b but supersedes push_a's
    // predecessor. The trigger must refuse.
    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "INSERT INTO git_push_approve_attempt
                        (attempt_id, push_request_id, operator, started_at,
                         state, outcome, completed_at, new_app_tip,
                         mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at,
                         supersedes_attempt_id)
                     VALUES (?1, ?2, 'carol', 1700000300,
                             'resolved', 'succeeded', 1700000300, ?3,
                             ?4, ?5, ?6, ?7,
                             ?8)",
                params![
                    ApproveAttemptId::new().as_uuid().to_string(),
                    push_b.as_uuid().to_string(),
                    git_oid('b').as_str(),
                    mint.jti.as_uuid().to_string(),
                    mint.github_app_id as i64,
                    mint.issued_at.as_millis(),
                    mint.expires_at.as_millis(),
                    predecessor.as_uuid().to_string(),
                ],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("reconciliation attempt must reference the same push as its predecessor"),
        "got: {err}"
    );
}

/// `supersedes_attempt_id` is established at INSERT, and the three
/// reconciliation INSERT triggers (born_terminal, predecessor_eligible,
/// same_push) fire only on INSERT. Without the UPDATE immutability
/// guard, a legal state transition such as
/// `started -> resolved(pre_patch_failure)` could be coerced to also
/// flip `supersedes_attempt_id`, bypassing every reconciliation
/// check. The trigger must refuse such an UPDATE.
#[test]
fn supersedes_immutable_trigger_refuses_update_setting_column() {
    let log = AuditLog::open_in_memory().unwrap();
    // Use two pushes: the PostPatchFailure predecessor lives on
    // push_a (it blocks start_approve_attempt for push_a), and the
    // fresh `started` attempt that we mutate lives on push_b (which
    // has no blocker). The same_push trigger only fires on INSERT,
    // so an UPDATE that flips supersedes_attempt_id to a different
    // push's predecessor would still bypass that check without the
    // immutability guard — exactly the bypass we're proving the
    // new trigger closes.
    let push_a = RequestId::new();
    let push_b = RequestId::new();
    let s = sample_session();
    log.open_session(&s).unwrap();
    record_staged_request(&log, push_a, s.session_id);
    record_staged_request(&log, push_b, s.session_id);
    let (predecessor, _) = drive_to_post_patch_failure(&log, push_a);

    let new_attempt = ApproveAttemptId::new();
    log.start_approve_attempt(
        new_attempt,
        push_b,
        "alice",
        UnixMillis::from_millis(1_700_000_500),
    )
    .unwrap();

    // UPDATE the `started` row to land in `resolved(pre_patch_failure)`
    // AND set supersedes_attempt_id at the same time. The legal
    // version of this transition (via complete_attempt_pre_patch_failure)
    // does not touch supersedes_attempt_id; we are simulating a
    // future-DAO or raw-SQL bypass.
    let err = log
        .with_conn_mut(|c| {
            Ok(c.execute(
                "UPDATE git_push_approve_attempt
                       SET state = 'resolved',
                           outcome = 'pre_patch_failure',
                           completed_at = 1700000600,
                           failure_detail = 'sneaky',
                           supersedes_attempt_id = ?1
                     WHERE attempt_id = ?2",
                params![
                    predecessor.as_uuid().to_string(),
                    new_attempt.as_uuid().to_string(),
                ],
            ))
        })
        .unwrap()
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("supersedes_attempt_id is immutable after insert"),
        "got: {err}"
    );
}

/// Sanity check that legal state transitions which do NOT touch
/// `supersedes_attempt_id` continue to work unchanged after the
/// UPDATE immutability trigger is in place.
#[test]
fn supersedes_immutable_trigger_admits_normal_state_transitions() {
    let log = AuditLog::open_in_memory().unwrap();
    let push_request_id = RequestId::new();
    let _session = open_with_staged_request(&log, push_request_id);

    let attempt = ApproveAttemptId::new();
    log.start_approve_attempt(
        attempt,
        push_request_id,
        "alice",
        UnixMillis::from_millis(1_700_000_500),
    )
    .unwrap();
    // started -> uncertain: must succeed (no supersedes change).
    log.mark_attempt_uncertain(attempt, sample_promote_mint_audit())
        .unwrap();
    // uncertain -> resolved(post_patch_failure): must succeed.
    log.complete_attempt_post_patch_failure(
        attempt,
        "github 5xx",
        UnixMillis::from_millis(1_700_000_600),
    )
    .unwrap();
}
