//! `RejectStagedPush` handler tests, including in-flight blockers.

use super::staged_push::{
    MAX_OPERATOR_BYTES, is_active_approve_refusal, is_unique_constraint_violation,
};
use super::test_support::*;
use super::*;
use wiremock::MockServer;

#[tokio::test]
async fn reject_staged_push_without_staging_configured_returns_error() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o");
    let resp = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id: RequestId::new(),
            operator: "alice".into(),
            reason: reason("nope"),
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(message.contains("staging"), "got: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn reject_staged_push_with_unknown_request_returns_unknown_staged_push() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let request_id = RequestId::new();
    let resp = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id,
            operator: "alice".into(),
            reason: reason("not staged"),
        },
        &state,
    )
    .await;
    assert_eq!(resp, ServerMessage::UnknownStagedPush { request_id });
}

#[tokio::test]
async fn reject_staged_push_happy_path_records_audit_and_deletes_staging() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_000_010_000),
        UnixMillis::from_millis(1_700_000_010_500),
    )
    .await;

    let resp = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id,
            operator: "alice".into(),
            reason: reason("contains a secret"),
        },
        &state,
    )
    .await;

    assert_eq!(resp, ServerMessage::StagedPushRejected { request_id });

    // Audit row is present with the right shape.
    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    let resolution = audit_entry
        .resolution
        .expect("resolution row recorded after reject");
    assert_eq!(resolution.decision, GitPushResolution::Rejected);
    assert_eq!(resolution.operator, "alice");
    assert_eq!(resolution.reason, "contains a secret");

    // Staging directory is gone; a follow-up reject sees UnknownStagedPush.
    let follow_up = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id,
            operator: "alice".into(),
            reason: reason("retry"),
        },
        &state,
    )
    .await;
    assert_eq!(follow_up, ServerMessage::UnknownStagedPush { request_id });
}

/// A second reject after an existing `Rejected` row returns
/// `AlreadyResolved` (the audit row was not authored by this call),
/// and — critically — opportunistically cleans up the staging dir
/// so a failed first-cleanup doesn't leave the entry stuck. The
/// original audit row is not overwritten.
#[tokio::test]
async fn reject_staged_push_already_resolved_path_retries_cleanup() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_000_020_000),
        UnixMillis::from_millis(1_700_000_020_500),
    )
    .await;

    // Record the operator decision out-of-band so the staging dir is
    // still on disk when dispatch sees the PK violation — the exact
    // shape of "first reject's cleanup failed".
    state
        .audit
        .record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id: request_id,
            decided_at: UnixMillis::from_millis(1_700_000_021_000),
            decision: GitPushResolution::Rejected,
            operator: "alice",
            reason: "first decision",
        })
        .unwrap();
    assert!(
        state
            .staging_store
            .as_ref()
            .unwrap()
            .load(request_id)
            .is_ok()
    );

    let resp = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id,
            operator: "bob".into(),
            reason: reason("second decision"),
        },
        &state,
    )
    .await;

    assert_eq!(
        resp,
        ServerMessage::StagedPushAlreadyResolved { request_id }
    );

    // Original audit row must be untouched.
    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    let resolution = audit_entry.resolution.expect("first decision still there");
    assert_eq!(resolution.operator, "alice");
    assert_eq!(resolution.reason, "first decision");

    // Staging dir was cleaned up on the retry path so the entry no
    // longer shows in `promote list`.
    match state.staging_store.as_ref().unwrap().load(request_id) {
        Err(StagingError::NotFound { .. }) => {}
        other => panic!("expected staging cleanup, got {other:?}"),
    }
}

#[tokio::test]
async fn reject_staged_push_with_empty_operator_returns_error() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let resp = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id: RequestId::new(),
            operator: String::new(),
            reason: reason("nope"),
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(message.contains("operator"), "got: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn reject_staged_push_with_oversize_operator_returns_error() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let oversized = "a".repeat(MAX_OPERATOR_BYTES + 1);
    let resp = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id: RequestId::new(),
            operator: oversized,
            reason: reason("nope"),
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(message.contains("operator"), "got: {message}");
            assert!(message.contains("byte"), "got: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

/// If somehow the audit log has a request row but no `Staged` outcome
/// (e.g. broker crashed mid-stage and resumed without re-recording),
/// the v13 trigger keeps the resolution table consistent by refusing
/// the insert. The broker surfaces this as a plain Error rather than
/// `StagedPushAlreadyResolved`, since no prior decision exists.
#[tokio::test]
async fn reject_staged_push_without_staged_outcome_returns_error() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    // Note: stage_with_audit records the request row but no outcome row.
    let request_id = stage_with_audit(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_000_030_000),
        UnixMillis::from_millis(1_700_000_030_500),
    )
    .await;

    let resp = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id,
            operator: "alice".into(),
            reason: reason("trigger should refuse"),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::Error { .. } => {}
        other => panic!("expected Error, got {other:?}"),
    }

    // Staging directory must still be present: the audit insert failed
    // before commit-then-delete could touch the filesystem.
    assert!(
        state
            .staging_store
            .as_ref()
            .unwrap()
            .load(request_id)
            .is_ok()
    );
}

/// A `Started` attempt blocks reject: the broker has committed to an
/// approve in flight but hasn't yet reached the PATCH boundary.
/// Surfacing the typed diagnostic (with the attempt_id and an
/// actionable hint) is the point of this slice — the raw trigger
/// ABORT text is opaque to the operator.
#[tokio::test]
async fn reject_staged_push_with_started_attempt_refuses_with_in_flight_diagnostic() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_001_010_000),
        UnixMillis::from_millis(1_700_001_010_500),
    )
    .await;
    let attempt_id = ApproveAttemptId::new();
    state
        .audit
        .start_approve_attempt(
            attempt_id,
            request_id,
            "alice",
            UnixMillis::from_millis(1_700_001_011_000),
        )
        .unwrap();

    let resp = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id,
            operator: "bob".into(),
            reason: reason("racing reject"),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains(&attempt_id.to_string()),
                "expected attempt id in diagnostic, got: {message}",
            );
            assert!(
                message.contains("in flight"),
                "expected 'in flight' phrasing, got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // No resolution row should have been written; the attempt
    // remains `Started` and the staging dir is still on disk.
    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    assert!(audit_entry.resolution.is_none());
    assert!(
        state
            .staging_store
            .as_ref()
            .unwrap()
            .load(request_id)
            .is_ok()
    );
}

/// Same shape as the `Started` case but the attempt has advanced to
/// `Uncertain` — the broker may have issued the PATCH but not yet
/// confirmed it. Reject is still refused with the in-flight
/// diagnostic; the operator waits for the attempt to resolve.
#[tokio::test]
async fn reject_staged_push_with_uncertain_attempt_refuses_with_in_flight_diagnostic() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_001_020_000),
        UnixMillis::from_millis(1_700_001_020_500),
    )
    .await;
    let attempt_id = ApproveAttemptId::new();
    state
        .audit
        .start_approve_attempt(
            attempt_id,
            request_id,
            "alice",
            UnixMillis::from_millis(1_700_001_021_000),
        )
        .unwrap();
    state
        .audit
        .mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
        .unwrap();

    let resp = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id,
            operator: "bob".into(),
            reason: reason("racing reject"),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains(&attempt_id.to_string()),
                "expected attempt id in diagnostic, got: {message}",
            );
            assert!(
                message.contains("in flight"),
                "expected 'in flight' phrasing, got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    assert!(audit_entry.resolution.is_none());
}

/// A `Resolved(Succeeded)` attempt is the joint-TX outcome: the
/// resolution row is already present alongside the attempt row.
/// Reject must reuse the existing already-resolved path so the
/// operator gets the same surface that a duplicate reject produces,
/// and so the staging dir cleanup retries on this call.
#[tokio::test]
async fn reject_staged_push_with_succeeded_attempt_returns_already_resolved() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_001_030_000),
        UnixMillis::from_millis(1_700_001_030_500),
    )
    .await;
    let attempt_id = ApproveAttemptId::new();
    state
        .audit
        .start_approve_attempt(
            attempt_id,
            request_id,
            "alice",
            UnixMillis::from_millis(1_700_001_031_000),
        )
        .unwrap();
    state
        .audit
        .mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
        .unwrap();
    state
        .audit
        .complete_attempt_succeeded(
            attempt_id,
            &sample_object_id('a'),
            "alice",
            "promoted by test",
            UnixMillis::from_millis(1_700_001_032_000),
        )
        .unwrap();
    // The joint TX wrote the resolution row alongside the attempt.
    let before = state.audit.get_git_push(request_id).unwrap().unwrap();
    assert!(before.resolution.is_some());

    let resp = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id,
            operator: "bob".into(),
            reason: reason("late reject"),
        },
        &state,
    )
    .await;

    assert_eq!(
        resp,
        ServerMessage::StagedPushAlreadyResolved { request_id }
    );

    // Original (approved) resolution row is untouched.
    let after = state.audit.get_git_push(request_id).unwrap().unwrap();
    let resolution = after.resolution.expect("resolution row remains");
    assert!(
        matches!(resolution.decision, GitPushResolution::Approved(_)),
        "expected approved decision, got {:?}",
        resolution.decision,
    );
    assert_eq!(resolution.operator, "alice");

    // The retry-cleanup path ran: staging dir is gone.
    match state.staging_store.as_ref().unwrap().load(request_id) {
        Err(StagingError::NotFound { .. }) => {}
        other => panic!("expected staging cleanup, got {other:?}"),
    }
}

/// A `Resolved(PostPatchFailure)` attempt quarantines the push: the
/// broker called `update_ref` but cannot confirm GitHub's terminal
/// state. Reject is refused until manual reconciliation; the
/// diagnostic must point at that operator action.
#[tokio::test]
async fn reject_staged_push_with_post_patch_failure_refuses_with_uncertain_diagnostic() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_001_040_000),
        UnixMillis::from_millis(1_700_001_040_500),
    )
    .await;
    let attempt_id = ApproveAttemptId::new();
    state
        .audit
        .start_approve_attempt(
            attempt_id,
            request_id,
            "alice",
            UnixMillis::from_millis(1_700_001_041_000),
        )
        .unwrap();
    state
        .audit
        .mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
        .unwrap();
    state
        .audit
        .complete_attempt_post_patch_failure(
            attempt_id,
            "github 502 on update_ref",
            UnixMillis::from_millis(1_700_001_042_000),
        )
        .unwrap();

    let resp = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id,
            operator: "bob".into(),
            reason: reason("late reject"),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains(&attempt_id.to_string()),
                "expected attempt id in diagnostic, got: {message}",
            );
            assert!(
                message.contains("reconcile") && message.contains("manually"),
                "expected manual-reconciliation hint, got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // No resolution row got written; the attempt remains in
    // `Resolved(PostPatchFailure)` quarantine.
    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    assert!(audit_entry.resolution.is_none());
}

/// Pre-patch failure is *not* a blocker — `reject_blocker_for_push`
/// returns `None` for an attempt that proved no PATCH was issued
/// (mint failure, plan failure, etc.), so reject proceeds normally.
/// This is the retry-after-transient-approve-failure path.
#[tokio::test]
async fn reject_staged_push_with_pre_patch_failure_attempt_proceeds_normally() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_001_050_000),
        UnixMillis::from_millis(1_700_001_050_500),
    )
    .await;
    let attempt_id = ApproveAttemptId::new();
    state
        .audit
        .start_approve_attempt(
            attempt_id,
            request_id,
            "alice",
            UnixMillis::from_millis(1_700_001_051_000),
        )
        .unwrap();
    state
        .audit
        .complete_attempt_pre_patch_failure(
            attempt_id,
            "mint failed",
            UnixMillis::from_millis(1_700_001_052_000),
        )
        .unwrap();

    let resp = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id,
            operator: "bob".into(),
            reason: reason("operator decision"),
        },
        &state,
    )
    .await;

    assert_eq!(resp, ServerMessage::StagedPushRejected { request_id });

    // Resolution row was written, staging dir removed.
    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    let resolution = audit_entry.resolution.expect("rejected resolution row");
    assert_eq!(resolution.decision, GitPushResolution::Rejected);
    assert_eq!(resolution.operator, "bob");
}

/// `is_active_approve_refusal` detects the
/// `git_push_resolution_refuses_active_approve` trigger's raised
/// message verbatim. This is the contract the handler depends on
/// when it re-queries the blocker on INSERT failure. Verifies the
/// match string is wired up correctly without standing up a full
/// dispatch — the literal lives in the migration SQL.
/// `is_active_approve_refusal` detects the
/// `git_push_resolution_refuses_active_approve` trigger firing.
/// This is the defence-in-depth path the handler relies on when an
/// attempt row lands between the preflight blocker check and the
/// resolution INSERT. Asserts both that a real trigger ABORT
/// matches the predicate and that a sibling PK violation does
/// *not* — keeping the existing
/// `is_unique_constraint_violation` branch distinct.
#[tokio::test]
async fn is_active_approve_refusal_matches_the_trigger_message() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_002_000_000),
        UnixMillis::from_millis(1_700_002_000_500),
    )
    .await;
    let attempt_id = ApproveAttemptId::new();
    state
        .audit
        .start_approve_attempt(
            attempt_id,
            request_id,
            "alice",
            UnixMillis::from_millis(1_700_002_001_000),
        )
        .unwrap();

    let err = state
        .audit
        .record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id: request_id,
            decided_at: UnixMillis::from_millis(1_700_002_002_000),
            decision: GitPushResolution::Rejected,
            operator: "bob",
            reason: "racing",
        })
        .expect_err("trigger refuses the INSERT");
    assert!(
        is_active_approve_refusal(&err),
        "predicate must classify trigger ABORT, got: {err:?}",
    );
    // A PK violation must *not* match this predicate so the
    // existing `is_unique_constraint_violation` branch keeps its
    // distinct behaviour.
    let fake_pk_err = crate::audit::AuditError::Sqlite(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error {
            code: rusqlite::ErrorCode::ConstraintViolation,
            extended_code: 0,
        },
        Some("UNIQUE constraint failed: git_push_resolution.push_request_id".into()),
    ));
    assert!(
        !is_active_approve_refusal(&fake_pk_err),
        "PK violation must not match the trigger predicate",
    );
    assert!(is_unique_constraint_violation(&fake_pk_err));
}
