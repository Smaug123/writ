//! `ReconcileStagedPush` manual-reconciliation state-machine tests.

use super::test_support::*;
use super::*;
use crate::audit::{GitPushApproveAttemptOutcome, GitPushApproveAttemptState};
use wiremock::MockServer;

#[tokio::test]
async fn reconcile_staged_push_without_staging_configured_returns_error() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o");
    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id: RequestId::new(),
            operator: "alice".into(),
            outcome: ReconcileOutcome::NotApplied {
                detail: "operator confirmed no PATCH landed".into(),
            },
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
async fn reconcile_staged_push_with_empty_operator_returns_error() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id: RequestId::new(),
            operator: String::new(),
            outcome: ReconcileOutcome::NotApplied { detail: "x".into() },
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
async fn reconcile_staged_push_with_oversize_operator_returns_error() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let oversize = "a".repeat(MAX_OPERATOR_BYTES + 1);
    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id: RequestId::new(),
            operator: oversize,
            outcome: ReconcileOutcome::NotApplied { detail: "x".into() },
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

#[tokio::test]
async fn reconcile_staged_push_with_empty_detail_returns_error() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id: RequestId::new(),
            operator: "alice".into(),
            outcome: ReconcileOutcome::NotApplied {
                detail: String::new(),
            },
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("detail") && message.contains("empty"),
                "got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn reconcile_staged_push_with_empty_reason_returns_error() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id: RequestId::new(),
            operator: "alice".into(),
            outcome: ReconcileOutcome::Applied {
                new_app_tip: sample_object_id('c'),
                reason: String::new(),
            },
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("reason") && message.contains("empty"),
                "got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn reconcile_staged_push_with_oversize_detail_returns_error() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let oversize = "z".repeat(crate::protocol::MAX_REJECTION_REASON_BYTES + 1);
    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id: RequestId::new(),
            operator: "alice".into(),
            outcome: ReconcileOutcome::NotApplied { detail: oversize },
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(message.contains("detail"), "got: {message}");
            assert!(message.contains("byte"), "got: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn reconcile_staged_push_with_unknown_request_returns_unknown_staged_push() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let request_id = RequestId::new();
    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator: "alice".into(),
            outcome: ReconcileOutcome::NotApplied {
                detail: "operator confirmed nothing landed".into(),
            },
        },
        &state,
    )
    .await;
    assert_eq!(resp, ServerMessage::UnknownStagedPush { request_id });
}

#[tokio::test]
async fn reconcile_staged_push_with_no_attempts_returns_not_reconcilable() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_010_000_000),
        UnixMillis::from_millis(1_700_010_000_500),
    )
    .await;
    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator: "alice".into(),
            outcome: ReconcileOutcome::NotApplied {
                detail: "no attempts to reconcile".into(),
            },
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::StagedPushNotReconcilable {
            request_id: got_id,
            reason,
        } => {
            assert_eq!(got_id, request_id);
            assert!(
                reason.contains("no approve attempt"),
                "got reason: {reason}",
            );
        }
        other => panic!("expected StagedPushNotReconcilable, got {other:?}"),
    }
}

#[tokio::test]
async fn reconcile_staged_push_with_in_flight_started_attempt_returns_not_reconcilable() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_011_000_000),
        UnixMillis::from_millis(1_700_011_000_500),
    )
    .await;
    let attempt_id = ApproveAttemptId::new();
    state
        .audit
        .start_approve_attempt(
            attempt_id,
            request_id,
            "alice",
            UnixMillis::from_millis(1_700_011_001_000),
        )
        .unwrap();

    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator: "alice".into(),
            outcome: ReconcileOutcome::NotApplied {
                detail: "racing reconciliation".into(),
            },
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::StagedPushNotReconcilable {
            request_id: got_id,
            reason,
        } => {
            assert_eq!(got_id, request_id);
            assert!(reason.contains("in-flight"), "got reason: {reason}");
        }
        other => panic!("expected StagedPushNotReconcilable, got {other:?}"),
    }

    // No reconciliation row was written.
    let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
    assert_eq!(attempts.len(), 1);
}

#[tokio::test]
async fn reconcile_staged_push_with_uncertain_not_boot_observed_returns_not_reconcilable() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_011_200_000),
        UnixMillis::from_millis(1_700_011_200_500),
    )
    .await;
    let attempt_id = ApproveAttemptId::new();
    state
        .audit
        .start_approve_attempt(
            attempt_id,
            request_id,
            "alice",
            UnixMillis::from_millis(1_700_011_201_000),
        )
        .unwrap();
    state
        .audit
        .mark_attempt_uncertain(attempt_id, sample_promote_mint_audit())
        .unwrap();
    // Note: no mark_attempt_boot_observed — the row may belong to a
    // live worker and reconciliation must wait.

    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator: "alice".into(),
            outcome: ReconcileOutcome::NotApplied {
                detail: "racing reconciliation".into(),
            },
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::StagedPushNotReconcilable {
            request_id: got_id,
            reason,
        } => {
            assert_eq!(got_id, request_id);
            assert!(reason.contains("in-flight"), "got reason: {reason}");
        }
        other => panic!("expected StagedPushNotReconcilable, got {other:?}"),
    }
}

#[tokio::test]
async fn reconcile_staged_push_with_only_pre_patch_failure_returns_not_reconcilable() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_012_000_000),
        UnixMillis::from_millis(1_700_012_000_500),
    )
    .await;
    let attempt_id = ApproveAttemptId::new();
    state
        .audit
        .start_approve_attempt(
            attempt_id,
            request_id,
            "alice",
            UnixMillis::from_millis(1_700_012_001_000),
        )
        .unwrap();
    state
        .audit
        .complete_attempt_pre_patch_failure(
            attempt_id,
            "mint failed",
            UnixMillis::from_millis(1_700_012_002_000),
        )
        .unwrap();

    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator: "alice".into(),
            outcome: ReconcileOutcome::NotApplied {
                detail: "nothing to clear".into(),
            },
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::StagedPushNotReconcilable {
            request_id: got_id,
            reason,
        } => {
            assert_eq!(got_id, request_id);
            assert!(
                reason.contains("no quarantined approve attempt"),
                "got reason: {reason}",
            );
        }
        other => panic!("expected StagedPushNotReconcilable, got {other:?}"),
    }
}

#[tokio::test]
async fn reconcile_staged_push_with_prior_resolution_returns_already_resolved() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_013_000_000),
        UnixMillis::from_millis(1_700_013_000_500),
    )
    .await;
    state
        .audit
        .record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id: request_id,
            decided_at: UnixMillis::from_millis(1_700_013_001_000),
            decision: GitPushResolution::Rejected,
            operator: "alice",
            reason: "prior decision",
        })
        .unwrap();

    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator: "bob".into(),
            outcome: ReconcileOutcome::NotApplied {
                detail: "racing reconciliation".into(),
            },
        },
        &state,
    )
    .await;
    assert_eq!(
        resp,
        ServerMessage::StagedPushAlreadyResolved { request_id }
    );
}

/// Happy-path: a `Resolved(PostPatchFailure)` attempt is the
/// canonical reconciliation target — terminal, no boot-observed
/// marker required. `Applied` writes the reconciliation row and
/// the joint-TX `git_push_resolution(decision='approved')` row,
/// then deletes the staging dir.
#[tokio::test]
async fn reconcile_staged_push_applied_against_post_patch_failure_records_resolution() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let (request_id, predecessor) =
        stage_with_post_patch_failure_attempt(&state, 1_700_020_000_000).await;
    let new_app_tip = sample_object_id('c');

    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator: "bob".into(),
            outcome: ReconcileOutcome::Applied {
                new_app_tip: new_app_tip.clone(),
                reason: "operator confirmed branch advanced".into(),
            },
        },
        &state,
    )
    .await;
    assert_eq!(resp, ServerMessage::StagedPushReconciled { request_id });

    // The resolution row is now `Approved` with the predecessor's
    // mint context copied through.
    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    let resolution = audit_entry.resolution.expect("resolution row recorded");
    assert!(
        matches!(resolution.decision, GitPushResolution::Approved(_)),
        "expected Approved decision, got {:?}",
        resolution.decision,
    );
    assert_eq!(resolution.operator, "bob");

    // The reconciliation row supersedes the predecessor and carries
    // the new_app_tip via its `Succeeded` outcome. Two attempt
    // rows, both committed.
    let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
    assert_eq!(attempts.len(), 2);
    assert!(
        attempts.iter().any(|a| a.attempt_id == predecessor),
        "predecessor row must remain",
    );
    let reconciliation = attempts
        .iter()
        .find(|a| a.attempt_id != predecessor)
        .expect("reconciliation row recorded");
    match &reconciliation.state {
        GitPushApproveAttemptState::Resolved {
            outcome: GitPushApproveAttemptOutcome::Succeeded { new_app_tip: tip },
            ..
        } => {
            assert_eq!(tip, &new_app_tip);
        }
        other => {
            panic!("expected reconciliation row to be Resolved(Succeeded), got {other:?}",)
        }
    }

    // Staging dir was deleted after the joint TX committed.
    match state.staging_store.as_ref().unwrap().load(request_id) {
        Err(StagingError::NotFound { .. }) => {}
        other => panic!("expected staging cleanup, got {other:?}"),
    }
}

/// `NotApplied` against a `Resolved(PostPatchFailure)` predecessor
/// writes a born-terminal `Resolved(PrePatchFailure)` reconciliation
/// row but no resolution row. The staging dir survives so a
/// follow-up reject can decide the operator action.
#[tokio::test]
async fn reconcile_staged_push_not_applied_against_post_patch_failure_leaves_push_rejectable() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let (request_id, _predecessor) =
        stage_with_post_patch_failure_attempt(&state, 1_700_021_000_000).await;

    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator: "bob".into(),
            outcome: ReconcileOutcome::NotApplied {
                detail: "operator confirmed branch did not advance".into(),
            },
        },
        &state,
    )
    .await;
    assert_eq!(resp, ServerMessage::StagedPushReconciled { request_id });

    // No resolution row — push is again rejectable.
    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    assert!(audit_entry.resolution.is_none());

    // Staging dir is still on disk so a follow-up reject finds it.
    assert!(
        state
            .staging_store
            .as_ref()
            .unwrap()
            .load(request_id)
            .is_ok(),
    );

    // Follow-up reject now proceeds (PrePatchFailure is not a
    // blocker after the predecessor was superseded).
    let follow_up = dispatch_message(
        ClientMessage::RejectStagedPush {
            request_id,
            operator: "bob".into(),
            reason: reason("after not-applied reconciliation"),
        },
        &state,
    )
    .await;
    assert_eq!(follow_up, ServerMessage::StagedPushRejected { request_id });
}

/// A boot-observed `Uncertain` row is the survivor case: the
/// daemon crashed mid-approve, boot reconcile marked the row
/// observable, and the operator manually decides the GitHub side.
/// Reconciliation `Applied` lands the resolution row and clears
/// the quarantine.
#[tokio::test]
async fn reconcile_staged_push_applied_against_boot_observed_uncertain_records_resolution() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let (request_id, _predecessor) =
        stage_with_boot_observed_uncertain_attempt(&state, 1_700_022_000_000).await;
    let new_app_tip = sample_object_id('d');

    let resp = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator: "bob".into(),
            outcome: ReconcileOutcome::Applied {
                new_app_tip: new_app_tip.clone(),
                reason: "branch advanced under restart".into(),
            },
        },
        &state,
    )
    .await;
    assert_eq!(resp, ServerMessage::StagedPushReconciled { request_id });

    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    let resolution = audit_entry.resolution.expect("resolution row recorded");
    assert!(matches!(
        resolution.decision,
        GitPushResolution::Approved(_)
    ));
}

/// Two reconciliations in a row against the same push: the second
/// fails because the predecessor is already superseded. The handler
/// surfaces the DAO Invariant as `StagedPushNotReconcilable` rather
/// than a generic Error so the CLI can guide the operator to
/// re-list and pick the new state.
#[tokio::test]
async fn reconcile_staged_push_against_already_superseded_predecessor_returns_not_reconcilable() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let (request_id, _predecessor) =
        stage_with_post_patch_failure_attempt(&state, 1_700_023_000_000).await;

    // First reconciliation clears the predecessor.
    let first = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator: "bob".into(),
            outcome: ReconcileOutcome::NotApplied {
                detail: "no patch landed".into(),
            },
        },
        &state,
    )
    .await;
    assert_eq!(first, ServerMessage::StagedPushReconciled { request_id });

    // Second call sees the predecessor has been superseded; the
    // classifier now reports NothingToReconcile (every blocker is
    // cleared) rather than Eligible.
    let second = dispatch_message(
        ClientMessage::ReconcileStagedPush {
            request_id,
            operator: "bob".into(),
            outcome: ReconcileOutcome::NotApplied {
                detail: "racing second call".into(),
            },
        },
        &state,
    )
    .await;
    match second {
        ServerMessage::StagedPushNotReconcilable {
            request_id: got_id,
            reason,
        } => {
            assert_eq!(got_id, request_id);
            assert!(
                reason.contains("no quarantined approve attempt"),
                "got reason: {reason}",
            );
        }
        other => panic!("expected StagedPushNotReconcilable, got {other:?}"),
    }
}
