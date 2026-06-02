//! Shared fixtures for the `git_push` DAO test modules. Hoisted here so
//! the per-concern `*_tests` modules and the inline `spec` module share
//! one definition of the sample records, the staged-request setup, and
//! the attempt-driving helpers instead of each re-declaring them.
//!
//! `super::*` re-exports the production items (`AuditLog`,
//! `GitPushRequestRecord`, the id and `UnixMillis` newtypes, …); the
//! explicit imports add the test-only `RepoRef` and re-export
//! `sample_session` from the audit-wide fixtures so the per-concern
//! modules pick it up through `use super::test_support::*`.

use super::*;
pub(super) use crate::audit::test_support::sample_session;
use crate::core::RepoRef;

pub(super) fn sample_git_repo() -> GitCloneRepo {
    GitCloneRepo::new(RepoRef {
        owner: "o".into(),
        name: "n".into(),
    })
    .unwrap()
}

pub(super) fn git_oid(nibble: char) -> GitObjectId {
    std::iter::repeat_n(nibble, 40)
        .collect::<String>()
        .parse()
        .unwrap()
}

pub(super) fn sample_git_push_request_record(
    push_request_id: RequestId,
    session_id: SessionId,
) -> GitPushRequestRecord {
    GitPushRequestRecord {
        push_request_id,
        session_id,
        received_at: UnixMillis::from_millis(1_700_000_100),
        repo: sample_git_repo(),
        branch: "main".parse().unwrap(),
        expected_remote_head: Some(git_oid('1')),
        new_head: git_oid('2'),
        correlation_id: None,
    }
}

pub(super) fn record_staged_request(
    log: &AuditLog,
    push_request_id: RequestId,
    session_id: SessionId,
) {
    log.record_git_push_request(&sample_git_push_request_record(push_request_id, session_id))
        .unwrap();
    log.record_git_push_outcome(&GitPushOutcomeRecord {
        push_request_id,
        completed_at: UnixMillis::from_millis(1_700_000_130),
        result: GitPushOutcomeResult::Staged,
        github_status: None,
        message: "queued for review",
    })
    .unwrap();
}

pub(super) fn sample_promote_mint_audit() -> PromoteMintAudit {
    PromoteMintAudit {
        jti: Jti::new(),
        github_app_id: 42,
        issued_at: UnixMillis::from_millis(1_700_000_190),
        expires_at: UnixMillis::from_millis(1_700_000_490),
    }
}

pub(super) fn open_with_staged_request(log: &AuditLog, push_request_id: RequestId) -> SessionId {
    let s = sample_session();
    log.open_session(&s).unwrap();
    record_staged_request(log, push_request_id, s.session_id);
    s.session_id
}

/// Drive a fresh attempt to `Resolved(PostPatchFailure)` — the
/// quintessential reconciliation predecessor. Returns the attempt id and
/// the captured mint so the test body can drive the reconciliation path
/// with the right copy-forward expectations.
pub(super) fn drive_to_post_patch_failure(
    log: &AuditLog,
    push_request_id: RequestId,
) -> (ApproveAttemptId, PromoteMintAudit) {
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
        "transport drop after PATCH",
        UnixMillis::from_millis(1_700_000_250),
    )
    .unwrap();
    (attempt_id, mint)
}
