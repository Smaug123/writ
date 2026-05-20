//! Drive approve attempts left non-terminal by a prior crash to a
//! state the rest of the broker can act on.
//!
//! The approve state machine (see `docs/design/approve_state_machine.md`)
//! has two non-terminal states:
//!
//! * `Started` — an attempt was recorded but no PATCH could have been
//!   issued yet. The broker crashed before TX2 committed, so GitHub is
//!   provably unchanged. We transition such rows to
//!   `Resolved(PrePatchFailure { detail = "broker restart" })` so the
//!   push becomes rejectable / retryable again.
//!
//! * `Uncertain` — the broker had committed to issuing a PATCH (TX2
//!   landed) but never recorded the outcome. GitHub's state is
//!   uncertain; only manual reconciliation against the remote ref can
//!   resolve the row. We log the row to `AUDIT_WRITE_FAILURE_TARGET`
//!   so the operator sees it on the next boot, and leave it in place
//!   for `reject_blocker_for_push` to surface as `AttemptInFlight`.
//!
//! No filesystem state is consulted: the audit log is the system of
//! record. The schema's forward-only triggers admit the
//! `Started -> Resolved(PrePatchFailure)` transition; this module is
//! the only caller that does so for the "broker restart" reason.

use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, AuditLog, GitPushApproveAttemptEntry,
    GitPushApproveAttemptState,
};
use crate::core::{ApproveAttemptId, UnixMillis};

/// Detail string written to `git_push_approve_attempt.failure_detail`
/// when boot reconcile transitions a `Started` attempt to
/// `Resolved(PrePatchFailure)`. The string is part of the audit
/// surface — operators grep for it to distinguish broker-restart
/// recoveries from runtime pre-PATCH failures. Do not change without
/// considering downstream tooling.
pub const BROKER_RESTART_DETAIL: &str = "broker restart";

/// Summary of one pass of [`reconcile_pending_approve_attempts`].
/// The counts let the caller emit a single boot log line summarising
/// what the audit log carried over from the prior process.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcileReport {
    /// Attempts found in `Started` and transitioned to
    /// `Resolved(PrePatchFailure { detail = "broker restart" })`.
    pub recovered_started: Vec<ApproveAttemptId>,
    /// Attempts found in `Uncertain` and left in place for manual
    /// reconciliation; emitted to `AUDIT_WRITE_FAILURE_TARGET` so the
    /// operator sees them on every boot until resolved.
    pub flagged_uncertain: Vec<ApproveAttemptId>,
}

impl ReconcileReport {
    pub fn is_empty(&self) -> bool {
        self.recovered_started.is_empty() && self.flagged_uncertain.is_empty()
    }
}

/// Sweep `git_push_approve_attempt` for rows whose state would block
/// the broker from accepting a fresh approve or reject for the same
/// push. Called once during daemon startup, *after* the broker socket
/// is bound (so this process has proven singleton ownership of the
/// audit DB) but *before* any request handler can run (so the first
/// request to land sees a quiescent state).
///
/// Ordering is load-bearing: running this before the bind would let a
/// second `writd` racing the live daemon's startup mutate the shared
/// DB before its bind fails on `AddrInUse`, potentially resolving the
/// live process's legitimate in-flight `Started` attempt as a fake
/// "broker restart" failure. The bind is the singleton claim; this
/// pass must come after it.
///
/// Errors abort startup: the audit DB is the single source of truth,
/// so a DAO failure here is correctness-fatal — refusing to start
/// beats limping with stale non-terminal rows that would silently
/// block every subsequent approve/reject.
pub fn reconcile_pending_approve_attempts(
    audit: &AuditLog,
    now: UnixMillis,
) -> Result<ReconcileReport, AuditError> {
    let pending = audit.list_blocking_approve_attempts()?;
    let mut report = ReconcileReport::default();

    for entry in pending {
        match entry.state {
            GitPushApproveAttemptState::Started => {
                recover_started(audit, &entry, now)?;
                report.recovered_started.push(entry.attempt_id);
            }
            GitPushApproveAttemptState::Uncertain { .. } => {
                flag_uncertain(&entry);
                report.flagged_uncertain.push(entry.attempt_id);
            }
            // The DAO query filters `state IN ('started', 'uncertain')`,
            // so a `Resolved` row reaching this arm would mean the row
            // parser disagrees with the SQL. Treat as a programmer
            // error rather than try to handle it.
            GitPushApproveAttemptState::Resolved { .. } => {
                return Err(AuditError::Invariant(
                    "boot reconcile: list_blocking_approve_attempts returned a resolved row",
                ));
            }
        }
    }

    Ok(report)
}

fn recover_started(
    audit: &AuditLog,
    entry: &GitPushApproveAttemptEntry,
    now: UnixMillis,
) -> Result<(), AuditError> {
    audit.complete_attempt_pre_patch_failure(entry.attempt_id, BROKER_RESTART_DETAIL, now)
}

fn flag_uncertain(entry: &GitPushApproveAttemptEntry) {
    tracing::error!(
        target: AUDIT_WRITE_FAILURE_TARGET,
        kind = "boot_reconcile_uncertain_attempt",
        attempt_id = %entry.attempt_id,
        push_request_id = %entry.push_request_id,
        operator = %entry.operator,
        started_at = entry.started_at.as_millis(),
        "approve attempt left uncertain across broker restart; manual reconciliation required \
         before any further approve/reject for this push can land",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        GitPushApproveAttemptOutcome, GitPushOutcomeRecord, GitPushOutcomeResult,
        GitPushRequestRecord, GitPushResolution, GitPushResolutionRecord, PromoteMintAudit,
    };
    use crate::core::{AgentKind, Jti, RepoRef, RequestId, SessionId, SessionRecord};
    use crate::vm_git::{GitCloneRepo, GitObjectId};
    use uuid::Uuid;

    fn now() -> UnixMillis {
        UnixMillis::from_millis(1_700_001_000)
    }
    fn started_at() -> UnixMillis {
        UnixMillis::from_millis(1_700_000_200)
    }
    fn mint_issued_at() -> UnixMillis {
        UnixMillis::from_millis(1_700_000_300)
    }
    fn mint_expires_at() -> UnixMillis {
        UnixMillis::from_millis(1_700_000_900)
    }

    fn sample_session() -> SessionRecord {
        SessionRecord {
            session_id: SessionId::new(),
            label: None,
            agent_kind: Some(AgentKind::Claude),
            agent_model: None,
            opened_at: UnixMillis::from_millis(1_700_000_000),
            closed_at: None,
        }
    }

    fn sample_repo() -> GitCloneRepo {
        GitCloneRepo::new(RepoRef {
            owner: "o".into(),
            name: "n".into(),
        })
        .unwrap()
    }

    fn git_oid(nibble: char) -> GitObjectId {
        std::iter::repeat_n(nibble, 40)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    fn record_staged_push(log: &AuditLog, session_id: SessionId) -> RequestId {
        let push_request_id = RequestId::new();
        log.record_git_push_request(&GitPushRequestRecord {
            push_request_id,
            session_id,
            received_at: UnixMillis::from_millis(1_700_000_100),
            repo: sample_repo(),
            branch: "main".parse().unwrap(),
            expected_remote_head: Some(git_oid('1')),
            new_head: git_oid('2'),
            correlation_id: None,
        })
        .unwrap();
        log.record_git_push_outcome(&GitPushOutcomeRecord {
            push_request_id,
            completed_at: UnixMillis::from_millis(1_700_000_130),
            result: GitPushOutcomeResult::Staged,
            github_status: None,
            message: "queued for review",
        })
        .unwrap();
        push_request_id
    }

    fn sample_mint() -> PromoteMintAudit {
        PromoteMintAudit {
            jti: Jti::from_uuid(Uuid::nil()),
            github_app_id: 42,
            issued_at: mint_issued_at(),
            expires_at: mint_expires_at(),
        }
    }

    fn open_log_with_session() -> (AuditLog, SessionId) {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        (log, s.session_id)
    }

    #[test]
    fn empty_log_returns_empty_report() {
        let log = AuditLog::open_in_memory().unwrap();
        let report = reconcile_pending_approve_attempts(&log, now()).unwrap();
        assert!(report.is_empty());
    }

    /// A single `Started` attempt is transitioned to
    /// `Resolved(PrePatchFailure)` with the broker-restart detail. The
    /// attempt's `completed_at` matches the clock supplied to the
    /// reconcile call.
    #[test]
    fn started_attempt_is_driven_to_pre_patch_failure() {
        let (log, session_id) = open_log_with_session();
        let push_request_id = record_staged_push(&log, session_id);
        let attempt_id = ApproveAttemptId::new();
        log.start_approve_attempt(attempt_id, push_request_id, "alice", started_at())
            .unwrap();

        let report = reconcile_pending_approve_attempts(&log, now()).unwrap();
        assert_eq!(report.recovered_started, vec![attempt_id]);
        assert!(report.flagged_uncertain.is_empty());

        let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
        assert_eq!(attempts.len(), 1);
        match &attempts[0].state {
            GitPushApproveAttemptState::Resolved {
                outcome,
                completed_at,
                mint,
            } => {
                assert_eq!(
                    *outcome,
                    GitPushApproveAttemptOutcome::PrePatchFailure {
                        detail: BROKER_RESTART_DETAIL.into(),
                    }
                );
                assert_eq!(*completed_at, now());
                assert!(mint.is_none(), "Started→PrePatch must not invent a mint");
            }
            other => panic!("expected Resolved(PrePatchFailure), got {other:?}"),
        }
    }

    /// After reconcile, reject for the recovered push must be allowed
    /// — this is the load-bearing property that makes the broker
    /// useful again after a restart.
    #[test]
    fn recovered_started_unblocks_reject() {
        let (log, session_id) = open_log_with_session();
        let push_request_id = record_staged_push(&log, session_id);
        let attempt_id = ApproveAttemptId::new();
        log.start_approve_attempt(attempt_id, push_request_id, "alice", started_at())
            .unwrap();
        assert!(
            log.reject_blocker_for_push(push_request_id)
                .unwrap()
                .is_some(),
            "pre-reconcile: Started attempt must block reject",
        );

        reconcile_pending_approve_attempts(&log, now()).unwrap();

        assert!(
            log.reject_blocker_for_push(push_request_id)
                .unwrap()
                .is_none(),
            "post-reconcile: PrePatchFailure must not block reject",
        );
        log.record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id,
            decided_at: now(),
            decision: GitPushResolution::Rejected,
            operator: "alice",
            reason: "no longer wanted",
        })
        .unwrap();
    }

    /// `Uncertain` is the post-PATCH-commit-pre-PATCH-result state.
    /// Boot reconcile must NOT transition it (only operator
    /// reconciliation can), but it must surface the row so the
    /// operator sees it in the boot logs.
    #[test]
    fn uncertain_attempt_is_flagged_and_not_modified() {
        let (log, session_id) = open_log_with_session();
        let push_request_id = record_staged_push(&log, session_id);
        let attempt_id = ApproveAttemptId::new();
        log.start_approve_attempt(attempt_id, push_request_id, "alice", started_at())
            .unwrap();
        log.mark_attempt_uncertain(attempt_id, sample_mint())
            .unwrap();

        let report = reconcile_pending_approve_attempts(&log, now()).unwrap();
        assert!(report.recovered_started.is_empty());
        assert_eq!(report.flagged_uncertain, vec![attempt_id]);

        let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
        assert!(
            matches!(
                attempts[0].state,
                GitPushApproveAttemptState::Uncertain { .. }
            ),
            "row must remain Uncertain after reconcile, got {:?}",
            attempts[0].state
        );
        assert!(
            log.reject_blocker_for_push(push_request_id)
                .unwrap()
                .is_some(),
            "post-reconcile: Uncertain must still block reject",
        );
    }

    /// A reconcile pass against a steady-state DB (only `Resolved`
    /// rows) must be a no-op. This is the common case on the second
    /// and subsequent boots of an operationally healthy broker.
    #[test]
    fn resolved_rows_are_ignored() {
        let (log, session_id) = open_log_with_session();
        let push_request_id = record_staged_push(&log, session_id);
        let attempt_id = ApproveAttemptId::new();
        log.start_approve_attempt(attempt_id, push_request_id, "alice", started_at())
            .unwrap();
        log.complete_attempt_pre_patch_failure(
            attempt_id,
            "mint denied",
            UnixMillis::from_millis(1_700_000_210),
        )
        .unwrap();

        let report = reconcile_pending_approve_attempts(&log, now()).unwrap();
        assert!(report.is_empty());

        let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
        match &attempts[0].state {
            GitPushApproveAttemptState::Resolved {
                outcome,
                completed_at,
                ..
            } => {
                assert_eq!(
                    *outcome,
                    GitPushApproveAttemptOutcome::PrePatchFailure {
                        detail: "mint denied".into(),
                    },
                    "reconcile must not overwrite a pre-existing PrePatchFailure detail",
                );
                assert_eq!(
                    *completed_at,
                    UnixMillis::from_millis(1_700_000_210),
                    "reconcile must not overwrite a pre-existing completed_at",
                );
            }
            other => panic!("expected Resolved(PrePatchFailure), got {other:?}"),
        }
    }

    /// Running reconcile twice is safe: the second call has nothing to
    /// recover (the Started rows are now Resolved) but still flags any
    /// persistent Uncertain rows. This mirrors what happens if the
    /// daemon crashes during boot reconcile itself.
    #[test]
    fn reconcile_is_idempotent_across_invocations() {
        let (log, session_id) = open_log_with_session();
        let push_started = record_staged_push(&log, session_id);
        let push_uncertain = record_staged_push(&log, session_id);
        let started = ApproveAttemptId::new();
        let uncertain = ApproveAttemptId::new();
        log.start_approve_attempt(started, push_started, "alice", started_at())
            .unwrap();
        log.start_approve_attempt(
            uncertain,
            push_uncertain,
            "alice",
            UnixMillis::from_millis(1_700_000_201),
        )
        .unwrap();
        log.mark_attempt_uncertain(uncertain, sample_mint())
            .unwrap();

        let first = reconcile_pending_approve_attempts(&log, now()).unwrap();
        assert_eq!(first.recovered_started, vec![started]);
        assert_eq!(first.flagged_uncertain, vec![uncertain]);

        let second =
            reconcile_pending_approve_attempts(&log, UnixMillis::from_millis(1_700_002_000))
                .unwrap();
        assert!(second.recovered_started.is_empty());
        assert_eq!(second.flagged_uncertain, vec![uncertain]);
    }

    /// Mixed state across many pushes: only the Started rows
    /// transition; ordering of the report matches the DAO ordering
    /// (started_at ascending) so operator-facing log lines stay
    /// stable across binary versions.
    #[test]
    fn mixed_state_reconcile_partitions_correctly() {
        let (log, session_id) = open_log_with_session();
        let push_started_old = record_staged_push(&log, session_id);
        let push_started_new = record_staged_push(&log, session_id);
        let push_uncertain = record_staged_push(&log, session_id);
        let push_resolved = record_staged_push(&log, session_id);

        let started_old = ApproveAttemptId::new();
        let started_new = ApproveAttemptId::new();
        let uncertain = ApproveAttemptId::new();
        let resolved = ApproveAttemptId::new();

        log.start_approve_attempt(
            started_old,
            push_started_old,
            "alice",
            UnixMillis::from_millis(1_700_000_200),
        )
        .unwrap();
        log.start_approve_attempt(
            uncertain,
            push_uncertain,
            "alice",
            UnixMillis::from_millis(1_700_000_210),
        )
        .unwrap();
        log.mark_attempt_uncertain(uncertain, sample_mint())
            .unwrap();
        log.start_approve_attempt(
            started_new,
            push_started_new,
            "alice",
            UnixMillis::from_millis(1_700_000_220),
        )
        .unwrap();
        log.start_approve_attempt(
            resolved,
            push_resolved,
            "alice",
            UnixMillis::from_millis(1_700_000_230),
        )
        .unwrap();
        log.complete_attempt_pre_patch_failure(
            resolved,
            "mint denied",
            UnixMillis::from_millis(1_700_000_240),
        )
        .unwrap();

        let report = reconcile_pending_approve_attempts(&log, now()).unwrap();
        assert_eq!(report.recovered_started, vec![started_old, started_new]);
        assert_eq!(report.flagged_uncertain, vec![uncertain]);
    }
}
