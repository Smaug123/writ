//! Drive state left non-terminal by a prior crash to a state the rest
//! of the broker can act on. Two independent boot passes live here:
//! [`reconcile_pending_approve_attempts`] for the approve-attempt state
//! machine (audit-only) and [`reconcile_orphaned_staged_carriers`] for
//! staged-push carriers stranded without an outcome row (filesystem-
//! aware, because the bundle bytes live only in the staging store).
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
//!   so the operator sees it on the next boot, write a boot-observed
//!   marker so the reconciliation DAO will accept the row as a valid
//!   supersession predecessor (see comment on the
//!   `git_push_approve_attempt_boot_observed` table in migration
//!   0004), and leave the row itself in place for
//!   `reject_blocker_for_push` to surface as `AttemptInFlight`.
//!
//! The approve-attempt pass consults no filesystem state: for approve
//! attempts the audit log is the sole system of record. The schema's
//! forward-only triggers admit the `Started -> Resolved(PrePatchFailure)`
//! transition; this module is the only caller that does so for the
//! "broker restart" reason. The carrier pass, by contrast, must read the
//! staging directory — see [`reconcile_orphaned_staged_carriers`].

use crate::audit::{
    AUDIT_WRITE_FAILURE_TARGET, AuditError, AuditLog, GitPushApproveAttemptEntry,
    GitPushApproveAttemptState, GitPushOutcomeRecord, GitPushOutcomeResult,
};
use crate::core::{ApproveAttemptId, RequestId, UnixMillis};
use crate::git_push_staging::GitPushStagingStore;

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
/// socket path) but *before* any request handler can run (so the first
/// request to land sees a quiescent state).
///
/// Ordering is load-bearing against any other daemon configured
/// against the same socket: running this before the bind would let a
/// second `writd` racing the live daemon's startup mutate the shared
/// DB before its bind fails on `AddrInUse`, potentially resolving the
/// live process's legitimate in-flight `Started` attempt as a fake
/// "broker restart" failure. The bind is the singleton claim for the
/// socket path; this pass must come after it.
///
/// Single-writer-ness against the audit DB itself is an operator-config
/// invariant — "one daemon per `--audit-db`" — shared with the signing
/// key, agent-VM session ledger, and UI bearer-file writes. See the
/// matching comment in `src/bin/writd.rs` for the cross-cutting context.
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
                flag_uncertain(audit, &entry, now)?;
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
    // Schema CHECK: `completed_at IS NULL OR completed_at >= started_at`.
    // If the wall clock moved backwards between the original
    // `start_approve_attempt` and this boot, the supplied `now` can be
    // strictly earlier than `entry.started_at`, and the DAO write would
    // fail the CHECK. Clamping forward preserves the invariant that
    // completed_at is monotonic per-row without lying about wall-clock
    // time outside the recovered band — the row's own `started_at`
    // bounds the lie.
    let completed_at = std::cmp::max(now, entry.started_at);
    // A `Started` row whose mint ledger row exists died *after* the
    // credential was issued (typically mid-prepare: fetch, unbundle,
    // plan, object uploads). GitHub's branch is still provably
    // unchanged — nothing before the PATCH can move it — but the
    // credential was burned and may have uploaded unreferenced
    // objects. The resolve below copies the ledger mint onto the
    // resolved row on its own (and the schema refuses a resolve that
    // drops it); the read here is only so the operator's boot log
    // names the credential.
    if let Some(mint) = audit.attempt_recorded_mint(entry.attempt_id)? {
        tracing::warn!(
            attempt_id = %entry.attempt_id,
            push_request_id = %entry.push_request_id,
            jti = %mint.jti,
            "approve attempt recovered from Started with a burned credential on record; \
             resolving as PrePatchFailure carrying the recorded mint",
        );
    }
    audit.complete_attempt_pre_patch_failure(entry.attempt_id, BROKER_RESTART_DETAIL, completed_at)
}

fn flag_uncertain(
    audit: &AuditLog,
    entry: &GitPushApproveAttemptEntry,
    now: UnixMillis,
) -> Result<(), AuditError> {
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
    // Stamp the row as observed across a daemon restart. The
    // reconciliation DAO refuses to supersede an `Uncertain` predecessor
    // without this marker, since the in-process broker that originally
    // wrote the row may still be racing to complete it. Writing here
    // (after the broker socket bind, before any request handler runs)
    // is the only place where "this row has survived a boot cycle" can
    // be established. The DAO call is idempotent so a re-boot against
    // a still-Uncertain row is a no-op.
    audit.mark_attempt_boot_observed(entry.attempt_id, now)
}

/// Message recorded on the `git_push_outcome` row that
/// [`reconcile_orphaned_staged_carriers`] writes retroactively for a
/// carrier orphaned by a crash between staging and the outcome write.
/// Operators grep for it to distinguish recovered carriers from pushes
/// staged normally (`"staged for review"`). Part of the audit surface;
/// do not change without considering downstream tooling.
pub const RECOVERED_STAGED_CARRIER_MESSAGE: &str =
    "recovered: staged carrier without outcome row after restart";

/// Repair carriers left on disk without a `staged` outcome row by a
/// crash between the filesystem staging step and the outcome write in
/// `vm_http::git_push`.
///
/// Such a carrier is stuck: `check_approvable_push` refuses it (no
/// `staged` result) and `git_push_resolution_requires_staged` refuses
/// any reject, so it can be neither approved nor rejected while sitting
/// visibly in `promote list`. The push handler commits the request row
/// *before* staging and writes the carrier with an atomic fsync+rename,
/// so a carrier present under `staged/` is complete and is backed by a
/// request row; retroactively recording its `staged` outcome (the
/// PK-unique slot is still empty) is therefore honest and makes the
/// carrier resolvable again.
///
/// Returns the request ids recovered this pass. Unlike
/// [`reconcile_pending_approve_attempts`] this consults the filesystem:
/// the bundle bytes live only in the staging store, so for push carriers
/// the filesystem is co-authoritative with the audit log.
///
/// Failure policy mirrors the daemon's split between its two durable
/// stores. A staging-store `list()` IO error (e.g. a malformed sibling
/// directory) is **best-effort**: it is logged and the sweep returns
/// `Ok(vec![])`, because failing to sweep is no worse than the
/// pre-existing stuck-carrier state and a corrupt sibling must not wedge
/// boot. An audit **write** failure is correctness-fatal and propagates,
/// matching [`reconcile_pending_approve_attempts`].
///
/// Call once at startup, after the broker socket bind and before any
/// request handler runs — the same ordering constraints that govern
/// [`reconcile_pending_approve_attempts`].
pub fn reconcile_orphaned_staged_carriers(
    audit: &AuditLog,
    staging: &GitPushStagingStore,
    now: UnixMillis,
) -> Result<Vec<RequestId>, AuditError> {
    let carriers = match staging.list_entries_for_recovery() {
        Ok(carriers) => carriers,
        Err(err) => {
            // Only a failure to open `staged/` itself reaches here — a
            // genuinely broken staging root, not a torn sibling. Skip
            // best-effort rather than wedge boot; a misconfigured root is
            // an operator problem the daemon should still start to report.
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "boot_carrier_sweep_open",
                error = %err,
                "boot carrier sweep: could not open the staging tree; skipping",
            );
            return Ok(Vec::new());
        }
    };

    let mut recovered = Vec::new();
    for carrier in carriers {
        // Per-entry: a single malformed sibling (e.g. a torn directory
        // left by an interrupted `delete`) is skipped so it cannot hide
        // every healthy carrier. It is never "recovered" — a `staged`
        // outcome for a torn carrier would point at an unpromotable push.
        let receipt = match carrier {
            Ok(receipt) => receipt,
            Err(err) => {
                tracing::error!(
                    target: AUDIT_WRITE_FAILURE_TARGET,
                    kind = "boot_carrier_sweep_entry",
                    error = %err,
                    "boot carrier sweep: skipping an unreadable staged entry",
                );
                continue;
            }
        };
        let request_id = receipt.push_request_id();
        let Some(entry) = audit.get_git_push(request_id)? else {
            // A carrier with no request row. The handler commits the
            // request row before staging, so this is unreachable barring
            // external tampering; surface it rather than delete the
            // agent's bundle bytes.
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "boot_carrier_sweep_drift",
                push_request_id = %request_id,
                "boot carrier sweep: staged carrier has no audit request row; \
                 staging store and audit log have drifted apart",
            );
            continue;
        };

        if entry.resolution.is_some() {
            // A resolution can only exist when a `staged` outcome row
            // exists (the `git_push_resolution_requires_staged` trigger),
            // so `result` must be `Some(Staged)` here. A resolved push's
            // staging directory is the resolver's to clean up, not this
            // sweep's.
            if entry.result.is_none() {
                return Err(AuditError::Invariant(
                    "boot carrier sweep: carrier has a resolution but no outcome row",
                ));
            }
            continue;
        }

        match entry.result {
            None => {
                // The orphan this sweep exists to repair. Re-fsync the
                // carrier's directory entry first: `stage()`'s final
                // `fsync_dir` may have failed (leaving the rename visible
                // but not durable), and we must not record `staged` for a
                // carrier a later power loss could drop — that is exactly
                // the `staged`-without-carrier state this ordering
                // prevents. A fsync failure here means we cannot yet
                // guarantee durability, so skip and log rather than record
                // the outcome; a later boot retries.
                if let Err(err) = staging.ensure_carrier_durable(request_id) {
                    tracing::error!(
                        target: AUDIT_WRITE_FAILURE_TARGET,
                        kind = "boot_carrier_sweep_fsync",
                        push_request_id = %request_id,
                        error = %err,
                        "boot carrier sweep: could not make carrier durable before \
                         recording its outcome; leaving for a later boot",
                    );
                    continue;
                }
                audit.record_git_push_outcome(&GitPushOutcomeRecord {
                    push_request_id: request_id,
                    completed_at: now,
                    result: GitPushOutcomeResult::Staged,
                    github_status: None,
                    message: RECOVERED_STAGED_CARRIER_MESSAGE,
                })?;
                recovered.push(request_id);
            }
            Some(GitPushOutcomeResult::Staged) => {
                // Carrier plus a `staged` outcome: already consistent.
            }
            Some(other) => {
                // A terminal non-staged outcome (e.g. `Denied` from a
                // staging-content conflict) with a carrier still on disk.
                // Not this sweep's concern; surface it for the operator.
                tracing::debug!(
                    push_request_id = %request_id,
                    result = ?other,
                    "boot carrier sweep: carrier carries a terminal non-staged \
                     outcome; leaving in place",
                );
            }
        }
    }

    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        GitPushApproveAttemptOutcome, GitPushOutcomeRecord, GitPushOutcomeResult,
        GitPushRequestRecord, GitPushResolution, GitPushResolutionRecord, PromoteMintAudit,
    };
    use crate::core::{AgentKind, Jti, RepoRef, RequestId, SessionId, SessionRecord};
    use crate::vm_git::{GitCloneRepo, GitObjectId, VmGitPushMetadata};
    use tempfile::TempDir;
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

    /// The review scenario that motivated the v7 mint ledger: the
    /// broker mints, records the mint in the ledger, and crashes during
    /// the prepare phase (fetch/unbundle/plan/uploads) with the attempt
    /// still `Started`. Boot reconcile must resolve the row *carrying*
    /// the recorded mint — the credential was really issued and used
    /// for uploads against GitHub, and its identity must not be lost.
    #[test]
    fn started_attempt_with_recorded_mint_recovers_capturing_the_mint() {
        let (log, session_id) = open_log_with_session();
        let push_request_id = record_staged_push(&log, session_id);
        let attempt_id = ApproveAttemptId::new();
        log.start_approve_attempt(attempt_id, push_request_id, "alice", started_at())
            .unwrap();
        let mint = sample_mint();
        log.record_attempt_mint(attempt_id, mint, mint_issued_at())
            .unwrap();

        let report = reconcile_pending_approve_attempts(&log, now()).unwrap();
        assert_eq!(report.recovered_started, vec![attempt_id]);

        let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
        match &attempts[0].state {
            GitPushApproveAttemptState::Resolved {
                outcome,
                mint: resolved_mint,
                ..
            } => {
                assert_eq!(
                    *outcome,
                    GitPushApproveAttemptOutcome::PrePatchFailure {
                        detail: BROKER_RESTART_DETAIL.into(),
                    }
                );
                assert_eq!(
                    *resolved_mint,
                    Some(mint),
                    "the ledger-recorded mint must be captured on the resolved row",
                );
            }
            other => panic!("expected Resolved(PrePatchFailure), got {other:?}"),
        }
        // And the push is retryable / rejectable again, exactly like a
        // mint-less recovery.
        assert!(
            log.reject_blocker_for_push(push_request_id)
                .unwrap()
                .is_none(),
        );
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
    /// operator sees it in the boot logs AND stamp a boot-observed
    /// marker so the reconciliation DAO will accept the row as an
    /// eligible supersession predecessor on the next operator action.
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
        // The boot-observed marker is the load-bearing contract with
        // the reconciliation DAO: confirm operator reconciliation
        // against this row will now succeed (the DAO refuses Uncertain
        // predecessors without this marker — see
        // `reconciliation_refused_when_uncertain_predecessor_not_boot_observed`).
        log.record_reconciliation_attempt_not_applied(
            ApproveAttemptId::new(),
            attempt_id,
            "carol",
            "remote ref did not advance",
            UnixMillis::from_millis(1_700_001_500),
        )
        .expect("boot reconcile must have stamped the boot-observed marker");
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

    /// If the wall clock moved backwards between the original
    /// `start_approve_attempt` and this boot, the supplied `now` is
    /// earlier than `entry.started_at`. The reconcile must still
    /// succeed (the DB CHECK `completed_at >= started_at` would
    /// otherwise reject the write), and the recovered row's
    /// `completed_at` must be clamped to at least `started_at`.
    #[test]
    fn recover_clamps_now_below_started_at() {
        let (log, session_id) = open_log_with_session();
        let push_request_id = record_staged_push(&log, session_id);
        let attempt_id = ApproveAttemptId::new();
        let started_at_value = UnixMillis::from_millis(1_700_000_500);
        log.start_approve_attempt(attempt_id, push_request_id, "alice", started_at_value)
            .unwrap();

        let earlier_now = UnixMillis::from_millis(1_700_000_400);
        assert!(earlier_now < started_at_value);
        let report = reconcile_pending_approve_attempts(&log, earlier_now).unwrap();
        assert_eq!(report.recovered_started, vec![attempt_id]);

        let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
        match &attempts[0].state {
            GitPushApproveAttemptState::Resolved { completed_at, .. } => {
                assert_eq!(
                    *completed_at, started_at_value,
                    "clamp must pull completed_at up to started_at",
                );
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
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

    // ---- orphaned-carrier sweep ---------------------------------------

    fn open_staging() -> (GitPushStagingStore, TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = GitPushStagingStore::open(tmp.path().join("staging")).unwrap();
        (store, tmp)
    }

    fn sample_push_metadata() -> VmGitPushMetadata {
        VmGitPushMetadata::new(
            sample_repo(),
            "main".parse().unwrap(),
            Some(git_oid('1')),
            git_oid('2'),
        )
    }

    /// Record only the `git_push_request` row — the state the handler
    /// reaches *before* staging the carrier and *before* the outcome
    /// write. Mirrors `record_staged_push` minus the outcome row.
    fn record_push_request_only(log: &AuditLog, session_id: SessionId) -> RequestId {
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
        push_request_id
    }

    fn stage_carrier(staging: &GitPushStagingStore, request_id: RequestId) {
        staging
            .stage(
                request_id,
                UnixMillis::from_millis(1_700_000_120),
                sample_push_metadata(),
                b"bundle bytes".to_vec(),
            )
            .unwrap();
    }

    /// The core repair: a carrier on disk whose request row exists but
    /// whose `staged` outcome row never committed (crash between staging
    /// and the outcome write) is made resolvable by writing the outcome
    /// retroactively.
    #[test]
    fn orphaned_carrier_is_recovered_to_staged() {
        let (log, session_id) = open_log_with_session();
        let (staging, _tmp) = open_staging();
        let request_id = record_push_request_only(&log, session_id);
        stage_carrier(&staging, request_id);

        // Precondition: not resolvable — no outcome row.
        assert!(
            log.get_git_push(request_id)
                .unwrap()
                .unwrap()
                .result
                .is_none()
        );

        let recovered = reconcile_orphaned_staged_carriers(&log, &staging, now()).unwrap();
        assert_eq!(recovered, vec![request_id]);

        let entry = log.get_git_push(request_id).unwrap().unwrap();
        assert_eq!(entry.result, Some(GitPushOutcomeResult::Staged));
        assert_eq!(
            entry.message.as_deref(),
            Some(RECOVERED_STAGED_CARRIER_MESSAGE)
        );
        assert_eq!(entry.completed_at, Some(now()));
    }

    /// A carrier that already carries its `staged` outcome (the common
    /// case: no crash) is left untouched — the sweep neither rewrites
    /// the row (which would trip the PK) nor reports it.
    #[test]
    fn already_staged_carrier_is_left_untouched() {
        let (log, session_id) = open_log_with_session();
        let (staging, _tmp) = open_staging();
        let request_id = record_staged_push(&log, session_id);
        stage_carrier(&staging, request_id);

        let recovered = reconcile_orphaned_staged_carriers(&log, &staging, now()).unwrap();
        assert!(recovered.is_empty());

        // Outcome row is the original, not a rewrite.
        let entry = log.get_git_push(request_id).unwrap().unwrap();
        assert_eq!(entry.result, Some(GitPushOutcomeResult::Staged));
        assert_eq!(entry.message.as_deref(), Some("queued for review"));
    }

    /// A carrier with no audit request row at all (staging store and
    /// audit log drifted) is surfaced but not repaired: the sweep must
    /// not fabricate a `staged` outcome for a push it has no request row
    /// for, nor delete the agent's bundle.
    #[test]
    fn carrier_without_request_row_is_left_in_place() {
        let log = AuditLog::open_in_memory().unwrap();
        let (staging, _tmp) = open_staging();
        let request_id = RequestId::new();
        stage_carrier(&staging, request_id);

        let recovered = reconcile_orphaned_staged_carriers(&log, &staging, now()).unwrap();
        assert!(recovered.is_empty());
        assert!(log.get_git_push(request_id).unwrap().is_none());
    }

    #[test]
    fn empty_staging_store_recovers_nothing() {
        let log = AuditLog::open_in_memory().unwrap();
        let (staging, _tmp) = open_staging();
        let recovered = reconcile_orphaned_staged_carriers(&log, &staging, now()).unwrap();
        assert!(recovered.is_empty());
    }

    /// A `list()` IO failure (here: a malformed sibling directory under
    /// `staged/`) is best-effort — the sweep logs and returns empty
    /// rather than aborting startup.
    #[test]
    fn list_error_is_best_effort() {
        let log = AuditLog::open_in_memory().unwrap();
        let (staging, _tmp) = open_staging();
        std::fs::create_dir(staging.root().join("staged").join("not-a-uuid")).unwrap();

        let recovered = reconcile_orphaned_staged_carriers(&log, &staging, now()).unwrap();
        assert!(recovered.is_empty());
    }

    /// Recovered carriers are resolvable end to end: after the sweep
    /// writes the `staged` outcome, a reject resolution is admitted by
    /// the `git_push_resolution_requires_staged` trigger.
    #[test]
    fn recovered_carrier_is_rejectable() {
        let (log, session_id) = open_log_with_session();
        let (staging, _tmp) = open_staging();
        let request_id = record_push_request_only(&log, session_id);
        stage_carrier(&staging, request_id);

        reconcile_orphaned_staged_carriers(&log, &staging, now()).unwrap();

        // The reject path's audit write now succeeds where it would have
        // been refused before recovery.
        log.record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id: request_id,
            decided_at: now(),
            decision: GitPushResolution::Rejected,
            operator: "alice",
            reason: "not wanted",
        })
        .unwrap();
        assert!(
            log.get_git_push(request_id)
                .unwrap()
                .unwrap()
                .resolution
                .is_some()
        );
    }

    /// A persistent torn sibling (a carrier whose `entry.json` was
    /// removed, as an interrupted `delete` would leave) must not block
    /// recovery of a healthy orphan sitting next to it — and must never
    /// itself be recovered. Regression test for the all-or-nothing
    /// `list()` the sweep originally used.
    #[test]
    fn corrupt_sibling_does_not_block_recovery_of_a_valid_orphan() {
        let (log, session_id) = open_log_with_session();
        let (staging, _tmp) = open_staging();

        // Healthy orphan: request row + intact carrier, no outcome row.
        let valid = record_push_request_only(&log, session_id);
        stage_carrier(&staging, valid);

        // Torn sibling: a carrier whose receipt is gone. It has no audit
        // row and must be skipped, not recovered.
        let torn = RequestId::new();
        stage_carrier(&staging, torn);
        std::fs::remove_file(
            staging
                .root()
                .join("staged")
                .join(torn.to_string())
                .join("entry.json"),
        )
        .unwrap();

        let recovered = reconcile_orphaned_staged_carriers(&log, &staging, now()).unwrap();
        assert_eq!(
            recovered,
            vec![valid],
            "the healthy orphan must be recovered"
        );
        assert_eq!(
            log.get_git_push(valid).unwrap().unwrap().result,
            Some(GitPushOutcomeResult::Staged),
        );
        // The torn sibling was never given an outcome row.
        assert!(log.get_git_push(torn).unwrap().is_none());
    }
}
