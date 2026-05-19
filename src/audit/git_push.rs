//! VM Git push audit DAOs and row parsing.

use rusqlite::{OptionalExtension, Row, params};

use super::{AuditError, AuditLog};
use crate::agent_plan::CorrelationId;
use crate::core::{ApproveAttemptId, Jti, RequestId, SessionId, UnixMillis};
use crate::vm_git::{GitBranchName, GitCloneRepo, GitObjectId};

#[derive(Debug)]
pub struct GitPushRequestRecord {
    pub push_request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub repo: GitCloneRepo,
    pub branch: GitBranchName,
    /// `None` records "the agent expects this push to create the branch":
    /// the staging path can preserve that distinction and the promotion
    /// path will fail-closed if a remote branch later appears.
    pub expected_remote_head: Option<GitObjectId>,
    pub new_head: GitObjectId,
    /// Opaque caller-supplied correlation id, threaded from the
    /// originating agent run when the push was authorised. `None` for
    /// pushes that were not tagged. See
    /// `docs/plans/2026-05-11-agent-plans.md` ("Correlation ID").
    pub correlation_id: Option<CorrelationId>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitPushOutcomeResult {
    Denied,
    ValidationFailed,
    Staged,
}

#[derive(Debug)]
pub struct GitPushOutcomeRecord<'a> {
    pub push_request_id: RequestId,
    pub completed_at: UnixMillis,
    pub result: GitPushOutcomeResult,
    pub github_status: Option<u16>,
    pub message: &'a str,
}

/// Mint context captured when an approval issues a GitHub App
/// installation token. Stored inline with the resolution row because
/// the originating session is closed by the time the operator decides,
/// so this mint cannot be threaded through the session-scoped
/// `request` / `grant_log` audit chain. The four fields together
/// answer "did this approval ever produce a credential, and which
/// one?" without a session-graph join.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PromoteMintAudit {
    pub jti: Jti,
    pub github_app_id: u64,
    pub issued_at: UnixMillis,
    pub expires_at: UnixMillis,
}

/// Operator decision on a staged push. `Approved` carries the mint
/// context the broker captured while issuing the installation token
/// used to promote the push; the schema's BEFORE-INSERT/UPDATE trigger
/// enforces that the column-level shape (all four mint columns NOT
/// NULL ↔ approved, all NULL ↔ rejected) matches this variant.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GitPushResolution {
    Rejected,
    Approved(PromoteMintAudit),
}

#[derive(Debug)]
pub struct GitPushResolutionRecord<'a> {
    pub push_request_id: RequestId,
    pub decided_at: UnixMillis,
    pub decision: GitPushResolution,
    pub operator: &'a str,
    pub reason: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitPushResolutionEntry {
    pub decided_at: UnixMillis,
    pub decision: GitPushResolution,
    pub operator: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitPushAuditEntry {
    pub push_request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub repo: GitCloneRepo,
    pub branch: GitBranchName,
    pub expected_remote_head: Option<GitObjectId>,
    pub new_head: GitObjectId,
    /// Correlation id recorded against the originating push request.
    /// `None` when the request was untagged.
    pub correlation_id: Option<CorrelationId>,
    pub completed_at: Option<UnixMillis>,
    pub result: Option<GitPushOutcomeResult>,
    pub github_status: Option<u16>,
    pub message: Option<String>,
    /// `Some` once an operator has recorded a decision against the
    /// staged push. The schema's `BEFORE INSERT` trigger makes this
    /// field reachable only when `result == Some(GitPushOutcomeResult::Staged)`.
    pub resolution: Option<GitPushResolutionEntry>,
}

/// Terminal outcome of an operator approve attempt. Mirrors the
/// `outcome` enum on `git_push_approve_attempt` and the CHECK
/// constraints that govern the row's shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitPushApproveAttemptOutcome {
    /// `update_ref` confirmed the GitHub branch was advanced to
    /// `new_app_tip`. Paired with a `git_push_resolution(decision='approved')`
    /// row written in the same transaction.
    Succeeded { new_app_tip: GitObjectId },
    /// The attempt failed before `update_ref` was issued. The GitHub
    /// branch is provably unchanged; the push remains rejectable /
    /// retryable. `detail` is recorded verbatim in `failure_detail`.
    PrePatchFailure { detail: String },
    /// `update_ref` was issued but the broker cannot prove whether
    /// GitHub honoured it (non-2xx response, transport drop, audit-write
    /// failure after success). The push is quarantined: reject is
    /// refused until manual operator reconciliation completes the
    /// attempt to `Succeeded` or `PrePatchFailure`. `detail` is recorded
    /// verbatim in `failure_detail`.
    PostPatchFailure { detail: String },
}

/// Lifecycle state of a `git_push_approve_attempt` row. Forward-only:
/// `Started → Uncertain → Resolved` or `Started → Resolved` (with
/// `PrePatchFailure`). The schema's `git_push_approve_attempt_forward_only`
/// trigger enforces this at the DB layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitPushApproveAttemptState {
    /// Written on entry to `approve_staged_push`, before mint or any
    /// orchestration. Carries operator and started_at; no mint context yet.
    Started,
    /// Written in the same TX that completes the post-walker lease
    /// check, immediately before `update_ref`. Carries the mint context
    /// the broker is about to use. Once this row commits the broker has
    /// promised "the PATCH may exist on GitHub"; reject is refused.
    Uncertain { mint: PromoteMintAudit },
    /// Terminal. Carries the outcome + the mint context if one was
    /// captured (always present for `Succeeded` and `PostPatchFailure`,
    /// always absent for `PrePatchFailure` that fell before mint, and
    /// optionally present for a `PrePatchFailure` that happened
    /// between mint and update_ref).
    Resolved {
        outcome: GitPushApproveAttemptOutcome,
        mint: Option<PromoteMintAudit>,
        completed_at: UnixMillis,
    },
}

/// A `git_push_approve_attempt` row read back from the audit log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitPushApproveAttemptEntry {
    pub attempt_id: ApproveAttemptId,
    pub push_request_id: RequestId,
    pub operator: String,
    pub started_at: UnixMillis,
    pub state: GitPushApproveAttemptState,
}

/// Whether a staged push has any approve attempt that prevents it from
/// being rejected. Returned by [`AuditLog::reject_blocker_for_push`];
/// the reject handler maps this into the reject-vs-refuse decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RejectBlocker {
    /// At least one attempt is `Started` or `Uncertain` — the prior
    /// approve has not finished. Reject must wait for it to resolve
    /// (or for boot reconcile to drive a stale `Started` to
    /// `PrePatchFailure`).
    AttemptInFlight { attempt_id: ApproveAttemptId },
    /// At least one attempt is `Resolved(Succeeded)`. The push is
    /// already approved; reject is logically impossible.
    AlreadyApproved { attempt_id: ApproveAttemptId },
    /// At least one attempt is `Resolved(PostPatchFailure)`. The
    /// GitHub state is uncertain; reject is refused until manual
    /// reconciliation drives the attempt to a definite outcome.
    PostPatchUncertain { attempt_id: ApproveAttemptId },
}

/// LEFT JOIN view of one staged push by `push_request_id`. Mirrors
/// `GIT_PUSH_AUDIT_ENTRY_BY_SESSION_SQL` minus the session-wide
/// `ORDER BY` clause. Schema v5 dropped `git_push_attempt` so this
/// view no longer joins on it; outcome columns alone describe the
/// broker-visible request lifecycle and `git_push_resolution` carries
/// the operator decision.
const GIT_PUSH_AUDIT_ENTRY_BY_REQUEST_SQL: &str = "
    SELECT
        r.push_request_id,
        r.session_id,
        r.received_at,
        r.repo,
        r.branch,
        r.expected_remote_head,
        r.new_head AS request_new_head,
        r.correlation_id,
        o.completed_at,
        o.result,
        o.github_status,
        o.message,
        res.decided_at,
        res.decision,
        res.operator,
        res.reason,
        res.mint_jti,
        res.mint_github_app_id,
        res.mint_issued_at,
        res.mint_expires_at
    FROM git_push_request r
    LEFT JOIN git_push_outcome o ON o.push_request_id = r.push_request_id
    LEFT JOIN git_push_resolution res ON res.push_request_id = r.push_request_id
    WHERE r.push_request_id = ?1
";

/// LEFT JOIN view of every staged push in one session, ordered by
/// arrival so callers can read the staged-push timeline.
const GIT_PUSH_AUDIT_ENTRY_BY_SESSION_SQL: &str = "
    SELECT
        r.push_request_id,
        r.session_id,
        r.received_at,
        r.repo,
        r.branch,
        r.expected_remote_head,
        r.new_head AS request_new_head,
        r.correlation_id,
        o.completed_at,
        o.result,
        o.github_status,
        o.message,
        res.decided_at,
        res.decision,
        res.operator,
        res.reason,
        res.mint_jti,
        res.mint_github_app_id,
        res.mint_issued_at,
        res.mint_expires_at
    FROM git_push_request r
    LEFT JOIN git_push_outcome o ON o.push_request_id = r.push_request_id
    LEFT JOIN git_push_resolution res ON res.push_request_id = r.push_request_id
    WHERE r.session_id = ?1
    ORDER BY r.received_at ASC, r.rowid ASC
";

/// Internal projection of the columns `complete_attempt_succeeded`
/// needs to copy from the attempt row into the resolution row. Held
/// only inside the joint transaction, so it does not appear in the
/// public types.
struct ApproveAttemptMintRow {
    state: String,
    push_request_id: String,
    mint_jti: Option<String>,
    mint_app: Option<i64>,
    mint_iat: Option<i64>,
    mint_exp: Option<i64>,
}

impl AuditLog {
    /// Persist a parsed VM Git push request before any credential mint,
    /// remote fetch, or external push is attempted.
    pub fn record_git_push_request(&self, r: &GitPushRequestRecord) -> Result<(), AuditError> {
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let session_closed_at: Option<Option<i64>> = tx
                .query_row(
                    "SELECT closed_at FROM session WHERE session_id = ?1",
                    params![r.session_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            match session_closed_at {
                None => return Err(AuditError::Invariant("session does not exist")),
                Some(Some(_)) => return Err(AuditError::Invariant("session is closed")),
                Some(None) => {}
            }

            tx.execute(
                "INSERT INTO git_push_request (
                     push_request_id,
                     session_id,
                     received_at,
                     repo,
                     branch,
                     expected_remote_head,
                     new_head,
                     correlation_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    r.push_request_id.as_uuid().to_string(),
                    r.session_id.as_uuid().to_string(),
                    r.received_at.as_millis(),
                    r.repo.to_string(),
                    r.branch.as_str(),
                    r.expected_remote_head.as_ref().map(GitObjectId::as_str),
                    r.new_head.as_str(),
                    r.correlation_id.as_ref().map(CorrelationId::as_str),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Append the terminal broker-visible result for a VM Git push request.
    /// This is permitted after session close because the request was accepted
    /// while the session was open. After the v5 schema, the only results
    /// the schema admits are `denied`, `validation_failed`, and `staged`;
    /// the post-promote terminal states are recorded against
    /// `git_push_approve_attempt` instead.
    pub fn record_git_push_outcome(&self, r: &GitPushOutcomeRecord<'_>) -> Result<(), AuditError> {
        if r.message.is_empty() {
            return Err(AuditError::Invariant(
                "git push outcome message must not be empty",
            ));
        }
        if let Some(status) = r.github_status
            && !(100..=599).contains(&status)
        {
            return Err(AuditError::Invariant(
                "git push outcome GitHub status must be 100..599",
            ));
        }

        self.with_conn_mut(|c| {
            c.execute(
                "INSERT INTO git_push_outcome (
                     push_request_id,
                     completed_at,
                     result,
                     github_status,
                     message
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    r.push_request_id.as_uuid().to_string(),
                    r.completed_at.as_millis(),
                    r.result.as_str(),
                    r.github_status.map(i64::from),
                    r.message,
                ],
            )?;
            Ok(())
        })
    }

    /// Persist an operator decision on a staged push. The v13 schema's
    /// `BEFORE INSERT` trigger requires `git_push_outcome.result = 'staged'`
    /// for this request id, and the table's primary key prevents a
    /// second decision being recorded — both constraints surface as
    /// `AuditError::Sqlite`. The caller is responsible for empty-string
    /// rejection so callers see a clean `Invariant` message instead of
    /// a raw SQL CHECK violation.
    pub fn record_git_push_resolution(
        &self,
        r: &GitPushResolutionRecord<'_>,
    ) -> Result<(), AuditError> {
        if r.operator.is_empty() {
            return Err(AuditError::Invariant(
                "git push resolution operator must not be empty",
            ));
        }
        if r.reason.is_empty() {
            return Err(AuditError::Invariant(
                "git push resolution reason must not be empty",
            ));
        }

        let (mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at) = match r.decision {
            GitPushResolution::Rejected => (None, None, None, None),
            GitPushResolution::Approved(audit) => {
                let github_app_id = i64::try_from(audit.github_app_id).map_err(|_| {
                    AuditError::Invariant(
                        "git push resolution mint github_app_id exceeds SQLite integer",
                    )
                })?;
                (
                    Some(audit.jti.as_uuid().to_string()),
                    Some(github_app_id),
                    Some(audit.issued_at.as_millis()),
                    Some(audit.expires_at.as_millis()),
                )
            }
        };

        self.with_conn_mut(|c| {
            c.execute(
                "INSERT INTO git_push_resolution (
                     push_request_id,
                     decided_at,
                     decision,
                     operator,
                     reason,
                     mint_jti,
                     mint_github_app_id,
                     mint_issued_at,
                     mint_expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    r.push_request_id.as_uuid().to_string(),
                    r.decided_at.as_millis(),
                    r.decision.kind_str(),
                    r.operator,
                    r.reason,
                    mint_jti,
                    mint_github_app_id,
                    mint_issued_at,
                    mint_expires_at,
                ],
            )?;
            Ok(())
        })
    }

    /// Fetch the joined audit view for one VM Git push by request id, or
    /// `None` if no request row has been recorded. Promote tooling uses
    /// this to attach session and outcome context to a staged push that
    /// the operator looked up by id.
    pub fn get_git_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<Option<GitPushAuditEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(GIT_PUSH_AUDIT_ENTRY_BY_REQUEST_SQL)?;
            let row = stmt
                .query_row(
                    params![push_request_id.as_uuid().to_string()],
                    git_push_audit_entry_from_row,
                )
                .optional()?;
            row.transpose()
        })
    }

    pub fn list_git_pushes_for_session(
        &self,
        id: SessionId,
    ) -> Result<Vec<GitPushAuditEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(GIT_PUSH_AUDIT_ENTRY_BY_SESSION_SQL)?;
            let rows = stmt
                .query_map(
                    params![id.as_uuid().to_string()],
                    git_push_audit_entry_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }

    /// Insert a fresh `Started` approve attempt against a staged push.
    /// Required preconditions: the request row exists and has a
    /// `Staged` outcome row (the v3 trigger
    /// `git_push_resolution_requires_staged` reaches the same shape from
    /// the resolution side; this DAO mirrors that for attempts so an
    /// attempt cannot land for a push the audit log never observed
    /// staged).
    pub fn start_approve_attempt(
        &self,
        attempt_id: ApproveAttemptId,
        push_request_id: RequestId,
        operator: &str,
        started_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if operator.is_empty() {
            return Err(AuditError::Invariant(
                "approve attempt operator must not be empty",
            ));
        }
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let staged: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM git_push_outcome
                     WHERE push_request_id = ?1 AND result = 'staged'",
                    params![push_request_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if staged.is_none() {
                return Err(AuditError::Invariant(
                    "approve attempt requires staged outcome",
                ));
            }
            // A resolution row (approved *or* rejected) already exists
            // for this push. Permitting a new attempt would let the
            // approve path advance GitHub against a push the audit log
            // has already declared terminal: the `complete_attempt_*`
            // joint TX would later fail the resolution PK INSERT, but
            // by then `update_ref` may already have run. Refuse here.
            let resolution: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM git_push_resolution
                     WHERE push_request_id = ?1",
                    params![push_request_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if resolution.is_some() {
                return Err(AuditError::Invariant(
                    "approve attempt refused: push already has a resolution",
                ));
            }

            tx.execute(
                "INSERT INTO git_push_approve_attempt (
                     attempt_id, push_request_id, operator, started_at,
                     state, outcome, completed_at, new_app_tip, failure_detail,
                     mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                 ) VALUES (?1, ?2, ?3, ?4, 'started',
                           NULL, NULL, NULL, NULL,
                           NULL, NULL, NULL, NULL)",
                params![
                    attempt_id.as_uuid().to_string(),
                    push_request_id.as_uuid().to_string(),
                    operator,
                    started_at.as_millis(),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Transition a `Started` attempt to `Uncertain`, persisting the
    /// captured mint context. Called immediately before issuing the
    /// GitHub `update_ref` PATCH: once this commit lands the broker
    /// owes the audit log a `Resolved` row, and reject must be refused
    /// in the interim.
    pub fn mark_attempt_uncertain(
        &self,
        attempt_id: ApproveAttemptId,
        mint: PromoteMintAudit,
    ) -> Result<(), AuditError> {
        let github_app_id = i64::try_from(mint.github_app_id).map_err(|_| {
            AuditError::Invariant("approve attempt mint github_app_id exceeds SQLite integer")
        })?;
        self.with_conn_mut(|c| {
            let updated = c.execute(
                "UPDATE git_push_approve_attempt
                    SET state = 'uncertain',
                        mint_jti = ?2,
                        mint_github_app_id = ?3,
                        mint_issued_at = ?4,
                        mint_expires_at = ?5
                  WHERE attempt_id = ?1
                    AND state = 'started'",
                params![
                    attempt_id.as_uuid().to_string(),
                    mint.jti.as_uuid().to_string(),
                    github_app_id,
                    mint.issued_at.as_millis(),
                    mint.expires_at.as_millis(),
                ],
            )?;
            if updated == 0 {
                return Err(AuditError::Invariant(
                    "approve attempt is not in 'started' state",
                ));
            }
            Ok(())
        })
    }

    /// Atomically complete an `Uncertain` attempt as `Succeeded` *and*
    /// write the matching `git_push_resolution(decision='approved')`
    /// row. This is the load-bearing transactional commit of the
    /// approve workflow: the audit log either records the full
    /// approval (attempt resolved + resolution row) or neither side
    /// commits. The resolution row's mint columns are derived from the
    /// attempt's stored mint to guarantee they agree.
    pub fn complete_attempt_succeeded(
        &self,
        attempt_id: ApproveAttemptId,
        new_app_tip: &GitObjectId,
        operator: &str,
        reason: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if operator.is_empty() {
            return Err(AuditError::Invariant(
                "approve resolution operator must not be empty",
            ));
        }
        if reason.is_empty() {
            return Err(AuditError::Invariant(
                "approve resolution reason must not be empty",
            ));
        }

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            // Load the current attempt row inside the TX so the
            // resolution row is written from the same mint context that
            // the attempt records.
            let row = tx
                .query_row(
                    "SELECT state, push_request_id,
                            mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                       FROM git_push_approve_attempt
                      WHERE attempt_id = ?1",
                    params![attempt_id.as_uuid().to_string()],
                    |row| {
                        Ok(ApproveAttemptMintRow {
                            state: row.get(0)?,
                            push_request_id: row.get(1)?,
                            mint_jti: row.get(2)?,
                            mint_app: row.get(3)?,
                            mint_iat: row.get(4)?,
                            mint_exp: row.get(5)?,
                        })
                    },
                )
                .optional()?;
            let Some(ApproveAttemptMintRow {
                state,
                push_request_id,
                mint_jti,
                mint_app,
                mint_iat,
                mint_exp,
            }) = row
            else {
                return Err(AuditError::Invariant("approve attempt does not exist"));
            };
            if state != "uncertain" {
                return Err(AuditError::Invariant(
                    "approve attempt is not in 'uncertain' state",
                ));
            }
            let (Some(mint_jti), Some(mint_app), Some(mint_iat), Some(mint_exp)) =
                (mint_jti, mint_app, mint_iat, mint_exp)
            else {
                return Err(AuditError::Invariant(
                    "approve attempt 'uncertain' row is missing mint context",
                ));
            };

            tx.execute(
                "UPDATE git_push_approve_attempt
                    SET state = 'resolved',
                        outcome = 'succeeded',
                        new_app_tip = ?2,
                        completed_at = ?3
                  WHERE attempt_id = ?1",
                params![
                    attempt_id.as_uuid().to_string(),
                    new_app_tip.as_str(),
                    completed_at.as_millis(),
                ],
            )?;

            tx.execute(
                "INSERT INTO git_push_resolution (
                     push_request_id, decided_at, decision, operator, reason,
                     mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                 ) VALUES (?1, ?2, 'approved', ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    push_request_id,
                    completed_at.as_millis(),
                    operator,
                    reason,
                    mint_jti,
                    mint_app,
                    mint_iat,
                    mint_exp,
                ],
            )?;

            tx.commit()?;
            Ok(())
        })
    }

    /// Complete a `Started` or `Uncertain` attempt as
    /// `PrePatchFailure`. The schema's forward-only trigger allows this
    /// transition from either non-terminal state; the DAO does the
    /// matching state check before issuing the UPDATE so an attempt
    /// that has already resolved produces a readable invariant error
    /// instead of a silent no-op.
    pub fn complete_attempt_pre_patch_failure(
        &self,
        attempt_id: ApproveAttemptId,
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        self.complete_attempt_failure(
            attempt_id,
            "pre_patch_failure",
            &["started", "uncertain"],
            detail,
            completed_at,
        )
    }

    /// Complete an `Uncertain` attempt as `PostPatchFailure`. Only
    /// admitted from `uncertain` — `started` cannot reach this state
    /// because no PATCH could have been issued yet.
    pub fn complete_attempt_post_patch_failure(
        &self,
        attempt_id: ApproveAttemptId,
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        self.complete_attempt_failure(
            attempt_id,
            "post_patch_failure",
            &["uncertain"],
            detail,
            completed_at,
        )
    }

    fn complete_attempt_failure(
        &self,
        attempt_id: ApproveAttemptId,
        outcome: &'static str,
        allowed_states: &[&'static str],
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if detail.is_empty() {
            return Err(AuditError::Invariant(
                "approve attempt failure detail must not be empty",
            ));
        }
        // SQLite CHECK forbids `failure_detail = ''` but a caller-supplied
        // string with whitespace-only content would pass; we keep the
        // strict empty-string check at the DAO boundary as a thin
        // sanity net. The `not empty` guard is intentionally tight; the
        // schema allows any non-empty string.

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let current_state: Option<String> = tx
                .query_row(
                    "SELECT state FROM git_push_approve_attempt WHERE attempt_id = ?1",
                    params![attempt_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(state) = current_state else {
                return Err(AuditError::Invariant("approve attempt does not exist"));
            };
            if !allowed_states.contains(&state.as_str()) {
                return Err(AuditError::Invariant(
                    "approve attempt is not in a state that admits this failure outcome",
                ));
            }

            tx.execute(
                "UPDATE git_push_approve_attempt
                    SET state = 'resolved',
                        outcome = ?2,
                        failure_detail = ?3,
                        completed_at = ?4
                  WHERE attempt_id = ?1",
                params![
                    attempt_id.as_uuid().to_string(),
                    outcome,
                    detail,
                    completed_at.as_millis(),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Return every approve-attempt row for one staged push, ordered
    /// by `started_at` ascending (then by attempt_id as a stable
    /// tiebreaker for the rare same-millisecond case). The reject
    /// handler and boot reconcile both consume this view.
    pub fn approve_attempts_for_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<Vec<GitPushApproveAttemptEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT attempt_id, push_request_id, operator, started_at,
                        state, outcome, completed_at,
                        new_app_tip, failure_detail,
                        mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                   FROM git_push_approve_attempt
                  WHERE push_request_id = ?1
                  ORDER BY started_at ASC, attempt_id ASC",
            )?;
            let rows = stmt
                .query_map(
                    params![push_request_id.as_uuid().to_string()],
                    git_push_approve_attempt_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }

    /// First attempt (oldest by `started_at`) whose state prevents
    /// reject from succeeding. Returns `None` when reject is allowed
    /// (no attempts, or only `PrePatchFailure` attempts).
    pub fn reject_blocker_for_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<Option<RejectBlocker>, AuditError> {
        let attempts = self.approve_attempts_for_push(push_request_id)?;
        Ok(attempts
            .into_iter()
            .find_map(|attempt| match attempt.state {
                GitPushApproveAttemptState::Started
                | GitPushApproveAttemptState::Uncertain { .. } => {
                    Some(RejectBlocker::AttemptInFlight {
                        attempt_id: attempt.attempt_id,
                    })
                }
                GitPushApproveAttemptState::Resolved { outcome, .. } => match outcome {
                    GitPushApproveAttemptOutcome::Succeeded { .. } => {
                        Some(RejectBlocker::AlreadyApproved {
                            attempt_id: attempt.attempt_id,
                        })
                    }
                    GitPushApproveAttemptOutcome::PostPatchFailure { .. } => {
                        Some(RejectBlocker::PostPatchUncertain {
                            attempt_id: attempt.attempt_id,
                        })
                    }
                    GitPushApproveAttemptOutcome::PrePatchFailure { .. } => None,
                },
            }))
    }
}

impl GitPushOutcomeResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::ValidationFailed => "validation_failed",
            Self::Staged => "staged",
        }
    }

    fn from_str(raw: &str) -> Result<Self, AuditError> {
        match raw {
            "denied" => Ok(Self::Denied),
            "validation_failed" => Ok(Self::ValidationFailed),
            "staged" => Ok(Self::Staged),
            _ => Err(AuditError::Invariant(
                "Git push audit outcome result is invalid",
            )),
        }
    }
}

impl GitPushResolution {
    /// The decision kind as stored in `git_push_resolution.decision`.
    /// Pairs with the four mint columns (`mint_jti`, `mint_github_app_id`,
    /// `mint_issued_at`, `mint_expires_at`); the schema's trigger enforces
    /// that the kind and the column-presence shape agree.
    pub fn kind_str(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Approved(_) => "approved",
        }
    }

    /// Reconstruct a resolution from a row's `decision` column and the
    /// four mint columns. Returns an `Invariant` error if the kind /
    /// column-presence pairing is corrupt — the SQL trigger normally
    /// prevents that, but defence in depth at the parse boundary keeps
    /// downstream code from observing an impossible variant.
    fn from_row_parts(
        decision: &str,
        mint_jti: Option<String>,
        mint_github_app_id: Option<i64>,
        mint_issued_at: Option<i64>,
        mint_expires_at: Option<i64>,
    ) -> Result<Self, AuditError> {
        match decision {
            "rejected" => match (
                mint_jti,
                mint_github_app_id,
                mint_issued_at,
                mint_expires_at,
            ) {
                (None, None, None, None) => Ok(Self::Rejected),
                _ => Err(AuditError::Invariant(
                    "Git push audit row: rejected resolution carries mint context",
                )),
            },
            "approved" => {
                let jti_str = mint_jti.ok_or(AuditError::Invariant(
                    "Git push audit row: approved resolution missing mint jti",
                ))?;
                let jti = uuid::Uuid::parse_str(&jti_str)
                    .map(Jti::from_uuid)
                    .map_err(|_| {
                        AuditError::Invariant("Git push audit row: mint jti is not a uuid")
                    })?;
                let github_app_id_i64 = mint_github_app_id.ok_or(AuditError::Invariant(
                    "Git push audit row: approved resolution missing mint github_app_id",
                ))?;
                let github_app_id = u64::try_from(github_app_id_i64).map_err(|_| {
                    AuditError::Invariant("Git push audit row: mint github_app_id is negative")
                })?;
                let issued_at =
                    mint_issued_at
                        .map(UnixMillis::from_millis)
                        .ok_or(AuditError::Invariant(
                            "Git push audit row: approved resolution missing mint issued_at",
                        ))?;
                let expires_at =
                    mint_expires_at
                        .map(UnixMillis::from_millis)
                        .ok_or(AuditError::Invariant(
                            "Git push audit row: approved resolution missing mint expires_at",
                        ))?;
                Ok(Self::Approved(PromoteMintAudit {
                    jti,
                    github_app_id,
                    issued_at,
                    expires_at,
                }))
            }
            _ => Err(AuditError::Invariant(
                "Git push audit resolution decision is invalid",
            )),
        }
    }
}

fn git_push_audit_entry_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<Result<GitPushAuditEntry, AuditError>> {
    let push_request_id_str: String = row.get("push_request_id")?;
    let session_id_str: String = row.get("session_id")?;
    let received_at: i64 = row.get("received_at")?;
    let repo_str: String = row.get("repo")?;
    let branch_str: String = row.get("branch")?;
    let expected_remote_head_str: Option<String> = row.get("expected_remote_head")?;
    let new_head_str: String = row.get("request_new_head")?;
    let correlation_id_raw: Option<String> = row.get("correlation_id")?;
    let completed_at: Option<i64> = row.get("completed_at")?;
    let result_str: Option<String> = row.get("result")?;
    let github_status: Option<i64> = row.get("github_status")?;
    let message: Option<String> = row.get("message")?;
    let resolution_decided_at: Option<i64> = row.get("decided_at")?;
    let resolution_decision: Option<String> = row.get("decision")?;
    let resolution_operator: Option<String> = row.get("operator")?;
    let resolution_reason: Option<String> = row.get("reason")?;
    let resolution_mint_jti: Option<String> = row.get("mint_jti")?;
    let resolution_mint_github_app_id: Option<i64> = row.get("mint_github_app_id")?;
    let resolution_mint_issued_at: Option<i64> = row.get("mint_issued_at")?;
    let resolution_mint_expires_at: Option<i64> = row.get("mint_expires_at")?;

    let parse = || -> Result<GitPushAuditEntry, AuditError> {
        let push_request_id = uuid::Uuid::parse_str(&push_request_id_str)
            .map_err(|_| AuditError::Invariant("Git push audit row: request id not a uuid"))?;
        let session_id = uuid::Uuid::parse_str(&session_id_str)
            .map_err(|_| AuditError::Invariant("Git push audit row: session id not a uuid"))?;
        let repo = repo_str
            .parse::<GitCloneRepo>()
            .map_err(|_| AuditError::Invariant("Git push audit row: repo is invalid"))?;
        let branch = branch_str
            .parse::<GitBranchName>()
            .map_err(|_| AuditError::Invariant("Git push audit row: branch is invalid"))?;
        let expected_remote_head = expected_remote_head_str
            .map(|s| s.parse::<GitObjectId>())
            .transpose()
            .map_err(|_| {
                AuditError::Invariant("Git push audit row: expected remote head is invalid")
            })?;
        let new_head = new_head_str
            .parse::<GitObjectId>()
            .map_err(|_| AuditError::Invariant("Git push audit row: new head is invalid"))?;
        let correlation_id = correlation_id_raw
            .map(CorrelationId::try_new)
            .transpose()
            .map_err(|_| AuditError::Invariant("Git push audit row: correlation_id is invalid"))?;

        let (completed_at, result, message) = match (completed_at, result_str, message) {
            (None, None, None) => (None, None, None),
            (Some(completed_at), Some(result), Some(message)) if !message.is_empty() => (
                Some(UnixMillis::from_millis(completed_at)),
                Some(GitPushOutcomeResult::from_str(&result)?),
                Some(message),
            ),
            _ => {
                return Err(AuditError::Invariant(
                    "Git push audit row: incomplete outcome",
                ));
            }
        };
        let github_status = github_status
            .map(|value| {
                let status = u16::try_from(value).map_err(|_| {
                    AuditError::Invariant("Git push audit row: GitHub status out of range")
                })?;
                if !(100..=599).contains(&status) {
                    return Err(AuditError::Invariant(
                        "Git push audit row: GitHub status outside HTTP range",
                    ));
                }
                Ok(status)
            })
            .transpose()?;

        // The first four resolution columns are `NOT NULL`, so they
        // are either all present (joined row matched) or all absent
        // (no resolution recorded). Any partial state is corruption.
        // The mint columns are nullable and validated against the
        // decision kind by `GitPushResolution::from_row_parts`.
        let resolution = match (
            resolution_decided_at,
            resolution_decision,
            resolution_operator,
            resolution_reason,
        ) {
            (None, None, None, None) => None,
            (Some(decided_at), Some(decision), Some(operator), Some(reason)) => {
                let decision = GitPushResolution::from_row_parts(
                    &decision,
                    resolution_mint_jti,
                    resolution_mint_github_app_id,
                    resolution_mint_issued_at,
                    resolution_mint_expires_at,
                )?;
                Some(GitPushResolutionEntry {
                    decided_at: UnixMillis::from_millis(decided_at),
                    decision,
                    operator,
                    reason,
                })
            }
            _ => {
                return Err(AuditError::Invariant(
                    "Git push audit row: incomplete resolution",
                ));
            }
        };

        Ok(GitPushAuditEntry {
            push_request_id: RequestId::from_uuid(push_request_id),
            session_id: SessionId::from_uuid(session_id),
            received_at: UnixMillis::from_millis(received_at),
            repo,
            branch,
            expected_remote_head,
            new_head,
            correlation_id,
            completed_at,
            result,
            github_status,
            message,
            resolution,
        })
    };
    Ok(parse())
}

fn git_push_approve_attempt_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<Result<GitPushApproveAttemptEntry, AuditError>> {
    let attempt_id_str: String = row.get("attempt_id")?;
    let push_request_id_str: String = row.get("push_request_id")?;
    let operator: String = row.get("operator")?;
    let started_at: i64 = row.get("started_at")?;
    let state_str: String = row.get("state")?;
    let outcome_str: Option<String> = row.get("outcome")?;
    let completed_at: Option<i64> = row.get("completed_at")?;
    let new_app_tip_str: Option<String> = row.get("new_app_tip")?;
    let failure_detail: Option<String> = row.get("failure_detail")?;
    let mint_jti_str: Option<String> = row.get("mint_jti")?;
    let mint_github_app_id: Option<i64> = row.get("mint_github_app_id")?;
    let mint_issued_at: Option<i64> = row.get("mint_issued_at")?;
    let mint_expires_at: Option<i64> = row.get("mint_expires_at")?;

    let parse = || -> Result<GitPushApproveAttemptEntry, AuditError> {
        let attempt_id = uuid::Uuid::parse_str(&attempt_id_str)
            .map(ApproveAttemptId::from_uuid)
            .map_err(|_| AuditError::Invariant("approve attempt row: attempt id is not a uuid"))?;
        let push_request_id = uuid::Uuid::parse_str(&push_request_id_str)
            .map(RequestId::from_uuid)
            .map_err(|_| AuditError::Invariant("approve attempt row: request id is not a uuid"))?;
        let started_at = UnixMillis::from_millis(started_at);

        // Mint context is all-or-nothing per the schema CHECK; reconstruct
        // a single Option<PromoteMintAudit> here so the rest of the parse
        // can treat it as one value.
        let mint = match (
            mint_jti_str,
            mint_github_app_id,
            mint_issued_at,
            mint_expires_at,
        ) {
            (None, None, None, None) => None,
            (Some(jti_str), Some(app_id), Some(issued_at), Some(expires_at)) => {
                let jti = uuid::Uuid::parse_str(&jti_str)
                    .map(Jti::from_uuid)
                    .map_err(|_| {
                        AuditError::Invariant("approve attempt row: mint jti is not a uuid")
                    })?;
                let github_app_id = u64::try_from(app_id).map_err(|_| {
                    AuditError::Invariant("approve attempt row: mint github_app_id is negative")
                })?;
                Some(PromoteMintAudit {
                    jti,
                    github_app_id,
                    issued_at: UnixMillis::from_millis(issued_at),
                    expires_at: UnixMillis::from_millis(expires_at),
                })
            }
            _ => {
                return Err(AuditError::Invariant(
                    "approve attempt row: mint context is partially populated",
                ));
            }
        };

        let state = match state_str.as_str() {
            "started" => {
                if outcome_str.is_some()
                    || completed_at.is_some()
                    || new_app_tip_str.is_some()
                    || failure_detail.is_some()
                    || mint.is_some()
                {
                    return Err(AuditError::Invariant(
                        "approve attempt row: 'started' state must not carry terminal fields",
                    ));
                }
                GitPushApproveAttemptState::Started
            }
            "uncertain" => {
                let mint = mint.ok_or(AuditError::Invariant(
                    "approve attempt row: 'uncertain' state requires mint context",
                ))?;
                if outcome_str.is_some()
                    || completed_at.is_some()
                    || new_app_tip_str.is_some()
                    || failure_detail.is_some()
                {
                    return Err(AuditError::Invariant(
                        "approve attempt row: 'uncertain' state must not carry terminal fields",
                    ));
                }
                GitPushApproveAttemptState::Uncertain { mint }
            }
            "resolved" => {
                let outcome_str = outcome_str.ok_or(AuditError::Invariant(
                    "approve attempt row: 'resolved' state requires an outcome",
                ))?;
                let completed_at = completed_at.ok_or(AuditError::Invariant(
                    "approve attempt row: 'resolved' state requires completed_at",
                ))?;
                let outcome = match outcome_str.as_str() {
                    "succeeded" => {
                        let new_app_tip_str = new_app_tip_str.ok_or(AuditError::Invariant(
                            "approve attempt row: 'succeeded' outcome requires new_app_tip",
                        ))?;
                        let new_app_tip = new_app_tip_str.parse::<GitObjectId>().map_err(|_| {
                            AuditError::Invariant("approve attempt row: new_app_tip is invalid")
                        })?;
                        if failure_detail.is_some() {
                            return Err(AuditError::Invariant(
                                "approve attempt row: 'succeeded' outcome must not carry failure_detail",
                            ));
                        }
                        GitPushApproveAttemptOutcome::Succeeded { new_app_tip }
                    }
                    "pre_patch_failure" => {
                        let detail = failure_detail.ok_or(AuditError::Invariant(
                            "approve attempt row: failure outcome requires failure_detail",
                        ))?;
                        if new_app_tip_str.is_some() {
                            return Err(AuditError::Invariant(
                                "approve attempt row: failure outcome must not carry new_app_tip",
                            ));
                        }
                        GitPushApproveAttemptOutcome::PrePatchFailure { detail }
                    }
                    "post_patch_failure" => {
                        let detail = failure_detail.ok_or(AuditError::Invariant(
                            "approve attempt row: failure outcome requires failure_detail",
                        ))?;
                        if new_app_tip_str.is_some() {
                            return Err(AuditError::Invariant(
                                "approve attempt row: failure outcome must not carry new_app_tip",
                            ));
                        }
                        GitPushApproveAttemptOutcome::PostPatchFailure { detail }
                    }
                    _ => {
                        return Err(AuditError::Invariant(
                            "approve attempt row: outcome value is invalid",
                        ));
                    }
                };
                GitPushApproveAttemptState::Resolved {
                    outcome,
                    mint,
                    completed_at: UnixMillis::from_millis(completed_at),
                }
            }
            _ => {
                return Err(AuditError::Invariant(
                    "approve attempt row: state value is invalid",
                ));
            }
        };

        Ok(GitPushApproveAttemptEntry {
            attempt_id,
            push_request_id,
            operator,
            started_at,
            state,
        })
    };
    Ok(parse())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::sample_session;
    use crate::core::RepoRef;
    use proptest::prelude::*;

    fn sample_git_repo() -> GitCloneRepo {
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

    fn sample_git_push_request_record(
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

    fn record_staged_request(log: &AuditLog, push_request_id: RequestId, session_id: SessionId) {
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

    fn sample_promote_mint_audit() -> PromoteMintAudit {
        PromoteMintAudit {
            jti: Jti::new(),
            github_app_id: 42,
            issued_at: UnixMillis::from_millis(1_700_000_190),
            expires_at: UnixMillis::from_millis(1_700_000_490),
        }
    }

    // ---- request / outcome scaffolding still under test --------------------

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

    // ---- resolution scaffolding ---------------------------------------------

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

    // ---- approve-attempt state machine --------------------------------------

    fn open_with_staged_request(log: &AuditLog, push_request_id: RequestId) -> SessionId {
        let s = sample_session();
        log.open_session(&s).unwrap();
        record_staged_request(log, push_request_id, s.session_id);
        s.session_id
    }

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
            .complete_attempt_pre_patch_failure(
                attempt_id,
                "",
                UnixMillis::from_millis(1_700_000_210),
            )
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

    /// Property test: any sequence of legal DAO calls leaves the
    /// attempt in a state that the row parser can round-trip.
    ///
    /// We model "any legal sequence" as one of four scripts. Each script
    /// drives the attempt to a state explicitly, exercising every arrow
    /// of the state machine. The invariant: round-tripping the row
    /// through `approve_attempts_for_push` produces a state value that
    /// equals the one we expect.
    #[derive(Clone, Debug)]
    enum AttemptScript {
        Started,
        StartedToPrePatchFailure,
        Uncertain,
        UncertainToSucceeded,
        UncertainToPrePatchFailure,
        UncertainToPostPatchFailure,
    }

    fn attempt_script_strategy() -> impl Strategy<Value = AttemptScript> {
        prop_oneof![
            Just(AttemptScript::Started),
            Just(AttemptScript::StartedToPrePatchFailure),
            Just(AttemptScript::Uncertain),
            Just(AttemptScript::UncertainToSucceeded),
            Just(AttemptScript::UncertainToPrePatchFailure),
            Just(AttemptScript::UncertainToPostPatchFailure),
        ]
    }

    proptest! {
        #[test]
        fn approve_attempt_state_machine_roundtrips_through_dao(
            script in attempt_script_strategy(),
        ) {
            let log = AuditLog::open_in_memory().unwrap();
            let push_request_id = RequestId::new();
            let _session = open_with_staged_request(&log, push_request_id);
            let attempt_id = ApproveAttemptId::new();
            let started_at = UnixMillis::from_millis(1_700_000_200);
            log.start_approve_attempt(attempt_id, push_request_id, "alice", started_at)
                .unwrap();

            let mint = sample_promote_mint_audit();
            let new_app_tip = git_oid('a');
            let expected_state = match script {
                AttemptScript::Started => GitPushApproveAttemptState::Started,
                AttemptScript::StartedToPrePatchFailure => {
                    log.complete_attempt_pre_patch_failure(
                        attempt_id,
                        "no go",
                        UnixMillis::from_millis(1_700_000_210),
                    )
                    .unwrap();
                    GitPushApproveAttemptState::Resolved {
                        outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                            detail: "no go".into(),
                        },
                        mint: None,
                        completed_at: UnixMillis::from_millis(1_700_000_210),
                    }
                }
                AttemptScript::Uncertain => {
                    log.mark_attempt_uncertain(attempt_id, mint).unwrap();
                    GitPushApproveAttemptState::Uncertain { mint }
                }
                AttemptScript::UncertainToSucceeded => {
                    log.mark_attempt_uncertain(attempt_id, mint).unwrap();
                    log.complete_attempt_succeeded(
                        attempt_id,
                        &new_app_tip,
                        "alice",
                        "looks good",
                        UnixMillis::from_millis(1_700_000_220),
                    )
                    .unwrap();
                    GitPushApproveAttemptState::Resolved {
                        outcome: GitPushApproveAttemptOutcome::Succeeded {
                            new_app_tip: new_app_tip.clone(),
                        },
                        mint: Some(mint),
                        completed_at: UnixMillis::from_millis(1_700_000_220),
                    }
                }
                AttemptScript::UncertainToPrePatchFailure => {
                    log.mark_attempt_uncertain(attempt_id, mint).unwrap();
                    log.complete_attempt_pre_patch_failure(
                        attempt_id,
                        "aborted",
                        UnixMillis::from_millis(1_700_000_220),
                    )
                    .unwrap();
                    GitPushApproveAttemptState::Resolved {
                        outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                            detail: "aborted".into(),
                        },
                        mint: Some(mint),
                        completed_at: UnixMillis::from_millis(1_700_000_220),
                    }
                }
                AttemptScript::UncertainToPostPatchFailure => {
                    log.mark_attempt_uncertain(attempt_id, mint).unwrap();
                    log.complete_attempt_post_patch_failure(
                        attempt_id,
                        "transport drop",
                        UnixMillis::from_millis(1_700_000_220),
                    )
                    .unwrap();
                    GitPushApproveAttemptState::Resolved {
                        outcome: GitPushApproveAttemptOutcome::PostPatchFailure {
                            detail: "transport drop".into(),
                        },
                        mint: Some(mint),
                        completed_at: UnixMillis::from_millis(1_700_000_220),
                    }
                }
            };

            let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
            prop_assert_eq!(attempts.len(), 1);
            prop_assert_eq!(&attempts[0].state, &expected_state);
            prop_assert_eq!(attempts[0].attempt_id, attempt_id);
            prop_assert_eq!(attempts[0].started_at, started_at);
        }
    }
}
