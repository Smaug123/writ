//! VM Git push audit DAOs and row parsing.

use rusqlite::{OptionalExtension, Row, params};

use super::validation::{parse_required_jti, parse_required_request_id};
use super::{AuditError, AuditLog};
use crate::agent_plan::CorrelationId;
use crate::core::{GitHubAccess, GrantedScope, Jti, RequestId, SessionId, UnixMillis};
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

#[derive(Debug)]
pub struct GitPushAttemptRecord {
    pub push_attempt_id: RequestId,
    pub push_request_id: RequestId,
    pub capability_request_id: RequestId,
    pub grant_jti: Jti,
    pub planned_at: UnixMillis,
    pub repo: GitCloneRepo,
    pub branch: GitBranchName,
    /// `None` records a planned branch-creation push (no `--force-with-lease`
    /// target). Must agree with the originating request's
    /// `expected_remote_head`.
    pub old_head: Option<GitObjectId>,
    pub new_head: GitObjectId,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitPushOutcomeResult {
    Denied,
    ValidationFailed,
    Staged,
    Pushed,
    LeaseRejected,
    PushRejected,
    PushFailed,
    AuditFailedAfterPush,
}

#[derive(Debug)]
pub struct GitPushOutcomeRecord<'a> {
    pub push_request_id: RequestId,
    pub push_attempt_id: Option<RequestId>,
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
    pub push_attempt_id: Option<RequestId>,
    pub capability_request_id: Option<RequestId>,
    pub grant_jti: Option<Jti>,
    pub planned_at: Option<UnixMillis>,
    /// `None` if no attempt has been recorded *or* the attempt was a planned
    /// branch-creation push. `push_attempt_id` is the discriminant.
    pub old_head: Option<GitObjectId>,
    pub attempted_new_head: Option<GitObjectId>,
    pub completed_at: Option<UnixMillis>,
    pub result: Option<GitPushOutcomeResult>,
    pub github_status: Option<u16>,
    pub message: Option<String>,
    /// `Some` once an operator has recorded a decision against the
    /// staged push. The v13 schema's `BEFORE INSERT` trigger makes this
    /// field reachable only when `result == Some(GitPushOutcomeResult::Staged)`.
    pub resolution: Option<GitPushResolutionEntry>,
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

    /// Persist the exact push the broker is about to attempt. This must
    /// happen after host-side validation and before the external `git push`.
    pub fn record_git_push_attempt(&self, r: &GitPushAttemptRecord) -> Result<(), AuditError> {
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let push_request: Option<(String, String, String, Option<String>, String)> = tx
                .query_row(
                    "SELECT session_id, repo, branch, expected_remote_head, new_head
                     FROM git_push_request
                     WHERE push_request_id = ?1",
                    params![r.push_request_id.as_uuid().to_string()],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                push_session,
                request_repo,
                request_branch,
                request_old_head,
                request_new_head,
            )) = push_request
            else {
                return Err(AuditError::Invariant("git push request does not exist"));
            };

            let request_repo = request_repo
                .parse::<GitCloneRepo>()
                .map_err(|_| AuditError::Invariant("git push request repo is invalid"))?;
            if !request_repo.as_repo_ref().matches(r.repo.as_repo_ref()) {
                return Err(AuditError::Invariant(
                    "git push attempt repo differs from request",
                ));
            }
            // Branch refnames are case-sensitive. Unlike GitHub owner/repo
            // names, a case-only branch change can target a different ref.
            if request_branch != r.branch.as_str() {
                return Err(AuditError::Invariant(
                    "git push attempt branch differs from request",
                ));
            }
            let attempt_old_head = r.old_head.as_ref().map(GitObjectId::as_str);
            if request_old_head.as_deref() != attempt_old_head {
                return Err(AuditError::Invariant(
                    "git push attempt old head differs from request",
                ));
            }
            if request_new_head != r.new_head.as_str() {
                return Err(AuditError::Invariant(
                    "git push attempt new head differs from request",
                ));
            }

            let grant: Option<(String, String, String)> = tx
                .query_row(
                    "SELECT request_id, session_id, scope_json
                     FROM grant_log
                     WHERE jti = ?1",
                    params![r.grant_jti.as_uuid().to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((grant_request_id, grant_session_id, grant_scope_json)) = grant else {
                return Err(AuditError::Invariant("git push grant does not exist"));
            };
            if grant_request_id != r.capability_request_id.as_uuid().to_string() {
                return Err(AuditError::Invariant(
                    "git push grant is not for the recorded capability request",
                ));
            }
            if grant_session_id != push_session {
                return Err(AuditError::Invariant(
                    "git push grant session differs from push request session",
                ));
            }
            let scope: GrantedScope = serde_json::from_str(&grant_scope_json)?;
            match scope {
                GrantedScope::GitHub(scope)
                    if scope.repository.matches(r.repo.as_repo_ref())
                        && scope.permissions.contents == Some(GitHubAccess::Write) => {}
                GrantedScope::GitHub(_) => {
                    return Err(AuditError::Invariant(
                        "git push grant is not contents:write for the requested repo",
                    ));
                }
            }

            tx.execute(
                "INSERT INTO git_push_attempt (
                     push_attempt_id,
                     push_request_id,
                     capability_request_id,
                     grant_jti,
                     planned_at,
                     repo,
                     branch,
                     old_head,
                     new_head
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    r.push_attempt_id.as_uuid().to_string(),
                    r.push_request_id.as_uuid().to_string(),
                    r.capability_request_id.as_uuid().to_string(),
                    r.grant_jti.as_uuid().to_string(),
                    r.planned_at.as_millis(),
                    r.repo.to_string(),
                    r.branch.as_str(),
                    r.old_head.as_ref().map(GitObjectId::as_str),
                    r.new_head.as_str(),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Append the terminal broker-visible result for a VM Git push request.
    /// This is permitted after session close because the request was accepted
    /// while the session was open.
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
        if git_push_result_requires_attempt(r.result) && r.push_attempt_id.is_none() {
            return Err(AuditError::Invariant(
                "git push outcome result requires an attempt",
            ));
        }
        if !git_push_result_requires_attempt(r.result) && r.push_attempt_id.is_some() {
            return Err(AuditError::Invariant(
                "git push outcome result must not reference an attempt",
            ));
        }

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            if let Some(push_attempt_id) = r.push_attempt_id {
                let attempt_request_id: Option<String> = tx
                    .query_row(
                        "SELECT push_request_id
                         FROM git_push_attempt
                         WHERE push_attempt_id = ?1",
                        params![push_attempt_id.as_uuid().to_string()],
                        |row| row.get(0),
                    )
                    .optional()?;
                match attempt_request_id {
                    Some(id) if id == r.push_request_id.as_uuid().to_string() => {}
                    Some(_) => {
                        return Err(AuditError::Invariant(
                            "git push outcome attempt belongs to a different request",
                        ));
                    }
                    None => return Err(AuditError::Invariant("git push attempt does not exist")),
                }
            }

            tx.execute(
                "INSERT INTO git_push_outcome (
                     push_request_id,
                     push_attempt_id,
                     completed_at,
                     result,
                     github_status,
                     message
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    r.push_request_id.as_uuid().to_string(),
                    r.push_attempt_id.map(|id| id.as_uuid().to_string()),
                    r.completed_at.as_millis(),
                    r.result.as_str(),
                    r.github_status.map(i64::from),
                    r.message,
                ],
            )?;
            tx.commit()?;
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
            let mut stmt = c.prepare(
                "SELECT
                     r.push_request_id,
                     r.session_id,
                     r.received_at,
                     r.repo,
                     r.branch,
                     r.expected_remote_head,
                     r.new_head AS request_new_head,
                     r.correlation_id,
                     a.push_attempt_id,
                     a.capability_request_id,
                     a.grant_jti,
                     a.planned_at,
                     a.old_head,
                     a.new_head AS attempted_new_head,
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
                 LEFT JOIN git_push_attempt a ON a.push_request_id = r.push_request_id
                 LEFT JOIN git_push_outcome o ON o.push_request_id = r.push_request_id
                 LEFT JOIN git_push_resolution res ON res.push_request_id = r.push_request_id
                 WHERE r.push_request_id = ?1",
            )?;
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
            let mut stmt = c.prepare(
                "SELECT
                     r.push_request_id,
                     r.session_id,
                     r.received_at,
                     r.repo,
                     r.branch,
                     r.expected_remote_head,
                     r.new_head AS request_new_head,
                     r.correlation_id,
                     a.push_attempt_id,
                     a.capability_request_id,
                     a.grant_jti,
                     a.planned_at,
                     a.old_head,
                     a.new_head AS attempted_new_head,
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
                 LEFT JOIN git_push_attempt a ON a.push_request_id = r.push_request_id
                 LEFT JOIN git_push_outcome o ON o.push_request_id = r.push_request_id
                 LEFT JOIN git_push_resolution res ON res.push_request_id = r.push_request_id
                 WHERE r.session_id = ?1
                 ORDER BY r.received_at ASC, r.rowid ASC",
            )?;
            let rows = stmt
                .query_map(
                    params![id.as_uuid().to_string()],
                    git_push_audit_entry_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }
}

impl GitPushOutcomeResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::ValidationFailed => "validation_failed",
            Self::Staged => "staged",
            Self::Pushed => "pushed",
            Self::LeaseRejected => "lease_rejected",
            Self::PushRejected => "push_rejected",
            Self::PushFailed => "push_failed",
            Self::AuditFailedAfterPush => "audit_failed_after_push",
        }
    }

    fn from_str(raw: &str) -> Result<Self, AuditError> {
        match raw {
            "denied" => Ok(Self::Denied),
            "validation_failed" => Ok(Self::ValidationFailed),
            "staged" => Ok(Self::Staged),
            "pushed" => Ok(Self::Pushed),
            "lease_rejected" => Ok(Self::LeaseRejected),
            "push_rejected" => Ok(Self::PushRejected),
            "push_failed" => Ok(Self::PushFailed),
            "audit_failed_after_push" => Ok(Self::AuditFailedAfterPush),
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

fn git_push_result_requires_attempt(result: GitPushOutcomeResult) -> bool {
    matches!(
        result,
        GitPushOutcomeResult::Pushed
            | GitPushOutcomeResult::LeaseRejected
            | GitPushOutcomeResult::PushRejected
            | GitPushOutcomeResult::PushFailed
            | GitPushOutcomeResult::AuditFailedAfterPush
    )
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
    let push_attempt_id_str: Option<String> = row.get("push_attempt_id")?;
    let capability_request_id_str: Option<String> = row.get("capability_request_id")?;
    let grant_jti_str: Option<String> = row.get("grant_jti")?;
    let planned_at: Option<i64> = row.get("planned_at")?;
    let old_head_str: Option<String> = row.get("old_head")?;
    let attempted_new_head_str: Option<String> = row.get("attempted_new_head")?;
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

        // SQLite's `TEXT PRIMARY KEY` does not imply NOT NULL, so a
        // corrupt row could carry a NULL `push_attempt_id` alongside
        // populated attempt columns and the LEFT JOIN would still hit.
        // `capability_request_id` is `NOT NULL REFERENCES request(...)`,
        // so it is a sound presence signal; if the row really is joined,
        // the in-branch `parse_required_*` calls surface a specific
        // invariant error for any per-column NULL surprise (including a
        // NULL primary key). `old_head` is no longer a discriminator
        // because it represents "branch creation" when null.
        let (
            push_attempt_id,
            capability_request_id,
            grant_jti,
            planned_at,
            old_head,
            attempted_new_head,
        ) = if capability_request_id_str.is_some() {
            let push_attempt_id = parse_required_request_id(
                push_attempt_id_str,
                "Git push audit row: attempt id missing or invalid",
            )?;
            let capability_request_id = parse_required_request_id(
                capability_request_id_str,
                "Git push audit row: capability request id missing or invalid",
            )?;
            let grant_jti = parse_required_jti(
                grant_jti_str,
                "Git push audit row: grant jti missing or invalid",
            )?;
            let planned_at = planned_at.ok_or(AuditError::Invariant(
                "Git push audit row: planned_at missing",
            ))?;
            let old_head = old_head_str
                .map(|s| s.parse::<GitObjectId>())
                .transpose()
                .map_err(|_| AuditError::Invariant("Git push audit row: old head invalid"))?;
            let attempted_new_head = attempted_new_head_str
                .ok_or(AuditError::Invariant(
                    "Git push audit row: attempted new head missing",
                ))?
                .parse::<GitObjectId>()
                .map_err(|_| {
                    AuditError::Invariant("Git push audit row: attempted new head invalid")
                })?;
            (
                Some(push_attempt_id),
                Some(capability_request_id),
                Some(grant_jti),
                Some(UnixMillis::from_millis(planned_at)),
                old_head,
                Some(attempted_new_head),
            )
        } else {
            (None, None, None, None, None, None)
        };

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
            push_attempt_id,
            capability_request_id,
            grant_jti,
            planned_at,
            old_head,
            attempted_new_head,
            completed_at,
            result,
            github_status,
            message,
            resolution,
        })
    };
    Ok(parse())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::{pre_mint, record_sample_write_grant, sample_session};
    use crate::core::{
        CapabilityRequest, CredentialGrant, GitHubGrantedScope, GitHubPermissions, GitHubRequest,
        MetadataAccess, PolicyDecision, RepoRef, TtlSeconds,
    };
    use proptest::prelude::*;

    fn sample_git_repo() -> GitCloneRepo {
        GitCloneRepo::new(RepoRef {
            owner: "o".into(),
            name: "n".into(),
        })
        .unwrap()
    }

    fn git_repo(owner: &str, name: &str) -> GitCloneRepo {
        GitCloneRepo::new(RepoRef {
            owner: owner.into(),
            name: name.into(),
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

    fn git_push_attempt_record(
        push_attempt_id: RequestId,
        push_request_id: RequestId,
        capability_request_id: RequestId,
        grant_jti: Jti,
        repo: GitCloneRepo,
        branch: GitBranchName,
    ) -> GitPushAttemptRecord {
        GitPushAttemptRecord {
            push_attempt_id,
            push_request_id,
            capability_request_id,
            grant_jti,
            planned_at: UnixMillis::from_millis(1_700_000_120),
            repo,
            branch,
            old_head: Some(git_oid('1')),
            new_head: git_oid('2'),
        }
    }

    #[derive(Clone, Debug)]
    enum GitPushAuditScript {
        ValidAttempted {
            result: GitPushOutcomeResult,
            github_status: Option<u16>,
            close_before_outcome: bool,
            attempt_repo_case_differs: bool,
            /// `true` exercises the branch-creation path: request and
            /// attempt both record `None` for their respective heads.
            branch_creation: bool,
        },
        ValidUnattempted {
            result: GitPushOutcomeResult,
            close_before_outcome: bool,
            branch_creation: bool,
        },
        RequestAfterClose,
        AttemptBeforeRequest,
        AttemptMissingGrant,
        AttemptMismatchedRepo,
        AttemptMismatchedBranch,
        /// `request_has_head = true`: request records `Some`, attempt
        /// records `None`. `false`: request `None`, attempt `Some`.
        /// Either way the attempt must be rejected.
        AttemptHeadPresenceMismatch {
            request_has_head: bool,
        },
        OutcomeWithoutRequest,
        OutcomeRequiresAttemptWithoutAttempt {
            result: GitPushOutcomeResult,
        },
        OutcomeUnexpectedAttempt {
            result: GitPushOutcomeResult,
        },
        OutcomeDifferentRequest {
            result: GitPushOutcomeResult,
        },
    }

    fn attempted_git_push_result_strategy() -> impl Strategy<Value = GitPushOutcomeResult> {
        prop_oneof![
            Just(GitPushOutcomeResult::Pushed),
            Just(GitPushOutcomeResult::LeaseRejected),
            Just(GitPushOutcomeResult::PushRejected),
            Just(GitPushOutcomeResult::PushFailed),
            Just(GitPushOutcomeResult::AuditFailedAfterPush),
        ]
    }

    fn unattempted_git_push_result_strategy() -> impl Strategy<Value = GitPushOutcomeResult> {
        prop_oneof![
            Just(GitPushOutcomeResult::Denied),
            Just(GitPushOutcomeResult::ValidationFailed),
            Just(GitPushOutcomeResult::Staged),
        ]
    }

    fn github_status_strategy() -> impl Strategy<Value = Option<u16>> {
        prop_oneof![Just(None), (100u16..=599).prop_map(Some)]
    }

    fn git_push_audit_script_strategy() -> impl Strategy<Value = GitPushAuditScript> {
        prop_oneof![
            (
                attempted_git_push_result_strategy(),
                github_status_strategy(),
                any::<bool>(),
                any::<bool>(),
                any::<bool>(),
            )
                .prop_map(
                    |(
                        result,
                        github_status,
                        close_before_outcome,
                        attempt_repo_case_differs,
                        branch_creation,
                    )| {
                        GitPushAuditScript::ValidAttempted {
                            result,
                            github_status,
                            close_before_outcome,
                            attempt_repo_case_differs,
                            branch_creation,
                        }
                    },
                ),
            (
                unattempted_git_push_result_strategy(),
                any::<bool>(),
                any::<bool>(),
            )
                .prop_map(|(result, close_before_outcome, branch_creation)| {
                    GitPushAuditScript::ValidUnattempted {
                        result,
                        close_before_outcome,
                        branch_creation,
                    }
                }),
            Just(GitPushAuditScript::RequestAfterClose),
            Just(GitPushAuditScript::AttemptBeforeRequest),
            Just(GitPushAuditScript::AttemptMissingGrant),
            Just(GitPushAuditScript::AttemptMismatchedRepo),
            Just(GitPushAuditScript::AttemptMismatchedBranch),
            any::<bool>().prop_map(|request_has_head| {
                GitPushAuditScript::AttemptHeadPresenceMismatch { request_has_head }
            }),
            Just(GitPushAuditScript::OutcomeWithoutRequest),
            attempted_git_push_result_strategy().prop_map(|result| {
                GitPushAuditScript::OutcomeRequiresAttemptWithoutAttempt { result }
            },),
            unattempted_git_push_result_strategy()
                .prop_map(|result| GitPushAuditScript::OutcomeUnexpectedAttempt { result }),
            attempted_git_push_result_strategy()
                .prop_map(|result| GitPushAuditScript::OutcomeDifferentRequest { result }),
        ]
    }

    #[test]
    fn git_push_request_attempt_and_outcome_roundtrip() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let push_request_id = RequestId::new();
        let push_request = sample_git_push_request_record(push_request_id, s.session_id);
        log.record_git_push_request(&push_request).unwrap();

        let capability_request_id = RequestId::new();
        let grant = record_sample_write_grant(&log, s.session_id, capability_request_id);
        let push_attempt_id = RequestId::new();
        log.record_git_push_attempt(&GitPushAttemptRecord {
            push_attempt_id,
            push_request_id,
            capability_request_id,
            grant_jti: grant.jti,
            planned_at: UnixMillis::from_millis(1_700_000_120),
            repo: sample_git_repo(),
            branch: "main".parse().unwrap(),
            old_head: Some(git_oid('1')),
            new_head: git_oid('2'),
        })
        .unwrap();
        log.record_git_push_outcome(&GitPushOutcomeRecord {
            push_request_id,
            push_attempt_id: Some(push_attempt_id),
            completed_at: UnixMillis::from_millis(1_700_000_130),
            result: GitPushOutcomeResult::Pushed,
            github_status: None,
            message: "pushed",
        })
        .unwrap();

        let entries = log.list_git_pushes_for_session(s.session_id).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.push_request_id, push_request_id);
        assert_eq!(entry.session_id, s.session_id);
        assert_eq!(entry.repo, sample_git_repo());
        assert_eq!(entry.branch, "main".parse::<GitBranchName>().unwrap());
        assert_eq!(entry.expected_remote_head, Some(git_oid('1')));
        assert_eq!(entry.new_head, git_oid('2'));
        assert_eq!(entry.push_attempt_id, Some(push_attempt_id));
        assert_eq!(entry.capability_request_id, Some(capability_request_id));
        assert_eq!(entry.grant_jti, Some(grant.jti));
        assert_eq!(
            entry.planned_at,
            Some(UnixMillis::from_millis(1_700_000_120))
        );
        assert_eq!(entry.old_head, Some(git_oid('1')));
        assert_eq!(entry.attempted_new_head, Some(git_oid('2')));
        assert_eq!(
            entry.completed_at,
            Some(UnixMillis::from_millis(1_700_000_130))
        );
        assert_eq!(entry.result, Some(GitPushOutcomeResult::Pushed));
        assert_eq!(entry.github_status, None);
        assert_eq!(entry.message.as_deref(), Some("pushed"));
    }

    proptest! {
        #[test]
        fn git_push_audit_state_machine_rejects_out_of_order_or_mismatched_rows(
            script in git_push_audit_script_strategy(),
        ) {
            let log = AuditLog::open_in_memory().unwrap();
            let s = sample_session();
            log.open_session(&s).unwrap();

            let push_request_id = RequestId::new();
            let push_request = sample_git_push_request_record(push_request_id, s.session_id);
            let capability_request_id = RequestId::new();
            let push_attempt_id = RequestId::new();

            match script {
                GitPushAuditScript::ValidAttempted {
                    result,
                    github_status,
                    close_before_outcome,
                    attempt_repo_case_differs,
                    branch_creation,
                } => {
                    let push_request = GitPushRequestRecord {
                        expected_remote_head: if branch_creation { None } else { Some(git_oid('1')) },
                        ..sample_git_push_request_record(push_request_id, s.session_id)
                    };
                    log.record_git_push_request(&push_request).unwrap();
                    let grant = record_sample_write_grant(&log, s.session_id, capability_request_id);
                    let attempt_repo = if attempt_repo_case_differs {
                        git_repo("O", "N")
                    } else {
                        sample_git_repo()
                    };
                    let attempt = GitPushAttemptRecord {
                        old_head: if branch_creation { None } else { Some(git_oid('1')) },
                        ..git_push_attempt_record(
                            push_attempt_id,
                            push_request_id,
                            capability_request_id,
                            grant.jti,
                            attempt_repo,
                            "main".parse().unwrap(),
                        )
                    };
                    log.record_git_push_attempt(&attempt).unwrap();
                    if close_before_outcome {
                        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_125))
                            .unwrap();
                    }
                    log.record_git_push_outcome(&GitPushOutcomeRecord {
                        push_request_id,
                        push_attempt_id: Some(push_attempt_id),
                        completed_at: UnixMillis::from_millis(1_700_000_130),
                        result,
                        github_status,
                        message: "state-machine outcome",
                    })
                    .unwrap();

                    let entries = log.list_git_pushes_for_session(s.session_id).unwrap();
                    assert_eq!(
                        entries,
                        vec![GitPushAuditEntry {
                            push_request_id,
                            session_id: s.session_id,
                            received_at: push_request.received_at,
                            repo: push_request.repo,
                            branch: push_request.branch,
                            expected_remote_head: push_request.expected_remote_head,
                            new_head: push_request.new_head,
                            correlation_id: push_request.correlation_id,
                            push_attempt_id: Some(push_attempt_id),
                            capability_request_id: Some(capability_request_id),
                            grant_jti: Some(grant.jti),
                            planned_at: Some(UnixMillis::from_millis(1_700_000_120)),
                            old_head: if branch_creation { None } else { Some(git_oid('1')) },
                            attempted_new_head: Some(git_oid('2')),
                            completed_at: Some(UnixMillis::from_millis(1_700_000_130)),
                            result: Some(result),
                            github_status,
                            message: Some("state-machine outcome".into()),
                            resolution: None,
                        }]
                    );
                }
                GitPushAuditScript::ValidUnattempted {
                    result,
                    close_before_outcome,
                    branch_creation,
                } => {
                    let push_request = GitPushRequestRecord {
                        expected_remote_head: if branch_creation { None } else { Some(git_oid('1')) },
                        ..sample_git_push_request_record(push_request_id, s.session_id)
                    };
                    log.record_git_push_request(&push_request).unwrap();
                    if close_before_outcome {
                        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_125))
                            .unwrap();
                    }
                    log.record_git_push_outcome(&GitPushOutcomeRecord {
                        push_request_id,
                        push_attempt_id: None,
                        completed_at: UnixMillis::from_millis(1_700_000_130),
                        result,
                        github_status: None,
                        message: "state-machine outcome",
                    })
                    .unwrap();

                    let entries = log.list_git_pushes_for_session(s.session_id).unwrap();
                    assert_eq!(
                        entries,
                        vec![GitPushAuditEntry {
                            push_request_id,
                            session_id: s.session_id,
                            received_at: push_request.received_at,
                            repo: push_request.repo,
                            branch: push_request.branch,
                            expected_remote_head: push_request.expected_remote_head,
                            new_head: push_request.new_head,
                            correlation_id: push_request.correlation_id,
                            push_attempt_id: None,
                            capability_request_id: None,
                            grant_jti: None,
                            planned_at: None,
                            old_head: None,
                            attempted_new_head: None,
                            completed_at: Some(UnixMillis::from_millis(1_700_000_130)),
                            result: Some(result),
                            github_status: None,
                            message: Some("state-machine outcome".into()),
                            resolution: None,
                        }]
                    );
                }
                GitPushAuditScript::RequestAfterClose => {
                    log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_090))
                        .unwrap();
                    assert!(log.record_git_push_request(&push_request).is_err());
                }
                GitPushAuditScript::AttemptBeforeRequest => {
                    let grant = record_sample_write_grant(&log, s.session_id, capability_request_id);
                    let err = log
                        .record_git_push_attempt(&git_push_attempt_record(
                            push_attempt_id,
                            push_request_id,
                            capability_request_id,
                            grant.jti,
                            sample_git_repo(),
                            "main".parse().unwrap(),
                        ))
                        .unwrap_err();
                    assert!(
                        matches!(err, AuditError::Invariant("git push request does not exist")),
                        "got: {err:?}"
                    );
                }
                GitPushAuditScript::AttemptMissingGrant => {
                    log.record_git_push_request(&push_request).unwrap();
                    let err = log
                        .record_git_push_attempt(&git_push_attempt_record(
                            push_attempt_id,
                            push_request_id,
                            capability_request_id,
                            Jti::new(),
                            sample_git_repo(),
                            "main".parse().unwrap(),
                        ))
                        .unwrap_err();
                    assert!(
                        matches!(err, AuditError::Invariant("git push grant does not exist")),
                        "got: {err:?}"
                    );
                }
                GitPushAuditScript::AttemptMismatchedRepo => {
                    log.record_git_push_request(&push_request).unwrap();
                    let grant = record_sample_write_grant(&log, s.session_id, capability_request_id);
                    let err = log
                        .record_git_push_attempt(&git_push_attempt_record(
                            push_attempt_id,
                            push_request_id,
                            capability_request_id,
                            grant.jti,
                            git_repo("o", "other"),
                            "main".parse().unwrap(),
                        ))
                        .unwrap_err();
                    assert!(
                        matches!(
                            err,
                            AuditError::Invariant("git push attempt repo differs from request")
                        ),
                        "got: {err:?}"
                    );
                }
                GitPushAuditScript::AttemptMismatchedBranch => {
                    log.record_git_push_request(&push_request).unwrap();
                    let grant = record_sample_write_grant(&log, s.session_id, capability_request_id);
                    let err = log
                        .record_git_push_attempt(&git_push_attempt_record(
                            push_attempt_id,
                            push_request_id,
                            capability_request_id,
                            grant.jti,
                            sample_git_repo(),
                            "Main".parse().unwrap(),
                        ))
                        .unwrap_err();
                    assert!(
                        matches!(
                            err,
                            AuditError::Invariant("git push attempt branch differs from request")
                        ),
                        "got: {err:?}"
                    );
                }
                GitPushAuditScript::AttemptHeadPresenceMismatch { request_has_head } => {
                    let push_request = GitPushRequestRecord {
                        expected_remote_head: if request_has_head { Some(git_oid('1')) } else { None },
                        ..sample_git_push_request_record(push_request_id, s.session_id)
                    };
                    log.record_git_push_request(&push_request).unwrap();
                    let grant = record_sample_write_grant(&log, s.session_id, capability_request_id);
                    let attempt = GitPushAttemptRecord {
                        old_head: if request_has_head { None } else { Some(git_oid('1')) },
                        ..git_push_attempt_record(
                            push_attempt_id,
                            push_request_id,
                            capability_request_id,
                            grant.jti,
                            sample_git_repo(),
                            "main".parse().unwrap(),
                        )
                    };
                    let err = log.record_git_push_attempt(&attempt).unwrap_err();
                    assert!(
                        matches!(
                            err,
                            AuditError::Invariant("git push attempt old head differs from request")
                        ),
                        "got: {err:?}"
                    );
                }
                GitPushAuditScript::OutcomeWithoutRequest => {
                    let err = log
                        .record_git_push_outcome(&GitPushOutcomeRecord {
                            push_request_id,
                            push_attempt_id: None,
                            completed_at: UnixMillis::from_millis(1_700_000_130),
                            result: GitPushOutcomeResult::Denied,
                            github_status: None,
                            message: "policy denied",
                        })
                        .unwrap_err();
                    assert!(matches!(err, AuditError::Sqlite(_)), "got: {err:?}");
                }
                GitPushAuditScript::OutcomeRequiresAttemptWithoutAttempt { result } => {
                    log.record_git_push_request(&push_request).unwrap();
                    let err = log
                        .record_git_push_outcome(&GitPushOutcomeRecord {
                            push_request_id,
                            push_attempt_id: None,
                            completed_at: UnixMillis::from_millis(1_700_000_130),
                            result,
                            github_status: None,
                            message: "attempt required",
                        })
                        .unwrap_err();
                    assert!(
                        matches!(
                            err,
                            AuditError::Invariant("git push outcome result requires an attempt")
                        ),
                        "got: {err:?}"
                    );
                }
                GitPushAuditScript::OutcomeUnexpectedAttempt { result } => {
                    log.record_git_push_request(&push_request).unwrap();
                    let grant = record_sample_write_grant(&log, s.session_id, capability_request_id);
                    log.record_git_push_attempt(&git_push_attempt_record(
                        push_attempt_id,
                        push_request_id,
                        capability_request_id,
                        grant.jti,
                        sample_git_repo(),
                        "main".parse().unwrap(),
                    ))
                    .unwrap();
                    let err = log
                        .record_git_push_outcome(&GitPushOutcomeRecord {
                            push_request_id,
                            push_attempt_id: Some(push_attempt_id),
                            completed_at: UnixMillis::from_millis(1_700_000_130),
                            result,
                            github_status: None,
                            message: "attempt not expected",
                        })
                        .unwrap_err();
                    assert!(
                        matches!(
                            err,
                            AuditError::Invariant(
                                "git push outcome result must not reference an attempt"
                            )
                        ),
                        "got: {err:?}"
                    );
                }
                GitPushAuditScript::OutcomeDifferentRequest { result } => {
                    log.record_git_push_request(&push_request).unwrap();
                    let second_push_request_id = RequestId::new();
                    log.record_git_push_request(&sample_git_push_request_record(
                        second_push_request_id,
                        s.session_id,
                    ))
                    .unwrap();
                    let grant = record_sample_write_grant(&log, s.session_id, capability_request_id);
                    log.record_git_push_attempt(&git_push_attempt_record(
                        push_attempt_id,
                        push_request_id,
                        capability_request_id,
                        grant.jti,
                        sample_git_repo(),
                        "main".parse().unwrap(),
                    ))
                    .unwrap();
                    let err = log
                        .record_git_push_outcome(&GitPushOutcomeRecord {
                            push_request_id: second_push_request_id,
                            push_attempt_id: Some(push_attempt_id),
                            completed_at: UnixMillis::from_millis(1_700_000_130),
                            result,
                            github_status: None,
                            message: "wrong attempt",
                        })
                        .unwrap_err();
                    assert!(
                        matches!(
                            err,
                            AuditError::Invariant(
                                "git push outcome attempt belongs to a different request"
                            )
                        ),
                        "got: {err:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn get_git_push_returns_none_when_request_missing() {
        let log = AuditLog::open_in_memory().unwrap();
        assert!(log.get_git_push(RequestId::new()).unwrap().is_none());
    }

    #[test]
    fn get_git_push_returns_request_only_view_before_attempt() {
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
        assert_eq!(entry.push_attempt_id, None);
        assert_eq!(entry.result, None);
        assert_eq!(entry.completed_at, None);
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
            push_attempt_id: None,
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

    /// The SQL `result` column stores the same strings produced by the
    /// `Serialize` impl. Pin them so a future serde rename can't silently
    /// orphan existing audit rows.
    #[test]
    fn outcome_result_sql_strings_match_serde_form() {
        let variants = [
            GitPushOutcomeResult::Denied,
            GitPushOutcomeResult::ValidationFailed,
            GitPushOutcomeResult::Staged,
            GitPushOutcomeResult::Pushed,
            GitPushOutcomeResult::LeaseRejected,
            GitPushOutcomeResult::PushRejected,
            GitPushOutcomeResult::PushFailed,
            GitPushOutcomeResult::AuditFailedAfterPush,
        ];
        for v in variants {
            let json = serde_json::to_value(v).unwrap();
            assert_eq!(json, serde_json::Value::String(v.as_str().to_string()));
            let back: GitPushOutcomeResult = serde_json::from_value(json).unwrap();
            assert_eq!(back, v);
        }
    }

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
            push_attempt_id: None,
            completed_at: UnixMillis::from_millis(1_700_000_130),
            result: GitPushOutcomeResult::ValidationFailed,
            github_status: None,
            message: "remote head moved",
        })
        .unwrap();
    }

    #[test]
    fn git_push_attempt_requires_matching_contents_write_grant() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let push_request_id = RequestId::new();
        log.record_git_push_request(&sample_git_push_request_record(
            push_request_id,
            s.session_id,
        ))
        .unwrap();

        let missing_grant = log
            .record_git_push_attempt(&GitPushAttemptRecord {
                push_attempt_id: RequestId::new(),
                push_request_id,
                capability_request_id: RequestId::new(),
                grant_jti: Jti::new(),
                planned_at: UnixMillis::from_millis(1_700_000_120),
                repo: sample_git_repo(),
                branch: "main".parse().unwrap(),
                old_head: Some(git_oid('1')),
                new_head: git_oid('2'),
            })
            .unwrap_err();
        assert!(
            matches!(
                missing_grant,
                AuditError::Invariant("git push grant does not exist")
            ),
            "got: {missing_grant:?}"
        );

        let capability_request_id = RequestId::new();
        let other_repo = RepoRef {
            owner: "o".into(),
            name: "other".into(),
        };
        let other_request = CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Write,
            repo: other_repo.clone(),
        });
        let other_scope = GrantedScope::GitHub(GitHubGrantedScope {
            repository: other_repo,
            permissions: GitHubPermissions {
                contents: Some(GitHubAccess::Write),
                metadata: Some(MetadataAccess::Read),
                ..Default::default()
            },
        });
        pre_mint(
            &log,
            capability_request_id,
            s.session_id,
            &other_request,
            &PolicyDecision::Grant {
                scope: other_scope.clone(),
                ttl: TtlSeconds::new(300).unwrap(),
            },
            UnixMillis::from_millis(1_700_000_110),
        )
        .unwrap();
        let wrong_repo_grant = CredentialGrant {
            jti: Jti::new(),
            request_id: capability_request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: other_scope,
            issued_at: UnixMillis::from_millis(1_700_000_110),
            expires_at: UnixMillis::from_millis(1_700_000_410),
        };
        log.record_grant(&wrong_repo_grant).unwrap();

        let wrong_repo = log
            .record_git_push_attempt(&GitPushAttemptRecord {
                push_attempt_id: RequestId::new(),
                push_request_id,
                capability_request_id,
                grant_jti: wrong_repo_grant.jti,
                planned_at: UnixMillis::from_millis(1_700_000_120),
                repo: sample_git_repo(),
                branch: "main".parse().unwrap(),
                old_head: Some(git_oid('1')),
                new_head: git_oid('2'),
            })
            .unwrap_err();
        assert!(
            matches!(
                wrong_repo,
                AuditError::Invariant(
                    "git push grant is not contents:write for the requested repo"
                )
            ),
            "got: {wrong_repo:?}"
        );
    }

    #[test]
    fn git_push_outcome_enforces_attempt_requirement() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let push_request_id = RequestId::new();
        log.record_git_push_request(&sample_git_push_request_record(
            push_request_id,
            s.session_id,
        ))
        .unwrap();

        let pushed_without_attempt = log
            .record_git_push_outcome(&GitPushOutcomeRecord {
                push_request_id,
                push_attempt_id: None,
                completed_at: UnixMillis::from_millis(1_700_000_130),
                result: GitPushOutcomeResult::Pushed,
                github_status: None,
                message: "pushed",
            })
            .unwrap_err();
        assert!(
            matches!(
                pushed_without_attempt,
                AuditError::Invariant("git push outcome result requires an attempt")
            ),
            "got: {pushed_without_attempt:?}"
        );

        let capability_request_id = RequestId::new();
        let grant = record_sample_write_grant(&log, s.session_id, capability_request_id);
        let push_attempt_id = RequestId::new();
        log.record_git_push_attempt(&GitPushAttemptRecord {
            push_attempt_id,
            push_request_id,
            capability_request_id,
            grant_jti: grant.jti,
            planned_at: UnixMillis::from_millis(1_700_000_120),
            repo: sample_git_repo(),
            branch: "main".parse().unwrap(),
            old_head: Some(git_oid('1')),
            new_head: git_oid('2'),
        })
        .unwrap();

        let denied_with_attempt = log
            .record_git_push_outcome(&GitPushOutcomeRecord {
                push_request_id,
                push_attempt_id: Some(push_attempt_id),
                completed_at: UnixMillis::from_millis(1_700_000_130),
                result: GitPushOutcomeResult::Denied,
                github_status: None,
                message: "policy denied",
            })
            .unwrap_err();
        assert!(
            matches!(
                denied_with_attempt,
                AuditError::Invariant("git push outcome result must not reference an attempt")
            ),
            "got: {denied_with_attempt:?}"
        );
    }

    #[test]
    fn git_push_outcome_without_request_is_rejected() {
        let log = AuditLog::open_in_memory().unwrap();
        let err = log
            .record_git_push_outcome(&GitPushOutcomeRecord {
                push_request_id: RequestId::new(),
                push_attempt_id: None,
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

    /// SQLite's `TEXT PRIMARY KEY` columns are nullable, so a corrupt
    /// row could land with `push_attempt_id = NULL` while the other
    /// (`NOT NULL`) attempt columns are populated. The LEFT JOIN would
    /// still hit. The row parser must surface that as a specific
    /// invariant error rather than silently report "no attempt" by
    /// using the nullable PK as its presence discriminator.
    #[test]
    fn list_surfaces_attempt_row_with_null_primary_key_as_invariant_error() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let push_request_id = RequestId::new();
        log.record_git_push_request(&sample_git_push_request_record(
            push_request_id,
            s.session_id,
        ))
        .unwrap();
        let capability_request_id = RequestId::new();
        let grant = record_sample_write_grant(&log, s.session_id, capability_request_id);

        log.with_conn_mut(|c| {
            c.execute(
                "INSERT INTO git_push_attempt \
                 (push_attempt_id, push_request_id, capability_request_id, grant_jti, planned_at, repo, branch, old_head, new_head) \
                 VALUES (NULL, ?1, ?2, ?3, ?4, 'o/n', 'main', ?5, ?6)",
                rusqlite::params![
                    push_request_id.as_uuid().to_string(),
                    capability_request_id.as_uuid().to_string(),
                    grant.jti.as_uuid().to_string(),
                    1_700_000_120_i64,
                    git_oid('1').as_str(),
                    git_oid('2').as_str(),
                ],
            )?;
            Ok(())
        })
        .unwrap();

        let err = log.list_git_pushes_for_session(s.session_id).unwrap_err();
        assert!(
            matches!(
                err,
                AuditError::Invariant("Git push audit row: attempt id missing or invalid")
            ),
            "got: {err:?}"
        );
    }

    fn record_staged_request(log: &AuditLog, push_request_id: RequestId, session_id: SessionId) {
        log.record_git_push_request(&sample_git_push_request_record(push_request_id, session_id))
            .unwrap();
        log.record_git_push_outcome(&GitPushOutcomeRecord {
            push_request_id,
            push_attempt_id: None,
            completed_at: UnixMillis::from_millis(1_700_000_130),
            result: GitPushOutcomeResult::Staged,
            github_status: None,
            message: "queued for review",
        })
        .unwrap();
    }

    #[test]
    fn record_resolution_roundtrips_via_get_git_push() {
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

    fn sample_promote_mint_audit() -> PromoteMintAudit {
        PromoteMintAudit {
            jti: Jti::new(),
            github_app_id: 42,
            issued_at: UnixMillis::from_millis(1_700_000_190),
            expires_at: UnixMillis::from_millis(1_700_000_490),
        }
    }

    /// `Approved` carries a `PromoteMintAudit` payload that the SQL
    /// trigger requires to be present iff the decision is approved.
    /// Round-trip the mint context through INSERT + LEFT JOIN read.
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

    /// A `Rejected` resolution leaves all four mint columns NULL —
    /// reading the row back observes exactly `Rejected`, not a corrupt
    /// `Approved` with partial mint context.
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

        let entry = log.get_git_push(push_request_id).unwrap().unwrap();
        assert_eq!(
            entry.resolution.unwrap().decision,
            GitPushResolution::Rejected
        );
    }

    /// Trigger defence: a direct INSERT that claims `approved` without
    /// supplying every mint column is refused. This guards against a
    /// caller bypassing the DAO and writing the column-form direct
    /// without the matching mint context.
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

    /// Mirror image of the previous trigger guard: a `rejected` row
    /// carrying mint context is refused.
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
            push_attempt_id: None,
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

    /// Pin the mapping between the in-memory variant and the SQL
    /// `decision` string. The CHECK constraint on `git_push_resolution`
    /// only admits `'rejected'` and `'approved'`, so an accidental
    /// rename here would orphan existing audit rows.
    #[test]
    fn resolution_decision_sql_strings_match_variant_kind() {
        assert_eq!(GitPushResolution::Rejected.kind_str(), "rejected");
        assert_eq!(
            GitPushResolution::Approved(sample_promote_mint_audit()).kind_str(),
            "approved"
        );
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
    /// belt-and-braces line of defence. The DAO is the parse-don't-
    /// validate boundary today, but a future code path that writes the
    /// row directly must not be able to land bytes outside the allowed
    /// class.
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
}
