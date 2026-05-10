//! Audit log backed by SQLite.
//!
//! The log is the system-of-record for broker activity: every session,
//! every capability request, every credential grant, and every post-policy
//! mint failure lands here. The raw JSON for requests, decisions, scopes,
//! and mint failures is stored verbatim, so the log can be replayed to
//! reconstruct history without depending on the broker binary staying
//! source-compatible.
//!
//! The `request` and `grant_log` tables are strictly append-only: once a
//! row lands it is never mutated or deleted. This is the part that
//! matters for audit-integrity claims.
//!
//! The `session` table carries open/close timestamps and is updated by
//! `close_session`; `closed_at` moves from NULL to a fixed timestamp
//! exactly once, and a `request` row can only be written while the
//! referenced session is open. That constraint is what makes
//! `closed_at` a meaningful upper bound on the session's activity
//! window during post-hoc review — the per-grant rows in `grant_log`
//! are what get reconciled against observed side-effects, and those
//! never move.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::{
    CapabilityRequest, CredentialGrant, GitHubAccess, GitHubGrantedScope, GitHubRequest,
    GrantedScope, Jti, MetadataAccess, PolicyDecision, RequestId, SessionId, UnixMillis,
};
use crate::vm_git::{GitBranchName, GitCloneRepo, GitObjectId};

mod agent_run;
mod claude_proxy;
mod nix_cache;
mod openai_proxy;
mod schema;
mod session;
mod validation;

pub use agent_run::{
    AgentRunAuditRecord, AgentRunOutcomeAuditRecord, AgentVmWorkspaceBootstrapAuditRecord,
};
pub use claude_proxy::{
    ClaudeProxyAuditDecision, ClaudeProxyAuditRoute, ClaudeProxyOutcomeRecord,
    ClaudeProxyRequestRecord,
};
pub use nix_cache::{
    NixCacheAuditDecision, NixCacheAuditEntry, NixCacheAuditRoute, NixCacheOutcomeRecord,
    NixCacheRequestRecord,
};
pub use openai_proxy::{
    OpenAiProxyAuditDecision, OpenAiProxyAuditRoute, OpenAiProxyOutcomeRecord,
    OpenAiProxyRequestRecord,
};

use validation::{parse_required_jti, parse_required_request_id};

/// How much a grant's effective lifetime may exceed the decision's TTL
/// ceiling before the audit layer rejects the row. Backend minters compare
/// a backend-reported expiry against their own clock and tolerate a small
/// amount of skew; this constant is the audit layer's matching slack, so
/// the skew allowance at mint time doesn't spuriously trip the divergence
/// check. Anything larger here would start to hide real disagreement
/// between the decision and the grant.
const AUDIT_TTL_SKEW_TOLERANCE_MILLIS: i64 = 60_000;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("internal lock poisoned")]
    Poisoned,

    /// Structural or cross-row audit invariant where the message names the
    /// failed relationship directly.
    #[error("invariant violated: {0}")]
    Invariant(&'static str),

    /// Field validation invariant where callers need the column or stream
    /// label alongside the reusable validation failure.
    #[error("invariant violated: {label}: {message}")]
    LabeledInvariant {
        label: &'static str,
        message: &'static str,
    },

    /// The on-disk schema was written by a newer broker than this binary
    /// knows how to read. Refusing to open is the correctness-over-
    /// availability call: a down-rev binary silently ignoring columns it
    /// doesn't understand is how audit logs lose data.
    #[error(
        "audit DB schema version {found} is newer than this binary supports (max {supported}); \
         upgrade the broker"
    )]
    SchemaTooNew { found: i32, supported: i32 },
}

/// JSON payload stored in the `mint_failure` table.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MintFailureRecord {
    pub error: String,
}

/// One request-and-decision, captured *before* the backend mint step is
/// attempted. Persisting this row before any `await` is what lets a
/// crash-after-mint, or a CloseSession landing during the mint's await,
/// leave a truthful audit trail: the request and its decision are already
/// durable, and the mint outcome is appended separately when it is known.
#[derive(Debug)]
pub struct PreMintRecord<'a> {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub request: &'a CapabilityRequest,
    pub decision: &'a PolicyDecision,
}

#[derive(Debug)]
pub struct GitPushRequestRecord {
    pub push_request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub repo: GitCloneRepo,
    pub branch: GitBranchName,
    pub expected_remote_head: GitObjectId,
    pub new_head: GitObjectId,
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
    pub old_head: GitObjectId,
    pub new_head: GitObjectId,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GitPushOutcomeResult {
    Denied,
    ValidationFailed,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitPushAuditEntry {
    pub push_request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub repo: GitCloneRepo,
    pub branch: GitBranchName,
    pub expected_remote_head: GitObjectId,
    pub new_head: GitObjectId,
    pub push_attempt_id: Option<RequestId>,
    pub capability_request_id: Option<RequestId>,
    pub grant_jti: Option<Jti>,
    pub planned_at: Option<UnixMillis>,
    pub old_head: Option<GitObjectId>,
    pub attempted_new_head: Option<GitObjectId>,
    pub completed_at: Option<UnixMillis>,
    pub result: Option<GitPushOutcomeResult>,
    pub github_status: Option<u16>,
    pub message: Option<String>,
}

pub struct AuditLog {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog").finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Open (or create) an on-disk audit log. The schema is brought up to
    /// the highest version this binary supports by running any missing
    /// migrations in order.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let mut conn = Connection::open(path)?;
        Self::init(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// In-memory audit log, for tests.
    pub fn open_in_memory() -> Result<Self, AuditError> {
        let mut conn = Connection::open_in_memory()?;
        Self::init(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn init(conn: &mut Connection) -> Result<(), AuditError> {
        // SQLite foreign_keys is per-connection and defaults to OFF, so the
        // REFERENCES clauses in the schema would otherwise be
        // parsed-and-ignored and orphan `request`/`grant_log` rows could
        // slip in. Must be set outside a transaction.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        schema::migrate(conn)
    }

    pub(super) fn with_conn<R>(
        &self,
        f: impl FnOnce(&Connection) -> Result<R, AuditError>,
    ) -> Result<R, AuditError> {
        let guard = self.conn.lock().map_err(|_| AuditError::Poisoned)?;
        f(&guard)
    }

    pub(super) fn with_conn_mut<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<R, AuditError>,
    ) -> Result<R, AuditError> {
        let mut guard = self.conn.lock().map_err(|_| AuditError::Poisoned)?;
        f(&mut guard)
    }

    /// Persist a request and its policy decision. Call this *before* the
    /// backend mint step is invoked (or, for a Deny decision, in place of
    /// it). Once this transaction commits, the broker has a durable audit
    /// row for the request regardless of what happens next — crash, kill,
    /// CloseSession, or backend failure. The matching mint outcome, if
    /// any, is appended later via [`AuditLog::record_grant`] or
    /// [`AuditLog::record_mint_failure`].
    pub fn record_pre_mint(&self, r: &PreMintRecord<'_>) -> Result<(), AuditError> {
        // Before we even touch the DB, make sure the decision's scope is
        // one the request could justify. Without this check a caller who
        // wires the wrong decision to the wrong request would persist an
        // audit row claiming authority the agent never asked for — e.g. a
        // Metadata request paired with a Grant of contents:write on a
        // different repo.
        if let PolicyDecision::Grant { scope, .. } = r.decision
            && !scope_authorised_by_request(r.request, scope)
        {
            return Err(AuditError::Invariant(
                "decision scope is not authorised by the request",
            ));
        }

        let request_json = serde_json::to_string(r.request)?;
        let decision_json = serde_json::to_string(r.decision)?;

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;

            // A request can only be audited against an open session.
            // `dispatch_capability` also checks this before the mint, but
            // the authoritative check lives here, inside the same tx as
            // the INSERT. Without it, a client could CloseSession and
            // then see audit rows land after the session's own
            // `closed_at` — which would silently strip `closed_at` of its
            // meaning as an activity-window bound. The existing FK covers
            // "session exists"; it cannot express "session is open",
            // which is why this check exists at all. The BEFORE-INSERT
            // trigger on `request` is braces to this belt.
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
                "INSERT INTO request (
                     request_id,
                     session_id,
                     received_at,
                     request_json,
                     decision_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    r.request_id.as_uuid().to_string(),
                    r.session_id.as_uuid().to_string(),
                    r.received_at.as_millis(),
                    request_json,
                    decision_json,
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

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
                     new_head
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    r.push_request_id.as_uuid().to_string(),
                    r.session_id.as_uuid().to_string(),
                    r.received_at.as_millis(),
                    r.repo.to_string(),
                    r.branch.as_str(),
                    r.expected_remote_head.as_str(),
                    r.new_head.as_str(),
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
            let push_request: Option<(String, String, String, String, String)> = tx
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
            if request_old_head != r.old_head.as_str() {
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
                    r.old_head.as_str(),
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

    /// Append the grant produced by a successful mint. The matching
    /// request row must already have been persisted via
    /// [`AuditLog::record_pre_mint`]; the FK on `grant_log.request_id`
    /// enforces this at the DB layer.
    ///
    /// The session may have been closed between `record_pre_mint` and
    /// this call (a CloseSession can land during the mint's `await`);
    /// that is *not* an error. The authority to mint was established at
    /// pre-mint time, so the resulting grant is still a legitimate
    /// audit row even if the session has since gone quiet on paper.
    pub fn record_grant(&self, grant: &CredentialGrant) -> Result<(), AuditError> {
        let grant_scope_json = serde_json::to_string(&grant.scope)?;
        let github_app_id = grant
            .github_app_id
            .ok_or(AuditError::Invariant("grant.github_app_id is missing"))?;
        let github_app_id = i64::try_from(github_app_id)
            .map_err(|_| AuditError::Invariant("grant.github_app_id exceeds SQLite integer"))?;

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;

            // Load the pre-mint decision so we can verify the grant
            // agrees with it. This couples audit integrity to what the
            // DB actually holds rather than trusting the caller — a
            // lying caller can't produce a row that disagrees with the
            // recorded decision.
            let recorded: Option<(String, String)> = tx
                .query_row(
                    "SELECT session_id, decision_json FROM request WHERE request_id = ?1",
                    params![grant.request_id.as_uuid().to_string()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            let (session_id_str, decision_json) = recorded.ok_or(AuditError::Invariant(
                "no pre-mint request row for this grant",
            ))?;

            if grant.session_id.as_uuid().to_string() != session_id_str {
                return Err(AuditError::Invariant(
                    "grant.session_id != request.session_id",
                ));
            }

            let decision: PolicyDecision = serde_json::from_str(&decision_json)?;
            let (decision_scope, decision_ttl) = match decision {
                PolicyDecision::Grant { scope, ttl } => (scope, ttl),
                PolicyDecision::Deny { .. } => {
                    return Err(AuditError::Invariant(
                        "cannot record a grant for a Deny decision",
                    ));
                }
            };

            // Decision and grant are both authority claims about the same
            // request, so they must agree on what that authority is.
            if grant.scope != decision_scope {
                return Err(AuditError::Invariant("grant.scope != decision.scope"));
            }
            // An inverted expiry (expires before issued) would silently
            // pass the TTL-ceiling comparison below because saturating_sub
            // of a negative gap is a negative lifetime, trivially less
            // than any positive ceiling. Reject explicitly.
            if grant.expires_at < grant.issued_at {
                return Err(AuditError::Invariant("grant expires before it was issued"));
            }
            let lifetime_millis = grant
                .expires_at
                .as_millis()
                .saturating_sub(grant.issued_at.as_millis());
            let max_millis = decision_ttl
                .as_i64()
                .saturating_mul(1000)
                .saturating_add(AUDIT_TTL_SKEW_TOLERANCE_MILLIS);
            if lifetime_millis > max_millis {
                return Err(AuditError::Invariant("grant lifetime exceeds decision ttl"));
            }

            tx.execute(
                "INSERT INTO grant_log (jti, request_id, session_id, github_app_id, scope_json, issued_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    grant.jti.as_uuid().to_string(),
                    grant.request_id.as_uuid().to_string(),
                    grant.session_id.as_uuid().to_string(),
                    github_app_id,
                    grant_scope_json,
                    grant.issued_at.as_millis(),
                    grant.expires_at.as_millis(),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Append a backend mint failure for a previously pre-minted request.
    /// Like [`AuditLog::record_grant`], this is permitted even if the
    /// session has since been closed: the request was accepted while the
    /// session was open, and the failure is the honest outcome of that
    /// acceptance.
    pub fn record_mint_failure(
        &self,
        request_id: RequestId,
        failed_at: UnixMillis,
        error: &str,
    ) -> Result<(), AuditError> {
        if error.is_empty() {
            return Err(AuditError::Invariant(
                "mint failure message must not be empty",
            ));
        }
        let failure_json = serde_json::to_string(&MintFailureRecord {
            error: error.to_string(),
        })?;

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;

            // Refuse to record a mint failure against a request whose
            // decision was Deny — such a row would be nonsense (a denied
            // request never reaches the mint step).
            let decision_json: Option<String> = tx
                .query_row(
                    "SELECT decision_json FROM request WHERE request_id = ?1",
                    params![request_id.as_uuid().to_string()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let decision_json = decision_json.ok_or(AuditError::Invariant(
                "no pre-mint request row for this mint failure",
            ))?;
            match serde_json::from_str::<PolicyDecision>(&decision_json)? {
                PolicyDecision::Grant { .. } => {}
                PolicyDecision::Deny { .. } => {
                    return Err(AuditError::Invariant(
                        "cannot record a mint failure for a Deny decision",
                    ));
                }
            }

            tx.execute(
                "INSERT INTO mint_failure (request_id, failed_at, failure_json) \
                 VALUES (?1, ?2, ?3)",
                params![
                    request_id.as_uuid().to_string(),
                    failed_at.as_millis(),
                    failure_json,
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn list_grants_for_session(
        &self,
        id: SessionId,
    ) -> Result<Vec<CredentialGrant>, AuditError> {
        self.with_conn(|c| {
            // Secondary sort on rowid so grants issued in the same instant
            // still come back in insert order. Without it, `ORDER BY
            // issued_at ASC` leaves same-timestamp rows in an unspecified
            // order and replay can't reconstruct the real sequence.
            let mut stmt = c.prepare(
                "SELECT jti, request_id, session_id, github_app_id, scope_json, issued_at, expires_at \
                 FROM grant_log WHERE session_id = ?1 ORDER BY issued_at ASC, rowid ASC",
            )?;
            let rows = stmt
                .query_map(params![id.as_uuid().to_string()], grant_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn get_grant(&self, jti: Jti) -> Result<Option<CredentialGrant>, AuditError> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT jti, request_id, session_id, github_app_id, scope_json, issued_at, expires_at \
                     FROM grant_log WHERE jti = ?1",
                    params![jti.as_uuid().to_string()],
                    grant_from_row,
                )
                .optional()?;
            match row {
                Some(Ok(g)) => Ok(Some(g)),
                Some(Err(e)) => Err(e),
                None => Ok(None),
            }
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
                     a.push_attempt_id,
                     a.capability_request_id,
                     a.grant_jti,
                     a.planned_at,
                     a.old_head,
                     a.new_head AS attempted_new_head,
                     o.completed_at,
                     o.result,
                     o.github_status,
                     o.message
                 FROM git_push_request r
                 LEFT JOIN git_push_attempt a ON a.push_request_id = r.push_request_id
                 LEFT JOIN git_push_outcome o ON o.push_request_id = r.push_request_id
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

/// True iff `scope` is a possible policy output for `request`. The audit
/// layer uses this to reject rows where the decision has been paired with
/// the wrong request — an invariant the policy engine maintains by
/// construction, but the audit layer can't assume its caller did.
///
/// Structural rather than derived-from-policy on purpose: the audit layer
/// doesn't know the policy config, so it can't re-run `policy::decide`.
/// What it can check is that the scope's backend, repo, and permission
/// set are shaped compatibly with the request, which is all we need to
/// rule out cross-request wire-ups. Policy-level narrowing (granting less
/// than requested) would be allowed by this check; v1 policy doesn't do
/// that, and a future narrowing policy's tighter constraint still
/// satisfies a looser structural check.
fn scope_authorised_by_request(request: &CapabilityRequest, scope: &GrantedScope) -> bool {
    match (request, scope) {
        (CapabilityRequest::GitHub(r), GrantedScope::GitHub(s)) => {
            github_scope_authorised_by_request(r, s)
        }
    }
}

fn github_scope_authorised_by_request(r: &GitHubRequest, s: &GitHubGrantedScope) -> bool {
    if &s.repository != r.repo() {
        return false;
    }
    // GitHub installation tokens always carry metadata:read, so it's fine
    // for the grant to include it regardless of request; other metadata
    // values are impossible (MetadataAccess is a one-variant enum) but
    // pattern-match explicitly so the compiler forces us to revisit this
    // if that ever changes.
    match s.permissions.metadata {
        None | Some(MetadataAccess::Read) => {}
    }
    match r {
        GitHubRequest::Metadata { .. } => {
            s.permissions.contents.is_none()
                && s.permissions.issues.is_none()
                && s.permissions.pull_requests.is_none()
        }
        GitHubRequest::Contents { access, .. } => {
            s.permissions.contents == Some(*access)
                && s.permissions.issues.is_none()
                && s.permissions.pull_requests.is_none()
        }
        GitHubRequest::Issues { access, .. } => {
            s.permissions.issues == Some(*access)
                && s.permissions.contents.is_none()
                && s.permissions.pull_requests.is_none()
        }
        GitHubRequest::PullRequests { access, .. } => {
            s.permissions.pull_requests == Some(*access)
                && s.permissions.contents.is_none()
                && s.permissions.issues.is_none()
        }
    }
}

impl GitPushOutcomeResult {
    fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::ValidationFailed => "validation_failed",
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
    let expected_remote_head_str: String = row.get("expected_remote_head")?;
    let new_head_str: String = row.get("request_new_head")?;
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
        let expected_remote_head =
            expected_remote_head_str
                .parse::<GitObjectId>()
                .map_err(|_| {
                    AuditError::Invariant("Git push audit row: expected remote head is invalid")
                })?;
        let new_head = new_head_str
            .parse::<GitObjectId>()
            .map_err(|_| AuditError::Invariant("Git push audit row: new head is invalid"))?;

        let has_attempt = push_attempt_id_str.is_some()
            || capability_request_id_str.is_some()
            || grant_jti_str.is_some()
            || planned_at.is_some()
            || old_head_str.is_some()
            || attempted_new_head_str.is_some();
        let (
            push_attempt_id,
            capability_request_id,
            grant_jti,
            planned_at,
            old_head,
            attempted_new_head,
        ) = if has_attempt {
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
                .ok_or(AuditError::Invariant(
                    "Git push audit row: old head missing",
                ))?
                .parse::<GitObjectId>()
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
                Some(old_head),
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

        Ok(GitPushAuditEntry {
            push_request_id: RequestId::from_uuid(push_request_id),
            session_id: SessionId::from_uuid(session_id),
            received_at: UnixMillis::from_millis(received_at),
            repo,
            branch,
            expected_remote_head,
            new_head,
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
        })
    };
    Ok(parse())
}

fn grant_from_row(row: &Row<'_>) -> rusqlite::Result<Result<CredentialGrant, AuditError>> {
    let jti_str: String = row.get("jti")?;
    let request_id_str: String = row.get("request_id")?;
    let session_id_str: String = row.get("session_id")?;
    let github_app_id: Option<i64> = row.get("github_app_id")?;
    let scope_json: String = row.get("scope_json")?;
    let issued_at: i64 = row.get("issued_at")?;
    let expires_at: i64 = row.get("expires_at")?;

    let parse = || -> Result<CredentialGrant, AuditError> {
        let jti = uuid::Uuid::parse_str(&jti_str)
            .map_err(|_| AuditError::Invariant("grant row: jti not a uuid"))?;
        let request_id = uuid::Uuid::parse_str(&request_id_str)
            .map_err(|_| AuditError::Invariant("grant row: request_id not a uuid"))?;
        let session_id = uuid::Uuid::parse_str(&session_id_str)
            .map_err(|_| AuditError::Invariant("grant row: session_id not a uuid"))?;
        let github_app_id = github_app_id
            .map(|id| {
                u64::try_from(id)
                    .map_err(|_| AuditError::Invariant("grant row: github_app_id is negative"))
            })
            .transpose()?;
        let scope: GrantedScope = serde_json::from_str(&scope_json)?;
        Ok(CredentialGrant {
            jti: Jti::from_uuid(jti),
            request_id: RequestId::from_uuid(request_id),
            session_id: SessionId::from_uuid(session_id),
            github_app_id,
            scope,
            issued_at: UnixMillis::from_millis(issued_at),
            expires_at: UnixMillis::from_millis(expires_at),
        })
    };
    Ok(parse())
}

#[cfg(test)]
mod tests {
    use super::schema::{MIGRATIONS, SCHEMA_VERSION, user_version};
    use super::*;
    use crate::agent_run::{
        AgentPromptSummary, AgentRunId, AgentRunOutcome, AgentRunStreamSummary,
        AgentRunTerminalStatus,
    };
    use crate::core::{
        AgentKind, GitHubAccess, GitHubGrantedScope, GitHubPermissions, GitHubRequest,
        MetadataAccess, RepoRef, SessionRecord, TtlSeconds,
    };
    use proptest::prelude::*;
    use tempfile::NamedTempFile;

    fn sample_session() -> SessionRecord {
        SessionRecord {
            session_id: SessionId::new(),
            label: Some("test".into()),
            agent_kind: Some(AgentKind::Claude),
            agent_model: Some("claude-opus-4-7".into()),
            opened_at: UnixMillis::from_millis(1_700_000_000),
            closed_at: None,
        }
    }

    fn sample_repo() -> RepoRef {
        RepoRef {
            owner: "o".into(),
            name: "n".into(),
        }
    }

    fn sample_request() -> CapabilityRequest {
        CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Write,
            repo: sample_repo(),
        })
    }

    fn sample_scope() -> GrantedScope {
        GrantedScope::GitHub(GitHubGrantedScope {
            repository: sample_repo(),
            permissions: GitHubPermissions {
                contents: Some(GitHubAccess::Write),
                metadata: Some(MetadataAccess::Read),
                ..Default::default()
            },
        })
    }

    fn sample_git_repo() -> GitCloneRepo {
        GitCloneRepo::new(sample_repo()).unwrap()
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
            expected_remote_head: git_oid('1'),
            new_head: git_oid('2'),
        }
    }

    fn record_sample_write_grant(
        log: &AuditLog,
        session_id: SessionId,
        capability_request_id: RequestId,
    ) -> CredentialGrant {
        let req = sample_request();
        let scope = sample_scope();
        pre_mint(
            log,
            capability_request_id,
            session_id,
            &req,
            &PolicyDecision::Grant {
                scope: scope.clone(),
                ttl: TtlSeconds::new(300).unwrap(),
            },
            UnixMillis::from_millis(1_700_000_110),
        )
        .unwrap();
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id: capability_request_id,
            session_id,
            github_app_id: Some(42),
            scope,
            issued_at: UnixMillis::from_millis(1_700_000_110),
            expires_at: UnixMillis::from_millis(1_700_000_410),
        };
        log.record_grant(&grant).unwrap();
        grant
    }

    #[derive(Clone, Debug)]
    enum GitPushAuditScript {
        ValidAttempted {
            result: GitPushOutcomeResult,
            github_status: Option<u16>,
            close_before_outcome: bool,
            attempt_repo_case_differs: bool,
        },
        ValidUnattempted {
            result: GitPushOutcomeResult,
            close_before_outcome: bool,
        },
        RequestAfterClose,
        AttemptBeforeRequest,
        AttemptMissingGrant,
        AttemptMismatchedRepo,
        AttemptMismatchedBranch,
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
            )
                .prop_map(
                    |(result, github_status, close_before_outcome, attempt_repo_case_differs)| {
                        GitPushAuditScript::ValidAttempted {
                            result,
                            github_status,
                            close_before_outcome,
                            attempt_repo_case_differs,
                        }
                    },
                ),
            (unattempted_git_push_result_strategy(), any::<bool>()).prop_map(
                |(result, close_before_outcome)| GitPushAuditScript::ValidUnattempted {
                    result,
                    close_before_outcome,
                },
            ),
            Just(GitPushAuditScript::RequestAfterClose),
            Just(GitPushAuditScript::AttemptBeforeRequest),
            Just(GitPushAuditScript::AttemptMissingGrant),
            Just(GitPushAuditScript::AttemptMismatchedRepo),
            Just(GitPushAuditScript::AttemptMismatchedBranch),
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
            old_head: git_oid('1'),
            new_head: git_oid('2'),
        }
    }

    #[test]
    fn session_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let back = log.get_session(s.session_id).unwrap().unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn missing_session_returns_none() {
        let log = AuditLog::open_in_memory().unwrap();
        assert!(log.get_session(SessionId::new()).unwrap().is_none());
    }

    #[test]
    fn close_session_sets_closed_at() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_500))
            .unwrap();
        let back = log.get_session(s.session_id).unwrap().unwrap();
        assert_eq!(back.closed_at, Some(UnixMillis::from_millis(1_700_000_500)));
    }

    #[test]
    fn close_session_is_idempotent_on_already_closed() {
        // Our UPDATE only matches rows where closed_at IS NULL, so
        // a second close is a silent no-op.
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(100))
            .unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(200))
            .unwrap();
        let back = log.get_session(s.session_id).unwrap().unwrap();
        assert_eq!(back.closed_at, Some(UnixMillis::from_millis(100)));
    }

    #[test]
    fn agent_vm_workspace_bootstrap_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let record = AgentVmWorkspaceBootstrapAuditRecord {
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            repo: "owner/repo".into(),
            destination: "/workspace/repo".into(),
            branch: "main".into(),
            warm: "devshell".into(),
        };

        log.record_agent_vm_workspace_bootstrap(&record).unwrap();

        assert_eq!(
            log.get_agent_vm_workspace_bootstrap(s.session_id)
                .unwrap()
                .unwrap(),
            record
        );
    }

    #[test]
    fn agent_vm_workspace_bootstrap_requires_open_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        let record = AgentVmWorkspaceBootstrapAuditRecord {
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            repo: "owner/repo".into(),
            destination: "/workspace/repo".into(),
            branch: "main".into(),
            warm: "none".into(),
        };

        let err = log
            .record_agent_vm_workspace_bootstrap(&record)
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("session does not exist")
        ));

        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_200))
            .unwrap();
        let err = log
            .record_agent_vm_workspace_bootstrap(&record)
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant("session is closed")));
    }

    #[test]
    fn agent_run_and_outcome_roundtrip_without_raw_prompt_or_streams_in_audit() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let prompt = crate::agent_run::AgentPrompt::new("SECRET prompt body");
        let run_id = AgentRunId::new();
        let record = AgentRunAuditRecord {
            run_id,
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: prompt.summary(),
        };

        log.record_agent_run(&record).unwrap();

        let entry = log.get_agent_run(run_id).unwrap().unwrap();
        assert_eq!(entry.run_id, run_id);
        assert_eq!(entry.session_id, s.session_id);
        assert_eq!(entry.agent_kind, AgentKind::Claude);
        assert_eq!(entry.prompt.byte_len, prompt.byte_len());
        assert_eq!(entry.prompt.redacted_preview, "<redacted>");
        let debug = format!("{entry:?}");
        assert!(!debug.contains(prompt.as_str()), "{debug}");

        let outcome = AgentRunOutcome {
            run_id,
            status: AgentRunTerminalStatus::Failed,
            exit_code: 7,
            stdout: AgentRunStreamSummary {
                path: "/private/writ/runs/stdout.log".into(),
                byte_len: 12,
                sha256_hex: crate::agent_run::sha256_hex(b"stdout bytes"),
                truncated: false,
            },
            stderr: AgentRunStreamSummary {
                path: "/private/writ/runs/stderr.log".into(),
                byte_len: 4096,
                sha256_hex: crate::agent_run::sha256_hex(b"stderr bytes"),
                truncated: true,
            },
        };
        let outcome_record = AgentRunOutcomeAuditRecord {
            completed_at: UnixMillis::from_millis(1_700_000_200),
            outcome: outcome.clone(),
        };

        log.record_agent_run_outcome(&outcome_record).unwrap();

        let entry = log.get_agent_run_outcome(run_id).unwrap().unwrap();
        assert_eq!(entry.outcome.run_id, run_id);
        assert_eq!(entry.outcome, outcome);
    }

    #[test]
    fn agent_run_requires_open_session_but_outcome_can_land_after_close() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        let run_id = AgentRunId::new();
        let record = AgentRunAuditRecord {
            run_id,
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Codex,
            prompt: crate::agent_run::AgentPrompt::new("prompt").summary(),
        };

        let err = log.record_agent_run(&record).unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("session does not exist")
        ));

        log.open_session(&s).unwrap();
        log.record_agent_run(&record).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_150))
            .unwrap();

        let outcome = AgentRunOutcome {
            run_id,
            status: AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: AgentRunStreamSummary {
                path: "/private/writ/runs/stdout.log".into(),
                byte_len: 0,
                sha256_hex: crate::agent_run::sha256_hex(b""),
                truncated: false,
            },
            stderr: AgentRunStreamSummary {
                path: "/private/writ/runs/stderr.log".into(),
                byte_len: 0,
                sha256_hex: crate::agent_run::sha256_hex(b""),
                truncated: false,
            },
        };

        log.record_agent_run_outcome(&AgentRunOutcomeAuditRecord {
            completed_at: UnixMillis::from_millis(1_700_000_200),
            outcome,
        })
        .unwrap();

        let closed_run = AgentRunAuditRecord {
            run_id: AgentRunId::new(),
            ..record
        };
        let err = log.record_agent_run(&closed_run).unwrap_err();
        assert!(matches!(err, AuditError::Invariant("session is closed")));
    }

    #[test]
    fn agent_run_validation_errors_name_the_failed_field() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let err = log
            .record_agent_run(&AgentRunAuditRecord {
                run_id: AgentRunId::new(),
                session_id: s.session_id,
                requested_at: UnixMillis::from_millis(1_700_000_100),
                agent_kind: AgentKind::Claude,
                prompt: AgentPromptSummary {
                    byte_len: 1,
                    sha256_hex: "not sha256".to_string(),
                    redacted_preview: "<redacted>".to_string(),
                },
            })
            .unwrap_err();

        assert!(matches!(
            err,
            AuditError::LabeledInvariant {
                label: "agent run prompt sha256",
                message: "sha256 hex digest is invalid",
            }
        ));

        let err = log
            .record_agent_run_outcome(&AgentRunOutcomeAuditRecord {
                completed_at: UnixMillis::from_millis(1_700_000_200),
                outcome: AgentRunOutcome {
                    run_id: AgentRunId::new(),
                    status: AgentRunTerminalStatus::Succeeded,
                    exit_code: 0,
                    stdout: AgentRunStreamSummary {
                        path: "relative/stdout.log".into(),
                        byte_len: 0,
                        sha256_hex: crate::agent_run::sha256_hex(b""),
                        truncated: false,
                    },
                    stderr: AgentRunStreamSummary {
                        path: "/private/writ/runs/stderr.log".into(),
                        byte_len: 0,
                        sha256_hex: crate::agent_run::sha256_hex(b""),
                        truncated: false,
                    },
                },
            })
            .unwrap_err();

        assert!(matches!(
            err,
            AuditError::LabeledInvariant {
                label: "stdout",
                message: "agent run stream path must be absolute",
            }
        ));
    }

    /// Helper: stash the request+decision row so subsequent `record_grant`
    /// or `record_mint_failure` calls have something to attach to.
    fn pre_mint(
        log: &AuditLog,
        request_id: RequestId,
        session_id: SessionId,
        request: &CapabilityRequest,
        decision: &PolicyDecision,
        received_at: UnixMillis,
    ) -> Result<(), AuditError> {
        log.record_pre_mint(&PreMintRecord {
            request_id,
            session_id,
            received_at,
            request,
            decision,
        })
    }

    fn record_nix_cache_request(
        log: &AuditLog,
        request_id: RequestId,
        session_id: SessionId,
        decision: &NixCacheAuditDecision,
        route: NixCacheAuditRoute,
    ) -> Result<(), AuditError> {
        log.record_nix_cache_request(&NixCacheRequestRecord {
            request_id,
            session_id,
            received_at: UnixMillis::from_millis(1_700_000_100),
            method: "GET",
            target: "/v1/nix/cache/nix-cache-info",
            route,
            decision,
        })
    }

    #[test]
    fn nix_cache_request_then_outcome_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();

        record_nix_cache_request(
            &log,
            request_id,
            s.session_id,
            &NixCacheAuditDecision::Allow,
            NixCacheAuditRoute::CacheInfo,
        )
        .unwrap();
        log.record_nix_cache_outcome(&NixCacheOutcomeRecord {
            request_id,
            completed_at: UnixMillis::from_millis(1_700_000_120),
            http_status: 200,
            upstream_url: Some("https://cache.example.test/nix-cache-info"),
            upstream_status: Some(200),
            response_bytes: 48,
            error: None,
        })
        .unwrap();

        let entries = log
            .list_nix_cache_requests_for_session(s.session_id)
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].request_id, request_id);
        assert_eq!(entries[0].session_id, s.session_id);
        assert_eq!(entries[0].method, "GET");
        assert_eq!(entries[0].target, "/v1/nix/cache/nix-cache-info");
        assert_eq!(entries[0].route, NixCacheAuditRoute::CacheInfo);
        assert_eq!(entries[0].decision, NixCacheAuditDecision::Allow);
        assert_eq!(
            entries[0].completed_at,
            Some(UnixMillis::from_millis(1_700_000_120))
        );
        assert_eq!(entries[0].http_status, Some(200));
        assert_eq!(
            entries[0].upstream_url.as_deref(),
            Some("https://cache.example.test/nix-cache-info")
        );
        assert_eq!(entries[0].upstream_status, Some(200));
        assert_eq!(entries[0].response_bytes, Some(48));
        assert_eq!(entries[0].error, None);
    }

    #[test]
    fn nix_cache_deny_request_roundtrips_without_upstream() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        let decision = NixCacheAuditDecision::Deny {
            reason: "missing credentials".into(),
        };

        record_nix_cache_request(
            &log,
            request_id,
            s.session_id,
            &decision,
            NixCacheAuditRoute::Unsupported,
        )
        .unwrap();
        log.record_nix_cache_outcome(&NixCacheOutcomeRecord {
            request_id,
            completed_at: UnixMillis::from_millis(1_700_000_101),
            http_status: 401,
            upstream_url: None,
            upstream_status: None,
            response_bytes: 25,
            error: None,
        })
        .unwrap();

        let entries = log
            .list_nix_cache_requests_for_session(s.session_id)
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].decision, decision);
        assert_eq!(entries[0].route, NixCacheAuditRoute::Unsupported);
        assert_eq!(entries[0].http_status, Some(401));
        assert_eq!(entries[0].upstream_url, None);
        assert_eq!(entries[0].upstream_status, None);
    }

    #[test]
    fn nix_cache_nar_request_route_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();

        record_nix_cache_request(
            &log,
            request_id,
            s.session_id,
            &NixCacheAuditDecision::Allow,
            NixCacheAuditRoute::Nar,
        )
        .unwrap();
        log.record_nix_cache_outcome(&NixCacheOutcomeRecord {
            request_id,
            completed_at: UnixMillis::from_millis(1_700_000_130),
            http_status: 200,
            upstream_url: Some("https://cache.example.test/nar/proof.nar.xz"),
            upstream_status: Some(200),
            response_bytes: 8192,
            error: None,
        })
        .unwrap();

        let entries = log
            .list_nix_cache_requests_for_session(s.session_id)
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::Nar);
        assert_eq!(entries[0].http_status, Some(200));
        assert_eq!(entries[0].response_bytes, Some(8192));
    }

    #[test]
    fn nix_cache_request_rejects_closed_or_missing_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_050))
            .unwrap();

        let closed = record_nix_cache_request(
            &log,
            RequestId::new(),
            s.session_id,
            &NixCacheAuditDecision::Allow,
            NixCacheAuditRoute::CacheInfo,
        )
        .unwrap_err();
        assert!(
            matches!(closed, AuditError::Invariant("session is closed")),
            "got: {closed:?}"
        );

        let missing = record_nix_cache_request(
            &log,
            RequestId::new(),
            SessionId::new(),
            &NixCacheAuditDecision::Allow,
            NixCacheAuditRoute::CacheInfo,
        )
        .unwrap_err();
        assert!(
            matches!(missing, AuditError::Invariant("session does not exist")),
            "got: {missing:?}"
        );
    }

    #[test]
    fn nix_cache_outcome_without_request_is_rejected() {
        let log = AuditLog::open_in_memory().unwrap();
        let err = log
            .record_nix_cache_outcome(&NixCacheOutcomeRecord {
                request_id: RequestId::new(),
                completed_at: UnixMillis::from_millis(1),
                http_status: 502,
                upstream_url: Some("https://cache.example.test/nix-cache-info"),
                upstream_status: None,
                response_bytes: 0,
                error: Some("upstream request failed"),
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
    fn claude_proxy_request_then_outcome_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();

        log.record_claude_proxy_request(&ClaudeProxyRequestRecord {
            request_id,
            session_id: s.session_id,
            received_at: UnixMillis::from_millis(1_700_000_200),
            method: "POST",
            target: "/v1/messages",
            route: ClaudeProxyAuditRoute::Messages,
            decision: &ClaudeProxyAuditDecision::Allow,
        })
        .unwrap();
        log.record_claude_proxy_outcome(&ClaudeProxyOutcomeRecord {
            request_id,
            completed_at: UnixMillis::from_millis(1_700_000_240),
            http_status: 200,
            upstream_url: Some("https://api.anthropic.com/v1/messages"),
            upstream_status: Some(200),
            response_bytes: 128,
            error: None,
        })
        .unwrap();

        let entry = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT r.method, r.target, r.route, r.decision,
                            o.http_status, o.upstream_url, o.upstream_status, o.response_bytes
                     FROM claude_proxy_request r
                     JOIN claude_proxy_outcome o USING (request_id)
                     WHERE r.request_id = ?1",
                    params![request_id.as_uuid().to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, i64>(7)?,
                        ))
                    },
                )?)
            })
            .unwrap();
        assert_eq!(
            entry,
            (
                "POST".into(),
                "/v1/messages".into(),
                "messages".into(),
                "allow".into(),
                200,
                "https://api.anthropic.com/v1/messages".into(),
                200,
                128,
            )
        );
    }

    #[test]
    fn openai_proxy_request_then_outcome_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();

        log.record_openai_proxy_request(&OpenAiProxyRequestRecord {
            request_id,
            session_id: s.session_id,
            received_at: UnixMillis::from_millis(1_700_000_300),
            method: "POST",
            target: "/v1/responses",
            route: OpenAiProxyAuditRoute::Responses,
            decision: &OpenAiProxyAuditDecision::Allow,
        })
        .unwrap();
        log.record_openai_proxy_outcome(&OpenAiProxyOutcomeRecord {
            request_id,
            completed_at: UnixMillis::from_millis(1_700_000_340),
            http_status: 200,
            upstream_url: Some("https://api.openai.com/v1/responses"),
            upstream_status: Some(200),
            response_bytes: 256,
            error: None,
        })
        .unwrap();

        let entries = log
            .list_openai_proxy_requests_for_session_for_test(s.session_id)
            .unwrap();
        assert_eq!(
            entries,
            vec![(
                OpenAiProxyAuditRoute::Responses,
                OpenAiProxyAuditDecision::Allow,
                Some(200),
            )]
        );
        assert_eq!(
            log.openai_proxy_outcome_for_test(request_id).unwrap(),
            Some((200, 256, None))
        );
    }

    #[test]
    fn openai_proxy_request_rejects_closed_or_missing_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_050))
            .unwrap();

        let closed = log
            .record_openai_proxy_request(&OpenAiProxyRequestRecord {
                request_id: RequestId::new(),
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(1_700_000_100),
                method: "POST",
                target: "/v1/responses",
                route: OpenAiProxyAuditRoute::Responses,
                decision: &OpenAiProxyAuditDecision::Allow,
            })
            .unwrap_err();
        assert!(
            matches!(closed, AuditError::Invariant("session is closed")),
            "got: {closed:?}"
        );

        let missing = log
            .record_openai_proxy_request(&OpenAiProxyRequestRecord {
                request_id: RequestId::new(),
                session_id: SessionId::new(),
                received_at: UnixMillis::from_millis(1_700_000_100),
                method: "POST",
                target: "/v1/responses",
                route: OpenAiProxyAuditRoute::Responses,
                decision: &OpenAiProxyAuditDecision::Allow,
            })
            .unwrap_err();
        assert!(
            matches!(missing, AuditError::Invariant("session does not exist")),
            "got: {missing:?}"
        );
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
            old_head: git_oid('1'),
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
        assert_eq!(entry.expected_remote_head, git_oid('1'));
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
                } => {
                    log.record_git_push_request(&push_request).unwrap();
                    let grant = record_sample_write_grant(&log, s.session_id, capability_request_id);
                    let attempt_repo = if attempt_repo_case_differs {
                        git_repo("O", "N")
                    } else {
                        sample_git_repo()
                    };
                    log.record_git_push_attempt(&git_push_attempt_record(
                        push_attempt_id,
                        push_request_id,
                        capability_request_id,
                        grant.jti,
                        attempt_repo,
                        "main".parse().unwrap(),
                    ))
                    .unwrap();
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
                            push_attempt_id: Some(push_attempt_id),
                            capability_request_id: Some(capability_request_id),
                            grant_jti: Some(grant.jti),
                            planned_at: Some(UnixMillis::from_millis(1_700_000_120)),
                            old_head: Some(git_oid('1')),
                            attempted_new_head: Some(git_oid('2')),
                            completed_at: Some(UnixMillis::from_millis(1_700_000_130)),
                            result: Some(result),
                            github_status,
                            message: Some("state-machine outcome".into()),
                        }]
                    );
                }
                GitPushAuditScript::ValidUnattempted {
                    result,
                    close_before_outcome,
                } => {
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
                old_head: git_oid('1'),
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
                old_head: git_oid('1'),
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
            old_head: git_oid('1'),
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

    #[test]
    fn pre_mint_then_record_grant_writes_both_tables() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let scope = sample_scope();
        let decision = PolicyDecision::Grant {
            scope: scope.clone(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: scope.clone(),
            issued_at: UnixMillis::from_millis(1_700_000_100),
            expires_at: UnixMillis::from_millis(1_700_000_400),
        };

        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();
        log.record_grant(&grant).unwrap();

        let grants = log.list_grants_for_session(s.session_id).unwrap();
        assert_eq!(grants, vec![grant.clone()]);
        let got = log.get_grant(grant.jti).unwrap().unwrap();
        assert_eq!(got, grant);
    }

    #[test]
    fn record_grant_rejects_missing_github_app_id() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let scope = sample_scope();
        let decision = PolicyDecision::Grant {
            scope: scope.clone(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();

        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: None,
            scope,
            issued_at: UnixMillis::from_millis(1_700_000_100),
            expires_at: UnixMillis::from_millis(1_700_000_400),
        };

        let err = log.record_grant(&grant).unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant("grant.github_app_id is missing")),
            "got: {err:?}"
        );
    }

    #[test]
    fn record_pre_mint_for_deny_writes_no_grant() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "policy says no".into(),
        };

        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();

        assert!(
            log.list_grants_for_session(s.session_id)
                .unwrap()
                .is_empty()
        );
    }

    /// A Deny request has no mint step, so there is no legitimate reason
    /// for a caller to append a grant against it. The audit layer reads
    /// the recorded decision back and refuses.
    #[test]
    fn record_grant_rejected_when_request_has_deny_decision() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "no".into(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();

        let bogus_grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(1),
            expires_at: UnixMillis::from_millis(2),
        };
        let err = log.record_grant(&bogus_grant).unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)));
    }

    /// `record_grant` depends on a prior `record_pre_mint` (FK enforces
    /// it at the DB layer too, but the app-layer check produces a
    /// readable error rather than a generic FK violation).
    #[test]
    fn record_grant_without_pre_mint_is_rejected() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id: RequestId::new(),
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(1),
            expires_at: UnixMillis::from_millis(2),
        };
        let err = log.record_grant(&grant).unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant(_)),
            "expected Invariant, got: {err:?}"
        );
    }

    /// Same invariant for `record_mint_failure`.
    #[test]
    fn record_mint_failure_without_pre_mint_is_rejected() {
        let log = AuditLog::open_in_memory().unwrap();
        let err = log
            .record_mint_failure(RequestId::new(), UnixMillis::from_millis(1), "boom")
            .unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant(_)),
            "expected Invariant, got: {err:?}"
        );
    }

    /// Regression: without `PRAGMA foreign_keys = ON`, SQLite silently
    /// ignores `REFERENCES` clauses and accepts orphan rows. Force a known
    /// FK violation and check the broker refuses it.
    #[test]
    fn foreign_key_enforcement_rejects_orphan_grant_row() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        // Bypass `record` (which would block this at the application layer)
        // and write directly. The FK to `request(request_id)` must bite.
        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO grant_log (jti, request_id, session_id, scope_json, issued_at, expires_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        Jti::new().as_uuid().to_string(),
                        RequestId::new().as_uuid().to_string(), // no matching request row
                        s.session_id.as_uuid().to_string(),
                        "{}",
                        1_i64,
                        2_i64,
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite FK error, got: {err:?}");
        };
        let msg = e.to_string().to_lowercase();
        assert!(
            msg.contains("foreign key"),
            "expected FK violation, got: {e}"
        );
    }

    /// Same as above but for the `session_id` FK from `request`. Belt and
    /// braces — both FK paths matter.
    #[test]
    fn foreign_key_enforcement_rejects_orphan_request_row() {
        let log = AuditLog::open_in_memory().unwrap();
        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO request (request_id, session_id, received_at, request_json, decision_json) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        RequestId::new().as_uuid().to_string(),
                        SessionId::new().as_uuid().to_string(), // no matching session row
                        1_i64,
                        "{}",
                        "{}",
                    ],
                )?;
                Ok(())
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
    fn grants_are_returned_in_issue_order() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let mk_grant = |at: i64| {
            let request_id = RequestId::new();
            let decision = PolicyDecision::Grant {
                scope: sample_scope(),
                ttl: TtlSeconds::new(300).unwrap(),
            };
            let grant = CredentialGrant {
                jti: Jti::new(),
                request_id,
                session_id: s.session_id,
                github_app_id: Some(42),
                scope: sample_scope(),
                issued_at: UnixMillis::from_millis(at),
                expires_at: UnixMillis::from_millis(at + 300),
            };
            let request = sample_request();
            pre_mint(
                &log,
                request_id,
                s.session_id,
                &request,
                &decision,
                UnixMillis::from_millis(at),
            )
            .unwrap();
            log.record_grant(&grant).unwrap();
            grant
        };

        let a = mk_grant(1000);
        let b = mk_grant(2000);
        let c = mk_grant(1500);

        let listed = log.list_grants_for_session(s.session_id).unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|g| g.issued_at.as_millis())
                .collect::<Vec<_>>(),
            vec![1000, 1500, 2000]
        );
        assert_eq!(
            listed.iter().map(|g| g.jti).collect::<Vec<_>>(),
            vec![a.jti, c.jti, b.jti]
        );
    }

    /// With millisecond resolution two grants can still share an
    /// `issued_at`, so `list_grants_for_session` must fall back on insert
    /// order rather than leaving the tie undefined. Record two rows with
    /// identical timestamps and check they come back in the order they
    /// were written.
    #[test]
    fn grants_with_identical_issued_at_preserve_insert_order() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let mk_grant = || {
            let request_id = RequestId::new();
            let decision = PolicyDecision::Grant {
                scope: sample_scope(),
                ttl: TtlSeconds::new(300).unwrap(),
            };
            let grant = CredentialGrant {
                jti: Jti::new(),
                request_id,
                session_id: s.session_id,
                github_app_id: Some(42),
                scope: sample_scope(),
                issued_at: UnixMillis::from_millis(5_000),
                expires_at: UnixMillis::from_millis(5_300),
            };
            let request = sample_request();
            pre_mint(
                &log,
                request_id,
                s.session_id,
                &request,
                &decision,
                UnixMillis::from_millis(5_000),
            )
            .unwrap();
            log.record_grant(&grant).unwrap();
            grant
        };

        let first = mk_grant();
        let second = mk_grant();
        let third = mk_grant();

        let listed = log.list_grants_for_session(s.session_id).unwrap();
        assert_eq!(
            listed.iter().map(|g| g.jti).collect::<Vec<_>>(),
            vec![first.jti, second.jti, third.jti]
        );
    }

    /// If the decision grants one scope but the supplied grant record
    /// carries a different one, the two rows would describe contradictory
    /// authority for the same request. `record_grant` loads the recorded
    /// decision back from the DB so it can cross-check without trusting
    /// the caller to re-supply it.
    #[test]
    fn record_grant_rejects_grant_with_divergent_scope() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision_scope = sample_scope();
        let decision = PolicyDecision::Grant {
            scope: decision_scope,
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_000),
        )
        .unwrap();

        let other_scope = GrantedScope::GitHub(GitHubGrantedScope {
            repository: RepoRef {
                owner: "different".into(),
                name: "repo".into(),
            },
            permissions: GitHubPermissions {
                contents: Some(GitHubAccess::Read),
                metadata: Some(MetadataAccess::Read),
                ..Default::default()
            },
        });
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: other_scope,
            issued_at: UnixMillis::from_millis(1_000),
            expires_at: UnixMillis::from_millis(2_000),
        };

        let err = log.record_grant(&grant).unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// Same idea as scope divergence: if the grant's effective lifetime
    /// grossly overshoots the decision's TTL ceiling, the two rows would
    /// disagree on how long the authority lasts. The audit layer allows
    /// a small skew (so minter clock tolerance doesn't spuriously trip
    /// it) but rejects anything beyond that.
    #[test]
    fn record_grant_rejects_lifetime_exceeding_ttl() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(60).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(0),
        )
        .unwrap();

        // Decision says 60s (60_000 ms). Grant lifetime is 1h (3_600_000 ms),
        // well past the 60_000 ms skew tolerance.
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(0),
            expires_at: UnixMillis::from_millis(3_600_000),
        };

        let err = log.record_grant(&grant).unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// An inverted expiry (expires before issued) would otherwise slip
    /// past the TTL-ceiling comparison because the signed
    /// `saturating_sub` produces a negative lifetime that's trivially
    /// under any positive ceiling. Explicit check catches the sign class.
    #[test]
    fn record_grant_rejects_expiry_before_issue() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(500),
        )
        .unwrap();

        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(500),
            // Deliberately before issued_at.
            expires_at: UnixMillis::from_millis(100),
        };

        let err = log.record_grant(&grant).unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// The other side of the boundary: a grant whose lifetime lands
    /// exactly at the TTL+skew ceiling must still be accepted, otherwise
    /// a minter operating inside its documented skew tolerance couldn't
    /// record its own grants.
    #[test]
    fn record_grant_accepts_lifetime_within_ttl_plus_skew() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let ttl_seconds: i64 = 300;
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(ttl_seconds).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(0),
        )
        .unwrap();

        // Lifetime = ttl + full skew tolerance, exactly on the boundary.
        let lifetime_millis = ttl_seconds * 1000 + AUDIT_TTL_SKEW_TOLERANCE_MILLIS;
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(0),
            expires_at: UnixMillis::from_millis(lifetime_millis),
        };

        log.record_grant(&grant).unwrap();
    }

    #[test]
    fn record_mint_failure_writes_to_mint_failure_table() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();

        log.record_mint_failure(
            request_id,
            UnixMillis::from_millis(1_700_000_105),
            "GitHub returned 422: repository not installed",
        )
        .unwrap();

        assert!(
            log.list_grants_for_session(s.session_id)
                .unwrap()
                .is_empty()
        );
        let recorded = log
            .with_conn(|c| {
                let json: String = c.query_row(
                    "SELECT failure_json FROM mint_failure WHERE request_id = ?1",
                    params![request_id.as_uuid().to_string()],
                    |row| row.get(0),
                )?;
                Ok(json)
            })
            .unwrap();
        let failure: MintFailureRecord = serde_json::from_str(&recorded).unwrap();
        assert_eq!(
            failure.error,
            "GitHub returned 422: repository not installed"
        );
    }

    /// Recording a grant *and* a mint failure for the same request_id
    /// would leave replay with contradictory outcomes. The cross-
    /// exclusion trigger on each table refuses the second insert.
    #[test]
    fn record_grant_and_mint_failure_are_mutually_exclusive() {
        for grant_first in [true, false] {
            let log = AuditLog::open_in_memory().unwrap();
            let s = sample_session();
            log.open_session(&s).unwrap();
            let request_id = RequestId::new();
            let req = sample_request();
            let decision = PolicyDecision::Grant {
                scope: sample_scope(),
                ttl: TtlSeconds::new(300).unwrap(),
            };
            pre_mint(
                &log,
                request_id,
                s.session_id,
                &req,
                &decision,
                UnixMillis::from_millis(0),
            )
            .unwrap();
            let grant = CredentialGrant {
                jti: Jti::new(),
                request_id,
                session_id: s.session_id,
                github_app_id: Some(42),
                scope: sample_scope(),
                issued_at: UnixMillis::from_millis(0),
                expires_at: UnixMillis::from_millis(1_000),
            };

            let (first, second) = if grant_first {
                (
                    log.record_grant(&grant),
                    log.record_mint_failure(request_id, UnixMillis::from_millis(10), "boom"),
                )
            } else {
                (
                    log.record_mint_failure(request_id, UnixMillis::from_millis(10), "boom")
                        .map(|_| ()),
                    log.record_grant(&grant),
                )
            };
            first.unwrap_or_else(|e| panic!("first insert should succeed: {e}"));
            let err = second.unwrap_err();
            let msg = format!("{err}").to_lowercase();
            assert!(
                msg.contains("already recorded"),
                "expected cross-exclusion trigger, got: {err:?}"
            );
        }
    }

    /// If the caller accidentally pairs a `Metadata` request with a
    /// `Contents:write` grant decision, the pre-mint row would claim
    /// authority the request never asked for. `record_pre_mint` rejects
    /// the pairing before any row lands.
    #[test]
    fn record_pre_mint_rejects_decision_scope_exceeding_request() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let metadata_request = CapabilityRequest::GitHub(GitHubRequest::Metadata {
            repo: sample_repo(),
        });
        let contents_write_scope = sample_scope();
        let decision = PolicyDecision::Grant {
            scope: contents_write_scope,
            ttl: TtlSeconds::new(300).unwrap(),
        };

        let err = pre_mint(
            &log,
            RequestId::new(),
            s.session_id,
            &metadata_request,
            &decision,
            UnixMillis::from_millis(0),
        )
        .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// Grant decision for a different repo than the request — structurally
    /// impossible output of the policy engine, so recording it would
    /// corrupt replay.
    #[test]
    fn record_pre_mint_rejects_grant_decision_on_different_repo() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request = CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Write,
            repo: sample_repo(),
        });
        let other_scope = GrantedScope::GitHub(GitHubGrantedScope {
            repository: RepoRef {
                owner: "other".into(),
                name: "repo".into(),
            },
            permissions: GitHubPermissions {
                contents: Some(GitHubAccess::Write),
                metadata: Some(MetadataAccess::Read),
                ..Default::default()
            },
        });
        let decision = PolicyDecision::Grant {
            scope: other_scope,
            ttl: TtlSeconds::new(300).unwrap(),
        };

        let err = pre_mint(
            &log,
            RequestId::new(),
            s.session_id,
            &request,
            &decision,
            UnixMillis::from_millis(0),
        )
        .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// Grant decision with the right resource but wrong access level
    /// (request read, decision write) is not a possible policy output for
    /// a correctly-paired request. Reject.
    #[test]
    fn record_pre_mint_rejects_decision_access_level_exceeding_request() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let read_request = CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Read,
            repo: sample_repo(),
        });
        // sample_scope() grants contents:write — stricter than the read
        // the request asked for.
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };

        let err = pre_mint(
            &log,
            RequestId::new(),
            s.session_id,
            &read_request,
            &decision,
            UnixMillis::from_millis(0),
        )
        .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// A Deny decision cannot carry a mint failure — the denied request
    /// never reaches the mint step.
    #[test]
    fn record_mint_failure_rejected_for_deny_decision() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "no".into(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();

        let err = log
            .record_mint_failure(
                request_id,
                UnixMillis::from_millis(1_700_000_110),
                "should not exist",
            )
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)));
    }

    /// An empty mint-failure message is not a legitimate audit row —
    /// replay couldn't distinguish it from a missing error.
    #[test]
    fn record_mint_failure_rejects_empty_error() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(0),
        )
        .unwrap();
        let err = log
            .record_mint_failure(request_id, UnixMillis::from_millis(5), "")
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// A closed session must not accumulate new pre-mint rows —
    /// otherwise its `closed_at` no longer bounds the session's activity
    /// window, which is the whole point of recording a close timestamp.
    /// The check has to live inside `record_pre_mint`'s transaction
    /// (belt) and inside a DB trigger (braces); this exercise covers
    /// the belt.
    #[test]
    fn record_pre_mint_rejects_write_against_closed_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_050))
            .unwrap();

        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        let err = pre_mint(
            &log,
            RequestId::new(),
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant("session is closed")),
            "got: {err:?}"
        );
    }

    /// Same rule applies to Deny rows: a closed session must not
    /// accumulate any new request rows at all, not just Grant ones.
    #[test]
    fn record_pre_mint_rejects_deny_against_closed_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_050))
            .unwrap();

        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "any".into(),
        };
        let err = pre_mint(
            &log,
            RequestId::new(),
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant("session is closed")),
            "got: {err:?}"
        );
    }

    /// The core fix: a CloseSession that lands *after* `record_pre_mint`
    /// commits but *before* the backend mint finishes must not prevent
    /// the broker from appending the resulting grant. The authority to
    /// mint was established when the pre-mint row committed; the grant
    /// is its truthful outcome and belongs in the log.
    #[test]
    fn record_grant_succeeds_when_session_closed_after_pre_mint() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();

        // Simulate CloseSession landing during the mint's `await`.
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_150))
            .unwrap();

        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(1_700_000_200),
            expires_at: UnixMillis::from_millis(1_700_000_500),
        };
        log.record_grant(&grant).unwrap();
        assert_eq!(
            log.list_grants_for_session(s.session_id).unwrap(),
            vec![grant]
        );
    }

    /// Symmetrical guarantee for the failure side: if the mint fails
    /// after the session has been closed, the failure must still be
    /// recorded — the broker accepted the request and called GitHub.
    #[test]
    fn record_mint_failure_succeeds_when_session_closed_after_pre_mint() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_150))
            .unwrap();

        log.record_mint_failure(
            request_id,
            UnixMillis::from_millis(1_700_000_200),
            "GitHub 503",
        )
        .unwrap();
    }

    /// Bypassing `record` (and therefore its in-transaction check) must
    /// still be caught: the BEFORE-INSERT trigger on `request` raises
    /// when the referenced session has `closed_at` set. This is the
    /// "braces" to the application-layer belt — the DB refuses to hold
    /// an audit row against a closed session even if the caller forgot
    /// to check.
    #[test]
    fn trigger_rejects_direct_insert_against_closed_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_050))
            .unwrap();

        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO request (request_id, session_id, received_at, request_json, decision_json) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        RequestId::new().as_uuid().to_string(),
                        s.session_id.as_uuid().to_string(),
                        1_700_000_100_i64,
                        "{}",
                        "{}",
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite trigger error, got: {err:?}");
        };
        assert!(
            e.to_string().to_lowercase().contains("session is closed"),
            "expected trigger message, got: {e}"
        );
    }

    /// An open session is still writable — a narrow regression test
    /// that the new trigger's `WHEN` clause doesn't accidentally fire
    /// when `closed_at IS NULL`.
    #[test]
    fn trigger_allows_insert_against_open_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        log.with_conn(|c| {
            c.execute(
                "INSERT INTO request (request_id, session_id, received_at, request_json, decision_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    RequestId::new().as_uuid().to_string(),
                    s.session_id.as_uuid().to_string(),
                    1_700_000_100_i64,
                    "{}",
                    "{}",
                ],
            )?;
            Ok(())
        })
        .unwrap();
    }

    /// A recorded audit row for an unknown session was previously
    /// caught only by the FK; `record_pre_mint` reports it explicitly so
    /// the error is readable rather than leaking SQLite's message.
    #[test]
    fn record_pre_mint_rejects_write_against_nonexistent_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let phantom = SessionId::new();
        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "any".into(),
        };
        let err = pre_mint(
            &log,
            RequestId::new(),
            phantom,
            &req,
            &decision,
            UnixMillis::from_millis(1),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant("session does not exist")),
            "got: {err:?}"
        );
    }

    fn read_user_version(log: &AuditLog) -> i32 {
        log.with_conn(user_version).unwrap()
    }

    fn column_exists(log: &AuditLog, table: &str, column: &str) -> bool {
        log.with_conn(|c| {
            let mut stmt = c.prepare(&format!("PRAGMA table_info({table})"))?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                if name == column {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .unwrap()
    }

    fn trigger_exists(log: &AuditLog, name: &str) -> bool {
        log.with_conn(|c| {
            let count: i64 = c.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                params![name],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        })
        .unwrap()
    }

    #[test]
    fn fresh_install_is_at_current_schema_version() {
        let log = AuditLog::open_in_memory().unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "mint_failure", "request_id"));
        assert!(column_exists(&log, "session", "agent_kind"));
        assert!(column_exists(&log, "grant_log", "github_app_id"));
        assert!(trigger_exists(&log, "request_requires_open_session"));
        assert!(trigger_exists(&log, "mint_failure_excludes_grant"));
        assert!(trigger_exists(&log, "grant_excludes_mint_failure"));
        assert!(column_exists(&log, "nix_cache_request", "route"));
        assert!(column_exists(&log, "nix_cache_outcome", "upstream_status"));
        assert!(column_exists(
            &log,
            "agent_vm_workspace_bootstrap",
            "session_id"
        ));
        assert!(trigger_exists(
            &log,
            "nix_cache_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "agent_vm_workspace_bootstrap_requires_open_session"
        ));
        assert!(column_exists(&log, "agent_run", "prompt_sha256"));
        assert!(column_exists(&log, "agent_run_outcome", "stdout_path"));
        assert!(trigger_exists(&log, "agent_run_requires_open_session"));
        assert!(column_exists(
            &log,
            "git_push_request",
            "expected_remote_head"
        ));
        assert!(column_exists(&log, "git_push_attempt", "grant_jti"));
        assert!(column_exists(&log, "git_push_outcome", "result"));
        assert!(trigger_exists(
            &log,
            "git_push_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "git_push_attempt_requires_matching_grant"
        ));
        assert!(trigger_exists(
            &log,
            "git_push_outcome_attempt_matches_request"
        ));
        assert!(column_exists(&log, "claude_proxy_request", "route"));
        assert!(column_exists(
            &log,
            "claude_proxy_outcome",
            "upstream_status"
        ));
        assert!(trigger_exists(
            &log,
            "claude_proxy_request_requires_open_session"
        ));
        assert!(column_exists(&log, "openai_proxy_request", "route"));
        assert!(column_exists(
            &log,
            "openai_proxy_outcome",
            "upstream_status"
        ));
        assert!(trigger_exists(
            &log,
            "openai_proxy_request_requires_open_session"
        ));
    }

    #[test]
    fn open_initialises_empty_file_db_at_current_schema_version() {
        let db = NamedTempFile::new().unwrap();
        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "session", "session_id"));
        assert!(column_exists(&log, "session", "agent_kind"));
        assert!(column_exists(&log, "request", "decision_json"));
        assert!(column_exists(&log, "grant_log", "jti"));
        assert!(column_exists(&log, "grant_log", "github_app_id"));
        assert!(column_exists(&log, "mint_failure", "failure_json"));
        assert!(column_exists(&log, "nix_cache_request", "request_id"));
        assert!(column_exists(&log, "nix_cache_outcome", "request_id"));
        assert!(column_exists(&log, "agent_vm_workspace_bootstrap", "warm"));
        assert!(column_exists(&log, "agent_run", "prompt_redacted_preview"));
        assert!(column_exists(&log, "agent_run_outcome", "stderr_sha256"));
        assert!(column_exists(&log, "git_push_request", "new_head"));
        assert!(column_exists(&log, "git_push_attempt", "old_head"));
        assert!(column_exists(&log, "git_push_outcome", "message"));
        assert!(column_exists(&log, "claude_proxy_request", "request_id"));
        assert!(column_exists(
            &log,
            "claude_proxy_outcome",
            "response_bytes"
        ));
        assert!(column_exists(&log, "openai_proxy_request", "request_id"));
        assert!(column_exists(
            &log,
            "openai_proxy_outcome",
            "response_bytes"
        ));
        assert!(trigger_exists(&log, "request_requires_open_session"));
        assert!(trigger_exists(
            &log,
            "nix_cache_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "agent_vm_workspace_bootstrap_requires_open_session"
        ));
        assert!(trigger_exists(&log, "agent_run_requires_open_session"));
        assert!(trigger_exists(
            &log,
            "git_push_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "claude_proxy_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "openai_proxy_request_requires_open_session"
        ));
    }

    #[test]
    fn reopen_at_current_version_is_a_noop() {
        // The pragma check is what makes this cheap on startup; verify
        // re-running migrate on an already-current DB doesn't error and
        // doesn't bump the version past the supported max.
        let db = NamedTempFile::new().unwrap();
        {
            let log = AuditLog::open(db.path()).unwrap();
            assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        }
        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
    }

    #[test]
    fn open_migrates_v1_database_to_nix_cache_audit_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            tx.execute_batch(MIGRATIONS[0].sql).unwrap();
            tx.pragma_update(None, "user_version", 1).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "nix_cache_request", "decision"));
        assert!(column_exists(&log, "nix_cache_outcome", "response_bytes"));
        assert!(column_exists(&log, "session", "agent_kind"));
        assert!(column_exists(&log, "grant_log", "github_app_id"));
        assert!(column_exists(&log, "agent_vm_workspace_bootstrap", "repo"));
        assert!(column_exists(&log, "agent_run", "run_id"));
        assert!(column_exists(&log, "agent_run_outcome", "run_id"));
        assert!(trigger_exists(
            &log,
            "nix_cache_request_requires_open_session"
        ));
    }

    #[test]
    fn open_migrates_v2_database_to_nar_cache_audit_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            tx.execute_batch(MIGRATIONS[0].sql).unwrap();
            tx.execute_batch(MIGRATIONS[1].sql).unwrap();
            tx.pragma_update(None, "user_version", 2).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        record_nix_cache_request(
            &log,
            request_id,
            s.session_id,
            &NixCacheAuditDecision::Allow,
            NixCacheAuditRoute::Nar,
        )
        .unwrap();

        let entries = log
            .list_nix_cache_requests_for_session(s.session_id)
            .unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::Nar);
    }

    #[test]
    fn open_migrates_v4_grant_rows_without_github_app_id() {
        let db = NamedTempFile::new().unwrap();
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let jti = Jti::new();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(4) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 4).unwrap();
            tx.execute(
                "INSERT INTO session (session_id, label, agent_kind, agent_model, opened_at, closed_at) \
                 VALUES (?1, NULL, 'claude', NULL, 1, NULL)",
                params![session_id.as_uuid().to_string()],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO request (request_id, session_id, received_at, request_json, decision_json) \
                 VALUES (?1, ?2, 2, '{}', '{}')",
                params![
                    request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                ],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO grant_log (jti, request_id, session_id, scope_json, issued_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, 3, 4)",
                params![
                    jti.as_uuid().to_string(),
                    request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                    serde_json::to_string(&sample_scope()).unwrap(),
                ],
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "grant_log", "github_app_id"));
        let grant = log.get_grant(jti).unwrap().unwrap();
        assert_eq!(grant.github_app_id, None);
    }

    #[test]
    fn open_migrates_v5_database_to_agent_vm_workspace_bootstrap_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(5) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 5).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(
            &log,
            "agent_vm_workspace_bootstrap",
            "destination"
        ));
        assert!(trigger_exists(
            &log,
            "agent_vm_workspace_bootstrap_requires_open_session"
        ));
    }

    #[test]
    fn open_migrates_v6_database_to_agent_run_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(6) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 6).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "agent_run", "prompt_sha256"));
        assert!(column_exists(&log, "agent_run_outcome", "stdout_path"));
        assert!(trigger_exists(&log, "agent_run_requires_open_session"));
    }

    #[test]
    fn open_migrates_v7_database_to_git_push_audit_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(7) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 7).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "git_push_request", "repo"));
        assert!(column_exists(
            &log,
            "git_push_attempt",
            "capability_request_id"
        ));
        assert!(column_exists(&log, "git_push_outcome", "github_status"));
        assert!(trigger_exists(
            &log,
            "git_push_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "git_push_attempt_requires_matching_grant"
        ));
        assert!(trigger_exists(
            &log,
            "git_push_outcome_attempt_matches_request"
        ));
    }

    #[test]
    fn open_migrates_v8_database_to_claude_proxy_audit_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(8) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 8).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "claude_proxy_request", "target"));
        assert!(column_exists(&log, "claude_proxy_outcome", "http_status"));
        assert!(trigger_exists(
            &log,
            "claude_proxy_request_requires_open_session"
        ));
    }

    #[test]
    fn open_migrates_v10_database_to_openai_proxy_audit_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(10) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 10).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "openai_proxy_request", "target"));
        assert!(column_exists(&log, "openai_proxy_outcome", "http_status"));
        assert!(trigger_exists(
            &log,
            "openai_proxy_request_requires_open_session"
        ));
    }

    /// A DB written by a future broker will carry a user_version beyond
    /// what this binary knows. Refuse to open rather than risk silently
    /// ignoring columns the newer schema relies on.
    #[test]
    fn open_rejects_schema_newer_than_supported() {
        let db = NamedTempFile::new().unwrap();
        {
            // Build at current version, then tell the DB it's from the future.
            let _ = AuditLog::open(db.path()).unwrap();
            let c = Connection::open(db.path()).unwrap();
            c.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        let err = AuditLog::open(db.path()).unwrap_err();
        match err {
            AuditError::SchemaTooNew { found, supported } => {
                assert_eq!(found, SCHEMA_VERSION + 1);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
    }
}
