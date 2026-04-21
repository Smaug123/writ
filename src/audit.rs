//! Audit log backed by SQLite.
//!
//! The log is the system-of-record for broker activity: every session,
//! every capability request, every credential grant lands here. The raw
//! JSON for requests, decisions, and scopes is stored verbatim, so the
//! log can be replayed to reconstruct history without depending on the
//! broker binary staying source-compatible.
//!
//! The `request` and `grant_log` tables are strictly append-only: once a
//! row lands it is never mutated or deleted. This is the part that
//! matters for audit-integrity claims.
//!
//! The `session` table carries open/close timestamps and is updated by
//! `close_session`. Session lifecycle is a mutable record for
//! convenience of querying, not an audit claim — the per-grant rows in
//! `grant_log` are what get reconciled against observed side-effects,
//! and those never move.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, Row, params};
use thiserror::Error;

use crate::core::{
    CapabilityRequest, CredentialGrant, GrantedScope, Jti, PolicyDecision, RequestId, SessionId,
    SessionRecord, UnixMillis,
};

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

    #[error("invariant violated: {0}")]
    Invariant(&'static str),
}

/// One audited request-and-decision, plus the grant record if the decision
/// was `Grant`. Passing these together keeps request+grant writes atomic
/// under a single transaction.
#[derive(Debug)]
pub struct AuditedRequest<'a> {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub request: &'a CapabilityRequest,
    pub decision: &'a PolicyDecision,
    pub grant: Option<&'a CredentialGrant>,
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
    /// Open (or create) an on-disk audit log. The schema is initialised
    /// idempotently.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let conn = Connection::open(path)?;
        Self::init(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// In-memory audit log, for tests.
    pub fn open_in_memory() -> Result<Self, AuditError> {
        let conn = Connection::open_in_memory()?;
        Self::init(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn init(conn: &Connection) -> Result<(), AuditError> {
        // SQLite foreign_keys is per-connection and defaults to OFF, so the
        // REFERENCES clauses in SCHEMA_SQL would otherwise be parsed-and-ignored
        // and orphan `request`/`grant_log` rows could slip in.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(SCHEMA_SQL)?;
        Ok(())
    }

    fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> Result<R, AuditError>) -> Result<R, AuditError> {
        let guard = self.conn.lock().map_err(|_| AuditError::Poisoned)?;
        f(&guard)
    }

    fn with_conn_mut<R>(&self, f: impl FnOnce(&mut Connection) -> Result<R, AuditError>) -> Result<R, AuditError> {
        let mut guard = self.conn.lock().map_err(|_| AuditError::Poisoned)?;
        f(&mut guard)
    }

    pub fn open_session(&self, s: &SessionRecord) -> Result<(), AuditError> {
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO session (session_id, label, agent_model, opened_at, closed_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    s.session_id.as_uuid().to_string(),
                    s.label,
                    s.agent_model,
                    s.opened_at.as_millis(),
                    s.closed_at.map(UnixMillis::as_millis),
                ],
            )?;
            Ok(())
        })
    }

    pub fn close_session(&self, id: SessionId, at: UnixMillis) -> Result<(), AuditError> {
        self.with_conn(|c| {
            c.execute(
                "UPDATE session SET closed_at = ?2 WHERE session_id = ?1 AND closed_at IS NULL",
                params![id.as_uuid().to_string(), at.as_millis()],
            )?;
            Ok(())
        })
    }

    pub fn get_session(&self, id: SessionId) -> Result<Option<SessionRecord>, AuditError> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT session_id, label, agent_model, opened_at, closed_at \
                     FROM session WHERE session_id = ?1",
                    params![id.as_uuid().to_string()],
                    session_from_row,
                )
                .optional()?;
            Ok(row)
        })
    }

    /// Record one request + decision, and (if the decision was Grant)
    /// the matching credential grant, atomically in one transaction.
    pub fn record(&self, r: &AuditedRequest<'_>) -> Result<(), AuditError> {
        match (r.decision, r.grant) {
            (PolicyDecision::Grant { scope, ttl }, Some(g)) => {
                if g.request_id != r.request_id {
                    return Err(AuditError::Invariant("grant.request_id != request.request_id"));
                }
                if g.session_id != r.session_id {
                    return Err(AuditError::Invariant("grant.session_id != request.session_id"));
                }
                // The decision and the grant are both authority claims
                // about the same request, so they must agree on what that
                // authority is. A mismatch means replay would read two
                // contradictory answers from the same row.
                if g.scope != *scope {
                    return Err(AuditError::Invariant("grant.scope != decision.scope"));
                }
                let lifetime_millis = g
                    .expires_at
                    .as_millis()
                    .saturating_sub(g.issued_at.as_millis());
                let max_millis = ttl
                    .as_i64()
                    .saturating_mul(1000)
                    .saturating_add(AUDIT_TTL_SKEW_TOLERANCE_MILLIS);
                if lifetime_millis > max_millis {
                    return Err(AuditError::Invariant("grant lifetime exceeds decision ttl"));
                }
            }
            (PolicyDecision::Grant { .. }, None) => {
                return Err(AuditError::Invariant(
                    "decision was Grant but no grant record was supplied",
                ));
            }
            (PolicyDecision::Deny { .. }, Some(_)) => {
                return Err(AuditError::Invariant(
                    "decision was Deny but a grant record was supplied",
                ));
            }
            (PolicyDecision::Deny { .. }, None) => {}
        }

        let request_json = serde_json::to_string(r.request)?;
        let decision_json = serde_json::to_string(r.decision)?;
        let grant_fields = match r.grant {
            Some(g) => Some((g.jti, serde_json::to_string(&g.scope)?, g.issued_at, g.expires_at)),
            None => None,
        };

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            tx.execute(
                "INSERT INTO request (request_id, session_id, received_at, request_json, decision_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    r.request_id.as_uuid().to_string(),
                    r.session_id.as_uuid().to_string(),
                    r.received_at.as_millis(),
                    request_json,
                    decision_json,
                ],
            )?;
            if let Some((jti, scope_json, issued_at, expires_at)) = grant_fields {
                tx.execute(
                    "INSERT INTO grant_log (jti, request_id, session_id, scope_json, issued_at, expires_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        jti.as_uuid().to_string(),
                        r.request_id.as_uuid().to_string(),
                        r.session_id.as_uuid().to_string(),
                        scope_json,
                        issued_at.as_millis(),
                        expires_at.as_millis(),
                    ],
                )?;
            }
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
                "SELECT jti, request_id, session_id, scope_json, issued_at, expires_at \
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
                    "SELECT jti, request_id, session_id, scope_json, issued_at, expires_at \
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
}

fn session_from_row(row: &Row<'_>) -> rusqlite::Result<SessionRecord> {
    let session_id_str: String = row.get(0)?;
    let label: Option<String> = row.get(1)?;
    let agent_model: Option<String> = row.get(2)?;
    let opened_at: i64 = row.get(3)?;
    let closed_at: Option<i64> = row.get(4)?;
    let uuid = uuid::Uuid::parse_str(&session_id_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;
    Ok(SessionRecord {
        session_id: SessionId::from_uuid(uuid),
        label,
        agent_model,
        opened_at: UnixMillis::from_millis(opened_at),
        closed_at: closed_at.map(UnixMillis::from_millis),
    })
}

fn grant_from_row(row: &Row<'_>) -> rusqlite::Result<Result<CredentialGrant, AuditError>> {
    let jti_str: String = row.get(0)?;
    let request_id_str: String = row.get(1)?;
    let session_id_str: String = row.get(2)?;
    let scope_json: String = row.get(3)?;
    let issued_at: i64 = row.get(4)?;
    let expires_at: i64 = row.get(5)?;

    let parse = || -> Result<CredentialGrant, AuditError> {
        let jti = uuid::Uuid::parse_str(&jti_str)
            .map_err(|_| AuditError::Invariant("grant row: jti not a uuid"))?;
        let request_id = uuid::Uuid::parse_str(&request_id_str)
            .map_err(|_| AuditError::Invariant("grant row: request_id not a uuid"))?;
        let session_id = uuid::Uuid::parse_str(&session_id_str)
            .map_err(|_| AuditError::Invariant("grant row: session_id not a uuid"))?;
        let scope: GrantedScope = serde_json::from_str(&scope_json)?;
        Ok(CredentialGrant {
            jti: Jti::from_uuid(jti),
            request_id: RequestId::from_uuid(request_id),
            session_id: SessionId::from_uuid(session_id),
            scope,
            issued_at: UnixMillis::from_millis(issued_at),
            expires_at: UnixMillis::from_millis(expires_at),
        })
    };
    Ok(parse())
}

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS session (
    session_id  TEXT PRIMARY KEY,
    label       TEXT,
    agent_model TEXT,
    opened_at   INTEGER NOT NULL,
    closed_at   INTEGER
);

CREATE TABLE IF NOT EXISTS request (
    request_id    TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES session(session_id),
    received_at   INTEGER NOT NULL,
    request_json  TEXT NOT NULL,
    decision_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_request_session ON request(session_id, received_at);

CREATE TABLE IF NOT EXISTS grant_log (
    jti         TEXT PRIMARY KEY,
    request_id  TEXT NOT NULL REFERENCES request(request_id),
    session_id  TEXT NOT NULL REFERENCES session(session_id),
    scope_json  TEXT NOT NULL,
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_grant_session ON grant_log(session_id, issued_at);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        GitHubAccess, GitHubGrantedScope, GitHubPermissions, GitHubRequest, RepoRef, TtlSeconds,
    };

    fn sample_session() -> SessionRecord {
        SessionRecord {
            session_id: SessionId::new(),
            label: Some("test".into()),
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
                metadata: Some(GitHubAccess::Read),
                ..Default::default()
            },
        })
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
    fn record_grant_writes_both_tables() {
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
            scope: scope.clone(),
            issued_at: UnixMillis::from_millis(1_700_000_100),
            expires_at: UnixMillis::from_millis(1_700_000_400),
        };

        log.record(&AuditedRequest {
            request_id,
            session_id: s.session_id,
            received_at: UnixMillis::from_millis(1_700_000_100),
            request: &req,
            decision: &decision,
            grant: Some(&grant),
        })
        .unwrap();

        let grants = log.list_grants_for_session(s.session_id).unwrap();
        assert_eq!(grants, vec![grant.clone()]);
        let got = log.get_grant(grant.jti).unwrap().unwrap();
        assert_eq!(got, grant);
    }

    #[test]
    fn record_deny_does_not_write_grant() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "policy says no".into(),
        };

        log.record(&AuditedRequest {
            request_id,
            session_id: s.session_id,
            received_at: UnixMillis::from_millis(1_700_000_100),
            request: &req,
            decision: &decision,
            grant: None,
        })
        .unwrap();

        assert!(log.list_grants_for_session(s.session_id).unwrap().is_empty());
    }

    #[test]
    fn grant_without_matching_decision_is_rejected() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "no".into(),
        };
        let bogus_grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(1),
            expires_at: UnixMillis::from_millis(2),
        };
        let err = log
            .record(&AuditedRequest {
                request_id,
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(1_700_000_100),
                request: &req,
                decision: &decision,
                grant: Some(&bogus_grant),
            })
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)));
    }

    #[test]
    fn grant_missing_for_grant_decision_is_rejected() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        let err = log
            .record(&AuditedRequest {
                request_id,
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(1_700_000_100),
                request: &req,
                decision: &decision,
                grant: None,
            })
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)));
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
                scope: sample_scope(),
                issued_at: UnixMillis::from_millis(at),
                expires_at: UnixMillis::from_millis(at + 300),
            };
            let request = sample_request();
            log.record(&AuditedRequest {
                request_id,
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(at),
                request: &request,
                decision: &decision,
                grant: Some(&grant),
            })
            .unwrap();
            grant
        };

        let a = mk_grant(1000);
        let b = mk_grant(2000);
        let c = mk_grant(1500);

        let listed = log.list_grants_for_session(s.session_id).unwrap();
        assert_eq!(listed.iter().map(|g| g.issued_at.as_millis()).collect::<Vec<_>>(),
                   vec![1000, 1500, 2000]);
        assert_eq!(listed.iter().map(|g| g.jti).collect::<Vec<_>>(),
                   vec![a.jti, c.jti, b.jti]);
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
                scope: sample_scope(),
                issued_at: UnixMillis::from_millis(5_000),
                expires_at: UnixMillis::from_millis(5_300),
            };
            let request = sample_request();
            log.record(&AuditedRequest {
                request_id,
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(5_000),
                request: &request,
                decision: &decision,
                grant: Some(&grant),
            })
            .unwrap();
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
    /// authority for the same request. Reject at the application layer.
    #[test]
    fn record_rejects_grant_with_divergent_scope() {
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
        let other_scope = GrantedScope::GitHub(GitHubGrantedScope {
            repository: RepoRef {
                owner: "different".into(),
                name: "repo".into(),
            },
            permissions: GitHubPermissions {
                contents: Some(GitHubAccess::Read),
                metadata: Some(GitHubAccess::Read),
                ..Default::default()
            },
        });
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            scope: other_scope,
            issued_at: UnixMillis::from_millis(1_000),
            expires_at: UnixMillis::from_millis(2_000),
        };

        let err = log
            .record(&AuditedRequest {
                request_id,
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(1_000),
                request: &req,
                decision: &decision,
                grant: Some(&grant),
            })
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// Same idea as scope divergence: if the grant's effective lifetime
    /// grossly overshoots the decision's TTL ceiling, the two rows would
    /// disagree on how long the authority lasts. The audit layer allows
    /// a small skew (so minter clock tolerance doesn't spuriously trip
    /// it) but rejects anything beyond that.
    #[test]
    fn record_rejects_grant_with_lifetime_exceeding_ttl() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(60).unwrap(),
        };
        // Decision says 60s (60_000 ms). Grant lifetime is 1h (3_600_000 ms),
        // well past the 60_000 ms skew tolerance.
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(0),
            expires_at: UnixMillis::from_millis(3_600_000),
        };

        let err = log
            .record(&AuditedRequest {
                request_id,
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(0),
                request: &req,
                decision: &decision,
                grant: Some(&grant),
            })
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// The other side of the boundary: a grant whose lifetime lands
    /// exactly at the TTL+skew ceiling must still be accepted, otherwise
    /// a minter operating inside its documented skew tolerance couldn't
    /// record its own grants.
    #[test]
    fn record_accepts_grant_within_ttl_plus_skew() {
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
        // Lifetime = ttl + full skew tolerance, exactly on the boundary.
        let lifetime_millis = ttl_seconds * 1000 + AUDIT_TTL_SKEW_TOLERANCE_MILLIS;
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(0),
            expires_at: UnixMillis::from_millis(lifetime_millis),
        };

        log.record(&AuditedRequest {
            request_id,
            session_id: s.session_id,
            received_at: UnixMillis::from_millis(0),
            request: &req,
            decision: &decision,
            grant: Some(&grant),
        })
        .unwrap();
    }
}
