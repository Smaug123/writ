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
    CapabilityRequest, CredentialGrant, GitHubGrantedScope, GitHubRequest, GrantedScope, Jti,
    MetadataAccess, PolicyDecision, RequestId, SessionId, SessionRecord, UnixMillis,
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

    /// The on-disk schema was written by a newer broker than this binary
    /// knows how to read. Refusing to open is the correctness-over-
    /// availability call: a down-rev binary silently ignoring columns it
    /// doesn't understand is how audit logs lose data.
    #[error(
        "audit DB schema version {found} is newer than this binary supports (max {supported}); \
         upgrade the broker"
    )]
    SchemaTooNew { found: i32, supported: i32 },

    #[error(
        "audit DB has user_version 0 but contains only part of the legacy v1 schema; \
         refuse to guess migration state"
    )]
    PartialLegacySchema,
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
    /// [`SCHEMA_VERSION`] by running any missing migrations in order.
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
        // REFERENCES clauses in the v1 schema would otherwise be
        // parsed-and-ignored and orphan `request`/`grant_log` rows could
        // slip in. Must be set outside a transaction.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        migrate(conn)
    }

    fn with_conn<R>(
        &self,
        f: impl FnOnce(&Connection) -> Result<R, AuditError>,
    ) -> Result<R, AuditError> {
        let guard = self.conn.lock().map_err(|_| AuditError::Poisoned)?;
        f(&guard)
    }

    fn with_conn_mut<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<R, AuditError>,
    ) -> Result<R, AuditError> {
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
                "INSERT INTO grant_log (jti, request_id, session_id, scope_json, issued_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    grant.jti.as_uuid().to_string(),
                    grant.request_id.as_uuid().to_string(),
                    grant.session_id.as_uuid().to_string(),
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

fn session_from_row(row: &Row<'_>) -> rusqlite::Result<SessionRecord> {
    let session_id_str: String = row.get(0)?;
    let label: Option<String> = row.get(1)?;
    let agent_model: Option<String> = row.get(2)?;
    let opened_at: i64 = row.get(3)?;
    let closed_at: Option<i64> = row.get(4)?;
    let uuid = uuid::Uuid::parse_str(&session_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
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

/// One versioned schema change. Migrations are applied in order; each
/// one advances `PRAGMA user_version` to its own `version` when it
/// commits, so a partial run (process killed mid-migration) resumes
/// cleanly at the next open.
///
/// Rules for adding a new migration:
///   1. Append a new entry with `version = SCHEMA_VERSION + 1`.
///   2. Bump [`SCHEMA_VERSION`].
///   3. Never edit a migration that has shipped — write another one.
///   4. Never renumber. Versions are append-only, like the audit log they
///      manage.
struct Migration {
    /// The schema version the DB is at *after* this migration commits.
    version: i32,
    sql: &'static str,
}

/// Highest schema version this binary knows how to read. An on-disk DB at
/// a version higher than this is rejected with [`AuditError::SchemaTooNew`]
/// rather than opened — we'd rather fail to start than silently drop data
/// into a schema a newer broker wrote.
const SCHEMA_VERSION: i32 = 4;

/// The full migration history. Each entry documents exactly one state
/// transition; the sequence of entries is the schema's lineage. Order
/// matters and must be strictly ascending in `version`.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: r#"
CREATE TABLE session (
    session_id  TEXT PRIMARY KEY,
    label       TEXT,
    agent_model TEXT,
    opened_at   INTEGER NOT NULL,
    closed_at   INTEGER
);

CREATE TABLE request (
    request_id    TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES session(session_id),
    received_at   INTEGER NOT NULL,
    request_json  TEXT NOT NULL,
    decision_json TEXT NOT NULL
);

CREATE INDEX idx_request_session ON request(session_id, received_at);

CREATE TABLE grant_log (
    jti         TEXT PRIMARY KEY,
    request_id  TEXT NOT NULL REFERENCES request(request_id),
    session_id  TEXT NOT NULL REFERENCES session(session_id),
    scope_json  TEXT NOT NULL,
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE INDEX idx_grant_session ON grant_log(session_id, issued_at);
"#,
    },
    Migration {
        version: 2,
        sql: "ALTER TABLE request ADD COLUMN mint_failure_json TEXT;",
    },
    // Belt-and-braces for the session-open check in `record`: the FK
    // from `request(session_id)` to `session(session_id)` ensures the
    // referenced session exists, but cannot express "is open". A
    // BEFORE-INSERT trigger raises SQLITE_CONSTRAINT_TRIGGER if the
    // session has already been closed, so any writer that reaches the
    // `request` table (including callers that bypass `AuditLog::record`)
    // is stopped at the DB boundary instead of silently corrupting the
    // activity-window bound that `closed_at` is supposed to provide.
    Migration {
        version: 3,
        sql: r#"
CREATE TRIGGER request_requires_open_session
BEFORE INSERT ON request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
"#,
    },
    // The post-mint outcome (success → grant_log; failure → mint_failure)
    // lives in its own append-only row rather than mutating the `request`
    // row. This preserves "request is strictly append-only" while letting
    // the broker pre-record the request before awaiting GitHub: the
    // outcome is appended only once the mint completes. Triggers enforce
    // that a given request_id has at most one of the two outcome rows —
    // a request either succeeded or failed, never both.
    Migration {
        version: 4,
        sql: r#"
CREATE TABLE mint_failure (
    request_id   TEXT PRIMARY KEY REFERENCES request(request_id),
    failed_at    INTEGER NOT NULL,
    failure_json TEXT NOT NULL
);

CREATE TRIGGER mint_failure_excludes_grant
BEFORE INSERT ON mint_failure
WHEN EXISTS (SELECT 1 FROM grant_log WHERE request_id = NEW.request_id)
BEGIN
    SELECT RAISE(ABORT, 'grant already recorded for this request');
END;

CREATE TRIGGER grant_excludes_mint_failure
BEFORE INSERT ON grant_log
WHEN EXISTS (SELECT 1 FROM mint_failure WHERE request_id = NEW.request_id)
BEGIN
    SELECT RAISE(ABORT, 'mint failure already recorded for this request');
END;
"#,
    },
];

// Belt-and-braces: the compile-time shape of MIGRATIONS is the source
// of truth, so verify it matches SCHEMA_VERSION at compile time rather
// than trust two constants to stay in sync by convention. A release
// build with the constants out of sync (new SCHEMA_VERSION without a
// matching migration, or a non-ascending version list) would otherwise
// silently produce a broker that either runs migrations in the wrong
// order (rolling `user_version` backwards) or never runs the new one at
// all. These `const` blocks are evaluated by the compiler; no runtime
// cost, no way to ship past them.
const _: () = {
    assert!(
        !MIGRATIONS.is_empty(),
        "MIGRATIONS must contain at least one entry"
    );
    assert!(
        MIGRATIONS[MIGRATIONS.len() - 1].version == SCHEMA_VERSION,
        "SCHEMA_VERSION must equal the last migration's version"
    );
    let mut i = 1;
    while i < MIGRATIONS.len() {
        assert!(
            MIGRATIONS[i - 1].version < MIGRATIONS[i].version,
            "migrations must be strictly ascending in version"
        );
        i += 1;
    }
};

fn migrate(conn: &mut Connection) -> Result<(), AuditError> {
    let mut current = user_version(conn)?;

    if current == 0 {
        match legacy_schema_state(conn)? {
            LegacySchemaState::Empty => {}
            // A v1-shaped DB written before we started tracking
            // `user_version` would read as version 0 but already have the
            // v1 tables. Fast-forward the pragma in-place so subsequent
            // migrations apply cleanly.
            LegacySchemaState::CompleteV1 => {
                conn.pragma_update(None, "user_version", 1)?;
                current = 1;
            }
            LegacySchemaState::PartialOrInconsistent => {
                return Err(AuditError::PartialLegacySchema);
            }
        }
    }

    if current > SCHEMA_VERSION {
        return Err(AuditError::SchemaTooNew {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }

    for m in MIGRATIONS.iter().filter(|m| m.version > current) {
        let tx = conn.transaction()?;
        tx.execute_batch(m.sql)?;
        tx.pragma_update(None, "user_version", m.version)?;
        tx.commit()?;
    }
    Ok(())
}

fn user_version(conn: &Connection) -> Result<i32, AuditError> {
    Ok(conn.query_row("PRAGMA user_version", [], |row| row.get(0))?)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum LegacySchemaState {
    Empty,
    CompleteV1,
    PartialOrInconsistent,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum TableShape {
    Missing,
    HasRequiredColumns,
    MissingRequiredColumns,
}

fn legacy_schema_state(conn: &Connection) -> Result<LegacySchemaState, AuditError> {
    let session = table_shape(
        conn,
        "session",
        &[
            "session_id",
            "label",
            "agent_model",
            "opened_at",
            "closed_at",
        ],
    )?;
    let request = table_shape(
        conn,
        "request",
        &[
            "request_id",
            "session_id",
            "received_at",
            "request_json",
            "decision_json",
        ],
    )?;
    let grant_log = table_shape(
        conn,
        "grant_log",
        &[
            "jti",
            "request_id",
            "session_id",
            "scope_json",
            "issued_at",
            "expires_at",
        ],
    )?;

    match (session, request, grant_log) {
        (TableShape::Missing, TableShape::Missing, TableShape::Missing) => {
            Ok(LegacySchemaState::Empty)
        }
        (
            TableShape::HasRequiredColumns,
            TableShape::HasRequiredColumns,
            TableShape::HasRequiredColumns,
        ) => Ok(LegacySchemaState::CompleteV1),
        _ => Ok(LegacySchemaState::PartialOrInconsistent),
    }
}

fn table_shape(
    conn: &Connection,
    name: &str,
    required_columns: &[&str],
) -> Result<TableShape, AuditError> {
    let columns = table_columns(conn, name)?;
    if columns.is_empty() {
        return Ok(TableShape::Missing);
    }
    if required_columns
        .iter()
        .all(|required| columns.iter().any(|column| column == required))
    {
        Ok(TableShape::HasRequiredColumns)
    } else {
        Ok(TableShape::MissingRequiredColumns)
    }
}

fn table_columns(conn: &Connection, name: &str) -> Result<Vec<String>, AuditError> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({name})"))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(columns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        GitHubAccess, GitHubGrantedScope, GitHubPermissions, GitHubRequest, MetadataAccess,
        RepoRef, TtlSeconds,
    };
    use tempfile::NamedTempFile;

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
                metadata: Some(MetadataAccess::Read),
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
        assert!(trigger_exists(&log, "request_requires_open_session"));
        assert!(trigger_exists(&log, "mint_failure_excludes_grant"));
        assert!(trigger_exists(&log, "grant_excludes_mint_failure"));
    }

    #[test]
    fn open_initialises_empty_file_db_at_current_schema_version() {
        let db = NamedTempFile::new().unwrap();
        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "session", "session_id"));
        assert!(column_exists(&log, "request", "decision_json"));
        assert!(column_exists(&log, "grant_log", "jti"));
        assert!(column_exists(&log, "mint_failure", "failure_json"));
        assert!(trigger_exists(&log, "request_requires_open_session"));
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

    /// A DB written before we started tracking `user_version` reads as
    /// version 0 but already has the v1 tables. The fast-forward path
    /// detects this and brings it up to current without trying to
    /// re-create existing tables.
    #[test]
    fn open_migrates_legacy_request_table_to_include_mint_failure_column() {
        let db = NamedTempFile::new().unwrap();
        let conn = Connection::open(db.path()).unwrap();
        conn.execute_batch(
            r#"
CREATE TABLE session (
    session_id  TEXT PRIMARY KEY,
    label       TEXT,
    agent_model TEXT,
    opened_at   INTEGER NOT NULL,
    closed_at   INTEGER
);

CREATE TABLE request (
    request_id    TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES session(session_id),
    received_at   INTEGER NOT NULL,
    request_json  TEXT NOT NULL,
    decision_json TEXT NOT NULL
);

CREATE INDEX idx_request_session ON request(session_id, received_at);

CREATE TABLE grant_log (
    jti         TEXT PRIMARY KEY,
    request_id  TEXT NOT NULL REFERENCES request(request_id),
    session_id  TEXT NOT NULL REFERENCES session(session_id),
    scope_json  TEXT NOT NULL,
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE INDEX idx_grant_session ON grant_log(session_id, issued_at);
"#,
        )
        .unwrap();
        drop(conn);

        let log = AuditLog::open(db.path()).unwrap();
        assert!(column_exists(&log, "request", "mint_failure_json"));
        assert!(column_exists(&log, "mint_failure", "failure_json"));
        assert!(trigger_exists(&log, "request_requires_open_session"));
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
    }

    #[test]
    fn open_rejects_partial_legacy_schema_without_fast_forwarding_version() {
        let db = NamedTempFile::new().unwrap();
        {
            let conn = Connection::open(db.path()).unwrap();
            conn.execute_batch(
                r#"
CREATE TABLE session (
    session_id  TEXT PRIMARY KEY,
    label       TEXT,
    agent_model TEXT,
    opened_at   INTEGER NOT NULL,
    closed_at   INTEGER
);
"#,
            )
            .unwrap();
        }

        let err = AuditLog::open(db.path()).unwrap_err();
        assert!(
            matches!(err, AuditError::PartialLegacySchema),
            "expected PartialLegacySchema, got: {err:?}"
        );

        let conn = Connection::open(db.path()).unwrap();
        assert_eq!(
            user_version(&conn).unwrap(),
            0,
            "partial legacy schema must not be fast-forwarded"
        );
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

    /// If a migration fails partway (process killed, disk full), the
    /// next open must resume from the last successfully-committed version
    /// rather than replay already-applied DDL. Each migration commits
    /// its version bump in the same transaction as its DDL, so version
    /// and schema can't disagree across restarts.
    #[test]
    fn partial_migration_resumes_from_last_committed_version() {
        let db = NamedTempFile::new().unwrap();
        {
            // Apply migration 1 only, by running it directly and stopping.
            let mut c = Connection::open(db.path()).unwrap();
            c.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
            let tx = c.transaction().unwrap();
            tx.execute_batch(MIGRATIONS[0].sql).unwrap();
            tx.pragma_update(None, "user_version", MIGRATIONS[0].version)
                .unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();
        // Every migration past the stopping point should have been
        // applied on open.
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "request", "mint_failure_json"));
        assert!(column_exists(&log, "mint_failure", "failure_json"));
        assert!(trigger_exists(&log, "request_requires_open_session"));
    }
}
