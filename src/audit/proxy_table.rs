//! Shared DAO for the structurally-identical broker-proxy audit tables.
//!
//! The Claude proxy, OpenAI proxy, and Nix cache audit tables are
//! `(*_request, *_outcome)` pairs with the same column shape: a request
//! row carrying `(method, target, route, decision, deny_reason)` and an
//! outcome row carrying `(http_status, upstream_url, upstream_status,
//! response_bytes, error)`. The only per-backend variation is the table
//! names, the route enum, and the diagnostic label that prefixes
//! validation errors. This module captures that shape once: a
//! [`ProxyAuditTable`] descriptor selects the table names, route
//! enum, and label, and the generic [`AuditLog::record_proxy_request`]
//! / [`AuditLog::record_proxy_outcome`] writers contain the shared SQL
//! and validation. Per-backend modules become thin shims that nominate
//! a descriptor and re-export the generic record types under the
//! per-backend names.

use rusqlite::{Connection, OptionalExtension, params};

use super::validation::labeled_invariant;
use super::{AuditError, AuditLog};
use crate::core::{RequestId, SessionId, UnixMillis};

/// Per-backend route enum projected into the audit row's `route`
/// column.
pub trait ProxyAuditRoute: Copy + 'static {
    /// Wire form stored in SQLite. Must match the per-backend
    /// `route IN (...)` CHECK constraint declared in the schema
    /// migrations.
    fn as_str(self) -> &'static str;

    /// Inverse of [`Self::as_str`]. `None` for any value not produced
    /// by [`Self::as_str`]; callers reading from prod tables should
    /// translate `None` into an `AuditError::Invariant`, callers in
    /// test helpers may panic.
    fn from_str(raw: &str) -> Option<Self>;
}

/// Selector for one of the structurally-identical proxy audit table
/// pairs. Implemented by zero-sized markers in the per-backend modules
/// (e.g., `ClaudeProxyAuditTable`).
pub trait ProxyAuditTable: 'static {
    type Route: ProxyAuditRoute;
    /// `*_request` table name. Must be a compile-time constant: the
    /// generic DAO interpolates it into SQL via `format!`, so a value
    /// derived from runtime input would be a SQL-injection vector.
    const REQUEST_TABLE: &'static str;
    /// `*_outcome` table name. Same constraint as [`Self::REQUEST_TABLE`].
    const OUTCOME_TABLE: &'static str;
    /// Diagnostic label prefixed onto every validation error message
    /// (e.g., `"Claude proxy"`, `"OpenAI proxy"`, `"Nix cache"`). Used
    /// only for `AuditError::LabeledInvariant` formatting; never goes
    /// into SQL.
    const LABEL: &'static str;
}

/// Allow/deny attached to a proxy request audit row. Owned form; the
/// borrow-friendly mirror used by the VM HTTP orchestration layer
/// lives in `vm_http::proxy_common::ProxyAuditDecisionRef`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyAuditDecision {
    Allow,
    Deny { reason: String },
}

#[derive(Debug)]
pub struct ProxyRequestRecord<'a, R> {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub method: &'a str,
    pub target: &'a str,
    pub route: R,
    pub decision: &'a ProxyAuditDecision,
}

#[derive(Debug)]
pub struct ProxyOutcomeRecord<'a> {
    pub request_id: RequestId,
    pub completed_at: UnixMillis,
    pub http_status: u16,
    pub upstream_url: Option<&'a str>,
    pub upstream_status: Option<u16>,
    pub response_bytes: u64,
    pub error: Option<&'a str>,
}

/// Field validation for a proxy request row, run before any transaction opens.
fn validate_proxy_request<T: ProxyAuditTable>(
    r: &ProxyRequestRecord<'_, T::Route>,
) -> Result<(), AuditError> {
    if r.method.is_empty() {
        return Err(labeled_invariant(T::LABEL, "method must not be empty"));
    }
    if r.target.is_empty() {
        return Err(labeled_invariant(T::LABEL, "target must not be empty"));
    }
    if let ProxyAuditDecision::Deny { reason } = r.decision
        && reason.is_empty()
    {
        return Err(labeled_invariant(
            T::LABEL,
            "denial reason must not be empty",
        ));
    }
    Ok(())
}

/// Field validation for a proxy outcome row, run before any transaction opens.
fn validate_proxy_outcome<T: ProxyAuditTable>(
    r: &ProxyOutcomeRecord<'_>,
) -> Result<(), AuditError> {
    if !(100..=599).contains(&r.http_status) {
        return Err(labeled_invariant(T::LABEL, "HTTP status must be 100..599"));
    }
    if let Some(status) = r.upstream_status
        && !(100..=599).contains(&status)
    {
        return Err(labeled_invariant(
            T::LABEL,
            "upstream status must be 100..599",
        ));
    }
    if let Some(error) = r.error
        && error.is_empty()
    {
        return Err(labeled_invariant(
            T::LABEL,
            "error must not be empty when present",
        ));
    }
    if r.response_bytes > i64::MAX as u64 {
        return Err(labeled_invariant(
            T::LABEL,
            "response bytes exceeds SQLite integer range",
        ));
    }
    Ok(())
}

/// Fail if `session_id` is absent or already closed. Runs inside the caller's
/// transaction so the check and the row insert(s) commit atomically.
fn check_session_open(conn: &Connection, session_id: SessionId) -> Result<(), AuditError> {
    let session_closed_at: Option<Option<i64>> = conn
        .query_row(
            "SELECT closed_at FROM session WHERE session_id = ?1",
            params![session_id.as_uuid().to_string()],
            |row| row.get(0),
        )
        .optional()?;
    match session_closed_at {
        None => Err(AuditError::Invariant("session does not exist")),
        Some(Some(_)) => Err(AuditError::Invariant("session is closed")),
        Some(None) => Ok(()),
    }
}

/// Insert one request row into this connection/transaction. Assumes
/// [`validate_proxy_request`] passed and [`check_session_open`] ran.
fn insert_proxy_request_row<T: ProxyAuditTable>(
    conn: &Connection,
    r: &ProxyRequestRecord<'_, T::Route>,
) -> Result<(), AuditError> {
    // Table name comes from a compile-time `&'static str` constant declared in
    // this crate, never user input.
    let sql = format!(
        "INSERT INTO {table} (
             request_id,
             session_id,
             received_at,
             method,
             target,
             route,
             decision,
             deny_reason
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        table = T::REQUEST_TABLE,
    );
    let (decision, deny_reason) = match r.decision {
        ProxyAuditDecision::Allow => ("allow", None),
        ProxyAuditDecision::Deny { reason } => ("deny", Some(reason.as_str())),
    };
    conn.execute(
        &sql,
        params![
            r.request_id.as_uuid().to_string(),
            r.session_id.as_uuid().to_string(),
            r.received_at.as_millis(),
            r.method,
            r.target,
            r.route.as_str(),
            decision,
            deny_reason,
        ],
    )?;
    Ok(())
}

/// Insert one outcome row into this connection/transaction. Assumes
/// [`validate_proxy_outcome`] passed.
fn insert_proxy_outcome_row<T: ProxyAuditTable>(
    conn: &Connection,
    r: &ProxyOutcomeRecord<'_>,
) -> Result<(), AuditError> {
    // See the table-name interpolation note on `insert_proxy_request_row`.
    let sql = format!(
        "INSERT INTO {table} (
             request_id,
             completed_at,
             http_status,
             upstream_url,
             upstream_status,
             response_bytes,
             error
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        table = T::OUTCOME_TABLE,
    );
    conn.execute(
        &sql,
        params![
            r.request_id.as_uuid().to_string(),
            r.completed_at.as_millis(),
            i64::from(r.http_status),
            r.upstream_url,
            r.upstream_status.map(i64::from),
            r.response_bytes as i64,
            r.error,
        ],
    )?;
    Ok(())
}

impl AuditLog {
    /// Persist a proxy-request audit row before the upstream call is
    /// attempted. The matching outcome row is appended via
    /// [`AuditLog::record_proxy_outcome`].
    ///
    /// This two-phase form is what makes the request durable *before* the
    /// action — required for any write that records granted authority. The
    /// authority-free proxy/cache read paths can instead coalesce both rows in
    /// one commit via [`AuditLog::record_proxy_request_and_outcome`].
    pub(super) fn record_proxy_request<T: ProxyAuditTable>(
        &self,
        r: &ProxyRequestRecord<'_, T::Route>,
    ) -> Result<(), AuditError> {
        validate_proxy_request::<T>(r)?;
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            check_session_open(&tx, r.session_id)?;
            insert_proxy_request_row::<T>(&tx, r)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Append an outcome row to a previously-recorded proxy-request
    /// audit row.
    pub(super) fn record_proxy_outcome<T: ProxyAuditTable>(
        &self,
        r: &ProxyOutcomeRecord<'_>,
    ) -> Result<(), AuditError> {
        validate_proxy_outcome::<T>(r)?;
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            insert_proxy_outcome_row::<T>(&tx, r)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Persist a proxy request row and its outcome row in a *single*
    /// transaction — one commit, one `fsync` — for the authority-free
    /// proxy/cache read paths (the VM Nix cache serve path) where the request
    /// row need not be durable *before* the action.
    ///
    /// This is the throughput lever for those high-volume rows. The two-phase
    /// [`record_proxy_request`] + [`record_proxy_outcome`] pays two fsync'd
    /// commits per request; on the broker-VM audit DB (a virtiofs mount, where
    /// every `fsync` round-trips to the host) that serialized double-commit
    /// dominated agent-VM provisioning. Coalescing halves it, and — because
    /// both rows share one transaction — a request row never lands without its
    /// outcome.
    ///
    /// It is deliberately *not* used for writes that record granted authority:
    /// grants/mints keep the two-phase split so the request is durable before
    /// the action. The durability this trades away — a request row that is not
    /// durable until its outcome is known — is harmless for a cache read that
    /// grants nothing: a crash mid-fetch leaves no row at all, rather than an
    /// orphan request row.
    ///
    /// One consequence is explicit and accepted: if the session **closes during
    /// the fetch**, this coalesced write is refused — the
    /// `*_request_requires_open_session` trigger forbids a request row for a
    /// now-closed session, and there is no earlier row to fall back on (unlike
    /// the two-phase path, whose pre-fetch request row survives a mid-fetch
    /// close). That cache read then goes unrecorded in the DB. It is bounded and
    /// benign: the paths that use this coalesced writer grant no authority, the
    /// caller refuses to serve the response (fail-closed), and — because the
    /// refusal is an `AuditError` — the caller still emits an
    /// [`AUDIT_WRITE_FAILURE_TARGET`](crate::audit::AUDIT_WRITE_FAILURE_TARGET)
    /// event, so the access is logged even when it is not a structured row.
    /// Reproducing the two-phase's mid-close durability would require the second
    /// fsync this method exists to remove, so it is a conscious trade for the
    /// authority-free paths only.
    pub(super) fn record_proxy_request_and_outcome<T: ProxyAuditTable>(
        &self,
        request: &ProxyRequestRecord<'_, T::Route>,
        outcome: &ProxyOutcomeRecord<'_>,
    ) -> Result<(), AuditError> {
        // Enforced at runtime, not just in debug: a stripped assert could
        // otherwise commit the outcome against the wrong request in a release
        // build, corrupting the request↔outcome association.
        if request.request_id != outcome.request_id {
            return Err(AuditError::Invariant(
                "coalesced audit rows must share a request_id",
            ));
        }
        validate_proxy_request::<T>(request)?;
        validate_proxy_outcome::<T>(outcome)?;
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            check_session_open(&tx, request.session_id)?;
            insert_proxy_request_row::<T>(&tx, request)?;
            insert_proxy_outcome_row::<T>(&tx, outcome)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Read-only check that a session exists and is open. Lets a caller that has
    /// deferred its audit row write (coalescing request+outcome into one commit
    /// after the action) still refuse work against a closed or unknown session
    /// *before* doing it, rather than only when the deferred write lands. Adds
    /// no commit — it is a single indexed `SELECT`.
    pub fn require_session_open(&self, session_id: SessionId) -> Result<(), AuditError> {
        self.with_conn(|c| check_session_open(c, session_id))
    }
}

#[cfg(test)]
impl AuditLog {
    /// Test-only helper: read back the `(http_status, response_bytes,
    /// error)` triple for a recorded outcome row. Generic over the
    /// table descriptor so each per-backend test module can call it
    /// against its own table.
    pub(crate) fn proxy_outcome_for_test<T: ProxyAuditTable>(
        &self,
        request_id: RequestId,
    ) -> Result<Option<(u16, u64, Option<String>)>, AuditError> {
        let sql = format!(
            "SELECT http_status, response_bytes, error
             FROM {table}
             WHERE request_id = ?1",
            table = T::OUTCOME_TABLE,
        );
        self.with_conn(|c| {
            c.query_row(&sql, params![request_id.as_uuid().to_string()], |row| {
                let http_status: i64 = row.get(0)?;
                let response_bytes: i64 = row.get(1)?;
                let error: Option<String> = row.get(2)?;
                Ok((http_status as u16, response_bytes as u64, error))
            })
            .optional()
            .map_err(AuditError::from)
        })
    }

    /// Test-only helper: list the `(route, decision, http_status)`
    /// projection for every proxy request-row attached to a session.
    /// Panics if the persisted route or decision strings are
    /// unrecognised; that's a schema-violation in test fixtures, not a
    /// production code path.
    #[allow(clippy::type_complexity)]
    pub(crate) fn list_proxy_requests_for_session_for_test<T: ProxyAuditTable>(
        &self,
        id: SessionId,
    ) -> Result<Vec<(T::Route, ProxyAuditDecision, Option<u16>)>, AuditError> {
        let sql = format!(
            "SELECT r.route, r.decision, r.deny_reason, o.http_status
             FROM {request_table} r
             LEFT JOIN {outcome_table} o ON o.request_id = r.request_id
             WHERE r.session_id = ?1
             ORDER BY r.received_at ASC, r.rowid ASC",
            request_table = T::REQUEST_TABLE,
            outcome_table = T::OUTCOME_TABLE,
        );
        self.with_conn(|c| {
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt
                .query_map(params![id.as_uuid().to_string()], |row| {
                    let route: String = row.get(0)?;
                    let decision: String = row.get(1)?;
                    let deny_reason: Option<String> = row.get(2)?;
                    let http_status: Option<i64> = row.get(3)?;
                    Ok((route, decision, deny_reason, http_status))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows
                .into_iter()
                .map(|(route, decision, deny_reason, http_status)| {
                    let route = T::Route::from_str(&route)
                        .unwrap_or_else(|| panic!("unknown {} audit route {route:?}", T::LABEL));
                    let decision = match (decision.as_str(), deny_reason) {
                        ("allow", _) => ProxyAuditDecision::Allow,
                        ("deny", Some(reason)) => ProxyAuditDecision::Deny { reason },
                        (other, deny_reason) => panic!(
                            "unexpected {} audit decision row: decision={other:?} deny_reason={deny_reason:?}",
                            T::LABEL
                        ),
                    };
                    (route, decision, http_status.map(|status| status as u16))
                })
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::sample_session;
    use proptest::prelude::*;

    /// Tiny scratch backend used to exercise the generic DAO without
    /// pulling in any production migration.
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    enum TestRoute {
        A,
        B,
    }

    impl ProxyAuditRoute for TestRoute {
        fn as_str(self) -> &'static str {
            match self {
                Self::A => "a",
                Self::B => "b",
            }
        }
        fn from_str(raw: &str) -> Option<Self> {
            match raw {
                "a" => Some(Self::A),
                "b" => Some(Self::B),
                _ => None,
            }
        }
    }

    struct TestTable;

    impl ProxyAuditTable for TestTable {
        type Route = TestRoute;
        const REQUEST_TABLE: &'static str = "test_proxy_request";
        const OUTCOME_TABLE: &'static str = "test_proxy_outcome";
        const LABEL: &'static str = "Test proxy";
    }

    /// Install scratch tables matching the same shape the real
    /// per-backend migrations create, so the generic DAO can exercise
    /// the same INSERT path.
    fn install_test_tables(log: &AuditLog) {
        log.with_conn_mut(|c| {
            c.execute_batch(
                r#"
CREATE TABLE test_proxy_request (
    request_id  TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES session(session_id),
    received_at INTEGER NOT NULL,
    method      TEXT NOT NULL CHECK (method != ''),
    target      TEXT NOT NULL CHECK (target != ''),
    route       TEXT NOT NULL CHECK (route IN ('a', 'b')),
    decision    TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    deny_reason TEXT,
    CHECK (
        (decision = 'allow' AND deny_reason IS NULL)
        OR (decision = 'deny' AND deny_reason IS NOT NULL AND deny_reason != '')
    )
);

CREATE TABLE test_proxy_outcome (
    request_id      TEXT PRIMARY KEY REFERENCES test_proxy_request(request_id),
    completed_at    INTEGER NOT NULL,
    http_status     INTEGER NOT NULL CHECK (http_status BETWEEN 100 AND 599),
    upstream_url    TEXT,
    upstream_status INTEGER CHECK (upstream_status BETWEEN 100 AND 599),
    response_bytes  INTEGER NOT NULL CHECK (response_bytes >= 0),
    error           TEXT CHECK (error IS NULL OR error != '')
);

CREATE TRIGGER test_proxy_request_requires_open_session
BEFORE INSERT ON test_proxy_request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
"#,
            )?;
            Ok(())
        })
        .unwrap();
    }

    fn sample_outcome(request_id: RequestId) -> ProxyOutcomeRecord<'static> {
        ProxyOutcomeRecord {
            request_id,
            completed_at: UnixMillis::from_millis(1_700_000_500),
            http_status: 200,
            upstream_url: Some("https://example.test/x"),
            upstream_status: Some(200),
            response_bytes: 16,
            error: None,
        }
    }

    #[allow(clippy::type_complexity)]
    fn dump_request_rows(
        log: &AuditLog,
    ) -> Vec<(
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
        Option<String>,
    )> {
        log.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT request_id, session_id, received_at, method, target, route, decision, \
                 deny_reason FROM test_proxy_request ORDER BY rowid",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
    }

    #[allow(clippy::type_complexity)]
    fn dump_outcome_rows(
        log: &AuditLog,
    ) -> Vec<(
        String,
        i64,
        i64,
        Option<String>,
        Option<i64>,
        i64,
        Option<String>,
    )> {
        log.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT request_id, completed_at, http_status, upstream_url, upstream_status, \
                 response_bytes, error FROM test_proxy_outcome ORDER BY rowid",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
    }

    /// The coalesced writer must reject a closed session exactly as the
    /// two-phase writer does, and — because both rows share one transaction —
    /// leave *neither* row behind on rejection.
    #[test]
    fn request_and_outcome_rejects_closed_session_without_writing() {
        let log = AuditLog::open_in_memory().unwrap();
        install_test_tables(&log);
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_050))
            .unwrap();
        let request_id = RequestId::new();

        let err = log
            .record_proxy_request_and_outcome::<TestTable>(
                &ProxyRequestRecord {
                    request_id,
                    session_id: s.session_id,
                    received_at: UnixMillis::from_millis(1_700_000_100),
                    method: "POST",
                    target: "/x",
                    route: TestRoute::A,
                    decision: &ProxyAuditDecision::Allow,
                },
                &sample_outcome(request_id),
            )
            .unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant("session is closed")),
            "got: {err:?}"
        );
        assert!(
            dump_request_rows(&log).is_empty(),
            "no request row on reject"
        );
        assert!(
            dump_outcome_rows(&log).is_empty(),
            "no outcome row on reject"
        );
    }

    /// Request and outcome rows that disagree on `request_id` are a programming
    /// error that must be refused at *runtime* — not merely a debug assert —
    /// writing nothing, so a release build can never commit an outcome attached
    /// to the wrong request while its own request row is left without one.
    #[test]
    fn request_and_outcome_rejects_mismatched_request_ids_without_writing() {
        let log = AuditLog::open_in_memory().unwrap();
        install_test_tables(&log);
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        let other_id = RequestId::new();

        let err = log
            .record_proxy_request_and_outcome::<TestTable>(
                &ProxyRequestRecord {
                    request_id,
                    session_id: s.session_id,
                    received_at: UnixMillis::from_millis(1_700_000_100),
                    method: "POST",
                    target: "/x",
                    route: TestRoute::A,
                    decision: &ProxyAuditDecision::Allow,
                },
                &sample_outcome(other_id),
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                AuditError::Invariant("coalesced audit rows must share a request_id")
            ),
            "got: {err:?}"
        );
        assert!(dump_request_rows(&log).is_empty());
        assert!(dump_outcome_rows(&log).is_empty());
    }

    #[test]
    fn request_then_outcome_roundtrip() {
        let log = AuditLog::open_in_memory().unwrap();
        install_test_tables(&log);
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();

        log.record_proxy_request::<TestTable>(&ProxyRequestRecord {
            request_id,
            session_id: s.session_id,
            received_at: UnixMillis::from_millis(1_700_000_400),
            method: "POST",
            target: "/x",
            route: TestRoute::A,
            decision: &ProxyAuditDecision::Allow,
        })
        .unwrap();
        log.record_proxy_outcome::<TestTable>(&sample_outcome(request_id))
            .unwrap();

        let entries = log
            .list_proxy_requests_for_session_for_test::<TestTable>(s.session_id)
            .unwrap();
        assert_eq!(
            entries,
            vec![(TestRoute::A, ProxyAuditDecision::Allow, Some(200))]
        );
        assert_eq!(
            log.proxy_outcome_for_test::<TestTable>(request_id).unwrap(),
            Some((200, 16, None))
        );
    }

    #[test]
    fn request_rejects_closed_or_missing_session() {
        let log = AuditLog::open_in_memory().unwrap();
        install_test_tables(&log);
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_050))
            .unwrap();

        let closed = log
            .record_proxy_request::<TestTable>(&ProxyRequestRecord {
                request_id: RequestId::new(),
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(1_700_000_100),
                method: "POST",
                target: "/x",
                route: TestRoute::A,
                decision: &ProxyAuditDecision::Allow,
            })
            .unwrap_err();
        assert!(
            matches!(closed, AuditError::Invariant("session is closed")),
            "got: {closed:?}"
        );

        let missing = log
            .record_proxy_request::<TestTable>(&ProxyRequestRecord {
                request_id: RequestId::new(),
                session_id: SessionId::new(),
                received_at: UnixMillis::from_millis(1_700_000_100),
                method: "POST",
                target: "/x",
                route: TestRoute::A,
                decision: &ProxyAuditDecision::Allow,
            })
            .unwrap_err();
        assert!(
            matches!(missing, AuditError::Invariant("session does not exist")),
            "got: {missing:?}"
        );
    }

    #[test]
    fn request_rejects_empty_method_target_and_deny_reason() {
        let log = AuditLog::open_in_memory().unwrap();
        install_test_tables(&log);
        let s = sample_session();
        log.open_session(&s).unwrap();

        let empty_method = log
            .record_proxy_request::<TestTable>(&ProxyRequestRecord {
                request_id: RequestId::new(),
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(1_700_000_100),
                method: "",
                target: "/x",
                route: TestRoute::A,
                decision: &ProxyAuditDecision::Allow,
            })
            .unwrap_err();
        assert!(
            matches!(
                empty_method,
                AuditError::LabeledInvariant {
                    label: "Test proxy",
                    message: "method must not be empty"
                }
            ),
            "got: {empty_method:?}"
        );

        let empty_target = log
            .record_proxy_request::<TestTable>(&ProxyRequestRecord {
                request_id: RequestId::new(),
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(1_700_000_100),
                method: "POST",
                target: "",
                route: TestRoute::A,
                decision: &ProxyAuditDecision::Allow,
            })
            .unwrap_err();
        assert!(
            matches!(
                empty_target,
                AuditError::LabeledInvariant {
                    label: "Test proxy",
                    message: "target must not be empty"
                }
            ),
            "got: {empty_target:?}"
        );

        let empty_deny_reason = log
            .record_proxy_request::<TestTable>(&ProxyRequestRecord {
                request_id: RequestId::new(),
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(1_700_000_100),
                method: "POST",
                target: "/x",
                route: TestRoute::A,
                decision: &ProxyAuditDecision::Deny {
                    reason: String::new(),
                },
            })
            .unwrap_err();
        assert!(
            matches!(
                empty_deny_reason,
                AuditError::LabeledInvariant {
                    label: "Test proxy",
                    message: "denial reason must not be empty"
                }
            ),
            "got: {empty_deny_reason:?}"
        );
    }

    #[test]
    fn outcome_rejects_out_of_range_status() {
        let log = AuditLog::open_in_memory().unwrap();
        install_test_tables(&log);
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        log.record_proxy_request::<TestTable>(&ProxyRequestRecord {
            request_id,
            session_id: s.session_id,
            received_at: UnixMillis::from_millis(1_700_000_100),
            method: "POST",
            target: "/x",
            route: TestRoute::A,
            decision: &ProxyAuditDecision::Allow,
        })
        .unwrap();

        let bad_status = log
            .record_proxy_outcome::<TestTable>(&ProxyOutcomeRecord {
                request_id,
                completed_at: UnixMillis::from_millis(1_700_000_500),
                http_status: 99,
                upstream_url: None,
                upstream_status: None,
                response_bytes: 0,
                error: None,
            })
            .unwrap_err();
        assert!(
            matches!(
                bad_status,
                AuditError::LabeledInvariant {
                    label: "Test proxy",
                    message: "HTTP status must be 100..599"
                }
            ),
            "got: {bad_status:?}"
        );

        let bad_upstream = log
            .record_proxy_outcome::<TestTable>(&ProxyOutcomeRecord {
                request_id,
                completed_at: UnixMillis::from_millis(1_700_000_500),
                http_status: 502,
                upstream_url: None,
                upstream_status: Some(600),
                response_bytes: 0,
                error: None,
            })
            .unwrap_err();
        assert!(
            matches!(
                bad_upstream,
                AuditError::LabeledInvariant {
                    label: "Test proxy",
                    message: "upstream status must be 100..599"
                }
            ),
            "got: {bad_upstream:?}"
        );
    }

    #[test]
    fn outcome_rejects_empty_error_and_oversize_bytes() {
        let log = AuditLog::open_in_memory().unwrap();
        install_test_tables(&log);
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        log.record_proxy_request::<TestTable>(&ProxyRequestRecord {
            request_id,
            session_id: s.session_id,
            received_at: UnixMillis::from_millis(1_700_000_100),
            method: "POST",
            target: "/x",
            route: TestRoute::A,
            decision: &ProxyAuditDecision::Allow,
        })
        .unwrap();

        let empty_err = log
            .record_proxy_outcome::<TestTable>(&ProxyOutcomeRecord {
                request_id,
                completed_at: UnixMillis::from_millis(1_700_000_500),
                http_status: 502,
                upstream_url: None,
                upstream_status: None,
                response_bytes: 0,
                error: Some(""),
            })
            .unwrap_err();
        assert!(
            matches!(
                empty_err,
                AuditError::LabeledInvariant {
                    label: "Test proxy",
                    message: "error must not be empty when present"
                }
            ),
            "got: {empty_err:?}"
        );

        let too_big = log
            .record_proxy_outcome::<TestTable>(&ProxyOutcomeRecord {
                request_id,
                completed_at: UnixMillis::from_millis(1_700_000_500),
                http_status: 200,
                upstream_url: None,
                upstream_status: None,
                response_bytes: u64::MAX,
                error: None,
            })
            .unwrap_err();
        assert!(
            matches!(
                too_big,
                AuditError::LabeledInvariant {
                    label: "Test proxy",
                    message: "response bytes exceeds SQLite integer range"
                }
            ),
            "got: {too_big:?}"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// For any valid request+outcome pair, the values read back via
        /// the generic SELECT helpers match what was written. Exercises
        /// the shared INSERT/SELECT path against arbitrary string and
        /// numeric payloads, so any divergence between the writer and
        /// reader shows up as a roundtrip mismatch.
        #[test]
        fn proxy_request_outcome_roundtrip_preserves_all_fields(
            // Excludes NUL because SQLite TEXT columns can't carry it
            // (rusqlite would round-trip it as BLOB) — anything else,
            // including SQL meta-characters, is fair game and goes
            // through parameterised queries.
            method in "[\\x01-\\x7e]{1,16}",
            target in "/[\\x01-\\x7e&&[^\\x00]]{0,80}",
            route_is_a in any::<bool>(),
            deny_reason in proptest::option::of("[\\x01-\\x7e]{1,80}"),
            http_status in 100u16..=599,
            upstream_status in proptest::option::of(100u16..=599),
            upstream_url in proptest::option::of("[\\x01-\\x7e]{1,80}"),
            response_bytes in 0u64..=(i64::MAX as u64),
            error in proptest::option::of("[\\x01-\\x7e]{1,80}"),
        ) {
            let log = AuditLog::open_in_memory().unwrap();
            install_test_tables(&log);
            let s = sample_session();
            log.open_session(&s).unwrap();
            let request_id = RequestId::new();

            let route = if route_is_a { TestRoute::A } else { TestRoute::B };
            let decision = match &deny_reason {
                None => ProxyAuditDecision::Allow,
                Some(reason) => ProxyAuditDecision::Deny { reason: reason.clone() },
            };

            log.record_proxy_request::<TestTable>(&ProxyRequestRecord {
                request_id,
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(1_700_000_400),
                method: &method,
                target: &target,
                route,
                decision: &decision,
            })
            .unwrap();

            log.record_proxy_outcome::<TestTable>(&ProxyOutcomeRecord {
                request_id,
                completed_at: UnixMillis::from_millis(1_700_000_500),
                http_status,
                upstream_url: upstream_url.as_deref(),
                upstream_status,
                response_bytes,
                error: error.as_deref(),
            })
            .unwrap();

            let outcome = log.proxy_outcome_for_test::<TestTable>(request_id).unwrap();
            prop_assert_eq!(outcome, Some((http_status, response_bytes, error)));

            let entries = log
                .list_proxy_requests_for_session_for_test::<TestTable>(s.session_id)
                .unwrap();
            prop_assert_eq!(entries, vec![(route, decision, Some(http_status))]);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Coalescing must be behaviour-preserving: for any valid
        /// request+outcome pair, writing both in one transaction via
        /// `record_proxy_request_and_outcome` leaves the two tables
        /// byte-for-byte identical to the two-phase
        /// `record_proxy_request` + `record_proxy_outcome`. Same inputs,
        /// same request_id and session — the only difference is the commit
        /// count, which the persisted rows must not reflect.
        #[test]
        fn request_and_outcome_matches_the_two_phase_writers(
            method in "[\\x01-\\x7e]{1,16}",
            target in "/[\\x01-\\x7e&&[^\\x00]]{0,80}",
            route_is_a in any::<bool>(),
            deny_reason in proptest::option::of("[\\x01-\\x7e]{1,80}"),
            http_status in 100u16..=599,
            upstream_status in proptest::option::of(100u16..=599),
            upstream_url in proptest::option::of("[\\x01-\\x7e]{1,80}"),
            response_bytes in 0u64..=(i64::MAX as u64),
            error in proptest::option::of("[\\x01-\\x7e]{1,80}"),
        ) {
            let two_phase = AuditLog::open_in_memory().unwrap();
            install_test_tables(&two_phase);
            let combined = AuditLog::open_in_memory().unwrap();
            install_test_tables(&combined);
            let s = sample_session();
            two_phase.open_session(&s).unwrap();
            combined.open_session(&s).unwrap();

            let request_id = RequestId::new();
            let route = if route_is_a { TestRoute::A } else { TestRoute::B };
            let decision = match &deny_reason {
                None => ProxyAuditDecision::Allow,
                Some(reason) => ProxyAuditDecision::Deny { reason: reason.clone() },
            };
            let request = ProxyRequestRecord {
                request_id,
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(1_700_000_400),
                method: &method,
                target: &target,
                route,
                decision: &decision,
            };
            let outcome = ProxyOutcomeRecord {
                request_id,
                completed_at: UnixMillis::from_millis(1_700_000_500),
                http_status,
                upstream_url: upstream_url.as_deref(),
                upstream_status,
                response_bytes,
                error: error.as_deref(),
            };

            two_phase.record_proxy_request::<TestTable>(&request).unwrap();
            two_phase.record_proxy_outcome::<TestTable>(&outcome).unwrap();
            combined
                .record_proxy_request_and_outcome::<TestTable>(&request, &outcome)
                .unwrap();

            prop_assert_eq!(dump_request_rows(&two_phase), dump_request_rows(&combined));
            prop_assert_eq!(dump_outcome_rows(&two_phase), dump_outcome_rows(&combined));
        }
    }
}
