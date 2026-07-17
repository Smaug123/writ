//! Session DAOs and the `SqlAgentKind` newtype that mediates the
//! `agent_kind` column between SQLite text and the typed `AgentKind`.

use rusqlite::{OptionalExtension, Row, params};

use super::{AuditError, AuditLog};
use writ_core::core::{AgentKind, SessionId, SessionRecord, UnixMillis};

impl AuditLog {
    pub fn open_session(&self, s: &SessionRecord) -> Result<(), AuditError> {
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO session (session_id, label, agent_kind, agent_model, opened_at, closed_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    s.session_id.as_uuid().to_string(),
                    s.label,
                    s.agent_kind.map(AgentKind::as_str),
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
                    "SELECT session_id, label, agent_kind, agent_model, opened_at, closed_at \
                     FROM session WHERE session_id = ?1",
                    params![id.as_uuid().to_string()],
                    session_from_row,
                )
                .optional()?;
            Ok(row)
        })
    }
}

pub(super) fn session_from_row(row: &Row<'_>) -> rusqlite::Result<SessionRecord> {
    let session_id_str: String = row.get("session_id")?;
    let label: Option<String> = row.get("label")?;
    let agent_kind: Option<SqlAgentKind> = row.get("agent_kind")?;
    let agent_model: Option<String> = row.get("agent_model")?;
    let opened_at: i64 = row.get("opened_at")?;
    let closed_at: Option<i64> = row.get("closed_at")?;
    let uuid = uuid::Uuid::parse_str(&session_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(SessionRecord {
        session_id: SessionId::from_uuid(uuid),
        label,
        agent_kind: agent_kind.map(SqlAgentKind::into_inner),
        agent_model,
        opened_at: UnixMillis::from_millis(opened_at),
        closed_at: closed_at.map(UnixMillis::from_millis),
    })
}

pub(super) struct SqlAgentKind(AgentKind);

impl SqlAgentKind {
    pub(super) fn into_inner(self) -> AgentKind {
        self.0
    }
}

impl rusqlite::types::FromSql for SqlAgentKind {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let raw = value.as_str()?;
        raw.parse::<AgentKind>()
            .map(Self)
            .map_err(|err| rusqlite::types::FromSqlError::Other(Box::new(err)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_session;

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
}
