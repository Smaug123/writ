//! Session DAOs and the `SqlAgentKind` newtype that mediates the
//! `agent_kind` column between SQLite text and the typed `AgentKind`.

use rusqlite::{OptionalExtension, Row, params};

use super::{AuditError, AuditLog};
use crate::core::{AgentKind, SessionId, SessionRecord, UnixMillis};

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
