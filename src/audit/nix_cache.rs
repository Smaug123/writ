//! Nix cache audit DAOs and row parsing.

use rusqlite::{OptionalExtension, Row, params};

use super::validation::u16_from_sql_status;
use super::{AuditError, AuditLog};
use crate::core::{RequestId, SessionId, UnixMillis};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NixCacheAuditRoute {
    CacheInfo,
    NarInfo,
    Nar,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NixCacheAuditDecision {
    Allow,
    Deny { reason: String },
}

#[derive(Debug)]
pub struct NixCacheRequestRecord<'a> {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub method: &'a str,
    pub target: &'a str,
    pub route: NixCacheAuditRoute,
    pub decision: &'a NixCacheAuditDecision,
}

#[derive(Debug)]
pub struct NixCacheOutcomeRecord<'a> {
    pub request_id: RequestId,
    pub completed_at: UnixMillis,
    pub http_status: u16,
    pub upstream_url: Option<&'a str>,
    pub upstream_status: Option<u16>,
    pub response_bytes: u64,
    pub error: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NixCacheAuditEntry {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub method: String,
    pub target: String,
    pub route: NixCacheAuditRoute,
    pub decision: NixCacheAuditDecision,
    pub completed_at: Option<UnixMillis>,
    pub http_status: Option<u16>,
    pub upstream_url: Option<String>,
    pub upstream_status: Option<u16>,
    pub response_bytes: Option<u64>,
    pub error: Option<String>,
}

impl AuditLog {
    /// Persist a VM Nix cache request before any upstream cache fetch is
    /// attempted. The matching outcome is appended with
    /// [`AuditLog::record_nix_cache_outcome`].
    pub fn record_nix_cache_request(
        &self,
        r: &NixCacheRequestRecord<'_>,
    ) -> Result<(), AuditError> {
        if r.method.is_empty() {
            return Err(AuditError::Invariant(
                "Nix cache audit method must not be empty",
            ));
        }
        if r.target.is_empty() {
            return Err(AuditError::Invariant(
                "Nix cache audit target must not be empty",
            ));
        }
        if let NixCacheAuditDecision::Deny { reason } = r.decision
            && reason.is_empty()
        {
            return Err(AuditError::Invariant(
                "Nix cache audit denial reason must not be empty",
            ));
        }

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

            let (decision, deny_reason) = match r.decision {
                NixCacheAuditDecision::Allow => ("allow", None),
                NixCacheAuditDecision::Deny { reason } => ("deny", Some(reason.as_str())),
            };
            tx.execute(
                "INSERT INTO nix_cache_request (
                     request_id,
                     session_id,
                     received_at,
                     method,
                     target,
                     route,
                     decision,
                     deny_reason
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
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
            tx.commit()?;
            Ok(())
        })
    }

    /// Append the observed broker outcome for a previously-recorded VM Nix
    /// cache request. This is a separate row so the upstream fetch is never
    /// attempted before the request itself is durable.
    pub fn record_nix_cache_outcome(
        &self,
        r: &NixCacheOutcomeRecord<'_>,
    ) -> Result<(), AuditError> {
        if !(100..=599).contains(&r.http_status) {
            return Err(AuditError::Invariant(
                "Nix cache audit HTTP status must be 100..599",
            ));
        }
        if let Some(status) = r.upstream_status
            && !(100..=599).contains(&status)
        {
            return Err(AuditError::Invariant(
                "Nix cache audit upstream status must be 100..599",
            ));
        }
        if let Some(error) = r.error
            && error.is_empty()
        {
            return Err(AuditError::Invariant(
                "Nix cache audit error must not be empty when present",
            ));
        }
        if r.response_bytes > i64::MAX as u64 {
            return Err(AuditError::Invariant(
                "Nix cache audit response bytes exceeds SQLite integer range",
            ));
        }

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            tx.execute(
                "INSERT INTO nix_cache_outcome (
                     request_id,
                     completed_at,
                     http_status,
                     upstream_url,
                     upstream_status,
                     response_bytes,
                     error
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
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
            tx.commit()?;
            Ok(())
        })
    }

    pub fn list_nix_cache_requests_for_session(
        &self,
        id: SessionId,
    ) -> Result<Vec<NixCacheAuditEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT
                     r.request_id,
                     r.session_id,
                     r.received_at,
                     r.method,
                     r.target,
                     r.route,
                     r.decision,
                     r.deny_reason,
                     o.completed_at,
                     o.http_status,
                     o.upstream_url,
                     o.upstream_status,
                     o.response_bytes,
                     o.error
                 FROM nix_cache_request r
                 LEFT JOIN nix_cache_outcome o ON o.request_id = r.request_id
                 WHERE r.session_id = ?1
                 ORDER BY r.received_at ASC, r.rowid ASC",
            )?;
            let rows = stmt
                .query_map(
                    params![id.as_uuid().to_string()],
                    nix_cache_audit_entry_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }
}

impl NixCacheAuditRoute {
    fn as_str(self) -> &'static str {
        match self {
            Self::CacheInfo => "cache_info",
            Self::NarInfo => "narinfo",
            Self::Nar => "nar",
            Self::Unsupported => "unsupported",
        }
    }

    fn from_str(raw: &str) -> Result<Self, AuditError> {
        match raw {
            "cache_info" => Ok(Self::CacheInfo),
            "narinfo" => Ok(Self::NarInfo),
            "nar" => Ok(Self::Nar),
            "unsupported" => Ok(Self::Unsupported),
            _ => Err(AuditError::Invariant("Nix cache audit route is invalid")),
        }
    }
}

fn nix_cache_audit_entry_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<Result<NixCacheAuditEntry, AuditError>> {
    let request_id_str: String = row.get(0)?;
    let session_id_str: String = row.get(1)?;
    let received_at: i64 = row.get(2)?;
    let method: String = row.get(3)?;
    let target: String = row.get(4)?;
    let route: String = row.get(5)?;
    let decision: String = row.get(6)?;
    let deny_reason: Option<String> = row.get(7)?;
    let completed_at: Option<i64> = row.get(8)?;
    let http_status: Option<i64> = row.get(9)?;
    let upstream_url: Option<String> = row.get(10)?;
    let upstream_status: Option<i64> = row.get(11)?;
    let response_bytes: Option<i64> = row.get(12)?;
    let error: Option<String> = row.get(13)?;

    let parse = || -> Result<NixCacheAuditEntry, AuditError> {
        let request_id = uuid::Uuid::parse_str(&request_id_str)
            .map_err(|_| AuditError::Invariant("Nix cache audit row: request_id not a uuid"))?;
        let session_id = uuid::Uuid::parse_str(&session_id_str)
            .map_err(|_| AuditError::Invariant("Nix cache audit row: session_id not a uuid"))?;
        let decision = match (decision.as_str(), deny_reason) {
            ("allow", None) => NixCacheAuditDecision::Allow,
            ("deny", Some(reason)) if !reason.is_empty() => NixCacheAuditDecision::Deny { reason },
            ("deny", _) => {
                return Err(AuditError::Invariant(
                    "Nix cache audit deny row lacks reason",
                ));
            }
            ("allow", Some(_)) => {
                return Err(AuditError::Invariant(
                    "Nix cache audit allow row has deny reason",
                ));
            }
            _ => {
                return Err(AuditError::Invariant("Nix cache audit decision is invalid"));
            }
        };
        let http_status = http_status.map(u16_from_sql_status).transpose()?;
        let upstream_status = upstream_status.map(u16_from_sql_status).transpose()?;
        let response_bytes = response_bytes
            .map(|value| {
                u64::try_from(value).map_err(|_| {
                    AuditError::Invariant("Nix cache audit response bytes is negative")
                })
            })
            .transpose()?;
        Ok(NixCacheAuditEntry {
            request_id: RequestId::from_uuid(request_id),
            session_id: SessionId::from_uuid(session_id),
            received_at: UnixMillis::from_millis(received_at),
            method,
            target,
            route: NixCacheAuditRoute::from_str(&route)?,
            decision,
            completed_at: completed_at.map(UnixMillis::from_millis),
            http_status,
            upstream_url,
            upstream_status,
            response_bytes,
            error,
        })
    };
    Ok(parse())
}
