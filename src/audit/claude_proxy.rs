//! Claude proxy audit DAOs.

use rusqlite::{OptionalExtension, params};

use super::{AuditError, AuditLog};
use crate::core::{RequestId, SessionId, UnixMillis};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ClaudeProxyAuditRoute {
    Messages,
    CountTokens,
    Models,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaudeProxyAuditDecision {
    Allow,
    Deny { reason: String },
}

#[derive(Debug)]
pub struct ClaudeProxyRequestRecord<'a> {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub method: &'a str,
    pub target: &'a str,
    pub route: ClaudeProxyAuditRoute,
    pub decision: &'a ClaudeProxyAuditDecision,
}

#[derive(Debug)]
pub struct ClaudeProxyOutcomeRecord<'a> {
    pub request_id: RequestId,
    pub completed_at: UnixMillis,
    pub http_status: u16,
    pub upstream_url: Option<&'a str>,
    pub upstream_status: Option<u16>,
    pub response_bytes: u64,
    pub error: Option<&'a str>,
}

impl AuditLog {
    /// Persist a VM Claude proxy request before any upstream model-provider
    /// request is attempted. The matching outcome is appended with
    /// [`AuditLog::record_claude_proxy_outcome`].
    pub fn record_claude_proxy_request(
        &self,
        r: &ClaudeProxyRequestRecord<'_>,
    ) -> Result<(), AuditError> {
        if r.method.is_empty() {
            return Err(AuditError::Invariant(
                "Claude proxy audit method must not be empty",
            ));
        }
        if r.target.is_empty() {
            return Err(AuditError::Invariant(
                "Claude proxy audit target must not be empty",
            ));
        }
        if let ClaudeProxyAuditDecision::Deny { reason } = r.decision
            && reason.is_empty()
        {
            return Err(AuditError::Invariant(
                "Claude proxy audit denial reason must not be empty",
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
                ClaudeProxyAuditDecision::Allow => ("allow", None),
                ClaudeProxyAuditDecision::Deny { reason } => ("deny", Some(reason.as_str())),
            };
            tx.execute(
                "INSERT INTO claude_proxy_request (
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

    /// Append the observed broker outcome for a previously-recorded VM Claude
    /// proxy request.
    pub fn record_claude_proxy_outcome(
        &self,
        r: &ClaudeProxyOutcomeRecord<'_>,
    ) -> Result<(), AuditError> {
        if !(100..=599).contains(&r.http_status) {
            return Err(AuditError::Invariant(
                "Claude proxy audit HTTP status must be 100..599",
            ));
        }
        if let Some(status) = r.upstream_status
            && !(100..=599).contains(&status)
        {
            return Err(AuditError::Invariant(
                "Claude proxy audit upstream status must be 100..599",
            ));
        }
        if let Some(error) = r.error
            && error.is_empty()
        {
            return Err(AuditError::Invariant(
                "Claude proxy audit error must not be empty when present",
            ));
        }
        if r.response_bytes > i64::MAX as u64 {
            return Err(AuditError::Invariant(
                "Claude proxy audit response bytes exceeds SQLite integer range",
            ));
        }

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            tx.execute(
                "INSERT INTO claude_proxy_outcome (
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

    #[cfg(test)]
    pub(crate) fn claude_proxy_outcome_for_test(
        &self,
        request_id: RequestId,
    ) -> Result<Option<(u16, u64, Option<String>)>, AuditError> {
        self.with_conn(|c| {
            c.query_row(
                "SELECT http_status, response_bytes, error
                 FROM claude_proxy_outcome
                 WHERE request_id = ?1",
                params![request_id.as_uuid().to_string()],
                |row| {
                    let http_status: i64 = row.get(0)?;
                    let response_bytes: i64 = row.get(1)?;
                    let error: Option<String> = row.get(2)?;
                    Ok((http_status as u16, response_bytes as u64, error))
                },
            )
            .optional()
            .map_err(AuditError::from)
        })
    }

    #[cfg(test)]
    pub(crate) fn list_claude_proxy_requests_for_session_for_test(
        &self,
        id: SessionId,
    ) -> Result<Vec<(ClaudeProxyAuditRoute, ClaudeProxyAuditDecision, Option<u16>)>, AuditError>
    {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT r.route, r.decision, r.deny_reason, o.http_status
                 FROM claude_proxy_request r
                 LEFT JOIN claude_proxy_outcome o ON o.request_id = r.request_id
                 WHERE r.session_id = ?1
                 ORDER BY r.received_at ASC, r.rowid ASC",
            )?;
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
                    let route = match route.as_str() {
                        "messages" => ClaudeProxyAuditRoute::Messages,
                        "count_tokens" => ClaudeProxyAuditRoute::CountTokens,
                        "models" => ClaudeProxyAuditRoute::Models,
                        "unsupported" => ClaudeProxyAuditRoute::Unsupported,
                        other => panic!("unknown Claude proxy audit route {other:?}"),
                    };
                    let decision = match (decision.as_str(), deny_reason) {
                        ("allow", _) => ClaudeProxyAuditDecision::Allow,
                        ("deny", Some(reason)) => ClaudeProxyAuditDecision::Deny { reason },
                        (other, deny_reason) => panic!(
                            "unexpected Claude proxy audit decision row: decision={other:?} deny_reason={deny_reason:?}"
                        ),
                    };
                    (route, decision, http_status.map(|status| status as u16))
                })
                .collect())
        })
    }
}

impl ClaudeProxyAuditRoute {
    fn as_str(self) -> &'static str {
        match self {
            Self::Messages => "messages",
            Self::CountTokens => "count_tokens",
            Self::Models => "models",
            Self::Unsupported => "unsupported",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::sample_session;

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
}
