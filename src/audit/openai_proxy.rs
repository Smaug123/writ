//! OpenAI proxy audit DAOs.

use rusqlite::{OptionalExtension, params};

use super::{AuditError, AuditLog};
use crate::core::{RequestId, SessionId, UnixMillis};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OpenAiProxyAuditRoute {
    Responses,
    ResponseCancel,
    Models,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenAiProxyAuditDecision {
    Allow,
    Deny { reason: String },
}

#[derive(Debug)]
pub struct OpenAiProxyRequestRecord<'a> {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub method: &'a str,
    pub target: &'a str,
    pub route: OpenAiProxyAuditRoute,
    pub decision: &'a OpenAiProxyAuditDecision,
}

#[derive(Debug)]
pub struct OpenAiProxyOutcomeRecord<'a> {
    pub request_id: RequestId,
    pub completed_at: UnixMillis,
    pub http_status: u16,
    pub upstream_url: Option<&'a str>,
    pub upstream_status: Option<u16>,
    pub response_bytes: u64,
    pub error: Option<&'a str>,
}

impl AuditLog {
    /// Persist a VM OpenAI proxy request before any upstream model-provider
    /// request is attempted. The matching outcome is appended with
    /// [`AuditLog::record_openai_proxy_outcome`].
    pub fn record_openai_proxy_request(
        &self,
        r: &OpenAiProxyRequestRecord<'_>,
    ) -> Result<(), AuditError> {
        if r.method.is_empty() {
            return Err(AuditError::Invariant(
                "OpenAI proxy audit method must not be empty",
            ));
        }
        if r.target.is_empty() {
            return Err(AuditError::Invariant(
                "OpenAI proxy audit target must not be empty",
            ));
        }
        if let OpenAiProxyAuditDecision::Deny { reason } = r.decision
            && reason.is_empty()
        {
            return Err(AuditError::Invariant(
                "OpenAI proxy audit denial reason must not be empty",
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
                OpenAiProxyAuditDecision::Allow => ("allow", None),
                OpenAiProxyAuditDecision::Deny { reason } => ("deny", Some(reason.as_str())),
            };
            tx.execute(
                "INSERT INTO openai_proxy_request (
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

    /// Append the observed broker outcome for a previously-recorded VM OpenAI
    /// proxy request.
    pub fn record_openai_proxy_outcome(
        &self,
        r: &OpenAiProxyOutcomeRecord<'_>,
    ) -> Result<(), AuditError> {
        if !(100..=599).contains(&r.http_status) {
            return Err(AuditError::Invariant(
                "OpenAI proxy audit HTTP status must be 100..599",
            ));
        }
        if let Some(status) = r.upstream_status
            && !(100..=599).contains(&status)
        {
            return Err(AuditError::Invariant(
                "OpenAI proxy audit upstream status must be 100..599",
            ));
        }
        if let Some(error) = r.error
            && error.is_empty()
        {
            return Err(AuditError::Invariant(
                "OpenAI proxy audit error must not be empty when present",
            ));
        }
        if r.response_bytes > i64::MAX as u64 {
            return Err(AuditError::Invariant(
                "OpenAI proxy audit response bytes exceeds SQLite integer range",
            ));
        }

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            tx.execute(
                "INSERT INTO openai_proxy_outcome (
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
    pub(crate) fn openai_proxy_outcome_for_test(
        &self,
        request_id: RequestId,
    ) -> Result<Option<(u16, u64, Option<String>)>, AuditError> {
        self.with_conn(|c| {
            c.query_row(
                "SELECT http_status, response_bytes, error
                 FROM openai_proxy_outcome
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
    pub(crate) fn list_openai_proxy_requests_for_session_for_test(
        &self,
        id: SessionId,
    ) -> Result<Vec<(OpenAiProxyAuditRoute, OpenAiProxyAuditDecision, Option<u16>)>, AuditError>
    {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT r.route, r.decision, r.deny_reason, o.http_status
                 FROM openai_proxy_request r
                 LEFT JOIN openai_proxy_outcome o ON o.request_id = r.request_id
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
                        "responses" => OpenAiProxyAuditRoute::Responses,
                        "response_cancel" => OpenAiProxyAuditRoute::ResponseCancel,
                        "models" => OpenAiProxyAuditRoute::Models,
                        "unsupported" => OpenAiProxyAuditRoute::Unsupported,
                        other => panic!("unknown OpenAI proxy audit route {other:?}"),
                    };
                    let decision = match (decision.as_str(), deny_reason) {
                        ("allow", _) => OpenAiProxyAuditDecision::Allow,
                        ("deny", Some(reason)) => OpenAiProxyAuditDecision::Deny { reason },
                        (other, deny_reason) => panic!(
                            "unexpected OpenAI proxy audit decision row: decision={other:?} deny_reason={deny_reason:?}"
                        ),
                    };
                    (route, decision, http_status.map(|status| status as u16))
                })
                .collect())
        })
    }
}

impl OpenAiProxyAuditRoute {
    fn as_str(self) -> &'static str {
        match self {
            Self::Responses => "responses",
            Self::ResponseCancel => "response_cancel",
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
}
