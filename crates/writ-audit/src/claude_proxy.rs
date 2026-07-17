//! Claude proxy audit DAOs.
//!
//! All the work happens in [`super::proxy_table`]; this module just
//! nominates a table descriptor and re-exports the generic record
//! types under the per-backend names.

use super::proxy_table::{
    ProxyAuditDecision, ProxyAuditRoute, ProxyAuditTable, ProxyOutcomeRecord, ProxyRequestRecord,
};
use super::{AuditError, AuditLog};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ClaudeProxyAuditRoute {
    Messages,
    CountTokens,
    Models,
    Unsupported,
}

impl ProxyAuditRoute for ClaudeProxyAuditRoute {
    fn as_str(self) -> &'static str {
        match self {
            Self::Messages => "messages",
            Self::CountTokens => "count_tokens",
            Self::Models => "models",
            Self::Unsupported => "unsupported",
        }
    }

    fn from_str(raw: &str) -> Option<Self> {
        Some(match raw {
            "messages" => Self::Messages,
            "count_tokens" => Self::CountTokens,
            "models" => Self::Models,
            "unsupported" => Self::Unsupported,
            _ => return None,
        })
    }
}

/// Zero-sized table descriptor selecting the `claude_proxy_request` /
/// `claude_proxy_outcome` pair.
pub(super) struct ClaudeProxyAuditTable;

impl ProxyAuditTable for ClaudeProxyAuditTable {
    type Route = ClaudeProxyAuditRoute;
    const REQUEST_TABLE: &'static str = "claude_proxy_request";
    const OUTCOME_TABLE: &'static str = "claude_proxy_outcome";
    const LABEL: &'static str = "Claude proxy";
}

pub type ClaudeProxyAuditDecision = ProxyAuditDecision;
pub type ClaudeProxyRequestRecord<'a> = ProxyRequestRecord<'a, ClaudeProxyAuditRoute>;
pub type ClaudeProxyOutcomeRecord<'a> = ProxyOutcomeRecord<'a>;

impl AuditLog {
    /// Persist a VM Claude proxy request before any upstream
    /// model-provider request is attempted. The matching outcome is
    /// appended with [`AuditLog::record_claude_proxy_outcome`].
    pub fn record_claude_proxy_request(
        &self,
        r: &ClaudeProxyRequestRecord<'_>,
    ) -> Result<(), AuditError> {
        self.record_proxy_request::<ClaudeProxyAuditTable>(r)
    }

    /// Append the observed broker outcome for a previously-recorded VM
    /// Claude proxy request.
    pub fn record_claude_proxy_outcome(
        &self,
        r: &ClaudeProxyOutcomeRecord<'_>,
    ) -> Result<(), AuditError> {
        self.record_proxy_outcome::<ClaudeProxyAuditTable>(r)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn claude_proxy_outcome_for_test(
        &self,
        request_id: writ_core::core::RequestId,
    ) -> Result<Option<(u16, u64, Option<String>)>, AuditError> {
        self.proxy_outcome_for_test::<ClaudeProxyAuditTable>(request_id)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn list_claude_proxy_requests_for_session_for_test(
        &self,
        id: writ_core::core::SessionId,
    ) -> Result<Vec<(ClaudeProxyAuditRoute, ClaudeProxyAuditDecision, Option<u16>)>, AuditError>
    {
        self.list_proxy_requests_for_session_for_test::<ClaudeProxyAuditTable>(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_session;
    use rusqlite::params;
    use writ_core::core::{RequestId, UnixMillis};

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
