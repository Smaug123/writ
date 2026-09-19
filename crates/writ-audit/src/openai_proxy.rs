//! OpenAI proxy audit DAOs.
//!
//! All the work happens in [`super::proxy_table`]; this module just
//! nominates a table descriptor and re-exports the generic record
//! types under the per-backend names.

use super::AuditLog;
use super::proxy_table::{
    ProxyAuditDecision, ProxyAuditRoute, ProxyAuditTable, ProxyOutcomeRecord, ProxyRequestRecord,
};
// Test-only, for the same reason as in `claude_proxy`: the production write path
// is the audit-pair guard, so nothing outside a test needs the error type here.
#[cfg(any(test, feature = "test-support"))]
use super::AuditError;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OpenAiProxyAuditRoute {
    Responses,
    ResponseCancel,
    Models,
    Unsupported,
}

impl ProxyAuditRoute for OpenAiProxyAuditRoute {
    fn as_str(self) -> &'static str {
        match self {
            Self::Responses => "responses",
            Self::ResponseCancel => "response_cancel",
            Self::Models => "models",
            Self::Unsupported => "unsupported",
        }
    }

    fn from_str(raw: &str) -> Option<Self> {
        Some(match raw {
            "responses" => Self::Responses,
            "response_cancel" => Self::ResponseCancel,
            "models" => Self::Models,
            "unsupported" => Self::Unsupported,
            _ => return None,
        })
    }
}

/// Zero-sized table descriptor selecting the `openai_proxy_request` /
/// `openai_proxy_outcome` pair.
///
/// `pub` so the VM-HTTP `broker_effect` driver can name it as its
/// [`EffectAuditTable`](crate::EffectAuditTable); it stays sealed.
pub struct OpenAiProxyAuditTable;

impl ProxyAuditTable for OpenAiProxyAuditTable {
    type Route = OpenAiProxyAuditRoute;
    const REQUEST_TABLE: &'static str = "openai_proxy_request";
    const OUTCOME_TABLE: &'static str = "openai_proxy_outcome";
    const LABEL: &'static str = "OpenAI proxy";
}

pub type OpenAiProxyAuditDecision = ProxyAuditDecision;
pub type OpenAiProxyRequestRecord<'a> = ProxyRequestRecord<'a, OpenAiProxyAuditRoute>;
pub type OpenAiProxyOutcomeRecord<'a> = ProxyOutcomeRecord<'a>;

impl AuditLog {
    #[cfg(test)]
    pub(crate) fn openai_proxy_outcome_for_test(
        &self,
        request_id: writ_core::core::RequestId,
    ) -> Result<Option<(u16, u64, Option<String>)>, AuditError> {
        self.proxy_outcome_for_test::<OpenAiProxyAuditTable>(request_id)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn list_openai_proxy_requests_for_session_for_test(
        &self,
        id: writ_core::core::SessionId,
    ) -> Result<Vec<(OpenAiProxyAuditRoute, OpenAiProxyAuditDecision, Option<u16>)>, AuditError>
    {
        self.list_proxy_requests_for_session_for_test::<OpenAiProxyAuditTable>(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_session;
    use writ_core::core::{RequestId, UnixMillis};

    #[test]
    fn openai_proxy_request_then_outcome_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();

        log.seed_effect_request::<OpenAiProxyAuditTable>(&OpenAiProxyRequestRecord {
            request_id,
            session_id: s.session_id,
            received_at: UnixMillis::from_millis(1_700_000_300),
            method: "POST",
            target: "/v1/responses",
            route: OpenAiProxyAuditRoute::Responses,
            decision: &OpenAiProxyAuditDecision::Allow,
        })
        .unwrap();
        log.seed_effect_outcome::<OpenAiProxyAuditTable>(&OpenAiProxyOutcomeRecord {
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
}
