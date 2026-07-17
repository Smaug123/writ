//! DAO for agent-VM network-health transition events.
//!
//! The daemon detects, host-side, when a running agent VM has lost its path to
//! the broker (see the host `agent_vm_lifecycle::network_health` module) and
//! appends one row here on each debounced transition. Append-only: no
//! UPDATE/DELETE.

use rusqlite::params;
use writ_core::core::NetworkHealth;

use super::{AuditError, AuditLog};
use writ_core::core::{SessionId, UnixMillis};

/// One debounced host-side network-health transition for a session. Recorded
/// only when the surfaced health value actually changes (e.g. `reachable` ->
/// `unreachable`); the DB also enforces `from_health != to_health`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmNetworkHealthEventRecord {
    pub session_id: SessionId,
    pub observed_at: UnixMillis,
    pub from_health: NetworkHealth,
    pub to_health: NetworkHealth,
    pub consecutive_failures: u32,
}

impl AuditLog {
    /// Append a network-health transition event. Best-effort at the call site:
    /// a probe racing session teardown trips the `requires_open_session`
    /// trigger and returns an error the caller logs rather than propagates.
    pub fn record_agent_vm_network_health_event(
        &self,
        r: &AgentVmNetworkHealthEventRecord,
    ) -> Result<(), AuditError> {
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO agent_vm_network_health_event \
                 (session_id, observed_at, from_health, to_health, consecutive_failures) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    r.session_id.as_uuid().to_string(),
                    r.observed_at.as_millis(),
                    r.from_health.as_str(),
                    r.to_health.as_str(),
                    i64::from(r.consecutive_failures),
                ],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_session;

    fn sample(session_id: SessionId) -> AgentVmNetworkHealthEventRecord {
        AgentVmNetworkHealthEventRecord {
            session_id,
            observed_at: UnixMillis::from_millis(1_700_000_300),
            from_health: NetworkHealth::Reachable,
            to_health: NetworkHealth::Unreachable,
            consecutive_failures: 3,
        }
    }

    fn rows(log: &AuditLog, id: SessionId) -> Vec<(String, String, i64)> {
        log.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT from_health, to_health, consecutive_failures \
                 FROM agent_vm_network_health_event \
                 WHERE session_id = ?1 ORDER BY event_id",
            )?;
            let mut q = stmt.query(params![id.as_uuid().to_string()])?;
            let mut out = Vec::new();
            while let Some(row) = q.next()? {
                out.push((row.get(0)?, row.get(1)?, row.get(2)?));
            }
            Ok(out)
        })
        .unwrap()
    }

    #[test]
    fn islanding_event_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.record_agent_vm_network_health_event(&sample(s.session_id))
            .unwrap();
        assert_eq!(
            rows(&log, s.session_id),
            vec![("reachable".to_string(), "unreachable".to_string(), 3)]
        );
    }

    #[test]
    fn recording_against_a_closed_session_is_refused() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_400))
            .unwrap();
        let err = log
            .record_agent_vm_network_health_event(&sample(s.session_id))
            .unwrap_err();
        assert!(
            format!("{err}").contains("session is closed"),
            "expected the requires_open_session trigger to fire, got: {err}"
        );
    }

    #[test]
    fn non_transition_is_rejected_by_the_db() {
        // Defense in depth: the DAO is only called on a real transition, but
        // the table also forbids from == to.
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let mut rec = sample(s.session_id);
        rec.from_health = NetworkHealth::Unreachable;
        rec.to_health = NetworkHealth::Unreachable;
        assert!(
            log.record_agent_vm_network_health_event(&rec).is_err(),
            "from_health == to_health must violate the CHECK"
        );
    }
}
