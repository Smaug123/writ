//! Stage-0 oracle for the "complete by construction" audit-pair invariant.
//!
//! The broker's central promise is that *no brokered effect happens without a
//! durable audit pair* — a `*_request` row recorded before the effect and a
//! matching `*_outcome` row recorded after. Today that promise is kept by
//! discipline at each of ~7 effect handlers (see
//! `docs/plans/2026-07-18-brokered-effect-audit-enforcement.md`); nothing in the
//! type system forces a handler that performs an effect to record the pair.
//!
//! This module is the *executable oracle* for that invariant: after driving any
//! effect, a test asserts that every `*_request` row has its `*_outcome`
//! partner. It is deliberately **table-name based** rather than typed, so one
//! primitive covers every effect regardless of its column shape — the pairs
//! differ in columns (proxy `method/target/route`, git-push `repo/branch/heads`,
//! flake `dirs/archive-metrics`) but they all share the shape *"a request row
//! joined to an outcome row on one key column"*. The key column is the only
//! per-effect parameter: `request_id` for the proxies and the host grant,
//! `push_request_id` for git-push, `run_id` for agent-runs.
//!
//! It is the executable form of the reviewer's finding: drive a handler that
//! forgets its outcome row and the oracle goes RED (see the `tests` below, and
//! `git_push.rs::git_push_handler_satisfies_audit_pair_oracle` for the same
//! assertion applied to a real current handler). As effects are ported onto the
//! single `broker_effect` driver in later stages, each port wires its handler
//! drive through [`AuditLog::assert_effect_audit_pairs_complete`], so this one
//! oracle grows to cover every capability — including future ones — by
//! construction.

use crate::AuditLog;

impl AuditLog {
    /// Assert the audit-pair invariant for one effect's `(request, outcome)`
    /// table pair: **every** `request_table` row has a matching `outcome_table`
    /// row on `join_column`. Panics with a diagnostic naming the tables when any
    /// request row is unpaired — which is exactly what a handler that performs an
    /// effect but forgets to record its outcome leaves behind.
    ///
    /// Pair this with [`AuditLog::table_row_count_for_test`] for a non-vacuity
    /// guard (assert the drive actually recorded an outcome before asserting the
    /// pair holds), so a drive that silently recorded *nothing* cannot pass
    /// vacuously.
    ///
    /// `request_table`, `outcome_table`, and `join_column` are trusted
    /// crate-internal identifiers — the same `&'static str` table/column names
    /// the DAOs already interpolate into SQL — never guest input.
    pub fn assert_effect_audit_pairs_complete(
        &self,
        request_table: &str,
        outcome_table: &str,
        join_column: &str,
    ) {
        let unpaired = self.unpaired_effect_request_rows(request_table, outcome_table, join_column);
        assert!(
            unpaired == 0,
            "audit-pair invariant violated: {unpaired} row(s) in `{request_table}` have no \
             matching `{outcome_table}` row on `{join_column}` — an effect was performed \
             without recording its outcome",
        );
    }

    /// The count behind [`AuditLog::assert_effect_audit_pairs_complete`]: rows in
    /// `request_table` with no matching `outcome_table` row on `join_column`.
    /// Zero means every begun effect is paired. Thin test-support wrapper over the
    /// production [`AuditLog::count_unpaired_effect_request_rows`], sharing its one
    /// `LEFT JOIN` query.
    pub fn unpaired_effect_request_rows(
        &self,
        request_table: &str,
        outcome_table: &str,
        join_column: &str,
    ) -> u64 {
        self.count_unpaired_effect_request_rows(request_table, outcome_table, join_column)
            .expect("audit-pair oracle count query")
    }

    /// Row count in an audit `table`, for the non-vacuity half of a drive
    /// assertion (snapshot before the drive, assert an increase after).
    pub fn table_row_count_for_test(&self, table: &str) -> u64 {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        self.with_conn(|c| {
            let count: i64 = c.query_row(&sql, [], |row| row.get(0))?;
            Ok(count as u64)
        })
        .expect("audit table row-count query")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_session;
    use writ_core::core::{RequestId, UnixMillis};

    use crate::claude_proxy::{
        ClaudeProxyAuditDecision, ClaudeProxyAuditRoute, ClaudeProxyOutcomeRecord,
        ClaudeProxyRequestRecord,
    };

    const REQ: &str = "claude_proxy_request";
    const OUT: &str = "claude_proxy_outcome";
    const KEY: &str = "request_id";

    fn record_request(
        log: &AuditLog,
        session_id: writ_core::core::SessionId,
        request_id: RequestId,
    ) {
        log.record_claude_proxy_request(&ClaudeProxyRequestRecord {
            request_id,
            session_id,
            received_at: UnixMillis::from_millis(1_700_000_200),
            method: "POST",
            target: "/v1/messages",
            route: ClaudeProxyAuditRoute::Messages,
            decision: &ClaudeProxyAuditDecision::Allow,
        })
        .unwrap();
    }

    fn record_outcome(log: &AuditLog, request_id: RequestId) {
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
    }

    /// GREEN: a fully-recorded two-phase pair leaves no unpaired request row, and
    /// the oracle assertion passes.
    #[test]
    fn complete_pair_satisfies_the_oracle() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();

        let before = log.table_row_count_for_test(OUT);
        record_request(&log, s.session_id, request_id);
        record_outcome(&log, request_id);

        // Non-vacuity: the drive actually recorded an outcome.
        assert_eq!(log.table_row_count_for_test(OUT), before + 1);
        assert_eq!(log.unpaired_effect_request_rows(REQ, OUT, KEY), 0);
        log.assert_effect_audit_pairs_complete(REQ, OUT, KEY);
    }

    /// RED: a request row with no outcome — the signature of a handler that
    /// performed an effect but forgot to record its outcome — is detected as one
    /// unpaired row.
    #[test]
    fn missing_outcome_is_detected_as_unpaired() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        record_request(&log, s.session_id, RequestId::new());
        // Deliberately skip the outcome — this is the un-audited effect.

        assert_eq!(log.unpaired_effect_request_rows(REQ, OUT, KEY), 1);
    }

    /// RED, via the panicking assertion the drive tests actually call: the oracle
    /// itself goes RED on an un-audited effect. This is the permanent guard that
    /// the oracle *can* catch the bug it exists to catch; if this ever stops
    /// panicking, the oracle has been weakened.
    #[test]
    #[should_panic(expected = "audit-pair invariant violated")]
    fn oracle_panics_on_unaudited_effect() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        record_request(&log, s.session_id, RequestId::new());
        // No outcome recorded.
        log.assert_effect_audit_pairs_complete(REQ, OUT, KEY);
    }

    /// Two complete pairs stay green; adding a third bare request row flips the
    /// count to one unpaired, proving the check is per-row, not all-or-nothing.
    #[test]
    fn detects_a_single_unpaired_row_among_complete_pairs() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        for _ in 0..2 {
            let id = RequestId::new();
            record_request(&log, s.session_id, id);
            record_outcome(&log, id);
        }
        assert_eq!(log.unpaired_effect_request_rows(REQ, OUT, KEY), 0);

        record_request(&log, s.session_id, RequestId::new());
        assert_eq!(log.unpaired_effect_request_rows(REQ, OUT, KEY), 1);
    }
}
