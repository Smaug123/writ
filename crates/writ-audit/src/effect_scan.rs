//! Boot-time scan for brokered-effect request rows with no matching outcome.
//!
//! The "complete by construction" invariant is that no brokered effect happens
//! without a durable `(request, outcome)` audit pair. The two-phase guard
//! ([`crate::EffectAuditTable`]) enforces the pairing while the process is alive;
//! this module is the **durable backstop** for the one window the guard cannot
//! close: a stop *between* the request-row commit and the outcome write — a hard
//! crash, or a handler that deliberately leaves the row for reconciliation (the
//! git-push staging-IO failure). A boot-time scan flags any such row so an
//! operator (or a table's own recovery sweep) can resolve it; the scan itself
//! only *reports* — it never fabricates an outcome (no table can always express a
//! truthful "incomplete" outcome, and a fabricated row corrupts the log worse
//! than a missing one).
//!
//! The scan is table-name based (the same `LEFT JOIN` the Stage-0 oracle uses),
//! so one query covers every pair regardless of column shape. The alerting lives
//! in the `writ` crate's boot sequence (this crate has no `tracing` dependency by
//! design); here we only compute the findings.

use crate::{AuditError, AuditLog};

/// One brokered-effect `(request, outcome)` table pair the boot scan ranges over.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EffectAuditPair {
    /// Diagnostic label (matches the pair's `EffectAuditTable::LABEL`).
    pub label: &'static str,
    /// `*_request` table name.
    pub request_table: &'static str,
    /// `*_outcome` table name.
    pub outcome_table: &'static str,
    /// The key column both rows share (`request_id` / `push_request_id`).
    pub join_column: &'static str,
}

/// Every effect table pair whose semantics make "a request row with no outcome"
/// mean a *dangling* effect — the request and outcome are both written within one
/// short-lived operation, so an unpaired row at boot is a stop mid-effect.
///
/// `agent_run` is deliberately **excluded**: it is outcome-only, its request row
/// is minted at run *launch* and its outcome arrives at run *completion*, so an
/// unpaired `agent_run` row is a run still in flight (or one whose outcome upload
/// was rejected and may be retried — see
/// [`AbandonableEffect`](crate::AbandonableEffect) on that table), not a lost
/// write; scanning it would false-positive on every live run. Its reconciliation
/// is a concern of the agent-run lifecycle. The host mint (`request` /
/// `grant_log`) is likewise not a simple `(request, outcome)` pair and is out of
/// scope.
///
/// Keep this list in step with the schema's `*_request` / `*_outcome` pairs; the
/// `effect_audit_pairs_match_the_schema` test fails if a pair is added to the
/// schema without being listed here (or vice versa).
pub const EFFECT_AUDIT_PAIRS: &[EffectAuditPair] = &[
    EffectAuditPair {
        label: "Claude proxy",
        request_table: "claude_proxy_request",
        outcome_table: "claude_proxy_outcome",
        join_column: "request_id",
    },
    EffectAuditPair {
        label: "OpenAI proxy",
        request_table: "openai_proxy_request",
        outcome_table: "openai_proxy_outcome",
        join_column: "request_id",
    },
    EffectAuditPair {
        label: "Nix cache",
        request_table: "nix_cache_request",
        outcome_table: "nix_cache_outcome",
        join_column: "request_id",
    },
    EffectAuditPair {
        label: "Flake provision",
        request_table: "flake_provision_request",
        outcome_table: "flake_provision_outcome",
        join_column: "request_id",
    },
    EffectAuditPair {
        label: "Git push",
        request_table: "git_push_request",
        outcome_table: "git_push_outcome",
        join_column: "push_request_id",
    },
];

/// One scan finding: an effect table with `count` request rows lacking an
/// outcome. Only non-empty findings are returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnpairedEffectRows {
    /// Diagnostic label from the pair's [`EffectAuditPair::label`].
    pub label: &'static str,
    /// The `*_request` table the unpaired rows are in.
    pub request_table: &'static str,
    /// How many request rows have no matching outcome row.
    pub count: u64,
}

impl AuditLog {
    /// Count request rows in one effect table pair that have no matching outcome
    /// row on `join_column`. Zero means every request in that table is paired.
    ///
    /// `request_table`, `outcome_table`, and `join_column` are trusted
    /// crate-internal identifiers (the same `&'static str`s the DAOs interpolate
    /// into SQL), never guest input; the query binds no parameters.
    pub fn count_unpaired_effect_request_rows(
        &self,
        request_table: &str,
        outcome_table: &str,
        join_column: &str,
    ) -> Result<u64, AuditError> {
        let sql = format!(
            "SELECT COUNT(*) FROM {request_table} r
             LEFT JOIN {outcome_table} o ON o.{join_column} = r.{join_column}
             WHERE o.{join_column} IS NULL",
        );
        self.with_conn(|c| {
            let count: i64 = c.query_row(&sql, [], |row| row.get(0))?;
            Ok(count as u64)
        })
    }

    /// Scan every [`EFFECT_AUDIT_PAIRS`] table for request rows with no matching
    /// outcome, returning only the non-empty findings. The durable backstop for
    /// the audit-pair invariant; the caller alerts on and/or reconciles the
    /// findings (this only reports).
    pub fn scan_unpaired_effect_rows(&self) -> Result<Vec<UnpairedEffectRows>, AuditError> {
        let mut findings = Vec::new();
        for pair in EFFECT_AUDIT_PAIRS {
            let count = self.count_unpaired_effect_request_rows(
                pair.request_table,
                pair.outcome_table,
                pair.join_column,
            )?;
            if count > 0 {
                findings.push(UnpairedEffectRows {
                    label: pair.label,
                    request_table: pair.request_table,
                    count,
                });
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claude_proxy::{
        ClaudeProxyAuditDecision, ClaudeProxyAuditRoute, ClaudeProxyOutcomeRecord,
        ClaudeProxyRequestRecord,
    };
    use crate::test_support::sample_session;
    use std::collections::BTreeSet;
    use writ_core::core::{RequestId, SessionId, UnixMillis};

    fn record_request(log: &AuditLog, session_id: SessionId, request_id: RequestId) {
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

    #[test]
    fn count_is_zero_for_a_complete_pair_and_one_for_a_dangling_request() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let paired = RequestId::new();
        record_request(&log, s.session_id, paired);
        record_outcome(&log, paired);
        assert_eq!(
            log.count_unpaired_effect_request_rows(
                "claude_proxy_request",
                "claude_proxy_outcome",
                "request_id",
            )
            .unwrap(),
            0,
        );

        // A request row with no outcome — the dangling effect the scan exists to
        // catch.
        record_request(&log, s.session_id, RequestId::new());
        assert_eq!(
            log.count_unpaired_effect_request_rows(
                "claude_proxy_request",
                "claude_proxy_outcome",
                "request_id",
            )
            .unwrap(),
            1,
        );
    }

    #[test]
    fn scan_reports_only_tables_with_dangling_rows() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        // All paired: nothing to report.
        let paired = RequestId::new();
        record_request(&log, s.session_id, paired);
        record_outcome(&log, paired);
        assert!(log.scan_unpaired_effect_rows().unwrap().is_empty());

        // One dangling Claude-proxy request: reported once, keyed to that table.
        record_request(&log, s.session_id, RequestId::new());
        let findings = log.scan_unpaired_effect_rows().unwrap();
        assert_eq!(
            findings,
            vec![UnpairedEffectRows {
                label: "Claude proxy",
                request_table: "claude_proxy_request",
                count: 1,
            }],
        );
    }

    /// The hard-coded [`EFFECT_AUDIT_PAIRS`] list must match exactly the schema's
    /// `<x>_request` / `<x>_outcome` table pairs, so a new effect pair added to
    /// the schema without being listed here (or a removed/renamed table) fails the
    /// build rather than silently escaping the boot scan. `agent_run` is excluded
    /// on purpose — it is named `agent_run` / `agent_run_outcome`, not
    /// `<x>_request` / `<x>_outcome`, so the naming heuristic already skips it.
    #[test]
    fn effect_audit_pairs_match_the_schema() {
        let log = AuditLog::open_in_memory().unwrap();
        let table_names: BTreeSet<String> = log
            .with_conn(|c| {
                let mut stmt = c.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?;
                let names = stmt
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<BTreeSet<_>, _>>()?;
                Ok(names)
            })
            .unwrap();

        // The schema's `(request, outcome)` pairs, by the `<x>_request` +
        // `<x>_outcome` naming convention.
        let schema_pairs: BTreeSet<&str> = table_names
            .iter()
            .filter_map(|name| name.strip_suffix("_request"))
            .filter(|stem| table_names.contains(&format!("{stem}_outcome")))
            .collect();

        let listed_stems: BTreeSet<&str> = EFFECT_AUDIT_PAIRS
            .iter()
            .map(|pair| {
                pair.request_table
                    .strip_suffix("_request")
                    .expect("request_table ends in _request")
            })
            .collect();

        assert_eq!(
            listed_stems, schema_pairs,
            "EFFECT_AUDIT_PAIRS is out of step with the schema's request/outcome table pairs",
        );

        // Every listed pair's tables and join column really exist.
        for pair in EFFECT_AUDIT_PAIRS {
            for table in [pair.request_table, pair.outcome_table] {
                assert!(
                    table_names.contains(table),
                    "{} names a table {table:?} that is not in the schema",
                    pair.label,
                );
            }
            let has_join_column = log
                .with_conn(|c| {
                    let sql = format!(
                        "SELECT COUNT(*) FROM pragma_table_info('{}') WHERE name = ?1",
                        pair.request_table
                    );
                    let count: i64 = c.query_row(&sql, [pair.join_column], |row| row.get(0))?;
                    Ok(count)
                })
                .unwrap();
            assert_eq!(
                has_join_column, 1,
                "{}: join column {:?} is not in {:?}",
                pair.label, pair.join_column, pair.request_table,
            );
        }
    }
}
