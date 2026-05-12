//! Plan submission audit DAO. One row per planner-run plan body, per
//! `docs/plans/2026-05-11-agent-plans.md`. Reviews, decisions, addenda,
//! and aborts are deferred to later slices; this module persists only
//! the plan itself.

use rusqlite::{OptionalExtension, Row, params};

use super::validation::validate_sha256_hex;
use super::{AuditError, AuditLog};
use crate::agent_plan::{PlanBody, PlanBodyError, PlanId};
use crate::agent_run::AgentRunId;
use crate::core::{SessionId, UnixMillis};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanSubmissionRecord {
    pub plan_id: PlanId,
    pub agent_run_id: AgentRunId,
    pub submitted_at: UnixMillis,
    pub body: PlanBody,
}

impl AuditLog {
    /// Persist one plan body against its planner [`AgentRunId`]. The
    /// row's `body_sha256` is computed here from the [`PlanBody`] so
    /// callers cannot disagree with the DB about the digest. The schema
    /// enforces `UNIQUE(agent_run_id)`: a second plan against the same
    /// planner run surfaces as `AuditError::Sqlite` from the UNIQUE
    /// violation rather than a soft retry.
    pub fn record_plan_submission(&self, r: &PlanSubmissionRecord) -> Result<(), AuditError> {
        let body_sha256 = r.body.sha256_hex();

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let agent_run: Option<(String, Option<i64>)> = tx
                .query_row(
                    "SELECT ar.session_id, s.closed_at
                     FROM agent_run ar
                     JOIN session s ON s.session_id = ar.session_id
                     WHERE ar.run_id = ?1",
                    params![r.agent_run_id.as_uuid().to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            match agent_run {
                None => return Err(AuditError::Invariant("agent run does not exist")),
                Some((_, Some(_))) => return Err(AuditError::Invariant("session is closed")),
                Some((_, None)) => {}
            }

            tx.execute(
                "INSERT INTO plan (
                     plan_id,
                     agent_run_id,
                     submitted_at,
                     body,
                     body_sha256
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    r.plan_id.as_uuid().to_string(),
                    r.agent_run_id.as_uuid().to_string(),
                    r.submitted_at.as_millis(),
                    r.body.as_str(),
                    &body_sha256,
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn get_plan(&self, plan_id: PlanId) -> Result<Option<PlanSubmissionRecord>, AuditError> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT plan_id, agent_run_id, submitted_at, body, body_sha256
                     FROM plan
                     WHERE plan_id = ?1",
                    params![plan_id.as_uuid().to_string()],
                    plan_from_row,
                )
                .optional()?;
            row.transpose()
        })
    }

    /// Plans for a session, ordered by submission time. Joins through
    /// `agent_run.session_id` since plans don't carry session_id
    /// directly. Ties broken by `rowid` for a stable order matching
    /// insert order within a single millisecond.
    pub fn list_plans_for_session(
        &self,
        session_id: SessionId,
    ) -> Result<Vec<PlanSubmissionRecord>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT p.plan_id, p.agent_run_id, p.submitted_at, p.body, p.body_sha256
                 FROM plan p
                 JOIN agent_run ar ON ar.run_id = p.agent_run_id
                 WHERE ar.session_id = ?1
                 ORDER BY p.submitted_at ASC, p.rowid ASC",
            )?;
            let rows = stmt
                .query_map(
                    params![session_id.as_uuid().to_string()],
                    plan_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }
}

fn plan_from_row(row: &Row<'_>) -> rusqlite::Result<Result<PlanSubmissionRecord, AuditError>> {
    let plan_id_str: String = row.get(0)?;
    let agent_run_id_str: String = row.get(1)?;
    let submitted_at: i64 = row.get(2)?;
    let body_text: String = row.get(3)?;
    let body_sha256: String = row.get(4)?;

    let parse = || -> Result<PlanSubmissionRecord, AuditError> {
        let plan_id = uuid::Uuid::parse_str(&plan_id_str)
            .map_err(|_| AuditError::Invariant("plan row: plan_id not a uuid"))?;
        let agent_run_id = uuid::Uuid::parse_str(&agent_run_id_str)
            .map_err(|_| AuditError::Invariant("plan row: agent_run_id not a uuid"))?;
        validate_sha256_hex(&body_sha256, "plan body sha256")?;
        let body = PlanBody::try_new(body_text).map_err(|e| match e {
            PlanBodyError::Empty => AuditError::Invariant("plan row: body is empty"),
            PlanBodyError::TooLarge { .. } => {
                AuditError::Invariant("plan row: body exceeds size limit")
            }
        })?;
        // belt-and-braces: the stored sha must match a fresh recompute
        // of the body bytes. If they disagree the row was tampered with.
        if body.sha256_hex() != body_sha256 {
            return Err(AuditError::Invariant(
                "plan row: body_sha256 does not match body",
            ));
        }
        Ok(PlanSubmissionRecord {
            plan_id: PlanId::from_uuid(plan_id),
            agent_run_id: AgentRunId::from_uuid(agent_run_id),
            submitted_at: UnixMillis::from_millis(submitted_at),
            body,
        })
    };
    Ok(parse())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_run::AgentPrompt;
    use crate::audit::test_support::sample_session;
    use crate::audit::{AgentRunAuditRecord, AuditError};
    use crate::core::AgentKind;
    use rusqlite::params;

    fn sample_planner_run(log: &AuditLog, session_id: SessionId) -> AgentRunId {
        let run_id = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id,
            session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: AgentPrompt::new("plan this").summary(),
            correlation_id: None,
        })
        .unwrap();
        run_id
    }

    #[test]
    fn plan_submission_roundtrips_against_open_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let run_id = sample_planner_run(&log, s.session_id);

        let plan_id = PlanId::new();
        let body = PlanBody::try_new("# Plan\n\nStep 1: replace bar with baz.").unwrap();
        let record = PlanSubmissionRecord {
            plan_id,
            agent_run_id: run_id,
            submitted_at: UnixMillis::from_millis(1_700_000_200),
            body: body.clone(),
        };

        log.record_plan_submission(&record).unwrap();

        let entry = log.get_plan(plan_id).unwrap().unwrap();
        assert_eq!(entry, record);
        // body_sha256 isn't on PlanSubmissionRecord but is in the DB;
        // verify the stored digest matches the body.
        let stored_sha: String = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT body_sha256 FROM plan WHERE plan_id = ?1",
                    params![plan_id.as_uuid().to_string()],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(stored_sha, body.sha256_hex());
    }

    #[test]
    fn plan_submission_rejects_unknown_agent_run() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let stray_run_id = AgentRunId::new();
        let err = log
            .record_plan_submission(&PlanSubmissionRecord {
                plan_id: PlanId::new(),
                agent_run_id: stray_run_id,
                submitted_at: UnixMillis::from_millis(1_700_000_200),
                body: PlanBody::try_new("# Plan").unwrap(),
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("agent run does not exist")
        ));
    }

    #[test]
    fn plan_submission_rejects_closed_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let run_id = sample_planner_run(&log, s.session_id);
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_150))
            .unwrap();

        let err = log
            .record_plan_submission(&PlanSubmissionRecord {
                plan_id: PlanId::new(),
                agent_run_id: run_id,
                submitted_at: UnixMillis::from_millis(1_700_000_200),
                body: PlanBody::try_new("# Plan").unwrap(),
            })
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant("session is closed")));
    }

    /// The DB trigger `plan_requires_open_session` is the belt-and-braces
    /// gate: bypass the preflight by writing raw SQL while the planner
    /// run's session is closed, and the trigger must still raise.
    #[test]
    fn plan_db_trigger_rejects_direct_insert_against_closed_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let run_id = sample_planner_run(&log, s.session_id);
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_150))
            .unwrap();

        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO plan
                     (plan_id, agent_run_id, submitted_at, body, body_sha256)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        PlanId::new().as_uuid().to_string(),
                        run_id.as_uuid().to_string(),
                        1_700_000_200_i64,
                        "# Plan",
                        crate::agent_run::sha256_hex(b"# Plan"),
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite trigger error, got {err:?}");
        };
        assert!(
            e.to_string().to_lowercase().contains("session is closed"),
            "got: {e}"
        );
    }

    #[test]
    fn plan_submission_rejects_second_plan_for_same_run() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let run_id = sample_planner_run(&log, s.session_id);

        let first = PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: run_id,
            submitted_at: UnixMillis::from_millis(1_700_000_200),
            body: PlanBody::try_new("# Plan A").unwrap(),
        };
        log.record_plan_submission(&first).unwrap();

        let second = PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: run_id,
            submitted_at: UnixMillis::from_millis(1_700_000_300),
            body: PlanBody::try_new("# Plan B").unwrap(),
        };
        let err = log.record_plan_submission(&second).unwrap_err();
        // UNIQUE(agent_run_id) surfaces as Sqlite error.
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite UNIQUE error, got {err:?}");
        };
        assert!(
            e.to_string().to_uppercase().contains("UNIQUE"),
            "got: {e}"
        );
    }

    /// The Rust [`PlanBody`] newtype rejects an empty string at parse
    /// time, so the DAO's caller can't pass one in. The DB CHECK is the
    /// belt-and-braces line of defence against a future code path that
    /// bypasses [`PlanBody::try_new`]: exercise it directly with raw
    /// SQL.
    #[test]
    fn plan_check_constraint_rejects_empty_body() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let run_id = sample_planner_run(&log, s.session_id);
        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO plan
                     (plan_id, agent_run_id, submitted_at, body, body_sha256)
                     VALUES (?1, ?2, ?3, '', ?4)",
                    params![
                        PlanId::new().as_uuid().to_string(),
                        run_id.as_uuid().to_string(),
                        1_700_000_200_i64,
                        crate::agent_run::sha256_hex(b""),
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CHECK"), "got: {msg}");
    }

    /// Mirrors the body CHECK: the digest column has its own
    /// `length(body_sha256) = 64` CHECK. A short digest must be
    /// rejected.
    #[test]
    fn plan_check_constraint_rejects_malformed_body_sha256() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let run_id = sample_planner_run(&log, s.session_id);
        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO plan
                     (plan_id, agent_run_id, submitted_at, body, body_sha256)
                     VALUES (?1, ?2, ?3, '# Plan', 'too short')",
                    params![
                        PlanId::new().as_uuid().to_string(),
                        run_id.as_uuid().to_string(),
                        1_700_000_200_i64,
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CHECK"), "got: {msg}");
    }

    #[test]
    fn list_plans_for_session_filters_and_orders() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let other_session = {
            let mut s2 = sample_session();
            s2.label = Some("other".into());
            log.open_session(&s2).unwrap();
            s2.session_id
        };

        let run_a = sample_planner_run(&log, s.session_id);
        let run_b = sample_planner_run(&log, s.session_id);
        let run_c = sample_planner_run(&log, other_session);

        let plan_a = PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: run_a,
            submitted_at: UnixMillis::from_millis(1_700_000_300),
            body: PlanBody::try_new("# Plan A").unwrap(),
        };
        let plan_b = PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: run_b,
            submitted_at: UnixMillis::from_millis(1_700_000_200),
            body: PlanBody::try_new("# Plan B").unwrap(),
        };
        let plan_c = PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: run_c,
            submitted_at: UnixMillis::from_millis(1_700_000_400),
            body: PlanBody::try_new("# Plan C").unwrap(),
        };
        log.record_plan_submission(&plan_a).unwrap();
        log.record_plan_submission(&plan_b).unwrap();
        log.record_plan_submission(&plan_c).unwrap();

        let plans = log.list_plans_for_session(s.session_id).unwrap();
        assert_eq!(plans, vec![plan_b.clone(), plan_a.clone()]);
        // The other session sees only its own plan.
        let other_plans = log.list_plans_for_session(other_session).unwrap();
        assert_eq!(other_plans, vec![plan_c]);
    }
}
