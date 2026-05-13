//! Plan submission audit DAO. One row per planner-run plan body, per
//! `docs/plans/2026-05-11-agent-plans.md`. Reviews, decisions, addenda,
//! and aborts are deferred to later slices; this module persists only
//! the plan itself.

use rusqlite::{OptionalExtension, Row, params};

use super::validation::validate_sha256_hex;
use super::{AuditError, AuditLog};
use crate::agent_plan::{
    AddendumId, CorrelationId, Decider, DecisionOutcome, PlanBody, PlanBodyError, PlanFeedback,
    PlanFeedbackError, PlanId, ReviewId, Verdict,
};
use crate::agent_run::AgentRunId;
use crate::core::{SessionId, UnixMillis};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanSubmissionRecord {
    pub plan_id: PlanId,
    pub agent_run_id: AgentRunId,
    pub submitted_at: UnixMillis,
    pub body: PlanBody,
}

/// One terminal `plan_decision` row. Per §"Plan lifecycle" exactly one
/// of these exists per plan: `Accepted` unlocks the implementer and
/// `RejectedRestart` closes the plan. The PRIMARY KEY on `plan_id`
/// enforces the at-most-one invariant at the DB level — a second
/// `record_plan_decision` against the same plan surfaces as a UNIQUE
/// constraint violation rather than silently overwriting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanDecisionRecord {
    pub plan_id: PlanId,
    pub decided_at: UnixMillis,
    pub outcome: DecisionOutcome,
    pub decider: Decider,
}

/// One `plan_review` row: a reviewer agent run posting a verdict (and
/// optionally feedback) against a plan. Per §"Plan lifecycle" a plan
/// may carry zero or more reviews; each reviewer run is responsible for
/// at most one row, enforced by `UNIQUE(agent_run_id)` at the schema
/// level. The DAO stores the `feedback_sha256` derived from the
/// [`PlanFeedback`] body so consumers cannot disagree with the DB about
/// the digest of what was recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanReviewRecord {
    pub review_id: ReviewId,
    pub plan_id: PlanId,
    pub agent_run_id: AgentRunId,
    pub submitted_at: UnixMillis,
    pub verdict: Verdict,
    pub feedback: Option<PlanFeedback>,
}

/// One `plan_addendum` row: an executor agent run posting a follow-up
/// addendum against an accepted plan. Per §"Plan lifecycle" a plan may
/// carry zero or more addenda after acceptance; each executor run is
/// responsible for at most one row, enforced by `UNIQUE(agent_run_id)`
/// at the schema level. The DAO stores `body_sha256` derived from the
/// [`PlanBody`] so consumers cannot disagree with the DB about the
/// digest of what was recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAddendumRecord {
    pub addendum_id: AddendumId,
    pub plan_id: PlanId,
    pub agent_run_id: AgentRunId,
    pub submitted_at: UnixMillis,
    pub body: PlanBody,
}

/// Body-less summary returned by [`AuditLog::list_plans`]. The listing
/// is intended for triage — operators want to see what plans exist and
/// which task they belong to without paying to load up to 256 KiB of
/// markdown for each row.
///
/// `correlation_id` is the value carried on the planner's `agent_run`
/// row (joined here so the summary is self-contained). Plans whose
/// planner run was not tagged surface `None`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanListEntry {
    pub plan_id: PlanId,
    pub agent_run_id: AgentRunId,
    pub correlation_id: Option<CorrelationId>,
    pub submitted_at: UnixMillis,
    pub body_sha256: String,
    pub body_bytes: u64,
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
                .query_map(params![session_id.as_uuid().to_string()], plan_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }

    /// Triage view across every plan in the log, joined with
    /// `agent_run.correlation_id`. When `filter` is `Some`, only plans
    /// whose planner run carries the same correlation id are returned;
    /// when `None`, every plan is returned. Order is `(submitted_at,
    /// rowid)` so ties within a millisecond stay stable.
    ///
    /// Body bytes are taken from `length(cast(body AS BLOB))` so the
    /// count matches the v16 byte-length CHECK rather than the
    /// character count `length(body)` would return for non-ASCII text.
    /// The body itself is never loaded; the listing stays cheap even
    /// for a 256 KiB body.
    pub fn list_plans(
        &self,
        filter: Option<&CorrelationId>,
    ) -> Result<Vec<PlanListEntry>, AuditError> {
        // Two SQL strings rather than one with an OR over filter
        // because `?1 IS NULL OR correlation_id = ?1` makes the
        // optimiser scan the join unnecessarily. The split is also
        // easier to read.
        self.with_conn(|c| {
            let rows: Vec<rusqlite::Result<Result<PlanListEntry, AuditError>>> = match filter {
                None => {
                    let mut stmt = c.prepare(
                        "SELECT p.plan_id, p.agent_run_id, ar.correlation_id,
                                p.submitted_at, p.body_sha256,
                                length(cast(p.body AS BLOB))
                         FROM plan p
                         JOIN agent_run ar ON ar.run_id = p.agent_run_id
                         ORDER BY p.submitted_at ASC, p.rowid ASC",
                    )?;
                    stmt.query_map([], plan_list_entry_from_row)?.collect()
                }
                Some(correlation_id) => {
                    let mut stmt = c.prepare(
                        "SELECT p.plan_id, p.agent_run_id, ar.correlation_id,
                                p.submitted_at, p.body_sha256,
                                length(cast(p.body AS BLOB))
                         FROM plan p
                         JOIN agent_run ar ON ar.run_id = p.agent_run_id
                         WHERE ar.correlation_id = ?1
                         ORDER BY p.submitted_at ASC, p.rowid ASC",
                    )?;
                    stmt.query_map(params![correlation_id.as_str()], plan_list_entry_from_row)?
                        .collect()
                }
            };
            rows.into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
        })
    }

    /// Look up the `correlation_id` of the `agent_run` that submitted
    /// the plan. Returns `Ok(None)` when no `agent_run` row exists with
    /// this id — callers must distinguish "the plan exists but has no
    /// such run" (an invariant violation, since plan rows have a FK
    /// onto `agent_run`) from "the run exists but is untagged" (the
    /// inner `Option<CorrelationId>` being `None`).
    pub fn correlation_id_for_run(
        &self,
        run_id: AgentRunId,
    ) -> Result<Option<Option<CorrelationId>>, AuditError> {
        self.with_conn(|c| {
            let raw: Option<Option<String>> = c
                .query_row(
                    "SELECT correlation_id FROM agent_run WHERE run_id = ?1",
                    params![run_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            match raw {
                None => Ok(None),
                Some(None) => Ok(Some(None)),
                Some(Some(value)) => CorrelationId::try_new(value)
                    .map(|c| Some(Some(c)))
                    .map_err(|_| AuditError::Invariant("agent run row: correlation_id is invalid")),
            }
        })
    }

    /// Record one terminal `plan_decision` row. The plan must exist;
    /// pre-check it in the same transaction so a missing plan surfaces
    /// as a clean `AuditError::Invariant("plan does not exist")` rather
    /// than a raw "FOREIGN KEY constraint failed" message.
    ///
    /// A second decision against the same plan returns the underlying
    /// SQLite UNIQUE constraint error (the PRIMARY KEY on `plan_id`);
    /// the server layer maps that to `PlanAlreadyDecided` on the wire
    /// via `is_unique_constraint_violation`.
    ///
    /// Unlike plan submission, the decision is *not* gated by the
    /// planner's session being open: operator decisions are
    /// deliberately cross-session. See migration 17's commentary.
    pub fn record_plan_decision(&self, r: &PlanDecisionRecord) -> Result<(), AuditError> {
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let plan_exists: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM plan WHERE plan_id = ?1",
                    params![r.plan_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if plan_exists.is_none() {
                return Err(AuditError::Invariant("plan does not exist"));
            }
            tx.execute(
                "INSERT INTO plan_decision (
                     plan_id,
                     decided_at,
                     outcome,
                     decider
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    r.plan_id.as_uuid().to_string(),
                    r.decided_at.as_millis(),
                    r.outcome.as_str(),
                    r.decider.as_str(),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Look up the decision for one plan, if any. Returns `Ok(None)`
    /// for "plan exists but is not yet decided" (the planner ran and
    /// the operator hasn't acted) and for "plan does not exist"
    /// — callers distinguish those via `get_plan` if they need to.
    pub fn get_plan_decision(
        &self,
        plan_id: PlanId,
    ) -> Result<Option<PlanDecisionRecord>, AuditError> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT plan_id, decided_at, outcome, decider
                     FROM plan_decision
                     WHERE plan_id = ?1",
                    params![plan_id.as_uuid().to_string()],
                    plan_decision_from_row,
                )
                .optional()?;
            row.transpose()
        })
    }

    /// Record one `plan_review` row. The plan and reviewer run are
    /// pre-checked in the same transaction so callers get a clean
    /// `AuditError::Invariant` for either missing referent rather than
    /// a raw "FOREIGN KEY constraint failed" string.
    ///
    /// Stage and session gating are belt-and-braces: the broker route
    /// enforces them up front, this pre-check restates them for a
    /// readable error, and the v20 triggers
    /// (`plan_review_requires_reviewer_stage`,
    /// `plan_review_requires_open_session`) catch any raw INSERT that
    /// bypasses both layers.
    ///
    /// A second review from the same reviewer run surfaces as the
    /// underlying SQLite UNIQUE constraint error (the
    /// `UNIQUE(agent_run_id)` clause); callers map that to a wire-side
    /// `PlanReviewAlreadyRecorded` (or equivalent) outcome.
    ///
    /// The `feedback_sha256` column is computed here from the
    /// [`PlanFeedback`] body so storage and digest cannot disagree;
    /// `feedback` and `feedback_sha256` go in together or stay
    /// `NULL` together, mirroring the table-level CHECK.
    pub fn record_plan_review(&self, r: &PlanReviewRecord) -> Result<(), AuditError> {
        let feedback_sha256 = r.feedback.as_ref().map(|f| f.sha256_hex());

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;

            let plan_exists: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM plan WHERE plan_id = ?1",
                    params![r.plan_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if plan_exists.is_none() {
                return Err(AuditError::Invariant("plan does not exist"));
            }

            let agent_run: Option<(String, Option<i64>, String, Option<String>)> = tx
                .query_row(
                    "SELECT ar.session_id, s.closed_at, ar.stage, ar.read_plan_id
                     FROM agent_run ar
                     JOIN session s ON s.session_id = ar.session_id
                     WHERE ar.run_id = ?1",
                    params![r.agent_run_id.as_uuid().to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let plan_id_str = r.plan_id.as_uuid().to_string();
            match agent_run {
                None => return Err(AuditError::Invariant("agent run does not exist")),
                Some((_, Some(_), _, _)) => {
                    return Err(AuditError::Invariant("session is closed"));
                }
                Some((_, None, ref stage, _)) if stage != "review" => {
                    return Err(AuditError::Invariant(
                        "plan_review requires agent_run.stage = 'review'",
                    ));
                }
                // The route contract (`docs/plans/2026-05-11-agent-plans.md`)
                // requires `run.read_plan_id = <plan_id>`; restate it here
                // so a reviewer that read plan A cannot attach a verdict
                // to plan B (and so the failure mode is a typed audit
                // error rather than a corrupt cross-plan row reaching
                // the table). The matching trigger is the last line of
                // defence against a raw INSERT.
                Some((_, None, _, ref read_plan_id))
                    if read_plan_id.as_deref() != Some(&plan_id_str) =>
                {
                    return Err(AuditError::Invariant(
                        "plan_review requires agent_run.read_plan_id = plan_id",
                    ));
                }
                Some(_) => {}
            }

            tx.execute(
                "INSERT INTO plan_review (
                     review_id,
                     plan_id,
                     agent_run_id,
                     submitted_at,
                     verdict,
                     feedback,
                     feedback_sha256
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    r.review_id.as_uuid().to_string(),
                    r.plan_id.as_uuid().to_string(),
                    r.agent_run_id.as_uuid().to_string(),
                    r.submitted_at.as_millis(),
                    r.verdict.as_str(),
                    r.feedback.as_ref().map(|f| f.as_str()),
                    feedback_sha256.as_deref(),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Look up one review by `review_id`. Returns `Ok(None)` if no row
    /// with that id exists.
    pub fn get_plan_review(
        &self,
        review_id: ReviewId,
    ) -> Result<Option<PlanReviewRecord>, AuditError> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT review_id, plan_id, agent_run_id, submitted_at,
                            verdict, feedback, feedback_sha256
                     FROM plan_review
                     WHERE review_id = ?1",
                    params![review_id.as_uuid().to_string()],
                    plan_review_from_row,
                )
                .optional()?;
            row.transpose()
        })
    }

    /// List every review attached to one plan, oldest first. `rowid`
    /// breaks ties on `submitted_at` so the order is stable across
    /// repeated reads even when two reviewers post in the same
    /// millisecond.
    pub fn list_plan_reviews_for_plan(
        &self,
        plan_id: PlanId,
    ) -> Result<Vec<PlanReviewRecord>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT review_id, plan_id, agent_run_id, submitted_at,
                        verdict, feedback, feedback_sha256
                 FROM plan_review
                 WHERE plan_id = ?1
                 ORDER BY submitted_at, rowid",
            )?;
            let rows =
                stmt.query_map(params![plan_id.as_uuid().to_string()], plan_review_from_row)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row??);
            }
            Ok(out)
        })
    }

    /// Record one `plan_addendum` row. The plan, the executor agent run,
    /// and the accepted-decision precondition are pre-checked in the
    /// same transaction so callers see a typed `AuditError::Invariant`
    /// for each failure mode rather than a raw "FOREIGN KEY constraint
    /// failed" or trigger-message string.
    ///
    /// Stage, session, read-plan binding, and the "decision must be
    /// accepted" rule are belt-and-braces: the broker route enforces
    /// them up front, this pre-check restates them for readable errors,
    /// and the v2 triggers (`plan_addendum_requires_open_session`,
    /// `plan_addendum_requires_executor_run`,
    /// `plan_addendum_requires_accepted_decision`) catch any raw INSERT
    /// that bypasses both layers.
    ///
    /// A second addendum from the same executor run surfaces as the
    /// underlying SQLite UNIQUE constraint error (the
    /// `UNIQUE(agent_run_id)` clause); callers may map that to a
    /// wire-side "addendum already recorded" outcome.
    ///
    /// The `body_sha256` column is computed here from the [`PlanBody`]
    /// so storage and digest cannot disagree.
    pub fn record_plan_addendum(&self, r: &PlanAddendumRecord) -> Result<(), AuditError> {
        let body_sha256 = r.body.sha256_hex();

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;

            let plan_exists: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM plan WHERE plan_id = ?1",
                    params![r.plan_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if plan_exists.is_none() {
                return Err(AuditError::Invariant("plan does not exist"));
            }

            // Addenda only apply to accepted plans. The route gate
            // enforces this for clean errors; restate it here so a
            // direct DAO caller (e.g. a backfill) gets a typed
            // invariant rather than the trigger's raw message.
            let accepted: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM plan_decision
                     WHERE plan_id = ?1 AND outcome = 'accepted'",
                    params![r.plan_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if accepted.is_none() {
                return Err(AuditError::Invariant(
                    "plan_addendum requires plan_decision.outcome = 'accepted'",
                ));
            }

            let agent_run: Option<(String, Option<i64>, String, Option<String>)> = tx
                .query_row(
                    "SELECT ar.session_id, s.closed_at, ar.stage, ar.read_plan_id
                     FROM agent_run ar
                     JOIN session s ON s.session_id = ar.session_id
                     WHERE ar.run_id = ?1",
                    params![r.agent_run_id.as_uuid().to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let plan_id_str = r.plan_id.as_uuid().to_string();
            match agent_run {
                None => return Err(AuditError::Invariant("agent run does not exist")),
                Some((_, Some(_), _, _)) => {
                    return Err(AuditError::Invariant("session is closed"));
                }
                Some((_, None, ref stage, _)) if stage != "execute" => {
                    return Err(AuditError::Invariant(
                        "plan_addendum requires agent_run.stage = 'execute'",
                    ));
                }
                // The route contract requires `run.read_plan_id =
                // <plan_id>`; restate it here so an executor that read
                // plan A cannot attach an addendum to plan B. The
                // matching trigger is the last line of defence against
                // a raw INSERT.
                Some((_, None, _, ref read_plan_id))
                    if read_plan_id.as_deref() != Some(&plan_id_str) =>
                {
                    return Err(AuditError::Invariant(
                        "plan_addendum requires agent_run.read_plan_id = plan_id",
                    ));
                }
                Some(_) => {}
            }

            tx.execute(
                "INSERT INTO plan_addendum (
                     addendum_id,
                     plan_id,
                     agent_run_id,
                     submitted_at,
                     body,
                     body_sha256
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    r.addendum_id.as_uuid().to_string(),
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

    /// Look up one addendum by `addendum_id`. Returns `Ok(None)` if no
    /// row with that id exists.
    pub fn get_plan_addendum(
        &self,
        addendum_id: AddendumId,
    ) -> Result<Option<PlanAddendumRecord>, AuditError> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT addendum_id, plan_id, agent_run_id, submitted_at,
                            body, body_sha256
                     FROM plan_addendum
                     WHERE addendum_id = ?1",
                    params![addendum_id.as_uuid().to_string()],
                    plan_addendum_from_row,
                )
                .optional()?;
            row.transpose()
        })
    }

    /// List every addendum attached to one plan, oldest first. `rowid`
    /// breaks ties on `submitted_at` so the order is stable across
    /// repeated reads even when two addenda land in the same
    /// millisecond.
    pub fn list_plan_addenda_for_plan(
        &self,
        plan_id: PlanId,
    ) -> Result<Vec<PlanAddendumRecord>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT addendum_id, plan_id, agent_run_id, submitted_at,
                        body, body_sha256
                 FROM plan_addendum
                 WHERE plan_id = ?1
                 ORDER BY submitted_at, rowid",
            )?;
            let rows = stmt.query_map(
                params![plan_id.as_uuid().to_string()],
                plan_addendum_from_row,
            )?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row??);
            }
            Ok(out)
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
            PlanBodyError::EmbeddedNul => {
                AuditError::Invariant("plan row: body contains embedded NUL")
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

fn plan_decision_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<Result<PlanDecisionRecord, AuditError>> {
    let plan_id_str: String = row.get(0)?;
    let decided_at: i64 = row.get(1)?;
    let outcome_str: String = row.get(2)?;
    let decider_str: String = row.get(3)?;

    let parse = || -> Result<PlanDecisionRecord, AuditError> {
        let plan_id = uuid::Uuid::parse_str(&plan_id_str)
            .map_err(|_| AuditError::Invariant("plan_decision row: plan_id not a uuid"))?;
        let outcome = outcome_str.parse::<DecisionOutcome>().map_err(|_| {
            AuditError::Invariant("plan_decision row: outcome is not a known wire string")
        })?;
        let decider = Decider::try_new(decider_str)
            .map_err(|_| AuditError::Invariant("plan_decision row: decider violates invariants"))?;
        Ok(PlanDecisionRecord {
            plan_id: PlanId::from_uuid(plan_id),
            decided_at: UnixMillis::from_millis(decided_at),
            outcome,
            decider,
        })
    };
    Ok(parse())
}

fn plan_review_from_row(row: &Row<'_>) -> rusqlite::Result<Result<PlanReviewRecord, AuditError>> {
    let review_id_str: String = row.get(0)?;
    let plan_id_str: String = row.get(1)?;
    let agent_run_id_str: String = row.get(2)?;
    let submitted_at: i64 = row.get(3)?;
    let verdict_str: String = row.get(4)?;
    let feedback_str: Option<String> = row.get(5)?;
    let feedback_sha256: Option<String> = row.get(6)?;

    let parse = || -> Result<PlanReviewRecord, AuditError> {
        let review_id = uuid::Uuid::parse_str(&review_id_str)
            .map_err(|_| AuditError::Invariant("plan_review row: review_id not a uuid"))?;
        let plan_id = uuid::Uuid::parse_str(&plan_id_str)
            .map_err(|_| AuditError::Invariant("plan_review row: plan_id not a uuid"))?;
        let agent_run_id = uuid::Uuid::parse_str(&agent_run_id_str)
            .map_err(|_| AuditError::Invariant("plan_review row: agent_run_id not a uuid"))?;
        let verdict = verdict_str.parse::<Verdict>().map_err(|_| {
            AuditError::Invariant("plan_review row: verdict is not a known wire string")
        })?;
        let feedback = match (feedback_str, feedback_sha256.as_deref()) {
            (None, None) => None,
            (Some(body), Some(stored_sha)) => {
                validate_sha256_hex(stored_sha, "plan_review feedback sha256")?;
                let parsed = PlanFeedback::try_new(body).map_err(|e| match e {
                    PlanFeedbackError::Empty => {
                        AuditError::Invariant("plan_review row: feedback is empty")
                    }
                    PlanFeedbackError::TooLarge { .. } => {
                        AuditError::Invariant("plan_review row: feedback exceeds size limit")
                    }
                    PlanFeedbackError::EmbeddedNul => {
                        AuditError::Invariant("plan_review row: feedback contains an embedded NUL")
                    }
                })?;
                // Belt-and-braces: the stored digest must agree with a
                // fresh recompute over the feedback bytes. A disagreement
                // means the row was tampered with after insertion.
                if parsed.sha256_hex() != stored_sha {
                    return Err(AuditError::Invariant(
                        "plan_review row: feedback_sha256 does not match feedback",
                    ));
                }
                Some(parsed)
            }
            _ => {
                return Err(AuditError::Invariant(
                    "plan_review row: feedback and feedback_sha256 must both be NULL or both be non-NULL",
                ));
            }
        };
        Ok(PlanReviewRecord {
            review_id: ReviewId::from_uuid(review_id),
            plan_id: PlanId::from_uuid(plan_id),
            agent_run_id: AgentRunId::from_uuid(agent_run_id),
            submitted_at: UnixMillis::from_millis(submitted_at),
            verdict,
            feedback,
        })
    };
    Ok(parse())
}

fn plan_addendum_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<Result<PlanAddendumRecord, AuditError>> {
    let addendum_id_str: String = row.get(0)?;
    let plan_id_str: String = row.get(1)?;
    let agent_run_id_str: String = row.get(2)?;
    let submitted_at: i64 = row.get(3)?;
    let body_text: String = row.get(4)?;
    let body_sha256: String = row.get(5)?;

    let parse = || -> Result<PlanAddendumRecord, AuditError> {
        let addendum_id = uuid::Uuid::parse_str(&addendum_id_str)
            .map_err(|_| AuditError::Invariant("plan_addendum row: addendum_id not a uuid"))?;
        let plan_id = uuid::Uuid::parse_str(&plan_id_str)
            .map_err(|_| AuditError::Invariant("plan_addendum row: plan_id not a uuid"))?;
        let agent_run_id = uuid::Uuid::parse_str(&agent_run_id_str)
            .map_err(|_| AuditError::Invariant("plan_addendum row: agent_run_id not a uuid"))?;
        validate_sha256_hex(&body_sha256, "plan_addendum body sha256")?;
        let body = PlanBody::try_new(body_text).map_err(|e| match e {
            PlanBodyError::Empty => AuditError::Invariant("plan_addendum row: body is empty"),
            PlanBodyError::TooLarge { .. } => {
                AuditError::Invariant("plan_addendum row: body exceeds size limit")
            }
            PlanBodyError::EmbeddedNul => {
                AuditError::Invariant("plan_addendum row: body contains embedded NUL")
            }
        })?;
        // Belt-and-braces: the stored digest must agree with a fresh
        // recompute over the body bytes. A disagreement means the row
        // was tampered with after insertion.
        if body.sha256_hex() != body_sha256 {
            return Err(AuditError::Invariant(
                "plan_addendum row: body_sha256 does not match body",
            ));
        }
        Ok(PlanAddendumRecord {
            addendum_id: AddendumId::from_uuid(addendum_id),
            plan_id: PlanId::from_uuid(plan_id),
            agent_run_id: AgentRunId::from_uuid(agent_run_id),
            submitted_at: UnixMillis::from_millis(submitted_at),
            body,
        })
    };
    Ok(parse())
}

fn plan_list_entry_from_row(row: &Row<'_>) -> rusqlite::Result<Result<PlanListEntry, AuditError>> {
    let plan_id_str: String = row.get(0)?;
    let agent_run_id_str: String = row.get(1)?;
    let correlation_id_raw: Option<String> = row.get(2)?;
    let submitted_at: i64 = row.get(3)?;
    let body_sha256: String = row.get(4)?;
    let body_bytes_signed: i64 = row.get(5)?;

    let parse = || -> Result<PlanListEntry, AuditError> {
        let plan_id = uuid::Uuid::parse_str(&plan_id_str)
            .map_err(|_| AuditError::Invariant("plan row: plan_id not a uuid"))?;
        let agent_run_id = uuid::Uuid::parse_str(&agent_run_id_str)
            .map_err(|_| AuditError::Invariant("plan row: agent_run_id not a uuid"))?;
        validate_sha256_hex(&body_sha256, "plan body sha256")?;
        let body_bytes = u64::try_from(body_bytes_signed)
            .map_err(|_| AuditError::Invariant("plan row: body byte count is negative"))?;
        let correlation_id = correlation_id_raw
            .map(CorrelationId::try_new)
            .transpose()
            .map_err(|_| AuditError::Invariant("plan row: agent_run.correlation_id is invalid"))?;
        Ok(PlanListEntry {
            plan_id: PlanId::from_uuid(plan_id),
            agent_run_id: AgentRunId::from_uuid(agent_run_id),
            correlation_id,
            submitted_at: UnixMillis::from_millis(submitted_at),
            body_sha256,
            body_bytes,
        })
    };
    Ok(parse())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_plan::Stage;
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
            stage: Stage::Plan,
            read_plan_id: None,
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
        assert!(e.to_string().to_uppercase().contains("UNIQUE"), "got: {e}");
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

    fn sample_planner_run_with_correlation(
        log: &AuditLog,
        session_id: SessionId,
        correlation_id: Option<CorrelationId>,
    ) -> AgentRunId {
        let run_id = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id,
            session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: AgentPrompt::new("plan this").summary(),
            correlation_id,
            stage: Stage::Plan,
            read_plan_id: None,
        })
        .unwrap();
        run_id
    }

    /// `list_plans` with no filter returns every plan across every
    /// session, ordered by `(submitted_at, rowid)`. The body itself is
    /// not loaded — only the digest and byte count are returned — but
    /// both must match the original [`PlanBody`].
    #[test]
    fn list_plans_returns_every_plan_ordered_by_submitted_at_and_rowid() {
        let log = AuditLog::open_in_memory().unwrap();
        let s1 = sample_session();
        log.open_session(&s1).unwrap();
        let s2 = {
            let mut s = sample_session();
            s.label = Some("other".into());
            log.open_session(&s).unwrap();
            s.session_id
        };
        let run_1 = sample_planner_run(&log, s1.session_id);
        let run_2 = sample_planner_run(&log, s1.session_id);
        let run_3 = sample_planner_run(&log, s2);

        let body_1 = PlanBody::try_new("# Plan one").unwrap();
        let body_2 = PlanBody::try_new("# Plan two").unwrap();
        let body_3 = PlanBody::try_new("# Plan three with a longer body").unwrap();

        log.record_plan_submission(&PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: run_1,
            submitted_at: UnixMillis::from_millis(1_700_000_300),
            body: body_1.clone(),
        })
        .unwrap();
        log.record_plan_submission(&PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: run_2,
            submitted_at: UnixMillis::from_millis(1_700_000_200),
            body: body_2.clone(),
        })
        .unwrap();
        log.record_plan_submission(&PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: run_3,
            submitted_at: UnixMillis::from_millis(1_700_000_400),
            body: body_3.clone(),
        })
        .unwrap();

        let plans = log.list_plans(None).unwrap();
        assert_eq!(plans.len(), 3);
        // Ordered ascending by submitted_at: body_2 (200), body_1 (300), body_3 (400).
        assert_eq!(plans[0].submitted_at.as_millis(), 1_700_000_200);
        assert_eq!(plans[0].body_sha256, body_2.sha256_hex());
        assert_eq!(plans[0].body_bytes, body_2.as_str().len() as u64);
        assert_eq!(plans[1].submitted_at.as_millis(), 1_700_000_300);
        assert_eq!(plans[1].body_sha256, body_1.sha256_hex());
        assert_eq!(plans[2].submitted_at.as_millis(), 1_700_000_400);
        assert_eq!(plans[2].body_sha256, body_3.sha256_hex());
    }

    /// `list_plans(Some(c))` returns only plans whose planner-run row
    /// carries the same correlation id. Untagged runs and runs with a
    /// different correlation id are filtered out.
    #[test]
    fn list_plans_filters_by_correlation_id() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let target = CorrelationId::try_new("feat-42_xyz").unwrap();
        let other = CorrelationId::try_new("feat-7_abc").unwrap();

        let tagged_target =
            sample_planner_run_with_correlation(&log, s.session_id, Some(target.clone()));
        let tagged_other =
            sample_planner_run_with_correlation(&log, s.session_id, Some(other.clone()));
        let untagged = sample_planner_run_with_correlation(&log, s.session_id, None);

        let body_target = PlanBody::try_new("# Plan T").unwrap();
        let body_other = PlanBody::try_new("# Plan O").unwrap();
        let body_untagged = PlanBody::try_new("# Plan U").unwrap();

        let plan_target = PlanId::new();
        log.record_plan_submission(&PlanSubmissionRecord {
            plan_id: plan_target,
            agent_run_id: tagged_target,
            submitted_at: UnixMillis::from_millis(1_700_000_200),
            body: body_target.clone(),
        })
        .unwrap();
        log.record_plan_submission(&PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: tagged_other,
            submitted_at: UnixMillis::from_millis(1_700_000_300),
            body: body_other.clone(),
        })
        .unwrap();
        log.record_plan_submission(&PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: untagged,
            submitted_at: UnixMillis::from_millis(1_700_000_400),
            body: body_untagged.clone(),
        })
        .unwrap();

        let plans = log.list_plans(Some(&target)).unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].plan_id, plan_target);
        assert_eq!(plans[0].correlation_id.as_ref(), Some(&target));
        assert_eq!(plans[0].body_sha256, body_target.sha256_hex());

        // `None` filter still returns all three.
        let all_plans = log.list_plans(None).unwrap();
        assert_eq!(all_plans.len(), 3);
    }

    /// A correlation id with no matching plans returns an empty vec,
    /// not an error.
    #[test]
    fn list_plans_with_unknown_correlation_id_returns_empty() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let run = sample_planner_run(&log, s.session_id);
        log.record_plan_submission(&PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: run,
            submitted_at: UnixMillis::from_millis(1_700_000_200),
            body: PlanBody::try_new("# Plan").unwrap(),
        })
        .unwrap();

        let stranger = CorrelationId::try_new("nope-1").unwrap();
        let plans = log.list_plans(Some(&stranger)).unwrap();
        assert!(plans.is_empty());
    }

    /// Two plans submitted in the same millisecond order by `rowid`,
    /// matching insert order. The list endpoint must agree with
    /// [`AuditLog::list_plans_for_session`] on this tie-break so the
    /// `writ plan list` view doesn't reshuffle on identical timestamps.
    #[test]
    fn list_plans_breaks_submitted_at_ties_by_rowid() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let run_a = sample_planner_run(&log, s.session_id);
        let run_b = sample_planner_run(&log, s.session_id);

        let first = PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: run_a,
            submitted_at: UnixMillis::from_millis(1_700_000_200),
            body: PlanBody::try_new("# Plan first").unwrap(),
        };
        let second = PlanSubmissionRecord {
            plan_id: PlanId::new(),
            agent_run_id: run_b,
            submitted_at: UnixMillis::from_millis(1_700_000_200),
            body: PlanBody::try_new("# Plan second").unwrap(),
        };
        log.record_plan_submission(&first).unwrap();
        log.record_plan_submission(&second).unwrap();

        let plans = log.list_plans(None).unwrap();
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].plan_id, first.plan_id);
        assert_eq!(plans[1].plan_id, second.plan_id);
    }

    /// `correlation_id_for_run` returns three distinct states.
    /// `Ok(None)` for an unknown run, `Ok(Some(None))` for a known but
    /// untagged run, `Ok(Some(Some(c)))` for a tagged run.
    #[test]
    fn correlation_id_for_run_distinguishes_unknown_untagged_and_tagged() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let tagged_id = CorrelationId::try_new("feat-1").unwrap();
        let tagged_run =
            sample_planner_run_with_correlation(&log, s.session_id, Some(tagged_id.clone()));
        let untagged_run = sample_planner_run_with_correlation(&log, s.session_id, None);
        let stray_run_id = AgentRunId::new();

        assert_eq!(
            log.correlation_id_for_run(tagged_run).unwrap(),
            Some(Some(tagged_id))
        );
        assert_eq!(
            log.correlation_id_for_run(untagged_run).unwrap(),
            Some(None)
        );
        assert_eq!(log.correlation_id_for_run(stray_run_id).unwrap(), None);
    }

    // --- plan_decision DAO --------------------------------------------

    fn submitted_plan(log: &AuditLog, session_id: SessionId) -> PlanId {
        let run_id = sample_planner_run(log, session_id);
        let plan_id = PlanId::new();
        log.record_plan_submission(&PlanSubmissionRecord {
            plan_id,
            agent_run_id: run_id,
            submitted_at: UnixMillis::from_millis(1_700_000_200),
            body: PlanBody::try_new("# Plan").unwrap(),
        })
        .unwrap();
        plan_id
    }

    /// Happy path: a decision against a known plan persists and reads
    /// back with every field intact.
    #[test]
    fn plan_decision_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);

        let record = PlanDecisionRecord {
            plan_id,
            decided_at: UnixMillis::from_millis(1_700_000_500),
            outcome: DecisionOutcome::Accepted,
            decider: Decider::try_new("cli:alice").unwrap(),
        };
        log.record_plan_decision(&record).unwrap();

        let read = log.get_plan_decision(plan_id).unwrap().unwrap();
        assert_eq!(read, record);
    }

    /// `get_plan_decision` returns `None` both for a plan that exists
    /// but has not been decided yet and for a plan that does not exist
    /// at all. Callers distinguish via `get_plan` if they need to.
    #[test]
    fn get_plan_decision_returns_none_for_undecided_and_missing_plans() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let undecided = submitted_plan(&log, s.session_id);
        let stray = PlanId::new();
        assert!(log.get_plan_decision(undecided).unwrap().is_none());
        assert!(log.get_plan_decision(stray).unwrap().is_none());
    }

    /// A decision against a plan that doesn't exist surfaces as a clean
    /// invariant error rather than a raw "FOREIGN KEY constraint
    /// failed" string.
    #[test]
    fn plan_decision_rejects_missing_plan() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let err = log
            .record_plan_decision(&PlanDecisionRecord {
                plan_id: PlanId::new(),
                decided_at: UnixMillis::from_millis(1_700_000_500),
                outcome: DecisionOutcome::Accepted,
                decider: Decider::try_new("cli:alice").unwrap(),
            })
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant("plan does not exist")));
    }

    /// A second decision against the same plan surfaces as a UNIQUE
    /// constraint violation — the wire layer maps that to
    /// `PlanAlreadyDecided` so a replay doesn't silently overwrite the
    /// original decision.
    #[test]
    fn plan_decision_rejects_second_decision_for_same_plan() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);

        log.record_plan_decision(&PlanDecisionRecord {
            plan_id,
            decided_at: UnixMillis::from_millis(1_700_000_500),
            outcome: DecisionOutcome::Accepted,
            decider: Decider::try_new("cli:alice").unwrap(),
        })
        .unwrap();

        let err = log
            .record_plan_decision(&PlanDecisionRecord {
                plan_id,
                decided_at: UnixMillis::from_millis(1_700_000_600),
                outcome: DecisionOutcome::RejectedRestart,
                decider: Decider::try_new("cli:bob").unwrap(),
            })
            .unwrap_err();
        assert!(
            matches!(err, AuditError::Sqlite(_)),
            "expected SQLite UNIQUE violation, got {err:?}",
        );
        // The first decision must survive — a failed second write must
        // not roll back or replace the first.
        let read = log.get_plan_decision(plan_id).unwrap().unwrap();
        assert_eq!(read.outcome, DecisionOutcome::Accepted);
        assert_eq!(read.decider.as_str(), "cli:alice");
    }

    /// Both terminal outcomes round-trip; the CHECK constraint accepts
    /// each wire string.
    #[test]
    fn plan_decision_persists_both_outcomes() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        for outcome in [DecisionOutcome::Accepted, DecisionOutcome::RejectedRestart] {
            let plan_id = submitted_plan(&log, s.session_id);
            log.record_plan_decision(&PlanDecisionRecord {
                plan_id,
                decided_at: UnixMillis::from_millis(1_700_000_500),
                outcome,
                decider: Decider::try_new("cli:alice").unwrap(),
            })
            .unwrap();
            assert_eq!(
                log.get_plan_decision(plan_id).unwrap().unwrap().outcome,
                outcome,
            );
        }
    }

    /// Belt-and-braces: a raw INSERT that bypasses the DAO must still
    /// be rejected by the schema CHECK if it tries to write an outcome
    /// outside the closed set.
    #[test]
    fn plan_decision_check_rejects_unknown_outcome() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);

        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_decision (plan_id, decided_at, outcome, decider)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        plan_id.as_uuid().to_string(),
                        1_700_000_500_i64,
                        "approved",
                        "cli:alice",
                    ],
                )?)
            })
            .unwrap_err();
        let rendered = err.to_string().to_lowercase();
        assert!(
            rendered.contains("check"),
            "expected CHECK violation, got {err}",
        );
    }

    /// Belt-and-braces: a raw INSERT with an empty decider must still
    /// be refused — the typed layer guarantees non-empty, the audit
    /// CHECK is the defence-in-depth.
    #[test]
    fn plan_decision_check_rejects_empty_decider() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);

        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_decision (plan_id, decided_at, outcome, decider)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        plan_id.as_uuid().to_string(),
                        1_700_000_500_i64,
                        "accepted",
                        "",
                    ],
                )?)
            })
            .unwrap_err();
        let rendered = err.to_string().to_lowercase();
        assert!(
            rendered.contains("check"),
            "expected CHECK violation, got {err}",
        );
    }

    /// Belt-and-braces: a raw INSERT with an embedded NUL in `decider`
    /// must still be refused by the audit CHECK.
    #[test]
    fn plan_decision_check_rejects_embedded_nul_in_decider() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);

        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_decision (plan_id, decided_at, outcome, decider)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        plan_id.as_uuid().to_string(),
                        1_700_000_500_i64,
                        "accepted",
                        "cli:al\0ce",
                    ],
                )?)
            })
            .unwrap_err();
        let rendered = err.to_string().to_lowercase();
        assert!(
            rendered.contains("check"),
            "expected CHECK violation, got {err}",
        );
    }

    /// Belt-and-braces: SQLite's well-known v1/v2 compat quirk allows
    /// NULL in a `TEXT PRIMARY KEY` column unless the column is
    /// explicitly marked `NOT NULL`, and the foreign key is satisfied
    /// by a NULL child (the reference rule treats NULL as "unmatched").
    /// Together these would let a raw INSERT smuggle a decision row
    /// referencing no plan and bypass the per-plan PK uniqueness. The
    /// schema declares `plan_id ... NOT NULL` precisely so this raw
    /// path is refused.
    #[test]
    fn plan_decision_rejects_null_plan_id_at_schema_boundary() {
        let log = AuditLog::open_in_memory().unwrap();
        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_decision (plan_id, decided_at, outcome, decider)
                     VALUES (NULL, ?1, ?2, ?3)",
                    params![1_700_000_500_i64, "accepted", "cli:alice"],
                )?)
            })
            .unwrap_err();
        let rendered = err.to_string().to_lowercase();
        assert!(
            rendered.contains("not null"),
            "expected NOT NULL violation on plan_id, got {err}",
        );
    }

    /// Decisions are deliberately cross-session: an operator may decide
    /// on a plan whose planner session is long since closed. Recording
    /// a decision after `close_session` must succeed.
    #[test]
    fn plan_decision_succeeds_after_planner_session_closes() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_300))
            .unwrap();

        log.record_plan_decision(&PlanDecisionRecord {
            plan_id,
            decided_at: UnixMillis::from_millis(1_700_000_500),
            outcome: DecisionOutcome::Accepted,
            decider: Decider::try_new("cli:alice").unwrap(),
        })
        .unwrap();

        let read = log.get_plan_decision(plan_id).unwrap().unwrap();
        assert_eq!(read.outcome, DecisionOutcome::Accepted);
    }

    // --- plan_review DAO ----------------------------------------------

    fn sample_review_run(log: &AuditLog, session_id: SessionId, plan_id: PlanId) -> AgentRunId {
        let run_id = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id,
            session_id,
            requested_at: UnixMillis::from_millis(1_700_000_300),
            agent_kind: AgentKind::Claude,
            prompt: AgentPrompt::new("review this plan").summary(),
            correlation_id: None,
            stage: Stage::Review,
            read_plan_id: Some(plan_id),
        })
        .unwrap();
        run_id
    }

    fn sample_review_record(
        log: &AuditLog,
        session_id: SessionId,
        plan_id: PlanId,
        verdict: Verdict,
        feedback: Option<PlanFeedback>,
    ) -> PlanReviewRecord {
        let reviewer = sample_review_run(log, session_id, plan_id);
        PlanReviewRecord {
            review_id: ReviewId::new(),
            plan_id,
            agent_run_id: reviewer,
            submitted_at: UnixMillis::from_millis(1_700_000_400),
            verdict,
            feedback,
        }
    }

    /// Happy path: a review against an open reviewer run round-trips
    /// (verdict and feedback intact) and the stored `feedback_sha256`
    /// agrees with a fresh recompute over the feedback bytes.
    #[test]
    fn plan_review_roundtrips_with_feedback() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        let feedback = PlanFeedback::try_new("Approve, with two nits inline.").unwrap();
        let record = sample_review_record(
            &log,
            s.session_id,
            plan_id,
            Verdict::Approve,
            Some(feedback.clone()),
        );

        log.record_plan_review(&record).unwrap();

        let read = log.get_plan_review(record.review_id).unwrap().unwrap();
        assert_eq!(read, record);

        let stored_sha: Option<String> = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT feedback_sha256 FROM plan_review WHERE review_id = ?1",
                    params![record.review_id.as_uuid().to_string()],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(stored_sha, Some(feedback.sha256_hex()));
    }

    /// A review with no feedback persists `feedback` and
    /// `feedback_sha256` as `NULL`. The paired-NULLs CHECK allows this
    /// and the read path returns `None`.
    #[test]
    fn plan_review_roundtrips_without_feedback() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        let record =
            sample_review_record(&log, s.session_id, plan_id, Verdict::RequestChanges, None);

        log.record_plan_review(&record).unwrap();

        let read = log.get_plan_review(record.review_id).unwrap().unwrap();
        assert_eq!(read, record);
        assert!(read.feedback.is_none());
    }

    /// `get_plan_review` returns `None` for an id that has no row.
    #[test]
    fn get_plan_review_returns_none_for_missing_review() {
        let log = AuditLog::open_in_memory().unwrap();
        assert!(log.get_plan_review(ReviewId::new()).unwrap().is_none());
    }

    /// A plan may carry many reviews; the listing orders by
    /// `submitted_at` (and `rowid` as tie-break) and includes every row.
    #[test]
    fn list_plan_reviews_for_plan_returns_each_review_in_submission_order() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);

        let first = {
            let mut r =
                sample_review_record(&log, s.session_id, plan_id, Verdict::RequestChanges, None);
            r.submitted_at = UnixMillis::from_millis(1_700_000_400);
            r
        };
        let second = {
            let mut r = sample_review_record(
                &log,
                s.session_id,
                plan_id,
                Verdict::Approve,
                Some(PlanFeedback::try_new("LGTM after the changes.").unwrap()),
            );
            r.submitted_at = UnixMillis::from_millis(1_700_000_500);
            r
        };
        log.record_plan_review(&first).unwrap();
        log.record_plan_review(&second).unwrap();

        let listed = log.list_plan_reviews_for_plan(plan_id).unwrap();
        assert_eq!(listed, vec![first, second]);
    }

    /// Reviews belong only to their plan: a query for one plan must
    /// not surface a review attached to a different plan.
    #[test]
    fn list_plan_reviews_for_plan_excludes_other_plans_reviews() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_a = submitted_plan(&log, s.session_id);
        let plan_b = submitted_plan(&log, s.session_id);

        let review_a = sample_review_record(&log, s.session_id, plan_a, Verdict::Approve, None);
        let review_b = sample_review_record(&log, s.session_id, plan_b, Verdict::Reject, None);
        log.record_plan_review(&review_a).unwrap();
        log.record_plan_review(&review_b).unwrap();

        assert_eq!(
            log.list_plan_reviews_for_plan(plan_a).unwrap(),
            vec![review_a]
        );
        assert_eq!(
            log.list_plan_reviews_for_plan(plan_b).unwrap(),
            vec![review_b]
        );
    }

    /// A review against a plan that doesn't exist surfaces as a clean
    /// invariant error rather than a raw foreign-key string.
    #[test]
    fn plan_review_rejects_missing_plan() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        // Spin up a reviewer run that names a non-existent plan via
        // read_plan_id — but the run itself is registered, so the
        // pre-check finds it. The plan itself, however, is missing.
        let reviewer = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id: reviewer,
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_300),
            agent_kind: AgentKind::Claude,
            prompt: AgentPrompt::new("review this plan").summary(),
            correlation_id: None,
            stage: Stage::Review,
            read_plan_id: None,
        })
        .unwrap();

        let err = log
            .record_plan_review(&PlanReviewRecord {
                review_id: ReviewId::new(),
                plan_id: PlanId::new(),
                agent_run_id: reviewer,
                submitted_at: UnixMillis::from_millis(1_700_000_400),
                verdict: Verdict::Approve,
                feedback: None,
            })
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant("plan does not exist")));
    }

    /// A review whose `agent_run_id` is unknown must surface as an
    /// invariant error — the typed layer caller has handed in a stale
    /// or fabricated run id.
    #[test]
    fn plan_review_rejects_missing_agent_run() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);

        let err = log
            .record_plan_review(&PlanReviewRecord {
                review_id: ReviewId::new(),
                plan_id,
                agent_run_id: AgentRunId::new(),
                submitted_at: UnixMillis::from_millis(1_700_000_400),
                verdict: Verdict::Approve,
                feedback: None,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("agent run does not exist")
        ));
    }

    /// A reviewer whose session has been closed cannot land a verdict.
    /// The pre-check returns `Invariant("session is closed")`; the
    /// follow-up `plan_review_db_trigger_rejects_direct_insert_against_closed_session`
    /// test exercises the trigger directly to prove the belt-and-braces
    /// gate fires even on a raw INSERT.
    #[test]
    fn plan_review_rejects_closed_reviewer_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        let reviewer = sample_review_run(&log, s.session_id, plan_id);
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_350))
            .unwrap();

        let err = log
            .record_plan_review(&PlanReviewRecord {
                review_id: ReviewId::new(),
                plan_id,
                agent_run_id: reviewer,
                submitted_at: UnixMillis::from_millis(1_700_000_400),
                verdict: Verdict::Approve,
                feedback: None,
            })
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant("session is closed")));
    }

    /// Belt-and-braces: the session trigger must fire on a raw INSERT
    /// that bypasses the DAO's pre-check, mirroring the
    /// `plan_db_trigger_rejects_direct_insert_against_closed_session`
    /// shape used for `plan`.
    #[test]
    fn plan_review_db_trigger_rejects_direct_insert_against_closed_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        let reviewer = sample_review_run(&log, s.session_id, plan_id);
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_350))
            .unwrap();

        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO plan_review
                     (review_id, plan_id, agent_run_id, submitted_at, verdict, feedback, feedback_sha256)
                     VALUES (?1, ?2, ?3, ?4, 'approve', NULL, NULL)",
                    params![
                        ReviewId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        reviewer.as_uuid().to_string(),
                        1_700_000_400_i64,
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

    /// A planner-stage run cannot post a review: the DAO pre-check
    /// surfaces a typed invariant error.
    #[test]
    fn plan_review_rejects_non_review_stage_run() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let planner = sample_planner_run(&log, s.session_id);
        let plan_id = PlanId::new();
        // Submit a plan against the planner so the FK is satisfied.
        log.record_plan_submission(&PlanSubmissionRecord {
            plan_id,
            agent_run_id: planner,
            submitted_at: UnixMillis::from_millis(1_700_000_200),
            body: PlanBody::try_new("# Plan").unwrap(),
        })
        .unwrap();

        let err = log
            .record_plan_review(&PlanReviewRecord {
                review_id: ReviewId::new(),
                plan_id,
                agent_run_id: planner,
                submitted_at: UnixMillis::from_millis(1_700_000_400),
                verdict: Verdict::Approve,
                feedback: None,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("plan_review requires agent_run.stage = 'review'")
        ));
    }

    /// Belt-and-braces: the stage trigger fires on a raw INSERT that
    /// bypasses the DAO pre-check.
    #[test]
    fn plan_review_db_trigger_rejects_non_review_stage_run() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let planner = sample_planner_run(&log, s.session_id);
        let plan_id = PlanId::new();
        log.record_plan_submission(&PlanSubmissionRecord {
            plan_id,
            agent_run_id: planner,
            submitted_at: UnixMillis::from_millis(1_700_000_200),
            body: PlanBody::try_new("# Plan").unwrap(),
        })
        .unwrap();

        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO plan_review
                     (review_id, plan_id, agent_run_id, submitted_at, verdict, feedback, feedback_sha256)
                     VALUES (?1, ?2, ?3, ?4, 'approve', NULL, NULL)",
                    params![
                        ReviewId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        planner.as_uuid().to_string(),
                        1_700_000_400_i64,
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite trigger error, got {err:?}");
        };
        let rendered = e.to_string();
        assert!(
            rendered.contains("plan_review requires agent_run.stage"),
            "got: {rendered}"
        );
    }

    /// The reviewer run's `read_plan_id` binds the verdict to a single
    /// plan: a review-stage reviewer that read plan A cannot attach a
    /// verdict to plan B. The pre-check surfaces this as a clean typed
    /// invariant; the matching trigger covers the raw-INSERT path.
    #[test]
    fn plan_review_rejects_run_bound_to_a_different_plan() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_a = submitted_plan(&log, s.session_id);
        let plan_b = submitted_plan(&log, s.session_id);
        // Reviewer reads plan A but attempts to verdict plan B.
        let reviewer = sample_review_run(&log, s.session_id, plan_a);

        let err = log
            .record_plan_review(&PlanReviewRecord {
                review_id: ReviewId::new(),
                plan_id: plan_b,
                agent_run_id: reviewer,
                submitted_at: UnixMillis::from_millis(1_700_000_400),
                verdict: Verdict::Approve,
                feedback: None,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("plan_review requires agent_run.read_plan_id = plan_id")
        ));
    }

    /// Belt-and-braces: a reviewer agent_run with no `read_plan_id`
    /// binding at all (raw INSERT bypasses the route, which would
    /// always set it) still cannot smuggle a verdict in. The trigger
    /// rejects every NULL/mismatched binding equally.
    #[test]
    fn plan_review_db_trigger_rejects_run_bound_to_a_different_plan() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_a = submitted_plan(&log, s.session_id);
        let plan_b = submitted_plan(&log, s.session_id);
        let reviewer = sample_review_run(&log, s.session_id, plan_a);

        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO plan_review
                     (review_id, plan_id, agent_run_id, submitted_at, verdict, feedback, feedback_sha256)
                     VALUES (?1, ?2, ?3, ?4, 'approve', NULL, NULL)",
                    params![
                        ReviewId::new().as_uuid().to_string(),
                        plan_b.as_uuid().to_string(),
                        reviewer.as_uuid().to_string(),
                        1_700_000_400_i64,
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite trigger error, got {err:?}");
        };
        let rendered = e.to_string();
        assert!(rendered.contains("read_plan_id"), "got: {rendered}");
    }

    /// A second review from the same reviewer run surfaces as the
    /// `UNIQUE(agent_run_id)` violation. The wire layer maps this to a
    /// "review already recorded" outcome; the audit-side raw error must
    /// be a SQLite UNIQUE so the mapping has something to match on.
    #[test]
    fn plan_review_rejects_second_review_for_same_run() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        let reviewer = sample_review_run(&log, s.session_id, plan_id);

        log.record_plan_review(&PlanReviewRecord {
            review_id: ReviewId::new(),
            plan_id,
            agent_run_id: reviewer,
            submitted_at: UnixMillis::from_millis(1_700_000_400),
            verdict: Verdict::Approve,
            feedback: None,
        })
        .unwrap();

        let err = log
            .record_plan_review(&PlanReviewRecord {
                review_id: ReviewId::new(),
                plan_id,
                agent_run_id: reviewer,
                submitted_at: UnixMillis::from_millis(1_700_000_500),
                verdict: Verdict::Reject,
                feedback: None,
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite UNIQUE error, got {err:?}");
        };
        assert!(e.to_string().to_uppercase().contains("UNIQUE"), "got: {e}");
    }

    /// Every closed-set wire value of [`Verdict`] persists and reads
    /// back; the CHECK on `verdict` accepts each.
    #[test]
    fn plan_review_persists_every_verdict() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);

        for verdict in [Verdict::Approve, Verdict::RequestChanges, Verdict::Reject] {
            let record = sample_review_record(&log, s.session_id, plan_id, verdict, None);
            log.record_plan_review(&record).unwrap();
            let read = log.get_plan_review(record.review_id).unwrap().unwrap();
            assert_eq!(read.verdict, verdict);
        }
    }

    /// Belt-and-braces: a raw INSERT with an unknown verdict must be
    /// refused by the CHECK constraint.
    #[test]
    fn plan_review_check_rejects_unknown_verdict() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        let reviewer = sample_review_run(&log, s.session_id, plan_id);

        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_review
                     (review_id, plan_id, agent_run_id, submitted_at, verdict, feedback, feedback_sha256)
                     VALUES (?1, ?2, ?3, ?4, 'approved', NULL, NULL)",
                    params![
                        ReviewId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        reviewer.as_uuid().to_string(),
                        1_700_000_400_i64,
                    ],
                )?)
            })
            .unwrap_err();
        let rendered = err.to_string().to_lowercase();
        assert!(
            rendered.contains("check"),
            "expected CHECK violation, got {err}"
        );
    }

    /// Belt-and-braces: the table-level paired-NULL CHECK refuses a
    /// row that has `feedback` set but no digest (and vice versa).
    #[test]
    fn plan_review_check_rejects_feedback_digest_pair_mismatch() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        let reviewer = sample_review_run(&log, s.session_id, plan_id);

        // feedback present, digest NULL — must be refused.
        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_review
                     (review_id, plan_id, agent_run_id, submitted_at, verdict, feedback, feedback_sha256)
                     VALUES (?1, ?2, ?3, ?4, 'approve', 'lgtm', NULL)",
                    params![
                        ReviewId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        reviewer.as_uuid().to_string(),
                        1_700_000_400_i64,
                    ],
                )?)
            })
            .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("check"),
            "expected CHECK violation, got {err}"
        );

        // digest present, feedback NULL — must also be refused.
        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_review
                     (review_id, plan_id, agent_run_id, submitted_at, verdict, feedback, feedback_sha256)
                     VALUES (?1, ?2, ?3, ?4, 'approve', NULL, ?5)",
                    params![
                        ReviewId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        reviewer.as_uuid().to_string(),
                        1_700_000_400_i64,
                        "a".repeat(64),
                    ],
                )?)
            })
            .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("check"),
            "expected CHECK violation, got {err}"
        );
    }

    /// Belt-and-braces: the `feedback_sha256` CHECK enforces lowercase
    /// hex in TEXT storage class — a 64-character non-hex string and a
    /// 64-byte BLOB binding both fail. Otherwise a raw INSERT could
    /// land a digest the typed read path (`validate_sha256_hex`)
    /// cannot deserialise, making the row unreachable by
    /// `get_plan_review` / `list_plan_reviews_for_plan`.
    #[test]
    fn plan_review_check_rejects_malformed_feedback_sha256() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        let reviewer = sample_review_run(&log, s.session_id, plan_id);

        // 64 chars, but contains 'g' — not a hex digit.
        let non_hex = "g".repeat(64);
        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_review
                     (review_id, plan_id, agent_run_id, submitted_at, verdict, feedback, feedback_sha256)
                     VALUES (?1, ?2, ?3, ?4, 'approve', 'lgtm', ?5)",
                    params![
                        ReviewId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        reviewer.as_uuid().to_string(),
                        1_700_000_400_i64,
                        non_hex,
                    ],
                )?)
            })
            .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("check"),
            "expected CHECK violation, got {err}"
        );

        // 64 bytes bound as a BLOB. Without `typeof = 'text'` the
        // CHECK would silently accept this since `length()` on a 64-
        // byte BLOB also returns 64.
        let blob_digest: Vec<u8> = vec![b'a'; 64];
        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_review
                     (review_id, plan_id, agent_run_id, submitted_at, verdict, feedback, feedback_sha256)
                     VALUES (?1, ?2, ?3, ?4, 'approve', 'lgtm', ?5)",
                    params![
                        ReviewId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        reviewer.as_uuid().to_string(),
                        1_700_000_400_i64,
                        blob_digest,
                    ],
                )?)
            })
            .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("check"),
            "expected CHECK violation, got {err}"
        );

        // 64 hex chars followed by `\0` plus filler, bound as TEXT.
        // `length()` and `GLOB` on TEXT stop at the first NUL byte, so
        // without the BLOB-length parity clause this value would slip
        // past both the size and the hex-class checks and land a row
        // the typed reader could not deserialise.
        let mut nul_padded = String::from("a").repeat(64);
        nul_padded.push('\0');
        nul_padded.push_str("junk");
        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_review
                     (review_id, plan_id, agent_run_id, submitted_at, verdict, feedback, feedback_sha256)
                     VALUES (?1, ?2, ?3, ?4, 'approve', 'lgtm', ?5)",
                    params![
                        ReviewId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        reviewer.as_uuid().to_string(),
                        1_700_000_400_i64,
                        nul_padded,
                    ],
                )?)
            })
            .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("check"),
            "expected CHECK violation, got {err}"
        );
    }

    /// Belt-and-braces: an oversize raw feedback body is refused by
    /// the column CHECK before the row lands.
    #[test]
    fn plan_review_check_rejects_oversize_feedback() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        let reviewer = sample_review_run(&log, s.session_id, plan_id);

        let oversize = "x".repeat(65537);
        let oversize_sha = crate::agent_run::sha256_hex(oversize.as_bytes());

        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_review
                     (review_id, plan_id, agent_run_id, submitted_at, verdict, feedback, feedback_sha256)
                     VALUES (?1, ?2, ?3, ?4, 'approve', ?5, ?6)",
                    params![
                        ReviewId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        reviewer.as_uuid().to_string(),
                        1_700_000_400_i64,
                        oversize,
                        oversize_sha,
                    ],
                )?)
            })
            .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("check"),
            "expected CHECK violation, got {err}"
        );
    }

    /// Belt-and-braces: SQLite's well-known v1/v2 compat quirk allows
    /// NULL in a `TEXT PRIMARY KEY` column unless explicitly marked
    /// `NOT NULL`. The schema declares `review_id ... NOT NULL` so a
    /// raw INSERT with `review_id = NULL` is refused.
    #[test]
    fn plan_review_rejects_null_review_id_at_schema_boundary() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        let reviewer = sample_review_run(&log, s.session_id, plan_id);

        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_review
                     (review_id, plan_id, agent_run_id, submitted_at, verdict, feedback, feedback_sha256)
                     VALUES (NULL, ?1, ?2, ?3, 'approve', NULL, NULL)",
                    params![
                        plan_id.as_uuid().to_string(),
                        reviewer.as_uuid().to_string(),
                        1_700_000_400_i64,
                    ],
                )?)
            })
            .unwrap_err();
        let rendered = err.to_string().to_lowercase();
        assert!(
            rendered.contains("not null"),
            "expected NOT NULL violation on review_id, got {err}"
        );
    }

    // --- plan_addendum DAO ---------------------------------------------

    /// Submit a plan and accept it, returning the plan id. Addenda
    /// require both — a plan row to FK against and an `accepted`
    /// decision row for the trigger / pre-check. Tests that exercise
    /// the missing-decision and rejected-decision paths build the
    /// preconditions themselves.
    fn accepted_plan(log: &AuditLog, session_id: SessionId) -> PlanId {
        let plan_id = submitted_plan(log, session_id);
        log.record_plan_decision(&PlanDecisionRecord {
            plan_id,
            decided_at: UnixMillis::from_millis(1_700_000_350),
            outcome: DecisionOutcome::Accepted,
            decider: Decider::try_new("cli:alice").unwrap(),
        })
        .unwrap();
        plan_id
    }

    fn sample_executor_run(log: &AuditLog, session_id: SessionId, plan_id: PlanId) -> AgentRunId {
        let run_id = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id,
            session_id,
            requested_at: UnixMillis::from_millis(1_700_000_360),
            agent_kind: AgentKind::Claude,
            prompt: AgentPrompt::new("execute this plan").summary(),
            correlation_id: None,
            stage: Stage::Execute,
            read_plan_id: Some(plan_id),
        })
        .unwrap();
        run_id
    }

    fn sample_addendum_record(
        log: &AuditLog,
        session_id: SessionId,
        plan_id: PlanId,
        body: PlanBody,
    ) -> PlanAddendumRecord {
        let executor = sample_executor_run(log, session_id, plan_id);
        PlanAddendumRecord {
            addendum_id: AddendumId::new(),
            plan_id,
            agent_run_id: executor,
            submitted_at: UnixMillis::from_millis(1_700_000_400),
            body,
        }
    }

    /// Happy path: an addendum against an executor run for an accepted
    /// plan round-trips (body intact) and the stored `body_sha256`
    /// agrees with a fresh recompute over the body bytes.
    #[test]
    fn plan_addendum_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = accepted_plan(&log, s.session_id);
        let body = PlanBody::try_new("# Addendum\n\nAlso: tidy up bar.").unwrap();
        let record = sample_addendum_record(&log, s.session_id, plan_id, body.clone());

        log.record_plan_addendum(&record).unwrap();

        let read = log.get_plan_addendum(record.addendum_id).unwrap().unwrap();
        assert_eq!(read, record);

        let stored_sha: String = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT body_sha256 FROM plan_addendum WHERE addendum_id = ?1",
                    params![record.addendum_id.as_uuid().to_string()],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(stored_sha, body.sha256_hex());
    }

    /// `get_plan_addendum` returns `None` for an id that has no row.
    #[test]
    fn get_plan_addendum_returns_none_for_missing_addendum() {
        let log = AuditLog::open_in_memory().unwrap();
        assert!(log.get_plan_addendum(AddendumId::new()).unwrap().is_none());
    }

    /// A plan may carry many addenda; the listing orders by
    /// `submitted_at` (and `rowid` as tie-break) and includes every
    /// row.
    #[test]
    fn list_plan_addenda_for_plan_returns_each_addendum_in_submission_order() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = accepted_plan(&log, s.session_id);

        let first = {
            let mut r = sample_addendum_record(
                &log,
                s.session_id,
                plan_id,
                PlanBody::try_new("# First addendum").unwrap(),
            );
            r.submitted_at = UnixMillis::from_millis(1_700_000_400);
            r
        };
        let second = {
            let mut r = sample_addendum_record(
                &log,
                s.session_id,
                plan_id,
                PlanBody::try_new("# Second addendum").unwrap(),
            );
            r.submitted_at = UnixMillis::from_millis(1_700_000_500);
            r
        };
        log.record_plan_addendum(&first).unwrap();
        log.record_plan_addendum(&second).unwrap();

        let listed = log.list_plan_addenda_for_plan(plan_id).unwrap();
        assert_eq!(listed, vec![first, second]);
    }

    /// Ties on `submitted_at` are broken by `rowid` so the order is
    /// stable across repeated reads. Insert two addenda at the same
    /// millisecond and confirm `rowid` order is preserved.
    #[test]
    fn list_plan_addenda_for_plan_breaks_submitted_at_ties_by_rowid() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = accepted_plan(&log, s.session_id);

        let first = sample_addendum_record(
            &log,
            s.session_id,
            plan_id,
            PlanBody::try_new("# First").unwrap(),
        );
        let second = sample_addendum_record(
            &log,
            s.session_id,
            plan_id,
            PlanBody::try_new("# Second").unwrap(),
        );
        log.record_plan_addendum(&first).unwrap();
        log.record_plan_addendum(&second).unwrap();

        let listed = log.list_plan_addenda_for_plan(plan_id).unwrap();
        assert_eq!(listed, vec![first, second]);
    }

    /// Addenda belong only to their plan: a query for one plan must
    /// not surface an addendum attached to a different plan.
    #[test]
    fn list_plan_addenda_for_plan_excludes_other_plans_addenda() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_a = accepted_plan(&log, s.session_id);
        let plan_b = accepted_plan(&log, s.session_id);

        let addendum_a = sample_addendum_record(
            &log,
            s.session_id,
            plan_a,
            PlanBody::try_new("# A").unwrap(),
        );
        let addendum_b = sample_addendum_record(
            &log,
            s.session_id,
            plan_b,
            PlanBody::try_new("# B").unwrap(),
        );
        log.record_plan_addendum(&addendum_a).unwrap();
        log.record_plan_addendum(&addendum_b).unwrap();

        assert_eq!(
            log.list_plan_addenda_for_plan(plan_a).unwrap(),
            vec![addendum_a]
        );
        assert_eq!(
            log.list_plan_addenda_for_plan(plan_b).unwrap(),
            vec![addendum_b]
        );
    }

    /// An addendum against a plan that doesn't exist surfaces as a
    /// clean invariant error rather than a raw foreign-key string.
    #[test]
    fn plan_addendum_rejects_missing_plan() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        // Build an executor run that names a non-existent plan via
        // read_plan_id; the run itself is registered, but the plan
        // never was, so the pre-check trips on plan-missing before
        // it reaches the run lookup.
        let executor = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id: executor,
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_360),
            agent_kind: AgentKind::Claude,
            prompt: AgentPrompt::new("execute this plan").summary(),
            correlation_id: None,
            stage: Stage::Execute,
            read_plan_id: None,
        })
        .unwrap();

        let err = log
            .record_plan_addendum(&PlanAddendumRecord {
                addendum_id: AddendumId::new(),
                plan_id: PlanId::new(),
                agent_run_id: executor,
                submitted_at: UnixMillis::from_millis(1_700_000_400),
                body: PlanBody::try_new("# Addendum").unwrap(),
            })
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant("plan does not exist")));
    }

    /// An addendum against an `agent_run_id` that has no row surfaces
    /// as an invariant error — the caller has handed in a stale or
    /// fabricated run id.
    #[test]
    fn plan_addendum_rejects_missing_agent_run() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = accepted_plan(&log, s.session_id);

        let err = log
            .record_plan_addendum(&PlanAddendumRecord {
                addendum_id: AddendumId::new(),
                plan_id,
                agent_run_id: AgentRunId::new(),
                submitted_at: UnixMillis::from_millis(1_700_000_400),
                body: PlanBody::try_new("# Addendum").unwrap(),
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("agent run does not exist")
        ));
    }

    /// An addendum against a plan whose decision has not yet been
    /// recorded is refused. The DAO surfaces a typed invariant rather
    /// than the trigger's raw message.
    #[test]
    fn plan_addendum_rejects_undecided_plan() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        // submitted_plan creates a plan with no decision.
        let plan_id = submitted_plan(&log, s.session_id);
        // The pre-check fires on the plan-not-accepted clause before
        // the agent run is even validated; build an executor run so
        // the test pinpoints the right invariant.
        let executor = sample_executor_run(&log, s.session_id, plan_id);

        let err = log
            .record_plan_addendum(&PlanAddendumRecord {
                addendum_id: AddendumId::new(),
                plan_id,
                agent_run_id: executor,
                submitted_at: UnixMillis::from_millis(1_700_000_400),
                body: PlanBody::try_new("# Addendum").unwrap(),
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("plan_addendum requires plan_decision.outcome = 'accepted'")
        ));
    }

    /// An addendum against a plan whose decision is `rejected_restart`
    /// is refused. Mirrors the undecided-plan test for the other
    /// outcome.
    #[test]
    fn plan_addendum_rejects_rejected_plan() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        log.record_plan_decision(&PlanDecisionRecord {
            plan_id,
            decided_at: UnixMillis::from_millis(1_700_000_350),
            outcome: DecisionOutcome::RejectedRestart,
            decider: Decider::try_new("cli:alice").unwrap(),
        })
        .unwrap();
        let executor = sample_executor_run(&log, s.session_id, plan_id);

        let err = log
            .record_plan_addendum(&PlanAddendumRecord {
                addendum_id: AddendumId::new(),
                plan_id,
                agent_run_id: executor,
                submitted_at: UnixMillis::from_millis(1_700_000_400),
                body: PlanBody::try_new("# Addendum").unwrap(),
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("plan_addendum requires plan_decision.outcome = 'accepted'")
        ));
    }

    /// Belt-and-braces: the accepted-decision trigger fires on a raw
    /// INSERT that bypasses the DAO pre-check. An undecided plan must
    /// have no addenda even from a raw write path.
    #[test]
    fn plan_addendum_db_trigger_rejects_undecided_plan() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = submitted_plan(&log, s.session_id);
        let executor = sample_executor_run(&log, s.session_id, plan_id);

        let body = "# Addendum";
        let body_sha = crate::agent_run::sha256_hex(body.as_bytes());
        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO plan_addendum
                     (addendum_id, plan_id, agent_run_id, submitted_at, body, body_sha256)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        AddendumId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        executor.as_uuid().to_string(),
                        1_700_000_400_i64,
                        body,
                        body_sha,
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite trigger error, got {err:?}");
        };
        assert!(e.to_string().contains("plan_decision.outcome"), "got: {e}");
    }

    /// An executor whose session has been closed cannot land an
    /// addendum. The DAO pre-check returns
    /// `Invariant("session is closed")`.
    #[test]
    fn plan_addendum_rejects_closed_executor_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = accepted_plan(&log, s.session_id);
        let executor = sample_executor_run(&log, s.session_id, plan_id);
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_390))
            .unwrap();

        let err = log
            .record_plan_addendum(&PlanAddendumRecord {
                addendum_id: AddendumId::new(),
                plan_id,
                agent_run_id: executor,
                submitted_at: UnixMillis::from_millis(1_700_000_400),
                body: PlanBody::try_new("# Addendum").unwrap(),
            })
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant("session is closed")));
    }

    /// Belt-and-braces: the session trigger fires on a raw INSERT
    /// that bypasses the DAO pre-check.
    #[test]
    fn plan_addendum_db_trigger_rejects_direct_insert_against_closed_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = accepted_plan(&log, s.session_id);
        let executor = sample_executor_run(&log, s.session_id, plan_id);
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_390))
            .unwrap();

        let body = "# Addendum";
        let body_sha = crate::agent_run::sha256_hex(body.as_bytes());
        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO plan_addendum
                     (addendum_id, plan_id, agent_run_id, submitted_at, body, body_sha256)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        AddendumId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        executor.as_uuid().to_string(),
                        1_700_000_400_i64,
                        body,
                        body_sha,
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

    /// A planner-stage run cannot post an addendum: the DAO pre-check
    /// surfaces a typed invariant error.
    #[test]
    fn plan_addendum_rejects_non_execute_stage_run() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = accepted_plan(&log, s.session_id);
        // Use the planner run that created the plan — it has stage='plan'.
        let planner: AgentRunId = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT agent_run_id FROM plan WHERE plan_id = ?1",
                    params![plan_id.as_uuid().to_string()],
                    |r| {
                        let s: String = r.get(0)?;
                        Ok(AgentRunId::from_uuid(uuid::Uuid::parse_str(&s).unwrap()))
                    },
                )?)
            })
            .unwrap();

        let err = log
            .record_plan_addendum(&PlanAddendumRecord {
                addendum_id: AddendumId::new(),
                plan_id,
                agent_run_id: planner,
                submitted_at: UnixMillis::from_millis(1_700_000_400),
                body: PlanBody::try_new("# Addendum").unwrap(),
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("plan_addendum requires agent_run.stage = 'execute'")
        ));
    }

    /// Belt-and-braces: the stage trigger fires on a raw INSERT.
    #[test]
    fn plan_addendum_db_trigger_rejects_non_execute_stage_run() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = accepted_plan(&log, s.session_id);
        let planner: AgentRunId = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT agent_run_id FROM plan WHERE plan_id = ?1",
                    params![plan_id.as_uuid().to_string()],
                    |r| {
                        let s: String = r.get(0)?;
                        Ok(AgentRunId::from_uuid(uuid::Uuid::parse_str(&s).unwrap()))
                    },
                )?)
            })
            .unwrap();

        let body = "# Addendum";
        let body_sha = crate::agent_run::sha256_hex(body.as_bytes());
        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO plan_addendum
                     (addendum_id, plan_id, agent_run_id, submitted_at, body, body_sha256)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        AddendumId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        planner.as_uuid().to_string(),
                        1_700_000_400_i64,
                        body,
                        body_sha,
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite trigger error, got {err:?}");
        };
        assert!(
            e.to_string()
                .contains("plan_addendum requires agent_run.stage"),
            "got: {e}"
        );
    }

    /// The executor run's `read_plan_id` binds the addendum to a
    /// single plan: an executor that read plan A cannot attach an
    /// addendum to plan B. Pre-check surfaces this as a clean typed
    /// invariant.
    #[test]
    fn plan_addendum_rejects_run_bound_to_a_different_plan() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_a = accepted_plan(&log, s.session_id);
        let plan_b = accepted_plan(&log, s.session_id);
        // Executor reads plan A but attempts to addend plan B.
        let executor = sample_executor_run(&log, s.session_id, plan_a);

        let err = log
            .record_plan_addendum(&PlanAddendumRecord {
                addendum_id: AddendumId::new(),
                plan_id: plan_b,
                agent_run_id: executor,
                submitted_at: UnixMillis::from_millis(1_700_000_400),
                body: PlanBody::try_new("# Addendum").unwrap(),
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("plan_addendum requires agent_run.read_plan_id = plan_id")
        ));
    }

    /// Belt-and-braces: the trigger refuses the same cross-plan
    /// binding on a raw INSERT.
    #[test]
    fn plan_addendum_db_trigger_rejects_run_bound_to_a_different_plan() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_a = accepted_plan(&log, s.session_id);
        let plan_b = accepted_plan(&log, s.session_id);
        let executor = sample_executor_run(&log, s.session_id, plan_a);

        let body = "# Addendum";
        let body_sha = crate::agent_run::sha256_hex(body.as_bytes());
        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO plan_addendum
                     (addendum_id, plan_id, agent_run_id, submitted_at, body, body_sha256)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        AddendumId::new().as_uuid().to_string(),
                        plan_b.as_uuid().to_string(),
                        executor.as_uuid().to_string(),
                        1_700_000_400_i64,
                        body,
                        body_sha,
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite trigger error, got {err:?}");
        };
        assert!(e.to_string().contains("read_plan_id"), "got: {e}");
    }

    /// A second addendum from the same executor run surfaces as the
    /// `UNIQUE(agent_run_id)` violation. Callers may map that
    /// wire-side to "addendum already recorded"; the audit-side raw
    /// error must be a SQLite UNIQUE so the mapping has something to
    /// match on.
    #[test]
    fn plan_addendum_rejects_second_addendum_for_same_run() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = accepted_plan(&log, s.session_id);
        let executor = sample_executor_run(&log, s.session_id, plan_id);

        log.record_plan_addendum(&PlanAddendumRecord {
            addendum_id: AddendumId::new(),
            plan_id,
            agent_run_id: executor,
            submitted_at: UnixMillis::from_millis(1_700_000_400),
            body: PlanBody::try_new("# First").unwrap(),
        })
        .unwrap();

        let err = log
            .record_plan_addendum(&PlanAddendumRecord {
                addendum_id: AddendumId::new(),
                plan_id,
                agent_run_id: executor,
                submitted_at: UnixMillis::from_millis(1_700_000_500),
                body: PlanBody::try_new("# Second").unwrap(),
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite UNIQUE error, got {err:?}");
        };
        assert!(e.to_string().to_uppercase().contains("UNIQUE"), "got: {e}");
    }

    /// Belt-and-braces: a raw INSERT with an empty body is refused by
    /// the column CHECK before the row lands.
    #[test]
    fn plan_addendum_check_rejects_empty_body() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = accepted_plan(&log, s.session_id);
        let executor = sample_executor_run(&log, s.session_id, plan_id);

        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_addendum
                     (addendum_id, plan_id, agent_run_id, submitted_at, body, body_sha256)
                     VALUES (?1, ?2, ?3, ?4, '', ?5)",
                    params![
                        AddendumId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        executor.as_uuid().to_string(),
                        1_700_000_400_i64,
                        crate::agent_run::sha256_hex(b""),
                    ],
                )?)
            })
            .unwrap_err();
        let rendered = err.to_string().to_lowercase();
        assert!(
            rendered.contains("check"),
            "expected CHECK violation, got {err}"
        );
    }

    /// Belt-and-braces: a malformed (short / non-hex) `body_sha256`
    /// is refused by the column CHECK.
    #[test]
    fn plan_addendum_check_rejects_malformed_body_sha256() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = accepted_plan(&log, s.session_id);
        let executor = sample_executor_run(&log, s.session_id, plan_id);

        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_addendum
                     (addendum_id, plan_id, agent_run_id, submitted_at, body, body_sha256)
                     VALUES (?1, ?2, ?3, ?4, '# Addendum', 'too short')",
                    params![
                        AddendumId::new().as_uuid().to_string(),
                        plan_id.as_uuid().to_string(),
                        executor.as_uuid().to_string(),
                        1_700_000_400_i64,
                    ],
                )?)
            })
            .unwrap_err();
        let rendered = err.to_string().to_lowercase();
        assert!(
            rendered.contains("check"),
            "expected CHECK violation, got {err}"
        );
    }

    /// Belt-and-braces: SQLite's well-known v1/v2 compat quirk allows
    /// NULL in a `TEXT PRIMARY KEY` column unless explicitly marked
    /// `NOT NULL`. The schema declares `addendum_id ... NOT NULL` so
    /// a raw INSERT with `addendum_id = NULL` is refused.
    #[test]
    fn plan_addendum_rejects_null_addendum_id_at_schema_boundary() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let plan_id = accepted_plan(&log, s.session_id);
        let executor = sample_executor_run(&log, s.session_id, plan_id);

        let body = "# Addendum";
        let body_sha = crate::agent_run::sha256_hex(body.as_bytes());
        let err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan_addendum
                     (addendum_id, plan_id, agent_run_id, submitted_at, body, body_sha256)
                     VALUES (NULL, ?1, ?2, ?3, ?4, ?5)",
                    params![
                        plan_id.as_uuid().to_string(),
                        executor.as_uuid().to_string(),
                        1_700_000_400_i64,
                        body,
                        body_sha,
                    ],
                )?)
            })
            .unwrap_err();
        let rendered = err.to_string().to_lowercase();
        assert!(
            rendered.contains("not null"),
            "expected NOT NULL violation on addendum_id, got {err}"
        );
    }
}
