//! Agent VM workspace bootstrap and agent-run audit records.
//!
//! Two related domains share this module: the workspace-bootstrap
//! intent recorded at session start, and the prompt/outcome pair
//! captured for each completed agent run inside that session.

use rusqlite::{Connection, OptionalExtension, Row, params};

use super::session::SqlAgentKind;
use super::validation::{
    bool_to_sql_i64, labeled_invariant, path_to_sql_text, u64_to_sql_i64,
    validate_agent_run_stream_path_text, validate_sha256_hex, validate_stream_summary,
};
use super::{AuditError, AuditLog};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use writ_agent_run::{
    AgentPromptSummary, AgentRunId, AgentRunOutcome, AgentRunStreamSummary, AgentRunTerminalStatus,
    CorrelationId, RunPurpose,
};
use writ_core::core::{AgentKind, SessionId, SessionRecord, UnixMillis};

/// What "the session's most recent run" means, as a SQL `ORDER BY`
/// fragment, in the one place every reader of that notion shares.
///
/// `requested_at` alone is **not** a total order: it is millisecond
/// granularity, so two runs requested in the same millisecond tie, and
/// which one SQLite returns is unspecified. `run_id` breaks the tie. It
/// carries no meaning and is not intended to — it is a UUID, so the
/// tiebreak is arbitrary but *stable*, which is the whole requirement.
/// Determinism is bought here, not a claim about which run is newer.
///
/// **This is defensive, not a fix for an observed bug.** Reverting to
/// `requested_at DESC` alone does not currently make the per-session
/// lookups and the batched [`AuditLog::sessions_with_latest_run`]
/// disagree: today both forms happen to walk ties in the same order,
/// and the property test still passes — that was checked rather than
/// assumed. What the tiebreak removes is the *dependence* on that
/// coincidence. `ORDER BY … LIMIT 1` and `ROW_NUMBER() OVER (…)` are
/// separately planned, and tie order is a property of the plan, so
/// adding an index on `requested_at`, upgrading the bundled SQLite, or
/// growing the table past a plan-shape threshold could change one and
/// not the other. Under a total order none of that is observable.
const LATEST_RUN_ORDER: &str = "requested_at DESC, run_id DESC";

/// How many session ids go into one `IN (...)` clause.
///
/// SQLite's compiled-in host-parameter limit is 32766 in the bundled
/// build and was 999 in older ones; 256 stays far below both without
/// making the query count interesting. It is a chunking bound, not a
/// cap on what callers may ask for: [`AuditLog::sessions_with_latest_run`]
/// accepts any number of ids and issues as many chunks as it needs.
const SESSION_LOOKUP_CHUNK: usize = 256;

/// What the UI's per-VM join needs to know about one session.
///
/// Both fields are `Option` and they are independently absent: a
/// session may have no audit row at all (the daemon knows about a VM
/// the log has not seen), and a session with a row may have no run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionRunSummary {
    pub session: Option<SessionRecord>,
    pub latest_run_id: Option<AgentRunId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentVmWorkspaceBootstrapAuditRecord {
    pub session_id: SessionId,
    pub requested_at: UnixMillis,
    pub repo: String,
    pub destination: String,
    pub branch: String,
    pub warm: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRunAuditRecord {
    pub run_id: AgentRunId,
    pub session_id: SessionId,
    pub requested_at: UnixMillis,
    pub agent_kind: AgentKind,
    pub prompt: AgentPromptSummary,
    /// Opaque caller-supplied correlation id. `None` for runs that
    /// were not tagged at request time. The orchestrator decides the
    /// semantics; the broker treats it as a join key.
    pub correlation_id: Option<CorrelationId>,
    /// Opaque caller-supplied tag saying what the run was *for*, as
    /// supplied on `RunAgent`.
    ///
    /// `None` has two truthful readings, and neither is "the caller
    /// declined to say": the run predates migration 8, or it was
    /// started through `StartAgentRun`, which carries a correlation id
    /// but has no purpose field. Rows written by `RunAgent` always
    /// carry `Some`, because the wire type is non-optional.
    pub purpose: Option<RunPurpose>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRunOutcomeAuditRecord {
    pub completed_at: UnixMillis,
    pub outcome: AgentRunOutcome,
}

/// Field validation for an agent-run request row, run before any transaction
/// opens (mirrors the pre-tx validation the proxy/flake DAOs do). The prompt
/// byte length is range-checked at insert time (it feeds a param), so it is not
/// re-checked here.
fn validate_agent_run_request(r: &AgentRunAuditRecord) -> Result<(), AuditError> {
    validate_sha256_hex(&r.prompt.sha256_hex, "agent run prompt sha256")?;
    if r.prompt.redacted_preview.is_empty() {
        return Err(AuditError::Invariant(
            "agent run prompt redacted preview must not be empty",
        ));
    }
    Ok(())
}

/// Insert one agent-run request row. Assumes [`validate_agent_run_request`]
/// passed and `check_session_open` ran.
fn insert_agent_run_request_row(
    conn: &Connection,
    r: &AgentRunAuditRecord,
) -> Result<(), AuditError> {
    conn.execute(
        "INSERT INTO agent_run (
             run_id,
             session_id,
             requested_at,
             agent_kind,
             prompt_bytes,
             prompt_sha256,
             prompt_redacted_preview,
             correlation_id,
             purpose
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            r.run_id.as_uuid().to_string(),
            r.session_id.as_uuid().to_string(),
            r.requested_at.as_millis(),
            r.agent_kind.as_str(),
            u64_to_sql_i64(r.prompt.byte_len, "agent run prompt bytes")?,
            &r.prompt.sha256_hex,
            &r.prompt.redacted_preview,
            r.correlation_id.as_ref().map(CorrelationId::as_str),
            r.purpose.as_ref().map(RunPurpose::as_str),
        ],
    )?;
    Ok(())
}

/// Validate and insert one agent-run outcome row. The stream-summary checks are
/// the outcome's only validation, so — unlike the request — there is no separate
/// pre-tx `validate` step to hoist.
fn insert_agent_run_outcome_row(
    conn: &Connection,
    r: &AgentRunOutcomeAuditRecord,
) -> Result<(), AuditError> {
    validate_stream_summary(&r.outcome.stdout, "stdout")?;
    validate_stream_summary(&r.outcome.stderr, "stderr")?;
    conn.execute(
        "INSERT INTO agent_run_outcome (
             run_id,
             completed_at,
             status,
             exit_code,
             stdout_path,
             stdout_bytes,
             stdout_sha256,
             stdout_truncated,
             stdout_stopped_at_deadline,
             stderr_path,
             stderr_bytes,
             stderr_sha256,
             stderr_truncated,
             stderr_stopped_at_deadline
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            r.outcome.run_id.as_uuid().to_string(),
            r.completed_at.as_millis(),
            agent_run_status_str(&r.outcome.status),
            r.outcome.exit_code,
            path_to_sql_text(&r.outcome.stdout.path, "stdout path")?,
            u64_to_sql_i64(r.outcome.stdout.byte_len, "stdout bytes")?,
            &r.outcome.stdout.sha256_hex,
            bool_to_sql_i64(r.outcome.stdout.truncated),
            bool_to_sql_i64(r.outcome.stdout.stopped_at_deadline),
            path_to_sql_text(&r.outcome.stderr.path, "stderr path")?,
            u64_to_sql_i64(r.outcome.stderr.byte_len, "stderr bytes")?,
            &r.outcome.stderr.sha256_hex,
            bool_to_sql_i64(r.outcome.stderr.truncated),
            bool_to_sql_i64(r.outcome.stderr.stopped_at_deadline),
        ],
    )?;
    Ok(())
}

/// Marker selecting the agent-run `(request, outcome)` pair for the generic
/// [`EffectAuditTable`](crate::effect_table::EffectAuditTable) guard. Zero-sized;
/// named only as a type argument.
///
/// Agent-runs are the *outcome-only* durability shape: the request row is minted
/// at run launch (`record_agent_run`) and only the outcome arrives at the outcome
/// endpoint, which therefore
/// [resumes](crate::AuditLog::resume_effect) the launch row rather than beginning
/// a second one — hence the [`OutcomeOnlyEffect`](crate::OutcomeOnlyEffect) impl
/// below. The two-phase
/// `begin_effect` + `complete` path also models launch-then-outcome, which is what
/// the equivalence proptest exercises against the direct writers.
pub struct AgentRunAuditTable;

impl crate::effect_table::sealed::Sealed for AgentRunAuditTable {}
impl crate::effect_table::EffectAuditTable for AgentRunAuditTable {
    // Both records own their fields, so neither row borrows.
    type RequestRow<'a> = AgentRunAuditRecord;
    type OutcomeRow<'a> = AgentRunOutcomeAuditRecord;
    type Key = AgentRunId;
    const REQUEST_TABLE: &'static str = "agent_run";
    const OUTCOME_TABLE: &'static str = "agent_run_outcome";
    const LABEL: &'static str = "Agent run";

    fn insert_request(conn: &Connection, row: &Self::RequestRow<'_>) -> Result<(), AuditError> {
        validate_agent_run_request(row)?;
        insert_agent_run_request_row(conn, row)
    }
    fn insert_outcome(conn: &Connection, row: &Self::OutcomeRow<'_>) -> Result<(), AuditError> {
        insert_agent_run_outcome_row(conn, row)
    }
    fn session_id(row: &Self::RequestRow<'_>) -> SessionId {
        row.session_id
    }
    fn request_key(row: &Self::RequestRow<'_>) -> AgentRunId {
        row.run_id
    }
    // The outcome record carries its run id nested in the `AgentRunOutcome`.
    fn outcome_key(row: &Self::OutcomeRow<'_>) -> AgentRunId {
        row.outcome.run_id
    }
}

impl crate::effect_table::OutcomeOnlyEffect for AgentRunAuditTable {
    fn request_row_exists(conn: &Connection, key: &AgentRunId) -> Result<bool, AuditError> {
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM agent_run WHERE run_id = ?1",
                params![key.as_uuid().to_string()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    fn outcome_row_exists(conn: &Connection, key: &AgentRunId) -> Result<bool, AuditError> {
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM agent_run_outcome WHERE run_id = ?1",
                params![key.as_uuid().to_string()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// The run id's UUID text. Injective, as `claim_token` requires.
    fn claim_token(key: &AgentRunId) -> String {
        key.as_uuid().to_string()
    }
}

/// An outcome upload that performed its filesystem work but cannot record a
/// truthful outcome — a log-directory or stream write that failed — must
/// [`abandon`](crate::RecordedRequest::abandon) rather than fabricate one. This
/// is not merely the usual "a fabricated row corrupts the log" argument: the
/// outcome row's primary key is the run id, so a fabricated failure row would
/// consume the run's *only* outcome slot and permanently prevent the real
/// outcome from ever being recorded. Leaving the launch row unpaired is exactly
/// what a run whose outcome has not arrived looks like, and the guest can retry.
impl crate::effect_table::AbandonableEffect for AgentRunAuditTable {}

impl AuditLog {
    pub fn record_agent_vm_workspace_bootstrap(
        &self,
        r: &AgentVmWorkspaceBootstrapAuditRecord,
    ) -> Result<(), AuditError> {
        if r.repo.is_empty() {
            return Err(AuditError::Invariant(
                "agent VM workspace repo must not be empty",
            ));
        }
        if r.destination.is_empty() {
            return Err(AuditError::Invariant(
                "agent VM workspace destination must not be empty",
            ));
        }
        if r.branch.is_empty() {
            return Err(AuditError::Invariant(
                "agent VM workspace branch must not be empty",
            ));
        }
        if !matches!(r.warm.as_str(), "none" | "sources" | "devshell") {
            return Err(AuditError::Invariant(
                "agent VM workspace warm mode is invalid",
            ));
        }

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            crate::validation::check_session_open(&tx, r.session_id)?;

            tx.execute(
                "INSERT INTO agent_vm_workspace_bootstrap (
                     session_id,
                     requested_at,
                     repo,
                     destination,
                     branch,
                     warm
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    r.session_id.as_uuid().to_string(),
                    r.requested_at.as_millis(),
                    &r.repo,
                    &r.destination,
                    &r.branch,
                    &r.warm,
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn get_agent_vm_workspace_bootstrap(
        &self,
        id: SessionId,
    ) -> Result<Option<AgentVmWorkspaceBootstrapAuditRecord>, AuditError> {
        self.with_conn(|c| {
            c.query_row(
                "SELECT session_id, requested_at, repo, destination, branch, warm
                 FROM agent_vm_workspace_bootstrap
                 WHERE session_id = ?1",
                params![id.as_uuid().to_string()],
                agent_vm_workspace_bootstrap_from_row,
            )
            .optional()
            .map_err(AuditError::from)
        })
    }

    pub fn record_agent_run(&self, r: &AgentRunAuditRecord) -> Result<(), AuditError> {
        validate_agent_run_request(r)?;
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            crate::validation::check_session_open(&tx, r.session_id)?;
            insert_agent_run_request_row(&tx, r)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn record_agent_run_outcome(
        &self,
        r: &AgentRunOutcomeAuditRecord,
    ) -> Result<(), AuditError> {
        self.with_conn_mut(|c| insert_agent_run_outcome_row(c, r))
    }

    pub fn get_agent_run(
        &self,
        run_id: AgentRunId,
    ) -> Result<Option<AgentRunAuditRecord>, AuditError> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT run_id, session_id, requested_at, agent_kind, prompt_bytes,
                            prompt_sha256, prompt_redacted_preview, correlation_id,
                            purpose
                     FROM agent_run
                     WHERE run_id = ?1",
                    params![run_id.as_uuid().to_string()],
                    agent_run_from_row,
                )
                .optional()?;
            row.transpose()
        })
    }

    pub fn get_agent_run_outcome(
        &self,
        run_id: AgentRunId,
    ) -> Result<Option<AgentRunOutcomeAuditRecord>, AuditError> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT run_id, completed_at, status, exit_code,
                            stdout_path, stdout_bytes, stdout_sha256, stdout_truncated,
                            stdout_stopped_at_deadline,
                            stderr_path, stderr_bytes, stderr_sha256, stderr_truncated,
                            stderr_stopped_at_deadline
                     FROM agent_run_outcome
                     WHERE run_id = ?1",
                    params![run_id.as_uuid().to_string()],
                    agent_run_outcome_from_row,
                )
                .optional()?;
            row.transpose()
        })
    }

    /// Most-recent `agent_run.run_id` for a session — by `requested_at`
    /// descending, with `run_id` as a tiebreak so the answer does not
    /// depend on SQLite's unspecified tie order (see the
    /// `LATEST_RUN_ORDER` constant). `None` if no run row exists. Used by the UI
    /// HTTP join to give the operator a stable handle to follow from a
    /// VM into a run view; the run itself is exposed through
    /// `/v1/agent-runs/<id>` and not inlined here.
    pub fn latest_agent_run_id_for_session(
        &self,
        session_id: SessionId,
    ) -> Result<Option<AgentRunId>, AuditError> {
        self.with_conn(|c| {
            let raw: Option<String> = c
                .query_row(
                    &format!(
                        "SELECT run_id FROM agent_run
                         WHERE session_id = ?1
                         ORDER BY {LATEST_RUN_ORDER}
                         LIMIT 1"
                    ),
                    params![session_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            raw.map(|s| {
                uuid::Uuid::parse_str(&s)
                    .map(AgentRunId::from_uuid)
                    .map_err(|_| AuditError::Invariant("agent run row: run_id not a uuid"))
            })
            .transpose()
        })
    }

    /// Lookup of the `correlation_id` belonging to an agent run on the
    /// given session. Returns `None` for sessions with no agent run
    /// (e.g. raw `start_agent_vm_session` flows) or with an untagged
    /// run. The VM HTTP git-push handler uses this to inherit the
    /// correlation id from the run onto the push it stages, so a
    /// `--correlation-id`'d run's pushes share the same join key.
    ///
    /// Today's product flow creates one run per session. Ordering by
    /// `requested_at` descending with a `run_id` tiebreak (the
    /// `LATEST_RUN_ORDER` constant) is defensive against a future N>1
    /// case so the answer stays deterministic; if the invariant is ever
    /// loosened, the policy "most recent run wins" is the obvious one
    /// and the audit row stores everything needed to revisit it.
    pub fn correlation_id_for_session(
        &self,
        session_id: SessionId,
    ) -> Result<Option<CorrelationId>, AuditError> {
        self.with_conn(|c| {
            let raw: Option<Option<String>> = c
                .query_row(
                    &format!(
                        "SELECT correlation_id FROM agent_run
                         WHERE session_id = ?1
                         ORDER BY {LATEST_RUN_ORDER}
                         LIMIT 1"
                    ),
                    params![session_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            match raw.flatten() {
                None => Ok(None),
                Some(value) => CorrelationId::try_new(value)
                    .map(Some)
                    .map_err(|_| AuditError::Invariant("agent run row: correlation_id is invalid")),
            }
        })
    }

    /// The most-recently-requested `agent_run` belonging to a session,
    /// or `None` if the session has no run.
    ///
    /// Today the product invariant is one run per session; ordering by
    /// `requested_at` descending with a `run_id` tiebreak (the
    /// `LATEST_RUN_ORDER` constant) is defensive against a future N>1
    /// case so the answer stays deterministic. "Most recent run wins" matches
    /// the corresponding choice in
    /// [`Self::correlation_id_for_session`].
    pub fn agent_run_for_session(
        &self,
        session_id: SessionId,
    ) -> Result<Option<AgentRunAuditRecord>, AuditError> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    &format!(
                        "SELECT run_id, session_id, requested_at, agent_kind, prompt_bytes,
                                prompt_sha256, prompt_redacted_preview, correlation_id,
                                purpose
                         FROM agent_run
                         WHERE session_id = ?1
                         ORDER BY {LATEST_RUN_ORDER}
                         LIMIT 1"
                    ),
                    params![session_id.as_uuid().to_string()],
                    agent_run_from_row,
                )
                .optional()?;
            row.transpose()
        })
    }

    /// The session row and latest run id for many sessions, in a bounded
    /// number of queries rather than two per session.
    ///
    /// Equivalent to calling [`Self::get_session`] and
    /// [`Self::latest_agent_run_id_for_session`] for each id — that
    /// equivalence is the property the tests assert, against those
    /// methods as the reference. Ids absent from the log map to a
    /// `SessionRunSummary` with both fields `None`, so the returned map
    /// has an entry for every id asked about and a caller never has to
    /// distinguish "not in the map" from "nothing recorded".
    ///
    /// The UI's `/v1/agent-vms` list is the reason this exists: it
    /// joins one row per live VM, and doing that per-session meant two
    /// SQLite round trips *and two mutex acquisitions* per VM on every
    /// request.
    pub fn sessions_with_latest_run(
        &self,
        ids: &[SessionId],
    ) -> Result<HashMap<SessionId, SessionRunSummary>, AuditError> {
        let chunk = NonZeroUsize::new(SESSION_LOOKUP_CHUNK).expect("chunk size is a nonzero const");
        self.sessions_with_latest_run_chunked(ids, chunk)
    }

    /// [`Self::sessions_with_latest_run`] with the chunk size exposed.
    ///
    /// Separate so the chunking can be tested at sizes that actually
    /// split the input. The production constant is 256, and a test that
    /// crossed it would have to insert hundreds of sessions to exercise
    /// a single boundary — so it would not be written, and the
    /// multi-chunk path would go unexercised.
    fn sessions_with_latest_run_chunked(
        &self,
        ids: &[SessionId],
        chunk: NonZeroUsize,
    ) -> Result<HashMap<SessionId, SessionRunSummary>, AuditError> {
        // Seeded with every id up front. The queries below only *fill
        // in* what they find, so an id with no session row and no run
        // still gets its (None, None) entry without a second pass.
        let mut out: HashMap<SessionId, SessionRunSummary> = ids
            .iter()
            .map(|id| (*id, SessionRunSummary::default()))
            .collect();
        if out.is_empty() {
            return Ok(out);
        }

        self.with_conn(|c| {
            for window in ids.chunks(chunk.get()) {
                let placeholders = std::iter::repeat_n("?", window.len())
                    .collect::<Vec<_>>()
                    .join(", ");
                let params: Vec<String> =
                    window.iter().map(|id| id.as_uuid().to_string()).collect();
                let params: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

                let mut stmt = c.prepare(&format!(
                    "SELECT session_id, label, agent_kind, agent_model, opened_at, closed_at
                     FROM session WHERE session_id IN ({placeholders})"
                ))?;
                for row in stmt.query_map(params.as_slice(), super::session::session_from_row)? {
                    let record = row?;
                    let id = record.session_id;
                    out.entry(id).or_default().session = Some(record);
                }

                // `ROW_NUMBER()` rather than `GROUP BY … HAVING MAX(…)`:
                // the bare-column form leaves the tiebreak to SQLite,
                // which is exactly the non-determinism `LATEST_RUN_ORDER`
                // exists to remove, and would let this disagree with the
                // per-session lookups it must match.
                let mut stmt = c.prepare(&format!(
                    "SELECT session_id, run_id FROM (
                         SELECT session_id, run_id,
                                ROW_NUMBER() OVER (
                                    PARTITION BY session_id
                                    ORDER BY {LATEST_RUN_ORDER}
                                ) AS rn
                         FROM agent_run WHERE session_id IN ({placeholders})
                     ) WHERE rn = 1"
                ))?;
                for row in stmt.query_map(params.as_slice(), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })? {
                    let (session_raw, run_raw) = row?;
                    let session_id = uuid::Uuid::parse_str(&session_raw)
                        .map(SessionId::from_uuid)
                        .map_err(|_| {
                            AuditError::Invariant("agent run row: session_id not a uuid")
                        })?;
                    let run_id = uuid::Uuid::parse_str(&run_raw)
                        .map(AgentRunId::from_uuid)
                        .map_err(|_| AuditError::Invariant("agent run row: run_id not a uuid"))?;
                    out.entry(session_id).or_default().latest_run_id = Some(run_id);
                }
            }
            Ok(())
        })?;

        Ok(out)
    }
}

fn agent_vm_workspace_bootstrap_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<AgentVmWorkspaceBootstrapAuditRecord> {
    let session_id: uuid::Uuid = row.get::<_, String>(0)?.parse().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(AgentVmWorkspaceBootstrapAuditRecord {
        session_id: SessionId::from_uuid(session_id),
        requested_at: UnixMillis::from_millis(row.get(1)?),
        repo: row.get(2)?,
        destination: row.get(3)?,
        branch: row.get(4)?,
        warm: row.get(5)?,
    })
}

fn agent_run_from_row(row: &Row<'_>) -> rusqlite::Result<Result<AgentRunAuditRecord, AuditError>> {
    let run_id_str: String = row.get(0)?;
    let session_id_str: String = row.get(1)?;
    let requested_at: i64 = row.get(2)?;
    let agent_kind: SqlAgentKind = row.get(3)?;
    let prompt_bytes: i64 = row.get(4)?;
    let prompt_sha256: String = row.get(5)?;
    let prompt_redacted_preview: String = row.get(6)?;
    let correlation_id_raw: Option<String> = row.get(7)?;
    let purpose_raw: Option<String> = row.get(8)?;

    let parse = || -> Result<AgentRunAuditRecord, AuditError> {
        let run_id = uuid::Uuid::parse_str(&run_id_str)
            .map_err(|_| AuditError::Invariant("agent run row: run_id not a uuid"))?;
        let session_id = uuid::Uuid::parse_str(&session_id_str)
            .map_err(|_| AuditError::Invariant("agent run row: session_id not a uuid"))?;
        let prompt_bytes = u64::try_from(prompt_bytes)
            .map_err(|_| AuditError::Invariant("agent run prompt bytes is negative"))?;
        validate_sha256_hex(&prompt_sha256, "agent run prompt sha256")?;
        if prompt_redacted_preview.is_empty() {
            return Err(AuditError::Invariant(
                "agent run prompt redacted preview is empty",
            ));
        }
        let correlation_id = correlation_id_raw
            .map(CorrelationId::try_new)
            .transpose()
            .map_err(|_| AuditError::Invariant("agent run row: correlation_id is invalid"))?;
        let purpose = purpose_raw
            .map(RunPurpose::try_new)
            .transpose()
            .map_err(|_| AuditError::Invariant("agent run row: purpose is invalid"))?;
        Ok(AgentRunAuditRecord {
            run_id: AgentRunId::from_uuid(run_id),
            session_id: SessionId::from_uuid(session_id),
            requested_at: UnixMillis::from_millis(requested_at),
            agent_kind: agent_kind.into_inner(),
            prompt: AgentPromptSummary {
                byte_len: prompt_bytes,
                sha256_hex: prompt_sha256,
                redacted_preview: prompt_redacted_preview,
            },
            correlation_id,
            purpose,
        })
    };
    Ok(parse())
}

fn agent_run_outcome_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<Result<AgentRunOutcomeAuditRecord, AuditError>> {
    let run_id_str: String = row.get(0)?;
    let completed_at: i64 = row.get(1)?;
    let status: String = row.get(2)?;
    let exit_code: i32 = row.get(3)?;
    let stdout_path: String = row.get(4)?;
    let stdout_bytes: i64 = row.get(5)?;
    let stdout_sha256: String = row.get(6)?;
    let stdout_truncated: i64 = row.get(7)?;
    let stdout_stopped_at_deadline: i64 = row.get(8)?;
    let stderr_path: String = row.get(9)?;
    let stderr_bytes: i64 = row.get(10)?;
    let stderr_sha256: String = row.get(11)?;
    let stderr_truncated: i64 = row.get(12)?;
    let stderr_stopped_at_deadline: i64 = row.get(13)?;

    let parse = || -> Result<AgentRunOutcomeAuditRecord, AuditError> {
        let run_id = uuid::Uuid::parse_str(&run_id_str)
            .map_err(|_| AuditError::Invariant("agent run outcome row: run_id not a uuid"))?;
        let run_id = AgentRunId::from_uuid(run_id);
        let status = agent_run_status_from_str(&status)?;
        let stdout = agent_run_stream_from_sql(
            stdout_path,
            stdout_bytes,
            stdout_sha256,
            stdout_truncated,
            stdout_stopped_at_deadline,
            "stdout",
        )?;
        let stderr = agent_run_stream_from_sql(
            stderr_path,
            stderr_bytes,
            stderr_sha256,
            stderr_truncated,
            stderr_stopped_at_deadline,
            "stderr",
        )?;
        Ok(AgentRunOutcomeAuditRecord {
            completed_at: UnixMillis::from_millis(completed_at),
            outcome: AgentRunOutcome {
                run_id,
                status,
                exit_code,
                stdout,
                stderr,
            },
        })
    };
    Ok(parse())
}

fn agent_run_stream_from_sql(
    path: String,
    byte_len: i64,
    sha256_hex: String,
    truncated: i64,
    stopped_at_deadline: i64,
    label: &'static str,
) -> Result<AgentRunStreamSummary, AuditError> {
    validate_agent_run_stream_path_text(&path, label)?;
    let byte_len = u64::try_from(byte_len)
        .map_err(|_| labeled_invariant(label, "agent run stream bytes is negative"))?;
    validate_sha256_hex(&sha256_hex, label)?;
    let truncated = agent_run_stream_flag_from_sql(truncated, label, "truncated")?;
    let stopped_at_deadline =
        agent_run_stream_flag_from_sql(stopped_at_deadline, label, "stopped_at_deadline")?;
    Ok(AgentRunStreamSummary {
        path: path.into(),
        byte_len,
        sha256_hex,
        truncated,
        stopped_at_deadline,
    })
}

/// Read one of a stream summary's boolean columns.
///
/// The CHECK constraints in the schema already confine these to 0 and 1, so a
/// third value means the row was not written by this code — a hand-edited DB, or
/// a future schema read by an older binary. Refused rather than coerced, which
/// is the same "correctness over availability" choice the version gate makes for
/// the DB as a whole.
fn agent_run_stream_flag_from_sql(
    raw: i64,
    label: &'static str,
    flag: &'static str,
) -> Result<bool, AuditError> {
    match raw {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(labeled_invariant(
            label,
            match flag {
                "truncated" => "agent run stream truncated flag is invalid",
                _ => "agent run stream stopped_at_deadline flag is invalid",
            },
        )),
    }
}

fn agent_run_status_str(status: &AgentRunTerminalStatus) -> &'static str {
    match status {
        AgentRunTerminalStatus::Succeeded => "succeeded",
        AgentRunTerminalStatus::Failed => "failed",
        AgentRunTerminalStatus::TimedOut => "timed_out",
    }
}

fn agent_run_status_from_str(raw: &str) -> Result<AgentRunTerminalStatus, AuditError> {
    match raw {
        "succeeded" => Ok(AgentRunTerminalStatus::Succeeded),
        "failed" => Ok(AgentRunTerminalStatus::Failed),
        "timed_out" => Ok(AgentRunTerminalStatus::TimedOut),
        _ => Err(AuditError::Invariant("agent run status is invalid")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_session;
    use proptest::prelude::*;
    use rusqlite::params;
    use writ_core::core::{AgentKind, SessionRecord};

    /// Raw `agent_run` rows (every column, in insert order) for the guard/direct
    /// equivalence proptest — the agent-run analogue of `proxy_table`'s
    /// `dump_request_rows`.
    #[allow(clippy::type_complexity)]
    fn dump_agent_run_request_rows(
        log: &AuditLog,
    ) -> Vec<(
        String,
        String,
        i64,
        String,
        i64,
        String,
        String,
        Option<String>,
        Option<String>,
    )> {
        log.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT run_id, session_id, requested_at, agent_kind, prompt_bytes, \
                 prompt_sha256, prompt_redacted_preview, correlation_id, purpose \
                 FROM agent_run ORDER BY rowid",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
    }

    /// One `agent_run_outcome` row, every column, in insert order.
    ///
    /// A named struct rather than a tuple because there are more columns than
    /// the standard library derives `Debug`/`PartialEq` for — and because a
    /// failure here should say *which* column diverged rather than print
    /// fourteen positional values.
    #[derive(Debug, Eq, PartialEq)]
    struct AgentRunOutcomeRow {
        run_id: String,
        completed_at: i64,
        status: String,
        exit_code: i64,
        stdout_path: String,
        stdout_bytes: i64,
        stdout_sha256: String,
        stdout_truncated: i64,
        stdout_stopped_at_deadline: i64,
        stderr_path: String,
        stderr_bytes: i64,
        stderr_sha256: String,
        stderr_truncated: i64,
        stderr_stopped_at_deadline: i64,
    }

    fn dump_agent_run_outcome_rows(log: &AuditLog) -> Vec<AgentRunOutcomeRow> {
        log.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT run_id, completed_at, status, exit_code, \
                 stdout_path, stdout_bytes, stdout_sha256, stdout_truncated, \
                 stdout_stopped_at_deadline, \
                 stderr_path, stderr_bytes, stderr_sha256, stderr_truncated, \
                 stderr_stopped_at_deadline \
                 FROM agent_run_outcome ORDER BY rowid",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(AgentRunOutcomeRow {
                        run_id: r.get(0)?,
                        completed_at: r.get(1)?,
                        status: r.get(2)?,
                        exit_code: r.get(3)?,
                        stdout_path: r.get(4)?,
                        stdout_bytes: r.get(5)?,
                        stdout_sha256: r.get(6)?,
                        stdout_truncated: r.get(7)?,
                        stdout_stopped_at_deadline: r.get(8)?,
                        stderr_path: r.get(9)?,
                        stderr_bytes: r.get(10)?,
                        stderr_sha256: r.get(11)?,
                        stderr_truncated: r.get(12)?,
                        stderr_stopped_at_deadline: r.get(13)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
    }

    #[test]
    fn agent_vm_workspace_bootstrap_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let record = AgentVmWorkspaceBootstrapAuditRecord {
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            repo: "owner/repo".into(),
            destination: "/workspace/repo".into(),
            branch: "main".into(),
            warm: "devshell".into(),
        };

        log.record_agent_vm_workspace_bootstrap(&record).unwrap();

        assert_eq!(
            log.get_agent_vm_workspace_bootstrap(s.session_id)
                .unwrap()
                .unwrap(),
            record
        );
    }

    #[test]
    fn agent_vm_workspace_bootstrap_requires_open_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        let record = AgentVmWorkspaceBootstrapAuditRecord {
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            repo: "owner/repo".into(),
            destination: "/workspace/repo".into(),
            branch: "main".into(),
            warm: "none".into(),
        };

        let err = log
            .record_agent_vm_workspace_bootstrap(&record)
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("session does not exist")
        ));

        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_200))
            .unwrap();
        let err = log
            .record_agent_vm_workspace_bootstrap(&record)
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant("session is closed")));
    }

    #[test]
    fn agent_run_and_outcome_roundtrip_without_raw_prompt_or_streams_in_audit() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let prompt = writ_agent_run::AgentPrompt::new("SECRET prompt body");
        let run_id = AgentRunId::new();
        let record = AgentRunAuditRecord {
            run_id,
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: prompt.summary(),
            correlation_id: None,
            purpose: None,
        };

        log.record_agent_run(&record).unwrap();

        let entry = log.get_agent_run(run_id).unwrap().unwrap();
        assert_eq!(entry.run_id, run_id);
        assert_eq!(entry.session_id, s.session_id);
        assert_eq!(entry.agent_kind, AgentKind::Claude);
        assert_eq!(entry.prompt.byte_len, prompt.byte_len());
        assert_eq!(entry.prompt.redacted_preview, "<redacted>");
        assert!(entry.correlation_id.is_none());
        let debug = format!("{entry:?}");
        assert!(!debug.contains(prompt.as_str()), "{debug}");

        let outcome = AgentRunOutcome {
            run_id,
            status: AgentRunTerminalStatus::Failed,
            exit_code: 7,
            stdout: AgentRunStreamSummary {
                path: "/private/writ/runs/stdout.log".into(),
                byte_len: 12,
                sha256_hex: writ_agent_run::sha256_hex(b"stdout bytes"),
                truncated: false,
                stopped_at_deadline: false,
            },
            stderr: AgentRunStreamSummary {
                path: "/private/writ/runs/stderr.log".into(),
                byte_len: 4096,
                sha256_hex: writ_agent_run::sha256_hex(b"stderr bytes"),
                truncated: true,
                stopped_at_deadline: false,
            },
        };
        let outcome_record = AgentRunOutcomeAuditRecord {
            completed_at: UnixMillis::from_millis(1_700_000_200),
            outcome: outcome.clone(),
        };

        log.record_agent_run_outcome(&outcome_record).unwrap();

        let entry = log.get_agent_run_outcome(run_id).unwrap().unwrap();
        assert_eq!(entry.outcome.run_id, run_id);
        assert_eq!(entry.outcome, outcome);
    }

    #[test]
    fn agent_run_requires_open_session_but_outcome_can_land_after_close() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        let run_id = AgentRunId::new();
        let record = AgentRunAuditRecord {
            run_id,
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Codex,
            prompt: writ_agent_run::AgentPrompt::new("prompt").summary(),
            correlation_id: None,
            purpose: None,
        };

        let err = log.record_agent_run(&record).unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("session does not exist")
        ));

        log.open_session(&s).unwrap();
        log.record_agent_run(&record).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_150))
            .unwrap();

        let outcome = AgentRunOutcome {
            run_id,
            status: AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: AgentRunStreamSummary {
                path: "/private/writ/runs/stdout.log".into(),
                byte_len: 0,
                sha256_hex: writ_agent_run::sha256_hex(b""),
                truncated: false,
                stopped_at_deadline: false,
            },
            stderr: AgentRunStreamSummary {
                path: "/private/writ/runs/stderr.log".into(),
                byte_len: 0,
                sha256_hex: writ_agent_run::sha256_hex(b""),
                truncated: false,
                stopped_at_deadline: false,
            },
        };

        log.record_agent_run_outcome(&AgentRunOutcomeAuditRecord {
            completed_at: UnixMillis::from_millis(1_700_000_200),
            outcome,
        })
        .unwrap();

        let closed_run = AgentRunAuditRecord {
            run_id: AgentRunId::new(),
            ..record
        };
        let err = log.record_agent_run(&closed_run).unwrap_err();
        assert!(matches!(err, AuditError::Invariant("session is closed")));
    }

    #[test]
    fn agent_run_validation_errors_name_the_failed_field() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let err = log
            .record_agent_run(&AgentRunAuditRecord {
                run_id: AgentRunId::new(),
                session_id: s.session_id,
                requested_at: UnixMillis::from_millis(1_700_000_100),
                agent_kind: AgentKind::Claude,
                prompt: AgentPromptSummary {
                    byte_len: 1,
                    sha256_hex: "not sha256".to_string(),
                    redacted_preview: "<redacted>".to_string(),
                },
                correlation_id: None,
                purpose: None,
            })
            .unwrap_err();

        assert!(matches!(
            err,
            AuditError::LabeledInvariant {
                label: "agent run prompt sha256",
                message: "sha256 hex digest is invalid",
            }
        ));

        let err = log
            .record_agent_run_outcome(&AgentRunOutcomeAuditRecord {
                completed_at: UnixMillis::from_millis(1_700_000_200),
                outcome: AgentRunOutcome {
                    run_id: AgentRunId::new(),
                    status: AgentRunTerminalStatus::Succeeded,
                    exit_code: 0,
                    stdout: AgentRunStreamSummary {
                        path: "relative/stdout.log".into(),
                        byte_len: 0,
                        sha256_hex: writ_agent_run::sha256_hex(b""),
                        truncated: false,
                        stopped_at_deadline: false,
                    },
                    stderr: AgentRunStreamSummary {
                        path: "/private/writ/runs/stderr.log".into(),
                        byte_len: 0,
                        sha256_hex: writ_agent_run::sha256_hex(b""),
                        truncated: false,
                        stopped_at_deadline: false,
                    },
                },
            })
            .unwrap_err();

        assert!(matches!(
            err,
            AuditError::LabeledInvariant {
                label: "stdout",
                message: "agent run stream path must be absolute",
            }
        ));
    }

    #[test]
    fn agent_run_roundtrips_with_correlation_id() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let run_id = AgentRunId::new();
        let correlation = CorrelationId::try_new("feature-42_xyz").unwrap();
        let record = AgentRunAuditRecord {
            run_id,
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: writ_agent_run::AgentPrompt::new("prompt").summary(),
            correlation_id: Some(correlation.clone()),
            purpose: None,
        };

        log.record_agent_run(&record).unwrap();
        let entry = log.get_agent_run(run_id).unwrap().unwrap();
        assert_eq!(entry.correlation_id, Some(correlation));
    }

    /// A pre-migration-14 row (NULL correlation_id) round-trips as
    /// `None`; reading back an old row must not surface a parse error.
    #[test]
    fn agent_run_correlation_id_null_surfaces_as_none() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let run_id = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id,
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: writ_agent_run::AgentPrompt::new("prompt").summary(),
            correlation_id: None,
            purpose: None,
        })
        .unwrap();
        let entry = log.get_agent_run(run_id).unwrap().unwrap();
        assert!(entry.correlation_id.is_none());
    }

    /// The DB's CHECK constraint is the belt-and-braces line of
    /// defence: even if a future code path bypasses
    /// `CorrelationId::try_new`, raw bytes outside the allowed class
    /// cannot land. We exercise the constraint directly via a raw
    /// INSERT to keep the test honest about which layer is rejecting.
    #[test]
    fn agent_run_correlation_id_check_constraint_rejects_invalid_bytes() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let run_id = AgentRunId::new();
        let err = log
            .with_conn_mut(|c| {
                c.execute(
                    "INSERT INTO agent_run (
                         run_id, session_id, requested_at, agent_kind,
                         prompt_bytes, prompt_sha256, prompt_redacted_preview,
                         correlation_id
                     ) VALUES (?1, ?2, ?3, 'claude', 1, ?4, '<redacted>', ?5)",
                    params![
                        run_id.as_uuid().to_string(),
                        s.session_id.as_uuid().to_string(),
                        1_700_000_100i64,
                        writ_agent_run::sha256_hex(b"x"),
                        "bad space",
                    ],
                )
                .map_err(AuditError::from)
            })
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CHECK"), "got: {msg}");

        let too_long = "a".repeat(65);
        let err_len = log
            .with_conn_mut(|c| {
                c.execute(
                    "INSERT INTO agent_run (
                         run_id, session_id, requested_at, agent_kind,
                         prompt_bytes, prompt_sha256, prompt_redacted_preview,
                         correlation_id
                     ) VALUES (?1, ?2, ?3, 'claude', 1, ?4, '<redacted>', ?5)",
                    params![
                        AgentRunId::new().as_uuid().to_string(),
                        s.session_id.as_uuid().to_string(),
                        1_700_000_101i64,
                        writ_agent_run::sha256_hex(b"y"),
                        too_long,
                    ],
                )
                .map_err(AuditError::from)
            })
            .unwrap_err();
        let msg_len = err_len.to_string();
        assert!(msg_len.contains("CHECK"), "got: {msg_len}");
    }

    /// A purpose round-trips verbatim, including the characters that
    /// forced it to be its own column rather than a second
    /// `correlation_id`: the colon in bailiff's `review:plan-abc`, and
    /// the spaces in an operator's free text.
    #[test]
    fn agent_run_roundtrips_with_purpose() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        for raw in ["plan-submit", "review:plan-abc", "review of plan #3"] {
            let run_id = AgentRunId::new();
            let purpose = RunPurpose::try_new(raw).unwrap();
            log.record_agent_run(&AgentRunAuditRecord {
                run_id,
                session_id: s.session_id,
                requested_at: UnixMillis::from_millis(1_700_000_100),
                agent_kind: AgentKind::Claude,
                prompt: writ_agent_run::AgentPrompt::new("prompt").summary(),
                correlation_id: None,
                purpose: Some(purpose.clone()),
            })
            .unwrap();

            let entry = log.get_agent_run(run_id).unwrap().unwrap();
            assert_eq!(entry.purpose, Some(purpose));
            assert_eq!(
                entry.purpose.as_ref().map(RunPurpose::as_str),
                Some(raw),
                "the audit row must store the caller's bytes unchanged",
            );
        }
    }

    /// A pre-migration-8 row (NULL purpose) reads back as `None` rather
    /// than as a parse error. The same shape a `StartAgentRun`-launched
    /// run has permanently, since that RPC has no purpose to give.
    #[test]
    fn agent_run_purpose_null_surfaces_as_none() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let run_id = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id,
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: writ_agent_run::AgentPrompt::new("prompt").summary(),
            correlation_id: None,
            purpose: None,
        })
        .unwrap();
        assert!(
            log.get_agent_run(run_id)
                .unwrap()
                .unwrap()
                .purpose
                .is_none()
        );
    }

    /// The CHECK constraint is an exact mirror of `RunPurpose::try_new`,
    /// so a code path that bypassed the type could still not land a
    /// value the reader would later refuse to parse. Driven through a
    /// raw INSERT so it is unambiguous which layer rejects.
    ///
    /// The NUL case is the one worth spelling out: SQLite's `length()`
    /// and `GLOB` both stop at the first NUL, so the byte-length clause
    /// (`length(cast(purpose AS BLOB)) = length(purpose)`) is the only
    /// thing standing between the column and an embedded NUL.
    #[test]
    fn agent_run_purpose_check_constraint_mirrors_the_parser() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let insert_raw = |value: &str| -> Result<(), AuditError> {
            log.with_conn_mut(|c| {
                c.execute(
                    "INSERT INTO agent_run (
                         run_id, session_id, requested_at, agent_kind,
                         prompt_bytes, prompt_sha256, prompt_redacted_preview,
                         correlation_id, purpose
                     ) VALUES (?1, ?2, ?3, 'claude', 1, ?4, '<redacted>', NULL, ?5)",
                    params![
                        AgentRunId::new().as_uuid().to_string(),
                        s.session_id.as_uuid().to_string(),
                        1_700_000_100i64,
                        writ_agent_run::sha256_hex(b"x"),
                        value,
                    ],
                )
                .map(|_| ())
                .map_err(AuditError::from)
            })
        };

        for bad in [
            "",                   // empty
            &"a".repeat(129),     // one over the cap
            "two\nlines",         // control character
            "tab\tseparated",     // control character
            "del\x7f",            // DEL is not printable
            "plan-\u{0430}",      // non-ASCII homoglyph
            "plan\u{200b}review", // zero-width space
            " leading",           // surrounding space
            "trailing ",          // surrounding space
            "nul\0byte",          // NUL: length() and GLOB are blind to it
        ] {
            let err = insert_raw(bad).expect_err(&format!("expected the CHECK to reject {bad:?}"));
            assert!(err.to_string().contains("CHECK"), "for {bad:?} got: {err}");
        }

        // ...and the values the parser accepts are accepted here too, so
        // the mirror is not merely strict in one direction.
        for ok in ["plan-submit", "review:plan-abc", "review of plan #3", "~"] {
            insert_raw(ok).unwrap_or_else(|e| panic!("expected {ok:?} to be accepted, got {e}"));
        }
    }

    /// `correlation_id_for_session` returns:
    ///   - `Some(id)` when the session's run was tagged,
    ///   - `None` when the run is untagged, and
    ///   - `None` when no run exists for the session at all (this is
    ///     the raw-VM-session case — `start_agent_vm_session` opens a
    ///     session without recording an `agent_run`).
    ///
    /// The VM git-push handler relies on the third case to leave the
    /// push correlation NULL for non-run flows.
    #[test]
    fn correlation_id_for_session_returns_run_value_or_none() {
        let log = AuditLog::open_in_memory().unwrap();

        // Session with no run — used by `start_agent_vm_session`.
        let no_run = sample_session();
        log.open_session(&no_run).unwrap();
        assert!(
            log.correlation_id_for_session(no_run.session_id)
                .unwrap()
                .is_none()
        );

        // Session whose run is untagged.
        let untagged = SessionRecord {
            session_id: SessionId::new(),
            ..sample_session()
        };
        log.open_session(&untagged).unwrap();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id: AgentRunId::new(),
            session_id: untagged.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: writ_agent_run::AgentPrompt::new("prompt").summary(),
            correlation_id: None,
            purpose: None,
        })
        .unwrap();
        assert!(
            log.correlation_id_for_session(untagged.session_id)
                .unwrap()
                .is_none()
        );

        // Session whose run carries a correlation id.
        let tagged = SessionRecord {
            session_id: SessionId::new(),
            ..sample_session()
        };
        log.open_session(&tagged).unwrap();
        let correlation = CorrelationId::try_new("feat-42_xyz").unwrap();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id: AgentRunId::new(),
            session_id: tagged.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_200),
            agent_kind: AgentKind::Claude,
            prompt: writ_agent_run::AgentPrompt::new("prompt").summary(),
            correlation_id: Some(correlation.clone()),
            purpose: None,
        })
        .unwrap();
        assert_eq!(
            log.correlation_id_for_session(tagged.session_id).unwrap(),
            Some(correlation)
        );
    }

    /// `agent_run_for_session` returns the latest run on a session and
    /// `None` when the session has no run.
    #[test]
    fn agent_run_for_session_returns_latest_run_or_none() {
        let log = AuditLog::open_in_memory().unwrap();
        let session = sample_session();
        log.open_session(&session).unwrap();

        // No run yet — returns None.
        assert!(
            log.agent_run_for_session(session.session_id)
                .unwrap()
                .is_none(),
        );

        // After recording two runs on the same session, the later one
        // wins (defensive against a future N>1 case).
        let earlier_run_id = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id: earlier_run_id,
            session_id: session.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: writ_agent_run::AgentPrompt::new("plan this").summary(),
            correlation_id: None,
            purpose: None,
        })
        .unwrap();
        let later_run_id = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id: later_run_id,
            session_id: session.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_200),
            agent_kind: AgentKind::Claude,
            prompt: writ_agent_run::AgentPrompt::new("review the plan").summary(),
            correlation_id: None,
            purpose: None,
        })
        .unwrap();

        let resolved = log
            .agent_run_for_session(session.session_id)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.run_id, later_run_id);

        // A session that is unknown to the audit log resolves to None.
        let other = SessionId::new();
        assert!(log.agent_run_for_session(other).unwrap().is_none());
    }

    #[test]
    fn latest_agent_run_id_returns_most_recent_or_none() {
        let log = AuditLog::open_in_memory().unwrap();

        // No run on the session.
        let bare = sample_session();
        log.open_session(&bare).unwrap();
        assert!(
            log.latest_agent_run_id_for_session(bare.session_id)
                .unwrap()
                .is_none()
        );

        // Two runs; the later requested_at wins regardless of insertion order.
        let session = SessionRecord {
            session_id: SessionId::new(),
            ..sample_session()
        };
        log.open_session(&session).unwrap();
        let earlier = AgentRunId::new();
        let later = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id: later,
            session_id: session.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_500),
            agent_kind: AgentKind::Claude,
            prompt: writ_agent_run::AgentPrompt::new("p").summary(),
            correlation_id: None,
            purpose: None,
        })
        .unwrap();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id: earlier,
            session_id: session.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: writ_agent_run::AgentPrompt::new("p").summary(),
            correlation_id: None,
            purpose: None,
        })
        .unwrap();
        assert_eq!(
            log.latest_agent_run_id_for_session(session.session_id)
                .unwrap(),
            Some(later)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// The generic guard's two-phase path (`begin_effect` + `complete`) must be
        /// behaviour-preserving for agent-runs: it leaves both tables byte-for-byte
        /// identical to the direct `record_agent_run` + `record_agent_run_outcome`.
        /// Agent-runs are the outcome-only shape at the *driver* layer, but at the
        /// DAO layer the two-phase writers already model launch-then-outcome, so
        /// this is the equivalence oracle — the flake/proxy analogue.
        #[test]
        fn begin_then_complete_matches_the_direct_agent_run_writers(
            agent_is_claude in any::<bool>(),
            prompt_bytes in 0u64..=1_000_000,
            has_correlation in any::<bool>(),
            purpose in proptest::option::of(
                proptest::sample::select(vec!["plan-submit", "review:plan-abc", "a b #3"])
            ),
            // From `ALL` rather than a hand-written list: this is the oracle
            // that says a status survives the round trip through SQLite, so it
            // must range over every status there is, including any added later.
            status in proptest::sample::select(AgentRunTerminalStatus::ALL.to_vec()),
            exit_code in any::<i32>(),
            stdout_bytes in 0u64..=(i64::MAX as u64),
            stderr_bytes in 0u64..=(i64::MAX as u64),
            stdout_truncated in any::<bool>(),
            stderr_truncated in any::<bool>(),
            stdout_stopped in any::<bool>(),
            stderr_stopped in any::<bool>(),
        ) {
            let direct = AuditLog::open_in_memory().unwrap();
            let guarded = std::sync::Arc::new(AuditLog::open_in_memory().unwrap());
            let s = sample_session();
            direct.open_session(&s).unwrap();
            guarded.open_session(&s).unwrap();

            let run_id = AgentRunId::new();
            let request = AgentRunAuditRecord {
                run_id,
                session_id: s.session_id,
                requested_at: UnixMillis::from_millis(1_700_000_100),
                agent_kind: if agent_is_claude {
                    AgentKind::Claude
                } else {
                    AgentKind::Codex
                },
                prompt: AgentPromptSummary {
                    byte_len: prompt_bytes,
                    sha256_hex: writ_agent_run::sha256_hex(b"prompt"),
                    redacted_preview: "<redacted>".to_string(),
                },
                correlation_id: has_correlation
                    .then(|| CorrelationId::try_new("feat-42_xyz").unwrap()),
                purpose: purpose.map(|p| RunPurpose::try_new(p).unwrap()),
            };
            // The outcome's key is nested (`outcome.run_id`); it must match the
            // request's `run_id` for `complete` to bind the pair.
            let outcome = AgentRunOutcomeAuditRecord {
                completed_at: UnixMillis::from_millis(1_700_000_200),
                outcome: AgentRunOutcome {
                    run_id,
                    status: status.clone(),
                    exit_code,
                    stdout: AgentRunStreamSummary {
                        path: "/private/writ/runs/stdout.log".into(),
                        byte_len: stdout_bytes,
                        sha256_hex: writ_agent_run::sha256_hex(b"stdout"),
                        truncated: stdout_truncated,
                        stopped_at_deadline: stdout_stopped,
                    },
                    stderr: AgentRunStreamSummary {
                        path: "/private/writ/runs/stderr.log".into(),
                        byte_len: stderr_bytes,
                        sha256_hex: writ_agent_run::sha256_hex(b"stderr"),
                        truncated: stderr_truncated,
                        stopped_at_deadline: stderr_stopped,
                    },
                },
            };

            direct.record_agent_run(&request).unwrap();
            direct.record_agent_run_outcome(&outcome).unwrap();
            guarded
                .begin_effect::<AgentRunAuditTable>(&request)
                .unwrap()
                .complete(&outcome)
                .unwrap();

            prop_assert_eq!(
                dump_agent_run_request_rows(&direct),
                dump_agent_run_request_rows(&guarded)
            );
            prop_assert_eq!(
                dump_agent_run_outcome_rows(&direct),
                dump_agent_run_outcome_rows(&guarded)
            );
        }
    }

    /// A session, how many runs it has, and whether the log knows it at
    /// all. `runs` deliberately reaches 3 so ties are reachable: every
    /// run in a session below is written at the *same* `requested_at`,
    /// which is the case `LATEST_RUN_ORDER`'s tiebreak exists for and
    /// the one a `requested_at`-only order answers arbitrarily.
    #[derive(Clone, Debug)]
    struct SessionPlan {
        opened: bool,
        runs: usize,
    }

    fn session_plan() -> impl Strategy<Value = SessionPlan> {
        (any::<bool>(), 0usize..=3).prop_map(|(opened, runs)| SessionPlan {
            // A session with no row cannot own runs: `record_agent_run`
            // enforces the foreign key.
            runs: if opened { runs } else { 0 },
            opened,
        })
    }

    /// Seed a log from the plans and return the ids in plan order,
    /// including the ids of sessions that were never opened.
    fn seed_sessions(log: &AuditLog, plans: &[SessionPlan]) -> Vec<SessionId> {
        plans
            .iter()
            .map(|plan| {
                let session = SessionRecord {
                    session_id: SessionId::new(),
                    ..sample_session()
                };
                let id = session.session_id;
                if plan.opened {
                    log.open_session(&session).unwrap();
                    for _ in 0..plan.runs {
                        log.record_agent_run(&AgentRunAuditRecord {
                            run_id: AgentRunId::new(),
                            session_id: id,
                            // Identical for every run in the session:
                            // the whole point is to force the tie.
                            requested_at: UnixMillis::from_millis(1_700_000_050),
                            agent_kind: AgentKind::Claude,
                            prompt: writ_agent_run::AgentPrompt::new("p").summary(),
                            correlation_id: None,
                            purpose: None,
                        })
                        .unwrap();
                    }
                }
                id
            })
            .collect()
    }

    proptest! {
        /// The batched lookup answers exactly what the per-session
        /// methods answer, for any mix of sessions and any chunk size.
        ///
        /// Those methods are the reference implementation: they are what
        /// `/v1/agent-vms` called before, so any disagreement is a
        /// behaviour change to the endpoint, not merely an internal
        /// inconsistency. Chunk sizes from 1 upward mean the multi-chunk
        /// path is exercised on almost every case rather than only when
        /// someone runs 257 VMs.
        #[test]
        fn the_batched_lookup_agrees_with_the_per_session_reference(
            plans in proptest::collection::vec(session_plan(), 0..8),
            chunk in 1usize..=8,
        ) {
            let log = AuditLog::open_in_memory().unwrap();
            let ids = seed_sessions(&log, &plans);

            let batched = log
                .sessions_with_latest_run_chunked(&ids, NonZeroUsize::new(chunk).unwrap())
                .unwrap();

            // An entry per id asked about, so callers never have to tell
            // "absent from the map" from "nothing recorded".
            prop_assert_eq!(batched.len(), ids.len());

            for id in &ids {
                let got = batched.get(id).expect("an entry for every id");
                prop_assert_eq!(&got.session, &log.get_session(*id).unwrap());
                prop_assert_eq!(
                    &got.latest_run_id,
                    &log.latest_agent_run_id_for_session(*id).unwrap()
                );
            }
        }

        /// Every reader of "the session's most recent run" picks the
        /// same one, including when runs tie on `requested_at`.
        ///
        /// Asserted separately from the batch property because these
        /// three are used in different places for different reasons —
        /// the git-push handler inherits a correlation id, the UI shows
        /// a handle — and nothing but this test stops one of them being
        /// reordered on its own.
        #[test]
        fn the_per_session_lookups_agree_on_which_run_is_latest(
            runs in 1usize..=4,
        ) {
            let log = AuditLog::open_in_memory().unwrap();
            let ids = seed_sessions(&log, &[SessionPlan { opened: true, runs }]);
            let id = ids[0];

            let by_id = log.latest_agent_run_id_for_session(id).unwrap();
            let by_record = log.agent_run_for_session(id).unwrap().map(|r| r.run_id);
            prop_assert_eq!(by_id, by_record);
            prop_assert!(by_id.is_some());
        }
    }

    /// A repeated id is answered once, not counted twice — the caller
    /// hands us whatever the VM daemon listed, and `IN (?, ?)` with a
    /// duplicate returns one row.
    #[test]
    fn a_repeated_id_yields_one_consistent_entry() {
        let log = AuditLog::open_in_memory().unwrap();
        let ids = seed_sessions(
            &log,
            &[SessionPlan {
                opened: true,
                runs: 1,
            }],
        );
        let id = ids[0];

        let batched = log.sessions_with_latest_run(&[id, id, id]).unwrap();
        assert_eq!(batched.len(), 1);
        assert_eq!(
            batched[&id].latest_run_id,
            log.latest_agent_run_id_for_session(id).unwrap()
        );
    }

    /// No ids means no queries and an empty map, rather than a
    /// syntactically invalid `IN ()`.
    #[test]
    fn an_empty_request_is_not_a_query() {
        let log = AuditLog::open_in_memory().unwrap();
        assert!(log.sessions_with_latest_run(&[]).unwrap().is_empty());
    }
}
