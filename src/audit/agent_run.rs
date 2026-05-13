//! Agent VM workspace bootstrap and agent-run audit records.
//!
//! Two related domains share this module: the workspace-bootstrap
//! intent recorded at session start, and the prompt/outcome pair
//! captured for each completed agent run inside that session.

use rusqlite::{OptionalExtension, Row, params};

use super::session::SqlAgentKind;
use super::validation::{
    bool_to_sql_i64, labeled_invariant, path_to_sql_text, u64_to_sql_i64,
    validate_agent_run_stream_path_text, validate_sha256_hex, validate_stream_summary,
};
use super::{AuditError, AuditLog};
use crate::agent_plan::{CorrelationId, PlanId, Stage};
use crate::agent_run::{
    AgentPromptSummary, AgentRunId, AgentRunOutcome, AgentRunStreamSummary, AgentRunTerminalStatus,
};
use crate::core::{AgentKind, SessionId, UnixMillis};

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
    /// were not tagged at request time. See
    /// `docs/plans/2026-05-11-agent-plans.md` ("Correlation ID") for
    /// the semantics.
    pub correlation_id: Option<CorrelationId>,
    /// Role of this run in the plan/review/decide/execute pipeline.
    /// See `docs/plans/2026-05-11-agent-plans.md` (§"Stages") for the
    /// gate this drives. The route-level enforcement that consults
    /// this column lands later in slice 3; persisting the value first
    /// lets the protocol/CLI change and the gate land independently.
    pub stage: Stage,
    /// Plan this run is bound to read (and act on). `Some` when the
    /// run is a reviewer or implementer pointed at a specific plan;
    /// `None` for planner runs (which create rather than read a plan)
    /// and for one-shot `execute`-stage runs that operate without a
    /// plan-binding. Drives `GET /v1/plans/<id>` authorisation: a run
    /// can only read the plan it was bound to at start time, so a
    /// later code path cannot retroactively widen the run's reach.
    /// See `docs/plans/2026-05-11-agent-plans.md` (§"Protocol
    /// additions"). The route-level enforcement lands in a later
    /// slice; persisting the value first lets the protocol/CLI change
    /// and the gate land independently.
    pub read_plan_id: Option<PlanId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRunOutcomeAuditRecord {
    pub completed_at: UnixMillis,
    pub outcome: AgentRunOutcome,
}

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
        validate_sha256_hex(&r.prompt.sha256_hex, "agent run prompt sha256")?;
        if r.prompt.redacted_preview.is_empty() {
            return Err(AuditError::Invariant(
                "agent run prompt redacted preview must not be empty",
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

            tx.execute(
                "INSERT INTO agent_run (
                     run_id,
                     session_id,
                     requested_at,
                     agent_kind,
                     prompt_bytes,
                     prompt_sha256,
                     prompt_redacted_preview,
                     correlation_id,
                     stage,
                     read_plan_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    r.run_id.as_uuid().to_string(),
                    r.session_id.as_uuid().to_string(),
                    r.requested_at.as_millis(),
                    r.agent_kind.as_str(),
                    u64_to_sql_i64(r.prompt.byte_len, "agent run prompt bytes")?,
                    &r.prompt.sha256_hex,
                    &r.prompt.redacted_preview,
                    r.correlation_id.as_ref().map(CorrelationId::as_str),
                    r.stage.as_str(),
                    r.read_plan_id.map(|id| id.as_uuid().to_string()),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn record_agent_run_outcome(
        &self,
        r: &AgentRunOutcomeAuditRecord,
    ) -> Result<(), AuditError> {
        validate_stream_summary(&r.outcome.stdout, "stdout")?;
        validate_stream_summary(&r.outcome.stderr, "stderr")?;

        self.with_conn_mut(|c| {
            c.execute(
                "INSERT INTO agent_run_outcome (
                     run_id,
                     completed_at,
                     status,
                     exit_code,
                     stdout_path,
                     stdout_bytes,
                     stdout_sha256,
                     stdout_truncated,
                     stderr_path,
                     stderr_bytes,
                     stderr_sha256,
                     stderr_truncated
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    r.outcome.run_id.as_uuid().to_string(),
                    r.completed_at.as_millis(),
                    agent_run_status_str(&r.outcome.status),
                    r.outcome.exit_code,
                    path_to_sql_text(&r.outcome.stdout.path, "stdout path")?,
                    u64_to_sql_i64(r.outcome.stdout.byte_len, "stdout bytes")?,
                    &r.outcome.stdout.sha256_hex,
                    bool_to_sql_i64(r.outcome.stdout.truncated),
                    path_to_sql_text(&r.outcome.stderr.path, "stderr path")?,
                    u64_to_sql_i64(r.outcome.stderr.byte_len, "stderr bytes")?,
                    &r.outcome.stderr.sha256_hex,
                    bool_to_sql_i64(r.outcome.stderr.truncated),
                ],
            )?;
            Ok(())
        })
    }

    pub fn get_agent_run(
        &self,
        run_id: AgentRunId,
    ) -> Result<Option<AgentRunAuditRecord>, AuditError> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT run_id, session_id, requested_at, agent_kind, prompt_bytes,
                            prompt_sha256, prompt_redacted_preview, correlation_id, stage,
                            read_plan_id
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
                            stderr_path, stderr_bytes, stderr_sha256, stderr_truncated
                     FROM agent_run_outcome
                     WHERE run_id = ?1",
                    params![run_id.as_uuid().to_string()],
                    agent_run_outcome_from_row,
                )
                .optional()?;
            row.transpose()
        })
    }

    /// Most-recent `agent_run.run_id` for a session, by `requested_at`.
    /// `None` if no run row exists. Used by the UI HTTP join to give
    /// the operator a stable handle to follow from a VM into a run
    /// view; the run itself is exposed through its own resource and
    /// not inlined here.
    pub fn latest_agent_run_id_for_session(
        &self,
        session_id: SessionId,
    ) -> Result<Option<AgentRunId>, AuditError> {
        self.with_conn(|c| {
            let raw: Option<String> = c
                .query_row(
                    "SELECT run_id FROM agent_run
                     WHERE session_id = ?1
                     ORDER BY requested_at DESC
                     LIMIT 1",
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
    /// Today's product flow creates one run per session. The
    /// `ORDER BY requested_at DESC LIMIT 1` is defensive against a
    /// future N>1 case so the answer stays deterministic; if the
    /// invariant is ever loosened, the policy "most recent run wins"
    /// is the obvious one and the audit row stores everything needed
    /// to revisit it.
    pub fn correlation_id_for_session(
        &self,
        session_id: SessionId,
    ) -> Result<Option<CorrelationId>, AuditError> {
        self.with_conn(|c| {
            let raw: Option<Option<String>> = c
                .query_row(
                    "SELECT correlation_id FROM agent_run
                     WHERE session_id = ?1
                     ORDER BY requested_at DESC
                     LIMIT 1",
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
    let stage_raw: String = row.get(8)?;
    let read_plan_id_raw: Option<String> = row.get(9)?;

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
        let stage = stage_raw
            .parse::<Stage>()
            .map_err(|_| AuditError::Invariant("agent run row: stage is invalid"))?;
        let read_plan_id = read_plan_id_raw
            .map(|s| s.parse::<PlanId>())
            .transpose()
            .map_err(|_| AuditError::Invariant("agent run row: read_plan_id is invalid"))?;
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
            stage,
            read_plan_id,
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
    let stderr_path: String = row.get(8)?;
    let stderr_bytes: i64 = row.get(9)?;
    let stderr_sha256: String = row.get(10)?;
    let stderr_truncated: i64 = row.get(11)?;

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
            "stdout",
        )?;
        let stderr = agent_run_stream_from_sql(
            stderr_path,
            stderr_bytes,
            stderr_sha256,
            stderr_truncated,
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
    label: &'static str,
) -> Result<AgentRunStreamSummary, AuditError> {
    validate_agent_run_stream_path_text(&path, label)?;
    let byte_len = u64::try_from(byte_len)
        .map_err(|_| labeled_invariant(label, "agent run stream bytes is negative"))?;
    validate_sha256_hex(&sha256_hex, label)?;
    let truncated = match truncated {
        0 => false,
        1 => true,
        _ => {
            return Err(labeled_invariant(
                label,
                "agent run stream truncated flag is invalid",
            ));
        }
    };
    Ok(AgentRunStreamSummary {
        path: path.into(),
        byte_len,
        sha256_hex,
        truncated,
    })
}

fn agent_run_status_str(status: &AgentRunTerminalStatus) -> &'static str {
    match status {
        AgentRunTerminalStatus::Succeeded => "succeeded",
        AgentRunTerminalStatus::Failed => "failed",
    }
}

fn agent_run_status_from_str(raw: &str) -> Result<AgentRunTerminalStatus, AuditError> {
    match raw {
        "succeeded" => Ok(AgentRunTerminalStatus::Succeeded),
        "failed" => Ok(AgentRunTerminalStatus::Failed),
        _ => Err(AuditError::Invariant("agent run status is invalid")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_plan::CorrelationId;
    use crate::audit::test_support::sample_session;
    use crate::core::{AgentKind, SessionRecord};
    use rusqlite::params;

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
        let prompt = crate::agent_run::AgentPrompt::new("SECRET prompt body");
        let run_id = AgentRunId::new();
        let record = AgentRunAuditRecord {
            run_id,
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: prompt.summary(),
            correlation_id: None,
            stage: Stage::Execute,
            read_plan_id: None,
        };

        log.record_agent_run(&record).unwrap();

        let entry = log.get_agent_run(run_id).unwrap().unwrap();
        assert_eq!(entry.run_id, run_id);
        assert_eq!(entry.session_id, s.session_id);
        assert_eq!(entry.agent_kind, AgentKind::Claude);
        assert_eq!(entry.prompt.byte_len, prompt.byte_len());
        assert_eq!(entry.prompt.redacted_preview, "<redacted>");
        assert!(entry.correlation_id.is_none());
        assert_eq!(entry.stage, Stage::Execute);
        assert!(entry.read_plan_id.is_none());
        let debug = format!("{entry:?}");
        assert!(!debug.contains(prompt.as_str()), "{debug}");

        let outcome = AgentRunOutcome {
            run_id,
            status: AgentRunTerminalStatus::Failed,
            exit_code: 7,
            stdout: AgentRunStreamSummary {
                path: "/private/writ/runs/stdout.log".into(),
                byte_len: 12,
                sha256_hex: crate::agent_run::sha256_hex(b"stdout bytes"),
                truncated: false,
            },
            stderr: AgentRunStreamSummary {
                path: "/private/writ/runs/stderr.log".into(),
                byte_len: 4096,
                sha256_hex: crate::agent_run::sha256_hex(b"stderr bytes"),
                truncated: true,
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
            prompt: crate::agent_run::AgentPrompt::new("prompt").summary(),
            correlation_id: None,
            stage: Stage::Execute,
            read_plan_id: None,
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
                sha256_hex: crate::agent_run::sha256_hex(b""),
                truncated: false,
            },
            stderr: AgentRunStreamSummary {
                path: "/private/writ/runs/stderr.log".into(),
                byte_len: 0,
                sha256_hex: crate::agent_run::sha256_hex(b""),
                truncated: false,
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
                stage: Stage::Execute,
                read_plan_id: None,
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
                        sha256_hex: crate::agent_run::sha256_hex(b""),
                        truncated: false,
                    },
                    stderr: AgentRunStreamSummary {
                        path: "/private/writ/runs/stderr.log".into(),
                        byte_len: 0,
                        sha256_hex: crate::agent_run::sha256_hex(b""),
                        truncated: false,
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
            prompt: crate::agent_run::AgentPrompt::new("prompt").summary(),
            correlation_id: Some(correlation.clone()),
            stage: Stage::Execute,
            read_plan_id: None,
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
            prompt: crate::agent_run::AgentPrompt::new("prompt").summary(),
            correlation_id: None,
            stage: Stage::Execute,
            read_plan_id: None,
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
                        crate::agent_run::sha256_hex(b"x"),
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
                        crate::agent_run::sha256_hex(b"y"),
                        too_long,
                    ],
                )
                .map_err(AuditError::from)
            })
            .unwrap_err();
        let msg_len = err_len.to_string();
        assert!(msg_len.contains("CHECK"), "got: {msg_len}");
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
            prompt: crate::agent_run::AgentPrompt::new("prompt").summary(),
            correlation_id: None,
            stage: Stage::Execute,
            read_plan_id: None,
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
            prompt: crate::agent_run::AgentPrompt::new("prompt").summary(),
            correlation_id: Some(correlation.clone()),
            stage: Stage::Execute,
            read_plan_id: None,
        })
        .unwrap();
        assert_eq!(
            log.correlation_id_for_session(tagged.session_id).unwrap(),
            Some(correlation)
        );
    }

    /// A run bound to an existing plan via `read_plan_id` round-trips
    /// through the DAO. The plan must exist first: the FK enforcement
    /// (enabled by `PRAGMA foreign_keys = ON` in `AuditLog::open`)
    /// would otherwise reject the insert.
    #[test]
    fn agent_run_roundtrips_with_read_plan_id() {
        use crate::agent_plan::{PlanBody, PlanId};
        use crate::audit::PlanSubmissionRecord;

        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        // First, write a planner run plus its plan so the FK target
        // exists for the implementer row we want to round-trip.
        let planner_run_id = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id: planner_run_id,
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: crate::agent_run::AgentPrompt::new("plan this").summary(),
            correlation_id: None,
            stage: Stage::Plan,
            read_plan_id: None,
        })
        .unwrap();
        let plan_id = PlanId::new();
        log.record_plan_submission(&PlanSubmissionRecord {
            plan_id,
            agent_run_id: planner_run_id,
            submitted_at: UnixMillis::from_millis(1_700_000_150),
            body: PlanBody::try_new("# Plan body").unwrap(),
        })
        .unwrap();

        let implementer_run_id = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id: implementer_run_id,
            session_id: s.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_200),
            agent_kind: AgentKind::Claude,
            prompt: crate::agent_run::AgentPrompt::new("execute against the plan").summary(),
            correlation_id: None,
            stage: Stage::Execute,
            read_plan_id: Some(plan_id),
        })
        .unwrap();

        let entry = log.get_agent_run(implementer_run_id).unwrap().unwrap();
        assert_eq!(entry.read_plan_id, Some(plan_id));
    }

    /// A run with `read_plan_id` naming a non-existent plan is rejected
    /// by the FK at INSERT time. Belt-and-braces: even if a future code
    /// path constructs a bogus `AgentRunAuditRecord`, the DB refuses to
    /// land a dangling reference.
    #[test]
    fn agent_run_read_plan_id_fk_rejects_unknown_plan() {
        use crate::agent_plan::PlanId;

        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let bogus_plan = PlanId::new();
        let err = log
            .record_agent_run(&AgentRunAuditRecord {
                run_id: AgentRunId::new(),
                session_id: s.session_id,
                requested_at: UnixMillis::from_millis(1_700_000_100),
                agent_kind: AgentKind::Claude,
                prompt: crate::agent_run::AgentPrompt::new("p").summary(),
                correlation_id: None,
                stage: Stage::Execute,
                read_plan_id: Some(bogus_plan),
            })
            .unwrap_err();
        let msg = err.to_string().to_uppercase();
        assert!(msg.contains("FOREIGN KEY"), "got: {err}");
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
            prompt: crate::agent_run::AgentPrompt::new("p").summary(),
            correlation_id: None,
            stage: Stage::Execute,
            read_plan_id: None,
        })
        .unwrap();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id: earlier,
            session_id: session.session_id,
            requested_at: UnixMillis::from_millis(1_700_000_100),
            agent_kind: AgentKind::Claude,
            prompt: crate::agent_run::AgentPrompt::new("p").summary(),
            correlation_id: None,
            stage: Stage::Execute,
            read_plan_id: None,
        })
        .unwrap();
        assert_eq!(
            log.latest_agent_run_id_for_session(session.session_id)
                .unwrap(),
            Some(later)
        );
    }
}
