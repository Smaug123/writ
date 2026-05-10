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
                     prompt_redacted_preview
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    r.run_id.as_uuid().to_string(),
                    r.session_id.as_uuid().to_string(),
                    r.requested_at.as_millis(),
                    r.agent_kind.as_str(),
                    u64_to_sql_i64(r.prompt.byte_len, "agent run prompt bytes")?,
                    &r.prompt.sha256_hex,
                    &r.prompt.redacted_preview,
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
                            prompt_sha256, prompt_redacted_preview
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
