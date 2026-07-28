//! Example/edge-case tests for [`super::wait_for_agent_run_outcome`].
use super::*;

/// Seed the FK chain (`session` → `agent_run`) the outcome row
/// references, and return a matching `AgentRunOutcomeAuditRecord`
/// the caller can hand to `record_agent_run_outcome` (or to the
/// wait helper as the expected return value). The outcome row is
/// *not* inserted — tests that exercise the "row appears later"
/// path want the chain present but the outcome absent until the
/// writer task fires.
///
/// `validate_stream_summary` requires an absolute UTF-8 path and a
/// 64-char hex sha256, so the synthetic record uses `/tmp` + a
/// zeroed digest. The wait helper does not inspect either field;
/// it just hands the record back verbatim.
fn seed_synthetic_outcome(
    audit: &AuditLog,
    run_id: AgentRunId,
) -> crate::audit::AgentRunOutcomeAuditRecord {
    use crate::agent_run::{AgentRunOutcome, AgentRunStreamSummary, AgentRunTerminalStatus};
    let session_id = SessionId::new();
    audit
        .open_session(&SessionRecord {
            session_id,
            label: Some("wait-helper test".into()),
            agent_kind: Some(AgentKind::Claude),
            agent_model: Some("claude-opus-4-7".into()),
            opened_at: UnixMillis::from_millis(1_700_000_000),
            closed_at: None,
        })
        .unwrap();
    audit
        .record_agent_run(&AgentRunAuditRecord {
            run_id,
            session_id,
            requested_at: UnixMillis::from_millis(1_700_000_050),
            agent_kind: AgentKind::Claude,
            prompt: crate::agent_run::AgentPrompt::new("test").summary(),
            correlation_id: None,
            purpose: None,
        })
        .unwrap();
    let stream = |label: &str| AgentRunStreamSummary {
        path: PathBuf::from(format!("/tmp/agent-runs/{run_id}/{label}.log")),
        byte_len: 0,
        sha256_hex: "0".repeat(64),
        truncated: false,
    };
    crate::audit::AgentRunOutcomeAuditRecord {
        completed_at: UnixMillis::from_millis(1_700_000_100),
        outcome: AgentRunOutcome {
            run_id,
            status: AgentRunTerminalStatus::Succeeded,
            exit_code: 0,
            stdout: stream("stdout"),
            stderr: stream("stderr"),
        },
    }
}

/// When the outcome row is already in the audit log, the wait helper
/// returns it on the first poll. Calling with `Duration::ZERO` proves
/// the helper does *not* wait one poll interval before checking — the
/// VM dispatch arm reaches the wait helper *after* `start_agent_run`
/// has run, so a fast-completing run (e.g. agent crashed during
/// startup, outcome already posted by the guest's error path) must
/// return immediately rather than burning a full poll interval.
#[tokio::test]
async fn wait_for_agent_run_outcome_returns_existing_row_immediately() {
    let audit = AuditLog::open_in_memory().unwrap();
    let run_id = AgentRunId::new();
    let record = seed_synthetic_outcome(&audit, run_id);
    audit.record_agent_run_outcome(&record).unwrap();

    let got =
        wait_for_agent_run_outcome(&audit, run_id, Duration::ZERO, Duration::from_millis(100))
            .await
            .unwrap();
    assert_eq!(got, record);
}

/// When the outcome row appears *after* the wait helper is called,
/// the helper returns it on the next poll. Spawns a background task
/// that inserts the row 30ms after the helper starts polling at
/// 10ms intervals; the helper's 1s timeout gives plenty of slack so
/// the assertion is on *correctness* (the returned record matches),
/// not on tight latency.
#[tokio::test]
async fn wait_for_agent_run_outcome_returns_when_row_appears_after_delay() {
    let audit = AuditLog::open_in_memory().unwrap();
    let run_id = AgentRunId::new();
    let record = seed_synthetic_outcome(&audit, run_id);
    let audit_arc = Arc::new(audit);

    let audit_writer = Arc::clone(&audit_arc);
    let record_for_writer = record.clone();
    let writer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        audit_writer
            .record_agent_run_outcome(&record_for_writer)
            .unwrap();
    });

    let got = wait_for_agent_run_outcome(
        &audit_arc,
        run_id,
        Duration::from_secs(1),
        Duration::from_millis(10),
    )
    .await
    .unwrap();
    assert_eq!(got, record);
    writer.await.unwrap();
}

/// When the outcome row never appears, the wait helper returns
/// `Timeout` after `timeout` elapses. Pin the run_id and timeout on
/// the error so the operator surface (the bailiff CLI will format
/// this) can name both fields.
#[tokio::test]
async fn wait_for_agent_run_outcome_returns_timeout_when_row_never_appears() {
    let audit = AuditLog::open_in_memory().unwrap();
    let run_id = AgentRunId::new();
    let timeout = Duration::from_millis(50);

    let err = wait_for_agent_run_outcome(&audit, run_id, timeout, Duration::from_millis(10))
        .await
        .unwrap_err();
    match err {
        WaitForAgentRunOutcomeError::Timeout {
            run_id: got_id,
            timeout: got_timeout,
        } => {
            assert_eq!(got_id, run_id);
            assert_eq!(got_timeout, timeout);
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
}
