//! Key=value writers for CLI subcommands that print structured records.
//!
//! Every writer takes a `&mut dyn Write` rather than printing to stdout
//! directly so the renderers stay testable with an in-memory buffer.
//! Section headers and `<none>` placeholders are emitted unconditionally
//! — operators consuming the output rely on the section layout being
//! parallel to the wire shape, so a missing field shows as
//! `field=<none>` rather than being silently elided.

use std::io::Write;

use crate::protocol::{AgentVmSessionInfo, StagedPushDetail, StagedPushSummary};

pub fn write_staged_push_summaries(
    out: &mut dyn Write,
    pushes: &[StagedPushSummary],
) -> std::io::Result<()> {
    for (index, push) in pushes.iter().enumerate() {
        if index > 0 {
            writeln!(out)?;
        }
        writeln!(out, "push_request_id={}", push.push_request_id)?;
        writeln!(out, "repo={}", push.repo)?;
        writeln!(out, "branch={}", push.branch.as_str())?;
        // `expected_remote_head` absent is the "branch creation" signal —
        // surface it explicitly rather than silently omitting the line so
        // operators don't mistake a missing field for a missing OID.
        match &push.expected_remote_head {
            Some(oid) => writeln!(out, "expected_remote_head={}", oid.as_str())?,
            None => writeln!(out, "expected_remote_head=<branch_creation>")?,
        }
        writeln!(out, "new_head={}", push.new_head.as_str())?;
        writeln!(out, "staged_at={}", push.staged_at.as_millis())?;
    }
    Ok(())
}

pub fn write_staged_push_detail(
    out: &mut dyn Write,
    push: &StagedPushDetail,
) -> std::io::Result<()> {
    write_staged_push_summaries(out, std::slice::from_ref(&push.summary))?;
    writeln!(out, "bundle_bytes={}", push.bundle_bytes)?;
    writeln!(out, "session_id={}", push.audit.session_id)?;
    writeln!(out, "received_at={}", push.audit.received_at.as_millis())?;
    match push.audit.result {
        Some(result) => writeln!(out, "audit_result={}", result.as_str())?,
        // `<none>` matches the staged-vs-unknown distinction in the wire
        // protocol: an audit row exists but no outcome has been recorded.
        None => writeln!(out, "audit_result=<none>")?,
    }
    Ok(())
}

pub fn write_agent_vm_sessions(
    out: &mut dyn Write,
    sessions: &[AgentVmSessionInfo],
) -> std::io::Result<()> {
    for (index, session) in sessions.iter().enumerate() {
        if index > 0 {
            writeln!(out)?;
        }
        writeln!(out, "session_id={}", session.session_id)?;
        writeln!(out, "status={}", session.status.as_str())?;
        writeln!(out, "subnet_index={}", session.subnet_index)?;
        writeln!(
            out,
            "runtime={}",
            if session.runtime_attached {
                "attached"
            } else {
                "detached"
            }
        )?;
        writeln!(out, "vm={}", session.vm_name)?;
        writeln!(out, "network={}", session.network_name)?;
        writeln!(out, "network_health={}", session.network_health.as_str())?;
        for broker_url in &session.broker_urls {
            writeln!(out, "broker_url={broker_url}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::agent_vm_lifecycle::{AgentVmSessionStateStatus, NetworkHealth};
    use crate::audit::GitPushOutcomeResult;
    use crate::core::{RequestId, SessionId, UnixMillis};
    use crate::protocol::StagedPushAuditView;

    #[test]
    fn agent_vm_list_output_is_key_value_and_marks_runtime_attachment() {
        let detached_id: SessionId = "51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d".parse().unwrap();
        let attached_id: SessionId = "b7960f37-3888-48a9-b0bb-a4edcaab2194".parse().unwrap();
        let sessions = vec![
            AgentVmSessionInfo {
                session_id: detached_id,
                status: AgentVmSessionStateStatus::Running,
                subnet_index: 252,
                vm_name: format!("writ-agent-vm-{detached_id}"),
                network_name: format!("writ-agent-net-{detached_id}"),
                broker_urls: vec!["http://192.168.252.1:51375/".into()],
                runtime_attached: false,
                network_health: NetworkHealth::Unknown,
            },
            AgentVmSessionInfo {
                session_id: attached_id,
                status: AgentVmSessionStateStatus::Starting,
                subnet_index: 253,
                vm_name: format!("writ-agent-vm-{attached_id}"),
                network_name: format!("writ-agent-net-{attached_id}"),
                broker_urls: vec!["http://192.168.253.1:51376/".into()],
                runtime_attached: true,
                network_health: NetworkHealth::Reachable,
            },
        ];
        let mut out = Vec::new();

        write_agent_vm_sessions(&mut out, &sessions).unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            concat!(
                "session_id=51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d\n",
                "status=running\n",
                "subnet_index=252\n",
                "runtime=detached\n",
                "vm=writ-agent-vm-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d\n",
                "network=writ-agent-net-51b8fd0f-6c10-454c-b0e6-7df1d60e2e6d\n",
                "network_health=unknown\n",
                "broker_url=http://192.168.252.1:51375/\n",
                "\n",
                "session_id=b7960f37-3888-48a9-b0bb-a4edcaab2194\n",
                "status=starting\n",
                "subnet_index=253\n",
                "runtime=attached\n",
                "vm=writ-agent-vm-b7960f37-3888-48a9-b0bb-a4edcaab2194\n",
                "network=writ-agent-net-b7960f37-3888-48a9-b0bb-a4edcaab2194\n",
                "network_health=reachable\n",
                "broker_url=http://192.168.253.1:51376/\n",
            )
        );
    }

    fn staged_summary_fixture(
        request_id: RequestId,
        branch: &str,
        expected_remote_head: Option<&str>,
        new_head: &str,
        staged_at_ms: i64,
    ) -> StagedPushSummary {
        StagedPushSummary {
            push_request_id: request_id,
            repo: "owner/repo".parse().unwrap(),
            branch: branch.parse().unwrap(),
            expected_remote_head: expected_remote_head.map(|s| s.parse().unwrap()),
            new_head: new_head.parse().unwrap(),
            staged_at: UnixMillis::from_millis(staged_at_ms),
        }
    }

    #[test]
    fn staged_push_list_output_is_key_value_separated_by_blank_lines() {
        let id_a: RequestId = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        let id_b: RequestId = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        let pushes = vec![
            staged_summary_fixture(
                id_a,
                "feature/x",
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                1_700_000_001_000,
            ),
            staged_summary_fixture(
                id_b,
                "feature/y",
                None,
                "cccccccccccccccccccccccccccccccccccccccc",
                1_700_000_002_000,
            ),
        ];
        let mut out = Vec::new();

        write_staged_push_summaries(&mut out, &pushes).unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            concat!(
                "push_request_id=11111111-1111-1111-1111-111111111111\n",
                "repo=owner/repo\n",
                "branch=feature/x\n",
                "expected_remote_head=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                "new_head=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
                "staged_at=1700000001000\n",
                "\n",
                "push_request_id=22222222-2222-2222-2222-222222222222\n",
                "repo=owner/repo\n",
                "branch=feature/y\n",
                "expected_remote_head=<branch_creation>\n",
                "new_head=cccccccccccccccccccccccccccccccccccccccc\n",
                "staged_at=1700000002000\n",
            )
        );
    }

    #[test]
    fn staged_push_detail_output_appends_bundle_and_audit_fields() {
        let request_id: RequestId = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let session_id: SessionId = "44444444-4444-4444-4444-444444444444".parse().unwrap();
        let summary = staged_summary_fixture(
            request_id,
            "main",
            Some("dddddddddddddddddddddddddddddddddddddddd"),
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            1_700_000_500_000,
        );
        let detail = StagedPushDetail {
            summary,
            bundle_bytes: 4096,
            audit: StagedPushAuditView {
                session_id,
                received_at: UnixMillis::from_millis(1_700_000_500_250),
                result: Some(GitPushOutcomeResult::Staged),
            },
        };
        let mut out = Vec::new();

        write_staged_push_detail(&mut out, &detail).unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            concat!(
                "push_request_id=33333333-3333-3333-3333-333333333333\n",
                "repo=owner/repo\n",
                "branch=main\n",
                "expected_remote_head=dddddddddddddddddddddddddddddddddddddddd\n",
                "new_head=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n",
                "staged_at=1700000500000\n",
                "bundle_bytes=4096\n",
                "session_id=44444444-4444-4444-4444-444444444444\n",
                "received_at=1700000500250\n",
                "audit_result=staged\n",
            )
        );
    }

    /// An audit row that exists without an outcome row prints as
    /// `<none>` rather than being suppressed: an operator triaging a
    /// stuck staged push wants to see the missing outcome explicitly.
    #[test]
    fn staged_push_detail_output_renders_missing_audit_outcome_as_none() {
        let request_id: RequestId = "55555555-5555-5555-5555-555555555555".parse().unwrap();
        let session_id: SessionId = "66666666-6666-6666-6666-666666666666".parse().unwrap();
        let detail = StagedPushDetail {
            summary: staged_summary_fixture(
                request_id,
                "main",
                None,
                "ffffffffffffffffffffffffffffffffffffffff",
                1,
            ),
            bundle_bytes: 0,
            audit: StagedPushAuditView {
                session_id,
                received_at: UnixMillis::from_millis(2),
                result: None,
            },
        };
        let mut out = Vec::new();

        write_staged_push_detail(&mut out, &detail).unwrap();

        let rendered = String::from_utf8(out).unwrap();
        assert!(rendered.contains("audit_result=<none>\n"), "{rendered}");
        assert!(
            rendered.contains("expected_remote_head=<branch_creation>\n"),
            "{rendered}",
        );
    }
}
