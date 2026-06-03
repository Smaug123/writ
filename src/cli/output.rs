//! Key=value writers for CLI subcommands that print structured records.
//!
//! Every writer takes a `&mut dyn Write` rather than printing to stdout
//! directly so the renderers stay testable with an in-memory buffer.
//! Section headers and `<none>` placeholders are emitted unconditionally
//! — operators consuming the output rely on the section layout being
//! parallel to the wire shape, so a missing field shows as
//! `field=<none>` rather than being silently elided.

use std::io::Write;

use crate::bailiff_plan_note::DecisionNote;
use crate::bailiff_plan_view::{
    BailiffPlanSummary, PlanFullView, SignedBailiffNote, VerifiedSection,
};
use crate::protocol::{AgentVmSessionInfo, SignedRunMetadata, StagedPushDetail, StagedPushSummary};

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

/// Render the `bailiff plan list` output. Empty slice emits a single
/// `no plans` line so an operator sees an explicit signal rather than
/// silent zero-byte output. Non-empty slices render each plan as a
/// key=value block separated by blank lines. Per-plan keys:
///
/// - `plan_id` — UUID.
/// - `state` — derived [`crate::bailiff_plan_view::WorkflowState`].
/// - `purpose` / `submitted_at` — submission projection (or `<none>`
///   when no submission has been recorded, the
///   [`crate::bailiff_plan_view::WorkflowState::Corrupt`] case).
/// - `decision_outcome` / `decision_decider` / `decided_at` — decision
///   projection (or `<none>` when no decision has been recorded).
/// - `reviewed_at` / `implemented_at` — timestamps from the matching
///   notes (or `<none>` when absent).
///
/// `<none>` is emitted unconditionally for absent fields rather than
/// silently elided so operators can distinguish "key missing because
/// no value" from "key missing because the formatter regressed."
///
/// `purpose` and `decision_decider` are free-form text — `--purpose`
/// accepts arbitrary strings, and `Decider::try_new` rejects only
/// embedded NUL. Both are routed through an inline-escape helper
/// that emits a bare token when the value is safe and a double-
/// quoted, backslash-escaped token when it contains newlines,
/// carriage returns, backslashes, double quotes, or matches the
/// literal `<none>` sentinel. This keeps each plan block parseable
/// as one line per key even when persisted metadata is adversarial.
pub fn write_bailiff_plan_list(
    out: &mut dyn Write,
    plans: &[BailiffPlanSummary],
) -> std::io::Result<()> {
    if plans.is_empty() {
        writeln!(out, "no plans")?;
        return Ok(());
    }
    for (index, plan) in plans.iter().enumerate() {
        if index > 0 {
            writeln!(out)?;
        }
        writeln!(out, "plan_id={}", plan.plan_id)?;
        writeln!(out, "state={}", plan.state())?;
        match &plan.submission {
            Some(s) => {
                write!(out, "purpose=")?;
                write_inline_value(out, &s.purpose)?;
                writeln!(out, "submitted_at={}", s.submitted_at.as_millis())?;
            }
            None => {
                writeln!(out, "purpose=<none>")?;
                writeln!(out, "submitted_at=<none>")?;
            }
        }
        match &plan.decision {
            Some(d) => {
                writeln!(out, "decision_outcome={}", d.outcome)?;
                write!(out, "decision_decider=")?;
                write_inline_value(out, d.decider.as_str())?;
                writeln!(out, "decided_at={}", d.decided_at.as_millis())?;
            }
            None => {
                writeln!(out, "decision_outcome=<none>")?;
                writeln!(out, "decision_decider=<none>")?;
                writeln!(out, "decided_at=<none>")?;
            }
        }
        match plan.reviewed_at {
            Some(t) => writeln!(out, "reviewed_at={}", t.as_millis())?,
            None => writeln!(out, "reviewed_at=<none>")?,
        }
        match plan.implemented_at {
            Some(t) => writeln!(out, "implemented_at={}", t.as_millis())?,
            None => writeln!(out, "implemented_at=<none>")?,
        }
    }
    Ok(())
}

/// Inline writer for free-form text values that share a line with their
/// `key=` prefix. Writes a single line terminated by `\n`.
///
/// Bare form: emit the raw value verbatim when it is a single line free
/// of backslashes, double quotes, and not equal to the `<none>`
/// sentinel. This keeps validated/well-behaved values readable.
///
/// Quoted form: when the value would otherwise break the one-line-per-
/// key invariant or collide with `<none>`, wrap in double quotes and
/// backslash-escape `\`, `"`, `\n`, `\r`. The leading `"` is the
/// unambiguous marker that the value is escaped; consumers can detect
/// the quoted form by inspecting the first byte after `=` and reverse
/// the escapes if they need the original string.
fn write_inline_value(out: &mut dyn Write, value: &str) -> std::io::Result<()> {
    let needs_quoting = value == "<none>"
        || value
            .bytes()
            .any(|b| matches!(b, b'\n' | b'\r' | b'\\' | b'"'));
    if !needs_quoting {
        return writeln!(out, "{value}");
    }
    out.write_all(b"\"")?;
    for ch in value.chars() {
        match ch {
            '\\' => out.write_all(b"\\\\")?,
            '"' => out.write_all(b"\\\"")?,
            '\n' => out.write_all(b"\\n")?,
            '\r' => out.write_all(b"\\r")?,
            c => write!(out, "{c}")?,
        }
    }
    writeln!(out, "\"")
}

/// Render the `bailiff plan show` output. Emits a top-level
/// `plan_id=<uuid>` line followed by four section blocks
/// (`-- plan --`, `-- decision --`, `-- review --`, `-- implement --`),
/// each separated from the previous by a blank line. Every section is
/// emitted unconditionally — an absent signed section surfaces as
/// `verification=<none>`, an absent decision surfaces as
/// `outcome=<none>`.
///
/// For each signed section the `verification` key carries one of:
///
/// - `verified` — envelope present at the writ output OID, decoded,
///   end-to-end verified, and the note's persisted `signed_metadata`
///   / `signature` match the envelope's. The metadata fields
///   (`run_id`, `session_id`, …) are projected from the envelope
///   (which agrees with the note in this state).
/// - `note_envelope_mismatch` — envelope verifies on its own but the
///   note's persisted metadata diverges from the envelope's. Both
///   sides render: the envelope's values as the unprefixed keys
///   (the cryptographic truth) and the note's values with a `note_`
///   prefix, so an operator can diff the two without re-reading
///   either source. The divergence itself is the trust violation;
///   the renderer's job is to surface it, not to choose which side
///   is "right."
/// - `writ_envelope_missing` — bailiff's local copy of writ's notes
///   ref has no annotation at the note's `writ_output_oid`. The
///   note's metadata is rendered (operator can compare against
///   writ's authoritative copy after a fetch). Recoverable by
///   re-running the relevant `submit*` verb to pull the envelope
///   across.
/// - `envelope_malformed` — an envelope body exists at the OID but
///   does not decode as `SignedRunEnvelope`. The note's metadata
///   is rendered plus a quoted `envelope_error=` line carrying the
///   underlying decode message.
/// - `signature_failure` — envelope decoded but the verifier
///   rejected it. The note's metadata is rendered plus a quoted
///   `verify_error=` line naming the specific check that failed.
///
/// `purpose` and the wrapped error strings are routed through the
/// same `write_inline_value` helper that [`write_bailiff_plan_list`]
/// uses — newlines, backslashes, embedded quotes, and the literal
/// `<none>` sentinel are double-quoted and escaped so the
/// one-line-per-key invariant survives even adversarial agent
/// output (the verify error chain may quote bytes from writ's
/// signed metadata).
pub fn write_bailiff_plan_show(out: &mut dyn Write, view: &PlanFullView) -> std::io::Result<()> {
    writeln!(out, "plan_id={}", view.plan_id)?;
    writeln!(out)?;
    writeln!(out, "-- plan --")?;
    write_signed_section(out, view.plan.as_ref())?;
    writeln!(out)?;
    writeln!(out, "-- decision --")?;
    write_decision_section(out, view.decision.as_ref())?;
    writeln!(out)?;
    writeln!(out, "-- review --")?;
    write_signed_section(out, view.review.as_ref())?;
    writeln!(out)?;
    writeln!(out, "-- implement --")?;
    write_signed_section(out, view.implement.as_ref())?;
    Ok(())
}

/// Render one signed section's body — the lines that follow the
/// `-- plan --` / `-- review --` / `-- implement --` header in
/// [`write_bailiff_plan_show`]. `None` surfaces as
/// `verification=<none>`; the five [`VerifiedSection`] variants each
/// pick the metadata projection appropriate to their trust state.
fn write_signed_section<T: SignedBailiffNote>(
    out: &mut dyn Write,
    section: Option<&VerifiedSection<T>>,
) -> std::io::Result<()> {
    let Some(section) = section else {
        return writeln!(out, "verification=<none>");
    };
    match section {
        VerifiedSection::Verified { note, envelope } => {
            writeln!(out, "verification=verified")?;
            write_signed_note_common(out, note)?;
            write_envelope_metadata(out, &envelope.metadata, "")?;
        }
        VerifiedSection::NoteEnvelopeMismatch { note, envelope } => {
            writeln!(out, "verification=note_envelope_mismatch")?;
            write_signed_note_common(out, note)?;
            write_envelope_metadata(out, &envelope.metadata, "")?;
            write_envelope_metadata(out, note.signed_metadata(), "note_")?;
            // Without these two digest lines, a signature-only
            // divergence (metadata byte-equal, signature differs) is
            // invisible — the two metadata projections render
            // identically and the operator sees
            // `verification=note_envelope_mismatch` with no
            // differing field. Dumping the full PEM-armoured
            // signature here would flood the page; a SHA-256 of the
            // signature string is enough to confirm "differ vs
            // identical" at a glance, and the operator can `git
            // notes show` the relevant ref if they need the body.
            writeln!(
                out,
                "signature_sha256={}",
                crate::agent_run::sha256_hex(envelope.signature.as_str().as_bytes())
            )?;
            writeln!(
                out,
                "note_signature_sha256={}",
                crate::agent_run::sha256_hex(note.signature().as_str().as_bytes())
            )?;
        }
        VerifiedSection::WritEnvelopeMissing { note } => {
            writeln!(out, "verification=writ_envelope_missing")?;
            write_signed_note_common(out, note)?;
            write_envelope_metadata(out, note.signed_metadata(), "")?;
        }
        VerifiedSection::EnvelopeMalformed { note, error } => {
            writeln!(out, "verification=envelope_malformed")?;
            write_signed_note_common(out, note)?;
            write_envelope_metadata(out, note.signed_metadata(), "")?;
            write!(out, "envelope_error=")?;
            write_inline_value(out, &error.to_string())?;
        }
        VerifiedSection::SignatureFailure { note, error } => {
            writeln!(out, "verification=signature_failure")?;
            write_signed_note_common(out, note)?;
            write_envelope_metadata(out, note.signed_metadata(), "")?;
            write!(out, "verify_error=")?;
            write_inline_value(out, &error.to_string())?;
        }
    }
    Ok(())
}

/// Render the note-side scalar lines (`purpose`, `writ_output_oid`).
/// Shared across every [`VerifiedSection`] variant: those fields are
/// bailiff-owned and present in every signed-note state, regardless of
/// what happened to the writ-side envelope.
fn write_signed_note_common<T: SignedBailiffNote>(
    out: &mut dyn Write,
    note: &T,
) -> std::io::Result<()> {
    write!(out, "purpose=")?;
    write_inline_value(out, note.purpose())?;
    writeln!(out, "writ_output_oid={}", note.writ_output_oid().as_str())?;
    Ok(())
}

/// Render the eight [`SignedRunMetadata`] scalar lines under the
/// supplied `prefix`. Used three ways: unprefixed for the cryptographic
/// truth (envelope-side in `Verified` / `NoteEnvelopeMismatch`, or
/// note-side in the failure variants where there is no trusted
/// envelope); prefixed `note_` only in `NoteEnvelopeMismatch`, where
/// the note's stored copy diverged from the envelope and the operator
/// needs to see both.
///
/// `capabilities` is emitted as one `{prefix}capability=` line per
/// entry: the wire shape is a list, and a single key with a
/// comma-joined value would collide with `RepoRef`'s `owner/name`
/// separator if a future capability ever embedded a list-of-repos.
/// One line per element also keeps each value short enough that no
/// quoting is required.
fn write_envelope_metadata(
    out: &mut dyn Write,
    metadata: &SignedRunMetadata,
    prefix: &str,
) -> std::io::Result<()> {
    writeln!(out, "{prefix}run_id={}", metadata.run_id)?;
    writeln!(out, "{prefix}session_id={}", metadata.session_id)?;
    writeln!(
        out,
        "{prefix}prompt_sha256={}",
        metadata.prompt_sha256.as_str()
    )?;
    writeln!(
        out,
        "{prefix}output_envelope_sha256={}",
        metadata.output_envelope_sha256.as_str()
    )?;
    writeln!(out, "{prefix}exit_code={}", metadata.exit_code)?;
    writeln!(
        out,
        "{prefix}completed_at={}",
        metadata.completed_at.as_millis()
    )?;
    writeln!(
        out,
        "{prefix}signing_key_fingerprint={}",
        metadata.signing_key_fingerprint.as_str()
    )?;
    for capability in &metadata.capabilities {
        write!(out, "{prefix}capability=")?;
        // Route the inline projection through `write_inline_value`:
        // `RepoRef::from_str` only rejects empty parts and embedded
        // '/', so a tampered envelope can still carry a `RepoRef`
        // whose owner or name contains a newline / CR. Without
        // quoting, that byte would break the one-key-per-line
        // invariant `bailiff plan show` promises and could forge
        // additional lines under any later key.
        // `write_inline_value` emits its own terminating newline.
        write_inline_value(out, &capability_inline(capability))?;
    }
    Ok(())
}

/// One-line projection of a [`CapabilitySet`] variant for the show
/// formatter. Inline form: `<kind>:<owner>/<name>`. Each variant has
/// exactly one repo field today, so the projection is total; a future
/// list-of-repos variant would shift to multi-line.
fn capability_inline(capability: &crate::core::CapabilitySet) -> String {
    use crate::core::CapabilitySet;
    match capability {
        CapabilitySet::WorkspaceRead { repo } => format!("workspace_read:{repo}"),
        CapabilitySet::WorkspaceWrite { repo } => format!("workspace_write:{repo}"),
    }
}

/// Render the decision-section body. `outcome=<none>` when absent,
/// three key=value lines otherwise. `decider` is free-form (today
/// `cli:<USER>` / `agent:<run_id>`) so it is routed through
/// [`write_inline_value`] for injection-safety, parallel with the
/// list verb's handling.
fn write_decision_section(
    out: &mut dyn Write,
    decision: Option<&DecisionNote>,
) -> std::io::Result<()> {
    let Some(decision) = decision else {
        return writeln!(out, "outcome=<none>");
    };
    writeln!(out, "outcome={}", decision.outcome)?;
    write!(out, "decider=")?;
    write_inline_value(out, decision.decider.as_str())?;
    writeln!(out, "decided_at={}", decision.decided_at.as_millis())?;
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
        for broker_url in &session.broker_urls {
            writeln!(out, "broker_url={broker_url}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::agent_vm_lifecycle::AgentVmSessionStateStatus;
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
            },
            AgentVmSessionInfo {
                session_id: attached_id,
                status: AgentVmSessionStateStatus::Starting,
                subnet_index: 253,
                vm_name: format!("writ-agent-vm-{attached_id}"),
                network_name: format!("writ-agent-net-{attached_id}"),
                broker_urls: vec!["http://192.168.253.1:51376/".into()],
                runtime_attached: true,
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
                "broker_url=http://192.168.252.1:51375/\n",
                "\n",
                "session_id=b7960f37-3888-48a9-b0bb-a4edcaab2194\n",
                "status=starting\n",
                "subnet_index=253\n",
                "runtime=attached\n",
                "vm=writ-agent-vm-b7960f37-3888-48a9-b0bb-a4edcaab2194\n",
                "network=writ-agent-net-b7960f37-3888-48a9-b0bb-a4edcaab2194\n",
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

    /// `bailiff plan list` with no plans prints a single `no plans`
    /// line so an operator sees an explicit zero-result signal rather
    /// than silent zero-byte output. Pins the empty-case contract.
    #[test]
    fn bailiff_plan_list_empty_prints_no_plans_marker() {
        let mut out = Vec::new();
        write_bailiff_plan_list(&mut out, &[]).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "no plans\n");
    }

    /// A plan in the `Implemented` state — every field set — renders
    /// all keys with concrete values and no `<none>` markers. Pins the
    /// full-fidelity rendering shape.
    #[test]
    fn bailiff_plan_list_renders_full_fidelity_implemented_row() {
        use crate::bailiff_decision::{Decider, Decision};
        use crate::bailiff_plan_note::PlanId;
        use crate::bailiff_plan_view::{BailiffPlanSummary, DecisionSummary, SubmissionSummary};

        let plan_id = PlanId::from_uuid("01234567-89ab-4cde-8123-456789abcdef".parse().unwrap());
        let summary = BailiffPlanSummary {
            plan_id,
            submission: Some(SubmissionSummary {
                purpose: "fix-oauth-drift".into(),
                submitted_at: UnixMillis::from_millis(1_700_000_000_000),
            }),
            decision: Some(DecisionSummary {
                outcome: Decision::Accepted,
                decider: Decider::try_new("cli:alice").unwrap(),
                decided_at: UnixMillis::from_millis(1_700_000_001_000),
            }),
            reviewed_at: Some(UnixMillis::from_millis(1_700_000_002_000)),
            implemented_at: Some(UnixMillis::from_millis(1_700_000_003_000)),
        };
        let mut out = Vec::new();
        write_bailiff_plan_list(&mut out, &[summary]).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            concat!(
                "plan_id=01234567-89ab-4cde-8123-456789abcdef\n",
                "state=implemented\n",
                "purpose=fix-oauth-drift\n",
                "submitted_at=1700000000000\n",
                "decision_outcome=accepted\n",
                "decision_decider=cli:alice\n",
                "decided_at=1700000001000\n",
                "reviewed_at=1700000002000\n",
                "implemented_at=1700000003000\n",
            ),
        );
    }

    /// A submission-only plan renders the submission block but `<none>`
    /// for every later-stage field. Pins the absence-signaling shape
    /// — silent omission would let a formatter regression hide missing
    /// keys from operators.
    #[test]
    fn bailiff_plan_list_renders_none_markers_for_unset_fields() {
        use crate::bailiff_plan_note::PlanId;
        use crate::bailiff_plan_view::{BailiffPlanSummary, SubmissionSummary};

        let plan_id = PlanId::from_uuid("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".parse().unwrap());
        let summary = BailiffPlanSummary {
            plan_id,
            submission: Some(SubmissionSummary {
                purpose: "p".into(),
                submitted_at: UnixMillis::from_millis(1),
            }),
            decision: None,
            reviewed_at: None,
            implemented_at: None,
        };
        let mut out = Vec::new();
        write_bailiff_plan_list(&mut out, &[summary]).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            concat!(
                "plan_id=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n",
                "state=submitted\n",
                "purpose=p\n",
                "submitted_at=1\n",
                "decision_outcome=<none>\n",
                "decision_decider=<none>\n",
                "decided_at=<none>\n",
                "reviewed_at=<none>\n",
                "implemented_at=<none>\n",
            ),
        );
    }

    /// Multiple plans render as key=value blocks separated by a single
    /// blank line. Pins the separator contract — a regression that
    /// switched to no separator or to a multi-blank-line gap would
    /// break scripts that split on `\n\n` to enumerate plans.
    #[test]
    fn bailiff_plan_list_separates_multiple_plans_with_blank_line() {
        use crate::bailiff_plan_note::PlanId;
        use crate::bailiff_plan_view::{BailiffPlanSummary, SubmissionSummary};

        let p1 = BailiffPlanSummary {
            plan_id: PlanId::from_uuid("11111111-1111-4111-8111-111111111111".parse().unwrap()),
            submission: Some(SubmissionSummary {
                purpose: "first".into(),
                submitted_at: UnixMillis::from_millis(1),
            }),
            decision: None,
            reviewed_at: None,
            implemented_at: None,
        };
        let p2 = BailiffPlanSummary {
            plan_id: PlanId::from_uuid("22222222-2222-4222-8222-222222222222".parse().unwrap()),
            submission: Some(SubmissionSummary {
                purpose: "second".into(),
                submitted_at: UnixMillis::from_millis(2),
            }),
            decision: None,
            reviewed_at: None,
            implemented_at: None,
        };
        let mut out = Vec::new();
        write_bailiff_plan_list(&mut out, &[p1, p2]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        // Exactly one blank line between the two `plan_id=` blocks.
        let count = rendered.matches("\n\n").count();
        assert_eq!(
            count, 1,
            "expected one blank-line separator, got: {rendered}"
        );
        assert!(rendered.starts_with("plan_id=11111111-"));
        assert!(rendered.contains("\nplan_id=22222222-"));
    }

    /// `purpose` accepts arbitrary `--purpose` input, and `Decider`
    /// rejects only embedded NUL — neither restricts newlines or the
    /// literal `<none>` sentinel. Without escaping, a purpose
    /// containing `\npurpose=injected\nplan_id=fake-id` would forge a
    /// new key=value block and split one plan row into two, and a
    /// decider literally equal to `<none>` would be indistinguishable
    /// from absence. Pins the quoted-form output so a regression that
    /// reverted to bare `key=value` for free-form text would surface
    /// here.
    #[test]
    fn bailiff_plan_list_quotes_purpose_and_decider_with_injection_characters() {
        use crate::bailiff_decision::{Decider, Decision};
        use crate::bailiff_plan_note::PlanId;
        use crate::bailiff_plan_view::{BailiffPlanSummary, DecisionSummary, SubmissionSummary};

        let summary = BailiffPlanSummary {
            plan_id: PlanId::from_uuid("33333333-3333-4333-8333-333333333333".parse().unwrap()),
            submission: Some(SubmissionSummary {
                purpose: "line1\nplan_id=forged\nline3".into(),
                submitted_at: UnixMillis::from_millis(10),
            }),
            decision: Some(DecisionSummary {
                outcome: Decision::Accepted,
                decider: Decider::try_new("<none>").unwrap(),
                decided_at: UnixMillis::from_millis(20),
            }),
            reviewed_at: None,
            implemented_at: None,
        };
        let mut out = Vec::new();
        write_bailiff_plan_list(&mut out, &[summary]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        // The forged-newline purpose round-trips as one quoted line.
        assert!(
            rendered.contains("\npurpose=\"line1\\nplan_id=forged\\nline3\"\n"),
            "expected escaped purpose, got: {rendered}"
        );
        // The literal-`<none>` decider is distinguishable from absence
        // because the quoted form starts with `"`.
        assert!(
            rendered.contains("\ndecision_decider=\"<none>\"\n"),
            "expected quoted decider, got: {rendered}"
        );
        // Sanity: exactly one line *starts* with `plan_id=`. The
        // forged `plan_id=forged` substring survives inside the
        // quoted purpose value, but it is no longer at the start of
        // a line, so the framing is unambiguous to a consumer that
        // tokenises by `\n` first.
        let plan_id_line_count = rendered
            .lines()
            .filter(|line| line.starts_with("plan_id="))
            .count();
        assert_eq!(plan_id_line_count, 1, "got: {rendered}");
    }

    /// A purpose containing characters that need quoting — backslash,
    /// double quote, carriage return — round-trips through the escape
    /// table. Pins each escape so the quoted form is reversible.
    #[test]
    fn bailiff_plan_list_escapes_backslash_quote_and_carriage_return() {
        use crate::bailiff_plan_note::PlanId;
        use crate::bailiff_plan_view::{BailiffPlanSummary, SubmissionSummary};

        let summary = BailiffPlanSummary {
            plan_id: PlanId::from_uuid("44444444-4444-4444-8444-444444444444".parse().unwrap()),
            submission: Some(SubmissionSummary {
                purpose: "a\\b\"c\rd".into(),
                submitted_at: UnixMillis::from_millis(1),
            }),
            decision: None,
            reviewed_at: None,
            implemented_at: None,
        };
        let mut out = Vec::new();
        write_bailiff_plan_list(&mut out, &[summary]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("\npurpose=\"a\\\\b\\\"c\\rd\"\n"),
            "expected escapes for backslash, quote, and CR; got: {rendered}"
        );
    }

    /// The `Corrupt` state — submission missing but other notes
    /// present — renders `state=corrupt` and `purpose=<none>`. Pins
    /// the operator-visible anomaly signal so a regression that
    /// silently dropped corrupt rows or rendered an empty state would
    /// surface here.
    #[test]
    fn bailiff_plan_list_renders_corrupt_state_when_submission_missing() {
        use crate::bailiff_decision::{Decider, Decision};
        use crate::bailiff_plan_note::PlanId;
        use crate::bailiff_plan_view::{BailiffPlanSummary, DecisionSummary};

        let summary = BailiffPlanSummary {
            plan_id: PlanId::from_uuid("ccccdddd-eeee-4fff-8000-111111111111".parse().unwrap()),
            submission: None,
            decision: Some(DecisionSummary {
                outcome: Decision::Rejected,
                decider: Decider::try_new("cli:bob").unwrap(),
                decided_at: UnixMillis::from_millis(5),
            }),
            reviewed_at: None,
            implemented_at: None,
        };
        let mut out = Vec::new();
        write_bailiff_plan_list(&mut out, &[summary]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(rendered.contains("\nstate=corrupt\n"));
        assert!(rendered.contains("\npurpose=<none>\n"));
        assert!(rendered.contains("\nsubmitted_at=<none>\n"));
        assert!(rendered.contains("\ndecision_outcome=rejected\n"));
    }

    // --- bailiff plan show formatter -----------------------------------

    mod show_tests {
        use super::*;
        use crate::bailiff_decision::{Decider, Decision};
        use crate::bailiff_plan_note::{DecisionNote, ImplementNote, PlanId, PlanNote, ReviewNote};
        use crate::bailiff_plan_view::{PlanFullView, VerifiedSection};
        use crate::core::{
            CapabilitySet, RepoRef, Sha256Hex, SshKeyFingerprint, SshSignature, UnixMillis,
        };
        use crate::protocol::SignedRunMetadata;
        use crate::run_envelope::SignedRunEnvelope;
        use crate::run_verify::VerifyError;
        use crate::vm_git::GitObjectId;

        const PLAN_ID_HEX: &str = "01234567-89ab-4cde-8123-456789abcdef";
        const WRIT_OUTPUT_OID: &str = "1111111111111111111111111111111111111111";
        const RUN_ID: &str = "22222222-2222-4222-8222-222222222222";
        const SESSION_ID: &str = "33333333-3333-4333-8333-333333333333";
        const FINGERPRINT: &str = "SHA256:nP9o8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        fn sample_metadata() -> SignedRunMetadata {
            SignedRunMetadata {
                run_id: RUN_ID.parse().unwrap(),
                session_id: SESSION_ID.parse().unwrap(),
                prompt_sha256: Sha256Hex::try_new("a".repeat(64)).unwrap(),
                output_envelope_sha256: Sha256Hex::try_new("b".repeat(64)).unwrap(),
                capabilities: vec![CapabilitySet::WorkspaceRead {
                    repo: RepoRef {
                        owner: "smaug123".into(),
                        name: "writ".into(),
                    },
                }],
                exit_code: 0,
                completed_at: UnixMillis::from_millis(1_700_000_000_000),
                signing_key_fingerprint: SshKeyFingerprint::try_new(FINGERPRINT.to_string())
                    .unwrap(),
            }
        }

        fn sample_signature() -> SshSignature {
            SshSignature::try_new(
                "-----BEGIN SSH SIGNATURE-----\nsomebase64==\n-----END SSH SIGNATURE-----"
                    .to_string(),
            )
            .unwrap()
        }

        fn sample_envelope() -> SignedRunEnvelope {
            // Output bytes don't need to match the digest in
            // `sample_metadata`'s `output_envelope_sha256` — the show
            // formatter does not re-verify; it only projects fields
            // through to text. The verification status is what the
            // `VerifiedSection` variant carries.
            SignedRunEnvelope {
                metadata: sample_metadata(),
                signature: sample_signature(),
                output: b"agent stdout bytes".to_vec(),
            }
        }

        fn sample_plan_note() -> PlanNote {
            PlanNote {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                purpose: "plan-submit".into(),
                writ_output_oid: GitObjectId::new(WRIT_OUTPUT_OID.to_string()).unwrap(),
                signed_metadata: sample_metadata(),
                signature: sample_signature(),
            }
        }

        fn sample_review_note() -> ReviewNote {
            ReviewNote {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                purpose: "plan-review".into(),
                writ_output_oid: GitObjectId::new(WRIT_OUTPUT_OID.to_string()).unwrap(),
                signed_metadata: sample_metadata(),
                signature: sample_signature(),
            }
        }

        fn sample_implement_note() -> ImplementNote {
            ImplementNote {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                purpose: "plan-implement".into(),
                writ_output_oid: GitObjectId::new(WRIT_OUTPUT_OID.to_string()).unwrap(),
                signed_metadata: sample_metadata(),
                signature: sample_signature(),
            }
        }

        fn empty_view() -> PlanFullView {
            PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: None,
                decision: None,
                review: None,
                implement: None,
            }
        }

        fn render(view: &PlanFullView) -> String {
            let mut out = Vec::new();
            write_bailiff_plan_show(&mut out, view).unwrap();
            String::from_utf8(out).unwrap()
        }

        /// An empty view (no notes attached under the plan ref — the
        /// "lookup hit nothing" case) still renders the canonical
        /// four-section frame, every section showing `<none>`. Pins
        /// the always-emit-headers contract so a regression that
        /// silently skipped absent sections surfaces here.
        #[test]
        fn show_renders_all_four_section_headers_with_none_when_empty() {
            let rendered = render(&empty_view());
            assert_eq!(
                rendered,
                concat!(
                    "plan_id=01234567-89ab-4cde-8123-456789abcdef\n",
                    "\n",
                    "-- plan --\n",
                    "verification=<none>\n",
                    "\n",
                    "-- decision --\n",
                    "outcome=<none>\n",
                    "\n",
                    "-- review --\n",
                    "verification=<none>\n",
                    "\n",
                    "-- implement --\n",
                    "verification=<none>\n",
                ),
            );
        }

        /// A `Verified` plan section renders the unified metadata
        /// projection: note-side scalars (`purpose`, `writ_output_oid`)
        /// plus envelope-side metadata. No `note_` prefixes appear
        /// because note and envelope agree in this variant. Pins the
        /// concrete shape so an operator scripting against the output
        /// has a stable contract.
        #[test]
        fn show_renders_verified_plan_section_with_full_metadata_projection() {
            let view = PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: Some(VerifiedSection::Verified {
                    note: sample_plan_note(),
                    envelope: sample_envelope(),
                }),
                decision: None,
                review: None,
                implement: None,
            };
            let rendered = render(&view);
            let plan_block = concat!(
                "-- plan --\n",
                "verification=verified\n",
                "purpose=plan-submit\n",
                "writ_output_oid=1111111111111111111111111111111111111111\n",
                "run_id=22222222-2222-4222-8222-222222222222\n",
                "session_id=33333333-3333-4333-8333-333333333333\n",
                "prompt_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                "output_envelope_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
                "exit_code=0\n",
                "completed_at=1700000000000\n",
                "signing_key_fingerprint=SHA256:nP9o8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
                "capability=workspace_read:smaug123/writ\n",
            );
            assert!(rendered.contains(plan_block), "got: {rendered}");
            assert!(
                !rendered.contains("note_run_id="),
                "Verified must not emit note_ prefixes; got: {rendered}",
            );
        }

        /// A `NoteEnvelopeMismatch` plan section renders both the
        /// envelope's metadata (unprefixed; the cryptographic truth)
        /// and the note's metadata (prefixed `note_`). Pins the
        /// dual-projection that lets operators diff the two without
        /// re-reading either source — the divergence is the trust
        /// violation.
        #[test]
        fn show_renders_note_envelope_mismatch_with_both_projections() {
            // Make the note's metadata visibly divergent from the
            // envelope's so a regression that emits the same values
            // under both prefixes surfaces here.
            let mut divergent_note = sample_plan_note();
            divergent_note.signed_metadata.run_id =
                "99999999-9999-4999-8999-999999999999".parse().unwrap();
            divergent_note.signed_metadata.completed_at =
                UnixMillis::from_millis(1_800_000_000_000);
            let view = PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: Some(VerifiedSection::NoteEnvelopeMismatch {
                    note: divergent_note,
                    envelope: sample_envelope(),
                }),
                decision: None,
                review: None,
                implement: None,
            };
            let rendered = render(&view);
            assert!(rendered.contains("verification=note_envelope_mismatch\n"));
            // Envelope-side (unprefixed) holds the original metadata.
            assert!(rendered.contains("run_id=22222222-2222-4222-8222-222222222222\n"));
            assert!(rendered.contains("completed_at=1700000000000\n"));
            // Note-side carries the divergent values under `note_`.
            assert!(rendered.contains("note_run_id=99999999-9999-4999-8999-999999999999\n"));
            assert!(rendered.contains("note_completed_at=1800000000000\n"));
            // Both signatures hash to the same value (this fixture
            // reuses `sample_signature()` on both sides). The lines
            // must still be present so the operator can confirm the
            // divergence is metadata-only.
            let expected_sig_digest =
                crate::agent_run::sha256_hex(sample_signature().as_str().as_bytes());
            assert!(
                rendered.contains(&format!("signature_sha256={expected_sig_digest}\n")),
                "missing envelope-side signature digest: {rendered}",
            );
            assert!(
                rendered.contains(&format!("note_signature_sha256={expected_sig_digest}\n")),
                "missing note-side signature digest: {rendered}",
            );
        }

        /// Regression for a Codex P2 finding: when only the signature
        /// differs (metadata byte-equal) the previous formatter
        /// emitted two byte-identical metadata projections with no
        /// hint as to what diverged. The `signature_sha256` /
        /// `note_signature_sha256` lines must hash the two
        /// signatures separately so the operator sees the
        /// divergence at a glance — full PEM-armoured signatures
        /// would flood the page, but a digest pin is enough to
        /// confirm "the two differ."
        #[test]
        fn show_signature_only_mismatch_renders_distinct_signature_digests() {
            // Note and envelope share metadata but carry distinct
            // signature bodies — the case Codex called out.
            let envelope_signature = sample_signature();
            let note_signature = SshSignature::try_new(
                "-----BEGIN SSH SIGNATURE-----\ndifferentbase64==\n-----END SSH SIGNATURE-----"
                    .to_string(),
            )
            .unwrap();
            let mut note = sample_plan_note();
            note.signature = note_signature.clone();
            let envelope = SignedRunEnvelope {
                metadata: sample_metadata(),
                signature: envelope_signature.clone(),
                output: b"out".to_vec(),
            };
            let view = PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: Some(VerifiedSection::NoteEnvelopeMismatch { note, envelope }),
                decision: None,
                review: None,
                implement: None,
            };
            let rendered = render(&view);
            let envelope_digest =
                crate::agent_run::sha256_hex(envelope_signature.as_str().as_bytes());
            let note_digest = crate::agent_run::sha256_hex(note_signature.as_str().as_bytes());
            assert_ne!(
                envelope_digest, note_digest,
                "fixture must exercise a real divergence",
            );
            assert!(
                rendered.contains(&format!("signature_sha256={envelope_digest}\n")),
                "missing envelope-side signature digest: {rendered}",
            );
            assert!(
                rendered.contains(&format!("note_signature_sha256={note_digest}\n")),
                "missing note-side signature digest: {rendered}",
            );
        }

        /// `WritEnvelopeMissing` projects the note's metadata as the
        /// best available view (envelope is absent). The verification
        /// line names the variant so an operator can re-run the
        /// relevant `submit*` verb to recover.
        #[test]
        fn show_renders_writ_envelope_missing_with_note_metadata() {
            let view = PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: Some(VerifiedSection::WritEnvelopeMissing {
                    note: sample_plan_note(),
                }),
                decision: None,
                review: None,
                implement: None,
            };
            let rendered = render(&view);
            assert!(rendered.contains("verification=writ_envelope_missing\n"));
            assert!(rendered.contains("purpose=plan-submit\n"));
            assert!(rendered.contains("run_id=22222222-2222-4222-8222-222222222222\n"));
            // No envelope-side payload or error line: those keys belong
            // to the variants that carry an envelope or an error.
            assert!(!rendered.contains("envelope_error="), "{rendered}");
            assert!(!rendered.contains("verify_error="), "{rendered}");
            assert!(!rendered.contains("note_run_id="), "{rendered}");
        }

        /// `EnvelopeMalformed` projects the note's metadata plus a
        /// quoted `envelope_error=` line carrying the decode failure
        /// message. The error string is routed through
        /// [`write_inline_value`] so a serde error containing a
        /// newline cannot inject a fake key=value line downstream.
        #[test]
        fn show_renders_envelope_malformed_with_quoted_decode_error() {
            // Synthesise a `serde_json::Error` whose `Display` form
            // contains a newline so the inline-quoting branch fires.
            let decode_error: serde_json::Error =
                serde_json::from_slice::<SignedRunEnvelope>(b"not\njson").unwrap_err();
            let view = PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: Some(VerifiedSection::EnvelopeMalformed {
                    note: sample_plan_note(),
                    error: decode_error,
                }),
                decision: None,
                review: None,
                implement: None,
            };
            let rendered = render(&view);
            assert!(rendered.contains("verification=envelope_malformed\n"));
            // The error line is present, on its own one-line key=value.
            let envelope_error_line = rendered
                .lines()
                .find(|l| l.starts_with("envelope_error="))
                .unwrap_or_else(|| panic!("missing envelope_error line in {rendered}"));
            // Exactly one `envelope_error=` line — the inline-quote
            // branch must collapse multi-line decode messages into a
            // single quoted token rather than emitting them verbatim.
            assert_eq!(
                rendered
                    .lines()
                    .filter(|l| l.starts_with("envelope_error="))
                    .count(),
                1,
                "expected exactly one envelope_error line, got: {rendered}",
            );
            // The note-side projection is still there.
            assert!(rendered.contains("purpose=plan-submit\n"));
            // The quoted form is present iff the error needs quoting;
            // we don't pin the exact decode message because serde_json's
            // wording is implementation-detail.
            assert!(
                !envelope_error_line.is_empty(),
                "envelope_error must not be blank, got: {rendered}",
            );
        }

        /// `SignatureFailure` projects the note's metadata plus a
        /// quoted `verify_error=` line naming the specific check that
        /// failed. Pin the error projection here so a regression that
        /// dropped the failure detail surfaces.
        #[test]
        fn show_renders_signature_failure_with_verify_error_line() {
            let view = PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: Some(VerifiedSection::SignatureFailure {
                    note: sample_plan_note(),
                    error: VerifyError::UnknownSigner {
                        fingerprint: SshKeyFingerprint::try_new(FINGERPRINT.to_string()).unwrap(),
                    },
                }),
                decision: None,
                review: None,
                implement: None,
            };
            let rendered = render(&view);
            assert!(rendered.contains("verification=signature_failure\n"));
            assert!(
                rendered.contains(&format!(
                    "verify_error=signing key {FINGERPRINT} is not in the allowed-signers list\n"
                )),
                "{rendered}"
            );
        }

        /// A populated decision section renders three key=value lines.
        /// Pins the shape; an absent decision (covered above) renders
        /// `outcome=<none>`.
        #[test]
        fn show_renders_decision_block_with_outcome_decider_and_decided_at() {
            let view = PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: None,
                decision: Some(DecisionNote {
                    plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                    outcome: Decision::Accepted,
                    decider: Decider::try_new("cli:alice").unwrap(),
                    decided_at: UnixMillis::from_millis(1_700_000_001_000),
                }),
                review: None,
                implement: None,
            };
            let rendered = render(&view);
            let block = concat!(
                "-- decision --\n",
                "outcome=accepted\n",
                "decider=cli:alice\n",
                "decided_at=1700000001000\n",
            );
            assert!(rendered.contains(block), "got: {rendered}");
        }

        /// An adversarial purpose carrying a newline survives the
        /// inline-quote pass — it cannot inject a fake `verification=`
        /// or `outcome=` line downstream. Pins the injection-safety
        /// contract for free-form text fields, parallel with the list
        /// verb's `bailiff_plan_list_quotes_purpose_and_decider_with_injection_characters`.
        #[test]
        fn show_quotes_purpose_with_embedded_newline() {
            let mut hostile_note = sample_plan_note();
            hostile_note.purpose = "first\nverification=forged\nsecond".into();
            let view = PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: Some(VerifiedSection::WritEnvelopeMissing { note: hostile_note }),
                decision: None,
                review: None,
                implement: None,
            };
            let rendered = render(&view);
            // The forged "verification=forged" survives inside the
            // quoted purpose but is no longer at the start of a line.
            assert!(
                rendered.contains("\npurpose=\"first\\nverification=forged\\nsecond\"\n"),
                "expected quoted purpose, got: {rendered}",
            );
            // Exactly one line starts with `verification=` — the real
            // one — so a tokeniser splitting on `\n` first cannot be
            // tricked into seeing the forged value.
            let count = rendered
                .lines()
                .filter(|l| l.starts_with("verification="))
                .count();
            // The three signed sections each emit one
            // `verification=` line; the decision section emits
            // `outcome=` instead.
            assert_eq!(count, 3, "got: {rendered}");
        }

        /// An adversarial decider equal to the literal `<none>`
        /// sentinel renders in quoted form so it is distinguishable
        /// from absence. Parallel with the list verb's pin.
        #[test]
        fn show_quotes_decider_when_equal_to_none_sentinel() {
            let view = PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: None,
                decision: Some(DecisionNote {
                    plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                    outcome: Decision::Rejected,
                    decider: Decider::try_new("<none>").unwrap(),
                    decided_at: UnixMillis::from_millis(1),
                }),
                review: None,
                implement: None,
            };
            let rendered = render(&view);
            assert!(
                rendered.contains("decider=\"<none>\"\n"),
                "expected quoted decider, got: {rendered}",
            );
        }

        /// Section ordering is `plan` → `decision` → `review` →
        /// `implement`. A regression to a different order would break
        /// scripts that parse positionally; pin the contract.
        #[test]
        fn show_emits_sections_in_canonical_order() {
            let view = PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: Some(VerifiedSection::WritEnvelopeMissing {
                    note: sample_plan_note(),
                }),
                decision: Some(DecisionNote {
                    plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                    outcome: Decision::Accepted,
                    decider: Decider::try_new("cli:alice").unwrap(),
                    decided_at: UnixMillis::from_millis(2),
                }),
                review: Some(VerifiedSection::WritEnvelopeMissing {
                    note: sample_review_note(),
                }),
                implement: Some(VerifiedSection::WritEnvelopeMissing {
                    note: sample_implement_note(),
                }),
            };
            let rendered = render(&view);
            let plan_at = rendered.find("-- plan --").unwrap();
            let decision_at = rendered.find("-- decision --").unwrap();
            let review_at = rendered.find("-- review --").unwrap();
            let implement_at = rendered.find("-- implement --").unwrap();
            assert!(plan_at < decision_at);
            assert!(decision_at < review_at);
            assert!(review_at < implement_at);
        }

        /// Multiple capabilities render as one `capability=` line per
        /// entry, in input order. Pins the per-entry shape so a
        /// future capability variant carrying a list-of-repos doesn't
        /// regress the per-line invariant.
        #[test]
        fn show_renders_one_capability_line_per_entry_in_input_order() {
            let mut metadata = sample_metadata();
            metadata.capabilities = vec![
                CapabilitySet::WorkspaceRead {
                    repo: RepoRef {
                        owner: "smaug123".into(),
                        name: "alpha".into(),
                    },
                },
                CapabilitySet::WorkspaceWrite {
                    repo: RepoRef {
                        owner: "smaug123".into(),
                        name: "beta".into(),
                    },
                },
            ];
            let mut note = sample_plan_note();
            note.signed_metadata = metadata.clone();
            let envelope = SignedRunEnvelope {
                metadata,
                signature: sample_signature(),
                output: b"out".to_vec(),
            };
            let view = PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: Some(VerifiedSection::Verified { note, envelope }),
                decision: None,
                review: None,
                implement: None,
            };
            let rendered = render(&view);
            let lines: Vec<&str> = rendered
                .lines()
                .filter(|l| l.starts_with("capability="))
                .collect();
            assert_eq!(
                lines,
                vec![
                    "capability=workspace_read:smaug123/alpha",
                    "capability=workspace_write:smaug123/beta",
                ],
            );
        }

        /// A capability whose `RepoRef` carries a newline (which
        /// `RepoRef::from_str` does not reject; a tampered envelope
        /// can still deserialize one) must be quoted, not emitted
        /// raw. The unquoted form would break the one-key-per-line
        /// invariant and could forge additional lines under any
        /// later key. Pins that `capability=` routes through
        /// `write_inline_value`.
        #[test]
        fn show_quotes_capability_with_embedded_newline() {
            let mut metadata = sample_metadata();
            metadata.capabilities = vec![CapabilitySet::WorkspaceRead {
                repo: RepoRef {
                    owner: "evil\noutput".into(),
                    name: "victim".into(),
                },
            }];
            let mut note = sample_plan_note();
            note.signed_metadata = metadata.clone();
            let envelope = SignedRunEnvelope {
                metadata,
                signature: sample_signature(),
                output: b"out".to_vec(),
            };
            let view = PlanFullView {
                plan_id: PlanId::from_uuid(PLAN_ID_HEX.parse().unwrap()),
                plan: Some(VerifiedSection::Verified { note, envelope }),
                decision: None,
                review: None,
                implement: None,
            };
            let rendered = render(&view);
            assert!(
                rendered.contains("capability=\"workspace_read:evil\\noutput/victim\""),
                "got: {rendered}",
            );
            // And the literal newline must NOT appear inside the
            // capability line — otherwise the injected `output`
            // token would surface as its own bogus key.
            assert!(
                !rendered.contains("evil\noutput"),
                "literal newline leaked into output: {rendered}",
            );
        }
    }
}
