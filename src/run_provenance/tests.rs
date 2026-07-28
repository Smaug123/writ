//! Properties of [`super::cross_check`].
//!
//! The interesting question about a cross-check is not whether it catches the
//! mismatch someone thought to write a test for — it is whether every field it
//! claims to compare is actually compared, and whether it stays quiet when
//! nothing is wrong. Both are properties over the whole space of runs, so both
//! are tested that way.

use super::*;
use crate::agent_run::{
    AgentPromptSummary, AgentRunOutcome, AgentRunStreamSummary, AgentRunTerminalStatus,
};
use proptest::prelude::*;

/// The five fields `cross_check` compares, as data.
///
/// Naming them lets one property say "perturb exactly this field and expect
/// exactly its finding", which is what pins that no field is silently
/// unchecked. A field added to the comparison without being added here shows
/// up as a gap in this list rather than as a passing test suite.
#[derive(Clone, Copy, Debug)]
enum ComparedField {
    Session,
    Prompt,
    ExitCode,
    CompletedAt,
    OutputEnvelope,
}

const COMPARED_FIELDS: &[ComparedField] = &[
    ComparedField::Session,
    ComparedField::Prompt,
    ComparedField::ExitCode,
    ComparedField::CompletedAt,
    ComparedField::OutputEnvelope,
];

fn sha256_hex_strategy() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        proptest::sample::select(b"0123456789abcdef".to_vec()),
        64..=64,
    )
    .prop_map(|bytes| String::from_utf8(bytes).expect("hex digits are ASCII"))
}

/// An audited run and the signed metadata a *truthful* note about it carries.
///
/// Built as a pair from one source of truth so the two agree by construction:
/// the properties below are about what happens when that agreement is broken,
/// which means the unbroken case has to be exactly right first.
fn matching_pair() -> impl Strategy<Value = (SignedRunMetadata, AuditedRun)> {
    (
        sha256_hex_strategy(),
        sha256_hex_strategy(),
        sha256_hex_strategy(),
        sha256_hex_strategy(),
        any::<i32>(),
        0i64..4_000_000_000_000,
        0u64..1_000_000,
        proptest::option::of(proptest::sample::select(vec![
            "plan-submit",
            "review:plan-abc",
            "review of plan #3",
        ])),
    )
        .prop_map(
            |(
                prompt_sha,
                envelope_sha,
                stdout_sha,
                stderr_sha,
                exit_code,
                completed_ms,
                prompt_bytes,
                purpose,
            )| {
                let run_id = AgentRunId::new();
                let session_id = SessionId::new();
                let completed_at = UnixMillis::from_millis(completed_ms);
                let stream = |sha: String, name: &str| AgentRunStreamSummary {
                    path: std::path::PathBuf::from(format!("/logs/{run_id}/{name}.log")),
                    byte_len: 0,
                    sha256_hex: sha,
                    truncated: false,
                };
                let request = AgentRunAuditRecord {
                    run_id,
                    session_id,
                    requested_at: completed_at,
                    agent_kind: crate::core::AgentKind::Claude,
                    prompt: AgentPromptSummary {
                        byte_len: prompt_bytes,
                        sha256_hex: prompt_sha.clone(),
                        redacted_preview: "<redacted>".to_string(),
                    },
                    correlation_id: None,
                    purpose: purpose
                        .map(|p| crate::agent_run::RunPurpose::try_new(p).expect("a valid tag")),
                };
                let outcome = AgentRunOutcomeAuditRecord {
                    completed_at,
                    outcome: AgentRunOutcome {
                        run_id,
                        status: if exit_code == 0 {
                            AgentRunTerminalStatus::Succeeded
                        } else {
                            AgentRunTerminalStatus::Failed
                        },
                        exit_code,
                        stdout: stream(stdout_sha, "stdout"),
                        stderr: stream(stderr_sha, "stderr"),
                    },
                };
                let signed = SignedRunMetadata {
                    run_id,
                    session_id,
                    prompt_sha256: Sha256Hex::try_new(prompt_sha).expect("64 hex digits"),
                    output_envelope_sha256: Sha256Hex::try_new(envelope_sha.clone())
                        .expect("64 hex digits"),
                    capabilities: Vec::new(),
                    exit_code,
                    completed_at,
                    signing_key_fingerprint: fingerprint(),
                };
                let audited = AuditedRun {
                    request,
                    outcome,
                    output_envelope_sha256: Sha256Hex::try_new(envelope_sha)
                        .expect("64 hex digits"),
                };
                (signed, audited)
            },
        )
}

/// Any fingerprint; `cross_check` does not compare it (the shell verifies the
/// signature instead), so its value is immaterial here.
fn fingerprint() -> crate::core::SshKeyFingerprint {
    const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");
    crate::signing::WritSigningKey::from_openssh_pem(SIGNING_PEM)
        .expect("the fixture key parses")
        .fingerprint()
}

/// Change one compared field on the *note*, leaving the log untouched.
fn perturb(signed: &mut SignedRunMetadata, field: ComparedField) {
    // A hash that differs from any the generator produces: it is out of the
    // generator's alphabet only in value, not in shape, so it stays a valid
    // `Sha256Hex` and the comparison — not a parse — is what rejects it.
    let other_hash = || Sha256Hex::try_new("f".repeat(64)).expect("64 hex digits");
    match field {
        ComparedField::Session => signed.session_id = SessionId::new(),
        ComparedField::Prompt => signed.prompt_sha256 = other_hash(),
        ComparedField::ExitCode => signed.exit_code = signed.exit_code.wrapping_add(1),
        ComparedField::CompletedAt => {
            signed.completed_at = UnixMillis::from_millis(signed.completed_at.as_millis() + 1);
        }
        ComparedField::OutputEnvelope => signed.output_envelope_sha256 = other_hash(),
    }
}

fn matches_field(finding: &RunProvenanceFinding, field: ComparedField) -> bool {
    matches!(
        (finding, field),
        (
            RunProvenanceFinding::SessionMismatch { .. },
            ComparedField::Session
        ) | (
            RunProvenanceFinding::PromptMismatch { .. },
            ComparedField::Prompt
        ) | (
            RunProvenanceFinding::ExitCodeMismatch { .. },
            ComparedField::ExitCode
        ) | (
            RunProvenanceFinding::CompletedAtMismatch { .. },
            ComparedField::CompletedAt
        ) | (
            RunProvenanceFinding::OutputEnvelopeMismatch { .. },
            ComparedField::OutputEnvelope
        )
    )
}

proptest! {
    /// A truthful note about an audited run reports nothing.
    ///
    /// The quiet case is the one that matters most in practice — a check that
    /// cries wolf on honest runs is a check operators learn to ignore — and it
    /// is the easiest to get wrong by comparing a field to itself in the wrong
    /// representation (a hash to a hex string, a timestamp to a different
    /// unit).
    #[test]
    fn a_note_that_matches_its_audit_rows_reports_nothing((signed, audited) in matching_pair()) {
        let findings = cross_check(&signed, &audited);
        prop_assert!(
            findings.is_empty(),
            "an honest note must corroborate cleanly, got {findings:?}",
        );
        let verdict = RunProvenanceVerdict::Checked {
            run_id: signed.run_id,
            findings,
        };
        prop_assert!(verdict.is_corroborated());
    }

    /// Altering any one compared field produces exactly that field's finding.
    ///
    /// Two things at once, and both are the point. *Exactly one* means no
    /// spurious findings — a mismatch report an operator cannot trust to be
    /// minimal is a report they have to re-derive by hand. *That field's*
    /// means every field named in the comparison is genuinely compared: a
    /// field dropped from `cross_check` fails here rather than passing
    /// silently, which is the failure mode a hand-written example per field
    /// would not catch when someone later adds a sixth field.
    #[test]
    fn altering_one_compared_field_produces_exactly_that_finding(
        (signed, audited) in matching_pair(),
        index in 0usize..COMPARED_FIELDS.len(),
    ) {
        let field = COMPARED_FIELDS[index];
        let mut tampered = signed.clone();
        perturb(&mut tampered, field);

        let findings = cross_check(&tampered, &audited);
        prop_assert_eq!(
            findings.len(),
            1,
            "perturbing {:?} must report it and nothing else, got {:?}",
            field,
            findings,
        );
        prop_assert!(
            matches_field(&findings[0], field),
            "perturbing {field:?} reported {:?}",
            findings[0],
        );
        let verdict = RunProvenanceVerdict::Checked {
            run_id: tampered.run_id,
            findings,
        };
        prop_assert!(!verdict.is_corroborated());
    }

    /// `cross_check` is invariant under the audit row's `purpose`.
    ///
    /// Deliberate, not an oversight: the signed metadata has no purpose
    /// field, so there is nothing on the note to compare the column
    /// against, and a "finding" derived from one side alone would be a
    /// disagreement with silence. Asserted rather than left implicit
    /// because the next person to read `cross_check` will see a column
    /// it ignores and have to work out whether that was intended.
    ///
    /// If the signed format ever grows a purpose, this property is what
    /// fails, and the fix is to compare it — not to delete this.
    #[test]
    fn the_comparison_ignores_the_audit_rows_purpose(
        (signed, audited) in matching_pair(),
        other in proptest::option::of(proptest::sample::select(vec![
            "plan-implement",
            "something else entirely",
        ])),
    ) {
        let baseline = cross_check(&signed, &audited);
        let repurposed = AuditedRun {
            request: AgentRunAuditRecord {
                purpose: other
                    .map(|p| crate::agent_run::RunPurpose::try_new(p).expect("a valid tag")),
                ..audited.request.clone()
            },
            ..audited.clone()
        };
        prop_assert_eq!(cross_check(&signed, &repurposed), baseline);
    }

    /// Findings come out in a fixed order, so two reports over the same
    /// divergence are byte-identical and an operator can diff them.
    #[test]
    fn findings_are_reported_in_field_order((signed, audited) in matching_pair()) {
        let mut tampered = signed.clone();
        for field in COMPARED_FIELDS {
            perturb(&mut tampered, *field);
        }
        let findings = cross_check(&tampered, &audited);
        prop_assert_eq!(findings.len(), COMPARED_FIELDS.len());
        for (finding, field) in findings.iter().zip(COMPARED_FIELDS) {
            prop_assert!(
                matches_field(finding, *field),
                "expected {field:?} at its position, got {finding:?}",
            );
        }
    }
}

/// A verdict that is not a clean comparison never reads as corroboration —
/// including `UnknownRun`, which is the one most easily mistaken for "nothing
/// wrong found".
#[test]
fn only_a_clean_comparison_counts_as_corroborated() {
    let run_id = AgentRunId::new();
    assert!(
        RunProvenanceVerdict::Checked {
            run_id,
            findings: Vec::new(),
        }
        .is_corroborated()
    );
    for verdict in [
        RunProvenanceVerdict::NotOurs {
            fingerprint: fingerprint(),
        },
        RunProvenanceVerdict::SignatureInvalid,
        RunProvenanceVerdict::UnknownRun { run_id },
        RunProvenanceVerdict::OutcomePending { run_id },
    ] {
        assert!(
            !verdict.is_corroborated(),
            "{verdict:?} must not read as corroboration",
        );
    }
}
