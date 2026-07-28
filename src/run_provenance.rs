//! Cross-check a signed run envelope against writ's own audit log.
//!
//! [`verify_run_envelope`](crate::run_verify::verify_run_envelope) answers a
//! narrower question than it looks like it answers: it proves the metadata was
//! signed by a key the verifier trusts and that the output bytes hash to what
//! the metadata claims. Both facts come *out of the envelope itself*. A note
//! that is internally consistent and correctly signed still says nothing about
//! whether writ ever ran the thing it describes — which is the question an
//! operator actually has when a workflow shows them a result.
//!
//! The audit log is the other half. Every field worth comparing already exists
//! on both sides, so this needs no change to the signed format: the row knows
//! the session, the prompt hash, the exit code, when the run finished, and
//! where its streams landed.
//!
//! This module is the pure half — it compares two already-loaded descriptions
//! of one run and says where they differ. Loading them, verifying the
//! signature, and re-deriving the output hash from the recorded stream files
//! belong to the shell, because only the daemon has the database and the
//! files.
//!
//! **What this does and does not establish.** Agreement means the log and the
//! note tell one story. It is not proof against a determined local attacker:
//! writ is single-operator, so whoever can rewrite the audit database can also
//! reach the signing key and mint a note to match. What it does catch is the
//! whole space of *partial* divergence — a note altered without the log, a row
//! altered without the note, a stream file replaced after the fact, or a bug
//! in either writer — and that is the space where a silent wrong answer is
//! otherwise indistinguishable from a right one.

use crate::agent_run::AgentRunId;
use crate::audit::{AgentRunAuditRecord, AgentRunOutcomeAuditRecord};
use crate::core::{SessionId, Sha256Hex, UnixMillis};
use crate::protocol::SignedRunMetadata;
use serde::{Deserialize, Serialize};

/// One run as writ's audit log describes it, assembled by the shell.
///
/// `output_envelope_sha256` is not a column: it is re-derived by rebuilding
/// the output envelope from the stream files the outcome row names. That
/// rebuild is the same code path the signing step used, so agreement here
/// means the envelope a verifier holds still describes the bytes writ kept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditedRun {
    pub request: AgentRunAuditRecord,
    pub outcome: AgentRunOutcomeAuditRecord,
    pub output_envelope_sha256: Sha256Hex,
}

/// One way a signed note and the audit log disagree about the same run.
///
/// Each variant carries both sides, because "they differ" is not actionable on
/// its own — an operator needs to see which value came from where to tell a
/// tampered note from a tampered row from a bug.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "finding", rename_all = "snake_case")]
pub enum RunProvenanceFinding {
    /// The note claims a different audit session than the row records. The
    /// session is the authority window the run happened inside, so this is the
    /// difference between "authorised then" and "authorised at all".
    SessionMismatch {
        signed: SessionId,
        audited: SessionId,
    },
    /// The note claims a different prompt than the run was given. The row
    /// stores only the hash — the prompt itself is never persisted — so this
    /// compares hashes.
    PromptMismatch {
        signed: Sha256Hex,
        audited: String,
    },
    ExitCodeMismatch {
        signed: i32,
        audited: i32,
    },
    /// The note and the row disagree about when the run finished.
    CompletedAtMismatch {
        signed: UnixMillis,
        audited: UnixMillis,
    },
    /// The note's output digest does not match one re-derived from the stream
    /// files the outcome row names — so the note describes output writ no
    /// longer has, or never had.
    OutputEnvelopeMismatch {
        signed: Sha256Hex,
        audited: Sha256Hex,
    },
}

/// What writ can say about a signed note someone presents to it.
///
/// A discriminated union rather than a bag of optional fields, because the
/// cases are answers to different questions and only one of them can be true
/// at a time. In particular a rejected signature returns *alone*: once the
/// metadata has failed to verify, its fields are unattributed bytes, and
/// cross-checking them against the log would produce findings that read as
/// evidence about a run while being evidence about nothing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum RunProvenanceVerdict {
    /// The note was signed by a key this daemon does not hold. Not an
    /// accusation: it is the expected answer when a note is presented to the
    /// wrong writ.
    NotOurs {
        fingerprint: crate::core::SshKeyFingerprint,
    },
    /// The fingerprint is this daemon's, but the signature does not verify
    /// over the metadata as presented — so the metadata was altered after
    /// signing.
    SignatureInvalid,
    /// The signature verifies, but no run by that id was ever recorded. A
    /// genuine note this daemon signed always has a row, so this means the
    /// log lost it (or the note came from a different database).
    UnknownRun { run_id: AgentRunId },
    /// The run was launched but has no outcome row, so there is nothing to
    /// compare a *completed* run's note against. Either the run is still in
    /// flight or it never reported one.
    OutcomePending { run_id: AgentRunId },
    /// The log has both halves and they were compared. An empty `findings` is
    /// the corroborated case.
    Checked {
        run_id: AgentRunId,
        findings: Vec<RunProvenanceFinding>,
    },
}

impl RunProvenanceVerdict {
    /// Whether the log corroborates the note without qualification.
    ///
    /// Deliberately narrow: only a completed comparison with nothing to report
    /// counts. Every other verdict — including "no such run" — is a reason not
    /// to treat the note as backed by writ's history.
    pub fn is_corroborated(&self) -> bool {
        matches!(self, Self::Checked { findings, .. } if findings.is_empty())
    }
}

/// Compare a signed note's metadata against the audit log's record of the same
/// run, returning every way they disagree.
///
/// Total and order-stable: the findings come out in field order, so two runs
/// of this over the same inputs produce byte-identical output and a caller can
/// diff reports. Returns every disagreement rather than the first, because an
/// operator triaging a mismatch wants the shape of the divergence — one field
/// off suggests a bug, all of them suggests the note describes another run
/// entirely.
///
/// `capabilities` and `signing_key_fingerprint` are deliberately not compared:
/// the audit log has no column for either, so there is nothing to compare
/// against, and inventing agreement from silence would be worse than the gap.
/// The fingerprint is checked where it can be — the shell verifies the
/// signature against the daemon's own key before this is reached.
///
/// `purpose` is the same gap from the other side: the row has it, the signed
/// metadata does not. A caller's tag is not evidence about a run, and a
/// "finding" derived from one side alone would be a disagreement with silence.
/// The comparison is invariant under it, which the tests assert rather than
/// leave to be inferred from its absence here.
pub fn cross_check(signed: &SignedRunMetadata, audited: &AuditedRun) -> Vec<RunProvenanceFinding> {
    let mut findings = Vec::new();
    if signed.session_id != audited.request.session_id {
        findings.push(RunProvenanceFinding::SessionMismatch {
            signed: signed.session_id,
            audited: audited.request.session_id,
        });
    }
    if signed.prompt_sha256.as_str() != audited.request.prompt.sha256_hex {
        findings.push(RunProvenanceFinding::PromptMismatch {
            signed: signed.prompt_sha256.clone(),
            audited: audited.request.prompt.sha256_hex.clone(),
        });
    }
    if signed.exit_code != audited.outcome.outcome.exit_code {
        findings.push(RunProvenanceFinding::ExitCodeMismatch {
            signed: signed.exit_code,
            audited: audited.outcome.outcome.exit_code,
        });
    }
    if signed.completed_at != audited.outcome.completed_at {
        findings.push(RunProvenanceFinding::CompletedAtMismatch {
            signed: signed.completed_at,
            audited: audited.outcome.completed_at,
        });
    }
    if signed.output_envelope_sha256 != audited.output_envelope_sha256 {
        findings.push(RunProvenanceFinding::OutputEnvelopeMismatch {
            signed: signed.output_envelope_sha256.clone(),
            audited: audited.output_envelope_sha256.clone(),
        });
    }
    findings
}

#[cfg(test)]
mod tests;
