//! Payload types carried inside the wire messages.
//!
//! These are the structured values that ride inside [`super::ClientMessage`]
//! and [`super::ServerMessage`] — staged-push views, the run-metadata
//! envelope, the reconcile verdict, and the `RejectionReason` newtype with
//! its length-bounded parse. The message DUs themselves live in the parent
//! module and re-export everything here, so `crate::protocol::…` call sites
//! are unchanged. Split out of `protocol.rs` to keep the message enums
//! readable.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::agent_run::AgentRunId;
use crate::agent_vm_lifecycle::{AgentVmSessionStateStatus, NetworkHealth};
use crate::audit::GitPushOutcomeResult;
use crate::core::{CapabilitySet, RequestId, SessionId, Sha256Hex, SshKeyFingerprint, UnixMillis};
use crate::vm_git::{GitBranchName, GitCloneRepo, GitObjectId, VmGitPushStagedReceipt};

/// A persisted daemon-managed agent VM session as reported by
/// [`super::ServerMessage::AgentVmSessions`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentVmSessionInfo {
    pub session_id: SessionId,
    pub status: AgentVmSessionStateStatus,
    pub subnet_index: u16,
    pub vm_name: String,
    pub network_name: String,
    pub broker_urls: Vec<String>,
    pub runtime_attached: bool,
    /// Host-observed reachability of this session's broker path. `#[serde(default)]`
    /// keeps the wire compatible with a peer that predates the field (it reads
    /// as `Unknown`). Only populated for runtime-attached sessions; a
    /// detached/persisted-only session reports `Unknown`.
    #[serde(default = "NetworkHealth::unknown")]
    pub network_health: NetworkHealth,
}

/// One row of [`super::ServerMessage::StagedPushes`]: the metadata an operator
/// needs to triage staged pushes without loading bundle bytes.
///
/// Fields mirror [`VmGitPushStagedReceipt`] one-for-one; no audit data is
/// joined here so that listing remains a single staging-store read. Use
/// [`super::ClientMessage::ShowStagedPush`] for the joined view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StagedPushSummary {
    pub push_request_id: RequestId,
    pub repo: GitCloneRepo,
    pub branch: GitBranchName,
    pub expected_remote_head: Option<GitObjectId>,
    pub new_head: GitObjectId,
    pub staged_at: UnixMillis,
}

impl StagedPushSummary {
    pub fn from_receipt(receipt: &VmGitPushStagedReceipt) -> Self {
        Self {
            push_request_id: receipt.push_request_id(),
            repo: receipt.repo().clone(),
            branch: receipt.branch().clone(),
            expected_remote_head: receipt.expected_remote_head().cloned(),
            new_head: receipt.new_head().clone(),
            staged_at: receipt.staged_at(),
        }
    }
}

/// Audit fragment attached to a staged-push detail view: the session the
/// push was issued from and the latest recorded outcome, if any.
///
/// `result` is `None` when the audit log has a request row but no outcome
/// row yet (e.g. the broker crashed between staging and recording the
/// outcome). The promote tool surfaces this state rather than silently
/// presenting an incomplete history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StagedPushAuditView {
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub result: Option<GitPushOutcomeResult>,
}

/// Full detail returned by [`super::ServerMessage::StagedPush`]: the staging
/// summary, the bundle byte length, and the audit-derived session/outcome
/// view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StagedPushDetail {
    pub summary: StagedPushSummary,
    pub bundle_bytes: u64,
    pub audit: StagedPushAuditView,
}

/// Maximum byte length of a [`RejectionReason`]. Sized to comfortably
/// hold the kind of one-paragraph explanation a human will type into
/// `--reason` while still bounding broker memory and audit-row size.
pub const MAX_REJECTION_REASON_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RejectionReasonError {
    #[error("rejection reason must not be empty")]
    Empty,
    #[error("rejection reason is {byte_len} bytes, exceeding the {max_bytes}-byte limit")]
    TooLong { byte_len: usize, max_bytes: usize },
}

/// Operator-supplied justification for rejecting a staged push. The
/// broker records the reason verbatim in the audit log, so the type is
/// parsed at the wire boundary: non-empty and bounded length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectionReason(String);

impl RejectionReason {
    pub fn try_new(reason: impl Into<String>) -> Result<Self, RejectionReasonError> {
        let reason = reason.into();
        if reason.is_empty() {
            return Err(RejectionReasonError::Empty);
        }
        if reason.len() > MAX_REJECTION_REASON_BYTES {
            return Err(RejectionReasonError::TooLong {
                byte_len: reason.len(),
                max_bytes: MAX_REJECTION_REASON_BYTES,
            });
        }
        Ok(Self(reason))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for RejectionReason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RejectionReason {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

/// The canonical metadata writ hashes and signs at the end of a
/// [`super::ClientMessage::RunAgent`] invocation. Returned verbatim in
/// [`super::ServerMessage::RunAgentCompleted`] alongside the detached
/// signature so bailiff (or any third-party verifier) can
/// re-canonicalise the bytes and confirm the signature without
/// having to guess at field order or serialisation choices.
///
/// `prompt_sha256` binds the signed output to its originating prompt:
/// a verifier re-hashes bailiff's plan note (or whichever artefact
/// carried the prompt) and confirms it matches the hash writ saw,
/// ruling out "valid signature + swapped prompt" forgeries.
///
/// `signing_key_fingerprint` identifies which writ-side key produced
/// the signature; bailiff's allowed-signers file resolves it to the
/// public key used to verify `signature`. Bailiff refuses to ingest
/// a note whose fingerprint isn't in its keyring.
///
/// `capabilities` is the full canonical collection writ accepted on
/// the wire — every granted variant, not a single composite — so
/// provenance checks on a multi-capability run see every authority
/// that produced the signed output.
///
/// `session_id` is the authority/audit window writ minted (or that
/// bailiff supplied on `RunAgent`) for *this run* — per the
/// 2026-05-16 session-model pin a writ session is per-agent-run,
/// not per workflow. Verifiers use it to correlate the signed
/// envelope with writ's audit row; workflow identity belongs to
/// bailiff's `PlanId` and is not carried in writ's signed bytes.
///
/// `deny_unknown_fields` catches an unexpected key at parse time
/// rather than silently dropping it; the canonical bytes are
/// reconstructed from this exact field set and any divergence would
/// break verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRunMetadata {
    pub run_id: AgentRunId,
    pub session_id: SessionId,
    pub prompt_sha256: Sha256Hex,
    pub output_envelope_sha256: Sha256Hex,
    pub capabilities: Vec<CapabilitySet>,
    pub exit_code: i32,
    pub completed_at: UnixMillis,
    pub signing_key_fingerprint: SshKeyFingerprint,
}

impl SignedRunMetadata {
    /// Canonical byte representation that the signature covers.
    ///
    /// The canonical form is `serde_json::to_vec` of this struct: a
    /// compact (no whitespace) JSON object with keys emitted in the
    /// declaration order pinned by the struct definition above. The
    /// struct definition *is* the contract — `deny_unknown_fields`
    /// plus the strict newtype validators (`Sha256Hex`,
    /// `SshKeyFingerprint`, `AgentRunId`, `SessionId`, `UnixMillis`,
    /// `CapabilitySet`) mean every wire payload that round-trips
    /// through `SignedRunMetadata` and back to bytes via
    /// `canonical_bytes` yields the same digest.
    ///
    /// A non-Rust verifier reproduces the canonical form by emitting
    /// JSON with the eight keys in the order they appear in this
    /// struct (`run_id`, `session_id`, `prompt_sha256`,
    /// `output_envelope_sha256`, `capabilities`, `exit_code`,
    /// `completed_at`, `signing_key_fingerprint`), each child value
    /// in its own canonical form (numbers as bare integers, strings
    /// in JSON-escaped UTF-8, the `capabilities` array preserving
    /// element order verbatim) and no insignificant whitespace.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self)
            .expect("SignedRunMetadata serialises to JSON without IO; cannot fail")
    }
}

/// Operator-supplied outcome for a manual reconciliation against a
/// quarantined staged push. Mirrors the two terminal states a
/// reconciliation row may land in.
///
/// `Applied` declares that the broker's earlier PATCH did land on
/// GitHub. `new_app_tip` is the SHA the operator observed on the
/// remote branch — copied verbatim into the
/// `git_push_resolution(decision='approved').new_app_tip` column the
/// joint TX writes alongside the born-terminal attempt row. `reason`
/// is the human note recorded as the resolution row's `reason`.
///
/// `NotApplied` declares that the PATCH did *not* land. No
/// resolution row is written; the predecessor is cleared as a
/// blocker and the push becomes rejectable/retryable. `detail` is
/// recorded verbatim on the attempt row's `failure_detail`.
///
/// The inner tag is `kind` (rather than `type`) so the wire shape
/// stays readable when nested under
/// `ClientMessage::ReconcileStagedPush` — the outer envelope already
/// owns the `type` key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReconcileOutcome {
    Applied {
        new_app_tip: GitObjectId,
        reason: String,
    },
    NotApplied {
        detail: String,
    },
}
