//! Wire protocol types for the writ Unix-socket interface.
//!
//! Every connection is a sequence of newline-terminated JSON lines.
//! The client sends one [`ClientMessage`] per line; the broker replies
//! with one [`ServerMessage`] per line. No multiplexing, no framing
//! beyond the newline.
//!
//! These types are thin wrappers over the core domain types: the
//! [`CapabilityRequest`] a client sends is exactly the struct the
//! policy engine consumes, and [`SessionId`]/[`UnixMillis`] are the
//! same values that land in the audit log. No translation layer.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::agent_plan::{
    AddendumId, CorrelationId, Decider, DecisionOutcome, DecisionView, PlanAbortReason, PlanBody,
    PlanFeedback, PlanId, ReviewId, Stage, Verdict,
};
use crate::agent_run::{AgentPrompt, AgentRunId};
use crate::agent_vm_lifecycle::AgentVmSessionStateStatus;
use crate::audit::GitPushOutcomeResult;
use crate::core::{AgentKind, CapabilityRequest, RequestId, SessionId, UnixMillis};
use crate::vm_git::{
    AgentVmWorkspaceBootstrap, GitBranchName, GitCloneRepo, GitObjectId, VmGitPushStagedReceipt,
};

/// A persisted daemon-managed agent VM session as reported by
/// [`ServerMessage::AgentVmSessions`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentVmSessionInfo {
    pub session_id: SessionId,
    pub status: AgentVmSessionStateStatus,
    pub subnet_index: u16,
    pub vm_name: String,
    pub network_name: String,
    pub broker_urls: Vec<String>,
    pub runtime_attached: bool,
}

/// One row of [`ServerMessage::StagedPushes`]: the metadata an operator
/// needs to triage staged pushes without loading bundle bytes.
///
/// Fields mirror [`VmGitPushStagedReceipt`] one-for-one; no audit data is
/// joined here so that listing remains a single staging-store read. Use
/// [`ClientMessage::ShowStagedPush`] for the joined view.
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

/// Full detail returned by [`ServerMessage::StagedPush`]: the staging
/// summary, the bundle byte length, and the audit-derived session/outcome
/// view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StagedPushDetail {
    pub summary: StagedPushSummary,
    pub bundle_bytes: u64,
    pub audit: StagedPushAuditView,
}

/// One row of [`ServerMessage::Plans`]: enough plan metadata to triage
/// without loading the body. `body_bytes` and `body_sha256` are taken
/// from the audit row directly so the listing is one query; the body
/// is fetched via [`ClientMessage::ShowPlan`] when wanted.
///
/// `correlation_id` is joined from the planner's `agent_run` row.
/// Plans whose planner run was untagged surface `None`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlanSummary {
    pub plan_id: PlanId,
    pub agent_run_id: AgentRunId,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub correlation_id: Option<CorrelationId>,
    pub submitted_at: UnixMillis,
    pub body_sha256: String,
    pub body_bytes: u64,
}

/// Full plan view returned by [`ServerMessage::Plan`]: the summary, the
/// verbatim body, every recorded review, and the operator decision (if
/// any). Splitting body out keeps the list path cheap and the show path
/// explicit about loading up to 256 KiB of markdown plus the joined
/// review rows.
///
/// `reviews` and `addenda` are both ordered oldest-first to match the
/// DAO's `submitted_at` ascending order, so the operator reading
/// top-to-bottom sees how reviewer opinion evolved and how executor
/// addenda were posted in turn. `decision` is `None` until an operator
/// runs `writ plan decide`; `abort` is `None` until the executor agent
/// posts a hard-abort via `POST /v1/plans/<id>/abort`. All four append-
/// only fields use `#[serde(default)]` so an older daemon's response
/// (one that predates the field) still parses on a newer CLI — the
/// older payload is treated as "no reviews, no addenda, no decision,
/// no abort," which matches its semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlanDetail {
    pub summary: PlanSummary,
    pub body: PlanBody,
    #[serde(default)]
    pub reviews: Vec<PlanReviewView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionView>,
    #[serde(default)]
    pub addenda: Vec<PlanAddendumView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort: Option<PlanAbortView>,
}

/// One review row as exposed on the broker socket. Mirrors
/// [`crate::audit::PlanReviewRecord`] minus the audit-only
/// `feedback_sha256` (the body is on the wire verbatim, so the digest
/// is recomputable) and `plan_id` (redundant on the parent `PlanDetail`
/// that carries this view).
///
/// `reviewer_run_id` is renamed from the schema column `agent_run_id`
/// so it doesn't collide with `PlanSummary.agent_run_id` (the
/// *planner's* run) inside the same `PlanDetail`. Confusing the two is
/// a real footgun in operator-facing output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanReviewView {
    pub review_id: ReviewId,
    pub reviewer_run_id: AgentRunId,
    pub submitted_at: UnixMillis,
    pub verdict: Verdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback: Option<PlanFeedback>,
}

/// One addendum row as exposed on the broker socket. Mirrors
/// [`crate::audit::PlanAddendumRecord`] minus `plan_id` (redundant on
/// the parent `PlanDetail` that carries this view); the digest is
/// recomputable from the verbatim `body` and is not on the wire for
/// the same reason as on [`PlanReviewView`].
///
/// `executor_run_id` is renamed from the schema column `agent_run_id`
/// so it doesn't collide with `PlanSummary.agent_run_id` (the
/// *planner's* run) inside the same `PlanDetail`. Confusing the
/// addendum's author with the planner is the same footgun the
/// reviewer-side rename guards against.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanAddendumView {
    pub addendum_id: AddendumId,
    pub executor_run_id: AgentRunId,
    pub submitted_at: UnixMillis,
    pub body: PlanBody,
}

/// One hard-abort row as exposed on the broker socket. Mirrors
/// [`crate::audit::PlanAbortRecord`] minus `plan_id` (redundant on the
/// parent `PlanDetail` that carries this view).
///
/// `executor_run_id` is renamed from the schema column `agent_run_id`
/// for the same reason as on [`PlanAddendumView`]: to disambiguate the
/// run that posted the abort from `PlanSummary.agent_run_id`, the
/// planner's run, inside the same `PlanDetail`. The schema enforces one
/// abort per plan, so `PlanDetail.abort` is at most one value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanAbortView {
    pub executor_run_id: AgentRunId,
    pub aborted_at: UnixMillis,
    pub reason: PlanAbortReason,
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

/// A message from the agent to the broker.
///
/// `#[serde(deny_unknown_fields)]` at the enum level catches typos at the
/// wire (e.g. `agentkind` instead of `agent_kind`) instead of silently
/// dropping the field and proceeding with a default. The `proptest`
/// `client_message_rejects_unknown_top_level_fields` pins this behaviour
/// for every variant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientMessage {
    /// Begin a new session. The broker assigns a session ID, records it
    /// in the audit log, and returns [`ServerMessage::SessionOpened`].
    OpenSession {
        /// Human-readable description, e.g. "fixing bug #123". Stored in
        /// the audit log; ignored by policy.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        label: Option<String>,
        /// Trusted coarse agent identity used by the broker to choose
        /// authority-bearing backend configuration.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        agent_kind: Option<AgentKind>,
        /// Model identifier, e.g. "claude-opus-4-7". Informational only.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        agent_model: Option<String>,
    },
    /// End an open session. The broker records the close timestamp.
    CloseSession { session_id: SessionId },
    /// Ask the broker to evaluate policy and, if granted, mint a
    /// credential. Returns [`ServerMessage::TokenGranted`] or
    /// [`ServerMessage::Denied`].
    Request {
        session_id: SessionId,
        capability: CapabilityRequest,
    },
    /// Start an isolated Apple-container agent VM managed by the daemon.
    /// The daemon assigns the session ID and broker endpoint.
    StartAgentVm {
        /// Human-readable description stored in the audit log.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        label: Option<String>,
        /// Trusted coarse agent identity used by the broker to choose
        /// authority-bearing backend configuration.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        agent_kind: Option<AgentKind>,
        /// Model identifier stored in the audit log.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        agent_model: Option<String>,
        /// Optional clean repo checkout and source/substitute warmup to
        /// complete before the guest agent command starts.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        workspace: Option<AgentVmWorkspaceBootstrap>,
        /// Command to run inside the VM after lifecycle preflight succeeds.
        guest_command: Vec<String>,
    },
    /// Start a product-level agent run in a daemon-managed VM. The prompt is
    /// carried as protocol data and must not be copied into guest argv or
    /// lifecycle state.
    StartAgentRun {
        /// Human-readable description stored in the audit log.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        label: Option<String>,
        /// Trusted coarse agent identity used by the broker to choose
        /// authority-bearing backend configuration and the guest adapter.
        agent_kind: AgentKind,
        /// Model identifier delivered to the guest agent via the brokered
        /// run-config channel and stored in the audit log.
        agent_model: String,
        /// Required clean repo checkout and source/substitute warmup to
        /// complete before the guest agent command starts.
        workspace: AgentVmWorkspaceBootstrap,
        /// Prompt to deliver to the guest agent over the brokered prompt
        /// channel. Debug output redacts this value.
        prompt: AgentPrompt,
        /// Role of this run in the plan/review/execute pipeline. Stored
        /// on the `agent_run.stage` audit column and used by the VM HTTP
        /// plan routes for per-stage authorisation.
        stage: Stage,
        /// Opaque caller-supplied identifier joining this run to a
        /// wider task (per `docs/plans/2026-05-11-agent-plans.md`).
        /// Stored verbatim on the `agent_run` audit row; the broker
        /// never interprets it.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        correlation_id: Option<CorrelationId>,
        /// Plan this run is bound to read (and act on). Required by
        /// the VM HTTP plan routes that gate review and execute runs
        /// on `agent_run.read_plan_id`. `None` for planner runs and
        /// for legacy execute runs that pre-date the plan pipeline.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        read_plan_id: Option<PlanId>,
    },
    /// Stop a daemon-managed agent VM session and close its audit session.
    StopAgentVm { session_id: SessionId },
    /// List persisted daemon-managed agent VM sessions. Records without an
    /// attached in-memory runtime are cleanup obligations after daemon restart.
    ///
    /// Written as an empty struct variant rather than a unit variant so that
    /// `deny_unknown_fields` at the enum level applies — serde's unit-variant
    /// deserialization path silently accepts trailing keys.
    ListAgentVms {},
    /// List every VM-staged push currently waiting for promotion review.
    /// Replies with [`ServerMessage::StagedPushes`].
    ///
    /// Empty struct rather than unit variant so the enum-level
    /// `deny_unknown_fields` applies. See [`ListAgentVms`].
    ListStagedPushes {},
    /// Look up one VM-staged push by request id. Replies with
    /// [`ServerMessage::StagedPush`] on hit and
    /// [`ServerMessage::UnknownStagedPush`] on miss.
    ShowStagedPush { request_id: RequestId },
    /// Record an operator decision to reject a VM-staged push. The
    /// broker writes a `git_push_resolution` audit row, removes the
    /// staging directory, and replies with
    /// [`ServerMessage::StagedPushRejected`] on success,
    /// [`ServerMessage::UnknownStagedPush`] if the staging directory
    /// is gone, or [`ServerMessage::StagedPushAlreadyResolved`] if a
    /// prior decision is already recorded against this request id.
    ///
    /// `operator` is the human identity the broker records in the
    /// audit row. The host CLI captures `$USER` and sends it; the
    /// broker is not the source of authentication and trusts whatever
    /// the local-socket peer asserts (the socket itself is the trust
    /// boundary).
    RejectStagedPush {
        request_id: RequestId,
        operator: String,
        reason: RejectionReason,
    },
    /// List every plan recorded in the audit log, optionally filtered
    /// to those whose planner run carries `correlation_id`. Replies
    /// with [`ServerMessage::Plans`].
    ListPlans {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        correlation_id: Option<CorrelationId>,
    },
    /// Fetch one plan by id, including the verbatim body. Replies
    /// with [`ServerMessage::Plan`] on hit and
    /// [`ServerMessage::UnknownPlan`] on miss.
    ShowPlan { plan_id: PlanId },
    /// Record an operator decision against a plan. The broker writes a
    /// `plan_decision` audit row and replies with
    /// [`ServerMessage::PlanDecided`] on success,
    /// [`ServerMessage::UnknownPlan`] if no such plan exists, or
    /// [`ServerMessage::PlanAlreadyDecided`] if a prior decision is
    /// already recorded against this plan id.
    ///
    /// `decider` is the human attribution the broker records verbatim
    /// in the audit row. Today the host CLI sends `cli:$USER`; a future
    /// orchestrator agent may send its own label. The local socket is
    /// the trust boundary; the broker doesn't authenticate the value.
    ///
    /// Decisions are deliberately cross-session: the planner's session
    /// may be long since closed when the operator decides.
    DecidePlan {
        plan_id: PlanId,
        outcome: DecisionOutcome,
        decider: Decider,
    },
}

/// A message from the broker to the agent.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Acknowledges [`ClientMessage::OpenSession`]; carries the
    /// broker-assigned session ID for use in subsequent messages.
    SessionOpened { session_id: SessionId },
    /// Acknowledges [`ClientMessage::CloseSession`].
    SessionClosed,
    /// Policy granted the request. `expires_at` is the backend-reported
    /// expiry in unix milliseconds; the grant is recorded in the audit log.
    TokenGranted {
        token: String,
        expires_at: UnixMillis,
    },
    /// Policy denied the request; `reason` is a human-readable explanation.
    Denied { reason: String },
    /// A daemon-managed agent VM is running and can reach this broker URL from
    /// inside the guest. The VM HTTP bearer token is injected into the guest
    /// environment, not returned over the host protocol.
    AgentVmStarted {
        session_id: SessionId,
        broker_url: String,
    },
    /// A product-level agent run was started. The prompt itself is not
    /// returned; `run_id` is the stable handle used by the VM prompt/log
    /// contract.
    AgentRunStarted {
        session_id: SessionId,
        run_id: AgentRunId,
        broker_url: String,
    },
    /// Acknowledges [`ClientMessage::StopAgentVm`].
    AgentVmStopped,
    /// Reports persisted daemon-managed agent VM sessions.
    AgentVmSessions { sessions: Vec<AgentVmSessionInfo> },
    /// The session referenced by [`ClientMessage::Request`] is not present
    /// in the audit store. Distinct from [`ServerMessage::ClosedSession`]
    /// (a known session whose lifetime ended) and from
    /// [`ServerMessage::Error`] (an internal failure). Carrying the kind
    /// as a tag means clients react to "session unknown" without
    /// string-matching a free-form error message.
    UnknownSession { session_id: SessionId },
    /// The session referenced by [`ClientMessage::Request`] exists but is
    /// already closed; no further requests will be granted under it.
    /// Distinct from [`ServerMessage::UnknownSession`] and
    /// [`ServerMessage::Error`] for the same reason: clients should be
    /// able to react without parsing prose.
    ClosedSession { session_id: SessionId },
    /// Listing of VM-staged pushes awaiting promotion review. Order
    /// follows the staging store's on-disk iteration; clients that care
    /// should sort by `staged_at` themselves.
    StagedPushes { pushes: Vec<StagedPushSummary> },
    /// One staged push with its bundle size and audit-derived context.
    StagedPush { push: StagedPushDetail },
    /// The `push_request_id` referenced by [`ClientMessage::ShowStagedPush`]
    /// has no on-disk staging entry. Distinct from
    /// [`ServerMessage::Error`] so clients can distinguish "no such
    /// staged push" from a corrupt store or IO failure.
    UnknownStagedPush { request_id: RequestId },
    /// Acknowledges [`ClientMessage::RejectStagedPush`]: the audit
    /// resolution row was written and the staging directory was
    /// removed. Carrying `request_id` lets the CLI confirm the exact
    /// push it asked to reject when scripting against the daemon.
    StagedPushRejected { request_id: RequestId },
    /// The staged push referenced by [`ClientMessage::RejectStagedPush`]
    /// already has a recorded operator decision. Distinct from
    /// [`ServerMessage::UnknownStagedPush`] and [`ServerMessage::Error`]
    /// so a replay surfaces as an explicit "already decided" outcome
    /// rather than a prose error string.
    StagedPushAlreadyResolved { request_id: RequestId },
    /// Listing of plans returned by [`ClientMessage::ListPlans`].
    /// Ordered ascending by `submitted_at` with rowid as the
    /// tie-break, matching the DAO query.
    Plans { plans: Vec<PlanSummary> },
    /// One plan with its verbatim body and joined correlation id.
    Plan { plan: PlanDetail },
    /// The `plan_id` referenced by [`ClientMessage::ShowPlan`] or
    /// [`ClientMessage::DecidePlan`] has no row in the audit log.
    /// Distinct from [`ServerMessage::Error`] so clients can
    /// distinguish "no such plan" from a corrupt store or IO failure.
    UnknownPlan { plan_id: PlanId },
    /// Acknowledges [`ClientMessage::DecidePlan`]: the audit row was
    /// written. Carrying `plan_id` lets the CLI confirm the exact
    /// plan it asked to decide when scripting against the daemon.
    PlanDecided { plan_id: PlanId },
    /// The plan referenced by [`ClientMessage::DecidePlan`] already
    /// has a recorded operator decision. Distinct from
    /// [`ServerMessage::UnknownPlan`] and [`ServerMessage::Error`]
    /// so a replay surfaces as an explicit "already decided" outcome
    /// rather than a prose error string.
    PlanAlreadyDecided { plan_id: PlanId },
    /// An internal failure (mint error, audit write failure, agent VM
    /// runtime not configured, …). The agent should surface `message` to
    /// the user and not retry automatically. Outcomes a client may want
    /// to handle differently — `UnknownSession`, `ClosedSession`,
    /// `Denied` — have their own variants and never collapse into this
    /// one.
    Error { message: String },
}

impl std::fmt::Debug for ServerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionOpened { session_id } => f
                .debug_struct("SessionOpened")
                .field("session_id", session_id)
                .finish(),
            Self::SessionClosed => write!(f, "SessionClosed"),
            // Token is a live credential; redact it in debug output so a
            // stray `dbg!` or tracing span doesn't spray it into logs.
            Self::TokenGranted { expires_at, .. } => f
                .debug_struct("TokenGranted")
                .field("token", &"<redacted>")
                .field("expires_at", expires_at)
                .finish(),
            Self::Denied { reason } => f.debug_struct("Denied").field("reason", reason).finish(),
            Self::AgentVmStarted {
                session_id,
                broker_url,
            } => f
                .debug_struct("AgentVmStarted")
                .field("session_id", session_id)
                .field("broker_url", broker_url)
                .finish(),
            Self::AgentRunStarted {
                session_id,
                run_id,
                broker_url,
            } => f
                .debug_struct("AgentRunStarted")
                .field("session_id", session_id)
                .field("run_id", run_id)
                .field("broker_url", broker_url)
                .finish(),
            Self::AgentVmStopped => write!(f, "AgentVmStopped"),
            Self::AgentVmSessions { sessions } => f
                .debug_struct("AgentVmSessions")
                .field("sessions", sessions)
                .finish(),
            Self::UnknownSession { session_id } => f
                .debug_struct("UnknownSession")
                .field("session_id", session_id)
                .finish(),
            Self::ClosedSession { session_id } => f
                .debug_struct("ClosedSession")
                .field("session_id", session_id)
                .finish(),
            Self::StagedPushes { pushes } => f
                .debug_struct("StagedPushes")
                .field("pushes", pushes)
                .finish(),
            Self::StagedPush { push } => f.debug_struct("StagedPush").field("push", push).finish(),
            Self::UnknownStagedPush { request_id } => f
                .debug_struct("UnknownStagedPush")
                .field("request_id", request_id)
                .finish(),
            Self::StagedPushRejected { request_id } => f
                .debug_struct("StagedPushRejected")
                .field("request_id", request_id)
                .finish(),
            Self::StagedPushAlreadyResolved { request_id } => f
                .debug_struct("StagedPushAlreadyResolved")
                .field("request_id", request_id)
                .finish(),
            Self::Plans { plans } => f.debug_struct("Plans").field("plans", plans).finish(),
            Self::Plan { plan } => f.debug_struct("Plan").field("plan", plan).finish(),
            Self::UnknownPlan { plan_id } => f
                .debug_struct("UnknownPlan")
                .field("plan_id", plan_id)
                .finish(),
            Self::PlanDecided { plan_id } => f
                .debug_struct("PlanDecided")
                .field("plan_id", plan_id)
                .finish(),
            Self::PlanAlreadyDecided { plan_id } => f
                .debug_struct("PlanAlreadyDecided")
                .field("plan_id", plan_id)
                .finish(),
            Self::Error { message } => f.debug_struct("Error").field("message", message).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{GitHubAccess, GitHubRequest, RepoRef};
    use crate::vm_git::{GitCloneRepo, WorkspaceWarmMode};
    use proptest::prelude::*;
    use std::path::PathBuf;

    fn fixed_session_id() -> SessionId {
        "00000000-0000-0000-0000-000000000001".parse().unwrap()
    }

    fn sample_repo() -> RepoRef {
        RepoRef {
            owner: "o".into(),
            name: "n".into(),
        }
    }

    fn sample_clone_repo() -> GitCloneRepo {
        "owner/repo".parse().unwrap()
    }

    // --- ClientMessage roundtrips -----------------------------------------

    #[test]
    fn open_session_with_fields_roundtrips() {
        let msg = ClientMessage::OpenSession {
            label: Some("fix bug 42".into()),
            agent_kind: Some(AgentKind::Claude),
            agent_model: Some("claude-opus-4-7".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn open_session_without_fields_roundtrips() {
        let msg = ClientMessage::OpenSession {
            label: None,
            agent_kind: None,
            agent_model: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn close_session_roundtrips() {
        let msg = ClientMessage::CloseSession {
            session_id: fixed_session_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn request_roundtrips() {
        let msg = ClientMessage::Request {
            session_id: fixed_session_id(),
            capability: CapabilityRequest::GitHub(GitHubRequest::Contents {
                access: GitHubAccess::Write,
                repo: sample_repo(),
            }),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn start_agent_vm_roundtrips() {
        let msg = ClientMessage::StartAgentVm {
            label: Some("agent vm".into()),
            agent_kind: Some(AgentKind::Codex),
            agent_model: Some("gpt-test".into()),
            workspace: None,
            guest_command: vec!["sleep".into(), "600".into()],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn start_agent_vm_with_workspace_roundtrips() {
        let msg = ClientMessage::StartAgentVm {
            label: Some("agent vm".into()),
            agent_kind: Some(AgentKind::Codex),
            agent_model: Some("gpt-test".into()),
            workspace: Some(AgentVmWorkspaceBootstrap {
                repo: sample_clone_repo(),
                destination: Some(PathBuf::from("/workspace/repo")),
                warm: WorkspaceWarmMode::DevShell,
            }),
            guest_command: vec!["codex".into()],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn start_agent_run_roundtrips_with_prompt_as_protocol_data() {
        let msg = ClientMessage::StartAgentRun {
            label: Some("agent run".into()),
            agent_kind: AgentKind::Claude,
            agent_model: "claude-test".into(),
            workspace: AgentVmWorkspaceBootstrap {
                repo: sample_clone_repo(),
                destination: Some(PathBuf::from("/workspace/repo")),
                warm: WorkspaceWarmMode::Sources,
            },
            prompt: AgentPrompt::new("fix the failing test"),
            stage: Stage::Execute,
            correlation_id: None,
            read_plan_id: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
        assert!(json.contains("fix the failing test"));
        // The optional fields are elided when None so older clients/servers
        // that predate them can still parse the message.
        assert!(!json.contains("correlation_id"));
        assert!(!json.contains("read_plan_id"));
    }

    #[test]
    fn start_agent_run_serialises_stage_for_every_variant() {
        for stage in [Stage::Plan, Stage::Review, Stage::Execute] {
            let msg = ClientMessage::StartAgentRun {
                label: None,
                agent_kind: AgentKind::Claude,
                agent_model: "claude-test".into(),
                workspace: AgentVmWorkspaceBootstrap {
                    repo: sample_clone_repo(),
                    destination: None,
                    warm: WorkspaceWarmMode::None,
                },
                prompt: AgentPrompt::new("p"),
                stage,
                correlation_id: None,
                read_plan_id: None,
            };
            let json = serde_json::to_string(&msg).unwrap();
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(value["stage"], stage.as_str(), "wire bytes: {json}");
            let back: ClientMessage = serde_json::from_str(&json).unwrap();
            assert_eq!(back, msg);
        }
    }

    /// `stage` is required on the wire — omitting it is a parse error,
    /// not a silent default to `execute`. The audit log can only hold
    /// one of the three legal stages, so the broker should reject
    /// stageless messages rather than fall back to a guess.
    #[test]
    fn start_agent_run_rejects_missing_stage() {
        let mut value = serde_json::json!({
            "type": "start_agent_run",
            "agent_kind": "claude",
            "agent_model": "claude-test",
            "workspace": {
                "repo": "owner/repo",
                "warm": "none",
            },
            "prompt": "p",
            "stage": "execute",
        });
        // Sanity check: with `stage` present, the message parses.
        assert!(serde_json::from_value::<ClientMessage>(value.clone()).is_ok());
        value.as_object_mut().unwrap().remove("stage");
        let err = serde_json::from_value::<ClientMessage>(value).unwrap_err();
        assert!(
            err.to_string().contains("stage"),
            "expected missing-stage error, got: {err}",
        );
    }

    #[test]
    fn start_agent_run_rejects_unknown_stage() {
        let value = serde_json::json!({
            "type": "start_agent_run",
            "agent_kind": "claude",
            "agent_model": "claude-test",
            "workspace": {
                "repo": "owner/repo",
                "warm": "none",
            },
            "prompt": "p",
            "stage": "planner",
        });
        let err = serde_json::from_value::<ClientMessage>(value).unwrap_err();
        assert!(
            err.to_string().contains("planner")
                || err.to_string().to_lowercase().contains("variant"),
            "expected unknown-stage error, got: {err}",
        );
    }

    #[test]
    fn start_agent_run_roundtrips_with_correlation_id() {
        let msg = ClientMessage::StartAgentRun {
            label: None,
            agent_kind: AgentKind::Claude,
            agent_model: "claude-test".into(),
            workspace: AgentVmWorkspaceBootstrap {
                repo: sample_clone_repo(),
                destination: None,
                warm: WorkspaceWarmMode::None,
            },
            prompt: AgentPrompt::new("p"),
            stage: Stage::Execute,
            correlation_id: Some(CorrelationId::try_new("feat-42_xyz").unwrap()),
            read_plan_id: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
        assert!(json.contains("feat-42_xyz"));
    }

    /// `read_plan_id` round-trips on the wire when present, and is
    /// elided when absent (so older deserialisers still parse the
    /// message). The field is the per-stage authorisation handle
    /// for the VM HTTP plan-read route; the broker writes whatever
    /// value the message carries straight onto the
    /// `agent_run.read_plan_id` audit column.
    #[test]
    fn start_agent_run_roundtrips_with_read_plan_id() {
        let plan_id = sample_plan_id();
        let msg = ClientMessage::StartAgentRun {
            label: None,
            agent_kind: AgentKind::Claude,
            agent_model: "claude-test".into(),
            workspace: AgentVmWorkspaceBootstrap {
                repo: sample_clone_repo(),
                destination: None,
                warm: WorkspaceWarmMode::None,
            },
            prompt: AgentPrompt::new("p"),
            stage: Stage::Execute,
            correlation_id: None,
            read_plan_id: Some(plan_id),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value["read_plan_id"],
            serde_json::Value::String(plan_id.as_uuid().to_string()),
        );
    }

    /// A garbage `read_plan_id` must be rejected at the protocol
    /// boundary; the audit-log CHECK should never be the line of
    /// defence. `PlanId` parses through `Uuid::from_str`, so any
    /// non-UUID payload is a deserialise error.
    #[test]
    fn start_agent_run_rejects_malformed_read_plan_id() {
        let value = serde_json::json!({
            "type": "start_agent_run",
            "agent_kind": "claude",
            "agent_model": "claude-test",
            "workspace": {
                "repo": "owner/repo",
                "warm": "none",
            },
            "prompt": "p",
            "stage": "execute",
            "read_plan_id": "not-a-uuid",
        });
        let err = serde_json::from_value::<ClientMessage>(value).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("uuid"),
            "expected uuid-parse error, got: {err}",
        );
    }

    #[test]
    fn stop_agent_vm_roundtrips() {
        let msg = ClientMessage::StopAgentVm {
            session_id: fixed_session_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn list_agent_vms_roundtrips() {
        let msg = ClientMessage::ListAgentVms {};
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn list_staged_pushes_roundtrips() {
        let msg = ClientMessage::ListStagedPushes {};
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn show_staged_push_roundtrips() {
        let msg = ClientMessage::ShowStagedPush {
            request_id: sample_request_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn reject_staged_push_roundtrips() {
        let msg = ClientMessage::RejectStagedPush {
            request_id: sample_request_id(),
            operator: "alice".into(),
            reason: RejectionReason::try_new("contains stray binary").unwrap(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn rejection_reason_empty_is_rejected() {
        let err = RejectionReason::try_new("").unwrap_err();
        assert!(matches!(err, RejectionReasonError::Empty));
    }

    #[test]
    fn rejection_reason_at_limit_is_accepted() {
        let body = "a".repeat(MAX_REJECTION_REASON_BYTES);
        let reason = RejectionReason::try_new(body.clone()).unwrap();
        assert_eq!(reason.as_str().len(), MAX_REJECTION_REASON_BYTES);
        // serde roundtrip preserves the body verbatim.
        let json = serde_json::to_string(&reason).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_str(), body);
    }

    #[test]
    fn rejection_reason_above_limit_is_rejected() {
        let body = "a".repeat(MAX_REJECTION_REASON_BYTES + 1);
        let err = RejectionReason::try_new(body).unwrap_err();
        let RejectionReasonError::TooLong {
            byte_len,
            max_bytes,
        } = err
        else {
            panic!("expected TooLong, got {err:?}");
        };
        assert_eq!(byte_len, MAX_REJECTION_REASON_BYTES + 1);
        assert_eq!(max_bytes, MAX_REJECTION_REASON_BYTES);
    }

    /// Deserializing a too-long reason must surface as a serde error so
    /// the broker rejects oversize payloads at the wire boundary rather
    /// than past it.
    #[test]
    fn rejection_reason_above_limit_fails_to_deserialize() {
        let body = "a".repeat(MAX_REJECTION_REASON_BYTES + 1);
        let json = serde_json::to_string(&body).unwrap();
        let err = serde_json::from_str::<RejectionReason>(&json).unwrap_err();
        assert!(
            err.to_string().contains("exceeding"),
            "expected length error message, got: {err}"
        );
    }

    /// And an empty string must fail at the wire too — guest UI may
    /// allow blanks but the broker rejects them so the audit row's
    /// `reason != ''` CHECK is never the line of defence.
    #[test]
    fn rejection_reason_empty_fails_to_deserialize() {
        let err = serde_json::from_str::<RejectionReason>("\"\"").unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "expected empty-string error message, got: {err}"
        );
    }

    // --- ServerMessage roundtrips -----------------------------------------

    #[test]
    fn session_opened_roundtrips() {
        let msg = ServerMessage::SessionOpened {
            session_id: fixed_session_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn session_closed_roundtrips() {
        let json = serde_json::to_string(&ServerMessage::SessionClosed).unwrap();
        assert_eq!(
            serde_json::from_str::<ServerMessage>(&json).unwrap(),
            ServerMessage::SessionClosed,
        );
    }

    #[test]
    fn token_granted_roundtrips() {
        let msg = ServerMessage::TokenGranted {
            token: "ghs_test".into(),
            expires_at: UnixMillis::from_millis(9_000_000_000),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn denied_roundtrips() {
        let msg = ServerMessage::Denied {
            reason: "not on allowlist".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn agent_vm_started_roundtrips() {
        let msg = ServerMessage::AgentVmStarted {
            session_id: fixed_session_id(),
            broker_url: "http://192.168.252.1:51375/".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn agent_run_started_roundtrips() {
        let msg = ServerMessage::AgentRunStarted {
            session_id: fixed_session_id(),
            run_id: "00000000-0000-0000-0000-000000000777".parse().unwrap(),
            broker_url: "http://192.168.252.1:51375/".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn agent_vm_stopped_roundtrips() {
        let json = serde_json::to_string(&ServerMessage::AgentVmStopped).unwrap();
        assert_eq!(
            serde_json::from_str::<ServerMessage>(&json).unwrap(),
            ServerMessage::AgentVmStopped,
        );
    }

    fn sample_request_id() -> RequestId {
        "f0f0f0f0-0000-0000-0000-000000000001".parse().unwrap()
    }

    fn sample_plan_id() -> PlanId {
        "f1f1f1f1-0000-0000-0000-000000000001".parse().unwrap()
    }

    fn sample_agent_run_id() -> AgentRunId {
        "f2f2f2f2-0000-0000-0000-000000000001".parse().unwrap()
    }

    fn sample_plan_body() -> PlanBody {
        PlanBody::try_new("# Plan\n\nStep 1: do the thing.").unwrap()
    }

    fn sample_plan_summary() -> PlanSummary {
        let body = sample_plan_body();
        PlanSummary {
            plan_id: sample_plan_id(),
            agent_run_id: sample_agent_run_id(),
            correlation_id: Some(CorrelationId::try_new("feat-42_xyz").unwrap()),
            submitted_at: UnixMillis::from_millis(1_700_000_000_000),
            body_sha256: body.sha256_hex(),
            body_bytes: body.byte_len(),
        }
    }

    fn sample_plan_detail() -> PlanDetail {
        PlanDetail {
            summary: sample_plan_summary(),
            body: sample_plan_body(),
            reviews: Vec::new(),
            decision: None,
            addenda: Vec::new(),
            abort: None,
        }
    }

    fn sample_abort_view() -> PlanAbortView {
        PlanAbortView {
            executor_run_id: "f7f7f7f7-0000-0000-0000-000000000001".parse().unwrap(),
            aborted_at: UnixMillis::from_millis(1_700_000_700_000),
            reason: PlanAbortReason::try_new("Migration plan no longer viable: schema changed.")
                .unwrap(),
        }
    }

    fn sample_addendum_id() -> AddendumId {
        "f5f5f5f5-0000-0000-0000-000000000001".parse().unwrap()
    }

    fn sample_addendum_view() -> PlanAddendumView {
        PlanAddendumView {
            addendum_id: sample_addendum_id(),
            executor_run_id: "f6f6f6f6-0000-0000-0000-000000000001".parse().unwrap(),
            submitted_at: UnixMillis::from_millis(1_700_000_500_000),
            body: PlanBody::try_new("# Addendum\n\nFollow-up notes.").unwrap(),
        }
    }

    fn sample_review_id() -> ReviewId {
        "f3f3f3f3-0000-0000-0000-000000000001".parse().unwrap()
    }

    fn sample_review_view() -> PlanReviewView {
        PlanReviewView {
            review_id: sample_review_id(),
            reviewer_run_id: "f4f4f4f4-0000-0000-0000-000000000001".parse().unwrap(),
            submitted_at: UnixMillis::from_millis(1_700_000_100_000),
            verdict: Verdict::RequestChanges,
            feedback: Some(PlanFeedback::try_new("Please tighten the migration step.").unwrap()),
        }
    }

    fn sample_object_id(nibble: char) -> GitObjectId {
        std::iter::repeat_n(nibble, 40)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    fn sample_staged_summary() -> StagedPushSummary {
        StagedPushSummary {
            push_request_id: sample_request_id(),
            repo: sample_clone_repo(),
            branch: "feature/x".parse().unwrap(),
            expected_remote_head: Some(sample_object_id('a')),
            new_head: sample_object_id('b'),
            staged_at: UnixMillis::from_millis(1_700_000_000_000),
        }
    }

    fn sample_staged_detail() -> StagedPushDetail {
        StagedPushDetail {
            summary: sample_staged_summary(),
            bundle_bytes: 4096,
            audit: StagedPushAuditView {
                session_id: fixed_session_id(),
                received_at: UnixMillis::from_millis(1_700_000_000_500),
                result: Some(GitPushOutcomeResult::Staged),
            },
        }
    }

    #[test]
    fn staged_pushes_roundtrips() {
        let msg = ServerMessage::StagedPushes {
            pushes: vec![sample_staged_summary()],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn staged_pushes_empty_roundtrips() {
        let msg = ServerMessage::StagedPushes { pushes: vec![] };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn staged_push_roundtrips() {
        let msg = ServerMessage::StagedPush {
            push: sample_staged_detail(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn staged_push_with_no_audit_outcome_roundtrips() {
        let mut detail = sample_staged_detail();
        detail.audit.result = None;
        let msg = ServerMessage::StagedPush { push: detail };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn staged_push_with_branch_creation_roundtrips() {
        let mut detail = sample_staged_detail();
        detail.summary.expected_remote_head = None;
        let msg = ServerMessage::StagedPush { push: detail };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn unknown_staged_push_roundtrips() {
        let msg = ServerMessage::UnknownStagedPush {
            request_id: sample_request_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn staged_push_rejected_roundtrips() {
        let msg = ServerMessage::StagedPushRejected {
            request_id: sample_request_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn staged_push_already_resolved_roundtrips() {
        let msg = ServerMessage::StagedPushAlreadyResolved {
            request_id: sample_request_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn list_plans_with_correlation_id_roundtrips() {
        let msg = ClientMessage::ListPlans {
            correlation_id: Some(CorrelationId::try_new("feat-42_xyz").unwrap()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
        assert!(json.contains("feat-42_xyz"));
    }

    /// `correlation_id` is `skip_serializing_if = Option::is_none` so a
    /// `None`-filter listing serialises without the field; a client
    /// that omits it must still deserialise to the same variant.
    #[test]
    fn list_plans_without_correlation_id_roundtrips_and_omits_field() {
        let msg = ClientMessage::ListPlans {
            correlation_id: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
        assert!(!json.contains("correlation_id"));
    }

    #[test]
    fn show_plan_roundtrips() {
        let msg = ClientMessage::ShowPlan {
            plan_id: sample_plan_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn plans_listing_roundtrips() {
        let msg = ServerMessage::Plans {
            plans: vec![sample_plan_summary()],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn plans_listing_empty_roundtrips() {
        let msg = ServerMessage::Plans { plans: vec![] };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    /// A plan whose planner run was untagged drops the correlation_id
    /// key on the wire entirely — older clients that predate the
    /// field stay compatible.
    #[test]
    fn plan_summary_without_correlation_id_omits_field_on_wire() {
        let summary = PlanSummary {
            correlation_id: None,
            ..sample_plan_summary()
        };
        let value: serde_json::Value = serde_json::to_value(&summary).unwrap();
        assert!(value.get("correlation_id").is_none());
        // And it parses back.
        let back: PlanSummary = serde_json::from_value(value).unwrap();
        assert_eq!(back, summary);
    }

    #[test]
    fn plan_detail_roundtrips() {
        let msg = ServerMessage::Plan {
            plan: sample_plan_detail(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    /// `reviews` always serialises (even when empty) so an operator
    /// reading the JSON can distinguish "no reviews" from "the daemon
    /// is silently dropping the field." The empty-Vec choice (rather
    /// than `skip_serializing_if`) is documented on `PlanDetail`.
    #[test]
    fn plan_detail_empty_reviews_serialises_as_empty_array() {
        let value: serde_json::Value = serde_json::to_value(sample_plan_detail()).unwrap();
        assert_eq!(value["reviews"], serde_json::json!([]));
    }

    /// `addenda` follows the same always-emit-[] convention as
    /// `reviews`, so an operator reading the JSON can tell the absence
    /// of executor addenda from a silent dropped field.
    #[test]
    fn plan_detail_empty_addenda_serialises_as_empty_array() {
        let value: serde_json::Value = serde_json::to_value(sample_plan_detail()).unwrap();
        assert_eq!(value["addenda"], serde_json::json!([]));
    }

    /// A `None` decision drops the key on the wire (matches the
    /// `correlation_id` convention on `PlanSummary`). An older daemon
    /// that predates the field stays compatible because `#[serde(
    /// default)]` accepts the missing key.
    #[test]
    fn plan_detail_without_decision_omits_field_on_wire() {
        let value: serde_json::Value = serde_json::to_value(sample_plan_detail()).unwrap();
        assert!(value.get("decision").is_none());
        let back: PlanDetail = serde_json::from_value(value).unwrap();
        assert!(back.decision.is_none());
    }

    /// A populated `PlanDetail` carrying mixed-verdict reviews and an
    /// `Accepted` decision roundtrips byte-for-byte. Pins the wire
    /// shape against the renderer and the audit-record-to-view
    /// mapping in `show_plan`.
    #[test]
    fn plan_detail_with_reviews_and_accepted_decision_roundtrips() {
        let mut detail = sample_plan_detail();
        detail.reviews = vec![
            PlanReviewView {
                verdict: Verdict::RequestChanges,
                ..sample_review_view()
            },
            PlanReviewView {
                review_id: "f3f3f3f3-0000-0000-0000-000000000002".parse().unwrap(),
                reviewer_run_id: "f4f4f4f4-0000-0000-0000-000000000002".parse().unwrap(),
                submitted_at: UnixMillis::from_millis(1_700_000_200_000),
                verdict: Verdict::Approve,
                feedback: None,
            },
        ];
        detail.decision = Some(DecisionView {
            outcome: DecisionOutcome::Accepted,
            decided_at: UnixMillis::from_millis(1_700_000_300_000),
        });
        let msg = ServerMessage::Plan { plan: detail };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    /// A `RejectedRestart` decision roundtrips on the same shape — pin
    /// both outcomes since the renderer formats them differently.
    #[test]
    fn plan_detail_with_rejected_restart_decision_roundtrips() {
        let mut detail = sample_plan_detail();
        detail.decision = Some(DecisionView {
            outcome: DecisionOutcome::RejectedRestart,
            decided_at: UnixMillis::from_millis(1_700_000_400_000),
        });
        let msg = ServerMessage::Plan { plan: detail };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    /// `feedback` drops on the wire when absent. Matches the
    /// `PlanSummary.correlation_id` convention so callers and
    /// scripted consumers can distinguish "no feedback" from "the
    /// daemon forgot to send it."
    #[test]
    fn plan_review_view_without_feedback_omits_field_on_wire() {
        let review = PlanReviewView {
            feedback: None,
            ..sample_review_view()
        };
        let value: serde_json::Value = serde_json::to_value(&review).unwrap();
        assert!(value.get("feedback").is_none());
        let back: PlanReviewView = serde_json::from_value(value).unwrap();
        assert_eq!(back, review);
    }

    /// An older daemon's payload (no `reviews`, no `decision`, no
    /// `addenda`, no `abort`) parses on the newer CLI as "no reviews,
    /// no decision, no addenda, no abort." This is the reason
    /// `#[serde(default)]` is on all four append-only fields.
    #[test]
    fn plan_detail_accepts_payload_without_reviews_or_decision() {
        let value = serde_json::json!({
            "summary": sample_plan_summary(),
            "body": sample_plan_body(),
        });
        let parsed: PlanDetail = serde_json::from_value(value).unwrap();
        assert!(parsed.reviews.is_empty());
        assert!(parsed.decision.is_none());
        assert!(parsed.addenda.is_empty());
        assert!(parsed.abort.is_none());
    }

    /// A `PlanDetail` carrying executor addenda roundtrips byte-for-
    /// byte. Pins the wire shape for the `executor_run_id` rename
    /// against the audit-record-to-view mapping in `show_plan`, and
    /// confirms the verbatim body survives the round trip.
    #[test]
    fn plan_detail_with_addenda_roundtrips() {
        let mut detail = sample_plan_detail();
        detail.addenda = vec![
            sample_addendum_view(),
            PlanAddendumView {
                addendum_id: "f5f5f5f5-0000-0000-0000-000000000002".parse().unwrap(),
                executor_run_id: "f6f6f6f6-0000-0000-0000-000000000002".parse().unwrap(),
                submitted_at: UnixMillis::from_millis(1_700_000_600_000),
                body: PlanBody::try_new("# Second addendum\n").unwrap(),
            },
        ];
        let msg = ServerMessage::Plan { plan: detail };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    /// `PlanAddendumView` uses `deny_unknown_fields`, so a stray key on
    /// the wire is rejected at parse time rather than silently dropped.
    /// Matches the `PlanReviewView` convention.
    #[test]
    fn plan_addendum_view_rejects_unknown_fields() {
        let mut value: serde_json::Value = serde_json::to_value(sample_addendum_view()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("bogus".into(), serde_json::json!("nope"));
        let result: Result<PlanAddendumView, _> = serde_json::from_value(value);
        assert!(result.is_err());
    }

    /// A `PlanDetail` carrying a hard-abort roundtrips byte-for-byte.
    /// Pins the `executor_run_id` rename against the audit-record-to-
    /// view mapping in `show_plan`, and confirms the verbatim reason
    /// survives the round trip.
    #[test]
    fn plan_detail_with_abort_roundtrips() {
        let mut detail = sample_plan_detail();
        detail.abort = Some(sample_abort_view());
        let msg = ServerMessage::Plan { plan: detail };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    /// A `None` abort drops the key on the wire (matches the
    /// `decision` convention). An older daemon that predates the
    /// field stays compatible because `#[serde(default)]` accepts the
    /// missing key.
    #[test]
    fn plan_detail_without_abort_omits_field_on_wire() {
        let value: serde_json::Value = serde_json::to_value(sample_plan_detail()).unwrap();
        assert!(value.get("abort").is_none());
        let back: PlanDetail = serde_json::from_value(value).unwrap();
        assert!(back.abort.is_none());
    }

    /// `PlanAbortView` uses `deny_unknown_fields`, so a stray key on
    /// the wire is rejected at parse time rather than silently dropped.
    /// Matches the `PlanReviewView` / `PlanAddendumView` convention.
    #[test]
    fn plan_abort_view_rejects_unknown_fields() {
        let mut value: serde_json::Value = serde_json::to_value(sample_abort_view()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("bogus".into(), serde_json::json!("nope"));
        let result: Result<PlanAbortView, _> = serde_json::from_value(value);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_plan_roundtrips() {
        let msg = ServerMessage::UnknownPlan {
            plan_id: sample_plan_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn decide_plan_roundtrips_for_every_outcome() {
        for outcome in [DecisionOutcome::Accepted, DecisionOutcome::RejectedRestart] {
            let msg = ClientMessage::DecidePlan {
                plan_id: sample_plan_id(),
                outcome,
                decider: Decider::try_new("cli:alice").unwrap(),
            };
            let json = serde_json::to_string(&msg).unwrap();
            let back: ClientMessage = serde_json::from_str(&json).unwrap();
            assert_eq!(back, msg);
            // The decider is on the wire verbatim — no escaping or
            // type-wrapping in the JSON shape.
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(value["decider"], "cli:alice");
        }
    }

    #[test]
    fn plan_decided_roundtrips() {
        let msg = ServerMessage::PlanDecided {
            plan_id: sample_plan_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn plan_already_decided_roundtrips() {
        let msg = ServerMessage::PlanAlreadyDecided {
            plan_id: sample_plan_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn plan_type_tags() {
        let list: serde_json::Value = serde_json::to_value(ClientMessage::ListPlans {
            correlation_id: None,
        })
        .unwrap();
        assert_eq!(list["type"], "list_plans");

        let show: serde_json::Value = serde_json::to_value(ClientMessage::ShowPlan {
            plan_id: sample_plan_id(),
        })
        .unwrap();
        assert_eq!(show["type"], "show_plan");

        let plans: serde_json::Value =
            serde_json::to_value(ServerMessage::Plans { plans: vec![] }).unwrap();
        assert_eq!(plans["type"], "plans");

        let plan: serde_json::Value = serde_json::to_value(ServerMessage::Plan {
            plan: sample_plan_detail(),
        })
        .unwrap();
        assert_eq!(plan["type"], "plan");

        let unknown: serde_json::Value = serde_json::to_value(ServerMessage::UnknownPlan {
            plan_id: sample_plan_id(),
        })
        .unwrap();
        assert_eq!(unknown["type"], "unknown_plan");

        let decide: serde_json::Value = serde_json::to_value(ClientMessage::DecidePlan {
            plan_id: sample_plan_id(),
            outcome: DecisionOutcome::Accepted,
            decider: Decider::try_new("cli:alice").unwrap(),
        })
        .unwrap();
        assert_eq!(decide["type"], "decide_plan");
        assert_eq!(decide["outcome"], "accepted");
        assert_eq!(decide["decider"], "cli:alice");

        let decided: serde_json::Value = serde_json::to_value(ServerMessage::PlanDecided {
            plan_id: sample_plan_id(),
        })
        .unwrap();
        assert_eq!(decided["type"], "plan_decided");

        let already: serde_json::Value = serde_json::to_value(ServerMessage::PlanAlreadyDecided {
            plan_id: sample_plan_id(),
        })
        .unwrap();
        assert_eq!(already["type"], "plan_already_decided");
    }

    /// `plan_decided` and `plan_already_decided` carry their own type
    /// tags so a client dispatching on `type` can distinguish a fresh
    /// decision from a replay without parsing a prose message.
    #[test]
    fn plan_decision_outcomes_have_distinct_tags() {
        let decided: serde_json::Value = serde_json::to_value(ServerMessage::PlanDecided {
            plan_id: sample_plan_id(),
        })
        .unwrap();
        let already: serde_json::Value = serde_json::to_value(ServerMessage::PlanAlreadyDecided {
            plan_id: sample_plan_id(),
        })
        .unwrap();
        let unknown: serde_json::Value = serde_json::to_value(ServerMessage::UnknownPlan {
            plan_id: sample_plan_id(),
        })
        .unwrap();
        let error: serde_json::Value = serde_json::to_value(ServerMessage::Error {
            message: "internal".into(),
        })
        .unwrap();
        let tags = [
            decided["type"].clone(),
            already["type"].clone(),
            unknown["type"].clone(),
            error["type"].clone(),
        ];
        for (i, a) in tags.iter().enumerate() {
            for b in tags.iter().skip(i + 1) {
                assert_ne!(a, b, "expected distinct type tags, got {a} == {b}");
            }
        }
    }

    /// `unknown_plan` carries its own type tag so a client dispatching
    /// on `type` can distinguish it from a generic internal-failure
    /// `Error` without parsing the message string.
    #[test]
    fn unknown_plan_distinct_from_error() {
        let unknown: serde_json::Value = serde_json::to_value(ServerMessage::UnknownPlan {
            plan_id: sample_plan_id(),
        })
        .unwrap();
        let error: serde_json::Value = serde_json::to_value(ServerMessage::Error {
            message: "internal".into(),
        })
        .unwrap();
        assert_ne!(unknown["type"], error["type"]);
    }

    #[test]
    fn staged_push_type_tags() {
        let list: serde_json::Value =
            serde_json::to_value(ClientMessage::ListStagedPushes {}).unwrap();
        assert_eq!(list["type"], "list_staged_pushes");

        let show: serde_json::Value = serde_json::to_value(ClientMessage::ShowStagedPush {
            request_id: sample_request_id(),
        })
        .unwrap();
        assert_eq!(show["type"], "show_staged_push");

        let listing: serde_json::Value =
            serde_json::to_value(ServerMessage::StagedPushes { pushes: vec![] }).unwrap();
        assert_eq!(listing["type"], "staged_pushes");

        let detail: serde_json::Value = serde_json::to_value(ServerMessage::StagedPush {
            push: sample_staged_detail(),
        })
        .unwrap();
        assert_eq!(detail["type"], "staged_push");

        let unknown: serde_json::Value = serde_json::to_value(ServerMessage::UnknownStagedPush {
            request_id: sample_request_id(),
        })
        .unwrap();
        assert_eq!(unknown["type"], "unknown_staged_push");

        let reject: serde_json::Value = serde_json::to_value(ClientMessage::RejectStagedPush {
            request_id: sample_request_id(),
            operator: "alice".into(),
            reason: RejectionReason::try_new("nope").unwrap(),
        })
        .unwrap();
        assert_eq!(reject["type"], "reject_staged_push");
        assert_eq!(reject["operator"], "alice");
        assert_eq!(reject["reason"], "nope");

        let rejected: serde_json::Value = serde_json::to_value(ServerMessage::StagedPushRejected {
            request_id: sample_request_id(),
        })
        .unwrap();
        assert_eq!(rejected["type"], "staged_push_rejected");

        let resolved: serde_json::Value =
            serde_json::to_value(ServerMessage::StagedPushAlreadyResolved {
                request_id: sample_request_id(),
            })
            .unwrap();
        assert_eq!(resolved["type"], "staged_push_already_resolved");
    }

    /// `unknown_staged_push` carries its own type tag so a client
    /// dispatching on `type` can distinguish it from a generic
    /// internal-failure `Error` without parsing the message string.
    #[test]
    fn unknown_staged_push_distinct_from_error() {
        let unknown: serde_json::Value = serde_json::to_value(ServerMessage::UnknownStagedPush {
            request_id: sample_request_id(),
        })
        .unwrap();
        let error: serde_json::Value = serde_json::to_value(ServerMessage::Error {
            message: "internal".into(),
        })
        .unwrap();
        assert_ne!(unknown["type"], error["type"]);
    }

    #[test]
    fn agent_vm_sessions_roundtrips() {
        let msg = ServerMessage::AgentVmSessions {
            sessions: vec![AgentVmSessionInfo {
                session_id: fixed_session_id(),
                status: AgentVmSessionStateStatus::Running,
                subnet_index: 252,
                vm_name: format!("writ-agent-vm-{}", fixed_session_id()),
                network_name: format!("writ-agent-net-{}", fixed_session_id()),
                broker_urls: vec!["http://192.168.252.1:51375/".into()],
                runtime_attached: false,
            }],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn error_roundtrips() {
        let msg = ServerMessage::Error {
            message: "mint failed".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn unknown_session_roundtrips() {
        let msg = ServerMessage::UnknownSession {
            session_id: fixed_session_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn closed_session_roundtrips() {
        let msg = ServerMessage::ClosedSession {
            session_id: fixed_session_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    /// Session-state outcomes carry their own type tag so a client
    /// dispatching on `type` can distinguish them from a generic
    /// internal-failure `Error` without parsing the message string.
    #[test]
    fn session_state_outcomes_have_distinct_tags() {
        let unknown: serde_json::Value = serde_json::to_value(ServerMessage::UnknownSession {
            session_id: fixed_session_id(),
        })
        .unwrap();
        assert_eq!(unknown["type"], "unknown_session");

        let closed: serde_json::Value = serde_json::to_value(ServerMessage::ClosedSession {
            session_id: fixed_session_id(),
        })
        .unwrap();
        assert_eq!(closed["type"], "closed_session");

        let error: serde_json::Value = serde_json::to_value(ServerMessage::Error {
            message: "mint failed".into(),
        })
        .unwrap();
        assert_eq!(error["type"], "error");
    }

    // --- Wire format pins -------------------------------------------------

    #[test]
    fn open_session_type_tag() {
        let v: serde_json::Value = serde_json::to_value(ClientMessage::OpenSession {
            label: None,
            agent_kind: None,
            agent_model: None,
        })
        .unwrap();
        assert_eq!(v["type"], "open_session");
    }

    #[test]
    fn close_session_type_tag() {
        let v: serde_json::Value = serde_json::to_value(ClientMessage::CloseSession {
            session_id: fixed_session_id(),
        })
        .unwrap();
        assert_eq!(v["type"], "close_session");
    }

    #[test]
    fn request_type_tag() {
        let v: serde_json::Value = serde_json::to_value(ClientMessage::Request {
            session_id: fixed_session_id(),
            capability: CapabilityRequest::GitHub(GitHubRequest::Metadata {
                repo: sample_repo(),
            }),
        })
        .unwrap();
        assert_eq!(v["type"], "request");
    }

    #[test]
    fn agent_vm_type_tags() {
        let start: serde_json::Value = serde_json::to_value(ClientMessage::StartAgentVm {
            label: None,
            agent_kind: None,
            agent_model: None,
            workspace: None,
            guest_command: vec!["true".into()],
        })
        .unwrap();
        assert_eq!(start["type"], "start_agent_vm");

        let stop: serde_json::Value = serde_json::to_value(ClientMessage::StopAgentVm {
            session_id: fixed_session_id(),
        })
        .unwrap();
        assert_eq!(stop["type"], "stop_agent_vm");

        let started: serde_json::Value = serde_json::to_value(ServerMessage::AgentVmStarted {
            session_id: fixed_session_id(),
            broker_url: "http://192.168.252.1:51375/".into(),
        })
        .unwrap();
        assert_eq!(started["type"], "agent_vm_started");

        let stopped: serde_json::Value =
            serde_json::to_value(ServerMessage::AgentVmStopped).unwrap();
        assert_eq!(stopped["type"], "agent_vm_stopped");

        let run: serde_json::Value = serde_json::to_value(ClientMessage::StartAgentRun {
            label: None,
            agent_kind: AgentKind::Claude,
            agent_model: "claude-test".into(),
            workspace: AgentVmWorkspaceBootstrap {
                repo: sample_clone_repo(),
                destination: None,
                warm: WorkspaceWarmMode::None,
            },
            prompt: AgentPrompt::new("secret prompt"),
            stage: Stage::Execute,
            correlation_id: None,
            read_plan_id: None,
        })
        .unwrap();
        assert_eq!(run["type"], "start_agent_run");
        assert_eq!(run["stage"], "execute");

        let run_started: serde_json::Value = serde_json::to_value(ServerMessage::AgentRunStarted {
            session_id: fixed_session_id(),
            run_id: "00000000-0000-0000-0000-000000000777".parse().unwrap(),
            broker_url: "http://192.168.252.1:51375/".into(),
        })
        .unwrap();
        assert_eq!(run_started["type"], "agent_run_started");

        let list: serde_json::Value = serde_json::to_value(ClientMessage::ListAgentVms {}).unwrap();
        assert_eq!(list["type"], "list_agent_vms");

        let sessions: serde_json::Value = serde_json::to_value(ServerMessage::AgentVmSessions {
            sessions: Vec::new(),
        })
        .unwrap();
        assert_eq!(sessions["type"], "agent_vm_sessions");
    }

    #[test]
    fn open_session_omits_absent_fields() {
        let v: serde_json::Value = serde_json::to_value(ClientMessage::OpenSession {
            label: None,
            agent_kind: None,
            agent_model: None,
        })
        .unwrap();
        assert!(v.get("label").is_none());
        assert!(v.get("agent_kind").is_none());
        assert!(v.get("agent_model").is_none());
    }

    #[test]
    fn token_granted_type_tag() {
        let v: serde_json::Value = serde_json::to_value(ServerMessage::TokenGranted {
            token: "t".into(),
            expires_at: UnixMillis::from_millis(0),
        })
        .unwrap();
        assert_eq!(v["type"], "token_granted");
    }

    #[test]
    fn denied_type_tag() {
        let v: serde_json::Value =
            serde_json::to_value(ServerMessage::Denied { reason: "x".into() }).unwrap();
        assert_eq!(v["type"], "denied");
    }

    // --- Debug redaction --------------------------------------------------

    #[test]
    fn token_granted_debug_redacts_token() {
        let msg = ServerMessage::TokenGranted {
            token: "ghs_secret_value".into(),
            expires_at: UnixMillis::from_millis(0),
        };
        let debug = format!("{msg:?}");
        assert!(!debug.contains("ghs_secret_value"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn start_agent_run_debug_redacts_prompt() {
        let msg = ClientMessage::StartAgentRun {
            label: None,
            agent_kind: AgentKind::Codex,
            agent_model: "gpt-5.4-mini".into(),
            workspace: AgentVmWorkspaceBootstrap {
                repo: sample_clone_repo(),
                destination: None,
                warm: WorkspaceWarmMode::None,
            },
            prompt: AgentPrompt::new("SECRET prompt"),
            stage: Stage::Execute,
            correlation_id: None,
            read_plan_id: None,
        };

        let debug = format!("{msg:?}");

        assert!(!debug.contains("SECRET prompt"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    // --- Property-based ---------------------------------------------------

    proptest! {
        #[test]
        fn open_session_roundtrips_arbitrary_strings(
            label in proptest::option::of("[^\n]{0,100}"),
            agent_model in proptest::option::of("[^\n]{0,80}"),
        ) {
            let msg = ClientMessage::OpenSession { label, agent_kind: None, agent_model };
            let json = serde_json::to_string(&msg).unwrap();
            let back: ClientMessage = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(msg, back);
        }

        #[test]
        fn denied_roundtrips_arbitrary_reason(reason in "[^\n]{0,200}") {
            let msg = ServerMessage::Denied { reason };
            let json = serde_json::to_string(&msg).unwrap();
            let back: ServerMessage = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(msg, back);
        }

        #[test]
        fn error_roundtrips_arbitrary_message(message in "[^\n]{0,200}") {
            let msg = ServerMessage::Error { message };
            let json = serde_json::to_string(&msg).unwrap();
            let back: ServerMessage = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(msg, back);
        }

        /// A typo at the wire (e.g. `agentkind` instead of `agent_kind`) must
        /// be a parse error, not a silently-dropped field that defaults the
        /// real one. This pins `deny_unknown_fields` for every variant: pick
        /// any sample message, inject an arbitrary key not used by any
        /// variant, and assert the result fails to parse.
        #[test]
        fn client_message_rejects_unknown_top_level_fields(
            variant_index in 0usize..13,
            // ASCII-letters-only key, excluded against the union of every
            // variant's known field names below.
            unknown_key in "[a-z]{1,16}",
        ) {
            const KNOWN_FIELDS: &[&str] = &[
                "type", "label", "agent_kind", "agent_model", "workspace",
                "guest_command", "session_id", "capability", "prompt",
                "stage", "correlation_id", "plan_id",
                "request_id", "reason", "operator",
                "outcome", "decider",
            ];
            prop_assume!(!KNOWN_FIELDS.contains(&unknown_key.as_str()));

            let msg = sample_client_message(variant_index);
            let mut value = serde_json::to_value(&msg).unwrap();
            value.as_object_mut().unwrap().insert(
                unknown_key.clone(),
                serde_json::Value::String("x".into()),
            );

            let result = serde_json::from_value::<ClientMessage>(value.clone());
            prop_assert!(
                result.is_err(),
                "variant {variant_index} accepted unknown key {unknown_key:?}: {value}",
            );
        }
    }

    /// One sample per `ClientMessage` variant. The order is fixed so the
    /// proptest's variant index is stable across runs.
    fn sample_client_message(index: usize) -> ClientMessage {
        match index {
            0 => ClientMessage::OpenSession {
                label: Some("fix bug".into()),
                agent_kind: Some(AgentKind::Claude),
                agent_model: Some("claude-test".into()),
            },
            1 => ClientMessage::CloseSession {
                session_id: fixed_session_id(),
            },
            2 => ClientMessage::Request {
                session_id: fixed_session_id(),
                capability: CapabilityRequest::GitHub(GitHubRequest::Metadata {
                    repo: sample_repo(),
                }),
            },
            3 => ClientMessage::StartAgentVm {
                label: None,
                agent_kind: None,
                agent_model: None,
                workspace: None,
                guest_command: vec!["true".into()],
            },
            4 => ClientMessage::StartAgentRun {
                label: None,
                agent_kind: AgentKind::Claude,
                agent_model: "claude-test".into(),
                workspace: AgentVmWorkspaceBootstrap {
                    repo: sample_clone_repo(),
                    destination: None,
                    warm: WorkspaceWarmMode::None,
                },
                prompt: AgentPrompt::new("p"),
                stage: Stage::Plan,
                correlation_id: None,
                read_plan_id: None,
            },
            5 => ClientMessage::StopAgentVm {
                session_id: fixed_session_id(),
            },
            6 => ClientMessage::ListAgentVms {},
            7 => ClientMessage::ListStagedPushes {},
            8 => ClientMessage::ShowStagedPush {
                request_id: "12345678-1234-1234-1234-123456789012".parse().unwrap(),
            },
            9 => ClientMessage::RejectStagedPush {
                request_id: "12345678-1234-1234-1234-123456789012".parse().unwrap(),
                operator: "alice".into(),
                reason: RejectionReason::try_new("leaks credentials").unwrap(),
            },
            10 => ClientMessage::ListPlans {
                correlation_id: Some(CorrelationId::try_new("feat-42_xyz").unwrap()),
            },
            11 => ClientMessage::ShowPlan {
                plan_id: sample_plan_id(),
            },
            12 => ClientMessage::DecidePlan {
                plan_id: sample_plan_id(),
                outcome: DecisionOutcome::Accepted,
                decider: Decider::try_new("cli:alice").unwrap(),
            },
            other => unreachable!("variant index out of range: {other}"),
        }
    }
}
