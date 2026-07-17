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

use serde::{Deserialize, Serialize};

use crate::agent_run::{AgentPrompt, AgentRunId, CorrelationId};
use crate::core::{
    AgentKind, CapabilityRequest, CapabilitySet, NotesRef, RequestId, SessionId, SshSignature,
    UnixMillis,
};
use crate::vm_git::{AgentVmWorkspaceBootstrap, GitObjectId};

mod views;
pub use views::{
    AgentVmSessionInfo, MAX_REJECTION_REASON_BYTES, ReconcileOutcome, RejectionReason,
    RejectionReasonError, SignedRunMetadata, StagedPushAuditView, StagedPushDetail,
    StagedPushSummary,
};

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
    /// lifecycle state. The broker delivers it verbatim over the brokered
    /// prompt channel; no further composition happens guest-side.
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
        /// Opaque caller-supplied identifier joining this run to a
        /// wider task (per `docs/plans/2026-05-11-agent-plans.md`).
        /// Stored verbatim on the `agent_run` audit row; the broker
        /// never interprets it.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        correlation_id: Option<CorrelationId>,
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
    /// List every VM-staged push currently waiting for promotion review,
    /// optionally filtered to those staged under a single audit session.
    /// Replies with [`ServerMessage::StagedPushes`].
    ///
    /// `session_id` is `None` for the legacy "list everything" shape; the
    /// broker honours the absence as an explicit "no filter" rather than
    /// defaulting to a hidden value. When `Some`, the broker resolves the
    /// audit-side set of `push_request_id`s recorded against that session
    /// and returns only the staged-store entries whose request id appears
    /// there. Sessions that have never had any push staged return an
    /// empty list (no error), since a session with no pushes is a
    /// well-defined input.
    ///
    /// Struct rather than unit variant so the enum-level
    /// `deny_unknown_fields` applies. See [`ClientMessage::ListAgentVms`].
    ListStagedPushes {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<SessionId>,
    },
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
    /// Record an operator decision to approve a VM-staged push: the
    /// broker should mint an installation token, walk the staged
    /// bundle's commits onto GitHub under the App's identity, signing
    /// each one, point the branch at the resulting tip, write the
    /// audit resolution row, and delete the staging directory. Replies
    /// with [`ServerMessage::StagedPushApproved`] on success,
    /// [`ServerMessage::UnknownStagedPush`] if the staging directory is
    /// gone, or [`ServerMessage::StagedPushAlreadyResolved`] if a prior
    /// decision is already recorded against this request id.
    ///
    /// `operator` is the human identity the broker records in the
    /// audit row. The host CLI captures `$USER` and sends it; the
    /// broker is not the source of authentication and trusts whatever
    /// the local-socket peer asserts (the socket itself is the trust
    /// boundary).
    ///
    /// Slice B1e.1 lands the request type only. Dispatch returns
    /// [`ServerMessage::Error`] until slice B1e.2 wires up the real
    /// mint + replay + signing + audit pipeline; this matches the
    /// same wire-first / handler-second split slice A1 used for
    /// [`ClientMessage::RunAgent`].
    ApproveStagedPush {
        request_id: RequestId,
        operator: String,
    },
    /// Record an operator decision to manually reconcile a quarantined
    /// staged push: one whose latest non-superseded approve attempt is
    /// either `Resolved(PostPatchFailure)` (the broker observed the
    /// PATCH go out but the response was ambiguous) or `Uncertain` and
    /// marked boot-observed (the daemon that wrote the row is provably
    /// dead, so the row can no longer race a live worker). The broker
    /// writes a born-terminal reconciliation attempt row that
    /// `supersedes_attempt_id`-references the predecessor; for an
    /// `Applied` outcome the same transaction also writes the
    /// `git_push_resolution(decision='approved')` row, advancing the
    /// push to a terminal "approved" state. For `NotApplied`, no
    /// resolution row is written and the push becomes
    /// rejectable/retryable.
    ///
    /// Replies with [`ServerMessage::StagedPushReconciled`] on success,
    /// [`ServerMessage::UnknownStagedPush`] if the staging directory is
    /// gone, [`ServerMessage::StagedPushAlreadyResolved`] if a prior
    /// resolution is already recorded, or
    /// [`ServerMessage::StagedPushNotReconcilable`] when no eligible
    /// blocker exists (no attempts at all, the latest attempt is still
    /// in flight, every blocker has already been superseded, or only
    /// `Resolved(PrePatchFailure)` attempts remain).
    ///
    /// `operator` is the human identity the broker records in both the
    /// reconciliation attempt row and (for `Applied`) the resolution
    /// row. As with reject/approve, the local socket is the trust
    /// boundary.
    ReconcileStagedPush {
        request_id: RequestId,
        operator: String,
        outcome: ReconcileOutcome,
    },
    /// Ask writ to spawn an agent with the given prompt and capability
    /// set, then write the signed terminal output as a note into the
    /// caller's Git repo at `output_ref`. Bailiff is the intended
    /// (sole) client of this RPC; see
    /// `docs/plans/2026-05-14-bailiff-split.md`.
    ///
    /// `session_id` binds the run to an audit session the caller
    /// previously opened with [`ClientMessage::OpenSession`]. When
    /// `Some`, writ validates the session exists and is still open
    /// before spawning, and stamps the same id into the signed
    /// metadata so a verifier can correlate the envelope back to the
    /// workflow session. When `None` (legacy / standalone use), writ
    /// mints a fresh id for the signed metadata alone — no audit
    /// session row is created, and the id is unreachable except via
    /// the signed envelope.
    ///
    /// Slice A1 lands the request type only. Dispatch returns
    /// [`ServerMessage::Error`] until slice B wires up the real spawner
    /// and signing path; the response variant
    /// (`ServerMessage::RunAgentCompleted`) arrives alongside its
    /// first consumer (the bailiff binary skeleton) in slice A2.
    RunAgent {
        /// Prompt delivered verbatim to the spawned agent's stdin.
        /// Writ forwards the bytes but does not store, persist, or
        /// interpret them — the audit row records only the hash.
        prompt: AgentPrompt,
        /// Authority granted to this run. Each variant maps to a
        /// `policy::*` oracle check at request time. Stored as a
        /// canonical collection on the audit row.
        capabilities: Vec<CapabilitySet>,
        /// Caller-supplied opaque tag recorded verbatim in audit.
        /// Writ never interprets the contents; bailiff uses it to
        /// reconcile the writ-side run with its own workflow vocabulary
        /// (e.g. `"plan-stage"`, `"review:plan-abc"`).
        purpose: String,
        /// Notes ref in the caller's Git repo where writ should
        /// attach the signed output note once the run completes.
        output_ref: NotesRef,
        /// Optional caller-supplied session id binding the run to an
        /// already-opened audit session. The field is omitted on the
        /// wire (`skip_serializing_if = "Option::is_none"`) and
        /// defaults to `None` on decode so a legacy caller that
        /// predates the field still parses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<SessionId>,
        /// When present, writ must run the agent inside a per-run VM
        /// provisioned with a checkout per the bootstrap. The agent's
        /// cwd inside the VM is the checkout destination, so a
        /// `CapabilitySet::WorkspaceWrite` capability is meaningful.
        /// When absent, writ takes the host-spawn path (no cwd,
        /// suitable only for read-only or prompt-only agent runs).
        ///
        /// Required when any element of `capabilities` is
        /// `CapabilitySet::WorkspaceWrite { .. }`: the broker rejects
        /// such a request with no workspace bootstrap, so the host
        /// path cannot mint write-capable runs against no checkout.
        /// Omitted on the wire when `None` so a legacy caller that
        /// predates this field still parses.
        ///
        /// Slice VM1 adds the field and the rejection gate. Slice VM2
        /// will replace today's "VM dispatch not yet wired" placeholder
        /// error with the real VM dispatch.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        workspace: Option<AgentVmWorkspaceBootstrap>,
        /// Agent kind to launch inside the VM. Required when `workspace`
        /// is present (VM mode); ignored on the host path. The wire
        /// shape carries the field as optional so a host-path caller
        /// that doesn't know about VM mode can omit it. A VM-mode
        /// request that omits the field is rejected by the dispatcher
        /// before any state work happens — picking a default would be
        /// a lie about which model the broker pins onto the VM's
        /// agent-run config.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_kind: Option<AgentKind>,
        /// Agent model identifier the broker pins onto the VM's
        /// `/v1/agent-runs/<id>/config` response. Required alongside
        /// `agent_kind` when `workspace` is present; ignored otherwise.
        /// Free-form string — the broker never parses the value, just
        /// hands it to the guest.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_model: Option<String>,
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
    /// or [`ClientMessage::ApproveStagedPush`] already has a recorded
    /// operator decision. Distinct from
    /// [`ServerMessage::UnknownStagedPush`] and [`ServerMessage::Error`]
    /// so a replay surfaces as an explicit "already decided" outcome
    /// rather than a prose error string.
    StagedPushAlreadyResolved { request_id: RequestId },
    /// Acknowledges [`ClientMessage::ApproveStagedPush`]: the audit
    /// resolution row was written, the bundle's commits were replayed
    /// onto GitHub under the App's identity, and the branch on GitHub
    /// has been updated to point at `new_app_tip` — the App-side
    /// commit SHA the walker produced for the last commit in the
    /// topo-sorted walk. Carrying both `request_id` and `new_app_tip`
    /// lets the CLI confirm both the exact push it asked to approve
    /// and the SHA the bailiff should attach its terminal-output note
    /// to.
    StagedPushApproved {
        request_id: RequestId,
        new_app_tip: GitObjectId,
    },
    /// Acknowledges [`ClientMessage::ReconcileStagedPush`]: the
    /// born-terminal reconciliation attempt row was committed,
    /// superseding the predecessor blocker. For an `Applied` outcome
    /// the joint TX also committed the
    /// `git_push_resolution(decision='approved')` row; for
    /// `NotApplied`, no resolution row was written and the push is
    /// once again rejectable/retryable. The CLI already knows which
    /// outcome it sent, so the ack does not echo it.
    StagedPushReconciled { request_id: RequestId },
    /// The staged push referenced by
    /// [`ClientMessage::ReconcileStagedPush`] has no eligible blocker
    /// to clear — no `Uncertain` (with a boot-observed marker) or
    /// `Resolved(PostPatchFailure)` attempt is currently outstanding
    /// against it. `reason` carries a typed diagnostic the CLI
    /// surfaces verbatim. Distinct from [`ServerMessage::Error`] so
    /// the CLI distinguishes "nothing to reconcile" from a broker
    /// failure without parsing prose.
    StagedPushNotReconcilable {
        request_id: RequestId,
        reason: String,
    },
    /// Synchronous reply to [`ClientMessage::RunAgent`]. The agent has
    /// run to completion (or to a non-zero terminal exit), writ has
    /// written the output envelope as a Git blob in the caller's repo,
    /// and `signed_metadata` carries the canonical bytes covered by
    /// `signature`. A verifier reconstructs the canonical bytes from
    /// `signed_metadata` and validates `signature` against the public
    /// key keyed by `signed_metadata.signing_key_fingerprint`.
    ///
    /// `output_oid` is the OID of the envelope blob writ wrote, so
    /// bailiff can attach the signed note at the requested ref
    /// without re-resolving the object.
    ///
    /// Slice A2 lands the wire shape; the dispatch path still
    /// short-circuits to [`ServerMessage::Error`] until slice B
    /// implements the spawner + signer.
    RunAgentCompleted {
        output_oid: GitObjectId,
        signed_metadata: SignedRunMetadata,
        signature: SshSignature,
    },
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
            Self::StagedPushApproved {
                request_id,
                new_app_tip,
            } => f
                .debug_struct("StagedPushApproved")
                .field("request_id", request_id)
                .field("new_app_tip", new_app_tip)
                .finish(),
            Self::StagedPushReconciled { request_id } => f
                .debug_struct("StagedPushReconciled")
                .field("request_id", request_id)
                .finish(),
            Self::StagedPushNotReconcilable { request_id, reason } => f
                .debug_struct("StagedPushNotReconcilable")
                .field("request_id", request_id)
                .field("reason", reason)
                .finish(),
            Self::RunAgentCompleted {
                output_oid,
                signed_metadata,
                signature,
            } => f
                .debug_struct("RunAgentCompleted")
                .field("output_oid", output_oid)
                .field("signed_metadata", signed_metadata)
                .field("signature", signature)
                .finish(),
            Self::Error { message } => f.debug_struct("Error").field("message", message).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_vm_lifecycle::{AgentVmSessionStateStatus, NetworkHealth};
    use crate::audit::GitPushOutcomeResult;
    use crate::core::{GitHubAccess, GitHubRequest, RepoRef, Sha256Hex, SshKeyFingerprint};
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
            correlation_id: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
        assert!(json.contains("fix the failing test"));
        // The optional correlation_id is elided when None so older
        // clients/servers that predate it can still parse the message.
        assert!(!json.contains("correlation_id"));
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
            correlation_id: Some(CorrelationId::try_new("feat-42_xyz").unwrap()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
        assert!(json.contains("feat-42_xyz"));
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
    fn run_agent_roundtrips() {
        let msg = ClientMessage::RunAgent {
            prompt: AgentPrompt::new("plan the change"),
            capabilities: vec![
                CapabilitySet::WorkspaceRead {
                    repo: sample_repo(),
                },
                CapabilitySet::WorkspaceWrite {
                    repo: sample_repo(),
                },
            ],
            purpose: "plan-stage".into(),
            output_ref: NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap(),
            session_id: Some(fixed_session_id()),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ClientMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, msg);
    }

    /// `capabilities` is the new wire field — pin its on-the-wire name
    /// (vs. an accidental `capability` / `capability_set` typo that
    /// future refactoring might introduce) and confirm the empty-vec
    /// case roundtrips, which lets bailiff express "no extra
    /// capabilities beyond what the session already grants" without
    /// special-casing the absent-field path.
    #[test]
    fn run_agent_pins_field_names_and_accepts_empty_capabilities() {
        let msg = ClientMessage::RunAgent {
            prompt: AgentPrompt::new("p"),
            capabilities: vec![],
            purpose: "reviewer".into(),
            output_ref: NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap(),
            session_id: None,
            workspace: None,
            agent_kind: None,
            agent_model: None,
        };
        let value: serde_json::Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(value["type"], "run_agent");
        assert!(value.get("capabilities").is_some(), "wire: {value}");
        assert!(value.get("purpose").is_some(), "wire: {value}");
        assert!(value.get("output_ref").is_some(), "wire: {value}");
        // `session_id` is omitted when `None` so the legacy wire shape
        // round-trips byte-for-byte. The bound test below pins the
        // present-on-the-wire spelling.
        assert!(value.get("session_id").is_none(), "wire: {value}");
        // Same elision rule for the VM1 `workspace` field: omitted on
        // the wire when `None` so the pre-VM1 shape (a host-path
        // `WorkspaceRead` caller) still encodes byte-for-byte the same.
        assert!(value.get("workspace").is_none(), "wire: {value}");
        let back: ClientMessage = serde_json::from_value(value).unwrap();
        assert_eq!(back, msg);
    }

    /// When the caller supplies a `session_id`, it appears on the wire
    /// under that exact field name. Pinning the spelling here means a
    /// drift to `audit_session_id` or `session` in a future refactor
    /// fails this test rather than silently changing the broker
    /// contract.
    #[test]
    fn run_agent_session_id_is_named_session_id_on_the_wire() {
        let session_id = fixed_session_id();
        let msg = ClientMessage::RunAgent {
            prompt: AgentPrompt::new("p"),
            capabilities: vec![],
            purpose: "plan-submit".into(),
            output_ref: NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap(),
            session_id: Some(session_id),
            workspace: None,
            agent_kind: None,
            agent_model: None,
        };
        let value: serde_json::Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(
            value["session_id"],
            serde_json::Value::String(session_id.as_uuid().to_string()),
            "wire: {value}",
        );
        let back: ClientMessage = serde_json::from_value(value).unwrap();
        assert_eq!(back, msg);
    }

    /// A wire payload that omits `session_id` decodes as `None` —
    /// preserves backward compatibility with the slice-A1 wire shape.
    #[test]
    fn run_agent_accepts_payload_without_session_id() {
        let value = serde_json::json!({
            "type": "run_agent",
            "prompt": "p",
            "capabilities": [],
            "purpose": "legacy",
            "output_ref": "refs/notes/writ/agent-outputs",
        });
        let back: ClientMessage = serde_json::from_value(value).unwrap();
        match back {
            ClientMessage::RunAgent { session_id, .. } => assert_eq!(session_id, None),
            other => panic!("expected RunAgent, got {other:?}"),
        }
    }

    /// When the caller supplies a `workspace` bootstrap, the field
    /// appears on the wire under that exact name and round-trips
    /// byte-equal. Pinning the spelling here means a future refactor
    /// to `vm_workspace` or `agent_workspace` fails this test rather
    /// than silently changing the broker contract — `bailiff plan
    /// implement` will be the first caller to depend on the field.
    #[test]
    fn run_agent_roundtrips_with_workspace_field() {
        let msg = ClientMessage::RunAgent {
            prompt: AgentPrompt::new("implement the plan"),
            capabilities: vec![CapabilitySet::WorkspaceWrite {
                repo: sample_repo(),
            }],
            purpose: "implement-stage".into(),
            output_ref: NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap(),
            session_id: Some(fixed_session_id()),
            workspace: Some(AgentVmWorkspaceBootstrap {
                repo: sample_clone_repo(),
                destination: Some(PathBuf::from("/workspace/repo")),
                warm: WorkspaceWarmMode::DevShell,
            }),
            agent_kind: None,
            agent_model: None,
        };
        let value: serde_json::Value = serde_json::to_value(&msg).unwrap();
        assert!(value.get("workspace").is_some(), "wire: {value}");
        let back: ClientMessage = serde_json::from_value(value).unwrap();
        assert_eq!(back, msg);
    }

    /// A wire payload that omits `workspace` decodes as `None` —
    /// preserves backward compatibility with the pre-VM1 wire shape
    /// for `WorkspaceRead` callers (`bailiff plan submit` and `bailiff
    /// plan review`), and is the spelling `skip_serializing_if =
    /// "Option::is_none"` produces on encode.
    #[test]
    fn run_agent_accepts_payload_without_workspace_field() {
        let value = serde_json::json!({
            "type": "run_agent",
            "prompt": "p",
            "capabilities": [],
            "purpose": "legacy",
            "output_ref": "refs/notes/writ/agent-outputs",
        });
        let back: ClientMessage = serde_json::from_value(value).unwrap();
        match back {
            ClientMessage::RunAgent { workspace, .. } => assert_eq!(workspace, None),
            other => panic!("expected RunAgent, got {other:?}"),
        }
    }

    /// When the caller supplies `agent_kind` and `agent_model`, both
    /// fields appear on the wire under those exact names and
    /// round-trip byte-equal. Slice VM2b adds the pair so VM-mode
    /// `RunAgent` callers can pick the model the broker pins onto the
    /// VM's `/v1/agent-runs/<id>/config` response — the host path
    /// ignores both fields, but the wire shape carries them
    /// regardless so a single decoder serves both modes.
    #[test]
    fn run_agent_roundtrips_with_agent_kind_and_model() {
        let msg = ClientMessage::RunAgent {
            prompt: AgentPrompt::new("implement on vm"),
            capabilities: vec![CapabilitySet::WorkspaceWrite {
                repo: sample_repo(),
            }],
            purpose: "implement-stage".into(),
            output_ref: NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap(),
            session_id: None,
            workspace: Some(AgentVmWorkspaceBootstrap {
                repo: sample_clone_repo(),
                destination: Some(PathBuf::from("/workspace/repo")),
                warm: WorkspaceWarmMode::DevShell,
            }),
            agent_kind: Some(AgentKind::Claude),
            agent_model: Some("claude-opus-4-7".into()),
        };
        let value: serde_json::Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(
            value["agent_kind"],
            serde_json::Value::String("claude".into())
        );
        assert_eq!(
            value["agent_model"],
            serde_json::Value::String("claude-opus-4-7".into()),
        );
        let back: ClientMessage = serde_json::from_value(value).unwrap();
        assert_eq!(back, msg);
    }

    /// A wire payload that omits `agent_kind` / `agent_model` decodes
    /// with both fields as `None` — preserves backward compatibility
    /// with the pre-VM2b wire shape (a host-path `WorkspaceRead`
    /// caller, e.g. `bailiff plan submit`, never supplies them).
    #[test]
    fn run_agent_accepts_payload_without_agent_kind_or_model() {
        let value = serde_json::json!({
            "type": "run_agent",
            "prompt": "p",
            "capabilities": [],
            "purpose": "legacy",
            "output_ref": "refs/notes/writ/agent-outputs",
        });
        let back: ClientMessage = serde_json::from_value(value).unwrap();
        match back {
            ClientMessage::RunAgent {
                agent_kind,
                agent_model,
                ..
            } => {
                assert_eq!(agent_kind, None);
                assert_eq!(agent_model, None);
            }
            other => panic!("expected RunAgent, got {other:?}"),
        }
    }

    /// `deny_unknown_fields` at the enum level catches a typo'd inner
    /// field name (e.g. `capability_set` from an earlier draft of the
    /// design doc) before it silently turns into "no capabilities".
    #[test]
    fn run_agent_rejects_legacy_capability_set_field() {
        let value = serde_json::json!({
            "type": "run_agent",
            "prompt": "p",
            "capability_set": {"kind": "workspace_read", "repo": "smaug123/writ"},
            "purpose": "x",
            "output_ref": "refs/notes/writ/agent-outputs",
        });
        let err = serde_json::from_value::<ClientMessage>(value).unwrap_err();
        assert!(
            err.to_string().contains("capability_set") || err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}",
        );
    }

    #[test]
    fn run_agent_rejects_invalid_notes_ref() {
        let value = serde_json::json!({
            "type": "run_agent",
            "prompt": "p",
            "capabilities": [],
            "purpose": "x",
            "output_ref": "not-under-refs/",
        });
        let err = serde_json::from_value::<ClientMessage>(value).unwrap_err();
        assert!(
            err.to_string().contains("refs/"),
            "expected refs-prefix error, got: {err}",
        );
    }

    #[test]
    fn list_agent_vms_roundtrips() {
        let msg = ClientMessage::ListAgentVms {};
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn list_staged_pushes_roundtrips() {
        let msg = ClientMessage::ListStagedPushes { session_id: None };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn list_staged_pushes_with_session_filter_roundtrips() {
        let msg = ClientMessage::ListStagedPushes {
            session_id: Some(fixed_session_id()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    /// Older callers that send `{"type": "list_staged_pushes"}` with no
    /// `session_id` key must still parse as the no-filter variant.
    /// `#[serde(default)]` carries this invariant; pinning it here so a
    /// future refactor that drops the default surfaces as a test failure
    /// rather than a silent wire-compat break.
    #[test]
    fn list_staged_pushes_without_session_field_parses_as_no_filter() {
        let json = r#"{"type":"list_staged_pushes"}"#;
        let parsed: ClientMessage = serde_json::from_str(json).unwrap();
        assert_eq!(parsed, ClientMessage::ListStagedPushes { session_id: None });
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
    fn approve_staged_push_roundtrips() {
        let msg = ClientMessage::ApproveStagedPush {
            request_id: sample_request_id(),
            operator: "alice".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn reconcile_staged_push_applied_roundtrips() {
        let msg = ClientMessage::ReconcileStagedPush {
            request_id: sample_request_id(),
            operator: "alice".into(),
            outcome: ReconcileOutcome::Applied {
                new_app_tip: sample_object_id('c'),
                reason: "verified on GitHub UI".into(),
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
        // The outcome is nested under `outcome` and carries its own `kind` tag,
        // distinct from the outer `type` discriminator.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["type"], "reconcile_staged_push");
        assert_eq!(value["outcome"]["kind"], "applied");
        assert_eq!(
            value["outcome"]["new_app_tip"],
            serde_json::Value::String(sample_object_id('c').as_str().to_string()),
        );
        assert_eq!(value["outcome"]["reason"], "verified on GitHub UI");
    }

    #[test]
    fn reconcile_staged_push_not_applied_roundtrips() {
        let msg = ClientMessage::ReconcileStagedPush {
            request_id: sample_request_id(),
            operator: "alice".into(),
            outcome: ReconcileOutcome::NotApplied {
                detail: "branch on GitHub is unchanged".into(),
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), msg);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["outcome"]["kind"], "not_applied");
        assert_eq!(value["outcome"]["detail"], "branch on GitHub is unchanged");
        // `new_app_tip` and `reason` are exclusive to the `applied` variant.
        assert!(value["outcome"].get("new_app_tip").is_none());
        assert!(value["outcome"].get("reason").is_none());
    }

    /// `ReconcileOutcome` is `deny_unknown_fields`: a typo in one of
    /// the variant fields must be a parse error, not silently dropped.
    #[test]
    fn reconcile_outcome_rejects_unknown_fields() {
        let bad = serde_json::json!({
            "kind": "applied",
            "new_app_tip": sample_object_id('c').as_str(),
            "reason": "ok",
            "extra": "stray",
        });
        let err = serde_json::from_value::<ReconcileOutcome>(bad).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}"
        );
    }

    /// Swapping the outcome `kind` must yield a different variant on
    /// the other end — the discriminator is load-bearing.
    #[test]
    fn reconcile_outcome_discriminator_chooses_variant() {
        let applied = serde_json::json!({
            "kind": "applied",
            "new_app_tip": sample_object_id('d').as_str(),
            "reason": "matches",
        });
        let parsed: ReconcileOutcome = serde_json::from_value(applied).unwrap();
        assert!(matches!(parsed, ReconcileOutcome::Applied { .. }));

        let not_applied = serde_json::json!({
            "kind": "not_applied",
            "detail": "no",
        });
        let parsed: ReconcileOutcome = serde_json::from_value(not_applied).unwrap();
        assert!(matches!(parsed, ReconcileOutcome::NotApplied { .. }));
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

    fn sample_agent_run_id() -> AgentRunId {
        "f2f2f2f2-0000-0000-0000-000000000001".parse().unwrap()
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
    fn staged_push_approved_roundtrips() {
        let msg = ServerMessage::StagedPushApproved {
            request_id: sample_request_id(),
            new_app_tip: sample_object_id('e'),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn staged_push_reconciled_roundtrips() {
        let msg = ServerMessage::StagedPushReconciled {
            request_id: sample_request_id(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["type"], "staged_push_reconciled");
    }

    #[test]
    fn staged_push_not_reconcilable_roundtrips() {
        let msg = ServerMessage::StagedPushNotReconcilable {
            request_id: sample_request_id(),
            reason: "no eligible blocker".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), msg);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["type"], "staged_push_not_reconcilable");
        assert_eq!(value["reason"], "no eligible blocker");
    }

    #[test]
    fn staged_push_type_tags() {
        let list: serde_json::Value =
            serde_json::to_value(ClientMessage::ListStagedPushes { session_id: None }).unwrap();
        assert_eq!(list["type"], "list_staged_pushes");
        // The optional `session_id` is elided on the wire when None so
        // a no-filter list looks byte-identical to the legacy payload.
        assert!(list.as_object().unwrap().get("session_id").is_none());

        let list_filtered: serde_json::Value =
            serde_json::to_value(ClientMessage::ListStagedPushes {
                session_id: Some(fixed_session_id()),
            })
            .unwrap();
        assert_eq!(list_filtered["type"], "list_staged_pushes");
        assert_eq!(
            list_filtered["session_id"],
            serde_json::Value::String(fixed_session_id().as_uuid().to_string()),
        );

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

        let approve: serde_json::Value = serde_json::to_value(ClientMessage::ApproveStagedPush {
            request_id: sample_request_id(),
            operator: "alice".into(),
        })
        .unwrap();
        assert_eq!(approve["type"], "approve_staged_push");
        assert_eq!(approve["operator"], "alice");

        let approved: serde_json::Value = serde_json::to_value(ServerMessage::StagedPushApproved {
            request_id: sample_request_id(),
            new_app_tip: sample_object_id('e'),
        })
        .unwrap();
        assert_eq!(approved["type"], "staged_push_approved");
        assert_eq!(
            approved["new_app_tip"],
            serde_json::Value::String(sample_object_id('e').as_str().to_string()),
        );

        let reconcile: serde_json::Value =
            serde_json::to_value(ClientMessage::ReconcileStagedPush {
                request_id: sample_request_id(),
                operator: "alice".into(),
                outcome: ReconcileOutcome::NotApplied {
                    detail: "no PATCH".into(),
                },
            })
            .unwrap();
        assert_eq!(reconcile["type"], "reconcile_staged_push");
        assert_eq!(reconcile["operator"], "alice");
        assert_eq!(reconcile["outcome"]["kind"], "not_applied");
        assert_eq!(reconcile["outcome"]["detail"], "no PATCH");

        let reconciled: serde_json::Value =
            serde_json::to_value(ServerMessage::StagedPushReconciled {
                request_id: sample_request_id(),
            })
            .unwrap();
        assert_eq!(reconciled["type"], "staged_push_reconciled");

        let not_reconcilable: serde_json::Value =
            serde_json::to_value(ServerMessage::StagedPushNotReconcilable {
                request_id: sample_request_id(),
                reason: "no eligible blocker".into(),
            })
            .unwrap();
        assert_eq!(not_reconcilable["type"], "staged_push_not_reconcilable");
        assert_eq!(not_reconcilable["reason"], "no eligible blocker");
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
                network_health: NetworkHealth::Reachable,
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

    fn sample_sha256_hex(nibble: char) -> Sha256Hex {
        Sha256Hex::try_new(std::iter::repeat_n(nibble, 64).collect::<String>()).unwrap()
    }

    fn sample_ssh_fingerprint() -> SshKeyFingerprint {
        SshKeyFingerprint::try_new("SHA256:Wn0p0WC9F8bJ35rwTRsLP6w8b9ZsZh4HX0FYpC0Zg").unwrap()
    }

    fn sample_ssh_signature() -> SshSignature {
        SshSignature::try_new(
            "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ...\n-----END SSH SIGNATURE-----",
        )
        .unwrap()
    }

    fn sample_signed_run_metadata() -> SignedRunMetadata {
        SignedRunMetadata {
            run_id: sample_agent_run_id(),
            session_id: fixed_session_id(),
            prompt_sha256: sample_sha256_hex('a'),
            output_envelope_sha256: sample_sha256_hex('b'),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: sample_repo(),
            }],
            exit_code: 0,
            completed_at: UnixMillis::from_millis(1_700_000_000_000),
            signing_key_fingerprint: sample_ssh_fingerprint(),
        }
    }

    #[test]
    fn run_agent_completed_roundtrips() {
        let msg = ServerMessage::RunAgentCompleted {
            output_oid: sample_object_id('c'),
            signed_metadata: sample_signed_run_metadata(),
            signature: sample_ssh_signature(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ServerMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, msg);
    }

    /// Pin the wire type tag and the public field names. A regression
    /// in any of these would silently break bailiff at parse time once
    /// slice B starts emitting real responses.
    #[test]
    fn run_agent_completed_pins_wire_shape() {
        let msg = ServerMessage::RunAgentCompleted {
            output_oid: sample_object_id('c'),
            signed_metadata: sample_signed_run_metadata(),
            signature: sample_ssh_signature(),
        };
        let value: serde_json::Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(value["type"], "run_agent_completed");
        assert!(value.get("output_oid").is_some(), "wire: {value}");
        assert!(value.get("signed_metadata").is_some(), "wire: {value}");
        assert!(value.get("signature").is_some(), "wire: {value}");
        let meta = &value["signed_metadata"];
        for field in [
            "run_id",
            "session_id",
            "prompt_sha256",
            "output_envelope_sha256",
            "capabilities",
            "exit_code",
            "completed_at",
            "signing_key_fingerprint",
        ] {
            assert!(
                meta.get(field).is_some(),
                "signed_metadata missing field {field}: {meta}",
            );
        }
    }

    /// `deny_unknown_fields` on `SignedRunMetadata` catches an
    /// unexpected key at parse time. The canonical bytes that
    /// `signature` covers are reconstructed from exactly this field
    /// set; a silently-dropped extra field would make verification
    /// inconsistent across versions.
    #[test]
    fn signed_run_metadata_rejects_unknown_fields() {
        let mut value: serde_json::Value =
            serde_json::to_value(sample_signed_run_metadata()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::Value::String("nope".into()));
        let err = serde_json::from_value::<SignedRunMetadata>(value).unwrap_err();
        assert!(
            err.to_string().contains("extra") || err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}",
        );
    }

    /// A malformed digest on the wire must be rejected at parse time
    /// rather than reaching the verifier. The error message must point
    /// the operator at the malformed value.
    #[test]
    fn signed_run_metadata_rejects_malformed_prompt_sha256() {
        let mut value: serde_json::Value =
            serde_json::to_value(sample_signed_run_metadata()).unwrap();
        value["prompt_sha256"] = serde_json::Value::String("not-a-hash".into());
        let err = serde_json::from_value::<SignedRunMetadata>(value).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("64") || msg.contains("hex"),
            "expected digest error, got: {msg}",
        );
    }

    /// Likewise for the fingerprint: the trust anchor is keyed by the
    /// `SHA256:` prefix shape, so a missing prefix is a wire-level
    /// rejection.
    #[test]
    fn signed_run_metadata_rejects_malformed_fingerprint() {
        let mut value: serde_json::Value =
            serde_json::to_value(sample_signed_run_metadata()).unwrap();
        value["signing_key_fingerprint"] = serde_json::Value::String("MD5:abc".into());
        let err = serde_json::from_value::<SignedRunMetadata>(value).unwrap_err();
        assert!(
            err.to_string().contains("SHA256:"),
            "expected fingerprint error, got: {err}",
        );
    }

    /// And likewise for the signature: a missing PEM framing marker
    /// is a wire-level rejection.
    #[test]
    fn run_agent_completed_rejects_malformed_signature() {
        let mut value: serde_json::Value = serde_json::to_value(ServerMessage::RunAgentCompleted {
            output_oid: sample_object_id('c'),
            signed_metadata: sample_signed_run_metadata(),
            signature: sample_ssh_signature(),
        })
        .unwrap();
        value["signature"] = serde_json::Value::String("not a pem block".into());
        let err = serde_json::from_value::<ServerMessage>(value).unwrap_err();
        assert!(
            err.to_string().contains("BEGIN SSH SIGNATURE")
                || err.to_string().contains("END SSH SIGNATURE"),
            "expected signature error, got: {err}",
        );
    }

    /// `canonical_bytes` is the contract the signature covers. A
    /// round-trip through `serde_json` (serialise → parse → serialise
    /// again via `canonical_bytes`) must reproduce the same bytes,
    /// otherwise a verifier deserialising the wire form and
    /// re-canonicalising would compute a different digest and reject
    /// a valid signature.
    #[test]
    fn signed_run_metadata_canonical_bytes_roundtrip_is_stable() {
        let meta = sample_signed_run_metadata();
        let first = meta.canonical_bytes();
        let parsed: SignedRunMetadata = serde_json::from_slice(&first).unwrap();
        let second = parsed.canonical_bytes();
        assert_eq!(first, second);
    }

    /// Pin the literal canonical byte sequence: a compact JSON object
    /// (no whitespace) with the eight keys in struct-declaration order.
    /// A reviewer reading this string sees exactly what the verifier
    /// must reproduce. Any reordering of fields in `SignedRunMetadata`
    /// or any switch to a different serialiser would break this.
    #[test]
    fn signed_run_metadata_canonical_bytes_pin_field_order() {
        let meta = sample_signed_run_metadata();
        let bytes = meta.canonical_bytes();
        let s = std::str::from_utf8(&bytes).unwrap();
        let expected = format!(
            "{{\"run_id\":\"{}\",\"session_id\":\"{}\",\
             \"prompt_sha256\":\"{}\",\"output_envelope_sha256\":\"{}\",\
             \"capabilities\":[{{\"kind\":\"workspace_read\",\"repo\":\"o/n\"}}],\
             \"exit_code\":0,\"completed_at\":1700000000000,\
             \"signing_key_fingerprint\":\"{}\"}}",
            sample_agent_run_id(),
            fixed_session_id(),
            sample_sha256_hex('a').as_str(),
            sample_sha256_hex('b').as_str(),
            sample_ssh_fingerprint().as_str(),
        );
        assert_eq!(s, expected);
    }

    /// Different metadata produces different canonical bytes — a basic
    /// distinctness check so a regression that collapses every payload
    /// to the same bytes (e.g. accidentally serialising a constant)
    /// surfaces immediately.
    #[test]
    fn signed_run_metadata_canonical_bytes_distinguish_distinct_payloads() {
        let a = sample_signed_run_metadata();
        let mut b = sample_signed_run_metadata();
        b.exit_code = 1;
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    /// `run_agent_completed` must carry its own type tag so a client
    /// dispatching on `type` distinguishes it from a generic
    /// internal-failure `Error` without parsing the message string.
    #[test]
    fn run_agent_completed_distinct_from_error() {
        let completed: serde_json::Value = serde_json::to_value(ServerMessage::RunAgentCompleted {
            output_oid: sample_object_id('c'),
            signed_metadata: sample_signed_run_metadata(),
            signature: sample_ssh_signature(),
        })
        .unwrap();
        let error: serde_json::Value = serde_json::to_value(ServerMessage::Error {
            message: "internal".into(),
        })
        .unwrap();
        assert_ne!(completed["type"], error["type"]);
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
            correlation_id: None,
        })
        .unwrap();
        assert_eq!(run["type"], "start_agent_run");

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
            correlation_id: None,
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
                "correlation_id",
                "request_id", "reason", "operator",
                "outcome",
                "capabilities", "purpose", "output_ref",
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
                correlation_id: None,
            },
            5 => ClientMessage::StopAgentVm {
                session_id: fixed_session_id(),
            },
            6 => ClientMessage::ListAgentVms {},
            7 => ClientMessage::ListStagedPushes { session_id: None },
            8 => ClientMessage::ShowStagedPush {
                request_id: "12345678-1234-1234-1234-123456789012".parse().unwrap(),
            },
            9 => ClientMessage::RejectStagedPush {
                request_id: "12345678-1234-1234-1234-123456789012".parse().unwrap(),
                operator: "alice".into(),
                reason: RejectionReason::try_new("leaks credentials").unwrap(),
            },
            10 => ClientMessage::RunAgent {
                prompt: AgentPrompt::new("hello"),
                capabilities: vec![CapabilitySet::WorkspaceRead {
                    repo: sample_repo(),
                }],
                purpose: "plan-stage".into(),
                output_ref: NotesRef::try_new("refs/notes/writ/agent-outputs").unwrap(),
                session_id: Some(fixed_session_id()),
                workspace: None,
                agent_kind: None,
                agent_model: None,
            },
            11 => ClientMessage::ApproveStagedPush {
                request_id: "12345678-1234-1234-1234-123456789012".parse().unwrap(),
                operator: "alice".into(),
            },
            12 => ClientMessage::ReconcileStagedPush {
                request_id: "12345678-1234-1234-1234-123456789012".parse().unwrap(),
                operator: "alice".into(),
                outcome: ReconcileOutcome::Applied {
                    new_app_tip: sample_object_id('c'),
                    reason: "verified".into(),
                },
            },
            other => unreachable!("variant index out of range: {other}"),
        }
    }
}
