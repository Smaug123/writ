//! Wire protocol types for the writ Unix-socket interface.
//!
//! Every connection is a sequence of newline-terminated JSON lines.
//! The client sends one [`ClientMessage`] per line; the broker replies
//! with one [`ServerMessage`] per line. No multiplexing, no framing
//! beyond the newline.
//!
//! The **first** line on every connection is a [`ClientMessage::Hello`]
//! declaring [`HOST_PROTOCOL_VERSION`], and the broker refuses the connection
//! before dispatching anything if it does not arrive or does not match. See
//! that constant for why, and `server::handshake` for the rule.
//!
//! These types are thin wrappers over the core domain types: the
//! [`CapabilityRequest`] a client sends is exactly the struct the
//! policy engine consumes, and [`SessionId`]/[`UnixMillis`] are the
//! same values that land in the audit log. No translation layer.

use serde::{Deserialize, Serialize};

use crate::agent_run::{AgentPrompt, AgentRunId, CorrelationId, RunPurpose};
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

/// The version of the host Unix-socket protocol this build speaks, declared by
/// the client in [`ClientMessage::Hello`] and checked by the broker before it
/// dispatches anything.
///
/// **Bump this on any change to the serialized shape of [`ClientMessage`] or
/// [`ServerMessage`]**: a renamed or added variant, an added or removed field,
/// a changed meaning. The rule has no "but this one is backwards-compatible"
/// exception, and the reason is specific to these two types rather than a
/// general caution.
///
/// The tempting exception — "an optional field with `#[serde(default)]` is free,
/// since both sides parse both shapes" — is **false here**. `ClientMessage`
/// carries `#[serde(deny_unknown_fields)]`, so the moment a newer client
/// actually emits that field, an older daemon rejects the whole message. And it
/// would reject it *after* accepting the handshake, because the version did not
/// move — which is precisely the skew this constant exists to catch, arrived at
/// by reasoning that sounds conservative. `skip_serializing_if` narrows the
/// window to callers who set the field; it does not close it.
///
/// So: if the bytes on the wire can differ, bump. Renaming `AgentRunStarted` to
/// `AgentRunAccepted`, as #21 did, is the obvious case; adding an optional field
/// to `RunAgent` is the non-obvious one, and it counts too.
///
/// ## What this buys, stated exactly
///
/// It is an **exact-match assertion**, not a negotiation of a common subset.
/// `writ` and `writd` are one build from one repo, so there is no supported
/// skew to negotiate — the only question worth asking is "are these the same
/// build?", and the only useful answer to "no" is to stop.
///
/// The skew it exists for is operational rather than contractual: leaving a
/// daemon running across an upgrade is an ordinary thing to do on a dev
/// machine. Before this, the two directions failed differently and one failed
/// silently:
///
/// * **Old client, new daemon.** The request still decoded, so the daemon
///   *acted* — and then wrote a reply variant the client could not parse. A
///   `StartAgentRun` booted a VM the caller never learned the name of,
///   recoverable only through `writ agent-vm list`. This is the case the
///   handshake actually fixes: the daemon now refuses a connection that
///   declares no version, before dispatching.
/// * **New client, old daemon.** The old daemon cannot parse `Hello` at all
///   (an unknown `type` tag is a deserialization error) and answers
///   [`ServerMessage::Error`], which every version has always understood. The
///   client stops there. This is why the client must **not** pipeline its
///   request behind the `Hello`: an old daemon processes lines in order, so a
///   pipelined request would be dispatched by the very daemon that just
///   refused the handshake. One extra round trip on a Unix socket is the price
///   of that, and it is not a price worth haggling over.
///
/// ## The honest limit
///
/// This protects the *next* breaking change, not the one already shipped. An
/// old `writ` binary does not send a `Hello` and never will; what changes is
/// that it is now refused cleanly instead of being served half an operation.
///
/// Version 1 is the first that says its own number. There is no version 0: a
/// connection that declares nothing is not "version 0", it is a client that
/// predates the handshake, and the broker says exactly that.
///
/// This is the third versioned boundary in writ, alongside
/// [`BROKER_PROTOCOL_VERSION`](crate::broker_protocol::BROKER_PROTOCOL_VERSION)
/// on the broker VM's ready file and
/// [`VM_HTTP_CONTRACT_VERSION`](writ_vm_git::VM_HTTP_CONTRACT_VERSION) on the
/// guest HTTP surface.
pub const HOST_PROTOCOL_VERSION: u32 = 1;

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
    /// Declare the protocol version this client speaks. Must be the **first**
    /// message on every connection; the broker dispatches nothing until it has
    /// arrived and matched [`HOST_PROTOCOL_VERSION`].
    ///
    /// Answered with [`ServerMessage::HelloAccepted`], or with
    /// [`ServerMessage::Error`] and a closed connection.
    Hello { protocol_version: u32 },
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
    /// Ask writ whether its audit log corroborates a signed run note.
    ///
    /// `verify_run_envelope` proves a note is internally consistent and
    /// signed by a trusted key — both facts drawn from the note itself. It
    /// cannot say whether writ ever ran the thing the note describes, because
    /// only the daemon holds the audit database and the stream files. This
    /// asks it.
    ///
    /// Only the metadata and its signature cross the wire, never the output
    /// bytes: `metadata.output_envelope_sha256` already binds them, and writd
    /// re-derives that digest from the stream files its own outcome row names.
    /// So the request stays a few hundred bytes however large the run's output
    /// was, and the output side of the comparison is writ checking its own
    /// files rather than trusting the caller's copy of them.
    VerifyAgentRun {
        signed_metadata: SignedRunMetadata,
        signature: SshSignature,
    },
    RunAgent {
        /// Prompt delivered verbatim to the spawned agent's stdin.
        /// Writ forwards the bytes but does not store, persist, or
        /// interpret them — the audit row records only the hash.
        prompt: AgentPrompt,
        /// Authority granted to this run. Each variant maps to a
        /// `policy::*` oracle check at request time. Stored as a
        /// canonical collection on the audit row.
        capabilities: Vec<CapabilitySet>,
        /// Caller-supplied opaque tag recorded verbatim on the
        /// `agent_run` audit row. Writ never interprets the contents for
        /// policy; bailiff uses it to reconcile the writ-side run with
        /// its own workflow vocabulary (e.g. `"plan-stage"`,
        /// `"review:plan-abc"`).
        ///
        /// Writ does *parse* it, as a bounded printable-ASCII tag — see
        /// [`RunPurpose`] for why an audit column that can never be
        /// corrected does not accept arbitrary bytes.
        purpose: RunPurpose,
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
    /// Acknowledges [`ClientMessage::Hello`]: the client's declared version
    /// matched, and the connection may now carry requests.
    ///
    /// `protocol_version` is the broker's own, and equals the client's by
    /// construction — the broker accepts nothing else. It is echoed anyway so
    /// a client that logs the handshake records what it actually agreed with,
    /// rather than what it assumed.
    ///
    /// Safe to add as a new variant, unlike a refusal: only a client that sent
    /// `Hello` can receive this, and any client new enough to send one is new
    /// enough to know the reply. A *refusal* has the opposite property, which
    /// is why refusals are [`Self::Error`].
    HelloAccepted { protocol_version: u32 },
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
    /// A product-level agent run was accepted. It is *not* running yet: writd
    /// answers here so that the caller holds the run's names before the slow
    /// part — queueing, workspace bootstrap, VM boot — begins, and can therefore
    /// stop it whatever happens next.
    ///
    /// Nothing is recorded under `session_id` until the run actually starts, so
    /// while writd is up a lookup that finds nothing means "not started yet".
    /// That is *not* a durability promise, and the difference matters: an
    /// accepted run lives only in the daemon's memory until it starts, so a
    /// writd that exits while it is queued discards it, and both ids then name
    /// nothing at all. Consistent with what a restart does to runs that *had*
    /// started — boot reconciliation tears every persisted agent VM down — but
    /// it means a caller cannot read "not found" as "still coming" across a
    /// daemon it did not watch stay up.
    ///
    /// The prompt itself is not returned; `run_id` is the stable handle used by
    /// the VM prompt/log contract. No `broker_url`, unlike
    /// [`Self::AgentVmStarted`]: there is no VM yet to have one.
    AgentRunAccepted {
        session_id: SessionId,
        run_id: AgentRunId,
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
    /// Answer to [`ClientMessage::VerifyAgentRun`]: what writ's own audit log
    /// says about a signed note presented to it.
    ///
    /// One variant for every shape of answer, so a caller matches
    /// exhaustively rather than reading a bag of optional fields — and so
    /// "no such run" cannot be mistaken for "nothing wrong found".
    AgentRunProvenance {
        verdict: crate::run_provenance::RunProvenanceVerdict,
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
            Self::HelloAccepted { protocol_version } => f
                .debug_struct("HelloAccepted")
                .field("protocol_version", protocol_version)
                .finish(),
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
            Self::AgentRunAccepted { session_id, run_id } => f
                .debug_struct("AgentRunAccepted")
                .field("session_id", session_id)
                .field("run_id", run_id)
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
            Self::AgentRunProvenance { verdict } => f
                .debug_struct("AgentRunProvenance")
                .field("verdict", verdict)
                .finish(),
            Self::Error { message } => f.debug_struct("Error").field("message", message).finish(),
        }
    }
}

#[cfg(test)]
mod tests;
