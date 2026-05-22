//! Pure data types and pure functions for the agent plan/review/decision
//! lifecycle. See `docs/plans/2026-05-11-agent-plans.md` for the design.
//!
//! This module mirrors `agent_run.rs`: parse-don't-validate newtypes,
//! exhaustive enum tags via serde, no IO, no DB binds. It defines the
//! shapes the audit layer will persist and the VM HTTP layer will speak,
//! plus the two pieces of business logic that don't need the audit DB
//! to be useful: the executor-prompt composition (§"Implementer prompt
//! construction") and the per-stage route-authorisation matrix
//! (§"Decision is the gate" / §"Protocol additions").

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

/// Largest plan body the broker will accept. Bounded so a buggy or
/// malicious planner can't drop a megabyte into one row; chosen so a
/// typical feature-request prompt plus a typical plan body fits within
/// [`crate::agent_run::MAX_AGENT_PROMPT_BYTES`] with comfortable
/// headroom for the separator and any rephrasing. Outsized plans should
/// either be split into addenda or rejected at the planner.
pub const MAX_PLAN_BODY_BYTES: usize = 256 * 1024;

/// Largest reviewer-feedback body the broker will accept. Feedback is
/// typically a few paragraphs; this bound exists to keep the row size
/// predictable, not to constrain prose.
pub const MAX_PLAN_FEEDBACK_BYTES: usize = 64 * 1024;

/// Largest hard-abort `reason` body. Aborts are one-paragraph signals,
/// not transcripts.
pub const MAX_PLAN_ABORT_REASON_BYTES: usize = 4 * 1024;

/// Largest [`Decider`] attribution string. Bounds the audit-row size for
/// the `decider` column. Deciders are short labels (e.g. `cli:alice` or
/// future `agent:<run_id>`), not prose; matches `MAX_OPERATOR_BYTES`
/// elsewhere so an operator capture of `$USER` and a `cli:` prefix
/// comfortably fit.
pub const MAX_DECIDER_BYTES: usize = 256;

/// Inclusive bounds on a [`CorrelationId`]. The lower bound rejects
/// the empty string at parse time so the audit column never has to
/// distinguish "absent" from "zero-length present".
pub const MIN_CORRELATION_ID_BYTES: usize = 1;
pub const MAX_CORRELATION_ID_BYTES: usize = 64;

/// Path prefix served by the VM HTTP plan routes. The collection
/// (`POST` to submit a plan) is exactly this; per-plan routes append
/// `/<plan_id>` and an optional suffix.
pub const VM_PLANS_PATH_PREFIX: &str = "/v1/plans";

// --- ID newtypes ------------------------------------------------------
//
// The audit layer stores these as TEXT (UUID rendered lowercase
// hyphenated) and the wire renders them transparently. Construction is
// explicit so a fresh ID never leaks in by accident — same shape as
// `AgentRunId`.

macro_rules! plan_uuid_id {
    ($(#[$meta:meta])* $name:ident, $debug_label:literal) => {
        $(#[$meta])*
        #[derive(Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[allow(clippy::new_without_default)]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            pub fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($debug_label, "({})"), self.0)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;
            fn from_str(raw: &str) -> Result<Self, Self::Err> {
                Ok(Self(Uuid::parse_str(raw)?))
            }
        }
    };
}

plan_uuid_id!(
    /// Identifies one submitted plan. Stable across reviews, the
    /// decision, addenda, and abort signals — every event downstream
    /// of a plan submission references the same `PlanId`.
    PlanId,
    "PlanId"
);

plan_uuid_id!(
    /// Identifies one reviewer verdict row.
    ReviewId,
    "ReviewId"
);

plan_uuid_id!(
    /// Identifies one execute-stage addendum to an accepted plan.
    AddendumId,
    "AddendumId"
);

// --- CorrelationId ----------------------------------------------------

/// Opaque caller-supplied identifier tying related agent runs and git
/// pushes together. Per the design (§"Correlation ID"), the broker
/// validates only as a safe id — bounded length, restricted character
/// class — and never interprets the contents. The upstream
/// orchestrator (today: a human; later: a separate agent) decides what
/// the id means.
///
/// Character class is `[A-Za-z0-9_-]` and length is
/// [`MIN_CORRELATION_ID_BYTES`]..=[`MAX_CORRELATION_ID_BYTES`]. The
/// class is deliberately narrow: no dots, slashes, or colons — that
/// way a correlation id cannot pose as a path segment or scheme
/// component if it ever leaks into a URL.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CorrelationId(String);

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CorrelationIdError {
    #[error(
        "correlation id must be {min}..={max} bytes; got {got}",
        min = MIN_CORRELATION_ID_BYTES,
        max = MAX_CORRELATION_ID_BYTES,
    )]
    InvalidLength { got: usize },
    #[error("correlation id byte at offset {at} is {byte:?}; expected [A-Za-z0-9_-]")]
    InvalidByte { at: usize, byte: u8 },
}

impl CorrelationId {
    pub fn try_new(raw: impl Into<String>) -> Result<Self, CorrelationIdError> {
        let raw = raw.into();
        let len = raw.len();
        if !(MIN_CORRELATION_ID_BYTES..=MAX_CORRELATION_ID_BYTES).contains(&len) {
            return Err(CorrelationIdError::InvalidLength { got: len });
        }
        for (at, byte) in raw.bytes().enumerate() {
            let ok = byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_';
            if !ok {
                return Err(CorrelationIdError::InvalidByte { at, byte });
            }
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CorrelationId({:?})", self.0)
    }
}

impl FromStr for CorrelationId {
    type Err = CorrelationIdError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::try_new(raw)
    }
}

impl Serialize for CorrelationId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CorrelationId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

// --- Bounded text bodies ---------------------------------------------

/// Markdown body of one plan submission. Non-empty, at most
/// [`MAX_PLAN_BODY_BYTES`]. Treated as opaque text by the broker; the
/// audit row stores both the raw body and a sha256 digest so future
/// queries can join "what was reviewed" to "what was executed against"
/// without re-reading the column.
#[derive(Clone, Eq, PartialEq)]
pub struct PlanBody(String);

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PlanBodyError {
    #[error("plan body must not be empty")]
    Empty,
    #[error("plan body is {byte_len} bytes, exceeding the {max_bytes}-byte limit")]
    TooLarge { byte_len: usize, max_bytes: usize },
    #[error("plan body contains an embedded NUL byte")]
    EmbeddedNul,
}

impl PlanBody {
    pub fn try_new(body: impl Into<String>) -> Result<Self, PlanBodyError> {
        let body = body.into();
        if body.is_empty() {
            return Err(PlanBodyError::Empty);
        }
        if body.len() > MAX_PLAN_BODY_BYTES {
            return Err(PlanBodyError::TooLarge {
                byte_len: body.len(),
                max_bytes: MAX_PLAN_BODY_BYTES,
            });
        }
        // Mirror the audit-schema CHECK on `plan.body`: an embedded NUL
        // is a parse error at the boundary, not a SQLite CHECK failure
        // surfaced from inside the DAO. Plan bodies are Markdown prose,
        // so a NUL is never anyone's intent; rejecting at the typed
        // boundary means downstream code can rely on the invariant
        // without re-checking.
        if body.as_bytes().contains(&0) {
            return Err(PlanBodyError::EmbeddedNul);
        }
        Ok(Self(body))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn byte_len(&self) -> u64 {
        self.0.len() as u64
    }

    /// Hex sha256 of the body bytes. Matches the
    /// `plan.body_sha256` audit column shape. Gated on the same
    /// features as [`crate::agent_run::sha256_hex`] because it
    /// piggybacks on the same dependency.
    #[cfg(any(feature = "host", feature = "vm-client"))]
    pub fn sha256_hex(&self) -> String {
        crate::agent_run::sha256_hex(self.as_bytes())
    }
}

impl fmt::Debug for PlanBody {
    // Plan bodies aren't secret, but they're large; an unredacted Debug
    // would spam tracing spans and logs. The byte_len is plenty for
    // observability; `as_str` gets the content when callers actually
    // want it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlanBody")
            .field("byte_len", &self.byte_len())
            .finish()
    }
}

impl Serialize for PlanBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PlanBody {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

/// Reviewer-supplied feedback prose. Non-empty when present at all;
/// the wire and DB shape is `Option<PlanFeedback>` so "no feedback"
/// remains distinct from "empty feedback string".
#[derive(Clone, Eq, PartialEq)]
pub struct PlanFeedback(String);

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PlanFeedbackError {
    #[error("plan feedback must not be empty")]
    Empty,
    #[error("plan feedback is {byte_len} bytes, exceeding the {max_bytes}-byte limit")]
    TooLarge { byte_len: usize, max_bytes: usize },
    #[error("plan feedback contains an embedded NUL byte")]
    EmbeddedNul,
}

impl PlanFeedback {
    pub fn try_new(body: impl Into<String>) -> Result<Self, PlanFeedbackError> {
        let body = body.into();
        if body.is_empty() {
            return Err(PlanFeedbackError::Empty);
        }
        if body.len() > MAX_PLAN_FEEDBACK_BYTES {
            return Err(PlanFeedbackError::TooLarge {
                byte_len: body.len(),
                max_bytes: MAX_PLAN_FEEDBACK_BYTES,
            });
        }
        // Mirror the audit-schema CHECK on `plan_review.feedback`: an
        // embedded NUL is a parse error at the boundary, not a SQLite
        // CHECK error surfaced from inside the DAO. Reviewer prose is
        // free-text Markdown, so a NUL is never anyone's intent;
        // rejecting at the typed boundary lets the DAO assume the
        // invariant.
        if body.as_bytes().contains(&0) {
            return Err(PlanFeedbackError::EmbeddedNul);
        }
        Ok(Self(body))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn byte_len(&self) -> u64 {
        self.0.len() as u64
    }

    #[cfg(any(feature = "host", feature = "vm-client"))]
    pub fn sha256_hex(&self) -> String {
        crate::agent_run::sha256_hex(self.as_bytes())
    }
}

impl fmt::Debug for PlanFeedback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlanFeedback")
            .field("byte_len", &self.byte_len())
            .finish()
    }
}

impl Serialize for PlanFeedback {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PlanFeedback {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

/// Implementer-supplied reason on a hard-abort. Non-empty, bounded.
/// Per the design (§"Decisions taken" item 9) this is a distinct
/// protocol message rather than overloading a non-zero exit, so the
/// reason text is part of the contract.
#[derive(Clone, Eq, PartialEq)]
pub struct PlanAbortReason(String);

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PlanAbortReasonError {
    #[error("plan abort reason must not be empty")]
    Empty,
    #[error("plan abort reason is {byte_len} bytes, exceeding the {max_bytes}-byte limit")]
    TooLarge { byte_len: usize, max_bytes: usize },
    #[error("plan abort reason contains an embedded NUL byte")]
    EmbeddedNul,
}

impl PlanAbortReason {
    pub fn try_new(reason: impl Into<String>) -> Result<Self, PlanAbortReasonError> {
        let reason = reason.into();
        if reason.is_empty() {
            return Err(PlanAbortReasonError::Empty);
        }
        if reason.len() > MAX_PLAN_ABORT_REASON_BYTES {
            return Err(PlanAbortReasonError::TooLarge {
                byte_len: reason.len(),
                max_bytes: MAX_PLAN_ABORT_REASON_BYTES,
            });
        }
        // Mirror the audit-schema CHECK on `plan_abort.reason`: an
        // embedded NUL is a parse error at the boundary, not a SQLite
        // CHECK failure surfaced from inside the DAO. Aborts are
        // free-text prose, so a NUL is never anyone's intent;
        // rejecting at the typed boundary lets the DAO assume the
        // invariant.
        if reason.as_bytes().contains(&0) {
            return Err(PlanAbortReasonError::EmbeddedNul);
        }
        Ok(Self(reason))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn byte_len(&self) -> u64 {
        self.0.len() as u64
    }
}

impl fmt::Debug for PlanAbortReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlanAbortReason")
            .field("byte_len", &self.byte_len())
            .finish()
    }
}

impl Serialize for PlanAbortReason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PlanAbortReason {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

// --- Closed enums -----------------------------------------------------

/// Role of one agent run in the plan/review/decide/execute pipeline.
/// Carried on `agent_run.stage` (per the design's audit-log additions)
/// and used by [`route_permitted_by_stage_and_decision`] to gate the
/// plan-related VM HTTP routes.
///
/// If you add a variant, add a matching audit migration: the
/// `agent_run.stage` column has a SQLite CHECK constraint enumerating
/// the accepted wire strings.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Plan,
    Review,
    Execute,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Review => "review",
            Self::Execute => "execute",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("unknown stage {0:?}; expected plan, review, or execute")]
pub struct StageParseError(String);

impl FromStr for Stage {
    type Err = StageParseError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "plan" => Ok(Self::Plan),
            "review" => Ok(Self::Review),
            "execute" => Ok(Self::Execute),
            _ => Err(StageParseError(raw.to_string())),
        }
    }
}

/// Reviewer verdict on a plan. `RequestChanges` and `Reject` are
/// distinct so the operator can tell "the reviewer wants iteration"
/// apart from "the reviewer thinks the work shouldn't happen".
///
/// If you add a variant, add a matching audit migration: the
/// `plan_review.verdict` column has a SQLite CHECK constraint
/// enumerating the accepted wire strings.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Approve,
    RequestChanges,
    Reject,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::RequestChanges => "request_changes",
            Self::Reject => "reject",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("unknown verdict {0:?}; expected approve, request_changes, or reject")]
pub struct VerdictParseError(String);

impl FromStr for Verdict {
    type Err = VerdictParseError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "approve" => Ok(Self::Approve),
            "request_changes" => Ok(Self::RequestChanges),
            "reject" => Ok(Self::Reject),
            _ => Err(VerdictParseError(raw.to_string())),
        }
    }
}

/// Terminal outcome of a plan after the operator decides. Per the
/// design (§"Plan lifecycle"), exactly one `plan_decision` row exists
/// per plan; `Accepted` unlocks the implementer, `RejectedRestart`
/// closes this plan and signals "if you want this work done, start a
/// new task" — the broker does nothing automatic.
///
/// If you add a variant, add a matching audit migration: the
/// `plan_decision.outcome` column has a SQLite CHECK constraint
/// enumerating the accepted wire strings.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    Accepted,
    RejectedRestart,
}

impl DecisionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::RejectedRestart => "rejected_restart",
        }
    }
}

impl fmt::Display for DecisionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("unknown decision outcome {0:?}; expected accepted or rejected_restart")]
pub struct DecisionOutcomeParseError(String);

impl FromStr for DecisionOutcome {
    type Err = DecisionOutcomeParseError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "accepted" => Ok(Self::Accepted),
            "rejected_restart" => Ok(Self::RejectedRestart),
            _ => Err(DecisionOutcomeParseError(raw.to_string())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DeciderError {
    #[error("decider must not be empty")]
    Empty,
    #[error("decider is {byte_len} bytes, exceeding the {max_bytes}-byte limit")]
    TooLong { byte_len: usize, max_bytes: usize },
    #[error("decider contains an embedded NUL byte")]
    EmbeddedNul,
}

/// Free-form attribution recorded against a [`DecisionView`]: who (or
/// what) the operator surface says made the call. Per §"Plan lifecycle",
/// today the host CLI writes `cli:<user>`; a future orchestrator agent
/// will write `agent:<run_id>`. The broker treats the string as opaque
/// and stores it verbatim, but parses at the wire boundary so the audit
/// row's CHECK constraint can never see an invalid value.
///
/// Invariants:
/// - non-empty
/// - byte length ≤ [`MAX_DECIDER_BYTES`]
/// - no embedded NUL (`length()` on a SQLite TEXT walks bytes as a C
///   string and would silently truncate at the first NUL, so the audit
///   CHECK rejects them — the newtype rejects them up-front for a
///   typed error).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decider(String);

impl Decider {
    pub fn try_new(decider: impl Into<String>) -> Result<Self, DeciderError> {
        let decider = decider.into();
        if decider.is_empty() {
            return Err(DeciderError::Empty);
        }
        if decider.len() > MAX_DECIDER_BYTES {
            return Err(DeciderError::TooLong {
                byte_len: decider.len(),
                max_bytes: MAX_DECIDER_BYTES,
            });
        }
        if decider.as_bytes().contains(&0) {
            return Err(DeciderError::EmbeddedNul);
        }
        Ok(Self(decider))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Decider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Decider {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Decider {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

// Prompt composition for executor / reviewer runs lives in the
// bailiff workflow modules ([`crate::bailiff_plan_implement`] and
// [`crate::bailiff_plan_review`]). The broker persists [`PlanBody`]
// and [`Stage`] but does not splice them.

// --- Route authorisation matrix --------------------------------------

/// One protected route in the plan-related VM HTTP surface (see
/// §"Protocol additions"). Used as input to
/// [`route_permitted_by_stage_and_decision`].
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum PlanRouteAction {
    /// `POST /v1/plans` — a planner submits a plan body.
    SubmitPlan,
    /// `GET /v1/plans/<plan_id>` — a reviewer or implementer reads
    /// the plan body.
    ReadPlan,
    /// `POST /v1/plans/<plan_id>/reviews` — a reviewer attaches a
    /// verdict.
    SubmitReview,
    /// `POST /v1/plans/<plan_id>/addenda` — an implementer appends
    /// an addendum after the plan was accepted.
    SubmitAddendum,
    /// `POST /v1/plans/<plan_id>/abort` — an implementer signals a
    /// hard-abort.
    SubmitAbort,
}

impl PlanRouteAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubmitPlan => "submit_plan",
            Self::ReadPlan => "read_plan",
            Self::SubmitReview => "submit_review",
            Self::SubmitAddendum => "submit_addendum",
            Self::SubmitAbort => "submit_abort",
        }
    }
}

impl fmt::Display for PlanRouteAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PlanRouteAuthError {
    #[error("stage {stage} is not permitted to {action}")]
    StageNotPermitted {
        stage: Stage,
        action: PlanRouteAction,
    },
    /// The plan-level decision gate hasn't admitted this action. The
    /// only outcome that admits is `Accepted`; both "no decision row
    /// yet" and `RejectedRestart` are denials.
    #[error(
        "{action} requires the plan decision to be accepted; current: {decision}",
        decision = display_decision_opt(*decision)
    )]
    DecisionNotAccepted {
        action: PlanRouteAction,
        decision: Option<DecisionOutcome>,
    },
}

fn display_decision_opt(d: Option<DecisionOutcome>) -> String {
    match d {
        None => "no decision recorded".to_string(),
        Some(o) => format!("{o}"),
    }
}

/// The pure stage→action gate enforced on every plan-related VM HTTP
/// route. Returns `Ok(())` exactly when the spec in §"Protocol
/// additions" allows the action.
///
/// Inputs the function does *not* take, because they require a DB
/// lookup the caller must do separately:
/// - whether the requesting run is bound to the target plan
///   (`agent_run.read_plan_id = <plan_id>` for `ReadPlan`,
///   `SubmitReview`, `SubmitAddendum`, `SubmitAbort`);
/// - whether the planner has already submitted a plan in this run
///   (uniqueness of `plan.agent_run_id` for `SubmitPlan`).
///
/// These are audit-row checks; this function is the part of the gate
/// that depends only on stable enum-valued inputs and can therefore
/// be exhaustively property-tested.
pub fn route_permitted_by_stage_and_decision(
    action: PlanRouteAction,
    stage: Stage,
    decision: Option<DecisionOutcome>,
) -> Result<(), PlanRouteAuthError> {
    let stage_ok = match (action, stage) {
        (PlanRouteAction::SubmitPlan, Stage::Plan) => true,
        (PlanRouteAction::SubmitPlan, _) => false,

        (PlanRouteAction::ReadPlan, Stage::Review | Stage::Execute) => true,
        (PlanRouteAction::ReadPlan, _) => false,

        (PlanRouteAction::SubmitReview, Stage::Review) => true,
        (PlanRouteAction::SubmitReview, _) => false,

        (PlanRouteAction::SubmitAddendum, Stage::Execute) => true,
        (PlanRouteAction::SubmitAddendum, _) => false,

        (PlanRouteAction::SubmitAbort, Stage::Execute) => true,
        (PlanRouteAction::SubmitAbort, _) => false,
    };
    if !stage_ok {
        return Err(PlanRouteAuthError::StageNotPermitted { stage, action });
    }

    // Acceptance gate. From the spec:
    //   - GET /v1/plans/<id> with stage=execute requires accepted decision
    //   - POST /v1/plans/<id>/addenda requires accepted decision
    //   - All other route+stage combinations skip the acceptance check
    //     (planner submits without a decision; reviewer reads/votes
    //     without a decision; execute-stage abort doesn't gate again
    //     because the run already implies acceptance to be running at
    //     all, and the spec deliberately omits the check there).
    let requires_acceptance = matches!(
        (action, stage),
        (PlanRouteAction::ReadPlan, Stage::Execute)
            | (PlanRouteAction::SubmitAddendum, Stage::Execute),
    );
    if requires_acceptance && decision != Some(DecisionOutcome::Accepted) {
        return Err(PlanRouteAuthError::DecisionNotAccepted { action, decision });
    }
    Ok(())
}

// --- VM HTTP path constructors ---------------------------------------

pub fn vm_plans_collection_path() -> &'static str {
    VM_PLANS_PATH_PREFIX
}

pub fn vm_plan_path(plan_id: PlanId) -> String {
    format!("{VM_PLANS_PATH_PREFIX}/{plan_id}")
}

pub fn vm_plan_reviews_path(plan_id: PlanId) -> String {
    format!("{VM_PLANS_PATH_PREFIX}/{plan_id}/reviews")
}

pub fn vm_plan_addenda_path(plan_id: PlanId) -> String {
    format!("{VM_PLANS_PATH_PREFIX}/{plan_id}/addenda")
}

pub fn vm_plan_abort_path(plan_id: PlanId) -> String {
    format!("{VM_PLANS_PATH_PREFIX}/{plan_id}/abort")
}

// --- VM HTTP wire-format types ---------------------------------------
//
// Symmetric Serialize/Deserialize with `deny_unknown_fields`. Both
// directions cross only between the broker and `writ-vm` (its trusted
// guest CLI), but the strictness pins typos at parse time rather than
// silently dropping fields — matches the rest of the protocol.

/// `POST /v1/plans` request body.
///
/// `agent_run_id` names the originating planner run. The VM-side CLI
/// already knows its run id from the
/// `/v1/agent-runs/{id}/config` handshake that started it, so passing it
/// back is a natural extension of the existing in-VM identifier flow.
/// The broker verifies the run belongs to the calling session before
/// persisting the plan: that closes the cross-session window where one
/// VM's bearer could otherwise attach a plan to another VM's run. The
/// stage-level check (`run.stage = 'plan'`) lands in slice 3 once the
/// `agent_run.stage` column exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSubmission {
    pub agent_run_id: crate::agent_run::AgentRunId,
    pub body: PlanBody,
}

/// `POST /v1/plans` response body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanCreated {
    pub plan_id: PlanId,
}

/// `POST /v1/plans/<plan_id>/reviews` request body.
///
/// `agent_run_id` names the reviewer run posting the verdict.
/// Mirrors the explicit-identification pattern from
/// [`PlanSubmission`]: the VM-side CLI already knows its run id from
/// the `/v1/agent-runs/{id}/config` handshake that started it, so
/// passing it back is a natural extension of the existing in-VM
/// identifier flow. The broker verifies the run belongs to the
/// calling session and is bound to the plan named in the URL path
/// before persisting the review, closing the cross-session window
/// where one VM's bearer could otherwise attach a verdict to another
/// VM's reviewer run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewSubmission {
    pub agent_run_id: crate::agent_run::AgentRunId,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub feedback: Option<PlanFeedback>,
}

/// `POST /v1/plans/<plan_id>/reviews` response body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCreated {
    pub review_id: ReviewId,
}

/// `POST /v1/plans/<plan_id>/addenda` request body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddendumSubmission {
    pub body: PlanBody,
}

/// `POST /v1/plans/<plan_id>/addenda` response body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddendumCreated {
    pub addendum_id: AddendumId,
}

/// `POST /v1/plans/<plan_id>/abort` request body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortSubmission {
    pub reason: PlanAbortReason,
}

/// `POST /v1/plans/<plan_id>/abort` response body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortRecorded {
    pub aborted_at: crate::core::UnixMillis,
}

/// `GET /v1/plans/<plan_id>` response body — everything an authorised
/// reviewer or implementer needs to read about a plan. The
/// originating feature-request prompt is *not* on this struct yet:
/// slice 5 of the implementation plan settles whether the broker
/// persists it on the `plan` row or has the implementer re-receive it
/// via the CLI starting the run. Until then the wire shape is
/// minimal so clients can't depend on a value the broker can't
/// actually serve.
///
/// `decision` is always present on the wire — explicitly `null` while
/// the plan is still under review, an object once the operator has
/// decided. The spec (§"Protocol additions") declares the field as
/// `decision: { outcome, decided_at } | null`, i.e. always present;
/// see the manual `Deserialize` impl below for the matching wire-side
/// enforcement (a missing key is a wire-contract violation, not an
/// implicit `None`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlanView {
    pub plan_id: PlanId,
    pub body: PlanBody,
    pub originating_run_id: crate::agent_run::AgentRunId,
    pub decision: Option<DecisionView>,
}

const PLAN_VIEW_FIELDS: &[&str] = &["plan_id", "body", "originating_run_id", "decision"];

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum PlanViewField {
    PlanId,
    Body,
    OriginatingRunId,
    Decision,
}

struct PlanViewVisitor;

impl<'de> serde::de::Visitor<'de> for PlanViewVisitor {
    type Value = PlanView;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("struct PlanView")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        use serde::de::Error;
        let mut plan_id: Option<PlanId> = None;
        let mut body: Option<PlanBody> = None;
        let mut originating_run_id: Option<crate::agent_run::AgentRunId> = None;
        // Outer `Option` tracks key presence; inner `Option` is the
        // semantic "no decision yet". They are kept distinct so a
        // missing key is reported as a wire-contract violation rather
        // than silently coerced to `None`.
        let mut decision: Option<Option<DecisionView>> = None;
        while let Some(key) = map.next_key::<PlanViewField>()? {
            match key {
                PlanViewField::PlanId => {
                    if plan_id.is_some() {
                        return Err(A::Error::duplicate_field("plan_id"));
                    }
                    plan_id = Some(map.next_value()?);
                }
                PlanViewField::Body => {
                    if body.is_some() {
                        return Err(A::Error::duplicate_field("body"));
                    }
                    body = Some(map.next_value()?);
                }
                PlanViewField::OriginatingRunId => {
                    if originating_run_id.is_some() {
                        return Err(A::Error::duplicate_field("originating_run_id"));
                    }
                    originating_run_id = Some(map.next_value()?);
                }
                PlanViewField::Decision => {
                    if decision.is_some() {
                        return Err(A::Error::duplicate_field("decision"));
                    }
                    decision = Some(map.next_value::<Option<DecisionView>>()?);
                }
            }
        }
        Ok(PlanView {
            plan_id: plan_id.ok_or_else(|| A::Error::missing_field("plan_id"))?,
            body: body.ok_or_else(|| A::Error::missing_field("body"))?,
            originating_run_id: originating_run_id
                .ok_or_else(|| A::Error::missing_field("originating_run_id"))?,
            decision: decision.ok_or_else(|| A::Error::missing_field("decision"))?,
        })
    }
}

impl<'de> Deserialize<'de> for PlanView {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_struct("PlanView", PLAN_VIEW_FIELDS, PlanViewVisitor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionView {
    pub outcome: DecisionOutcome,
    pub decided_at: crate::core::UnixMillis,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Newtype invariants --------------------------------------------------

    #[test]
    fn correlation_id_accepts_safe_alphanumeric_underscore_dash() {
        for ok in [
            "a",
            "ABC",
            "feat-2026-05-11",
            "task_123",
            "Z9_-",
            // exactly max length
            &"a".repeat(MAX_CORRELATION_ID_BYTES),
        ] {
            let parsed = CorrelationId::try_new(ok)
                .unwrap_or_else(|e| panic!("expected {ok:?} to parse, got {e}"));
            assert_eq!(parsed.as_str(), ok);
        }
    }

    #[test]
    fn correlation_id_rejects_empty_too_long_and_bad_chars() {
        // empty
        assert!(matches!(
            CorrelationId::try_new(""),
            Err(CorrelationIdError::InvalidLength { got: 0 })
        ));
        // one over max
        let too_long = "a".repeat(MAX_CORRELATION_ID_BYTES + 1);
        assert!(matches!(
            CorrelationId::try_new(&too_long),
            Err(CorrelationIdError::InvalidLength { .. })
        ));
        // forbidden bytes — path/scheme-style separators
        for bad in [
            "foo.bar", "foo/bar", "foo:bar", "foo bar", "foo\nbar", "foo!",
        ] {
            let err = CorrelationId::try_new(bad).unwrap_err();
            assert!(
                matches!(err, CorrelationIdError::InvalidByte { .. }),
                "expected InvalidByte for {bad:?}, got {err:?}",
            );
        }
    }

    #[test]
    fn correlation_id_serde_is_bare_string_and_roundtrips() {
        let c = CorrelationId::try_new("plan-2026-05-11_42").unwrap();
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#""plan-2026-05-11_42""#);
        let back: CorrelationId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
        // invalid wire payloads are rejected on parse
        assert!(serde_json::from_str::<CorrelationId>(r#""bad/id""#).is_err());
        assert!(serde_json::from_str::<CorrelationId>(r#""""#).is_err());
    }

    #[test]
    fn plan_body_rejects_empty_and_too_large() {
        assert!(matches!(PlanBody::try_new(""), Err(PlanBodyError::Empty)));
        let too_big = "x".repeat(MAX_PLAN_BODY_BYTES + 1);
        assert!(matches!(
            PlanBody::try_new(too_big),
            Err(PlanBodyError::TooLarge { .. })
        ));
        // exactly at the limit is accepted
        let just_right = "x".repeat(MAX_PLAN_BODY_BYTES);
        assert!(PlanBody::try_new(just_right).is_ok());
    }

    /// The audit schema rejects NULs in `plan.body`; the newtype must
    /// match so callers get a typed boundary error rather than a raw
    /// SQLite CHECK violation surfaced from inside the DAO.
    #[test]
    fn plan_body_rejects_embedded_nul() {
        assert!(matches!(
            PlanBody::try_new("hi\0world"),
            Err(PlanBodyError::EmbeddedNul)
        ));
        // A wire payload with `\u0000` must also fail at the parse
        // boundary, not slip through to the DB layer.
        assert!(serde_json::from_str::<PlanBody>("\"hi\\u0000world\"").is_err());
    }

    #[test]
    fn plan_body_debug_does_not_print_content() {
        // Big plan bodies in logs are a footgun. Debug shows byte_len
        // only; callers wanting the content go through `as_str`.
        let body = PlanBody::try_new("ULTRASECRET_MARKER").unwrap();
        let debug = format!("{body:?}");
        assert!(!debug.contains("ULTRASECRET_MARKER"), "{debug}");
        assert!(debug.contains("byte_len"));
    }

    #[test]
    fn plan_body_serialises_transparently() {
        let body = PlanBody::try_new("# Plan\n\nDo a thing.").unwrap();
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(json, "\"# Plan\\n\\nDo a thing.\"");
        let back: PlanBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back, body);
        // a wire payload that violates the invariant must fail to parse
        // — i.e. the parse-don't-validate boundary is upheld.
        assert!(serde_json::from_str::<PlanBody>("\"\"").is_err());
    }

    #[test]
    fn plan_feedback_rejects_empty_and_too_large() {
        assert!(matches!(
            PlanFeedback::try_new(""),
            Err(PlanFeedbackError::Empty)
        ));
        let too_big = "x".repeat(MAX_PLAN_FEEDBACK_BYTES + 1);
        assert!(matches!(
            PlanFeedback::try_new(too_big),
            Err(PlanFeedbackError::TooLarge { .. })
        ));
    }

    /// The audit schema rejects NULs in `plan_review.feedback`; the
    /// newtype must match so a typed payload that the parse boundary
    /// would accept can never fail later with a raw SQLite CHECK error
    /// inside the DAO.
    #[test]
    fn plan_feedback_rejects_embedded_nul() {
        assert!(matches!(
            PlanFeedback::try_new("ok\0nit"),
            Err(PlanFeedbackError::EmbeddedNul)
        ));
        // A wire payload with `\u0000` must also fail at the parse
        // boundary, not slip through to the DB layer.
        assert!(serde_json::from_str::<PlanFeedback>("\"ok\\u0000nit\"").is_err());
    }

    #[test]
    fn plan_abort_reason_rejects_empty_and_too_large() {
        assert!(matches!(
            PlanAbortReason::try_new(""),
            Err(PlanAbortReasonError::Empty)
        ));
        let too_big = "x".repeat(MAX_PLAN_ABORT_REASON_BYTES + 1);
        assert!(matches!(
            PlanAbortReason::try_new(too_big),
            Err(PlanAbortReasonError::TooLarge { .. })
        ));
    }

    #[test]
    fn plan_abort_reason_rejects_embedded_nul() {
        assert!(matches!(
            PlanAbortReason::try_new("ok\0nit"),
            Err(PlanAbortReasonError::EmbeddedNul)
        ));
        // Also reject NULs that arrive via JSON `\u0000`: the parser
        // should refuse at the typed boundary, not slip through to the
        // DB CHECK.
        assert!(serde_json::from_str::<PlanAbortReason>("\"ok\\u0000nit\"").is_err());
    }

    // --- Closed enums --------------------------------------------------------

    #[test]
    fn stage_roundtrips_as_stable_wire_string() {
        for (stage, wire) in [
            (Stage::Plan, "plan"),
            (Stage::Review, "review"),
            (Stage::Execute, "execute"),
        ] {
            assert_eq!(stage.as_str(), wire);
            assert_eq!(stage.to_string(), wire);
            assert_eq!(wire.parse::<Stage>().unwrap(), stage);
            assert_eq!(
                serde_json::to_string(&stage).unwrap(),
                format!("\"{wire}\""),
            );
            let back: Stage = serde_json::from_str(&format!("\"{wire}\"")).unwrap();
            assert_eq!(back, stage);
        }
        assert!("planner".parse::<Stage>().is_err());
        assert!("PLAN".parse::<Stage>().is_err());
        assert!(serde_json::from_str::<Stage>(r#""planner""#).is_err());
    }

    #[test]
    fn verdict_roundtrips_as_stable_wire_string() {
        for (verdict, wire) in [
            (Verdict::Approve, "approve"),
            (Verdict::RequestChanges, "request_changes"),
            (Verdict::Reject, "reject"),
        ] {
            assert_eq!(verdict.as_str(), wire);
            assert_eq!(wire.parse::<Verdict>().unwrap(), verdict);
            assert_eq!(
                serde_json::to_string(&verdict).unwrap(),
                format!("\"{wire}\""),
            );
            let back: Verdict = serde_json::from_str(&format!("\"{wire}\"")).unwrap();
            assert_eq!(back, verdict);
        }
        assert!("requestChanges".parse::<Verdict>().is_err());
    }

    #[test]
    fn decision_outcome_roundtrips_as_stable_wire_string() {
        for (outcome, wire) in [
            (DecisionOutcome::Accepted, "accepted"),
            (DecisionOutcome::RejectedRestart, "rejected_restart"),
        ] {
            assert_eq!(outcome.as_str(), wire);
            assert_eq!(wire.parse::<DecisionOutcome>().unwrap(), outcome);
            assert_eq!(
                serde_json::to_string(&outcome).unwrap(),
                format!("\"{wire}\""),
            );
        }
        assert!("rejected".parse::<DecisionOutcome>().is_err());
    }

    // --- Decider newtype ----------------------------------------------------

    #[test]
    fn decider_accepts_typical_attribution_strings() {
        for ok in [
            "cli:alice",
            "cli:unknown",
            "agent:6f7c3e1f-1c5e-4b1d-9b6c-1f1c2b3d4e5f",
            "a",
            &"x".repeat(MAX_DECIDER_BYTES),
        ] {
            let parsed = Decider::try_new(ok)
                .unwrap_or_else(|e| panic!("expected {ok:?} to parse, got {e}"));
            assert_eq!(parsed.as_str(), ok);
        }
    }

    #[test]
    fn decider_rejects_empty_too_long_and_embedded_nul() {
        assert!(matches!(Decider::try_new(""), Err(DeciderError::Empty)));
        let oversize = "x".repeat(MAX_DECIDER_BYTES + 1);
        assert!(matches!(
            Decider::try_new(&oversize),
            Err(DeciderError::TooLong { .. })
        ));
        assert!(matches!(
            Decider::try_new("cli:al\0ce"),
            Err(DeciderError::EmbeddedNul)
        ));
    }

    #[test]
    fn decider_serializes_as_plain_string() {
        let d = Decider::try_new("cli:alice").unwrap();
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, "\"cli:alice\"");
        let back: Decider = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    /// Deserialising the wire form runs through `try_new`, so a JSON
    /// string that violates the invariants is rejected at the wire
    /// boundary rather than reaching the audit row.
    #[test]
    fn decider_deserialization_runs_validation() {
        assert!(serde_json::from_str::<Decider>("\"\"").is_err());
        let oversize = format!("\"{}\"", "x".repeat(MAX_DECIDER_BYTES + 1));
        assert!(serde_json::from_str::<Decider>(&oversize).is_err());
        assert!(serde_json::from_str::<Decider>("\"cli:al\\u0000ce\"").is_err());
    }

    // --- Prompt composition --------------------------------------------------

    // --- Route authorisation matrix -----------------------------------------

    /// Exhaustive enumeration of the (action, stage, decision) cube
    /// against the spec table in `docs/plans/2026-05-11-agent-plans.md`
    /// §"Protocol additions". If you change the matrix in
    /// [`route_permitted_by_stage_and_decision`] you must change this
    /// table — both sides reference the same line of the design doc.
    #[test]
    fn route_authorisation_matrix_matches_spec() {
        let decisions = [
            None,
            Some(DecisionOutcome::Accepted),
            Some(DecisionOutcome::RejectedRestart),
        ];
        let actions = [
            PlanRouteAction::SubmitPlan,
            PlanRouteAction::ReadPlan,
            PlanRouteAction::SubmitReview,
            PlanRouteAction::SubmitAddendum,
            PlanRouteAction::SubmitAbort,
        ];
        let stages = [Stage::Plan, Stage::Review, Stage::Execute];

        for action in actions {
            for stage in stages {
                for &decision in &decisions {
                    let allowed = expected_allow(action, stage, decision);
                    let actual = route_permitted_by_stage_and_decision(action, stage, decision);
                    if allowed {
                        assert!(
                            actual.is_ok(),
                            "expected Allow for ({action:?}, {stage:?}, {decision:?}), got {actual:?}",
                        );
                    } else {
                        assert!(
                            actual.is_err(),
                            "expected Deny for ({action:?}, {stage:?}, {decision:?}), got {actual:?}",
                        );
                    }
                }
            }
        }
    }

    /// Oracle re-implementation of the rules, written from the spec
    /// table without consulting [`route_permitted_by_stage_and_decision`]
    /// — when both implementations agree on every cube cell, the gate
    /// faithfully encodes the spec.
    fn expected_allow(
        action: PlanRouteAction,
        stage: Stage,
        decision: Option<DecisionOutcome>,
    ) -> bool {
        let accepted = decision == Some(DecisionOutcome::Accepted);
        match action {
            PlanRouteAction::SubmitPlan => stage == Stage::Plan,
            PlanRouteAction::ReadPlan => match stage {
                Stage::Plan => false,
                Stage::Review => true,
                Stage::Execute => accepted,
            },
            PlanRouteAction::SubmitReview => stage == Stage::Review,
            PlanRouteAction::SubmitAddendum => stage == Stage::Execute && accepted,
            PlanRouteAction::SubmitAbort => stage == Stage::Execute,
        }
    }

    #[test]
    fn route_authorisation_error_kind_reflects_failure_mode() {
        // Wrong stage -> StageNotPermitted regardless of decision.
        let err = route_permitted_by_stage_and_decision(
            PlanRouteAction::SubmitPlan,
            Stage::Execute,
            Some(DecisionOutcome::Accepted),
        )
        .unwrap_err();
        assert!(matches!(err, PlanRouteAuthError::StageNotPermitted { .. }));

        // Right stage, missing acceptance -> DecisionNotAccepted.
        let err =
            route_permitted_by_stage_and_decision(PlanRouteAction::ReadPlan, Stage::Execute, None)
                .unwrap_err();
        assert!(matches!(
            err,
            PlanRouteAuthError::DecisionNotAccepted { .. }
        ));

        // Right stage, rejected decision -> DecisionNotAccepted (not
        // "not permitted"; the stage *is* permitted, the decision
        // refuses).
        let err = route_permitted_by_stage_and_decision(
            PlanRouteAction::SubmitAddendum,
            Stage::Execute,
            Some(DecisionOutcome::RejectedRestart),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PlanRouteAuthError::DecisionNotAccepted { .. }
        ));
    }

    // --- VM HTTP paths -------------------------------------------------------

    #[test]
    fn vm_plan_paths_have_expected_shape() {
        let plan_id = PlanId::from_uuid("550e8400-e29b-41d4-a716-446655440000".parse().unwrap());
        assert_eq!(vm_plans_collection_path(), "/v1/plans");
        assert_eq!(
            vm_plan_path(plan_id),
            "/v1/plans/550e8400-e29b-41d4-a716-446655440000",
        );
        assert_eq!(
            vm_plan_reviews_path(plan_id),
            "/v1/plans/550e8400-e29b-41d4-a716-446655440000/reviews",
        );
        assert_eq!(
            vm_plan_addenda_path(plan_id),
            "/v1/plans/550e8400-e29b-41d4-a716-446655440000/addenda",
        );
        assert_eq!(
            vm_plan_abort_path(plan_id),
            "/v1/plans/550e8400-e29b-41d4-a716-446655440000/abort",
        );
    }

    // --- Wire-format struct happy paths -------------------------------------

    #[test]
    fn plan_submission_roundtrips_through_json() {
        let m = PlanSubmission {
            agent_run_id: crate::agent_run::AgentRunId::new(),
            body: PlanBody::try_new("# Plan").unwrap(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: PlanSubmission = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
        // Extra fields are rejected — deny_unknown_fields.
        let run_id_json = serde_json::to_string(&m.agent_run_id).unwrap();
        let with_typo =
            format!("{{\"agent_run_id\":{run_id_json},\"body\":\"# Plan\",\"bodyy\":\"oops\"}}");
        assert!(serde_json::from_str::<PlanSubmission>(&with_typo).is_err());
        // Missing agent_run_id is rejected.
        let missing_run = "{\"body\":\"# Plan\"}";
        assert!(serde_json::from_str::<PlanSubmission>(missing_run).is_err());
    }

    #[test]
    fn review_submission_roundtrips_with_and_without_feedback() {
        let run_id = crate::agent_run::AgentRunId::new();
        let with = ReviewSubmission {
            agent_run_id: run_id,
            verdict: Verdict::RequestChanges,
            feedback: Some(PlanFeedback::try_new("re-scope step 3").unwrap()),
        };
        let without = ReviewSubmission {
            agent_run_id: run_id,
            verdict: Verdict::Approve,
            feedback: None,
        };
        for r in [with, without] {
            let json = serde_json::to_string(&r).unwrap();
            let back: ReviewSubmission = serde_json::from_str(&json).unwrap();
            assert_eq!(back, r);
        }
    }

    /// `deny_unknown_fields` and the new `agent_run_id` requirement are
    /// load-bearing for the route. Pin both: a typoed field name fails
    /// to parse, and a body without `agent_run_id` is rejected before
    /// the route's session-ownership check would even fire.
    #[test]
    fn review_submission_rejects_unknown_field_and_missing_run_id() {
        let with_typo = r#"{"agent_run_id":"550e8400-e29b-41d4-a716-446655440000","verdict":"approve","feedbck":"oops"}"#;
        assert!(serde_json::from_str::<ReviewSubmission>(with_typo).is_err());
        let missing_run = r#"{"verdict":"approve"}"#;
        assert!(serde_json::from_str::<ReviewSubmission>(missing_run).is_err());
    }

    #[test]
    fn plan_view_roundtrips_with_and_without_decision() {
        let plan_id = PlanId::new();
        let run_id = crate::agent_run::AgentRunId::new();
        let body = PlanBody::try_new("# Plan").unwrap();
        for decision in [
            None,
            Some(DecisionView {
                outcome: DecisionOutcome::Accepted,
                decided_at: crate::core::UnixMillis::from_millis(1_700_000_000_000),
            }),
        ] {
            let view = PlanView {
                plan_id,
                body: body.clone(),
                originating_run_id: run_id,
                decision,
            };
            let json = serde_json::to_string(&view).unwrap();
            let back: PlanView = serde_json::from_str(&json).unwrap();
            assert_eq!(back, view);
        }
    }

    /// The spec (§"Protocol additions") shapes `decision` as
    /// `{ outcome, decided_at } | null` — always present, never
    /// omitted. A previous version of this struct skipped the key when
    /// `decision == None`, which clients written against the
    /// documented contract would reject. Pin the on-wire shape here
    /// directly so an accidental `skip_serializing_if` regression
    /// fails this test.
    #[test]
    fn plan_view_no_decision_serialises_as_explicit_null() {
        let view = PlanView {
            plan_id: PlanId::new(),
            body: PlanBody::try_new("# Plan").unwrap(),
            originating_run_id: crate::agent_run::AgentRunId::new(),
            decision: None,
        };
        let value: serde_json::Value = serde_json::to_value(&view).unwrap();
        assert_eq!(
            value.get("decision"),
            Some(&serde_json::Value::Null),
            "decision must be present and explicitly null: {value}",
        );
    }

    /// Slice 4c stubs originating-prompt persistence by *omitting* the
    /// field rather than persisting an empty string. Slice 5 finalises
    /// the storage strategy and re-adds the field — but until then the
    /// wire shape must not declare a field the broker can't honestly
    /// populate. Pin the omission directly so an accidental slice-5
    /// preview that adds `originating_prompt` to the struct fails here.
    #[test]
    fn plan_view_omits_originating_prompt_in_slice_4() {
        let view = PlanView {
            plan_id: PlanId::new(),
            body: PlanBody::try_new("# Plan").unwrap(),
            originating_run_id: crate::agent_run::AgentRunId::new(),
            decision: None,
        };
        let value: serde_json::Value = serde_json::to_value(&view).unwrap();
        assert!(
            value.get("originating_prompt").is_none(),
            "originating_prompt must be absent in slice 4c: {value}",
        );
    }

    /// A `PlanView` payload missing the `decision` key entirely is a
    /// wire-contract violation, not a "no decision" signal. The custom
    /// `Deserialize` impl rejects it with serde's `missing_field`
    /// error so a stale or buggy VM HTTP implementation that drops the
    /// key can't be silently misread.
    #[test]
    fn plan_view_rejects_absent_decision_key() {
        let plan_id = PlanId::new();
        let run_id = crate::agent_run::AgentRunId::new();
        // A valid `PlanView` minus the `decision` key.
        let payload = serde_json::json!({
            "plan_id": plan_id,
            "body": "# Plan",
            "originating_run_id": run_id,
        });
        let err = serde_json::from_value::<PlanView>(payload).unwrap_err();
        assert!(
            err.to_string().contains("missing field `decision`"),
            "expected missing-field error, got {err}",
        );
    }

    /// Belt-and-braces: an unknown field is also rejected. The custom
    /// `Deserialize` relies on the derived `field_identifier` enum to
    /// reject unknown keys, so this pins that the manual rewrite did
    /// not regress the prior `deny_unknown_fields` guarantee. The
    /// dropped slice-5 field `originating_prompt` doubles as today's
    /// unknown-key witness: a client that round-trips against an
    /// older mock must be rejected, not silently accepted.
    #[test]
    fn plan_view_rejects_unknown_field() {
        let plan_id = PlanId::new();
        let run_id = crate::agent_run::AgentRunId::new();
        let payload = serde_json::json!({
            "plan_id": plan_id,
            "body": "# Plan",
            "originating_run_id": run_id,
            "decision": null,
            "originating_prompt": "Original feature ask.",
        });
        let err = serde_json::from_value::<PlanView>(payload).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown") || msg.contains("originating_prompt"),
            "expected unknown-field rejection, got {msg}",
        );
    }

    #[test]
    fn ids_are_freshly_unique_and_roundtrip_through_string() {
        for pair in [
            (PlanId::new().to_string(), PlanId::new().to_string()),
            (ReviewId::new().to_string(), ReviewId::new().to_string()),
            (AddendumId::new().to_string(), AddendumId::new().to_string()),
        ] {
            assert_ne!(pair.0, pair.1, "fresh ids must differ");
            // and parse-roundtrip
            let _: PlanId = pair.0.parse().unwrap_or_else(|_| {
                // best-effort: at least one of the three types should
                // round-trip; the others are exercised in the loop body
                // via fmt::Display.
                PlanId::new()
            });
        }
        let p = PlanId::new();
        let back: PlanId = p.to_string().parse().unwrap();
        assert_eq!(p, back);
    }
}
