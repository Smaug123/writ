//! VM Git push audit DAOs and row parsing.

use rusqlite::{OptionalExtension, Row, params};

use super::{AuditError, AuditLog};
use writ_agent_run::CorrelationId;
use writ_core::core::{ApproveAttemptId, Jti, RequestId, SessionId, UnixMillis};
use writ_vm_git::{GitBranchName, GitCloneRepo, GitObjectId};

/// The approve-attempt state machine's vocabulary: the flat discriminants
/// the `state` / `outcome` columns store, and the only conversion between
/// those strings and the data-carrying DUs below.
mod approve_attempt;

/// The `impl AuditLog` read/write methods for the git-push audit rows live
/// here; the record types and row-mapping helpers stay in this module. Split
/// out to keep `git_push.rs` readable.
mod dao;

pub use approve_attempt::{
    ApproveAttemptOutcomeName, ApproveAttemptStateName, ApproveAttemptTransition,
    IllegalApproveTransition, apply as apply_approve_transition,
};

/// The base `(request, outcome)` [`EffectAuditTable`](crate::EffectAuditTable)
/// marker, re-exported so the VM-HTTP `broker_effect` driver can name it.
pub use dao::GitPushAuditTable;

#[derive(Debug)]
pub struct GitPushRequestRecord {
    pub push_request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub repo: GitCloneRepo,
    pub branch: GitBranchName,
    /// `None` records "the agent expects this push to create the branch":
    /// the staging path can preserve that distinction and the promotion
    /// path will fail-closed if a remote branch later appears.
    pub expected_remote_head: Option<GitObjectId>,
    pub new_head: GitObjectId,
    /// Opaque caller-supplied correlation id, threaded from the
    /// originating agent run when the push was authorised. `None` for
    /// pushes that were not tagged. See
    /// `docs/plans/2026-05-11-agent-plans.md` ("Correlation ID").
    pub correlation_id: Option<CorrelationId>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitPushOutcomeResult {
    Denied,
    ValidationFailed,
    Staged,
}

#[derive(Debug)]
pub struct GitPushOutcomeRecord<'a> {
    pub push_request_id: RequestId,
    pub completed_at: UnixMillis,
    pub result: GitPushOutcomeResult,
    pub github_status: Option<u16>,
    pub message: &'a str,
}

/// Mint context captured when an approval issues a GitHub App
/// installation token. Stored inline with the resolution row because
/// the originating session is closed by the time the operator decides,
/// so this mint cannot be threaded through the session-scoped
/// `request` / `grant_log` audit chain. The four fields together
/// answer "did this approval ever produce a credential, and which
/// one?" without a session-graph join.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PromoteMintAudit {
    pub jti: Jti,
    pub github_app_id: u64,
    pub issued_at: UnixMillis,
    pub expires_at: UnixMillis,
}

/// Operator decision on a staged push. `Approved` carries the mint
/// context the broker captured while issuing the installation token
/// used to promote the push; the schema's BEFORE-INSERT/UPDATE trigger
/// enforces that the column-level shape (all four mint columns NOT
/// NULL ↔ approved, all NULL ↔ rejected) matches this variant.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GitPushResolution {
    Rejected,
    Approved(PromoteMintAudit),
}

#[derive(Debug)]
pub struct GitPushResolutionRecord<'a> {
    pub push_request_id: RequestId,
    pub decided_at: UnixMillis,
    pub decision: GitPushResolution,
    pub operator: &'a str,
    pub reason: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitPushResolutionEntry {
    pub decided_at: UnixMillis,
    pub decision: GitPushResolution,
    pub operator: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitPushAuditEntry {
    pub push_request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub repo: GitCloneRepo,
    pub branch: GitBranchName,
    pub expected_remote_head: Option<GitObjectId>,
    pub new_head: GitObjectId,
    /// Correlation id recorded against the originating push request.
    /// `None` when the request was untagged.
    pub correlation_id: Option<CorrelationId>,
    pub completed_at: Option<UnixMillis>,
    pub result: Option<GitPushOutcomeResult>,
    pub github_status: Option<u16>,
    pub message: Option<String>,
    /// `Some` once an operator has recorded a decision against the
    /// staged push. The schema's `BEFORE INSERT` trigger makes this
    /// field reachable only when `result == Some(GitPushOutcomeResult::Staged)`.
    pub resolution: Option<GitPushResolutionEntry>,
}

/// Terminal outcome of an operator approve attempt. Mirrors the
/// `outcome` enum on `git_push_approve_attempt` and the CHECK
/// constraints that govern the row's shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitPushApproveAttemptOutcome {
    /// `update_ref` confirmed the GitHub branch was advanced to
    /// `new_app_tip`. Paired with a `git_push_resolution(decision='approved')`
    /// row written in the same transaction.
    Succeeded { new_app_tip: GitObjectId },
    /// The attempt failed before `update_ref` was issued. The GitHub
    /// branch is provably unchanged; the push remains rejectable /
    /// retryable. `detail` is recorded verbatim in `failure_detail`.
    PrePatchFailure { detail: String },
    /// `update_ref` was issued but the broker cannot prove whether
    /// GitHub honoured it (non-2xx response, transport drop, audit-write
    /// failure after success). The push is quarantined: reject is
    /// refused until manual operator reconciliation completes the
    /// attempt to `Succeeded` or `PrePatchFailure`. `detail` is recorded
    /// verbatim in `failure_detail`.
    PostPatchFailure { detail: String },
}

/// Lifecycle state of a `git_push_approve_attempt` row. Forward-only:
/// `Started → Uncertain → Resolved` or `Started → Resolved` (with
/// `PrePatchFailure`). The schema's `git_push_approve_attempt_forward_only`
/// trigger enforces this at the DB layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitPushApproveAttemptState {
    /// Written on entry to `approve_staged_push`, before mint or any
    /// orchestration. Carries operator and started_at; no mint context yet.
    Started,
    /// Written in the same TX that completes the post-walker lease
    /// check, immediately before `update_ref`. Carries the mint context
    /// the broker is about to use. Once this row commits the broker has
    /// promised "the PATCH may exist on GitHub"; reject is refused.
    Uncertain { mint: PromoteMintAudit },
    /// Terminal. Carries the outcome + the mint context if one was
    /// captured (always present for `Succeeded` and `PostPatchFailure`,
    /// always absent for `PrePatchFailure` that fell before mint, and
    /// optionally present for a `PrePatchFailure` that happened
    /// between mint and update_ref).
    Resolved {
        outcome: GitPushApproveAttemptOutcome,
        mint: Option<PromoteMintAudit>,
        completed_at: UnixMillis,
    },
}

/// Proof that an approve attempt is durably recorded as `Uncertain`.
///
/// Only [`AuditLog::mark_attempt_uncertain`] can produce one (the field
/// is private to this module), and the promote layer requires one to
/// issue its `PATCH`. So "the audit log records that a PATCH may exist
/// *before* one can" is a fact the compiler checks rather than an
/// ordering convention someone has to keep honouring: without the row
/// there is no witness, and without the witness there is no PATCH.
///
/// It deliberately does *not* implement `Clone`/`Copy`. A witness is
/// about one attempt; carrying `attempt_id` lets the promote layer
/// check it is being handed the witness for the attempt it prepared.
#[derive(Debug, Eq, PartialEq)]
pub struct UncertainAttempt {
    attempt_id: ApproveAttemptId,
}

impl UncertainAttempt {
    pub fn attempt_id(&self) -> ApproveAttemptId {
        self.attempt_id
    }

    /// Fabricate a witness without touching an audit log. Tests of the
    /// promote layer drive the PATCH directly and have no `AuditLog` to
    /// mint one from; production code cannot reach this.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(attempt_id: ApproveAttemptId) -> Self {
        Self { attempt_id }
    }
}

/// A `git_push_approve_attempt` row read back from the audit log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitPushApproveAttemptEntry {
    pub attempt_id: ApproveAttemptId,
    pub push_request_id: RequestId,
    pub operator: String,
    pub started_at: UnixMillis,
    pub state: GitPushApproveAttemptState,
}

/// Whether a staged push has an approve attempt that the manual
/// reconciliation handler can act on. Returned by
/// [`AuditLog::classify_reconciliation_target`]; the broker's
/// `reconcile_staged_push` RPC maps this into the
/// reconciled-vs-not-reconcilable reply.
///
/// The variants are mutually exclusive: a push has exactly one
/// classification at any point in time. The `Eligible` variant carries
/// the attempt id that a follow-up
/// [`AuditLog::record_reconciliation_attempt_applied`] /
/// [`AuditLog::record_reconciliation_attempt_not_applied`] call will
/// supersede.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationTarget {
    /// Found a non-superseded predecessor in an eligible state — the
    /// caller should drive the reconciliation through the DAO. An
    /// `Uncertain` predecessor only counts as eligible when it carries
    /// a boot-observed marker (proof that the live broker is no longer
    /// running the attempt); a `Resolved(PostPatchFailure)` predecessor
    /// is always eligible.
    Eligible { attempt_id: ApproveAttemptId },
    /// No approve attempt has ever been recorded against this push.
    NoAttempts,
    /// At least one non-superseded attempt is `Started`, or `Uncertain`
    /// without a boot-observed marker. The live broker may still be
    /// driving it; reconciliation must wait until boot reconcile runs.
    AttemptInFlight,
    /// Every non-superseded attempt is `Resolved(PrePatchFailure)`
    /// (cleanly terminated) or `Resolved(Succeeded)` (already approved).
    /// Nothing for the operator to clear.
    NothingToReconcile,
}

/// Whether a staged push has any approve attempt that prevents it from
/// being rejected. Returned by [`AuditLog::reject_blocker_for_push`];
/// the reject handler maps this into the reject-vs-refuse decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RejectBlocker {
    /// At least one attempt is `Started` or `Uncertain` — the prior
    /// approve has not finished. Reject must wait for it to resolve
    /// (or for boot reconcile to drive a stale `Started` to
    /// `PrePatchFailure`).
    AttemptInFlight { attempt_id: ApproveAttemptId },
    /// At least one attempt is `Resolved(Succeeded)`. The push is
    /// already approved; reject is logically impossible.
    AlreadyApproved { attempt_id: ApproveAttemptId },
    /// At least one attempt is `Resolved(PostPatchFailure)`. The
    /// GitHub state is uncertain; reject is refused until manual
    /// reconciliation drives the attempt to a definite outcome.
    PostPatchUncertain { attempt_id: ApproveAttemptId },
}

/// LEFT JOIN view of one staged push by `push_request_id`. Mirrors
/// `GIT_PUSH_AUDIT_ENTRY_BY_SESSION_SQL` minus the session-wide
/// `ORDER BY` clause. Schema v5 dropped `git_push_attempt` so this
/// view no longer joins on it; outcome columns alone describe the
/// broker-visible request lifecycle and `git_push_resolution` carries
/// the operator decision.
const GIT_PUSH_AUDIT_ENTRY_BY_REQUEST_SQL: &str = "
    SELECT
        r.push_request_id,
        r.session_id,
        r.received_at,
        r.repo,
        r.branch,
        r.expected_remote_head,
        r.new_head AS request_new_head,
        r.correlation_id,
        o.completed_at,
        o.result,
        o.github_status,
        o.message,
        res.decided_at,
        res.decision,
        res.operator,
        res.reason,
        res.mint_jti,
        res.mint_github_app_id,
        res.mint_issued_at,
        res.mint_expires_at
    FROM git_push_request r
    LEFT JOIN git_push_outcome o ON o.push_request_id = r.push_request_id
    LEFT JOIN git_push_resolution res ON res.push_request_id = r.push_request_id
    WHERE r.push_request_id = ?1
";

/// LEFT JOIN view of every staged push in one session, ordered by
/// arrival so callers can read the staged-push timeline.
const GIT_PUSH_AUDIT_ENTRY_BY_SESSION_SQL: &str = "
    SELECT
        r.push_request_id,
        r.session_id,
        r.received_at,
        r.repo,
        r.branch,
        r.expected_remote_head,
        r.new_head AS request_new_head,
        r.correlation_id,
        o.completed_at,
        o.result,
        o.github_status,
        o.message,
        res.decided_at,
        res.decision,
        res.operator,
        res.reason,
        res.mint_jti,
        res.mint_github_app_id,
        res.mint_issued_at,
        res.mint_expires_at
    FROM git_push_request r
    LEFT JOIN git_push_outcome o ON o.push_request_id = r.push_request_id
    LEFT JOIN git_push_resolution res ON res.push_request_id = r.push_request_id
    WHERE r.session_id = ?1
    ORDER BY r.received_at ASC, r.rowid ASC
";

/// Metadata about a quarantined predecessor attempt that a
/// reconciliation row is about to supersede. Built inside the
/// reconciliation joint TX from a single SELECT so the eligibility
/// check and the row-copy run from the same snapshot.
struct ReconciliationPredecessor {
    /// The predecessor's push request id, copied verbatim into the
    /// reconciliation row so the schema's `same_push` trigger has
    /// nothing to complain about and the resolution INSERT lands on
    /// the right push.
    push_request_id: String,
    /// The predecessor's captured mint columns. Always present for
    /// eligible predecessors: `Uncertain` rows carry mint by the v5
    /// `state != 'uncertain' OR mint_jti IS NOT NULL` CHECK, and
    /// `Resolved(PostPatchFailure)` rows carry mint by the matching
    /// `coalesce(outcome, '') != 'post_patch_failure' OR mint_jti IS NOT NULL`
    /// CHECK.
    mint_jti: Option<String>,
    mint_app: Option<i64>,
    mint_iat: Option<i64>,
    mint_exp: Option<i64>,
}

struct PredecessorMintColumns<'a> {
    jti: &'a str,
    github_app_id: i64,
    issued_at: i64,
    expires_at: i64,
}

impl ReconciliationPredecessor {
    /// Borrow the predecessor's mint columns as a struct of `Some`-only
    /// fields. The eligibility check guarantees mint is present, but
    /// the parse boundary still surfaces an `Invariant` error rather
    /// than panicking if a future schema change weakens the CHECK.
    fn require_mint(&self) -> Result<PredecessorMintColumns<'_>, AuditError> {
        let (Some(jti), Some(github_app_id), Some(issued_at), Some(expires_at)) = (
            self.mint_jti.as_deref(),
            self.mint_app,
            self.mint_iat,
            self.mint_exp,
        ) else {
            return Err(AuditError::Invariant(
                "reconciliation predecessor missing mint context",
            ));
        };
        Ok(PredecessorMintColumns {
            jti,
            github_app_id,
            issued_at,
            expires_at,
        })
    }
}

/// Look up the predecessor of a reconciliation row inside the joint TX,
/// verifying it exists, is in an eligible state (`Uncertain` or
/// `Resolved(PostPatchFailure)`), and has not already been superseded.
/// The schema's `predecessor_eligible` and supersedes-UNIQUE constraints
/// catch the same violations as defence in depth, but doing the check
/// in Rust surfaces a typed `Invariant` error rather than the raw
/// `RAISE(ABORT)` message.
fn load_reconciliation_predecessor(
    tx: &rusqlite::Transaction<'_>,
    supersedes: ApproveAttemptId,
) -> Result<ReconciliationPredecessor, AuditError> {
    let row = tx
        .query_row(
            "SELECT state, outcome, push_request_id,
                    mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
               FROM git_push_approve_attempt
              WHERE attempt_id = ?1",
            params![supersedes.as_uuid().to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((state, outcome, push_request_id, mint_jti, mint_app, mint_iat, mint_exp)) = row
    else {
        return Err(AuditError::Invariant(
            "reconciliation predecessor does not exist",
        ));
    };
    let state = ApproveAttemptStateName::parse_wire(&state).ok_or(AuditError::Invariant(
        "approve attempt row: state value is invalid",
    ))?;
    let outcome_name = match outcome.as_deref() {
        None => None,
        Some(raw) => Some(ApproveAttemptOutcomeName::parse_wire(raw).ok_or(
            AuditError::Invariant("approve attempt row: outcome value is invalid"),
        )?),
    };
    let is_uncertain = state == ApproveAttemptStateName::Uncertain;
    let is_post_patch_failure = state == ApproveAttemptStateName::Resolved
        && outcome_name == Some(ApproveAttemptOutcomeName::PostPatchFailure);
    if !is_uncertain && !is_post_patch_failure {
        return Err(AuditError::Invariant(
            "reconciliation predecessor is not in an eligible state",
        ));
    }
    let already_superseded: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM git_push_approve_attempt
              WHERE supersedes_attempt_id = ?1",
            params![supersedes.as_uuid().to_string()],
            |row| row.get(0),
        )
        .optional()?;
    if already_superseded.is_some() {
        return Err(AuditError::Invariant(
            "reconciliation predecessor has already been superseded",
        ));
    }
    // An Uncertain row may belong to the currently-running broker (it
    // is written between TX2 and TX3 of approve_staged_push). Reconciling
    // such a row before the worker finishes would race the worker's
    // resolution write — see comment on the boot-observed table in
    // migration 0004. Require the boot-observed marker, which only boot
    // reconcile writes, before admitting an Uncertain predecessor.
    // Resolved(PostPatchFailure) rows are terminal: once TX3 commits the
    // live broker never touches them again, so no gate is needed.
    if is_uncertain {
        let observed: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM git_push_approve_attempt_boot_observed
                  WHERE attempt_id = ?1",
                params![supersedes.as_uuid().to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if observed.is_none() {
            return Err(AuditError::Invariant(
                "reconciliation of uncertain predecessor requires boot-observed marker",
            ));
        }
    }
    Ok(ReconciliationPredecessor {
        push_request_id,
        mint_jti,
        mint_app,
        mint_iat,
        mint_exp,
    })
}

impl GitPushOutcomeResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::ValidationFailed => "validation_failed",
            Self::Staged => "staged",
        }
    }

    fn from_str(raw: &str) -> Result<Self, AuditError> {
        match raw {
            "denied" => Ok(Self::Denied),
            "validation_failed" => Ok(Self::ValidationFailed),
            "staged" => Ok(Self::Staged),
            _ => Err(AuditError::Invariant(
                "Git push audit outcome result is invalid",
            )),
        }
    }
}

impl GitPushResolution {
    /// The decision kind as stored in `git_push_resolution.decision`.
    /// Pairs with the four mint columns (`mint_jti`, `mint_github_app_id`,
    /// `mint_issued_at`, `mint_expires_at`); the schema's trigger enforces
    /// that the kind and the column-presence shape agree.
    pub fn kind_str(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Approved(_) => "approved",
        }
    }

    /// Reconstruct a resolution from a row's `decision` column and the
    /// four mint columns. Returns an `Invariant` error if the kind /
    /// column-presence pairing is corrupt — the SQL trigger normally
    /// prevents that, but defence in depth at the parse boundary keeps
    /// downstream code from observing an impossible variant.
    fn from_row_parts(
        decision: &str,
        mint_jti: Option<String>,
        mint_github_app_id: Option<i64>,
        mint_issued_at: Option<i64>,
        mint_expires_at: Option<i64>,
    ) -> Result<Self, AuditError> {
        match decision {
            "rejected" => match (
                mint_jti,
                mint_github_app_id,
                mint_issued_at,
                mint_expires_at,
            ) {
                (None, None, None, None) => Ok(Self::Rejected),
                _ => Err(AuditError::Invariant(
                    "Git push audit row: rejected resolution carries mint context",
                )),
            },
            "approved" => {
                let jti_str = mint_jti.ok_or(AuditError::Invariant(
                    "Git push audit row: approved resolution missing mint jti",
                ))?;
                let jti = uuid::Uuid::parse_str(&jti_str)
                    .map(Jti::from_uuid)
                    .map_err(|_| {
                        AuditError::Invariant("Git push audit row: mint jti is not a uuid")
                    })?;
                let github_app_id_i64 = mint_github_app_id.ok_or(AuditError::Invariant(
                    "Git push audit row: approved resolution missing mint github_app_id",
                ))?;
                let github_app_id = u64::try_from(github_app_id_i64).map_err(|_| {
                    AuditError::Invariant("Git push audit row: mint github_app_id is negative")
                })?;
                let issued_at =
                    mint_issued_at
                        .map(UnixMillis::from_millis)
                        .ok_or(AuditError::Invariant(
                            "Git push audit row: approved resolution missing mint issued_at",
                        ))?;
                let expires_at =
                    mint_expires_at
                        .map(UnixMillis::from_millis)
                        .ok_or(AuditError::Invariant(
                            "Git push audit row: approved resolution missing mint expires_at",
                        ))?;
                Ok(Self::Approved(PromoteMintAudit {
                    jti,
                    github_app_id,
                    issued_at,
                    expires_at,
                }))
            }
            _ => Err(AuditError::Invariant(
                "Git push audit resolution decision is invalid",
            )),
        }
    }
}

fn git_push_audit_entry_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<Result<GitPushAuditEntry, AuditError>> {
    let push_request_id_str: String = row.get("push_request_id")?;
    let session_id_str: String = row.get("session_id")?;
    let received_at: i64 = row.get("received_at")?;
    let repo_str: String = row.get("repo")?;
    let branch_str: String = row.get("branch")?;
    let expected_remote_head_str: Option<String> = row.get("expected_remote_head")?;
    let new_head_str: String = row.get("request_new_head")?;
    let correlation_id_raw: Option<String> = row.get("correlation_id")?;
    let completed_at: Option<i64> = row.get("completed_at")?;
    let result_str: Option<String> = row.get("result")?;
    let github_status: Option<i64> = row.get("github_status")?;
    let message: Option<String> = row.get("message")?;
    let resolution_decided_at: Option<i64> = row.get("decided_at")?;
    let resolution_decision: Option<String> = row.get("decision")?;
    let resolution_operator: Option<String> = row.get("operator")?;
    let resolution_reason: Option<String> = row.get("reason")?;
    let resolution_mint_jti: Option<String> = row.get("mint_jti")?;
    let resolution_mint_github_app_id: Option<i64> = row.get("mint_github_app_id")?;
    let resolution_mint_issued_at: Option<i64> = row.get("mint_issued_at")?;
    let resolution_mint_expires_at: Option<i64> = row.get("mint_expires_at")?;

    let parse = || -> Result<GitPushAuditEntry, AuditError> {
        let push_request_id = uuid::Uuid::parse_str(&push_request_id_str)
            .map_err(|_| AuditError::Invariant("Git push audit row: request id not a uuid"))?;
        let session_id = uuid::Uuid::parse_str(&session_id_str)
            .map_err(|_| AuditError::Invariant("Git push audit row: session id not a uuid"))?;
        let repo = repo_str
            .parse::<GitCloneRepo>()
            .map_err(|_| AuditError::Invariant("Git push audit row: repo is invalid"))?;
        let branch = branch_str
            .parse::<GitBranchName>()
            .map_err(|_| AuditError::Invariant("Git push audit row: branch is invalid"))?;
        let expected_remote_head = expected_remote_head_str
            .map(|s| s.parse::<GitObjectId>())
            .transpose()
            .map_err(|_| {
                AuditError::Invariant("Git push audit row: expected remote head is invalid")
            })?;
        let new_head = new_head_str
            .parse::<GitObjectId>()
            .map_err(|_| AuditError::Invariant("Git push audit row: new head is invalid"))?;
        let correlation_id = correlation_id_raw
            .map(CorrelationId::try_new)
            .transpose()
            .map_err(|_| AuditError::Invariant("Git push audit row: correlation_id is invalid"))?;

        let (completed_at, result, message) = match (completed_at, result_str, message) {
            (None, None, None) => (None, None, None),
            (Some(completed_at), Some(result), Some(message)) if !message.is_empty() => (
                Some(UnixMillis::from_millis(completed_at)),
                Some(GitPushOutcomeResult::from_str(&result)?),
                Some(message),
            ),
            _ => {
                return Err(AuditError::Invariant(
                    "Git push audit row: incomplete outcome",
                ));
            }
        };
        let github_status = github_status
            .map(|value| {
                let status = u16::try_from(value).map_err(|_| {
                    AuditError::Invariant("Git push audit row: GitHub status out of range")
                })?;
                if !(100..=599).contains(&status) {
                    return Err(AuditError::Invariant(
                        "Git push audit row: GitHub status outside HTTP range",
                    ));
                }
                Ok(status)
            })
            .transpose()?;

        // The first four resolution columns are `NOT NULL`, so they
        // are either all present (joined row matched) or all absent
        // (no resolution recorded). Any partial state is corruption.
        // The mint columns are nullable and validated against the
        // decision kind by `GitPushResolution::from_row_parts`.
        let resolution = match (
            resolution_decided_at,
            resolution_decision,
            resolution_operator,
            resolution_reason,
        ) {
            (None, None, None, None) => None,
            (Some(decided_at), Some(decision), Some(operator), Some(reason)) => {
                let decision = GitPushResolution::from_row_parts(
                    &decision,
                    resolution_mint_jti,
                    resolution_mint_github_app_id,
                    resolution_mint_issued_at,
                    resolution_mint_expires_at,
                )?;
                Some(GitPushResolutionEntry {
                    decided_at: UnixMillis::from_millis(decided_at),
                    decision,
                    operator,
                    reason,
                })
            }
            _ => {
                return Err(AuditError::Invariant(
                    "Git push audit row: incomplete resolution",
                ));
            }
        };

        Ok(GitPushAuditEntry {
            push_request_id: RequestId::from_uuid(push_request_id),
            session_id: SessionId::from_uuid(session_id),
            received_at: UnixMillis::from_millis(received_at),
            repo,
            branch,
            expected_remote_head,
            new_head,
            correlation_id,
            completed_at,
            result,
            github_status,
            message,
            resolution,
        })
    };
    Ok(parse())
}

fn git_push_approve_attempt_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<Result<GitPushApproveAttemptEntry, AuditError>> {
    let attempt_id_str: String = row.get("attempt_id")?;
    let push_request_id_str: String = row.get("push_request_id")?;
    let operator: String = row.get("operator")?;
    let started_at: i64 = row.get("started_at")?;
    let state_str: String = row.get("state")?;
    let outcome_str: Option<String> = row.get("outcome")?;
    let completed_at: Option<i64> = row.get("completed_at")?;
    let new_app_tip_str: Option<String> = row.get("new_app_tip")?;
    let failure_detail: Option<String> = row.get("failure_detail")?;
    let mint_jti_str: Option<String> = row.get("mint_jti")?;
    let mint_github_app_id: Option<i64> = row.get("mint_github_app_id")?;
    let mint_issued_at: Option<i64> = row.get("mint_issued_at")?;
    let mint_expires_at: Option<i64> = row.get("mint_expires_at")?;

    let parse = || -> Result<GitPushApproveAttemptEntry, AuditError> {
        let attempt_id = uuid::Uuid::parse_str(&attempt_id_str)
            .map(ApproveAttemptId::from_uuid)
            .map_err(|_| AuditError::Invariant("approve attempt row: attempt id is not a uuid"))?;
        let push_request_id = uuid::Uuid::parse_str(&push_request_id_str)
            .map(RequestId::from_uuid)
            .map_err(|_| AuditError::Invariant("approve attempt row: request id is not a uuid"))?;
        let started_at = UnixMillis::from_millis(started_at);

        // Mint context is all-or-nothing per the schema CHECK; reconstruct
        // a single Option<PromoteMintAudit> here so the rest of the parse
        // can treat it as one value.
        let mint = match (
            mint_jti_str,
            mint_github_app_id,
            mint_issued_at,
            mint_expires_at,
        ) {
            (None, None, None, None) => None,
            (Some(jti_str), Some(app_id), Some(issued_at), Some(expires_at)) => {
                let jti = uuid::Uuid::parse_str(&jti_str)
                    .map(Jti::from_uuid)
                    .map_err(|_| {
                        AuditError::Invariant("approve attempt row: mint jti is not a uuid")
                    })?;
                let github_app_id = u64::try_from(app_id).map_err(|_| {
                    AuditError::Invariant("approve attempt row: mint github_app_id is negative")
                })?;
                Some(PromoteMintAudit {
                    jti,
                    github_app_id,
                    issued_at: UnixMillis::from_millis(issued_at),
                    expires_at: UnixMillis::from_millis(expires_at),
                })
            }
            _ => {
                return Err(AuditError::Invariant(
                    "approve attempt row: mint context is partially populated",
                ));
            }
        };

        let state_name = ApproveAttemptStateName::parse_wire(&state_str).ok_or(
            AuditError::Invariant("approve attempt row: state value is invalid"),
        )?;
        let state = match state_name {
            ApproveAttemptStateName::Started => {
                if outcome_str.is_some()
                    || completed_at.is_some()
                    || new_app_tip_str.is_some()
                    || failure_detail.is_some()
                    || mint.is_some()
                {
                    return Err(AuditError::Invariant(
                        "approve attempt row: 'started' state must not carry terminal fields",
                    ));
                }
                GitPushApproveAttemptState::Started
            }
            ApproveAttemptStateName::Uncertain => {
                let mint = mint.ok_or(AuditError::Invariant(
                    "approve attempt row: 'uncertain' state requires mint context",
                ))?;
                if outcome_str.is_some()
                    || completed_at.is_some()
                    || new_app_tip_str.is_some()
                    || failure_detail.is_some()
                {
                    return Err(AuditError::Invariant(
                        "approve attempt row: 'uncertain' state must not carry terminal fields",
                    ));
                }
                GitPushApproveAttemptState::Uncertain { mint }
            }
            ApproveAttemptStateName::Resolved => {
                let outcome_str = outcome_str.ok_or(AuditError::Invariant(
                    "approve attempt row: 'resolved' state requires an outcome",
                ))?;
                let completed_at = completed_at.ok_or(AuditError::Invariant(
                    "approve attempt row: 'resolved' state requires completed_at",
                ))?;
                let outcome_name = ApproveAttemptOutcomeName::parse_wire(&outcome_str).ok_or(
                    AuditError::Invariant("approve attempt row: outcome value is invalid"),
                )?;
                let outcome = match outcome_name {
                    ApproveAttemptOutcomeName::Succeeded => {
                        let new_app_tip_str = new_app_tip_str.ok_or(AuditError::Invariant(
                            "approve attempt row: 'succeeded' outcome requires new_app_tip",
                        ))?;
                        let new_app_tip = new_app_tip_str.parse::<GitObjectId>().map_err(|_| {
                            AuditError::Invariant("approve attempt row: new_app_tip is invalid")
                        })?;
                        if failure_detail.is_some() {
                            return Err(AuditError::Invariant(
                                "approve attempt row: 'succeeded' outcome must not carry failure_detail",
                            ));
                        }
                        GitPushApproveAttemptOutcome::Succeeded { new_app_tip }
                    }
                    ApproveAttemptOutcomeName::PrePatchFailure => {
                        let detail = failure_detail.ok_or(AuditError::Invariant(
                            "approve attempt row: failure outcome requires failure_detail",
                        ))?;
                        if new_app_tip_str.is_some() {
                            return Err(AuditError::Invariant(
                                "approve attempt row: failure outcome must not carry new_app_tip",
                            ));
                        }
                        GitPushApproveAttemptOutcome::PrePatchFailure { detail }
                    }
                    ApproveAttemptOutcomeName::PostPatchFailure => {
                        let detail = failure_detail.ok_or(AuditError::Invariant(
                            "approve attempt row: failure outcome requires failure_detail",
                        ))?;
                        if new_app_tip_str.is_some() {
                            return Err(AuditError::Invariant(
                                "approve attempt row: failure outcome must not carry new_app_tip",
                            ));
                        }
                        GitPushApproveAttemptOutcome::PostPatchFailure { detail }
                    }
                };
                GitPushApproveAttemptState::Resolved {
                    outcome,
                    mint,
                    completed_at: UnixMillis::from_millis(completed_at),
                }
            }
        };

        Ok(GitPushApproveAttemptEntry {
            attempt_id,
            push_request_id,
            operator,
            started_at,
            state,
        })
    };
    Ok(parse())
}

#[cfg(test)]
mod approve_attempt_tests;
#[cfg(test)]
mod reconciliation_tests;
#[cfg(test)]
mod reject_blocker_tests;
#[cfg(test)]
mod request_outcome_tests;
#[cfg(test)]
mod resolution_tests;
#[cfg(test)]
mod test_support;

/// Property spec living next to the production code: it states the
/// state-machine contract over *arbitrary* legal call sequences, where
/// the sibling `approve_attempt_tests` pin individual transitions.
#[cfg(test)]
mod spec {
    use super::test_support::*;
    use super::*;
    use proptest::prelude::*;

    /// Property test: any sequence of legal DAO calls leaves the
    /// attempt in a state that the row parser can round-trip.
    ///
    /// We model "any legal sequence" as one of six scripts. Each script
    /// drives the attempt to a state explicitly, exercising every arrow
    /// of the state machine. The invariant: round-tripping the row
    /// through `approve_attempts_for_push` produces a state value that
    /// equals the one we expect.
    #[derive(Clone, Debug)]
    enum AttemptScript {
        Started,
        StartedToPrePatchFailure,
        Uncertain,
        UncertainToSucceeded,
        UncertainToPrePatchFailure,
        UncertainToPostPatchFailure,
    }

    fn attempt_script_strategy() -> impl Strategy<Value = AttemptScript> {
        prop_oneof![
            Just(AttemptScript::Started),
            Just(AttemptScript::StartedToPrePatchFailure),
            Just(AttemptScript::Uncertain),
            Just(AttemptScript::UncertainToSucceeded),
            Just(AttemptScript::UncertainToPrePatchFailure),
            Just(AttemptScript::UncertainToPostPatchFailure),
        ]
    }

    proptest! {
        #[test]
        fn approve_attempt_state_machine_roundtrips_through_dao(
            script in attempt_script_strategy(),
        ) {
            let log = AuditLog::open_in_memory().unwrap();
            let push_request_id = RequestId::new();
            let _session = open_with_staged_request(&log, push_request_id);
            let attempt_id = ApproveAttemptId::new();
            let started_at = UnixMillis::from_millis(1_700_000_200);
            log.start_approve_attempt(attempt_id, push_request_id, "alice", started_at)
                .unwrap();

            let mint = sample_promote_mint_audit();
            let new_app_tip = git_oid('a');
            let expected_state = match script {
                AttemptScript::Started => GitPushApproveAttemptState::Started,
                AttemptScript::StartedToPrePatchFailure => {
                    log.complete_attempt_pre_patch_failure(
                        attempt_id,
                        "no go",
                        UnixMillis::from_millis(1_700_000_210),
                    )
                    .unwrap();
                    GitPushApproveAttemptState::Resolved {
                        outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                            detail: "no go".into(),
                        },
                        mint: None,
                        completed_at: UnixMillis::from_millis(1_700_000_210),
                    }
                }
                AttemptScript::Uncertain => {
                    log.mark_attempt_uncertain(attempt_id, mint).unwrap();
                    GitPushApproveAttemptState::Uncertain { mint }
                }
                AttemptScript::UncertainToSucceeded => {
                    log.mark_attempt_uncertain(attempt_id, mint).unwrap();
                    log.complete_attempt_succeeded(
                        attempt_id,
                        &new_app_tip,
                        "alice",
                        "looks good",
                        UnixMillis::from_millis(1_700_000_220),
                    )
                    .unwrap();
                    GitPushApproveAttemptState::Resolved {
                        outcome: GitPushApproveAttemptOutcome::Succeeded {
                            new_app_tip: new_app_tip.clone(),
                        },
                        mint: Some(mint),
                        completed_at: UnixMillis::from_millis(1_700_000_220),
                    }
                }
                AttemptScript::UncertainToPrePatchFailure => {
                    log.mark_attempt_uncertain(attempt_id, mint).unwrap();
                    log.complete_attempt_pre_patch_failure(
                        attempt_id,
                        "aborted",
                        UnixMillis::from_millis(1_700_000_220),
                    )
                    .unwrap();
                    GitPushApproveAttemptState::Resolved {
                        outcome: GitPushApproveAttemptOutcome::PrePatchFailure {
                            detail: "aborted".into(),
                        },
                        mint: Some(mint),
                        completed_at: UnixMillis::from_millis(1_700_000_220),
                    }
                }
                AttemptScript::UncertainToPostPatchFailure => {
                    log.mark_attempt_uncertain(attempt_id, mint).unwrap();
                    log.complete_attempt_post_patch_failure(
                        attempt_id,
                        "transport drop",
                        UnixMillis::from_millis(1_700_000_220),
                    )
                    .unwrap();
                    GitPushApproveAttemptState::Resolved {
                        outcome: GitPushApproveAttemptOutcome::PostPatchFailure {
                            detail: "transport drop".into(),
                        },
                        mint: Some(mint),
                        completed_at: UnixMillis::from_millis(1_700_000_220),
                    }
                }
            };

            let attempts = log.approve_attempts_for_push(push_request_id).unwrap();
            prop_assert_eq!(attempts.len(), 1);
            prop_assert_eq!(&attempts[0].state, &expected_state);
            prop_assert_eq!(attempts[0].attempt_id, attempt_id);
            prop_assert_eq!(attempts[0].started_at, started_at);
        }
    }
}
