//! VM Git push audit DAOs and row parsing.

use rusqlite::{OptionalExtension, Row, params};

use super::{AuditError, AuditLog};
use crate::agent_run::CorrelationId;
use crate::core::{ApproveAttemptId, Jti, RequestId, SessionId, UnixMillis};
use crate::vm_git::{GitBranchName, GitCloneRepo, GitObjectId};

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
    #[cfg(test)]
    pub(crate) fn for_test(attempt_id: ApproveAttemptId) -> Self {
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

/// Internal projection of the columns `complete_attempt_succeeded`
/// needs to copy from the attempt row into the resolution row. Held
/// only inside the joint transaction, so it does not appear in the
/// public types.
struct ApproveAttemptMintRow {
    state: String,
    push_request_id: String,
    mint_jti: Option<String>,
    mint_app: Option<i64>,
    mint_iat: Option<i64>,
    mint_exp: Option<i64>,
}

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
    let is_uncertain = state == "uncertain";
    let is_post_patch_failure =
        state == "resolved" && outcome.as_deref() == Some("post_patch_failure");
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

impl AuditLog {
    /// Persist a parsed VM Git push request before any credential mint,
    /// remote fetch, or external push is attempted.
    pub fn record_git_push_request(&self, r: &GitPushRequestRecord) -> Result<(), AuditError> {
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let session_closed_at: Option<Option<i64>> = tx
                .query_row(
                    "SELECT closed_at FROM session WHERE session_id = ?1",
                    params![r.session_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            match session_closed_at {
                None => return Err(AuditError::Invariant("session does not exist")),
                Some(Some(_)) => return Err(AuditError::Invariant("session is closed")),
                Some(None) => {}
            }

            tx.execute(
                "INSERT INTO git_push_request (
                     push_request_id,
                     session_id,
                     received_at,
                     repo,
                     branch,
                     expected_remote_head,
                     new_head,
                     correlation_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    r.push_request_id.as_uuid().to_string(),
                    r.session_id.as_uuid().to_string(),
                    r.received_at.as_millis(),
                    r.repo.to_string(),
                    r.branch.as_str(),
                    r.expected_remote_head.as_ref().map(GitObjectId::as_str),
                    r.new_head.as_str(),
                    r.correlation_id.as_ref().map(CorrelationId::as_str),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Append the terminal broker-visible result for a VM Git push request.
    /// This is permitted after session close because the request was accepted
    /// while the session was open. After the v5 schema, the only results
    /// the schema admits are `denied`, `validation_failed`, and `staged`;
    /// the post-promote terminal states are recorded against
    /// `git_push_approve_attempt` instead.
    pub fn record_git_push_outcome(&self, r: &GitPushOutcomeRecord<'_>) -> Result<(), AuditError> {
        if r.message.is_empty() {
            return Err(AuditError::Invariant(
                "git push outcome message must not be empty",
            ));
        }
        if let Some(status) = r.github_status
            && !(100..=599).contains(&status)
        {
            return Err(AuditError::Invariant(
                "git push outcome GitHub status must be 100..599",
            ));
        }

        self.with_conn_mut(|c| {
            c.execute(
                "INSERT INTO git_push_outcome (
                     push_request_id,
                     completed_at,
                     result,
                     github_status,
                     message
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    r.push_request_id.as_uuid().to_string(),
                    r.completed_at.as_millis(),
                    r.result.as_str(),
                    r.github_status.map(i64::from),
                    r.message,
                ],
            )?;
            Ok(())
        })
    }

    /// Persist an operator decision on a staged push. The v13 schema's
    /// `BEFORE INSERT` trigger requires `git_push_outcome.result = 'staged'`
    /// for this request id, and the table's primary key prevents a
    /// second decision being recorded — both constraints surface as
    /// `AuditError::Sqlite`. The caller is responsible for empty-string
    /// rejection so callers see a clean `Invariant` message instead of
    /// a raw SQL CHECK violation.
    pub fn record_git_push_resolution(
        &self,
        r: &GitPushResolutionRecord<'_>,
    ) -> Result<(), AuditError> {
        if r.operator.is_empty() {
            return Err(AuditError::Invariant(
                "git push resolution operator must not be empty",
            ));
        }
        if r.reason.is_empty() {
            return Err(AuditError::Invariant(
                "git push resolution reason must not be empty",
            ));
        }

        let (mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at) = match r.decision {
            GitPushResolution::Rejected => (None, None, None, None),
            GitPushResolution::Approved(audit) => {
                let github_app_id = i64::try_from(audit.github_app_id).map_err(|_| {
                    AuditError::Invariant(
                        "git push resolution mint github_app_id exceeds SQLite integer",
                    )
                })?;
                (
                    Some(audit.jti.as_uuid().to_string()),
                    Some(github_app_id),
                    Some(audit.issued_at.as_millis()),
                    Some(audit.expires_at.as_millis()),
                )
            }
        };

        self.with_conn_mut(|c| {
            c.execute(
                "INSERT INTO git_push_resolution (
                     push_request_id,
                     decided_at,
                     decision,
                     operator,
                     reason,
                     mint_jti,
                     mint_github_app_id,
                     mint_issued_at,
                     mint_expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    r.push_request_id.as_uuid().to_string(),
                    r.decided_at.as_millis(),
                    r.decision.kind_str(),
                    r.operator,
                    r.reason,
                    mint_jti,
                    mint_github_app_id,
                    mint_issued_at,
                    mint_expires_at,
                ],
            )?;
            Ok(())
        })
    }

    /// Fetch the joined audit view for one VM Git push by request id, or
    /// `None` if no request row has been recorded. Promote tooling uses
    /// this to attach session and outcome context to a staged push that
    /// the operator looked up by id.
    pub fn get_git_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<Option<GitPushAuditEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(GIT_PUSH_AUDIT_ENTRY_BY_REQUEST_SQL)?;
            let row = stmt
                .query_row(
                    params![push_request_id.as_uuid().to_string()],
                    git_push_audit_entry_from_row,
                )
                .optional()?;
            row.transpose()
        })
    }

    pub fn list_git_pushes_for_session(
        &self,
        id: SessionId,
    ) -> Result<Vec<GitPushAuditEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(GIT_PUSH_AUDIT_ENTRY_BY_SESSION_SQL)?;
            let rows = stmt
                .query_map(
                    params![id.as_uuid().to_string()],
                    git_push_audit_entry_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }

    /// Insert a fresh `Started` approve attempt against a staged push.
    /// Required preconditions: the request row exists and has a
    /// `Staged` outcome row (the v3 trigger
    /// `git_push_resolution_requires_staged` reaches the same shape from
    /// the resolution side; this DAO mirrors that for attempts so an
    /// attempt cannot land for a push the audit log never observed
    /// staged).
    pub fn start_approve_attempt(
        &self,
        attempt_id: ApproveAttemptId,
        push_request_id: RequestId,
        operator: &str,
        started_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if operator.is_empty() {
            return Err(AuditError::Invariant(
                "approve attempt operator must not be empty",
            ));
        }
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let staged: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM git_push_outcome
                     WHERE push_request_id = ?1 AND result = 'staged'",
                    params![push_request_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if staged.is_none() {
                return Err(AuditError::Invariant(
                    "approve attempt requires staged outcome",
                ));
            }
            // A resolution row (approved *or* rejected) already exists
            // for this push. Permitting a new attempt would let the
            // approve path advance GitHub against a push the audit log
            // has already declared terminal: the `complete_attempt_*`
            // joint TX would later fail the resolution PK INSERT, but
            // by then `update_ref` may already have run. Refuse here.
            let resolution: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM git_push_resolution
                     WHERE push_request_id = ?1",
                    params![push_request_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if resolution.is_some() {
                return Err(AuditError::Invariant(
                    "approve attempt refused: push already has a resolution",
                ));
            }
            // Another attempt is still running (`started`/`uncertain`)
            // or a prior attempt is quarantined as `post_patch_failure`.
            // A second attempt would race the first's PATCH (in-flight)
            // or contradict the quarantine (post-patch failure leaves
            // GitHub's state uncertain until manual reconciliation).
            // Only a clean slate, or a history of `pre_patch_failure`
            // resolutions, is retryable.
            //
            // The NOT EXISTS clause excludes attempts that have been
            // cleared by a v6 reconciliation row (a successful manual
            // reconciliation supersedes its predecessor's quarantine).
            // Without this filter, an operator who reconciled a
            // `PostPatchFailure` to "did not apply" could never retry
            // the push — the predecessor would forever block fresh
            // starts.
            let blocker: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM git_push_approve_attempt a
                      WHERE a.push_request_id = ?1
                        AND (a.state IN ('started', 'uncertain')
                          OR (a.state = 'resolved' AND a.outcome = 'post_patch_failure'))
                        AND NOT EXISTS (
                            SELECT 1 FROM git_push_approve_attempt b
                            WHERE b.supersedes_attempt_id = a.attempt_id
                        )
                      LIMIT 1",
                    params![push_request_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if blocker.is_some() {
                return Err(AuditError::Invariant(
                    "approve attempt refused: prior attempt is in-flight or quarantined",
                ));
            }

            tx.execute(
                "INSERT INTO git_push_approve_attempt (
                     attempt_id, push_request_id, operator, started_at,
                     state, outcome, completed_at, new_app_tip, failure_detail,
                     mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                 ) VALUES (?1, ?2, ?3, ?4, 'started',
                           NULL, NULL, NULL, NULL,
                           NULL, NULL, NULL, NULL)",
                params![
                    attempt_id.as_uuid().to_string(),
                    push_request_id.as_uuid().to_string(),
                    operator,
                    started_at.as_millis(),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Transition a `Started` attempt to `Uncertain`, persisting the
    /// captured mint context. Called immediately before issuing the
    /// GitHub `update_ref` PATCH: once this commit lands the broker
    /// owes the audit log a `Resolved` row, and reject must be refused
    /// in the interim.
    ///
    /// Returns the [`UncertainAttempt`] witness. The promote layer
    /// demands one to issue its PATCH, so "the durable record that a
    /// PATCH may exist precedes the PATCH" is a fact the type system
    /// checks rather than a comment someone has to keep honouring.
    pub fn mark_attempt_uncertain(
        &self,
        attempt_id: ApproveAttemptId,
        mint: PromoteMintAudit,
    ) -> Result<UncertainAttempt, AuditError> {
        let github_app_id = i64::try_from(mint.github_app_id).map_err(|_| {
            AuditError::Invariant("approve attempt mint github_app_id exceeds SQLite integer")
        })?;
        self.with_conn_mut(|c| {
            let updated = c.execute(
                "UPDATE git_push_approve_attempt
                    SET state = 'uncertain',
                        mint_jti = ?2,
                        mint_github_app_id = ?3,
                        mint_issued_at = ?4,
                        mint_expires_at = ?5
                  WHERE attempt_id = ?1
                    AND state = 'started'",
                params![
                    attempt_id.as_uuid().to_string(),
                    mint.jti.as_uuid().to_string(),
                    github_app_id,
                    mint.issued_at.as_millis(),
                    mint.expires_at.as_millis(),
                ],
            )?;
            if updated == 0 {
                return Err(AuditError::Invariant(
                    "approve attempt is not in 'started' state",
                ));
            }
            Ok(UncertainAttempt { attempt_id })
        })
    }

    /// Atomically complete an `Uncertain` attempt as `Succeeded` *and*
    /// write the matching `git_push_resolution(decision='approved')`
    /// row. This is the load-bearing transactional commit of the
    /// approve workflow: the audit log either records the full
    /// approval (attempt resolved + resolution row) or neither side
    /// commits. The resolution row's mint columns are derived from the
    /// attempt's stored mint to guarantee they agree.
    pub fn complete_attempt_succeeded(
        &self,
        attempt_id: ApproveAttemptId,
        new_app_tip: &GitObjectId,
        operator: &str,
        reason: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if operator.is_empty() {
            return Err(AuditError::Invariant(
                "approve resolution operator must not be empty",
            ));
        }
        if reason.is_empty() {
            return Err(AuditError::Invariant(
                "approve resolution reason must not be empty",
            ));
        }

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            // Load the current attempt row inside the TX so the
            // resolution row is written from the same mint context that
            // the attempt records.
            let row = tx
                .query_row(
                    "SELECT state, push_request_id,
                            mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                       FROM git_push_approve_attempt
                      WHERE attempt_id = ?1",
                    params![attempt_id.as_uuid().to_string()],
                    |row| {
                        Ok(ApproveAttemptMintRow {
                            state: row.get(0)?,
                            push_request_id: row.get(1)?,
                            mint_jti: row.get(2)?,
                            mint_app: row.get(3)?,
                            mint_iat: row.get(4)?,
                            mint_exp: row.get(5)?,
                        })
                    },
                )
                .optional()?;
            let Some(ApproveAttemptMintRow {
                state,
                push_request_id,
                mint_jti,
                mint_app,
                mint_iat,
                mint_exp,
            }) = row
            else {
                return Err(AuditError::Invariant("approve attempt does not exist"));
            };
            if state != "uncertain" {
                return Err(AuditError::Invariant(
                    "approve attempt is not in 'uncertain' state",
                ));
            }
            let (Some(mint_jti), Some(mint_app), Some(mint_iat), Some(mint_exp)) =
                (mint_jti, mint_app, mint_iat, mint_exp)
            else {
                return Err(AuditError::Invariant(
                    "approve attempt 'uncertain' row is missing mint context",
                ));
            };

            tx.execute(
                "UPDATE git_push_approve_attempt
                    SET state = 'resolved',
                        outcome = 'succeeded',
                        new_app_tip = ?2,
                        completed_at = ?3
                  WHERE attempt_id = ?1",
                params![
                    attempt_id.as_uuid().to_string(),
                    new_app_tip.as_str(),
                    completed_at.as_millis(),
                ],
            )?;

            tx.execute(
                "INSERT INTO git_push_resolution (
                     push_request_id, decided_at, decision, operator, reason,
                     mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                 ) VALUES (?1, ?2, 'approved', ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    push_request_id,
                    completed_at.as_millis(),
                    operator,
                    reason,
                    mint_jti,
                    mint_app,
                    mint_iat,
                    mint_exp,
                ],
            )?;

            tx.commit()?;
            Ok(())
        })
    }

    /// Complete a `Started` or `Uncertain` attempt as
    /// `PrePatchFailure`. The schema's forward-only trigger allows this
    /// transition from either non-terminal state; the DAO does the
    /// matching state check before issuing the UPDATE so an attempt
    /// that has already resolved produces a readable invariant error
    /// instead of a silent no-op.
    ///
    /// Mint columns are not touched: a `Started` row stays mint-NULL
    /// and an `Uncertain` row keeps the mint context recorded by
    /// [`AuditLog::mark_attempt_uncertain`]. If the caller has a mint
    /// to record (e.g. mint succeeded but the walker refused before
    /// the PATCH boundary), use
    /// [`AuditLog::complete_attempt_pre_patch_failure_capturing_mint`]
    /// instead.
    pub fn complete_attempt_pre_patch_failure(
        &self,
        attempt_id: ApproveAttemptId,
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        self.complete_attempt_failure(
            attempt_id,
            "pre_patch_failure",
            &["started", "uncertain"],
            detail,
            completed_at,
        )
    }

    /// Complete a `Started` attempt as `PrePatchFailure` while
    /// capturing the mint context the caller already minted. This is
    /// the path for the "mint succeeded, prepare/plan/walker failed
    /// before TX2" case in the approve flow: GitHub was never PATCHed
    /// (so the resolution is provably retryable, hence
    /// `pre_patch_failure`), but the broker burned a real credential
    /// that the audit log must record. Refused from any state other
    /// than `Started`: an `Uncertain` row already carries its mint via
    /// [`AuditLog::mark_attempt_uncertain`], and the column-level
    /// immutability trigger would block writing a different one — use
    /// [`AuditLog::complete_attempt_pre_patch_failure`] in that case.
    pub fn complete_attempt_pre_patch_failure_capturing_mint(
        &self,
        attempt_id: ApproveAttemptId,
        mint: PromoteMintAudit,
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if detail.is_empty() {
            return Err(AuditError::Invariant(
                "approve attempt failure detail must not be empty",
            ));
        }
        let github_app_id = i64::try_from(mint.github_app_id).map_err(|_| {
            AuditError::Invariant("approve attempt mint github_app_id exceeds SQLite integer")
        })?;

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let current_state: Option<String> = tx
                .query_row(
                    "SELECT state FROM git_push_approve_attempt WHERE attempt_id = ?1",
                    params![attempt_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(state) = current_state else {
                return Err(AuditError::Invariant("approve attempt does not exist"));
            };
            if state != "started" {
                return Err(AuditError::Invariant(
                    "approve attempt: capturing-mint pre_patch_failure requires 'started' state",
                ));
            }

            tx.execute(
                "UPDATE git_push_approve_attempt
                    SET state = 'resolved',
                        outcome = 'pre_patch_failure',
                        failure_detail = ?2,
                        completed_at = ?3,
                        mint_jti = ?4,
                        mint_github_app_id = ?5,
                        mint_issued_at = ?6,
                        mint_expires_at = ?7
                  WHERE attempt_id = ?1",
                params![
                    attempt_id.as_uuid().to_string(),
                    detail,
                    completed_at.as_millis(),
                    mint.jti.as_uuid().to_string(),
                    github_app_id,
                    mint.issued_at.as_millis(),
                    mint.expires_at.as_millis(),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Complete an `Uncertain` attempt as `PostPatchFailure`. Only
    /// admitted from `uncertain` — `started` cannot reach this state
    /// because no PATCH could have been issued yet.
    pub fn complete_attempt_post_patch_failure(
        &self,
        attempt_id: ApproveAttemptId,
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        self.complete_attempt_failure(
            attempt_id,
            "post_patch_failure",
            &["uncertain"],
            detail,
            completed_at,
        )
    }

    /// Record that boot reconcile observed an `Uncertain` attempt at
    /// daemon startup. The marker is the "this row has survived a
    /// daemon restart" claim that the reconciliation DAO requires
    /// before admitting an `Uncertain` predecessor — see comment on
    /// the `git_push_approve_attempt_boot_observed` table in
    /// migration 0004.
    ///
    /// Idempotent: a second call against the same `attempt_id` is a
    /// no-op (preserving the original `observed_at`), matching the
    /// boot reconcile contract that re-observing a still-Uncertain row
    /// across successive boots must not error.
    pub fn mark_attempt_boot_observed(
        &self,
        attempt_id: ApproveAttemptId,
        observed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        self.with_conn_mut(|c| {
            c.execute(
                "INSERT OR IGNORE INTO git_push_approve_attempt_boot_observed
                     (attempt_id, observed_at)
                 VALUES (?1, ?2)",
                params![attempt_id.as_uuid().to_string(), observed_at.as_millis()],
            )?;
            Ok(())
        })
    }

    /// Record a manual reconciliation attempt against a quarantined
    /// predecessor (state `Uncertain` or `Resolved(PostPatchFailure)`),
    /// declaring that the operator has confirmed the PATCH did land on
    /// GitHub. Writes a born-terminal `Resolved(Succeeded)` attempt row
    /// pointing back at the predecessor via `supersedes_attempt_id`,
    /// and — in the same transaction — the matching
    /// `git_push_resolution(decision='approved')` row carrying the
    /// predecessor's captured mint context. The mint is copied verbatim
    /// (rather than re-captured at reconciliation time) because the
    /// audit log's promise is "this approval used credential X"; only
    /// the predecessor knows which credential was issued to GitHub.
    ///
    /// The DAO refuses to write if the predecessor is not in an
    /// eligible state or has already been superseded; the schema
    /// triggers enforce the same invariant as defence in depth.
    pub fn record_reconciliation_attempt_applied(
        &self,
        attempt_id: ApproveAttemptId,
        supersedes: ApproveAttemptId,
        new_app_tip: &GitObjectId,
        operator: &str,
        reason: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if operator.is_empty() {
            return Err(AuditError::Invariant(
                "reconciliation attempt operator must not be empty",
            ));
        }
        if reason.is_empty() {
            return Err(AuditError::Invariant(
                "reconciliation attempt reason must not be empty",
            ));
        }

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let predecessor = load_reconciliation_predecessor(&tx, supersedes)?;
            let mint = predecessor.require_mint()?;

            tx.execute(
                "INSERT INTO git_push_approve_attempt (
                     attempt_id, push_request_id, operator, started_at,
                     state, outcome, completed_at, new_app_tip, failure_detail,
                     mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at,
                     supersedes_attempt_id
                 ) VALUES (?1, ?2, ?3, ?4, 'resolved', 'succeeded', ?4,
                           ?5, NULL,
                           ?6, ?7, ?8, ?9,
                           ?10)",
                params![
                    attempt_id.as_uuid().to_string(),
                    predecessor.push_request_id,
                    operator,
                    completed_at.as_millis(),
                    new_app_tip.as_str(),
                    mint.jti,
                    mint.github_app_id,
                    mint.issued_at,
                    mint.expires_at,
                    supersedes.as_uuid().to_string(),
                ],
            )?;

            tx.execute(
                "INSERT INTO git_push_resolution (
                     push_request_id, decided_at, decision, operator, reason,
                     mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                 ) VALUES (?1, ?2, 'approved', ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    predecessor.push_request_id,
                    completed_at.as_millis(),
                    operator,
                    reason,
                    mint.jti,
                    mint.github_app_id,
                    mint.issued_at,
                    mint.expires_at,
                ],
            )?;

            tx.commit()?;
            Ok(())
        })
    }

    /// Record a manual reconciliation attempt declaring that the
    /// operator has confirmed the PATCH did *not* land on GitHub. Writes
    /// a born-terminal `Resolved(PrePatchFailure)` attempt row that
    /// supersedes the predecessor; once this commits, the push is once
    /// again rejectable (a follow-up Reject would write the
    /// `decision='rejected'` row). The reconciliation row carries the
    /// predecessor's mint context — even though no PATCH landed, the
    /// audit log records the credential that *was* issued to GitHub —
    /// and the schema CHECK admits mint on a `pre_patch_failure` row.
    ///
    /// No `git_push_resolution` row is written here. Reconciliation as
    /// "not applied" leaves the push in the same state as if the
    /// original approve had hit a pre-PATCH failure; the operator drives
    /// the eventual reject/retry through the existing handlers.
    pub fn record_reconciliation_attempt_not_applied(
        &self,
        attempt_id: ApproveAttemptId,
        supersedes: ApproveAttemptId,
        operator: &str,
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if operator.is_empty() {
            return Err(AuditError::Invariant(
                "reconciliation attempt operator must not be empty",
            ));
        }
        if detail.is_empty() {
            return Err(AuditError::Invariant(
                "reconciliation attempt failure detail must not be empty",
            ));
        }

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let predecessor = load_reconciliation_predecessor(&tx, supersedes)?;
            let mint = predecessor.require_mint()?;

            tx.execute(
                "INSERT INTO git_push_approve_attempt (
                     attempt_id, push_request_id, operator, started_at,
                     state, outcome, completed_at, new_app_tip, failure_detail,
                     mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at,
                     supersedes_attempt_id
                 ) VALUES (?1, ?2, ?3, ?4, 'resolved', 'pre_patch_failure', ?4,
                           NULL, ?5,
                           ?6, ?7, ?8, ?9,
                           ?10)",
                params![
                    attempt_id.as_uuid().to_string(),
                    predecessor.push_request_id,
                    operator,
                    completed_at.as_millis(),
                    detail,
                    mint.jti,
                    mint.github_app_id,
                    mint.issued_at,
                    mint.expires_at,
                    supersedes.as_uuid().to_string(),
                ],
            )?;

            tx.commit()?;
            Ok(())
        })
    }

    fn complete_attempt_failure(
        &self,
        attempt_id: ApproveAttemptId,
        outcome: &'static str,
        allowed_states: &[&'static str],
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if detail.is_empty() {
            return Err(AuditError::Invariant(
                "approve attempt failure detail must not be empty",
            ));
        }
        // SQLite CHECK forbids `failure_detail = ''` but a caller-supplied
        // string with whitespace-only content would pass; we keep the
        // strict empty-string check at the DAO boundary as a thin
        // sanity net. The `not empty` guard is intentionally tight; the
        // schema allows any non-empty string.

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let current_state: Option<String> = tx
                .query_row(
                    "SELECT state FROM git_push_approve_attempt WHERE attempt_id = ?1",
                    params![attempt_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(state) = current_state else {
                return Err(AuditError::Invariant("approve attempt does not exist"));
            };
            if !allowed_states.contains(&state.as_str()) {
                return Err(AuditError::Invariant(
                    "approve attempt is not in a state that admits this failure outcome",
                ));
            }

            tx.execute(
                "UPDATE git_push_approve_attempt
                    SET state = 'resolved',
                        outcome = ?2,
                        failure_detail = ?3,
                        completed_at = ?4
                  WHERE attempt_id = ?1",
                params![
                    attempt_id.as_uuid().to_string(),
                    outcome,
                    detail,
                    completed_at.as_millis(),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Return every approve-attempt row for one staged push, ordered
    /// by `started_at` ascending (then by attempt_id as a stable
    /// tiebreaker for the rare same-millisecond case). The reject
    /// handler and boot reconcile both consume this view.
    pub fn approve_attempts_for_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<Vec<GitPushApproveAttemptEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT attempt_id, push_request_id, operator, started_at,
                        state, outcome, completed_at,
                        new_app_tip, failure_detail,
                        mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                   FROM git_push_approve_attempt
                  WHERE push_request_id = ?1
                  ORDER BY started_at ASC, attempt_id ASC",
            )?;
            let rows = stmt
                .query_map(
                    params![push_request_id.as_uuid().to_string()],
                    git_push_approve_attempt_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }

    /// First attempt (oldest by `started_at`) whose state prevents
    /// reject from succeeding. Returns `None` when reject is allowed
    /// (no attempts, only `PrePatchFailure` attempts, or every
    /// blocker has been cleared by a v6 reconciliation row that
    /// supersedes it).
    pub fn reject_blocker_for_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<Option<RejectBlocker>, AuditError> {
        let attempts = self.approve_attempts_for_push(push_request_id)?;
        let superseded_ids = self.superseded_attempt_ids_for_push(push_request_id)?;
        Ok(attempts.into_iter().find_map(|attempt| {
            if superseded_ids.contains(&attempt.attempt_id) {
                return None;
            }
            match attempt.state {
                GitPushApproveAttemptState::Started
                | GitPushApproveAttemptState::Uncertain { .. } => {
                    Some(RejectBlocker::AttemptInFlight {
                        attempt_id: attempt.attempt_id,
                    })
                }
                GitPushApproveAttemptState::Resolved { outcome, .. } => match outcome {
                    GitPushApproveAttemptOutcome::Succeeded { .. } => {
                        Some(RejectBlocker::AlreadyApproved {
                            attempt_id: attempt.attempt_id,
                        })
                    }
                    GitPushApproveAttemptOutcome::PostPatchFailure { .. } => {
                        Some(RejectBlocker::PostPatchUncertain {
                            attempt_id: attempt.attempt_id,
                        })
                    }
                    GitPushApproveAttemptOutcome::PrePatchFailure { .. } => None,
                },
            }
        }))
    }

    /// Set of `attempt_id`s for a push that have been superseded by a
    /// v6 reconciliation row. Helper for `reject_blocker_for_push` so
    /// the in-Rust classification logic stays alongside the row-walk;
    /// pushing the filter into the underlying SQL would force
    /// `approve_attempts_for_push` (which is also the audit-history
    /// view) to decide whether to hide superseded rows or not.
    fn superseded_attempt_ids_for_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<std::collections::HashSet<ApproveAttemptId>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT supersedes_attempt_id
                   FROM git_push_approve_attempt
                  WHERE push_request_id = ?1
                    AND supersedes_attempt_id IS NOT NULL",
            )?;
            let mut out = std::collections::HashSet::new();
            let mut rows = stmt.query(params![push_request_id.as_uuid().to_string()])?;
            while let Some(row) = rows.next()? {
                let raw: String = row.get(0)?;
                let id = uuid::Uuid::parse_str(&raw)
                    .map(ApproveAttemptId::from_uuid)
                    .map_err(|_| {
                        AuditError::Invariant("approve attempt row: supersedes id is not a uuid")
                    })?;
                out.insert(id);
            }
            Ok(out)
        })
    }

    /// Classify the staged push for the manual reconciliation handler.
    /// Picks the oldest non-superseded eligible predecessor (`Uncertain`
    /// with a boot-observed marker, or `Resolved(PostPatchFailure)`).
    /// Returns a typed [`ReconciliationTarget`] so the broker reply can
    /// distinguish "go ahead" from the four distinct "nothing to do"
    /// shapes without parsing prose.
    ///
    /// Composes the existing reads ([`Self::approve_attempts_for_push`],
    /// supersession-set lookup, boot-observed-set lookup) rather than
    /// pushing the classification down into one SQL query: each
    /// sub-read is already tested in isolation, and the classification
    /// is a small Rust match the schema is too coarse to express.
    pub fn classify_reconciliation_target(
        &self,
        push_request_id: RequestId,
    ) -> Result<ReconciliationTarget, AuditError> {
        let attempts = self.approve_attempts_for_push(push_request_id)?;
        if attempts.is_empty() {
            return Ok(ReconciliationTarget::NoAttempts);
        }
        let superseded = self.superseded_attempt_ids_for_push(push_request_id)?;
        let boot_observed = self.boot_observed_attempt_ids_for_push(push_request_id)?;

        // First non-superseded eligible attempt wins (started_at ASC).
        let mut in_flight = false;
        let mut eligible: Option<ApproveAttemptId> = None;

        for attempt in attempts {
            if superseded.contains(&attempt.attempt_id) {
                continue;
            }
            match &attempt.state {
                GitPushApproveAttemptState::Started => {
                    in_flight = true;
                }
                GitPushApproveAttemptState::Uncertain { .. } => {
                    if boot_observed.contains(&attempt.attempt_id) {
                        if eligible.is_none() {
                            eligible = Some(attempt.attempt_id);
                        }
                    } else {
                        in_flight = true;
                    }
                }
                GitPushApproveAttemptState::Resolved { outcome, .. } => match outcome {
                    GitPushApproveAttemptOutcome::PostPatchFailure { .. } => {
                        if eligible.is_none() {
                            eligible = Some(attempt.attempt_id);
                        }
                    }
                    GitPushApproveAttemptOutcome::Succeeded { .. }
                    | GitPushApproveAttemptOutcome::PrePatchFailure { .. } => {}
                },
            }
        }

        if let Some(attempt_id) = eligible {
            return Ok(ReconciliationTarget::Eligible { attempt_id });
        }
        if in_flight {
            return Ok(ReconciliationTarget::AttemptInFlight);
        }
        Ok(ReconciliationTarget::NothingToReconcile)
    }

    /// `attempt_id`s for one push that boot reconcile has observed as
    /// `Uncertain` survivors of a daemon restart — the live broker
    /// never writes these markers, so any row in the set is provably
    /// out from under the live worker. The reconciliation DAO requires
    /// a marker before admitting an `Uncertain` predecessor, and
    /// `classify_reconciliation_target` consults the same set so the
    /// `AttemptInFlight` reply means "wait for boot reconcile" rather
    /// than "wait forever."
    fn boot_observed_attempt_ids_for_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<std::collections::HashSet<ApproveAttemptId>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT bo.attempt_id
                   FROM git_push_approve_attempt_boot_observed bo
                   JOIN git_push_approve_attempt a
                     ON a.attempt_id = bo.attempt_id
                  WHERE a.push_request_id = ?1",
            )?;
            let mut out = std::collections::HashSet::new();
            let mut rows = stmt.query(params![push_request_id.as_uuid().to_string()])?;
            while let Some(row) = rows.next()? {
                let raw: String = row.get(0)?;
                let id = uuid::Uuid::parse_str(&raw)
                    .map(ApproveAttemptId::from_uuid)
                    .map_err(|_| {
                        AuditError::Invariant("boot-observed row: attempt_id is not a uuid")
                    })?;
                out.insert(id);
            }
            Ok(out)
        })
    }

    /// Every approve-attempt row currently in a non-terminal state
    /// (`Started` or `Uncertain`), ordered by `started_at` ascending
    /// (then by `attempt_id` as a stable tiebreaker for the rare
    /// same-millisecond case). Consumed by boot reconcile to drive
    /// `Started` attempts to `Resolved(PrePatchFailure)` and to flag
    /// `Uncertain` attempts for operator review; the schema's
    /// forward-only triggers guarantee no `Resolved` row appears in
    /// the result set.
    ///
    /// The NOT EXISTS clause excludes attempts that a v6 reconciliation
    /// row already cleared — an `Uncertain` predecessor superseded by
    /// a successful manual reconciliation is no longer something boot
    /// reconcile needs to act on.
    pub fn list_blocking_approve_attempts(
        &self,
    ) -> Result<Vec<GitPushApproveAttemptEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT a.attempt_id, a.push_request_id, a.operator, a.started_at,
                        a.state, a.outcome, a.completed_at,
                        a.new_app_tip, a.failure_detail,
                        a.mint_jti, a.mint_github_app_id, a.mint_issued_at, a.mint_expires_at
                   FROM git_push_approve_attempt a
                  WHERE a.state IN ('started', 'uncertain')
                    AND NOT EXISTS (
                        SELECT 1 FROM git_push_approve_attempt b
                        WHERE b.supersedes_attempt_id = a.attempt_id
                    )
                  ORDER BY a.started_at ASC, a.attempt_id ASC",
            )?;
            let rows = stmt
                .query_map([], git_push_approve_attempt_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }
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

        let state = match state_str.as_str() {
            "started" => {
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
            "uncertain" => {
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
            "resolved" => {
                let outcome_str = outcome_str.ok_or(AuditError::Invariant(
                    "approve attempt row: 'resolved' state requires an outcome",
                ))?;
                let completed_at = completed_at.ok_or(AuditError::Invariant(
                    "approve attempt row: 'resolved' state requires completed_at",
                ))?;
                let outcome = match outcome_str.as_str() {
                    "succeeded" => {
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
                    "pre_patch_failure" => {
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
                    "post_patch_failure" => {
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
                    _ => {
                        return Err(AuditError::Invariant(
                            "approve attempt row: outcome value is invalid",
                        ));
                    }
                };
                GitPushApproveAttemptState::Resolved {
                    outcome,
                    mint,
                    completed_at: UnixMillis::from_millis(completed_at),
                }
            }
            _ => {
                return Err(AuditError::Invariant(
                    "approve attempt row: state value is invalid",
                ));
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
