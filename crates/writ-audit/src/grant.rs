//! Credential grant audit DAOs: pre-mint request rows, mint failures,
//! and the `grant_log` rows that capture successful mints.

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};

use super::effect_table::{EffectAuditTable, sealed};
use super::{AuditError, AuditLog};
use writ_core::core::{
    CapabilityRequest, CredentialGrant, GitHubGrantedScope, GitHubRequest, GrantedScope, Jti,
    MetadataAccess, PolicyDecision, RequestId, SessionId, UnixMillis,
};

/// How much a grant's effective lifetime may exceed the decision's TTL
/// ceiling before the audit layer rejects the row. Backend minters compare
/// a backend-reported expiry against their own clock and tolerate a small
/// amount of skew; this constant is the audit layer's matching slack, so
/// the skew allowance at mint time doesn't spuriously trip the divergence
/// check. Anything larger here would start to hide real disagreement
/// between the decision and the grant.
const AUDIT_TTL_SKEW_TOLERANCE_MILLIS: i64 = 60_000;

/// One `mint_denied` row, read back.
///
/// The reason is a plain column rather than a JSON payload (unlike
/// [`MintFailureRecord`]): it is a single sentence with no structure to
/// preserve, and wrapping it would make the log harder to read by hand for no
/// gain in fidelity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintDenialRecord {
    pub request_id: RequestId,
    pub denied_at: UnixMillis,
    pub reason: String,
}

/// JSON payload stored in the `mint_failure` table.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MintFailureRecord {
    pub error: String,
}

/// One request-and-decision, captured *before* the backend mint step is
/// attempted. Persisting this row before any `await` is what lets a
/// crash-after-mint, or a CloseSession landing during the mint's await,
/// leave a truthful audit trail: the request and its decision are already
/// durable, and the mint outcome is appended separately when it is known.
#[derive(Debug)]
pub struct PreMintRecord<'a> {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub request: &'a CapabilityRequest,
    pub decision: &'a PolicyDecision,
}

/// One ending of a host capability mint, as it is written to the log.
///
/// The mint is the one brokered effect whose outcome lives in more than one
/// physical table — a granted credential, a backend refusal, and a policy denial
/// carry genuinely different columns — so the DU is what lets the single
/// [`EffectAuditTable`] outcome slot describe all three. The `mint_outcome` view
/// is the reading half of the same idea.
///
/// Every variant is *truthful about a completed effect*, which is what keeps the
/// mint out of [`AbandonableEffect`](crate::AbandonableEffect) territory: there
/// is no ending here that has to be left dangling.
#[derive(Clone, Debug)]
pub enum HostMintOutcome<'a> {
    /// Policy refused the request; no mint was attempted. The `reason` is the
    /// same sentence the agent is told.
    Denied {
        request_id: RequestId,
        denied_at: UnixMillis,
        reason: &'a str,
    },
    /// Policy allowed the request and the backend mint failed. `error` is the
    /// full `Display` + source chain, which is deliberately richer than what the
    /// agent is shown.
    Failed {
        request_id: RequestId,
        failed_at: UnixMillis,
        error: &'a str,
    },
    /// A credential was minted. Carries the whole grant, because the row records
    /// the authority that was actually issued rather than the one requested.
    Granted(&'a CredentialGrant),
}

impl HostMintOutcome<'_> {
    /// The request this outcome belongs to.
    pub fn request_id(&self) -> RequestId {
        match self {
            Self::Denied { request_id, .. } | Self::Failed { request_id, .. } => *request_id,
            Self::Granted(grant) => grant.request_id,
        }
    }
}

/// The host capability mint's `(request, outcome)` audit pair: the `request`
/// table, and the `mint_outcome` view over `grant_log` / `mint_failure` /
/// `mint_denied`.
///
/// This is the effect that made the guard's `OUTCOME_TABLE` a *logical* name
/// rather than a physical one, and it is the pattern any future multi-outcome
/// effect should follow: keep one precise table per ending, and union them into
/// a view whose only obligation is to expose the join column. The guard, the
/// boot-time unpaired-row scan, and the Stage-0 oracle then need to know nothing
/// about the fan-out — see `docs/design/architecture.md` §5.4.
///
/// Unlike the tables that predate it, the request row here is written by
/// `begin_effect` *and the decision is already in it*: `decision_json` is
/// recorded before the mint is attempted, so a grant row that disagrees with the
/// decision is refused by reading the DB rather than by trusting the caller.
pub struct HostMintAuditTable;

impl sealed::Sealed for HostMintAuditTable {}

impl EffectAuditTable for HostMintAuditTable {
    type RequestRow<'a> = PreMintRecord<'a>;
    type OutcomeRow<'a> = HostMintOutcome<'a>;
    type Key = RequestId;

    const REQUEST_TABLE: &'static str = "request";
    const OUTCOME_TABLE: &'static str = "mint_outcome";
    const LABEL: &'static str = "Host mint";

    fn insert_request(conn: &Connection, row: &PreMintRecord<'_>) -> Result<(), AuditError> {
        insert_pre_mint_row(conn, row)
    }

    fn insert_outcome(conn: &Connection, row: &HostMintOutcome<'_>) -> Result<(), AuditError> {
        match row {
            HostMintOutcome::Denied {
                request_id,
                denied_at,
                reason,
            } => insert_mint_denied_row(conn, *request_id, *denied_at, reason),
            HostMintOutcome::Failed {
                request_id,
                failed_at,
                error,
            } => insert_mint_failure_row(conn, *request_id, *failed_at, error),
            HostMintOutcome::Granted(grant) => insert_grant_row(conn, grant),
        }
    }

    fn session_id(row: &PreMintRecord<'_>) -> SessionId {
        row.session_id
    }

    fn request_key(row: &PreMintRecord<'_>) -> RequestId {
        row.request_id
    }

    fn outcome_key(row: &HostMintOutcome<'_>) -> RequestId {
        row.request_id()
    }
}

/// Insert one `request` row. Runs inside the caller's transaction; the
/// session-open check belongs to the caller (the guard performs it before
/// calling this).
fn insert_pre_mint_row(conn: &Connection, r: &PreMintRecord<'_>) -> Result<(), AuditError> {
    // Before we even touch the DB, make sure the decision's scope is
    // one the request could justify. Without this check a caller who
    // wires the wrong decision to the wrong request would persist an
    // audit row claiming authority the agent never asked for — e.g. a
    // Metadata request paired with a Grant of contents:write on a
    // different repo.
    if let PolicyDecision::Grant { scope, .. } = r.decision
        && !scope_authorised_by_request(r.request, scope)
    {
        return Err(AuditError::Invariant(
            "decision scope is not authorised by the request",
        ));
    }

    let request_json = serde_json::to_string(r.request)?;
    let decision_json = serde_json::to_string(r.decision)?;

    conn.execute(
        "INSERT INTO request (
             request_id,
             session_id,
             received_at,
             request_json,
             decision_json
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            r.request_id.as_uuid().to_string(),
            r.session_id.as_uuid().to_string(),
            r.received_at.as_millis(),
            request_json,
            decision_json,
        ],
    )?;
    Ok(())
}

/// Insert one `grant_log` row, verified against the decision the `request` row
/// already holds. Runs inside the caller's transaction.
fn insert_grant_row(conn: &Connection, grant: &CredentialGrant) -> Result<(), AuditError> {
    let grant_scope_json = serde_json::to_string(&grant.scope)?;
    let github_app_id = grant
        .github_app_id
        .ok_or(AuditError::Invariant("grant.github_app_id is missing"))?;
    let github_app_id = i64::try_from(github_app_id)
        .map_err(|_| AuditError::Invariant("grant.github_app_id exceeds SQLite integer"))?;

    // Load the pre-mint decision so we can verify the grant
    // agrees with it. This couples audit integrity to what the
    // DB actually holds rather than trusting the caller — a
    // lying caller can't produce a row that disagrees with the
    // recorded decision.
    let recorded: Option<(String, String)> = conn
        .query_row(
            "SELECT session_id, decision_json FROM request WHERE request_id = ?1",
            params![grant.request_id.as_uuid().to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let (session_id_str, decision_json) = recorded.ok_or(AuditError::Invariant(
        "no pre-mint request row for this grant",
    ))?;

    if grant.session_id.as_uuid().to_string() != session_id_str {
        return Err(AuditError::Invariant(
            "grant.session_id != request.session_id",
        ));
    }

    let decision: PolicyDecision = serde_json::from_str(&decision_json)?;
    let (decision_scope, decision_ttl) = match decision {
        PolicyDecision::Grant { scope, ttl } => (scope, ttl),
        PolicyDecision::Deny { .. } => {
            return Err(AuditError::Invariant(
                "cannot record a grant for a Deny decision",
            ));
        }
    };

    // Decision and grant are both authority claims about the same
    // request, so they must agree on what that authority is.
    if grant.scope != decision_scope {
        return Err(AuditError::Invariant("grant.scope != decision.scope"));
    }
    // An inverted expiry (expires before issued) would silently
    // pass the TTL-ceiling comparison below because saturating_sub
    // of a negative gap is a negative lifetime, trivially less
    // than any positive ceiling. Reject explicitly.
    if grant.expires_at < grant.issued_at {
        return Err(AuditError::Invariant("grant expires before it was issued"));
    }
    let lifetime_millis = grant
        .expires_at
        .as_millis()
        .saturating_sub(grant.issued_at.as_millis());
    let max_millis = decision_ttl
        .as_i64()
        .saturating_mul(1000)
        .saturating_add(AUDIT_TTL_SKEW_TOLERANCE_MILLIS);
    if lifetime_millis > max_millis {
        return Err(AuditError::Invariant("grant lifetime exceeds decision ttl"));
    }

    conn.execute(
        "INSERT INTO grant_log (jti, request_id, session_id, github_app_id, scope_json, issued_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            grant.jti.as_uuid().to_string(),
            grant.request_id.as_uuid().to_string(),
            grant.session_id.as_uuid().to_string(),
            github_app_id,
            grant_scope_json,
            grant.issued_at.as_millis(),
            grant.expires_at.as_millis(),
        ],
    )?;
    Ok(())
}

/// Insert one `mint_failure` row. Runs inside the caller's transaction.
fn insert_mint_failure_row(
    conn: &Connection,
    request_id: RequestId,
    failed_at: UnixMillis,
    error: &str,
) -> Result<(), AuditError> {
    if error.is_empty() {
        return Err(AuditError::Invariant(
            "mint failure message must not be empty",
        ));
    }
    let failure_json = serde_json::to_string(&MintFailureRecord {
        error: error.to_string(),
    })?;

    // Refuse to record a mint failure against a request whose
    // decision was Deny — such a row would be nonsense (a denied
    // request never reaches the mint step).
    match recorded_decision(
        conn,
        request_id,
        "no pre-mint request row for this mint failure",
    )? {
        PolicyDecision::Grant { .. } => {}
        PolicyDecision::Deny { .. } => {
            return Err(AuditError::Invariant(
                "cannot record a mint failure for a Deny decision",
            ));
        }
    }

    conn.execute(
        "INSERT INTO mint_failure (request_id, failed_at, failure_json) \
         VALUES (?1, ?2, ?3)",
        params![
            request_id.as_uuid().to_string(),
            failed_at.as_millis(),
            failure_json,
        ],
    )?;
    Ok(())
}

/// Insert one `mint_denied` row. Runs inside the caller's transaction.
///
/// The mirror image of [`insert_mint_failure_row`]'s decision check: a denial
/// row against a request whose recorded decision was `Grant` is just as much
/// nonsense as a mint failure against a `Deny`, and the log would then hold two
/// mutually contradictory statements about the same request.
///
/// The *reason* is checked too, against the one already in `decision_json`.
/// [`insert_grant_row`] verifies its outcome against the recorded decision
/// rather than trusting the caller, and a denial is no different: the row's
/// whole content is that sentence, so a caller that recorded a different one
/// would leave the log holding two incompatible accounts of the same refusal —
/// with nothing to say which the agent was actually given. Reading it back out
/// of the DB is what makes this an invariant rather than a convention.
fn insert_mint_denied_row(
    conn: &Connection,
    request_id: RequestId,
    denied_at: UnixMillis,
    reason: &str,
) -> Result<(), AuditError> {
    if reason.is_empty() {
        return Err(AuditError::Invariant("denial reason must not be empty"));
    }
    match recorded_decision(conn, request_id, "no pre-mint request row for this denial")? {
        PolicyDecision::Deny {
            reason: decided_reason,
        } => {
            if decided_reason != reason {
                return Err(AuditError::Invariant("denial reason != decision reason"));
            }
        }
        PolicyDecision::Grant { .. } => {
            return Err(AuditError::Invariant(
                "cannot record a denial for a Grant decision",
            ));
        }
    }

    conn.execute(
        "INSERT INTO mint_denied (request_id, denied_at, reason) VALUES (?1, ?2, ?3)",
        params![
            request_id.as_uuid().to_string(),
            denied_at.as_millis(),
            reason,
        ],
    )?;
    Ok(())
}

/// The decision recorded on `request_id`'s pre-mint row. `missing` is the
/// invariant message for "there is no such row", so the error names the write
/// that would have been orphaned rather than the read that noticed.
fn recorded_decision(
    conn: &Connection,
    request_id: RequestId,
    missing: &'static str,
) -> Result<PolicyDecision, AuditError> {
    let decision_json: Option<String> = conn
        .query_row(
            "SELECT decision_json FROM request WHERE request_id = ?1",
            params![request_id.as_uuid().to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let decision_json = decision_json.ok_or(AuditError::Invariant(missing))?;
    Ok(serde_json::from_str::<PolicyDecision>(&decision_json)?)
}

/// Half-pair writers, for testing the mint DAO's own invariants.
///
/// **There is no production caller.** The only way to write these rows in a
/// shipped build is [`AuditLog::begin_effect`] with [`HostMintAuditTable`],
/// which hands back a guard that must be discharged with one of the three
/// [`HostMintOutcome`] endings — that is what makes the mint's pair complete by
/// construction rather than by the shell remembering to append an outcome.
///
/// They exist because the invariants below (scope authorisation, grant/decision
/// agreement, the TTL-divergence ceiling, "no mint failure for a Deny") are
/// properties of *one row*, and asserting them through the guard's sequencing
/// would test the sequencing over again at every one. `#[cfg(test)]` rather
/// than merely private, so a future production caller is a compile error rather
/// than a review question.
#[cfg(test)]
impl AuditLog {
    /// Persist a request and its policy decision, in its own transaction.
    ///
    /// The session-open check lives inside the same transaction as the INSERT.
    /// Without it, a client could CloseSession and then see audit rows land
    /// after the session's own `closed_at` — which would silently strip
    /// `closed_at` of its meaning as an activity-window bound. The existing FK
    /// covers "session exists"; it cannot express "session is open". The
    /// BEFORE-INSERT trigger on `request` is braces to this belt.
    pub(crate) fn record_pre_mint(&self, r: &PreMintRecord<'_>) -> Result<(), AuditError> {
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            crate::validation::check_session_open(&tx, r.session_id)?;
            insert_pre_mint_row(&tx, r)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Append the grant produced by a successful mint. The matching
    /// request row must already have been persisted via
    /// [`AuditLog::record_pre_mint`]; the FK on `grant_log.request_id`
    /// enforces this at the DB layer.
    ///
    /// The session may have been closed between `record_pre_mint` and
    /// this call (a CloseSession can land during the mint's `await`);
    /// that is *not* an error. The authority to mint was established at
    /// pre-mint time, so the resulting grant is still a legitimate
    /// audit row even if the session has since gone quiet on paper.
    pub(crate) fn record_grant(&self, grant: &CredentialGrant) -> Result<(), AuditError> {
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            insert_grant_row(&tx, grant)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Append a backend mint failure for a previously pre-minted request.
    /// Like [`AuditLog::record_grant`], this is permitted even if the
    /// session has since been closed: the request was accepted while the
    /// session was open, and the failure is the honest outcome of that
    /// acceptance.
    pub(crate) fn record_mint_failure(
        &self,
        request_id: RequestId,
        failed_at: UnixMillis,
        error: &str,
    ) -> Result<(), AuditError> {
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            insert_mint_failure_row(&tx, request_id, failed_at, error)?;
            tx.commit()?;
            Ok(())
        })
    }
}

impl AuditLog {
    pub fn list_grants_for_session(
        &self,
        id: SessionId,
    ) -> Result<Vec<CredentialGrant>, AuditError> {
        self.with_conn(|c| {
            // Secondary sort on rowid so grants issued in the same instant
            // still come back in insert order. Without it, `ORDER BY
            // issued_at ASC` leaves same-timestamp rows in an unspecified
            // order and replay can't reconstruct the real sequence.
            let mut stmt = c.prepare(
                "SELECT jti, request_id, session_id, github_app_id, scope_json, issued_at, expires_at \
                 FROM grant_log WHERE session_id = ?1 ORDER BY issued_at ASC, rowid ASC",
            )?;
            let rows = stmt
                .query_map(params![id.as_uuid().to_string()], grant_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }

    /// Every policy denial recorded against `id`, oldest first.
    ///
    /// The counterpart to [`AuditLog::list_grants_for_session`], and the read
    /// half of the `mint_denied` row: a log that can record a denial but not
    /// read one back is only half a record. `mint_denied` has no `session_id`
    /// of its own — the `request` row it references already carries one, and
    /// duplicating it would create a second place for the two to disagree — so
    /// this joins rather than filtering directly.
    ///
    /// Secondary sort on rowid for the same reason as the grant listing: two
    /// denials in the same millisecond must still come back in insert order.
    pub fn list_mint_denials_for_session(
        &self,
        id: SessionId,
    ) -> Result<Vec<MintDenialRecord>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT d.request_id, d.denied_at, d.reason \
                 FROM mint_denied d JOIN request r ON r.request_id = d.request_id \
                 WHERE r.session_id = ?1 ORDER BY d.denied_at ASC, d.rowid ASC",
            )?;
            let rows = stmt
                .query_map(params![id.as_uuid().to_string()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter()
                .map(|(request_id, denied_at, reason)| {
                    let request_id = uuid::Uuid::parse_str(&request_id)
                        .map_err(|_| AuditError::Invariant("denial row: request_id not a uuid"))?;
                    Ok(MintDenialRecord {
                        request_id: RequestId::from_uuid(request_id),
                        denied_at: UnixMillis::from_millis(denied_at),
                        reason,
                    })
                })
                .collect()
        })
    }

    /// True iff this session holds a recorded grant that authorises `request`.
    /// Lets a later action reuse a capability the session already proved —
    /// e.g. provisioning a repo the session was granted contents-read on by an
    /// earlier clone — without minting a fresh credential. It applies the same
    /// structural `scope_authorised_by_request` check that guards `grant_log`
    /// rows against cross-request wire-ups, so a grant only ever authorises the
    /// request it could itself have been minted from.
    pub fn session_holds_grant_authorising(
        &self,
        session_id: SessionId,
        request: &CapabilityRequest,
    ) -> Result<bool, AuditError> {
        Ok(self
            .list_grants_for_session(session_id)?
            .iter()
            .any(|grant| scope_authorised_by_request(request, &grant.scope)))
    }

    pub fn get_grant(&self, jti: Jti) -> Result<Option<CredentialGrant>, AuditError> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT jti, request_id, session_id, github_app_id, scope_json, issued_at, expires_at \
                     FROM grant_log WHERE jti = ?1",
                    params![jti.as_uuid().to_string()],
                    grant_from_row,
                )
                .optional()?;
            match row {
                Some(Ok(g)) => Ok(Some(g)),
                Some(Err(e)) => Err(e),
                None => Ok(None),
            }
        })
    }
}

/// True iff `scope` is a possible policy output for `request`. The audit
/// layer uses this to reject rows where the decision has been paired with
/// the wrong request — an invariant the policy engine maintains by
/// construction, but the audit layer can't assume its caller did.
///
/// Structural rather than derived-from-policy on purpose: the audit layer
/// doesn't know the policy config, so it can't re-run `policy::decide`.
/// What it can check is that the scope's backend, repo, and permission
/// set are shaped compatibly with the request, which is all we need to
/// rule out cross-request wire-ups. Policy-level narrowing (granting less
/// than requested) would be allowed by this check; v1 policy doesn't do
/// that, and a future narrowing policy's tighter constraint still
/// satisfies a looser structural check.
fn scope_authorised_by_request(request: &CapabilityRequest, scope: &GrantedScope) -> bool {
    match (request, scope) {
        (CapabilityRequest::GitHub(r), GrantedScope::GitHub(s)) => {
            github_scope_authorised_by_request(r, s)
        }
    }
}

fn github_scope_authorised_by_request(r: &GitHubRequest, s: &GitHubGrantedScope) -> bool {
    // Exact `!=` is intentional: `s.repository` was cloned from
    // `r.repo()` by `policy::decide_github`, so a byte-identical match
    // is what proves the scope was minted from this request. A
    // case-insensitive `matches` here would let a row with
    // operator-edited casing pass the structural check.
    if &s.repository != r.repo() {
        return false;
    }
    // GitHub installation tokens always carry metadata:read, so it's fine
    // for the grant to include it regardless of request; other metadata
    // values are impossible (MetadataAccess is a one-variant enum) but
    // pattern-match explicitly so the compiler forces us to revisit this
    // if that ever changes.
    match s.permissions.metadata {
        None | Some(MetadataAccess::Read) => {}
    }
    match r {
        GitHubRequest::Metadata { .. } => {
            s.permissions.contents.is_none()
                && s.permissions.issues.is_none()
                && s.permissions.pull_requests.is_none()
        }
        GitHubRequest::Contents { access, .. } => {
            s.permissions.contents == Some(*access)
                && s.permissions.issues.is_none()
                && s.permissions.pull_requests.is_none()
        }
        GitHubRequest::Issues { access, .. } => {
            s.permissions.issues == Some(*access)
                && s.permissions.contents.is_none()
                && s.permissions.pull_requests.is_none()
        }
        GitHubRequest::PullRequests { access, .. } => {
            s.permissions.pull_requests == Some(*access)
                && s.permissions.contents.is_none()
                && s.permissions.issues.is_none()
        }
    }
}

pub(super) fn grant_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<Result<CredentialGrant, AuditError>> {
    let jti_str: String = row.get("jti")?;
    let request_id_str: String = row.get("request_id")?;
    let session_id_str: String = row.get("session_id")?;
    let github_app_id: Option<i64> = row.get("github_app_id")?;
    let scope_json: String = row.get("scope_json")?;
    let issued_at: i64 = row.get("issued_at")?;
    let expires_at: i64 = row.get("expires_at")?;

    let parse = || -> Result<CredentialGrant, AuditError> {
        let jti = uuid::Uuid::parse_str(&jti_str)
            .map_err(|_| AuditError::Invariant("grant row: jti not a uuid"))?;
        let request_id = uuid::Uuid::parse_str(&request_id_str)
            .map_err(|_| AuditError::Invariant("grant row: request_id not a uuid"))?;
        let session_id = uuid::Uuid::parse_str(&session_id_str)
            .map_err(|_| AuditError::Invariant("grant row: session_id not a uuid"))?;
        let github_app_id = github_app_id
            .map(|id| {
                u64::try_from(id)
                    .map_err(|_| AuditError::Invariant("grant row: github_app_id is negative"))
            })
            .transpose()?;
        let scope: GrantedScope = serde_json::from_str(&scope_json)?;
        Ok(CredentialGrant {
            jti: Jti::from_uuid(jti),
            request_id: RequestId::from_uuid(request_id),
            session_id: SessionId::from_uuid(session_id),
            github_app_id,
            scope,
            issued_at: UnixMillis::from_millis(issued_at),
            expires_at: UnixMillis::from_millis(expires_at),
        })
    };
    Ok(parse())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        pre_mint, sample_repo, sample_request, sample_scope, sample_session,
    };
    use writ_core::core::{
        GitHubAccess, GitHubGrantedScope, GitHubPermissions, GitHubRequest, MetadataAccess,
        RepoRef, TtlSeconds,
    };

    #[test]
    fn pre_mint_then_record_grant_writes_both_tables() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let scope = sample_scope();
        let decision = PolicyDecision::Grant {
            scope: scope.clone(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: scope.clone(),
            issued_at: UnixMillis::from_millis(1_700_000_100),
            expires_at: UnixMillis::from_millis(1_700_000_400),
        };

        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();
        log.record_grant(&grant).unwrap();

        let grants = log.list_grants_for_session(s.session_id).unwrap();
        assert_eq!(grants, vec![grant.clone()]);
        let got = log.get_grant(grant.jti).unwrap().unwrap();
        assert_eq!(got, grant);
    }

    #[test]
    fn session_holds_grant_authorising_matches_only_the_recorded_request() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let scope = sample_scope();
        let decision = PolicyDecision::Grant {
            scope: scope.clone(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();
        log.record_grant(&CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope,
            issued_at: UnixMillis::from_millis(1_700_000_100),
            expires_at: UnixMillis::from_millis(1_700_000_400),
        })
        .unwrap();

        // The recorded grant authorises the exact request it was minted from.
        assert!(
            log.session_holds_grant_authorising(s.session_id, &req)
                .unwrap()
        );
        // It does not authorise a different repository,
        let other_repo = CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Write,
            repo: RepoRef {
                owner: "o".into(),
                name: "other".into(),
            },
        });
        assert!(
            !log.session_holds_grant_authorising(s.session_id, &other_repo)
                .unwrap()
        );
        // nor any request for a session that holds no grants.
        assert!(
            !log.session_holds_grant_authorising(SessionId::new(), &req)
                .unwrap()
        );
    }

    #[test]
    fn record_grant_rejects_missing_github_app_id() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let scope = sample_scope();
        let decision = PolicyDecision::Grant {
            scope: scope.clone(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();

        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: None,
            scope,
            issued_at: UnixMillis::from_millis(1_700_000_100),
            expires_at: UnixMillis::from_millis(1_700_000_400),
        };

        let err = log.record_grant(&grant).unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant("grant.github_app_id is missing")),
            "got: {err:?}"
        );
    }

    #[test]
    fn record_pre_mint_for_deny_writes_no_grant() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "policy says no".into(),
        };

        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();

        assert!(
            log.list_grants_for_session(s.session_id)
                .unwrap()
                .is_empty()
        );
    }

    /// A Deny request has no mint step, so there is no legitimate reason
    /// for a caller to append a grant against it. The audit layer reads
    /// the recorded decision back and refuses.
    #[test]
    fn record_grant_rejected_when_request_has_deny_decision() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "no".into(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();

        let bogus_grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(1),
            expires_at: UnixMillis::from_millis(2),
        };
        let err = log.record_grant(&bogus_grant).unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)));
    }

    /// `record_grant` depends on a prior `record_pre_mint` (FK enforces
    /// it at the DB layer too, but the app-layer check produces a
    /// readable error rather than a generic FK violation).
    #[test]
    fn record_grant_without_pre_mint_is_rejected() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id: RequestId::new(),
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(1),
            expires_at: UnixMillis::from_millis(2),
        };
        let err = log.record_grant(&grant).unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant(_)),
            "expected Invariant, got: {err:?}"
        );
    }

    /// Same invariant for `record_mint_failure`.
    #[test]
    fn record_mint_failure_without_pre_mint_is_rejected() {
        let log = AuditLog::open_in_memory().unwrap();
        let err = log
            .record_mint_failure(RequestId::new(), UnixMillis::from_millis(1), "boom")
            .unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant(_)),
            "expected Invariant, got: {err:?}"
        );
    }

    #[test]
    fn grants_are_returned_in_issue_order() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let mk_grant = |at: i64| {
            let request_id = RequestId::new();
            let decision = PolicyDecision::Grant {
                scope: sample_scope(),
                ttl: TtlSeconds::new(300).unwrap(),
            };
            let grant = CredentialGrant {
                jti: Jti::new(),
                request_id,
                session_id: s.session_id,
                github_app_id: Some(42),
                scope: sample_scope(),
                issued_at: UnixMillis::from_millis(at),
                expires_at: UnixMillis::from_millis(at + 300),
            };
            let request = sample_request();
            pre_mint(
                &log,
                request_id,
                s.session_id,
                &request,
                &decision,
                UnixMillis::from_millis(at),
            )
            .unwrap();
            log.record_grant(&grant).unwrap();
            grant
        };

        let a = mk_grant(1000);
        let b = mk_grant(2000);
        let c = mk_grant(1500);

        let listed = log.list_grants_for_session(s.session_id).unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|g| g.issued_at.as_millis())
                .collect::<Vec<_>>(),
            vec![1000, 1500, 2000]
        );
        assert_eq!(
            listed.iter().map(|g| g.jti).collect::<Vec<_>>(),
            vec![a.jti, c.jti, b.jti]
        );
    }

    /// With millisecond resolution two grants can still share an
    /// `issued_at`, so `list_grants_for_session` must fall back on insert
    /// order rather than leaving the tie undefined. Record two rows with
    /// identical timestamps and check they come back in the order they
    /// were written.
    #[test]
    fn grants_with_identical_issued_at_preserve_insert_order() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let mk_grant = || {
            let request_id = RequestId::new();
            let decision = PolicyDecision::Grant {
                scope: sample_scope(),
                ttl: TtlSeconds::new(300).unwrap(),
            };
            let grant = CredentialGrant {
                jti: Jti::new(),
                request_id,
                session_id: s.session_id,
                github_app_id: Some(42),
                scope: sample_scope(),
                issued_at: UnixMillis::from_millis(5_000),
                expires_at: UnixMillis::from_millis(5_300),
            };
            let request = sample_request();
            pre_mint(
                &log,
                request_id,
                s.session_id,
                &request,
                &decision,
                UnixMillis::from_millis(5_000),
            )
            .unwrap();
            log.record_grant(&grant).unwrap();
            grant
        };

        let first = mk_grant();
        let second = mk_grant();
        let third = mk_grant();

        let listed = log.list_grants_for_session(s.session_id).unwrap();
        assert_eq!(
            listed.iter().map(|g| g.jti).collect::<Vec<_>>(),
            vec![first.jti, second.jti, third.jti]
        );
    }

    /// If the decision grants one scope but the supplied grant record
    /// carries a different one, the two rows would describe contradictory
    /// authority for the same request. `record_grant` loads the recorded
    /// decision back from the DB so it can cross-check without trusting
    /// the caller to re-supply it.
    #[test]
    fn record_grant_rejects_grant_with_divergent_scope() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision_scope = sample_scope();
        let decision = PolicyDecision::Grant {
            scope: decision_scope,
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_000),
        )
        .unwrap();

        let other_scope = GrantedScope::GitHub(GitHubGrantedScope {
            repository: RepoRef {
                owner: "different".into(),
                name: "repo".into(),
            },
            permissions: GitHubPermissions {
                contents: Some(GitHubAccess::Read),
                metadata: Some(MetadataAccess::Read),
                ..Default::default()
            },
        });
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: other_scope,
            issued_at: UnixMillis::from_millis(1_000),
            expires_at: UnixMillis::from_millis(2_000),
        };

        let err = log.record_grant(&grant).unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// Same idea as scope divergence: if the grant's effective lifetime
    /// grossly overshoots the decision's TTL ceiling, the two rows would
    /// disagree on how long the authority lasts. The audit layer allows
    /// a small skew (so minter clock tolerance doesn't spuriously trip
    /// it) but rejects anything beyond that.
    #[test]
    fn record_grant_rejects_lifetime_exceeding_ttl() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(60).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(0),
        )
        .unwrap();

        // Decision says 60s (60_000 ms). Grant lifetime is 1h (3_600_000 ms),
        // well past the 60_000 ms skew tolerance.
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(0),
            expires_at: UnixMillis::from_millis(3_600_000),
        };

        let err = log.record_grant(&grant).unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// An inverted expiry (expires before issued) would otherwise slip
    /// past the TTL-ceiling comparison because the signed
    /// `saturating_sub` produces a negative lifetime that's trivially
    /// under any positive ceiling. Explicit check catches the sign class.
    #[test]
    fn record_grant_rejects_expiry_before_issue() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(500),
        )
        .unwrap();

        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(500),
            // Deliberately before issued_at.
            expires_at: UnixMillis::from_millis(100),
        };

        let err = log.record_grant(&grant).unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// The other side of the boundary: a grant whose lifetime lands
    /// exactly at the TTL+skew ceiling must still be accepted, otherwise
    /// a minter operating inside its documented skew tolerance couldn't
    /// record its own grants.
    #[test]
    fn record_grant_accepts_lifetime_within_ttl_plus_skew() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let ttl_seconds: i64 = 300;
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(ttl_seconds).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(0),
        )
        .unwrap();

        // Lifetime = ttl + full skew tolerance, exactly on the boundary.
        let lifetime_millis = ttl_seconds * 1000 + AUDIT_TTL_SKEW_TOLERANCE_MILLIS;
        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(0),
            expires_at: UnixMillis::from_millis(lifetime_millis),
        };

        log.record_grant(&grant).unwrap();
    }

    #[test]
    fn record_mint_failure_writes_to_mint_failure_table() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();

        log.record_mint_failure(
            request_id,
            UnixMillis::from_millis(1_700_000_105),
            "GitHub returned 422: repository not installed",
        )
        .unwrap();

        assert!(
            log.list_grants_for_session(s.session_id)
                .unwrap()
                .is_empty()
        );
        let recorded = log
            .with_conn(|c| {
                let json: String = c.query_row(
                    "SELECT failure_json FROM mint_failure WHERE request_id = ?1",
                    params![request_id.as_uuid().to_string()],
                    |row| row.get(0),
                )?;
                Ok(json)
            })
            .unwrap();
        let failure: MintFailureRecord = serde_json::from_str(&recorded).unwrap();
        assert_eq!(
            failure.error,
            "GitHub returned 422: repository not installed"
        );
    }

    /// Recording a grant *and* a mint failure for the same request_id
    /// would leave replay with contradictory outcomes. The cross-
    /// exclusion trigger on each table refuses the second insert.
    #[test]
    fn record_grant_and_mint_failure_are_mutually_exclusive() {
        for grant_first in [true, false] {
            let log = AuditLog::open_in_memory().unwrap();
            let s = sample_session();
            log.open_session(&s).unwrap();
            let request_id = RequestId::new();
            let req = sample_request();
            let decision = PolicyDecision::Grant {
                scope: sample_scope(),
                ttl: TtlSeconds::new(300).unwrap(),
            };
            pre_mint(
                &log,
                request_id,
                s.session_id,
                &req,
                &decision,
                UnixMillis::from_millis(0),
            )
            .unwrap();
            let grant = CredentialGrant {
                jti: Jti::new(),
                request_id,
                session_id: s.session_id,
                github_app_id: Some(42),
                scope: sample_scope(),
                issued_at: UnixMillis::from_millis(0),
                expires_at: UnixMillis::from_millis(1_000),
            };

            let (first, second) = if grant_first {
                (
                    log.record_grant(&grant),
                    log.record_mint_failure(request_id, UnixMillis::from_millis(10), "boom"),
                )
            } else {
                (
                    log.record_mint_failure(request_id, UnixMillis::from_millis(10), "boom")
                        .map(|_| ()),
                    log.record_grant(&grant),
                )
            };
            first.unwrap_or_else(|e| panic!("first insert should succeed: {e}"));
            let err = second.unwrap_err();
            let msg = format!("{err}").to_lowercase();
            assert!(
                msg.contains("already recorded"),
                "expected cross-exclusion trigger, got: {err:?}"
            );
        }
    }

    /// If the caller accidentally pairs a `Metadata` request with a
    /// `Contents:write` grant decision, the pre-mint row would claim
    /// authority the request never asked for. `record_pre_mint` rejects
    /// the pairing before any row lands.
    #[test]
    fn record_pre_mint_rejects_decision_scope_exceeding_request() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let metadata_request = CapabilityRequest::GitHub(GitHubRequest::Metadata {
            repo: sample_repo(),
        });
        let contents_write_scope = sample_scope();
        let decision = PolicyDecision::Grant {
            scope: contents_write_scope,
            ttl: TtlSeconds::new(300).unwrap(),
        };

        let err = pre_mint(
            &log,
            RequestId::new(),
            s.session_id,
            &metadata_request,
            &decision,
            UnixMillis::from_millis(0),
        )
        .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// Grant decision for a different repo than the request — structurally
    /// impossible output of the policy engine, so recording it would
    /// corrupt replay.
    #[test]
    fn record_pre_mint_rejects_grant_decision_on_different_repo() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request = CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Write,
            repo: sample_repo(),
        });
        let other_scope = GrantedScope::GitHub(GitHubGrantedScope {
            repository: RepoRef {
                owner: "other".into(),
                name: "repo".into(),
            },
            permissions: GitHubPermissions {
                contents: Some(GitHubAccess::Write),
                metadata: Some(MetadataAccess::Read),
                ..Default::default()
            },
        });
        let decision = PolicyDecision::Grant {
            scope: other_scope,
            ttl: TtlSeconds::new(300).unwrap(),
        };

        let err = pre_mint(
            &log,
            RequestId::new(),
            s.session_id,
            &request,
            &decision,
            UnixMillis::from_millis(0),
        )
        .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// Grant decision with the right resource but wrong access level
    /// (request read, decision write) is not a possible policy output for
    /// a correctly-paired request. Reject.
    #[test]
    fn record_pre_mint_rejects_decision_access_level_exceeding_request() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let read_request = CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Read,
            repo: sample_repo(),
        });
        // sample_scope() grants contents:write — stricter than the read
        // the request asked for.
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };

        let err = pre_mint(
            &log,
            RequestId::new(),
            s.session_id,
            &read_request,
            &decision,
            UnixMillis::from_millis(0),
        )
        .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// A Deny decision cannot carry a mint failure — the denied request
    /// never reaches the mint step.
    #[test]
    fn record_mint_failure_rejected_for_deny_decision() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "no".into(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();

        let err = log
            .record_mint_failure(
                request_id,
                UnixMillis::from_millis(1_700_000_110),
                "should not exist",
            )
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)));
    }

    /// **A denial's reason must be the reason the decision recorded.**
    ///
    /// The whole content of a `mint_denied` row is that sentence, and the
    /// `request` row already holds one. If they were allowed to differ the log
    /// would permanently carry two incompatible accounts of the same refusal,
    /// with nothing to say which the agent was actually given — so the DAO
    /// re-reads the recorded decision rather than trusting the caller, exactly
    /// as the grant path re-reads it to check scope and TTL.
    ///
    /// The three-outcome shape makes this a *new* way to be wrong, which is why
    /// it gets its own test: a grant's disagreement with its decision is
    /// structural (wrong scope, over-long lifetime), while a denial's is one
    /// string against another.
    #[test]
    fn a_denial_must_carry_the_reason_the_decision_recorded() {
        let log = std::sync::Arc::new(AuditLog::open_in_memory().unwrap());
        let s = sample_session();
        log.open_session(&s).unwrap();
        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "write access to o/n is not on the writable-repos allowlist".into(),
        };
        let begin = |request_id| {
            log.begin_effect::<HostMintAuditTable>(&PreMintRecord {
                request_id,
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(1_700_000_100),
                request: &req,
                decision: &decision,
            })
            .unwrap()
        };

        // A different sentence — even a plausible-looking summary of the same
        // refusal — is refused.
        let mismatched = RequestId::new();
        let err = begin(mismatched)
            .complete(&HostMintOutcome::Denied {
                request_id: mismatched,
                denied_at: UnixMillis::from_millis(1_700_000_110),
                reason: "not on the allowlist",
            })
            .unwrap_err();
        assert!(
            matches!(
                err,
                AuditError::Invariant("denial reason != decision reason")
            ),
            "got: {err:?}",
        );
        assert!(
            log.list_mint_denials_for_session(s.session_id)
                .unwrap()
                .is_empty(),
        );

        // Non-vacuity: the very same shape, with the recorded reason, lands.
        let matching = RequestId::new();
        begin(matching)
            .complete(&HostMintOutcome::Denied {
                request_id: matching,
                denied_at: UnixMillis::from_millis(1_700_000_110),
                reason: "write access to o/n is not on the writable-repos allowlist",
            })
            .unwrap();
        assert_eq!(
            log.list_mint_denials_for_session(s.session_id)
                .unwrap()
                .len(),
            1,
        );
    }

    /// An empty mint-failure message is not a legitimate audit row —
    /// replay couldn't distinguish it from a missing error.
    #[test]
    fn record_mint_failure_rejects_empty_error() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(0),
        )
        .unwrap();
        let err = log
            .record_mint_failure(request_id, UnixMillis::from_millis(5), "")
            .unwrap_err();
        assert!(matches!(err, AuditError::Invariant(_)), "got: {err:?}");
    }

    /// A closed session must not accumulate new pre-mint rows —
    /// otherwise its `closed_at` no longer bounds the session's activity
    /// window, which is the whole point of recording a close timestamp.
    /// The check has to live inside `record_pre_mint`'s transaction
    /// (belt) and inside a DB trigger (braces); this exercise covers
    /// the belt.
    #[test]
    fn record_pre_mint_rejects_write_against_closed_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_050))
            .unwrap();

        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        let err = pre_mint(
            &log,
            RequestId::new(),
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant("session is closed")),
            "got: {err:?}"
        );
    }

    /// Same rule applies to Deny rows: a closed session must not
    /// accumulate any new request rows at all, not just Grant ones.
    #[test]
    fn record_pre_mint_rejects_deny_against_closed_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_050))
            .unwrap();

        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "any".into(),
        };
        let err = pre_mint(
            &log,
            RequestId::new(),
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant("session is closed")),
            "got: {err:?}"
        );
    }

    /// The core fix: a CloseSession that lands *after* `record_pre_mint`
    /// commits but *before* the backend mint finishes must not prevent
    /// the broker from appending the resulting grant. The authority to
    /// mint was established when the pre-mint row committed; the grant
    /// is its truthful outcome and belongs in the log.
    #[test]
    fn record_grant_succeeds_when_session_closed_after_pre_mint() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();

        // Simulate CloseSession landing during the mint's `await`.
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_150))
            .unwrap();

        let grant = CredentialGrant {
            jti: Jti::new(),
            request_id,
            session_id: s.session_id,
            github_app_id: Some(42),
            scope: sample_scope(),
            issued_at: UnixMillis::from_millis(1_700_000_200),
            expires_at: UnixMillis::from_millis(1_700_000_500),
        };
        log.record_grant(&grant).unwrap();
        assert_eq!(
            log.list_grants_for_session(s.session_id).unwrap(),
            vec![grant]
        );
    }

    /// Symmetrical guarantee for the failure side: if the mint fails
    /// after the session has been closed, the failure must still be
    /// recorded — the broker accepted the request and called GitHub.
    #[test]
    fn record_mint_failure_succeeds_when_session_closed_after_pre_mint() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let request_id = RequestId::new();
        let req = sample_request();
        let decision = PolicyDecision::Grant {
            scope: sample_scope(),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        pre_mint(
            &log,
            request_id,
            s.session_id,
            &req,
            &decision,
            UnixMillis::from_millis(1_700_000_100),
        )
        .unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_150))
            .unwrap();

        log.record_mint_failure(
            request_id,
            UnixMillis::from_millis(1_700_000_200),
            "GitHub 503",
        )
        .unwrap();
    }

    /// A recorded audit row for an unknown session was previously
    /// caught only by the FK; `record_pre_mint` reports it explicitly so
    /// the error is readable rather than leaking SQLite's message.
    #[test]
    fn record_pre_mint_rejects_write_against_nonexistent_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let phantom = SessionId::new();
        let req = sample_request();
        let decision = PolicyDecision::Deny {
            reason: "any".into(),
        };
        let err = pre_mint(
            &log,
            RequestId::new(),
            phantom,
            &req,
            &decision,
            UnixMillis::from_millis(1),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuditError::Invariant("session does not exist")),
            "got: {err:?}"
        );
    }
}
