//! Audit log backed by SQLite.
//!
//! The log is the system-of-record for broker activity: every session,
//! every capability request, every credential grant, and every post-policy
//! mint failure lands here. The raw JSON for requests, decisions, scopes,
//! and mint failures is stored verbatim, so the log can be replayed to
//! reconstruct history without depending on the broker binary staying
//! source-compatible.
//!
//! The `request` and `grant_log` tables are strictly append-only: once a
//! row lands it is never mutated or deleted. This is the part that
//! matters for audit-integrity claims.
//!
//! The `session` table carries open/close timestamps and is updated by
//! `close_session`; `closed_at` moves from NULL to a fixed timestamp
//! exactly once, and a `request` row can only be written while the
//! referenced session is open. That constraint is what makes
//! `closed_at` a meaningful upper bound on the session's activity
//! window during post-hoc review — the per-grant rows in `grant_log`
//! are what get reconciled against observed side-effects, and those
//! never move.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;
use thiserror::Error;

mod agent_run;
mod claude_proxy;
mod flake_provision;
mod git_push;
mod grant;
mod nix_cache;
mod openai_proxy;
mod proxy_table;
mod schema;
mod session;
#[cfg(test)]
mod test_support;
mod validation;

pub use agent_run::{
    AgentRunAuditRecord, AgentRunOutcomeAuditRecord, AgentVmWorkspaceBootstrapAuditRecord,
};
pub use claude_proxy::{
    ClaudeProxyAuditDecision, ClaudeProxyAuditRoute, ClaudeProxyOutcomeRecord,
    ClaudeProxyRequestRecord,
};
pub use flake_provision::{
    FlakeProvisionAuditEntry, FlakeProvisionAuditOutcome, FlakeProvisionOutcomeRecord,
    FlakeProvisionRequestRecord, FlakeProvisionResult,
};
pub use git_push::{
    GitPushApproveAttemptEntry, GitPushApproveAttemptOutcome, GitPushApproveAttemptState,
    GitPushAuditEntry, GitPushOutcomeRecord, GitPushOutcomeResult, GitPushRequestRecord,
    GitPushResolution, GitPushResolutionEntry, GitPushResolutionRecord, PromoteMintAudit,
    ReconciliationTarget, RejectBlocker,
};
pub use grant::{MintFailureRecord, PreMintRecord};
pub use nix_cache::{
    NixCacheAuditDecision, NixCacheAuditEntry, NixCacheAuditRoute, NixCacheOutcomeRecord,
    NixCacheRequestRecord,
};
pub use openai_proxy::{
    OpenAiProxyAuditDecision, OpenAiProxyAuditRoute, OpenAiProxyOutcomeRecord,
    OpenAiProxyRequestRecord,
};
pub use proxy_table::ProxyAuditDecision;

/// `tracing` target stamped on every event emitted when an audit
/// append, read, or referenced-artifact write fails. The audit log is
/// the system-of-record for broker activity, so any failure to persist
/// or look up audit data is correctness-significant; operators should
/// alert on this target. Filter with
/// `RUST_LOG=writ.audit_write_failure=error`.
///
/// Each event carries a `kind` field naming the specific operation
/// that failed (e.g. `broker_grant`, `claude_proxy_outcome`,
/// `nix_cache_request`, `agent_run_log_directory`), plus an `error`
/// field with the underlying message and any per-site identifiers
/// (`jti`, `request_id`, `session_id`, `run_id`) that are in scope.
pub const AUDIT_WRITE_FAILURE_TARGET: &str = "writ.audit_write_failure";

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("internal lock poisoned")]
    Poisoned,

    /// Structural or cross-row audit invariant where the message names the
    /// failed relationship directly.
    #[error("invariant violated: {0}")]
    Invariant(&'static str),

    /// Field validation invariant where callers need the column or stream
    /// label alongside the reusable validation failure.
    #[error("invariant violated: {label}: {message}")]
    LabeledInvariant {
        label: &'static str,
        message: &'static str,
    },

    /// The on-disk schema was written by a newer broker than this binary
    /// knows how to read. Refusing to open is the correctness-over-
    /// availability call: a down-rev binary silently ignoring columns it
    /// doesn't understand is how audit logs lose data.
    #[error(
        "audit DB schema version {found} is newer than this binary supports (max {supported}); \
         upgrade the broker"
    )]
    SchemaTooNew { found: i32, supported: i32 },

    /// The on-disk schema_version registry records a migration name at
    /// `version` that disagrees with the in-code migration at that
    /// version. This is the signal that the DB was written by a binary
    /// whose migration list has since been re-arranged (e.g. a slice-G
    /// schema squash that renumbered post-plan migrations). Refusing
    /// to open is the only safe answer: pretending the DB is at this
    /// binary's `version` would skip migrations the new shape needs.
    /// Pre-v1, the resolution is to drop the DB and let `AuditLog::open`
    /// re-init from scratch.
    #[error(
        "audit DB schema history is incompatible with this binary: \
         version {version} on disk is {found_name:?} but this binary expects {expected_name:?}; \
         pre-v1 resolution is to drop the audit DB and let it re-init"
    )]
    SchemaHistoryMismatch {
        version: i32,
        found_name: String,
        expected_name: &'static str,
    },
}

pub struct AuditLog {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog").finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Open (or create) an on-disk audit log. The schema is brought up to
    /// the highest version this binary supports by running any missing
    /// migrations in order.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let mut conn = Connection::open(path)?;
        Self::init(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// In-memory audit log, for tests.
    pub fn open_in_memory() -> Result<Self, AuditError> {
        let mut conn = Connection::open_in_memory()?;
        Self::init(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn init(conn: &mut Connection) -> Result<(), AuditError> {
        // SQLite foreign_keys is per-connection and defaults to OFF, so the
        // REFERENCES clauses in the schema would otherwise be
        // parsed-and-ignored and orphan `request`/`grant_log` rows could
        // slip in. Must be set outside a transaction.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        schema::migrate(conn)
    }

    pub(super) fn with_conn<R>(
        &self,
        f: impl FnOnce(&Connection) -> Result<R, AuditError>,
    ) -> Result<R, AuditError> {
        let guard = self.conn.lock().map_err(|_| AuditError::Poisoned)?;
        f(&guard)
    }

    pub(super) fn with_conn_mut<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<R, AuditError>,
    ) -> Result<R, AuditError> {
        let mut guard = self.conn.lock().map_err(|_| AuditError::Poisoned)?;
        f(&mut guard)
    }
}
