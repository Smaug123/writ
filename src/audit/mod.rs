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
mod agent_vm_network_health;
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
pub use agent_vm_network_health::AgentVmNetworkHealthEventRecord;
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

/// Whether an [`AuditLog`] is backed by a file or by `:memory:`. Only the
/// on-disk log runs the WAL/`synchronous` tuning; an in-memory log (the
/// pervasive test backing) has no journal to tune and must stay a plain
/// memory-journal DB.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Durability {
    Disk,
    Memory,
}

/// On-disk audit DBs run in WAL mode with `synchronous = NORMAL`: a committed
/// transaction appends to the write-ahead log and the DB is fsynced only at
/// checkpoint, not once per commit. This is what removes the
/// ~two-fsyncs-per-write tax that serialized every VM-facing nix-cache request
/// through the single audit connection — agent-VM provisioning was dominated by
/// it. WAL keeps a committed transaction durable across a `writd` crash (the WAL
/// is replayed on the next open); a host power-loss or kernel panic can still
/// lose transactions committed since the last checkpoint — the accepted
/// tradeoff for the audit log's write throughput.
///
/// `journal_mode = WAL` is persisted in the DB header, so it survives reopen; it
/// is re-issued on every open so an existing rollback-journal DB is upgraded in
/// place. If the backing filesystem cannot support WAL — its shared-memory
/// wal-index needs an mmap the VFS may not provide, a real risk on the virtiofs
/// mount that backs the broker-VM audit dir under `broker_placement = vm` —
/// SQLite silently keeps the prior mode. We detect that, keep the fully-durable
/// `synchronous = FULL` (NORMAL is only safe under WAL), and warn loudly rather
/// than run in a quietly less-durable rollback-journal + NORMAL combination.
fn configure_disk_durability(conn: &Connection) -> Result<(), AuditError> {
    // `PRAGMA journal_mode = WAL` returns the resulting mode as a row.
    let journal_mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if journal_mode.eq_ignore_ascii_case("wal") {
        conn.execute_batch("PRAGMA synchronous = NORMAL;")?;
    } else {
        tracing::warn!(
            journal_mode = %journal_mode,
            "audit DB could not enter WAL mode; keeping rollback journal with synchronous=FULL",
        );
        conn.execute_batch("PRAGMA synchronous = FULL;")?;
    }
    Ok(())
}

impl AuditLog {
    /// Open (or create) an on-disk audit log. The schema is brought up to
    /// the highest version this binary supports by running any missing
    /// migrations in order.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let mut conn = Connection::open(path)?;
        Self::init(&mut conn, Durability::Disk)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// In-memory audit log, for tests.
    pub fn open_in_memory() -> Result<Self, AuditError> {
        let mut conn = Connection::open_in_memory()?;
        Self::init(&mut conn, Durability::Memory)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn init(conn: &mut Connection, durability: Durability) -> Result<(), AuditError> {
        // SQLite foreign_keys is per-connection and defaults to OFF, so the
        // REFERENCES clauses in the schema would otherwise be
        // parsed-and-ignored and orphan `request`/`grant_log` rows could
        // slip in. Must be set outside a transaction.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        if durability == Durability::Disk {
            configure_disk_durability(conn)?;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn pragma_string(log: &AuditLog, pragma: &str) -> String {
        log.with_conn(|c| Ok(c.query_row(&format!("PRAGMA {pragma}"), [], |r| r.get(0))?))
            .unwrap()
    }

    fn pragma_int(log: &AuditLog, pragma: &str) -> i64 {
        log.with_conn(|c| Ok(c.query_row(&format!("PRAGMA {pragma}"), [], |r| r.get(0))?))
            .unwrap()
    }

    #[test]
    fn on_disk_open_uses_wal_and_synchronous_normal() {
        // WAL turns the per-commit fsync of the rollback journal into an append
        // that fsyncs only at checkpoint; synchronous=NORMAL (== 1) is the safe
        // companion under WAL. Together they are what takes the ~2×fsync tax off
        // every audit write (the agent-VM provisioning hot path).
        let db = NamedTempFile::new().unwrap();
        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(
            pragma_string(&log, "journal_mode").to_ascii_lowercase(),
            "wal"
        );
        assert_eq!(
            pragma_int(&log, "synchronous"),
            1,
            "expected synchronous=NORMAL (1)"
        );
    }

    #[test]
    fn wal_data_survives_a_clean_reopen() {
        // A row committed under WAL by the first connection must be visible after
        // the log is dropped (checkpointed on close) and reopened.
        use crate::audit::test_support::sample_session;
        let db = NamedTempFile::new().unwrap();
        let s = sample_session();
        {
            let log = AuditLog::open(db.path()).unwrap();
            log.open_session(&s).unwrap();
        }
        let log = AuditLog::open(db.path()).unwrap();
        assert!(
            log.get_session(s.session_id).unwrap().is_some(),
            "session written under WAL must survive a clean reopen",
        );
    }

    #[test]
    fn in_memory_open_is_not_forced_into_wal() {
        // The WAL/synchronous config is disk-only; an in-memory log opens as a
        // plain memory-journal DB (regression guard so the disk path can't leak
        // a warning or a wrong-pragma into the pervasive in-memory test opens).
        let log = AuditLog::open_in_memory().unwrap();
        assert_eq!(
            pragma_string(&log, "journal_mode").to_ascii_lowercase(),
            "memory"
        );
    }
}
