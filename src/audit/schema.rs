//! Schema migrations for the audit log.
//!
//! The schema lives as a sequence of SQL migration files under
//! `migrations/`. Each is embedded with `include_str!` and recorded in
//! the [`MIGRATIONS`] list with its version number; the compile-time
//! `const _:` block below this list verifies the constants stay in
//! sync. Migrations are append-only — see [`Migration`] for the rules.
//!
//! At startup [`migrate`] walks pending migrations one at a time, each
//! inside a `BEGIN IMMEDIATE` transaction (SQLite's natural analogue
//! of an advisory lock — there is no `pg_advisory_lock` in SQLite, so
//! the lock is the transaction itself), and stamps the applied version
//! into the `schema_version` registry table. A process killed
//! mid-migration rolls back; the next open resumes from the last
//! committed version.

use std::time::SystemTime;

use rusqlite::Connection;
use rusqlite::TransactionBehavior;
use rusqlite::params;

use super::AuditError;

/// One versioned schema change. Migrations are applied in order; each
/// commit records its `version` in the `schema_version` registry
/// table, so a partial run (process killed mid-migration) resumes
/// cleanly at the next open.
///
/// Rules for adding a new migration:
///   1. Add `migrations/000N_<slug>.sql` (sequential `N`).
///   2. Append `Migration { version: SCHEMA_VERSION + 1, name: "000N_<slug>",
///      sql: include_str!("migrations/000N_<slug>.sql") }`.
///   3. Bump [`SCHEMA_VERSION`].
///   4. Never edit a migration that has shipped — write another one.
///   5. Never renumber. Versions are append-only, like the audit log
///      they manage.
pub(super) struct Migration {
    /// The schema version the DB is at *after* this migration commits.
    pub(super) version: i32,
    /// Human-readable migration slug. Recorded verbatim in
    /// `schema_version.name` so a `SELECT * FROM schema_version` reads
    /// like a changelog rather than a stack of bare integers.
    pub(super) name: &'static str,
    pub(super) sql: &'static str,
}

/// Highest schema version this binary knows how to read. An on-disk DB at
/// a version higher than this is rejected with [`AuditError::SchemaTooNew`]
/// rather than opened — we'd rather fail to start than silently drop data
/// into a schema a newer broker wrote.
pub(super) const SCHEMA_VERSION: i32 = 7;

/// The full migration history. Each entry documents exactly one state
/// transition; the sequence of entries is the schema's lineage. Order
/// must be strictly ascending and contiguous from 1 to [`SCHEMA_VERSION`].
pub(super) const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        // Renamed from "0001_initial" in slice G5: the v1 SQL was
        // squashed in place to drop plan-era tables and columns, so
        // a pre-G5 DB that records the bare "0001_initial" name now
        // has an incompatible on-disk shape. The `_v2` suffix makes
        // `verify_schema_history` reject those DBs at version 1
        // instead of resuming forward over a non-squashed base.
        name: "0001_initial_v2",
        sql: include_str!("migrations/0001_initial_v2.sql"),
    },
    Migration {
        version: 2,
        name: "0002_git_push_resolution_mint",
        sql: include_str!("migrations/0002_git_push_resolution_mint.sql"),
    },
    Migration {
        version: 3,
        name: "0003_approve_attempt_state_machine",
        sql: include_str!("migrations/0003_approve_attempt_state_machine.sql"),
    },
    Migration {
        version: 4,
        name: "0004_approve_attempt_reconciliation",
        sql: include_str!("migrations/0004_approve_attempt_reconciliation.sql"),
    },
    Migration {
        version: 5,
        name: "0005_flake_provision",
        sql: include_str!("migrations/0005_flake_provision.sql"),
    },
    Migration {
        version: 6,
        name: "0006_agent_vm_network_health",
        sql: include_str!("migrations/0006_agent_vm_network_health.sql"),
    },
    Migration {
        version: 7,
        name: "0007_approve_attempt_mint_ledger",
        sql: include_str!("migrations/0007_approve_attempt_mint_ledger.sql"),
    },
];

// Belt-and-braces: the compile-time shape of MIGRATIONS is the source
// of truth, so verify it matches SCHEMA_VERSION at compile time rather
// than trust two constants to stay in sync by convention. A release
// build with the constants out of sync (new SCHEMA_VERSION without a
// matching migration, a non-ascending version list, or a gap) would
// otherwise silently produce a broker that either runs migrations in
// the wrong order or never runs the new one at all.
const _: () = {
    assert!(
        !MIGRATIONS.is_empty(),
        "MIGRATIONS must contain at least one entry"
    );
    assert!(
        MIGRATIONS[0].version == 1,
        "first migration must be version 1"
    );
    assert!(
        MIGRATIONS[MIGRATIONS.len() - 1].version == SCHEMA_VERSION,
        "SCHEMA_VERSION must equal the last migration's version"
    );
    let mut i = 1;
    while i < MIGRATIONS.len() {
        assert!(
            MIGRATIONS[i - 1].version + 1 == MIGRATIONS[i].version,
            "migration versions must be contiguous and strictly ascending"
        );
        i += 1;
    }
};

/// Bring the audit DB up to [`SCHEMA_VERSION`], applying any pending
/// migrations in order.
///
/// Each migration runs inside its own `BEGIN IMMEDIATE` transaction.
/// SQLite has no `pg_advisory_lock`, but `BEGIN IMMEDIATE` acquires
/// the database's RESERVED lock immediately — a second writer racing
/// to migrate the same file gets `SQLITE_BUSY` and bails rather than
/// silently interleaving with us. Re-reading the version inside each
/// transaction means even if two migrators serialised on the lock,
/// the second observes the new version and resumes from there rather
/// than re-applying a migration the first already committed.
///
/// The lock is released between migrations: that's intentional, since
/// the daemon owning this DB is singleton via Unix-socket bind so
/// there is no contending writer in practice, and dropping the lock
/// between steps keeps a long migration sequence from holding a
/// global write lock for its entire duration.
pub(super) fn migrate(conn: &mut Connection) -> Result<(), AuditError> {
    ensure_schema_version_table(conn)?;
    verify_schema_history(conn)?;

    loop {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = current_version(&tx)?;

        if current > SCHEMA_VERSION {
            return Err(AuditError::SchemaTooNew {
                found: current,
                supported: SCHEMA_VERSION,
            });
        }
        if current == SCHEMA_VERSION {
            tx.commit()?;
            return Ok(());
        }

        let next = MIGRATIONS
            .iter()
            .find(|m| m.version == current + 1)
            .expect("MIGRATIONS covers 1..=SCHEMA_VERSION contiguously (compile-time asserted)");

        tx.execute_batch(next.sql)?;
        tx.execute(
            "INSERT INTO schema_version (version, name, applied_at_ms) VALUES (?1, ?2, ?3)",
            params![next.version, next.name, now_unix_ms()],
        )?;
        tx.commit()?;
    }
}

fn ensure_schema_version_table(conn: &Connection) -> Result<(), AuditError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version       INTEGER PRIMARY KEY NOT NULL CHECK(version >= 1),
            name          TEXT    NOT NULL,
            applied_at_ms INTEGER NOT NULL CHECK(applied_at_ms > 0)
         );",
    )?;
    Ok(())
}

/// Every recorded `schema_version.name` must match the in-code migration
/// at that version. A mismatch means the DB was written by a binary
/// whose migration list has since been re-arranged (e.g. the slice-G
/// schema squash that renumbered post-plan migrations from 0004→0002
/// etc.). Trusting the version number alone would silently treat an
/// old-shape DB as if the new migrations had already run, leaving the
/// DB missing tables and columns the new code expects. The audit log's
/// correctness-over-availability stance demands we refuse to open
/// rather than limp along on a half-migrated database.
fn verify_schema_history(conn: &Connection) -> Result<(), AuditError> {
    let mut stmt = conn.prepare("SELECT version, name FROM schema_version ORDER BY version")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, i32>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (version, found_name) = row?;
        if !(1..=SCHEMA_VERSION).contains(&version) {
            // A version outside `1..=SCHEMA_VERSION` is either future
            // (`SchemaTooNew` handles that downstream) or impossibly
            // low (`CHECK(version >= 1)` blocks that at write-time).
            // Leave it for the version-bound check rather than misclassify.
            continue;
        }
        let expected = MIGRATIONS
            .iter()
            .find(|m| m.version == version)
            .expect("MIGRATIONS covers 1..=SCHEMA_VERSION contiguously (compile-time asserted)");
        if expected.name != found_name {
            return Err(AuditError::SchemaHistoryMismatch {
                version,
                found_name,
                expected_name: expected.name,
            });
        }
    }
    Ok(())
}

pub(super) fn current_version(conn: &Connection) -> Result<i32, AuditError> {
    // Empty registry → 0 (nothing applied). The registry is contiguous
    // by construction (compile-time invariant), so MAX equals the
    // count and is also the highest applied version.
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?)
}

fn now_unix_ms() -> i64 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock before UNIX epoch");
    i64::try_from(now.as_millis()).expect("system clock past i64::MAX millis since epoch")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::audit::test_support::{pre_mint, sample_request, sample_session};
    use crate::core::{Jti, PolicyDecision, RequestId, SessionId, UnixMillis};
    use tempfile::NamedTempFile;

    #[test]
    fn fresh_open_is_at_current_schema_version() {
        let log = AuditLog::open_in_memory().unwrap();
        let v = log.with_conn(current_version).unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    /// Every entry in `MIGRATIONS` must record its `name` row in the
    /// `schema_version` registry after a fresh open. Walking the table
    /// rather than asserting against a single hardcoded version means
    /// future migrations don't need to revisit this test.
    #[test]
    fn fresh_open_records_migration_metadata() {
        let log = AuditLog::open_in_memory().unwrap();
        for migration in MIGRATIONS {
            let (name, applied_at_ms): (String, i64) = log
                .with_conn(|c| {
                    Ok(c.query_row(
                        "SELECT name, applied_at_ms FROM schema_version WHERE version = ?1",
                        params![migration.version],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?)
                })
                .unwrap();
            assert_eq!(name, migration.name);
            assert!(
                applied_at_ms > 0,
                "applied_at_ms should be a real timestamp for {}",
                migration.name
            );
        }
    }

    #[test]
    fn reopen_at_current_version_is_a_noop() {
        let db = NamedTempFile::new().unwrap();
        let first_applied_at_ms: i64 = {
            let log = AuditLog::open(db.path()).unwrap();
            log.with_conn(|c| {
                Ok(c.query_row(
                    "SELECT applied_at_ms FROM schema_version WHERE version = ?1",
                    params![SCHEMA_VERSION],
                    |row| row.get(0),
                )?)
            })
            .unwrap()
        };

        // Reopen — should observe one row per migration, unchanged.
        let log = AuditLog::open(db.path()).unwrap();
        let (count, applied_at_ms): (i64, i64) = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*), MAX(applied_at_ms) FROM schema_version",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?)
            })
            .unwrap();
        assert_eq!(
            count,
            MIGRATIONS.len() as i64,
            "no duplicate INSERT on reopen"
        );
        assert_eq!(
            applied_at_ms, first_applied_at_ms,
            "applied_at_ms is from the first apply, not a reapply"
        );
    }

    /// Regression net for the squash: enumerate the tables, indexes,
    /// and triggers the rest of the audit module relies on. If
    /// `0001_initial.sql` ever loses one, this fires before any
    /// downstream FK / business-logic test starts hunting for the
    /// root cause.
    #[test]
    fn applied_schema_contains_expected_tables_and_triggers() {
        let log = AuditLog::open_in_memory().unwrap();
        let names = |ty: &'static str| -> std::collections::BTreeSet<String> {
            log.with_conn(|c| {
                let mut stmt = c.prepare(
                    "SELECT name FROM sqlite_master WHERE type = ?1 AND name NOT LIKE 'sqlite_%'",
                )?;
                let mut rows = stmt.query(params![ty])?;
                let mut out = std::collections::BTreeSet::new();
                while let Some(row) = rows.next()? {
                    out.insert(row.get::<_, String>(0)?);
                }
                Ok(out)
            })
            .unwrap()
        };

        let tables = names("table");
        for expected in [
            "schema_version",
            "session",
            "request",
            "grant_log",
            "mint_failure",
            "agent_run",
            "agent_run_outcome",
            "agent_vm_workspace_bootstrap",
            "claude_proxy_request",
            "claude_proxy_outcome",
            "openai_proxy_request",
            "openai_proxy_outcome",
            "nix_cache_request",
            "nix_cache_outcome",
            "flake_provision_request",
            "flake_provision_outcome",
            "git_push_request",
            "git_push_outcome",
            "git_push_resolution",
            "git_push_approve_attempt",
            "git_push_approve_attempt_boot_observed",
            "agent_vm_network_health_event",
        ] {
            assert!(tables.contains(expected), "missing table: {expected}");
        }

        // Plan lifecycle tables were removed in slice G: bailiff owns
        // plan storage as git notes; the audit log no longer mirrors it.
        for forbidden in [
            "plan",
            "plan_decision",
            "plan_review",
            "plan_addendum",
            "plan_abort",
        ] {
            assert!(
                !tables.contains(forbidden),
                "plan-era table {forbidden} should have been dropped"
            );
        }

        let triggers = names("trigger");
        for expected in [
            "request_requires_open_session",
            "mint_failure_excludes_grant",
            "grant_excludes_mint_failure",
            "agent_run_requires_open_session",
            "agent_vm_workspace_bootstrap_requires_open_session",
            "claude_proxy_request_requires_open_session",
            "openai_proxy_request_requires_open_session",
            "nix_cache_request_requires_open_session",
            "flake_provision_request_requires_open_session",
            "agent_vm_network_health_event_requires_open_session",
            "git_push_request_requires_open_session",
            "git_push_resolution_requires_staged",
            "git_push_resolution_refuses_active_approve",
            "git_push_resolution_mint_matches_decision_insert",
            "git_push_resolution_mint_matches_decision_update",
            "git_push_approve_attempt_forward_only",
            "git_push_approve_attempt_mint_immutable",
            "git_push_approve_attempt_reconciliation_is_born_terminal",
            "git_push_approve_attempt_reconciliation_predecessor_eligible",
            "git_push_approve_attempt_reconciliation_same_push",
            "git_push_approve_attempt_reconciliation_uncertain_needs_boot_observed",
            "git_push_approve_attempt_supersedes_immutable",
        ] {
            assert!(triggers.contains(expected), "missing trigger: {expected}");
        }
    }

    /// A v1 DB that already carried a `decision = 'approved'` row
    /// cannot be upgraded — the new schema needs mint context that
    /// pre-upgrade rows lack. The v2 migration's defensive guard
    /// refuses the upgrade so an operator deliberately resolves the
    /// situation rather than discovering unreadable rows later. No
    /// shipped broker actually writes legacy approved rows, but the
    /// pre-v2 schema admitted them, so the guard is principled even
    /// if rarely triggered.
    #[test]
    fn v2_migration_refuses_legacy_approved_resolution_row() {
        let db = NamedTempFile::new().unwrap();
        // Build a v1 DB shape by hand: apply migration 1 directly
        // and stop. `AuditLog::open` would otherwise run v2 first.
        {
            let mut conn = Connection::open(db.path()).unwrap();
            ensure_schema_version_table(&conn).unwrap();
            for migration in MIGRATIONS.iter().take_while(|m| m.version < 2) {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                tx.execute_batch(migration.sql).unwrap();
                tx.execute(
                    "INSERT INTO schema_version (version, name, applied_at_ms) VALUES (?1, ?2, ?3)",
                    params![migration.version, migration.name, 1_i64],
                )
                .unwrap();
                tx.commit().unwrap();
            }

            // Plant a legacy 'approved' row by walking the audit chain
            // the v1 schema requires (session → request → staged
            // outcome → resolution) without going through the DAO,
            // which would reject the inconsistency at the type layer.
            let session_id = SessionId::new();
            conn.execute(
                "INSERT INTO session (session_id, opened_at, agent_kind) \
                 VALUES (?1, 1, 'claude')",
                params![session_id.as_uuid().to_string()],
            )
            .unwrap();
            let push_request_id = RequestId::new();
            conn.execute(
                "INSERT INTO git_push_request \
                 (push_request_id, session_id, received_at, repo, branch, \
                  expected_remote_head, new_head) \
                 VALUES (?1, ?2, 2, 'o/n', 'main', NULL, ?3)",
                params![
                    push_request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                    "a".repeat(40),
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO git_push_outcome \
                 (push_request_id, push_attempt_id, completed_at, result, \
                  github_status, message) \
                 VALUES (?1, NULL, 3, 'staged', NULL, 'queued')",
                params![push_request_id.as_uuid().to_string()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO git_push_resolution \
                 (push_request_id, decided_at, decision, operator, reason) \
                 VALUES (?1, 4, 'approved', 'alice', 'looks good')",
                params![push_request_id.as_uuid().to_string()],
            )
            .unwrap();
        }

        let err = AuditLog::open(db.path()).unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite CHECK error, got: {err:?}");
        };
        assert!(
            e.to_string().to_lowercase().contains("check"),
            "expected CHECK constraint failure, got: {e}"
        );

        // The v1 DB is unchanged: the migration aborted in a single
        // transaction. Reopening still observes schema_version = 1.
        let current = Connection::open(db.path())
            .unwrap()
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get::<_, i32>(0)
            })
            .unwrap();
        assert_eq!(current, 1);
    }

    /// A DB written by a future broker will carry a `schema_version`
    /// row beyond what this binary knows. Refuse to open rather than
    /// risk silently ignoring columns the newer schema relies on.
    #[test]
    fn open_rejects_schema_newer_than_supported() {
        let db = NamedTempFile::new().unwrap();
        {
            // Build at current version, then forge a future row.
            let _ = AuditLog::open(db.path()).unwrap();
            let c = Connection::open(db.path()).unwrap();
            c.execute(
                "INSERT INTO schema_version (version, name, applied_at_ms) VALUES (?1, ?2, ?3)",
                params![SCHEMA_VERSION + 1, "future_phantom", 1_i64],
            )
            .unwrap();
        }
        let err = AuditLog::open(db.path()).unwrap_err();
        match err {
            AuditError::SchemaTooNew { found, supported } => {
                assert_eq!(found, SCHEMA_VERSION + 1);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
    }

    /// A pre-G5 DB stopped at version 1 recorded the unsuffixed
    /// `0001_initial` name. Post-G5 the v1 migration was squashed in
    /// place and renamed `0001_initial_v2`, so the same recorded name
    /// now signals "DB is at the pre-squash v1 shape (plan tables
    /// present, `agent_run.stage`/`read_plan_id` still there)" rather
    /// than the new squashed shape. Refusing to open is required:
    /// blindly applying the renumbered 0002-0004 migrations over a
    /// pre-squash v1 base would leave the DB in a hybrid half-squashed
    /// state.
    #[test]
    fn open_rejects_pre_squash_v1_history() {
        let db = NamedTempFile::new().unwrap();
        {
            // We have to write the row manually rather than execute
            // pre-G5 SQL: the squash drops the old plan tables, so
            // simulating the *exact* old-v1 shape would require an
            // archived copy of the old 0001_initial.sql. The name
            // mismatch alone is what catches this on a real upgrade,
            // and that's what's under test.
            let conn = Connection::open(db.path()).unwrap();
            ensure_schema_version_table(&conn).unwrap();
            conn.execute(
                "INSERT INTO schema_version (version, name, applied_at_ms) VALUES (?1, ?2, ?3)",
                params![1, "0001_initial", 1_i64],
            )
            .unwrap();
        }
        let err = AuditLog::open(db.path()).unwrap_err();
        match err {
            AuditError::SchemaHistoryMismatch {
                version,
                found_name,
                expected_name,
            } => {
                assert_eq!(version, 1);
                assert_eq!(found_name, "0001_initial");
                assert_eq!(expected_name, "0001_initial_v2");
            }
            other => panic!("expected SchemaHistoryMismatch, got {other:?}"),
        }
    }

    /// A DB written by a pre-G5 binary that ran past v1 records a
    /// different `name` for at least one post-v1 version (the slice-G
    /// squash renumbered 0004-0006 → 0002-0004). Catching the v2
    /// mismatch is the same correctness story as the v1 case above,
    /// but the second-row check exercises the loop's "skip v1, fault
    /// on v2" path.
    #[test]
    fn open_rejects_schema_with_mismatched_post_v1_history() {
        let db = NamedTempFile::new().unwrap();
        {
            let conn = Connection::open(db.path()).unwrap();
            ensure_schema_version_table(&conn).unwrap();
            conn.execute(
                "INSERT INTO schema_version (version, name, applied_at_ms) VALUES (?1, ?2, ?3)",
                params![1, "0001_initial_v2", 1_i64],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO schema_version (version, name, applied_at_ms) VALUES (?1, ?2, ?3)",
                params![2, "0002_plan_addendum", 2_i64],
            )
            .unwrap();
        }
        let err = AuditLog::open(db.path()).unwrap_err();
        match err {
            AuditError::SchemaHistoryMismatch {
                version,
                found_name,
                expected_name,
            } => {
                assert_eq!(version, 2);
                assert_eq!(found_name, "0002_plan_addendum");
                assert_eq!(expected_name, "0002_git_push_resolution_mint");
            }
            other => panic!("expected SchemaHistoryMismatch, got {other:?}"),
        }
    }

    /// Counterpart to the rejection tests: a partially-migrated DB at
    /// v1 whose recorded row matches the in-code v1 migration name
    /// must still open and complete the remaining migrations.
    /// Otherwise the history check would refuse legitimate resumption
    /// after a process killed mid-migration sequence.
    #[test]
    fn open_resumes_when_recorded_history_matches() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            ensure_schema_version_table(&conn).unwrap();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            tx.execute_batch(MIGRATIONS[0].sql).unwrap();
            tx.execute(
                "INSERT INTO schema_version (version, name, applied_at_ms) VALUES (?1, ?2, ?3)",
                params![1, "0001_initial_v2", 1_i64],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        // `AuditLog::open` walks forward to SCHEMA_VERSION; nothing in
        // the v1 fixture conflicts with the post-v1 migrations.
        let _ = AuditLog::open(db.path()).unwrap();
        let current = Connection::open(db.path())
            .unwrap()
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get::<_, i32>(0)
            })
            .unwrap();
        assert_eq!(current, SCHEMA_VERSION);
    }

    /// Documents the lock contract: while another writer holds the
    /// DB's write lock, a fresh `AuditLog::open` against the same path
    /// surfaces SQLite's busy/locked error rather than silently
    /// interleaving with the holder. This is the "advisory lock"
    /// guarantee for the migration runner.
    #[test]
    fn migration_acquires_immediate_lock() {
        let db = NamedTempFile::new().unwrap();
        // Bring the DB up to current version once, then close.
        drop(AuditLog::open(db.path()).unwrap());

        // Hold a write lock on the same file from a separate connection.
        let blocker = Connection::open(db.path()).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

        // A second open must fail acquiring its own lock rather than
        // proceed past the busy holder.
        let err = AuditLog::open(db.path()).unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite busy/locked error, got: {err:?}");
        };
        let msg = e.to_string().to_lowercase();
        assert!(
            msg.contains("busy") || msg.contains("locked"),
            "expected busy/locked, got: {e}"
        );

        blocker.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn foreign_key_enforcement_rejects_orphan_grant_row() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        // Bypass `record` (which would block this at the application layer)
        // and write directly. The FK to `request(request_id)` must bite.
        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO grant_log (jti, request_id, session_id, scope_json, issued_at, expires_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        Jti::new().as_uuid().to_string(),
                        RequestId::new().as_uuid().to_string(), // no matching request row
                        s.session_id.as_uuid().to_string(),
                        "{}",
                        1_i64,
                        2_i64,
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite FK error, got: {err:?}");
        };
        let msg = e.to_string().to_lowercase();
        assert!(
            msg.contains("foreign key"),
            "expected FK violation, got: {e}"
        );
    }

    /// Same as above but for the `session_id` FK from `request`. Belt and
    /// braces — both FK paths matter.
    #[test]
    fn foreign_key_enforcement_rejects_orphan_request_row() {
        let log = AuditLog::open_in_memory().unwrap();
        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO request (request_id, session_id, received_at, request_json, decision_json) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        RequestId::new().as_uuid().to_string(),
                        SessionId::new().as_uuid().to_string(), // no matching session row
                        1_i64,
                        "{}",
                        "{}",
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite FK error, got: {err:?}");
        };
        assert!(
            e.to_string().to_lowercase().contains("foreign key"),
            "expected FK violation, got: {e}"
        );
    }

    /// `closed_at IS NULL` on the session row is the only audit-time
    /// guarantee that a session is open. The trigger refuses to add
    /// an audit row against a closed session even if the caller forgot
    /// to check.
    #[test]
    fn trigger_rejects_direct_insert_against_closed_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_050))
            .unwrap();

        let err = log
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO request (request_id, session_id, received_at, request_json, decision_json) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        RequestId::new().as_uuid().to_string(),
                        s.session_id.as_uuid().to_string(),
                        1_700_000_100_i64,
                        "{}",
                        "{}",
                    ],
                )?;
                Ok(())
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite trigger error, got: {err:?}");
        };
        assert!(
            e.to_string().to_lowercase().contains("session is closed"),
            "expected trigger message, got: {e}"
        );
    }

    /// An open session is still writable — a narrow regression test
    /// that the new trigger's `WHEN` clause doesn't accidentally fire
    /// when `closed_at IS NULL`.
    #[test]
    fn trigger_allows_insert_against_open_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        log.with_conn(|c| {
            c.execute(
                "INSERT INTO request (request_id, session_id, received_at, request_json, decision_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    RequestId::new().as_uuid().to_string(),
                    s.session_id.as_uuid().to_string(),
                    1_700_000_100_i64,
                    "{}",
                    "{}",
                ],
            )?;
            Ok(())
        })
        .unwrap();
    }

    /// Regression guard for the NUL-injection case in two flavours:
    ///
    /// 1. A TEXT-bound `"abc\0/"`. SQLite's `length()` and `GLOB` walk
    ///    TEXT as a C-string and stop at the first NUL, so without the
    ///    BLOB-length parity clause a CHECK that only inspected the
    ///    `abc` prefix would let this through.
    /// 2. A BLOB-bound `b"abc\0/"`. SQLite columns declared TEXT still
    ///    accept BLOB storage class, and on BLOBs `length()` returns
    ///    the byte count so the parity clause is vacuously true; only
    ///    the `typeof = 'text'` clause catches this path.
    ///
    /// In both cases the prefix `abc` is valid but the trailing `/`
    /// is not in `[A-Za-z0-9_-]`, exactly the shape the newtype
    /// rejects and the DAO read path would later trip on. Both tables
    /// share the expression, so verify both.
    #[test]
    fn correlation_id_check_rejects_embedded_nul() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let smuggled_text: &str = "abc\0/";
        let smuggled_blob: &[u8] = b"abc\0/";

        let agent_run_with_correlation = |raw_corr: rusqlite::types::Value| {
            log.with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO agent_run (
                         run_id, session_id, requested_at, agent_kind,
                         prompt_bytes, prompt_sha256, prompt_redacted_preview,
                         correlation_id
                     ) VALUES (?1, ?2, 10, 'claude', 1, ?3, '<redacted>', ?4)",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        s.session_id.as_uuid().to_string(),
                        "a".repeat(64),
                        raw_corr,
                    ],
                ))
            })
            .unwrap()
            .unwrap_err()
        };

        let push_with_correlation = |raw_corr: rusqlite::types::Value| {
            log.with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO git_push_request \
                     (push_request_id, session_id, received_at, repo, branch, expected_remote_head, new_head, correlation_id) \
                     VALUES (?1, ?2, 11, 'o/n', 'main', NULL, ?3, ?4)",
                    params![
                        RequestId::new().as_uuid().to_string(),
                        s.session_id.as_uuid().to_string(),
                        "b".repeat(40),
                        raw_corr,
                    ],
                ))
            })
            .unwrap()
            .unwrap_err()
        };

        for binding in [
            rusqlite::types::Value::Text(smuggled_text.to_owned()),
            rusqlite::types::Value::Blob(smuggled_blob.to_owned()),
        ] {
            let err = agent_run_with_correlation(binding.clone());
            assert!(err.to_string().contains("CHECK"), "got: {err}");
            let err = push_with_correlation(binding);
            assert!(err.to_string().contains("CHECK"), "got: {err}");
        }
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
