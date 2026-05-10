//! Schema migrations for the audit log.
//!
//! Migrations are append-only — see the [`Migration`] doc for the
//! invariants that govern this list. The compile-time `const _:` block
//! below this list verifies the constants stay in sync; do not split
//! the assertion away from the migration list it asserts about.

use rusqlite::Connection;

use super::AuditError;

/// One versioned schema change. Migrations are applied in order; each
/// one advances `PRAGMA user_version` to its own `version` when it
/// commits, so a partial run (process killed mid-migration) resumes
/// cleanly at the next open.
///
/// Rules for adding a new migration:
///   1. Append a new entry with `version = SCHEMA_VERSION + 1`.
///   2. Bump [`SCHEMA_VERSION`].
///   3. Never edit a migration that has shipped — write another one.
///   4. Never renumber. Versions are append-only, like the audit log they
///      manage.
pub(super) struct Migration {
    /// The schema version the DB is at *after* this migration commits.
    pub(super) version: i32,
    pub(super) sql: &'static str,
}

/// Highest schema version this binary knows how to read. An on-disk DB at
/// a version higher than this is rejected with [`AuditError::SchemaTooNew`]
/// rather than opened — we'd rather fail to start than silently drop data
/// into a schema a newer broker wrote.
pub(super) const SCHEMA_VERSION: i32 = 12;

/// The full migration history. Each entry documents exactly one state
/// transition; the sequence of entries is the schema's lineage. Order
/// matters and must be strictly ascending in `version`.
pub(super) const MIGRATIONS: &[Migration] = &[
    // Initial schema. The two outcome tables (`grant_log` and
    // `mint_failure`) are kept separate from `request` so the broker can
    // pre-record a request before awaiting GitHub and append the outcome
    // once the mint completes, while leaving `request` strictly
    // append-only. Triggers enforce that:
    //   - `request` rows can only be inserted while the referenced
    //     session is open — belt-and-braces for the FK, which can say
    //     "session exists" but not "is open", preserving `closed_at`
    //     as a meaningful activity-window bound.
    //   - a given `request_id` has at most one outcome row (grant xor
    //     mint_failure), so replay never sees contradictory outcomes.
    Migration {
        version: 1,
        sql: r#"
CREATE TABLE session (
    session_id  TEXT PRIMARY KEY,
    label       TEXT,
    agent_model TEXT,
    opened_at   INTEGER NOT NULL,
    closed_at   INTEGER
);

CREATE TABLE request (
    request_id    TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES session(session_id),
    received_at   INTEGER NOT NULL,
    request_json  TEXT NOT NULL,
    decision_json TEXT NOT NULL
);

CREATE INDEX idx_request_session ON request(session_id, received_at);

CREATE TABLE grant_log (
    jti         TEXT PRIMARY KEY,
    request_id  TEXT NOT NULL REFERENCES request(request_id),
    session_id  TEXT NOT NULL REFERENCES session(session_id),
    scope_json  TEXT NOT NULL,
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE INDEX idx_grant_session ON grant_log(session_id, issued_at);

CREATE TABLE mint_failure (
    request_id   TEXT PRIMARY KEY REFERENCES request(request_id),
    failed_at    INTEGER NOT NULL,
    failure_json TEXT NOT NULL
);

CREATE TRIGGER request_requires_open_session
BEFORE INSERT ON request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;

CREATE TRIGGER mint_failure_excludes_grant
BEFORE INSERT ON mint_failure
WHEN EXISTS (SELECT 1 FROM grant_log WHERE request_id = NEW.request_id)
BEGIN
    SELECT RAISE(ABORT, 'grant already recorded for this request');
END;

CREATE TRIGGER grant_excludes_mint_failure
BEFORE INSERT ON grant_log
WHEN EXISTS (SELECT 1 FROM mint_failure WHERE request_id = NEW.request_id)
BEGIN
    SELECT RAISE(ABORT, 'mint failure already recorded for this request');
END;
"#,
    },
    Migration {
        version: 2,
        sql: r#"
CREATE TABLE nix_cache_request (
    request_id   TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES session(session_id),
    received_at  INTEGER NOT NULL,
    method       TEXT NOT NULL,
    target       TEXT NOT NULL,
    route        TEXT NOT NULL CHECK (route IN ('cache_info', 'narinfo', 'unsupported')),
    decision     TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    deny_reason  TEXT,
    CHECK (
        (decision = 'allow' AND deny_reason IS NULL)
        OR (decision = 'deny' AND deny_reason IS NOT NULL AND deny_reason != '')
    )
);

CREATE INDEX idx_nix_cache_request_session
    ON nix_cache_request(session_id, received_at);

CREATE TABLE nix_cache_outcome (
    request_id     TEXT PRIMARY KEY REFERENCES nix_cache_request(request_id),
    completed_at   INTEGER NOT NULL,
    http_status    INTEGER NOT NULL CHECK (http_status BETWEEN 100 AND 599),
    upstream_url   TEXT,
    upstream_status INTEGER CHECK (upstream_status BETWEEN 100 AND 599),
    response_bytes INTEGER NOT NULL CHECK (response_bytes >= 0),
    error          TEXT CHECK (error IS NULL OR error != '')
);

CREATE TRIGGER nix_cache_request_requires_open_session
BEFORE INSERT ON nix_cache_request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
"#,
    },
    Migration {
        version: 3,
        sql: r#"
DROP TRIGGER nix_cache_request_requires_open_session;
DROP INDEX idx_nix_cache_request_session;

ALTER TABLE nix_cache_outcome RENAME TO nix_cache_outcome_v2;
ALTER TABLE nix_cache_request RENAME TO nix_cache_request_v2;

CREATE TABLE nix_cache_request (
    request_id   TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES session(session_id),
    received_at  INTEGER NOT NULL,
    method       TEXT NOT NULL,
    target       TEXT NOT NULL,
    route        TEXT NOT NULL CHECK (route IN ('cache_info', 'narinfo', 'nar', 'unsupported')),
    decision     TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    deny_reason  TEXT,
    CHECK (
        (decision = 'allow' AND deny_reason IS NULL)
        OR (decision = 'deny' AND deny_reason IS NOT NULL AND deny_reason != '')
    )
);

INSERT INTO nix_cache_request (
    request_id,
    session_id,
    received_at,
    method,
    target,
    route,
    decision,
    deny_reason
)
SELECT
    request_id,
    session_id,
    received_at,
    method,
    target,
    route,
    decision,
    deny_reason
FROM nix_cache_request_v2;

CREATE INDEX idx_nix_cache_request_session
    ON nix_cache_request(session_id, received_at);

CREATE TABLE nix_cache_outcome (
    request_id     TEXT PRIMARY KEY REFERENCES nix_cache_request(request_id),
    completed_at   INTEGER NOT NULL,
    http_status    INTEGER NOT NULL CHECK (http_status BETWEEN 100 AND 599),
    upstream_url   TEXT,
    upstream_status INTEGER CHECK (upstream_status BETWEEN 100 AND 599),
    response_bytes INTEGER NOT NULL CHECK (response_bytes >= 0),
    error          TEXT CHECK (error IS NULL OR error != '')
);

INSERT INTO nix_cache_outcome (
    request_id,
    completed_at,
    http_status,
    upstream_url,
    upstream_status,
    response_bytes,
    error
)
SELECT
    request_id,
    completed_at,
    http_status,
    upstream_url,
    upstream_status,
    response_bytes,
    error
FROM nix_cache_outcome_v2;

DROP TABLE nix_cache_outcome_v2;
DROP TABLE nix_cache_request_v2;

CREATE TRIGGER nix_cache_request_requires_open_session
BEFORE INSERT ON nix_cache_request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
"#,
    },
    Migration {
        version: 4,
        sql: r#"
ALTER TABLE session
    ADD COLUMN agent_kind TEXT CHECK (agent_kind IN ('claude', 'codex'));
"#,
    },
    Migration {
        version: 5,
        sql: r#"
ALTER TABLE grant_log
    ADD COLUMN github_app_id INTEGER CHECK (github_app_id IS NULL OR github_app_id >= 0);
"#,
    },
    Migration {
        version: 6,
        sql: r#"
CREATE TABLE agent_vm_workspace_bootstrap (
    session_id   TEXT PRIMARY KEY REFERENCES session(session_id),
    requested_at INTEGER NOT NULL,
    repo         TEXT NOT NULL CHECK (repo != ''),
    destination  TEXT NOT NULL CHECK (destination != ''),
    branch       TEXT NOT NULL CHECK (branch != ''),
    warm         TEXT NOT NULL CHECK (warm IN ('none', 'sources', 'devshell'))
);

CREATE TRIGGER agent_vm_workspace_bootstrap_requires_open_session
BEFORE INSERT ON agent_vm_workspace_bootstrap
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
"#,
    },
    Migration {
        version: 7,
        sql: r#"
CREATE TABLE agent_run (
    run_id                  TEXT PRIMARY KEY,
    session_id              TEXT NOT NULL REFERENCES session(session_id),
    requested_at            INTEGER NOT NULL,
    agent_kind              TEXT NOT NULL CHECK (agent_kind IN ('claude', 'codex')),
    prompt_bytes            INTEGER NOT NULL CHECK (prompt_bytes >= 0),
    prompt_sha256           TEXT NOT NULL CHECK (length(prompt_sha256) = 64),
    prompt_redacted_preview TEXT NOT NULL CHECK (prompt_redacted_preview != '')
);

CREATE TABLE agent_run_outcome (
    run_id           TEXT PRIMARY KEY REFERENCES agent_run(run_id),
    completed_at     INTEGER NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('succeeded', 'failed')),
    exit_code        INTEGER NOT NULL,
    stdout_path      TEXT NOT NULL CHECK (stdout_path != ''),
    stdout_bytes     INTEGER NOT NULL CHECK (stdout_bytes >= 0),
    stdout_sha256    TEXT NOT NULL CHECK (length(stdout_sha256) = 64),
    stdout_truncated INTEGER NOT NULL CHECK (stdout_truncated IN (0, 1)),
    stderr_path      TEXT NOT NULL CHECK (stderr_path != ''),
    stderr_bytes     INTEGER NOT NULL CHECK (stderr_bytes >= 0),
    stderr_sha256    TEXT NOT NULL CHECK (length(stderr_sha256) = 64),
    stderr_truncated INTEGER NOT NULL CHECK (stderr_truncated IN (0, 1))
);

CREATE TRIGGER agent_run_requires_open_session
BEFORE INSERT ON agent_run
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
"#,
    },
    Migration {
        version: 8,
        sql: r#"
CREATE TABLE git_push_request (
    push_request_id      TEXT PRIMARY KEY,
    session_id           TEXT NOT NULL REFERENCES session(session_id),
    received_at          INTEGER NOT NULL,
    repo                 TEXT NOT NULL CHECK (repo != ''),
    branch               TEXT NOT NULL CHECK (branch != ''),
    expected_remote_head TEXT NOT NULL CHECK (length(expected_remote_head) = 40),
    new_head             TEXT NOT NULL CHECK (length(new_head) = 40)
);

CREATE INDEX idx_git_push_request_session
    ON git_push_request(session_id, received_at);

CREATE TABLE git_push_attempt (
    push_attempt_id      TEXT PRIMARY KEY,
    push_request_id      TEXT NOT NULL UNIQUE REFERENCES git_push_request(push_request_id),
    capability_request_id TEXT NOT NULL REFERENCES request(request_id),
    grant_jti            TEXT NOT NULL REFERENCES grant_log(jti),
    planned_at           INTEGER NOT NULL,
    repo                 TEXT NOT NULL CHECK (repo != ''),
    branch               TEXT NOT NULL CHECK (branch != ''),
    old_head             TEXT NOT NULL CHECK (length(old_head) = 40),
    new_head             TEXT NOT NULL CHECK (length(new_head) = 40)
);

CREATE TABLE git_push_outcome (
    push_request_id TEXT PRIMARY KEY REFERENCES git_push_request(push_request_id),
    push_attempt_id TEXT REFERENCES git_push_attempt(push_attempt_id),
    completed_at    INTEGER NOT NULL,
    result          TEXT NOT NULL CHECK (
        result IN (
            'denied',
            'validation_failed',
            'pushed',
            'lease_rejected',
            'push_rejected',
            'push_failed',
            'audit_failed_after_push'
        )
    ),
    github_status   INTEGER CHECK (github_status BETWEEN 100 AND 599),
    message         TEXT NOT NULL CHECK (message != ''),
    CHECK (
        (result IN ('denied', 'validation_failed') AND push_attempt_id IS NULL)
        OR (
            result IN (
                'pushed',
                'lease_rejected',
                'push_rejected',
                'push_failed',
                'audit_failed_after_push'
            )
            AND push_attempt_id IS NOT NULL
        )
    )
);

CREATE TRIGGER git_push_request_requires_open_session
BEFORE INSERT ON git_push_request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;

CREATE TRIGGER git_push_attempt_requires_matching_grant
BEFORE INSERT ON git_push_attempt
WHEN NOT EXISTS (
    SELECT 1 FROM grant_log
    WHERE jti = NEW.grant_jti AND request_id = NEW.capability_request_id
)
BEGIN
    SELECT RAISE(ABORT, 'git push grant does not match capability request');
END;

CREATE TRIGGER git_push_outcome_attempt_matches_request
BEFORE INSERT ON git_push_outcome
WHEN NEW.push_attempt_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM git_push_attempt
    WHERE push_attempt_id = NEW.push_attempt_id
      AND push_request_id = NEW.push_request_id
)
BEGIN
    SELECT RAISE(ABORT, 'git push attempt belongs to a different request');
END;
"#,
    },
    Migration {
        version: 9,
        sql: r#"
CREATE TABLE claude_proxy_request (
    request_id  TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES session(session_id),
    received_at INTEGER NOT NULL,
    method      TEXT NOT NULL CHECK (method != ''),
    target      TEXT NOT NULL CHECK (target != ''),
    route       TEXT NOT NULL CHECK (route IN ('messages', 'count_tokens', 'unsupported')),
    decision    TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    deny_reason TEXT,
    CHECK (
        (decision = 'allow' AND deny_reason IS NULL)
        OR (decision = 'deny' AND deny_reason IS NOT NULL AND deny_reason != '')
    )
);

CREATE INDEX idx_claude_proxy_request_session
    ON claude_proxy_request(session_id, received_at);

CREATE TABLE claude_proxy_outcome (
    request_id      TEXT PRIMARY KEY REFERENCES claude_proxy_request(request_id),
    completed_at    INTEGER NOT NULL,
    http_status     INTEGER NOT NULL CHECK (http_status BETWEEN 100 AND 599),
    upstream_url    TEXT,
    upstream_status INTEGER CHECK (upstream_status BETWEEN 100 AND 599),
    response_bytes  INTEGER NOT NULL CHECK (response_bytes >= 0),
    error           TEXT CHECK (error IS NULL OR error != '')
);

CREATE TRIGGER claude_proxy_request_requires_open_session
BEFORE INSERT ON claude_proxy_request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
"#,
    },
    Migration {
        version: 10,
        sql: r#"
DROP TRIGGER claude_proxy_request_requires_open_session;
DROP INDEX idx_claude_proxy_request_session;

ALTER TABLE claude_proxy_outcome RENAME TO claude_proxy_outcome_v9;
ALTER TABLE claude_proxy_request RENAME TO claude_proxy_request_v9;

CREATE TABLE claude_proxy_request (
    request_id  TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES session(session_id),
    received_at INTEGER NOT NULL,
    method      TEXT NOT NULL CHECK (method != ''),
    target      TEXT NOT NULL CHECK (target != ''),
    route       TEXT NOT NULL CHECK (route IN ('messages', 'count_tokens', 'models', 'unsupported')),
    decision    TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    deny_reason TEXT,
    CHECK (
        (decision = 'allow' AND deny_reason IS NULL)
        OR (decision = 'deny' AND deny_reason IS NOT NULL AND deny_reason != '')
    )
);

INSERT INTO claude_proxy_request (
    request_id,
    session_id,
    received_at,
    method,
    target,
    route,
    decision,
    deny_reason
)
SELECT
    request_id,
    session_id,
    received_at,
    method,
    target,
    route,
    decision,
    deny_reason
FROM claude_proxy_request_v9;

CREATE INDEX idx_claude_proxy_request_session
    ON claude_proxy_request(session_id, received_at);

CREATE TABLE claude_proxy_outcome (
    request_id      TEXT PRIMARY KEY REFERENCES claude_proxy_request(request_id),
    completed_at    INTEGER NOT NULL,
    http_status     INTEGER NOT NULL CHECK (http_status BETWEEN 100 AND 599),
    upstream_url    TEXT,
    upstream_status INTEGER CHECK (upstream_status BETWEEN 100 AND 599),
    response_bytes  INTEGER NOT NULL CHECK (response_bytes >= 0),
    error           TEXT CHECK (error IS NULL OR error != '')
);

INSERT INTO claude_proxy_outcome (
    request_id,
    completed_at,
    http_status,
    upstream_url,
    upstream_status,
    response_bytes,
    error
)
SELECT
    request_id,
    completed_at,
    http_status,
    upstream_url,
    upstream_status,
    response_bytes,
    error
FROM claude_proxy_outcome_v9;

DROP TABLE claude_proxy_outcome_v9;
DROP TABLE claude_proxy_request_v9;

CREATE TRIGGER claude_proxy_request_requires_open_session
BEFORE INSERT ON claude_proxy_request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
"#,
    },
    Migration {
        version: 11,
        sql: r#"
CREATE TABLE openai_proxy_request (
    request_id  TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES session(session_id),
    received_at INTEGER NOT NULL,
    method      TEXT NOT NULL CHECK (method != ''),
    target      TEXT NOT NULL CHECK (target != ''),
    route       TEXT NOT NULL CHECK (route IN ('responses', 'response_cancel', 'models', 'unsupported')),
    decision    TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    deny_reason TEXT,
    CHECK (
        (decision = 'allow' AND deny_reason IS NULL)
        OR (decision = 'deny' AND deny_reason IS NOT NULL AND deny_reason != '')
    )
);

CREATE INDEX idx_openai_proxy_request_session
    ON openai_proxy_request(session_id, received_at);

CREATE TABLE openai_proxy_outcome (
    request_id      TEXT PRIMARY KEY REFERENCES openai_proxy_request(request_id),
    completed_at    INTEGER NOT NULL,
    http_status     INTEGER NOT NULL CHECK (http_status BETWEEN 100 AND 599),
    upstream_url    TEXT,
    upstream_status INTEGER CHECK (upstream_status BETWEEN 100 AND 599),
    response_bytes  INTEGER NOT NULL CHECK (response_bytes >= 0),
    error           TEXT CHECK (error IS NULL OR error != '')
);

CREATE TRIGGER openai_proxy_request_requires_open_session
BEFORE INSERT ON openai_proxy_request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
"#,
    },
    // The host-staging push model never contacts GitHub during the agent
    // request. It needs three things the v8 schema can't express:
    //   - `staged` as a terminal unattempted outcome (the bundle has been
    //     parked for human review; no attempt was ever planned),
    //   - `git_push_request.expected_remote_head` nullable, so the agent
    //     can declare "I'm creating this branch; there is no upstream
    //     head to compare against" without lying via a sentinel,
    //   - `git_push_attempt.old_head` nullable, so the eventual promote
    //     path can plan a branch-creation push and the audit row faithfully
    //     records "no `--force-with-lease` target".
    // SQLite can't ALTER COLUMN to drop NOT NULL, so the three git_push_*
    // tables are rebuilt as `_v8` shadows, the data is copied in, and the
    // shadows are dropped — same shape as migration 10.
    Migration {
        version: 12,
        sql: r#"
DROP TRIGGER git_push_request_requires_open_session;
DROP TRIGGER git_push_attempt_requires_matching_grant;
DROP TRIGGER git_push_outcome_attempt_matches_request;
DROP INDEX idx_git_push_request_session;

ALTER TABLE git_push_outcome RENAME TO git_push_outcome_v8;
ALTER TABLE git_push_attempt RENAME TO git_push_attempt_v8;
ALTER TABLE git_push_request RENAME TO git_push_request_v8;

CREATE TABLE git_push_request (
    push_request_id      TEXT PRIMARY KEY,
    session_id           TEXT NOT NULL REFERENCES session(session_id),
    received_at          INTEGER NOT NULL,
    repo                 TEXT NOT NULL CHECK (repo != ''),
    branch               TEXT NOT NULL CHECK (branch != ''),
    expected_remote_head TEXT CHECK (expected_remote_head IS NULL OR length(expected_remote_head) = 40),
    new_head             TEXT NOT NULL CHECK (length(new_head) = 40)
);

INSERT INTO git_push_request (
    push_request_id,
    session_id,
    received_at,
    repo,
    branch,
    expected_remote_head,
    new_head
)
SELECT
    push_request_id,
    session_id,
    received_at,
    repo,
    branch,
    expected_remote_head,
    new_head
FROM git_push_request_v8;

CREATE INDEX idx_git_push_request_session
    ON git_push_request(session_id, received_at);

CREATE TABLE git_push_attempt (
    push_attempt_id       TEXT PRIMARY KEY,
    push_request_id       TEXT NOT NULL UNIQUE REFERENCES git_push_request(push_request_id),
    capability_request_id TEXT NOT NULL REFERENCES request(request_id),
    grant_jti             TEXT NOT NULL REFERENCES grant_log(jti),
    planned_at            INTEGER NOT NULL,
    repo                  TEXT NOT NULL CHECK (repo != ''),
    branch                TEXT NOT NULL CHECK (branch != ''),
    old_head              TEXT CHECK (old_head IS NULL OR length(old_head) = 40),
    new_head              TEXT NOT NULL CHECK (length(new_head) = 40)
);

INSERT INTO git_push_attempt (
    push_attempt_id,
    push_request_id,
    capability_request_id,
    grant_jti,
    planned_at,
    repo,
    branch,
    old_head,
    new_head
)
SELECT
    push_attempt_id,
    push_request_id,
    capability_request_id,
    grant_jti,
    planned_at,
    repo,
    branch,
    old_head,
    new_head
FROM git_push_attempt_v8;

CREATE TABLE git_push_outcome (
    push_request_id TEXT PRIMARY KEY REFERENCES git_push_request(push_request_id),
    push_attempt_id TEXT REFERENCES git_push_attempt(push_attempt_id),
    completed_at    INTEGER NOT NULL,
    result          TEXT NOT NULL CHECK (
        result IN (
            'denied',
            'validation_failed',
            'staged',
            'pushed',
            'lease_rejected',
            'push_rejected',
            'push_failed',
            'audit_failed_after_push'
        )
    ),
    github_status   INTEGER CHECK (github_status BETWEEN 100 AND 599),
    message         TEXT NOT NULL CHECK (message != ''),
    CHECK (
        (result IN ('denied', 'validation_failed', 'staged') AND push_attempt_id IS NULL)
        OR (
            result IN (
                'pushed',
                'lease_rejected',
                'push_rejected',
                'push_failed',
                'audit_failed_after_push'
            )
            AND push_attempt_id IS NOT NULL
        )
    )
);

INSERT INTO git_push_outcome (
    push_request_id,
    push_attempt_id,
    completed_at,
    result,
    github_status,
    message
)
SELECT
    push_request_id,
    push_attempt_id,
    completed_at,
    result,
    github_status,
    message
FROM git_push_outcome_v8;

DROP TABLE git_push_outcome_v8;
DROP TABLE git_push_attempt_v8;
DROP TABLE git_push_request_v8;

CREATE TRIGGER git_push_request_requires_open_session
BEFORE INSERT ON git_push_request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;

CREATE TRIGGER git_push_attempt_requires_matching_grant
BEFORE INSERT ON git_push_attempt
WHEN NOT EXISTS (
    SELECT 1 FROM grant_log
    WHERE jti = NEW.grant_jti AND request_id = NEW.capability_request_id
)
BEGIN
    SELECT RAISE(ABORT, 'git push grant does not match capability request');
END;

CREATE TRIGGER git_push_outcome_attempt_matches_request
BEFORE INSERT ON git_push_outcome
WHEN NEW.push_attempt_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM git_push_attempt
    WHERE push_attempt_id = NEW.push_attempt_id
      AND push_request_id = NEW.push_request_id
)
BEGIN
    SELECT RAISE(ABORT, 'git push attempt belongs to a different request');
END;
"#,
    },
];

// Belt-and-braces: the compile-time shape of MIGRATIONS is the source
// of truth, so verify it matches SCHEMA_VERSION at compile time rather
// than trust two constants to stay in sync by convention. A release
// build with the constants out of sync (new SCHEMA_VERSION without a
// matching migration, or a non-ascending version list) would otherwise
// silently produce a broker that either runs migrations in the wrong
// order (rolling `user_version` backwards) or never runs the new one at
// all. These `const` blocks are evaluated by the compiler; no runtime
// cost, no way to ship past them.
const _: () = {
    assert!(
        !MIGRATIONS.is_empty(),
        "MIGRATIONS must contain at least one entry"
    );
    assert!(
        MIGRATIONS[MIGRATIONS.len() - 1].version == SCHEMA_VERSION,
        "SCHEMA_VERSION must equal the last migration's version"
    );
    let mut i = 1;
    while i < MIGRATIONS.len() {
        assert!(
            MIGRATIONS[i - 1].version < MIGRATIONS[i].version,
            "migrations must be strictly ascending in version"
        );
        i += 1;
    }
};

pub(super) fn migrate(conn: &mut Connection) -> Result<(), AuditError> {
    let current = user_version(conn)?;

    if current > SCHEMA_VERSION {
        return Err(AuditError::SchemaTooNew {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }

    for m in MIGRATIONS.iter().filter(|m| m.version > current) {
        let tx = conn.transaction()?;
        tx.execute_batch(m.sql)?;
        tx.pragma_update(None, "user_version", m.version)?;
        tx.commit()?;
    }
    Ok(())
}

pub(super) fn user_version(conn: &Connection) -> Result<i32, AuditError> {
    Ok(conn.query_row("PRAGMA user_version", [], |row| row.get(0))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::audit::nix_cache::{
        NixCacheAuditDecision, NixCacheAuditRoute, NixCacheRequestRecord,
    };
    use crate::audit::test_support::{pre_mint, sample_request, sample_scope, sample_session};
    use crate::core::{Jti, PolicyDecision, RequestId, SessionId, UnixMillis};
    use rusqlite::params;
    use tempfile::NamedTempFile;

    fn read_user_version(log: &AuditLog) -> i32 {
        log.with_conn(user_version).unwrap()
    }

    fn column_exists(log: &AuditLog, table: &str, column: &str) -> bool {
        log.with_conn(|c| {
            let mut stmt = c.prepare(&format!("PRAGMA table_info({table})"))?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                if name == column {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .unwrap()
    }

    fn trigger_exists(log: &AuditLog, name: &str) -> bool {
        log.with_conn(|c| {
            let count: i64 = c.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                params![name],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        })
        .unwrap()
    }

    fn record_nix_cache_request(
        log: &AuditLog,
        request_id: RequestId,
        session_id: SessionId,
        decision: &NixCacheAuditDecision,
        route: NixCacheAuditRoute,
    ) -> Result<(), AuditError> {
        log.record_nix_cache_request(&NixCacheRequestRecord {
            request_id,
            session_id,
            received_at: UnixMillis::from_millis(1_700_000_100),
            method: "GET",
            target: "/v1/nix/cache/nix-cache-info",
            route,
            decision,
        })
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

    #[test]
    fn fresh_install_is_at_current_schema_version() {
        let log = AuditLog::open_in_memory().unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "mint_failure", "request_id"));
        assert!(column_exists(&log, "session", "agent_kind"));
        assert!(column_exists(&log, "grant_log", "github_app_id"));
        assert!(trigger_exists(&log, "request_requires_open_session"));
        assert!(trigger_exists(&log, "mint_failure_excludes_grant"));
        assert!(trigger_exists(&log, "grant_excludes_mint_failure"));
        assert!(column_exists(&log, "nix_cache_request", "route"));
        assert!(column_exists(&log, "nix_cache_outcome", "upstream_status"));
        assert!(column_exists(
            &log,
            "agent_vm_workspace_bootstrap",
            "session_id"
        ));
        assert!(trigger_exists(
            &log,
            "nix_cache_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "agent_vm_workspace_bootstrap_requires_open_session"
        ));
        assert!(column_exists(&log, "agent_run", "prompt_sha256"));
        assert!(column_exists(&log, "agent_run_outcome", "stdout_path"));
        assert!(trigger_exists(&log, "agent_run_requires_open_session"));
        assert!(column_exists(
            &log,
            "git_push_request",
            "expected_remote_head"
        ));
        assert!(column_exists(&log, "git_push_attempt", "grant_jti"));
        assert!(column_exists(&log, "git_push_outcome", "result"));
        assert!(trigger_exists(
            &log,
            "git_push_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "git_push_attempt_requires_matching_grant"
        ));
        assert!(trigger_exists(
            &log,
            "git_push_outcome_attempt_matches_request"
        ));
        assert!(column_exists(&log, "claude_proxy_request", "route"));
        assert!(column_exists(
            &log,
            "claude_proxy_outcome",
            "upstream_status"
        ));
        assert!(trigger_exists(
            &log,
            "claude_proxy_request_requires_open_session"
        ));
        assert!(column_exists(&log, "openai_proxy_request", "route"));
        assert!(column_exists(
            &log,
            "openai_proxy_outcome",
            "upstream_status"
        ));
        assert!(trigger_exists(
            &log,
            "openai_proxy_request_requires_open_session"
        ));
    }

    #[test]
    fn open_initialises_empty_file_db_at_current_schema_version() {
        let db = NamedTempFile::new().unwrap();
        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "session", "session_id"));
        assert!(column_exists(&log, "session", "agent_kind"));
        assert!(column_exists(&log, "request", "decision_json"));
        assert!(column_exists(&log, "grant_log", "jti"));
        assert!(column_exists(&log, "grant_log", "github_app_id"));
        assert!(column_exists(&log, "mint_failure", "failure_json"));
        assert!(column_exists(&log, "nix_cache_request", "request_id"));
        assert!(column_exists(&log, "nix_cache_outcome", "request_id"));
        assert!(column_exists(&log, "agent_vm_workspace_bootstrap", "warm"));
        assert!(column_exists(&log, "agent_run", "prompt_redacted_preview"));
        assert!(column_exists(&log, "agent_run_outcome", "stderr_sha256"));
        assert!(column_exists(&log, "git_push_request", "new_head"));
        assert!(column_exists(&log, "git_push_attempt", "old_head"));
        assert!(column_exists(&log, "git_push_outcome", "message"));
        assert!(column_exists(&log, "claude_proxy_request", "request_id"));
        assert!(column_exists(
            &log,
            "claude_proxy_outcome",
            "response_bytes"
        ));
        assert!(column_exists(&log, "openai_proxy_request", "request_id"));
        assert!(column_exists(
            &log,
            "openai_proxy_outcome",
            "response_bytes"
        ));
        assert!(trigger_exists(&log, "request_requires_open_session"));
        assert!(trigger_exists(
            &log,
            "nix_cache_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "agent_vm_workspace_bootstrap_requires_open_session"
        ));
        assert!(trigger_exists(&log, "agent_run_requires_open_session"));
        assert!(trigger_exists(
            &log,
            "git_push_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "claude_proxy_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "openai_proxy_request_requires_open_session"
        ));
    }

    #[test]
    fn reopen_at_current_version_is_a_noop() {
        // The pragma check is what makes this cheap on startup; verify
        // re-running migrate on an already-current DB doesn't error and
        // doesn't bump the version past the supported max.
        let db = NamedTempFile::new().unwrap();
        {
            let log = AuditLog::open(db.path()).unwrap();
            assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        }
        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
    }

    #[test]
    fn open_migrates_v1_database_to_nix_cache_audit_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            tx.execute_batch(MIGRATIONS[0].sql).unwrap();
            tx.pragma_update(None, "user_version", 1).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "nix_cache_request", "decision"));
        assert!(column_exists(&log, "nix_cache_outcome", "response_bytes"));
        assert!(column_exists(&log, "session", "agent_kind"));
        assert!(column_exists(&log, "grant_log", "github_app_id"));
        assert!(column_exists(&log, "agent_vm_workspace_bootstrap", "repo"));
        assert!(column_exists(&log, "agent_run", "run_id"));
        assert!(column_exists(&log, "agent_run_outcome", "run_id"));
        assert!(trigger_exists(
            &log,
            "nix_cache_request_requires_open_session"
        ));
    }

    #[test]
    fn open_migrates_v2_database_to_nar_cache_audit_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            tx.execute_batch(MIGRATIONS[0].sql).unwrap();
            tx.execute_batch(MIGRATIONS[1].sql).unwrap();
            tx.pragma_update(None, "user_version", 2).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        record_nix_cache_request(
            &log,
            request_id,
            s.session_id,
            &NixCacheAuditDecision::Allow,
            NixCacheAuditRoute::Nar,
        )
        .unwrap();

        let entries = log
            .list_nix_cache_requests_for_session(s.session_id)
            .unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, NixCacheAuditRoute::Nar);
    }

    #[test]
    fn open_migrates_v4_grant_rows_without_github_app_id() {
        let db = NamedTempFile::new().unwrap();
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let jti = Jti::new();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(4) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 4).unwrap();
            tx.execute(
                "INSERT INTO session (session_id, label, agent_kind, agent_model, opened_at, closed_at) \
                 VALUES (?1, NULL, 'claude', NULL, 1, NULL)",
                params![session_id.as_uuid().to_string()],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO request (request_id, session_id, received_at, request_json, decision_json) \
                 VALUES (?1, ?2, 2, '{}', '{}')",
                params![
                    request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                ],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO grant_log (jti, request_id, session_id, scope_json, issued_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, 3, 4)",
                params![
                    jti.as_uuid().to_string(),
                    request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                    serde_json::to_string(&sample_scope()).unwrap(),
                ],
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "grant_log", "github_app_id"));
        let grant = log.get_grant(jti).unwrap().unwrap();
        assert_eq!(grant.github_app_id, None);
    }

    #[test]
    fn open_migrates_v5_database_to_agent_vm_workspace_bootstrap_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(5) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 5).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(
            &log,
            "agent_vm_workspace_bootstrap",
            "destination"
        ));
        assert!(trigger_exists(
            &log,
            "agent_vm_workspace_bootstrap_requires_open_session"
        ));
    }

    #[test]
    fn open_migrates_v6_database_to_agent_run_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(6) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 6).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "agent_run", "prompt_sha256"));
        assert!(column_exists(&log, "agent_run_outcome", "stdout_path"));
        assert!(trigger_exists(&log, "agent_run_requires_open_session"));
    }

    #[test]
    fn open_migrates_v7_database_to_git_push_audit_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(7) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 7).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "git_push_request", "repo"));
        assert!(column_exists(
            &log,
            "git_push_attempt",
            "capability_request_id"
        ));
        assert!(column_exists(&log, "git_push_outcome", "github_status"));
        assert!(trigger_exists(
            &log,
            "git_push_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "git_push_attempt_requires_matching_grant"
        ));
        assert!(trigger_exists(
            &log,
            "git_push_outcome_attempt_matches_request"
        ));
    }

    #[test]
    fn open_migrates_v8_database_to_claude_proxy_audit_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(8) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 8).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "claude_proxy_request", "target"));
        assert!(column_exists(&log, "claude_proxy_outcome", "http_status"));
        assert!(trigger_exists(
            &log,
            "claude_proxy_request_requires_open_session"
        ));
    }

    #[test]
    fn open_migrates_v10_database_to_openai_proxy_audit_schema() {
        let db = NamedTempFile::new().unwrap();
        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(10) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 10).unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();

        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "openai_proxy_request", "target"));
        assert!(column_exists(&log, "openai_proxy_outcome", "http_status"));
        assert!(trigger_exists(
            &log,
            "openai_proxy_request_requires_open_session"
        ));
    }

    /// Migration 12 rebuilds the three `git_push_*` tables to relax
    /// `NOT NULL` on `expected_remote_head` / `old_head` and to admit
    /// the `'staged'` outcome. Verify pre-existing v11 rows survive
    /// the rebuild and that the new permissions take effect.
    #[test]
    fn open_migrates_v11_database_to_relaxed_git_push_heads_schema() {
        let db = NamedTempFile::new().unwrap();
        let session_id = SessionId::new();
        let capability_request_id = RequestId::new();
        let grant_jti = Jti::new();
        let pre_existing_push_request_id = RequestId::new();
        let pre_existing_push_attempt_id = RequestId::new();
        let oid_a = "a".repeat(40);
        let oid_b = "b".repeat(40);

        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(11) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 11).unwrap();

            tx.execute(
                "INSERT INTO session (session_id, label, agent_kind, agent_model, opened_at, closed_at) \
                 VALUES (?1, NULL, 'claude', NULL, 1, NULL)",
                params![session_id.as_uuid().to_string()],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO request (request_id, session_id, received_at, request_json, decision_json) \
                 VALUES (?1, ?2, 2, '{}', '{}')",
                params![
                    capability_request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                ],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO grant_log \
                 (jti, request_id, session_id, scope_json, issued_at, expires_at, github_app_id) \
                 VALUES (?1, ?2, ?3, ?4, 3, 4, 42)",
                params![
                    grant_jti.as_uuid().to_string(),
                    capability_request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                    serde_json::to_string(&sample_scope()).unwrap(),
                ],
            )
            .unwrap();

            tx.execute(
                "INSERT INTO git_push_request \
                 (push_request_id, session_id, received_at, repo, branch, expected_remote_head, new_head) \
                 VALUES (?1, ?2, ?3, 'o/n', 'main', ?4, ?5)",
                params![
                    pre_existing_push_request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                    1_700_000_100_i64,
                    oid_a,
                    oid_b,
                ],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO git_push_attempt \
                 (push_attempt_id, push_request_id, capability_request_id, grant_jti, planned_at, repo, branch, old_head, new_head) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 'o/n', 'main', ?6, ?7)",
                params![
                    pre_existing_push_attempt_id.as_uuid().to_string(),
                    pre_existing_push_request_id.as_uuid().to_string(),
                    capability_request_id.as_uuid().to_string(),
                    grant_jti.as_uuid().to_string(),
                    1_700_000_120_i64,
                    oid_a,
                    oid_b,
                ],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO git_push_outcome \
                 (push_request_id, push_attempt_id, completed_at, result, github_status, message) \
                 VALUES (?1, ?2, ?3, 'pushed', 200, 'ok')",
                params![
                    pre_existing_push_request_id.as_uuid().to_string(),
                    pre_existing_push_attempt_id.as_uuid().to_string(),
                    1_700_000_130_i64,
                ],
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);

        let preserved: (String, String, String) = log
            .with_conn(|c| {
                let row = c.query_row(
                    "SELECT r.expected_remote_head, a.old_head, o.result \
                     FROM git_push_request r \
                     JOIN git_push_attempt a USING (push_request_id) \
                     JOIN git_push_outcome o USING (push_request_id) \
                     WHERE r.push_request_id = ?1",
                    params![pre_existing_push_request_id.as_uuid().to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )?;
                Ok(row)
            })
            .unwrap();
        assert_eq!(preserved.0, "a".repeat(40));
        assert_eq!(preserved.1, "a".repeat(40));
        assert_eq!(preserved.2, "pushed");

        assert!(trigger_exists(
            &log,
            "git_push_request_requires_open_session"
        ));
        assert!(trigger_exists(
            &log,
            "git_push_attempt_requires_matching_grant"
        ));
        assert!(trigger_exists(
            &log,
            "git_push_outcome_attempt_matches_request"
        ));

        let new_request_id = RequestId::new();
        log.with_conn(|c| {
            c.execute(
                "INSERT INTO git_push_request \
                 (push_request_id, session_id, received_at, repo, branch, expected_remote_head, new_head) \
                 VALUES (?1, ?2, ?3, 'o/n', 'feat', NULL, ?4)",
                params![
                    new_request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                    1_700_000_140_i64,
                    "c".repeat(40),
                ],
            )?;
            c.execute(
                "INSERT INTO git_push_outcome \
                 (push_request_id, push_attempt_id, completed_at, result, github_status, message) \
                 VALUES (?1, NULL, ?2, 'staged', NULL, 'queued for review')",
                params![
                    new_request_id.as_uuid().to_string(),
                    1_700_000_141_i64,
                ],
            )?;
            Ok(())
        })
        .unwrap();
    }

    /// A DB written by a future broker will carry a user_version beyond
    /// what this binary knows. Refuse to open rather than risk silently
    /// ignoring columns the newer schema relies on.
    #[test]
    fn open_rejects_schema_newer_than_supported() {
        let db = NamedTempFile::new().unwrap();
        {
            // Build at current version, then tell the DB it's from the future.
            let _ = AuditLog::open(db.path()).unwrap();
            let c = Connection::open(db.path()).unwrap();
            c.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
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
