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
pub(super) const SCHEMA_VERSION: i32 = 20;

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
    // Stage B: operator resolutions of staged pushes.
    //
    // `git_push_outcome` is `PRIMARY KEY (push_request_id)` — exactly
    // one row per push, written by the broker when it decides whether
    // a push got denied / validation-failed / staged / pushed. That
    // leaves no room for a second row recording "the operator later
    // rejected or approved this staged push" without violating the PK
    // or mutating audit rows in place.
    //
    // The fix is a parallel table keyed by the same `push_request_id`
    // that records *operator* decisions. The append-only property is
    // preserved at every layer: outcomes are one-shot, resolutions are
    // one-shot, neither is updated. A trigger enforces that resolutions
    // can only be inserted on pushes whose outcome is `'staged'`, so a
    // `'denied'` or `'pushed'` push can never accumulate a contradictory
    // operator resolution and the state machine stays explicit.
    //
    // `decision` carries both `'rejected'` (Stage B) and `'approved'`
    // (Stage D) from day one so the eventual approve path doesn't need
    // another migration.
    Migration {
        version: 13,
        sql: r#"
CREATE TABLE git_push_resolution (
    push_request_id TEXT PRIMARY KEY REFERENCES git_push_request(push_request_id),
    decided_at      INTEGER NOT NULL,
    decision        TEXT NOT NULL CHECK (decision IN ('rejected', 'approved')),
    operator        TEXT NOT NULL CHECK (operator != ''),
    reason          TEXT NOT NULL CHECK (reason != '')
);

CREATE TRIGGER git_push_resolution_requires_staged
BEFORE INSERT ON git_push_resolution
WHEN NOT EXISTS (
    SELECT 1 FROM git_push_outcome
    WHERE push_request_id = NEW.push_request_id
      AND result = 'staged'
)
BEGIN
    SELECT RAISE(ABORT, 'git push must be staged to be resolved');
END;
"#,
    },
    // Correlation id metadata: an opaque caller-supplied identifier
    // that ties related agent runs and git pushes together. Per
    // `docs/plans/2026-05-11-agent-plans.md`, the broker validates as a
    // safe id (bounded length, restricted character class) and never
    // interprets the contents. The CHECK constraint mirrors the
    // `CorrelationId` newtype's invariants so a future code path that
    // skips the DAO's parse-don't-validate boundary still cannot land
    // a malformed id in the audit log. The GLOB pattern `*[^A-Za-z0-9_-]*`
    // matches any string containing at least one byte outside the
    // allowed class; `NOT GLOB` rejects it.
    //
    // The leading `typeof(correlation_id) = 'text'` and BLOB-length
    // parity clauses together form a NUL guard. SQLite's declared
    // column types are advisory: a TEXT column will happily store a
    // value with storage class BLOB if a raw writer binds bytes that
    // way, and `length()`/`GLOB` on TEXT stop at the first NUL byte.
    // Without these guards, a raw insert binding e.g. `b"abc\0/"`
    // (whether the binding is TEXT or BLOB) would pass a check that
    // only inspected the `abc` prefix — and then later reads would
    // fail when `CorrelationId::try_new` saw the full byte string.
    // `typeof = 'text'` forces TEXT storage class, and the BLOB-cast
    // length parity then forces the absence of embedded NULs, so the
    // GLOB and length bounds see the same bytes the newtype would.
    //
    // Existing rows are filled with NULL (the column accepts NULL
    // because the value is optional per the design).
    Migration {
        version: 14,
        sql: r#"
ALTER TABLE agent_run ADD COLUMN correlation_id TEXT
    CHECK (correlation_id IS NULL OR (
        typeof(correlation_id) = 'text'
        AND length(correlation_id) = length(cast(correlation_id AS BLOB))
        AND length(correlation_id) BETWEEN 1 AND 64
        AND correlation_id NOT GLOB '*[^A-Za-z0-9_-]*'
    ));

ALTER TABLE git_push_request ADD COLUMN correlation_id TEXT
    CHECK (correlation_id IS NULL OR (
        typeof(correlation_id) = 'text'
        AND length(correlation_id) = length(cast(correlation_id AS BLOB))
        AND length(correlation_id) BETWEEN 1 AND 64
        AND correlation_id NOT GLOB '*[^A-Za-z0-9_-]*'
    ));
"#,
    },
    // Plan submissions: per `docs/plans/2026-05-11-agent-plans.md`,
    // a planner agent_run records exactly one plan body for downstream
    // reviewers and implementers. The UNIQUE(agent_run_id) constraint
    // enforces the one-plan-per-run invariant at the database level so
    // a future code path that bypasses the DAO still cannot land a
    // duplicate.
    //
    // The body column stores the raw textual plan; body_sha256 is a
    // hex digest computed by the broker before insertion so consumers
    // can reference plans by content without rehashing. CHECK
    // constraints mirror `PlanBody`'s "non-empty" and the digest's
    // "64 hex chars" invariants from the Rust newtypes.
    //
    // The session-gating trigger mirrors the pattern already used for
    // agent_run and git_push_request: a plan can only be inserted
    // while its planner run's session is still open. The stage='plan'
    // gate (planner runs only) is intentionally deferred to a later
    // slice — adding it here would require coordinating with the
    // agent_run stage column and the broker's run-staging logic.
    Migration {
        version: 15,
        sql: r#"
CREATE TABLE plan (
    plan_id       TEXT PRIMARY KEY,
    agent_run_id  TEXT NOT NULL REFERENCES agent_run(run_id),
    submitted_at  INTEGER NOT NULL,
    body          TEXT NOT NULL CHECK (body != ''),
    body_sha256   TEXT NOT NULL CHECK (length(body_sha256) = 64),
    UNIQUE (agent_run_id)
);

CREATE INDEX idx_plan_agent_run ON plan(agent_run_id);

CREATE TRIGGER plan_requires_open_session
BEFORE INSERT ON plan
WHEN EXISTS (
    SELECT 1 FROM agent_run ar
    JOIN session s ON s.session_id = ar.session_id
    WHERE ar.run_id = NEW.agent_run_id AND s.closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
"#,
    },
    // Harden the `plan.body` CHECK. v15 only required `body != ''`,
    // which is weaker than `PlanBody`'s invariant in two ways:
    //
    //   1. SQLite's declared column type is advisory — a raw writer
    //      that binds bytes with storage class BLOB will satisfy `body
    //      != ''` even though `PlanBody::try_new` later refuses to
    //      parse the value. Without `typeof(body) = 'text'` the column
    //      can hold values the typed layer cannot read back.
    //   2. `length()` on a TEXT value walks the bytes as a C string and
    //      stops at the first NUL, so `length(body) BETWEEN 1 AND N`
    //      would happily admit `"a\0" || huge_blob`. Casting to BLOB
    //      and using `length(cast(body AS BLOB))` measures the full
    //      byte count, and `instr(cast(body AS BLOB), x'00') = 0`
    //      proves there is no embedded NUL anywhere in the payload.
    //
    // The upper bound mirrors `MAX_PLAN_BODY_BYTES` in `agent_plan.rs`
    // (256 KiB). It is intentionally redundant with `PlanBody::try_new`
    // — defence in depth so a future raw insert path cannot smuggle
    // megabyte-sized plans into the audit log.
    //
    // Nothing references `plan` via foreign key (the design has plan
    // as a leaf), so the standard SQLite table-recreation pattern
    // simplifies to: drop trigger/index, rename, create, copy, drop
    // old, restore index/trigger.
    //
    // The migration begins with a pre-flight guard. A v15 DB could
    // legitimately contain plan rows that violate the new invariants
    // (because the v15 CHECK was only `body != ''` and the old
    // `PlanBody::try_new` did not reject embedded NULs), and the
    // copy step would otherwise abort with a generic "CHECK
    // constraint failed" message. A temp trigger that RAISEs gives
    // the operator a targeted, actionable error and leaves the v15
    // schema untouched (the transaction rolls back).
    Migration {
        version: 16,
        sql: r#"
-- Pre-flight: a v15 DB could legitimately contain plan rows that
-- violate the new invariants (the v15 CHECK was only `body != ''`,
-- and `PlanBody::try_new` did not reject embedded NULs). If we just
-- ran the copy, SQLite would abort with a generic "CHECK constraint
-- failed: plan" message that does not say which invariant or which
-- row. A trigger that RAISEs explicitly gives the operator a
-- targeted message before the destructive recreate begins.
CREATE TEMP TABLE _plan_v16_preflight (sentinel INTEGER);
CREATE TEMP TRIGGER _plan_v16_preflight_guard
BEFORE INSERT ON _plan_v16_preflight
WHEN EXISTS (
    SELECT 1 FROM plan
    WHERE typeof(body) != 'text'
       OR length(cast(body AS BLOB)) > 262144
       OR instr(cast(body AS BLOB), x'00') != 0
)
BEGIN
    SELECT RAISE(
        ABORT,
        'migration 16: existing plan rows violate the hardened body invariants (BLOB storage class, embedded NUL byte, or body size > 262144 bytes); inspect and clean these rows before upgrading'
    );
END;
INSERT INTO _plan_v16_preflight VALUES (0);
DROP TRIGGER _plan_v16_preflight_guard;
DROP TABLE _plan_v16_preflight;

DROP TRIGGER plan_requires_open_session;
DROP INDEX idx_plan_agent_run;

ALTER TABLE plan RENAME TO plan_v15;

CREATE TABLE plan (
    plan_id       TEXT PRIMARY KEY,
    agent_run_id  TEXT NOT NULL REFERENCES agent_run(run_id),
    submitted_at  INTEGER NOT NULL,
    body          TEXT NOT NULL CHECK (
        typeof(body) = 'text'
        AND length(cast(body AS BLOB)) BETWEEN 1 AND 262144
        AND instr(cast(body AS BLOB), x'00') = 0
    ),
    body_sha256   TEXT NOT NULL CHECK (length(body_sha256) = 64),
    UNIQUE (agent_run_id)
);

-- Preserve `rowid` from the v15 table so `list_plans_for_session`'s
-- `ORDER BY submitted_at, rowid` tie-break stays stable across the
-- recreate. Without this, SQLite is free to assign fresh rowids and
-- ties in the same `submitted_at` would reorder after upgrade.
INSERT INTO plan (rowid, plan_id, agent_run_id, submitted_at, body, body_sha256)
SELECT rowid, plan_id, agent_run_id, submitted_at, body, body_sha256
FROM plan_v15;

DROP TABLE plan_v15;

CREATE INDEX idx_plan_agent_run ON plan(agent_run_id);

CREATE TRIGGER plan_requires_open_session
BEFORE INSERT ON plan
WHEN EXISTS (
    SELECT 1 FROM agent_run ar
    JOIN session s ON s.session_id = ar.session_id
    WHERE ar.run_id = NEW.agent_run_id AND s.closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
"#,
    },
    // Agent-run stage: per `docs/plans/2026-05-11-agent-plans.md`, every
    // agent run carries one of three roles in the plan/review/decide/
    // execute pipeline. The column is NOT NULL — every run has exactly
    // one role — and the CHECK mirrors the closed `Stage` enum on the
    // Rust side so a future code path that bypasses the DAO still cannot
    // land a malformed value.
    //
    // Pre-existing rows are backfilled in two passes. The ALTER fills
    // every row with `'execute'` (today's one-shot implementer flow,
    // which is exactly what `execute` will denote once the gate lands).
    // The follow-up UPDATE rewrites any run referenced by
    // `plan.agent_run_id` to `'plan'`: v16 (and v15 before it) already
    // accepted plan submissions and `plan` is the only ground-truth
    // signal that an existing run was a planner, so without this pass
    // the gate would later treat those runs as implementers and the
    // audit log would misclassify them. The DEFAULT serves only the
    // backfill; the DAO supplies the stage explicitly on every insert
    // so no in-app write relies on it.
    //
    // The `typeof(stage) = 'text'` guard prevents a raw caller from
    // smuggling a BLOB-bound value of the same byte content past the
    // `IN (...)` literal-text check. SQLite's affinity rules will not
    // coerce a BLOB to TEXT for the equality, but the guard makes the
    // intent explicit and matches the migration-14 pattern for safety.
    Migration {
        version: 17,
        sql: r#"
ALTER TABLE agent_run ADD COLUMN stage TEXT NOT NULL DEFAULT 'execute'
    CHECK (
        typeof(stage) = 'text'
        AND stage IN ('plan','review','execute')
    );

UPDATE agent_run
SET stage = 'plan'
WHERE run_id IN (SELECT agent_run_id FROM plan);
"#,
    },
    // Slice 6 (operator decision path). Adds the `plan_decision` table:
    // exactly one terminal decision row per plan. PRIMARY KEY on
    // `plan_id` enforces the uniqueness; the foreign key onto `plan`
    // means a decision can only be written for a plan that exists.
    //
    // Unlike `plan` itself, the decision is *not* gated by the planner
    // run's session being open. Operator decisions are deliberately
    // cross-session — by design the host CLI today (and a future
    // orchestrator agent tomorrow) may decide on a plan whose planner
    // VM and session are long gone. The plan FK is the only invariant
    // worth enforcing in the schema.
    //
    // `outcome` is the closed enum from `agent_plan::DecisionOutcome`;
    // its CHECK enumerates exactly the wire strings the newtype
    // produces. `decider` is a free-form attribution string bounded by
    // the same defence-in-depth pattern as the v16 `plan.body` CHECK
    // (TEXT storage class, no embedded NUL, byte-bounded by
    // `length(cast(... AS BLOB))`). The byte cap mirrors the
    // `MAX_DECIDER_BYTES` newtype bound; a raw INSERT that bypasses
    // the typed layer still cannot smuggle a giant or NUL-bearing
    // attribution into the audit log.
    Migration {
        version: 18,
        sql: r#"
CREATE TABLE plan_decision (
    -- TEXT PRIMARY KEY in a rowid table is a long-standing SQLite quirk:
    -- it does *not* imply NOT NULL (preserved for v1/v2 compat). NULL
    -- child keys also bypass the FK reference rule. Without an explicit
    -- NOT NULL, a raw INSERT with `plan_id = NULL` would slip past both
    -- guards and break the "exactly one decision per plan" invariant.
    plan_id     TEXT PRIMARY KEY NOT NULL REFERENCES plan(plan_id),
    decided_at  INTEGER NOT NULL,
    outcome     TEXT NOT NULL CHECK (outcome IN ('accepted', 'rejected_restart')),
    decider     TEXT NOT NULL CHECK (
        typeof(decider) = 'text'
        AND length(cast(decider AS BLOB)) BETWEEN 1 AND 256
        AND instr(cast(decider AS BLOB), x'00') = 0
    )
);
"#,
    },
    // Implementer/reviewer plan-binding: per
    // `docs/plans/2026-05-11-agent-plans.md`, a `review`- or
    // `execute`-stage run that is meant to read a specific plan carries
    // the target `plan_id` on its `agent_run` row. The VM HTTP plan-read
    // route (slice 4c) consults this column to authorise
    // `GET /v1/plans/<plan_id>`; persisting it on the audit row means a
    // future code path that bypasses the route still cannot retroactively
    // claim a different plan than the broker recorded at run start.
    //
    // Nullable: planner runs do not read a plan (they create one), and
    // pre-migration rows have no plan binding to recover. Backfill is
    // therefore implicit-NULL; no UPDATE pass is needed.
    //
    // FK to `plan(plan_id)` is enforced because `AuditLog::init` sets
    // `PRAGMA foreign_keys = ON` per-connection. The `typeof = 'text'`
    // guard prevents a raw caller from smuggling BLOB-storage-class
    // bytes past the FK (SQLite compares storage classes when matching
    // FKs, so a BLOB-bound UUID would never match the TEXT-typed
    // `plan.plan_id`, but the guard is explicit defence in depth and
    // matches the migration-14 / migration-17 pattern).
    Migration {
        version: 19,
        sql: r#"
ALTER TABLE agent_run ADD COLUMN read_plan_id TEXT NULL
    REFERENCES plan(plan_id)
    CHECK (read_plan_id IS NULL OR typeof(read_plan_id) = 'text');
"#,
    },
    // Slice 6 (reviewer verdicts). Adds the `plan_review` table:
    // zero-or-more reviewer rows per plan, each verdict attached to one
    // reviewer agent run. There can be many reviews per plan (different
    // reviewers, different rounds) but at most one review per reviewer
    // run — enforced by `UNIQUE(agent_run_id)` so a future code path
    // that bypasses the DAO cannot stuff a single reviewer with two
    // verdicts.
    //
    // Two triggers gate inserts:
    //
    //   * `plan_review_requires_open_session` — mirrors the
    //     `plan_requires_open_session` pattern. A review can only land
    //     while the reviewer's session is still open; once an operator
    //     closes the session no further verdicts can attach. Pairs with
    //     the existing session-window invariant.
    //
    //   * `plan_review_requires_reviewer_run` — verdicts belong to
    //     `review`-stage runs that explicitly read this plan: both
    //     `agent_run.stage = 'review'` and `agent_run.read_plan_id =
    //     NEW.plan_id` must hold. The route contract requires the same
    //     pair (`docs/plans/2026-05-11-agent-plans.md`, "POST
    //     /v1/plans/<plan_id>/reviews" → `run.stage = 'review' and
    //     run.read_plan_id = <plan_id>`); restating both in the trigger
    //     means even a raw INSERT cannot smuggle in a planner/executor
    //     row, a verdict against a different plan than the reviewer
    //     read, or a reviewer with no `read_plan_id` binding at all.
    //
    // `verdict` is the closed enum from `agent_plan::Verdict`; its CHECK
    // enumerates exactly the wire strings the newtype produces.
    // `feedback` is optional prose bounded by the same defence-in-depth
    // pattern as `plan.body` (TEXT storage class, no embedded NUL,
    // byte-bounded). The byte cap mirrors `MAX_PLAN_FEEDBACK_BYTES`
    // (64 KiB); a raw INSERT that bypasses the typed layer still cannot
    // smuggle an oversized or NUL-bearing feedback row into the audit
    // log. `feedback` and `feedback_sha256` always travel together — a
    // dedicated table-level CHECK enforces "both or neither" so a
    // future code path cannot persist a digest with no body or vice
    // versa.
    Migration {
        version: 20,
        sql: r#"
CREATE TABLE plan_review (
    -- TEXT PRIMARY KEY in a rowid table does not imply NOT NULL (the
    -- v1/v2 compat quirk also exploited by the plan_decision migration);
    -- mark explicitly so a raw INSERT with `review_id = NULL` cannot
    -- bypass the per-row uniqueness.
    review_id        TEXT PRIMARY KEY NOT NULL,
    plan_id          TEXT NOT NULL REFERENCES plan(plan_id),
    agent_run_id     TEXT NOT NULL REFERENCES agent_run(run_id),
    submitted_at     INTEGER NOT NULL,
    verdict          TEXT NOT NULL CHECK (
        typeof(verdict) = 'text'
        AND verdict IN ('approve', 'request_changes', 'reject')
    ),
    feedback         TEXT NULL CHECK (
        feedback IS NULL OR (
            typeof(feedback) = 'text'
            AND length(cast(feedback AS BLOB)) BETWEEN 1 AND 65536
            AND instr(cast(feedback AS BLOB), x'00') = 0
        )
    ),
    -- The digest must be exactly 64 lowercase hex chars in TEXT storage
    -- class; a BLOB binding, a 64-character non-hex value, or a value
    -- like `<64 hex chars>\0junk` would otherwise be silently accepted
    -- and then fail later inside the DAO read path
    -- (`plan_review_from_row` runs `validate_sha256_hex`).
    --
    -- The four clauses combine to make every byte of the stored value
    -- pass the hex test:
    --
    --   * `typeof = 'text'` rejects a BLOB binding (SQLite's declared
    --     column types are advisory — TEXT NULL accepts a BLOB unless
    --     this guard is present).
    --   * `length(cast AS BLOB) = length(...)` rejects any embedded
    --     NUL, because `length()` on TEXT stops at the first NUL while
    --     the BLOB length walks every byte.
    --   * `length(...) = 64` pins the size.
    --   * `NOT GLOB '*[^0-9a-f]*'` rejects any non-hex character.
    --
    -- Without the NUL parity guard, `length()` and `GLOB` only see the
    -- prefix before a NUL, so a value such as `'aa..aa\0junk'` would
    -- slip past the size and class checks and then be unreadable by
    -- the typed reader.
    feedback_sha256  TEXT NULL CHECK (
        feedback_sha256 IS NULL OR (
            typeof(feedback_sha256) = 'text'
            AND length(feedback_sha256) = length(cast(feedback_sha256 AS BLOB))
            AND length(feedback_sha256) = 64
            AND feedback_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    UNIQUE (agent_run_id),
    CHECK (
        (feedback IS NULL AND feedback_sha256 IS NULL)
        OR (feedback IS NOT NULL AND feedback_sha256 IS NOT NULL)
    )
);

CREATE INDEX idx_plan_review_plan ON plan_review(plan_id);

CREATE TRIGGER plan_review_requires_open_session
BEFORE INSERT ON plan_review
WHEN EXISTS (
    SELECT 1 FROM agent_run ar
    JOIN session s ON s.session_id = ar.session_id
    WHERE ar.run_id = NEW.agent_run_id AND s.closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;

CREATE TRIGGER plan_review_requires_reviewer_run
BEFORE INSERT ON plan_review
WHEN NOT EXISTS (
    SELECT 1 FROM agent_run ar
    WHERE ar.run_id = NEW.agent_run_id
      AND ar.stage = 'review'
      AND ar.read_plan_id = NEW.plan_id
)
BEGIN
    SELECT RAISE(ABORT,
        'plan_review requires agent_run.stage = ''review'' AND agent_run.read_plan_id = plan_id');
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

    /// Migration 13 adds the `git_push_resolution` table and its
    /// staged-only trigger. Verify pre-existing v12 rows survive, the
    /// trigger refuses resolutions on non-staged pushes, and a
    /// resolution on a staged push commits cleanly.
    #[test]
    fn open_migrates_v12_database_to_resolution_schema() {
        let db = NamedTempFile::new().unwrap();
        let session_id = SessionId::new();
        let pushed_request_id = RequestId::new();
        let pushed_attempt_id = RequestId::new();
        let staged_request_id = RequestId::new();
        let capability_request_id = RequestId::new();
        let grant_jti = Jti::new();
        let oid_a = "a".repeat(40);
        let oid_b = "b".repeat(40);
        let oid_c = "c".repeat(40);

        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(12) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 12).unwrap();

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

            // A terminally `pushed` push: must remain ineligible for
            // resolution after the migration.
            tx.execute(
                "INSERT INTO git_push_request \
                 (push_request_id, session_id, received_at, repo, branch, expected_remote_head, new_head) \
                 VALUES (?1, ?2, 10, 'o/n', 'main', ?3, ?4)",
                params![
                    pushed_request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                    oid_a,
                    oid_b,
                ],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO git_push_attempt \
                 (push_attempt_id, push_request_id, capability_request_id, grant_jti, planned_at, repo, branch, old_head, new_head) \
                 VALUES (?1, ?2, ?3, ?4, 20, 'o/n', 'main', ?5, ?6)",
                params![
                    pushed_attempt_id.as_uuid().to_string(),
                    pushed_request_id.as_uuid().to_string(),
                    capability_request_id.as_uuid().to_string(),
                    grant_jti.as_uuid().to_string(),
                    oid_a,
                    oid_b,
                ],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO git_push_outcome \
                 (push_request_id, push_attempt_id, completed_at, result, github_status, message) \
                 VALUES (?1, ?2, 30, 'pushed', 200, 'ok')",
                params![
                    pushed_request_id.as_uuid().to_string(),
                    pushed_attempt_id.as_uuid().to_string(),
                ],
            )
            .unwrap();

            // A `staged` push: the migration must leave it resolvable.
            tx.execute(
                "INSERT INTO git_push_request \
                 (push_request_id, session_id, received_at, repo, branch, expected_remote_head, new_head) \
                 VALUES (?1, ?2, 40, 'o/n', 'feat', NULL, ?3)",
                params![
                    staged_request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                    oid_c,
                ],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO git_push_outcome \
                 (push_request_id, push_attempt_id, completed_at, result, github_status, message) \
                 VALUES (?1, NULL, 50, 'staged', NULL, 'queued for review')",
                params![staged_request_id.as_uuid().to_string()],
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);

        // Pre-existing rows survived the migration intact.
        let preserved: String = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT result FROM git_push_outcome WHERE push_request_id = ?1",
                    params![pushed_request_id.as_uuid().to_string()],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(preserved, "pushed");

        // Trigger rejects resolutions on non-staged pushes.
        let blocked = log
            .with_conn(|c| {
                let err = c.execute(
                    "INSERT INTO git_push_resolution \
                     (push_request_id, decided_at, decision, operator, reason) \
                     VALUES (?1, 60, 'rejected', 'patrick', 'no')",
                    params![pushed_request_id.as_uuid().to_string()],
                );
                Ok(err)
            })
            .unwrap()
            .unwrap_err();
        let message = blocked.to_string();
        assert!(
            message.contains("git push must be staged to be resolved"),
            "got: {message}"
        );

        // Trigger rejects resolutions on requests with no outcome row.
        let no_outcome_request_id = RequestId::new();
        log.with_conn(|c| {
            c.execute(
                "INSERT INTO git_push_request \
                 (push_request_id, session_id, received_at, repo, branch, expected_remote_head, new_head) \
                 VALUES (?1, ?2, 70, 'o/n', 'orphan', NULL, ?3)",
                params![
                    no_outcome_request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                    "d".repeat(40),
                ],
            )?;
            Ok(())
        })
        .unwrap();
        let blocked_no_outcome = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO git_push_resolution \
                     (push_request_id, decided_at, decision, operator, reason) \
                     VALUES (?1, 71, 'rejected', 'patrick', 'no')",
                    params![no_outcome_request_id.as_uuid().to_string()],
                ))
            })
            .unwrap()
            .unwrap_err();
        assert!(
            blocked_no_outcome
                .to_string()
                .contains("git push must be staged to be resolved"),
            "got: {blocked_no_outcome}",
        );

        // Resolution on a staged push commits cleanly.
        log.with_conn(|c| {
            c.execute(
                "INSERT INTO git_push_resolution \
                 (push_request_id, decided_at, decision, operator, reason) \
                 VALUES (?1, 80, 'rejected', 'patrick', 'looks malicious')",
                params![staged_request_id.as_uuid().to_string()],
            )?;
            Ok(())
        })
        .unwrap();

        // Double-resolution violates the PK.
        let dup = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO git_push_resolution \
                     (push_request_id, decided_at, decision, operator, reason) \
                     VALUES (?1, 81, 'approved', 'patrick', 'changed mind')",
                    params![staged_request_id.as_uuid().to_string()],
                ))
            })
            .unwrap()
            .unwrap_err();
        assert!(dup.to_string().contains("UNIQUE"), "got: {dup}");

        // CHECK rejects unknown decisions.
        let other_staged_request_id = RequestId::new();
        log.with_conn(|c| {
            c.execute(
                "INSERT INTO git_push_request \
                 (push_request_id, session_id, received_at, repo, branch, expected_remote_head, new_head) \
                 VALUES (?1, ?2, 90, 'o/n', 'feat2', NULL, ?3)",
                params![
                    other_staged_request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                    "e".repeat(40),
                ],
            )?;
            c.execute(
                "INSERT INTO git_push_outcome \
                 (push_request_id, push_attempt_id, completed_at, result, github_status, message) \
                 VALUES (?1, NULL, 91, 'staged', NULL, 'queued for review')",
                params![other_staged_request_id.as_uuid().to_string()],
            )?;
            Ok(())
        })
        .unwrap();
        let bad_decision = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO git_push_resolution \
                     (push_request_id, decided_at, decision, operator, reason) \
                     VALUES (?1, 92, 'maybe', 'patrick', 'unsure')",
                    params![other_staged_request_id.as_uuid().to_string()],
                ))
            })
            .unwrap()
            .unwrap_err();
        assert!(
            bad_decision.to_string().contains("CHECK"),
            "got: {bad_decision}"
        );

        // Approved decision is admitted on a freshly staged push (Stage D
        // piggybacks on the v13 CHECK).
        log.with_conn(|c| {
            c.execute(
                "INSERT INTO git_push_resolution \
                 (push_request_id, decided_at, decision, operator, reason) \
                 VALUES (?1, 93, 'approved', 'patrick', 'lgtm')",
                params![other_staged_request_id.as_uuid().to_string()],
            )?;
            Ok(())
        })
        .unwrap();
    }

    /// Migration 14 adds `correlation_id` to `agent_run` and
    /// `git_push_request`. Verify the new columns exist with NULL for
    /// pre-existing rows (no rewrite), that valid values can be
    /// written, and that the CHECK constraint rejects malformed bytes.
    #[test]
    fn open_migrates_v13_database_to_correlation_id_schema() {
        let db = NamedTempFile::new().unwrap();
        let session_id = SessionId::new();
        let run_id = uuid::Uuid::new_v4();
        let push_request_id = RequestId::new();
        let oid_a = "a".repeat(40);

        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(13) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 13).unwrap();

            tx.execute(
                "INSERT INTO session (session_id, label, agent_kind, agent_model, opened_at, closed_at) \
                 VALUES (?1, NULL, 'claude', NULL, 1, NULL)",
                params![session_id.as_uuid().to_string()],
            )
            .unwrap();

            // Pre-migration agent_run row: must survive with a NULL
            // correlation_id once the column is added.
            tx.execute(
                "INSERT INTO agent_run (
                     run_id, session_id, requested_at, agent_kind,
                     prompt_bytes, prompt_sha256, prompt_redacted_preview
                 ) VALUES (?1, ?2, 2, 'claude', 1, ?3, '<redacted>')",
                params![
                    run_id.to_string(),
                    session_id.as_uuid().to_string(),
                    "a".repeat(64),
                ],
            )
            .unwrap();

            // Pre-migration git_push_request row: same expectation.
            tx.execute(
                "INSERT INTO git_push_request \
                 (push_request_id, session_id, received_at, repo, branch, expected_remote_head, new_head) \
                 VALUES (?1, ?2, 3, 'o/n', 'main', NULL, ?3)",
                params![
                    push_request_id.as_uuid().to_string(),
                    session_id.as_uuid().to_string(),
                    oid_a,
                ],
            )
            .unwrap();

            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);

        assert!(column_exists(&log, "agent_run", "correlation_id"));
        assert!(column_exists(&log, "git_push_request", "correlation_id"));

        let agent_run_value: Option<String> = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT correlation_id FROM agent_run WHERE run_id = ?1",
                    params![run_id.to_string()],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
        assert!(agent_run_value.is_none());

        let push_request_value: Option<String> = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT correlation_id FROM git_push_request WHERE push_request_id = ?1",
                    params![push_request_id.as_uuid().to_string()],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
        assert!(push_request_value.is_none());

        // A subsequent write with a well-formed correlation id is
        // accepted.
        let tagged_run_id = uuid::Uuid::new_v4();
        log.with_conn(|c| {
            c.execute(
                "INSERT INTO agent_run (
                     run_id, session_id, requested_at, agent_kind,
                     prompt_bytes, prompt_sha256, prompt_redacted_preview,
                     correlation_id
                 ) VALUES (?1, ?2, 4, 'claude', 1, ?3, '<redacted>', ?4)",
                params![
                    tagged_run_id.to_string(),
                    session_id.as_uuid().to_string(),
                    "b".repeat(64),
                    "good-id_42",
                ],
            )?;
            Ok(())
        })
        .unwrap();

        // CHECK rejects an empty string (length must be ≥ 1).
        let bad_empty = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO agent_run (
                         run_id, session_id, requested_at, agent_kind,
                         prompt_bytes, prompt_sha256, prompt_redacted_preview,
                         correlation_id
                     ) VALUES (?1, ?2, 5, 'claude', 1, ?3, '<redacted>', '')",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        session_id.as_uuid().to_string(),
                        "c".repeat(64),
                    ],
                ))
            })
            .unwrap()
            .unwrap_err();
        assert!(bad_empty.to_string().contains("CHECK"), "got: {bad_empty}");

        // CHECK rejects bytes outside the allowed `[A-Za-z0-9_-]` class.
        let bad_char = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO git_push_request \
                     (push_request_id, session_id, received_at, repo, branch, expected_remote_head, new_head, correlation_id) \
                     VALUES (?1, ?2, 6, 'o/n', 'main', NULL, ?3, ?4)",
                    params![
                        RequestId::new().as_uuid().to_string(),
                        session_id.as_uuid().to_string(),
                        "b".repeat(40),
                        "bad space",
                    ],
                ))
            })
            .unwrap()
            .unwrap_err();
        assert!(bad_char.to_string().contains("CHECK"), "got: {bad_char}");
    }

    /// Migration 15 adds the `plan` table. Verify a v14 DB with a
    /// populated agent_run survives the migration, that the table and
    /// its constraints are in place, and that the session-gating
    /// trigger is wired up.
    #[test]
    fn open_migrates_v14_database_to_plan_schema() {
        let db = NamedTempFile::new().unwrap();
        let session_id = SessionId::new();
        let run_id = uuid::Uuid::new_v4();

        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(14) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 14).unwrap();

            tx.execute(
                "INSERT INTO session (session_id, label, agent_kind, agent_model, opened_at, closed_at) \
                 VALUES (?1, NULL, 'claude', NULL, 1, NULL)",
                params![session_id.as_uuid().to_string()],
            )
            .unwrap();

            tx.execute(
                "INSERT INTO agent_run (
                     run_id, session_id, requested_at, agent_kind,
                     prompt_bytes, prompt_sha256, prompt_redacted_preview,
                     correlation_id
                 ) VALUES (?1, ?2, 2, 'claude', 1, ?3, '<redacted>', NULL)",
                params![
                    run_id.to_string(),
                    session_id.as_uuid().to_string(),
                    "a".repeat(64),
                ],
            )
            .unwrap();

            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "plan", "plan_id"));
        assert!(column_exists(&log, "plan", "agent_run_id"));
        assert!(column_exists(&log, "plan", "body_sha256"));
        assert!(trigger_exists(&log, "plan_requires_open_session"));

        let body_sha = crate::agent_run::sha256_hex(b"# Plan");
        let plan_id_a = uuid::Uuid::new_v4();
        log.with_conn(|c| {
            c.execute(
                "INSERT INTO plan
                 (plan_id, agent_run_id, submitted_at, body, body_sha256)
                 VALUES (?1, ?2, 3, '# Plan', ?3)",
                params![plan_id_a.to_string(), run_id.to_string(), &body_sha,],
            )?;
            Ok(())
        })
        .unwrap();

        // UNIQUE(agent_run_id) gates a second plan for the same run.
        let dup_err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan
                     (plan_id, agent_run_id, submitted_at, body, body_sha256)
                     VALUES (?1, ?2, 4, '# Plan v2', ?3)",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        run_id.to_string(),
                        &body_sha,
                    ],
                ))
            })
            .unwrap()
            .unwrap_err();
        assert!(
            dup_err.to_string().to_uppercase().contains("UNIQUE"),
            "got: {dup_err}",
        );

        // CHECK rejects an empty body.
        let empty_err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan
                     (plan_id, agent_run_id, submitted_at, body, body_sha256)
                     VALUES (?1, ?2, 5, '', ?3)",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        uuid::Uuid::new_v4().to_string(),
                        crate::agent_run::sha256_hex(b""),
                    ],
                ))
            })
            .unwrap()
            .unwrap_err();
        assert!(empty_err.to_string().contains("CHECK"), "got: {empty_err}");
    }

    /// Migration 16 hardens the `plan.body` CHECK from `body != ''` to
    /// the same `typeof = 'text' AND byte-bounded AND no embedded NUL`
    /// shape used for `correlation_id`. Existing rows must survive the
    /// table recreate, and the new CHECK must reject the three vectors
    /// the old one missed: BLOB-typed payloads, embedded NULs, and
    /// oversized bodies.
    #[test]
    fn open_migrates_v15_database_to_hardened_plan_body_check() {
        let db = NamedTempFile::new().unwrap();
        let session_id = SessionId::new();
        let run_id = uuid::Uuid::new_v4();
        let plan_id = uuid::Uuid::new_v4();
        let body = "# Plan\n\nBody text.";
        let body_sha = crate::agent_run::sha256_hex(body.as_bytes());

        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(15) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 15).unwrap();

            tx.execute(
                "INSERT INTO session (session_id, label, agent_kind, agent_model, opened_at, closed_at) \
                 VALUES (?1, NULL, 'claude', NULL, 1, NULL)",
                params![session_id.as_uuid().to_string()],
            )
            .unwrap();

            tx.execute(
                "INSERT INTO agent_run (
                     run_id, session_id, requested_at, agent_kind,
                     prompt_bytes, prompt_sha256, prompt_redacted_preview,
                     correlation_id
                 ) VALUES (?1, ?2, 2, 'claude', 1, ?3, '<redacted>', NULL)",
                params![
                    run_id.to_string(),
                    session_id.as_uuid().to_string(),
                    "a".repeat(64),
                ],
            )
            .unwrap();

            tx.execute(
                "INSERT INTO plan (plan_id, agent_run_id, submitted_at, body, body_sha256) \
                 VALUES (?1, ?2, 3, ?3, ?4)",
                params![plan_id.to_string(), run_id.to_string(), body, &body_sha],
            )
            .unwrap();

            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "plan", "plan_id"));
        assert!(trigger_exists(&log, "plan_requires_open_session"));

        // The pre-existing row survives the table recreate verbatim.
        let (got_body, got_sha): (String, String) = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT body, body_sha256 FROM plan WHERE plan_id = ?1",
                    params![plan_id.to_string()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )?)
            })
            .unwrap();
        assert_eq!(got_body, body);
        assert_eq!(got_sha, body_sha);

        // A fresh valid plan still inserts after the migration.
        let run_id_b = uuid::Uuid::new_v4();
        let plan_id_b = uuid::Uuid::new_v4();
        log.with_conn(|c| {
            c.execute(
                "INSERT INTO agent_run (
                     run_id, session_id, requested_at, agent_kind,
                     prompt_bytes, prompt_sha256, prompt_redacted_preview,
                     correlation_id
                 ) VALUES (?1, ?2, 4, 'claude', 1, ?3, '<redacted>', NULL)",
                params![
                    run_id_b.to_string(),
                    session_id.as_uuid().to_string(),
                    "a".repeat(64),
                ],
            )?;
            c.execute(
                "INSERT INTO plan (plan_id, agent_run_id, submitted_at, body, body_sha256) \
                 VALUES (?1, ?2, 5, ?3, ?4)",
                params![
                    plan_id_b.to_string(),
                    run_id_b.to_string(),
                    "ok body",
                    crate::agent_run::sha256_hex(b"ok body"),
                ],
            )?;
            Ok(())
        })
        .unwrap();

        // Three new vectors the v15 CHECK admitted are now rejected.
        let insert_plan = |run: uuid::Uuid, body: rusqlite::types::Value| {
            log.with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO plan (plan_id, agent_run_id, submitted_at, body, body_sha256) \
                     VALUES (?1, ?2, 6, ?3, ?4)",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        run.to_string(),
                        body,
                        "a".repeat(64),
                    ],
                ))
            })
            .unwrap()
            .unwrap_err()
        };

        // (a) TEXT-bound embedded NUL — `length()` on TEXT would have
        // stopped at the NUL and reported a length-1 string, passing
        // v15. The `instr(..., x'00')` clause inspects all bytes.
        let run_id_nul = uuid::Uuid::new_v4();
        log.with_conn(|c| {
            c.execute(
                "INSERT INTO agent_run (
                     run_id, session_id, requested_at, agent_kind,
                     prompt_bytes, prompt_sha256, prompt_redacted_preview,
                     correlation_id
                 ) VALUES (?1, ?2, 7, 'claude', 1, ?3, '<redacted>', NULL)",
                params![
                    run_id_nul.to_string(),
                    session_id.as_uuid().to_string(),
                    "a".repeat(64),
                ],
            )?;
            Ok(())
        })
        .unwrap();
        let err = insert_plan(
            run_id_nul,
            rusqlite::types::Value::Text("hi\0there".to_owned()),
        );
        assert!(err.to_string().contains("CHECK"), "got: {err}");

        // (b) BLOB-bound payload — the column is declared TEXT but
        // SQLite would still store a BLOB-classed value; only
        // `typeof = 'text'` catches this path.
        let run_id_blob = uuid::Uuid::new_v4();
        log.with_conn(|c| {
            c.execute(
                "INSERT INTO agent_run (
                     run_id, session_id, requested_at, agent_kind,
                     prompt_bytes, prompt_sha256, prompt_redacted_preview,
                     correlation_id
                 ) VALUES (?1, ?2, 8, 'claude', 1, ?3, '<redacted>', NULL)",
                params![
                    run_id_blob.to_string(),
                    session_id.as_uuid().to_string(),
                    "a".repeat(64),
                ],
            )?;
            Ok(())
        })
        .unwrap();
        let err = insert_plan(run_id_blob, rusqlite::types::Value::Blob(b"hello".to_vec()));
        assert!(err.to_string().contains("CHECK"), "got: {err}");

        // (c) Oversized body — v15 had no upper bound at all.
        let run_id_big = uuid::Uuid::new_v4();
        log.with_conn(|c| {
            c.execute(
                "INSERT INTO agent_run (
                     run_id, session_id, requested_at, agent_kind,
                     prompt_bytes, prompt_sha256, prompt_redacted_preview,
                     correlation_id
                 ) VALUES (?1, ?2, 9, 'claude', 1, ?3, '<redacted>', NULL)",
                params![
                    run_id_big.to_string(),
                    session_id.as_uuid().to_string(),
                    "a".repeat(64),
                ],
            )?;
            Ok(())
        })
        .unwrap();
        let huge = "x".repeat(262_145);
        let err = insert_plan(run_id_big, rusqlite::types::Value::Text(huge));
        assert!(err.to_string().contains("CHECK"), "got: {err}");
    }

    /// `list_plans_for_session` orders by `(submitted_at, rowid)` so
    /// rows sharing a timestamp keep their insertion order. The v15
    /// to v16 recreate would otherwise be free to assign fresh
    /// rowids in a different order; the migration explicitly carries
    /// the old `rowid` across to keep that tie-break stable.
    #[test]
    fn migration_16_preserves_plan_rowid_ordering() {
        let db = NamedTempFile::new().unwrap();
        let session_id = SessionId::new();
        let run_ids: [uuid::Uuid; 3] = std::array::from_fn(|_| uuid::Uuid::new_v4());
        let plan_ids: [uuid::Uuid; 3] = std::array::from_fn(|_| uuid::Uuid::new_v4());

        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(15) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 15).unwrap();

            tx.execute(
                "INSERT INTO session (session_id, label, agent_kind, agent_model, opened_at, closed_at) \
                 VALUES (?1, NULL, 'claude', NULL, 1, NULL)",
                params![session_id.as_uuid().to_string()],
            )
            .unwrap();

            // Three runs and three plans with the SAME submitted_at, so
            // the only stable tie-break is rowid.
            for (run, plan) in run_ids.iter().zip(plan_ids.iter()) {
                tx.execute(
                    "INSERT INTO agent_run (
                         run_id, session_id, requested_at, agent_kind,
                         prompt_bytes, prompt_sha256, prompt_redacted_preview,
                         correlation_id
                     ) VALUES (?1, ?2, 2, 'claude', 1, ?3, '<redacted>', NULL)",
                    params![
                        run.to_string(),
                        session_id.as_uuid().to_string(),
                        "a".repeat(64),
                    ],
                )
                .unwrap();
                tx.execute(
                    "INSERT INTO plan (plan_id, agent_run_id, submitted_at, body, body_sha256) \
                     VALUES (?1, ?2, 100, 'body', ?3)",
                    params![
                        plan.to_string(),
                        run.to_string(),
                        crate::agent_run::sha256_hex(b"body"),
                    ],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }

        // Snapshot v15 ordering before migration.
        let pre_order: Vec<(i64, String)> = {
            let c = Connection::open(db.path()).unwrap();
            let mut stmt = c
                .prepare("SELECT rowid, plan_id FROM plan ORDER BY submitted_at, rowid")
                .unwrap();
            stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        };

        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);

        let post_order: Vec<(i64, String)> = log
            .with_conn(|c| {
                let mut stmt =
                    c.prepare("SELECT rowid, plan_id FROM plan ORDER BY submitted_at, rowid")?;
                let rows: Vec<(i64, String)> = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .unwrap();

        assert_eq!(
            pre_order, post_order,
            "rowid order must survive the v15 to v16 recreate",
        );
    }

    /// A v15 DB could contain plan rows that violate the new
    /// invariants (the v15 CHECK was only `body != ''` and the old
    /// `PlanBody::try_new` did not reject embedded NULs). Migration
    /// 16 must refuse such a DB with a targeted, actionable error
    /// rather than a generic "CHECK constraint failed" surfaced from
    /// the copy step.
    #[test]
    fn migration_16_refuses_v15_db_with_nul_plan_body() {
        let db = NamedTempFile::new().unwrap();
        let session_id = SessionId::new();
        let run_id = uuid::Uuid::new_v4();
        let plan_id = uuid::Uuid::new_v4();
        let dirty_body = "before\0after";
        let body_sha = crate::agent_run::sha256_hex(dirty_body.as_bytes());

        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(15) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 15).unwrap();

            tx.execute(
                "INSERT INTO session (session_id, label, agent_kind, agent_model, opened_at, closed_at) \
                 VALUES (?1, NULL, 'claude', NULL, 1, NULL)",
                params![session_id.as_uuid().to_string()],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO agent_run (
                     run_id, session_id, requested_at, agent_kind,
                     prompt_bytes, prompt_sha256, prompt_redacted_preview,
                     correlation_id
                 ) VALUES (?1, ?2, 2, 'claude', 1, ?3, '<redacted>', NULL)",
                params![
                    run_id.to_string(),
                    session_id.as_uuid().to_string(),
                    "a".repeat(64),
                ],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO plan (plan_id, agent_run_id, submitted_at, body, body_sha256) \
                 VALUES (?1, ?2, 3, ?3, ?4)",
                params![
                    plan_id.to_string(),
                    run_id.to_string(),
                    dirty_body,
                    &body_sha,
                ],
            )
            .unwrap();
            tx.commit().unwrap();
        }

        // The open should fail; the rolled-back transaction must leave
        // the v15 schema intact so the operator can inspect the bad
        // row and decide what to do.
        let err = AuditLog::open(db.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("migration 16") && msg.contains("plan rows violate"),
            "expected targeted migration-16 message, got: {msg}",
        );

        // The v15 row is still there and the schema is still v15.
        let conn = Connection::open(db.path()).unwrap();
        let user_version: i32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 15);
        let recovered_body: String = conn
            .query_row(
                "SELECT body FROM plan WHERE plan_id = ?1",
                params![plan_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(recovered_body, dirty_body);
    }

    /// A v16 DB carries `agent_run` rows without a `stage` column; the
    /// migration adds the column with `DEFAULT 'execute'` so historical
    /// rows acquire a meaningful role rather than NULL (which the
    /// NOT NULL clause would refuse anyway). v16 (and v15 before it)
    /// already accepted plan submissions, so any run referenced by
    /// `plan.agent_run_id` is a planner and the follow-up UPDATE must
    /// rewrite it to `'plan'`; runs with no `plan` row stay at
    /// `'execute'`. After migration the CHECK must reject both an
    /// out-of-set value and a BLOB-bound smuggle of a valid-looking
    /// byte string — the two cases the migration-14 regression test
    /// established as the threat model for TEXT affinity columns.
    #[test]
    fn open_migrates_v16_database_to_agent_run_stage_schema() {
        let db = NamedTempFile::new().unwrap();
        let session_id = SessionId::new();
        let executor_run_id = uuid::Uuid::new_v4();
        let planner_run_id = uuid::Uuid::new_v4();
        let plan_id = uuid::Uuid::new_v4();

        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(16) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 16).unwrap();

            tx.execute(
                "INSERT INTO session (session_id, label, agent_kind, agent_model, opened_at, closed_at) \
                 VALUES (?1, NULL, 'claude', NULL, 1, NULL)",
                params![session_id.as_uuid().to_string()],
            )
            .unwrap();

            for run_id in [executor_run_id, planner_run_id] {
                tx.execute(
                    "INSERT INTO agent_run (
                         run_id, session_id, requested_at, agent_kind,
                         prompt_bytes, prompt_sha256, prompt_redacted_preview,
                         correlation_id
                     ) VALUES (?1, ?2, 2, 'claude', 1, ?3, '<redacted>', NULL)",
                    params![
                        run_id.to_string(),
                        session_id.as_uuid().to_string(),
                        "a".repeat(64),
                    ],
                )
                .unwrap();
            }

            // The planner run produced a v15 plan row; the migration must
            // notice this and lift the run's stage from the 'execute'
            // default to 'plan'.
            tx.execute(
                "INSERT INTO plan (plan_id, agent_run_id, submitted_at, body, body_sha256) \
                 VALUES (?1, ?2, 3, '# Plan', ?3)",
                params![
                    plan_id.to_string(),
                    planner_run_id.to_string(),
                    crate::agent_run::sha256_hex(b"# Plan"),
                ],
            )
            .unwrap();

            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "agent_run", "stage"));

        // A run with no plan row stays at the 'execute' default.
        let executor_stage: String = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT stage FROM agent_run WHERE run_id = ?1",
                    params![executor_run_id.to_string()],
                    |r| r.get::<_, String>(0),
                )?)
            })
            .unwrap();
        assert_eq!(executor_stage, "execute");

        // A run referenced by plan.agent_run_id is rewritten to 'plan'.
        let planner_stage: String = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT stage FROM agent_run WHERE run_id = ?1",
                    params![planner_run_id.to_string()],
                    |r| r.get::<_, String>(0),
                )?)
            })
            .unwrap();
        assert_eq!(planner_stage, "plan");

        // CHECK refuses an out-of-set TEXT value.
        let unknown_err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO agent_run (
                         run_id, session_id, requested_at, agent_kind,
                         prompt_bytes, prompt_sha256, prompt_redacted_preview,
                         correlation_id, stage
                     ) VALUES (?1, ?2, 3, 'claude', 1, ?3, '<redacted>', NULL, 'decide')",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        session_id.as_uuid().to_string(),
                        "a".repeat(64),
                    ],
                ))
            })
            .unwrap()
            .unwrap_err();
        assert!(
            unknown_err.to_string().contains("CHECK"),
            "got: {unknown_err}"
        );

        // CHECK refuses a BLOB-bound value even when the bytes spell a
        // valid variant — `typeof = 'text'` is what stops the smuggle.
        let blob_err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO agent_run (
                         run_id, session_id, requested_at, agent_kind,
                         prompt_bytes, prompt_sha256, prompt_redacted_preview,
                         correlation_id, stage
                     ) VALUES (?1, ?2, 4, 'claude', 1, ?3, '<redacted>', NULL, ?4)",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        session_id.as_uuid().to_string(),
                        "a".repeat(64),
                        rusqlite::types::Value::Blob(b"plan".to_vec()),
                    ],
                ))
            })
            .unwrap()
            .unwrap_err();
        assert!(blob_err.to_string().contains("CHECK"), "got: {blob_err}");

        // A fresh insert with each valid stage round-trips.
        for stage in ["plan", "review", "execute"] {
            let id = uuid::Uuid::new_v4();
            log.with_conn(|c| {
                c.execute(
                    "INSERT INTO agent_run (
                         run_id, session_id, requested_at, agent_kind,
                         prompt_bytes, prompt_sha256, prompt_redacted_preview,
                         correlation_id, stage
                     ) VALUES (?1, ?2, 5, 'claude', 1, ?3, '<redacted>', NULL, ?4)",
                    params![
                        id.to_string(),
                        session_id.as_uuid().to_string(),
                        "a".repeat(64),
                        stage,
                    ],
                )?;
                Ok(())
            })
            .unwrap();
            let got: String = log
                .with_conn(|c| {
                    Ok(c.query_row(
                        "SELECT stage FROM agent_run WHERE run_id = ?1",
                        params![id.to_string()],
                        |r| r.get::<_, String>(0),
                    )?)
                })
                .unwrap();
            assert_eq!(got, stage);
        }
    }

    /// Migration 19 adds `agent_run.read_plan_id TEXT NULL REFERENCES
    /// plan(plan_id)`. A v18 DB carrying both an executor run and a
    /// planner run (with its plan row) must survive the migration with
    /// `read_plan_id` NULL on every pre-existing row (no historical
    /// signal lets us recover a binding). After the migration:
    ///
    ///   - a fresh insert naming an existing `plan.plan_id` is accepted;
    ///   - a fresh insert naming a non-existent UUID is rejected by the
    ///     foreign-key enforcement (proves `PRAGMA foreign_keys = ON`
    ///     reaches this column);
    ///   - a BLOB-bound value is rejected by the `typeof = 'text'`
    ///     guard, matching the migration-14/17 threat model.
    #[test]
    fn open_migrates_v18_database_to_read_plan_id_schema() {
        let db = NamedTempFile::new().unwrap();
        let session_id = SessionId::new();
        let executor_run_id = uuid::Uuid::new_v4();
        let planner_run_id = uuid::Uuid::new_v4();
        let plan_id = uuid::Uuid::new_v4();

        {
            let mut conn = Connection::open(db.path()).unwrap();
            let tx = conn.transaction().unwrap();
            for migration in MIGRATIONS.iter().take(18) {
                tx.execute_batch(migration.sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 18).unwrap();

            tx.execute(
                "INSERT INTO session (session_id, label, agent_kind, agent_model, opened_at, closed_at) \
                 VALUES (?1, NULL, 'claude', NULL, 1, NULL)",
                params![session_id.as_uuid().to_string()],
            )
            .unwrap();

            tx.execute(
                "INSERT INTO agent_run (
                     run_id, session_id, requested_at, agent_kind,
                     prompt_bytes, prompt_sha256, prompt_redacted_preview,
                     correlation_id, stage
                 ) VALUES (?1, ?2, 2, 'claude', 1, ?3, '<redacted>', NULL, 'execute')",
                params![
                    executor_run_id.to_string(),
                    session_id.as_uuid().to_string(),
                    "a".repeat(64),
                ],
            )
            .unwrap();

            tx.execute(
                "INSERT INTO agent_run (
                     run_id, session_id, requested_at, agent_kind,
                     prompt_bytes, prompt_sha256, prompt_redacted_preview,
                     correlation_id, stage
                 ) VALUES (?1, ?2, 2, 'claude', 1, ?3, '<redacted>', NULL, 'plan')",
                params![
                    planner_run_id.to_string(),
                    session_id.as_uuid().to_string(),
                    "a".repeat(64),
                ],
            )
            .unwrap();

            tx.execute(
                "INSERT INTO plan (plan_id, agent_run_id, submitted_at, body, body_sha256) \
                 VALUES (?1, ?2, 3, '# Plan', ?3)",
                params![
                    plan_id.to_string(),
                    planner_run_id.to_string(),
                    crate::agent_run::sha256_hex(b"# Plan"),
                ],
            )
            .unwrap();

            tx.commit().unwrap();
        }

        let log = AuditLog::open(db.path()).unwrap();
        assert_eq!(read_user_version(&log), SCHEMA_VERSION);
        assert!(column_exists(&log, "agent_run", "read_plan_id"));

        // Pre-existing rows survive with read_plan_id NULL.
        for run_id in [executor_run_id, planner_run_id] {
            let read_plan: Option<String> = log
                .with_conn(|c| {
                    Ok(c.query_row(
                        "SELECT read_plan_id FROM agent_run WHERE run_id = ?1",
                        params![run_id.to_string()],
                        |r| r.get(0),
                    )?)
                })
                .unwrap();
            assert!(
                read_plan.is_none(),
                "pre-existing run {run_id} should have NULL read_plan_id"
            );
        }

        // A fresh insert with an existing plan_id is accepted.
        let bound_run_id = uuid::Uuid::new_v4();
        log.with_conn(|c| {
            c.execute(
                "INSERT INTO agent_run (
                     run_id, session_id, requested_at, agent_kind,
                     prompt_bytes, prompt_sha256, prompt_redacted_preview,
                     correlation_id, stage, read_plan_id
                 ) VALUES (?1, ?2, 4, 'claude', 1, ?3, '<redacted>', NULL, 'execute', ?4)",
                params![
                    bound_run_id.to_string(),
                    session_id.as_uuid().to_string(),
                    "a".repeat(64),
                    plan_id.to_string(),
                ],
            )?;
            Ok(())
        })
        .unwrap();
        let bound_value: Option<String> = log
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT read_plan_id FROM agent_run WHERE run_id = ?1",
                    params![bound_run_id.to_string()],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(bound_value.as_deref(), Some(plan_id.to_string().as_str()));

        // A fresh insert naming a non-existent plan_id is rejected by
        // the FK constraint. This proves `PRAGMA foreign_keys = ON`
        // reaches this column (REFERENCES alone is parsed-and-ignored
        // without the pragma).
        let bogus_plan = uuid::Uuid::new_v4();
        let fk_err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO agent_run (
                         run_id, session_id, requested_at, agent_kind,
                         prompt_bytes, prompt_sha256, prompt_redacted_preview,
                         correlation_id, stage, read_plan_id
                     ) VALUES (?1, ?2, 5, 'claude', 1, ?3, '<redacted>', NULL, 'review', ?4)",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        session_id.as_uuid().to_string(),
                        "a".repeat(64),
                        bogus_plan.to_string(),
                    ],
                ))
            })
            .unwrap()
            .unwrap_err();
        assert!(
            fk_err.to_string().to_uppercase().contains("FOREIGN KEY"),
            "got: {fk_err}"
        );

        // CHECK refuses a BLOB-bound value even when the bytes spell a
        // valid UUID — `typeof = 'text'` is the smuggle stopper.
        let blob_err = log
            .with_conn(|c| {
                Ok(c.execute(
                    "INSERT INTO agent_run (
                         run_id, session_id, requested_at, agent_kind,
                         prompt_bytes, prompt_sha256, prompt_redacted_preview,
                         correlation_id, stage, read_plan_id
                     ) VALUES (?1, ?2, 6, 'claude', 1, ?3, '<redacted>', NULL, 'execute', ?4)",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        session_id.as_uuid().to_string(),
                        "a".repeat(64),
                        rusqlite::types::Value::Blob(plan_id.to_string().into_bytes()),
                    ],
                ))
            })
            .unwrap()
            .unwrap_err();
        assert!(blob_err.to_string().contains("CHECK"), "got: {blob_err}");
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
