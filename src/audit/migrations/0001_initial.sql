-- tables

CREATE TABLE agent_run (
    run_id                  TEXT PRIMARY KEY,
    session_id              TEXT NOT NULL REFERENCES session(session_id),
    requested_at            INTEGER NOT NULL,
    agent_kind              TEXT NOT NULL CHECK (agent_kind IN ('claude', 'codex')),
    prompt_bytes            INTEGER NOT NULL CHECK (prompt_bytes >= 0),
    prompt_sha256           TEXT NOT NULL CHECK (length(prompt_sha256) = 64),
    prompt_redacted_preview TEXT NOT NULL CHECK (prompt_redacted_preview != '')
, correlation_id TEXT
    CHECK (correlation_id IS NULL OR (
        typeof(correlation_id) = 'text'
        AND length(correlation_id) = length(cast(correlation_id AS BLOB))
        AND length(correlation_id) BETWEEN 1 AND 64
        AND correlation_id NOT GLOB '*[^A-Za-z0-9_-]*'
    )), stage TEXT NOT NULL DEFAULT 'execute'
    CHECK (
        typeof(stage) = 'text'
        AND stage IN ('plan','review','execute')
    ), read_plan_id TEXT NULL
    REFERENCES plan(plan_id)
    CHECK (read_plan_id IS NULL OR typeof(read_plan_id) = 'text'));

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

CREATE TABLE agent_vm_workspace_bootstrap (
    session_id   TEXT PRIMARY KEY REFERENCES session(session_id),
    requested_at INTEGER NOT NULL,
    repo         TEXT NOT NULL CHECK (repo != ''),
    destination  TEXT NOT NULL CHECK (destination != ''),
    branch       TEXT NOT NULL CHECK (branch != ''),
    warm         TEXT NOT NULL CHECK (warm IN ('none', 'sources', 'devshell'))
);

CREATE TABLE claude_proxy_outcome (
    request_id      TEXT PRIMARY KEY REFERENCES claude_proxy_request(request_id),
    completed_at    INTEGER NOT NULL,
    http_status     INTEGER NOT NULL CHECK (http_status BETWEEN 100 AND 599),
    upstream_url    TEXT,
    upstream_status INTEGER CHECK (upstream_status BETWEEN 100 AND 599),
    response_bytes  INTEGER NOT NULL CHECK (response_bytes >= 0),
    error           TEXT CHECK (error IS NULL OR error != '')
);

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

CREATE TABLE git_push_request (
    push_request_id      TEXT PRIMARY KEY,
    session_id           TEXT NOT NULL REFERENCES session(session_id),
    received_at          INTEGER NOT NULL,
    repo                 TEXT NOT NULL CHECK (repo != ''),
    branch               TEXT NOT NULL CHECK (branch != ''),
    expected_remote_head TEXT CHECK (expected_remote_head IS NULL OR length(expected_remote_head) = 40),
    new_head             TEXT NOT NULL CHECK (length(new_head) = 40)
, correlation_id TEXT
    CHECK (correlation_id IS NULL OR (
        typeof(correlation_id) = 'text'
        AND length(correlation_id) = length(cast(correlation_id AS BLOB))
        AND length(correlation_id) BETWEEN 1 AND 64
        AND correlation_id NOT GLOB '*[^A-Za-z0-9_-]*'
    )));

CREATE TABLE git_push_resolution (
    push_request_id TEXT PRIMARY KEY REFERENCES git_push_request(push_request_id),
    decided_at      INTEGER NOT NULL,
    decision        TEXT NOT NULL CHECK (decision IN ('rejected', 'approved')),
    operator        TEXT NOT NULL CHECK (operator != ''),
    reason          TEXT NOT NULL CHECK (reason != '')
);

CREATE TABLE grant_log (
    jti         TEXT PRIMARY KEY,
    request_id  TEXT NOT NULL REFERENCES request(request_id),
    session_id  TEXT NOT NULL REFERENCES session(session_id),
    scope_json  TEXT NOT NULL,
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
, github_app_id INTEGER CHECK (github_app_id IS NULL OR github_app_id >= 0));

CREATE TABLE mint_failure (
    request_id   TEXT PRIMARY KEY REFERENCES request(request_id),
    failed_at    INTEGER NOT NULL,
    failure_json TEXT NOT NULL
);

CREATE TABLE nix_cache_outcome (
    request_id     TEXT PRIMARY KEY REFERENCES nix_cache_request(request_id),
    completed_at   INTEGER NOT NULL,
    http_status    INTEGER NOT NULL CHECK (http_status BETWEEN 100 AND 599),
    upstream_url   TEXT,
    upstream_status INTEGER CHECK (upstream_status BETWEEN 100 AND 599),
    response_bytes INTEGER NOT NULL CHECK (response_bytes >= 0),
    error          TEXT CHECK (error IS NULL OR error != '')
);

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

CREATE TABLE openai_proxy_outcome (
    request_id      TEXT PRIMARY KEY REFERENCES openai_proxy_request(request_id),
    completed_at    INTEGER NOT NULL,
    http_status     INTEGER NOT NULL CHECK (http_status BETWEEN 100 AND 599),
    upstream_url    TEXT,
    upstream_status INTEGER CHECK (upstream_status BETWEEN 100 AND 599),
    response_bytes  INTEGER NOT NULL CHECK (response_bytes >= 0),
    error           TEXT CHECK (error IS NULL OR error != '')
);

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

CREATE TABLE request (
    request_id    TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES session(session_id),
    received_at   INTEGER NOT NULL,
    request_json  TEXT NOT NULL,
    decision_json TEXT NOT NULL
);

CREATE TABLE session (
    session_id  TEXT PRIMARY KEY,
    label       TEXT,
    agent_model TEXT,
    opened_at   INTEGER NOT NULL,
    closed_at   INTEGER
, agent_kind TEXT CHECK (agent_kind IN ('claude', 'codex')));


-- indexes

CREATE INDEX idx_claude_proxy_request_session
    ON claude_proxy_request(session_id, received_at);

CREATE INDEX idx_git_push_request_session
    ON git_push_request(session_id, received_at);

CREATE INDEX idx_grant_session ON grant_log(session_id, issued_at);

CREATE INDEX idx_nix_cache_request_session
    ON nix_cache_request(session_id, received_at);

CREATE INDEX idx_openai_proxy_request_session
    ON openai_proxy_request(session_id, received_at);

CREATE INDEX idx_plan_agent_run ON plan(agent_run_id);

CREATE INDEX idx_plan_review_plan ON plan_review(plan_id);

CREATE INDEX idx_request_session ON request(session_id, received_at);


-- triggers

CREATE TRIGGER agent_run_requires_open_session
BEFORE INSERT ON agent_run
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;

CREATE TRIGGER agent_vm_workspace_bootstrap_requires_open_session
BEFORE INSERT ON agent_vm_workspace_bootstrap
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;

CREATE TRIGGER claude_proxy_request_requires_open_session
BEFORE INSERT ON claude_proxy_request
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

CREATE TRIGGER git_push_request_requires_open_session
BEFORE INSERT ON git_push_request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;

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

CREATE TRIGGER grant_excludes_mint_failure
BEFORE INSERT ON grant_log
WHEN EXISTS (SELECT 1 FROM mint_failure WHERE request_id = NEW.request_id)
BEGIN
    SELECT RAISE(ABORT, 'mint failure already recorded for this request');
END;

CREATE TRIGGER mint_failure_excludes_grant
BEFORE INSERT ON mint_failure
WHEN EXISTS (SELECT 1 FROM grant_log WHERE request_id = NEW.request_id)
BEGIN
    SELECT RAISE(ABORT, 'grant already recorded for this request');
END;

CREATE TRIGGER nix_cache_request_requires_open_session
BEFORE INSERT ON nix_cache_request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;

CREATE TRIGGER openai_proxy_request_requires_open_session
BEFORE INSERT ON openai_proxy_request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;

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

CREATE TRIGGER request_requires_open_session
BEFORE INSERT ON request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;

