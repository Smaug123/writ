-- Flake-input provisioning audit (FK1).
--
-- The broker, on the host, runs `nix flake archive` to copy a repo's
-- committed, locked flake inputs into a binary cache the no-egress guest
-- can substitute from. That fetch is new host egress to URLs named in the
-- repo's lock, so it is audited the same two-phase way as the proxy
-- tables: a request row recorded before the fetch is attempted (so the
-- attempted egress is durable even if the broker dies mid-fetch), and an
-- outcome row appended after. Both are append-only; there is no UPDATE or
-- DELETE path in the DAO.

CREATE TABLE flake_provision_request (
    request_id  TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES session(session_id),
    received_at INTEGER NOT NULL,
    -- The flake checkout the inputs are provisioned from, and the
    -- broker-local binary cache they are archived into. Absolute paths,
    -- validated non-empty at the DAO and here.
    flake_dir   TEXT NOT NULL CHECK (flake_dir != ''),
    cache_dir   TEXT NOT NULL CHECK (cache_dir != ''),
    -- Number of inputs the committed lock declared (the functional core's
    -- count, gated against the configured bound before this row is written).
    input_count INTEGER NOT NULL CHECK (input_count >= 0)
);

CREATE TABLE flake_provision_outcome (
    request_id          TEXT PRIMARY KEY REFERENCES flake_provision_request(request_id),
    completed_at        INTEGER NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('success', 'failure')),
    -- Store paths the archive landed in the cache, and their total size on
    -- disk. Zero on failure: a partial archive is not trusted (fail-closed).
    archived_path_count INTEGER NOT NULL CHECK (archived_path_count >= 0),
    archived_bytes      INTEGER NOT NULL CHECK (archived_bytes >= 0),
    -- Present exactly on failure (timeout, non-zero exit, or over-budget).
    error               TEXT,
    CHECK (
        (status = 'success' AND error IS NULL)
        OR (status = 'failure' AND error IS NOT NULL AND error != '')
    )
);

CREATE INDEX idx_flake_provision_request_session
    ON flake_provision_request(session_id, received_at);

-- Mirror the proxy tables: a provisioning row can only be written while the
-- referenced session is open, so a session's `closed_at` stays a true upper
-- bound on its activity window.
CREATE TRIGGER flake_provision_request_requires_open_session
BEFORE INSERT ON flake_provision_request
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
