-- Let an agent run end because writ stopped it, not only because the agent
-- did.
--
-- `status` gains 'timed_out': the host `RunAgent` arm can now be given a
-- deadline, and a run still alive when it passes is killed. That ending is
-- writ's, not the agent's, so it must not be recorded as 'failed' — 'failed'
-- means the agent ran to completion and chose a non-zero code, and an operator
-- reading this table has to be able to tell the two apart after the fact. See
-- `AgentRunTerminalStatus`.
--
-- SQLite cannot alter a CHECK constraint, so the table is rebuilt. Every other
-- column, constraint and type is carried across byte-for-byte from
-- 0001_initial_v2.sql; the sole difference is the widened `status` CHECK.
--
-- `exit_code` stays NOT NULL and is not special-cased for the new status. A
-- timed-out run records -1, which is already this schema's value for "died by
-- signal, no exit code" (writ kills with a signal, so that is literally what
-- happened) and is unreachable as a real exit code, since Unix codes are
-- 0-255. The status is what distinguishes writ's kill from any other signal
-- death; the number is not asked to.
--
-- No backfill and no rewriting of existing rows: every row already in this
-- table was written when 'timed_out' did not exist, so every one of them is
-- exactly as true after this migration as before it.

CREATE TABLE agent_run_outcome_new (
    run_id           TEXT PRIMARY KEY REFERENCES agent_run(run_id),
    completed_at     INTEGER NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('succeeded', 'failed', 'timed_out')),
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

INSERT INTO agent_run_outcome_new
SELECT run_id, completed_at, status, exit_code,
       stdout_path, stdout_bytes, stdout_sha256, stdout_truncated,
       stderr_path, stderr_bytes, stderr_sha256, stderr_truncated
FROM agent_run_outcome;

DROP TABLE agent_run_outcome;
ALTER TABLE agent_run_outcome_new RENAME TO agent_run_outcome;
