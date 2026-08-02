-- Record the third way a captured stream can be incomplete: writ stopped
-- reading it.
--
-- Until now a stream summary said one of two things. Either it was complete —
-- drained to EOF — or `truncated`, meaning the stream outran the run's capture
-- cap and writ deliberately kept a prefix. Both describe a stream writ read to
-- the end of its interest in it.
--
-- There is now a third: writ stopped reading while the stream was still open,
-- because something still held the write end after the run's process group was
-- swept. A descendant that calls `setsid(2)` leaves the group, so the kill
-- misses it, and the capture would otherwise never see EOF. Writ gives the
-- drain a grace period after the sweep and then closes the file.
--
-- Why this is not `truncated`. The two answer different questions and only one
-- of them is bounded. `truncated` is writ's own choice — the remainder is
-- everything past a cap writ picked, and the file holds exactly that prefix.
-- `stopped_at_deadline` is not a choice about how much to keep; it is writ
-- ceasing to listen, and what the writer went on to produce is unknown *and
-- unbounded*. Folding them together would let an operator read "we capped this"
-- when what happened was "we lost the rest". They are also independent: a
-- stream can outrun the cap and *then* be cut short, so this is a second flag
-- rather than a third value of the first.
--
-- What stays true either way: the file at `*_path` is complete as a file. Writ
-- closes and syncs it before the summary is built, so `*_bytes` and `*_sha256`
-- never describe something still being appended to. That is what makes these
-- rows checkable, and it is why a capture cut short is *stopped* rather than
-- abandoned — an abandoned reader would keep writing after the row was
-- recorded, and the row would be a lie in an append-only log.
--
-- SQLite cannot add a column with a CHECK constraint referencing it via
-- ALTER TABLE ADD COLUMN in all supported versions, and this schema states its
-- boolean domains explicitly everywhere else, so the table is rebuilt as
-- 0009 did. Every other column, constraint and type is carried across
-- byte-for-byte from 0009_agent_run_timed_out.sql; the sole difference is the
-- two new columns.
--
-- Existing rows backfill to 0, and that is a statement of fact rather than a
-- default: every row already in this table was written by a capture that ran to
-- EOF or to the cap, because no other ending existed to record. So each is
-- exactly as true after this migration as before it.

CREATE TABLE agent_run_outcome_new (
    run_id                     TEXT PRIMARY KEY REFERENCES agent_run(run_id),
    completed_at               INTEGER NOT NULL,
    status                     TEXT NOT NULL CHECK (status IN ('succeeded', 'failed', 'timed_out')),
    exit_code                  INTEGER NOT NULL,
    stdout_path                TEXT NOT NULL CHECK (stdout_path != ''),
    stdout_bytes               INTEGER NOT NULL CHECK (stdout_bytes >= 0),
    stdout_sha256              TEXT NOT NULL CHECK (length(stdout_sha256) = 64),
    stdout_truncated           INTEGER NOT NULL CHECK (stdout_truncated IN (0, 1)),
    stdout_stopped_at_deadline INTEGER NOT NULL CHECK (stdout_stopped_at_deadline IN (0, 1)),
    stderr_path                TEXT NOT NULL CHECK (stderr_path != ''),
    stderr_bytes               INTEGER NOT NULL CHECK (stderr_bytes >= 0),
    stderr_sha256              TEXT NOT NULL CHECK (length(stderr_sha256) = 64),
    stderr_truncated           INTEGER NOT NULL CHECK (stderr_truncated IN (0, 1)),
    stderr_stopped_at_deadline INTEGER NOT NULL CHECK (stderr_stopped_at_deadline IN (0, 1))
);

INSERT INTO agent_run_outcome_new
SELECT run_id, completed_at, status, exit_code,
       stdout_path, stdout_bytes, stdout_sha256, stdout_truncated, 0,
       stderr_path, stderr_bytes, stderr_sha256, stderr_truncated, 0
FROM agent_run_outcome;

DROP TABLE agent_run_outcome;
ALTER TABLE agent_run_outcome_new RENAME TO agent_run_outcome;
