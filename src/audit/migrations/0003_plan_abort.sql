-- v3: plan_abort
--
-- An execute-stage agent run that decides the accepted plan is
-- fundamentally unworkable mid-execution posts a hard-abort against it.
-- Per `docs/plans/2026-05-11-agent-plans.md` §"Decisions taken" item 9
-- this is a distinct protocol message rather than a non-zero exit, so
-- the row exists to give the operator a queryable durable signal
-- without re-reading the implementer's transcript.
--
-- Shape mirrors `plan_decision`: `plan_id` is the primary key, so a
-- given plan carries at-most-one abort row. A second abort against the
-- same plan surfaces to the caller as a UNIQUE / PRIMARY KEY violation;
-- the wire layer maps that to `PlanAlreadyAborted` (or similar) rather
-- than silently overwriting. The row does *not* mutate any
-- `plan_decision` — the operator separately decides whether to start a
-- fresh planning task.
--
-- Triggers reassert the route's preconditions for raw INSERTs (open
-- session, execute-stage run bound to this plan). The abort route
-- deliberately does not require `plan_decision.outcome = 'accepted'`
-- — by the time an execute-stage run is running at all, the route
-- gate has already enforced acceptance at the read-plan step, so a
-- duplicate check here would only fire on a forged raw INSERT path.
-- The matching pure gate in `agent_plan::route_permitted_by_stage_and_decision`
-- documents the same choice.

CREATE TABLE plan_abort (
    -- TEXT PRIMARY KEY in a rowid table does not imply NOT NULL (the
    -- v1 compat quirk also exploited by plan_decision / plan_review /
    -- plan_addendum); mark explicitly so a raw INSERT with
    -- `plan_id = NULL` cannot bypass the per-plan uniqueness.
    plan_id          TEXT PRIMARY KEY NOT NULL REFERENCES plan(plan_id),
    agent_run_id     TEXT NOT NULL REFERENCES agent_run(run_id),
    aborted_at       INTEGER NOT NULL,
    -- Bounded short text. The byte count matches
    -- `MAX_PLAN_ABORT_REASON_BYTES`; the `typeof` + BLOB-length parity
    -- shape mirrors plan_addendum.body for the same reasons (TEXT
    -- columns silently accept BLOB storage class; `length` walks TEXT
    -- as a C-string and stops at the first NUL, so a BLOB-length parity
    -- check is the only reliable byte-count gate).
    reason           TEXT NOT NULL CHECK (
        typeof(reason) = 'text'
        AND length(cast(reason AS BLOB)) BETWEEN 1 AND 4096
    )
);

CREATE TRIGGER plan_abort_requires_open_session
BEFORE INSERT ON plan_abort
WHEN EXISTS (
    SELECT 1 FROM agent_run ar
    JOIN session s ON s.session_id = ar.session_id
    WHERE ar.run_id = NEW.agent_run_id AND s.closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;

CREATE TRIGGER plan_abort_requires_executor_run
BEFORE INSERT ON plan_abort
WHEN NOT EXISTS (
    SELECT 1 FROM agent_run ar
    WHERE ar.run_id = NEW.agent_run_id
      AND ar.stage = 'execute'
      AND ar.read_plan_id = NEW.plan_id
)
BEGIN
    SELECT RAISE(ABORT,
        'plan_abort requires agent_run.stage = ''execute'' AND agent_run.read_plan_id = plan_id');
END;
