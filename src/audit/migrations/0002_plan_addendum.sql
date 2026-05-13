-- v2: plan_addendum
--
-- An accepted plan may grow follow-up addenda during execution. Each row
-- is one body submission posted by an execute-stage agent run that read
-- the plan it is addending. Schema, indexes, and triggers parallel
-- `plan_review`: an `agent_run` is bound to exactly one row by
-- `UNIQUE(agent_run_id)`, the digest column is hex-text only, the body
-- has the same 256 KiB cap as `plan.body`, and the run/session/decision
-- preconditions are reasserted by triggers so a raw INSERT cannot bypass
-- the DAO pre-checks.

CREATE TABLE plan_addendum (
    -- TEXT PRIMARY KEY in a rowid table does not imply NOT NULL (the
    -- v1 compat quirk also exploited by plan_decision / plan_review);
    -- mark explicitly so a raw INSERT with `addendum_id = NULL` cannot
    -- bypass the per-row uniqueness.
    addendum_id      TEXT PRIMARY KEY NOT NULL,
    plan_id          TEXT NOT NULL REFERENCES plan(plan_id),
    agent_run_id     TEXT NOT NULL REFERENCES agent_run(run_id),
    submitted_at     INTEGER NOT NULL,
    body             TEXT NOT NULL CHECK (
        typeof(body) = 'text'
        AND length(cast(body AS BLOB)) BETWEEN 1 AND 262144
        AND instr(cast(body AS BLOB), x'00') = 0
    ),
    -- The digest must be exactly 64 lowercase hex chars in TEXT storage
    -- class; see the parallel commentary on `plan_review.feedback_sha256`
    -- for the rationale on each clause.
    body_sha256      TEXT NOT NULL CHECK (
        typeof(body_sha256) = 'text'
        AND length(body_sha256) = length(cast(body_sha256 AS BLOB))
        AND length(body_sha256) = 64
        AND body_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    UNIQUE (agent_run_id)
);

-- Listings order by (plan_id, submitted_at); the index covers both the
-- per-plan filter and the within-plan ordering.
CREATE INDEX idx_plan_addendum_plan ON plan_addendum(plan_id, submitted_at);

CREATE TRIGGER plan_addendum_requires_open_session
BEFORE INSERT ON plan_addendum
WHEN EXISTS (
    SELECT 1 FROM agent_run ar
    JOIN session s ON s.session_id = ar.session_id
    WHERE ar.run_id = NEW.agent_run_id AND s.closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;

CREATE TRIGGER plan_addendum_requires_executor_run
BEFORE INSERT ON plan_addendum
WHEN NOT EXISTS (
    SELECT 1 FROM agent_run ar
    WHERE ar.run_id = NEW.agent_run_id
      AND ar.stage = 'execute'
      AND ar.read_plan_id = NEW.plan_id
)
BEGIN
    SELECT RAISE(ABORT,
        'plan_addendum requires agent_run.stage = ''execute'' AND agent_run.read_plan_id = plan_id');
END;

-- Addenda are only meaningful for plans whose decision is Accepted: the
-- route gate enforces this for clean errors, but the trigger is the
-- belt-and-braces layer against any raw INSERT that bypasses the route.
-- The wire-side mapping converts the trigger message into a typed
-- `PlanNotAccepted` (or equivalent) outcome.
CREATE TRIGGER plan_addendum_requires_accepted_decision
BEFORE INSERT ON plan_addendum
WHEN NOT EXISTS (
    SELECT 1 FROM plan_decision
    WHERE plan_id = NEW.plan_id AND outcome = 'accepted'
)
BEGIN
    SELECT RAISE(ABORT,
        'plan_addendum requires plan_decision.outcome = ''accepted'' for plan_id');
END;
