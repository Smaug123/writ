-- v5: drop the unused `git_push_attempt` table; introduce an explicit
-- approve-attempt state machine.
--
-- The first iteration of `approve_staged_push` (slice B1e.2e) treated
-- approve as a procedural sequence over three durable stores (GitHub
-- branch ref, audit DB, staging dir on disk) with no transaction
-- manager. Every codex review surfaced a different failure-mode
-- interaction at the seams — see docs/design/approve_state_machine.md
-- for the diagnosis and replacement design.
--
-- This migration prepares the audit schema for that replacement:
--
--   * Drops the `git_push_attempt` table and its dependents. The
--     table was specified for an abandoned direct-push design and
--     was never written by any production code (only test scaffolding
--     called `record_git_push_attempt`). With it goes the
--     `push_attempt_id` column on `git_push_outcome` and the five
--     result enum values that required a paired attempt row
--     (`pushed`, `lease_rejected`, `push_rejected`, `push_failed`,
--     `audit_failed_after_push`).
--
--   * Adds `git_push_approve_attempt`, the table of operator approve
--     attempts. One row per `ApproveStagedPush` invocation. The row
--     transitions `started` → `uncertain` (committed in the same TX
--     immediately before the GitHub PATCH) → `resolved` (terminal).
--     Forward-only transitions are enforced by trigger. The
--     `Uncertain` row is the load-bearing durable line: it gates
--     reject from contradicting an approve that may already have
--     advanced the GitHub branch.

-- Defensive precondition: no production caller has written to
-- `git_push_attempt` and no production caller has written a
-- non-(denied|validation_failed|staged) outcome. Refuse the upgrade
-- rather than silently dropping rows. The temp-table-with-CHECK
-- pattern is the same one v4 uses to abort a DDL transaction with a
-- descriptive error in plain SQLite.
CREATE TEMP TABLE _migration_v5_legacy_attempt_guard (
    legacy_rows_must_be_zero INTEGER NOT NULL
        CHECK (legacy_rows_must_be_zero = 0)
);
INSERT INTO _migration_v5_legacy_attempt_guard
    SELECT (SELECT COUNT(*) FROM git_push_attempt)
         + (SELECT COUNT(*) FROM git_push_outcome WHERE push_attempt_id IS NOT NULL)
         + (SELECT COUNT(*) FROM git_push_outcome
                WHERE result NOT IN ('denied', 'validation_failed', 'staged'));
DROP TABLE _migration_v5_legacy_attempt_guard;

DROP TRIGGER git_push_outcome_attempt_matches_request;
DROP TRIGGER git_push_attempt_requires_matching_grant;
DROP TABLE git_push_attempt;

-- `git_push_resolution_requires_staged` lives on `git_push_resolution`
-- but its body references `git_push_outcome`. The rebuild dance below
-- (DROP + CREATE _new + RENAME) leaves the trigger's parsed reference
-- pointing at the dropped table, so subsequent INSERTs into
-- `git_push_resolution` fire a "no such table" error. Drop the
-- trigger explicitly and recreate it verbatim after the rebuild.
DROP TRIGGER git_push_resolution_requires_staged;

-- SQLite cannot remove a column referenced by a CHECK constraint, and
-- there is no in-place way to retighten a TEXT CHECK enum. Rebuild
-- `git_push_outcome` without `push_attempt_id` and with the pruned
-- result enum, copy rows over, then swap. The remaining row data is
-- preserved verbatim.
CREATE TABLE git_push_outcome_new (
    push_request_id TEXT PRIMARY KEY REFERENCES git_push_request(push_request_id),
    completed_at    INTEGER NOT NULL,
    result          TEXT NOT NULL CHECK (
        result IN ('denied', 'validation_failed', 'staged')
    ),
    github_status   INTEGER CHECK (github_status BETWEEN 100 AND 599),
    message         TEXT NOT NULL CHECK (message != '')
);

INSERT INTO git_push_outcome_new
    (push_request_id, completed_at, result, github_status, message)
    SELECT push_request_id, completed_at, result, github_status, message
        FROM git_push_outcome;

DROP TABLE git_push_outcome;
ALTER TABLE git_push_outcome_new RENAME TO git_push_outcome;

-- Recreate the trigger that was dropped before the rebuild so that
-- `git_push_resolution` continues to gate inserts on a matching
-- staged outcome. Body is identical to the v1 definition.
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

-- Approve-attempt state machine. See docs/design/approve_state_machine.md.
--
-- Lifecycle:
--   started   – written immediately on entry to approve_staged_push,
--               before mint, before run_approve. operator + started_at.
--   uncertain – written in the same TX that completes the post-walker
--               lease check, just before update_ref. Carries the
--               captured mint context. Once committed, reject is
--               refused: the PATCH may already have hit GitHub.
--   resolved  – terminal. Carries an outcome:
--                 succeeded            – PATCH confirmed; new_app_tip set.
--                 pre_patch_failure    – failed before update_ref was
--                                        issued. Provably retryable.
--                 post_patch_failure   – update_ref was called but the
--                                        terminal state is uncertain
--                                        (non-2xx, transport drop,
--                                        audit-write failure after
--                                        success). Operator must
--                                        reconcile manually.
CREATE TABLE git_push_approve_attempt (
    attempt_id          TEXT PRIMARY KEY,
    push_request_id     TEXT NOT NULL REFERENCES git_push_request(push_request_id),
    operator            TEXT NOT NULL CHECK (operator != ''),
    started_at          INTEGER NOT NULL CHECK (started_at > 0),
    state               TEXT NOT NULL CHECK (state IN ('started', 'uncertain', 'resolved')),
    outcome             TEXT CHECK (outcome IS NULL OR
                              outcome IN ('succeeded', 'pre_patch_failure', 'post_patch_failure')),
    completed_at        INTEGER CHECK (completed_at IS NULL OR completed_at >= started_at),
    new_app_tip         TEXT CHECK (new_app_tip IS NULL OR length(new_app_tip) = 40),
    failure_detail      TEXT CHECK (failure_detail IS NULL OR failure_detail != ''),
    -- inline mint context (parallels git_push_resolution mint columns).
    -- All four set together when the attempt transitions started → uncertain.
    mint_jti            TEXT,
    mint_github_app_id  INTEGER CHECK (mint_github_app_id IS NULL OR mint_github_app_id >= 0),
    mint_issued_at      INTEGER CHECK (mint_issued_at IS NULL OR mint_issued_at > 0),
    mint_expires_at     INTEGER CHECK (mint_expires_at IS NULL OR mint_expires_at > 0),
    -- Cross-column shape invariants. CHECK fires on both INSERT and UPDATE
    -- so these hold throughout the row's lifetime. Comparisons that include
    -- nullable columns (`outcome`) substitute an empty-string sentinel before
    -- comparing: SQLite's `=` and `IN` return NULL when either side is NULL,
    -- and CHECK constraints treat NULL as pass, so a naive
    -- `(outcome = 'succeeded') = (new_app_tip IS NOT NULL)` would silently
    -- admit a `started` row that already carries a `new_app_tip`. Forcing
    -- the LHS to a definite 0/1 closes that gap.
    CHECK ((state = 'resolved') = (outcome IS NOT NULL)),
    CHECK ((state = 'resolved') = (completed_at IS NOT NULL)),
    CHECK ((coalesce(outcome, '') = 'succeeded') = (new_app_tip IS NOT NULL)),
    CHECK ((coalesce(outcome, '') IN ('pre_patch_failure', 'post_patch_failure'))
        = (failure_detail IS NOT NULL)),
    -- Mint context is all-or-nothing.
    CHECK ((mint_jti IS NULL) = (mint_github_app_id IS NULL)),
    CHECK ((mint_jti IS NULL) = (mint_issued_at IS NULL)),
    CHECK ((mint_jti IS NULL) = (mint_expires_at IS NULL)),
    -- State / mint coupling. The `Uncertain` row's load-bearing role is
    -- to carry the captured mint context for the in-flight PATCH; a
    -- `Started` row by definition has no mint yet; a `Resolved` row
    -- with outcome `succeeded` or `post_patch_failure` must carry the
    -- mint the PATCH used. Without these constraints, manual SQL or a
    -- future migration could land an `uncertain` row with NULL mint
    -- that `git_push_approve_attempt_from_row` would refuse to parse,
    -- making `reject_blocker_for_push` fail on the very state it is
    -- meant to block.
    CHECK (state != 'started' OR mint_jti IS NULL),
    CHECK (state != 'uncertain' OR mint_jti IS NOT NULL),
    CHECK (coalesce(outcome, '') != 'succeeded' OR mint_jti IS NOT NULL),
    CHECK (coalesce(outcome, '') != 'post_patch_failure' OR mint_jti IS NOT NULL)
);

CREATE INDEX idx_git_push_approve_attempt_push_request
    ON git_push_approve_attempt(push_request_id);

-- Forward-only state transitions. SQLite CHECK constraints can validate
-- the NEW row's cross-column shape but cannot compare NEW to OLD; a
-- BEFORE UPDATE trigger is the only way to enforce that the transition
-- itself is legal. The three allowed transitions are enumerated below;
-- anything else (including reverting `resolved`, jumping straight from
-- `started` to a non-pre_patch_failure outcome, or trying to retain
-- `started`) is rejected. `IS NOT` is SQLite's NULL-safe inequality.
CREATE TRIGGER git_push_approve_attempt_forward_only
BEFORE UPDATE ON git_push_approve_attempt
WHEN NOT (
    -- started → uncertain
    (OLD.state = 'started' AND NEW.state = 'uncertain' AND NEW.outcome IS NULL)
    OR
    -- started → resolved(pre_patch_failure)
    (OLD.state = 'started' AND NEW.state = 'resolved'
        AND NEW.outcome = 'pre_patch_failure')
    OR
    -- uncertain → resolved (any outcome)
    (OLD.state = 'uncertain' AND NEW.state = 'resolved'
        AND NEW.outcome IN ('succeeded', 'pre_patch_failure', 'post_patch_failure'))
)
BEGIN
    SELECT RAISE(ABORT, 'illegal git_push_approve_attempt state transition');
END;

-- Mint context is immutable once written. The DAO sets it on the
-- started → uncertain transition; later UPDATEs that complete the
-- attempt must preserve it verbatim. Without this trigger the
-- `Uncertain` row could carry one mint and the `Resolved(Succeeded)`
-- row could carry a different one, breaking the audit's
-- "this approval used credential X" promise.
CREATE TRIGGER git_push_approve_attempt_mint_immutable
BEFORE UPDATE ON git_push_approve_attempt
WHEN OLD.mint_jti IS NOT NULL
 AND (
        NEW.mint_jti IS NOT OLD.mint_jti
     OR NEW.mint_github_app_id IS NOT OLD.mint_github_app_id
     OR NEW.mint_issued_at IS NOT OLD.mint_issued_at
     OR NEW.mint_expires_at IS NOT OLD.mint_expires_at
 )
BEGIN
    SELECT RAISE(ABORT, 'git_push_approve_attempt mint context is immutable once set');
END;
