-- v6: support manual reconciliation of `Resolved(PostPatchFailure)`
-- attempts via a new born-terminal row that supersedes the predecessor.
--
-- The v5 schema makes `Resolved` terminal (the forward-only trigger
-- refuses any UPDATE that originates from `state='resolved'`). That is
-- the right invariant for the in-flight approve workflow — once an
-- attempt has committed an outcome, the audit log must never let a
-- later step rewrite it — but it also means a `Resolved(PostPatchFailure)`
-- attempt cannot be cleared from the blocker query by mutating it.
--
-- The B2 reconciliation flow keeps the audit log append-only by writing
-- a *new* attempt row that records the operator's manual decision. The
-- new row carries `supersedes_attempt_id` pointing back at the
-- quarantined predecessor; the blocking-query reads (`start_approve_attempt`,
-- `reject_blocker_for_push`, `list_blocking_approve_attempts`) filter
-- out attempts that have been superseded so a successful reconciliation
-- behaves like the predecessor never blocked. Both attempt rows remain
-- on disk, preserving the full reconciliation history.
--
-- See docs/design/approve_state_machine.md ("Open questions", item 4).

ALTER TABLE git_push_approve_attempt
    ADD COLUMN supersedes_attempt_id TEXT
        REFERENCES git_push_approve_attempt(attempt_id);

-- A row can be superseded at most once. Without UNIQUE, manual SQL or
-- a future code path could write two reconciliation rows pointing at
-- the same predecessor, leaving the blocker query unable to identify
-- *which* one cleared the quarantine. The partial index syntax restricts
-- the constraint to non-NULL values: ordinary (non-reconciliation) rows
-- carry NULL and are free to coexist.
CREATE UNIQUE INDEX idx_git_push_approve_attempt_supersedes_unique
    ON git_push_approve_attempt(supersedes_attempt_id)
    WHERE supersedes_attempt_id IS NOT NULL;

-- A reconciliation row must be born terminal: the operator inspects
-- the remote ref and commits the answer, there is no "started" or
-- "uncertain" phase. The reconciliation row's outcome is either
-- `succeeded` (operator confirmed the PATCH landed) or
-- `pre_patch_failure` (operator confirmed it did not, and the push is
-- once again rejectable / retryable). `post_patch_failure` is forbidden
-- on a reconciliation row — that outcome is a broker-runtime statement
-- about uncertainty, not an operator decision; admitting it would let
-- reconciliation cycle indefinitely.
CREATE TRIGGER git_push_approve_attempt_reconciliation_is_born_terminal
BEFORE INSERT ON git_push_approve_attempt
WHEN NEW.supersedes_attempt_id IS NOT NULL
 AND (NEW.state != 'resolved'
   OR NEW.outcome NOT IN ('succeeded', 'pre_patch_failure'))
BEGIN
    SELECT RAISE(ABORT, 'reconciliation attempt must be born resolved with succeeded or pre_patch_failure outcome');
END;

-- A reconciliation row's predecessor must be an attempt that needs
-- clearing: either `Uncertain` (the broker crashed mid-PATCH and the
-- attempt is still in flight on the audit log) or
-- `Resolved(PostPatchFailure)` (the broker observed the PATCH go out
-- and the response was uncertain). `Started` is excluded because boot
-- reconcile already drives those to `pre_patch_failure` automatically;
-- `Resolved(Succeeded)` and `Resolved(PrePatchFailure)` are excluded
-- because they are not blockers and reconciliation has nothing to do.
--
-- The predecessor must also not itself have been superseded — without
-- this clause an operator could chain reconciliation rows
-- (a → b → c → ...) which would defeat the UNIQUE-on-supersedes_attempt_id
-- and admit multiple "live" reconciliation lineages.
CREATE TRIGGER git_push_approve_attempt_reconciliation_predecessor_eligible
BEFORE INSERT ON git_push_approve_attempt
WHEN NEW.supersedes_attempt_id IS NOT NULL
 AND NOT EXISTS (
        SELECT 1 FROM git_push_approve_attempt p
        WHERE p.attempt_id = NEW.supersedes_attempt_id
          AND (
                p.state = 'uncertain'
             OR (p.state = 'resolved' AND p.outcome = 'post_patch_failure')
          )
          AND NOT EXISTS (
                SELECT 1 FROM git_push_approve_attempt q
                WHERE q.supersedes_attempt_id = p.attempt_id
          )
 )
BEGIN
    SELECT RAISE(ABORT, 'reconciliation attempt predecessor is not an eligible blocker');
END;

-- The reconciliation row must reference the same push as its
-- predecessor. Without this guard a manual SQL writer could clear a
-- blocker on push A by writing a reconciliation row against push B,
-- which would silently strand push A's quarantine.
CREATE TRIGGER git_push_approve_attempt_reconciliation_same_push
BEFORE INSERT ON git_push_approve_attempt
WHEN NEW.supersedes_attempt_id IS NOT NULL
 AND NEW.push_request_id != (
        SELECT push_request_id FROM git_push_approve_attempt
        WHERE attempt_id = NEW.supersedes_attempt_id
 )
BEGIN
    SELECT RAISE(ABORT, 'reconciliation attempt must reference the same push as its predecessor');
END;

-- `git_push_resolution_refuses_active_approve` from v5 refuses any
-- resolution INSERT while a push has a blocking attempt. v6 introduces
-- the supersession concept; a `Resolved(PostPatchFailure)` attempt that
-- a *successful* reconciliation row supersedes is no longer a blocker,
-- and the joint TX of `record_reconciliation_attempt_applied` must be
-- able to land its `git_push_resolution(decision='approved')` row. Drop
-- the v5 trigger and recreate it with the supersession filter so the
-- contradiction window stays closed for non-superseded blockers.
DROP TRIGGER git_push_resolution_refuses_active_approve;

CREATE TRIGGER git_push_resolution_refuses_active_approve
BEFORE INSERT ON git_push_resolution
WHEN EXISTS (
    SELECT 1 FROM git_push_approve_attempt a
    WHERE a.push_request_id = NEW.push_request_id
      AND (a.state IN ('started', 'uncertain')
        OR (a.state = 'resolved' AND a.outcome = 'post_patch_failure'))
      AND NOT EXISTS (
          SELECT 1 FROM git_push_approve_attempt b
          WHERE b.supersedes_attempt_id = a.attempt_id
      )
)
BEGIN
    SELECT RAISE(ABORT, 'git push resolution refused: approve attempt is in-flight or quarantined');
END;
