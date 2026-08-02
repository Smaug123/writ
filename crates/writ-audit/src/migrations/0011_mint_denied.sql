-- Give the host capability mint a *total* outcome, so it becomes an ordinary
-- `(request, outcome)` audit pair like every other brokered effect.
--
-- The mint had three endings and recorded only two of them. A request whose
-- policy decision was `Grant` ends in a `grant_log` row (minted) or a
-- `mint_failure` row (the backend refused); a request whose decision was `Deny`
-- ended in *nothing at all* — the `request` row carried the decision, and no
-- outcome row was ever written. That is why the mint could not be expressed as
-- an `EffectAuditTable`: "a request row with no outcome" meant either "denied"
-- or "we stopped mid-effect", and no query could tell the two apart.
--
-- `mint_denied` closes that. A denial is now an outcome row like the other two,
-- which makes the missing-outcome case mean exactly one thing again: writ
-- stopped between the request-row commit and the outcome write. That is what
-- the boot-time unpaired-row scan looks for, and it is why the mint pair can
-- now join it (`EFFECT_AUDIT_PAIRS`) — before this migration the scan would
-- have reported every routine denial as a dangling effect and drowned the
-- signal it exists to carry.
--
-- Why a denial is a *row* and not the guard's `abandon` escape hatch. `abandon`
-- deliberately leaves a request row dangling for reconciliation, and is meant
-- for the rare case where no truthful outcome exists (git-push's staging-IO
-- failure). A denial is not that: "policy said no, and here is the reason" is a
-- perfectly truthful outcome, it is the *common* case rather than a rare one,
-- and routing it through `abandon` would put a dangling row in the log for
-- every denied request — the same drowning, differently spelled. The proxies
-- already record their denials as outcome rows; this makes the mint agree with
-- them.
--
-- The reason is stored verbatim rather than as a code. It is the same string
-- the agent is told, it comes from `policy::decide` (never from the guest), and
-- an operator reading the log wants the sentence, not an enum they must map
-- back by hand.

CREATE TABLE mint_denied (
    request_id TEXT PRIMARY KEY REFERENCES request(request_id),
    denied_at  INTEGER NOT NULL,
    reason     TEXT NOT NULL CHECK (reason != '')
);

-- Index `grant_log` by the column the view joins on.
--
-- Load-bearing, not housekeeping. `grant_log`'s primary key is `jti` and its
-- only other index is `(session_id, issued_at)`, so before this every query
-- against `mint_outcome` — the exclusion triggers below, which fire on *every*
-- mint outcome, and the boot scan's `LEFT JOIN` — would full-scan `grant_log`.
-- In an append-only table that grows for the life of the broker, that makes the
-- cost of recording the n-th outcome O(n), and the cumulative cost quadratic.
-- The backfill's `NOT EXISTS` below has the same problem, so this comes first.
--
-- UNIQUE rather than a plain index, because that is the invariant: one request
-- carries one decision and admits one mint, and the triggers below now enforce
-- it going forward. Making the index unique states the same thing about rows
-- already on disk. No shipped writ can have written a duplicate — a request id
-- is minted per call and `record_grant` runs once per request — so a database
-- where this fails has been edited by hand, and refusing to open it is the
-- correct answer under correctness-over-availability.
CREATE UNIQUE INDEX idx_grant_log_request ON grant_log(request_id);

-- The mint's logical outcome table: one row per request that reached an
-- ending, whichever ending it was. This is what makes the pair expressible as
-- a single `(request_table, outcome_table, join_column)` triple — the shape the
-- unpaired-row scan and the Stage-0 audit-pair oracle both range over — without
-- teaching either of them that one effect has three physical outcome tables.
--
-- `kind` is carried so a reader of the view can tell the endings apart without
-- joining back to all three tables. Nothing in the guard depends on it; it
-- exists for the operator query and for diagnostics.
--
-- A view rather than a fourth table with the union materialised into it: the
-- three tables have genuinely different columns (a grant has a jti, a scope and
-- an expiry; a failure has an error; a denial has a reason), and collapsing
-- them into one wide table with mostly-NULL columns would trade three precise
-- shapes for one shape that permits nonsense. The view is derived, so it cannot
-- disagree with the rows it is derived from.
CREATE VIEW mint_outcome (request_id, kind) AS
    SELECT request_id, 'granted' FROM grant_log
    UNION ALL
    SELECT request_id, 'failed'  FROM mint_failure
    UNION ALL
    SELECT request_id, 'denied'  FROM mint_denied;

-- One outcome per request, enforced across all three tables at once.
--
-- The pair of triggers this replaces (`grant_excludes_mint_failure` and
-- `mint_failure_excludes_grant`) named each other explicitly, which is a shape
-- that costs a new trigger per table *pair*: a third outcome would need four
-- more, and a fourth would need six. Phrasing the guard against `mint_outcome`
-- instead makes each trigger say the thing that is actually invariant — "this
-- request has no outcome yet" — and adding another outcome table extends the
-- view rather than multiplying the triggers.
--
-- These are BEFORE INSERT, so `NEW` is not yet in its own table and the view
-- reflects only already-committed outcomes. That is what makes it correct for
-- the trigger on a table to consult a view that includes that same table.
--
-- Note this is a *tightening* for `grant_log`, whose primary key is `jti`
-- rather than `request_id`: two grants for one request were previously
-- storable. One request carries one decision and admits one mint, so the second
-- row was always nonsense; it is now refused.
DROP TRIGGER grant_excludes_mint_failure;
DROP TRIGGER mint_failure_excludes_grant;

CREATE TRIGGER grant_log_excludes_other_mint_outcomes
BEFORE INSERT ON grant_log
WHEN EXISTS (SELECT 1 FROM mint_outcome WHERE request_id = NEW.request_id)
BEGIN
    SELECT RAISE(ABORT, 'an outcome is already recorded for this request');
END;

CREATE TRIGGER mint_failure_excludes_other_mint_outcomes
BEFORE INSERT ON mint_failure
WHEN EXISTS (SELECT 1 FROM mint_outcome WHERE request_id = NEW.request_id)
BEGIN
    SELECT RAISE(ABORT, 'an outcome is already recorded for this request');
END;

CREATE TRIGGER mint_denied_excludes_other_mint_outcomes
BEFORE INSERT ON mint_denied
WHEN EXISTS (SELECT 1 FROM mint_outcome WHERE request_id = NEW.request_id)
BEGIN
    SELECT RAISE(ABORT, 'an outcome is already recorded for this request');
END;

-- Backfill the denials this schema could not previously hold.
--
-- Not optional, and not cosmetic. The mint joins the boot-time unpaired-row
-- scan with this migration, so without a backfill every request an existing
-- broker ever denied would be reported at boot, forever, as a dangling effect —
-- reintroducing exactly the drowning `mint_denied` exists to prevent, for
-- historical rows instead of future ones.
--
-- Nothing here is invented. The denial is read out of `decision_json`, which
-- `record_pre_mint` wrote in the same row: the request row *is* the record that
-- the request was denied and why, and this migration only moves that fact into
-- the shape the rest of the schema can join against.
--
-- `denied_at` deserves its own sentence, because it is the one column whose
-- meaning shifts slightly. On a row written from here on it is the moment the
-- outcome was committed; on a backfilled row it is `request.received_at` — the
-- commit of the row that carried the decision. Those are the same instant to
-- within one guard's two commits (`policy::decide` runs before the request row
-- is written, so the decision predates `received_at`), and it is a timestamp
-- this database actually recorded rather than one chosen to look plausible.
--
-- Two filters, both deliberate:
--
--   * A `Deny` whose reason is empty is skipped rather than given a placeholder.
--     No shipped writ can produce one — `policy::decide`'s single deny site
--     always formats a reason — so such a row was planted by hand, and a
--     fabricated reason would be worse than the dangling row the scan will
--     report. (The `reason != ''` CHECK would otherwise abort the migration and
--     leave the DB unopenable, which is a poor way to learn this.)
--   * A `Deny` that somehow already has a grant or mint-failure row is skipped.
--     The DAO refuses both pairings, so this cannot arise from writ; the guard
--     is here so a hand-edited database fails the *scan* rather than the
--     migration.
--
-- A `Grant` decision with no outcome is deliberately NOT backfilled: that is a
-- broker that stopped between the request row and the mint, which is precisely
-- the finding the scan exists to surface.
INSERT INTO mint_denied (request_id, denied_at, reason)
SELECT r.request_id, r.received_at, json_extract(r.decision_json, '$.reason')
FROM request r
WHERE json_extract(r.decision_json, '$.result') = 'deny'
  AND COALESCE(json_extract(r.decision_json, '$.reason'), '') != ''
  AND NOT EXISTS (SELECT 1 FROM grant_log g WHERE g.request_id = r.request_id)
  AND NOT EXISTS (SELECT 1 FROM mint_failure f WHERE f.request_id = r.request_id);
