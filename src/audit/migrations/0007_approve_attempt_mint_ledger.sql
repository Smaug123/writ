-- v7: record the approve-time mint durably *before* the prepare phase.
--
-- The v5 state machine records the mint context inline on the attempt
-- row, but only at the `started → uncertain` transition (TX2) — the v5
-- CHECK `state != 'started' OR mint_jti IS NULL` forbids it earlier.
-- Since the Uncertain window was narrowed to the single `PATCH`
-- round-trip, everything expensive (staging fetch, unbundle, plan,
-- object uploads) runs *before* TX2 with the row still `started` and
-- the mint columns still NULL. A broker crash in that phase therefore
-- lost the identity of a credential that was really issued — and
-- really used, for the object uploads — against GitHub: boot reconcile
-- resolved the `started` row with no mint context to preserve.
--
-- This migration adds an append-only ledger keyed by attempt id. The
-- broker inserts the ledger row immediately after the mint returns,
-- before any of the prepare work starts, so from that point on the
-- credential's identity survives any crash. The attempt row's own
-- mint columns are unchanged (still written at TX2, still governed by
-- the v5 CHECKs); the trigger below pins the two records to agree.
--
-- Widening the `state` CHECK enum instead (a distinct `minted` state)
-- would need a full table rebuild: SQLite cannot alter a CHECK, the
-- table has an incoming FK from `git_push_approve_attempt_boot_observed`
-- plus a self-FK, and `PRAGMA foreign_keys` cannot be toggled inside
-- the migration transaction. The ledger records the same fact with a
-- plain CREATE TABLE and no change to the blocker/reconcile queries,
-- for which "mint recorded" and "no mint yet" are the same state:
-- both are provably pre-PATCH.
CREATE TABLE git_push_approve_attempt_mint (
    attempt_id          TEXT PRIMARY KEY NOT NULL
        REFERENCES git_push_approve_attempt(attempt_id),
    mint_jti            TEXT NOT NULL,
    mint_github_app_id  INTEGER NOT NULL CHECK (mint_github_app_id >= 0),
    mint_issued_at      INTEGER NOT NULL CHECK (mint_issued_at > 0),
    mint_expires_at     INTEGER NOT NULL CHECK (mint_expires_at > 0),
    recorded_at         INTEGER NOT NULL CHECK (recorded_at > 0)
);

-- A ledger row exists only for an attempt that is still `started`.
-- The runtime writes it in the gap between the mint and the prepare
-- phase; by the time the row is `uncertain` or `resolved` the mint is
-- carried inline and a late ledger INSERT could only rewrite history.
-- (`started` rows have NULL inline mint by the v5 CHECK, so this also
-- guarantees a ledger INSERT can never contradict inline columns.)
CREATE TRIGGER git_push_approve_attempt_mint_ledger_requires_started
BEFORE INSERT ON git_push_approve_attempt_mint
WHEN NOT EXISTS (
        SELECT 1 FROM git_push_approve_attempt a
        WHERE a.attempt_id = NEW.attempt_id
          AND a.state = 'started'
)
BEGIN
    SELECT RAISE(ABORT, 'attempt mint ledger row requires a started attempt');
END;

-- The inline mint columns, whenever they get written (TX2 or a
-- mint-capturing pre-PATCH resolve), must agree with the ledger row if
-- one exists. Without this, the audit log could carry two answers to
-- "which credential did this attempt burn?".
CREATE TRIGGER git_push_approve_attempt_mint_matches_ledger
BEFORE UPDATE ON git_push_approve_attempt
WHEN NEW.mint_jti IS NOT NULL
 AND EXISTS (
        SELECT 1 FROM git_push_approve_attempt_mint m
        WHERE m.attempt_id = NEW.attempt_id
          AND (m.mint_jti != NEW.mint_jti
            OR m.mint_github_app_id != NEW.mint_github_app_id
            OR m.mint_issued_at != NEW.mint_issued_at
            OR m.mint_expires_at != NEW.mint_expires_at)
)
BEGIN
    SELECT RAISE(ABORT, 'git_push_approve_attempt mint columns must match the mint ledger row');
END;

-- The other direction of the same agreement: an attempt with a ledger
-- row must never *resolve* with its inline mint columns still NULL.
-- Without this, a resolve path that simply doesn't set the mint
-- columns (they are preserved as NULL, so the matches-ledger trigger
-- above never fires) would leave `Resolved { mint: None }` alongside a
-- ledger row that says a credential was burned — two conflicting
-- answers to the same audit question. The DAO copies the ledger mint
-- into every resolve that originates from `started`; this trigger is
-- the defence in depth against raw SQL and future DAO paths.
CREATE TRIGGER git_push_approve_attempt_resolve_carries_ledger_mint
BEFORE UPDATE ON git_push_approve_attempt
WHEN NEW.state = 'resolved'
 AND NEW.mint_jti IS NULL
 AND EXISTS (
        SELECT 1 FROM git_push_approve_attempt_mint m
        WHERE m.attempt_id = NEW.attempt_id
)
BEGIN
    SELECT RAISE(ABORT, 'resolving a minted attempt must carry the ledger mint');
END;

-- The ledger is append-only, like the audit log it serves: a row
-- records "this credential was issued for this attempt", which no
-- later event can make untrue. (The `_ledger_` infix keeps these
-- distinct from v5's `git_push_approve_attempt_mint_immutable`, which
-- guards the *inline* mint columns on the attempt table.)
CREATE TRIGGER git_push_approve_attempt_mint_ledger_immutable
BEFORE UPDATE ON git_push_approve_attempt_mint
BEGIN
    SELECT RAISE(ABORT, 'git_push_approve_attempt_mint rows are immutable');
END;

CREATE TRIGGER git_push_approve_attempt_mint_ledger_no_delete
BEFORE DELETE ON git_push_approve_attempt_mint
BEGIN
    SELECT RAISE(ABORT, 'git_push_approve_attempt_mint rows are append-only');
END;
