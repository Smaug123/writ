-- v4: git_push_resolution mint context
--
-- The approve path mints a short-lived GitHub App installation token
-- immediately before promoting the staged push. That mint must be
-- auditable *with* the resolution row, because the originating session
-- is long since closed by the time the operator decides — so the mint
-- cannot be threaded through the session-scoped `request` / `grant_log`
-- audit chain. Instead each approve resolution carries its own mint
-- context inline: enough to answer "did this approval ever produce a
-- credential, and which one?" without joining against the closed
-- session's audit trail.
--
-- Reject decisions never mint, so all four mint columns are NULL there.
-- The two triggers below enforce the cross-column invariant on the row:
-- `approved` iff all four mint columns NOT NULL; `rejected` iff all
-- four are NULL. Without them a raw INSERT could record a contradiction
-- between the decision and the mint context.

-- Defensive precondition: the v3 schema admitted `decision = 'approved'`
-- even though no shipped daemon writes such rows (the only caller — the
-- reject handler — writes `Rejected`; the approve handler currently
-- returns a placeholder). If a legacy `approved` row sneaked in (raw
-- DB tooling, a test fixture replayed against a long-running DB), we
-- have no mint context to backfill and the new read path would surface
-- it as an invariant error after migration. Refuse the upgrade so an
-- operator can deliberately resolve the situation rather than discover
-- silent unreadable rows later. Wrapped in a temp table whose CHECK
-- fires the moment the count is non-zero — the only SQL idiom that
-- aborts a DDL transaction with a descriptive error in plain SQLite.
CREATE TEMP TABLE _migration_v4_legacy_approved_guard (
    legacy_approved_rows_must_be_zero INTEGER NOT NULL
        CHECK (legacy_approved_rows_must_be_zero = 0)
);
INSERT INTO _migration_v4_legacy_approved_guard
    SELECT COUNT(*) FROM git_push_resolution WHERE decision = 'approved';
DROP TABLE _migration_v4_legacy_approved_guard;

ALTER TABLE git_push_resolution ADD COLUMN mint_jti TEXT;
ALTER TABLE git_push_resolution ADD COLUMN mint_github_app_id INTEGER
    CHECK (mint_github_app_id IS NULL OR mint_github_app_id >= 0);
ALTER TABLE git_push_resolution ADD COLUMN mint_issued_at INTEGER
    CHECK (mint_issued_at IS NULL OR mint_issued_at > 0);
ALTER TABLE git_push_resolution ADD COLUMN mint_expires_at INTEGER
    CHECK (mint_expires_at IS NULL OR mint_expires_at > 0);

CREATE TRIGGER git_push_resolution_mint_matches_decision_insert
BEFORE INSERT ON git_push_resolution
WHEN
    (NEW.decision = 'approved' AND (
        NEW.mint_jti IS NULL
        OR NEW.mint_github_app_id IS NULL
        OR NEW.mint_issued_at IS NULL
        OR NEW.mint_expires_at IS NULL
    ))
    OR
    (NEW.decision = 'rejected' AND (
        NEW.mint_jti IS NOT NULL
        OR NEW.mint_github_app_id IS NOT NULL
        OR NEW.mint_issued_at IS NOT NULL
        OR NEW.mint_expires_at IS NOT NULL
    ))
BEGIN
    SELECT RAISE(ABORT, 'git push resolution mint context must match decision');
END;

-- Defence in depth: the table is INSERT-only at the DAO layer, but the
-- column-level CHECKs don't fire on UPDATE for the cross-column shape,
-- so an UPDATE that flipped `decision` without touching the mint
-- columns (or vice versa) could otherwise leave a contradictory row.
CREATE TRIGGER git_push_resolution_mint_matches_decision_update
BEFORE UPDATE ON git_push_resolution
WHEN
    (NEW.decision = 'approved' AND (
        NEW.mint_jti IS NULL
        OR NEW.mint_github_app_id IS NULL
        OR NEW.mint_issued_at IS NULL
        OR NEW.mint_expires_at IS NULL
    ))
    OR
    (NEW.decision = 'rejected' AND (
        NEW.mint_jti IS NOT NULL
        OR NEW.mint_github_app_id IS NOT NULL
        OR NEW.mint_issued_at IS NOT NULL
        OR NEW.mint_expires_at IS NOT NULL
    ))
BEGIN
    SELECT RAISE(ABORT, 'git push resolution mint context must match decision');
END;
