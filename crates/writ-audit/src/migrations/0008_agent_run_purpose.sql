-- Record the caller's `RunAgent` purpose on the agent_run row.
--
-- `purpose` is the caller's opaque reconciliation tag ("plan-submit",
-- "review:plan-abc"). It could not reuse `correlation_id`: that column's
-- character class is alnum + '-' + '_', which rejects the colon bailiff
-- puts in its purposes, so a valid request would have failed at parse
-- time.
--
-- The column is NULLABLE and is not backfilled. NULL means "this run was
-- recorded before writ recorded purposes", which is true; inventing a
-- sentinel would be fabricating a value into an append-only log. NULL is
-- also the permanent shape for runs started via `StartAgentRun`, an RPC
-- that carries a correlation id but has no purpose field at all — so the
-- absence is a live case, not only a historical one.
--
-- The CHECK is an exact mirror of `RunPurpose::try_new`, not a coarse
-- floor: printable ASCII is expressible in GLOB, so SQLite can reject
-- precisely what the Rust parser rejects. That matters because
-- `agent_run_from_row` turns an unparseable value into an Invariant
-- error — a CHECK any weaker than the parser would let a row land that
-- the reader later refuses, which is an audit log that cannot be read
-- back.
--
-- Clause by clause:
--   * `length(cast(purpose AS BLOB)) = length(purpose)` is the one guard
--     against an embedded NUL. It is NOT redundant with the GLOB below:
--     both `length()` and `GLOB` stop at the first NUL, so without this
--     clause 'ab' || char(0) || 'cd' is accepted as a 2-character
--     string. (Verified against SQLite directly.)
--   * `length(purpose) BETWEEN 1 AND 128` — the GLOB forces ASCII, so
--     characters and bytes coincide here.
--   * `NOT GLOB '*[^ -~]*'` — every byte printable ASCII, 0x20..=0x7e.
--     This excludes NUL, CR/LF, TAB, ESC, DEL, the C1 range, and every
--     zero-width and bidi character by construction rather than by
--     blocklist.
--   * the leading/trailing pair — space is the only whitespace the class
--     admits, which is what makes those two tests exhaustive.
--
-- Rust remains the definition of the type; this mirrors it. The
-- invariant to preserve is that no path writes this column except
-- through `RunPurpose::as_str`.
ALTER TABLE agent_run ADD COLUMN purpose TEXT
CHECK (purpose IS NULL OR (
    typeof(purpose) = 'text'
    AND length(cast(purpose AS BLOB)) = length(purpose)
    AND length(purpose) BETWEEN 1 AND 128
    AND purpose NOT GLOB '*[^ -~]*'
    AND purpose NOT GLOB ' *'
    AND purpose NOT GLOB '* '
));
