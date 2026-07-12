# Approve as a state machine

The first implementation of `approve_staged_push` (slice B1e.2e and the
codex iteration that followed it) treated approve as a procedural
sequence: validate, mint, PATCH GitHub, write a `git_push_resolution`
row, delete the staging dir. Each codex review surfaced a different
failure-mode interaction at the seams between those side-effects:
concurrent approve/reject (R1, R3), unbounded HTTP body in error
surfaces (R4), the post-promote audit-write hole (R5), the
crash-between-PATCH-and-audit hole (R6), refinements to the marker
placement (R7). Round 6 added a write-ahead marker file; round 7
flagged that it should be checked before minting and that it was
quarantining staged pushes for failure modes that never reached the
PATCH.

The recurring shape is that approve mutates **three durable stores**
in sequence — GitHub's branch ref, the audit DB, the staging directory
on disk — with no transaction manager. Every fix has been "add more
state to one of the three stores." The mutex (R3), the staging scrub
(R5), and the marker file (R6) collectively constitute a homebrew
two-phase commit. This doc replaces that with an explicit state
machine, with the audit DB designated as the single source of truth
and the only durable mutation point that gates reject.

## Goals

1. Eliminate the contradictory-audit failure mode: it must be
   impossible for `RejectStagedPush` to write a `Rejected` row when an
   approve attempt may have advanced the branch on GitHub.
2. Eliminate the filesystem marker. The state lives in SQLite, which
   already has transaction semantics; the staging dir is just a
   data carrier (the bundle bytes) and is best-effort to clean up.
3. Make the failure surface enumerable. Every reachable state should
   appear in the state schema; recovery should be "load the highest
   state per attempt" rather than "intersect three stores."
4. Make the system property-testable: state transitions form a small
   graph that can be driven by a generator.

## State model

Each operator `ApproveStagedPush` invocation creates an **attempt**
row. An attempt is a value with three states:

```
                                             ┌─ Resolved(Succeeded { new_app_tip })
                                             │
Started ──► Uncertain ──── update_ref ───────┤
   │                                         │
   │                                         └─ Resolved(PostPatchFailure { detail })
   │
   └─ Resolved(PrePatchFailure { detail })
```

- **Started**: written immediately on entry to `approve_staged_push`,
  before mint, before `prepare_approve`. Records the operator, the
  push_request_id, and `started_at`. Pre-PATCH transient failures
  (mint failure, prepare failure, plan failure, walker failure,
  pre-PATCH lease failures) transition to
  `Resolved(PrePatchFailure)`. Note that the entire expensive,
  network-bound part of an approve — the staging fetch, the unbundle,
  and every object upload — runs in this state: none of it can move a
  branch, and boot reconcile resolves a wedged `Started` row without an
  operator. Because that phase runs *after* the mint, the credential's
  identity is persisted up front in the append-only
  `git_push_approve_attempt_mint` ledger (schema v7) — the `Started`
  row itself cannot carry mint columns (v5 CHECK), and without the
  ledger a crash mid-prepare would lose which credential was issued
  and used for the uploads.
- **Uncertain**: written in the same SQLite transaction that completes
  the *last* check before `update_ref` is called — the post-walker
  lease check. Once `Uncertain` lands, the broker has committed to
  "the PATCH may exist on GitHub." Any outcome from `update_ref`
  (success, non-2xx, transport drop, broker crash) lands in
  `Resolved` from here. **`Uncertain` is the load-bearing transition
  that gates reject.**
- **Resolved**: terminal. Carries an `outcome`:
  - `Succeeded { new_app_tip }` — PATCH confirmed succeeded.
  - `PrePatchFailure { detail }` — failed before `update_ref` was
    issued. Provably retryable (the PATCH was never sent).
  - `PostPatchFailure { detail }` — `update_ref` was called but
    GitHub's state is uncertain (non-2xx response, transport drop,
    audit-write failure after success). The push is quarantined
    until manual reconciliation.

A push's overall status is derived from its attempts:

- *Approved* iff any attempt is `Resolved(Succeeded)`. In this case
  there is also a `git_push_resolution` row written in the same TX
  as the attempt completion.
- *Rejected* iff a `git_push_resolution` row with `decision='rejected'`
  exists. Reject is only admitted when no attempt blocks it.
- *Pending* otherwise (attempt(s) in `Started`/`Uncertain`, or only
  `PrePatchFailure` attempts, or no attempts).

`PostPatchFailure` attempts block reject *forever* without explicit
operator reconciliation. There is no automatic recovery from that
state — by design, since the only safe recovery is to inspect the
remote ref.

## Schema (v5)

```sql
-- v5: explicit approve-attempt state machine
--
-- Approve is modelled as an attempt-scoped state machine
-- (see docs/design/approve_state_machine.md). Each operator approve
-- invocation creates one row here; the row transitions Started ->
-- Uncertain (just before update_ref) -> Resolved (terminal).
-- Reject consults this table to refuse the operation when an
-- attempt may have advanced the branch on GitHub.

CREATE TABLE git_push_approve_attempt (
    attempt_id          TEXT PRIMARY KEY,
    push_request_id     TEXT NOT NULL REFERENCES git_push_request(push_request_id),
    operator            TEXT NOT NULL CHECK (operator != ''),
    started_at          INTEGER NOT NULL CHECK (started_at > 0),
    state               TEXT NOT NULL CHECK (state IN ('started','uncertain','resolved')),
    outcome             TEXT CHECK (outcome IS NULL OR
                              outcome IN ('succeeded','pre_patch_failure','post_patch_failure')),
    completed_at        INTEGER CHECK (completed_at IS NULL OR completed_at >= started_at),
    new_app_tip         TEXT CHECK (new_app_tip IS NULL OR length(new_app_tip) = 40),
    failure_detail      TEXT,
    -- inline mint context (parallels git_push_resolution mint columns)
    mint_jti            TEXT,
    mint_github_app_id  INTEGER CHECK (mint_github_app_id IS NULL OR mint_github_app_id >= 0),
    mint_issued_at      INTEGER CHECK (mint_issued_at IS NULL OR mint_issued_at > 0),
    mint_expires_at     INTEGER CHECK (mint_expires_at IS NULL OR mint_expires_at > 0),
    -- cross-column invariants (triggers below)
    CHECK ((state = 'resolved') = (outcome IS NOT NULL)),
    CHECK ((state = 'resolved') = (completed_at IS NOT NULL)),
    CHECK ((outcome = 'succeeded') = (new_app_tip IS NOT NULL)),
    CHECK (outcome IN ('pre_patch_failure','post_patch_failure') = (failure_detail IS NOT NULL))
);

CREATE INDEX idx_git_push_approve_attempt_push_request
    ON git_push_approve_attempt(push_request_id);

-- BEFORE UPDATE triggers enforce forward-only transitions:
-- started -> uncertain or resolved; uncertain -> resolved; resolved -> resolved (no-op).
-- They also enforce that mint context only appears once it has been acquired.
--
-- A sibling BEFORE INSERT trigger on `git_push_resolution`
-- (`git_push_resolution_refuses_active_approve`) refuses any resolution
-- row while an approve attempt for the same `push_request_id` is in
-- one of the blocking states: `Started`, `Uncertain`, or
-- `Resolved(PostPatchFailure)`. The approve path's own joint-TX commit
-- flips the attempt to `Resolved(Succeeded)` *before* its resolution
-- INSERT runs (same TX), so the trigger sees `succeeded` at INSERT
-- time and lets it through. A reject that races the approve sees the
-- in-flight state and is refused at the schema boundary; this is the
-- defence-in-depth that catches future code paths which forget to
-- consult `reject_blocker_for_push`.
```

The same migration drops `git_push_attempt` and its trigger, and drops
`git_push_outcome.push_attempt_id` and the result values that required
it (`pushed`, `lease_rejected`, `push_rejected`, `push_failed`,
`audit_failed_after_push`). None of those values are written by any
production code in the operator-approve world — they were specified
for the abandoned direct-push design and never wired up. Their
deletion is a separate concern of this migration only for staging
hygiene; they have no production references.

## Approve flow

```
acquire decision-lock(push_request_id)
INSERT git_push_approve_attempt (state='started', operator, started_at)   -- TX1
mint() ; on fail:
    UPDATE state='resolved', outcome='pre_patch_failure',
           failure_detail=..., completed_at=now                            -- TX
    return Error
INSERT git_push_approve_attempt_mint (attempt_id, mint_jti, mint_*)        -- TX (v7 ledger)
  -- the burned credential's identity, durable *before* any of the
  -- crash-prone prepare work uses it. A crash anywhere below leaves a
  -- Started row whose mint boot reconcile can recover from this row.
  ; on fail:
    UPDATE state='resolved', outcome='pre_patch_failure',
           mint_jti=..., mint_*, failure_detail=..., completed_at=now      -- TX
    return Error
prepare_approve()  ; on fail (any RunApproveError — the type cannot
    express a PATCH failure, so every one of them is provably pre-PATCH):
    -- mint succeeded but no PATCH was issued. `pre_patch_failure`
    -- proves GitHub is unchanged (retry is safe), but the burned
    -- credential is recorded inline so the audit log can still answer
    -- "which mint was used by this attempt." Mint columns set in the
    -- same UPDATE that resolves the row.
    UPDATE state='resolved', outcome='pre_patch_failure',
           mint_jti=..., mint_*,
           failure_detail=..., completed_at=now                            -- TX
    return Error
UPDATE state='uncertain', mint_jti=..., mint_*                              -- TX2 (load-bearing)
  -- yields an `UncertainAttempt` witness, which is the only key that
  -- opens `PreparedApprove::commit`. The PATCH is unreachable without
  -- this row, so TX2 cannot drift back to before the walker again.
prepared.commit(&witness)   -- final lease recheck + the one branch-moving call
  -- re-verifies GET /git/ref/heads/<branch> == expected_remote_head
  -- immediately before the PATCH, so the time the broker spends
  -- between prepare and here (object-source reaping, TX2) is outside
  -- the publish race. GitHub's force=false PATCH is fast-forward-only,
  -- not compare-and-swap: without this, a branch rewound to an
  -- ancestor during that interval would still accept the PATCH and
  -- publish against a baseline the approval never covered.
  case Err(FinalLeaseLookup | FinalLeaseMoved):
    -- provably pre-PATCH (the PATCH was never sent); the trigger
    -- admits Uncertain → Resolved(PrePatchFailure), mint preserved
    UPDATE state='resolved', outcome='pre_patch_failure',
           failure_detail=..., completed_at=now                             -- TX
    return Error (push remains retryable / rejectable)
  case Ok(Noop | Advanced { new_app_tip }):
    -- single transaction commits both halves
    BEGIN
      UPDATE git_push_approve_attempt
         SET state='resolved', outcome='succeeded',
             new_app_tip=?, completed_at=now
       WHERE attempt_id = ?
      INSERT INTO git_push_resolution
        (push_request_id, decided_at, decision='approved', operator, reason,
         mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at)
    COMMIT
    DELETE staging dir (best-effort, post-TX, warn on failure)
    return StagedPushApproved
  case Err(UpdateRef(_)):
    -- the only variant that wraps a *sent* PATCH; its existence is the
    -- proof that a PATCH reached GitHub and did not confirm. The
    -- classification is the variant match itself — no cause-string
    -- inspection to get wrong.
    UPDATE state='resolved', outcome='post_patch_failure',
           failure_detail=..., completed_at=now                             -- TX
    log AUDIT_WRITE_FAILURE_TARGET ; return Error
```

The TX2 transition replaces the R6 marker file. If the broker crashes
between TX2 and a `Resolved` UPDATE, the attempt is left in
`Uncertain`; reject is refused and boot reconcile surfaces it for
operator review.

The joint TX in the success case replaces R5's `scrub_staging_after_failed_audit`.
Audit and attempt-state are committed atomically; the staging-dir
delete is post-TX and best-effort (a stale dir surfaces in
`promote list` but cannot cause a contradictory reject because the
audit row is already there).

## Reject flow

```
acquire decision-lock(push_request_id)
SELECT state, outcome FROM git_push_approve_attempt
   WHERE push_request_id = ?
classify:
  any row has state='started' or state='uncertain':
    refuse: "approve attempt in flight or unresolved; retry once it resolves
             or trigger manual reconciliation"
  any row has outcome='succeeded':
    refuse via existing StagedPushAlreadyResolved path (the resolution row
    is also present)
  any row has outcome='post_patch_failure':
    refuse: "approve attempt may have advanced the branch on GitHub;
             inspect the remote ref and reconcile manually before
             retrying"
  otherwise (no attempts, or only pre_patch_failure attempts):
    INSERT git_push_resolution (decision='rejected', operator, reason)
    DELETE staging dir (best-effort)
```

No marker file. No `crossed_patch_boundary` predicate. No reading the
filesystem. Reject is a single audit query under a single lock.

## Boot reconcile

On broker startup the audit log is the source of truth. The reconcile
worker queries:

```sql
SELECT attempt_id, push_request_id, state
  FROM git_push_approve_attempt
 WHERE state IN ('started', 'uncertain')
```

For each row:

- `state = 'started'`: the broker crashed during an approve attempt
  before any `update_ref` could have been issued. Transition to
  `Resolved(PrePatchFailure { detail = "broker restart" })` so the
  push is rejectable / retryable. If the v7 mint ledger carries a row
  for the attempt (the crash happened after the mint, e.g. mid-prepare),
  the recovery copies that mint onto the resolved row so the burned
  credential's identity survives; a schema trigger pins the two records
  to agree. The dead attempt's on-disk staging repo is *not* consulted
  or removed (boot reconcile stays filesystem-blind); staging repos are
  keyed by attempt id, so the residue can never collide with the fresh
  attempt a retry mints — it just occupies disk until swept.
- `state = 'uncertain'`: the broker crashed *after* committing to
  PATCH. Log to `AUDIT_WRITE_FAILURE_TARGET`; leave the row. The push
  surfaces in `promote list` flagged as `requires_reconcile`. Operator
  decides; manual tooling completes the attempt to
  `Resolved(Succeeded)` or `Resolved(PostPatchFailure)`.

## What this replaces

| Existing mechanism | Fate |
|---|---|
| `PROMOTE_IN_FLIGHT_MARKER` file + `mark_promote_in_flight` / `clear_promote_in_flight` / `has_promote_in_flight_marker` (R6) | Never landed on `main`; lived only on the abandoned `slice-b1e2e-approve-handler` branch which was superseded by the state-machine restructure — no deletion needed |
| `scrub_staging_after_failed_audit` (R5) | Same as above; subsumed by the joint TX in the design and never imported into the restructure |
| Variant discrimination `RunApproveError::Execute(_)` vs `ExecuteError::UpdateRef(_)` (R7) | Becomes the `Resolved(PrePatchFailure)` vs `Resolved(PostPatchFailure)` outcome choice |
| Per-`RequestId` `decision_lock` (R3) | Dropped — the `git_push_resolution_refuses_active_approve` BEFORE INSERT trigger refuses contradictory commits at the SQL boundary; the in-process lock was an R3-era optimization for diagnostic quality, which `reject_blocker_for_push` + the trigger-error mapping now provide |
| `git_push_resolution` table | Kept; success-row write becomes joint with attempt completion |
| `git_push_attempt` table | Deleted in B1e.3a (never wired up in production code) |
| `git_push_outcome.push_attempt_id` column + dependent result values | Deleted in B1e.3a (same reason) |

## Slice breakdown

- **B1e.3a** — schema v5 migration; `GitPushApproveAttemptRecord` types;
  DAO methods (`start_approve_attempt`, `mark_attempt_uncertain`,
  `complete_attempt_succeeded`, `complete_attempt_pre_patch_failure`,
  `complete_attempt_post_patch_failure`, `reject_blocker_for_push`);
  trigger tests + DAO property tests. **No handler changes.**
- **B1e.3b** — refactor `approve_staged_push` to drive the state
  machine. All existing approve tests pass under the new model.
- **B1e.3c** — wire `AuditLog::reject_blocker_for_push` into
  `reject_staged_push`. Before the resolution INSERT, classify any
  blocking attempt and surface a typed diagnostic
  (`AttemptInFlight`, `AlreadyApproved`, `PostPatchUncertain`)
  instead of leaking the trigger's raw ABORT text. The
  `git_push_resolution_refuses_active_approve` trigger stays as
  defence-in-depth; add an `is_active_approve_refusal` predicate that
  translates the SELECT-vs-INSERT race back into the same typed
  surface. The R6-era marker code never landed on `main` (see the
  table above), so this slice has no deletion work.
- **B1e.3d.1** — boot reconcile worker:
  `AuditLog::list_blocking_approve_attempts` DAO + new
  `boot_reconcile` module that drives `Started` rows to
  `Resolved(PrePatchFailure { detail = "broker restart" })` and
  surfaces `Uncertain` rows on `AUDIT_WRITE_FAILURE_TARGET`. Wired
  into `writd` *after* the broker socket bind (the singleton claim
  for the socket path, so a second `writd` configured against the
  same `--socket` cannot mutate the shared audit DB before its bind
  fails) but before any request serving. Single-writer-ness against
  the audit DB itself is an operator-config invariant — "one daemon
  per `--audit-db`" — shared with the signing-key, VM-session-ledger
  and UI-bearer-file writes; a cross-cutting DB-lock slice is
  deferred. A DAO failure here refuses startup (the audit DB is the
  system of record). The clock supplied to reconcile is clamped up
  to each row's `started_at` before the
  `complete_attempt_pre_patch_failure` write, so a backwards
  wall-clock step between `start_approve_attempt` and the next boot
  cannot violate the `completed_at >= started_at` CHECK.
- **B1e.3d.2** — end-to-end property test that generates
  approve/reject/crash/restart traces and asserts the audit-log
  invariants stated below.

## Test strategy

### DAO-level (B1e.3a)

- Trigger tests: every illegal transition (`resolved → started`,
  `uncertain` with `outcome != NULL`, `succeeded` with
  `new_app_tip = NULL`, etc.) is rejected by SQLite.
- DAO property test: for any sequence of `start → (transition*)`
  operations, the resulting row satisfies the per-state shape
  invariants stated above (this is also covered by the triggers but
  exercising it via the DAO API catches accidental SQL drift).

### End-to-end (B1e.3d)

A `proptest`-driven scenario test:

- Generate a random sequence of `Stage`, `Approve`, `Reject`,
  `CrashAndRestart` events for N push_request_ids.
- For each `Approve`, randomise which sub-step fails (mint /
  prepare / plan / walker / update_ref).
- Drive the broker; assert the following invariants on the audit
  log at the end of each step:
  1. At most one `Resolved(Succeeded)` attempt per push.
  2. If any attempt is `Resolved(Succeeded)` then a
     `git_push_resolution(decision='approved')` row exists for that
     push, with `mint_jti` matching the attempt.
  3. If a `git_push_resolution(decision='rejected')` row exists then
     no attempt for that push is `Uncertain`, `Resolved(Succeeded)`,
     or `Resolved(PostPatchFailure)`.
  4. After a `CrashAndRestart` event, no attempt is in `Started`
     state (boot reconcile transitions them all).
  5. Total `git_push_resolution` rows ≤ total operator decisions
     submitted (no contradictory audits invented mid-flight).

## Open questions

1. **N attempts per push**: design admits multiple attempts. We could
   restrict to one and force operator intervention after each
   pre-patch failure; I think N is right (transient failures are
   common) but the DAO/migration is identical either way.
2. **Reconcile UI**: `promote show <id>` should display attempts
   alongside the staged push. Out of scope for B1e.3a; pinned for
   B1e.3d when we have a full attempt history.
3. **Reaper for stuck `Uncertain` attempts**: a manual operator CLI
   verb (`writ promote reconcile <attempt_id> --confirmed-applied`
   or `--confirmed-not-applied`). Out of scope for the current
   slices; tracked in B2.
4. **Reconciliation transition out of `PostPatchFailure`**: the v5
   forward-only trigger refuses any update from `resolved`, so a
   `PostPatchFailure` row is terminal at the DAO level. The
   reconciliation tooling (see open-question 3 above) will write a
   *new* attempt rather than mutating the quarantined one — keeping
   the audit log append-only and preserving the full reconciliation
   history. `start_approve_attempt` will need a corresponding
   relaxation (or a sibling `start_reconciliation_attempt` entry
   point) at that time. Out of scope for B1e.3a.
