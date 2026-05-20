# Slice B2.4 plan — proptest reconciliation events

Drafted 2026-05-20. Tracks task #95 ("B2.4 (stretch): proptest reconciliation events").

## Goal

Extend the existing `tests/approve_state_machine.rs` state-machine
proptest to drive reconciliation events alongside
Stage/Approve/Reject/Crash, so the schema-v6 triggers and the joint
reconciliation/resolution TX are exercised under random traces.

## Scope

Add to the same test file; do not split out. The reconciliation flow
only makes sense composed with the prior state machine, and the
existing model already maintains the slot↔request-id mapping,
timestamp generator, mint factory, and audit handle we need.

## New code

1. **New event:** `Reconcile(usize, ReconcileVerdict)` where
   `ReconcileVerdict ∈ { Applied, NotApplied }`. Two variants only —
   the SHA/operator/reason are fixtures (`oid('r')`, `OPERATOR`,
   `"manual reconciliation"`).
2. **`Scenario::reconcile(slot, verdict) -> Result<(), Refused>`:**
   - Query `approve_attempts_for_push` for the push.
   - Determine the candidate predecessor: latest non-superseded
     attempt whose state is `Resolved(PostPatchFailure)` or
     `Uncertain`.
   - For `Uncertain` predecessors, require a boot-observed marker —
     easiest: only attempt the call if the most recent prior event
     was `Crash` (which writes the marker via
     `reconcile_pending_approve_attempts`). Otherwise return `Refused`.
   - If no eligible predecessor, return `Refused` (matches existing
     pattern — refusal shrinks).
   - Call the matching DAO method; surface successes for invariant 5
     counting.
3. **Crash semantics:** No change. Boot reconcile already writes the
   `git_push_approve_attempt_boot_observed` row for surviving
   `Uncertain` rows — that's exactly what makes them reconcilable on
   the *next* event.
4. **`arb_event` extension:** add a `Reconcile` arm to `prop_oneof!`
   with both verdicts.

## New invariants (extend `check_invariants`)

- **I6 (chain length ≤ 1):** No attempt with `supersedes_attempt_id`
  set has another attempt superseding it. Already enforced by the
  UNIQUE partial index, but checking this in-test pins it.
- **I7 (Applied ⇒ resolution):** For every attempt that is
  `Resolved(Succeeded)` AND has `supersedes_attempt_id` set, the push
  carries a `git_push_resolution(Approved)` row whose `mint_jti`
  matches the predecessor's mint.
- **I8 (NotApplied ⇒ no fresh resolution):** A reconciliation row
  with outcome `pre_patch_failure` (and `supersedes_attempt_id` set)
  does not by itself produce a resolution row — i.e. it's safe to
  call this and find `entry.resolution` is `None` unless a *later*
  approve/reject ran.
- **I9 (post-Applied reject refusal):** After an Applied
  reconciliation lands, `reject_blocker_for_push` reports no blocker
  AND a subsequent `Reject` for that push must be refused by the
  *resolution* gate (push already approved) rather than the *blocker*
  gate. Lightweight assertion: don't try to drive reject here; just
  confirm `entry.resolution` is `Some(Approved)`.

**Generalise I5:** A successful `Reconcile(_, Applied)` counts as one
submitted operator decision (writes a resolution row);
`Reconcile(_, NotApplied)` does not.

## Refused-vs-error discipline

Keep the current pattern: any DAO call that returns
`AuditError::Invariant(...)` from a precondition violation maps to
`Refused` and the proptest skips the step. Real bugs (Sqlite errors,
mint missing, foreign-key violations) propagate via `unwrap()` so a
violation surfaces with a real trace.

## Out of scope

- No CLI/server-side reconciliation path. The proptest exercises the
  DAO + schema, matching the existing model's level (the unit tests
  in `git_push_approve` cover the orchestrator).
- No new boot-observed event. We piggyback on `Crash`; introducing a
  separate `BootObserve` event would let `Uncertain` survive crashes
  that don't tick the reconcile worker, but the current model has no
  such state.

## Estimated size

~150–200 lines added to `tests/approve_state_machine.rs`. No
production-code changes expected. Single PR, single commit.

## Open question

Whether to also assert that a `Reconcile(slot, NotApplied)` followed
by a `Reject(slot)` in the trace produces a
`git_push_resolution(Rejected)` row — i.e. NotApplied truly clears
the blocker. This would require driving a deterministic event pair
from inside the proptest's model rather than waiting for the random
walk to produce it; doable but pushes the test toward example-based.
Preference: rely on the random walk plus invariant I5 (resolution
count ≤ submitted decisions) to surface inconsistency, and skip the
targeted pair.
