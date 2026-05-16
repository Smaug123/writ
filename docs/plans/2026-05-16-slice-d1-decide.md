# Slice D1 — `bailiff plan decide`

Bailiff-local operator verb that records an accept/reject decision
on a previously-submitted plan. No agent run, no writd interaction:
this is pure orchestrator-side lifecycle state.

Companion to `docs/plans/2026-05-14-bailiff-split.md`. That doc lists
slice D as "review + decide" bundled; this plan picks decide off as
D1 (smaller, ships in parallel with anything writd-side, unblocks
the read-side gate D2 and E will consult).

## Why split D into D1 + D2

The doc-level slice D mixes two unrelated concerns:

1. **decide** — operator records a verdict on a submitted plan. No
   agent run; no prompt composition; bailiff-local note write.
2. **review** — bailiff spawns a reviewer agent via RunAgent with a
   review-stage capability set, composing the plan body into the
   reviewer's prompt.

D2 (review) requires defining a review-stage variant of
`CapabilitySet`, designing the reviewer prompt template, and wiring
a second RunAgent call site. D1 needs none of that. They have
independent risk profiles, so they ship independently.

## What D1 does

### Decision note shape

A new bailiff-owned note type stored under the same per-plan ref
`refs/notes/bailiff/v1/plans/<plan-id>` as the submission note from
slice C, attached to a **different** deterministic seed OID so the
two notes coexist without colliding.

```rust
pub struct DecisionNote {
    pub plan_id: PlanId,
    pub outcome: Decision,   // Accepted | Rejected
    pub decider: Decider,
    pub decided_at: DateTime<Utc>,
}
```

Canonicalisation, parse round-trip, and `deny_unknown_fields` follow
the same pattern as `PlanNote` in `src/bailiff_plan_note.rs`.

### `Decision` enum — rename, drop `Restart`

The existing in-tree `DecisionOutcome { Accepted, RejectedRestart }`
in `src/agent_plan.rs:554` carries the old "broker auto-restarts on
reject" framing. Bailiff does no auto-anything; "rejected" is just
"this plan is dead, do whatever you want next." Drop the suffix:

```rust
pub enum Decision { Accepted, Rejected }
```

Slice G deletes `agent_plan.rs` anyway; the new enum lives in the
bailiff-side module from day one and never gets aliased from the
old name.

### `Decider` moves to bailiff

The existing `Decider` newtype in `src/agent_plan.rs:614` is generic
enough to use as-is (non-empty bounded string, parses `cli:<user>`
or `agent:<run_id>`). Move it wholesale to a new bailiff-side
module rather than re-export from a doomed location.

### Idempotent storage

One decision per plan. Attempting to decide a plan that already has
a decision note is a typed error (`DecisionAlreadyRecorded`), not a
silent overwrite. Operator workflow on "I want to change my mind"
is "the plan is dead, submit a new one" — bailiff doesn't model
amendments.

The deterministic seed OID for a decision note is `<plan_id>::decision`
(via `plan_decision_seed_blob_bytes(plan_id)`), distinct from the
submission seed `<plan_id>` so the two notes attach to different
objects under the same notes ref.

### Read helper

```rust
pub fn read_decision_note(
    repo: &Path,
    plan_id: PlanId,
) -> Result<Option<DecisionNote>, ReadDecisionError>;
```

Lands in D1 to pin the seed-OID convention now that idempotent
storage is in place. D2 (review) and slice E (implementer) call
this to gate "is the plan accepted?" — the design doc's "read gate
that today is `route_permitted_by_stage_and_decision`."

### CLI verb

```
bailiff plan decide \
    --plan-id <uuid> \
    --accept | --reject \
    [--decider <string>] \
    [--bailiff-repo <path>]
```

`--decider` defaults to `cli:<USER>` (mirrors how the existing
broker code labels operator-driven decisions). `--accept` and
`--reject` are mutually exclusive and one is required.

The verb writes the decision note to bailiff's repo and prints
nothing on success (exit 0); non-zero exit + stderr message on any
failure (unknown plan, already decided, repo path missing).

## What D1 does **not** do

- **Sign the decision.** Per the bailiff-split doc's deferred list:
  bailiff-owned notes are unsigned in v1. Writ's submission
  signature remains the trust anchor for the plan-as-a-whole.
- **Abort.** `PlanAbortReason` exists in `agent_plan.rs` but the
  abort path is implementer-driven (slice E), not operator-driven.
  Deferred entirely from D1.
- **Multi-decision history.** Idempotent only. See "Extending later"
  below for the migration path.
- **Read-side rendering.** `bailiff plan show` / `list` arrive in
  slice F; D1 only adds `read_decision_note` as the predicate D2/E
  consume programmatically.
- **Decider-policy enforcement.** Whether `agent:<run_id>` should
  ever appear on a decision note is a policy question for a later
  slice. D1 stores whatever `Decider` parses.

## Extending later

Two foreseeable extensions, both cheap:

1. **Append-only / history.** Switch from a single `<plan_id>::decision`
   seed to per-decision UUIDs, scan-and-sort on read. The plan-notes
   ref prefix already has `v1`; the migration is
   `refs/notes/bailiff/v1/plans/` → `v2/plans/`, which pre-v1 we
   take freely (no data preservation). The `read_decision_note`
   signature stays single-valued; only its implementation changes.
2. **Bailiff signing decisions.** Add a `signature` field with
   `Option<SshSignature>` (or schema-bump to v2 if we want it
   required). Either way, the change is local to `DecisionNote` and
   the write helper.

The shape we ship in D1 does not foreclose either.

## Risks and tradeoffs

- **`Decider` lives in two places transiently.** The new bailiff-side
  module duplicates the existing `agent_plan::Decider` until slice G
  deletes the latter. We accept the duplication for the same reason
  the slice C composition module duplicates: pulling the in-tree
  types into bailiff-owned namespaces is part of the larger split.
  Slice G is the cleanup.
- **`DecisionOutcome` rename touches existing code.** `Accepted /
  RejectedRestart` is used in `src/agent_plan.rs`, `src/protocol.rs`,
  `src/server.rs`, and the audit migrations. **D1 does not rename
  those.** The old enum keeps its old name in writ-side code that
  slice G will delete; the new `Decision` enum is a parallel,
  bailiff-side type. This is structurally the same parallel-types
  pattern slice C used for `PlanId`.
- **The bailiff-repo handle is not held across operations.** Each
  CLI verb opens the bare repo, writes one note, and drops the
  handle. The notes-write mutex on `NotesRepo` covers concurrent
  decide invocations against the same repo path.

## Plan of work

1. **D1.1 — `Decision` + `Decider` newtypes** in a new
   `src/bailiff_decision.rs`. `Decider` is a verbatim move from
   `agent_plan.rs` (with the existing tests adapted). `Decision`
   is the renamed two-variant enum, plus `Display` / `FromStr` /
   serde coverage. Property tests on the round-trip.
2. **D1.2 — `DecisionNote` shape** alongside `PlanNote` in
   `src/bailiff_plan_note.rs` (or a sibling module, decided in
   implementation). Canonical bytes, parse round-trip, seed-OID
   helper `plan_decision_seed_blob_bytes(plan_id)`.
3. **D1.3 — write helper** `write_decision_note` in
   `src/bailiff_plan_write.rs` (sibling to `write_plan_note`).
   Idempotent-by-error: returns `DecisionAlreadyRecorded` rather
   than overwriting. Integration tests against a real bare repo
   under `tempfile::tempdir`.
4. **D1.4 — read helper** `read_decision_note` in
   `src/bailiff_plan_read.rs` (new module; D2 + E both consume
   from it). Returns `Option<DecisionNote>`. Integration tests
   that write-then-read round-trip.
5. **D1.5 — CLI verb** `bailiff plan decide` in `src/bin/bailiff.rs`.
   Test parses for the flag matrix (`--accept` / `--reject` /
   mutual exclusion / decider default / unknown-plan failure).

Each step is independently revertable. Steps 1–4 are pure library;
step 5 wires them to clap.

## Out of scope

- Anything writd-side. D1 does not change `BrokerState`, the wire
  protocol, or the audit DB.
- `bailiff plan abort` (implementer-driven, slice E).
- `bailiff plan show` / `list` (read paths, slice F).
- Multi-decision history (deferred; see "Extending later").
- Bailiff signing its own notes (deferred per the parent plan).
