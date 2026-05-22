# Slice G — strip writ

Drafted 2026-05-21. Implements slice G of
`docs/plans/2026-05-14-bailiff-split.md`: delete the writ-side
legacy plan code that bailiff now owns end-to-end. This is the
destructive consolidation that closes the half-migrated state slices
A–F left behind.

## What ships

Net deletion of the writ-side plan surface:

- `writ plan list / show / decide` CLI verbs.
- Broker RPC variants `ClientMessage::{ListPlans, ShowPlan,
  DecidePlan}` and the corresponding `ServerMessage` responses
  (`Plans`, `Plan`, `UnknownPlan`, `PlanDecided`,
  `PlanAlreadyDecided`).
- Broker handlers `list_plans` / `show_plan` / `decide_plan` in
  `src/server.rs`.
- The VM-side HTTP route layer at `src/vm_http/plan.rs` (~3.6k LoC).
- The in-tree composition module `src/bailiff.rs` (~440 LoC),
  whose remaining live callers (`bailiff_plan_review`,
  `bailiff_plan_implement`) absorb the separator constants and
  compose helpers.
- The `Stage` and `read_plan_id` fields on
  `VmAgentRunConfigResponse` in `src/agent_run.rs`.
- The audit DAO at `src/audit/plan.rs` (~3.7k LoC) and the
  five plan-related tables (`plan`, `plan_decision`,
  `plan_review`, `plan_addendum`, `plan_abort`).
- The top-level `agent_plan` module (~1.7k LoC).

After G, writ knows nothing about plans. Bailiff owns the workflow
end-to-end; writ only mints credentials, runs agents, and signs
output envelopes.

## What stays in scope

- Source-tree squash: edit code, no compatibility shims, no `#[deprecated]`
  re-exports. Pre-v1, no external consumers.
- A schema-migration squash: edit `0001_initial.sql` in place to
  drop the plan-related `CREATE TABLE`s; delete
  `0002_plan_addendum.sql` and `0003_plan_abort.sql`. Pre-v1, no
  prod consumers; the design's "bulk-drop the audit DB" sentence
  sanctions discarding dev DBs that historically ran the old 0001.
  Goes in a **standalone PR** so the migration history rewrite is
  reviewable on its own.
- Wire-protocol enum exhaustiveness: deleting a `ClientMessage`
  variant deletes its `ServerMessage` reply variants in the same
  PR, so the protocol enum is always exhaustive at compile time.

## What stays out of scope

- **Renaming `capture_operator_identity`.** It still serves the
  non-plan writ CLI verbs (`writ git-push approve / reject`); the
  `cli:unknown` fallback only goes away for the plan-decide call
  site. Bailiff's strictness (require `--decider` or `$USER`)
  is an architectural choice for the new shape and does not
  retro-apply to the surviving writ verbs.
- **Multi-version protocol shims.** No "accept v1 plan-RPCs and
  reply with `PlanGone`" transitional state. The CLI is the only
  caller; delete both ends in one PR.
- **Slice H docs.** Rewriting `docs/design/broker.md` to no
  longer mention plans is the next slice; G keeps the existing
  docs unchanged so the diff is purely code. **Reviewers (and
  Codex): docs are intentionally stale through slice G; flagging
  out-of-date references to deleted plan types is not actionable
  feedback for this slice.**
- **`bailiff plan abort`.** Still deferred (from D1, F); not part
  of G either.

## Dependency graph (why the sub-slices are ordered the way they are)

Reading "→" as "imports from":

```
src/bin/writ.rs (PlanCmd verbs)
  → protocol::{ClientMessage, ServerMessage} (plan variants)
  → agent_plan::{PlanId, Stage, Decider, ...}

src/server.rs (list_plans / show_plan / decide_plan handlers)
  → protocol::{ClientMessage, ServerMessage} (plan variants)
  → agent_plan::*
  → audit::plan (DAO)

src/vm_http/plan.rs (route layer)
  → agent_plan::*
  → audit::plan (DAO)
  → agent_run::{stage, read_plan_id} (on VmAgentRunConfigResponse)

src/bailiff.rs (compose helpers)
  → agent_plan::{Stage, PlanBody}
  → agent_run::{stage, read_plan_id}
  ← src/bailiff_plan_review.rs (REVIEWER_PROMPT_SEPARATOR)
  ← src/bailiff_plan_implement.rs (PLAN_PROMPT_SEPARATOR)
  ← src/bin/writ-vm.rs (fetch_effective_prompt — legacy VM dispatch)
  ← src/vm_client.rs (docstring reference only)

src/agent_run.rs
  → agent_plan::{Stage, PlanId} (via field types)
  ← src/vm_http/plan.rs
  ← src/bailiff.rs

src/audit/plan.rs
  → agent_plan::*
  ← src/server.rs
  ← src/vm_http/plan.rs

src/agent_plan.rs
  ← everywhere above
```

Each sub-slice deletes a layer once its readers are gone. Top-down
(outer first), bottom-up by import direction.

## Plan of work

### G1 — strip writ broker plan RPC (CLI + protocol + server)

Delete the writ-broker plan dispatch path top-to-bottom in one PR:

- Remove `PlanCmd::{List, Show, Decide}` from `src/bin/writ.rs`,
  the `plan` dispatch arm, the matching CLI parse tests, and the
  call to `capture_operator_identity` at the decide site.
- Remove `ClientMessage::{ListPlans, ShowPlan, DecidePlan}` and
  `ServerMessage::{Plans, Plan, UnknownPlan, PlanDecided,
  PlanAlreadyDecided}` from `src/protocol.rs`, their serde
  discriminants, value/debug impls, and tests.
- Remove `list_plans`, `show_plan`, `decide_plan` from
  `src/server.rs`, the dispatch entry, and the ~21 handler tests.

Why bundled: the CLI is the only caller; the server is the only
implementor; bundling keeps the enum exhaustive at every commit
boundary and removes a self-contained dispatch path in one PR.

`agent_plan.rs` and `audit::plan` remain — they still have other
readers (`vm_http/plan.rs`, `bailiff.rs`).

~-1.7k LoC. Single PR.

### G2 — strip VM HTTP plan route layer (and Path-2 caller chain)

Delete `src/vm_http/plan.rs` entirely; remove its module
declaration; remove the writ-vm route mount.

This is where the `Stage` / `read_plan_id` route-auth checks live;
deleting the route layer drops those reads. `audit::plan`'s
remaining readers go to zero after this PR.

**Scope expansion (in-progress):** Codex flagged a P1 on the first
G2 attempt — removing the plan routes leaves
`StartAgentRun { stage, read_plan_id }` and the writ-vm `Cmd::Agent`
dispatch as half-migrated state with no surviving consumer. The
fix-forward (this PR) absorbs what was originally planned as G4
into G2: strip `stage` / `read_plan_id` from the entire Path-2
chain (`writ agent run` CLI args → `ClientMessage::StartAgentRun`
wire variant → `server.rs` dispatch → `start_agent_run_session` →
`VmHttpAgentRunService::insert_run_config` → `VmAgentRunConfigResponse`),
restore writ-vm `Cmd::Agent { AgentCmd::Run }` minus
`fetch_effective_prompt` (pass raw prompt through), and delete
`check_start_agent_run_binding`. The audit DAO row still carries
`stage` / `read_plan_id` columns (defaulted to `Stage::Execute` /
`None` at insert time) until G5's pure-deletion sweep.

`src/bailiff.rs` and `fetch_effective_prompt` are now the only
remaining `Stage` readers; G3 deletes them.

~-3.6k LoC (route layer) + ~-400 LoC (Path-2 strip) net. Single PR.

### G3 — relocate compose helpers, delete src/bailiff.rs

Landed as a single PR on branch
`slice-g3-relocate-compose-helpers`. Final shape diverged slightly
from this plan:

- `PLAN_PROMPT_SEPARATOR` is now a private `const` in
  `src/bailiff_plan_implement.rs`; the `AgentPrompt`-typed
  `compose_implementer_prompt` from `src/bailiff.rs` was *not*
  relocated — it had no production callers (only an integration
  proptest), and the consumer module already had its own bytes-
  typed `compose_implementer_prompt_bytes`. Delete-not-move was the
  cleaner outcome (gospel principle 3, no speculative generality).
- The proptest that previously called `compose_implementer_prompt`
  in `tests/properties.rs` was relocated into
  `src/bailiff_plan_implement.rs`'s `compose_tests` mod, retargeted
  at `compose_implementer_prompt_bytes` (now reachable via
  `use super::*` since both items are private). Gospel principle 4
  said keep the property test; principle 1 said run it next to
  what it tests.
- Symmetric treatment for the reviewer side: `REVIEWER_PROMPT_SEPARATOR`
  moved into `src/bailiff_plan_review.rs` as a private `const`;
  `compose_reviewer_prompt` was a no-caller delete.
- `fetch_effective_prompt` was already deleted in G2's fix-forward
  (writ-vm plan dispatch went with it), so G3 just confirmed
  no callers remained.
- `src/vm_client.rs`'s `fetch_plan` docstring was updated to note
  the route handler is gone and the function awaits deletion in G5.
- A stale `// crate::bailiff` comment in `src/agent_plan.rs` was
  retargeted to point at the surviving workflow modules.

After G3, `src/agent_run.rs`'s `Stage` / `read_plan_id` fields
have no readers and `agent_plan.rs`'s sole remaining reader is
`src/audit/plan.rs`. Final diff was -347 / +105 LoC across 8 files
(`src/bailiff.rs` deleted outright at 251 LoC).

### G4 — absorbed into G2

The `VmAgentRunConfigResponse` field strip originally planned for
G4 was pulled forward into G2 (see scope-expansion note above)
because removing the VM HTTP plan routes is exactly what makes
the carried `stage` / `read_plan_id` fields dead end-to-end. The
hand-rolled missing-vs-null visitor was replaced with derive +
`deny_unknown_fields` at the same time — the distinction only
mattered while `read_plan_id` was load-bearing.

No standalone PR.

### G5 — combined pure-deletion PR (agent_run fields + audit DAO + agent_plan)

Bundled per "you can combine any amount of pure deletion you
like": once G1–G4 have removed the readers, this PR is a single
sweep of pure removals.

- Delete `src/audit/plan.rs` (~3.7k LoC). Remove its `pub mod
  plan;` registration from `src/audit/mod.rs`. Update any
  audit-level integration tests that exercise the plan DAO
  (they should fail to compile, which is the signal).
- Delete `src/agent_plan.rs` (~1.7k LoC). Remove `pub mod
  agent_plan;` from `src/lib.rs`. The compiler is the verifier
  here: if anything still imports from `agent_plan`, the build
  fails and reveals an earlier slice missed a caller.

(`agent_run.rs`'s `Stage` / `read_plan_id` strip is its own
sub-slice, G4 above. Originally I drafted these as G4/G5/G6;
bundling G5+G6 here because both are pure deletions once their
readers are gone. Holding G4 separate because the visitor /
field-removal edits are surgical rather than wholesale and
deserve to be reverted in isolation if anything regresses.)

The schema-migration squash is **not part of this PR** — see
the standalone migration PR below.

~-5.4k LoC. Single PR.

### Standalone PR — migration squash

Independent of the G-ordered work; runs in parallel with G1–G5
and can land in any order relative to them (its only constraint
is that no in-tree code reads from the plan tables once it lands,
which G5 guarantees). Worth landing **after** G5 so the source-
tree and the schema agree at every commit, but the PR itself
touches only `src/audit/migrations/`.

- Edit `src/audit/migrations/0001_initial.sql` in place to drop
  the plan-related `CREATE TABLE`s (`plan`, `plan_decision`,
  `plan_review`).
- Delete `src/audit/migrations/0002_plan_addendum.sql`.
- Delete `src/audit/migrations/0003_plan_abort.sql`.
- Pin a schema-migration unit test: fresh-init runs all current
  migrations and `SELECT name FROM sqlite_master WHERE
  type='table' AND name LIKE 'plan%'` returns the empty set.

Sanctioned by the bailiff-split design's "pre-v1, we just bulk-
drop the audit DB" sentence: any dev environment that already
ran the old 0001 either re-inits the DB or hand-drops the
plan tables. No prod consumers.

PR body should explicitly say "**docs are intentionally stale
through slice G — flagging out-of-date references to deleted
plan types is not actionable feedback for this slice**" so
Codex doesn't churn on it.

~-200 LoC (migration files only). Single PR.

## Estimated total

~-11k LoC across five PRs (G1–G5) plus the standalone migration
squash. Each is independently revertible: G1 removes a self-
contained RPC path, G2 removes a self-contained HTTP path, G3 is
the only sub-slice with a non-trivial move (separators and
compose into the bailiff workflow modules), G4 is the surgical
visitor-field strip, G5 is the combined pure-deletion sweep, and
the migration PR touches only `src/audit/migrations/`.

## Risks and tradeoffs

- **Compile-graph ordering.** Six sub-slices in strict dependency
  order means an earlier merge gates the next PR. Mitigation:
  each PR can be opened back-to-back; reviewers don't need to
  wait for the entire epic to land before approving G1. The
  total wall-clock cost of strict ordering is one round-trip per
  sub-slice, which is fine for a half-day of work.
- **Lost diagnostic surface inside writ.** After G, an operator
  who wants to inspect plan state goes through `bailiff plan
  list / show` only — there's no longer a writ-side fallback if
  bailiff is wedged. This is the point: a single source of truth
  is the goal. The migration-completion principle from
  `gospel.md` (`# Example: migrations and deletion`) explicitly
  privileges this over keeping a half-finished migration around
  as insurance.
- **Audit-table loss.** Once 0007 lands, historic plan rows are
  gone. The bailiff repo (notes ref `refs/notes/bailiff/v1/plans/*`)
  is the new source of truth; pre-v1, we accept that the legacy
  audit history is unrecoverable. Documented in the
  `bailiff-split` design's "We explicitly defer" section.
- **`src/bailiff.rs`'s name collision with the bailiff binary.**
  Today the top-level `bailiff` module (composition helpers) and
  the `bailiff_plan_*` modules and the `bin/bailiff` binary all
  coexist. G3 deletes the top-level `bailiff` module, leaving
  the `bailiff_plan_*` namespace as the only library-side
  `bailiff*` prefix. The bin remains. No rename required.
- **Migration squash breaks already-initialised dev DBs.** Any
  dev environment that ran the historical `0001_initial.sql`
  will not have its plan tables removed by the rewritten 0001
  (migrations are append-only at runtime). Mitigation is
  documented in the design: bulk-drop the dev DB. Sanctioned
  pre-v1; would not be acceptable post-v1.

## Open questions

- **Should G3 absorb writ-vm's full legacy plan-dispatch
  removal or split it out as G3a/G3b?** The legacy VM-side
  dispatch (the call site for `fetch_effective_prompt`) is
  modest and tightly coupled to the deletion of `src/bailiff.rs`,
  so bundling makes sense. Flagging in case the diff turns out
  larger than expected during G3.
- **Slice H ordering.** Docs slice (H) is the natural follow-up.
  Should it ship per-G-PR (each PR carries a doc tweak) or as
  one consolidated rewrite of `broker.md` + new `bailiff.md`?
  Default is consolidated; keeps G's diff purely code.
