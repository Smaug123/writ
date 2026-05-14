# Bailiff split — design

Plan for separating the workflow-orchestration concerns currently embedded in
`writ` into a distinct component called **bailiff**, leaving `writ` as a pure
capability broker. Companion to [`docs/design/broker.md`](../design/broker.md)
and [`docs/plans/2026-05-11-agent-plans.md`](./2026-05-11-agent-plans.md).

## Goal

Today `writ` does two jobs at once. The audit + per-route gate is broker
territory (per `broker.md`). But the plan/review/execute workflow vocabulary
— prompt composition, the `plan decide` CLI verb, the very fact that the
broker knows the word "plan" — has leaked in alongside.

Lift the workflow-shaped pieces out, behind a clear interface, into a
component named **bailiff**. Keep the broker passive: rows, gates, reads.
The orchestrator (bailiff) owns the workflow — what stages mean, how
prompts are composed, when a decision is made, what the operator's CLI
surface looks like for those verbs.

This is an incremental separation, not a rewrite. The broker schema
mostly stays put for v1. We surface the boundary so future work — a
second workflow, an external orchestrator, a different agent runtime —
has somewhere to plug in.

## Why this shape

`broker.md` already states the broker's job: ephemeral credentials, a
policy chokepoint, an audit log complete by construction. None of those
require knowing what a "plan" is. The plan-vocabulary has accreted
inside the broker for ergonomic reasons (single binary, single SQLite
DB, single CLI). That's defensible at v1 scale and was the right call
when there was no second consumer, but the leakage is real:

- **Prompt composition is workflow knowledge.** `agent_plan.rs` hard-codes
  `PLAN_PROMPT_SEPARATOR = "\n\n---\n\n# Approved plan\n\n"` and the
  reviewer separator (`agent_plan.rs:55–67`), and `writ-vm` calls
  `compose_effective_prompt` to splice them (`writ-vm.rs:301–319`). A
  pure broker would expose body and originating prompt as data and let
  the orchestrator decide how to splice.

- **`writ plan decide` is an orchestrator verb on the broker binary.**
  The handler (`writ.rs:108–122` → `server.rs:582–639`) is a passive
  row-write, but the CLI surface is workflow vocabulary bolted onto
  the broker.

- **The stage enum encodes workflow.** `agent_run.stage IN ('plan',
  'review', 'execute')` is a closed workflow vocabulary. A maximally
  orthogonal broker would express generic capability bindings
  (can-submit-blob-of-kind-X, can-read-blob-Y) and let the orchestrator
  declare the plan/review/execute shape on top.

The cleanest factoring at the v1-vocabulary level: **writ exposes
generic typed-audit-blob + gate primitives; bailiff speaks
plan/review/decide on top.** We don't go all the way there in this
plan — full schema genericisation is deferred — but we move enough
that bailiff has a name, a code home, and clear ownership of the
opinionated pieces.

## Conceptual model

### What stays in `writ`

The three legitimate broker jobs the existing plan code already does:

1. **Append-only audit rows** for plan/review/decision/addendum/abort
   (`src/audit/plan.rs`, migrations 0001–0003). These remain the
   broker's persisted shape.
2. **Per-stage, per-route gating** on the VM HTTP plan endpoints
   (`src/vm_http/plan.rs`). The gate is exactly what a capability
   broker is for.
3. **The decision gate** — refusing to serve plan body to an
   execute-stage run without `outcome = accepted`
   (`agent_plan::route_permitted_by_stage_and_decision`,
   `agent_plan.rs:846`).

These keep writing rows to the broker DB. The row shapes are
broker-internal and don't have to be generic on day one.

### What moves out to `bailiff`

Three things, in increasing order of disruption:

1. **Prompt composition.** `PLAN_PROMPT_SEPARATOR`,
   `REVIEWER_PROMPT_SEPARATOR`, `compose_implementer_prompt`,
   `compose_reviewer_prompt`, `compose_effective_prompt`,
   `stage_consumes_plan_body` (`agent_plan.rs:55–67, 687–760`) plus
   the caller `fetch_and_compose_effective_prompt`
   (`writ-vm.rs:301–319`).
2. **The `writ plan decide` CLI verb** (`writ.rs:108–122` and the
   handler in `server.rs:582–639`).
3. **(Deferred.)** The `Stage::Plan|Review|Execute` enum and the
   per-stage authorisation matrix. These are workflow vocabulary, but
   they're load-bearing for the gate, and replacing them with generic
   capability bindings is a much bigger change. Leave for v2.

### Process / crate shape

For v1, **bailiff is a crate, not a separate process.** The
orchestration code moves into a new module (call it `bailiff` —
sibling to `audit`, `policy`, `agent_plan`) and is linked into both
`writ-vm` and the CLI binary. This is the same compromise the broker
already makes for `audit` and `policy`: factor as a unit of code, not
a unit of deployment, until a second deployment-shape demands it.

When an external orchestrator process actually exists, this crate
becomes the in-process half of a wire protocol, and the v2 schema
generalisation can happen behind it. v1 declines to predict that
protocol.

## Phased plan

### Phase 1 — Move prompt composition into bailiff

Cleanest first cut. Today `writ-vm` composes
`feature_prompt + "# Approved plan" + body` itself; that's pure
workflow knowledge baked into the broker's VM-side daemon.

- Pull `PLAN_PROMPT_SEPARATOR`, `REVIEWER_PROMPT_SEPARATOR`,
  `compose_*` functions, `stage_consumes_plan_body`,
  `MAX_PLAN_BODY_BYTES`, and the stage *interpretation* helpers out
  of `src/agent_plan.rs` into the new `bailiff` crate.
- The pure types (`PlanBody`, `Stage`, `Verdict`, `DecisionOutcome`,
  `PlanId`, etc.) stay in `agent_plan.rs` because the broker schema
  persists them — but the *composition logic* leaves.
- `GET /v1/plans/<id>` grows: today `fetch_plan(...)` returns body
  only. Add a sibling field for `originating_prompt` (the planner
  run's prompt, joined from `agent_run` via `plan.agent_run_id`) so
  a client can compose without per-route plumbing. The broker
  exposes the two values; the orchestrator splices them.
- `fetch_and_compose_effective_prompt` (`writ-vm.rs:301–319`)
  becomes `fetch_effective_prompt`: the VM-side runner calls into
  bailiff to do the splice. Initially this is a function call into
  the new crate; when bailiff is a separate process it becomes a
  local-socket call.
- Tests: composition tests in `agent_plan.rs` and the property test
  `compose_implementer_prompt_three_segments`
  (`tests/properties.rs:610`) move with the code. They're already
  well-shaped property tests.

**Why first:** small blast radius, no schema change, no CLI change.
Proves the broker can serve "body + originating prompt" as raw data
without baking the splice in.

### Phase 2 — Move the `decide` verb out of writ

Today `writ plan decide` is a CLI subcommand on the broker binary.
The handler (`server.rs:582–639`) is itself a passive audit append.

- Add an HTTP endpoint `POST /v1/plans/<id>/decisions` (or the
  Unix-socket equivalent, whichever fits the existing transport
  story). It does exactly what `server.rs:582–639` does today: take
  `outcome` + `decider`, append to `plan_decision`, surface
  `PlanAlreadyDecided` on PK collision.
- Bailiff becomes the only client of that endpoint. The new CLI
  verb is `bailiff plan decide`. Remove `PlanCmd::Decide` from
  `writ.rs` and the dispatch in `server.rs`.
- Keep `writ plan list` and `writ plan show` for now — they're
  read-only audit queries, exactly what a broker should expose.
  Long-term these may also migrate; no rush.

Note: this trades one API-surface owner for another. The decide
gate is *already* enforced inside the broker DB
(`plan_decision.plan_id` is PK); both today's CLI handler and
tomorrow's HTTP handler are passive writers. The move is about
API-surface ownership, not enforcement.

### Phase 3 — Docs and naming

- Move `docs/plans/2026-05-11-agent-plans.md` to be a bailiff design
  doc (rename and update front matter), leaving a short pointer in
  `docs/design/broker.md` that the plan/review/execute *workflow*
  lives elsewhere now. Keep the broker doc's mention of plan tables
  under "audit log shape, used by orchestrators."
- Split `docs/user_facing/cli-reference.md` into `writ` (sessions,
  grants, audit queries) and `bailiff` (plan/review/decide).
- Add a top-level `bailiff` doc that's the orchestrator counterpart
  to `broker.md`.

## What we explicitly defer

- **Genericising the audit schema** ("typed audit blob + capability
  binding + gate"). The `plan`, `plan_decision`, `plan_review`,
  `plan_addendum`, `plan_abort` tables and the `agent_run.stage`
  CHECK constraint stay. Renaming them to opaque `agent_artifact`
  rows keyed by `kind` is a much bigger migration with no second
  consumer to justify it. v1 already decided "free-form markdown for
  v1; structured later" — same principle applies to the table names.

- **Replacing the `Stage` enum with capability bindings.** The
  current `Stage::Plan|Review|Execute` is workflow knowledge in
  writ. Replacing it with `can-submit-blob-of-kind-X /
  can-read-blob-Y` is the right destination but needs bailiff to
  actually exist as an independent process and a second workflow to
  demand it. Until then, having the broker know the words is
  acceptable leakage and dramatically simpler.

- **Bailiff as a separate process.** v1 is a crate. An external
  orchestrator process is a v2 concern that wants a wire protocol
  this plan doesn't try to predict.

- **`writ plan list / show` migration.** These are read-only audit
  views and don't carry workflow logic. They can move when
  convenient.

## Risks and tradeoffs

- **The new `GET /v1/plans/<id>` shape needs the originating prompt.**
  Phase 1 requires the broker to expose this, which means a
  schema-level join from `plan.agent_run_id` →
  `agent_run.prompt_*`. That data is already there; it's a query,
  not a migration.

- **The split is partial by design.** The broker will still know
  the words "plan", "review", "execute" in its schema after this
  refactor. That's the deliberate v1-scale call. The goal is to
  remove the *opinionated* parts (prompt format, decision verb)
  without paying the cost of a generic-artifact rewrite that
  doesn't yet have a second client to justify it.

- **Bailiff-as-crate masks the real boundary.** Linking bailiff
  into `writ-vm` lets it call audit DAOs directly, which would
  smear the boundary again. Mitigation: bailiff sees the broker
  only through the wire protocol it would speak from a separate
  process — HTTP for VM-side, Unix socket for host-side. The crate
  may not reach into `audit::` directly. The compiler can enforce
  this with module visibility.

## Order of operations

1. Create `bailiff` as a crate (sibling to existing modules; not
   yet a binary).
2. Move composition logic + separators + `compose_effective_prompt`
   into it. Update `writ-vm.rs:301–319` to call into it. Keep all
   tests passing.
3. Add `originating_prompt` to `PlanView` returned by `GET
   /v1/plans/<id>`, fed by an audit-side join. Property-test the
   join.
4. Add `POST /v1/plans/<id>/decisions` to the VM HTTP layer (or
   Unix-socket equivalent). Make `writ plan decide` call that
   endpoint instead of writing the row directly via the local
   socket. Small CLI change but proves the API works end-to-end.
5. Add a `bailiff` binary that owns the `plan decide` verb. Delete
   the verb from `writ`.
6. Update docs.

Each step is independently revertable, and each ships a working
system.

## Open questions

1. **Where does the bailiff↔broker boundary actually run on host
   side?** The decide handler currently dispatches over the
   Unix-socket `ClientMessage::DecidePlan`. If bailiff is in-process
   we could keep that and just rename the caller; if we want the
   boundary visible we add an HTTP/local-socket route. The plan
   above assumes a route; revisit if that turns out to be
   ceremony-for-ceremony's-sake.

2. **Reviewer separator vs implementer separator.** Both move with
   composition. No question, just noting they're a pair and must
   move together.

3. **Naming.** "bailiff" is the working name. If something better
   surfaces during phase 1 — when we actually look at the crate
   boundary in code — rename then; renames are cheap before any
   external surface exists.
