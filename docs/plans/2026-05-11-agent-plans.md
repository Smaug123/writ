# Agent plans — design

> **Historical / point-in-time.** This doc captures the design as
> originally landed. Subsequent work in
> [`2026-05-14-bailiff-split.md`](./2026-05-14-bailiff-split.md) splits
> the workflow-orchestration parts described here (prompt composition,
> the `plan decide` verb) out of `writ` into a separate `bailiff`
> component. The schema and gate described below remain in `writ`; the
> opinionated workflow vocabulary moves. Read this doc for the
> motivating shape, then the bailiff-split doc for where the boundary
> now runs.

Plan for adding "the agent proposes a plan" as a first-class concept in writ,
covering plan submission, plan review by other agents, a decision gate, and
execution against an accepted plan. Companion to
[`docs/design/broker.md`](../design/broker.md) and
[`docs/design/apple-container-agent-vm.md`](../design/apple-container-agent-vm.md).

## Goal

Today writ records what an agent was asked (`agent_run.prompt_*` summary) and
what it did (`agent_run_outcome`, plus the audit chain of capability grants /
pushes / proxied API calls). Add the middle layer: what the agent *planned*
in response, what other agents thought of that plan, and the final
go/no-go decision — all as durable, queryable rows in the broker DB, with
strong links from plans through to the runs that proposed, reviewed, and
executed them.

The primary consumer is the next agent. The secondary consumer is a human or
future orchestrator drilling down "this feature request produced these PRs;
these were the agent runs and their transcripts; these were the rounds of
plan iteration with these other agents."

## Why this shape

The broker invariant (`broker.md`): if the only authoritative record of agent
activity lives on the broker, no parallel channel can drift. Plans, reviewer
verdicts, and decisions are exactly the kind of state that must not be
forgeable from inside the VM. They live in the broker DB. Repo-side
materialisation is a deferred derived rendering, not the source of truth.

writ targets an autonomous-agent "dark factory" mode: agents proposing,
agents reviewing, agents executing, with humans as occasional observers.
That pushes us toward machine-consumable structured surfaces (typed rows,
stable keys, deterministic query paths) rather than human-discoverability
shortcuts. The first iteration accepts free-form markdown plan bodies for
ergonomic reasons, but every plan/review/decision is its own row, joinable
through the audit chain.

The broker stays passive: it records, gates per stage, and serves data
back. It does not spawn reviewer VMs, choose reviewers, apply edits to
plans, or decide accept/reject. Those are operator (today: human; later: a
separate orchestrator agent) responsibilities. This keeps writ a capability
broker rather than a workflow engine, and defers the orchestration design
until we have real usage data.

## Conceptual model

### Stages

Each agent run carries a stage:

```text
'plan'    — produces a plan, terminates
'review'  — reads a plan, produces a verdict + optional feedback, terminates
'execute' — reads an accepted plan, performs the work, may submit addenda,
            terminates
```

Stages drive per-stage VM HTTP authorisation (only a `plan`-stage run can
`POST /v1/plans`, only a `review`-stage run can post a review, and so on).
The enum is closed today but easy to extend.

### Correlation ID

An opaque caller-supplied identifier (validated only as a safe id —
character class plus length bound — never interpreted) on `agent_run` and
`git_push_request`. The broker stores it and serves it back unmodified.
This is the join key for "all runs that belong together," and the bridge
for any future orchestrator that wants to group runs without writ knowing
what a "feature" is. The broker does not enforce uniqueness, does not
mint these itself in v1, and does not require them to be present (an
ad-hoc one-off run with no correlation is still legal).

### Plan lifecycle

For a given plan, the durable event stream is:

```text
plan_submitted     — planner run posts a body. There is exactly one
                     plan row per submission; a planner that wants to
                     revise must submit a new plan.

plan_review        — zero or more reviewer runs each post a verdict
                     in { approve, request_changes, reject } plus
                     optional feedback. Reviewers cannot edit the plan
                     body; they only attach verdicts.

plan_decision      — exactly one terminal row, written by an operator
                     (host CLI today). Outcome is { accepted,
                     rejected_restart }. accepted unlocks the
                     implementer; rejected_restart closes this plan
                     and signals "if you want this work done, start a
                     new task" — the broker does nothing automatic.

plan_addendum      — append-only stream from a subsequent execute-stage
                     run when it discovers the plan is incomplete.
                     Addenda are notes, not amendments: the plan body
                     itself remains immutable after submission.
```

The hard-abort case (the implementer finds the plan unworkable mid-execution)
is a distinct protocol message, not just a non-zero exit. It records a
durable signal that the operator can act on without re-reading the
implementer's transcript.

### Decision is the gate

The broker enforces that an `execute`-stage run cannot start (or, if
started, cannot read its target plan) unless the plan has a
`plan_decision` row with `outcome = accepted`. This is the one place the
broker is more than a passive recorder: it refuses to serve plan data to
an executor that the operator hasn't approved. The orchestration above
that — spawning reviewers, collating verdicts, calling `writ plan
decide` — stays external.

## Audit-log additions

Schema sketch; final column details (constraints, indexes, triggers) settle
at implementation time. Existing audit-log conventions (typed UUID strings,
unix millisecond timestamps, JSON columns for round-trippable bodies,
session-open trigger gating, append-only) apply.

```text
-- New on existing tables
agent_run.correlation_id    TEXT NULL
agent_run.stage             TEXT NOT NULL CHECK (stage IN ('plan','review','execute'))
agent_run.read_plan_id      TEXT NULL REFERENCES plan(plan_id)
git_push_request.correlation_id  TEXT NULL

-- New tables
plan
  plan_id            TEXT PRIMARY KEY
  agent_run_id       TEXT NOT NULL REFERENCES agent_run(run_id)
  submitted_at       INTEGER NOT NULL
  body               TEXT NOT NULL CHECK (body != '')
  body_sha256        TEXT NOT NULL CHECK (length(body_sha256) = 64)
  -- one plan submission per planner run; enforce UNIQUE(agent_run_id).

plan_review
  review_id          TEXT PRIMARY KEY
  plan_id            TEXT NOT NULL REFERENCES plan(plan_id)
  agent_run_id       TEXT NOT NULL REFERENCES agent_run(run_id)
  submitted_at       INTEGER NOT NULL
  verdict            TEXT NOT NULL CHECK (
                       verdict IN ('approve','request_changes','reject'))
  feedback           TEXT NULL
  feedback_sha256    TEXT NULL
  -- a reviewer run submits at most one review; enforce UNIQUE(agent_run_id).

plan_decision
  plan_id            TEXT PRIMARY KEY REFERENCES plan(plan_id)
  decided_at         INTEGER NOT NULL
  outcome            TEXT NOT NULL CHECK (
                       outcome IN ('accepted','rejected_restart'))
  decider            TEXT NOT NULL  -- free-form attribution; e.g.
                                    -- 'cli:<hostname>' or, later,
                                    -- 'agent:<run_id>'.

plan_addendum
  addendum_id        TEXT PRIMARY KEY
  plan_id            TEXT NOT NULL REFERENCES plan(plan_id)
  agent_run_id       TEXT NOT NULL REFERENCES agent_run(run_id)
  submitted_at       INTEGER NOT NULL
  body               TEXT NOT NULL CHECK (body != '')
  body_sha256        TEXT NOT NULL CHECK (length(body_sha256) = 64)
  -- addendum-producing runs must have stage='execute'; enforce by trigger.

plan_abort
  plan_id            TEXT PRIMARY KEY REFERENCES plan(plan_id)
  agent_run_id       TEXT NOT NULL REFERENCES agent_run(run_id)
  aborted_at         INTEGER NOT NULL
  reason             TEXT NOT NULL CHECK (reason != '')
  -- written by an execute-stage run that gives up on the plan. Does not
  -- by itself change plan_decision; the operator decides whether to
  -- start a fresh planning task.
```

Triggers enforce stage→action consistency (only `plan`-stage runs can
appear in `plan.agent_run_id`; only `review`-stage runs in
`plan_review.agent_run_id`; only `execute`-stage runs in `plan_addendum`
and `plan_abort`). `agent_run_requires_open_session` and the rest of the
session-gating regime carry over.

## Protocol additions

### VM HTTP (bearer + source-subnet gated as today)

```text
POST /v1/plans
  body:   { body: string }
  auth:   run.stage = 'plan' and run has not yet submitted a plan
  return: { plan_id }

GET  /v1/plans/<plan_id>
  auth:   run.read_plan_id = <plan_id>, and either
          run.stage = 'review'                                    OR
          run.stage = 'execute' AND plan_decision.outcome = 'accepted'
  return: { plan_id, body, originating_prompt, originating_run_id,
            decision: { outcome, decided_at } | null }

POST /v1/plans/<plan_id>/reviews
  body:   { verdict, feedback?: string }
  auth:   run.stage = 'review' and run.read_plan_id = <plan_id>
  return: { review_id }

POST /v1/plans/<plan_id>/addenda
  body:   { body: string }
  auth:   run.stage = 'execute' and run.read_plan_id = <plan_id>
          and plan_decision.outcome = 'accepted'
  return: { addendum_id }

POST /v1/plans/<plan_id>/abort
  body:   { reason: string }
  auth:   run.stage = 'execute' and run.read_plan_id = <plan_id>
  return: { aborted_at }
```

Body size limits, content-type discipline, and audit-row pre-write on each
side mirror the existing Git/Nix routes. Bodies are bounded markdown text;
specific limits set at implementation time.

### Host Unix socket / CLI

```text
writ agent run --correlation-id <X> --stage plan
               --agent <kind> --prompt <text> [--repo ...]

writ agent run --correlation-id <X> --stage review
               --read-plan <plan_id>
               --agent <kind> --prompt <text>

writ agent run --correlation-id <X> --stage execute
               --read-plan <plan_id>
               --agent <kind> [--repo ...]
               -- (broker constructs the prompt; see below)

writ plan list [--correlation-id <X>]
writ plan show <plan_id>            # plan body, reviews, addenda, decision
writ plan decide <plan_id> --accept | --reject-restart [--decider <s>]
```

`writ plan decide` is a daemon RPC that writes the `plan_decision` row. The
broker does not spawn anything in response. If `--reject-restart` is chosen,
the operator (or, eventually, an orchestrator agent) is responsible for
starting a fresh `--stage plan` run with an updated prompt.

### Implementer prompt construction

When an `execute`-stage run starts with `--read-plan <id>`, the broker
constructs its effective prompt from:

```text
<original feature-request prompt that produced plan_id>
+ <plan_id body>
```

These are concatenated by the broker (or by `writ-vm agent run` on the
guest side, fetching both from the VM HTTP plan route) before being fed
to the agent runtime. The implementer does *not* receive reviewer feedback
by default; reviewer feedback is for the decision, not for execution. If
operators want a specific concern surfaced to the implementer, it should
either be folded into a revised plan (a new `plan` row under the same
correlation_id) or appended to the implementer's `--prompt` explicitly.

## Decisions taken (with reasons)

1. **Broker-canonical store, not repo-canonical.** A VM-writeable plan
   file is forgeable; the audit invariant requires a non-VM source of
   truth. Repo materialisation, if added later, is a host-side push of
   a derived artifact (see "deferred" below).

2. **Broker is passive, not orchestrator.** writ records and gates;
   spawning reviewers, choosing them, and pressing accept/reject stays
   external. Until we have real usage of the plan/review cycle, we don't
   know what an orchestrator should look like, and we'd be guessing.

3. **Opaque external correlation_id, no internal feature entity.** The
   broker doesn't know what a "feature" is. The orchestrator (or the
   human) maintains that abstraction outside writ and passes an id in.
   If writ later grows orchestration features it can mint its own ids;
   it doesn't have to today.

4. **Ephemeral agents at every stage, no paused VMs.** The planner
   submits and dies; reviewers each spin up and die; the implementer
   spins up after decision and dies. This matches the user's stated
   preference for ephemeral agents and avoids holding VM resources
   across an unbounded human-decision wait. A future Nix-prepopulated
   image will reduce spin-up cost without changing this model.

5. **Stages are an `agent_run` enum, not separate run types.** Stage
   drives authorisation but agent runs otherwise share the existing
   schema (prompt summary, stream capture, outcome). Smaller change,
   reuses existing audit shape.

6. **Plan bodies are free-form markdown for v1.** Structured plans are
   strictly better long-term (mechanical reconciliation against
   actual work), but free-form is dramatically easier to bootstrap and
   reviewable today. The schema treats the body as opaque text; future
   structured-plan migration can add a parallel structured column or a
   new table without disturbing existing rows.

7. **Plans are immutable; revision = new plan, not edit.** Addenda are
   notes attached after acceptance; they do not modify the body. If a
   reviewer says "request_changes" and the operator wants a revised
   plan, that's a new `plan` row, not a mutation. This keeps the
   history honest and avoids the "what did the reviewer actually
   approve?" problem.

8. **Implementer prompt = feature-request prompt + plan body.** Plan
   body alone is too thin (the agent doesn't see the surrounding intent
   or constraints); original-prompt alone defeats the point of planning.
   Reviewer feedback stays out of the implementer's input by default,
   for the reason in "Implementer prompt construction" above.

9. **Hard-abort is a distinct protocol message, not a non-zero exit.**
   The operator/orchestrator can distinguish "implementer crashed" from
   "implementer believes the plan is fundamentally wrong" without
   reading transcripts. The cost is one extra route and one extra
   table; the value is queryable, durable signal.

10. **Repo materialisation deferred.** With broker-canonical, the next
    agent reads via VM HTTP; humans drill down via `writ plan show` or
    SQLite. Repo-side discoverability has real long-term value (see
    "deferred"), but is not on the critical path for the dark-factory
    flow.

## Implementation slices

In order. Each slice is independently testable and lands real value.

1. **Correlation ID plumbing.** Migration adds `correlation_id` to
   `agent_run` and `git_push_request`. CLI accepts `--correlation-id`
   and stores it. No behavioural change yet; just metadata. Smallest
   possible step; unlocks future stitching.

2. **Plan table + `POST /v1/plans` + `writ plan list/show`.** Planner
   stage runs can submit a plan; the operator can read it back. Does
   not yet require stage enforcement at the route level (defer to
   slice 3); for now the plan submission accepts any authenticated
   run for the planner's session.

3. **`agent_run.stage` + per-stage VM HTTP authorisation.** Adds the
   stage enum, threads it through `StartAgentRun`/the CLI, and
   enforces stage→action consistency on every plan-related route.
   The gate that makes the rest coherent.

4. **`--read-plan` + `GET /v1/plans/<id>` + implementer prompt
   composition.** Implementer can fetch and execute against an
   accepted plan. The `plan_decision.outcome = 'accepted'` check
   short-circuits this in v1 by treating any plan as implicitly
   accepted (until slice 6 lands). Slice 4 makes plan→execute
   end-to-end usable for one-off testing without yet requiring the
   review cycle.

5. **VM-side implementer prompt composition.** Decided: the host CLI
   re-supplies the originating feature-request prompt at implementer
   launch (no new SQLite column on `plan`), and the in-VM wrapper
   composes it with the plan body before invoking the LLM. The broker
   threads `stage` and `read_plan_id` into `VmAgentRunConfigResponse`
   so the wrapper knows when to fetch `GET /v1/plans/<id>` and call
   [`compose_effective_prompt`]. Open question 1 is closed by this
   slice. Reviewer composition follows the same shape in slice 6 with
   a distinct `# Proposed plan` separator so an LLM cannot mistake an
   under-review plan for an approved one.

6. **Reviews + decision (`plan_review`, `plan_decision`, `writ plan
   decide`, route enforcement, reviewer prompt composition).** Adds
   the gate and extends [`compose_effective_prompt`] to compose the
   reviewer's operator-supplied prompt with the plan body via
   [`REVIEWER_PROMPT_SEPARATOR`]. After this slice the full plan →
   review → decide → execute cycle works.

7. **Addenda.** `plan_addendum`, `POST /v1/plans/<id>/addenda`,
   surfaced in `writ plan show`.

8. **Hard-abort.** `plan_abort`, `POST /v1/plans/<id>/abort`, surfaced
   in `writ plan show`.

(1)–(4) is the MVP that proves the data model. (5)–(8) round out the
cycle.

## Out of scope / deferred

- **Structured plans.** Plan bodies stay free-form markdown for v1; a
  future migration adds a structured representation alongside or in
  place of the body.

- **Repo materialisation.** Optional future feature: when an
  implementer's PR lands, the broker pushes a parallel notes ref
  (`refs/notes/writ/plans/<id>`) carrying the accepted plan body and
  decision attribution. Git's content-addressed model and the notes
  mechanism support this without polluting the working tree; GitHub
  persists pushed notes refs and serves them via the Data API.
  Arbitrary `refs/*` namespaces outside `refs/{heads,tags,pull,notes}`
  may or may not survive GitHub's ruleset config — verify before
  betting a design on them. Cleanly host-side because canonical is
  in the broker; can be added later without touching the existing
  schema.

- **Orchestration inside writ.** Spawning reviewer VMs automatically
  on plan submission, collating verdicts, auto-deciding on threshold
  rules, retry-on-rejection — all explicitly deferred until we have
  real usage to design against.

- **Prepopulated Nix-store guest image.** Mentioned by the user as a
  follow-on optimisation to reduce many-VMs spin-up cost. Self-
  contained; lands after the plan/review cycle is wired.

- **Reviewer arbitration policy.** "What if reviewers disagree?" is an
  orchestrator-level decision. In v1 the operator reads `writ plan
  show` and decides. A future orchestrator may encode quorum or
  hierarchy rules.

- **Plan visibility to non-implementer execute runs.** If a future
  workflow needs an execute-stage run that reads a plan but does not
  own it (e.g. a sibling executor reviewing parallel work), it gets
  its own slice with its own authorisation rules.

## Open implementation questions

1. **Originating-prompt persistence.** *Resolved in slice 5:* the
   host CLI re-supplies the originating feature-request prompt at
   implementer launch — no new SQLite column on `plan`. The in-VM
   wrapper fetches the plan body separately and composes the two
   before invoking the LLM. The "prompts not in SQLite" convention
   from `apple-container-agent-vm.md` is therefore preserved. The
   wrapper-state-vs-LLM-state distinction is intentional: the LLM
   already has the feature-request prompt as its input and could
   already hit `GET /v1/plans/<id>` from inside the VM with the same
   bearer, so the wrapper concatenating before invocation does not
   expand the attack surface.

2. **Reviewer feedback to the implementer.** Default is "no, feedback
   is for the decision, not for execution." If we discover that
   reviewers commonly produce execution-relevant guidance that the
   re-planning loop can't absorb, this becomes a configurable flag
   on `--stage execute` or a join in the VM HTTP plan-fetch route.

3. **Cross-correlation analytics.** `writ plan list --correlation-id`
   gives one-task drill-down. Higher-level queries ("which agents
   most often have plans rejected?", "average rounds to acceptance")
   are not part of v1 but should be cheap given the row shape. Worth
   sanity-checking the schema choices against a few such queries
   before slice 1 lands.

4. **Migration of `agent_run` rows that predate `stage`.** Existing
   rows have no stage. The migration can either (a) leave them
   NULL and require new rows to set it, or (b) backfill all
   existing rows as `execute` (since today's runs are one-shot
   execution). (b) makes the column NOT NULL from the start, which
   is preferable; the cost is one historical-rewrite migration step.
