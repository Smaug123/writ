# Promote bailiff's plan workflow from hardcoded dispatch to data

Drafted 2026-07-26. Companion to `../design/architecture.md` §5.11 (the
subsystem this rewrites) and `2026-05-14-bailiff-split.md` (the
orchestrator-daemon model the current locking cites but does not deliver).
Sibling of `2026-07-25-approve-state-machine-as-a-type.md`, which asked the same
question — *where does a state machine's truth live?* — of the approve path.
That plan found the states already typed and the relation *around* them
scattered. This one finds the same shape one layer up.

Implement this plan with each stage on its own branch, stacked as necessary on
previous branches, so that a reviewer can review each branch in isolation.

## The objection

A reviewer's critique, quoted in full:

> **Orchestration is hardcoded exactly where it most needs to be data.**
>
> bailiff's plan→decide→review→implement sequence is baked into CLI dispatch and
> per-verb functions (`bin/bailiff.rs:477-596`); workflow state is derived in each
> verb by checking which notes happen to exist (`submit_implement` does its own
> 25-line "is there a submission? a decision? is it Accepted? no implement note
> yet?" gate; `bailiff_plan_view.rs:85-101` re-derives state separately for
> display). The repo guard locks the whole repo, not per-plan, and the
> cross-process flock lives in the binary rather than the library.
>
> Against your end goal — "spin up several variants, actually build them,
> autonomously explore whether queued work got easier, compose a dossier" — this
> structure can't be extended; it can only be copy-pasted. To add variant-compare
> today you'd duplicate `submit_implement` three times and hand-thread the
> comparison.
>
> This is where the small-orthogonal-core principle should bite hardest. The
> orchestration engine wants to be: a workflow described as data (a DU of steps:
> run-agent, gate-on-decision, fan-out-N-variants, collect-evidence, ask-human),
> an explicit `PlanState` machine validating transitions in one place, and an
> interpreter that executes steps via writ and persists state in the notes/db.
> Everything you described — review-required-before-merge, variant exploration,
> dossier assembly, even preference-policy learning — then becomes new step
> variants and new interpreters over the same workflow data, and the workflow log
> doubles as part of the audit record. Design this before extending bailiff
> further; the current three-stage pipeline is small enough to migrate now and
> won't be in six months.

## Verdict: valid, and the evidence is stronger than the objection states

### There are four encodings of the transition relation, and they disagree

The objection names two (`submit_implement`'s gate and `view.rs`'s display
derivation). There are four, and no two agree:

| # | Site | What it treats as legal |
|---|------|-------------------------|
| 1 | `plan_decide` (`bin/bailiff.rs:1013`) | *Everything.* No precondition is read. The only check is `WriteDecisionNoteError::DecisionAlreadyRecorded`, which is a write-time idempotency test, not a gate. |
| 2 | `submit_review` (`bailiff_plan_review.rs:160-178`) | Submission exists. The decision is never read, so a `Rejected` plan reviews happily. |
| 3 | `submit_implement` (`bailiff_plan_implement.rs:204-234`) | Submission + decision + `Accepted` + no prior implement. Review is never read, so implement runs on an unreviewed plan. |
| 4 | `BailiffPlanSummary::state` (`bailiff_plan_view.rs:129-146`) | A fourth relation, for display, documented as preferring "the latest stage present in the underlying data" — so `Reviewed` overrides `Rejected`. |

Site 1 is not merely lax; it is actively productive of the anomaly site 4 exists
to report. `write_decision_note` creates the per-plan ref, and `list_plan_ids`
enumerates plans *by ref existence* (`bailiff_plan_read.rs:373-376`), so
`bailiff plan decide --accept --plan-id <fresh uuid>` yields a plan row in state
`Corrupt`. The `WorkflowState::Corrupt` docstring
(`bailiff_plan_view.rs:29-35`) says that state is reachable "only when a
non-submission note was attached first ... or when a submission note was
manually deleted after the fact" — i.e. the display layer believes the supported
CLI cannot produce it, and a sibling verb produces it in one command.

`architecture.md` §5.11 records the gap as intentional — "decide and review
deliberately do not gate on submission presence" — which is exactly the
condition this plan reverses, and the reason to reverse it is the paragraph
above: two subsystems disagree about whether the same state is legal, and the
disagreement is not written down anywhere as a disagreement.

### The locking criticism is a correctness defect today, not only a fan-out blocker

Three separate problems, in ascending order of severity:

- **The flock is per-verb, not per-repo-mutation.** It lives at
  `<bailiff_repo>/bailiff-implement.lock` (`bin/bailiff.rs:811-832`) and is
  taken by `plan_implement` alone (`bin/bailiff.rs:918`). Cross-process
  `submit`/`review` hold only the in-process mutex.
- **`plan_decide` holds no lock at all.** It opens its own `NotesRepo` inside
  `spawn_blocking` (`bin/bailiff.rs:1035-1038`) and never touches
  `BailiffRepoGuard`. One of the four mutators is outside the single-writer
  invariant that `bailiff_repo_guard.rs` advertises.
- **The library cannot be used safely without the binary.** `bailiff_repo_guard.rs:39-43`
  states the cross-process lock "is a CLI-layer concern, not a property of this
  primitive", while `bailiff_repo_guard.rs:6-7` justifies the guard's existence
  by the long-running orchestrator-daemon model. That daemon, when written, gets
  the in-process half and silently loses the half that is load-bearing for
  `WorkspaceWrite`.

On granularity: `bailiff_repo_guard.rs:23-28` justifies whole-repo locking by
"humans driving the CLI one command at a time and ... the rarity of overlapping
bailiff operations". The end goal invalidates the premise by construction — N
variant runs are simultaneous, each holding the lock for an LLM run's duration.
The rationale was sound when written; the feature that breaks it is the next one.

### Where the objection over-reaches

**The five-variant step DU is partly speculative.** Of `run-agent`,
`gate-on-decision`, `fan-out-N-variants`, `collect-evidence`, and `ask-human`,
only `run-agent` has three existing implementations. `gospel.md` is explicit:
abstractions "must earn their place by simplifying the composition story. If you
can't explain how a feature composes with every other feature, the design is
wrong." Building `ask-human` and preference-policy learning now means inventing
their composition rules with no consumer to check them against.

**`gate-on-decision` should not be a step at all.** A gate sequenced as a step is
a gate a workflow author can omit — the illegal state stays representable. The
precondition belongs *on* a stage, answered by the state machine, so that
constructing a stage without its gate is not expressible. This is the difference
between the objection's design and the one below, and it is the whole
make-illegal-states-unrepresentable point.

**The workflow log already exists.** "The workflow log doubles as part of the
audit record" describes what bailiff's notes already are: each stage attaches a
signed note, state is derived from the note set, and writ's audit DB holds the
grant side. A separate step log would be a second encoding of the same truth —
the defect this plan is fixing, reintroduced one level up. Declined; the state
machine reading the notes *is* the log.

So: **build the machine, fix the locks, extract the descriptor that three
implementations have already earned, and design fan-out without building it.**

## The remedy

- One module owns the vocabulary of plan states, the transition relation, and
  every predicate derived from a state. Four call sites become four calls.
- Locking becomes a library property, keyed per plan, taken by every mutator —
  so the orchestrator daemon inherits it and N variants do not serialise.
- The three agent-run workflows become three *values* of one stage descriptor
  executed by one interpreter. Each descriptor names its precondition as a state
  predicate, so a stage that could run out of order cannot be constructed.
- Fan-out and dossier assembly are written down as the next two descriptor
  values and deliberately not built. Slice 3's core is right iff they turn out to
  be one value plus one interpreter arm each.

## Behaviour change (decided, not incidental)

The four relations cannot be unified without choosing one. The choice is to
tighten to the intended workflow:

```
              before                          after
decide     :  (no precondition)            :  Submitted
review     :  Submitted                    :  Accepted
implement  :  Accepted && !Implemented     :  Reviewed && !Implemented
```

Three deltas. `bailiff` is a workspace member with no dependents
(only its own `bin/` consumes the library), so nothing in-tree needs migrating,
but **any operator flow that skips `review` stops working**, and
`architecture.md` §5.11's "decide and review deliberately do not gate" sentence
becomes false and must change in the same slice. Each delta gets a named test
asserting the *new* refusal, so the change is pinned rather than absorbed.

`Corrupt` stays representable after the tightening — a manually deleted
submission note still produces it — and denies every stage.

---

## Slice 1 — `PlanState`: one transition relation

**Dependencies**: none.

**Implements**: verdict §1; the behaviour-change table.

New `crates/bailiff/src/bailiff_plan_state.rs`:

- `NotePresence` — the parsed observation `{ submission, decision, review,
  implement }` that the four readers already produce. Built once by a reader,
  not re-derived per call site.
- `PlanState` — replaces `WorkflowState`, which moves here from
  `bailiff_plan_view.rs` (the display projection keeps re-exporting it so
  `output.rs` is untouched).
- `PlanStage` — the four events (`Submit`, `Decide`, `Review`, `Implement`).
- `fn derive(&NotePresence) -> PlanState` — total, the only definition.
- `fn allows(PlanState, PlanStage) -> Result<(), IllegalTransition>` — total, the
  only definition, carrying the state and stage in the error so each CLI verb
  can still render an operator-facing next step.

Following `2026-07-25-approve-state-machine-as-a-type.md`'s recorded lesson,
generate the enums, their `ALL` lists, and the wire strings from one
variant⇒literal table, so `ALL` cannot disagree with the variants.

Call sites rewired: `submit_implement`'s 25-line inline gate becomes one
`allows` call; `submit_review` and `plan_decide` gain theirs; `BailiffPlanSummary::state`
delegates to `derive`.

**Correctness oracle**:
- Property: `derive` is total over all 2⁴ presence combinations × both `Decision`
  values, and agrees with the pre-slice `WorkflowState::state` on every input
  *except* an explicitly enumerated delta table. The delta table is the behaviour
  change, written as data, in a test — not a diff a reviewer has to reconstruct.
- Property: `allows` is total over `PlanState::ALL × PlanStage::ALL`.
- Property (reachability): every `PlanState` except `Corrupt` is reachable from
  `Absent` by some legal `PlanStage` sequence. Catches states orphaned by the
  tightening.
- Property (monotonicity): applying a legal stage never decreases position in the
  progression order.
- Three named tests, one per behaviour delta, asserting the new refusal — the
  `decide`-on-unsubmitted one specifically asserting no ref is created, since ref
  creation is what manufactures `Corrupt`.
- Existing `tests/properties.rs` passes with the delta table's cases updated and
  nothing else touched.

---

## Slice 2 — locking: per plan, in the library, taken by every mutator

**Dependencies**: none (orthogonal to slice 1; may be built in parallel).

**Implements**: verdict §2.

`BailiffRepoGuard` becomes `PlanGuard::acquire(repo, plan_id)`, holding **two**
levels, because they solve different problems and neither subsumes the other:

- the in-process `Arc<AsyncMutex<_>>`, now keyed per plan id rather than
  per repo — still required because a single process can hold a given flock only
  once (as `bin/bailiff/tests.rs:1153` already documents);
- a per-plan flock at `<bailiff_repo>/locks/<plan-id>.lock`, moved out of the
  binary, so a library caller — the orchestrator daemon — is protected.

Per-plan granularity is sound *if* concurrent writes to distinct plans are
genuinely disjoint. They touch distinct refs (`refs/notes/bailiff/v1/plans/<id>`),
which is the argument, but `git notes` invocations share a repository and use a
temporary index, so **this must be proven, not assumed**. If the concurrency
test below fails, the fallback is a short repo-wide mutex held for the duration
of a single git invocation, with the per-plan lock still spanning the workflow —
and the slice says so in its docstring rather than silently widening the lock.

`plan_decide` joins the other three under the guard.

**Correctness oracle**:
- Property: two workflows on *distinct* plan ids both make progress while the
  other holds its guard — a test that deadlocks or serialises under the current
  whole-repo lock, which is what makes it evidence.
- Property: two workflows on the *same* plan id serialise, in-process and
  cross-process (the existing `bailiff_repo_guard.rs` tests generalised, plus the
  existing cross-process flock test retargeted at the per-plan path).
- Stress test: N concurrent real workflows on N distinct plan ids against one
  bare repo; assert all N notes land, no ref is clobbered, and no git invocation
  reports index contention. **This is the test that decides the fallback**; run
  it enough times to trust it, and record the result in the slice.
- Existing `submit_implement` duplicate-gate tests pass unchanged.

---

## Slice 3 — the stage descriptor and its interpreter

**Dependencies**: slices 1 and 2.

**Implements**: verdict §1 and §3; the objection's core remedy.

The three workflows share a skeleton — read inputs, take the guard, gate, read
and verify the prior envelope, compose a prompt, run the agent, write a signed
note — implemented three times with three near-identical `Inputs`/`Outcome`/`Error`
triples and three CLI functions taking 10–12 hand-threaded arguments. Rule of
three is met; the descriptor is earned.

`StageSpec` (inert data) names the axes that actually vary. They were surveyed
rather than guessed, because one of them is not a boolean:

- **precondition**: a `PlanStage`, so slice 1 answers legality and a spec without
  a gate is not constructible;
- **capabilities**: `WorkspaceRead` for submit/review, `WorkspaceWrite` for
  implement;
- **prompt composition**: which prior note's verified body is spliced in
  (submit has none);
- **note writer**: which seed and note type the stage attaches;
- **session ownership**: a DU, not a flag. Submit and review open and close their
  own session; implement is VM-dispatched, so the broker mints and closes it and
  bailiff must not (`bailiff_plan_implement.rs:254-261`). A boolean here would
  make the illegal "bailiff closes a broker-owned session" state representable.

`fn run_stage(client, guard, spec, inputs) -> Result<StageOutcome, StageError>`
is the interpreter. The three verbs become three `StageSpec` values plus their
CLI argument parsing.

The error surface is the subtle part: each verb today maps its errors to
messages naming the operator's next step (`bin/bailiff.rs:949-1010`). Collapsing
must not flatten those into one generic string; the spec carries its own
renderer.

**Correctness oracle**:
- **Recorded-trace equivalence** (the reference-implementation trick): before
  refactoring, capture the exact sequence of writ RPCs each of the three
  workflows emits against a stub client, for both happy and each sad path. After
  refactoring, assert the interpreter emits byte-identical traces for the three
  spec values. This is what makes "no behaviour change" a checked claim rather
  than a hope, and it must be captured *first*, on the pre-refactor code.
- Every existing test in `bailiff_plan_{submit,review,implement}.rs` and
  `tests/properties.rs` passes untouched. Rewriting one is a signal the refactor
  changed behaviour; treat it as a finding, not a chore.
- Property: for every `StageSpec`, running it from a state its precondition
  forbids performs **zero** writ RPCs — the pre-RPC-gate discipline the current
  code states in comments becomes a checked property of the interpreter.
- Named test per verb asserting the operator-facing error text for each gate
  failure survives the collapse.

---

## Slice 4 — fan-out, designed and not built

**Dependencies**: slice 3 (this section is written as part of slice 3's docs; no
code ships).

**Implements**: the objection's end goal, recorded so it is not re-derived.

**Recommendation: a variant is a child `PlanId`**, with `parent: Option<PlanId>`
added to `PlanNote`, rather than a variant discriminator in the seed suffix.

The seed scheme is `plan_id`, `plan_id::decision`, `plan_id::review`,
`plan_id::implement` under one per-plan ref — structurally one note per kind per
plan. Child-plan variants keep that invariant intact: the state machine works
per-plan unchanged, `submit_implement`'s duplicate gate keeps its current
meaning, slice 2's per-plan locks *are* the parallelism story with no further
work, and the only new data is one optional field. The alternative
(`::implement::<n>` seeds) touches seed derivation, all four readers, the
duplicate gate's meaning, and the one-note-per-kind assumption the ref scheme
rests on. The `v1` in `BAILIFF_PLAN_NOTES_REF_PREFIX` is the migration path if
this call turns out wrong.

What then needs building: a `FanOut` spec (N children from one parent) and a
`Collect` spec (read children, compose a dossier). If each is one spec value plus
one interpreter arm, slice 3's core was right. **If either requires changing
`StageSpec` itself, that is the signal the descriptor was drawn at the wrong
altitude** — record which axis was missing rather than widening the type in
place.

---

## Non-goals

- **No new note schema in slices 1–3.** The four seeds and their notes are
  correct; only slice 4 adds a field, and slice 4 does not ship here.
- **No separate workflow-step log.** The notes are the log; a second one would
  reintroduce the dual-truth defect this plan removes.
- **No `ask-human` or preference-policy step variants.** No consumer;
  speculative generality.
- **No writ-side changes.** Every slice is inside `crates/bailiff/`; the broker's
  RPC surface, audit schema, and capability model are untouched.
- **No change to envelope verification.** The fetch → verify → decode path each
  stage runs is correct and moves into the interpreter verbatim.

## Doc updates required

`architecture.md` §5.11 changes in slices 1 and 2: the "decide and review
deliberately do not gate on submission presence" sentence becomes false (slice 1),
and "single-writer via an in-process `BailiffRepoGuard` plus a cross-process
flock for `implement`" becomes false (slice 2). Slice 3 rewrites the **Lives in**
file list.
