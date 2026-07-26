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
tighten to the workflow the original design specifies:

```
              before                        after
submit     :  (no precondition)          :  Absent
review     :  Submitted                  :  Submitted   (unchanged)
decide     :  (no precondition)          :  Reviewed
implement  :  Accepted && !Implemented   :  Accepted
```

**Review precedes the decision.** `2026-05-11-agent-plans.md` says so three
times — "plan submission, plan review by other agents, a decision gate", "the
**review → decide → execute** cycle works", and "reviewer feedback is for the
decision, not for execution" — and `submit_implement`'s own docstring cites the
last of those as the reason it keeps the review note out of the implementer's
prompt. The pre-slice code did not enforce any order, and the display layer's
"highest stage reached" rule silently assumed the opposite one (it ranked
`Reviewed` above `Accepted`), which is why `{submission, review, decision}`
rendered as `reviewed` rather than as the verdict it carries.

This ordering was got wrong once during implementation: an earlier draft of this
plan enforced `decide` → `review`, derived from the *shipped gate code* rather
than from the design doc, and shipped it. Codex review caught the symptom — the
reviewer prompt says `# Proposed plan`, which would have become a lie — and the
order was corrected before merge. The prompt label needs no change under the
corrected order.

`bailiff` is a workspace member with no dependents (only its own `bin/` consumes
the library), so nothing in-tree needed migrating, but **any operator flow that
runs `decide` before `review` stops working**, and `architecture.md` §5.11's
"decide and review deliberately do not gate" sentence becomes false. Each delta
gets a named test asserting the *new* refusal, so the change is pinned rather
than absorbed.

`Corrupt` stays representable after the tightening — a manually deleted note
still produces it — and denies every stage.

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

## Slice 3b — one note, one writer, one error

**Dependencies**: slice 3.

**Implements**: the last triplication in the subsystem, and the precondition
that makes slice 4's schema change a one-place edit.

Slice 3 deliberately kept `bailiff_plan_write.rs` out of its diff by leaving the
note-write error generic (`N`) in the two runner phases. Measured afterwards,
what that left behind is a triplication at **four** levels:

| Level | Evidence |
|---|---|
| the note body | `PlanNote`, `ReviewNote`, `ImplementNote` are field-for-field identical |
| the writer | `write_review_note` and `write_implement_note` are byte-identical modulo names and one line wrap; `write_plan_note` differs only in its storage call |
| the error | three enums, three of whose four variants are the same, differing in one noun |
| the tests | 1,168 lines across three modules with the same test names modulo the noun |

`AgentStage` already *is* the three-way distinction, so no new vocabulary is
needed: it gains a seed projection, and the three structs become one.

What ships:

- One `StageNote` body. Its canonical bytes must be **identical** to what the
  three structs produce today or existing notes stop parsing — pinned by keeping
  the three old structs in the test module as reference implementations and
  asserting byte-equality, not by inspection.
- `write_stage_note(repo, writ_repo_path, writ_notes_ref, stage, plan_id,
  purpose, completed, allowed_signers)`, and one `WriteStageNoteError
  { RepoLock, FetchVerify, AlreadyRecorded { stage, .. }, Write { stage, .. } }`.
- The generic `N` disappears from `run_under_owned_session` /
  `run_under_broker_session`, and with it the closure: the runners take an
  `AgentStage` and call the one writer.
- Three test modules become one, parameterised over `AgentStage::ALL`.

**One behaviour delta, and it is a strengthening.** `write_plan_note` calls
`write_note`; the other two call `write_note_if_absent`. Both refuse a
duplicate, but the submission's refusal arrives as a generic
`WritePlanNote(NotesRepoError)` — a git failure — where the other two arrive as
the typed `AlreadyRecorded`. Collapsing onto `write_note_if_absent` makes the
submission's duplicate typed like its siblings.
`write_plan_note_refuses_to_overwrite_existing_plan_id` changes from asserting
the generic variant to asserting the typed one, and that edit *is* the record of
the delta. Unreachable through the workflow either way, since slice 1 gates
`Submit` to `Absent`.

**Correctness oracle**:
- The 24 RPC fixtures and `rpc_trace_baseline.rs` unmodified again. Checked
  rather than hoped: all six of its `Write*Note` assertions are variant-name
  patterns with `..`, so changing the `source` *type* is invisible to them —
  which is exactly why this slice is safe and slice 3's enum collapse was not.
- Property: for each `AgentStage`, `StageNote`'s canonical bytes equal the
  pre-collapse struct's for the same field values. A reference implementation,
  not an eyeball.
- Property: the four seeds stay pairwise distinct and unchanged (extends
  `bailiff_submission_and_decision_seeds_differ_for_every_plan_id` to all four).
- Mutation: swapping two stages' seeds must fail a named test; observe it.
- `tests/stage_gate_zero_rpc.rs` passes unmodified — it plants notes at all four
  seeds, so a seed regression fails there too, independently.

### Slice 3b as built

Shipped. All gates pass, and **the oracle held again: `rpc_trace_baseline.rs`
and all 24 fixtures are byte-for-byte unmodified**, as the variant-name analysis
above predicted.

Four things are worth recording.

**1. The plan said "one `StageNote` body". That would have been a type-safety
regression, so three types ship instead — generated from one macro.**
`read_plan_body_bytes` takes `&PlanNote` specifically, because the submission's
body is what gets spliced into the reviewer's and implementer's prompts. Under
one shared type, handing it the *review* note would compile, and the implementer
would receive the review as its approved plan. So the duplication is removed at
the source (a `stage_note!` macro, following `plan_enum!`) while the distinction
stays at the call sites. Removing triplication is not the goal; removing the
*opportunity for the three to disagree* is, and a shared type would have traded
one such opportunity for a worse one.

A consequence worth stating: because the three bodies are byte-identical,
`stage_note_body`'s three match arms are **unobservable on the wire** — building
the "wrong" one writes the same bytes. The type distinction protects readers,
not writers. `the_three_stage_notes_share_one_wire_form` records that as a
property rather than leaving it as a gap someone later mistakes for coverage.

**2. There was a *fourth* encoding, and only deleting the writers found it.** A
`Verb { Plan, Review, Implement }` enum with its own `arb_verb` strategy lived in
`bailiff_plan_write.rs`'s proptest module — a fourth spelling of the three-stage
distinction alongside the three note types, three writers, and three error
enums. Nothing pointed at it; it surfaced as a dead-code error after the writers
it drove were gone. Two of its properties were also narrower than they needed to
be: `every_verb_round_trips` is now `every_stage_round_trips`, and
`review_and_implement_writes_are_idempotent` is now
`every_stage_write_is_idempotent_by_error` — whose scope *is* the record of the
behaviour delta, since the submission was excluded precisely because it was the
one calling `write_note`.

**3. Clippy's argument-count limit produced a better design than the plan had.**
`write_stage_note` came out at eight parameters. The fix was not a suppression:
four of them (two paths, two ids) travel together from CLI to runner to write and
are permutable without the compiler noticing, so they became `StageNoteTarget` —
which the runners were already building. `purpose` and the output ref
deliberately stayed out of it: they go to writ *and* onto the note, so they live
in `StageRunInputs` alone and the runner passes the same values to both. A copy
on the target would be a second place for them to disagree.

**4. A golden-bytes test, because the existing one stops short on purpose.**
`*_canonical_bytes_pin_field_order` pins the *positions* of the five top-level
keys and says so, "leaving inner-value canonicalisation to each field type's own
round-trip test". That leaves a gap: a serde rename inside `SignedRunMetadata`,
a changed number format, or a stray space keeps every key in its position and
still rewrites the bytes on disk — which orphans every note already in an
operator's repo. `stage_note_canonical_bytes_are_the_checked_in_wire_form`
closes it. Written with a deliberately wrong literal first and observed to fail.

Three mutations, each caught by the intended assertion:

| Mutation | Fails on |
|---|---|
| `note_seed` swaps Review and Implement | `happy_path_round_trips_for_every_stage` (+ 4 others) |
| revert to `write_note` (the pre-3b submission behaviour) | `a_second_write_is_refused_and_the_first_body_survives`, `every_stage_write_is_idempotent_by_error` |
| reorder two fields in the generated body | the golden test (+ the three position tests) |

Net: 1,168 lines of triplicated tests became one 450-line module whose every case
runs for all three stages, so several properties previously pinned for one or two
stages now hold for all three.

---

## Slice 4 — fan-out, designed and not built

**Dependencies**: slice 3 (this section is written as part of slice 3's docs; no
code ships).

**Implements**: the objection's end goal, recorded so it is not re-derived.

> **Superseded 2026-07-26 by "Slice 4, revised" below.** The recommendation in
> this section was written before `bailiff_plan_state.rs` existed, and its
> central claim — "the state machine works per-plan unchanged" — is false
> against the state machine slice 1 actually shipped. Kept in place because the
> reasoning that overturns it is only legible next to it.

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

## Slice 4, revised — N runs under one plan

**Dependencies**: slice 3b.

**Implements**: the objection's end goal. Replaces the recommendation above.

### Why the child-plan recommendation does not survive slice 1

A child plan carrying only an implement note has `NotePresence
{ ref_exists: true, submission: false, …, implement: true }`, which
`derive_state` reads as `Corrupt` — and before its run it is `Absent`.
`Implement` is illegal from both. So the child's gate cannot be
`allows(child_state, Implement)`; it has to consult the *parent*.

That means one of:

- `derive_state` takes a second input (the parent's state), so the parse is no
  longer a function of the plan's own notes; or
- a second relation, `allows_child(parent_state, child_state, stage)`, beside
  the first.

The second is the four-disagreeing-encodings defect, re-created deliberately.
The first is defensible but drags a further cost: a fan-out workflow then holds
**two** plan locks, so `PlanGuard` needs a documented acquisition order (by id)
to stay deadlock-free — a hazard slice 2 does not currently have, since every
workflow holds exactly one.

This is precisely the signal the section above asked for: *"if either requires
changing `StageSpec` itself, that is the signal the descriptor was drawn at the
wrong altitude — record which axis was missing."* **The missing axis is: whose
state does the precondition read?** Every stage so far reads the plan it writes
to. `AgentStage::precondition`'s test
(`each_agent_stage_gates_on_its_namesake_plan_stage`) exists to make that
assumption fail loudly rather than generalise silently, and here it fires.

### What ships instead

The `::implement::<n>` seed scheme the section above rejected. Its stated cost
was that it "touches seed derivation, all four readers, the duplicate gate's
meaning, and the one-note-per-kind assumption the ref scheme rests on" — but
slice 1 centralised three of those four into one definition, so the same change
is now local:

- `plan_implement_seed_blob_bytes(plan_id, attempt)`. Attempt 0 must hash to the
  **current** seed's bytes, or every existing implement note is orphaned.
- `NotePresence.implement` becomes a count rather than a bool. `derive_state`
  reads `Implemented` iff the count is ≥ 1 — one line, one definition.
- `Implement` becomes legal from `Implemented` as well as `Accepted`.

That last change **deletes
`legal_stages_never_repeat_from_the_state_they_produce` for one stage**, and
that is the honest headline of this slice rather than a regrettable side effect:
the property asserts every stage is one-shot, and fan-out means implement
deliberately is not. The property survives for `Submit`, `Review`, and `Decide`;
`Implement` gets a named replacement asserting the *bounded* thing instead — that
repeating it adds an attempt and never overwrites one.

Nothing else moves. One plan, one ref, one lock, one relation, one state
machine. There is no `parent` field, no second gate, and no lock ordering rule.

**What varies between variants needs no schema at all.** Agent kind and model
are already on the signed metadata each run's envelope carries, via the writ
session; the prompt is already hashed into it. So "which variant was this?" is
answerable from the notes bailiff already stores, and `Collect` is a read-side
projection over the attempts rather than a new record.

**Correctness oracle**:
- Property: `plan_implement_seed_blob_bytes(id, 0)` equals the pre-slice-4 seed
  for every plan id. Written against the old function kept as a reference
  implementation, so it cannot drift.
- Property: the four seed families stay pairwise distinct across all
  `(plan_id, attempt)` pairs — the invariant the whole per-plan ref scheme rests
  on, and the one an attempt suffix could break by colliding with another
  family's bytes.
- Property (replaces the deleted one for `Implement`): from `Implemented`,
  `Implement` is legal, and running it yields `Implemented` with the count
  incremented by exactly one and no existing attempt's bytes changed.
- Every other slice-1 property passes **unmodified**, including
  `reachable_presences_are_exactly_the_non_corrupt_states` — a count-valued
  field widens that enumeration, so its bound needs stating rather than
  silently growing.
- `tests/stage_gate_zero_rpc.rs` extends: `Implement` moves from the forbidden
  half to the allowed half for `Implemented`, which is the behaviour delta
  written as a test rather than as a diff.
- The 24 RPC fixtures unmodified: a first attempt emits the same trace it does
  today.

**Non-goals for this slice**: no `Collect`/dossier verb, and no concurrency
across attempts. Attempts under one plan share one lock, so N runs on one plan
**serialise** — which is a real limitation and the reason to state it rather
than discover it. If parallel variants are wanted, that is a follow-on that
needs the lock keyed by `(plan, attempt)` for the write and by `plan` for the
gate, and it should be measured before being assumed necessary.

### Slice 4 as built

Shipped. All gates pass; **the 24 RPC fixtures are byte-for-byte unmodified**,
as predicted — a first attempt puts exactly what it always did on the wire.

**1. `NotePresence.implement` stayed a `bool`.** The plan said "becomes a count".
Writing it out, the count is not what the relation needs: `derive_state` asks
only "is this plan implemented at all", and a count would have widened slice 1's
48-element enumeration — the domain every property there quantifies over — to
carry a number none of them read. Parse-don't-validate cuts the other way here:
the observation the relation takes should be exactly what the relation uses.
The count lives where it is *used* instead, in the workflow choosing its next
attempt and in `plan show`.

That has a load-bearing consequence, so it is stated rather than assumed:
**attempts are dense from zero**, which is what makes "attempt zero exists"
equivalent to "any attempt exists". Density is why the gate still costs one note
read rather than a scan, and `read_implement_attempts` refuses a gap
(`NonDenseAttempts`) rather than truncating at it — a gap would otherwise hide
every attempt past it from every reader while the next write happily filled the
hole, leaving two live notes nobody had reconciled.

**2. The attempt lives on a new `StageNoteSlot`, not on `AgentStage`.** Putting
it on `AgentStage` would have made "the third submission" representable. The slot
is a refinement — `Submission | Review | Implement(ImplementAttempt)` — with
`stage()` projecting back; the inverse is not a function, which is exactly the
fan-out shape. `AgentStage` keeps answering the gate and the prompt, neither of
which has an attempt.

**3. Five slice-1 properties failed, and only two were the planned deltas.** The
plan named `legal_stages_never_repeat_from_the_state_they_produce`. The other
three were found by running:

| Property | What it turned out to say |
|---|---|
| `implement_now_requires_an_accepted_verdict` | asserted `Implement` is illegal from `Implemented` — the old duplicate gate, now the feature |
| `next_stage_follows_the_chain_and_stops_at_terminals` | `Implemented` was a terminal; it no longer is |
| `rank_is_defined_for_every_state_on_the_progression` | **every legal move strictly increases rank** |

The third is the interesting one. Rank monotonicity is what makes
`already_passed_from` — defined as "beyond every legal predecessor" — mean
"already passed", and a repeatable stage is a self-loop, so monotonicity cannot
hold universally any more. Rather than dropping the property, it now names the
**exact pair** that is exempt (`Implement` from `Implemented`, landing on
`Implemented`), so any *other* move that stops advancing rank still fails. Same
treatment for the one-shot property: scoped to the other three stages, with
`implement_is_the_one_repeatable_stage` pinning that the exemption set has
exactly one member — computed from the relation, not written down beside it.

`already_passed_from` needed no edit at all: it derives from
`legal_predecessors`, so adding `Implemented` to that list flipped it for free.
That is slice 1's design paying off, and it is the reason this slice is one
entry in a table rather than a new shape.

**4. Two stale operator surfaces.** `plan implement`'s clap help still listed
"already-implemented → submit a fresh plan if a re-implement is needed", and the
`AlreadyRecorded` message still called repeat attempts "a future v1 → v2
migration". Both were true when written and are now the opposite of the feature.
Same class as the `decide` clap help found in slice 1's fourth review round —
help text does not fail a build.

**5. Codex found the gap check only catching gaps of width one.** The first
version probed a single slot past the first miss. That is enough for `{0, 2}`
and useless for `{0, 3}`: the scan returned `next_free = 1` and attempt 3 stayed
invisible to every reader while the next run refilled slot 1. The test I had
written used width one, so it passed.

The rule the fix follows: **a check that samples cannot establish an invariant
that quantifies.** Density is a claim about *every* slot, so the scan now reads
every slot in the bounded range and refuses on the first note that follows a
hole. That costs `MAX` probes at two git invocations each, which is why `MAX`
came down from 256 to 32 — it is a *cost* bound, not a product opinion about
fan-out width, and the docstring now says so. Neither caller is on the gate's
path: one is about to run an agent for minutes, the other is `plan show`.

The replacement test is parameterised over gap widths that straddle the old
check's reach (`{0,2}`, `{0,3}`, `{0,1,5}`, `{0,9}`), and an early-stopping scan
is caught by `{0,3}` — Codex's own example.

**6. Codex round 2 found two more stale surfaces, one of them a test.** The
`plan implement` clap help still promised, a paragraph above the one slice 4
edited, that "the pre-RPC duplicate gate refuses a second `bailiff plan
implement` on the same plan to foreclose a double-push" — the opposite of the
feature, and a *safety* claim rather than a description. The corrected text says
what is actually guaranteed instead: each run pushes, so a repeat is a
deliberate act, and what append-only slots plus the plan lock buy is that an
earlier attempt's note is never rewritten and two concurrent runs cannot claim
the same index.

The second is more interesting. Two `#[ignore]`d end-to-end tests (awaiting slice
VM3) still asserted the one-shot contract: one required a repeat to return
`IllegalTransition`, the other required exactly one of three concurrent calls to
win. Ignored tests fail no gate, so nothing in this repo would have noticed until
VM3 un-ignored them — at which point they would have looked like a regression in
VM3's work rather than a contract change made here. Both are rewritten to the new
contract, and the concurrency one now witnesses something sharper than before:
**no call may fail with `AlreadyRecorded`**, because that variant means two
callers picked the same index, which is precisely the race the lock exists to
prevent. Neither has been observed to hold — they cannot run yet — and both say
so.

Five mutations, each caught by the intended assertion:

| Mutation | Fails on |
|---|---|
| attempt zero gets an indexed suffix | `attempt_zero_keeps_the_pre_slice_4_seed` (+2) |
| the scan stops after two consecutive misses | `a_gap_in_the_attempt_sequence_is_refused_at_any_width`, on `{0,3}` |
| the gap check is dropped entirely | the same test, on `{0,2}` |
| `Implement` stops being repeatable | 3 state properties **and** the grid-count assertion in `stage_gate_zero_rpc` |

The grid test derives both halves from `allows`, so a widened relation would
have silently moved cases across it. It now asserts the split as a number: four
permitted pairs, one of which — `Implement` from `Implemented` — is this slice.

---

## Outcome so far

**Slices 1 and 2 shipped** (`4e35069`, `e850e9d`); slice 3 not started. Both
passed the full gate set — `fmt`, `clippy --all-targets --all-features -D
warnings`, `test`, the `vm-client` feature build, and `cargo doc -D warnings`.

Four things are worth recording because they change what the remaining slices
should assume.

**1. The `cargo doc` gate earned its keep twice.** It caught `derive` colliding
with the derive attribute macro (fixed by renaming to `derive_state`, which is
better at call sites anyway) and every stale intra-doc link left by the error
variants slice 1 deleted. `build`, `test`, and `clippy` all passed throughout.

**2. Mutation-testing the properties was not ceremony.** Five mutations —
widening the relation, reverting a tightening, and three wrong state⇒presence
pairings — were each caught by two or more properties. That is the only reason
to believe them.

**3. Slice 2's design was wrong twice, and the tests found both.** The first
draft layered a per-plan async mutex over the flock, which forced a process-wide
registry, lifetime bookkeeping, and a field order chosen so the layers released
in reverse acquisition order. The eviction sweep read `Arc::strong_count` on a
map-held strong reference, so its threshold counted the map itself and it
evicted mutexes callers were still blocked on; and the field order released the
mutex before the flock, so a woken waiter hit a still-held lockfile. Neither
layer was needed: `flock` binds to an *open file description*, so two `open`
calls contend inside one process too. **The lesson for slice 3: prefer the
primitive that already has the property over the abstraction that reconstructs
it.**

**4. Two assumptions in this plan were wrong, both in slice 2's favour.**

- The plan said the per-git-invocation fallback lock might be needed. It already
  exists: `NotesRepo` serialises each note write behind a per-canonical-path
  mutex. Nothing to add.
- The plan proposed keeping *two* lock layers because "a single process can hold
  a given flock only once" (quoting `bin/bailiff/tests.rs:1153`). That comment
  describes the behaviour accurately but the conclusion drawn from it was
  backwards — same-process contention is what makes the single mechanism
  sufficient, not what rules it out.

The stress test the plan demanded was run and is recorded in the guard's module
docs: 32 concurrent cross-process `git notes add` calls on 32 distinct refs in
one bare repo, all successful, every note readable.

**One test was deleted rather than migrated.**
`implement_lock_blocks_concurrent_acquire_and_releases_on_drop` pinned the
CLI-layer flock helper, including its fail-fast behaviour. Its own docstring
listed "swapping `try_lock` for `lock`" as a regression it would catch — which
is precisely the deliberate change. A comment at its former site records that,
and points at the guard-module tests that replace it.

**5. Codex review found three more, all valid.** Recorded because two of them are
the *same shape* as the bugs above — a lock whose scope did not match the scope
of the thing it protected.

- **The shared writ mirror was left per-plan.** Every workflow force-fetches
  `refs/notes/writ/v1/*` into one destination, so per-plan locks do not
  serialise it; a fetch for one plan can roll the mirror back between another
  plan's fetch and its read, and on the implement path that can strike *after*
  the agent has pushed. `NotesRepo`'s mutex does not cover it — it serialises
  each git invocation, not the fetch→read pair, and it is process-wide where the
  hazard is not. Fixed with `lock_writ_mirror`, a repo-wide flock held only
  across that pair, taken inside the plan lock (total order, no deadlock).
  Slice 2 had *widened* this hazard in-process: the old repo-wide guard
  accidentally covered it.
- **`run_blocking` was cancellation-unsafe.** Tokio does not cancel a running
  `spawn_blocking`, so a dropped workflow future closed the lockfile while the
  closure still held the repo. The two-layer draft had this right by accident —
  it passed the mutex guard *into* the closure — and collapsing to one mechanism
  lost the property. Fixed by handing the lockfile to the task and taking it
  back.
- **The contention notice was invisible.** `tracing::info!` sits below the
  `warn` filter `bin/bailiff.rs` installs, so a waiting CLI looked hung. Now
  `warn!`. (Codex's stated reason — that the binary installs no subscriber — was
  wrong; it calls `telemetry::init("warn")`. The conclusion held.)

**6. Codex review ran four rounds; nine findings, all valid.** The two locking
bugs above were found by my own tests; the rest by review. Grouped by what they
have in common rather than by round:

*Scope mismatches (4).* The shared writ mirror left per-plan; the mutation lock
covering fetch→read but not the note write; `write_decision_note` missing the
lock entirely; `run_blocking` releasing the lock on cancellation. Each is the
same error — a lock whose scope did not match the scope of the thing it
protected — and the last two are *regressions introduced while fixing the first
two*.

*Wrong-by-construction evidence (1).* The 32-way concurrency experiment I used
to justify per-plan locking only ever ran notes-add against notes-add.
`NotesRepo::fetch_from_remote`'s docstring states the constraint that actually
mattered — "Git's index / refs / objects writes are not safe under concurrent
fetch+notes-add into the same destination" — and I had read that file without
reading that paragraph.

*Resource exhaustion (1).* Waiting on a plan flock parked a `spawn_blocking`
worker for the length of an agent run, starving the holder of the worker it
needed to release the lock.

*Model errors (3).* The stage order (below); `decided_at` stamped before a lock
that now waits; ref existence dropped from the observation, collapsing "never
touched" into "empty ref left by manual repair".

*Stale surfaces (1).* The `decide` verb's clap help kept advertising the old
predecessor.

**7. The stage order was wrong, and the options I offered concealed it.** Slice 1
shipped `decide` → `review`. `2026-05-11-agent-plans.md` specifies the opposite
three times over, and `submit_implement`'s own docstring cites one of those lines
as the reason it keeps the review note out of the implementer prompt. The options
put to the repo owner were derived from the *shipped gate code*, so the design
doc never entered the decision. Review caught the symptom — the reviewer prompt
says `# Proposed plan`, which the inverted order turned into a lie — and the
literal fix on offer was to relabel the prompt, which would have cemented the
inversion. **Deriving a "principled" choice from current behaviour reproduces
current behaviour's mistakes.**

**8. Three attempts to test one locking property, two of which proved nothing.**
`!contender.is_finished()` and a sequence-number ordering assertion both passed
with the bug deliberately reintroduced: "the contender did not get there" is
indistinguishable from "the contender was correctly blocked". What worked was
abandoning concurrency in the test entirely — a synchronous `try_lock` probe for
cancellation, and for the missing decision-note lock, making the lock
*unobtainable* and requiring the error. The rule that emerged: **to test that a
lock is taken, break the lock, not the timing.**

An unreachable error variant sat in the tree for a full round without any gate
noticing. `clippy` does not warn on one, and it was the only trace that a call
site had been dropped.

## Slice 3: the baseline is captured; the interpreter is not built

The plan's precondition is met. `crates/bailiff/tests/rpc_trace_baseline.rs`
records **24 traces** — the exact `ClientMessage` sequence each workflow puts on
the wire — taken against the pre-refactor code, which is the only moment they
could have been taken. Every control-flow-distinct path is covered: happy,
pre-RPC refusal, post-gate/pre-session failure, and each post-session failure,
for all three workflows.

Three of them carry most of the weight:

- **`implement_happy` has no `session_id`** and carries workspace and agent
  identity inline, because the VM arm mints and closes the audit session
  broker-side. Session ownership is therefore a **DU, not a boolean**, in
  `StageSpec` — now pinned rather than merely argued.
- **The zero-RPC fixtures** are what stop a rejected workflow burning an audit
  row, and there are six of them, because "before the gate" and "after the gate
  but before the session" are different failures.
- **`*_close_session_error` vs `*_cleanup_close_error`** emit *identical* traces
  and differ only in which error survives. Where two branches share a trace, the
  assertion is on the returned variant instead — the baseline pins outcomes as
  well as messages.

**Six Codex rounds on the baseline, ten findings, all valid.** Five were the same
defect wearing different clothes: *an assertion that could not fail for the
reason it claimed.* The stub returned before reading, so zero-RPC fixtures passed
on an emitted RPC; `UPDATE_RPC_TRACES` was tested with `is_ok()`, so `=0` silently
disabled all comparison; the review note-failure scenario failed pre-RPC and
recorded an empty trace under a name promising a post-run branch; the
session-mismatch scenarios accepted any error, and a stale signature meant
deleting the check would fail later with the same trace.

The rule that finally covers all of them: **a trace pins what was sent and
nothing about which branch sent it.** Wherever two branches can produce the same
trace, only the outcome distinguishes them.

Each property was then checked by mutation rather than by going green — prompt
drift, a deleted `close_session`, a genuinely-emitted RPC against an empty
fixture, and a corrupted fixture under `UPDATE_RPC_TRACES=0`. One of those
mutations initially matched nothing (the constant is private; the pattern
required `pub`), and the assertion that the mutation had applied is what caught
it.

**What remains:** the `StageSpec` descriptor and its interpreter. The axes are
settled — precondition (a `PlanStage`, so slice 1 answers legality), capability
set, prompt composition, note writer, and session ownership as a DU — and the
regression net is now checked rather than hoped for.

## Slice 3, revised: phases, not one interpreter over a union error

The slice-3 sketch above says "`fn run_stage(client, guard, spec, inputs) ->
Result<StageOutcome, StageError>` is the interpreter. The three verbs become
three `StageSpec` values plus their CLI argument parsing." Writing it out
against the actual error surface showed that shape costs more than it buys, in
a way worth recording rather than silently working around.

### The measurement

`StageError` as a single union has to hold every failure any of the three
stages can raise. Counting them against the three existing enums:

| Failure group | Submit | Review | Implement |
|---|---|---|---|
| lock / read state / illegal transition | ✓ | ✓ | ✓ |
| read submission note, verify envelope, compose prompt | — | ✓ | ✓ |
| open session, session-id cross-check, close session | ✓ | ✓ | — |
| run agent, write note, write-task join | ✓ | ✓ | ✓ |

Three of the four groups are *not* universal, so a single union makes three
illegal states representable at once: a `Submit` failure that names a planner
envelope it never read; an `Implement` failure that names a session bailiff
never opened; and — because the implement path has no bailiff-side session id
before `RunAgent` returns — a `RunAgent` variant whose `session_id` has to
widen to `Option<SessionId>` for one arm's benefit. The note-write error is a
fourth: the three `write_*_note` helpers have three distinct error types, so
`StageError::WriteNote` would carry a three-arm union of which each caller can
reach exactly one.

That is the same defect this plan exists to remove — one encoding that is
wrong for every specific case — reintroduced at the error layer. Slice 1's own
lesson applies: `PlanState::presence` returns `Option<NotePresence>` rather
than a widened struct precisely so `Corrupt` cannot claim a note set.

There is also a hard constraint. `tests/rpc_trace_baseline.rs` — the regression
net this refactor is being run against — makes 18 assertions on the *variants*
of `SubmitPlanError` / `SubmitReviewError` / `SubmitImplementError`. They are
what distinguish the branch pairs that emit identical traces. Collapsing those
three enums means rewriting the oracle in the same commit that changes the code
it checks, which is how an assertion stops being able to fail. Checked rather
than assumed: every one of the 18 is a variant-name-only pattern (`{ .. }` or
`(_)`), so **variant names and enum names must survive; payload types may
change.**

### What ships instead

The three workflows differ in **which phases run**, not in **how a phase runs**.
So the data is a phase vocabulary, and each stage is the composition of its
phases — short enough to read at a glance, and statically typed so that no
stage can be handed a phase it has no error variant for.

New `crates/bailiff/src/bailiff_stage.rs`:

- `AgentStage` — `Submit | Review | Implement`. Deliberately *not* `PlanStage`:
  `Decide` runs no agent, so "compose a prompt for the decide stage" is not
  expressible. `precondition()` returns the `PlanStage` slice 1 gates on and
  `plan_body_heading()` the framing, so the two static axes cannot disagree with
  the stage or with each other.
- `PlanBodyHeading` — `Proposed | Approved`, with `separator()` returning the
  byte-identical strings the two modules held as private constants. An enum, not
  a `&'static str` field, because the distinction is load-bearing (§7 above: the
  inverted stage order turned `# Proposed plan` into a lie) and a third framing
  should not be reachable by typo.
- `open_plan_stage(repo, plan_id, stage) -> Result<PlanGuard, OpenPlanStageError>`
  — take the lock, read the state, ask the relation. Takes a `PlanStage`, not an
  `AgentStage`, because `decide` runs this phase too; four callers, all four
  producing all four error variants.
- `compose_with_plan_body(...) -> Result<AgentPrompt, ComposePlanPromptError>`
  — read the submission note, fetch+verify the planner envelope, decode, splice
  under the heading. Two callers, both producing all four variants.
- `run_under_owned_session(...) -> Result<StageRun, OwnedSessionRunError<N>>`
  and `run_under_broker_session(...) -> Result<StageRun, BrokerSessionRunError<N>>`.

**Session ownership is a DU promoted to the type level.** Two functions rather
than one function over a `SessionOwnership` tag: the close-session path is not
*reachable* from the broker-managed stage, rather than merely unreached. The
slice-3 sketch's stated goal — "a boolean here would make the illegal 'bailiff
closes a broker-owned session' state representable" — is met more strongly by
splitting the function than by tagging its argument. The two `session` argument
types (`OwnedSession` carries a label and optional identity; `BrokerSession`
carries the `AgentVmWorkspaceBootstrap` and required identity) are what route a
caller to the right one, which matches what the broker already keys on.

`N` is the note-write error, left generic so `bailiff_plan_write.rs` — 797
lines with its own test suites — stays entirely out of this diff. The writer
arrives as a closure built one line above the call; it is the tail of a linear
pipeline, not a strategy selected at a distance.

### Where this leaves the objection

The objection asked for "an interpreter that executes steps via writ". What it
was really asking for is that adding a stage must not mean copy-pasting 120
lines of sequencing, and that is what the phase vocabulary delivers: slice 4's
`FanOut` is `open_plan_stage` per child, one `compose_with_plan_body` against
the parent, and `run_under_broker_session` per child. If a future stage really
does want one dispatch point over `AgentStage`, `run_stage` is a thin cap over
these phases whose union error is honest *because* the phases below it are
precise. It is not built here: nothing calls it, and speculative generality is
a non-goal.

**Correctness oracle for this slice:**
- The 24 RPC fixtures pass **unmodified**, and `rpc_trace_baseline.rs` is not
  edited. This is the primary oracle and the reason the enums survive.
- Every existing test in `bailiff_plan_{submit,review,implement,write}.rs`,
  `bin/bailiff/tests.rs`, and `tests/properties.rs` passes untouched.
- New property (`tests/stage_gate_zero_rpc.rs`): for every `AgentStage` and
  every `PlanState` its precondition forbids, the workflow performs **zero**
  writ RPCs. Plans are planted in each state by writing real notes at the four
  seeds, so the property runs against `summarize_plan` rather than a model of
  it. This generalises the three `*_refused` fixtures from one state each to
  every forbidden state.
- Mutation: reverting each phase extraction (or dropping the gate from one
  stage) must fail a named test, asserted by observing the failure.

## Slice 3 as built

Shipped. `bailiff_stage.rs` holds the phase vocabulary; the three workflow
bodies are now their phase compositions plus a total `From` per phase error, and
`plan_decide` in the binary is the gate phase's fourth caller. All gates pass,
and **the oracle held: `rpc_trace_baseline.rs` and all 24 fixtures are byte-for-
byte unmodified**, which is the whole reason the enums survived.

Four things are worth recording.

**1. The refined type removed an `expect`, and merging two enums removed a
disagreement.** `compose_with_plan_body` originally took an `AgentStage` and an
`.expect("this stage consumes a plan body")`. Replacing that with
`PlanBodyStage` — the two stages that consume one — makes the caller carry the
proof. The first draft of that had `PlanBodyStage` *and* a separate
`PlanBodyHeading { Proposed, Approved }`, which are bijective; a bijective pair
of enums is a pair that can disagree, and disagreeing encodings are the entire
subject of this plan. Collapsed to one, with the framing derived.

**2. Two test blocks moved with the code they cover, and one grew a mirror.**
`build_request_tests` and both `compose_tests` modules now live in
`bailiff_stage/tests.rs`, because the functions they pinned became bindings over
shared ones. Moving a test to follow its code is not the "rewriting a test is a
finding" case the oracle warns about — the assertions are the same assertions on
the same values — and a comment at each former site says where they went. While
moving `build_request_tests`, its mirror image turned out never to have existed:
nothing asserted that an *owned*-session request carries `workspace: None`. A
bootstrap there would silently reroute the run into the VM arm, which then
rejects it for carrying a session id, so the two fields are a pair.
`owned_request_binds_the_session_and_carries_no_workspace` is new.

**3. The new grid property caught the shadowed-assertion trap once more, and
this time before review.** `tests/stage_gate_zero_rpc.rs` sweeps all 3 × 7
(stage, state) pairs: forbidden ⇒ zero RPCs *and* an `IllegalTransition` naming
the planted state; allowed ⇒ at least one RPC, as the control against a workflow
that had stopped talking to writ at all. States are planted from
`PlanState::presence()` and read back through `summarize_plan`, so the file
cannot encode a fifth opinion about which notes a state has.

The first version asserted the error variant *before* the RPC count. Every
mutation then failed on the variant line, and the RPC-count assertion — the
point of the file — was never once observed to catch anything. Swapping the
order fixed it. Four mutations, each caught by the line it should be:

| Mutation | Fails on |
|---|---|
| gate dropped for `submit` only | `Submit from corrupt is forbidden but emitted [OpenSession …]` |
| gate dropped entirely | the variant line (review's post-gate `expect` panics first, zero RPCs) |
| the two prompt framings swapped | 6 of 11 baseline trace tests |
| happy-path `close_session` deleted | 4 of 11 baseline trace tests |

The second row is the one to keep in mind: **removing a check is not the same as
removing its effect.** Dropping the gate does not make review emit RPCs, because
the `expect` that the gate discharges panics first. Only the stage with no
post-gate read (`submit`) actually leaks an RPC, so a grid that omitted `submit`
would have been much weaker than it looked.

The `cargo doc -D warnings` gate caught two more stale intra-doc links — the
third time in this plan it has been the only gate to notice something. `build`,
`test`, and `clippy` were all green with them in the tree.

**4. What this says about slice 4.** The plan's test for whether the descriptor
was drawn at the right altitude was "if fan-out is one spec value plus one
interpreter arm, slice 3's core was right." Under the phase vocabulary the
question becomes: is a variant run a *new composition of existing phases*?
It is — `open_plan_stage` per child, one `compose_with_plan_body` against the
parent, `run_under_broker_session` per child — with no new phase and no change
to an existing one. The axis that would break it is a stage whose precondition
is not its own plan's state (a child gated on its parent's), which is exactly
where `AgentStage::precondition`'s test
(`each_agent_stage_gates_on_its_namesake_plan_stage`) is written to force a
deliberate change rather than silently generalise.

## Slice 5 — the dossier is a read

**Dependencies**: slice 4.

**Implements**: the end goal's last clause — "spin up several variants, actually
build them, … compose a dossier". Slice 4 made variants exist; nothing showed
what they *did*.

`plan show` renders each attempt's metadata and verification status, not its
output, so N variants were countable but not comparable. `bailiff plan dossier`
assembles the approved plan body once — the context every attempt shared — then
every attempt's verified stdout.

**Deliberately a read, not an agent run.** Fable's step list has
`collect-evidence` as a workflow step, and a comparing agent is the obvious
reading of "compose a dossier". But such an agent needs the variants' outputs
assembled before it can compare them, and this *is* that assembly. Building the
agent now would mean a fifth note kind and a new stage with no consumer —
speculative generality. If one is later wanted, its prompt is this verb's
output, and it composes as one more `AgentStage` over the existing phases.

**One parser, per-caller policy.** `read_plan_body_bytes` was the fetch →
re-verify → decode chain hard-wired to `&PlanNote` *and* to the planner's
acceptance rules (non-empty, non-truncated, UTF-8). The dossier needs the chain
for `&ImplementNote` and needs the opposite rules: an implementer that pushes
and says nothing is ordinary, a long run hitting the output cap is ordinary, and
its stdout need not be text. So the chain is now `read_verified_output`, generic
over the existing `SignedBailiffNote` trait and returning the decoded
`OutputEnvelope` with **no policy applied**; `read_plan_body_bytes` is a thin
wrapper applying the planner's three rules. Parse once, judge per caller.

**The format carries agent-controlled bytes, which is new here.** Every other
writer in `output.rs` promises one line per key and escapes free-form text onto
one line; a hundred lines of implementer output escaped onto one is unreadable,
and raw bytes would break the contract every consumer relies on. So output
travels length-prefixed — `stdout_bytes=<n>`, then exactly `n` bytes, then a
newline. A length prefix rather than a delimiter *specifically because* the
payload is agent-controlled: an implementer can emit a convincing delimiter on
purpose, and no escaping scheme survives that as cleanly as a byte count.

**Correctness oracle**:
- The 24 RPC fixtures unmodified — splitting `read_plan_body_bytes` must not
  change what review or implement do.
- Named test: an attempt whose envelope does not verify contributes **no bytes**,
  and the failure is per-attempt rather than failing the whole dossier. This is
  the verb's load-bearing security property: unverified agent output rendered
  beside verified output with nothing to tell them apart is the worst thing a
  dossier could do.
- Property: for any payload — newlines, NULs, non-UTF-8, embedded
  `stdout_bytes=` lookalikes — the declared length matches what follows and the
  payload round-trips through a re-implemented reader.
- Named tests for the policy split: an empty output and a non-UTF-8 output are
  rendered, not refused, where `read_plan_body_bytes` refuses both.

### Slice 5 as built

Shipped, and one finding is worth more than the feature.

**Mutation testing found a property with no test.** Making `read_verified_output`
skip `verify_run_envelope` was caught. Making the *renderer* emit a
`stdout_bytes` block on the failure arm was **caught by nothing** — every test in
the crate passed while the renderer printed unverified agent bytes labelled
`verification=failed` right next to them.

The reader-side test (`an_unverifiable_attempt_contributes_no_bytes`) proves the
reader withholds the bytes; it says nothing about what the renderer does with a
failure it is handed. Two halves of one promise, and only one was covered.
`a_failed_attempt_emits_no_stdout_block` is the other half. The general shape,
which has now recurred at every layer of this plan: **a promise that spans two
components needs a test at each, because a test of one half passes while the
other half breaks it.**

**Two `git checkout -- <file>` mistakes.** Reverting a mutation that way
discarded uncommitted work twice — once the slice-4 relation edit, once this
slice's entire renderer. Both were caught immediately (the tests started failing
for the wrong reason), but the habit is wrong: scratchpad copies for mutations,
and commit before mutating. Recorded because the second one happened after
noticing the first.

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
