# Promote the approve-attempt state machine to a first-class Rust type

Drafted 2026-07-25. Companion to `../design/approve_state_machine.md` (the
original design) and `../design/architecture.md` §5.4 (the audit subsystem, where this machine lives). Sibling of the structural
backlog in `2026-07-17-architecture-refactor-backlog.md`, which addressed *module
shape*; this plan addresses *where a state machine's truth lives*.

## The objection

A reviewer's critique, quoted in full:

> **State machines live in SQL + procedure, with Rust mirroring them by hand.**
> The approve machine's truth is in triggers (correct as a backstop) but the Rust
> side mirrors it: a preflight query (`reject_blocker_for_push`), a
> `RejectBlocker` enum, and a trigger-message string constant that must stay in
> sync. The VM lifecycle has only `Starting`/`Running`, with the single-owner
> invariant stated in a comment rather than a type, and transitions implicit in
> function call order. Adding a `Stopping` state or a third approve outcome means
> coordinated edits across SQL, trigger CASE arms, Rust enums, and N match sites.
>
> Keep the triggers — they're the unkillable layer — but promote each state
> machine to a first-class Rust type (states + transition functions returning
> `Result<NewState, InvalidTransition>`) that the DAO persists, rather than the
> DAO being the machine.

## Verdict: valid for approve, in substance; not valid for the VM lifecycle

The framing needs one correction before the remedy is right.

**The approve *states* are already a first-class type.** `GitPushApproveAttemptState`
(`git_push.rs:147`) is a proper DU carrying its data — `Uncertain { mint }`,
`Resolved { outcome, mint, completed_at }` — and `git_push_approve_attempt_from_row`
parses rows into it rather than validating them. `UncertainAttempt` goes further:
a witness the promote layer must present to issue its PATCH, so "the durable
record precedes the effect" is compiler-checked. That is not hand-mirroring; it
is already the pattern the objection asks for.

**What is genuinely missing is everything *around* the states.** Four specific
defects, all instances of the reviewer's complaint:

1. **The wire names are stringly-typed at every write site.** There is no
   enum↔string codec: `"started"`, `"uncertain"`, `"pre_patch_failure"` appear as
   bare literals in eight DAO sites (`dao.rs:403,588,663-664,709,752-753,987`) and
   again in the parser's `match` (`git_push.rs:770-841`), which is one-way — it
   reads strings but nothing writes them through a shared function. Adding an
   outcome means grepping for literals and hoping.

2. **The legal-transition relation has no Rust definition at all.** It exists in
   two independent encodings: the `git_push_approve_attempt_forward_only`
   trigger's three arms (`0003_…sql:219-235`), and a scatter of per-method
   preflights — `if state != "started"`, an `allowed_states: &[&'static str]`
   parameter threaded through `complete_attempt_failure`, and `UPDATE … WHERE
   state = 'started'`. Nothing ties the two encodings together; no test asserts
   that Rust's notion of a legal transition equals SQLite's.

3. **The "does this attempt block?" predicate is written six times in two
   languages.** `git_push_resolution_refuses_active_approve` (trigger),
   `git_push_approve_attempt_reconciliation_predecessor_eligible` (trigger),
   `start_approve_attempt`'s SQL preflight, `list_blocking_approve_attempts`
   (SQL), `reject_blocker_for_push` (Rust), `classify_reconciliation_target`
   (Rust), plus `load_reconciliation_predecessor`'s `state == "uncertain"` /
   `outcome == Some("post_patch_failure")` string test. They agree today. Nothing
   makes them agree tomorrow.

4. **A trigger message is mirrored as a Rust literal — and its reference has
   already drifted.** `staged_push.rs:1681` matches the trigger's abort text
   verbatim, and its doc comment cites
   `migrations/0005_approve_attempt_state_machine.sql`, a file that does not
   exist (it is `0003_…`; the *schema version* is 5). The predicted drift is
   already observable, which is the strongest possible evidence for the
   objection.

**The VM lifecycle claim does not hold.** `AgentVmSessionStateStatus` has two
states and one transition. Its legality check is a single Rust `if` in one place
(`state_store.rs:423,468`: refuse `mark_running` unless the loaded record equals
the caller's and is `Starting`), the store is a JSON file with no triggers, and
the managed-stop match is deliberately wildcard-free so a new status fails to
compile. There is no second encoding to drift from — the dual-truth problem that
motivates the remedy is absent. Promoting a one-edge machine to a transition
function would be speculative generality, which `gospel.md` rules out; the honest
answer is "when a third state actually arrives, build the type then." Left alone.

So: **fix the approve machine, leave the VM lifecycle.**

## The remedy

Keep the triggers exactly as they are — the objection is right that they are the
unkillable layer, and correctness-over-availability says the DB should refuse a
contradiction even if every Rust caller is wrong. Change what sits above them:

- One module owns the state machine's vocabulary (wire names), its transition
  relation, and every predicate derived from a state.
- The DAO becomes a *persister* of that machine's decisions rather than the
  machine itself: read row → parse to state → ask the machine → write.
- The two encodings get bound together by a **property test that treats SQLite as
  the oracle**: for every (state, transition) pair, the Rust machine accepts iff
  the schema accepts. A future state or outcome added to one side and not the
  other fails the test rather than shipping.

That last point is the load-bearing one. Duplication that *cannot* silently
diverge is a different animal from duplication that can; the test converts the
former into the latter, in the codebase's existing property-testing idiom.

## Slices

Each is independently reviewable, stacked on its predecessor, and passes the full
CI gate set before the next begins.

### Slice 1 — the wire-name codec

New `crates/writ-audit/src/git_push/approve_attempt.rs`: `ApproveAttemptStateName`
and `ApproveAttemptOutcomeName` (the flat discriminants the `state` / `outcome`
columns store) with `as_wire()` / `parse_wire()`, plus `name()` accessors on the
data-carrying `GitPushApproveAttemptState` / `…Outcome`. Every literal in `dao.rs`
and the parser routes through it.

Tests: round-trip property; and a **schema-agreement test** — every name in the
Rust enum is accepted by the column's CHECK constraint, and any string outside
the set is rejected. That pins the Rust enum to the SQL enum.

### Slice 2 — the transition relation as a pure total function

`ApproveAttemptTransition` (the events: `RecordMint`, `MarkUncertain`,
`ResolveSucceeded`, `ResolvePrePatchFailure`, `CapturePrePatchFailure`,
`ResolvePostPatchFailure`) and
`fn apply(&ApproveAttempt, &Transition) -> Result<ApproveAttempt, IllegalApproveTransition>`
— one place enumerating what is legal. The DAO's ad-hoc preflights are replaced
by a parse of the current row plus a call to `apply`;
`allowed_states: &[&'static str]` disappears.

The machine's state is `ApproveAttempt`: the row's position **plus the v7 mint
ledger**. The ledger looks like a side table, but migration 0007 says it exists
only because SQLite could not widen the `state` CHECK to add a `minted` state —
"the ledger records the same fact with a plain CREATE TABLE" — and two triggers
(`mint_matches_ledger`, `resolve_carries_ledger_mint`) judge writes against it.
A machine that could not see it would permit moves the database refuses, which
is exactly what the first draft did: `apply(&Started, MarkUncertain { mint: B })`
returned `Ok` for an attempt whose ledger already recorded A. Modelling the
ledger also lets the machine *derive* the mint a resolve records, so no call site
has to remember to carry it.

Test: the **Rust ≡ SQLite oracle**. For every (position, transition) pair —
positions being row states crossed with ledger presence — build the row by a
legal path in a real in-memory DB, then compare `apply` against a naive writer
that never consults it, asserting both accept the same moves.

### Slice 3 — the derived predicates, in one place

Reading the six sites side by side showed that the one phrase "does this attempt
stand in the way?" hides *three* predicates, so each is named once on
`AttemptPosition` (the `(state, outcome)` pair a row records):
`blocks_resolution`, `is_in_flight`, `is_reconcilable`, plus `reject_blocker` for
the classification. The distinction that matters is that `blocks_resolution`
excludes `Resolved(Succeeded)` — the approve path's own joint transaction writes
the resolution row — while `reject_blocker` includes it.

The SQL stops being a second encoding: `position_predicate_sql` renders a
position set as `(state, coalesce(outcome, '')) IN (VALUES …)`, so the two
queries that spelled the predicate out now build their clause by filtering
`AttemptPosition::all()` through the same function the Rust folds call. The
`Uncertain`-needs-a-boot-observed-marker rule stays in the DAO: it is a fact
about the row, not its position.

Tests: `sql_predicate_selects_what_rust_selects` (the generator renders each
predicate faithfully) and `blocks_resolution_agrees_with_the_trigger` (the
predicate matches the schema's own version — a resolution INSERT is refused iff
it says so).

### Slice 4 — delete the mirrored trigger message

`writ-audit` classifies the trigger's constraint violation into
`AuditError::ResolutionRefusedByActiveApprove`; the shell matches the variant
instead of the string, and `is_active_approve_refusal` is deleted along with the
stale `0005_…` reference. The literal survives in exactly one place, beside the
predicate it enforces, because SQLite gives `RAISE(ABORT, …)` no
machine-readable identity.

The pinning test reads the trigger body back from **`sqlite_master`**, not from
the migration list. That distinction is load-bearing and was found by mutation:
v5 created this trigger and v6 dropped and recreated it, so the old wording is
still in the v5 migration text, and a migration-searching test went on passing
after the live trigger was reworded — the exact failure it exists to catch.

## Outcome

All four slices shipped, each reviewed clean by Codex. Two defects were caught in
review rather than by me, both worth recording because they are the same shape —
a test asserting less than it claimed:

1. The `ALL`-completeness test could not actually prove `ALL` was complete (a new
   variant had to be *named* in the match, but not *listed*). Fixed at the root
   by generating the enum, `ALL`, and both conversion directions from one
   variant⇒literal table, so the list cannot disagree with the variants.
2. `apply` could not see the v7 mint ledger, so it permitted moves
   `mint_matches_ledger` refuses — a soundness violation of the slice's own
   headline property, invisible because the oracle never seeded a ledger row.
   Fixed by making the ledger part of the machine's state, which migration 0007
   argues it always was.

The lesson generalises: for each of these, writing the mutation was what exposed
the gap. A property test that has never been watched to fail is a claim, not
evidence.

## Non-goals

- **No schema change.** The tables and triggers are correct; this plan does not
  touch a `.sql` file except where slice 4's message constant demands it.
- **No behaviour change.** Every slice preserves observable broker behaviour;
  the existing `tests/approve_state_machine.rs` trace property is the regression
  net and must keep passing untouched.
- **No VM-lifecycle work**, for the reasons above.
