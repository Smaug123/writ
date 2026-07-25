# Promote the approve-attempt state machine to a first-class Rust type

Drafted 2026-07-25. Companion to `../design/approve_state_machine.md` (the
original design) and `../design/architecture.md` §5.5. Sibling of the structural
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

`ApproveAttemptTransition` (the events: `MarkUncertain`, `ResolveSucceeded`,
`ResolvePrePatchFailure`, `ResolvePostPatchFailure`) and
`fn apply(&State, &Transition) -> Result<State, IllegalTransition>` — one place
enumerating what is legal. The DAO's ad-hoc preflights are replaced by a parse of
the current row plus a call to `apply`; `allowed_states: &[&'static str]`
disappears.

Test: the **Rust ≡ SQLite oracle**. For every (state, transition) pair, build a
row in that state in a real in-memory DB, drive the DAO, and assert the write
succeeds iff `apply` returned `Ok`.

### Slice 3 — the derived predicates, in one place

`blocks_resolution()`, `reject_blocker()`, and `reconciliation_eligibility()` as
methods on the state. `reject_blocker_for_push`, `classify_reconciliation_target`,
`start_approve_attempt`'s preflight, and `load_reconciliation_predecessor` all
call them instead of restating the predicate.

Test: for random attempt states, the Rust predicate agrees with the trigger — a
resolution INSERT is refused iff `blocks_resolution()` says so.

### Slice 4 — delete the mirrored trigger message

`writ-audit` classifies the trigger's constraint violation into a typed
`AuditError` variant; the shell matches the variant instead of the string. The
literal then lives in exactly one Rust place, with a test asserting the embedded
migration SQL contains it. The stale `0005_…` doc reference goes with it.

## Non-goals

- **No schema change.** The tables and triggers are correct; this plan does not
  touch a `.sql` file except where slice 4's message constant demands it.
- **No behaviour change.** Every slice preserves observable broker behaviour;
  the existing `tests/approve_state_machine.rs` trace property is the regression
  net and must keep passing untouched.
- **No VM-lifecycle work**, for the reasons above.
