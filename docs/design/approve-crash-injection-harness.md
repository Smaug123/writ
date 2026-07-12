# Deterministic crash-injection harness for the approve pipeline

Drafted 2026-07-12, following the round of reviews on the
`unbounded-http-promotion` branch. Companion implementation plan:
`docs/plans/2026-07-12-approve-crash-injection-harness.md`.

## §1 Motivation

Recent review rounds found four defects in the approve pipeline that
share one shape: *the broker dies (or stalls) at a specific point, and
the durable state left behind is wrong or wedges recovery*:

- a crash mid-prepare lost the identity of a minted credential
  (fixed by the v7 mint ledger);
- a crash mid-prepare left a request-keyed staging dir that made every
  retry fail `StagingDirExists` (fixed by attempt-keyed dirs);
- the ledger's mint-follows-attempt invariant held on the production
  resolve path but not across the whole DAO surface (fixed by the
  auto-copy + `resolve_carries_ledger_mint` trigger);
- an awaited filesystem deletion sat between the final lease check and
  the PATCH (fixed by backgrounding it).

None of these were reachable by the existing test strategy. The
audit-DB state machine has a property harness
(`tests/approve_state_machine.rs`), but it models *audit rows only*:
its `Crash` event exercises boot reconcile against the DB and nothing
else. The approve pipeline actually mutates **three durable stores**
— the audit DB, the filesystem (staging repos), and GitHub (uploaded
objects, the branch ref) — and only the first had its crash states
enumerated. The other two were reviewer-dependent.

This harness makes that class mechanical: run the *real*
`approve_staged_push` handler against real (temp) filesystem state,
real `git`, and a stateful fake GitHub; kill it at every point between
durable effects; reboot; reconcile; retry or reject; and assert that
the audit log's claims are true of the fake GitHub and that recovery
always makes progress.

## §2 What "crash" means here

A real crash stops execution without running cleanup. The harness
simulates it by **dropping the handler's future at an await point**:
the handler runs as a plain (unspawned) future inside the test; when
the crash plan's chosen point is reached, the point parks forever and
notifies the harness, which drops the future. Dropping a future at an
await abandons all subsequent code — including `resolve_*` error
handling and staging cleanup — which is exactly the crash semantics we
want, with one caveat:

**Caveat (Drop honesty).** Dropping a future runs `Drop` impls; a real
crash does not. This is sound for the approve pipeline because nothing
on that path performs *semantic* cleanup in `Drop` — `StagingRepo`
deliberately has no `Drop` (documented on the type), and the remaining
drops are memory/zeroize only. This is a standing invariant the
harness relies on: **no type used on the approve path may perform
observable cleanup in `Drop`**. It is stated here and on the crash
module; a reviewer adding a self-cleaning guard type to this path must
extend the harness first.

A second caveat: `tokio::spawn`ed work (the backgrounded staging-dir
deletion) survives a future-drop but not a real crash. Crash points
are therefore placed *before* any spawn so both timelines are
exercised; the spawned work itself is best-effort by design.

SQLite gives us torn-write freedom for the audit store: every DAO
write is a transaction, so "crash mid-write" is indistinguishable from
"crash before the write". Filesystem effects are not atomic; §6
(stretch) covers torn residue.

## §3 Crash points

A tiny module, `crash` (name bikesheddable), exposes:

```rust
/// Await a named crash point. In non-test builds this is an empty
/// inline function. In test builds it consults a tokio task-local
/// `CrashPlan`; in counting mode it increments a counter, in crash
/// mode it parks forever (after notifying the harness) when the
/// running count matches the plan's target index.
pub(crate) async fn point(name: &'static str);
```

- `#[cfg(not(test))]`: empty body. Zero cost, zero behavior change,
  visible at every call site (explicit over implicit — the points are
  in the production source, greppable, self-documenting).
- `#[cfg(test)]`: task-local `Option<Arc<CrashPlan>>`. No plan set →
  no-op, so the entire existing test suite is unaffected.

Call sites bracket every durable effect in the approve path
(`approve_staged_push` / `execute_started_attempt`,
`prepare_staging_repo` / `run_prepare_steps`, `prepare_approve`,
`PreparedApprove::commit`): after the `Started` insert, after the
mint, after `record_attempt_mint`, after each staging-repo step
(mkdir, bundle write, init, fetch, unbundle), after plan/walk uploads,
after `mark_attempt_uncertain`, after the PATCH, after the joint
success TX. The exact list is discovered, not maintained: the harness
first runs one full approve in **counting mode** to learn `N`, then
sweeps `k ∈ 0..N`. Adding a new point later automatically widens the
sweep.

Residual risk: a future durable effect added *without* a crash point
is invisible to the sweep. That is a review convention ("new durable
effect ⇒ new `crash::point`"), recorded here and in the crash module
docs; it cannot be machine-checked without heavier interposition than
this codebase's dependency-rejection style permits.

## §4 The stateful fake GitHub

`wiremock` matchers with **stateful responders** over
`Arc<Mutex<GitHubModel>>` — no new dependencies. The model implements
the six Git Data endpoints the client uses (`POST git/blobs`,
`git/trees`, `git/commits`, `GET git/ref/heads/{branch}`, `GET
repos/{o}/{r}`, `PATCH git/refs/heads/{branch}`) plus the installation
token mint:

- object store keyed by SHA (content hashing may be fake — opaque
  SHAs handed out by the model are fine; the pipeline treats them as
  opaque);
- a refs map with **fast-forward PATCH semantics**: a non-descendant
  update is refused with 422, a descendant (or ancestor-to-descendant)
  update moves the ref — this is what makes the lease-TOCTOU class
  expressible;
- signed commit creates answer with an affirmative `verification`
  block (matching the real contract the mocks previously got wrong);
- a **request log** (method, path, body digest, serial number) so the
  oracle can ask "did the crashed attempt send a PATCH?" — the ground
  truth that classifies pre- vs post-PATCH crashes without trusting
  the audit log under test.

The model is also the fault-injection surface for later work (delayed
responses, 500s, withheld bodies).

## §5 The fake origin

`prepare_staging_repo` runs a real `git fetch <url> <sha>`.
`GitCloneBaseUrl` accepts `http://127.0.0.1:{port}/`, and git's
**dumb HTTP protocol** needs only static file service over a bare
repo: run `git update-server-info` in the origin after each mutation,
serve `info/refs` and `objects/**` verbatim (loose objects — fresh
test repos keep everything loose). Fetch-by-SHA over dumb HTTP walks
objects directly, so no `uploadpack.allowAnySHA1InWant` and no
`http-backend` CGI. If dumb HTTP proves flaky in practice, the
fallback is a ~100-line CGI shim around `git http-backend`; the plan
isolates this behind a helper whose oracle is protocol-independent.

The origin builder also produces the staged **bundle** (real
`git bundle create` of the commits past the prereq), reusing the
`build_real_staging_repo` idioms already in `git_push_approve`'s
tests. Tests skip when `git` is absent, same as today.

## §6 The sweep and its invariants

For each crash index `k` (and for each scenario below), a fresh
world: temp work_root, temp **file-backed** audit DB (in-memory can't
survive "reboot"), fresh fake GitHub + origin with a two-commit chain
staged for push.

1. Drive `ApproveStagedPush` through `dispatch_message` with a plan
   that crashes at point `k`. Drop the future on park.
2. **Reboot**: open a new `AuditLog` over the same DB file; run
   `reconcile_pending_approve_attempts`.
3. Assert the post-reboot invariants:
   - **I-A (recovery totality).** No attempt remains `Started`. A
     recovered attempt with a mint-ledger row is
     `Resolved(PrePatchFailure)` carrying exactly that mint.
   - **I-B (pre-PATCH truth).** If the model's request log shows no
     PATCH from the crashed attempt: the model's branch ref is
     untouched, and the push is recoverable *without publishing*.
     The broker's own knowledge is deliberately weaker than the
     model's ground truth here: a crash between the `Uncertain` TX
     and the PATCH leaves an `Uncertain` row the broker cannot
     distinguish from a sent PATCH, so `reject_blocker_for_push` is
     `None` iff the crashed attempt never reached `Uncertain`; an
     `Uncertain` survivor is quarantined until the operator
     reconciles it `NotApplied` (the verdict the model's unmoved ref
     dictates), after which retry and reject both proceed. In no
     case is recovery refused for an unmodeled reason (in
     particular, never `StagingDirExists`).
   - **I-C (post-PATCH honesty).** If a PATCH was received: the
     attempt is `Uncertain` (now boot-observed) or terminal with
     mint recorded; reject is refused; `classify_reconciliation_target`
     is `Eligible`; and the operator verdict *dictated by the model's
     actual ref* (`Applied` iff the ref moved) lands successfully with
     the resolution mint equal to the ledger mint.
4. **Scenario A (retry to success):** run a second, crash-free
   approve (or the reconciliation from I-C). Assert **I-D**: the push
   ends with exactly one `git_push_resolution(approved)` row, the
   model ref equals the bundle tip, and every ref movement in the
   model's log corresponds to an attempt that did *not* resolve
   `PrePatchFailure`.
5. **Scenario B (reject instead):** where I-B applies, reject after
   reboot and assert it lands; where I-C applies, assert reject is
   refused until reconciliation, then (after `NotApplied` when the
   model shows no ref movement) lands.

Runtime budget: `N` is expected to be ≲ 20; two scenarios × N cases,
each dominated by a handful of subprocess `git` calls on empty-commit
repos — a few seconds total, acceptable in `cargo test`. If it grows,
shard by scenario before reaching for `#[ignore]`.

## §7 Stretch: multi-crash traces and torn residue

- **Double crash:** crash at `k₁`, reboot, retry with a crash at
  `k₂`, reboot, then finish. `N²` is too many with real subprocesses;
  sample `(k₁, k₂)` with proptest at a modest case count. Invariants
  unchanged — that is the point of writing them state-based rather
  than trace-based.
- **Torn residue:** after a crash inside the staging-repo phase,
  additionally corrupt the residue (truncate `staged.bundle`, empty
  the dir) before rebooting. Attempt-keyed dirs should make every
  such mutation invisible to the retry; pin that.

## §8 What this deliberately does not cover

- Concurrency races between live tasks (two simultaneous approves):
  the DAO-level guards have targeted tests; interleaving exploration
  would need a different scheduler-control harness.
- reqwest/transport semantics: pinned by the timeout behavioral tests
  in `github_git_db`.
- The VM/agent side of staging: the harness starts from an
  already-staged push.
