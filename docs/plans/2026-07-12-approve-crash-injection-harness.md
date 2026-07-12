# Plan — approve crash-injection harness

Drafted 2026-07-12. Implements
`docs/design/approve-crash-injection-harness.md` (referenced below as
DESIGN). Read that first; it fixes the crash semantics (future-drop),
the Drop-honesty invariant, and the sweep invariants I-A…I-D.

Implement this plan with each stage on its own branch, stacked as
necessary on previous branches, so that a reviewer can review each
branch in isolation.

General notes:

- Everything test-facing lives under `#[cfg(test)]` (the harness
  drives the private `dispatch_message` seam, so it sits in
  `src/server/` test modules; shared pieces go in existing
  `test_support` homes). No cargo feature, no release-build impact.
- Every stage must leave all five CI gates green (`fmt`, `clippy
  --all-targets --all-features -D warnings`, `cargo test`, `cargo doc
  -D warnings`, nix build).
- Stages 1, 2 and 3 are mutually independent and can be built in
  parallel.

---

## Stage 1: crash-point primitive

**Dependencies**: none.

**Implements**: DESIGN §2, §3.

New module `src/crash_point.rs` (compiled always; body differs by
`cfg(test)`):

- `pub(crate) async fn point(name: &'static str)` — empty inline
  no-op in non-test builds; in test builds consults a tokio
  task-local `Option<Arc<CrashPlan>>`.
- `CrashPlan` (test-only): `Count(AtomicUsize)` mode records every
  point passed (and its name, for diagnostics); `CrashAt { index,
  parked_tx }` mode notifies `parked_tx` and awaits
  `std::future::pending()` when the running count hits `index`.
- Harness helper `run_until_crash(plan, fut)`: polls `fut` against
  the parked notification via `select!`; on notification drops `fut`
  and reports `Crashed { at_index, at_name }`; otherwise returns the
  future's output.
- Module docs carry the two caveats from DESIGN §2 verbatim (Drop
  honesty; spawn survival) and the review convention "new durable
  effect ⇒ new `crash::point`".

No production call sites yet (that is Stage 4), so this stage is pure
infrastructure.

**Correctness oracle** (unit tests in the module):

- A toy async fn with three named points, run in counting mode,
  reports exactly 3 with the right names in order.
- For each `k ∈ 0..3`, `run_until_crash` on the toy fn stops at point
  `k`: side effects before `k` observed, side effects after `k`
  absent, and the reported name matches.
- With no plan installed, the toy fn runs to completion (the no-op
  guarantee the rest of the suite relies on).

---

## Stage 2: stateful fake GitHub

**Dependencies**: none.

**Implements**: DESIGN §4.

`GitHubModel` behind `Arc<Mutex<_>>`, mounted on a `wiremock`
`MockServer` via stateful `Respond` impls (no new dependencies):

- object store (opaque model-issued SHAs), refs map, request log
  (serial, method, path);
- `POST git/blobs|trees|commits` insert and return SHAs; signed
  commit creates return an affirmative `verification` block;
- `GET git/ref/heads/{branch}`, `GET repos/{o}/{r}` read the model;
- `PATCH git/refs/heads/{branch}` applies fast-forward semantics:
  moves the ref iff the new SHA descends from the current tip in the
  model's commit graph, else 422 with GitHub's "not a fast forward"
  shape;
- the installation-token endpoint (reuse the JSON shape from
  `staged_push_approve_tests`);
- test-side handles: `set_ref`, `ref_of`, `patch_requests()`,
  `ref_history()`.

Home: a new `src/server/test_support` module (or sibling file) so both
the harness and future handler tests can use it.

**Correctness oracle** (unit tests):

- upload blob→tree→commit→PATCH advances the ref; `ref_history()`
  records exactly one move.
- PATCH to a non-descendant returns 422 and the ref does not move.
- a signed commit create carries `verification.verified == true`;
  `create_commit` (the real client) accepts it end-to-end against the
  mock server.
- request log serials strictly increase and classify PATCHes
  correctly.

---

## Stage 3: fake origin + staged-push fixture

**Dependencies**: none.

**Implements**: DESIGN §5.

- `FakeOrigin`: builds a bare repo with a deterministic two-commit
  chain (reusing the `run_git`/pinned-identity idioms from
  `git_push_approve` tests), runs `git update-server-info`, and
  serves the repo over dumb HTTP from a local listener (static GETs
  of `info/refs` and `objects/**`; hyper is already a dependency).
  Exposes `base_url() -> GitCloneBaseUrl`-compatible string, the
  prereq SHA, the tip SHA, and `bundle_bytes()` (real
  `git bundle create` of tip-past-prereq).
- Skips when `git` is absent, matching `maybe_git()` precedent.
- If dumb HTTP turns out not to satisfy `git fetch <url> <sha>` on
  some git version, swap the serving strategy for a `git
  http-backend` CGI shim *behind the same helper API* — the oracle
  below is deliberately protocol-independent.

**Correctness oracle** (integration-style unit test, real git):

- `prepare_staging_repo` — the real production function — succeeds
  against `FakeOrigin`: staging repo contains both the prereq (via
  the HTTP fetch) and the bundle tip (via unbundle). This is new
  coverage by itself: the prepare fetch path currently has no test
  that exercises a successful fetch.

---

## Stage 4: crash points in the approve path + happy-path pipeline test

**Dependencies**: Stages 1, 2, 3.

**Implements**: DESIGN §3 (call sites); DESIGN §6 step 1 without the
crash.

- Sprinkle `crash_point::point("...")` between every durable effect
  listed in DESIGN §3, in `execute_started_attempt`,
  `prepare_staging_repo`/`run_prepare_steps`, `prepare_approve`, and
  around `PreparedApprove::commit`. Points go *before* any
  `tokio::spawn` per the spawn caveat.
- New test fixture `approve_world()`: temp work_root, **file-backed**
  audit DB in a tempdir, `FakeOrigin`, `GitHubModel` server, real
  `git` in `PromoteRuntimeConfig`, staged push whose receipt matches
  the origin (prereq = origin tip, bundle = fixture bundle).
- First full-pipeline test: `ApproveStagedPush` through
  `dispatch_message` with **no crash plan** succeeds end-to-end —
  also new coverage (today's handler tests stop at the bogus-git
  failure).

**Correctness oracle**:

- The happy-path test: reply is the approved message; model ref ==
  bundle tip; audit shows `Resolved(Succeeded)` with resolution mint
  == ledger mint; staging dir eventually removed.
- A counting-mode run of the same approve reports a stable `N` (≈ the
  DESIGN §3 list; assert `N >= 12` rather than an exact constant so
  adding points is not a test-breaking event).
- Entire existing suite still green (points are no-ops without a
  plan).

---

## Stage 5: the single-crash sweep

**Dependencies**: Stage 4.

**Implements**: DESIGN §6 (all invariants).

One test per scenario, each looping `k ∈ 0..N` (N from a counting
pre-run) with a fresh `approve_world()` per `k`:

- crash at `k` (drop the handler future), reboot (new `AuditLog` over
  the same file), `reconcile_pending_approve_attempts`;
- assert I-A (recovery totality; recovered minted attempts carry the
  ledger mint);
- classify pre- vs post-PATCH from the **model's request log**, then
  assert I-B or I-C accordingly;
- Scenario A: drive retry/reconciliation to final success; assert
  I-D (single resolution row, model ref == bundle tip, every model
  ref move maps to a non-`PrePatchFailure` attempt).
- Scenario B: drive reject; assert it lands where I-B applies and is
  refused-until-reconciled where I-C applies.

**Correctness oracle**: the sweep itself — plus two meta-checks:

- the sweep observes at least one pre-PATCH and at least one
  post-PATCH crash index (guards against the classifier silently
  degenerating);
- a "no-crash" control iteration through the same loop body ends in
  the same final state as Stage 4's happy-path test.

Retro-validation (manual, in the PR description, not CI): revert the
attempt-keyed-staging-dir commit locally and confirm the sweep fails
at the staging-dir indices; revert the ledger auto-copy and confirm
I-A fails. This demonstrates the harness would have caught both
review findings mechanically.

---

## Stage 6 (stretch): double-crash sampling and torn residue

**Dependencies**: Stage 5.

**Implements**: DESIGN §7.

- proptest over `(k₁, k₂)` (crash, reboot, retry-with-crash, reboot,
  finish), modest case count (~32) to respect the subprocess budget;
  same invariants, asserted after each reboot.
- torn-residue mutations after staging-phase crashes (truncate
  `staged.bundle`, empty the dir) before reboot; assert the retry is
  unaffected.

**Correctness oracle**: the property runs green; a saved-regression
seed corpus starts empty (`proptest-regressions/` as usual).

---

## Stage 7 (stretch): rival-actor sweep

**Dependencies**: Stage 5.

**Implements**: extends DESIGN §6 beyond crashes. Motivated by the
final-lease-recheck finding (a branch rewound between the post-walk
check and the PATCH published against an unapproved baseline): that
bug was a *concurrent actor* race, not a crash, so the crash sweep
alone would not have found it. The same point instrumentation can:
instead of parking at point `k`, the plan performs an injected action
— rewind the fake GitHub's branch to the prereq's parent (or advance
it to a foreign commit) — and lets the handler continue.

For each `k` and each rival action, assert: the approve either
succeeds having published *from the approved baseline* (the model's
ref history shows no publish on top of a foreign/rewound tip) or
resolves as a failure that leaves the model's ref exactly where the
rival put it. A publish whose parent chain does not include
`expected_remote_head` at the recorded position is the failure this
stage exists to catch.

**Correctness oracle**: the sweep runs green; retro-validation
(manual, in the PR description): revert the `FinalLease*` recheck in
`commit_prepared_promotion` and confirm the rewind action at the
post-prepare indices turns the sweep red.
