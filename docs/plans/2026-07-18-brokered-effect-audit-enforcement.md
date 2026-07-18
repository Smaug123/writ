# Design + plan — make brokered effects "complete by construction"

Drafted 2026-07-18. Addresses the review finding that the broker's central
promise — *the only way to act is to obtain a grant, so the audit log is
complete by construction* — is today enforced by **discipline**, not by the
type system. Each effect handler independently remembers to write its
audit pair; nothing stops the next capability (PR creation, comment posting,
which orchestration will need) from performing an effect without an audit row.

This is a **new PR series off `main`**, to start after the current
`rename/git-push-replay-modules` branch squashes. It does not append to that
branch.

Scope (chosen 2026-07-18): the ~7 `vm_http` effects plus the DAO-level
deduplication. The host-side capability mint (`server.rs::request_capability`)
and `git_push`'s host-side approval/reconciliation state machine are
**deferred** — see [§7](#7-deliberately-out-of-scope). Mechanism: a sealed,
`#[must_use]` audit-pair guard plus a single generic driver behind a
`BrokeredEffect` trait (not a monolithic DU interpreter — see
[§3.4](#34-why-a-trait-driver-and-not-one-du-interpreter)).

---

## 1. The invariant at stake

The reviewer names two problems that are worth keeping separate, because they
live at different layers and carry different risk.

**Problem A — DAO-level repetition (storage layer).** The session-open guard
```rust
match session_closed_at {
    None            => Err(Invariant("session does not exist")),
    Some(Some(_))   => Err(Invariant("session is closed")),
    Some(None)      => Ok(()),
}
```
is copy-pasted **five times** (`agent_run.rs:85`, `agent_run.rs:148`,
`flake_provision.rs:111`, `grant.rs:88`, `git_push/dao.rs:25`) despite
`proxy_table::check_session_open` (`proxy_table.rs:142`) already factoring it
out. The two-phase *request-row → outcome-row* skeleton (a `*_request` table
gated on open-session plus an append-after `*_outcome` table FK'd to it, with a
`LEFT JOIN … list_*_for_session` reader) is re-hand-rolled in `flake_provision`
and in `git_push`'s base pair; `flake_provision.rs`'s own module doc notes the
parallel while declining to share it. This is bounded boilerplate, low risk.

**Problem B — the load-bearing invariant (orchestration layer).** *Nothing in
the type system forces a handler that performs an effect to record the audit
pair.* The sequence — resolve authority → decide policy → record request row →
perform effect → record outcome row → map response — is hand-wired at ~7 sites,
and each new capability is a fresh chance to forget. Per the VM-layer review, a
new capability today touches ~6 edit sites: dispatcher routing
(`route_authenticated_vm_http_request`), `VmHttpServices`, auth-scheme selection
(`auth_scheme_for_target`), body-limit selection (`route_request_body_limit`),
the audit DAO, and config.

Problem B is the reviewer's central point and the one this plan is built around.
Problem A is a supporting cleanup that also happens to be the natural
foundation for B (the guard in B is a generalization of the DAO skeleton in A).

---

## 2. Current state — what is already right

The fix is **less invention than hoisting**: two of the three pieces already
exist in miniature.

- **`proxy_table.rs` is the DAO skeleton, already generic** over three backends
  (`claude_proxy`, `openai_proxy`, `nix_cache`). It holds one copy of the
  request/outcome SQL, the field validation, `check_session_open`, and *both* a
  two-phase writer and a coalesced single-commit writer
  (`record_proxy_request_and_outcome`, for the authority-free nix-cache serve).
  The per-backend files are ~50-line shims: a zero-sized table marker, a route
  enum, re-exported record types. **This is proof the pattern generalizes.**

- **`proxy_common::route_proxy_request` is the driver the reviewer wants**,
  already, but only for the two proxies (`proxy_common.rs:935`). It owns the
  record→fetch→record sequence; the `ProxyBackend` trait supplies only the
  per-backend bits (route classification, header allowlist, upstream URL, auth
  resolution, audit-record shape); and — critically — the upstream credential is
  reached *only* inside the driver via `B::resolve_upstream_auth`. A backend
  impl cannot skip the audit rows, because the driver, not the impl, calls them.

- **`grant.rs` is the two-phase substrate for the host mint**, with the pair
  ordering enforced by DB FKs + mutual-exclusion triggers
  (`grant_excludes_mint_failure`) and the unforgeable `AuthorizedMint`
  (`policy.rs:52`) making "mint without a decision" a compile error. But its
  *orchestration* is hand-wired inline in `request_capability`
  (`server.rs:462`), and diverges again in the promote-mint path — evidence that
  the skeleton is a per-site convention, not a shared abstraction.

### 2.1 The divergence surface (why one monolith won't do)

The seven effects genuinely differ along three axes. Any honest design must
absorb this variation rather than pretend it away.

| Effect | Authority | Policy | Audit durability | Effect shape |
|---|---|---|---|---|
| git_clone | **mints** GH token (`request_capability`) | genuine (`policy::decide`) | two-phase (delegated) | git subprocess, buffered bundle |
| git_push (VM stage) | none | always-allow | **explicit two-phase** | fs staging (fsync+rename) |
| flake_provision | none (re-derive from mirror) | **grant re-check** (`session_holds_grant_authorising`) | two-phase (delegated) | `nix flake archive` |
| agent_runs (outcome) | none (ownership match) | ownership + idempotency | **outcome-row only** (request row at launch) | fs write of logs |
| claude_proxy | host key from store | always-allow | two-phase **or** coalesced | upstream HTTP, buffered **or streaming** |
| openai_proxy | host key / OAuth | always-allow | two-phase | upstream HTTP, buffered/streaming |
| nix_cache | none (serve grants nothing) | always-allow | **coalesced single-commit** | local fs + upstream HTTP, streaming |

Authority is a spectrum (mint fresh → reuse recorded grant → match ownership →
nothing); durability tracks it (the more authority conferred, the stronger the
request-row-before-effect insistence); and effect shape ranges from a synchronous
map removal to a streaming upstream body whose outcome row is written from a
`Drop` impl after the response head is already committed
(`proxy_common.rs:583`). The design must make *the audit pair* uniform while
leaving *these three axes* as declared parameters.

---

## 3. The design

Three layers, bottom-up. Each is independently landable and independently
testable; the invariant becomes airtight only when all three are in place, but
each earns its keep before then.

### 3.1 Layer 1 — the sealed, must-use audit-pair guard (`writ-audit`)

Generalize `proxy_table` from "three structurally-identical proxy tables" to
"any effect table that is a `(request, outcome)` pair," and expose the pair
**only** through a linear guard.

```rust
// writ-audit — extends the existing ProxyAuditTable descriptor.
pub trait EffectAuditTable: 'static {
    type RequestRow<'a>;
    type OutcomeRow<'a>;
    const REQUEST_TABLE: &'static str;   // compile-time const; never runtime input (SQLi note preserved)
    const OUTCOME_TABLE: &'static str;
    const LABEL: &'static str;
    fn insert_request(conn: &Connection, row: &Self::RequestRow<'_>) -> Result<(), AuditError>;
    fn insert_outcome(conn: &Connection, row: &Self::OutcomeRow<'_>) -> Result<(), AuditError>;
    /// What an effect that never completed looks like in the log. Lets the
    /// guard's Drop backstop record a truthful "unattempted" outcome, and forces
    /// each effect to *define* its incomplete-state row.
    fn dropped_outcome(request_id: RequestId) -> Self::OutcomeRow<'static>;
}

/// The ONLY way to obtain one is `AuditLog::begin_effect`, which writes the
/// request row (session-open-checked, in its own committed transaction — the
/// two-phase durability point). The ONLY ordinary way to discharge it is
/// `complete`. Dropping it without `complete` is a programming error.
#[must_use = "a begun effect must be completed with an outcome row, or it is unaudited"]
pub struct RecordedRequest<T: EffectAuditTable> {
    request_id: RequestId,
    audit: Arc<AuditLog>,
    /// Set when an outcome write is *attempted* (see `complete`), not when it
    /// succeeds — so a failed outcome write is surfaced to the caller rather
    /// than re-recorded by `Drop` as a dropped/unattempted effect.
    discharged: bool,
    _table: PhantomData<fn() -> T>,
}

impl AuditLog {
    pub fn begin_effect<T: EffectAuditTable>(
        self: &Arc<Self>,
        row: &T::RequestRow<'_>,
    ) -> Result<RecordedRequest<T>, AuditError> { /* check_session_open + insert_request, commit */ }

    /// Coalesced single-commit form for authority-free reads (nix-cache serve).
    /// Same as begin+complete but one fsync; refuses a mid-fetch session close.
    pub fn record_effect_coalesced<T: EffectAuditTable>(
        &self, request: &T::RequestRow<'_>, outcome: &T::OutcomeRow<'_>,
    ) -> Result<(), AuditError> { /* one transaction */ }
}

impl<T: EffectAuditTable> RecordedRequest<T> {
    pub fn request_id(&self) -> RequestId { self.request_id }
    pub fn complete(mut self, outcome: &T::OutcomeRow<'_>) -> Result<(), AuditError> {
        // Discharge BEFORE the write. An outcome write was attempted, so this is
        // no longer an un-audited effect: if the write *fails*, the error is
        // returned to the driver (which 500s + emits AUDIT_WRITE_FAILURE), but it
        // must NOT also trip the Drop backstop, which would relabel an effect
        // that already ran as "unattempted".
        self.discharged = true;
        self.audit.record_outcome::<T>(outcome)
    }
}

impl<T: EffectAuditTable> Drop for RecordedRequest<T> {
    fn drop(&mut self) {
        if self.discharged { return; }   // completed, or a completion write was attempted
        // Fail fast in tests; fail visibly in prod. Never silently swallow.
        debug_assert!(false, "RecordedRequest<{}> dropped without complete()", T::LABEL);
        let _ = self.audit.record_outcome::<T>(&T::dropped_outcome(self.request_id))
            .inspect_err(|e| tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET, kind = "effect_outcome_dropped",
                request_id = %self.request_id, error = %e, "audit outcome dropped"));
    }
}
```

Why this shape:

- **Make illegal states unrepresentable.** "Request row without a decision to
  write an outcome" is now unconstructable outside `begin_effect`; "outcome row
  without a prior request row" is unconstructable because `record_outcome` is
  `pub(crate)`, reachable only through `RecordedRequest::complete` (and the
  coalesced writer, which writes both). The public surface is `begin_effect`,
  `complete`, and `record_effect_coalesced` — three operations, and every one of
  them writes *both halves or refuses*.
- **Drop is the backstop, not the mechanism.** Every begun guard is discharged
  by `complete` (buffered) or by being moved into a streaming body (see §3.2).
  Drop-*without-discharge* is a *bug*, and it fails loudly: `debug_assert` blows
  up every test that hits it, and prod emits `AUDIT_WRITE_FAILURE`.
  (`ProxyStreamBody::drop` already sets the precedent for a synchronous outcome
  write from Drop; `proxy_common.rs:583`.) A completion write that is *attempted
  and fails* is not a drop: `complete` marks the guard discharged before the
  write, so the failure surfaces as the driver's 500 + `AUDIT_WRITE_FAILURE`
  once, never as a second "unattempted" row.
- **Durability stays a first-class choice**, not an accident: two-phase is
  `begin_effect` + `complete`; coalesced is `record_effect_coalesced`. Nothing
  else. `agent_runs`' outcome-only shape is expressed as a `RecordedRequest`
  begun at *run launch* and completed at the outcome endpoint — the guard can be
  threaded through the run's lifetime (stored, not held on the stack), which is
  strictly better than today's "request row written elsewhere, hope the outcome
  follows."

This layer subsumes Problem A: `check_session_open` has one home; the
per-effect DAOs collapse to an `EffectAuditTable` impl (the marker + the two
`insert_*` column serializers + `dropped_outcome`), exactly as the proxy shims
already are.

### 3.2 Layer 2 — the `BrokeredEffect` trait + single driver (`vm_http`)

Hoist `route_proxy_request` into one driver over all HTTP effects. The trait
carries the three axes of variation from [§2.1](#21-the-divergence-surface-why-one-monolith-wont-do) as declared associated
items; the driver owns the sequence.

```rust
pub(in crate::vm_http) trait BrokeredEffect: Sized + 'static {
    type Table: EffectAuditTable;   // which (request, outcome) pair this effect audits
    type Authority;                 // resolved credential/handle — minted token, host key, () for authority-free
    type Request;                   // parsed guest request (parse-don't-validate already happened)

    /// `TwoPhase` (grants authority: request row durable before the effect) or
    /// `Coalesced` (authority-free read: request+outcome in one commit). Selects
    /// which driver path and which `perform` below apply — this is what keeps the
    /// nix-cache serve on its single-fsync commit rather than regressing it to two.
    const DURABILITY: Durability;

    // --- routing/transport, folded in from the three scattered switch sites ---
    fn matches(target: &str, method: &str) -> bool;
    fn auth_scheme() -> VmHttpAuthScheme;              // Bearer | Basic
    fn body_limit(&self) -> Option<usize>;             // None = does not read body

    // --- policy: DU-inspected, never a pluggable "decide()" object ---
    fn decide(&self, session: &VmHttpSession, req: &Self::Request) -> EffectDecision;

    // --- the ONLY credential handoff: driver calls this, impls never touch the store ---
    async fn resolve_authority(&self, session: &VmHttpSession, req: &Self::Request)
        -> Result<Self::Authority, VmHttpResponse>;

    // --- the audit request row (pure) ---
    fn request_row<'a>(&'a self, ctx: &'a EffectCtx, req: &'a Self::Request, d: &'a EffectDecision)
        -> <Self::Table as EffectAuditTable>::RequestRow<'a>;

    // --- the effect. Receives the resolved authority, NOT the broker state. One
    //     of the two below is implemented, per DURABILITY (in Rust: two sub-traits
    //     over a shared meta trait; elided here for readability).

    /// TwoPhase. Receives the ALREADY-BEGUN guard and MUST discharge it:
    ///   - buffered  → `recorded.complete(&outcome_row)`, then build the response;
    ///   - streaming → move `recorded` into the `ProxyStream` body, which
    ///                 completes on Drop once the byte count / error is known
    ///                 (today's `ProxyStreamAudit`).
    /// Completion lives here, not in the driver, precisely because a streaming
    /// outcome is unknown until the body drains. The guard's `#[must_use]` +
    /// Drop-bomb force the discharge; the driver guarantees begin-before-perform.
    async fn perform(&self, authority: Self::Authority, req: Self::Request,
                     recorded: RecordedRequest<Self::Table>) -> VmHttpDispatch;

    /// Coalesced (authority-free reads only). No pre-begun guard: returns the
    /// request+outcome rows so the driver writes BOTH in one commit via
    /// `record_effect_coalesced`, preserving the nix-cache single-fsync path.
    async fn perform_coalesced<'a>(
        &'a self, authority: Self::Authority, req: Self::Request, ctx: &'a EffectCtx,
    ) -> (
        <Self::Table as EffectAuditTable>::RequestRow<'a>,
        <Self::Table as EffectAuditTable>::OutcomeRow<'a>,
        VmHttpDispatch,
    );
}

pub(in crate::vm_http) async fn broker_effect<E: BrokeredEffect>(
    audit: &Arc<AuditLog>, session: &VmHttpSession, request: &VmHttpRequest,
    body: Vec<u8>, effect: E,
) -> VmHttpDispatch {
    let parsed = /* E parses body/target into E::Request, or 400 */;
    match effect.decide(session, &parsed) {
        EffectDecision::Deny { reason, status } => return record_denied::<E>(audit, session, request, reason, status),
        EffectDecision::Allow => {}
    }
    let authority = match effect.resolve_authority(session, &parsed).await {
        Ok(a) => a, Err(resp) => return resp.into(),
    };
    match E::DURABILITY {
        Durability::TwoPhase => {
            // Request row durable BEFORE the effect; on failure the effect never runs.
            let recorded = match audit.begin_effect::<E::Table>(
                &effect.request_row(&ctx, &parsed, &decision),
            ) {
                Ok(r) => r, Err(e) => return audit_write_500(e),
            };
            // `perform` is unreachable without a live `recorded`, and MUST discharge
            // it (complete, or move into a streaming body). The guard forces the
            // pair; the driver forces begin-before-perform.
            effect.perform(authority, parsed, recorded).await
        }
        Durability::Coalesced => {
            // Authority-free read: refuse a closed/unknown session up front (no
            // commit — fail-closed, exactly as nix-cache does today)...
            if let Err(e) = audit.require_session_open(session.session_id()) {
                return audit_write_500(e);
            }
            // ...run the effect, then write request+outcome in ONE commit (one fsync).
            let (req_row, out_row, response) =
                effect.perform_coalesced(authority, parsed, &ctx).await;
            if let Err(e) = audit.record_effect_coalesced::<E::Table>(&req_row, &out_row) {
                return audit_write_500(e);
            }
            response
        }
    }
}
```

The type-level force is the same one `route_proxy_request` already relies on and
the reviewer asked for: **`perform` is unreachable except through `broker_effect`,
which has already begun the audit pair, and cannot return without discharging the
guard.** `perform`'s signature hands it `Self::Authority`, never `&BrokerState` —
so an impl cannot reach the secret store *through its arguments*. The two
durability paths are what let this one driver **preserve** today's semantics
rather than regress them: the two-phase path threads the `RecordedRequest` into a
`ProxyStream` body so a streaming outcome is still recorded from `Drop` once the
byte count is known (today's `ProxyStreamAudit`), and the coalesced path keeps the
authority-free nix-cache serve on its single post-fetch commit (Finding from the
Codex review of PR #325: a fixed always-two-phase driver would have both lost the
deferred streaming outcome and doubled the cache-serve fsync).

### 3.3 Layer 3 — the effect registry (the "complete by construction" capstone)

Today three functions switch on the same target string in three places:
`auth_scheme_for_target` (`mod.rs:953`), `route_request_body_limit`
(`mod.rs:1304`), and the `route_authenticated_vm_http_request` if/else
(`mod.rs:1350`). Collapse them into one registry the dispatcher iterates:

```rust
// The dispatcher can do exactly ONE thing with a matched route: hand it to broker_effect.
async fn dispatch(services: &VmHttpServices<S>, session, request, body) -> VmHttpDispatch {
    for entry in services.effects() {          // Vec<Box<dyn ErasedEffect>>, or a match that only calls broker_effect
        if entry.matches(&request.target, &request.method) {
            return entry.run(audit, session, request, body).await;  // == broker_effect::<E>(…)
        }
    }
    route_session_endpoint(session, request).into()
}
```

`auth_scheme_for_target` and `route_request_body_limit` read `entry.auth_scheme()`
/ `entry.body_limit()` from the *same* matched entry, so the three switch sites
become one. **A new capability is now one `BrokeredEffect` impl + one registry
row** — not six edit sites — and, decisively, *there is no code path from the
dispatcher to an effect's IO that does not pass through `broker_effect`*. That is
the step that turns "complete by discipline" into "complete by construction" at
the routing boundary.

Within-crate sealing is a boundary-discipline lever, not an airtight compiler
guarantee: the effect impls and `BrokerState` live in the same crate, so Rust
visibility can't fully forbid an impl from importing the store. We raise the cost
structurally — put the impls in a `vm_http::effects` submodule whose `perform`
signature never receives the store, and keep `AuditLog::record_outcome` and the
raw secret accessors `pub(crate)`/`pub(in vm_http)` so an impl that tries to
bypass the guard has to visibly reach across a module boundary. The *audit-pair*
invariant, which is the one that matters, **is** made airtight by the guard + the
driver owning the sequence + the enumeration test in [§4](#4-the-correctness-oracle).

### 3.4 Why a trait-driver and not one DU interpreter

The review comment's literal phrasing ("make a brokered effect a value … one
execution function") reads as a discriminated union `BrokeredEffect {
GitClone{…}, ClaudeProxy{…}, … }` with a single `execute()` that matches each
variant. We deliberately do **not** do that, and it's worth recording why,
because the codebase's stated invariant is "interpreter, not traits."

That invariant is about **policy**: `policy::decide` inspects request *data* and
must stay a `match`, never a `Backend::mint()` — and this design keeps it that
way (`EffectDecision` is DU-inspected in `decide`). But effect **execution** is
the imperative shell touching genuinely heterogeneous IO: a `reqwest` client with
a streaming body, a git subprocess, an `fsync`+rename, a `nix` realisation. A DU
would have to carry all of those as variant payloads, and `execute()`'s match
arms would each *be* the old handler body — the single function would be the
seven handlers concatenated under one `match`, centralizing the sequence but not
the divergence. The trait keeps each effect's IO in its own file behind a uniform
sequence, which is exactly what `proxy_common`'s accepted `ProxyBackend` already
does. So: DU for the *decision*, sealed trait for the *effect*. (Chosen
2026-07-18.)

---

## 4. The correctness oracle

The gospel's demand — *leverage compute; make the machine enforce the invariant*
— gives us the single most valuable artifact here, and it is what would have
caught "forgot to audit":

> **A property test that enumerates every registered `BrokeredEffect`, drives it
> through `broker_effect` on both the success and the failure path (with a fake
> `Authority` and a fake effect body), and asserts the audit log ends with
> exactly one request row and exactly one outcome row for that effect.**

Because effects are registry entries, this test *automatically covers every
future capability* — you cannot add an effect that escapes the invariant check
without also registering it, at which point the test drives it. This is the
executable proof of "complete by construction." It arrives in two steps: the
reusable **oracle primitive** and its RED proof land **first** (Stage 0,
`AuditLog::assert_effect_audit_pairs_complete`), wired through the current
handlers that are cheaply drivable; it *graduates* to the registry-enumeration
form above — drive *every* registered effect through `broker_effect` — once the
driver and registry exist (Stages 4 and 6), at which point new capabilities are
covered by construction. Until then each ported effect adds its own drive to the
primitive, so coverage grows monotonically rather than being front-loaded.

Supporting oracles:
- **Byte-for-byte DAO equivalence** (proptest), the pattern already used by
  `request_and_outcome_matches_the_two_phase_writers` (`proxy_table.rs:1024`):
  each ported DAO writes rows identical to the hand-rolled one it replaces.
- **Drop backstop** test: a `RecordedRequest` dropped without `complete` panics
  under `debug_assert` and emits `AUDIT_WRITE_FAILURE`.
- **Registry totality**: a test asserting every `Endpoint map` route in the
  architecture doc resolves to exactly one registry entry (no route reachable
  outside the driver).

---

## 5. Implementation plan

> Implement this plan with each stage on its own branch, stacked as necessary on
> previous branches, so that a reviewer can review each branch in isolation.

Each stage is behaviour-preserving on its own; the invariant tightens
monotonically. Stages 1 and 2 are pure Problem-A cleanup and can land (and be
reviewed) independently of the rest.

### Stage 0 — the audit-pair oracle, RED first

**Dependencies**: none. **Implements**: [§4](#4-the-correctness-oracle).

Build the reusable oracle *primitive* —
`AuditLog::assert_effect_audit_pairs_complete(request_table, outcome_table, join_column)`
(test-support only, zero production code) — which asserts that no `*_request`
row lacks its `*_outcome` partner. It is table-name based, so one primitive
covers every effect regardless of column shape; the only per-effect parameter is
the join key (`request_id` / `push_request_id` / `run_id`). Prove it RED on an
un-audited effect — a request row with no outcome makes the assertion panic, kept
as a permanent `#[should_panic]` guard — and wire the current handlers that are
cheaply drivable with existing fixtures through it: git-push (fs staging), the
Claude and OpenAI proxies (buffered upstream), nix-cache (coalesced serve), and
agent-runs (outcome endpoint), each on its own success path plus a
representative failure. The two heavy-IO handlers are deferred to their Stage-5
ports, where the fixture that drives their real IO already exists: git-clone
(spawns `git`; and it audits via the host `request`/`grant_log` grant tables,
whose pairing is a decision-dependent three-way — grant *or* mint-failure *or* a
legitimate deny with neither — not a simple `(request, outcome)`), and
flake-provision (spawns `nix flake archive`).

**Oracle**: GREEN across the five wired current handlers, provably RED
(`#[should_panic]`) on an un-audited effect. This is the testing infrastructure
every later stage consumes; each ported effect (Stages 4–5) adds its drive to the
same oracle, so coverage reaches all seven — and, once the registry lands
(Stage 6), every future capability — by construction.

### Stage 1 — one session-open guard

**Dependencies**: none. **Implements**: [§1](#1-the-invariant-at-stake) Problem A (guard dedup).

Replace the five hand-copied `check_session_open` blocks with the shared
`proxy_table::check_session_open`, hoisted to a `writ-audit` `session`/`validation`
helper. No behaviour change. **Oracle**: existing per-DAO tests pass unchanged;
a proptest that the shared check and each removed copy agree on
{open, closed, missing} sessions.

### Stage 2 — generic two-phase DAO carrying an effect payload

**Dependencies**: Stage 1. **Implements**: [§3.1](#31-layer-1--the-sealed-must-use-audit-pair-guard-writ-audit) (DAO side, sans guard).

Introduce `EffectAuditTable` and port `flake_provision` and `git_push`'s **base**
request/outcome pair onto the generic writer/reader (columns stay bespoke via
`insert_request`/`insert_outcome`; the skeleton is shared). Do **not** touch
`git_push`'s approval-attempt ledger. **Oracle**: byte-for-byte-equivalence
proptest (per [§4](#4-the-correctness-oracle)) that each ported table writes rows identical to the
hand-rolled version; all `writ-audit` tests pass.

### Stage 3 — the `RecordedRequest` guard

**Dependencies**: Stage 2. **Implements**: [§3.1](#31-layer-1--the-sealed-must-use-audit-pair-guard-writ-audit) (guard).

Add `begin_effect` / `RecordedRequest` / `complete` / `record_effect_coalesced`
and the Drop backstop; re-express the existing `proxy_table` two-phase and
coalesced writers *in terms of the guard* (so proxies/nix-cache exercise it
immediately). **Oracle**: the existing proxy roundtrip + coalesced-equivalence
proptests pass through the guard unchanged; a new test that Drop-without-complete
`debug_assert`-panics and emits `AUDIT_WRITE_FAILURE`.

### Stage 4 — the driver, consumed by the already-trait-shaped effects

**Dependencies**: Stage 3. **Implements**: [§3.2](#32-layer-2--the-brokeredeffect-trait--single-driver-vm_http).

Add `BrokeredEffect` + `broker_effect`, and port the two proxies + nix-cache
(which are already `ProxyBackend`-shaped, so lowest risk) onto it. Retire
`route_proxy_request` in favour of `broker_effect`. **Oracle**: all existing
`vm_http` proxy/nix-cache tests pass; the Stage-0 harness now drives these three
through `broker_effect` and stays GREEN.

### Stage 5 — port the hand-wired handlers

**Dependencies**: Stage 4. **Implements**: [§3.2](#32-layer-2--the-brokeredeffect-trait--single-driver-vm_http) (remaining effects).

One sub-branch per handler (`git_clone`, `git_push` VM-stage, `flake_provision`,
`agent_runs`), each converting the handler to a `BrokeredEffect` impl. `git_clone`
keeps its mint by making `resolve_authority` call `request_capability`;
`flake_provision` keeps its grant re-check in `decide`; `agent_runs` threads a
`RecordedRequest` from run-launch to the outcome endpoint. **Oracle**: each
handler's existing tests pass; the Stage-0 harness now covers it through the
driver.

### Stage 6 — the registry (capstone)

**Dependencies**: Stage 5. **Implements**: [§3.3](#33-layer-3--the-effect-registry-the-complete-by-construction-capstone).

Replace `route_authenticated_vm_http_request`, `auth_scheme_for_target`, and
`route_request_body_limit` with one registry the dispatcher iterates; move effect
impls into `vm_http::effects` and tighten `record_outcome`/secret visibility so
an effect cannot reach the store or the raw outcome writer. **Oracle**: registry-
totality test (every documented route resolves to exactly one entry, none
reachable outside `broker_effect`); the invariant oracle is now
add-a-capability-proof; full gate suite green.

---

## 6. Reconciliation with the gospel (no speculative generality)

The abstraction earns its place by the "explain how it composes with every other
feature" test: every effect is `decide → resolve_authority → begin → perform →
complete → respond`, and the axes that differ (authority, durability, effect
shape, transport) are *declared*, not branched. It is not speculative — there are
seven instances today, `proxy_common` already proves the composition, and the
review names the next two (PR creation, comment posting). It shrinks surface area
rather than adding it: three switch sites → one registry entry per effect; five
session-open copies → one; two hand-rolled two-phase skeletons → the shared one.

---

## 7. Deliberately out of scope

- **Host-side capability mint** (`request_capability`, `server.rs:462`). It
  shares the *invariant* and could reuse `RecordedRequest`, but it rides a
  different transport (Unix socket), a different response mapping, and the
  unforgeable `AuthorizedMint` — and it already carries the tightest existing
  enforcement (FK + exclusion trigger + `AuthorizedMint`). Folding it in is a
  clean follow-up once the guard exists, not a prerequisite.
- **`git_push`'s approval / reconciliation / mint ledger** (six tables, the
  approve-attempt state machine in `git_push/dao.rs`). It has no analogue and is
  not a simple `(request, outcome)` pair; forcing it through the generic would be
  the abstraction failing the composition test. Only its VM-side *staging* pair
  is in scope (Stage 5).
- **Streaming-body rework.** The streaming proxy path keeps its `Drop`-time
  outcome write; the guard is threaded into the stream body rather than
  redesigned.
