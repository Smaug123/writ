# Design + plan — enforce the guest contract version broker-side

Drafted 2026-07-25, for issue #342. Follow-up to #338 / PR #341, which added
`VM_HTTP_CONTRACT_VERSION` and made `writ-vm` verify it at startup.

> Implement this plan with each stage on its own branch, stacked as necessary on
> previous branches, so that a reviewer can review each branch in isolation.

---

## 1. The gap

PR #341's handshake is **guest-side**, so it protects only a guest that *has*
the check. A guest image built before it makes no such call, and the broker
serves it exactly as before. That is precisely the case the handshake was for: a
stale image cached in the local `container` store, paired with a freshly-built
host.

The two directions are not symmetric, and only one of them is covered:

| Stale side | Caught by | Status |
|---|---|---|
| Broker older than guest | the guest's startup check (#341) | done |
| **Guest older than broker** | nothing — the broker cannot tell | **this plan** |

A stale guest can `git clone`, stage a push, and provision flake inputs against
a newer broker, discovering the skew only when it reaches whichever endpoint
actually moved — *after* effects, not before. The audit log then contains a
half-finished run whose cause is a version mismatch nobody has yet observed.

## 2. The constraint that shapes the fix

The obvious answer — require a contract-version header on every guest request —
**does not work**, because most guest-facing traffic does not originate in
`writ`:

| Route | Client | Sends a writ header? |
|---|---|---|
| `/anthropic/v1/*` | Claude Code | never |
| `/openai/v1/*` | codex | never |
| `/v1/nix/cache/*`, `/v1/nix/prewarm/*` | `nix` itself | never |
| `/v1/git/clone`, `/v1/git/push` | `writ-vm` | yes |
| `/v1/nix/flake/provision` | `writ-vm` | yes |
| `/v1/agent-runs/{id}/config`, `…/outcome` | `writ-vm` | yes |
| `/v1/session` | `writ-vm` — but see §3.3 | yes, unchecked |

Requiring a header universally would break both model proxies and the binary
cache. So enforcement applies to the `writ-vm`-originated subset — which is
exactly where the damaging pre-effect actions live.

## 3. The design

### 3.1 The header

One constant beside `VM_HTTP_CONTRACT_VERSION` in `crates/writ-vm-git`, the
crate that already pins every guest-facing wire literal:

```rust
/// Carries [`VM_HTTP_CONTRACT_VERSION`] on every request `writ-vm` originates.
/// Absent means "a guest older than the version that introduced this header",
/// which is why absence is refused rather than tolerated.
pub const VM_HTTP_CONTRACT_HEADER: &str = "writ-contract-version";
```

No `x-` prefix (RFC 6648). Parsed at the boundary into a
`GuestContract::{Version(u32), Absent, Malformed}` — parse, don't validate — so
the dispatcher matches on a value rather than re-deriving one from a string.

### 3.2 The per-route declaration

`VmHttpRoute` gains an exhaustive `match`, so a future capability *must* state
which side of the line it is on. As with `PlainRoute`, the point is not the
boolean but the recorded justification:

```rust
/// Whether this route requires the guest to declare its contract version.
enum ContractCheck {
    /// Originated by `writ-vm`: refuse unless the declared version matches.
    Required,
    /// Exempt, and why it must be.
    Exempt(ContractExemption),
}

enum ContractExemption {
    /// The handshake itself. Gating `/v1/session` would make a mismatch
    /// undiagnosable — it is the endpoint you call to *find out* the broker's
    /// version, and `writ-vm session` is exempted guest-side for the same
    /// reason. The readiness probes hand-roll it too.
    Handshake,
    /// A third-party client (Claude Code, codex, `nix`) that will never send a
    /// writ header. Refusing here would break the proxies and the cache.
    ThirdPartyClient,
    /// Nothing is reached and no effect is attempted, so the answer does not
    /// depend on the contract: `LegacyProxyPath`'s `410` and `Unmatched`'s
    /// `404` are more informative than a version refusal would be.
    NoEffect,
}
```

Assignment: `GitClone`, `GitPush`, `FlakeProvision`, `AgentRunConfig`,
`AgentRunOutcome` are `Required`. Note that two of those are `PlainRoute`s —
origin is orthogonal to whether a route is brokered, which is why the
declaration lives on `VmHttpRoute` and matches both arms.

### 3.3 Why `/v1/session` must be exempt

It is `writ-vm`-originated, and it is still exempt, for three independent
reasons: it is the endpoint the guest reads the broker's version *out of* (gate
it and a mismatch becomes undiagnosable); `writ-vm session` is already exempted
guest-side as the during-mismatch diagnostic, and gating it host-side would undo
that; and the readiness probes hand-roll `GET /v1/session` over a raw socket
(`broker_entrypoint`'s tests, and the `prove-*` scripts' health checks). The
handshake endpoint cannot itself be gated by the handshake.

### 3.4 Where in the dispatch, and what it answers

`serve_vm_http_request` resolves the route, authenticates, reads the body, then
dispatches. The check goes **after authentication, before the body read**:

- *After auth*, so an unauthenticated peer learns nothing about broker versions,
  and the existing auth-denial audit shape is untouched.
- *Before the body read*, so a refused push does not buffer up to
  `git_push_max_body_bytes` (65 MiB by default) from a guest we have already
  decided to refuse. Buffering work for a request we will not serve is the
  unbounded-work pattern the gospel warns about.
- *Before the handler*, so no effect runs and **no audit pair is written**. That
  is the whole point of the issue: refuse before effects, not after.

Answer `426 Upgrade Required` — the one status that means "I refuse over this
protocol version, upgrade and retry" — with a plain-text body naming both
versions and the remedy, plus a `tracing::warn!`, because the guest's stderr is
inside a VM and the daemon log is where an operator is already looking.

The remedy text moves from `writ-vm-client` to `writ-vm-git` so host and guest
produce the *same* diagnostic from one definition, generalised over an unknown
peer version:

```rust
pub enum GuestContract { Version(u32), Absent, Malformed(String) }
pub fn contract_mismatch_remedy(guest: GuestContract, broker: u32) -> String;
```

`Absent` and `Malformed` both name the guest as the stale side, and soundly so:
the header arrives with the contract version that introduced it, so a guest that
omits it necessarily predates that version.

### 3.5 What this guarantees, and what it does not

**Guarantee.** A guest whose contract version differs from the broker's — or
which is old enough not to declare one — cannot perform *any* brokered
host-authority effect: no clone, no push, no flake provision, no agent-run
outcome. Since a run's first action is a clone, the run fails before it does
anything, and the failure names the stale side.

**Not guaranteed.** Such a guest can still reach the model proxies and the
binary cache, which are exempt. Those confer no host authority beyond what the
session already grants, and they are what the vendor-namespace `410` covers, but
the exemption is real and should not be papered over: a stale guest can still
burn model tokens before its first clone fails.

**Not a security control.** The header is guest-controlled; a compromised guest
can claim any version it likes. This is skew protection between builds we
control, nothing more. The security boundary remains the broker's independent
re-validation of every field (`CLAUDE.md`: treat the guest as compromised the
moment the agent command starts), which this does not touch.

### 3.6 Making the version bump self-enforcing

`broker_contract_fingerprint_is_pinned` currently digests
`"{method} {target} -> {identity}"` over a corpus swept through
`VmHttpRoute::resolve`. Adding `ContractCheck` does not move any route, so **as
it stands the golden test would not demand the version bump this change
requires** — the same class of miss that PR #341's review caught twice.

So fold the declaration into the digested line:

```rust
format!("{method} {target} -> {} [{}]", route.identity(), route.contract_check())
```

Then "which routes require the header" becomes part of the pinned guest-facing
contract, and any future change to the exemption set forces a version bump and
an appended history row on its own. That is the mechanism, not a discipline.

---

## 4. Implementation plan

### Stage 1 — the guest sends the header

**Dependencies**: PR #341 merged. **Implements**: §3.1.

Add `VM_HTTP_CONTRACT_HEADER`, `VM_SESSION_PATH` (the last guest-facing path
literal still hardcoded in the client), and `WRIT_VM_ORIGINATED_TARGETS` to
`writ-vm-git`. Demote `VmClientConfig::endpoint` — which hands out a bare `Url`,
leaving each call site to remember the bearer token, as seven sites did by hand
— to an implementation detail of `VmClientConfig::{get, post}`, which return a
`reqwest::RequestBuilder` already carrying **both** the bearer token and the
contract header. Port all seven call sites. The point is "hard to misuse": a new
endpoint gets both by construction rather than by copying the site above it.

`GuestContract` and the generalised `contract_mismatch_remedy` wait for Stage 2,
where the second consumer appears; introducing an `Absent`/`Malformed` the guest
can never produce would be dead code here.

**This stage is deliberately separable, unlike #339's.** Sending a header the
broker ignores is purely additive: a Stage-1 guest works against every existing
broker, and every existing guest works against a Stage-1 broker (which is
unchanged). #339's halves could not be split because retiring the old paths
broke its own guest; nothing here breaks until Stage 2 starts refusing. Main is
green and deployable at every commit.

No version bump: the broker serves nothing differently, and the fingerprint
covers what a guest *reads*, not what it sends. If
`broker_contract_fingerprint_is_pinned` fails in this stage, that reasoning was
wrong and the stage needs rethinking — so leaving it untouched is itself an
oracle.

**Correctness oracle**:
- **One test, driving every client entry point** (clone, push, workspace init's
  provision, agent-run config, agent-run outcome, session) against the capturing
  stub, accumulating the observed request targets; asserts every captured
  request carries `writ-contract-version: <VM_HTTP_CONTRACT_VERSION>` *and* the
  bearer token, and that the set of observed targets equals a new
  `writ_vm_git::WRIT_VM_ORIGINATED_TARGETS`. A future entry point that skips the
  helper fails the header assertion; a future `Required` route with no client
  call fails the set equality (Stage 2 ties that list to the route table).
- **RED first**: drop the header from one ported call site, watch the test name
  that call site, restore.
- The agent-run entries are reconciled by construction: the test drives
  `fetch_agent_run_config` / `upload_agent_run_outcome` with the very id the list
  spells out, so a change to `vm_agent_run_{config,outcome}_path`'s shape moves
  the observed target and fails the set equality.

### Stage 2 — the broker requires it

**Dependencies**: Stage 1. **Implements**: §3.2–§3.6.

Add `ContractCheck` / `ContractExemption` and
`VmHttpRoute::contract_check(&self)` as an exhaustive match; parse the header in
`VmHttpRequest`; enforce in `serve_vm_http_request` between authentication and
the body read; fold the declaration into the fingerprint's digested line; bump
`VM_HTTP_CONTRACT_VERSION` **and** `BROKER_PROTOCOL_VERSION` and append the
`GUEST_CONTRACT_HISTORY` row (a new digest, since §3.6 puts the declaration in
it); update `architecture.md`'s endpoint map with the per-route column.

**Correctness oracle**:
- **Exhaustiveness**: `contract_check` is a `match` with no wildcard, so a new
  route is a compile error until it chooses. (`ContractExemption`'s variants
  carry the reason, so "chooses" means "states why".)
- **The cross-crate coupling, both directions**: the set of `ENDPOINT_MAP`
  routes whose `contract_check()` is `Required` equals the set of routes that
  `WRIT_VM_ORIGINATED_TARGETS` resolves to. This is what keeps the client's idea
  of what it originates and the broker's idea of what it requires from drifting
  — the exact failure mode that produced #338 and this issue.
- **Refusal, per `Required` route** (driven from `ENDPOINT_MAP`, so totality
  comes free from `the_endpoint_map_covers_every_route`): a request with no
  header, and one with a mismatched version, each answer `426`, name the correct
  stale side, and leave **zero rows in every effect table** — reusing the
  Stage-6 capstone's audit-table sweep in its no-rows mode. A well-formed
  matching header behaves exactly as before (the existing audit-pair drive test,
  updated to send the header, *is* this assertion).
- **Exemption, per exempt route**: a request with no header behaves exactly as
  it does today — one assertion per route rather than a blanket one, so the
  exemption set cannot silently widen.
- `GET /v1/session` with no header still answers `200` with the contract
  version, and the `broker_entrypoint` readiness probes still pass unmodified.
- **Ordering**: a `POST /v1/git/push` declaring a body larger than the push
  limit, with no header, answers `426` — *not* the `400 …exceeds limit` it would
  get if the body were read first. This pins "refuse before buffering".
- **Ordering, the other edge**: an unauthenticated request with no header
  answers `401`, not `426`, so version state is not disclosed pre-auth.
- **Property** (over `route_table`'s existing `target_strategy`): for any
  generated target, if the resolved route is `Required` then a header-less
  request is refused and records nothing. Run it with the enforcement stubbed
  out first and watch it fail.
- Both version constants move, and the fingerprint test demands it — verified by
  reverting the bump and watching it fail with the append-a-row message.

---

## 5. Risks

- **Transport race on early refusal.** Answering `426` before draining a large
  push body means a client mid-upload may observe a connection reset rather than
  the response. Accepted: the guest's own startup check (#341) is the primary
  diagnostic path, so this path is only ever reached by a *stale* guest, which
  by construction has no better diagnostic anyway. The daemon-side `warn!` is
  where the real answer lives. The alternative — buffering up to 65 MiB from a
  guest we have already refused, on every attempt — is worse.
- **The exempt surface stays reachable to a stale guest** (§3.5). Bounded and
  stated, not closed.
- **Guest-controlled header** (§3.5). Skew protection, not a security control.
- **Neither side helps a peer built before its half.** A stale broker ignores
  the header; a stale guest ignores the session version. The pair is complete
  only for builds from this revision onward — which is inherent to any
  handshake, and the reason the `410` and the `426` both name a remedy.
