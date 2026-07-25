# Design + plan — give each model proxy its own URL namespace

Drafted 2026-07-25, from a finding the Stage-6 route-table totality test
surfaced (PR #337). Fixes a *misrouting and audit-misattribution* bug where the
Claude proxy silently swallows every OpenAI models request.

> Implement this plan with each stage on its own branch, stacked as necessary on
> previous branches, so that a reviewer can review each branch in isolation.

---

## 1. The bug

Both model proxies are mounted in the **same** URL namespace, because both
vendors' SDKs use the same one:

| Guest path | Claude backend | OpenAI backend |
|---|---|---|
| `/v1/messages`, `/v1/messages/count_tokens` | ✅ its own | — |
| `/v1/responses`, `/v1/responses/{id}/cancel` | — | ✅ its own |
| **`/v1/models`** | ✅ claims it | ✅ claims it |
| **`/v1/models/{id}`** | ✅ claims it | ✅ claims it |

`VmHttpRoute::resolve` classifies Claude first (as the dispatcher's original
if-chain always did), so **the whole `/v1/models*` space resolves to the Claude
proxy**. Two consequences, and the second is the serious one:

1. **The guest gets a wrong answer.** `ClaudeBackend::classify_proxy_target`
   returns `Unsupported` for a path that is not one of its own models routes, and
   `ProxyEffect::classify` turns `Unsupported` into a **`404 not found`**. So
   `codex` listing or retrieving a model gets a 404 from a proxy that was never
   meant to serve it. `OpenAiProxyAuditRoute::Models` and
   `openai_proxy_model_id` are implemented and unit-tested, but **unreachable
   through the dispatcher** — dead code in production.
2. **The audit log attributes it to the wrong vendor.** The 404 is recorded as a
   `Deny` in `claude_proxy_request` / `claude_proxy_outcome`. A reviewer
   reconstructing what the agent did sees an OpenAI-destined request recorded
   against Anthropic's table. For a system whose central promise is "the audit
   log *is* the history", recording an effect against the wrong upstream is a
   correctness defect, not a routing annoyance.

The bug predates the route table — it is the original if-chain order — but
nothing stated it, and `architecture.md`'s endpoint map read as though OpenAI
served `/v1/models`. PR #337 pinned the current behaviour in
`the_claude_proxy_shadows_the_whole_models_space` and documented it rather than
changing it, because moving the endpoint moves it between two upstreams *and*
two audit tables.

### 1.1 Why it cannot be fixed by ordering

There is no correct order. `/v1/models` is a real, distinct endpoint of *both*
vendor APIs; whichever backend is tried first, the other's models routes are
unreachable. The ambiguity is in the address space, so that is where it has to
be fixed.

---

## 2. Options

**A. Vendor prefixes — chosen.** Serve each proxy under its own prefix:
`/anthropic/v1/*` and `/openai/v1/*`. Ambiguity becomes unrepresentable rather
than resolved by precedence: no target can classify as two backends, and a test
can assert exactly that for all targets.

**B. Disambiguate `/v1/models` by a request signal** (which auth header shape
arrived, a query parameter, which service is configured). Rejected: routing on
an implicit signal is exactly the "no magic / explicit over implicit" rule this
codebase holds, and the signal is guest-controlled — a guest could steer its
request into the *other* vendor's audit table by changing a header.

**C. Route `/v1/models*` to whichever proxy is configured, keeping Claude when
both are.** Rejected: it fixes only single-proxy deployments and leaves an
order-dependent rule in exactly the configuration that matters (both proxies
enabled is the dark-factory case).

### 2.1 Why breaking the URL contract is cheap here

`writ` controls both sides. The guest binary (`writ-vm`) is built from this
flake (`agent-vm-writ-vm-<system>-musl`, baked into
`agent-vm-guest-image-<system>`), and it is `writ-vm` that sets the base URLs:

- Claude Code: `ANTHROPIC_BASE_URL = "{broker_url}"` (e.g. `http://…:49152/`),
  the SDK appends `/v1/messages`.
- codex: `model_providers.writ-broker.base_url = "{broker_url}v1"`.

Both are *configurable base URLs* — no client-side patching is needed, only a
different string. Per the gospel's migration rule, when you control the
consumers you migrate them and delete the old path; the only residual is a
**stale guest image** in the local Apple container store paired with a fresh
host, which §4 Stage 1 handles explicitly rather than leaving to a confusing 404.

Note also that the upstream path mapping is already decoupled:
`ProxyBackend::relative_upstream_path` maps a guest path to the upstream path
(`/v1/messages` → `v1/messages`), so changing the *guest-facing* prefix requires
no change to what is sent to Anthropic or OpenAI.

### 2.2 A second hazard this removes

Today three different APIs share `/v1/*`: Anthropic's, OpenAI's, and **writ's
own** (`/v1/session`, `/v1/git/*`, `/v1/nix/*`, `/v1/agent-runs/*`). That the
broker's own endpoints have not yet collided with a vendor path is luck, not
design. After this change `/v1/*` belongs solely to writ's own API, which is
worth asserting as a test.

Moving writ's own endpoints (e.g. to `/writ/v1/*`) is **out of scope**: they
collide with nothing today, and it would multiply the breaking surface for no
present gain.

---

## 3. The design

Two new path constants beside the existing ones in `crates/writ-vm-git`
(the crate that already pins every guest-facing path literal):

```rust
pub const VM_ANTHROPIC_PROXY_PREFIX: &str = "/anthropic";
pub const VM_OPENAI_PROXY_PREFIX: &str = "/openai";
```

Each backend classifies **only** under its own prefix — `ClaudeBackend` strips
`/anthropic` before matching `/v1/messages`, `OpenAiBackend` strips `/openai`
before matching `/v1/responses`. `VmHttpRoute::resolve` gains no new ordering
dependency, because the prefixes are disjoint by construction.

The legacy paths become a **named, closed** route:

```rust
// PlainRoute
/// A model-proxy path from before the vendor namespaces (`/v1/messages`,
/// `/v1/responses`, `/v1/models*`). Answered `410 Gone` naming the fix, so a
/// stale guest image fails loudly and diagnosably instead of looking like an
/// unknown endpoint. Records nothing: no effect was attempted.
LegacyProxyPath,
```

`410 Gone` rather than `404`: the endpoint genuinely existed and is genuinely
gone, and the body can name the remedy ("rebuild the guest image"). It is a
`PlainRoute`, so it stays inside the Stage-6 totality invariant — one more
reviewed variant, not an escape hatch — and it is deleted in Stage 3.

---

## 4. Implementation plan

### Stage 1 — vendor namespaces on the host

**Dependencies**: none (PR #337 must have landed). **Implements**: §3.

Add the prefixes; teach both backends to classify under their own prefix only;
add `PlainRoute::LegacyProxyPath` and resolve the old paths to it; update the
route table's endpoint map, the audit-pair drive oracle, and `architecture.md`.

**Correctness oracle**:
- **RED first, and this is the load-bearing one**: a property test that for
  *all* generated targets **at most one** proxy backend classifies it
  (`ClaudeBackend::classify_proxy_target(t).is_some() as u8 +
  OpenAiBackend::classify_proxy_target(t).is_some() as u8 <= 1`). Run it against
  today's code and watch it fail on `/v1/models`; it must pass after the change.
  This is the invariant that made the bug possible, so it is the one to make
  machine-checked.
- `/openai/v1/models` and `/openai/v1/models/{id}` resolve to `OpenAiProxy` and
  reach `OpenAiProxyAuditRoute::Models` — the previously-unreachable code path,
  now driven.
- `/anthropic/v1/messages` and `/anthropic/v1/models/{id}` resolve to
  `ClaudeProxy` and forward unchanged (same upstream path, same headers).
- Every legacy path returns `410` and records **no** audit row in either proxy
  table.
- `every_brokered_route_records_a_complete_audit_pair` (#337) still passes, now
  driving the prefixed paths — so the audit pair follows the endpoints.
- `/v1/*` contains only writ's own API: a test asserting no vendor path resolves
  to a proxy route.
- Delete `the_claude_proxy_shadows_the_whole_models_space`; the shadowing it
  pinned no longer exists.

### Stage 2 — point the guest at the new namespaces

**Dependencies**: Stage 1. **Implements**: §2.1.

`writ-vm` sets `ANTHROPIC_BASE_URL = "{broker_url}anthropic"` and
`model_providers.writ-broker.base_url = "{broker_url}openai/v1"`.

**Correctness oracle**:
- The existing `claude_process_plan` / `codex_process_plan` tests assert the new
  values (they already pin the old ones).
- **The cross-boundary oracle worth adding**: take the base URL each process
  plan configures, append the vendor SDK's own path suffix (`/v1/messages`,
  `/v1/responses`), and assert the *host's* `VmHttpRoute::resolve` classifies the
  result as that vendor's proxy. This makes guest configuration and host routing
  provably agree — the exact class of mismatch this whole plan is about, and
  something no test covered before.
- `scripts/prove-*.sh` agent-VM runs still complete (real hardware, not CI).

### Stage 3 — delete the legacy shim

**Dependencies**: Stage 2, plus one release in which stale guest images have
been rebuilt. **Implements**: the migration's completion.

Remove `PlainRoute::LegacyProxyPath`; the old paths become `Unmatched` (404).

**Correctness oracle**: a legacy path resolves to `Unmatched`; the route-table
coverage test passes with the variant gone; full gate suite green.

---

## 5. Risks

- **Stale guest image against a fresh broker.** The Stage-1 `410` makes this
  loud and self-describing rather than a silent 404. A version handshake between
  `writ-vm` and the broker would close it properly; that is a larger feature and
  is *not* proposed here.
- **A vendor SDK that does not honour its base-URL setting for every route.**
  Both do today (that is how the broker works at all), but Stage 2's
  cross-boundary oracle only proves the paths *writ* constructs. A vendor client
  that hard-codes an absolute URL for some endpoint would bypass the broker
  entirely and be refused by the no-egress firewall — visible, not silent.
- **Behaviour change for `/v1/models` under Claude.** Claude Code's own models
  requests move from `/v1/models*` to `/anthropic/v1/models*`. Same backend, same
  upstream, same audit table; only the guest-facing path changes.
