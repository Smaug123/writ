# writd zero-downtime upgrade — design and plan

Plan for letting `writd` be restarted (typically: upgraded to a new binary)
without killing in-flight agent VMs. Companion to
[`docs/design/broker.md`](../design/broker.md) and
[`docs/design/apple-container-agent-vm.md`](../design/apple-container-agent-vm.md).

Implement this plan with each stage on its own branch, stacked as necessary
on previous branches, so that a reviewer can review each branch in isolation.

## Goal

Today an in-flight agent dies when `writd` exits. The VM survives in the
container runtime, but the next call it makes through the VM HTTP listener
fails — and on the next `writd` boot, `reconcile_persisted_sessions`
(`src/agent_vm_daemon.rs:871`, called from `src/bin/writd.rs:125`) tears
the VM down as a "cleanup obligation."

End state: a `writd` restart leaves running agents alive and able to keep
talking to the broker, with at most a short connection-refused window that
the guest absorbs by retrying. Operator-initiated upgrade is a single
`writ-upgrade` (or equivalent) shell invocation; no per-agent intervention.

## Why this shape

### Trust model permits persisting tokens

The current "tear down on boot" design exists because the per-session
bearer secret (`RunningVmHttpSession`, `src/agent_vm_daemon.rs:231`) and
the HTTP listener live only in memory. The comment at
`src/agent_vm_daemon.rs:336` is explicit: "the previous `writd` process
owned the broker bearer token, the VM HTTP listener socket, and the
runtime handle, none of which survive a crash."

The trust-model question is: can the bearer secret live durably on the
host without weakening the broker invariant? The threat model has two
principals — the local user (who runs `writd`) and the agent inside the
VM. The local user is trusted; the agent is not. Persisting the bearer
token to the existing secret store (already used for the GitHub App
private key, the only other long-lived host secret —
`docs/design/broker.md:96`) does not give the agent anything it didn't
already have at session start; it only changes who else on the host could
read it. Since the host is already a single-tenant trust boundary, the
extra exposure is acceptable.

This reverses the assumption in the `src/agent_vm_daemon.rs:336`
docstring. Update that comment as part of stage 3.

### The guest already retries the obvious failures, but not at this layer

Both Claude and Codex retry network failures internally for several
minutes, so a transient connection-refused on the broker side does not
by itself kill an agent's outbound traffic. But the guest CLI
(`writ-vm`) wrapping those agents — used for git pushes, agent-run
bootstrap, and plan-related routes — uses a default `reqwest::Client::new()`
with no retry policy, no timeout, and no backoff. A single failed
`.send().await?` exits non-zero (`src/bin/writ-vm.rs:153`). So even with
the broker fixed, the guest dies on the connection-refused window
unless its client gains a retry loop. The fix is local: five call sites
in `src/vm_client.rs` (lines 415, 431, 460, 505, 544) all funnel through
the same construction pattern.

### Adopt, don't resume

Reconciliation today is "clean everything up on boot." The change is to
attempt *adoption* first: probe the persisted VM, reload its token,
re-bind its listener, refresh PF anchors, and admit it into the
in-memory `running` map. If any step fails — the container is gone, the
port is taken, PF refuses — fall back to today's tear-down. This keeps
the post-reconcile invariants identical to today's; only the happy path
gains a new branch. Treating dirty VMs as recoverable rather than as
garbage is what produces the upgrade story.

### Restart is not strictly zero-downtime; it's "guest-absorbed downtime"

True socket handoff (fd-passing between old and new `writd`) is possible
on macOS via `launchd` socket activation, but it doubles the moving
parts and is not necessary for the goal. The guest-side retry helper
gives a 30–60 second budget; the cold restart sequence
(load-state → adopt sessions → reopen sockets) finishes in well under
that. So this plan does not include socket handoff. If the
guest-absorbed window proves too long in practice, socket handoff is a
later optimisation; it does not invalidate any of the schema or token
work below.

## Conceptual model

### Component-level changes

```text
secret store
  + per-session bearer token persistence (encrypted at rest, same store
    as the GitHub App key)

AgentVmDaemon::reconcile_persisted_sessions
  ! adopt-or-tear-down per session, instead of always tear-down
  + for each persisted session: probe → reload token → rebind listener
    → refresh PF → admit into `running` map
  + on any step failing, fall back to existing tear-down path
    (preserves today's invariants)

writd top-level
  + SIGTERM handler: close Unix socket → stop accepting new VM HTTP
    connections → drain in-flight handlers (bounded) → exit, leaving
    VMs running and tokens persisted

writ-vm guest CLI
  + centralised broker client with retry-on-pre-send-failure
    (exponential backoff, capped total budget, idempotent calls only)
  + 5 call sites in src/vm_client.rs route through it
```

### What survives a restart

```text
survives                         destroyed
--------                         ---------
container VM                     in-memory `running` map
PF anchors                       reqwest::Client connection pool
session state JSON               kernel listener sockets (rebuilt)
audit-log open session row       (none beyond above)
secret-store bearer token
network / subnet allocation
```

### What does not change

- Per-session VM HTTP listener *port*. The guest stores its broker URL
  at session start; we re-bind on the same port post-restart. If the
  port has been taken in the meantime, adoption fails for that session
  and we fall back to tear-down.
- Session subnet, network name, firewall anchor name. All keyed on
  `SessionId`, which is stable across restart.
- Bearer-token wire format and HTTP authorisation logic. The guest
  cannot tell that the broker process is new.
- Reconciliation's terminal invariant: every session in
  `state_store` is either in `running` or fully torn down.

## Implementation slices

Each stage stands alone. Stages 1 and 2 are independent and can be
implemented in parallel; stage 3 depends on stage 2; stage 4 depends on
stage 3. Each stage delivers a testable improvement even if no later
stage lands.

### Stage 1: Guest-side broker client with retry-on-connection-failure

**Dependencies**: none.

**Implements**: "the guest already retries the obvious failures, but not
at this layer" above.

**Scope**:
- Introduce a `BrokerClient` (or similarly named) helper in
  `src/vm_client.rs` that wraps `reqwest::Client` and exposes the
  request shapes used by the five call sites (lines 415, 431, 460, 505,
  544).
- Retry only on *pre-send* failures: connection refused, connection
  reset before any bytes sent, DNS resolution failures (shouldn't
  occur on the broker URL but bound the policy anyway), and connect
  timeouts. **Do not retry** on 5xx, mid-request failures, or
  read-side timeouts: those may have already mutated broker state and
  require idempotency keys (deferred).
- Exponential backoff: starting at e.g. 200 ms, doubling, capped per-
  request at e.g. 30 s; capped total budget at e.g. 60 s; jitter to
  avoid thundering herd if multiple guests hit a restart at once.
- Migrate the five call sites to it.

**Correctness oracle**:
- Property test against a mock HTTP server that refuses connections for
  a configurable initial window and then accepts: for every (window,
  budget) pair with `window < budget`, the call succeeds; for
  `window > budget`, the call fails with the expected variant.
- Property test: a 5xx response causes a single failure, not a retry
  storm (verify by counting requests to the mock).
- Integration test: an in-flight `writ-vm` call survives the broker
  socket being closed and reopened within the budget window.

### Stage 2: Persist bearer tokens in the secret store

**Dependencies**: none.

**Implements**: "trust model permits persisting tokens" above.

**Scope**:
- Add a typed entry to the secret store keyed by `SessionId` holding
  the bearer token (and any other in-memory secrets that
  `RunningVmHttpSession` carries that the guest is allowed to learn
  again post-restart; the bearer token may be the only one).
- Write on session start, before the VM is told its broker URL.
- Delete on session end (normal stop + reconcile tear-down path).
- The session-state JSON does *not* gain the token; the token stays in
  the secret store, which is the existing trust boundary for host-
  resident secrets.

**Correctness oracle**:
- Property test on the secret store entry: write/read round-trip,
  delete-then-read returns absent, two concurrent writes for the same
  session are serialised by the existing store's locking (or fail
  deterministically — the existing store's contract decides which).
- Integration test: after a normal start → stop sequence, no bearer
  token entry remains in the secret store. (Catches leaks before stage
  3 starts depending on them.)
- Audit-log property: every persisted bearer token corresponds to an
  open audit session row, and vice versa. The state-store, audit log,
  and secret store agree on which sessions exist.

### Stage 3: Adopt-on-boot in `reconcile_persisted_sessions`

**Dependencies**: stage 2.

**Implements**: "adopt, don't resume" above. The load-bearing change.

**Scope**:
- Reshape `reconcile_persisted_sessions`
  (`src/agent_vm_daemon.rs:871`) to attempt adoption first, falling
  back to the existing tear-down path on any failure.
- Adoption sequence per session:
  1. Confirm the container is alive (`container list` or equivalent).
  2. Reload the bearer token from the secret store.
  3. Verify the PF anchor exists; reinstall if missing.
  4. Re-bind the VM HTTP listener on the same port. If `EADDRINUSE`,
     fall back to tear-down.
  5. Spawn the listener task, construct a `RunningVmHttpSession`, and
     install it in `running`.
  6. Leave the audit session row open (today's code closes it; skip
     that on the adoption branch).
- Any step's failure short-circuits to today's tear-down + state-record
  removal + audit close. The post-reconcile invariant is unchanged:
  every persisted session is either in `running` or fully gone.
- Update the `AgentVmReconcileReport` shape (`src/agent_vm_daemon.rs:344`)
  to distinguish `adopted` from `cleaned` sessions; surface both in the
  boot log so an operator can see "n adopted, m cleaned" at startup.
- Update the docstring at `src/agent_vm_daemon.rs:336` to reflect the
  new design (it currently asserts that bearer tokens cannot survive
  a crash).

**Correctness oracle**:
- Property test on the reconciliation state machine: model the per-
  session outcome as `{adopted, cleaned, failed-preserved}`; for every
  permutation of (container alive?, token present?, port free?, PF
  anchor present?), the machine produces the documented outcome.
- Integration test (the headline scenario): start `writd`, start a
  session, observe a successful `/v1/session` call from the guest;
  `SIGKILL` `writd`; start a new `writd`; observe a successful
  `/v1/session` from the same guest without the guest restarting.
- Integration test for the fallback path: same scenario but with the
  container killed externally between the two `writd` boots; assert
  the session is cleaned up rather than adopted.

### Stage 4: Graceful shutdown on SIGTERM

**Dependencies**: stage 3 (without adoption, graceful shutdown gains
the operator nothing — the VMs would just be torn down on the next
boot anyway).

**Implements**: "what survives a restart" above (the polite version of
the path stage 3 already supports via `SIGKILL`).

**Scope**:
- Install a SIGTERM handler in `src/bin/writd.rs` that:
  1. Closes the Unix socket so no new operator RPCs are accepted.
  2. Stops the VM HTTP listeners from accepting new connections, but
     allows existing connection handlers to drain (bounded by a small
     timeout, e.g. 5 s).
  3. Exits cleanly. State store, audit log, and secret store are
     already on-disk; nothing else to flush.
- VMs are *not* stopped. PF anchors are *not* removed. The next `writd`
  (stage 3's adoption path) picks them up.
- Add a `writ daemon upgrade` operator command (or similar) that does
  the boring orchestration: send SIGTERM to current writd, wait for
  exit, exec the new binary, exit. Optional; useful but not load-
  bearing — an operator can do this by hand.

**Correctness oracle**:
- Integration test: start `writd`, start a session, send SIGTERM,
  assert `writd` exits within the grace period; assert the VM is
  still running; start a new `writd`; assert the session is adopted.
- Integration test: a request in flight when SIGTERM arrives completes
  successfully within the grace period.
- Integration test: a request that exceeds the grace period is killed
  rather than blocking shutdown indefinitely.

## Out of scope / deferred

- **Socket handoff between old and new `writd`.** Possible via
  `launchd` socket activation; doubles the moving parts. The
  guest-side retry helper covers the cold-restart gap. Reassess if
  measured restart windows are >10 s.

- **Idempotency keys for non-idempotent broker routes.** Stage 1
  deliberately does not retry mid-request failures because
  `POST /v1/git-push-requests` and friends are not idempotent: a
  retry after the server has already mutated state would double-stage.
  A separate change adds request IDs and a server-side dedup table;
  it stands alone and unblocks retrying 5xx, but is not on the
  critical path for the upgrade story.

- **Live binary swap (no exit at all).** A future Rust hot-reload
  story would let `writd` swap code without dropping connections.
  Not pursued; the costs are very high for a marginal improvement
  over the cold-restart-plus-guest-retry path.

- **Cross-version protocol negotiation.** Today the VM HTTP wire
  format is a single version. If we ever bump it incompatibly, the
  adoption path needs to refuse adoption of sessions that were
  started on the old protocol (and the guest needs to refuse to talk
  to a broker advertising a newer one). Add when the first
  incompatible change is on the table; not before.

- **Multi-host operator workflows.** This plan assumes one
  `writd` per host. Coordinated upgrades across a fleet are
  out of scope.

## Open implementation questions

1. **Where exactly does the bearer token live in the secret store?**
   The existing store holds the GitHub App private key under a known
   namespace. Bearer tokens are per-session, ephemeral until session
   end; they want a separate namespace (e.g. `agent-vm/<session_id>`).
   Naming and lifecycle integration with the existing store API
   settles at stage 2 implementation time.

2. **Listener port reuse after restart.** The kernel may hold the port
   in `TIME_WAIT` briefly after the old `writd` exits. `SO_REUSEADDR`
   should let the new `writd` bind anyway, but verify on macOS and
   document the failure mode. If it turns out to be unreliable, the
   acceptable fallback is "reconcile tears down sessions whose port
   we cannot re-bind" — that is, today's behaviour for a subset of
   sessions, which is strictly better than today's behaviour for
   all sessions.

3. **Retry budget tuning.** The guest's retry budget must comfortably
   exceed the worst-case restart window (load state + adopt N
   sessions + rebind N listeners). Pick a starting number, measure
   in stage 3's integration tests, and tighten later. The risk of
   too-long a budget is that real failures masquerade as slow
   restarts; the risk of too-short is unnecessary agent failures.
   60 s is a reasonable starting point; revisit with telemetry.

4. **What does `writ daemon upgrade` do about the operator socket?**
   When a host CLI is mid-RPC during SIGTERM, it sees its socket
   close. The CLI should retry (same logic family as the guest
   retry helper, but simpler: it's local). Decide whether to share
   code with stage 1 or duplicate; the answer probably depends on
   whether the host CLI's HTTP-ish layer is general enough to host
   a shared helper.

5. **Audit-row semantics under adoption.** Today an audit session row
   is closed on reconcile. Under adoption, it stays open across
   the restart. This means "session uptime" no longer corresponds
   to "single `writd` process lifetime." If any downstream query
   assumed otherwise, fix it. The audit log already records
   `writd` boot events separately; consumers wanting the old
   semantic can join against those.
