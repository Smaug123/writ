# `ipv4_only_locked_v1` implementation plan

Implement this plan with each stage on its own branch, stacked as necessary on
previous branches, so that a reviewer can review each branch in isolation.

The design is
[`docs/design/ipv4-only-network-confinement.md`](../design/ipv4-only-network-confinement.md).
This plan supersedes the July 2026 plan that lived on the
`codex/ipv4-lock-stage-1-gate` branch. That plan's Stage 1 gate refused every
startable configuration, its Stage 2 harness needed observers that were Stages
4, 5, 7 and 8, and Stage 5 depended on Stage 2 in turn. The re-slice below
follows one rule: **build the host-owned observers first, then one vertical
experiment, and generalise only when a second experiment demands it.**

Starting point on `main` (September 2026): layer 1 is shipped for host
placement (#288); vm placement refuses new sessions (#396);
`ipv4_only_locked_v1` parses and is refused by `ConfiguredIpv6Profile::admit`
(#397). Parked branches worth mining are named per stage. None should be
rebased wholesale.

Two conventions apply throughout. Guest-side code goes in a crate or behind
the `vm-client` feature, never in the flat root crate, so a host build cannot
pull it in by accident. And nothing gains a test-only bypass on the object a
gate guards: a test that needs to get past admission constructs the admitted
value directly, as the vm-placement tests do today.

---

## Stage A: Design record

**Dependencies:** None. This is the branch that carries this file.

**Implements:** The whole design as a record; layer 1 rewritten as
current-state; the evidence protocol.

**Correctness oracle:** Every symbol, step name, and PR number the design cites
for shipped behaviour exists on `main` (`AgentVmStartStep`'s step sequence,
`--deny-guest-ipv6`, `parse_bridge_for_gateway`, `ConfiguredIpv6Profile::admit`,
the PF rule text in `agent_vm_firewall.rs`). `cargo doc` is unaffected;
markdown links resolve.

---

## Stage B1: Guest handoff plan, as data

**Dependencies:** Stage A.

**Implements:** Layer 2, "Before announcing readiness" steps 1–7, as a pure
description; the fixed `container run` capability argv.

Add a Linux-only crate (`crates/writ-guest-init`, no host deps) holding: the
ordered handoff plan as a DU of steps (chown, sysctl write, verify-no-ipv6,
drop-caps, set-no-new-privs, setgroups, setresgid, setresuid, re-verify), the
expected post-handoff `/proc/self/status` shape as a parsed type, and the
`LOCKED_CAPABILITY_ARGV_PROFILE` constant with its parser. Salvage the argv
profile and its tests from `codex/ipv4-lock-stage-1-gate`
(`src/agent_vm_start_gate.rs`).

**Correctness oracle:**
- Property: the argv profile parses back to exactly the capability set the
  design lists, and any argv that adds, drops, or reorders a `--cap-add`
  fails to parse.
- Property: a `/proc/self/status` document is accepted iff every capability
  field is zero, `NoNewPrivs` is 1, Uid/Gid are all 1000, and Groups is empty;
  generators mutate one field at a time and each mutation is rejected.
- The step sequence is exhaustive and ordered: a property asserts that the
  sysctl steps precede the bounding-set drop, that the bounding-set drop,
  inheritable/ambient clear, and `NoNewPrivs` all precede the identity change
  (they need `CAP_SETPCAP`, which the identity change discards), that the
  identity change is the last privileged step, and that nothing follows
  re-verify.

---

## Stage B2: `writ-agent-vm-guest-init` binary

**Dependencies:** Stage B1.

**Implements:** Layer 2 steps 1–9: the interpreter for B1's plan, the
`security-ready` record, the USR1 wait, and the final `exec`.

**Correctness oracle:**
- Integration test on the Linux CI runner: run the binary in a container
  launched with the B1 argv profile, wrapping a probe command that prints
  `/proc/self/status`, `ip -6 addr`, and `ip -6 route`; after sending USR1 the
  output satisfies B1's acceptance type. This is host-observed and pre-release,
  so it is trusted evidence.
- Every injected failure (chown of a missing dir, a sysctl that cannot be
  written, an address that survives step 3, a bounding-set entry that survives
  step 5, an identity change refused with `EPERM`) prevents `exec`: the probe
  command never runs, and one bounded failure record is emitted.
- The `security-ready` record is one line, versioned, under a fixed byte
  bound, and emitted exactly once; a property fuzzes the wrapped argv and
  asserts the record is unchanged.
- The wait is armed before the record is published: the integration test
  sends `USR1` the instant it reads the record, repeatedly across many runs,
  and the probe command runs every time; a variant that sends `USR1` before
  the record is read observes no release and no termination.

---

## Stage B3: Official image with the isolation ABI

**Dependencies:** Stage B2.

**Implements:** Layer 2, "fixed identity and initializer ABI"; the
`org.writ.agent-vm.isolation-abi = 1` label.

The Nix image sets the initializer as PID 1, fixes UID/GID 1000 with a
writable home, workspace, and Nix store owned by it, and stamps the label.
Salvage the label constant, `parse_image_inspect_isolation_abi_v1`, and the
bounded `container inspect` reader from the stage-1 branch; the host side
lands in Stage D.

**Correctness oracle:**
- `nix build` of the image succeeds; the B2 integration test passes against
  the built image rather than a bespoke container.
- Image scan (in CI, over the built rootfs): no setuid or setgid file, no file
  capabilities, no writable path on the initializer's own binary or its
  directory.
- Smoke: `git`, `nix`, `claude`, and `codex` each start and print a version
  as UID 1000 after handoff.

---

## Stage C1: PF helper `protocol-version` and a versioned result

**Dependencies:** Stage A. Independent of B.

**Implements:** Privileged-helper boundary, the probe and the bounded JSON
result.

Salvage `ProtocolVersion` and `protocol_version_json` from the stage-1 branch.
Report version 2 only once C2 has landed in full, policy file included; until
then the command exists and reports 1, so Stage D can be written against a
real probe. Protocol v2 *means* C2's boundary, so admission on "v2" is
admission on the whole of it.

**Correctness oracle:**
- The command is non-mutating: with a fake `pfctl` recorder injected, it
  invokes nothing.
- Output is one line, one object, under `PF_HELPER_PROTOCOL_MAX_BYTES`, parsed
  by a host-side type that rejects trailing data, a second object, or an
  unknown protocol name.

---

## Stage C2: Helper protocol v2: policy file, exact readback, re-resolve

**Dependencies:** Stage C1.

**Implements:** Privileged-helper boundary in full: the root-owned policy
file, "syntax-checks, atomically loads, parses exact readback, and re-resolves
after the load"; closes two of the layer-1 deltas.

Pools, the broker-port range, and the admitted interface-name policy move from
CLI arguments to a fixed-path policy file that must be root-owned, a regular
file, not a symlink, and not group- or world-writable; the helper refuses to
run otherwise. The session facts that remain arguments (session id, subnet,
ports, broker host) are validated against the file, as they are validated
against the arguments today. Without this, "locked_v1 admits on protocol v2"
would open the profile while the helper still took its own bounds from the
unprivileged caller.

`install` and `--deny-guest-ipv6` then run: precheck, resolve, `pfctl -n`
syntax check, load, `pfctl -sr` readback parsed to the ruleset type and
compared for equality with the intended one, resolve again and compare
interface names. Any mismatch is an error *after* the anchor has been loaded,
so the helper's result says which phase failed and the daemon treats the
session as unreleasable (it is already fail-closed on any helper error).

**Correctness oracle:**
- Policy loading is a library function taking a path: a temp-dir test covers
  each refusal (missing, symlink, wrong owner, group-writable, world-writable,
  unparseable) and the one acceptance; a property asserts a session fact
  outside the policy's pools or port range is refused exactly as the CLI
  bounds refuse it today.
- With a fake `pfctl` scripted per invocation: a readback that is missing a
  rule, has an extra rule, has a rule on a different interface, or is empty
  fails with the readback-phase error; an interface that changes name between
  the two resolutions fails with the re-resolve error.
- Property: for any valid session ruleset, render → parse is the identity, so
  a correct readback always compares equal.
- The order of `pfctl` invocations is asserted exactly: syntax check before
  load, readback after, never a flush.

---

## Stage C2b: Interface-scoped IPv4 rules

**Dependencies:** Stage C2. May proceed alongside C3.

**Implements:** Layer 1, known delta "the IPv4 rules are source-scoped".

The renderer scopes the IPv4 allow and deny to the resolved bridge and
members, with `block return in quick on <iface> inet from any to any` as the
default, so an out-of-subnet source has nothing to fall through to. Because
this changes the anchor the legacy profile installs, it lands behind the
existing `--deny-guest-ipv6` step (the interfaces are known there) and the
subnet-scoped rules stay in front of it as today; the property that the two
placements share one renderer (F1) applies here first.

**Correctness oracle:**
- Property over generated session facts and interface sets: the rendered
  anchor's rule list, in order, is the subnet-scoped allow and deny, then per
  interface an IPv4 allow for the broker tuple, an IPv4 default deny, and the
  IPv6 deny; render → parse is the identity.
- A pure packet-decision model over the rendered rules: for every generated
  IPv4 packet on a resolved interface, only the intended broker tuple passes,
  regardless of source; on an unrelated interface the anchor decides nothing.
- `scripts/prove-agent-vm-lifecycle.sh` gains the spoofed-source probe from
  the root guest and asserts the labelled IPv4 deny counter rose, with the
  unconfined-control clause from E3 applied once E3 exists.

---

## Stage C3: Labelled counters as a host observer

**Dependencies:** Stage C2.

**Implements:** Evidence protocol rule 1, the PF counter source.

Add a `counters` helper command that reads `pfctl -vsr` for a session anchor
and returns the packet and byte counters as a typed `PfCounterSnapshot` keyed
by (label, interface): the shipped renderer stamps the same label on the
bridge rule and on each `vmenet` member rule, so the label alone is not a key,
and the interface is printed in the rule text. `PfCounterDelta` is the
difference of two snapshots and rejects a pair with different key sets. This
is infrastructure for Stage E3 and is inert until then.

**Correctness oracle:**
- Property: parsing `pfctl -vsr` verbose output for a generated ruleset with
  generated counters recovers every (label, interface) pair's counters,
  including a ruleset rendered by the real renderer for a bridge with several
  members; unlabelled rules are ignored; the same (label, interface) pair
  seen twice is an error.
- Property: `delta(a, b)` is defined iff `a` and `b` have the same key set,
  and is componentwise `b - a`, refusing a negative (counters only rise
  between snapshots of the same loaded anchor).

---

## Stage D: Locked-profile admission evidence, inert

**Dependencies:** Stages B3 and C2.

**Implements:** Persistence and compatibility, "admission is conditional on
host-gathered runtime evidence", as infrastructure only. **The profile stays
closed at the end of this stage.** Opening it before the locked start path
exists (E2) would route a `locked_v1` session down the legacy root prelaunch,
which is the one thing the profile promises not to do.

Add `LockedV1RuntimeEvidence`, a struct of parsed, host-observed facts: the
helper's protocol probe (C1, reporting v2 only once C2 including its policy
file has landed), the image's ABI label read via bounded `container inspect`
(B3), the Apple `container` CLI version line, and the macOS build from
`sw_vers`. Add `ConfiguredIpv6Profile::admit_locked(evidence)`, the pure
decision, and the daemon-side gatherer that produces the evidence by running
the probes with bounded output. `ConfiguredIpv6Profile::admit` is unchanged
and still refuses `Ipv4OnlyLockedV1`; nothing calls `admit_locked` yet.
`Ipv6IsolationMode` does *not* yet gain a variant: no session can run in the
mode until E2, and the state store must not be able to say one does. Salvage
the three parsers from the stage-1 branch; do not salvage
`decide_agent_vm_start`, and do not add a bypass field to the plan.

**Correctness oracle:**
- Exhaustive over `admit_locked`: every combination of {helper v1, v2,
  unparseable} × {label absent, 0, 1, unknown} × {CLI pinned, other,
  unparseable} × {macOS build pinned, other, unparseable} is tested, and only
  the one admitting combination yields `Ok`; each refusal names the wrong
  fact.
- The gatherer with a fake tool: each probe's output is bounded and a probe
  that hangs, over-produces, or exits non-zero yields the corresponding
  "unparseable" evidence, never a panic or an admit.
- The existing "closed profile refuses new sessions and creates nothing" test
  still passes unchanged: `admit` did not change, so `locked_v1` is refused
  before any probe runs.

---

## Stage E1: Lifecycle phases and state schema v3

**Dependencies:** Stage D.

**Implements:** Lifecycle model; Persistence and compatibility, schema v3 and
the v2 cleanup-only reader.

The phase DU replaces the boolean-ish start outcomes for the locked mode; the
persisted record carries the phase reached, the resolved interfaces, and the
firewall phase. `ReleaseAttempted` is written before the release signal is
sent, so a crash or an unreadable `kill` result cannot leave a running
workload behind a record that says it was never released. The v2 reader
produces only a stop plan.

**Correctness oracle:**
- State-machine property: for every phase, inject failure or a simulated crash
  immediately after it, then run boot reconcile; the session is cleaned, PF is
  removed only after VM absence is proved, and `ReleaseAttempted` was never
  reached without `GuestSecurityLocked` and `FinalFirewallInstalled`.
- Property: `ReleaseAttempted` is unconstructible from any other pair of
  phases (a compile-time fact where the types allow it, a test where not), and
  the persisted record shows `ReleaseAttempted` before the fake tool's log
  shows the `kill`, under every injected `kill` outcome (success, failure,
  timeout, daemon crash mid-call).
- Reconcile treats `ReleaseAttempted` exactly as `WorkloadReleased`: authority
  revoked first, then cleanup; it never re-sends the signal or re-enters the
  start path.
- Every v2 record in `proptest-regressions` and the existing state-store tests
  still loads, as cleanup-only, and is never reported as locked.

---

## Stage E2: Host-placement locked start, and the profile opens

**Dependencies:** Stages D, E1.

**Implements:** Layer 2 host side: the locked `StartVm` argv, waiting for
`security-ready` via bounded `container logs`, release via
`container kill --signal USR1`; Layer 1 with C2's readback in the deny step;
and the migration of every post-release host-to-guest interaction off
`container exec`.

The last item is the one an earlier draft of this plan missed. Today the
daemon releases the guest and then runs `container exec` to write the
broker-ready marker and to poll the workspace-bootstrap result files
(`release_and_wait_for_workspace_bootstrap_with_timeout`). Under the locked
profile the container's initial process holds temporary capabilities, and a
post-release `exec` is a fresh process in that container with whatever
authority the runtime grants it, which contradicts the no-post-release-exec
guarantee layer 2 exists to give. So: broker-ready becomes part of the release
signal (the daemon does not send `USR1` until the broker is ready, so the
marker has nothing left to say), and the bootstrap outcome is read from the
same bounded `container logs` channel as `security-ready`, as versioned
records with the failure bounded exactly as today's failure file is. The two
records have different standing. The `security-ready` record is emitted
before any untrusted code runs and gates release. The bootstrap record is
emitted after release, by which point repository-controlled code has run
under the same UID as PID 1 and can write whatever it likes to PID 1's
stdout; it therefore gates nothing that carries authority, exactly as today's
bootstrap files do not, and is used only to end the wait, report to the
operator, and bound the timeout. A forged bootstrap success harms only the
agent that forged it. After `USR1`, the daemon runs no `container exec`
against a locked session, and the helper for the mode that still needs one
(`Ipv4OnlyNoGuestIpv6`) is the only caller left.

With that in place, `Ipv6IsolationMode` gains `Ipv4OnlyLockedV1`, the state
schema gains its mode spelling, and `admit` calls D's `admit_locked` for the
locked profile. The host-placement pin list ships **empty**, so at the end of
this stage the profile still admits on no real host; E3 adds the first (CLI,
macOS build) pair in the same change that records its proof passing. That is
what keeps a stage landing on its own from exposing an unproven path. Both
front doors open together: `writ-agent-vm-runner start` and `managed-start` call the same
library gatherer as the daemon and pass its evidence to the same `admit`, so
the runner cannot start a locked session on a host the daemon would refuse.

Nothing here is a proof. It is the daemon doing the locked sequence under the
fake tool, with every step's failure leaving the workload unreleased.

**Correctness oracle:**
- Fake-tool daemon tests: the recorded `container run` argv contains exactly
  the B1 profile; `USR1` is sent iff the ready record was observed, the broker
  is ready, and the deny readback succeeded; a missing, malformed, duplicated,
  or over-long ready record, a `logs` timeout, or a helper readback failure
  each leave the session in a phase before `ReleaseAttempted` and trigger
  cleanup. A `kill` that fails or times out is different: the record already
  says `ReleaseAttempted`, and the daemon revokes authority and cleans up
  without ever re-entering the release path, under every kill outcome.
- The fake tool's invocation log for a locked session contains no `exec` after
  the `kill --signal USR1` line, asserted by a test that runs the full
  start-and-bootstrap sequence; the legacy profile's sequence is unchanged and
  its existing tests still pass.
- Property over fuzzed `container logs` output: only a line that parses as
  the versioned ready record releases, and a ready record appearing after
  `USR1` is ignored. Bootstrap records are parsed the same way but a test
  asserts, by inspecting every consumer, that nothing with authority (grants,
  proxies, staged pushes) keys off bootstrap success; it ends the wait and
  is reported, nothing more.
- `admit` now yields `Ipv4OnlyLockedV1` under exactly D's admitting evidence
  and refuses otherwise; the "creates nothing" test runs for every refusing
  combination: no subprocess beyond the probes, no audit row, no state record.
- The runner's existing "closed profile is refused here too" test runs for
  every refusing evidence combination, with the probes faked, and the runner
  builds a locked plan only under the admitting one.
- Stop and reconcile of a persisted `Ipv4OnlyLockedV1` session need no
  evidence: the persisted-session tests run under a daemon whose evidence
  gathering is scripted to fail.

---

## Stage E3: The vertical proof, with host-owned evidence

**Dependencies:** Stages E2, C2b, and C3.

**Implements:** Proof obligations 1 and 2; Evidence protocol rules 1–6.

Evolve `scripts/prove-agent-vm-lifecycle.sh`, and the small Rust it shells to,
so that grading uses only host-owned facts: a host-minted nonce, a host
listener on the bridge's ULA and link-local addresses expecting that nonce, the
labelled deny counter delta from C3 across a host-timed window of two RA
intervals, and a positive control in the same run: a root guest from the proof
image on a network the proof creates itself, with no anchor, reaching an
identical listener. The proof runs twice, once per profile, because the two
have different expected counters: under the legacy profile the root guest can
re-enable IPv6, so the deny counters must rise; under the locked profile it
cannot, so they must stay at zero. The guest attack binary is told the targets
and its output is attached as diagnostics. This is where `ipv4-lock/02-claim`'s `Claim<T>` gets its first
consumer: guest-reported facts arrive as claims, and the grader cannot read
them without unwrapping into the diagnostics appendix. Keep the attack set to
what the design lists (sysctl, rtnetlink, raw socket, namespace, proc alias,
setuid, file capability, child process); do not build a schedule language.

**Correctness oracle:**
- On hardware, legacy profile: the positive control reaches its listener; the
  protected session's listener accepts nothing and its deny counters rose by
  at least the commanded probe count.
- On hardware, locked profile: the positive control reaches its listener; the
  protected session's listener accepts nothing and its deny counters are
  zero; the pre-release `/proc/<pid>/status` read matches B1's acceptance
  type. The change that records this passing is the change that adds the
  host's (CLI, macOS build) pair to the host-placement pin list; the pin list
  test asserts every entry names a proof record.
- The proof fails, each with a distinct message, when the positive control
  does not reach its listener (observer broken), when the listener tool is
  missing, when the legacy run's RA route never returns, and when a locked
  run's counter is non-zero.
- Under the locked image, the attack binary's own diagnostics show each
  attack failing at the syscall as UID 1000, and the host verdict is
  unchanged with those diagnostics deleted.

---

## Stage F1: Quarantine and atomic replacement in the helper

**Dependencies:** Stage C2. May proceed alongside D and E.

**Implements:** Layer 1, "Quarantine and replacement".

Two operations. `quarantine` resolves the bridge carrying the session gateway
with at least one member (the broker VM's; the bridge does not exist before a
VM runs on the network), loads the bridge-scoped IPv6 deny plus an IPv4
deny-all for the session subnet, and reads it back. `finalize` replaces that
with the final ruleset in one `pfctl -f` load, verified by readback, and on a
readback mismatch reloads quarantine and reads that back too. Never a flush.
Both return the anchor's state as `Quarantined`, `Final`, or `Unknown`.

The reported state always comes from a readback, never from a `pfctl` exit
status: a failed or timed-out load does not prove the kernel did not commit
it. After any load outcome the helper reads the anchor back and reports what
it saw; `Unknown` means the readback itself failed or matched neither ruleset.

**Correctness oracle:**
- With a scripted fake `pfctl`: a failed syntax check (no load attempted)
  reports `Quarantined` after a readback confirming it; a failed, killed, or
  timed-out `finalize` load is followed by a readback and reports whichever
  ruleset that readback matches, re-quarantining first if it matched neither;
  a readback mismatch after a successful load reports `Quarantined` iff the
  re-quarantine's readback matches, and `Unknown` otherwise; a property over
  failure position and over the fake's post-failure anchor contents asserts
  that every result is one of the three states, that `Final` is reported only
  when the final readback matched exactly, and that no result is reported
  without a readback having run after the last load attempt.
- `quarantine` before any VM is on the network fails closed with the
  no-bridge error, and `finalize` without a prior quarantine readback is
  refused.
- Property: `finalize` output equals the host-placement ruleset for the same
  session facts plus the broker-VM endpoint, so the two placements share one
  rule renderer.

---

## Stage F2: Broker-VM internal firewall in the ready document

**Dependencies:** Stage F1.

**Implements:** Layer 3.

The broker VM installs its internal-interface rules, reads them back, records
the readback in `BrokerReadyDoc`, and drops `CAP_NET_ADMIN` before executing
`writd`. The daemon refuses a ready document without a matching readback.

**Correctness oracle:**
- Property over fuzzed ready documents: only a document whose readback equals
  the rendered internal ruleset for the session subnet and port is accepted.
- Broker entrypoint test in a Linux container: after readiness, the entrypoint
  process has no `CAP_NET_ADMIN`, and the rules are present.

---

## Stage F3: VM-placement locked start

**Dependencies:** Stages E2, F1, F2.

**Implements:** Lifecycle model for vm placement; lifts
`Ipv6ConfinementUnavailableForVmBroker`.

Split network creation from broker launch: create network, start broker,
`quarantine` (the bridge now exists), wait for the ready document, discover
the broker IPv4, `finalize`, start the agent VM (its initializer waits), the
two-member interface deny with readback, and only then the E2 release
(`security-ready` observed, `USR1`). The deny with both members present must
precede `USR1`; the finalized anchor was resolved with one member.

**Correctness oracle:**
- Fake-tool daemon tests: the order of helper and `container` invocations is
  exactly the design's; the agent VM is started only after a helper result of
  `Final`; `kill --signal USR1` appears only after a two-member deny readback
  succeeded; on `Quarantined` or `Unknown` the daemon stops the broker, proves
  it absent, and removes the anchor, in that order; the E1 state-machine
  property runs with the vm phases present.
- The vm-placement refusal is removed for the locked profile only; the legacy
  profile under vm placement is still refused, with the existing test. The
  vm-placement pin list is separate from host placement's and ships empty; F4
  populates it, so vm placement admits on no real host until its proof has
  passed there.

---

## Stage F4: Proof obligation 3

**Dependencies:** Stages E3 and F3.

**Implements:** Proof obligations 3.

Extend the E3 proof with a forbidden listener on the broker VM's internal
interface, and a second session, in both teardown orders.

**Correctness oracle:** As E3, plus: the broker listener accepts nothing; each
session's positive control reaches only its own broker; neither session's
attack reaches the other; both teardown orders leave both anchors empty and
both networks absent.

---

## Stage G: Soak, closing the legacy profile, and release

**Dependencies:** Stage F4.

**Implements:** Proof obligation 4; Persistence and compatibility, upgrade and
rollback; closing `ipv4_only_no_guest_ipv6` and `dual_stack_required` to new
sessions.

**Correctness oracle:**
- A soak driver runs start, attack, stop repeatedly and restarts `writd` at
  every persisted phase; no run is inconclusive; sleep/wake, `container`
  restart, and interface churn are each exercised once with the E3 evidence
  intact.
- Closing the two unlocked profiles is the change to `admit`: after it, only
  `Ipv4OnlyLockedV1` yields a mode. `DualStackRequired` is closed alongside
  the legacy profile, not merely left unstartable: it still runs the root
  prelaunch path, so on any platform where its IPv6 validation passed it would
  restore network-management authority, against invariant 9. The existing
  refusal and reconcile tests run against both, in place of
  `Ipv4OnlyLockedV1`.
- Upgrade from a legacy daemon with a live session: the new daemon reconciles
  it as cleanup-only; rollback with a locked session live: the old daemon
  refuses to start on the spelling, as #397's test already asserts.
