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
expected post-handoff `/proc/self/status` shape as a parsed type with two
acceptance proofs (awaiting release, `USR1` blocked because PID 1 is parked
in `sigwait`; released, `USR1` unblocked in the `exec`ed workload), and the
`LOCKED_CAPABILITY_ARGV_PROFILE` constant with its parser. Salvage the argv
profile and its tests from `codex/ipv4-lock-stage-1-gate`
(`src/agent_vm_start_gate.rs`).

**Correctness oracle:**
- Property: the argv profile parses back to exactly the capability set the
  design lists, and any argv that adds, drops, or reorders a `--cap-add`
  fails to parse.
- Property: a `/proc/self/status` document is accepted iff every capability
  field is zero, `NoNewPrivs` is 1, Uid/Gid are all 1000, Groups is empty, and
  `SigBlk` has `USR1` set (awaiting release) or clear (released); generators
  mutate one field at a time and each mutation is rejected by the proof for
  its phase, and no document satisfies both proofs.
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
  output satisfies B1's released acceptance type (`LockedReleased`). This is
  host-observed, so it is trusted evidence.
- Every injected failure (chown of a missing dir, a sysctl that cannot be
  written, an address that survives step 3, a bounding-set entry that survives
  step 5, an identity change refused with `EPERM`) prevents `exec`: the probe
  command never runs, and one bounded failure record is emitted.
- The `security-ready` record is one line, versioned, under a fixed byte
  bound, and emitted exactly once; a property fuzzes the wrapped argv and
  asserts the record is unchanged.
- The wait is armed before the record is published: the integration test
  sends `USR1` the instant it reads the record, repeatedly across many runs,
  and the probe command runs every time, never a terminated PID 1. The probe
  command also prints its signal mask (`SigBlk` in `/proc/self/status`), and
  B1's released acceptance type requires `USR1` unblocked in it, while its
  awaiting-release type, the one the host's gate applies to PID 1 before
  sending `USR1`, requires it blocked. (A signal
  that arrives after arming and before the host reads the record is simply
  pending and released next; the guest cannot observe when the host read the
  line, so ordering on the host side is the trusted host's job, and it sends
  only after reading.)

---

## Stage B3: Official image with the isolation ABI

**Dependencies:** Stage B2.

**Implements:** Layer 2, "fixed identity and initializer ABI"; the
`org.writ.agent-vm.isolation-abi = 1` label.

The Nix image sets the initializer as PID 1, fixes UID/GID 1000 with a
writable home, workspace, and Nix store owned by it, and stamps the label.
The label is self-asserted, so it is a *compatibility* signal (an old image
is refused for the right reason), not an identity: any image can carry it.
Identity is the image's resolved digest, which Stage D reads and E3 pins.
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

The placement check itself is already on `main`: the helper's install
precheck (`session_anchor_placement`) refuses to load a session's rules
unless `anchor "writ/session/*"` is present and preceded by neither a
`pass ... quick` rule nor *any other filter anchor*. What C2 adds is the
`preflight` command that reports that same classification as bounded JSON
without loading anything, so Stage D can use it as admission evidence. The second condition
is the important one: a main-ruleset readback shows an earlier anchor only as
its invocation line, not the rules loaded inside it, and a `quick` pass
inside `com.apple/*` is just as final as one in `pf.conf`. So the only
placement preflight can vouch for is writ's anchor ahead of everything else
that filters, and the installation docs say to put it there. The precheck
also refuses any loaded translation rule with the `pass` modifier
(`ensure_no_pass_translation_rules`): translation runs before filtering,
and such a rule passes matching packets without consulting any filter rule,
so it bypasses the session anchor wherever the anchor sits. This is
host-local state no version pin captures.

`install` and `--deny-guest-ipv6` then run: precheck, resolve, `pfctl -n`
syntax check, load, `pfctl -sr` readback parsed to the ruleset type and
compared for equality with the intended one, resolve again and compare
interface names. Any mismatch is an error *after* the anchor has been loaded,
so the helper's result says which phase failed and the daemon treats the
session as unreleasable (it is already fail-closed on any helper error).

**Correctness oracle:**
- `preflight` over generated main rulesets: reports present-and-first iff
  the anchor line exists and every earlier line is neither a `quick` pass nor
  an anchor invocation; a `quick` pass or another anchor after writ's, or a
  non-quick pass or a scrub/nat/rdr anchor before it, is accepted.
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
existing `--deny-guest-ipv6` step (the interfaces are known there). The
subnet-scoped rules that `InstallFirewall` loads before the VM exists are a
bootstrap anchor only: the post-attach load *replaces* them, because a
`quick` rule matched on the session `/24` would otherwise fire first for a
frame with that source arriving on an unrelated interface, and the anchor
would be deciding traffic it has no business deciding. The property that the
two placements will share one renderer applies here first.

**Correctness oracle:**
- Property over generated session facts and interface sets: the post-attach
  anchor's rule list, in order, is per interface an IPv4 allow for the broker
  tuple, an IPv4 default deny, and the IPv6 deny, and contains no rule
  without an `on <iface>`; the bootstrap anchor is the subnet-scoped pair as
  today; render → parse is the identity for both.
- A pure packet-decision model over the rendered rules: for every generated
  IPv4 packet on a resolved interface, only the intended broker tuple passes,
  regardless of source; on an unrelated interface the anchor decides nothing.
- `scripts/prove-agent-vm-lifecycle.sh` gains the spoofed-source probe from
  the root guest and asserts the labelled IPv4 deny counter rose, with the
  unconfined-control clause from E3 applied once E3 exists.

**Landed, with one deviation on the third oracle.** The root guest cannot
send a spoofed-source probe: #402 dropped `CAP_NET_RAW` from the released
workload, and `container exec` inherits that. The lifecycle proof instead
asserts every rule of the loaded anchor carries `on <iface>` and grades an
in-subnet probe to a forbidden host port on the labelled IPv4 interface
deny's counter, which shows the rule the readback names is the rule deciding
the guest's frames. The spoofed sender is the separate probe container of
question 4 under "Beyond E3", where it also answers whether vmnet forwards
such a frame.

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
file has landed), the helper's `preflight` report on the main ruleset (C2),
the image's ABI label *and resolved manifest digest* read via bounded
`container inspect` (B3), the Apple `container` CLI version line, and the
macOS build from `sw_vers`. The digest is what `container run` is later
given, never the tag, so the image inspected is the image started. Add
`ConfiguredIpv6Profile::admit_locked(evidence, allowlist)`, the pure decision
over an explicit allowlist of proven (CLI, macOS build, image digest)
records, and the daemon-side gatherer that produces the evidence by running
the probes with bounded output. Production passes the shipped allowlist,
empty until E3; tests pass synthetic ones. `ConfiguredIpv6Profile::admit` is unchanged
and still refuses `Ipv4OnlyLockedV1`; nothing calls `admit_locked` yet.
`Ipv6IsolationMode` does *not* yet gain a variant: no session can run in the
mode until E2, and the state store must not be able to say one does. Salvage
the three parsers from the stage-1 branch; do not salvage
`decide_agent_vm_start`, and do not add a bypass field to the plan.

**Correctness oracle:**
- Exhaustive over `admit_locked` with a synthetic allowlist: every
  combination of {helper v1, v2, unparseable} × {preflight ok, anchor absent,
  quick pass ahead} × {label absent, 0, 1, unknown} × {digest listed, other,
  unparseable} × {CLI listed, other, unparseable} × {macOS build listed,
  other, unparseable} is tested, and only the one admitting combination
  yields `Ok`; each refusal names the wrong fact. With the empty production
  allowlist, every combination refuses.
- The gatherer with a fake tool: each probe's output is bounded and a probe
  that hangs, over-produces, or exits non-zero yields the corresponding
  "unparseable" evidence, never a panic or an admit.
- The existing "closed profile refuses new sessions and creates nothing" test
  still passes unchanged: `admit` did not change, so `locked_v1` is refused
  before any probe runs.

**Landed, with five notes.**

The probes run through `process_supervisor::run_supervised`, not a bare
`tokio::time::timeout` over a captured child: the privileged probes are `sudo`
wrapping the helper wrapping `pfctl`, so a deadline that killed only the
direct child would leave a wedged `pfctl` holding the captured pipe open and
accumulating with every refused start. The group kill cannot reach the *root*
half of that chain (an unprivileged daemon's `kill(2)` on a root process is
`EPERM`), so the stated guarantee is the weaker one: the daemon stops waiting,
reports the fact unreadable, and does not admit, possibly leaving a wedged
root helper behind. A test of its own drives a probe that *forks* the hang and
waits on it rather than `exec`ing it, reads the descendant's pid while the
probe is still running (so a slow shell delays the test instead of failing it)
and asserts the pid is gone afterwards; it fails against the
direct-child-only version.

Being the first caller to spawn through `sudo` also exposed a latent flaw in
the shared supervisor: its timeout and cap-rejection arms tolerate `EPERM`
from `killpg` as "the group is already empty", then reap the leader with an
*unbounded* `wait`. That reasoning holds for a child the daemon could have
signalled and fails for one that raised its own privilege — the call would
then block forever, which is the one thing the whole-call deadline exists to
rule out. The reap is now bounded by a grace period and abandoned after it, so
the worst case is `timeout + POST_KILL_REAP_GRACE`. A test reproduces the
state portably, without root, by having the child leave the process group the
supervisor made for it: the kill then reports success against a live child,
exactly as `EPERM` does. It hangs against the unbounded version.

The gatherer is a free `gather_locked_v1_evidence(&LockedV1ProbePlan)` rather
than a method on the daemon, and the plan is built by
`LockedV1ProbePlan::for_host(tools, image)` from exactly what the daemon
config already holds. Nothing on `AgentVmDaemon` calls it: a daemon method
with no caller would be dead weight until E2 wires the locked start path.

The evidence is six flat observations rather than five, because the label and
the digest come from one `container inspect` run but fail separately: a label
value that is not a decimal version leaves the digest perfectly readable. The
gatherer maps a document it cannot parse at all onto both facts unreadable, so
the plan's `{label} × {digest}` grid is still swept in full.

The allowlist is read as a trie keyed (CLI, macOS build, image digest), so a
refusal names the level at which the observed platform left it: "this CLI is
in no record" and "this proven CLI was never proven with that image" are
different sentences, and the sweep asserts every refusal names a fact that is
genuinely wrong in that cell rather than merely refusing.

Two things were made single-source on the way past. `PfPreflightUnclean` is
now the one definition of "this report does not permit an install", which
`PfPreflightReport::require_clean` converts into the operator-facing
`PfctlError`, so the install precheck and the admission evidence cannot
disagree about the same report. And the ABI label's *spelling* joins its value
in `crates/writ-guest-init` (`isolation-abi-label`, read by both the crate and
`flake.nix`), because a host looking for a label the image does not stamp
would refuse a correct image.

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

**Landed, with five notes.**

Four holes a review found over three rounds, every one the same shape: the
snapshot union is publicly constructible, so the store is the only thing
between a caller and a record, and each guard it had covered one field. The
first was separate — `FirewallFacts::new` now refuses an empty interface set,
because a value the writer could build and the reader could not accept is a
record that stops reconciliation reaching *any* session (`load_all` fails
whole) — and so was promoting a cleanup-only v2 record, now refused outright
because it would rewrite the record as v3 and leave the caller holding a value
that no longer matches the disk.

The other two (a `Claimed` record advanced straight to `WorkloadReleased`; an
advance that rewrote the interfaces, and then the guest ABI, an earlier phase
recorded) were whack-a-mole, so the guards are gone. `advance_locked` now
makes one comparison: rewind the proposed snapshot a step
(`LockedLifecycle::previous`) and require it to equal the recorded one. That
asks, in a single equality, every question the field-by-field guards had to
remember to ask, and a phase that later gains a fact is covered without
touching the store. The property `an_advance_is_exactly_a_rewind` states it
over facts that vary independently of the phase, with a companion test
pinning that the generator reaches both answers; the pre-review guard fails
it. That property runs fewer cases than the default on purpose: each case
writes and re-reads a real fsynced record, and what the rule *says* is
covered exhaustively and for nothing by `rewinding_a_snapshot_yields_the_one_before_it`,
so the store-backed cases only have to show the store applies it.

`QuarantineInstalled` and `BrokerReady` are not in the code. Vm placement
refuses new sessions (#396), so a phase no session can be in would be a
representable state nothing can reach — the same argument that keeps
`Ipv6IsolationMode` a smaller set than `ConfiguredIpv6Profile`. They land with
the placement, and the design record says so.

The model is two types, because moving forward and looking back are different
problems. The typestates carry a live start; each is constructible only by
consuming its predecessor, so the stage's "`ReleaseAttempted` is
unconstructible from any other pair of phases" is the compile-time fact the
oracle allowed for rather than a test. The snapshot `LockedLifecycle` is what
a record says: a union with one variant per phase carrying that phase's facts,
so the reader refuses a released session that names no interfaces instead of
handing teardown an empty list.

"Persisted before the signal is sent" is structural, not ordered by hand.
`ReleaseSignal` wraps the `container kill --signal USR1` and has no
constructor outside the state store, which mints it only after writing
`ReleaseAttempted`; `advance_locked` refuses to write that phase at all, so
there is one door and it is the one that hands over the signal. The test
covers the outcomes that matter — the kill succeeded, failed, or never ran
(where a timeout and a daemon that died before sending both land, since
neither leaves the host any more certain).

Locked records exist only in tests until E2, through two `#[cfg(test)]`
helpers (`with_locked_lifecycle_for_test`, `overwrite_for_test`). They bypass
no gate: admission is `ConfiguredIpv6Profile::admit`, which refuses the
profile outright, and nothing in production builds a `LockedLifecycle` because
nothing builds the typestates that make one. E2 replaces them with the real
start path and should re-run the phase sweep against it.

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
macOS build, image digest) record in the same change that records its proof
passing. That is what keeps a stage landing on its own from exposing an
unproven path. Both
front doors open together: `writ-agent-vm-runner start` and `managed-start` call the same
library gatherer as the daemon and pass its evidence to the same `admit`, so
the runner cannot start a locked session on a host the daemon would refuse.

Nothing here is a proof. It is the daemon doing the locked sequence under the
fake tool, with every step's failure leaving the workload unreleased.

This stage is built in three branches. The observers come first and the
profile opens last, so no commit leaves `Ipv6IsolationMode::Ipv4OnlyLockedV1`
representable without a start path behind it:

- **E2a**, the host's read side of the guest record channel: the bounded
  `container logs` read, the scan that decides what a log reports, and the
  release gate's precondition. No caller; the profile stays closed.
- **E2b**, the locked start's invocations as data: the `container run` argv
  carrying B1's capability profile and the image's digest, and the
  `container kill --signal USR1` that E1's `ReleaseSignal` wraps. Still no
  caller.
- **E2c**, in three parts, because building it found that the locked start
  does not fit the machine the legacy one runs on:
  - **E2c-1**, the mode itself. `Ipv6IsolationMode` gains `Ipv4OnlyLockedV1`,
    the state schema gains its spelling, every place that dispatches on the
    mode answers for it, and the locked sequence is projected as its own
    ordered data. `admit` still refuses the profile.
  - **E2c-2**, the daemon interpreting that sequence through E1's typestates.
  - **E2c-3**, in three parts of its own — see below; the profile opens last,
    on an empty host-placement pin list.

**Correctness oracle:**
- Fake-tool daemon tests: the recorded `container run` argv contains exactly
  the B1 profile, and the started VM is *read back* and found to carry the
  digest that was inspected (see E2b's note: naming a local image by digest is
  not possible on this runtime, so the guarantee is taken by readback);
  `USR1` is sent iff the ready record was observed, the broker
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

**E2a landed.** `agent_vm_guest_log` reads the channel and `agent_vm_probe`
holds the bounded-run policy it shares with Stage D's evidence gatherer, which
now goes through it rather than keeping a second copy.

Two decisions are worth the reviewer's attention. The read is plain
`container logs <vm>`: `-n` keeps the *last* n lines, so a guest that flooded
its log could push the record out of the window and be read as silent, where
reading it all and refusing the overrun fails closed instead. And a line
wearing the record prefix that does not parse is refused rather than skipped,
because the prefix is the initializer's — a line carrying it that the host
cannot read is a disagreement about the handoff contract, not noise.

The ABI check is here as well as in Stage D's admission, and they check
different things: D reads the label an *image* stamps, this reads what the
*running* initializer announced. Both compile from one file in
`crates/writ-guest-init`, which is what makes a disagreement between them
worth refusing.

One bound is a judgement rather than a measurement. A read that the release
budget (rather than its own deadline) cut short reports `Silent`, not a tool
timeout: with no time left the host cannot tell a wedged `container logs` from
a guest that had not spoken yet, so it makes the weaker claim. A wedged tool
with budget to spare still reports the timeout, and a test pins the
distinction.

`overall_timeout` is the whole wait, not the wait plus one poll interval: the
sleep between reads is capped by what is left, the same way each read is. That
cap is a pure function (`next_poll_sleep`) with a property over every
combination of interval, budget and elapsed time, because the first two
attempts to test it by *timing the loop* measured process spawn latency
instead — one passed under the weakening it was written for, and the other
failed the full suite on a budget that a cold spawn exhausted. A bound that
can be stated purely should not be tested against a clock.

Four weakenings were injected and fail these tests: a scan that skips a
malformed prefixed line, one that takes the first of two records, a wait that
releases on any announced ABI, and a `next_poll_sleep` that ignores the
remaining budget.

A record must begin its line, because accepting one embedded in a longer line
hands the framing to whoever wrote it. That rests on `container logs`
returning the guest's stdio lines undecorated, which was measured rather than
assumed: on Apple `container` 1.4.1 (macOS 25G72), a container whose command
`printf`s one line yields exactly those bytes and a bare newline — no
timestamp, no prefix, no carriage return — and the kernel's messages are on
`--boot`, where the record never appears.

---

**E2b landed, with two measured departures from this plan.**

`agent_vm_locked_start` holds the readback and the launch's locked-only
pieces; `AgentVmSessionPlan::locked_start_vm_invocation` assembles the argv
from the same `base_run_argv` the legacy launch uses.

**The image cannot be named by digest.** Apple `container` 1.4.1 resolves a
`name@sha256:…` reference against the registry — `container run
writ-agent-vm-guest@sha256:…` fails with a 401 from `registry-1.docker.io` —
and the guest image is built locally and pushed nowhere; a bare digest or
image id is refused outright ("cannot specify 64 byte hex string as
reference"). Only a tag names a local image. So the guarantee is taken the
other way round, the way Stage C2 takes it for PF: name the tag, then read the
container back with `container inspect` and refuse to go on unless it carries
the admitted digest.

The readback has to happen **before the container runs**, so the locked launch
is `container create` then `container start`, not `container run`. `create`
resolves the tag and records the resolved digest, capability set, `/proc`
relaxation and first process while the container is still `stopped`, and a
review round caught the first draft getting this wrong: it used `run` and
argued the window was harmless because PID 1 would be the initializer waiting
for release. That reasoning is circular. If the tag were repointed between
admission and launch, the replacement image's PID 1 is whatever its author
chose, need not wait for anything, and would already be running behind only
the bootstrap firewall. `container inspect` reports `image.descriptor.digest`,
`capAdd`, `capDrop`, `readonlyPaths` and `initProcess`, so the readback checks
the image, the capability set, the `/proc` relaxation, and that PID 1 is the
initializer running as root. That is stronger than the reference would have
been: a reference says what was asked for, the readback says what the runtime
built, which is where a flag that was accepted and ignored would show up. The
window it leaves is empty — PID 1 is the initializer and has published no
`security-ready`, so nothing repository-controlled has run.

Two things the readback caught immediately. `container inspect` spells
capabilities `CAP_CHOWN` where `--cap-add` spells them `CHOWN`, so a readback
that compared the strings it sent would have passed on any container. And
`useInit` has to be part of the verdict: the runtime's own init process
becomes PID 1 and the configured executable its *child*, so every claim about
"PID 1" — including the release gate's later read of `/proc/1/status` — would
be about the wrong process.

**The locked launch must relax `/proc/sys`, and must not use the kernel-line
IPv6 disable.** vminit mounts `/proc/bus`, `/proc/fs`, `/proc/irq` and
`/proc/sys` read-only, and the B1 handoff *must* write `disable_ipv6`
(`Ipv6Sysctl::must_exist` makes a missing one a handoff failure, because the
verification step relies on it). Measured: the write fails with `EROFS` even
holding `CAP_NET_ADMIN`, so under the defaults the locked handoff cannot
complete at all. `--read-only-path` is additive except for `NONE`, which
clears the defaults, so the launch clears them and gives back all but
`/proc/sys` — measured to leave `/proc/sys` writable and `/proc/irq` still
refused. The relaxation is spent inside the trusted window: PID 1 writes the
sysctls, drops every capability, and becomes 1000:1000, after which the
workload can no more write them than under the default mount. The path list is
version-specific, which is safe because Stage D pins the CLI version as a
whole record.

The legacy profile's `--kernel-arg ipv6.disable=1` is therefore *excluded*
here: it removes `/proc/sys/net/ipv6` entirely, which is exactly the
`disable_ipv6` the handoff requires to exist. The two enforcements are
mutually exclusive and the locked profile takes the one whose completion it
can observe, with host PF the backstop either way. A test asserts the kernel
arg is absent, naming that reason.

Nine weakenings were injected and fail these tests: a readback that compares
the argv spelling of a capability, one that ignores the `/proc` relaxation,
one that ignores PID 1's identity, one that ignores `useInit`, a launch that
swaps the relaxation for the legacy kernel argument, and a launch that goes
back to a single `container run`.

---

**E2c-1 landed, and found that the locked start is a different machine.**

`start_agent_vm_session` is synchronous, iterates `AgentVmStartStep`, and is
the entry point for *both* the daemon and `writ-agent-vm-runner`. The locked
tail does not fit it: waiting for the guest record is a bounded async poll,
and the release is minted by the state store rather than constructed by a
caller. Adding locked variants to `AgentVmStartStep` would have handed that
interpreter steps it has no way to carry out.

So the locked sequence is its own ordered type, `LockedStartStep`, sitting
next to the `LockedPhase` each step establishes. `AgentVmStartStep` is
untouched.

**A locked session is therefore managed-only, structurally.** Its release
signal exists only once the state store has recorded the attempt to send it
(Stage E1), so a start path with no store could start a guest, confine it, and
never release it. `start_agent_vm_session` refuses the locked mode before it
creates anything, and a test asserts nothing ran. That is also what the
`start_agent_vm_session` doc comment anticipated when it said a future closed
profile with an active mode would break its "a plan cannot carry a closed
profile" reasoning — this is that profile, and the refusal is the answer.

The mode variant's value right now is the compiler. Five exhaustive matches
had to answer for it, and — more to the point — five `== Ipv4OnlyNoGuestIpv6`
comparisons would have quietly handed a locked session the legacy answer.
Those are now `Ipv6IsolationMode` predicates (`requires_guest_command`,
`has_firewall_ipv6_cidr`, `startable_without_a_state_store`) named for the
question each site asks, so a mode added later must decide rather than inherit
a branch.

One test had to be rewritten rather than extended. Stage D's
`the_locked_spelling_parses_here_and_is_unknown_to_an_older_binary` used this
build's `Ipv6IsolationMode` as the stand-in for an older binary, which was
only valid while that type lacked the variant. The stand-in is now an explicit
two-variant enum in the test, so the rollback property is still tested rather
than quietly lost.

Two weakenings were injected and fail these tests: a storeless start that runs
the locked profile, and a locked mode that does not require a guest command.
The second exposed a tautology on the way — the first version of its test
asked `requires_guest_command` what to expect, so it passed whatever the
predicate said; the expected answers are now written out per mode, with a
length assertion so a new mode cannot slip through unanswered.

---

**E2c-2 landed.** `agent_vm_locked_session::run_locked_start` walks the
sequence: create, read back, start, install the interface-scoped anchor, wait
for the guest's record, then release. Two things move at every step — the
typestate that carries the proof forward, and the record that says what a
crash would find — and the record is always written before the effect whose
completion it would otherwise have to infer.

Three pieces had to land with it. A locked plan now claims a *locked* record
at `Claimed`, because `advance_locked` refuses a record that is not already
locked, so a locked session claiming a legacy one could never record a phase.
`start_steps` returns the shared prefix and stops for a locked plan, rather
than projecting the legacy `container run` a locked session must never make.
And the final firewall install is run capturing its output, so the interfaces
in `FirewallFacts` are the ones the helper resolved rather than any the host
guessed; an install that stopped short of `reresolve` is refused, because the
phases after the load are the ones that check the anchor says what was asked
for.

`GuestLogChannel` is passed in rather than built inside, so the bounds the
host waits under are the caller's to state — and so a test does not have to
sit out a budget sized for a VM boot.

The release ordering could not be weakened to test it, which is the outcome
Stage E1 was designed for: `send_release` needs a `ReleaseSignal`, and
`record_release_attempted` is the only thing that makes one, so there is no
version of this function that sends before recording. The test asserts the
consequence instead — the fake `kill` copies the session's record as it runs,
and that copy already says `release_attempted`.

A review round found two things the first draft got wrong, both about what
happens either side of the release. The configured guest environment was
dropped — the create was given no `--env-file`, so a managed session would
have started a VM that could not reach its own broker; the plan now
materialises the file and the create is given it, for exactly as long as it
takes to read it. And a record that could not be written *after* a successful
`kill` was classified as "never released", which is the one answer that is
certainly wrong: the signal had been delivered. That failure now says the
workload may be running, which is what the `ReleaseAttempted` already on disk
means.

A second round found a race this stage introduced. Every step ran under the
bounded probe, which stops *waiting* at its deadline but cannot stop the
process: the PF helper runs behind `sudo`, so the root half is beyond an
unprivileged daemon's `kill(2)`. Harmless for a read — the fact is simply
unread — but for an *install* it means the daemon could move on to teardown,
flush the anchor, and have the helper load its rules afterwards, leaving an
anchor behind for a session that no longer exists. The install is now waited
for, bounded in bytes but not in time, which is what the legacy launch does
with the same command. A test with a three-second helper fails the moment
anyone reintroduces a shorter deadline.

The same round asked for a pre-release read of the guest's `/proc/1/status`
against B1's `LockedAwaitingRelease`, and this stage deliberately does not do
it. The release is gated on two host-observed facts: the image the runtime
actually built — the readback also confirms PID 1 is the initializer, running
as root, with no interposed runtime init — and the initializer's own
`security-ready` record, which its handoff emits only after the capability
drop the record asserts. A `/proc` read would mean a `container exec` into the
guest, the move layer 2 exists to avoid, to learn something those two already
bound. What it would additionally catch is an *admitted image whose
initializer is buggy*: a real if narrow gap, and E3's to close with evidence
rather than this path's to close with an exec.

Six weakenings were injected and fail these tests: a readback whose verdict is
discarded, a firewall install accepted at a phase before `reresolve`, a create
that drops the guest environment, a post-release write failure classified as
unreleased, an install that fails, and one that floods.
Every failure before the release leaves the workload unreleased, asserted by
the absence of any `kill` in the fake tool's log rather than by inspecting the
code path.

---

## Stage E2c-3: the post-release channel, and the profile opens

**Dependencies:** E2c-2.

Three concerns, and the word between them is "and", so they are three
branches. The order is forced: the record channel is infrastructure the daemon
consumes, the daemon's use of it must work before a real session can reach it,
and the profile may only open once both hold.

One thing E2c-2 deliberately left to its caller has to become structural here.
`run_locked_start` sends the release whenever the guest says it is ready; the
design requires the host not to release until *its own broker* is up, because
the release is what tells the guest the broker exists (there is no
broker-ready file any more). A caller obligation in a doc comment is the shape
Stage E1 refused for the release signal, and it is refused here too: the proof
is a value the broker's own spawn produces.

---

### Stage E2c-3a: the post-release record channel

**Dependencies:** E2c-2.

**Implements:** Layer 2, "workspace-bootstrap success and bounded failure
records use the same host-side log channel as `security-ready`".

The locked guest's bootstrap script stops waiting for a broker-ready file —
being released *is* that signal — and prints versioned `bootstrap-ok` and
bounded `bootstrap-failed` records to PID 1's stdout instead of touching
sentinel files. The host gains a reader for them on E2a's channel.

The two record kinds share a channel and have nothing else in common, and the
reader must encode that. `security-ready` is emitted before any
repository-controlled code exists and gates release. A bootstrap record is
emitted *after* release, by code running as the same UID as PID 1, which can
print whatever it likes — so it ends a wait, is reported to an operator, and
carries no authority. The reader for bootstrap records must therefore refuse
to read a `security-ready` record as anything at all: a workload that prints
one is not making a claim the host will act on.

Inert: no caller. The legacy path keeps its files and its `exec` polling
untouched.

**Correctness oracle:**
- Property over fuzzed `container logs` output: a bootstrap record is read
  only when it is exactly a rendered record on its own line; a
  `security-ready` line is never read as a bootstrap outcome, however it is
  positioned; two bootstrap records are refused, as `security-ready` already
  is.
- The failure record's message is bounded exactly as today's failure file is,
  and a guest that floods the channel is refused rather than read in part.
- The locked guest script contains no broker-ready wait and no sentinel-file
  write, asserted against the script text; the legacy script is unchanged,
  asserted by its existing tests still passing.
- A weakening that reads a post-release `security-ready` as a bootstrap
  outcome fails these tests.

---

**E2c-3a landed.** The two vocabularies are separated by their *prefix*
(`writ-agent-vm-bootstrap` against the initializer's
`writ-agent-vm-guest-init`), which turns "a bootstrap reader must never read a
`security-ready` record" from a rule into something neither reader can do:
each sees only its own prefix. Both directions are stated as properties.

The scripts are not duplicated. The sentinel writes became two substitution
points — where success is reported, and where a failure reason is sent — so
the legacy profile's substitution reproduces today's scripts and a test
asserts exactly that, by putting the legacy signalling back into the locked
script and finding the legacy script. Any divergence in the nix prologue, the
egress gate or the workspace init fails there.

The failure emitter is shell, so its bound is `tr` and `cut` semantics rather
than an argument: `LC_ALL=C tr -c '[:alnum:][:punct:] ' ' '` leaves only
single-byte characters, which is what makes the `cut -c` bound a byte bound
and stops a split multibyte character growing when the host decodes it. A test
runs the real emitter under `/bin/sh` against reasons a guest can actually
produce — multi-line, control bytes, non-ASCII, four thousand characters — and
requires the host's parser to accept every result.

Three comments in the shared script fragments named the sentinel files; they
now describe what the code does under either profile.

One thing the existing tests caught: the first version of the shared scanner
counted prefixed lines before parsing any, which changed a landed answer — a
malformed line beside a valid record became `Repeated` instead of `Malformed`.
The shared helper now parses as it finds, so the first thing wrong with a log
in reading order is still the thing reported.

A review round caught two things, and the first was a straight miss against
this plan. The locked script was to stop waiting for the broker-ready file,
because being released *is* that signal — and it still had the wait. Nothing
in the locked start creates that file, so the script would have blocked
forever on it, never reaching the gate, the workspace init, or any outcome to
report. The wait is now part of the signalling scheme, present only where a
daemon touches the file.

The second: the failure bound kept the *head* of the reason. The sentinel path
deliberately tails its failure file because a workspace init that fails after
a great deal of progress prints the actionable error last, so keeping the
first 380 bytes keeps the progress and throws away the error. The emitter now
tails too, and a test feeds it forty lines of progress followed by a Nix error
and requires the error to survive.

Four weakenings were injected and fail these tests: a bootstrap reader that
accepts the initializer's prefix, a locked script that keeps writing the
sentinel files, one that keeps the broker-ready wait, and a failure bound that
keeps the head instead of the tail.

---

### Stage E2c-3b: the daemon runs a locked session end to end

**Dependencies:** E2c-3a.

**Implements:** Layer 2 host side, the remainder: the daemon's start arm
dispatching on the mode, broker-readiness as a precondition the types carry,
and the post-release wait on the log channel.

The daemon's start arm dispatches: a locked plan claims its record, runs the
shared prefix, and hands off to `run_locked_start`; every other mode is
untouched. `run_locked_start` gains a parameter that only the broker's spawn
produces, so the release cannot be ordered before broker readiness by a caller
that forgot — the same move `ReleaseSignal` makes for the record.

After the release, the daemon waits on the bootstrap record rather than
polling files over `container exec`. At that point a locked session has no
`exec` in its life at all.

**Correctness oracle:**
- Fake-tool daemon test over a full locked start: the invocation log contains
  no `exec` for a locked session, at any point — not merely after the `kill`.
- `run_locked_start` cannot be called without the broker-readiness value (a
  compile-time fact, as with `ReleaseSignal`); a test asserts the daemon's
  arm obtains it from the spawn rather than constructing one.
- A bootstrap failure is surfaced to the operator with its bounded reason, and
  the session is cleaned up; a bootstrap *success* is asserted to gate nothing
  that carries authority, by enumerating every consumer of the start's success
  (grants, proxies, staged pushes) and showing none keys off it.
- The legacy profile's start sequence is unchanged, asserted by its existing
  fake-tool tests.

---

**E2c-3b landed.** The daemon's start arm dispatches on the decision rather
than on the mode. `ConfiguredIpv6Profile::admit` now answers with an
`AdmittedProfile`, which mirrors `Ipv6IsolationMode` variant for variant and
carries the `LockedV1Admission` on the locked one — the readback accepts no
image but the admitted digest, so the digest has to arrive *with* the
decision, and pairing a mode with an optional admission would make a locked
decision without its evidence representable. `admit` still refuses the locked
profile, so nothing constructs that variant outside a test; that is E2c-3c's
line to change, and it changes one `match` arm.

Broker readiness is `vm_http::BrokerListening`. Only `RunningVmHttpSession`
produces one and only `spawn` produces one of those, so `run_locked_start`
cannot be called before the broker is up. It carries the port, and the start
refuses a proof naming a port its own plan does not advertise — which turns
the token from a ceremony into a check: "a broker is up" would have been
satisfied by *any* session's broker.

That ordering forced the arm's shape. A locked start runs only the shared
prefix here, because everything after it must happen with the broker
listening; `complete_locked_session_prefix` is that, under the same rollback
rule the legacy completion uses (a start that failed clean loses its claimed
record; one that failed dirty keeps it, because the record is the teardown
obligation). Spawning the broker earlier than the legacy arm does is safe, and
for a reason worth stating: the only guest process at that point is the
initializer, parked in `sigwait`, and the bootstrap anchor already allows the
broker port, which is what `spawn`'s own precondition asks for.

The post-release wait is `GuestBootstrapChannel`, a separate type from
`GuestLogChannel` over the same command. Not a second method, because the two
waits share only the command: one reads a log with a single trusted writer for
the fact that gates the release, under a cap sized for one record and a
hundred and twenty seconds; the other reads a log the released workload is
writing to, for an outcome carrying no authority, under the megabyte cap the
sentinel path already applies to a guest read and the twenty minutes a Nix
warm can take. Two types means neither can perform the other's wait, and the
one thing they do share — the bounded poll, including `next_poll_sleep` and
its property — is written once.

A locked session therefore has no `container exec` in its life at all, which a
fake-tool daemon test asserts over the *whole* invocation log rather than the
part after the release. Writing that test found a trap worth naming: the
`container create` argv contains the entire guest script, so a fixture logging
`"$*"` verbatim puts the script's own words where the test looks for
subcommands. The locked fixture flattens each invocation to one line.

"A bootstrap success gates nothing carrying authority" is a workspace guard
that enumerates the readers of `GuestBootstrapRecord` and `await_bootstrap`:
the module that defines them, the daemon arm that turns the outcome into a
started session or an operator-facing failure, and the test that holds the
guest's own emitter to the host's parser. A grant, proxy or staged push that
began consulting it fails the build. What the guard cannot see is the outcome
laundered through a third value; nothing does that, and the shape that would
make it impossible is not worth building for a value with one consumer.

A review round found the one thing none of that would have caught, because it
is about the *guest*: wiring the arm up made the locked profile reachable
against the official image for the first time, and that image's `HOME` is
`/root`, mode 0700. The locked workload is 1000:1000, and the setup script
runs under `set -eu` and writes `$HOME/.claude` before it can report anything
— so the container would have died with no record and the host would have
waited out the full twenty minutes. The daemon now sets `HOME` for this
profile alone, from `OwnedDirectory::Home`'s official-image path, which is
hoisted into the shared crate so the initializer's interpreter and the host
read one constant.

The test for it is not "HOME is set". Every directory the script writes to
before its first outcome has to be one the handoff chowned, and that is what
is asserted — over the env file a real locked start produced, against
`OwnedDirectory::ALL`. It fails without the fix and would catch the next path
added to the prologue.

A third round found the same mistake in its last hiding place. `--dry-run`
promises to print commands rather than run them, and that promise held for
free while admission was pure. It is not free now: a locked `start --dry-run`
was running all five probes, the privileged helper among them, before the
caller ever looked at the flag. A dry run for that profile therefore cannot
reach a plan at all — what follows the probes depends on what they say — so it
prints *the probes*, which is the honest preview and the only part of the
start a dry run can know. `ConfiguredIpv6Profile::is_decided_by_the_host` is
the pure question a caller that must run nothing asks first.

A fourth round found the last one, and it is the most consequential. Deciding
the profile had been hoisted out of `accept_agent_run_session` — that function
is not `async` on purpose — which put the five probes *outside* the
pending-run bound `enqueue` takes. Concurrent requests could therefore have
writd probing on their behalf without limit: the bound went on bounding the
runs writd remembers and stopped bounding the work it does per request.

So admission moved back inside, after the bound, and `accept_agent_run_session`
became `async`. What its old signature was protecting survives — writd still
starts nothing before the caller is told the run's name — but the reason it
awaited nothing has expired: a decision that *is* work cannot be made
anywhere cheaper, and every other refusal in that function is ordered against
the bound for exactly this reason. `place` is now held across the probes, so
the number of requests that can have writd probing at once is the number of
runs it will admit. The existing spawn-hygiene-style guard on that function
gained the ordering as a second assertion, beside the one that says this is
the only place that enqueues.

A fifth round found the raw start route, which has no queue place to bound it
with and takes its subnet lock only *after* the decision. The answer there is
not another bound but not doing the work N times: the probes ask a question
about the host, so concurrent starts were running five subprocesses each to
learn the same thing. An `admission_lock` serialises the gathering. The trade
is stated rather than assumed — a waiter queues instead of being handed the
answer gathered before it asked, because admitting a session on evidence that
predates the request is a staleness this gate should not take on.

Its test detects the overlap *in the probe* rather than timing the loop: the
fake writes a file while it runs and records any second probe that finds it
there, so what the test observes is a fact about writd rather than about how
fast the machine is.

The same round found a fixture that was green for the wrong reason. The
probe-host sweep's `container image inspect` output was a plausible-looking
shape rather than the real one, so `ImageInspection::parse` refused it and two
of the four hosts refused over the *same* fact — a sweep over four hosts that
was really a sweep over three. The test had only asserted that something
refused. It now asserts *which* fact each host's refusal is about, which is
what makes the sweep a sweep.

That is five places in this slice where a pure function becoming effectful
broke something downstream, and the pattern is worth naming: every caller
relying on admission being free had to be found, because none of them said so.
The compiler found the ones the `async` boundary touched and a reviewer found
the rest. A type that made "this is now work" visible to callers would have
found them all; `async` was that type where a signature changed, and for the
rest the cost was invisible because nothing about an ordering says what it is
protecting.

Six weakenings were injected and fail these tests: a locked session wrapped
with the sentinel scripts, a release that accepts any listening broker, an
`exec` anywhere in the locked path, a bootstrap reader that ends its wait on a
`security-ready` line, and a locked guest left with the image's `HOME`.

---

### Stage E2c-3c: the profile opens

**Dependencies:** E2c-3b.

**Implements:** Persistence and compatibility, the admission half:
`ConfiguredIpv6Profile::admit` consulting `admit_locked`, and both front doors
agreeing.

`admit` becomes evidence-taking for the locked profile: the daemon gathers
Stage D's six facts and passes them to `admit_locked` with
`ProvenPlatforms::shipped()`, which is **empty**. So at the end of this stage
the profile is open in the code and admits on no host at all; Stage E3 adds
the first (CLI, macOS build, image digest) record in the same change that
records its proof passing.

`writ-agent-vm-runner`'s `start` and `managed-start` call the same library
gatherer and the same `admit`, so the runner cannot start a locked session on
a host the daemon would refuse. Note the storeless `start` refuses the locked
mode regardless (E2c-1): admission parity is about not acquiring a profile
through a second front door, not about the raw path gaining a capability it
structurally cannot have.

**Correctness oracle:**
- `admit` yields `Ipv4OnlyLockedV1` under exactly D's admitting evidence and
  refuses otherwise, swept over the same grid D sweeps.
- The "creates nothing" test runs for every refusing combination: no
  subprocess beyond the probes, no audit row, no state record.
- The shipped allowlist admits nothing, and a test asserts every entry in it
  names a proof record — vacuously true while it is empty, and the assertion
  that stops it being filled in without one.
- The runner refuses every evidence combination the daemon refuses, with the
  probes faked, and builds a locked plan only under the admitting one.
- Stop and reconcile of a persisted locked session need no evidence: the
  persisted-session tests run under a daemon whose evidence gathering is
  scripted to fail.

---

**E2c-3c landed, and deleted a front door rather than adding a second.**

`ConfiguredIpv6Profile::admit` is gone, and with it `Ipv6ProfileClosed`. There
is one door, `admit_on_this_host`, and it is exhaustive on the configured
profile: two profiles are decided on their spelling and read nothing off the
host, the locked one gathers Stage D's six facts and asks `admit_locked` with
`ProvenPlatforms::shipped()`. The daemon and `writ-agent-vm-runner` both call
it, so parity is not something a test has to check — there is one function and
both callers are it. What the runner's test checks is that it *is* that
function: the refusal is the sentence `LockedV1Refused` words, not one of the
runner's own.

Deleting the pure `admit` was the whole point. A profile whose answer depends
on the host cannot be decided by a pure function, and keeping one beside an
evidence-taking one would have been exactly the second front door this stage
exists to avoid.

The cost of asking changed, and the code had to say so. Admission was free and
asked wherever the answer was wanted; it is now five subprocesses, so it is
asked once per start and threaded. `accept_agent_run_session` is deliberately
not `async` — a caller gets its run's ids without writd awaiting anything —
so it *takes* an `AdmittedProfile` rather than deciding one, and
`AcceptedAgentRun` carries it to the start. Accepting a run therefore cannot
happen without a decision having been made, and the decision the start uses is
the one the caller was answered on.

The two types stopped being different sizes. `ConfiguredIpv6Profile` and
`Ipv6IsolationMode` are now variant for variant the same set, so the
justification in their docs — "the configured set must name profiles that
exist only to be refused" — was no longer true and was rewritten rather than
left standing. What keeps them apart is standing, not size: one is a request,
the other is proof a session may run in it. The test that asserted the
configured set was larger is replaced by one asserting the two spell the same
profile the same way, so an operator reading a state record reads their own
word back.

A shipped allowlist entry is now four fields, not three: the fourth is the
dated proof run that put it there. The first attempt at this was a
`docs/proven-platforms.md` the test `include_str!`d, and the Nix gate rejected
it — the build's source filter excludes `docs/`, so the file was simply not
there. That was the better answer arriving by the shorter road. A field cannot
be forgotten the way a cross-file convention can: there is no way to write an
entry without being asked where the proof is, and
`every_shipped_platform_names_a_dated_proof_run` refuses an answer with no
date in it, because a proof is a statement about a moment. Its own predicate
is tested against the answers that dodge the question (blank, "proven", "see
the plan"), since the list it guards is empty and would otherwise not say a
word until the first platform was added — the moment it is needed.

The refusal's cost is asserted against the probe plan rather than against a
list of commands somebody thought to exclude: the daemon's fake logs every
argv, and every line must be one of `LockedV1ProbePlan::for_host`'s. Swept over
four hosts that refuse over different facts, because what a refusal costs must
not depend on which fact refused it.

Reconcile is the other half of that. Its test now runs under a host whose
probes all fail *and* asserts no probe was run at all — not merely that
teardown tolerated a refusing host, but that it never asked. A daemon that
gathered evidence on the way to a teardown would be one an unreadable host
could not be cleaned up on.

One thing could not be weakened, which is worth recording as a success rather
than a gap: `LockedV1Admission` has no public constructor, so an attempt to
have the door return an admission carrying a digest other than the probed one
does not compile.

A review round caught two things, and the first was a self-inflicted ordering
regression. `accept_agent_run_session` checks the broker placement first, and
its comment says why — placement is the more specific answer, since the
agent-run route does not exist on the v1 broker VM under any profile. Moving
the profile decision *out* of that function inverted the order the comment
describes: a vm-placement config would have waited out five probes to be told,
in the wrong words, something that was true before they ran. The decision for
this route is now `admitted_profile_for_agent_run`, which checks placement and
then probes, and a test asserts a vm-placement agent run is refused with
nothing in the tool log at all.

The second is the test suite depending on the machine it runs on. The runner's
admission test used bare tool names, which `PATH` resolves — so on a
configured development host the probes found the *real* `container` and the
real helper, and what the test observed became a fact about that host. Fixed
twice over: the paths are absolute and unresolvable, and the assertion is on
the refusal's *type* rather than its wording, because the claim is that this
door hands back what the shared one produced. `build_start_plan` stopped
stringifying the refusal so the test can say so by downcasting.

Five weakenings were injected and fail these tests: an allowlist entry whose
proof run names no date, a door that probes a host other than the one it was
asked about, a door that probes for the profiles decided on their spelling, a
reconcile that asks admission on its way to a teardown, an agent-run route
that asks about the profile before the placement, a dry run that asks for a
decision before it looks at the flag, an accept that probes before taking its
place in the queue, a placement check moved after the probes, a daemon that
gathers admission concurrently, and the fixture whose image-inspect document
was the wrong shape.

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
  zero; the pre-release `/proc/<pid>/status` read matches B1's
  awaiting-release acceptance type (`LockedAwaitingRelease`). The change that records this passing is the change that adds the
  host's (CLI, macOS build, image digest) record to the host-placement
  allowlist; the allowlist test asserts every entry names a proof record.
- The proof fails, each with a distinct message, when the positive control
  does not reach its listener (observer broken), when the listener tool is
  missing, when the legacy run's RA route never returns, and when a locked
  run's counter is non-zero.
- Under the locked image, the attack binary's own diagnostics show each
  attack failing at the syscall as UID 1000, and the host verdict is
  unchanged with those diagnostics deleted.

---

## Stage E3, in five parts

E3 is one stage in the design and five in the doing, because "grade on
host-owned facts" is four separable changes to the harness and a run on
hardware, and only the last of them needs a Mac with `container` on it. The
order is forced the usual way: the grader is what the rig feeds, the rig is
what the attack binary exercises, and the record can only be written by a run
that passed.

What exists already, and is not rebuilt here: Stage C3's `PfCounterSnapshot`,
its `delta`, and the helper's `counters` command, which reads one anchor's
labelled rules as a typed document. What does *not* exist is a consumer: the
harness still scrapes `pfctl -vsr` with `awk` of its own, which is the thing
E3's evidence rules are about.

One thing the survey settled. The session anchor's `pass` rules are
deliberately unlabelled, so they carry no counter key and the typed document
covers the **denies** only. That is the right shape for this stage rather than
a gap to close: the denies are what the two profiles disagree about, and the
positive control is graded by a host listener seeing a host-minted nonce, not
by a pass counter. The harness keeps its ad-hoc read of the pass counters
where it already uses them — diagnosing a failed positive control — and
nothing grades on them.

---

### Stage E3a: the grader reads counters, not text

**Dependencies:** C3.

**Implements:** Evidence protocol rule 1 (the host grades on what the host
read), for the counter half.

The harness's `pf_iface_deny_packets` becomes two readings of the helper's
`counters` document either side of a host-timed window, and a pure grader over
their `delta`. The expectation is inert data with one variant per profile:
the legacy profile's denies must rise by at least the number of probes
commanded, the locked profile's must not move at all.

The typed read is stronger than the `awk` it replaces in a way worth stating:
`PfCounterSnapshot::delta` refuses two readings whose key sets differ or whose
counters fell, so an anchor reloaded mid-window is an error rather than a
plausible-looking small delta. The `awk` could only ever have read that as a
number.

**Correctness oracle:**
- Property over pairs of snapshots: the graded rise equals the summed rise of
  every interface-scoped IPv6 deny key, and no other key contributes.
- A window in which the anchor was reloaded is refused, not graded.
- `Unmoved` is met by exactly a zero rise, and `RoseByAtLeast(n)` by exactly a
  rise of `n` or more; each refusal names the reading it saw.
- A weakening that grades on the sum of *all* deny keys, or that reads a
  missing key as zero, fails these.

---

**E3a landed.** `agent_vm_proof::grade_deny_window` is the pure grading, and
`writ-agent-vm-proof deny-window` is the unprivileged binary the harness
shells to. The harness's IPv4 leg — the one that already grades on a deny
delta — is its first consumer; the IPv6 window arrives with the rig in E3c.

The grader is its own binary rather than a helper subcommand on purpose. The
helper runs under `sudo`, and its job is to *read* PF; this decides what a
reading means. Building the grading into the helper would put a proof's
expectations inside the thing being measured, and running it as root would be
a second privileged surface for nothing.

Two refusals are worth naming, because they are what the `awk` could not say.
A window whose two readings have different key sets, or in which a counter
fell, is a window in which the anchor was reloaded — so their difference is
not a measurement, and `PfCounterSnapshot::delta` refuses it rather than
returning a plausible number. And an anchor with *no* rule of the family under
test counts nothing, which satisfies `Unmoved` perfectly; that absence is
`NoSuchDeny` rather than a reading of zero, which is the same fail-closed move
the `awk` made by dying unless a rule rendered with a counter.

The harness keeps its text-scraping read of the counters in one place: the
diagnosis of a *failed* positive control. Nothing grades on it, and a refusal
to parse would be the wrong answer there — the question is where the packets
went, not whether the anchor is well-formed.

A review round found a third way for a missing rule to look like a satisfied
one, and it is the same shape as the other two. A counter key is a label *and*
an interface, and the grader matched on the label alone — so a rule carrying
the interface-deny label but scoped to no interface counted as one. The helper
never files that pairing (a subnet-scoped deny gets a different label), but
the grader reads a *file*, and the wire format admits it: a document whose
only rule of that label was unscoped would have satisfied `Unmoved` with no
interface deny in it at all. Both halves of the key are matched now.

Four weakenings were injected and fail these tests: a missing rule read as a
zero rise, a rule scoped to no interface counted as an interface deny, a
grader that sums every deny key rather than the family's, and an `Unmoved`
that tolerates one stray frame. A fifth — ignoring the reloaded-anchor refusal
— could not be written: `delta` returns a `Result` and `?` is the only way
past it, so the refusal is structural rather than remembered.

---

### Stage E3b: what the guest says arrives as a claim

**Dependencies:** E3a.

**Implements:** Evidence protocol rules 2–4 (a guest-reported fact is not
evidence).

`Claim<T>` lands from `ipv4-lock/02-claim` and gets its first consumer. The
harness reads guest-reported facts today — `ip -6 addr`, `ip -6 route`, the
presence of `/proc/sys/net/ipv6` — and grades on them directly. They become
claims: readable into the diagnostics appendix, and unable to reach a verdict
except through `corroborated_by` against something the host holds.

The nonce is what the host holds. `Claim::corroborated_by` is available only
for `HostHeld` types, a sealed set that excludes `bool` on purpose, so a
guest-computed verdict has no upward path at all.

**Correctness oracle:**
- The module's own tests come with it, including the one that pins `Claim`
  having no `PartialEq`: `claim == Claim::asserted(true)` would recover any
  guest verdict without going near `HostHeld`, and an earlier version shipped
  exactly that.
- A test enumerates every guest-reported field the harness reads and requires
  each to be a `Claim`: a new one added as a bare value fails the build.
- The grader's verdict is unchanged when every claim is replaced with a
  hostile one — asserted by running the grading twice, once over the real
  diagnostics and once over fabricated ones.

---

**E3b landed.** `Claim<T>` is `src/agent_vm_claim.rs` (renamed from the parked
branch's `agent_vm_ipv6_claim`, since the claims it holds are no longer only
about IPv6), and its first consumer is `agent_vm_proof::guest`.

The harness no longer reads the guest at all. It has exactly two ways in:
`guest_report <slot>` asks one question and captures the answer unread, and
`guest_act` commands an action whose exit status is logged and ignored. The
answers are graded once, at the end, by `writ-agent-vm-proof guest-report`,
and the only thing they can do there is withdraw the verdict: each slot's
parser is host-authored and fail-closed, reads its capture into a
`Claim<bool>`, and from there into a `Doubt`, and `Doubt::shadowing` is the
only way a doubt reaches `SessionVerdict`. So a guest that reports holding
`NET_RAW` fails the proof, and one that reports not holding it has proved
nothing — and the run's summary now says exactly that, instead of listing the
guest's account among the things proven.

The report is a total map from `GuestSlot` to `Claim<RawCapture>`, not a
struct, so the "a new guest field added as a bare value fails the build"
oracle is structural: there is no field to add, and a new slot does not
compile until `GuestSlot::doubt` says how the host reads it. What is tested
is the link to the script: every `guest_report` slot there is a `GuestSlot`,
asked once, and nothing but the two helpers and the failure dump execs into
the guest. The "grading twice" oracle is a property: over arbitrary host
verdicts and pairs of arbitrary reports, the verdict is the host's or
withdrawn, and the best any fabricated report can do — the passing answer to
every question — is exactly the host's verdict.

Three legs that graded on the guest had to move onto host evidence, or stop
being claimed:

- **The positive control** (the guest reaches the broker) was the guest's
  `wget` exit status. It is now the broker listener's own access log, graded
  by `writ-agent-vm-proof listener-log`: a well-formed `GET /broker.txt` line
  answered 200 to the guest's address. The forbidden listener's log is graded
  the other way, fail-closed: any address of the session subnet anywhere in
  it, including an `accept` line or a traceback's `request from (…)`, is
  contact.
- **Direct internet and DNS** were graded only on the guest failing. Each is
  now its own counted window on the IPv4 interface deny, which is sound
  because a guest on an `--internal` network does get a default route via the
  host bridge (measured on `container` 1.4.1), so the first frame of each
  probe lands on an interface the anchor is scoped to. What that proves is
  narrower than the legs' names, and the run's summary says only the narrow
  thing (a fourth review round's point): the counter is not per destination,
  so a guest that sent some other blocked frame instead of the commanded
  probe satisfies it too. Destination-specific evidence is E3c's — evidence
  protocol rule 4 puts the experiment's nonce in its own PF labels. The
  forbidden-port leg is specific already, by its listener.
- **The guest's address**, which scopes the broker-log grading and the
  post-stop PF state check, was the guest's `ip addr`. It is now read from
  `container inspect`, which the runtime that allocated it answers.

The IPv6 legs have no host evidence yet, on purpose: the guest's account of
its posture before and after a root re-enable attempt is a doubt, and the
host's own IPv6 evidence is E3c's window and positive control.

When the broker reach is waived (`WRIT_PROVE_TOLERATE_BLOCKED_HOST_LISTENER`),
the guest's broker answer fails by construction. `guest-report --waived
broker-fetch` still withdraws the verdict; it exits 3 rather than 1 only when
that is the sole answer withdrawing it, so the waiver the harness asked for is
distinguishable from a guest answer it did not expect (and from clap's exit 2
for a misspelt slot, which grades nothing).

Weakenings injected and failing: the capability decoder reading only
`CapEff`; tolerating a missing capability set; leaving one slot unparsed;
ignoring the broker's body; ignoring doubt altogether; dropping the sysctl
check after the re-enable; reading listener silence from access lines only;
parsing whole digit runs rather than windows, which misses a `.port`-suffixed
address; and a serve that ignores the status. On the script side: an exec
outside the two helpers, a slot asked twice, a slot the grader lacks, and the
capture bound drifting between the script and the grader.

The script change itself runs only on hardware, and E3e exercises it.

A review round found three more ways for the new host evidence to read as a
pass, each reproduced before it was fixed:

- **A forged status.** `http.server` logs the request line verbatim, quotes
  included, so a guest sending `GET /broker.txt HTTP/1.1" 200 -` got a 400
  logged *after* its own `200`, and a parser reading from the front took the
  guest's. The status is now read from the end of the line, where only the
  listener writes, and the request must be exactly a GET of the path.
- **An accept with no request.** Plain `http.server` writes nothing at all
  for a connection accepted and closed without a request, so the forbidden
  listener's silence was not a witness. Both listeners now run
  `scripts/lib/accept-logging-http-server.py`, which is `http.server` plus an
  `accept <peer> <port>` line written before the request is read.
  `scripts/test-proof-helpers.sh` runs it on loopback and fails against plain
  `http.server`.
- **A truncated answer.** An answer that reached the capture bound was
  parsed from its retained prefix, and several parsers read only the lines
  they need, so a contradiction past the cut went unseen. Reaching the bound,
  as the host measured it on the bytes it kept, is now doubt in itself. So is
  an answer that is not UTF-8 (a second round's find): a lossy decode turns
  each bad byte into three, so an answer under the bound on disk overran it
  decoded, and the cut dropped a tail the byte count never saw. A third round
  found the in-memory constructor inferring the same fact from the retained
  length, which a cut inside a multibyte character leaves *under* the bound;
  there is now one constructor, over the bytes the guest sent, and both paths
  build through it.

**A finding for E3c and E3e.** The E3 oracles above say that under the legacy
profile "the root guest can re-enable IPv6, so the deny counters must rise".
That stopped being true with #415: the legacy launch now passes
`--kernel-arg ipv6.disable=1`, so a legacy root guest has no IPv6 stack to
re-enable and emits no IPv6 at all — which is exactly what this harness's
re-enable leg asserts. Under both profiles, then, the protected workload's
IPv6 deny counter is expected to stay at zero, and "rose by at least the
commanded probe count" needs a sender that *can* emit IPv6 on the protected
session's network: a separately launched probe container attached there
without the kernel argument, not the workload. E3c has to decide that before
its oracle can be written.

---

### Stage E3c: the observation rig

**Dependencies:** E3b.

**Implements:** Proof obligation 1; evidence protocol rules 5–6.

The host mints a nonce, serves it from listeners bound to the bridge's ULA and
link-local addresses, and measures the deny delta across a window of two RA
intervals that the *host* times. The positive control runs in the same
invocation: a root guest from the proof image, on a network the proof creates
itself with no anchor on it, reaching an identical listener. Without it, a
protected session that reaches nothing proves only that the harness is broken.

**Correctness oracle:**
- On hardware: the positive control reaches its listener and the protected
  session's listeners accept nothing.
- Distinct failures, each with its own message, for: the positive control not
  reaching its listener, the listener tool missing, and the legacy run's RA
  route never returning.
- The window is host-timed, asserted by the grader refusing a window shorter
  than two RA intervals — a bound that is pure and tested here, not timed on
  hardware.

---

### Stage E3d: the attack binary

**Dependencies:** E3c.

**Implements:** Proof obligation 2.

A guest-side binary attempting the eight attacks the design lists — sysctl,
rtnetlink, raw socket, namespace, proc alias, setuid, file capability, child
process — told its targets, reporting each outcome. Not a schedule language:
eight attempts and eight results.

Its output is diagnostics, never evidence. That is what E3b's shape is for,
and the oracle below is the one that proves it.

**Correctness oracle:**
- Under the locked image, each attack fails at the syscall as UID 1000, and
  the binary says which syscall and which errno.
- **The host verdict is unchanged with the diagnostics deleted.** This is the
  load-bearing one: it is what makes the attack binary an explanation rather
  than a source of truth.
- The binary compiles for the guest target and is absent from the production
  image, asserted by the image's own rootfs scan.

---

### Stage E3e: the run, and the record

**Dependencies:** E3d.

**Implements:** the proof.

Run the harness on hardware, twice, once per profile. Then — in the same
change — add the host's `(CLI, macOS build, image digest)` record to
`SHIPPED_PROVEN_PLATFORMS`, with the dated proof run E2c-3c made a required
field.

**This slice cannot be done without the hardware**, which is the point: the
allowlist entry is the claim that the proof passed *there*, and nothing else
in this plan can make it true.

**Correctness oracle:**
- Legacy profile: positive control reaches its listener; the protected
  session's listener accepts nothing; deny counters rose by at least the
  commanded probe count.
- Locked profile: positive control reaches its listener; the protected
  session's listener accepts nothing; deny counters are zero; the pre-release
  `/proc/<pid>/status` read matches B1's `LockedAwaitingRelease`.
- The profile admits on that host afterwards, and on no other — the allowlist
  is three facts about one machine.

---

## Beyond E3: what waits on the proof

Nothing past E3 is planned as a stage yet, on purpose. The rest of the
design — vm-placement quarantine and atomic replacement in the helper, the
broker VM's internal firewall in its ready document, the vm-placement locked
start, closing the two unlocked profiles, and soak, upgrade, and rollback —
depends on facts about this platform that nobody has measured, and a stage
written before the measurement gets an oracle that cannot be satisfied or,
worse, one that can be satisfied by the wrong implementation. Four rounds of
review on an earlier draft of this plan found a new such contradiction every
round; each was real, and each was in a stage past this line.

E3's proof is where the answers get recorded, as pinned facts about the
(CLI, macOS build) it ran on. The questions, and what each one decides:

1. **When does the host bridge exist, and when do members attach?** The
   helper derives interfaces from the gateway, so an interface-scoped
   quarantine cannot be installed before there is an interface. If the bridge
   appears only with the first VM, vm placement's sequence is: broker first,
   then quarantine, then agent. If it can be created earlier, the sequence
   simplifies.
2. **Does host PF see frames switched between two guests on the shared
   bridge?** Layer 3 exists because the design *assumes* it may not. If PF
   does see them, the broker VM's own firewall is defence in depth rather
   than the only boundary, and its readback need not gate readiness.
3. **Does PF see vmnet's router advertisements, and in which direction?**
   Decides whether the IPv6 deny needs an `out` half, and whether a guest can
   even acquire an address to attack from.
4. **Does vmnet forward a frame whose IPv4 source is outside the subnet?**
   Decides whether the source-scoped IPv4 rules are a live gap or a
   theoretical one, and so how urgent C2b is for the legacy profile. The
   sender half is now answered (2026-09-08, see the design doc's source-scoped
   delta): the legacy workload holds `CAP_NET_RAW` (Apple `container`'s default;
   the launch passes no `--cap-*`), so it *can* build such a frame — `IP_FREEBIND`
   is bind-only, so caps are the sender-side boundary. The open half is vmnet
   forwarding: measure it with a raw-socket sender inside
   `scripts/prove-agent-vm-lifecycle.sh` once C3's labelled deny counter exists,
   grading on that counter and/or a pcap-header parse of the bridge, with a
   positive control. Independently, the legacy launch now passes `--cap-drop
   NET_RAW` (#402), removing the sender-side capability regardless of the
   vmnet answer; a raw-socket sender for that measurement therefore has to run
   from a separately launched probe container, not the session's workload.
5. **What does `pfctl -sr` readback look like for a loaded session anchor on
   this platform** (rule order, label rendering, counter formatting)? C2 and
   C3 are written against the documented format; the proof confirms it.

When E3 has recorded those, the next plan revision adds stages for vm
placement with oracles that reference the recorded facts. Until then vm
placement keeps refusing new sessions and the parked harness branch stays
parked.

The two unlocked profiles are not left for that revision. Both still run the
root prelaunch, and invariant 9 admits neither on a host where the handoff
exists, so they close *per host* in the same decision that opens the locked
profile there. The decision has two levels. First, firewall safety: if
`preflight` reports that the session anchor is not reached, nothing admits,
because that is a fact about whether any session rule is consulted and no
profile survives it. Second, only when the firewall is safe: `admit` for
`ipv4_only_no_guest_ipv6` or `dual_stack_required` refuses whenever the
locked evidence on this host would admit, and admits otherwise. That lands in
E2 as part of `admit`, so E3's first allowlist entry closes the legacy
profiles on that host in the same change, and a host without a proof record
is never left with nothing startable for want of a pin, which is the #397
failure. The oracle is E2's existing exhaustive one, extended: for every
evidence combination with preflight failed, nothing admits; for every other
combination, exactly one of {locked admits, legacy admits} holds.
