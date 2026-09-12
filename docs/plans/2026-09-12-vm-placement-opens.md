# VM placement opens: implementation plan

Implement this plan with each stage on its own branch, stacked as necessary on
previous branches, so that a reviewer can review each branch in isolation.

The designs are
[`docs/vmnet-accept-bug-and-broker-vm-plan.md`](../vmnet-accept-bug-and-broker-vm-plan.md)
(§9, the broker-in-a-VM topology and its build order, of which steps 1–6
shipped as #229–#248) and
[`docs/design/ipv4-only-network-confinement.md`](../design/ipv4-only-network-confinement.md)
("VM placement (provisional)" and "Enforcement layer 3: broker-VM ingress").
This plan is the "next plan revision" that the IPv4-lock plan's "Beyond E3"
section defers to, brought forward for the reason below.

## Why now, and what changed

`broker_placement = vm` is code-complete and was shown on hardware
(2026-06-25) to sidestep the macOS vmnet `accept()` defect: the agent VM
reached the broker VM guest-to-guest and got an HTTP reply. It is also the
only placement the platform can serve in a release build of `writd`, because
the defect breaks every host `accept()` of a vmnet-originated connection
(reconfirmed 2026-09-08 and 2026-09-11 on macOS 26.6 with `container` 1.0.0;
the pure-C repro is unchanged). Yet the daemon refuses every new session
under VM placement (`Ipv6ConfinementUnavailableForVmBroker`, #396,
`src/agent_vm_daemon/daemon_impl.rs`), because host PF may not see frames
switched between two guests on the shared bridge and the broker VM installs
no firewall of its own. So today, on the development host, no placement can
start a session in a release build. The debug build is the only thing that
works, and it works by scheduling luck.

The IPv4-lock plan ordered VM placement after its Stage E3 proof, so that the
platform facts E3 measures would shape the VM-placement stages. That ordering
assumed host placement was a working product to prove first. It is not, on
this platform, so the facts are measured directly (Stage V0 below) and the
VM-placement stages follow from them. Stages D, E1, E2 and E3 of the IPv4-lock
plan are unaffected and can proceed in parallel; V4 states the one point of
contact (the `BrokerReady` phase).

Two actions run in parallel with this plan and are not stages:

- **Report the defect upstream.** No issue on `apple/container` mentions it
  (searched 2026-09-11 for `ENOTCONN`, `accept`, `getpeername`). File a GitHub
  issue there and a Feedback Assistant report, both pointing at
  `../vmnet-accept-repro`.
- **Run the C repro on a second Mac.** Every observation so far is one
  machine. If it does not reproduce elsewhere, host placement is a per-host
  problem and the urgency here changes; the plan does not.

## Facts measured on 2026-09-12 (macOS 26.6, `container` 1.0.0, guest kernel 6.18.5)

These answer the "Beyond E3" questions this plan depends on, except Q2, which
needs `pfctl` and is Stage V0.

1. **Bridge timing (Q1).** `container network create --internal` creates no
   host interface. The host `bridgeN` (carrying the gateway address) and the
   first `vmenetN` member appear with the first VM on the network; each later
   VM attaches one more `vmenet` member to the same bridge. So under VM
   placement the bridge exists once the broker VM is running, before the agent
   VM starts. The one-member interval holds only the trusted broker VM.
2. **Router advertisements on internal networks (part of Q3).** An internal
   network carries an IPv6 `/64` (`container network inspect` reports it) and
   a guest on it acquires a global ULA from it by SLAAC. Both the broker VM's
   internal interface and the agent VM therefore have IPv6 addresses unless
   something removes them; layer 3 must not assume otherwise.
3. **Guest-to-guest TCP works on an internal network** (reconfirmed).
4. **The guest kernel has nftables built in**: `CONFIG_NF_TABLES`,
   `NF_TABLES_INET`, `NF_TABLES_IPV6`, `NFT_CT`, `NF_CONNTRACK`,
   `BRIDGE_NETFILTER` are all `=y`. A container launched with the default
   capability set cannot use it (`nft add table` fails with "Operation not
   permitted"); with `--cap-add NET_ADMIN` it can install a ruleset and read
   it back as JSON (`nft -j list ruleset`) with per-rule counters. Apple
   `container`'s default set holds `CAP_NET_RAW` but not `CAP_NET_ADMIN`.
5. **The host bridge exposes no IP-filter toggle.** `ifconfig` knows
   `hostfilter` only; `net.link.bridge.*` has no PF switch. Whether PF sees
   bridged frames is therefore a measurement (V0), not a configuration.

## What the facts settle about the sequence

The design left VM placement's start sequence as questions because of Q1.
With Q1 answered, the existing vm-arm sequence already satisfies the fixed
invariant ("the workload is never released unless the session anchor has been
read back as the final ruleset with both members present, immediately before
the release signal"): the bootstrap anchor is loaded before any VM exists;
the broker VM starts on the shared network; the agent VM starts; the attached
anchor is installed with `DenyGuestIpv6 { min_members: 2 }` and read back
exactly; only then is the workload released. During the one-member interval
only the trusted broker VM is on the bridge, and the agent VM runs only the
trusted prelaunch under the bootstrap anchor until release. **No quarantine
anchor and no atomic replacement step are needed**; V0 records that in the
design in place of the provisional sequence. What is missing is only layer
3, and V0 decides whether layer 3 is the boundary or defence in depth.

Layer 3 is built and gates readiness in either case. If V0 finds that host
PF does see bridged frames, the design permits the readback not to gate
readiness; this plan gates anyway, because one code path whose guarantee
does not depend on a measured platform property is simpler to state than two,
and the cost is a broker VM that refuses to become ready when its own
firewall is not exactly what it intended, which is the behaviour we want.

---

## Stage V0: Measure whether host PF sees guest-to-guest frames; record the facts

**Dependencies:** None.

**Implements:** "Beyond E3" Q2 and the design amendment that turns "VM
placement (provisional)" into current-state facts.

Add `scripts/measure-vmnet-bridge-pf.sh` (host-owned, needs `sudo` for
`pfctl`). It creates an internal network, starts two Alpine VMs, discovers the
bridge and both members from the gateway address (the same way the helper
does), loads a labelled anchor under `writ/session/*` with `pass ... keep
state` and `block` rules whose only purpose is counting: an IPv4 TCP rule for
guest A to guest B port 9000, an IPv6 rule for guest A to guest B, and a
positive-control IPv4 rule for guest A to the gateway on a port the host does
not listen on. Guest B runs a `nc` listener; guest A is commanded to connect
over IPv4 and IPv6 a known number of times and to the control target the
same number of times. The script reads the counters back with `pfctl -vsr`
and prints a verdict per family, then tears everything down.

The verdict, with the CLI version, macOS build and kernel string, goes into
the design doc's VM-placement section, together with facts 1–5 above and the
sequence conclusion. The provisional sequence, `QuarantineInstalled`, and
"atomic replacement" are removed from the design's VM-placement section and
from the lifecycle model's phase list, with a sentence saying why (fact 1).
Layer 3's "provisional" status becomes "designed, built by
`docs/plans/2026-09-12-vm-placement-opens.md`".

**Correctness oracle:**
- The measurement is two-sided and non-vacuous: the control counter must rise
  by at least the number of commanded probes, or the script fails rather than
  reporting a verdict. Guest B's listener log (read by the host) must show
  the guest-to-guest connections actually arrived, so "PF counted nothing"
  cannot be confused with "nothing was sent".
- The verdict is one of exactly two recorded strings per family; the script
  exits non-zero on anything else.
- The design doc's symbol references still resolve after the edit (the
  Stage A oracle of the IPv4-lock plan applies); markdown links resolve.

---

## Stage V1: The broker's internal-interface firewall as data

**Dependencies:** None (parallel with V0).

**Implements:** Layer 3's ruleset: deny all IPv6 input on the internal
interface; allow only IPv4 TCP from the session subnet to the broker port;
deny all other internal-interface input; forwarding denied on that interface.

In `writ-core`, next to `session_attached_pf_ruleset`, add
`broker_internal_nft_ruleset(interface, subnet, broker_port)` producing an
ordered rule list as a DU (not strings), a renderer to the `nft -f` text form,
and a parser for the `nft -j list ruleset` JSON form that yields the same DU.
Deny rules carry counters and fixed labels (comments), mirroring the PF
labels (`writ deny broker v6 internal`, `writ deny broker v4 internal`), so a
later observer can read them the way C3's host observer reads PF. Add a
`BrokerFirewallReadback` type: the parsed ruleset plus the interface, with a
single constructor that compares a readback against an intent and refuses
any difference.

Extend `pf_packet_model.rs`'s approach with a small nft packet model: given a
packet (family, protocol, interface, source, destination, port) and the DU,
decide accept or drop.

**Correctness oracle:**
- Property: render then parse is the identity on the DU, for all interfaces,
  subnets and ports the generators produce.
- Property: every rule in the ruleset names the internal interface; a
  generated ruleset with one rule's interface, family, port, subnet, or order
  mutated is refused by the readback constructor.
- Property (the confinement claim): for all packets, the model accepts iff
  the packet is IPv4 TCP on the internal interface from the subnet to the
  broker port; generators construct allowed and denied cases directly and a
  test asserts both classes are exercised.
- The rendered text is byte-for-byte the text a test on a Linux box with real
  `nft` loads and reads back to the same JSON the parser accepts; that test
  is `#[ignore]`d on GitHub CI (it needs `CAP_NET_ADMIN` in a network
  namespace) and is run on the Linux droplet, as B2's were.

---

## Stage V2: `writd broker` installs the firewall and drops `NET_ADMIN` before readiness

**Dependencies:** V1.

**Implements:** Layer 3's sequence inside the broker VM: install, read back,
compare, drop network authority, then serve; and the launch-side changes it
needs.

Session spec schema v3 gains `internal_cidr` (the route-fix prologue already
receives it as argv; the spec is the typed channel). `run_broker` gains a
step between `prepare_broker`'s config load and its listener bind:

1. resolve the internal interface from `internal_cidr` (`ip -j addr`, parsed,
   never a caller-supplied name);
2. write `disable_ipv6=1` for that interface and verify by readback, so the
   agent has no IPv6 target on the broker even before the deny;
3. render V1's ruleset, load it with `nft -f -`, read back with
   `nft -j list ruleset`, construct `BrokerFirewallReadback` (refuses on any
   difference);
4. drop `CAP_NET_ADMIN` from the bounding, permitted, effective, inheritable
   and ambient sets and set `no_new_privs`, then re-read `/proc/self/status`
   and refuse to continue if the capability is still present anywhere.

Each step is a variant of a `BrokerFirewallStep` DU that a small interpreter
executes, so the ordering is data a test can assert over and the effects are
fakeable. Any failure is reported in the broker log and exits the process
before the ready file exists; the host sees `ExitedBeforeReady` with the
captured log, as it does today for any early exit.

Launch side: `run_invocation` adds `--cap-add NET_ADMIN` for the broker VM
(the broker image's `brokerRequiredBins` gains `nft`; the image gains
`nftables`). This changes the pinned broker contract fingerprint, so the
fingerprint and `BROKER_PROTOCOL_VERSION` are bumped here, and the rebuild
hint in `crates/writ-vm-git` is checked.

**Correctness oracle:**
- Property: the step sequence is exhaustive and ordered: interface resolution
  precedes the sysctl, the sysctl and install precede the readback, the
  readback precedes the capability drop, the drop precedes the bind, and
  nothing privileged follows the drop.
- Fake-`nft` tests (a `/bin/sh` script recording argv, as the fake `container`
  scripts do): with a readback that differs from the intent in any one rule,
  with `nft` failing, with the capability still present after the drop, and
  with the sysctl readback wrong, the ready file is never written and the
  process exits non-zero with the reason in the log; with everything
  matching, the ready file appears only after the bind.
- `broker_contract_fingerprint_is_pinned` fails until the fingerprint is
  bumped, and the launch argv test asserts exactly one `--cap-add`, of
  `NET_ADMIN`, and nothing else added.
- Linux integration test in a user+network namespace running the real
  sequence against real `nft` (`#[ignore]`d on GitHub CI; run on the droplet).
- `nix eval` of the broker image still passes; `build-broker-image` on the
  Mac produces an image whose rootfs scan finds `nft`.

---

## Stage V3: The ready document carries the firewall readback; the host gates on it

**Dependencies:** V2.

**Implements:** The evidence-protocol rule that, for VM placement, the
grading fact is "the broker VM's own firewall readback taken by trusted
broker-side code before it drops authority", delivered to the host through
the channel the host already trusts for readiness.

`BrokerReadyDoc` gains `internal_firewall: BrokerFirewallReadback`
(mandatory; a doc without it fails to parse at this protocol version).
`gate_ready_doc` on the host recomputes the intended ruleset from facts the
host owns (the internal CIDR it created the network with, the broker port it
chose) plus the one broker-supplied fact, the interface name, and refuses the
doc unless the readback equals that intent. `launch_broker_vm` returns a
`BrokerVmReady` value whose `internal_firewall` field is the verified
readback; there is no way to obtain the value without it.

**Correctness oracle:**
- Property: for all (cidr, port, interface), a doc carrying the exact
  rendering is accepted and a doc carrying any single-rule mutation, a
  different interface, or no readback is refused; the refusal names the
  difference.
- `broker_vm_runner` fake tests: a fake broker that writes a legacy or
  firewall-less ready doc produces a launch failure and teardown, the same
  path `ExitedBeforeReady` takes today, and the agent VM is never started (no
  `run` for `writ-agent-vm-<id>` in the fake's log).
- Protocol version bumped once for V2+V3 together if they land as one
  reviewable pair; the fingerprint test pins it.

---

## Stage V4: Lift the refusal; `BrokerReady` becomes a typed phase

**Dependencies:** V3, and V0's design amendment.

**Implements:** The design's `(VmBrokerPlacement => BrokerInternalFirewallFinal)`
conjunct of the release invariant, enforced by types rather than by refusing
to start.

Delete the unconditional `Ipv6ConfinementUnavailableForVmBroker` return in
`start_session` and the variant itself. `start_vm_broker_session` takes the
`BrokerVmReady` from V3 and builds the agent plan from it, so an agent VM
under VM placement cannot be started from anything but a firewall-verified
broker. Persist the readback's summary (interface, rule count, protocol
version) in the session's state record so listings and reconciliation can
show it. If the IPv4-lock plan's E1 (lifecycle phases, state schema v3) has
landed, `BrokerReady` is that plan's phase carrying this value; if not, this
stage adds the field to the current schema with the migration test the
state-store tests already use, and E1 adopts it. Either way, `QuarantineInstalled`
is not added (V0).

Update `docs/design/architecture.md` §5 (the "Under VM broker placement
there is no such confinement" paragraph becomes a statement of layer 3 and
the ready-doc gate) and the memory of #396 in the design doc.

**Correctness oracle:**
- `vm_broker_placement_refuses_new_sessions_while_ipv6_is_unconfined` is
  replaced by two tests: a fake broker whose ready doc carries a matching
  readback leads to an agent `run` in the fake's log after the broker's, with
  `--cap-drop NET_RAW` and the broker VM's IP as the PF allow target; a fake
  broker whose ready doc lacks the readback leads to no agent `run`, a
  cleaned-up broker VM and networks, and an empty state store, exactly what
  the deleted test asserted for the refusal.
- `start_vm_placement_session_past_the_gate` and its three callers are
  deleted; the tests they served call `start_session` directly.
- `cargo doc` with warnings denied passes after the variant is deleted
  (intra-doc links to it are the easy thing to miss).

---

## Stage V5: Acceptance on hardware in a release build, with host-owned layer-3 evidence

**Dependencies:** V4; the broker image rebuilt with V2.

**Implements:** The vmnet doc's §9.6 step 7 ("with `broker_placement = vm`,
a release build completes a real `agent-vm start` + clone + warm") and the
layer-3 obligation of the confinement design's proof list, item 3.

`scripts/prove-agent-vm-daemon.sh` gains `WRIT_PROVE_BROKER_PLACEMENT=vm`
and `WRIT_PROVE_WRITD_PROFILE=release`. Under those it builds a release
`writd`, builds and loads the broker image, configures VM placement with
`ipv4_only_no_guest_ipv6`, and runs the daemon proof unchanged for the
positive path (start, session, clone, cache). It then adds host-owned
layer-3 legs, read from the trusted broker VM with `container exec
writ-broker-vm-<id> nft -j list ruleset`, which the evidence protocol counts
as host-owned because the broker VM never runs agent code:

- the ruleset read live equals the readback the ready doc carried;
- a root agent that re-enables IPv6 and probes the broker VM's ULA raises
  the labelled IPv6 deny counter by at least the number of commanded probes
  (this is the one place a rising IPv6 counter is expected, as in the
  host-placement proof);
- a probe to a broker-VM port other than the broker's raises the labelled
  IPv4 deny counter, and the broker's own log shows no request for it;
- the released broker process holds no `CAP_NET_ADMIN` (its
  `/proc/<pid>/status` via `container exec`, decoded by the proof's existing
  capability decoder).

The host PF legs of `prove-agent-vm-lifecycle.sh` (interface-scoped anchor
with both members, forbidden host port counted by the IPv4 interface deny,
IPv6 host deny) are asserted here too, against the two-member anchor.
`prove-agent-vm-lifecycle.sh` itself stays a host-placement proof and keeps
its waiver knob; it is not taught VM placement, because the daemon proof
exercises the real broker rather than a stand-in.

**Correctness oracle:**
- The proof is green end to end on the development host with a **release**
  `writd`, which no proof has been since the defect appeared; a debug build
  passes the same proof, so the placement, not the build profile, is what
  changed.
- Every counter-based leg is non-vacuous in the way the lifecycle proof's
  are: a probe that sends nothing fails the leg.
- The proof's summary line names each leg; a waived or skipped leg cannot
  print the success line.

---

## After V5

- The IPv4-lock plan's Stage E2/E3 (locked profile) apply to the agent VM
  identically under both placements, because the agent's launch, guest init,
  and attached anchor do not depend on placement; when E3 runs, it runs
  under VM placement on this host.
- Host placement stays the revert target (`broker_placement = host`, the
  default). When Apple fixes vmnet, `prove-agent-vm-lifecycle.sh`'s
  broker-reach leg goes green without the waiver, and the VM-placement
  machinery becomes deletable per the vmnet doc's §9.0.
- Deferred, as before: restart-reconcile of orphaned broker VMs; the
  agent-run session kind under VM placement (`AgentRunUnsupportedForVmBroker`
  stays); the separate ~1h "interface vanished" vmnet instability, which
  affects both placements and is a session-length concern, not a boundary one.
