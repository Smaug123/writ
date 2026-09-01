# IPv4-only agent-VM network confinement

Status: **layer 1 shipped; layer 2 designed, not built; layer 3 and vm
placement provisional.** This document
is the design record behind the `ipv4_only_locked_v1` IPv6 profile, which
`writd` recognises and refuses today (#397) and will admit once every layer
below is in force. The implementation plan is
[`docs/plans/2026-09-01-ipv4-only-locked-v1.md`](../plans/2026-09-01-ipv4-only-locked-v1.md).

An earlier draft of this document (July 2026) argued that the legacy
`ipv4_only_no_guest_ipv6` mode was unsafe and should be refused. Its own
prescription for the fix — an interface-scoped host PF deny with the helper
resolving the interface independently — was what #288 then shipped, so the
legacy mode is the *strongest* confinement writ has today and remains the only
profile that starts a session. The sections below describe layer 1 as it is,
not as it was proposed; layers 2 and 3 are the remaining specification.

`docs/design/architecture.md` §5.5–5.7 is the current-state map of the
subsystem; this document is the security argument and the target state.

## Scope and threat model

The agent controls arbitrary guest userland code, including code that starts as
UID 0 under the current image. It may make arbitrary syscalls, spawn children,
modify network configuration when its capability set permits that, and send raw
packets when `CAP_NET_RAW` is present. Per `CLAUDE.md`, the guest is treated as
compromised from the moment the agent command starts.

The trusted computing base is:

- the macOS host, `writd`, and the narrow privileged PF helper;
- Apple `container` and its Linux guest kernel;
- the official guest image before the trusted initializer hands control to the
  workload (layer 2, not yet built);
- for VM broker placement, the dedicated broker VM and its kernel.

A guest-kernel exploit is outside this design's containment claim. Host PF and
the broker VM's ingress firewall nevertheless remain independent protection
against compromised guest userland. If the supported Apple networking surface
cannot provide a durable host-side packet selector, the profile stays closed;
the design does not silently weaken its claim.

## Required invariants

The release transition is governed by this implication:

```text
WorkloadReleased
  => HostFirewallFinal
  && GuestNetworkAuthorityRemoved
  && GuestIpv6Absent
  && (VmBrokerPlacement => BrokerInternalFirewallFinal)
```

More concretely:

1. After release, the workload cannot send IPv6 to the macOS host, its broker
   VM, another session, or an external destination.
2. "No guest IPv6" means no non-loopback IPv6 address and no IPv6 route. It
   does not mean only "no global address" or "no default route".
3. The only permitted network tuple is the intended IPv4 broker endpoint and
   port.
4. No repository-controlled or agent-controlled code runs before persistent
   isolation is installed and verified.
5. Failure or uncertainty at any isolation stage prevents release.
6. Session authority is revoked independently of infrastructure cleanup.
7. PF remains installed until the agent VM is proven absent.
8. A recurring monitor is diagnostic only; it is not a security control.
9. The irreversible guest privilege handoff applies to every agent-VM profile,
   so changing profiles cannot restore network-management authority.

Today, `HostFirewallFinal` holds for host placement (layer 1).
`GuestNetworkAuthorityRemoved` does not hold anywhere (layer 2 is unbuilt), and
`BrokerInternalFirewallFinal` does not hold anywhere (layer 3 is unbuilt), which
is why vm placement refuses new sessions (#396). `GuestIpv6Absent` is
established at release and is then a precondition the root workload can undo;
the host deny is what makes undoing it useless for egress.

## Why a guest sysctl alone was never a boundary

The historical start sequence loaded IPv4-only PF rules, started a root shell,
ran a root `container exec` that wrote `disable_ipv6=1`, checked a snapshot, and
released the same authority-bearing root workload. The workload can write `0`
back, re-enable router advertisements, reacquire Apple's vmnet ULA, and use
IPv6 outside source-scoped IPv4 PF rules.

Blocking only Apple's observed `/64` is not sufficient either. A guest with
`CAP_NET_ADMIN` can add another ULA, a link-local address, or a global-unicast
source. Blocking ULA and link-local ranges is still incomplete when raw packet
injection is available. Repeated discovery is a TOCTOU detector, not a packet
boundary. **A rule matched on what the guest says its address is cannot confine
a guest that chooses its address; only a rule matched on the interface the
guest's frames arrive on can.** That sentence is the whole reason layer 1 is
interface-scoped and the reason layer 2 exists: layer 1 makes the guest's
network authority useless for egress, and layer 2 removes the authority so that
the proof has less to prove.

## Enforcement layer 1: host PF (shipped, #288)

### What runs today

For a host-placement session the start-step state machine
(`AgentVmStartStep`, `agent_vm_lifecycle.rs`) is:

```text
ProbeNetworkAbsent -> CreateNetwork -> InspectAndValidate -> InstallFirewall
  -> ProbeVmAbsent -> StartVm -> InstallGuestIpv6Deny
  -> ProbeAndValidateGuestIpv6 -> ReleaseGuestCommand
```

`InstallFirewall` loads the IPv4 session anchor: allow the agent subnet to the
broker endpoint on the broker ports, then `block return` everything else from
the agent subnet. `StartVm` starts the VM under a guarded prelaunch command that
sets `disable_ipv6=1` and waits; the agent command has not run yet.

`InstallGuestIpv6Deny` invokes the privileged helper with `--deny-guest-ipv6`.
The helper, not the daemon, resolves the interface: it runs the fixed
`/sbin/ifconfig`, finds the `bridgeN` carrying the pool-validated session
gateway, requires that bridge to have the expected number of `vmenetN` members
(one for host placement, the agent's; two for vm placement, the broker's and
the agent's), retries while they attach, and fails closed if no single such
bridge exists. An unrelated interface that happens to share the gateway (an
`en0` or `utun` on an overlapping LAN) is rejected as a candidate rather than
matched, so it can neither be selected nor block the real bridge. It then
re-loads the session anchor with, on the bridge and each member:

```pf
block return in quick on <iface> inet6 all label "writ deny agent v6 iface"
```

The daemon never passes an interface name to the helper; a direct malicious
invocation of the helper cannot make it deny IPv6 on `en0`. Only after the deny
is loaded does `ProbeAndValidateGuestIpv6` confirm the guest holds no routable
IPv6 (a precondition, see below) and `ReleaseGuestCommand` start the workload.

The live proof `scripts/prove-agent-vm-lifecycle.sh` asserts the anchor carries
the interface deny, then has a root guest write `disable_ipv6=0`, re-enable
RAs, bounce the link, wait for a routed IPv6 default to come back, and send a
real ICMPv6 echo to the reacquired gateway. The proof fails, not passes, if
the guest lacks `ping`, or if no route came back, so it cannot pass vacuously.

### Known deltas from the target rules

These are hardening items on a layer that already holds, listed so they are
not rediscovered. None reopens the bypass #288 closed.

- **Direction.** The shipped rule is `in` only; the target rule has no
  direction. `in` on the bridge is what stops guest-originated frames, which is
  the containment claim. Whether `out` matters depends on whether PF sees
  vmnet's router advertisements at all (they may be injected below PF). The
  vertical proof should measure this with a labelled `out` counter before
  anyone reasons about it.
- **`return` versus `drop`.** `return` answers the guest with a reset or
  unreachable, which is a covert channel of one bit per probe and a faster
  failure for legitimate misconfiguration. Not a containment difference.
- **No readback, no post-load re-resolve.** The helper resolves the interface
  once, before loading. The target boundary resolves again immediately after
  the load and parses `pfctl -sr` back to prove the loaded anchor is exactly
  the intended one. Both are required before `ipv4_only_locked_v1` admits,
  because vm placement's quarantine-then-replace sequence (below) has no
  meaning without an exact readback.
- **The IPv4 rules are source-scoped, not interface-scoped.** The shipped
  anchor is `pass in quick inet proto tcp from <agent /24> to <broker> port
  $broker_ports` and `block return in quick inet from <agent /24> to any`. A
  packet whose IPv4 source is outside the session subnet matches neither, and
  falls through to whatever the host's default PF policy is. Linux lets even
  an unprivileged process send a one-way UDP datagram with a foreign source
  via `IP_FREEBIND`, so this does not need `CAP_NET_RAW`; whether such a frame
  is forwarded by vmnet at all is unknown and must be measured, not assumed.
  The target rules match the IPv4 allow and a default deny on the resolved
  interfaces, exactly as the IPv6 deny already does, and the vertical proof
  sends a spoofed-source probe. This is the one delta that is a possible live
  gap under the legacy profile today rather than hardening; it is listed here
  because the fix is the same interface-scoped renderer the locked profile
  needs, and it is not blocked on any of layers 2 or 3.
- **`ifconfig` text.** Resolution parses `ifconfig` output rather than a
  `getifaddrs` snapshot. The parser is pure and property-tested
  (`parse_bridge_for_gateway`); replacing it is not a security item.
- **Interface stability** is a platform admission requirement, not something
  writ repairs by polling. Same-name disappearance and reappearance is covered
  by PF's name binding. A network that silently reattaches under a different
  name is not safe to repair after the fact; on a supported version that would
  mean a root-resident attachment mechanism, a deliberately host-wide deny, or
  keeping the profile closed.

### VM placement (provisional)

Host placement installs the final anchor before the agent VM's workload runs,
as above. VM placement is harder in two ways that are facts about the
platform, not choices: the shared network exists before the broker's IPv4
address is known, and the host `bridgeN` and its `vmenetN` members appear
only once a VM is running on the network, so an interface-scoped rule cannot
precede the first VM.

What is fixed is the invariant, not the sequence: **the agent VM's workload
is never released unless the session anchor has been read back as the final
ruleset with both members present, immediately before the release signal**,
and any state the helper cannot read back as known forbids release and tears
the session down. The sequence that satisfies it (broker first, then a
quarantine anchor on the one-member bridge, then discovery of the broker's
IPv4, then atomic replacement, then the agent VM, then the two-member deny)
is the likely shape, but it is written down in the plan's "Beyond E3"
section as questions rather than here as steps, because whether PF even sees
guest-to-guest frames on that bridge, and when the bridge appears, are things
the host-placement proof has to measure first. Until then vm placement
refuses new sessions (`Ipv6ConfinementUnavailableForVmBroker`, #396).

## Enforcement layer 2: one-way guest handoff (not built)

The official agent image contains a small Linux-only
`writ-agent-vm-guest-init` binary that runs as PID 1. It is the only guest code
that runs with temporary network-management authority.

Apple `container` launches it with `--cap-drop ALL` and only these temporary
capabilities:

- `CAP_CHOWN`;
- `CAP_SETGID`;
- `CAP_SETUID`;
- `CAP_SETPCAP`;
- `CAP_NET_ADMIN`, for the IPv6 sysctls.

It is never granted `CAP_NET_RAW`, `CAP_SYS_ADMIN`, `CAP_BPF`, or
`CAP_SYS_PTRACE`. The exact `container run` argv fragment is a fixed constant,
parsed rather than assembled, so a drifting flag is a test failure and not a
quietly wider capability set.

Before announcing readiness, PID 1:

1. Creates and changes ownership only on the fixed runtime, home, workspace,
   and writable Nix directories.
2. Sets `accept_ra=0`, `autoconf=0`, and `router_solicitations=0` where present.
3. Sets `disable_ipv6=1` for `all`, `default`, and every existing interface.
4. Verifies that no non-loopback IPv6 address or IPv6 route exists.
5. While still UID 0 and holding `CAP_SETPCAP`: drops every capability from
   the bounding set, clears the inheritable and ambient sets, and sets
   `NoNewPrivs=1`. The order matters: dropping the bounding set needs
   `CAP_SETPCAP`, and the identity change in step 6 discards it.
6. Clears supplementary groups and changes real, effective, and saved GID then
   UID to the fixed official-image identity 1000:1000, with `KEEPCAPS` off, so
   the transition itself clears the permitted and effective sets. `CAP_SETGID`
   and `CAP_SETUID` are therefore the last capabilities held, and they are
   consumed by the calls that need them.
7. Re-verifies identity, every capability set (bounding included),
   `NoNewPrivs`, sysctls, addresses, and routes.
8. Blocks `USR1` and arms the wait for it (a `sigwait` on the blocked set,
   or a `signalfd`), *then* emits one bounded, versioned `security-ready`
   record and waits as the restricted identity for the host release signal.
   The order matters: the host may send the signal the instant it observes
   the record, and an unblocked `USR1` arriving before the wait is armed would
   either terminate PID 1 with the default action or be lost.
9. On release, `exec`s the existing guest bootstrap command. No root
   supervisor survives.

The agent image has a fixed identity and initializer ABI, advertised by an OCI
label (`org.writ.agent-vm.isolation-abi`); UID, GID, and the capability set are
not configuration knobs. An image without the label, or with a version the
daemon does not know, does not admit `ipv4_only_locked_v1`.

The host observes the pre-release record through bounded `container logs` and
releases PID 1 with `container kill --signal USR1`. This preserves the no-host-
mount invariant and avoids creating a privileged `container exec` process after
untrusted code starts. That rule has consequences for the existing
post-release interactions, which today are `container exec` calls: the
broker-ready marker is subsumed by the release signal (the host does not send
`USR1` until its broker is ready), and workspace-bootstrap success and bounded
failure records use the same host-side log channel as `security-ready`. After
release the host never `exec`s into a locked session; guest-written
post-release records remain untrusted diagnostics.

Layer 2's correctness is checkable without any macOS proof: run the initializer
in a Linux container in CI and read `/proc/self/status` of the released process
for zeroed capability sets, `NoNewPrivs: 1`, UID and GID 1000, empty groups,
and no non-loopback IPv6 state; scan the image for setuid bits and file
capabilities. Those facts are observed *before* the workload starts, by code
that is still trusted, which is the whole point of the handoff.

## Enforcement layer 3: broker-VM ingress (provisional)

Host PF may not see frames switched directly between two guests on the shared
vmnet. That is an assumption, and the first thing the vertical proof measures
for vm placement; if it is false, this layer is defence in depth and its
readback need not gate readiness. If it is true, the trusted broker VM must
install its own internal-interface firewall before publishing readiness:

- deny all IPv6 input and forwarding on the internal interface;
- allow only IPv4 TCP from the session subnet to the broker port;
- deny all other internal-interface input;
- read the rules back;
- drop network-administration authority before executing `writd`.

The broker binds an IPv4 listener for the agent path. Failure to install or
read back the broker firewall prevents readiness and therefore prevents the
agent VM from starting. Until this exists, vm placement refuses new sessions
(`Ipv6ConfinementUnavailableForVmBroker`).

## Evidence protocol

This section did not exist in the July draft, and its absence is why the
adversarial-harness attempt could not converge: every review round rediscovered
that some fact used to grade a proof had been reported by the party under test.
The rules are:

1. **The host owns every fact that gates release or grades a proof.** Those
   facts are: PF rule counters read via labelled rules (`pfctl -vsr` on the
   session anchor); accept and connect logs of listeners the host runs; the
   host's clock; the phase transitions `writd` writes; and, for vm placement,
   the broker VM's own firewall readback taken by trusted broker-side code
   before it drops authority.
2. **Guest output is diagnostics or explicit doubt, never a verdict.** A guest
   claim can lower confidence (a guest that reports reaching a forbidden target
   is a failed proof even if the host saw nothing) but cannot raise it. "The
   guest failed to connect" is not evidence; "the forbidden listener accepted
   nothing and the labelled deny counter rose by at least the number of probes
   the host commanded" is.
3. **Challenges are host-issued.** The host decides when an attack window
   opens and closes, tells the guest attack binary what to attempt, and grades
   on its own observations within that window. The attack binary's exit status
   is logged and ignored.
4. **Every experiment is correlated by a host-minted nonce**, present in the
   listener's expected payload, in the PF rule labels for that experiment, and
   in the session's audit rows, so two concurrent proofs cannot grade each
   other's packets.
5. **Inconclusive is failure, and every negative has a positive control in the
   same run.** A silent listener proves nothing unless the same run shows a
   sender that *can* emit IPv6 on a bridge of the same kind reaching that
   listener, with the same tooling. The positive control is therefore a
   separate, unconfined sender the proof controls (a root guest on a
   proof-created network with no anchor), not the protected workload with a
   layer withheld: under the locked profile the workload has no IPv6 and no
   network authority, so withholding the host deny would produce no packets
   and the "control" would be vacuous. Missing tools, missing routes, and
   timeouts are failures, not skips.
6. **Evidence is concrete host-owned types.** `PfCounterDelta`,
   `ListenerObservation`, `PhaseTransition`, and the like, joined by nonce and
   phase, with the guest's diagnostic records attached as an untrusted
   appendix. Not a generic transcript table, and not a plan language: there is
   one experiment per placement, and it is written out step by step.

The parked `Claim<T>` taint type (`ipv4-lock/02-claim`) is the right shape for
rule 2's "explicit doubt" and should be adopted when a host consumer exists,
which is the vertical proof in plan stage E and not before.

## Lifecycle model

Start is represented by explicit phases:

```text
Claimed
-> NetworkValidated            (bootstrap anchor loaded; no interface yet)
-> QuarantineInstalled         (vm placement only, provisional)
-> BrokerReady                 (vm placement only, provisional)
-> AgentVmStarted              (initializer running, holding for release)
-> FinalFirewallInstalled      (interface-scoped anchor, members attached,
                                read back)
-> GuestSecurityLocked         (security-ready observed)
-> ReleaseAttempted            (persisted before the signal is sent)
-> WorkloadReleased
```

The interface firewall becomes final *after* the agent VM starts, because
that is when its `vmenet` member exists; this is the shipped order
(`StartVm` then `InstallGuestIpv6Deny`), and between the two the VM runs only
trusted code under the bootstrap anchor.

Not every placement performs every effect, but it uses the same ordered state
model; the two vm-only phases, `QuarantineInstalled` and `BrokerReady`, are
provisional on the questions above and host placement never enters them.
`ReleaseAttempted` is constructible only from `GuestSecurityLocked` and
`FinalFirewallInstalled` (plus `BrokerReady` with a final internal firewall for
vm placement), and it is persisted *before* `container kill --signal USR1` is
run. The signal is an effect whose outcome the daemon cannot always learn: a
failed or timed-out `kill` does not prove the signal was not delivered, and
the daemon can crash after delivery and before recording it. A session found
in `ReleaseAttempted` is therefore treated as released: reconciliation revokes
its authority and cleans it up, never resumes it. `WorkloadReleased` records
that the kill reported success and is the only phase in which the daemon
proceeds to wait for bootstrap. The shipped start steps map onto these phases with
`QuarantineInstalled` and `BrokerReady` absent for host placement and
`GuestSecurityLocked` currently meaning "the prelaunch precondition held", which
layer 2 upgrades to "the initializer's security-ready record was observed".

Teardown and boot reconciliation revoke the audit session and broker authority
before or independently of infrastructure cleanup. They then stop and prove
the agent absent, stop and prove the broker absent where applicable, remove PF,
remove networks, and finally remove persisted state. If absence is uncertain,
PF and cleanup state remain. The shipped `reconcile_one_session` already
observes the last three rules; the phase model makes them a property that can
be checked by injecting failure after every phase.

## Privileged-helper boundary

Interface-wide rules make selecting the wrong interface a host-network denial
of service. The helper's boundary is therefore narrow, and partly shipped:

- production uses fixed `/sbin/pfctl` and `/sbin/ifconfig`; there is no
  caller-controlled executable path (shipped);
- the helper accepts structured session facts, never PF text (shipped);
- it derives the interfaces itself from the pool-validated gateway (shipped);
- pools, allowed ports, and admitted interface policy come from a fixed,
  root-owned, non-symlink, non-group/world-writable policy file (not shipped;
  today they are validated CLI arguments);
- it syntax-checks, atomically loads, parses exact readback, and re-resolves
  after the load (not shipped);
- it answers `protocol-version` with one bounded JSON object, and returns
  bounded versioned JSON describing anchor, interfaces, and firewall phase (not
  shipped; the daemon's `ipv4_only_locked_v1` admission depends on the probe).

Tests inject a fake `pfctl` path into the unprivileged Rust library, not into
the production privileged CLI.

## Persistence and compatibility

`ipv6_mode` is parsed as `ConfiguredIpv6Profile`, and a running or persisted
session carries an `Ipv6IsolationMode`; `ConfiguredIpv6Profile::admit` is the
only way between them (#397). `ipv4_only_locked_v1` is recognised so a config
naming it is refused for the right reason, and refused because layers 2 and 3
do not exist. A `writd` older than #397 rejects the spelling as an unknown
value, which is what makes rolling back fail closed rather than quietly running
under another profile.

The legacy `ipv4_only_no_guest_ipv6` profile **is not refused** and will not
be while it is the strongest confinement available. Once `locked_v1` admits on
a host, the legacy profile's remaining weakness there is that its guest keeps
network authority (layer 2), and invariant 9 says no profile may keep it once
the handoff exists. So the two decisions are one decision: on a host whose
evidence admits `locked_v1`, `ipv4_only_no_guest_ipv6` and
`dual_stack_required` refuse; on any other host they admit as today. Per host,
not globally, so that a host without a proof record is never left with
nothing startable. `dual_stack_required` is included even though it does not
start on this platform, because it too runs the root prelaunch.

When `locked_v1` admits, admission is conditional on host-gathered runtime
evidence, not on the spelling alone: the helper's protocol probe reports v2,
the image's isolation-ABI label is v1, and the platform is one the proof has
been run against. "Platform" is two identifiers, because PF and vmnet belong
to macOS while the guest kernel ships with the CLI, and macOS updates change
vmnet behaviour without touching the CLI version (this subsystem's journal
records RA behaviour changing across an OS update): the Apple `container` CLI
version line (today `1.0.0`, build `ee848e3`) and the macOS build
(`sw_vers` BuildVersion, today `25G72`). A third fact is host-local and no
pin captures it: the effective placement of the `writ/session/*` anchor in
the main ruleset. A `pass in quick` in `/etc/pf.conf` ahead of that anchor
means no session rule is ever consulted, while every child-anchor readback
still succeeds. The helper therefore reads the main ruleset back and reports
whether the anchor is present and precedes any `quick` pass, and that report
is admission evidence too. Both are exact-match pins against a
list the proof maintains, so a host update closes the profile until the proof
is re-run there. The list starts empty and a platform enters it only in the
same change that records the proof passing on it, so the code that can admit
the profile lands before the profile actually admits anywhere. Those are inputs to `admit`, gathered at start, so that a
plan can only ever be built from an admitted mode; there is no separate gate
type and no bypass on the plan for tests, because a test that bypasses the
guard is not testing it.

The locked lifecycle writes state schema v3 containing interface identity,
firewall phase, isolation profile and ABI, placement, and cleanup facts. A v2
reader exists only to drive cleanup. A live v2 session is never relabelled as
hardened. Upgrade requires stopping every legacy session, installing helper
protocol v2, loading the official guest and broker image ABIs, then starting
the new daemon. Rollback requires draining v3 sessions first.

## Rejected alternatives

- Observed-prefix PF: source-spoofable.
- ULA-only or ULA-plus-link-local PF: incomplete address enumeration.
- Repeated guest probing: detects after escape and races the first packet.
- Guest sysctl alone: reversible by the root workload.
- Capability drop while retaining a root supervisor: leaves a privileged
  process in the same trust domain.
- `--read-only` rootfs: does not protect `/proc` and conflicts with the private
  writable Nix store.
- Silent fallback to dual-stack: vm placement cannot use it, and source-prefix
  rules still require privilege confinement.
- A generic adversarial-testing platform (plan language, transcript tables,
  positional record joins) ahead of a single vertical experiment: it grew to
  eight thousand lines with no consumer and no satisfiable oracle, because the
  host-owned observers it needed were later stages. Build the observers, then
  one experiment, then generalise only if a second experiment demands it.

If stable interface admission cannot be proved, the safe alternatives are to
keep the profile closed or use a host-pinned agent kernel with IPv6 compiled
out and a separately reviewed IPv4 boundary. A weaker CIDR rule is not an
alternative.

## Proof obligations

The load-bearing macOS proof is `scripts/prove-agent-vm-lifecycle.sh`, evolved
in place rather than replaced. Today it grades the re-enabled-IPv6 probe on the
guest's `ping` exit status, which the evidence protocol classifies as
diagnostics. The obligations, in the order the plan delivers them:

1. **Host placement, layer 1, under the legacy profile** (exists; upgrade
   its evidence): the root guest re-enables IPv6 and is commanded to probe; the
   labelled IPv6 deny counters on the session anchor rise by at least the
   number of probes commanded, and a host ULA or link-local listener bound on
   the bridge accepts nothing, across at least two RA intervals. The positive
   control is an unconfined root guest on a proof-created network with no
   anchor, reaching an identical listener in the same run. This is the only
   proof in which the IPv6 deny counter is expected to rise, because it is the
   only one whose workload can emit IPv6. The same run sends an IPv4 probe
   with a spoofed, out-of-subnet source to a forbidden host port and expects
   the interface-scoped IPv4 deny counter to rise and the listener to stay
   silent; the unconfined control sends the same probe and must reach its
   listener, or the platform does not forward such frames and the case is
   recorded as not applicable there, which is itself a pinned fact.
2. **Host placement under the locked profile**: before release, the host reads
   the initializer's `security-ready` record and the released process's
   `/proc/<pid>/status` via bounded `container exec` and sees the locked
   identity; after release, the same attacks run from the unprivileged
   workload and the host observes: listener silent, deny counters *zero* (a
   rise would mean the guest emitted IPv6, which is itself a layer-2 failure),
   positive control still reaching its listener. The guest's diagnostics show
   each attack failing at the syscall, and the host verdict is unchanged with
   those diagnostics deleted.
3. **Everything past host placement** — vm placement, layer 3, two-session
   isolation, soak, upgrade and rollback — is stated as obligations only once
   the proof above has recorded the platform facts listed in the plan's
   "Beyond E3" section. Writing those obligations now would be specifying an
   oracle for machinery whose shape those facts decide.

Pure tests cover packet classification, interface resolution, lifecycle phase
ordering, cleanup reconstruction, and every injected failure position. Property
generators construct valid allowed/denied and target/unrelated cases directly
and assert that each class is exercised.
