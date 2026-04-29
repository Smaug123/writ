# Apple container agent VM plan

Plan for running an LLM coding agent inside an Apple `container` VM, with a
host broker as the only authority-bearing bridge to the outside world.

## Goal

Run one agent session in one isolated Linux VM:

- no host filesystem mounts;
- no host SSH agent or Unix socket forwarding;
- private writable root filesystem, including `/nix/store`;
- no direct network egress;
- all external effects pass through the host broker;
- the broker decides Git clone/fetch/push permissions, applies commit
  signatures, mediates model/API traffic, and writes the audit log.

The broker should remain an ordinary user process where possible. Privileged
operations should live behind a small, auditable helper with a narrow command
set.

## Empirical findings

Observed on macOS 26.4.1 with Apple `container` CLI 0.11.0 after
`container system start`.

### VM and mount isolation

Command shape:

```sh
container run --name writ-step1-netnone \
  --network none \
  --cpus 1 \
  --memory 512m \
  -d alpine:latest sleep 600
```

`container inspect` reported:

- `mounts: []`
- `publishedPorts: []`
- `publishedSockets: []`
- `ssh: false`
- `networks: []`

Inside the guest, `mount` showed the root filesystem as an ext4 block device:

```text
/dev/vdb on / type ext4 (rw,relatime)
```

No host bind mounts were present.

### No-network mode

With `--network none`, the guest had only loopback:

```text
1: lo: <LOOPBACK,UP,LOWER_UP>
```

There was no route table entry. Direct HTTP, ICMP, and DNS probes failed:

- `wget http://1.1.1.1` -> `Network unreachable`
- `ping 1.1.1.1` -> `Network unreachable`
- `nslookup github.com` -> no DNS server reachable

This is a useful fail-closed mode, but by itself it gives the agent no path to
the broker unless we use a non-network host integration. Since we want no
mounts and no socket forwarding, the better primitive is a host-only network.

### Private writable `/nix/store`

Inside the no-network VM:

```sh
mkdir -p /nix/store
touch /nix/store/writ-probe
```

The write succeeded. A second VM from the same image, also with
`--network none`, did not see `/nix` or `/nix/store/writ-probe`.

Conclusion: a private writable `/nix/store` is feasible as ordinary guest
rootfs state. We do not need to mount the host Nix store.

### Default networking is unsafe

A container started on the default network got:

```text
ipv4Address: 192.168.64.2/24
ipv4Gateway: 192.168.64.1
default via 192.168.64.1 dev eth0
```

Direct `wget http://1.1.1.1` succeeded. The default network must not be used
for the agent VM.

### Internal network is the right primitive

Command shape:

```sh
container network create --internal --subnet 192.168.127.0/24 writ-step1-internal
container run --name writ-step1-internalvm \
  --network writ-step1-internal \
  --cpus 1 \
  --memory 512m \
  -d alpine:latest sleep 600
```

`container network inspect` reported:

```text
mode: hostOnly
ipv4Subnet: 192.168.127.0/24
ipv4Gateway: 192.168.127.1
```

The guest got `192.168.127.2/24` and a default route via
`192.168.127.1`. Direct internet and DNS timed out, but a host service bound
to `0.0.0.0` was reachable from the guest at `http://192.168.127.1:<port>`.

This gives us the bridge we need for the broker, but it also creates the main
remaining host-side isolation problem: a guest on an internal network can
reach any host service that is listening on all interfaces unless the host
firewall blocks it.

One additional detail: the host-only gateway address is not a normal host
address. A test bind to `192.168.125.1` failed with:

```text
OSError: [Errno 49] Can't assign requested address
```

So the broker should not depend on binding directly to the gateway IP.

## Proposed architecture

### Session lifecycle

For each agent session:

1. Allocate a session ID.
2. Allocate an IPv4 `/24` and IPv6 prefix from broker-owned pools.
3. Create a unique internal Apple container network.
4. Install host firewall rules for that session subnet.
5. Start the VM on that internal network, with no mounts, no SSH forwarding,
   no socket publishing, no published ports, and no default network.
6. Tell the agent the broker URL, e.g. `http://192.168.X.1:<broker-port>`.
7. On shutdown, stop/delete the VM, delete the network, flush firewall rules,
   and remove any live firewall states for the session subnet.

The invariant is: the VM is not started until the firewall rules are loaded.
If network creation or firewall installation fails, the session fails closed.

### Broker transport

The broker should expose a small HTTP API on a high, random, per-session port
or on a fixed port with session authentication. The guest reaches it through
the internal network gateway address.

The existing Unix-socket protocol can remain for host CLI use. The VM-facing
transport should be HTTP because the guest cannot use the host Unix socket
without a mount or socket publication.

The VM-facing API should not mint raw GitHub tokens into the VM. Instead, the
broker should perform or proxy the operation:

- `OpenSession`, `CloseSession`
- `GitClone`, `GitFetch`, `GitPush`
- `HttpConnect` or request/response proxy for permitted domains
- `NixFetch` or HTTP proxy for substituters
- `SignCommit` or broker-side Git object rewriting/signing

The important shift from the current v1 broker is that credentials stay on the
host side. The VM gets capabilities represented as broker API calls, not bearer
tokens that can be replayed elsewhere.

First VM HTTP transport slice implemented in `src/vm_http.rs`:

- the broker may ask the OS for an ephemeral port by binding to port `0`, but
  it must do so before starting the VM and must keep the returned listener
  open. The transport helper checks the chosen port against the configured
  `BrokerPortRange`; if repeated port-`0` binds do not land inside that range,
  it scans the allowed range directly from a randomized offset. This keeps wide
  ephemeral ranges cheap while still supporting narrow configured ranges such
  as a two-port test harness range. The returned `BrokerPort` is the value the
  lifecycle caller can install into PF, persist in session state, and advertise
  to the guest;
- each VM HTTP session has a generated bearer secret and an expected source
  IPv4 subnet. Requests are authorized only when the TCP peer address is inside
  the session subnet and the `Authorization: Bearer ...` value matches the
  per-session secret. This is intentionally in addition to PF, because the
  current proven PF strategy may require a wildcard host listener;
- the listener runner has an explicit shutdown path and drains connection
  handlers before returning, so the lifecycle owner does not have to abort a
  detached accept loop during session teardown;
- the only implemented VM route is `GET /v1/session`, which returns the
  session identity and protocol version. Git, Nix, model, and signing
  operations are deliberately not exposed until their host-side policy and
  audit semantics are designed. Authentication denials are returned as HTTP
  `401`/`403` today; durable audit rows for those denials belong in the next
  broker-integration slice, where the VM HTTP runner has access to broker
  audit state.

## Host-side filtering

Use macOS PF (`pfctl`) with per-session anchors. The broker itself should not
run as root; use a small privileged helper or launchd service that accepts
only structured operations:

```text
InstallSessionFirewall(session_id, ipv4_subnet, optional_ipv6_prefix, broker_ports)
RemoveSessionFirewall(session_id)
```

The helper must validate that:

- every supplied subnet belongs to the broker-managed range;
- the session ID is a safe anchor name component;
- broker ports are in an allowed local range;
- generated PF rules parse with `pfctl -n` before being loaded;
- cleanup only touches the matching session anchor.

First manual helper slice implemented as `writ-agent-vm-pf-helper`:

- `install` accepts the session ID, broker-owned IPv4/IPv6 pools, the requested
  session IPv4 subnet, an optional session IPv6 subnet, broker ports, and a
  configured broker port range;
- it validates the supplied session subnets against the owned pools and the
  broker ports against the configured range before rendering the existing
  `core::agent_vm` PF ruleset;
- it refuses to install unless PF is enabled and `pfctl -sr` contains the direct
  `anchor "writ/session/*"` bootstrap;
- it writes the rendered rules to a temporary file, runs `pfctl -n -f`, then
  loads only the session anchor with `pfctl -a writ/session/<id> -f`;
- `remove` is currently stateless and therefore accepts the session network
  again; it kills live states for the validated supplied session subnets and
  flushes only the matching session anchor. This is acceptable for the manual
  helper, but the daemonized helper should persist `(session_id, ipv4,
  optional_ipv6)` on install and reject mismatched removals.

Second manual lifecycle slice implemented as `writ-agent-vm-runner`, with
quiet-list cleanup postconditions:

- `start` allocates the planned session subnet from broker-owned IPv4/IPv6 pools and
  derives stable Apple container network/VM names from the session ID;
- it creates the Apple `--internal` network, runs `container network inspect`,
  and refuses to continue unless the reported IPv4 subnet/gateway match the
  planned session network. In `dual-stack-required` mode it also requires the
  reported IPv6 subnet/gateway to match the planned session network;
- only after that inspection passes does it install the PF session anchor
  through `writ-agent-vm-pf-helper`, and only after PF install succeeds does it
  run the VM;
- if network creation succeeds but inspection or PF install fails, it removes
  the network before returning an error; if VM start fails after PF install, it
  attempts VM removal, then removes the PF anchor and network. Cleanup
  attempts all applicable steps and reports all cleanup errors, not only the
  first one;
- `stop` reconstructs the session network and firewall scope from the same
  session ID, pools, subnet index, and IPv6 mode, then removes the VM, PF
  anchor/states, and network in that order. VM and network removal are
  postcondition-checked with Apple Container quiet-list output: the runner does
  not report success until the deleted resources are no longer observable in
  `container list --all --quiet` and `container network list --quiet`;
- `stop` requires an explicit `--ipv6-mode` so the removal firewall scope
  matches the mode used at install time;
- both `start` and `stop` support `--dry-run`, which prints the exact process
  invocations that may be used for the lifecycle path without touching
  `container` or PF.

First stateful lifecycle-manager slice implemented in `writ-agent-vm-runner`
managed mode:

- `managed-start` uses the same lifecycle plan as `start`, but first writes a
  durable per-session state record under
  `$XDG_STATE_HOME/writ/agent-vm-sessions` or
  `~/.local/state/writ/agent-vm-sessions`, overrideable on managed commands
  with `--state-dir` / `WRIT_AGENT_VM_STATE_DIR`. Empty `XDG_STATE_HOME` is
  treated as unset, and missing or invalid `HOME` fails visibly rather than
  falling back to a temporary directory. On Unix the state directory is
  forced to mode `0700`, state files are created as `0600`, and file/directory
  syncs are used around create, replace, and remove operations;
- the record stores the session ID, broker-owned pools, subnet index, exact
  derived IPv4/IPv6 subnets, firewall IPv6 scope, VM/network names, broker
  ports and allowed port range, IPv6 mode, image, guest command, and resource
  sizing. On read, these redundant facts are re-derived and cross-checked, so
  a corrupted or hand-edited record fails closed instead of driving cleanup
  with mismatched parameters;
- if `managed-start` fails before creating any infrastructure, it removes the
  state record. If it fails after partial infrastructure creation and rollback
  cleanup also fails, the `Starting` record remains so `managed-stop` can retry
  cleanup from recorded facts. Managed start and stop take a state-store OS
  advisory lock while interpreting those records, and `Starting -> Running`
  promotion only succeeds if the original `Starting` record is still present
  and unchanged. The lock is blocking: a concurrent managed operation waits
  until the current one releases the store lock, so a wedged runner process must
  be killed or supervised by the caller before later managed operations can
  proceed;
- `managed-stop` accepts only `--session-id`, loads the recorded state, derives
  the `AgentVmSessionStopPlan` from that record, accepts both `Starting` and
  `Running` records, and removes the state file only after VM, PF, and network
  cleanup report success. If cleanup fails, the record remains so the same
  session can be retried without asking the caller to reconstruct subnet or
  IPv6-mode arguments;
- state schema version `1` is fail-closed. There is no migration path yet:
  bumping the version rejects older records on disk until an explicit migrator
  is implemented;
- the existing stateless `start`/`stop` commands remain available for manual
  proof harnesses and low-level debugging, but the production broker should
  call the managed commands or the equivalent Rust `start_managed...` /
  `stop_managed...` API.

The runner advertises the broker URL over the IPv4 host-only gateway for now.
In `dual-stack-required` mode, IPv6 is validated and filtered, but it is not
handed to the guest as a broker endpoint until the VM-facing transport has
explicit IPv6 binding and authentication semantics.

Third manual lifecycle slice: explicit IPv6 posture:

- the lifecycle plan now carries an explicit IPv6 isolation mode. The default
  `dual-stack-required` mode preserves the original fail-closed behavior:
  Apple `container network inspect` must report both IPv4 and IPv6 fields, and
  the reported IPv6 subnet/gateway must match the broker-planned network;
- `ipv4-only-no-guest-ipv6` is an explicit fallback for the current observed
  Apple CLI behavior where the internal network either omits IPv6 details or
  reports an Apple-chosen ULA `/64` that is not the broker-planned prefix. In
  this mode the runner installs an IPv4-only PF anchor before starting any VM,
  then starts the VM with a small guarded prelaunch command rather than
  immediately running the authority-bearing agent command;
- the guarded VM waits on `/run/writ-agent-vm/start`. While it is waiting, the
  runner executes `ip -6` inside the guest and refuses to release the real
  command unless the guest has no non-link-local IPv6 address and no IPv6
  default route. If the image lacks the `ip` command, the start fails closed;
- because this mode wraps and later `exec`s the requested command, it requires
  an explicit guest command rather than relying on an image default command;
- only after the guest IPv6 posture check passes does the runner touch the
  start file, causing the guarded process to `exec` the requested guest
  command. If probing or release fails, cleanup removes the VM, PF anchor, and
  network.

This mode is not a silent fallback. It is a separately named posture with its
own proof obligation, because the guarantee is different: "no guest IPv6
route/address exists" rather than "PF has been installed for the inspected
IPv6 prefix." The runner deliberately omits `--ipv6-cidr` when installing the
PF anchor in this mode; installing a rule for the broker-planned IPv6 prefix
would be misleading when Apple attached a different ULA prefix. The active
protection, and the only IPv6 enforcement in this mode, is the pre-release
guest proof that there is no routable IPv6 state.

That proof is point-in-time: it runs immediately before releasing the guarded
guest command. The current assumption is that Apple `--internal` networks do
not later inject IPv6 router advertisements or otherwise add a routable IPv6
configuration after the probe. If that assumption fails in manual testing, this
mode should stay disabled until the runner can continuously monitor IPv6 state
or enforce an equivalent in-guest IPv6 disablement before release.

### PF strategy

The first implementation should be conservative:

- allow the agent subnet to connect only to broker ports;
- block all other IPv4 traffic from the agent subnet;
- block all other IPv6 traffic from the agent prefix;
- remove live states on teardown.

Two implementation variants need a privileged proof spike.

#### Variant A: broker binds wildcard, PF filters access

The broker listens on `0.0.0.0:<port>` and possibly `[::]:<port>`. PF allows
the agent subnet to that port and blocks all other ports from the agent subnet.

This is simpler and likely to work immediately. The broker must also reject
unexpected source subnets at the application layer, because a wildcard listener
may be reachable from other host interfaces unless the host firewall also
restricts inbound access from non-agent networks.

Sketch:

```pf
agent4 = "192.168.126.0/24"
agent6 = "fd83:b6f2:e57:f536::/64"
broker_ports = "{ 18080, 18081 }"

pass in quick inet proto tcp from $agent4 to any port $broker_ports keep state
pass in quick inet6 proto tcp from $agent6 to any port $broker_ports keep state

block return in quick inet from $agent4 to any label "writ deny agent v4"
block return in quick inet6 from $agent6 to any label "writ deny agent v6"
```

#### Variant B: PF redirects gateway traffic to localhost

The broker listens only on `127.0.0.1:<port>` / `[::1]:<port>`. PF redirects
traffic from the agent subnet to the internal-network gateway address onto the
localhost broker.

This is cleaner if macOS PF applies `rdr` to these vmnet packets in the
expected place. It was not proven in the first spike.

Sketch:

```pf
agent4 = "192.168.126.0/24"
gw4 = "192.168.126.1"
broker_ports = "{ 18080, 18081 }"

rdr pass inet proto tcp from $agent4 to $gw4 port $broker_ports -> 127.0.0.1
block return in quick inet from $agent4 to any label "writ deny agent v4"
```

If this works, it avoids exposing the broker on wildcard host interfaces.

### Bootstrap

macOS `/etc/pf.conf` defines Apple anchor points but not a writ session
anchor. Install a one-time top-level rule that points directly at the
per-session anchor path rather than loading under `com.apple/*`:

```pf
anchor "writ/session/*"
```

The helper can then load session rules into anchors such as:

```text
writ/session/<session-id>
```

This bootstrap is a setup step and should be explicit in the installer docs.
The broker should refuse to start VM sessions if the anchor point is missing.
Do not rely on `anchor "writ/*"` for this shape: on macOS PF it may not
evaluate rules loaded into the nested `writ/session/<session-id>` anchor.

## Nix inside the VM

Use an OCI image containing:

- Nix;
- Git;
- the agent runtime;
- a small VM-side broker client;
- certificate roots;
- no host-specific secrets.

The VM gets a private writable `/nix/store` in its own ext4 rootfs. Nix
substituters are reached through the broker proxy. The broker can enforce:

- allowed substituter hosts;
- maximum response size;
- fixed request methods;
- audit rows per fetch;
- optional content hash checks where Nix exposes expected hashes.

Do not mount the host Nix store. Sharing the host store would break the
filesystem isolation goal and complicate auditability.

## Git model

The current broker mints short-lived GitHub App tokens and returns them to the
caller. For the VM design, this should change.

Preferred model:

- VM asks broker to clone/fetch/push a repo.
- Broker evaluates policy.
- Broker uses host-held GitHub App credentials.
- Broker either streams Git smart-HTTP between VM and GitHub, or materializes
  the requested repository data through a broker-owned Git service.
- Pushes pass through broker-side validation and signing before GitHub sees
  them.

Commit signing options:

1. VM-side commits call `SignCommit` on the broker as a Git signing helper.
   This keeps signing keys on the host, but the VM still constructs the commit
   object.
2. Broker-side push rewriting receives proposed Git objects from the VM,
   validates policy, signs or rewrites commits on the host, and pushes to
   GitHub. This keeps the strongest control boundary, but rewritten commits
   change object IDs.

Option 1 is a smaller first step. Option 2 is the cleaner authority boundary
if commit identity must be entirely broker-controlled.

## Tests and proof spikes

First pure slice implemented in `src/core/agent_vm.rs`:

- typed IPv4/IPv6 CIDRs with host-bit validation;
- broker-managed agent network pools, with allocation as the only public path
  to an `AgentNetwork`;
- RFC1918 and ULA checks for pool bases;
- broker port validation with explicit rejection of port 0;
- structured PF ruleset descriptions plus a renderer;
- property tests for host-bit rejection, subnet containment, allocation
  injectivity, IPv4 `/24` stride, and rendered broker-port coverage.

`BrokerPort` proves "stable and unprivileged"; the privileged helper adds the
configured `BrokerPortRange` check before loading PF rules.

The next spike should run with a temporary internal network and a temporary PF
anchor:

1. Start two host services: one intended broker port, one forbidden port.
2. Start an internal-network VM.
3. Verify the VM can reach the broker port.
4. Verify the VM cannot reach the forbidden host port.
5. Sanity-check that direct IPv4 internet still times out.
6. Sanity-check that direct DNS still times out.
7. Verify IPv6 cannot bypass the IPv4 rules.
8. Verify cleanup removes rules, states, VM, and network.
9. Repeat with two simultaneous session subnets to test rule independence.

After that, add Rust tests around the pure parts:

- session network allocation never overlaps;
- generated PF input is valid for only allowed subnet/port/session values;
- illegal session IDs and non-owned subnets are rejected before rendering;
- policy decisions for Git/network operations match a simple oracle.

The PF integration test will need a privileged test harness and should be
opt-in. The pure rendering and allocation tests should run unprivileged.

Manual PF proof harness added in `scripts/prove-pf-internal-network.sh`:

- creates a temporary Apple `container --internal` network and Alpine VM;
- starts one host broker listener and one host forbidden listener;
- installs the temporary `writ/session/<uuid>` PF anchor through
  `writ-agent-vm-pf-helper`, which renders through `src/core/agent_vm.rs` and
  loads the anchor only after `pfctl -n` accepts the generated rules;
- asserts broker reachability and forbidden-host-port blocking on the same
  gateway address. This is the load-bearing PF check, because only PF can
  distinguish those host ports;
- also sanity-checks direct IPv4 and direct external-DNS blocking. Those probes
  are not independent PF proof, because Apple `container --internal` is already
  host-only and should fail them even with an empty session anchor;
- when network inspect reports IPv6 and the VM has an address in that prefix,
  it also asserts host IPv6 lateral blocking and IPv6 non-bypass;
- stops the VM, removes the network, flushes the PF anchor, and kills matching
  PF states through `trap` cleanup.

It is deliberately not part of normal CI because it needs Apple `container`,
`pfctl`, root privileges, and the one-time top-level
`anchor "writ/session/*"` PF
bootstrap.

Privileged proof result on 2026-04-28:

- with only the broader `anchor "writ/*"` bootstrap, the VM could reach the
  broker port but could also reach the forbidden host port. That indicates
  rules loaded into `writ/session/<session-id>` were not being evaluated by
  that bootstrap shape on macOS PF;
- after adding the direct `anchor "writ/session/*"` bootstrap, the same
  harness passed for IPv4: the VM reached the broker port, the forbidden host
  port failed with `Connection refused` from PF `block return`, direct
  `http://1.1.1.1/` failed, and external DNS via `1.1.1.1` failed. The
  broker-vs-forbidden gateway-port result is the PF-specific evidence; the
  internet and DNS failures are host-only-network sanity checks;
- the successful run did not prove IPv6 because Apple `container network
  inspect` did not report both an IPv6 subnet and gateway, so the harness
  skipped IPv6 probes explicitly;
- a follow-up run with `anchor "writ/session/*"` present and the broader
  `anchor "writ/*"` absent also passed, so the broader anchor is unnecessary
  for this harness;
- after replacing the proof-only renderer with `writ-agent-vm-pf-helper`, the
  helper-backed harness also passed: it validated and loaded
  `writ/session/<session-id>`, allowed the broker port, blocked the forbidden
  host port on the same gateway, cleaned up the anchor through helper `remove`,
  and again skipped IPv6 because no usable IPv6 subnet and gateway were
  reported.

Manual lifecycle runner status:

- `writ-agent-vm-runner start --dry-run` emits the intended ordering:
  `container network create`, `container network inspect`, helper `install`,
  then `container run` with the session network and no mount/publish flags;
- with `--ipv6-mode ipv4-only-no-guest-ipv6`, dry-run start additionally emits
  the guarded VM start, the guest IPv6 probe, and the release command in that
  order. The authority-bearing guest command is embedded behind the guard and
  is not executed until the release command runs;
- `writ-agent-vm-runner stop --dry-run` emits cleanup in reverse authority
  order: VM removal attempts, helper `remove`, then network removal attempts.
  Non-dry-run `stop` treats exact absence from `container list --all --quiet`
  and `container network list --quiet`, not command exit alone or `inspect`
  output, as the VM/network cleanup oracle. Stop requires explicit
  `--ipv6-mode` to keep helper removal symmetric with helper install;
- non-dry-run start in default `dual-stack-required` mode is expected to fail
  closed on the current observed Apple CLI output until `container network
  inspect` reports the IPv6 fields needed to prove that the PF IPv6 prefix
  matches the actual VM network;
- non-dry-run start in `ipv4-only-no-guest-ipv6` mode should be manually
  exercised on macOS with Apple `container`: it is intended to proceed when
  inspect either omits IPv6 entirely or reports an Apple-chosen ULA `/64`, but
  only if the guest image can prove, via `ip -6`, that no routable guest IPv6
  posture exists. A non-ULA observed IPv6 subnet, malformed prefix, IPv6
  gateway without subnet, or gateway outside the subnet remains a hard failure.

Manual runner lifecycle proof harness added in
`scripts/prove-agent-vm-lifecycle.sh`:

- builds `writ-agent-vm-pf-helper` and `writ-agent-vm-runner`;
- starts host broker and forbidden listeners;
- starts a real runner-managed session in `ipv4-only-no-guest-ipv6` mode with
  a guarded guest command that writes a release marker and then sleeps;
- asserts that the runner released the command, the guest has required probe
  tools, the guest has no routable IPv6 posture after release, the broker port
  is reachable, the forbidden host port is blocked, and direct IPv4/DNS sanity
  probes fail;
- stops the session through `writ-agent-vm-runner stop`;
- asserts the VM and network are absent from Apple Container quiet-list output,
  the PF anchor is empty, and any observed guest-IPv4 PF states are gone after
  runner stop;
- keeps trap cleanup as a fallback, but treats runner `stop` plus post-stop
  assertions as the proof path.

Manual two-session runner proof harness added in
`scripts/prove-agent-vm-two-sessions.sh`:

- builds `writ-agent-vm-pf-helper` and `writ-agent-vm-runner`;
- starts two host broker listeners and one forbidden listener;
- runs two full passes, one stopping session A first and one stopping session
  B first. Each pass starts two real runner-managed sessions in
  `ipv4-only-no-guest-ipv6` mode on different subnet indexes and different
  broker ports;
- asserts each VM reaches only its own broker port through its own host-only
  gateway, and cannot reach the other session's broker port on that same
  gateway. This is the load-bearing session-independence check, because both
  tested broker listeners are live on the host at the same time;
- asserts both VMs have no routable IPv6 posture and fail the
  forbidden-host-port, direct IPv4, and direct DNS probes;
- snapshots both PF anchors before teardown. After stopping the first session
  in the pass, it verifies that the stopped session's VM, network, PF anchor,
  and observed guest-IPv4 PF states are gone, the survivor's PF anchor is
  unchanged, and the survivor still reaches its own broker while still failing
  the stopped session's broker port;
- stops the survivor and verifies its VM, network, PF anchor, and observed
  guest-IPv4 PF states are gone;
- keeps trap cleanup as a fallback.

Manual macOS result on 2026-04-29: this harness passed in both teardown
orders for subnet indexes 252 and 253. The run proved that two simultaneous
runner-managed `ipv4-only-no-guest-ipv6` sessions can each reach only their
own broker, cannot reach the other live session's broker port through their
own gateway, keep the survivor's PF anchor unchanged after stopping the first
session, and clean up both sessions' VMs, networks, PF anchors, and observed
guest-IPv4 PF states.

## Risks

- PF rule ordering on macOS can be surprising when other software also manages
  anchors. The broker should own a dedicated anchor and never flush global
  rules.
- Host-only vmnet gateway addresses are reachable but not bindable. This
  pushes us toward wildcard binding plus filtering, or PF `rdr` if proven.
- IPv6 must be handled explicitly. The lifecycle runner either requires
  `container network inspect` to report the IPv6 prefix or uses the separately
  named `ipv4-only-no-guest-ipv6` posture to prove the guest has no routable
  IPv6 before releasing the real command.
- Existing host services bound to `0.0.0.0` are reachable from the VM unless
  blocked. This is the main isolation gap after switching to `--internal`.
- Cleanup must remove live PF states. Otherwise an already-open connection may
  outlive the policy row that allowed it.
- A host-local broker API must authenticate the session, not just rely on
  source IP. Source subnet filtering is necessary but not sufficient for API
  authority.

## Feasibility verdict

The design is feasible if host-side filtering is treated as part of the
trusted computing base.

The confirmed pieces are:

- Apple `container` can run the agent VM without host mounts.
- `--network none` fully removes guest egress.
- `--internal` creates a host-only network that blocks direct internet while
  preserving a path to a host broker.
- The guest rootfs is private and writable, so `/nix/store` can be private.

PF enforcement has been proven for the IPv4 host-gateway port distinction:
the VM can reach the broker port while a second host port on the same gateway
is blocked by the session anchor. Runner-managed two-session IPv4 isolation
has also been proven manually in both teardown orders. Dual-stack IPv6 PF
enforcement remains unproven.
