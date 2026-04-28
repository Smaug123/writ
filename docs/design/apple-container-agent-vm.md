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

## Host-side filtering

Use macOS PF (`pfctl`) with per-session anchors. The broker itself should not
run as root; use a small privileged helper or launchd service that accepts
only structured operations:

```text
InstallSessionFirewall(session_id, ipv4_subnet, ipv6_prefix, broker_ports)
RemoveSessionFirewall(session_id)
```

The helper must validate that:

- the subnet belongs to the broker-managed range;
- the session ID is a safe anchor name component;
- broker ports are in an allowed local range;
- generated PF rules parse with `pfctl -n` before being loaded;
- cleanup only touches the matching session anchor.

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

The current `BrokerPort` type only proves "stable and unprivileged"; the
privileged helper should add a configured `BrokerPortRange` check before
loading PF rules.

The next spike should run with a temporary internal network and a temporary PF
anchor:

1. Start two host services: one intended broker port, one forbidden port.
2. Start an internal-network VM.
3. Verify the VM can reach the broker port.
4. Verify the VM cannot reach the forbidden host port.
5. Verify direct IPv4 internet still times out.
6. Verify direct DNS still times out.
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
- renders the temporary `writ/session/<uuid>` PF anchor through
  `src/core/agent_vm.rs`;
- loads the anchor only after `pfctl -n` accepts the generated rules;
- asserts broker reachability, forbidden-host-port blocking, direct IPv4
  blocking, and direct external-DNS blocking; when network inspect reports
  IPv6 and the VM has an address in that prefix, it also asserts host IPv6
  lateral blocking and IPv6 non-bypass;
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
  `http://1.1.1.1/` failed, and external DNS via `1.1.1.1` failed;
- the successful run did not prove IPv6 because Apple `container network
  inspect` did not report both an IPv6 subnet and gateway, so the harness
  skipped IPv6 probes explicitly;
- a follow-up run with `anchor "writ/session/*"` present and the broader
  `anchor "writ/*"` absent also passed, so the broader anchor is unnecessary
  for this harness.

## Risks

- PF rule ordering on macOS can be surprising when other software also manages
  anchors. The broker should own a dedicated anchor and never flush global
  rules.
- Host-only vmnet gateway addresses are reachable but not bindable. This
  pushes us toward wildcard binding plus filtering, or PF `rdr` if proven.
- IPv6 must be handled explicitly. The internal network creates an IPv6 prefix
  as well as IPv4.
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

The unproven but plausible piece is the PF enforcement layer. That should be
the next proof spike before implementing the full brokered agent runner.
