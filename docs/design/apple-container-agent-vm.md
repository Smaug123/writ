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

Treat every guest-originated broker request as hostile, and at minimum treat the
guest VM as compromised once the agent command has started. The VM may honestly
run the requested agent, or it may send arbitrary VM HTTP requests using its
session bearer secret. Repository-controlled bootstrap work, including devshell
warmup, is not a relaxation of that boundary. Therefore every interaction with
Git, Nix, model APIs, signing, or any other outside authority must continue to
cross a broker endpoint that authenticates the session, parses the request into
typed data, applies policy, enforces size and resource bounds, and audits the
outcome. Guest-side convenience commands are ergonomic wrappers only; they are
not part of the authority boundary.

The workspace-bootstrap upgrade intentionally has no managed-state migration
path. Operators upgrading across that change must stop and remove all existing
daemon-managed VMs before starting the new daemon. Persisted records from older
versions are cleanup obligations only, not resumable sessions.

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
- the base VM route is `GET /v1/session`, which returns the session identity
  and protocol version. The Git clone route can be enabled by running the VM
  HTTP listener with a `VmHttpGitCloneService`; Nix, model, and signing
  operations remain deliberately unexposed until their host-side policy and
  audit semantics are designed. Authentication denials are returned as HTTP
  `401`/`403`; routes that are not ordinary capability mints need their own
  durable audit shapes because transport-auth failures are not GitHub
  capability requests.

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
  runner runs one guest exec that first **enforces** the posture — disabling
  IPv6 in the guest kernel (`net.ipv6.conf.{all,default}.disable_ipv6=1`, which
  flushes any address the guest already SLAAC'd) — and then **verifies** it by
  running `ip -6`, refusing to release the real command unless the guest now
  has no non-link-local IPv6 address and no IPv6 default route. Enforce and
  verify are one atomic exec, so no Router Advertisement can re-add an address
  between them; the verify is still load-bearing (a failed disable leaves the
  address and fails the start). If the image lacks the `ip` command, the start
  fails closed;
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
would be misleading when Apple attached a different ULA prefix.

The original probe was point-in-time and rested on an assumption that Apple
`--internal` networks do not later inject IPv6 Router Advertisements. **That
assumption failed**: on macOS 26.5.1 / `container` 0.11.0 the host vmnet
advertises IPv6 RAs on the shared link regardless of the network's own (absent)
v6 config, and a guest with default `accept_ra` SLAACs a global-scope ULA
(`fd…/64 … proto kernel_ra`) a beat after boot — after the point-in-time probe
would have passed. The first remedy ("enforce an equivalent in-guest IPv6
disablement before release") is one layer of the mode: the pre-release step
disables IPv6 in the guest kernel (flushing any RA-acquired address and ignoring
later RAs) and then verifies the clean posture.

That in-guest disable is **not sufficient on its own**, because it runs before
the agent command is released and the guest runs as root: once released, the
agent can write `0` back to `disable_ipv6`, wait for the next vmnet RA, and
re-acquire the ULA — a bypass the pre-release proof cannot see (#288). So the
mode also installs a **host-side backstop the guest cannot undo**: after the VM
(and thus its host `bridgeN`) is up, the runner re-invokes the privileged
pf-helper with `--deny-guest-ipv6`. The **pf-helper itself** then discovers the
bridge carrying the session's IPv4 gateway via `ifconfig` (see
`parse_bridge_for_gateway`), reads its `vmenet*` members, and re-loads the
session PF anchor with an interface-scoped IPv6 deny (`block return in quick on
<iface> inet6 all`) on the bridge and members. Discovery lives at the privileged
boundary, not the unprivileged runner, so the helper never trusts a
caller-supplied interface name — a direct `--deny-guest-ipv6` invocation cannot
make it load a rule on an unrelated host interface such as `en0`. The scope is
by interface rather than source CIDR precisely because the RA ULA prefix is
unpredictable *and* a root guest could reassign its source address anyway — only
the interface scope holds.

Discovery is defensive on two axes so the deny can never land on the wrong or an
incomplete interface set: it accepts only a `bridgeN`-named interface with
`vmenetN` membership (rejecting a LAN/VPN `en0`/`utun` that happens to carry the
gateway when the RFC1918 pool overlaps), and it waits for the expected number of
members to attach — one for host placement (the agent's `vmenet`), two for vm
placement (the broker VM's plus the agent's) — before installing, so the agent's
own interface is never missing from the deny. It is installed before the guest
command is released, and fails closed: if no qualifying bridge carries the
gateway (or too few members have attached) after a bounded retry, the start
aborts rather than release the guest without the backstop.
`scripts/prove-agent-vm-lifecycle.sh` proves, on real hardware, both that the
rule is installed and that a root guest which re-enables IPv6 still cannot egress
it (it requires a real ICMPv6 probe tool and fails the proof, rather than
passing, if none is present).

The guarantee is therefore layered: "the guest kernel has IPv6 disabled" (belt,
guest-side, holds against RAs at boot) **and** "the host drops all IPv6 on the
agent's bridge" (suspenders, host-side, holds against a compromised root guest).

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
gw4 = "192.168.126.1"
gw6 = "fd83:b6f2:e57:f536::1"
broker_ports = "{ 18080, 18081 }"

pass in quick inet proto tcp from $agent4 to $gw4 port $broker_ports keep state
pass in quick inet6 proto tcp from $agent6 to $gw6 port $broker_ports keep state

block return in quick inet from $agent4 to any label "writ deny agent v4"
block return in quick inet6 from $agent6 to any label "writ deny agent v6"
```

The allow rules pin the destination to the gateway address rather than the
wildcard `any`, so PF mechanically enforces "agent talks to broker only" even
if Apple's `--internal` is dropped or a routable interface is later attached
to the bridge — defence in depth that does not rely on the surrounding network
configuration.

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

### Flake-input provisioning

A no-egress guest cannot fetch a flake's *inputs*. `nix develop` /
`nix flake metadata` resolve the inputs a repo's `flake.lock` pins
(`github:numtide/flake-utils`, `github:NixOS/nixpkgs`, …) directly from their
origins, which the guest firewall blocks; the nix-cache proxy only substitutes
*store paths by hash*, so it is not a flake-input fetcher. Out of the box a
no-egress guest therefore cannot evaluate any flake with inputs.

The broker closes this gap the same way it provisions a repo for `git clone`:
the host (which has egress) fetches the inputs, and the guest consumes them
through the substituter it already trusts.

1. **Retain.** Each `git clone` keeps its bare mirror in a `(repo, rev)`-keyed
   cache (`flake_mirror_cache_dir`). Concurrent VMs cloning the same commit
   share one mirror.
2. **Provision.** Between checkout and warm, the guest POSTs `(repo, rev)` to
   `/v1/nix/flake/provision`. The broker re-derives the checkout from its
   retained mirror (a `git clone --local`, so the working tree is independent
   of the mirror's lifetime) and runs `nix flake archive
   --no-update-lock-file` over the committed lock, fetching the inputs'
   content-addressed source paths into a shared cache (`flake_input_cache_dir`).
   The guest never sends flake content. `--no-update-lock-file` (not merely
   `--no-write-lock-file`) is load-bearing: a stale lock — `flake.nix` and
   `flake.lock` disagreeing — fails closed rather than provisioning an
   unreviewed, in-memory-updated input graph. The committed lock is *untrusted*
   input (the agent's repo wrote it), so the host-side classifier is a security
   gate, not just a feature filter (see "Scope" below).
3. **Serve + substitute.** The nix-cache endpoint serves that cache
   *local-first*: a provisioned path is served from the local archive; anything
   else proxies upstream (cache.nixos.org). With github blocked, the guest's
   `nix develop` substitutes the locked inputs from the local archive and never
   contacts github. Build outputs substitute from cache.nixos.org as normal.

The inputs are content-addressed (`fixed:r:sha256:…`), hence self-certifying:
the local archive is admitted by hash verification, so no broker signing key
and no guest `trusted-public-keys` change are needed. `nix flake archive` is
platform-independent — an aarch64-darwin host produces exactly the input
*source* paths an aarch64-linux guest needs to evaluate; the guest's *build
outputs* still substitute from cache.nixos.org.

The guest gains no new egress, preserving the trust model: the broker (which
already has egress for `git clone`) is the boundary. The host fetch runs with
import-from-derivation disabled (`allow-import-from-derivation=false`) and
against the committed lock only (`--no-update-lock-file`), and is audited in the
`flake_provision` table. Its bounds differ in kind: the input *count* is checked
against the lock before any fetch; the *timeout* caps wall-clock; the
total-*bytes* cap is a fail-closed check on the archived result (an over-budget
archive is discarded, never published) rather than an in-flight limit — a single
very large input can still consume network and disk up to the timeout before
being rejected, and `nix flake archive` is not run in a forced sandbox. Because
a session may only provision a repo it was itself granted contents-read on — the
provision endpoint requires a prior clone grant for `(repo)` in the session — a
session cannot drive
provisioning of another session's cached private mirror.

**Enabling.** Provisioning is on exactly when `flake_mirror_cache_dir` is set:
the clone handler then retains mirrors and `/v1/nix/flake/provision` is served.
Without it the endpoint answers `404` and the guest degrades — the bootstrap
provision call is best-effort, so warm still runs and surfaces the original
github-unreachable failure only if the inputs were really needed.

**Scope (v1).** Public inputs only. A committed `flake.lock` is required; a
missing lock is a clear error. The host-side classifier admits an input only if
it is locked (carries `narHash`, plus `rev` for git-like inputs), non-local (no
`path:`/`file://`), and free of *static* credential markers (no `ssh`/`git+ssh`
transport, no `user[:pass]@` userinfo). It also rejects a *literal* internal
host — an IP literal that is loopback / link-local (incl. the `169.254.169.254`
metadata address) / private / CGNAT, or `localhost` — parsed through the WHATWG
URL parser first so integer/hex/octal and short-form IPv4 spellings and
authority-smuggling tricks are canonicalised before the range check.

The host fetch runs **credential-free**: the broker clears the environment to
the non-credential plumbing nix needs (PATH, daemon socket, CA certs) with a
fresh `HOME`, so the operator's user-level `nix.conf` / `~/.netrc` / git
credentials cannot reach it. That is what makes "a private input fails at
fetch" hold instead of silently caching private source for the guest with the
operator's tokens.

Residuals worth stating plainly rather than overclaiming (the implementation
documents these in `src/flake_provision.rs`; the deferred disposable egress-VM
provisioner would close the first two):

- **System nix credentials.** A system-level `/etc/nix/nix.conf`
  `access-tokens`, on a host where the broker is not a trusted nix user, is not
  overridden by the credential-free environment, so a private input could
  authenticate through it.
- **Pre-realised store paths.** nix runs against the host's default
  store/daemon, so a private input whose fixed-output source is *already
  realised* in that store is archived without a fetch — bypassing the "fails at
  fetch" assumption. A fresh per-run store would close this.
- **DNS to internal addresses.** The classifier rejects only *literal* internal
  hosts; an allowed *domain* can DNS-resolve to an internal address, and `nix
  flake archive` runs with no fetch-time egress filter, so it would connect
  before any hash check. Fetch-time public-IP enforcement (a network sandbox or
  proxy) is needed.

Separately, a private `github:`/`https:` input whose lock entry *looks* public
(no static credential markers) passes the classifier and then fails inside `nix
flake archive`, surfacing as a generic provisioning failure — not the clear
"unprovisionable" message the statically auth-requiring cases get.

Until the egress-VM provisioner lands, run the broker as a non-trusted nix
user, without system credentials, on a host whose outbound network it is
acceptable for the broker to reach. Brokered private-input fetch via the GitHub
App, and host-side locking for lock-less repos, are follow-ups.

**Guarantee / envelope.** At bootstrap, every *provisionable* input in the
committed lock becomes available to the guest, so `nix develop` evaluates and
enters the devShell **provided (a) the committed lock's inputs are all
provisionable — public and classifier-admitted, per "Scope" above — and (b) the
devShell's output closure is substitutable from cache.nixos.org for the guest
system**. If the lock pins a non-provisionable input (private/auth-requiring/
local), that input is not provisioned and warm fails even when the output
closure is cached. Constraint (b) is lifted by the pre-warmed devShell cache
(`docs/plans/2026-06-07-prewarmed-devshell-cache.md`): with
`nix_prewarm_cache_dir` configured, the devShell warm is served strictly from
the operator's signed pre-warm archive (plus this input archive) through the
`/v1/nix/prewarm` view, so the closure need not be on cache.nixos.org — but
must instead have been pre-warmed; the warm never proxies the public upstream
at all. A later in-guest flake edit that needs a brand-new input
will not substitute either — that is the no-egress envelope, by design: the
broker is not a general egress proxy.

**Cache growth.** Both the `(repo, rev)` mirror store and the content-addressed
input archive accumulate across sessions; the archive is content-addressed, so
cross-session sharing is safe and deduplicates. A bounded GC for the mirror
store is a follow-up — it must skip a mirror that a provision is mid-`git clone
--local`-ing, so it cannot delete an entry out from under a running clone.

The end-to-end behaviour is exercised by
`scripts/prove-agent-vm-devshell-warm.sh`, which boots a no-egress VM, warms a
real flake devShell, and asserts the locked inputs were served from the
provisioned cache rather than fetched from github.

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

First Git clone bundle model slice implemented in `src/vm_git.rs` and
`src/vm_git_bundle.rs`:

- the VM-facing route is pinned as `POST /v1/git/clone`, with a validated JSON
  body containing a GitHub repo and optional Git ref;
- repo and ref inputs are parsed into VM-safe wire types. Secret-env-var and
  host path inputs are parsed separately in the host-only bundle module before
  any command can be described. Invalid owner/name/ref syntax, relative
  work/output paths, zero timeouts, and zero bundle-size limits fail before the
  executor runs;
- the VM HTTP route derives the existing `GitHubRequest::Contents { access:
  Read, ... }` capability from the parsed clone request, so the broker
  integration reuses the current policy and audit path rather than adding
  Git-specific policy plumbing;
- `GitCloneBundlePlan` describes a host-side `git clone --mirror` followed by
  `git bundle create`, using an askpass boundary and required secret
  environment variable name. The plan carries no token value, and generated
  command argv contains no token material: only static Git flags, the parsed
  Git clone base URL plus GitHub owner/repo path, local temp paths, and
  optionally the validated Git ref. The clone base URL defaults to
  `https://github.com`, and startup config may override it only with an
  `http`/`https` URL without credentials, query, or fragment. Every planned Git
  invocation also carries a clean Git-configuration environment
  (`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
  `GIT_CONFIG_COUNT=0`) so ambient `url.*.insteadOf`, credential helpers, or
  environment-injected Git config cannot rewrite the HTTPS/App-token boundary
  into SSH or user credentials.

Second Git clone bundle executor slice implemented in `src/vm_git_bundle.rs`:

- `run_git_clone_bundle()` executes the planned clone and bundle commands with
  a cleared child environment, the clean Git-config variables above, null
  stdin/stdout/stderr, and only the required token environment variable passed
  to the clone step;
- the executor creates the planned work directory with private `0700`
  permissions, refuses a reused work directory, refuses a pre-existing bundle
  path using no-follow metadata, requires the bundle path to live under the
  work directory after lexical `..` normalisation, resolves relative `git`
  through the parent `PATH` before clearing the child environment, runs Git
  from `/` so broker-local `.git/config` cannot participate in config
  discovery, and enforces the per-command timeout from the plan;
- after clone and before bundle creation it canonicalises the mirror and
  bundle parent paths, rejecting symlink layouts that would place the bundle
  outside the work directory or inside the mirror repository despite passing
  the earlier lexical check;
- after bundle creation it verifies the output is a regular file, still
  resolves inside the work directory and outside the mirror repository, and is
  at or below the plan's maximum bundle size. Each Git subprocess runs in its
  own process group with an armed cleanup guard immediately after spawn. For
  success and nonzero-exit paths, the executor observes child exit without
  reaping the leader, kills the process group, and only then reaps the leader
  for `ExitStatus`; timeout, error, and future-cancellation cleanup also kill
  the process group. This keeps ordinary Git helpers from continuing with the
  secret-bearing environment after the executor returns;
- the current maximum bundle size is an output admission check, not a disk
  quota: clone and bundle creation can still consume temporary disk and IO
  until Git exits or the timeout fires. A production resource-budget slice
  still needs a bounded filesystem, per-run quota, or streaming bundle target
  if the broker must cap disk consumption during Git execution. The executor
  itself still does not mint credentials; callers supply the token boundary
  explicitly.

First VM HTTP Git clone integration slice implemented in `src/vm_http.rs` and
`src/server.rs`:

- the Unix-socket capability dispatcher now exposes a structured
  `request_capability()` outcome so VM HTTP can reuse the same session
  preflight, policy decision, pre-mint audit row, GitHub App mint, grant audit,
  and mint-failure audit path without returning raw tokens to the guest;
- the HTTP reader preserves body bytes that arrive in the same TCP read as the
  headers, rejects duplicate or invalid `Content-Length` and any
  `Transfer-Encoding`, and caps request bodies at 64 KiB. `POST
  /v1/git/clone` parses that bounded JSON body into `VmGitCloneRequest` before
  any Git command is planned. Other authenticated routes are selected before
  body reads, so a bearer-bearing guest cannot occupy connection handlers by
  declaring bodies on endpoints that do not consume them;
- when the route is enabled with `VmHttpGitCloneService`, the broker derives
  the read-only GitHub contents capability, mints a host-side installation
  token, runs the existing bundle executor with that token only in the Git
  subprocess environment, reads the resulting bundle, removes the per-request
  clone directory, and returns `application/x-git-bundle` bytes to the VM.
  Cleanup failure is a `500 clone_failed` response rather than a successful
  bundle response, because leaving private repository artifacts on the host is
  not a success state;
- inactive sessions are treated as client-context failures on the VM HTTP
  surface: an unknown session returns `401 denied`, a closed session returns
  `410 denied`, and host-side mint/audit failures return a generic
  `500 clone_failed` without echoing backend diagnostics to the VM. Non-`POST`
  methods on `/v1/git/clone` return `404`, as does every method when the Git
  route is not configured, so a guest cannot distinguish a disabled route from
  an absent one by method probing;
- the service creates each clone under a dedicated work root and refuses to use
  an existing work root with group/world access bits. The per-request work
  directory is still unique and `0700`, and is removed before the HTTP response
  is reported as successful. Concurrent first requests may race to create the
  work root; an `AlreadyExists` race is re-inspected and accepted only if the
  resulting directory still satisfies the private-mode invariant;
- the VM HTTP read timeout is scoped only to reading request headers and the
  bounded request body. Capability minting and Git execution are not cancelled
  by that transport read budget; Git subprocesses are bounded by the
  `GitCloneBundlePlan` timeout so the clone cleanup path still runs;
- this wires the route into the VM HTTP runner API, not yet into the production
  daemon startup/config path. The next broker slice should decide how `writd`
  owns the VM HTTP listener, Git binary/askpass paths, work root, size limit,
  and shutdown alongside the managed VM lifecycle.

First daemon-owned VM HTTP runtime slice implemented in `src/vm_http.rs`,
`src/config.rs`, and `src/bin/writd.rs`:

- `DaemonConfig` now accepts an optional `agent_vm.vm_http` block containing
  the wildcard/listen address, broker port range, Git binary, askpass program,
  token environment variable name, Git clone base URL, Git work root, clone
  timeout, maximum returned bundle size, Nix cache proxy settings, optional
  Claude proxy settings including the Anthropic API version, and optional
  agent-run log root. `writd` parses that
  block at startup into the typed `VmHttpGitRuntimeConfig`, so bad port ranges,
  unsafe clone base URLs, relative askpass/work-root/log-root paths, invalid
  token environment names, unsafe upstream URLs, zero timeouts, zero byte
  limits, and unwritable agent-run log roots fail before the daemon starts
  serving requests;
- `prepare_vm_http_git_session()` is the per-session ownership primitive for
  the later lifecycle/protocol slice. Given broker state, the daemon's static
  runtime config, a session ID, and the session IPv4 subnet, it binds and keeps
  open the VM HTTP listener, generates the bearer token, constructs the
  `VmHttpSession`, and returns the selected `BrokerPort` before the VM is
  started. The lifecycle caller can then install PF with the actual selected
  port rather than predicting it;
- `PreparedVmHttpGitSession::spawn()` starts the listener only after the caller
  has finished the fail-closed lifecycle steps that depend on the selected
  port. The returned `RunningVmHttpGitSession` owns the shutdown channel and
  task handle, and `shutdown().await` drains the VM HTTP runner. Dropping the
  running owner sends shutdown and aborts the task as a last-resort cleanup;
- this slice did not yet add a Unix-socket API to create agent VM sessions;
  that protocol surface is the next implemented slice below.

First daemon protocol lifecycle slice implemented in `src/agent_vm_daemon.rs`,
`src/server.rs`, `src/protocol.rs`, and `src/bin/writ.rs`:

- the host Unix-socket protocol now has `start_agent_vm`, `stop_agent_vm`, and
  `list_agent_vms` messages, exposed by the CLI as
  `writ agent-vm start -- <command>`, `writ agent-vm stop <session-id>`, and
  `writ agent-vm list`. Starting an agent VM creates the audit session inside
  `writd`; stopping the VM drives managed cleanup and closes the audit session.
  These CLI calls use a longer timeout than ordinary token-mint requests
  because Apple Container startup/teardown can include cold image work, PF
  helper execution, and guest preflight probes;
- `agent_vm.lifecycle` daemon config supplies the broker-owned IPv4/IPv6 pools,
  allowed subnet-index range, managed state directory, Apple `container`,
  `sudo`, and PF-helper tool paths, IPv6 isolation mode, image, and resource
  sizing. `writd` validates both lifecycle and VM HTTP config at startup before
  serving the socket. Managed agent VMs reject non-wildcard VM HTTP bind
  addresses because the guest is told to reach the listener through its
  per-session host-only gateway address;
- `AgentVmDaemon` serializes start/stop operations in-process, scans persisted
  managed session records to choose the first unused subnet index in the
  configured range, prepares the VM HTTP listener to obtain the actual broker
  port, then starts the managed lifecycle plan with that single selected broker
  port. The VM HTTP task is spawned only after managed start reports success.
  The managed state store also rejects a second live record with the same
  subnet index under its file lock, so a second `writd` sharing the state
  directory cannot race into the same `/24`;
- the VM receives `WRIT_BROKER_URL` and `WRIT_BROKER_TOKEN` through a transient
  `container run --env-file` rather than through command argv or persisted
  state. The env file is created with `0600` permissions and removed after the
  `container run` invocation returns. The managed state record stores the
  broker port and cleanup facts, but not the bearer token;
- on stop, the daemon first runs managed VM/PF/network cleanup from persisted
  state while leaving the state record in place, so a mistyped or non-VM
  session ID cannot close an unrelated audit session. After cleanup succeeds it
  closes the audit session, shuts down the in-memory VM HTTP task, and only
  then removes the state record. If any of those steps fail, the state record
  remains so retrying `stop_agent_vm` can use the same recorded cleanup facts;
- daemon restart recovery is intentionally cleanup-first: managed state
  survives and can drive cleanup after a restart, but in-memory VM HTTP tasks
  and bearer tokens do not. The Unix-socket protocol now exposes
  `list_agent_vms`, surfaced as `writ agent-vm list`, which reports persisted
  records with `runtime=detached` when the restarted daemon has no attached VM
  HTTP task. Listing is observational and does not wait behind the daemon's
  start/stop lifecycle mutex, so it remains useful while investigating a slow
  or stuck start; `runtime` is therefore a retryable snapshot, not an
  authority boundary. Operators can then run `writ agent-vm stop <session-id>`
  without reconstructing subnet or firewall scope by hand. A later resurrection
  protocol may safely rebind equivalent VM HTTP authority; until then, detached
  records are cleanup obligations. In-process cancellation during
  `start_agent_vm` is also treated as a crash/restart recovery case:
  state/audit may need follow-up cleanup from the persisted record rather than
  relying on the original future to run its rollback branch.

First VM-side client slice implemented in `src/vm_client.rs` and
`src/bin/writ-vm.rs`:

- the guest now has a small `writ-vm` CLI that reads the daemon-injected
  `WRIT_BROKER_URL` and `WRIT_BROKER_TOKEN` values, or accepts explicit
  overrides for tests;
- `writ-vm session` calls `GET /v1/session` and prints the broker's session
  descriptor JSON;
- `writ-vm git clone <owner>/<repo> [destination] [--ref <ref>]` posts the
  structured `VmGitCloneRequest` to `/v1/git/clone`, requires the broker's
  `application/x-git-bundle` response, refuses responses above the VM client's
  bounded bundle-size cap before buffering them, writes the bundle to a `0600`
  temporary file next to the requested checkout, invokes guest-local Git, and
  removes the temporary bundle afterwards. Full refs such as
  `refs/heads/main` are fetched from the bundle and checked out detached,
  because `git clone --branch refs/heads/main` does not resolve that spelling
  from a bundle. The explicit-ref path conservatively rejects an existing
  destination before `git init`, so it does not have weaker overwrite behaviour
  than the plain `git clone` path;
- the VM client never receives GitHub credentials. Its bearer secret is used
  only for the VM HTTP broker request and is redacted from debug output. The
  subsequent guest-local Git command receives neither `WRIT_BROKER_URL` nor
  `WRIT_BROKER_TOKEN`; it reads only from the temporary bundle path and the
  requested checkout destination. Any resulting checkout `origin` is therefore
  not durable fetch authority; later fetch/push should be brokered operations
  rather than reuse of the one-shot bundle path.

First guest image/proof integration slice implemented in `flake.nix` and
`scripts/prove-agent-vm-daemon.sh`:

- Cargo now has a lean `vm-client` feature for the guest binary. The default
  `host` feature still builds the daemon, audit log, GitHub minter, secret
  stores, PF/lifecycle helpers, and VM HTTP server, but `cargo build
  --no-default-features --features vm-client --bin writ-vm` builds only the
  guest client surface and excludes host-only dependencies such as `keyring`,
  `rusqlite`, and `jsonwebtoken`. This feature boundary is the prerequisite for
  Darwin-hosted Linux cross compilation;
- the flake now exposes Nix-built Linux OCI archives for the daemon-managed
  guest image: `agent-vm-guest-image-aarch64-linux`,
  `agent-vm-guest-image-x86_64-linux`, and a host-architecture-derived
  `agent-vm-guest-image` alias. The archive is tagged
  `writ-agent-vm-guest:latest` and contains `writ-vm`, guest-local Git, Nix,
  CA roots, `sh`, `ip`, and the core utilities needed by the
  prelaunch/release scripts. It deliberately does not ship host-side binaries
  such as `writd`, the lifecycle runner, or the PF helper;
- the daemon proof harness defaults to building the matching Nix production image,
  loading it with `container image load --input`, and starting the managed VM
  from that image. Supplying `WRIT_PROVE_IMAGE` keeps the old "use an already
  available image" path, and `WRIT_PROVE_BUILD_GUEST_IMAGE=0` uses a preloaded
  `writ-agent-vm-guest:latest`;
- the harness no longer treats raw `wget` against VM HTTP as the end-to-end
  guest proof. Inside the VM it now runs `writ-vm session` and
  `writ-vm git clone proof-owner/proof-repo /tmp/writ-agent-vm-checkout`,
  then verifies the checkout content with guest-local Git. The fake host Git
  still avoids real GitHub network access, but now materializes a real Git
  repository and bundle rather than returning marker bytes, so the guest
  client proves both the broker HTTP path and bundle consumption by Git.

Second guest image/cross-build preparation slice implemented in `src/lib.rs`,
`src/vm_git.rs`, `src/vm_git_bundle.rs`, and `src/bearer.rs`:

- the VM-client Git module now contains only the guest-visible clone
  request/response types, route constants, and GitHub repo/ref validation.
  Host-only bundle planning, credential-boundary types, Git subprocess
  execution, process-group cleanup, and related tests moved to
  `vm_git_bundle`, which is compiled only with the default `host` feature;
- `policy` and the host Unix-socket `protocol` are host-gated, so a
  `--no-default-features --features vm-client` build no longer compiles daemon
  policy/protocol modules the guest never uses;
- the shared VM HTTP bearer-token byte predicate lives in a tiny common module
  instead of in `vm_client`, keeping the validator available to both the host
  HTTP endpoint and the guest client without implying the host endpoint depends
  on guest client behaviour.

First Darwin-hosted cross-build slice implemented in `flake.nix`:

- the flake exposes standalone musl Linux guest-client binary packages:
  `agent-vm-writ-vm-aarch64-linux-musl`,
  `agent-vm-writ-vm-x86_64-linux-musl`, and the host-architecture-derived
  `agent-vm-writ-vm-musl` alias;
- each package uses the `vm-client` feature, `--no-default-features`, and
  `--bin writ-vm`, with checks disabled because the target binary is not
  executable on the Darwin builder. The current target triples are
  `aarch64-unknown-linux-musl` and `x86_64-unknown-linux-musl`. These are Nix
  packages/closures, not necessarily single static files; the aarch64 output
  currently uses the musl dynamic loader from its Nix closure;
- this proves the Rust guest client can be cross-compiled from macOS without a
  Linux builder. The OCI assembly slice below consumes this cross-built client;
  the remaining target-specific inputs are Linux userland packages (`git`,
  `ip`, CA roots, shell, and core utilities) from Linux package sets.

First Darwin-hosted OCI assembly slice implemented in `flake.nix` and
`scripts/prove-agent-vm-daemon.sh`:

- the flake now uses `nix2container` to assemble the `agent-vm-guest-image-*`
  and `agent-vm-guest-proof-image-*` OCI archives as packages for the current
  build host. On macOS, `nix build .#agent-vm-guest-image-aarch64-linux`
  therefore runs the archive assembly on Darwin instead of selecting
  `packages.aarch64-linux` and requiring a Linux builder for the final image
  step;
- the image root is a host-built symlink farm containing the cross-compiled
  `writ-vm` guest package plus target Linux userland paths. Target packages
  such as Git, `iproute2`, shell, core utilities, and CA roots are still Linux
  Nix store paths; the current expectation is that Nix obtains them from
  substitutes or an available target builder. The image also carries
  conventional empty runtime mount points such as `/tmp`, `/run`, `/var/tmp`,
  and `/root`; the lifecycle runner mounts those paths as tmpfs for each VM
  session so guest temp files, release markers, and root-user tool state are
  per-session runtime state, not static image content;
- the proof harness now builds the current-host package attr
  `.#agent-vm-guest-image-${WRIT_PROVE_GUEST_SYSTEM}` and loads the
  resulting OCI archive directly with `container image load --input`.

First guest image reduction slice implemented in `flake.nix` and
`scripts/prove-agent-vm-daemon.sh`:

- `agent-vm-guest-image-*` is the production/default image. It carries a routine
  development toolset (`curl`, `grep`, `sed`, `awk`, `find`, `rg`, `jq`, `less`,
  `diff` alongside the coreutils/git/nix base) because the agent shells out to
  these during real work, and its archive build fails if any are absent. It
  still intentionally excludes the proof-only egress/DNS negative-control tools
  `wget`, `nslookup`, and `dig`; the production archive build fails if any of
  those names appear in the root symlink farm. (Tool *absence* was never the
  egress boundary — the per-session PF firewall is — so this exclusion is a
  "proof tools must not leak into prod" hygiene guard, not a security control;
  `curl` covers the in-guest HTTP need and can only reach the broker anyway.)
- `agent-vm-guest-proof-image-*` is the manual proof image. It keeps the
  production runtime plus `wget`, `nslookup`, and `dig` (`awk`/`grep` are now
  inherited from the production base), and its archive build fails if any of
  those proof assertion tools are absent;
- the daemon proof harness now avoids proof-only guest tools in its assertions,
  so it defaults to the production `writ-agent-vm-guest:latest` image.
  Supplying `WRIT_PROVE_IMAGE` still opts into an externally-provided image.

First guest Nix bootstrap slice implemented in `flake.nix` and
`scripts/prove-agent-vm-daemon.sh`:

- the production guest image now includes the Nix CLI and sets
  `NIX_SSL_CERT_FILE` to the image CA bundle alongside Git's CA configuration;
- the image archive build fails if the required production runtime commands
  `git`, `ip`, `nix`, `sh`, or `writ-vm` are absent. The existing production
  forbidden-bin check still rejects PATH-exposed proof-only tools under `/bin`
  in the production image;
- the daemon proof harness now asserts `command -v nix` and `nix --version`
  inside the managed VM. This is deliberately a no-network bootstrap smoke:
  it proves the Nix CLI can start in the isolated guest image, not that Nix can
  fetch substituters or build derivations through broker policy. Brokered
  substituter access remains a later slice.

First Nix substituter authentication proof slice implemented in
`scripts/prove-nix-substituter-auth.sh`:

- the harness starts a host-local fake HTTP binary cache, creates a temporary
  `0600` netrc file, and runs host Nix with isolated `HOME`,
  `XDG_CONFIG_HOME`, `NIX_CONF_DIR`, and empty `NIX_CONFIG`;
- Nix is pointed at the fake cache with `nix path-info --store <cache-url>` for
  a deliberately missing store path. The command is expected to fail after the
  cache says the narinfo is missing; the captured cache request log is the
  oracle;
- the passing proof shows Nix requests `/nix-cache-info` and the target
  `.narinfo` path with netrc-derived HTTP Basic authorization, while the raw
  session token is absent from the substituter URL, Nix argv, stdout, and
  stderr;
- this selects the first brokered-substituter auth shape: the guest can receive
  a broker URL plus a session-scoped netrc entry, and the VM HTTP Nix route
  should authenticate Basic credentials in addition to its source-subnet check.
  The proof does not yet proxy real upstream caches, verify signatures, or
  stream NAR contents.

First VM HTTP Nix cache route slice implemented in `src/vm_http.rs` and
`scripts/prove-vm-http-nix-cache-route.sh`:

- the VM HTTP dispatcher now treats `/v1/nix/cache/*` as a separate auth
  surface: the existing source-subnet check still applies, but credentials are
  accepted as HTTP Basic with login `writ-vm` and the session bearer token as
  the password. Existing `/v1/session` and `/v1/git/clone` routes continue to
  require Bearer authorization;
- the initial cache implementation is deliberately a skeleton. It serves
  `GET`/`HEAD /v1/nix/cache/nix-cache-info` with cache metadata for
  `/nix/store`, returns a controlled 404 for well-formed `.narinfo` requests,
  and rejects all other cache paths. There is no upstream proxy, signature
  verification, NAR streaming, or store-realisation path in this slice;
- unit and property tests cover route classification, Basic-vs-Bearer
  separation, Basic challenge headers, no body read for cheap cache routes, and
  controlled cache misses. The ignored proof harness starts the real VM HTTP
  server and runs host Nix with a temporary netrc file against the skeleton
  cache, proving Nix can authenticate to the broker route without putting the
  session token in the substituter URL, argv, stdout, or stderr;
- that route slice stopped short of injecting guest Nix netrc/config; the next
  slice below wires that into managed VM start.

First daemon-injected guest Nix config slice implemented in
`src/agent_vm_daemon.rs` and `scripts/prove-agent-vm-daemon.sh`:

- `start_agent_vm` now injects `WRIT_NIX_CACHE_URL`,
  `WRIT_NIX_BASIC_LOGIN`, `WRIT_NIX_NETRC`, and `NIX_CONF_DIR` alongside the
  existing VM HTTP broker URL/token. The cache URL is derived mechanically from
  the per-session broker URL as `/v1/nix/cache`;
- the daemon wraps the requested guest command in a small guest-local setup
  script. Before executing the requested command it writes a `0600` netrc at
  `/run/writ-agent-vm/netrc` with login `writ-vm` and the VM bearer token, and
  writes `/run/writ-agent-vm/nix-conf/nix.conf` with `nix-command`,
  `netrc-file`, empty ambient token/key settings, and the brokered cache as the
  configured substituter;
- the managed state file still does not persist the bearer value. Unit tests
  assert the env-file and command argv carry no token in process argv/state, and
  a property test checks the wrapper preserves the original guest argv exactly;
- the daemon proof harness now runs host-started guest Nix inside the managed
  VM against `$WRIT_NIX_CACHE_URL`. The expected result is a nonzero
  authenticated cache miss from the skeleton route, not 401/403 and not token
  leakage into Nix output. This proves the injected config is sufficient for
  real guest Nix to authenticate to the VM HTTP route.

First brokered Nix metadata proxy slice implemented in `src/vm_http.rs`,
`src/config.rs`, and `scripts/prove-agent-vm-daemon.sh`:

- `agent_vm.vm_http` now requires an explicit `nix_cache_url`, a nonzero
  `nix_cache_max_metadata_bytes`, and, after the NAR slice below, a nonzero
  `nix_cache_max_nar_bytes`. Startup parsing normalises the upstream base URL,
  accepts only `http`/`https`, rejects query/fragment components and embedded
  credentials, and keeps the byte caps typed in the runtime config;
- authenticated `GET`/`HEAD /v1/nix/cache/nix-cache-info` and valid
  `/<hash>.narinfo` requests are proxied to that upstream. Response bodies are
  read with a running byte counter, upstream 404s become controlled broker
  404s, unsupported upstream statuses become 502s, and non-cache paths still
  fail closed before reaching the upstream;
- at this point the proxy was still metadata-only. NAR content streaming,
  signature/content verification, and cache-host allow-lists beyond the
  configured base URL remained separate slices;
- the daemon proof harness now starts a local fake upstream binary cache and
  verifies that guest Nix causes the daemon to fetch both `nix-cache-info` and
  the target `.narinfo` from that upstream. The VM still observes a controlled
  cache miss for the proof store path, but the miss is now through the proxy
  rather than through a local skeleton response.

First brokered Nix cache audit slice implemented in `src/audit.rs` and
`src/vm_http.rs`:

- audit schema version 2 adds `nix_cache_request` and `nix_cache_outcome`;
  schema version 3 widens the route enum to include bounded NAR body requests.
  The request row records the session, method, target, classified route
  (`nix-cache-info`, `.narinfo`, NAR body, or unsupported), and allow/deny decision.
  The outcome row records the broker HTTP status, optional upstream URL and
  upstream status, response byte count, and a bounded error label;
- the VM HTTP Nix cache route writes the request row before contacting the
  upstream cache. If that write fails, the route fails closed with `500`
  instead of making an unaudited upstream request. The outcome row is written
  before a proxied response is returned to the VM, so success, controlled
  misses, unsupported upstream statuses, and response-size failures all have
  durable outcomes;
- Basic-auth denials for Nix cache paths are also audited without contacting
  the upstream. This gives transport-auth failures their own audit shape
  instead of trying to encode them as GitHub capability requests;
- unit tests cover the schema migration, closed/missing-session rejection,
  orphan-outcome rejection, success, controlled miss, local method rejection,
  auth denial, oversized metadata, and unsupported upstream status audit rows.

First brokered Nix NAR transport slice implemented in `src/vm_http.rs`,
`src/config.rs`, and `src/audit.rs`:

- authenticated `GET`/`HEAD /v1/nix/cache/nar/<file>` requests now proxy to
  the configured upstream binary cache when `<file>` is a single safe filename
  segment. Paths with slashes, dot-directory traversal, spaces, query strings,
  percent-encoded separators, empty names, or leading/trailing dots are
  rejected before contacting the upstream;
- NAR responses require an upstream `Content-Length` and that length must be at
  or below `nix_cache_max_nar_bytes`. Missing lengths and oversized declared
  lengths fail as audited `502` responses before body streaming begins. `HEAD`
  is handled as a bounded metadata check with an empty body;
- successful `GET` streams the NAR body from upstream to the VM instead of
  buffering it in broker memory. Because the HTTP status and headers are sent
  before the body is complete, stream-truncation or body-read failures are
  recorded in the Nix cache audit outcome rather than converted into a different
  VM-visible status after the fact;
- this slice was still only cache transport. The metadata-admission slices
  below constrain `.narinfo` structure and signatures before forwarding, but
  the broker still does not sign `.narinfo` itself or check NAR content hashes.
  Those remain follow-on slices before treating the VM as able to build
  entirely from brokered cache authority.

First brokered Nix cache trust-key plumbing slice implemented in
`src/nix_cache.rs`, `src/config.rs`, and `src/agent_vm_daemon.rs`:

- `agent_vm.vm_http` now accepts optional
  `nix_cache_trusted_public_keys`, parsed as Nix cache public-key strings.
  The parser rejects empty values, whitespace/control-byte shapes, multiple
  separators, malformed base64 padding, and, after the later signature slice,
  public-key material that is not a 32-byte Ed25519 public key before the
  runtime config is built;
- daemon-managed VM start joins those typed keys into the generated guest
  `nix.conf` as `trusted-public-keys = ...`. The field defaults to an empty
  list so the current proof harness can keep exercising authenticated cache
  misses against an unsigned fake cache;
- this deliberately does not disable Nix signature checks. The next proof slice
  should generate a signed fake binary cache, configure the daemon with that
  cache's public key, and prove a real substitute can be realised through the
  brokered VM HTTP cache route.

First signed Nix substitute-realisation proof slice implemented in
`scripts/prove-agent-vm-daemon.sh`:

- the daemon proof harness now creates an ephemeral Nix binary-cache signing
  keypair, adds a tiny proof file to the host Nix store, and uses `nix copy
  --to file://...?secret-key=...` to populate a signed local fake cache. The
  proof file is fixed-output and constant, so it leaves one small reusable host
  `/nix/store` path rather than accumulating per-run store entries;
- the generated public key is inserted into
  `agent_vm.vm_http.nix_cache_trusted_public_keys`, so the guest keeps normal
  Nix signature verification enabled rather than disabling it with
  `require-sigs = false`;
- the fake upstream cache is now file-backed and serves `/nix-cache-info`,
  the signed `.narinfo`, and the referenced `nar/...` body. The VM proof runs
  `nix copy --from "$WRIT_NIX_CACHE_URL" <proof-store-path>` and checks the
  realised store object contents inside the isolated guest;
- this proves real guest Nix can authenticate to the brokered VM HTTP cache
  route, trust the daemon-configured cache key, fetch metadata and NAR bytes
  through the daemon, and realise a signed substitute. At this point it still
  relied on guest Nix for signature/content verification; the later broker-side
  signature slice below narrows that to NAR body hash verification.

First broker-side Nix `.narinfo` admission slice implemented in
`src/nix_cache.rs` and `src/vm_http.rs`:

- `parse_narinfo_for_store_hash()` reads bounded upstream `.narinfo` metadata
  before the broker forwards a successful
  `GET /v1/nix/cache/<hash>.narinfo` response to the VM. The parser preserves
  the original body for forwarding, but parses `StorePath`, `URL`, and
  `NarHash` into typed policy inputs;
- a forwarded `.narinfo` must contain exactly one non-empty `StorePath`, `URL`,
  and `NarHash`. `StorePath` must be a single `/nix/store/<hash>-<name>` path
  whose hash part equals the requested `<hash>.narinfo`; `NarHash` must have
  the `algorithm:digest` shape; and `URL` must be `nar/<safe-filename>`.
  Absolute URLs, leading slashes, traversal, query/fragment-like bytes, extra
  path segments, duplicate/missing fields, mismatched store hashes, and
  malformed hash fields fail closed before the VM sees the metadata;
- the safe filename rule is shared with the VM HTTP `/v1/nix/cache/nar/<file>`
  classifier through `NixCacheNarFileName`, so the parser and route cannot
  drift on which NAR body paths the broker is willing to proxy;
- rejected upstream metadata becomes an audited `502` with a bounded static
  error label identifying the rejected field or mismatch class. `HEAD` remains
  a bounded upstream existence check;
- this slice was broker-side metadata admission, not broker-side signature or
  NAR body hash verification. A malicious or buggy upstream could no longer
  swap the `StorePath` hash while preserving a safe `URL`, but it could still
  return structurally valid metadata with a signed-but-untrusted key, a bad
  signature, or a NAR body that does not match `NarHash`; guest Nix still
  caught those cases. The signature slice below removes the untrusted/bad
  signature cases from the VM-visible surface.

First broker-side Nix `.narinfo` signature-verification slice implemented in
`src/nix_cache.rs` and `src/vm_http.rs`:

- `NixTrustedPublicKey` now parses Nix cache public keys as named 32-byte
  Ed25519 keys, not just syntactic `name:base64` strings. Invalid key lengths
  and duplicate key names fail during daemon/config construction before the VM
  can be started with ambiguous or unverifiable trust material;
- `.narinfo` admission now parses `NarSize`, `References`, and one-or-more
  `Sig` fields in addition to `StorePath`, `URL`, and `NarHash`. The signature
  fingerprint is the Nix binary-cache fingerprint
  `1;<store-path>;<nar-hash>;<nar-size>;<comma-separated full reference paths>`,
  pinned by a fixture generated with the local Nix CLI;
- successful `GET /v1/nix/cache/<hash>.narinfo` forwarding now requires at
  least one `Sig` whose key name matches a configured trusted public key and
  whose Ed25519 signature verifies that fingerprint. Missing signatures,
  malformed signatures, untrusted key names, trusted-key signature mismatch,
  malformed `NarSize`, and malformed `References` fail closed as audited
  `502`s with bounded static labels. `HEAD` remains an existence-only upstream
  check;
- Nix signatures do not cover the `URL` or `Compression` fields, so the
  earlier broker URL admission rule remains load-bearing and the body slice
  below admits on the tuple `(URL, Compression, NarHash, NarSize)`: a signed
  `.narinfo` can only direct the VM to a single broker-admitted
  `nar/<safe-filename>` route with one explicit compression/hash/size contract.

First broker-side Nix NAR body-verification slice implemented in
`src/nix_cache.rs` and `src/vm_http.rs`:

- signed `.narinfo` admission now also parses `Compression` and records an
  in-memory per-session admission for the exact `nar/<safe-filename>` together
  with the signed `NarHash`, `NarSize`, and compression mode. The admission map
  is intentionally per-session-lifetime and unbounded because entries are small
  and eviction would make a valid NAR follow-up request order-dependent.
  Admission fails closed if signed `NarSize` exceeds the configured
  `nix_cache_max_nar_bytes`, if `NarHash` is not a broker-verifiable SHA-256
  digest, or if a later signed `.narinfo` tries to reuse the same NAR filename
  with different compression/hash/size metadata. Two store paths may point to
  the same NAR filename only when that body metadata is identical;
- authenticated `GET`/`HEAD /v1/nix/cache/nar/<file>` now requires that prior
  signed admission before contacting the upstream cache. This closes the
  direct-NAR path where a VM could request a safe-looking NAR filename that no
  signed metadata had authorized;
- successful NAR `GET` is now buffered up to `nix_cache_max_nar_bytes`, decoded
  for supported compression modes (`xz` and `none`), checked against signed
  `NarSize`, and hashed with SHA-256 before the broker returns `200` to the VM.
  XZ decoding runs on Tokio's blocking pool with an explicit liblzma memlimit
  of `nix_cache_max_nar_bytes + 16 MiB`; peak broker memory is bounded by the
  compressed body, signed `NarSize`, and that decoder-state budget.
  Decompression failure, decoded-size mismatch, task failure, and hash mismatch
  all become audited `502`s. This trades streaming for correctness: the broker
  no longer sends success headers before it knows the body matches the signed
  metadata. The proxied `Content-Type` remains `application/x-nix-nar` for both
  raw and compressed NAR bytes, matching binary-cache practice; Nix uses the
  narinfo URL/compression metadata to interpret the body;
- NAR `HEAD` remains an existence/length check because it has no body to hash,
  but it still requires prior signed admission and a bounded upstream
  `Content-Length`. Guest Nix still performs its own signature/content checks;
  the broker-side check is a defense-in-depth boundary that prevents a buggy or
  malicious upstream from delivering bytes that contradict admitted metadata.

First workspace bootstrap slice implemented in `src/protocol.rs`,
`src/bin/writ.rs`, `src/bin/writ-vm.rs`, `src/vm_git.rs`, `src/vm_client.rs`,
`src/agent_vm_daemon.rs`, and `src/audit.rs`:

- `start_agent_vm` accepts an optional structured workspace bootstrap containing
  a GitHub `owner/name` repository, an optional destination, and a warmup mode
  (`none`, `sources`, or `devshell`). The first production CLI surface assumes
  branch `main`, no submodules, and no Git LFS. The default destination is
  `/workspace/<repo-name>`, and non-default destinations must be absolute;
- the daemon still uses the existing managed lifecycle state machine, but when
  a workspace is requested it wraps the guest command in a second in-guest gate.
  The lifecycle may release the container process, but that process waits for
  `/run/writ-agent-vm/broker-ready` before attempting any brokered clone. The
  daemon starts VM HTTP, touches that readiness file with `container exec`, and
  then polls `/run/writ-agent-vm/bootstrap-ok` or
  `/run/writ-agent-vm/bootstrap-failed`. `writ agent-vm start` does not return
  success until the workspace bootstrap reports success. Plain VM operations
  keep the shorter CLI timeout; only workspace starts use the longer timeout
  needed for substitute prefetching;
- each workspace start records a session-linked
  `agent_vm_workspace_bootstrap` audit row before lifecycle startup begins,
  including repository, resolved destination, branch, and warmup mode. The
  per-request Git and Nix cache audit rows remain the authority trail for the
  individual broker interactions;
- `writ-vm workspace init` requests only `refs/heads/main` through the existing
  host-produced Git bundle route, initialises a normal checkout, adds a
  credential-free `https://github.com/<owner>/<repo>.git` origin, creates local
  branch `main`, sets its upstream to `origin/main`, and verifies the worktree
  is clean after clone and warmup. The VM still never receives GitHub
  credentials, and the resulting `origin` URL is not usable authority without a
  later brokered fetch/push operation;
- `sources` warmup runs Nix flake metadata refresh with lockfile writes
  disabled, under a strictly substitute-only envelope (`builders =`,
  `max-jobs = 0`, `fallback = false`) — metadata builds nothing. `devshell`
  warmup additionally runs `nix develop .#default --command true` under the same
  envelope except `max-jobs = 1`. That deliberately widens the devshell envelope
  from "substitute only" to "substitute, plus build anything with no
  substituter": substitution is still always preferred and `fallback` stays
  `false` (a *failed* substitution is a hard error, not a from-source rebuild),
  but `allowSubstitutes = false` / `preferLocalBuild` setup-hook derivations
  (e.g. `cargoHelperFunctionsHook`) Nix refuses to substitute — and any local
  package or `runCommand` in the devshell — now build locally rather than
  failing the warm. `builders` stays empty so nothing is offloaded, and the
  no-egress sandbox still fails any build that must fetch sources/FODs. Both use
  the daemon-injected brokered Nix cache configuration, so startup fails visibly
  if the devshell closure is not realisable from configured substituters plus
  those bounded local builds. The flake feature is enabled only in the workspace
  bootstrap wrapper; non-workspace VM sessions keep the narrower Nix setup. The
  daemon still does not run `cargo build`, `nix build`, or other repository
  build commands as an explicit first-version bootstrap step. When the broker
  has a `nix_prewarm_cache_dir` configured, the daemon additionally injects
  `WRIT_NIX_PREWARM_URL` and the `devshell` warm becomes *strict*: both warm
  invocations replace their substituters with the broker's pre-warm-only
  `/v1/nix/prewarm` view (local archives only, miss ⇒ 404, never an upstream
  proxy), so the warm realises exactly the human-pre-warmed closure or fails
  fast — `sources` warms and the agent's later Nix usage stay on the proxied
  `/v1/nix/cache` view. The strict realisation step is `nix print-dev-env`
  rather than `nix develop --command true`: it realises the identical dev-env
  closure — the same one the pre-warm builder signed via `print-dev-env
  --profile` — without `nix develop`'s additional interactive-shell
  resolution (`nixpkgs#bashInteractive`), which lies outside that closure and
  is unservable by the strict substituter. The agent's own `nix develop`
  wrapper still pulls the shell through the proxied view at run time;
- Cargo dependency-source prefetching remains deliberately outside this first
  slice. A generic Rust workspace can require crates.io or Git dependency
  network access after the devshell starts, and the VM has no general outbound
  HTTP authority. A future slice should either broker Cargo source
  materialisation from `Cargo.lock` into an out-of-repo cache or require
  project-level vendoring/Nix source derivations before claiming full
  cargo-offline readiness.

First agent-runner UX slice implemented in `src/bin/writ.rs`:

- the host CLI now exposes `writ agent run --repo <owner/repo> --agent
  claude|codex --prompt <text> [--warm none|sources|devshell]`. This is a
  top-level product command, separate from the lower-level
  `writ agent-vm start -- <guest-command>` debugging surface;
- the command uses a product-level daemon protocol message,
  `StartAgentRun`. The prompt is protocol data on the host Unix socket, not
  part of the guest command. The daemon assigns an `AgentRunId`, records only
  prompt metadata in the audit log, stores the raw prompt in memory for the
  VM HTTP broker, and advertises a one-shot authenticated prompt route:

  ```text
  GET /v1/agent-runs/<run-id>/prompt
  ```

  The route returns the prompt at most once and is protected by the same VM
  bearer token and source-subnet check as the Git/Nix VM HTTP routes. The
  prompt is not copied into guest argv, guest environment, daemon lifecycle
  state, or SQLite audit rows. The current CLI still accepts `--prompt <text>`,
  so the local shell boundary can expose it before `writ` sends the request.
  `AgentPrompt` rejects values above 1 MiB before they can enter the daemon or
  VM prompt route;
- for Claude, the selected agent runtime is now a brokered Claude Code adapter.
  The guest command is `writ-vm agent run --run-id <run-id> --agent claude`.
  `writ-vm` fetches the one-shot prompt from the VM HTTP broker, invokes
  `claude --bare --print --model haiku --effort low --output-format text
  --no-session-persistence --tools ""` with that prompt on stdin,
  captures stdout/stderr into private per-run files, and uploads the run
  outcome metadata plus retained stream bytes back to the broker. With the
  default `--warm devshell`, the command is executed through the same
  bounded-build/no-lockfile envelope as workspace devshell warmup:

  ```text
  nix --option builders "" \
    --option max-jobs 1 \
    --option fallback false \
    develop --no-write-lock-file .#default \
    --command writ-vm agent run --run-id <run-id> --agent <agent>
  ```

  Workspace bootstrap has already proved that the default devshell can be
  entered; these flags keep the final adapter invocation in the same
  correctness envelope. With lesser warm modes the adapter runs directly after
  the requested bootstrap;
- the Claude Code process never receives the host Anthropic credential.
  `writ-vm` sets `ANTHROPIC_BASE_URL` to the broker URL and
  `ANTHROPIC_AUTH_TOKEN` to the VM bearer token, while removing common
  Anthropic credential environment variables from the child process. The
  broker handles `/v1/messages` and `/v1/messages/count_tokens`, audits each
  request/outcome, strips sandbox auth headers, forwards only Claude-safe
  metadata headers, injects the configured host-side Anthropic credential, and
  sends the configured Anthropic API version on the upstream request;
- `src/agent_run.rs` defines the prompt/log contract used by the real Claude
  adapter and by hidden fake-adapter tests: the prompt is written to the agent
  process on stdin, stdout and stderr are drained concurrently into private
  per-run `<log-root>/<run-id>/stdout.log` and `stderr.log` files, retained
  bytes are bounded, the full streams are hashed and counted, and the outcome
  exposes terminal status plus exit code. The stream files intentionally outlive
  the VM session because audit rows point at them, but the runtime still needs
  a retention, quota, and GC policy for `<log-root>`. Tests exercise fake
  agents that succeed, fail, write both streams, receive quoted prompt text on
  stdin, and emit large streams that must be drained without retaining
  unbounded log bodies;
- the audit schema has `agent_run` and `agent_run_outcome` rows. `agent_run`
  stores run/session identity, selected agent kind, prompt byte length, prompt
  SHA-256, and a redacted preview marker. `agent_run_outcome` stores status,
  exit code, stream paths, stream byte counts, stream hashes, and truncation
  flags. For truncated VM uploads, the broker audits the retained artifact
  count/hash instead of an unverifiable guest-reported full-stream count/hash.
  VM-side outcome upload is wired into the managed lifecycle for Claude; Codex
  remains a later adapter. The host CLI's optional `--model` value is still
  audit metadata in this slice: it does not propagate to the VM adapter. A
  later slice should replace the hardcoded Claude health-check model/effort
  with an explicit host-to-guest runtime selection contract before this command
  becomes a general-purpose Claude runner.

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
  then `container run` with the session network, tmpfs mounts for `/tmp`,
  `/run`, `/var/tmp`, and `/root`, and no host bind/publish flags;
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

Manual daemon proof harness added in `scripts/prove-agent-vm-daemon.sh`:

- builds `writ`, `writd`, `writ-agent-vm-pf-helper`, and by default the Nix
  guest OCI image containing `writ-vm`;
- starts a local fake GitHub API and configures `writd` to use it for
  installation-token minting. The harness also starts a local Basic-auth Git
  smart-HTTP origin containing a deterministic proof repo, and configures the
  daemon's Git clone base URL to that origin. The host Git binary is real, so
  the proof exercises the production `git clone --mirror` / `git bundle
  create` executor without depending on real GitHub availability or external
  network egress;
- starts `writd` with a temporary config, file secret store, audit DB, managed
  state directory, VM HTTP work root, and Unix socket;
- starts the VM through the public Unix-socket CLI:
  `writ agent-vm start -- <guest-command>`;
- asserts the released guest command is running, the guest still has no
  routable IPv6 posture, and the daemon-injected `WRIT_BROKER_URL` /
  `WRIT_BROKER_TOKEN` environment variables are present. It also checks the
  daemon-written Nix netrc/config paths exist inside the VM;
- from inside the VM, runs `writ-vm session`, `writ-vm git clone`, and
  `nix copy --from "$WRIT_NIX_CACHE_URL" <proof-store-path>` through the
  daemon-owned VM HTTP listener. The clone route must mint through the fake
  GitHub API, run real host Git against the local origin through askpass Basic
  auth without leaking the token into proof logs, return a valid deterministic
  Git bundle to the VM client, and let guest-local Git create a checkout from
  that bundle. The Nix route must authenticate with the daemon-written netrc
  and realise the signed proof store path through the brokered cache proxy;
- stops the session through `writ agent-vm stop <session-id>` and asserts the
  VM, network, PF anchor, observed guest-IPv4 PF states, and managed state
  record are gone.

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
