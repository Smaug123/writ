# Agent‑VM broker unreachable on Apple `container`: vmnet `accept()` bug — status & proposed plan

**Status:** root cause identified and reduced to a minimal pure‑C reproduction; no vendor fix yet; a debug‑build workaround is in use. This doc is written to be reviewable without prior context (e.g. by an external model). It marks claims as **[verified]** (observed on this machine), **[inferred]**, or **[proposed]**.

---

## 1. TL;DR

- `writ agent-vm start` fails: the guest can't talk to the host broker; the workspace clone dies with `error: VM broker request failed: error sending request for url (http://192.168.252.1:<port>/v1/git/clone)`. **[verified]**
- Root cause is **not** in writ, tokio/mio, or the network config. It's macOS **vmnet**: `accept()` on the host returns a *not‑connected* socket (`getpeername`→`EINVAL`, `recv`→`ENOTCONN`) for connections originating from a `container` guest — while loopback connections to the same listener are fine. **[verified, incl. a 30‑line C repro]**
- It only manifests in **optimized/release** builds of the broker (timing‑sensitive); a **debug** build of `writd` works and is the current stopgap. **[verified]**
- Reproduces on `container` **0.11.0 and 1.0.0**; not fixable by downgrading tokio/mio (tried mio 0.8→1.2). `--publish-socket` is the wrong direction; no vsock is exposed by the CLI. **[verified]**
- **Proposed fix (Path A):** run the broker in its own dedicated **trusted Linux VM** so the agent→broker `accept()` happens in Linux (which is healthy), not on the macOS host. Keeps Apple `container` and the trust model. **[proposed; key networking primitives verified]**

---

## 2. Symptom

`writ agent-vm start --agent claude --repo <owner/repo> --workspace <path> -- sleep infinity` fails during workspace bootstrap:

```
error: agent VM start ... failed: agent VM workspace bootstrap failed: writ-vm workspace init failed with exit 1
stderr:
error: VM broker request failed: error sending request for url (http://192.168.252.1:<port>/v1/git/clone)
```

The error is reqwest's transport‑level failure (no HTTP response received), not an HTTP status.

## 3. Environment

- macOS **26.5.1** (build 25F80), `xnu-12377.121.6`, Apple Silicon (arm64).
- Apple `container` **0.11.0** (commit `d9b8a8d`) — later **1.0.0** (commit `ee848e3`); bug present on both.
- Broker: `writd` (Rust, tokio + hyper). Guest network: per‑session `--internal` vmnet, subnet `192.168.252.0/24`, host gateway `.1`, guest `.2`. Egress denied via macOS PF; guest reaches the broker only at the gateway:broker‑port.

## 4. Root cause and evidence

The broker binds `0.0.0.0:<port>` on the host. The guest connects to `192.168.252.1:<port>`. The TCP handshake completes, the guest sends its HTTP request, the host **kernel ACKs the bytes**, but the broker application reads **EOF/ENOTCONN** and closes — so the request never reaches the HTTP handler.

### 4.1 Evidence chain **[verified]**

1. **It's the broker binary, not network/state.** Same source commit, binaries verified before each run, sessions stopped between runs:

   | `writd` build | result |
   |---|---|
   | `cargo build` (debug) | start succeeds (many/many) |
   | `cargo build --release` | start fails (all) |
   | nix `./result/bin/writd` (release) | start fails (all) |

   Runs were interleaved on the same machine within minutes (release‑fail, then debug‑pass), so it isn't accumulated state.

2. **Packet capture (`tcpdump -i vmenet0`) of a failing clone:** handshake completes; guest sends a 278‑byte request; host kernel `ACK`s it (`ack 279`); host then sends `FIN` with `seq 1` (zero response bytes) and an `RST` (unread bytes left in the socket buffer). `netstat -s`: 0 bad checksums, 0 retransmits. Concurrent **loopback** probes to the same broker are served (HTTP 403) fine.

3. **Broker‑side instrumentation** (placed *after* `serve_connection`, so it can't perturb the read path): for the guest peer, the request handler (`service_fn`) is invoked **0 times** and `serve_connection` returns `Ok` — i.e. hyper saw EOF before any request.

4. **Ground truth via raw syscalls, bypassing tokio.** A `libc::recv(MSG_PEEK|MSG_DONTWAIT)` on the accepted fd returns **`ENOTCONN` (errno 57)** continuously for 300 ms; `getpeername` returns **`EINVAL`**. Probed **synchronously the instant `accept()` returns** (before any task scheduling): the fd is *already* not‑connected, while `accept()` simultaneously returned a valid peer address (`192.168.252.2:…`). So a not‑connected socket comes straight out of `accept()`.

5. **Pure‑C minimal repro** (no Rust/tokio/writ/PF, stock `container` default network + stock `alpine`): a blocking‑`accept()` C server on the host; an `alpine` container client over vmnet. In one server process: the loopback control connection is healthy (`getpeername=OK recv=DATA`), and every container/vmnet connection is `getpeername=EINVAL, recv=ENOTCONN`. Deterministic (100% of vmnet connections). See `../../vmnet-accept-repro/` (`server.c`, `run.sh`, `README.md`).

### 4.2 Ruled out **[verified]**

- **writ logic / broker correctness** — loopback is served fine concurrently; the C repro has no writ code.
- **Network/PF/MTU** — request bytes reach the host kernel (ACKed); guest MTU 1280 vs host 1500 was tested and irrelevant; PF passes the connection (state table shows it).
- **tokio/mio version** — bug reproduces across every reachable mio: 1.2.0 (tokio 1.52/1.47), 1.1.0 & 1.0.4 (tokio 1.44), and 0.8.11 (tokio 1.38, built by temporarily swapping `Command::process_group` for `pre_exec`+`setpgid`). All fail.
- **`container` version** — fails on both 0.11.0 and 1.0.0.
- **Hand‑run client misconfig** (a red herring encountered along the way): a `claude` launched by hand in the guest lacks `ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN` (set only by the `writ-vm agent run` wrapper), so it tries `api.anthropic.com` directly and the no‑egress firewall refuses it. Not the same bug.

### 4.3 Mechanism **[inferred]**

The release build calls `accept()` very soon after the connection arrives; under that timing macOS vmnet hands back a socket whose connection state is not yet wired up, and it never recovers (sticky `ENOTCONN`). The slower debug build accepts late enough that the socket is fully wired. A deliberate post‑accept delay does **not** help (the socket is born broken); a pre‑accept delay test was inconclusive (nonblocking `accept()` never even accepts these connections; blocking accepts them broken). Net: no reliable small timing fix. **[verified that no small fix worked]**

## 5. Separate, secondary instability **[verified]**

On a long‑running session (~1 h after a successful debug‑build start), the session's **host‑side vmnet interface vanished**: `192.168.252.1` gone from the host, `vmenet0` inactive, no `bridge100` — although the container still showed "running", the broker still listened, and the `container`‑level network + vmnet plugin process were still registered. Guest then gets `No route to host`. Not sleep (caffeinate held the system awake; 8‑day uptime); the box was under high load. This is a *different* vmnet fragility from the `accept()` bug and would affect any design that rides the vmnet bridge.

## 6. Current workaround **[verified]**

Run a **debug** build of the broker: `cargo build --bin writd && ./target/debug/writd`. A real `agent-vm start` then completes end‑to‑end (clone + devShell warm; ~900 broker requests served). Caveats: relies on build timing (could regress under load or on other hardware), and the §5 interface‑vanishing fragility still applies to long sessions.

## 7. Options considered

| Option | Verdict |
|---|---|
| Report to Apple; wait for vmnet fix | Right thing to do; slow. Repro is ready. **[recommended in parallel]** |
| Downgrade tokio/mio | **Dead end** — all mio versions fail. **[verified]** |
| Upgrade `container` 0.11.0 → 1.0.0 | **No change** — still fails. **[verified]** |
| `--publish-socket` as broker transport | **Wrong direction** — it's container→host (host reaches a guest service); broker needs guest→host. **[verified]** |
| Bind‑mount a host unix socket into the guest | **Fails** — `connect()` → "Not supported" (virtiofs can't carry socket connects across the VM boundary). **[verified]** |
| vsock | The clean transport (VZ supports it, bidirectional), but **not exposed by the `container` CLI**. **[verified]** |
| Lima / colima | Lima default `vz` backend is also vmnet‑backed → very likely same bug; only Lima+QEMU+slirp avoids vmnet but is slow on ARM and breaks the no‑egress model. Also: writ's backend is **not pluggable** (no runtime abstraction; lifecycle hardcodes the `container` CLI + vmnet gateway model + PF), so swapping is a rewrite. **[inferred + verified non‑pluggability]** |

## 8. Verified networking primitives (for the plan) **[verified]**

- **guest↔guest TCP works** on both NAT and `--internal` networks (an alpine client container reached an alpine server container and got data back, rc=0). The `accept()` happens in the Linux guest, not the macOS host — and is healthy.
- **`--internal` network** = no internet egress (confirmed) and still allows guest↔guest.
- **Multi‑network attach** works: a container with `--network internal --network default` gets both interfaces. Caveat: the default route landed on the no‑egress interface, so a dual‑homed VM must set its default route via the NAT interface.
- **`--publish-socket`** carries host→guest service traffic (the working direction), usable for a host‑side review UI.

## 9. Proposed plan — Path A: broker in a dedicated trusted VM **[proposed]**

**Principle:** move the broker off the macOS host into a Linux VM, so the agent→broker `accept()` happens in Linux (verified healthy), sidestepping the macOS vmnet bug at the root. Keep Apple `container`, the no‑egress agent, and the broker‑as‑trust‑boundary model.

### 9.0 Reversibility — this must be a swappable placement, not a one‑way migration

The vmnet bug is a vendor defect Apple may fix. So Path A is built **behind a selector**, not as a replacement: a config field **`agent_vm.broker_placement`** with two values, both first‑class:

- **`host`** *(default)* — today's behavior exactly: the broker is spun up in‑process on the host (`prepare_vm_http_session(...).spawn()`), guest reaches it at `gateway:port`. This is the **revert target**: when Apple fixes vmnet, set `broker_placement = host` and Path A's machinery is bypassed entirely (and can later be deleted).
- **`vm`** — Path A: the broker runs in a dedicated VM; guest reaches it guest↔guest.

Implementation discipline so the swap stays clean:
- The selector is **data, not a plugin** — a `BrokerPlacement` enum the daemon matches on at session start (in keeping with "data descriptions over behavioral abstractions"; no trait‑object indirection for two known variants). The two arms produce a uniform result: `{ broker_url, teardown handle }`; the rest of `start_session` is shared.
- The `host` arm is the existing code path, unchanged, and remains the default — so every slice below is additive and the working host path is never regressed.
- This is a *justified* abstraction (two real implementations the operator selects), not speculative generality: the moment Apple fixes vmnet, the `vm` arm becomes dead code to delete, and the seam collapses back to the `host` path.

### 9.1 Topology (per session, `broker_placement = vm`)

```
 macOS host  (trust root: keychain)
 └─ writd-host (launcher): reads secrets, drives `container`, owns durable audit.db + push-staging
      │ creates 2 networks, launches 2 VMs, injects secrets
      ▼
  ┌──────────────────────────────┐         ┌──────────────────────────────┐
  │ BROKER VM (trusted)          │         │ AGENT VM (untrusted)         │
  │ `writd --broker`             │         │ writ-vm + claude/codex       │
  │ eth0: writ-net-<id> (internal)│◄────────│ eth0: writ-net-<id> (internal)│
  │ eth1: default (NAT egress) ──┼─► GitHub │ (no 2nd iface ⇒ no egress)   │
  │ secrets injected (no keychain)│ Anthropic│ WRIT_BROKER_URL=<brokerIP>:p │
  └──────────────────────────────┘   nix   └──────────────────────────────┘
        ▲ agent↔broker over the internal bridge: Linux accept() — healthy
```

- **Internal net** (`container network create --internal writ-net-<id> --subnet …`): carries agent↔broker; no NAT ⇒ the agent has **no egress by topology** (stronger than today's PF‑only control).
- **Agent VM**: internal net only; its only reachable peer is the broker VM. `WRIT_BROKER_URL` = broker VM internal IP:port (instead of the host gateway). The boot egress‑gate's positive control becomes "reach broker VM"; negative ("no internet") is now also guaranteed by topology.
- **Broker VM**: dual‑homed (internal + default/NAT); its image sets `default route via eth1` so outbound (GitHub/Anthropic/nix upstream) works while the internal subnet stays on eth0.

### 9.2 What code moves where

- **Broker VM = a Linux build of writd's existing broker**: the `vm_http` server (git clone/push, nix cache + prewarm, Claude/OpenAI proxies, `/v1/session`, agent‑runs) + GitHub minting. This is a *subset* of today's writd; it drops the macOS‑only pieces — no keychain (secrets injected), no PF (egress via its NAT iface; agent isolation via topology), no `container` CLI (the host launcher drives that).
- **Host launcher = slimmed writd** keeping the macOS‑only responsibilities: keychain access + secret injection; `container network/run/exec/stop/delete` (today's `agent_vm_lifecycle`, extended from one VM to two); durable **audit.db + push‑staging on the host** and the human‑review/promote UI.
- **Agent VM = essentially unchanged.** `guest_command.rs` already parses host:port out of `WRIT_BROKER_URL`; only the value changes.

### 9.3 Secrets injection
Host launcher reads keychain (GitHub app keys, Anthropic key, signing key) → writes an ephemeral `0600` file → mounts it into the broker VM via virtiofs (files traverse virtiofs; sockets don't). Broker VM loads via a file secret‑store (config already has a `File` variant). Removed on teardown.

### 9.4 Durable host state + human review
Broker VM bind‑mounts host directories for `audit.db` and the git‑push staging store, so audit + review stay durable on the host, outside both VMs. Approvals flow host→broker via a polled mounted dir or `--publish-socket` (host→guest works).

### 9.5 Trust model (preserved)
Root of trust = host launcher (keychain) + dedicated broker VM. The broker VM is trusted by construction (controlled image, never runs agent code), exactly as the host broker was. The agent VM stays untrusted and only ever sees the brokered API + short‑lived minted tokens. Audit/review stay durable on the host.

### 9.6 Incremental build order (seam‑first; every slice additive, `host` stays default)
1. **Seam:** add `BrokerPlacement {Host, Vm}` config (default `Host`) + the session‑start match with only the `Host` arm implemented (= current behavior, refactored behind the seam). No behavior change; existing tests green. *This delivers the reversibility property up front.*
2. **Standalone broker entrypoint** (`writd broker`): assemble the existing vm_http serving stack from config + a **file** secret store + a session spec, bind TCP, serve until shutdown. CI‑testable with the existing fakes (no VM/container needed). Needed by the `Vm` arm.
3. **Broker VM image** (Linux `writd broker`) + secret injection (host writes an ephemeral 0600 file, mounted via virtiofs; broker loads `FileSecretStore`).
4. **`Vm` arm of the seam:** create the internal net + launch the dual‑homed broker VM + attach the agent VM to the internal net + set `broker_url` to the broker‑VM IP; wire teardown of both VMs + net.
5. Durable audit/staging via host‑mounted volumes; review UI on the host.
6. Update the egress gate's positive‑control target (broker‑VM IP).
7. **Acceptance test: with `broker_placement = vm`, a `release` build completes a real `agent-vm start` + clone + warm + a `claude` call; with `broker_placement = host`, behavior is byte‑for‑byte today's.**

### 9.7 Caveats / residual risks
- The agent↔broker hop still rides the vmnet **bridge**, so the §5 "interface vanished" instability could still hit long sessions. Path A fixes the `accept()` bug, not general vmnet flakiness — design for restart / keep sessions short.
- New surface: broker‑VM dual‑homing (egress routing), secrets living in a VM, two‑VM lifecycle. Bounded.
- **Per‑session broker VM** (clean isolation, +1 VM boot/session) vs. **one long‑lived broker** multi‑homed onto per‑session nets (less churn, more wiring). Start per‑session; optimize later.

### 9.8 Alternative — Design 2 (single NAT net + PF)
Both VMs on one NAT network; host PF pins the agent to "broker‑VM‑IP only." Reuses writ's existing PF code (retarget the allow rule) and keeps secrets on the host — but the agent's isolation then rests on PF correctness rather than topology, and the agent sits on a network that *has* a NAT route (only PF stops egress). Lower‑effort, slightly weaker isolation.

## 10. Open questions for the reviewer
1. Is moving the trust anchor from a host process to a dedicated VM acceptable, or is keeping secrets on the host (Design 2, or a host‑initiated reverse tunnel) strongly preferred?
2. Per‑session broker VM vs. one long‑lived broker VM — isolation vs. startup latency / churn.
3. Does Path A's reliance on the vmnet bridge (still subject to §5) undermine it enough to justify the heavier QEMU/user‑mode or direct‑Virtualization.framework(vsock) routes instead?
4. Is there a smaller transport fix we've missed (the broker channel is the only thing that must cross the guest↔host boundary)?

## 11. Reproduction & artifacts
- Minimal C repro: `../../vmnet-accept-repro/` (run `./run.sh`; needs `container system start` + `alpine:latest`).
- Workaround: debug `writd` (`cargo build --bin writd && ./target/debug/writd`).
