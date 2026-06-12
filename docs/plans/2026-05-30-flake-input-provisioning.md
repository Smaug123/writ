# Slice — flake-input provisioning for no-egress agent VMs

Drafted 2026-05-30. Closes the gap that makes `writ agent-vm start
--repo … --warm devshell` (and `--warm sources`) fail on any repo with
flake inputs. The host-side clone now works, but the guest's warm step
runs `nix flake metadata` / `nix develop` (`src/vm_client.rs:1327`
`warm_workspace`, args from `src/vm_git.rs:28` `nix_develop_command_args`),
which fetches the repo's flake *inputs* (`github:numtide/flake-utils/…`,
`github:NixOS/nixpkgs/…`) directly from github. The guest has no egress
except the broker, so the fetch dies with `Could not resolve host:
github.com`.

The broker's nix-cache endpoint (`src/vm_http/nix_cache.rs`) proxies only
the *substituter* — store paths addressed by hash — which is not a flake
input fetcher. So today the no-egress model simply cannot evaluate a
flake. This slice makes the broker provision a repo's locked inputs the
same way it already provisions the repo itself for `git clone`: the host
(which has egress) fetches them, and the guest consumes them through the
substituter it already trusts. The guest gains no new egress, preserving
the VM trust model (guest is hostile after an agent runs; broker is the
boundary).

## Motivation

`--warm devshell` is the default, and it is how an interactive agent gets
a working toolchain inside the VM. Right now it is unusable for any
real-world repo. The failure is fundamental to the no-egress design, not
a config error: flake-input fetching is a separate code path from
substitution, and there is no brokered route for it.

## What we proved first (Stage 0 — landed)

`scripts/prove-flake-offline.sh` answers the make-or-break question
before any production code, on the host, without a VM and without root:

> When a flake input's github origin is *firewalled* (not merely
> `--offline`), does Nix fall back to substituting the locked input from a
> cache, or hard-fail on the blocked origin?

It archives a flake's inputs into a `file://` cache (the broker-side
action), then runs a fresh, isolated Nix consumer under `sandbox-exec`
with all IP egress denied (the guest firewall, reproduced), pointed at
only that cache. A negative control (empty cache → fails reaching github,
proving the isolation is real) and a positive case (archive cache →
**succeeds**) together prove: **Nix substitutes the locked input from the
cache when the origin is blocked.** The design is sound.

Findings that shaped the rest of this plan (see the
`project_flake_input_provisioning` memory):

- `--offline` does **not** block flake-input origin fetches; only real
  network isolation does. The guest's firewall is what forces substitution.
- `nix flake metadata` and `nix flake archive` are **vacuous** consumer
  ops — they complete from lock/git-cache data without realising input
  *source* paths. Only an op that reads input content (a real `nix
  develop` eval) forces store-path realisation. The harness uses a
  `builtins.readFile (input + "/…")` probe for this reason.
- Archived input paths are content-addressed (`CA: fixed:r:sha256:…`),
  hence **self-certifying**. No broker Nix signing key and no guest
  `trusted-public-keys` change are needed; the local cache is admitted by
  CA hash-verification.
- `nix flake archive` is platform-independent: the aarch64-darwin host
  produces exactly the input *source* paths the aarch64-linux guest needs
  to evaluate. The guest system's *build outputs* still substitute from
  cache.nixos.org via the existing proxy, unchanged.

## Design

At workspace bootstrap, after the host-side clone and **before** the
guest's warm step:

1. **Broker provisions** the repo's committed, locked flake inputs on the
   host: `nix flake archive --to file://<broker-cache> --no-update-lock-file
   <repo>`. `--no-update-lock-file` (not merely `--no-write-lock-file`) is
   load-bearing: the latter would still let Nix resolve and archive an
   *updated* lock graph in memory when `flake.nix` and `flake.lock`
   disagree, provisioning inputs that are not in the committed, reviewed
   lock — so a stale lock must fail closed. Pure-eval, no IFD, sandboxed,
   bounded (timeout / total bytes / input count), audited. Fetches the
   whole transitive input graph; integrity is self-certifying
   (content-addressed).
2. **Broker serves** the local cache through the existing `/v1/nix/cache`
   endpoint, **local-first** (local archive hit → serve, admitting CA
   narinfos by hash-verification; miss → proxy upstream cache.nixos.org as
   today).
3. **Guest realises** the input paths before warm (`nix copy --from
   <broker-cache> <paths>`), so they are present and valid when `nix
   develop` evaluates the locked flake; the fetcher finds them and never
   contacts github. Build outputs substitute from cache.nixos.org as
   normal.

### Design space (alternatives rejected)

- **A github-tarball proxy endpoint.** Nix has no clean hook to redirect
  `github:` fetches to a custom host, and an HTTP CONNECT proxy would
  re-open general egress — a trust-model regression. Rejected.
- **Bake nixpkgs/flake-utils into the guest image.** Doesn't generalise to
  arbitrary pins; speculative. Rejected.
- **Host `nix print-dev-env` injection.** Sidesteps the input fetch but
  loses in-guest `nix` for the agent (it can no longer `nix develop` /
  rebuild). Rejected as the primary path; remains a possible future
  lightweight mode.

## Decisions (made with the user, 2026-05-30)

- **Where the host fetch runs:** in the broker process, bounded /
  pure-eval / sandboxed / audited — consistent with how the host already
  runs `git clone`. (A disposable egress-VM provisioner was considered for
  stronger isolation but is more machinery; deferred.)
- **Input scope (v1):** public inputs only (github/https needing no
  credentials). Private or auth-requiring inputs fail with a clear
  message; brokered private-input fetch via the GitHub App is a follow-up.
- **Lock requirement (v1):** require a committed `flake.lock`. Missing-lock
  → clear error; host-side locking (which adds host-side evaluation) is a
  follow-up.

## What ships

- A host provisioning primitive: typed, bounded, audited `nix flake
  archive` into a broker-local binary cache.
- Local-first serving in `src/vm_http/nix_cache.rs`, admitting the local
  archive's CA paths by hash-verification.
- Bootstrap wiring: the guest provisions then realises inputs before
  `warm_workspace` (`src/vm_client.rs:518` `init_workspace_from_broker`).
- A `flake_provision` audit table.
- An end-to-end VM proof, `scripts/prove-agent-vm-devshell-warm.sh`.
- Config: host `nix_program`, provisioning cache dir, bounds; docs.

## What stays in scope

- Reusing the existing substituter transport and NAR-verification
  machinery; one substituter URL for the guest (no second endpoint).
- Bounds enforced fail-closed (timeout, total bytes, input count), logged
  when a limit truncates coverage.
- Cache GC / size cap for the broker-local archive.

## What stays out of scope

- Private / auth-requiring flake inputs (needs App-token injection +
  policy on which repos an input may point at).
- Non-`flake.lock` repos (host-side locking).
- Arbitrary later in-guest flake mutations needing brand-new inputs — the
  no-egress envelope cannot cover unbounded later fetches without becoming
  a general proxy. Stated honestly in docs, not silently.
- A broker Nix signing key / guest `trusted-public-keys` change — dropped;
  CA admission makes it unnecessary.

## Plan of work

### FK0 — Offline-substitution proof (landed)

`scripts/prove-flake-offline.sh`. Host-only, root-free, `shellcheck`-clean.
The correctness oracle for the whole design: negative control (egress
blocked + empty cache → github-unreachable failure) and positive (egress
blocked + archive cache → success). Supports `--flake DIR --system` to
prove a real repo's inputs.

### FK1 — Host provisioning primitive

Typed, bounded, audited `nix flake archive` into the broker cache. A
lock-driven functional core; `nix` shelled at the edge (mirrors how the
code shells to `git`). Oracle: integration test against a local fixture
flake (no network) asserting the expected paths land; property tests on
the bounds (oversized / over-count locks rejected). Adds the
`flake_provision` table and append-only invariants.

### FK2 — Serve the local cache local-first

Extend `route_nix_cache_request` (`src/vm_http/nix_cache.rs`) to check the
local archive before proxying upstream, admitting its CA narinfos by
content-hash verification. Back-compatible: an empty local cache leaves
behaviour identical. Oracle: a path in the local cache is served + verified
and audited as local; a miss proxies upstream; existing nix-cache tests
still pass.

### FK3 — Wire provisioning into bootstrap

Trigger shape decided (2026-06-03): a **separate `/v1/nix/flake/provision`
endpoint** the guest calls after clone and before `warm_workspace`
(`src/vm_client.rs:518`), backed by a **host-side retained bare-`mirror.git`
cache keyed by `(repo, rev)`** so concurrent VMs provisioning the same flake
share one fetch. The broker re-derives the checkout from its own retained
mirror (`git archive <rev>` → temp `flake_dir` → `provision_flake_inputs`);
the guest never POSTs flake content.

Decomposed into reviewable stages:

- **FK3a — serve a shared CA cache dir.** Add `flake_input_cache_dir` to
  `AgentVmHttpConfig` (default `<work_root>/flake-input-cache`) and wire it
  into the runtime nix-cache via `with_local_cache_dir`. Empty dir ⇒ no
  behaviour change. *(landed in this PR)*
- **FK3b — the `(repo, rev)`-keyed mirror store** (`src/vm_git_mirror_cache.rs`).
  A retain-only cache: atomic staged publish, dedup of concurrent clones of the
  same key, and a stale-staging sweep. It deliberately does **not** evict —
  deleting an entry safely needs to know which mirrors are pinned by an
  in-flight provision, the same coordination the eviction-safe read needs, so
  bounding races in-flight inserts/readers if done here. Bounded GC moves to
  FK4 and the pinned read to FK3c. *(primitive landed in #193; the eviction it
  initially carried was dropped as premature.)*
- **FK3c — wire retention + the provision endpoint.** Replace the clone
  handler's immediate `remove_dir_all` (`src/vm_http/git_clone.rs`) by resolving
  the rev and inserting the mirror into the store; add `/v1/nix/flake/provision`
  (protocol + route + session-capability auth) which leases a `flake_dir` from
  the retained mirror (pinned against eviction) and calls
  `provision_flake_inputs` into the shared cache. Introduces the host
  `nix_program` path + bounds config.
- **FK3d — guest bootstrap call.** In `init_workspace_from_broker`, between
  checkout and warm, POST the provision request; degrade on refuse.
- **FK3e — end-to-end oracle.** `scripts/prove-agent-vm-devshell-warm.sh`
  boots a no-egress VM, clones a fixture repo with a real github input, warms
  `devshell`, asserts success, asserts no guest github egress, checks the
  `flake_provision` audit rows.

### FK4 — Docs, config, GC

Document the behaviour and knobs (bounds, enable flag, cache GC), update
getting-started / configuration. State the guarantee precisely (below).
Includes the bounded GC for the `(repo, rev)` mirror store deferred from FK3b:
an eviction pass that skips mirrors pinned by an in-flight provision (the pin
coordination FK3c introduces), so it cannot delete an entry out from under a
running `git`/`nix`.

## Guarantee / envelope

At bootstrap, every input in the committed lock becomes available to the
guest, so `nix develop` evaluates and enters the shell **provided the
devShell's output closure is substitutable from cache.nixos.org for the
guest system**. A later in-guest flake edit that needs a brand-new input
will not substitute — that is the no-egress envelope, documented rather
than papered over.

## Risks and tradeoffs

- **Host-side fetch of repo-pinned URLs.** `nix flake archive` fetches
  whatever the committed lock pins (github, https, arbitrary tarball/git).
  This runs at bootstrap, before any agent runs, against the user's own
  chosen repo's committed lock, and fetches content-addressed inputs
  (integrity guaranteed). The new host surface is egress to URLs named in
  the lock; bounded (timeout / bytes / count), audited, run pure-eval /
  no-IFD / sandboxed. A disposable egress-VM provisioner remains the
  stronger-isolation option if this surface proves uncomfortable.
- **Output closure must be in cache.nixos.org.** If a repo's devShell
  pulls something not in the binary cache for the guest system, warm still
  fails (this slice does not change that). Pre-existing constraint of the
  `max-jobs=0 / fallback=false` warm; called out in docs. *Lifted by the
  follow-on `2026-06-07-prewarmed-devshell-cache` slice (PW3): with
  `nix_prewarm_cache_dir` configured, the devShell warm is served strictly
  from the operator's signed pre-warm archive instead of cache.nixos.org.*
- **Cache growth.** The broker-local archive accumulates across sessions;
  FK4 adds a size cap / GC. Content-addressed, so sharing across sessions
  is safe and deduplicates.

## Open questions

- Per-session vs. shared content-addressed broker archive. **Resolved:**
  shared CA store with per-session `flake_provision` audit rows (the user
  expects many concurrent VMs provisioning the same flake, so cross-session
  dedup matters). Revisit only if audit isolation later demands per-session.
- Whether FK3 folds provisioning into the clone response or uses a separate
  `/v1/nix/flake/provision` call. **Resolved (2026-06-03):** separate
  endpoint, with a `(repo, rev)`-keyed retained host mirror cache so clone +
  provision don't double-fetch and concurrent VMs share one fetch.
