# Refactor backlog — from a flat 40-module crate to domain-shaped boundaries

Drafted 2026-07-17. Companion to the current-state map in
[`../design/architecture.md`](../design/architecture.md), which shipped in the
same change. This plan is the *sequenced structural remediation* of the debt
that map names in §2–§3. **It is a backlog, not a commitment**: each slice is
independently reviewable and independently shippable, ordered so the cheap,
high-leverage moves land first. No code moves in the doc PR; this file exists so
the work is scoped and ready to pick up.

## Motivation

A reviewer summarised the problem as *"the repo records its history, not its
architecture,"* with three structural symptoms:

1. **A flat ~40-module root crate**, every module `#[cfg(feature = "host")]`,
   with names encoding accretion order rather than domain
   (`git_push_replay_object_source` vs `git_push_replay_object_parse` vs
   `git_push_replay_walker`; two modules both named `nix_cache`).
2. **God-files** at 2.5–3.7k lines (`config.rs` 3673, `vm_client.rs` 3294,
   `agent_vm_lifecycle.rs` 3215, `server.rs` 3188, `nix_cache.rs` 2749,
   `broker_vm.rs` 2636, `agent_vm_daemon.rs` 2602).
3. **A feature flag doing a crate's job**: `host` enables `vm-client`
   (`Cargo.toml:16`), so the broker carries the guest HTTP client and `reqwest`.

The design-doc half of that critique (append-only journals) is addressed by
`architecture.md`. This plan addresses the code shape.

## Framing: what each boundary costs, and which we want

Per the project's boundary-cost framework (`gospel.md`, "when should I introduce
a boundary?"):

- **Module boundaries are cheap.** The compiler checks the interface; no runtime
  cost; refactoring across them is mechanical. Split whenever local reasoning
  demands it — i.e. when a file exceeds what you can hold in your head. The
  god-files qualify on their own.
- **Crate boundaries cost a little more** (a named unit, a manifest, a published
  interface) but buy two things worth having here: **compile-time isolation**
  (editing the VM sandbox shouldn't recompile the audit log — the exact reason
  `writ-core` was already extracted) and, in one case, a **machine-enforced
  invariant** the codebase currently upholds only by discipline.

So this is *not* "split everything into crates." The strongest single move is
the one that turns a discipline-enforced rule into a compile error (Slice 4);
the rest are justified by compile isolation and local reasoning, and are ranked
accordingly. Two principles from `gospel.md` govern the sequence:

- **Complete migrations.** Each slice fully lands its move — no half-migrated
  state where two module layouts coexist. Keep root-crate re-exports
  (`writ::audit`, `writ::vm_git`, …) stable across a move so downstream
  (`bailiff`, tests) doesn't churn; delete the old path in the *same* slice.
- **Delete aggressively.** Several vestigial paths and stale comments surfaced
  while mapping the code; removing them (Slice 3) is pure orthogonality win and
  costs nothing.

Large mechanical moves are exactly what the compiler is good at carrying; don't
be timid about them, but keep each one in its own PR.

## Target crate graph

```
bailiff ─▶ writ (shell: daemon + binaries)
                 │
     ┌───────────┼────────────┬───────────────┐
     ▼           ▼            ▼                ▼
 writ-vm-host  writ-git    writ-audit    writ-vm-client
 (sandbox)    (pipeline)   (SQLite log)  (guest surface)
     └───────────┴────────────┴───────────────┘
                 ▼
            writ-vm-git ─▶ writ-core
```

`writ` stays the imperative shell that wires effects to the daemon. The
subsystem names in `architecture.md` §5 are the intended crate seams; the ones
below are the subset worth promoting from module to crate.

---

## Slices

### Slice 0 — the map (shipped)

`architecture.md`; historical banners on the design journals; `AGENTS.md`,
`CLAUDE.md`, and `src/lib.rs` repointed at the map. This backlog.

### Slice 1 — sever the `host` → `vm-client` feature entanglement

**Highest leverage-to-cost in the list.** Today host code uses exactly two
things that live behind `vm-client`: the env-var-name constants
`VM_BROKER_URL_ENV`/`VM_BROKER_TOKEN_ENV` (re-exported at
`agent_vm_daemon.rs:52`), and the `pub use writ_vm_git as vm_git` re-export
gated on `vm-client` at `lib.rs:101` (host uses `crate::vm_git` in ~20 modules).
For those two, `host` pulls in the whole 3.3k-line `vm_client.rs` guest client
and `reqwest`-for-guest that it never runs.

Steps:
- Move the two env-var-name constants to `writ-vm-git` (they are a shared
  host↔guest contract, not guest-client internals).
- Add a `#[cfg(feature = "host")] pub use writ_vm_git as vm_git;` so host gets
  the wire types without `vm-client`.
- Add `dep:reqwest` directly to the `host` feature (host needs it for the GitHub
  minter and the VM proxies — today it only gets it transitively via
  `vm-client`).
- Remove `"vm-client"` from the `host` feature list (`Cargo.toml:16`).

**Done when** a `--no-default-features --features host` build does not compile
`vm_client.rs`, `--all-features --all-targets` clippy/test/doc all pass, and the
`writ-vm` (`--no-default-features --features vm-client`) build is unchanged.
Mechanical; no behaviour change.

### Slice 2 — disambiguate the two `nix_cache` modules

Rename by layer (they are domain-lib vs HTTP-shell, see `architecture.md` §5.6):
- `src/nix_cache.rs` (types + Ed25519 verification + NAR hashing + admission
  parsers, zero HTTP) → `src/nix_narinfo.rs` (or `nix_cache_admission`).
- `src/vm_http/nix_cache.rs` (the `VmHttpNixCacheService`) keeps its role; its
  module path already disambiguates once the domain module is renamed.

Pure rename + import fixups, fully compiler-checked. Do the analogous
disambiguation for `flake_provision.rs` (runs `nix flake archive`) vs
`flake_provision_from_mirror.rs` (mirror lookup + orchestration) vs
`vm_http/flake_provision.rs` (HTTP shell) if it reads cleanly in the same pass.

### Slice 3 — delete vestigial paths and correct stale in-code claims

"Delete aggressively." Each is independently verifiable:
- Remove the vestigial staging-repo bring-up in `git_push_replay.rs`
  (`GitPushReplayPlan` / `ReplayTarget` / `ingest_bundle` / `prepare_staging_repo`)
  — constructed only by that module's own tests; the live approve path uses
  `git_push_approve.rs::run_prepare_steps`. Confirm zero non-test callers, then
  delete both the path and its tests.
- Fix the `MirrorCache::get` doc-comment that still says "no eviction today"
  though `evict_to_bounds` exists (`vm_git_mirror_cache.rs`).
- Correct `bailiff`'s docstrings that describe the writ-side strip as pending
  ("slice G deletes writ's legacy verb", "the soon-to-leave `agent_plan::PlanId`",
  "the legacy `RejectedRestart` naming") — the migration is complete in code;
  only the comments lag.

### Slice 4 — extract the guest client into its own crate (`writ-vm-client`)

**The machine-enforced-invariant slice.** "The guest surface must not link host
deps" is currently upheld only by discipline plus the `writ-vm` binary's build
flags. Move `vm_client.rs` (and its guest-only helpers) into a crate whose
manifest depends only on `writ-vm-git`, `writ-core`, `reqwest`, `ring`,
`base64`. After this, a host dependency creeping into the guest surface is a
**compile error in the crate graph**, not a lint nobody runs. Depends on Slice 1
having already severed the feature entanglement. Keep `writ::vm_client`
re-exporting the crate so `writ-vm` and any host test references don't churn.

### Slice 5 — extract the audit log into `writ-audit`

The cleanest remaining seam and the closest analogue to the existing
`writ-core` extraction: `src/audit/` + `src/boot_reconcile.rs` are a
self-contained SQLite subsystem with a narrow interface (open/migrate, the
typed row DAOs, the two-phase write helpers, reconcile). Depends on `writ-core`
for the id/`UnixMillis` types. Re-export as `writ::audit` to keep call sites
stable. Buys compile isolation: editing schema/DAOs stops recompiling the whole
shell.

### Slice 6 — extract the git pipeline into `writ-git`

`git_push_{staging,approve,promote,replay,replay_object_parse,
replay_object_source,replay_walker}.rs`, `clean_git.rs`, `github_git_db.rs`, and
the shared `notes_repo.rs` + `vm_git_bundle.rs` + `vm_git_mirror_cache.rs`.
Larger and with more inbound edges (server, vm_http, bailiff via `notes_repo`),
so do it after Slices 4–5 prove the extraction pattern. Rename the
accretion-order modules to domain names *inside* the new crate in the same pass
(e.g. `git_push_replay_object_source` → `objects::cat_file_source`,
`git_push_replay_object_parse` → `objects::parse`,
`git_push_replay_walker` → `replay::walker`). Note `notes_repo` is shared with
`bailiff`; if the coupling is awkward, split it into a small `writ-git-notes`
that both depend on rather than forcing `bailiff` to pull the whole pipeline.

### Slice 7 — extract the VM sandbox into `writ-vm-host`

`agent_vm_{lifecycle,daemon,firewall}.rs` (+ their dirs),
`broker_{vm,vm_runner,entrypoint,session,log_forwarder}.rs`,
`process_supervisor.rs`, `vm_http/`, and the Nix provisioning modules. The
biggest and most-coupled subsystem (depends on the pipeline, minting, and
audit), so it goes last among the crate splits. The `writ-agent-vm-runner` and
`writ-agent-vm-pf-helper` binaries move with it.

### Slice 8 — break up god-files within their crates (opportunistic, ongoing)

Cheap module boundaries, interleavable with the above and each other:
- `server.rs` → `transport`/`dispatch` + `staged_push` + `run_agent`
  submodules (the staged-push and run-agent orchestration is ~70% of the file
  and is not transport).
- `config.rs` → one submodule per config block (`github_apps`, `policy`,
  `agent_vm`, `ui_http`, `run_agent`, secret store) behind a thin root.
- `agent_vm_lifecycle.rs`, `vm_client.rs`, `protocol.rs`,
  `git_push_replay_walker.rs` (trait + `ShaMap` + both planners + message
  rendering are four separable concerns in one 1485-line file).

Each split is a self-contained PR that moves code without changing it; the
target is that no single file exceeds what one reading can hold.

---

## Verification (applies to every slice)

The feature matrix is the trap, so run the full CI gate set every time, not a
subset (per `CLAUDE.md`):

```sh
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features
nix build .#packages.x86_64-linux.default
```

Plus, for the feature-touching slices (1, 4), explicitly build both surfaces in
isolation:

```sh
cargo build --no-default-features --features host
cargo build --no-default-features --features vm-client   # the writ-vm surface
```

`cargo doc` is load-bearing: `build`/`test`/`clippy` all silently pass on a
broken intra-doc link introduced by moving a module, only the doc gate catches
it. Re-exports (`writ::audit`, `writ::vm_git`, `writ::vm_client`) must stay
stable across each crate extraction so `bailiff` and the `server/` test
submodules don't need edits — if a slice forces downstream edits, that is a
signal the seam is in the wrong place.

## Risks and non-goals

- **Feature-combination breakage** is the main risk; the isolated builds above
  are the guard. `--all-features --all-targets` is what catches a module that
  compiles under `default` but not under `vm-client`.
- **Test-module churn.** `src/server/` and the `agent_vm_*/` dirs hold test
  submodules that reference `crate::…` paths; a crate extraction reparents them.
  Prefer keeping the tests with their subject in the new crate.
- **Not a rewrite.** No behaviour changes, no new abstractions, no
  speculative genericity. Every slice is "same code, better boundary" or "less
  code." If a slice tempts a redesign, that is a separate proposal.
- **Ordering is a recommendation, not a lock.** Slices 1–3 are independent and
  can land in any order; 4–7 should follow the dependency order given; 8 is
  continuous.
