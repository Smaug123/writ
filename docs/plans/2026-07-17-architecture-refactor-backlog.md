# Refactor backlog — from a flat 40-module crate to domain-shaped boundaries

Drafted 2026-07-17. Companion to the current-state map in
[`../design/architecture.md`](../design/architecture.md), which shipped in the
same change. This plan is the *sequenced structural remediation* of the debt
that map names in §2–§3. **It is a backlog, not a commitment**: each slice is
independently reviewable and independently shippable, ordered so the cheap,
high-leverage moves land first. No code moves in the doc PR; this file exists so
the work is scoped and ready to pick up.

**Status (2026-07-26): closed out.** Slices 0–5b are implemented, Slices 6 and 7
were investigated and *declined* on the boundary-cost framework below (no
`writ-git`, no `writ-vm-host` — the evidence is in their sections), and Slice 8
is a standing opportunistic habit rather than a task list: no file in the tree
now exceeds ~2.1k lines, and the largest, `agent_vm_lifecycle.rs`, is at its
intrinsic domain size. Nothing in this backlog is waiting to be picked up.

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

Drafted as:

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

**Landed as** the same graph minus its two left-hand nodes: investigation under
Slices 6 and 7 found that neither `writ-git` nor `writ-vm-host` is a real seam,
and both were declined on the boundary-cost framework below (see those sections
for the evidence). `writ-agent-run` was extracted instead (Slice 4a), so the
shipped graph is `bailiff ─▶ writ ─▶ {writ-audit, writ-vm-client,
writ-agent-run} ─▶ writ-vm-git ─▶ writ-core`.

`writ` stays the imperative shell that wires effects to the daemon. The
subsystem names in `architecture.md` §5 were the *candidate* crate seams; the
sections below record, for each, whether it survived contact with the actual
coupling graph.

---

## Slices

### Slice 0 — the map (shipped)

`architecture.md`; historical banners on the design journals; `AGENTS.md`,
`CLAUDE.md`, and `src/lib.rs` repointed at the map. This backlog.

### Slice 1 — sever the `host` → `vm-client` feature entanglement (implemented)

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

### Slice 2 — disambiguate the two `nix_cache` modules (implemented)

Renamed by layer (they are domain-lib vs HTTP-shell, see `architecture.md` §5.6):
- `src/nix_cache.rs` (types + Ed25519 verification + NAR hashing + admission
  parsers, zero HTTP) → **`src/nix_binary_cache.rs`**. Chosen over the sketch's
  `nix_narinfo`/`nix_cache_admission` because the module also owns store paths
  and NAR hashing, not just narinfo/admission — its own doc already called it
  the "Nix binary-cache" layer.
- `src/vm_http/nix_cache.rs` (the `VmHttpNixCacheService`) keeps its name; its
  module path (`crate::vm_http::nix_cache`) already disambiguates it from the
  renamed `crate::nix_binary_cache`.

Pure `git mv` + word-boundary-guarded rewrite of `crate::nix_cache` paths, fully
compiler-checked. The `flake_provision.rs` / `flake_provision_from_mirror.rs` /
`vm_http/flake_provision.rs` trio is **deferred**: those names do not actually
*collide* (only the two `nix_cache` did), so renaming them is lower-value churn
better folded into the god-file/naming pass (Slice 8).

### Slice 3 — correct stale in-code claims (implemented); vestigial-replay delete re-scoped

"Delete aggressively." Two independently-verifiable stale-comment fixes, done:
- Fixed the `MirrorCache::get` doc-comment that still said "no eviction today"
  though `evict_to_bounds` exists (`vm_git_mirror_cache.rs`).
- Swept `bailiff`'s docstrings for *every* claim that described the writ-side
  strip as still pending (`plan decide` "going away in slice G", the
  "soon-to-leave `agent_plan::PlanId`", `agent_plan::PlanBody` as a current
  alternative) and reworded to past tense — the strip is complete (writ has no
  `agent_plan` module, no `plan decide` verb, no `RejectedRestart`). writ's own
  audit-schema comments keep their accurate past-tense slice-G history.

**Re-scoped.** The third item — "remove the vestigial staging-repo bring-up in
`git_push_replay.rs`" — is larger than a dead-path delete. The `GitPushReplayPlan`
/ `ReplayTarget` / `ingest_bundle` / `prepare_staging_repo` cluster does have zero
external *code* callers (the live approve path reimplements bring-up in
`git_push_approve.rs`), but it is **interleaved** in the same 1804-line module
with the *live* `TrailerSource` / `TrailerKey` / `TrailerValue` commit-trailer
vocabulary that `git_push_approve`, `git_push_promote`, and
`git_push_walker` all import. Removing the dead cluster therefore means
*extracting* the trailer types (e.g. into a `git_push_trailers` module) and
deleting the rest — a module split, not a one-shot delete. Folded into **Slice
6** (git-pipeline extraction), where these boundaries move anyway; doing it there
avoids a risky ~1.4k-line surgery bundled with unrelated work.

### Slice 4a — relocate `agent_run` into a shared `writ-agent-run` crate (implemented)

A prerequisite for 4b that the original sketch missed: `vm_client` imports the
`agent_run` contract (prompt/output types + the agent process-runner), and a
guest-client crate can't depend back on `writ`. `agent_run` is also used by ~20
host modules and by bailiff, so it belongs in a *shared* crate, not the guest
one (chosen over folding it into `writ-core`).

Extracted `src/agent_run.rs` → `crates/writ-agent-run/` (deps: `writ-core` for
`process_spawn`, `serde`, `uuid`, `ring`). The crate mirrors writ's `host` /
`vm-client` feature names so the moved module's `#[cfg(...)]` attributes are
unchanged; a `test-support` feature exposes the test-only `AgentPrompt::new` to
downstream test crates (`writ` enables it as a dev-dependency). `writ` re-exports
it via `pub use writ_agent_run as agent_run`, so all ~40 `crate::agent_run::…` /
`writ::agent_run::…` call sites are unchanged. The crate's tests run in the
workspace `cargo test` via feature unification (writ/host → writ-agent-run/host).

### Slice 4b — extract the guest client into `writ-vm-client` (implemented)

**The machine-enforced-invariant slice.** With `agent_run` in `writ-agent-run`
(4a), moved `src/vm_client.rs` → `crates/writ-vm-client/` (deps: `writ-core`,
`writ-vm-git`, `writ-agent-run` [vm-client], `reqwest`, `tokio`, `base64`,
`serde_json`, `thiserror`, `uuid` — **no host crate**). Rewrote the four
`crate::` module prefixes (`agent_run`/`bearer`/`process_spawn`/`vm_git`) to
their crates. `writ` re-exports `pub use writ_vm_client as vm_client` under the
`vm-client` feature (optional dep), so the `writ-vm` binary is unchanged.

Host-dep-freedom is now a crate-graph property: `--features host` does not pull
`writ-vm-client` (verified via `cargo tree`). Two clean-ups fell out — `writ`'s
`vm-client` feature no longer needs `reqwest`/`base64`/`ring` (only `vm_client`
used them; host keeps its own copies), and the `writ_core::bearer` re-export is
now `#[cfg(feature = "host")]` (its only guest user left with `vm_client`). The
41 guest lib tests moved with the crate and run under the default `cargo test`
(writ-vm-client is a workspace member).

### Slice 5a — move `NetworkHealth` into `writ-core` (implemented)

A prerequisite the sketch missed: `src/audit/` references two root-crate
modules — `agent_vm_lifecycle::NetworkHealth` (the audit network-health row) and
(via `boot_reconcile.rs`) `git_push_staging`. The first is resolved here; the
second by leaving `boot_reconcile.rs` in `writ` (it is an *orchestrator* that
uses the audit DAOs + the git pipeline, not audit storage — see 5b).

`NetworkHealth` is a pure, wire-facing state enum (its own doc says it is
surfaced in `writ agent-vm list` and stored in the audit log), used by the
daemon, CLI, protocol, and audit. Moved the enum to a new
`crates/writ-core/src/core/network_health.rs`; the host
`agent_vm_lifecycle::network_health` module (the debounced tracker that
*produces* it) re-exports it via `pub use crate::core::NetworkHealth`, so every
`agent_vm_lifecycle::NetworkHealth` consumer is unchanged. Three files touched.

### Slice 5b — extract the audit log into `writ-audit` (implemented)

Moved `src/audit/` → `crates/writ-audit/` (deps `writ-core`, `writ-agent-run`
[host], `writ-vm-git`, `rusqlite`, `serde`, `serde_json`, `time`, `uuid`,
`thiserror`). Rewrote `crate::{core,agent_run,vm_git}` → their crates and
`crate::audit` → `crate`; re-exported as `pub use writ_audit as audit` under the
`host` feature (optional dep), so all ~32 `crate::audit::…` consumers are
unchanged. `boot_reconcile.rs` stays in `writ` — it drives the audit DAOs but
also needs `git_push_staging` (Slice 6), so it's an orchestrator, not storage.

Two mechanical wrinkles the compiler surfaced: the crate-root `AuditLog`
`with_conn` helpers were `pub(super)` (invalid at a lib root) → `pub(crate)`; and
the `*_for_test` DAO read-back helpers (used by `writ`'s vm_http/git_push tests)
were `#[cfg(test)]` and don't cross crates → moved behind a `test-support`
feature (`writ` enables it as a dev-dependency), matching the 4a pattern. Buys
compile isolation: editing schema/DAOs stops recompiling the whole shell.

### Slice 6 — git-pipeline hygiene (no crate)

**Decision: do *not* extract a `writ-git` crate.** Investigation showed the git
pipeline is not a clean crate boundary the way audit/agent-run/vm-client were.
Its outbound couplings: the shared `signing` subsystem (`WritSigningKey`, also
used by run-provenance `run_verify`, and needing the `SecretStore`);
`git_commit_sign` ↔ `github_git_db` mutual entanglement; and `crash_point` /
`process_supervisor` shared with the shell. (The `github` *minting* coupling was
only a doc comment — the pipeline doesn't mint.) A `writ-git` crate would need
3–4 prerequisite relocations first and still depend on many crates, diluting the
compile-isolation payoff — a boundary whose cost exceeds its benefit per the
boundary framework. The four *clean* crate boundaries the reviewer named
(agent-run, guest-client, audit, + pre-existing core/vm-git) are all extracted.

Instead, do the low-risk internal hygiene that improves local reasoning without
paying for a bad boundary:

**Done — the re-scoped Slice 3 item.** `git_push_replay.rs` was dead except for
the commit-trailer vocabulary. Extracted `TrailerSource`/`TrailerKey`/
`TrailerValue` (+ their tests) into `git_push_trailers.rs`, re-pathed the four
importers, and deleted the vestigial `GitPushReplayPlan`/`ReplayTarget`/
`ingest_bundle`/`prepare_staging_repo` cluster and its tests — net −1.5k lines.

**Module renames (implemented).** Renamed the three accretion-order git-push
modules to domain names, dropping the `replay_` prefix left over from the
now-deleted `git_push_replay.rs` god-module: `git_push_replay_object_source` →
`git_push_objects_cat_file`, `git_push_replay_object_parse` →
`git_push_object_parse`, `git_push_replay_walker` → `git_push_walker`. Pure
renames (five `git mv`s plus a word-boundary identifier rewrite), fully
compiler-checked; the names now encode layering, not commit order. The
`vm_http::flake_provision` / `flake_provision` / `flake_provision_from_mirror`
trio was left as-is: those names are domain-descriptive (the shared prefix marks
a real subsystem, disambiguated by the `_from_mirror` suffix and the `vm_http::`
path — the same rule that kept `vm_http::nix_cache` in Slice 2), not
accretion-order artifacts.

### Slice 7 — the VM sandbox (`writ-vm-host`)

The candidate set: `agent_vm_{lifecycle,daemon,firewall}.rs` (+ their dirs),
`broker_{vm,vm_runner,entrypoint,session,log_forwarder}.rs`,
`process_supervisor.rs`, `vm_http/`, and the Nix provisioning modules — ~60
files and ~43k lines with tests, plus the `writ-agent-vm-runner` and
`writ-agent-vm-pf-helper` binaries. It was scheduled last among the crate
splits because it is the biggest and most-coupled subsystem.

**Decision: do *not* extract a `writ-vm-host` crate.** Same verdict as Slice 6
and for a stronger reason — this boundary is not even a DAG, so it fails before
the cost/benefit question is reached.

- **It is entangled with `BrokerState`, which *is* the shell.** The set holds 23
  `crate::server::…` references, 13 of them to `BrokerState`, spread over 15
  files: essentially every `vm_http` handler is generic over `S: SecretStore` and
  takes an `Arc<BrokerState<S>>`. That struct owns the minter, policy config,
  audit handle, staging store, notes repo, signing key, and promote runtime.
  Moving it into `writ-vm-host` moves the shell; leaving it behind means
  inverting the dependency behind a trait the shell implements — an interface for
  exactly one implementation, which would make every handler's control flow
  non-local. That is the thing the rest of this repo is arranged to avoid, and
  buying it with a crate boundary is a bad trade at any price.
- **The dependency runs both ways.** The subsystem reaches back for
  `crate::server::{run_with_agent_vm, capture_stream_capped,
  MAX_RUN_AGENT_STREAM_BYTES, error_with_source_chain, CapabilityOutcome}` while
  `server.rs`'s dispatch calls *into* the subsystem. A crate boundary must be
  acyclic, so those five would have to be relocated first — and
  `run_with_agent_vm` is the shell's own run-agent path, not VM-sandbox
  internals.
- **The ordinary shell couplings are heavy too**: `crate::secret` (22),
  `crate::config` (16), `crate::signing` (7), `crate::git_push_{staging,promote}`
  (8), plus `github`, `policy`, `protocol`, `run_envelope`, and `crash_point`.
  (`core`/`agent_run`/`audit`/`vm_git`, the four heaviest by raw count, are
  already their own crates and would be ordinary dependencies.)

What the crate would buy is compile isolation, and it would not get it: a crate
that depends on the shell's central state struct recompiles on every edit to that
struct, which is most edits. The four clean boundaries the original review named
(agent-run, guest-client, audit, plus the pre-existing core/vm-git) are all
extracted; the remainder of the tree is one program, and the honest description
of it is a functional core in five crates with an imperative shell in `writ`.

The local-reasoning goal Slice 7 was reaching for is better served by Slice 8's
in-crate module boundaries, which cost nothing and are already delivering it —
`vm_http/`, `agent_vm_daemon/`, `agent_vm_lifecycle/`, and `broker_vm/` are all
directories with named submodules now, which is the readability win a crate
split was going to be a very expensive way to buy.

### Slice 8 — break up god-files within their crates (opportunistic, ongoing)

Cheap module boundaries, interleavable with the above and each other. Each split
is a self-contained PR that moves code without changing it; the target is that no
single file exceeds what one reading can hold.

- **`config.rs` (3673 → `config/mod.rs` 1375):** taken in two slices into a
  `config/` directory. First the audit-directory dedication check + legacy
  audit-DB migration (a self-contained filesystem concern with no
  `#[serde(default)]` coupling) moved to `config/audit_dir.rs` (code + tests),
  re-exported so `crate::config::…` call sites are unchanged. The `AgentVm*`
  config block was flagged as the next candidate but its `#[serde(default =
  "…")]` string paths make a domain split churny — and it turned out unnecessary:
  the remaining bulk was a ~1.6k-line inline `#[cfg(test)] mod tests`, so the
  cleaner move was to relocate that to `config/tests.rs`, leaving `config/mod.rs`
  a 1375-line single-concern file (the `DaemonConfig` tree + validators). The 75
  tests run unchanged; the serde-default coupling was sidestepped entirely.
- **`server.rs` (3188 → 881):** two cohesive subsystems, each reached only
  through `dispatch_message`, lifted into `pub(super)` submodules:
  - `server/staged_push.rs` (1772) — the `list`/`show`/`reject`/`approve`/
    `reconcile` approval handlers. The five dispatch arms delegate; the four
    dedicated test files gained explicit `use super::staged_push::…` imports.
  - `server/run_agent.rs` (569) — the `RunAgent` handler and its VM-dispatch
    path. Only `run_agent` is `pub(super)` (dispatch's single entry); the shared
    output-capture helper `capture_stream_capped` + `MAX_RUN_AGENT_STREAM_BYTES`
    stay at the module root because `agent_vm_daemon::materialize` also consumes
    them via `crate::server::…`. `run_agent_tests` drives through
    `dispatch_message`, so no test edits were needed.

  `server.rs` is now pure transport, dispatch, and connection handling.
- **`agent_vm_lifecycle.rs` (3215 → 2405, started):** the largest root-crate
  god-file. Two inherent `impl` blocks lifted into submodules — inherent-impl
  moves need no call-site changes (method resolution is by type), so only the
  handful of private methods invoked from *outside* their impl needed
  `pub(super)`:
  - `invocation.rs` — the 336-line `ProcessInvocation` execution primitive.
    Three helpers called on it from sibling types
    (`output`/`failed_from_output`/`resource_still_present`) became `pub(super)`;
    `invocation_tests` untouched.
  - `plan.rs` — the 478-line `AgentVmSessionPlan` start-step/invocation builder.
    Only `run_start_vm_invocation` (called from the `run_start_step` free
    function) needed `pub(super)`; the twelve other private builders stayed
    private.

  Remaining clean seam: the session-teardown/`run_*_cleanup_until_absent`
  machinery (~394 lines, with a dedicated `cleanup_tests.rs`).
- **`protocol.rs` (2296 → `protocol/mod.rs` 2072 + `views.rs` 246):** the
  payload types the wire messages *carry* — the staged-push views, the
  `SignedRunMetadata` envelope, `ReconcileOutcome`, and the `RejectionReason`
  newtype with its bounded parse — moved to `protocol/views.rs`, re-exported so
  `crate::protocol::…` call sites are unchanged. The `ClientMessage`/
  `ServerMessage` DUs and the wire tests stay in `mod.rs`; views' doc-links to
  the message enums became `[super::…]`, and the test module picked up the
  handful of crate-type imports the payload move stranded.
- **`github_git_db.rs` (2538 → 2146):** the `GitDataClient` request methods
  (blob/tree/commit creation, ref read/update — a 392-line inherent `impl`)
  moved to `github_git_db/client.rs`. All seven methods are `pub`, so the
  by-type inherent-impl move needed zero `pub(super)` bumps and zero call-site
  changes; the struct, its timeout/error types, the domain types it returns, and
  the wire DTOs stay in the parent, reached via `super`. (~1.6k of the original
  lines are the inline test module — a candidate future test-file split, as done
  for `nix_binary_cache.rs` below and still pending for `git_push_approve.rs`.)
- **`broker_vm.rs` (2636 → 2422):** the `BrokerVmPlan` launch/teardown builders
  (network-create/run/inspect/logs/stop invocations — a 214-line inherent
  `impl`) moved to `broker_vm/plan.rs`. Ten of eleven methods are `pub` and the
  one private helper (`broker_command`) has no external caller, so the by-type
  move needed no `pub(super)` bumps or call-site changes. Broker config, secret
  export, and `container inspect` state-parsing remain in the parent as further
  candidate seams.
- **`nix_binary_cache.rs` (2752 → 1345):** this file's production half is a
  single coherent concern — the Nix binary-cache value types, narinfo parsing,
  Ed25519 verification, and NAR hashing — so there was no domain seam to cut;
  its length was the ~1.4k-line inline `#[cfg(test)] mod tests`. Relocated that
  module verbatim to `nix_binary_cache/tests.rs` (a file submodule; `use
  super::*` still resolves), leaving a 1345-line single-concern production file.
  The 41 tests run unchanged in their new location.
- **`git_push_approve.rs` (2387 → 898):** same template — its production half is
  the approve-preparation logic (`PreparedApprove`/`StagingRepo` bring-up and
  verify), and the length was the ~1.5k-line inline test module. Relocated to
  `git_push_approve/tests.rs`. One wrinkle the compiler caught: an
  `include_str!("../tests/fixtures/…")` had to become `../../tests/fixtures/…`
  because the test file sits one directory deeper than the original — the
  standing gotcha for any `include_*!` when a module moves into a subdirectory.
- **`writ-vm-client/src/lib.rs` (3291 → 1628):** the single largest file in the
  tree, and — like the two above — a single-concern guest-command crate whose
  bulk was a ~1.7k-line inline test module. Relocated to
  `crates/writ-vm-client/src/tests.rs`; the 41 tests run unchanged. (No
  `include_*!` paths this time, so no fixup.)
- **`bailiff` binary (`src/bin/bailiff.rs`, 2428 → 1255):** the CLI command
  surface plus a ~1.2k-line inline test module of clap-parsing/dispatch tests.
  Relocated to `src/bin/bailiff/tests.rs`. A binary's entry file is a *crate
  root*, so a bare `mod tests;` resolves to a sibling `src/bin/tests.rs` — which
  cargo would auto-discover as a *second binary* — so the split needs an explicit
  `#[path = "bailiff/tests.rs"] mod tests;`. The 36 tests run unchanged.
- **`writ-audit/src/git_push.rs` (2236 → 1010):** unlike the files above this is
  production-heavy — its bulk was a single 1226-line `impl AuditLog` block of
  git-push audit DAO methods (read/write the request/outcome/resolution/
  approve-attempt rows). Moved that impl to `git_push/dao.rs`; the record types,
  row-mapping helpers, and row structs stay in `git_push.rs`. All 23 methods but
  three are `pub`, and those three private helpers have no external caller, so
  the by-type inherent-impl move needed no `pub(super)` bumps or call-site
  changes. The `UncertainAttempt` witness invariant is preserved: its field is
  still module-private (the `dao` submodule is a descendant of `git_push`, so
  external crates still cannot forge one).
- **`agent_vm_daemon.rs` (2603 → 1295):** the biggest single seam in the tree —
  a 1308-line `impl AgentVmDaemon` (session start/stop/reconcile orchestration
  and its network-health/broker-VM/cleanup helpers). Moved to
  `agent_vm_daemon/daemon_impl.rs`. Four of the ~24 private methods are called
  from test modules — three from test *submodule files* (`agent_vm_daemon/*.rs`)
  and one `#[cfg(test)]` helper from an inline test — and a private method in a
  child module is invisible to *sibling* modules, so those four became
  `pub(super)`; the rest stayed private. All the `pub` methods resolve by type,
  so no call-site changes. (Lesson: for a big impl, scan both inline tests *and*
  sibling test-submodule files for private-method calls before moving.)
- **`vm_http/mod.rs` (2832 → 1677):** the HTTP dispatch core is a coherent
  concern (listener/session/auth/routing/framing), so the length was again a
  ~1.15k-line inline `#[cfg(test)] mod tests`. Relocated to `vm_http/tests.rs`.
  Two things that could have bitten but did not: the module's
  `include_str!("../../tests/fixtures/…")` needed *no* fixup because `mod.rs` and
  `tests.rs` are siblings in the same directory (unlike the `git_push_approve`
  file-module case); and the `#[cfg(test)]` dispatch helpers the tests call
  (`dispatch_vm_http_head`, `DispatchedTestResponse`) stay in `mod.rs` and remain
  reachable from the child `tests` module via `super`. The 30 tests run
  unchanged.

- **Batch test-split (six files at once):** once the pattern was proven, the
  remaining test-dominated single-concern files were relocated in one PR rather
  than one-at-a-time — `github_git_db.rs` (2150 → 524), `broker_vm.rs`
  (2422 → 966), `protocol/mod.rs` (2072 → 534), `notes_repo.rs` (2060 → 1022),
  `writ-vm-git/src/lib.rs` (2017 → 1214), and `git_push_object_parse.rs`
  (2009 → 827). Each moved its single inline `#[cfg(test)] mod tests` to a
  sibling `tests.rs`; none had `include_*!` paths, so no fixups. This clears the
  last of the >2k-line files apart from `agent_vm_lifecycle.rs` (below).

- **`agent_vm_lifecycle.rs` (2409 → 2102):** the session-teardown execution —
  `fail_after_cleanup` and the `run_*_cleanup_until_absent` family (run the stop
  invocations, poll `container`/network resources until provably absent, fold
  the per-step errors into one `CleanupErrors`) — moved to
  `agent_vm_lifecycle/cleanup.rs`. This was the fiddliest free-function cluster:
  seven of the thirteen functions are called from outside (the start-failure
  path, `stop`, the managed-lifecycle functions, and `cleanup_tests`), so they
  became `pub(super)` and the parent re-imports them with `use cleanup::*` so
  both its own calls and the sibling test module's `use super::*` still resolve.
  The genuinely shared helpers it leans on — `resource_list_contains_exact_line`,
  `shell_quote`, `derive_session_network`, and the start-path
  `wait_for_guest_ipv6_inspection` — deliberately stay at the module root
  (`plan`/`invocation` use them too), reached via `super`. That leaves
  `agent_vm_lifecycle.rs` as the lifecycle types + small impls + start/stop/
  managed orchestration; its residue is intrinsic domain size, not a mixed bag.

Rule of thumb learned from the config split: extract the chunks with no
`#[serde(default = "…")]` coupling first — moving a struct away from its default
fns means re-pathing each `default = "…"` attribute, which is churnier.

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
  can land in any order; 4–5 followed the dependency order given; 6 and 7 were
  investigated and declined (their sections record why); 8 is continuous and is
  the only slice with work left in it.
