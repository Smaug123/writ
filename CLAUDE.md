# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`writ` is a local capability broker for coding agents. `writd` is a daemon on a
Unix socket; an agent asks it for one narrowly-scoped, short-lived credential
per action (e.g. "push to `smaug123/writ`"), and every grant is recorded in an
append-only SQLite audit log. See `docs/design/architecture.md` for the
canonical current-state architecture (one section per subsystem: guarantees,
primitives, invariants), and `README.md` for the user-facing framing. The other
`docs/design/` files are historical build journals, superseded by
`architecture.md` wherever they describe layout or schema.

## Build, test, lint

Everything runs inside the Nix dev shell (`nix develop`), which supplies
`cargo`, `rustc`, `clippy`, `rustfmt`, `git`, `claude-code`, and `codex`. In a
fresh tree, prefix cargo/codex invocations with `nix develop -c` (the direnv
`.envrc` loads it automatically in interactive shells).

CI fails if **any** of these gates fails, so run all of them before committing —
passing a subset locally still blocks the PR:

```sh
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test
# `host` (the default) does not enable `vm-client`, so `cargo test` skips the
# guest surface; run its lib+bin tests directly (tests/ suites are host-only):
cargo test -p writ --no-default-features --features vm-client --lib --bins
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features
nix build .#packages.x86_64-linux.default   # the separate Nix-build CI job
```

The `cargo doc` gate is load-bearing and easy to forget: `build`, `test`, and
`clippy` all silently pass on a broken intra-doc link — only `cargo doc` with
warnings denied catches it.

Run a single test: `cargo test <substring>` or, scoped to a member crate,
`cargo test -p bailiff <substring>` (workspace members are `writ`, `writ-core`,
`writ-vm-git`, `bailiff`).

Do **not** raise `--test-threads` (or `RUST_TEST_THREADS`) above the core count.
Much of this suite spawns real subprocesses and waits on real deadlines, so
oversubscribing the machine makes scheduling latency — not the code — decide
whether a timeout fires. The default (one thread per core) is the right setting;
if the machine is otherwise busy, run with *fewer*. See
`docs/known-test-flakes.md`.

After raising a PR, run `codex review --base main` to get a Codex review. It
prints a great deal to stdout before the freeform review text at the end.

## Feature flags (a common footgun)

Cargo features gate which modules even compile. Most of the codebase is
`#[cfg(feature = "host")]`.

- `host` (in `default`) — the daemon, CLI, and all host-side deps (SQLite,
  keyring, GitHub/JWT, hyper, compression).
- `vm-client` — the guest-side surface. The `writ-vm` binary builds with
  `--no-default-features --features vm-client`; it must not pull in host deps.

If you add a host-only module, gate it with `#[cfg(feature = "host")]` in
`src/lib.rs` or `vm-client` builds break. `--all-features`/`--all-targets` in
the gates above is what catches feature-combination mistakes.

## Workspace layout

- **`crates/writ-core`** — the pure functional core: request/decision/grant
  types, capability sets, signing, ids. No host effects (tokio is behind its own
  `host` feature). Re-exported from the root crate as `writ::core`.
- **root `writ` crate** — the imperative shell. Binaries: `writd` (daemon),
  `writ` (CLI client), `writ-vm` (guest CLI), `writ-agent-vm-runner`,
  `writ-agent-vm-pf-helper`.
- **`crates/writ-vm-git`** — wire types shared between host and guest for
  VM-mediated git (branch/object-id parsing, clone/push request shapes).
- **`crates/bailiff`** — a plan-workflow product (submit → review → decide →
  implement) built *on top of* writ. Records each step as a signed git note in
  its own bare repo and verifies agent-run envelopes minted by the broker.
  `bailiff` depends on `writ`; `writ` never depends on `bailiff`.

## Architecture notes that span multiple files

- **Interpreter pattern, not traits.** `CapabilityRequest` is a discriminated
  union; `policy::decide` is a pure `match` producing `PolicyDecision`
  (`Grant`/`Deny`); the shell then mints. The policy engine *inspects* request
  data, so it is a DU, not a `Backend` trait with a `mint()` method. Follow this
  when extending: construct inert data, interpret it separately.
- **Audit log is complete by construction.** Because the only way to act is to
  obtain a grant, the SQLite log (`audit/`) *is* the history. Writes are
  two-phase (request row commits before the mint is awaited; a grant or
  mint-failure row follows), and schema evolves through migrations keyed off
  `PRAGMA user_version`. A DB at a higher version than the binary understands is
  refused, not opened — correctness over availability.
- **Agent-VM subsystem** (`agent_vm_*`, `broker_vm*`, `vm_http`, `vm_git_*`,
  `flake_*`, `nix_cache`) is large and security-critical. An agent runs inside
  an Apple `container` Linux VM with no host mounts and no network egress; every
  external effect (git, Nix substitution, model APIs, signing) crosses a host
  broker endpoint. **Treat the guest as compromised the moment the agent
  command starts** — guest-side `writ-vm` commands are ergonomic wrappers, never
  the authority boundary. The broker independently re-validates every field
  (repo, branch, ancestry, object graph) before using host authority. See
  `docs/design/architecture.md` §5.5–5.7 for the current shape;
  `docs/design/apple-container-agent-vm.md` and `docs/design/vm-mediated-push.md`
  are the (historical) design journals behind it.
- The `scripts/prove-*.sh` scripts are adversarial end-to-end proofs (no-egress,
  offline flake realisation, broker readiness) run on real hardware, not part of
  `cargo test`.

## Conventions

This codebase follows the design principles in the user's `gospel.md`
closely: functional core / imperative shell, parse-don't-validate at every
boundary, make illegal states unrepresentable, and **property-based testing over
example-based**. Proptest is used pervasively (`tests/properties.rs` plus
per-module `#[cfg(test)]` blocks); saved counterexamples live in
`proptest-regressions/`. When fixing a bug, add the failing property/test first,
watch it fail, then fix.

The current-state architecture map is `docs/design/architecture.md` (start
there); the other `docs/design/` files are historical build journals. Dated
implementation plans (decomposed into reviewable slices) live in `docs/plans/`.
Known test flakes are documented in `docs/known-test-flakes.md` and `FLAKE.md`.
