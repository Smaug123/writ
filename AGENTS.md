Before committing, run every one of these gates (the same list as `CLAUDE.md`). CI fails if any of them does, so a commit that passes locally on a subset will block the PR:

1. `cargo fmt`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test`
4. `cargo test -p writ --no-default-features --features vm-client --lib --bins` (the guest surface, which the default `host` feature set skips)
5. `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features`
6. `nix build .#packages.x86_64-linux.default` (the separate Nix-build CI job)
7. `./scripts/test-proof-helpers.sh` (the pure-bash helpers the `prove-*.sh` harnesses share)

The cargo doc gate is easy to forget because `cargo build`, `cargo test`, and `cargo clippy` all silently pass on a broken intra-doc link — only `cargo doc` (with the rustdoc warnings denied) surfaces it. Treat it as load-bearing as the clippy gate.

## Architecture

Start from **[`docs/design/architecture.md`](docs/design/architecture.md)** —
the canonical current-state map of the system, one section per subsystem
(guarantees, primitives, invariants) with pointers into the code. Read it before
changing a subsystem, and update the relevant section *in place* in the same PR
when you change that subsystem's shape.

The other files in `docs/design/` are **historical build journals**: useful for
rationale and empirical findings, but superseded by `architecture.md` wherever
they describe layout, schema, or "what exists." Do not extend them
slice-by-slice — that idiom is what left the repo recording its history instead
of its architecture. Record new rationale in a dated `docs/plans/` slice; record
the *result* in `architecture.md`. Known structural debt and its remediation are
tracked in
[`docs/plans/2026-07-17-architecture-refactor-backlog.md`](docs/plans/2026-07-17-architecture-refactor-backlog.md).
