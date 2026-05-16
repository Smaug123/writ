Before committing, run *all three* of the following gates. CI fails if any of them does, so a commit that passes locally on a subset will block the PR:

1. `cargo fmt`
2. `cargo clippy --all-targets -- -D warnings`
3. `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features`

The cargo doc gate is easy to forget because `cargo build`, `cargo test`, and `cargo clippy` all silently pass on a broken intra-doc link — only `cargo doc` (with the rustdoc warnings denied) surfaces it. Treat it as load-bearing as the clippy gate.

There are design docs in docs/design/ .
