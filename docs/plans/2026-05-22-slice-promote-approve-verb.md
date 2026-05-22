# Slice — `writ promote approve` CLI verb

Drafted 2026-05-22. Closes the operator-toolkit gap left by the
B1e family: the broker has shipped a full `ApproveStagedPush` RPC
(slices B1e.2 through B1e.3d.2 — handler, state machine, audit
write-ahead marker, boot reconcile worker, end-to-end property
test), but `writ` exposes only `promote list`, `promote show`,
`promote reject`, and `promote reconcile`. There is no
operator-facing way to actually accept a staged push. This slice
adds that verb.

## Motivation

Slice E4c closed the dogfood loop on the bailiff side: a single
operator can drive `submit → decide → review → implement` from
`bailiff` and the implementer agent pushes through writd's
GitHub-App minter. The push lands in writd's staging directory
and shows up in `writ promote list`, but the dogfood stops there
because the operator has no command to promote it onto the App
identity. The two existing operator verdicts are `reject` and
`reconcile` (the latter being for *out-of-band* recovery, not the
happy path); the missing `approve` is the happy path.

Once this verb ships, the full
`bailiff plan submit → decide → implement → writ promote approve`
loop is reachable end-to-end from CLI, and slice H ("rewrite
`docs/design/broker.md`, add `docs/design/bailiff.md`, split
CLI reference") can be the first feature driven through the
dogfood.

## What ships

One clap subcommand and one dispatch arm in `src/bin/writ.rs`:

- `PromoteCmd::Approve { request_id: String }` variant — bare
  shape, mirroring `PromoteCmd::Reject` except no `--reason`
  flag. The library's `ApproveStagedPush` request does not carry
  a reason field; approve is an unconditional verdict.
- Dispatch arm that parses `request_id` to `RequestId`, captures
  `$USER` via the existing `capture_operator_identity()` helper,
  sends `ClientMessage::ApproveStagedPush { request_id, operator }`,
  and maps each documented response variant.
- Three clap-surface tests (see below).
- One-line success print:
  `approved push_request_id=<id> new_app_tip=<oid>`.

## Surface details

The verb is intentionally bare:

- **No `--reason` flag.** `ClientMessage::ApproveStagedPush` has no
  reason field; the wire shape pinned in slice B1e.1
  (`src/protocol.rs:401-404`) is `{ request_id, operator }`. Adding
  an operator-side reason that the broker discards would be a
  lie. If we ever decide approval needs a justification string,
  it's a coordinated protocol + handler + CLI change, not a
  CLI-only one.
- **No "are you sure" prompt.** The broker's state machine
  (slices B1e.3a–B1e.3d) makes approve idempotent against its
  own resolution row and serialises against concurrent
  reject/reconcile — so a misclick cannot race into a corrupt
  state. The state-machine pin is what makes this safe.
- **Receipt prints `new_app_tip`.** `ServerMessage::StagedPushApproved`
  (`src/protocol.rs:566-569`) carries both `request_id` and
  `new_app_tip: GitObjectId` — the App-side commit SHA the walker
  produced on the upstream branch. Bailiff (and the operator) need
  that SHA to verify the push landed; printing it on the receipt
  is the only place a CLI caller sees it without querying the
  audit DB.
- **Operator identity captured the same way as Reject.**
  `capture_operator_identity()` reads `$USER` (or `"unknown"`).
  The local-socket peer is the trust boundary; the broker records
  whatever the host asserts.

## Error mapping

`ApproveStagedPush` surfaces three documented response variants
(`src/protocol.rs:380-404` and `src/protocol.rs:566-569`):

| Server response | Operator-facing message |
| --- | --- |
| `StagedPushApproved { request_id, new_app_tip }` | `approved push_request_id={request_id} new_app_tip={new_app_tip}` (stdout) |
| `UnknownStagedPush { request_id }` | `no staged push with id {request_id}` |
| `StagedPushAlreadyResolved { request_id }` | `staged push {request_id} already has an operator decision recorded` (verbatim from `Reject`'s wording — same invariant) |
| `Error { message }` | passthrough — the broker already names its own failures |
| any other variant | `unexpected response: {other:?}` |

The two non-success-non-Error variants reuse `Reject`'s exact
wording (`src/bin/writ.rs:518-526`) because the invariant the
operator hit is identical: the staging directory is gone, or a
prior decision is already recorded.

## What stays in scope

- Tests-first: write the three clap-surface tests, observe them
  fail (the variant doesn't exist), then add the variant +
  dispatch arm. Per Gospel.
- Output discipline: `println!` to stdout on success; everything
  else returns `Err(...)` and lands on stderr via `main()`'s
  existing `eprintln!` path.

## What stays out of scope

- **Bailiff-side notification of the approve outcome.** Bailiff
  has no way to learn that a staged push the implementer agent
  produced has been promoted to GitHub; an operator who wants to
  cross-reference reads writ's audit log. Threading the
  `new_app_tip` back into a bailiff-side note ("plan X's implement
  push landed at commit Y on the upstream branch") is a future
  slice — bailiff would have to grow a new note kind or a column
  in the implement note, and that's a refs-shape change.
- **Docs updates.** `docs/user_facing/cli-reference.md` doesn't
  mention the existing promote verbs at the level of detail this
  one will need either; a single-verb edit would be a stub. Slice
  H is the natural home for the docs sweep.
- **End-to-end tests.** The broker's
  `approve_staged_push` handler has full end-to-end coverage
  (slice B1e.3d.2's property test). Duplicating at the binary
  layer would test clap, not the handler. The three parser tests
  cover the binding.

## Plan of work

One PR, no sub-slices.

### Step 1 — three failing parser tests

In `src/bin/writ.rs` `#[cfg(test)] mod tests`, adjacent to the
existing `promote_reject_cli_*` and `promote_reconcile_cli_*`
tests:

- `promote_approve_cli_parses_request_id` — `writ promote
  approve <id>` parses into `PromoteCmd::Approve { request_id }`.
- `promote_approve_cli_requires_request_id` — `writ promote
  approve` with no positional argument fails parse.
- `promote_approve_cli_rejects_extra_flags` — passing
  `--reason` should fail (no such flag). This pins that the
  variant stays bare; a future "let's add a reason field" PR
  has to delete this test deliberately, which is the right
  threshold.

Observe all three fail to compile (variant doesn't exist).

### Step 2 — add the clap variant

Add `PromoteCmd::Approve { request_id: String }` between `Show`
and `Reject` in the existing `enum PromoteCmd` declaration
(`src/bin/writ.rs:90-182`). Docstring: "Approve a staged push:
the broker mints an installation token, replays the staged
commits under the App's identity, points the branch at the new
tip, and records the audit resolution. Returns the App-side
commit SHA on success." Mirrors `Reject`'s tone.

### Step 3 — dispatch arm

Add the dispatch arm in `Cmd::Promote { action }` (next to the
existing `PromoteCmd::Reject` and `PromoteCmd::Reconcile`
arms at `src/bin/writ.rs:503-577`). Body:

```rust
PromoteCmd::Approve { request_id } => {
    let id: RequestId = request_id
        .parse()
        .map_err(|e| format!("invalid request ID: {e}"))?;
    let operator = capture_operator_identity();
    let msg = ClientMessage::ApproveStagedPush { request_id: id, operator };
    match call(&socket_path, &msg)? {
        ServerMessage::StagedPushApproved { request_id, new_app_tip } => {
            println!("approved push_request_id={request_id} new_app_tip={new_app_tip}");
        }
        ServerMessage::UnknownStagedPush { request_id } => {
            return Err(format!("no staged push with id {request_id}").into());
        }
        ServerMessage::StagedPushAlreadyResolved { request_id } => {
            return Err(format!(
                "staged push {request_id} already has an operator decision recorded",
            ).into());
        }
        ServerMessage::Error { message } => return Err(message.into()),
        other => return Err(format!("unexpected response: {other:?}").into()),
    }
}
```

### Step 4 — gate suite + commit + PR + codex review

- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo fmt --all -- --check`
- Commit, push, open PR
- Run `codex review --base main` per `CLAUDE.md`; iterate to
  convergence per the `feedback_codex_loop_smell` heuristic
  (shape of findings, not round count).

## Estimated total

~60 LoC across one PR. Variant declaration + dispatch arm ≈ 30
LoC of production code; three parser tests ≈ 30 LoC. Smallest
slice in the bailiff/writ split family — there's no library
work, no protocol work, no schema work. Pure CLI binding.

## Risks and tradeoffs

- **Operator footgun: irrevocable.** Once approved, the staged
  push has minted a real GitHub-App token and pushed real
  commits. There is no `writ promote unapprove`. The recourse for
  a regretted approval is a separate `git revert` against the
  upstream branch, with no writ involvement. The brokered state
  machine pin (a second approve gets `StagedPushAlreadyResolved`,
  not a duplicate push) makes the *machine* side safe; the
  *operator* side relies on the operator looking at `promote
  show` first. This slice does not add a confirmation prompt
  because the existing `reject` doesn't either — adding one to
  approve only would be asymmetric, and a "rejected by accident"
  push is just as wasteful as an "approved by accident" one.

- **No bailiff-side feedback loop.** As noted in
  "out of scope": bailiff doesn't learn that the staged push
  it produced has landed. Operators who want a single record of
  truth have to consult writ's audit DB. This is a real
  limitation but a future slice; threading `new_app_tip` into
  bailiff's implement note would be the natural shape.

- **Receipt format pin.** Once `approved push_request_id=X
  new_app_tip=Y` is in operators' shell history and grep
  pipelines, the format is sticky. The format chosen here
  matches the `reject` / `reconcile` style
  (`<verb> push_request_id=<id> [extra=…]`) deliberately so the
  whole verb family parses uniformly. A future change would have
  to migrate the same shape across all four verbs at once.

## Open questions

None. The RPC is settled (B1e.3), the audit pipeline is settled
(B2.1–B2.4), the CLI templates are right next door. The binding
is mechanical.
