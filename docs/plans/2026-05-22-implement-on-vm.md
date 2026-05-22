# Slice — `bailiff plan implement` on the agent-VM path

Drafted 2026-05-22. Closes the structural gap that today makes
`bailiff plan implement` impossible to run end-to-end: bailiff's
implementer workflow sends `ClientMessage::RunAgent` carrying
`CapabilitySet::WorkspaceWrite { repo }`, but writd's `RunAgent`
dispatch (`src/server.rs:1997-2104`) is host-only — it spawns a
subprocess via `tokio::process::Command::new(&spawn_config.command)`
with no working-directory provisioning. The `with_cwd()` builder at
`src/agent_run.rs:435` exists but is only used by the VM-side runner
(`src/agent_vm_daemon.rs`); the host path never touches it. So the
implementer agent runs against writd's own cwd with no checkout to
mutate, and any "implement" output is signed prose, not commits.

The VM trust model memory pins the deeper reason this should be in
a VM, not patched into the host path: the guest is compromised once
the agent runs. Implementer agents that mutate a workspace must
execute inside a per-run VM so a compromised agent can't reach
writd's host filesystem, and the broker's signing path remains the
trust boundary.

## Motivation

Three failures converge here:

1. **Host path has no checkout.** The implementer agent has nowhere
   to `git commit && git push`, so `bailiff plan implement` cannot
   produce a staged push. The whole `submit → decide → implement →
   promote approve` dogfood loop dead-ends at implement.
2. **`WorkspaceWrite` is not enforced by writd.** The capability is
   recorded in the signed metadata but the `RunAgent` dispatch never
   checks it. A request that demands write authority gets the same
   no-cwd host spawn as a read-only one. The capability declaration
   is currently a lie, not a constraint.
3. **VM trust model isn't honoured for implement.** Per the project
   memory: "guest VM is compromised after an agent runs; trust
   boundary is the broker + human review." Running an implementer
   agent in writd's own host process violates that model — a
   compromised agent has writd's filesystem and credentials in
   reach. The agent-VM lifecycle already exists to enforce this
   boundary (used by `writ agent run` and exercised by
   `scripts/prove-agent-vm-claude-proxy.sh`); we just haven't routed
   bailiff's implementer through it.

Closing this lets the bailiff/writ dogfood produce real commits
through real GitHub-App credentials, which is the prerequisite for
slice H (docs sweep driven through the loop).

## Design space

Three structural options. The choice hinges on whether to keep
`RunAgent`'s synchronous request/response shape or move the
implement workflow onto an async run-then-wait model.

### Option A — Extend `RunAgent` with optional workspace bootstrap

Add `workspace: Option<AgentVmWorkspaceBootstrap>` to
`ClientMessage::RunAgent`. When `Some`, writd routes through the VM
lifecycle (the same machinery `StartAgentRun` drives at
`src/agent_vm_daemon.rs:608-682`), waits for the run to complete,
captures the output, signs the envelope, and returns
`RunAgentCompleted` exactly as today. When `None`, today's host
spawn path is preserved verbatim.

- **Pros**: Bailiff's workflow shape is unchanged
  (`client.run_agent(...).await` still yields the signed envelope).
  One RPC variant, one client method. The
  `bailiff_plan_implement.rs:249-264` block keeps its synchronous
  read of `completed.signed_metadata.session_id` and follow-on
  `write_implement_note`. The server can now refuse `RunAgent` that
  carries any `WorkspaceWrite` capability without a workspace
  bootstrap — making the illegal state (Write capability + no cwd)
  unrepresentable in practice.
- **Cons**: One RPC variant means two code paths inside the
  dispatch arm. The "host vs VM" decision is now interior, not
  surfaced at the wire level. A reader of `RunAgent`'s definition
  must trace the dispatch to see that `workspace.is_some()` flips
  the entire execution model.

### Option B — Bailiff sends `StartAgentRun`; add a synchronous "wait" RPC

Keep `RunAgent` host-only. Add a `WaitForAgentRun { run_id }` RPC
that blocks until the VM run completes and returns the equivalent
of `RunAgentCompleted`. Bailiff's implementer call site becomes
`start_agent_run` then `wait_for_agent_run`.

- **Pros**: Wire-level separation of host vs VM. Each RPC has one
  code path.
- **Cons**: Two RPCs to do one thing bailiff used to do with one.
  The "wait" RPC has to invent its own completion semantics
  (today's VM lifecycle writes an audit row on completion but
  doesn't surface a wire signal; we'd need a notification channel
  or a poll loop). Bailiff's workflow gains a state transition
  ("started, awaiting completion") that has to survive client
  reconnect to be useful — that's structural work the host
  synchronous shape doesn't need.

### Option C — Defer; reject `WorkspaceWrite` over `RunAgent` and call it

Just close the lie: server-side, reject `RunAgent` carrying
`WorkspaceWrite` with a clear error. Leave implement broken until
someone wires up A or B.

- **Pros**: Trivially small. Tightens the wire contract.
- **Cons**: Doesn't fix anything the user wants fixed. Reject this.

## Recommendation: Option A

Smaller protocol surface, no workflow-shape disturbance for bailiff,
and the rejection-of-`WorkspaceWrite`-without-workspace check comes
for free as a same-slice tightening. The interior branching
("host vs VM inside one dispatch arm") is a real cost but the
alternative (a new async completion model) is structurally bigger
work for the same operator-visible outcome.

The recommendation does not preclude B later. If we later want a
wire-level split — for example if the VM run grows to take long
enough that bailiff should reconnect rather than hold a TCP — the
"interior dispatch on `workspace.is_some()`" can be lifted to two
RPCs without changing the bailiff workflow shape: the inner
synchronous behaviour stays the same, only the wire framing
changes.

## What ships (Option A)

Four sub-slices. Each is a separate PR; they land in order. The
split is by layer so any one PR can be reviewed without the others
loaded:

1. **VM1** — Protocol surface only. Add `workspace:
   Option<AgentVmWorkspaceBootstrap>` to `ClientMessage::RunAgent`.
   Server-side: reject `RunAgent` carrying any `WorkspaceWrite`
   capability when `workspace.is_none()` (clear error). Reject
   `RunAgent` carrying `workspace.is_some()` with a placeholder
   "VM dispatch not yet implemented" error — the field decodes,
   the gate rejects. Pins the wire shape and the invariant.
2. **VM2** — Server-side VM dispatch. When `workspace.is_some()`,
   route through the VM lifecycle (same machinery
   `start_agent_run_session` uses at
   `src/agent_vm_daemon.rs:608-682`), wait for run completion,
   capture stdout/stderr/exit-code, build the same
   `OutputEnvelope` shape today's host path produces, sign, and
   return `RunAgentCompleted`. Reuses `capture_stream_capped` and
   the existing 4 MiB cap.
3. **VM3** — Bailiff plumbing. Add `workspace:
   AgentVmWorkspaceBootstrap` to `SubmitImplementInputs`; thread it
   through to `RunAgentRequest`. Bailiff CLI (`src/bin/bailiff.rs`)
   reads the workspace fields from bailiff's config TOML:
   `clone_url`, `destination` (optional), `warm` (`none` /
   `sources` / `devshell`). Existing host-path
   `RunAgent`-using workflows (`submit_plan`, `submit_review`)
   pass `workspace: None`.
4. **VM4** — End-to-end test. A `prove-bailiff-plan-implement.sh`
   shell script in `scripts/` along the lines of
   `prove-agent-vm-claude-proxy.sh`, using a synthetic agent
   wrapper that emits a deterministic commit on stdout (or runs a
   `git commit && git push` against the in-VM checkout). Pins
   that the full `bailiff plan submit → decide → implement` loop
   produces a staged push visible to `writ promote list`.

## Surface details

### Protocol change (VM1)

```rust
RunAgent {
    prompt: AgentPrompt,
    capabilities: Vec<CapabilitySet>,
    purpose: String,
    output_ref: NotesRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_id: Option<SessionId>,
    /// When present, writd runs the agent inside a per-run VM
    /// provisioned with a checkout per the bootstrap. The agent's
    /// cwd inside the VM is the checkout destination, so a
    /// `WorkspaceWrite` capability is meaningful. When absent,
    /// writd takes the host-spawn path (no cwd, suitable only for
    /// read-only or prompt-only agent runs).
    ///
    /// Required when any element of `capabilities` is
    /// `CapabilitySet::WorkspaceWrite { .. }`. The broker rejects
    /// a `WorkspaceWrite` request with no workspace bootstrap so
    /// the host path cannot mint write-capable runs against no
    /// checkout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workspace: Option<AgentVmWorkspaceBootstrap>,
}
```

The field is `Option<>` and `#[serde(default)]` so a legacy caller
parses unchanged. The `WorkspaceWrite`-without-`workspace`
rejection is the load-bearing invariant.

### Server-side enforcement (VM1 → VM2)

The check lives at the entry of the `RunAgent` dispatch arm
(`src/server.rs:325-331`), before any spawn or VM startup:

```rust
let needs_vm = capabilities.iter().any(|c|
    matches!(c, CapabilitySet::WorkspaceWrite { .. }));
match (needs_vm, workspace) {
    (true, None) => return ServerMessage::Error {
        message: "RunAgent: WorkspaceWrite capability requires a workspace bootstrap".into(),
    },
    (_, Some(ws)) => {
        // VM dispatch (VM2 wires this up; VM1 returns Error).
    }
    (false, None) => {
        // Existing host spawn (today's lines 1997-2104).
    }
}
```

Where the `Some(ws)` arm goes:

- VM1 returns `ServerMessage::Error { message: "RunAgent: VM dispatch not yet wired" }`.
- VM2 replaces the body with a call into the existing VM lifecycle
  machinery. The synchronous wrapper around the async run is the
  only new piece — write a wait helper in `agent_vm_daemon.rs` that
  takes a `run_id`, awaits the run's completion future (or polls
  the audit-row insertion), and returns the captured streams +
  exit code. Reuse `capture_stream_capped` for the 4 MiB cap.

### Bailiff config (VM3)

Bailiff's daemon TOML gains:

```toml
[implement_workspace]
clone_url = "https://github.com/org/repo.git"
destination = "/repo"  # optional; defaults to writd's choice
warm = "devshell"      # "none" | "sources" | "devshell"
```

`SubmitImplementInputs` gains `pub workspace: AgentVmWorkspaceBootstrap`.
The CLI binding in `src/bin/bailiff.rs` reads the config block and
builds the bootstrap.

### Timeouts

The implementer's VM run is potentially long (VM boot + repo clone
+ warm + agent run). The bailiff client timeout should match the
upper bound: `AGENT_VM_WORKSPACE_CALL_TIMEOUT = 30min` is the
existing constant for VM-bound workspace operations. Use it for
the implement-side `RunAgent` call. (The CLI-side flock from slice
E4c P2 means there's one implement in flight per process anyway,
so a 30-minute hold is acceptable.)

## What stays in scope

- Tests-first per Gospel: every layer-change ships its failing
  test, then the change.
- The same operator-visible CLI surface: `bailiff plan implement
  <plan-id>`. No new verbs.
- VM1's rejection invariant is property-tested at the protocol
  layer (cap-Write without workspace → Error).
- VM4's e2e script reuses `prove-agent-vm-claude-proxy.sh`'s
  general structure (writd boot, fake git origin, warm mode env
  var) but invokes bailiff at the top.

## What stays out of scope

- **`WorkspaceRead` on the host path.** `submit_plan` and
  `submit_review` keep using `RunAgent` with `workspace: None`.
  The semantics of "read capability without a checkout" are
  already in place (the read path is prompt-in / stdout-out; the
  agent doesn't actually need a working tree to be a "reader"
  in the current model). Reconsidering that is a separate
  conversation.
- **Per-run VM image variants.** This slice uses whatever VM
  image writd already builds for `StartAgentRun`. If implementer
  agents need a different toolchain than reviewer/planner agents,
  that's downstream.
- **A new "wait for run" RPC.** Recommendation Option A keeps the
  synchronous shape; Option B's wait RPC is deferred until/unless
  the synchronous hold becomes operationally untenable.
- **Bailiff-side notification of approve outcome.** The
  promote-approve slice flagged this gap (the bailiff implement
  note has no field for the App-side `new_app_tip`); this slice
  doesn't fix it either.
- **Cross-process VM coordination.** The bailiff CLI flock at
  `<bailiff_repo>/bailiff-implement.lock` already serialises
  cross-process bailiff invocations against the same on-disk
  repo. Cross-process coordination of *VM lifecycle* is writd's
  problem and is already handled by writd's session model.

## Plan of work

### VM1 — Protocol surface

- One PR. ~200 LoC across `src/protocol.rs`, `src/server.rs`,
  tests in `src/server.rs`'s `#[cfg(test)]` block.
- Tests first (all should compile-fail until the field exists):
  - `run_agent_decodes_with_workspace_field`
  - `run_agent_decodes_without_workspace_field_legacy_shape`
  - `run_agent_rejects_workspace_write_without_workspace_bootstrap`
  - `run_agent_with_workspace_returns_vm_not_yet_wired_error`
- Then add the field + the gate + the placeholder VM-rejected
  arm. Existing host-spawn path is untouched (the `(false, None)`
  arm is verbatim today's code).
- Gate suite, commit, PR, codex review.

### VM2 — Server-side VM dispatch

- One PR. ~400-600 LoC across `src/agent_vm_daemon.rs` (sync
  wait helper) and `src/server.rs` (the `(_, Some(ws))` arm).
- Tests first:
  - `run_agent_in_vm_returns_completed_envelope_with_captured_streams` —
    end-to-end through the in-process broker, with a stub
    agent-VM (the existing test fixtures support this; see
    `run_agent_round_trip_signs_and_writes_note` at
    `src/server.rs:2898-3011` for the host-path analogue).
  - `run_agent_in_vm_propagates_nonzero_exit_code` — exit code
    surfaces in the envelope, doesn't poison the signature.
  - `run_agent_in_vm_caps_stdout_at_max_run_agent_stream_bytes` —
    4 MiB cap honoured, truncation marker recorded.
- Then wire the sync wait helper + the dispatch arm.
- Gate suite, commit, PR, codex review.

### VM3 — Bailiff plumbing

- One PR. ~250 LoC across `src/bailiff_plan_implement.rs`,
  `src/bin/bailiff.rs`, `tests/bailiff_plan_implement_*.rs`.
- Tests first:
  - `submit_implement_passes_workspace_through_to_run_agent` —
    the `RunAgentRequest` writd receives carries the workspace
    bootstrap as supplied in `SubmitImplementInputs`.
  - `bailiff_plan_implement_cli_reads_workspace_from_config` —
    CLI parser test asserting the implement-workspace TOML
    block lands in the inputs.
- Then add the field on `SubmitImplementInputs`, thread through
  the call, update the CLI binding.
- Gate suite, commit, PR, codex review.

### VM4 — End-to-end shell test

- One PR. ~300 LoC, single shell script + minimal Rust if the
  fake-agent wrapper needs anything beyond `bash`.
- Test structure mirrors `prove-agent-vm-claude-proxy.sh`:
  fixture writd config, fake git origin, fake agent wrapper, run
  `bailiff plan submit` then `... decide` then `... implement`,
  assert `writ promote list` shows the staged push.

## Estimated total

VM1 ≈ 200 LoC, VM2 ≈ 400-600 LoC, VM3 ≈ 250 LoC, VM4 ≈ 300 LoC.
Combined ~1100-1300 LoC across four PRs over ~one to two weeks
elapsed.

## Risks and tradeoffs

- **VM2 is the load-bearing piece and the largest.** The
  synchronous wrapper around the async VM run is the only piece
  with no existing analogue. If the VM lifecycle's completion
  signal isn't ergonomic to await synchronously (e.g. it goes
  through audit-row insertion rather than a future), VM2 may
  grow a polling loop or need a new notification channel inside
  `agent_vm_daemon`. The plan assumes the future shape is
  achievable; if not, that's where re-scoping happens.
- **Two paths inside one RPC dispatch.** The "host vs VM" branch
  inside `RunAgent` is a real local-reasoning cost. The trade is
  bailiff's workflow shape staying simple; if the branch grows
  hair (different audit shapes, different timeout semantics,
  divergent error mappings), revisit Option B.
- **30-minute hold per implement.** The CLI-side flock means
  only one implement runs per bailiff process at a time, but
  the writd-side hold is a long-lived TCP. A writd restart
  during an implement run drops the connection. Bailiff has no
  resumption logic today; the operator re-runs `bailiff plan
  implement`. This is acceptable for a dogfood loop but should
  be revisited if implementer runs become longer or more common.
- **VM image content is writd's existing one.** If the
  implementer agent needs tools the current image doesn't have
  (specific git config, specific package, specific shell), this
  surfaces as a runtime failure in VM4. Plan ahead by reading
  what the existing image includes.

## Open questions

- **Can the VM lifecycle expose a synchronous completion future
  cleanly?** This is the VM2 risk. Quick answer needs a closer
  read of `agent_vm_daemon.rs:608-682` — out of scope for this
  plan, in scope for VM2's first test.
- **Should `WorkspaceRead` runs migrate to the VM too?** Not for
  this slice (out of scope above), but worth a follow-up
  conversation. The current asymmetry (Read on host, Write in
  VM) is defensible but inconsistent.
- **What's the right `clone_url` default?** Bailiff's TOML needs
  a value; this slice expects the operator to supply it
  explicitly. A future ergonomic might infer it from `git
  remote get-url origin` of bailiff's bare repo's remote, but
  that's a CLI nicety, not a protocol concern.
