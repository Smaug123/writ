# Bailiff split — design

Plan for splitting writ into two daemons:

- **writ** — capability broker + agent spawner + audit. Mints credentials,
  spawns agents on someone's behalf, signs their output, records the
  resulting facts. Knows nothing about plan/review/decide.
- **bailiff** — workflow orchestrator. Drives a plan/review/execute
  lifecycle, stores the artefacts (plan body, originating prompts,
  reviewer feedback, decisions, aborts) as Git notes in its own bare
  repo, and owns the operator-facing CLI verbs for that workflow.

The two talk over a Unix socket: bailiff is the only client of a new
`writ run-agent` RPC; writ writes the signed agent output as a Git
object into bailiff's repo, and bailiff decides what to do with it.

Companion to [`docs/design/broker.md`](../design/broker.md) and
[`docs/plans/2026-05-11-agent-plans.md`](./2026-05-11-agent-plans.md).
Supersedes the earlier in-place version of this doc, which proposed a
more conservative "lift composition out into a module" split; slices 1
and 2 of that earlier plan have shipped (the composition + fetch
helpers live in `src/bailiff.rs`) and form the in-tree precursor to the
new bailiff binary.

Pre-v1 prototype, so wire-format compat and DB migration are not
constraints: anything currently in the audit DB can be deleted, and
the wire protocol can be reshaped freely.

## Why this shape

The earlier plan kept the workflow vocabulary inside writ: the
`Stage::Plan|Review|Execute` enum on `agent_run`, the `read_plan_id`
gate, the `/v1/plans/*` HTTP routes, the audit tables
(`plan`/`plan_decision`/`plan_review`/`plan_addendum`/`plan_abort`),
and the `writ plan *` CLI subcommands. Two pressures push for going
further:

1. **The originating-prompt slice doesn't fit.** Step 3 of the earlier
   plan required exposing the planner run's prompt over `GET
   /v1/plans/<id>`. The schema only stores `prompt_bytes` +
   `prompt_sha256` + the literal string `"<redacted>"`
   (`src/audit/migrations/0001_initial.sql` and
   `src/agent_run.rs::summary`); the prompt text is never persisted,
   per the explicit "prompts should not be embedded in audit rows"
   principle in `src/agent_run.rs:1`. To fulfil that slice, the broker
   would have to either (a) accept prompt text into audit rows
   (violating its own principle) or (b) introduce a content store
   outside audit. The right answer is (b), which the earlier plan
   never quite committed to.

2. **`Stage` and `read_plan_id` are workflow knowledge inside the
   broker.** The earlier plan deferred removing them as "v2 concern."
   Pre-v1 with no second consumer, the cheaper path is to remove them
   now while the cost is small.

The new plan does both at once: storage moves to bailiff's repo (Git
notes), workflow vocabulary leaves writ entirely.

## Conceptual model

### What writ does (and *only* does)

- **Sessions and credential grants.** Existing. Per-session per-route
  minting, audited.
- **Agent runs.** Spawn an agent with a prompt and a set of
  capabilities, capture stdout/stderr into a canonical envelope
  blob, sign the envelope hash + metadata, write the envelope as a
  Git object into bailiff's repo. Audit (run_id, prompt_sha256,
  capabilities, output_envelope_sha256, signature, exit_code) —
  `capabilities` is the same canonical collection writ accepted on
  the wire, so a multi-capability run records every granted variant,
  not a single composite.
- **Signing.** Writ holds an SSH signing key. Every terminal output
  gets a detached signature over the canonical bytes of
  `SignedRunMetadata { run_id, prompt_sha256, output_envelope_sha256,
  capabilities, exit_code, completed_at, session_id,
  signing_key_fingerprint }` — exactly the things writ observed
  first-hand, plus its own key identity. Including `prompt_sha256`
  is what binds the signed output to its originating prompt: a third
  party verifying the note can re-hash bailiff's plan note and
  confirm it matches the prompt writ saw, ruling out "valid signature
  + swapped prompt" forgeries. The signature is what bailiff (and any
  third party) uses to attest "writ confirms this output came from
  run R driven by prompt P under capabilities C at time T."

Writ knows nothing about the words "plan", "review", "decide",
"execute". The `Stage` enum and `read_plan_id` column are gone.

### What bailiff does

- **Owns a bare Git repo** (host-side, separate from any workspace
  repo). Path is config-driven.
- **Drives the lifecycle.** `bailiff plan submit/show/list/decide/abort`.
  The verb surface that today lives on writ moves wholesale.
- **Stores artefacts as Git notes.** Plan submissions, originating
  prompts, reviewer feedback, decisions, aborts. Each stored under a
  per-purpose notes ref. Concrete ref scheme is an implementation
  detail; a reasonable starting point is
  `refs/notes/writ/agent-outputs` (writ-owned writes, keyed by a
  per-run identifier blob) feeding into bailiff-owned curation refs
  (`refs/notes/bailiff/plans/...`, etc.).
- **Owns the read gate** that today is
  `route_permitted_by_stage_and_decision`. Composition of an
  implementer's effective prompt happens iff bailiff's own lifecycle
  state says the plan is accepted. Writ is not involved in that
  decision — bailiff simply does or doesn't compose the plan body
  into the next agent's prompt.
- **Mid-run agent coordination.** When an agent wants to pause for
  human help, that's bailiff's concern: bailiff knows what the agent
  is working on. Writ launched the agent; writ doesn't care how
  bailiff communicates with it mid-run.

### The wire interface

Single transport: Unix socket (matches what writ already serves). New
RPC, shape sketched (final field set decided in implementation):

```
ClientMessage::RunAgent {
    prompt: AgentPrompt,
    capabilities: Vec<CapabilitySet>,
    purpose: String,        // opaque to writ; recorded as-is in audit
    output_ref: GitRef,     // where in bailiff's repo to write the
                            // signed output note
}

ServerMessage::RunAgentCompleted {
    run_id,
    output_oid,                 // OID of the output envelope blob writ
                                // wrote into bailiff's repo
    signed_metadata: SignedRunMetadata {
        run_id,
        prompt_sha256,
        output_envelope_sha256, // matches the blob at `output_oid`
        capabilities,           // canonical serialisation of the granted Vec
        exit_code,
        completed_at,
        session_id,
        signing_key_fingerprint, // SSH key fingerprint identifying writ's
                                 // signer; bailiff's keyring resolves it
    },
    signature,                  // detached SSH signature over the
                                // canonical bytes of signed_metadata
}
```

The output envelope is a single blob covering both streams (one
canonical container framing `{stdout_bytes, stderr_bytes,
stdout_truncated_at, stderr_truncated_at}`). Signing the envelope
hash rather than stdout alone means stderr — which carries
meaningful diagnostics, especially for non-zero exit codes — can't
be silently lost or altered after the fact. The blob writ writes
into bailiff's repo *is* the envelope; bailiff's reader splits it
back into per-stream bytes for display.

The `SignedRunMetadata` payload is exactly what writ hashed and
signed; returning it in full (rather than just the signature) is
what lets bailiff or any third-party reader re-canonicalise the
bytes and verify the signature. The note stored in bailiff's repo
contains the same `(signed_metadata, signature)` pair alongside the
output blob, so verification is self-contained from a clone of
bailiff's repo *plus* its keyring: `signing_key_fingerprint`
identifies which writ-side key produced the signature, and bailiff
resolves the fingerprint to a public key via a config-driven SSH
allowed-signers file (the same trust-anchor shape Git itself uses
for commit-signature verification). Bailiff refuses to ingest a
note whose fingerprint isn't in the keyring.

`RunAgent` is request/response over the existing one-shot dispatch
path: writ spawns the agent, waits for it to terminate, builds the
output envelope from stdout + stderr, hashes it, signs the metadata,
writes the envelope as a blob and the signed metadata + signature
as a note in bailiff's repo at the requested ref, and returns a
single `RunAgentCompleted`. The audit row records the same canonical
metadata + signature. No separate "started" frame: there is nothing
for bailiff to do mid-run on the writ wire (mid-run agent
coordination goes through bailiff's own channels — see below).

Pre-v1: whole-artefact-at-end. No streaming. If the agent crashes
with partial output, writ still writes whatever was captured and
signs the partial; the audit row records the non-zero exit code.

Keeping `RunAgent` synchronous on the wire keeps slice A small: the
existing `dispatch_message` loop in `src/server.rs` returns one
`ServerMessage` per request, and slice B fits that shape without
having to refactor the connection handler. A future "started + later
completed" split (needed for cancellation while a run is in flight,
or for streaming) is an explicit non-goal here.

### Capability sets

Sum type, serialised over the wire. Replaces the implicit `Stage`
enum + per-stage policy matrix. Closed enum for v1; broaden later if
a second workflow needs it.

Sketch (variants and field shape decided in implementation):

```
enum CapabilitySet {
    /// Read-only access to a workspace repo. Plan and review agents.
    WorkspaceRead { repo, ref_pattern },
    /// Read + branch-write under staging review. Implementer agents.
    WorkspaceWrite { repo, base, target_branch },
    /// GitHub API access scoped to a single repo + scope.
    GithubScoped { repo, scope },
}
```

A run may be granted a set of these — hence the `Vec<CapabilitySet>`
in the request — so that, e.g., an implementer can hold both
`WorkspaceWrite` and `GithubScoped` simultaneously without bailiff
having to pick a single composite variant. Writ enforces each
granted capability through the existing `policy::*` matrix —
`policy` stays inside writ as the authorisation oracle, just keyed
on capability-set variants instead of stage. Bailiff decides which
set is appropriate for each workflow position.

### What stays in writ but changes shape

- `policy::*` stays; per-stage logic becomes per-capability-variant
  logic.
- `agent_run` audit row keeps most columns. `stage` and
  `read_plan_id` drop. `capabilities` (canonical serialisation of
  the granted `Vec<CapabilitySet>`) and `signature` are added —
  storing the full collection, not just one variant, so policy
  replay and provenance checks for a multi-capability run see every
  authority that produced the signed output.
- VM HTTP layer (`vm_http/*`) keeps its credential-issuance and
  replay routes. Loses `/v1/plans/*`.

### What leaves writ entirely

- `agent_plan.rs` and all its types (`Stage`, `PlanBody`, `PlanId`,
  `PlanView`, `Decider`, `DecisionView`, `DecisionOutcome`,
  `route_permitted_by_stage_and_decision`).
- `bailiff.rs` (the in-tree module) — its composition functions move
  into the bailiff binary.
- All `plan*` audit tables/migrations.
- `vm_http/plan.rs`.
- The decide/abort/review handlers in `server.rs`.
- `writ plan *` CLI verbs.

## Phased plan

Each slice is independently revertable; the whole sequence is a
meaningful rewrite of several files. Pre-v1, the destructive slice
(G) is free.

### Slice A — wire protocol skeleton

Define `RunAgent` / `RunAgentCompleted` in `protocol.rs` (single
synchronous request/response — no `RunAgentStarted` frame, see the
wire-interface section above). Stub `CapabilitySet` sum type with
one or two variants. Add a bailiff binary skeleton
(`src/bin/bailiff.rs`) that connects to writ over the Unix socket
and exposes no commands yet. No behaviour change to existing flows.

### Slice B — bailiff repo, writ signing

Bailiff: config path for its bare repo; init on first run; helpers to
write notes whose body **is** the signed envelope. Writ: SSH signing
key in `SecretStore`. A round-trip test where bailiff sends `RunAgent
{ prompt: "noop", capability_set: minimal, purpose: "test",
output_ref: ... }`, writ runs a no-op child, writes a signed note to
bailiff's repo, and bailiff verifies the signature.

**Design decisions pinned 2026-05-15** (after PR #102 was abandoned as
over-engineered):

- *Durability — note body carries the envelope.* The envelope bytes go
  into the note body, not into a separate `git hash-object`-written
  blob. `git clone` and `git fetch` are reachability-based, so a loose
  blob named only by OID inside a note body would be missing from
  remote clones and would be eligible for `git gc --prune`. Putting the
  envelope in the note body makes the bytes reachable via the notes
  ref, which the verification story already requires. The notes
  attachment object is a per-run seed blob whose only role is to be an
  OID the note can be keyed on; it carries no payload.
- *Namespace versioning.* Notes refs encode a version inside the
  owner namespace: `refs/notes/writ/v1/agent-outputs`,
  `refs/notes/bailiff/v1/plans/<plan-id>`, etc. Bumping `writ/v1` →
  `writ/v2` is independent of bumping `bailiff/v1` → `bailiff/v2`.
- *Threat model.* Bailiff **owns** its bare repo and is the sole
  writer (via writ through `BailiffRepo`). Validation defends against
  operator error and corruption, not against an attacker who can write
  to bailiff's filesystem. A compromised host can also forge the
  signing key, so adversarial-repo validation buys nothing on top.
  `BailiffRepo::open` therefore checks: HEAD present, `core.bare=true`
  (via `git config --bool --get` — last-wins handling falls out for
  free), `objects/` and `refs/` exist as directories, `commondir`
  absent (`symlink_metadata`), `extensions.objectformat` unset or
  `sha1` (via `git config --get`), and a process-wide notes-write
  mutex keyed on the canonical path (the only race-correctness check
  that's actually load-bearing — concurrent `git notes add` against
  the same ref silently loses notes, empirically verified).

### Slice C — plan submission via the new shape

`bailiff plan submit` (CLI verb in the bailiff binary). Asks writ to
run-agent with the planner's prompt + a plan-stage capability set; on
completion, writes a plan note in bailiff's plan-notes namespace.
Writ now spawns planner agents through `RunAgent`. The old
`/v1/plans` submission endpoint can stay live during this slice; the
new path is exercised end-to-end alongside it.

### Slice D — review and decide

`bailiff plan decide accept|reject` writes a decision note. `bailiff
plan review` spawns a reviewer agent through `RunAgent` with a
review-stage capability set and the plan body composed into the
prompt. Composition is bailiff-internal: writ still receives the
composed prompt bytes (it has to, in order to forward them to the
agent's stdin) but writ does not store, persist, or interpret them.
The boundary writ enforces is "bytes in transit, not artefacts": the
plan body never lands in writ's audit DB, never appears in writ's
storage, never gates writ's behaviour. That's the same shape writ
already gives `agent_run` prompts today.

### Slice E — implementer through new shape

`bailiff plan implement` (verb name TBD). Spawns an implementer agent
through `RunAgent` with an execute-stage capability set, composing
the accepted plan + originating prompt into the implementer's prompt.
The "is the plan accepted?" gate lives in bailiff's read-side: refuse
to compose unless bailiff's own decision note says accepted.

### Slice F — read paths

`bailiff plan show/list` — read notes out of bailiff's repo, verify
writ's signatures, return to the operator.

### Slice G — strip writ

Destructive. Delete plan endpoints, CLI verbs, audit tables, and
types from writ. Drop `Stage` and `read_plan_id` from `agent_run`.
Delete `agent_plan.rs` and the in-tree `bailiff` module. Pre-v1, we
just bulk-drop the audit DB.

### Slice H — docs

Rewrite `docs/design/broker.md` to no longer mention plans. Add
`docs/design/bailiff.md` as the orchestrator counterpart. Split the
CLI reference.

## What we explicitly defer

- **Streaming output from a running agent.** Whole-artefact-at-end is
  enough for v1. If an agent wants to pause for human help mid-run,
  bailiff handles that out-of-band (e.g. bailiff writes coordination
  notes and the agent polls them); writ isn't involved.
- **Bailiff-side signing of decisions.** Bailiff *could* sign its own
  attestation notes; for v1, unsigned bailiff-owned notes are fine.
  Writ's signed agent-run outputs are the trust anchor.
- **Multi-tenant bailiff.** One bailiff process, one repo.
- **A second workflow type.** Plans are the only workflow bailiff
  knows. The capability-set sum type is shaped to let a second
  workflow drop in without changing the writ interface.
- **Wire-format versioning.** Pre-v1; reshape freely.

## Risks and tradeoffs

- **Two daemons instead of one.** That's the point — the boundary
  stops being "discipline" and starts being a wire protocol. The
  operational surface doubles. Mitigation: well-known paths for
  bailiff's repo and writ's socket; bailiff launches writ if it
  isn't already up (or fails fast and tells the operator to start
  it).
- **Signing key management.** Writ now holds a long-lived signing key
  alongside short-lived credentials. Same `SecretStore` abstraction
  the GitHub App key uses applies.
- **Trust-anchor distribution.** Bailiff verifying a signed note
  requires knowing which SSH public key(s) are allowed to sign on
  writ's behalf. Bootstrap is "writ prints its key fingerprint on
  first run; operator adds it to bailiff's allowed-signers file."
  Single-host pre-v1; documenting a key-rotation flow is deferred.
- **Bailiff's repo accumulates plan refs.** Same problem any
  append-only Git data store has. GC/rotation deferred.
- **In-flight slice 3 (originating_prompt on `PlanView`) is dropped.**
  No code in main depends on it; the new shape gives bailiff
  first-class access to the originating prompt as a note, so the
  exposure becomes moot.

## Open questions

1. **Session model.** Today a session represents "a thing the user is
   doing" (a panel, a feature). With bailiff orchestrating, a session
   becomes a unit of bailiff workflow containing many writ agent
   runs. Concretely: bailiff opens one writ session per plan
   workflow; every agent run for that plan happens inside that
   session. Confirm during slice C.

2. **Exact ref scheme inside bailiff's repo.** Probably
   `refs/notes/writ/agent-outputs` for writ-written notes (keyed by a
   per-run identifier blob), with bailiff-owned curation refs
   (`refs/notes/bailiff/plans/<plan-id>`, etc.) pointing into them.
   Pin during slice B.

3. **Crash semantics.** If the agent dies mid-run, writ still writes
   whatever was captured + exit code; bailiff decides whether to keep
   the note. Probably right but worth pinning during slice B.
