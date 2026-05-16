# Slice D2 — `bailiff plan review`

Bailiff workflow verb that spawns a reviewer agent via `RunAgent`,
verifies the signed envelope writ produces, and records a
[`ReviewNote`] under the plan-scoped notes ref. The plan body the
reviewer reads is the planner's own stdout (signed by writ in slice
C), so D2 is also the first slice that reads back a previously-signed
envelope to compose a follow-up agent's prompt.

Companion to:
- `docs/plans/2026-05-14-bailiff-split.md` (parent split, §"Slice D")
- `docs/plans/2026-05-16-slice-d1-decide.md` (D1 — the operator-side
  `decide` verb that shipped first)

## Why D2 follows D1

D1 was strictly bailiff-local: no agent, no envelope verification, no
prompt composition — just an operator writing a verdict note. D2 adds
the second `RunAgent`-driven workflow alongside `submit_plan` and so
needs the same shape that slice C built (`bailiff_plan_submit.rs`):
open session, run agent, fetch+verify envelope, write note, close
session. Splitting D1 off let that operator-only path ship without
waiting for the review-flow design to settle; D2 is the agent-driven
counterpart.

## What D2 does

### Review-note shape

A bailiff-owned attestation that writ ran a reviewer agent for one
plan. Stored under the same per-plan ref
`refs/notes/bailiff/v1/plans/<plan-id>` as the submission and decision
notes, attached to a **third** deterministic seed OID so all three
coexist:

```rust
pub struct ReviewNote {
    pub plan_id: PlanId,
    pub purpose: String,
    pub writ_output_oid: GitObjectId,
    pub signed_metadata: SignedRunMetadata,
    pub signature: SshSignature,
}
```

Field-for-field identical to [`PlanNote`]. The reviewer's prose + any
structured verdict the agent emits live in the writ-signed envelope at
`writ_output_oid`; bailiff stores the attestation, slice F (read
paths) renders the prose to the operator. The bailiff side does not
parse the agent's stdout in D2 — that's a slice-F concern and the
shape we want is "writ signs the bytes, bailiff carries them, the
reader decodes them."

Seed-OID helper: `plan_review_seed_blob_bytes(plan_id) -> Vec<u8>`
returning `format!("{plan_id}::review").into_bytes()`. Distinct from
`plan_submission_seed_blob_bytes` (bare plan id) and
`plan_decision_seed_blob_bytes` (`::decision` suffix), so the three
notes attach to different objects under one ref.

### Single review per plan (idempotent)

One review note per plan. Re-running `bailiff plan review` against a
plan that already has a review is a typed error
(`ReviewAlreadyRecorded`), not a silent overwrite — mirrors D1.3's
`DecisionAlreadyRecorded` behaviour. "I want a second opinion" is "the
plan is dead, submit a new one" for v1; multi-review history is a
future `v2`-prefix bump (see "Extending later").

### Prompt composition

`bailiff plan review` composes the reviewer's effective prompt from
two pieces:

1. The operator-supplied **reviewer instructions** prompt (read from
   `--prompt-file`, the same shape `plan submit` uses).
2. The **plan body** — the planner agent's stdout from the submission
   note's signed envelope.

Composition is bailiff-internal: writ receives the composed prompt as
opaque bytes (it has to forward them to the reviewer agent's stdin)
but writ does not store, persist, or interpret them. This is the same
boundary `agent_run` prompts already respect today.

Concretely:

1. Read `PlanNote` for `plan_id` from
   `refs/notes/bailiff/v1/plans/<plan-id>`. Failure path: typed
   `PlanSubmissionMissing { plan_id }`.
2. Read the envelope note from
   `refs/notes/writ/v1/agent-outputs` at `plan_note.writ_output_oid`.
   Decode as `SignedRunEnvelope`. Verify under `allowed_signers`
   (same `verify_run_envelope` writ side already uses).
3. Decode `envelope.output` as an `OutputEnvelope`; extract
   `stdout` bytes; UTF-8 decode (planner output is human prose).
   Reject empty or non-UTF-8 with a typed error — the planner's
   stdout *is* the plan body, and a non-text plan body is a
   protocol violation.
4. Concatenate `reviewer_instructions` + separator + `plan_body`
   into a fresh `AgentPrompt` (boundary check on combined size).
   Separator constant lives next to `submit_review` so D2's
   reviewer framing doesn't collide with the implementer's framing
   (slice E will add the implementer separator and may lift both
   into a shared module then).

The composition logic mirrors the existing
[`crate::bailiff::compose_reviewer_prompt`] but takes raw plan-body
bytes (not an `agent_plan::PlanBody`) so we don't grow a fresh
dependency on the `agent_plan` types that slice G deletes. The
separator string matches `bailiff::REVIEWER_PROMPT_SEPARATOR`
verbatim — pre-slice-G we share the constant; post-slice-G the
constant moves to its new home.

### Capability set

The reviewer runs under a single `WorkspaceRead { repo }`. No new
`CapabilitySet` variant is needed: the slice-A doc-comment on
`CapabilitySet::WorkspaceRead` already says "Used for plan-stage and
review-stage agents under today's workflow vocabulary." The reviewer
must not write to the workspace; that's an implementer concern in
slice E.

### Workflow function `submit_review`

New module `src/bailiff_plan_review.rs` (sibling to
`src/bailiff_plan_submit.rs`). Same async function shape:

```rust
pub async fn submit_review(
    client: &WritClient,
    bailiff_repo: Arc<AsyncMutex<NotesRepo>>,
    writ_repo_path: &Path,
    allowed_signers: AllowedSigners,
    inputs: SubmitReviewInputs,
) -> Result<SubmitReviewOutcome, SubmitReviewError>;
```

`SubmitReviewInputs` mirrors `SubmitPlanInputs` plus:
- `plan_id` — already-existing plan (no `Option`; bailiff cannot
  invent the id this time).
- `reviewer_instructions: AgentPrompt` — operator-supplied prompt.
  The composed prompt is built inside `submit_review` and never
  surfaces in the input struct.

Error matrix mirrors `SubmitPlanError` plus three new tagged failures:
- `PlanSubmissionMissing { plan_id }` — bailiff was asked to review a
  plan it has no submission note for; pre-RPC, no cleanup needed.
- `ReadPlanEnvelope { source }` — fetching or decoding the planner's
  envelope failed; pre-RPC.
- `ComposeReviewerPrompt { source }` — the composed prompt overran
  the `AgentPrompt` byte limit; pre-RPC.

Post-RPC failures (`OpenSession`, `RunAgent`, `SessionIdMismatch`,
`WriteReviewNote`, `WriteTaskFailed`, `CloseSession`) follow the
identical close-on-error contract `submit_plan` already has.

### CLI verb

```
bailiff plan review \
    --plan-id <uuid> \
    --prompt-file <path> \
    --repo <owner/name> \
    --writ-allowed-signers <path> \
    [--purpose <string>]      (default: "plan-review")
    [--label <string>]
    [--agent <kind>]          (default: claude)
    [--model <string>]
    [--bailiff-repo <path>]
    [--writ-repo <path>]
```

Mirrors `bailiff plan submit` minus `--plan-id` (which becomes
required, not auto-allocated) and plus nothing else. Prints the
review note's bailiff-side OID on success; non-zero exit + stderr
message on any typed failure.

## What D2 does **not** do

- **Parse a structured verdict out of the reviewer's stdout.** The
  reviewer agent's output is signed prose; D2 stores the attestation,
  slice F renders it. A future `verdict` field on `ReviewNote` is a
  schema bump (v1 → v2 ref prefix) — defer until we have a real
  consumer.
- **Gate `bailiff plan decide` on review presence.** D1.3 deliberately
  decoupled decide from submission; we don't re-couple it here.
  Operator can decide a plan before or after review; the read-side
  in slice F can flag "decided without review" if useful.
- **Multi-review history.** Idempotent only, same as D1. See
  "Extending later."
- **Implementer-side composition.** Slice E owns that; D2 only
  composes the reviewer's prompt.
- **Bailiff signing its own review notes.** Per the parent split
  doc's deferred list: writ's submission signature on the embedded
  envelope is the trust anchor for the run; bailiff-owned notes are
  unsigned in v1.

## Extending later

Two foreseeable extensions, both cheap:

1. **Multi-review history.** Switch from a single `<plan_id>::review`
   seed to per-review UUIDs, scan-and-sort on read. Same `v1` → `v2`
   ref-prefix bump migration path D1 documented; the
   `read_review_note` signature stays single-valued only in its v1
   shape.
2. **Structured verdict extraction.** Bailiff parses an `approve` /
   `request_changes` / `reject` tag out of the reviewer's stdout and
   surfaces it on `ReviewNote`. Either a schema bump (verdict becomes
   required) or a sibling `verdict()` getter that runs at read time.

The shape we ship in D2 forecloses neither.

## Risks and tradeoffs

- **Plan-body extraction is the first read-back-and-verify of writ's
  envelopes inside a workflow.** Slice C wrote the envelope; D2 is
  the first time bailiff reads one back and acts on the contents.
  The verify path is the same `verify_run_envelope` writ uses, so
  the failure modes are pinned, but the *unpack* layer
  (`SignedRunEnvelope` → `OutputEnvelope` → UTF-8 stdout) is new
  call-site code with new typed failures.
- **Reviewer composition lives next to `submit_review` rather than
  in the existing `src/bailiff.rs` module.** The existing module
  takes `agent_plan::PlanBody`, which slice G deletes; rather than
  thread a temporary `PlanBody::try_new` shim through bailiff just
  to delete it again in slice G, D2's composition takes raw bytes
  and re-asserts the same byte cap on the combined prompt. The
  separator constant is the only thing we share; that's a pure
  `&'static str` whose lift to a shared module in slice E (or G)
  is mechanical.
- **`ReviewNote` is a verbatim duplicate of `PlanNote`'s field set.**
  Tempting to unify them under a shared `SignedAgentRunNote` struct.
  Resisted for D2: the two notes have *different* semantic roles
  even though their fields coincide today, and a future schema bump
  on either side (e.g. `ReviewNote.verdict`) breaks the unification.
  Locality wins over de-duplication here — the cost of two parallel
  structs is one screen of code; the cost of unifying then later
  un-unifying is a wire-level migration.
- **Bailiff repo handle is not held across operations.** Same shape
  as D1 / slice C — each `submit_review` invocation locks the repo
  via `AsyncMutex<NotesRepo>` for the duration of its blocking
  section, drops it after.

## Plan of work

1. **D2.1 — `ReviewNote` primitive + seed-OID helper** in
   `src/bailiff_plan_note.rs` (alongside `PlanNote` and
   `DecisionNote`). Add `ReviewNote` struct with
   `deny_unknown_fields`, canonical-bytes + parse round-trip, and
   `plan_review_seed_blob_bytes(plan_id)`. Tests: round-trip on a
   sample note, seed bytes uniqueness vs submission/decision seeds,
   schema lock on field names/order.
2. **D2.2 — write helper `write_review_note`** in
   `src/bailiff_plan_write.rs` (sibling to `write_plan_note`). Same
   fetch-verify-attach shape: read the writ envelope, verify
   `metadata`/`signature` match what `RunAgentCompleted` returned,
   run it through `verify_run_envelope`, then attach a `ReviewNote`
   under `plan_review_seed_blob_bytes(plan_id)`. Idempotent-by-error:
   `ReviewAlreadyRecorded { plan_id, existing_oid }` rather than
   overwriting. Integration tests against a real bare repo
   (mirror `write_plan_note`'s suite).
3. **D2.3 — read helper `read_review_note`** in
   `src/bailiff_plan_read.rs` (sibling to `read_decision_note`).
   Returns `Result<Option<ReviewNote>, ReadReviewError>` where the
   error variants include `PlanIdMismatch` (same defence-in-depth
   guard D1.4 ships for decisions). Tests: write-then-read
   round-trip, missing returns `None`, planted-foreign-plan-id
   surfaces `PlanIdMismatch`.
4. **D2.4 — workflow function `submit_review`** in a new
   `src/bailiff_plan_review.rs` (mirror of
   `src/bailiff_plan_submit.rs`). Inputs/outcome/error shapes
   described above. End-to-end tests against a live broker (mirror
   `submit_plan_round_trips_through_open_run_write_close` and the
   write-failure / session-mismatch tests). Pre-RPC failure path
   (`PlanSubmissionMissing`) tested without involving the broker.
5. **D2.5 — CLI verb `bailiff plan review`** in `src/bin/bailiff.rs`.
   New `PlanCmd::Review` variant; new `plan_review` async function
   that wires the CLI inputs to `submit_review`. Clap parse tests
   for the flag matrix (required vs default flags, plan-id parse
   errors).

Each step is independently revertable. Steps 1–3 are pure library
(no network, no broker). Step 4 introduces the workflow function but
is callable from a test harness. Step 5 wires it to the binary.

## Out of scope

- Anything writ-side. D2 does not change `BrokerState`, the wire
  protocol, or `policy::*`. `WorkspaceRead` is already a
  recognised capability.
- `bailiff plan implement` (slice E).
- `bailiff plan show` / `list` (slice F).
- Bailiff signing its own review notes (deferred per parent plan).
- Structured verdict extraction (deferred; see "Extending later").
- Multi-review history (deferred; same).
