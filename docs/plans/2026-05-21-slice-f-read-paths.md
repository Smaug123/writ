# Slice F — read paths

Drafted 2026-05-21. Implements slice F of
`docs/plans/2026-05-14-bailiff-split.md`: `bailiff plan show / list`
read notes out of bailiff's repo, verify writ's signatures on
referenced run envelopes, and render to the operator.

## What ships

Two CLI verbs:

- `bailiff plan list` — enumerate every plan-id in bailiff's repo,
  one row per plan, showing purpose + workflow state (submitted /
  reviewed / accepted / rejected / implemented) + the four
  timestamps. **No signature verification at the list level.**
  Rationale: list is a summary; an unverified row is not a trust
  claim, just metadata. Per-plan verify happens at `show`.
- `bailiff plan show <plan-id>` — render every available note
  (plan / decision / review / implement), and for every
  `writ_output_oid` referenced verify the SSHSIG against
  `--writ-allowed-signers`. The view reports each signature as
  verified-or-failed.

## What stays in scope

- Read-only. Neither verb touches writ over the socket.
- Operates on bailiff's bare repo + the local copy of writ's
  notes (already fetched at submission / review / implement time).
  No new fetches.
- Pure-library helpers in `bailiff_plan_read` so a future
  agent-facing read API can reuse them without going through clap.
- All output to stdout in a fixed human-friendly format. No JSON
  flag; no `--format`. YAGNI — add when an integrator asks.

## What stays out of scope

- **`bailiff plan abort`.** Already deferred from D1; not part of F.
- **Pagination / filters.** No `--state` / `--decider` / `--since`.
  The current cohort of plan-ids fits in one screen for any
  realistic operator workflow; revisit when N gets large.
- **Refetch from writ.** If a writ note has been added since the
  submission's `fetch_from_remote`, this slice will not see it.
  That's an operator concern (run the relevant `submit*` verb to
  bring it across) and not what `show` is for.
- **Signing bailiff-owned notes.** Same deferral as D1/E.
- **Stream-of-truth verification.** `show` verifies what's present.
  It does NOT attempt to detect "the plan exists but the planner
  envelope is missing from writ's local copy" as a distinct error
  state — that surfaces naturally as a `WritEnvelopeMissing`
  variant on each per-section verification result.

## Existing surface this composes

- `NotesRepo::read_note_at_seed` — already used by every
  `read_*_note` helper.
- `bailiff_plan_read::{read_plan_note, read_decision_note,
  read_review_note, read_implement_note}` — already exist; return
  decoded note bodies. No signature verify (correctly).
- `run_verify::verify_run_envelope` — pure verifier, given a
  `SignedRunEnvelope` and an `AllowedSigners`.
- `bailiff_plan_note::plan_notes_ref(plan_id)` and the four seed
  helpers — pin the canonical paths.

Missing surface this slice adds:

1. **`NotesRepo::list_refs_under_prefix`** — wrap
   `git for-each-ref refs/notes/bailiff/v1/plans/`. Returns
   `Vec<NotesRef>`. The clean-git env scaffolding already lives in
   the module; this is one more command builder.
2. **`bailiff_plan_read::list_plan_ids`** — call (1), strip the
   `refs/notes/bailiff/v1/plans/` prefix, parse each tail as a
   `PlanId`. Returns `Vec<PlanId>`. A non-parseable tail is a hard
   error (semantic corruption — bailiff is the only writer to that
   ref namespace).
3. **`bailiff_plan_read::read_writ_envelope_at_oid`** — given a
   writ-output OID and a bailiff `NotesRepo`, look up the writ
   note at `refs/notes/writ/v1/agent-outputs` with that OID as the
   target, decode the body as `SignedRunEnvelope`. Returns
   `Option<SignedRunEnvelope>` for the not-yet-fetched case. Used
   internally by `read_full_plan`; not surfaced on the CLI.

## Plan of work

### F1 — list-refs primitive

Add `NotesRepo::list_refs_under_prefix(prefix: &str) ->
Result<Vec<NotesRef>, NotesRepoError>`. Invokes `git for-each-ref
--format=%(refname) <prefix>`. Tests:

- Empty repo → empty vec.
- Write three notes under three plan-id refs → vec has three
  entries, all under the prefix, lexicographically sorted (so
  `list` output is stable).
- Prefix that matches no refs → empty vec, not an error.
- Inject a malformed-from-the-outside ref name → surfaces as
  `NotesRepoError` (we never produce one ourselves; pin behaviour
  for the operator-corruption case).

~80 LoC including tests. Single PR.

### F2 — list_plan_ids helper + `bailiff plan list` CLI

Add `bailiff_plan_read::list_plan_ids(bailiff_repo: &NotesRepo) ->
Result<Vec<PlanId>, ListPlanIdsError>`. Calls F1 with the
documented prefix, strips, parses each tail as `PlanId`.
`ListPlanIdsError::Read | ListPlanIdsError::ParseRef`.

Add `bailiff_plan_read::summarize_plan(repo, plan_id) ->
Result<PlanSummary, SummarizePlanError>` returning:

```rust
struct PlanSummary {
    plan_id: PlanId,
    purpose: String,
    submitted_at: UnixMillis,    // from signed_metadata.completed_at
    decision: Option<DecisionSummary>,
    reviewed: bool,
    implemented_at: Option<UnixMillis>,
}
```

`DecisionSummary { outcome, decider, decided_at }` — small
projection of `DecisionNote`. `submitted_at` comes from the writ
envelope's metadata, but we lift it from `PlanNote.signed_metadata`
directly (no envelope lookup required) so list is one repo-pass.

CLI verb wires F2 to clap: `bailiff plan list`. No flags. Output
is a fixed columnar table (the formatter lives in
`lib::cli::output` next to its siblings). Tests cover:

- Empty repo → "no plans" message, exit 0.
- Mixed states (submitted / decided-accept / decided-reject /
  reviewed / implemented) → expected ordering + state column.

~250 LoC across helper + CLI + tests. Single PR.

### F3 — read_writ_envelope_at_oid + read_full_plan pure helpers

Add `bailiff_plan_read::read_writ_envelope_at_oid(repo, oid) ->
Result<Option<SignedRunEnvelope>, ReadWritEnvelopeError>` reading
`refs/notes/writ/v1/agent-outputs` at the supplied OID.

Add `bailiff_plan_read::read_full_plan(repo, plan_id,
allowed_signers) -> Result<PlanFullView, ReadFullPlanError>`
composing the four `read_*_note` helpers and, for every available
note carrying a `writ_output_oid`, calling
`read_writ_envelope_at_oid` and `verify_run_envelope`.

```rust
struct PlanFullView {
    plan_id: PlanId,
    plan: VerifiedSection<PlanNote>,
    decision: Option<DecisionNote>,    // bailiff-owned, unsigned
    review: Option<VerifiedSection<ReviewNote>>,
    implement: Option<VerifiedSection<ImplementNote>>,
}

enum VerifiedSection<T> {
    Verified { note: T },
    WritEnvelopeMissing { note: T },
    SignatureFailure { note: T, error: VerifyError },
}
```

The reason for surfacing the failure variants rather than
`Result<T, ...>` is that `show` wants to print every available
section even when one fails to verify — turning a single
verification failure into a hard `Err` would suppress the rest of
the plan history, which is exactly when an operator most needs to
see it.

Tests:

- Happy path: write a plan + decision + review + implement → all
  four sections come back `Verified`.
- Missing writ envelope (delete the corresponding writ note before
  reading) → `WritEnvelopeMissing`, other sections unaffected.
- Tampered writ envelope (mutate the metadata bytes in-place) →
  `SignatureFailure` with the underlying `VerifyError`.

~200 LoC including tests. Single PR.

### F4 — `bailiff plan show` CLI

CLI verb wires F3 to clap: `bailiff plan show --plan-id <id>
--writ-allowed-signers <path>`. Output is a fixed multi-section
text format (formatter in `lib::cli::output`). Sections render in
order — Plan / Decision / Review / Implement — each headed by its
verification status. Missing-because-not-yet-written sections are
omitted; missing-because-not-fetched and signature-failure
sections render with the failure noted explicitly.

Tests: identical fixture sweep to F3 (happy / missing envelope /
signature failure) at the binary boundary, asserting the rendered
text shape per case.

~200 LoC across CLI + formatter + tests. Single PR.

## Estimated total

~700 LoC across four PRs (F1–F4). Each is independently
revertible. F1 and F2 are pure additions to `NotesRepo` and
`bailiff_plan_read`; F3 is a new composition over existing
helpers; F4 is the user-visible verb plus a formatter.

## Risks and tradeoffs

- **`for-each-ref` lexicographic order is stable but operator-
  invisible.** Operators may expect "most-recent-first" sorting.
  Defer until someone asks; the column for `submitted_at` makes
  it trivially sortable by other tools (e.g. piped through
  `sort`). Adding an in-binary sort flag is a follow-up slice.
- **`list` reads N×2 notes (plan + decision) at startup.** For
  current N this is fine; if it becomes hot, the optimisation is
  to drop the decision read and surface "decided yes/no" from a
  separate index. Out of scope for F.
- **`read_writ_envelope_at_oid` is the first place bailiff reads
  *its own local copy* of writ's notes outside a workflow verb.**
  This is structurally fine — bailiff is the sole writer to its
  repo, including writes triggered by `fetch_from_remote` — but
  pinning the read-side path in `bailiff_plan_read` keeps slice F
  symmetric with the existing module layout (workflows in
  `bailiff_plan_implement.rs` etc., readers in `bailiff_plan_read.rs`).
- **`VerifiedSection` is bailiff-specific.** The verifier's natural
  return is `Result<(), VerifyError>`. Wrapping into a
  three-variant enum is a presentation concern — `show` is the
  consumer. If a programmatic caller surfaces later that wants
  the raw verifier result, expose it then; the variant shape
  doesn't foreclose either direction.

## Open questions

- Should `show` accept a `--plan-id <id>` flag or take the id as
  a positional argument? `decide` and `review` take the id as a
  flag; I'll match for consistency.
- Should the list verb show a count footer? Probably yes for
  ergonomic feedback ("4 plans") — easy to add inside the
  formatter and easy to drop if it gets in the way.
