# Slice E4c — `bailiff plan implement` CLI verb

Drafted 2026-05-22. Closes the CLI gap left by slice E4b
(`bailiff_plan_implement::submit_implement`): the workflow function
exists, is end-to-end tested against a real broker, but is not
reachable from `bailiff plan implement` — that subcommand does not
exist. This slice wires the verb.

## Motivation

Slice E4b landed `submit_implement` as a library function so the
workflow could be tested in isolation. The CLI binding was implicit
follow-up that never shipped — slices F (read paths) and G (strip
writ) jumped the queue. With G merged, the writ→bailiff carve-out is
complete on the daemon side, and the missing implement verb is now
the only thing between an operator and a complete
`submit → decide → review → implement → PR` flow driven entirely
through `bailiff`.

That flow is the dogfood we want: the first piece of slice-H work
(rewrite `docs/design/broker.md`, add `docs/design/bailiff.md`,
split CLI reference) is a natural candidate to drive through the
bailiff pipeline once this verb lands. But that's slice H; this
slice is just the CLI binding.

## What ships

One new clap subcommand and one dispatch function in
`src/bin/bailiff.rs`:

- `PlanCmd::Implement` variant — required `--plan-id`,
  `--prompt-file`, `--repo`, `--writ-allowed-signers`; optional
  `--bailiff-repo`, `--writ-repo`, `--purpose`, `--label`,
  `--agent`, `--model`.
- `plan_implement(...)` async fn that reads the prompt file, parses
  the allowed-signers file, opens the bailiff repo, constructs
  `SubmitImplementInputs`, calls `submit_implement`, and prints the
  implement note's bailiff-side OID on success.
- Dispatch arm in `dispatch()` routing `PlanCmd::Implement` to
  `plan_implement`.
- Clap-surface tests pinning the required and optional flag sets, the
  required-ness of `--plan-id`, and the value-parser wiring on
  `PlanId`.
- Two docstring fixups: the binary-level docstring at the top of
  `src/bin/bailiff.rs` and the `Cmd::Plan` enum variant doc currently
  read "submit/decide/review today; implement lands in a later slice"
  — drop the proviso.

## Surface details

The verb mirrors `bailiff plan review` with three deliberate
differences. None of them are obvious from the flag spelling, so this
section pins the reasoning.

- **`--prompt-file` carries the *feature* prompt, not plan body.**
  `submit_implement` composes the implementer's effective prompt
  internally as `feature_prompt + PLAN_PROMPT_SEPARATOR + plan_body`
  where `plan_body` is decoded from the verified planner envelope.
  The CLI must not let the operator pass plan body bytes here — but
  enforcing that is the library's job; the CLI just hands the bytes
  over and `compose_implementer_prompt_bytes` does its own
  `AgentPrompt::try_new` cap check on the composed result. The clap
  docstring on `--prompt-file` should explicitly say "the operator's
  original feature prompt" so the surface is honest about which of
  the three planner / reviewer / implementer prompt roles this is.

- **Capability set is `WorkspaceWrite`, not `WorkspaceRead`.** The
  implementer is allowed to mutate the repo (and via the GitHub-App
  minter, push). This is the difference that makes the duplicate
  gate load-bearing: a second `bailiff plan implement` against an
  already-implemented plan could push a second set of changes. The
  pre-RPC `AlreadyImplemented` gate in `submit_implement` is what
  forecloses that. The CLI exposes one repo via `--repo`; the
  capability `Vec` has one element. (`SubmitImplementInputs.capabilities`
  is a `Vec` because the wire shape is and a future stage may
  grant several; today it's always a singleton.)

- **`--purpose` defaults to `"plan-implement"`** (parallels
  `plan-submit` / `plan-review`).

Required-vs-optional follows `bailiff plan review`'s shape:
`--plan-id` is required (implementing presupposes a submitted +
decided plan; there is no auto-allocation), `--writ-allowed-signers`
is required (envelope verification is non-optional), `--prompt-file`
and `--repo` are required (no sensible defaults). All path defaults
match `plan submit` / `plan review` — `default_bailiff_repo_path()`
and `default_writ_repo_path()` already exist; this slice reuses them.

## Error mapping

`submit_implement` surfaces eleven typed variants. The dispatcher
in `plan_implement` maps each to a user-facing message that names
the operator's recourse explicitly. Most are passthrough
`Err(format!("{e}").into())`; four deserve specific messages:

| `SubmitImplementError` variant | User-facing recourse |
| --- | --- |
| `PlanSubmissionMissing` | "no submission note recorded for plan X; run `bailiff plan submit` first" |
| `PlanNotDecided` | "plan X has no decision recorded; run `bailiff plan decide --accept` first" |
| `PlanRejected` | "plan X was rejected; refusing to implement a rejected plan — submit a fresh plan" |
| `AlreadyImplemented` | "implement already recorded for plan X; bailiff does not re-run the implementer — submit a fresh plan if a re-implement is needed" |
| `WriteImplementNote { source: ImplementAlreadyRecorded { .. } }` | Same message as `AlreadyImplemented` (the post-RPC variant of the same invariant — the implementer agent ran but the bailiff-side write lost a race; recourse is identical, modulo the writ-side envelope being stamped). |

The remaining variants (`ReadTaskFailed`, `ReadPlanNote`,
`ReadDecisionNote`, `ReadImplementNote`, `ReadPlanEnvelope`,
`ComposeImplementerPrompt`, `OpenSession`, `RunAgent`,
`SessionIdMismatch`, `WriteImplementNote { source: ... }`
non-idempotency cases, `WriteTaskFailed`, `CloseSession`) are
runtime / contract failures whose existing `#[error(...)]`
messages are already actionable — passthrough is fine.

## What stays in scope

- Tests-first: write the four clap-surface tests, observe them fail,
  then add the variant + dispatch arm. (Per Gospel: failing test
  first, then fix.)
- The two docstring fixups so the binary header and `Cmd::Plan`
  doc don't lie about the verb set.
- Output discipline: print the implement note's bailiff-side OID to
  stdout on success (mirrors `plan_review` printing
  `review_note_oid`). Errors go to stderr via the `main()`
  `eprintln!` path.

## What stays out of scope

- **Docs updates.** `docs/user_facing/cli-reference.md` does not
  mention bailiff at all yet — adding a bailiff section is slice H.
  This slice deliberately ships the verb without doc updates, matching
  the F2 / F4 precedent.
- **Multi-implement history.** A second implementer run against an
  already-implemented plan is refused. Multi-attempt history is the
  same "fresh plan" recourse `plan_review` documents and is a
  future `v1` → `v2` ref-shape migration.
- **End-to-end tests.** `submit_implement` already has four
  end-to-end tests in `src/bailiff_plan_implement.rs::end_to_end_tests`
  (happy path, `PlanSubmissionMissing`, `PlanNotDecided`,
  `PlanRejected`, `AlreadyImplemented`, plus the concurrent
  duplicate-gate test). Duplicating them at the binary layer would
  test clap, not the workflow. The clap-surface tests cover the
  binding; the workflow tests cover the workflow.
- **Bailiff-side `RunAgent` configuration.** Writ's
  `RunAgentDaemonConfig.spawn_command` is operator-configured and
  out of bailiff's scope. The dogfood loop assumes the operator has
  pointed writd at a real agent wrapper; this slice does not change
  that.

## Plan of work

One PR, no sub-slices. The work is too small to split usefully.

### E4c.1 — clap surface + dispatch

1. **Tests first** in `src/bin/bailiff.rs` `#[cfg(test)] mod tests`:
   - `plan_implement_parses_minimum_required_flags` — `--plan-id`,
     `--prompt-file`, `--repo`, `--writ-allowed-signers` parse and
     thread into `PlanCmd::Implement`. Defaults: `purpose ==
     "plan-implement"`, `agent == AgentKind::Claude`, all
     `Option<_>` fields are `None`.
   - `plan_implement_accepts_every_optional_flag` — full surface
     round-trip including `--bailiff-repo`, `--writ-repo`,
     `--purpose`, `--label`, `--agent codex`, `--model`.
   - `plan_implement_rejects_missing_plan_id` — pin
     `Option<PlanId>` would silently accept this; required is
     load-bearing.
   - `plan_implement_rejects_malformed_plan_id` — pin that
     `value_parser` stays wired to `PlanId::from_str`.

   Observe all four fail (variant doesn't exist).

2. Add `PlanCmd::Implement` clap variant — copy `Review`'s flag
   shape; change `--purpose` default to `"plan-implement"`; rewrite
   the variant docstring to describe the implementer role and
   reference `submit_implement`'s gates. The `--prompt-file` doc
   must say "the operator's original feature prompt — `submit_implement`
   composes this with the approved plan body internally."

3. Wire the dispatch arm in `dispatch()`: pattern-match
   `PlanCmd::Implement { .. }`, call `plan_implement(...)`.

4. Add `plan_implement` async fn modelled on `plan_review`:
   - Read & parse `--prompt-file` → `AgentPrompt`.
   - Parse `--repo` → `RepoRef`.
   - Read & parse `--writ-allowed-signers` → `AllowedSigners`.
   - Resolve `--bailiff-repo` / `--writ-repo` defaults via the
     existing `default_*_path()` helpers.
   - Open the bailiff repo on a blocking task.
   - Build `SubmitImplementInputs` with `WorkspaceWrite` on the
     resolved `RepoRef`.
   - Call `submit_implement(&client, bailiff, &writ_repo_path,
     allowed, inputs)`.
   - On `Ok`, print `outcome.implement_note_oid`.
   - On `Err`, map the four variants in the table above to specific
     messages; everything else falls through to
     `Err(format!("{e}").into())`.

5. Update the docstrings: drop the "implement lands in a later
   slice" proviso from the binary header (line 12-15-ish) and from
   the `Cmd::Plan` enum variant (line 65-ish).

6. Observe the four parser tests pass; run the full gate
   (`cargo test`, `cargo clippy --all-targets`, `cargo fmt --
   --check`).

7. Commit, push, open PR, run `codex review --base main` per
   `CLAUDE.md`.

## Estimated total

~250 LoC across one PR. CLI variant + dispatch arm + error mapping
≈ 130 LoC of production code; four clap tests ≈ 100 LoC; docstring
fixups ≈ 20 LoC. Tests-first per Gospel; the surface tests are
mechanical pins, not searches.

## Risks and tradeoffs

- **Error-mapping divergence from `plan_review`.** `plan_review`
  only maps `ReviewAlreadyRecorded`; everything else falls through
  to `format!("{e}")`. This slice maps five variants. The asymmetry
  is intentional — `submit_implement` has more *pre-RPC* gates
  (`PlanSubmissionMissing`, `PlanNotDecided`, `PlanRejected`,
  `AlreadyImplemented`) than `submit_review` does, and those gates
  exist because the implementer holds `WorkspaceWrite`. An
  operator who trips one needs the actionable message; a passthrough
  `format!` is OK for the runtime failures because their existing
  `#[error]` strings already name the broken precondition.

- **Duplicate-implement footgun.** Even with the pre-RPC gate,
  multi-implement could theoretically slip if the on-disk note
  state diverges from writ's audit log (e.g. someone restores
  bailiff's bare repo from a backup older than its last implement
  note). The duplicate-gate test
  (`concurrent_submit_implement_serialises_on_the_duplicate_gate`)
  pins the in-process invariant; cross-process backup-restore
  hazards are an operational concern out of scope for this slice.

- **No dogfood execution in this slice.** This slice *enables* the
  dogfood; it doesn't *perform* it. The first plan driven through
  the full loop is slice H (or whatever the operator points at
  first). The interactive instructions for that flow are a
  follow-up artifact, not part of this slice.

## Open questions

None. The library is settled; the CLI binding is mechanical.
