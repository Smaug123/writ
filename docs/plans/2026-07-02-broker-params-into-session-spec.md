# Slice — Part C: host→broker params via the session spec (freeze the broker argv)

Drafted 2026-07-02. This is **Part C** of the broker-image/version handshake
(`docs/plans/2026-07-01-broker-image-version-handshake.md`), which shipped Parts
A + B in #254 and explicitly deferred Part C. Goal: move pure-data host→broker
parameters off the `writd broker` CLI and into the versioned session spec, so the
argv stops being an evolving contract surface. After this, a *future* param
addition can no longer clap-crash a stale broker before `main` runs (the #251
incident class); it degrades to a clean, self-describing version error that
Part A surfaces loudly and fast.

## Correction to the merged Part C sketch (read this first)

The #254 doc's Part C rationale is **factually wrong about the current code** and
this plan supersedes it:

> "...into the session-spec JSON, which already tolerates unknown fields (the
> `surprise:true` test at `src/broker_session.rs:244`)."

The opposite is true. `RawBrokerSessionSpec` is `#[serde(deny_unknown_fields)]`
(`src/broker_session.rs:30-38`) and the test at that line is named
`rejects_unknown_fields` — it asserts `surprise:true` → `Err(...Json(_))`
(`:242-249`). So the forward-compatibility property Part C assumed *does not
exist*. Worse, `parse_json` strict-parses the body **before** it checks the
`version` field (`:96-101`), so a future `version:2` spec that adds any field
fails with an opaque `unknown field` JSON error — **not** the clean
`UnsupportedVersion` the doc promised. Part C therefore has to *build* the
forward-compat mechanism before it can move anything into the spec.

## Decisions (pending confirmation — plan written to the recommended answers)

Two forks were surfaced to the user; unanswered at drafting time. The plan below
assumes the **recommended** option in each; both alternatives degrade the plan
cheaply (noted inline), so redirecting is a matter of dropping/renaming a slice.

1. **Spec forward-compat posture — recommended: strict, version-first.**
   Peek + gate `version` from a tolerant envelope, *then* strict-parse the
   versioned body (keep `deny_unknown_fields` *within* a version). Every shape
   change bumps `version` → an older broker returns a clean `UnsupportedVersion`
   (caught by Part A, logged), while a host typo (`brokr_port`) is still rejected
   loudly within a version. This preserves gospel strictness (parse-don't-
   validate, make-illegal-states-unrepresentable) and still delivers the doc's
   real goal (clean cross-version error). It does **not** grant free additive
   fields: each addition is a version bump + image rebuild — the same, already-
   accepted story as Part B's `BROKER_PROTOCOL_VERSION`.
   - *Alternative (tolerant):* drop `deny_unknown_fields`, mark new fields
     `#[serde(default)]`; additive "advisory" fields need no bump but the
     safe-to-ignore contract is discipline, not types, and host typos stop being
     caught. If chosen, Slice C1 changes from "reorder" to "relax + default", and
     the version bumps in C2 become optional for additive-only changes.

2. **Move scope — recommended: move both `--log-file` and `--ready-file`.**
   Freeze the bootstrap argv to exactly `--config --session-spec
   --bearer-token-file` — the three paths needed to *locate and authenticate the
   spec* — and carry everything the broker uses *after* parsing the spec (its log
   sink, its ready-file target) inside the spec. This is the full "collapse the
   contract to a single schema" that the runtime-token sequel (below) needs, and
   it most directly prevents recurrence of the exact #251 incident (which was
   `--log-file`).
   - *Alternative (log-file only / nothing):* dropping the `--ready-file` move
     leaves a half-migrated argv (gospel dislikes coexisting truths) but avoids
     touching the readiness path; "move nothing" reduces Part C to Slice C1 + the
     freeze comment and defers the real win. Either just removes slice content.

## Why the argv is the right thing to freeze

The `writd broker` argv today (`broker_command`, `src/broker_vm.rs:246-261`):

```
writd broker --config <p> --session-spec <p> --bearer-token-file <p> \
             --ready-file <guest-path> --log-file <guest-path>
```

`clap` parses argv **before** `main`'s body — a broker can never self-report an
argv-level incompatibility (this is the structural fact Part B's design section
calls out). Two of these five flags are *pure host→broker data* the broker only
needs after it is already running:

- `--ready-file` — a guest path the broker *writes* at the end of startup
  (`serve_broker`, consumed at `src/broker_entrypoint.rs:527`). The host watches
  its own mount-side path independently (`agent_vm_daemon.rs:1957`,
  `staging_dir/ready`), so moving the guest path into the spec changes nothing
  host-side.
- `--log-file` — a guest path for the broker's tracing sink. Notably it is *not*
  even in `BrokerArgs` (`src/broker_entrypoint.rs:66-73`); the bin reads it only
  to install telemetry (`src/bin/writd.rs:95`) before calling `run_broker`.

The other three are genuine **bootstrap**: you need them *to find and read the
spec at all* (`--config` opens the audit DB / secret store / vm_http config;
`--session-spec` is the spec itself; `--bearer-token-file` is a secret kept
deliberately out of the config document). They stay on the argv as the permanent,
frozen bootstrap contract. The invariant becomes crisp: **argv = locate + auth
the spec; spec = everything the broker uses once the spec is parsed.**

## Slice C1 — version-first spec parsing (prerequisite, no wire change)

**Status (2026-07-02): implemented** on branch `part-c1-version-first-spec-parse`.
Local gates green: `cargo fmt`, `cargo clippy --all-targets --all-features -D
warnings`, `cargo test`, `cargo doc`. The `nix build .#packages.x86_64-linux`
gate is **CI-only on this host** (aarch64-darwin has no x86_64-linux builder →
platform mismatch); it's a pure-Rust change with no new deps, so CI's Linux job
covers it. Wire format unchanged (still version 1), no image rebuild.


Make cross-version spec skew a clean `UnsupportedVersion` instead of an opaque
unknown-field error, *without* changing the version-1 wire format. This is a pure
internal-robustness change: no image rebuild, no host change, independently
mergeable, and it is the foundation the #254 doc wrongly assumed already existed.

- Refactor `BrokerSessionSpec::parse_json` (`src/broker_session.rs:96`) to:
  1. deserialize a tolerant envelope that reads *only* `version` (e.g.
     `#[derive(Deserialize)] struct VersionEnvelope { version: u32 }`, no
     `deny_unknown_fields`);
  2. if `version != SUPPORTED_SESSION_SPEC_VERSION` → `UnsupportedVersion(v)`
     immediately;
  3. only then deserialize the strict, `deny_unknown_fields`
     `RawBrokerSessionSpec` for the matched version and validate as today.
- Net effect on the truth table:
  - newer `version` + new fields → `UnsupportedVersion` (was: `Json(unknown
    field)`); **this is the behavioural fix**;
  - same `version` + unknown field → still `Json` (host-typo detection preserved);
  - same `version`, valid → unchanged.

### Slice C1 tests (test-first)

- **Failing test to add first** (`broker_session.rs` tests):
  `v2_spec_with_an_added_field_reports_unsupported_version` — a `version:2` doc
  carrying an extra field currently yields `Json(_)`; assert it yields
  `UnsupportedVersion(2)`. Watch it fail, then implement.
- Keep `rejects_unknown_fields` (`:242`) green: a `version:1` doc with `surprise`
  must still be `Json(_)` (strict within a version).
- Keep `rejects_unsupported_version` (`:233`) green.
- Proptest: for any `version != 1` and any otherwise-valid body (with or without
  extra fields), `parse_json` → `UnsupportedVersion(version)` — never `Json`.
- Round-trip unchanged: `parse_json(spec.to_json()) == spec`.

## Slice C2 — move `ready_file` + `log_file` into the spec (stop-the-world)

**Status (2026-07-02): implemented** on branch `part-c2-params-into-session-spec`.
Local gates green (`fmt`, `clippy --all-targets --all-features -D warnings`,
`cargo test`, `cargo doc`). `nix build .#packages.x86_64-linux` is CI-only on this
host. **Breaking: rebuild the broker image** (`writ agent-vm build-broker-image`)
before running the `vm` placement, or a start fails fast with a spec/version
error (Part A). Modelled `ready_file`/`log_file` as a `GuestAbsPath` newtype.

A single atomic flag-day slice. The broker VM image and host `writd` are built
from the same tree and have no independent external consumers, so gospel's
"stop the world" migration applies: change both sides at once, minimise the
window where two truths coexist. Part B already forces a broker-image rebuild
after #254 (the protocol `0→1` self-demonstration); landing C2 *before* that
rebuild folds the whole move into **one** rebuild (protocol `→2`) rather than two.

### Spec schema (version 2)

Add two fields carrying guest paths the host already computes (`guest_ready_file`
/ `guest_log_file`, `src/broker_vm.rs:235-243`):

- `ready_file: GuestAbsPath`
- `log_file: GuestAbsPath`

Model both as a `GuestAbsPath` newtype (parse-don't-validate: non-empty,
absolute) rather than raw `String`, so an empty/relative guest path is
unrepresentable in interior code. `BrokerSessionSpec::new` gains two params;
`to_json`/`RawBrokerSessionSpec` stamp `version: 2` and the two fields;
`parse_json` (already version-gated by C1) parses the v2 body.
`SUPPORTED_SESSION_SPEC_VERSION` → 2.

*If log-forwarding must remain optional (see writd.rs:74's "absent for the
in-process host daemon" note), make `log_file: Option<GuestAbsPath>` instead —
but the VM broker always forwards, so required is the honest default. Decide with
Decision 2.*

### Broker side

- `src/bin/writd.rs`: the `Broker` subcommand drops the `ready_file` and
  `log_file` clap args, leaving `--config --session-spec --bearer-token-file`.
  Because `log_file` is needed for telemetry *before* `run_broker`, `main` now:
  1. reads + parses the spec from `--session-spec` (moving this IO to the shell —
     more functional-core-aligned);
  2. installs telemetry with `spec.log_file`;
  3. calls `run_broker` with the **already-parsed** `BrokerSessionSpec`.
  - Ordering consequence (state it explicitly): a spec read/parse failure now
    occurs *before* telemetry is up, so it prints to **stderr** and exits rather
    than reaching the file sink. This loses nothing — pre-telemetry failures
    never reached the file sink anyway (the #254 doc's own motivation notes the
    forwarder "tailed an empty file"), and Part A's liveness check now captures
    that stderr via `container logs` and returns `ExitedBeforeReady`. A spec
    parse failure is exactly the "broker can't start" class Part A owns.
- `src/broker_entrypoint.rs`: `BrokerArgs.session_spec` becomes a parsed
  `BrokerSessionSpec` (not a `PathBuf`); drop `BrokerArgs.ready_file`. `run_broker`
  no longer calls `BrokerSessionSpec::read_file` (`:285`) and reads the ready path
  from `spec.ready_file` at the `serve_broker` call (`:527`).

### Host side

- `src/broker_vm.rs`: `broker_command` (`:246`) drops the `--ready-file` and
  `--log-file` argv pairs. The host populates `BrokerSessionSpec` with the guest
  paths it currently passes as those flags (`guest_ready_file`/`guest_log_file`),
  so nothing the host *computes* changes — only where it puts the values.
- Bump `BROKER_PROTOCOL_VERSION` → 2 (`src/broker_protocol.rs:34`): the argv
  contract shrank **and** the spec schema changed — either alone warrants it per
  the constant's own doc comment.

### Self-demonstration / transition

- New host + new image: argv is the frozen three; spec v2 carries the paths;
  works.
- New host + **stale** image (the real risk): the stale broker gets no
  `--ready-file`/`--log-file` (harmless — they were `Optional`) and reads a
  `version:2` spec it cannot parse → exits fast with a JSON/version error →
  Part A returns `ExitedBeforeReady` with that stderr. Loud + fast, as intended.
- Old host + new image is not a real deployment path (built together); the
  protocol bump + image rebuild is the coordination point.

### Slice C2 tests (property-first)

- Spec round-trip including the new fields, over arbitrary valid
  `(session_id, cidr, bind_addr, port, ready_file, log_file)`:
  `parse_json(spec.to_json()) == spec`, with `version:2` on the wire.
- `GuestAbsPath` parse rejects empty and relative paths (proptest: any non-empty
  string starting with `/` round-trips; others reject).
- Host constructs the spec carrying the same guest paths it previously passed as
  `--ready-file`/`--log-file` (assert against `guest_ready_file`/`guest_log_file`).
- `run_broker` writes its ready file at `spec.ready_file` (extend the existing
  ready-file entrypoint tests, which currently drive `args.ready_file`).
- **CI pins to update (both carry bump reminders):**
  - `broker_contract_fingerprint_is_pinned` (`src/broker_vm.rs:1242`): the
    `broker-cli-flags` line becomes `--config --session-spec --bearer-token-file`
    and the ready-doc line's `protocol_version` becomes `2`. Failing this test is
    the machine-enforced reminder to bump + rebuild.
  - the exact-argv assertion in
    `run_invocation_is_dual_homed_with_mounts_and_broker_command`
    (`src/broker_vm.rs:1215-1231`): drop the two flag pairs.
- Update `broker_session` tests to v2; keep the C1 version-first tests green.

## Out of scope — the runtime-derived token (Part C's sequel)

Once the argv is frozen and the whole host→broker contract is a single versioned
schema (the spec + the ready doc), the hand-bumped `BROKER_PROTOCOL_VERSION` and
its CI snapshot could be *replaced* by a token derived at boot from the schema
itself (one hash of the canonicalised spec/ready schemas), retiring the manual
bump entirely — the #254 doc's "fully-automatic Option 1". That is a separate
follow-up slice, gated on this one landing, and is **not** planned here (no
speculative generality: build it when the manual bump actually proves painful).

## Files touched

- `src/broker_session.rs` — version-first `parse_json` (C1); `ready_file` +
  `log_file` fields, `GuestAbsPath`, `version:2`, `SUPPORTED_SESSION_SPEC_VERSION`
  (C2); tests.
- `src/bin/writd.rs` — drop `ready_file`/`log_file` clap args; parse spec then
  init telemetry then `run_broker(spec)`.
- `src/broker_entrypoint.rs` — `BrokerArgs` takes a parsed spec, loses
  `ready_file`; `run_broker` reads ready path from the spec; entrypoint tests.
- `src/broker_vm.rs` — `broker_command` drops two flag pairs; host populates the
  spec's guest paths; update the fingerprint + exact-argv pins.
- `src/broker_protocol.rs` — `BROKER_PROTOCOL_VERSION` → 2.
- `src/agent_vm_daemon.rs` — spec-construction call site passes the guest paths
  (host-side watch path at `:1957` is unchanged).

## Verification

- `cargo fmt`; `cargo clippy --all-targets --all-features -- -D warnings`;
  `cargo test`; `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features`;
  `nix build .#packages.x86_64-linux.default`.
- On real hardware: rebuild the broker image
  (`writ agent-vm build-broker-image`), then `writ agent-vm start …` succeeds on
  the v2 contract; and, pointing the daemon at a **stale** (pre-C2) image,
  confirm the start fails in ~seconds (Part A `ExitedBeforeReady`) rather than at
  the 180s timeout.
