# Slice — broker-VM image/version handshake (fail fast on a stale broker image)

Drafted 2026-07-01. Makes a version-skewed broker VM image a **loud, fast**
error instead of an opaque 180s timeout. Two complementary parts: (A) the host
notices the broker VM *exited* before it published readiness and fails
immediately with the broker's own stderr; (B) the broker reports a protocol
version in its ready file and the host refuses a mismatch with an actionable
"rebuild the image" message. Part C (move host→broker parameters off the CLI and
into the forward-compatible session spec) is flagged as the enabler for a future
*fully*-automatic token, and is **not** implemented in this slice.

## Motivation

The `broker_placement = vm` arm boots a broker VM whose image bakes in a full
`writd` binary (the broker runs `writd broker`; see
`crates/../src/broker_vm.rs:239` `broker_command`). The host `writd` and the
in-VM `writd` are the **same binary built from the same source tree** — the host
one via `cargo build`, the guest one via `nix build` of the broker image. They
are only ever meant to be built together.

On 2026-07-01, commit `60847bc` (#251, "Forward broker logs to host daemon")
added `--log-file` to the broker argv (`src/broker_vm.rs:251`). The host `writd`
was rebuilt from HEAD; the `writ-broker-vm:latest` image was **not**. Its
pre-#251 `writd` rejected the unknown flag at clap parsing:

```
error: unexpected argument '--log-file' found
  tip: a similar argument exists: '--ready-file'
Usage: writd broker --config <CONFIG> --session-spec <SESSION_SPEC> ...
```

The broker process died before `main`'s body ran, so it never published the
ready file. The host's ready-wait (`launch_broker_vm`,
`src/broker_vm_runner.rs:52`) watches *only* for the file, so it burned the full
`BROKER_VM_READY_TIMEOUT` (180s, `src/agent_vm_daemon.rs`) and returned
`ReadyTimeout` — with the real cause (`container logs writ-broker-vm-<id>`)
trapped inside the guest. Ironically the #251 log-forwarder could not surface it
either: the broker died at argv parsing, *before* it ever opened `--log-file`,
so the forwarder tailed an empty file.

## Design: two failure modes, two mechanisms

| Mode | Example | Only detectable by |
| --- | --- | --- |
| **Broker can't start** | old image rejects `--log-file` at clap parse (this incident); config parse error; boot panic | an *external* liveness check — the broker writes nothing before it dies |
| **Broker starts but mismatched** | a future host adds a session-spec field an old broker ignores; ready-file schema drift | a *version token the broker reports* |

Structural fact that shapes the whole design: **clap parses argv before `main`'s
body runs**, so a broker can never self-report an argv-level incompatibility. The
version handshake (Part B) therefore *cannot* catch this incident on its own;
the liveness check (Part A) is what does. Both are needed to deliver "older image
→ loud + fast".

## Part A — fail fast on broker exit

`launch_broker_vm` (`src/broker_vm_runner.rs:52`) currently races
`wait_for_ready_file` (`:109`) against a `tokio::time::timeout`, polling only the
file. Add a second racer that watches broker-VM liveness.

- The plan already exposes `inspect_invocation()` (`src/broker_vm.rs:334`), and
  the inspect JSON carries `"state": "running"` (the `parse_broker_ipv4_on_network`
  path at `:748` already reads that document). Add a small
  `parse_broker_state(json) -> Option<BrokerVmState>` that extracts the state
  string and classifies it as `Running` / `Terminal(state)` / `Unknown`.
- In `launch_broker_vm`, replace the single ready-file wait with a loop that each
  `poll_interval` (250ms) does: (1) `ready_file.try_exists()` — on `true`, break
  to the handshake step; (2) `inspect_invocation().run()` and
  `parse_broker_state` — on a **terminal** state, abort now.
- On terminal-before-ready, capture the broker's stderr tail via a new
  `logs_invocation()` on the plan (`container logs <vm>`), bounded to the last
  ~16 KiB, and return a new
  `BrokerVmLaunchError::ExitedBeforeReady { state: String, logs: String }`.
- Startup flap: right after `container run -d`, `inspect` may briefly report the
  VM as absent/creating. Treat only a *definitively observed* terminal state as
  failure; `Unknown`/absent keeps polling until the existing 180s timeout, so a
  slow boot still yields `ReadyTimeout` (unchanged behaviour).

Implementation note: `run_capturing_stdout` (`src/agent_vm_lifecycle.rs:1256`)
returns stdout only and errors on non-zero exit, but the clap error is on
*stderr* and `container logs` may exit non-zero. Add a
`run_capturing_output(&self) -> (ExitStatus, String stdout, String stderr)`
helper (it already pipes both streams in `output()` at `:1290`) and use it for
log capture so we keep the message even when `container logs` is unhappy.

Host wiring: `complete_vm_broker_start` (`src/agent_vm_daemon.rs:1955`) maps the
error through `AgentVmDaemonError::BrokerVmLaunch`; `ExitedBeforeReady` flows
through unchanged and the daemon's existing `warn!` at the start-failure site now
prints the broker's real stderr.

### Part A tests (extend the fake-`container` script pattern in `broker_vm_runner.rs`)

- Broker "exits" before ready: fake `container inspect` returns
  `"state": "stopped"` and `container logs` prints a canned clap error → returns
  `ExitedBeforeReady` **promptly** (well under the 180s timeout) and the error
  string contains the captured log line.
- Broker stays running, never ready: inspect always `running`, no ready file →
  still `ReadyTimeout` (existing behaviour preserved).
- Ready appears before any terminal state → success (existing test still holds).

## Part B — versioned ready-file handshake

Today the ready file is the bare port `"{port}\n"`, written atomically by
`write_ready_file_atomic` (`src/broker_entrypoint.rs:218`), and the host only
checks existence. Upgrade it to a typed, versioned document — the same pattern as
the existing `BrokerSessionSpec` version field (`src/broker_session.rs:33`,
rejects `!= 1` at `:99`), but in the broker→host direction.

- New module `src/broker_protocol.rs` (gated `#[cfg(feature = "host")]` — the
  broker is host-featured `writd`, and this keeps it out of the `vm-client`
  guest surface):
  - `pub const BROKER_PROTOCOL_VERSION: u32 = 1;` with a doc comment listing what
    counts as a bump (broker CLI args, session-spec schema, ready-file schema,
    broker-read config schema) and a pointer to the pinning test below.
  - `pub struct BrokerReadyDoc { protocol_version: u32, broker_port: u16,
    writd_build: Option<String> }` (serde). `writd_build` is **display only**
    (e.g. `CARGO_PKG_VERSION` + short git hash if available); it is **never** the
    gate — dev trees are dirty, so a hash is unreliable for comparison.
  - A parser that also accepts the **legacy bare-integer** form and maps it to
    `protocol_version = 0` ("pre-handshake broker"), so an old image that somehow
    reaches the ready-file write still yields a clean mismatch rather than a
    parse error.
- Broker side: `write_ready_file_atomic` serialises the JSON doc (stamping
  `BROKER_PROTOCOL_VERSION` and `writd_build`) instead of `"{port}\n"`. Still
  atomic (temp + rename), still written strictly after the listener is serving
  (`serve_broker`, `src/broker_entrypoint.rs:453`).
- Host side: after the ready file appears (Part A loop), read + parse the doc and
  check `protocol_version == BROKER_PROTOCOL_VERSION`. On mismatch return
  `BrokerVmLaunchError::ProtocolMismatch { host: u32, guest: u32 }`, whose
  `Display` names `writ agent-vm build-broker-image`. Cross-check that
  `broker_port` in the doc equals the port the host told the broker to bind (a
  cheap parse-don't-validate assertion reaching the mint side).

**Self-demonstrating on deploy.** After this lands, the new host run against the
*current* (bare-port) image immediately yields `ProtocolMismatch { host: 1,
guest: 0 }` — which is exactly the image rebuild the change is asking for. That
is the intended one-time compatibility break; from then on both sides speak the
structured doc.

### Part B token maintenance — CI snapshot (semi-automatic)

The runtime gate stays a trivial `u32 ==` (no schema machinery in the
security-critical broker path). The *reminder to bump it* is machine-enforced by
a CI snapshot test (`broker_contract_fingerprint_is_pinned` in `broker_vm.rs`),
so a contract change that forgets the bump fails **at CI, before the image is
ever built**.

**Implementation choice.** The original sketch derived the fingerprint with
`schemars` (JSON-Schema of the wire types) + clap `CommandFactory` introspection.
The shipped version instead uses a **dependency-free canonical-example
snapshot**, which achieves the same "contract change → CI break → bump reminder"
property with less machinery (gospel: small orthogonal core), and adds a
*compile-time* forcing function schemars lacks:

- **Broker CLI flags:** projected from `sample_plan().run_invocation()` — the
  actual argv the host constructs — by collecting the `--flag` names after the
  `broker` token. (This is also independently pinned by the pre-existing exact-argv
  assertion in `run_invocation_is_dual_homed_with_mounts_and_broker_command`,
  which now carries a bump reminder.)
- **Ready-doc schema:** `serde_json::to_string` of a **fully-populated
  `BrokerReadyDoc` struct literal**. The exhaustive literal fails to compile when
  a field is added, and the serialized string changes when a field is
  renamed/removed — so both forms of drift are caught.
- The two are concatenated and asserted against a checked-in snapshot string
  whose failure message says: update the snapshot **and** bump
  `BROKER_PROTOCOL_VERSION` (and rebuild the broker image).
- The **session-spec** schema is guarded independently by its own `version` field
  and the `broker_session` tests, so it is not re-pinned here. The broker-read
  **config** schema is the residual not mechanically pinned — a config-shape
  change that affects the broker should still bump the version (documented on
  `BROKER_PROTOCOL_VERSION`).

### Part B tests (property-first)

- Proptest round-trip: `BrokerReadyDoc` serialises and parses back to itself for
  arbitrary `(version, port, build)`.
- Legacy bare-integer content parses to `protocol_version = 0`.
- Host gate: rejects every `guest != host`, accepts equality; port cross-check
  rejects a doc whose `broker_port` differs from the expected port.
- The structural-fingerprint snapshot test above.

## Part C — deferred: params via the forward-compatible session spec (Option-1 enabler)

Not in this slice. Recorded so the end state is explicit: move pure-data
host→broker parameters (e.g. `--log-file`) off the `writd broker` CLI and into
the session-spec JSON, which already tolerates unknown fields (the `surprise:true`
test at `src/broker_session.rs:244`). Then a future param addition can no longer
clap-crash an old broker — it degrades to Part B's clean version mismatch — and
the entire host→broker contract collapses to a single schema. At that point the
CI snapshot's structural fingerprint could graduate into a *runtime* derived
token (one `schema_for!` + hash at boot), retiring the hand-bumped integer
entirely. This is the fully-automatic Option 1; it is gated on Part C landing
first.

## Files touched (Parts A + B) — as shipped

- `src/broker_vm_runner.rs` — liveness race (`wait_for_ready_or_exit`,
  `capture_broker_logs`, `tail`), ready-doc gate (`gate_ready_doc`, new
  `expected_port` param), and the `ExitedBeforeReady`/`ReadyRead`/`ReadyParse`/
  `ProtocolMismatch`/`ReadyPortMismatch` error variants; tests (fail-fast,
  version-mismatch, port-mismatch, updated success/timeout).
- `src/broker_vm.rs` — `logs_invocation()`, `BrokerVmState` + `parse_broker_state`
  (+ tests); `broker_contract_fingerprint_is_pinned` CI snapshot + bump reminder
  on the exact-argv test.
- `src/broker_entrypoint.rs` — `write_ready_file_atomic` writes the JSON doc;
  updated the two ready-file tests and the end-to-end assertion.
- `src/broker_protocol.rs` — **new**: `BROKER_PROTOCOL_VERSION`,
  `LEGACY_PROTOCOL_VERSION`, `BrokerReadyDoc` (+ `current`/`to_ready_file`/`parse`),
  `BrokerReadyDocError`, property tests; wired into `src/lib.rs` under
  `#[cfg(feature = "host")]`.
- `src/agent_vm_lifecycle.rs` — `CapturedOutput` + `run_capturing_output` helper.
- `src/agent_vm_daemon.rs` — call site passes `broker_port` to `launch_broker_vm`.
- `src/agent_vm_daemon/lifecycle_tests.rs` — fake `container` publishes a
  well-formed ready doc (was an empty marker) so it clears the new gate.
- No `Cargo.toml` change: the CI snapshot uses a dependency-free canonical-example
  pin rather than `schemars` (see the token-maintenance note above).

## Verification

- `cargo fmt`, `cargo clippy --all-targets --all-features -D warnings`,
  `cargo test`, `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features`,
  `nix build .#packages.x86_64-linux.default`.
- On real hardware: rebuild the broker image
  (`writ agent-vm build-broker-image`), then `writ agent-vm start …` succeeds;
  and, to exercise Part A, point the daemon at a deliberately stale image and
  confirm the start fails in ~seconds with the broker's clap error rather than at
  180s.
