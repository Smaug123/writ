# Slice — pre-warmed devShell closure cache for no-egress agent VMs

Drafted 2026-06-07. Closes the second half of the no-egress `--warm
devshell` gap. Flake-input provisioning (the `2026-05-30` slice, FK0–FK4)
made the guest able to *evaluate* a flake offline by brokering its locked
input **source trees**. This slice makes the guest able to *realise* the
devShell **closure** offline by serving its pre-built, signed store paths
from a human-warmed cache — so a closure containing derivations that are
in no public cache no longer falls through to a local, egress-needing
build.

## Motivation

`nix develop .#default` does two things: it *evaluates* the workspace
flake (needs the input source trees — solved by FK) and it *realises* the
devShell closure (needs every store path the shell references). The
realisation half is unsolved for any closure that contains derivations
absent from `cache.nixos.org`.

The motivating failure, warming the `dumb-fsharp-lsp` devShell:

```
error: Cannot build '/nix/store/…-FSharp.Compiler.Service.43.12.204.nupkg.drv'.
       > trying https://www.nuget.org/api/v2/package/FSharp.Compiler.Service/43.12.204
       > curl: (6) Could not resolve host: www.nuget.org
       > error: cannot download FSharp.Compiler.Service.43.12.204.nupkg from any mirror
…
error: Cannot build '/nix/store/…-dumb-fsharp-lsp-nuget-deps.drv': 1 dependency failed.
```

`dumb-fsharp-lsp-nuget-deps` and the `nupkg` FODs it depends on are
derivations **defined inside the flake**, not flake inputs. `nix flake
archive` never builds them, and `cache.nixos.org` does not have them. So
at `max-jobs = 1` (`crates/writ-vm-git/src/lib.rs:51`,
`GUEST_DEVSHELL_WARM_MAX_JOBS`) the guest falls through to *building* them
locally; the build reaches for `www.nuget.org` / `tarballs.nixos.org`; DNS
fails (correctly — the guest has no egress); the warm dies.

This is exactly the residual the `650f99d` commit message named: *"a
closure with outputs genuinely absent from public caches needs the closure
pre-realised in an egress builder … also requires signing input-addressed
outputs, since they are not self-certifying like the current CA input
sources."* This slice is that work — but far smaller than a full
"egress-VM provisioner", because the serving machinery already exists.

## Key finding — one surgical enabling change

The broker's nix-cache endpoint already has everything needed to serve a
signed, input-addressed closure from a local `file://`-style directory:

- **Local NAR serving** — `serve_local_nar` (`src/vm_http/nix_cache.rs:775`),
  already used for FK's CA archive.
- **NAR-body verification against the narinfo** —
  `verify_nar_body_on_blocking_thread`, already applied to local NARs.
- **Signed-narinfo parse + trusted-key verification** —
  `parse_signed_narinfo_for_store_hash(body, hash, trusted_public_keys)`,
  already used on the **upstream** path (`fetch_metadata`,
  `src/vm_http/nix_cache.rs:443`).
- **Trusted-key plumbing** — the single config field
  `nix_cache_trusted_public_keys` feeds *both* the broker's admission
  (`src/config.rs:723`) *and* the guest's `WRIT_NIX_TRUSTED_PUBLIC_KEYS`
  nix.conf line (`src/agent_vm_daemon.rs:874`,
  `src/agent_vm_daemon/guest_command.rs:86`). One key, both sides trust it.

The **only** thing blocking it: `try_serve_local_narinfo`
(`src/vm_http/nix_cache.rs:694`) admits *only* content-addressed narinfos
via `parse_content_addressed_narinfo_for_store_hash`, which rejects
input-addressed paths as `NotSelfCertifying`. Relax that one gate to
**"CA self-certifying, OR signed by a trusted key"** and the existing
serve/verify path handles the rest unchanged.

## Trust model

A CA path is self-certifying — the broker cannot forge it. A *signed* path
is only as trustworthy as the key. We put the pre-warm signing **secret
key only on the egress builder VM** — never on the broker, never on the
guest. The signature therefore *means* "a human warmed this exact closure
from `main`", which is the existing trust boundary (broker + human review;
see `project_vm_trust_model`). Defence in depth is preserved: the broker
verifies the signature on admission, the guest verifies it again on
substitution; neither can be handed a forged or unsigned input-addressed
path.

`max-jobs = 1` stays as-is. The `allowSubstitutes = false` setup-hook
derivations (e.g. `cargoHelperFunctionsHook`) still build locally from
their substitutable inputs — no egress. The pre-warm cache only ensures
the *egress-needing* FODs/outputs are substitutable, so they are never
built.

## Decisions (made with the user, 2026-06-07)

1. **Strict — pre-warm only.** The devShell warm is served **exclusively**
   from the pre-warm cache (plus the FK CA input archive); it does **not**
   fall back to `cache.nixos.org`. The warm is then fully determined by the
   pinned `main` closure and fails fast if a path was not warmed
   (correctness over availability). Lowest-blast-radius enforcement: scope
   "strict" to the *warm* by pointing the warm command's substituters at a
   pre-warm-only broker view (no upstream), leaving the agent's later Nix
   usage and the FK flow on the existing proxy endpoint. (A stronger
   variant — drop the upstream proxy for the whole session — is noted under
   *Out of scope / follow-ons*.)
2. **Separate durable dir.** The pre-warmed closure lives in its own
   `nix_prewarm_cache_dir`, served local-first alongside
   `flake_input_cache_dir`. This keeps the manually-managed, durable
   pre-warm content clear of the auto-provisioned, GC-eligible CA archive.
3. **Committed warm script.** Port the orchestrator's `warm-cache.sh`
   pattern into `host-setup/` (key-init + a devShell warm script) with
   shellcheck, rather than documented commands only.

Reference implementation copied from: `../github-actions-runner-orchestrator/host-setup/mac-cache/`
(`init-cache.sh`, `warm-cache.sh`, `warm-flake-inputs.sh`). Two
writ-specific adaptations: warm a **devShell via `--profile`** (not `nix
build` of a package), and serve **through the broker** (no darkhttpd — the
broker already is the cache server).

## Builder side (warm "manually from main" on an egress VM)

The guest is `aarch64-linux`; an Apple-silicon host cannot build that,
hence the builder VM. On it (it has egress), one-time:

```sh
nix-store --generate-binary-cache-key writ-prewarm-1 prewarm.secret prewarm.public
```

Then, per workspace repo at `main`, into the signed pre-warm cache — both
the input source trees (eval) and the devShell closure (realisation),
because strict mode forbids the upstream fallback that supplies public
paths today:

```sh
# input source trees (so offline eval works without upstream)
nix flake archive --no-update-lock-file \
  --to "file://$PREWARM?secret-key=$PWD/prewarm.secret" "$REPO"

# the devShell closure — use --profile (a devShell is not `nix build`-able)
nix develop "$REPO#default" --profile ./dev-profile --command true
nix copy --to "file://$PREWARM?secret-key=$PWD/prewarm.secret" ./dev-profile
```

`./dev-profile` is realised by `--profile`, so `nix copy` of it captures
exactly the closure `nix develop .#default` will demand (including
build-time deps like the `nuget-deps` FOD output). The signed `$PREWARM`
directory is then transferred to the broker host's `nix_prewarm_cache_dir`,
and `writ-prewarm-1:<base64>` is added to `nix_cache_trusted_public_keys`.

## Plan of work

### PW0 — Offline pre-warm proof (host-only, before production code) — landed

`scripts/prove-prewarm-signed-offline.sh`. Mirrors
`scripts/prove-flake-offline.sh`. Builds a minimal **input-addressed**
derivation (no `outputHash` — addressed like a compiled devShell output,
not a self-certifying CA flake input), signs it into a `file://` cache with
a generated key, then runs an isolated Nix consumer under `sandbox-exec`
with all IP egress denied and a fresh chroot store that holds no derivation
for the path (so it can only be substituted, never built). Three controls,
all passing on the host:

- NEGATIVE (empty cache): the path is neither substitutable nor buildable →
  fails. Proves the test is not vacuous.
- NEGATIVE (untrusted key): signed cache present but its key not in
  `trusted-public-keys` and `require-sigs` on → the consumer **refuses** the
  path. This is the security-critical control — the trust model is that a
  signature *means* "a human warmed this exact closure from main".
- POSITIVE (trusted key): the consumer substitutes the path offline.

Hermetic (the probe needs no network to build), so it runs anywhere on
macOS. Proves the "sign + substitute input-addressed offline" mechanic, and
that signature verification is load-bearing, before any broker change.

### PW1 — Broker: admit signed local narinfos — landed

Relax `try_serve_local_narinfo` to admit "CA self-certifying **OR** signed
by a trusted key" (try CA parse first; on `NotSelfCertifying`, try
`parse_signed_narinfo_for_store_hash(…, trusted_public_keys())`). The
admitted-NAR source stays `Local`; `serve_local_nar` and
`verify_nar_body_on_blocking_thread` are unchanged. Tests first
(unit/property): a signed input-addressed narinfo in the local dir is
served + admitted + NAR-verified; an unsigned or untrusted-signed
input-addressed narinfo fails closed; the existing CA path is byte-for-byte
unchanged. *This is the pure, security-critical core; keep it small.*

### PW2 — Config: a separate, durable pre-warm cache dir — landed

Add `nix_prewarm_cache_dir` to the vm_http config and runtime
(`src/config.rs`), served local-first **before** `flake_input_cache_dir`.
Generalise the single `local_cache_dir()` in
`src/vm_http/nix_cache/config.rs` to an ordered list (pre-warm, then
flake-input). Pre-warm dir is durable and not subject to the FK GC. The
pre-warm public key rides the existing `nix_cache_trusted_public_keys` (no
new key field). Tests: config parse/validation; the broker serves the new
dir local-first; the guest nix.conf carries the pre-warm key.

### PW3 — Strict warm view + warm command wiring — landed

Expose a pre-warm-only serving view (no upstream proxy; serves pre-warm +
FK CA dirs, 404 on miss) and point the warm command's substituters at it.
Shape as landed: a dedicated route `/v1/nix/prewarm` reusing the local
serving + signed admission with the upstream disabled, and a
`--option substituters <prewarm-url>` override on the warm's nix
invocations, so the warm cannot reach upstream even though the session
nix.conf default still can. Tests: the warm's substituter override is
present and points at the pre-warm view; the pre-warm view never proxies
upstream.

Decisions made during implementation (2026-06-12, with the user):

- **Strictness is gated on the operator opting in.** The daemon injects
  `WRIT_NIX_PREWARM_URL` (and the guest warm goes strict) only when
  `nix_prewarm_cache_dir` is configured. Plan-literal unconditional
  strictness would have broken every devShell warm of a not-yet-pre-warmed
  repo (and `scripts/prove-agent-vm-devshell-warm.sh`) between PW3 and PW5;
  gating keeps PW3 inert-by-default, the PW2 precedent.
- **Both warm steps are pinned, not just `nix develop`.** The devShell
  warm's `nix flake metadata` (eval/input fetch) and `nix develop`
  (realisation) both carry the override, so the *whole* warm provably never
  proxies upstream — otherwise PW5's "0 warm requests hit upstream" would
  hold only by accident of the FK dir being populated. The sources-only
  warm (`--warm sources`) keeps the proxied default: strictness is the
  devShell warm's contract.
- **Not** wired into the shared `nix_develop_command_args`: that function
  also builds the agent-run `nix develop` wrapper, which decision 1
  deliberately leaves on the proxied endpoint (and which is assembled
  before the broker URL exists). The override is scoped to the warm call
  sites in `vm_client`.
- **The runtime FK `/v1/nix/flake/provision` step is kept unconditionally**
  (belt-and-braces): it is already best-effort, and under a strict warm it
  is what keeps an FK-provisionable but not-yet-pre-warmed repo evaluable
  (the pre-warm view serves the FK dir too).

### PW4 — Builder tooling (committed scripts)

Under `host-setup/` (ported from the orchestrator): a key-init script and
`warm-devshell-cache.sh <repo> [#attr]` that runs the `nix flake archive`
+ `nix develop --profile` + signed `nix copy` sequence above, records a
manifest line (what was warmed, for later pruning), and shellchecks clean.
Docs: a runbook for warming from `main` on the builder VM and transferring
the dir to the broker host.

### PW5 — End-to-end oracle

Extend `scripts/prove-agent-vm-devshell-warm.sh` (or a sibling) so the
fixture devShell contains a path **absent from `cache.nixos.org`** (a
`runCommand`/FOD). Pre-warm + sign it (and the inputs) into
`nix_prewarm_cache_dir`; run the no-egress warm with the strict pre-warm-
only substituter. Assert: (a) the warm succeeds with the guest firewalled
off both github and `nuget.org`; (b) the non-public path was served from
the pre-warm dir, **0** warm requests hit upstream; (c) the guest still
cannot reach the FOD's source host (negative control).

## Guarantee / envelope

After this slice, with a repo pre-warmed from `main`: `nix develop
.#default` inside a no-egress guest realises its **entire** closure from
the signed pre-warm cache + the FK CA input archive, with **no** upstream
proxying during warm. Any path not in the pre-warm cache makes the warm
fail fast (not silently rebuild). The signing key is the human's
attestation that the closure came from `main`. The guest gains no egress;
`max-jobs = 1` is retained only for substituter-less setup hooks, which
build from substitutable inputs.

## Out of scope / follow-ons

- **Whole-session strict** (drop the `cache.nixos.org` upstream proxy
  entirely, so the broker never proxies an external cache for *any* guest
  Nix op). Strictly stronger and closes a real egress surface, but a larger
  migration that breaks the existing FK upstream-proxy proof; elect
  separately.
- **Automatic / per-(repo, rev) pre-warm** keyed like the mirror store, and
  GC/pruning of the pre-warm dir via the recorded manifest. Manual warming
  from `main` is the agreed interim.
- **Builder provisioning** (standing up the egress builder VM itself) —
  operational, out of this slice.
