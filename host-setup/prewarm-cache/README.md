# Pre-warmed devShell cache — builder runbook

Operator tooling for the pre-warmed devShell closure cache
(`docs/plans/2026-06-07-prewarmed-devshell-cache.md`). The broker side is
already in place: with `nix_prewarm_cache_dir` configured (see
`docs/user_facing/configuration.md`), the broker serves that directory —
admitting trusted-signed paths — through the strict `/v1/nix/prewarm` view,
and every no-egress guest devShell warm is pinned to it. These scripts produce
the directory's contents: a signed copy of a repository's flake-input sources
and devShell closure, warmed from reviewed `main` on a machine that *does*
have egress.

The signature is the trust anchor. The signing **secret key exists only on
the builder VM** — never on the broker host, never in a guest — so a valid
`writ-prewarm-1:` signature *means* "a human warmed this exact closure from
`main`". The broker verifies it on admission and the guest verifies it again
on substitution.

## Single-machine macOS shortcut (`warm-via-container.sh`)

If the broker is your Mac and you just want a repo pre-warmed locally, you do
**not** need to stand up a separate builder VM by hand. `warm-via-container.sh`
is the host-side automation: it drives an Apple `container` (the same guest
image the agent VMs use, on the default NAT network so it has egress) as the
aarch64-linux builder, and runs `init-prewarm-cache.sh` + `warm-devshell-cache.sh`
inside it against a fresh checkout of the repo:

```sh
container system start                                   # once per boot
./warm-via-container.sh Smaug123/dumb-fsharp-lsp         # owner/name, or a git URL
```

It clones **`main`** — the branch the guest's workspace init checks out
(`DEFAULT_WORKSPACE_BRANCH`), exactly the rev `agent-vm start --repo <repo>`
demands — so the warm matches what the guest will need (override with
`WRIT_PREWARM_REF`). A full git URL is cloned verbatim with your configured
credentials, so **private repos work** (its userinfo is redacted from logs).
The injected build toolset (grep/find/jq/flock) comes from *writ's* pinned
nixpkgs, not the warmed repo's lock — it runs as root near the signing key, so
it must be trusted. The signed `cache/` lands
directly in `WRIT_PREWARM_DIR/cache` on this host, so the "Transferring to the
broker host" step below is a no-op; the script prints the exact
`nix_prewarm_cache_dir` + `nix_cache_trusted_public_keys` lines to paste into
`writd`'s config. Restart `writd` once after the first config change. Re-run to
refresh after the default branch moves (already-signed paths are skipped).

Tunables via env (`WRIT_PREWARM_DIR`, `WRIT_PREWARM_REF`, `WRIT_PREWARM_IMAGE`,
`WRIT_PREWARM_SYSTEM`, `WRIT_PREWARM_CPUS`, `WRIT_PREWARM_MEMORY`,
`WRIT_PREWARM_TOOLS_NIXPKGS`); run with no args for the full list.

**Security trade-off.** Here the builder and broker are one machine, so the
signing key lives under `WRIT_PREWARM_DIR/keys/` on the broker host — a
relaxation of the "key only on the builder" model above. It is still sound: the
guest only ever sees `cache/` over HTTP, never `keys/`. For a true split, use
the manual builder-VM flow below (run `warm-devshell-cache.sh` on a separate
machine and rsync only `cache/`).

## The builder VM

Warming *realises* the devShell, which means building for the guest system —
so the builder must *be* the guest system: **aarch64-linux** for an
Apple-silicon broker host (any aarch64 Linux VM with Nix will do; it does not
need Apple's `container` tooling). It needs:

- outbound network (this is the one machine in the scheme that fetches from
  the open internet: github, cache.nixos.org, nuget.org, …);
- `nix` (any version with `nix-command` + `flakes`; the scripts pass
  `--extra-experimental-features` themselves), `jq`, `git`, `bash`, `flock`
  (util-linux, in every distro base — the warm lock), and the usual
  `grep` / `find` / coreutils (present on any normal Linux; the scripts
  preflight-check them and abort loudly if absent, since a missing `grep`
  would otherwise make input-archiving a silent no-op);
- disk for the Nix store plus the cache dir (devShell closures run to
  gigabytes).

`warm-devshell-cache.sh` refuses to run on any other system
(`builtins.currentSystem` is checked) — in particular on the operator's Mac,
where it would otherwise silently warm a darwin closure no guest can use.

## One-time setup

```sh
./init-prewarm-cache.sh
```

Generates the `writ-prewarm-1` signing keypair under
`~/.local/share/writ-prewarm/keys/` (override the base dir with
`WRIT_PREWARM_DIR`) and creates the sibling `cache/` directory. Idempotent:
re-running never regenerates the key — regenerating would invalidate the
public key registered in broker configs, untrusting everything warmed so far.

Register the printed public key on the broker host (`writd`'s config):

```toml
[agent_vm.vm_http]
nix_prewarm_cache_dir = "/var/lib/writ/prewarm-cache"   # wherever you transfer to
nix_cache_trusted_public_keys = [
  "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
  "writ-prewarm-1:<base64 from init-prewarm-cache.sh>",
]
```

The same list feeds the guest's `trusted-public-keys`, so registering it once
covers both verification points. Note that **setting `nix_prewarm_cache_dir`
flips every devShell warm to strict**: repos that are not pre-warmed will fail
`--warm devshell` rather than fall back to cache.nixos.org. Pre-warm the repos
you use before (or in the same breath as) enabling it.

## Warming a repository

On the builder VM, with the repository cloned and checked out at the reviewed
commit (normally `main`):

```sh
git -C ~/src/the-repo fetch origin && git -C ~/src/the-repo checkout origin/main
./warm-devshell-cache.sh ~/src/the-repo            # devShells.aarch64-linux.default
./warm-devshell-cache.sh ~/src/the-repo someShell  # a non-default attr
```

(A remote flakeref like `github:owner/repo/main` also works — the builder has
egress — but a local checkout is easier to review and to pin.)

The script:

1. archives the flake's **locked input source trees** into the cache, signed.
   The strict warm has no upstream fallback, so even publicly-cached inputs
   (nixpkgs itself) must be present. A stale or missing committed
   `flake.lock` fails the warm (`--no-update-lock-file`);
2. realises the **devShell closure** via a profile (`nix print-dev-env
   --profile` — exactly the closure the guest's `nix develop` will demand,
   including build-time fixed-output fetches like nuget packages) and signs
   it into the cache. The profile is kept under `profiles/` as a GC root, so
   re-warming after a small change only builds and copies the delta;
3. appends one line per warmed store path to `manifest/inputs-warmed.log` /
   `manifest/devshells-warmed.log` (`ts <TAB> flakeref <TAB> rev <TAB>
   path`) — the input for future pruning.

Guard rails, machine-enforced and fail-closed: wrong-platform hosts are
refused; the `devShells.<system>.<attr>` derivation's `.system` is asserted;
a local directory is refused unless it is a git work tree whose clean status
was successfully verified (no git, not a work tree, a failed `git status`,
or modified tracked files all abort — the closure would, or could, be no
commit's closure, so the signature would attest to nothing reviewable);
every flakeref must resolve to a git revision, which rides each manifest
line; a committed lock that pins local filesystem inputs (`path:`,
`git+file:`) is refused before anything is archived — those would sign
builder-local files, outside the reviewed revision, into the broker-served
cache; warming a branch other than `main` (local or remote ref alike) warns
loudly. Concurrent warms serialise on a lock under the base dir.

Re-warm whenever `main` moves in a way that changes the devShell (most
commonly a `flake.lock` bump or dependency change). Warming is incremental:
already-cached paths are skipped by `nix copy`.

## Transferring to the broker host

Only ever transfer `cache/` — never `keys/`. Copy the NARs before the
narinfos: the broker serves the directory live and fails closed on a narinfo
whose NAR is missing, so this ordering keeps a mid-transfer cache consistent
(the same order `nix copy` itself writes). With rsync:

```sh
prewarm=~/.local/share/writ-prewarm
rsync -av "$prewarm/cache/nar/" broker-host:/var/lib/writ/prewarm-cache/nar/
rsync -av --exclude 'nar/' "$prewarm/cache/" broker-host:/var/lib/writ/prewarm-cache/
```

The broker reads the directory lazily per request, so no restart is needed
after a re-transfer (the first-time `nix_prewarm_cache_dir` config change does
need one). The directory must be readable and searchable by the `writd` user —
the broker validates this at startup and fails fast otherwise.

There is no automatic pruning yet; the manifests record what each warm added
so a later pruning pass can compute a keep-set. The cache is content-addressed
on disk (`<hash>.narinfo` + `nar/`), so re-transfers and re-warms are safe to
repeat.

## Security notes

- **Never** copy `keys/` off the builder, commit it, or place it under
  `cache/`. `init-prewarm-cache.sh` refuses symlink/hard-link arrangements
  that would smuggle the secret into the transferable directory, but the
  operator holds the last line.
- Warming **builds the repository's code** on the builder VM — that is the
  machine's purpose — and the builder holds the signing secret. Only warm
  refs you have reviewed (the signature claims exactly that). The script
  avoids running the repo's `shellHook` outside the Nix build sandbox
  (`print-dev-env` realises without executing it), but Nix builds themselves
  execute repo-controlled derivations.
- Rotation: re-warming with a new key is **not** enough — `nix copy` skips
  paths already in the cache, so their narinfos would keep only the old
  signature and be rejected the moment `-1` is retired. Instead:

  1. generate `writ-prewarm-2` (`WRIT_PREWARM_KEY_NAME=writ-prewarm-2
     ./init-prewarm-cache.sh`) and add its public key to
     `nix_cache_trusted_public_keys` **alongside** `-1`;
  2. re-sign everything already in the cache with the new key — the
     manifests enumerate every warmed path:

     ```sh
     prewarm=~/.local/share/writ-prewarm
     cut -f4 "$prewarm"/manifest/*.log | sort -u \
       | nix --extra-experimental-features nix-command \
           store sign --stdin \
           --store "file://$prewarm/cache" \
           --key-file "$prewarm/keys/writ-prewarm-2.secret"
     ```

  3. re-transfer the cache (the narinfos changed; same `nar/`-first order),
     and only then retire `-1` from the config and delete its key.

  The conservative alternative is to rotate into a fresh cache: point
  `WRIT_PREWARM_DIR` somewhere new, re-warm every repo (the builder's local
  store makes this cheap), transfer, and flip `nix_prewarm_cache_dir` over.
