#!/usr/bin/env bash
# Warm the pre-warm signing cache with a repository's devShell closure and
# flake-input sources (PW4 of docs/plans/2026-06-07-prewarmed-devshell-cache.md).
#
# Run on the EGRESS BUILDER VM (a Linux machine matching the guest system —
# aarch64-linux for Apple-silicon brokers). For one repository at a reviewed
# commit (normally `main`), this:
#
#   1. archives the flake's LOCKED INPUT SOURCE TREES (so the guest's strict
#      warm can evaluate the flake offline: the pre-warm view is the warm's
#      ONLY substituter, with no upstream fallback to supply public inputs);
#   2. realises the devShell via a PROFILE (`nix print-dev-env --profile` —
#      a devShell is not `nix build`-able; the profile pins exactly the
#      closure the guest's `nix develop` will demand, including build-time
#      FOD outputs like nuget package fetches) and gc-roots it for cheap
#      re-warms;
#   3. signs both sets into the cache dir (`nix copy ...?secret-key=...`
#      signs each narinfo as it is written — no separate sign pass);
#   4. records one manifest line per warmed store path (the input to the
#      pruning follow-on).
#
# The cache dir is then transferred to the broker host's
# `nix_prewarm_cache_dir` per README.md. The signature means "a human warmed
# this exact closure from main", so this script machine-enforces what it can
# of that sentence:
#
#   - PLATFORM. The host must BE the guest system (realising the closure
#     requires building for it). We refuse to run elsewhere, force the
#     system-qualified `devShells.<system>.<attr>` installable, and assert the
#     resolved derivation's `.system` — an unguarded `nix develop .#default`
#     on the operator's Mac would silently sign a darwin closure no guest can
#     use (belt, braces: a flake could also define a cross attr).
#   - EXACTNESS, fail-closed. A local directory must be a git work tree whose
#     clean status was successfully verified; modified tracked files — or any
#     failure to verify at all — are refused: the closure would be (or could
#     be) no commit's closure, so the signature would attest to nothing
#     reviewable. (Untracked files are tolerated — a git-backed flake
#     archives tracked content only.) Every flakeref must resolve to a git
#     revision, recorded in each manifest line — and the revision is resolved
#     ONCE, with all later nix invocations pinned to it, so a mutable ref
#     (github:owner/repo/main) that advances mid-warm cannot make the signed
#     closure disagree with the recorded rev. Warming a branch other than
#     `main` warns loudly but proceeds (release branches are the operator's
#     call).
#   - HOOK CODE. Realisation builds the repo's derivations (that is the
#     point — this VM is the egress sandbox), but `print-dev-env` does NOT
#     execute the devShell's `shellHook` the way `nix develop --command`
#     would: repo-controlled hook code never runs unsandboxed as the user
#     that can read the signing key. Warm only reviewed refs regardless.
#
# Mechanism notes carried over from the reviewed orchestrator warmer this is
# ported from (host-setup/mac-cache in github-actions-runner-orchestrator):
#   - STREAM the input path list into `nix copy --stdin` (an input set is many
#     paths; never splat it into argv — E2BIG). The closure copy passes the
#     single profile path and lets nix compute the closure itself.
#   - ONE host-level lock (atomic mkdir + stale-PID reclaim) around the whole
#     mutating sequence, so two concurrent warms cannot interleave cache
#     writes or manifest lines.
#   - Manifests live OUTSIDE the transferable cache dir.
#
# PRUNING is out of scope (plan follow-on): the manifest written here is its
# input (keep-set = union of recent warms per repo).
set -euo pipefail

usage() {
  cat <<EOF >&2
usage: $(basename "$0") <flakeref> [attr]

  <flakeref>  The repository to warm: a local checkout directory (at a
              reviewed commit, normally main) or any flakeref nix
              understands (e.g. github:owner/repo/main).
  [attr]      The devShell attribute name; default 'default'. Resolved as
              devShells.$target_system.<attr> — never the host-native attr.

Run init-prewarm-cache.sh once first. Environment: WRIT_PREWARM_DIR,
WRIT_PREWARM_KEY_NAME, WRIT_PREWARM_SYSTEM (see common.sh).
EOF
  exit 2
}

# Shared layout (base, key_name + validation, target_system, keys_dir,
# cache_dir, manifest_dir, profiles_dir, secret_key, public_key). One
# definition, shared with init-prewarm-cache.sh, so we sign with exactly the
# key it created.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "$dir/common.sh"

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
raw_flakeref="$1"
attr="${2:-default}"

# The attr is interpolated into an attribute path and a profile filename;
# constrain it the same way common.sh constrains the key name.
case "$attr" in
  "" | *[!A-Za-z0-9._-]* | *..*)
    echo "error: attr must be a non-empty name of [A-Za-z0-9._-] with no '..'; got '$attr'." >&2
    exit 1
    ;;
esac

# --- preconditions -----------------------------------------------------------

# nix: archive/eval/print-dev-env/copy. jq: parse the archive's --json tree.
for tool in nix jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool not found on PATH." >&2
    exit 1
  fi
done

# Flake-consuming nix commands below need both experimental features; the
# builder VM may not have them enabled globally. Keep the flag list in one
# place.
nix_flags=(--extra-experimental-features 'nix-command flakes')

# PLATFORM GUARD. Realising the devShell needs builds FOR the guest system,
# which requires building ON it (no remote builders are configured here). An
# unguarded run on the operator's Mac would resolve and sign the host-native
# (darwin) devShell — a closure no guest can substitute, discovered only when
# the strict warm 404s. Fail here with the real explanation instead.
current_system="$(nix "${nix_flags[@]}" eval --impure --raw --expr builtins.currentSystem)"
if [ "$current_system" != "$target_system" ]; then
  echo "error: this host is $current_system but the guests need $target_system closures." >&2
  echo "       Run this on the $target_system egress builder VM (or set WRIT_PREWARM_SYSTEM" >&2
  echo "       if your guests genuinely differ)." >&2
  exit 1
fi

# Signing key must be present, a regular file, and readable by us — we can't
# sign without it. (init-prewarm-cache.sh creates it 0600.)
if [ -L "$secret_key" ] || [ ! -f "$secret_key" ]; then
  echo "error: signing key $secret_key missing or not a regular file; run init-prewarm-cache.sh first." >&2
  exit 1
fi
if [ ! -r "$secret_key" ]; then
  echo "error: signing key $secret_key not readable by $(id -un); run as the key's owner." >&2
  exit 1
fi

# Cache dir must be a real directory (not a symlink) — we write narinfos/nars
# into it and the runbook rsyncs it verbatim.
if [ -L "$cache_dir" ]; then
  echo "error: cache dir $cache_dir is a symlink." >&2
  exit 1
fi
if [ ! -d "$cache_dir" ]; then
  echo "error: cache dir $cache_dir not found; run init-prewarm-cache.sh first." >&2
  exit 1
fi

# Resolve the flakeref. A directory is canonicalised to an absolute path so
# the meaning never depends on nix's cwd handling; anything else (URL /
# registry ref) is honoured verbatim — nix fetches it itself (this VM has
# egress).
if [ -d "$raw_flakeref" ]; then
  flakeref="$(cd "$raw_flakeref" && pwd)"
  if [ ! -f "$flakeref/flake.nix" ]; then
    echo "error: $flakeref has no flake.nix." >&2
    exit 1
  fi
  # EXACTNESS, fail-closed: a local directory must be a git work tree whose
  # clean status we successfully VERIFIED — anything less (no git, not a work
  # tree, `git status` itself failing) is refused, because a tree whose
  # exactness cannot be checked could be a dirty or no-commit's tree and the
  # signature would attest to nothing reviewable. Modified tracked files are
  # refused for the same reason; untracked files are tolerated (a git-backed
  # flake archives tracked content only, so they cannot change what is
  # warmed). Loudly note a non-main branch; the signature's meaning is
  # "warmed from main".
  if ! command -v git >/dev/null 2>&1; then
    echo "error: git not found on PATH; it is required to verify a local checkout's exactness." >&2
    exit 1
  fi
  if ! git -C "$flakeref" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "error: $flakeref is not a git work tree. The pre-warm signature attests a reviewed" >&2
    echo "       commit; warm a git checkout (or a remote flakeref like github:owner/repo/main)." >&2
    exit 1
  fi
  if ! status_out="$(git -C "$flakeref" status --porcelain)"; then
    echo "error: 'git status' failed in $flakeref; refusing to warm a tree whose cleanliness cannot be verified." >&2
    exit 1
  fi
  dirty="$(printf '%s\n' "$status_out" | grep -v '^??' || true)"
  if [ -n "$dirty" ]; then
    echo "error: $flakeref has modified tracked files; commit or stash before warming:" >&2
    printf '%s\n' "$dirty" >&2
    exit 1
  fi
  branch="$(git -C "$flakeref" symbolic-ref --short -q HEAD || echo "(detached HEAD)")"
  if [ "$branch" != "main" ]; then
    echo "WARNING: warming branch '$branch', not 'main'. The pre-warm signature is" >&2
    echo "         normally the attestation that a closure came from reviewed main." >&2
  fi
else
  flakeref="$raw_flakeref"
fi

# Resolve the revision ONCE and PIN every later nix invocation to it. The
# metadata's `.url` is the rev-locked flakeref (github:owner/repo/<rev>;
# git+file://…?rev=<rev>): a mutable ref like github:owner/repo/main is
# dereferenced exactly here, so a branch that advances mid-warm (or a fetcher
# cache that expires between steps) cannot make the signed closure disagree
# with the manifest's recorded rev. A flakeref that resolves to no revision
# (a tarball, a non-git path) is refused outright: nothing reviewable to
# attest. --no-update-lock-file: a stale lock — flake.nix and flake.lock
# disagreeing — fails here rather than warming an in-memory updated input
# graph the committed repo will not use.
metadata_json="$(nix "${nix_flags[@]}" flake metadata --json --no-update-lock-file "$flakeref")"
rev="$(printf '%s' "$metadata_json" | jq -r '.revision // empty')"
pinned_flakeref="$(printf '%s' "$metadata_json" | jq -r '.url // empty')"
if [ -z "$rev" ] || [ -z "$pinned_flakeref" ]; then
  echo "error: $flakeref resolves to no git revision; the manifest must record the exact commit the signature attests." >&2
  exit 1
fi
echo "==> warming $flakeref (rev $rev, pinned as $pinned_flakeref), devShell attr '$attr' for $target_system"

# --- lock --------------------------------------------------------------------
# ONE host-level lock around the whole mutating sequence (cache writes +
# manifest appends): two concurrent warms must not interleave. Atomic mkdir is
# create-or-fail on POSIX with no external dependency (works on any builder,
# unlike flock(1)). The lock lives OUTSIDE the transferable cache dir.
#
# A stale lock (a previous warm killed mid-run) would otherwise wedge all
# future warms: we record our PID inside the lockdir; on contention we reclaim
# only if the recorded PID is dead. We never auto-reclaim a live lock.
lock_dir="$base/warm.lock"
# `held` gates the release trap: only ever rm the lock dir we actually own, so
# a failed acquire (timeout below) never deletes the live holder's lock.
held=0
release_lock() {
  if [ "$held" -eq 1 ]; then
    rm -rf "$lock_dir" 2>/dev/null || true
  fi
}
trap 'release_lock' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

acquire_lock() {
  local tries=0 owner
  while ! mkdir "$lock_dir" 2>/dev/null; do
    owner=""
    [ -f "$lock_dir/pid" ] && owner="$(cat "$lock_dir/pid" 2>/dev/null || true)"
    if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
      tries=$((tries + 1))
      if [ "$tries" -ge 60 ]; then
        echo "error: could not acquire $lock_dir after 60s; warm held by live PID $owner." >&2
        exit 1
      fi
      sleep 1
      continue
    fi
    # No live owner: the lock is stale (holder died). Reclaim it; a race here
    # just means another waiter wins the re-mkdir and we keep waiting.
    # (Residual narrow window: a holder that has mkdir'd but not yet written
    # its pid looks stale; acceptable for a manual warmer.)
    echo "warn: reclaiming stale lock $lock_dir (owner PID '${owner:-unknown}' not alive)." >&2
    rm -rf "$lock_dir" 2>/dev/null || true
  done
  # Mark held BEFORE writing pid so the release trap cleans up even if the
  # pid write fails.
  held=1
  echo "$$" > "$lock_dir/pid"
}

acquire_lock

# --- manifest ----------------------------------------------------------------
# One append-only line per warmed store path, OUTSIDE the transferable cache
# dir, split per kind (input sources vs devShell closure) so the pruning
# follow-on can treat them distinctly. TSV: ts <TAB> flakeref <TAB> rev <TAB>
# path. Written under the lock, so no interleaving with a concurrent warm.
mkdir -p "$manifest_dir" "$profiles_dir"
chmod 700 "$manifest_dir" "$profiles_dir"
inputs_log="$manifest_dir/inputs-warmed.log"
closure_log="$manifest_dir/devshells-warmed.log"
run_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

manifest_record() {
  # $1 = log file, $2 = store path
  printf '%s\t%s\t%s\t%s\n' "$run_ts" "$raw_flakeref" "$rev" "$2" >> "$1"
}

signed_dest="file://$cache_dir?secret-key=$secret_key"

# --- 1. flake-input source trees ----------------------------------------------
# `nix flake archive --json` copies the flake's and ALL (transitive) inputs'
# source trees into the LOCAL store — fetching any missing ones from their
# origins here, on the egress builder — and prints the path tree. We then sign
# only the INPUT trees into the cache: the flake's own top-level tree changes
# every commit and the guest never substitutes it (it has the brokered
# checkout), so copying it would only bloat the durable cache. The strict warm
# needs these inputs present — the pre-warm view is its ONLY substituter, so
# there is no upstream to supply even nixpkgs.
echo "==> archiving locked flake inputs"
archive_json="$(nix "${nix_flags[@]}" flake archive --json --no-update-lock-file "$pinned_flakeref")"
input_paths="$(printf '%s' "$archive_json" | jq -r '[.inputs | .. | .path? // empty] | unique[]' | grep '^/nix/store/' || true)"
if [ -z "$input_paths" ]; then
  echo "    note: flake has no inputs; nothing to archive."
else
  input_count="$(printf '%s\n' "$input_paths" | wc -l | tr -d ' ')"
  echo "    signing $input_count input source path(s) into the cache"
  # STREAM into `nix copy --stdin` (no argv splat). The destination store URL
  # carries the secret-key query, signing each narinfo as it is written.
  printf '%s\n' "$input_paths" \
    | nix "${nix_flags[@]}" copy --stdin --to "$signed_dest"
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    manifest_record "$inputs_log" "$p"
  done <<< "$input_paths"
fi

# --- 2. devShell closure --------------------------------------------------------
# Force the system-qualified attr (never host-native resolution) on the
# rev-PINNED flakeref, then assert the resolved derivation really builds for
# the guest system — a flake that overrides `system` per-shell would slip
# past the qualification alone.
installable="$pinned_flakeref#devShells.$target_system.$attr"
echo "==> resolving $installable"
if ! drv="$(nix "${nix_flags[@]}" eval --raw "$installable.drvPath")"; then
  echo "error: could not resolve a derivation for $installable (does the flake define devShells.$target_system.$attr?)." >&2
  exit 1
fi
[ -n "$drv" ] || { echo "error: empty derivation path for $installable." >&2; exit 1; }
sys="$(nix "${nix_flags[@]}" eval --raw "$installable.system")"
if [ "$sys" != "$target_system" ]; then
  echo "error: REFUSING to warm $installable: its derivation builds for '$sys', not '$target_system'; the guests could never substitute it." >&2
  exit 1
fi
echo "    drv: $drv (system asserted: $sys)"

# Realise the devShell environment into a PROFILE. `nix print-dev-env
# --profile` realises exactly what the guest's `nix develop` will demand (the
# same env derivation, including build-time inputs such as FOD fetches) and
# leaves the profile as a gc-root under profiles/, so a re-warm after a lock
# bump only builds the delta. The printed env script itself is discarded —
# realisation is the point, and unlike `nix develop --command` this never
# executes the repo's shellHook outside the build sandbox.
# Slug from the CANONICAL flakeref (not the raw arg), so `.`, `./repo`, and
# the absolute path all reuse one profile generation chain.
profile_slug="$(printf '%s#%s' "$flakeref" "$attr" | tr -c 'A-Za-z0-9._-' '-')"
profile="$profiles_dir/$profile_slug"
echo "==> realising the devShell closure (builds run here, on the egress builder)"
nix "${nix_flags[@]}" print-dev-env --no-update-lock-file --profile "$profile" "$installable" > /dev/null

# The profile symlink resolves to the realised env store path; its runtime
# closure is the full set the guest substitutes.
env_path="$(nix "${nix_flags[@]}" path-info "$profile")"
closure="$(nix-store -qR "$env_path")"
closure_count="$(printf '%s\n' "$closure" | wc -l | tr -d ' ')"
echo "    env: $env_path ($closure_count path(s) in closure)"

# Sign the whole closure into the cache. A single installable: nix copy
# computes and copies the closure itself (no argv splat to worry about).
echo "==> signing the devShell closure into the cache"
nix "${nix_flags[@]}" copy --to "$signed_dest" "$env_path"
while IFS= read -r p; do
  [ -n "$p" ] || continue
  manifest_record "$closure_log" "$p"
done <<< "$closure"

echo
echo "warm-devshell-cache: done."
echo "  warmed:   $flakeref (rev $rev) devShells.$target_system.$attr"
echo "  cache:    $cache_dir (signed with $key_name)"
echo "  manifest: $inputs_log, $closure_log"
echo "  profile:  $profile (gc-root; keeps re-warms incremental)"
echo
echo "Next: transfer $cache_dir to the broker host's nix_prewarm_cache_dir"
echo "(nar/ first, then the narinfos — see README.md)."
