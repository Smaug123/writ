#!/usr/bin/env bash
# Warm a repository's devShell into the DURABLE local pre-warm cache, on a
# single-machine macOS broker, by driving an Apple `container` as the
# aarch64-linux egress builder.
#
# `warm-devshell-cache.sh` must run ON a builder that IS the guest system
# (its platform guard refuses darwin); on an Apple-silicon Mac that builder
# is a Linux container. This script is the missing host-side half: it stands
# up that container (the same guest image the agent VMs use, on the default
# NAT network so it has egress), then runs the committed `init-prewarm-cache.sh`
# + `warm-devshell-cache.sh` INSIDE it against a fresh checkout of the repo.
# The signed `cache/` it produces is already on the broker host, so the
# runbook's "transfer to the broker" step is a no-op — point
# `nix_prewarm_cache_dir` at it and restart writd.
#
# It is the automation of scripts/prove-agent-vm-prewarm-strict.sh's
# `run_prewarm_builder`, generalised from the test fixture to any repo and a
# durable output dir.
#
# WHICH REV. The agent VM's workspace init checks out DEFAULT_WORKSPACE_BRANCH
# — "main" (crates/writ-vm-git/src/lib.rs; src/vm_client.rs requests
# refs/heads/main), NOT the remote's default branch. So this warms `main` by
# default (override with WRIT_PREWARM_REF), matching exactly what
# `agent-vm start --repo <repo>` will demand. Warming a different rev whose
# devShell derivation differs would leave the guest's `nix develop` 404ing
# under the strict warm and falling through to an egress-needing build — the
# very failure this avoids.
#
# SINGLE-MACHINE SECURITY NOTE. The signing key is written to
# $WRIT_PREWARM_DIR/keys/ on THIS host (the container writes it through a bind
# mount). The strict trust model puts the key "only on the builder, never on
# the broker"; here builder and broker are one Mac, so that separation is
# relaxed. It is still sound: the guest only ever sees `cache/` over HTTP and
# never `keys/`. For a true split (separate builder VM), run
# `warm-devshell-cache.sh` there and rsync only `cache/` per README.md.
set -Eeuo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF >&2
usage: $(basename "$0") <repo> [attr]

  <repo>  The repository to warm, as either:
            owner/name              -> https://github.com/owner/name
            a full git URL          -> cloned verbatim (uses your git creds,
                                       so private repos work)
  [attr]  devShell attribute name; default 'default'. Warmed as
          devShells.<guest-system>.<attr>.

Produces a signed pre-warm cache under WRIT_PREWARM_DIR/cache on THIS host.

Environment overrides:
  WRIT_PREWARM_DIR       host pre-warm base, default ~/.local/share/writ-prewarm
  WRIT_PREWARM_SYSTEM    guest system, default derived from arch (aarch64-linux)
  WRIT_PREWARM_IMAGE     builder/guest image, default writ-agent-vm-guest:latest
  WRIT_PREWARM_REF       git ref to clone+warm, default 'main' (the branch the
                         guest's workspace init checks out)
  WRIT_PREWARM_CPUS      builder container vCPUs, default 4
  WRIT_PREWARM_MEMORY    builder container memory, default 8192m
  WRIT_PREWARM_TOOLS_NIXPKGS
                         nixpkgs flakeref for the injected grep/find/jq/flock
                         (the production guest image strips them). Default: the
                         nixpkgs writ itself pins (trusted) — NOT the warmed
                         repo's, which runs as root near the signing key.

Run on the broker Mac with Apple \`container\` installed and
\`container system start\` already done. The builder container needs egress
(the default NAT network provides it).
EOF
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
raw_repo="$1"
attr="${2:-default}"

# Constrain attr exactly as warm-devshell-cache.sh does (it is interpolated
# into an attribute path and a profile filename downstream).
case "$attr" in
  "" | *[!A-Za-z0-9._-]* | *..*)
    echo "error: attr must be a non-empty name of [A-Za-z0-9._-] with no '..'; got '$attr'." >&2
    exit 1
    ;;
esac

# --- host config -------------------------------------------------------------
prewarm_dir="${WRIT_PREWARM_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/writ-prewarm}"
image="${WRIT_PREWARM_IMAGE:-writ-agent-vm-guest:latest}"
cpus="${WRIT_PREWARM_CPUS:-4}"
memory="${WRIT_PREWARM_MEMORY:-8192m}"

# Guest system: the agent guests match the broker's architecture. Default from
# the host arch; override for an x86_64 broker or a cross setup.
if [ -n "${WRIT_PREWARM_SYSTEM:-}" ]; then
  guest_system="$WRIT_PREWARM_SYSTEM"
else
  case "$(uname -m)" in
    arm64 | aarch64) guest_system="aarch64-linux" ;;
    x86_64 | amd64) guest_system="x86_64-linux" ;;
    *)
      echo "error: cannot derive a guest system from arch '$(uname -m)'; set WRIT_PREWARM_SYSTEM." >&2
      exit 1
      ;;
  esac
fi

# --- preconditions -----------------------------------------------------------
# Host tools: container (the builder), git (the clone), python3 (parse the
# repo's flake.lock for its nixpkgs). The committed scripts that run INSIDE
# the container have their own preflight (nix/jq/flock/grep/git).
for tool in container git python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool not found on PATH." >&2
    exit 1
  fi
done
for script in common.sh init-prewarm-cache.sh warm-devshell-cache.sh; do
  if [ ! -f "$dir/$script" ]; then
    echo "error: $dir/$script not found; run this from the host-setup/prewarm-cache checkout." >&2
    exit 1
  fi
done
if ! container system status >/dev/null 2>&1; then
  echo "error: Apple 'container' system is not running; run 'container system start'." >&2
  exit 1
fi
if ! container image inspect "$image" >/dev/null 2>&1; then
  echo "error: builder/guest image '$image' not found; build or load it first" >&2
  echo "       (writ agent-vm build-image), or set WRIT_PREWARM_IMAGE." >&2
  exit 1
fi

# Resolve <repo> to a clone URL (`repo_url`, used only for `git clone`) and a
# REDACTED label (`repo_label`, used for every log line and the manifest-bearing
# slug). owner/name is the common case and mirrors `agent-vm start --repo
# owner/name`; a full URL is honoured verbatim so a private repo clones with
# your configured git credentials.
case "$raw_repo" in
  *://* | git@*)
    repo_url="$raw_repo"
    # Strip any embedded userinfo (https://token@host/...) so a credential
    # never reaches a log line, the manifest, or the on-disk slug. The
    # scp-form `git@host:...` carries no secret, so it is left as-is.
    case "$repo_url" in
      *://*@*) repo_label="${repo_url%%://*}://${repo_url#*://*@}" ;;
      *) repo_label="$repo_url" ;;
    esac
    ;;
  */*)
    case "$raw_repo" in
      *[!A-Za-z0-9._/-]* | */*/* | /* | */)
        echo "error: '$raw_repo' is not an owner/name; pass a full git URL instead." >&2
        exit 1
        ;;
      *)
        repo_url="https://github.com/$raw_repo"
        repo_label="$raw_repo"
        ;;
    esac
    ;;
  *)
    echo "error: '$raw_repo' is neither owner/name nor a git URL." >&2
    exit 1
    ;;
esac

# A filesystem-safe, repo-distinguishing slug for the in-container checkout
# path. warm-devshell-cache.sh records that path as the flakeref in its
# manifest and derives the gc-root profile name from it, so a per-repo slug
# keeps per-repo pruning/auditing and profile separation — a fixed
# `/work/repo` would collapse every repo's bookkeeping into one. Derived from
# the REDACTED label, never repo_url, so a credential can never reach it.
slug="$(printf '%s' "$repo_label" | tr -c 'A-Za-z0-9._-' '-' | sed -E 's/-+/-/g; s/^-//; s/-$//')"
[ -n "$slug" ] || slug="repo"

# --- work dir + container cleanup --------------------------------------------
builder_name="writ-prewarm-builder-$$"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/writ-prewarm-via-container.XXXXXX")"
cleanup() {
  container stop "$builder_name" >/dev/null 2>&1 || true
  container delete "$builder_name" >/dev/null 2>&1 || container rm "$builder_name" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

mkdir -p "$prewarm_dir"

# --- 1. fresh checkout at the rev the guest will use -------------------------
# The guest's workspace init always checks out DEFAULT_WORKSPACE_BRANCH —
# "main" (crates/writ-vm-git/src/lib.rs; src/vm_client.rs requests
# refs/heads/main) — NOT the remote's default branch. Warm that exact ref so
# the closure matches what `agent-vm start --repo <repo>` demands; warming a
# divergent default-HEAD would 404 the strict warm even as this script reports
# success. Override only to warm a different ref deliberately.
ref="${WRIT_PREWARM_REF:-main}"
echo "==> cloning $repo_label (ref $ref)"
git clone --quiet --branch "$ref" -- "$repo_url" "$work_dir/$slug"
if [ ! -f "$work_dir/$slug/flake.nix" ]; then
  echo "error: $repo_label has no flake.nix at the checked-out ref." >&2
  exit 1
fi
rev="$(git -C "$work_dir/$slug" rev-parse HEAD)"
echo "    rev $rev"

# --- 2. nixpkgs for the injected toolset -------------------------------------
# The production guest image strips grep/find/sed/awk (no-egress posture); init
# needs `find` and warm needs `grep`, so ride a real toolset in via `nix shell`.
#
# TRUST: source the toolset from WRIT's OWN pinned nixpkgs — a trusted, reviewed
# ref — NEVER the warmed repo's flake.lock. The driver runs these tools as root,
# OUTSIDE the nix build sandbox, with /prewarm/keys mounted; a repo-pinned
# toolset (an attacker's `github:<evil>/nixpkgs` masquerading via repo ==
# "nixpkgs") would execute repo-controlled binaries with access to the signing
# key. writ's lock is the trust anchor this script already ships under.
if [ -n "${WRIT_PREWARM_TOOLS_NIXPKGS:-}" ]; then
  tools_nixpkgs="$WRIT_PREWARM_TOOLS_NIXPKGS"
else
  writ_lock="$dir/../../flake.lock"
  tools_nixpkgs="$(python3 - "$writ_lock" <<'PY'
import json, sys
try:
    lock = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    sys.exit(0)
for node in lock.get("nodes", {}).values():
    loc = node.get("locked", {})
    if loc.get("type") == "github" and loc.get("repo") == "nixpkgs" and loc.get("rev"):
        print(f'github:{loc["owner"]}/{loc["repo"]}/{loc["rev"]}')
        break
PY
)"
  if [ -z "$tools_nixpkgs" ]; then
    echo "error: could not derive a trusted nixpkgs from writ's flake.lock ($writ_lock);" >&2
    echo "       set WRIT_PREWARM_TOOLS_NIXPKGS to a trusted nixpkgs flakeref." >&2
    exit 1
  fi
fi
echo "    toolset nixpkgs (trusted, from writ): $tools_nixpkgs"

# --- 3. inner driver (runs inside the guest-system container) ----------------
cat > "$work_dir/driver-inner.sh" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
export HOME=/root NIX_CONF_DIR=/root/nix-conf
export WRIT_PREWARM_DIR=/prewarm WRIT_PREWARM_SYSTEM='$guest_system'
# What the daemon's nix.conf prologue gives agent guests, supplied by hand
# here: root builds (the image has no nixbld group) and the flake features.
mkdir -p /root/nix-conf
printf 'experimental-features = nix-command flakes\nbuild-users-group =\n' > /root/nix-conf/nix.conf
# The bind-mounted checkout is host-owned, so root's git needs safe.directory.
git config --global safe.directory '*'
tools=(nix --extra-experimental-features "nix-command flakes" shell
  '$tools_nixpkgs#jq' '$tools_nixpkgs#flock' '$tools_nixpkgs#gnugrep' '$tools_nixpkgs#findutils' -c)
echo "== init-prewarm-cache.sh =="
"\${tools[@]}" bash /prewarm-scripts/init-prewarm-cache.sh
echo "== warm-devshell-cache.sh /work/$slug $attr =="
"\${tools[@]}" bash /prewarm-scripts/warm-devshell-cache.sh '/work/$slug' '$attr'
EOF

# --- 4. start the egress builder + run init + warm ---------------------------
echo "==> starting builder container $builder_name ($guest_system, egress)"
echo "    (realises the devShell closure for $guest_system; expect several minutes)"
container run --name "$builder_name" --cpus "$cpus" --memory "$memory" \
  --volume "$prewarm_dir:/prewarm" \
  --volume "$work_dir:/work" \
  --volume "$dir:/prewarm-scripts" \
  -d "$image" sleep 7200 >/dev/null

# Wait for the container to become exec-able (mirrors the oracle's poll).
ready=""
for _ in $(seq 1 150); do
  if container exec "$builder_name" sh -lc 'true' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.2
done
[ -n "$ready" ] || { echo "error: builder container $builder_name did not become exec-able." >&2; exit 1; }

echo "==> warming inside the builder"
container exec "$builder_name" sh -lc 'bash /work/driver-inner.sh'

# --- 5. read the key, open the cache for host (writd) reads ------------------
public_key="$(container exec "$builder_name" sh -lc 'cat /prewarm/keys/writ-prewarm-1.public')"
case "$public_key" in
  writ-prewarm-1:*) ;;
  *)
    echo "error: unexpected pre-warm public key shape: $public_key" >&2
    exit 1
    ;;
esac
# cache/ and manifest/ are written 0700 under the container's umask; the broker
# (writd) must read cache/ and these assertions read the manifest. keys/ stays
# closed — it is never transferred and the guest never sees it.
container exec "$builder_name" sh -lc 'chmod -R a+rX /prewarm/cache /prewarm/manifest' || true

cache_dir="$prewarm_dir/cache"
echo
echo "warm-via-container: done."
echo "  warmed:   $repo_label (rev $rev) devShells.$guest_system.$attr"
echo "  cache:    $cache_dir"
echo "  key:      $public_key"
echo
echo "Wire it into the broker (writd) config's [agent_vm.vm_http] and restart writd:"
echo "  nix_prewarm_cache_dir = \"$cache_dir\""
echo "  nix_cache_trusted_public_keys = ["
echo "    \"cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=\","
echo "    \"$public_key\","
echo "  ]"
echo
echo "Re-run this to refresh after the repo's default branch moves; already-signed"
echo "paths are skipped on copy."
