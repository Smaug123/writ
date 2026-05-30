#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/prove-flake-offline.sh [--flake DIR] [--system SYSTEM] [--keep]

Stage-0 proof for writ's planned flake-input provisioning (see
docs/design / the flake-input-provisioning plan).

The design claim under test: the broker, on the host (which has egress),
runs `nix flake archive` to copy a repo's *locked* flake inputs into a
binary cache it serves; the no-egress guest then enters the devShell using
only that cache, never contacting github. The make-or-break question is:

  when the flake input's github origin is UNREACHABLE (firewalled), does
  Nix fall back to substituting the locked input from the cache, or does it
  hard-fail on the blocked origin?

This harness answers that on the host, without a VM and without root, by:

  1. archiving a flake's inputs into a file:// cache (online), then
  2. running a fresh, isolated Nix consumer under `sandbox-exec` with all IP
     egress denied (so github is genuinely unreachable, exactly like the
     guest firewall), pointed at only that cache as a substituter.

It asserts a NEGATIVE control (empty cache => the consumer fails trying to
reach github, proving the isolation is real and the test is not vacuous) and
a POSITIVE case (archive cache => the consumer succeeds by substituting the
input). macOS only: it relies on `sandbox-exec` for root-free egress denial.

Options:
  --flake DIR       Prove a real checked-out repo's inputs instead of the
                    built-in minimal flake. DIR must contain a committed
                    flake.lock (the harness will not mutate it). Archiving a
                    real repo's inputs (e.g. nixpkgs) may download a lot.
  --system SYSTEM   Guest system whose devShell is evaluated in --flake mode.
                    Default: aarch64-linux (what the writ guest evaluates).
                    Evaluation is host-OS-agnostic; only input *sources* are
                    realised, nothing is built.
  --keep            Do not delete the temporary working tree on exit.
  -h, --help        Show this help.
EOF
}

log() { printf '[prove-flake-offline] %s\n' "$*"; }
die() { printf '[prove-flake-offline] error: %s\n' "$*" >&2; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

FLAKE_DIR=""
SYSTEM="aarch64-linux"
KEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --flake) FLAKE_DIR="${2:?--flake needs a directory}"; shift 2 ;;
    --system) SYSTEM="${2:?--system needs a value}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only: this harness uses sandbox-exec for root-free egress denial"
require_cmd nix
require_cmd sandbox-exec

# The isolated chroot store's parent must not be a symlink, which rules out
# /tmp, $TMPDIR and /var on macOS (all symlinks into /private). $HOME is a real
# directory, so anchor the whole working tree there.
BASE="$(mktemp -d "$HOME/.writ-prove-flake-offline.XXXXXX")"
cleanup() {
  # Nix store paths are read-only (0444/0555); make them writable before rm.
  chmod -R u+w "$BASE" 2>/dev/null || true
  if [[ "$KEEP" == "1" ]]; then
    printf '[prove-flake-offline] kept working tree: %s\n' "$BASE" >&2
  else
    rm -rf "$BASE" 2>/dev/null || true
  fi
}
trap cleanup EXIT

CACHE="$BASE/cache"
EMPTY="$BASE/empty"
PROFILE="$BASE/no-egress.sb"
mkdir -p "$CACHE" "$EMPTY"

# Deny all outbound IP traffic (so github is unreachable) while still allowing
# unix-domain sockets, which Nix needs to talk to the local daemon.
cat > "$PROFILE" <<'SB'
(version 1)
(allow default)
(deny network-outbound (remote ip))
(allow network-outbound (remote unix-socket))
SB

NIX_FF=(--extra-experimental-features nix-command --extra-experimental-features flakes)

if [[ -n "$FLAKE_DIR" ]]; then
  [[ -f "$FLAKE_DIR/flake.nix" ]] || die "no flake.nix in $FLAKE_DIR"
  [[ -f "$FLAKE_DIR/flake.lock" ]] || die "$FLAKE_DIR has no committed flake.lock (v1 requires a locked flake)"
  FLAKE_REF="$FLAKE_DIR"
  # Evaluating .drvPath forces every input source referenced by the devShell's
  # derivation attributes (builder, buildInputs, shellHook, ...) to be realised
  # into the store -- exactly what `nix develop` needs -- without building any
  # output. NB: .name is too shallow; a real shell can compute its name without
  # touching most inputs, which would make the proof vacuous.
  FORCE_ATTR="devShells.$SYSTEM.default.drvPath"
  log "flake: $FLAKE_REF  (forcing eval of .$FORCE_ATTR; input sources realised, nothing built)"
else
  FLAKE_REF="$BASE/flake"
  mkdir -p "$FLAKE_REF"
  cat > "$FLAKE_REF/flake.nix" <<'EOF'
{
  description = "writ prove-flake-offline minimal consumer flake";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  outputs = { self, flake-utils }: {
    # Reading a file out of the input forces its SOURCE store path to be
    # realised -- the same thing `nix develop` does when it evaluates a real
    # flake. `nix flake metadata`/`archive` do NOT force this and so make a
    # vacuous test.
    probe = builtins.substring 0 16 (builtins.readFile (flake-utils + "/flake.nix"));
  };
}
EOF
  FORCE_ATTR="probe"
  log "flake: built-in minimal flake (input: flake-utils)"
fi

log "phase 1: archive locked flake inputs into a broker-style file cache (online)"
if [[ -z "$FLAKE_DIR" ]]; then
  nix "${NIX_FF[@]}" flake lock "$FLAKE_REF" >/dev/null
fi
# --no-update-lock-file (not merely --no-write-lock-file) so a STALE committed
# lock fails closed: --no-write would still let Nix resolve and archive an
# updated graph in memory, testing inputs that are not in the committed lock.
nix "${NIX_FF[@]}" flake archive --to "file://$CACHE" --no-update-lock-file "$FLAKE_REF" >/dev/null
narinfos="$(find "$CACHE" -name '*.narinfo' | wc -l | tr -d ' ')"
[[ "$narinfos" -gt 0 ]] || die "flake archive produced no narinfos in $CACHE"
log "archived $narinfos input store path(s)"

# Run a fresh, isolated Nix consumer with all IP egress denied, pointed at one
# substituter cache. Fresh HOME + chroot store guarantee no pre-cached copy.
consume() {
  local subcache="$1" home store
  home="$(mktemp -d "$BASE/home.XXXXXX")"
  store="$(mktemp -d "$BASE/store.XXXXXX")"
  sandbox-exec -f "$PROFILE" env -i PATH="$PATH" HOME="$home" XDG_CACHE_HOME="$home/.cache" \
    nix "${NIX_FF[@]}" eval \
      --store "local?root=$store" \
      --substituters "file://$subcache" \
      --extra-trusted-substituters "file://$subcache" \
      --no-use-registries \
      --no-update-lock-file \
      "$FLAKE_REF#$FORCE_ATTR"
}

log "phase 2: NEGATIVE control -- egress blocked, empty cache (must fail reaching github)"
neg_out="$BASE/neg.out"
if consume "$EMPTY" >"$neg_out" 2>&1; then
  sed 's/^/    | /' "$neg_out" >&2
  die "negative control unexpectedly SUCCEEDED -- the consumer reached the input some other way, so the test is vacuous"
fi
if ! grep -Eq 'github\.com|Could not connect|Failed to connect|unable to download' "$neg_out"; then
  sed 's/^/    | /' "$neg_out" >&2
  die "negative control failed, but not because github was blocked -- the environment is not isolating as expected"
fi
log "negative control failed as expected (github genuinely unreachable, input absent)"

log "phase 3: POSITIVE -- egress blocked, archive cache as the only substituter (must succeed)"
pos_out="$BASE/pos.out"
if ! consume "$CACHE" >"$pos_out" 2>&1; then
  sed 's/^/    | /' "$pos_out" >&2
  die "positive case FAILED -- Nix did not fall back to substituting the input from the cache"
fi
log "positive case succeeded: $(tail -1 "$pos_out")"

log "PROVED: with the input origin firewalled, Nix substitutes locked flake inputs from the"
log "        broker-style cache instead of failing. The flake-input provisioning design holds."
