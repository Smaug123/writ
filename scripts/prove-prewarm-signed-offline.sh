#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/prove-prewarm-signed-offline.sh [--keep]

PW0 proof for writ's planned pre-warmed devShell closure cache (see
docs/plans/2026-06-07-prewarmed-devshell-cache.md).

Flake-input provisioning (the 2026-05-30 slice) brokers a flake's *input
source trees*, which are content-addressed and so self-certifying: the
broker and guest accept them by hash, no signing key needed. But a
devShell *closure* contains ordinary input-addressed derivation outputs
(compiled binaries, wrappers built atop a nuget/FOD fetch). Those are NOT
self-certifying. To serve them to a no-egress guest they must be SIGNED by
a key the guest trusts. The make-or-break question this slice rests on:

  with the build origin firewalled and local building impossible, does Nix
  realise a signed, INPUT-ADDRESSED store path from a pre-warm cache it
  trusts -- and does it REFUSE that same path when the signing key is not
  trusted?

This harness answers both on the host, without a VM and without root:

  1. (builder, trusted) build a small input-addressed derivation and
     `nix copy` it into a file:// cache signed with a generated key;
  2. (consumer, isolated) under `sandbox-exec` with all IP egress denied
     and a fresh chroot store that holds no derivation for the path (so it
     CANNOT be built, only substituted), substitute the path from the
     cache.

It asserts:
  - NEGATIVE (empty cache): the consumer cannot obtain the path at all
    (not substitutable, not buildable) -- proving the test is not vacuous;
  - NEGATIVE (untrusted key): the signed cache is present but its key is
    NOT trusted and require-sigs is on -- the consumer REFUSES the path.
    This is the security-critical control: the whole trust model is that a
    signature means "a human warmed this exact closure from main";
  - POSITIVE (trusted key): the consumer substitutes the path.

The probe derivation needs no network to build, so this proof is hermetic
(no host egress required) and is safe to run anywhere. macOS only: it
relies on `sandbox-exec` for root-free egress denial.

Options:
  --keep            Do not delete the temporary working tree on exit.
  -h, --help        Show this help.
EOF
}

log() { printf '[prove-prewarm-signed] %s\n' "$*"; }
die() { printf '[prove-prewarm-signed] error: %s\n' "$*" >&2; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

KEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --keep) KEEP=1; shift ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only: this harness uses sandbox-exec for root-free egress denial"
require_cmd nix
require_cmd nix-store
require_cmd nix-instantiate
require_cmd sandbox-exec

# The isolated chroot store's parent must not be a symlink, which rules out
# /tmp, $TMPDIR and /var on macOS (all symlinks into /private). $HOME is a real
# directory, so anchor the whole working tree there.
BASE="$(mktemp -d "$HOME/.writ-prove-prewarm-signed.XXXXXX")"
cleanup() {
  # Nix store paths are read-only (0444/0555); make them writable before rm.
  chmod -R u+w "$BASE" 2>/dev/null || true
  if [[ "$KEEP" == "1" ]]; then
    printf '[prove-prewarm-signed] kept working tree: %s\n' "$BASE" >&2
  else
    rm -rf "$BASE" 2>/dev/null || true
  fi
}
trap cleanup EXIT

CACHE="$BASE/prewarm-cache"
EMPTY="$BASE/empty-cache"
PROFILE="$BASE/no-egress.sb"
SECRET_KEY="$BASE/prewarm.secret"
PUBLIC_KEY="$BASE/prewarm.public"
PROBE_NIX="$BASE/prewarm-probe.nix"
mkdir -p "$CACHE" "$EMPTY"

# Deny all outbound IP traffic (so the build origin is unreachable) while still
# allowing unix-domain sockets, which Nix needs to talk to the local daemon.
cat > "$PROFILE" <<'SB'
(version 1)
(allow default)
(deny network-outbound (remote ip))
(allow network-outbound (remote unix-socket))
SB

NIX_FF=(--extra-experimental-features nix-command --extra-experimental-features flakes)

# A minimal INPUT-ADDRESSED derivation (no outputHash -> addressed by the hash
# of its build instructions, exactly like a compiled devShell output, NOT like
# a content-addressed flake input or FOD). A per-run nonce gives it a fresh
# output path each run, so the host store never already holds it and phase 1
# genuinely builds. It needs no network, so the proof is hermetic; egress is
# denied in phase 2 only to mirror the guest firewall and to ensure the cache
# is the sole source.
NONCE="$(nix-instantiate --eval --expr 'builtins.currentTime' 2>/dev/null || date +%s)"
cat > "$PROBE_NIX" <<EOF
derivation {
  name = "writ-prewarm-proof-${NONCE}";
  system = builtins.currentSystem;
  builder = "/bin/sh";
  args = [ "-c" "echo writ-prewarm-proof-${NONCE} > \$out" ];
}
EOF

log "generating a pre-warm binary-cache signing keypair (secret stays here, public is what the guest would trust)"
nix-store --generate-binary-cache-key "writ-prewarm-proof-${NONCE}" "$SECRET_KEY" "$PUBLIC_KEY"
PUBKEY="$(cat "$PUBLIC_KEY")"
log "pre-warm public key: ${PUBKEY}"

log "phase 1: (builder) realise the input-addressed probe and sign it into the pre-warm cache"
DRV="$(nix-instantiate "$PROBE_NIX")"
# A `/bin/sh` builder works because the macOS nix-daemon builds without a
# sandbox by default. This is the egress-capable builder VM in miniature. (Nix
# may warn that the result has no gcroot; harmless -- nothing GCs mid-run.)
OUT="$(nix-store --realise "$DRV")"
[[ -n "$OUT" ]] || die "phase 1 build produced no output path"
log "built input-addressed path: ${OUT}"
nix "${NIX_FF[@]}" copy --to "file://$CACHE?secret-key=$SECRET_KEY" "$OUT" >/dev/null
hash_part="${OUT#/nix/store/}"
hash_part="${hash_part%%-*}"
[[ -f "$CACHE/${hash_part}.narinfo" ]] || die "phase 1 did not write a narinfo for ${hash_part} into the cache"
if ! grep -q '^Sig: ' "$CACHE/${hash_part}.narinfo"; then
  sed 's/^/    | /' "$CACHE/${hash_part}.narinfo" >&2
  die "phase 1 narinfo is not signed -- nix copy --to file://...?secret-key did not sign"
fi
log "signed narinfo written: ${hash_part}.narinfo"

# Substitute the path INTO a fresh chroot store under egress denial. The chroot
# store holds no derivation for the path, so it cannot be built there -- success
# is attributable to substitution alone. `require-sigs true` forces signature
# verification; `trusted-public-keys` is the only thing that admits the key.
consume() {
  local from_cache="$1" trusted_keys="$2" store
  store="$(mktemp -d "$BASE/store.XXXXXX")"
  sandbox-exec -f "$PROFILE" env -i PATH="$PATH" HOME="$BASE" \
    nix "${NIX_FF[@]}" copy \
      --from "file://$from_cache" \
      --to "local?root=$store" \
      --option require-sigs true \
      --option trusted-public-keys "$trusted_keys" \
      "$OUT"
}

log "phase 2: NEGATIVE control -- egress blocked, EMPTY cache (path is neither substitutable nor buildable; must fail)"
neg_empty="$BASE/neg-empty.out"
if consume "$EMPTY" "$PUBKEY" >"$neg_empty" 2>&1; then
  sed 's/^/    | /' "$neg_empty" >&2
  die "empty-cache control unexpectedly SUCCEEDED -- the consumer obtained the path some other way; the test is vacuous"
fi
log "empty-cache control failed as expected (no substituter has the path, and it cannot be built here)"

log "phase 2: NEGATIVE control -- signed cache present but key UNTRUSTED, require-sigs on (must be refused)"
neg_untrusted="$BASE/neg-untrusted.out"
if consume "$CACHE" "" >"$neg_untrusted" 2>&1; then
  sed 's/^/    | /' "$neg_untrusted" >&2
  die "untrusted-key control unexpectedly SUCCEEDED -- a path signed by an untrusted key was accepted; the signature gate is NOT load-bearing"
fi
if ! grep -Eiq 'signature|trusted|untrusted|cannot add path|lacks a (valid )?signature' "$neg_untrusted"; then
  sed 's/^/    | /' "$neg_untrusted" >&2
  die "untrusted-key control failed, but not because of the signature -- check the failure reason"
fi
log "untrusted-key control refused as expected (signature by an untrusted key is rejected)"

log "phase 3: POSITIVE -- egress blocked, signed cache, key TRUSTED, require-sigs on (must succeed by substitution)"
pos_out="$BASE/pos.out"
if ! consume "$CACHE" "$PUBKEY" >"$pos_out" 2>&1; then
  sed 's/^/    | /' "$pos_out" >&2
  die "positive case FAILED -- Nix did not substitute the signed input-addressed path from the trusted cache"
fi
log "positive case succeeded: the signed input-addressed path was substituted offline from the trusted pre-warm cache"

log "PROVED: a signed, input-addressed store path substitutes into a no-egress consumer from a pre-warm"
log "        cache iff its signing key is trusted. The pre-warmed devShell cache design holds: the broker"
log "        can serve such paths (PW1) and the signature is the human's attestation of a main closure."
