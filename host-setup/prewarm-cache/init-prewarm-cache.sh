#!/usr/bin/env bash
# Initialise the pre-warm signing cache on the egress builder VM (PW4 of
# docs/plans/2026-06-07-prewarmed-devshell-cache.md).
#
# This lays the foundation the warmer (warm-devshell-cache.sh) builds on: a
# binary-cache signing keypair and the cache directory whose contents the
# runbook later transfers to the broker host's `nix_prewarm_cache_dir`. The
# signature this key produces *means* "a human warmed this exact closure from
# main" — it is what lets the broker admit, and the no-egress guest accept, an
# input-addressed (non-self-certifying) devShell closure path.
#
# Two invariants are established here and relied on by everything downstream:
#   1. The signing PRIVATE key lives OUTSIDE the transferable cache dir. Only
#      `cache/` is ever rsync'd to the broker host; the key must never ride
#      along (the broker and guest hold only the PUBLIC key, via
#      `nix_cache_trusted_public_keys`).
#   2. The keypair is generated ONCE and never regenerated: regenerating would
#      invalidate the public key already registered in broker configs, turning
#      every previously-warmed path untrusted.
#
# Idempotent: re-running verifies and re-asserts modes but never clobbers the
# key or the cache contents. Runs entirely as the invoking user under $HOME —
# no sudo, nothing under /etc.
set -euo pipefail

# Shared layout (base, key_name + validation, target_system, keys_dir,
# cache_dir, manifest_dir, profiles_dir, secret_key, public_key). One
# definition, shared with warm-devshell-cache.sh.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=./common.sh
. "$dir/common.sh"

# `find` is used by the hard-link safety check below; without it that check
# would silently pass (an empty `$(find ...)`), skipping a real defence. Treat
# it as a hard dependency, like nix.
for tool in nix-store nix find; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool not found on PATH." >&2
    exit 1
  fi
done

# Refuse a symlinked cache/ or keys/ leaf BEFORE creating or writing anything.
# A `keys -> cache` symlink (or vice versa) would make the mkdir/chmod and the
# later key write follow into the transferable cache dir, landing the 0600
# secret where the runbook's rsync would ship it to the broker host — breaking
# invariant 1.
for d in "$cache_dir" "$keys_dir"; do
  if [ -L "$d" ]; then
    echo "error: $d is a symlink; WRIT_PREWARM_DIR must hold real, distinct cache/ and keys/ directories." >&2
    exit 1
  fi
done

# 0700 keys dir: defence in depth around the 0600 secret key.
mkdir -p "$cache_dir"
mkdir -p "$keys_dir"
chmod 700 "$keys_dir"

# Belt-and-braces over the leaf check: now both exist as real dirs, assert the
# keys dir does not RESOLVE to or inside the cache dir (catches deeper aliasing
# a leaf-symlink check can't see, e.g. a symlinked ancestor). pwd -P
# canonicalises away every symlink in the path.
cache_real="$(cd "$cache_dir" && pwd -P)"
keys_real="$(cd "$keys_dir" && pwd -P)"
case "$keys_real/" in
  "$cache_real"/)
    echo "error: keys dir and cache dir resolve to the same path ($keys_real)." >&2
    exit 1
    ;;
  "$cache_real"/*)
    echo "error: keys dir ($keys_real) resolves inside the transferable cache dir ($cache_real); the signing key would be shipped to the broker host." >&2
    exit 1
    ;;
esac

# The keys dir is real (checked above), but a key FILE could still be a
# pre-created symlink pointing into the cache dir (a restore, a manual slip).
# The generate/chmod/convert steps below would follow it and write or expose
# the secret under cache/. Require the key paths to be regular files or absent
# — never symlinks (incl. dangling) or other special types.
for f in "$secret_key" "$public_key"; do
  if [ -L "$f" ] || { [ -e "$f" ] && [ ! -f "$f" ]; }; then
    echo "error: $f is a symlink or non-regular file; refusing to write the key through it." >&2
    exit 1
  fi
done

# Generate the keypair only on first run — never regenerate an existing one
# (invariant 2: that would invalidate the public key already registered in
# broker configs).
if [ -e "$secret_key" ]; then
  echo "Signing key already present at $secret_key — verifying."
else
  echo "Generating binary-cache signing keypair '$key_name'..."
  # nix-store --generate-binary-cache-key <name> <secret-file> <public-file>
  nix-store --generate-binary-cache-key "$key_name" "$secret_key" "$public_key"
fi

# Re-apply the secret mode on every run (invariant 1): a partial previous run,
# a restore, or a manual edit could have left it lax. Cheap and idempotent.
chmod 600 "$secret_key"

# A hard link from the cache dir to the secret's inode would let the runbook's
# rsync ship the key bytes to the broker host under a second name even though
# the secret "lives" in keys/ — same inode, two paths, and modes are per-inode
# so 0600 doesn't help. A freshly generated key has exactly one link; more than
# one means something else references this inode. Fail closed and let the
# operator investigate. (`find -links` is portable across GNU/BSD, unlike
# stat's divergent flags.)
if [ -n "$(find "$secret_key" ! -links 1 -print)" ]; then
  echo "error: $secret_key has more than one hard link; an extra link (e.g. into the transferable cache dir) could ship the key to the broker host. Remove stray links and re-run." >&2
  exit 1
fi

# Derive the public key FROM the secret on every run, written atomically, so
# the value we print (and the operator registers in the broker config) always
# matches the secret actually used to sign — even if .public was lost, never
# written, or went stale. A corrupt secret makes convert fail here (set -e),
# surfacing it rather than emitting a bogus key. The temp file is born inside
# the 0700 keys dir; published 0644 only at the rename.
tmp_pub="$(mktemp "$keys_dir/.public.XXXXXX")"
nix key convert-secret-to-public \
  --extra-experimental-features nix-command \
  < "$secret_key" > "$tmp_pub"
chmod 644 "$tmp_pub"
mv -f "$tmp_pub" "$public_key"

# No nix-cache-info is written here: the broker serves its own synthetic
# cache metadata on /v1/nix/prewarm and reads only `<hash>.narinfo` + `nar/`
# from the transferred dir, and `nix copy --to file://…` initialises the
# local cache layout itself.

echo
echo "Pre-warm signing cache initialised."
echo "  cache dir (transfer ONLY this to the broker host): $cache_dir"
echo "  signing private key (0600, NEVER transfer/commit): $secret_key"
echo
echo "Public key — add this to the broker's vm_http nix_cache_trusted_public_keys:"
echo
cat "$public_key"
echo
echo "Next: warm a repository with warm-devshell-cache.sh, then follow the"
echo "README to transfer $cache_dir to the broker host's nix_prewarm_cache_dir."
