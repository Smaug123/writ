# shellcheck shell=bash
# shellcheck disable=SC2034 # every variable here exists FOR the sourcing scripts
# Shared layout + name resolution for the pre-warm cache builder scripts.
#
# SOURCED (not executed) by init-prewarm-cache.sh (the key initialiser) and
# warm-devshell-cache.sh (the warmer). Sharing one definition of where the key
# and cache live means the warmer provably signs with the key the initialiser
# created, into the directory the runbook says to transfer — no drift between
# the scripts. Callers must `set -euo pipefail` before sourcing; an unsafe key
# name `exit`s the sourcing script.
#
# Defines: base, key_name, target_system, keys_dir, cache_dir, manifest_dir,
# profiles_dir, secret_key, public_key.

# Base dir is out-of-tree: the key, cache content, manifests, and gc-root
# profiles are builder-VM state; only the *scripts* are version-controlled.
base="${WRIT_PREWARM_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/writ-prewarm}"

# The signing key name becomes the prefix of every narinfo signature and must
# match a `nix_cache_trusted_public_keys` entry on the broker (which is also
# what the guest's nix.conf trusts — one list, both sides). The `-1` suffix
# leaves room to rotate (publish `-2` alongside, retire `-1`) without a
# flag-day. Override only if you know why.
key_name="${WRIT_PREWARM_KEY_NAME:-writ-prewarm-1}"

# Constrain the key name to a safe single basename before it lands in any
# path. It is interpolated into keys/<name>.secret, so a '/' or '..' could
# escape keys_dir and write the PRIVATE key under the transferable cache dir.
# A ':' would also break the `name:base64` signature format. Allow only
# [A-Za-z0-9._-], non-empty, with no '..'.
case "$key_name" in
  "" | *[!A-Za-z0-9._-]* | *..*)
    echo "error: WRIT_PREWARM_KEY_NAME must be a non-empty name of [A-Za-z0-9._-] with no '..'; got '$key_name'." >&2
    exit 1
    ;;
esac

# The guest system the warmed closures must be built for. The agent guests are
# Apple-container Linux VMs matching the broker host's architecture, so this is
# aarch64-linux on Apple silicon (writ's `defaultGuestSystem`). The warmer
# refuses to run on any other system: realising the devShell *requires* a
# builder of this platform, and an unguarded warm on the operator's Mac would
# silently sign a darwin closure no guest can use.
target_system="${WRIT_PREWARM_SYSTEM:-aarch64-linux}"

# Layout: keys/, manifest/, and profiles/ are SIBLINGS of cache/, never under
# it. cache/ is the ONLY directory the runbook transfers to the broker host;
# everything secret (the signing key) or builder-local (manifests, gc-root
# profiles) stays outside it.
keys_dir="$base/keys"
cache_dir="$base/cache"
manifest_dir="$base/manifest"
profiles_dir="$base/profiles"
secret_key="$keys_dir/$key_name.secret"
public_key="$keys_dir/$key_name.public"
