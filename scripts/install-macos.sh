#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/install-macos.sh [SRC_DIR]

Install writ and writd to a stable path and give writd a stable code-signing
identifier, so the macOS Application Firewall keys on one path and one
designated requirement across rebuilds (see the firewall discussion in
docs/plans/2026-09-16-macos-firewall-stable-identity.md).

SRC_DIR defaults to target/release. Build first with `cargo build --release`.

Both binaries are installed; only writd is signed with the stable identity,
because only writd binds a TCP listener the firewall filters. If the Stage 2
signing identity exists (scripts/create-writd-signing-identity.sh) it is used;
otherwise writd is signed ad-hoc with a note, which stabilises the identifier
but not the full requirement.

Always run the installed writd from this path; a writd run from target/ or the
Nix store is a different path (and identity) to the firewall.

Environment overrides:
  WRIT_BIN_DIR          install destination directory (default: ~/.local/bin)
  WRIT_WRITD_IDENTIFIER code-signing identifier for writd (default: org.writ.writd)
  WRIT_SIGN_IDENTITY_CN signing identity common name (default: "org.writ.writd signing")
  WRIT_SIGN_KEYCHAIN    keychain holding the signing identity, if not on the
                        default search list (must match create-writd-signing-identity.sh)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

SRC_DIR="${1:-target/release}"
BIN_DIR="${WRIT_BIN_DIR:-$HOME/.local/bin}"
IDENTIFIER="${WRIT_WRITD_IDENTIFIER:-org.writ.writd}"
SIGN_CN="${WRIT_SIGN_IDENTITY_CN:-org.writ.writd signing}"

command -v codesign >/dev/null 2>&1 || { echo "error: this script is macOS-only (needs codesign)" >&2; exit 1; }
for bin in writ writd; do
  [[ -f "$SRC_DIR/$bin" ]] || { echo "error: $SRC_DIR/$bin not found; build with 'cargo build --release'" >&2; exit 1; }
done

mkdir -p "$BIN_DIR"
install -m 0755 "$SRC_DIR/writ"  "$BIN_DIR/writ"
install -m 0755 "$SRC_DIR/writd" "$BIN_DIR/writd"

# A non-default keychain (WRIT_SIGN_KEYCHAIN) is not on the search list, so the
# lookup and the signing must both be told which keychain to use, or a real
# identity would silently fall back to ad-hoc.
SIGN_KEYCHAIN="${WRIT_SIGN_KEYCHAIN:-}"
find_args=(-p codesigning)
[[ -n "$SIGN_KEYCHAIN" ]] && find_args+=("$SIGN_KEYCHAIN")

# Resolve the identity whose common name is EXACTLY "$SIGN_CN" to its SHA-1
# fingerprint and sign by that, so neither the lookup nor `codesign --sign`
# matches a different identity by substring. The quotes around "$SIGN_CN" make
# the grep a whole-name match against find-identity's `N) <sha1> "<name>"` lines.
# -v: codesign uses only *valid* identities, so looking up anything less would
# hand codesign a fingerprint it then rejects with "no identity found".
sign="-"
# `|| true`: grep exits non-zero when the identity is absent, and pipefail +
# set -e would abort before the ad-hoc fallback could run.
sha="$(security find-identity -v "${find_args[@]}" 2>/dev/null \
  | grep -F "\"${SIGN_CN}\"" | grep -oE '[0-9A-Fa-f]{40}' | head -n1 || true)"
if [[ -n "$sha" ]]; then
  sign="$sha"
elif security find-identity "${find_args[@]}" 2>/dev/null | grep -qF "\"${SIGN_CN}\""; then
  # Present but invalid. Failing beats the ad-hoc fallback here: silently
  # signing ad-hoc would look like a working install while the firewall
  # requirement quietly degrades to a per-build cdhash.
  echo "error: signing identity '${SIGN_CN}' exists but is not valid for code signing," >&2
  echo "       so codesign would refuse it ('no identity found'). Usual cause: its" >&2
  echo "       certificate is not trusted — re-run scripts/create-writd-signing-identity.sh," >&2
  echo "       which marks it trusted. (Also check 'security list-keychains' lists a" >&2
  echo "       keychain path that actually exists.)" >&2
  exit 1
else
  echo "note: signing identity '${SIGN_CN}' not found; signing writd ad-hoc." >&2
  echo "      run scripts/create-writd-signing-identity.sh first for a rebuild-stable requirement." >&2
  echo "      (already ran it? check 'security list-keychains' — a search list naming a" >&2
  echo "      nonexistent keychain path hides identities from codesign)" >&2
fi

codesign_args=(--force --sign "$sign" --identifier "$IDENTIFIER")
if [[ "$sign" != "-" && -n "$SIGN_KEYCHAIN" ]]; then
  codesign_args+=(--keychain "$SIGN_KEYCHAIN")
fi
codesign "${codesign_args[@]}" "$BIN_DIR/writd"

echo "installed:"
echo "  $BIN_DIR/writ"
echo "  $BIN_DIR/writd  (signed as ${IDENTIFIER})"
echo "writd designated requirement:"
codesign -d -r- "$BIN_DIR/writd" 2>&1 | sed -n 's/^designated => /  /p'
echo "next: scripts/allow-writd-firewall.sh   # one-time firewall allow (needs sudo)"
