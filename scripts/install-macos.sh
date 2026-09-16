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

sign="-"
if security find-identity -p codesigning 2>/dev/null | grep -Fq "$SIGN_CN"; then
  sign="$SIGN_CN"
else
  echo "note: signing identity '${SIGN_CN}' not found; signing writd ad-hoc." >&2
  echo "      run scripts/create-writd-signing-identity.sh first for a rebuild-stable requirement." >&2
fi

codesign --force --sign "$sign" --identifier "$IDENTIFIER" "$BIN_DIR/writd"

echo "installed:"
echo "  $BIN_DIR/writ"
echo "  $BIN_DIR/writd  (signed as ${IDENTIFIER})"
echo "writd designated requirement:"
codesign -d -r- "$BIN_DIR/writd" 2>&1 | sed -n 's/^designated => /  /p'
echo "next: scripts/allow-writd-firewall.sh   # one-time firewall allow (needs sudo)"
