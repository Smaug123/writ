#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/allow-writd-firewall.sh

One-time: allow writd through the macOS Application Firewall so its broker/UI
listeners can accept connections from agent VMs.

Why this is needed: the firewall (socketfilterfw) filters incoming connections
per binary. A blocked writd still completes the TCP handshake and the kernel
ACKs the request, but the firewall detaches the socket before accept() returns
it, so accept() hands back a not-connected socket (getpeername EINVAL, recv
ENOTCONN) and the request never reaches the process. Loopback is exempt, which
is why local tools work while an agent VM times out. (This is the symptom that
was long mistaken for an Apple vmnet defect; see
docs/vmnet-accept-bug-and-broker-vm-plan.md.)

Because writd is installed at a stable path (scripts/install-macos.sh) signed
with a stable identity (scripts/create-writd-signing-identity.sh), this allow
survives rebuilds and only needs running once. It needs sudo.

Environment overrides:
  WRIT_BIN_DIR   directory writd was installed in (default: ~/.local/bin)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

BIN_DIR="${WRIT_BIN_DIR:-$HOME/.local/bin}"
WRITD="$BIN_DIR/writd"
FW=/usr/libexec/ApplicationFirewall/socketfilterfw

[[ -x "$FW" ]] || { echo "error: socketfilterfw not found at $FW (macOS only)" >&2; exit 1; }
[[ -f "$WRITD" ]] || { echo "error: writd not installed at $WRITD; run scripts/install-macos.sh first" >&2; exit 1; }

sudo "$FW" --add "$WRITD" >/dev/null
sudo "$FW" --unblockapp "$WRITD" >/dev/null

echo "firewall state for ${WRITD}:"
"$FW" --getappblocked "$WRITD"
