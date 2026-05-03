#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/prove-vm-http-nix-cache-route.sh

Manual proof harness for the VM HTTP Nix cache route skeleton.

This runs the ignored Rust proof that starts a localhost VM HTTP listener,
writes a temporary netrc entry, and asks real host Nix to query the brokered
cache URL. The cache intentionally returns a missing narinfo; the oracle is
that Nix reaches that authenticated miss without putting the bearer token in
the URL, argv, stdout, or stderr.
EOF
}

log() {
  printf '[prove-vm-http-nix] %s\n' "$*"
}

die() {
  printf '[prove-vm-http-nix] error: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

choose_cargo() {
  if command -v cargo >/dev/null 2>&1; then
    CARGO_CMD=(cargo)
    return
  fi
  if command -v nix >/dev/null 2>&1; then
    CARGO_CMD=(nix develop -c cargo)
    return
  fi
  die "missing required command: cargo, or nix for the repo development shell"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_CMD=()

require_cmd nix
choose_cargo

log "running ignored VM HTTP Nix cache route proof"
(
  cd "$ROOT_DIR"
  "${CARGO_CMD[@]}" test --lib \
    vm_http::tests::nix_cli_can_authenticate_to_vm_http_nix_cache_route_with_netrc \
    -- --ignored --nocapture
)

log "VM HTTP Nix cache route proof succeeded"
