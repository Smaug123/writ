#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/prove-pf-internal-network.sh

Manual proof harness for Apple container internal-network PF filtering.

Requires:
  - macOS with Apple container installed and `container system start` already run
  - root privileges through sudo for pfctl
  - a top-level PF rule in /etc/pf.conf: anchor "writ/session/*"
  - python3, curl, cargo or nix, and an Alpine image usable by Apple container

Environment overrides:
  WRIT_PROVE_IMAGE       OCI image to run, default alpine:latest
  WRIT_PROVE_IPV4_CIDR   internal Apple container subnet, default 192.168.252.0/24
  WRIT_PROVE_IPV4_POOL   broker-owned IPv4 pool, default is the session /24's /16
  WRIT_PROVE_IPV6_CIDR   fallback IPv6 PF prefix for rendering if network inspect
                         reports none; IPv6 probes are skipped in that case,
                         default fd83:b6f2:e57:f536::/64
  WRIT_PROVE_IPV6_POOL   broker-owned IPv6 pool, default is the session /64's /48
  WRIT_PROVE_BROKER_PORT_MIN  minimum allowed broker port, default 49152
  WRIT_PROVE_BROKER_PORT_MAX  maximum allowed broker port, default 65535
EOF
}

log() {
  printf '[prove-pf] %s\n' "$*"
}

die() {
  printf '[prove-pf] error: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/writ-pf-proof.XXXXXX")"
IMAGE="${WRIT_PROVE_IMAGE:-alpine:latest}"
IPV4_CIDR="${WRIT_PROVE_IPV4_CIDR:-192.168.252.0/24}"
IPV4_POOL="${WRIT_PROVE_IPV4_POOL:-}"
IPV6_CIDR="${WRIT_PROVE_IPV6_CIDR:-fd83:b6f2:e57:f536::/64}"
IPV6_POOL="${WRIT_PROVE_IPV6_POOL:-}"
BROKER_PORT_MIN="${WRIT_PROVE_BROKER_PORT_MIN:-49152}"
BROKER_PORT_MAX="${WRIT_PROVE_BROKER_PORT_MAX:-65535}"
SESSION_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
SHORT_ID="${SESSION_ID%%-*}"
NETWORK_NAME="writ-pf-${SHORT_ID}"
VM_NAME="writ-pf-vm-${SHORT_ID}"
BROKER_DIR="${TMP_DIR}/broker"
FORBIDDEN_DIR="${TMP_DIR}/forbidden"
NETWORK_INSPECT_FILE="${TMP_DIR}/network-inspect.txt"
PF_ANCHOR=""
HELPER=""
BROKER_PID=""
FORBIDDEN_PID=""
FORBIDDEN_V6_PID=""
FORBIDDEN_V6_PORT=""
IPV6_GATEWAY=""
IPV6_PROBES_ENABLED=0
CARGO_CMD=()

cleanup_started=0
cleanup() {
  if [[ "$cleanup_started" -eq 1 ]]; then
    return
  fi
  cleanup_started=1

  log "cleaning up VM, network, listeners, and PF anchor"

  if [[ -n "$VM_NAME" ]]; then
    container rm -f "$VM_NAME" >/dev/null 2>&1 || true
    container stop "$VM_NAME" >/dev/null 2>&1 || true
    container delete "$VM_NAME" >/dev/null 2>&1 || true
    container rm "$VM_NAME" >/dev/null 2>&1 || true
  fi

  if [[ -n "$PF_ANCHOR" ]]; then
    sudo "$HELPER" remove \
      --session-id "$SESSION_ID" \
      --ipv4-pool "$IPV4_POOL" \
      --ipv6-pool "$IPV6_POOL" \
      --ipv4-cidr "$IPV4_CIDR" \
      --ipv6-cidr "$IPV6_CIDR" >/dev/null 2>&1 || true
  fi

  if [[ -n "$BROKER_PID" ]]; then
    kill "$BROKER_PID" >/dev/null 2>&1 || true
    wait "$BROKER_PID" 2>/dev/null || true
  fi
  if [[ -n "$FORBIDDEN_PID" ]]; then
    kill "$FORBIDDEN_PID" >/dev/null 2>&1 || true
    wait "$FORBIDDEN_PID" 2>/dev/null || true
  fi
  if [[ -n "$FORBIDDEN_V6_PID" ]]; then
    kill "$FORBIDDEN_V6_PID" >/dev/null 2>&1 || true
    wait "$FORBIDDEN_V6_PID" 2>/dev/null || true
  fi

  if [[ -n "$NETWORK_NAME" ]]; then
    container network rm "$NETWORK_NAME" >/dev/null 2>&1 || \
      container network delete "$NETWORK_NAME" >/dev/null 2>&1 || true
  fi

  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

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

pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

pick_port_ipv6() {
  python3 -c 'import socket; s=socket.socket(socket.AF_INET6); s.bind(("::1", 0)); print(s.getsockname()[1]); s.close()'
}

cidr_gateway() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=True)
print(next(network.hosts()))
PY
}

cidr_supernet() {
  python3 - "$1" "$2" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=True)
print(network.supernet(new_prefix=int(sys.argv[2])))
PY
}

extract_network_field() {
  python3 - "$1" "$2" <<'PY'
import json
import re
import sys

path, key = sys.argv[1:]
text = open(path, encoding="utf-8").read()

def emit(value):
    if isinstance(value, str) and value and value.lower() not in {"null", "none"}:
        print(value)
        return True
    return False

def walk(value):
    if isinstance(value, dict):
        for k, v in value.items():
            if k == key and emit(v):
                return True
            if walk(v):
                return True
    elif isinstance(value, list):
        for item in value:
            if walk(item):
                return True
    return False

try:
    if walk(json.loads(text)):
        raise SystemExit(0)
except Exception:
    pass

match = re.search(rf'(?im)^\s*{re.escape(key)}\s*[:=]\s*"?([^"\n,]+)', text)
if match:
    value = match.group(1).strip()
    if value and value.lower() not in {"null", "none"}:
        print(value)
        raise SystemExit(0)

raise SystemExit(1)
PY
}

extract_first_ipv6_cidr() {
  python3 - "$1" <<'PY'
import ipaddress
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
for token in re.findall(r"[0-9A-Fa-f:]+/\d{1,3}", text):
    try:
        network = ipaddress.ip_network(token, strict=True)
    except ValueError:
        continue
    if network.version == 6 and network.prefixlen == 64:
        print(network)
        raise SystemExit(0)

raise SystemExit(1)
PY
}

canonical_ipv6_slash64() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

raw = sys.argv[1]
try:
    network = ipaddress.ip_network(raw, strict=True)
except ValueError as e:
    print(f"{raw!r} is not a strict IPv6 network: {e}", file=sys.stderr)
    raise SystemExit(1)

if network.version != 6 or network.prefixlen != 64:
    print(f"{raw!r} is not an IPv6 /64 subnet", file=sys.stderr)
    raise SystemExit(1)

print(network)
PY
}

start_http_server() {
  local dir="$1"
  local port="$2"
  local log_file="$3"
  python3 -m http.server "$port" --bind 0.0.0.0 --directory "$dir" \
    >"$log_file" 2>&1 &
  echo "$!"
}

start_http_server_ipv6() {
  local dir="$1"
  local port="$2"
  local log_file="$3"
  python3 -m http.server "$port" --bind :: --directory "$dir" \
    >"$log_file" 2>&1 &
  echo "$!"
}

wait_for_host_http() {
  local port="$1"
  local label="$2"
  local path="$3"
  local expected="$4"
  for _ in {1..50}; do
    if curl --silent --fail --max-time 1 "http://127.0.0.1:${port}/${path}" \
      | grep -q "^${expected}$"; then
      return 0
    fi
    sleep 0.1
  done
  die "${label} listener did not start on port ${port}"
}

wait_for_host_http_ipv6() {
  local port="$1"
  local label="$2"
  local path="$3"
  local expected="$4"
  for _ in {1..50}; do
    if curl --silent --fail --max-time 1 "http://[::1]:${port}/${path}" \
      | grep -q "^${expected}$"; then
      return 0
    fi
    sleep 0.1
  done
  die "${label} IPv6 listener did not start on port ${port}"
}

guest() {
  container exec "$VM_NAME" sh -lc "$1"
}

wait_for_guest_exec() {
  for _ in {1..50}; do
    if guest 'true' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  die "VM did not become ready for container exec: ${VM_NAME}"
}

expect_guest_success() {
  local label="$1"
  local command="$2"
  log "assert: ${label}"
  if guest "$command"; then
    log "pass: ${label}"
  else
    die "expected success: ${label}"
  fi
}

expect_guest_blocked() {
  local label="$1"
  local command="$2"
  log "assert: ${label}"
  set +e
  guest "$command"
  local status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    die "expected block/failure but probe succeeded: ${label}"
  fi
  if [[ "$status" -eq 77 ]]; then
    die "probe unavailable inside guest: ${label}"
  fi
  log "pass: ${label}"
}

guest_has_ipv6_in_cidr() {
  local cidr="$1"
  local addrs

  if ! addrs="$(guest "if command -v ip >/dev/null 2>&1; then ip -6 -o addr show scope global 2>/dev/null | awk '{print \$4}'; else exit 77; fi")"; then
    return 1
  fi

  python3 - "$cidr" "$addrs" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=True)
for raw in sys.argv[2].split():
    try:
        address = ipaddress.ip_interface(raw).ip
    except ValueError:
        continue
    if address.version == 6 and address in network:
        raise SystemExit(0)

raise SystemExit(1)
PY
}

assert_pf_anchor_empty() {
  if [[ -z "$PF_ANCHOR" ]]; then
    return
  fi
  if sudo pfctl -a "$PF_ANCHOR" -sr 2>/dev/null | grep -q '[^[:space:]]'; then
    die "PF anchor still contains rules after cleanup: ${PF_ANCHOR}"
  fi
}

require_cmd container
require_cmd curl
require_cmd python3
require_cmd sudo
require_cmd uuidgen
choose_cargo

mkdir -p "$BROKER_DIR" "$FORBIDDEN_DIR"
printf 'broker-ok\n' >"${BROKER_DIR}/broker.txt"
printf 'forbidden-open\n' >"${FORBIDDEN_DIR}/forbidden.txt"

log "requesting sudo credentials for pfctl"
sudo -v

if ! sudo pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; then
  die "PF is not enabled; enable it before running this proof harness"
fi
if ! sudo pfctl -sr 2>/dev/null | grep -q 'anchor "writ/session/\*"'; then
  if sudo pfctl -sr 2>/dev/null | grep -q 'anchor "writ/\*"'; then
    die 'found anchor "writ/*", but this harness loads writ/session/<uuid>; add `anchor "writ/session/*"` to /etc/pf.conf and reload PF'
  fi
  die 'missing top-level PF anchor; add `anchor "writ/session/*"` to /etc/pf.conf and reload PF'
fi

log "building PF helper from the Rust core model"
"${CARGO_CMD[@]}" build --quiet --bin writ-agent-vm-pf-helper
HELPER="${ROOT_DIR}/target/debug/writ-agent-vm-pf-helper"

BROKER_PORT="$(pick_port)"
FORBIDDEN_PORT="$(pick_port)"
while [[ "$FORBIDDEN_PORT" == "$BROKER_PORT" ]]; do
  FORBIDDEN_PORT="$(pick_port)"
done

BROKER_PID="$(start_http_server "$BROKER_DIR" "$BROKER_PORT" "${TMP_DIR}/broker.log")"
FORBIDDEN_PID="$(start_http_server "$FORBIDDEN_DIR" "$FORBIDDEN_PORT" "${TMP_DIR}/forbidden.log")"
wait_for_host_http "$BROKER_PORT" "broker" "broker.txt" "broker-ok"
wait_for_host_http "$FORBIDDEN_PORT" "forbidden" "forbidden.txt" "forbidden-open"
log "host listeners are up: broker=${BROKER_PORT}, forbidden=${FORBIDDEN_PORT}"

log "creating internal Apple container network ${NETWORK_NAME} (${IPV4_CIDR})"
container network create --internal --subnet "$IPV4_CIDR" "$NETWORK_NAME" >/dev/null
container network inspect "$NETWORK_NAME" >"$NETWORK_INSPECT_FILE"
IPV4_GATEWAY="$(extract_network_field "$NETWORK_INSPECT_FILE" ipv4Gateway || true)"
if [[ -z "$IPV4_GATEWAY" ]]; then
  IPV4_GATEWAY="$(cidr_gateway "$IPV4_CIDR")"
fi
IPV4_GATEWAY="${IPV4_GATEWAY%%/*}"
INSPECT_IPV6_CIDR="$(extract_network_field "$NETWORK_INSPECT_FILE" ipv6Subnet || true)"
if [[ -z "$INSPECT_IPV6_CIDR" ]]; then
  log "network inspect did not expose ipv6Subnet; trying heuristic IPv6 /64 extraction"
  INSPECT_IPV6_CIDR="$(extract_first_ipv6_cidr "$NETWORK_INSPECT_FILE" || true)"
fi
IPV6_GATEWAY="$(extract_network_field "$NETWORK_INSPECT_FILE" ipv6Gateway || true)"
IPV6_GATEWAY="${IPV6_GATEWAY%%/*}"
if [[ -n "$INSPECT_IPV6_CIDR" ]]; then
  if ! IPV6_CIDR="$(canonical_ipv6_slash64 "$INSPECT_IPV6_CIDR")"; then
    die "network inspect reported invalid IPv6 subnet: ${INSPECT_IPV6_CIDR}"
  fi
else
  FALLBACK_IPV6_CIDR="$IPV6_CIDR"
  if ! IPV6_CIDR="$(canonical_ipv6_slash64 "$FALLBACK_IPV6_CIDR")"; then
    die "fallback IPv6 subnet is invalid: ${FALLBACK_IPV6_CIDR}"
  fi
  log "network inspect did not report an IPv6 /64; using fallback PF prefix ${IPV6_CIDR} and skipping IPv6 probes"
fi
if [[ -z "$IPV4_POOL" ]]; then
  IPV4_POOL="$(cidr_supernet "$IPV4_CIDR" 16)"
fi
if [[ -z "$IPV6_POOL" ]]; then
  IPV6_POOL="$(cidr_supernet "$IPV6_CIDR" 48)"
fi
if [[ -n "$INSPECT_IPV6_CIDR" && -n "$IPV6_GATEWAY" ]]; then
  IPV6_PROBES_ENABLED=1
  FORBIDDEN_V6_PORT="$(pick_port_ipv6)"
  while [[ "$FORBIDDEN_V6_PORT" == "$BROKER_PORT" || "$FORBIDDEN_V6_PORT" == "$FORBIDDEN_PORT" ]]; do
    FORBIDDEN_V6_PORT="$(pick_port_ipv6)"
  done
  FORBIDDEN_V6_PID="$(start_http_server_ipv6 \
    "$FORBIDDEN_DIR" \
    "$FORBIDDEN_V6_PORT" \
    "${TMP_DIR}/forbidden-v6.log")"
  wait_for_host_http_ipv6 "$FORBIDDEN_V6_PORT" "forbidden" "forbidden.txt" "forbidden-open"
  log "host IPv6 forbidden listener is up: forbidden_v6=${FORBIDDEN_V6_PORT}"
else
  log "network inspect did not report both an IPv6 subnet and gateway; IPv6 probes will be skipped"
fi

log "validating and loading PF anchor through helper"
PF_ANCHOR="writ/session/${SESSION_ID}"
LOADED_PF_ANCHOR="$(sudo "$HELPER" install \
  --session-id "$SESSION_ID" \
  --ipv4-pool "$IPV4_POOL" \
  --ipv6-pool "$IPV6_POOL" \
  --ipv4-cidr "$IPV4_CIDR" \
  --ipv6-cidr "$IPV6_CIDR" \
  --broker-port "$BROKER_PORT" \
  --broker-port-min "$BROKER_PORT_MIN" \
  --broker-port-max "$BROKER_PORT_MAX")"
if [[ "$LOADED_PF_ANCHOR" != "$PF_ANCHOR" ]]; then
  die "helper loaded unexpected PF anchor ${LOADED_PF_ANCHOR}; expected ${PF_ANCHOR}"
fi
log "loaded PF anchor ${PF_ANCHOR}"

log "starting VM ${VM_NAME} on ${NETWORK_NAME}"
container run --name "$VM_NAME" \
  --network "$NETWORK_NAME" \
  --cpus 1 \
  --memory 512m \
  -d "$IMAGE" sleep 600 >/dev/null
wait_for_guest_exec

expect_guest_success \
  "guest has required probe tools" \
  'command -v wget >/dev/null && command -v nslookup >/dev/null'

if [[ "$IPV6_PROBES_ENABLED" -eq 1 ]]; then
  log "assert: VM has a global IPv6 address inside ${IPV6_CIDR}"
  if guest_has_ipv6_in_cidr "$IPV6_CIDR"; then
    log "pass: VM has a global IPv6 address inside ${IPV6_CIDR}"
  else
    die "network inspect reported ${IPV6_CIDR}, but the VM has no global IPv6 address in that prefix"
  fi
fi

BROKER_URL="http://${IPV4_GATEWAY}:${BROKER_PORT}/broker.txt"
FORBIDDEN_URL="http://${IPV4_GATEWAY}:${FORBIDDEN_PORT}/forbidden.txt"

expect_guest_success \
  "VM can reach broker port through host-only gateway" \
  "wget -q -T 3 -O - '$BROKER_URL' | grep -q '^broker-ok$'"

expect_guest_blocked \
  "VM cannot reach forbidden host port" \
  "wget -q -T 3 -O - '$FORBIDDEN_URL'"

if [[ "$IPV6_PROBES_ENABLED" -eq 1 ]]; then
  FORBIDDEN_V6_URL="http://[${IPV6_GATEWAY}]:${FORBIDDEN_V6_PORT}/forbidden.txt"
  expect_guest_blocked \
    "VM cannot reach forbidden host IPv6 port" \
    "wget -q -T 3 -O - '$FORBIDDEN_V6_URL'"
fi

expect_guest_blocked \
  "VM cannot reach direct IPv4 internet" \
  "wget -q -T 3 -O - 'http://1.1.1.1/'"

expect_guest_blocked \
  "VM cannot reach direct external DNS" \
  "nslookup github.com 1.1.1.1 >/dev/null"

if [[ "$IPV6_PROBES_ENABLED" -eq 1 ]]; then
  expect_guest_blocked \
    "VM cannot use IPv6 as a bypass" \
    'if command -v ping6 >/dev/null 2>&1; then ping6 -c 1 -W 3 2606:4700:4700::1111 >/dev/null; else exit 77; fi'
else
  log "skip: IPv6 bypass probe skipped because the internal network did not report usable IPv6"
fi

cleanup
trap - EXIT INT TERM
assert_pf_anchor_empty
if [[ "$IPV6_PROBES_ENABLED" -eq 1 ]]; then
  log "PF proof succeeded for ${IPV4_CIDR} and ${IPV6_CIDR}; broker allowed, forbidden host ports blocked; direct egress sanity probes failed"
else
  log "PF proof succeeded for ${IPV4_CIDR}; broker allowed, forbidden host port blocked; direct IPv4/DNS sanity probes failed; IPv6 probes skipped"
fi
