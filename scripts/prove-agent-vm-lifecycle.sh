#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/prove-agent-vm-lifecycle.sh

Manual proof harness for the writ-agent-vm-runner lifecycle.

Requires:
  - macOS with Apple container installed and `container system start` already run
  - root privileges through sudo for pfctl
  - a top-level PF rule in /etc/pf.conf: anchor "writ/session/*"
  - python3, curl, cargo or nix, and an Alpine-compatible image with sh, ip,
    wget, and nslookup

Environment overrides:
  WRIT_PROVE_IMAGE       OCI image to run, default alpine:latest
  WRIT_PROVE_IPV4_POOL   broker-owned IPv4 pool, default 192.168.0.0/16
  WRIT_PROVE_IPV6_POOL   broker-owned IPv6 pool, default fd83:b6f2:e57::/48
  WRIT_PROVE_SUBNET_INDEX  session subnet index, default 252
  WRIT_PROVE_BROKER_PORT_MIN  minimum allowed broker port, default 49152
  WRIT_PROVE_BROKER_PORT_MAX  maximum allowed broker port, default 65535
EOF
}

log() {
  printf '[prove-lifecycle] %s\n' "$*"
}

die() {
  printf '[prove-lifecycle] error: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/writ-lifecycle-proof.XXXXXX")"
IMAGE="${WRIT_PROVE_IMAGE:-alpine:latest}"
IPV4_POOL="${WRIT_PROVE_IPV4_POOL:-192.168.0.0/16}"
IPV6_POOL="${WRIT_PROVE_IPV6_POOL:-fd83:b6f2:e57::/48}"
SUBNET_INDEX="${WRIT_PROVE_SUBNET_INDEX:-252}"
BROKER_PORT_MIN="${WRIT_PROVE_BROKER_PORT_MIN:-49152}"
BROKER_PORT_MAX="${WRIT_PROVE_BROKER_PORT_MAX:-65535}"
IPV6_MODE="ipv4-only-no-guest-ipv6"
SESSION_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
NETWORK_NAME="writ-agent-net-${SESSION_ID}"
VM_NAME="writ-agent-vm-${SESSION_ID}"
PF_ANCHOR="writ/session/${SESSION_ID}"
BROKER_DIR="${TMP_DIR}/broker"
FORBIDDEN_DIR="${TMP_DIR}/forbidden"
START_OUTPUT="${TMP_DIR}/runner-start.txt"
RUNNER=""
HELPER=""
BROKER_PID=""
FORBIDDEN_PID=""
BROKER_PORT=""
FORBIDDEN_PORT=""
IPV4_CIDR=""
IPV6_CIDR=""
IPV4_GATEWAY=""
GUEST_IPV4=""
CARGO_CMD=()
STOP_DONE=0
cleanup_started=0

cleanup() {
  if [[ "$cleanup_started" -eq 1 ]]; then
    return
  fi
  cleanup_started=1

  log "cleaning up VM, network, listeners, and PF anchor"

  if [[ "$STOP_DONE" -eq 0 && -x "$RUNNER" ]]; then
    "$RUNNER" \
      --pf-helper "$HELPER" \
      stop \
      --session-id "$SESSION_ID" \
      --ipv4-pool "$IPV4_POOL" \
      --ipv6-pool "$IPV6_POOL" \
      --ipv6-mode "$IPV6_MODE" \
      --subnet-index "$SUBNET_INDEX" >/dev/null 2>&1 || true
  fi

  if [[ -n "$VM_NAME" ]]; then
    container rm -f "$VM_NAME" >/dev/null 2>&1 || true
    container stop "$VM_NAME" >/dev/null 2>&1 || true
    container delete "$VM_NAME" >/dev/null 2>&1 || true
    container rm "$VM_NAME" >/dev/null 2>&1 || true
  fi

  if [[ -n "$HELPER" && -n "$IPV4_CIDR" ]]; then
    helper_remove=(
      sudo "$HELPER" remove
      --session-id "$SESSION_ID"
      --ipv4-pool "$IPV4_POOL"
      --ipv6-pool "$IPV6_POOL"
      --ipv4-cidr "$IPV4_CIDR"
    )
    if [[ "$IPV6_MODE" == "dual-stack-required" && -n "$IPV6_CIDR" ]]; then
      helper_remove+=(--ipv6-cidr "$IPV6_CIDR")
    fi
    "${helper_remove[@]}" >/dev/null 2>&1 || true
  fi

  if [[ -n "$NETWORK_NAME" ]]; then
    container network rm "$NETWORK_NAME" >/dev/null 2>&1 || \
      container network delete "$NETWORK_NAME" >/dev/null 2>&1 || true
  fi

  if [[ -n "$BROKER_PID" ]]; then
    kill "$BROKER_PID" >/dev/null 2>&1 || true
    wait "$BROKER_PID" 2>/dev/null || true
  fi
  if [[ -n "$FORBIDDEN_PID" ]]; then
    kill "$FORBIDDEN_PID" >/dev/null 2>&1 || true
    wait "$FORBIDDEN_PID" 2>/dev/null || true
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

cidr_alloc_subnet() {
  python3 - "$1" "$2" "$3" <<'PY'
import ipaddress
import sys

base = ipaddress.ip_network(sys.argv[1], strict=True)
new_prefix = int(sys.argv[2])
index = int(sys.argv[3])
if new_prefix < base.prefixlen:
    print(f"new prefix /{new_prefix} is shorter than base {base}", file=sys.stderr)
    raise SystemExit(1)
size = 1 << (base.max_prefixlen - new_prefix)
subnet = ipaddress.ip_network((int(base.network_address) + index * size, new_prefix))
if not subnet.subnet_of(base):
    print(f"subnet index {index} is outside {base}", file=sys.stderr)
    raise SystemExit(1)
print(subnet)
PY
}

cidr_gateway() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=True)
print(next(network.hosts()))
PY
}

pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

start_http_server() {
  local dir="$1"
  local port="$2"
  local log_file="$3"
  python3 -m http.server "$port" --bind 0.0.0.0 --directory "$dir" \
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

guest() {
  container exec "$VM_NAME" sh -lc "$1"
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
  log "pass: ${label}"
}

wait_for_released_guest_command() {
  log "assert: released guest command is running"
  for _ in {1..50}; do
    if guest 'test "$(cat /tmp/writ-agent-vm-released 2>/dev/null)" = lifecycle-released' \
      >/dev/null 2>&1; then
      log "pass: released guest command is running"
      return
    fi
    sleep 0.1
  done
  die "released guest command did not write its marker"
}

guest_ipv4_addr() {
  guest "ip -4 -o addr show scope global | awk '{print \$4}' | head -n 1 | cut -d/ -f1"
}

assert_guest_has_no_routable_ipv6() {
  log "assert: guest has no routable IPv6 address or default route"
  set +e
  guest '
    if ! command -v ip >/dev/null 2>&1; then exit 77; fi
    addrs="$(ip -6 -o addr show scope global)" || exit 1
    if [ -n "$addrs" ]; then
      printf "%s\n" "$addrs"
      exit 1
    fi
    routes="$(ip -6 route show default)" || exit 1
    if [ -n "$routes" ]; then
      printf "%s\n" "$routes"
      exit 1
    fi
  '
  local status=$?
  set -e
  if [[ "$status" -eq 77 ]]; then
    die "guest lacks ip command for IPv6 posture assertion"
  fi
  if [[ "$status" -ne 0 ]]; then
    die "guest has routable IPv6 posture or the IPv6 probe failed"
  fi
  log "pass: guest has no routable IPv6 address or default route"
}

assert_pf_anchor_empty() {
  if sudo pfctl -a "$PF_ANCHOR" -sr 2>/dev/null | grep -q '[^[:space:]]'; then
    die "PF anchor still contains rules after runner stop: ${PF_ANCHOR}"
  fi
}

assert_no_pf_state_for_guest() {
  if [[ -z "$GUEST_IPV4" ]]; then
    log "skip: no guest IPv4 address recorded for PF state assertion"
    return
  fi
  local escaped_ipv4="${GUEST_IPV4//./\\.}"
  if sudo pfctl -ss 2>/dev/null | grep -E "(^|[^0-9.])${escaped_ipv4}([^0-9.]|$)" >/dev/null; then
    die "PF still has live state mentioning guest IPv4 ${GUEST_IPV4}"
  fi
}

container_list_contains() {
  local name="$1"
  local listed
  listed="$(container list --all --quiet 2>/dev/null)" || \
    die "could not list containers after runner stop"
  grep -Fxq "$name" <<<"$listed"
}

network_list_contains() {
  local name="$1"
  local listed
  listed="$(container network list --quiet 2>/dev/null)" || \
    die "could not list networks after runner stop"
  grep -Fxq "$name" <<<"$listed"
}

assert_container_absent() {
  if container_list_contains "$VM_NAME"; then
    die "VM still exists after runner stop: ${VM_NAME}"
  fi
}

assert_network_absent() {
  if network_list_contains "$NETWORK_NAME"; then
    die "network still exists after runner stop: ${NETWORK_NAME}"
  fi
}

require_cmd container
require_cmd curl
require_cmd python3
require_cmd sudo
require_cmd uuidgen
choose_cargo

IPV4_CIDR="$(cidr_alloc_subnet "$IPV4_POOL" 24 "$SUBNET_INDEX")"
IPV6_CIDR="$(cidr_alloc_subnet "$IPV6_POOL" 64 "$SUBNET_INDEX")"
IPV4_GATEWAY="$(cidr_gateway "$IPV4_CIDR")"

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

log "building PF helper and lifecycle runner"
"${CARGO_CMD[@]}" build --quiet \
  --bin writ-agent-vm-pf-helper \
  --bin writ-agent-vm-runner
HELPER="${ROOT_DIR}/target/debug/writ-agent-vm-pf-helper"
RUNNER="${ROOT_DIR}/target/debug/writ-agent-vm-runner"

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

log "starting runner-managed VM ${VM_NAME} on ${IPV4_CIDR}"
"$RUNNER" \
  --pf-helper "$HELPER" \
  start \
  --session-id "$SESSION_ID" \
  --ipv4-pool "$IPV4_POOL" \
  --ipv6-pool "$IPV6_POOL" \
  --subnet-index "$SUBNET_INDEX" \
  --broker-port "$BROKER_PORT" \
  --broker-port-min "$BROKER_PORT_MIN" \
  --broker-port-max "$BROKER_PORT_MAX" \
  --image "$IMAGE" \
  --ipv6-mode "$IPV6_MODE" \
  -- sh -c 'printf lifecycle-released >/tmp/writ-agent-vm-released; sleep 600' \
  | tee "$START_OUTPUT"

grep -Fxq "session_id=${SESSION_ID}" "$START_OUTPUT" || die "runner did not print expected session ID"
grep -Fxq "network=${NETWORK_NAME}" "$START_OUTPUT" || die "runner did not print expected network"
grep -Fxq "vm=${VM_NAME}" "$START_OUTPUT" || die "runner did not print expected VM"
grep -Fxq "broker_url=http://${IPV4_GATEWAY}:${BROKER_PORT}/" "$START_OUTPUT" || \
  die "runner did not print expected broker URL"

wait_for_released_guest_command

expect_guest_success \
  "guest has required probe tools" \
  'command -v ip >/dev/null && command -v wget >/dev/null && command -v nslookup >/dev/null'

assert_guest_has_no_routable_ipv6

GUEST_IPV4="$(guest_ipv4_addr)"
if [[ -z "$GUEST_IPV4" ]]; then
  die "could not determine guest IPv4 address"
fi
log "guest IPv4 address is ${GUEST_IPV4}"

BROKER_URL="http://${IPV4_GATEWAY}:${BROKER_PORT}/broker.txt"
FORBIDDEN_URL="http://${IPV4_GATEWAY}:${FORBIDDEN_PORT}/forbidden.txt"

expect_guest_success \
  "VM can reach broker port through host-only gateway" \
  "wget -q -T 3 -O - '$BROKER_URL' | grep -q '^broker-ok$'"

expect_guest_blocked \
  "VM cannot reach forbidden host port" \
  "wget -q -T 3 -O - '$FORBIDDEN_URL'"

expect_guest_blocked \
  "VM cannot reach direct IPv4 internet" \
  "wget -q -T 3 -O - 'http://1.1.1.1/'"

expect_guest_blocked \
  "VM cannot reach direct external DNS" \
  "nslookup github.com 1.1.1.1 >/dev/null"

log "stopping session through lifecycle runner"
"$RUNNER" \
  --pf-helper "$HELPER" \
  stop \
  --session-id "$SESSION_ID" \
  --ipv4-pool "$IPV4_POOL" \
  --ipv6-pool "$IPV6_POOL" \
  --ipv6-mode "$IPV6_MODE" \
  --subnet-index "$SUBNET_INDEX"
STOP_DONE=1

assert_container_absent
assert_network_absent
assert_pf_anchor_empty
assert_no_pf_state_for_guest

cleanup
trap - EXIT INT TERM
log "runner lifecycle proof succeeded for ${IPV4_CIDR}; broker reachable, forbidden host port blocked, IPv6 posture proven, and runner cleanup verified"
