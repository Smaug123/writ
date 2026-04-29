#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/prove-agent-vm-two-sessions.sh

Manual proof harness for two simultaneous writ-agent-vm-runner sessions.

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
  WRIT_PROVE_SUBNET_A_INDEX  first session subnet index, default 252
  WRIT_PROVE_SUBNET_B_INDEX  second session subnet index, default 253
  WRIT_PROVE_BROKER_PORT_MIN  minimum allowed broker port, default 49152
  WRIT_PROVE_BROKER_PORT_MAX  maximum allowed broker port, default 65535
EOF
}

log() {
  printf '[prove-two-sessions] %s\n' "$*"
}

die() {
  printf '[prove-two-sessions] error: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${WRIT_PROVE_IMAGE:-alpine:latest}"
IPV4_POOL="${WRIT_PROVE_IPV4_POOL:-192.168.0.0/16}"
IPV6_POOL="${WRIT_PROVE_IPV6_POOL:-fd83:b6f2:e57::/48}"
SUBNET_A_INDEX="${WRIT_PROVE_SUBNET_A_INDEX:-252}"
SUBNET_B_INDEX="${WRIT_PROVE_SUBNET_B_INDEX:-253}"
BROKER_PORT_MIN="${WRIT_PROVE_BROKER_PORT_MIN:-49152}"
BROKER_PORT_MAX="${WRIT_PROVE_BROKER_PORT_MAX:-65535}"
IPV6_MODE="ipv4-only-no-guest-ipv6"

RUNNER=""
HELPER=""
CARGO_CMD=()

CURRENT_TMP_DIR=""
CURRENT_SESSION_A_ID=""
CURRENT_SESSION_B_ID=""
CURRENT_NETWORK_A_NAME=""
CURRENT_NETWORK_B_NAME=""
CURRENT_VM_A_NAME=""
CURRENT_VM_B_NAME=""
CURRENT_IPV4_A_CIDR=""
CURRENT_IPV4_B_CIDR=""
CURRENT_IPV6_A_CIDR=""
CURRENT_IPV6_B_CIDR=""
CURRENT_BROKER_A_PID=""
CURRENT_BROKER_B_PID=""
CURRENT_FORBIDDEN_PID=""
CURRENT_STOP_A_DONE=1
CURRENT_STOP_B_DONE=1
CURRENT_CLEANUP_STARTED=0

cleanup_session() {
  local session_id="$1"
  local subnet_index="$2"
  local vm_name="$3"
  local network_name="$4"
  local ipv4_cidr="$5"
  local ipv6_cidr="$6"
  local stop_done="$7"

  if [[ "$stop_done" -eq 0 && -x "$RUNNER" ]]; then
    "$RUNNER" \
      --pf-helper "$HELPER" \
      stop \
      --session-id "$session_id" \
      --ipv4-pool "$IPV4_POOL" \
      --ipv6-pool "$IPV6_POOL" \
      --ipv6-mode "$IPV6_MODE" \
      --subnet-index "$subnet_index" >/dev/null 2>&1 || true
  fi

  container rm -f "$vm_name" >/dev/null 2>&1 || true
  container stop "$vm_name" >/dev/null 2>&1 || true
  container delete "$vm_name" >/dev/null 2>&1 || true
  container rm "$vm_name" >/dev/null 2>&1 || true

  if [[ -n "$HELPER" && -n "$ipv4_cidr" ]]; then
    local helper_remove
    helper_remove=(
      sudo "$HELPER" remove
      --session-id "$session_id"
      --ipv4-pool "$IPV4_POOL"
      --ipv6-pool "$IPV6_POOL"
      --ipv4-cidr "$ipv4_cidr"
    )
    if [[ "$IPV6_MODE" == "dual-stack-required" && -n "$ipv6_cidr" ]]; then
      helper_remove+=(--ipv6-cidr "$ipv6_cidr")
    fi
    "${helper_remove[@]}" >/dev/null 2>&1 || true
  fi

  container network rm "$network_name" >/dev/null 2>&1 || \
    container network delete "$network_name" >/dev/null 2>&1 || true
}

cleanup() {
  if [[ "$CURRENT_CLEANUP_STARTED" -eq 1 ]]; then
    return
  fi
  CURRENT_CLEANUP_STARTED=1

  log "cleaning up VMs, networks, listeners, and PF anchors"
  if [[ -n "$CURRENT_SESSION_B_ID" ]]; then
    cleanup_session "$CURRENT_SESSION_B_ID" "$SUBNET_B_INDEX" "$CURRENT_VM_B_NAME" \
      "$CURRENT_NETWORK_B_NAME" "$CURRENT_IPV4_B_CIDR" "$CURRENT_IPV6_B_CIDR" \
      "$CURRENT_STOP_B_DONE"
  fi
  if [[ -n "$CURRENT_SESSION_A_ID" ]]; then
    cleanup_session "$CURRENT_SESSION_A_ID" "$SUBNET_A_INDEX" "$CURRENT_VM_A_NAME" \
      "$CURRENT_NETWORK_A_NAME" "$CURRENT_IPV4_A_CIDR" "$CURRENT_IPV6_A_CIDR" \
      "$CURRENT_STOP_A_DONE"
  fi

  for pid in "$CURRENT_BROKER_A_PID" "$CURRENT_BROKER_B_PID" "$CURRENT_FORBIDDEN_PID"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" 2>/dev/null || true
    fi
  done

  if [[ -n "$CURRENT_TMP_DIR" ]]; then
    rm -rf "$CURRENT_TMP_DIR"
  fi
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
  local vm_name="$1"
  local command="$2"
  container exec "$vm_name" sh -lc "$command"
}

expect_guest_success() {
  local label="$1"
  local vm_name="$2"
  local command="$3"
  log "assert: ${label}"
  if guest "$vm_name" "$command"; then
    log "pass: ${label}"
  else
    die "expected success: ${label}"
  fi
}

expect_guest_blocked() {
  local label="$1"
  local vm_name="$2"
  local command="$3"
  log "assert: ${label}"
  set +e
  guest "$vm_name" "$command"
  local status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    die "expected block/failure but probe succeeded: ${label}"
  fi
  log "pass: ${label}"
}

wait_for_released_guest_command() {
  local label="$1"
  local vm_name="$2"
  local marker="$3"
  log "assert: ${label} released guest command is running"
  for _ in {1..50}; do
    if guest "$vm_name" "test \"\$(cat /tmp/writ-agent-vm-released 2>/dev/null)\" = '$marker'" \
      >/dev/null 2>&1; then
      log "pass: ${label} released guest command is running"
      return
    fi
    sleep 0.1
  done
  die "${label} released guest command did not write its marker"
}

guest_ipv4_addr() {
  local vm_name="$1"
  guest "$vm_name" "ip -4 -o addr show scope global | awk '{print \$4}' | head -n 1 | cut -d/ -f1"
}

assert_guest_has_no_routable_ipv6() {
  local label="$1"
  local vm_name="$2"
  log "assert: ${label} has no routable IPv6 address or default route"
  set +e
  guest "$vm_name" '
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
    die "${label} lacks ip command for IPv6 posture assertion"
  fi
  if [[ "$status" -ne 0 ]]; then
    die "${label} has routable IPv6 posture or the IPv6 probe failed"
  fi
  log "pass: ${label} has no routable IPv6 address or default route"
}

assert_pf_anchor_empty() {
  local label="$1"
  local anchor="$2"
  if sudo pfctl -a "$anchor" -sr 2>/dev/null | grep -q '[^[:space:]]'; then
    die "${label} PF anchor still contains rules after runner stop: ${anchor}"
  fi
}

assert_no_pf_state_for_guest() {
  local label="$1"
  local guest_ipv4="$2"
  if [[ -z "$guest_ipv4" ]]; then
    log "skip: no ${label} guest IPv4 address recorded for PF state assertion"
    return
  fi
  local escaped_ipv4="${guest_ipv4//./\\.}"
  if sudo pfctl -ss 2>/dev/null | grep -E "(^|[^0-9.])${escaped_ipv4}([^0-9.]|$)" >/dev/null; then
    die "PF still has live state mentioning ${label} guest IPv4 ${guest_ipv4}"
  fi
}

pf_anchor_rules() {
  local anchor="$1"
  sudo pfctl -a "$anchor" -sr 2>/dev/null || \
    die "could not read PF anchor rules: ${anchor}"
}

assert_pf_anchor_unchanged() {
  local label="$1"
  local anchor="$2"
  local expected_file="$3"
  local current_file="$4"
  pf_anchor_rules "$anchor" >"$current_file"
  if ! cmp -s "$expected_file" "$current_file"; then
    die "${label} PF anchor changed while stopping the other session"
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
  local label="$1"
  local vm_name="$2"
  if container_list_contains "$vm_name"; then
    die "${label} VM still exists after runner stop: ${vm_name}"
  fi
}

assert_network_absent() {
  local label="$1"
  local network_name="$2"
  if network_list_contains "$network_name"; then
    die "${label} network still exists after runner stop: ${network_name}"
  fi
}

start_session() {
  local label="$1"
  local session_id="$2"
  local subnet_index="$3"
  local vm_name="$4"
  local network_name="$5"
  local ipv4_cidr="$6"
  local ipv4_gateway="$7"
  local broker_port="$8"
  local marker="$9"
  local output_file="${10}"
  local command="printf '$marker' >/tmp/writ-agent-vm-released; sleep 600"

  log "starting ${label} ${vm_name} on ${ipv4_cidr}"
  "$RUNNER" \
    --pf-helper "$HELPER" \
    start \
    --session-id "$session_id" \
    --ipv4-pool "$IPV4_POOL" \
    --ipv6-pool "$IPV6_POOL" \
    --subnet-index "$subnet_index" \
    --broker-port "$broker_port" \
    --broker-port-min "$BROKER_PORT_MIN" \
    --broker-port-max "$BROKER_PORT_MAX" \
    --image "$IMAGE" \
    --ipv6-mode "$IPV6_MODE" \
    -- sh -c "$command" \
    | tee "$output_file"

  grep -Fxq "session_id=${session_id}" "$output_file" || \
    die "${label} runner did not print expected session ID"
  grep -Fxq "network=${network_name}" "$output_file" || \
    die "${label} runner did not print expected network"
  grep -Fxq "vm=${vm_name}" "$output_file" || \
    die "${label} runner did not print expected VM"
  grep -Fxq "broker_url=http://${ipv4_gateway}:${broker_port}/" "$output_file" || \
    die "${label} runner did not print expected broker URL"
}

stop_session() {
  local label="$1"
  local session_id="$2"
  local subnet_index="$3"
  log "stopping ${label} through lifecycle runner"
  "$RUNNER" \
    --pf-helper "$HELPER" \
    stop \
    --session-id "$session_id" \
    --ipv4-pool "$IPV4_POOL" \
    --ipv6-pool "$IPV6_POOL" \
    --ipv6-mode "$IPV6_MODE" \
    --subnet-index "$subnet_index"
}

assert_basic_session_posture() {
  local label="$1"
  local vm_name="$2"
  local gateway="$3"
  local own_broker_port="$4"
  local own_expected="$5"
  local other_broker_port="$6"

  expect_guest_success \
    "${label} can reach its broker port through its host-only gateway" \
    "$vm_name" \
    "wget -q -T 3 -O - 'http://${gateway}:${own_broker_port}/broker.txt' | grep -q '^${own_expected}$'"

  expect_guest_blocked \
    "${label} cannot reach the other session broker port through its own gateway" \
    "$vm_name" \
    "wget -q -T 3 -O - 'http://${gateway}:${other_broker_port}/broker.txt'"

  expect_guest_blocked \
    "${label} cannot reach forbidden host port" \
    "$vm_name" \
    "wget -q -T 3 -O - 'http://${gateway}:${FORBIDDEN_PORT}/forbidden.txt'"

  expect_guest_blocked \
    "${label} cannot reach direct IPv4 internet" \
    "$vm_name" \
    "wget -q -T 3 -O - 'http://1.1.1.1/'"

  expect_guest_blocked \
    "${label} cannot reach direct external DNS" \
    "$vm_name" \
    "nslookup github.com 1.1.1.1 >/dev/null"
}

run_two_session_pass() {
  local pass_label="$1"
  local first_to_stop="$2"
  local tmp_dir
  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/writ-two-session-proof.XXXXXX")"

  CURRENT_TMP_DIR="$tmp_dir"
  CURRENT_SESSION_A_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  CURRENT_SESSION_B_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  CURRENT_NETWORK_A_NAME="writ-agent-net-${CURRENT_SESSION_A_ID}"
  CURRENT_NETWORK_B_NAME="writ-agent-net-${CURRENT_SESSION_B_ID}"
  CURRENT_VM_A_NAME="writ-agent-vm-${CURRENT_SESSION_A_ID}"
  CURRENT_VM_B_NAME="writ-agent-vm-${CURRENT_SESSION_B_ID}"
  CURRENT_IPV4_A_CIDR="$(cidr_alloc_subnet "$IPV4_POOL" 24 "$SUBNET_A_INDEX")"
  CURRENT_IPV4_B_CIDR="$(cidr_alloc_subnet "$IPV4_POOL" 24 "$SUBNET_B_INDEX")"
  CURRENT_IPV6_A_CIDR="$(cidr_alloc_subnet "$IPV6_POOL" 64 "$SUBNET_A_INDEX")"
  CURRENT_IPV6_B_CIDR="$(cidr_alloc_subnet "$IPV6_POOL" 64 "$SUBNET_B_INDEX")"
  CURRENT_BROKER_A_PID=""
  CURRENT_BROKER_B_PID=""
  CURRENT_FORBIDDEN_PID=""
  CURRENT_STOP_A_DONE=0
  CURRENT_STOP_B_DONE=0
  CURRENT_CLEANUP_STARTED=0

  local pf_a_anchor="writ/session/${CURRENT_SESSION_A_ID}"
  local pf_b_anchor="writ/session/${CURRENT_SESSION_B_ID}"
  local broker_a_dir="${tmp_dir}/broker-a"
  local broker_b_dir="${tmp_dir}/broker-b"
  local forbidden_dir="${tmp_dir}/forbidden"
  local start_a_output="${tmp_dir}/runner-start-a.txt"
  local start_b_output="${tmp_dir}/runner-start-b.txt"
  local pf_a_before_stop="${tmp_dir}/pf-a-before-stop.txt"
  local pf_b_before_stop="${tmp_dir}/pf-b-before-stop.txt"
  local pf_survivor_after_stop="${tmp_dir}/pf-survivor-after-stop.txt"
  local ipv4_a_gateway
  local ipv4_b_gateway
  local broker_a_port
  local broker_b_port
  local forbidden_port
  local guest_a_ipv4
  local guest_b_ipv4

  ipv4_a_gateway="$(cidr_gateway "$CURRENT_IPV4_A_CIDR")"
  ipv4_b_gateway="$(cidr_gateway "$CURRENT_IPV4_B_CIDR")"

  mkdir -p "$broker_a_dir" "$broker_b_dir" "$forbidden_dir"
  printf 'broker-a-ok\n' >"${broker_a_dir}/broker.txt"
  printf 'broker-b-ok\n' >"${broker_b_dir}/broker.txt"
  printf 'forbidden-open\n' >"${forbidden_dir}/forbidden.txt"

  broker_a_port="$(pick_port)"
  broker_b_port="$(pick_port)"
  while [[ "$broker_b_port" == "$broker_a_port" ]]; do
    broker_b_port="$(pick_port)"
  done
  forbidden_port="$(pick_port)"
  while [[ "$forbidden_port" == "$broker_a_port" || "$forbidden_port" == "$broker_b_port" ]]; do
    forbidden_port="$(pick_port)"
  done

  CURRENT_BROKER_A_PID="$(start_http_server "$broker_a_dir" "$broker_a_port" "${tmp_dir}/broker-a.log")"
  CURRENT_BROKER_B_PID="$(start_http_server "$broker_b_dir" "$broker_b_port" "${tmp_dir}/broker-b.log")"
  CURRENT_FORBIDDEN_PID="$(start_http_server "$forbidden_dir" "$forbidden_port" "${tmp_dir}/forbidden.log")"
  wait_for_host_http "$broker_a_port" "${pass_label} broker A" "broker.txt" "broker-a-ok"
  wait_for_host_http "$broker_b_port" "${pass_label} broker B" "broker.txt" "broker-b-ok"
  wait_for_host_http "$forbidden_port" "${pass_label} forbidden" "forbidden.txt" "forbidden-open"
  FORBIDDEN_PORT="$forbidden_port"
  log "${pass_label}: host listeners are up: broker_a=${broker_a_port}, broker_b=${broker_b_port}, forbidden=${forbidden_port}"

  start_session "${pass_label} session A" "$CURRENT_SESSION_A_ID" "$SUBNET_A_INDEX" \
    "$CURRENT_VM_A_NAME" "$CURRENT_NETWORK_A_NAME" "$CURRENT_IPV4_A_CIDR" \
    "$ipv4_a_gateway" "$broker_a_port" "lifecycle-released-a" "$start_a_output"
  start_session "${pass_label} session B" "$CURRENT_SESSION_B_ID" "$SUBNET_B_INDEX" \
    "$CURRENT_VM_B_NAME" "$CURRENT_NETWORK_B_NAME" "$CURRENT_IPV4_B_CIDR" \
    "$ipv4_b_gateway" "$broker_b_port" "lifecycle-released-b" "$start_b_output"

  wait_for_released_guest_command "${pass_label} session A" "$CURRENT_VM_A_NAME" "lifecycle-released-a"
  wait_for_released_guest_command "${pass_label} session B" "$CURRENT_VM_B_NAME" "lifecycle-released-b"

  expect_guest_success \
    "${pass_label} session A guest has required probe tools" \
    "$CURRENT_VM_A_NAME" \
    'command -v ip >/dev/null && command -v wget >/dev/null && command -v nslookup >/dev/null'
  expect_guest_success \
    "${pass_label} session B guest has required probe tools" \
    "$CURRENT_VM_B_NAME" \
    'command -v ip >/dev/null && command -v wget >/dev/null && command -v nslookup >/dev/null'

  assert_guest_has_no_routable_ipv6 "${pass_label} session A" "$CURRENT_VM_A_NAME"
  assert_guest_has_no_routable_ipv6 "${pass_label} session B" "$CURRENT_VM_B_NAME"

  guest_a_ipv4="$(guest_ipv4_addr "$CURRENT_VM_A_NAME")"
  guest_b_ipv4="$(guest_ipv4_addr "$CURRENT_VM_B_NAME")"
  if [[ -z "$guest_a_ipv4" || -z "$guest_b_ipv4" ]]; then
    die "${pass_label}: could not determine both guest IPv4 addresses"
  fi
  log "${pass_label}: guest IPv4 addresses: session_a=${guest_a_ipv4}, session_b=${guest_b_ipv4}"

  assert_basic_session_posture "${pass_label} session A" "$CURRENT_VM_A_NAME" "$ipv4_a_gateway" \
    "$broker_a_port" "broker-a-ok" "$broker_b_port"
  assert_basic_session_posture "${pass_label} session B" "$CURRENT_VM_B_NAME" "$ipv4_b_gateway" \
    "$broker_b_port" "broker-b-ok" "$broker_a_port"

  pf_anchor_rules "$pf_a_anchor" >"$pf_a_before_stop"
  pf_anchor_rules "$pf_b_anchor" >"$pf_b_before_stop"

  if [[ "$first_to_stop" == "A" ]]; then
    stop_session "${pass_label} session A" "$CURRENT_SESSION_A_ID" "$SUBNET_A_INDEX"
    CURRENT_STOP_A_DONE=1
    assert_container_absent "${pass_label} session A" "$CURRENT_VM_A_NAME"
    assert_network_absent "${pass_label} session A" "$CURRENT_NETWORK_A_NAME"
    assert_pf_anchor_empty "${pass_label} session A" "$pf_a_anchor"
    assert_no_pf_state_for_guest "${pass_label} session A" "$guest_a_ipv4"
    assert_pf_anchor_unchanged "${pass_label} session B" "$pf_b_anchor" \
      "$pf_b_before_stop" "$pf_survivor_after_stop"
    expect_guest_success \
      "${pass_label} session B still reaches its broker after session A stopped" \
      "$CURRENT_VM_B_NAME" \
      "wget -q -T 3 -O - 'http://${ipv4_b_gateway}:${broker_b_port}/broker.txt' | grep -q '^broker-b-ok$'"
    expect_guest_blocked \
      "${pass_label} session B still cannot reach session A broker port after session A stopped" \
      "$CURRENT_VM_B_NAME" \
      "wget -q -T 3 -O - 'http://${ipv4_b_gateway}:${broker_a_port}/broker.txt'"

    stop_session "${pass_label} session B" "$CURRENT_SESSION_B_ID" "$SUBNET_B_INDEX"
    CURRENT_STOP_B_DONE=1
    assert_container_absent "${pass_label} session B" "$CURRENT_VM_B_NAME"
    assert_network_absent "${pass_label} session B" "$CURRENT_NETWORK_B_NAME"
    assert_pf_anchor_empty "${pass_label} session B" "$pf_b_anchor"
    assert_no_pf_state_for_guest "${pass_label} session B" "$guest_b_ipv4"
  else
    stop_session "${pass_label} session B" "$CURRENT_SESSION_B_ID" "$SUBNET_B_INDEX"
    CURRENT_STOP_B_DONE=1
    assert_container_absent "${pass_label} session B" "$CURRENT_VM_B_NAME"
    assert_network_absent "${pass_label} session B" "$CURRENT_NETWORK_B_NAME"
    assert_pf_anchor_empty "${pass_label} session B" "$pf_b_anchor"
    assert_no_pf_state_for_guest "${pass_label} session B" "$guest_b_ipv4"
    assert_pf_anchor_unchanged "${pass_label} session A" "$pf_a_anchor" \
      "$pf_a_before_stop" "$pf_survivor_after_stop"
    expect_guest_success \
      "${pass_label} session A still reaches its broker after session B stopped" \
      "$CURRENT_VM_A_NAME" \
      "wget -q -T 3 -O - 'http://${ipv4_a_gateway}:${broker_a_port}/broker.txt' | grep -q '^broker-a-ok$'"
    expect_guest_blocked \
      "${pass_label} session A still cannot reach session B broker port after session B stopped" \
      "$CURRENT_VM_A_NAME" \
      "wget -q -T 3 -O - 'http://${ipv4_a_gateway}:${broker_b_port}/broker.txt'"

    stop_session "${pass_label} session A" "$CURRENT_SESSION_A_ID" "$SUBNET_A_INDEX"
    CURRENT_STOP_A_DONE=1
    assert_container_absent "${pass_label} session A" "$CURRENT_VM_A_NAME"
    assert_network_absent "${pass_label} session A" "$CURRENT_NETWORK_A_NAME"
    assert_pf_anchor_empty "${pass_label} session A" "$pf_a_anchor"
    assert_no_pf_state_for_guest "${pass_label} session A" "$guest_a_ipv4"
  fi

  cleanup
  CURRENT_TMP_DIR=""
  CURRENT_SESSION_A_ID=""
  CURRENT_SESSION_B_ID=""
  log "${pass_label}: two-session pass succeeded for ${CURRENT_IPV4_A_CIDR} and ${CURRENT_IPV4_B_CIDR}"
}

require_cmd container
require_cmd curl
require_cmd python3
require_cmd sudo
require_cmd uuidgen
choose_cargo

if [[ "$SUBNET_A_INDEX" == "$SUBNET_B_INDEX" ]]; then
  die "session subnet indexes must differ"
fi

cidr_alloc_subnet "$IPV4_POOL" 24 "$SUBNET_A_INDEX" >/dev/null
cidr_alloc_subnet "$IPV4_POOL" 24 "$SUBNET_B_INDEX" >/dev/null
cidr_alloc_subnet "$IPV6_POOL" 64 "$SUBNET_A_INDEX" >/dev/null
cidr_alloc_subnet "$IPV6_POOL" 64 "$SUBNET_B_INDEX" >/dev/null

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

run_two_session_pass "pass 1, stop A first" "A"
run_two_session_pass "pass 2, stop B first" "B"

trap - EXIT INT TERM
log "two-session lifecycle proof succeeded in both teardown orders for subnet indexes ${SUBNET_A_INDEX} and ${SUBNET_B_INDEX}"
