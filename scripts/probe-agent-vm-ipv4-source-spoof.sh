#!/usr/bin/env bash
set -Eeuo pipefail

# Associative arrays below need bash 4+; macOS's /bin/bash is 3.2. The Nix
# dev shell (and Homebrew) provide a modern bash on PATH.
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  printf '[probe-ipv4-spoof] error: bash %s is too old; run from `nix develop` (bash 4+ required)\n' "$BASH_VERSION" >&2
  exit 1
fi

usage() {
  cat <<'EOF'
Usage: scripts/probe-agent-vm-ipv4-source-spoof.sh

Measures, on real hardware, what happens to an IPv4 frame the agent guest
sends with a source address outside its session subnet.

Why: the session PF anchor's IPv4 rules are matched on the session /24 as
*source* (`pass in quick inet proto tcp from <agent /24> to <broker> ...` and
`block return in quick inet from <agent /24> to any`). A frame whose source is
not in that /24 matches neither rule and falls through to whatever the host's
default PF policy is. Whether Apple's vmnet forwards such a frame at all is
unknown; this script finds out. See docs/design/ipv4-only-network-confinement.md,
"Known deltas from the target rules" and "Evidence protocol", and
docs/plans/2026-09-01-ipv4-only-locked-v1.md, stage C2b and "Beyond E3"
question 4.

This is a measurement, not a proof: it reports what it observed and a verdict,
and its exit status is 0 whenever the measurement itself completed. It runs
two guests from the same image:

  unconfined  a root guest on a network this script creates itself, with no
              PF anchor. This is the evidence protocol's positive control: a
              sender that *can* reach the listener, with the same tooling, on
              a bridge of the same kind. What it observes is the platform fact
              about vmnet, with the session rules out of the picture.
  session     a runner-managed guest under the legacy ipv4-only profile,
              exactly as prove-agent-vm-lifecycle.sh starts it. What it
              observes is what the session rules do with the same frames.

From each guest it sends UDP datagrams to a host listener at that guest's
gateway, with three sources:

  control   the guest's own address: unconfined it MUST reach the listener,
            and under the session it MUST be forwarded onto the bridge,
            counted by the labelled IPv4 deny, and NOT delivered. Anything
            else means the observers are broken and the run aborts.
  foreign   an address outside every network the script knows about
            (10.77.0.5/32 by default, added to eth0 by the root guest)
  sibling   an address in a *different* session /24 of the broker's pool
            (index SUBNET_INDEX+1, or SUBNET_INDEX-1 when the session holds
            the pool's last /24), the cross-session case; skipped, and said
            so, when the pool has only one /24

For each datagram the host observes three things, none reported by a guest:
  - tcpdump on that guest's bridge: was the frame forwarded to the host side?
  - a host UDP listener bound on every address: did it reach a host socket?
  - (session only) the anchor's labelled rule counters: did PF count it?

One guest-side fact gates whether host silence means anything: eth0's TX
packet counter must rise and nc must print no error, or the guest emitted
nothing. Guest facts can withhold a verdict, never award one: a session
result whose unconfined twin was forwarded but which was itself not seen on
the bridge is reported INCONCLUSIVE, not as a platform fact. The IPv4 deny is
source-scoped to the session /24, so for the foreign and sibling probes it
cannot match by construction; a rise in its counter during those windows is
unrelated in-subnet traffic and is reported as such.

Requires:
  - macOS with Apple container installed and `container system start` already run
  - root privileges through sudo for pfctl and tcpdump
  - a top-level PF rule in /etc/pf.conf: anchor "writ/session/*"
  - no other writ session anchor loaded: every child of that wildcard is
    evaluated for every bridge, so another session's source-scoped deny
    (above all one on the sibling /24) would confound both guests. The
    script refuses to start while any exists.
  - python3, curl, cargo or nix, and an Alpine-compatible image with sh, ip,
    and a BusyBox nc that supports `-u` and `-s ADDR` (alpine:latest does)

Environment overrides (same as prove-agent-vm-lifecycle.sh, plus two):
  WRIT_PROVE_IMAGE       OCI image to run, default alpine:latest
  WRIT_PROVE_IPV4_POOL   broker-owned IPv4 pool, default 192.168.0.0/16
  WRIT_PROVE_IPV6_POOL   broker-owned IPv6 pool, default fd83:b6f2:e57::/48
  WRIT_PROVE_SUBNET_INDEX  session subnet index, default 252
  WRIT_PROVE_BROKER_PORT_MIN  minimum allowed broker port, default 49152
  WRIT_PROVE_BROKER_PORT_MAX  maximum allowed broker port, default 65535
  WRIT_PROBE_FOREIGN_SOURCE   out-of-pool source to spoof, default 10.77.0.5
  WRIT_PROBE_CONTROL_SUBNET   /24 for the unconfined network, outside the
                              pool, default 172.31.77.0/24
EOF
}

log() {
  printf '[probe-ipv4-spoof] %s\n' "$*"
}

die() {
  printf '[probe-ipv4-spoof] error: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/writ-ipv4-spoof-probe.XXXXXX")"
IMAGE="${WRIT_PROVE_IMAGE:-alpine:latest}"
IPV4_POOL="${WRIT_PROVE_IPV4_POOL:-192.168.0.0/16}"
IPV6_POOL="${WRIT_PROVE_IPV6_POOL:-fd83:b6f2:e57::/48}"
SUBNET_INDEX="${WRIT_PROVE_SUBNET_INDEX:-252}"
BROKER_PORT_MIN="${WRIT_PROVE_BROKER_PORT_MIN:-49152}"
BROKER_PORT_MAX="${WRIT_PROVE_BROKER_PORT_MAX:-65535}"
FOREIGN_SOURCE="${WRIT_PROBE_FOREIGN_SOURCE:-10.77.0.5}"
CONTROL_SUBNET="${WRIT_PROBE_CONTROL_SUBNET:-172.31.77.0/24}"
IPV6_MODE="ipv4-only-no-guest-ipv6"
SESSION_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
NETWORK_NAME="writ-agent-net-${SESSION_ID}"
VM_NAME="writ-agent-vm-${SESSION_ID}"
PF_ANCHOR="writ/session/${SESSION_ID}"
CONTROL_NETWORK="writ-probe-ctl-net-${SESSION_ID}"
CONTROL_VM="writ-probe-ctl-vm-${SESSION_ID}"
BROKER_DIR="${TMP_DIR}/broker"
START_OUTPUT="${TMP_DIR}/runner-start.txt"
LISTENER_LOG="${TMP_DIR}/listener.log"
RUNNER=""
HELPER=""
BROKER_PID=""
LISTENER_PID=""
BROKER_PORT=""
PROBE_PORT=""
IPV4_CIDR=""
IPV4_GATEWAY=""
SIBLING_INDEX=""
SIBLING_CIDR=""
SIBLING_SOURCE=""
CARGO_CMD=()
STOP_DONE=0
CONTROL_STARTED=0
cleanup_started=0
# Per-target facts, keyed "session" / "unconfined": the guest, its gateway,
# the host bridge its frames traverse, and the tcpdump capturing that bridge.
declare -A TARGET_VM=() TARGET_GATEWAY=() TARGET_BRIDGE=() TARGET_CAPTURE=() TARGET_CAPTURE_PID=()

cleanup() {
  if [[ "$cleanup_started" -eq 1 ]]; then
    return
  fi
  cleanup_started=1
  log "cleaning up VMs, networks, listeners, captures, and PF anchor"

  local pid
  for pid in "${TARGET_CAPTURE_PID[@]}"; do
    sudo kill "$pid" >/dev/null 2>&1 || true
  done
  if [[ -n "$LISTENER_PID" ]]; then
    kill "$LISTENER_PID" >/dev/null 2>&1 || true
    wait "$LISTENER_PID" 2>/dev/null || true
  fi

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

  container rm -f "$VM_NAME" >/dev/null 2>&1 || true
  container stop "$VM_NAME" >/dev/null 2>&1 || true
  container delete "$VM_NAME" >/dev/null 2>&1 || true

  if [[ -n "$HELPER" && -n "$IPV4_CIDR" ]]; then
    sudo "$HELPER" remove \
      --session-id "$SESSION_ID" \
      --ipv4-pool "$IPV4_POOL" \
      --ipv6-pool "$IPV6_POOL" \
      --ipv4-cidr "$IPV4_CIDR" >/dev/null 2>&1 || true
  fi

  container network rm "$NETWORK_NAME" >/dev/null 2>&1 || \
    container network delete "$NETWORK_NAME" >/dev/null 2>&1 || true

  if [[ "$CONTROL_STARTED" -eq 1 ]]; then
    container rm -f "$CONTROL_VM" >/dev/null 2>&1 || true
    container stop "$CONTROL_VM" >/dev/null 2>&1 || true
    container delete "$CONTROL_VM" >/dev/null 2>&1 || true
    container network rm "$CONTROL_NETWORK" >/dev/null 2>&1 || \
      container network delete "$CONTROL_NETWORK" >/dev/null 2>&1 || true
  fi

  if [[ -n "$BROKER_PID" ]]; then
    kill "$BROKER_PID" >/dev/null 2>&1 || true
    wait "$BROKER_PID" 2>/dev/null || true
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
size = 1 << (base.max_prefixlen - new_prefix)
subnet = ipaddress.ip_network((int(base.network_address) + index * size, new_prefix))
if not subnet.subnet_of(base):
    print(f"subnet index {index} is outside {base}", file=sys.stderr)
    raise SystemExit(1)
print(subnet)
PY
}

# The index of a /24 in the pool other than $2, preferring $2+1 and falling
# back to $2-1; prints nothing when the pool holds a single /24.
sibling_subnet_index() {
  python3 - "$1" "$2" <<'PY'
import ipaddress
import sys

base = ipaddress.ip_network(sys.argv[1], strict=True)
index = int(sys.argv[2])
count = 1 << max(0, 24 - base.prefixlen)
for candidate in (index + 1, index - 1):
    if 0 <= candidate < count:
        print(candidate)
        break
PY
}

# Fails unless address $2 lies outside network $1.
require_outside() {
  python3 - "$1" "$2" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=True)
address = ipaddress.ip_address(sys.argv[2])
if address in network:
    print(f"{address} is inside {network}", file=sys.stderr)
    raise SystemExit(1)
PY
}

# Fails unless networks $1 and $2 are disjoint.
require_disjoint() {
  python3 - "$1" "$2" <<'PY'
import ipaddress
import sys

a = ipaddress.ip_network(sys.argv[1], strict=True)
b = ipaddress.ip_network(sys.argv[2], strict=True)
if a.overlaps(b):
    print(f"{a} overlaps {b}", file=sys.stderr)
    raise SystemExit(1)
PY
}

cidr_host() {
  # The n-th usable host of a network.
  python3 - "$1" "$2" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=True)
hosts = network.hosts()
for _ in range(int(sys.argv[2]) - 1):
    next(hosts)
print(next(hosts))
PY
}

# A free port in [MIN, MAX] for PROTO (tcp|udp), tested on the wildcard
# address the host listeners bind. The broker port must lie inside the range
# the runner is told about, or it refuses to start (BrokerPortOutsideRange).
pick_port() {
  python3 - "$1" "$2" "$3" <<'PY'
import random
import socket
import sys

proto, lo, hi = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
candidates = list(range(lo, hi + 1))
random.shuffle(candidates)
for port in candidates[:512]:
    with socket.socket(socket.AF_INET, kind) as s:
        try:
            s.bind(("0.0.0.0", port))
        except OSError:
            continue
        print(port)
        raise SystemExit(0)
print(f"no free {proto} port in {lo}-{hi}", file=sys.stderr)
raise SystemExit(1)
PY
}

start_http_server() {
  python3 -m http.server "$2" --bind 0.0.0.0 --directory "$1" >"$3" 2>&1 &
  echo "$!"
}

# A UDP listener on every host address, logging one line per datagram:
# "<source ip> <source port> <payload>". This, not anything a guest says,
# is what decides "reached the host". Sets LISTENER_PID rather than echoing
# it: launched inside a `$(...)` the listener would inherit the substitution's
# pipe and its receive loop would hold it open forever.
start_udp_listener() {
  python3 - "$1" "$2" <<'PY' >"${TMP_DIR}/listener.err" 2>&1 &
import socket
import sys

port = int(sys.argv[1])
log_path = sys.argv[2]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", port))
with open(log_path, "a", buffering=1) as log:
    log.write("listening\n")
    while True:
        data, (host, sport) = sock.recvfrom(4096)
        log.write(f"{host} {sport} {data.decode('ascii', 'replace')}\n")
PY
  LISTENER_PID=$!
}

# Run a shell command as root inside guest $1.
guest_in() {
  container exec "$1" sh -lc "$2"
}

wait_for_released_guest_command() {
  for _ in {1..50}; do
    if guest_in "$VM_NAME" 'test "$(cat /tmp/writ-agent-vm-released 2>/dev/null)" = probe-released' \
      >/dev/null 2>&1; then
      return
    fi
    sleep 0.1
  done
  die "released guest command did not write its marker"
}

wait_for_guest_shell() {
  for _ in {1..300}; do
    if guest_in "$1" true >/dev/null 2>&1; then
      return
    fi
    sleep 0.1
  done
  die "guest ${1} did not accept an exec within 30s"
}

guest_ipv4_addr() {
  guest_in "$1" "ip -4 -o addr show scope global | awk '{print \$4}' | head -n 1 | cut -d/ -f1"
}

guest_default_gateway() {
  guest_in "$1" "ip -4 route show default | awk '{print \$3}' | head -n 1"
}

# eth0's transmitted-packet counter, as the guest kernel reports it. Guest
# reported, so it never decides a verdict; it only decides whether there was
# a frame for the host observers to see at all.
guest_tx_packets() {
  local n
  n="$(guest_in "$1" 'cat /sys/class/net/eth0/statistics/tx_packets' 2>/dev/null | tr -d '[:space:]')"
  [[ "$n" =~ ^[0-9]+$ ]] || die "could not read eth0 tx_packets in ${1} (got '${n}')"
  printf '%s\n' "$n"
}

require_guest_tooling() {
  guest_in "$1" 'command -v ip >/dev/null && command -v nc >/dev/null' \
    || die "guest image lacks ip or nc (use WRIT_PROVE_IMAGE with BusyBox nc)"
  guest_in "$1" 'nc 2>&1 | grep -q -- "-s ADDR"' \
    || die "guest nc does not support -s ADDR; the probe needs a source-selectable sender"
}

# Child anchors currently loaded under writ/session, one per line. Both
# listings are consulted because pfctl prints nested anchors differently
# across macOS releases.
existing_session_anchors() {
  { sudo pfctl -a writ/session -sA 2>/dev/null; sudo pfctl -sA 2>/dev/null; } \
    | grep -Eo 'writ/session/[0-9a-f-]+' | sort -u
}

# The bridge the interface-scoped IPv6 deny was installed on, read from the
# session anchor: the same interface the session's IPv4 frames traverse.
session_bridge() {
  sudo pfctl -a "$PF_ANCHOR" -sr 2>/dev/null \
    | grep -Eo 'on bridge[0-9]+' | head -n 1 | awk '{print $2}'
}

# The host bridge whose address is gateway $1, from ifconfig: the same lookup
# the runner performs (parse_bridge_for_gateway) for the session bridge.
bridge_for_gateway() {
  ifconfig | awk -v gw="$1" '
    /^[a-z]/ { iface = $1; sub(":$", "", iface) }
    $1 == "inet" && $2 == gw && iface ~ /^bridge[0-9]+$/ { print iface; exit }
  '
}

# Per-label packet counters of the session anchor, as "label count" lines.
anchor_counters() {
  sudo pfctl -a "$PF_ANCHOR" -vsr 2>/dev/null | python3 -c '
import re, sys
label = None
for line in sys.stdin:
    m = re.search(r"label \"([^\"]+)\"", line)
    if m:
        label = m.group(1)
        continue
    m = re.search(r"Packets: (\d+)", line)
    if m and label is not None:
        print(f"{label} {m.group(1)}")
        label = None
'
}

counter_of() {
  # $1 = counters text, $2 = label
  printf '%s\n' "$1" | awk -v l="$2" '$0 ~ "^"l" " {print $NF}' | head -n 1
}

# Start capturing UDP to the probe port on target $1's bridge.
start_capture() {
  local target="$1" bridge="${TARGET_BRIDGE[$1]}"
  local capture="${TMP_DIR}/tcpdump-${target}.log" err="${TMP_DIR}/tcpdump-${target}.err"
  log "capturing UDP to port ${PROBE_PORT} on ${bridge} (${target})"
  # The redirects are deliberately the unprivileged shell's: the log lives in
  # the user-owned TMP_DIR, and only the capture itself needs root.
  # shellcheck disable=SC2024
  sudo tcpdump -i "$bridge" -n -l -q "udp and dst port ${PROBE_PORT}" >"$capture" 2>"$err" &
  TARGET_CAPTURE_PID[$target]=$!
  TARGET_CAPTURE[$target]="$capture"
  sleep 2
  kill -0 "${TARGET_CAPTURE_PID[$target]}" 2>/dev/null \
    || die "tcpdump did not start on ${bridge}: $(cat "$err")"
}

# Send one UDP datagram from target $1's guest with source $3 to that guest's
# gateway, and report what the host saw. The guest's exit status is logged
# and ignored. Writes one line "<name> <emitted> <forwarded> <reached> <delta>"
# to result-<target>-<name>, because every consumer is a single `read`.
probe() {
  local target="$1" name="$2" source="$3" add_address="$4"
  local vm="${TARGET_VM[$target]}" gateway="${TARGET_GATEWAY[$target]}"
  local bridge="${TARGET_BRIDGE[$target]}" capture="${TARGET_CAPTURE[$target]}"
  local nonce="writ-spoof-${target}-${name}-${RANDOM}${RANDOM}"
  log "probe ${target}/${name}: source ${source} -> ${gateway}:${PROBE_PORT} (${nonce})"

  if [[ "$add_address" == "yes" ]]; then
    # Tolerate an alias that already exists, then insist it is there: a
    # silently missing alias would make nc fail to bind, no frame would be
    # sent, and every observer's silence would read as a platform verdict.
    guest_in "$vm" "ip addr add ${source}/32 dev eth0 2>/dev/null || true" || true
    guest_in "$vm" "ip -4 -o addr show dev eth0 | grep -q 'inet ${source}/32 '" \
      || die "${vm} did not configure ${source}/32 on eth0; the ${target}/${name} probe would send nothing"
  fi

  local before="" after="" tx_before tx_after
  if [[ "$target" == "session" ]]; then
    before="$(anchor_counters)"
  fi
  tx_before="$(guest_tx_packets "$vm")"
  local capture_lines_before
  capture_lines_before="$(wc -l <"$capture" | tr -d ' ')"

  # -w 1: BusyBox nc otherwise waits for a reply that never comes. Its exit
  # status is diagnostic (a reply timeout is the expected outcome). Whether a
  # frame left the guest at all is decided below from eth0's TX counter and
  # nc's stderr, not from this status.
  local nc_err="${TMP_DIR}/nc-${target}-${name}.err"
  set +e
  guest_in "$vm" "printf '%s' '${nonce}' | nc -u -s ${source} -w 1 ${gateway} ${PROBE_PORT}" 2>"$nc_err"
  local guest_status=$?
  set -e
  log "  guest nc exit status ${guest_status} (diagnostic only)"
  sleep 2
  tx_after="$(guest_tx_packets "$vm")"

  local emitted="yes"
  if [[ -s "$nc_err" ]]; then
    emitted="no"
    log "  guest nc wrote to stderr: $(tr '\n' ' ' <"$nc_err")"
  fi
  if (( tx_after <= tx_before )); then
    emitted="no"
    log "  guest eth0 TX packet counter did not rise (${tx_before} -> ${tx_after})"
  fi

  local forwarded="no" reached="no"
  if sed -n "$((capture_lines_before + 1)),\$p" "$capture" | grep -q "${source}\.[0-9]* > ${gateway}\.${PROBE_PORT}"; then
    forwarded="yes"
  fi
  if grep -q "^${source} [0-9]* ${nonce}\$" "$LISTENER_LOG"; then
    reached="yes"
  fi
  local delta=0 counter_text=""
  if [[ "$target" == "session" ]]; then
    after="$(anchor_counters)"
    local v4_before v4_after
    v4_before="$(counter_of "$before" "writ deny agent v4")"
    v4_after="$(counter_of "$after" "writ deny agent v4")"
    delta=$(( ${v4_after:-0} - ${v4_before:-0} ))
    counter_text="; 'writ deny agent v4' counter +${delta}"
  fi

  log "  guest emitted a frame: ${emitted}; forwarded onto ${bridge}: ${forwarded}; reached host socket: ${reached}${counter_text}"
  RESULTS+=("${target}/${name} source=${source} emitted=${emitted} forwarded=${forwarded} reached=${reached} deny_v4_delta=${delta}")
  printf '%s %s %s %s %s\n' "$name" "$emitted" "$forwarded" "$reached" "$delta" >"${TMP_DIR}/result-${target}-${name}"
}

require_cmd container
require_cmd python3
require_cmd curl
require_cmd uuidgen
require_cmd tcpdump
require_cmd ifconfig
choose_cargo

IPV4_CIDR="$(cidr_alloc_subnet "$IPV4_POOL" 24 "$SUBNET_INDEX")"
IPV4_GATEWAY="$(cidr_host "$IPV4_CIDR" 1)"
# The unconfined network must be a /24 disjoint from the pool, so that neither
# guest's own address is "foreign" or "sibling" to the other.
[[ "$CONTROL_SUBNET" == */24 ]] || die "WRIT_PROBE_CONTROL_SUBNET=${CONTROL_SUBNET} must be a /24"
require_disjoint "$IPV4_POOL" "$CONTROL_SUBNET" \
  || die "WRIT_PROBE_CONTROL_SUBNET=${CONTROL_SUBNET} overlaps the pool ${IPV4_POOL}"
# A "foreign" source inside any network here is not foreign: inside the
# session /24 the source-scoped deny matches it legitimately, elsewhere in
# the pool it is the sibling case, and inside the control subnet it is that
# guest's own neighbourhood. Either way the verdict would be about the wrong
# thing.
require_outside "$IPV4_POOL" "$FOREIGN_SOURCE" \
  || die "WRIT_PROBE_FOREIGN_SOURCE=${FOREIGN_SOURCE} lies inside the pool ${IPV4_POOL}; the foreign probe needs an out-of-pool source"
require_outside "$CONTROL_SUBNET" "$FOREIGN_SOURCE" \
  || die "WRIT_PROBE_FOREIGN_SOURCE=${FOREIGN_SOURCE} lies inside the control subnet ${CONTROL_SUBNET}"
SIBLING_INDEX="$(sibling_subnet_index "$IPV4_POOL" "$SUBNET_INDEX")"
if [[ -n "$SIBLING_INDEX" ]]; then
  SIBLING_CIDR="$(cidr_alloc_subnet "$IPV4_POOL" 24 "$SIBLING_INDEX")"
  SIBLING_SOURCE="$(cidr_host "$SIBLING_CIDR" 7)"
else
  log "pool ${IPV4_POOL} holds a single /24: the sibling-subnet probe is unavailable and will be skipped"
fi

mkdir -p "$BROKER_DIR"
printf 'broker-ok\n' >"${BROKER_DIR}/broker.txt"

log "requesting sudo credentials for pfctl and tcpdump"
sudo -v
sudo pfctl -s info 2>/dev/null | grep -q 'Status: Enabled' || die "PF is not enabled"
sudo pfctl -sr 2>/dev/null | grep -q 'anchor "writ/session/\*"' \
  || die 'missing top-level PF anchor; add `anchor "writ/session/*"` to /etc/pf.conf and reload PF'
# Every child anchor of the wildcard is consulted for every packet on every
# interface, so a concurrent session's `block ... from <its /24>` would deny
# our sibling-source datagram on the unconfined bridge as well, and the run
# would pin that as a vmnet fact. Refuse rather than reason around it.
EXISTING_ANCHORS="$(existing_session_anchors)"
[[ -z "$EXISTING_ANCHORS" ]] \
  || die "other writ session anchors are loaded and would confound the measurement; stop those sessions first: $(tr '\n' ' ' <<<"$EXISTING_ANCHORS")"

log "building PF helper and lifecycle runner"
"${CARGO_CMD[@]}" build --quiet --bin writ-agent-vm-pf-helper --bin writ-agent-vm-runner
HELPER="${ROOT_DIR}/target/debug/writ-agent-vm-pf-helper"
RUNNER="${ROOT_DIR}/target/debug/writ-agent-vm-runner"

BROKER_PORT="$(pick_port tcp "$BROKER_PORT_MIN" "$BROKER_PORT_MAX")"
PROBE_PORT="$(pick_port udp "$BROKER_PORT_MIN" "$BROKER_PORT_MAX")"
# Prefer a distinct probe port so the log reads unambiguously, but the probe
# listener is UDP and the broker allow is TCP-only, so sharing the number is
# harmless. A one-port range (min == max) is valid and must not spin here.
for _ in {1..20}; do
  [[ "$PROBE_PORT" != "$BROKER_PORT" ]] && break
  [[ "$BROKER_PORT_MIN" == "$BROKER_PORT_MAX" ]] && break
  PROBE_PORT="$(pick_port udp "$BROKER_PORT_MIN" "$BROKER_PORT_MAX")"
done
if [[ "$PROBE_PORT" == "$BROKER_PORT" ]]; then
  log "probe UDP port shares its number with the TCP broker port ${BROKER_PORT} (range has no free alternative)"
fi
BROKER_PID="$(start_http_server "$BROKER_DIR" "$BROKER_PORT" "${TMP_DIR}/broker.log")"
start_udp_listener "$PROBE_PORT" "$LISTENER_LOG"
for _ in {1..50}; do
  grep -q '^listening$' "$LISTENER_LOG" 2>/dev/null && break
  sleep 0.1
done
grep -q '^listening$' "$LISTENER_LOG" \
  || die "UDP listener did not start: $(cat "${TMP_DIR}/listener.err" 2>/dev/null)"
log "host listeners are up: broker=${BROKER_PORT}, probe target (forbidden)=${PROBE_PORT}"

# --- the unconfined positive control: a root guest on a network of this
# script's own making, with no PF anchor, from the same image. Created the
# way the runner creates session networks and guests, minus the anchor.
log "starting unconfined control guest ${CONTROL_VM} on ${CONTROL_SUBNET} (no PF anchor)"
CONTROL_STARTED=1
container network create --internal --subnet "$CONTROL_SUBNET" "$CONTROL_NETWORK" >/dev/null
container run --name "$CONTROL_VM" --network "$CONTROL_NETWORK" -d "$IMAGE" sh -c 'sleep 600' >/dev/null
wait_for_guest_shell "$CONTROL_VM"
require_guest_tooling "$CONTROL_VM"
TARGET_VM[unconfined]="$CONTROL_VM"
TARGET_GATEWAY[unconfined]="$(guest_default_gateway "$CONTROL_VM")"
[[ -n "${TARGET_GATEWAY[unconfined]}" ]] || die "could not determine the control guest's default gateway"
require_outside "$IPV4_POOL" "${TARGET_GATEWAY[unconfined]}" \
  || die "the control network's gateway ${TARGET_GATEWAY[unconfined]} lies inside the pool; the network was not created on ${CONTROL_SUBNET}"
TARGET_BRIDGE[unconfined]="$(bridge_for_gateway "${TARGET_GATEWAY[unconfined]}")"
[[ -n "${TARGET_BRIDGE[unconfined]}" ]] || die "no host bridge carries the control gateway ${TARGET_GATEWAY[unconfined]}"
CONTROL_GUEST_IPV4="$(guest_ipv4_addr "$CONTROL_VM")"
[[ -n "$CONTROL_GUEST_IPV4" ]] || die "could not determine the control guest's IPv4 address"
log "control guest is ${CONTROL_GUEST_IPV4} behind ${TARGET_GATEWAY[unconfined]} on ${TARGET_BRIDGE[unconfined]}"

# --- the session under test.
log "starting runner-managed VM ${VM_NAME} on ${IPV4_CIDR} under ${IPV6_MODE}"
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
  -- sh -c 'printf probe-released >/tmp/writ-agent-vm-released; sleep 600' \
  | tee "$START_OUTPUT"
grep -Fxq "session_id=${SESSION_ID}" "$START_OUTPUT" || die "runner did not print expected session ID"
wait_for_released_guest_command
require_guest_tooling "$VM_NAME"

TARGET_VM[session]="$VM_NAME"
TARGET_GATEWAY[session]="$IPV4_GATEWAY"
GUEST_IPV4="$(guest_ipv4_addr "$VM_NAME")"
[[ -n "$GUEST_IPV4" ]] || die "could not determine the session guest's IPv4 address"
TARGET_BRIDGE[session]="$(session_bridge)"
[[ -n "${TARGET_BRIDGE[session]}" ]] || die "could not find the session bridge in the PF anchor (is the IPv6 interface deny installed?)"
[[ "${TARGET_BRIDGE[session]}" != "${TARGET_BRIDGE[unconfined]}" ]] \
  || die "the session and control networks share ${TARGET_BRIDGE[session]}; the control would not be unconfined"
log "session guest is ${GUEST_IPV4} behind ${IPV4_GATEWAY} on ${TARGET_BRIDGE[session]}"

start_capture unconfined
start_capture session

log "session anchor rules:"
sudo pfctl -a "$PF_ANCHOR" -sr 2>/dev/null | sed 's/^/    /'

RESULTS=()

# --- positive controls first. The unconfined guest's own address must reach
# the listener, or the observers and tooling are broken and nothing else in
# the run can be graded. Its spoofed sends must at least be emitted, or the
# sender cannot spoof and the session's silence would be about nc, not vmnet.
probe unconfined control "$CONTROL_GUEST_IPV4" no
read -r _ uc_emitted uc_forwarded uc_reached _ <"${TMP_DIR}/result-unconfined-control"
[[ "$uc_emitted" == "yes" ]] \
  || die "the unconfined guest did not emit its own-address datagram (nc error or no TX); the sender is not working"
[[ "$uc_forwarded" == "yes" ]] \
  || die "the unconfined own-address datagram was not seen on ${TARGET_BRIDGE[unconfined]}; the capture is not observing that bridge"
[[ "$uc_reached" == "yes" ]] \
  || die "the unconfined own-address datagram did not reach the host listener; with no anchor in the way the listener or host path is broken, so no silence below would mean anything"

probe unconfined foreign "$FOREIGN_SOURCE" yes
read -r _ uf_emitted uf_fwd uf_reached _ <"${TMP_DIR}/result-unconfined-foreign"
[[ "$uf_emitted" == "yes" ]] \
  || die "the unconfined guest did not emit the foreign-source datagram; the spoofing sender does not work even without confinement"
if [[ -n "$SIBLING_SOURCE" ]]; then
  probe unconfined sibling "$SIBLING_SOURCE" yes
  read -r _ us_emitted us_fwd us_reached _ <"${TMP_DIR}/result-unconfined-sibling"
  [[ "$us_emitted" == "yes" ]] \
    || die "the unconfined guest did not emit the sibling-source datagram; the spoofing sender does not work even without confinement"
fi

# --- session calibration: an in-subnet frame must be forwarded, counted by
# the labelled IPv4 deny, and never delivered, or a blind capture, a broken
# counter parser, or an anchor that is not denying would each let a later
# delivery be misattributed to spoofing.
probe session control "$GUEST_IPV4" no
read -r _ ctl_emitted ctl_forwarded ctl_reached ctl_delta <"${TMP_DIR}/result-session-control"
[[ "$ctl_emitted" == "yes" ]] \
  || die "the session guest did not emit the control datagram (nc error or no TX); the sender is not working"
[[ "$ctl_forwarded" == "yes" ]] \
  || die "the control datagram from the session guest's own address was not seen on ${TARGET_BRIDGE[session]}; the capture is not observing the session bridge"
[[ "$ctl_reached" == "no" ]] \
  || die "the control datagram from the session guest's own address REACHED the host listener; the session anchor is not denying in-subnet traffic, so a spoof result could not be told apart from an unconfined session"
[[ "$ctl_delta" -gt 0 ]] \
  || die "the control datagram did not raise the 'writ deny agent v4' counter (delta ${ctl_delta}); either the anchor did not match it or the counter parser is broken"

probe session foreign "$FOREIGN_SOURCE" yes
if [[ -n "$SIBLING_SOURCE" ]]; then
  probe session sibling "$SIBLING_SOURCE" yes
fi

log "stopping session through lifecycle runner"
"$RUNNER" \
  --pf-helper "$HELPER" \
  stop \
  --session-id "$SESSION_ID" \
  --ipv4-pool "$IPV4_POOL" \
  --ipv6-pool "$IPV6_POOL" \
  --ipv6-mode "$IPV6_MODE" \
  --subnet-index "$SUBNET_INDEX" >/dev/null
STOP_DONE=1

log "results (host-observed; guest output was diagnostic only):"
for r in "${RESULTS[@]}"; do
  log "  ${r}"
done

# Verdict per spoofed source, graded from host-observed facts with the
# unconfined result for the same source as the positive control. Guest facts
# (emission) can withhold a verdict but never award one.
#   $1 name; $2 $3 unconfined forwarded/reached;
#   $4..$7 session emitted/forwarded/reached/deny delta.
verdict() {
  local name="$1" u_fwd="$2" u_reached="$3" emitted="$4" fwd="$5" reached="$6" delta="$7"
  # The IPv4 deny is `from <session /24>`; an out-of-subnet source cannot
  # match it, so any movement in its counter during this window is other
  # in-subnet traffic (DHCP, ARP-triggered retries, ...), not this datagram.
  local counter_note=""
  if [[ "$delta" -gt 0 ]]; then
    counter_note=" ('writ deny agent v4' rose by ${delta} during the session window; the source-scoped rule cannot have matched this source, so that is unrelated in-subnet traffic, not evidence about this datagram.)"
  fi
  if [[ "$u_reached" == "yes" ]]; then
    log "PLATFORM ${name}: unconfined, the spoofed-source datagram was forwarded and DELIVERED to the host socket. vmnet forwards spoofed IPv4 sources and the host accepts them; only PF stands between such a frame and a host socket."
  elif [[ "$u_fwd" == "yes" ]]; then
    log "PLATFORM ${name}: unconfined, the spoofed-source datagram was forwarded onto the bridge but not delivered. vmnet forwards spoofed IPv4 sources; something in the host stack (default PF policy, reverse-path check) drops them before a socket, independent of any session anchor."
  else
    log "PLATFORM ${name}: unconfined, the spoofed-source datagram never appeared on the bridge although the same guest's own-address datagram did. vmnet does not forward spoofed IPv4 sources. Record this as a pinned platform fact (plan 'Beyond E3' question 4); C2b becomes hardening rather than a live fix."
  fi

  if [[ "$emitted" != "yes" ]]; then
    log "VERDICT ${name}: INCONCLUSIVE — the session guest did not emit the datagram (see the nc stderr and TX counter lines above), so the session observers' silence says nothing. Fix the sender and rerun."
  elif [[ "$reached" == "yes" ]]; then
    log "VERDICT ${name}: LIVE GAP — under the session anchor the spoofed-source datagram reached a host socket the session may not reach. The source-scoped IPv4 rules do not confine it; stage C2b (interface-scoped IPv4 rules) is urgent for the legacy profile.${counter_note}"
  elif [[ "$fwd" == "yes" && "$u_reached" == "yes" ]]; then
    log "VERDICT ${name}: UNEXPLAINED — forwarded but not delivered under the session, yet delivered unconfined. The session anchor is the only difference and its source-scoped rules cannot match this source. Do not pin either way; inspect PF state and the top-level rules.${counter_note}"
  elif [[ "$fwd" == "yes" && "$u_fwd" == "yes" ]]; then
    log "VERDICT ${name}: forwarded onto the session bridge, not delivered, matching the unconfined control — dropped by the host stack outside the session rules; the confinement is not the reason it stopped. C2b still applies as the session's own guarantee.${counter_note}"
  elif [[ "$fwd" == "yes" ]]; then
    log "VERDICT ${name}: UNEXPLAINED — forwarded on the session bridge but the same source never appeared on the unconfined bridge. vmnet behaved differently per bridge; the platform line above cannot be pinned from this run. Rerun before recording anything.${counter_note}"
  elif [[ "$u_fwd" == "yes" ]]; then
    log "VERDICT ${name}: INCONCLUSIVE — not seen on the session bridge although the same source was forwarded unconfined. Either the emission witness (guest TX counter) misled, or the two bridges differ; the guest-side evidence is too coarse to pin this. Rerun before recording anything.${counter_note}"
  else
    log "VERDICT ${name}: not forwarded, consistent with the unconfined control — the platform fact above holds under the session too.${counter_note}"
  fi
}
read -r _ f_emitted f_fwd f_reached f_delta <"${TMP_DIR}/result-session-foreign"
verdict foreign "$uf_fwd" "$uf_reached" "$f_emitted" "$f_fwd" "$f_reached" "$f_delta"
if [[ -n "$SIBLING_SOURCE" ]]; then
  read -r _ s_emitted s_fwd s_reached s_delta <"${TMP_DIR}/result-session-sibling"
  verdict sibling "$us_fwd" "$us_reached" "$s_emitted" "$s_fwd" "$s_reached" "$s_delta"
else
  log "VERDICT sibling: not measured — ${IPV4_POOL} holds a single /24, so there is no other session subnet to spoof from."
fi

cleanup
trap - EXIT INT TERM
log "measurement complete"
