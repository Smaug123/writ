#!/usr/bin/env bash
set -Eeuo pipefail

# macOS's /bin/bash is 3.2; run from a modern bash (the Nix dev shell, or
# Homebrew) so `local -n`-free code below still gets a 4+ `read`/`printf`.
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  printf '[probe-ipv4-spoof] error: bash %s is too old; run from `nix develop` (bash 4+ required)\n' "$BASH_VERSION" >&2
  exit 1
fi

usage() {
  cat <<'EOF'
Usage: scripts/probe-agent-vm-ipv4-source-spoof.sh

Measures, on real hardware, whether a compromised root agent in a writ session
guest can emit an IPv4 frame with a *spoofed* source address (one outside the
address it was assigned).

Why this, and not "does vmnet forward a spoofed frame": the session PF anchor's
IPv4 rules match on the session /24 as *source*, so a frame whose source is
outside that /24 would fall through them (plan "Beyond E3" question 4). But a
frame has to exist before vmnet or PF can forward or filter it, and forging an
IPv4 source needs a Linux capability: CAP_NET_ADMIN to add an address alias (or
change routing) so a normal socket can bind a foreign source, or CAP_NET_RAW to
open a raw / AF_PACKET socket that writes the header directly. Apple `container`
runs the guest *workload* without either (writ's own locked profile
additionally proves this: crates/writ-guest-init/src/capability_argv.rs grants
NET_ADMIN only to PID 1 for the IPv6-sysctl handoff and drops it before the
workload, and never grants NET_RAW). So the source-scoped rules never face an
out-of-subnet frame from this guest: it cannot build one. This probe verifies
that on hardware.

It starts one runner-managed guest exactly as prove-agent-vm-lifecycle.sh does
(so it exercises the real launch path, and would catch a regression that handed
the workload NET_ADMIN/NET_RAW), then gathers three kinds of evidence:

  positive control (host-owned): the guest sends a UDP datagram from its OWN
      source; tcpdump on the session bridge (BPF, so it taps the interface
      before PF filters) MUST see it. This proves the send path and the capture
      both work, so the silence in the spoof attempts below means something.

  spoof attempts (guest acts, host observes): the guest tries to configure a
      foreign source alias (`ip addr add`, which needs CAP_NET_ADMIN) and then
      send from it. The host bridge MUST NOT see any frame carrying the foreign
      source. The guest's own error is captured as the mechanistic reason.

  capability readout (guest-reported, host-parsed): the guest's
      /proc/self/status is read and this script (never the guest) decodes the
      CapEff / CapPrm / CapBnd masks, asserting CAP_NET_ADMIN and CAP_NET_RAW
      are absent from the bounding set (so root cannot reacquire them).

Grading is host-owned. The load-bearing facts are the bridge captures: the
positive control MUST be forwarded and NO spoofed frame may reach the bridge.
The `ip addr add` error and the capability masks are guest-reported diagnostics
that EXPLAIN the silence; they can withhold the reassuring verdict (an absent
control, or a spoofed frame on the wire, forces INCONCLUSIVE or the alarming
"spoof possible") but they never award it on their own. A guest that could
spoof and chose to would be caught on the wire regardless of what it reports.

This is a measurement, not a proof: exit status is 0 whenever the measurement
completed, and the verdict is printed. See
docs/design/ipv4-only-network-confinement.md ("Evidence protocol") and
docs/plans/2026-09-01-ipv4-only-locked-v1.md ("Beyond E3" question 4).

Environment overrides:
  WRIT_PROVE_IMAGE            guest image (default alpine:latest)
  WRIT_PROVE_IPV4_POOL        session pool (default 192.168.0.0/16)
  WRIT_PROVE_IPV6_POOL        session IPv6 pool (default fd83:b6f2:e57::/48)
  WRIT_PROVE_SUBNET_INDEX     /24 index in the pool (default 252)
  WRIT_PROVE_BROKER_PORT_MIN  broker/probe port range floor (default 49152)
  WRIT_PROVE_BROKER_PORT_MAX  broker/probe port range ceiling (default 65535)
  WRIT_PROBE_FOREIGN_SOURCE   out-of-pool source to attempt (default 10.77.0.5)
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
IPV6_MODE="ipv4-only-no-guest-ipv6"
SESSION_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
NETWORK_NAME="writ-agent-net-${SESSION_ID}"
VM_NAME="writ-agent-vm-${SESSION_ID}"
BROKER_DIR="${TMP_DIR}/broker"
START_OUTPUT="${TMP_DIR}/runner-start.txt"
RUNNER=""
HELPER=""
BROKER_PID=""
BROKER_PORT=""
PROBE_PORT=""
IPV4_CIDR=""
IPV4_GATEWAY=""
GUEST_IPV4=""
SESSION_BRIDGE=""
CAPTURE_FILE=""
CAPTURE_PID=""
CARGO_CMD=()
STOP_DONE=0
CLEANUP_STARTED=0

cleanup() {
  [[ "$CLEANUP_STARTED" -eq 1 ]] && return
  CLEANUP_STARTED=1
  log "cleaning up VM, network, capture, broker, and PF anchor"

  if [[ -n "$CAPTURE_PID" ]]; then
    sudo kill "$CAPTURE_PID" >/dev/null 2>&1 || true
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

  if [[ -n "$BROKER_PID" ]]; then
    kill "$BROKER_PID" >/dev/null 2>&1 || true
    wait "$BROKER_PID" 2>/dev/null || true
  fi

  rm -rf "$TMP_DIR"
}
on_signal() {
  cleanup
  trap - EXIT
  exit 130
}
trap cleanup EXIT
trap on_signal INT TERM

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

# Succeeds iff address $2 lies inside network $1.
addr_in_cidr() {
  ! require_outside "$1" "$2" 2>/dev/null
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
# address. The broker port must lie inside the range the runner is told about,
# or it refuses to start (BrokerPortOutsideRange).
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

require_guest_tooling() {
  guest_in "$1" 'command -v ip >/dev/null && command -v nc >/dev/null' \
    || die "guest image lacks ip or nc (use WRIT_PROVE_IMAGE with BusyBox nc)"
  guest_in "$1" 'nc 2>&1 | grep -q -- "-s ADDR"' \
    || die "guest nc does not support -s ADDR; the probe needs a source-selectable sender"
}

guest_ipv4_addr() {
  guest_in "$1" "ip -4 -o addr show scope global | awk '{print \$4}' | head -n 1 | cut -d/ -f1"
}

guest_default_gateway() {
  guest_in "$1" "ip -4 route show default | awk '{print \$3}' | head -n 1"
}

# eth0's transmitted-packet counter, as the guest kernel reports it. Guest
# reported, so it never decides a verdict; it only decides whether there was a
# frame for the capture to see at all.
guest_tx_packets() {
  local n
  n="$(guest_in "$1" 'cat /sys/class/net/eth0/statistics/tx_packets' 2>/dev/null | tr -d '[:space:]')"
  [[ "$n" =~ ^[0-9]+$ ]] || die "could not read eth0 tx_packets in ${1} (got '${n}')"
  printf '%s\n' "$n"
}

# The host bridge whose address is gateway $1, from ifconfig: the same lookup
# the runner performs (parse_bridge_for_gateway) for the session bridge.
bridge_for_gateway() {
  ifconfig | awk -v gw="$1" '
    /^[a-z]/ { iface = $1; sub(":$", "", iface) }
    $1 == "inet" && $2 == gw && iface ~ /^bridge[0-9]+$/ { print iface; exit }
  '
}

# Source address of the first packet, from line $2 onward of capture $1,
# addressed to $3:$4 whose payload carries nonce $5; empty if none. tcpdump -A
# prints the header line, then the payload as text, so the nonce line is
# attributed to the most recent header for our destination.
bridge_source_for_nonce() {
  sed -n "$(($2 + 1)),\$p" "$1" | awk -v dst=" > $3.$4: " -v nonce="$5" '
    / IP [0-9.]+ > [0-9.]+: / { hdr = (index($0, dst) ? $0 : "") ; next }
    hdr != "" && index($0, nonce) {
      sub(/.* IP /, "", hdr); sub(/\.[0-9]+ > .*/, "", hdr); print hdr; exit
    }
  '
}

# `ps` rather than `kill -0`: the capture runs under sudo, and kill -0 on a
# root process from here fails whether or not it exists; and ps's *output*, not
# its exit status: on recent macOS `ps -p` can exit 1 with "ps: time: requires
# entitlement" while still listing the process.
process_alive() {
  [[ -n "$(ps -p "$1" -o pid= 2>/dev/null)" ]]
}

# Start capturing UDP to the probe port on the session bridge.
start_capture() {
  local err="${TMP_DIR}/tcpdump.err"
  CAPTURE_FILE="${TMP_DIR}/tcpdump.log"
  log "capturing UDP to port ${PROBE_PORT} on ${SESSION_BRIDGE}"
  # The redirects are deliberately the unprivileged shell's: the log lives in
  # the user-owned TMP_DIR, and only the capture itself needs root.
  # shellcheck disable=SC2024
  sudo tcpdump -i "$SESSION_BRIDGE" -n -l -q -A "udp and dst port ${PROBE_PORT}" >"$CAPTURE_FILE" 2>"$err" &
  CAPTURE_PID=$!
  sleep 2
  process_alive "$CAPTURE_PID" \
    || die "tcpdump did not start on ${SESSION_BRIDGE}: $(cat "$err")"
}

# Decode a guest's /proc/self/status (read from file $1) HERE on the host, never
# in the guest: whether CAP_NET_ADMIN (bit 12) and CAP_NET_RAW (bit 13) are
# present in the effective, permitted, and bounding sets. Prints, on the last
# line, a machine verdict: "CAPS <net_admin_bnd> <net_raw_bnd> <net_admin_eff>
# <net_raw_eff>" with yes/no fields, and human lines before it. Fails only if
# the status text carries no Cap* lines at all (a garbled read).
decode_caps() {
  python3 - "$1" <<'PY'
import re
import sys

CAP_NET_ADMIN = 12
CAP_NET_RAW = 13
text = open(sys.argv[1]).read()
sets = {}
for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
    m = re.search(rf"^{name}:\s*([0-9A-Fa-f]+)", text, re.MULTILINE)
    if m:
        sets[name] = int(m.group(1), 16)
if not sets:
    print("no Cap* lines in /proc/self/status", file=sys.stderr)
    raise SystemExit(1)


def has(mask, bit):
    return "yes" if (mask >> bit) & 1 else "no"


# Human-readable lines to stderr (shown to the operator); only the machine
# verdict goes to stdout, so the caller captures exactly one line.
for name in ("CapEff", "CapPrm", "CapBnd"):
    if name in sets:
        print(
            f"  {name}=0x{sets[name]:016x} "
            f"NET_ADMIN={has(sets[name], CAP_NET_ADMIN)} "
            f"NET_RAW={has(sets[name], CAP_NET_RAW)}",
            file=sys.stderr,
        )
bnd = sets.get("CapBnd", 0)
eff = sets.get("CapEff", 0)
# Absent from the bounding set means the process can never regain the cap, even
# after a setuid or capset; that is the security-relevant fact.
print(
    "CAPS "
    f"{has(bnd, CAP_NET_ADMIN)} {has(bnd, CAP_NET_RAW)} "
    f"{has(eff, CAP_NET_ADMIN)} {has(eff, CAP_NET_RAW)}"
)
PY
}

# Emit one UDP datagram from the guest with source $2 toward the gateway, adding
# $2 as an eth0 alias first when $3 is "yes". Reports, via the RESULT_* globals:
#   RESULT_EMITTED    yes|no    guest-reported (TX counter rose, or nc succeeded)
#   RESULT_BRIDGE_SRC <ip>|-    host-owned: the source the capture saw, "-" none
#   RESULT_ADD_OUT    <text>    guest-reported `ip addr add` output ("" if $3=no)
#   RESULT_ADD_OK     yes|no|na did the alias actually get configured?
send_datagram() {
  local name="$1" source="$2" add_alias="$3"
  local nonce="writ-spoof-${name}-${RANDOM}${RANDOM}"
  RESULT_ADD_OUT=""
  RESULT_ADD_OK="na"
  log "attempt ${name}: source ${source} -> ${IPV4_GATEWAY}:${PROBE_PORT} (${nonce})"

  if [[ "$add_alias" == "yes" ]]; then
    # Capture the add's merged output: a real failure (EPERM from a missing
    # CAP_NET_ADMIN) is the whole point of the measurement, and `|| true` keeps
    # its non-zero exit (or a benign already-exists) from tripping errexit.
    RESULT_ADD_OUT="$(guest_in "$VM_NAME" "ip addr add ${source}/32 dev eth0" 2>&1)" || true
    if guest_in "$VM_NAME" "ip -4 -o addr show dev eth0 | grep -q 'inet ${source}/32 '"; then
      RESULT_ADD_OK="yes"
      log "  alias ${source}/32 configured on eth0 (CAP_NET_ADMIN present)"
    else
      RESULT_ADD_OK="no"
      log "  alias ${source}/32 NOT configured: [${RESULT_ADD_OUT:-<no output>}]"
    fi
  fi

  local tx_before tx_after cap_before
  tx_before="$(guest_tx_packets "$VM_NAME")"
  cap_before="$(wc -l <"$CAPTURE_FILE" | tr -d ' ')"

  # -w 1: BusyBox nc otherwise waits for a reply that never comes. Its exit
  # status is diagnostic; whether a frame left the guest is decided from the TX
  # counter and the capture, not from nc. Sending from an unconfigured source
  # fails to bind, which is exactly what we want to observe when the alias add
  # was denied.
  local nc_err="${TMP_DIR}/nc-${name}.err"
  set +e
  guest_in "$VM_NAME" "printf '%s' '${nonce}' | nc -u -s ${source} -w 1 ${IPV4_GATEWAY} ${PROBE_PORT}" 2>"$nc_err"
  local guest_status=$?
  set -e
  log "  guest nc exit status ${guest_status} (diagnostic only)"
  sleep 2
  tx_after="$(guest_tx_packets "$VM_NAME")"

  RESULT_BRIDGE_SRC="$(bridge_source_for_nonce "$CAPTURE_FILE" "$cap_before" "$IPV4_GATEWAY" "$PROBE_PORT" "$nonce")"
  RESULT_BRIDGE_SRC="${RESULT_BRIDGE_SRC:--}"

  if [[ "$RESULT_BRIDGE_SRC" != "-" ]]; then
    RESULT_EMITTED="yes"
  elif (( tx_after > tx_before )); then
    RESULT_EMITTED="yes"
  elif [[ "$guest_status" -eq 0 ]]; then
    RESULT_EMITTED="yes"
  else
    RESULT_EMITTED="no"
  fi
  log "  emitted (guest-reported): ${RESULT_EMITTED}; source on ${SESSION_BRIDGE} (host-owned): ${RESULT_BRIDGE_SRC}"
}

require_cmd container
require_cmd python3
require_cmd uuidgen
require_cmd tcpdump
require_cmd ifconfig
choose_cargo

IPV4_CIDR="$(cidr_alloc_subnet "$IPV4_POOL" 24 "$SUBNET_INDEX")"
IPV4_GATEWAY="$(cidr_host "$IPV4_CIDR" 1)"
# A "foreign" source inside the session /24 would be legitimately covered by
# the source-scoped deny, so it would not be a spoof at all.
require_outside "$IPV4_CIDR" "$FOREIGN_SOURCE" \
  || die "WRIT_PROBE_FOREIGN_SOURCE=${FOREIGN_SOURCE} lies inside the session /24 ${IPV4_CIDR}; it needs to be an out-of-subnet source"

mkdir -p "$BROKER_DIR"
printf 'broker-ok\n' >"${BROKER_DIR}/broker.txt"

log "requesting sudo credentials for the lifecycle runner and tcpdump"
sudo -v
sudo pfctl -s info 2>/dev/null | grep -q 'Status: Enabled' || die "PF is not enabled"
sudo pfctl -sr 2>/dev/null | grep -q 'anchor "writ/session/\*"' \
  || die 'missing top-level PF anchor; add `anchor "writ/session/*"` to /etc/pf.conf and reload PF'

log "building PF helper and lifecycle runner"
"${CARGO_CMD[@]}" build --quiet --bin writ-agent-vm-pf-helper --bin writ-agent-vm-runner
HELPER="${ROOT_DIR}/target/debug/writ-agent-vm-pf-helper"
RUNNER="${ROOT_DIR}/target/debug/writ-agent-vm-runner"

BROKER_PORT="$(pick_port tcp "$BROKER_PORT_MIN" "$BROKER_PORT_MAX")"
PROBE_PORT="$(pick_port udp "$BROKER_PORT_MIN" "$BROKER_PORT_MAX")"
# Prefer a distinct probe port so the log reads unambiguously. Nothing binds
# the probe port on the host (the bridge capture is the observer), and the
# broker allow is TCP-only, so sharing the number with the TCP broker is
# harmless. A one-port range (min == max) is valid and must not spin here.
for _ in {1..20}; do
  [[ "$PROBE_PORT" != "$BROKER_PORT" ]] && break
  [[ "$BROKER_PORT_MIN" == "$BROKER_PORT_MAX" ]] && break
  PROBE_PORT="$(pick_port udp "$BROKER_PORT_MIN" "$BROKER_PORT_MAX")"
done
BROKER_PID="$(start_http_server "$BROKER_DIR" "$BROKER_PORT" "${TMP_DIR}/broker.log")"
log "broker is up on ${BROKER_PORT} (TCP); probe target port is ${PROBE_PORT} (UDP, no host listener — the bridge capture is the observer)"

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

GUEST_IPV4="$(guest_ipv4_addr "$VM_NAME")"
[[ -n "$GUEST_IPV4" ]] || die "could not determine the session guest's IPv4 address"
SESSION_BRIDGE="$(bridge_for_gateway "$IPV4_GATEWAY")"
[[ -n "$SESSION_BRIDGE" ]] || die "no host bridge carries the session gateway ${IPV4_GATEWAY}"
log "session guest is ${GUEST_IPV4} behind ${IPV4_GATEWAY} on ${SESSION_BRIDGE}"

start_capture

# --- capability readout: the mechanistic reason the guest cannot spoof. Read
# the raw status from the guest (untrusted input) and decode it on the host.
STATUS_FILE="${TMP_DIR}/guest-status.txt"
guest_in "$VM_NAME" 'cat /proc/self/status' >"$STATUS_FILE" 2>/dev/null \
  || die "could not read /proc/self/status in the guest"
GUEST_UID="$(guest_in "$VM_NAME" 'id -u' 2>/dev/null | tr -d '[:space:]')"
log "guest workload capability posture (uid ${GUEST_UID:-?}; decoded on the host):"
# decode_caps prints the per-set human lines to stderr (shown above the verdict)
# and exactly the "CAPS ..." machine line to stdout, which we capture and split.
CAPS_LINE="$(decode_caps "$STATUS_FILE")" \
  || die "could not decode the guest capability masks"
read -r _ CAP_NET_ADMIN_BND CAP_NET_RAW_BND CAP_NET_ADMIN_EFF CAP_NET_RAW_EFF <<<"$CAPS_LINE"

# --- positive control: the guest's own-source frame MUST reach the bridge, or
# the capture is not observing the wire and no silence below means anything.
send_datagram control "$GUEST_IPV4" no
CONTROL_EMITTED="$RESULT_EMITTED"
CONTROL_BRIDGE_SRC="$RESULT_BRIDGE_SRC"
[[ "$CONTROL_EMITTED" == "yes" ]] \
  || die "the guest did not emit its own-address datagram (nc error and no TX, capture saw nothing); the sender is not working"
[[ "$CONTROL_BRIDGE_SRC" != "-" ]] \
  || die "the guest's own-address datagram was not seen on ${SESSION_BRIDGE}; the capture is not observing the wire, so no silence below would mean anything"

# --- the spoof attempt: add a foreign alias (needs CAP_NET_ADMIN) and send.
send_datagram foreign "$FOREIGN_SOURCE" yes
FOREIGN_ADD_OK="$RESULT_ADD_OK"
FOREIGN_ADD_OUT="$RESULT_ADD_OUT"
FOREIGN_BRIDGE_SRC="$RESULT_BRIDGE_SRC"

process_alive "$CAPTURE_PID" \
  || die "the bridge capture was not running at the end of the attempts; its silence would have been graded, so nothing is graded"

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

# --- was the foreign source spoofed onto the bridge?
FOREIGN_ON_BRIDGE="no"
if [[ "$FOREIGN_BRIDGE_SRC" != "-" ]] && ! addr_in_cidr "$IPV4_CIDR" "$FOREIGN_BRIDGE_SRC"; then
  FOREIGN_ON_BRIDGE="yes"
fi
caps_denied="no"
if [[ "$CAP_NET_ADMIN_BND" == "no" && "$CAP_NET_RAW_BND" == "no" ]]; then
  caps_denied="yes"
fi

log "results (host-observed unless noted):"
log "  positive control: own source ${GUEST_IPV4} seen on ${SESSION_BRIDGE} as ${CONTROL_BRIDGE_SRC}"
log "  spoof attempt: ip addr add ${FOREIGN_SOURCE}/32 -> ${FOREIGN_ADD_OK} [${FOREIGN_ADD_OUT:-<no output>}] (guest-reported)"
log "  spoof attempt: foreign source on ${SESSION_BRIDGE} -> ${FOREIGN_BRIDGE_SRC} (host-owned)"
log "  CapBnd: NET_ADMIN=${CAP_NET_ADMIN_BND} NET_RAW=${CAP_NET_RAW_BND}; CapEff: NET_ADMIN=${CAP_NET_ADMIN_EFF} NET_RAW=${CAP_NET_RAW_EFF} (guest-reported, host-decoded)"

# --- verdict (host-owned). The bridge is the arbiter: it sits after vmnet and
# before PF, so a foreign source on it is a real spoofed frame regardless of
# what the guest reports, and its absence (with the control present) means no
# spoof escaped in this run. The capabilities explain why.
if [[ "$FOREIGN_ON_BRIDGE" == "yes" ]]; then
  log "VERDICT: SPOOF POSSIBLE — a frame carrying the out-of-subnet source ${FOREIGN_BRIDGE_SRC} reached the host bridge. The capability model did NOT prevent source forgery here (CapBnd NET_ADMIN=${CAP_NET_ADMIN_BND} NET_RAW=${CAP_NET_RAW_BND}, add=${FOREIGN_ADD_OK}). The source-scoped IPv4 rules face a real out-of-subnet frame: plan 'Beyond E3' question 4 is live and stage C2b (interface-scoped rules) is warranted. Investigate why the workload could spoof."
elif [[ "$caps_denied" == "yes" && "$FOREIGN_ADD_OK" != "yes" ]]; then
  log "VERDICT: CAPABILITY-DENIED — the guest workload lacks CAP_NET_ADMIN and CAP_NET_RAW in its bounding set (so root cannot reacquire them), \`ip addr add\` was refused, and no out-of-subnet frame reached the host bridge while the own-source control did. A compromised root agent cannot build an IPv4 frame with a spoofed source, so the source-scoped session rules never face one. This is the answer to plan 'Beyond E3' question 4 for this launch path: source spoofing is prevented below vmnet and PF, at the capability layer."
else
  # Fail-closed catch-all: no spoofed frame was seen this run, but the guest
  # holds or could reacquire a forging capability (CapBnd shows one, or the
  # alias add succeeded), or the two disagree (e.g. a forged /proc claiming the
  # caps absent while the add worked). A post-vmnet observer's silence is not
  # reassuring here — it may be nc, timing, or vmnet, none of which it can pin —
  # so this is never read as denied.
  log "VERDICT: CAPABILITY PRESENT — the guest holds, or could reacquire, a capability that enables source forgery (CapBnd NET_ADMIN=${CAP_NET_ADMIN_BND} NET_RAW=${CAP_NET_RAW_BND}, add=${FOREIGN_ADD_OK}), or the capability readout and the add result disagree, yet no spoofed frame was seen on the bridge this run. Treat source spoofing as possible and re-run the forwarding measurement; do NOT read this as denied."
fi

cleanup
trap - EXIT INT TERM
log "measurement complete"
