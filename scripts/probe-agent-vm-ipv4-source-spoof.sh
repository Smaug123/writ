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
              sender whose frames a capture on the same kind of bridge does
              see, so that a session bridge's silence can mean something.
  session     a runner-managed guest under the legacy ipv4-only profile,
              exactly as prove-agent-vm-lifecycle.sh starts it. What it
              observes is what the session rules do with the same frames.

From each guest it sends a UDP datagram toward that guest's gateway, with
three sources:

  control   the guest's own address: unconfined it MUST be forwarded onto the
            bridge (the capture works), and under the session it MUST be
            forwarded AND counted by the labelled IPv4 deny (the anchor is
            denying in-subnet traffic). Anything else aborts the run.
  foreign   an address outside every network the script knows about
            (10.77.0.5/32 by default, added to eth0 by the root guest)
  sibling   an address in a *different* session /24 of the broker's pool
            (index SUBNET_INDEX+1, or SUBNET_INDEX-1 when the session holds
            the pool's last /24), the cross-session case; skipped, and said
            so, when the pool has only one /24

The design question ("Beyond E3" question 4) is whether vmnet forwards a
frame whose IPv4 source is outside the session /24. Two host-owned observers
answer it, neither reported by a guest:
  - tcpdump on that guest's bridge: did vmnet put the frame on the host
    bridge? BPF taps the interface before PF filters, so this is a vmnet fact
    independent of any anchor. It correlates by the host-minted nonce in the
    payload, not by source, and reports the source it saw: a platform that
    anti-spoofs by REWRITING the source is a distinct outcome, not a drop.
  - (session only) the anchor's labelled deny counter: did PF deny it? The
    IPv4 deny is source-scoped to the session /24, so a genuinely foreign
    source cannot match it; a spoofed frame forwarded onto the bridge and not
    counted is loose on the host side — the source-scoping gap C2b closes.

The result is deliberately asymmetric. The one trusted observer, the bridge
capture, sits after vmnet, so a POSITIVE result (the spoofed frame on the
bridge) is conclusive and proves the frame was emitted, but a NEGATIVE result
is not: capture silence cannot be told apart from a guest that never emitted
the spoofed source, since emission of a spoofed frame rests only on the
aggregate, guest-reported TX counter. The probe therefore pins a live gap
when it sees one, and reports "not forwarded" as INCONCLUSIVE rather than as
a reassuring platform fact. C2b stays warranted until a trusted pre-vmnet
observer (which this platform does not offer) could pin the negative.

Note: an earlier draft also bound a host UDP listener at the gateway, but
Apple's vmnet does not deliver guest UDP addressed to the gateway into host
sockets (TCP to the broker works; UDP does not), so socket delivery could
never be a signal even unconfined. Forwarding onto the bridge is the signal
instead, and the design question is about forwarding in any case.

One guest-side fact gates whether the capture's silence means anything:
eth0's TX packet counter must have risen and nc must have printed nothing, or
the guest is taken to have emitted nothing. A frame the capture saw was
emitted whatever nc said afterwards (an ICMP port-unreachable, or PF's `block
return`, can make nc report an error after the frame has left). Guest facts
can withhold a verdict, never award one.

Requires:
  - macOS with Apple container installed and `container system start` already run
  - root privileges through sudo for pfctl and tcpdump
  - a top-level PF rule in /etc/pf.conf: anchor "writ/session/*"
  - no other writ session anchor loaded: every child of that wildcard is
    evaluated for every bridge, so another session's source-scoped deny
    (above all one on the sibling /24) would confound both guests. The
    script refuses to start while any exists, and polls the anchor list
    every 0.2s across the probe windows, failing the run if one appears
    or if this run's own anchor loses its IPv4 deny.
    An anchor that comes and goes within one poll interval is the residual
    gap: PF offers no exclusivity primitive, so do not run this alongside
    anything that starts writ sessions.
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
RUNNER=""
HELPER=""
BROKER_PID=""
ANCHOR_WATCH_PID=""
ANCHOR_INTRUSIONS=""
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
  log "cleaning up VMs, networks, captures, and PF anchor"

  if [[ -n "$ANCHOR_WATCH_PID" ]]; then
    kill "$ANCHOR_WATCH_PID" >/dev/null 2>&1 || true
    wait "$ANCHOR_WATCH_PID" 2>/dev/null || true
  fi
  # `${arr[@]+"${arr[@]}"}`: an empty array under `set -u` is an error on
  # bash 4.0-4.3, and this runs from the EXIT trap after early failures.
  local pid
  for pid in ${TARGET_CAPTURE_PID[@]+"${TARGET_CAPTURE_PID[@]}"}; do
    sudo kill "$pid" >/dev/null 2>&1 || true
  done

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

# Succeeds iff address $2 lies inside network $1.
addr_in_cidr() {
  ! require_outside "$1" "$2" 2>/dev/null
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
# address. The broker port must lie inside the range the runner is told
# about, or it refuses to start (BrokerPortOutsideRange).
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
# a frame for the capture to see at all.
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
# across macOS releases. Every child name counts, not only UUID-shaped
# ones: the wildcard evaluates `writ/session/manual` too. An empty listing
# is success (grep's 1 must not trip errexit through pipefail): no anchors
# is the state we want.
existing_session_anchors() {
  { sudo pfctl -a writ/session -sA 2>/dev/null; sudo pfctl -sA 2>/dev/null; } \
    | { grep -Eo 'writ/session/[^[:space:]]+' || true; } | sort -u
}

# Die unless this run's own anchor is loaded with its labelled IPv4 deny.
# A verdict about "what the session rules do" is vacuous if they are gone.
require_own_anchor_loaded() {
  sudo pfctl -a "$PF_ANCHOR" -sr 2>/dev/null | grep -q 'writ deny agent v4' \
    || die "this run's anchor ${PF_ANCHOR} is not loaded with its IPv4 deny (${1}); the session rules are not in place, so nothing is graded"
}

# Die if any session anchor other than this run's own is loaded. Every child
# of the `writ/session/*` wildcard is consulted for every packet on every
# interface, so a concurrent session's `block ... from <its /24>` would deny
# our sibling-source datagram on the unconfined bridge as well, and the run
# would pin that as a vmnet fact. Checked before anything starts, again once
# both guests are up, and again after the last probe, so a session that
# appears during the build or startup or mid-window is caught, not reasoned
# around. $1 names the moment for the message.
require_no_other_anchors() {
  local others
  others="$(existing_session_anchors | { grep -Fxv "$PF_ANCHOR" || true; })"
  [[ -z "$others" ]] \
    || die "other writ session anchors are loaded (${1}) and would confound the measurement; stop those sessions first: $(tr '\n' ' ' <<<"$others")"
}

# Poll the anchor list in the background for the whole probe window, noting
# every foreign anchor seen with a timestamp. The snapshot checks cannot see
# a session that comes and goes between them; this narrows that to one poll
# interval, which is the best PF's tooling allows. `sudo -n`: the background
# loop must never block on a password prompt.
start_anchor_watch() {
  ANCHOR_INTRUSIONS="${TMP_DIR}/anchor-intrusions.log"
  : >"$ANCHOR_INTRUSIONS"
  # The loop must not inherit errexit: a transient pfctl or sudo failure
  # would end it silently and the run would grade without its protection.
  # A poll whose both listings fail is recorded as POLL-FAILURE, and the
  # stop below treats that, or a dead watcher, as a failed run.
  (
    set +e
    while true; do
      listing_a="$(sudo -n pfctl -a writ/session -sA 2>/dev/null)"; status_a=$?
      listing_b="$(sudo -n pfctl -sA 2>/dev/null)"; status_b=$?
      if (( status_a != 0 && status_b != 0 )); then
        printf '%s POLL-FAILURE\n' "$(date +%H:%M:%S)" >>"$ANCHOR_INTRUSIONS"
      fi
      others="$(printf '%s\n%s\n' "$listing_a" "$listing_b" \
        | grep -Eo 'writ/session/[^[:space:]]+' | sort -u | grep -Fxv "$PF_ANCHOR")"
      if [[ -n "$others" ]]; then
        printf '%s %s\n' "$(date +%H:%M:%S)" "$(tr '\n' ' ' <<<"$others")" >>"$ANCHOR_INTRUSIONS"
      fi
      # Our own anchor must stay loaded with its deny for the whole window,
      # or a later result would be graded against rules that were not there.
      if ! sudo -n pfctl -a "$PF_ANCHOR" -sr 2>/dev/null | grep -q 'writ deny agent v4'; then
        printf '%s OWN-ANCHOR-MISSING\n' "$(date +%H:%M:%S)" >>"$ANCHOR_INTRUSIONS"
      fi
      sleep 0.2
    done
  ) &
  ANCHOR_WATCH_PID=$!
}

stop_anchor_watch() {
  local alive=1
  kill -0 "$ANCHOR_WATCH_PID" 2>/dev/null || alive=0
  kill "$ANCHOR_WATCH_PID" >/dev/null 2>&1 || true
  wait "$ANCHOR_WATCH_PID" 2>/dev/null || true
  ANCHOR_WATCH_PID=""
  [[ "$alive" -eq 1 ]] \
    || die "the anchor watcher was not running at the end of the probe windows; the concurrency check lapsed, so nothing is graded"
  if grep -q 'OWN-ANCHOR-MISSING' "$ANCHOR_INTRUSIONS"; then
    die "this run's anchor ${PF_ANCHOR} was missing its IPv4 deny at some point during the probe windows ($(grep -c OWN-ANCHOR-MISSING "$ANCHOR_INTRUSIONS") polls); the session rules were not in place throughout, so nothing is graded"
  fi
  if grep -q 'POLL-FAILURE' "$ANCHOR_INTRUSIONS"; then
    die "the anchor watcher could not list PF anchors during the probe windows ($(grep -c POLL-FAILURE "$ANCHOR_INTRUSIONS") failed polls); the concurrency check lapsed, so nothing is graded"
  fi
  [[ ! -s "$ANCHOR_INTRUSIONS" ]] \
    || die "another writ session anchor was loaded during the probe windows; its rules were consulted for our datagrams, so nothing is graded. Seen: $(sort -u "$ANCHOR_INTRUSIONS" | tr '\n' ';')"
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

# Source address of the first packet, from line $2 onward of capture $1,
# addressed to $3:$4 whose payload carries nonce $5; empty if none. tcpdump
# -A prints the header line, then the payload as text, so the nonce line is
# attributed to the most recent header for our destination.
bridge_source_for_nonce() {
  sed -n "$(($2 + 1)),\$p" "$1" | awk -v dst=" > $3.$4: " -v nonce="$5" '
    / IP [0-9.]+ > [0-9.]+: / { hdr = (index($0, dst) ? $0 : "") ; next }
    hdr != "" && index($0, nonce) {
      sub(/.* IP /, "", hdr); sub(/\.[0-9]+ > .*/, "", hdr); print hdr; exit
    }
  '
}

# Die unless every bridge capture is still running. A capture that died
# mid-window returns empty lookups, which would grade as "not forwarded" and
# pin a false drop. `ps` rather than `kill -0`: the captures run under sudo,
# and kill -0 on a root process from here fails whether or not it exists. And
# ps's *output* rather than its exit status: on recent macOS `ps -p` can exit
# 1 with "ps: time: requires entitlement" while still listing the process.
process_alive() {
  [[ -n "$(ps -p "$1" -o pid= 2>/dev/null)" ]]
}

require_observers_alive() {
  local moment="$1" target
  for target in "${!TARGET_CAPTURE_PID[@]}"; do
    process_alive "${TARGET_CAPTURE_PID[$target]}" \
      || die "the ${target} bridge capture was not running ${moment}; its silence would have been graded, so nothing is graded"
  done
}

# Start capturing UDP to the probe port on target $1's bridge.
start_capture() {
  local target="$1" bridge="${TARGET_BRIDGE[$1]}"
  local capture="${TMP_DIR}/tcpdump-${target}.log" err="${TMP_DIR}/tcpdump-${target}.err"
  log "capturing UDP to port ${PROBE_PORT} on ${bridge} (${target})"
  # The redirects are deliberately the unprivileged shell's: the log lives in
  # the user-owned TMP_DIR, and only the capture itself needs root.
  # shellcheck disable=SC2024
  sudo tcpdump -i "$bridge" -n -l -q -A "udp and dst port ${PROBE_PORT}" >"$capture" 2>"$err" &
  TARGET_CAPTURE_PID[$target]=$!
  TARGET_CAPTURE[$target]="$capture"
  sleep 2
  process_alive "${TARGET_CAPTURE_PID[$target]}" \
    || die "tcpdump did not start on ${bridge}: $(cat "$err")"
}

# Send one UDP datagram from target $1's guest with source $3 toward that
# guest's gateway, and report what the bridge capture saw. The guest's exit
# status is logged and ignored. Writes one line to result-<target>-<name>,
# because every consumer is a single `read`:
#   <name> <emitted> <forwarded> <delta> <bridge src> <rewritten>
# where bridge src is the source the capture saw ("-" if none) and rewritten
# is "no" or "bridge" (the capture saw a source other than the requested one).
probe() {
  local target="$1" name="$2" source="$3" add_address="$4"
  local vm="${TARGET_VM[$target]}" gateway="${TARGET_GATEWAY[$target]}"
  local bridge="${TARGET_BRIDGE[$target]}" capture="${TARGET_CAPTURE[$target]}"
  local nonce="writ-spoof-${target}-${name}-${RANDOM}${RANDOM}"
  log "probe ${target}/${name}: source ${source} -> ${gateway}:${PROBE_PORT} (${nonce})"

  if [[ "$add_address" == "yes" ]]; then
    # Tolerate an alias that already exists, then insist it is there: a
    # silently missing alias would make nc fail to bind, no frame would be
    # sent, and the capture's silence would read as a platform verdict.
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
  # status is diagnostic. Whether a frame left the guest at all is decided
  # below from the capture, the TX counter, and nc's stderr, not this status.
  local nc_err="${TMP_DIR}/nc-${target}-${name}.err"
  set +e
  guest_in "$vm" "printf '%s' '${nonce}' | nc -u -s ${source} -w 1 ${gateway} ${PROBE_PORT}" 2>"$nc_err"
  local guest_status=$?
  set -e
  log "  guest nc exit status ${guest_status} (diagnostic only)"
  sleep 2
  tx_after="$(guest_tx_packets "$vm")"

  local guest_says_emitted="yes"
  if [[ -s "$nc_err" ]]; then
    guest_says_emitted="no"
    log "  guest nc wrote to stderr: $(tr '\n' ' ' <"$nc_err")"
  fi
  if (( tx_after <= tx_before )); then
    guest_says_emitted="no"
    log "  guest eth0 TX packet counter did not rise (${tx_before} -> ${tx_after})"
  fi

  # The bridge capture (BPF, which taps the interface before PF filters) is
  # the host observer that matters: did vmnet put the frame on the host
  # bridge? Correlate by nonce only; the source is an observation.
  local fwd_src forwarded="no" rewritten="no"
  fwd_src="$(bridge_source_for_nonce "$capture" "$capture_lines_before" "$gateway" "$PROBE_PORT" "$nonce")"
  if [[ -n "$fwd_src" ]]; then
    forwarded="yes"
  fi
  # Host evidence outranks the guest's: a frame the capture saw was emitted,
  # whatever nc printed afterwards (an ICMP port-unreachable, or PF's `block
  # return`, can make nc report an error once the frame has left). The
  # guest-side witness only decides when the capture saw nothing.
  local emitted="$guest_says_emitted"
  if [[ "$forwarded" == "yes" ]]; then
    emitted="yes"
    if [[ "$guest_says_emitted" == "no" ]]; then
      log "  (the capture saw the frame, so it was emitted; the guest-side error above is diagnostic)"
    fi
  fi
  if [[ -n "$fwd_src" && "$fwd_src" != "$source" ]]; then
    rewritten="bridge"
    log "  SOURCE REWRITTEN on the bridge: requested ${source}, bridge saw ${fwd_src}"
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

  log "  guest emitted a frame: ${emitted}; forwarded onto ${bridge}: ${forwarded} (src ${fwd_src:--})${counter_text}"
  RESULTS+=("${target}/${name} source=${source} emitted=${emitted} forwarded=${forwarded} bridge_src=${fwd_src:--} rewritten=${rewritten} deny_v4_delta=${delta}")
  printf '%s %s %s %s %s %s\n' "$name" "$emitted" "$forwarded" "$delta" "${fwd_src:--}" "$rewritten" \
    >"${TMP_DIR}/result-${target}-${name}"
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
require_no_other_anchors "before start"

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
if [[ "$PROBE_PORT" == "$BROKER_PORT" ]]; then
  log "probe UDP target port shares its number with the TCP broker port ${BROKER_PORT} (range has no free alternative); harmless, nothing binds it on the host"
fi
BROKER_PID="$(start_http_server "$BROKER_DIR" "$BROKER_PORT" "${TMP_DIR}/broker.log")"
log "broker is up on ${BROKER_PORT} (TCP); probe target port is ${PROBE_PORT} (UDP, no host listener — the bridge capture is the observer)"

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
require_no_other_anchors "after both guests started"
require_own_anchor_loaded "after both guests started"
start_anchor_watch

log "session anchor rules:"
sudo pfctl -a "$PF_ANCHOR" -sr 2>/dev/null | sed 's/^/    /'

RESULTS=()

# --- positive controls first. The unconfined guest's own address must be
# forwarded onto its bridge, or the capture is not observing that bridge and
# nothing else in the run can be graded. Its spoofed sends must at least be
# emitted, or the sender cannot spoof and a session silence would be about
# nc, not vmnet.
probe unconfined control "$CONTROL_GUEST_IPV4" no
read -r _ uc_emitted uc_forwarded _ _ _ <"${TMP_DIR}/result-unconfined-control"
[[ "$uc_emitted" == "yes" ]] \
  || die "the unconfined guest did not emit its own-address datagram (nc error and no TX, and the capture saw nothing); the sender is not working"
[[ "$uc_forwarded" == "yes" ]] \
  || die "the unconfined own-address datagram was not seen on ${TARGET_BRIDGE[unconfined]}; the capture is not observing that bridge, so no silence below would mean anything"

probe unconfined foreign "$FOREIGN_SOURCE" yes
read -r _ uf_emitted uf_fwd _ uf_fwd_src _ <"${TMP_DIR}/result-unconfined-foreign"
[[ "$uf_emitted" == "yes" ]] \
  || die "the unconfined guest did not emit the foreign-source datagram; the spoofing sender does not work even without confinement"
if [[ -n "$SIBLING_SOURCE" ]]; then
  probe unconfined sibling "$SIBLING_SOURCE" yes
  read -r _ us_emitted us_fwd _ us_fwd_src _ <"${TMP_DIR}/result-unconfined-sibling"
  [[ "$us_emitted" == "yes" ]] \
    || die "the unconfined guest did not emit the sibling-source datagram; the spoofing sender does not work even without confinement"
fi

# --- session calibration: an in-subnet frame must be forwarded onto the
# session bridge and counted by the labelled IPv4 deny, or a blind capture,
# a broken counter parser, or an anchor that is not denying would each let a
# later result be misread. (Delivery to a host socket is not a signal here:
# vmnet does not deliver guest UDP to the gateway into host sockets at all.)
probe session control "$GUEST_IPV4" no
read -r _ ctl_emitted ctl_forwarded ctl_delta _ _ <"${TMP_DIR}/result-session-control"
[[ "$ctl_emitted" == "yes" ]] \
  || die "the session guest did not emit the control datagram (nc error and no TX, and the capture saw nothing); the sender is not working"
[[ "$ctl_forwarded" == "yes" ]] \
  || die "the control datagram from the session guest's own address was not seen on ${TARGET_BRIDGE[session]}; the capture is not observing the session bridge"
[[ "$ctl_delta" -gt 0 ]] \
  || die "the control datagram did not raise the 'writ deny agent v4' counter (delta ${ctl_delta}); either the anchor did not match an in-subnet frame or the counter parser is broken"

probe session foreign "$FOREIGN_SOURCE" yes
if [[ -n "$SIBLING_SOURCE" ]]; then
  probe session sibling "$SIBLING_SOURCE" yes
fi
# A session that appeared during the probe windows would have had its rules
# consulted for our datagrams; if one is here now, or the watch saw one pass
# through, nothing above is graded. Likewise an observer that died: every
# empty lookup above would then be a lie.
require_no_other_anchors "after the probes"
require_own_anchor_loaded "after the probes"
stop_anchor_watch
require_observers_alive "after the probes"

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

# Verdict per spoofed source, from host-owned facts: the session bridge
# capture (did vmnet put the frame on the host bridge?) and the labelled deny
# counter (did the session anchor deny it?). The unconfined result for the
# same source is the positive control that vmnet forwards a spoofed source at
# all. tcpdump taps the interface before PF filters, so a frame on the bridge
# is a vmnet fact independent of the anchor, and the two bridges should agree
# on forwarding; the counter is the PF fact. Guest facts (emission) can
# withhold a verdict but never award one.
#   $1 name; $2 requested source;
#   $3 $4 unconfined forwarded / bridge source;
#   $5..$8 session emitted / forwarded / deny delta / bridge source.
# Observed sources are "-" when the capture saw nothing.
verdict() {
  local name="$1" source="$2"
  local u_fwd="$3" u_fwd_src="$4"
  local emitted="$5" fwd="$6" delta="$7" fwd_src="$8"

  # vmnet may rewrite a spoofed source as it forwards (anti-spoof by rewrite,
  # not drop). Where a rewritten source lands decides which rules cover it:
  # inside the session /24 the source-scoped deny applies; outside, nothing in
  # the anchor can match it.
  local u_bridge_rw="no" bridge_rw="no" src_in_session="no"
  if [[ "$u_fwd_src" != "-" && "$u_fwd_src" != "$source" ]]; then u_bridge_rw="yes"; fi
  if [[ "$fwd_src" != "-" && "$fwd_src" != "$source" ]]; then bridge_rw="yes"; fi
  if [[ "$fwd_src" != "-" ]] && addr_in_cidr "$IPV4_CIDR" "$fwd_src"; then src_in_session="yes"; fi

  # --- the platform fact: does vmnet forward a spoofed source onto a host
  # bridge, and as-sent or rewritten? Pinned only when the two bridges agree,
  # since BPF is pre-PF and both bridges are the same kind.
  if [[ "$emitted" != "yes" ]]; then
    log "PLATFORM ${name}: the session guest did not emit its copy (see the nc stderr and TX lines above), so the session bridge cannot corroborate the control; not pinned. See the verdict below."
  elif [[ "$fwd" == "no" && "$delta" -gt 0 ]]; then
    log "PLATFORM ${name}: the session bridge capture saw no frame yet 'writ deny agent v4' rose by ${delta}; a rewrite into the subnet the capture missed cannot be ruled out, so no forwarding fact (least of all 'does not forward') can be pinned from this run. See the verdict below."
  elif [[ "$fwd" != "$u_fwd" || "$bridge_rw" != "$u_bridge_rw" ]]; then
    log "PLATFORM ${name}: the two bridges disagree (unconfined forwarded=${u_fwd} bridge-rewritten=${u_bridge_rw}, session forwarded=${fwd} bridge-rewritten=${bridge_rw}); tcpdump taps before PF, so they should agree — no platform fact can be pinned from this run. See the verdict below."
  elif [[ "$u_bridge_rw" == "yes" ]]; then
    log "PLATFORM ${name}: vmnet forwards the spoofed source but REWRITES it (requested ${source}, bridge saw ${u_fwd_src}). It anti-spoofs by rewriting, not dropping. Record this as a pinned platform fact (plan 'Beyond E3' question 4), distinct from both 'forwards as-is' and 'does not forward'."
  elif [[ "$u_fwd" == "yes" ]]; then
    log "PLATFORM ${name}: vmnet forwards the spoofed source as sent onto the host bridge. Record this as a pinned platform fact (plan 'Beyond E3' question 4): the source-scoped IPv4 rules face a real frame, so C2b (interface-scoped rules) is a live fix, not hardening."
  else
    log "PLATFORM ${name}: neither bridge saw the spoofed-source frame, but no trusted observer confirms the spoofed frame was emitted at all — the bridge capture is the only host-owned observer and it sits after vmnet, so a guest that silently failed to emit the spoofed source and a vmnet that dropped it look identical here (the TX counter is aggregate and guest-reported). Consistent with vmnet dropping spoofed sources, but NOT pinnable. See the verdict below. To pin 'does not forward' you would need a trusted pre-vmnet observer, which this platform does not offer; treat C2b as warranted meanwhile."
  fi

  # --- the confinement verdict: what the session anchor did with the frame.
  if [[ "$emitted" != "yes" ]]; then
    log "VERDICT ${name}: INCONCLUSIVE — the session guest did not emit the datagram (see the nc stderr and TX counter lines above), so its bridge's silence says nothing. Fix the sender and rerun."
  elif [[ "$fwd" == "no" && "$delta" -gt 0 ]]; then
    log "VERDICT ${name}: INCONCLUSIVE — 'writ deny agent v4' rose by ${delta} during the window but the bridge capture saw no frame; a rewrite into the subnet the capture missed, or unrelated in-subnet traffic, cannot be told apart. Rerun before recording anything."
  elif [[ "$fwd" == "no" && "$u_fwd" == "yes" ]]; then
    log "VERDICT ${name}: UNEXPLAINED — the frame was forwarded on the unconfined bridge but not the session bridge, yet tcpdump taps before PF, so the anchor cannot account for the difference. Inspect the captures and rerun; do not pin either way."
  elif [[ "$fwd" == "no" ]]; then
    log "VERDICT ${name}: INCONCLUSIVE — neither bridge saw the spoofed-source frame, but the only trusted observer sits after vmnet, so this cannot be told apart from a guest that never emitted the spoofed frame (its emission rests on the aggregate, guest-reported TX counter). A forwarded result would be conclusive; a silent one is not. Do not record 'vmnet does not forward' from this; C2b stays warranted. Rerun, or add an (untrusted) guest-side eth0 capture as corroboration, if you must characterise this."
  elif [[ "$src_in_session" == "yes" && "$delta" -eq 0 ]]; then
    log "VERDICT ${name}: LIVE GAP (ANCHOR) — the bridge carried an IN-SUBNET source (${fwd_src}, rewritten from ${source}) that the session deny should have matched, yet 'writ deny agent v4' did not count it. This is not the source-scoping gap: the anchor failed to deny an in-subnet frame. Investigate the anchor (rule order, interface, state) before attributing anything to C2b."
  elif [[ "$src_in_session" == "yes" ]]; then
    log "VERDICT ${name}: REWRITTEN INTO THE SUBNET — vmnet rewrote the source to the in-subnet ${fwd_src} and the session deny counted it (+${delta}). The confinement held, but because vmnet rewrote the source into the session /24, not because the source-scoped rules address spoofing. C2b still applies as the session's own guarantee."
  elif [[ "$delta" -gt 0 ]]; then
    log "VERDICT ${name}: INCONCLUSIVE — the bridge carried the out-of-subnet source ${fwd_src}, which the source-scoped deny cannot match, yet 'writ deny agent v4' rose by ${delta}; that is unrelated in-subnet traffic in the window, or a rewrite the capture missed. Rerun before recording anything."
  else
    local rw_note=""
    [[ "$bridge_rw" == "yes" ]] && rw_note=" (rewritten from ${source}, but still outside the session /24)"
    log "VERDICT ${name}: LIVE GAP — vmnet forwarded the frame onto the host bridge with the out-of-subnet source ${fwd_src}${rw_note}, and the session anchor did not deny it ('writ deny agent v4' unchanged); the source-scoped rules cannot match it, so the frame is loose on the host side. Stage C2b (interface-scoped IPv4 rules) is urgent for the legacy profile."
  fi
}
read -r _ f_emitted f_fwd f_delta f_fwd_src _ <"${TMP_DIR}/result-session-foreign"
verdict foreign "$FOREIGN_SOURCE" \
  "$uf_fwd" "$uf_fwd_src" \
  "$f_emitted" "$f_fwd" "$f_delta" "$f_fwd_src"
if [[ -n "$SIBLING_SOURCE" ]]; then
  read -r _ s_emitted s_fwd s_delta s_fwd_src _ <"${TMP_DIR}/result-session-sibling"
  verdict sibling "$SIBLING_SOURCE" \
    "$us_fwd" "$us_fwd_src" \
    "$s_emitted" "$s_fwd" "$s_delta" "$s_fwd_src"
else
  log "VERDICT sibling: not measured — ${IPV4_POOL} holds a single /24, so there is no other session subnet to spoof from."
fi

cleanup
trap - EXIT INT TERM
log "measurement complete"
