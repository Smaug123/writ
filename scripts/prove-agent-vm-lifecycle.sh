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
    wget, and nslookup (the IPv6 backstop assertion sends a real IPv6 TCP
    probe with wget and grades it on the host's PF deny counter; the released
    workload holds no CAP_NET_RAW, so a raw-socket tool such as busybox ping
    cannot be the sender)
  - a python3 that the macOS Application Firewall allows incoming connections
    to: this proof's broker is `python3 -m http.server`, and a blocked
    interpreter fails only for the guest. The proof preflights this before it
    builds anything and prints the one command that fixes it.

Environment overrides:
  WRIT_PROVE_IMAGE       OCI image to run, default alpine:latest
  WRIT_PROVE_IPV4_POOL   broker-owned IPv4 pool, default 192.168.0.0/16
  WRIT_PROVE_IPV6_POOL   broker-owned IPv6 pool, default fd83:b6f2:e57::/48
  WRIT_PROVE_SUBNET_INDEX  session subnet index, default 252
  WRIT_PROVE_BROKER_PORT_MIN  minimum allowed broker port, default 49152
  WRIT_PROVE_BROKER_PORT_MAX  maximum allowed broker port, default 65535
  WRIT_PROVE_TOLERATE_BLOCKED_HOST_LISTENER=1
                         carry on past a broker-reach failure whose evidence
                         says a host socket filter ate the request above PF
                         (on macOS: the Application Firewall blocking the
                         listener's binary), so the firewall legs still run;
                         the proof then exits 2. This also downgrades the
                         host-listener preflight to a warning, since that gate
                         predicts exactly the failure being waived
EOF
}

log() {
  printf '[prove-lifecycle] %s\n' "$*"
}

die() {
  printf '[prove-lifecycle] error: %s\n' "$*" >&2
  dump_pf_diagnostics
  exit 1
}

# For failures before any PF anchor or VM exists. `die` dumps PF state through
# sudo, which at that point would prompt for a password this script has not
# asked for yet, to describe an anchor that was never installed.
die_before_setup() {
  printf '[prove-lifecycle] error: %s\n' "$*" >&2
  exit 1
}

# Stands in for die_before_setup when WRIT_PROVE_TOLERATE_BLOCKED_HOST_LISTENER=1:
# it returns instead of exiting, so the run carries on to the legs the waiver
# exists to exercise. assert_broker_reachable then grades the failure for real and
# forces the non-zero exit, so waiving the preflight cannot turn into a green run.
warn_before_setup() {
  printf '[prove-lifecycle] warning: %s\n' "$*" >&2
  printf '[prove-lifecycle] warning: continuing because WRIT_PROVE_TOLERATE_BLOCKED_HOST_LISTENER=1; the proof will exit non-zero\n' >&2
}

# On failure, before anything is torn down: what PF did with the session's
# frames. The per-rule counters say which rule of the anchor decided each
# packet and on which interface; the states say what `keep state` created.
# Best effort, so a failure before the anchor or VM exists prints nothing.
dump_pf_diagnostics() {
  if [[ -z "${PF_ANCHOR:-}" ]]; then
    return
  fi
  printf '[prove-lifecycle] diagnostics: pfctl -a %s -vvsr\n' "$PF_ANCHOR" >&2
  sudo pfctl -a "$PF_ANCHOR" -vvsr >&2 2>/dev/null || true
  printf '[prove-lifecycle] diagnostics: pfctl -vss (session subnet only)\n' >&2
  sudo pfctl -vss 2>/dev/null | grep -B1 -A3 -F "${IPV4_CIDR%.0/24}." >&2 || true
  printf '[prove-lifecycle] diagnostics: pfctl -s info\n' >&2
  sudo pfctl -s info >&2 2>/dev/null || true
  printf '[prove-lifecycle] diagnostics: pfctl -s Interfaces -v (bridge and vmenet)\n' >&2
  sudo pfctl -s Interfaces -v 2>/dev/null | grep -A8 -E '^(bridge|vmenet)' >&2 || true
  printf '[prove-lifecycle] diagnostics: ifconfig (bridge and vmenet)\n' >&2
  ifconfig 2>/dev/null | grep -A12 -E '^(bridge|vmenet)[0-9]+:' >&2 || true
  if [[ -n "${VM_NAME:-}" ]]; then
    printf '[prove-lifecycle] diagnostics: guest ip addr / route / neigh\n' >&2
    container exec "$VM_NAME" sh -lc 'ip -4 addr; ip -4 route; ip neigh' >&2 2>/dev/null || true
  fi
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/host-listener-preflight.sh
source "${ROOT_DIR}/scripts/lib/host-listener-preflight.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/broker-reach-evidence.sh
source "${ROOT_DIR}/scripts/lib/broker-reach-evidence.sh"
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
    local helper_remove
    helper_remove=(
      sudo "$HELPER" remove
      --session-id "$SESSION_ID"
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

# Linux capability bit numbers (include/uapi/linux/capability.h).
CAP_NET_ADMIN_BIT=12
CAP_NET_RAW_BIT=13

# rc 0 iff bit $2 is set in the hex capability mask $1 as /proc/<pid>/status
# renders it. Decoded here in bash (64-bit arithmetic), not in the guest's
# 32-bit busybox ash.
cap_mask_has_bit() {
  local mask="$1"
  local bit="$2"
  [[ "$mask" =~ ^[0-9a-fA-F]{1,16}$ ]] || die "malformed capability mask: '${mask}'"
  (( (0x$mask >> bit) & 1 ))
}

# The decoder's own positive control, so the assertion below cannot pass
# because the decoder reads every mask as empty. Apple `container`'s documented
# default set (AUDIT_WRITE CHOWN DAC_OVERRIDE FOWNER FSETID KILL MKNOD
# NET_BIND_SERVICE NET_RAW SETFCAP SETGID SETPCAP SETUID SYS_CHROOT) renders as
# this mask: it holds NET_RAW and CHOWN and not NET_ADMIN.
assert_capability_decoder_works() {
  local default_set=00000000a80425fb
  if ! cap_mask_has_bit "$default_set" "$CAP_NET_RAW_BIT"; then
    die "capability decoder self-test: NET_RAW not found in ${default_set}"
  fi
  if ! cap_mask_has_bit "$default_set" 0; then
    die "capability decoder self-test: CHOWN not found in ${default_set}"
  fi
  if cap_mask_has_bit "$default_set" "$CAP_NET_ADMIN_BIT"; then
    die "capability decoder self-test: NET_ADMIN found in ${default_set}"
  fi
}

# The released workload is PID 1 (the IPv4-only prelaunch gate `exec`s the
# guest command once released), so its capability sets are /proc/1/status's.
# Every one of the five sets is checked: a capability that is merely not
# effective — still permitted, or still in the bounding set for a re-exec of a
# file-capability binary to pick up — must fail too.
assert_released_workload_lacks_net_admin_and_net_raw() {
  log "assert: released workload holds neither NET_ADMIN nor NET_RAW in any capability set"
  assert_capability_decoder_works
  # Positive control on the target: PID 1 must be the released guest command,
  # not the prelaunch gate or an init shim, or the masks describe the wrong
  # process. The released command is a `while :; do sleep; done` loop, not a
  # bare `sleep`, precisely so BusyBox ash does not tail-exec it away and
  # PID 1's cmdline keeps the marker (capabilities are preserved across any
  # exec regardless, so /proc/1/status is the workload's posture either way).
  guest 'tr "\0" " " </proc/1/cmdline | grep -q lifecycle-released' \
    || die "guest PID 1 is not the released guest command"
  local status
  status="$(guest 'cat /proc/1/status')" || die "could not read /proc/1/status in the guest"
  local seen=0
  local name mask
  while read -r name mask; do
    case "$name" in
      CapInh:|CapPrm:|CapEff:|CapBnd:|CapAmb:) ;;
      *) continue ;;
    esac
    seen=$((seen + 1))
    if cap_mask_has_bit "$mask" "$CAP_NET_ADMIN_BIT"; then
      die "released workload holds NET_ADMIN in ${name} ${mask}"
    fi
    if cap_mask_has_bit "$mask" "$CAP_NET_RAW_BIT"; then
      die "released workload holds NET_RAW in ${name} ${mask} (the IPv4-only launch must pass --cap-drop NET_RAW)"
    fi
    log "  ${name} ${mask}: no NET_ADMIN, no NET_RAW"
  done <<<"$status"
  [[ "$seen" -eq 5 ]] || die "expected 5 capability sets in /proc/1/status, decoded ${seen}"
  log "pass: released workload holds neither NET_ADMIN nor NET_RAW in any capability set"
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

# The attached anchor: once the VM's bridge and members exist, every rule of
# the session anchor is scoped to one of them, so the anchor decides every
# frame the guest emits however the guest addressed it, and no frame that
# arrives on any other host interface. A rule without `on <iface>` here is the
# bootstrap anchor surviving past the attach, which is a failed replacement.
assert_pf_anchor_is_interface_scoped() {
  log "assert: every rule of the PF session anchor is scoped to the agent's bridge or a member"
  local rules
  rules="$(sudo pfctl -a "$PF_ANCHOR" -sr 2>/dev/null || true)"
  printf '%s\n' "$rules"
  local unscoped
  unscoped="$(printf '%s\n' "$rules" | grep -Ev '^$|^(pass|block)[^"]* on (bridge|vmenet)[0-9]+ ' || true)"
  if [[ -n "$unscoped" ]]; then
    die "PF anchor holds a rule not scoped to the agent's bridge or a member: ${unscoped}"
  fi
  # e.g. pass in quick on bridge100 inet proto tcp from 10.200.7.0/24 to 10.200.7.1 port = 49152 flags S/SA keep state
  if ! printf '%s\n' "$rules" | grep -Eq '^pass in quick on (bridge|vmenet)[0-9]+ inet proto tcp from '; then
    die "PF anchor lacks an interface-scoped IPv4 allow for the broker: ${PF_ANCHOR}"
  fi
  # e.g. block return in quick on bridge100 inet all label "writ deny agent v4 iface"
  if ! printf '%s\n' "$rules" | grep -Eq '^block return in quick on (bridge|vmenet)[0-9]+ inet all label '; then
    die "PF anchor lacks an interface-scoped IPv4 deny: ${PF_ANCHOR}"
  fi
  # e.g. block return in quick on bridge100 inet6 all label "writ deny agent v6 iface"
  if ! printf '%s\n' "$rules" | grep -Eq '^block return in quick on (bridge|vmenet)[0-9]+ inet6 all label '; then
    die "PF anchor lacks an interface-scoped IPv6 deny (the IPv4-only backstop): ${PF_ANCHOR}"
  fi
  log "pass: PF session anchor is interface-scoped, with the IPv4 allow, the IPv4 deny, and the IPv6 deny"
}

# The core of the P1: a root guest can undo the in-guest IPv6 disable and
# reacquire a vmnet-RA ULA after release. Prove the *host* PF interface deny
# still blocks its IPv6 egress, so the bypass is closed at a layer the guest
# cannot touch.
# The summed packet counter of the session anchor's interface-scoped denies of
# one family (`inet` or `inet6`), read on the host from `pfctl -vsr`, which
# renders each rule followed by an indented `[ Evaluations: N Packets: N Bytes:
# N States: N ]` line. The firewall installs a separate `block ... <af> all`
# per interface (the bridge AND each vmenet member), and PF may drop the probe
# on any of them, so this aggregates the Packets counters of ALL matching
# denies. Dies unless at least one such rule renders with a counter, so a
# format drift fails the proof rather than reading as zero.
pf_iface_deny_packets() {
  local family="$1"
  local rules
  rules="$(sudo pfctl -a "$PF_ANCHOR" -vsr 2>/dev/null)" \
    || die "could not read verbose rules for ${PF_ANCHOR}"
  local count
  count="$(printf '%s\n' "$rules" | awk -v family="$family" '
    $0 ~ ("^block .* on (bridge|vmenet)[0-9]+ " family " all") { rule = 1; next }
    rule && match($0, /Packets: [0-9]+/) {
      total += substr($0, RSTART + 9, RLENGTH - 9); matched = 1; rule = 0; next
    }
    /^[^ \t[]/ { rule = 0 }
    END { if (matched) print total }
  ')"
  [[ "$count" =~ ^[0-9]+$ ]] \
    || die "no ${family} interface deny with a packet counter rendered in pfctl -vsr for ${PF_ANCHOR}"
  printf '%s\n' "$count"
}

# The packet and state counters of the session anchor's interface-scoped
# broker `pass` rules, summed over every interface the firewall installed
# one on, read the same way as pf_iface_deny_packets. Prints "PACKETS STATES".
# Dies on format drift rather than reading as zero, for the same reason.
pf_broker_pass_counters() {
  local rules
  rules="$(sudo pfctl -a "$PF_ANCHOR" -vsr 2>/dev/null)" \
    || die "could not read verbose rules for ${PF_ANCHOR}"
  local counters
  counters="$(printf '%s\n' "$rules" | awk '
    /^pass in quick on (bridge|vmenet)[0-9]+ inet proto tcp from / { rule = 1; next }
    rule && match($0, /Packets: [0-9]+/) {
      packets += substr($0, RSTART + 9, RLENGTH - 9)
      if (match($0, /States: [0-9]+/)) { states += substr($0, RSTART + 8, RLENGTH - 8) }
      matched = 1; rule = 0; next
    }
    /^[^ \t[]/ { rule = 0 }
    END { if (matched) print packets, states }
  ')"
  [[ "$counters" =~ ^[0-9]+\ [0-9]+$ ]] \
    || die "no interface-scoped broker pass rule with counters rendered in pfctl -vsr for ${PF_ANCHOR}"
  printf '%s\n' "$counters"
}

# Broker reachability is the proof's positive control: the one connection the
# anchor must pass. When it fails, the question is where the request died, and
# the answer decides who is at fault:
#
#   - PF counted it on a deny rule            -> the anchor is implicated
#   - PF passed it and the listening process
#     never saw it                            -> a socket filter above PF
#   - anything else                            -> a human reads the evidence
#
# The middle case has been rediscovered from a bare timeout more than once. On
# macOS it is the Application Firewall (`socketfilterfw`) blocking the
# listener's binary: the kernel completes the handshake and ACKs the request,
# then the filter detaches the socket before `accept()` returns it, so the
# process never sees a byte while loopback — which the firewall exempts — keeps
# working. It is not an Apple vmnet defect; see
# docs/vmnet-accept-bug-and-broker-vm-plan.md, whose original root cause is
# superseded by the correction at its head.
#
# Five things are read on the host to tell those cases apart: the anchor's pass
# and deny counters, the PF state's TCP phases, which requests the listener
# logged, and whether the listener itself reported a not-connected socket
# (ENOTCONN) while serving the guest. That last witness is process-level proof
# that accept() happened, which is why a state pair of TIME_WAIT:TIME_WAIT — all
# a short graded probe may leave behind — no longer hides the diagnosis.
# scripts/lib/broker-reach-evidence.sh does the classification as pure string
# logic, and scripts/test-proof-helpers.sh tests it without hardware.
#
# WRIT_PROVE_TOLERATE_BLOCKED_HOST_LISTENER=1 lets the proof carry on past that
# one signature, so the firewall legs that follow can still be exercised on an
# affected host; the final summary then says the positive control was waived,
# and the proof exits non-zero.
BROKER_REACH_WAIVED=0
assert_broker_reachable() {
  local label="VM can reach broker port through host-only gateway"
  local deny_before pass_before
  deny_before="$(pf_iface_deny_packets inet)"
  pass_before="$(pf_broker_pass_counters)"
  log "assert: ${label}"
  if guest "wget -q -T 3 -O - '$BROKER_URL' | grep -q '^broker-ok$'"; then
    log "pass: ${label}"
    return
  fi
  local deny_after pass_after
  deny_after="$(pf_iface_deny_packets inet)"
  pass_after="$(pf_broker_pass_counters)"
  local pass_packets=$(( ${pass_after% *} - ${pass_before% *} ))
  local pass_states="${pass_after#* }"
  local deny_packets=$(( deny_after - deny_before ))
  # pfctl prints the TCP state pair as `<src-state>:<dst-state>`, the last field
  # on the tuple line.
  local host_state state_pair=""
  host_state="$(sudo pfctl -ss 2>/dev/null \
    | grep -F "tcp ${IPV4_GATEWAY}:${BROKER_PORT} <- ${GUEST_IPV4}:" || true)"
  if [[ -n "$host_state" ]]; then
    state_pair="${host_state##* }"
  fi
  local broker_log="${TMP_DIR}/broker.log"
  local guest_logged=0 loopback_logged=0 listener_detached=0
  grep -Fq "${GUEST_IPV4} - -" "$broker_log" 2>/dev/null && guest_logged=1
  grep -Fq "127.0.0.1 - -" "$broker_log" 2>/dev/null && loopback_logged=1
  # python's http.server names the peer as `from ('<ip>', <port>)` when a
  # handler raises, so both witnesses must name the guest before this counts as
  # a detached socket on the guest's own request.
  if grep -Fq 'Socket is not connected' "$broker_log" 2>/dev/null \
    && grep -Fq "from ('${GUEST_IPV4}'" "$broker_log" 2>/dev/null; then
    listener_detached=1
  fi
  local phase
  phase="$(writ_tcp_state_pair_phase "$state_pair")"
  log "broker-reach failure evidence:"
  log "  anchor broker pass rule: +${pass_packets} packet(s) during the probe, ${pass_states} live state(s)"
  log "  anchor IPv4 interface deny: +${deny_packets} packet(s) during the probe"
  log "  host PF state for ${IPV4_GATEWAY}:${BROKER_PORT} <- ${GUEST_IPV4}: ${host_state:-none} (${phase})"
  log "  broker log: loopback request logged=${loopback_logged}, guest request logged=${guest_logged}"
  log "  broker listener reported ENOTCONN while serving the guest: ${listener_detached}"
  # The listener's own log, in full. It is a handful of lines, and when a socket
  # filter is at work the traceback in it names the cause outright — that was
  # sitting unread in this file the first time this leg was diagnosed by hand.
  local log_lines=0
  if [[ -s "$broker_log" ]]; then
    log_lines="$(grep -c '' "$broker_log")"
  fi
  log "broker listener log (${broker_log}, ${log_lines} line(s)):"
  if (( log_lines > 0 )); then
    while IFS= read -r line; do
      log "  ${line}"
    done <"$broker_log"
  else
    log "  (empty)"
  fi
  local verdict
  verdict="$(writ_classify_broker_reach_evidence "$pass_packets" "$pass_states" \
    "$deny_packets" "$loopback_logged" "$guest_logged" "$state_pair" \
    "$listener_detached")"
  case "$verdict" in
    pf-dropped)
      log "diagnosis: an interface-scoped deny rule of the session anchor counted the guest's probe, so PF itself dropped it. The anchor, the pools it was rendered from, or the broker port is wrong. This is not a host socket filter."
      die "expected success: ${label} (PF dropped it; see diagnosis above)"
      ;;
    listener-never-saw-request)
      log "diagnosis: PF passed the guest's connection and dropped nothing, the handshake completed on the host, and the listening process never saw the request — a socket filter took it above PF. On macOS that is the Application Firewall blocking the listener's binary (loopback is exempt, which is why this proof's own loopback control request was logged). The session anchor is not implicated. This proof's preflight tests exactly this before booting a VM, so reaching here means the host changed under the run, or the guest's path differs from the interface the preflight used. Remedy: unblock the listener's binary with 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp <binary>' (scripts/allow-writd-firewall.sh does it for writd) and re-run. Background: docs/vmnet-accept-bug-and-broker-vm-plan.md, whose original vmnet root cause is superseded by the correction at its head."
      if [[ "${WRIT_PROVE_TOLERATE_BLOCKED_HOST_LISTENER:-0}" == "1" ]]; then
        BROKER_REACH_WAIVED=1
        log "WAIVED: continuing past the positive control because WRIT_PROVE_TOLERATE_BLOCKED_HOST_LISTENER=1; the proof will exit non-zero"
        return
      fi
      die "expected success: ${label} (a host socket filter blocked the listener; see diagnosis above; set WRIT_PROVE_TOLERATE_BLOCKED_HOST_LISTENER=1 to exercise the remaining legs anyway)"
      ;;
    *)
      log "diagnosis: none. The evidence above matches no known signature, so read it rather than assuming a firewall: in particular, a pass rule that counted nothing means PF never saw the guest's packets at all, which points at the bridge or the guest's route."
      die "expected success: ${label} (evidence above is inconclusive)"
      ;;
  esac
}

# The interface-scoped IPv4 deny is live on the guest's actual path: a TCP
# connect from the guest to a host port that is not the broker's must be
# blocked by that rule and counted by it. The guest's exit code is not the
# oracle (see assert_guest_ipv6_disable_is_irreversible); the host's deny-rule
# packet counter is. This exercises the same rule a forged-source frame would
# hit, but with an in-subnet source: the released workload holds neither
# NET_RAW nor NET_ADMIN (asserted above), so it cannot forge a source at all,
# and the forged-source measurement is a separate probe container's job (the
# plan's "Beyond E3", question 4). What this proves is that the rule counted
# in the readback is the rule deciding the guest's frames.
assert_forbidden_ipv4_egress_counted() {
  local before
  before="$(pf_iface_deny_packets inet)"
  log "probing a forbidden host port (IPv4 deny counter before: ${before})"
  expect_guest_blocked \
    "VM cannot reach forbidden host port" \
    "wget -q -T 3 -O - '$FORBIDDEN_URL'"
  local after
  after="$(pf_iface_deny_packets inet)"
  log "IPv4 deny counter after: ${after}"
  if (( after <= before )); then
    die "the host IPv4 interface deny counted no packet during the guest's probe (before=${before}, after=${after}); the probe sent nothing, or PF did not see it on the bridge"
  fi
  log "pass: host PF blocked $((after - before)) IPv4 packet(s) to the forbidden host port"
}

assert_guest_ipv6_disable_is_irreversible() {
  log "assert: a root guest cannot re-enable IPv6 (kernel ipv6.disable=1)"
  # The Ipv4OnlyNoGuestIpv6 launch disables IPv6 on the guest kernel boot line
  # (`--kernel-arg ipv6.disable=1`), so the P1 attack — a root guest writing
  # `disable_ipv6=0`, re-soliciting a vmnet RA and reacquiring a ULA — is not
  # merely blocked at the host but impossible in the guest: there is no IPv6
  # stack and no `/proc/sys/net/ipv6` to write. Prove that by running the exact
  # re-enable sequence a malicious root would, then requiring that nothing came
  # back.
  guest '
    for s in all default eth0; do
      printf 0 > /proc/sys/net/ipv6/conf/$s/disable_ipv6 2>/dev/null || true
      printf 2 > /proc/sys/net/ipv6/conf/$s/accept_ra 2>/dev/null || true
    done
    ip link set eth0 down 2>/dev/null || true
    ip link set eth0 up 2>/dev/null || true
  ' || true
  sleep 4
  log "guest IPv6 state after attempting re-enable:"
  guest 'ip -6 -o addr show 2>&1; ip -6 route show 2>&1; ls -d /proc/sys/net/ipv6 2>&1' || true
  # Positive proof the stack is gone, not merely that an RA has not arrived yet:
  # the kernel's IPv6 sysctl tree is absent. If it is present, the boot argument
  # did not take, so IPv6 is NOT irreversibly disabled and this must fail rather
  # than trust an empty `ip -6` snapshot.
  if guest 'test -e /proc/sys/net/ipv6'; then
    die "guest /proc/sys/net/ipv6 exists after re-enable attempt: the ipv6.disable=1 boot argument did not take, so IPv6 is not irreversibly disabled"
  fi
  # And no address or route may have appeared despite the re-enable attempt.
  local addrs routes
  addrs="$(guest 'ip -6 -o addr show scope global 2>/dev/null' | tr -d '[:space:]')"
  routes="$(guest 'ip -6 route show default 2>/dev/null' | tr -d '[:space:]')"
  if [ -n "$addrs" ] || [ -n "$routes" ]; then
    die "guest acquired IPv6 after a root re-enable attempt (addr='${addrs}' route='${routes}'); the kernel-line disable is not irreversible"
  fi
  # The host PF interface-scoped `block ... inet6 all` deny is still installed
  # (assert_pf_anchor_is_interface_scoped checks its presence) as defence in
  # depth against a guest-kernel compromise. Exercising its counter with a live
  # IPv6 frame now requires a separate IPv6-enabled probe container, because
  # this session's workload can no longer emit IPv6 at all; that live-fire test
  # is the vertical proof's job (docs/plans/2026-09-01-ipv4-only-locked-v1.md,
  # Stage E3), not this host-placement smoke proof.
  log "pass: a root guest holds no IPv6 address or route after a re-enable attempt, and /proc/sys/net/ipv6 is absent"
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

# Cheapest gate first: this proof's broker is a host listener, and a host
# socket filter that blocks it is invisible to every loopback check the harness
# makes. Catch that here, in about a second, rather than after a build, a sudo
# prompt, a PF anchor, and a VM boot.
#
# Under the waiver this must warn rather than exit. The waiver's whole purpose is
# to exercise the remaining legs on a host whose listener is blocked, and a fatal
# preflight would make it unreachable: the run would stop here, long before
# assert_broker_reachable, which is where the waiver is implemented.
if [[ "${WRIT_PROVE_TOLERATE_BLOCKED_HOST_LISTENER:-0}" == "1" ]]; then
  writ_require_reachable_host_listener log warn_before_setup
else
  writ_require_reachable_host_listener log die_before_setup
fi

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

# Protocol v2: the helper validates every session against the pools and
# broker-port range in its root-owned policy file, not against arguments. The
# file must name this proof's pools, or every install the runner asks for is
# refused.
log "checking the PF helper's policy file matches this proof's pools and port range"
PREFLIGHT="$(sudo "$HELPER" preflight)" \
  || die "PF helper preflight failed; install /etc/writ/agent-vm-pf-policy.json (see docs/user_facing/getting-started.md) with ipv4_pool=${IPV4_POOL} ipv6_pool=${IPV6_POOL} broker_port_min=${BROKER_PORT_MIN} broker_port_max=${BROKER_PORT_MAX}"
EXPECTED_POLICY="\"policy\":{\"ipv4_pool\":\"${IPV4_POOL}\",\"ipv6_pool\":\"${IPV6_POOL}\",\"broker_port_min\":${BROKER_PORT_MIN},\"broker_port_max\":${BROKER_PORT_MAX}}"
printf '%s' "$PREFLIGHT" | grep -Fq "$EXPECTED_POLICY" \
  || die "PF helper policy file does not match this proof: expected ${EXPECTED_POLICY} in ${PREFLIGHT}"
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
  -- sh -c 'printf lifecycle-released >/tmp/writ-agent-vm-released; while :; do sleep 600; done' \
  | tee "$START_OUTPUT"

grep -Fxq "session_id=${SESSION_ID}" "$START_OUTPUT" || die "runner did not print expected session ID"
grep -Fxq "network=${NETWORK_NAME}" "$START_OUTPUT" || die "runner did not print expected network"
grep -Fxq "vm=${VM_NAME}" "$START_OUTPUT" || die "runner did not print expected VM"
grep -Fxq "broker_url=http://${IPV4_GATEWAY}:${BROKER_PORT}/" "$START_OUTPUT" || \
  die "runner did not print expected broker URL"

wait_for_released_guest_command

# The IPv4-only launch drops CAP_NET_RAW (the default set never holds
# CAP_NET_ADMIN): without either, the workload cannot forge an out-of-subnet
# IPv4 source. The attached anchor below would block such a frame anyway (its
# rules are interface-scoped, not source-scoped); the capability drop is the
# sender-side half of the same boundary.
assert_released_workload_lacks_net_admin_and_net_raw

expect_guest_success \
  "guest has required probe tools" \
  'command -v ip >/dev/null && command -v wget >/dev/null && command -v nslookup >/dev/null'

assert_guest_has_no_routable_ipv6

# The attached anchor must be on the agent VM's bridge and members before the
# guest command was ever released.
assert_pf_anchor_is_interface_scoped

GUEST_IPV4="$(guest_ipv4_addr)"
if [[ -z "$GUEST_IPV4" ]]; then
  die "could not determine guest IPv4 address"
fi
log "guest IPv4 address is ${GUEST_IPV4}"

BROKER_URL="http://${IPV4_GATEWAY}:${BROKER_PORT}/broker.txt"
FORBIDDEN_URL="http://${IPV4_GATEWAY}:${FORBIDDEN_PORT}/forbidden.txt"

assert_broker_reachable

assert_forbidden_ipv4_egress_counted

expect_guest_blocked \
  "VM cannot reach direct IPv4 internet" \
  "wget -q -T 3 -O - 'http://1.1.1.1/'"

expect_guest_blocked \
  "VM cannot reach direct external DNS" \
  "nslookup github.com 1.1.1.1 >/dev/null"

# Adversarial: closes the exact P1 — a root guest re-enabling IPv6 post-release.
# The kernel-line disable makes that re-enable impossible in the guest, so this
# asserts irreversibility; the host PF IPv6 deny remains as defence in depth.
assert_guest_ipv6_disable_is_irreversible

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
if (( BROKER_REACH_WAIVED == 1 )); then
  log "runner lifecycle proof INCOMPLETE for ${IPV4_CIDR}: the positive control (broker reachable) was waived under WRIT_PROVE_TOLERATE_BLOCKED_HOST_LISTENER=1 because a host socket filter blocked this proof's broker listener; every other leg passed: workload holds neither NET_ADMIN nor NET_RAW, session anchor interface-scoped, forbidden host port blocked and counted by the IPv4 interface deny, IPv6 posture proven, the guest kernel disable of IPv6 is irreversible from a root guest, and runner cleanup verified"
  exit 2
fi
log "runner lifecycle proof succeeded for ${IPV4_CIDR}; workload holds neither NET_ADMIN nor NET_RAW, session anchor interface-scoped, broker reachable, forbidden host port blocked and counted by the IPv4 interface deny, IPv6 posture proven, the guest kernel disable of IPv6 is irreversible from a root guest, and runner cleanup verified"
