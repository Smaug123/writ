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

# The interface-scoped IPv4 deny is live on the guest's actual path: a TCP
# connect from the guest to a host port that is not the broker's must be
# blocked by that rule and counted by it. The guest's exit code is not the
# oracle (see assert_reenabled_ipv6_egress_blocked); the host's deny-rule
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

assert_reenabled_ipv6_egress_blocked() {
  log "assert: a root guest that re-enables IPv6 still cannot egress it"
  # A real IPv6 packet probe is mandatory: without one this assertion could pass
  # vacuously (a tool that fails before sending returns non-zero, which looks
  # "blocked") and so could not detect a nonfunctional PF rule. The sender is
  # busybox wget (required of the image above), which needs no capability. The
  # released workload holds no CAP_NET_RAW, and `container exec` inherits that,
  # so busybox ping/ping6 — a raw ICMP socket with no SOCK_DGRAM fallback —
  # would die before sending anything; it cannot be the sender.
  # Undo the in-guest disable exactly as a malicious agent would, then nudge the
  # link so a fresh RA is solicited.
  guest '
    for s in all default eth0; do
      printf 0 > /proc/sys/net/ipv6/conf/$s/disable_ipv6 2>/dev/null || true
      printf 2 > /proc/sys/net/ipv6/conf/$s/accept_ra 2>/dev/null || true
    done
    ip link set eth0 down 2>/dev/null || true
    ip link set eth0 up 2>/dev/null || true
  ' || true
  sleep 4
  log "guest IPv6 state after re-enabling:"
  guest 'ip -6 -o addr show; ip -6 route show' || true
  # There must be an IPv6 target to probe. The RA restores a default route via the
  # host bridge; ping that. Fail the proof (not pass) if no route came back, so a
  # vacuous "nothing to send" can never masquerade as "blocked".
  local gw
  gw="$(guest 'ip -6 route show default 2>/dev/null | awk "{print \$3}" | head -n1' | tr -d "[:space:]")"
  [ -n "$gw" ] \
    || die "guest reacquired no IPv6 default route after re-enabling; cannot send a routed IPv6 probe to prove the deny (investigate RA timing)"
  # A link-local gateway (the RA's source) needs the zone of the link it came
  # in on; a global one does not.
  local target="$gw"
  if [[ "$gw" == fe80:* ]]; then
    target="${gw}%eth0"
  fi
  local before
  before="$(pf_iface_deny_packets inet6)"
  log "probing IPv6 egress to reacquired gateway ${gw} (deny counter before: ${before})"
  # A TCP connect over IPv6 to the host bridge. The guest's exit code is not the
  # oracle: with `block return` PF answers with a reset, and with no deny the
  # gateway has no IPv6 listener on that port either, so wget fails both ways.
  # The oracle is the host's deny-rule packet counter: it moves iff an IPv6
  # frame from the guest reached PF on the bridge and was blocked by exactly
  # that rule (the connect's SYN, or the neighbour solicitation that precedes
  # it). A probe that sends nothing leaves it unchanged and fails the proof.
  # Residual window: the guest kernel's own solicitations after the re-enable
  # can also hit the deny between the two readings, so a moving counter is
  # proof that PF blocks the guest's IPv6 on this bridge rather than proof
  # that it was wget's frame specifically.
  expect_guest_blocked \
    "re-enabled guest IPv6 egress to the host bridge is refused" \
    "wget -q -T 3 -O /dev/null 'http://[${target}]:${BROKER_PORT}/broker.txt'"
  local after
  after="$(pf_iface_deny_packets inet6)"
  log "deny counter after: ${after}"
  if (( after <= before )); then
    die "the host IPv6 interface deny counted no packet during the guest's probe (before=${before}, after=${after}); the probe sent nothing, or PF did not see it on the bridge"
  fi
  log "pass: host PF blocked $((after - before)) IPv6 packet(s) from the re-enabled guest"
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

expect_guest_success \
  "VM can reach broker port through host-only gateway" \
  "wget -q -T 3 -O - '$BROKER_URL' | grep -q '^broker-ok$'"

assert_forbidden_ipv4_egress_counted

expect_guest_blocked \
  "VM cannot reach direct IPv4 internet" \
  "wget -q -T 3 -O - 'http://1.1.1.1/'"

expect_guest_blocked \
  "VM cannot reach direct external DNS" \
  "nslookup github.com 1.1.1.1 >/dev/null"

# Adversarial: closes the exact P1 — a root guest re-enabling IPv6 post-release.
assert_reenabled_ipv6_egress_blocked

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
log "runner lifecycle proof succeeded for ${IPV4_CIDR}; workload holds neither NET_ADMIN nor NET_RAW, session anchor interface-scoped, broker reachable, forbidden host port blocked and counted by the IPv4 interface deny, IPv6 posture proven, host IPv6 interface deny holds against a re-enabling root guest, and runner cleanup verified"
