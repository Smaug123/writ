#!/usr/bin/env bash
set -Eeuo pipefail

# Unit tests for the pure helpers the proof harnesses share.
#
# The harnesses themselves need real hardware: a macOS host, Apple container,
# sudo, PF. The *classification* of their evidence is pure string logic, so it
# is tested here instead, on any machine, in milliseconds. That matters because
# a misclassification is silent: it does not fail a proof, it explains one
# wrongly, and a wrong explanation sends a human off to debug the wrong
# subsystem.
#
# Usage: scripts/test-proof-helpers.sh [path-to-broker-reach-evidence.sh]

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_LIB="${1:-${ROOT_DIR}/scripts/lib/broker-reach-evidence.sh}"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/broker-reach-evidence.sh
source "$EVIDENCE_LIB"

FAILURES=0
CHECKS=0

check() {
  local label="$1" expected="$2" actual="$3"
  CHECKS=$((CHECKS + 1))
  if [[ "$actual" == "$expected" ]]; then
    printf '  ok    %s\n' "$label"
  else
    printf '  FAIL  %s\n         expected %q, got %q\n' "$label" "$expected" "$actual"
    FAILURES=$((FAILURES + 1))
  fi
}

check_phase() {
  local pair="$1" expected="$2"
  check "state pair ${pair:-<none>} is ${expected}" \
    "$expected" "$(writ_tcp_state_pair_phase "$pair")"
}

# check_verdict <label> <expected> [key=value ...]
# Defaults describe the waivable signature; each case overrides what it is about.
check_verdict() {
  local label="$1" expected="$2"
  shift 2
  local pass_packets=10 pass_states=1 deny_packets=0
  local loopback_logged=1 guest_logged=0
  local state_pair='ESTABLISHED:FIN_WAIT_2' listener_detached=0
  local kv
  for kv in "$@"; do
    case "$kv" in
      pass_packets=*|pass_states=*|deny_packets=*|loopback_logged=*|guest_logged=*|state_pair=*|listener_detached=*)
        eval "${kv%%=*}=\${kv#*=}"
        ;;
      *) printf 'bad override %q\n' "$kv" >&2; exit 2 ;;
    esac
  done
  check "$label" "$expected" \
    "$(writ_classify_broker_reach_evidence "$pass_packets" "$pass_states" \
      "$deny_packets" "$loopback_logged" "$guest_logged" "$state_pair" \
      "$listener_detached")"
}

printf 'writ_tcp_state_pair_phase\n'
check_phase 'ESTABLISHED:ESTABLISHED' post-handshake
check_phase 'ESTABLISHED:FIN_WAIT_2' post-handshake
check_phase 'FIN_WAIT_2:TIME_WAIT' post-handshake
check_phase 'TIME_WAIT:TIME_WAIT' indeterminate
check_phase 'SYN_SENT:CLOSED' pre-handshake
check_phase 'SYN_SENT:ESTABLISHED' pre-handshake
check_phase 'NO_TRAFFIC:NO_TRAFFIC' pre-handshake
check_phase '' indeterminate
check_phase 'garbage' indeterminate

printf 'writ_classify_broker_reach_evidence\n'

# The signature originally captured on this host: the state still showed a
# post-handshake phase when the failure was graded.
check_verdict 'post-handshake state, no process witness: blocked listener' \
  listener-never-saw-request

# The 2026-09-19 run: same cause, but both ends had closed by grading time, so
# the PF state alone was inconclusive and the listener's own ENOTCONN is the
# witness that accept() had happened.
check_verdict 'TIME_WAIT pair with an ENOTCONN witness: blocked listener' \
  listener-never-saw-request state_pair='TIME_WAIT:TIME_WAIT' listener_detached=1

# Without that witness a bare TIME_WAIT pair stays inconclusive: a reset can
# leave a reset-adjacent state, so it is not evidence the handshake completed.
check_verdict 'TIME_WAIT pair with no witness: inconclusive' \
  inconclusive state_pair='TIME_WAIT:TIME_WAIT'

# A half-open connection is never waived, whatever else is true: an ENOTCONN
# from some earlier request must not launder a SYN that was never answered.
check_verdict 'half-open state, even with a witness: inconclusive' \
  inconclusive state_pair='SYN_SENT:ESTABLISHED' listener_detached=1
check_verdict 'SYN to a dead port: inconclusive' \
  inconclusive state_pair='SYN_SENT:CLOSED'

# PF's own deny counter firing outranks everything: the anchor is implicated,
# which is the opposite conclusion, so it must never be reported as a filter
# above PF.
check_verdict 'deny counter fired: PF dropped it' \
  pf-dropped deny_packets=3
check_verdict 'deny counter fired even with the blocked-listener shape' \
  pf-dropped deny_packets=1 state_pair='TIME_WAIT:TIME_WAIT' listener_detached=1

# The remaining shapes are different failures, not a blocked listener.
check_verdict 'guest request was served: inconclusive' \
  inconclusive guest_logged=1
check_verdict 'loopback control never logged: inconclusive' \
  inconclusive loopback_logged=0
check_verdict 'PF pass rule counted nothing: inconclusive' \
  inconclusive pass_packets=0
check_verdict 'PF pass rule made no state: inconclusive' \
  inconclusive pass_states=0

# No PF state survived to grading time, but the process reported a detached
# socket while serving the guest: that witness stands on its own.
check_verdict 'no PF state but an ENOTCONN witness: blocked listener' \
  listener-never-saw-request state_pair='' listener_detached=1
check_verdict 'no PF state and no witness: inconclusive' \
  inconclusive state_pair=''

printf '\n%d check(s), %d failure(s)\n' "$CHECKS" "$FAILURES"
(( FAILURES == 0 )) || exit 1
