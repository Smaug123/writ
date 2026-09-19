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
# Usage: scripts/test-proof-helpers.sh [evidence-lib] [preflight-lib]

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_LIB="${1:-${ROOT_DIR}/scripts/lib/broker-reach-evidence.sh}"
PREFLIGHT_LIB="${2:-${ROOT_DIR}/scripts/lib/host-listener-preflight.sh}"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/broker-reach-evidence.sh
source "$EVIDENCE_LIB"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/host-listener-preflight.sh
source "$PREFLIGHT_LIB"

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

printf 'writ_require_reachable_host_listener\n'

# The probe itself needs a network stack and a spare port, so these stub it and
# test the wrapper's contract instead: which reporter gets called for each
# outcome, and — the part a waiver depends on — whether the run continues when
# the caller's fatal reporter chooses to return rather than exit.
STUB_RC=0
writ_probe_host_listener_offloopback() {
  printf 'stub finding line one\n'
  printf 'stub finding line two\n'
  return "$STUB_RC"
}

REPORTED=""
FATAL_CALLS=0
stub_log() { REPORTED="${REPORTED}log:$1
"; }
stub_die_returns() { FATAL_CALLS=$((FATAL_CALLS + 1)); REPORTED="${REPORTED}fatal:$1
"; }
stub_die_exits() { printf 'fatal:%s\n' "$1"; exit 1; }

# Bash 3.2 — stock on macOS, and what this script's shebang resolves to on a
# machine without a newer bash on PATH — misparses an unparenthesised `case`
# pattern inside a command substitution. So substring assertions live in a
# function rather than inline in `$(...)`, and this file stays runnable by the
# oldest bash on any machine that runs the harnesses.
reported_has() {  # <needle>... -> "yes" if $REPORTED contains all of them, in order
  local rest="$REPORTED" needle
  for needle in "$@"; do
    case "$rest" in
      *"$needle"*) rest="${rest#*"$needle"}" ;;
      *) printf '%s\n' "$REPORTED"; return 0 ;;
    esac
  done
  printf 'yes\n'
}

run_wrapper() {  # <probe-rc> <fatal-fn> -> prints the wrapper's own return code
  STUB_RC="$1"
  REPORTED=""
  FATAL_CALLS=0
  local rc=0
  writ_require_reachable_host_listener stub_log "$2" || rc=$?
  printf '%s\n' "$rc"
}

check 'reachable: wrapper returns 0' 0 "$(run_wrapper 0 stub_die_returns)"
run_wrapper 0 stub_die_returns >/dev/null
check 'reachable: nothing fatal is reported' 0 "$FATAL_CALLS"
check 'reachable: the finding is logged as a pass' \
  yes "$(reported_has 'log:pass: stub finding line one')"

check 'untestable: wrapper returns 0' 0 "$(run_wrapper 2 stub_die_returns)"
run_wrapper 2 stub_die_returns >/dev/null
check 'untestable: nothing fatal is reported' 0 "$FATAL_CALLS"
check 'untestable: the skip is warned about' \
  yes "$(reported_has 'log:warning: skipping')"

# A fatal reporter that exits stops the run: the default, so a blocked listener
# costs a second instead of a VM boot.
( run_wrapper 1 stub_die_exits >/dev/null ) >/dev/null 2>&1 && wrapper_rc=0 || wrapper_rc=$?
check 'unreachable with an exiting reporter: the run stops' 1 "$wrapper_rc"

# A fatal reporter that RETURNS lets the run continue. This is the contract the
# lifecycle proof's waiver rides on: WRIT_PROVE_TOLERATE_BLOCKED_HOST_LISTENER=1
# must reach the later legs, which a fatal preflight would make unreachable.
check 'unreachable with a returning reporter: the run continues' \
  0 "$(run_wrapper 1 stub_die_returns)"
run_wrapper 1 stub_die_returns >/dev/null
check 'unreachable: the fatal reporter is called exactly once' 1 "$FATAL_CALLS"
check 'unreachable: every finding line is reported, in order' \
  yes "$(reported_has 'log:  stub finding line one' 'log:  stub finding line two')"

printf '\n%d check(s), %d failure(s)\n' "$CHECKS" "$FAILURES"
(( FAILURES == 0 )) || exit 1
