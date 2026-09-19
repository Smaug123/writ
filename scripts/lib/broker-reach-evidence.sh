# shellcheck shell=bash
#
# Pure classification of a failed broker-reachability probe.
#
# The proof harnesses stand a host HTTP listener up and assert that a guest VM
# can reach it through the host-only gateway. That assertion is the positive
# control: the one connection the PF session anchor must pass. When it fails,
# the question is *where* the request died, and the answer decides whether the
# anchor is implicated:
#
#   - PF dropped it              -> the anchor (or the pool/port wiring) is wrong
#   - PF passed it, but the
#     listening process never
#     saw the request            -> a host socket filter ate it above PF
#   - anything else              -> inconclusive; a human reads the evidence
#
# The middle case is the macOS Application Firewall (ALF, `socketfilterfw`)
# blocking the listener's binary: a blocked binary still completes the TCP
# handshake and the kernel ACKs the request, then the filter detaches the
# socket before `accept()` hands it over, so `recv` fails with ENOTCONN and the
# process never sees a byte. Loopback is exempt from ALF, which is why the
# harness's own loopback control request is logged while the guest's is not.
# See docs/vmnet-accept-bug-and-broker-vm-plan.md (whose original vmnet
# root-cause is superseded by the correction at its head).
#
# These functions take values and return values so they can be tested without
# a VM, a host listener, or PF: see scripts/test-proof-helpers.sh.

# writ_tcp_state_pair_phase <state-pair>
#
# Classifies the `<src-state>:<dst-state>` pair that `pfctl -ss` prints as the
# last field of a state's tuple line. Prints one of:
#
#   pre-handshake    at least one endpoint has not completed the 3-way
#                    handshake, so a SYN to a dead port or a half-open
#                    connection cannot be ruled out
#   post-handshake   at least one endpoint is in a phase only reachable after
#                    the handshake completed, and neither is pre-handshake
#   indeterminate    neither of the above; notably TIME_WAIT:TIME_WAIT, which a
#                    reset can also leave behind
writ_tcp_state_pair_phase() {
  local pair="${1-}"
  local a="${pair%%:*}"
  local b="${pair##*:}"
  local pre_re='^(SYN_SENT|SYN_RCVD|CLOSED|NO_TRAFFIC)$'
  local post_re='^(ESTABLISHED|FIN_WAIT_1|FIN_WAIT_2|CLOSING|CLOSE_WAIT|LAST_ACK)$'

  if [[ -z "$pair" || "$pair" != *:* ]]; then
    printf 'indeterminate\n'
    return 0
  fi
  if [[ "$a" =~ $pre_re || "$b" =~ $pre_re ]]; then
    printf 'pre-handshake\n'
    return 0
  fi
  if [[ "$a" =~ $post_re || "$b" =~ $post_re ]]; then
    printf 'post-handshake\n'
    return 0
  fi
  printf 'indeterminate\n'
}

# writ_listener_detached_for_peer <peer-ip>
#
# Reads a python `http.server` log on stdin and prints 1 if that listener
# reported a not-connected socket *for this peer*, 0 otherwise.
#
# The correlation matters. http.server frames each failed request as a block:
#
#   ----------------------------------------
#   Exception occurred during processing of request from ('10.0.0.9', 51234)
#   Traceback (most recent call last):
#     ...
#   OSError: [Errno 57] Socket is not connected
#   ----------------------------------------
#
# The harness's listener binds 0.0.0.0, so anything that can route to this host
# can produce one of these. A traceback naming some other peer says nothing about
# the guest's request, and treating it as the guest's witness would waive a real
# guest failure — the one direction of error that must not happen here. So the
# peer and the error have to appear in the *same* block.
writ_listener_detached_for_peer() {
  local peer="${1-}"
  if [[ -z "$peer" ]]; then
    printf '0\n'
    return 0
  fi
  # The trailing quote and comma in the needle stop 192.168.252.2 from matching a
  # block belonging to 192.168.252.22.
  awk -v needle="('${peer}'," '
    /^-+$/ { in_peer_block = 0; next }
    /^Exception occurred during processing of request from / {
      in_peer_block = (index($0, needle) > 0)
      next
    }
    in_peer_block && (index($0, "Socket is not connected") > 0 \
      || index($0, "Errno 57") > 0) { found = 1 }
    END { print (found ? 1 : 0) }
  '
}

# writ_classify_broker_reach_evidence <pass-packets> <pass-states> <deny-packets> \
#     <loopback-logged> <guest-logged> <state-pair> <listener-detached>
#
# All arguments are read on the host after the probe failed:
#   pass-packets/pass-states  delta on the anchor's broker pass rule
#   deny-packets              delta on the anchor's interface-scoped IPv4 deny
#   loopback-logged/guest-logged  1 if the listener logged that request
#   state-pair                TCP phases from the host's PF state, or "" if none
#   listener-detached         1 if the listener reported a not-connected socket
#                             (ENOTCONN) while serving the guest
#
# Prints exactly one verdict:
#   pf-dropped                    PF counted the probe on a deny rule
#   listener-never-saw-request    PF passed it; the process never read it
#   inconclusive                  anything else
writ_classify_broker_reach_evidence() {
  local pass_packets="${1-0}"
  local pass_states="${2-0}"
  local deny_packets="${3-0}"
  local loopback_logged="${4-0}"
  local guest_logged="${5-0}"
  local state_pair="${6-}"
  local listener_detached="${7-0}"

  if (( deny_packets > 0 )); then
    printf 'pf-dropped\n'
    return 0
  fi

  # The handshake must be known to have completed: either the host's PF state
  # still shows a post-handshake phase, or the listening process itself
  # reported a detached socket, which it can only do after accept() returned,
  # which only happens once the handshake completed. The second witness is why
  # TIME_WAIT:TIME_WAIT is no longer fatal to the diagnosis: by the time a
  # short probe has failed and been graded, both ends may have closed.
  local phase
  phase="$(writ_tcp_state_pair_phase "$state_pair")"
  local handshake_completed=0
  if [[ "$phase" == post-handshake ]]; then
    handshake_completed=1
  elif [[ "$phase" != pre-handshake ]] && (( listener_detached == 1 )); then
    handshake_completed=1
  fi

  if (( pass_packets > 0 && pass_states > 0 \
    && loopback_logged == 1 && guest_logged == 0 \
    && handshake_completed == 1 )); then
    printf 'listener-never-saw-request\n'
    return 0
  fi

  printf 'inconclusive\n'
}
