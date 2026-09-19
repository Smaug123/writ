# shellcheck shell=bash
#
# Preflight for the proof harnesses that stand a host HTTP listener up and
# expect a guest VM to reach it over a host-only network.
#
# On macOS the Application Firewall (ALF, `socketfilterfw`) filters *incoming*
# connections per binary, and loopback is exempt. A blocked binary therefore
# looks healthy to every loopback readiness check the harness does, and fails
# only for the guest: the kernel completes the handshake and ACKs the request,
# then ALF detaches the socket before `accept()` hands it over, so `recv` fails
# with ENOTCONN and the process never sees a byte. The harnesses' listener is
# `python3 -m http.server`, so the binary in question is whichever interpreter
# `python3` resolves to — which on a nix host is a store path that gets its own
# firewall entry, blocked by default, and a fresh one on every version bump.
#
# That failure used to surface minutes later as a mystifying broker-reach
# failure, after a build, a sudo prompt, a PF anchor, and a VM boot. This probe
# reproduces it in about a second, with no VM, no PF, and no sudo: serve a
# sentinel on 0.0.0.0, fetch it over loopback (which ALF exempts) and then over
# a real interface address (which it does not). Loopback yes plus off-loopback
# no is the signature.
#
# The probe speaks only to this host, so it proves nothing about PF, the
# bridge, or the guest — that is the proof's own job. It rules out exactly one
# class of failure, the one that is invisible until a guest tries.

WRIT_ALF_TOOL="${WRIT_ALF_TOOL:-/usr/libexec/ApplicationFirewall/socketfilterfw}"

# writ_resolve_python_listener_binary
#
# Prints the binary that will own the listening socket. This is deliberately
# not `command -v python3`: on this host /usr/bin/python3 is Apple's
# xcode_select tool shim (one of 78 hardlinks to the same file, alongside
# /usr/bin/clang and /usr/bin/git), which execs `$(xcode-select -p)/usr/bin/
# xcrun`, which resolves python3 off PATH. The interpreter that ends up holding
# the socket can therefore be several hops from the name that was typed, and
# the firewall judges the interpreter. Asking the interpreter itself is the only
# reliable answer.
writ_resolve_python_listener_binary() {
  python3 -c 'import os, sys; print(os.path.realpath(sys.executable))' 2>/dev/null
}

# writ_alf_verdict <binary>
#
# Prints the firewall's own words about that binary, or a note that the
# firewall tool is absent (this is macOS-only, and the harnesses are too).
# Needs no privileges.
writ_alf_verdict() {
  local binary="${1-}"
  if [[ ! -x "$WRIT_ALF_TOOL" ]]; then
    printf 'no firewall tool at %s (not macOS?)\n' "$WRIT_ALF_TOOL"
    return 1
  fi
  "$WRIT_ALF_TOOL" --getappblocked "$binary" 2>&1 || true
}

# writ_probe_host_listener_offloopback
#
# Prints findings on stdout. Returns:
#   0  a host listener is reachable on a non-loopback address
#   1  it is not; the findings name the cause and the remedy
#   2  the probe could not run (no non-loopback IPv4 address to test against),
#      so the caller should warn and carry on rather than fail
writ_probe_host_listener_offloopback() (
  local iface addr port dir token server_pid=0 log_file ready=0

  iface="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')"
  if [[ -z "$iface" ]]; then
    printf 'no default route, so there is no non-loopback address to probe\n'
    return 2
  fi
  addr="$(ifconfig "$iface" 2>/dev/null | awk '$1 == "inet" {print $2; exit}')"
  if [[ -z "$addr" ]]; then
    printf 'default-route interface %s has no IPv4 address to probe\n' "$iface"
    return 2
  fi

  dir="$(mktemp -d "${TMPDIR:-/tmp}/writ-listener-probe.XXXXXX")" || {
    printf 'could not create a temporary directory for the probe\n'
    return 2
  }
  # shellcheck disable=SC2064  # $dir and $server_pid are wanted as they are now
  trap "rm -rf -- '$dir'; [[ \$server_pid -gt 0 ]] && kill \$server_pid 2>/dev/null; true" EXIT

  # A random token, so a stray server on the same port cannot fake a pass.
  token="writ-listener-probe-$(( RANDOM ))-$(date +%s)"
  printf '%s\n' "$token" >"${dir}/probe.txt"
  log_file="${dir}/server.log"

  port="$(python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()' 2>/dev/null)"
  if [[ -z "$port" ]]; then
    printf 'could not pick a free port with python3\n'
    return 2
  fi

  # Bound to 0.0.0.0, exactly as the harnesses bind it, for about a second.
  python3 -m http.server "$port" --bind 0.0.0.0 --directory "$dir" \
    >"$log_file" 2>&1 &
  server_pid=$!

  local _
  for _ in {1..50}; do
    if curl --silent --fail --noproxy '*' --max-time 1 \
      "http://127.0.0.1:${port}/probe.txt" 2>/dev/null | grep -Fqx "$token"; then
      ready=1
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  if (( ready == 0 )); then
    printf 'the probe listener never served its own loopback request on port %s\n' "$port"
    printf 'python3 -m http.server is broken here, so the proof cannot stand a broker up:\n'
    sed 's/^/  /' "$log_file" 2>/dev/null || true
    return 1
  fi

  # --noproxy '*' on both requests: curl otherwise honours http_proxy/ALL_PROXY,
  # and a no_proxy that covers only localhost would send this one through a proxy
  # that cannot reach a private address — failing a perfectly healthy listener.
  if curl --silent --fail --noproxy '*' --max-time 3 \
    "http://${addr}:${port}/probe.txt" 2>/dev/null | grep -Fqx "$token"; then
    printf 'a host listener on %s:%s is reachable off-loopback\n' "$addr" "$port"
    return 0
  fi

  # Loopback served, a real interface address did not. Name the binary, ask the
  # firewall about it, and look for the fingerprint in the listener's own log.
  local binary verdict
  binary="$(writ_resolve_python_listener_binary)"
  verdict="$(writ_alf_verdict "$binary")"
  printf 'a host listener served 127.0.0.1:%s but not %s:%s (same process, same socket)\n' \
    "$port" "$addr" "$port"
  printf 'listener binary (the process that owns the socket): %s\n' "${binary:-unknown}"
  printf 'macOS firewall says: %s\n' "$verdict"
  if grep -Fq 'Socket is not connected' "$log_file" 2>/dev/null; then
    printf 'the listener reported a not-connected socket (ENOTCONN) for that request:\n'
    printf '  a socket filter completed the handshake and then detached the socket\n'
  fi
  printf 'a guest VM reaches this host over a real interface, never loopback, so the\n'
  printf 'broker-reach leg of this proof cannot pass while that holds.\n'
  if [[ "$verdict" == *blocked* ]]; then
    printf 'remedy (one command, then re-run this proof):\n'
    printf '  sudo %s --unblockapp %q\n' "$WRIT_ALF_TOOL" "$binary"
    printf 'note that a nix store path changes on every version bump, and each new\n'
    printf 'path is a fresh firewall entry that starts out blocked.\n'
  else
    printf 'the firewall does not report that binary as blocked, so something else is\n'
    printf 'dropping it: check PF for rules covering %s, and any other socket filter.\n' "$iface"
  fi
  return 1
)

# writ_require_reachable_host_listener <log-fn> <die-fn>
#
# Wraps the probe in the caller's own reporting. The caller passes the names of
# its `log` and `die` functions rather than the library assuming they exist,
# because each harness prefixes its output differently.
#
# <die-fn> decides whether an unreachable listener is fatal: if it exits, the run
# stops here; if it returns, this function returns 0 and the run continues. That
# is deliberate, and it is how a harness honours a waiver — a fatal preflight
# would make an opt-in "carry on past a blocked listener" knob unreachable, since
# the run would die before it got to the leg that implements the waiver.
writ_require_reachable_host_listener() {
  local log_fn="$1" die_fn="$2"
  local findings probe_status=0

  "$log_fn" "preflight: a host listener is reachable off-loopback (no VM needed)"
  findings="$(writ_probe_host_listener_offloopback)" || probe_status=$?
  case "$probe_status" in
    0)
      "$log_fn" "pass: ${findings}"
      ;;
    2)
      "$log_fn" "warning: skipping the host-listener preflight: ${findings}"
      "$log_fn" "warning: a firewall-blocked listener will now surface later, as a broker-reach failure"
      ;;
    *)
      while IFS= read -r line; do
        "$log_fn" "  ${line}"
      done <<<"$findings"
      "$die_fn" "host listener is not reachable off-loopback; see the findings above"
      ;;
  esac
}
