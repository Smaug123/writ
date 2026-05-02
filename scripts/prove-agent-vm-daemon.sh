#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/prove-agent-vm-daemon.sh

Manual proof harness for daemon-managed agent VM lifecycle and VM HTTP Git clone.

Requires:
  - macOS with Apple container installed and `container system start` already run
  - root privileges through sudo for pfctl
  - a top-level PF rule in /etc/pf.conf: anchor "writ/session/*"
  - python3, curl, cargo or nix, and an Alpine-compatible image with sh, ip,
    wget, and nslookup

What it proves:
  - writd starts an agent VM through the Unix-socket `start_agent_vm` protocol
  - the VM receives WRIT_BROKER_URL and WRIT_BROKER_TOKEN through the daemon
  - the VM can call GET /v1/session on the daemon-owned VM HTTP listener
  - the VM can call POST /v1/git/clone and receive a host-produced bundle
  - `stop_agent_vm` removes the VM, network, PF anchor/states, and state record

The GitHub API and host git binary are local fakes. This keeps the proof focused
on Apple Container/PF/daemon wiring rather than real GitHub availability.

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
  printf '[prove-daemon] %s\n' "$*"
}

die() {
  printf '[prove-daemon] error: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/writ-daemon-proof.XXXXXX")"
chmod 700 "$TMP_DIR"

IMAGE="${WRIT_PROVE_IMAGE:-alpine:latest}"
IPV4_POOL="${WRIT_PROVE_IPV4_POOL:-192.168.0.0/16}"
IPV6_POOL="${WRIT_PROVE_IPV6_POOL:-fd83:b6f2:e57::/48}"
SUBNET_INDEX="${WRIT_PROVE_SUBNET_INDEX:-252}"
BROKER_PORT_MIN="${WRIT_PROVE_BROKER_PORT_MIN:-49152}"
BROKER_PORT_MAX="${WRIT_PROVE_BROKER_PORT_MAX:-65535}"
PROOF_OWNER="proof-owner"
PROOF_REPO="proof-repo"
PROOF_REPO_FULL="${PROOF_OWNER}/${PROOF_REPO}"
PROOF_TOKEN="ghs_daemon_proof_token"
PROOF_BUNDLE_MARKER="fake-git-bundle-from-daemon"

CONFIG_FILE="${TMP_DIR}/writd-config.json"
SOCKET_PATH="${TMP_DIR}/writd.sock"
AUDIT_DB="${TMP_DIR}/audit.db"
STATE_DIR="${TMP_DIR}/state"
SECRETS_DIR="${TMP_DIR}/secrets"
GIT_WORK_ROOT="${TMP_DIR}/git-work"
FAKE_GITHUB_SCRIPT="${TMP_DIR}/fake-github.py"
FAKE_GIT="${TMP_DIR}/fake-git"
FAKE_ASKPASS="${TMP_DIR}/fake-askpass"
FAKE_GIT_ARGS_LOG="${TMP_DIR}/fake-git-args.log"
FAKE_GITHUB_LOG="${TMP_DIR}/fake-github.log"
WRITD_LOG="${TMP_DIR}/writd.log"
START_OUTPUT="${TMP_DIR}/agent-vm-start.txt"

CARGO_CMD=()
WRIT_BIN=""
WRITD_BIN=""
HELPER=""
FAKE_GITHUB_PORT=""
FAKE_GITHUB_PID=""
WRITD_PID=""
SESSION_ID=""
NETWORK_NAME=""
VM_NAME=""
PF_ANCHOR=""
IPV4_CIDR=""
GUEST_IPV4=""
STOP_DONE=0
cleanup_started=0

dump_log() {
  local label="$1"
  local path="$2"
  if [[ -s "$path" ]]; then
    printf '\n[prove-daemon] ==== %s: %s ====\n' "$label" "$path" >&2
    sed -n '1,240p' "$path" >&2 || true
  fi
}

dump_diagnostics() {
  printf '\n[prove-daemon] diagnostics for failed run under %s\n' "$TMP_DIR" >&2
  dump_log "writd log" "$WRITD_LOG"
  dump_log "fake GitHub log" "$FAKE_GITHUB_LOG"
  dump_log "fake git argv log" "$FAKE_GIT_ARGS_LOG"
  dump_log "start output" "$START_OUTPUT"
  if [[ -d "$STATE_DIR" ]]; then
    printf '\n[prove-daemon] ==== state records: %s ====\n' "$STATE_DIR" >&2
    find "$STATE_DIR" -maxdepth 1 -type f -print >&2 || true
  fi
}

cleanup() {
  local status=$?
  if [[ "$cleanup_started" -eq 1 ]]; then
    return
  fi
  cleanup_started=1

  log "cleaning up daemon, VM, network, fake services, and PF anchor"

  if [[ -z "$SESSION_ID" && -d "$STATE_DIR" ]]; then
    local state_file
    state_file="$(find "$STATE_DIR" -maxdepth 1 -name '*.json' -type f -print -quit 2>/dev/null || true)"
    if [[ -n "$state_file" ]]; then
      SESSION_ID="$(basename "$state_file" .json)"
      NETWORK_NAME="writ-agent-net-${SESSION_ID}"
      VM_NAME="writ-agent-vm-${SESSION_ID}"
      PF_ANCHOR="writ/session/${SESSION_ID}"
    fi
  fi

  if [[ "$STOP_DONE" -eq 0 && -n "$SESSION_ID" && -x "$WRIT_BIN" && -S "$SOCKET_PATH" ]]; then
    "$WRIT_BIN" --socket "$SOCKET_PATH" agent-vm stop "$SESSION_ID" >/dev/null 2>&1 || true
  fi

  if [[ -n "$VM_NAME" ]]; then
    container rm -f "$VM_NAME" >/dev/null 2>&1 || true
    container stop "$VM_NAME" >/dev/null 2>&1 || true
    container delete "$VM_NAME" >/dev/null 2>&1 || true
    container rm "$VM_NAME" >/dev/null 2>&1 || true
  fi

  if [[ -n "$HELPER" && -x "$HELPER" && -n "$SESSION_ID" && -n "$IPV4_CIDR" ]]; then
    sudo "$HELPER" remove \
      --session-id "$SESSION_ID" \
      --ipv4-pool "$IPV4_POOL" \
      --ipv6-pool "$IPV6_POOL" \
      --ipv4-cidr "$IPV4_CIDR" >/dev/null 2>&1 || true
  fi

  if [[ -n "$NETWORK_NAME" ]]; then
    container network rm "$NETWORK_NAME" >/dev/null 2>&1 || \
      container network delete "$NETWORK_NAME" >/dev/null 2>&1 || true
  fi

  if [[ -n "$WRITD_PID" ]]; then
    kill "$WRITD_PID" >/dev/null 2>&1 || true
    wait "$WRITD_PID" 2>/dev/null || true
  fi
  if [[ -n "$FAKE_GITHUB_PID" ]]; then
    kill "$FAKE_GITHUB_PID" >/dev/null 2>&1 || true
    wait "$FAKE_GITHUB_PID" 2>/dev/null || true
  fi

  if [[ "$status" -ne 0 ]]; then
    dump_diagnostics
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

pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
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

write_fake_github_server() {
  cat >"$FAKE_GITHUB_SCRIPT" <<'PY'
import datetime
import http.server
import json
import sys

PORT = int(sys.argv[1])
OWNER = sys.argv[2]
REPO = sys.argv[3]
TOKEN = sys.argv[4]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(fmt % args, flush=True)

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        if self.path != "/app/installations/999/access_tokens":
            self.send_response(404)
            self.end_headers()
            return
        expires = (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=3600)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        body = {
            "token": TOKEN,
            "expires_at": expires,
            "permissions": {"contents": "read", "metadata": "read"},
            "repository_selection": "selected",
            "repositories": [{"full_name": f"{OWNER}/{REPO}"}],
        }
        encoded = json.dumps(body).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
server.serve_forever()
PY
}

write_fake_git() {
  cat >"$FAKE_GIT" <<EOF
#!/bin/sh
set -eu
printf '%s\n' "\$*" >> '$(printf "%s" "$FAKE_GIT_ARGS_LOG" | sed "s/'/'\\\\''/g")'

case " \$* " in
  *" clone "*)
    if [ "\${WRIT_GIT_TOKEN:-}" != "$PROOF_TOKEN" ]; then
      printf 'missing expected git token env\n' >&2
      exit 23
    fi
    mirror_dir=""
    for arg in "\$@"; do
      mirror_dir="\$arg"
    done
    /bin/mkdir -p "\$mirror_dir"
    exit 0
    ;;
  *" bundle create "*)
    bundle_path=""
    previous=""
    for arg in "\$@"; do
      if [ "\$previous" = "--" ]; then
        bundle_path="\$arg"
        break
      fi
      previous="\$arg"
    done
    if [ -z "\$bundle_path" ]; then
      printf 'missing bundle path\n' >&2
      exit 24
    fi
    printf '%s\n' "$PROOF_BUNDLE_MARKER" > "\$bundle_path"
    exit 0
    ;;
  *)
    printf 'unexpected fake git invocation: %s\n' "\$*" >&2
    exit 25
    ;;
esac
EOF
  chmod 700 "$FAKE_GIT"

  cat >"$FAKE_ASKPASS" <<'EOF'
#!/bin/sh
printf 'x-access-token\n'
EOF
  chmod 700 "$FAKE_ASKPASS"
}

write_config() {
  python3 - "$CONFIG_FILE" \
    "$SOCKET_PATH" \
    "$AUDIT_DB" \
    "$SECRETS_DIR" \
    "$STATE_DIR" \
    "$IPV4_POOL" \
    "$IPV6_POOL" \
    "$SUBNET_INDEX" \
    "$IMAGE" \
    "$HELPER" \
    "$BROKER_PORT_MIN" \
    "$BROKER_PORT_MAX" \
    "$FAKE_GIT" \
    "$FAKE_ASKPASS" \
    "$GIT_WORK_ROOT" \
    "$FAKE_GITHUB_PORT" \
    "$PROOF_OWNER" <<'PY'
import json
import sys

(
    config_path,
    socket_path,
    audit_db,
    secrets_dir,
    state_dir,
    ipv4_pool,
    ipv6_pool,
    subnet_index,
    image,
    helper,
    broker_port_min,
    broker_port_max,
    fake_git,
    fake_askpass,
    git_work_root,
    fake_github_port,
    owner,
) = sys.argv[1:]

config = {
    "github": {
        "app_id": 42,
        "installation_id": 999,
        "installation_owner": owner,
        "private_key_secret": "gh-app-pk",
        "api_base": f"http://127.0.0.1:{fake_github_port}",
    },
    "policy": {"default_ttl": 3600, "writable_repos": []},
    "secret_store": {"type": "file", "path": secrets_dir},
    "socket_path": socket_path,
    "audit_db": audit_db,
    "agent_vm": {
        "lifecycle": {
            "ipv4_pool": ipv4_pool,
            "ipv6_pool": ipv6_pool,
            "subnet_index_min": int(subnet_index),
            "subnet_index_max": int(subnet_index),
            "container": "container",
            "sudo": "sudo",
            "pf_helper": helper,
            "state_dir": state_dir,
            "ipv6_mode": "ipv4_only_no_guest_ipv6",
            "image": image,
            "cpus": 1,
            "memory_mib": 512,
        },
        "vm_http": {
            "bind_addr": "0.0.0.0",
            "broker_port_min": int(broker_port_min),
            "broker_port_max": int(broker_port_max),
            "git_program": fake_git,
            "askpass_program": fake_askpass,
            "token_env": "WRIT_GIT_TOKEN",
            "work_root": git_work_root,
            "clone_timeout_secs": 10,
            "max_bundle_bytes": 1048576,
        },
    },
}

with open(config_path, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
PY
}

start_fake_github() {
  FAKE_GITHUB_PORT="$(pick_port)"
  write_fake_github_server
  python3 "$FAKE_GITHUB_SCRIPT" "$FAKE_GITHUB_PORT" "$PROOF_OWNER" "$PROOF_REPO" "$PROOF_TOKEN" \
    >"$FAKE_GITHUB_LOG" 2>&1 &
  FAKE_GITHUB_PID="$!"
  for _ in {1..50}; do
    if curl --silent --fail --max-time 1 "http://127.0.0.1:${FAKE_GITHUB_PORT}/health" \
      >/dev/null 2>&1; then
      return
    fi
    sleep 0.1
  done
  die "fake GitHub API did not start on port ${FAKE_GITHUB_PORT}"
}

wait_for_writd_socket() {
  for _ in {1..100}; do
    if [[ -S "$SOCKET_PATH" ]]; then
      return
    fi
    if [[ -n "$WRITD_PID" ]] && ! kill -0 "$WRITD_PID" >/dev/null 2>&1; then
      cat "$WRITD_LOG" >&2 || true
      die "writd exited before creating its socket"
    fi
    sleep 0.1
  done
  cat "$WRITD_LOG" >&2 || true
  die "writd did not create its socket at ${SOCKET_PATH}"
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

wait_for_released_guest_command() {
  log "assert: daemon-started guest command is running"
  for _ in {1..50}; do
    if guest 'test "$(cat /tmp/writ-agent-vm-daemon-released 2>/dev/null)" = daemon-released' \
      >/dev/null 2>&1; then
      log "pass: daemon-started guest command is running"
      return
    fi
    sleep 0.1
  done
  die "daemon-started guest command did not write its marker"
}

guest_ipv4_addr() {
  guest "ip -4 -o addr show scope global | awk '{print \$4}' | head -n 1 | cut -d/ -f1"
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

assert_fake_git_used_cleanly() {
  if ! grep -Fq "clone --mirror -- https://github.com/${PROOF_REPO_FULL}.git" "$FAKE_GIT_ARGS_LOG"; then
    die "fake git log does not show the expected clone URL"
  fi
  if ! grep -Fq "bundle create --" "$FAKE_GIT_ARGS_LOG"; then
    die "fake git log does not show bundle creation"
  fi
  if grep -Fq "$PROOF_TOKEN" "$FAKE_GIT_ARGS_LOG"; then
    die "fake git argv log leaked the proof token"
  fi
}

container_list_contains() {
  local name="$1"
  local listed
  listed="$(container list --all --quiet 2>/dev/null)" || \
    die "could not list containers after daemon stop"
  grep -Fxq "$name" <<<"$listed"
}

network_list_contains() {
  local name="$1"
  local listed
  listed="$(container network list --quiet 2>/dev/null)" || \
    die "could not list networks after daemon stop"
  grep -Fxq "$name" <<<"$listed"
}

assert_container_absent() {
  if container_list_contains "$VM_NAME"; then
    die "VM still exists after daemon stop: ${VM_NAME}"
  fi
}

assert_network_absent() {
  if network_list_contains "$NETWORK_NAME"; then
    die "network still exists after daemon stop: ${NETWORK_NAME}"
  fi
}

assert_pf_anchor_empty() {
  if sudo pfctl -a "$PF_ANCHOR" -sr 2>/dev/null | grep -q '[^[:space:]]'; then
    die "PF anchor still contains rules after daemon stop: ${PF_ANCHOR}"
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

assert_state_removed() {
  if [[ -e "${STATE_DIR}/${SESSION_ID}.json" ]]; then
    die "managed state record still exists after daemon stop: ${STATE_DIR}/${SESSION_ID}.json"
  fi
}

require_cmd container
require_cmd curl
require_cmd python3
require_cmd sudo
choose_cargo

IPV4_CIDR="$(cidr_alloc_subnet "$IPV4_POOL" 24 "$SUBNET_INDEX")"

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

log "building daemon, CLI, and PF helper"
(
  cd "$ROOT_DIR"
  "${CARGO_CMD[@]}" build --bin writ --bin writd --bin writ-agent-vm-pf-helper >/dev/null
)
WRIT_BIN="${ROOT_DIR}/target/debug/writ"
WRITD_BIN="${ROOT_DIR}/target/debug/writd"
HELPER="${ROOT_DIR}/target/debug/writ-agent-vm-pf-helper"
[[ -x "$WRIT_BIN" ]] || die "writ binary was not built at ${WRIT_BIN}"
[[ -x "$WRITD_BIN" ]] || die "writd binary was not built at ${WRITD_BIN}"
[[ -x "$HELPER" ]] || die "PF helper was not built at ${HELPER}"

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"
cp "${ROOT_DIR}/tests/fixtures/rsa_test_1.pem" "${SECRETS_DIR}/gh-app-pk"
chmod 600 "${SECRETS_DIR}/gh-app-pk"

write_fake_git
start_fake_github
write_config

log "starting writd with fake GitHub API on port ${FAKE_GITHUB_PORT}"
"$WRITD_BIN" --config "$CONFIG_FILE" --socket "$SOCKET_PATH" --audit-db "$AUDIT_DB" \
  >"$WRITD_LOG" 2>&1 &
WRITD_PID="$!"
wait_for_writd_socket

log "starting daemon-managed VM on ${IPV4_CIDR}"
if ! "$WRIT_BIN" --socket "$SOCKET_PATH" agent-vm start \
  --label "daemon proof" \
  --model "proof" \
  -- sh -lc 'printf daemon-released >/tmp/writ-agent-vm-daemon-released; sleep 600' \
  >"$START_OUTPUT"; then
  cat "$START_OUTPUT" >&2 || true
  cat "$WRITD_LOG" >&2 || true
  die "writ agent-vm start failed"
fi
cat "$START_OUTPUT"

SESSION_ID="$(awk -F= '$1 == "session_id" {print $2}' "$START_OUTPUT")"
[[ -n "$SESSION_ID" ]] || die "could not parse session_id from daemon start output"
NETWORK_NAME="writ-agent-net-${SESSION_ID}"
VM_NAME="writ-agent-vm-${SESSION_ID}"
PF_ANCHOR="writ/session/${SESSION_ID}"

wait_for_released_guest_command
expect_guest_success "guest has required probe tools" \
  'command -v ip >/dev/null && command -v wget >/dev/null && command -v nslookup >/dev/null'
assert_guest_has_no_routable_ipv6

GUEST_IPV4="$(guest_ipv4_addr)"
[[ -n "$GUEST_IPV4" ]] || die "could not determine guest IPv4 address"
log "guest IPv4 address is ${GUEST_IPV4}"

expect_guest_success "guest sees daemon-injected broker URL and token" \
  'test -n "$WRIT_BROKER_URL" && test -n "$WRIT_BROKER_TOKEN"'
expect_guest_success "VM can call daemon VM HTTP session endpoint" \
  'wget -q -O - --header "Authorization: Bearer $WRIT_BROKER_TOKEN" "${WRIT_BROKER_URL}v1/session" | grep -q "\"api\":\"writ-vm-http\""'
expect_guest_success "VM can request a host-produced Git bundle through daemon VM HTTP" \
  "wget -q -O /tmp/writ-agent-vm-daemon.bundle \
    --header \"Authorization: Bearer \${WRIT_BROKER_TOKEN}\" \
    --header 'Content-Type: application/json' \
    --post-data '{\"repo\":\"${PROOF_REPO_FULL}\"}' \
    \"\${WRIT_BROKER_URL}v1/git/clone\" && \
    grep -Fxq '${PROOF_BUNDLE_MARKER}' /tmp/writ-agent-vm-daemon.bundle"
assert_fake_git_used_cleanly

log "stopping session through daemon"
"$WRIT_BIN" --socket "$SOCKET_PATH" agent-vm stop "$SESSION_ID"
STOP_DONE=1

assert_container_absent
assert_network_absent
assert_pf_anchor_empty
assert_no_pf_state_for_guest
assert_state_removed

log "daemon lifecycle proof succeeded for ${IPV4_CIDR}; VM HTTP session and Git clone route worked, and daemon stop cleanup was verified"
