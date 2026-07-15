#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/prove-agent-vm-claude-proxy.sh

Manual proof harness for daemon-managed Claude inside an agent VM, brokered
through the VM HTTP Claude reverse proxy.

Requires:
  - macOS with Apple container installed and `container system start` already run
  - root privileges through sudo for pfctl
  - a top-level PF rule in /etc/pf.conf: anchor "writ/session/*"
  - python3, curl, git, sqlite3, sudo, cargo or the Nix dev shell, and either
    Nix substitutes/builders for the guest image closure or a preloaded image
    containing sh, ip, git, nix, writ-vm, and claude
  - one of WRIT_PROVE_CLAUDE_CODE_OAUTH_TOKEN, CLAUDE_CODE_OAUTH_TOKEN,
    WRIT_PROVE_ANTHROPIC_API_KEY, or ANTHROPIC_API_KEY in the host environment

What it proves:
  - writd starts a daemon-managed agent VM through `writ agent run`
  - the VM fetches its prompt through the authenticated broker route
  - `writ-vm` invokes:
      claude --bare --print --model haiku --effort low --output-format text
  - the VM points Claude at the broker, not directly at Anthropic
  - the broker strips guest auth, injects the host-side Anthropic credential,
    proxies `/v1/messages`, and records Claude proxy audit rows
  - the VM uploads retained stdout/stderr outcome artifacts to the broker
  - the retained stdout artifact starts with `Hello`
  - daemon stop removes the VM, network, PF anchor, and state record

The GitHub API and Git origin are local fakes. The Anthropic call is real by
default; the key is written only to the temporary host secret store and is
unset before writd or the CLI are started.

Environment overrides:
  WRIT_PROVE_CLAUDE_CODE_OAUTH_TOKEN  Host Anthropic OAuth token, preferred over
                                      every other credential source
  CLAUDE_CODE_OAUTH_TOKEN  Host Anthropic OAuth token, used if no
                           WRIT_PROVE_CLAUDE_CODE_OAUTH_TOKEN is set
  WRIT_PROVE_ANTHROPIC_API_KEY  Host Anthropic API key, used if no OAuth
                                token is provided; preferred over
                                ANTHROPIC_API_KEY
  WRIT_PROVE_IMAGE       OCI image to run, default writ-agent-vm-guest:latest
  WRIT_PROVE_BUILD_GUEST_IMAGE  build/load the Nix guest image, default auto
                                (auto builds unless WRIT_PROVE_IMAGE is set)
                                false/no/off/0 use a preloaded image
  WRIT_PROVE_GUEST_SYSTEM  Nix guest image target system, default host-derived
                           aarch64-linux or x86_64-linux
  WRIT_PROVE_IPV4_POOL   broker-owned IPv4 pool, default 192.168.0.0/16
  WRIT_PROVE_IPV6_POOL   broker-owned IPv6 pool, default fd83:b6f2:e57::/48
  WRIT_PROVE_SUBNET_INDEX  session subnet index, default 252
  WRIT_PROVE_BROKER_PORT_MIN  minimum allowed broker port, default 49152
  WRIT_PROVE_BROKER_PORT_MAX  maximum allowed broker port, default 65535
  WRIT_PROVE_CLAUDE_UPSTREAM  Claude upstream base URL, default
                              https://api.anthropic.com
  WRIT_PROVE_WARM        agent workspace warm mode, default none
  WRIT_PROVE_TIMEOUT_SECS  outcome polling timeout, default 600
EOF
}

log() {
  printf '[prove-claude-proxy] %s\n' "$*"
}

die() {
  printf '[prove-claude-proxy] error: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/writ-claude-proxy-proof.XXXXXX")"
chmod 700 "$TMP_DIR"

if [[ -n "${WRIT_PROVE_IMAGE:-}" ]]; then
  IMAGE="$WRIT_PROVE_IMAGE"
  BUILD_GUEST_IMAGE="${WRIT_PROVE_BUILD_GUEST_IMAGE:-0}"
else
  IMAGE="writ-agent-vm-guest:latest"
  BUILD_GUEST_IMAGE="${WRIT_PROVE_BUILD_GUEST_IMAGE:-auto}"
fi
IPV4_POOL="${WRIT_PROVE_IPV4_POOL:-192.168.0.0/16}"
IPV6_POOL="${WRIT_PROVE_IPV6_POOL:-fd83:b6f2:e57::/48}"
SUBNET_INDEX="${WRIT_PROVE_SUBNET_INDEX:-252}"
BROKER_PORT_MIN="${WRIT_PROVE_BROKER_PORT_MIN:-49152}"
BROKER_PORT_MAX="${WRIT_PROVE_BROKER_PORT_MAX:-65535}"
CLAUDE_UPSTREAM="${WRIT_PROVE_CLAUDE_UPSTREAM:-https://api.anthropic.com}"
WARM="${WRIT_PROVE_WARM:-none}"
TIMEOUT_SECS="${WRIT_PROVE_TIMEOUT_SECS:-600}"
PROMPT="Testing: please say anything starting with the word 'Hello'"
PROOF_OWNER="proof-owner"
PROOF_REPO="proof-repo"
PROOF_REPO_FULL="${PROOF_OWNER}/${PROOF_REPO}"
PROOF_TOKEN="ghs_claude_proxy_proof_token"
PROOF_BUNDLE_MARKER="fake-git-bundle-for-claude-proxy-proof"

CONFIG_FILE="${TMP_DIR}/writd-config.json"
SOCKET_PATH="${TMP_DIR}/writd.sock"
AUDIT_DB="${TMP_DIR}/audit/audit.db"  # dedicated dir: the broker VM mounts the audit DB's parent read-write
STATE_DIR="${TMP_DIR}/state"
SECRETS_DIR="${TMP_DIR}/secrets"
GIT_WORK_ROOT="${TMP_DIR}/git-work"
AGENT_RUN_LOG_ROOT="${TMP_DIR}/agent-run-logs"
FAKE_GIT_ORIGIN_ROOT="${TMP_DIR}/fake-git-origin"
FAKE_GIT_ORIGIN_SOURCE="${TMP_DIR}/fake-git-origin-source"
FAKE_GITHUB_SCRIPT="${TMP_DIR}/fake-github.py"
FAKE_GIT_ORIGIN_SCRIPT="${TMP_DIR}/fake-git-origin.py"
FAKE_ASKPASS="${TMP_DIR}/fake-askpass"
FAKE_ASKPASS_LOG="${TMP_DIR}/fake-askpass.log"
FAKE_GITHUB_LOG="${TMP_DIR}/fake-github.log"
FAKE_GIT_ORIGIN_LOG="${TMP_DIR}/fake-git-origin.log"
WRITD_LOG="${TMP_DIR}/writd.log"
RUN_OUTPUT="${TMP_DIR}/agent-run.txt"

CARGO_CMD=()
REAL_GIT=""
WRIT_BIN=""
WRITD_BIN=""
HELPER=""
FAKE_GITHUB_PORT=""
FAKE_GITHUB_PID=""
FAKE_GIT_ORIGIN_PORT=""
FAKE_GIT_ORIGIN_PID=""
WRITD_PID=""
SESSION_ID=""
RUN_ID=""
NETWORK_NAME=""
VM_NAME=""
PF_ANCHOR=""
IPV4_CIDR=""
STDOUT_PATH=""
STDERR_PATH=""
STOP_DONE=0
cleanup_started=0

dump_log() {
  local label="$1"
  local path="$2"
  if [[ -s "$path" ]]; then
    printf '\n[prove-claude-proxy] ==== %s: %s ====\n' "$label" "$path" >&2
    sed -n '1,240p' "$path" >&2 || true
  fi
}

dump_audit_summary() {
  if [[ ! -s "$AUDIT_DB" ]]; then
    return
  fi
  printf '\n[prove-claude-proxy] ==== audit summary: %s ====\n' "$AUDIT_DB" >&2
  sqlite3 "$AUDIT_DB" \
    "SELECT run_id, status, exit_code, stdout_path, stderr_path FROM agent_run_outcome;" \
    >&2 || true
  sqlite3 "$AUDIT_DB" \
    "SELECT route, decision, deny_reason, http_status, upstream_status, error
       FROM claude_proxy_request
       LEFT JOIN claude_proxy_outcome USING (request_id);" \
    >&2 || true
}

dump_diagnostics() {
  printf '\n[prove-claude-proxy] diagnostics for failed run under %s\n' "$TMP_DIR" >&2
  dump_log "writd log" "$WRITD_LOG"
  dump_log "fake GitHub log" "$FAKE_GITHUB_LOG"
  dump_log "fake Git origin log" "$FAKE_GIT_ORIGIN_LOG"
  dump_log "fake askpass log" "$FAKE_ASKPASS_LOG"
  dump_log "agent run output" "$RUN_OUTPUT"
  if [[ -n "$STDOUT_PATH" ]]; then
    dump_log "agent stdout artifact" "$STDOUT_PATH"
  fi
  if [[ -n "$STDERR_PATH" ]]; then
    dump_log "agent stderr artifact" "$STDERR_PATH"
  fi
  dump_audit_summary
  if [[ -d "$STATE_DIR" ]]; then
    printf '\n[prove-claude-proxy] ==== state records: %s ====\n' "$STATE_DIR" >&2
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
  if [[ -n "$FAKE_GIT_ORIGIN_PID" ]]; then
    kill "$FAKE_GIT_ORIGIN_PID" >/dev/null 2>&1 || true
    wait "$FAKE_GIT_ORIGIN_PID" 2>/dev/null || true
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

choose_real_git() {
  REAL_GIT="$(command -v git || true)"
  [[ -n "$REAL_GIT" ]] || die "missing required command: git"
}

default_guest_system() {
  case "$(uname -m)" in
    arm64|aarch64)
      printf 'aarch64-linux\n'
      ;;
    x86_64|amd64)
      printf 'x86_64-linux\n'
      ;;
    *)
      die "unsupported host architecture for default guest image: $(uname -m)"
      ;;
  esac
}

load_guest_image() {
  case "$BUILD_GUEST_IMAGE" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      log "using preloaded guest image ${IMAGE}"
      return
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|auto|AUTO|Auto)
      ;;
    *)
      die "WRIT_PROVE_BUILD_GUEST_IMAGE must be auto, true/false, yes/no, on/off, or 1/0"
      ;;
  esac

  require_cmd nix
  local guest_system
  guest_system="${WRIT_PROVE_GUEST_SYSTEM:-$(default_guest_system)}"
  local image_attr="agent-vm-guest-image-${guest_system}"

  log "building guest OCI image ${IMAGE} from .#${image_attr}"
  local image_archive
  image_archive="$(cd "$ROOT_DIR" && nix build --no-link --print-out-paths ".#${image_attr}")" || \
    die "failed to build guest OCI image .#${image_attr}"

  log "loading guest OCI image ${IMAGE} into Apple container"
  container image load --input "$image_archive" >/dev/null || \
    die "failed to load guest OCI image archive ${image_archive}"
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

shell_quote() {
  printf "'"
  printf "%s" "$1" | sed "s/'/'\\\\''/g"
  printf "'"
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

write_fake_askpass() {
  local log_path
  log_path="$(shell_quote "$FAKE_ASKPASS_LOG")"
  cat >"$FAKE_ASKPASS" <<EOF
#!/bin/sh
set -eu
prompt="\${1:-}"
printf 'prompt=%s\n' "\$prompt" >> ${log_path}
case "\$prompt" in
  *Username*) printf 'x-access-token\n' ;;
  *Password*) printf '%s\n' "\${WRIT_GIT_TOKEN:?missing WRIT_GIT_TOKEN for git askpass}" ;;
  *) printf 'unexpected askpass prompt: %s\n' "\$prompt" >&2; exit 1 ;;
esac
EOF
  chmod 700 "$FAKE_ASKPASS"
}

prepare_fake_git_origin() {
  mkdir -p "${FAKE_GIT_ORIGIN_ROOT}/${PROOF_OWNER}"
  "$REAL_GIT" -C "$TMP_DIR" init "$FAKE_GIT_ORIGIN_SOURCE" >/dev/null
  "$REAL_GIT" -C "$FAKE_GIT_ORIGIN_SOURCE" config user.email proof@example.com
  "$REAL_GIT" -C "$FAKE_GIT_ORIGIN_SOURCE" config user.name 'writ proof'
  "$REAL_GIT" -C "$FAKE_GIT_ORIGIN_SOURCE" config commit.gpgsign false
  printf '%s\n' "$PROOF_BUNDLE_MARKER" > "${FAKE_GIT_ORIGIN_SOURCE}/README.md"
  "$REAL_GIT" -C "$FAKE_GIT_ORIGIN_SOURCE" add README.md
  GIT_AUTHOR_DATE='2001-01-01T00:00:00Z' \
    GIT_COMMITTER_DATE='2001-01-01T00:00:00Z' \
    "$REAL_GIT" -C "$FAKE_GIT_ORIGIN_SOURCE" commit -m 'proof bundle' >/dev/null
  "$REAL_GIT" -C "$FAKE_GIT_ORIGIN_SOURCE" branch -M main
  "$REAL_GIT" clone --bare \
    "$FAKE_GIT_ORIGIN_SOURCE" \
    "${FAKE_GIT_ORIGIN_ROOT}/${PROOF_OWNER}/${PROOF_REPO}.git" >/dev/null
  "$REAL_GIT" -C "${FAKE_GIT_ORIGIN_ROOT}/${PROOF_OWNER}/${PROOF_REPO}.git" \
    update-server-info
}

write_fake_git_origin_server() {
  cat >"$FAKE_GIT_ORIGIN_SCRIPT" <<'PY'
import base64
import http.server
import subprocess
import sys
import urllib.parse

PORT = int(sys.argv[1])
PROJECT_ROOT = sys.argv[2]
TOKEN = sys.argv[3]
GIT = sys.argv[4]
EXPECTED_AUTH = "Basic " + base64.b64encode(
    f"x-access-token:{TOKEN}".encode()
).decode()

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(fmt % args, flush=True)

    def _send(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _authorized(self):
        return self.headers.get("Authorization", "") == EXPECTED_AUTH

    def _challenge(self):
        print(f"auth=denied path={self.path}", flush=True)
        self._send(
            401,
            b"auth required\n",
            [("WWW-Authenticate", 'Basic realm="writ-proof-git"')],
        )

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self._handle_git()

    def do_POST(self):
        self._handle_git()

    def _handle_git(self):
        if self.path == "/health":
            self._send(200, b"ok\n")
            return
        if not self._authorized():
            self._challenge()
            return

        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length)
        print(f"auth=ok method={self.command} path={parsed.path}", flush=True)

        env = {
            "GIT_PROJECT_ROOT": PROJECT_ROOT,
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": parsed.path,
            "QUERY_STRING": parsed.query,
            "REQUEST_METHOD": self.command,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(length),
            "REMOTE_USER": "x-access-token",
        }
        proc = subprocess.run(
            [GIT, "http-backend"],
            input=body,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )
        if proc.stderr:
            sys.stderr.buffer.write(proc.stderr)
            sys.stderr.flush()
        if proc.returncode != 0:
            self._send(500, b"git http-backend failed\n")
            return

        raw = proc.stdout
        marker = b"\r\n\r\n"
        if marker in raw:
            header_bytes, response_body = raw.split(marker, 1)
        elif b"\n\n" in raw:
            header_bytes, response_body = raw.split(b"\n\n", 1)
        else:
            self._send(500, b"git http-backend returned malformed CGI response\n")
            return

        status = 200
        headers = []
        for line in header_bytes.replace(b"\r\n", b"\n").split(b"\n"):
            if not line:
                continue
            name, value = line.decode("iso-8859-1").split(":", 1)
            value = value.strip()
            if name.lower() == "status":
                status = int(value.split(" ", 1)[0])
            elif name.lower() == "content-length":
                continue
            else:
                headers.append((name, value))
        self._send(status, response_body, headers)

server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
server.serve_forever()
PY
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
    "$REAL_GIT" \
    "$FAKE_GIT_ORIGIN_PORT" \
    "$FAKE_ASKPASS" \
    "$GIT_WORK_ROOT" \
    "$FAKE_GITHUB_PORT" \
    "$PROOF_OWNER" \
    "$CLAUDE_UPSTREAM" \
    "$AGENT_RUN_LOG_ROOT" \
    "$CRED_SECRET_NAME" \
    "$CRED_KIND" <<'PY'
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
    real_git,
    fake_git_origin_port,
    fake_askpass,
    git_work_root,
    fake_github_port,
    owner,
    claude_upstream,
    agent_run_log_root,
    cred_secret_name,
    cred_kind,
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
            "git_program": real_git,
            "git_clone_base_url": f"http://127.0.0.1:{fake_git_origin_port}",
            "askpass_program": fake_askpass,
            "token_env": "WRIT_GIT_TOKEN",
            "work_root": git_work_root,
            "clone_timeout_secs": 10,
            "max_bundle_bytes": 1048576,
            "nix_cache_url": "https://cache.nixos.org",
            "nix_cache_trusted_public_keys": [],
            "nix_cache_max_metadata_bytes": 1048576,
            "nix_cache_max_nar_bytes": 67108864,
            "claude_proxy": {
                "upstream_base_url": claude_upstream,
                "auth_secret": cred_secret_name,
                "auth_kind": cred_kind,
                "anthropic_version": "2023-06-01",
                "timeout_secs": 60,
                "max_request_bytes": 2097152,
                "max_response_bytes": 8388608,
            },
            "agent_run_log_root": agent_run_log_root,
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

start_fake_git_origin() {
  FAKE_GIT_ORIGIN_PORT="$(pick_port)"
  write_fake_git_origin_server
  python3 "$FAKE_GIT_ORIGIN_SCRIPT" \
    "$FAKE_GIT_ORIGIN_PORT" \
    "$FAKE_GIT_ORIGIN_ROOT" \
    "$PROOF_TOKEN" \
    "$REAL_GIT" \
    >"$FAKE_GIT_ORIGIN_LOG" 2>&1 &
  FAKE_GIT_ORIGIN_PID="$!"
  for _ in {1..50}; do
    if curl --silent --fail --max-time 1 "http://127.0.0.1:${FAKE_GIT_ORIGIN_PORT}/health" \
      >/dev/null 2>&1; then
      return
    fi
    sleep 0.1
  done
  die "fake Git origin did not start on port ${FAKE_GIT_ORIGIN_PORT}"
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

wait_for_agent_outcome() {
  local deadline=$((SECONDS + TIMEOUT_SECS))
  local row=""
  while [[ "$SECONDS" -lt "$deadline" ]]; do
    row="$(sqlite3 -separator $'\t' "$AUDIT_DB" \
      "SELECT status, exit_code, stdout_path, stderr_path
         FROM agent_run_outcome
        WHERE run_id = '${RUN_ID}';" 2>/dev/null || true)"
    if [[ -n "$row" ]]; then
      IFS=$'\t' read -r OUTCOME_STATUS OUTCOME_EXIT STDOUT_PATH STDERR_PATH <<<"$row"
      return
    fi
    if [[ -n "$WRITD_PID" ]] && ! kill -0 "$WRITD_PID" >/dev/null 2>&1; then
      cat "$WRITD_LOG" >&2 || true
      die "writd exited before the agent outcome was recorded"
    fi
    sleep 2
  done
  die "timed out waiting ${TIMEOUT_SECS}s for agent run outcome ${RUN_ID}"
}

assert_stdout_starts_with_hello() {
  [[ "$OUTCOME_STATUS" == "succeeded" ]] || \
    die "agent run status was ${OUTCOME_STATUS}, expected succeeded; stderr artifact: ${STDERR_PATH}"
  [[ "$OUTCOME_EXIT" == "0" ]] || \
    die "agent run exit code was ${OUTCOME_EXIT}, expected 0; stderr artifact: ${STDERR_PATH}"
  [[ -f "$STDOUT_PATH" ]] || die "stdout artifact was not materialized: ${STDOUT_PATH}"

  local prefix
  prefix="$(LC_ALL=C head -c 5 "$STDOUT_PATH")"
  if [[ "$prefix" != "Hello" ]]; then
    dump_log "agent stdout artifact" "$STDOUT_PATH"
    dump_log "agent stderr artifact" "$STDERR_PATH"
    die "stdout artifact does not start with Hello"
  fi
}

assert_claude_proxy_audit() {
  local proxy_count
  proxy_count="$(sqlite3 "$AUDIT_DB" \
    "SELECT COUNT(*)
       FROM claude_proxy_request r
       JOIN claude_proxy_outcome o USING (request_id)
      WHERE r.session_id = '${SESSION_ID}'
        AND r.route = 'messages'
        AND r.decision = 'allow'
        AND o.upstream_status BETWEEN 200 AND 299;")"
  [[ "$proxy_count" -gt 0 ]] || \
    die "audit log does not show a successful proxied Claude messages request"

  local denied_count
  denied_count="$(sqlite3 "$AUDIT_DB" \
    "SELECT COUNT(*)
       FROM claude_proxy_request
      WHERE session_id = '${SESSION_ID}'
        AND decision = 'deny';")"
  [[ "$denied_count" -eq 0 ]] || \
    die "audit log shows denied Claude proxy requests for session ${SESSION_ID}"
}

assert_real_git_origin_used_cleanly() {
  if ! grep -Fq "auth=ok method=GET path=/${PROOF_REPO_FULL}.git/info/refs" "$FAKE_GIT_ORIGIN_LOG"; then
    die "fake Git origin log does not show the expected info/refs request"
  fi
  if ! grep -Fq "auth=ok method=POST path=/${PROOF_REPO_FULL}.git/git-upload-pack" "$FAKE_GIT_ORIGIN_LOG"; then
    die "fake Git origin log does not show the expected upload-pack request"
  fi
  if ! grep -Fq "Username" "$FAKE_ASKPASS_LOG"; then
    die "askpass log does not show a username prompt from host Git"
  fi
  if ! grep -Fq "Password" "$FAKE_ASKPASS_LOG"; then
    die "askpass log does not show a password prompt from host Git"
  fi
  if grep -Fq "$PROOF_TOKEN" "$FAKE_GIT_ORIGIN_LOG" "$FAKE_ASKPASS_LOG"; then
    die "host Git proof logs leaked the proof token"
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

assert_state_removed() {
  if [[ -e "${STATE_DIR}/${SESSION_ID}.json" ]]; then
    die "managed state record still exists after daemon stop: ${STATE_DIR}/${SESSION_ID}.json"
  fi
}

require_cmd container
require_cmd curl
require_cmd git
require_cmd python3
require_cmd sqlite3
require_cmd sudo
choose_cargo
choose_real_git

case "$WARM" in
  none|sources|devshell) ;;
  *) die "WRIT_PROVE_WARM must be none, sources, or devshell" ;;
esac

case "$TIMEOUT_SECS" in
  ''|*[!0-9]*) die "WRIT_PROVE_TIMEOUT_SECS must be a positive integer" ;;
esac
[[ "$TIMEOUT_SECS" -gt 0 ]] || die "WRIT_PROVE_TIMEOUT_SECS must be positive"

CLAUDE_OAUTH_TOKEN_VALUE="${WRIT_PROVE_CLAUDE_CODE_OAUTH_TOKEN:-${CLAUDE_CODE_OAUTH_TOKEN:-}}"
ANTHROPIC_API_KEY_VALUE="${WRIT_PROVE_ANTHROPIC_API_KEY:-${ANTHROPIC_API_KEY:-}}"
if [[ -n "$CLAUDE_OAUTH_TOKEN_VALUE" ]]; then
  CRED_KIND="oauth"
  CRED_SECRET_NAME="anthropic-oauth-token"
  CRED_VALUE="$CLAUDE_OAUTH_TOKEN_VALUE"
elif [[ -n "$ANTHROPIC_API_KEY_VALUE" ]]; then
  CRED_KIND="x_api_key"
  CRED_SECRET_NAME="anthropic-api-key"
  CRED_VALUE="$ANTHROPIC_API_KEY_VALUE"
else
  die "set WRIT_PROVE_CLAUDE_CODE_OAUTH_TOKEN, CLAUDE_CODE_OAUTH_TOKEN, WRIT_PROVE_ANTHROPIC_API_KEY, or ANTHROPIC_API_KEY in the host environment"
fi

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

load_guest_image

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
printf '%s' "$CRED_VALUE" >"${SECRETS_DIR}/${CRED_SECRET_NAME}"
chmod 600 "${SECRETS_DIR}/${CRED_SECRET_NAME}"
unset CRED_VALUE
unset CLAUDE_OAUTH_TOKEN_VALUE
unset ANTHROPIC_API_KEY_VALUE
unset ANTHROPIC_API_KEY || true
unset WRIT_PROVE_ANTHROPIC_API_KEY || true
unset CLAUDE_CODE_OAUTH_TOKEN || true
unset WRIT_PROVE_CLAUDE_CODE_OAUTH_TOKEN || true

write_fake_askpass
prepare_fake_git_origin
start_fake_github
start_fake_git_origin
write_config

log "starting writd with fake GitHub API on port ${FAKE_GITHUB_PORT}, fake Git origin on port ${FAKE_GIT_ORIGIN_PORT}, and Claude upstream ${CLAUDE_UPSTREAM}"
env -u ANTHROPIC_API_KEY -u WRIT_PROVE_ANTHROPIC_API_KEY \
  -u CLAUDE_CODE_OAUTH_TOKEN -u WRIT_PROVE_CLAUDE_CODE_OAUTH_TOKEN \
  "$WRITD_BIN" --config "$CONFIG_FILE" --socket "$SOCKET_PATH" --audit-db "$AUDIT_DB" \
  >"$WRITD_LOG" 2>&1 &
WRITD_PID="$!"
wait_for_writd_socket

log "starting Claude agent run on ${IPV4_CIDR} with --model haiku and --effort low"
if ! env -u ANTHROPIC_API_KEY -u WRIT_PROVE_ANTHROPIC_API_KEY \
  -u CLAUDE_CODE_OAUTH_TOKEN -u WRIT_PROVE_CLAUDE_CODE_OAUTH_TOKEN \
  "$WRIT_BIN" --socket "$SOCKET_PATH" agent run \
    --label "claude proxy proof" \
    --model "haiku" \
    --repo "$PROOF_REPO_FULL" \
    --agent claude \
    --warm "$WARM" \
    --prompt "$PROMPT" >"$RUN_OUTPUT"; then
  cat "$RUN_OUTPUT" >&2 || true
  cat "$WRITD_LOG" >&2 || true
  die "writ agent run failed to start"
fi
cat "$RUN_OUTPUT"

SESSION_ID="$(awk -F= '$1 == "session_id" {print $2}' "$RUN_OUTPUT")"
RUN_ID="$(awk -F= '$1 == "run_id" {print $2}' "$RUN_OUTPUT")"
[[ -n "$SESSION_ID" ]] || die "could not parse session_id from agent run output"
[[ -n "$RUN_ID" ]] || die "could not parse run_id from agent run output"
NETWORK_NAME="writ-agent-net-${SESSION_ID}"
VM_NAME="writ-agent-vm-${SESSION_ID}"
PF_ANCHOR="writ/session/${SESSION_ID}"

wait_for_agent_outcome
assert_stdout_starts_with_hello
assert_claude_proxy_audit
assert_real_git_origin_used_cleanly

log "stopping session through daemon"
"$WRIT_BIN" --socket "$SOCKET_PATH" agent-vm stop "$SESSION_ID"
STOP_DONE=1

assert_container_absent
assert_network_absent
assert_pf_anchor_empty
assert_state_removed

log "Claude proxy proof succeeded for ${IPV4_CIDR}; stdout starts with Hello, Claude proxy audit rows show a successful brokered /v1/messages call, and daemon stop cleanup was verified"
