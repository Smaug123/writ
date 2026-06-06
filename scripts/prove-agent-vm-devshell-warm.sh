#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/prove-agent-vm-devshell-warm.sh

Manual end-to-end proof (FK3e) that a no-egress agent VM can warm a flake
devShell because the broker provisions the flake's locked inputs for it.

Requires:
  - macOS with Apple container installed and `container system start` already run
  - root privileges through sudo for pfctl
  - a top-level PF rule in /etc/pf.conf: anchor "writ/session/*"
  - python3, curl, git, nix, cargo or the Nix dev shell, and either Nix
    substitutes/builders for the guest image closure or a preloaded image
    containing sh, ip, git, nix, and writ-vm
  - HOST network egress to github.com (for `nix flake archive`) and to
    https://cache.nixos.org (for the devShell's output closure). The guest has
    no egress except the broker; that asymmetry is the whole point.

What it proves:
  - writd starts a no-egress agent VM with flake-input provisioning enabled
    (a `(repo, rev)` mirror cache, so the clone handler retains the bare mirror
    the provision endpoint re-derives the checkout from)
  - `writ-vm workspace init --warm devshell` inside the VM clones a fixture repo,
    drives `POST /v1/nix/flake/provision`, and enters `nix develop` — with the
    guest firewalled off github, so the locked inputs can only have come from the
    broker's provisioned, content-addressed cache (served local-first)
  - the guest genuinely cannot reach github (a direct fetch from inside the VM
    fails), so the warm success is attributable to provisioning, not egress
  - the broker recorded a successful `flake_provision` audit row for the session
  - `stop_agent_vm` removes the VM, network, PF anchor/states, and state record

The GitHub App API and the Git origin are local fakes (the fixture repo is
served locally), and the host Git binary clones from that origin through the
production executor. But the flake *inputs* the lock pins are real github
flakes, fetched by the broker's real `nix flake archive`, and the devShell's
output closure substitutes from the real cache.nixos.org through the broker
proxy. This keeps the GitHub-App/clone wiring hermetic while exercising the
genuine flake-input provisioning path end to end.

Environment overrides:
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
EOF
}

log() {
  printf '[prove-devshell] %s\n' "$*"
}

die() {
  printf '[prove-devshell] error: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/writ-devshell-proof.XXXXXX")"
chmod 700 "$TMP_DIR"

# `nix flake lock` (in prepare_fake_git_origin) realises the fixture's input
# *sources*. Keep them out of the shared /nix/store the broker uses, so the
# broker's later `nix flake archive` must fetch them itself — proving its
# egress and the real provisioning path rather than copying paths this harness
# pre-realised. A chroot store's parent must not be a symlink, which on macOS
# rules out $TMPDIR/var; anchor it under $HOME, like prove-flake-offline.sh.
LOCK_STORE_BASE="$(mktemp -d "${HOME}/.writ-devshell-proof.XXXXXX")"
chmod 700 "$LOCK_STORE_BASE"

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
PROOF_OWNER="proof-owner"
PROOF_REPO="proof-repo"
PROOF_REPO_FULL="${PROOF_OWNER}/${PROOF_REPO}"
PROOF_TOKEN="ghs_devshell_proof_token"
# The real cache.nixos.org signing key, so the broker proxy admits the
# devShell's output-closure NARs substituted from the genuine upstream.
CACHE_NIXOS_ORG_URL="https://cache.nixos.org"
CACHE_NIXOS_ORG_KEY="cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
# Real github flakes the fixture's lock pins; the broker's `nix flake archive`
# fetches their sources, and the guest probes one directly as a negative
# control — with the guest firewalled, that fetch must fail.
NIXPKGS_REF="github:NixOS/nixpkgs/nixos-24.11"
FLAKE_UTILS_REF="github:numtide/flake-utils"
GUEST_EGRESS_PROBE_FLAKE="$FLAKE_UTILS_REF"
WORKSPACE_DEST="/tmp/writ-agent-vm-workspace"

CONFIG_FILE="${TMP_DIR}/writd-config.json"
SOCKET_PATH="${TMP_DIR}/writd.sock"
AUDIT_DB="${TMP_DIR}/audit.db"
STATE_DIR="${TMP_DIR}/state"
SECRETS_DIR="${TMP_DIR}/secrets"
GIT_WORK_ROOT="${TMP_DIR}/git-work"
FLAKE_MIRROR_CACHE_DIR="${TMP_DIR}/flake-mirror-cache"
FLAKE_INPUT_CACHE_DIR="${TMP_DIR}/flake-input-cache"
FAKE_GIT_ORIGIN_ROOT="${TMP_DIR}/fake-git-origin"
FAKE_GIT_ORIGIN_SOURCE="${TMP_DIR}/fake-git-origin-source"
FAKE_GITHUB_SCRIPT="${TMP_DIR}/fake-github.py"
FAKE_GIT_ORIGIN_SCRIPT="${TMP_DIR}/fake-git-origin.py"
FAKE_ASKPASS="${TMP_DIR}/fake-askpass"
FAKE_ASKPASS_LOG="${TMP_DIR}/fake-askpass.log"
FAKE_GITHUB_LOG="${TMP_DIR}/fake-github.log"
FAKE_GIT_ORIGIN_LOG="${TMP_DIR}/fake-git-origin.log"
WRITD_LOG="${TMP_DIR}/writd.log"
START_OUTPUT="${TMP_DIR}/agent-vm-start.txt"

CARGO_CMD=()
REAL_GIT=""
REAL_NIX=""
WRIT_BIN=""
WRITD_BIN=""
HELPER=""
FAKE_GITHUB_PORT=""
FAKE_GITHUB_PID=""
FAKE_GIT_ORIGIN_PORT=""
FAKE_GIT_ORIGIN_PID=""
SUDO_KEEPALIVE_PID=""
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
    printf '\n[prove-devshell] ==== %s: %s ====\n' "$label" "$path" >&2
    sed -n '1,240p' "$path" >&2 || true
  fi
}

dump_diagnostics() {
  printf '\n[prove-devshell] diagnostics for failed run under %s\n' "$TMP_DIR" >&2
  dump_log "writd log" "$WRITD_LOG"
  dump_log "fake GitHub log" "$FAKE_GITHUB_LOG"
  dump_log "fake Git origin log" "$FAKE_GIT_ORIGIN_LOG"
  dump_log "fake askpass log" "$FAKE_ASKPASS_LOG"
  dump_log "start output" "$START_OUTPUT"
  if [[ -d "$STATE_DIR" ]]; then
    printf '\n[prove-devshell] ==== state records: %s ====\n' "$STATE_DIR" >&2
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

  if [[ -n "$SUDO_KEEPALIVE_PID" ]]; then
    kill "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1 || true
    wait "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
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
  if [[ -n "$LOCK_STORE_BASE" && -d "$LOCK_STORE_BASE" ]]; then
    # Nix store paths are read-only (0444/0555); make them writable before rm.
    chmod -R u+w "$LOCK_STORE_BASE" 2>/dev/null || true
    rm -rf "$LOCK_STORE_BASE"
  fi
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

choose_real_nix() {
  REAL_NIX="$(command -v nix || true)"
  [[ -n "$REAL_NIX" ]] || die "missing required command: nix"
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
  cat >"$FAKE_ASKPASS" <<EOF
#!/bin/sh
set -eu
prompt="\${1:-}"
printf 'prompt=%s\n' "\$prompt" >> '$(printf "%s" "$FAKE_ASKPASS_LOG" | sed "s/'/'\\\\''/g")'
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

  # A minimal flake whose devShell evaluation needs real github inputs
  # (nixpkgs + flake-utils, plus flake-utils's own `systems` input), but whose
  # output closure (mkShellNoCC) substitutes from cache.nixos.org. `${system}`
  # is escaped so the shell leaves it for Nix; the input refs interpolate.
  cat >"${FAKE_GIT_ORIGIN_SOURCE}/flake.nix" <<EOF
{
  description = "writ flake-input provisioning proof fixture";
  inputs.nixpkgs.url = "${NIXPKGS_REF}";
  inputs.flake-utils.url = "${FLAKE_UTILS_REF}";
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system: {
      devShells.default = nixpkgs.legacyPackages.\${system}.mkShellNoCC { };
    });
}
EOF
  "$REAL_GIT" -C "$FAKE_GIT_ORIGIN_SOURCE" add flake.nix

  # Generate the committed lock on the host (which has github egress); v1
  # provisioning requires a committed flake.lock and provisions exactly it. Run
  # it against an isolated chroot store + cache so the realised input sources do
  # NOT land in the shared /nix/store the broker uses; the lock written to the
  # working tree is store-independent (content-addressed narHash/rev).
  log "locking fixture flake inputs on the host into an isolated store (needs github egress)"
  mkdir -p "${LOCK_STORE_BASE}/home/.cache"
  HOME="${LOCK_STORE_BASE}/home" \
    XDG_CACHE_HOME="${LOCK_STORE_BASE}/home/.cache" \
    "$REAL_NIX" --extra-experimental-features 'nix-command flakes' \
    --store "local?root=${LOCK_STORE_BASE}/store" \
    flake lock "$FAKE_GIT_ORIGIN_SOURCE" >/dev/null 2>&1 || \
    die "nix flake lock failed; the host needs github egress to lock the fixture"
  [[ -f "${FAKE_GIT_ORIGIN_SOURCE}/flake.lock" ]] || \
    die "nix flake lock did not produce a flake.lock"
  "$REAL_GIT" -C "$FAKE_GIT_ORIGIN_SOURCE" add flake.lock

  GIT_AUTHOR_DATE='2001-01-01T00:00:00Z' \
    GIT_COMMITTER_DATE='2001-01-01T00:00:00Z' \
    "$REAL_GIT" -C "$FAKE_GIT_ORIGIN_SOURCE" commit -m 'flake fixture' >/dev/null
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
import os
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
    "$REAL_NIX" \
    "$FAKE_GIT_ORIGIN_PORT" \
    "$FAKE_ASKPASS" \
    "$GIT_WORK_ROOT" \
    "$FAKE_GITHUB_PORT" \
    "$CACHE_NIXOS_ORG_URL" \
    "$CACHE_NIXOS_ORG_KEY" \
    "$FLAKE_MIRROR_CACHE_DIR" \
    "$FLAKE_INPUT_CACHE_DIR" \
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
    real_git,
    real_nix,
    fake_git_origin_port,
    fake_askpass,
    git_work_root,
    fake_github_port,
    cache_url,
    cache_key,
    flake_mirror_cache_dir,
    flake_input_cache_dir,
    owner,
) = sys.argv[1:]

config = {
    # Agent-keyed registry: the session's --agent claude selects this App.
    "github_apps": {
        "claude": {
            "app_id": 42,
            "installation_id": 999,
            "installation_owner": owner,
            "private_key_secret": "gh-app-pk",
            "api_base": f"http://127.0.0.1:{fake_github_port}",
        },
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
            "cpus": 2,
            "memory_mib": 2048,
        },
        "vm_http": {
            "bind_addr": "0.0.0.0",
            "broker_port_min": int(broker_port_min),
            "broker_port_max": int(broker_port_max),
            "git_program": real_git,
            "nix_program": real_nix,
            "git_clone_base_url": f"http://127.0.0.1:{fake_git_origin_port}",
            "askpass_program": fake_askpass,
            "token_env": "WRIT_GIT_TOKEN",
            "work_root": git_work_root,
            "clone_timeout_secs": 60,
            "max_bundle_bytes": 1048576,
            # Real upstream: the broker proxies the genuine cache.nixos.org so
            # the guest can substitute the devShell's output closure, while the
            # flake *inputs* are served local-first from what provisioning
            # archived into flake_input_cache_dir.
            "nix_cache_url": cache_url,
            "nix_cache_trusted_public_keys": [cache_key],
            "nix_cache_max_metadata_bytes": 4194304,
            "nix_cache_max_nar_bytes": 1073741824,
            # Enabling the mirror cache turns on clone-mirror retention AND the
            # /v1/nix/flake/provision endpoint that re-derives from it.
            "flake_mirror_cache_dir": flake_mirror_cache_dir,
            "flake_input_cache_dir": flake_input_cache_dir,
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
  log "assert: the agent command runs after the workspace bootstrap"
  for _ in {1..50}; do
    if guest 'test "$(cat /tmp/writ-agent-vm-devshell-released 2>/dev/null)" = devshell-released' \
      >/dev/null 2>&1; then
      log "pass: the agent command is running after bootstrap"
      return
    fi
    sleep 0.1
  done
  die "the post-bootstrap agent command did not write its marker"
}

guest_ipv4_addr() {
  guest '
    set -- $(ip -4 -o addr show scope global)
    addr="${4:-}"
    test -n "$addr"
    printf "%s\n" "${addr%%/*}"
  '
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

assert_real_git_origin_used_cleanly() {
  if ! grep -Fq "auth=ok method=GET path=/${PROOF_REPO_FULL}.git/info/refs" "$FAKE_GIT_ORIGIN_LOG"; then
    die "fake Git origin log does not show the expected info/refs request"
  fi
  if ! grep -Fq "auth=ok method=POST path=/${PROOF_REPO_FULL}.git/git-upload-pack" "$FAKE_GIT_ORIGIN_LOG"; then
    die "fake Git origin log does not show the expected upload-pack request"
  fi
  # Exactly one fetch must hit the origin: the workspace clone. Provisioning
  # must re-derive its checkout from the retained (repo, rev) mirror, never by
  # re-fetching the origin. A second upload-pack would mean that mirror reuse
  # regressed to a re-clone fallback, which this proof exists to rule out.
  local upload_pack_count
  upload_pack_count="$(grep -Fc "auth=ok method=POST path=/${PROOF_REPO_FULL}.git/git-upload-pack" "$FAKE_GIT_ORIGIN_LOG" || true)"
  if [[ "$upload_pack_count" -ne 1 ]]; then
    die "expected exactly one origin upload-pack (the workspace clone), saw ${upload_pack_count}; provisioning may have re-cloned instead of reusing the retained mirror"
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

assert_flake_provision_audited() {
  log "assert: the broker recorded a successful flake_provision audit row"
  local rows
  rows="$(python3 - "$AUDIT_DB" "$SESSION_ID" <<'PY'
import sqlite3
import sys

audit_db, session_id = sys.argv[1:]
con = sqlite3.connect(audit_db)
try:
    total = con.execute(
        "SELECT count(*) FROM flake_provision_request WHERE session_id = ?",
        (session_id,),
    ).fetchone()[0]
    ok = con.execute(
        "SELECT count(*) FROM flake_provision_outcome o "
        "JOIN flake_provision_request r ON r.request_id = o.request_id "
        "WHERE r.session_id = ? AND o.status = 'success'",
        (session_id,),
    ).fetchone()[0]
finally:
    con.close()
print(f"{total} {ok}")
PY
)" || die "could not query flake_provision audit rows from ${AUDIT_DB}"
  local request_count="${rows%% *}"
  local success_count="${rows##* }"
  if [[ "$request_count" -lt 1 ]]; then
    die "no flake_provision_request row for session ${SESSION_ID}"
  fi
  if [[ "$success_count" -lt 1 ]]; then
    die "no successful flake_provision_outcome row for session ${SESSION_ID} (requests: ${request_count})"
  fi
  log "pass: ${request_count} flake_provision request(s), ${success_count} succeeded"
}

assert_broker_cache_populated() {
  log "assert: provisioning populated the broker-local flake-input cache"
  if ! find "$FLAKE_INPUT_CACHE_DIR" -maxdepth 1 -name '*.narinfo' -type f -print -quit \
    2>/dev/null | grep -q .; then
    die "broker flake-input cache ${FLAKE_INPUT_CACHE_DIR} has no narinfo after provisioning"
  fi
  log "pass: broker flake-input cache holds at least one provisioned narinfo"
}

assert_guest_consumed_provisioned_cache() {
  log "assert: every provisioned flake input the warm requested was served locally, none from upstream"
  # The nix-cache endpoint serves local-first: a 200 served from the local
  # archive records an `upstream_url` naming the `file://` archive, while an
  # upstream proxy records the real cache.nixos.org URL. We cross-reference
  # everything the broker provisioned (both narinfo metadata and NAR bodies)
  # against what the guest requested: at least one provisioned object must have
  # been served locally, and *no* provisioned object may have been served from
  # upstream. The latter is the real guard — it fails if local-first regresses
  # for any input even though that input is also public on cache.nixos.org.
  # (The devShell's own closure legitimately comes from upstream; those objects
  # are not in the local cache, so they are ignored.)
  local result
  result="$(python3 - "$AUDIT_DB" "$SESSION_ID" "$FLAKE_INPUT_CACHE_DIR" <<'PY'
import os
import sqlite3
import sys

audit_db, session_id, cache_dir = sys.argv[1:]

# Every file the broker provisioned, by request basename: the narinfos
# (`<hash>.narinfo`, requested at `.../<hash>.narinfo`) and their NAR bodies
# (`nar/<file>`, requested at `.../nar/<file>`). Matching on basename covers
# both the metadata and the bytes, so a regression that serves the narinfo
# locally but proxies the NAR upstream is still caught.
provisioned = {name for name in os.listdir(cache_dir) if name.endswith(".narinfo")}
nar_dir = os.path.join(cache_dir, "nar")
if os.path.isdir(nar_dir):
    provisioned.update(os.listdir(nar_dir))

con = sqlite3.connect(audit_db)
try:
    rows = con.execute(
        "SELECT r.target, o.http_status, o.upstream_url "
        "FROM nix_cache_outcome o "
        "JOIN nix_cache_request r ON r.request_id = o.request_id "
        "WHERE r.session_id = ?",
        (session_id,),
    ).fetchall()
finally:
    con.close()

local_hits = 0
upstream_leaks = 0
for target, http_status, upstream_url in rows:
    base = (target or "").rsplit("/", 1)[-1]
    if base not in provisioned or http_status != 200:
        continue
    if upstream_url and upstream_url.startswith("file://"):
        local_hits += 1
    elif upstream_url:
        upstream_leaks += 1

print(f"{len(provisioned)} {local_hits} {upstream_leaks}")
PY
)" || die "could not query nix_cache audit rows from ${AUDIT_DB}"
  local provisioned_count="${result%% *}"
  local rest="${result#* }"
  local local_hits="${rest%% *}"
  local upstream_leaks="${rest##* }"
  if [[ "$provisioned_count" -lt 1 ]]; then
    die "no provisioned narinfos in ${FLAKE_INPUT_CACHE_DIR}; provisioning wrote nothing to consume"
  fi
  if [[ "$upstream_leaks" -ne 0 ]]; then
    die "${upstream_leaks} provisioned flake-input path(s) were served from upstream instead of the local cache; local-first serving regressed"
  fi
  if [[ "$local_hits" -lt 1 ]]; then
    die "the warm requested no provisioned flake-input path locally; it may not have consumed the provisioned cache at all"
  fi
  log "pass: ${local_hits} provisioned flake-input request(s) served locally, 0 served from upstream"
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
require_cmd git
require_cmd nix
require_cmd python3
require_cmd sudo
choose_cargo
choose_real_git
choose_real_nix

IPV4_CIDR="$(cidr_alloc_subnet "$IPV4_POOL" 24 "$SUBNET_INDEX")"

log "requesting sudo credentials for pfctl"
sudo -v
# The guest-image build and the in-guest `--warm devshell` bootstrap can run
# well past sudo's default 5-minute timestamp before writd invokes
# `sudo writ-agent-vm-pf-helper` (with stdin closed). Refresh the timestamp in
# the background so those later, non-interactive PF operations still succeed.
( while true; do sudo -n -v >/dev/null 2>&1 || exit; sleep 60; done ) &
SUDO_KEEPALIVE_PID="$!"

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

write_fake_askpass
prepare_fake_git_origin
start_fake_github
start_fake_git_origin
write_config

log "starting writd with fake GitHub API on port ${FAKE_GITHUB_PORT}, fake Git origin on port ${FAKE_GIT_ORIGIN_PORT}, and real upstream Nix cache ${CACHE_NIXOS_ORG_URL}"
"$WRITD_BIN" --config "$CONFIG_FILE" --socket "$SOCKET_PATH" --audit-db "$AUDIT_DB" \
  >"$WRITD_LOG" 2>&1 &
WRITD_PID="$!"
wait_for_writd_socket

# Start with the workspace bootstrap: this is the production warm path. The
# daemon uses the flakes-enabling bootstrap script and, before the agent runs,
# performs `writ-vm workspace init --warm devshell` in-guest (clone, then
# POST /v1/nix/flake/provision, then `nix develop`). The start call BLOCKS
# until that bootstrap reports ok or fails, so a successful return here IS the
# headline assertion: warm succeeded inside the no-egress VM.
log "starting daemon-managed VM on ${IPV4_CIDR} with --warm devshell (clone + provision + nix develop run in-guest before start returns)"
if ! "$WRIT_BIN" --socket "$SOCKET_PATH" agent-vm start \
  --label "devshell warm proof" \
  --agent claude \
  --model "proof" \
  --repo "$PROOF_REPO_FULL" \
  --workspace "$WORKSPACE_DEST" \
  --warm devshell \
  -- sh -lc 'printf devshell-released >/tmp/writ-agent-vm-devshell-released; sleep 600' \
  >"$START_OUTPUT"; then
  cat "$START_OUTPUT" >&2 || true
  cat "$WRITD_LOG" >&2 || true
  die "writ agent-vm start failed (workspace bootstrap / devshell warm did not succeed)"
fi
cat "$START_OUTPUT"
log "pass: no-egress VM completed clone + flake-input provisioning + devshell warm at bootstrap"

SESSION_ID="$(awk -F= '$1 == "session_id" {print $2}' "$START_OUTPUT")"
[[ -n "$SESSION_ID" ]] || die "could not parse session_id from daemon start output"
NETWORK_NAME="writ-agent-net-${SESSION_ID}"
VM_NAME="writ-agent-vm-${SESSION_ID}"
PF_ANCHOR="writ/session/${SESSION_ID}"

wait_for_released_guest_command
expect_guest_success "guest has required probe tools" \
  'command -v sh >/dev/null && command -v ip >/dev/null && command -v git >/dev/null && command -v nix >/dev/null && command -v writ-vm >/dev/null'
expect_guest_success "guest can start Nix CLI without network" \
  'nix_version="$(nix --version)" && test -n "$nix_version"'
assert_guest_has_no_routable_ipv6

GUEST_IPV4="$(guest_ipv4_addr)"
[[ -n "$GUEST_IPV4" ]] || die "could not determine guest IPv4 address"
log "guest IPv4 address is ${GUEST_IPV4}"

expect_guest_success "guest sees daemon-injected broker URL and token" \
  'test -n "$WRIT_BROKER_URL" && test -n "$WRIT_BROKER_TOKEN"'
expect_guest_success "guest sees daemon-written Nix cache auth config" \
  'contains_file() {
     needle="$1"
     file="$2"
     while IFS= read -r line; do
       case "$line" in *"$needle"*) return 0;; esac
     done < "$file"
     return 1
   }
   test -n "$WRIT_NIX_CACHE_URL" && \
    test -n "$WRIT_NIX_NETRC" && \
    test -n "$WRIT_NIX_TRUSTED_PUBLIC_KEYS" && \
    test -n "$NIX_CONF_DIR" && \
    test -f "$WRIT_NIX_NETRC" && \
    test -f "$NIX_CONF_DIR/nix.conf" && \
    contains_file "$WRIT_NIX_TRUSTED_PUBLIC_KEYS" "$NIX_CONF_DIR/nix.conf"'
expect_guest_success "VM can call daemon VM HTTP session endpoint through writ-vm" \
  "session_json=\"\$(writ-vm session)\" && \
    case \"\$session_json\" in *'\"api\": \"writ-vm-http\"'*) ;; *) printf '%s\n' \"\$session_json\"; exit 1;; esac && \
    case \"\$session_json\" in *'\"session_id\": \"${SESSION_ID}\"'*) ;; *) printf '%s\n' \"\$session_json\"; exit 1;; esac"
# Negative control: the guest cannot reach github directly. Targeting the
# `/main` branch forces a live github lookup that the content-addressed
# provisioned cache cannot answer, bounded by an explicit connect timeout with
# no retries so a blackholed connect fails fast. Crucially, the probe must fail
# *for the right reason*: it is only a clean no-egress signal if nix could not
# connect to / resolve github. A success (egress open), an HTTP error like a
# rate limit (egress open but throttled), or any non-network error must NOT be
# mistaken for "no egress", so we capture the output and classify it.
expect_guest_success "guest cannot reach github directly (no egress)" \
  "probe_out=/tmp/writ-egress-probe.out; \
    set +e; \
    nix --extra-experimental-features 'nix-command flakes' \
        --option connect-timeout 5 --option download-attempts 1 \
        flake metadata '${GUEST_EGRESS_PROBE_FLAKE}/main' --refresh \
        > \"\$probe_out\" 2>&1; \
    probe_rc=\$?; \
    set -e; \
    if [ \"\$probe_rc\" -eq 0 ]; then \
      printf 'guest unexpectedly resolved %s from github (egress is open)\n' '${GUEST_EGRESS_PROBE_FLAKE}/main'; \
      cat \"\$probe_out\"; exit 1; \
    fi; \
    if ! grep -qi github \"\$probe_out\"; then \
      printf 'negative-control failure does not mention github; cannot attribute it to no-egress\n'; \
      cat \"\$probe_out\"; exit 1; \
    fi; \
    if ! grep -qiE 'could not resolve|couldn.t resolve|name resolution|temporary failure|network is unreachable|connection refused|connection timed out|timeout was reached|failed to connect|could not connect|no route to host' \"\$probe_out\"; then \
      printf 'negative-control failed for a non-network reason (rate limit, bad ref, or nix config); not a clean no-egress signal\n'; \
      cat \"\$probe_out\"; exit 1; \
    fi"

# The bootstrap already cloned + provisioned + warmed before start returned
# (asserted by the start succeeding). Confirm in-guest that it left the clean
# workspace checkout and signalled bootstrap success.
expect_guest_success "bootstrap left the workspace checkout and an ok marker" \
  "test -f '${WORKSPACE_DEST}/flake.nix' && \
    test -f '${WORKSPACE_DEST}/flake.lock' && \
    test -f /run/writ-agent-vm/bootstrap-ok"

assert_real_git_origin_used_cleanly
assert_flake_provision_audited
assert_broker_cache_populated
assert_guest_consumed_provisioned_cache

log "stopping session through daemon"
"$WRIT_BIN" --socket "$SOCKET_PATH" agent-vm stop "$SESSION_ID"
STOP_DONE=1

assert_container_absent
assert_network_absent
assert_pf_anchor_empty
assert_no_pf_state_for_guest
assert_state_removed

log "devshell-warm proof succeeded for ${IPV4_CIDR}: the no-egress VM cloned the fixture, the broker provisioned its locked flake inputs, \`nix develop\` entered the devShell with github unreachable while consuming the provisioned local cache, and daemon stop cleanup was verified"
