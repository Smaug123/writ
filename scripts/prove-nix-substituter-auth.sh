#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/prove-nix-substituter-auth.sh

Manual proof harness for guest-Nix substituter authentication.

This runs host-local Nix against a fake HTTP binary cache and proves the
intended VM-side auth shape before we build the real broker proxy:

  - Nix can use an isolated netrc file for binary-cache HTTP auth.
  - Nix requests nix-cache-info and narinfo paths with session authority.
  - The secret is not embedded in the substituter URL or Nix argv.
  - Ambient user Nix config is not required.

The fake binary cache deliberately returns 404 for the requested narinfo. The
Nix command is expected to fail after making the authenticated cache requests;
the captured request log is the correctness oracle.

Environment overrides:
  WRIT_PROVE_NIX_TOKEN  token to place in the temporary netrc
                        default writ-vm-substituter-proof-token
EOF
}

log() {
  printf '[prove-nix-auth] %s\n' "$*"
}

die() {
  printf '[prove-nix-auth] error: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/writ-nix-auth-proof.XXXXXX")"
chmod 700 "$TMP_DIR"

SERVER_SCRIPT="${TMP_DIR}/fake-binary-cache.py"
REQUEST_LOG="${TMP_DIR}/requests.jsonl"
PORT_FILE="${TMP_DIR}/port"
NETRC_FILE="${TMP_DIR}/netrc"
NIX_STDOUT="${TMP_DIR}/nix.stdout"
NIX_STDERR="${TMP_DIR}/nix.stderr"
NIX_HOME="${TMP_DIR}/home"
NIX_XDG_CONFIG_HOME="${TMP_DIR}/xdg-config"
NIX_CONF_DIR="${TMP_DIR}/nix-conf"
LOGIN="writ-vm"
TOKEN="${WRIT_PROVE_NIX_TOKEN:-writ-vm-substituter-proof-token}"
STORE_PATH="/nix/store/00000000000000000000000000000000-writ-nix-auth-proof"
SERVER_PID=""

if [[ -z "$TOKEN" || "$TOKEN" == *[[:space:]]* ]]; then
  die "WRIT_PROVE_NIX_TOKEN must be non-empty and must not contain whitespace"
fi

cleanup() {
  local rc=$?
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
  exit "$rc"
}
trap cleanup EXIT INT TERM

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

write_fake_binary_cache() {
  cat >"$SERVER_SCRIPT" <<'PY'
import base64
import http.server
import json
import pathlib
import socketserver
import sys

request_log = pathlib.Path(sys.argv[1])
port_file = pathlib.Path(sys.argv[2])
login = sys.argv[3]
token = sys.argv[4]
expected_auth = "Basic " + base64.b64encode(f"{login}:{token}".encode()).decode()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _record(self):
        record = {
            "method": self.command,
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
        }
        with request_log.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def _require_auth(self, record):
        if record["authorization"] is None:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="writ-nix-cache"')
            self.end_headers()
            return False
        if record["authorization"] != expected_auth:
            self.send_response(403)
            self.end_headers()
            return False
        return True

    def do_GET(self):
        record = self._record()
        if not self._require_auth(record):
            return
        if self.path == "/nix-cache-info":
            body = b"StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 40\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.endswith(".narinfo"):
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_HEAD(self):
        record = self._record()
        if not self._require_auth(record):
            return
        if self.path == "/nix-cache-info" or self.path.endswith(".narinfo"):
            self.send_response(404 if self.path.endswith(".narinfo") else 200)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()


with socketserver.TCPServer(("127.0.0.1", 0), Handler) as httpd:
    port_file.write_text(str(httpd.server_address[1]), encoding="utf-8")
    httpd.serve_forever()
PY
}

start_fake_binary_cache() {
  write_fake_binary_cache
  python3 "$SERVER_SCRIPT" "$REQUEST_LOG" "$PORT_FILE" "$LOGIN" "$TOKEN" &
  SERVER_PID="$!"
  for _ in {1..50}; do
    if [[ -s "$PORT_FILE" ]]; then
      return
    fi
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      die "fake binary cache exited before writing a port file"
    fi
    sleep 0.1
  done
  die "fake binary cache did not start"
}

write_netrc() {
  printf 'machine 127.0.0.1 login %s password %s\n' "$LOGIN" "$TOKEN" >"$NETRC_FILE"
  chmod 600 "$NETRC_FILE"
}

assert_token_not_in_command_surface() {
  local store_url="$1"
  shift
  if [[ "$store_url" == *"$TOKEN"* ]]; then
    die "substituter URL contains the raw token"
  fi
  local arg
  for arg in "$@"; do
    if [[ "$arg" == *"$TOKEN"* ]]; then
      die "Nix argv contains the raw token"
    fi
  done
}

run_nix_probe() {
  local port
  port="$(<"$PORT_FILE")"
  local store_url="http://127.0.0.1:${port}"

  local -a nix_args=(
    path-info
    --refresh
    --store "$store_url"
    --option experimental-features "nix-command"
    --option access-tokens ""
    --option substituters ""
    --option trusted-public-keys ""
    --option netrc-file "$NETRC_FILE"
    "$STORE_PATH"
  )
  assert_token_not_in_command_surface "$store_url" "${nix_args[@]}"

  mkdir -p "$NIX_HOME" "$NIX_XDG_CONFIG_HOME" "$NIX_CONF_DIR"
  : >"$NIX_CONF_DIR/nix.conf"

  log "running Nix against fake binary cache at ${store_url}"
  set +e
  env -i \
    PATH="$PATH" \
    HOME="$NIX_HOME" \
    XDG_CONFIG_HOME="$NIX_XDG_CONFIG_HOME" \
    NIX_CONF_DIR="$NIX_CONF_DIR" \
    NIX_CONFIG="" \
    TMPDIR="${TMPDIR:-/tmp}" \
    nix "${nix_args[@]}" >"$NIX_STDOUT" 2>"$NIX_STDERR"
  local rc=$?
  set -e

  if [[ "$rc" -eq 0 ]]; then
    die "Nix unexpectedly succeeded against the fake cache for ${STORE_PATH}"
  fi
  log "Nix exited ${rc}; inspecting captured binary-cache requests"
}

assert_requests_are_authenticated() {
  python3 - \
    "$REQUEST_LOG" \
    "$NIX_STDOUT" \
    "$NIX_STDERR" \
    "$LOGIN" \
    "$TOKEN" \
    <<'PY'
import base64
import json
import pathlib
import sys

request_log = pathlib.Path(sys.argv[1])
nix_stdout = pathlib.Path(sys.argv[2])
nix_stderr = pathlib.Path(sys.argv[3])
login = sys.argv[4]
token = sys.argv[5]
expected_auth = "Basic " + base64.b64encode(f"{login}:{token}".encode()).decode()

if not request_log.exists():
    raise SystemExit("fake binary cache received no requests")

records = [
    json.loads(line)
    for line in request_log.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
if not records:
    raise SystemExit("fake binary cache received no requests")

if not any(record["path"] == "/nix-cache-info" for record in records):
    raise SystemExit(f"Nix never requested /nix-cache-info: {records!r}")
if not any(record["path"].endswith(".narinfo") for record in records):
    raise SystemExit(f"Nix never requested a narinfo path: {records!r}")

for record in records:
    path = record["path"]
    auth = record["authorization"]
    if token in path:
        raise SystemExit(f"raw token leaked into request path: {record!r}")
    if auth != expected_auth:
        raise SystemExit(f"request did not carry expected netrc Basic auth: {record!r}")
    if not (path == "/nix-cache-info" or path.endswith(".narinfo")):
        raise SystemExit(f"unexpected binary-cache request path: {record!r}")

for label, path in (("stdout", nix_stdout), ("stderr", nix_stderr)):
    text = path.read_text(encoding="utf-8", errors="replace")
    if token in text:
        raise SystemExit(f"raw token leaked into Nix {label}")

print(
    "authenticated paths: "
    + ", ".join(f"{record['method']} {record['path']}" for record in records)
)
PY
}

require_cmd nix
require_cmd python3

write_netrc
start_fake_binary_cache
run_nix_probe
assert_requests_are_authenticated

log "Nix substituter auth proof succeeded; netrc Basic auth covers nix-cache-info and narinfo without putting the token in the URL or argv"
