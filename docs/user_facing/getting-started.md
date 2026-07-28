# Getting started

End-to-end: from a fresh checkout to an agent that can `git push`.

## 1. Create a GitHub App

`writ` mints **GitHub App installation tokens**, so you need a GitHub App
that you (or your org) own. The PAT/OAuth-token paths are not supported.

1. Go to **Settings → Developer settings → GitHub Apps → New GitHub App**
   (the URL depends on whether the app belongs to a user or an org).
2. Name it anything (e.g. `writ-bot-yourname`). Webhook can be disabled.
3. Set permissions to the union of what you want the broker to be able to
   ask for. A reasonable starting set:
    - **Contents:** Read & write
    - **Issues:** Read & write
    - **Pull requests:** Read & write
    - **Metadata:** Read-only (forced by GitHub)
4. Create the app. Note the **App ID** shown on the settings page.
5. Under **Private keys**, **Generate a private key**. GitHub will
   download a `.pem` file. Keep it.
6. Under **Install App**, install it on your account or org and pick the
   repositories you want the broker to be able to mint tokens for.
   Note the numeric **Installation ID** (visible in the URL after install,
   e.g. `/settings/installations/67890`).

You now have three things: an app ID, an installation ID, and a private
key PEM file.

## 2. Build and install

The repo is a single Cargo crate that produces two binaries.

```bash
cargo build --release
# binaries land in ./target/release/{writ,writd}
# copy them onto your $PATH however you usually do that
install -m 0755 target/release/writd ~/.local/bin/writd
install -m 0755 target/release/writ  ~/.local/bin/writ
```

There is also a Nix flake (`flake.nix`) if you prefer.

## 3. Store the private key

The broker never reads the PEM file directly — it goes through a
[secret store](configuration.md#secret-stores). The default is a file
backend under `$XDG_DATA_HOME/writ/secrets/` with `0600` permissions.

```bash
mkdir -p "${XDG_DATA_HOME:-$HOME/.local/share}/writ/secrets"
chmod 0700 "${XDG_DATA_HOME:-$HOME/.local/share}/writ/secrets"
install -m 0600 ~/Downloads/writ-bot-yourname.*.private-key.pem \
  "${XDG_DATA_HOME:-$HOME/.local/share}/writ/secrets/gh-app-pk"
```

The filename (`gh-app-pk` here) is the **secret key name** you'll
reference in `config.json` as `private_key_secret`.

### Alternative: macOS Keychain

If you'd rather have macOS unlock the secret for you at login, store the
PEM in the login keychain as a generic password. `security` is the
built-in CLI; no extra install needed.

```bash
security add-generic-password \
  -s writ \
  -a gh-app-pk \
  -w "$(cat ~/Downloads/writ-bot-yourname.*.private-key.pem)"
```

- `-s writ` is the **service**. It has to match `secret_store.service`
  in `config.json` below.
- `-a gh-app-pk` is the **account**, which is the secret key name
  referenced from `private_key_secret` in `config.json`.
- `-w "$(...)"` passes the PEM as the password. It appears briefly in
  `ps`-visible argv; if that matters on a shared machine, drop the
  trailing argument (`-w` with no value makes `security` prompt
  interactively) and paste the PEM at the prompt.

To replace an existing entry in place, add `-U`:

```bash
security add-generic-password -U \
  -s writ -a gh-app-pk \
  -w "$(cat ~/Downloads/writ-bot-yourname.*.private-key.pem)"
```

Sanity-check by reading it back:

```bash
security find-generic-password -s writ -a gh-app-pk -w
```

That should print the PEM verbatim. To remove the entry later:

```bash
security delete-generic-password -s writ -a gh-app-pk
```

When you use the keychain, point `config.json` at the keyring backend
(otherwise the daemon still looks in the file store):

```json
"secret_store": { "type": "keyring", "service": "writ" }
```

For the freedesktop Secret Service equivalent on Linux, see
[Configuration → Secret stores](configuration.md#secret-stores).

## 4. Write `config.json`

Default location is `$XDG_CONFIG_HOME/writ/config.json` (typically
`~/.config/writ/config.json`).

```json
{
  "github_apps": {
    "claude": {
      "app_id": 12345,
      "installation_id": 67890,
      "installation_owner": "smaug123",
      "private_key_secret": "gh-app-pk"
    }
  },
  "policy": {
    "default_ttl": 3600,
    "writable_repos": ["smaug123/writ"]
  }
}
```

`github_apps` is keyed by agent kind (`claude` or `codex`). At least one
entry is required; sessions must be opened with `--agent claude` or
`--agent codex` so the broker knows which App to mint with. If you run
both Claude and Codex with separate GitHub Apps, list both keys; see
[Configuration](configuration.md#github_apps).

`installation_owner` is the user or org that the installation belongs to.
The broker rejects requests for repos owned by anybody else before
talking to GitHub at all — that's how it stops a typo'd request like
`openai/agent-infra` from quietly minting a token for your private fork.

`writable_repos` is the allowlist for *write* requests. Read requests are
permitted on any repo the installation can see, since the GitHub App
itself enforces the installation boundary.

### Optional: `agent_vm` block

`writ agent` boots a per-session VM that the agent runs inside. To
enable it, add an `agent_vm` block alongside the others. Both inner
structs (`lifecycle` and `vm_http`) are `deny_unknown_fields`, so don't
sneak in keys outside the documented schema — the daemon refuses to
start.

```json
"agent_vm": {
  "lifecycle": {
    "ipv4_pool": "192.168.0.0/16",
    "ipv6_pool": "fd83:b6f2:e57::/48",
    "subnet_index_min": 252,
    "subnet_index_max": 252,
    "container": "container",
    "sudo": "sudo",
    "pf_helper": "/abs/path/to/writ-agent-vm-pf-helper",
    "state_dir": "/abs/path/to/writ/agent-vm-state",
    "ipv6_mode": "ipv4_only_no_guest_ipv6",
    "image": "writ-agent-vm-guest:latest",
    "cpus": 1,
    "memory_mib": 512
  },
  "vm_http": {
    "bind_addr": "0.0.0.0",
    "broker_port_min": 49152,
    "broker_port_max": 65535,
    "git_program": "/abs/path/to/git",
    "askpass_program": "/abs/path/to/git-askpass.sh",
    "token_env": "WRIT_GIT_TOKEN",
    "work_root": "/abs/path/to/writ/git-work",
    "clone_timeout_secs": 30,
    "max_bundle_bytes": 1048576,
    "nix_cache_url": "https://cache.nixos.org",
    "nix_cache_trusted_public_keys": [
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
    ],
    "nix_cache_max_metadata_bytes": 1048576,
    "nix_cache_max_nar_bytes": 67108864,
    "flake_mirror_cache_dir": "/abs/path/to/writ/flake-mirror-cache",
    "git_push_staging_root": "/abs/path/to/writ/git-push-staging"
  }
}
```

Before that block does anything useful you need four things on disk:

1. **`pf_helper`** — `writ-agent-vm-pf-helper` from `agent-infra`. The
   daemon shells out to it via `sudo` to bring up PF anchors, so make
   sure you have a sudoers entry (or are happy to type your password
   each session).
2. **`image`** — `writ-agent-vm-guest:latest` is just a tag. Apple's
   `container` won't find it until you build the guest image (e.g.
   `nix build .#agent-vm-guest-image-aarch64-linux`) and load the
   resulting archive via `container image load --input <archive>`.
3. **`askpass_program`** — there's no shipped binary; drop a small
   script wherever the config points and `chmod +x` it. The two
   prompts Git sends during HTTPS auth need to be answered like so:
   ```sh
   #!/usr/bin/env sh
   case "$1" in
     *Username*) printf 'x-access-token\n' ;;
     *Password*) printf '%s\n' "${WRIT_GIT_TOKEN:?missing WRIT_GIT_TOKEN for git askpass}" ;;
     *) printf 'unexpected askpass prompt: %s\n' "$1" >&2; exit 1 ;;
   esac
   ```
   The env var name must match `token_env` above.
4. **`git_program`** — absolute path to the git binary you want the
   broker to shell out to. Don't rely on `$PATH`.

`git_push_staging_root` is optional; if omitted it defaults to a
subdirectory of `work_root`.

`agent_run_log_root` is a **top-level** key, not part of `agent_vm` — both
ways of running an agent write per-run `stdout.log` / `stderr.log` beneath it,
so neither section owns it:

```json
"agent_run_log_root": "/abs/path/to/writ/agent-run-logs"
```

It is optional and defaults to `$XDG_DATA_HOME/writ/agent-runs` (falling back
to `~/.local/share/writ/agent-runs`). The daemon creates it at boot and proves
it writable, so a bad path is a startup error rather than a surprise mid-run.
Paths recorded on audit rows are absolute, so moving this root leaves logs
already written where they are.

`flake_mirror_cache_dir` is optional but recommended: setting it turns on
**flake-input provisioning**, so `writ agent … --warm devshell` works for a
repo with public flake inputs even though the guest has no egress. The broker
fetches the repo's committed, locked inputs on the host and serves them to the
guest's Nix through the cache it already trusts; without this key, a no-egress
`nix develop` cannot resolve `github:` inputs and warm fails. (v1 provisions
public inputs only; a private or auth-requiring input is not provisioned.) See
[configuration](configuration.md#agent_vm) for the related knobs and
[the design doc](../design/apple-container-agent-vm.md) for the
guarantee/envelope.

### Optional: `claude_proxy` block

`writ agent run --model …` only reaches Anthropic via a broker-side
proxy. Without it, the run fails with a proxy-not-configured error
rather than the actual upstream call. Add a `claude_proxy` block under
`vm_http`:

```json
"claude_proxy": {
  "upstream_base_url": "https://api.anthropic.com",
  "auth_secret": "anthropic-key",
  "auth_kind": "x_api_key",
  "anthropic_version": "2023-06-01",
  "timeout_secs": 60,
  "max_request_bytes": 2097152,
  "max_response_bytes": 8388608
}
```

`auth_secret` is the secret-store key (same store as
`private_key_secret`) holding the API key or OAuth token.
`auth_kind` is one of `x_api_key`, `authorization_bearer`, or `oauth`
— the broker picks the matching header per variant. Anthropic OAuth
tokens beginning `sk-ant-oat01-` must use `oauth`; static Anthropic API
keys use `x_api_key`.

## 5. Run the daemon

```bash
writd
# writd: listening on /run/user/1000/writ/writd.sock
```

Leave that running in a terminal pane (or under your supervisor of
choice — `systemd --user`, `launchd`, `tmux`, whatever). Restarting is
cheap; the daemon keeps no in-memory state that isn't also in the
audit DB.

## 6. Make a request

In another shell:

```bash
SESSION=$(writ open-session --label "first run" --agent claude)
echo "session: $SESSION"

# Read access — granted on any repo the installation can see.
TOKEN=$(writ request "$SESSION" github metadata smaug123/writ)
echo "got a token, length ${#TOKEN}"

writ close-session "$SESSION"
```

If the daemon's running and your config is good, you should see a
session UUID, then a `ghs_…` token printed to stdout, then nothing.

A real agent recipe looks like:

```bash
SESSION=$(writ open-session --label "fixing bug 42" --agent claude --model claude-opus-4-7)
TOKEN=$(writ request "$SESSION" github contents write smaug123/writ)
git -c "http.extraheader=Authorization: Bearer $TOKEN" \
    push origin HEAD
writ close-session "$SESSION"
```

The token is good for ~1 hour; if you need another action, ask for
another credential. Each request is one row in the audit log.

## 7. Check the audit log

```bash
sqlite3 "${XDG_DATA_HOME:-$HOME/.local/share}/writ/audit/audit.db" \
  'SELECT request_id, request_json, decision_json FROM request ORDER BY received_at DESC LIMIT 5;'
```

See [Audit log](audit-log.md) for the full schema and useful queries.

## Troubleshooting

- **`cannot connect to /run/user/1000/writ/writd.sock`** — the daemon
  isn't running, or it's running under a different user. Start `writd`.
- **`denied: write access to X is not on the writable-repos allowlist`** —
  add the repo to `policy.writable_repos` in `config.json` and restart
  `writd`.
- **`installation X does not own Y`** — `installation_owner` in your
  config doesn't match the repo you asked for. Either fix the config,
  or install the GitHub App on the right account.
- **Mint failures** — check `mint_failure` in the audit DB; the
  `failure_json` column has GitHub's response body.
