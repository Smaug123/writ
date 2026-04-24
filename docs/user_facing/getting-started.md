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

If you'd rather use the OS keychain (macOS Keychain or freedesktop
Secret Service), see [Configuration → Secret stores](configuration.md#secret-stores).

## 4. Write `config.json`

Default location is `$XDG_CONFIG_HOME/writ/config.json` (typically
`~/.config/writ/config.json`).

```json
{
  "github": {
    "app_id": 12345,
    "installation_id": 67890,
    "installation_owner": "smaug123",
    "private_key_secret": "gh-app-pk"
  },
  "policy": {
    "default_ttl": 3600,
    "writable_repos": ["smaug123/writ"]
  }
}
```

`installation_owner` is the user or org that the installation belongs to.
The broker rejects requests for repos owned by anybody else before
talking to GitHub at all — that's how it stops a typo'd request like
`openai/agent-infra` from quietly minting a token for your private fork.

`writable_repos` is the allowlist for *write* requests. Read requests are
permitted on any repo the installation can see, since the GitHub App
itself enforces the installation boundary.

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
SESSION=$(writ open-session --label "first run")
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
SESSION=$(writ open-session --label "fixing bug 42" --model claude-opus-4-7)
TOKEN=$(writ request "$SESSION" github contents write smaug123/writ)
git -c "http.extraheader=Authorization: Bearer $TOKEN" \
    push origin HEAD
writ close-session "$SESSION"
```

The token is good for ~1 hour; if you need another action, ask for
another credential. Each request is one row in the audit log.

## 7. Check the audit log

```bash
sqlite3 "${XDG_DATA_HOME:-$HOME/.local/share}/writ/audit.db" \
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
