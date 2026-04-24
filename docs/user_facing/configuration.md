# Configuration

The daemon is configured by a single JSON file, loaded at startup. There
is no runtime reload — restart `writd` to pick up changes. Restarts are
cheap; no in-memory state is lost.

## Where the daemon looks

| What            | Default location                                | Override                      |
| --------------- | ----------------------------------------------- | ----------------------------- |
| Config file     | `$XDG_CONFIG_HOME/writ/config.json`             | `writd --config <path>`       |
| Audit database  | `$XDG_DATA_HOME/writ/audit.db`                  | `writd --audit-db <path>` or `audit_db` in config |
| Unix socket     | `$XDG_RUNTIME_DIR/writ/writd.sock`              | `writd --socket <path>` or `socket_path` in config |
| File secret store base | `$XDG_DATA_HOME/writ/secrets/`           | `secret_store.path` in config |

If `XDG_CONFIG_HOME` / `XDG_DATA_HOME` / `XDG_RUNTIME_DIR` are unset, the
daemon falls back to `~/.config`, `~/.local/share`, and
`~/.local/run` respectively.

The CLI client (`writ`) finds the socket via `--socket`, the
`WRIT_SOCKET` environment variable, or the same default.

## Full config reference

```json
{
  "github": {
    "app_id": 12345,
    "installation_id": 67890,
    "installation_owner": "smaug123",
    "private_key_secret": "gh-app-pk",
    "api_base": "https://api.github.com"
  },
  "policy": {
    "default_ttl": 3600,
    "writable_repos": ["smaug123/writ", "smaug123/notes"]
  },
  "secret_store": { "type": "file", "path": "/home/me/.local/share/writ/secrets" },
  "socket_path": "/run/user/1000/writ/writd.sock",
  "audit_db": "/home/me/.local/share/writ/audit.db"
}
```

### `github`

| Field                | Required | Description                                                                  |
| -------------------- | -------- | ---------------------------------------------------------------------------- |
| `app_id`             | yes      | GitHub App ID (numeric).                                                     |
| `installation_id`    | yes      | Installation ID (numeric).                                                   |
| `installation_owner` | yes      | User or org login that the installation belongs to. Used to reject requests for repos owned by anyone else **before** any GitHub call. |
| `private_key_secret` | yes      | Key under which the App's RSA private key is stored in the secret store. Must be non-empty, contain no `/` or NUL, and not start with `.`. |
| `api_base`           | no       | Defaults to `https://api.github.com`. Override for GitHub Enterprise Server (no trailing slash). |

### `policy`

| Field             | Required | Description |
| ----------------- | -------- | ----------- |
| `default_ttl`     | yes      | Ceiling on grant lifetime in seconds. Must be **`1`–`3600`** — GitHub installation tokens always live ~1 hour and cannot be asked for less, so a `default_ttl` shorter than ~3600 will cause the mint step to refuse rather than write a misleading audit row. |
| `writable_repos`  | no       | List of `"owner/name"` strings that may be the target of write requests. Match is case-insensitive (GitHub treats `Smaug123/Writ` and `smaug123/writ` as the same repo). Defaults to empty (no writes permitted). |

See [Policy](policy.md) for what "write" means per request type.

### `secret_store`

A tagged enum, defaulting to the file backend at
`$XDG_DATA_HOME/writ/secrets`.

```json
{ "type": "file", "path": "/path/to/dir" }
```

```json
{ "type": "keyring", "service": "writ" }
```

If you omit the field entirely, you get the file backend at the default
path.

### `socket_path` / `audit_db`

Optional path overrides. The CLI flags `--socket` and `--audit-db` take
precedence over the config; the config takes precedence over the XDG
defaults.

## Secret stores

The broker holds exactly one long-lived secret: the GitHub App RSA
private key. There are two backends.

### File (default)

PEM is stored as a `0600` file under a `0700` directory.

```bash
mkdir -p "${XDG_DATA_HOME:-$HOME/.local/share}/writ/secrets"
chmod 0700 "${XDG_DATA_HOME:-$HOME/.local/share}/writ/secrets"
install -m 0600 ~/Downloads/your-app.private-key.pem \
  "${XDG_DATA_HOME:-$HOME/.local/share}/writ/secrets/gh-app-pk"
```

The daemon refuses to read a secret file whose permissions are looser
than `0600`, or whose parent directory is looser than `0700`. Fix the
permissions; don't try to disable the check.

Filenames are the **secret key** referenced from `config.json` as
`private_key_secret`. Names cannot contain `/`, NUL, or start with `.`.

### Keyring (opt-in)

Uses macOS Keychain or the freedesktop Secret Service. Set:

```json
"secret_store": { "type": "keyring", "service": "writ" }
```

Then add the secret with whatever tool fits your OS (`security
add-generic-password` on macOS; `secret-tool store` on Linux), using
`writ` as the service and your `private_key_secret` value as the
account.

The keyring backend is convenient on a desktop where the OS unlocks the
keychain for you at login. On a headless host (CI runner, server) the
file backend with strict permissions is usually the right default.

## What `writd` does on startup

1. Reads `config.json`. Invalid JSON or out-of-range values fail loudly.
2. Opens the audit DB, running migrations if needed. A DB at a higher
   schema version than this binary understands is **refused** rather
   than opened — that's deliberate. Downgrade the DB or upgrade the
   binary.
3. Constructs the configured secret store. The file backend will create
   the directory if missing; it will *not* loosen permissions on a
   directory that already exists.
4. Binds the Unix socket. If the socket already exists (e.g. from a
   crashed previous run), it's removed first. The parent directory is
   created with `0700` if missing.
5. Logs `writd: listening on …` to stderr and starts the dispatch loop.

The daemon exits non-zero on fatal errors (config, DB, socket bind).
Per-connection errors are logged and don't bring the daemon down.
