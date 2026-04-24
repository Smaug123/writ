# CLI reference

Two binaries: `writd` (the daemon) and `writ` (the client an agent
calls).

## `writd` — the daemon

```text
writd [--config <path>] [--socket <path>] [--audit-db <path>]
```

| Flag           | Description                                                                                  |
| -------------- | -------------------------------------------------------------------------------------------- |
| `-c, --config` | Path to `config.json`. Default: `$XDG_CONFIG_HOME/writ/config.json`.                          |
| `--socket`     | Override the Unix socket path. Beats both `socket_path` in config and the XDG default.        |
| `--audit-db`   | Override the audit DB path. Beats both `audit_db` in config and the XDG default.              |

`writd` runs in the foreground; supervise it however you usually do
(systemd user unit, launchd, tmux, `&`).

## `writ` — the client

```text
writ [--socket <path>] <subcommand>
```

| Flag       | Description                                                                                          |
| ---------- | ---------------------------------------------------------------------------------------------------- |
| `--socket` | Path to the daemon socket. Also reads `WRIT_SOCKET`. Default: `$XDG_RUNTIME_DIR/writ/writd.sock`.    |

Each invocation makes one request and exits. Successful output goes to
**stdout** (a session ID, or a token). Errors go to **stderr** and the
process exits with code 1.

A 60-second timeout is applied to each request; if the daemon takes
longer than that, the CLI bails rather than wedging the agent's
pipeline.

### `writ open-session [--label <text>] [--model <text>]`

Opens a session and prints its UUID to stdout.

| Flag      | Description                                                                                       |
| --------- | ------------------------------------------------------------------------------------------------- |
| `--label` | Free-form description shown in the audit log. Use it: `--label "fixing bug 42"`. Optional.        |
| `--model` | Agent/model identifier shown in the audit log, e.g. `claude-opus-4-7`. Optional.                  |

Both are stored verbatim and ignored by policy.

```bash
SESSION=$(writ open-session --label "fixing bug 42" --model claude-opus-4-7)
```

### `writ close-session <session-id>`

Records the close timestamp on the session. Closing is **advisory and
idempotent**; audit rows outlive their session, and an agent that
forgets to close does not lose its grants.

```bash
writ close-session "$SESSION"
```

### `writ request <session-id> github <action> <repo>`

Asks the broker to evaluate policy and, on grant, mint a credential.
Prints the raw token to stdout (so you can capture it with
`TOKEN=$(writ …)`).

The action grammar:

| Subcommand                                           | What it asks for                  |
| ---------------------------------------------------- | --------------------------------- |
| `github contents read <owner/repo>`                  | Read repo contents (clone, pull). |
| `github contents write <owner/repo>`                 | Write repo contents (push).       |
| `github issues read <owner/repo>`                    | Read issues.                      |
| `github issues write <owner/repo>`                   | Create/comment on issues.         |
| `github pull-requests read <owner/repo>`             | Read PRs.                         |
| `github pull-requests write <owner/repo>`            | Create/comment on PRs.            |
| `github metadata <owner/repo>`                       | Repo metadata only (always read). |

Any granted token also carries `metadata: read`, because GitHub
requires it on every installation token.

Examples:

```bash
TOKEN=$(writ request "$SESSION" github contents read smaug123/writ)

TOKEN=$(writ request "$SESSION" github pull-requests write smaug123/writ)

TOKEN=$(writ request "$SESSION" github metadata smaug123/writ)
```

### Exit codes

| Exit | Meaning                                                                          |
| ---- | -------------------------------------------------------------------------------- |
| 0    | Success. Stdout is the requested value.                                          |
| 1    | Anything else: invalid args, daemon unreachable, denial, mint error, timeout. The reason is on stderr. |

The CLI does not retry on its own. An agent that gets a non-zero exit
should surface the stderr line to the user, not silently re-attempt.

## Using the token

The token is a standard GitHub App installation token. Anywhere a PAT
or OAuth token works, this works:

```bash
# git over HTTPS
git -c "http.extraheader=Authorization: Bearer $TOKEN" \
    push origin HEAD

# gh CLI
GH_TOKEN=$TOKEN gh pr create --title "..." --body "..."

# raw API
curl -H "Authorization: Bearer $TOKEN" \
     -H "Accept: application/vnd.github+json" \
     https://api.github.com/repos/smaug123/writ
```

The token expires within ~1 hour. For a longer-running task, request a
fresh token per action rather than storing it.
