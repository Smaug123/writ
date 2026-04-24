# Audit log

Every session, every request, every grant, and every mint failure is
written to a SQLite database. By default it lives at
`$XDG_DATA_HOME/writ/audit.db`. The log is append-only: nothing is
updated except `session.closed_at`.

If the broker is the only thing that can mint credentials for your
agent, the audit log *is* the history of what your agent had the
authority to do.

## Schema

```sql
CREATE TABLE session (
  session_id  TEXT PRIMARY KEY,
  label       TEXT,
  agent_model TEXT,
  opened_at   INTEGER NOT NULL,
  closed_at   INTEGER
);

CREATE TABLE request (
  request_id    TEXT PRIMARY KEY,
  session_id    TEXT NOT NULL REFERENCES session(session_id),
  received_at   INTEGER NOT NULL,
  request_json  TEXT NOT NULL,
  decision_json TEXT NOT NULL
);

CREATE TABLE grant_log (
  jti         TEXT PRIMARY KEY,
  request_id  TEXT NOT NULL REFERENCES request(request_id),
  session_id  TEXT NOT NULL REFERENCES session(session_id),
  scope_json  TEXT NOT NULL,
  issued_at   INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);

CREATE TABLE mint_failure (
  request_id   TEXT PRIMARY KEY REFERENCES request(request_id),
  failed_at    INTEGER NOT NULL,
  failure_json TEXT NOT NULL
);
```

A few invariants worth knowing:

- **Timestamps are unix milliseconds.** Use `datetime(ts/1000, 'unixepoch')`
  in SQLite to render them.
- **`request` commits *before* the mint is attempted.** A crash between
  the request commit and the outcome commit leaves a `request` row with
  no matching `grant_log` or `mint_failure`. That's the honest "in
  flight at crash time" state, and it's what replay tools should
  recognise.
- **A request has at most one outcome.** Triggers enforce that a given
  `request_id` appears in *either* `grant_log` *or* `mint_failure`,
  never both.
- **The token itself is never stored.** Only the metadata that proves
  it was issued — the `jti` (a UUID the broker generates), the
  `scope_json`, and timestamps.
- **Closing a session is advisory.** Audit rows outlive their session;
  forgetting to call `writ close-session` does not lose anything.

## Useful queries

Open a SQLite shell:

```bash
sqlite3 "${XDG_DATA_HOME:-$HOME/.local/share}/writ/audit.db"
```

(Add `.headers on` and `.mode column` for a friendlier display.)

### What did this session do?

```sql
SELECT
  datetime(received_at/1000, 'unixepoch') AS at,
  json_extract(request_json,  '$.GitHub') AS request,
  json_extract(decision_json, '$.type')   AS decision
FROM request
WHERE session_id = '00000000-0000-0000-0000-...'
ORDER BY received_at;
```

### Recent grants, with scope

```sql
SELECT
  datetime(g.issued_at/1000, 'unixepoch')  AS issued,
  datetime(g.expires_at/1000, 'unixepoch') AS expires,
  s.label,
  s.agent_model,
  g.scope_json
FROM grant_log g
JOIN session s USING (session_id)
ORDER BY g.issued_at DESC
LIMIT 20;
```

### Anything denied recently

```sql
SELECT
  datetime(received_at/1000, 'unixepoch') AS at,
  json_extract(decision_json, '$.reason') AS reason,
  request_json
FROM request
WHERE json_extract(decision_json, '$.type') = 'deny'
ORDER BY received_at DESC
LIMIT 20;
```

### Mint failures (talked to GitHub, didn't get a token)

```sql
SELECT
  datetime(failed_at/1000, 'unixepoch') AS at,
  request_id,
  failure_json
FROM mint_failure
ORDER BY failed_at DESC
LIMIT 10;
```

The `failure_json` includes GitHub's response body when the mint failed
because of an HTTP error.

### Requests in flight at crash time

```sql
SELECT request_id, session_id, received_at
FROM request
WHERE NOT EXISTS (SELECT 1 FROM grant_log    WHERE request_id = request.request_id)
  AND NOT EXISTS (SELECT 1 FROM mint_failure WHERE request_id = request.request_id);
```

If this returns rows during normal operation, look at the daemon log
to see if it crashed. Empty during steady state.

### Sessions still open

```sql
SELECT session_id, label, agent_model,
       datetime(opened_at/1000, 'unixepoch') AS opened
FROM session
WHERE closed_at IS NULL
ORDER BY opened_at DESC;
```

## Schema versioning

The DB carries a `PRAGMA user_version` set by the daemon's migration
framework. Each migration commits its DDL and version bump in a single
transaction, so a process killed mid-migration resumes cleanly the next
time `writd` opens the DB.

A DB at a higher schema version than this binary understands is
**refused** (the daemon won't open it) rather than opened with columns
the binary doesn't know about. That's deliberate: the failure mode of a
silently-down-rev binary writing rows that lie about their content is
much worse than the failure mode of a clean refusal. Upgrade the binary
or move the old DB aside.

## Backups

The audit DB is a regular SQLite file. `cp` while the daemon is idle
works; for a hot copy use `sqlite3 audit.db ".backup target.db"`. There
is nothing else to back up — secrets live in the secret store
(file or keyring), not in this DB.
