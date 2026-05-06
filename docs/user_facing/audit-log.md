# Audit log

Every session, every capability request, every grant, every mint
failure, and every brokered VM Nix cache request is written to a
SQLite database. By default it lives at
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
  agent_kind  TEXT,
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
  jti           TEXT PRIMARY KEY,
  request_id    TEXT NOT NULL REFERENCES request(request_id),
  session_id    TEXT NOT NULL REFERENCES session(session_id),
  github_app_id INTEGER,
  scope_json    TEXT NOT NULL,
  issued_at     INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL
);

CREATE TABLE mint_failure (
  request_id   TEXT PRIMARY KEY REFERENCES request(request_id),
  failed_at    INTEGER NOT NULL,
  failure_json TEXT NOT NULL
);

CREATE TABLE nix_cache_request (
  request_id   TEXT PRIMARY KEY,
  session_id   TEXT NOT NULL REFERENCES session(session_id),
  received_at  INTEGER NOT NULL,
  method       TEXT NOT NULL,
  target       TEXT NOT NULL,
  route        TEXT NOT NULL CHECK (route IN ('cache_info', 'narinfo', 'unsupported')),
  decision     TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
  deny_reason  TEXT,
  CHECK (
    (decision = 'allow' AND deny_reason IS NULL)
    OR (decision = 'deny' AND deny_reason IS NOT NULL AND deny_reason != '')
  )
);

CREATE TABLE nix_cache_outcome (
  request_id      TEXT PRIMARY KEY REFERENCES nix_cache_request(request_id),
  completed_at    INTEGER NOT NULL,
  http_status     INTEGER NOT NULL CHECK (http_status BETWEEN 100 AND 599),
  upstream_url    TEXT,
  upstream_status INTEGER CHECK (upstream_status BETWEEN 100 AND 599),
  response_bytes  INTEGER NOT NULL CHECK (response_bytes >= 0),
  error           TEXT CHECK (error IS NULL OR error != '')
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
- **Nix cache requests use their own request/outcome pair.**
  `nix_cache_request` commits before the broker contacts the upstream
  binary cache. `nix_cache_outcome` records the broker HTTP status,
  optional upstream URL/status, response byte count, and a bounded
  error label. A crash between those two commits leaves a Nix cache
  request with no outcome.
- **Nix cache auth denials are audited without upstream contact.**
  They appear as `decision = 'deny'` with a `deny_reason`, no
  upstream URL/status, and the HTTP status returned to the VM in
  `nix_cache_outcome`.
- **The token itself is never stored.** Only the metadata that proves
  it was issued — the `jti` (a UUID the broker generates), the
  `github_app_id`, `scope_json`, and timestamps. Older rows written
  before schema version 5 may have `github_app_id = NULL`.
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
  s.agent_kind,
  s.agent_model,
  g.github_app_id,
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

### VM Nix cache activity

```sql
SELECT
  datetime(r.received_at/1000, 'unixepoch') AS received,
  r.method,
  r.target,
  r.route,
  r.decision,
  r.deny_reason,
  o.http_status,
  o.upstream_status,
  o.response_bytes,
  o.error
FROM nix_cache_request r
LEFT JOIN nix_cache_outcome o USING (request_id)
WHERE r.session_id = '00000000-0000-0000-0000-...'
ORDER BY r.received_at DESC;
```

For auth denials, `decision` is `deny` and `deny_reason` names the
transport failure. For upstream cache misses, `decision` is `allow`,
`http_status` is `404`, and `upstream_status` is usually `404`.

### Requests in flight at crash time

```sql
SELECT request_id, session_id, received_at
FROM request
WHERE NOT EXISTS (SELECT 1 FROM grant_log    WHERE request_id = request.request_id)
  AND NOT EXISTS (SELECT 1 FROM mint_failure WHERE request_id = request.request_id);
```

If this returns rows during normal operation, look at the daemon log
to see if it crashed. Empty during steady state.

For brokered Nix cache requests, use the matching query:

```sql
SELECT request_id, session_id, received_at, method, target, route, decision
FROM nix_cache_request
WHERE NOT EXISTS (
  SELECT 1
  FROM nix_cache_outcome
  WHERE request_id = nix_cache_request.request_id
);
```

### Sessions still open

```sql
SELECT session_id, label, agent_kind, agent_model,
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
