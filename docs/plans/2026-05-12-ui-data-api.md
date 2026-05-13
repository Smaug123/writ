# UI data API — design

Plan for adding a read-only JSON HTTP transport to `writd` that exposes
broker state for external UIs (web, TUI, MCP, ad-hoc `curl`). Companion to
[`docs/design/broker.md`](../design/broker.md) and
[`docs/plans/2026-05-11-agent-plans.md`](./2026-05-11-agent-plans.md).

## Goal

Expose the broker's persisted state as a typed JSON API so any consumer can
read it without speaking the Unix-socket wire protocol and without opening
`audit.db` directly. The API is the contract; the consumer (browser SPA,
ratatui binary, MCP wrapper, `curl | jq` in a script) is interchangeable.

Slice 1, in scope here: list and detail for daemon-managed agent VM
sessions, including the joined session metadata and a pointer to the
current `agent_run` row. Enough to render "which VMs are we managing, and
what's each one doing right now."

## Why this shape

The broker's existing invariants are unchanged. SQLite stays behind the
daemon's `Mutex<Connection>`; there is no second reader. New HTTP routes
are thin views over the same handler functions that already back the
Unix-socket commands (`ListAgentVms` is the seed for `GET /v1/agent-vms`).

Three audiences want this data: a web UI, a future TUI, and the operator
at a shell. A single typed JSON API serves all three without any of them
becoming privileged. The broker doc explicitly contemplates "HTTP as a
second transport behind the same handler functions"; this slice cashes
that in for reads only.

Mutations stay on the Unix socket in slice 1. The Unix-socket protocol is
the existing write contract (`StartAgentVm`, `StopAgentVm`,
`RejectStagedPush`, future `PlanDecide`); the HTTP listener does not
duplicate it. Splitting reads from writes keeps the new surface small,
defers the auth-on-mutation question, and matches the case-by-case
flexibility the broker design prefers for v1.

The trust boundary is bearer-token-on-localhost. Binding to `127.0.0.1`
is *not* sufficient on its own — a browser tab on any third-party site
can issue cross-origin requests to loopback. A required bearer in
`Authorization` headers closes that hole and reuses the same shape as
the existing VM-HTTP bearer; the operator-trust model already accepts
file-permission-gated secrets on disk.

## Transport

### Listener

A third HTTP listener inside `writd`, distinct from:

- the host **Unix socket** at `$XDG_RUNTIME_DIR/writ/writd.sock` (the
  primary control plane; line-delimited JSON), and
- the **per-VM HTTP** listeners bound to each VM's bridge network
  (guest-to-host, authority-bearing, bearer-gated).

The UI HTTP listener is bound to `127.0.0.1` on a **static port** read
from config:

```json
{
  "ui_http": {
    "bind": "127.0.0.1:7378"
  }
}
```

`ui_http` is absent by default; when absent, the listener is not started
and the daemon behaves exactly as today. Port `7378` is a suggested
default for the `getting-started.md` walkthrough, not a hard-coded
value.

If the configured port is already in use, `writd` fails to start with a
clear error. Slice 1 does not attempt ephemeral fallback; static port
was requested for bookmarkability.

### Authentication

On daemon start, `writd` writes a fresh bearer to
`$XDG_RUNTIME_DIR/writ/ui-bearer` (mode `0600`, replaced atomically on
each start) and keeps it in memory. The token is a 32-byte URL-safe
random string. Every request must carry

```
Authorization: Bearer <token>
```

Requests without that header, or with a mismatched token, get `401`. The
bearer is regenerated on each daemon start; consumers re-read the file
when they get `401`. No refresh, no rotation in slice 1.

`curl` form:

```sh
curl -sS \
  -H "Authorization: Bearer $(cat "$XDG_RUNTIME_DIR/writ/ui-bearer")" \
  http://127.0.0.1:7378/v1/agent-vms | jq
```

### Method and content type

Slice 1 is GET-only. The listener rejects `POST`/`PUT`/`PATCH`/`DELETE`
with `405`. All responses are `application/json; charset=utf-8`,
compact. No `?pretty=` switch — consumers pipe to `jq`.

No `Access-Control-*` headers. Cross-origin reads from a browser are
not in scope; SPAs that want to consume this API run same-origin behind
a local proxy or use a fetch with the bearer included from a script
context that's already trusted (Electron, a `file://` page the user
loaded themselves, the TUI, …).

## API surface (slice 1)

### `GET /v1/agent-vms`

List every persisted daemon-managed VM session: starting, running, and
orphaned (row exists, runtime not attached after a daemon restart).
Order: newest `opened_at` first. No filtering, no pagination.

```text
$ curl -sS -H "Authorization: Bearer $T" \
    http://127.0.0.1:7378/v1/agent-vms | jq
{
  "agent_vms": [
    {
      "session_id": "0193f5b2-...-...",
      "label": "fix flaky test in pipeline",
      "agent_kind": "claude",
      "agent_model": "claude-opus-4-7",
      "vm_name": "writ-agent-0193f5b2",
      "network_name": "writ-net-0",
      "subnet_index": 0,
      "broker_urls": ["http://192.168.64.1:53219"],
      "status": "running",
      "runtime_attached": true,
      "opened_at": 1715512345678,
      "closed_at": null,
      "current_run_id": "01941a02-..."
    },
    {
      "session_id": "0193f4...-...",
      "label": null,
      "agent_kind": "codex",
      "agent_model": "gpt-test",
      "vm_name": "writ-agent-0193f4",
      "network_name": "writ-net-1",
      "subnet_index": 1,
      "broker_urls": [],
      "status": "starting",
      "runtime_attached": false,
      "opened_at": 1715508000000,
      "closed_at": 1715509200000,
      "current_run_id": null
    }
  ]
}
```

### `GET /v1/agent-vms/{session_id}`

Same row shape as one element of the list, returned unwrapped:

```text
$ curl -sS -H "Authorization: Bearer $T" \
    http://127.0.0.1:7378/v1/agent-vms/0193f5b2-... | jq
{
  "session_id": "0193f5b2-...",
  "label": "fix flaky test in pipeline",
  "agent_kind": "claude",
  ...
  "current_run_id": "01941a02-..."
}
```

`404` with a tagged body if the session is unknown:

```json
{ "error": "unknown_session", "session_id": "0193f5b2-..." }
```

### Field semantics

- `session_id`, `vm_name`, `network_name`, `subnet_index`, `broker_urls`,
  `runtime_attached`, `status`: identical to the existing
  `AgentVmSessionInfo` (`src/protocol.rs`). `status` is the
  `AgentVmSessionStateStatus` enum, serialised snake-case (`starting`,
  `running`, …). The wire type is the authority; the HTTP view never
  introduces a parallel string.
- `label`, `agent_kind`, `agent_model`, `opened_at`, `closed_at`: joined
  from the `session` audit row. Timestamps are unix milliseconds
  (`UnixMillis`). `closed_at` is `null` until the session is closed.
  A row with `runtime_attached = false` and `closed_at != null` is a
  cleanly-shut-down session; one with both `false` and `null` is an
  orphan from a prior daemon process.
- `current_run_id`: latest `agent_run.run_id` for this session, or
  `null` if no run has started. The client follows
  `/v1/agent-runs/{id}` (slice 2) to fetch run state. Slice 1 does
  not inline run data. Reason: keeps the list endpoint cheap, defers
  the join shape until the agent-run resource exists, lets a UI poll
  one run by id without re-pulling every VM.

### Errors

All error responses are JSON objects with a machine-readable `error`
tag. No prose-only errors; clients branch on the tag, not on parsed
strings. Tags introduced in slice 1:

```text
401 → { "error": "missing_bearer" }
401 → { "error": "invalid_bearer" }
404 → { "error": "unknown_session", "session_id": "..." }
405 → { "error": "method_not_allowed", "allowed": ["GET"] }
500 → { "error": "internal", "message": "<one line, no secrets>" }
```

`internal` `message` is a one-line summary suitable for surfacing to a
human; it must never embed bearers, tokens, prompts, plan bodies, or any
secret material. The daemon's existing redaction discipline applies.

## Decisions taken (with reasons)

1. **Read-only in slice 1.** Mutations stay on the Unix socket. The Unix
   socket is already the write surface (`StartAgentVm`, etc.); duplicating
   it on HTTP would double the auth/audit surface for no slice-1 caller.
   Write endpoints land when a UI feature concretely needs them.

2. **Bearer in a file, not Host-header sniffing.** A 0600 file is the
   existing pattern (VM HTTP bearer); the daemon controls who can read
   it via filesystem permissions, which is the same trust boundary the
   socket already relies on. Host-header checks are weaker (a
   misconfigured proxy or a curl with `--resolve` defeats them).

3. **Static port via config, not ephemeral.** Operator requested
   bookmarkability. The cost is that two daemon instances on one host
   collide; this is already true for the Unix socket and accepted.

4. **Listener off by default.** Adding a network listener — even on
   loopback — is a step beyond the broker's v1 scope. Operators opt in
   by configuring `ui_http.bind`. Absent config = no listener, no
   bearer file, no behavioural change.

5. **No CORS, no SPA-from-`writd` serving.** The HTTP transport is a
   data API only. UIs (web SPA hosted elsewhere, TUI binary, MCP
   wrapper) live outside `writd`. Cross-origin browser reads would
   require a thoughtful auth story we don't need yet; same-origin or
   non-browser callers cover slice 1.

6. **`current_run_id` reference, not inlined run object.** Slice 1
   exposes only one resource (`agent-vms`). Inlining a sub-document now
   would commit the join shape before the joined resource exists.
   Reference + follow-up GET is the orthogonal default; slice 2
   introduces `/v1/agent-runs/{id}` with the full shape.

7. **Envelope `{ "agent_vms": [...] }` on lists, bare object on
   details.** Envelopes leave room to add `next_cursor`, `total`,
   warnings, or a schema-version field without breaking clients. The
   convention matches the existing wire protocol
   (`ServerMessage::AgentVmSessions { sessions }`).

8. **Tagged JSON errors.** Mirrors the broker's existing preference for
   typed `ServerMessage` variants over prose error strings. Lets `jq`
   scripts branch on `.error`.

9. **No `Access-Control-Allow-*` headers.** A `127.0.0.1` listener that
   returns wildcard CORS is fully readable from any website the user
   visits — the bearer is the only thing standing between a malicious
   page and the user's agent state, and a leaked bearer is a real risk
   if the daemon ever serves arbitrary browser origins. Keep the API
   un-CORS-ed; cross-origin consumers proxy.

## Implementation slices

In order. Each lands independently.

1. **HTTP listener scaffold.** New module `src/ui_http/` mirroring
   `src/vm_http/` shape: an `axum`-or-hand-rolled router started from
   `writd::main` when `ui_http.bind` is configured. Bearer write to
   `$XDG_RUNTIME_DIR/writ/ui-bearer` on start, bearer-check middleware,
   `405` and `401` machinery. Health-check route returns `{ "ok": true }`
   so the slice is end-to-end testable before any real route exists.

2. **`GET /v1/agent-vms` and `/v1/agent-vms/{id}`.** Handler joins the
   existing in-memory VM registry with `session` and the latest
   `agent_run` per session_id. Reuses the same query path
   `ListAgentVms` runs. Unit tests cover: list ordering, joined
   `closed_at` for closed sessions, `current_run_id` when present /
   absent, `404` on unknown id, `401` paths, `405` on `POST`.

3. **Config + docs.** Add `ui_http` to `config.rs` and to
   `docs/user_facing/configuration.md`. Add a one-paragraph section to
   `getting-started.md` showing the `curl` command and the bearer
   file. CLI help text on `writd` references the bearer file path.

(1)–(3) is the slice-1 MVP. Slice-2 work (`/v1/agent-runs`, `/v1/plans`,
`/v1/staged-pushes`, `/v1/tasks/{correlation_id}`) is its own design.

## Out of scope / deferred

- **Write endpoints.** No HTTP mutations. Plan decisions, staged-push
  rejections, VM start/stop stay on the Unix socket until a concrete
  UI feature demands HTTP writes.
- **Streaming / SSE / websockets.** Slice 1 is poll-only.
- **Pagination / filtering / sort.** Single-user local data volume is
  small. Add when a real consumer asks.
- **CORS / cross-origin browser support.** Out by design; revisit when
  a hosted UI is actually proposed.
- **TLS / non-loopback bind.** The listener is loopback-only. Exposing
  it on a LAN address would need TLS, a real auth story, and a fresh
  threat model; not on this critical path.
- **Schema versioning beyond a path prefix.** `v1` in the path is the
  whole versioning story for slice 1. A `?schema=` query param or
  `Accept: application/vnd.writ.v2+json` is fine to add later but
  unnecessary now.
- **OpenAPI / typed client generation.** Manual route docs in this file
  are enough at slice-1 scope. Add when consumers proliferate.
- **MCP wrapper.** Mentioned by the operator as a possible future
  consumer. Slice 1's job is to make wrapping cheap; the MCP server
  itself is a separate project.

## Open questions

1. **Should the bearer file path be configurable?** Default
   `$XDG_RUNTIME_DIR/writ/ui-bearer` matches the existing convention,
   but a `ui_http.bearer_path` override is cheap to add if operators
   want it (e.g. for non-XDG environments). Defer until a concrete
   need.

2. **Should `current_run_id` reflect "the run that is currently active"
   or "the most recent run, regardless of status"?** Slice 1 specifies
   "most recent run" because the resource is cheaper to query
   (single `agent_run.opened_at DESC LIMIT 1`) and the consumer can
   tell from the run's outcome whether it's still active. If a future
   UI wants the strict "active or null" semantics, that's a derived
   field added on top, not a change to this one.

3. **Should `404` on unknown id include the daemon's session-id format
   error tag, or just a generic `unknown_session`?** Slice 1 returns
   `unknown_session` for both malformed and absent ids. If consumers
   want to distinguish "you sent garbage" from "we don't have it" we
   can split into `malformed_session_id` + `unknown_session` without
   a wire break.
