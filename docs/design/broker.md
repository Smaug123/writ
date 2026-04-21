# Capability broker — design (v1)

## One-line summary

A local daemon that mints short-lived, per-request-scoped credentials for agents
(initially: GitHub App installation tokens) and keeps an append-only audit log
of every request, decision, and grant.

## Why this shape

The broker exists because we want three things at once:

1. **Ephemeral credentials.** The agent should never hold a long-lived secret.
2. **A policy chokepoint.** Some requests should be denied, narrowed, or
   escalated; the policy layer runs in one place.
3. **An audit log that is complete by construction.** If the only way to act
   on the world is to obtain a credential from the broker, the broker's log
   *is* the history. There is no parallel channel that could drift.

These combine into a capability-style design: the broker hands out reified
grants, one per request, each with a narrowed scope. The alternative — a
general-purpose "get me a token with all the permissions" endpoint plus a
separate audit log — is weaker on all three axes.

## Data model

Everything the broker does is a pure transformation of data. The core types
are a small, closed set:

```text
CapabilityRequest   — what an agent asks for
PolicyDecision      — Grant{narrowed_scope, ttl} | Deny{reason}
CredentialGrant     — what was actually minted (jti, session, scope, ttl)
ObservedEffect      — (deferred) side-effect observed on an external system
```

`CapabilityRequest` is a discriminated union over (service × action class):

```rust
CapabilityRequest::GitHub(GitHubRequest::ReadContents { repo })
CapabilityRequest::GitHub(GitHubRequest::WriteContents { repo })
CapabilityRequest::GitHub(GitHubRequest::ReadIssues    { repo })
// ...
```

Why a DU, not a polymorphic `Backend` trait with a `mint()` method? Because
the policy engine needs to *inspect* requests to decide. A trait object
exposes only its interface; a DU exposes its full shape, so the policy can
match on `WriteContents { repo: RepoRef { owner: "smaug123", .. }, .. }` and
say yes. The interpreter pattern: construct data, then interpret it.

## Sessions

A **session** is a broker-issued, server-side identity for one agent
conversation. Sessions exist so that every downstream artifact (requests,
grants, audit rows) can be linked back to a single conversation, even if the
agent process dies and restarts.

The broker issues the session ID at handshake time (the agent does not choose
it). Client-supplied metadata — agent model, free-form label — is stored
alongside but has no semantic weight; the session ID is the only thing the
broker trusts.

Sessions can be opened, closed, and listed. Closing is advisory and
idempotent — audit rows outlive their session.

## Credentials

The broker mints **GitHub App installation tokens** by signing a 10-minute JWT
with the app's RSA private key and exchanging it at
`/app/installations/{id}/access_tokens`. The POST body narrows both the
repository set and the permission set at mint time, so each grant carries the
minimum rights sufficient to perform the one requested action.

The broker does **not** wrap these in its own token format. It hands the raw
installation token to the agent and logs the grant. The token's `jti` (we
generate a UUID and keep it in the audit log; GitHub doesn't expose one
directly) is the correlation key for later reconciliation against observed
side effects.

The broker never persists the installation token itself. It lives in memory
for the duration of the response and then is gone. Only the grant record
(who, what, when, scope, expiry) is persisted.

## Secret storage

The app's private key is the only long-lived secret the broker holds. It
lives behind a `SecretStore` trait with two implementations:

- **File backend** — 0600-permissioned PEM file under
  `$XDG_DATA_HOME/agent-infra/` (or `~/.local/share/agent-infra/` fallback).
  Works on macOS and Linux. The default.
- **Keyring backend** — uses the `keyring` crate, which wraps macOS Keychain
  and Linux Secret Service. Opt-in via config.

This is the one place where an interface has more than one implementation on
day one, so a trait is justified (no speculative generality: it earns its
place). A third backend (e.g. HashiCorp Vault for shared team use) would
slot in behind the same trait.

## Policy engine

For v1, policy is a Rust `match` expression over `CapabilityRequest`. The
policy config is a struct with fields like `writable_repos`, deserialised
from a TOML file at startup. No DSL, no Cedar, no OPA.

The shape of policy is still unclear — once we have half a dozen real-world
policy decisions in our heads, we'll know what shape the externalisation
wants to take. Rushing to Cedar now is speculative generality. Rust's
exhaustiveness checking already forces us to think about every request
variant; that's a lot of what a policy DSL buys you.

## Transport

Local Unix socket at `$XDG_RUNTIME_DIR/agent-infra/broker.sock` (falling back
to a well-known path under the user's home). Filesystem permissions
(`0700` on the parent dir) are the auth boundary: if you can open the
socket, you are trusted.

Wire protocol is line-delimited JSON. Each line is one request, each line of
response is one reply. No framing beyond newlines. This is small enough to
hand-roll; `tokio::net::UnixListener` plus `serde_json` is the whole thing.

HTTP over a Unix socket (axum, tower) is tempting but buys framing we don't
need and a framework we definitely don't need. When we grow a remote
deployment story, we'll add HTTP as a second transport behind the same
handler functions.

## Audit log

SQLite at `$XDG_DATA_HOME/agent-infra/audit.db`. Schema:

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

CREATE TABLE grant (
  jti         TEXT PRIMARY KEY,
  request_id  TEXT NOT NULL REFERENCES request(request_id),
  session_id  TEXT NOT NULL REFERENCES session(session_id),
  scope_json  TEXT NOT NULL,
  issued_at   INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
```

Append-only. Timestamps are unix microseconds. JSON columns are the full
serialised core types — verbose but cheap, and they round-trip exactly, so
you can query the log and replay history if the broker's in-memory code
needs it.

No migrations framework yet — a single embedded `CREATE TABLE IF NOT EXISTS`
idempotent setup function.

## Commit authorship

Out of scope for the broker. The broker mints credentials; the client (git,
octocrab, whatever) decides how the commit is authored.

The default we encode in convention-for-now is **user-as-author, bot-as-pusher**:
the agent's local `git` uses the user's `user.name` / `user.email`; the push
is authenticated with the bot's installation token. This preserves
contribution-graph attribution while keeping the credential ephemeral.

Switching to bot-as-author later requires only a client-side change: the
agent runs `git commit --author="agent-infra-bot[bot] <id+...@users.noreply.github.com>"`.
No broker change is needed.

## Concurrency

The broker may receive concurrent requests (one Claude in each of several
tmux panes). Async (`tokio`) is used to multiplex; the core types and
policy engine are synchronous and pure.

SQLite is accessed under a single `Mutex<Connection>` for v1 — contention
is irrelevant at the expected request rate (≪1/s) and it keeps the code
simple. If we see contention, switch to a writer task with a channel.

## Non-goals (v1)

- **Webhook ingestion / side-effect reconciliation.** The grant log alone is
  ~80% of the audit value. Webhooks need a public ingress and tunnelling or
  polling; defer until the grant log is actually in use.
- **Ask-human flow.** Auto-grant or auto-deny only. If we hit a concrete
  request that needs human approval, add it as a third `PolicyDecision`
  variant then.
- **Policy DSL** (Cedar, OPA). Hardcoded `match` first.
- **Backend trait for credential sources.** GitHub App only. The trait
  appears with the second backend.
- **Remote access, multi-tenancy, team use.** Single-user local.
- **Web UI.** `sqlite3` at the CLI is the audit query tool.
- **MCP server wrapping.** Agents invoke the CLI via Bash; an MCP wrapper
  is a later convenience.

## Directory layout

```
src/
  lib.rs              re-exports
  core/
    mod.rs            ids, common types
    request.rs        CapabilityRequest, GitHubRequest, RepoRef
    decision.rs       PolicyDecision, GrantedScope
    grant.rs          CredentialGrant
  policy.rs           pure policy evaluation
  secret/
    mod.rs            SecretStore trait
    file.rs           file-backed impl
    keyring.rs        keyring-crate-backed impl
  audit.rs            SQLite audit log
  github.rs           GitHub App JWT + installation token exchange
  protocol.rs         wire protocol types (open_session, ...)
  server.rs           Unix socket listener + dispatch
  config.rs           TOML config loading
  bin/
    agent-broker.rs   daemon
    agent-identity.rs CLI client
docs/
  design/
    broker.md         this document
```

## Open questions

1. **Installation discovery.** If the user has multiple GitHub App
   installations (personal + org), which one handles a given repo? For v1
   we assume one installation and fail loudly otherwise; we can add a
   "find installation for repo" step later.

2. **Clock source.** `time::OffsetDateTime::now_utc()` is fine for audit
   timestamps but makes deterministic testing harder. Inject a `Clock`
   trait? Deferred until a test actually needs it.

3. **Token refresh for long-running agent sessions.** A single `git push`
   finishes in seconds, but a long test run might not. For v1 the client
   re-requests a fresh credential per action. If this is painful, add a
   "renew" operation that re-runs policy and mints a new token without a
   full new request.
