# writ — user docs

`writ` is a local capability broker for coding agents. Instead of giving an
agent a long-lived GitHub Personal Access Token, you run a small daemon
(`writd`) on your laptop. The agent asks the daemon for one credential per
action — "I want to push to `smaug123/writ`" — and the daemon mints a
short-lived, narrowly-scoped GitHub App installation token, hands it to the
agent, and writes a row to an append-only audit log.

The model is one credential per action, scoped to one repo and one
permission, expiring within an hour, and recorded in SQLite for later
inspection.

## Where to start

1. **[Getting started](getting-started.md)** — create a GitHub App,
   install the daemon, make your first request.
2. **[Configuration](configuration.md)** — `config.json` reference,
   default paths, secret-store options.
3. **[CLI reference](cli-reference.md)** — every flag for `writ` and
   `writd`, with examples you can paste into an agent prompt.
4. **[Policy](policy.md)** — when requests are granted, when they are
   denied, and how to expand the writable-repo allowlist.
5. **[Audit log](audit-log.md)** — the SQLite schema, useful queries,
   and how to reconstruct what an agent did.

## What writ is not (today)

- Not a remote service. It listens on a Unix socket; you must already
  trust anyone who can open that socket.
- Not multi-tenant. One daemon per user; one GitHub App installation per
  daemon.
- Not a webhook receiver. The audit log records what the broker minted;
  it does not (yet) reconcile against what GitHub actually saw.
- Not an interactive approval prompt. Every request is auto-granted or
  auto-denied by static policy.
- Not a backend abstraction layer. GitHub is the only supported
  credential source in v1.

If you need any of those, `writ` is the wrong tool today.
