# Policy

What the broker grants, what it denies, and how to change either.

## The decision rules

Policy is a pure function of the request and the `policy` block of
`config.json`. The v1 rules:

| Request                                  | Decision                                                                                  |
| ---------------------------------------- | ----------------------------------------------------------------------------------------- |
| `github metadata <repo>`                 | **Granted** — metadata is always read-only; GitHub forces it on every token.              |
| `github <thing> read <repo>`             | **Granted** on any repo the GitHub App installation can see.                              |
| `github <thing> write <repo>`            | **Granted** iff `<repo>` is on the `writable_repos` allowlist.                            |
| Anything for a repo not owned by the installation | **Denied** at the mint step before any GitHub call (see below).                  |

There are no other knobs. There is no per-session quota, no time-of-day
rule, no human-approval path. If you find yourself wanting one, tell the
maintainers — the shape of policy is intentionally not abstracted yet.

## Read access

If the GitHub App is installed on a repo, the broker will mint a
read-scoped token for it on request. The broker does not maintain its
own list of readable repos; the installation boundary is the
authority. If you want to revoke read access to a repo, uninstall the
App from it on GitHub.

## Write access

Writes require an explicit allowlist entry in `config.json`:

```json
"policy": {
  "default_ttl": 3600,
  "writable_repos": ["smaug123/writ", "smaug123/notes"]
}
```

Matching is **case-insensitive**. `Smaug123/Writ` in the config
authorises a request for `smaug123/writ`, and vice versa. (GitHub
itself treats those as the same repo; a case-sensitive check here
would deny writes that the rest of the stack would happily perform.)

A denial looks like:

```text
$ writ request "$SESSION" github contents write someone-else/thing
error: denied: write access to someone-else/thing is not on the writable-repos allowlist
```

To add a repo:

1. Edit `config.json`.
2. Restart `writd`.

There is no runtime reload. Restart is the supported way to change
policy.

## The installation-owner check

The broker requires `github.installation_owner` in `config.json`. Every
mint request is rejected before any GitHub call if the requested repo's
owner doesn't match (case-insensitive).

The reason is subtle. GitHub's
`POST /app/installations/{id}/access_tokens` takes an *unqualified*
repository list — just names, not `owner/name`. So if your installation
owns `smaug123/agent-infra` and an agent asks for
`openai/agent-infra`, GitHub would mint a token for *your* repo while
the audit log would record the request as `openai/agent-infra`. That's
exactly the kind of silent drift the audit log exists to prevent. So
the broker checks the owner up-front and refuses.

Practically: requests for repos in someone else's account fail with an
error. If you legitimately want the broker to act on multiple
installations, you'd need multiple `writd` instances today.

## Ceiling on grant lifetime

`policy.default_ttl` is a **ceiling**, not an exact lifetime. The mint
step compares it against GitHub's reported `expires_at` and refuses to
issue a token that would outlive it (with a 60-second clock-skew
tolerance).

GitHub installation tokens always live ~1 hour and the API will not
issue one for less. If you set `default_ttl: 300`, every mint will
fail. The valid range is **1–3600 seconds**, but in practice a value
≥ ~3540 is the only thing GitHub will satisfy.

The audit log's `expires_at` column is always the
backend-reported value, so it's the truth about when the token actually
stops working.

## What ends up in the granted scope

A grant is for **one repo**, with **one permission set**, plus
`metadata: read`. So `github contents write smaug123/writ` produces a
token whose permissions are exactly:

```json
{ "contents": "write", "metadata": "read" }
```

No `issues`, no `pull_requests`. Each action gets its own narrowly
scoped token.

If GitHub returns a token whose echoed permissions don't match what
policy asked for (silently widened *or* narrowed), the broker rejects
the response and records a `mint_failure` row instead of handing out a
mismatched token. This is one of the harder-to-misuse properties the
broker maintains.

## What's deliberately not here

- **No "ask the human" decision.** Auto-grant or auto-deny only. If you
  hit a request that should pop a prompt, that's a feature request, not
  a configuration change.
- **No DSL, OPA, or Cedar.** Policy is a Rust `match`. The plan is to
  see what real-world rules look like before externalising.
- **No per-action quotas or rate limits.** GitHub's own rate limits
  apply to the minted tokens.
