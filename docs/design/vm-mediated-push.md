# VM-mediated Git push

Design for letting a managed agent VM ask the host broker to push Git changes
without ever receiving a GitHub token.

## Goal

The guest sends an inert push intent to the broker. The host broker
authenticates the VM session, parses the intent into typed data, validates the
repository, branch, policy decision, remote ancestry, and object graph, then
uses the existing GitHub App contents-write path to perform the push from the
host side.

The GitHub installation token remains host-only. It may enter a host child
process environment for Git askpass, but it must never appear in a VM HTTP
response, guest environment variable, guest filesystem, CLI stdout, audit row,
or durable daemon-managed session state.

This is the push-side counterpart to the existing VM clone flow:

- guest convenience CLI: `writ-vm`;
- guest authority: only the VM broker bearer token;
- host policy decision: ordinary `GitHubRequest::Contents { access: Write }`;
- host GitHub credential: existing GitHub App installation-token minter;
- host Git execution: clean config, private work directory, askpass boundary.

## Non-goals

- No raw GitHub token in the guest.
- No direct network egress from the guest.
- No arbitrary host-side Git command forwarding.
- No force-push or branch deletion in the first push slice.
- No branch creation in the first push slice. Requiring an existing remote head
  gives the ancestry check a concrete base.
- No patch-application or broker-authored commit synthesis until bundle push is
  implemented and reviewed.

## Trust boundary

Treat every VM HTTP request as hostile even after bearer authentication. The
session bearer secret proves only that the request came through the managed VM
transport for that session. It does not prove that the original requested agent
is still running honestly.

The guest may lie about:

- repository and branch;
- expected remote head;
- new head;
- bundle contents;
- local Git configuration;
- whether the local checkout was originally created by `writ-vm`.

Therefore the broker must independently validate every field that matters
before using host authority.

## First protocol slice

Implement bundle push first. Patch and commit intents are later protocol
variants, not fields silently accepted by the first implementation.

Endpoint:

```text
POST /v1/git/push
Authorization: Bearer <vm-session-token>
Content-Type: application/vnd.writ.git-push-bundle
Content-Length: <bounded>

<u64 metadata_json_length, big endian>
<metadata_json bytes>
<raw git bundle bytes>
```

Metadata JSON:

```json
{
  "repo": "owner/name",
  "branch": "main",
  "expected_remote_head": "0123456789abcdef0123456789abcdef01234567",
  "new_head": "89abcdef0123456789abcdef0123456789abcdef"
}
```

The length prefix keeps the large binary bundle out of JSON without adding a
multipart parser. The broker enforces independent configured bounds for:

- complete VM HTTP request body;
- metadata JSON bytes;
- bundle bytes;
- host Git work directory lifetime;
- Git subprocess timeout.

The first slice accepts only SHA-1 object IDs because GitHub repositories are
SHA-1 today. If SHA-256 repository support becomes relevant, add an explicit
object-format field and reject unknown formats rather than guessing from string
length.

## Typed request data

Add VM-facing push types beside the clone types:

- `VM_GIT_PUSH_PATH`;
- `VmGitPushRequest`;
- `GitBranchName`;
- `GitObjectId`;
- `VmGitPushErrorResponse`;
- `VmGitPushReceipt`.

`GitBranchName` is a branch name, not a full ref. Parsing rejects empty names,
path traversal, control bytes, leading dash, ref lock suffixes, path components
ending in `.`, double slash, `..`, `@{`, `\`, bare `@`, and any name for which
`refs/heads/<name>` would fail `git check-ref-format --branch` equivalently.
Interior code constructs `refs/heads/<branch>` itself.

`GitObjectId` is a lowercase or uppercase 40-hex string normalized to lowercase
at the boundary.

The typed request maps to:

```text
CapabilityRequest::GitHub(
  GitHubRequest::Contents {
    access: GitHubAccess::Write,
    repo
  }
)
```

Policy remains the existing contents-write allowlist policy. Push does not add
a second policy language.

## Guest CLI

Add:

```text
writ-vm git push [--repo owner/name] [--branch name]
                 [--expected-remote-head oid] [--new-head oid]
                 [--git path]
```

Default inference is ergonomic only, not authoritative:

- `repo` may be inferred from `origin` if it is a canonical GitHub HTTPS remote;
- `branch` may be inferred from the current branch's upstream;
- `expected_remote_head` may be inferred from the upstream tracking ref;
- `new_head` may be inferred from `HEAD`.

If inference is ambiguous, detached, unborn, or non-GitHub, the CLI fails and
asks for explicit flags. The host still validates every inferred value.

The guest creates a bundle containing `expected_remote_head..new_head` and sends
it to the broker. The guest-side Git subprocesses must run with
`WRIT_BROKER_URL` and `WRIT_BROKER_TOKEN` removed from their environment, as the
clone path already does.

## Host push flow

For one authenticated VM push request:

1. Parse the length-prefixed request body into typed metadata and bounded bundle
   bytes.
2. Record `git_push_request` with the parsed intent, session ID, and received
   time before minting credentials or contacting GitHub.
3. Request a contents-write capability through the existing broker path.
   This records the ordinary capability request, policy decision, grant, or
   mint failure. If policy denies, record a denied push outcome and stop.
4. Create a private host work directory.
5. Initialize a temporary bare staging repository with clean Git config.
6. Write the bundle to the work directory.
7. Fetch the current remote branch into the staging repository using the
   host-only GitHub App token and askpass boundary.
8. Verify the fetched remote head equals `expected_remote_head`.
9. Verify the bundle is valid for the staging repository.
10. Fetch the bundle's advertised head into a temporary local ref.
11. Verify the temporary ref resolves to `new_head^{commit}`.
12. Verify `expected_remote_head` is an ancestor of `new_head`.
13. Record `git_push_attempt` with the exact repo, branch, old head, new head,
    grant correlation, and command plan before the external write.
14. Run `git push` from the host:

```text
git -c credential.helper= \
    -c credential.useHttpPath=true \
    push --porcelain --force-with-lease=refs/heads/<branch>:<expected_remote_head> \
    -- <repo-url> <temp-new-ref>:refs/heads/<branch>
```

15. Record `git_push_outcome`.
16. Return a receipt containing repo, branch, old head, new head, and a push
    audit identifier. The receipt contains no token and no raw stderr.

The host may use one token for remote inspection and push. The token is still a
single contents-write grant audited through the existing grant log.

## Ancestry validation

The first slice is a fast-forward update only:

```text
remote(expected_remote_head) --ancestor-of--> new_head
```

The broker checks this using host Git in the temporary staging repo after both
the remote branch and bundle commits are present locally.

Do not rely on the guest's claim that a bundle was made from the expected base.
Do not rely on `--force-with-lease` alone. The lease protects against a race
between validation and push; it is not the ancestry proof.

Do not use a shallow remote fetch until tests prove the resulting object graph
still supports the ancestry oracle. Correctness comes before minimizing fetch
bytes.

## Audit model

Push needs its own durable audit shape because the broker is no longer merely
minting a credential and handing it to a client. It is performing the external
write itself.

Add tables conceptually shaped as:

```sql
CREATE TABLE git_push_request (
  push_request_id     TEXT PRIMARY KEY,
  session_id          TEXT NOT NULL REFERENCES session(session_id),
  received_at         INTEGER NOT NULL,
  repo                TEXT NOT NULL,
  branch              TEXT NOT NULL,
  expected_remote_head TEXT NOT NULL,
  new_head            TEXT NOT NULL,
  decision            TEXT NOT NULL
);

CREATE TABLE git_push_attempt (
  push_attempt_id TEXT PRIMARY KEY,
  push_request_id TEXT NOT NULL REFERENCES git_push_request(push_request_id),
  request_id      TEXT NOT NULL REFERENCES request(request_id),
  grant_jti       TEXT NOT NULL REFERENCES grant_log(jti),
  planned_at      INTEGER NOT NULL,
  repo            TEXT NOT NULL,
  branch          TEXT NOT NULL,
  old_head        TEXT NOT NULL,
  new_head        TEXT NOT NULL
);

CREATE TABLE git_push_outcome (
  push_request_id TEXT PRIMARY KEY REFERENCES git_push_request(push_request_id),
  push_attempt_id TEXT REFERENCES git_push_attempt(push_attempt_id),
  completed_at    INTEGER NOT NULL,
  result          TEXT NOT NULL,
  github_status   INTEGER,
  message         TEXT NOT NULL
);
```

Exact column names can change during implementation. The current
implementation reifies the decision state through the presence or absence of
`git_push_attempt` and `git_push_outcome` rows rather than a
`git_push_request.decision` column, but these invariants must not change:

- `git_push_request` requires an open session and commits before minting or
  contacting GitHub.
- `git_push_attempt` commits after validation but before `git push`.
- If `git_push_attempt` cannot be recorded, the broker must not push.
- `git_push_outcome` may land after the session has closed.
- A crash after `git_push_attempt` and before `git_push_outcome` leaves an
  honest in-flight-at-crash state.
- A denied or validation-failed request has an outcome but no attempt.
- Raw tokens, raw bundle bytes, and raw patch contents are not stored in SQLite.

The existing capability grant log remains the proof of which GitHub App token
was minted. The push audit tables record what the broker did with that grant.

## Failure behaviour

Failures before `git_push_attempt` are non-effects. Return a structured VM Git
push error and record a terminal outcome when the request was parsed far enough
to have a `push_request_id`.

Failures after `git_push_attempt` may or may not have reached GitHub. Record the
outcome as precisely as possible:

- `pushed`;
- `lease_rejected`;
- `push_rejected`;
- `push_failed`;
- `audit_failed_after_push`.

If outcome recording fails after a push may have occurred, return a server error
and write a bounded stderr log line. Do not retry automatically; retries need a
fresh remote-head check and a fresh audit request.

## Later intent variants

After bundle push is implemented, add explicit variants:

- patch intent: guest sends a base commit plus patch; host applies it in a
  temporary checkout, creates the commit, then uses the same push validator;
- commit intent: guest sends a structured tree/commit description; host writes
  objects and creates the commit.

Both variants should desugar to the same internal primitive:

```text
ValidatedPush {
  repo,
  branch,
  expected_remote_head,
  new_head,
  staging_ref
}
```

That keeps the external write path small and shared.

## Incremental implementation stages

1. Typed push wire types and request parser, with property tests.
2. Push audit migrations and append-only invariants.
3. Host-side push planner and executor using fake Git and local Git tests.
4. VM HTTP `POST /v1/git/push`, wired to policy and audit.
5. Guest `writ-vm git push` command.
6. User-facing docs and a fake-GitHub proof script.

Each stage must have its own correctness oracle. No stage should introduce a
path that can perform a host-side GitHub write without a prior durable
`git_push_attempt` row.
