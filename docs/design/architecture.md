# writ — architecture (current state)

**This is the canonical map of what writ is *now*.** It supersedes the
directory-layout and schema sections of the older design docs, which are
slice-by-slice journals of *how we got here* rather than descriptions of the
system as it stands. Those journals are retained — see
[Appendix: design journals](#appendix-design-journals-historical) — but read
this first.

> **Maintaining this doc.** Edit it *in place* when the architecture changes.
> Do **not** append "and then slice X added…" notes; that idiom is exactly
> what left the design docs describing the repo's history instead of its
> shape. If a change alters a subsystem's guarantees, primitives, or
> invariants, change the relevant subsystem page here in the same PR. Detailed
> rationale for a change belongs in a dated `docs/plans/` slice; the *result*
> belongs here.

The current module layout has real structural debt (a flat ~40-module root
crate and several 2.5–3.7k-line god-files). That debt is catalogued, with a
sequenced remediation, in
[`../plans/2026-07-17-architecture-refactor-backlog.md`](../plans/2026-07-17-architecture-refactor-backlog.md).
This document describes the system as it *actually behaves* today, using the
domain subsystems it *should* be organised around, and points at the files
each subsystem currently spans.

---

## 1. What writ is, in one paragraph

`writ` is a local capability broker for coding agents. `writd` is a daemon; an
agent asks it for one narrowly-scoped, short-lived credential per action
("push to `smaug123/writ`"), and every grant is recorded in an append-only
SQLite audit log. Two invariants give the system its shape:

1. **The audit log is complete by construction.** The *only* way for an agent
   to affect the outside world is to obtain a grant from the broker, so the
   broker's log *is* the history. There is no parallel channel that could
   drift.
2. **The guest is treated as compromised.** The most capable agents run inside
   a sandboxed Apple-`container` Linux VM with no host mounts and no network
   egress. Every external effect (git, Nix substitution, model APIs, signing)
   crosses a host broker endpoint that **independently re-validates every
   field** — repo, branch, ancestry, object graph — before spending host
   authority. Guest-side tooling is ergonomic sugar, never the authority
   boundary.

Everything below is a consequence of holding those two invariants at once.

## 2. Workspace crates

| Crate | Role | Depends on |
|---|---|---|
| **`writ-core`** (`crates/writ-core/`) | Pure data core: request/decision/grant types, ids, capability sets, the PF/network model, SSHSIG signing types. No dependency on the rest of writ. | — |
| **`writ-vm-git`** (`crates/writ-vm-git/`) | Host↔guest wire types for VM-mediated git (clone/push request shapes, object-id/branch parsing). | `writ-core` |
| **`writ-agent-run`** (`crates/writ-agent-run/`) | The managed-agent run contract (prompt/output/correlation-id types) plus the agent process-runner. Shared by host, guest, and bailiff; re-exported as `writ::agent_run`. | `writ-core` |
| **`writ-vm-client`** (`crates/writ-vm-client/`) | The guest-side `writ-vm` command surface that runs inside the agent VM. Links no host-only dependency — enforced by the crate graph. Re-exported as `writ::vm_client` under the `vm-client` feature. | `writ-core`, `writ-vm-git`, `writ-agent-run` |
| **`writ-audit`** (`crates/writ-audit/`) | The append-only SQLite audit log: schema/migrations, the typed row DAOs, and two-phase write helpers. Re-exported as `writ::audit` under the `host` feature. | `writ-core`, `writ-agent-run`, `writ-vm-git` |
| **`writ`** (root) | The imperative shell: the daemon and all host effects. Binaries `writd`, `writ`, `writ-vm`, `writ-agent-vm-runner`, `writ-agent-vm-pf-helper`. | `writ-core`, `writ-vm-git`, `writ-agent-run`, `writ-vm-client` (opt), `writ-audit` (opt) |
| **`bailiff`** (`crates/bailiff/`) | A plan-workflow product (submit → decide → review → implement) built *on top of* writ. | `writ` |

Dependency direction is strict: `bailiff` → `writ` → {`writ-vm-git`,
`writ-agent-run`, `writ-vm-client`, `writ-audit`, `writ-core`}. `writ` never
depends on `bailiff`; `writ-vm-client` (the guest surface) never depends on
`writ`.

Almost all of the accretion lives inside the root `writ` crate, which is a flat
list of ~40 modules gated by `#[cfg(feature = "host")]`. The subsystems in §4
are the *domain* structure that flat list should be read through; the refactor
backlog proposes promoting the strongest of these boundaries to real crates.

## 3. Feature flags

- **`host`** (in `default`) — the daemon, CLI, and all host-side deps (SQLite,
  keyring, GitHub/JWT, hyper, compression), plus `reqwest` for its own outbound
  HTTP (GitHub minter, VM proxies) and `writ-vm-git` for the shared wire types.
- **`vm-client`** — the guest-side surface. The `writ-vm` binary builds with
  `--no-default-features --features vm-client` and must not pull in host deps.

The two surfaces are **disjoint**: `host` does not enable `vm-client`, and the
guest client is its own crate (`writ-vm-client`), pulled in only under the
`vm-client` feature — so a `--features host` build never compiles it or its
`reqwest`-for-guest. Host-dep-freedom is therefore a **crate-graph property**: a
host dependency creeping into the guest surface is a compile error, not a lint.
The shared host↔guest wire contract — the VM-git request/response types and the
broker/pre-warm env-var *names* — lives in `writ-vm-git`; the
`pub use writ_vm_git as vm_git` re-export is gated on `any(host, vm-client)` so
both surfaces get it.

`writ-vm-client` is a workspace member, so its tests run under the default
`cargo test`. `writ`'s own remaining vm-client surface is just the `writ-vm`
binary; CI exercises it with
`cargo test -p writ --no-default-features --features vm-client --lib --bins`.

## 4. Cross-cutting invariants

These hold across subsystems and are the reason to trust the whole:

- **Interpreter pattern, not traits.** `CapabilityRequest` is a discriminated
  union; `policy::decide` is a pure `match` producing a `Decision`; the shell
  then mints. Policy *inspects* request data, so it is a DU, not a `Backend`
  trait with a `mint()` method (`policy.rs:118`, `crates/writ-core/src/core/request.rs:11`).
- **Parse, don't validate, at every wire boundary.** Inbound messages carry
  `#[serde(deny_unknown_fields)]`; scalars are newtypes with fallible
  constructors (`TtlSeconds`, `Sha256Hex`, `NotesRef`, `PfInterface`,
  `GitObjectId`, `GitCommitSha`). Interior code receives proof, not promises.
- **Server-issued identity.** Session ids are minted by the broker
  (`SessionId::new()` at `server.rs:203`), never chosen by the client. Grant
  authority (`AuthorizedMint`, `policy.rs:52`) has private fields and no public
  constructor, so it cannot be forged outside the policy engine.
- **Transport auth = filesystem permissions.** The Unix socket's parent dir is
  forced/checked to `0700` and refuses group/world bits (`server.rs:823`). If
  you can open the socket, you are trusted.
- **Two-phase, append-only audit.** The request row commits *before* any
  network mint; the outcome row (grant or mint-failure) follows. A minted token
  whose grant fails to record is never delivered (`server.rs:533`). A DB at a
  higher/mismatched schema version than the binary is refused, not opened
  (correctness over availability).
- **Re-validation on the guest boundary.** Nothing the guest claims is trusted:
  the broker re-derives object graphs from bundle bytes, re-checks branch tips
  before and after replay, re-authorises repos against the session's grants,
  and reads guest-writable files with `O_NOFOLLOW` + fstat + byte caps.

---

## 5. Subsystems

Each subsystem below lists **Purpose · Lives in · Primitives · Guarantees ·
Invariants · Neighbours**. File:line pointers are entry points, not
exhaustive.

### 5.1 writ-core — the pure functional core

**Purpose.** The dependency-free foundation: writ's closed set of pure data
types, so editing the application layers doesn't recompile the core.
("Dependency-free" means no dependency on the rest of writ, not zero external
crates.)

**Lives in.** `crates/writ-core/src/core/` (nine submodules) plus three
low-level host helpers (`bearer`, `process_spawn`, `telemetry`). Re-exported
from the root crate as `writ::core` (`lib.rs:37`).

**Primitives.** UUID newtypes via the `uuid_id!` macro — `SessionId`,
`RequestId`, `Jti`, `ApproveAttemptId` (`core/mod.rs:37`); `UnixMillis`
(`core/mod.rs:105`); `RepoRef`/case-folded `CanonicalRepoRef`
(`core/mod.rs:144`); `CapabilityRequest`/`GitHubRequest`
(`core/request.rs:11,22`); `PolicyDecision`, `GrantedScope`, bounded
`TtlSeconds` (≤ `GITHUB_INSTALLATION_TOKEN_MAX_SECONDS`=3600)
(`core/decision.rs`); `CredentialGrant` (deliberately omits the token string,
`core/grant.rs:10`); `CapabilitySet`; `Sha256Hex`; `NotesRef`;
`SshKeyFingerprint`/`SshSignature`; the entire Apple-container network model
(`AgentNetwork`, `Ipv4Cidr`, `PfRuleset`, `render_pf`) in `core/agent_vm.rs`;
and the `NetworkHealth` reachability enum (`core/network_health.rs`).

**Guarantees.** `core` is pure — no IO. The only host-only surface is
`process_spawn::spawn_async`, gated behind the crate's own `host` feature (which
alone pulls in tokio).

**Invariants.** Make-illegal-states-unrepresentable: `Metadata` requests carry a
one-variant `MetadataAccess::Read`; private constructors (`AgentNetwork::new`,
`CanonicalRepoRef`) carry proof; parse-don't-validate constructors reject bad
input (`PfInterface::new` rejects pf.conf metacharacters, `Ipv4Cidr::new`
rejects host bits, `TtlSeconds::new`). Load-bearing `deny_unknown_fields` on
`GitHubPermissions` and `CapabilitySet`.

**Neighbours.** Consumed by the root crate's host modules and by `writ-vm-git`.
`bailiff` does *not* depend on `writ-core` directly (it goes through `writ`).

### 5.2 Broker daemon — transport, protocol, sessions, policy, config

**Purpose.** The `writd` process: a single Unix-socket broker that opens/closes
sessions, runs each capability request through the pure policy chokepoint, mints
a short-lived token, and audits every step. It also hosts staged-push
approve/reject/reconcile and agent-run/agent-VM orchestration.

**Lives in.** `server.rs` (881 lines: transport, dispatch, connection handling)
plus `server/staged_push.rs` (1772: the list/show/reject/approve/reconcile
approval handlers) and `server/run_agent.rs` (569: the `RunAgent` handler and
its VM-dispatch path); `server/` also holds the test submodules. `protocol/`
(`mod.rs` 2072 for the `ClientMessage`/`ServerMessage` DUs + `views.rs` 246 for
the payload types they carry),
`broker_session.rs`, `broker_protocol.rs`, `policy.rs`,
`config/` (`mod.rs` ~2960 + `audit_dir.rs`), `bin/writd.rs`, `bin/writ.rs` (the
operator CLI verbs).

**Primitives.** Wire DUs `ClientMessage` (`protocol/mod.rs:38`, tagged +
`deny_unknown_fields`) and `ServerMessage` (`protocol/mod.rs:304`, tagged, not
`deny_unknown_fields` since outbound); `Decision`/`AuthorizedMint`
(`policy.rs:97,52`); config root `DaemonConfig` (`config/mod.rs`,
`deny_unknown_fields`): `github_apps`, `policy`, `agent_vm?`, `secret_store`,
`socket_path?`, `audit_db?`, `ui_http?`, `run_agent?`.

**Entry points.** Accept loop `serve_broker_with_agent_vm` (`server.rs:843`,
task-per-connection) → `handle_connection` (`server.rs:662`) →
`dispatch_message_with_agent_vm` (`server.rs:189`, the big `ClientMessage`
match) → `dispatch_capability`/`request_capability` (`server.rs:438`); the
staged-push arms delegate to `server/staged_push.rs`.

**Guarantees.** Filesystem-permission transport auth (§4); two-phase audit
ordering (§4); each connection line is bounded (`MAX_LINE_BYTES`,
`server.rs:614`) with a 60s idle timeout.

**Invariants.** Server-issued session ids; policy exhaustiveness by `match`
(`decide`, `policy.rs:118`; `is_write`, `policy.rs:148`); config validated at
load (`deny_unknown_fields` throughout plus explicit `validate()`).

**Neighbours.** Calls audit, credential minting, the git pipeline
(staged-push), and the VM sandbox (`AgentVmDaemon`). Called by the `writ` CLI
over the socket; guests reach the *separate* `vm_http` surface (§5.6), not this
one.

**Current-state note.** The host transport is still line-delimited JSON over a
Unix socket, as `broker.md` describes — but that doc's "add HTTP later"
prediction has landed as *three* additional transports it never documents: the
guest-facing `vm_http` HTTP listener (§5.6), the read-only `ui_http` JSON API
(§5.10), and a broker-in-VM mode (`writd broker`, `broker_entrypoint.rs`) that
binds a fixed TCP port and negotiates `BROKER_PROTOCOL_VERSION=2` via a
ready-file handshake (§5.5). The staged-push approval subsystem and the
run-agent orchestration have been split into `server/staged_push.rs` and
`server/run_agent.rs`; `server.rs` is now ~880 lines of transport, dispatch, and
connection handling — the shared output-capture helper (`capture_stream_capped`,
also used by `agent_vm_daemon::materialize`) stays at the module root.

### 5.3 Credential minting & secrets

**Purpose.** Mints short-lived, narrowly-scoped GitHub App installation tokens;
produces SSHSIG commit/run signatures; brokers ChatGPT/OpenAI OAuth for model
proxying; and stores the few long-lived secrets those flows need.

**Lives in.** `github.rs` (1832), `signing.rs`, `git_commit_sign.rs`,
`openai_chatgpt_auth.rs`, `secret/` (`mod.rs`, `file.rs`, `keyring_store.rs`).

**Primitives.** Per-`AgentKind` App registry `GitHubAppRegistryConfig`
(`github.rs:88`, non-empty by construction); `MintRequest`/`MintResponse`
(`github.rs:636`); `MintedToken` with redacting `Debug` (`github.rs:148`);
`SecretStore` trait + `FileSecretStore`/`KeyringSecretStore`
(`secret/mod.rs:94`); `WritSigningKey`/`WritVerifyingKey` (`signing.rs:82,269`);
redacting OAuth `ChatgptAuthBundle`/`ChatgptTokens` (`openai_chatgpt_auth.rs`).

**Entry points.** `GitHubMinter::mint_for_agent` (`github.rs:278`);
`WritSigningKey::sign`/`sign_commit` (`signing.rs:127`); `git_commit_sign`
canonical-commit signing (`git_commit_sign.rs:117`);
`ChatgptOauthAuthority::current_headers` (`openai_chatgpt_auth.rs:525`).

**Guarantees.** Token TTL bounded at mint (reject if GitHub's `expires_at`
exceeds `issued_at + ttl + 60s`, `github.rs:477`); the raw token is **never
persisted** — only the `CredentialGrant` record is. GitHub failures collapse to
`MintError::ApiError` with a truncated body.

**Invariants.** JWT is RS256, `iat` backdated 60s, `exp = now+8min` under
GitHub's 10-min ceiling; scope is narrowed in the POST body to a single repo +
exact permissions, then **echo-verified** against GitHub's response
(owner/repo-set/permissions equality, `github.rs:345,427,454`). The
`SecretStore` is the only long-lived-secret home. Outbound HTTP clients that
carry a live secret refuse redirects so a 3xx `Location` can't exfiltrate it
(ChatGPT refresh client, `openai_chatgpt_auth.rs:395`; and the shared VM proxy
client, §5.6).

**Neighbours.** Held by `BrokerState` (`server.rs:94`); called by the
capability path and staged-push promote; signing consumed by the git pipeline;
OAuth headers consumed by the VM model proxies.

**Current-state note.** `broker.md` describes a *single*-App minter; it is now a
per-`AgentKind` registry, and commit/run SSHSIG signing and full ChatGPT OAuth
rotation are new since that doc.

### 5.4 Audit log & boot reconciliation

**Purpose.** The SQLite system-of-record for *all* broker activity — sessions,
requests, grants/mint-failures, and every effect path (git-push, proxies,
nix-cache, flake-provision, agent runs). Complete by construction (§4).

**Lives in.** The `writ-audit` crate (`lib.rs`, `schema.rs`, `migrations/`,
`session.rs`, `grant.rs`, `git_push.rs` + `git_push/`, `agent_run.rs`,
`proxy_table.rs`, `nix_binary_cache`-audit `nix_cache.rs`, `flake_provision.rs`,
…), re-exported as `writ::audit`. Its boot-time reconciler, `boot_reconcile.rs`,
stays in `writ` — it *drives* the audit DAOs but also needs the git pipeline
(`git_push_staging`), so it is an orchestrator, not audit storage.

**Primitives.** `AuditLog { conn: Mutex<Connection> }`
(`writ-audit/src/lib.rs`); refuse-to-open errors
`SchemaTooNew`/`SchemaHistoryMismatch` (same); `Migration { version, name, sql }`
+ `MIGRATIONS` (`writ-audit/src/schema.rs:38,57`); generic proxy row types
(`proxy_table.rs`); git-push state enums (`writ-audit/src/git_push.rs`);
`ReconcileReport`
(`boot_reconcile.rs:55`).

**Schema.** ~24 live tables across **7 migrations** (`audit/schema.rs`), versus
the 4 tables `broker.md` documents. Version is tracked in a `schema_version`
*registry table* — **not** `PRAGMA user_version` as `broker.md` implies.

**Guarantees & invariants.** Each migration runs its DDL + version-bump in one
`BEGIN IMMEDIATE` transaction, so a mid-migration crash resumes cleanly; a
down-rev/mismatched DB is refused (§4). At-most-one-outcome per request is
enforced by SQL triggers (`grant_excludes_mint_failure` /
`mint_failure_excludes_grant`), plus forward-only triggers on the approve-attempt
ledger. Timestamps are `UnixMillis` integers. Boot reconciliation
(`reconcile_pending_approve_attempts`, `boot_reconcile.rs:95`) recognises
"in-flight at crash" rows and either recovers or flags them uncertain.

**Neighbours.** Written by the broker core and every effect handler; read by
`ui_http`/CLI and by boot reconcile at daemon startup.

### 5.5 Agent-VM sandbox — lifecycle, firewall, broker-in-VM

**Purpose.** Run an agent inside an Apple-`container` Linux VM given only tmpfs
mounts and no NAT egress, so it can touch neither the host filesystem nor the
network directly. A broker (the §5.6 HTTP surface) is the sole bridge for
external effects, reachable only on a whitelisted broker port/IP.

**Lives in.** `agent_vm_lifecycle.rs` (2405) + `agent_vm_lifecycle/` (the
`parse`/`state_store`/`network_health`/`invocation`/`plan` submodules —
`invocation` holds the `ProcessInvocation` execution primitive, `plan` the
`AgentVmSessionPlan` start-step state machine + invocation builders),
`agent_vm_daemon.rs` (2602) + `agent_vm_daemon/`, `agent_vm_firewall.rs`,
`broker_vm.rs` (2636), `broker_vm_runner.rs`, `broker_entrypoint.rs`,
`broker_session.rs`, `broker_log_forwarder.rs`, `process_supervisor.rs`,
`bin/writ-agent-vm-runner.rs`, `bin/writ-agent-vm-pf-helper.rs`. The PF ruleset
model itself lives in `writ-core` (`core/agent_vm.rs`).

**Topology.** *Host:* the `writd` daemon (`AgentVmDaemon`), an unprivileged
lifecycle runner (`writ-agent-vm-runner`, owns Apple-`container` ordering), and
a root PF helper (`writ-agent-vm-pf-helper`, pins `/sbin/pfctl` +
`/sbin/ifconfig`, trusts no caller-supplied path). *Guest:* the agent VM, and —
under `BrokerPlacement::Vm` — a dedicated broker VM running `writd broker` on a
shared `--internal` network. `process_supervisor.rs` is the shared subprocess
core (timeout + process-group SIGKILL).

**Primitives.** `AgentVmSessionPlan`/`StopPlan`
(`agent_vm_lifecycle.rs:160,193`); `AgentVmSessionState`/`Store`
(`agent_vm_lifecycle/state_store.rs`); the start-step state machine
`AgentVmStartStep` (ProbeNetworkAbsent → CreateNetwork → InspectAndValidate →
InstallFirewall → ProbeVmAbsent → StartVm → InstallGuestIpv6Deny →
ProbeAndValidateGuestIpv6 → ReleaseGuestCommand); firewall
`SessionFirewallInstall`/`Removal`/`PfctlInvocation` (`agent_vm_firewall.rs`);
broker `BrokerVmPlan`/`BrokerSessionSpec`/`GuestAbsPath` (`broker_vm.rs:186`,
`broker_session.rs:63,24`).

**Guarantees.** No egress except the broker: host placement via PF default-deny
(whitelist broker ports, then `block return`); VM placement by topology
(`--internal`, no NAT). IPv6 isolated with a backstop guest deny. The agent VM
gets no host mounts (tmpfs only); only the broker VM bind-mounts
session/secrets(ro)/audit. Idempotent restart: `Probe*Absent` steps refuse to
touch infra this call didn't create. On boot, `reconcile_one_session` closes
broker authority in the audit log *before* unbounded teardown, and the daemon
refuses to start while an obligation remains (`agent_vm_daemon.rs:1678`).

**Invariants.** Fail-closed firewall (`ensure_pf_enabled` +
`ensure_session_bootstrap_anchor` before install; `ensure_session_anchor_empty`
after remove). Guest-compromised re-validation: the PF helper self-discovers
deny interfaces from the gateway; the broker reads guest-writable ready/log
files with `O_NOFOLLOW` + fstat-regular + byte caps
(`broker_vm_runner.rs:284`); the broker port is re-checked against the config
range; a protocol-version gate rejects a stale broker image. Session state is
persisted as a versioned record under a single-owner file lock.

**Neighbours.** Hosts the §5.6 HTTP endpoints; feeds the git-push pipeline;
shares the audit log. Design detail (empirical isolation findings, PF strategy)
lives in the `apple-container-agent-vm.md` journal.

### 5.6 VM broker HTTP surface & Nix provisioning

**Purpose.** The host-side, VM-facing HTTP surface every guest effect must
cross. The guest reaches only these localhost-subnet routes; each re-validates
the request and injects host-held credentials before touching the outside
world. Nix provisioning lets a no-egress guest still realise a locked flake:
the broker fetches and content-addresses the flake's inputs host-side, then
serves them through a substituter the guest trusts, keeping evaluation offline.

**Lives in.** `vm_http/` (`mod.rs` [2832 lines], `claude_proxy.rs`,
`openai_proxy.rs`, `git_clone.rs`, `git_push.rs`, `flake_provision.rs`,
`nix_cache.rs` + `nix_cache/`, `agent_runs.rs`, `proxy_common.rs`) plus the
Nix domain modules `nix_binary_cache.rs` (2749), `flake_lock.rs`,
`flake_materialize.rs`, `flake_provision.rs`, `flake_provision_from_mirror.rs`.

**Endpoint map** (dispatch `route_authenticated_vm_http_request`,
`vm_http/mod.rs:1350`): `GET /v1/session`; `/v1/nix/cache/*` &
`/v1/nix/prewarm/*`; Claude proxy `/v1/messages`, `/v1/messages/count_tokens`,
`/v1/models/*`; OpenAI proxy `/v1/responses`, `/v1/models`; `POST /v1/git/clone`;
`POST /v1/git/push`; `POST /v1/nix/flake/provision`; `GET/POST
/v1/agent-runs/{id}/config|outcome`. Path literals are pinned in
`crates/writ-vm-git/src/lib.rs:20`.

**Nix binary cache — model vs service (two modules).** Two different *layers*,
now named apart (they were both `nix_cache` until backlog Slice 2):
- **`src/nix_binary_cache.rs`** is a pure host-side **domain library** — the
  primitive types (`NixStorePath`, `NixNarInfo`), Ed25519 signature
  verification, NAR hashing, and the admission parsers. Zero HTTP code.
- **`src/vm_http/nix_cache.rs`** is the imperative **HTTP shell** —
  `VmHttpNixCacheService` serves the binary-cache protocol, does archive IO and
  upstream proxying, and audits, importing the parsers/types from
  `crate::nix_binary_cache`.

  Data-model-plus-crypto vs. the network service that uses it.

**Primitives.** Proxy: `ProxyRequestFields`, `ProxyFetch`, `UpstreamAuth`
(`proxy_common.rs`). Flake: `FlakeLock`/`FlakeProvisionPlan`
(`flake_lock.rs:49,95`), `MaterializedFlake` (`flake_materialize.rs:46`),
`FlakeProvisionReport` (`flake_provision.rs:76`). Nix cache: `NixNarInfo`,
`NixTrustedPublicKeys` (`nix_binary_cache.rs:50,68`), route enum `VmNixCacheRoute`
(`vm_http/nix_cache/route.rs:28`).

**Guarantees.** The guest reaches only these routes (subnet auth). Each
re-validates: the nix cache admits only signed narinfos and verifies NAR bytes
before relay; flake provision re-derives the checkout from the broker's own
retained mirror and re-authorises the repo against this session's grants
(`vm_http/flake_provision.rs:120`). Model credentials are injected host-side
only: guest auth is stripped and the host key attached from the secret store.

**Invariants.** Proxy clients refuse redirects
(`reqwest::redirect::Policy::none()`, `proxy_common.rs:708`) so a `Location`
header can't leak the live host key cross-origin. Per-route byte caps
(`MAX_VM_HTTP_BODY_BYTES=64K`, outcome 4M, streamed-response caps). Guest fields
(e.g. a flake request's `(repo, rev)`) are re-validated, never trusted;
store-hash/NAR-name inputs are parsed into strict typed enums.

**Neighbours.** Mounted by the in-VM broker (`VmHttpServices`, all
`Option<Service>`); proxies use minting for creds; git push feeds §5.7; clone
retains a `(repo, rev)` mirror (§5.8) that flake provision reuses; every route
is audited.

### 5.7 Git-push pipeline — host-side re-validation & replay

**Purpose.** Because the guest is untrusted, the broker never forwards the
guest's bundle to GitHub. It persists the bundle host-side and, at approval
time, **re-derives the object graph itself**: unbundle into an isolated repo →
`git rev-list` ancestry walk → re-upload every blob/tree/commit under the App
identity via GitHub's Git Data API → move the ref. Nothing the guest claims
(tip SHA, ancestry, object bytes) is trusted.

**Lives in.** `git_push_staging.rs` (1503), `git_push_approve.rs` (2389),
`git_push_promote.rs` (1782), `git_push_trailers.rs` (the commit-trailer
vocabulary), `git_push_replay_object_parse.rs` (2009),
`git_push_replay_object_source.rs`, `git_push_replay_walker.rs` (1485) +
`git_push_replay_walker/`, `clean_git.rs` (hardened git subprocess helpers).

**Stage flow.**
1. **Stage** (`git_push_staging.rs:151`): the guest POST persists `bundle` +
   `entry.json` receipt atomically (scratch → fsync → rename, idempotent by
   `RequestId`). No GitHub contact.
2. **Approve** (`git_push_approve.rs:254`): stand up a fresh `0700` bare staging
   repo, fetch prereqs, unbundle, gate that the tip is a commit, plan the walk,
   replay, re-check the lease. Split at `PreparedApprove::commit` — the only
   step that moves a GitHub branch.
3. **Promote** (`git_push_promote.rs:432,518`): upload the closure via
   `replay_commits`, then issue the single `PATCH` under `force=false`.
4. **Replay/walk** (`git_push_replay_walker.rs:319`): per-commit → tree closure
   → blob re-upload.

**Primitives.** `StagedEntry`/`GitPushStagingStore` (`git_push_staging.rs`);
parsed `StagingCommit`/`StagingTree` + `ParseObjectError`
(`git_push_replay_object_parse.rs`); plan types `FastForwardPlan`,
`BranchCreationPlan`, `ShaMap` (`git_push_replay_walker.rs`); the object-source
abstraction `trait GitObjectSource` with production `CatFileObjectSource`
(`git_push_replay_object_source.rs`).

**Guarantees.** The branch tip is re-checked via `get_branch_head` *before*
replay, *after*, and once more inside `commit_prepared_promotion`, all with
`force=false`; ancestry is proven by rev-list, not by guest claims. Objects
reach GitHub only as App-identity re-uploads (optionally SSH-signed for the
Verified badge), never the guest's raw bytes.

**Invariants.** Parse-don't-validate on object bytes: the parser rejects
anything `git fsck` would (tree sort order, `.git`/name aliases, bad tz, NUL) so
an invalid object can't launder into a valid one. Fast-forward vs
branch-creation is decided by a boundary rev-list; shallow/disjoint/diverged/
rewind histories are refused. Byte caps bound subprocess stdout
(`REV_LIST_STDOUT_BYTE_CAP=16 MiB`, `SMALL_STDOUT_CAP=4 KiB`); a per-object read
deadline + `max_object_bytes` bound `cat-file`, with poison + `killpg` on
timeout.

**Neighbours.** Fed by `vm_http/git_push.rs`; uses `github_git_db` (§5.8) for
authority; hardened subprocesses via `clean_git`; audit/mint rows are written by
the caller (`server.rs`); `boot_reconcile` recovers stranded carriers.

**Current-state note.** Entirely absent from `broker.md`. The former
`git_push_replay.rs` held a vestigial staging-repo bring-up path
(`GitPushReplayPlan`/`ingest_bundle`/`prepare_staging_repo`) constructed only by
its own tests — a dead duplicate of the live `git_push_approve.rs` bring-up. It
was deleted; its one live export, the commit-trailer vocabulary
(`TrailerSource`/`TrailerKey`/`TrailerValue`), moved to `git_push_trailers.rs`.

### 5.8 Git storage & transport

**Purpose.** Four host-side components under the pipeline:
- **`github_git_db.rs`** (2538) — a typed client for GitHub's Git Database API
  (blobs/trees/commits/refs), used to re-create bundle commits object-by-object
  under the App identity so published commits land Verified.
- **`notes_repo.rs`** (2060) — a shared bare-repo wrapper (used by both writ and
  bailiff) for attaching/reading git notes that carry signed run envelopes.
- **`vm_git_bundle.rs`** (1760) — plans/executes `git clone --mirror` + `git
  bundle create` for a guest clone request.
- **`vm_git_mirror_cache.rs`** (951) — a `(repo, rev)`-keyed on-disk cache of
  bare mirrors so flake provisioning reuses a mirror instead of re-fetching.

**Primitives.** `GitDataClient`/`CommitRequest`/`CommitIdentity`/`TreeEntry`
(`github_git_db.rs`); `NotesRepo`/`WriteOutcome` (`notes_repo.rs:120,101`);
`GitCloneBundlePlan`/`GitCredentialBoundary` (`vm_git_bundle.rs:51,22`);
`MirrorCache`/`MirrorCacheKey`/`MirrorCacheBounds` (`vm_git_mirror_cache.rs`).

**Guarantees.** `github_git_db`: every client is time-bounded by construction;
blobs are always base64 to avoid SHA desync; a signed `create_commit` returns a
SHA only if GitHub reports `verified:true`; `update_ref` hard-codes
`force:false` so non-fast-forwards surface as errors. `notes_repo`: byte-exact
round-trip (bypassing `stripspace`), append-only notes in a validated bare repo,
serialised by a per-repo process-wide mutex; the note **body is an opaque signed
envelope — verification lives in callers** (`run_verify.rs`), not here.
`vm_git_bundle`: size cap + path-containment re-checked post-run.
`vm_git_mirror_cache`: atomic-rename publish, pin-protected + bounded eviction.

**Invariants.** Commit-signature check (`github_git_db.rs:439`); bundle byte cap
+ path containment enforced at plan time and re-canonicalised at runtime;
`GitCommitSha::parse`/`MirrorCacheKey` sha256 slug are parse-don't-validate;
cache eviction honours `max_entries` + `max_bytes` oldest-first and skips
pinned slugs.

**Neighbours.** `github_git_db` → git pipeline + minting; `notes_repo` →
`run_verify`, `server`, `agent_vm_daemon/materialize`, bailiff;
`vm_git_bundle`/mirror cache → the VM git endpoints and flake provisioning.

**Current-state note.** `notes_repo` is *not* bailiff-only: each daemon owns its
own bare repo (writ writes `refs/notes/writ/v1/*`; bailiff fetches those and
curates `refs/notes/bailiff/v1/plans/*`).

### 5.9 Run provenance — envelopes & verification

**Purpose.** The broker's `RunAgent` handler mints a signed envelope per agent
run (metadata + detached SSHSIG + framed output), stores it as a git note, and
downstream consumers (bailiff) verify it.

**Lives in.** The `writ-agent-run` crate (the run contract + process-runner,
re-exported as `writ::agent_run`), plus `run_envelope.rs`, `run_verify.rs` and
`SignedRunMetadata` in `protocol/views.rs`. `writ-agent-run`'s contract types are
always compiled; its runner/hashing sit behind the crate's `vm-client` feature
(and host-only `AgentPrompt::summary` behind `host`), so both the daemon and the
guest share it. The `run_envelope`/`run_verify` host modules stay in `writ`.

**Primitives.** `SignedRunEnvelope` + `OutputEnvelope`
(`run_envelope.rs:111,68`); `SignedRunMetadata` with `canonical_bytes()`
(`protocol/views.rs:178`); `AllowedSigners`/`verify_run_envelope`
(`run_verify.rs:61,265`).

**Guarantees & invariants.** The signature covers only
`metadata.canonical_bytes()` (compact serde JSON, fixed field order,
`deny_unknown_fields`); the output is bound transitively via
`output_envelope_sha256`. Verification runs three ordered checks — output-digest
re-hash → fingerprint-in-keyring → SSHSIG verify under the `writ.run-agent`
namespace — so tampered output → `OutputDigestMismatch`, unknown key →
`UnknownSigner`, tampered metadata → `SignatureInvalid`.

**Neighbours.** Repo/object types come from `writ-vm-git`; envelopes are minted
on the VM-sandbox run path and verified by bailiff via a notes-ref fetch.

### 5.10 Clients & UI

**Purpose.** The non-daemon surfaces:
- **`writ-vm-client`** crate (re-exported as `writ::vm_client`) — the guest-side
  `writ-vm` command surface. Runs *inside* the VM, consumes daemon-injected
  `WRIT_BROKER_URL`/`WRIT_BROKER_TOKEN`, and does git clone/push, workspace
  init/warm, session fetch, and agent-run exchange against the §5.6 HTTP surface.
  Never touches GitHub credentials, and — as its own crate — links no host dep.
- **`writ_client.rs`** (1288) — the *bailiff→writ* async client over the
  Unix-socket RPC (today exposes `run_agent`). Named `writ_client` for accretion
  reasons; it is not the operator CLI.
- **`cli/`** — pure, testable helpers lifted out of the `writ` binary (clap
  parsers, operator identity, workspace bootstrap, record output).
- **`ui_http/`** — a read-only loopback JSON API, single-bearer-token gated,
  GET-only, joining broker/audit state for a UI/TUI/MCP/curl. Routes
  `/v1/health`, `/v1/agent-vms`, `/v1/agent-vms/<id>`.
- **`crates/writ-vm-git/`** — the shared host↔guest wire-types crate.

**Guarantees & invariants.** The guest client is an ergonomic wrapper, **not an
authority boundary**: it re-asserts local invariants (branch-head/bundle-head
mismatch, bundle-size cap) for fast failure, but the broker re-validates every
request server-side. The `writ-vm-client` crate depends only on `writ-core`,
`writ-vm-git`, `writ-agent-run`, `reqwest`, `base64` — no host crate — so the
crate graph, not a feature flag, is what keeps the guest surface host-dep-free.
The UI is read-only over audit: GET-only, 405 on writes. Wire boundaries
parse-don't-validate (bearer-token byte check, broker-URL rejects
query/fragment/non-http).

**Neighbours.** `vm_client` → §5.6; `writ_client` → the daemon; `ui_http` →
audit; `writ-vm-git` shared with the git pipeline and run provenance.

**Current-state note.** `broker.md` lists "Web UI" and "MCP wrapping" as v1
non-goals; both now exist in read-only form via `ui_http` (see the
`2026-05-12-ui-data-api.md` plan).

### 5.11 bailiff — workflow on top of writ

**Purpose.** A separate binary implementing a per-plan **submit → decide →
review → implement** workflow layered on writ's `RunAgent`/`OpenSession` RPCs.
Each step verifies a broker-minted signed run envelope and records a
bailiff-owned note in bailiff's own bare git repo, keeping product-level
workflow out of the security-critical broker.

**Lives in.** `crates/bailiff/` (`bailiff_plan_{submit,review,implement,write,
read,view,note}.rs`, `bailiff_decision.rs`, `bailiff_repo_guard.rs`, `bin/`).

**Workflow.** The state (`WorkflowState`: Submitted/Accepted/Rejected/Reviewed/
Implemented, `bailiff_plan_view.rs:85`) is *derived* from which notes exist —
"highest stage reached." Legal-transition gating is enforced at the implement
step (`submit_implement` requires submission → decision → `Accepted` → no prior
implement, `bailiff_plan_implement.rs:204`); decide and review deliberately do
not gate on submission presence.

**Guarantees & invariants.** Each stage attaches a distinct note under one
per-plan ref `refs/notes/bailiff/v1/plans/<id>` at deterministic per-stage seed
OIDs. Every signed stage runs fetch → verify: fetch writ's
`refs/notes/writ/v1/*`, re-decode the envelope, check metadata+signature parity
against the RPC reply, then `verify_run_envelope`. Append-only/idempotent via
`NotesRepo::write_note_if_absent` (duplicate → `AlreadyRecorded`);
`deny_unknown_fields` on all notes; cross-plan `PlanIdMismatch` guards;
single-writer via an in-process `BailiffRepoGuard` plus a cross-process flock
for `implement` (load-bearing because implement grants `WorkspaceWrite`).

**Current-state note.** The bailiff *split* is **complete in code**: the writ
root crate has no `agent_plan` module and no plan/decide CLI verb (top-level
`Cmd` is only OpenSession/CloseSession/Request/AgentVm/Agent/Promote). bailiff's
docstrings match: they describe the strip in the past tense, not as pending.

---

## Appendix: design journals (historical)

These predate this document and are **journals of how subsystems were built**,
decomposed into slices. They remain useful for *rationale and empirical
findings*, but where they describe directory layout, schema, or "what exists,"
this document is authoritative. Do not extend them slice-by-slice; record new
rationale in a dated `docs/plans/` slice and update §5 here.

| Journal | Still useful for | Superseded here by |
|---|---|---|
| [`broker.md`](./broker.md) | The original "why this shape": capability model, why-a-DU, the audit rationale, XDG path conventions. | §1, §4, §5.1–5.4 (its file layout and 4-table schema are stale). |
| [`apple-container-agent-vm.md`](./apple-container-agent-vm.md) | Empirical VM-isolation findings, PF strategy, the no-egress proof spikes, the Nix-in-VM reasoning. | §5.5, §5.6. |
| [`vm-mediated-push.md`](./vm-mediated-push.md) | The trust-boundary argument and ancestry-validation reasoning behind the push pipeline. | §5.7. |
| [`approve_state_machine.md`](./approve_state_machine.md) | The approve/reject state model and boot-reconcile design (schema "v5" is a snapshot). | §5.4, §5.7. |
| [`approve-crash-injection-harness.md`](./approve-crash-injection-harness.md) | The deterministic crash-injection test design (fake GitHub, fake origin, crash points). | Still current as a *test* design; not superseded. |

Planned implementation slices live in [`../plans/`](../plans/); the structural
remediation of the debt noted in §2–§3 is
[`../plans/2026-07-17-architecture-refactor-backlog.md`](../plans/2026-07-17-architecture-refactor-backlog.md).
