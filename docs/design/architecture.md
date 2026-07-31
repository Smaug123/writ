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

**What is *not* in the threat model: another local user on the same machine.**
writ is single-operator. Its trust boundary runs between the host user account
that runs `writd` — trusted, since it owns the config, the signing key and the
audit database outright — and the agent inside the VM, which is not. Containing
the agent is the whole point; containing a hostile uid on the same host is not a
goal writ pursues.

This is a decision rather than an oversight, and it settles a question that had
been reopened per-directory more than once. Nothing validates the ancestor chain
of writ's durable directories, and the mode checks guarding the secret store,
the socket parent and the bearer file test `mode & 0o077 == 0` without ever
consulting `st_uid` — which a macOS ACL (`chmod +a`) sidesteps entirely, since
`st_mode` cannot express one. Under this threat model those are **known and
accepted**, not latent bugs. Do not file them again per-root.

The guards stay where they already exist. They cost a few lines each, they keep
`writd` from silently becoming multi-user-exposed should the single-operator
assumption ever stop holding, and "if you can open the socket, you are trusted"
is only a safe thing to say while the socket is unreachable by anyone else. They
are hygiene and defence-in-depth — not a boundary, and not to be extended into
one. Ownership checks, ancestor-chain walks and `openat`-anchored descriptors
are all out of scope.

None of this relaxes the guest boundary. A host path component derived from
guest-controlled data is still a bug, governed by invariant 2 — which is why
`MirrorCacheKey`'s slug is a SHA-256 digest rather than a repository name, and
why `AgentRunId` is a `Uuid` the host minted rather than a string the guest
chose.

## 2. Workspace crates

| Crate | Role | Depends on |
|---|---|---|
| **`writ-core`** (`crates/writ-core/`) | Pure data core: request/decision/grant types, ids, capability sets, the PF/network model, SSHSIG signing types. Also the home for helpers that must have exactly one workspace-wide definition (`git_env`, `process_spawn`), since every other crate can reach here. No dependency on the rest of writ. | — |
| **`writ-vm-git`** (`crates/writ-vm-git/`) | Host↔guest wire types for VM-mediated git (clone/push request shapes, object-id/branch parsing). | `writ-core` |
| **`writ-agent-run`** (`crates/writ-agent-run/`) | The managed-agent run contract (prompt/output/correlation-id types) plus the agent process-runner. Shared by host, guest, and bailiff; re-exported as `writ::agent_run`. | `writ-core` |
| **`writ-vm-client`** (`crates/writ-vm-client/`) | The guest-side `writ-vm` command surface that runs inside the agent VM. Links no host-only dependency — enforced by the crate graph. Re-exported as `writ::vm_client` under the `vm-client` feature. | `writ-core`, `writ-vm-git`, `writ-agent-run` |
| **`writ-audit`** (`crates/writ-audit/`) | The append-only SQLite audit log: schema/migrations, the typed row DAOs, and two-phase write helpers. Re-exported as `writ::audit` under the `host` feature. | `writ-core`, `writ-agent-run`, `writ-vm-git` |
| **`writ`** (root) | The imperative shell: the daemon and all host effects. Binaries `writd`, `writ`, `writ-vm`, `writ-agent-vm-runner`, `writ-agent-vm-pf-helper`. | `writ-core`, `writ-vm-git`, `writ-agent-run`, `writ-vm-client` (opt), `writ-audit` (opt) |
| **`bailiff`** (`crates/bailiff/`) | A plan-workflow product (submit → review → decide → implement) built *on top of* writ. | `writ` |

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
  you can open the socket, you are trusted — which is a safe thing to say
  because writ is single-operator (§1). There is no peer-credential check, and
  under that threat model there does not need to be one.
- **Two-phase, append-only audit.** The request row commits *before* any
  network mint; the outcome row (grant or mint-failure) follows. A minted token
  whose grant fails to record is never delivered (`server.rs:533`). A DB at a
  higher/mismatched schema version than the binary is refused, not opened
  (correctness over availability).
- **Re-validation on the guest boundary.** Nothing the guest claims is trusted:
  the broker re-derives object graphs from bundle bytes, re-checks branch tips
  before and after replay, re-authorises repos against the session's grants,
  and reads guest-writable files with `O_NOFOLLOW` + fstat + byte caps.
- **One definition per safety-critical discipline.** Subprocess supervision and
  the hardened Git environment each have exactly one home, and
  `tests/shared_hardening_helpers.rs` scans the workspace to keep it that way.
  Spawning a child goes through `writ_core::process_spawn` (one
  transient-refusal classifier); bounding one goes through `process_supervisor`
  (timeout, byte caps, process-group SIGKILL); running `git` goes through
  `writ_core::git_env`'s recipe. The guard exists because duplication here is a
  *structural* defect no behavioural test can catch — two implementations is not
  a wrong answer, it only becomes a bug later when one is updated and the other
  is not. This was not hypothetical: five partial copies of the process
  discipline had accumulated, and the `GIT_CONFIG_*` recipe had been re-typed at
  eight sites, three of which silently omitted `GIT_CONFIG_COUNT=0`. Separately,
  the recipe was *documented* as neutralising `GIT_CONFIG_PARAMETERS` via
  `GIT_CONFIG_COUNT=0` and did not — git parses that variable on an independent
  path. Every production caller also calls `env_clear`, which strips it anyway,
  so no live hole existed there; the exposure was in test helpers, which layer the
  recipe over an inherited environment. `git_env` now names the variable
  explicitly, with a test that asks real `git` rather than trusting the
  reasoning — because a recipe that is only safe when callers happen to do
  something else as well is not a recipe you can reason about locally.

  **What these guards do and do not establish.** They ask "is this discipline
  defined twice?", which is not the same question as "is it applied everywhere?".
  A helper that simply never mentions the recipe passes all of them, and several
  did — including `writ-vm-client`'s four guest-side git runners, which
  `git_env`'s own module doc named as consumers while they ran git with no
  hardening at all. A sixth guard now flags any `git`-named helper that builds and
  runs a process `Command` without applying the recipe. That is still a
  name-keyed heuristic; the durable form of the invariant is a **construction
  boundary** — a type from which the only obtainable runnable git `Command` is a
  hardened one, so the recipe is enforced by construction rather than by the
  author remembering. `clean_git`'s `CleanGitInvocation` is the closest existing
  thing (it carries the recipe as validated `CleanGitEnv` values and is the
  guard's one recorded exemption); generalising it is not yet done.

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

**Lives in.** `crates/writ-core/src/core/` (nine submodules) plus four
low-level shared helpers (`bearer`, `git_env`, `process_spawn`, `telemetry`).
Re-exported from the root crate as `writ::core` (`lib.rs:37`).

Being the crate everything else depends on makes this the right home for
anything that must have exactly one definition workspace-wide, which is why
`git_env` (the hardened `GIT_CONFIG_*`/`HOME` recipe) and `process_spawn` (the
transient-spawn-refusal classifier) live here rather than beside their main
consumers: a copy in a crate the guest-side crates cannot reach is a copy those
crates will re-type.

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

**Guarantees.** `core` is pure — no IO. The only host-only surfaces are
`process_spawn::spawn_async` and `git_env::apply_clean_git_config_async`, both
gated behind the crate's own `host` feature (which alone pulls in tokio); the
blocking twins of each are available everywhere, including `vm-client` builds.
`git_env` also guarantees the recipe is applied whole: `GIT_CONFIG_DENY_ENV` is
the complete config-source denial set (`GIT_CONFIG_NOSYSTEM=1`,
`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_COUNT=0`, **and**
`GIT_CONFIG_PARAMETERS=` — the last is a separate channel git parses
independently of the count, so it needs its own entry), `CLEAN_GIT_CONFIG_ENV` is
that plus `HOME=/dev/null` plus `GIT_IMPOSED_CONFIG`, and tests assert the three
cannot drift apart. A caller needing a real `HOME` (nix fetching a flake input)
takes the denial set and supplies its own — never a subset. One test runs real
`git` under the recipe with injections on every channel and asserts none lands,
because the shape of the constant cannot tell you whether git honours it.

`GIT_IMPOSED_CONFIG` is the one part of the recipe that *asserts* configuration
rather than denying it: `maintenance.auto=false` and `gc.auto=0`, so no
`git maintenance run --auto --quiet --detach` outlives the command that spawned
it and keeps writing to `objects/`. writd reasons about the contents of the
repositories it owns — object graphs, ancestry, which refs exist — and a detached
process rewriting the store underneath that reasoning is the nonlocal effect this
codebase rejects. It also actually happened: a fixture that committed and then
cloned raced maintenance's transient `.tmp-<pid>-pack-*.idx` and got ENOENT.
`git fetch` is the live blast radius (the notes repo and the push staging store
both fetch; `notes add`, `hash-object -w` and `bundle unbundle` spawn nothing),
measured on git 2.54 rather than inferred.

Two consequences worth knowing. First, `CLEAN_GIT_CONFIG_ENV` is delivered
through the numbered `GIT_CONFIG_KEY_<n>` channel, so its `GIT_CONFIG_COUNT` is
the pair count and not `0`; that denies inherited pairs just as completely,
provided the recipe fills every slot below the count, which is what
`the_imposed_config_fills_exactly_the_slots_the_count_declares` pins. Second, the
denial set deliberately does *not* impose this: its callers are nix (operating on
caches writ does not own) and the guest's git inside the VM (whose filesystem
dies with the VM). Nor can the env channel reach a `receive-pack` — `git push`
strips `GIT_CONFIG_COUNT` for a local-transport child — but nothing in writd
pushes into a repository it owns. Suppression does not remove writ's ability to
compact: the `*.auto` knobs gate only the uninvited run, and an explicit
`git gc` still packs. Writ now schedules that itself — see
`NotesRepo::compact_if_needed` below.

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

**Lives in.** `server.rs` (922 lines: transport, dispatch, connection handling)
plus `server/staged_push.rs` (1772: the list/show/reject/approve/reconcile
approval handlers) and `server/run_agent.rs` (543: both `RunAgent` arms — host
spawn and VM dispatch — and the signing/notes tail they share);
`server/` also holds the test submodules. `protocol/`
(`mod.rs` 534 for the `ClientMessage`/`ServerMessage` DUs + `views.rs` 246 for
the payload types they carry + `tests.rs` for the wire tests),
`broker_session.rs`, `broker_protocol.rs`, `policy.rs`,
`config/` (`mod.rs` 1375 + `audit_dir.rs` + `tests.rs`), `bin/writd.rs`,
`bin/writ.rs` (the
operator CLI verbs).

**Primitives.** Wire DUs `ClientMessage` (`protocol/mod.rs:38`, tagged +
`deny_unknown_fields`) and `ServerMessage` (`protocol/mod.rs:304`, tagged, not
`deny_unknown_fields` since outbound); `Decision`/`AuthorizedMint`
(`policy.rs:97,52`); config root `DaemonConfig` (`config/mod.rs`,
`deny_unknown_fields`): `github_apps`, `policy`, `agent_vm?`, `secret_store`,
`socket_path?`, `audit_db?`, `ui_http?`, `run_agent?`, `agent_run_log_root?`,
`max_concurrent_agent_runs?`.

**Agent-run concurrency.** One broker-wide bound, `BrokerState::agent_run_slots`
(`AgentRunSlots`, default 2, `max_concurrent_agent_runs?`), covers every way to
start an agent run: both `RunAgent` arms and `StartAgentRun`. One bound rather
than one per path — the paths differ in what a run costs (a child plus threads,
or a whole VM) but not in whose machine pays. Top-level config for the same
reason as `agent_run_log_root`: a VM-only daemon has no `run_agent` section and a
host-only one has no `agent_vm` section. `NonZeroUsize`, and rejected above
`Semaphore::MAX_PERMITS` during preflight, so neither a wedged daemon nor a
startup panic is reachable from a config value.

The slot's *lifetime* differs by path, and that is the load-bearing part. A host
run ends when its handler returns, so a function-scoped permit is the run's
lifetime. A VM run does not: `StartAgentRun` answers as soon as the VM is up, so
`start_agent_run_session` hands the permit to the running session, where it lives
inside the `running` map's value and is released when the session is removed —
by construction rather than by remembering, since a missed release is permanent
and shrinks the bound for the daemon's lifetime.

Whether a caller *waits* is also per-path (`AgentRunQueueing`), for one reason:
whether anyone is still listening when the wait ends. `RunAgent` (both arms)
queues indefinitely — its caller holds the connection for the whole run.
`StartAgentRun` waits at most `AGENT_RUN_QUEUE_WAIT` and then answers
`AgentRunsAtCapacity`, because its CLI has a 30-minute deadline of which the
bootstrap may take 20; a permit granted after that would boot a VM whose session
id reaches nobody. Refusals happen before the per-session lock is registered, so
a rejected start leaves nothing behind. Still open: the bound covers *executing*
runs, not *waiting* callers, each of which holds a task, a connection, and a
decoded prompt.

A restart does not carry slots over, because it does not carry sessions over:
boot reconciliation tears down every persisted agent VM before writd serves.

**Agent-run deadlines.** A host-spawned run may be bounded by
`run_agent.spawn_timeout_secs`. It is **absent by default and absent means
unbounded** — writ has no basis for guessing an agent's longest legitimate run,
and a wrong guess kills real work — so the default path is the plain blocking
`wait(2)` it has always been, not a deadline set to infinity. Zero is refused at
parse time rather than read as either "unbounded" or "immediately", since those
are opposites and absence already spells the first.

A run stopped this way is recorded `AgentRunTerminalStatus::TimedOut`, which
exists precisely so it is not recorded `Failed`: `Failed` means the agent ran to
completion and chose a non-zero code, and this ending is writ's decision, not the
agent's. The run is *paired* in the log — request and outcome both — because
writ knows exactly how it ended; contrast the VM arm, whose `RUN_AGENT_VM_TIMEOUT`
leaves the request unpaired because a guest that never uploaded an outcome leaves
writ with nothing truthful to record. Whatever the agent emitted before the kill
is still captured, minus anything left unflushed in the dead process's buffers.

**The deadline is a promise about the call, not about one of the things the call
waits on** — the same rule `process_supervisor` states for its own timeout. A
host run waits on three things, and all three are under it:

* **The prompt write.** It goes to its own thread, so waiting for the agent is
  the only thing the run blocks on. Written inline, a 1 MiB prompt to an agent
  that neither reads stdin nor exits blocks in `write(2)` against a 64 KiB pipe
  buffer and the deadline is never evaluated at all.
* **The agent.** Polled to the deadline, then its process group is signalled.
  Killing a pid reaches one process; any descendant inherits the stdout/stderr
  pipes, so the capture threads never see EOF. Measured: before the group kill, a
  fake agent that backgrounds a `sleep` kept a 500ms-deadline run pending past a
  60-second backstop. Real coding agents spawn subprocesses constantly, so
  without this the timeout would have been a bound in name only.
* **The stream drains.** The half a wait-shaped deadline cannot reach: when the
  agent exits promptly but leaves a descendant holding the pipes, the wait is
  *over*, so there is nothing left for it to fire on, and yet the run is not
  assembled until EOF. Bounded by the same deadline, which sweeps the group.

Ordering is load-bearing: **observe, then kill, then reap**, the discipline
`writ_core::process_group` documents. A group kill is only safe while the leader
is unreaped, because the pgid *is* the leader's pid and a reaped pid can be
recycled onto a group writ does not own. So a deadline-bounded run observes the
agent's exit with `waitid(WNOWAIT)`, keeps the zombie until the drains are done
(which may need a second group kill), and reaps last. That primitive lives in
`writ-core` rather than beside either caller because there are now two of them in
different crates, and its errno argument took three review rounds to state.

Which ending gets recorded turns on **who ended the process**: an exit code means
the agent decided, even a moment past its deadline; `SIGKILL` *that writ sent* is
the timeout; any other signal is somebody else's doing and is recorded as the
failure it is. So a run whose agent finished and whose leftovers writ swept is
recorded as the agent's own outcome — writ stopped a descendant, not the run.

The group is set on every run, but only the deadline path signals it. **An
unbounded run still sweeps nothing** — whether it should is the separate open
question about what a finished run guarantees, and answering it as a side effect
of adding timeouts would be the wrong way to decide it.

`GuestReportedRunStatus` is the guest-facing half of the status enum, and it has
no `TimedOut`. A guest asserting that the broker stopped its run would give one
audit value two meanings, so the wire type simply cannot express it and
`"timed_out"` from a guest fails to deserialise.

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

**Config validation accumulates.** Every config check runs on every boot and
the failures are reported together, rather than one per restart
(`config/accumulate.rs`). `Accumulator::record` stores a failure instead of
short-circuiting and hands back a `Failed` marker; `all_recorded!` +
`Accumulator::unpack` recover the values only when all of them are present.
`Errors<E>` is a **non-empty** report, always derived from an accumulator's own
error list, so "rejected with no reasons given" is unrepresentable. (`Failed`
is crate-private: it says *some* accumulator failed, not *this* one, and Rust
cannot bind a zero-sized witness to an instance without generative branding —
so `unpack` never trusts it for the report's contents.) Two rules shape where
the errors come from:

- A check whose own inputs failed is *skipped*, not reported, so an operator
  sees a root cause once instead of a cascade of its consequences.
- Nested reports flatten (`record_many` / `Errors::map_into`), so a bad
  `lifecycle` section cannot hide every fault in `vm_http`.

**Validation is planned, then executed.** `AgentVmHttpConfig::check` runs every
check that touches nothing and returns a `VmHttpPlan` — the validated runtime
config plus the directories that still need creating; `VmHttpPlan::materialize`
carries that out. This is the interpreter pattern applied to config, and it *composes*:
`AgentVmDaemonConfig::check` holds a `VmHttpPlan` inside an
`AgentVmDaemonPlan`, and `check_daemon_sections` holds that while it validates
`ui_http` and the shape of `agent_run_log_root`, so nothing is created until
every section — plus the daemon-level bind invariant, via
`AgentVmDaemonRuntimeConfig::check_bind_addr`, which takes the bare address so
it cannot hide behind an unrelated fault — has been checked. **No config
rejected on its text leaves debris.** That matters most for `work_root`, where
a directory created at the process umask (0755) would make
`validate_existing_work_root` refuse that path on every later boot too.

Once the text is known good, the two effectful steps — creating
`agent_run_log_root` and materialising the `agent_vm` plan — are independent, so
both run and both report into one accumulator: an unwritable log root must not
hide an unwritable `git_push_staging_root`. This is the one place where a
rejected config *can* leave a directory behind, and only one whose own creation
succeeded.

Inside `materialize` the work root is prepared first, and **every** root waits on
it, including one the operator named explicitly. Whether a named root is really a
descendant cannot be decided there — it need not exist yet, so it cannot be
canonicalised, and a lexical `starts_with` is case-sensitive and blind to
symlinks and `..`. Guessing permissively would mutate the filesystem for an
already-rejected config, since a rejected work root is often one that merely
*exists* with loose permissions and happily accepts `create_dir_all` of a child.
The cost is one extra round-trip when the work root and another root are both
broken; textual faults in those roots are unaffected, as `check` reports them
without gating on anything.

This split leaves one place an operator can still need two passes: once for what
the config says, once for what the filesystem permits.

**Known granularity limit.** Leaf constructors (`VmHttpNixCacheConfig::new`,
`VmGitPushBodyLimits::new`, the proxy configs, …) are still fail-fast, so each
counts as *one* check: setting two bad fields within a single constructor
reports only the first. The section-level tiering that cost a restart per
mistake is gone; per-field accumulation inside those constructors would mean
reworking them across `vm_http`, `writ-core`, and the lifecycle module.

`writd` calls `check_daemon_sections`, which validates `agent_vm`, `ui_http`,
and `agent_run_log_root` together, up front, before the socket bind, the
signing key, and the reconcile passes — so a bad `ui_http.bind` is reported
alongside everything else rather than after all of that succeeds.

`agent_run_log_root` is top-level rather than a `vm_http` key because neither
subsystem section can own it: `StartAgentRun` reaches the VM `RunAgent` arm
with no `run_agent` section configured, and a host-spawn-only daemon has no
`agent_vm` section. It defaults to `$XDG_DATA_HOME/writ/agent-runs` and is
created **owner-only** and probed at boot, via the `AgentRunLogRoot`
check/prepare pair — the same text-then-effect split the `vm_http` roots use,
as a type so that a raw relative path cannot reach
`AgentVmDaemonConfig::to_runtime_config`. 0700 is what makes the two effectful
steps order-independent: a log root named beneath a not-yet-existing
`vm_http.work_root` creates that parent at 0700, which is exactly what
`ensure_vm_http_work_root_private` demands, and it matches what the runtime
(`writ_agent_run`'s `ensure_private_dir`) enforces before every run. Its
default comes from the `config::default_paths` table like every other (see
"Default paths" below). Both `RunAgent` arms
write here: per-run `<root>/<run-id>/stdout.log` and `stderr.log`, pointed at
by `agent_run_outcome` rows. The host arm reaches it through
`RunAgentSpawnConfig.log_root`, which is non-optional — a spawn config with
nowhere to put streams describes a run that could start but never be audited.

**Default paths.** Every location writ derives from the environment is a
`DefaultPath` entry in `config::default_paths` — the config file, the audit DB
(and its legacy sibling), the notes repo, the secret store, the agent-run log
root, the socket, the UI bearer file, the agent-VM work root and state dir.
Each entry names the XDG variable that owns it, the two suffixes, and the
config key that overrides it; `DefaultPath::resolve_from` is the one function
that turns an entry plus an environment into a path. Consumers outside the
crate declare their own entry (bailiff's repo) and resolve it with the same
code.

Resolution is **fallible, and refuses rather than guessing**. Two holes had
been copy-pasted into all nine resolvers: `var_os` returns `Some("")` for an
exported-but-empty XDG variable, so joining produced a *CWD-relative* path; and
an unset `HOME` fell back to `/tmp`. The second is not hypothetical on macOS,
which sets no `XDG_RUNTIME_DIR` — every macOS install already takes the `HOME`
branch for the socket and bearer file. It matters most for two entries: the
audit DB is consulted as a live authorisation oracle (`flake_provision` gates
guest access on `session_holds_grant_authorising`, over unsigned rows), so a
pre-created database fabricates *grants*, not just history; and writ performs
no peer-credential check, so whoever binds the socket path first *is* writd to
every client. Refusing was chosen over normalising because normalising moves
durable state — the exact silent-fork failure the legacy-audit-DB guard exists
to prevent — whereas refusing moves nothing and names both the variable and
the config key. Because `AUDIT_DB` and `LEGACY_AUDIT_DB` are entries in one
table resolved by one function, the guard can no longer probe a different base
directory than the one writd is about to open.

Resolving a path is **not** trusting it: nothing here checks directory
ownership, and the mode-only (`mode & 0o077 == 0`) checks guarding the secret
store, socket parent, and bearer file are bypassable by a macOS ACL, which
`st_mode` does not reflect. That is a separate, still-open question.

**Neighbours.** Calls audit, credential minting, the git pipeline
(staged-push), and the VM sandbox (`AgentVmDaemon`). Called by the `writ` CLI
over the socket; guests reach the *separate* `vm_http` surface (§5.6), not this
one.

**Current-state note.** The host transport is still line-delimited JSON over a
Unix socket, as `broker.md` describes — but that doc's "add HTTP later"
prediction has landed as *three* additional transports it never documents: the
guest-facing `vm_http` HTTP listener (§5.6), the read-only `ui_http` JSON API
(§5.10), and a broker-in-VM mode (`writd broker`, `broker_entrypoint.rs`) that
binds a fixed TCP port and negotiates `BROKER_PROTOCOL_VERSION` via a
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
`effect_table.rs`, `effect_scan.rs`, …), re-exported as `writ::audit`. Its
boot-time reconciler, `boot_reconcile.rs`,
stays in `writ` — it *drives* the audit DAOs but also needs the git pipeline
(`git_push_staging`), so it is an orchestrator, not audit storage.

**Primitives.** `AuditLog { conn: Mutex<Connection> }`
(`writ-audit/src/lib.rs`); refuse-to-open errors
`SchemaTooNew`/`SchemaHistoryMismatch` (same); `Migration { version, name, sql }`
+ `MIGRATIONS` (`writ-audit/src/schema.rs:38,57`); generic proxy row types
(`proxy_table.rs`); git-push state enums (`writ-audit/src/git_push.rs`); the
approve-attempt state machine (`writ-audit/src/git_push/approve_attempt.rs`, see
below); `ReconcileReport`
(`boot_reconcile.rs:55`). The generic two-phase audit-pair guard
(`effect_table.rs`) is the emerging spine of the "complete by construction"
work: `EffectAuditTable` describes any `(request, outcome)` table pair, and the
`RecordedRequest` guard makes the pair the only expressible write —
`begin_effect` records the request row (session-open-checked) and returns a
`#[must_use]` guard whose `complete` records the matching outcome (refusing one
whose key disagrees); `record_effect_coalesced` writes both in one commit for the
authority-free Nix-cache serve and for locally-generated proxy responses (a
denial, an unsupported route), which perform no IO. The shared open-session check
lives once in `validation::check_session_open`. The VM-HTTP driver (§5.6) has
adopted the guard, and for the four tables it fully owns — both model proxies,
Nix-cache, flake-provision — the unguarded half-pair writers are now `#[cfg(test)]`,
so **the guard is the only way production code can write those tables**. The two
that keep public unpaired writers do so for stated reasons: `git_push` (boot
reconciliation appends an outcome for an orphaned carrier) and `agent_run` (the
VM arm mints the request row at run launch, and the outcome arrives later over
the guest's HTTP surface — see the outcome-only shape in §5.6).

The host arm records the agent kind its `run_agent.spawn_agent_kind` config
declares, not the one the caller's session declares, and refuses a session that
disagrees. The arm spawns exactly one binary and the operator who chose it is
the only party who knows what it is; a caller's kind is a guess about a
daemon-side configuration it cannot see (bailiff's `--agent` defaults to
`claude` regardless). Neither value is checkable against the binary, but only
one is written by someone in a position to know — and the refusal matters
because the session's kind is not inert: it routes credential mints to a GitHub
App, so a mismatch would mint as one agent and execute as another. The VM arm
has no such gap: there the kind *builds* the guest command.

`agent_run` is the one table used in *both* guard shapes, because its two arms
genuinely differ. The VM arm spans two processes and two lifecycle events, so
it is outcome-only: launch writes the row, the outcome endpoint `resume_effect`s
it. The host-spawn arm performs the whole run inside one handler, so it is
ordinary two-phase — `begin_effect` before the child starts, `complete` with
the capture's outcome, `abandon` when the run cannot report one truthfully (an
unspawnable command, a stream that could not be captured). Both leave an
unpaired row in that last case, which is what an unfinished run looks like;
neither fabricates a terminal status, because the outcome row is keyed on the
run id and a fabricated row would consume the run's only outcome slot forever.
This is also why `EFFECT_AUDIT_PAIRS` excludes `agent_run`: an unpaired row
there is indistinguishable from a run still in flight, so the generic boot scan
would false-positive on every live run.

**The two caller tags on an `agent_run` row.** `correlation_id` and `purpose`
are both opaque strings writ stores and never interprets, but they arrive from
different RPCs and neither substitutes for the other. `RunAgent` carries a
`purpose` and no correlation id; `StartAgentRun` the reverse. `AgentRunTags`
bundles them so each call site states which it is supplying and which it is
not, rather than passing a lengthening tail of positional `Option`s.

They are separate columns because `CorrelationId`'s class (alnum, `-`, `_`) is
narrow by design — it must not be able to pose as a path segment or URL scheme
— and rejects the colon in bailiff's `review:plan-abc`. Routing a purpose
through it would have turned a valid request into a parse error.

`RunPurpose` is therefore its own type: 1..=128 bytes of printable ASCII with
no leading or trailing space. The class is an allowlist rather than a blocklist
of dangerous characters, which is what makes it exhaustive — it excludes NUL,
CR/LF, ESC, C1, zero-width spaces, and bidi overrides by construction, so two
purposes cannot be unequal as join keys while rendering identically. Allowing
Unicode could not deliver that: it would need a format-character blocklist that
is wrong by default whenever Unicode gains a member, and would still admit the
homoglyphs (Cyrillic `а` is an ordinary letter) that motivate it. The cost is
that a purpose is Latin-script; that is a loud parse-time rejection, and the
class can be widened later without invalidating a single stored value, whereas
a log full of Unicode purposes could never be narrowed.

The migration-8 CHECK is an *exact* mirror of `RunPurpose::try_new` rather than
a coarse floor, because printable ASCII is expressible in SQLite's GLOB. That
matters: `agent_run_from_row` turns an unparseable value into an `Invariant`
error, so a CHECK any weaker than the parser would admit rows the reader later
refuses — an audit log that cannot be read back. One clause is subtle and
load-bearing: `length(cast(purpose AS BLOB)) = length(purpose)` is the only
guard against an embedded NUL, because both `length()` and `GLOB` stop at the
first one.

The column is nullable and is not backfilled — a sentinel would be fabricated
audit data. `NULL` reads as "no purpose was supplied", which covers both rows
predating the migration and every `StartAgentRun` row permanently.

**The approve-attempt state machine.** `approve_attempt.rs` owns the vocabulary
and the transition relation of the operator-approve lifecycle, which the DAO
merely persists. Three layers:

- **Vocabulary.** `ApproveAttemptStateName` / `ApproveAttemptOutcomeName` — the
  flat discriminants the `state` / `outcome` columns hold, generated with
  `as_wire`/`parse_wire`/`ALL` from one variant⇒literal table, so no hand-kept
  list can fall out of step. Every DAO read *and* write goes through them; the
  names appear nowhere else as literals.
- **Position.** `ApproveAttempt { state, ledger_mint }`. The v7 mint ledger
  (`git_push_approve_attempt_mint`) is part of the attempt's durable position,
  not a side table: migration 0007 adopted it only because SQLite cannot widen a
  CHECK to add a `minted` state, and two triggers judge writes against it. A
  machine blind to it would permit moves the schema refuses.
- **Relation.** `apply(&ApproveAttempt, &ApproveAttemptTransition) ->
  Result<ApproveAttempt, IllegalApproveTransition>` — one wildcard-free match,
  each refusal naming the invariant it protects. The DAO reads the row, asks
  `apply`, and writes every mutable column from the position it returns, so a
  write cannot disagree with the decision.

- **Derived predicates.** `AttemptPosition` (the `(state, outcome)` pair) answers
  the questions the queries ask — `blocks_resolution`, `is_in_flight`,
  `is_reconcilable`, `reject_blocker` — once each. `position_predicate_sql`
  renders a position set as a SQL `IN` clause, so the queries that ask those
  questions *derive* their predicate from the same functions the Rust folds use
  rather than restating it. Note `blocks_resolution` excludes
  `Resolved(Succeeded)`: the approve path's own joint transaction writes the
  resolution row.
- **Refusals are typed.** The one trigger whose firing a caller must act on
  (`git_push_resolution_refuses_active_approve`) is classified inside the crate
  into `AuditError::ResolutionRefusedByActiveApprove`; its abort text is matched
  in exactly one place, beside the predicate, because SQLite gives
  `RAISE(ABORT, …)` no machine-readable identity.

**Guarantee (schema-backed).** The triggers below remain the authority — the
database refuses a contradiction even when every Rust caller is wrong — and the
Rust machine is held to them mechanically:
`approve_attempt::tests::transition_agrees_with_the_schema` drives every
(position, transition) pair against a real database, comparing `apply` against a
naive writer that never consults it, and
`rust_and_schema_admit_the_same_{state,outcome}_names` compares `ALL` against the
CHECK literals read back from `sqlite_master`;
`blocks_resolution_agrees_with_the_trigger` and
`trigger_message_matches_the_live_trigger` do the same for the blocking
predicate and its abort text. Divergence in *either* direction fails the build.
Each of these reads the **live** schema rather than the migration list — a
superseded migration still carries the old definition, so searching history
would let a reworded trigger pass. The one place the machine is deliberately stricter than the
schema (a mint-capturing resolve from `Uncertain`) is enumerated in the test, not
implicit.

**Schema.** ~24 live tables across **7 migrations** (`audit/schema.rs`), versus
the 4 tables `broker.md` documents. Version is tracked in a `schema_version`
*registry table* — **not** `PRAGMA user_version` as `broker.md` implies.

**Guarantees & invariants.** Each migration runs its DDL + version-bump in one
`BEGIN IMMEDIATE` transaction, so a mid-migration crash resumes cleanly; a
down-rev/mismatched DB is refused (§4). At-most-one-outcome per request is
enforced by SQL triggers (`grant_excludes_mint_failure` /
`mint_failure_excludes_grant`), plus forward-only triggers on the approve-attempt
ledger. Timestamps are `UnixMillis` integers. Boot reconciliation
(`boot_reconcile.rs`) runs three passes at daemon startup:
`reconcile_pending_approve_attempts` recovers or flags-uncertain "in-flight at
crash" approve-attempt rows; `reconcile_orphaned_staged_carriers` re-pairs staged
git-push carriers left on disk without an outcome; and
`reconcile_unpaired_effect_rows` — the durable backstop for the audit-pair
invariant (§4) — scans every short-lived `(request, outcome)` effect pair
(`effect_scan::EFFECT_AUDIT_PAIRS`: the proxies, nix-cache, flake-provision, and
git-push, but *not* outcome-only `agent_run`, whose request row legitimately
outlives its outcome) and flags any request row left without its partner. That
last pass is **report-only** (it never fabricates an outcome) and runs *after*
persisted-session reconciliation (§5.5), so a broker VM that survived a host
crash and still writes the DB over virtiofs has been torn down — leaving the DB
quiescent — before the scan reads it.

**Neighbours.** Written by the broker core and every effect handler; read by
`ui_http`/CLI and by boot reconcile at daemon startup.

### 5.5 Agent-VM sandbox — lifecycle, firewall, broker-in-VM

**Purpose.** Run an agent inside an Apple-`container` Linux VM given only tmpfs
mounts and no NAT egress, so it can touch neither the host filesystem nor the
network directly. A broker (the §5.6 HTTP surface) is the sole bridge for
external effects, reachable only on a whitelisted broker port/IP.

**Lives in.** `agent_vm_lifecycle.rs` (2102) + `agent_vm_lifecycle/` (the
`parse`/`state_store`/`network_health`/`invocation`/`plan`/`cleanup` submodules —
`invocation` holds the `ProcessInvocation` execution primitive, `plan` the
`AgentVmSessionPlan` start-step state machine + invocation builders, `cleanup`
the session-teardown execution — run stop invocations, poll resources until
absent, fold errors),
`agent_vm_daemon.rs` (1295, with the `AgentVmDaemon` method impl in
`agent_vm_daemon/daemon_impl.rs`) + `agent_vm_daemon/`, `agent_vm_firewall.rs`,
`broker_vm.rs` (966, with the `BrokerVmPlan` invocation builders in
`broker_vm/plan.rs` and tests in `broker_vm/tests.rs`), `broker_vm_runner.rs`,
`broker_entrypoint.rs`,
`broker_session.rs`, `broker_log_forwarder.rs`, `process_supervisor.rs`,
`bin/writ-agent-vm-runner.rs`, `bin/writ-agent-vm-pf-helper.rs`. The PF ruleset
model itself lives in `writ-core` (`core/agent_vm.rs`).

**Topology.** *Host:* the `writd` daemon (`AgentVmDaemon`), an unprivileged
lifecycle runner (`writ-agent-vm-runner`, owns Apple-`container` ordering), and
a root PF helper (`writ-agent-vm-pf-helper`, pins `/sbin/pfctl` +
`/sbin/ifconfig`, trusts no caller-supplied path). *Guest:* the agent VM, and —
under `BrokerPlacement::Vm` — a dedicated broker VM running `writd broker` on a
shared `--internal` network.

`process_supervisor.rs` (2069, byte-cap policy in
`process_supervisor/capture.rs`) is filed under this subsystem for historical
reasons but is **workspace-wide**: it supervises every bounded child (agent-VM
and broker lifecycle, `clean_git`'s git replay, `flake_provision`'s nix,
`notes_repo`'s git). Two arms over one contract — `run_supervised` (async) and
`run_supervised_blocking` (for callers not on a runtime, notably `notes_repo`,
which holds a `std::sync::Mutex` across the whole invocation and so cannot
await). Both give a wall-clock timeout, a stdout byte cap, a line-aligned
tail-capped stderr, and a process-group SIGKILL, and both share the byte-cap
policy, the `waitid(WNOWAIT)`-then-`killpg`-then-reap ordering, and the cleanup
guard, so the pair cannot drift. The blocking arm additionally owns **stdin**,
because a single-threaded caller that writes stdin to completion before draining
stdout deadlocks against a child that fills its stdout pipe; it drives all three
streams from one non-blocking `poll(2)` loop. `git_push_objects_cat_file`'s
long-lived `cat-file --batch` session is not spawn-and-wait, so it uses neither
arm, but it shares the group-kill primitives rather than re-deriving them.

Two properties are stated jointly for both arms because having them in only one
was a live defect in each case. **The timeout bounds the whole call, not just the
child**: a capture drain reaches EOF only when every fd on the pipe's write end
closes, and a descendant that called `setsid` has left the process group, survives
the SIGKILL, and holds it open indefinitely — so the drain joins are bounded by the
same deadline, and a capture that cannot complete is reported as `TimedOut` rather
than as a short but plausible-looking stdout. **A failed capture is never a
capture**: a read error, or a drain task that dies, surfaces as
`SupervisorError::CaptureRead` instead of being folded into EOF, because callers
parse stdout as data (one object id per `rev-list` line) where a truncated prefix
reads as a complete, shorter answer.

**What the supervisor does not decide.** It reports a `born_dead_signature` — pid
absent when probed, and killed by `SIGKILL` (§`docs/known-test-flakes.md`) — as
*evidence*, not as permission to re-run. The probe cannot prove non-execution:
`getpgid` answers `ESRCH` for an exited-but-unreaped child on macOS, so a child
that ran, took effect, and was then killed matches the same signature. Replay
safety is therefore a fact about the command, decided at the call site
(`notes_repo::OnBornDead`), not a boolean the supervisor hands out.

**Primitives.** `AgentVmSessionPlan`/`StopPlan`
(`agent_vm_lifecycle.rs:160,193`); `AgentVmSessionState`/`Store`
(`agent_vm_lifecycle/state_store.rs`); the start-step state machine
`AgentVmStartStep` (ProbeNetworkAbsent → CreateNetwork → InspectAndValidate →
InstallFirewall → ProbeVmAbsent → StartVm → InstallGuestIpv6Deny →
ProbeAndValidateGuestIpv6 → ReleaseGuestCommand); firewall
`SessionFirewallInstall`/`Removal`/`PfctlInvocation` (`agent_vm_firewall.rs`);
broker `BrokerVmPlan`/`BrokerSessionSpec`/`GuestAbsPath` (`broker_vm.rs:190`,
`broker_session.rs:63,24`).

**Guarantees.** No egress except the broker: host placement via PF default-deny
(whitelist broker ports, then `block return`); VM placement by topology
(`--internal`, no NAT). IPv6 isolated with a backstop guest deny. The agent VM
gets no host mounts (tmpfs only); only the broker VM bind-mounts
session/secrets(ro)/audit. Idempotent restart: `Probe*Absent` steps refuse to
touch infra this call didn't create. On boot, `reconcile_one_session` closes
broker authority in the audit log *before* unbounded teardown, and the daemon
refuses to start while an obligation remains (`agent_vm_daemon/daemon_impl.rs:704`).

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

**Lives in.** `vm_http/` (`mod.rs` [1677 lines, tests in `vm_http/tests.rs`],
`claude_proxy.rs`,
`openai_proxy.rs`, `git_clone.rs`, `git_push.rs`, `flake_provision.rs`,
`nix_cache.rs` + `nix_cache/`, `agent_runs.rs`, `proxy_common.rs`) plus the
Nix domain modules `nix_binary_cache.rs` (1345, with its test suite in
`nix_binary_cache/tests.rs`), `flake_lock.rs`,
`flake_materialize.rs`, `flake_provision.rs`, `flake_provision_from_mirror.rs`.

**Endpoint map** (`vm_http/route_table.rs`). writ's own API lives under `/v1/*`:
`GET /v1/session`; `/v1/nix/cache/*` & `/v1/nix/prewarm/*`; `POST /v1/git/clone`;
`POST /v1/git/push`; `POST /v1/nix/flake/provision`; `GET/POST
/v1/agent-runs/{id}/config|outcome`. All of those but `/v1/session` and the Nix
cache are `writ-vm`-originated, and require the contract-version header (below). Each **model vendor has its own namespace**:
Claude proxy `/anthropic/v1/messages`, `/anthropic/v1/messages/count_tokens`,
`/anthropic/v1/models*`; OpenAI proxy `/openai/v1/responses`,
`/openai/v1/responses/{id}/cancel`, `/openai/v1/models*`. Path literals are
pinned in `crates/writ-vm-git/src/lib.rs:20`.

The vendor split is load-bearing, not cosmetic: `/v1/models` is a real endpoint
of *both* vendor APIs, so while they shared one namespace the backend classified
first (Claude) shadowed the other's models routes — answering `404` from the
wrong proxy and recording the attempt against the wrong vendor's audit table.
`route_table`'s `no_target_is_claimed_by_both_proxy_backends` property now makes
that unrepresentable, and `writs_own_v1_api_is_never_a_proxy_route` keeps `/v1/*`
writ's alone. The migration is complete: the pre-split paths are ordinary
unknown targets, and the `410 Gone` shim that named the rebuild is deleted. It
was there for guest images built before the split, and no such image can reach a
model proxy any more — it declares no contract version (below), so the broker
refuses its `workspace init` clone with `426` naming the same remedy, before an
agent process exists to issue a model request
(`docs/plans/2026-07-25-proxy-vendor-namespaces.md`, Stage 2).

**Two version handshakes, one fingerprint.** The guest and the broker are built
from the same tree and only ever meant to ship together, but both run from images
loaded into the local container store, so a rebuilt host can launch a stale one.
Each axis has a constant and refuses a mismatch with an actionable "rebuild the
image":

- **host ↔ broker VM** (`broker_placement = vm`): `BROKER_PROTOCOL_VERSION`
  (`broker_protocol.rs`), stamped into the broker's ready file and checked by the
  host at launch.
- **guest ↔ broker**: `VM_HTTP_CONTRACT_VERSION` (`writ-vm-git`), reported in
  `GET /v1/session` and checked by `writ-vm` at startup before any real work —
  `writ-vm session` is exempt, being the diagnostic one needs *during* a
  mismatch. The guest parses only the `version` field, so a newer broker's extra
  fields cannot stop an older guest from diagnosing the skew, and the version
  ordering decides which side is told to rebuild.

  The startup check is **guest-side**, so it protects only a guest that has it.
  The broker therefore enforces the same version from its own side: `writ-vm`
  declares `VM_HTTP_CONTRACT_VERSION` in a `writ-contract-version` header on
  every request it originates, and a route that requires one refuses a missing
  or mismatched declaration with `426 Upgrade Required`, naming the stale side —
  **after** authentication (so an unauthenticated peer learns no versions) and
  **before** the body read (so a refused push is not buffered first), hence
  before any effect and with no audit row written.

  It cannot be demanded of every request: most guest traffic is `nix`, Claude
  Code and codex, which will never send a writ header. So `VmHttpRoute` carries
  an exhaustive `contract_check()` — `Required`, or `Exempt` with the reason
  (`Handshake` / `ThirdPartyClient` / `NoEffect`) — and a new capability must
  choose. `GET /v1/session` is writ-vm-originated and still exempt: it is where a
  guest *reads* the broker's version, so gating it would make a skew
  undiagnosable, and the readiness probes hand-roll it. The two sides are kept in
  step by `WRIT_VM_ORIGINATED_TARGETS` (`writ-vm-git`), against which the route
  table pins two implications: everything the guest originates is
  `Required`-or-`Handshake`, and everything `Required` is originated.

  What this does **not** cover, stated plainly: the exempt surface — the model
  proxies and the binary cache — stays reachable to a stale guest, so it can burn
  model tokens before its first clone is refused. And the header is
  guest-controlled, so this is skew protection between builds we control, not a
  security control; the boundary remains the broker's independent re-validation
  of every field.

Both are pinned by one CI test, `broker_contract_fingerprint_is_pinned`
(`broker_vm/tests.rs`): it snapshots the broker's CLI flags and ready-doc schema,
and pins a **digest of the guest-facing route surface** — sourced from the route
table's endpoint map, which the totality oracle already forces to be complete,
and including each route's `contract_check`, so that changing *which* routes
demand a declaration moves the digest even though no path moved —
in an append-only `GUEST_ROUTE_DIGEST_HISTORY` indexed by
`VM_HTTP_CONTRACT_VERSION`. Because the live digest must equal the row *for the
current version*, and the history must have exactly one row per version, moving a
path fails until a new row is appended and the version bumped. (A golden test
cannot make the wrong repair impossible; it can make the right one easy and the
wrong one — overwriting recorded history — conspicuous in review.) That coverage
exists because the mechanism was twice not applied: the model-proxy namespaces
moved every guest URL, and `/v1/session` began reporting a contract version, both
without a bump. A path change *is* a contract change.

**The route table.** A request is classified **once**, by
`VmHttpRoute::resolve`, into either `Brokered(BrokeredRoute)` — an effect whose
`(request, outcome)` audit pair the `broker_effect` driver owns — or
`Plain(PlainRoute)`, a *closed* set of routes that deliberately record no pair
(the session endpoint; the agent-run *config* endpoint; `git_clone`, whose audit
is the host mint, until that follow-up). The resolved route then answers every
downstream question: which auth scheme applies, what body limit to read under,
how an auth *denial* is recorded against that route's own table, and which
handler runs. Four sites used to re-derive that from the target independently.

Two oracles keep it honest, and together make the invariant
add-a-capability-proof: adding a `BrokeredRoute` variant is a **compile error**
until the body-limit, denial, and dispatch matches all handle it; a coverage test
then fails until it appears in the documented endpoint map; and
`every_brokered_route_records_a_complete_audit_pair` (`vm_http/tests.rs`) fails
until the route is actually driven end-to-end and leaves a complete audit pair.

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
`AdmittedFlakeProvision`/`PerformedFlakeProvision`/`FlakeProvisionReport`
(`flake_provision.rs`) — the admit/run split that lets the shell record the
attempt between pre-flight and egress; the flake modules write no audit rows
themselves. Nix cache: `NixNarInfo`,
`NixTrustedPublicKeys` (`nix_binary_cache.rs:50,68`), route enum `VmNixCacheRoute`
(`vm_http/nix_cache/route.rs:28`).

**Guarantees.** The guest reaches only these routes (subnet auth). Each
re-validates: the nix cache admits only signed narinfos and verifies NAR bytes
before relay; flake provision re-derives the checkout from the broker's own
retained mirror and re-authorises the repo against this session's grants
(`vm_http/flake_provision.rs:120`). Model credentials are injected host-side
only: guest auth is stripped and the host key attached from the secret store.

**The brokered-effect driver.** An effect's `(request, outcome)` audit pair is
written by `vm_http/broker_effect.rs`, not by the handler: an effect declares
`BrokeredEffect` (which `EffectAuditTable`, how to *acquire* the guard, how to
`perform`), and the *driver* holds the `#[must_use]` `RecordedRequest` guard
across the effect and discharges it — `complete` with a truthful outcome,
`abandon` where no outcome is truthful, or into a streaming body that completes
on drop. Acquisition has two shapes: **two-phase** (`begin_effect` writes the
request row before the effect — the proxies, git-push staging, flake
provisioning) and **outcome-only** (`resume_effect` re-acquires the row an
earlier lifecycle event minted — agent-run outcomes, whose `agent_run` row is
written at run *launch*). `resume_effect` also *claims* the key for the guard's
lifetime, so two concurrent uploads for one run cannot both perform the effect
and then race for the outcome row's primary key; the loser is refused with
`409` rather than told a `200` it cannot verify. Each handler keeps a
*reject-before-begin* phase for everything that answers without attempting an
effect (a malformed body, a closed session, a foreign or unknown run, an
idempotent retry, a flake cache miss or a lock the classifier refuses), so those
record nothing. The authority-free nix-cache serve — already atomically paired
via `record_effect_coalesced` — joins with the route registry.

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

**Lives in.** `git_push_staging.rs` (1503), `git_push_approve.rs` (898, with its
test suite in `git_push_approve/tests.rs`),
`git_push_promote.rs` (1782), `git_push_trailers.rs` (the commit-trailer
vocabulary), `git_push_object_parse.rs` (827, tests in
`git_push_object_parse/tests.rs`),
`git_push_objects_cat_file.rs`, `git_push_walker.rs` (1485) +
`git_push_walker/`, `clean_git.rs` (661 — the git-flavoured wrapper: it owns
program resolution, stderr secret-redaction, and the success/exit-status policy,
delegating the supervision loop to `process_supervisor` (§5.5) and the env recipe
to `writ_core::git_env` (§5.1)).

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
4. **Replay/walk** (`git_push_walker.rs:319`): per-commit → tree closure
   → blob re-upload.

**Primitives.** `StagedEntry`/`GitPushStagingStore` (`git_push_staging.rs`);
parsed `StagingCommit`/`StagingTree` + `ParseObjectError`
(`git_push_object_parse.rs`); plan types `FastForwardPlan`,
`BranchCreationPlan`, `ShaMap` (`git_push_walker.rs`); the object-source
abstraction `trait GitObjectSource` with production `CatFileObjectSource`
(`git_push_objects_cat_file.rs`).

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
- **`github_git_db.rs`** (571, with the `GitDataClient` request methods in
  `github_git_db/client.rs` and tests in `github_git_db/tests.rs`) — a typed
  client for GitHub's Git Database API
  (blobs/trees/commits/refs), used to re-create bundle commits object-by-object
  under the App identity so published commits land Verified. Split in two by
  lifetime: the bounded transport (`GitDataHttp`, one per broker, held on
  `BrokerState`) and the credentials (`GitDataClient`, one per approve, since
  the installation token is minted per approve).
- **`notes_repo.rs`** (1154, tests in `notes_repo/tests.rs`) — a shared bare-repo wrapper (used by both writ and
  bailiff) for attaching/reading git notes that carry signed run envelopes.
- **`vm_git_bundle.rs`** (1760) — plans/executes `git clone --mirror` + `git
  bundle create` for a guest clone request.
- **`vm_git_mirror_cache.rs`** (951) — a `(repo, rev)`-keyed on-disk cache of
  bare mirrors so flake provisioning reuses a mirror instead of re-fetching.

**Primitives.** `GitDataHttp`/`GitDataClient`/`CommitRequest`/`CommitIdentity`/
`TreeEntry` (`github_git_db.rs`); `NotesRepo`/`WriteOutcome` (`notes_repo.rs:120,101`);
`GitCloneBundlePlan`/`GitCredentialBoundary` (`vm_git_bundle.rs:51,22`);
`MirrorCache`/`MirrorCacheKey`/`MirrorCacheBounds` (`vm_git_mirror_cache.rs`).

**Guarantees.** `github_git_db`: every client is time-bounded by construction
(a `GitDataClient` can only be built from a `GitDataHttp`, which can only be
built from `GitDataTimeouts`), and the approve path is handed a client rather
than the credentials to build one, so it cannot construct a per-request
transport;
blobs are always base64 to avoid SHA desync; a signed `create_commit` returns a
SHA only if GitHub reports `verified:true`; `update_ref` hard-codes
`force:false` so non-fast-forwards surface as errors. `notes_repo`: byte-exact
round-trip (bypassing `stripspace`), append-only notes in a validated bare repo,
serialised by a per-repo process-wide mutex; the note **body is an opaque signed
envelope — verification lives in callers** (`run_verify.rs`), not here. Every
`notes_repo` git child is supervised (§5.5), so each invocation is bounded by a
wall-clock deadline, a stdout cap, and a process-group kill — these calls are
bailiff workflow steps, so an unbounded wait is a workflow that stops with no
diagnosis, and a `for-each-ref` over a corrupted ref namespace must not be able
to buffer without bound. `vm_git_bundle`: size cap + path-containment re-checked
post-run. `vm_git_mirror_cache`: atomic-rename publish, pin-protected + bounded
eviction.

**Invariants.** Commit-signature check (`github_git_db/client.rs:228`); bundle
byte cap + path containment enforced at plan time (lexically — the bundle does
not exist yet) and re-checked at runtime by a single `validate_bundle_location`
that canonicalises once and asserts both "under the work dir" and "not under the
mirror", so the two halves of the boundary cannot be updated out of step;
`GitCommitSha::parse`/`MirrorCacheKey` sha256 slug are parse-don't-validate;
cache eviction honours `max_entries` + `max_bytes` oldest-first and skips
pinned slugs.

**Neighbours.** `github_git_db` → git pipeline + minting; `notes_repo` →
`run_verify`, `server`, `agent_vm_daemon/materialize`, bailiff;
`vm_git_bundle`/mirror cache → the VM git endpoints and flake provisioning.

**Current-state note.** `notes_repo` is *not* bailiff-only: each daemon owns its
own bare repo (writ writes `refs/notes/writ/v1/*`; bailiff fetches those and
curates `refs/notes/bailiff/v1/plans/*`).

**Compaction.** Because §5.1 suppresses git's background auto-maintenance in
every repo writ owns, packing loose objects is now writ's job.
`NotesRepo::compact_if_needed` measures with `count-objects -v`, decides with the
pure policy in `notes_repo/compaction.rs`, and runs a plain `git gc` when the
loose count reaches git's own `gc.auto` default of 6700 — the aim being to do
what git would have done, where git would have done it, but synchronously and
under the per-repo mutex every other mutation here already takes. `writd` calls it
after the note write in `sign_and_store_run`, so both `RunAgent` arms are covered;
a compaction failure is logged and does not fail a run whose envelope is already
durable.

Three facts behind that shape, each measured on git 2.54 rather than assumed.
(1) `gc` serialises against `gc` through `<repo>/gc.pid` — a second gc whose
recorded pid looks live refuses outright — whereas `git maintenance` does not
consult that lock at all, which is why `GC_ARGV` is a `gc` and why `--force` is
forbidden. (2) The prune grace (default two weeks) is the *only* concurrent-writer
mitigation these repos get: git-gc(1) lists two and the other is reflog
retention, which does not apply because a bare repo defaults
`core.logAllRefUpdates` to false and so writes no reflog. Because that grace is
the only one, writ *imposes* the date (`--prune=2.weeks.ago`, git's own default
spelled out) rather than inheriting it: the hardened recipe silences the system
and global config but deliberately not `<repo>/config`, and a `gc.pruneExpire=now`
set there makes a plain `gc` prune a freshly-written unreferenced object
immediately. (3) Compaction is read-safe even though it eventually
prunes writ's seed blobs. Those blobs are genuinely unreachable — git-gc(1) is
explicit that a note attached to an object does not keep it alive — but a note
lookup does not need them, because the notes tree keys entries on the OID's hex
string rather than on a reference to the object. `notes_stay_readable_after_a_gc_
prunes_the_unreachable_seed_blob` pins this, and bailiff has always relied on it
implicitly: a fetch only ever transferred the reachable objects, so bailiff's
mirror has never held writ's seed blobs.

Compaction runs on a request path, so a failure that repeats every request would
be a permanent tax on every agent run — and the worst case is self-sustaining, a
`gc` killed at the invocation deadline having published nothing, leaving the
loose count above the threshold for the next request to retry from scratch. A
per-repo retry gate (`COMPACTION_RETRY_BACKOFF`, one hour) bounds that to one
attempt per window, so the fallback is "no compaction" — what writ did before —
rather than "no compaction plus a deadline's delay on everything". The gate lives
inside the notes-write mutex's payload rather than beside it, which makes
consulting it without holding that lock unwriteable, and shares it between
handles on one repo exactly as the lock is shared.

The gate covers the whole attempt. It is consulted *before* `count-objects`,
because measuring is itself an invocation against the object directory and can be
the thing holding to the deadline; it closes on a failure at any step, including
the measurement taken *after* a successful repack; and it closes on a `gc` that
returns success having moved the count not at all, which would otherwise be a
full repack per request for as long as the cause lasts. "At any step" is
structural rather than remembered: `attempt_compaction` is not given the state to
record in, so the gate is written in exactly one place and no exit can forget it.
Three separate hand-written exits were tried first, and two of them missed a
path. That is reachable rather than theoretical:
measured on git 2.54, `gc.cruftPacks=false` in `<repo>/config` leaves young
unreachable objects loose, and writ's seed blobs are exactly those, so `GC_ARGV`
imposes `--cruft` alongside the prune date. Those two are where imposition stops
— they are the settings writ's stated guarantees rest on, whereas other config
can make a `gc` slower or looser without breaking a guarantee, and chasing every
knob would be re-implementing git's configuration in argv.

Two things still open. Bailiff's own repo accumulates one pack per
`fetch_from_remote` and nothing yet calls `compact_if_needed` for it, so the pack
half of git's auto policy (`gc.autoPackLimit`) has no live trigger and is
deliberately not implemented. And a plain `gc` rewrites all packs, so its cost
grows with total history while the threshold that fires it counts only the recent
backlog; a large enough repo may never finish inside `NOTES_GIT_TIMEOUT`. Raising
that deadline is not obviously right, because the mutex is held throughout, so a
longer deadline stalls every note write; the likelier answer is an operation
whose cost matches its trigger (`git repack -d` packs loose objects without
rewriting existing packs), at the price of the `gc.pid` exclusion above. That
trade is unresolved rather than decided.

### 5.9 Run provenance — envelopes & verification

**Purpose.** The broker's `RunAgent` handler mints a signed envelope per agent
run (metadata + detached SSHSIG + framed output), stores it as a git note, and
downstream consumers (bailiff) verify it.

**Lives in.** The `writ-agent-run` crate (the run contract + process-runner,
re-exported as `writ::agent_run`), plus `agent_run_envelope.rs` (builds the
signed envelope from an outcome row), `run_envelope.rs`, `run_verify.rs`,
`run_provenance.rs` (the pure log/note cross-check) and `SignedRunMetadata` in
`protocol/views.rs`. `writ-agent-run`'s contract types are
always compiled; its runner/hashing sit behind the crate's `vm-client` feature
(and host-only `AgentPrompt::summary` behind `host`), so both the daemon and the
guest share it. The `run_envelope`/`run_verify` host modules stay in `writ`.

**Primitives.** `SignedRunEnvelope` + `OutputEnvelope`
(`run_envelope.rs:111,68`); `SignedRunMetadata` with `canonical_bytes()`
(`protocol/views.rs:178`); `AllowedSigners`/`verify_run_envelope`
(`run_verify.rs:61,265`).

**Two questions, two mechanisms.** `verify_run_envelope` answers "is this note
internally consistent and signed by a key I trust" — both facts drawn from the
note itself, so any holder can check it, and bailiff does. It cannot answer
"did writ actually run this", because that evidence lives in the audit
database and the stream files, which only the daemon has.
`ClientMessage::VerifyAgentRun` is the second question:
`run_provenance::cross_check` compares the note's metadata against the
`agent_run` / `agent_run_outcome` rows (session, prompt hash, exit code,
completion time, output digest) and returns a `RunProvenanceVerdict` — a DU, so
"no such run" cannot be read as "nothing wrong found". Only metadata and
signature cross the wire: `output_envelope_sha256` already binds the output,
and writd re-derives that digest from its *own* stream files via §5.9's
materialiser, which re-checks those files against the rows as it reads. So the
request stays small however large the run's output was, and the output side of
the comparison is writ checking its own files rather than agreeing with the
caller's copy of them.

The two checks compose in one order only, and a caller that skips the first
gets a true answer to the wrong question: only metadata and signature travel,
so an envelope whose *body* was swapped after signing still asks writd about
authentic metadata, and writd — re-deriving the digest from its own intact
files — truthfully answers "corroborated" about a note that is not the one the
caller holds. `run_verify::check_output_digest` is that first half, split out
of `verify_run_envelope` because it is the one check that needs no keyring and
the one whose absence is silent; `writ agent verify` runs it before the RPC.

This needs no change to the signed format — every compared field already exists
on both sides. It is also not proof against a determined local attacker: writ
is single-operator, so whoever can rewrite the database can reach the signing
key. What it closes is *partial* divergence — a note altered without the log, a
row altered without the note, a stream file replaced after the fact, or a bug
in either writer — which is the space where a wrong answer is otherwise
indistinguishable from a right one.

**Guarantees & invariants.** The signature covers only
`metadata.canonical_bytes()` (compact serde JSON, fixed field order,
`deny_unknown_fields`); the output is bound transitively via
`output_envelope_sha256`. Verification runs three ordered checks — output-digest
re-hash → fingerprint-in-keyring → SSHSIG verify under the `writ.run-agent`
namespace — so tampered output → `OutputDigestMismatch`, unknown key →
`UnknownSigner`, tampered metadata → `SignatureInvalid`.

**Neighbours.** Repo/object types come from `writ-vm-git`; envelopes are minted
by `agent_run_envelope::materialize_signed_run_envelope` — which **both**
`RunAgent` arms call, so a host-spawned and a VM-sandboxed run produce
envelopes that mean the same thing — and verified by bailiff via a notes-ref
fetch. Its inputs are the `agent_run_outcome` row and the stream files that
row names, never an in-memory capture, so the signed bytes describe what
survived the run.

Re-reading those files opens a window in which they can change — anything
running as the daemon's user can rewrite one, including a detached helper left
behind by the agent whose output it is — so the bytes are checked against the
row before they are signed, and a mismatch refuses rather than vouches. The
recorded hash is writ's own: computed by the host arm's capture, or re-derived
by the broker from the guest's upload before writing it (§5.6 checks the
guest's claim against the bytes at that point). The check is total — length and
hash of the *whole* file, not of the prefix that gets signed. That costs
nothing extra: the read already has to continue past the envelope cap (the only
way to know the file ran over it), so hashing what it reads is the whole of the
additional work, and checking only the prefix would let a tamperer who keeps
the length above the cap buy a signature the row contradicts.

The read ends one byte past the length the row records, rather than at EOF: a
file that keeps growing has no EOF, and a host-spawned agent that leaves a
helper appending to its own stream file would otherwise choose how long writ
reads and hashes for it. That one byte is all a mismatch needs. So the row's
length bounds the read in time the way the envelope cap bounds it in memory.

The file is also opened `O_NONBLOCK|O_NOFOLLOW` and `fstat`ed for "regular
file" before any of it is read — a path is not a file, and the host-spawn arm's
agent runs as writd's own user, so it can leave a FIFO where its log used to
be; opening one blocks before any check could run. Checking the descriptor
rather than the path is what makes that a check rather than a race.

Both crates hash a stream through one `writ_agent_run::Sha256Stream`, so the
capture's digest and this re-read's are comparable by construction.

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
  `/v1/health`, `/v1/agent-vms`, `/v1/agent-vms/<id>`,
  `/v1/agent-runs/<run_id>`. The run resource is keyed by run id rather
  than nested under the session, because a run outlives its VM: the audit
  rows survive `close_agent_vm_session`, so nesting would shrink the
  reachable set as sessions end. Follow `current_run_id` from a VM row to
  reach it. The VM routes join audit state through one batched
  `sessions_with_latest_run` rather than per-row lookups, so query count
  is bounded by chunk size rather than by fleet size, and list and detail
  cannot drift into answering differently about the same session.
- **`crates/writ-vm-git/`** — the shared host↔guest wire-types crate.

**Guarantees & invariants.** The guest client is an ergonomic wrapper, **not an
authority boundary**: it re-asserts local invariants (branch-head/bundle-head
mismatch, bundle-size cap) for fast failure, but the broker re-validates every
request server-side. The `writ-vm-client` crate depends only on `writ-core`,
`writ-vm-git`, `writ-agent-run`, `reqwest`, `base64` — no host crate — so the
crate graph, not a feature flag, is what keeps the guest surface host-dep-free.
The UI is read-only over audit: GET-only, 405 on writes. Wire boundaries
parse-don't-validate (bearer-token byte check, broker-URL rejects
query/fragment/non-http). Every UI response is a *projection* of audit rows
with nothing recomputed — `/v1/agent-runs/<id>` reports the `sha256_hex` the
outcome row recorded and does not re-hash the stream files, because
corroborating a recorded digest against bytes on disk is §5.9's job and a
read endpoint that silently did both would make a verification result look
like a field.

**Neighbours.** `vm_client` → §5.6; `writ_client` → the daemon; `ui_http` →
audit; `writ-vm-git` shared with the git pipeline and run provenance.

**Current-state note.** `broker.md` lists "Web UI" and "MCP wrapping" as v1
non-goals; both now exist in read-only form via `ui_http` (see the
`2026-05-12-ui-data-api.md` plan).

### 5.11 bailiff — workflow on top of writ

**Purpose.** A separate binary implementing a per-plan **submit → review →
decide → implement** workflow layered on writ's `RunAgent`/`OpenSession` RPCs.
Each step verifies a broker-minted signed run envelope and records a
bailiff-owned note in bailiff's own bare git repo, keeping product-level
workflow out of the security-critical broker.

**Lives in.** `crates/bailiff/` (`bailiff_plan_{submit,review,implement,write,
read,view,note,state}.rs`, `bailiff_stage.rs`, `bailiff_decision.rs`,
`bailiff_repo_guard.rs`, `bin/`).

**Stage phases.** The three agent-run workflows are compositions of a shared
phase vocabulary in `bailiff_stage.rs`, not three hand-written bodies:
`open_plan_stage` (take the plan lock, then gate), `compose_with_plan_body`
(read the submission note, verify the planner envelope, splice the body under
the stage's framing), and one of two run phases. `AgentStage` is `PlanStage`
minus `Decide` — the stage with no agent run — and `PlanBodyStage` refines it
further to the two stages that *consume* a plan body, so "compose a prompt for
decide" and "splice a plan body into the planner's own prompt" are both
unrepresentable. Each phase's error type is total for its callers, so every
workflow's map into its own error enum is an exhaustive match with no
unreachable arm.

**Session ownership is a type-level distinction.** `run_under_owned_session`
(submit, review) opens the session, binds `RunAgent` to it, cross-checks the id
the broker stamped into the signed metadata, and closes it on every exit path
after the open. The broker requires this: its host-spawn arm refuses a
`RunAgent` with no `session_id`, because the run's `agent_run` row keys onto a
`session` row and there is no honest id to record without one (it used to mint
an unopened `SessionId` and stamp it into the signed envelope, which claimed a
session no verifier could resolve). `run_under_broker_session` (implement) does
none of that: writd's VM dispatch arm mints its own audit session and closes it
before `RunAgent` returns — and correspondingly *refuses* a caller-supplied
`session_id`. Two functions rather than one function over a flag, so the
close-session path is not *reachable* from the VM-dispatched stage. Callers are routed by the
data they hold — only implement has an `AgentVmWorkspaceBootstrap`, which is the
same field writd's dispatch keys on.

**Workflow.** One transition relation, in `bailiff_plan_state.rs`. `NotePresence`
is the observation (whether the plan's ref exists, which of the four notes exist,
and the decision's outcome — ref existence is what keeps an untouched id apart
from an existing-but-empty ref, which is an anomaly rather than a fresh plan),
`derive_state` parses it into a `PlanState` (Absent/Submitted/Accepted/Rejected/
Reviewed/Implemented/Corrupt), and `allows(state, stage)` is the gate every
mutating verb calls — submit from `Absent`, review from `Submitted`, decide from
`Reviewed`, implement from `Accepted` **or `Implemented`**.

`implement` is the one repeatable stage: fan-out is N implementer runs on one
accepted plan, so a plan that is already `Implemented` may take another attempt.
Each attempt owns a seed (`<plan-id>::implement`, then `::implement::<n>`;
attempt zero keeps the pre-fan-out bytes so existing notes are not orphaned) and
attempts are **dense from zero**, which is what lets the gate ask about attempt
zero alone rather than scanning. A gap is refused, not truncated. The attempt
index is chosen by the workflow under the plan lock, never named by an operator,
and it rides on `StageNoteSlot` rather than on `AgentStage` so that "the third
submission" stays unrepresentable. Attempts on one plan share that lock, so they
serialise; parallel variants would need the write keyed by `(plan, attempt)`. Review precedes the decision because
reviewer feedback is an input to it (`2026-05-11-agent-plans.md`: "the review →
decide → execute cycle"; "reviewer feedback is for the decision, not for
execution"). The four ad-hoc idempotency gates are
subsumed: a stage is illegal from the state it produces, so "already decided /
reviewed / implemented" needs no separate check (the write-side
`write_note_if_absent` rejection remains as the backstop, in the same spirit as
the approve path's SQL triggers).

`Corrupt` is *defined by* the relation rather than listed separately: it is any
note set no legal stage sequence could have produced. That makes the corruption
detector and the gate two readings of one definition, checked by a reference
implementation that walks the relation without consulting the state⇒presence map
(`reachable_presences_are_exactly_the_non_corrupt_states`).

**History.** Until 2026-07-26 this was four disagreeing encodings: `plan_decide`
read no precondition at all (so it could stamp a verdict on an unsubmitted plan
and *manufacture* the `Corrupt` row the display layer exists to report),
`submit_review` gated on the submission alone, `submit_implement` gated on
submission → `Accepted` → no prior implement but never read the review note at
all, and `BailiffPlanSummary::state` derived a fourth relation for display whose
"highest stage reached" rule assumed the opposite stage order. Unifying them
tightened every gate; see `docs/plans/2026-07-26-bailiff-workflow-as-data.md`
for the delta table.

**Reading back.** `bailiff plan show` renders each note's metadata and
verification status; `bailiff plan dossier` renders what the runs *produced* —
the approved plan body once, then every implementer attempt's verified stdout —
which is what makes N variants comparable. The dossier re-verifies against
writ's current copy rather than trusting the note, withholds the bytes of any
attempt that fails to verify (recording the failure per attempt, so one bad
attempt does not hide the rest), and length-prefixes agent-controlled bytes
(`stdout_bytes=<n>` then exactly `n` bytes) so the output stays parseable
without escaping what a human needs to read. The shared fetch→verify→decode
chain is `read_verified_output`; acceptance policy is the caller's, because the
planner's stdout must be non-empty text while an implementer's need not be.

**Guarantees & invariants.** Each stage attaches a distinct note under one
per-plan ref `refs/notes/bailiff/v1/plans/<id>` at deterministic per-stage seed
OIDs, projected from `AgentStage::note_seed`. Every signed stage runs
fetch → verify: fetch writ's `refs/notes/writ/v1/*`, re-decode the envelope,
check metadata+signature parity against the RPC reply, then
`verify_run_envelope`. All three envelope-bearing stages go through one
`write_stage_note`; append-only/idempotent via `NotesRepo::write_note_if_absent`
(duplicate → `WriteStageNoteError::AlreadyRecorded`, which names its stage);
`deny_unknown_fields` on all notes; cross-plan `PlanIdMismatch` guards.

The three note bodies are field-identical and emitted by one `stage_note!`
macro, but stay **distinct types**: `read_plan_body_bytes` takes the submission
specifically, because its body is what gets spliced into the reviewer's and
implementer's prompts, and under a shared type handing it the review note would
compile. The macro removes the duplication at the source; the type system keeps
the distinction at the call sites. Their canonical bytes are pinned by a
checked-in literal, since a wire-format change orphans every note already in an
operator's repo.

**Locking.** Single-writer **per plan**, via `PlanGuard` (`bailiff_repo_guard.rs`):
one `flock` on `<bailiff_repo>/bailiff-locks/<plan-id>.lock`, taken on a blocking
thread and held for the whole workflow, so every gate-then-write sequence is
atomic. `acquire` waits rather than failing — the holder is typically
mid-LLM-run. All four mutating verbs take it, including `decide`, which before
2026-07-26 took no lock at all.

A **second, repo-wide** lock (`lock_repo_mutations`,
`<repo>/bailiff-locks/_repo-mutation.lock`) serialises every mutation of the
repo — fetches into the shared writ mirror and note writes alike. Per-plan locks
are the wrong granularity for git's repo-level structures:
`NotesRepo::fetch_from_remote` states that "Git's index / refs / objects writes
are not safe under concurrent fetch+notes-add into the same destination" and
enforces it with a *process-wide* mutex, which is the one scope that does not
help two `bailiff` processes on different plans. Held across each
fetch→read→write, inside the plan lock — the ordering is total (plan, then
mutation), so the pair cannot deadlock.

Waiting on a plan lock **polls with async backoff** rather than parking a
`spawn_blocking` worker on a blocking `flock`: a plan lock can be held across an
agent run, and a waiter occupying a pool worker for that long starves the holder
of the worker it needs to write the note that would release the lock.

One mechanism per scope, not two per scope: an `flock` binds to an *open file
description*, so two `open` calls contend even inside one process, and the kernel
supplies the in-process queueing that an earlier draft built a mutex registry to
provide. `PlanGuard::run_blocking` hands its lockfile *to* the blocking task, so
a cancelled workflow keeps the lock until its closure actually returns.
Per-plan granularity is safe because each plan owns its ref and git updates refs
through their own lockfiles (measured: 32 concurrent cross-process `git notes
add` calls on distinct refs, all successful); concurrent *git invocations*
against one repo are serialised a layer down by `NotesRepo`'s own per-path
mutex.

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
