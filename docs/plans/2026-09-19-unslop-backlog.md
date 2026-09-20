# Unslop backlog — structural review of the whole tree

Drafted 2026-09-19 against `main` at `100bb03`. Companion to
[`2026-07-17-architecture-refactor-backlog.md`](2026-07-17-architecture-refactor-backlog.md),
which fixed the *crate and file shape*; this one is about what is left once the
shape is right: duplication, vestigial code, comment archaeology, and tests that
no longer earn their keep. **It is a backlog, not a commitment.**

Scope: structure only. This is not a correctness or security review; nothing
below changes behaviour except where explicitly labelled *broken*.

Method: eight independent readers each took one slice (≈20–33k lines), read it
in full, and verified every duplication claim by `diff`/`grep`. Every `path:line`
below is against `100bb03`. Four of the most consequential claims were re-verified
by hand before this document was written (marked **verified**).

## Headline numbers

| Measure | Value |
|---|---|
| Rust lines (all crates + tests) | 182,617 |
| Shell lines (`scripts/`, `host-setup/`) | 11,713 |
| Comment lines in Rust | 36,472 (20%) — bailiff 29%, writ-agent-run 30% |
| Comment lines narrating history ("previously", "slice", "PR #", "no longer", "now") | ≈700 |
| `#[test]`/`#[tokio::test]` functions | ≈2,700 |
| `proptest!` blocks | ≈100 |
| `#[allow(clippy::too_many_arguments)]` | 28 |
| Test lines as share of slice | 50–66% everywhere |
| Estimated deletable lines (Rust + shell) | ≈15,000 |
| Plan/journal docs that are pure history | ≈8,000 lines |

## The five patterns

Almost every finding is an instance of one of these. Fix the pattern once per
crate rather than chasing instances.

### P1. Test scaffolding was copy-pasted instead of shared (largest delta)

Every slice found the same thing: the first test in a module built a fixture by
hand, and every later test copied it. No crate has a crate-level test-support
module; the ten `test_support.rs` files that exist are per-module and duplicate
each other.

Verified copies:

- `InMemStore` (a `Mutex<HashMap>` `SecretStore` with three 3-line methods),
  byte-identical in **12 files**: `src/server/test_support.rs:21`,
  `src/writ_client.rs:1129`, `src/config/tests.rs:2041`, `src/signing.rs:373`,
  `src/github.rs:731`, `src/vm_http/tests.rs:66`,
  `src/agent_vm_daemon/test_support.rs:37`, and four bailiff files
  (`bailiff_plan_submit.rs:390`, `bailiff_plan_review.rs:437`,
  `bailiff_plan_implement.rs:505`, `bailiff_plan_write/end_to_end_tests.rs:47`).
- A full 13-field `BrokerState { .. }` literal at **15 sites**
  (`src/server/test_support.rs:91,145`, `src/writ_client.rs:1202,1380`,
  `src/server/approve_crash_tests.rs:223`, `src/vm_http/tests.rs:131`,
  `src/agent_vm_daemon/test_support.rs:73`, six in bailiff).
- The VM-HTTP test scaffold (`MockServer::start` / `make_broker_state` /
  `session_for_subnet` / `open_audit_session` / `XService::new(...)`) at
  **≈115 sites**: `claude_proxy.rs` ×14, `openai_proxy.rs` ×8,
  `nix_cache/local_cache_tests.rs` ×27, `nix_cache/proxy_tests.rs` ×23,
  `vm_http/git_push.rs` ×15, `git_clone.rs` ×10, `agent_runs.rs` ×9,
  `vm_http/flake_provision.rs` ×9. Five hand-written
  `VmHttpServices { git_clone: None, … }` literals although `VmHttpServices::none()`
  exists.
- Fake executable-script writers: 11 `write_fake_*_tool` in
  `src/agent_vm_daemon/test_support.rs:97-446` (`write_fake_workspace_success_tool`
  at 409 is byte-identical to `write_fake_tool` at 97), six more in
  `src/agent_vm_firewall.rs` tests, five in `src/broker_vm_runner.rs`, two in
  `src/bin/writ-agent-vm-pf-helper.rs`, eight `write_*_fake_agent` in
  `crates/writ-agent-run/src/lib.rs:3892-4047`. All end in the same
  `fs::write` + `set_mode(0o700)` tail.
- Daemon test harness: 25 of 41 tests in `src/agent_vm_daemon/lifecycle_tests.rs`
  open with the identical seven-line tempdir/log/fake-tool/config/`AgentVmDaemon::new`
  block.
- Bailiff: `InMemStore` + `find_in_path` + `spawn_broker` (~100 lines) identical
  in four files; three stub brokers; eight hand-rolled "sign a
  `SignedRunMetadata` over an `OutputEnvelope`" builders;
  `bailiff_plan_read/test_support.rs` and `bailiff_plan_write/test_support.rs`
  duplicate `SIGNING_*` consts, `bailiff_repo`, `writ_notes_ref`, `signed_envelope`.
- Real-git helpers: `run_git` byte-identical in `src/git_push_walker/test_support.rs:121`,
  `src/fake_origin.rs:234`, `src/git_push_approve/tests.rs:218`; `rev_parse` ×3;
  `maybe_git`/`required_git`/`locate_git` ×3; `required_test_tool` in
  `src/vm_http/tests.rs:298`, `src/vm_git_bundle.rs:951`,
  `crates/writ-vm-git/src/tests.rs:151`, `crates/writ-vm-client/src/tests.rs:173`;
  `find_in_path` ×5; `tool_on_path`/`nix_program`/`git_on_path` are three more
  spellings; `shell_quote`/`shell_single_quote` ×6.
- Sample-value helpers: `sample_repo` ×7, `sample_object_id` ×7,
  `sample_signature` ×5, `sample_identity` ×4, `sample_metadata` ×5,
  `freshly_signed` ×4; signing-key fixture `include_str!` at 22 sites under four
  loader names.
- Per-file scaffold repetition: `src/server/run_agent_tests.rs` builds the 10-field
  `ClientMessage::RunAgent { .. }` literal 25 times; `src/config/tests.rs` repeats
  the `"github_apps"/"policy"` JSON preamble 20 times;
  `src/openai_chatgpt_auth/tests.rs` 15 tests share a 10-line preamble;
  `src/git_push_promote.rs` builds the same `InMemoryGitObjectSource` 7 times
  under 47 `Mock::given` blocks; `src/github.rs` repeats one
  `mint_for_agent_scoped(...)` call 20 times; `notes_repo/tests.rs` repeats
  `NotesRepo::init_or_open(tmp.path().join("r")).unwrap()` 51 times;
  `crates/writ-audit/src/grant.rs` repeats a 12-line `pre_mint` preamble ~20
  times; `approve_attempt_tests.rs` calls `start_approve_attempt(id, push, "alice", t)`
  40+ times; eight copies of the ~40-line daemon-config JSON literal across
  `broker_vm/tests.rs`, `broker_entrypoint.rs`, `lifecycle_tests.rs`.

**Fix (one PR per crate, M each; ≈ −5,000 lines total):**

- `writ-core`: `#[cfg(any(test, feature = "test-support"))] pub mod test_support`
  with `tool_on_path`, `shell_single_quote`, `write_executable_script(dir, name, body)`,
  `InMemorySecretStore` (move the `SecretStore` trait's in-memory impl next to the
  trait in `src/secret/mod.rs` if it cannot live in core), a `count_kinds`
  generator-coverage helper. Downstream crates enable `test-support` as a
  dev-dependency, as `writ-agent-run` already does.
- Root crate: `#[cfg(test)] pub(crate) mod test_support` with
  `broker_state(registry, overrides)`, `git::{run_git, rev_parse, required_git}`,
  `fixtures::signing_key()`, `sample::{repo, object_id, signature, identity}`,
  `FakeContainer` script composer, `Harness` for the daemon tests,
  `TestBroker::builder()` for VM-HTTP.
- Bailiff: one crate-level `mod test_support` plus `tests/common/mod.rs`.
- Delete the per-module copies in the same PR (complete the migration; do not
  leave both).

### P2. Production helpers were copy-pasted with drifting semantics

Unlike P1, these are in production code and the copies have *diverged*, so the
repo currently has several slightly different answers to one question.

- **Private directories and files.** `create_private_dir` in
  `src/broker_vm.rs:735`, `src/git_push_staging.rs:581`,
  `src/vm_git_mirror_cache.rs:507`, `src/vm_http/agent_runs.rs:525`,
  `crates/writ-agent-run/src/lib.rs:2075`; `create_private_dir_all` byte-identical
  in `vm_git_mirror_cache.rs:497` and `flake_materialize.rs:149`;
  `write_private_file` in `broker_vm.rs:754`, `git_push_staging.rs:605`,
  `vm_http/agent_runs.rs:541`, async twins in `git_push_approve.rs:651-750`;
  `create_private_work_dir` in `vm_git_bundle.rs:612`; `prepare_git_work_root`
  in `git_clone.rs:479`. **Verified**: the five `create_private_dir` bodies differ
  in whether they are recursive, whether they tolerate an existing dir, and
  whether they chmod a reused dir. Each carries its own umask essay.
  Fix: `writ_core::private_fs::{create_dir_0700, create_dir_all_0700, write_new_0600, write_0600}`
  with the rationale written once; `spawn_blocking` wrappers where async is
  needed. S, ≈ −150 lines, and one semantics instead of five.
- **Upstream URL parsing.** `VmHttpClaudeProxyConfig::new_with_anthropic_version`
  (`src/vm_http/claude_proxy.rs:145-195`), `VmHttpOpenAiProxyConfig::new`
  (`openai_proxy.rs:106-160`), `VmHttpNixCacheConfig::new_with_trusted_public_keys`
  (`nix_cache/config.rs:60-105`), `GitCloneBaseUrl::parse` (`vm_git_bundle.rs:250-283`)
  are the same 30 lines with four parallel 5-variant error enums. Fix:
  `UpstreamBaseUrl::parse` + one error enum; the four configs hold it; fold the
  identical proxy fields into one `ProxyUpstream` struct so the duplicated
  inherent+trait accessor pairs go away. M, ≈ −250.
- **CIDR parsing ×5.** `src/agent_vm_lifecycle/parse.rs:416-472`,
  `state_store.rs:852-887`, `agent_vm_pf_helper_policy.rs:241-267`,
  `broker_session.rs:238-249`, `bin/writ-agent-vm-runner.rs:374-393`; plus
  `src/config/mod.rs:2050-2104` `parse_ipv4_cidr_config`/`parse_ipv6_cidr_config`
  identical after s/4/6/. Fix: `impl FromStr for Ipv4Cidr/Ipv6Cidr` in writ-core
  (they already implement `Display`). S.
- **Gateway arithmetic ×7.** "network + 1" in `crates/writ-core/src/core/agent_vm.rs:411,439,444,777,1333,1590`
  and `pf_packet_model.rs:172`. Fix: `Ipv4Cidr::first_host()`. S.
- **Validated-string newtypes ×11.** `Sha256Hex`, `NotesRef`, `SshKeyFingerprint`,
  `SshSignature`, `GitCloneRepo`, `GitCloneRef`, `GitBranchName`, `GitObjectId`,
  `AgentPrompt`, `CorrelationId`, `RunPurpose` each hand-roll ~40 lines of
  `as_str`/`Display`/`FromStr`/`Serialize`/`Deserialize` plus the same four
  example tests. `AgentRunId` (`crates/writ-agent-run/src/lib.rs:35-283`) hand-writes
  what `uuid_id!` generates. The two 75/100-line serde visitors in
  `crates/writ-vm-git/src/lib.rs:731-809, 1144-1245` exist only to make a missing
  `Option` key an error, which `#[serde(deserialize_with)]` already does. Fix: a
  `validated_string!` macro beside `uuid_id!` (`writ-core/src/core/mod.rs:51`),
  export `uuid_id!`. M, ≈ −400.
- **`Sha256Hex::try_new(sha256_hex(x)).expect(..)`** at `run_verify.rs:273`,
  `agent_run_envelope.rs:169` and 30+ test sites; `sha256_hex: String` on six
  agent-run fields while `Sha256Hex` has 96 uses elsewhere. Fix:
  `Sha256Hex::of(&[u8])`, `Sha256Stream::finish() -> Sha256Hex`. S.
- **Wire framing ×3.** `read_line_bounded`/`MAX_LINE_BYTES` verbatim in
  `src/server.rs:835,847` and `src/writ_client.rs:43,368` (with a comment at
  `writ_client.rs:364` defending the duplication); the `to_string + push('\n') + write_all`
  frame hand-spelled at seven sites; `src/bin/writ.rs:1047-1208` is a third client
  with its own handshake and `BrokerReplyError`. Fix: `protocol::framing`, and
  make `writ` drive `WritClient` under a `tokio::time::timeout`. M, ≈ −250.
- **`GitDataClient` request boilerplate ×7** (`src/github_git_db/client.rs:56-403`,
  `src/github.rs:367-397` with literal header strings instead of the constants).
  Fix: private `request(method, segments)` + `into_success(Response)`. S, ≈ −90.
- **Config path-shape checks ×6** in `src/config/mod.rs:951,1614,1836,1867,1898,1930`,
  each with its own `Empty*`/`Relative*` error pair (10 variants in
  `AgentVmHttpConfigError`) and a `WritableRoot`/`RootPreparationFault` mapping
  that exists only to preserve variant *names*. Fix: one `PathShapeError { field }`.
  M, ≈ −250.
- **`writ-vm-client` command runner ×4** (`crates/writ-vm-client/src/lib.rs:974-1042, 1190-1238`,
  hardening comment pasted verbatim twice); three step enums named by accretion
  (`VmGitCloneStep` holds `Status`/`ResolveHead`). Fix: one `run_command` + one
  `Step` enum + `Spawn{step}`/`Failed{step}`. S, ≈ −150.
- **Two `git_env` loops ×4** (`crates/writ-core/src/git_env.rs:218-274`, sync and
  async copies of two functions; tokio 1.52 has `Command::as_std_mut()`). S.
- **Proxy backends.** `claude_proxy_auth_failure` ≡ `openai_proxy_auth_failure`;
  `*_forward_headers` share the dedupe loop; `forward_header_name`/`response_header_name`
  are 8- and 12-arm `eq_ignore_ascii_case` chains; `*_model_id` identical modulo
  prefix; `begin_error_response` identical in `vm_http/git_push.rs:343` and
  `vm_http/flake_provision.rs:324` (both string-match `AuditError::Invariant`);
  `fetch_metadata`/`fetch_nar` in `vm_http/nix_cache.rs:402,540` share a 50-line
  prologue; `read_upstream_body_bounded` copied from `proxy_common.rs:179`. Fix:
  header tables as `const` slices, one `forward_headers::<B>()`, one
  `fetch_upstream`, typed `AuditError::SessionUnknown/SessionClosed`. M, ≈ −300.
- **writ-audit**: `read_attempt_ledger_mint` vs `attempt_recorded_mint`
  (`git_push/dao.rs:177,656`); two 28-line SQL consts differing in the suffix
  (`git_push.rs:278,308`); migration-replay loop ×4 in `schema.rs`; three "latest
  run" queries (`agent_run.rs:416-512`) with a property that exists only because
  there are three. S, ≈ −150.
- **notes_repo**: the 26-line `notes add` argv block *including its 7-line comment*
  is byte-identical between `write_note` and `write_note_if_absent`
  (`src/notes_repo.rs:593-618, 669-694`); writ's own writer hard-codes
  `user.name=bailiff`. S.
- **bailiff read side.** `read_{decision,review,plan,implement}_note`
  (`bailiff_plan_read.rs:78-320`) are identical after noun-normalisation with four
  identical error enums and four identical 7-test modules (1,071 lines). The
  write side was already collapsed (`write_stage_note` + `stage_tests.rs`); the
  read side never was. Fix: `read_note_at::<N: StageNote>`. M, ≈ −900.
- **bailiff workflow surface.** `Submit{Plan,Review,Implement}Outcome` are
  `StageRun + plan_id` renamed; three error enums + eight `From` impls relabel the
  phase errors; `bin/bailiff.rs` `plan_submit/review/implement` share a 55-line
  prelude byte-for-byte; `ListError`/`ShowError`/`DossierError` are three copies
  of `{OpenRepo, Read(E)}`. Fix: return `(PlanId, StageRun)`, transparent error
  enums, a flattened clap `WorkflowArgs`. S–M, ≈ −350.
- **Shell.** Of ≈10.7k harness lines, ≈2.5–3k are byte-identical helpers
  (`write_fake_github_server` 54 lines ×6, `write_fake_git_origin_server` 116 ×6,
  `cidr_alloc_subnet` ×8, `choose_cargo` ×10, `require_cmd` ×11, `pick_port` ×9,
  `load_guest_image` ×6, `assert_*_absent` ×7, `log`/`die` ×13 differing only by
  prefix); `write_config` is a 95–123-line Python heredoc ×6; the "start python
  server, poll `/health` 50×" loop is copied three times inside one file.
  `flake.nix:279-563` and `:594-698` repeat the whole OCI image recipe. Fix:
  `scripts/lib/prove-common.sh` sourced by every harness (only 3 of 13 source
  the two existing libs); `mkOciImage` in the flake. L (mechanical, 13 files),
  ≈ −2,500.

### P3. Migrations were finished but the old path was never deleted

The gospel's "half-migrated system" tax. Each of these is a completed migration
whose predecessor still exists, usually as `#[cfg(test)]`, "kept for
compatibility", or simply unreferenced.

- **Dead branch-creation planner** (**verified**: no production caller outside
  its own module). `plan_branch_creation_via_rev_list`, `BranchCreationPlan`,
  `BranchCreationPlanError`, `branch_creation_to_fast_forward`
  (`src/git_push_walker.rs:528-776, 1018-1052`); `GitDataClient::get_default_branch`
  (`src/github_git_db/client.rs:250-290`) exists only for it; the approve handler
  refuses branch creation (`src/server/staged_push.rs:649`). Delete with
  `branch_creation_plan_tests.rs` (keep ~150 lines of pure `parse_*` tests), five
  `get_default_branch_*` tests, the `rev_list_plan_rejects_any_disjoint_history`
  proptest, and the stale flow doc at `github_git_db.rs:15-20`. M, ≈ −1,100.
- **writ-audit pre-guard writers.** `effect_table.rs` *is* the generic two-phase
  primitive and every table is on it, but 14 `#[cfg(test)]` direct writers remain
  (`proxy_table.rs:282,300`; `claude_proxy.rs:76,86`; `openai_proxy.rs:68,78`;
  `nix_cache.rs:91,101`; `flake_provision.rs:220,238`; `grant.rs:418,438,452`),
  and five "guard ≡ direct writer" proptests (`proxy_table.rs:1012,1076`;
  `flake_provision.rs:637`; `agent_run.rs:1547`;
  `git_push/request_outcome_tests.rs:252`) now compare a function with itself
  because both sides call the same `insert_*_row`. Ten `dump_*_rows` helpers
  exist only for them. Delete; retarget remaining tests at
  `begin_effect(..)?.complete(..)`. M, ≈ −750.
- **bailiff golden RPC traces.** `tests/rpc_trace_baseline.rs:3-10` says of itself
  "exists to be captured before slice 3, not because it is useful on its own";
  slice 3 shipped. 22 fixture files, an `UPDATE_RPC_TRACES=1` blessing switch.
  Replace with variant-sequence assertions. Also `bailiff_plan_state/tests.rs:47-67,
  182-269` pin the *deleted* derivation against the new one; and
  `bailiff_plan_write/end_to_end_tests.rs` (536 lines) is a real-broker copy of
  `stage_tests::happy_path_round_trips_for_every_stage`. M, ≈ −900.
- **`#[cfg(not(unix))]` arms** ×15 in `crates/writ-agent-run/src/lib.rs` plus
  `AgentExit::Reaped`, for a platform the workspace cannot build on
  (`writ-vm-client` uses `std::os::unix` unconditionally; CI is Linux only). S.
- **Constructor and runner ladders in `src/vm_http/mod.rs`**:
  `VmHttpRuntimeConfig::new` → `new_with_claude_proxy` (zero external callers) →
  `new_with_proxies`; `prepare_vm_http_session` (test-only) → `_with_agent_runs`
  → `_on_listener`; `run_vm_http` (test-only) → `run_vm_http_until_shutdown`
  (test-only) → `run_vm_http_runtime_until_shutdown`; `VmHttpProxies` is a
  two-`Option` pass-through. `VmHttpRequest.content_length` is parsed with two
  error variants and never read. `src/server.rs:1057` `run` / `:356`
  `dispatch_message` are test-only wrappers over the `_with_agent_vm` variants.
  Delete the ladders; tests call the real entry points. M, ≈ −200, −3 `allow`s.
- **Dead functions/variants**: `teardown_broker_vm` (`broker_vm_runner.rs:174`),
  `BrokerVmPlan::stop_invocations`, `BoundedOutput::combined`,
  `SessionFirewallInstall::new` (test-only, 8 params), `PersistedIpv6IsolationMode`
  (variant-for-variant copy of `Ipv6IsolationMode`), `AgentVmSessionState::from_json_bytes`,
  `session_pf_ruleset` (`writ-core/core/agent_vm.rs:729`, no production caller),
  `CommitSignError::Newtype`, `WritSigningKeyError::Fingerprint`,
  `PlanNotesRefError` (bailiff), `AgentStage::plan_body_stage`,
  `default_config_path` (`config/mod.rs:2128`), `AgentVmDaemonConfig::to_runtime_config`
  and its two tests, `secret_store_or_default`, the `default_*_path` wrappers used
  only by tests, `GitCloneBundlePlan::new`/`GitCloneBundleSource::github`
  (tests only; production uses `new_with_source`), `FlakeLock::version`,
  `FlakeProvisionPlan::cache_file_url`, `PerformedFlakeProvision::into_result`,
  `latest_agent_run_id_for_session`, eleven `pub use` re-exports in
  `crates/writ-audit/src/lib.rs:69-77` with zero external references, the
  `pub(crate) use … SignedBailiffNote` path-compat shim in `bailiff_plan_read.rs:43-51`.
  Also `git_push_object_parse.rs:261-264,537`: six `#[cfg_attr(not(test), allow(dead_code))]`
  serialisers waiting for "a dry-run orchestrator in a follow-up slice" that does
  not exist — move them into the test module as the oracle. S each.
- **Scripts**: `prove-nix-substituter-auth.sh` (298 lines, "before we build the
  real broker proxy"), `prove-vm-http-nix-cache-route.sh` (a wrapper around one
  `#[ignore]` test), `prove-flake-offline.sh` and `prove-prewarm-signed-offline.sh`
  ("proof for writ's *planned* …" — FK/PW shipped) are superseded by
  `prove-agent-vm-daemon.sh`. Archive with a tag. S, ≈ −950.
- **Orphaned proptest regressions** (**verified**): `proptest-regressions/audit/git_push.txt`
  (`src/audit` no longer exists; the crate copy is the live one) and
  `proptest-regressions/protocol.txt` (the test moved to `src/protocol/tests.rs`,
  so proptest now reads `proptest-regressions/protocol/tests.txt`; the saved seed
  is never replayed). Delete / move. S.
- **Docs**: 9 of 25 `docs/plans/*.md` have zero inbound references; ≈20 are
  shipped and therefore history; 40+ path references point at files that no
  longer exist (`src/vm_client.rs`, `src/protocol.rs`, `src/audit/plan.rs`, …).
  `docs/design/apple-container-agent-vm.md` (1,710 lines) references nine dead
  paths. `FLAKE.md` is an earlier draft of `docs/known-test-flakes.md` §1.
  `docs/vmnet-accept-bug-and-broker-vm-plan.md` opens with a 25-line CORRECTION
  saying its own root cause is wrong, and 12 places still link to it as the
  explanation. Move shipped plans and journals to `docs/plans/archive/` and
  `docs/design/archive/`, add a one-line `**Status:**` to the rest. Note
  `2026-05-11-writd-upgrade.md` is neither shipped nor marked
  (`daemon_impl.rs:946` still does what the plan set out to remove). S, ≈ 8,000
  lines out of the live tree.

### P4. Comments narrate the history of the code instead of describing it

About 700 lines say "previously / no longer / now / used to / slice X / PR #N /
a reviewer found"; a further large share are doc comments that *argue* a design
decision at essay length where `architecture.md` already records it. Comment
density is 20% overall, 29% in bailiff, 30% in writ-agent-run. Three doc comments
are attached to the **wrong item** and several **contradict the code**.

Wrong item (**verified** for the first):

- `src/protocol/mod.rs:296-334`: the `RunAgent` doc (ending "Slice A1 lands the
  request type only…") is followed by the `VerifyAgentRun` doc and then the
  `VerifyAgentRun` variant; `RunAgent` at `:335` is undocumented.
- `src/config/mod.rs:2132-2144`: the `default_audit_db_path` doc sits on
  `default_agent_run_log_root`.
- `src/config/audit_dir.rs:118-153`: the `ensure_audit_dir_is_dedicated` doc sits
  on `ensure_audit_db_entry_is_regular_file`.
- `src/broker_entrypoint.rs:264-269`: `prepare_broker`'s doc is glued onto
  `struct PreparedBroker`. `src/git_push_objects_cat_file.rs:287-290`: a doc for
  an RAII guard that lives in `process_supervisor`. `src/notes_repo.rs:1659-1690`:
  two stacked docs, the first describing a field that no longer exists.
  `crates/writ-agent-run/src/lib.rs:124-128`: a paragraph pasted twice.
  `bailiff_plan_write.rs:71-72,143-144`: "shared by write_stage_note,
  write_stage_note, and write_stage_note" (mechanical rename).

Stale claims that contradict the code:

- `README.md:34-42` "Not an interactive approval prompt… every request is
  auto-granted or auto-denied" and "GitHub is the only supported credential
  source" — `writ promote approve/reject` and the model proxies exist; the README
  never mentions the agent-VM subsystem. `docs/user_facing/cli-reference.md` omits
  `agent-vm`, `promote`, `agent verify`, `writd broker`.
- `crates/writ-core/src/lib.rs:1` "dependency-free" (it pulls `libc`,
  `tracing-subscriber`, optional `tokio`); `writ-vm-git/src/lib.rs:3-5` names a
  `host` feature the crate does not have; `writ-core/Cargo.toml:6` "the only
  host-only surface" is false.
- `crates/writ-audit/src/effect_audit_oracle.rs:1-26` "kept by discipline…
  nothing in the type system forces a handler" — false since the guard landed;
  `effect_table.rs:10` "exactly three operations" then lists two;
  `git_push/dao.rs:376` cites "the v13 schema" (`SCHEMA_VERSION` is 11).
- `src/protocol/mod.rs:255-259,312-316,548-550` "returns Error until slice …"
  (implemented); `:307-310` says `session_id: None` mints a fresh id (host arm
  refuses, `server/run_agent.rs:465`); `src/config/mod.rs:137-142` says the host
  arm "writes no files… records no audit rows" (it does both);
  `src/server/run_agent.rs:639-645` "Nothing bounds N" (bounded at `:560`);
  `src/writ_client.rs:4` cites `server.rs:1322` of a 1,158-line file and says
  "the only verb is run_agent" (three verbs).
- `src/git_push_approve.rs:1-34` says the handler is not wired yet (it is at
  `staged_push.rs:893`); `:454-457,469` name a function that does not exist.
  `src/git_push_walker.rs:12-15,44-45` "lands in a later commit/slice" (both exist).
- `src/agent_vm_lifecycle/cleanup.rs:8-9` says it uses `shell_quote` and
  `derive_session_network` (uses neither); `src/broker_vm.rs:6-7` "a later slice"
  (it is `broker_vm_runner.rs`); `src/vm_git_mirror_cache.rs:562-564` "no read
  API yet" (`get` exists); `vm_http/git_push.rs:1084-1099` two contradictory
  paragraphs about deleting the carrier.
- `docs/design/architecture.md:17-20, 92-96` still describe god-files and a flat
  crate that the 07-17 backlog says are fixed; `:1086,1133` record line counts
  already stale. `AGENTS.md:1-7` lists "all three" CI gates, omits four, and its
  clippy line lacks `--all-features`; it disagrees with `CLAUDE.md:17-44`.
- `host-setup/prewarm-cache/warm-via-container.sh:681-683,867-869` says the guest
  image strips grep/find/sed/awk; `flake.nix:453-471` ships them.
- `#[ignore = "re-enabled by slice VM3 once bailiff passes workspace: Some(...)"]`
  ×3 in `bailiff_plan_implement.rs:720,1057,1191` — bailiff passes it now; the real
  reason is that the test broker has no VM.

Design essays (correct but ten times too long; the rule is one sentence, the
rest is in `architecture.md` or git):

- `src/server/run_agent.rs:62-122` (61 lines on `AgentRunSlots` arguing two
  rejected alternatives); `src/protocol/mod.rs:34-99` (66 lines on the version
  constant); `src/config/default_paths.rs:1-105` (100-line module doc, plus a
  20-line "what the pre-table resolvers did" section); `src/server/staged_push.rs:382-459`
  (78-line numbered flow restating the body).
- `src/git_push_promote.rs` tells the three-lease-check story six times (1-38,
  233-249, 387-490 — 104 doc lines on a 46-line fn — 547-584, 286-297, 219-223).
  `src/notes_repo.rs` `GC_ARGV` 48 lines, `COMPACTION_GIT_TIMEOUT` 45,
  `compact_if_needed` 80; `compaction.rs` makes the "two axes" argument three times.
- `crates/writ-core/src/process_spawn.rs` states the RLIMIT_NPROC circular-cause
  argument three times (16-20, 208-220, 259-277) and again in three test docs;
  `git_env.rs:9-43` biography (keep 45-150, which are measured facts);
  `process_group.rs` "took three rounds of review"; `byte_size.rs:3-18` "Before
  this type they were spelled two ways".
- Bailiff module docs of 34–92 `//!` lines each (`bailiff_repo_guard.rs` 92,
  `bailiff_stage.rs` 55, `bailiff_plan_implement.rs` 55, …) that re-argue
  `architecture.md` §5.11; test docstrings that narrate reviews ("Regression for
  a Codex P2 finding", "Codex review caught it, correctly"); a 14-line eulogy for
  deleted tests at `bin/bailiff/tests.rs:1139-1152`.
- Agent-VM: `daemon_impl.rs:167-193, 264-288, 586-614` ("Eight now, because…"),
  `agent_vm_lifecycle.rs:113-155` (43 lines on a 10-line shell script),
  refactor trailers repeated on both sides of every module split
  (`invocation.rs:10-11`, `plan.rs:8-9`, `cleanup.rs:10-11`, `daemon_impl.rs:4-10`,
  and their parent-side duplicates).
- writ-audit: `approve_attempt.rs:13-32, 52-56, 364-369, 499-507` ("the first
  draft", "a reviewer was right", "used to spell them out in SQL");
  `schema.rs:60-65, 212-220, 398-411, 908-916` slice-G narration; pre-squash
  numbers `v5`/`v6`/`v3` leak through comments while the files are `0003`/`0004`.
- vm_http: `flake_provision.rs:1-52`, `flake_fixtures.rs:58-100` (43 lines on
  where a `-c` flag "used to live"), `agent_runs.rs:465-498` (33 lines on one
  bool), "Stage-0 audit-pair oracle" ×6, `route_table.rs:1-8` ("Three functions
  used to switch…").
- Non-code: `Cargo.toml:19-23,46-49`, `writ-audit/Cargo.toml:6-9`,
  `flake.nix:38-45,374-382,396-398` ("**now** ship… **no longer** forbidden"),
  `docs/known-test-flakes.md:45-66` and `FLAKE.md:132-181` stacking "Later /
  Later still / Correction" on a conclusion now known wrong.

**Fix (one comment-only PR per crate, S–M each; ≈ −3,000 lines):** the rule for
each block is *present tense, one sentence of rule, measured facts stay,
biography goes to git*. Fix the displaced docs and the false claims first; they
are the only comment defects that actively mislead.

### P5. Tests: examples where a property belongs, strings where a variant belongs

About 2,700 example tests against about 100 property blocks. The property tests
that exist are excellent (see "What is good"); the problem is the example tests
around them.

- **Properties that enumerate by hand and drift.** **Verified**:
  `src/protocol/tests.rs:1424` `client_message_rejects_unknown_top_level_fields`
  draws `variant_index in 0usize..13` while `ClientMessage` has 15 variants
  (`Hello`, `VerifyAgentRun` are never exercised) — exactly the drift the property
  was meant to prevent. Same shape: `prop_oneof![Just(..)]` strategies in
  `agent_vm_lifecycle.rs:1815-1838,1942-1947`, `cleanup_tests.rs:217-230`;
  `result_pick in 0u8..3` (`request_outcome_tests.rs:253`), `route_is_a: bool`,
  `agent_is_claude: bool`; `public_inputs_strategy` (`flake_lock.rs:1052`) only
  ever generates `github` inputs; `bailiff_plan_note.rs:1480` loops eight random
  ids by hand. Fix: a `const ALL: &[Self]` per enum with a compile-time
  exhaustiveness `match`, and `prop::sample::select(ALL)` — `PfInstallPhase::ALL`
  and `AgentRunTerminalStatus::ALL` already do this.
- **Tautological tests.** `crates/writ-core/src/bearer.rs:12-14`: the "reference"
  predicate is a character-for-character copy of the function under test.
  Constants asserted equal to their own literal: `writ-vm-git/src/tests.rs:714-770`,
  `process_spawn.rs:479-506`, `github_git_db/tests.rs:194-210`,
  `notes_repo/tests.rs:2062-2069` (make these `const _: () = assert!`),
  `flake_provision.rs:681`, `flake_lock.rs:1000`, `vm_git_bundle.rs:1981`,
  `route_table.rs:830` (`expected` derived from the same `matches!`),
  `github.rs:1798-1811` (tests `format!` on a local string). Substring assertions
  on script constants: `guest_env_tests.rs:107-131`, `guest_command_tests.rs:143-424`
  (12 tests of `script.contains(..)`), `broker_vm/tests.rs:437-455`. Delete, or run
  the script under `sh` with fakes as `guest_command_tests.rs:11-48` already does.
- **Example lists that are one property.** `git_push_object_parse/tests.rs`: 45
  examples hand-enumerating fsck rules; the oracle is differential (`parse` ok
  iff `git hash-object` + `git fsck --strict` accept). `src/config/tests.rs:717-930`:
  12 `agent_vm_http_config_rejects_*` differing only in the mutated field.
  `src/protocol/tests.rs`: ~35 six-line `*_roundtrips`/`*_type_tag` examples.
  `classify_*_strips_query_string`, `resolution_does_not_depend_on_the_method`,
  `nix_cache_path_classifier_rejects_non_cache_protocol_paths` (25 literals beside
  a proptest that should absorb them). `github_git_db/tests.rs` three ×3 families
  that are one table each. `bin/bailiff/tests.rs`: 14 "verb rejects missing flag"
  tests → one table over `(verb, required_flags)`. Ten writ-audit tests re-assert
  the session trichotomy that `validation.rs:135-159` proves once. Reference-
  predicate properties for `CorrelationId`, `Sha256Hex`, `NotesRef`, `SshKeyFingerprint`,
  `SshSignature`, `BrokerPort`, `PfCounterKey` on the model of `RunPurpose`
  (`writ-agent-run/src/lib.rs:2599-2689`).
- **Assertions on error-message text** (≈150 sites): 49 in the git slice, 33 in
  writ-audit (SQLite prose), 17 audit-label strings in nix-cache tests, 13 in the
  member crates, `src/bin/writ.rs:1306-1351`, `staged_push_approve_tests.rs`,
  bailiff `bin/tests.rs` `msg.contains("--plan-id") || msg.contains("required")`.
  Root causes are structural: `CleanGitError` stringified at five boundaries
  "because it is `pub(crate)`" (`walker.rs:533`, `approve.rs:140`, `cat_file.rs:116`);
  `sha: String` in error variants where a `GitObjectId` is in hand
  (`GitObjectSourceError`, `ReplayError::UnmappedParent`, `DivergedHistory`,
  `BundleTipNotACommit`); `PromptMismatch { signed: Sha256Hex, audited: String }`;
  `AuditError::Invariant(&'static str)` with ~80 literals matched by string in
  `vm_http` handlers; `narinfo_audit_error_label` is a 30-arm variant→string
  table; the bins return `Box<dyn Error>`. Fix the types; the string assertions
  then become `matches!(err, Variant { .. })`.
- **Heavy tests of pure things.** `src/writ_client.rs:1174,1356` spawn a broker +
  `cat` to check a framing property that is one line
  (`serde_json::to_string(&max_prompt).len() <= MAX_LINE_BYTES`); every Claude
  header test spins a raw TCP upstream + wiremock + audit DB to check
  `forward_header_name` while OpenAI tests the pure fn directly; eight bailiff
  gate tests spin a full broker to observe a pre-RPC refusal that
  `tests/stage_gate_zero_rpc.rs` already proves over the whole grid;
  `state_store_tests.rs:36-710` writes eight stateful shell fakes to re-test exit
  code handling that is property-tested; `prepare_approve_bounds_a_stalled_cat_file_traversal`
  (97 lines, 120 s guard) re-tests a lower layer's timeout through the whole
  pipeline. Keep one per layer.
- **Source-scanning tests.** `src/server/run_agent_tests.rs:1697,2006` `include_str!`
  production source and brace-match it; the first could be a type
  (`accept_agent_run_session` requiring an `AgentRunQueuePlace` minted by
  `enqueue`), the second greps for the word `timeout`.
  `tests/shared_hardening_helpers.rs` is the justified version of this pattern.
- **`#[ignore]` with stale reasons**: bailiff ×3 (above); `nix_cli_can_authenticate…`
  (`vm_http/tests.rs:1358`, ~100 lines, never runs in CI); writ-guest-init ×4 are
  the crate's only runtime evidence and nothing runs them — worth a
  `prove-*.sh` entry.
- **Missing-git policy is four-way**: `eprintln!("skipping"); return` (×11 in
  `approve/tests.rs`), `required_git()` panic, `locate_git()` panic, silent
  assumption. The Nix shell guarantees git; standardise on panic.
- **`commit_under_another_attempts_witness_panics`** (`approve/tests.rs:1010`)
  fakes the expected panic when git is absent, so it passes for the wrong reason
  on a git-less box.
- **`bin/bailiff/tests.rs:342-389`** mutates `HOME`/`XDG_DATA_HOME` with `unsafe
  set_var` in a parallel test binary. Give `DefaultPath::resolve` a lookup fn.
- **`process_supervisor.rs`** `blocking_tests` (1668-2237) mirror `tests` case for
  case by design; a shared `(script, modes, expected)` table run through both
  supervisors makes the parity mechanical instead of a comment.
- **Test-module convention is three-way** in every crate: inline `mod tests`
  (some over 1,000 lines: `git_push_promote.rs` 1,254, `github.rs` 1,126,
  `output.rs` 1,024, `bailiff_plan_note.rs` 960, `agent_vm_firewall.rs` 1,472,
  `writ-agent-run/lib.rs` 1,535), sibling `*_tests.rs`, and directory `tests.rs`;
  `nix_cache/route.rs`, `nar_verify.rs`, `agent_vm_lifecycle.rs` keep an inline
  `mod spec` *beside* sibling files. Pick: sibling file over ~300 lines, inline
  below.

## Structure findings that are not one of the five patterns

- **28 `too_many_arguments` want spec structs.** `run_agent` (10 params),
  `run_agent_in_vm` (10), `run_agent_in_vm_after_start` (8) carry the
  `ClientMessage::RunAgent` fields one by one — make the variant
  `RunAgent(RunAgentRequest)` (the client already has such a struct at
  `writ_client.rs:57`). `prepare_approve` (12), `prepare_approve_with_staging_repo`
  (10), `prepare_fast_forward_plan` (8): `repo, branch, expected_remote_head,
  bundle_tip, trailers, signing_key, attempt_id` travel together untouched —
  `ApproveRequest<'a>`; comments at `approve.rs:247-251`, `promote.rs:491-497`
  *argue against* the struct. `AgentVmSessionPlan::new`/`new_with_guest_env`
  (10/12), `AgentVmLifecycleRuntimeConfig::new` (10), `SessionFirewallSpec::new`
  (8), `BrokerVmPlan::new` (9) — `BrokerVmSessionRequest` already shows the shape;
  `state_store_tests.rs` copies the 10-arg call eight times.
  `check_daemon_sections` takes 7 loose `DaemonConfig` fields "because the binary
  destructures it first". `bin/bailiff.rs` `dispatch` destructures each variant
  to re-pass 5–12 fields positionally. `record_nix_cache_request_and_outcome`
  should take the record the caller builds.
- **`writ-core` contains effects.** `process_spawn.rs` (spawns, sleeps, reader
  threads), `process_group.rs` (`waitid`, `killpg`), `telemetry.rs` (global
  subscriber, opens files), `UnixMillis::now()`; `tracing-subscriber` is a
  non-optional dep, so the pure wire-types crate `writ-vm-git` drags it into the
  guest. Purity is a doc claim, not a crate-graph property (unlike the guest-client
  dep-freedom the 07-17 backlog made mechanical). Smallest honest fix: `telemetry`
  back to the root crate (only binaries use it) and `process_*` + `git_env`
  behind a `sys` feature or a `writ-sys` crate so `cargo tree` can check "core has
  no `libc`/`tokio`". M.
- **`crates/writ-agent-run/src/lib.rs` (4,063 lines) is three concerns**: wire
  types (1–712), `mod process_runner` (713–2526), `mod tests` (2528–4063). Split
  by the template the 07-17 backlog used. S.
- **`agent_vm_lifecycle.rs` is split by impl block, not concern**: `plan.rs`,
  `cleanup.rs`, `invocation.rs` are `use super::*` reaching into parent privates;
  `ProcessInvocation`/`BoundedOutput`/`CapturedTail` live in the parent but are
  used only in `invocation.rs`. `agent_vm_daemon.rs` interleaves two `#[cfg(test)]`
  modules between production impls and free functions. M.
- **Stringly typed values.** `BrokerUrl(String)` built by `format!` in two places
  then flattened to `String` in three message types; `BrokerVmState::Terminal(String)`;
  `PfctlInvocation.args: Vec<String>`; `VmHttpNixCacheProxyFetch.upstream_url: String`
  with `""` as "none" decoded by `is_empty()`; `git_clone.rs:390-520` returns
  `Result<_, String>` although `GitCloneBundleRunError` exists;
  `FlakeInputClass::Public { source_type: String }` matched against five literals;
  `AgentVmWorkspaceBootstrapAuditRecord.warm: String` validated against three
  literals at write time; `nonneg(value, what: &str)` dispatching on the label
  string. `ChatgptOauthState::Loaded { .. }` forces six `let Loaded{..} = state
  else { unreachable!() }`; `classify_refresh_failure_body` ignores its argument
  and `classify_refresh_failure_status` returns an enum with an impossible
  variant, producing two `unreachable!()` arms.
- **One-implementation traits.** `ChatgptOauthClock` + `SystemClock` (pass
  `now`); `GitObjectSource` (one production impl + in-memory test impl; tolerable
  as a test seam, but `FakeGitHub` shows the codebase already prefers stateful
  fakes); `run_cleanup_until_resource_absent_with` takes four closures — a pure
  `AbsenceLoop` state machine would let the four example tests become one
  property. `ProxyBackend` has two real impls and earns its place, but six of its
  consts are derivable from one `NAME`, and `into_vm_http_dispatch` exists only to
  pick between two parallel `VmHttpDispatch` arms.
- **Hand-written `Debug` to redact one field**: 24 arms for `ServerMessage`
  (`protocol/mod.rs:574-671`), again for `CapabilityOutcome` (`server.rs:215-235`).
  The crate already has five redacting newtypes; wrap the token and derive.
- **Hidden effect**: `WRIT_KEEP_FAILED_BROKER_VM` read from the environment
  mid-orchestration (`daemon_impl.rs:1463`). Move to config.
- **`src/bin/writd.rs:565-578`** `mem::forget`s a watch sender so the UI listener
  never sees shutdown.
- **Naming.** Fallible `&str` constructors are variously `try_new`, `new`,
  `parse`, `check`, `parse_json` (`RejectionReason::try_new`, `SecretKey::new`,
  `GitCloneBaseUrl::parse`, `NixNarHash::new`, `AgentRunLogRoot::check`,
  `BrokerSessionSpec::parse_json`, `AgentVmSessionPlan::new` vs the real
  `new_with_guest_env`); pick `parse` for `&str → Result`. Eleven of twelve
  modules inside crate `bailiff` are named `bailiff_*` (`bailiff::bailiff_plan_submit::submit_plan`);
  no crate outside references them. `github.rs` is the App-token minter, not
  the GitHub client (`github_git_db.rs` is). `git_push_objects_cat_file` vs
  `git_push_object_parse`. `broker_entrypoint.rs:854` names a test helper
  `broker_config_json`, shadowing the real `broker_vm::broker_config_json`.
  `AgentStage: Display` says "submission/review/implement" while `PlanStage::as_str`
  says "submit/…". `agent_vm_daemon.rs:53-55,77` re-export `vm_git` constants under
  `AGENT_VM_*` aliases.
- **Shell.** `host-setup/prewarm-cache/*.sh` use ~25 inline
  `echo "error" >&2; exit 1` blocks instead of `die`; `warm-via-container.sh`
  re-implements three validators from `common.sh` instead of sourcing it.
  `.github/workflows/ci.yml` pins `actions/checkout` at v6 and v4.

## Broken (found incidentally; the only behavioural findings)

- **`prove-agent-vm-claude-proxy.sh:602` and `prove-agent-vm-codex-proxy.sh:606`
  write a top-level `"github"` config key** (**verified**).
  `src/config/tests.rs:253 rejects_legacy_github_field` asserts writd refuses
  exactly that key (removed 2026-05-10). The line dates from 2026-05-08 and
  survived last night's #420 edit, so neither proxy proof can have run since
  May. The two files are 885/1000 lines identical; merge into one
  vendor-parametrised harness when fixing.

## Suggested order

Same framework as the 07-17 backlog: cheap, no-decision, high-leverage first;
each slice independently shippable; complete each migration in its own PR.

1. **Delete** (P3). No design decisions, pure orthogonality win, every item is
   verified unreferenced. Start with the branch-creation planner, the writ-audit
   self-equivalence tests, the rpc-trace baseline, the four stale proof scripts,
   the orphaned regressions, and the plan archive. ≈ −4,000 Rust/shell, ≈ 8,000
   docs moved.
2. **Fix the proxy harnesses** (Broken) while merging them. ≈ −1,000.
3. **Shared test support, one crate at a time** (P1). Mechanical; the compiler
   carries it. ≈ −5,000.
4. **Production primitives** (P2): `private_fs`, `UpstreamBaseUrl`, `FromStr for
   *Cidr`, `validated_string!`, `Sha256Hex::of`, `protocol::framing`,
   `prove-common.sh`, `mkOciImage`. ≈ −4,000.
5. **Spec structs and typed errors** (Structure). This is what makes the ≈150
   string assertions in P5 deletable, so do it before the test pass.
6. **Comment pass, one crate per PR** (P4). Displaced and false docs first.
   ≈ −3,000.
7. **Property conversions** (P5) as an ongoing habit; the `ALL`-slice + exhaustive
   `match` rule and the "sibling file over 300 lines" rule are cheap to adopt now.

## What is good (do not "fix")

Every reader was asked to name what to leave alone. The list is long, which is
the point: the *designs* are sound; the slop is around them.

- `src/policy.rs` `AuthorizedMint`; `server::Dispatched`/`AfterReply`;
  `handshake::admit` as a pure DU; `config/accumulate.rs` and the `DEFAULT_PATHS`
  table; the approve crash/rival sweeps against a fake's ground truth.
- `writ-audit`: the `EffectAuditTable` guard (sealed trait, `#[must_use]`,
  `compile_fail` doctests); `approve_attempt.rs` as a pure state machine with the
  schema triggers as backstop and the naive-probe `transition_agrees_with_the_schema`
  oracle; the migration runner with compile-time contiguity.
- Git pipeline: `git_push_object_parse.rs` pure parsers with serialize inverses;
  `notes_repo/compaction.rs` pure decisions over names and counts; `crash_point.rs`
  + `tests/approve_state_machine.rs`; `PreparedApprove::commit(&UncertainAttempt)`;
  `fake_github.rs` as a stateful model; `run_provenance` "perturb exactly one field".
- Agent VM: `AgentVmStartStep` DU → `run_start_step` with the outcome→cleanup
  property; `process_supervisor/capture.rs` chunk-boundary independence;
  `agent_vm_pf_helper_protocol.rs` exact-render parsing and generators that carry
  their own verdict; `broker_contract_fingerprint_is_pinned`;
  `ConfiguredIpv6Profile` vs `Ipv6IsolationMode`; `LineReassembler`'s split oracle.
- vm_http: `broker_effect.rs` driver-owns-the-guard; `route_table.rs` with
  `route_enum!` totality and `every_audited_route_records_a_complete_audit_pair`;
  `nix_binary_cache/tests.rs` mutation-enum and CA self-certification oracles;
  `flake_lock.rs` as bytes-in/plan-out; the crash-injection test in
  `vm_http/git_push.rs`.
- Member crates: `pf_*` + `pf_packet_model.rs` (rule DU, exact readback grammar,
  packet-decision oracle over every packet, generator-coverage checks);
  `writ-guest-init/handoff.rs` two independent oracles; `proc_status.rs` proof
  types; `GuestContract` pinned from both sides; `ChildGuard` discipline; the
  `RunPurpose` reference-predicate property (the model for the other newtypes).
- Bailiff: `bailiff_plan_state.rs` transition relation with `Corrupt` defined by
  unreachability; `bailiff_stage.rs` three-phase factoring (do **not** replace
  with a `StageSpec` interpreter); `tests/stage_gate_zero_rpc.rs`;
  `PlanGuard::run_blocking`; the write side's `write_stage_note` + `stage_note!`.
- Shell/docs: `scripts/lib/*.sh` pure helpers with `test-proof-helpers.sh`;
  `host-setup/prewarm-cache/common.sh`; the `flake.nix` rootfs assertions;
  `architecture.md`'s per-subsystem shape and its superseded-journal appendix;
  `docs/known-test-flakes.md` §2.
