# Flaky test investigation: git children SIGKILLed under high test parallelism

**Status:** resolved in the only sense that matters to the suite — the failure is
recognised and absorbed. The *sender* of the signal is still unnamed, and that is
now known not to matter. See [Resolution](#resolution-the-child-is-born-dead).

**Severity:** test-harness flake, not a product-correctness bug. It only manifests when
the test suite runs at high concurrency; the production code paths are not implicated.

> **Caveat on the reproduction below.** `cargo test -p writ --lib` no longer
> exercises this fault at all: bailiff has since become its own crate, and the
> `NotesRepo` victims listed under "Symptom" live there now. Use
> `cargo test --workspace`. At `-p writ --lib` what you will reproduce instead is
> a *different and unrelated* family of failures — wall-clock deadline misses
> under CPU oversubscription — which is tracked separately and must not be
> confused with this one.

## Symptom

Tests that shell out to `git` through `NotesRepo` (a *synchronous* `std::process`
spawn) intermittently fail, because the `git` child is **killed by `SIGKILL`
mid-operation** by something outside `NotesRepo`. Two surface forms, same cause:

- `GitFailed { args: [...], status: ExitStatus(unix_wait_status(9)), stderr: "" }`
  — the child was killed by signal 9 *after* we finished writing its stdin.
- `GitStdinWrite { source: Os { code: 32, kind: BrokenPipe } }`
  — the child died *while/before* we wrote its stdin, so the write hit `EPIPE`.

A **different test fails on each run** — whichever git child happens to be alive when
the stray kill lands. Examples seen:

- `bailiff_plan_read::full_plan_tests::read_full_plan_marks_section_when_*`
- `bailiff_plan_read::decision_tests::read_decision_note_does_not_cross_read_between_plans`
- `clean_git::tests::run_clean_git_subprocess_sees_only_hardened_env_vars`
  (its own doc comment already anticipates an "ETXTBSY past the retry ceiling under
  parallel-test load" variant)
- `git_push_objects_cat_file::tests::cat_file_source_drop_kills_process_group`
  (times out 30s waiting for its wrapper to write a pid file — consistent with the
  wrapper being killed before it could write)

## Reproduction

On an 18-core machine, default test concurrency:

```sh
# ~25–30% of runs fail (different test each time):
cargo test --workspace
cargo test -p writ --lib

# Oversubscribing threads raises the hit rate:
cargo test -p writ --lib -- --test-threads=40
```

A tight loop that stops on the first failure:

```sh
for i in $(seq 1 12); do
  cargo test -p writ --lib > /tmp/run_$i.log 2>&1 || { echo "FAILED iter $i"; break; }
  echo "iter $i ok"
done
```

## Established facts

Each of these is backed by a reproduction, not inference:

1. **Pre-existing.** Reproduces on clean `main` (checked out in a fresh worktree),
   independent of any in-flight branch.

2. **Concurrency-only — not a per-test bug.**
   - The synchronous notes-git tests, run *in isolation* at `--test-threads=40`,
     pass **8/8**.
   - At `--test-threads=2` the full suite passes **4/4**.
   - Failures appear only when the `#[tokio::test]` broker/end-to-end tests run
     **concurrently** with the sync notes-git tests.

3. **Not OS resource exhaustion.**
   - `log show --last 25m --predicate '… jetsam / lowswap / Kill …'` shows **no**
     OS-level kill events around a failing run.
   - Process limits are nowhere near saturated (`kern.maxprocperuid = 10666`,
     `kern.maxproc = 16000`).

4. **Our explicit kill code is exonerated.** Every `killpg`/`kill` site we own was
   instrumented to log each call (pgid, caller's process group, leader liveness) and to
   assert it never targets the caller's own group:
   - `process_supervisor::kill_process_group_inner`
   - `git_push_objects_cat_file` (`Drop`, `close`, `kill_process_group_best_effort`)

   During failing runs these logged **zero calls**. The only `kill_on_drop(true)` in the
   tree (the `cat-file --batch` child in `git_push_objects_cat_file`) also never
   fired. So the stray `SIGKILL` does **not** originate from our process-group kill
   machinery — the careful `waitid(WNOWAIT)`-before-`killpg` dance there is not the
   problem.

5. **Victim is always a sync (`std::process`) git child** spawned by `NotesRepo`,
   which sets no process group of its own (it inherits the test harness's). The kill
   correlates with concurrent `#[tokio::test]` execution.

## Resolution: the child is born dead

The fault was closed without ever naming the sender, by finding the mark it leaves.

**Immediately after `spawn()` returns a pid, `getpgid(pid)` reports `ESRCH`.** The
child is gone microseconds after we are handed its pid, before it executes a single
instruction. Every healthy child reports the harness's process group; only the doomed
one reports "no such process".

That single fact explains the whole symptom set:

- **Empty stderr** — there was never a running process to write any.
- **Two error shapes, one fault** — `unix_wait_status(9)` when `wait` reaches the
  corpse first, `GitStdinWrite`/`BrokenPipe` when the stdin write gets there first.
- **"A different test each run"** — the constant is the shared `NotesRepo` spawn
  path, not any test.

**Evidence.** Born-dead children were counted per run: **0 in every passing run**
(~2264 spawns each), **≥1 in every failing run**. Rate ≈ 1 per 2000 spawns under load.

**Correction to fact 4 above.** Its verdict (our kill code is innocent) is correct,
but its evidence was void: the instrumentation used `tracing` in test binaries that
install **no subscriber**, and `eprintln!` from *passing* tests, which libtest
discards. It could not have printed anything either way. Re-done with an appending
`write(2)` plus a `DYLD_INTERPOSE` shim on `kill`/`killpg` — which catches senders in
tokio and every dependency, not just our own call sites — a failing run shows **2023
spawns, 2022 reaps, zero signals sent in-process**.

Two other candidate explanations were tested and **refuted**: our own supervisor's
timeout-`killpg` (zero `killpg` calls in the victim's process), and macOS killing
concurrent execs of the same binary (2400 concurrent `git --version` from the same
store path, zero kills — consistent with established fact 2's 144k-operation result).

**The fix.** Every synchronous git child in `NotesRepo` now goes through
`run_git_child`, which re-runs the invocation while `child_ran_nothing` holds:

```
getpgid(pid) == ESRCH immediately after spawn   AND   killed by SIGKILL
```

The first conjunct was presented as a *proof*, resting on the zombie rule: we have
not reaped the child, so one that had run and exited — however briefly — would still
hold an unreaped process-table entry and `getpgid` would succeed, making `ESRCH` mean
the pid never became a live process.

> **Correction (later, and load-bearing).** That reasoning is wrong on macOS, which
> is the only platform the flake was ever observed on. The zombie rule holds on
> Linux; XNU's pid lookup **excludes zombies**, so `getpgid` answers `ESRCH` for a
> child that ran, took effect, and exited without being reaped. Demonstrated by
> `process_supervisor::blocking_tests::getpgid_reports_esrch_for_a_child_that_did_run`,
> which touches a file and then `kill -9`s itself: the marker exists, the status is
> `SIGKILL`, and the probe still reports absent. Both conjuncts of the "proof" are
> therefore satisfiable *after an observable side effect*.
>
> So the mark is **evidence, not proof**, and it cannot by itself license replaying a
> non-idempotent command. The retry survives, because every invocation in
> `notes_repo` is independently replay-safe — `hash-object -w` is content-addressed,
> `fetch` and `init` converge, `notes add` without `-f` *refuses* on a second run so
> it cannot double-apply — but that is now stated per invocation at the call site, as
> `OnBornDead::Retry` with its justification, rather than derived from a property of
> the probe. The supervisor no longer offers a generic "safe to re-run" boolean,
> because the next caller would have believed it.

The second conjunct guards one way the probe could lie (if anything ever set
`SIGCHLD` to `SIG_IGN`, children would be auto-reaped; such a child cannot then be
waited for, so it surfaces as a `GitWait` error instead). It does not bound *when*
the kill landed, which is the gap the correction above describes.

Note what is **not** used: emptiness of stdout/stderr. That was the first
formulation and it is unsound — `CaptureOutput::Discard` makes stdout empty by
construction, so for the mutating callers (`notes add`, `update-ref`) the test would
have been vacuous, and a child killed *after* committing its ref would have been
replayed into a spurious "note already exists" failure. Caught in review.

The config-validation children on the `NotesRepo::open` path go through the same
helper. They previously called `Command::output()` directly and so were not covered
at all — which mattered, because the flake was first observed there:
`GitFailed { args: ["config"], status: unix_wait_status(9) }`.

**Still unknown, and deliberately not depended upon:** which kernel path discards the
process. SIP blocks `proc:::signal-send` and the unified log needs privileges. The fix
recognises, from in-process evidence, that the child ran nothing; it does not guess at
the cause.

## Next step: catch the signal sender

The investigation is blocked on attributing the `SIGKILL` to a sender. A signal tracer
ends it immediately.

**macOS (today, needs sudo; SIP may restrict `ustack`):**

```sh
sudo dtrace -n 'proc:::signal-send /args[2] == 9/ {
    printf("%s[%d] -> pid %d", execname, pid, args[1]->pr_pid); ustack();
}'
# …while looping `cargo test -p writ --lib` in another terminal.
```

**Linux with root (e.g. inside an agent VM):**

```sh
strace -f -e trace=kill,tgkill,rt_sigqueueinfo -p <test-runner-pid>
# or broader: strace -f -e %signal -p <test-runner-pid>
```

Caveat: the flake currently reproduces on the **macOS host**. tokio uses a different
process backend on Linux (pidfd/signalfd) vs macOS (kqueue + signal handler), so the
flake may change shape or not reproduce under Linux — confirm it reproduces there before
relying on `strace`.

## Interim guidance

- A red CI run that fails one of the tests above with `unix_wait_status(9)` /
  `BrokenPipe` on a git child is almost certainly this flake — re-run to confirm before
  investigating as a real regression.
- Do **not** "fix" it by loosening the assertions in the victim tests; the tests are
  correct, the harness is killing their subprocesses.
