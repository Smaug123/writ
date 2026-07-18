# Flaky test investigation: git children SIGKILLed under high test parallelism

**Status:** open — narrowed substantially, not yet root-caused. Needs a syscall/signal
tracer to finish (see [Next step](#next-step-catch-the-signal-sender)).

**Severity:** test-harness flake, not a product-correctness bug. It only manifests when
the test suite runs at high concurrency; the production code paths are not implicated.
But it does make CI intermittently red, so it must be fixed before we rely on green CI.

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

## Current hypothesis

With our kill code ruled out, the `SIGKILL` is coming from **tokio's process
machinery** (many concurrent `current_thread` runtimes spinning up/down, plus the
global `SIGCHLD`/reaper handling) or from the **macOS kernel** — i.e. upstream of our
code. This is **not yet confirmed**; it is the leading theory consistent with all five
facts above.

Notably, this means the earlier plan to "harden our `killpg` gaps" would **not** fix it:
the instrumentation shows there is no gap in our `killpg` being hit. Hardening must wait
on identifying the actual sender.

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
