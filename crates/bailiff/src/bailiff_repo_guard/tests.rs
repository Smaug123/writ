//! Properties of [`PlanGuard`].
//!
//! The load-bearing test is
//! [`distinct_plans_make_progress_concurrently`]: it deadlocks under
//! the pre-slice-2 whole-repo guard and passes under the per-plan one,
//! which is what makes it evidence for the granularity change rather
//! than a restatement of it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tempfile::TempDir;
use writ::notes_repo::NotesRepo;

use super::*;
use crate::bailiff_plan_note::{PlanId, plan_notes_ref};

fn repo(tmp: &TempDir) -> Arc<NotesRepo> {
    Arc::new(NotesRepo::init_or_open(tmp.path().join("bare")).unwrap())
}

/// Two workflows on **different** plans hold their guards at the same
/// time.
///
/// Written as a rendezvous rather than a timing check: each task takes
/// its guard, then waits for the other to have taken one too. Under a
/// whole-repo lock the second `acquire` blocks forever and the test
/// times out; under per-plan locks both proceed. No sleep is involved,
/// so it does not measure the scheduler (see
/// `docs/known-test-flakes.md`).
#[tokio::test]
async fn distinct_plans_make_progress_concurrently() {
    let tmp = TempDir::new().unwrap();
    let repo = repo(&tmp);
    let both_in = Arc::new(tokio::sync::Barrier::new(2));

    let spawn = |plan_id: PlanId| {
        let repo = Arc::clone(&repo);
        let barrier = Arc::clone(&both_in);
        tokio::spawn(async move {
            let _guard = PlanGuard::acquire(repo, plan_id).await.unwrap();
            // Only completes if the *other* task also holds a guard.
            barrier.wait().await;
        })
    };

    let a = spawn(PlanId::new());
    let b = spawn(PlanId::new());
    tokio::time::timeout(Duration::from_secs(10), async {
        a.await.unwrap();
        b.await.unwrap();
    })
    .await
    .expect("distinct plans must not serialise against each other");
}

/// Two workflows on the **same** plan serialise: the second
/// `acquire` does not return until the first guard drops.
#[tokio::test]
async fn same_plan_serialises_in_process() {
    let tmp = TempDir::new().unwrap();
    let repo = repo(&tmp);
    let plan_id = PlanId::new();
    let order = Arc::new(AtomicUsize::new(0));

    let first = PlanGuard::acquire(Arc::clone(&repo), plan_id)
        .await
        .unwrap();

    let order_for_task = Arc::clone(&order);
    let repo_for_task = Arc::clone(&repo);
    let second = tokio::spawn(async move {
        let _g = match PlanGuard::acquire(repo_for_task, plan_id).await {
            Ok(g) => g,
            Err(e) => panic!("CONTENDER ERR: {e:?}"),
        };
        // Records 2 only if it ran after the release below.
        order_for_task.fetch_add(2, Ordering::SeqCst)
    });

    // Yield generously; the spawned task must still be blocked.
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        order.load(Ordering::SeqCst),
        0,
        "the second acquire must not proceed while the first guard is held",
    );

    order.fetch_add(1, Ordering::SeqCst);
    drop(first);

    let observed = tokio::time::timeout(Duration::from_secs(10), second)
        .await
        .expect("the second acquire must proceed once the first releases")
        .unwrap();
    assert_eq!(observed, 1, "the second acquire ran before the release");
}

/// The lock is held across `run_blocking` *and* across the `await`
/// points between two of them — the invariant the whole design exists
/// for. A second acquirer must not interleave into the gap.
#[tokio::test]
async fn the_lock_spans_awaits_between_blocking_sections() {
    let tmp = TempDir::new().unwrap();
    let repo = repo(&tmp);
    let plan_id = PlanId::new();
    let interleaved = Arc::new(AtomicUsize::new(0));

    let mut guard = PlanGuard::acquire(Arc::clone(&repo), plan_id)
        .await
        .unwrap();

    let flag = Arc::clone(&interleaved);
    let repo_for_task = Arc::clone(&repo);
    let contender = tokio::spawn(async move {
        let _g = PlanGuard::acquire(repo_for_task, plan_id).await.unwrap();
        flag.fetch_add(1, Ordering::SeqCst);
    });

    let first = guard
        .run_blocking(|r| r.path().to_path_buf())
        .await
        .unwrap();
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    let second = guard
        .run_blocking(|r| r.path().to_path_buf())
        .await
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(
        interleaved.load(Ordering::SeqCst),
        0,
        "a contender acquired the lock between two run_blocking sections",
    );

    drop(guard);
    tokio::time::timeout(Duration::from_secs(10), contender)
        .await
        .expect("the contender must proceed once the guard drops")
        .unwrap();
}

/// A second *open file description* on the same plan's lockfile
/// cannot take the `flock` while a guard holds it, and can once the
/// guard drops.
///
/// This is the whole exclusion mechanism, probed the way another
/// process would probe it. That the probe also fails from *inside*
/// this process is the point: `flock` binds to an open file
/// description rather than a process, which is why the in-process
/// mutex layer the first draft wrapped around it was redundant.
#[tokio::test]
async fn the_lockfile_excludes_every_other_holder_per_plan() {
    let tmp = TempDir::new().unwrap();
    let repo = repo(&tmp);
    let plan_id = PlanId::new();

    let probe = |id: PlanId| {
        let path = repo.path().join("bailiff-locks").join(format!("{id}.lock"));
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .unwrap()
    };

    let guard = PlanGuard::acquire(Arc::clone(&repo), plan_id)
        .await
        .unwrap();

    let held = probe(plan_id);
    assert!(
        matches!(held.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "a second descriptor must not take a held plan's flock",
    );

    // A different plan is free even while this one is held — the
    // granularity claim, stated as an assertion.
    let other = probe(PlanId::new());
    assert!(
        other.try_lock().is_ok(),
        "a different plan's lockfile must not contend",
    );

    drop(held);
    drop(other);
    drop(guard);

    // Release is asserted through `PlanGuard`, not through a raw
    // `try_lock` on a fresh descriptor. The raw probe was flaky at
    // roughly 1-in-20 under parallel load: it races the kernel's
    // close-releases-the-flock step, which is not this module's
    // property to assert. `acquire` *waits*, so this is deterministic,
    // and it checks the contract a caller actually depends on — the
    // next workflow for this plan proceeds.
    tokio::time::timeout(
        Duration::from_secs(10),
        PlanGuard::acquire(Arc::clone(&repo), plan_id),
    )
    .await
    .expect("the next acquire must proceed once the guard drops")
    .expect("re-acquiring a released plan must succeed");
}

/// Guards really do serialise note writes for one plan: two tasks each
/// read-then-write under a guard, and the second observes the first's
/// note. Without the guard spanning both, both could observe an empty
/// ref and race.
#[tokio::test]
async fn a_guarded_read_then_write_is_atomic_for_one_plan() {
    let tmp = TempDir::new().unwrap();
    let repo = repo(&tmp);
    let plan_id = PlanId::new();

    let write_if_absent = |repo: Arc<NotesRepo>| async move {
        let mut guard = PlanGuard::acquire(repo, plan_id).await.unwrap();
        guard
            .run_blocking(move |r| {
                let notes_ref = plan_notes_ref(plan_id);
                let seed = b"seed".to_vec();
                let existing = r
                    .write_note_if_absent(&notes_ref, &seed, b"body")
                    .expect("write must succeed");
                matches!(existing, writ::notes_repo::WriteOutcome::Written(_))
            })
            .await
            .unwrap()
    };

    let a = tokio::spawn(write_if_absent(Arc::clone(&repo)));
    let b = tokio::spawn(write_if_absent(Arc::clone(&repo)));
    let (a, b) = tokio::join!(a, b);
    let wrote = [a.unwrap(), b.unwrap()];
    assert_eq!(
        wrote.iter().filter(|w| **w).count(),
        1,
        "exactly one guarded writer must have created the note",
    );
}

/// Cancelling a workflow mid-`run_blocking` must not release the
/// plan's lock while the blocking closure is still running.
///
/// Tokio does not cancel an already-running `spawn_blocking` task, so
/// a guard that owned the lockfile itself would close it on drop while
/// the closure kept touching the repo — and another workflow for the
/// same plan could interleave with the first one's gate or write. The
/// fix is that `run_blocking` hands the lockfile *to* the task.
///
/// The check is a **synchronous probe**, deliberately. Two earlier
/// drafts asserted against a spawned contender — first
/// `!contender.is_finished()`, then a sequence-number ordering — and
/// *both passed with the bug reintroduced*, because neither could tell
/// "the contender was correctly blocked" from "the contender had not
/// been scheduled yet". Probing the lockfile from this thread depends
/// on no scheduling whatsoever: either the flock is held at the moment
/// we look, or it is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_run_blocking_holds_the_lock_until_the_closure_returns() {
    let tmp = TempDir::new().unwrap();
    let repo = repo(&tmp);
    let plan_id = PlanId::new();

    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

    let mut guard = PlanGuard::acquire(Arc::clone(&repo), plan_id)
        .await
        .unwrap();

    // Start the blocking work, then cancel the future without awaiting
    // it to completion.
    {
        let fut = guard.run_blocking(move |_repo| {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        let mut fut = std::pin::pin!(fut);
        tokio::select! {
            _ = &mut fut => panic!("the blocking closure cannot finish before it is released"),
            _ = tokio::task::yield_now() => {}
        }
    } // <- cancellation

    // The blocking closure is definitely running now (it said so), and
    // the guard is gone.
    started_rx.recv().unwrap();
    drop(guard);

    let lock_path = repo
        .path()
        .join("bailiff-locks")
        .join(format!("{plan_id}.lock"));
    let probe = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    assert!(
        matches!(probe.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "the plan lock was released while the cancelled workflow's blocking closure was \
         still running",
    );
    drop(probe);

    // Releasing the closure lets it return, which drops the lockfile
    // it owns — after which the plan is acquirable again.
    release_tx.send(()).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        PlanGuard::acquire(Arc::clone(&repo), plan_id),
    )
    .await
    .expect("the plan must be acquirable once the blocking closure returns")
    .expect("re-acquiring a released plan must succeed");
}

/// The repo-mutation lock is repo-wide, unlike the plan locks.
///
/// `NotesRepo::fetch_from_remote` states that "Git's index / refs /
/// objects writes are not safe under concurrent fetch+notes-add into
/// the same destination" and enforces it with a *process-wide* mutex —
/// which is the one scope that does not help two `bailiff` processes
/// on different plans. This lock covers every repo mutation, fetches
/// and note writes alike; on the implement path a collision can
/// otherwise lose the note for a run whose agent has already pushed.
///
/// Probed synchronously, for the reason given on
/// `cancelling_run_blocking_holds_the_lock_until_the_closure_returns`.
#[test]
fn the_repo_mutation_lock_is_repo_wide_while_plan_locks_are_not() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("bare")).unwrap();

    let open = |name: String| {
        let path = repo.path().join("bailiff-locks").join(name);
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .unwrap()
    };

    let held = lock_repo_mutations(&repo).expect("first mutation lock must succeed");

    // A second holder — of any plan, in any process — must wait.
    let probe = open("_repo-mutation.lock".to_string());
    assert!(
        matches!(probe.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "the mutation lock must exclude every other holder repo-wide",
    );
    drop(probe);

    // ... but it must not serialise unrelated plan work, which is the
    // whole point of keeping it separate from the plan locks.
    let plan_probe = open(format!("{}.lock", PlanId::new()));
    assert!(
        plan_probe.try_lock().is_ok(),
        "the mutation lock must not contend with per-plan locks",
    );

    drop(held);
    lock_repo_mutations(&repo).expect("the mutation lock must be reacquirable once released");
}

/// A waiter must not consume a blocking worker for the duration of the
/// holder's critical section.
///
/// A plan lock can be held across an entire agent run. If waiting on
/// it parked a `spawn_blocking` worker, a waiter would occupy that
/// worker for the whole run — while the holder needs a worker of its
/// own to perform the note write that would release the lock. With a
/// one-worker pool that is an immediate deadlock, and the default pool
/// deadlocks too once enough waiters fill it.
///
/// The runtime is built by hand because `#[tokio::test]` gives no way
/// to cap the blocking pool, and the cap is the whole point: it turns
/// a latent, load-dependent hang into a deterministic one.
///
/// **Under regression this test hangs rather than failing.** Restoring
/// the blocking `flock` was tried, and the inner `timeout` does fire —
/// but tokio then blocks on runtime shutdown waiting for the parked
/// blocking task, which cannot return because nothing will release the
/// lock. A deadlock is not a value a test can observe and report; a
/// stuck run is the signal.
#[test]
fn a_waiter_does_not_starve_the_holder_of_blocking_workers() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let repo = repo(&tmp);
        let plan_id = PlanId::new();

        let mut holder = PlanGuard::acquire(Arc::clone(&repo), plan_id)
            .await
            .unwrap();

        let repo_for_waiter = Arc::clone(&repo);
        let waiter =
            tokio::spawn(
                async move { PlanGuard::acquire(repo_for_waiter, plan_id).await.unwrap() },
            );

        // Let the waiter reach its wait.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }

        // The holder must still be able to run blocking work. This is
        // the assertion that hangs if the waiter parked the only
        // worker.
        let observed = tokio::time::timeout(
            Duration::from_secs(10),
            holder.run_blocking(|r| r.path().to_path_buf()),
        )
        .await
        .expect("the holder must still get a blocking worker while a waiter waits")
        .unwrap();
        assert_eq!(observed, repo.path());

        drop(holder);
        tokio::time::timeout(Duration::from_secs(10), waiter)
            .await
            .expect("the waiter must proceed once the holder releases")
            .unwrap();
    });
}
