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
