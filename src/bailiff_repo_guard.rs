//! Cross-workflow lock-hold helper for bailiff's bare notes repo.
//!
//! Bailiff workflows ([`crate::bailiff_plan_submit::submit_plan`],
//! [`crate::bailiff_plan_review::submit_review`], and the future
//! `submit_implement`) all mutate bailiff's bare repo through an
//! `Arc<AsyncMutex<NotesRepo>>` handle. Per the long-running
//! orchestrator-daemon model (`docs/plans/2026-05-14-bailiff-split.md`),
//! the single-writer invariant on that repo requires every "read
//! then later write" sequence within one workflow to hold the lock
//! across both ends — otherwise two concurrent workflows for the same
//! artefact can both pass a pre-RPC read gate before either reaches
//! its write, turning the gate advisory and letting both broker
//! sessions (and any `WorkspaceWrite`-capable agent runs) proceed.
//!
//! Before this helper existed, every workflow's `spawn_blocking`
//! section acquired and released the lock independently
//! (`bailiff_repo.blocking_lock()`), so the lock only protected each
//! individual git invocation, not the workflow. [`BailiffRepoGuard`]
//! is the primitive that fixes this: acquire once at the top of a
//! workflow, hold across every `spawn_blocking` section and every
//! `await` between them, release on `Drop`.
//!
//! Lock granularity: the underlying mutex protects the whole bare
//! repo, so two workflows that touch different plan ids still
//! serialise. That's deliberate — the in-flight LLM-run length (often
//! minutes) is amortised by humans driving the CLI one command at a
//! time and by the rarity of overlapping bailiff operations, and per
//! plan-id locking would be a much bigger structural change.
//! Cross-process callers (two bailiff CLI invocations against the
//! same on-disk repo) are out of scope for this primitive; git's
//! notes-add idempotency at the seed OID is what catches that case.

use std::sync::Arc;

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tokio::task::JoinError;

use crate::notes_repo::NotesRepo;

/// Lock-hold scope for one bailiff workflow.
///
/// Acquire once via [`Self::acquire`] at the top of a workflow and
/// keep the value alive for the entire workflow. Use
/// [`Self::run_blocking`] for any git-shelling-out section; the lock
/// is held across the call (the guard is moved into the
/// `spawn_blocking` task and moved back out on completion). `await`
/// points *between* `run_blocking` calls also keep the lock held.
/// On drop the lock is released and the next waiter on the same
/// `Arc<AsyncMutex<NotesRepo>>` can proceed.
///
/// The struct is intentionally neither [`Clone`] nor [`Copy`]: only
/// one workflow holds the lock at a time, and duplicating the guard
/// would defeat the invariant. Two concurrent workflows must each
/// call [`Self::acquire`] independently; the second `acquire` blocks
/// until the first guard drops.
pub struct BailiffRepoGuard {
    // Invariant: `Some` between `acquire` and the value's `Drop`.
    // [`Self::run_blocking`] uses [`Option::take`] to hand the guard
    // off to a blocking task and put it back; the field is therefore
    // momentarily `None` only inside that method.
    guard: Option<OwnedMutexGuard<NotesRepo>>,
}

impl BailiffRepoGuard {
    /// Acquire the lock on `repo`. Awaits until the lock is free,
    /// matching `AsyncMutex::lock_owned` semantics (no timeout, no
    /// poison concept).
    pub async fn acquire(repo: Arc<AsyncMutex<NotesRepo>>) -> Self {
        Self {
            guard: Some(repo.lock_owned().await),
        }
    }

    /// Run `work` in a `spawn_blocking` task under the held lock.
    ///
    /// The guard is moved into the closure for its execution and
    /// moved back out on completion, so the caller's `Self` keeps
    /// holding the lock across this call. The return type is the
    /// closure's `R` — typically a `Result<T, E>` produced by the
    /// underlying read/write helper.
    ///
    /// Surfaces a [`JoinError`] iff the `spawn_blocking` task itself
    /// panicked or was cancelled — the same condition each workflow
    /// already maps to its own `WriteTaskFailed` / `ReadTaskFailed`
    /// error variant.
    ///
    /// # Panics
    ///
    /// Panics if the spawn_blocking task panics or completes without
    /// returning the guard. Both cases violate `OwnedMutexGuard`'s
    /// `Send + 'static` contract or this method's internal protocol;
    /// neither is reachable from outside the module.
    pub async fn run_blocking<F, R>(&mut self, work: F) -> Result<R, JoinError>
    where
        F: FnOnce(&NotesRepo) -> R + Send + 'static,
        R: Send + 'static,
    {
        let guard = self
            .guard
            .take()
            .expect("BailiffRepoGuard invariant: guard is always Some between acquire and Drop");
        let (guard, result) = tokio::task::spawn_blocking(move || {
            let r = work(&guard);
            (guard, r)
        })
        .await?;
        self.guard = Some(guard);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::sync::Mutex as AsyncMutex;

    use super::*;

    /// Open a bare repo in a tempdir so we have something for the
    /// guard to point at. The repo is unused beyond providing a
    /// well-formed [`NotesRepo`].
    fn open_repo() -> (tempfile::TempDir, Arc<AsyncMutex<NotesRepo>>) {
        let tmp = tempfile::tempdir().unwrap();
        let repo = NotesRepo::init_or_open(tmp.path().join("bare")).unwrap();
        (tmp, Arc::new(AsyncMutex::new(repo)))
    }

    /// Acquire → drop → reacquire round-trips: the second `acquire`
    /// must complete promptly because the first guard's `Drop`
    /// released the lock. A regression here would be the guard
    /// leaking the lock past its lexical scope.
    #[tokio::test]
    async fn acquire_then_drop_releases_the_lock() {
        let (_tmp, repo) = open_repo();
        let first = BailiffRepoGuard::acquire(Arc::clone(&repo)).await;
        drop(first);
        // If the lock were still held, `try_lock` would fail; we
        // also want a positive witness that a fresh `acquire`
        // proceeds, so use a timeout to bound a hypothetical hang.
        tokio::time::timeout(
            Duration::from_secs(1),
            BailiffRepoGuard::acquire(Arc::clone(&repo)),
        )
        .await
        .expect("acquire must complete after the prior guard dropped");
    }

    /// Two concurrent acquires must serialise: the second one only
    /// progresses after the first guard drops. Witnesses the
    /// single-writer invariant the primitive exists to enforce.
    #[tokio::test]
    async fn second_acquire_blocks_until_first_guard_drops() {
        let (_tmp, repo) = open_repo();
        let first = BailiffRepoGuard::acquire(Arc::clone(&repo)).await;

        let repo_clone = Arc::clone(&repo);
        let second = tokio::spawn(async move { BailiffRepoGuard::acquire(repo_clone).await });

        // Yield repeatedly so the spawned task has a chance to make
        // progress (if it can). After a brief grace period the
        // second acquire must still be pending.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            !second.is_finished(),
            "second acquire must not finish while first guard is held"
        );

        drop(first);
        tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("second acquire must complete after first guard drops")
            .expect("second acquire task must not panic");
    }

    /// Multiple `run_blocking` calls back-to-back must all see the
    /// same lock. Witnesses the across-call hold: if the guard
    /// were released between calls, an interleaving task could grab
    /// the lock; the counter below is incremented inside each
    /// `run_blocking` so two interleaved workflows would produce
    /// non-monotonic results.
    #[tokio::test]
    async fn run_blocking_holds_lock_across_multiple_calls() {
        let (_tmp, repo) = open_repo();
        let mut guard = BailiffRepoGuard::acquire(Arc::clone(&repo)).await;

        // A side task tries to acquire and increment a shared
        // counter. While our `guard` is alive, the side task must
        // not make progress.
        let counter = Arc::new(AtomicUsize::new(0));
        let repo_clone = Arc::clone(&repo);
        let counter_clone = Arc::clone(&counter);
        let race = tokio::spawn(async move {
            let _g = BailiffRepoGuard::acquire(repo_clone).await;
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let first = guard.run_blocking(|_repo| 1usize).await.unwrap();
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "racing acquire must not have progressed across the first run_blocking",
        );

        let second = guard.run_blocking(|_repo| 2usize).await.unwrap();
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "racing acquire must still be blocked across the second run_blocking",
        );

        assert_eq!(first, 1);
        assert_eq!(second, 2);

        drop(guard);
        tokio::time::timeout(Duration::from_secs(1), race)
            .await
            .expect("racing acquire must complete after our guard drops")
            .expect("racing task must not panic");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// The closure passed to `run_blocking` sees a `&NotesRepo`
    /// pointing at the locked repo (not a stale or unrelated one).
    /// Pins that we deref the guard, not something else, into the
    /// closure's argument.
    #[tokio::test]
    async fn run_blocking_passes_the_locked_repo_to_the_closure() {
        let (tmp, repo) = open_repo();
        let mut guard = BailiffRepoGuard::acquire(Arc::clone(&repo)).await;
        let expected = tmp.path().join("bare").canonicalize().unwrap();
        let observed = guard
            .run_blocking(move |repo| repo.path().to_path_buf())
            .await
            .unwrap();
        assert_eq!(observed, expected);
    }
}
