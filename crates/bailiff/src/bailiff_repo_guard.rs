//! Per-plan workflow locking for bailiff's bare notes repo.
//!
//! Every bailiff workflow is a "read the state, then later write a
//! note" sequence. For the read to be a *gate* rather than a hint, the
//! lock has to span both ends: otherwise two workflows for the same
//! plan can both pass [`crate::bailiff_plan_state::allows`] before
//! either reaches its write, and both broker sessions — including the
//! `WorkspaceWrite`-capable implementer run — proceed.
//!
//! # What changed in slice 2
//!
//! The predecessor of this module, `BailiffRepoGuard`, had three
//! defects that `docs/plans/2026-07-26-bailiff-workflow-as-data.md`
//! records in full:
//!
//! 1. **It locked the whole repo.** Two workflows on unrelated plans
//!    serialised for the length of an LLM run. That was justified at
//!    the time by "humans drive the CLI one command at a time", a
//!    premise variant fan-out invalidates by construction.
//! 2. **The cross-process half lived in the binary.** `bin/bailiff.rs`
//!    took an `flock` named `bailiff-implement.lock`, so a library
//!    caller — the long-running orchestrator this module's own
//!    docstring cited as its reason to exist — got only the in-process
//!    half, and even the CLI took it for `implement` alone.
//! 3. **`decide` took no lock at all**, in or out of process.
//!
//! [`PlanGuard`] fixes all three: it is keyed per plan, it owns both
//! halves, and all four mutating verbs acquire it.
//!
//! # Why per-plan granularity is safe
//!
//! Each plan's notes live under its own ref
//! (`refs/notes/bailiff/v1/plans/<id>`), so two plans' writes touch
//! disjoint refs, and git updates a ref through its own lockfile.
//! Object writes are content-addressed, so they cannot conflict.
//! Measured rather than assumed: 32 concurrent cross-process `git
//! notes add` invocations on 32 distinct refs in one bare repo all
//! succeeded with every note readable afterwards.
//!
//! The remaining question — whether concurrent *git invocations*
//! against one repo contend on the index — is answered a layer down:
//! [`writ::notes_repo::NotesRepo`] already serialises each individual
//! note write behind a process-wide per-canonical-path mutex. So the
//! short repo-wide "one git call at a time" lock this design would
//! otherwise need already exists, and `PlanGuard` is free to be the
//! long, per-plan, workflow-scoped lock without duplicating it.
//!
//! # One mechanism, not two
//!
//! Exclusion is a single per-plan `flock`, acquired on a blocking
//! thread and held for the workflow's lifetime.
//!
//! The first draft layered a per-plan async mutex *over* the flock —
//! the mutex to make same-process callers queue, the flock to exclude
//! other processes. That design needed a process-wide registry of
//! mutexes keyed by `(repo, plan)`, lifetime bookkeeping to keep the
//! registry from growing once per plan ever seen, and a field
//! declaration order chosen so the two layers released in the reverse
//! of their acquisition order. Two distinct bugs came out of that
//! bookkeeping — an eviction sweep that could hand a fresh mutex to a
//! caller while another still held the old one, and a release-ordering
//! window that let a woken in-process waiter collide with a lockfile
//! not yet released — and the tests caught both.
//!
//! None of it was necessary: an `flock` is associated with an *open
//! file description*, not a process, so two `open` calls contend even
//! inside one process. The kernel already provides exactly the
//! queueing the mutex layer was built to add. One primitive, no
//! registry, no ordering subtlety, and the same guarantee.
//!
//! # Waiting, not failing
//!
//! `acquire` waits. A caller that finds a plan busy logs once and
//! blocks rather than erroring, because the holder is typically
//! mid-LLM-run and "come back later" is not something a caller can act
//! on any better than the kernel can. This matches the in-process
//! semantics workflows always had (`Mutex::lock` waits) and extends
//! them across processes, replacing the CLI-layer `try_lock` that
//! failed fast for `implement` alone.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::task::JoinError;

use writ::notes_repo::NotesRepo;

use crate::bailiff_plan_note::PlanId;

/// Directory under bailiff's bare repo holding per-plan lockfiles.
/// A dedicated subdirectory rather than the repo root so the lockfiles
/// cannot be mistaken for git's own state; git ignores directories it
/// does not know about inside a `GIT_DIR`.
const LOCK_DIR: &str = "bailiff-locks";

/// Lock-hold scope for one bailiff workflow on one plan.
///
/// Acquire once via [`Self::acquire`] at the top of a workflow and
/// keep the value alive for the whole thing. Use [`Self::run_blocking`]
/// for any git-shelling-out section; the lock is held across the call
/// and across `await` points between calls. On drop the lockfile
/// closes and the next waiter — in this process or another — proceeds.
///
/// Neither [`Clone`] nor [`Copy`]: exactly one workflow holds a plan's
/// lock at a time, and duplicating the guard would defeat that.
pub struct PlanGuard {
    /// The `flock`ed lockfile. Released when this `File` drops, or —
    /// as a backstop against an unclean exit — when the process ends
    /// and the kernel closes the descriptor.
    ///
    /// `Option` because [`Self::run_blocking`] *moves* it into the
    /// blocking task and takes it back. That hand-off is what makes
    /// the guard cancellation-safe: tokio does not cancel an
    /// already-running `spawn_blocking`, so if the caller's future is
    /// dropped mid-call, a lockfile owned by `PlanGuard` would close
    /// while the blocking closure was still touching the repo — and
    /// another workflow for the same plan could interleave with it.
    /// Owned by the task instead, the `flock` outlives the cancelled
    /// future and releases exactly when the closure returns.
    ///
    /// `None` only for the duration of that call.
    lockfile: Option<File>,
    repo: Arc<NotesRepo>,
}

impl PlanGuard {
    /// Take `plan_id`'s lock, waiting if another workflow holds it.
    ///
    /// Errors only if the lockfile cannot be created or locked — a
    /// filesystem problem, not contention.
    pub async fn acquire(repo: Arc<NotesRepo>, plan_id: PlanId) -> Result<Self, PlanGuardError> {
        let repo_path = repo.path().to_path_buf();
        // `flock` blocks, so it must not run on a runtime thread.
        let lockfile =
            tokio::task::spawn_blocking(move || acquire_plan_lockfile(&repo_path, plan_id))
                .await
                .map_err(|source| PlanGuardError::LockTaskFailed { plan_id, source })??;
        Ok(Self {
            lockfile: Some(lockfile),
            repo,
        })
    }

    /// Run `work` against the repo in a `spawn_blocking` task under
    /// the held lock.
    ///
    /// The lockfile is moved into the task and moved back out, so the
    /// `flock` is held for exactly as long as the closure runs even if
    /// the caller's future is cancelled in the meantime — tokio does
    /// not cancel an already-running `spawn_blocking`, so a lockfile
    /// the guard kept would close while the closure was still using
    /// the repo.
    ///
    /// Surfaces a [`JoinError`] iff the task panicked or was
    /// cancelled — the same condition each workflow maps to its own
    /// `ReadTaskFailed` / `WriteTaskFailed` variant. In that case the
    /// lockfile died with the task, which closes its descriptor and
    /// releases the lock; the guard is left unusable and any further
    /// `run_blocking` panics rather than silently running unlocked.
    pub async fn run_blocking<F, R>(&mut self, work: F) -> Result<R, JoinError>
    where
        F: FnOnce(&NotesRepo) -> R + Send + 'static,
        R: Send + 'static,
    {
        let lockfile = self
            .lockfile
            .take()
            .expect("PlanGuard invariant: the lockfile is Some outside run_blocking");
        let repo = Arc::clone(&self.repo);
        let (lockfile, result) = tokio::task::spawn_blocking(move || {
            let r = work(&repo);
            (lockfile, r)
        })
        .await?;
        self.lockfile = Some(lockfile);
        Ok(result)
    }
}

/// Open this plan's lockfile and take the `flock`, waiting for it.
///
/// Blocking; callers run it on a blocking thread. Distinct
/// `--bailiff-repo` paths do not contend, and neither do distinct plan
/// ids within one repo.
fn acquire_plan_lockfile(repo_path: &Path, plan_id: PlanId) -> Result<File, PlanGuardError> {
    let dir = repo_path.join(LOCK_DIR);
    std::fs::create_dir_all(&dir).map_err(|source| PlanGuardError::OpenLockfile {
        path: dir.clone(),
        source,
    })?;
    let path = dir.join(format!("{plan_id}.lock"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|source| PlanGuardError::OpenLockfile {
            path: path.clone(),
            source,
        })?;
    // Report contention once before settling in to wait, so an
    // operator staring at an idle CLI knows why. `warn`, not `info`:
    // the `bailiff` binary initialises telemetry at `warn`
    // (`bin/bailiff.rs`), so an `info` event here is filtered out and
    // the command just looks hung for the length of an LLM run.
    match file.try_lock() {
        Ok(()) => return Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => {
            tracing::warn!(
                %plan_id,
                lockfile = %path.display(),
                "waiting for another bailiff workflow to release this plan",
            );
        }
        Err(std::fs::TryLockError::Error(source)) => {
            return Err(PlanGuardError::OpenLockfile { path, source });
        }
    }
    file.lock()
        .map_err(|source| PlanGuardError::OpenLockfile { path, source })?;
    Ok(file)
}

/// Lockfile name for the shared writ-notes mirror. Cannot collide
/// with a plan lockfile: those are named by UUID.
const MIRROR_LOCK: &str = "_writ-mirror.lock";

/// Take the repo-wide lock guarding bailiff's mirror of writ's notes,
/// waiting for it. Blocking; call from inside a [`PlanGuard::run_blocking`]
/// section, which is already on a blocking thread.
///
/// Per-plan locks are the right granularity for *plan* state, because
/// each plan owns its ref. They are the wrong granularity for the
/// writ mirror, which every workflow fetches into the same
/// destination (`refs/notes/writ/v1/*`, force-fetched). Two workflows
/// for different plans do not contend on their plan locks, so without
/// this a fetch from one can roll the shared mirror back between
/// another's fetch and its read — and on the implement path that can
/// happen *after* the agent has already pushed, leaving the run
/// without its `ImplementNote`.
///
/// `NotesRepo`'s own mutex does not cover this: it serialises each git
/// invocation, not the fetch-then-read pair, and it is process-wide
/// where this hazard is not.
///
/// **Lock ordering: plan lock first, then this one.** Every caller
/// takes it inside a held [`PlanGuard`] and releases it before the
/// guard drops, so the order is total and cannot deadlock.
pub(crate) fn lock_writ_mirror(repo: &NotesRepo) -> Result<File, PlanGuardError> {
    let dir = repo.path().join(LOCK_DIR);
    std::fs::create_dir_all(&dir).map_err(|source| PlanGuardError::OpenLockfile {
        path: dir.clone(),
        source,
    })?;
    let path = dir.join(MIRROR_LOCK);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|source| PlanGuardError::OpenLockfile {
            path: path.clone(),
            source,
        })?;
    file.lock()
        .map_err(|source| PlanGuardError::OpenLockfile { path, source })?;
    Ok(file)
}

/// Why a plan's lock could not be taken.
#[derive(Debug, thiserror::Error)]
pub enum PlanGuardError {
    /// The `spawn_blocking` task that waits on the `flock` panicked
    /// or was cancelled. A tokio-runtime condition, not contention.
    #[error("the lock task for plan {plan_id} failed: {source}")]
    LockTaskFailed {
        plan_id: PlanId,
        #[source]
        source: JoinError,
    },
    /// The lockfile (or its directory) could not be created or locked.
    #[error("acquiring the plan lockfile at {}: {source}", .path.display())]
    OpenLockfile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests;
