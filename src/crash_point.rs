//! Crash points: deterministic fault injection for the approve
//! pipeline (and any future multi-store effect sequence).
//!
//! Production code marks the boundary after every durable effect with
//! `crash_point::point("name").await`. In non-test builds that call is
//! an empty inline function — zero cost, zero behaviour, but visible
//! and greppable at every call site. In test builds it consults a
//! tokio task-local [`CrashPlan`]; with no plan installed it is still
//! a no-op, so the rest of the suite never notices the points exist.
//!
//! A harness installs a plan with [`run_until_crash`]: in counting
//! mode the future runs to completion and the plan reports how many
//! points it passed (and their names, in order); in crash mode the
//! plan parks the future forever at the chosen point and
//! `run_until_crash` **drops** it — abandoning all subsequent code,
//! including error handling and cleanup, exactly as a crash would.
//! The sweep pattern is: one counting run to learn `N`, then a crash
//! run for each `k ∈ 0..N`. Adding a new point later automatically
//! widens the sweep; no manual index list exists to go stale.
//!
//! See `docs/design/approve-crash-injection-harness.md` for the full
//! design. Two caveats from there are load-bearing:
//!
//! * **Drop honesty.** Dropping a future runs `Drop` impls; a real
//!   crash does not. This is sound only while no type on an
//!   instrumented path performs *observable* cleanup in `Drop`
//!   (`StagingRepo` deliberately has none). A reviewer adding a
//!   self-cleaning guard type to an instrumented path must extend the
//!   harness first.
//! * **Spawn survival.** `tokio::spawn`ed work outlives the dropped
//!   future but would not outlive a real crash, and task-locals do
//!   not propagate into `tokio::spawn` or `spawn_blocking`. Points
//!   must therefore live in the instrumented function's own async
//!   control flow — after the `.await` on a `spawn_blocking`, never
//!   inside its closure — and before any `tokio::spawn`.
//!
//! Review convention: **a new durable effect on an instrumented path
//! gets a new `point` after it.** The sweep can only see the
//! boundaries it is told about.

/// Mark the boundary after a durable effect.
///
/// `name` is diagnostic only (it appears in counting-mode listings and
/// crash reports); indices, not names, drive the sweep, so renaming a
/// point is free.
// dead_code: the production call sites arrive with the instrumentation
// stage of the harness plan; this allow goes with them.
#[cfg(not(test))]
#[allow(dead_code)]
#[inline(always)]
pub(crate) async fn point(_name: &'static str) {}

#[cfg(test)]
pub(crate) use test_impl::point;
#[cfg(test)]
pub(crate) use test_impl::{CrashOutcome, CrashPlan, run_until_crash};

#[cfg(test)]
mod test_impl {
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    tokio::task_local! {
        static CRASH_PLAN: Arc<CrashPlan>;
    }

    #[derive(Debug)]
    enum Mode {
        /// Pass every point, recording it.
        Count,
        /// Park forever at the point whose running index equals this.
        CrashAt(usize),
    }

    /// A single run's fault-injection schedule plus what it observed.
    /// One plan drives one run: the running counter is never reset, so
    /// reusing a plan across runs would misnumber the points.
    #[derive(Debug)]
    pub(crate) struct CrashPlan {
        mode: Mode,
        counter: AtomicUsize,
        names: Mutex<Vec<&'static str>>,
        parked: tokio::sync::Notify,
        crashed_at: Mutex<Option<(usize, &'static str)>>,
    }

    impl CrashPlan {
        /// A plan that lets the run complete and counts the points.
        pub(crate) fn count() -> Arc<Self> {
            Arc::new(Self::new(Mode::Count))
        }

        /// A plan that parks the run at the `index`th point passed
        /// (0-based, in execution order).
        pub(crate) fn crash_at(index: usize) -> Arc<Self> {
            Arc::new(Self::new(Mode::CrashAt(index)))
        }

        fn new(mode: Mode) -> Self {
            Self {
                mode,
                counter: AtomicUsize::new(0),
                names: Mutex::new(Vec::new()),
                parked: tokio::sync::Notify::new(),
                crashed_at: Mutex::new(None),
            }
        }

        /// Number of points passed so far (in counting mode after a
        /// completed run: the total, i.e. the sweep's `N`).
        pub(crate) fn points_passed(&self) -> usize {
            self.counter.load(Ordering::SeqCst)
        }

        /// Names of the points passed, in execution order.
        pub(crate) fn names(&self) -> Vec<&'static str> {
            self.names
                .lock()
                .expect("crash plan names poisoned")
                .clone()
        }
    }

    /// What happened to the instrumented future.
    #[derive(Debug)]
    pub(crate) enum CrashOutcome<T> {
        /// No crash was scheduled inside the run's point range; the
        /// future ran to completion.
        Completed(T),
        /// The future was parked at the named point and dropped —
        /// everything after that point never ran.
        Crashed { index: usize, name: &'static str },
    }

    impl<T> CrashOutcome<T> {
        #[track_caller]
        pub(crate) fn expect_completed(self, msg: &str) -> T {
            match self {
                Self::Completed(v) => v,
                Self::Crashed { index, name } => {
                    panic!("{msg}: crashed at point {index} ({name})")
                }
            }
        }

        #[track_caller]
        pub(crate) fn expect_crashed(self, msg: &str) -> (usize, &'static str)
        where
            T: std::fmt::Debug,
        {
            match self {
                Self::Completed(v) => panic!("{msg}: completed with {v:?}"),
                Self::Crashed { index, name } => (index, name),
            }
        }
    }

    /// Await a named crash point under whatever plan the harness
    /// installed. With no plan in scope this is a no-op.
    pub(crate) async fn point(name: &'static str) {
        let Ok(plan) = CRASH_PLAN.try_with(Arc::clone) else {
            return;
        };
        let index = plan.counter.fetch_add(1, Ordering::SeqCst);
        plan.names
            .lock()
            .expect("crash plan names poisoned")
            .push(name);
        if let Mode::CrashAt(target) = plan.mode
            && index == target
        {
            *plan
                .crashed_at
                .lock()
                .expect("crash plan crashed_at poisoned") = Some((index, name));
            plan.parked.notify_one();
            // Park forever; the harness drops this future, abandoning
            // everything downstream of the point — the crash.
            std::future::pending::<()>().await;
        }
    }

    /// Run `fut` under `plan`. Returns [`CrashOutcome::Crashed`] the
    /// moment the plan parks the future (dropping it), or
    /// [`CrashOutcome::Completed`] with the future's output.
    pub(crate) async fn run_until_crash<T>(
        plan: &Arc<CrashPlan>,
        fut: impl Future<Output = T>,
    ) -> CrashOutcome<T> {
        let scoped = CRASH_PLAN.scope(Arc::clone(plan), fut);
        tokio::pin!(scoped);
        tokio::select! {
            out = &mut scoped => CrashOutcome::Completed(out),
            _ = plan.parked.notified() => {
                let (index, name) = plan
                    .crashed_at
                    .lock()
                    .expect("crash plan crashed_at poisoned")
                    .expect("parked notification without a recorded crash point");
                // `scoped` is dropped when this function returns: the
                // instrumented future is abandoned mid-await.
                CrashOutcome::Crashed { index, name }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{CrashOutcome, CrashPlan, point, run_until_crash};

    /// A toy three-step pipeline: each step records a durable "effect"
    /// (a vec entry) and passes a crash point. The oracle for the
    /// whole mechanism is that a crash at point `k` preserves exactly
    /// the first `k + 1` effects.
    async fn toy_pipeline(effects: Arc<Mutex<Vec<&'static str>>>) -> &'static str {
        effects.lock().unwrap().push("alpha");
        point("after_alpha").await;
        effects.lock().unwrap().push("beta");
        point("after_beta").await;
        effects.lock().unwrap().push("gamma");
        point("after_gamma").await;
        "done"
    }

    #[tokio::test]
    async fn counting_mode_reports_every_point_in_order() {
        let effects = Arc::new(Mutex::new(Vec::new()));
        let plan = CrashPlan::count();
        let out = run_until_crash(&plan, toy_pipeline(Arc::clone(&effects)))
            .await
            .expect_completed("counting mode must not crash");
        assert_eq!(out, "done");
        assert_eq!(plan.points_passed(), 3);
        assert_eq!(
            plan.names(),
            vec!["after_alpha", "after_beta", "after_gamma"]
        );
        assert_eq!(
            *effects.lock().unwrap(),
            vec!["alpha", "beta", "gamma"],
            "counting mode must not perturb the pipeline",
        );
    }

    /// The sweep contract: crash at `k` ⇒ effects `0..=k` happened,
    /// everything after did not, and the report names the point.
    #[tokio::test]
    async fn crashing_at_each_point_preserves_exactly_the_prior_effects() {
        let all_names = ["after_alpha", "after_beta", "after_gamma"];
        let all_effects = ["alpha", "beta", "gamma"];
        for k in 0..3 {
            let effects = Arc::new(Mutex::new(Vec::new()));
            let plan = CrashPlan::crash_at(k);
            let (index, name) = run_until_crash(&plan, toy_pipeline(Arc::clone(&effects)))
                .await
                .expect_crashed("plan must crash inside the pipeline");
            assert_eq!(index, k);
            assert_eq!(name, all_names[k]);
            assert_eq!(
                *effects.lock().unwrap(),
                &all_effects[..=k],
                "crash at point {k} must abandon every later effect",
            );
        }
    }

    /// Crashing past the last point means the run completes — this is
    /// what lets a sweep discover its own upper bound by observing
    /// `Completed` (or, better, by counting first).
    #[tokio::test]
    async fn crash_index_beyond_the_run_completes_normally() {
        let effects = Arc::new(Mutex::new(Vec::new()));
        let plan = CrashPlan::crash_at(3);
        let out = run_until_crash(&plan, toy_pipeline(effects))
            .await
            .expect_completed("an out-of-range crash index must not fire");
        assert_eq!(out, "done");
        assert_eq!(plan.points_passed(), 3);
    }

    /// The no-plan guarantee the rest of the test suite relies on:
    /// instrumented code called outside `run_until_crash` behaves as
    /// if the points were not there.
    #[tokio::test]
    async fn without_a_plan_points_are_no_ops() {
        let effects = Arc::new(Mutex::new(Vec::new()));
        let out = toy_pipeline(Arc::clone(&effects)).await;
        assert_eq!(out, "done");
        assert_eq!(*effects.lock().unwrap(), vec!["alpha", "beta", "gamma"]);
    }

    /// Nested scopes: a crashed inner future must not wedge the outer
    /// harness — the outcome is reported and the harness continues.
    /// (This is the reboot-and-retry shape Stage 5 uses in a loop.)
    #[tokio::test]
    async fn sequential_runs_are_independent() {
        for k in [1usize, 0, 2] {
            let effects = Arc::new(Mutex::new(Vec::new()));
            let plan = CrashPlan::crash_at(k);
            match run_until_crash(&plan, toy_pipeline(Arc::clone(&effects))).await {
                CrashOutcome::Crashed { index, .. } => assert_eq!(index, k),
                CrashOutcome::Completed(_) => panic!("k={k} must crash"),
            }
        }
    }
}
