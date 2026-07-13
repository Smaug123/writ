//! Stage 7: the rival-actor sweep. The crash sweep kills the broker
//! at every instrumented point; this sweep instead lets it live while
//! *someone else* moves the branch at every point — the race class
//! behind the final-lease-recheck finding (a branch rewound between
//! the post-walk lease check and the PATCH would have published on
//! top of an unapproved baseline). A crash can't express that bug;
//! a rival move can.
//!
//! Mechanism: [`CrashPlan::act_at`] fires the rival's move at point
//! `k` and lets the handler continue to whatever outcome the
//! production code reaches. Two rival moves are swept:
//!
//! * **rewind** to a model-known *ancestor* of the seeded head — the
//!   dangerous one, because GitHub's non-forced PATCH is a
//!   descent-from-current check, not compare-and-swap, so a PATCH
//!   built against the old baseline still fast-forwards from the
//!   rewound tip;
//! * **advance** to a foreign (parentless) commit — the loud one,
//!   which any surviving PATCH would refuse 422.
//!
//! Oracle (plan stage 7): for every point and every rival move, the
//! approve either succeeds having published *from the approved
//! baseline* — the fake's ref history shows the publish stepping from
//! `expected_remote_head`, never from the rival's tip — or resolves
//! as a failure that leaves the ref exactly where the rival put it.

use super::approve_crash_tests::{ApproveWorld, WORLD_BRANCH, count_points};
use super::*;
use crate::audit::GitPushApproveAttemptState;
use crate::crash_point::{CrashPlan, run_until_crash};

/// The rewind target: taught to the model as the seeded head's parent,
/// so a PATCH built on the old baseline still descends from it.
const ANCESTOR: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// The foreign commit: a parentless stranger nothing descends from.
const FOREIGN: &str = "ffffffffffffffffffffffffffffffffffffffff";

#[derive(Clone, Copy, Debug)]
enum Rival {
    RewindToAncestor,
    AdvanceToForeign,
}

impl Rival {
    fn sha(self) -> &'static str {
        match self {
            Self::RewindToAncestor => ANCESTOR,
            Self::AdvanceToForeign => FOREIGN,
        }
    }
}

#[tokio::test]
async fn rival_ref_moves_at_every_point_never_publish_off_the_approved_baseline() {
    let Some((n, names)) = count_points().await else {
        eprintln!("skipping: `git` not on PATH");
        return;
    };

    for rival in [Rival::RewindToAncestor, Rival::AdvanceToForeign] {
        let mut saw_publish = false;
        let mut saw_failure = false;
        for (k, &name) in names.iter().enumerate() {
            let label = format!("k={k} ({name}) [{rival:?}]");
            let world = ApproveWorld::start()
                .await
                .expect("git existed for the counting run");
            // Teach the model the graph that makes the rival's moves
            // meaningful: the seeded head descends from ANCESTOR (so a
            // rewind is a *plausible* baseline for a fast-forward, not
            // an automatic 422), and FOREIGN is unrelated to anything.
            world.github.seed_commit(ANCESTOR, &[]);
            world
                .github
                .seed_commit(world.origin.prereq().as_str(), &[ANCESTOR]);
            world.github.seed_commit(FOREIGN, &[]);

            let plan =
                CrashPlan::act_at(k, world.github.force_ref_setter(WORLD_BRANCH, rival.sha()));
            let resp = run_until_crash(
                &plan,
                dispatch_message(world.approve_message(), &world.state),
            )
            .await
            .expect_completed("the rival mode never parks the handler");
            assert!(plan.acted(), "the rival's move must fire at {label}");

            let history = world.github.ref_history(WORLD_BRANCH);
            match resp {
                ServerMessage::StagedPushApproved { new_app_tip, .. } => {
                    saw_publish = true;
                    // The publish must step from the approved baseline.
                    // Its predecessor in the ref history is the tip the
                    // PATCH actually fast-forwarded from; a rival tip
                    // there is the TOCTOU this sweep exists to catch.
                    let i = history
                        .iter()
                        .position(|sha| sha == new_app_tip.as_str())
                        .unwrap_or_else(|| {
                            panic!("published tip missing from ref history at {label}")
                        });
                    assert!(i >= 1, "the seed precedes any publish at {label}");
                    assert_eq!(
                        history[i - 1],
                        world.origin.prereq().as_str(),
                        "publish must step from the approved baseline, \
                         not the rival's tip, at {label}",
                    );
                    assert_eq!(
                        world.github.patch_requests().len(),
                        1,
                        "exactly one PATCH behind a publish at {label}",
                    );
                }
                ServerMessage::Error { .. } => {
                    saw_failure = true;
                    // Failure must leave the world exactly as the rival
                    // made it: no publish, ref at the rival's tip.
                    assert_eq!(
                        world.github.ref_of(WORLD_BRANCH).unwrap(),
                        rival.sha(),
                        "failure must leave the ref where the rival put it at {label}",
                    );
                    assert_eq!(
                        history,
                        vec![
                            world.origin.prereq().as_str().to_string(),
                            rival.sha().to_string(),
                        ],
                        "no publish may land once the rival's move is refused at {label}",
                    );
                    // The handler lived, so its own error handling ran:
                    // nothing may be left Started or Uncertain.
                    let attempts = world
                        .state
                        .audit
                        .approve_attempts_for_push(world.request_id)
                        .unwrap();
                    assert!(
                        attempts.iter().all(|a| matches!(
                            a.state,
                            GitPushApproveAttemptState::Resolved { .. }
                        )),
                        "a live handler must resolve its attempt at {label}: {attempts:?}",
                    );
                }
                other => panic!("unexpected reply at {label}: {other:?}"),
            }
        }
        // Meta-check: the sweep must observe both outcomes, or half
        // its assertions never ran. The rival firing after the PATCH
        // can't fail the approve; firing before any lease check must.
        assert!(
            saw_publish && saw_failure,
            "the {rival:?} sweep over {n} points must observe both outcomes \
             (publish: {saw_publish}, failure: {saw_failure})",
        );
    }
}
