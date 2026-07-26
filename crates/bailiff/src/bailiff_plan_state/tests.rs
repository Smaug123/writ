//! Properties of the plan transition relation.
//!
//! The suite is built around three reference implementations that
//! never consult the thing they check:
//!
//! - [`pre_slice1_state`] is the derivation as it stood before this
//!   module existed, so the behaviour change is pinned as an explicit
//!   table rather than left for a reviewer to reconstruct from a diff;
//! - [`write_note`] applies a stage's note write without knowing
//!   anything about [`PlanState`], so walking the relation with it
//!   checks [`PlanState::presence`] against
//!   [`PlanStage::legal_predecessors`] — the module's two encodings of
//!   the workflow's shape;
//! - [`all_presences`] enumerates the full 24-element observation
//!   space, so every "for all note sets" claim below is exhaustive
//!   rather than sampled. Proptest would be strictly weaker here: the
//!   space is small enough to test completely.

use std::collections::BTreeSet;

use super::*;

/// Every possible note set: 2 submission × 3 decision × 2 review × 2
/// implement.
fn all_presences() -> Vec<NotePresence> {
    let mut out = Vec::with_capacity(24);
    for submission in [false, true] {
        for decision in [None, Some(Decision::Accepted), Some(Decision::Rejected)] {
            for review in [false, true] {
                for implement in [false, true] {
                    out.push(NotePresence {
                        submission,
                        decision,
                        review,
                        implement,
                    });
                }
            }
        }
    }
    out
}

/// The derivation exactly as `BailiffPlanSummary::state` implemented it
/// before slice 1 (`bailiff_plan_view.rs:129-146`): "the highest
/// workflow step reached", with a missing submission folded to
/// `Corrupt`. Returns the rendered string so it cannot accidentally be
/// written in terms of the new enum.
fn pre_slice1_state(p: &NotePresence) -> &'static str {
    if !p.submission {
        return "corrupt";
    }
    if p.implement {
        return "implemented";
    }
    if p.review {
        return "reviewed";
    }
    match p.decision {
        Some(Decision::Accepted) => "accepted",
        Some(Decision::Rejected) => "rejected",
        None => "submitted",
    }
}

/// Apply a stage's note write. Knows only which note each stage
/// attaches — nothing about states, predecessors, or presences — so
/// the relation walk below is independent of what it checks.
fn write_note(p: NotePresence, stage: PlanStage, outcome: Decision) -> NotePresence {
    match stage {
        PlanStage::Submit => NotePresence {
            submission: true,
            ..p
        },
        PlanStage::Decide => NotePresence {
            decision: Some(outcome),
            ..p
        },
        PlanStage::Review => NotePresence { review: true, ..p },
        PlanStage::Implement => NotePresence {
            implement: true,
            ..p
        },
    }
}

/// Every note set reachable from nothing by a legal sequence of
/// stages, found by walking [`PlanStage::legal_predecessors`] and
/// applying [`write_note`]. Also asserts the load-bearing invariant
/// that a *legal* move never lands on `Corrupt` — if the relation
/// permits a stage whose resulting note set has no `presence`, that is
/// precisely the drift this module exists to prevent.
fn reachable_presences() -> BTreeSet<NotePresence> {
    let mut seen = BTreeSet::new();
    let mut frontier = vec![NotePresence::NONE];
    seen.insert(NotePresence::NONE);
    while let Some(current) = frontier.pop() {
        let state = derive_state(&current);
        for &stage in PlanStage::ALL {
            if !stage.legal_predecessors().contains(&state) {
                continue;
            }
            // `Decide` is the only stage whose write carries data, so
            // it is the only one that branches. The others ignore the
            // outcome argument.
            let outcomes: &[Decision] = match stage {
                PlanStage::Decide => &[Decision::Accepted, Decision::Rejected],
                _ => &[Decision::Accepted],
            };
            for &outcome in outcomes {
                let next = write_note(current, stage, outcome);
                assert_ne!(
                    derive_state(&next),
                    PlanState::Corrupt,
                    "stage {stage} is legal from {state} but produces a note set with no state: \
                     {next:?}",
                );
                if seen.insert(next) {
                    frontier.push(next);
                }
            }
        }
    }
    seen
}

/// The headline property: `Corrupt` means "no legal sequence of stages
/// produces this note set", and nothing else. Bidirectional — a
/// presence is reachable iff `derive` gives it a non-`Corrupt` state —
/// so neither a state whose presence the relation cannot reach nor a
/// reachable note set that `derive` calls corrupt survives.
#[test]
fn reachable_presences_are_exactly_the_non_corrupt_states() {
    let reachable = reachable_presences();
    let non_corrupt: BTreeSet<NotePresence> = all_presences()
        .into_iter()
        .filter(|p| derive_state(p) != PlanState::Corrupt)
        .collect();
    assert_eq!(reachable, non_corrupt);
    // Pin the count so a future stage that widens the relation has to
    // come back here and say so.
    assert_eq!(reachable.len(), 6);
}

/// Binds the module's two encodings of the workflow shape: for every
/// legal move, the note write lands exactly on the successor's
/// declared `presence`, and every non-`Corrupt` state's presence is
/// itself reachable.
#[test]
fn presence_agrees_with_the_transition_relation() {
    for &state in PlanState::ALL {
        let Some(presence) = state.presence() else {
            assert_eq!(state, PlanState::Corrupt);
            continue;
        };
        // Inverse: `derive` recovers the state its presence came from.
        assert_eq!(
            derive_state(&presence),
            state,
            "presence of {state} derives elsewhere"
        );
        for &stage in PlanStage::ALL {
            if !stage.legal_predecessors().contains(&state) {
                continue;
            }
            for outcome in [Decision::Accepted, Decision::Rejected] {
                let next = derive_state(&write_note(presence, stage, outcome));
                assert!(
                    next.presence().is_some(),
                    "{stage} from {state} (outcome {outcome}) lands on {next}",
                );
            }
        }
    }
}

/// The deliberate behaviour change, as data. Every note set on which
/// slice 1 disagrees with the old derivation, and no others.
///
/// Two kinds of entry. Most are note sets the old code labelled with a
/// workflow stage even though no legal sequence produces them —
/// implement-without-review, a verdict recorded before any review, and
/// so on. Two are *relabellings*: `{sub, rev, decision}` used to read
/// as `reviewed` under the old "highest stage reached" rule, and now
/// reads as the verdict it carries, because the decision is the later
/// step. The remaining one is the empty set, which the old code called
/// `Corrupt` because a plan ref could not exist without a note; the
/// machine needs it as `Absent` for `submit` to start from.
fn behaviour_delta_table() -> Vec<(NotePresence, &'static str, PlanState)> {
    let p = |submission, decision, review, implement| NotePresence {
        submission,
        decision,
        review,
        implement,
    };
    let acc = Some(Decision::Accepted);
    let rej = Some(Decision::Rejected);
    vec![
        // Nothing recorded: was the corrupt bucket, now the start.
        (NotePresence::NONE, "corrupt", PlanState::Absent),
        // A verdict recorded before any review — the ordering the
        // design doc rules out, and the gap the old `decide` verb left
        // wide open.
        (p(true, acc, false, false), "accepted", PlanState::Corrupt),
        (p(true, rej, false, false), "rejected", PlanState::Corrupt),
        // Reviewed *and* decided: the old rule reported the earlier
        // stage, the relation reports the later one.
        (p(true, acc, true, false), "reviewed", PlanState::Accepted),
        (p(true, rej, true, false), "reviewed", PlanState::Rejected),
        // Implemented without some earlier stage.
        (
            p(true, None, false, true),
            "implemented",
            PlanState::Corrupt,
        ),
        (p(true, acc, false, true), "implemented", PlanState::Corrupt),
        (p(true, rej, false, true), "implemented", PlanState::Corrupt),
        (p(true, None, true, true), "implemented", PlanState::Corrupt),
        (p(true, rej, true, true), "implemented", PlanState::Corrupt),
    ]
}

#[test]
fn derive_matches_the_old_derivation_except_on_the_delta_table() {
    let table = behaviour_delta_table();
    for (presence, old, new) in &table {
        assert_eq!(
            pre_slice1_state(presence),
            *old,
            "delta table misstates the old behaviour for {presence:?}",
        );
        assert_eq!(
            derive_state(presence),
            *new,
            "delta table misstates the new behaviour for {presence:?}",
        );
        assert_ne!(
            pre_slice1_state(presence),
            new.as_str(),
            "delta table lists {presence:?} as changed, but it did not change",
        );
    }
    // Everything outside the table is unchanged. This is the half that
    // makes the table a *complete* account of the behaviour change.
    let changed: BTreeSet<NotePresence> = table.iter().map(|(p, _, _)| *p).collect();
    for presence in all_presences() {
        if changed.contains(&presence) {
            continue;
        }
        assert_eq!(
            derive_state(&presence).as_str(),
            pre_slice1_state(&presence),
            "undeclared behaviour change at {presence:?}",
        );
    }
    assert_eq!(table.len(), 10);
}

/// `derive` is defined on the whole observation space, and the states
/// it can return are exactly those with a presence, plus `Corrupt`.
#[test]
fn derive_is_total_over_the_observation_space() {
    let produced: BTreeSet<PlanState> = all_presences().iter().map(derive_state).collect();
    let expected: BTreeSet<PlanState> = PlanState::ALL.iter().copied().collect();
    assert_eq!(
        produced, expected,
        "some state is unreachable by derivation"
    );
    assert_eq!(all_presences().len(), 24);
}

/// `allows` is total, and agrees with the relation it is defined from.
#[test]
fn allows_is_total_and_agrees_with_legal_predecessors() {
    for &state in PlanState::ALL {
        for &stage in PlanStage::ALL {
            let permitted = allows(state, stage).is_ok();
            assert_eq!(permitted, stage.legal_predecessors().contains(&state));
            if !permitted {
                let err = allows(state, stage).unwrap_err();
                assert_eq!(err, IllegalTransition { state, stage });
                // Every refusal explains itself: the message names the
                // blocked stage and is not a bare debug dump.
                let msg = err.to_string();
                assert!(msg.contains(stage.as_str()), "{msg}");
                assert!(msg.contains(state.as_str()), "{msg}");
            }
        }
    }
}

/// A legal stage always moves the plan strictly forward: `Corrupt`
/// permits nothing, and no stage is legal from the state it produces
/// (which is what makes the machine subsume the old `AlreadyRecorded`
/// pre-RPC gates rather than merely coexist with them).
#[test]
fn legal_stages_never_repeat_from_the_state_they_produce() {
    for &state in PlanState::ALL {
        let Some(presence) = state.presence() else {
            continue;
        };
        for &stage in PlanStage::ALL {
            if !stage.legal_predecessors().contains(&state) {
                continue;
            }
            for outcome in [Decision::Accepted, Decision::Rejected] {
                let next = derive_state(&write_note(presence, stage, outcome));
                assert_ne!(next, state, "{stage} from {state} is a self-loop");
                assert!(
                    allows(next, stage).is_err(),
                    "{stage} is legal again from {next}, so the duplicate gate is not subsumed",
                );
            }
        }
    }
}

#[test]
fn corrupt_denies_every_stage() {
    for &stage in PlanStage::ALL {
        assert!(allows(PlanState::Corrupt, stage).is_err());
    }
    assert_eq!(PlanState::Corrupt.next_stage(), None);
    assert_eq!(PlanState::Corrupt.presence(), None);
}

/// The three tightenings from the plan's behaviour-change table, named
/// one per delta so a reviewer sees each refusal asserted directly
/// rather than inferred from a quantified property.
#[test]
fn decide_now_requires_a_review() {
    // `decide` used to read no precondition whatsoever.
    assert!(allows(PlanState::Absent, PlanStage::Decide).is_err());
    assert!(allows(PlanState::Submitted, PlanStage::Decide).is_err());
    assert!(allows(PlanState::Reviewed, PlanStage::Decide).is_ok());
}

#[test]
fn review_precedes_the_decision() {
    // Reviewer feedback is an input to the verdict, so review runs on
    // a plain submission and is not legal once a verdict exists.
    assert!(allows(PlanState::Submitted, PlanStage::Review).is_ok());
    assert!(allows(PlanState::Absent, PlanStage::Review).is_err());
    assert!(allows(PlanState::Accepted, PlanStage::Review).is_err());
    assert!(allows(PlanState::Rejected, PlanStage::Review).is_err());
}

#[test]
fn implement_now_requires_an_accepted_verdict() {
    assert!(allows(PlanState::Submitted, PlanStage::Implement).is_err());
    assert!(allows(PlanState::Reviewed, PlanStage::Implement).is_err());
    assert!(allows(PlanState::Rejected, PlanStage::Implement).is_err());
    assert!(allows(PlanState::Accepted, PlanStage::Implement).is_ok());
    // The old duplicate gate, now a consequence of the relation.
    assert!(allows(PlanState::Implemented, PlanStage::Implement).is_err());
}

/// `next_stage` is the remedy hint's source; pin the chain and the two
/// terminals so an error message cannot start recommending nonsense.
#[test]
fn next_stage_follows_the_chain_and_stops_at_terminals() {
    assert_eq!(PlanState::Absent.next_stage(), Some(PlanStage::Submit));
    assert_eq!(PlanState::Submitted.next_stage(), Some(PlanStage::Review));
    assert_eq!(PlanState::Reviewed.next_stage(), Some(PlanStage::Decide));
    assert_eq!(PlanState::Accepted.next_stage(), Some(PlanStage::Implement));
    assert_eq!(PlanState::Rejected.next_stage(), None);
    assert_eq!(PlanState::Implemented.next_stage(), None);
}

/// Pins the lowercase spellings the CLI renders. `bailiff plan list`
/// output is a user-facing surface; these strings are its vocabulary.
#[test]
fn state_and_stage_strings_are_stable() {
    assert_eq!(PlanState::Absent.as_str(), "absent");
    assert_eq!(PlanState::Corrupt.as_str(), "corrupt");
    assert_eq!(PlanState::Submitted.as_str(), "submitted");
    assert_eq!(PlanState::Accepted.as_str(), "accepted");
    assert_eq!(PlanState::Rejected.as_str(), "rejected");
    assert_eq!(PlanState::Reviewed.as_str(), "reviewed");
    assert_eq!(PlanState::Implemented.as_str(), "implemented");
    assert_eq!(PlanState::Submitted.to_string(), "submitted");

    assert_eq!(PlanStage::Submit.as_str(), "submit");
    assert_eq!(PlanStage::Decide.as_str(), "decide");
    assert_eq!(PlanStage::Review.as_str(), "review");
    assert_eq!(PlanStage::Implement.as_str(), "implement");

    // Distinctness, so no two variants can be conflated in output.
    let states: BTreeSet<&str> = PlanState::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(states.len(), PlanState::ALL.len());
    let stages: BTreeSet<&str> = PlanStage::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(stages.len(), PlanStage::ALL.len());
}

/// The remedy text is generated from the relation, so a wrong hint
/// means a wrong relation. Pin the two shapes an operator actually
/// hits.
#[test]
fn illegal_transition_names_the_operators_next_step() {
    let err = allows(PlanState::Reviewed, PlanStage::Implement).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("requires accepted"), "{msg}");
    assert!(msg.contains("run `bailiff plan decide` first"), "{msg}");

    let terminal = allows(PlanState::Rejected, PlanStage::Implement).unwrap_err();
    let msg = terminal.to_string();
    assert!(msg.contains("terminal"), "{msg}");

    let corrupt = allows(PlanState::Corrupt, PlanStage::Review).unwrap_err();
    let msg = corrupt.to_string();
    assert!(msg.contains("bailiff plan show"), "{msg}");
}

/// A repeated command must never be told to run a *later* stage:
/// nothing downstream can make an already-passed stage legal again.
///
/// This is the guidance the per-verb "already recorded ... submit a
/// fresh plan" messages carried before the transition relation
/// replaced them; losing it was a real regression, caught in review.
#[test]
fn repeating_a_passed_stage_recommends_a_fresh_plan_not_a_later_stage() {
    for (state, stage) in [
        (PlanState::Submitted, PlanStage::Submit),
        (PlanState::Accepted, PlanStage::Decide),
        (PlanState::Rejected, PlanStage::Decide),
        (PlanState::Reviewed, PlanStage::Review),
        (PlanState::Accepted, PlanStage::Review),
        (PlanState::Implemented, PlanStage::Implement),
    ] {
        assert!(
            stage.already_passed_from(state),
            "{stage} from {state} is a repeat and must be recognised as one",
        );
        let msg = allows(state, stage).unwrap_err().to_string();
        assert!(msg.contains("already past"), "{msg}");
        assert!(msg.contains("submit a fresh plan"), "{msg}");
        assert!(
            !msg.contains("first"),
            "a repeated command must not recommend running another stage: {msg}",
        );
    }
}

/// The converse: a stage that has simply not become legal *yet* keeps
/// the actionable "run X first" hint.
#[test]
fn a_not_yet_reachable_stage_still_names_the_next_command() {
    for (state, stage, expected) in [
        (PlanState::Absent, PlanStage::Decide, "bailiff plan submit"),
        (
            PlanState::Submitted,
            PlanStage::Implement,
            "bailiff plan review",
        ),
        (
            PlanState::Reviewed,
            PlanStage::Implement,
            "bailiff plan decide",
        ),
    ] {
        assert!(!stage.already_passed_from(state));
        let msg = allows(state, stage).unwrap_err().to_string();
        assert!(msg.contains(expected), "{msg}");
    }
}

/// `already_passed_from` is derived from `rank`, so the two must agree
/// with the relation everywhere: a stage can never be both "already
/// passed" and currently legal.
#[test]
fn a_passed_stage_is_never_also_legal() {
    for &state in PlanState::ALL {
        for &stage in PlanStage::ALL {
            if stage.already_passed_from(state) {
                assert!(
                    allows(state, stage).is_err(),
                    "{stage} is both legal from {state} and marked already-passed",
                );
            }
        }
    }
}

/// `rank` orders exactly the states the relation can reach, and
/// `Corrupt` — which is not on the progression — has none.
#[test]
fn rank_is_defined_for_every_state_on_the_progression() {
    assert_eq!(PlanState::Corrupt.rank(), None);
    for &state in PlanState::ALL {
        assert_eq!(
            state.rank().is_some(),
            state != PlanState::Corrupt,
            "{state}",
        );
    }
    // Every legal move strictly increases rank, which is what makes
    // "beyond every predecessor" mean "already passed".
    for &state in PlanState::ALL {
        for &stage in PlanStage::ALL {
            if !stage.legal_predecessors().contains(&state) {
                continue;
            }
            let Some(presence) = state.presence() else {
                continue;
            };
            for outcome in [Decision::Accepted, Decision::Rejected] {
                let next = derive_state(&write_note(presence, stage, outcome));
                assert!(
                    next.rank() > state.rank(),
                    "{stage} from {state} lands on {next}, which does not advance rank",
                );
            }
        }
    }
}
