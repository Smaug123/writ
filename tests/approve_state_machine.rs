//! End-to-end property test for the approve-attempt state machine
//! (slice B1e.3d.2 of `docs/design/approve_state_machine.md`).
//!
//! What this test *does*: drive the audit-log DAO + boot reconcile +
//! `reject_blocker_for_push` against random traces of
//! `Stage`/`Approve`/`Reject`/`Crash` events, and after every event
//! assert the five invariants the design doc names.
//!
//! What this test *does not* do: run the real `approve_staged_push`
//! orchestrator (with GitHub minter, walker, signing). The orchestrator
//! is exercised by the unit tests in `git_push_approve` and
//! `git_push_promote`; here the model writes the same audit-log
//! sequence the orchestrator would write, so the test exercises the
//! state machine + reconcile + reject-blocker composition without
//! pulling in HTTP / signing-key fixtures.

use proptest::prelude::*;
use uuid::Uuid;

use writ::audit::{
    AuditLog, GitPushApproveAttemptOutcome, GitPushApproveAttemptState, GitPushOutcomeRecord,
    GitPushOutcomeResult, GitPushRequestRecord, GitPushResolution, GitPushResolutionRecord,
    PromoteMintAudit,
};
use writ::boot_reconcile::reconcile_pending_approve_attempts;
use writ::core::{
    AgentKind, ApproveAttemptId, Jti, RepoRef, RequestId, SessionId, SessionRecord, UnixMillis,
};
use writ::vm_git::{GitCloneRepo, GitObjectId};

const NUM_PUSHES: usize = 4;
const OPERATOR: &str = "alice";
const APPROVE_REASON: &str = "looks good";
const REJECT_REASON: &str = "no thanks";

/// Outcomes the broker can drive a single approve attempt to. Mirrors
/// the design-doc enumeration of sub-step failure points; the
/// `UncertainOrphan` variant simulates the broker crashing between
/// `mark_attempt_uncertain` (TX2) and the resolving write (TX3) — boot
/// reconcile must surface it but leave it untouched.
#[derive(Clone, Debug)]
enum ApproveOutcome {
    /// Started then left in place — the broker crashed before any
    /// TX2 work landed. Boot reconcile must drive this to
    /// `Resolved(PrePatchFailure { detail = "broker restart" })` on
    /// the next `Crash` event; without this variant invariant 4 has
    /// no data to assert against (every other outcome immediately
    /// transitions past `Started`).
    StartedOrphan,
    /// Pre-mint refusal: walker/plan/prepare declined before any
    /// mint was issued. No mint context recorded on the attempt row.
    MintFailure,
    /// Post-mint, pre-PATCH refusal: mint succeeded but the broker
    /// refused to issue `update_ref`. Mint context captured.
    PostMintPrePatchFailure,
    /// Marked `Uncertain` then left in place — the broker crashed
    /// between TX2 and TX3. Reconcile must NOT advance this row.
    UncertainOrphan,
    /// Marked `Uncertain` then resolved `Succeeded`: the happy path.
    /// Atomically writes a `git_push_resolution(approved)` row carrying
    /// the same mint context.
    UncertainSucceeded,
    /// Marked `Uncertain` then resolved `PostPatchFailure`: the PATCH
    /// was issued but the broker cannot prove GitHub honoured it.
    /// Quarantines the push from reject until manual reconciliation.
    UncertainPostPatchFailure,
}

#[derive(Clone, Debug)]
enum Event {
    /// Record a `git_push_request` + `git_push_outcome(Staged)` pair
    /// for the given push slot (no-op if already staged).
    Stage(usize),
    /// Attempt approve for the given slot, driving to the chosen
    /// outcome. Refused by the DAO if the push is already
    /// resolved / in-flight — the model then silently skips.
    Approve(usize, ApproveOutcome),
    /// Attempt reject for the given slot. Skipped if a blocker is
    /// present or the push is already resolved.
    Reject(usize),
    /// Boot reconcile pass: `Started → Resolved(PrePatchFailure)`
    /// for every non-terminal `Started` row; `Uncertain` rows
    /// untouched.
    Crash,
}

fn arb_outcome() -> impl Strategy<Value = ApproveOutcome> {
    prop_oneof![
        Just(ApproveOutcome::StartedOrphan),
        Just(ApproveOutcome::MintFailure),
        Just(ApproveOutcome::PostMintPrePatchFailure),
        Just(ApproveOutcome::UncertainOrphan),
        Just(ApproveOutcome::UncertainSucceeded),
        Just(ApproveOutcome::UncertainPostPatchFailure),
    ]
}

fn arb_event() -> impl Strategy<Value = Event> {
    let slot = 0usize..NUM_PUSHES;
    prop_oneof![
        slot.clone().prop_map(Event::Stage),
        (slot.clone(), arb_outcome()).prop_map(|(i, o)| Event::Approve(i, o)),
        slot.clone().prop_map(Event::Reject),
        Just(Event::Crash),
    ]
}

fn oid(nibble: char) -> GitObjectId {
    std::iter::repeat_n(nibble, 40)
        .collect::<String>()
        .parse()
        .unwrap()
}

/// The model broker: an in-memory `AuditLog` plus the slot↔request-id
/// mapping the test uses to address pushes. Methods return
/// `Result<(), Refused>` where `Refused` means "audit log declined the
/// transition; skip this event" — the proptest treats refusal as a
/// no-op so traces shrink down to minimal violating sequences.
struct Scenario {
    audit: AuditLog,
    pushes: [Option<RequestId>; NUM_PUSHES],
    session_id: SessionId,
    next_ts_ms: i64,
}

#[derive(Debug)]
struct Refused;

impl Scenario {
    fn new() -> Self {
        let audit = AuditLog::open_in_memory().unwrap();
        let session = SessionRecord {
            session_id: SessionId::new(),
            label: None,
            agent_kind: Some(AgentKind::Claude),
            agent_model: None,
            opened_at: UnixMillis::from_millis(1),
            closed_at: None,
        };
        audit.open_session(&session).unwrap();
        Self {
            audit,
            pushes: Default::default(),
            session_id: session.session_id,
            next_ts_ms: 1_000,
        }
    }

    fn next_ts(&mut self) -> UnixMillis {
        let t = self.next_ts_ms;
        self.next_ts_ms += 1;
        UnixMillis::from_millis(t)
    }

    fn fresh_mint(&mut self) -> PromoteMintAudit {
        let issued = self.next_ts();
        let expires = UnixMillis::from_millis(issued.as_millis() + 3_600_000_i64);
        PromoteMintAudit {
            jti: Jti::from_uuid(Uuid::new_v4()),
            github_app_id: 42,
            issued_at: issued,
            expires_at: expires,
        }
    }

    fn stage(&mut self, slot: usize) {
        if self.pushes[slot].is_some() {
            return;
        }
        let push_id = RequestId::new();
        let received_at = self.next_ts();
        let completed_at = self.next_ts();
        self.audit
            .record_git_push_request(&GitPushRequestRecord {
                push_request_id: push_id,
                session_id: self.session_id,
                received_at,
                repo: GitCloneRepo::new(RepoRef {
                    owner: "o".into(),
                    name: "n".into(),
                })
                .unwrap(),
                branch: "main".parse().unwrap(),
                expected_remote_head: Some(oid('1')),
                new_head: oid('2'),
                correlation_id: None,
            })
            .unwrap();
        self.audit
            .record_git_push_outcome(&GitPushOutcomeRecord {
                push_request_id: push_id,
                completed_at,
                result: GitPushOutcomeResult::Staged,
                github_status: None,
                message: "queued",
            })
            .unwrap();
        self.pushes[slot] = Some(push_id);
    }

    fn approve(&mut self, slot: usize, outcome: &ApproveOutcome) -> Result<(), Refused> {
        let Some(push_id) = self.pushes[slot] else {
            return Err(Refused);
        };
        let attempt_id = ApproveAttemptId::new();
        let started_at = self.next_ts();
        // `start_approve_attempt` is the gate; the DAO refuses if the
        // push is resolved, has an in-flight attempt, or is
        // post-patch-quarantined. Anything past this point is
        // guaranteed-valid by the state machine.
        self.audit
            .start_approve_attempt(attempt_id, push_id, OPERATOR, started_at)
            .map_err(|_| Refused)?;
        match outcome {
            ApproveOutcome::StartedOrphan => {
                // intentionally leave the row in `Started` — the next
                // `Crash` (boot reconcile) is what advances it.
            }
            ApproveOutcome::MintFailure => {
                let now = self.next_ts();
                self.audit
                    .complete_attempt_pre_patch_failure(attempt_id, "mint denied", now)
                    .unwrap();
            }
            ApproveOutcome::PostMintPrePatchFailure => {
                let mint = self.fresh_mint();
                let now = self.next_ts();
                self.audit
                    .complete_attempt_pre_patch_failure_capturing_mint(
                        attempt_id,
                        mint,
                        "walker refused",
                        now,
                    )
                    .unwrap();
            }
            ApproveOutcome::UncertainOrphan => {
                let mint = self.fresh_mint();
                self.audit.mark_attempt_uncertain(attempt_id, mint).unwrap();
            }
            ApproveOutcome::UncertainSucceeded => {
                let mint = self.fresh_mint();
                self.audit.mark_attempt_uncertain(attempt_id, mint).unwrap();
                let now = self.next_ts();
                self.audit
                    .complete_attempt_succeeded(
                        attempt_id,
                        &oid('3'),
                        OPERATOR,
                        APPROVE_REASON,
                        now,
                    )
                    .unwrap();
            }
            ApproveOutcome::UncertainPostPatchFailure => {
                let mint = self.fresh_mint();
                self.audit.mark_attempt_uncertain(attempt_id, mint).unwrap();
                let now = self.next_ts();
                self.audit
                    .complete_attempt_post_patch_failure(attempt_id, "github 500", now)
                    .unwrap();
            }
        }
        Ok(())
    }

    fn reject(&mut self, slot: usize) -> Result<(), Refused> {
        let Some(push_id) = self.pushes[slot] else {
            return Err(Refused);
        };
        if self
            .audit
            .reject_blocker_for_push(push_id)
            .unwrap()
            .is_some()
        {
            return Err(Refused);
        }
        let already_resolved = self
            .audit
            .get_git_push(push_id)
            .unwrap()
            .and_then(|e| e.resolution)
            .is_some();
        if already_resolved {
            return Err(Refused);
        }
        let now = self.next_ts();
        self.audit
            .record_git_push_resolution(&GitPushResolutionRecord {
                push_request_id: push_id,
                decided_at: now,
                decision: GitPushResolution::Rejected,
                operator: OPERATOR,
                reason: REJECT_REASON,
            })
            .map_err(|_| Refused)
    }

    fn crash(&mut self) {
        let now = self.next_ts();
        reconcile_pending_approve_attempts(&self.audit, now).unwrap();
    }

    /// Counts the resolution rows currently in the DB by walking the
    /// pushes the test created. Used for invariant 5.
    fn count_resolutions(&self) -> u32 {
        let mut count = 0u32;
        for push_opt in &self.pushes {
            let Some(push_id) = push_opt else { continue };
            if self
                .audit
                .get_git_push(*push_id)
                .unwrap()
                .and_then(|e| e.resolution)
                .is_some()
            {
                count += 1;
            }
        }
        count
    }

    /// Check invariants 1–4 against the current audit state. The `last_was_crash`
    /// flag gates invariant 4 (which only holds immediately after a
    /// boot-reconcile pass — Started rows can validly appear once new
    /// approve events run afterwards).
    fn check_invariants(&self, last_was_crash: bool) -> Result<(), String> {
        for push_opt in &self.pushes {
            let Some(push_id) = push_opt else { continue };
            let attempts = self
                .audit
                .approve_attempts_for_push(*push_id)
                .map_err(|e| e.to_string())?;

            // Invariant 1: at most one `Resolved(Succeeded)` attempt per push.
            let succeeded: Vec<_> = attempts
                .iter()
                .filter(|a| {
                    matches!(
                        &a.state,
                        GitPushApproveAttemptState::Resolved {
                            outcome: GitPushApproveAttemptOutcome::Succeeded { .. },
                            ..
                        }
                    )
                })
                .collect();
            if succeeded.len() > 1 {
                return Err(format!(
                    "invariant 1: {} Succeeded attempts for push {}",
                    succeeded.len(),
                    push_id
                ));
            }

            let entry = self
                .audit
                .get_git_push(*push_id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("push {push_id} missing from audit"))?;

            // Invariant 2: if any attempt is `Succeeded`, then a
            // `git_push_resolution(approved)` row exists with mint_jti
            // matching the attempt's recorded mint.
            if let Some(s) = succeeded.first() {
                let GitPushApproveAttemptState::Resolved {
                    mint: attempt_mint, ..
                } = &s.state
                else {
                    unreachable!()
                };
                let attempt_mint = attempt_mint
                    .as_ref()
                    .ok_or_else(|| format!("invariant 2: Succeeded missing mint for {push_id}"))?;
                let resolution = entry.resolution.as_ref().ok_or_else(|| {
                    format!("invariant 2: Succeeded without resolution row for {push_id}")
                })?;
                let GitPushResolution::Approved(res_mint) = &resolution.decision else {
                    return Err(format!(
                        "invariant 2: Succeeded but resolution is Rejected for {push_id}"
                    ));
                };
                if res_mint.jti != attempt_mint.jti {
                    return Err(format!(
                        "invariant 2: jti mismatch for {push_id}: attempt={} resolution={}",
                        attempt_mint.jti, res_mint.jti
                    ));
                }
            }

            // Invariant 3: if a `git_push_resolution(rejected)` row exists,
            // then no attempt is `Uncertain`, `Succeeded`, or `PostPatchFailure`.
            if let Some(res) = entry.resolution.as_ref()
                && matches!(res.decision, GitPushResolution::Rejected)
            {
                for a in &attempts {
                    match &a.state {
                        GitPushApproveAttemptState::Uncertain { .. } => {
                            return Err(format!(
                                "invariant 3: Uncertain attempt alongside Rejected for {push_id}"
                            ));
                        }
                        GitPushApproveAttemptState::Resolved { outcome, .. } => match outcome {
                            GitPushApproveAttemptOutcome::Succeeded { .. } => {
                                return Err(format!(
                                    "invariant 3: Succeeded attempt alongside Rejected for {push_id}"
                                ));
                            }
                            GitPushApproveAttemptOutcome::PostPatchFailure { .. } => {
                                return Err(format!(
                                    "invariant 3: PostPatchFailure attempt alongside Rejected for {push_id}"
                                ));
                            }
                            GitPushApproveAttemptOutcome::PrePatchFailure { .. } => {}
                        },
                        GitPushApproveAttemptState::Started => {}
                    }
                }
            }

            // Invariant 4: immediately after a boot-reconcile pass,
            // no attempt is in `Started`.
            if last_was_crash {
                for a in &attempts {
                    if matches!(a.state, GitPushApproveAttemptState::Started) {
                        return Err(format!(
                            "invariant 4: Started attempt {} survived crash for push {}",
                            a.attempt_id, push_id
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

proptest! {
    /// Drive a randomly generated trace and assert all five
    /// invariants. Invariants 1–4 are checked after every step;
    /// invariant 5 is checked at the end of the trace (it's a global
    /// counter relation, not a per-step property).
    #[test]
    fn approve_state_machine_invariants_hold_under_random_traces(
        events in proptest::collection::vec(arb_event(), 0..40),
    ) {
        let mut scenario = Scenario::new();
        let mut submitted_decisions: u32 = 0;
        for ev in &events {
            match ev {
                Event::Stage(i) => scenario.stage(*i),
                Event::Approve(i, o) => {
                    if scenario.approve(*i, o).is_ok() {
                        submitted_decisions += 1;
                    }
                }
                Event::Reject(i) => {
                    if scenario.reject(*i).is_ok() {
                        submitted_decisions += 1;
                    }
                }
                Event::Crash => scenario.crash(),
            }
            let last_was_crash = matches!(ev, Event::Crash);
            if let Err(violation) = scenario.check_invariants(last_was_crash) {
                return Err(TestCaseError::fail(violation));
            }
        }
        // Invariant 5: total resolution rows ≤ total operator decisions submitted.
        let total_resolutions = scenario.count_resolutions();
        prop_assert!(
            total_resolutions <= submitted_decisions,
            "invariant 5: {total_resolutions} resolutions exceed {submitted_decisions} submitted decisions",
        );
    }
}
