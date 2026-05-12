//! Property-based tests for the core data model. The invariant here is
//! simply "any core value round-trips cleanly through JSON"; it's a
//! one-line assertion but it catches a surprising number of serde
//! mistakes (typos in `rename_all`, adjacent-tag clashes, etc.).

use proptest::prelude::*;
use writ::agent_plan::{
    AbortSubmission, AddendumSubmission, CorrelationId, DecisionOutcome, DecisionView,
    MAX_CORRELATION_ID_BYTES, MIN_CORRELATION_ID_BYTES, PLAN_PROMPT_SEPARATOR, PlanAbortReason,
    PlanBody, PlanCreated, PlanFeedback, PlanId, PlanRouteAction, PlanSubmission, PlanView,
    ReviewSubmission, Stage, Verdict, compose_implementer_prompt,
    route_permitted_by_stage_and_decision,
};
use writ::agent_run::{AgentPrompt, AgentRunId};
use writ::audit::{
    AgentRunAuditRecord, AuditLog, GitPushRequestRecord, PlanSubmissionRecord, PreMintRecord,
};
use writ::core::{
    AgentKind, CapabilityRequest, CredentialGrant, GitHubAccess, GitHubGrantedScope,
    GitHubPermissions, GitHubRequest, GrantedScope, Jti, MetadataAccess, PolicyDecision, RepoRef,
    RequestId, SessionId, SessionRecord, TtlSeconds, UnixMillis,
};
use writ::policy::{PolicyConfig, decide};
use writ::vm_git::{GitBranchName, GitCloneRepo, GitObjectId};

fn arb_repo() -> impl Strategy<Value = RepoRef> {
    ("[a-zA-Z0-9_-]{1,32}", "[a-zA-Z0-9_.-]{1,32}")
        .prop_map(|(owner, name)| RepoRef { owner, name })
}

fn arb_access() -> impl Strategy<Value = GitHubAccess> {
    prop_oneof![Just(GitHubAccess::Read), Just(GitHubAccess::Write)]
}

fn arb_github_request() -> impl Strategy<Value = GitHubRequest> {
    prop_oneof![
        (arb_access(), arb_repo())
            .prop_map(|(access, repo)| GitHubRequest::Contents { access, repo }),
        (arb_access(), arb_repo())
            .prop_map(|(access, repo)| GitHubRequest::Issues { access, repo }),
        (arb_access(), arb_repo())
            .prop_map(|(access, repo)| GitHubRequest::PullRequests { access, repo }),
        arb_repo().prop_map(|repo| GitHubRequest::Metadata { repo }),
    ]
}

fn arb_request() -> impl Strategy<Value = CapabilityRequest> {
    arb_github_request().prop_map(CapabilityRequest::GitHub)
}

fn arb_permissions() -> impl Strategy<Value = GitHubPermissions> {
    (
        prop::option::of(arb_access()),
        prop::option::of(arb_access()),
        prop::option::of(arb_access()),
        prop::option::of(Just(MetadataAccess::Read)),
    )
        .prop_map(
            |(contents, issues, pull_requests, metadata)| GitHubPermissions {
                contents,
                issues,
                pull_requests,
                metadata,
            },
        )
}

fn arb_scope() -> impl Strategy<Value = GrantedScope> {
    (arb_repo(), arb_permissions()).prop_map(|(repository, permissions)| {
        GrantedScope::GitHub(GitHubGrantedScope {
            repository,
            permissions,
        })
    })
}

fn arb_ttl() -> impl Strategy<Value = TtlSeconds> {
    (1i64..=3600).prop_map(|s| TtlSeconds::new(s).expect("1..=3600 is valid"))
}

fn arb_decision() -> impl Strategy<Value = PolicyDecision> {
    prop_oneof![
        (arb_scope(), arb_ttl()).prop_map(|(scope, ttl)| PolicyDecision::Grant { scope, ttl }),
        "[^\u{0}]{0,128}".prop_map(|reason| PolicyDecision::Deny { reason }),
    ]
}

fn arb_grant() -> impl Strategy<Value = CredentialGrant> {
    (
        arb_scope(),
        prop::option::of(0u64..1_000_000),
        0i64..10_000_000_000,
        1i64..=3600,
    )
        .prop_map(|(scope, github_app_id, issued, ttl)| CredentialGrant {
            jti: Jti::new(),
            request_id: RequestId::new(),
            session_id: SessionId::new(),
            github_app_id,
            scope,
            issued_at: UnixMillis::from_millis(issued),
            expires_at: UnixMillis::from_millis(issued + ttl),
        })
}

fn arb_session() -> impl Strategy<Value = SessionRecord> {
    (
        prop::option::of("[a-zA-Z0-9 ]{0,64}"),
        prop::option::of(prop_oneof![Just(AgentKind::Claude), Just(AgentKind::Codex)]),
        prop::option::of("[a-zA-Z0-9.-]{0,64}"),
        0i64..10_000_000_000,
        prop::option::of(0i64..10_000_000_000),
    )
        .prop_map(
            |(label, agent_kind, agent_model, opened, closed)| SessionRecord {
                session_id: SessionId::new(),
                label,
                agent_kind,
                agent_model,
                opened_at: UnixMillis::from_millis(opened),
                closed_at: closed.map(UnixMillis::from_millis),
            },
        )
}

proptest! {
    #[test]
    fn request_roundtrips_through_json(req in arb_request()) {
        let j = serde_json::to_string(&req).unwrap();
        let back: CapabilityRequest = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, req);
    }

    #[test]
    fn decision_roundtrips_through_json(d in arb_decision()) {
        let j = serde_json::to_string(&d).unwrap();
        let back: PolicyDecision = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, d);
    }

    #[test]
    fn grant_roundtrips_through_json(g in arb_grant()) {
        let j = serde_json::to_string(&g).unwrap();
        let back: CredentialGrant = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, g);
    }

    #[test]
    fn session_roundtrips_through_json(s in arb_session()) {
        let j = serde_json::to_string(&s).unwrap();
        let back: SessionRecord = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, s);
    }

    #[test]
    fn repo_ref_roundtrips(repo in arb_repo()) {
        let rendered = repo.to_string();
        let parsed: RepoRef = rendered.parse().unwrap();
        prop_assert_eq!(parsed, repo);
    }

    /// Oracle: `matches` is exactly equality on the canonical projection.
    /// Anyone touching the GitHub boundary can substitute one for the
    /// other; the only reason to keep `matches` around is readability at
    /// the call site.
    #[test]
    fn matches_iff_canonical_eq(a in arb_repo(), b in arb_repo()) {
        prop_assert_eq!(a.matches(&b), a.canonicalise() == b.canonicalise());
    }

    /// Any write request whose repo is on the allowlist is granted; any
    /// write whose repo is not is denied. This is the whole v1 policy.
    #[test]
    fn policy_write_is_granted_iff_repo_is_writable(
        req in arb_github_request(),
        writable in prop::collection::vec(arb_repo(), 0..5),
    ) {
        let policy = PolicyConfig {
            writable_repos: writable.clone(),
            default_ttl: TtlSeconds::new(300).unwrap(),
        };
        let wrapped = CapabilityRequest::GitHub(req.clone());
        let is_write = matches!(
            req,
            GitHubRequest::Contents { access: GitHubAccess::Write, .. }
                | GitHubRequest::Issues { access: GitHubAccess::Write, .. }
                | GitHubRequest::PullRequests { access: GitHubAccess::Write, .. }
        );
        let on_allowlist = writable.iter().any(|r| r.matches(req.repo()));

        match decide(&wrapped, &policy) {
            PolicyDecision::Grant { .. } => {
                if is_write {
                    prop_assert!(on_allowlist, "granted write but repo not on allowlist: {req:?}");
                }
            }
            PolicyDecision::Deny { .. } => {
                prop_assert!(is_write && !on_allowlist, "denied non-write or allowlisted repo: {req:?}");
            }
        }
    }

    /// Every grant includes `metadata: read` (GitHub requires it on every
    /// installation token) and the repo on the grant matches the requested repo.
    #[test]
    fn grants_include_metadata_and_match_repo(
        req in arb_github_request(),
    ) {
        let policy = PolicyConfig {
            writable_repos: vec![req.repo().clone()],
            default_ttl: TtlSeconds::new(300).unwrap(),
        };
        let wrapped = CapabilityRequest::GitHub(req.clone());
        match decide(&wrapped, &policy) {
            PolicyDecision::Grant { scope: GrantedScope::GitHub(s), .. } => {
                prop_assert_eq!(s.repository, req.repo().clone());
                prop_assert_eq!(s.permissions.metadata, Some(MetadataAccess::Read));
            }
            PolicyDecision::Deny { reason } => prop_assert!(false, "unexpectedly denied: {reason}"),
        }
    }

    /// `record_grant ∘ record_pre_mint ∘ decide` accepts iff `decide`
    /// returned `Grant`. The property exercises the full audit chain at
    /// once: `record_pre_mint` is expected to accept any decision `decide`
    /// produces (its output is structurally valid by construction), and
    /// the trailing `record_grant` must succeed for `Grant` decisions and
    /// fail for `Deny` ones.
    #[test]
    fn audit_chain_accepts_grant_iff_decide_grants(
        req in arb_github_request(),
        writable in prop::collection::vec(arb_repo(), 0..5),
        ttl in arb_ttl(),
        github_app_id in 0u64..1_000_000,
    ) {
        let policy = PolicyConfig {
            writable_repos: writable,
            default_ttl: ttl,
        };
        let cap_req = CapabilityRequest::GitHub(req.clone());
        let decision = decide(&cap_req, &policy);

        let log = AuditLog::open_in_memory().unwrap();
        let session = SessionRecord {
            session_id: SessionId::new(),
            label: None,
            agent_kind: None,
            agent_model: None,
            opened_at: UnixMillis::from_millis(0),
            closed_at: None,
        };
        log.open_session(&session).unwrap();

        let request_id = RequestId::new();
        let pre_mint = log.record_pre_mint(&PreMintRecord {
            request_id,
            session_id: session.session_id,
            received_at: UnixMillis::from_millis(0),
            request: &cap_req,
            decision: &decision,
        });
        prop_assert!(
            pre_mint.is_ok(),
            "decide produced a decision record_pre_mint rejected: req={req:?} decision={decision:?} err={pre_mint:?}",
        );

        match &decision {
            PolicyDecision::Grant { scope, ttl: granted_ttl } => {
                let lifetime_ms = granted_ttl.as_i64().saturating_mul(1000);
                let grant = CredentialGrant {
                    jti: Jti::new(),
                    request_id,
                    session_id: session.session_id,
                    github_app_id: Some(github_app_id),
                    scope: scope.clone(),
                    issued_at: UnixMillis::from_millis(0),
                    expires_at: UnixMillis::from_millis(lifetime_ms),
                };
                let result = log.record_grant(&grant);
                prop_assert!(
                    result.is_ok(),
                    "Grant decision but record_grant failed: req={req:?} scope={scope:?} err={result:?}",
                );
            }
            PolicyDecision::Deny { .. } => {
                // Any grant attempt against a Deny pre-mint row must fail.
                // Scope is irrelevant: record_grant rejects on the recorded
                // decision before checking the scope.
                let bogus = CredentialGrant {
                    jti: Jti::new(),
                    request_id,
                    session_id: session.session_id,
                    github_app_id: Some(github_app_id),
                    scope: GrantedScope::GitHub(GitHubGrantedScope {
                        repository: req.repo().clone(),
                        permissions: GitHubPermissions::default(),
                    }),
                    issued_at: UnixMillis::from_millis(0),
                    expires_at: UnixMillis::from_millis(1_000),
                };
                let result = log.record_grant(&bogus);
                prop_assert!(
                    result.is_err(),
                    "Deny decision but record_grant accepted: req={req:?} grant={bogus:?}",
                );
            }
        }
    }

    /// `record_pre_mint` rejects any Grant decision whose scope isn't
    /// structurally compatible with the request, regardless of which
    /// `GitHubRequest` variant is involved. The DAO previously had a
    /// single hand-rolled unit test for this; the property pins it for
    /// every variant against an oracle re-implementation of the rules.
    #[test]
    fn record_pre_mint_agrees_with_scope_authorisation_oracle(
        req in arb_github_request(),
        // Bias scope.repository to the request's repo half the time, so
        // the `repo matches` branch gets exercised — random unrelated
        // repos almost never collide.
        copy_repo in any::<bool>(),
        scope_repo in arb_repo(),
        permissions in arb_permissions(),
    ) {
        let log = AuditLog::open_in_memory().unwrap();
        let session = SessionRecord {
            session_id: SessionId::new(),
            label: None,
            agent_kind: None,
            agent_model: None,
            opened_at: UnixMillis::from_millis(0),
            closed_at: None,
        };
        log.open_session(&session).unwrap();

        let scope_repo = if copy_repo { req.repo().clone() } else { scope_repo };
        let github_scope = GitHubGrantedScope { repository: scope_repo, permissions };
        let cap_req = CapabilityRequest::GitHub(req.clone());
        let decision = PolicyDecision::Grant {
            scope: GrantedScope::GitHub(github_scope.clone()),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        let result = log.record_pre_mint(&PreMintRecord {
            request_id: RequestId::new(),
            session_id: session.session_id,
            received_at: UnixMillis::from_millis(0),
            request: &cap_req,
            decision: &decision,
        });

        let expected = oracle_scope_authorises_request(&req, &github_scope);
        prop_assert_eq!(
            result.is_ok(),
            expected,
            "req={:?} scope={:?} actual={:?}",
            req,
            github_scope,
            result,
        );
    }
}

/// Mirror of `audit::grant::scope_authorised_by_request` (private to that
/// module). The audit-layer rule is structural: matching repo, every
/// permission slot the request didn't ask for must be `None`, and the slot
/// it did ask for must equal the requested access. Metadata is allowed to
/// be either `None` or `Some(Read)` independent of the request.
fn oracle_scope_authorises_request(req: &GitHubRequest, scope: &GitHubGrantedScope) -> bool {
    if &scope.repository != req.repo() {
        return false;
    }
    match scope.permissions.metadata {
        None | Some(MetadataAccess::Read) => {}
    }
    match req {
        GitHubRequest::Metadata { .. } => {
            scope.permissions.contents.is_none()
                && scope.permissions.issues.is_none()
                && scope.permissions.pull_requests.is_none()
        }
        GitHubRequest::Contents { access, .. } => {
            scope.permissions.contents == Some(*access)
                && scope.permissions.issues.is_none()
                && scope.permissions.pull_requests.is_none()
        }
        GitHubRequest::Issues { access, .. } => {
            scope.permissions.issues == Some(*access)
                && scope.permissions.contents.is_none()
                && scope.permissions.pull_requests.is_none()
        }
        GitHubRequest::PullRequests { access, .. } => {
            scope.permissions.pull_requests == Some(*access)
                && scope.permissions.contents.is_none()
                && scope.permissions.issues.is_none()
        }
    }
}

// ---------------------------------------------------------------------------
// agent_plan: pure types for the plan/review/decide/execute lifecycle.
//
// The inline unit tests in `src/agent_plan.rs` pin individual examples and
// the exhaustive route-authorisation cube. These properties extend that by
// fuzzing over the full input space — the gospel principle is "always write
// the property-based tests", and several of these caught their own
// candidate bugs during authoring (e.g. that the `[^...]` regex emits
// multi-byte codepoints whose continuation bytes the byte-level class
// check must still reject).
// ---------------------------------------------------------------------------

fn arb_correlation_id() -> impl Strategy<Value = CorrelationId> {
    "[A-Za-z0-9_-]{1,64}"
        .prop_map(|s| CorrelationId::try_new(s).expect("regex produces only valid correlation ids"))
}

fn arb_plan_body() -> impl Strategy<Value = PlanBody> {
    // Bounded so per-case work stays cheap; the `MAX_PLAN_BODY_BYTES`
    // boundary is pinned in the inline unit tests. NULs are excluded
    // because the newtype rejects them at the parse boundary to match
    // the audit-schema CHECK on `plan.body`.
    "[^\\x00]{1,256}"
        .prop_map(|s| PlanBody::try_new(s).expect("regex produces non-empty NUL-free bounded body"))
}

fn arb_plan_feedback() -> impl Strategy<Value = PlanFeedback> {
    ".{1,128}"
        .prop_map(|s| PlanFeedback::try_new(s).expect("regex produces non-empty bounded body"))
}

fn arb_plan_abort_reason() -> impl Strategy<Value = PlanAbortReason> {
    ".{1,128}"
        .prop_map(|s| PlanAbortReason::try_new(s).expect("regex produces non-empty bounded body"))
}

fn arb_stage() -> impl Strategy<Value = Stage> {
    prop_oneof![Just(Stage::Plan), Just(Stage::Review), Just(Stage::Execute)]
}

fn arb_verdict() -> impl Strategy<Value = Verdict> {
    prop_oneof![
        Just(Verdict::Approve),
        Just(Verdict::RequestChanges),
        Just(Verdict::Reject),
    ]
}

fn arb_decision_outcome() -> impl Strategy<Value = DecisionOutcome> {
    prop_oneof![
        Just(DecisionOutcome::Accepted),
        Just(DecisionOutcome::RejectedRestart),
    ]
}

fn arb_plan_route_action() -> impl Strategy<Value = PlanRouteAction> {
    prop_oneof![
        Just(PlanRouteAction::SubmitPlan),
        Just(PlanRouteAction::ReadPlan),
        Just(PlanRouteAction::SubmitReview),
        Just(PlanRouteAction::SubmitAddendum),
        Just(PlanRouteAction::SubmitAbort),
    ]
}

fn arb_plan_id() -> impl Strategy<Value = PlanId> {
    any::<u128>().prop_map(|n| PlanId::from_uuid(uuid::Uuid::from_u128(n)))
}

fn arb_agent_run_id() -> impl Strategy<Value = AgentRunId> {
    any::<u128>().prop_map(|n| AgentRunId::from_uuid(uuid::Uuid::from_u128(n)))
}

fn arb_decision_view() -> impl Strategy<Value = DecisionView> {
    (arb_decision_outcome(), 0i64..10_000_000_000).prop_map(|(outcome, decided_at)| DecisionView {
        outcome,
        decided_at: writ::core::UnixMillis::from_millis(decided_at),
    })
}

/// Oracle re-implementation of the route-authorisation rules from
/// §"Protocol additions" in `docs/plans/2026-05-11-agent-plans.md`, written
/// without consulting `route_permitted_by_stage_and_decision`. When both
/// implementations agree on every cube cell we know the gate faithfully
/// encodes the spec.
fn oracle_route_allowed(
    action: PlanRouteAction,
    stage: Stage,
    decision: Option<DecisionOutcome>,
) -> bool {
    let accepted = decision == Some(DecisionOutcome::Accepted);
    match action {
        PlanRouteAction::SubmitPlan => stage == Stage::Plan,
        PlanRouteAction::ReadPlan => match stage {
            Stage::Plan => false,
            Stage::Review => true,
            Stage::Execute => accepted,
        },
        PlanRouteAction::SubmitReview => stage == Stage::Review,
        PlanRouteAction::SubmitAddendum => stage == Stage::Execute && accepted,
        PlanRouteAction::SubmitAbort => stage == Stage::Execute,
    }
}

proptest! {
    /// Any valid `CorrelationId` survives the `try_new(as_str())` and
    /// JSON round-trips, and its on-wire form is a bare string equal to
    /// `as_str` (no escaping needed since the class excludes JSON's
    /// reserved characters).
    #[test]
    fn correlation_id_idempotent_and_roundtrips_through_json(c in arb_correlation_id()) {
        let again = CorrelationId::try_new(c.as_str()).unwrap();
        prop_assert_eq!(&again, &c);

        let j = serde_json::to_string(&c).unwrap();
        prop_assert_eq!(&j, &format!("\"{}\"", c.as_str()));
        let back: CorrelationId = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, c);
    }

    /// Any string with a byte outside `[A-Za-z0-9_-]` is rejected,
    /// regardless of where the offending character sits. Pins the
    /// byte-level enforcement against the full Unicode complement of
    /// the class.
    #[test]
    fn correlation_id_rejects_chars_outside_class(
        prefix in "[A-Za-z0-9_-]{0,30}",
        bad in "[^A-Za-z0-9_-]",
        suffix in "[A-Za-z0-9_-]{0,30}",
    ) {
        let id = format!("{prefix}{bad}{suffix}");
        // Outside the parser's length window the rejection reason is
        // length, not the bad byte — uninteresting for this property.
        prop_assume!((MIN_CORRELATION_ID_BYTES..=MAX_CORRELATION_ID_BYTES).contains(&id.len()));
        prop_assert!(
            CorrelationId::try_new(&id).is_err(),
            "expected {:?} to be rejected for a non-class byte",
            id,
        );
    }

    /// `PlanBody` round-trips through JSON for any valid body.
    #[test]
    fn plan_body_roundtrips_through_json(body in arb_plan_body()) {
        let j = serde_json::to_string(&body).unwrap();
        let back: PlanBody = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, body);
    }

    /// `PlanFeedback` round-trips through JSON.
    #[test]
    fn plan_feedback_roundtrips_through_json(fb in arb_plan_feedback()) {
        let j = serde_json::to_string(&fb).unwrap();
        let back: PlanFeedback = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, fb);
    }

    /// `PlanAbortReason` round-trips through JSON.
    #[test]
    fn plan_abort_reason_roundtrips_through_json(r in arb_plan_abort_reason()) {
        let j = serde_json::to_string(&r).unwrap();
        let back: PlanAbortReason = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, r);
    }

    /// `Stage`: `as_str`, `FromStr`, `Display`, and JSON form all agree.
    /// If a new variant is added, this property fails until every
    /// projection is wired up.
    #[test]
    fn stage_all_text_projections_agree(s in arb_stage()) {
        prop_assert_eq!(s.as_str().parse::<Stage>().unwrap(), s);
        prop_assert_eq!(s.to_string(), s.as_str());
        let j = serde_json::to_string(&s).unwrap();
        prop_assert_eq!(&j, &format!("\"{}\"", s.as_str()));
        let back: Stage = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, s);
    }

    /// `Verdict`: as above.
    #[test]
    fn verdict_all_text_projections_agree(v in arb_verdict()) {
        prop_assert_eq!(v.as_str().parse::<Verdict>().unwrap(), v);
        prop_assert_eq!(v.to_string(), v.as_str());
        let j = serde_json::to_string(&v).unwrap();
        prop_assert_eq!(&j, &format!("\"{}\"", v.as_str()));
        let back: Verdict = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, v);
    }

    /// `DecisionOutcome`: as above.
    #[test]
    fn decision_outcome_all_text_projections_agree(d in arb_decision_outcome()) {
        prop_assert_eq!(d.as_str().parse::<DecisionOutcome>().unwrap(), d);
        prop_assert_eq!(d.to_string(), d.as_str());
        let j = serde_json::to_string(&d).unwrap();
        prop_assert_eq!(&j, &format!("\"{}\"", d.as_str()));
        let back: DecisionOutcome = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, d);
    }

    /// `compose_implementer_prompt` is a structural concatenation: the
    /// result starts with the feature prompt, ends with the plan body,
    /// contains the separator between them, and has byte length equal
    /// to the sum of the three parts.
    #[test]
    fn compose_implementer_prompt_three_segments(
        feature_text in "[ -~]{1,1024}",
        plan_text in "[ -~]{1,1024}",
    ) {
        let feature = AgentPrompt::try_new(feature_text.clone()).unwrap();
        let plan = PlanBody::try_new(plan_text.clone()).unwrap();
        let combined = compose_implementer_prompt(&feature, &plan).unwrap();

        let s = combined.as_str();
        prop_assert!(s.starts_with(&feature_text), "missing prefix");
        prop_assert!(s.ends_with(&plan_text), "missing suffix");
        prop_assert!(s.contains(PLAN_PROMPT_SEPARATOR), "missing separator");
        prop_assert_eq!(
            s.len(),
            feature_text.len() + PLAN_PROMPT_SEPARATOR.len() + plan_text.len(),
        );
    }

    /// `route_permitted_by_stage_and_decision` agrees with the oracle on
    /// every `(action, stage, decision)` triple. The inline unit test
    /// enumerates the same cube; this property generates additionally so
    /// a future variant added to either `PlanRouteAction` or `Stage`
    /// gets picked up by *both* without further plumbing.
    #[test]
    fn route_authorisation_agrees_with_oracle(
        action in arb_plan_route_action(),
        stage in arb_stage(),
        decision in prop::option::of(arb_decision_outcome()),
    ) {
        let expected = oracle_route_allowed(action, stage, decision);
        let actual = route_permitted_by_stage_and_decision(action, stage, decision);
        prop_assert_eq!(
            actual.is_ok(),
            expected,
            "({:?}, {:?}, {:?}): expected {}, got {:?}",
            action,
            stage,
            decision,
            expected,
            actual,
        );
    }

    /// Wire-format: `PlanSubmission` round-trips through JSON.
    #[test]
    fn plan_submission_roundtrips(
        agent_run_id in arb_agent_run_id(),
        body in arb_plan_body(),
    ) {
        let m = PlanSubmission { agent_run_id, body };
        let j = serde_json::to_string(&m).unwrap();
        let back: PlanSubmission = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, m);
    }

    /// Wire-format: `PlanCreated` is `{ "plan_id": "<uuid>" }`. Picks up
    /// any `serde(transparent)` mistake on `PlanId` and any rename slip
    /// on the field name.
    #[test]
    fn plan_created_roundtrips(plan_id in arb_plan_id()) {
        let m = PlanCreated { plan_id };
        let j = serde_json::to_string(&m).unwrap();
        let back: PlanCreated = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, m);
        prop_assert_eq!(&j, &format!("{{\"plan_id\":\"{}\"}}", plan_id));
    }

    /// Wire-format: `ReviewSubmission` round-trips with and without the
    /// optional feedback field, and the absent case omits the key
    /// entirely (per `skip_serializing_if = "Option::is_none"`).
    #[test]
    fn review_submission_roundtrips(
        verdict in arb_verdict(),
        feedback in prop::option::of(arb_plan_feedback()),
    ) {
        let r = ReviewSubmission { verdict, feedback };
        let j = serde_json::to_string(&r).unwrap();
        if r.feedback.is_none() {
            prop_assert!(
                !j.contains("feedback"),
                "skip_serializing_if violated: {}",
                j,
            );
        }
        let back: ReviewSubmission = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, r);
    }

    /// Wire-format: `AddendumSubmission` round-trips through JSON.
    #[test]
    fn addendum_submission_roundtrips(body in arb_plan_body()) {
        let m = AddendumSubmission { body };
        let j = serde_json::to_string(&m).unwrap();
        let back: AddendumSubmission = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, m);
    }

    /// Wire-format: `AbortSubmission` round-trips through JSON.
    #[test]
    fn abort_submission_roundtrips(reason in arb_plan_abort_reason()) {
        let m = AbortSubmission { reason };
        let j = serde_json::to_string(&m).unwrap();
        let back: AbortSubmission = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, m);
    }

    /// Wire-format: `PlanView` round-trips with and without a decision,
    /// across freshly-generated `PlanId` / `AgentRunId` / prompt
    /// content. The `decision` key is always present per the spec
    /// (§"Protocol additions": `decision: { ... } | null`) — when the
    /// plan is still under review it serialises as explicit `null`,
    /// never an absent key.
    #[test]
    fn plan_view_roundtrips(
        plan_id in arb_plan_id(),
        run_id in arb_agent_run_id(),
        body in arb_plan_body(),
        prompt_text in "[ -~]{1,1024}",
        decision in prop::option::of(arb_decision_view()),
    ) {
        let view = PlanView {
            plan_id,
            body,
            originating_run_id: run_id,
            originating_prompt: AgentPrompt::try_new(prompt_text).unwrap(),
            decision,
        };
        let j = serde_json::to_string(&view).unwrap();
        let back: PlanView = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(&back, &view);

        // The `decision` key is always present; if `None`, it must be
        // explicit `null` rather than an absent key.
        let value: serde_json::Value = serde_json::from_str(&j).unwrap();
        let decision_value = value.get("decision");
        prop_assert!(decision_value.is_some(), "decision key absent: {j}");
        if view.decision.is_none() {
            prop_assert_eq!(
                decision_value,
                Some(&serde_json::Value::Null),
                "decision must be explicit null when absent: {}",
                j,
            );
        }
    }

    /// Any valid `CorrelationId` round-trips through the `agent_run`
    /// audit DAO. The DAO's CHECK constraint and the `CorrelationId`
    /// newtype agree on the allowed character class, so writes through
    /// the parse-don't-validate boundary must not be rejected at the DB.
    #[test]
    fn agent_run_correlation_id_roundtrips_through_audit_log(
        c in arb_correlation_id(),
    ) {
        let log = AuditLog::open_in_memory().unwrap();
        let session = SessionRecord {
            session_id: SessionId::new(),
            label: None,
            agent_kind: None,
            agent_model: None,
            opened_at: UnixMillis::from_millis(0),
            closed_at: None,
        };
        log.open_session(&session).unwrap();
        let run_id = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id,
            session_id: session.session_id,
            requested_at: UnixMillis::from_millis(1),
            agent_kind: AgentKind::Claude,
            prompt: AgentPrompt::try_new("p").unwrap().summary(),
            correlation_id: Some(c.clone()),
        })
        .unwrap();
        let entry = log.get_agent_run(run_id).unwrap().unwrap();
        prop_assert_eq!(entry.correlation_id, Some(c));
    }

    /// Any valid `PlanBody` round-trips through the plan audit DAO. The
    /// DAO computes `body_sha256` on insert, so this also exercises the
    /// `sha256_hex` projection — a body that survives a roundtrip is
    /// one whose stored digest agrees with a fresh recompute (see the
    /// belt-and-braces check in `plan_from_row`).
    #[test]
    fn plan_body_roundtrips_through_audit_log(body in arb_plan_body()) {
        let log = AuditLog::open_in_memory().unwrap();
        let session = SessionRecord {
            session_id: SessionId::new(),
            label: None,
            agent_kind: None,
            agent_model: None,
            opened_at: UnixMillis::from_millis(0),
            closed_at: None,
        };
        log.open_session(&session).unwrap();
        let run_id = AgentRunId::new();
        log.record_agent_run(&AgentRunAuditRecord {
            run_id,
            session_id: session.session_id,
            requested_at: UnixMillis::from_millis(1),
            agent_kind: AgentKind::Claude,
            prompt: AgentPrompt::try_new("p").unwrap().summary(),
            correlation_id: None,
        })
        .unwrap();

        let plan_id = PlanId::new();
        let record = PlanSubmissionRecord {
            plan_id,
            agent_run_id: run_id,
            submitted_at: UnixMillis::from_millis(2),
            body,
        };
        log.record_plan_submission(&record).unwrap();
        let entry = log.get_plan(plan_id).unwrap().unwrap();
        prop_assert_eq!(entry, record);
    }

    /// Same invariant for the git push request DAO.
    #[test]
    fn git_push_request_correlation_id_roundtrips_through_audit_log(
        c in arb_correlation_id(),
    ) {
        let log = AuditLog::open_in_memory().unwrap();
        let session = SessionRecord {
            session_id: SessionId::new(),
            label: None,
            agent_kind: None,
            agent_model: None,
            opened_at: UnixMillis::from_millis(0),
            closed_at: None,
        };
        log.open_session(&session).unwrap();
        let push_request_id = RequestId::new();
        let repo = GitCloneRepo::new(RepoRef {
            owner: "o".into(),
            name: "n".into(),
        })
        .unwrap();
        let branch: GitBranchName = "main".parse().unwrap();
        let new_head: GitObjectId = "a".repeat(40).parse().unwrap();
        log.record_git_push_request(&GitPushRequestRecord {
            push_request_id,
            session_id: session.session_id,
            received_at: UnixMillis::from_millis(1),
            repo,
            branch,
            expected_remote_head: None,
            new_head,
            correlation_id: Some(c.clone()),
        })
        .unwrap();
        let entry = log.get_git_push(push_request_id).unwrap().unwrap();
        prop_assert_eq!(entry.correlation_id, Some(c));
    }
}
