//! Property-based tests for the core data model. The invariant here is
//! simply "any core value round-trips cleanly through JSON"; it's a
//! one-line assertion but it catches a surprising number of serde
//! mistakes (typos in `rename_all`, adjacent-tag clashes, etc.).

use std::net::Ipv4Addr;

use proptest::prelude::*;
use writ::agent_run::{
    AgentPrompt, AgentRunId, CorrelationId, MAX_CORRELATION_ID_BYTES, MIN_CORRELATION_ID_BYTES,
};
use writ::agent_vm_lifecycle::parse_bridge_for_gateway;
use writ::audit::{
    AgentRunAuditRecord, AuditLog, GitPushRequestRecord, HostMintAuditTable, HostMintOutcome,
    PreMintRecord,
};
use writ::core::{
    AgentKind, CapabilityRequest, CapabilitySet, CredentialGrant, GitHubAccess, GitHubGrantedScope,
    GitHubPermissions, GitHubRequest, GrantedScope, Jti, MetadataAccess, PfInterface,
    PolicyDecision, RepoRef, RequestId, SessionId, SessionRecord, TtlSeconds, UnixMillis,
};
use writ::policy::{Decision, PolicyConfig, decide};
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

fn arb_capability_set() -> impl Strategy<Value = CapabilitySet> {
    prop_oneof![
        arb_repo().prop_map(|repo| CapabilitySet::WorkspaceRead { repo }),
        arb_repo().prop_map(|repo| CapabilitySet::WorkspaceWrite { repo }),
    ]
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
    fn capability_set_roundtrips_through_json(cap in arb_capability_set()) {
        let j = serde_json::to_string(&cap).unwrap();
        let back: CapabilitySet = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(back, cap);
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
            Decision::Grant(_) => {
                if is_write {
                    prop_assert!(on_allowlist, "granted write but repo not on allowlist: {req:?}");
                }
            }
            Decision::Deny { .. } => {
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
            Decision::Grant(auth) => {
                let s = auth.scope();
                prop_assert_eq!(&s.repository, req.repo());
                prop_assert_eq!(s.permissions.metadata, Some(MetadataAccess::Read));
            }
            Decision::Deny { reason } => prop_assert!(false, "unexpectedly denied: {reason}"),
        }
    }

    /// The mint's audit pair is completable by **exactly** the outcome its
    /// decision admits, and by no other.
    ///
    /// `begin_effect` is expected to accept any decision `decide` produces (its
    /// output is structurally valid by construction). What varies is the
    /// discharge: a `Grant` decision takes a `Granted` outcome and refuses
    /// `Denied`; a `Deny` decision takes `Denied` and refuses `Granted`. Both
    /// directions matter — the log holds two statements about each request (the
    /// decision, and what came of it), and a pair that admitted the wrong
    /// outcome would let them contradict each other.
    ///
    /// The `Denied` half is new: before `mint_denied` existed, a denied request
    /// had no outcome to record at all, so this property could only be stated
    /// for half the decisions `decide` produces.
    #[test]
    fn the_mint_pair_admits_exactly_the_outcome_its_decision_implies(
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
        let decision_record = decision.to_record();

        let log = std::sync::Arc::new(AuditLog::open_in_memory().unwrap());
        let session = SessionRecord {
            session_id: SessionId::new(),
            label: None,
            agent_kind: None,
            agent_model: None,
            opened_at: UnixMillis::from_millis(0),
            closed_at: None,
        };
        log.open_session(&session).unwrap();

        // One request row per attempt: a guard is per request id, and a
        // refused `complete` consumes it, so the two halves cannot share one.
        let begin = |request_id| log.begin_effect::<HostMintAuditTable>(&PreMintRecord {
            request_id,
            session_id: session.session_id,
            received_at: UnixMillis::from_millis(0),
            request: &cap_req,
            decision: &decision_record,
        });

        let admitted_id = RequestId::new();
        let refused_id = RequestId::new();
        let (admitted, refused) = (begin(admitted_id), begin(refused_id));
        prop_assert!(
            admitted.is_ok() && refused.is_ok(),
            "decide produced a decision begin_effect rejected: req={req:?} decision={decision:?} \
             admitted={admitted:?} refused={refused:?}",
        );
        let (admitted, refused) = (admitted.unwrap(), refused.unwrap());

        // A grant shaped to agree with whatever decision was produced. For a
        // `Deny` it is the deliberately-bogus one: `insert_grant_row` refuses on
        // the recorded decision before it ever looks at the scope.
        let grant_for = |request_id| match &decision {
            Decision::Grant(auth) => CredentialGrant {
                jti: Jti::new(),
                request_id,
                session_id: session.session_id,
                github_app_id: Some(github_app_id),
                scope: GrantedScope::GitHub(auth.scope().clone()),
                issued_at: UnixMillis::from_millis(0),
                expires_at: UnixMillis::from_millis(auth.ttl().as_i64().saturating_mul(1000)),
            },
            Decision::Deny { .. } => CredentialGrant {
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
            },
        };

        // Discharge both guards *before* asserting: an outstanding guard dropped
        // by an early return trips the Drop backstop, which would bury the
        // property's own diagnostic under "dropped without discharge".
        let denied = |request_id, reason: &'static str| HostMintOutcome::Denied {
            request_id,
            denied_at: UnixMillis::from_millis(1),
            reason,
        };
        let (admitted_grant, refused_grant) = (grant_for(admitted_id), grant_for(refused_id));
        let (admitted_result, refused_result) = match &decision {
            Decision::Grant(_) => (
                admitted.complete(&HostMintOutcome::Granted(&admitted_grant)),
                refused.complete(&denied(refused_id, "policy said no")),
            ),
            Decision::Deny { reason } => (
                admitted.complete(&HostMintOutcome::Denied {
                    request_id: admitted_id,
                    denied_at: UnixMillis::from_millis(1),
                    reason,
                }),
                refused.complete(&HostMintOutcome::Granted(&refused_grant)),
            ),
        };

        prop_assert!(
            admitted_result.is_ok(),
            "the outcome the decision implies was refused: req={req:?} decision={decision:?} \
             err={admitted_result:?}",
        );
        prop_assert!(
            refused_result.is_err(),
            "the outcome the decision contradicts was accepted: req={req:?} decision={decision:?}",
        );

        // And the pair is complete: every request row that reached an outcome
        // has one, which is the invariant the boot-time scan ranges over.
        prop_assert_eq!(
            log.count_unpaired_effect_request_rows("request", "mint_outcome", "request_id").unwrap(),
            1,
            "only the deliberately-refused request should be left dangling",
        );
    }

    /// Beginning the mint's effect rejects any Grant decision whose scope isn't
    /// structurally compatible with the request, regardless of which
    /// `GitHubRequest` variant is involved. The DAO previously had a
    /// single hand-rolled unit test for this; the property pins it for
    /// every variant against an oracle re-implementation of the rules.
    #[test]
    fn beginning_the_mint_agrees_with_the_scope_authorisation_oracle(
        req in arb_github_request(),
        // Bias scope.repository to the request's repo half the time, so
        // the `repo matches` branch gets exercised — random unrelated
        // repos almost never collide.
        copy_repo in any::<bool>(),
        scope_repo in arb_repo(),
        permissions in arb_permissions(),
    ) {
        let log = std::sync::Arc::new(AuditLog::open_in_memory().unwrap());
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
        let request_id = RequestId::new();
        let begun = log.begin_effect::<HostMintAuditTable>(&PreMintRecord {
            request_id,
            session_id: session.session_id,
            received_at: UnixMillis::from_millis(0),
            request: &cap_req,
            decision: &decision,
        });

        // Discharge before asserting. The mint has no `abandon` — every ending
        // it can reach is truthfully expressible — so an accepted request row
        // has to be finished, and finishing it here also proves the accepted
        // scope is one a grant can actually be recorded against.
        let (accepted, completed) = match begun {
            Ok(guard) => {
                let grant = CredentialGrant {
                    jti: Jti::new(),
                    request_id,
                    session_id: session.session_id,
                    github_app_id: Some(1),
                    scope: GrantedScope::GitHub(github_scope.clone()),
                    issued_at: UnixMillis::from_millis(0),
                    expires_at: UnixMillis::from_millis(300_000),
                };
                (true, Some(guard.complete(&HostMintOutcome::Granted(&grant))))
            }
            Err(_) => (false, None),
        };

        let expected = oracle_scope_authorises_request(&req, &github_scope);
        prop_assert_eq!(
            accepted,
            expected,
            "req={:?} scope={:?} completed={:?}",
            req,
            github_scope,
            completed,
        );
        if let Some(completed) = completed {
            prop_assert!(
                completed.is_ok(),
                "an authorised scope was begun but its grant was refused: req={req:?} \
                 scope={github_scope:?} err={completed:?}",
            );
        }
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
// Correlation IDs and their audit-log round-trips.
// ---------------------------------------------------------------------------

fn arb_correlation_id() -> impl Strategy<Value = CorrelationId> {
    "[A-Za-z0-9_-]{1,64}"
        .prop_map(|s| CorrelationId::try_new(s).expect("regex produces only valid correlation ids"))
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

    /// For any number of concurrent agent VMs, each session's IPv4 gateway maps
    /// back to exactly its own bridge and member interface, and a gateway no
    /// interface carries fails closed. This is the guarantee the IPv4-only IPv6
    /// backstop relies on to scope its deny to the right session's bridge.
    #[test]
    fn bridge_discovery_maps_each_gateway_to_its_own_bridge_and_member(n in 2usize..=6) {
        // Noise the parser must ignore: loopback and a real uplink whose inet is
        // not a session gateway.
        let mut text = String::from(
            "lo0: flags=8049<UP,LOOPBACK> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n\
             en0: flags=8863<UP> mtu 1500\n\tinet 10.0.0.5 netmask 0xffffff00\n",
        );
        let mut expected = Vec::new();
        for i in 0..n {
            let bridge = format!("bridge{}", 100 + i);
            let member = format!("vmenet{i}");
            let octet = (200 + i) as u8;
            let gw = Ipv4Addr::new(192, 168, octet, 1);
            text.push_str(&format!(
                "{bridge}: flags=8a63<UP,BROADCAST> mtu 1500 index {}\n\
                 \tether fe:b2:14:ac:08:{:02x}\n\
                 \tinet {gw} netmask 0xffffff00 broadcast 192.168.{octet}.255\n\
                 \tinet6 fe80::1%{bridge} prefixlen 64 scopeid 0x19\n\
                 \tmember: {member} flags=20003<VIRTIO>\n\
                 \t\tifmaxaddr 0 port 24 priority 0 path cost 0\n",
                25 + i,
                i,
            ));
            expected.push((gw, bridge, member));
        }
        for (gw, bridge, member) in expected {
            let disc = parse_bridge_for_gateway(&text, gw, 1).unwrap();
            prop_assert_eq!(disc.bridge().as_str(), bridge.as_str());
            prop_assert_eq!(
                disc.members().iter().map(PfInterface::as_str).collect::<Vec<_>>(),
                vec![member.as_str()]
            );
            let deny = disc.deny_interfaces();
            prop_assert_eq!(
                deny.iter().map(PfInterface::as_str).collect::<Vec<_>>(),
                vec![bridge.as_str(), member.as_str()]
            );
        }
        prop_assert!(parse_bridge_for_gateway(&text, Ipv4Addr::new(203, 0, 113, 1), 1).is_err());
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
            purpose: None,
        })
        .unwrap();
        let entry = log.get_agent_run(run_id).unwrap().unwrap();
        prop_assert_eq!(entry.correlation_id, Some(c));
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
