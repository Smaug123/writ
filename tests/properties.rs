//! Property-based tests for the core data model. The invariant here is
//! simply "any core value round-trips cleanly through JSON"; it's a
//! one-line assertion but it catches a surprising number of serde
//! mistakes (typos in `rename_all`, adjacent-tag clashes, etc.).

use agent_infra::core::{
    CapabilityRequest, CredentialGrant, GitHubGrantedScope, GitHubPermissions, GitHubRequest,
    GrantedScope, Jti, PolicyDecision, RepoRef, RequestId, SessionId, SessionRecord, TtlSeconds,
    UnixSeconds,
};
use proptest::prelude::*;

fn arb_repo() -> impl Strategy<Value = RepoRef> {
    ("[a-zA-Z0-9_-]{1,32}", "[a-zA-Z0-9_.-]{1,32}").prop_map(|(owner, name)| RepoRef {
        owner,
        name,
    })
}

fn arb_access() -> impl Strategy<Value = agent_infra::core::GitHubAccess> {
    prop_oneof![
        Just(agent_infra::core::GitHubAccess::Read),
        Just(agent_infra::core::GitHubAccess::Write),
    ]
}

fn arb_github_request() -> impl Strategy<Value = GitHubRequest> {
    prop_oneof![
        (arb_access(), arb_repo()).prop_map(|(access, repo)| GitHubRequest::Contents { access, repo }),
        (arb_access(), arb_repo()).prop_map(|(access, repo)| GitHubRequest::Issues { access, repo }),
        (arb_access(), arb_repo()).prop_map(|(access, repo)| GitHubRequest::PullRequests { access, repo }),
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
        prop::option::of(arb_access()),
    )
        .prop_map(|(contents, issues, pull_requests, metadata)| GitHubPermissions {
            contents,
            issues,
            pull_requests,
            metadata,
        })
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
    (arb_scope(), 0i64..10_000_000_000, 1i64..=3600).prop_map(|(scope, issued, ttl)| {
        CredentialGrant {
            jti: Jti::new(),
            request_id: RequestId::new(),
            session_id: SessionId::new(),
            scope,
            issued_at: UnixSeconds::from_i64(issued),
            expires_at: UnixSeconds::from_i64(issued + ttl),
        }
    })
}

fn arb_session() -> impl Strategy<Value = SessionRecord> {
    (
        prop::option::of("[a-zA-Z0-9 ]{0,64}"),
        prop::option::of("[a-zA-Z0-9.-]{0,64}"),
        0i64..10_000_000_000,
        prop::option::of(0i64..10_000_000_000),
    )
        .prop_map(|(label, agent_model, opened, closed)| SessionRecord {
            session_id: SessionId::new(),
            label,
            agent_model,
            opened_at: UnixSeconds::from_i64(opened),
            closed_at: closed.map(UnixSeconds::from_i64),
        })
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
}
