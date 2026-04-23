//! Property-based tests for the core data model. The invariant here is
//! simply "any core value round-trips cleanly through JSON"; it's a
//! one-line assertion but it catches a surprising number of serde
//! mistakes (typos in `rename_all`, adjacent-tag clashes, etc.).

use proptest::prelude::*;
use writ::core::{
    CapabilityRequest, CredentialGrant, GitHubAccess, GitHubGrantedScope, GitHubPermissions,
    GitHubRequest, GrantedScope, Jti, MetadataAccess, PolicyDecision, RepoRef, RequestId,
    SessionId, SessionRecord, TtlSeconds, UnixMillis,
};
use writ::policy::{PolicyConfig, decide};

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
    (arb_scope(), 0i64..10_000_000_000, 1i64..=3600).prop_map(|(scope, issued, ttl)| {
        CredentialGrant {
            jti: Jti::new(),
            request_id: RequestId::new(),
            session_id: SessionId::new(),
            scope,
            issued_at: UnixMillis::from_millis(issued),
            expires_at: UnixMillis::from_millis(issued + ttl),
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
            opened_at: UnixMillis::from_millis(opened),
            closed_at: closed.map(UnixMillis::from_millis),
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
        let on_allowlist = writable.iter().any(|r| r == req.repo());

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
}
