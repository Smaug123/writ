//! The policy engine: a pure function from (request, config) to decision.
//!
//! v1 policy is deliberately minimal:
//!   * Reads on any repo that's part of the GitHub App installation are
//!     granted (GitHub enforces the installation boundary itself).
//!   * Writes are granted only if the repo is on the `writable_repos`
//!     allowlist.
//!   * Metadata is always granted.
//!
//! Everything routes through `decide`, which is deterministic and side-effect
//! free. A Cedar/OPA-style DSL is a non-goal until the shape of policy has
//! stabilised — once we have half a dozen real rules in mind, we'll know what
//! shape the externalisation should take.

use serde::{Deserialize, Serialize};

use crate::core::{
    CapabilityRequest, GitHubAccess, GitHubGrantedScope, GitHubPermissions, GitHubRequest,
    GrantedScope, MetadataAccess, PolicyDecision, RepoRef, TtlSeconds,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Repos on which write access is permitted. Read access is permitted
    /// on any repo that the GitHub App installation itself can see.
    #[serde(default)]
    pub writable_repos: Vec<RepoRef>,

    /// Ceiling on effective grant lifetime. The audit log records the
    /// backend-reported expiry, which may be shorter; if the backend can't
    /// issue a token within this ceiling (GitHub's installation tokens are
    /// always ~1 hour, and can't be asked for less), the mint step fails
    /// rather than produce a grant that outlives the decision. Bounded to
    /// the 1-hour installation token ceiling by `TtlSeconds` itself.
    pub default_ttl: TtlSeconds,
}

/// Evaluate the policy for one request.
pub fn decide(request: &CapabilityRequest, policy: &PolicyConfig) -> PolicyDecision {
    match request {
        CapabilityRequest::GitHub(r) => decide_github(r, policy),
    }
}

fn decide_github(r: &GitHubRequest, policy: &PolicyConfig) -> PolicyDecision {
    if is_write(r) {
        let repo = r.repo();
        if !policy.writable_repos.iter().any(|w| w == repo) {
            return PolicyDecision::Deny {
                reason: format!("write access to {repo} is not on the writable-repos allowlist"),
            };
        }
    }
    PolicyDecision::Grant {
        scope: GrantedScope::GitHub(GitHubGrantedScope {
            repository: r.repo().clone(),
            permissions: permissions_for_request(r),
        }),
        ttl: policy.default_ttl,
    }
}

fn is_write(r: &GitHubRequest) -> bool {
    matches!(
        r,
        GitHubRequest::Contents {
            access: GitHubAccess::Write,
            ..
        } | GitHubRequest::Issues {
            access: GitHubAccess::Write,
            ..
        } | GitHubRequest::PullRequests {
            access: GitHubAccess::Write,
            ..
        }
    )
}

/// The GitHub App permission set a mint step should carry for one request.
/// `metadata: read` is always included because GitHub requires it on every
/// installation token.
fn permissions_for_request(r: &GitHubRequest) -> GitHubPermissions {
    let mut p = GitHubPermissions {
        metadata: Some(MetadataAccess::Read),
        ..Default::default()
    };
    match r {
        GitHubRequest::Metadata { .. } => {}
        GitHubRequest::Contents { access, .. } => p.contents = Some(*access),
        GitHubRequest::Issues { access, .. } => p.issues = Some(*access),
        GitHubRequest::PullRequests { access, .. } => p.pull_requests = Some(*access),
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(owner: &str, name: &str) -> RepoRef {
        RepoRef {
            owner: owner.into(),
            name: name.into(),
        }
    }

    fn policy_with(writable: Vec<RepoRef>) -> PolicyConfig {
        PolicyConfig {
            writable_repos: writable,
            default_ttl: TtlSeconds::new(300).unwrap(),
        }
    }

    fn expect_grant(d: PolicyDecision) -> GitHubGrantedScope {
        match d {
            PolicyDecision::Grant {
                scope: GrantedScope::GitHub(s),
                ..
            } => s,
            other => panic!("expected Grant, got {other:?}"),
        }
    }

    #[test]
    fn read_on_any_repo_is_granted() {
        let policy = policy_with(vec![]);
        let req = CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Read,
            repo: repo("anyone", "anywhere"),
        });
        let scope = expect_grant(decide(&req, &policy));
        assert_eq!(scope.permissions.contents, Some(GitHubAccess::Read));
        assert_eq!(scope.permissions.metadata, Some(MetadataAccess::Read));
        assert_eq!(scope.permissions.issues, None);
        assert_eq!(scope.permissions.pull_requests, None);
    }

    #[test]
    fn write_on_allowlisted_repo_is_granted() {
        let r = repo("smaug123", "writ");
        let policy = policy_with(vec![r.clone()]);
        let req = CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Write,
            repo: r.clone(),
        });
        let scope = expect_grant(decide(&req, &policy));
        assert_eq!(scope.repository, r);
        assert_eq!(scope.permissions.contents, Some(GitHubAccess::Write));
    }

    #[test]
    fn write_on_other_repo_is_denied() {
        let policy = policy_with(vec![repo("smaug123", "writ")]);
        let req = CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Write,
            repo: repo("someone-else", "thing"),
        });
        match decide(&req, &policy) {
            PolicyDecision::Deny { reason } => {
                assert!(reason.contains("someone-else/thing"), "got: {reason}");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn metadata_request_is_always_granted() {
        let policy = policy_with(vec![]);
        let req = CapabilityRequest::GitHub(GitHubRequest::Metadata {
            repo: repo("any", "repo"),
        });
        let scope = expect_grant(decide(&req, &policy));
        assert_eq!(scope.permissions.metadata, Some(MetadataAccess::Read));
        assert_eq!(scope.permissions.contents, None);
    }

    #[test]
    fn issues_and_pr_writes_respect_allowlist() {
        let r = repo("o", "n");
        let policy = policy_with(vec![r.clone()]);
        for req in [
            CapabilityRequest::GitHub(GitHubRequest::Issues {
                access: GitHubAccess::Write,
                repo: r.clone(),
            }),
            CapabilityRequest::GitHub(GitHubRequest::PullRequests {
                access: GitHubAccess::Write,
                repo: r.clone(),
            }),
        ] {
            assert!(
                matches!(decide(&req, &policy), PolicyDecision::Grant { .. }),
                "write on allowlisted repo should be granted: {req:?}"
            );
        }

        let disallowed = repo("other", "repo");
        for req in [
            CapabilityRequest::GitHub(GitHubRequest::Issues {
                access: GitHubAccess::Write,
                repo: disallowed.clone(),
            }),
            CapabilityRequest::GitHub(GitHubRequest::PullRequests {
                access: GitHubAccess::Write,
                repo: disallowed.clone(),
            }),
        ] {
            assert!(
                matches!(decide(&req, &policy), PolicyDecision::Deny { .. }),
                "write on non-allowlisted repo should be denied: {req:?}"
            );
        }
    }

    #[test]
    fn granted_scope_only_has_the_one_requested_permission() {
        let r = repo("o", "n");
        let policy = policy_with(vec![r.clone()]);
        let req = CapabilityRequest::GitHub(GitHubRequest::Issues {
            access: GitHubAccess::Write,
            repo: r.clone(),
        });
        let scope = expect_grant(decide(&req, &policy));
        assert_eq!(scope.permissions.issues, Some(GitHubAccess::Write));
        assert_eq!(scope.permissions.contents, None);
        assert_eq!(scope.permissions.pull_requests, None);
        assert_eq!(scope.permissions.metadata, Some(MetadataAccess::Read));
    }

    #[test]
    fn grant_ttl_equals_policy_default() {
        let policy = PolicyConfig {
            writable_repos: vec![],
            default_ttl: TtlSeconds::new(1200).unwrap(),
        };
        let req = CapabilityRequest::GitHub(GitHubRequest::Metadata {
            repo: repo("any", "repo"),
        });
        match decide(&req, &policy) {
            PolicyDecision::Grant { ttl, .. } => assert_eq!(ttl, policy.default_ttl),
            other => panic!("expected Grant, got {other:?}"),
        }
    }

    #[test]
    fn policy_config_parses_from_json() {
        let json = r#"{
            "default_ttl": 300,
            "writable_repos": ["smaug123/writ"]
        }"#;
        let c: PolicyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(c.default_ttl.as_i64(), 300);
        assert_eq!(c.writable_repos.len(), 1);
    }

    #[test]
    fn policy_config_rejects_out_of_range_ttl() {
        let json = r#"{"default_ttl": 99999, "writable_repos": []}"#;
        assert!(serde_json::from_str::<PolicyConfig>(json).is_err());
    }
}
