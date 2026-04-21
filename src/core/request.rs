use super::{GitHubAccess, RepoRef};
use serde::{Deserialize, Serialize};

/// A single request from an agent for authority to perform one action.
///
/// Modelled as a closed discriminated union so the policy engine can pattern
/// match exhaustively — if a new action class is added, the compiler forces
/// the policy to consider it rather than silently falling through.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "backend", content = "request")]
pub enum CapabilityRequest {
    // `rename_all = "snake_case"` would turn `GitHub` into `git_hub`, which is
    // surprising for a wire format. Name it explicitly.
    #[serde(rename = "github")]
    GitHub(GitHubRequest),
}

/// What the agent wants to do on GitHub, keyed by the GitHub App permission
/// name the action requires.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "resource")]
pub enum GitHubRequest {
    Contents {
        access: GitHubAccess,
        repo: RepoRef,
    },
    Issues {
        access: GitHubAccess,
        repo: RepoRef,
    },
    PullRequests {
        access: GitHubAccess,
        repo: RepoRef,
    },
    /// Always read-only by construction (GitHub does not offer
    /// `metadata: write`); enumerated explicitly so callers can request
    /// read-only access without specifying an `access` field.
    Metadata {
        repo: RepoRef,
    },
}

impl GitHubRequest {
    pub fn repo(&self) -> &RepoRef {
        match self {
            Self::Contents { repo, .. }
            | Self::Issues { repo, .. }
            | Self::PullRequests { repo, .. }
            | Self::Metadata { repo } => repo,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_repo() -> RepoRef {
        RepoRef {
            owner: "smaug123".into(),
            name: "agent-infra".into(),
        }
    }

    #[test]
    fn contents_write_roundtrips() {
        let r = CapabilityRequest::GitHub(GitHubRequest::Contents {
            access: GitHubAccess::Write,
            repo: sample_repo(),
        });
        let j = serde_json::to_string(&r).unwrap();
        let back: CapabilityRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn metadata_request_has_no_access_field() {
        let r = CapabilityRequest::GitHub(GitHubRequest::Metadata {
            repo: sample_repo(),
        });
        let j = serde_json::to_string(&r).unwrap();
        assert!(
            !j.contains("access"),
            "serialised metadata request contained 'access': {j}"
        );
    }

    #[test]
    fn repo_accessor_returns_same_ref() {
        let r = sample_repo();
        let req = GitHubRequest::Issues {
            access: GitHubAccess::Read,
            repo: r.clone(),
        };
        assert_eq!(req.repo(), &r);
    }

    /// Pin the wire-level name of the GitHub backend. Regressing this
    /// silently (e.g. via `rename_all` producing "git_hub") would break
    /// every deployed client at once.
    #[test]
    fn github_variant_serialises_as_literal_github() {
        let r = CapabilityRequest::GitHub(GitHubRequest::Metadata {
            repo: sample_repo(),
        });
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["backend"], serde_json::Value::String("github".into()));
    }
}
