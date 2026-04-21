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
        let r = CapabilityRequest::GitHub(GitHubRequest::Metadata { repo: sample_repo() });
        let j = serde_json::to_string(&r).unwrap();
        assert!(!j.contains("access"), "serialised metadata request contained 'access': {j}");
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
}
