use super::{GitHubAccess, RepoRef};
use serde::{Deserialize, Serialize};

/// The output of the policy engine: grant the request (possibly with narrowed
/// scope and bounded TTL), or deny it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum PolicyDecision {
    Grant {
        scope: GrantedScope,
        ttl: TtlSeconds,
    },
    Deny {
        reason: String,
    },
}

/// Time-to-live for a grant. Positive and bounded at construction time so
/// that interior code can rely on `ttl > 0` and `ttl <= 3600`. Deserialisation
/// runs the same check, so config-loaded values can't slip past the bounds.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct TtlSeconds(i64);

impl TryFrom<i64> for TtlSeconds {
    type Error = TtlError;
    fn try_from(v: i64) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}

impl From<TtlSeconds> for i64 {
    fn from(t: TtlSeconds) -> Self {
        t.0
    }
}

/// Maximum TTL for a GitHub App installation token.
pub const GITHUB_INSTALLATION_TOKEN_MAX_SECONDS: i64 = 3600;

impl TtlSeconds {
    pub fn new(seconds: i64) -> Result<Self, TtlError> {
        if seconds <= 0 {
            return Err(TtlError::NonPositive(seconds));
        }
        if seconds > GITHUB_INSTALLATION_TOKEN_MAX_SECONDS {
            return Err(TtlError::TooLong {
                got: seconds,
                max: GITHUB_INSTALLATION_TOKEN_MAX_SECONDS,
            });
        }
        Ok(Self(seconds))
    }
    pub fn as_i64(self) -> i64 {
        self.0
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TtlError {
    #[error("TTL must be positive, got {0}")]
    NonPositive(i64),
    #[error("TTL must not exceed {max} seconds, got {got}")]
    TooLong { got: i64, max: i64 },
}

/// The effective scope of a grant. One variant per backend, mirroring
/// `CapabilityRequest`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "backend", content = "scope")]
pub enum GrantedScope {
    GitHub(GitHubGrantedScope),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitHubGrantedScope {
    pub repository: RepoRef,
    pub permissions: GitHubPermissions,
}

/// GitHub App permissions supported by the broker. Unset fields are treated
/// by the GitHub API as "no access at all", which is the safe default.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct GitHubPermissions {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub contents: Option<GitHubAccess>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub issues: Option<GitHubAccess>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pull_requests: Option<GitHubAccess>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metadata: Option<GitHubAccess>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_rejects_non_positive() {
        assert!(matches!(TtlSeconds::new(0), Err(TtlError::NonPositive(0))));
        assert!(matches!(TtlSeconds::new(-1), Err(TtlError::NonPositive(-1))));
    }

    #[test]
    fn ttl_rejects_too_long() {
        assert!(matches!(
            TtlSeconds::new(GITHUB_INSTALLATION_TOKEN_MAX_SECONDS + 1),
            Err(TtlError::TooLong { .. })
        ));
    }

    #[test]
    fn ttl_accepts_boundary_values() {
        assert!(TtlSeconds::new(1).is_ok());
        assert!(TtlSeconds::new(GITHUB_INSTALLATION_TOKEN_MAX_SECONDS).is_ok());
    }

    #[test]
    fn grant_roundtrips() {
        let d = PolicyDecision::Grant {
            scope: GrantedScope::GitHub(GitHubGrantedScope {
                repository: RepoRef {
                    owner: "a".into(),
                    name: "b".into(),
                },
                permissions: GitHubPermissions {
                    contents: Some(GitHubAccess::Write),
                    metadata: Some(GitHubAccess::Read),
                    ..Default::default()
                },
            }),
            ttl: TtlSeconds::new(300).unwrap(),
        };
        let j = serde_json::to_string(&d).unwrap();
        let back: PolicyDecision = serde_json::from_str(&j).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn deny_roundtrips() {
        let d = PolicyDecision::Deny {
            reason: "not on allowlist".into(),
        };
        let j = serde_json::to_string(&d).unwrap();
        let back: PolicyDecision = serde_json::from_str(&j).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn empty_permissions_omit_null_fields() {
        let p = GitHubPermissions::default();
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, "{}");
    }

    #[test]
    fn ttl_deserialise_rejects_out_of_range() {
        assert!(serde_json::from_str::<TtlSeconds>("0").is_err());
        assert!(serde_json::from_str::<TtlSeconds>("-10").is_err());
        assert!(
            serde_json::from_str::<TtlSeconds>(&format!(
                "{}",
                GITHUB_INSTALLATION_TOKEN_MAX_SECONDS + 1
            ))
            .is_err()
        );
    }

    #[test]
    fn ttl_deserialise_accepts_valid() {
        let t: TtlSeconds = serde_json::from_str("300").unwrap();
        assert_eq!(t.as_i64(), 300);
    }
}
