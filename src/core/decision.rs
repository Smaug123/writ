use super::{GitHubAccess, RepoRef};
use serde::{Deserialize, Serialize};

/// Access level for the `metadata` GitHub App permission. GitHub does not
/// offer `metadata: write` — the permission is read-only by construction —
/// so this one-variant enum keeps that invariant checkable by the type
/// system. The request side achieves the same thing by giving
/// [`super::GitHubRequest::Metadata`] no `access` field at all; this is the
/// matching constraint on the grant side.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataAccess {
    Read,
}

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

/// Ceiling on the effective lifetime of a grant, in seconds. Positive and
/// bounded at construction time so that interior code can rely on
/// `ttl > 0` and `ttl <= 3600`. Deserialisation runs the same check, so
/// config-loaded values can't slip past the bounds.
///
/// This is a *ceiling*, not an exact lifetime: backend mint steps compare
/// the backend-reported expiry against `issued_at + ttl` (with a small
/// skew tolerance) and refuse to produce a grant that would outlive it.
/// The audit log's `expires_at` is always the backend-reported value, and
/// may be shorter than `ttl` would imply.
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
    // `rename_all = "snake_case"` would turn `GitHub` into `git_hub`, which is
    // surprising for a wire format. Name it explicitly.
    #[serde(rename = "github")]
    GitHub(GitHubGrantedScope),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitHubGrantedScope {
    pub repository: RepoRef,
    pub permissions: GitHubPermissions,
}

/// GitHub App permissions supported by the broker. Unset fields are treated
/// by the GitHub API as "no access at all", which is the safe default.
///
/// `deny_unknown_fields` is load-bearing: the GitHub-minter's post-response
/// check (`parsed.permissions != scope.permissions`) compares the permissions
/// echoed back by GitHub against the ones the policy asked for, to catch
/// silent narrowing *and silent widening*. Without this attribute, a newly-
/// added GitHub App permission that GitHub returned but we hadn't yet modelled
/// would be dropped by the default serde deserializer before reaching the
/// equality check, letting an over-grant slip into the agent's hands while
/// the audit log described strictly less authority.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubPermissions {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub contents: Option<GitHubAccess>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub issues: Option<GitHubAccess>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pull_requests: Option<GitHubAccess>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metadata: Option<MetadataAccess>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_rejects_non_positive() {
        assert!(matches!(TtlSeconds::new(0), Err(TtlError::NonPositive(0))));
        assert!(matches!(
            TtlSeconds::new(-1),
            Err(TtlError::NonPositive(-1))
        ));
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
                    metadata: Some(MetadataAccess::Read),
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

    /// Pin the GitHub variant's wire name on the grant side too. Matches
    /// the request side; inconsistency here would bite at the audit log
    /// and any external replay tooling.
    #[test]
    fn granted_scope_github_variant_serialises_as_literal_github() {
        let s = GrantedScope::GitHub(GitHubGrantedScope {
            repository: RepoRef {
                owner: "a".into(),
                name: "b".into(),
            },
            permissions: GitHubPermissions::default(),
        });
        let v: serde_json::Value = serde_json::to_value(&s).unwrap();
        assert_eq!(v["backend"], serde_json::Value::String("github".into()));
    }

    #[test]
    fn metadata_access_serialises_snake_case() {
        assert_eq!(
            serde_json::to_string(&MetadataAccess::Read).unwrap(),
            r#""read""#
        );
    }

    #[test]
    fn metadata_permissions_reject_write_on_deserialise() {
        assert!(serde_json::from_str::<GitHubPermissions>(r#"{"metadata":"write"}"#).is_err());
    }
}
