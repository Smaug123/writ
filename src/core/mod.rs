//! Pure data types. No IO, no side effects. Everything here round-trips
//! through serde and is safe to construct from tests.

mod decision;
mod grant;
mod request;
mod session;

pub use decision::{
    GitHubGrantedScope, GitHubPermissions, GrantedScope, MetadataAccess, PolicyDecision, TtlError,
    TtlSeconds,
};
pub use grant::CredentialGrant;
pub use request::{CapabilityRequest, GitHubRequest};
pub use session::SessionRecord;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// --- Nominal IDs ------------------------------------------------------

macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            // A `Default` impl would silently mint a fresh random UUID,
            // which is a surprising meaning of "default value". Keep
            // generation explicit.
            #[allow(clippy::new_without_default)]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
            pub fn from_uuid(u: Uuid) -> Self {
                Self(u)
            }
            pub fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Uuid::parse_str(s)?))
            }
        }
    };
}

uuid_id!(
    /// Broker-issued identity for one agent conversation.
    SessionId
);
uuid_id!(
    /// Identifies one capability request from an agent.
    RequestId
);
uuid_id!(
    /// Identifies one credential grant — the reconciliation key for
    /// matching audit records against later-observed side effects.
    Jti
);

// --- Timestamp --------------------------------------------------------

/// A unix-epoch timestamp in milliseconds, always UTC. Millisecond
/// resolution is fine enough that parallel agent panes or a burst of
/// GitHub calls within the same wall-clock second still get distinct
/// received_at/issued_at/closed_at values, which the audit log relies on
/// to reconstruct event order during replay.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixMillis(i64);

impl UnixMillis {
    pub fn now() -> Self {
        // `unix_timestamp_nanos` is i128; dividing by 1_000_000 lands us in
        // i64 millisecond space for any plausible calendar date.
        let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        Self((nanos / 1_000_000) as i64)
    }
    pub fn from_millis(v: i64) -> Self {
        Self(v)
    }
    pub fn as_millis(self) -> i64 {
        self.0
    }
    /// Construct from a whole-number unix-seconds value (e.g. GitHub's
    /// `expires_at`, JWT `iat`/`exp`). The resulting instant sits exactly
    /// on a second boundary.
    pub fn from_seconds(s: i64) -> Self {
        Self(s.saturating_mul(1000))
    }
    /// Truncate to whole unix seconds. Needed where a wire format
    /// (JWT claims, GitHub REST) only carries second precision.
    pub fn as_seconds_floor(self) -> i64 {
        self.0.div_euclid(1000)
    }
}

impl std::fmt::Display for UnixMillis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// --- RepoRef ----------------------------------------------------------

/// A GitHub repository reference in "owner/name" form. Serialised as a
/// bare string.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RepoRef {
    pub owner: String,
    pub name: String,
}

impl RepoRef {
    /// Case-insensitive equality, matching GitHub's own resolution
    /// semantics for owner and repository names. Use this anywhere a
    /// comparison crosses the GitHub boundary (policy allowlists,
    /// response verification) so operator-typed casing doesn't cause
    /// spurious mismatches. `PartialEq` is left exact so collections
    /// keyed on `RepoRef` behave predictably; the broker only treats
    /// case as irrelevant when *comparing against GitHub-sourced names*.
    pub fn matches(&self, other: &Self) -> bool {
        self.owner.eq_ignore_ascii_case(&other.owner) && self.name.eq_ignore_ascii_case(&other.name)
    }
}

impl std::fmt::Display for RepoRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RepoRefParseError {
    #[error("expected 'owner/name', got '{0}'")]
    Malformed(String),
}

impl std::str::FromStr for RepoRef {
    type Err = RepoRefParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (owner, name) = s
            .split_once('/')
            .ok_or_else(|| RepoRefParseError::Malformed(s.to_string()))?;
        if owner.is_empty() || name.is_empty() || name.contains('/') {
            return Err(RepoRefParseError::Malformed(s.to_string()));
        }
        Ok(Self {
            owner: owner.to_string(),
            name: name.to_string(),
        })
    }
}

impl Serialize for RepoRef {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for RepoRef {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// --- GitHubAccess -----------------------------------------------------

/// Access level for a GitHub App permission.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubAccess {
    Read,
    Write,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn repo_ref_parses_well_formed() {
        let r: RepoRef = "smaug123/writ".parse().unwrap();
        assert_eq!(r.owner, "smaug123");
        assert_eq!(r.name, "writ");
        assert_eq!(r.to_string(), "smaug123/writ");
    }

    #[test]
    fn repo_ref_rejects_malformed() {
        for bad in ["no-slash", "/name", "owner/", "a/b/c", "", "/"] {
            assert!(
                RepoRef::from_str(bad).is_err(),
                "expected parse failure for {bad:?}"
            );
        }
    }

    #[test]
    fn repo_ref_serde_is_bare_string() {
        let r = RepoRef {
            owner: "o".into(),
            name: "n".into(),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, r#""o/n""#);
        let back: RepoRef = serde_json::from_str(&j).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn matches_is_case_insensitive_but_eq_is_not() {
        let a = RepoRef {
            owner: "Smaug123".into(),
            name: "Writ".into(),
        };
        let b = RepoRef {
            owner: "smaug123".into(),
            name: "writ".into(),
        };
        assert!(a.matches(&b));
        assert!(b.matches(&a));
        assert_ne!(a, b, "PartialEq must stay exact so Hash/collections behave");
    }

    #[test]
    fn matches_rejects_different_owner_or_name() {
        let r = RepoRef {
            owner: "o".into(),
            name: "n".into(),
        };
        assert!(!r.matches(&RepoRef {
            owner: "o".into(),
            name: "m".into(),
        }));
        assert!(!r.matches(&RepoRef {
            owner: "p".into(),
            name: "n".into(),
        }));
    }

    #[test]
    fn ids_are_freshly_unique() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn id_roundtrips_through_string() {
        let a = SessionId::new();
        let s = a.to_string();
        let back: SessionId = s.parse().unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn unix_millis_serialises_as_integer() {
        let t = UnixMillis::from_millis(1_700_000_000_123);
        assert_eq!(serde_json::to_string(&t).unwrap(), "1700000000123");
    }

    #[test]
    fn unix_millis_seconds_conversion_is_exact_at_boundaries() {
        let t = UnixMillis::from_seconds(1_700_000_000);
        assert_eq!(t.as_millis(), 1_700_000_000_000);
        assert_eq!(t.as_seconds_floor(), 1_700_000_000);
    }

    #[test]
    fn unix_millis_seconds_floor_truncates_towards_minus_infinity() {
        // Negative timestamps are unusual but possible; `div_euclid`
        // guarantees we round toward minus infinity so a pre-epoch ms
        // value doesn't silently round the wrong way.
        assert_eq!(UnixMillis::from_millis(1_500).as_seconds_floor(), 1);
        assert_eq!(UnixMillis::from_millis(-1).as_seconds_floor(), -1);
        assert_eq!(UnixMillis::from_millis(-1_000).as_seconds_floor(), -1);
    }

    #[test]
    fn github_access_serialises_snake_case() {
        assert_eq!(
            serde_json::to_string(&GitHubAccess::Read).unwrap(),
            r#""read""#
        );
        assert_eq!(
            serde_json::to_string(&GitHubAccess::Write).unwrap(),
            r#""write""#
        );
    }
}
