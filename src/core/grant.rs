use super::decision::GrantedScope;
use super::{Jti, RequestId, SessionId, UnixMillis};
use serde::{Deserialize, Serialize};

/// The persistent record of one credential mint. The *token string itself is
/// deliberately not stored here*: it lives in memory during the response to
/// the agent and nowhere else. What persists is the proof that a grant was
/// made, narrow enough to correlate against later-observed side effects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialGrant {
    pub jti: Jti,
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub scope: GrantedScope,
    pub issued_at: UnixMillis,
    pub expires_at: UnixMillis,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{GitHubAccess, GitHubGrantedScope, GitHubPermissions, RepoRef};

    #[test]
    fn grant_roundtrips() {
        let g = CredentialGrant {
            jti: Jti::new(),
            request_id: RequestId::new(),
            session_id: SessionId::new(),
            scope: GrantedScope::GitHub(GitHubGrantedScope {
                repository: RepoRef {
                    owner: "o".into(),
                    name: "n".into(),
                },
                permissions: GitHubPermissions {
                    contents: Some(GitHubAccess::Read),
                    metadata: Some(GitHubAccess::Read),
                    ..Default::default()
                },
            }),
            issued_at: UnixMillis::from_millis(1_700_000_000),
            expires_at: UnixMillis::from_millis(1_700_000_300),
        };
        let j = serde_json::to_string(&g).unwrap();
        let back: CredentialGrant = serde_json::from_str(&j).unwrap();
        assert_eq!(back, g);
    }
}
