//! GitHub App installation-token minter.
//!
//! Given a granted scope, produces a short-lived installation token
//! narrow-scoped to one repo and the requested permissions. The flow:
//!
//!   1. Load the App's RSA private key from the configured `SecretStore`.
//!   2. Sign an app JWT (RS256, `iss` = app id, `exp` ≤ 10 min).
//!   3. POST `/app/installations/{id}/access_tokens` with the JWT as
//!      `Authorization: Bearer …`, and a body restricting repositories
//!      and permissions.
//!   4. Trust GitHub's `expires_at` as authoritative for the grant record.
//!
//! The broker does not wrap or re-sign the token — it hands the raw
//! installation token back to the agent so standard `gh`/Octokit tooling
//! works unchanged. We record the `jti` we generated alongside the grant
//! so webhooks observed later can be reconciled by time, actor, and repo.

use crate::core::{GitHubGrantedScope, GitHubPermissions, Jti, UnixSeconds};
use crate::secret::{SecretError, SecretKey, SecretStore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// How long we ask the JWT to live. GitHub rejects anything over 10 minutes;
/// leave a minute of headroom.
const JWT_LIFETIME_SECONDS: i64 = 9 * 60;

/// How far we backdate `iat` to tolerate a minute of clock skew against GitHub.
const JWT_BACKDATE_SECONDS: i64 = 60;

/// Static configuration for one GitHub App installation. One broker
/// instance fronts one installation in v1.
#[derive(Clone, Debug)]
pub struct GitHubAppConfig {
    pub app_id: u64,
    pub installation_id: u64,
    /// Key under which the RSA private key (PEM) is stored in the
    /// broker's `SecretStore`. The broker never reads the key from disk
    /// or env directly — that's the secret store's job.
    pub private_key_secret: SecretKey,
    /// Base URL of the GitHub REST API, without trailing slash. Overridable
    /// for tests (wiremock) or GitHub Enterprise Server.
    pub api_base: String,
}

/// A freshly-minted installation token. The broker passes `token` through
/// to the agent raw and persists only `jti` + `expires_at` in the audit log.
#[derive(Clone, Debug)]
pub struct MintedToken {
    pub token: String,
    pub jti: Jti,
    /// The expiry GitHub tells us it will enforce. Authoritative.
    pub expires_at: UnixSeconds,
}

/// Mints installation tokens for one `GitHubAppConfig` using long-lived
/// private-key material loaded lazily from a `SecretStore` on each mint.
pub struct GitHubMinter<S: SecretStore> {
    config: GitHubAppConfig,
    secrets: S,
    http: reqwest::Client,
}

impl<S: SecretStore> GitHubMinter<S> {
    pub fn new(config: GitHubAppConfig, secrets: S) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("agent-infra-broker/0.1")
            .build()
            .expect("reqwest client constructs with default config");
        Self {
            config,
            secrets,
            http,
        }
    }

    /// Mint one installation token for `scope`. The scope's repository must
    /// belong to the installation; if it doesn't, GitHub responds 422 and
    /// we surface that verbatim as `MintError::ApiError`.
    pub async fn mint(&self, scope: &GitHubGrantedScope) -> Result<MintedToken, MintError> {
        let pem = self
            .secrets
            .get(&self.config.private_key_secret)?
            .ok_or_else(|| MintError::PrivateKeyMissing(self.config.private_key_secret.clone()))?;

        let now = UnixSeconds::now().as_i64();
        let jwt = sign_jwt(&pem, self.config.app_id, now)?;

        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.config.api_base.trim_end_matches('/'),
            self.config.installation_id
        );

        let body = MintRequest {
            repositories: vec![scope.repository.name.as_str()],
            permissions: &scope.permissions,
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(jwt)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(MintError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        let parsed: MintResponse = resp.json().await?;
        let expires_at = parse_rfc3339_seconds(&parsed.expires_at)?;

        Ok(MintedToken {
            token: parsed.token,
            jti: Jti::new(),
            expires_at: UnixSeconds::from_i64(expires_at),
        })
    }
}

#[derive(Debug, Error)]
pub enum MintError {
    #[error("private key not found in secret store under key {0:?}")]
    PrivateKeyMissing(SecretKey),
    #[error(transparent)]
    Secret(#[from] SecretError),
    #[error("failed to build JWT: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("GitHub returned {status}: {body}")]
    ApiError { status: u16, body: String },
    #[error("GitHub returned a malformed expiry timestamp {0:?}")]
    BadExpiry(String),
}

#[derive(Serialize)]
struct MintRequest<'a> {
    repositories: Vec<&'a str>,
    permissions: &'a GitHubPermissions,
}

#[derive(Deserialize)]
struct MintResponse {
    token: String,
    expires_at: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct AppJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

fn sign_jwt(private_key_pem: &str, app_id: u64, now: i64) -> Result<String, MintError> {
    let claims = AppJwtClaims {
        iat: now - JWT_BACKDATE_SECONDS,
        exp: now + JWT_LIFETIME_SECONDS,
        iss: app_id.to_string(),
    };
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;
    Ok(jsonwebtoken::encode(&header, &claims, &key)?)
}

fn parse_rfc3339_seconds(s: &str) -> Result<i64, MintError> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|t| t.unix_timestamp())
        .map_err(|_| MintError::BadExpiry(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{GitHubAccess, RepoRef};
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Pregenerated 2048-bit RSA material for tests. jsonwebtoken enforces
    // a 2048-bit RS256 minimum and generating fresh keys inside the test
    // harness takes tens of seconds on a cold cache; fixed fixtures keep
    // the suite snappy. These are test-only and carry no production value.
    // We ship the private key for fixture 1 (we sign with it) and only
    // the public key for fixture 2 (we only need it to prove that a
    // mismatched-key JWT fails to verify).
    const TEST_PRIV_1: &str = include_str!("../tests/fixtures/rsa_test_1.pem");
    const TEST_PUB_1: &str = include_str!("../tests/fixtures/rsa_test_1.pub.pem");
    const TEST_PUB_2: &str = include_str!("../tests/fixtures/rsa_test_2.pub.pem");

    #[derive(Default)]
    struct InMemStore(Mutex<HashMap<String, String>>);

    impl SecretStore for InMemStore {
        fn get(&self, key: &SecretKey) -> Result<Option<String>, SecretError> {
            Ok(self.0.lock().unwrap().get(key.as_str()).cloned())
        }
        fn put(&self, key: &SecretKey, value: &str) -> Result<(), SecretError> {
            self.0
                .lock()
                .unwrap()
                .insert(key.as_str().to_string(), value.to_string());
            Ok(())
        }
        fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
            self.0.lock().unwrap().remove(key.as_str());
            Ok(())
        }
    }

    fn write_scope(owner: &str, name: &str) -> GitHubGrantedScope {
        GitHubGrantedScope {
            repository: RepoRef {
                owner: owner.into(),
                name: name.into(),
            },
            permissions: GitHubPermissions {
                contents: Some(GitHubAccess::Write),
                metadata: Some(GitHubAccess::Read),
                ..Default::default()
            },
        }
    }

    fn minter_with_key(server: &MockServer) -> GitHubMinter<InMemStore> {
        let pk = SecretKey::new("gh-app-pk").unwrap();
        let store = InMemStore::default();
        store.put(&pk, TEST_PRIV_1).unwrap();
        GitHubMinter::new(
            GitHubAppConfig {
                app_id: 42,
                installation_id: 999,
                private_key_secret: pk,
                api_base: server.uri(),
            },
            store,
        )
    }

    #[test]
    fn jwt_claims_roundtrip_and_verify_with_public_key() {
        let now = 1_700_000_000_i64;
        let jwt = sign_jwt(TEST_PRIV_1, 12345, now).expect("sign");

        let mut v = Validation::new(Algorithm::RS256);
        v.required_spec_claims.clear();
        v.validate_exp = false;
        v.set_issuer(&["12345"]);
        let decoded = decode::<AppJwtClaims>(
            &jwt,
            &DecodingKey::from_rsa_pem(TEST_PUB_1.as_bytes()).unwrap(),
            &v,
        )
        .expect("verify with public key");
        assert_eq!(decoded.claims.iss, "12345");
        assert_eq!(decoded.claims.iat, now - JWT_BACKDATE_SECONDS);
        assert_eq!(decoded.claims.exp, now + JWT_LIFETIME_SECONDS);
    }

    #[test]
    fn jwt_verification_fails_with_different_key() {
        let jwt = sign_jwt(TEST_PRIV_1, 1, 0).expect("sign");

        let mut v = Validation::new(Algorithm::RS256);
        v.required_spec_claims.clear();
        v.validate_exp = false;
        assert!(
            decode::<AppJwtClaims>(
                &jwt,
                &DecodingKey::from_rsa_pem(TEST_PUB_2.as_bytes()).unwrap(),
                &v,
            )
            .is_err(),
            "JWT signed by key 1 should not verify under key 2's public key"
        );
    }

    #[tokio::test]
    async fn mint_exchanges_jwt_for_installation_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .and(header("Accept", "application/vnd.github+json"))
            .and(header("X-GitHub-Api-Version", "2022-11-28"))
            .and(body_json(serde_json::json!({
                "repositories": ["n"],
                "permissions": {"contents": "write", "metadata": "read"}
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_fake_value",
                "expires_at": "2024-01-01T00:00:00Z",
                "permissions": {"contents": "write", "metadata": "read"},
                "repository_selection": "selected"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let minted = minter.mint(&write_scope("o", "n")).await.expect("mint ok");

        assert_eq!(minted.token, "ghs_fake_value");
        assert_eq!(minted.expires_at.as_i64(), 1_704_067_200);
    }

    #[tokio::test]
    async fn mint_surfaces_api_error_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
                "message": "repository not installed"
            })))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        match minter.mint(&write_scope("o", "nope")).await {
            Err(MintError::ApiError { status, body }) => {
                assert_eq!(status, 422);
                assert!(
                    body.contains("repository not installed"),
                    "expected message in body, got: {body}"
                );
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mint_fails_cleanly_when_private_key_missing() {
        let server = MockServer::start().await;
        let minter = GitHubMinter::new(
            GitHubAppConfig {
                app_id: 1,
                installation_id: 1,
                private_key_secret: SecretKey::new("absent").unwrap(),
                api_base: server.uri(),
            },
            InMemStore::default(),
        );
        match minter.mint(&write_scope("o", "n")).await {
            Err(MintError::PrivateKeyMissing(k)) => assert_eq!(k.as_str(), "absent"),
            other => panic!("expected PrivateKeyMissing, got {other:?}"),
        }
    }

    #[test]
    fn expiry_parser_accepts_rfc3339() {
        assert_eq!(
            parse_rfc3339_seconds("2024-01-01T00:00:00Z").unwrap(),
            1_704_067_200
        );
    }

    #[test]
    fn expiry_parser_rejects_malformed() {
        assert!(matches!(
            parse_rfc3339_seconds("not a date"),
            Err(MintError::BadExpiry(_))
        ));
    }

    #[test]
    fn trailing_slash_in_api_base_does_not_double_slash() {
        // Manually build the URL the way mint() does, just to lock the
        // invariant: we strip one trailing slash from api_base.
        let base = "https://example.com/api/v3/";
        let url = format!(
            "{}/app/installations/{}/access_tokens",
            base.trim_end_matches('/'),
            7
        );
        assert_eq!(
            url,
            "https://example.com/api/v3/app/installations/7/access_tokens"
        );
    }
}
