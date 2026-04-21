//! GitHub App installation-token minter.
//!
//! Given a granted scope and a TTL ceiling, produces a short-lived
//! installation token narrow-scoped to one repo and the requested
//! permissions. The flow:
//!
//!   1. Load the App's RSA private key from the configured `SecretStore`.
//!   2. Sign an app JWT (RS256, `iss` = app id, `exp` ≤ 10 min).
//!   3. POST `/app/installations/{id}/access_tokens` with the JWT as
//!      `Authorization: Bearer …`, and a body restricting repositories
//!      and permissions.
//!   4. Trust GitHub's `expires_at` as authoritative for the grant record,
//!      but refuse to mint at all if that expiry exceeds the policy's TTL
//!      ceiling (plus a small clock-skew tolerance). GitHub cannot be asked
//!      for a shorter-lived token, so a policy asking for less than ~1h
//!      will be refused rather than produce an audit record that lies
//!      about the lifetime.
//!
//! The broker does not wrap or re-sign the token — it hands the raw
//! installation token back to the agent so standard `gh`/Octokit tooling
//! works unchanged. We record the `jti` we generated alongside the grant
//! so webhooks observed later can be reconciled by time, actor, and repo.

use crate::core::{
    CredentialGrant, GitHubGrantedScope, GitHubPermissions, GrantedScope, Jti, RequestId,
    SessionId, TtlSeconds, UnixSeconds,
};
use crate::secret::{SecretError, SecretKey, SecretStore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// How long we ask the JWT to live. GitHub rejects anything over 10 minutes;
/// leave a minute of headroom.
const JWT_LIFETIME_SECONDS: i64 = 9 * 60;

/// How far we backdate `iat` to tolerate a minute of clock skew against GitHub.
const JWT_BACKDATE_SECONDS: i64 = 60;

/// Tolerance added to the TTL ceiling check when comparing the broker's
/// `now` against GitHub's `expires_at`. GitHub computes `expires_at` from
/// its own clock, so a broker clock that's a few seconds behind GitHub
/// would otherwise reject perfectly valid tokens. 60 s is loose enough to
/// cover any non-pathological NTP state and tight enough that a broken
/// clock can't silently widen the grant envelope by a meaningful amount.
const TTL_SKEW_TOLERANCE_SECONDS: i64 = 60;

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

/// A freshly-minted installation token, bundled with the metadata needed
/// to build a matching audit record. Fields are private on purpose: the
/// only way to get the raw token out — and the only way to produce a
/// `CredentialGrant` for the audit log — is to consume this value via
/// [`MintedToken::into_grant_and_token`]. Pairing the token and the
/// grant through a single consuming call rules out a whole class of
/// drift bugs where the audit record disagrees with the token that was
/// actually handed to the agent (wrong `jti`, a fresh `UnixSeconds::now()`
/// instead of the broker-clock reading the TTL check validated, a scope
/// different from the one the minter signed for).
#[derive(Debug)]
pub struct MintedToken {
    token: String,
    jti: Jti,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
    scope: GitHubGrantedScope,
}

impl MintedToken {
    /// Broker-clock timestamp captured immediately before the mint request
    /// went out, and the reference against which GitHub's `expires_at` was
    /// compared for the TTL check.
    pub fn issued_at(&self) -> UnixSeconds {
        self.issued_at
    }

    /// The expiry GitHub said it will enforce. Authoritative.
    pub fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    pub fn jti(&self) -> Jti {
        self.jti
    }

    pub fn scope(&self) -> &GitHubGrantedScope {
        &self.scope
    }

    /// Consume the minted token, returning the raw token string (to hand
    /// to the agent) and the matching `CredentialGrant` (to record in the
    /// audit log). The grant's `(jti, issued_at, expires_at, scope)` come
    /// straight from the mint, so there's no way for them to drift from
    /// what was actually issued.
    pub fn into_grant_and_token(
        self,
        request_id: RequestId,
        session_id: SessionId,
    ) -> (String, CredentialGrant) {
        let grant = CredentialGrant {
            jti: self.jti,
            request_id,
            session_id,
            scope: GrantedScope::GitHub(self.scope),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        };
        (self.token, grant)
    }
}

/// Mints installation tokens for one `GitHubAppConfig` using long-lived
/// private-key material loaded lazily from a `SecretStore` on each mint.
pub struct GitHubMinter<S: SecretStore> {
    config: GitHubAppConfig,
    secrets: S,
    http: reqwest::Client,
}

/// Per-request timeout for calls out to GitHub. Above a few seconds GitHub is
/// either degraded or the network has failed — waiting longer trades a failed
/// request for a blocked caller, which is the wrong side of that bargain for
/// a broker serving multiple agents.
const GITHUB_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Tighter cap on the TCP/TLS handshake specifically, so a black-holed route
/// can't eat the full per-request budget before the body even starts.
const GITHUB_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl<S: SecretStore> GitHubMinter<S> {
    pub fn new(config: GitHubAppConfig, secrets: S) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("agent-infra-broker/0.1")
            .timeout(GITHUB_REQUEST_TIMEOUT)
            .connect_timeout(GITHUB_CONNECT_TIMEOUT)
            .build()
            .expect("reqwest client constructs with default config");
        Self {
            config,
            secrets,
            http,
        }
    }

    /// Mint one installation token for `scope`, provided the backend-
    /// reported expiry fits within `ttl` (plus skew tolerance) of the
    /// broker's clock at mint time.
    ///
    /// The scope's repository must belong to the installation; if it
    /// doesn't, GitHub responds 422 and we surface that verbatim as
    /// `MintError::ApiError`.
    ///
    /// `ttl` is a ceiling, not a request: GitHub installation tokens are
    /// always minted for ~1 hour, so a `ttl` shorter than that will cause
    /// `MintError::TtlExceeded` rather than silently produce a token whose
    /// real lifetime outlives what the policy granted.
    pub async fn mint(
        &self,
        scope: GitHubGrantedScope,
        ttl: TtlSeconds,
    ) -> Result<MintedToken, MintError> {
        let pem = self
            .secrets
            .get(&self.config.private_key_secret)?
            .ok_or_else(|| MintError::PrivateKeyMissing(self.config.private_key_secret.clone()))?;

        let issued_at = UnixSeconds::now().as_i64();
        let jwt = sign_jwt(&pem, self.config.app_id, issued_at)?;

        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.config.api_base.trim_end_matches('/'),
            self.config.installation_id
        );

        let resp = {
            // Scope the borrow so `scope` becomes owned again once the
            // request body has been serialised and the send future begins.
            let body = MintRequest {
                repositories: vec![scope.repository.name.as_str()],
                permissions: &scope.permissions,
            };
            self.http
                .post(&url)
                .bearer_auth(jwt)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .json(&body)
                .send()
                .await?
        };

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

        // Defence-in-depth: GitHub should never return a token expiring at
        // or before our issue time, but if it did we'd otherwise happily
        // record a grant that was already dead and hand the agent a
        // useless token. Bail loudly instead.
        if expires_at <= issued_at {
            return Err(MintError::ExpiryNotInFuture {
                issued_at,
                actual_expires_at: expires_at,
            });
        }

        let max_allowed = issued_at + ttl.as_i64() + TTL_SKEW_TOLERANCE_SECONDS;
        if expires_at > max_allowed {
            return Err(MintError::TtlExceeded {
                ttl_seconds: ttl.as_i64(),
                issued_at,
                actual_expires_at: expires_at,
            });
        }

        Ok(MintedToken {
            token: parsed.token,
            jti: Jti::new(),
            issued_at: UnixSeconds::from_i64(issued_at),
            expires_at: UnixSeconds::from_i64(expires_at),
            scope,
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
    /// `body` carries the full error payload GitHub returned; `Display`
    /// truncates it so that logs pulling the error via `{err}` don't
    /// inherit an unbounded-length payload (and get a lightly defensive
    /// cap against any unexpected sensitive echo). Programmatic callers
    /// that actually want the full body can destructure the variant.
    #[error("GitHub returned {status}: {}", truncate_for_display(body))]
    ApiError { status: u16, body: String },
    #[error("GitHub returned a malformed expiry timestamp {0:?}")]
    BadExpiry(String),
    #[error(
        "GitHub issued a token expiring at {actual_expires_at} which exceeds the policy TTL ceiling of {ttl_seconds}s from {issued_at}"
    )]
    TtlExceeded {
        ttl_seconds: i64,
        issued_at: i64,
        actual_expires_at: i64,
    },
    #[error(
        "GitHub issued a token with expiry {actual_expires_at} at or before its issue time {issued_at}"
    )]
    ExpiryNotInFuture {
        issued_at: i64,
        actual_expires_at: i64,
    },
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

/// Cap at 256 chars so an unbounded API payload can't balloon a log line.
/// Counts chars (not bytes) to avoid slicing mid-multi-byte scalar value.
const API_ERROR_DISPLAY_CAP: usize = 256;

fn truncate_for_display(body: &str) -> String {
    let mut out: String = body.chars().take(API_ERROR_DISPLAY_CAP).collect();
    if body.chars().count() > API_ERROR_DISPLAY_CAP {
        out.push_str("... (truncated)");
    }
    out
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
        let (expiry_ts, expiry_str) = expiry_seconds_from_now(3600);
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
                "expires_at": expiry_str,
                "permissions": {"contents": "write", "metadata": "read"},
                "repository_selection": "selected"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let minted = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .expect("mint ok");

        assert_eq!(minted.expires_at().as_i64(), expiry_ts);
        let (token, _grant) = minted.into_grant_and_token(RequestId::new(), SessionId::new());
        assert_eq!(token, "ghs_fake_value");
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
        match minter
            .mint(write_scope("o", "nope"), TtlSeconds::new(3600).unwrap())
            .await
        {
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
        match minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
        {
            Err(MintError::PrivateKeyMissing(k)) => assert_eq!(k.as_str(), "absent"),
            other => panic!("expected PrivateKeyMissing, got {other:?}"),
        }
    }

    /// Build an RFC3339 timestamp `secs` from now. Used to drive the TTL
    /// ceiling tests against the broker's real clock rather than a pinned
    /// 2024 date the ceiling check would find trivially in the past.
    fn expiry_seconds_from_now(secs: i64) -> (i64, String) {
        let ts = UnixSeconds::now().as_i64() + secs;
        let formatted = time::OffsetDateTime::from_unix_timestamp(ts)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        (ts, formatted)
    }

    fn mock_mint_response(expires_at_rfc3339: &str) -> ResponseTemplate {
        ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": "ghs_fake_value",
            "expires_at": expires_at_rfc3339,
            "permissions": {"contents": "write", "metadata": "read"},
            "repository_selection": "selected"
        }))
    }

    #[tokio::test]
    async fn mint_rejects_past_dated_expiry() {
        // GitHub should never hand us a token that's already expired, but
        // if the API ever returns one (misconfigured enterprise clock,
        // stale cache, bug) we must fail loudly rather than bank a dead
        // grant. Use a timestamp well before any plausible test-run clock.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(mock_mint_response("2000-01-01T00:00:00Z"))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let err = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .expect_err("should reject past expiry");
        assert!(
            matches!(err, MintError::ExpiryNotInFuture { .. }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn mint_rejects_when_github_expiry_exceeds_policy_ttl() {
        // Policy asks for 5 minutes; GitHub hands back its usual 1h token.
        // Broker must refuse rather than record a lie.
        let server = MockServer::start().await;
        let (expiry_ts, expiry_str) = expiry_seconds_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(mock_mint_response(&expiry_str))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        match minter
            .mint(write_scope("o", "n"), TtlSeconds::new(300).unwrap())
            .await
        {
            Err(MintError::TtlExceeded {
                ttl_seconds,
                actual_expires_at,
                ..
            }) => {
                assert_eq!(ttl_seconds, 300);
                assert_eq!(actual_expires_at, expiry_ts);
            }
            other => panic!("expected TtlExceeded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mint_accepts_expiry_within_ttl_plus_skew() {
        // GitHub's clock a few seconds ahead of ours: expires_at slightly
        // past the raw TTL ceiling but well within skew tolerance. Accept.
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600 + 30);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(mock_mint_response(&expiry_str))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let minted = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .expect("mint within skew tolerance should succeed");
        assert!(minted.expires_at().as_i64() > minted.issued_at().as_i64());
    }

    #[tokio::test]
    async fn mint_rejects_expiry_just_past_skew_tolerance() {
        // The other side of the skew boundary: 10s past the tolerance
        // window must reject, to pin the meaning of the constant.
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600 + TTL_SKEW_TOLERANCE_SECONDS + 10);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(mock_mint_response(&expiry_str))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let err = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .expect_err("should reject past-skew expiry");
        assert!(matches!(err, MintError::TtlExceeded { .. }), "got: {err:?}");
    }

    #[tokio::test]
    async fn minted_token_issued_at_tracks_broker_clock() {
        // MintedToken.issued_at must be the broker's clock at mint start —
        // i.e. the same reference used for the TTL check — not a fresh
        // `now()` the caller could otherwise skew after the fact.
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(mock_mint_response(&expiry_str))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let before = UnixSeconds::now().as_i64();
        let minted = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .unwrap();
        let after = UnixSeconds::now().as_i64();

        let iat = minted.issued_at().as_i64();
        assert!(
            iat >= before && iat <= after,
            "issued_at {iat} outside [{before}, {after}]"
        );
    }

    #[tokio::test]
    async fn into_grant_and_token_preserves_mint_fields() {
        // The whole reason `MintedToken` exists as a distinct type is to
        // make the (token, grant) pair come apart together so the audit
        // record can't drift from what was actually issued. Pin that: the
        // resulting grant must carry the same jti, issued_at, expires_at,
        // and scope that the minter captured.
        let server = MockServer::start().await;
        let (expiry_ts, expiry_str) = expiry_seconds_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(mock_mint_response(&expiry_str))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let requested_scope = write_scope("o", "n");
        let minted = minter
            .mint(requested_scope.clone(), TtlSeconds::new(3600).unwrap())
            .await
            .unwrap();

        let captured_jti = minted.jti();
        let captured_issued_at = minted.issued_at();
        let captured_expires_at = minted.expires_at();
        assert_eq!(minted.scope(), &requested_scope);

        let request_id = RequestId::new();
        let session_id = SessionId::new();
        let (token, grant) = minted.into_grant_and_token(request_id, session_id);

        assert_eq!(token, "ghs_fake_value");
        assert_eq!(grant.jti, captured_jti);
        assert_eq!(grant.request_id, request_id);
        assert_eq!(grant.session_id, session_id);
        assert_eq!(grant.issued_at, captured_issued_at);
        assert_eq!(grant.expires_at, captured_expires_at);
        assert_eq!(grant.expires_at.as_i64(), expiry_ts);
        assert_eq!(grant.scope, GrantedScope::GitHub(requested_scope));
    }

    #[test]
    fn api_error_display_truncates_long_bodies() {
        let long_body = "x".repeat(API_ERROR_DISPLAY_CAP * 10);
        let err = MintError::ApiError {
            status: 500,
            body: long_body.clone(),
        };
        let shown = format!("{err}");
        assert!(
            shown.len() < long_body.len(),
            "display should be shorter than raw body"
        );
        assert!(
            shown.contains("... (truncated)"),
            "truncation marker missing: {shown}"
        );
    }

    #[test]
    fn api_error_display_leaves_short_bodies_intact() {
        let body = "{\"message\": \"Not Found\"}";
        let err = MintError::ApiError {
            status: 404,
            body: body.to_string(),
        };
        let shown = format!("{err}");
        assert!(shown.contains(body), "short body should not be truncated: {shown}");
        assert!(!shown.contains("truncated"));
    }

    #[test]
    fn api_error_display_handles_multibyte_boundary() {
        // If truncation sliced on byte boundaries rather than char
        // boundaries, a body containing multi-byte scalars right at the
        // cap would panic. Exercise that path explicitly.
        let body = "é".repeat(API_ERROR_DISPLAY_CAP * 2);
        let err = MintError::ApiError {
            status: 422,
            body,
        };
        let _ = format!("{err}");
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
