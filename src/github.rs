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
    CredentialGrant, GitHubGrantedScope, GitHubPermissions, GrantedScope, Jti, RepoRef, RequestId,
    SessionId, TtlSeconds, UnixMillis,
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
    /// The user or organisation that owns the installation. GitHub's
    /// `POST /app/installations/{id}/access_tokens` endpoint takes an
    /// *unqualified* `repositories` list, which the installation resolves
    /// against its own set. A request asking for `openai/agent-infra` on
    /// an installation that owns `patrick/agent-infra` would otherwise
    /// mint a token for the wrong repo while the audit row claimed the
    /// requested one. Keeping the installation owner in config lets the
    /// minter reject the request before any token is issued.
    pub installation_owner: String,
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
/// actually handed to the agent (wrong `jti`, a fresh `UnixMillis::now()`
/// instead of the broker-clock reading the TTL check validated, a scope
/// different from the one the minter signed for).
///
/// `Debug` is hand-rolled to redact the token string: a stray
/// `tracing::debug!({minted:?})` or `dbg!` would otherwise spray a live
/// credential into logs. All other fields are safe to print.
pub struct MintedToken {
    token: String,
    jti: Jti,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
    scope: GitHubGrantedScope,
}

impl std::fmt::Debug for MintedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedToken")
            .field("token", &"<redacted>")
            .field("jti", &self.jti)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish()
    }
}

impl MintedToken {
    /// Broker-clock timestamp captured immediately before the mint request
    /// went out, and the reference against which GitHub's `expires_at` was
    /// compared for the TTL check.
    pub fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }

    /// The expiry GitHub said it will enforce. Authoritative.
    pub fn expires_at(&self) -> UnixMillis {
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
            .user_agent("writ/0.1")
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
        // GitHub's `POST /access_tokens` takes an unqualified `repositories`
        // list and resolves it against the installation, so a request whose
        // owner doesn't match this installation would otherwise silently
        // mint a same-named repo belonging to the installation's owner.
        // Reject before signing anything.
        //
        // GitHub resolves owner and repo names case-insensitively (it even
        // returns responses in the *canonical* casing, not the casing the
        // caller sent), so compare that way here too. Otherwise a config
        // with `installation_owner = "smaug123"` against a canonical login
        // of `Smaug123` would spuriously reject every request.
        if !scope
            .repository
            .owner
            .eq_ignore_ascii_case(&self.config.installation_owner)
        {
            return Err(MintError::RepoNotInInstallation {
                requested: scope.repository.clone(),
                installation_owner: self.config.installation_owner.clone(),
            });
        }

        let pem = self
            .secrets
            .get(&self.config.private_key_secret)?
            .ok_or_else(|| MintError::PrivateKeyMissing(self.config.private_key_secret.clone()))?;

        // Broker clock at mint start, kept at millisecond resolution for
        // the audit record. JWT `iat` is a whole-seconds claim, so the
        // signing step only sees the floored value.
        let issued_at = UnixMillis::now();
        let issued_at_seconds = issued_at.as_seconds_floor();
        let jwt = sign_jwt(&pem, self.config.app_id, issued_at_seconds)?;

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
        // Defence-in-depth: GitHub should never return a 2xx with an empty
        // or whitespace-only token, but handing one to the agent would
        // still record a successful grant for a credential that can't
        // possibly authenticate. Bail loudly.
        if parsed.token.trim().is_empty() {
            return Err(MintError::EmptyToken);
        }

        // Verify GitHub minted the scope we asked for. We always request a
        // single named repository, so a successful response must be
        // repository_selection=selected and must enumerate exactly that repo.
        // `all` means GitHub returned a token covering the whole installation,
        // which is broader than the one-repo audit row we would record.
        //
        // The check has to be *exact*: if GitHub returned `[o/n, o/other]`
        // when we asked for `o/n`, the token is genuinely broader than the
        // audit row would claim — recording a one-repo scope for a token
        // that covers two would be the silent over-grant this whole boundary
        // exists to prevent. So reject on any extra entry as well as on a
        // missing one.
        //
        // GitHub returns `full_name` in the repo's canonical casing, which
        // need not match the casing the caller supplied. Compare
        // case-insensitively to match GitHub's own resolution semantics.
        let expected = scope.repository.to_string();
        match parsed.repository_selection {
            RepositorySelection::Selected => {
                let matches_expected = parsed.repositories.len() == 1
                    && parsed.repositories[0]
                        .full_name
                        .eq_ignore_ascii_case(&expected);
                if !matches_expected {
                    return Err(MintError::UnexpectedRepositories {
                        requested: scope.repository.clone(),
                        returned: parsed
                            .repositories
                            .iter()
                            .map(|r| r.full_name.clone())
                            .collect(),
                    });
                }
            }
            RepositorySelection::All => {
                return Err(MintError::UnexpectedRepositorySelection {
                    requested: scope.repository.clone(),
                    returned: "all",
                });
            }
        }
        if parsed.permissions != scope.permissions {
            return Err(MintError::UnexpectedPermissions {
                requested: scope.permissions.clone(),
                returned: parsed.permissions,
            });
        }

        // GitHub's `expires_at` is whole-seconds-precision, so the TTL
        // comparisons below stay in seconds and the audit record gets
        // the timestamp lifted to millisecond space on the second boundary.
        let expires_at_seconds = parse_rfc3339_seconds(&parsed.expires_at)?;

        // Defence-in-depth: GitHub should never return a token expiring at
        // or before our issue time, but if it did we'd otherwise happily
        // record a grant that was already dead and hand the agent a
        // useless token. Bail loudly instead.
        if expires_at_seconds <= issued_at_seconds {
            return Err(MintError::ExpiryNotInFuture {
                issued_at: issued_at_seconds,
                actual_expires_at: expires_at_seconds,
            });
        }

        let max_allowed = issued_at_seconds + ttl.as_i64() + TTL_SKEW_TOLERANCE_SECONDS;
        if expires_at_seconds > max_allowed {
            return Err(MintError::TtlExceeded {
                ttl_seconds: ttl.as_i64(),
                issued_at: issued_at_seconds,
                actual_expires_at: expires_at_seconds,
            });
        }

        Ok(MintedToken {
            token: parsed.token,
            jti: Jti::new(),
            issued_at,
            expires_at: UnixMillis::from_seconds(expires_at_seconds),
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
    #[error("GitHub returned a 2xx response with an empty token string")]
    EmptyToken,
    #[error(
        "requested repository {requested} is not owned by the configured installation \
         (owner {installation_owner:?})"
    )]
    RepoNotInInstallation {
        requested: RepoRef,
        installation_owner: String,
    },
    #[error(
        "GitHub minted a token whose repository set {returned:?} does not include the requested \
         repository {requested}"
    )]
    UnexpectedRepositories {
        requested: RepoRef,
        returned: Vec<String>,
    },
    #[error(
        "GitHub minted a token with repository_selection={returned:?} while the requested \
         repository was {requested}"
    )]
    UnexpectedRepositorySelection {
        requested: RepoRef,
        returned: &'static str,
    },
    #[error(
        "GitHub minted a token with permissions {returned:?} that do not match the requested \
         permissions {requested:?}"
    )]
    UnexpectedPermissions {
        requested: GitHubPermissions,
        returned: GitHubPermissions,
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
    /// Permissions GitHub actually granted on the token. GitHub may narrow
    /// these from the request (if the App itself lacks the permission on
    /// this installation), so comparing the response against the requested
    /// scope catches silent narrowing that would otherwise leave the audit
    /// log describing stronger authority than the token carries.
    #[serde(default)]
    permissions: GitHubPermissions,
    repository_selection: RepositorySelection,
    /// Populated when `repository_selection` is `selected`. Omitted or
    /// empty under `all`.
    #[serde(default)]
    repositories: Vec<MintResponseRepo>,
}

#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RepositorySelection {
    All,
    Selected,
}

#[derive(Deserialize)]
struct MintResponseRepo {
    full_name: String,
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
    use crate::core::{GitHubAccess, MetadataAccess, RepoRef};
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
                metadata: Some(MetadataAccess::Read),
                ..Default::default()
            },
        }
    }

    fn minter_with_key(server: &MockServer) -> GitHubMinter<InMemStore> {
        minter_with_owner(server, "o")
    }

    fn minter_with_owner(
        server: &MockServer,
        installation_owner: &str,
    ) -> GitHubMinter<InMemStore> {
        let pk = SecretKey::new("gh-app-pk").unwrap();
        let store = InMemStore::default();
        store.put(&pk, TEST_PRIV_1).unwrap();
        GitHubMinter::new(
            GitHubAppConfig {
                app_id: 42,
                installation_id: 999,
                installation_owner: installation_owner.into(),
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
                "repository_selection": "selected",
                "repositories": [{"full_name": "o/n"}]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let minted = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .expect("mint ok");

        assert_eq!(minted.expires_at().as_seconds_floor(), expiry_ts);
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
                installation_owner: "o".into(),
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
        let ts = UnixMillis::now().as_seconds_floor() + secs;
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
            "repository_selection": "selected",
            "repositories": [{"full_name": "o/n"}]
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
        assert!(minted.expires_at().as_millis() > minted.issued_at().as_millis());
    }

    #[tokio::test]
    async fn mint_rejects_expiry_safely_past_skew_tolerance() {
        // Keep a wide margin over the skew boundary so the test remains
        // deterministic even under a slow or highly parallel test run.
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600 + TTL_SKEW_TOLERANCE_SECONDS + 300);
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
        let before = UnixMillis::now().as_millis();
        let minted = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .unwrap();
        let after = UnixMillis::now().as_millis();

        let iat = minted.issued_at().as_millis();
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
        assert_eq!(grant.expires_at.as_seconds_floor(), expiry_ts);
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
        assert!(
            shown.contains(body),
            "short body should not be truncated: {shown}"
        );
        assert!(!shown.contains("truncated"));
    }

    #[test]
    fn api_error_display_handles_multibyte_boundary() {
        // If truncation sliced on byte boundaries rather than char
        // boundaries, a body containing multi-byte scalars right at the
        // cap would panic. Exercise that path explicitly.
        let body = "é".repeat(API_ERROR_DISPLAY_CAP * 2);
        let err = MintError::ApiError { status: 422, body };
        let _ = format!("{err}");
    }

    #[tokio::test]
    async fn mint_rejects_empty_token() {
        // A 2xx response with a blank token would otherwise bank an
        // audit record for a credential that can't authenticate.
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "   ",
                "expires_at": expiry_str,
                "permissions": {"contents": "write", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"full_name": "o/n"}]
            })))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let err = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .expect_err("empty token should be rejected");
        assert!(matches!(err, MintError::EmptyToken), "got: {err:?}");
    }

    #[tokio::test]
    async fn mint_refuses_request_whose_owner_is_not_the_installation_owner() {
        // The installation owns `o/*`. A request for `someone-else/n` shares
        // the name but not the owner; GitHub would resolve it against the
        // installation and silently mint `o/n`, leaving the audit row
        // claiming `someone-else/n`. Reject before the HTTP call.
        let server = MockServer::start().await;
        // Do not mount the mint endpoint: if the minter ever reaches it,
        // wiremock returns 404 and the test will fail loudly on the wrong
        // error variant.
        let minter = minter_with_owner(&server, "o");
        let err = minter
            .mint(
                write_scope("someone-else", "n"),
                TtlSeconds::new(3600).unwrap(),
            )
            .await
            .expect_err("cross-owner request must be refused");
        match err {
            MintError::RepoNotInInstallation {
                requested,
                installation_owner,
            } => {
                assert_eq!(requested.owner, "someone-else");
                assert_eq!(installation_owner, "o");
            }
            other => panic!("expected RepoNotInInstallation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mint_rejects_when_response_lists_a_different_repo() {
        // If GitHub returned a token whose `repositories` didn't include
        // the one we asked for, handing it to the agent would bank an
        // audit row for authority the token can't exercise. Reject.
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_fake_value",
                "expires_at": expiry_str,
                "permissions": {"contents": "write", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"full_name": "o/not-the-one"}]
            })))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let err = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .expect_err("divergent repositories must be rejected");
        match err {
            MintError::UnexpectedRepositories {
                requested,
                returned,
            } => {
                assert_eq!(requested.to_string(), "o/n");
                assert_eq!(returned, vec!["o/not-the-one".to_string()]);
            }
            other => panic!("expected UnexpectedRepositories, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mint_rejects_when_response_lists_extra_repos() {
        // "Selected" responses must enumerate *exactly* the repo we asked
        // for; a superset means the token carries authority the audit row
        // won't describe. Reject even when the requested repo is present.
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_fake_value",
                "expires_at": expiry_str,
                "permissions": {"contents": "write", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [
                    {"full_name": "o/n"},
                    {"full_name": "o/other"}
                ]
            })))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let err = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .expect_err("superset of requested repos must be rejected");
        match err {
            MintError::UnexpectedRepositories {
                requested,
                returned,
            } => {
                assert_eq!(requested.to_string(), "o/n");
                assert_eq!(returned, vec!["o/n".to_string(), "o/other".to_string()]);
            }
            other => panic!("expected UnexpectedRepositories, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mint_rejects_when_response_narrows_permissions() {
        // GitHub may narrow permissions if the App itself lacks the
        // requested level on this installation — e.g. we asked for
        // contents:write, it replies contents:read. Handing the agent a
        // token that's weaker than the audit record claims is a silent
        // authority lie; reject instead.
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_fake_value",
                "expires_at": expiry_str,
                "permissions": {"contents": "read", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"full_name": "o/n"}]
            })))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let err = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .expect_err("narrowed permissions must be rejected");
        assert!(
            matches!(err, MintError::UnexpectedPermissions { .. }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn mint_owner_check_is_case_insensitive() {
        // GitHub treats owner/repo names case-insensitively. A config that
        // says `installation_owner = "smaug123"` against a request whose
        // canonical owner is `Smaug123` must not be refused.
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_fake_value",
                "expires_at": expiry_str,
                "permissions": {"contents": "write", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"full_name": "Smaug123/n"}]
            })))
            .mount(&server)
            .await;

        let minter = minter_with_owner(&server, "smaug123");
        minter
            .mint(write_scope("Smaug123", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .expect("case-mismatched owner within installation should be accepted");
    }

    #[tokio::test]
    async fn mint_accepts_response_with_canonical_casing() {
        // The broker sent the lowercase casing; GitHub echoed back the
        // canonical `Smaug123/WriT`. The repo-enumeration check must
        // accept the match rather than trip UnexpectedRepositories on its
        // own output.
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_fake_value",
                "expires_at": expiry_str,
                "permissions": {"contents": "write", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"full_name": "Smaug123/WriT"}]
            })))
            .mount(&server)
            .await;

        let minter = minter_with_owner(&server, "smaug123");
        minter
            .mint(
                write_scope("smaug123", "writ"),
                TtlSeconds::new(3600).unwrap(),
            )
            .await
            .expect("canonical-cased response must match case-insensitively");
    }

    #[tokio::test]
    async fn mint_rejects_response_with_unknown_permission_key() {
        // GitHub adds a new App permission we don't yet model, and echoes
        // it back on the token. The default serde behaviour would silently
        // drop the unknown field, letting an over-grant slip past the
        // widening check. `deny_unknown_fields` on GitHubPermissions turns
        // this into a response parse failure, which surfaces as
        // MintError::Http (the json body cannot be deserialised into
        // MintResponse).
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_fake_value",
                "expires_at": expiry_str,
                "permissions": {
                    "contents": "write",
                    "metadata": "read",
                    "workflows": "write"
                },
                "repository_selection": "selected",
                "repositories": [{"full_name": "o/n"}]
            })))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let err = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .expect_err("unknown permission in response must not be silently accepted");
        // reqwest wraps serde_json failures as a generic Http error.
        assert!(matches!(err, MintError::Http(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn mint_rejects_repository_selection_all() {
        // The broker requested a one-repo token. If GitHub replies that the
        // token covers "all" repos, the token is broader than the audit row
        // would describe, so reject instead of handing it to the agent.
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .and(body_json(serde_json::json!({
                "repositories": ["n"],
                "permissions": {"contents": "write", "metadata": "read"}
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_fake_value",
                "expires_at": expiry_str,
                "permissions": {"contents": "write", "metadata": "read"},
                "repository_selection": "all"
            })))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let err = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .expect_err("all-repos token must be rejected");
        match err {
            MintError::UnexpectedRepositorySelection {
                requested,
                returned,
            } => {
                assert_eq!(requested.to_string(), "o/n");
                assert_eq!(returned, "all");
            }
            other => panic!("expected UnexpectedRepositorySelection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn minted_token_debug_redacts_token_string() {
        // A stray `{minted:?}` in a log line must not spray the live
        // credential. Every other field stays printable so debug output
        // remains useful.
        let server = MockServer::start().await;
        let (_, expiry_str) = expiry_seconds_from_now(3600);
        Mock::given(method("POST"))
            .and(path("/app/installations/999/access_tokens"))
            .respond_with(mock_mint_response(&expiry_str))
            .mount(&server)
            .await;

        let minter = minter_with_key(&server);
        let minted = minter
            .mint(write_scope("o", "n"), TtlSeconds::new(3600).unwrap())
            .await
            .unwrap();

        let shown = format!("{minted:?}");
        assert!(
            !shown.contains("ghs_fake_value"),
            "Debug output leaked token string: {shown}"
        );
        assert!(
            shown.contains("<redacted>"),
            "expected redaction marker: {shown}"
        );
        assert!(
            shown.contains("jti"),
            "other fields should still render: {shown}"
        );
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
