//! ChatGPT-login OAuth bundle handling for the OpenAI proxy.
//!
//! The broker holds a single ChatGPT auth bundle (the contents of a
//! codex `auth.json`) in the secret store. On each upstream request, the
//! [`ChatgptOauthAuthority`] consults the in-memory copy, refreshes the
//! `access_token` against `https://auth.openai.com/oauth/token` when it
//! is close to expiry, and yields the headers that the OpenAI Responses
//! API expects (`Authorization: Bearer …`, `ChatGPT-Account-ID: …`, and
//! conditionally `X-OpenAI-Fedramp: true`).
//!
//! Persistence model:
//!
//! * The bundle is the raw JSON blob written by `codex login` (a
//!   `tokens` object plus `last_refresh`). We treat it as opaque enough
//!   that the broker can hand back the same bytes after a successful
//!   refresh.
//! * On a *permanent* refresh failure (`refresh_token_expired`,
//!   `refresh_token_reused`, or `refresh_token_invalidated`) the
//!   authority deletes the secret-store entry and surfaces
//!   `chatgpt_oauth_login_required` so the operator gets a clear signal.
//! * On a *transient* refresh failure (network error, 5xx) the cache is
//!   left intact and the request fails with
//!   `chatgpt_oauth_refresh_transient`.
//! * When a refresh *succeeds* upstream but the durable write back to the
//!   secret store fails, the cache keeps the freshly rotated tokens (the
//!   old refresh token is now spent, so reverting would strand the
//!   session). The refreshing request surfaces the `SecretStore` error,
//!   but the cache is flagged as ahead of durable storage and later
//!   requests keep serving the valid cached token while retrying the
//!   write until it lands. See [`ChatgptOauthAuthority::current_headers`]
//!   for the full envelope.
//!
//! Concurrency: a single [`tokio::sync::Mutex`] serialises all access to
//! the cached bundle. That makes refreshes single-shot — concurrent
//! requests queue behind the lock and observe the freshly refreshed
//! token rather than each launching their own refresh.

use std::sync::Arc;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::secret::{SecretError, SecretKey, SecretStore};

/// Codex's first-party OAuth client id. Required by the refresh flow.
pub const CHATGPT_OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

/// Production refresh-token endpoint.
pub const CHATGPT_OAUTH_REFRESH_URL: &str = "https://auth.openai.com/oauth/token";

/// Refresh `access_token` if it would expire within this many seconds.
/// Matches codex's "imminently expiring" notion with a small safety
/// margin so a request that wins the lock right before expiry doesn't
/// race the upstream clock.
pub const CHATGPT_OAUTH_REFRESH_LEEWAY_SECONDS: i64 = 60;

/// Mirror of codex's `AuthDotJson`. Field names match the on-disk JSON
/// codex itself produces so that the same blob round-trips cleanly.
///
/// `Debug` is hand-rolled to redact `openai_api_key` and to delegate to
/// `ChatgptTokens`'s own redacting `Debug`: a stray `{bundle:?}` (or a
/// debug print of the enclosing `ChatgptOauthState::Loaded`) would
/// otherwise spray live credentials into logs.
#[derive(Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ChatgptAuthBundle {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,
    #[serde(
        rename = "OPENAI_API_KEY",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub openai_api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<ChatgptTokens>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refresh: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<String>,
}

impl std::fmt::Debug for ChatgptAuthBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatgptAuthBundle")
            .field("auth_mode", &self.auth_mode)
            .field(
                "openai_api_key",
                &self.openai_api_key.as_ref().map(|_| "<redacted>"),
            )
            .field("tokens", &self.tokens)
            .field("last_refresh", &self.last_refresh)
            .field("agent_identity", &self.agent_identity)
            .finish()
    }
}

/// Mirror of codex's `TokenData`.
///
/// `Debug` is hand-rolled to redact the three credential strings: a
/// stray `{tokens:?}` would otherwise dump live tokens.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct ChatgptTokens {
    /// Raw JWT string. Codex parses claims out of this; we only need
    /// `chatgpt_account_id` / `chatgpt_account_is_fedramp`, plus `exp`
    /// for the optional account-level expiry signal.
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

impl std::fmt::Debug for ChatgptTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatgptTokens")
            .field("id_token", &"<redacted>")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("account_id", &self.account_id)
            .finish()
    }
}

/// Parsed claims from a ChatGPT id_token. We only decode the fields we
/// need to populate request headers; everything else is ignored.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChatgptIdTokenInfo {
    pub chatgpt_account_id: Option<String>,
    pub chatgpt_account_is_fedramp: bool,
}

/// Headers to inject on an outgoing OpenAI Responses request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatgptUpstreamHeaders {
    pub access_token: String,
    pub account_id: Option<String>,
    pub is_fedramp_account: bool,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum JwtPayloadError {
    #[error("JWT must have header.payload.signature with non-empty parts")]
    InvalidFormat,
    #[error("JWT payload is not valid base64url")]
    InvalidBase64,
    #[error("JWT payload is not valid JSON")]
    InvalidJson,
}

/// Decode the unsigned payload of a JWT. We deliberately do not verify
/// the signature: the JWT was minted by ChatGPT and we trust that the
/// secret-store contents came from a trusted operator. We only read
/// claims to make refresh decisions and populate request headers.
pub fn decode_jwt_payload<T>(jwt: &str) -> Result<T, JwtPayloadError>
where
    T: serde::de::DeserializeOwned,
{
    let mut parts = jwt.split('.');
    let payload = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) if !h.is_empty() && !p.is_empty() && !s.is_empty() => p,
        _ => return Err(JwtPayloadError::InvalidFormat),
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| JwtPayloadError::InvalidBase64)?;
    serde_json::from_slice(&bytes).map_err(|_| JwtPayloadError::InvalidJson)
}

#[derive(Deserialize)]
struct ExpClaim {
    #[serde(default)]
    exp: Option<i64>,
}

/// Read the `exp` claim from a JWT payload. `Ok(None)` when the JWT
/// parses but has no `exp` field; `Err(_)` when the JWT is malformed.
pub fn parse_jwt_expiration(jwt: &str) -> Result<Option<i64>, JwtPayloadError> {
    let claim: ExpClaim = decode_jwt_payload(jwt)?;
    Ok(claim.exp)
}

#[derive(Deserialize)]
struct ChatgptIdClaims {
    #[serde(rename = "https://api.openai.com/auth", default)]
    auth: Option<ChatgptIdAuthClaims>,
}

#[derive(Deserialize, Default)]
struct ChatgptIdAuthClaims {
    #[serde(default)]
    chatgpt_account_id: Option<String>,
    #[serde(default)]
    chatgpt_account_is_fedramp: bool,
}

/// Read the ChatGPT-specific claims out of the id_token. Missing claims
/// turn into defaults — we never fail the request just because the
/// optional fedramp flag was absent.
pub fn parse_chatgpt_id_token_info(jwt: &str) -> Result<ChatgptIdTokenInfo, JwtPayloadError> {
    let claims: ChatgptIdClaims = decode_jwt_payload(jwt)?;
    let auth = claims.auth.unwrap_or_default();
    Ok(ChatgptIdTokenInfo {
        chatgpt_account_id: auth.chatgpt_account_id,
        chatgpt_account_is_fedramp: auth.chatgpt_account_is_fedramp,
    })
}

/// Decision returned by [`refresh_decision`]: should the broker refresh
/// the access_token before sending the next request?
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RefreshDecision {
    /// Token is unparsable — we cannot prove it is valid, so refresh.
    /// On reject this folds into "permanent failure → login required".
    UnparsableJwt,
    /// Token expires within the leeway window or has already expired.
    Stale,
    /// Token is good enough to use as-is.
    Fresh,
}

pub fn refresh_decision(
    access_token_jwt: &str,
    now_unix_seconds: i64,
    leeway_seconds: i64,
) -> RefreshDecision {
    let exp = match parse_jwt_expiration(access_token_jwt) {
        Ok(Some(exp)) => exp,
        Ok(None) => return RefreshDecision::UnparsableJwt,
        Err(_) => return RefreshDecision::UnparsableJwt,
    };
    if now_unix_seconds + leeway_seconds >= exp {
        RefreshDecision::Stale
    } else {
        RefreshDecision::Fresh
    }
}

/// Wire shape of POST `/oauth/token`. Mirrors codex's `RefreshRequest`.
#[derive(Serialize)]
pub struct ChatgptRefreshRequestBody<'a> {
    pub client_id: &'a str,
    pub grant_type: &'static str,
    pub refresh_token: &'a str,
}

/// Wire shape of a successful refresh response.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct ChatgptRefreshResponseBody {
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Outcome categories of a refresh attempt. The wire details (HTTP
/// status, JSON body) live in the categoriser, not here.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RefreshOutcomeKind {
    /// Successful refresh; new tokens have been merged into the bundle.
    Success,
    /// Permanent: refresh token is dead. Caller should delete the
    /// secret and surface `chatgpt_oauth_login_required`.
    LoginRequired,
    /// Transient: keep the bundle, surface
    /// `chatgpt_oauth_refresh_transient`.
    Transient,
}

/// Categorise an HTTP response from the refresh endpoint into a
/// [`RefreshOutcomeKind`]. 401 with one of the known error codes is
/// permanent; everything else (5xx, network) is transient.
pub fn classify_refresh_failure_status(status: u16) -> RefreshOutcomeKind {
    if status == 401 {
        // The body decides; this conservatively flags as permanent.
        // Use [`classify_refresh_failure_body`] to refine when the body
        // is available.
        RefreshOutcomeKind::LoginRequired
    } else {
        RefreshOutcomeKind::Transient
    }
}

/// Refine the classification using the response body. Codex treats
/// `refresh_token_expired/reused/invalidated` as permanent and any
/// other 401 body as permanent too (the user's only recourse is
/// re-login). The status check has already filtered to 401.
pub fn classify_refresh_failure_body(body: &str) -> RefreshOutcomeKind {
    // We deliberately accept any 401 as permanent. Codex's classifier
    // exposes finer-grained reasons but they all map to "user must
    // re-login" from our perspective. Distinguishing them adds no
    // operational value.
    let _ = body;
    RefreshOutcomeKind::LoginRequired
}

/// Apply a refresh response to a bundle. Fields not returned by the
/// upstream are preserved (codex itself rotates only on demand).
pub fn apply_refresh_response(
    bundle: &mut ChatgptAuthBundle,
    response: &ChatgptRefreshResponseBody,
    now_rfc3339: String,
) -> Result<(), &'static str> {
    let Some(tokens) = bundle.tokens.as_mut() else {
        return Err("bundle is missing tokens; refresh would create them out of thin air");
    };
    if let Some(id_token) = &response.id_token {
        tokens.id_token = id_token.clone();
    }
    if let Some(access_token) = &response.access_token {
        tokens.access_token = access_token.clone();
    }
    if let Some(refresh_token) = &response.refresh_token {
        tokens.refresh_token = refresh_token.clone();
    }
    bundle.last_refresh = Some(now_rfc3339);
    Ok(())
}

/// Errors visible to the proxy layer. These map 1:1 to audit error
/// labels so the wiring code can route them without inspecting fields.
#[derive(Debug, thiserror::Error)]
pub enum ChatgptOauthError {
    /// The secret store has no bundle. The operator never seeded one
    /// or the previous attempt deleted it.
    #[error("ChatGPT auth bundle is missing; operator must run `writ secret put` again")]
    LoginRequired,
    /// Network/5xx during refresh; cache untouched.
    #[error("ChatGPT auth refresh transiently failed: {0}")]
    RefreshTransient(String),
    /// Secret store I/O failed.
    #[error("secret store I/O failed: {0}")]
    SecretStore(#[from] SecretError),
    /// Bundle JSON malformed; treat as login-required.
    #[error("ChatGPT auth bundle is malformed: {0}")]
    BundleMalformed(String),
}

impl ChatgptOauthError {
    /// Stable label for audit `error` field.
    pub fn audit_error_label(&self) -> &'static str {
        match self {
            ChatgptOauthError::LoginRequired => "chatgpt_oauth_login_required",
            ChatgptOauthError::RefreshTransient(_) => "chatgpt_oauth_refresh_transient",
            ChatgptOauthError::SecretStore(_) => "upstream auth load failed",
            ChatgptOauthError::BundleMalformed(_) => "chatgpt_oauth_login_required",
        }
    }
}

/// Configuration for [`ChatgptOauthAuthority`].
///
/// The clock and HTTP client are injected so tests can drive both
/// (deterministic `now()` + a wiremock refresh endpoint). The secret
/// store is *not* held by the authority; it is passed in per-call to
/// [`ChatgptOauthAuthority::current_headers`] so the authority does
/// not have to own an `Arc<S>` clone of the broker's store.
pub struct ChatgptOauthAuthorityConfig {
    pub secret_key: SecretKey,
    pub refresh_url: reqwest::Url,
    pub http_client: reqwest::Client,
    pub clock: Arc<dyn ChatgptOauthClock>,
    pub leeway_seconds: i64,
}

/// Source of "now". Production uses [`SystemClock`]; tests use a fake.
pub trait ChatgptOauthClock: Send + Sync {
    fn now_unix_seconds(&self) -> i64;
    fn now_rfc3339(&self) -> String;
}

/// Production clock: wall-clock UTC.
pub struct SystemClock;

impl ChatgptOauthClock for SystemClock {
    fn now_unix_seconds(&self) -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }

    fn now_rfc3339(&self) -> String {
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default()
    }
}

/// Holds the cached bundle and serialises refreshes.
pub struct ChatgptOauthAuthority {
    config: ChatgptOauthAuthorityConfig,
    state: Mutex<ChatgptOauthState>,
}

#[derive(Debug)]
enum ChatgptOauthState {
    /// We have not yet attempted to load the bundle from the secret store.
    Cold,
    /// A bundle is cached. `needs_persist` records that the cached bundle
    /// is *ahead* of durable storage — a refresh rotated the tokens in
    /// memory but the subsequent `put` failed. While set, every
    /// [`ChatgptOauthAuthority::current_headers`] call retries the durable
    /// write so the gap closes as soon as the secret store recovers. A
    /// bundle freshly loaded from the store is in sync, so it starts
    /// `false`.
    Loaded {
        bundle: ChatgptAuthBundle,
        needs_persist: bool,
    },
}

impl ChatgptOauthAuthority {
    pub fn new(config: ChatgptOauthAuthorityConfig) -> Self {
        Self {
            config,
            state: Mutex::new(ChatgptOauthState::Cold),
        }
    }

    /// Resolve the headers to attach to the next upstream request.
    ///
    /// Order of operations:
    ///   1. Acquire the state lock (refresh serialised).
    ///   2. Load the bundle from the secret store on cold start.
    ///   3. Flush any write left pending by an earlier refresh whose `put`
    ///      failed, so durable storage is repaired before we risk another
    ///      refresh.
    ///   4. Inspect the cached `access_token` JWT. If it is stale (or
    ///      unparseable), call `/oauth/token`.
    ///   5. Persist any successful refresh back to the secret store
    ///      before returning the new headers.
    ///
    /// Persistence-failure envelope: a refresh mutates the in-memory
    /// bundle with the freshly rotated tokens *before* it attempts the
    /// durable `put`, and never reverts that mutation — the upstream has
    /// already invalidated the old refresh token, so the new one is the
    /// only usable credential and must not be discarded. If the `put`
    /// fails, the refreshing call surfaces the error (`SecretStore`) but
    /// the cache retains the new token and is flagged as ahead of durable
    /// storage; subsequent calls keep serving the valid cached token and
    /// retry the write until it lands. The only unrecoverable window is a
    /// process restart between the failed write and a later successful
    /// one, which loads the stale (spent) durable token and forces a
    /// re-login.
    pub async fn current_headers<S: SecretStore + ?Sized>(
        &self,
        secret_store: &S,
    ) -> Result<ChatgptUpstreamHeaders, ChatgptOauthError> {
        let mut state = self.state.lock().await;
        if matches!(&*state, ChatgptOauthState::Cold) {
            let loaded = load_bundle_from_secret_store(secret_store, &self.config.secret_key)?;
            *state = ChatgptOauthState::Loaded {
                bundle: loaded,
                needs_persist: false,
            };
        }

        // If an earlier refresh left the cache ahead of durable storage,
        // flush it now — before any refresh below, which could itself fail
        // transiently and otherwise leave the spent refresh token durable.
        // Best-effort: a still-failing write must not fail this request,
        // since the cached token is valid.
        self.retry_pending_persist(secret_store, &mut state);

        // Judge freshness *after* the flush: `put` is synchronous and
        // unbounded, so a barely-fresh token could cross into expiry while
        // the flush blocks. Reading `now` here keeps the decision honest.
        let bundle = match &*state {
            ChatgptOauthState::Loaded { bundle, .. } => bundle,
            ChatgptOauthState::Cold => unreachable!("loaded above"),
        };
        let tokens = bundle
            .tokens
            .as_ref()
            .ok_or_else(|| ChatgptOauthError::BundleMalformed("missing tokens".into()))?;
        let decision = refresh_decision(
            &tokens.access_token,
            self.config.clock.now_unix_seconds(),
            self.config.leeway_seconds,
        );
        if decision != RefreshDecision::Fresh {
            self.refresh(secret_store, &mut state).await?;
        }

        let bundle = match &*state {
            ChatgptOauthState::Loaded { bundle, .. } => bundle,
            ChatgptOauthState::Cold => unreachable!("loaded above"),
        };
        let tokens = bundle.tokens.as_ref().ok_or_else(|| {
            ChatgptOauthError::BundleMalformed("missing tokens after refresh".into())
        })?;
        let id_info = parse_chatgpt_id_token_info(&tokens.id_token)
            .map_err(|err| ChatgptOauthError::BundleMalformed(format!("id_token: {err}")))?;
        // The id_token's `chatgpt_account_id` claim is the source of
        // truth post-refresh. `tokens.account_id` is a legacy field
        // that codex writes once at login and never updates; if the
        // user rotates workspaces, only the id_token reflects it. Fall
        // back to the legacy field only when the id_token has no claim.
        let account_id = id_info
            .chatgpt_account_id
            .clone()
            .or_else(|| tokens.account_id.clone());
        Ok(ChatgptUpstreamHeaders {
            access_token: tokens.access_token.clone(),
            account_id,
            is_fedramp_account: id_info.chatgpt_account_is_fedramp,
        })
    }

    async fn refresh<S: SecretStore + ?Sized>(
        &self,
        secret_store: &S,
        state: &mut ChatgptOauthState,
    ) -> Result<(), ChatgptOauthError> {
        let ChatgptOauthState::Loaded { bundle, .. } = state else {
            unreachable!("refresh requires Loaded state");
        };
        let refresh_token = bundle
            .tokens
            .as_ref()
            .ok_or_else(|| ChatgptOauthError::BundleMalformed("missing tokens".into()))?
            .refresh_token
            .clone();
        let body = ChatgptRefreshRequestBody {
            client_id: CHATGPT_OAUTH_CLIENT_ID,
            grant_type: "refresh_token",
            refresh_token: &refresh_token,
        };
        let response = self
            .config
            .http_client
            .post(self.config.refresh_url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|err| ChatgptOauthError::RefreshTransient(err.to_string()))?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            let raw_body = response.text().await.unwrap_or_default();
            return self.handle_refresh_failure(secret_store, state, status, &raw_body);
        }
        let parsed: ChatgptRefreshResponseBody = response
            .json()
            .await
            .map_err(|err| ChatgptOauthError::RefreshTransient(err.to_string()))?;
        let now = self.config.clock.now_rfc3339();

        let ChatgptOauthState::Loaded {
            bundle,
            needs_persist,
        } = state
        else {
            unreachable!("refresh requires Loaded state");
        };
        // Mutate the cache with the rotated tokens *before* persisting. The
        // upstream has invalidated the old refresh token, so the new token
        // is now the only usable credential — we must not lose it, even if
        // the durable write below fails.
        apply_refresh_response(bundle, &parsed, now)
            .map_err(|err| ChatgptOauthError::BundleMalformed(err.to_string()))?;
        match persist_bundle(secret_store, &self.config.secret_key, bundle) {
            Ok(()) => {
                *needs_persist = false;
                Ok(())
            }
            Err(err) => {
                // The cache holds the freshly rotated tokens; flag it as
                // ahead of durable storage so a later call retries the
                // write, and surface the failure now.
                *needs_persist = true;
                Err(err)
            }
        }
    }

    /// Best-effort retry of a durable write that a prior [`Self::refresh`]
    /// left pending. A no-op unless the cache is flagged as ahead of
    /// durable storage. A persist failure here is swallowed (logged): the
    /// cached token is valid, so the request proceeds and the flag stays
    /// set for the next attempt.
    fn retry_pending_persist<S: SecretStore + ?Sized>(
        &self,
        secret_store: &S,
        state: &mut ChatgptOauthState,
    ) {
        let ChatgptOauthState::Loaded {
            bundle,
            needs_persist,
        } = state
        else {
            return;
        };
        if !*needs_persist {
            return;
        }
        match persist_bundle(secret_store, &self.config.secret_key, bundle) {
            Ok(()) => *needs_persist = false,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "chatgpt oauth durable persist still failing; serving valid cached token",
                );
            }
        }
    }

    fn handle_refresh_failure<S: SecretStore + ?Sized>(
        &self,
        secret_store: &S,
        state: &mut ChatgptOauthState,
        status: u16,
        body: &str,
    ) -> Result<(), ChatgptOauthError> {
        let kind = match classify_refresh_failure_status(status) {
            RefreshOutcomeKind::Success => unreachable!("non-success status"),
            RefreshOutcomeKind::LoginRequired => classify_refresh_failure_body(body),
            RefreshOutcomeKind::Transient => RefreshOutcomeKind::Transient,
        };
        match kind {
            RefreshOutcomeKind::Success => unreachable!("non-success branch"),
            RefreshOutcomeKind::LoginRequired => {
                secret_store.delete(&self.config.secret_key)?;
                *state = ChatgptOauthState::Cold;
                Err(ChatgptOauthError::LoginRequired)
            }
            RefreshOutcomeKind::Transient => Err(ChatgptOauthError::RefreshTransient(format!(
                "refresh status {status}: {}",
                truncate_for_log(body)
            ))),
        }
    }
}

/// Serialize the bundle and write it to the secret store. A serialization
/// failure is reported as `BundleMalformed`; a store failure propagates as
/// `SecretStore`.
fn persist_bundle<S: SecretStore + ?Sized>(
    secret_store: &S,
    secret_key: &SecretKey,
    bundle: &ChatgptAuthBundle,
) -> Result<(), ChatgptOauthError> {
    let serialized = serde_json::to_string(bundle).map_err(|_| {
        ChatgptOauthError::BundleMalformed("failed to serialize refreshed bundle".into())
    })?;
    secret_store.put(secret_key, &serialized)?;
    Ok(())
}

fn load_bundle_from_secret_store<S: SecretStore + ?Sized>(
    secret_store: &S,
    secret_key: &SecretKey,
) -> Result<ChatgptAuthBundle, ChatgptOauthError> {
    let raw = secret_store
        .get(secret_key)?
        .ok_or(ChatgptOauthError::LoginRequired)?;
    let bundle: ChatgptAuthBundle = serde_json::from_str(&raw).map_err(|err| {
        // serde_json's Display includes the offending input fragment for some
        // failures (e.g. "unknown variant `<value>`"), and the bundle holds
        // tokens — surface only the position so logs cannot leak fragments.
        ChatgptOauthError::BundleMalformed(format!(
            "invalid JSON at line {} column {}",
            err.line(),
            err.column()
        ))
    })?;
    if bundle.tokens.is_none() {
        return Err(ChatgptOauthError::BundleMalformed("missing tokens".into()));
    }
    Ok(bundle)
}

fn truncate_for_log(body: &str) -> String {
    const CAP: usize = 256;
    if body.chars().count() <= CAP {
        body.to_string()
    } else {
        let head: String = body.chars().take(CAP).collect();
        format!("{head}…")
    }
}

#[cfg(test)]
#[path = "openai_chatgpt_auth/tests.rs"]
mod tests;
