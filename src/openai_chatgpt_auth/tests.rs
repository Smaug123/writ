use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use base64::Engine as _;
use proptest::prelude::*;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::secret::{SecretError, SecretKey, SecretStore};

use super::*;

#[derive(Default)]
struct InMemStore {
    map: StdMutex<HashMap<String, String>>,
    /// When set, every `put` fails with a simulated store error. Lets a
    /// test drive the "refresh succeeded upstream but the durable write
    /// failed" path, then "repair" the store to watch the cache heal.
    fail_puts: AtomicBool,
    /// Simulates wall-clock time elapsing inside a (possibly slow) `put`:
    /// each successful write advances the shared clock by this many
    /// seconds. Lets a test prove that token freshness is judged *after*
    /// the pending-persist flush, not before.
    put_clock: StdMutex<Option<(Arc<FakeClock>, i64)>>,
    /// Number of `get`s served so far, and — if set — the count after which
    /// every subsequent `get` deletes the entry and returns `None`. Models an
    /// operator revoking the secret out-of-band *during* an operation (e.g.
    /// between the reconcile read and the guarded write-back of a refresh).
    get_count: AtomicUsize,
    revoke_after_gets: StdMutex<Option<usize>>,
    /// After this many `get`s, every subsequent `get` first overwrites the
    /// entry with the given value (a concurrent operator *replacement*), then
    /// returns it.
    replace_after_gets: StdMutex<Option<(usize, String)>>,
    /// Total `put`s attempted (including those that error), so a test can
    /// observe whether a durability-confirming re-write happened.
    put_count: AtomicUsize,
    /// When set, `put` persists the value but *then* returns an error —
    /// modelling `FileSecretStore::put`, whose `rename` makes the new bytes
    /// visible to `get` before the parent-directory fsync that can fail.
    put_persists_but_errors: AtomicBool,
}

impl SecretStore for InMemStore {
    fn get(&self, key: &SecretKey) -> Result<Option<String>, SecretError> {
        let served = self.get_count.fetch_add(1, Ordering::SeqCst) + 1;
        if matches!(*self.revoke_after_gets.lock().unwrap(), Some(after) if served > after) {
            self.map.lock().unwrap().remove(key.as_str());
            return Ok(None);
        }
        if let Some((_, value)) = self
            .replace_after_gets
            .lock()
            .unwrap()
            .clone()
            .filter(|(after, _)| served > *after)
        {
            self.map
                .lock()
                .unwrap()
                .insert(key.as_str().to_string(), value);
        }
        Ok(self.map.lock().unwrap().get(key.as_str()).cloned())
    }

    fn put(&self, key: &SecretKey, value: &str) -> Result<(), SecretError> {
        self.put_count.fetch_add(1, Ordering::SeqCst);
        if self.fail_puts.load(Ordering::SeqCst) {
            return Err(SecretError::Keyring("simulated put failure".into()));
        }
        self.map
            .lock()
            .unwrap()
            .insert(key.as_str().to_string(), value.to_string());
        if let Some((clock, secs)) = &*self.put_clock.lock().unwrap() {
            clock.set(clock.now_unix_seconds() + *secs);
        }
        if self.put_persists_but_errors.load(Ordering::SeqCst) {
            // Value is now visible to `get`, but the write reports failure.
            return Err(SecretError::Keyring(
                "simulated post-persist failure".into(),
            ));
        }
        Ok(())
    }

    fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        self.map.lock().unwrap().remove(key.as_str());
        Ok(())
    }
}

impl InMemStore {
    fn set_fail_puts(&self, fail: bool) {
        self.fail_puts.store(fail, Ordering::SeqCst);
    }

    fn advance_clock_on_put(&self, clock: Arc<FakeClock>, secs: i64) {
        *self.put_clock.lock().unwrap() = Some((clock, secs));
    }

    fn revoke_after_gets(&self, after: usize) {
        *self.revoke_after_gets.lock().unwrap() = Some(after);
    }

    fn replace_after_gets(&self, after: usize, value: String) {
        *self.replace_after_gets.lock().unwrap() = Some((after, value));
    }

    fn set_put_persists_but_errors(&self, on: bool) {
        self.put_persists_but_errors.store(on, Ordering::SeqCst);
    }

    fn put_count(&self) -> usize {
        self.put_count.load(Ordering::SeqCst)
    }

    fn contains(&self, key: &SecretKey) -> bool {
        self.map.lock().unwrap().contains_key(key.as_str())
    }
}

struct FakeClock {
    now_unix_seconds: StdMutex<i64>,
}

impl FakeClock {
    fn new(now_unix_seconds: i64) -> Self {
        Self {
            now_unix_seconds: StdMutex::new(now_unix_seconds),
        }
    }

    #[allow(dead_code)]
    fn set(&self, now: i64) {
        *self.now_unix_seconds.lock().unwrap() = now;
    }
}

impl ChatgptOauthClock for FakeClock {
    fn now_unix_seconds(&self) -> i64 {
        *self.now_unix_seconds.lock().unwrap()
    }

    fn now_rfc3339(&self) -> String {
        let secs = self.now_unix_seconds();
        time::OffsetDateTime::from_unix_timestamp(secs)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    }
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn jwt_with_payload(payload: &serde_json::Value) -> String {
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let body = b64url(serde_json::to_vec(payload).unwrap().as_slice());
    let sig = b64url(b"sig");
    format!("{header}.{body}.{sig}")
}

fn access_token_with_exp(exp_unix: i64) -> String {
    jwt_with_payload(&json!({"exp": exp_unix}))
}

fn id_token_with_chatgpt_claims(account_id: &str, fedramp: bool, exp: i64) -> String {
    jwt_with_payload(&json!({
        "exp": exp,
        "https://api.openai.com/auth": {
            "chatgpt_account_id": account_id,
            "chatgpt_account_is_fedramp": fedramp,
        }
    }))
}

fn make_bundle(access_exp: i64, refresh_token: &str, fedramp: bool) -> ChatgptAuthBundle {
    ChatgptAuthBundle {
        auth_mode: Some("chatgpt".into()),
        openai_api_key: None,
        tokens: Some(ChatgptTokens {
            id_token: id_token_with_chatgpt_claims("acct-123", fedramp, access_exp + 86400),
            access_token: access_token_with_exp(access_exp),
            refresh_token: refresh_token.into(),
            account_id: Some("acct-123".into()),
        }),
        last_refresh: Some("2026-01-01T00:00:00Z".into()),
        agent_identity: None,
    }
}

#[test]
fn debug_redacts_tokens_and_api_key() {
    let bundle = make_bundle(/*exp=*/ 4_000, "very-secret-refresh", false);
    // Drop in an API key so we can confirm it doesn't appear in the Debug
    // output.
    let bundle = ChatgptAuthBundle {
        openai_api_key: Some("sk-very-secret-api-key".into()),
        ..bundle
    };
    let rendered = format!("{bundle:?}");

    assert!(!rendered.contains("very-secret-refresh"), "{rendered}");
    assert!(!rendered.contains("sk-very-secret-api-key"), "{rendered}");
    let tokens = bundle.tokens.as_ref().unwrap();
    assert!(
        !rendered.contains(tokens.access_token.as_str()),
        "{rendered}"
    );
    assert!(!rendered.contains(tokens.id_token.as_str()), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    // Non-secret fields are still visible so debug output stays useful.
    assert!(rendered.contains("acct-123"), "{rendered}");
    assert!(rendered.contains("2026-01-01T00:00:00Z"), "{rendered}");
}

#[test]
fn state_debug_redacts_durable_raw_blob() {
    // `durable_raw` is the raw auth.json JSON — live tokens. It must not leak
    // through the state's Debug even though `ChatgptAuthBundle` redacts its
    // own fields.
    let bundle = make_bundle(/*exp=*/ 4_000, "very-secret-refresh", false);
    let durable_raw = serde_json::to_string(&bundle).unwrap();
    let state = ChatgptOauthState::Loaded {
        bundle,
        durable_raw,
        needs_persist: false,
    };
    let rendered = format!("{state:?}");
    assert!(!rendered.contains("very-secret-refresh"), "{rendered}");
    assert!(
        !rendered.contains(&access_token_with_exp(4_000)),
        "{rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[test]
fn parse_jwt_expiration_reads_exp_claim() {
    let jwt = jwt_with_payload(&json!({"exp": 1735689600_i64}));
    assert_eq!(parse_jwt_expiration(&jwt).unwrap(), Some(1735689600));
}

#[test]
fn parse_jwt_expiration_returns_none_when_exp_absent() {
    let jwt = jwt_with_payload(&json!({"sub": "user"}));
    assert_eq!(parse_jwt_expiration(&jwt).unwrap(), None);
}

#[test]
fn parse_jwt_expiration_rejects_jwts_without_three_parts() {
    assert_eq!(
        parse_jwt_expiration("only.two"),
        Err(JwtPayloadError::InvalidFormat)
    );
    assert_eq!(
        parse_jwt_expiration(""),
        Err(JwtPayloadError::InvalidFormat)
    );
    assert_eq!(
        parse_jwt_expiration("a..b"),
        Err(JwtPayloadError::InvalidFormat)
    );
}

#[test]
fn parse_jwt_expiration_rejects_invalid_base64_payload() {
    let bad = "header.@@@@.sig";
    assert_eq!(
        parse_jwt_expiration(bad),
        Err(JwtPayloadError::InvalidBase64)
    );
}

#[test]
fn parse_jwt_expiration_rejects_non_json_payload() {
    let payload = b64url(b"not-json");
    let jwt = format!("h.{payload}.s");
    assert_eq!(
        parse_jwt_expiration(&jwt),
        Err(JwtPayloadError::InvalidJson)
    );
}

#[test]
fn parse_chatgpt_id_token_info_extracts_account_id_and_fedramp() {
    let jwt = id_token_with_chatgpt_claims("acct-7", true, 9999);
    let info = parse_chatgpt_id_token_info(&jwt).unwrap();
    assert_eq!(info.chatgpt_account_id.as_deref(), Some("acct-7"));
    assert!(info.chatgpt_account_is_fedramp);
}

#[test]
fn parse_chatgpt_id_token_info_defaults_when_auth_claim_missing() {
    let jwt = jwt_with_payload(&json!({"sub": "anon"}));
    let info = parse_chatgpt_id_token_info(&jwt).unwrap();
    assert_eq!(info, ChatgptIdTokenInfo::default());
}

#[test]
fn refresh_decision_is_fresh_when_token_well_outside_leeway() {
    let token = access_token_with_exp(2000);
    assert_eq!(
        refresh_decision(&token, /*now=*/ 1000, /*leeway=*/ 60),
        RefreshDecision::Fresh
    );
}

#[test]
fn refresh_decision_is_stale_when_token_inside_leeway() {
    let token = access_token_with_exp(1050);
    assert_eq!(
        refresh_decision(&token, /*now=*/ 1000, /*leeway=*/ 60),
        RefreshDecision::Stale
    );
}

#[test]
fn refresh_decision_is_stale_when_token_already_expired() {
    let token = access_token_with_exp(900);
    assert_eq!(
        refresh_decision(&token, /*now=*/ 1000, /*leeway=*/ 60),
        RefreshDecision::Stale
    );
}

#[test]
fn refresh_decision_is_unparsable_when_jwt_missing_exp() {
    let token = jwt_with_payload(&json!({"sub": "x"}));
    assert_eq!(
        refresh_decision(&token, /*now=*/ 1000, /*leeway=*/ 60),
        RefreshDecision::UnparsableJwt
    );
}

#[test]
fn refresh_decision_is_unparsable_when_jwt_garbled() {
    assert_eq!(
        refresh_decision("nope", 1000, 60),
        RefreshDecision::UnparsableJwt
    );
}

proptest! {
    #[test]
    fn refresh_decision_matches_naive_predicate(
        exp in -1_000_000_000_i64..1_000_000_000_i64,
        now in -1_000_000_000_i64..1_000_000_000_i64,
        leeway in 0_i64..3600,
    ) {
        let token = access_token_with_exp(exp);
        let got = refresh_decision(&token, now, leeway);
        let expected = if now.saturating_add(leeway) >= exp {
            RefreshDecision::Stale
        } else {
            RefreshDecision::Fresh
        };
        prop_assert_eq!(got, expected);
    }

    #[test]
    fn refresh_decision_unparsable_implies_stale_or_login_required(
        garbage in "[a-z]{0,20}",
        now in 0_i64..1_000_000_000,
        leeway in 0_i64..3600,
    ) {
        let got = refresh_decision(&garbage, now, leeway);
        prop_assert_eq!(got, RefreshDecision::UnparsableJwt);
    }
}

#[test]
fn apply_refresh_response_rotates_each_field_when_provided() {
    let mut bundle = make_bundle(/*exp=*/ 100, /*refresh=*/ "old-refresh", false);
    let resp = ChatgptRefreshResponseBody {
        id_token: Some(id_token_with_chatgpt_claims("acct-new", true, 5000)),
        access_token: Some(access_token_with_exp(4000)),
        refresh_token: Some("new-refresh".into()),
    };
    apply_refresh_response(&mut bundle, &resp, "2026-02-02T00:00:00Z".into()).unwrap();
    let tokens = bundle.tokens.as_ref().unwrap();
    assert_eq!(tokens.access_token, access_token_with_exp(4000));
    assert_eq!(tokens.refresh_token, "new-refresh");
    assert_eq!(bundle.last_refresh.as_deref(), Some("2026-02-02T00:00:00Z"));
    let info = parse_chatgpt_id_token_info(&tokens.id_token).unwrap();
    assert_eq!(info.chatgpt_account_id.as_deref(), Some("acct-new"));
    assert!(info.chatgpt_account_is_fedramp);
}

#[test]
fn apply_refresh_response_preserves_fields_absent_from_response() {
    let mut bundle = make_bundle(100, "old-refresh", false);
    let original_id = bundle.tokens.as_ref().unwrap().id_token.clone();
    let resp = ChatgptRefreshResponseBody {
        id_token: None,
        access_token: Some(access_token_with_exp(7000)),
        refresh_token: None,
    };
    apply_refresh_response(&mut bundle, &resp, "2026-02-02T00:00:00Z".into()).unwrap();
    let tokens = bundle.tokens.as_ref().unwrap();
    assert_eq!(tokens.id_token, original_id);
    assert_eq!(tokens.refresh_token, "old-refresh");
    assert_eq!(tokens.access_token, access_token_with_exp(7000));
}

#[test]
fn apply_refresh_response_rejects_when_bundle_lacks_tokens() {
    let mut bundle = ChatgptAuthBundle::default();
    let resp = ChatgptRefreshResponseBody::default();
    let err = apply_refresh_response(&mut bundle, &resp, "now".into()).unwrap_err();
    assert!(err.contains("tokens"));
}

#[test]
fn classify_refresh_failure_status_marks_401_login_required() {
    assert_eq!(
        classify_refresh_failure_status(401),
        RefreshOutcomeKind::LoginRequired
    );
}

#[test]
fn classify_refresh_failure_status_marks_5xx_transient() {
    for code in [500_u16, 502, 503, 504] {
        assert_eq!(
            classify_refresh_failure_status(code),
            RefreshOutcomeKind::Transient
        );
    }
}

#[test]
fn classify_refresh_failure_status_marks_404_transient() {
    assert_eq!(
        classify_refresh_failure_status(404),
        RefreshOutcomeKind::Transient
    );
}

#[test]
fn audit_error_label_is_stable_per_variant() {
    assert_eq!(
        ChatgptOauthError::LoginRequired.audit_error_label(),
        "chatgpt_oauth_login_required"
    );
    assert_eq!(
        ChatgptOauthError::RefreshTransient("x".into()).audit_error_label(),
        "chatgpt_oauth_refresh_transient"
    );
    assert_eq!(
        ChatgptOauthError::BundleMalformed("x".into()).audit_error_label(),
        "chatgpt_oauth_login_required"
    );
}

fn build_authority(refresh_url: &str, clock: Arc<FakeClock>) -> (ChatgptOauthAuthority, SecretKey) {
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let config = ChatgptOauthAuthorityConfig {
        secret_key: key.clone(),
        refresh_url: reqwest::Url::parse(refresh_url).unwrap(),
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap(),
        clock,
        leeway_seconds: CHATGPT_OAUTH_REFRESH_LEEWAY_SECONDS,
    };
    let authority = ChatgptOauthAuthority::new(config);
    (authority, key)
}

#[tokio::test]
async fn current_headers_returns_cached_headers_when_token_is_fresh() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 10_000, "refresh-1", true);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    let (authority, _) = build_authority(&server.uri(), clock);

    let headers = authority.current_headers(&store).await.unwrap();

    assert_eq!(headers.access_token, access_token_with_exp(10_000));
    assert_eq!(headers.account_id.as_deref(), Some("acct-123"));
    assert!(headers.is_fedramp_account);
    // No mock was registered → if the authority had hit the upstream
    // refresh endpoint, the request would have 404'd.
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn current_headers_refreshes_when_token_is_stale_and_persists_new_bundle() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 1_050, "refresh-old", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token_with_chatgpt_claims("acct-rotated", true, 99_999),
            "access_token": access_token_with_exp(50_000),
            "refresh_token": "refresh-new",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));

    let headers = authority.current_headers(&store).await.unwrap();

    assert_eq!(headers.access_token, access_token_with_exp(50_000));
    assert_eq!(headers.account_id.as_deref(), Some("acct-rotated"));
    assert!(headers.is_fedramp_account);
    let stored: ChatgptAuthBundle =
        serde_json::from_str(&store.get(&key).unwrap().unwrap()).unwrap();
    let stored_tokens = stored.tokens.unwrap();
    assert_eq!(stored_tokens.refresh_token, "refresh-new");
    assert_eq!(stored_tokens.access_token, access_token_with_exp(50_000));
}

#[tokio::test]
async fn put_failure_after_refresh_keeps_new_token_and_heals_durable_on_next_call() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 1_050, "refresh-old", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token_with_chatgpt_claims("acct-rotated", false, 99_999),
            "access_token": access_token_with_exp(50_000),
            "refresh_token": "refresh-new",
        })))
        // Exactly one upstream refresh across BOTH calls: the second call
        // must heal durable storage from the cached token, not re-refresh.
        .expect(1)
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));

    // First call: token is stale, so we refresh upstream (rotating the
    // refresh token) — but the durable write fails.
    store.set_fail_puts(true);
    let err = authority.current_headers(&store).await.unwrap_err();
    assert!(
        matches!(err, ChatgptOauthError::SecretStore(_)),
        "expected SecretStore error, got {err:?}"
    );
    // Durable storage still holds the OLD (now-spent) refresh token: a
    // restart here would load a token the upstream has already invalidated.
    let stored: ChatgptAuthBundle =
        serde_json::from_str(&store.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(stored.tokens.unwrap().refresh_token, "refresh-old");

    // The secret store recovers.
    store.set_fail_puts(false);

    // Second call: the cached access_token is already fresh, so we must not
    // hit the upstream again (`.expect(1)`). The cache is dirty from the
    // failed write, so we retry persistence and it now succeeds.
    let headers = authority.current_headers(&store).await.unwrap();
    assert_eq!(headers.access_token, access_token_with_exp(50_000));

    // Durable storage has caught up to the rotated token.
    let stored: ChatgptAuthBundle =
        serde_json::from_str(&store.get(&key).unwrap().unwrap()).unwrap();
    let stored_tokens = stored.tokens.unwrap();
    assert_eq!(stored_tokens.refresh_token, "refresh-new");
    assert_eq!(stored_tokens.access_token, access_token_with_exp(50_000));
}

#[tokio::test]
async fn pending_persist_is_flushed_before_a_stale_token_refresh() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 1_050, "refresh-old", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    // First refresh rotates to a token that expires at 2_000 (fresh now, but
    // stale once the clock advances). Highest priority + single use.
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token_with_chatgpt_claims("acct-rotated", false, 99_999),
            "access_token": access_token_with_exp(2_000),
            "refresh_token": "refresh-mid",
        })))
        .with_priority(1)
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // Every later refresh fails transiently.
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(503).set_body_string("backend down"))
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));

    // First call: stale token → refresh to "refresh-mid", but the durable
    // write fails, leaving the cache ahead of durable storage.
    store.set_fail_puts(true);
    let err = authority.current_headers(&store).await.unwrap_err();
    assert!(matches!(err, ChatgptOauthError::SecretStore(_)), "{err:?}");
    let stored: ChatgptAuthBundle =
        serde_json::from_str(&store.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(stored.tokens.unwrap().refresh_token, "refresh-old");

    // The store recovers, and enough time passes that the cached
    // "refresh-mid" access token is now itself stale.
    store.set_fail_puts(false);
    clock.set(1_995);

    // Second call: the token is stale, so we head for a refresh — which now
    // fails transiently (503). The pending write must be flushed *before*
    // that refresh, so durable storage holds the valid, not-yet-spent
    // "refresh-mid" token instead of the spent "refresh-old". Otherwise a
    // restart here would still force a re-login.
    let err = authority.current_headers(&store).await.unwrap_err();
    match err {
        ChatgptOauthError::RefreshTransient(msg) => assert!(msg.contains("503"), "{msg}"),
        other => panic!("expected RefreshTransient, got {other:?}"),
    }
    let stored: ChatgptAuthBundle =
        serde_json::from_str(&store.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(stored.tokens.unwrap().refresh_token, "refresh-mid");
}

#[tokio::test]
async fn freshness_is_reevaluated_after_a_slow_pending_persist() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 1_050, "refresh-old", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    // First refresh rotates to a token that expires at 2_000 — fresh at
    // now = 1_000. Highest priority, single use.
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token_with_chatgpt_claims("acct-rotated", false, 99_999),
            "access_token": access_token_with_exp(2_000),
            "refresh_token": "refresh-mid",
        })))
        .with_priority(1)
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // Any later refresh rotates to a long-lived token.
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token_with_chatgpt_claims("acct-rotated", false, 99_999),
            "access_token": access_token_with_exp(99_000),
            "refresh_token": "refresh-new",
        })))
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));

    // First call: stale v1 → refresh to exp=2_000/"refresh-mid", but the
    // durable write fails, leaving needs_persist set.
    store.set_fail_puts(true);
    authority.current_headers(&store).await.unwrap_err();

    // Store recovers, but the now-successful write "takes" 1_500 simulated
    // seconds each time, so the pending-persist flush pushes the clock from
    // 1_000 to 2_500 — past the cached token's 2_000 expiry.
    store.set_fail_puts(false);
    store.advance_clock_on_put(Arc::clone(&clock), 1_500);

    // Second call: at entry the cached token (exp 2_000) is still fresh
    // (now = 1_000). The flush advances the clock to 2_500. Freshness must
    // be judged *after* the flush, so the now-expired token triggers a
    // refresh and we return the freshly rotated long-lived token rather than
    // handing back an expired one.
    let headers = authority.current_headers(&store).await.unwrap();
    assert_eq!(headers.access_token, access_token_with_exp(99_000));
}

#[tokio::test]
async fn partially_persisted_write_is_retried_to_confirm_durability() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 1_050, "refresh-old", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token_with_chatgpt_claims("acct", false, 99_999),
            "access_token": access_token_with_exp(50_000),
            "refresh_token": "refresh-new",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));

    // First call refreshes and the write becomes visible to `get`, but the
    // durability fsync fails, so `put` reports an error (file-backend
    // rename-succeeds-but-dir-fsync-fails).
    store.set_put_persists_but_errors(true);
    let err = authority.current_headers(&store).await.unwrap_err();
    assert!(matches!(err, ChatgptOauthError::SecretStore(_)), "{err:?}");
    let puts_after_first = store.put_count();

    // The fsync path recovers.
    store.set_put_persists_but_errors(false);

    // Second call: the store already observably holds the rotated bundle, but
    // that write was never confirmed durable. We must recognise it as our own
    // pending write and *re-write* it (not adopt it as synced and stop), so a
    // later crash cannot lose the rotated token. `.expect(1)` confirms no
    // second upstream refresh.
    let headers = authority.current_headers(&store).await.unwrap();
    assert_eq!(headers.access_token, access_token_with_exp(50_000));
    assert!(
        store.put_count() > puts_after_first,
        "an unconfirmed write must be retried to confirm durability",
    );
    let stored: ChatgptAuthBundle =
        serde_json::from_str(&store.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(stored.tokens.unwrap().refresh_token, "refresh-new");
}

#[tokio::test]
async fn put_failure_still_serves_cached_token_while_store_stays_broken() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 1_050, "refresh-old", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token_with_chatgpt_claims("acct-rotated", false, 99_999),
            "access_token": access_token_with_exp(50_000),
            "refresh_token": "refresh-new",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));

    // The store is broken for the whole test.
    store.set_fail_puts(true);

    // First call refreshes upstream and fails to persist.
    let err = authority.current_headers(&store).await.unwrap_err();
    assert!(matches!(err, ChatgptOauthError::SecretStore(_)), "{err:?}");

    // Second call: even though the durable write is still failing, we hold a
    // valid, freshly-rotated token in memory, so we serve it rather than
    // failing closed. The retry attempt is best-effort and swallowed.
    let headers = authority.current_headers(&store).await.unwrap();
    assert_eq!(headers.access_token, access_token_with_exp(50_000));

    // Durable storage is still stale — the write never succeeded.
    let stored: ChatgptAuthBundle =
        serde_json::from_str(&store.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(stored.tokens.unwrap().refresh_token, "refresh-old");
}

#[tokio::test]
async fn out_of_band_secret_replacement_is_adopted() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    // A fresh bundle: no refresh needed, so any upstream call would be a bug.
    let original = make_bundle(/*exp=*/ 10_000, "refresh-original", false);
    store
        .put(&key, &serde_json::to_string(&original).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    let (authority, _) = build_authority(&server.uri(), Arc::clone(&clock));

    // Prime the (broker-wide, long-lived) cache with the original bundle.
    let h1 = authority.current_headers(&store).await.unwrap();
    assert_eq!(h1.access_token, access_token_with_exp(10_000));

    // Operator rotates the credential out-of-band (e.g. re-ran `codex login`
    // + `writ secret put`) to a different, still-fresh bundle.
    let replacement = ChatgptAuthBundle {
        auth_mode: Some("chatgpt".into()),
        openai_api_key: None,
        tokens: Some(ChatgptTokens {
            id_token: id_token_with_chatgpt_claims("acct-replaced", false, 99_999),
            access_token: access_token_with_exp(20_000),
            refresh_token: "refresh-replacement".into(),
            account_id: Some("acct-replaced".into()),
        }),
        last_refresh: Some("2026-03-03T00:00:00Z".into()),
        agent_identity: None,
    };
    store
        .put(&key, &serde_json::to_string(&replacement).unwrap())
        .unwrap();

    // The next call must reconcile with the store and serve the replacement,
    // not the stale cache.
    let h2 = authority.current_headers(&store).await.unwrap();
    assert_eq!(h2.access_token, access_token_with_exp(20_000));
    assert_eq!(h2.account_id.as_deref(), Some("acct-replaced"));
    // No refresh was ever needed.
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn concurrent_revocation_during_refresh_is_not_clobbered() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    // Stale token, so this call performs a refresh (network round-trip).
    let bundle = make_bundle(/*exp=*/ 1_050, "refresh-old", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token_with_chatgpt_claims("acct", false, 99_999),
            "access_token": access_token_with_exp(50_000),
            "refresh_token": "refresh-new",
        })))
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));

    // The operator revokes (deletes) after the first store read — i.e. during
    // the refresh round-trip, before the guarded write-back re-reads.
    store.revoke_after_gets(1);

    let err = authority.current_headers(&store).await.unwrap_err();
    assert!(matches!(err, ChatgptOauthError::LoginRequired), "{err:?}");
    // The freshly refreshed token must not resurrect the revoked secret.
    assert!(
        !store.contains(&key),
        "a refresh must not recreate a concurrently revoked secret",
    );
}

#[tokio::test]
async fn permanent_failure_does_not_delete_a_concurrent_replacement() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    // Stale token → refresh; upstream will answer 401 (token permanently dead).
    let dead = make_bundle(/*exp=*/ 1_050, "refresh-dead", false);
    store
        .put(&key, &serde_json::to_string(&dead).unwrap())
        .unwrap();
    // What the operator installs mid-refresh.
    let replacement = make_bundle(/*exp=*/ 50_000, "refresh-operator-new", false);
    let replacement_raw = serde_json::to_string(&replacement).unwrap();

    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "refresh_token_expired",
        })))
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));

    // The operator replaces the secret after the reconcile read — during the
    // refresh round-trip whose 401 concerns only the *old* token.
    store.replace_after_gets(1, replacement_raw.clone());

    let err = authority.current_headers(&store).await.unwrap_err();
    assert!(matches!(err, ChatgptOauthError::LoginRequired), "{err:?}");
    // The permanent-failure delete must not erase the operator's replacement.
    // (`contains` reads the map directly, so it does not re-trigger the
    // replacement hook the way another `get` would.)
    assert!(
        store.contains(&key),
        "a 401 for the old token must not delete a concurrent replacement",
    );
}

#[tokio::test]
async fn pending_persist_retry_reconciles_when_secret_revoked_mid_call() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 1_050, "refresh-old", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token_with_chatgpt_claims("acct", false, 99_999),
            "access_token": access_token_with_exp(50_000),
            "refresh_token": "refresh-new",
        })))
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));

    // Call 1 refreshes but the durable write fails, leaving the cache ahead
    // with a pending persist. (Two store reads: reconcile + guarded write.)
    store.set_fail_puts(true);
    let err = authority.current_headers(&store).await.unwrap_err();
    assert!(matches!(err, ChatgptOauthError::SecretStore(_)), "{err:?}");

    // The store recovers, but the operator revokes after call 2's reconcile
    // read and before the pending-persist retry's guarded read (get #4).
    store.set_fail_puts(false);
    store.revoke_after_gets(3);

    // The retry observes the revocation; it must reconcile and refuse *this*
    // call rather than serving the stale cached token, and must not recreate
    // the revoked secret.
    let err = authority.current_headers(&store).await.unwrap_err();
    assert!(matches!(err, ChatgptOauthError::LoginRequired), "{err:?}");
    assert!(
        !store.contains(&key),
        "a pending-persist retry must not resurrect a revoked secret",
    );
}

#[tokio::test]
async fn out_of_band_secret_deletion_revokes_access() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 10_000, "refresh-1", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    let (authority, _) = build_authority(&server.uri(), Arc::clone(&clock));

    // Prime the cache.
    authority.current_headers(&store).await.unwrap();

    // Operator revokes by deleting the secret.
    store.delete(&key).unwrap();

    // Access must be refused, and the cache must not recreate the secret.
    let err = authority.current_headers(&store).await.unwrap_err();
    assert!(matches!(err, ChatgptOauthError::LoginRequired), "{err:?}");
    assert!(
        !store.contains(&key),
        "revoked secret must not be recreated"
    );
}

#[tokio::test]
async fn out_of_band_deletion_with_pending_persist_does_not_recreate_secret() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 1_050, "refresh-old", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token_with_chatgpt_claims("acct", false, 99_999),
            "access_token": access_token_with_exp(50_000),
            "refresh_token": "refresh-new",
        })))
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));

    // Refresh succeeds upstream, but the durable write fails: the cache is now
    // ahead of the store with a pending persist.
    store.set_fail_puts(true);
    let err = authority.current_headers(&store).await.unwrap_err();
    assert!(matches!(err, ChatgptOauthError::SecretStore(_)), "{err:?}");

    // Operator revokes by deleting the secret (the store is healthy for it).
    store.set_fail_puts(false);
    store.delete(&key).unwrap();

    // The pending write must NOT resurrect the revoked secret; the next call
    // reconciles, refuses, and leaves the store empty.
    let err = authority.current_headers(&store).await.unwrap_err();
    assert!(matches!(err, ChatgptOauthError::LoginRequired), "{err:?}");
    assert!(
        !store.contains(&key),
        "pending persist must not recreate a revoked secret",
    );
}

#[tokio::test]
async fn permanent_refresh_failure_deletes_secret_and_surfaces_login_required() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 1_050, "dead-refresh", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "refresh_token_expired",
        })))
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));

    let err = authority.current_headers(&store).await.unwrap_err();

    assert!(matches!(err, ChatgptOauthError::LoginRequired));
    assert!(!store.contains(&key));
}

#[tokio::test]
async fn transient_refresh_failure_keeps_secret_and_surfaces_transient_error() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 1_050, "refresh-old", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(503).set_body_string("backend down"))
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));

    let err = authority.current_headers(&store).await.unwrap_err();

    match err {
        ChatgptOauthError::RefreshTransient(msg) => {
            assert!(msg.contains("503"), "{msg}");
        }
        other => panic!("expected RefreshTransient, got {other:?}"),
    }
    // Secret must remain so the operator can retry without re-login.
    assert!(store.contains(&key));
}

#[tokio::test]
async fn missing_secret_returns_login_required() {
    let store = InMemStore::default();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, clock);

    let err = authority.current_headers(&store).await.unwrap_err();

    assert!(matches!(err, ChatgptOauthError::LoginRequired));
}

#[tokio::test]
async fn malformed_bundle_returns_bundle_malformed() {
    let store = InMemStore::default();
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    store.put(&key, "not-json").unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, clock);

    let err = authority.current_headers(&store).await.unwrap_err();

    assert!(matches!(err, ChatgptOauthError::BundleMalformed(_)));
}

#[tokio::test]
async fn second_concurrent_request_observes_freshly_refreshed_token() {
    let store = Arc::new(InMemStore::default());
    let key = SecretKey::new("openai-chatgpt-auth").unwrap();
    let bundle = make_bundle(/*exp=*/ 1_050, "refresh-old", false);
    store
        .put(&key, &serde_json::to_string(&bundle).unwrap())
        .unwrap();
    let clock = Arc::new(FakeClock::new(1_000));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token_with_chatgpt_claims("acct-rotated", false, 99_999),
            "access_token": access_token_with_exp(50_000),
            "refresh_token": "refresh-new",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let refresh_url = format!("{}/oauth/token", server.uri());
    let (authority, _) = build_authority(&refresh_url, Arc::clone(&clock));
    let authority = Arc::new(authority);

    let a = Arc::clone(&authority);
    let b = Arc::clone(&authority);
    let store_a = Arc::clone(&store);
    let store_b = Arc::clone(&store);
    let (h1, h2) = tokio::join!(
        async move { a.current_headers(&*store_a).await.unwrap() },
        async move { b.current_headers(&*store_b).await.unwrap() }
    );

    assert_eq!(h1.access_token, access_token_with_exp(50_000));
    assert_eq!(h2.access_token, access_token_with_exp(50_000));
    // .expect(1) on the mock asserts a single refresh call.
}
