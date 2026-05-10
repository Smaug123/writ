use std::collections::HashMap;
use std::sync::Mutex as StdMutex;

use base64::Engine as _;
use proptest::prelude::*;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::secret::{SecretError, SecretKey, SecretStore};

use super::*;

#[derive(Default)]
struct InMemStore(StdMutex<HashMap<String, String>>);

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

impl InMemStore {
    fn contains(&self, key: &SecretKey) -> bool {
        self.0.lock().unwrap().contains_key(key.as_str())
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
    assert!(!rendered.contains(tokens.access_token.as_str()), "{rendered}");
    assert!(!rendered.contains(tokens.id_token.as_str()), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    // Non-secret fields are still visible so debug output stays useful.
    assert!(rendered.contains("acct-123"), "{rendered}");
    assert!(rendered.contains("2026-01-01T00:00:00Z"), "{rendered}");
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
