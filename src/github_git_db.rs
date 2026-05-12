//! GitHub Git Database REST client used by the broker's push-replay engine.
//!
//! Replay re-creates every commit between the upstream branch tip and a
//! VM-supplied bundle tip via the GitHub `git/blobs`, `git/trees`, and
//! `git/commits` endpoints under the host App's identity, so the published
//! commits land with the Verified badge while preserving provenance back
//! to the bundle. This module exposes typed wrappers for those POSTs; the
//! per-commit walker that orchestrates them lives in
//! [`crate::git_push_replay`].
//!
//! Only [`GitDataClient::create_blob`] is implemented in this commit;
//! tree and commit creation, plus the walker, land in later slices and
//! reuse the auth/URL/error scaffolding established here.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use crate::core::RepoRef;
use crate::vm_git::GitObjectId;

const ACCEPT_HEADER: &str = "application/vnd.github+json";
const API_VERSION_HEADER: &str = "2022-11-28";

/// Authenticated client for one installation's Git Database namespace.
///
/// Holds the installation token and the resolved `api_base` so callers
/// can drive several blob/tree/commit creates with a single client. The
/// token is private and the hand-rolled `Debug` redacts it; the only
/// way to surface the token after construction is through the request
/// path, which writes it into the `Authorization: Bearer …` header and
/// nowhere else.
pub struct GitDataClient {
    http: reqwest::Client,
    api_base: String,
    token: String,
}

impl std::fmt::Debug for GitDataClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitDataClient")
            .field("api_base", &self.api_base)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GitDataError {
    #[error("GitHub Git Data request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("GitHub Git Data API returned {status}: {body}")]
    ApiError {
        status: reqwest::StatusCode,
        body: String,
    },
}

impl GitDataClient {
    /// `api_base` is the GitHub REST API root *without* a trailing slash
    /// (e.g. `https://api.github.com`); the path segments for each
    /// endpoint are concatenated on. Tests pass a `wiremock` server URI
    /// in to swap the destination.
    pub fn new(
        http: reqwest::Client,
        api_base: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            http,
            api_base: api_base.into(),
            token: token.into(),
        }
    }

    /// `POST /repos/{owner}/{repo}/git/blobs` — upload raw bytes as a
    /// blob and return the SHA GitHub computed for it.
    ///
    /// The body is always sent with `encoding: "base64"`; UTF-8 mode
    /// would let GitHub interpret a CR / LF / NUL byte differently
    /// from the staging repo's view of the same blob, which would
    /// silently desync the SHA the walker is about to plug into the
    /// next tree. Base64 is the unambiguous transport for arbitrary
    /// bytes.
    ///
    /// The returned SHA is what the next tree-create call must use as
    /// the `sha` for the corresponding entry; callers track the
    /// `bundle blob SHA → app blob SHA` mapping themselves.
    pub async fn create_blob(
        &self,
        repo: &RepoRef,
        content: &[u8],
    ) -> Result<GitObjectId, GitDataError> {
        let url = format!(
            "{}/repos/{}/{}/git/blobs",
            self.api_base.trim_end_matches('/'),
            repo.owner,
            repo.name,
        );
        let body = BlobCreateBody {
            content: BASE64_STANDARD.encode(content),
            encoding: "base64",
        };
        let response = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(GitDataError::ApiError { status, body });
        }
        let parsed: BlobCreateResponse = response.json().await?;
        Ok(parsed.sha)
    }
}

#[derive(serde::Serialize)]
struct BlobCreateBody {
    content: String,
    encoding: &'static str,
}

#[derive(serde::Deserialize)]
struct BlobCreateResponse {
    sha: GitObjectId,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn sample_repo() -> RepoRef {
        RepoRef::from_str("owner/name").unwrap()
    }

    fn sample_object_id(nibble: char) -> GitObjectId {
        GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
    }

    fn client_against(server: &MockServer, token: &str) -> GitDataClient {
        GitDataClient::new(reqwest::Client::new(), server.uri(), token.to_string())
    }

    #[tokio::test]
    async fn create_blob_sends_base64_body_and_returns_sha() {
        let server = MockServer::start().await;
        let raw = b"hello\x00world\n";
        let encoded = BASE64_STANDARD.encode(raw);
        let returned = sample_object_id('a');
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/blobs"))
            .and(header("Accept", ACCEPT_HEADER))
            .and(header("X-GitHub-Api-Version", API_VERSION_HEADER))
            .and(header("Authorization", "Bearer ghs_fake_token"))
            .and(body_json(json!({
                "content": encoded,
                "encoding": "base64",
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
                "url": format!("https://api.github.com/repos/owner/name/git/blobs/{}", returned.as_str()),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let got = client
            .create_blob(&sample_repo(), raw)
            .await
            .expect("blob create ok");
        assert_eq!(got, returned);
    }

    #[tokio::test]
    async fn create_blob_surfaces_api_error_body_on_4xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/blobs"))
            .respond_with(
                ResponseTemplate::new(422).set_body_json(json!({"message": "Validation Failed"})),
            )
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_blob(&sample_repo(), b"payload")
            .await
            .expect_err("4xx must surface as ApiError");
        match err {
            GitDataError::ApiError { status, body } => {
                assert_eq!(status.as_u16(), 422);
                assert!(
                    body.contains("Validation Failed"),
                    "ApiError body must echo the response payload so operators can diagnose: {body:?}",
                );
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_blob_surfaces_api_error_on_5xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/blobs"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream unavailable"))
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_blob(&sample_repo(), b"payload")
            .await
            .expect_err("5xx must surface as ApiError");
        match err {
            GitDataError::ApiError { status, body } => {
                assert_eq!(status.as_u16(), 503);
                assert_eq!(body, "upstream unavailable");
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_blob_round_trips_binary_content_unchanged() {
        // Bytes that would be silently mangled by a UTF-8 transport:
        // a NUL byte, a bare CR, an invalid UTF-8 lead byte, and a
        // high-bit byte that is not the start of a valid codepoint.
        // Base64 must survive all of these unmodified so the SHA the
        // walker plugs into the next tree matches what the staging
        // repo actually held.
        let raw: &[u8] = b"\x00\rgit\xc3\x28\xff\n";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/blobs"))
            .and(body_json(json!({
                "content": BASE64_STANDARD.encode(raw),
                "encoding": "base64",
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": sample_object_id('b').as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        client
            .create_blob(&sample_repo(), raw)
            .await
            .expect("binary content survives transport");
    }

    #[tokio::test]
    async fn create_blob_returns_http_error_when_response_sha_is_invalid() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/blobs"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": "not a valid sha",
            })))
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_blob(&sample_repo(), b"payload")
            .await
            .expect_err("malformed sha must not be returned silently");
        assert!(
            matches!(err, GitDataError::Http(_)),
            "GitObjectId rejection during deserialisation surfaces as a transport error: {err:?}",
        );
    }

    #[test]
    fn debug_redacts_token() {
        let client =
            GitDataClient::new(reqwest::Client::new(), "https://api.example", "ghs_secret");
        let rendered = format!("{client:?}");
        assert!(
            !rendered.contains("ghs_secret"),
            "Debug must not echo the token: {rendered}",
        );
        assert!(
            rendered.contains("<redacted>"),
            "Debug should label the redacted slot: {rendered}",
        );
    }
}
