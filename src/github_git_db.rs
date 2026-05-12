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
//! Blob, tree, and commit creation are implemented; the walker that
//! drives them per commit lands in a later slice and reuses the
//! auth/URL/error scaffolding established here.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use crate::core::RepoRef;
use crate::vm_git::GitObjectId;

const ACCEPT_HEADER: &str = "application/vnd.github+json";
const API_VERSION_HEADER: &str = "2022-11-28";
/// GitHub's REST API rejects requests without a `User-Agent`. We set
/// it per-request rather than via `reqwest::ClientBuilder::user_agent`
/// so a caller that passes in a default-constructed `reqwest::Client`
/// still produces a working request — this is a protocol requirement,
/// not a client preference.
const USER_AGENT_HEADER: &str = "writ/0.1";

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
            .header("User-Agent", USER_AGENT_HEADER)
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

    /// `POST /repos/{owner}/{repo}/git/trees` — create a tree from a
    /// list of entries and return the SHA GitHub assigned.
    ///
    /// The body lists each entry's `path`, `mode`, `type`, and the
    /// SHA of the object it references (a blob, an already-created
    /// subtree, or a submodule commit). We do not use the API's
    /// `base_tree` parameter: the replay walker recursively creates
    /// the trees it needs and points unchanged subtrees at their
    /// existing SHAs, which is unambiguous without a base.
    ///
    /// An empty `entries` slice produces git's well-known empty
    /// tree; the API accepts this and the walker depends on it for
    /// initial commits whose root is empty.
    pub async fn create_tree(
        &self,
        repo: &RepoRef,
        entries: &[TreeEntry],
    ) -> Result<GitObjectId, GitDataError> {
        let url = format!(
            "{}/repos/{}/{}/git/trees",
            self.api_base.trim_end_matches('/'),
            repo.owner,
            repo.name,
        );
        let body = TreeCreateBody {
            tree: entries
                .iter()
                .map(|entry| TreeEntryWire {
                    path: &entry.path,
                    mode: entry.kind.mode(),
                    object_type: entry.kind.object_type(),
                    sha: &entry.sha,
                })
                .collect(),
        };
        let response = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .header("User-Agent", USER_AGENT_HEADER)
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(GitDataError::ApiError { status, body });
        }
        let parsed: TreeCreateResponse = response.json().await?;
        Ok(parsed.sha)
    }

    /// `POST /repos/{owner}/{repo}/git/commits` — create a commit
    /// pointing at the given `tree`, with the given `parents`, and
    /// return the SHA GitHub assigned.
    ///
    /// `parents` may be empty for an initial commit, or hold several
    /// entries for an octopus merge. `author` typically preserves
    /// the bundle commit's authorship; `committer` is the App
    /// identity.
    ///
    /// **GitHub does not auto-sign commits created via the Git
    /// Database API**, even when the committer matches the App
    /// identity — that auto-signing only applies to the higher-level
    /// Contents API. If `signature` is `None`, the resulting commit
    /// publishes with `verification.reason = "unsigned"` and no
    /// Verified badge. To get Verified, the caller must supply a
    /// detached PGP/SSH signature over the canonical commit object
    /// here; producing that signature is the replay walker's
    /// responsibility, not this client's.
    ///
    /// `message` is forwarded verbatim — the replay layer is
    /// responsible for appending its provenance trailer before this
    /// is called.
    pub async fn create_commit(
        &self,
        repo: &RepoRef,
        request: &CommitRequest<'_>,
    ) -> Result<GitObjectId, GitDataError> {
        let url = format!(
            "{}/repos/{}/{}/git/commits",
            self.api_base.trim_end_matches('/'),
            repo.owner,
            repo.name,
        );
        let body = CommitCreateBody {
            message: request.message,
            tree: request.tree,
            parents: request.parents,
            author: identity_wire(request.author),
            committer: identity_wire(request.committer),
            signature: request.signature,
        };
        let response = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .header("Accept", ACCEPT_HEADER)
            .header("X-GitHub-Api-Version", API_VERSION_HEADER)
            .header("User-Agent", USER_AGENT_HEADER)
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(GitDataError::ApiError { status, body });
        }
        let parsed: CommitCreateResponse = response.json().await?;
        Ok(parsed.sha)
    }
}

/// One row in a tree being uploaded to GitHub. The kind constrains
/// `mode` and `type` jointly so a caller can't write a (mode, type)
/// pair the API would reject — e.g. `040000` paired with `blob`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEntry {
    pub path: String,
    pub kind: TreeEntryKind,
    pub sha: GitObjectId,
}

/// What a tree entry points at. Each variant fixes both the file
/// `mode` and the object `type` GitHub expects, so the on-wire pair
/// is always valid by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeEntryKind {
    /// Regular file: mode `100644`, type `blob`.
    Blob,
    /// Executable file: mode `100755`, type `blob`.
    Executable,
    /// Symbolic link: mode `120000`, type `blob`. The referenced
    /// blob's content is the link target.
    Symlink,
    /// Subtree: mode `040000`, type `tree`.
    Subtree,
    /// Submodule pointer: mode `160000`, type `commit`. The SHA
    /// names a commit in another repository.
    Submodule,
}

impl TreeEntryKind {
    const fn mode(self) -> &'static str {
        match self {
            Self::Blob => "100644",
            Self::Executable => "100755",
            Self::Symlink => "120000",
            Self::Subtree => "040000",
            Self::Submodule => "160000",
        }
    }

    const fn object_type(self) -> &'static str {
        match self {
            Self::Blob | Self::Executable | Self::Symlink => "blob",
            Self::Subtree => "tree",
            Self::Submodule => "commit",
        }
    }
}

/// Name, email, and authoring time of a Git author or committer.
///
/// `date` is whatever the bundle carried for that commit, including
/// its timezone offset. Sub-second precision (if the caller somehow
/// constructed one) is dropped when sent to GitHub since the API
/// documents seconds-precision ISO-8601.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitIdentity {
    pub name: String,
    pub email: String,
    pub date: time::OffsetDateTime,
}

/// Inputs to [`GitDataClient::create_commit`].
///
/// Bundled as a struct so the call site is readable and so adding
/// optional fields (notably `signature`) does not blow past
/// clippy's argument-count threshold.
///
/// `signature`, when `Some`, must be a detached PGP or SSH
/// signature over the canonical commit object the API would
/// construct from the other fields. GitHub validates the signature
/// against the supplied identities; if it does not match the
/// commit GitHub assembles, the published commit's
/// `verification.reason` reflects that mismatch.
#[derive(Clone, Debug)]
pub struct CommitRequest<'a> {
    pub tree: &'a GitObjectId,
    pub parents: &'a [GitObjectId],
    pub message: &'a str,
    pub author: &'a CommitIdentity,
    pub committer: &'a CommitIdentity,
    pub signature: Option<&'a str>,
}

/// Format an `OffsetDateTime` as RFC 3339 truncated to whole seconds.
///
/// GitHub documents `author.date`/`committer.date` as
/// `YYYY-MM-DDTHH:MM:SSZ` (or with an explicit offset); the `time`
/// crate's default RFC 3339 emits sub-second digits when present,
/// which is technically out of spec for the API. Truncating here
/// avoids the question entirely.
fn rfc3339_seconds(date: time::OffsetDateTime) -> String {
    date.replace_nanosecond(0)
        .expect("zero is a valid nanosecond for OffsetDateTime")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("OffsetDateTime always formats as RFC 3339")
}

fn identity_wire(identity: &CommitIdentity) -> CommitIdentityWire<'_> {
    CommitIdentityWire {
        name: &identity.name,
        email: &identity.email,
        date: rfc3339_seconds(identity.date),
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

#[derive(serde::Serialize)]
struct TreeCreateBody<'a> {
    tree: Vec<TreeEntryWire<'a>>,
}

#[derive(serde::Serialize)]
struct TreeEntryWire<'a> {
    path: &'a str,
    mode: &'static str,
    #[serde(rename = "type")]
    object_type: &'static str,
    sha: &'a GitObjectId,
}

#[derive(serde::Deserialize)]
struct TreeCreateResponse {
    sha: GitObjectId,
}

#[derive(serde::Serialize)]
struct CommitCreateBody<'a> {
    message: &'a str,
    tree: &'a GitObjectId,
    parents: &'a [GitObjectId],
    author: CommitIdentityWire<'a>,
    committer: CommitIdentityWire<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct CommitIdentityWire<'a> {
    name: &'a str,
    email: &'a str,
    date: String,
}

#[derive(serde::Deserialize)]
struct CommitCreateResponse {
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
            .and(header("User-Agent", USER_AGENT_HEADER))
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

    fn entry(path: &str, kind: TreeEntryKind, sha: GitObjectId) -> TreeEntry {
        TreeEntry {
            path: path.to_string(),
            kind,
            sha,
        }
    }

    #[test]
    fn tree_entry_kind_mode_and_type_match_github_wire_format() {
        // Lock the (mode, type) pairs so a typo in the const tables
        // would fail loudly. These are the values GitHub's API
        // documents and the only ones it accepts.
        let cases = [
            (TreeEntryKind::Blob, "100644", "blob"),
            (TreeEntryKind::Executable, "100755", "blob"),
            (TreeEntryKind::Symlink, "120000", "blob"),
            (TreeEntryKind::Subtree, "040000", "tree"),
            (TreeEntryKind::Submodule, "160000", "commit"),
        ];
        for (kind, mode, object_type) in cases {
            assert_eq!(kind.mode(), mode, "wrong mode for {kind:?}");
            assert_eq!(kind.object_type(), object_type, "wrong type for {kind:?}");
        }
    }

    #[tokio::test]
    async fn create_tree_sends_each_kind_with_correct_mode_and_type() {
        // One entry of every kind, so a regression in any (mode,
        // type) pair would mismatch the body matcher.
        let server = MockServer::start().await;
        let blob_sha = sample_object_id('a');
        let exec_sha = sample_object_id('b');
        let symlink_sha = sample_object_id('c');
        let subtree_sha = sample_object_id('d');
        let submodule_sha = sample_object_id('e');
        let returned = sample_object_id('f');
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .and(header("Accept", ACCEPT_HEADER))
            .and(header("X-GitHub-Api-Version", API_VERSION_HEADER))
            .and(header("User-Agent", USER_AGENT_HEADER))
            .and(header("Authorization", "Bearer ghs_fake_token"))
            .and(body_json(json!({
                "tree": [
                    { "path": "README", "mode": "100644", "type": "blob", "sha": blob_sha.as_str() },
                    { "path": "scripts/run", "mode": "100755", "type": "blob", "sha": exec_sha.as_str() },
                    { "path": "link", "mode": "120000", "type": "blob", "sha": symlink_sha.as_str() },
                    { "path": "vendor", "mode": "040000", "type": "tree", "sha": subtree_sha.as_str() },
                    { "path": "submod", "mode": "160000", "type": "commit", "sha": submodule_sha.as_str() },
                ],
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let entries = vec![
            entry("README", TreeEntryKind::Blob, blob_sha),
            entry("scripts/run", TreeEntryKind::Executable, exec_sha),
            entry("link", TreeEntryKind::Symlink, symlink_sha),
            entry("vendor", TreeEntryKind::Subtree, subtree_sha),
            entry("submod", TreeEntryKind::Submodule, submodule_sha),
        ];
        let client = client_against(&server, "ghs_fake_token");
        let got = client
            .create_tree(&sample_repo(), &entries)
            .await
            .expect("tree create ok");
        assert_eq!(got, returned);
    }

    #[tokio::test]
    async fn create_tree_with_no_entries_posts_empty_tree_array() {
        // Initial commits may have an empty root tree; the walker
        // relies on this call succeeding and getting the empty-tree
        // SHA back.
        let server = MockServer::start().await;
        let returned = sample_object_id('0');
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .and(body_json(json!({ "tree": [] })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let got = client
            .create_tree(&sample_repo(), &[])
            .await
            .expect("empty tree create ok");
        assert_eq!(got, returned);
    }

    #[tokio::test]
    async fn create_tree_surfaces_api_error_body_on_4xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_json(json!({"message": "path 'foo' is invalid"})),
            )
            .mount(&server)
            .await;

        let entries = vec![entry("foo", TreeEntryKind::Blob, sample_object_id('a'))];
        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_tree(&sample_repo(), &entries)
            .await
            .expect_err("4xx must surface as ApiError");
        match err {
            GitDataError::ApiError { status, body } => {
                assert_eq!(status.as_u16(), 422);
                assert!(
                    body.contains("path 'foo' is invalid"),
                    "ApiError body must echo the response payload: {body:?}",
                );
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_tree_returns_http_error_when_response_sha_is_invalid() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/trees"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": "not a valid sha",
            })))
            .mount(&server)
            .await;

        let entries = vec![entry("foo", TreeEntryKind::Blob, sample_object_id('a'))];
        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_tree(&sample_repo(), &entries)
            .await
            .expect_err("malformed sha must not be returned silently");
        assert!(
            matches!(err, GitDataError::Http(_)),
            "GitObjectId rejection surfaces as a transport error: {err:?}",
        );
    }

    fn sample_identity(name: &str, date: time::OffsetDateTime) -> CommitIdentity {
        CommitIdentity {
            name: name.to_string(),
            email: format!("{name}@example.invalid"),
            date,
        }
    }

    fn unsigned_request<'a>(
        tree: &'a GitObjectId,
        parents: &'a [GitObjectId],
        message: &'a str,
        author: &'a CommitIdentity,
        committer: &'a CommitIdentity,
    ) -> CommitRequest<'a> {
        CommitRequest {
            tree,
            parents,
            message,
            author,
            committer,
            signature: None,
        }
    }

    #[test]
    fn rfc3339_seconds_drops_subsecond_precision() {
        // The wire format GitHub documents is YYYY-MM-DDTHH:MM:SSZ;
        // emitting sub-second digits is technically out of spec and
        // would let a caller-constructed sub-second `OffsetDateTime`
        // surface a deviation. Truncating here keeps the wire shape
        // stable.
        use time::macros::datetime;
        let with_nanos = datetime!(2024-01-15 10:30:45.123456789 UTC);
        assert_eq!(rfc3339_seconds(with_nanos), "2024-01-15T10:30:45Z");
    }

    #[test]
    fn rfc3339_seconds_preserves_non_utc_offset() {
        // Git commits carry the original author/committer offset
        // (e.g. `+0530`); we forward it verbatim so the replayed
        // commit's timestamp is faithful to the bundle.
        use time::macros::datetime;
        let with_offset = datetime!(2024-01-15 10:30:45 +05:30);
        assert_eq!(rfc3339_seconds(with_offset), "2024-01-15T10:30:45+05:30");
    }

    #[tokio::test]
    async fn create_commit_sends_message_tree_parents_and_identities() {
        // Standard non-initial commit with one parent. Asserts that
        // every documented field is on the wire and that the
        // returned sha is propagated up.
        use time::macros::datetime;
        let server = MockServer::start().await;
        let tree_sha = sample_object_id('a');
        let parent_sha = sample_object_id('b');
        let returned = sample_object_id('c');
        let author = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
        let committer = sample_identity("WritApp", datetime!(2024-01-15 10:31:00 UTC));

        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .and(header("Accept", ACCEPT_HEADER))
            .and(header("X-GitHub-Api-Version", API_VERSION_HEADER))
            .and(header("User-Agent", USER_AGENT_HEADER))
            .and(header("Authorization", "Bearer ghs_fake_token"))
            .and(body_json(json!({
                "message": "Fix the thing",
                "tree": tree_sha.as_str(),
                "parents": [parent_sha.as_str()],
                "author": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "committer": {
                    "name": "WritApp",
                    "email": "WritApp@example.invalid",
                    "date": "2024-01-15T10:31:00Z",
                },
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let parents = std::slice::from_ref(&parent_sha);
        let got = client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree_sha, parents, "Fix the thing", &author, &committer),
            )
            .await
            .expect("commit create ok");
        assert_eq!(got, returned);
    }

    #[tokio::test]
    async fn create_commit_sends_empty_parents_for_initial_commit() {
        // Initial commits have no parents; the walker relies on
        // sending `[]` and the API accepting it.
        use time::macros::datetime;
        let server = MockServer::start().await;
        let tree_sha = sample_object_id('a');
        let returned = sample_object_id('c');
        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));

        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .and(body_json(json!({
                "message": "Initial",
                "tree": tree_sha.as_str(),
                "parents": [],
                "author": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "committer": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let got = client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree_sha, &[], "Initial", &ident, &ident),
            )
            .await
            .expect("initial commit ok");
        assert_eq!(got, returned);
    }

    #[tokio::test]
    async fn create_commit_sends_all_parents_for_merge_commit() {
        // Octopus merges have several parents; both must appear in
        // order so GitHub records the merge topology correctly.
        use time::macros::datetime;
        let server = MockServer::start().await;
        let tree_sha = sample_object_id('a');
        let parent_a = sample_object_id('b');
        let parent_b = sample_object_id('c');
        let returned = sample_object_id('d');
        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));

        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .and(body_json(json!({
                "message": "Merge branch",
                "tree": tree_sha.as_str(),
                "parents": [parent_a.as_str(), parent_b.as_str()],
                "author": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "committer": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        let parents = [parent_a, parent_b];
        let got = client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree_sha, &parents, "Merge branch", &ident, &ident),
            )
            .await
            .expect("merge commit ok");
        assert_eq!(got, returned);
    }

    #[tokio::test]
    async fn create_commit_surfaces_api_error_body_on_4xx() {
        use time::macros::datetime;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_json(json!({"message": "tree sha does not exist"})),
            )
            .mount(&server)
            .await;

        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
        let tree = sample_object_id('a');
        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree, &[], "msg", &ident, &ident),
            )
            .await
            .expect_err("4xx must surface as ApiError");
        match err {
            GitDataError::ApiError { status, body } => {
                assert_eq!(status.as_u16(), 422);
                assert!(
                    body.contains("tree sha does not exist"),
                    "ApiError body must echo the response payload: {body:?}",
                );
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_commit_returns_http_error_when_response_sha_is_invalid() {
        use time::macros::datetime;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": "not a valid sha",
            })))
            .mount(&server)
            .await;

        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
        let tree = sample_object_id('a');
        let client = client_against(&server, "ghs_fake_token");
        let err = client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree, &[], "msg", &ident, &ident),
            )
            .await
            .expect_err("malformed sha must not be returned silently");
        assert!(
            matches!(err, GitDataError::Http(_)),
            "GitObjectId rejection surfaces as a transport error: {err:?}",
        );
    }

    #[tokio::test]
    async fn create_commit_omits_signature_field_when_none() {
        // With no signature, the field must be absent from the JSON
        // body — not present-with-null — so GitHub doesn't reject the
        // request and the absence is unambiguous on the wire.
        use time::macros::datetime;
        let server = MockServer::start().await;
        let tree_sha = sample_object_id('a');
        let returned = sample_object_id('b');
        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));

        // Strict matcher: the absence of `signature` from this JSON
        // object means the wire body must not include the key at all.
        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .and(body_json(json!({
                "message": "msg",
                "tree": tree_sha.as_str(),
                "parents": [],
                "author": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "committer": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_against(&server, "ghs_fake_token");
        client
            .create_commit(
                &sample_repo(),
                &unsigned_request(&tree_sha, &[], "msg", &ident, &ident),
            )
            .await
            .expect("unsigned commit create ok");
    }

    #[tokio::test]
    async fn create_commit_forwards_signature_field_when_some() {
        // Verified commits require a detached signature on the
        // wire. The wrapper must pass it through verbatim; producing
        // and validating it is the replay walker's responsibility.
        use time::macros::datetime;
        let server = MockServer::start().await;
        let tree_sha = sample_object_id('a');
        let returned = sample_object_id('b');
        let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
        let signature = "-----BEGIN PGP SIGNATURE-----\n\nfakeArmoredSignaturePayload\n-----END PGP SIGNATURE-----\n";

        Mock::given(method("POST"))
            .and(path("/repos/owner/name/git/commits"))
            .and(body_json(json!({
                "message": "Signed commit",
                "tree": tree_sha.as_str(),
                "parents": [],
                "author": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "committer": {
                    "name": "Alice",
                    "email": "Alice@example.invalid",
                    "date": "2024-01-15T10:30:45Z",
                },
                "signature": signature,
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "sha": returned.as_str(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let request = CommitRequest {
            tree: &tree_sha,
            parents: &[],
            message: "Signed commit",
            author: &ident,
            committer: &ident,
            signature: Some(signature),
        };
        let client = client_against(&server, "ghs_fake_token");
        let got = client
            .create_commit(&sample_repo(), &request)
            .await
            .expect("signed commit create ok");
        assert_eq!(got, returned);
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
