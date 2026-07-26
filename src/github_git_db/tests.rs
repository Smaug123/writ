//! Tests for the GitHub Git Database client, domain types, and wire DTOs. Split out of `github_git_db.rs` (an inline `#[cfg(test)]` module); tests unchanged.

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
    GitDataClient::new(&GitDataHttp::production(), server.uri(), token.to_string())
}

/// A server that accepts the request and then never answers must
/// not park a Git Data call forever. Driven with tiny bounds so the
/// test costs milliseconds; the mechanism under test (the
/// per-request small-call budget firing on a withheld response) is
/// the same one the production bounds arm.
#[tokio::test]
async fn git_data_request_against_a_withholding_server_times_out() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/ref/heads/main"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "ref": "refs/heads/main",
                    "object": { "sha": sample_object_id('a').as_str(), "type": "commit" },
                }))
                .set_delay(Duration::from_secs(30)),
        )
        .mount(&server)
        .await;
    let client = GitDataClient::new(
        &GitDataHttp::new(GitDataTimeouts::new(
            Duration::from_millis(200),
            Duration::from_millis(200),
            Duration::from_millis(500),
        )),
        server.uri(),
        "ghs_token".to_string(),
    );

    let started = std::time::Instant::now();
    let err = client
        .get_branch_head(&sample_repo(), &GitBranchName::new("main").unwrap())
        .await
        .expect_err("a withheld response must not resolve");

    assert!(
        matches!(&err, GitDataError::Http(source) if source.is_timeout()),
        "expected a timeout, got: {err:?}",
    );
    // The bound is 500ms; anything near the mock's 30s delay means
    // no timeout was armed at all.
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "request took {:?} — the timeout did not fire",
        started.elapsed(),
    );
}

/// The counterpart guarantee to the withholding test: a blob
/// upload that makes steady progress but takes longer than the
/// small-call budget must NOT be killed. reqwest's builder-level
/// `read_timeout` is a flat deadline armed at dispatch and running
/// until the response *headers* arrive — the whole upload phase
/// counts against it, and GitHub sends nothing until it has
/// consumed the body — so bounding uploads with it rejects
/// legitimate slow pushes (a 256 MiB object is ~342 MiB of base64;
/// >30 s at uplinks below ~90 Mbit/s). Uploads run under the
/// `total` ceiling only; the mock's response delay stands in for
/// the time GitHub spends consuming a large body.
#[tokio::test]
async fn create_blob_survives_a_response_slower_than_the_small_call_budget() {
    let server = MockServer::start().await;
    let returned = sample_object_id('b');
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/blobs"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({ "sha": returned.as_str() }))
                // Longer than the small-call budget, well inside total.
                .set_delay(Duration::from_millis(500)),
        )
        .mount(&server)
        .await;
    let client = GitDataClient::new(
        &GitDataHttp::new(GitDataTimeouts::new(
            Duration::from_millis(200),
            Duration::from_millis(200),
            Duration::from_secs(5),
        )),
        server.uri(),
        "ghs_token".to_string(),
    );

    let sha = client
        .create_blob(&sample_repo(), b"payload")
        .await
        .expect("a slow-but-progressing upload must get the full total budget");
    assert_eq!(sha, returned);
}

/// Same guarantee for the other two object uploads. A commit is
/// not necessarily small — the staging repo admits commit objects
/// up to 256 MiB and nearly all of that can be the message
/// forwarded verbatim — and a tree body scales with the number of
/// entries. Both must run under the `total` budget, not the
/// small-call one.
#[tokio::test]
async fn create_commit_survives_a_response_slower_than_the_small_call_budget() {
    use time::macros::datetime;
    let server = MockServer::start().await;
    let returned = sample_object_id('b');
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/commits"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({ "sha": returned.as_str() }))
                .set_delay(Duration::from_millis(500)),
        )
        .mount(&server)
        .await;
    let client = GitDataClient::new(
        &GitDataHttp::new(GitDataTimeouts::new(
            Duration::from_millis(200),
            Duration::from_millis(200),
            Duration::from_secs(5),
        )),
        server.uri(),
        "ghs_token".to_string(),
    );

    let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
    let tree = sample_object_id('a');
    let request = CommitRequest {
        tree: &tree,
        parents: &[],
        message: "msg",
        author: &ident,
        committer: &ident,
        signature: None,
    };
    let sha = client
        .create_commit(&sample_repo(), &request)
        .await
        .expect("a slow-but-progressing commit upload must get the full total budget");
    assert_eq!(sha, returned);
}

#[tokio::test]
async fn create_tree_survives_a_response_slower_than_the_small_call_budget() {
    let server = MockServer::start().await;
    let returned = sample_object_id('b');
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/trees"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({ "sha": returned.as_str() }))
                .set_delay(Duration::from_millis(500)),
        )
        .mount(&server)
        .await;
    let client = GitDataClient::new(
        &GitDataHttp::new(GitDataTimeouts::new(
            Duration::from_millis(200),
            Duration::from_millis(200),
            Duration::from_secs(5),
        )),
        server.uri(),
        "ghs_token".to_string(),
    );

    let sha = client
        .create_tree(&sample_repo(), &[])
        .await
        .expect("a slow-but-progressing tree upload must get the full total budget");
    assert_eq!(sha, returned);
}

/// The production bounds are what the promote path actually runs
/// under, and the whole point is that none of them is "unbounded".
#[test]
fn production_git_data_timeouts_are_bounded_and_ordered() {
    let timeouts = GitDataTimeouts::production();
    assert!(!timeouts.connect.is_zero());
    assert!(!timeouts.small_call.is_zero());
    assert!(!timeouts.total.is_zero());
    assert!(
        timeouts.connect <= timeouts.small_call,
        "a connect bound above the small-call bound cannot be reached",
    );
    assert!(
        timeouts.small_call <= timeouts.total,
        "a small-call bound above the total bound cannot be reached",
    );
    // Not a preference: an hour-long ceiling would be unbounded in
    // every sense that matters to a wedged approve attempt.
    assert!(timeouts.total <= Duration::from_secs(600));
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
            ResponseTemplate::new(422).set_body_json(json!({"message": "path 'foo' is invalid"})),
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
    CommitIdentity::new(name, format!("{name}@example.invalid"), date)
        .expect("test datetime is RFC 3339 representable")
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
fn commit_identity_drops_subsecond_precision_on_date() {
    // The wire format GitHub documents is YYYY-MM-DDTHH:MM:SSZ;
    // emitting sub-second digits is technically out of spec and
    // would let a caller-constructed sub-second `OffsetDateTime`
    // surface a deviation. Truncating at construction keeps the
    // wire shape stable.
    use time::macros::datetime;
    let identity = CommitIdentity::new(
        "Alice",
        "alice@example.invalid",
        datetime!(2024-01-15 10:30:45.123456789 UTC),
    )
    .expect("UTC date is RFC 3339 representable");
    assert_eq!(identity.date_rfc3339, "2024-01-15T10:30:45Z");
}

#[test]
fn commit_identity_preserves_non_utc_offset() {
    // Git commits carry the original author/committer offset
    // (e.g. `+0530`); we forward it verbatim so the replayed
    // commit's timestamp is faithful to the bundle.
    use time::macros::datetime;
    let identity = CommitIdentity::new(
        "Alice",
        "alice@example.invalid",
        datetime!(2024-01-15 10:30:45 +05:30),
    )
    .expect("+05:30 offset is RFC 3339 representable");
    assert_eq!(identity.date_rfc3339, "2024-01-15T10:30:45+05:30");
}

#[test]
fn commit_identity_rejects_subminute_offset() {
    // RFC 3339 only allows offsets in whole minutes. `time` lets
    // you build a sub-minute offset with `UtcOffset::from_hms`,
    // and the RFC 3339 formatter rejects it. The validated
    // constructor must surface that as an error rather than
    // panicking inside `create_commit` later.
    use time::macros::datetime;
    let subminute_offset =
        time::UtcOffset::from_hms(0, 0, 30).expect("seconds-precision offset constructs");
    let weird_date = datetime!(2024-01-15 10:30:45 UTC).replace_offset(subminute_offset);
    let err = CommitIdentity::new("Alice", "alice@example.invalid", weird_date)
        .expect_err("sub-minute offset must not be accepted");
    assert!(
        matches!(err, CommitIdentityError::Rfc3339Format(_)),
        "expected an Rfc3339Format error, got {err:?}",
    );
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
            ResponseTemplate::new(422).set_body_json(json!({"message": "tree sha does not exist"})),
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
            // GitHub reports its verdict on the signature we sent;
            // a signed create-commit only yields a SHA when that
            // verdict is affirmative, so the mock must carry it.
            "verification": { "verified": true, "reason": "valid" },
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

/// A signed create-commit whose response says GitHub could not
/// verify the signature must fail. The whole point of supplying a
/// signature is that the published commit carries the Verified
/// badge; if GitHub disagrees, the SHA must not escape this
/// function and reach branch publication.
#[tokio::test]
async fn create_commit_rejects_signed_commit_github_reports_unverified() {
    use time::macros::datetime;
    let server = MockServer::start().await;
    let returned = sample_object_id('b');
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/commits"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": returned.as_str(),
            "verification": {
                "verified": false,
                "reason": "unknown_key",
                "signature": "-----BEGIN SSH SIGNATURE-----\n…\n",
                "payload": "tree …",
            },
        })))
        .mount(&server)
        .await;

    let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
    let tree = sample_object_id('a');
    let request = CommitRequest {
        tree: &tree,
        parents: &[],
        message: "msg",
        author: &ident,
        committer: &ident,
        signature: Some("-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----\n"),
    };
    let client = client_against(&server, "ghs_fake_token");
    let err = client
        .create_commit(&sample_repo(), &request)
        .await
        .expect_err("an unverified signed commit must not be returned as a success");
    match err {
        GitDataError::UnverifiedSignedCommit { sha, reason } => {
            assert_eq!(sha, returned.as_str());
            assert_eq!(reason, "unknown_key");
        }
        other => panic!("expected UnverifiedSignedCommit, got {other:?}"),
    }
}

/// GitHub omitting the `verification` object entirely from a
/// signed commit's response is just as unusable as a `false`
/// verdict: we cannot confirm the Verified guarantee, so we refuse
/// rather than publish and hope.
#[tokio::test]
async fn create_commit_rejects_signed_commit_with_no_verification_object() {
    use time::macros::datetime;
    let server = MockServer::start().await;
    let returned = sample_object_id('b');
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/commits"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": returned.as_str(),
        })))
        .mount(&server)
        .await;

    let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
    let tree = sample_object_id('a');
    let request = CommitRequest {
        tree: &tree,
        parents: &[],
        message: "msg",
        author: &ident,
        committer: &ident,
        signature: Some("-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----\n"),
    };
    let client = client_against(&server, "ghs_fake_token");
    let err = client
        .create_commit(&sample_repo(), &request)
        .await
        .expect_err("a signed commit with no verification verdict must not succeed");
    assert!(
        matches!(err, GitDataError::MissingVerification { ref sha } if sha == returned.as_str()),
        "expected MissingVerification, got {err:?}",
    );
}

/// The happy path: signature supplied, GitHub reports
/// `verified: true`, the SHA flows back to the walker.
#[tokio::test]
async fn create_commit_accepts_signed_commit_github_reports_verified() {
    use time::macros::datetime;
    let server = MockServer::start().await;
    let returned = sample_object_id('b');
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/commits"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": returned.as_str(),
            "verification": {
                "verified": true,
                "reason": "valid",
            },
        })))
        .mount(&server)
        .await;

    let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
    let tree = sample_object_id('a');
    let request = CommitRequest {
        tree: &tree,
        parents: &[],
        message: "msg",
        author: &ident,
        committer: &ident,
        signature: Some("-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----\n"),
    };
    let client = client_against(&server, "ghs_fake_token");
    let got = client
        .create_commit(&sample_repo(), &request)
        .await
        .expect("verified signed commit is the happy path");
    assert_eq!(got, returned);
}

/// An *unsigned* create-commit never promised a Verified badge, so
/// the (inevitably `verified: false`) verdict is not an error. The
/// pre-promote bring-up flows and test fixtures depend on this.
#[tokio::test]
async fn create_commit_tolerates_unverified_verdict_when_request_is_unsigned() {
    use time::macros::datetime;
    let server = MockServer::start().await;
    let returned = sample_object_id('b');
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/commits"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": returned.as_str(),
            "verification": {
                "verified": false,
                "reason": "unsigned",
            },
        })))
        .mount(&server)
        .await;

    let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
    let tree = sample_object_id('a');
    let client = client_against(&server, "ghs_fake_token");
    let got = client
        .create_commit(
            &sample_repo(),
            &unsigned_request(&tree, &[], "msg", &ident, &ident),
        )
        .await
        .expect("an unsigned request makes no Verified claim to break");
    assert_eq!(got, returned);
}

proptest::proptest! {
    // Each case stands up a wiremock server, so keep the case
    // count modest; the input space here is tiny (2 × 3 shapes)
    // and this many cases covers it many times over.
    #![proptest_config(proptest::test_runner::Config::with_cases(24))]

    /// The invariant the replay path leans on: `create_commit`
    /// returns a SHA **exactly** when either the request carried no
    /// signature (no Verified claim was made) or GitHub affirmed
    /// `verification.verified == true`. Every other combination —
    /// signed-and-refuted, signed-and-no-verdict — must be an error,
    /// whatever `reason` string GitHub attaches.
    #[test]
    fn signed_create_commit_succeeds_exactly_when_github_reports_verified(
        signed in proptest::bool::ANY,
        verification in proptest::option::of((proptest::bool::ANY, "[a-z_]{1,16}")),
    ) {
        use time::macros::datetime;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            let returned = sample_object_id('b');
            let mut body = json!({ "sha": returned.as_str() });
            if let Some((verified, reason)) = &verification {
                body["verification"] = json!({ "verified": verified, "reason": reason });
            }
            Mock::given(method("POST"))
                .and(path("/repos/owner/name/git/commits"))
                .respond_with(ResponseTemplate::new(201).set_body_json(body))
                .mount(&server)
                .await;

            let ident = sample_identity("Alice", datetime!(2024-01-15 10:30:45 UTC));
            let tree = sample_object_id('a');
            let request = CommitRequest {
                tree: &tree,
                parents: &[],
                message: "msg",
                author: &ident,
                committer: &ident,
                signature: signed.then_some(
                    "-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----\n",
                ),
            };
            let client = client_against(&server, "ghs_fake_token");
            let result = client.create_commit(&sample_repo(), &request).await;

            let should_succeed =
                !signed || matches!(verification, Some((true, _)));
            proptest::prop_assert_eq!(
                result.is_ok(),
                should_succeed,
                "signed={:?} verification={:?} gave {:?}",
                signed,
                verification,
                result.map(|sha| sha.as_str().to_string()),
            );
            Ok(())
        })?;
    }
}

#[test]
fn debug_redacts_token() {
    let client = GitDataClient::new(
        &GitDataHttp::production(),
        "https://api.example",
        "ghs_secret",
    );
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

// ----- get_default_branch tests ---------------------------------

#[tokio::test]
async fn get_default_branch_sends_authed_get_and_parses_default_branch_field() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name"))
        .and(header("Accept", ACCEPT_HEADER))
        .and(header("X-GitHub-Api-Version", API_VERSION_HEADER))
        .and(header("User-Agent", USER_AGENT_HEADER))
        .and(header("Authorization", "Bearer ghs_fake_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42,
            "name": "name",
            "full_name": "owner/name",
            "default_branch": "main",
            "private": false,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = client
        .get_default_branch(&sample_repo())
        .await
        .expect("default branch lookup ok");
    assert_eq!(branch.as_str(), "main");
}

#[tokio::test]
async fn get_default_branch_accepts_non_main_default_branch_name() {
    // Older or operator-customised repos use `master`, `trunk`,
    // etc. The walker has no opinion on what the operator chose;
    // any valid branch name flows through.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "default_branch": "trunk",
        })))
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = client
        .get_default_branch(&sample_repo())
        .await
        .expect("default branch lookup ok");
    assert_eq!(branch.as_str(), "trunk");
}

#[tokio::test]
async fn get_default_branch_surfaces_api_error_body_on_404() {
    // Repo doesn't exist (or the App doesn't have access).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "Not Found"})))
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let err = client
        .get_default_branch(&sample_repo())
        .await
        .expect_err("404 must surface as ApiError");
    match err {
        GitDataError::ApiError { status, body } => {
            assert_eq!(status.as_u16(), 404);
            assert!(body.contains("Not Found"), "echo body: {body:?}");
        }
        other => panic!("expected ApiError, got {other:?}"),
    }
}

#[tokio::test]
async fn get_default_branch_rejects_invalid_branch_name_from_github() {
    // Defensive parsing: a default_branch value that fails
    // GitBranchName validation surfaces as a typed error rather
    // than a panic or a silent coerce. GitHub should never emit
    // this, but if it does, we want the failure mode to be
    // diagnosable rather than mysterious.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "default_branch": "..",
        })))
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let err = client
        .get_default_branch(&sample_repo())
        .await
        .expect_err("malformed branch name must not return silently");
    assert!(
        matches!(err, GitDataError::InvalidDefaultBranch { .. }),
        "expected InvalidDefaultBranch, got {err:?}",
    );
}

#[tokio::test]
async fn get_default_branch_returns_http_error_when_default_branch_missing() {
    // Response missing the `default_branch` field is a transport
    // / schema issue and surfaces as a transport error via serde.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42,
            "name": "name",
        })))
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let err = client
        .get_default_branch(&sample_repo())
        .await
        .expect_err("missing default_branch must not succeed");
    assert!(
        matches!(err, GitDataError::Http(_)),
        "expected Http error on missing field, got {err:?}",
    );
}

// ----- get_branch_head tests ------------------------------------

#[tokio::test]
async fn get_branch_head_sends_authed_get_and_returns_commit_sha() {
    let server = MockServer::start().await;
    let returned = sample_object_id('a');
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/ref/heads/main"))
        .and(header("Accept", ACCEPT_HEADER))
        .and(header("X-GitHub-Api-Version", API_VERSION_HEADER))
        .and(header("User-Agent", USER_AGENT_HEADER))
        .and(header("Authorization", "Bearer ghs_fake_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ref": "refs/heads/main",
            "node_id": "ignored",
            "url": "https://api.github.com/repos/owner/name/git/refs/heads/main",
            "object": {
                "sha": returned.as_str(),
                "type": "commit",
                "url": format!(
                    "https://api.github.com/repos/owner/name/git/commits/{}",
                    returned.as_str(),
                ),
            },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = GitBranchName::new("main").unwrap();
    let sha = client
        .get_branch_head(&sample_repo(), &branch)
        .await
        .expect("branch head lookup ok");
    assert_eq!(sha, returned);
}

#[test]
fn percent_encode_ref_segment_preserves_unreserved_and_slash_and_encodes_others() {
    // Unreserved set per RFC 3986 §2.3 plus '/' for ref hierarchy:
    // pass through unchanged.
    assert_eq!(
        percent_encode_ref_segment("AZaz09-._~/main"),
        "AZaz09-._~/main",
    );
    // URL-reserved bytes that git nonetheless accepts in branch
    // names: encode as %HH (uppercase, RFC 3986 §2.1).
    assert_eq!(percent_encode_ref_segment("release#1"), "release%231");
    assert_eq!(percent_encode_ref_segment("100%"), "100%25");
    assert_eq!(
        percent_encode_ref_segment("feat(area)+v2"),
        "feat%28area%29%2Bv2",
    );
    // UTF-8 multi-byte sequence encoded byte-by-byte (RFC 3986
    // §2.5): the 'é' in 'café' is 0xC3 0xA9.
    assert_eq!(percent_encode_ref_segment("café"), "caf%C3%A9");
}

/// Regression test for the URL-reserved-bytes issue: a branch
/// name git considers valid but which contains `#` or `%` must
/// reach GitHub at the correctly-encoded path. Without
/// percent-encoding, `release#1` would 404 against GitHub
/// because the `#` turns into a URL fragment.
#[tokio::test]
async fn get_branch_head_percent_encodes_url_reserved_bytes_in_branch_name() {
    let server = MockServer::start().await;
    let returned = sample_object_id('d');
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/ref/heads/release%231"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ref": "refs/heads/release#1",
            "object": { "sha": returned.as_str(), "type": "commit" },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = GitBranchName::new("release#1").unwrap();
    let sha = client
        .get_branch_head(&sample_repo(), &branch)
        .await
        .expect("URL-reserved bytes must be percent-encoded");
    assert_eq!(sha, returned);
}

#[tokio::test]
async fn get_branch_head_passes_slashes_in_branch_name_through_url_path() {
    // `feature/foo` is a valid git branch name. The Git Database
    // API treats the ref path as hierarchical, so slashes belong
    // in the path literally — not percent-encoded.
    let server = MockServer::start().await;
    let returned = sample_object_id('b');
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/ref/heads/feature/foo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ref": "refs/heads/feature/foo",
            "object": {
                "sha": returned.as_str(),
                "type": "commit",
            },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = GitBranchName::new("feature/foo").unwrap();
    let sha = client
        .get_branch_head(&sample_repo(), &branch)
        .await
        .expect("nested branch head lookup ok");
    assert_eq!(sha, returned);
}

#[tokio::test]
async fn get_branch_head_surfaces_api_error_body_on_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/ref/heads/main"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"message": "Branch not found"})),
        )
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = GitBranchName::new("main").unwrap();
    let err = client
        .get_branch_head(&sample_repo(), &branch)
        .await
        .expect_err("404 must surface as ApiError");
    match err {
        GitDataError::ApiError { status, body } => {
            assert_eq!(status.as_u16(), 404);
            assert!(body.contains("Branch not found"), "echo body: {body:?}");
        }
        other => panic!("expected ApiError, got {other:?}"),
    }
}

#[tokio::test]
async fn get_branch_head_rejects_response_pointing_at_non_commit() {
    // Defensive: branches always point at commits, so a `tag`
    // (or anything else) means we'd hand back a SHA the walker
    // would plug into a parent slot where only commit SHAs are
    // valid. Refuse at the boundary.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/ref/heads/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": {
                "sha": sample_object_id('c').as_str(),
                "type": "tag",
            },
        })))
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = GitBranchName::new("main").unwrap();
    let err = client
        .get_branch_head(&sample_repo(), &branch)
        .await
        .expect_err("non-commit ref target must be rejected");
    match err {
        GitDataError::UnexpectedRefObjectType {
            ref_name,
            object_type,
        } => {
            assert_eq!(ref_name, "refs/heads/main");
            assert_eq!(object_type, "tag");
        }
        other => panic!("expected UnexpectedRefObjectType, got {other:?}"),
    }
}

#[tokio::test]
async fn get_branch_head_returns_http_error_when_response_sha_is_invalid() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/ref/heads/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": {
                "sha": "not a valid sha",
                "type": "commit",
            },
        })))
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = GitBranchName::new("main").unwrap();
    let err = client
        .get_branch_head(&sample_repo(), &branch)
        .await
        .expect_err("malformed sha must not be returned silently");
    assert!(
        matches!(err, GitDataError::Http(_)),
        "GitObjectId rejection surfaces as transport error: {err:?}",
    );
}

#[tokio::test]
async fn update_ref_sends_patch_with_sha_and_force_false_returns_ok_on_200() {
    let server = MockServer::start().await;
    let new_head = sample_object_id('a');
    Mock::given(method("PATCH"))
        .and(path("/repos/owner/name/git/refs/heads/main"))
        .and(header("Accept", ACCEPT_HEADER))
        .and(header("X-GitHub-Api-Version", API_VERSION_HEADER))
        .and(header("User-Agent", USER_AGENT_HEADER))
        .and(header("Authorization", "Bearer ghs_fake_token"))
        .and(body_json(json!({
            "sha": new_head.as_str(),
            "force": false,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ref": "refs/heads/main",
            "object": { "sha": new_head.as_str(), "type": "commit" },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = GitBranchName::new("main").unwrap();
    client
        .update_ref(&sample_repo(), &branch, &new_head)
        .await
        .expect("fast-forward update ok");
}

/// Regression: the URL-grammar asymmetry between `GET .../ref/...`
/// (singular) and `PATCH .../refs/...` (plural) is the actual
/// GitHub API. A typo here is undetectable by clippy/typechecker
/// and would 404 silently against the real API, so the path is
/// asserted explicitly.
#[tokio::test]
async fn update_ref_uses_plural_refs_path_segment() {
    let server = MockServer::start().await;
    let new_head = sample_object_id('b');
    Mock::given(method("PATCH"))
        .and(path("/repos/owner/name/git/refs/heads/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ref": "refs/heads/main",
            "object": { "sha": new_head.as_str(), "type": "commit" },
        })))
        .expect(1)
        .mount(&server)
        .await;
    // A separate mount that responds 404 to the singular path —
    // if `update_ref` accidentally used `.../ref/...` this mock
    // would match and the test would fail.
    Mock::given(method("PATCH"))
        .and(path("/repos/owner/name/git/ref/heads/main"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "wrong path"})))
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = GitBranchName::new("main").unwrap();
    client
        .update_ref(&sample_repo(), &branch, &new_head)
        .await
        .expect("plural `refs` path must reach the mock");
}

/// A 422 from GitHub is the documented "not a fast forward"
/// failure mode. The body carries the GitHub-side reason and must
/// reach the operator unchanged so they can distinguish "the
/// walker chain doesn't descend from the current tip" from other
/// 422 cases (e.g. malformed sha).
#[tokio::test]
async fn update_ref_surfaces_422_as_api_error_with_body() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/repos/owner/name/git/refs/heads/main"))
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_json(json!({"message": "Update is not a fast forward"})),
        )
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = GitBranchName::new("main").unwrap();
    let err = client
        .update_ref(&sample_repo(), &branch, &sample_object_id('c'))
        .await
        .expect_err("422 must surface as ApiError");
    match err {
        GitDataError::ApiError { status, body } => {
            assert_eq!(status.as_u16(), 422);
            assert!(
                body.contains("not a fast forward"),
                "ApiError body must echo GitHub's reason: {body:?}",
            );
        }
        other => panic!("expected ApiError, got {other:?}"),
    }
}

#[tokio::test]
async fn update_ref_surfaces_5xx_as_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/repos/owner/name/git/refs/heads/main"))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream unavailable"))
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = GitBranchName::new("main").unwrap();
    let err = client
        .update_ref(&sample_repo(), &branch, &sample_object_id('d'))
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
async fn update_ref_percent_encodes_url_reserved_bytes_in_branch_name() {
    let server = MockServer::start().await;
    let new_head = sample_object_id('e');
    Mock::given(method("PATCH"))
        .and(path("/repos/owner/name/git/refs/heads/release%231"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ref": "refs/heads/release#1",
            "object": { "sha": new_head.as_str(), "type": "commit" },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = GitBranchName::new("release#1").unwrap();
    client
        .update_ref(&sample_repo(), &branch, &new_head)
        .await
        .expect("URL-reserved bytes must be percent-encoded");
}

#[tokio::test]
async fn update_ref_passes_slashes_in_branch_name_through_url_path() {
    let server = MockServer::start().await;
    let new_head = sample_object_id('f');
    Mock::given(method("PATCH"))
        .and(path("/repos/owner/name/git/refs/heads/feature/foo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ref": "refs/heads/feature/foo",
            "object": { "sha": new_head.as_str(), "type": "commit" },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    let branch = GitBranchName::new("feature/foo").unwrap();
    client
        .update_ref(&sample_repo(), &branch, &new_head)
        .await
        .expect("nested branch ref must pass slashes through");
}

/// Building a `GitDataClient` must not build a `reqwest::Client`.
///
/// The transport is the expensive half: `reqwest`'s `rustls-tls-native-roots`
/// backend reads and parses the platform root store on every
/// `ClientBuilder::build()` — measured at ~7 s for the first build in a process
/// on macOS and ~80 ms steady-state, versus effectively zero for a clone (the
/// client is `Arc`-backed). The credentials are the cheap half, and they are
/// what varies: an approve mints a fresh installation token, so it needs a
/// fresh *client* but the same *transport*. Splitting [`GitDataHttp`] out is
/// what lets the broker build the transport once and pay only the credential
/// cost per approve.
///
/// Asserted by counting builds rather than by timing them: a timing
/// assertion would be a benchmark wearing a test's clothes — slow (it has to
/// build a transport to calibrate against) and load-dependent. The count is
/// exact, and it states the property directly.
#[test]
fn a_client_borrows_its_transport_instead_of_building_one() {
    let before = transports_built_on_this_thread();
    let http = GitDataHttp::production();
    let clients: Vec<GitDataClient> = (0..64)
        .map(|i| GitDataClient::new(&http, "https://api.github.com", format!("ghs_token_{i}")))
        .collect();

    assert_eq!(clients.len(), 64);
    assert_eq!(
        transports_built_on_this_thread() - before,
        1,
        "64 clients over one transport must build exactly the one transport",
    );
}
