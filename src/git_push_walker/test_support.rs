//! Shared fixtures and real-git helpers for the walker test modules.
//!
//! `super::*` re-exports the production items and the parent module's
//! private `use` aliases (`GitObjectId`, `RepoRef`, `Duration`, …); the
//! explicit imports add what the parent does not pull in.

use super::*;
pub(super) use crate::test_support::{
    commit_empty, commit_merge, init_test_repo, required_tool, rev_parse, run_git,
    shell_quote_path, write_executable_script,
};
use std::str::FromStr;

use crate::github_git_db::GitDataHttp;

use serde_json::json;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub(super) fn sample_repo() -> RepoRef {
    RepoRef::from_str("owner/name").unwrap()
}

pub(super) fn sample_object_id(nibble: char) -> GitObjectId {
    GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
}

pub(super) fn sample_identity(name: &str) -> CommitIdentity {
    use time::macros::datetime;
    CommitIdentity::new(
        name,
        format!("{name}@example.invalid"),
        datetime!(2024-01-15 10:30:45 UTC),
    )
    .expect("sample date formats")
}

pub(super) fn client_against(server: &MockServer, token: &str) -> GitDataClient {
    GitDataClient::new(&GitDataHttp::production(), server.uri(), token.to_string())
}

/// Mount a blob create that strictly matches the given content
/// and responds with the given SHA. Returns nothing — failing
/// the strict body match shows up as the test's commit-create
/// matcher never firing (or wiremock surfaces an unmatched
/// request).
pub(super) async fn mount_blob_create(server: &MockServer, content: &[u8], returned: &GitObjectId) {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(content);
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/blobs"))
        .and(body_json(json!({
            "content": encoded,
            "encoding": "base64",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": returned.as_str(),
        })))
        .expect(1)
        .mount(server)
        .await;
}

pub(super) async fn mount_tree_create(
    server: &MockServer,
    expected_body: serde_json::Value,
    returned: &GitObjectId,
) {
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/trees"))
        .and(body_json(expected_body))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": returned.as_str(),
        })))
        .expect(1)
        .mount(server)
        .await;
}

pub(super) async fn mount_commit_create(
    server: &MockServer,
    expected_body: serde_json::Value,
    returned: &GitObjectId,
) {
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/commits"))
        .and(body_json(expected_body))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": returned.as_str(),
        })))
        .expect(1)
        .mount(server)
        .await;
}

/// The planner shell-outs are sub-second under a normal load.
/// 10s gives plenty of room on a saturated CI host without
/// letting a wedged child hang the suite indefinitely.
pub(super) const TEST_GIT_TIMEOUT: Duration = Duration::from_secs(10);
