//! Example-based tests for inline commit signing in the walker:
//! the `Some(signing_key)` path emits a verifiable SSHSIG, every
//! commit in a chain is signed, and `None` omits the field.

use super::test_fixture::InMemoryGitObjectSource;
use super::test_support::*;
use super::*;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test fixture: parse the in-tree Ed25519 signing key so the
/// walker tests can drive the `Some(&key)` path.
fn load_test_signing_key() -> WritSigningKey {
    const PRIVATE_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");
    WritSigningKey::from_openssh_pem(PRIVATE_PEM).expect("fixture key parses")
}

/// Test fixture: matching public key for verifying SSHSIG output
/// the walker generated.
fn load_test_public_key() -> ssh_key::PublicKey {
    const PUBLIC_OPENSSH: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key.pub");
    ssh_key::PublicKey::from_openssh(PUBLIC_OPENSSH).expect("fixture public key parses")
}

/// Drive `replay_commits` with `signing_key: Some(&key)` for a
/// single-commit chain and assert the create_commit POST body
/// carries an SSHSIG signature that verifies under the `"git"`
/// namespace against the canonical bytes
/// [`crate::git_commit_sign::canonical_commit_bytes`] would
/// produce for the same wire fields. This is the property the
/// promotion path leans on: GitHub verifies the signature against
/// the bytes it re-canonicalises from the wire body, so a
/// signature that round-trips under our own canonicaliser is the
/// same bytes GitHub will see.
#[tokio::test]
async fn replay_with_signing_key_sends_verifiable_signature_to_create_commit() {
    use crate::git_commit_sign::{CommitSigningInput, canonical_commit_bytes};
    use crate::signing::GIT_SSHSIG_NAMESPACE;
    use ssh_key::SshSig;

    let server = MockServer::start().await;
    let commit_bundle = sample_object_id('1');
    let tree_bundle = sample_object_id('2');
    let tree_app = sample_object_id('a');
    let commit_app = sample_object_id('b');

    let author = sample_identity("Alice");
    let committer = sample_identity("Bot");
    let message = "subject\n\nbody\n";

    let mut source = InMemoryGitObjectSource::new();
    source.insert_tree(tree_bundle.clone(), StagingTree { entries: vec![] });
    source.insert_commit(
        commit_bundle.clone(),
        StagingCommit {
            tree: tree_bundle.clone(),
            parents: vec![],
            author: author.clone(),
            committer: committer.clone(),
            message: message.to_string(),
        },
    );
    mount_tree_create(&server, json!({ "tree": [] }), &tree_app).await;

    // Loose matcher (method + path only): the signature bytes are
    // produced by ssh-key and not necessarily stable across
    // releases of the crate, so a strict body matcher is the
    // wrong contract. We assert the *property* (signature
    // verifies against the canonical bytes) after the call.
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/commits"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": commit_app.as_str(),
            "verification": { "verified": true, "reason": "valid" },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let key = load_test_signing_key();
    let client = client_against(&server, "ghs_fake_token");
    let (final_sha, _) = replay_commits(
        &client,
        &sample_repo(),
        &source,
        std::slice::from_ref(&commit_bundle),
        ShaMap::new(),
        &[],
        Some(&key),
    )
    .await
    .expect("walker ok");
    assert_eq!(final_sha, commit_app);

    // Pull the captured request and pin both shape and signing.
    let received = server
        .received_requests()
        .await
        .expect("wiremock recording enabled");
    let commit_post = received
        .iter()
        .find(|r| r.url.path() == "/repos/owner/name/git/commits")
        .expect("commit POST should have been issued");
    let body: serde_json::Value =
        serde_json::from_slice(&commit_post.body).expect("commit body is JSON");
    assert_eq!(body["tree"], json!(tree_app.as_str()));
    assert_eq!(body["parents"], json!([]));
    assert_eq!(body["message"], json!(message));
    let armored = body["signature"]
        .as_str()
        .expect("signing key threaded → body has a string signature field");
    let parsed: SshSig = armored.parse().expect("SSHSIG armor parses");

    let expected_canonical = canonical_commit_bytes(&CommitSigningInput {
        tree: &tree_app,
        parents: &[],
        author: &author,
        committer: &committer,
        message,
    })
    .expect("canonicalise");
    load_test_public_key()
        .verify(GIT_SSHSIG_NAMESPACE, &expected_canonical, &parsed)
        .expect("walker-produced signature verifies under the git namespace");
}

/// Every commit in a two-commit chain is independently signed,
/// not just the first or last. Regression pin: a refactor that
/// signed only the final commit (e.g. by hoisting the signing
/// step out of `replay_one_commit`) would let unsigned commits
/// land on GitHub and publish without the Verified badge.
#[tokio::test]
async fn replay_with_signing_key_signs_every_commit_in_a_chain() {
    use crate::git_commit_sign::{CommitSigningInput, canonical_commit_bytes};
    use crate::signing::GIT_SSHSIG_NAMESPACE;
    use ssh_key::SshSig;

    let server = MockServer::start().await;
    let tree_bundle = sample_object_id('1');
    let tree_app = sample_object_id('a');
    let c0_bundle = sample_object_id('2');
    let c1_bundle = sample_object_id('3');
    let c0_app = sample_object_id('b');
    let c1_app = sample_object_id('c');

    let author = sample_identity("Alice");
    let committer = sample_identity("Bot");

    let mut source = InMemoryGitObjectSource::new();
    source.insert_tree(tree_bundle.clone(), StagingTree { entries: vec![] });
    source.insert_commit(
        c0_bundle.clone(),
        StagingCommit {
            tree: tree_bundle.clone(),
            parents: vec![],
            author: author.clone(),
            committer: committer.clone(),
            message: "c0\n".to_string(),
        },
    );
    source.insert_commit(
        c1_bundle.clone(),
        StagingCommit {
            tree: tree_bundle.clone(),
            parents: vec![c0_bundle.clone()],
            author: author.clone(),
            committer: committer.clone(),
            message: "c1\n".to_string(),
        },
    );
    mount_tree_create(&server, json!({ "tree": [] }), &tree_app).await;

    // Two POSTs to /git/commits, sequenced by .up_to_n_times(1)
    // + a second mount so each one returns its own SHA. Both carry an
    // affirmative verification verdict: these are signed requests, and
    // `create_commit` will not return a SHA GitHub declined to verify.
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/commits"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": c0_app.as_str(),
            "verification": { "verified": true, "reason": "valid" },
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/commits"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": c1_app.as_str(),
            "verification": { "verified": true, "reason": "valid" },
        })))
        .mount(&server)
        .await;

    let key = load_test_signing_key();
    let client = client_against(&server, "ghs_fake_token");
    let (final_sha, _) = replay_commits(
        &client,
        &sample_repo(),
        &source,
        &[c0_bundle.clone(), c1_bundle.clone()],
        ShaMap::new(),
        &[],
        Some(&key),
    )
    .await
    .expect("walker ok");
    assert_eq!(final_sha, c1_app);

    let received = server.received_requests().await.expect("recording enabled");
    let commit_posts: Vec<_> = received
        .iter()
        .filter(|r| r.url.path() == "/repos/owner/name/git/commits")
        .collect();
    assert_eq!(commit_posts.len(), 2, "one POST per commit in the chain");

    let pubk = load_test_public_key();
    for (post, (expected_parents, expected_message)) in commit_posts.iter().zip([
        (Vec::<GitObjectId>::new(), "c0\n"),
        (vec![c0_app.clone()], "c1\n"),
    ]) {
        let body: serde_json::Value =
            serde_json::from_slice(&post.body).expect("commit body is JSON");
        let armored = body["signature"]
            .as_str()
            .expect("every commit must carry a signature");
        let parsed: SshSig = armored.parse().expect("SSHSIG armor parses");
        let canonical = canonical_commit_bytes(&CommitSigningInput {
            tree: &tree_app,
            parents: &expected_parents,
            author: &author,
            committer: &committer,
            message: expected_message,
        })
        .expect("canonicalise");
        pubk.verify(GIT_SSHSIG_NAMESPACE, &canonical, &parsed)
            .expect("each chain commit signs under its own canonical bytes");
    }
}

/// Regression pin against an inverted-Option bug: when
/// `signing_key` is `None`, the request body must omit the
/// `signature` field entirely (not send an empty string or a
/// `null`). GitHub treats both as malformed.
#[tokio::test]
async fn replay_without_signing_key_omits_signature_field_from_body() {
    let server = MockServer::start().await;
    let commit_bundle = sample_object_id('1');
    let tree_bundle = sample_object_id('2');
    let tree_app = sample_object_id('a');
    let commit_app = sample_object_id('b');

    let mut source = InMemoryGitObjectSource::new();
    source.insert_tree(tree_bundle.clone(), StagingTree { entries: vec![] });
    source.insert_commit(
        commit_bundle.clone(),
        StagingCommit {
            tree: tree_bundle.clone(),
            parents: vec![],
            author: sample_identity("Alice"),
            committer: sample_identity("Bot"),
            message: "x\n".to_string(),
        },
    );
    mount_tree_create(&server, json!({ "tree": [] }), &tree_app).await;
    Mock::given(method("POST"))
        .and(path("/repos/owner/name/git/commits"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "sha": commit_app.as_str(),
        })))
        .mount(&server)
        .await;

    let client = client_against(&server, "ghs_fake_token");
    replay_commits(
        &client,
        &sample_repo(),
        &source,
        std::slice::from_ref(&commit_bundle),
        ShaMap::new(),
        &[],
        None,
    )
    .await
    .expect("walker ok");

    let received = server.received_requests().await.expect("recording enabled");
    let commit_post = received
        .iter()
        .find(|r| r.url.path() == "/repos/owner/name/git/commits")
        .expect("commit POST should have been issued");
    let body: serde_json::Value =
        serde_json::from_slice(&commit_post.body).expect("commit body is JSON");
    assert!(
        body.get("signature").is_none(),
        "None signing key must produce a body with no signature field, got: {body}"
    );
}
